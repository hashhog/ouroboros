//! Bitcoin difficulty adjustment algorithm
//!
//! Implements GetNextWorkRequired from Bitcoin Core pow.cpp.
//! Handles mainnet, testnet3/testnet4 (min-difficulty exception, BIP94),
//! and regtest (always minimum difficulty).

use bitcoin::Network;
use primitive_types::U256;

use super::pow::bits_to_target;
use crate::chain_params::{ConsensusParams, get_consensus_params};

/// Difficulty adjustment interval (2016 blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

/// Target timespan (2 weeks in seconds)
pub const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60; // 1,209,600 seconds

/// Target spacing (10 minutes in seconds)
pub const TARGET_SPACING: i64 = 10 * 60; // 600 seconds

/// Mainnet PoW limit (minimum difficulty, maximum target)
/// 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
pub const POW_LIMIT_MAINNET: u32 = 0x1d00ffff;

/// Testnet PoW limit (same as mainnet)
pub const POW_LIMIT_TESTNET: u32 = 0x1d00ffff;

/// Regtest PoW limit (very easy - 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
pub const POW_LIMIT_REGTEST: u32 = 0x207fffff;

/// Block index information needed for difficulty calculation
#[derive(Debug, Clone)]
pub struct BlockIndexInfo {
    pub height: u32,
    pub bits: u32,
    pub timestamp: u32,
}

/// Calculate the next work required for a block.
///
/// This is the main entry point for difficulty adjustment, matching
/// Bitcoin Core's GetNextWorkRequired() in pow.cpp.
///
/// # Arguments
/// * `last_block` - The previous block (tip)
/// * `new_block_time` - Timestamp of the new block being validated
/// * `network` - The Bitcoin network
/// * `get_ancestor` - Callback to get ancestor blocks by height
///
/// # Returns
/// The expected nBits value for the next block
pub fn get_next_work_required<F>(
    last_block: &BlockIndexInfo,
    new_block_time: u32,
    network: Network,
    get_ancestor: F,
) -> u32
where
    F: Fn(u32) -> Option<BlockIndexInfo>,
{
    let params = get_consensus_params(network);
    let pow_limit_bits = params.pow_limit_bits;

    // Regtest: always return pow_limit (no retargeting)
    if params.pow_no_retargeting {
        return pow_limit_bits;
    }

    let next_height = last_block.height + 1;

    // Only change once per difficulty adjustment interval
    if next_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
        // Testnet special rules (testnet3 and testnet4)
        if params.pow_allow_min_difficulty_blocks {
            // If new block's timestamp is more than 2x target spacing after
            // the previous block, allow min-difficulty block
            if new_block_time > last_block.timestamp + (TARGET_SPACING as u32 * 2) {
                return pow_limit_bits;
            }

            // Otherwise, walk back to find the last non-min-difficulty block
            // Bitcoin Core: walk back until we find a non-pow-limit block or
            // hit a retarget boundary
            let mut index = last_block.clone();
            while index.height > 0
                && index.height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
                && index.bits == pow_limit_bits
            {
                if let Some(prev) = get_ancestor(index.height - 1) {
                    index = prev;
                } else {
                    break;
                }
            }
            return index.bits;
        }

        // Normal case: return previous block's bits
        return last_block.bits;
    }

    // Difficulty adjustment: calculate new target

    // Get the first block of the 2016-block period
    let first_height = last_block.height - (DIFFICULTY_ADJUSTMENT_INTERVAL - 1);
    let first_block = match get_ancestor(first_height) {
        Some(b) => b,
        None => return pow_limit_bits, // Shouldn't happen, but safe fallback
    };

    calculate_next_work_required(last_block, &first_block, &params)
}

/// Calculate the next difficulty target at a retarget boundary.
///
/// Matches Bitcoin Core's CalculateNextWorkRequired() in pow.cpp:50-85.
///
/// For BIP94 networks (testnet4), uses the first block's nBits as the base
/// to defend against the time-warp attack. For all other networks, uses the
/// last block's nBits.
///
/// # Arguments
/// * `last_block` - The last block in the period (height % 2016 == 2015)
/// * `first_block` - The first block in the period (height = last - 2015).
///                   Both `first_block.timestamp` (used for actualTimespan) and
///                   `first_block.bits` (used as BIP94 base) are required.
/// * `params` - Consensus parameters
///
/// # Returns
/// The new difficulty in compact "bits" format
pub fn calculate_next_work_required(
    last_block: &BlockIndexInfo,
    first_block: &BlockIndexInfo,
    params: &ConsensusParams,
) -> u32 {
    // If no retargeting (regtest), keep the same difficulty
    if params.pow_no_retargeting {
        return last_block.bits;
    }

    // Calculate actual timespan
    let mut actual_timespan = (last_block.timestamp as i64) - (first_block.timestamp as i64);

    // Clamp timespan to [target/4, target*4]
    if actual_timespan < TARGET_TIMESPAN / 4 {
        actual_timespan = TARGET_TIMESPAN / 4;
    }
    if actual_timespan > TARGET_TIMESPAN * 4 {
        actual_timespan = TARGET_TIMESPAN * 4;
    }

    // BIP94 (testnet4): use the first block's nBits as the base instead of
    // the last block's. The first block of a period cannot use the
    // min-difficulty exception, so this preserves the real difficulty across
    // the retarget and prevents the time-warp attack where miners lower
    // difficulty via min-diff blocks then raise timestamps at the boundary.
    // Reference: bitcoin-core/src/pow.cpp:67-76 (enforce_BIP94 branch).
    let base_bits = if params.enforce_bip94 {
        first_block.bits
    } else {
        last_block.bits
    };

    // Convert to target
    let base_target = bits_to_target(base_bits);
    let pow_limit = bits_to_target(params.pow_limit_bits);

    // Calculate new target: base_target * (actual_timespan / target_timespan)
    let new_target = (base_target * U256::from(actual_timespan as u64)) / U256::from(TARGET_TIMESPAN as u64);

    // Cap at pow_limit
    let final_target = if new_target > pow_limit {
        pow_limit
    } else {
        new_target
    };

    // Convert back to compact bits
    target_to_bits(final_target)
}

/// Convert a U256 target to compact "bits" format.
///
/// Bitcoin's compact format:
/// - Bits 24-31: exponent (number of bytes - 3 for the shift)
/// - Bits 0-23: mantissa (significant digits)
///
/// Formula: target = mantissa * 256^(exponent - 3)
pub fn target_to_bits(target: U256) -> u32 {
    // Use common crate's implementation which handles the conversion correctly
    common::crypto::target_to_bits(target)
}

/// Calculate difficulty adjustment with BIP94 support.
///
/// Deprecated: as of the BIP94 wiring fix, `calculate_next_work_required`
/// now natively reads `first_block.bits` and applies the BIP94 rule when
/// `params.enforce_bip94` is true. This function is preserved as a thin
/// wrapper for backward compatibility with any out-of-tree callers.
#[deprecated(
    since = "0.2.0",
    note = "Use calculate_next_work_required directly; BIP94 is now handled natively."
)]
pub fn calculate_next_work_required_bip94(
    last_block: &BlockIndexInfo,
    first_block: &BlockIndexInfo,
    params: &ConsensusParams,
) -> u32 {
    calculate_next_work_required(last_block, first_block, params)
}

/// Check if a difficulty transition is permitted.
///
/// Matches Bitcoin Core's PermittedDifficultyTransition() in pow.cpp.
///
/// # Arguments
/// * `height` - Block height
/// * `old_bits` - Previous block's difficulty
/// * `new_bits` - New block's difficulty
/// * `network` - Bitcoin network
///
/// # Returns
/// True if the transition is valid
pub fn permitted_difficulty_transition(
    height: u32,
    old_bits: u32,
    new_bits: u32,
    network: Network,
) -> bool {
    let params = get_consensus_params(network);

    // Testnets allow any transition due to min-difficulty rules
    if params.pow_allow_min_difficulty_blocks {
        return true;
    }

    // At adjustment boundaries, check the new difficulty is within 4x
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        let pow_limit = bits_to_target(params.pow_limit_bits);
        let old_target = bits_to_target(old_bits);
        let new_target = bits_to_target(new_bits);

        // Calculate maximum allowed target (4x easier)
        let max_target = {
            let expanded = old_target * U256::from(TARGET_TIMESPAN as u64 * 4);
            let result = expanded / U256::from(TARGET_TIMESPAN as u64);
            if result > pow_limit { pow_limit } else { result }
        };

        // Calculate minimum allowed target (4x harder)
        let min_target = {
            let contracted = old_target * U256::from(TARGET_TIMESPAN as u64 / 4);
            contracted / U256::from(TARGET_TIMESPAN as u64)
        };

        // Round-trip through bits to match Bitcoin Core's comparison
        let max_bits = target_to_bits(max_target);
        let min_bits = target_to_bits(min_target);

        let max_target_rounded = bits_to_target(max_bits);
        let min_target_rounded = bits_to_target(min_bits);

        if new_target > max_target_rounded || new_target < min_target_rounded {
            return false;
        }
    } else {
        // Not an adjustment boundary: difficulty must stay the same
        if old_bits != new_bits {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_to_bits_genesis() {
        // Genesis block target
        let genesis_bits = 0x1d00ffff;
        let target = bits_to_target(genesis_bits);
        let roundtrip_bits = target_to_bits(target);
        assert_eq!(roundtrip_bits, genesis_bits);
    }

    #[test]
    fn test_target_to_bits_roundtrip() {
        let test_values = [
            0x1d00ffff, // Genesis
            0x1b0404cb, // ~Block 32k
            0x1a05db8b, // ~Block 100k
            0x18009645, // ~Block 500k
            0x170b0c00, // ~Block 1M (approximate)
        ];

        for bits in test_values {
            let target = bits_to_target(bits);
            let roundtrip = target_to_bits(target);
            assert_eq!(roundtrip, bits, "Roundtrip failed for 0x{:08x}", bits);
        }
    }

    /// Helper for mainnet retarget tests: build a `first_block` with a given
    /// timestamp. `bits` is irrelevant on non-BIP94 networks (last_block.bits
    /// is used as the base) so we mirror last_block.bits for clarity.
    fn first_block(height: u32, bits: u32, timestamp: u32) -> BlockIndexInfo {
        BlockIndexInfo { height, bits, timestamp }
    }

    #[test]
    fn test_difficulty_adjustment_no_change() {
        // When actual timespan equals target, difficulty shouldn't change
        let params = get_consensus_params(Network::Bitcoin);
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: 0x1d00ffff,
            timestamp: 1231006505 + (TARGET_TIMESPAN as u32),
        };
        let first = first_block(0, 0x1d00ffff, 1231006505);

        let new_bits = calculate_next_work_required(&last_block, &first, &params);
        assert_eq!(new_bits, 0x1d00ffff);
    }

    #[test]
    fn test_difficulty_adjustment_increase() {
        // Blocks found in half the time -> difficulty doubles (target halves)
        let params = get_consensus_params(Network::Bitcoin);
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: 0x1d00ffff,
            timestamp: 1231006505 + ((TARGET_TIMESPAN / 2) as u32),
        };
        let first = first_block(0, 0x1d00ffff, 1231006505);

        let new_bits = calculate_next_work_required(&last_block, &first, &params);

        // New difficulty should be higher (lower bits value)
        // Target halved means bits should be lower
        let old_target = bits_to_target(0x1d00ffff);
        let new_target = bits_to_target(new_bits);
        assert!(new_target < old_target, "Target should decrease for faster blocks");
    }

    #[test]
    fn test_difficulty_adjustment_decrease() {
        // Blocks found in double the time -> difficulty halves (target doubles)
        let params = get_consensus_params(Network::Bitcoin);
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: 0x1d00ffff,
            timestamp: 1231006505 + ((TARGET_TIMESPAN * 2) as u32),
        };
        let first = first_block(0, 0x1d00ffff, 1231006505);

        let new_bits = calculate_next_work_required(&last_block, &first, &params);

        // At genesis difficulty (pow_limit), it can't get any easier
        // So it should stay the same
        assert_eq!(new_bits, 0x1d00ffff);
    }

    #[test]
    fn test_difficulty_clamping_max() {
        // Even with very long timespan, max adjustment is 4x
        let params = get_consensus_params(Network::Bitcoin);
        let start_bits = 0x1b0404cb; // Higher difficulty than genesis
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: start_bits,
            timestamp: 1231006505 + ((TARGET_TIMESPAN * 10) as u32), // 10x target time
        };
        let first = first_block(0, start_bits, 1231006505);

        let new_bits = calculate_next_work_required(&last_block, &first, &params);

        // Should be clamped to 4x adjustment max
        let old_target = bits_to_target(start_bits);
        let new_target = bits_to_target(new_bits);
        let max_target = old_target * U256::from(4u64);

        assert!(new_target <= max_target, "Should be clamped to 4x max");
    }

    #[test]
    fn test_difficulty_clamping_min() {
        // Even with very short timespan, min adjustment is 1/4
        let params = get_consensus_params(Network::Bitcoin);
        let start_bits = 0x1b0404cb;
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: start_bits,
            timestamp: 1231006505 + 1000, // Very fast blocks
        };
        let first = first_block(0, start_bits, 1231006505);

        let new_bits = calculate_next_work_required(&last_block, &first, &params);

        // Should be clamped to 1/4 adjustment min
        let old_target = bits_to_target(start_bits);
        let new_target = bits_to_target(new_bits);
        let min_target = old_target / U256::from(4u64);

        // Due to compact bit representation rounding, new_target should be approximately
        // at or below the min_target (target goes down = difficulty goes up)
        // The exact relationship depends on the bits-to-target rounding.
        // What matters is that the actual timespan was clamped to TARGET_TIMESPAN/4.

        // Verify the adjustment is in the right direction (target decreased)
        assert!(new_target < old_target, "Target should decrease for fast blocks");

        // Verify it's not more than 4x harder (target not less than old/4)
        // Allow some tolerance for rounding in compact representation
        let tolerance = old_target / U256::from(100u64); // 1% tolerance
        assert!(
            new_target + tolerance >= min_target,
            "Should be approximately clamped to 1/4 min (got {:?}, min {:?})",
            new_target,
            min_target
        );
    }

    #[test]
    fn test_regtest_no_retargeting() {
        // Regtest always returns pow_limit
        let block = BlockIndexInfo {
            height: 100,
            bits: 0x1b0404cb,
            timestamp: 1231006505,
        };

        let result = get_next_work_required(
            &block,
            1231006505 + 1000,
            Network::Regtest,
            |_| None,
        );

        assert_eq!(result, POW_LIMIT_REGTEST);
    }

    #[test]
    fn test_testnet_min_difficulty_20_minutes() {
        // Testnet: if >20 minutes since last block, allow min difficulty
        let last_block = BlockIndexInfo {
            height: 100,
            bits: 0x1b0404cb, // Higher difficulty
            timestamp: 1231006505,
        };

        // New block 25 minutes later (>20 min)
        let new_time = 1231006505 + (25 * 60);

        let result = get_next_work_required(
            &last_block,
            new_time,
            Network::Testnet,
            |_| None,
        );

        assert_eq!(result, POW_LIMIT_TESTNET, "Should allow min difficulty after 20+ minutes");
    }

    #[test]
    fn test_testnet_walkback() {
        // Testnet: if <20 minutes, walk back to find last non-min-diff block
        let last_block = BlockIndexInfo {
            height: 103,
            bits: POW_LIMIT_TESTNET, // Min difficulty
            timestamp: 1231006505 + 600, // 10 min
        };

        // New block 5 minutes later (<20 min)
        let new_time = 1231006505 + 900;

        // Ancestor at height 100 has real difficulty
        let real_diff_block = BlockIndexInfo {
            height: 100,
            bits: 0x1b0404cb,
            timestamp: 1231006505,
        };

        let result = get_next_work_required(
            &last_block,
            new_time,
            Network::Testnet,
            |h| {
                if h >= 100 && h <= 102 {
                    if h == 100 {
                        Some(real_diff_block.clone())
                    } else {
                        Some(BlockIndexInfo {
                            height: h,
                            bits: POW_LIMIT_TESTNET,
                            timestamp: 1231006505 + (h - 100) * 60,
                        })
                    }
                } else {
                    None
                }
            },
        );

        assert_eq!(result, 0x1b0404cb, "Should walk back to real difficulty block");
    }

    #[test]
    fn test_permitted_transition_mainnet() {
        // On mainnet, non-adjustment blocks must keep same difficulty
        assert!(permitted_difficulty_transition(
            100,
            0x1b0404cb,
            0x1b0404cb,
            Network::Bitcoin
        ));

        // Different difficulty at non-adjustment should fail
        assert!(!permitted_difficulty_transition(
            100,
            0x1b0404cb,
            0x1d00ffff,
            Network::Bitcoin
        ));
    }

    #[test]
    fn test_permitted_transition_adjustment() {
        // At adjustment boundary, changes within 4x are allowed
        assert!(permitted_difficulty_transition(
            2016,
            0x1b0404cb,
            0x1b0404cb, // Same
            Network::Bitcoin
        ));
    }

    #[test]
    fn test_permitted_transition_testnet() {
        // Testnet allows any transition
        assert!(permitted_difficulty_transition(
            100,
            0x1b0404cb,
            0x1d00ffff,
            Network::Testnet
        ));
    }

    // ----------------------------------------------------------------------
    // BIP94 (testnet4) regression tests
    //
    // Per Bitcoin Core pow.cpp:67-76, when `enforce_BIP94` is true the
    // retarget formula uses pindexFirst->nBits (first block of the period)
    // instead of pindexLast->nBits. This blocks the time-warp attack where
    // an attacker uses the testnet min-difficulty exception to inflate the
    // tip's nBits and then warp forward at the boundary.
    //
    // Before this fix, the Rust path silently used last_block.bits even
    // when params.enforce_bip94 was true (TODO comment at line 157).
    // ----------------------------------------------------------------------

    #[test]
    fn test_bip94_uses_first_block_bits_not_last() {
        // Adversarial scenario: at the retarget boundary the last block was
        // a min-difficulty block (POW_LIMIT_TESTNET), but the first block
        // of the period had the real difficulty (0x1b0404cb).
        //
        // - With BIP94 (testnet4): base = first_block.bits  -> retarget away from
        //   real difficulty, NOT from the min-diff tip.
        // - Without BIP94 (testnet3): base = last_block.bits -> retarget away
        //   from POW_LIMIT_TESTNET (which is what the time-warp exploit relies on).
        //
        // We verify the two paths diverge: the testnet4 result must be HARDER
        // than the testnet3 result given the same actual_timespan.
        let real_bits = 0x1b0404cb;
        let min_diff = POW_LIMIT_TESTNET;
        let first_time: u32 = 1700000000;
        let last_time: u32 = first_time + (TARGET_TIMESPAN as u32); // exact target timespan

        let last_block = BlockIndexInfo {
            height: 2015,
            bits: min_diff,         // tip ended on a min-difficulty block
            timestamp: last_time,
        };
        let first = BlockIndexInfo {
            height: 0,
            bits: real_bits,        // period's first block had real difficulty
            timestamp: first_time,
        };

        let testnet4_params = get_consensus_params(Network::Testnet4);
        assert!(testnet4_params.enforce_bip94, "testnet4 must enforce BIP94");
        let testnet4_bits = calculate_next_work_required(&last_block, &first, &testnet4_params);

        let testnet3_params = get_consensus_params(Network::Testnet);
        assert!(!testnet3_params.enforce_bip94, "testnet3 must NOT enforce BIP94");
        let testnet3_bits = calculate_next_work_required(&last_block, &first, &testnet3_params);

        // BIP94 must use first_block.bits as the base, so when the actual
        // timespan equals the target, the result is ~first_block.bits.
        assert_eq!(
            testnet4_bits, real_bits,
            "BIP94 must base retarget on first_block.bits ({:#010x}), got {:#010x}",
            real_bits, testnet4_bits,
        );

        // testnet3 (no BIP94) bases retarget on last_block.bits == min_diff,
        // so the retarget result is ~min_diff (capped at pow_limit).
        assert_eq!(
            testnet3_bits, min_diff,
            "Non-BIP94 must base retarget on last_block.bits ({:#010x}), got {:#010x}",
            min_diff, testnet3_bits,
        );

        // Sanity: the two paths must diverge — this is the whole point of BIP94.
        assert_ne!(
            testnet4_bits, testnet3_bits,
            "BIP94 path must diverge from non-BIP94 path on the time-warp scenario",
        );
        // BIP94 result must be the harder difficulty (lower target = lower bits
        // when the exponents match; here real_bits=0x1b... < min_diff=0x1d...).
        assert!(
            testnet4_bits < testnet3_bits,
            "BIP94 must yield harder difficulty than non-BIP94 in time-warp scenario",
        );
    }

    #[test]
    fn test_bip94_get_next_work_required_end_to_end() {
        // End-to-end: drive get_next_work_required (the entry point that
        // validation calls) on a testnet4 retarget boundary and confirm
        // it consults first_block.bits, not last_block.bits.
        let real_bits = 0x1b0404cb;
        let min_diff = POW_LIMIT_TESTNET;
        let first_time: u32 = 1700000000;

        // Build a 2016-block period: height 0..=2015. first block (height 0)
        // has real difficulty, last block (height 2015) is min-diff after a
        // string of min-diff blocks. The next block to validate is height 2016
        // (a retarget boundary).
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: min_diff,
            timestamp: first_time + (TARGET_TIMESPAN as u32),
        };

        let new_block_time = last_block.timestamp + TARGET_SPACING as u32;

        // Ancestor lookup returns the period's first block at height 0.
        let result = get_next_work_required(
            &last_block,
            new_block_time,
            Network::Testnet4,
            |h| {
                if h == 0 {
                    Some(BlockIndexInfo {
                        height: 0,
                        bits: real_bits,
                        timestamp: first_time,
                    })
                } else {
                    None
                }
            },
        );

        // BIP94 must compute the new bits from first_block.bits (real_bits),
        // not from last_block.bits (min_diff). With actual_timespan == target,
        // the retarget yields ~first_block.bits.
        assert_eq!(
            result, real_bits,
            "testnet4 retarget must use first_block.bits (BIP94); got {:#010x}, want {:#010x}",
            result, real_bits,
        );

        // Cross-check: the same call on testnet3 (no BIP94) yields the
        // last_block.bits result (min_diff). The two networks MUST produce
        // different nBits for the same scenario.
        let result_testnet3 = get_next_work_required(
            &last_block,
            new_block_time,
            Network::Testnet,
            |h| {
                if h == 0 {
                    Some(BlockIndexInfo {
                        height: 0,
                        bits: real_bits,
                        timestamp: first_time,
                    })
                } else {
                    None
                }
            },
        );
        assert_ne!(
            result, result_testnet3,
            "testnet4 (BIP94) and testnet3 paths must diverge at retarget; \
             both returned {:#010x}",
            result,
        );
    }

    #[test]
    fn test_bip94_matches_python_path_on_simple_retarget() {
        // Mirror the Python path in src/ouroboros/validation.py:691-696:
        //   if self.network == "testnet4":
        //       old_target = _bits_to_target(period_start_block.bits)
        //   else:
        //       old_target = _bits_to_target(prev_block.bits)
        //
        // For a clean retarget (actual == target timespan), BIP94 yields
        // first_block.bits exactly; the legacy Rust path (using
        // last_block.bits) would yield last_block.bits and silently fork.
        let testnet4_params = get_consensus_params(Network::Testnet4);
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: 0x1d00abcd,        // Different from first; pre-fix would emit ~this
            timestamp: 1700000000 + (TARGET_TIMESPAN as u32),
        };
        let first = BlockIndexInfo {
            height: 0,
            bits: 0x1c00ffff,        // The "real" period-start difficulty
            timestamp: 1700000000,
        };

        let bits = calculate_next_work_required(&last_block, &first, &testnet4_params);

        // BIP94 must base retarget on first.bits, giving ~first.bits exactly
        // (because actual_timespan == TARGET_TIMESPAN). The pre-fix code
        // would have emitted ~last_block.bits (0x1d00abcd) instead.
        assert_eq!(
            bits, first.bits,
            "BIP94 must emit first.bits ({:#010x}); pre-fix code would have emitted \
             ~last_block.bits ({:#010x}). got {:#010x}",
            first.bits, last_block.bits, bits,
        );
        assert_ne!(
            bits, last_block.bits,
            "BIP94 must NOT emit last_block.bits ({:#010x}) — that is the bug \
             fixed by wiring first_block.bits through calculate_next_work_required",
            last_block.bits,
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_bip94_wrapper_matches_canonical_path() {
        // The deprecated calculate_next_work_required_bip94 wrapper must
        // remain byte-identical with the canonical path for all networks.
        let last_block = BlockIndexInfo {
            height: 2015,
            bits: 0x1d00abcd,
            timestamp: 1700000000 + (TARGET_TIMESPAN as u32),
        };
        let first = BlockIndexInfo {
            height: 0,
            bits: 0x1c00ffff,
            timestamp: 1700000000,
        };

        for network in [Network::Bitcoin, Network::Testnet, Network::Testnet4] {
            let params = get_consensus_params(network);
            let canonical = calculate_next_work_required(&last_block, &first, &params);
            let deprecated = calculate_next_work_required_bip94(&last_block, &first, &params);
            assert_eq!(
                canonical, deprecated,
                "deprecated wrapper must match canonical path on network {:?}",
                network,
            );
        }
    }
}
