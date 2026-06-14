//! BIP68 Sequence Lock validation
//!
//! This module implements BIP68 relative lock-time enforcement for transaction
//! inputs. Sequence numbers can encode relative timelocks that must be satisfied
//! before a transaction can be included in a block.
//!
//! Reference: Bitcoin Core consensus/tx_verify.cpp CalculateSequenceLocks, EvaluateSequenceLocks

use bitcoin::Network;

// BIP68 constants (from Bitcoin Core primitives/transaction.h)
/// If this flag is set, sequence is NOT treated as a relative lock-time
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// If this flag is set, the lock-time is time-based; otherwise it's block-based
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Mask for the lower 16 bits which contain the lock value
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;

/// Time-based locks are measured in 512-second intervals
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9; // 2^9 = 512 seconds

/// Special sequence value indicating the input is final
pub const SEQUENCE_FINAL: u32 = 0xFFFFFFFF;

// Flag passed to CalculateSequenceLocks (from Bitcoin Core consensus/consensus.h)
/// Verify sequence numbers according to BIP68
pub const LOCKTIME_VERIFY_SEQUENCE: u32 = 1 << 0;

// BIP68/112 (CSV) activation heights per network
/// Returns the BIP68 (CSV) activation height for the given network.
pub fn csv_activation_height(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 419328,     // mainnet
        Network::Testnet => 770112,     // testnet3
        Network::Testnet4 => 0,         // active from genesis
        Network::Signet => 0,           // active from genesis
        Network::Regtest => 0,          // active from genesis
        #[allow(unreachable_patterns)]
        _ => 0,                         // conservative default
    }
}

/// Represents the calculated sequence lock requirements for a transaction.
///
/// A transaction is sequence-locked until `min_height` blocks have passed
/// and `min_time` seconds of median time past have elapsed.
///
/// Values of -1 mean "no lock of this type required".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceLock {
    /// Minimum block height at which the tx can be included.
    /// This is the "last invalid height" — tx is valid at height > min_height.
    /// -1 means no height-based lock.
    pub min_height: i32,

    /// Minimum median time past at which the tx can be included.
    /// This is the "last invalid time" — tx is valid when MTP > min_time.
    /// -1 means no time-based lock.
    pub min_time: i64,
}

impl SequenceLock {
    /// Create a new sequence lock with no constraints (-1, -1)
    pub fn new() -> Self {
        Self {
            min_height: -1,
            min_time: -1,
        }
    }
}

impl Default for SequenceLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Input data needed to calculate sequence locks for a transaction input.
#[derive(Debug, Clone)]
pub struct InputLockInfo {
    /// The nSequence value for this input
    pub sequence: u32,
    /// The height at which the referenced UTXO was confirmed
    pub prev_height: u32,
    /// The median time past of the block at (prev_height - 1).
    /// This is the "coin time" used for time-based locks.
    pub prev_median_time: i64,
}

/// BIP-68 applies only when version >= 2. Core stores version as uint32_t and
/// compares it UNSIGNED (fEnforceBIP68 = tx.version >= 2, tx_verify.cpp:51), so a
/// high-bit version (e.g. 0x80000002) STILL enforces BIP-68. ouroboros decodes the
/// version as i32 (signed); a signed comparison would treat 0x80000002 as negative
/// and SKIP enforcement, false-accepting a tx with an unmet relative timelock (a
/// chain split). Cast to u32 to match Core exactly.
pub fn bip68_version_active(version: i32) -> bool {
    (version as u32) >= 2
}

/// Calculate sequence locks for a transaction.
///
/// This mirrors Bitcoin Core's `CalculateSequenceLocks()` in consensus/tx_verify.cpp.
///
/// For each input where `nSequence` bit 31 is NOT set:
/// - If bit 22 is set: interpret lower 16 bits as 512-second granularity time lock
/// - If bit 22 is clear: interpret lower 16 bits as block-height lock
///
/// # Arguments
/// * `tx_version` - Transaction version (BIP68 only applies to version >= 2)
/// * `inputs` - Input lock information for each transaction input
/// * `enforce_bip68` - Whether BIP68 is active (based on block height and LOCKTIME_VERIFY_SEQUENCE flag)
///
/// # Returns
/// A `SequenceLock` containing the minimum height and time requirements.
pub fn calculate_sequence_locks(
    tx_version: i32,
    inputs: &[InputLockInfo],
    enforce_bip68: bool,
) -> SequenceLock {
    let mut lock = SequenceLock::new();

    // BIP68 only applies to transactions version 2 or higher (compared unsigned).
    if !bip68_version_active(tx_version) || !enforce_bip68 {
        return lock;
    }

    for input in inputs {
        // Skip inputs with disable flag set (bit 31)
        if input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }

        // Extract the lock value (lower 16 bits)
        let lock_value = (input.sequence & SEQUENCE_LOCKTIME_MASK) as i64;

        if input.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            // Time-based lock (bit 22 is set)
            // Time-based locks are measured from the MTP of the block prior to the
            // block containing the UTXO being spent (i.e., prev_height - 1).
            //
            // The lock value is in 512-second granularity.
            // We subtract 1 to convert from "first valid time" to "last invalid time"
            // semantics (matching nLockTime behavior).
            let coin_time = input.prev_median_time;
            let time_lock = coin_time + (lock_value << SEQUENCE_LOCKTIME_GRANULARITY) - 1;
            lock.min_time = lock.min_time.max(time_lock);
        } else {
            // Height-based lock (bit 22 is clear)
            // Height-based locks are measured from the height of the block
            // containing the UTXO being spent.
            //
            // We subtract 1 to convert from "first valid height" to "last invalid height"
            // semantics (matching nLockTime behavior).
            let height_lock = (input.prev_height as i32) + (lock_value as i32) - 1;
            lock.min_height = lock.min_height.max(height_lock);
        }
    }

    lock
}

/// Evaluate whether sequence locks are satisfied for inclusion in a block.
///
/// This mirrors Bitcoin Core's `EvaluateSequenceLocks()` in consensus/tx_verify.cpp.
///
/// # Arguments
/// * `lock` - The calculated sequence lock requirements
/// * `block_height` - Height of the block where the tx would be included
/// * `block_median_time` - Median time past of the *previous* block
///
/// # Returns
/// `true` if the sequence locks are satisfied, `false` otherwise.
pub fn evaluate_sequence_locks(
    lock: &SequenceLock,
    block_height: u32,
    block_median_time: i64,
) -> bool {
    // Block height check: min_height < block_height
    // (min_height is the "last invalid height", so tx is valid at heights > min_height)
    if lock.min_height >= block_height as i32 {
        return false;
    }

    // Time check: min_time < block_median_time
    // (min_time is the "last invalid time", so tx is valid when MTP > min_time)
    if lock.min_time >= block_median_time {
        return false;
    }

    true
}

/// Check if a transaction satisfies BIP68 sequence locks for inclusion in a block.
///
/// This is a convenience function that combines `calculate_sequence_locks()` and
/// `evaluate_sequence_locks()`.
///
/// # Arguments
/// * `tx_version` - Transaction version
/// * `inputs` - Input lock information for each transaction input
/// * `block_height` - Height of the block where the tx would be included
/// * `block_median_time` - Median time past of the previous block
/// * `enforce_bip68` - Whether BIP68 is active
///
/// # Returns
/// `true` if the transaction satisfies all sequence locks, `false` otherwise.
pub fn check_sequence_locks(
    tx_version: i32,
    inputs: &[InputLockInfo],
    block_height: u32,
    block_median_time: i64,
    enforce_bip68: bool,
) -> bool {
    let lock = calculate_sequence_locks(tx_version, inputs, enforce_bip68);
    evaluate_sequence_locks(&lock, block_height, block_median_time)
}

/// Check if BIP68 sequence locks should be enforced for a given height and network.
pub fn is_bip68_active(height: u32, network: Network) -> bool {
    height >= csv_activation_height(network)
}

/// Locktime threshold: values below this are block heights, above are Unix timestamps.
/// Reference: Bitcoin Core consensus/consensus.h LOCKTIME_THRESHOLD
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Check if a transaction is final for inclusion in a block.
///
/// A transaction is final if:
/// - nLockTime == 0, OR
/// - nLockTime < threshold (block height or MTP depending on type), OR
/// - All inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
///
/// Reference: Bitcoin Core IsFinalTx() in consensus/tx_verify.cpp
///
/// # Arguments
/// * `locktime` - Transaction nLockTime
/// * `sequences` - List of nSequence values for each input
/// * `block_height` - Height of the block where the tx would be included
/// * `block_mtp` - Median time past of the previous block (BIP 113)
///
/// # Returns
/// `true` if the transaction is final, `false` otherwise.
pub fn is_final_tx(
    locktime: u32,
    sequences: &[u32],
    block_height: u32,
    block_mtp: i64,
) -> bool {
    // nLockTime == 0 means the tx is always final
    if locktime == 0 {
        return true;
    }

    // All inputs with SEQUENCE_FINAL → tx is final regardless of locktime
    if sequences.iter().all(|&seq| seq == SEQUENCE_FINAL) {
        return true;
    }

    // Determine threshold to compare against
    if locktime < LOCKTIME_THRESHOLD {
        // Height-based locktime: tx is final when locktime < block_height
        locktime < block_height
    } else {
        // Time-based locktime (BIP 113): tx is final when locktime < MTP
        (locktime as i64) < block_mtp
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip68_version_active_compares_unsigned() {
        // Core compares version unsigned (uint32_t, tx_verify.cpp:51): a high-bit
        // version still enforces BIP-68. A signed >= 2 (the bug) treats 0x80000002
        // (= -2147483646 as i32) as < 2 and skips enforcement.
        assert!(bip68_version_active(0x8000_0002u32 as i32));
        assert!(bip68_version_active(0xFFFF_FFFFu32 as i32));
        assert!(bip68_version_active(2));
        assert!(bip68_version_active(3));
        assert!(!bip68_version_active(1));
        assert!(!bip68_version_active(0));
    }

    #[test]
    fn test_sequence_lock_constants() {
        // Verify constants match Bitcoin Core definitions
        assert_eq!(SEQUENCE_LOCKTIME_DISABLE_FLAG, 0x80000000);
        assert_eq!(SEQUENCE_LOCKTIME_TYPE_FLAG, 0x00400000);
        assert_eq!(SEQUENCE_LOCKTIME_MASK, 0x0000FFFF);
        assert_eq!(SEQUENCE_LOCKTIME_GRANULARITY, 9);
        assert_eq!(SEQUENCE_FINAL, 0xFFFFFFFF);
    }

    #[test]
    fn test_csv_activation_heights() {
        assert_eq!(csv_activation_height(Network::Bitcoin), 419328);
        assert_eq!(csv_activation_height(Network::Testnet4), 0);
        assert_eq!(csv_activation_height(Network::Regtest), 0);
    }

    #[test]
    fn test_sequence_lock_disabled_flag() {
        // Input with disable flag set should not contribute to locks
        let inputs = vec![InputLockInfo {
            sequence: SEQUENCE_LOCKTIME_DISABLE_FLAG | 100, // Disable flag + 100 blocks
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        assert_eq!(lock.min_height, -1);
        assert_eq!(lock.min_time, -1);
    }

    #[test]
    fn test_sequence_lock_final() {
        // SEQUENCE_FINAL has the disable flag set
        let inputs = vec![InputLockInfo {
            sequence: SEQUENCE_FINAL,
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        assert_eq!(lock.min_height, -1);
        assert_eq!(lock.min_time, -1);
    }

    #[test]
    fn test_sequence_lock_height_based() {
        // Height-based lock: 100 blocks relative lock
        let inputs = vec![InputLockInfo {
            sequence: 100, // No flags, just 100 blocks
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        // min_height = prev_height + lock_value - 1 = 1000 + 100 - 1 = 1099
        assert_eq!(lock.min_height, 1099);
        assert_eq!(lock.min_time, -1);

        // Should be valid at height 1100 or later
        assert!(!evaluate_sequence_locks(&lock, 1099, 0));
        assert!(!evaluate_sequence_locks(&lock, 1000, 0));
        assert!(evaluate_sequence_locks(&lock, 1100, 0));
        assert!(evaluate_sequence_locks(&lock, 1200, 0));
    }

    #[test]
    fn test_sequence_lock_time_based() {
        // Time-based lock: 1 * 512 seconds = 512 seconds relative lock
        let inputs = vec![InputLockInfo {
            sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 1, // Type flag + 1 unit
            prev_height: 1000,
            prev_median_time: 1600000000, // Coin time
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        assert_eq!(lock.min_height, -1);
        // min_time = coin_time + (1 << 9) - 1 = 1600000000 + 512 - 1 = 1600000511
        assert_eq!(lock.min_time, 1600000511);

        // Should be valid when MTP > 1600000511
        assert!(!evaluate_sequence_locks(&lock, 2000, 1600000511));
        assert!(!evaluate_sequence_locks(&lock, 2000, 1600000500));
        assert!(evaluate_sequence_locks(&lock, 2000, 1600000512));
        assert!(evaluate_sequence_locks(&lock, 2000, 1700000000));
    }

    #[test]
    fn test_sequence_lock_multiple_inputs() {
        // Multiple inputs with different locks - take the maximum
        let inputs = vec![
            InputLockInfo {
                sequence: 50, // 50 blocks
                prev_height: 1000,
                prev_median_time: 1600000000,
            },
            InputLockInfo {
                sequence: 100, // 100 blocks
                prev_height: 900, // Earlier confirmation
                prev_median_time: 1599000000,
            },
            InputLockInfo {
                sequence: SEQUENCE_LOCKTIME_DISABLE_FLAG, // Disabled
                prev_height: 800,
                prev_median_time: 1598000000,
            },
        ];

        let lock = calculate_sequence_locks(2, &inputs, true);
        // Input 0: 1000 + 50 - 1 = 1049
        // Input 1: 900 + 100 - 1 = 999
        // Input 2: disabled
        // Max = 1049
        assert_eq!(lock.min_height, 1049);
        assert_eq!(lock.min_time, -1);
    }

    #[test]
    fn test_sequence_lock_mixed_height_and_time() {
        let inputs = vec![
            InputLockInfo {
                sequence: 100, // Height-based: 100 blocks
                prev_height: 1000,
                prev_median_time: 1600000000,
            },
            InputLockInfo {
                sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 10, // Time-based: 10 * 512 = 5120 seconds
                prev_height: 1000,
                prev_median_time: 1600000000,
            },
        ];

        let lock = calculate_sequence_locks(2, &inputs, true);
        // Height: 1000 + 100 - 1 = 1099
        // Time: 1600000000 + (10 * 512) - 1 = 1600005119
        assert_eq!(lock.min_height, 1099);
        assert_eq!(lock.min_time, 1600005119);

        // Need both conditions to be satisfied
        assert!(!evaluate_sequence_locks(&lock, 1100, 1600000000)); // Height OK, time not
        assert!(!evaluate_sequence_locks(&lock, 1000, 1600005120)); // Time OK, height not
        assert!(evaluate_sequence_locks(&lock, 1100, 1600005120)); // Both OK
    }

    #[test]
    fn test_sequence_lock_version_1_ignored() {
        // BIP68 does not apply to version 1 transactions
        let inputs = vec![InputLockInfo {
            sequence: 100,
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(1, &inputs, true);
        assert_eq!(lock.min_height, -1);
        assert_eq!(lock.min_time, -1);
    }

    #[test]
    fn test_sequence_lock_bip68_not_enforced() {
        // When BIP68 is not enforced, sequence locks are ignored
        let inputs = vec![InputLockInfo {
            sequence: 100,
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, false);
        assert_eq!(lock.min_height, -1);
        assert_eq!(lock.min_time, -1);
    }

    #[test]
    fn test_check_sequence_locks_convenience() {
        let inputs = vec![InputLockInfo {
            sequence: 100,
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        // Should fail at height 1099
        assert!(!check_sequence_locks(2, &inputs, 1099, 0, true));
        // Should pass at height 1100
        assert!(check_sequence_locks(2, &inputs, 1100, 0, true));
    }

    #[test]
    fn test_bip68_activation() {
        // Mainnet activation at 419328
        assert!(!is_bip68_active(419327, Network::Bitcoin));
        assert!(is_bip68_active(419328, Network::Bitcoin));
        assert!(is_bip68_active(500000, Network::Bitcoin));

        // Testnet4 active from genesis
        assert!(is_bip68_active(0, Network::Testnet4));
        assert!(is_bip68_active(100, Network::Testnet4));
    }

    #[test]
    fn test_sequence_lock_zero_value() {
        // A sequence of 0 with no flags means "lock for 0 blocks"
        let inputs = vec![InputLockInfo {
            sequence: 0, // 0 blocks relative lock
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        // min_height = 1000 + 0 - 1 = 999
        assert_eq!(lock.min_height, 999);
        // Should be valid at height 1000 or later
        assert!(evaluate_sequence_locks(&lock, 1000, 0));
    }

    #[test]
    fn test_sequence_lock_max_value() {
        // Maximum lock value is 0xFFFF (65535)
        let inputs = vec![InputLockInfo {
            sequence: SEQUENCE_LOCKTIME_MASK, // Max blocks
            prev_height: 1000,
            prev_median_time: 1600000000,
        }];

        let lock = calculate_sequence_locks(2, &inputs, true);
        // min_height = 1000 + 65535 - 1 = 66534
        assert_eq!(lock.min_height, 66534);
    }

    // =========================================================================
    // is_final_tx tests
    // =========================================================================

    #[test]
    fn test_is_final_tx_zero_locktime() {
        // nLockTime == 0 is always final
        let sequences = vec![0u32, 0u32]; // non-final sequences
        assert!(is_final_tx(0, &sequences, 100, 1600000000));
    }

    #[test]
    fn test_is_final_tx_all_sequences_final() {
        // All inputs with SEQUENCE_FINAL makes tx final regardless of locktime
        let sequences = vec![SEQUENCE_FINAL, SEQUENCE_FINAL];
        // Locktime in the future
        assert!(is_final_tx(1000, &sequences, 100, 1600000000));
        // Time-based locktime in the future
        assert!(is_final_tx(1700000000, &sequences, 100, 1600000000));
    }

    #[test]
    fn test_is_final_tx_height_based() {
        let sequences = vec![0u32]; // non-final sequence

        // locktime 100, block height 99 → NOT final
        assert!(!is_final_tx(100, &sequences, 99, 0));
        // locktime 100, block height 100 → NOT final (locktime must be < height)
        assert!(!is_final_tx(100, &sequences, 100, 0));
        // locktime 100, block height 101 → final
        assert!(is_final_tx(100, &sequences, 101, 0));
    }

    #[test]
    fn test_is_final_tx_time_based() {
        let sequences = vec![0u32]; // non-final sequence
        let locktime = 1600000000u32; // Time-based (>= 500_000_000)

        // MTP = 1599999999 → NOT final
        assert!(!is_final_tx(locktime, &sequences, 1000, 1599999999));
        // MTP = 1600000000 → NOT final (locktime must be < MTP)
        assert!(!is_final_tx(locktime, &sequences, 1000, 1600000000));
        // MTP = 1600000001 → final
        assert!(is_final_tx(locktime, &sequences, 1000, 1600000001));
    }

    #[test]
    fn test_is_final_tx_mixed_sequences() {
        // One SEQUENCE_FINAL, one non-final → uses locktime check
        let sequences = vec![SEQUENCE_FINAL, 0u32];
        // Locktime 100, height 99 → NOT final
        assert!(!is_final_tx(100, &sequences, 99, 0));
        // Locktime 100, height 101 → final
        assert!(is_final_tx(100, &sequences, 101, 0));
    }

    #[test]
    fn test_locktime_threshold_boundary() {
        let sequences = vec![0u32];

        // Just below threshold (499_999_999) → height-based
        assert!(is_final_tx(499_999_999, &sequences, 500_000_000, 0));
        assert!(!is_final_tx(499_999_999, &sequences, 499_999_998, 0));

        // At threshold (500_000_000) → time-based
        assert!(is_final_tx(500_000_000, &sequences, 0, 500_000_001));
        assert!(!is_final_tx(500_000_000, &sequences, 0, 500_000_000));
    }
}
