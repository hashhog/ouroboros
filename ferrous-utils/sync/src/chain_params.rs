//! Chain parameters for different Bitcoin networks
//!
//! Provides genesis block hashes and timestamps for block metadata and fallback lookups.
//! Also includes consensus parameters for difficulty adjustment and anti-DoS thresholds.

use bitcoin::Network;
use primitive_types::U256;

/// Consensus parameters for proof-of-work and difficulty adjustment.
///
/// Mirrors Bitcoin Core's Consensus::Params from consensus/params.h.
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    /// PoW limit in compact "bits" format (minimum difficulty)
    pub pow_limit_bits: u32,

    /// Allow min-difficulty blocks (testnet3/testnet4)
    pub pow_allow_min_difficulty_blocks: bool,

    /// No difficulty retargeting (regtest)
    pub pow_no_retargeting: bool,

    /// Enforce BIP94 time warp fix (testnet4)
    pub enforce_bip94: bool,

    /// Target spacing between blocks in seconds (10 minutes)
    pub pow_target_spacing: i64,

    /// Target timespan for difficulty adjustment (2 weeks)
    pub pow_target_timespan: i64,
}

impl ConsensusParams {
    /// Difficulty adjustment interval (number of blocks between adjustments)
    pub fn difficulty_adjustment_interval(&self) -> u32 {
        (self.pow_target_timespan / self.pow_target_spacing) as u32
    }
}

/// Get consensus parameters for a network.
pub fn get_consensus_params(network: Network) -> ConsensusParams {
    match network {
        Network::Bitcoin => ConsensusParams {
            pow_limit_bits: 0x1d00ffff,
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            pow_target_spacing: 10 * 60, // 10 minutes
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
        },
        Network::Testnet => ConsensusParams {
            pow_limit_bits: 0x1d00ffff,
            pow_allow_min_difficulty_blocks: true, // Testnet3 20-minute rule
            pow_no_retargeting: false,
            enforce_bip94: false,
            pow_target_spacing: 10 * 60,
            pow_target_timespan: 14 * 24 * 60 * 60,
        },
        Network::Testnet4 => ConsensusParams {
            pow_limit_bits: 0x1d00ffff,
            pow_allow_min_difficulty_blocks: true, // Testnet4 also has min-diff rule
            pow_no_retargeting: false,
            enforce_bip94: true, // BIP94 time warp fix
            pow_target_spacing: 10 * 60,
            pow_target_timespan: 14 * 24 * 60 * 60,
        },
        Network::Regtest => ConsensusParams {
            pow_limit_bits: 0x207fffff, // Very easy difficulty for regtest
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: true, // No retargeting on regtest
            enforce_bip94: false,
            pow_target_spacing: 10 * 60,
            pow_target_timespan: 14 * 24 * 60 * 60,
        },
        Network::Signet => ConsensusParams {
            pow_limit_bits: 0x1e0377ae, // Signet has different limit
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            pow_target_spacing: 10 * 60,
            pow_target_timespan: 14 * 24 * 60 * 60,
        },
        // Non-exhaustive match for future network variants
        #[allow(unreachable_patterns)]
        _ => ConsensusParams {
            // Default to mainnet params for unknown networks
            pow_limit_bits: 0x1d00ffff,
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            pow_target_spacing: 10 * 60,
            pow_target_timespan: 14 * 24 * 60 * 60,
        },
    }
}

/// Genesis block hash (internal byte order) and timestamp for each network
pub fn genesis_block_hash(network: Network) -> [u8; 32] {
    match network {
        Network::Bitcoin => [
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
            0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
            0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
            0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        Network::Testnet => [
            0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
            0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
            0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
            0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
        ],
        Network::Testnet4 => [
            0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3, 0x5b,
            0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4, 0x7f, 0x50,
            0xae, 0x72, 0x5a, 0xe2, 0xde, 0x53, 0xbc, 0xfb,
            0xba, 0xf2, 0x84, 0xda, 0x00, 0x00, 0x00, 0x00,
        ],
        _ => [0u8; 32],
    }
}

/// Genesis block bits (compact target) for each network.
/// All use 0x1d00ffff (difficulty 1).
pub fn genesis_bits(network: Network) -> u32 {
    let _ = network;
    0x1d00ffff
}

/// nMinimumChainWork: minimum total chain work required during header sync.
///
/// This is the anti-DoS threshold used in PRESYNC/REDOWNLOAD. A peer must demonstrate
/// at least this much cumulative proof-of-work before we permanently store their headers.
/// Values are from Bitcoin Core's chainparams.cpp.
///
/// Reference: bitcoin/src/kernel/chainparams.cpp
pub fn minimum_chain_work(network: Network) -> U256 {
    match network {
        // Mainnet: updated periodically in Bitcoin Core releases
        // From Bitcoin Core 28.0: 0x0000000000000000000000000001128750f82f4c366153a3a030
        Network::Bitcoin => U256::from_str_radix(
            "0001128750f82f4c366153a3a030",
            16,
        ).unwrap_or_else(|_| U256::one()),

        // Testnet3: 0x0000000000000000000000000000000017dde1c649f3708d14b6
        Network::Testnet => U256::from_str_radix(
            "17dde1c649f3708d14b6",
            16,
        ).unwrap_or_else(|_| U256::one()),

        // Testnet4: 0x0000000000000000000000000000000009a0fe15d0177d086304
        Network::Testnet4 => U256::from_str_radix(
            "09a0fe15d0177d086304",
            16,
        ).unwrap_or_else(|_| U256::one()),

        // Signet: 0x00000000000000000000000000000000000000000b463ea0a4b8
        Network::Signet => U256::from_str_radix(
            "0b463ea0a4b8",
            16,
        ).unwrap_or_else(|_| U256::one()),

        // Regtest: no minimum (testing)
        Network::Regtest => U256::zero(),

        // Default for unknown networks
        #[allow(unreachable_patterns)]
        _ => U256::one(),
    }
}

/// Headers presync commitment period: number of blocks between commitment checkpoints.
///
/// During PRESYNC, we store 1-bit commitments at these intervals to verify
/// the peer sends the same chain in REDOWNLOAD. ~640 blocks balances
/// memory usage vs verification security.
///
/// Reference: Bitcoin Core net_processing.cpp HeadersSyncParams
pub fn headers_presync_commitment_period(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 641,
        Network::Testnet => 673,
        Network::Testnet4 => 606,
        Network::Signet => 620,
        Network::Regtest => 275,
        #[allow(unreachable_patterns)]
        _ => 641,
    }
}

/// Headers redownload buffer size: minimum validated headers before releasing to index.
///
/// During REDOWNLOAD, headers are buffered until this many have verified commitments.
/// This provides a "lookahead" that validates headers aren't being substituted.
///
/// Reference: Bitcoin Core net_processing.cpp HeadersSyncParams
pub fn headers_redownload_buffer_size(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 15218,
        Network::Testnet => 14460,
        Network::Testnet4 => 16092,
        Network::Signet => 15724,
        Network::Regtest => 7017,
        #[allow(unreachable_patterns)]
        _ => 15218,
    }
}

/// Genesis block timestamp (Unix time) for each network
pub fn genesis_block_timestamp(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 1231006505,
        Network::Testnet => 1296688602,
        Network::Testnet4 => 1714777860,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_params_mainnet() {
        let params = get_consensus_params(Network::Bitcoin);
        assert_eq!(params.pow_limit_bits, 0x1d00ffff);
        assert!(!params.pow_allow_min_difficulty_blocks);
        assert!(!params.pow_no_retargeting);
        assert!(!params.enforce_bip94);
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
    }

    #[test]
    fn test_consensus_params_testnet() {
        let params = get_consensus_params(Network::Testnet);
        assert_eq!(params.pow_limit_bits, 0x1d00ffff);
        assert!(params.pow_allow_min_difficulty_blocks);
        assert!(!params.pow_no_retargeting);
        assert!(!params.enforce_bip94);
    }

    #[test]
    fn test_consensus_params_testnet4() {
        let params = get_consensus_params(Network::Testnet4);
        assert!(params.pow_allow_min_difficulty_blocks);
        assert!(params.enforce_bip94);
    }

    #[test]
    fn test_consensus_params_regtest() {
        let params = get_consensus_params(Network::Regtest);
        assert_eq!(params.pow_limit_bits, 0x207fffff);
        assert!(params.pow_no_retargeting);
    }

    #[test]
    fn test_difficulty_adjustment_interval() {
        let params = get_consensus_params(Network::Bitcoin);
        // 2 weeks / 10 minutes = 2016 blocks
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
    }

    #[test]
    fn test_minimum_chain_work_mainnet() {
        let min_work = minimum_chain_work(Network::Bitcoin);
        // Mainnet has significant minimum work
        assert!(min_work > U256::from(1_000_000_000u64));
    }

    #[test]
    fn test_minimum_chain_work_regtest() {
        let min_work = minimum_chain_work(Network::Regtest);
        // Regtest has no minimum
        assert_eq!(min_work, U256::zero());
    }

    #[test]
    fn test_minimum_chain_work_testnet() {
        let min_work = minimum_chain_work(Network::Testnet);
        // Testnet has lower minimum than mainnet but still significant
        assert!(min_work > U256::zero());
    }

    #[test]
    fn test_headers_presync_commitment_period() {
        // All networks should have reasonable commitment periods (~600-700 blocks)
        assert_eq!(headers_presync_commitment_period(Network::Bitcoin), 641);
        assert_eq!(headers_presync_commitment_period(Network::Testnet), 673);
        assert_eq!(headers_presync_commitment_period(Network::Testnet4), 606);
        assert_eq!(headers_presync_commitment_period(Network::Signet), 620);
        assert_eq!(headers_presync_commitment_period(Network::Regtest), 275);
    }

    #[test]
    fn test_headers_redownload_buffer_size() {
        // Buffer sizes should be ~15k headers (to verify ~24 commitments)
        let mainnet_buf = headers_redownload_buffer_size(Network::Bitcoin);
        let mainnet_period = headers_presync_commitment_period(Network::Bitcoin);
        // Buffer should hold roughly 23-26 commitment periods
        let commitments_in_buffer = mainnet_buf / mainnet_period;
        assert!(commitments_in_buffer >= 20);
        assert!(commitments_in_buffer <= 30);
    }
}
