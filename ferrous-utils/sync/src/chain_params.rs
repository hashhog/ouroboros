//! Chain parameters for different Bitcoin networks
//!
//! Provides genesis block hashes and timestamps for block metadata and fallback lookups.
//! Also includes consensus parameters for difficulty adjustment, anti-DoS thresholds,
//! hardcoded checkpoints, and minimum chain work.
//!
//! Reference: Bitcoin Core chainparams.cpp

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
        // Regtest genesis: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
        Network::Regtest => [
            0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
            0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
            0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
            0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
        ],
        // Signet genesis: 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
        Network::Signet => [
            0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4,
            0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
            0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25,
            0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
        ],
        #[allow(unreachable_patterns)]
        _ => [0u8; 32],
    }
}

/// Genesis block bits (compact target) for each network.
pub fn genesis_bits(network: Network) -> u32 {
    match network {
        // Regtest uses minimum difficulty: 0x207fffff
        Network::Regtest => 0x207fffff,
        // Signet uses custom difficulty
        Network::Signet => 0x1e0377ae,
        // All others use difficulty 1: 0x1d00ffff
        _ => 0x1d00ffff,
    }
}

// =============================================================================
// Checkpoints
// =============================================================================

/// A checkpoint: a known-good (height, block_hash) pair.
///
/// Checkpoints are used to:
/// 1. Prevent DoS by rejecting forks that branch before the last checkpoint
/// 2. Speed up IBD by skipping script validation for blocks below checkpoints
///
/// Reference: Bitcoin Core chainparams.cpp checkpointData
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: [u8; 32],
}

impl Checkpoint {
    /// Create a new checkpoint from height and hash (internal byte order).
    pub const fn new(height: u32, hash: [u8; 32]) -> Self {
        Self { height, hash }
    }

    /// Create a checkpoint from a hex string (big-endian display order).
    /// Panics if the hex string is invalid.
    pub fn from_hex(height: u32, hex: &str) -> Self {
        let mut hash = [0u8; 32];
        // Bitcoin block hashes are displayed in big-endian but stored in little-endian
        let bytes = hex::decode(hex).expect("Invalid checkpoint hex");
        assert_eq!(bytes.len(), 32, "Checkpoint hash must be 32 bytes");
        // Reverse to internal byte order (little-endian)
        for (i, b) in bytes.iter().enumerate() {
            hash[31 - i] = *b;
        }
        Self { height, hash }
    }
}

/// Get checkpoints for a network.
///
/// Returns a list of (height, hash) pairs representing known-good blocks.
/// During IBD, blocks at or before the last checkpoint can skip script validation
/// (only PoW and merkle root are verified).
///
/// Reference: Bitcoin Core chainparams.cpp checkpointData
pub fn get_checkpoints(network: Network) -> Vec<Checkpoint> {
    match network {
        Network::Bitcoin => vec![
            // Selected mainnet checkpoints from Bitcoin Core
            // These are permanent - once set, they should never change
            Checkpoint::from_hex(11111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
            Checkpoint::from_hex(33333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
            Checkpoint::from_hex(74000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
            Checkpoint::from_hex(105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
            Checkpoint::from_hex(134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
            Checkpoint::from_hex(168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
            Checkpoint::from_hex(193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
            Checkpoint::from_hex(210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
            Checkpoint::from_hex(216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
            Checkpoint::from_hex(225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
            Checkpoint::from_hex(250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
            Checkpoint::from_hex(279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
            Checkpoint::from_hex(295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"),
            Checkpoint::from_hex(478559, "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43"),
            Checkpoint::from_hex(556767, "0000000000000000000f1c54590ee18d15ec70e68ae69f6a189353478d13b113"),
            Checkpoint::from_hex(630000, "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d"),
            Checkpoint::from_hex(740000, "000000000000000000021e8758bc1d04ebcd96cc81e2e626acdc0e2d05ec19c5"),
            Checkpoint::from_hex(850000, "00000000000000000001fcf3bf89d71a1f44c6da86dcd0c1f2a90dd1c6097eba"),
        ],
        Network::Testnet => vec![
            // Testnet3 checkpoints
            Checkpoint::from_hex(546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
        ],
        Network::Testnet4 => vec![
            // Testnet4 is relatively new, minimal checkpoints
            // Genesis is the only certain one
        ],
        Network::Signet => vec![
            // Signet checkpoints (optional, signet has signed blocks)
        ],
        Network::Regtest => vec![
            // No checkpoints for regtest (testing)
        ],
        #[allow(unreachable_patterns)]
        _ => vec![],
    }
}

/// Get the last checkpoint for a network.
///
/// Returns None if no checkpoints are defined.
pub fn get_last_checkpoint(network: Network) -> Option<Checkpoint> {
    get_checkpoints(network).into_iter().last()
}

/// Get checkpoint at a specific height, if one exists.
pub fn get_checkpoint_at_height(network: Network, height: u32) -> Option<Checkpoint> {
    get_checkpoints(network)
        .into_iter()
        .find(|cp| cp.height == height)
}

/// Check if a height is at or before the last checkpoint.
///
/// Used to determine if script validation can be skipped during IBD.
pub fn is_below_last_checkpoint(network: Network, height: u32) -> bool {
    get_last_checkpoint(network)
        .map(|cp| height <= cp.height)
        .unwrap_or(false)
}

/// Verify a block hash matches the checkpoint at that height.
///
/// Returns:
/// - Some(true) if checkpoint exists and hash matches
/// - Some(false) if checkpoint exists and hash does NOT match (invalid!)
/// - None if no checkpoint at that height
pub fn verify_checkpoint(network: Network, height: u32, block_hash: &[u8; 32]) -> Option<bool> {
    get_checkpoint_at_height(network, height).map(|cp| &cp.hash == block_hash)
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
        // Regtest and Signet share testnet3 timestamp
        Network::Regtest => 1296688602,
        Network::Signet => 1598918400,
        #[allow(unreachable_patterns)]
        _ => 0,
    }
}

/// Genesis block nonce for each network.
pub fn genesis_nonce(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 2083236893,
        Network::Testnet => 414098458,
        Network::Testnet4 => 393743547,
        // Regtest uses nonce=2 (very easy difficulty, found instantly)
        Network::Regtest => 2,
        Network::Signet => 52613770,
        #[allow(unreachable_patterns)]
        _ => 0,
    }
}

/// Get BIP activation heights for a network.
///
/// Returns (BIP34, BIP65, BIP66, CSV, SegWit) activation heights.
/// For regtest, all soft forks are active from height 0 or 1.
pub fn bip_activation_heights(network: Network) -> (u32, u32, u32, u32, u32) {
    match network {
        Network::Bitcoin => (
            227931,  // BIP34
            388381,  // BIP65 (CLTV)
            363725,  // BIP66 (strict DER)
            419328,  // CSV
            481824,  // SegWit
        ),
        Network::Testnet => (
            21111,   // BIP34
            581885,  // BIP65
            330776,  // BIP66
            770112,  // CSV
            834624,  // SegWit
        ),
        Network::Testnet4 => (
            1, 1, 1, 1, 1, // All active from height 1
        ),
        Network::Signet => (
            1, 1, 1, 1, 1, // All active from height 1
        ),
        // Regtest: all soft forks active from genesis (height 0 for SegWit, 1 for others)
        Network::Regtest => (
            1,  // BIP34
            1,  // BIP65
            1,  // BIP66
            1,  // CSV
            0,  // SegWit (active from genesis)
        ),
        #[allow(unreachable_patterns)]
        _ => (0, 0, 0, 0, 0),
    }
}

/// Check if all soft forks are active from genesis for this network.
///
/// Returns true for regtest where all consensus rules apply from block 0.
pub fn all_forks_active_from_genesis(network: Network) -> bool {
    matches!(network, Network::Regtest | Network::Testnet4 | Network::Signet)
}

/// Default port for P2P connections on each network.
pub fn default_p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Testnet4 => 48333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
        #[allow(unreachable_patterns)]
        _ => 8333,
    }
}

/// Default port for RPC server on each network.
pub fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
        #[allow(unreachable_patterns)]
        _ => 8332,
    }
}

/// Subsidy halving interval for each network.
pub fn subsidy_halving_interval(network: Network) -> u32 {
    match network {
        // Regtest has a very short halving interval for testing
        Network::Regtest => 150,
        // All other networks use 210,000 blocks (~4 years)
        _ => 210000,
    }
}

/// Check if this is a regtest network (for special handling).
pub fn is_regtest(network: Network) -> bool {
    matches!(network, Network::Regtest)
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

    // =========================================================================
    // Checkpoint tests
    // =========================================================================

    #[test]
    fn test_checkpoint_from_hex() {
        // Test with a known mainnet checkpoint (block 11111)
        let cp = Checkpoint::from_hex(
            11111,
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
        );
        assert_eq!(cp.height, 11111);
        // Hash should be in internal byte order (little-endian)
        assert_eq!(cp.hash[31], 0x00); // First byte of display hex is last in internal
        assert_eq!(cp.hash[0], 0x1d);  // Last byte of display hex is first in internal
    }

    #[test]
    fn test_get_checkpoints_mainnet() {
        let checkpoints = get_checkpoints(Network::Bitcoin);
        // Mainnet should have several checkpoints
        assert!(!checkpoints.is_empty());
        // First checkpoint should be at height 11111
        assert_eq!(checkpoints[0].height, 11111);
        // Checkpoints should be in ascending order
        for i in 1..checkpoints.len() {
            assert!(checkpoints[i].height > checkpoints[i - 1].height);
        }
    }

    #[test]
    fn test_get_checkpoints_testnet() {
        let checkpoints = get_checkpoints(Network::Testnet);
        // Testnet3 has at least one checkpoint
        assert!(!checkpoints.is_empty());
        assert_eq!(checkpoints[0].height, 546);
    }

    #[test]
    fn test_get_checkpoints_regtest() {
        let checkpoints = get_checkpoints(Network::Regtest);
        // Regtest has no checkpoints
        assert!(checkpoints.is_empty());
    }

    #[test]
    fn test_get_last_checkpoint_mainnet() {
        let last_cp = get_last_checkpoint(Network::Bitcoin);
        assert!(last_cp.is_some());
        let cp = last_cp.unwrap();
        // Last mainnet checkpoint should be at a high block
        assert!(cp.height > 800_000);
    }

    #[test]
    fn test_get_last_checkpoint_regtest() {
        let last_cp = get_last_checkpoint(Network::Regtest);
        // Regtest has no checkpoints
        assert!(last_cp.is_none());
    }

    #[test]
    fn test_is_below_last_checkpoint() {
        // Mainnet: blocks below last checkpoint
        assert!(is_below_last_checkpoint(Network::Bitcoin, 100));
        assert!(is_below_last_checkpoint(Network::Bitcoin, 500_000));

        // Get actual last checkpoint height
        let last_cp = get_last_checkpoint(Network::Bitcoin).unwrap();

        // Height equal to last checkpoint is still "below"
        assert!(is_below_last_checkpoint(Network::Bitcoin, last_cp.height));

        // Height above last checkpoint is not "below"
        assert!(!is_below_last_checkpoint(Network::Bitcoin, last_cp.height + 1));

        // Regtest has no checkpoints, so nothing is "below"
        assert!(!is_below_last_checkpoint(Network::Regtest, 100));
    }

    #[test]
    fn test_get_checkpoint_at_height() {
        // Should find checkpoint at height 11111
        let cp = get_checkpoint_at_height(Network::Bitcoin, 11111);
        assert!(cp.is_some());
        assert_eq!(cp.unwrap().height, 11111);

        // Should not find checkpoint at arbitrary height
        let no_cp = get_checkpoint_at_height(Network::Bitcoin, 12345);
        assert!(no_cp.is_none());
    }

    #[test]
    fn test_verify_checkpoint_match() {
        // Get the checkpoint at height 11111
        let cp = get_checkpoint_at_height(Network::Bitcoin, 11111).unwrap();

        // Verify with correct hash should return Some(true)
        let result = verify_checkpoint(Network::Bitcoin, 11111, &cp.hash);
        assert_eq!(result, Some(true));

        // Verify with wrong hash should return Some(false)
        let wrong_hash = [0u8; 32];
        let result = verify_checkpoint(Network::Bitcoin, 11111, &wrong_hash);
        assert_eq!(result, Some(false));

        // Verify at non-checkpoint height should return None
        let result = verify_checkpoint(Network::Bitcoin, 12345, &cp.hash);
        assert_eq!(result, None);
    }

    // =========================================================================
    // Regtest-specific tests
    // =========================================================================

    #[test]
    fn test_regtest_genesis_hash() {
        let hash = genesis_block_hash(Network::Regtest);
        // Regtest genesis hash: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
        // In internal byte order (little-endian), last byte is 0x0f
        assert_eq!(hash[31], 0x0f);
        assert_eq!(hash[0], 0x06);
    }

    #[test]
    fn test_regtest_genesis_bits() {
        // Regtest uses minimum difficulty 0x207fffff
        assert_eq!(genesis_bits(Network::Regtest), 0x207fffff);
        // Other networks use standard difficulty 0x1d00ffff
        assert_eq!(genesis_bits(Network::Bitcoin), 0x1d00ffff);
    }

    #[test]
    fn test_regtest_genesis_nonce() {
        // Regtest genesis nonce is 2 (trivial to find at min difficulty)
        assert_eq!(genesis_nonce(Network::Regtest), 2);
    }

    #[test]
    fn test_regtest_all_forks_active() {
        // Regtest has all forks active from genesis
        assert!(all_forks_active_from_genesis(Network::Regtest));
        assert!(all_forks_active_from_genesis(Network::Testnet4));
        assert!(all_forks_active_from_genesis(Network::Signet));
        assert!(!all_forks_active_from_genesis(Network::Bitcoin));
        assert!(!all_forks_active_from_genesis(Network::Testnet));
    }

    #[test]
    fn test_regtest_ports() {
        assert_eq!(default_p2p_port(Network::Regtest), 18444);
        assert_eq!(default_rpc_port(Network::Regtest), 18443);
    }

    #[test]
    fn test_regtest_halving_interval() {
        // Regtest has a short halving interval (150 blocks)
        assert_eq!(subsidy_halving_interval(Network::Regtest), 150);
        // Other networks use 210,000
        assert_eq!(subsidy_halving_interval(Network::Bitcoin), 210000);
    }

    #[test]
    fn test_is_regtest() {
        assert!(is_regtest(Network::Regtest));
        assert!(!is_regtest(Network::Bitcoin));
        assert!(!is_regtest(Network::Testnet));
    }

    #[test]
    fn test_bip_activation_heights_regtest() {
        let (bip34, bip65, bip66, csv, segwit) = bip_activation_heights(Network::Regtest);
        // Regtest: BIP34/65/66/CSV active from height 1, SegWit from height 0
        assert_eq!(bip34, 1);
        assert_eq!(bip65, 1);
        assert_eq!(bip66, 1);
        assert_eq!(csv, 1);
        assert_eq!(segwit, 0);
    }

    #[test]
    fn test_signet_genesis_hash() {
        let hash = genesis_block_hash(Network::Signet);
        // Signet genesis hash: 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
        // In internal byte order, first byte is 0xf6
        assert_eq!(hash[0], 0xf6);
        // Last bytes are leading zeros (00000008...)
        assert_eq!(hash[31], 0x00);
    }
}
