//! BIP9 versionbits state machine for soft fork activation
//!
//! Implements the BIP9 deployment state machine:
//! DEFINED -> STARTED -> LOCKED_IN -> ACTIVE (or FAILED)
//!
//! Reference: Bitcoin Core versionbits.cpp, BIP9
//! https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki

use std::collections::HashMap;
use bitcoin::Network;

/// Version bits constants
pub const VERSIONBITS_TOP_BITS: i32 = 0x20000000;
pub const VERSIONBITS_TOP_MASK: i32 = 0xE0000000u32 as i32;
pub const VERSIONBITS_NUM_BITS: usize = 29;

/// BIP9 deployment states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdState {
    /// First state that each softfork starts out as.
    /// The genesis block is by definition in this state for each deployment.
    Defined,
    /// For blocks past the starttime.
    Started,
    /// For at least one retarget period after the first retarget period with STARTED
    /// blocks of which at least threshold have the associated bit set in nVersion,
    /// until min_activation_height is reached.
    LockedIn,
    /// For all blocks after the LOCKED_IN retarget period (final state).
    Active,
    /// For all blocks once the first retarget period after the timeout time is hit,
    /// if LOCKED_IN wasn't already reached (final state).
    Failed,
}

impl ThresholdState {
    /// Get state name (matches Bitcoin Core's StateName())
    pub fn name(&self) -> &'static str {
        match self {
            ThresholdState::Defined => "defined",
            ThresholdState::Started => "started",
            ThresholdState::LockedIn => "locked_in",
            ThresholdState::Active => "active",
            ThresholdState::Failed => "failed",
        }
    }
}

/// Special values for deployment start time
pub const ALWAYS_ACTIVE: i64 = -1;
pub const NEVER_ACTIVE: i64 = -2;

/// BIP9 deployment parameters
#[derive(Debug, Clone)]
pub struct BIP9Deployment {
    /// Bit position to select the particular bit in nVersion (0-28)
    pub bit: u8,
    /// Start MedianTime for version bits miner confirmation
    pub start_time: i64,
    /// Timeout/expiry MedianTime for the deployment attempt
    pub timeout: i64,
    /// Minimum activation height (BIP341 style speedy trial)
    pub min_activation_height: u32,
    /// Human-readable name for the deployment
    pub name: &'static str,
}

impl BIP9Deployment {
    /// Check if a block version signals this deployment
    pub fn check_signal(&self, version: i32) -> bool {
        // Top 3 bits must be 001 (version bits signaling active)
        if (version & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS {
            return false;
        }
        // Check the specific bit
        let mask = 1i32 << self.bit;
        (version & mask) != 0
    }

    /// Get the mask for this deployment's bit
    pub fn mask(&self) -> u32 {
        1u32 << self.bit
    }
}

/// Statistics for an in-progress BIP9 deployment
#[derive(Debug, Clone, Default)]
pub struct BIP9Stats {
    /// Length of blocks of the BIP9 signalling period
    pub period: u32,
    /// Number of blocks with the version bit set required to activate
    pub threshold: u32,
    /// Number of blocks elapsed since the beginning of the current period
    pub elapsed: u32,
    /// Number of blocks with the version bit set since the beginning of the current period
    pub count: u32,
    /// False if there are not enough blocks left in this period to pass activation threshold
    pub possible: bool,
}

/// Deployment thresholds by network
#[derive(Debug, Clone)]
pub struct DeploymentThresholds {
    /// Period for state transitions (typically 2016 blocks)
    pub period: u32,
    /// Required signaling threshold for activation
    pub threshold: u32,
}

impl DeploymentThresholds {
    /// Get deployment thresholds for a network
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self {
                period: 2016,
                threshold: 1815, // 90% (1815/2016)
            },
            Network::Testnet | Network::Testnet4 => Self {
                period: 2016,
                threshold: 1512, // 75% (1512/2016)
            },
            Network::Regtest => Self {
                period: 144,    // Smaller period for testing
                threshold: 108, // 75%
            },
            Network::Signet => Self {
                period: 2016,
                threshold: 1815, // 90% like mainnet
            },
            // Default to mainnet params for unknown networks
            #[allow(unreachable_patterns)]
            _ => Self {
                period: 2016,
                threshold: 1815,
            },
        }
    }
}

/// Block index information needed for versionbits state calculation
pub trait BlockIndexProvider {
    /// Get the median time past for a block at height
    fn get_median_time_past(&self, height: u32) -> Option<i64>;
    /// Get the block version at height
    fn get_block_version(&self, height: u32) -> Option<i32>;
    /// Get the current chain height
    fn get_chain_height(&self) -> u32;
}

/// Cache for deployment states at retarget boundaries
pub type ThresholdConditionCache = HashMap<u32, ThresholdState>;

/// BIP9 versionbits state machine calculator
pub struct VersionBitsChecker {
    deployment: BIP9Deployment,
    thresholds: DeploymentThresholds,
}

impl VersionBitsChecker {
    /// Create a new checker for a deployment
    pub fn new(deployment: BIP9Deployment, network: Network) -> Self {
        Self {
            deployment,
            thresholds: DeploymentThresholds::for_network(network),
        }
    }

    /// Get the state for a block at the given height.
    ///
    /// This computes the state based on the deployment parameters and
    /// the chain state at the given height. State transitions only occur
    /// at retarget boundaries (every `period` blocks).
    ///
    /// The algorithm follows Bitcoin Core's GetStateFor():
    /// - State is the same for all blocks in a period
    /// - State is computed based on pindexPrev (the previous block)
    /// - Transitions happen at period boundaries
    ///
    /// # Arguments
    /// * `height` - Block height to compute state for
    /// * `provider` - Block index provider for chain data
    /// * `cache` - State cache for efficiency (keyed by period number)
    pub fn get_state_for<P: BlockIndexProvider>(
        &self,
        height: u32,
        provider: &P,
        cache: &mut ThresholdConditionCache,
    ) -> ThresholdState {
        // Check always-active and never-active
        if self.deployment.start_time == ALWAYS_ACTIVE {
            return ThresholdState::Active;
        }
        if self.deployment.start_time == NEVER_ACTIVE {
            return ThresholdState::Failed;
        }

        let period = self.thresholds.period;

        // Determine which period this height is in
        // Period 0: blocks 0 to period-1
        // Period 1: blocks period to 2*period-1
        // etc.
        let current_period = height / period;

        // Walk backwards to find a cached period state
        let mut to_compute = Vec::new();
        let mut check_period = current_period;

        while !cache.contains_key(&check_period) {
            if check_period == 0 {
                // Period 0 is always DEFINED
                cache.insert(0, ThresholdState::Defined);
                break;
            }

            // Check if MTP at start of this period is before start_time
            // Start of period N is at height N * period
            let period_start_height = check_period * period;
            if let Some(mtp) = provider.get_median_time_past(period_start_height.saturating_sub(1)) {
                if mtp < self.deployment.start_time {
                    cache.insert(check_period, ThresholdState::Defined);
                    break;
                }
            }

            to_compute.push(check_period);
            check_period -= 1;
        }

        // Get the known state for the earliest period we have
        let mut state = cache.get(&check_period).copied().unwrap_or(ThresholdState::Defined);

        // Walk forward and compute states for each period
        while let Some(compute_period) = to_compute.pop() {
            // The state for period N is computed based on:
            // - Previous state (from period N-1)
            // - MTP at the end of period N-1 (for DEFINED->STARTED, STARTED->FAILED)
            // - Signal counts in period N-1 (for STARTED->LOCKED_IN)
            let prev_period_end = compute_period * period - 1;
            let next_state = self.compute_next_state(state, prev_period_end, provider);
            cache.insert(compute_period, next_state);
            state = next_state;
        }

        state
    }

    /// Compute the next state given the current state and the previous period.
    ///
    /// # Arguments
    /// * `state` - Current state (from previous period)
    /// * `prev_period_end` - Height of the last block of the previous period
    /// * `provider` - Block index provider for chain data
    ///
    /// The state for a new period is determined by:
    /// - The state at the end of the previous period
    /// - MTP at the end of the previous period (for time-based transitions)
    /// - Signal counts in the previous period (for STARTED->LOCKED_IN)
    fn compute_next_state<P: BlockIndexProvider>(
        &self,
        state: ThresholdState,
        prev_period_end: u32,
        provider: &P,
    ) -> ThresholdState {
        let period = self.thresholds.period;
        let threshold = self.thresholds.threshold;

        // Get median time past at end of previous period
        let mtp = provider
            .get_median_time_past(prev_period_end)
            .unwrap_or(0);

        match state {
            ThresholdState::Defined => {
                // Transition to STARTED if we're past the start time
                if mtp >= self.deployment.start_time {
                    ThresholdState::Started
                } else {
                    ThresholdState::Defined
                }
            }
            ThresholdState::Started => {
                // Count signaling blocks in the previous period
                let period_start = prev_period_end.saturating_sub(period - 1);
                let mut count = 0u32;

                for h in period_start..=prev_period_end {
                    if let Some(version) = provider.get_block_version(h) {
                        if self.deployment.check_signal(version) {
                            count += 1;
                        }
                    }
                }

                if count >= threshold {
                    ThresholdState::LockedIn
                } else if mtp >= self.deployment.timeout {
                    ThresholdState::Failed
                } else {
                    ThresholdState::Started
                }
            }
            ThresholdState::LockedIn => {
                // Transition to ACTIVE if we've reached min_activation_height
                // prev_period_end + 1 is the first block of the new period
                if prev_period_end + 1 >= self.deployment.min_activation_height {
                    ThresholdState::Active
                } else {
                    ThresholdState::LockedIn
                }
            }
            // Terminal states
            ThresholdState::Active | ThresholdState::Failed => state,
        }
    }

    /// Get statistics for an in-progress deployment
    pub fn get_stats<P: BlockIndexProvider>(
        &self,
        height: u32,
        provider: &P,
    ) -> BIP9Stats {
        let period = self.thresholds.period;
        let threshold = self.thresholds.threshold;

        // Find how many blocks are in the current period
        let blocks_in_period = (height % period) + 1;
        let period_start = height.saturating_sub(blocks_in_period - 1);

        let mut count = 0u32;
        for h in period_start..=height {
            if let Some(version) = provider.get_block_version(h) {
                if self.deployment.check_signal(version) {
                    count += 1;
                }
            }
        }

        let elapsed = blocks_in_period;
        let remaining = period - elapsed;
        // Activation is still possible if (threshold - count) <= remaining
        let possible = count + remaining >= threshold;

        BIP9Stats {
            period,
            threshold,
            elapsed,
            count,
            possible,
        }
    }

    /// Get the height since when the current state started
    pub fn get_state_since_height<P: BlockIndexProvider>(
        &self,
        height: u32,
        provider: &P,
        cache: &mut ThresholdConditionCache,
    ) -> u32 {
        if self.deployment.start_time == ALWAYS_ACTIVE
            || self.deployment.start_time == NEVER_ACTIVE
        {
            return 0;
        }

        let current_state = self.get_state_for(height, provider, cache);
        if current_state == ThresholdState::Defined {
            return 0;
        }

        let period = self.thresholds.period;

        // Find the period start for current height
        let mut period_start = height - (height % period);

        // Walk backwards to find where state changed
        while period_start >= period {
            let prev_period = period_start - period;
            let prev_state = self.get_state_for(prev_period, provider, cache);
            if prev_state != current_state {
                return period_start;
            }
            period_start = prev_period;
        }

        period_start
    }
}

/// Known deployments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeploymentPos {
    /// Dummy deployment for testing
    TestDummy,
    /// Taproot (BIP340/341/342)
    Taproot,
}

/// Get deployments for a network
pub fn get_deployments(network: Network) -> Vec<(DeploymentPos, BIP9Deployment)> {
    match network {
        Network::Bitcoin => vec![
            (
                DeploymentPos::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: 1619222400, // April 24, 2021 00:00:00 UTC
                    timeout: 1628640000,    // August 11, 2021 00:00:00 UTC
                    min_activation_height: 709632, // Speedy trial
                    name: "taproot",
                },
            ),
        ],
        Network::Testnet => vec![
            (
                DeploymentPos::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: ALWAYS_ACTIVE,
                    timeout: i64::MAX,
                    min_activation_height: 0,
                    name: "taproot",
                },
            ),
        ],
        Network::Testnet4 => vec![
            (
                DeploymentPos::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: ALWAYS_ACTIVE,
                    timeout: i64::MAX,
                    min_activation_height: 0,
                    name: "taproot",
                },
            ),
        ],
        Network::Signet => vec![
            (
                DeploymentPos::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: ALWAYS_ACTIVE,
                    timeout: i64::MAX,
                    min_activation_height: 0,
                    name: "taproot",
                },
            ),
        ],
        Network::Regtest => vec![
            (
                DeploymentPos::TestDummy,
                BIP9Deployment {
                    bit: 28,
                    start_time: 0,
                    timeout: i64::MAX,
                    min_activation_height: 0,
                    name: "testdummy",
                },
            ),
            (
                DeploymentPos::Taproot,
                BIP9Deployment {
                    bit: 2,
                    start_time: ALWAYS_ACTIVE,
                    timeout: i64::MAX,
                    min_activation_height: 0,
                    name: "taproot",
                },
            ),
        ],
        #[allow(unreachable_patterns)]
        _ => vec![],
    }
}

/// Cache for all deployment states
pub struct VersionBitsCache {
    caches: HashMap<DeploymentPos, ThresholdConditionCache>,
    network: Network,
}

impl VersionBitsCache {
    /// Create a new cache for a network
    pub fn new(network: Network) -> Self {
        Self {
            caches: HashMap::new(),
            network,
        }
    }

    /// Get the state of a deployment at a given height
    pub fn get_state<P: BlockIndexProvider>(
        &mut self,
        pos: DeploymentPos,
        height: u32,
        provider: &P,
    ) -> Option<ThresholdState> {
        let deployments = get_deployments(self.network);
        let deployment = deployments.iter().find(|(p, _)| *p == pos)?;

        let cache = self.caches.entry(pos).or_insert_with(HashMap::new);
        let checker = VersionBitsChecker::new(deployment.1.clone(), self.network);

        Some(checker.get_state_for(height, provider, cache))
    }

    /// Check if a deployment is active after a given height
    pub fn is_active_after<P: BlockIndexProvider>(
        &mut self,
        pos: DeploymentPos,
        height: u32,
        provider: &P,
    ) -> bool {
        self.get_state(pos, height, provider) == Some(ThresholdState::Active)
    }

    /// Compute the block version to use for new blocks
    ///
    /// Sets version bits for deployments that are STARTED or LOCKED_IN
    pub fn compute_block_version<P: BlockIndexProvider>(
        &mut self,
        height: u32,
        provider: &P,
    ) -> i32 {
        let mut version = VERSIONBITS_TOP_BITS;

        for (pos, deployment) in get_deployments(self.network) {
            let state = self.get_state(pos, height, provider);
            if state == Some(ThresholdState::Started) || state == Some(ThresholdState::LockedIn) {
                version |= deployment.mask() as i32;
            }
        }

        version
    }

    /// Get info for all deployments (for getblockchaininfo RPC)
    pub fn get_all_deployment_info<P: BlockIndexProvider>(
        &mut self,
        height: u32,
        provider: &P,
    ) -> Vec<DeploymentInfo> {
        let mut result = Vec::new();

        for (pos, deployment) in get_deployments(self.network) {
            let cache = self.caches.entry(pos).or_insert_with(HashMap::new);
            let checker = VersionBitsChecker::new(deployment.clone(), self.network);

            let state = checker.get_state_for(height, provider, cache);
            let since = checker.get_state_since_height(height, provider, cache);

            let stats = if state == ThresholdState::Started || state == ThresholdState::LockedIn {
                Some(checker.get_stats(height, provider))
            } else {
                None
            };

            result.push(DeploymentInfo {
                name: deployment.name.to_string(),
                bit: deployment.bit,
                state,
                since,
                start_time: deployment.start_time,
                timeout: deployment.timeout,
                min_activation_height: deployment.min_activation_height,
                stats,
            });
        }

        result
    }

    /// Clear all cached states
    pub fn clear(&mut self) {
        self.caches.clear();
    }
}

/// Deployment information for RPC
#[derive(Debug, Clone)]
pub struct DeploymentInfo {
    pub name: String,
    pub bit: u8,
    pub state: ThresholdState,
    pub since: u32,
    pub start_time: i64,
    pub timeout: i64,
    pub min_activation_height: u32,
    pub stats: Option<BIP9Stats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        versions: HashMap<u32, i32>,
        mtps: HashMap<u32, i64>,
        height: u32,
    }

    impl MockProvider {
        fn new(height: u32) -> Self {
            Self {
                versions: HashMap::new(),
                mtps: HashMap::new(),
                height,
            }
        }

        fn set_version(&mut self, height: u32, version: i32) {
            self.versions.insert(height, version);
        }

        fn set_mtp(&mut self, height: u32, mtp: i64) {
            self.mtps.insert(height, mtp);
        }
    }

    impl BlockIndexProvider for MockProvider {
        fn get_median_time_past(&self, height: u32) -> Option<i64> {
            self.mtps.get(&height).copied()
        }

        fn get_block_version(&self, height: u32) -> Option<i32> {
            self.versions.get(&height).copied()
        }

        fn get_chain_height(&self) -> u32 {
            self.height
        }
    }

    #[test]
    fn test_state_defined_at_genesis() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 1000000000,
            timeout: 2000000000,
            min_activation_height: 0,
            name: "test",
        };

        let provider = MockProvider::new(0);
        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        let state = checker.get_state_for(0, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Defined);
    }

    #[test]
    fn test_always_active() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: ALWAYS_ACTIVE,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        let provider = MockProvider::new(100);
        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        let state = checker.get_state_for(100, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_never_active() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: NEVER_ACTIVE,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        let provider = MockProvider::new(100);
        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        let state = checker.get_state_for(100, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Failed);
    }

    #[test]
    fn test_transition_to_started() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 1000000000,
            timeout: 2000000000,
            min_activation_height: 0,
            name: "test",
        };

        let mut provider = MockProvider::new(6048);

        // Period 0 (heights 0-2015): MTP before start time
        for h in 0..2016 {
            provider.set_mtp(h, 999999999);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        // Period 1 (heights 2016-4031): MTP after start time
        // State for period 1 is determined by MTP at end of period 0 (h=2015)
        // Since MTP(2015) < start_time, period 1 is still DEFINED
        for h in 2016..4032 {
            provider.set_mtp(h, 1000000001);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        // Period 2 (heights 4032-6047): MTP after start time
        // State for period 2 is determined by MTP at end of period 1 (h=4031)
        // Since MTP(4031) >= start_time, period 2 is STARTED
        for h in 4032..6048 {
            provider.set_mtp(h, 1000000002);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        // Period 0 (before start time) - should be DEFINED
        let state = checker.get_state_for(2015, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Defined);

        // Period 1 (MTP at period 0 end is before start time) - should be DEFINED
        let state = checker.get_state_for(4031, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Defined);

        // Period 2 (MTP at period 1 end is after start time) - should be STARTED
        let state = checker.get_state_for(4032, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Started);
    }

    #[test]
    fn test_check_signal() {
        let deployment = BIP9Deployment {
            bit: 2,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        // Valid signaling: top 3 bits = 001, bit 2 set
        let version = VERSIONBITS_TOP_BITS | (1 << 2);
        assert!(deployment.check_signal(version));

        // Not signaling: bit 2 not set
        let version = VERSIONBITS_TOP_BITS;
        assert!(!deployment.check_signal(version));

        // Invalid: top 3 bits not 001
        let version = 0x10000000 | (1 << 2);
        assert!(!deployment.check_signal(version));
    }

    #[test]
    fn test_transition_to_locked_in() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        let mut provider = MockProvider::new(6048);

        // Period 0 (heights 0-2015): MTP > start_time (0), all signaling
        // State for period 1 will be STARTED (because MTP at end of period 0 >= start_time)
        for h in 0..2016 {
            provider.set_mtp(h, 1);
            provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
        }

        // Period 1 (heights 2016-4031): All signaling
        // State for period 2 will be LOCKED_IN (because all blocks in period 1 signaled)
        for h in 2016..4032 {
            provider.set_mtp(h, 2);
            provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
        }

        // Period 2 (heights 4032-6047): Any versions
        for h in 4032..6048 {
            provider.set_mtp(h, 3);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        // Period 1: STARTED (MTP at period 0 end >= start_time)
        let state = checker.get_state_for(2016, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Started);

        // Period 2: LOCKED_IN (all blocks in period 1 signaled)
        let state = checker.get_state_for(4032, &provider, &mut cache);
        assert_eq!(state, ThresholdState::LockedIn);
    }

    #[test]
    fn test_transition_to_active() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        let mut provider = MockProvider::new(8064);

        // Period 0 (heights 0-2015): MTP > start_time, all signaling
        // State for period 1: STARTED
        for h in 0..2016 {
            provider.set_mtp(h, 1);
            provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
        }

        // Period 1 (heights 2016-4031): all signaling
        // State for period 2: LOCKED_IN (all blocks in period 1 signaled)
        for h in 2016..4032 {
            provider.set_mtp(h, 2);
            provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
        }

        // Period 2 (heights 4032-6047): any versions
        // State for period 3: ACTIVE (transition from LOCKED_IN)
        for h in 4032..6048 {
            provider.set_mtp(h, 3);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        // Period 3 (heights 6048-8063)
        for h in 6048..8064 {
            provider.set_mtp(h, 4);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        // Period 2: LOCKED_IN
        let state = checker.get_state_for(4032, &provider, &mut cache);
        assert_eq!(state, ThresholdState::LockedIn);

        // Period 3: ACTIVE
        let state = checker.get_state_for(6048, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_transition_to_failed() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: 100,
            min_activation_height: 0,
            name: "test",
        };

        let mut provider = MockProvider::new(4032);

        // First period: MTP after start but before timeout, no signaling
        for h in 0..2016 {
            provider.set_mtp(h, 1);
            provider.set_version(h, VERSIONBITS_TOP_BITS); // No signal
        }

        // Second period: MTP after timeout, no signaling -> FAILED
        for h in 2016..4032 {
            provider.set_mtp(h, 101); // After timeout
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        // FAILED is period 2's state ([4032,6047]): period 1 (2016-4031) is
        // STARTED, and at the end of period 1 (MTP 101 >= timeout 100, zero
        // signals) it transitions to FAILED for the next period. Height 4031 is
        // still in the STARTED period 1 (get_state_for(h) = state of block h,
        // matching Core GetStateFor); query the first block of period 2.
        let state = checker.get_state_for(4032, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Failed);
    }

    #[test]
    fn test_bip9_stats() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 0,
            name: "test",
        };

        let mut provider = MockProvider::new(2016);

        // Half signaling
        for h in 0..2016 {
            provider.set_mtp(h, 1);
            if h % 2 == 0 {
                provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
            } else {
                provider.set_version(h, VERSIONBITS_TOP_BITS);
            }
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);

        let stats = checker.get_stats(2015, &provider);
        assert_eq!(stats.period, 2016);
        assert_eq!(stats.threshold, 1815);
        assert_eq!(stats.elapsed, 2016);
        assert_eq!(stats.count, 1008); // Half of 2016
        assert!(!stats.possible); // 1008 < 1815
    }

    #[test]
    fn test_testnet_threshold() {
        let thresholds = DeploymentThresholds::for_network(Network::Testnet);
        assert_eq!(thresholds.period, 2016);
        assert_eq!(thresholds.threshold, 1512); // 75%
    }

    #[test]
    fn test_mainnet_threshold() {
        let thresholds = DeploymentThresholds::for_network(Network::Bitcoin);
        assert_eq!(thresholds.period, 2016);
        assert_eq!(thresholds.threshold, 1815); // 90%
    }

    #[test]
    fn test_compute_block_version() {
        let mut cache = VersionBitsCache::new(Network::Regtest);
        let mut provider = MockProvider::new(144);

        // Set up state for STARTED deployment
        for h in 0..144 {
            provider.set_mtp(h, 1);
            provider.set_version(h, VERSIONBITS_TOP_BITS);
        }

        // compute_block_version(h) sets bits for deployments whose state at
        // block h is STARTED or LOCKED_IN. Regtest TestDummy (bit 28, start=0)
        // is DEFINED in period 0 ([0,143]) and only STARTED from period 1
        // ([144,287]) — a DEFINED deployment never signals. Query a period-1
        // height (144 = the block being assembled on tip 143, the production
        // case). Taproot is ALWAYS_ACTIVE -> ACTIVE, which is terminal and does
        // NOT signal, so its bit is intentionally not set.
        let version = cache.compute_block_version(144, &provider);

        // Should have top bits set
        assert_eq!(version & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);

        // TestDummy is STARTED at period 1, so its bit 28 must be set.
        assert_ne!(version & (1 << 28), 0);
    }

    #[test]
    fn test_min_activation_height() {
        let deployment = BIP9Deployment {
            bit: 1,
            start_time: 0,
            timeout: i64::MAX,
            min_activation_height: 6048, // Must wait until height 6048
            name: "test",
        };

        let mut provider = MockProvider::new(8064);

        // Setup all periods signaling
        for h in 0..8064 {
            provider.set_mtp(h, 1);
            provider.set_version(h, VERSIONBITS_TOP_BITS | (1 << 1));
        }

        let checker = VersionBitsChecker::new(deployment, Network::Bitcoin);
        let mut cache = ThresholdConditionCache::new();

        // LOCKED_IN is period 2's state ([4032,6047]): period 1 (2016-4031) is
        // STARTED and signals over threshold, so period 2 locks in. It must NOT
        // be ACTIVE yet because min_activation_height is 6048. Height 4031 is
        // still STARTED (period 1); query the first block of period 2.
        let state = checker.get_state_for(4032, &provider, &mut cache);
        assert_eq!(state, ThresholdState::LockedIn);

        // ACTIVE is period 3's state ([6048,8063]): LOCKED_IN -> ACTIVE once the
        // first block of the new period (6048) reaches min_activation_height
        // 6048. Height 6047 is still LOCKED_IN (period 2); query period 3.
        let state = checker.get_state_for(6048, &provider, &mut cache);
        assert_eq!(state, ThresholdState::Active);
    }

    #[test]
    fn test_state_name() {
        assert_eq!(ThresholdState::Defined.name(), "defined");
        assert_eq!(ThresholdState::Started.name(), "started");
        assert_eq!(ThresholdState::LockedIn.name(), "locked_in");
        assert_eq!(ThresholdState::Active.name(), "active");
        assert_eq!(ThresholdState::Failed.name(), "failed");
    }

    #[test]
    fn test_get_deployments_mainnet() {
        let deployments = get_deployments(Network::Bitcoin);
        assert!(!deployments.is_empty());

        // Find taproot deployment
        let taproot = deployments
            .iter()
            .find(|(pos, _)| *pos == DeploymentPos::Taproot);
        assert!(taproot.is_some());

        let (_, dep) = taproot.unwrap();
        assert_eq!(dep.bit, 2);
        assert_eq!(dep.min_activation_height, 709632);
    }

    #[test]
    fn test_get_deployments_testnet() {
        let deployments = get_deployments(Network::Testnet);

        // Taproot should be always active on testnet
        let taproot = deployments
            .iter()
            .find(|(pos, _)| *pos == DeploymentPos::Taproot);
        assert!(taproot.is_some());

        let (_, dep) = taproot.unwrap();
        assert_eq!(dep.start_time, ALWAYS_ACTIVE);
    }
}
