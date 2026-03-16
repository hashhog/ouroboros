//! Headers-sync anti-DoS protection (PRESYNC/REDOWNLOAD)
//!
//! Implements Bitcoin Core's header synchronization anti-DoS mechanism to prevent
//! memory exhaustion attacks from peers sending millions of low-work headers.
//!
//! ## Overview
//!
//! During initial sync, a malicious peer could send an endless stream of low-difficulty
//! headers, exhausting node memory before PoW is validated. This module implements
//! a two-phase approach:
//!
//! 1. **PRESYNC**: Accept headers without permanent storage. Track only:
//!    - Cumulative proof-of-work
//!    - Last header hash
//!    - 1-bit commitments at periodic intervals (for later verification)
//!
//!    When cumulative work reaches `nMinimumChainWork`, transition to REDOWNLOAD.
//!
//! 2. **REDOWNLOAD**: Re-request all headers from the peer and store them permanently.
//!    Verify 1-bit commitments match to ensure peer sent the same chain.
//!
//! Reference: Bitcoin Core net_processing.cpp HeadersSyncState

use bitcoin::Network;
use bitcoin::hashes::Hash;
use primitive_types::U256;
use siphasher::sip::SipHasher;
use std::hash::Hasher;

use crate::chain_params::{
    headers_presync_commitment_period, headers_redownload_buffer_size, minimum_chain_work,
};
use crate::validate::pow::{bits_to_target, calculate_work};
use crate::validate::difficulty::permitted_difficulty_transition;

/// Maximum headers per protocol message (Bitcoin P2P limit)
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// Maximum time in future a block timestamp can be (2 hours in seconds)
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;

/// Maximum block time increase per block (based on MTP rule: ~6 blocks/second theoretical max)
pub const MAX_BLOCKS_PER_SECOND: u32 = 6;

/// Sync state during headers synchronization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadersSyncPhase {
    /// Initial phase: validating work accumulation without storing headers
    Presync,
    /// Re-downloading headers after work threshold reached
    Redownload,
    /// Sync complete or failed
    Final,
}

/// Compressed header for REDOWNLOAD buffering (48 bytes vs 80 for full header)
///
/// We don't store prev_blockhash since it's reconstructed from the previous header.
#[derive(Debug, Clone)]
pub struct CompressedHeader {
    pub version: i32,
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl CompressedHeader {
    /// Create from a full block header
    pub fn from_header(header: &bitcoin::blockdata::block::Header) -> Self {
        Self {
            version: header.version.to_consensus(),
            merkle_root: *header.merkle_root.as_ref(),
            time: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
        }
    }
}

/// Result of processing headers during presync/redownload
#[derive(Debug)]
pub struct HeadersSyncResult {
    /// Whether processing succeeded
    pub success: bool,
    /// Whether more headers should be requested
    pub request_more: bool,
    /// Headers ready to be stored in block index (only during REDOWNLOAD)
    pub headers_to_store: Vec<bitcoin::blockdata::block::Header>,
    /// Error message if success is false
    pub error: Option<String>,
}

/// Header sync state machine for anti-DoS protection
///
/// Tracks state per-peer during headers synchronization.
pub struct HeadersSyncState {
    /// Network for chainparams lookups
    network: Network,

    /// Current sync phase
    phase: HeadersSyncPhase,

    /// Minimum required work (from chainparams)
    minimum_required_work: U256,

    /// Commitment period (blocks between 1-bit commitments)
    commitment_period: u32,

    /// Redownload buffer size
    redownload_buffer_size: u32,

    // === PRESYNC state ===
    /// Cumulative work seen during PRESYNC
    presync_work: U256,

    /// Hash of last header received during PRESYNC
    presync_last_hash: [u8; 32],

    /// Height of last header during PRESYNC
    presync_height: u32,

    /// 1-bit commitments stored during PRESYNC
    /// Each bit is: hash(salt, header_hash) & 1
    presync_commitments: Vec<bool>,

    /// Random offset for commitment points (prevents prediction)
    commit_offset: u32,

    /// Maximum allowed commitments (based on time constraints)
    max_commitments: u32,

    /// Salt for commitment hashing (prevents precomputation)
    hasher_key: (u64, u64),

    // === REDOWNLOAD state ===
    /// Buffered compressed headers during REDOWNLOAD
    redownload_buffer: Vec<CompressedHeader>,

    /// Height of last buffered header
    redownload_buffer_last_height: u32,

    /// Hash of last buffered header
    redownload_buffer_last_hash: [u8; 32],

    /// Prev hash for first header in buffer (for reconstruction)
    redownload_buffer_first_prev_hash: [u8; 32],

    /// Work accumulated during REDOWNLOAD
    redownload_work: U256,

    /// Index into presync_commitments for verification
    commitment_index: usize,

    /// True when redownload work >= minimum (release all remaining headers)
    process_all_remaining: bool,

    /// Chain start hash (genesis or fork point)
    chain_start_hash: [u8; 32],
}

impl HeadersSyncState {
    /// Create a new header sync state for a peer
    ///
    /// # Arguments
    /// * `network` - Network for chainparams
    /// * `chain_start_hash` - Hash of the block we're syncing from (genesis or fork point)
    /// * `chain_start_time` - Median time past of chain_start (for commitment limit calculation)
    pub fn new(network: Network, chain_start_hash: [u8; 32], chain_start_time: u32) -> Self {
        let minimum_required_work = minimum_chain_work(network);
        let commitment_period = headers_presync_commitment_period(network);
        let redownload_buffer_size = headers_redownload_buffer_size(network);

        // Generate random salt for commitment hashing
        let hasher_key = (
            rand::random::<u64>(),
            rand::random::<u64>(),
        );

        // Random commit offset within [0, commitment_period)
        let commit_offset = rand::random::<u32>() % commitment_period;

        // Calculate maximum commitments based on time constraints
        // Max possible chain length from chain_start to now + future tolerance
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let max_time_span = now.saturating_add(MAX_FUTURE_BLOCK_TIME)
            .saturating_sub(chain_start_time);
        // Max blocks = max_time_span * MAX_BLOCKS_PER_SECOND (theoretical limit from MTP rule)
        let max_blocks = (max_time_span as u64) * (MAX_BLOCKS_PER_SECOND as u64);
        let max_commitments = ((max_blocks / commitment_period as u64) + 1).min(u32::MAX as u64) as u32;

        Self {
            network,
            phase: HeadersSyncPhase::Presync,
            minimum_required_work,
            commitment_period,
            redownload_buffer_size,
            presync_work: U256::zero(),
            presync_last_hash: chain_start_hash,
            presync_height: 0,
            presync_commitments: Vec::new(),
            commit_offset,
            max_commitments,
            hasher_key,
            redownload_buffer: Vec::new(),
            redownload_buffer_last_height: 0,
            redownload_buffer_last_hash: [0u8; 32],
            redownload_buffer_first_prev_hash: [0u8; 32],
            redownload_work: U256::zero(),
            commitment_index: 0,
            process_all_remaining: false,
            chain_start_hash,
        }
    }

    /// Get current sync phase
    pub fn phase(&self) -> HeadersSyncPhase {
        self.phase
    }

    /// Get cumulative work seen during presync
    pub fn presync_work(&self) -> U256 {
        self.presync_work
    }

    /// Get presync height
    pub fn presync_height(&self) -> u32 {
        self.presync_height
    }

    /// Get number of commitments stored
    pub fn commitment_count(&self) -> usize {
        self.presync_commitments.len()
    }

    /// Process headers received from peer
    ///
    /// # Arguments
    /// * `headers` - Headers received in message
    /// * `full_message` - True if this is a complete 2000-header message
    ///
    /// # Returns
    /// Result indicating success, whether to request more, and headers to store
    pub fn process_headers(
        &mut self,
        headers: &[bitcoin::blockdata::block::Header],
        full_message: bool,
    ) -> HeadersSyncResult {
        match self.phase {
            HeadersSyncPhase::Presync => self.process_presync(headers, full_message),
            HeadersSyncPhase::Redownload => self.process_redownload(headers, full_message),
            HeadersSyncPhase::Final => HeadersSyncResult {
                success: false,
                request_more: false,
                headers_to_store: Vec::new(),
                error: Some("Sync already finalized".to_string()),
            },
        }
    }

    /// Process headers during PRESYNC phase
    fn process_presync(
        &mut self,
        headers: &[bitcoin::blockdata::block::Header],
        full_message: bool,
    ) -> HeadersSyncResult {
        if headers.is_empty() {
            // Empty response - peer has no more headers or we reached tip
            if self.presync_work >= self.minimum_required_work {
                // Sufficient work - transition to redownload
                self.transition_to_redownload();
                return HeadersSyncResult {
                    success: true,
                    request_more: true, // Request headers again for redownload
                    headers_to_store: Vec::new(),
                    error: None,
                };
            } else {
                // Insufficient work - reject this peer's chain
                self.phase = HeadersSyncPhase::Final;
                return HeadersSyncResult {
                    success: false,
                    request_more: false,
                    headers_to_store: Vec::new(),
                    error: Some(format!(
                        "Peer's chain has insufficient work: {} < {}",
                        self.presync_work, self.minimum_required_work
                    )),
                };
            }
        }

        let mut prev_hash = self.presync_last_hash;
        let mut prev_bits = 0u32; // Will be set from first header

        for (i, header) in headers.iter().enumerate() {
            let height = self.presync_height + i as u32 + 1;

            // 1. Verify continuity: header connects to previous
            let header_prev_hash: [u8; 32] = *header.prev_blockhash.as_ref();
            if header_prev_hash != prev_hash {
                self.phase = HeadersSyncPhase::Final;
                return HeadersSyncResult {
                    success: false,
                    request_more: false,
                    headers_to_store: Vec::new(),
                    error: Some(format!(
                        "Header at height {} doesn't connect: prev_hash mismatch",
                        height
                    )),
                };
            }

            // 2. Verify difficulty transition is permitted
            let header_bits = header.bits.to_consensus();
            if i > 0 || self.presync_height > 0 {
                // Get previous bits (from prev header in batch or stored)
                let check_bits = if i > 0 {
                    headers[i - 1].bits.to_consensus()
                } else {
                    prev_bits
                };

                if !permitted_difficulty_transition(height, check_bits, header_bits, self.network) {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some(format!(
                            "Invalid difficulty transition at height {}: {} -> {}",
                            height, check_bits, header_bits
                        )),
                    };
                }
            }

            // 3. Accumulate work
            let target = bits_to_target(header_bits);
            let work = calculate_work(target);
            self.presync_work = self.presync_work.saturating_add(work);

            // 4. Store commitment if at commitment point
            let header_hash = header.block_hash();
            let hash_bytes: [u8; 32] = *header_hash.as_ref();
            if (height % self.commitment_period) == self.commit_offset {
                if self.presync_commitments.len() >= self.max_commitments as usize {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some("Chain too long (exceeded max commitments)".to_string()),
                    };
                }
                let commitment = self.compute_commitment(&hash_bytes);
                self.presync_commitments.push(commitment);
            }

            // Update tracking state
            prev_hash = hash_bytes;
            prev_bits = header_bits;
        }

        // Update state after processing batch
        self.presync_last_hash = prev_hash;
        self.presync_height += headers.len() as u32;

        // Check if we've reached sufficient work
        if self.presync_work >= self.minimum_required_work {
            // Transition to REDOWNLOAD
            self.transition_to_redownload();
            return HeadersSyncResult {
                success: true,
                request_more: true, // Request from beginning for redownload
                headers_to_store: Vec::new(),
                error: None,
            };
        }

        // Continue presync
        HeadersSyncResult {
            success: true,
            request_more: full_message, // Request more if we got a full batch
            headers_to_store: Vec::new(),
            error: None,
        }
    }

    /// Transition from PRESYNC to REDOWNLOAD phase
    fn transition_to_redownload(&mut self) {
        log::info!(
            "PRESYNC complete: {} work accumulated, {} commitments stored. Starting REDOWNLOAD.",
            self.presync_work,
            self.presync_commitments.len()
        );

        self.phase = HeadersSyncPhase::Redownload;
        self.redownload_buffer.clear();
        self.redownload_buffer_last_height = 0;
        self.redownload_buffer_last_hash = self.chain_start_hash;
        self.redownload_buffer_first_prev_hash = [0u8; 32];
        self.redownload_work = U256::zero();
        self.commitment_index = 0;
        self.process_all_remaining = false;
    }

    /// Process headers during REDOWNLOAD phase
    fn process_redownload(
        &mut self,
        headers: &[bitcoin::blockdata::block::Header],
        full_message: bool,
    ) -> HeadersSyncResult {
        if headers.is_empty() {
            // Empty response - release any remaining buffered headers
            let headers_to_store = self.release_buffered_headers(true);
            self.phase = HeadersSyncPhase::Final;
            return HeadersSyncResult {
                success: true,
                request_more: false,
                headers_to_store,
                error: None,
            };
        }

        let mut prev_hash = self.redownload_buffer_last_hash;

        for (i, header) in headers.iter().enumerate() {
            let height = self.redownload_buffer_last_height + i as u32 + 1;

            // 1. Verify continuity
            let header_prev_hash: [u8; 32] = *header.prev_blockhash.as_ref();
            if header_prev_hash != prev_hash {
                self.phase = HeadersSyncPhase::Final;
                return HeadersSyncResult {
                    success: false,
                    request_more: false,
                    headers_to_store: Vec::new(),
                    error: Some(format!(
                        "REDOWNLOAD: Header at height {} doesn't connect",
                        height
                    )),
                };
            }

            // 2. Verify difficulty transition
            let header_bits = header.bits.to_consensus();
            if i > 0 {
                let prev_bits = headers[i - 1].bits.to_consensus();
                if !permitted_difficulty_transition(height, prev_bits, header_bits, self.network) {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some(format!(
                            "REDOWNLOAD: Invalid difficulty at height {}",
                            height
                        )),
                    };
                }
            } else if !self.redownload_buffer.is_empty() {
                let prev_bits = self.redownload_buffer.last().unwrap().bits;
                if !permitted_difficulty_transition(height, prev_bits, header_bits, self.network) {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some(format!(
                            "REDOWNLOAD: Invalid difficulty at height {} (cross-batch)",
                            height
                        )),
                    };
                }
            }

            // 3. Accumulate work
            let target = bits_to_target(header_bits);
            let work = calculate_work(target);
            self.redownload_work = self.redownload_work.saturating_add(work);

            // Check if we've reached minimum work (can release all remaining)
            if !self.process_all_remaining && self.redownload_work >= self.minimum_required_work {
                self.process_all_remaining = true;
            }

            // 4. Verify commitment if at commitment point (before reaching work threshold)
            let header_hash = header.block_hash();
            let hash_bytes: [u8; 32] = *header_hash.as_ref();
            if !self.process_all_remaining && (height % self.commitment_period) == self.commit_offset {
                if self.commitment_index >= self.presync_commitments.len() {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some("REDOWNLOAD: More commitments expected than stored".to_string()),
                    };
                }

                let expected = self.presync_commitments[self.commitment_index];
                let actual = self.compute_commitment(&hash_bytes);

                if expected != actual {
                    self.phase = HeadersSyncPhase::Final;
                    return HeadersSyncResult {
                        success: false,
                        request_more: false,
                        headers_to_store: Vec::new(),
                        error: Some(format!(
                            "REDOWNLOAD: Commitment mismatch at height {} (peer sent different chain)",
                            height
                        )),
                    };
                }
                self.commitment_index += 1;
            }

            // 5. Buffer header for later release
            if self.redownload_buffer.is_empty() {
                self.redownload_buffer_first_prev_hash = header_prev_hash;
            }
            self.redownload_buffer.push(CompressedHeader::from_header(header));
            prev_hash = hash_bytes;
        }

        // Update tracking
        self.redownload_buffer_last_height += headers.len() as u32;
        self.redownload_buffer_last_hash = prev_hash;

        // Release headers from buffer when we have enough verified commitments
        let headers_to_store = self.release_buffered_headers(false);

        HeadersSyncResult {
            success: true,
            request_more: full_message,
            headers_to_store,
            error: None,
        }
    }

    /// Release headers from redownload buffer that have sufficient verified commitments
    fn release_buffered_headers(&mut self, release_all: bool) -> Vec<bitcoin::blockdata::block::Header> {
        let mut released: Vec<bitcoin::blockdata::block::Header> = Vec::new();

        let release_threshold = if release_all || self.process_all_remaining {
            0 // Release all
        } else {
            self.redownload_buffer_size as usize
        };

        while self.redownload_buffer.len() > release_threshold {
            if let Some(compressed) = self.redownload_buffer.first() {
                // Reconstruct full header
                let prev_hash = if released.is_empty() {
                    bitcoin::BlockHash::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array(
                            self.redownload_buffer_first_prev_hash
                        )
                    )
                } else {
                    released.last().unwrap().block_hash()
                };

                let header = bitcoin::blockdata::block::Header {
                    version: bitcoin::blockdata::block::Version::from_consensus(compressed.version),
                    prev_blockhash: prev_hash,
                    merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array(compressed.merkle_root)
                    ),
                    time: compressed.time,
                    bits: bitcoin::CompactTarget::from_consensus(compressed.bits),
                    nonce: compressed.nonce,
                };

                released.push(header);
                self.redownload_buffer.remove(0);
            } else {
                break;
            }
        }

        // Update first_prev_hash for remaining buffer
        if !self.redownload_buffer.is_empty() && !released.is_empty() {
            self.redownload_buffer_first_prev_hash = *released.last().unwrap().block_hash().as_ref();
        }

        released
    }

    /// Compute 1-bit commitment for a header hash
    fn compute_commitment(&self, header_hash: &[u8; 32]) -> bool {
        let mut hasher = SipHasher::new_with_keys(self.hasher_key.0, self.hasher_key.1);
        hasher.write(header_hash);
        let hash = hasher.finish();
        (hash & 1) == 1
    }

    /// Build locator for next headers request
    ///
    /// During PRESYNC: returns last header hash
    /// During REDOWNLOAD: returns chain_start_hash (to re-request from beginning)
    pub fn next_headers_request_locator(&self) -> Vec<[u8; 32]> {
        match self.phase {
            HeadersSyncPhase::Presync => vec![self.presync_last_hash],
            HeadersSyncPhase::Redownload => {
                // Request from the last buffered header if we have any, else from start
                if self.redownload_buffer_last_height > 0 {
                    vec![self.redownload_buffer_last_hash]
                } else {
                    vec![self.chain_start_hash]
                }
            }
            HeadersSyncPhase::Final => Vec::new(),
        }
    }

    /// Finalize and clean up state
    pub fn finalize(&mut self) {
        self.presync_commitments.clear();
        self.presync_commitments.shrink_to_fit();
        self.redownload_buffer.clear();
        self.redownload_buffer.shrink_to_fit();
        self.presync_last_hash = [0u8; 32];
        self.redownload_buffer_last_hash = [0u8; 32];
        self.redownload_buffer_first_prev_hash = [0u8; 32];
        self.phase = HeadersSyncPhase::Final;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn create_test_header(
        prev_hash: bitcoin::BlockHash,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> bitcoin::blockdata::block::Header {
        bitcoin::blockdata::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    #[test]
    fn test_headers_sync_state_new() {
        let state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );
        assert_eq!(state.phase(), HeadersSyncPhase::Presync);
        assert_eq!(state.presync_work(), U256::zero());
        assert_eq!(state.presync_height(), 0);
    }

    #[test]
    fn test_commitment_computation_deterministic() {
        let state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );
        let hash = [1u8; 32];
        let c1 = state.compute_commitment(&hash);
        let c2 = state.compute_commitment(&hash);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_presync_empty_headers_insufficient_work() {
        let mut state = HeadersSyncState::new(
            Network::Bitcoin, // Has high minimum work
            [0u8; 32],
            0,
        );

        let result = state.process_headers(&[], false);
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("insufficient work"));
    }

    #[test]
    fn test_presync_empty_headers_sufficient_work_regtest() {
        // Regtest has zero minimum work
        let mut state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );

        // Even with zero work (empty headers), regtest should accept
        let result = state.process_headers(&[], false);
        assert!(result.success);
        assert_eq!(state.phase(), HeadersSyncPhase::Redownload);
    }

    #[test]
    fn test_presync_header_continuity_check() {
        let mut state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );

        // Create header that doesn't connect (wrong prev_hash)
        let bad_header = create_test_header(
            bitcoin::BlockHash::from_byte_array([1u8; 32]), // Wrong prev
            1000,
            0x207fffff, // Regtest difficulty
            0,
        );

        let result = state.process_headers(&[bad_header], false);
        assert!(!result.success);
        assert!(result.error.unwrap().contains("prev_hash mismatch"));
    }

    #[test]
    fn test_presync_work_accumulation() {
        let mut state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );

        // Create valid connecting header
        let header = create_test_header(
            bitcoin::BlockHash::all_zeros(),
            1000,
            0x207fffff, // Regtest difficulty
            0,
        );

        let result = state.process_headers(&[header], false);
        assert!(result.success);
        assert!(state.presync_work() > U256::zero());
        assert_eq!(state.presync_height(), 1);
    }

    #[test]
    fn test_locator_during_presync() {
        let start_hash = [42u8; 32];
        let state = HeadersSyncState::new(
            Network::Regtest,
            start_hash,
            0,
        );

        let locator = state.next_headers_request_locator();
        assert_eq!(locator.len(), 1);
        assert_eq!(locator[0], start_hash);
    }

    #[test]
    fn test_finalize_clears_state() {
        let mut state = HeadersSyncState::new(
            Network::Regtest,
            [0u8; 32],
            0,
        );

        // Add some state
        state.presync_commitments.push(true);
        state.redownload_buffer.push(CompressedHeader {
            version: 1,
            merkle_root: [0u8; 32],
            time: 0,
            bits: 0,
            nonce: 0,
        });

        state.finalize();

        assert_eq!(state.phase(), HeadersSyncPhase::Final);
        assert!(state.presync_commitments.is_empty());
        assert!(state.redownload_buffer.is_empty());
    }
}
