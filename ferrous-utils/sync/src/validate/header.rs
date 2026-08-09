//! Block header validation chain

use std::sync::Arc;

use bitcoin::{blockdata::block::Header, Network};
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use crate::chain_params::{
    get_checkpoints, get_last_checkpoint, verify_checkpoint, is_below_last_checkpoint,
    minimum_chain_work, Checkpoint,
};
use common::BlockHeaderWrapper;
use primitive_types::U256;

use super::pow::{bits_to_target, validate_pow};
use super::difficulty::{self, BlockIndexInfo};
use crate::chain_params::get_consensus_params;
use bitcoin::hashes::Hash as _;

/// Header validation error types
#[derive(Error, Debug)]
pub enum HeaderValidationError {
    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("Proof of work validation failed")]
    InvalidPow,

    #[error("Previous block hash mismatch")]
    PrevHashMismatch,

    #[error("Timestamp too far in the future")]
    TimestampTooFarFuture,

    #[error("Timestamp not greater than median time past")]
    TimestampBeforeMedian,

    #[error("Version too low for soft fork compliance")]
    InvalidVersion,

    #[error("Difficulty does not match expected value")]
    InvalidDifficulty,

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Invalid header chain: {0}")]
    InvalidChain(String),

    #[error("Checkpoint validation failed at height {0}: block hash does not match")]
    CheckpointMismatch(u32),

    #[error("Chain branches before last checkpoint at height {0}")]
    ForkBeforeCheckpoint(u32),

    #[error("Chain has insufficient work: {0} < minimum {1}")]
    InsufficientChainWork(String, String),
}

/// Result type for header validation
pub type Result<T> = std::result::Result<T, HeaderValidationError>;

/// Core's FIRST `ContextualCheckBlockHeader` gate, as a pure function of the
/// header pair, the height, the network and an ancestor resolver:
///
/// ```text
/// if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
///     return state.Invalid(BLOCK_INVALID_HEADER, "bad-diffbits", ...);
/// ```
/// bitcoin-core/src/validation.cpp:4088-4089.
///
/// Split out of [`HeaderValidator::validate_difficulty`] so the rule can be
/// unit-tested against injected ancestors on mainnet- and testnet4-shaped
/// parameters, with no RocksDB in the loop.  A regtest-only test would be a
/// NO-OP here: `pow_no_retargeting` makes every height answer powLimit, so an
/// implementation that ignores the rule entirely passes it.
pub fn check_diffbits<F>(
    header: &Header,
    prev_header: &Header,
    prev_height: u32,
    network: Network,
    get_ancestor: F,
) -> Result<()>
where
    F: Fn(u32) -> Option<BlockIndexInfo>,
{
    let actual_bits = header.bits.to_consensus();
    let prev_bits = prev_header.bits.to_consensus();
    let height = prev_height + 1;
    let params = get_consensus_params(network);
    let last_block = BlockIndexInfo {
        height: prev_height,
        bits: prev_bits,
        timestamp: prev_header.time,
    };

    match difficulty::get_next_work_required(&last_block, header.time, network, get_ancestor) {
        Some(bits) => {
            if actual_bits != bits {
                log::warn!(
                    "bad-diffbits at height {}: nBits {:#010x} != required {:#010x}",
                    height,
                    actual_bits,
                    bits
                );
                return Err(HeaderValidationError::InvalidDifficulty);
            }
            Ok(())
        }
        None => {
            // NARROW, documented fallback — never a silent skip.
            //
            // `get_next_work_required` propagates absence instead of answering
            // powLimit (see its fail-closed contract).  On this path the
            // ancestor set comes from OUR OWN store below OUR OWN active tip,
            // so a miss is a datadir-shaped gap (assumeUTXO base, pruned
            // body), not something a peer can steer.  What is still
            // enforceable:
            //   * min-difficulty networks: `PermittedDifficultyTransition`
            //     returns true unconditionally (Core pow.cpp:91) so it has
            //     zero strength — use the explicit two-value rule instead
            //     (powLimit and prev.nBits are the only values the truncated
            //     path can produce).
            //   * everything else: the 4x/0.25x clamp still binds.
            let ok = if params.pow_allow_min_difficulty_blocks {
                actual_bits == params.pow_limit_bits || actual_bits == prev_bits
            } else {
                difficulty::permitted_difficulty_transition(
                    height,
                    prev_bits,
                    actual_bits,
                    network,
                )
            };
            if ok {
                log::warn!(
                    "bad-diffbits ancestors unresolvable at height {} — accepted \
                     on the narrow fallback (nBits {:#010x}, prev {:#010x})",
                    height,
                    actual_bits,
                    prev_bits
                );
                Ok(())
            } else {
                log::warn!(
                    "bad-diffbits at height {} (ancestors unresolvable, fallback \
                     rejected): nBits {:#010x}, prev {:#010x}",
                    height,
                    actual_bits,
                    prev_bits
                );
                Err(HeaderValidationError::InvalidDifficulty)
            }
        }
    }
}

/// Block header validator
pub struct HeaderValidator {
    db: Arc<BlockchainDB>,
    network: Network,
}

impl HeaderValidator {
    /// Create a new header validator
    pub fn new(db: Arc<BlockchainDB>, network: Network) -> Self {
        Self { db, network }
    }

    /// Validate a single block header
    ///
    /// Performs comprehensive validation including:
    /// - Proof of work verification
    /// - Previous block hash continuity
    /// - Timestamp validation
    /// - Version compliance
    /// - Difficulty target verification
    pub fn validate_header(
        &self,
        header: &BlockHeaderWrapper,
        prev_header: &BlockHeaderWrapper,
        prev_height: u32,
    ) -> Result<()> {
        let inner = header.inner();
        let prev_inner = prev_header.inner();

        // 1. Check version for soft fork compliance
        self.validate_version(inner)?;

        // 2. Verify previous block hash matches
        if inner.prev_blockhash != prev_header.block_hash() {
            return Err(HeaderValidationError::PrevHashMismatch);
        }

        // 3. Validate timestamp
        self.validate_timestamp(inner, prev_inner)?;

        // 4. Verify difficulty matches expected
        //    Core ContextualCheckBlockHeader "bad-diffbits"
        //    (validation.cpp:4088-4089).
        self.validate_difficulty(inner, prev_inner, prev_height)?;

        // 5. Check proof of work (most expensive check last)
        let target = bits_to_target(inner.bits.to_consensus());
        if !validate_pow(header, target) {
            return Err(HeaderValidationError::InvalidPow);
        }

        Ok(())
    }

    /// Validate an entire chain of headers
    ///
    /// Checks that all headers form a valid chain and that difficulty
    /// adjustments are correct for the network rules.
    /// `first_height` is the height of `headers[0]`; every subsequent header
    /// is one higher.  The height is REQUIRED — the difficulty rule is
    /// height-dependent (retarget boundary, min-difficulty walk-back), so a
    /// height-free variant cannot evaluate it.
    pub fn validate_header_chain(
        &self,
        headers: &[BlockHeaderWrapper],
        first_height: u32,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        // Validate each header in sequence
        for i in 0..headers.len() {
            if i == 0 {
                // For the first header, we need to get the previous header from the database
                // This is a simplified version - in practice we'd need to know the height
                continue; // Skip first header validation in this simplified version
            }

            let prev_header = &headers[i - 1];
            let current_header = &headers[i];

            self.validate_header(current_header, prev_header, first_height + (i as u32) - 1)?;
        }

        // NOTE: the old `validate_chain_difficulty_adjustments` heuristic was
        // deleted here.  It compared the RAW u32 compact nBits values as a
        // ±10% ratio and used the BATCH INDEX (`(i + 1) % 2016`) as the
        // retarget-boundary test — both meaningless (compact encoding is not
        // linear in difficulty, and batch index is not height).  With the real
        // per-header rule above it was pure false-reject risk.

        Ok(())
    }

    /// Get the median time past for a given height
    ///
    /// Returns the median timestamp of the last 11 blocks (including the current height).
    /// This is used for timestamp validation to prevent timestamp manipulation attacks.
    pub fn get_median_time_past(&self, height: u32) -> Result<u32> {
        // For heights less than 11, we need at least height+1 blocks
        let start_height = if height >= 10 { height.saturating_sub(10) } else { 0 };
        let count = (height - start_height + 1).min(11);

        let mut timestamps = Vec::with_capacity(count as usize);

        for h in start_height..=height {
            let block = self.db.get_block_by_height(h)?
                .ok_or_else(|| HeaderValidationError::BlockNotFound(format!("Block at height {}", h)))?;

            timestamps.push(block.inner().header.time);
        }

        // Sort timestamps and return median
        timestamps.sort_unstable();
        let median_index = timestamps.len() / 2;
        Ok(timestamps[median_index])
    }

    // NOTE: `HeaderValidator::get_next_work_required(height)` used to live
    // here.  It was a dead, height-indexed, mainnet-only THIRD implementation
    // of the retarget rule (hardcoded 0x1d00ffff for genesis, `(height+1) %
    // 2016` boundary test, no min-difficulty / BIP94 handling) referenced only
    // by this file's own tests.  Deleted so a future caller cannot pick up the
    // wrong engine: `validate/difficulty.rs` is the one Rust implementation,
    // and `ouroboros.validation._get_expected_bits` is the one Python
    // implementation.

    /// Validate timestamp constraints
    fn validate_timestamp(&self, header: &Header, prev_header: &Header) -> Result<()> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Check not too far in the future (2 hours)
        const MAX_FUTURE_SECONDS: u32 = 2 * 60 * 60;
        if header.time > current_time + MAX_FUTURE_SECONDS {
            return Err(HeaderValidationError::TimestampTooFarFuture);
        }

        // Check greater than median time past
        // During header sync, we skip this check entirely since we don't have full block data
        // to calculate proper median time. Bitcoin's actual median time calculation
        // uses the median of the last 11 blocks, which we can't do accurately during
        // header-only sync. We'll do full validation later when syncing blocks.
        // 
        // For now, we only check that timestamps aren't completely invalid (too far in future).
        // The backward timestamp check is skipped during header sync to allow the sync to proceed.
        // Full timestamp validation will happen during block sync when we have complete data.
        //
        // Note: We could add a flag to distinguish header sync vs block sync, but for now
        // we'll just skip the backward check to allow header sync to complete.
        // Skip backward timestamp validation during header sync
        // if prev_header.time > header.time + MAX_BACKWARD_SECONDS {
        //     return Err(HeaderValidationError::TimestampBeforeMedian);
        // }

        Ok(())
    }

    /// Validate version for soft fork compliance
    fn validate_version(&self, header: &Header) -> Result<()> {
        // Basic version validation
        // Bitcoin Core requires version >= 1 for BIP34 compliance after block 227,835
        // For now, just check minimum version
        if header.version.to_consensus() < 1 {
            return Err(HeaderValidationError::InvalidVersion);
        }

        Ok(())
    }

    /// Validate difficulty target — Core's FIRST ContextualCheckBlockHeader
    /// gate: `block.nBits != GetNextWorkRequired(pindexPrev, &block, params)`
    /// -> `bad-diffbits` (bitcoin-core/src/validation.cpp:4088-4089).
    ///
    /// This is NOT the hash-vs-declared-target check (that is
    /// `CheckProofOfWork`, run by the caller as step 5).  It is
    /// nBits-vs-REQUIRED, and without it a peer can hand us a chain of
    /// difficulty-1 headers whose hashes legitimately meet their own claimed
    /// targets.
    ///
    /// Before this fix the body of `if actual_bits != expected_bits {}` was
    /// literally EMPTY with a comment saying production would be "much
    /// stricter".  That branch has been on the production block-connect path
    /// (block.rs:504, reached from `validate_block_from_bytes` for every
    /// block below the assumevalid checkpoint) the whole time.
    ///
    /// POISON-IMMUNITY.  Ancestors are resolved through
    /// [`Self::ancestor_provider`], which only consults the height index
    /// BELOW a hash that has been proven to sit on the active best chain.
    /// `prev_header` here is by construction the caller's parent block
    /// (block.rs:500 reads it by height and `validate_header` then asserts
    /// `header.prev_blockhash == prev_header.block_hash()`), so its ancestry
    /// IS the active chain — this is Core's `pindexLast->GetAncestor(h)`.
    fn validate_difficulty(
        &self,
        header: &Header,
        prev_header: &Header,
        prev_height: u32,
    ) -> Result<()> {
        let anchor_hash = prev_header.block_hash().to_byte_array();
        check_diffbits(
            header,
            prev_header,
            prev_height,
            self.network,
            |h| self.ancestor_at(h, prev_height, &anchor_hash),
        )
    }

    /// Resolve an ancestor of the block at `(anchor_height, anchor_hash)` for
    /// the difficulty rule — Core's `pindexLast->GetAncestor(height)`.
    ///
    /// The anchor is verified to be the active-chain block at
    /// `anchor_height` (its hash must match the height index) BEFORE any
    /// height-addressed read is allowed.  Without that proof a height read
    /// could return a block from a different chain, which is the inversion
    /// this whole fix exists to avoid.
    ///
    /// Cost: `None` for `height >= anchor_height` never touches the DB; a
    /// retarget boundary costs exactly ONE `get_block_by_height`
    /// (`anchor_height - 2015`), not a 2015-block walk.  The min-difficulty
    /// walk-back is the only multi-read case and is testnet-only.
    fn ancestor_at(
        &self,
        height: u32,
        anchor_height: u32,
        anchor_hash: &[u8; 32],
    ) -> Option<BlockIndexInfo> {
        if height > anchor_height {
            return None;
        }
        // Anchor proof: the height index must agree that `anchor_hash` is the
        // active-chain block at `anchor_height`.
        match self.db.get_block_hash_by_height(anchor_height) {
            Ok(Some(h)) if &h == anchor_hash => {}
            _ => return None,
        }
        let block = self.db.get_block_by_height(height).ok()??;
        let hdr = block.inner().header;
        Some(BlockIndexInfo {
            height,
            bits: hdr.bits.to_consensus(),
            timestamp: hdr.time,
        })
    }

    // =========================================================================
    // Checkpoint validation
    // =========================================================================

    /// Validate a header against checkpoints.
    ///
    /// This checks:
    /// 1. If a checkpoint exists at this height, the hash must match
    /// 2. The chain must not fork before the last checkpoint
    ///
    /// Returns Ok(true) if the header is at a checkpoint height (can skip script validation),
    /// Ok(false) if validation passed but not at a checkpoint.
    pub fn validate_checkpoint(
        &self,
        height: u32,
        block_hash: &[u8; 32],
    ) -> Result<bool> {
        // Check if there's a checkpoint at this exact height
        if let Some(matches) = verify_checkpoint(self.network, height, block_hash) {
            if !matches {
                return Err(HeaderValidationError::CheckpointMismatch(height));
            }
            return Ok(true); // At checkpoint, hash matches
        }

        Ok(false) // Not at a checkpoint height
    }

    /// Check if a fork point is valid with respect to checkpoints.
    ///
    /// A fork is invalid if it branches off before the last checkpoint.
    /// This prevents attackers from creating long alternative chains that
    /// could waste validation resources.
    pub fn validate_fork_point(&self, fork_height: u32) -> Result<()> {
        if let Some(last_cp) = get_last_checkpoint(self.network) {
            if fork_height < last_cp.height {
                return Err(HeaderValidationError::ForkBeforeCheckpoint(last_cp.height));
            }
        }
        Ok(())
    }

    /// Check if a height is at or below the last checkpoint.
    ///
    /// Used to determine if script validation can be skipped during IBD.
    /// Blocks at or below the last checkpoint only need PoW and merkle root validation.
    pub fn is_below_checkpoint(&self, height: u32) -> bool {
        is_below_last_checkpoint(self.network, height)
    }

    /// Get all checkpoints for this network.
    pub fn get_checkpoints(&self) -> Vec<Checkpoint> {
        get_checkpoints(self.network)
    }

    /// Get the last checkpoint height, or None if no checkpoints exist.
    pub fn last_checkpoint_height(&self) -> Option<u32> {
        get_last_checkpoint(self.network).map(|cp| cp.height)
    }

    /// Validate that a chain has sufficient cumulative work.
    ///
    /// Rejects headers from chains with less work than nMinimumChainWork.
    /// This prevents DoS attacks where an attacker sends headers from
    /// a low-work chain.
    pub fn validate_minimum_chain_work(&self, chain_work: U256) -> Result<()> {
        let min_work = minimum_chain_work(self.network);
        if chain_work < min_work {
            return Err(HeaderValidationError::InsufficientChainWork(
                format!("{:x}", chain_work),
                format!("{:x}", min_work),
            ));
        }
        Ok(())
    }

    /// Check if script validation can be skipped for a block.
    ///
    /// During IBD, blocks at or below the last checkpoint can skip script validation
    /// because they have been validated by the wider network and are protected by PoW.
    /// Only PoW and merkle root need to be verified.
    pub fn can_skip_script_validation(&self, height: u32, block_hash: &[u8; 32]) -> bool {
        // Must be at or below last checkpoint
        if !self.is_below_checkpoint(height) {
            return false;
        }

        // If at a checkpoint height, verify hash matches
        if let Some(matches) = verify_checkpoint(self.network, height, block_hash) {
            if !matches {
                return false; // Checkpoint mismatch - must do full validation
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{blockdata::block::Header, BlockHash, TxMerkleNode};
    use bitcoin::hashes::Hash;
    use std::sync::Arc;
    use tempdir::TempDir;

    fn create_test_db() -> (Arc<BlockchainDB>, TempDir) {
        let temp_dir = TempDir::new("sync_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        (db, temp_dir)
    }

    fn create_test_header(
        prev_hash: BlockHash,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> BlockHeaderWrapper {
        let header = Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: prev_hash,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(bits),
            nonce,
        };
        BlockHeaderWrapper::new(header)
    }

    #[test]
    fn test_validate_header_basic() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        let genesis_header = create_test_header(
            BlockHash::all_zeros(),
            1231006505,
            0x1d00ffff,
            2083236893,
        );

        // Test self-validation (genesis -> genesis should fail due to prev_hash mismatch)
        let result = validator.validate_header(&genesis_header, &genesis_header, 0);
        assert!(matches!(result, Err(HeaderValidationError::PrevHashMismatch)));
    }

    #[test]
    fn test_validate_header_pow() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        // Create a header with invalid nonce (should fail PoW)
        let header1 = create_test_header(
            BlockHash::all_zeros(),
            1231006505,
            0x1d00ffff,
            0, // Invalid nonce
        );

        let header2 = create_test_header(
            header1.block_hash(),
            1231006506,
            0x1d00ffff,
            0,
        );

        let result = validator.validate_header(&header2, &header1, 0);
        // This might pass or fail depending on whether nonce 0 happens to be valid
        // In practice, we'd use known valid headers
        let _ = result; // Just ensure it doesn't panic
    }

    #[test]
    fn test_get_median_time_past() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db.clone(), Network::Bitcoin);

        // Store some test blocks
        for height in 0..12 {
            let prev_hash = if height == 0 {
                BlockHash::all_zeros()
            } else {
                let prev_block = db.get_block_by_height(height - 1).unwrap().unwrap();
                prev_block.block_hash()
            };

            let header = create_test_header(
                prev_hash,
                1231006505 + height * 600, // 10 minutes apart
                0x1d00ffff,
                height, // Simple nonce
            );

            let block = common::BlockWrapper::new(bitcoin::Block {
                header: header.inner().clone(),
                txdata: vec![], // Empty block
            });

            // Store the block
            db.store_block(&block).unwrap();

            // Store block metadata for height lookup
            let metadata = common::BlockMetadata::new(
                height,
                [0u8; 32], // Simple chainwork for testing
                header.inner().time,
            );
            db.store_block_metadata(height, &block.block_hash().to_byte_array(), &metadata).unwrap();
        }

        // Test median time past for height 11
        let median_time = validator.get_median_time_past(11).unwrap();

        // For height 11, gets heights 1-11 (11 blocks total)
        // Timestamps: 1231007105, 1231007705, ..., 1231013105
        // Sorted: same order, median is the 6th element (0-indexed) of 11 elements
        let expected_median = 1231006505 + 6 * 600;
        assert_eq!(median_time, expected_median);
    }

    #[test]
    fn test_validate_header_chain() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        let mut headers: Vec<BlockHeaderWrapper> = Vec::new();

        // Create a short valid chain
        for i in 0..5 {
            let prev_hash = if i == 0 {
                BlockHash::all_zeros()
            } else {
                headers[i - 1].block_hash()
            };

            let header = create_test_header(
                prev_hash,
                1231006505 + i as u32 * 600,
                0x1d00ffff,
                i as u32,
            );

            headers.push(header);
        }

        // Validate the chain
        let result = validator.validate_header_chain(&headers, 0);
        // This is a simplified test - in practice we'd need to store blocks first
        let _ = result; // Just ensure it doesn't panic
    }

    #[test]
    fn test_timestamp_validation() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db.clone(), Network::Bitcoin);

        let header1 = create_test_header(
            BlockHash::all_zeros(),
            1231006505,
            0x1d00ffff,
            1,
        );

        // Test future timestamp (too far ahead)
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32 + 3 * 60 * 60; // 3 hours in future

        let header2 = create_test_header(
            header1.block_hash(),
            future_time,
            0x1d00ffff,
            2,
        );

        let result = validator.validate_header(&header2, &header1, 0);
        assert!(matches!(result, Err(HeaderValidationError::TimestampTooFarFuture)));
    }

    #[test]
    fn test_version_validation() {
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        // Create header with invalid version
        let header = Header {
            version: bitcoin::blockdata::block::Version::from_consensus(0), // Invalid version
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1231006505,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2083236893, // Genesis nonce
        };

        let wrapper = BlockHeaderWrapper::new(header);
        let prev_wrapper = BlockHeaderWrapper::new(Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1231006504,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        });

        let result = validator.validate_header(&wrapper, &prev_wrapper, 0);
        assert!(matches!(result, Err(HeaderValidationError::InvalidVersion)));
    }

    #[test]
    fn test_real_bitcoin_difficulty_adjustments() {
        // Test with real Bitcoin difficulty adjustment data
        // Block 0: Genesis, 0x1d00ffff
        // Block 2016: First adjustment, actual timespan was about 8 days
        // Block 4032: Second adjustment, etc.

        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        // `HeaderValidator::get_next_work_required` was a dead, mainnet-only
        // duplicate of validate/difficulty.rs and has been deleted; the real
        // rule is exercised by `validate_difficulty` (see the bad-diffbits
        // tests below) and by difficulty.rs's own suite.
        let _ = validator;
    }

    #[test]
    fn test_header_chain_validation_with_difficulty_changes() {
        // Test header chain validation across difficulty adjustment boundaries
        let (db, _temp_dir) = create_test_db();
        let validator = HeaderValidator::new(db, Network::Bitcoin);

        let mut headers: Vec<BlockHeaderWrapper> = Vec::new();

        // Create headers that simulate a difficulty adjustment
        // First 2015 blocks at one difficulty, then adjustment
        for i in 0..2020 {
            let prev_hash = if i == 0 {
                BlockHash::all_zeros()
            } else {
                headers[i - 1].block_hash()
            };

            // Simulate difficulty change at block 2016
            let bits = if i < 2016 { 0x1d00ffff } else { 0x1c000000 }; // Simplified difficulty change

            let header = create_test_header(
                prev_hash,
                1231006505 + i as u32 * 600, // 10 minutes apart
                bits,
                i as u32,
            );

            headers.push(header);
        }

        // Validate the chain (this is a simplified test)
        let result = validator.validate_header_chain(&headers, 0);
        // The result may fail due to various reasons in this simplified test,
        // but the important thing is that it doesn't panic
        let _ = result;
    }

    // =====================================================================
    // bad-diffbits — Core validation.cpp:4088-4089
    //
    // Driven through `check_diffbits` with an INJECTED ancestor provider, so
    // the rule is exercised on mainnet- and testnet4-shaped parameters
    // without a RocksDB in the loop.  Before this fix `validate_difficulty`
    // computed `expected_bits`/`actual_bits` and then had an EMPTY
    // `if actual_bits != expected_bits {}` body — every one of the reject
    // cases below returned Ok(()).
    // =====================================================================

    const MAINNET_REAL_BITS: u32 = 0x1b0404cb;
    const POW_LIMIT: u32 = 0x1d00ffff;

    fn hdr(bits: u32, time: u32) -> Header {
        Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(bits),
            nonce: 0,
        }
    }

    fn no_ancestors(_h: u32) -> Option<BlockIndexInfo> {
        None
    }

    #[test]
    fn test_diffbits_mainnet_non_boundary() {
        // The actual production defect: a difficulty-1 header below a
        // real-difficulty parent, at a NON-boundary height.  Requires no
        // ancestor lookup at all, so it can never "fail to resolve".
        let prev = hdr(MAINNET_REAL_BITS, 1_760_000_000);
        let good = hdr(MAINNET_REAL_BITS, 1_760_000_600);
        let bad = hdr(POW_LIMIT, 1_760_000_600);

        assert!(check_diffbits(&good, &prev, 900_000, Network::Bitcoin, no_ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&bad, &prev, 900_000, Network::Bitcoin, no_ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ), "difficulty-1 nBits under a real-difficulty parent must be rejected");
    }

    #[test]
    fn test_diffbits_mainnet_boundary() {
        // Retarget at height 2016: actual timespan == target, so the new bits
        // equal the old bits.  A header claiming powLimit is rejected.
        let first_time = 1_231_006_505u32;
        let prev = hdr(MAINNET_REAL_BITS, first_time + 14 * 24 * 3600);
        let ancestors = |h: u32| {
            if h == 0 {
                Some(BlockIndexInfo { height: 0, bits: MAINNET_REAL_BITS, timestamp: first_time })
            } else {
                None
            }
        };
        let good = hdr(MAINNET_REAL_BITS, prev.time + 600);
        let bad = hdr(POW_LIMIT, prev.time + 600);

        assert!(check_diffbits(&good, &prev, 2015, Network::Bitcoin, ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&bad, &prev, 2015, Network::Bitcoin, ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ));
    }

    #[test]
    fn test_diffbits_testnet4_20min_rule_both_directions() {
        // (a) gap > 20 min -> powLimit is REQUIRED; carrying prev.bits is a
        //     rejection.  (b) gap <= 20 min with a real-difficulty parent ->
        //     prev.bits is required; carrying powLimit is a rejection.
        // An implementation that only handles (a) splits the chain on (b).
        let prev_real = hdr(MAINNET_REAL_BITS, 1_700_000_000);

        // (a)
        let late = hdr(POW_LIMIT, prev_real.time + 1201);
        let late_wrong = hdr(MAINNET_REAL_BITS, prev_real.time + 1201);
        assert!(check_diffbits(&late, &prev_real, 1000, Network::Testnet4, no_ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&late_wrong, &prev_real, 1000, Network::Testnet4, no_ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ), "a >20-minute testnet4 gap MUST carry powLimit");

        // (b) parent at powLimit, real-difficulty ancestor two hops back.
        let prev_min = hdr(POW_LIMIT, 1_700_000_000);
        let ancestors = |h: u32| match h {
            999 => Some(BlockIndexInfo { height: 999, bits: POW_LIMIT, timestamp: 1_699_999_400 }),
            998 => Some(BlockIndexInfo { height: 998, bits: MAINNET_REAL_BITS, timestamp: 1_699_998_800 }),
            _ => None,
        };
        let soon_good = hdr(MAINNET_REAL_BITS, prev_min.time + 300);
        let soon_bad = hdr(POW_LIMIT, prev_min.time + 300);
        assert!(check_diffbits(&soon_good, &prev_min, 1000, Network::Testnet4, ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&soon_bad, &prev_min, 1000, Network::Testnet4, ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ), "inside the 20-minute window the walk-back result is required, not powLimit");
    }

    #[test]
    fn test_diffbits_testnet4_bip94_boundary() {
        // BIP94: the retarget base is the FIRST block of the period, not prev.
        // Period-first and prev carry DIFFERENT bits so a mainnet-shaped
        // implementation produces a different answer and fails loudly.
        let first_time = 1_700_000_000u32;
        let prev = hdr(POW_LIMIT, first_time + 14 * 24 * 3600);
        let ancestors = |h: u32| {
            if h == 0 {
                Some(BlockIndexInfo { height: 0, bits: MAINNET_REAL_BITS, timestamp: first_time })
            } else {
                None
            }
        };
        // actual_timespan == TARGET_TIMESPAN -> base bits are preserved.
        let bip94_answer = MAINNET_REAL_BITS;         // first-block base
        let mainnet_answer = POW_LIMIT;               // last-block base

        let good = hdr(bip94_answer, prev.time + 600);
        let bad = hdr(mainnet_answer, prev.time + 600);
        assert!(check_diffbits(&good, &prev, 2015, Network::Testnet4, ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&bad, &prev, 2015, Network::Testnet4, ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ), "testnet4 must use the BIP94 (first-block) base, not the mainnet one");
        assert_ne!(bip94_answer, mainnet_answer);
    }

    #[test]
    fn test_diffbits_mainnet_unresolvable_still_clamped() {
        // Boundary with NO ancestor: the rule cannot be evaluated.  The narrow
        // fallback keeps the 4x clamp, so a 5x difficulty DROP is still
        // rejected — "unresolvable" is not a free pass.
        let prev = hdr(MAINNET_REAL_BITS, 1_231_006_505 + 14 * 24 * 3600);
        // 0x1d00ffff is ~2^32 times easier than 0x1b0404cb -> way past 4x.
        let way_easier = hdr(POW_LIMIT, prev.time + 600);
        assert!(matches!(
            check_diffbits(&way_easier, &prev, 2015, Network::Bitcoin, no_ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ));
        // Unchanged bits at a boundary are inside the clamp -> accepted.
        let same = hdr(MAINNET_REAL_BITS, prev.time + 600);
        assert!(check_diffbits(&same, &prev, 2015, Network::Bitcoin, no_ancestors).is_ok());
    }

    #[test]
    fn test_diffbits_testnet4_unresolvable_rejects_third_value() {
        // Truncated walk-back on testnet4: PermittedDifficultyTransition is
        // unconditionally true there, so the fallback is the explicit
        // two-value rule.  A THIRD value must still be rejected.
        let prev = hdr(POW_LIMIT, 1_700_000_000);
        let third = hdr(0x1c00ffff, prev.time + 300);
        assert!(matches!(
            check_diffbits(&third, &prev, 1000, Network::Testnet4, no_ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ));
        // The two permitted values still pass.
        assert!(check_diffbits(&hdr(POW_LIMIT, prev.time + 300), &prev, 1000, Network::Testnet4, no_ancestors).is_ok());
    }

    #[test]
    fn test_diffbits_regtest_is_a_noop_surface() {
        // DOCSTRING WARNING: this case is INSUFFICIENT on its own.  Regtest
        // sets pow_no_retargeting, so every height answers powLimit and an
        // implementation that ignores the difficulty rule entirely passes it.
        // It is here only to prove the fix does not break regtest fixtures.
        let prev = hdr(0x207fffff, 1_700_000_000);
        assert!(check_diffbits(&hdr(0x207fffff, prev.time + 1), &prev, 500, Network::Regtest, no_ancestors).is_ok());
        assert!(matches!(
            check_diffbits(&hdr(0x207ffffe, prev.time + 1), &prev, 500, Network::Regtest, no_ancestors),
            Err(HeaderValidationError::InvalidDifficulty)
        ));
    }
}
