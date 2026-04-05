//! Block validation module

use std::sync::Arc;
use std::collections::HashSet;

use bitcoin::{Block, Network};
use bitcoin::hashes::Hash;
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use common::{BlockWrapper, BlockHeaderWrapper, BlockMetadata, TransactionWrapper, OutPointWrapper, UTXO};
use crate::chainwork::compute_chainwork;
use common::crypto::compute_merkle_root;

use super::header::{HeaderValidator, HeaderValidationError};
use super::transaction::{TransactionValidator, TransactionValidationError};

/// Block validation error types
#[derive(Error, Debug)]
pub enum BlockValidationError {
    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("Header validation error: {0}")]
    HeaderValidation(#[from] HeaderValidationError),

    #[error("Transaction validation error: {0}")]
    TransactionValidation(#[from] TransactionValidationError),

    #[error("Block size exceeds limit")]
    SizeExceeded,

    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    #[error("Block has no transactions")]
    NoTransactions,

    #[error("Block has no coinbase transaction")]
    NoCoinbase,

    #[error("Block has multiple coinbase transactions")]
    MultipleCoinbase,

    #[error("Duplicate transaction detected")]
    DuplicateTransaction,

    #[error("Total sigops exceeds limit")]
    TooManySigops,

    #[error("Coinbase amount exceeds subsidy + fees")]
    CoinbaseAmountExceeded,

    #[error("Previous block not found")]
    PreviousBlockNotFound,

    #[error("Block not found: {0}")]
    BlockNotFound(String),
}

/// Result type for block validation
pub type Result<T> = std::result::Result<T, BlockValidationError>;

/// Read the assumevalid height from OUROBOROS_ASSUMEVALID env var.
/// - Not set or empty → use default for the network (u32::MAX = skip scripts for all blocks)
/// - "0" → disable (validate everything)
/// - Any other u32 → use that height
fn assumevalid_height_from_env() -> Option<u32> {
    match std::env::var("OUROBOROS_ASSUMEVALID") {
        Ok(val) if val == "0" => Some(0),
        Ok(val) => val.parse::<u32>().ok(),
        Err(_) => None,
    }
}

/// Block validator
pub struct BlockValidator {
    db: Arc<BlockchainDB>,
    header_validator: HeaderValidator,
    tx_validator: TransactionValidator,
    /// Blocks at or below this height skip script/input validation (assumevalid).
    /// 0 = validate everything. u32::MAX = skip scripts for entire chain.
    assumevalid_height: u32,
    /// Network for determining activation heights
    network: Network,
}

impl BlockValidator {
    /// Create a new block validator
    pub fn new(db: Arc<BlockchainDB>, network: Network) -> Self {
        let header_validator = HeaderValidator::new(Arc::clone(&db), network);
        let tx_validator = TransactionValidator::new(Arc::clone(&db));

        let default_height = match network {
            Network::Bitcoin => 938_343,   // Bitcoin Core v28 default assumevalid
            Network::Testnet4 => 123_613,  // Testnet4 assumevalid
            _ => 0,                        // Validate everything on other networks
        };
        let assumevalid_height = assumevalid_height_from_env().unwrap_or(default_height);

        if assumevalid_height == 0 {
            log::info!("[validator] assumevalid disabled — full validation for all blocks");
        } else {
            log::info!("[validator] assumevalid enabled — skipping script/input validation for blocks ≤ height {}", assumevalid_height);
        }

        Self {
            db,
            header_validator,
            tx_validator,
            assumevalid_height,
            network,
        }
    }

    /// Validate a block.
    ///
    /// When `height ≤ assumevalid_height`, performs only structural checks
    /// (header PoW, merkle root, coinbase structure, duplicate txs, sigops)
    /// and skips per-transaction input validation and script checks — matching
    /// Bitcoin Core's `assumevalid` optimization (validation.cpp:2344-2378).
    ///
    /// Above the assumevalid height, full validation is performed.
    pub fn validate_block(&self, block: &BlockWrapper, prev_height: u32) -> Result<()> {
        let inner = block.inner();
        let height = prev_height + 1;
        let full_validation = height > self.assumevalid_height;

        // 1. Validate header (PoW, timestamps, difficulty — always)
        self.validate_header(block, prev_height)?;

        // 2. Check block weight limit (always — quick check on tx count)
        self.check_size_limits(inner)?;

        // 3. Verify merkle root (always — proves tx integrity)
        if !self.verify_merkle_root(inner) {
            return Err(BlockValidationError::InvalidMerkleRoot);
        }

        // 4. Non-empty block
        if inner.txdata.is_empty() {
            return Err(BlockValidationError::NoTransactions);
        }

        // 5. Coinbase checks (always — cheap structural)
        let coinbase_tx = &inner.txdata[0];
        if !coinbase_tx.is_coinbase() {
            return Err(BlockValidationError::NoCoinbase);
        }
        for tx in inner.txdata.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(BlockValidationError::MultipleCoinbase);
            }
        }

        // 6. Duplicate tx check (always)
        self.check_duplicate_transactions(inner)?;

        // 7. Per-transaction validation
        if full_validation {
            self.tx_validator.check_coinbase(coinbase_tx, height)
                .map_err(BlockValidationError::TransactionValidation)?;

            for tx in inner.txdata.iter().skip(1) {
                let tx_wrapper = TransactionWrapper::new(tx.clone());
                self.tx_validator.validate_transaction(&tx_wrapper, height, true)
                    .map_err(BlockValidationError::TransactionValidation)?;
            }
        }

        // 8. Sigop cost limit with BIP141 witness discount (always enforced)
        //
        // Reference: Bitcoin Core validation.cpp ConnectBlock()
        //
        // Legacy/P2SH sigops cost 4 weight units each (WITNESS_SCALE_FACTOR).
        // Witness sigops cost 1 weight unit each (discounted).
        // Total block sigop cost must not exceed MAX_BLOCK_SIGOPS_COST (80,000).
        let (verify_p2sh, verify_witness) = self.get_sigop_flags(height);
        let total_sigop_cost = super::sigop::get_block_sigop_cost(
            &inner.txdata,
            &self.db,
            verify_p2sh,
            verify_witness,
        );
        if total_sigop_cost > super::sigop::MAX_BLOCK_SIGOPS_COST {
            return Err(BlockValidationError::TooManySigops);
        }

        Ok(())
    }

    /// Get sigop verification flags based on block height and network.
    ///
    /// Returns (verify_p2sh, verify_witness) based on activation heights.
    fn get_sigop_flags(&self, height: u32) -> (bool, bool) {
        use super::script::activation_heights;

        // P2SH activation height
        let p2sh_height = match self.network {
            Network::Bitcoin => 173805,
            _ => 0, // active from genesis on testnets
        };
        let verify_p2sh = height >= p2sh_height;

        // SegWit activation height
        let segwit_height = activation_heights::segwit_height(self.network);
        let verify_witness = height >= segwit_height;

        (verify_p2sh, verify_witness)
    }

    /// Validate block header
    fn validate_header(&self, block: &BlockWrapper, prev_height: u32) -> Result<()> {
        let inner = block.inner();
        let header = BlockHeaderWrapper::new(inner.header);

        let prev_block = self.db.get_block_by_height(prev_height)?
            .ok_or(BlockValidationError::PreviousBlockNotFound)?;
        let prev_header = BlockHeaderWrapper::new(prev_block.inner().header);

        self.header_validator.validate_header(&header, &prev_header)?;

        Ok(())
    }

    /// Check block size limits.
    ///
    /// Uses transaction count as a fast upper-bound proxy instead of
    /// re-serializing the entire block (which was the previous bottleneck).
    /// Bitcoin's max block weight is 4M weight units; the absolute max
    /// serialized size is 4MB.
    fn check_size_limits(&self, block: &Block) -> Result<()> {
        // Each tx is at least 60 bytes serialized (version + 1 in + 1 out + locktime).
        // 4_000_000 / 60 ≈ 66_666 transactions max. Use a generous ceiling.
        const MAX_TX_COUNT: usize = 100_000;
        if block.txdata.len() > MAX_TX_COUNT {
            return Err(BlockValidationError::SizeExceeded);
        }
        Ok(())
    }

    /// Verify merkle root matches transactions
    pub fn verify_merkle_root(&self, block: &Block) -> bool {
        let txids: Vec<[u8; 32]> = block.txdata
            .iter()
            .map(|tx| *tx.compute_txid().as_byte_array())
            .collect();

        let computed_root = compute_merkle_root(&txids);
        let header_root = block.header.merkle_root.as_byte_array();
        computed_root == *header_root
    }

    /// Check for duplicate transactions in block
    fn check_duplicate_transactions(&self, block: &Block) -> Result<()> {
        let mut seen_txids = HashSet::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if !seen_txids.insert(txid) {
                return Err(BlockValidationError::DuplicateTransaction);
            }
        }

        Ok(())
    }

    /// Validate block subsidy
    pub fn validate_block_subsidy(&self, block: &Block, height: u32, total_fees: u64) -> Result<()> {
        let subsidy = self.calculate_block_subsidy(height);

        let coinbase = &block.txdata[0];
        let coinbase_total: u64 = coinbase.output.iter()
            .map(|out| out.value.to_sat())
            .sum();

        let max_coinbase = subsidy
            .checked_add(total_fees)
            .ok_or(BlockValidationError::CoinbaseAmountExceeded)?;

        if coinbase_total > max_coinbase {
            return Err(BlockValidationError::CoinbaseAmountExceeded);
        }

        Ok(())
    }

    /// Calculate block subsidy for a given height
    ///
    /// Bitcoin subsidy starts at 50 BTC and halves every 210,000 blocks.
    pub fn calculate_block_subsidy(&self, height: u32) -> u64 {
        let halvings = height / 210_000;
        if halvings >= 64 {
            return 0;
        }
        50_000_000_000u64 >> halvings
    }

    /// Apply block to database using a two-phase commit for crash safety.
    ///
    /// **Phase 1**: Write HEAD_BLOCKS marker to META_CF, then apply all UTXO
    /// changes (spend inputs, create outputs) and store the block body +
    /// metadata.
    ///
    /// **Phase 2**: Update BEST_BLOCK_HASH / BEST_HEIGHT, then delete the
    /// HEAD_BLOCKS marker.
    ///
    /// If the process crashes between Phase 1 and Phase 2, the HEAD_BLOCKS
    /// marker will persist and `BlockchainDB::recover_from_crash()` (called
    /// on next startup) will roll back the partial apply using undo data in
    /// SPENT_CF.
    ///
    /// Ref: Bitcoin Core txdb.cpp DB_HEAD_BLOCKS pattern.
    pub fn apply_block(&self, block: &BlockWrapper, height: u32) -> Result<()> {
        let inner = block.inner();
        let block_hash = *block.block_hash().as_byte_array();

        // Phase 1: Write HEAD_BLOCKS marker
        // Record old tip so crash recovery knows where to roll back to.
        let (old_tip_hash, old_tip_height) = if height == 0 {
            ([0u8; 32], 0u32)
        } else {
            self.db.get_best_block().unwrap_or(([0u8; 32], 0))
        };
        self.db.write_head_blocks(
            &old_tip_hash,
            old_tip_height,
            &block_hash,
            height,
        )?;

        // UTXO mutations + transaction index
        for (tx_pos, tx) in inner.txdata.iter().enumerate() {
            let txid = tx.compute_txid();

            if !tx.is_coinbase() {
                for input in &tx.input {
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    self.db.spend_utxo(outpoint.inner(), &txid.as_byte_array())?;
                }
            }

            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                let utxo = UTXO::new(
                    outpoint.clone(),
                    output.value.to_sat(),
                    output.script_pubkey.clone(),
                    Some(height),
                    tx.is_coinbase(),
                );
                self.db.add_utxo(outpoint.inner(), &utxo)?;
            }

            // Store transaction index: txid → (block_hash, height, position)
            self.db.store_tx_index(
                txid.as_byte_array(),
                &block_hash,
                height,
                tx_pos as u32,
            )?;
        }

        // Store block body + metadata
        self.db.store_block(block)?;

        let timestamp = inner.header.time;
        let bits = inner.header.bits.to_consensus();
        let prev_chainwork = if height == 0 {
            [0u8; 32]
        } else {
            self.db
                .get_block_metadata(height - 1)
                .ok()
                .and_then(|opt| opt.map(|m| m.chainwork))
                .unwrap_or([0u8; 32])
        };
        let chainwork = compute_chainwork(&prev_chainwork, bits);
        let metadata = BlockMetadata::new(height, chainwork, timestamp);
        self.db.store_block_metadata(height, &block_hash, &metadata)?;

        // Phase 2: Update chain tip + delete marker
        self.db.update_best_block(&block_hash, height)?;
        self.db.delete_head_blocks()?;

        Ok(())
    }

    /// Disconnect a block — reverse UTXO changes made by `apply_block()`.
    ///
    /// Used for blockchain reorganizations (reorgs).  Processes transactions
    /// in reverse order:
    ///
    /// 1. Remove UTXOs *created* by this block (outputs → delete from chainstate).
    /// 2. Restore UTXOs *spent* by this block (inputs → read undo data from
    ///    SPENT_CF, re-add to chainstate, delete undo record).
    /// 3. Update `BEST_BLOCK_HASH` / `BEST_HEIGHT` to the previous block.
    ///
    /// The block index entry (height → hash + metadata) and the block body in
    /// BLOCKS_CF are **not** removed — callers may choose to keep or prune them.
    pub fn disconnect_block(&self, block: &BlockWrapper, height: u32) -> Result<()> {
        let inner = block.inner();

        // Process transactions in reverse order (last tx first)
        for tx in inner.txdata.iter().rev() {
            let txid = tx.compute_txid();

            // 1. Remove outputs (UTXOs created by this block)
            for vout in 0..tx.output.len() {
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                self.db.delete_utxo(outpoint.inner())?;
            }

            // 2. Restore inputs (UTXOs spent by this block)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    // Read undo record from SPENT_CF
                    match self.db.get_spent_utxo(outpoint.inner())? {
                        Some((_spending_txid, utxo)) => {
                            // Restore the UTXO to chainstate
                            self.db.add_utxo(outpoint.inner(), &utxo)?;
                            // Remove the undo record
                            self.db.delete_spent_record(outpoint.inner())?;
                        }
                        None => {
                            log::warn!(
                                "disconnect_block: no undo record for outpoint {:?} — \
                                 UTXO cannot be restored",
                                input.previous_output,
                            );
                        }
                    }
                }
            }

            // 3. Remove transaction index entry
            self.db.delete_tx_index(txid.as_byte_array())?;
        }

        // 3. Update best block to the previous block
        if height > 0 {
            let prev_hash = *inner.header.prev_blockhash.as_byte_array();
            self.db.update_best_block(&prev_hash, height - 1)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Block, BlockHash, Transaction};
    use std::sync::Arc;
    use tempdir::TempDir;

    fn create_test_db() -> (TempDir, Arc<BlockchainDB>) {
        let temp_dir = TempDir::new("bitcoin_block_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        (temp_dir, db)
    }

    #[test]
    fn test_verify_merkle_root() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

        // Create a simple block with one transaction
        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let txids: Vec<[u8; 32]> = vec![*coinbase_tx.compute_txid().as_byte_array()];
        let merkle_root = compute_merkle_root(&txids);

        let block = Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::blockdata::block::TxMerkleNode::from_byte_array(merkle_root),
                time: 1234567890u32, // timestamp as u32
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx],
        };

        let block_wrapper = BlockWrapper::new(block);
        assert!(validator.verify_merkle_root(block_wrapper.inner()));
    }

    #[test]
    fn test_calculate_block_subsidy() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

        // Genesis block: 50 BTC
        assert_eq!(validator.calculate_block_subsidy(0), 50_000_000_000);
        assert_eq!(validator.calculate_block_subsidy(209_999), 50_000_000_000);

        // After first halving: 25 BTC
        assert_eq!(validator.calculate_block_subsidy(210_000), 25_000_000_000);
        assert_eq!(validator.calculate_block_subsidy(419_999), 25_000_000_000);

        // After second halving: 12.5 BTC
        assert_eq!(validator.calculate_block_subsidy(420_000), 12_500_000_000);

        // After 64 halvings: 0
        assert_eq!(validator.calculate_block_subsidy(64 * 210_000), 0);
    }

    #[test]
    fn test_check_duplicate_transactions() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

        // Create a transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid = tx.compute_txid();
        let merkle_root = compute_merkle_root(&[*txid.as_byte_array()]);

        // Create block with duplicate transactions
        let block = Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::blockdata::block::TxMerkleNode::from_byte_array(merkle_root),
                time: 1234567890u32, // timestamp as u32
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx.clone(), tx], // Duplicate!
        };

        let block_wrapper = BlockWrapper::new(block);
        let result = validator.check_duplicate_transactions(block_wrapper.inner());
        assert!(matches!(result, Err(BlockValidationError::DuplicateTransaction)));
    }
}

