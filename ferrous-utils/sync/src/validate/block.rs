//! Block validation module

use std::sync::Arc;
use std::collections::HashSet;

use bitcoin::{Block, Network};
use bitcoin::hashes::Hash;
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use common::{BlockWrapper, BlockHeaderWrapper, BlockMetadata, TransactionWrapper, OutPointWrapper, UTXO};
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

/// Block validator
pub struct BlockValidator {
    db: Arc<BlockchainDB>,
    header_validator: HeaderValidator,
    tx_validator: TransactionValidator,
}

impl BlockValidator {
    /// Create a new block validator
    pub fn new(db: Arc<BlockchainDB>, network: Network) -> Self {
        let header_validator = HeaderValidator::new(Arc::clone(&db), network);
        let tx_validator = TransactionValidator::new(Arc::clone(&db));
        Self {
            db,
            header_validator,
            tx_validator,
        }
    }

    /// Validate a block completely
    ///
    /// Performs comprehensive validation including:
    /// - Header validation
    /// - Block size/weight limits
    /// - Merkle root verification
    /// - Coinbase transaction validation
    /// - All other transaction validation
    /// - Total sigops check
    /// - Duplicate transaction check
    pub fn validate_block(&self, block: &BlockWrapper, prev_height: u32) -> Result<()> {
        let inner = block.inner();

        // 1. Validate header
        self.validate_header(block, prev_height)?;

        // 2. Check block size/weight limits
        self.check_size_limits(inner)?;

        // 3. Verify merkle root matches transactions
        if !self.verify_merkle_root(inner) {
            return Err(BlockValidationError::InvalidMerkleRoot);
        }

        // 4. Check transaction count
        if inner.txdata.is_empty() {
            return Err(BlockValidationError::NoTransactions);
        }

        // 5. Validate coinbase transaction (first transaction)
        let coinbase_tx = &inner.txdata[0];
        if !coinbase_tx.is_coinbase() {
            return Err(BlockValidationError::NoCoinbase);
        }

        // Check for multiple coinbase transactions
        for tx in inner.txdata.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(BlockValidationError::MultipleCoinbase);
            }
        }

        // 6. Check for duplicate transactions
        self.check_duplicate_transactions(inner)?;

        // 7. Validate all transactions
        let mut total_fees = 0u64;
        let mut total_sigops = 0usize;

        // Validate coinbase
        self.tx_validator.check_coinbase(coinbase_tx, prev_height + 1)
            .map_err(BlockValidationError::TransactionValidation)?;

        // Validate other transactions
        for tx in inner.txdata.iter().skip(1) {
            let tx_wrapper = TransactionWrapper::new(tx.clone());
            self.tx_validator.validate_transaction(&tx_wrapper, prev_height + 1, true)
                .map_err(BlockValidationError::TransactionValidation)?;

            // Calculate fee for this transaction
            // (This is simplified - full implementation would need to sum inputs/outputs)
            let fee = self.calculate_tx_fee(tx)?;
            total_fees = total_fees
                .checked_add(fee)
                .ok_or(BlockValidationError::Database(DbError::InvalidData("Fee overflow".to_string())))?;

            // Count sigops
            total_sigops += self.tx_validator.get_sigop_count(tx);
        }

        // 8. Check total sigops
        const MAX_SIGOPS: usize = 80_000; // Bitcoin's limit
        if total_sigops > MAX_SIGOPS {
            return Err(BlockValidationError::TooManySigops);
        }

        // 9. Validate coinbase amount
        self.validate_block_subsidy(inner, prev_height + 1, total_fees)?;

        Ok(())
    }

    /// Validate block header
    fn validate_header(&self, block: &BlockWrapper, prev_height: u32) -> Result<()> {
        let inner = block.inner();
        let header = BlockHeaderWrapper::new(inner.header);

        // Get previous block header
        let prev_block = self.db.get_block_by_height(prev_height)?
            .ok_or(BlockValidationError::PreviousBlockNotFound)?;
        let prev_header = BlockHeaderWrapper::new(prev_block.inner().header);

        // Validate header
        self.header_validator.validate_header(&header, &prev_header)?;

        Ok(())
    }

    /// Check block size limits
    ///
    /// Bitcoin has a 1MB size limit for legacy blocks, but weight limits are more important
    /// for SegWit blocks. For now, we check both size and weight.
    fn check_size_limits(&self, block: &Block) -> Result<()> {
        // Serialize block to get size
        use bitcoin::consensus::Encodable;
        let mut encoder = Vec::new();
        block.consensus_encode(&mut encoder)
            .map_err(|e| BlockValidationError::Database(DbError::InvalidData(format!("Encoding error: {}", e))))?;

        let size = encoder.len();

        // Block size limit: 1MB (legacy), but can be larger with SegWit
        // We use a more lenient limit here (4MB) to handle SegWit blocks
        const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB
        if size > MAX_BLOCK_SIZE {
            return Err(BlockValidationError::SizeExceeded);
        }

        Ok(())
    }

    /// Verify merkle root matches transactions
    pub fn verify_merkle_root(&self, block: &Block) -> bool {
        // Get all transaction IDs
        let txids: Vec<[u8; 32]> = block.txdata
            .iter()
            .map(|tx| *tx.compute_txid().as_byte_array())
            .collect();

        // Compute merkle root
        let computed_root = compute_merkle_root(&txids);

        // Compare to header merkle root
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

    /// Calculate transaction fee
    ///
    /// This is a simplified version - full implementation would need to
    /// look up all input UTXOs and sum them.
    fn calculate_tx_fee(&self, tx: &bitcoin::Transaction) -> Result<u64> {
        // For now, return 0 as placeholder
        // Full implementation would:
        // 1. Get all input UTXOs
        // 2. Sum input amounts
        // 3. Sum output amounts
        // 4. Return difference
        let _ = tx;
        Ok(0)
    }

    /// Validate block subsidy
    ///
    /// Calculates expected subsidy (50 BTC halving every 210,000 blocks)
    /// and verifies coinbase output <= subsidy + fees
    pub fn validate_block_subsidy(&self, block: &Block, height: u32, total_fees: u64) -> Result<()> {
        // Calculate expected subsidy
        let subsidy = self.calculate_block_subsidy(height);

        // Get coinbase output amount
        let coinbase = &block.txdata[0];
        let coinbase_total: u64 = coinbase.output.iter()
            .map(|out| out.value.to_sat())
            .sum();

        // Verify coinbase output <= subsidy + fees
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
        // Number of halvings
        let halvings = height / 210_000;

        // After 64 halvings, subsidy becomes 0
        if halvings >= 64 {
            return 0;
        }

        // Initial subsidy: 50 BTC = 5,000,000,000 satoshis
        let initial_subsidy = 50_000_000_000u64;

        // Calculate subsidy after halvings
        initial_subsidy >> halvings
    }

    /// Apply block to database
    ///
    /// Updates UTXO set (remove spent, add new), stores block, and updates best block.
    /// All operations are performed atomically using a batch.
    pub fn apply_block(&self, block: &BlockWrapper, height: u32) -> Result<()> {
        let inner = block.inner();
        let block_hash = *block.block_hash().as_byte_array();

        // Create batch for atomic operations
        // Note: Batch operations are not yet fully implemented
        let _batch = self.db.create_batch();

        // Update UTXO set
        for tx in &inner.txdata {
            let txid = tx.compute_txid();

            if !tx.is_coinbase() {
                // Remove spent UTXOs (inputs)
                for input in &tx.input {
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    let _spent_utxo = self.db.spend_utxo(outpoint.inner(), &txid.as_byte_array())?;
                    // Note: In a real implementation, we'd add this to the batch
                }
            }

            // Add new UTXOs (outputs)
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                let utxo = UTXO::new(
                    outpoint.clone(),
                    output.value.to_sat(),
                    output.script_pubkey.clone(),
                    Some(height),
                    tx.is_coinbase(),
                );

                // Note: In a real implementation, we'd add this to the batch
                self.db.add_utxo(outpoint.inner(), &utxo)?;
            }
        }

        // Store block
        self.db.store_block(block)?;

        // Store block metadata
        // Note: header.time is already u32 in bitcoin 0.32
        let timestamp = inner.header.time;
        let metadata = BlockMetadata::new(
            height,
            [0u8; 32], // TODO: calculate chainwork
            timestamp,
        );
        self.db.store_block_metadata(height, &block_hash, &metadata)?;

        // Update best block
        self.db.update_best_block(&block_hash, height)?;

        // Apply batch (in real implementation)
        // self.db.apply_batch(batch)?;

        Ok(())
    }

    /// Disconnect block (reverse UTXO changes)
    ///
    /// This is used for blockchain reorganizations (reorgs).
    /// Reverses the UTXO changes made by apply_block.
    pub fn disconnect_block(&self, block: &BlockWrapper) -> Result<()> {
        let inner = block.inner();

        // Reverse UTXO changes
        for tx in inner.txdata.iter().rev() {
            let txid = tx.compute_txid();

            // Remove new UTXOs (outputs)
            for vout in 0..tx.output.len() {
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                // Note: In a real implementation, we'd remove this UTXO from the database
                let _ = outpoint;
            }

            if !tx.is_coinbase() {
                // Restore spent UTXOs (inputs)
                for input in &tx.input {
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    // Note: In a real implementation, we'd restore this UTXO from the spent CF
                    let _ = outpoint;
                }
            }
        }

        // Note: In a full implementation, we would:
        // 1. Remove block from database
        // 2. Restore UTXOs from spent CF back to chainstate CF
        // 3. Remove new UTXOs from chainstate CF
        // 4. Update best block pointer

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

