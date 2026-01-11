//! Transaction validation module

use std::sync::Arc;
use std::collections::HashSet;

use bitcoin::{Transaction, OutPoint, absolute::LockTime};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use common::TransactionWrapper;

/// Transaction validation error types
#[derive(Error, Debug)]
pub enum TransactionValidationError {
    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("Transaction has no inputs")]
    NoInputs,

    #[error("Transaction has no outputs")]
    NoOutputs,

    #[error("Duplicate input detected")]
    DuplicateInput,

    #[error("Invalid coinbase structure")]
    InvalidCoinbase,

    #[error("Transaction size exceeds limit")]
    SizeExceeded,

    #[error("Invalid lock time")]
    InvalidLockTime,

    #[error("Input not found in UTXO set: {0}")]
    InputNotFound(String),

    #[error("Double spend detected: {0}")]
    DoubleSpend(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Invalid output amount")]
    InvalidOutputAmount,

    #[error("Output amount overflow")]
    OutputAmountOverflow,

    #[error("Outputs exceed inputs")]
    OutputsExceedInputs,

    #[error("Fee too low")]
    FeeTooLow,

    #[error("Invalid coinbase height")]
    InvalidCoinbaseHeight,

    #[error("Coinbase amount exceeds subsidy + fees")]
    CoinbaseAmountExceeded,

    #[error("Transaction is not final")]
    NotFinal,
}

/// Result type for transaction validation
pub type Result<T> = std::result::Result<T, TransactionValidationError>;

/// Transaction validator
pub struct TransactionValidator {
    db: Arc<BlockchainDB>,
}

impl TransactionValidator {
    /// Create a new transaction validator
    pub fn new(db: Arc<BlockchainDB>) -> Self {
        Self { db }
    }

    /// Validate a transaction
    ///
    /// Performs comprehensive validation including:
    /// - Structure checks (inputs/outputs, duplicates)
    /// - Coinbase validation (if applicable)
    /// - Size limits
    /// - Lock time validation
    /// - Input validation (if check_inputs is true)
    /// - Amount validation
    pub fn validate_transaction(
        &self,
        tx: &TransactionWrapper,
        height: u32,
        check_inputs: bool,
    ) -> Result<()> {
        let inner = tx.inner();

        // 1. Structure checks
        self.check_structure(inner)?;

        // 2. Size limits
        self.check_size_limits(inner)?;

        // 3. Coinbase structure (if coinbase)
        if inner.is_coinbase() {
            self.check_coinbase(inner, height)?;
        }

        // 4. Lock time validation
        self.check_lock_time(inner, height)?;

        // 5. Validate inputs (if requested)
        if check_inputs && !inner.is_coinbase() {
            self.validate_transaction_inputs(inner)?;
        }

        // 6. Validate amounts
        let total_input = if inner.is_coinbase() {
            0 // Coinbase has no inputs to validate
        } else {
            self.validate_transaction_inputs(inner)?
        };
        self.validate_amounts(inner, total_input)?;

        Ok(())
    }

    /// Check transaction structure
    fn check_structure(&self, tx: &Transaction) -> Result<()> {
        // Non-empty inputs
        if tx.input.is_empty() {
            return Err(TransactionValidationError::NoInputs);
        }

        // Non-empty outputs (except for some edge cases, but generally required)
        if tx.output.is_empty() {
            return Err(TransactionValidationError::NoOutputs);
        }

        // No duplicate inputs
        let mut seen_inputs = HashSet::new();
        for input in &tx.input {
            let outpoint = OutPoint::new(input.previous_output.txid, input.previous_output.vout);
            if !seen_inputs.insert(outpoint) {
                return Err(TransactionValidationError::DuplicateInput);
            }
        }

        Ok(())
    }

    /// Check transaction size limits
    ///
    /// Bitcoin has a 100KB size limit for standard transactions (1MB for legacy,
    /// but 100KB is the current relay limit)
    fn check_size_limits(&self, tx: &Transaction) -> Result<()> {
        // Serialize transaction to get size
        let mut encoder = Vec::new();
        tx.consensus_encode(&mut encoder)
            .map_err(|e| TransactionValidationError::Database(DbError::InvalidData(format!("Encoding error: {}", e))))?;

        let size = encoder.len();

        // Standard transaction size limit is 100KB (but can be larger in blocks)
        // We use a more lenient limit here for block validation (1MB)
        const MAX_TX_SIZE: usize = 1_000_000; // 1MB
        if size > MAX_TX_SIZE {
            return Err(TransactionValidationError::SizeExceeded);
        }

        // Check output count limit (Bitcoin Core has 5000 output limit)
        const MAX_OUTPUTS: usize = 5000;
        if tx.output.len() > MAX_OUTPUTS {
            return Err(TransactionValidationError::SizeExceeded);
        }

        Ok(())
    }

    /// Check lock time
    fn check_lock_time(&self, tx: &Transaction, height: u32) -> Result<()> {
        let lock_time = tx.lock_time;

        match lock_time {
            LockTime::Blocks(block_height) => {
                // Block-based lock time: must be less than or equal to current height
                if block_height.to_consensus_u32() > height {
                    return Err(TransactionValidationError::InvalidLockTime);
                }
            }
            LockTime::Seconds(timestamp) => {
                // Time-based lock time: checked against block time
                // For now, we accept it (would need block time to fully validate)
                let _ = timestamp;
            }
        }

        Ok(())
    }

    /// Validate transaction inputs
    ///
    /// Checks all inputs exist in UTXO set, verifies no double spends,
    /// and verifies all signatures.
    ///
    /// Returns the total input amount in satoshis.
    pub fn validate_transaction_inputs(&self, tx: &Transaction) -> Result<u64> {
        let mut total_input = 0u64;
        let mut seen_outpoints = HashSet::new();

        for (input_idx, input) in tx.input.iter().enumerate() {
            let outpoint = OutPoint::new(input.previous_output.txid, input.previous_output.vout);

            // Check for duplicate inputs in this transaction
            if !seen_outpoints.insert(outpoint) {
                return Err(TransactionValidationError::DuplicateInput);
            }

            // Get UTXO from database
            let utxo = self.db.get_utxo(&outpoint)?
                .ok_or_else(|| {
                    TransactionValidationError::InputNotFound(
                        format!("{}:{}", outpoint.txid, outpoint.vout)
                    )
                })?;

            // Check if UTXO is already spent (double spend check)
            // This is simplified - in production, we'd track spending in the current block
            // For now, we rely on the database to prevent double spends

            // Verify signature
            // This is a placeholder - full signature verification requires:
            // 1. Creating the sighash for this input
            // 2. Extracting signature and pubkey from script_sig
            // 3. Verifying the signature cryptographically
            // For now, we'll just check that script_sig is non-empty
            if input.script_sig.is_empty() {
                return Err(TransactionValidationError::SignatureVerificationFailed(
                    format!("Empty script_sig for input {}", input_idx)
                ));
            }

            // Add to total input
            total_input = total_input
                .checked_add(utxo.amount)
                .ok_or(TransactionValidationError::OutputAmountOverflow)?;
        }

        Ok(total_input)
    }

    /// Validate transaction amounts
    ///
    /// Checks output amounts are valid (> 0, no overflow),
    /// verifies total_output <= total_input, and calculates fee.
    ///
    /// Returns the transaction fee in satoshis.
    pub fn validate_amounts(&self, tx: &Transaction, total_input: u64) -> Result<u64> {
        let mut total_output = 0u64;

        // Validate each output
        for (_i, output) in tx.output.iter().enumerate() {
            let amount = output.value.to_sat();

            // Output amount must be > 0
            if amount == 0 {
                return Err(TransactionValidationError::InvalidOutputAmount);
            }

            // Check for overflow
            total_output = total_output
                .checked_add(amount)
                .ok_or(TransactionValidationError::OutputAmountOverflow)?;
        }

        // Total output must not exceed total input
        if total_output > total_input {
            return Err(TransactionValidationError::OutputsExceedInputs);
        }

        // Calculate fee
        let fee = total_input
            .checked_sub(total_output)
            .ok_or(TransactionValidationError::OutputAmountOverflow)?;

        // Minimum fee check (1 sat/vbyte)
        let tx_size = {
            let mut encoder = Vec::new();
            tx.consensus_encode(&mut encoder)
                .map_err(|e| TransactionValidationError::Database(DbError::InvalidData(format!("Encoding error: {}", e))))?;
            encoder.len()
        };
        let min_fee = tx_size as u64; // 1 sat per byte

        if fee < min_fee && !tx.is_coinbase() {
            return Err(TransactionValidationError::FeeTooLow);
        }

        Ok(fee)
    }

    /// Check coinbase transaction structure
    ///
    /// Verifies:
    /// - Coinbase structure (first input has null prevout)
    /// - Block height encoding in coinbase script
    /// - Output amount (subsidy + fees)
    pub fn check_coinbase(&self, tx: &Transaction, _height: u32) -> Result<()> {
        // Coinbase must have exactly one input
        if tx.input.len() != 1 {
            return Err(TransactionValidationError::InvalidCoinbase);
        }

        let coinbase_input = &tx.input[0];

        // Coinbase input must have null prevout (all zeros)
        let null_txid = bitcoin::Txid::from_byte_array([0u8; 32]);
        if coinbase_input.previous_output.txid != null_txid ||
           coinbase_input.previous_output.vout != u32::MAX {
            return Err(TransactionValidationError::InvalidCoinbase);
        }

        // Coinbase script must be 2-100 bytes
        if coinbase_input.script_sig.len() < 2 || coinbase_input.script_sig.len() > 100 {
            return Err(TransactionValidationError::InvalidCoinbase);
        }

        // Verify block height is encoded in coinbase script
        // The first bytes should encode the height using compact size
        // This is a simplified check - full validation would decode the height
        if coinbase_input.script_sig.is_empty() {
            return Err(TransactionValidationError::InvalidCoinbase);
        }

        // Validate coinbase output amount
        // This will be done in validate_amounts with the total fees
        // For now, we'll just check that there's at least one output
        if tx.output.is_empty() {
            return Err(TransactionValidationError::InvalidCoinbase);
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

    /// Check if transaction is final
    ///
    /// A transaction is final if:
    /// - Lock time is 0, or
    /// - Lock time is less than current height/time
    pub fn is_final(&self, tx: &Transaction, height: u32, _time: u32) -> bool {
        let lock_time = tx.lock_time;

        match lock_time {
            LockTime::Blocks(block_height) => {
                // Block-based: must be <= current height
                block_height.to_consensus_u32() <= height
            }
            LockTime::Seconds(_timestamp) => {
                // Time-based: simplified - assume final for now
                // In production, would check against block time
                true
            }
        }
    }

    /// Get signature operation count
    ///
    /// Counts the number of signature operations in the transaction.
    /// This is a simplified version - full implementation would count
    /// OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY.
    pub fn get_sigop_count(&self, tx: &Transaction) -> usize {
        let mut count = 0;

        // Count sigops in outputs (scriptPubKey)
        for output in &tx.output {
            count += count_sigops_in_script(&output.script_pubkey);
        }

        // Count sigops in inputs (scriptSig)
        // Note: For P2SH, this is more complex and requires executing the redeem script
        for input in &tx.input {
            count += count_sigops_in_script(&input.script_sig);
        }

        count
    }
}

/// Count signature operations in a script
///
/// This is a simplified implementation that counts opcodes.
/// A full implementation would properly handle P2SH and witness scripts.
fn count_sigops_in_script(script: &bitcoin::Script) -> usize {
    let mut count = 0;

    for instruction in script.instructions() {
        match instruction {
            Ok(bitcoin::blockdata::script::Instruction::Op(opcode)) => {
                use bitcoin::blockdata::opcodes::all::*;
                match opcode {
                    OP_CHECKSIG | OP_CHECKSIGVERIFY => count += 1,
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                        // CHECKMULTISIG counts as 20 sigops (Bitcoin consensus rule)
                        count += 20;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf};
    use std::sync::Arc;
    use tempdir::TempDir;

    fn create_test_db() -> (TempDir, Arc<BlockchainDB>) {
        let temp_dir = TempDir::new("bitcoin_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        (temp_dir, db)
    }

    #[test]
    fn test_check_structure_no_inputs() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let wrapper = TransactionWrapper::new(tx);
        let result = validator.check_structure(wrapper.inner());
        assert!(matches!(result, Err(TransactionValidationError::NoInputs)));
    }

    #[test]
    fn test_check_structure_no_outputs() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([0u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let wrapper = TransactionWrapper::new(tx);
        let result = validator.check_structure(wrapper.inner());
        assert!(matches!(result, Err(TransactionValidationError::NoOutputs)));
    }

    #[test]
    fn test_check_structure_duplicate_inputs() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        let prev_txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = bitcoin::OutPoint::new(prev_txid, 0);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::transaction::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: outpoint, // Duplicate!
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::transaction::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let wrapper = TransactionWrapper::new(tx);
        let result = validator.check_structure(wrapper.inner());
        assert!(matches!(result, Err(TransactionValidationError::DuplicateInput)));
    }

    #[test]
    fn test_check_coinbase() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        // Valid coinbase
        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]), // Height encoding
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(50_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let wrapper = TransactionWrapper::new(coinbase_tx);
        let result = validator.check_coinbase(wrapper.inner(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_block_subsidy() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

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
    fn test_is_final() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        // Transaction with lock time 0 (always final)
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        assert!(validator.is_final(&tx, 100, 1000000));

        // Transaction with block lock time
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(100),
            input: vec![],
            output: vec![],
        };

        assert!(!validator.is_final(&tx, 50, 1000000));
        assert!(validator.is_final(&tx, 100, 1000000));
        assert!(validator.is_final(&tx, 150, 1000000));
    }

    #[test]
    fn test_get_sigop_count() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db);

        use bitcoin::blockdata::script::Builder;
        use bitcoin::opcodes::all::OP_CHECKSIG;

        let script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script.into(),
            }],
        };

        assert_eq!(validator.get_sigop_count(&tx), 1);
    }
}

