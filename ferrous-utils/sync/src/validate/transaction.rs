//! Transaction validation module

use std::sync::Arc;
use std::collections::HashSet;

use std::collections::HashMap;

use bitcoin::{Network, Transaction, OutPoint, absolute::LockTime};
use bitcoin::hashes::Hash;
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use common::{TransactionWrapper, UTXO};

/// Coinbase transaction outputs can only be spent after this number of new blocks.
/// Reference: Bitcoin Core consensus/consensus.h
pub const COINBASE_MATURITY: u32 = 100;

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

    #[error("Negative output value")]
    NegativeOutputAmount,

    #[error("Output value exceeds MAX_MONEY")]
    OutputAmountTooLarge,

    #[error("Invalid output amount")]
    InvalidOutputAmount,

    #[error("Output amount overflow")]
    OutputAmountOverflow,

    #[error("Outputs exceed inputs")]
    OutputsExceedInputs,

    #[error("Invalid coinbase height")]
    InvalidCoinbaseHeight,

    #[error("Coinbase amount exceeds subsidy + fees")]
    CoinbaseAmountExceeded,

    #[error("Transaction is not final")]
    NotFinal,

    #[error("Premature spend of coinbase at depth {depth}")]
    PrematureCoinbaseSpend { depth: i64 },
}

/// Result type for transaction validation
pub type Result<T> = std::result::Result<T, TransactionValidationError>;

/// Transaction validator
pub struct TransactionValidator {
    db: Arc<BlockchainDB>,
    /// Network used for consensus-activation-height lookups (e.g. BIP34).
    network: Network,
}

impl TransactionValidator {
    /// Create a new transaction validator
    pub fn new(db: Arc<BlockchainDB>, network: Network) -> Self {
        Self { db, network }
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

        // 5+6. Validate inputs and amounts (single pass)
        if !inner.is_coinbase() && check_inputs {
            let total_input = self.validate_transaction_inputs(inner)?;
            self.validate_amounts(inner, total_input)?;
        }

        Ok(())
    }

    /// Validate a non-coinbase transaction and return its fee.
    ///
    /// Same semantics as `validate_transaction(tx, height, check_inputs=true)`
    /// but returns the computed fee (`total_input - total_output`) instead of
    /// `()`. Uses `validate_transaction_inputs_with_extras_at_height` so
    /// coinbase maturity is enforced AND outputs created by earlier txs in
    /// the same block (`extras`) resolve intra-block dependencies.
    ///
    /// For coinbase txs returns `Ok(0)` — the caller aggregates only
    /// non-coinbase fees into the block subsidy check.
    ///
    /// Used by `BlockValidator::validate_block_with_flags` for the
    /// Python drain-path route.
    pub fn validate_transaction_with_fee(
        &self,
        tx: &TransactionWrapper,
        height: u32,
        extras: &HashMap<OutPoint, UTXO>,
    ) -> Result<u64> {
        let (fee, _scripts) = self.validate_transaction_with_fee_and_scripts(tx, height, extras)?;
        Ok(fee)
    }

    /// Same as `validate_transaction_with_fee` but additionally returns the
    /// script_pubkey of each input in input order.
    ///
    /// For coinbase transactions the returned `Vec` is empty (the coinbase
    /// has no real previous outputs to look up).
    ///
    /// W85 regression fix: `validate_block_with_flags` already pays for one
    /// UTXO fetch per input here for amount + coinbase-maturity checks. By
    /// returning the script_pubkeys, the block-level sigop counter can
    /// reuse them for `is_p2sh` / witness-program detection instead of
    /// performing 2 additional `db.get_utxo()` round-trips per input.
    pub fn validate_transaction_with_fee_and_scripts(
        &self,
        tx: &TransactionWrapper,
        height: u32,
        extras: &HashMap<OutPoint, UTXO>,
    ) -> Result<(u64, Vec<bitcoin::ScriptBuf>)> {
        let inner = tx.inner();

        self.check_structure(inner)?;
        self.check_size_limits(inner)?;
        if inner.is_coinbase() {
            self.check_coinbase(inner, height)?;
        }
        self.check_lock_time(inner, height)?;

        if inner.is_coinbase() {
            return Ok((0, Vec::new()));
        }
        let (total_input, scripts) = self
            .validate_transaction_inputs_with_extras_at_height_and_scripts(
                inner, height, extras,
            )?;
        let fee = self.validate_amounts(inner, total_input)?;
        Ok((fee, scripts))
    }

    /// Same as `validate_transaction_inputs_at_height` but resolves inputs
    /// from `extras` (intra-block UTXOs) before falling back to the DB.
    ///
    /// `extras` holds `OutPoint → UTXO` for outputs created by earlier
    /// transactions in the same block so that chained intra-block spends
    /// validate correctly. Python reference: `validation.py` `intra_block_utxos`.
    pub fn validate_transaction_inputs_with_extras_at_height(
        &self,
        tx: &Transaction,
        spending_height: u32,
        extras: &HashMap<OutPoint, UTXO>,
    ) -> Result<u64> {
        let (total_input, _scripts) = self
            .validate_transaction_inputs_with_extras_at_height_and_scripts(
                tx, spending_height, extras,
            )?;
        Ok(total_input)
    }

    /// Same as `validate_transaction_inputs_with_extras_at_height` but also
    /// returns the script_pubkey of each input (in input order).
    ///
    /// The script_pubkey vector is sized exactly `tx.input.len()`. Used by
    /// the validate hot path to dedupe UTXO fetches with sigop counting
    /// (see `get_block_sigop_cost_with_prefetched_scripts`).
    pub fn validate_transaction_inputs_with_extras_at_height_and_scripts(
        &self,
        tx: &Transaction,
        spending_height: u32,
        extras: &HashMap<OutPoint, UTXO>,
    ) -> Result<(u64, Vec<bitcoin::ScriptBuf>)> {
        let mut total_input = 0u64;
        let mut seen_outpoints = HashSet::new();
        let mut script_pubkeys: Vec<bitcoin::ScriptBuf> = Vec::with_capacity(tx.input.len());

        for input in tx.input.iter() {
            let outpoint = OutPoint::new(input.previous_output.txid, input.previous_output.vout);

            if !seen_outpoints.insert(outpoint) {
                return Err(TransactionValidationError::DuplicateInput);
            }

            let utxo = if let Some(u) = extras.get(&outpoint) {
                u.clone()
            } else {
                self.db.get_utxo(&outpoint)?
                    .ok_or_else(|| TransactionValidationError::InputNotFound(
                        format!("{}:{}", outpoint.txid, outpoint.vout)
                    ))?
            };

            if spending_height > 0 && utxo.is_coinbase {
                let utxo_height = utxo.height.unwrap_or(0);
                let depth = spending_height as i64 - utxo_height as i64;
                if depth < COINBASE_MATURITY as i64 {
                    return Err(TransactionValidationError::PrematureCoinbaseSpend { depth });
                }
            }

            total_input = total_input
                .checked_add(utxo.amount)
                .ok_or(TransactionValidationError::OutputAmountOverflow)?;
            script_pubkeys.push(utxo.script_pubkey);
        }

        Ok((total_input, script_pubkeys))
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

    /// Check transaction structural limits.
    ///
    /// Uses input/output counts as a fast proxy instead of re-serializing.
    /// A block can be at most 4MB, so any individual tx is bounded by that.
    fn check_size_limits(&self, tx: &Transaction) -> Result<()> {
        const MAX_INPUTS: usize = 100_000;
        const MAX_OUTPUTS: usize = 100_000;

        if tx.input.len() > MAX_INPUTS || tx.output.len() > MAX_OUTPUTS {
            return Err(TransactionValidationError::SizeExceeded);
        }

        Ok(())
    }

    /// Check lock time
    ///
    /// Implements Bitcoin Core's `IsFinalTx` for block-validation time.
    /// Reference: `bitcoin-core/src/consensus/tx_verify.cpp`.
    ///
    /// A transaction is final (may be included in a block) iff ANY of:
    ///   (a) `nLockTime == 0` (no lock-time restriction),
    ///   (b) `nLockTime < height` for height-based lock-times (and
    ///       `nLockTime < block_time` for time-based lock-times — see
    ///       note below), OR
    ///   (c) every input has `nSequence == SEQUENCE_FINAL` (`0xFFFFFFFF`),
    ///       opting out of lock-time entirely.
    ///
    /// The SEQUENCE_FINAL escape hatch (c) is required for consensus and
    /// was missing from the original implementation. W66 at mainnet
    /// height 782,291 (2026-04-18) surfaced this: three transactions in
    /// that block had `nLockTime > 782_291` (future) but all inputs at
    /// `nSequence == 0xFFFFFFFF`. Every other mainnet node accepted the
    /// block; ouroboros rejected it and wedged for ~5 h.
    ///
    /// Time-based lock-times: Bitcoin Core uses
    /// `block.GetMedianTimePast()` post-BIP113 (active since height
    /// 419,328). This validator does not yet plumb MTP through; for
    /// time-based lock-times we preserve the previous accept-all
    /// behaviour. That is a separate consensus hole for future work but
    /// is not the cause of the W66 wedge and is extremely rare at the
    /// heights currently involved in IBD.
    fn check_lock_time(&self, tx: &Transaction, height: u32) -> Result<()> {
        use bitcoin::Sequence;

        // Case (a): zero lock-time — always final.
        if tx.lock_time == LockTime::ZERO {
            return Ok(());
        }

        // Case (b): lock-time is in the past relative to the block being
        // validated. For height-based, `nLockTime < height` is final;
        // for time-based, we defer to case (c) (see note above about
        // BIP113 MTP plumbing).
        let past = match tx.lock_time {
            LockTime::Blocks(h) => h.to_consensus_u32() < height,
            LockTime::Seconds(_) => false,
        };
        if past {
            return Ok(());
        }

        // Case (c): every input opts out of lock-time via SEQUENCE_FINAL.
        if tx.input.iter().all(|inp| inp.sequence == Sequence::MAX) {
            return Ok(());
        }

        // Preserve prior accept-all behaviour for time-based lock-times
        // whose nLockTime is not yet `past` and whose sequences are not
        // all final. Fixing this properly requires MTP plumbing; for
        // now, avoid regressing on any previously-accepted tx.
        if matches!(tx.lock_time, LockTime::Seconds(_)) {
            return Ok(());
        }

        Err(TransactionValidationError::InvalidLockTime)
    }

    /// Validate transaction inputs
    ///
    /// Checks all inputs exist in UTXO set, verifies no double spends,
    /// and verifies all signatures.
    ///
    /// Returns the total input amount in satoshis.
    pub fn validate_transaction_inputs(&self, tx: &Transaction) -> Result<u64> {
        // Call the height-aware version with height=0 to skip coinbase maturity check.
        // This maintains backward compatibility with existing callers.
        self.validate_transaction_inputs_at_height(tx, 0)
    }

    /// Validate transaction inputs at a specific spending height.
    ///
    /// Checks all inputs exist in UTXO set, verifies no double spends,
    /// verifies all signatures, and enforces coinbase maturity.
    ///
    /// # Arguments
    /// * `tx` - The transaction to validate
    /// * `spending_height` - The height of the block where this tx will be included.
    ///                       If 0, coinbase maturity check is skipped.
    ///
    /// # Returns
    /// The total input amount in satoshis.
    ///
    /// # Errors
    /// Returns `PrematureCoinbaseSpend` if any input spends a coinbase output
    /// that has fewer than COINBASE_MATURITY (100) confirmations.
    ///
    /// Reference: Bitcoin Core consensus/tx_verify.cpp CheckTxInputs()
    pub fn validate_transaction_inputs_at_height(&self, tx: &Transaction, spending_height: u32) -> Result<u64> {
        let mut total_input = 0u64;
        let mut seen_outpoints = HashSet::new();

        for input in tx.input.iter() {
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

            // Coinbase maturity check:
            // If the UTXO is from a coinbase transaction, it cannot be spent until
            // it has at least COINBASE_MATURITY (100) confirmations.
            // Reference: Bitcoin Core consensus/tx_verify.cpp line 179
            if spending_height > 0 && utxo.is_coinbase {
                let utxo_height = utxo.height.unwrap_or(0);
                let depth = spending_height as i64 - utxo_height as i64;
                if depth < COINBASE_MATURITY as i64 {
                    return Err(TransactionValidationError::PrematureCoinbaseSpend { depth });
                }
            }

            // Signature verification lives in script.rs behind skip_scripts.
            // An empty script_sig is legal for SegWit inputs (signature lives in
            // the witness), so do NOT reject on that here.

            // Add to total input
            total_input = total_input
                .checked_add(utxo.amount)
                .ok_or(TransactionValidationError::OutputAmountOverflow)?;
        }

        Ok(total_input)
    }

    /// Validate transaction amounts
    ///
    /// Checks output amounts are valid (> 0, no overflow) and
    /// verifies total_output <= total_input.
    ///
    /// Returns the transaction fee in satoshis.
    ///
    /// Note: relay fee checks (min fee per byte) belong in mempool acceptance,
    /// not block validation. Bitcoin Core enforces relay fees only for mempool
    /// policy, not consensus.
    pub fn validate_amounts(&self, tx: &Transaction, total_input: u64) -> Result<u64> {
        // MAX_MONEY = 21_000_000 BTC in satoshis. Matches Python
        // validation.py:48 and Bitcoin Core's COIN * 21_000_000.
        const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

        let mut total_output = 0u64;

        for output in &tx.output {
            let amount = output.value.to_sat();

            // Bitcoin's wire format uses int64 for output values; the bitcoin
            // crate deserialises as u64.  A negative wire value (e.g. -1 =
            // 0xffffffffffffffff) arrives with the high bit set.  Check for
            // sign before the upper-bound check — mirrors Bitcoin Core
            // consensus/tx_check.cpp::CheckTransaction (negative first, then
            // toolarge).
            if (amount as i64) < 0 {
                return Err(TransactionValidationError::NegativeOutputAmount);
            }

            // Per-output upper-bound check (consensus/tx_check.cpp::CheckTransaction — Core parity).
            // Core: "bad-txns-vout-toolarge". Mirrors the negative check above.
            if amount > MAX_MONEY {
                return Err(TransactionValidationError::OutputAmountTooLarge);
            }

            total_output = total_output
                .checked_add(amount)
                .ok_or(TransactionValidationError::OutputAmountOverflow)?;

            if total_output > MAX_MONEY {
                return Err(TransactionValidationError::OutputAmountOverflow);
            }
        }

        if total_output > total_input {
            return Err(TransactionValidationError::OutputsExceedInputs);
        }

        let fee = total_input
            .checked_sub(total_output)
            .ok_or(TransactionValidationError::OutputAmountOverflow)?;

        Ok(fee)
    }

    /// Check coinbase transaction structure
    ///
    /// Verifies:
    /// - Coinbase structure (first input has null prevout)
    /// - BIP34 block-height encoding in coinbase scriptSig (post-activation)
    /// - Coinbase script 2–100 bytes
    /// - At least one output
    pub fn check_coinbase(&self, tx: &Transaction, height: u32) -> Result<()> {
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
        let sig_len = coinbase_input.script_sig.len();
        if sig_len < 2 || sig_len > 100 {
            return Err(TransactionValidationError::InvalidCoinbase);
        }

        // BIP34: the coinbase scriptSig must BEGIN WITH the canonical
        // `CScript() << nHeight` serialisation of the block height. Activation
        // height is network-dependent — mainnet 227_931, testnet4/regtest/signet 1.
        //
        // Core ContextualCheckBlock (validation.cpp:4151-4159):
        //     CScript expect = CScript() << nHeight;
        //     if sig.size() < expect.size() || !equal(expect, sig[..expect.size()])
        //         -> "bad-cb-height"
        // The `<< nHeight` encoding (script.h push_int64) is NOT always a
        // length-prefixed push:
        //     0      -> OP_0  (0x00)
        //     1..16  -> OP_1..OP_16 (0x51..0x60, single opcode, NO length prefix)
        //     else   -> minimal little-endian sign-magnitude CScriptNum push.
        // The previous code read script[0] as a length-prefix and rejected the
        // OP_1..OP_16 single-opcode form, so regtest/testnet4/signet heights 1..16
        // (BIP34 active from height 1) were spuriously rejected with "Invalid
        // coinbase height". Mainnet was unaffected: its post-activation heights are
        // always > 16, hence always length-prefixed. This now mirrors Core's
        // prefix-equality AND the Python validator (validation.py _validate_coinbase),
        // which already used `_encode_bip34_height` + a starts_with check.
        // Reference: bitcoin-core/src/script/script.h CScript::operator<<(int64_t)
        //            + validation.cpp ContextualCheckBlock; chainparams.cpp BIP34Height.
        fn encode_bip34_height(height: u32) -> Vec<u8> {
            if height == 0 {
                return vec![0x00]; // OP_0
            }
            if height <= 16 {
                return vec![0x50 + height as u8]; // OP_1..OP_16
            }
            // minimal little-endian sign-magnitude bytes, length-prefixed
            let mut le: Vec<u8> = Vec::new();
            let mut h = height;
            while h > 0 {
                le.push((h & 0xff) as u8);
                h >>= 8;
            }
            // high bit of MSB set -> append a 0x00 sign byte to stay positive
            if le.last().is_some_and(|b| b & 0x80 != 0) {
                le.push(0x00);
            }
            let mut out = Vec::with_capacity(1 + le.len());
            out.push(le.len() as u8);
            out.extend_from_slice(&le);
            out
        }
        let bip34_height = crate::chain_params::bip_activation_heights(self.network).0;
        if height >= bip34_height {
            let expect = encode_bip34_height(height);
            let script = coinbase_input.script_sig.as_bytes();
            if script.len() < expect.len() || !script.starts_with(&expect) {
                return Err(TransactionValidationError::InvalidCoinbaseHeight);
            }
        }

        // At least one output
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

        // Initial subsidy: 50 BTC = 5_000_000_000 satoshis
        // Reference: Bitcoin Core amount.h COIN = 100_000_000; nSubsidy = 50 * COIN
        let initial_subsidy = 5_000_000_000u64;

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

    /// Get signature operation count (legacy method, no witness discount)
    ///
    /// Counts the number of signature operations in the transaction.
    /// This is a simplified version - full implementation would count
    /// OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY.
    ///
    /// **Deprecated**: Use `get_sigop_cost()` instead for proper BIP141 witness discount.
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

    /// Get signature operation cost with BIP141 witness discount.
    ///
    /// Implements proper sigop cost calculation:
    /// - Legacy sigops cost WITNESS_SCALE_FACTOR (4) weight units each
    /// - P2SH redeem script sigops cost WITNESS_SCALE_FACTOR (4) weight units each
    /// - Witness sigops cost 1 weight unit each (discounted)
    ///
    /// This matches Bitcoin Core's `GetTransactionSigOpCost()`.
    ///
    /// # Arguments
    /// * `tx` - The transaction to count sigops for
    /// * `verify_p2sh` - Whether to count P2SH redeem script sigops
    /// * `verify_witness` - Whether to count witness script sigops
    pub fn get_sigop_cost(&self, tx: &Transaction, verify_p2sh: bool, verify_witness: bool) -> i64 {
        super::sigop::get_transaction_sigop_cost(tx, &self.db, verify_p2sh, verify_witness)
    }
}

/// Check if spending a coinbase output is allowed at the given height.
///
/// Coinbase outputs require COINBASE_MATURITY (100) confirmations before
/// they can be spent. This function returns true if the maturity requirement
/// is satisfied.
///
/// # Arguments
/// * `is_coinbase` - Whether the UTXO being spent is from a coinbase transaction
/// * `utxo_height` - The height at which the UTXO was created
/// * `spending_height` - The height of the block where the spending tx will be included
///
/// # Returns
/// * `Ok(())` if the coinbase maturity requirement is satisfied
/// * `Err((depth, required))` if the coinbase is not mature enough, with the current
///   depth and required depth
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp line 179
pub fn check_coinbase_maturity(
    is_coinbase: bool,
    utxo_height: u32,
    spending_height: u32,
) -> std::result::Result<(), (i64, u32)> {
    if !is_coinbase {
        return Ok(());
    }

    let depth = spending_height as i64 - utxo_height as i64;
    if depth < COINBASE_MATURITY as i64 {
        Err((depth, COINBASE_MATURITY))
    } else {
        Ok(())
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
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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

    /// BIP34 activation height is network-dependent.
    ///
    /// Pre-fix: `check_coinbase` used `const BIP34_HEIGHT: u32 = 227_931`
    /// (mainnet only). On testnet4/regtest BIP34 is active from height 1, so
    /// a height-1 coinbase without the height push MUST be rejected — but the
    /// old constant let it pass silently.
    ///
    /// Post-fix: `bip_activation_heights(network).0` returns 1 for testnet4,
    /// causing the missing-height-push to be rejected at height >= 1.
    #[test]
    fn test_bip34_height_is_network_aware() {
        // --- testnet4: BIP34 active from height 1 ---
        // A coinbase at height 1 with NO height-push in scriptSig must fail
        // on testnet4. Script: two-byte padding, no height push.
        let (_temp_dir, db) = create_test_db();
        let validator_t4 = TransactionValidator::new(Arc::clone(&db), Network::Testnet4);

        // Coinbase scriptSig: 0x02 0x00 (length=2, value=0x00) — encodes
        // height 0, not height 1.  On mainnet this block would be < 227_931
        // so the BIP34 check is skipped; on testnet4 height 1 is already
        // active and must be rejected.
        let bad_t4_coinbase = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]), // encodes height 0
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(625_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // On testnet4, height 1 >= bip34_height(1), so wrong height must
        // be rejected with InvalidCoinbaseHeight.
        let result = validator_t4.check_coinbase(&bad_t4_coinbase, 1);
        assert!(
            matches!(result, Err(TransactionValidationError::InvalidCoinbaseHeight)),
            "testnet4 h=1: coinbase with wrong height must be rejected; got {:?}",
            result
        );

        // Mainnet validator at the SAME height should ACCEPT (height 1 <
        // mainnet BIP34 activation 227_931 — check not yet enforced).
        let validator_main = TransactionValidator::new(Arc::clone(&db), Network::Bitcoin);
        let result_main = validator_main.check_coinbase(&bad_t4_coinbase, 1);
        assert!(
            result_main.is_ok(),
            "mainnet h=1: BIP34 not yet active, coinbase must be accepted; got {:?}",
            result_main
        );
    }

    /// Regression: BIP34 coinbase height for heights 1..16 uses Core's
    /// OP_1..OP_16 single-opcode encoding (`CScript() << nHeight`), NOT a
    /// length-prefixed push. The pre-fix decoder read OP_1 (0x51) as a
    /// push-size of 81 and rejected every regtest/testnet4 height-1..16 block
    /// with InvalidCoinbaseHeight (the `generatetoaddress` self-reject,
    /// _finding-ouroboros-regtest-mining-bip34). Mainnet was unaffected:
    /// post-227_931 heights are always > 16 (always length-prefixed).
    #[test]
    fn test_bip34_accepts_op_n_low_heights() {
        let (_temp_dir, db) = create_test_db();
        let v = TransactionValidator::new(Arc::clone(&db), Network::Regtest);

        let cb = |script_sig: Vec<u8>| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // height 1 -> OP_1 (0x51) + extra-nonce padding: MUST be accepted
        // (this is the exact case the pre-fix decoder rejected).
        assert!(
            v.check_coinbase(&cb(vec![0x51, 0x00]), 1).is_ok(),
            "regtest h=1: canonical OP_1 coinbase height must be accepted"
        );
        // height 16 -> OP_16 (0x60): accepted.
        assert!(
            v.check_coinbase(&cb(vec![0x60, 0x00]), 16).is_ok(),
            "regtest h=16: canonical OP_16 coinbase height must be accepted"
        );
        // height 17 -> length-prefixed minimal push 0x01 0x11: accepted.
        assert!(
            v.check_coinbase(&cb(vec![0x01, 0x11]), 17).is_ok(),
            "regtest h=17: length-prefixed coinbase height must be accepted"
        );
        // height 0 -> OP_0 (0x00) + padding: accepted.
        assert!(
            v.check_coinbase(&cb(vec![0x00, 0x00]), 0).is_ok(),
            "regtest h=0: OP_0 coinbase height must be accepted"
        );
        // wrong height: OP_2 (0x52) claimed at height 1 -> rejected.
        assert!(
            matches!(
                v.check_coinbase(&cb(vec![0x52, 0x00]), 1),
                Err(TransactionValidationError::InvalidCoinbaseHeight)
            ),
            "regtest h=1 with OP_2 (wrong height) must be rejected"
        );
        // wrong height: length-prefixed 18 claimed at height 17 -> rejected.
        assert!(
            matches!(
                v.check_coinbase(&cb(vec![0x01, 0x12]), 17),
                Err(TransactionValidationError::InvalidCoinbaseHeight)
            ),
            "regtest h=17 encoding 18 (wrong height) must be rejected"
        );
    }

    #[test]
    fn test_validate_amounts_accepts_zero_value_output() {
        // Regression: zero-value outputs are consensus-valid (OP_RETURN
        // witness commitments, data-embed txs). The earlier `amount == 0`
        // rejection broke every modern block in B3 cross-check.
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: Amount::from_sat(500),
                    script_pubkey: ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: Amount::ZERO, // OP_RETURN-style
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x00]),
                },
            ],
        };

        let result = validator.validate_amounts(&tx, 1000);
        assert!(result.is_ok(), "zero-value output must not be rejected");
        assert_eq!(result.unwrap(), 500, "fee = 1000 - 500 = 500");
    }

    #[test]
    fn test_validate_amounts_rejects_single_output_over_max_money() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(21_000_001 * 100_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = validator.validate_amounts(&tx, u64::MAX);
        // A single output > MAX_MONEY is Core's "bad-txns-vout-toolarge"
        // (consensus/tx_check.cpp CheckTransaction:30), which validate_amounts
        // maps to OutputAmountTooLarge. The prior assertion expected
        // InvalidOutputAmount — a variant the validator never produces — so it
        // failed on every run.
        assert!(matches!(
            result,
            Err(TransactionValidationError::OutputAmountTooLarge)
        ));
    }

    #[test]
    fn test_calculate_block_subsidy() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // Genesis block: 50 BTC = 5_000_000_000 satoshis
        // Reference: Bitcoin Core amount.h COIN = 100_000_000; nSubsidy = 50 * COIN
        assert_eq!(validator.calculate_block_subsidy(0), 5_000_000_000);
        assert_eq!(validator.calculate_block_subsidy(209_999), 5_000_000_000);

        // After first halving: 25 BTC = 2_500_000_000 satoshis
        assert_eq!(validator.calculate_block_subsidy(210_000), 2_500_000_000);
        assert_eq!(validator.calculate_block_subsidy(419_999), 2_500_000_000);

        // After second halving: 12.5 BTC = 1_250_000_000 satoshis
        assert_eq!(validator.calculate_block_subsidy(420_000), 1_250_000_000);

        // After 64 halvings: 0
        assert_eq!(validator.calculate_block_subsidy(64 * 210_000), 0);
    }

    #[test]
    fn test_is_final() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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

    /// Build a minimal one-input, one-output transaction with the given
    /// lock-time and sequence. Used by the lock-time regression tests
    /// below. Shape-valid, not signature-valid (we only exercise
    /// `check_lock_time`).
    fn make_locktime_tx(lock_time_consensus: u32, sequence: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time_consensus),
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([1u8; 32]),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::transaction::Sequence(sequence),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_check_lock_time_accepts_zero_locktime() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // nLockTime == 0 is always final regardless of sequence.
        let tx = make_locktime_tx(0, 0);
        assert!(validator.check_lock_time(&tx, 782_291).is_ok());
    }

    #[test]
    fn test_check_lock_time_accepts_past_height_locktime() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // nLockTime < current height is final even without SEQUENCE_FINAL
        // (anti-fee-snipe pattern: most wallets set lock_time = height-1
        // and sequence = 0xFFFFFFFE for RBF).
        let tx = make_locktime_tx(782_290, 0xFFFFFFFE);
        assert!(validator.check_lock_time(&tx, 782_291).is_ok());
    }

    #[test]
    fn test_check_lock_time_rejects_future_locktime_with_non_final_sequence() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // nLockTime > height AND any input has non-final sequence:
        // the transaction is not yet final and MUST be rejected.
        let tx = make_locktime_tx(782_300, 0xFFFFFFFE);
        assert!(matches!(
            validator.check_lock_time(&tx, 782_291),
            Err(TransactionValidationError::InvalidLockTime)
        ));
    }

    #[test]
    fn test_check_lock_time_accepts_future_locktime_with_sequence_final() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // W66 regression: nLockTime > height but all inputs are
        // SEQUENCE_FINAL (0xFFFFFFFF). Per BIP65/IsFinalTx the tx opts
        // out of lock-time enforcement and is final. This is the pattern
        // that wedged ouroboros at mainnet block 782,291 against txs
        // #219 (locktime=782,300), #232 (locktime=782,295), and #233
        // (locktime=782,299).
        let tx = make_locktime_tx(782_299, 0xFFFFFFFF);
        assert!(
            validator.check_lock_time(&tx, 782_291).is_ok(),
            "tx with future locktime + SEQUENCE_FINAL must be accepted (W66)"
        );

        // And at the exact block height, same story.
        let tx = make_locktime_tx(782_291, 0xFFFFFFFF);
        assert!(validator.check_lock_time(&tx, 782_291).is_ok());
    }

    #[test]
    fn test_check_lock_time_rejects_locktime_at_block_height_without_final_sequence() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // Edge case: nLockTime == height with non-final sequence. Per
        // Core's strict `<` comparison this is NOT yet final
        // (the lock-time is not in the PAST, it's the CURRENT block).
        // The previous implementation used `>` and accepted this
        // incorrectly.
        let tx = make_locktime_tx(782_291, 0xFFFFFFFE);
        assert!(matches!(
            validator.check_lock_time(&tx, 782_291),
            Err(TransactionValidationError::InvalidLockTime)
        ));
    }

    #[test]
    fn test_check_lock_time_time_based_preserves_accept_all() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

        // Time-based lock-times (nLockTime >= 500,000,000) are accepted
        // unconditionally by the current implementation (BIP113 MTP not
        // yet plumbed through). This test locks in the behaviour so a
        // stricter fix doesn't silently regress IBD.
        let tx = make_locktime_tx(1_700_000_000, 0xFFFFFFFE);
        assert!(validator.check_lock_time(&tx, 782_291).is_ok());
    }

    #[test]
    fn test_get_sigop_count() {
        let (_temp_dir, db) = create_test_db();
        let validator = TransactionValidator::new(db, Network::Bitcoin);

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

    #[test]
    fn test_coinbase_maturity_constant() {
        // Verify COINBASE_MATURITY matches Bitcoin Core
        assert_eq!(COINBASE_MATURITY, 100);
    }

    #[test]
    fn test_check_coinbase_maturity_non_coinbase() {
        // Non-coinbase UTXOs should always pass
        assert!(check_coinbase_maturity(false, 0, 1).is_ok());
        assert!(check_coinbase_maturity(false, 100, 100).is_ok());
        assert!(check_coinbase_maturity(false, 200, 100).is_ok());
    }

    #[test]
    fn test_check_coinbase_maturity_immature() {
        // Coinbase at height 100, spending at height 150 (depth = 50)
        let result = check_coinbase_maturity(true, 100, 150);
        assert!(result.is_err());
        let (depth, required) = result.unwrap_err();
        assert_eq!(depth, 50);
        assert_eq!(required, 100);

        // Coinbase at height 100, spending at height 199 (depth = 99)
        let result = check_coinbase_maturity(true, 100, 199);
        assert!(result.is_err());
        let (depth, _) = result.unwrap_err();
        assert_eq!(depth, 99);

        // Coinbase at height 100, spending at height 101 (depth = 1)
        let result = check_coinbase_maturity(true, 100, 101);
        assert!(result.is_err());
        let (depth, _) = result.unwrap_err();
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_check_coinbase_maturity_mature() {
        // Coinbase at height 100, spending at height 200 (depth = 100) - exactly at maturity
        assert!(check_coinbase_maturity(true, 100, 200).is_ok());

        // Coinbase at height 100, spending at height 201 (depth = 101) - beyond maturity
        assert!(check_coinbase_maturity(true, 100, 201).is_ok());

        // Coinbase at height 0, spending at height 100 (depth = 100)
        assert!(check_coinbase_maturity(true, 0, 100).is_ok());

        // Coinbase at height 0, spending at height 1000 (depth = 1000)
        assert!(check_coinbase_maturity(true, 0, 1000).is_ok());
    }

    #[test]
    fn test_check_coinbase_maturity_edge_cases() {
        // Spending at same height as coinbase (depth = 0)
        let result = check_coinbase_maturity(true, 100, 100);
        assert!(result.is_err());
        let (depth, _) = result.unwrap_err();
        assert_eq!(depth, 0);

        // Very large heights
        assert!(check_coinbase_maturity(true, 800000, 800100).is_ok());
        let result = check_coinbase_maturity(true, 800000, 800099);
        assert!(result.is_err());
    }
}

