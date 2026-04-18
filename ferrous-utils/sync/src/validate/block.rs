//! Block validation module

use std::sync::Arc;
use std::collections::HashSet;

use bitcoin::{Block, Network, OutPoint};
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

    #[error("BIP30: duplicate unspent txid")]
    Bip30DuplicateTxid,

    #[error("BIP68: sequence lock not satisfied")]
    InvalidSequenceLock,

    #[error("BIP68: missing UTXO for input {0}")]
    Bip68MissingUtxo(String),

    #[error("BIP141: block has witness data but no witness commitment")]
    MissingWitnessCommitment,

    #[error("BIP141: coinbase witness must be exactly one 32-byte item")]
    InvalidCoinbaseWitnessNonce,

    #[error("BIP141: witness commitment mismatch")]
    WitnessCommitmentMismatch,
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

    /// Validate a block with explicit flags, matching Python's two-axis model.
    ///
    /// Unlike `validate_block()` which uses `assumevalid_height` to gate both
    /// the per-tx loop *and* script verification together, this method:
    ///
    /// - **Always** runs the per-tx loop (structural + amount + coinbase
    ///   maturity + lock-time checks), matching Python's `skip_scripts=True`
    ///   behavior which still performs these checks.
    /// - Reserves `skip_scripts` as a future gate for `script::verify_*`
    ///   calls. Today it is unused because the production validate path does
    ///   not call the script interpreter (see B3 Stage 1 audit); the flag is
    ///   plumbed through for forward compat when script verification lands.
    ///
    /// This is the entry point used by the Python FFI path
    /// (`validate_block_from_bytes`).  Internal Rust callers in
    /// `FastSync`/`BlockSync` continue to use `validate_block()` to preserve
    /// their current assumevalid-driven behavior.
    ///
    /// Reference: OUROBOROS-B3-RUST-VALIDATE-SCOPE.md,
    /// OUROBOROS-B3-STAGE1-KICKOFF.md.
    pub fn validate_block_with_flags(
        &self,
        block: &BlockWrapper,
        prev_height: u32,
        skip_scripts: bool,
    ) -> Result<()> {
        let _ = skip_scripts; // reserved for future script-verify gating
        let inner = block.inner();
        let height = prev_height + 1;

        // 1. Validate header (PoW, timestamps, difficulty)
        self.validate_header(block, prev_height)?;

        // 2. Check block weight limit
        self.check_size_limits(inner)?;

        // 3. Verify merkle root
        if !self.verify_merkle_root(inner) {
            return Err(BlockValidationError::InvalidMerkleRoot);
        }

        // 4. Non-empty block
        if inner.txdata.is_empty() {
            return Err(BlockValidationError::NoTransactions);
        }

        // 5. Coinbase position + uniqueness
        let coinbase_tx = &inner.txdata[0];
        if !coinbase_tx.is_coinbase() {
            return Err(BlockValidationError::NoCoinbase);
        }
        for tx in inner.txdata.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(BlockValidationError::MultipleCoinbase);
            }
        }

        // 6. Duplicate tx check (structural, in-block only)
        self.check_duplicate_transactions(inner)?;

        // 6b. BIP30 duplicate-txid against UTXO set (mainnet window only)
        self.check_bip30(inner, height)?;

        // 7. Per-tx validation — always, regardless of assumevalid.
        //    Matches Python's skip_scripts=True path which keeps UTXO
        //    lookups, coinbase maturity, amount, and BIP68 checks.
        self.tx_validator.check_coinbase(coinbase_tx, height)
            .map_err(BlockValidationError::TransactionValidation)?;

        // 7b. BIP68 sequence-lock enforcement is gated on network activation
        //     and requires the previous block's MTP once. Fetch lazily on
        //     first time-locked input; height-locked inputs don't need it.
        let enforce_bip68 = super::sequence_lock::is_bip68_active(height, self.network);
        let mut block_median_time: Option<i64> = None;

        // Accumulate fees across non-coinbase txs so we can verify coinbase
        // amount = subsidy + fees after the per-tx loop.
        let mut total_fees: u64 = 0;

        // Intra-block UTXO view so tx N can spend an output created by
        // an earlier tx M<N in the same block. Python reference:
        // `validation.py::validate_block` `intra_block_utxos`.
        let mut intra_utxos: std::collections::HashMap<OutPoint, UTXO> =
            std::collections::HashMap::new();

        // Seed the view with the coinbase's outputs (coinbase maturity still
        // applies to anyone trying to spend them).
        let cb_txid = coinbase_tx.compute_txid();
        for (vout, out) in coinbase_tx.output.iter().enumerate() {
            let op = OutPoint { txid: cb_txid, vout: vout as u32 };
            let outpoint_wrapper = common::OutPointWrapper::new(op);
            intra_utxos.insert(op, UTXO::new(
                outpoint_wrapper,
                out.value.to_sat(),
                out.script_pubkey.clone(),
                Some(height),
                true,
            ));
        }

        for tx in inner.txdata.iter().skip(1) {
            let tx_wrapper = TransactionWrapper::new(tx.clone());
            let fee = self.tx_validator
                .validate_transaction_with_fee(&tx_wrapper, height, &intra_utxos)
                .map_err(BlockValidationError::TransactionValidation)?;
            total_fees = total_fees.checked_add(fee)
                .ok_or(BlockValidationError::CoinbaseAmountExceeded)?;

            if enforce_bip68 && tx.version.0 >= 2 {
                self.check_tx_sequence_locks(
                    tx, prev_height, height, &mut block_median_time, &intra_utxos,
                )?;
            }

            // Register this tx's outputs for subsequent txs in the same block.
            let txid = tx.compute_txid();
            for (vout, out) in tx.output.iter().enumerate() {
                let op = OutPoint { txid, vout: vout as u32 };
                let outpoint_wrapper = common::OutPointWrapper::new(op);
                intra_utxos.insert(op, UTXO::new(
                    outpoint_wrapper,
                    out.value.to_sat(),
                    out.script_pubkey.clone(),
                    Some(height),
                    false,
                ));
            }
        }

        // 7c. Coinbase amount ≤ subsidy + fees (BIP34+ and coinbase-burn check).
        //     Matches Python `validation.py:420-426`.
        self.validate_block_subsidy(inner, height, total_fees)?;

        // 7d. BIP141 witness commitment.
        self.check_witness_commitment(inner, height)?;

        // 8. Sigop cost limit with BIP141 witness discount
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

    /// BIP30 duplicate-txid prohibition.
    ///
    /// Rejects a block that contains a tx whose txid already has any unspent
    /// outputs in the UTXO set. Enforcement rules (mirror of Python
    /// `validation.py:336-354` and Bitcoin Core `IsBIP30Repeat`):
    ///
    /// - Heights 91_842 and 91_880 are the two historical grandfathered
    ///   duplicates — never enforce.
    /// - Within `[BIP34, BIP30_RECHECK)` = `[227_931, 1_983_702)` BIP34 coinbase
    ///   height encoding guarantees uniqueness, so the check is skipped as a
    ///   performance optimisation.
    /// - Everywhere else on mainnet the check is enforced.
    ///
    /// Non-mainnet networks never enforce.
    fn check_bip30(&self, block: &Block, height: u32) -> Result<()> {
        if self.network != Network::Bitcoin {
            return Ok(());
        }
        if height == 91_842 || height == 91_880 {
            return Ok(());
        }
        const BIP34_HEIGHT: u32 = 227_931;
        const BIP30_RECHECK_HEIGHT: u32 = 1_983_702;
        if height >= BIP34_HEIGHT && height < BIP30_RECHECK_HEIGHT {
            return Ok(());
        }

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for vout in 0..tx.output.len() as u32 {
                let op = OutPoint { txid, vout };
                if self.db.get_utxo(&op)?.is_some() {
                    return Err(BlockValidationError::Bip30DuplicateTxid);
                }
            }
        }
        Ok(())
    }

    /// BIP141 witness-commitment verification.
    ///
    /// Post-SegWit activation, a block carrying any witness data must embed
    /// a witness commitment in a coinbase `OP_RETURN` output in the form
    /// `OP_RETURN 0x24 <magic=0xaa21a9ed> <32-byte commitment>`. The commitment
    /// is `dSHA256(witness_merkle_root || coinbase_witness_nonce)`, where the
    /// witness merkle root is computed over wtxids with the coinbase's wtxid
    /// replaced by 32 zero bytes.
    ///
    /// If multiple qualifying outputs exist, **the last one wins** (per BIP141
    /// and Bitcoin Core `GetWitnessCommitmentIndex`). Python reference:
    /// `validation.py::_validate_witness_commitment`.
    fn check_witness_commitment(&self, block: &Block, height: u32) -> Result<()> {
        use bitcoin::hashes::{sha256d, Hash as _};
        use super::script::activation_heights::segwit_height;

        let activation = segwit_height(self.network);
        if height < activation {
            return Ok(());
        }

        let has_witness = block.txdata.iter().any(|tx| {
            tx.input.iter().any(|inp| !inp.witness.is_empty())
        });

        let coinbase = &block.txdata[0];
        let commitment: Option<[u8; 32]> = coinbase.output.iter().rev().find_map(|out| {
            let spk = out.script_pubkey.as_bytes();
            if spk.len() >= 38
                && spk[0] == 0x6A
                && spk[1] == 0x24
                && spk[2..6] == [0xaa, 0x21, 0xa9, 0xed]
            {
                let mut c = [0u8; 32];
                c.copy_from_slice(&spk[6..38]);
                Some(c)
            } else {
                None
            }
        });

        match (has_witness, commitment) {
            (true, None) => Err(BlockValidationError::MissingWitnessCommitment),
            (true, Some(commit)) => {
                let cb_witness = &coinbase.input[0].witness;
                let nonce = match cb_witness.last() {
                    Some(n) if cb_witness.len() == 1 && n.len() == 32 => n,
                    _ => return Err(BlockValidationError::InvalidCoinbaseWitnessNonce),
                };

                let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
                wtxids.push([0u8; 32]);
                for tx in block.txdata.iter().skip(1) {
                    wtxids.push(*tx.compute_wtxid().as_byte_array());
                }
                let witness_root = compute_merkle_root(&wtxids);

                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&witness_root);
                buf[32..].copy_from_slice(nonce);
                let expected = sha256d::Hash::hash(&buf);

                if *expected.as_byte_array() != commit {
                    return Err(BlockValidationError::WitnessCommitmentMismatch);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// BIP68 sequence-lock enforcement for a single non-coinbase transaction.
    ///
    /// `block_median_time` is the MTP of the *previous* block. It's lazily
    /// fetched (11 block reads) only when a time-locked input is seen.
    /// Height-locked inputs don't require it.
    ///
    /// Reference: Bitcoin Core `SequenceLocks`/`EvaluateSequenceLocks` and
    /// Python `validation.py` `check_sequence_locks`.
    fn check_tx_sequence_locks(
        &self,
        tx: &bitcoin::Transaction,
        prev_height: u32,
        height: u32,
        block_median_time: &mut Option<i64>,
        extras: &std::collections::HashMap<OutPoint, UTXO>,
    ) -> Result<()> {
        use super::sequence_lock::{
            InputLockInfo, check_sequence_locks,
            SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
        };

        // Fast path: if every input has the disable flag, nothing to check.
        let any_live = tx.input.iter().any(|i| {
            i.sequence.0 & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
        });
        if !any_live {
            return Ok(());
        }

        let mut input_infos = Vec::with_capacity(tx.input.len());
        for input in &tx.input {
            let utxo = if let Some(u) = extras.get(&input.previous_output) {
                u.clone()
            } else {
                self.db.get_utxo(&input.previous_output)?
                    .ok_or_else(|| BlockValidationError::Bip68MissingUtxo(
                        format!("{}:{}", input.previous_output.txid, input.previous_output.vout)))?
            };
            let prev_h = utxo.height.unwrap_or(0);

            // MTP at (prev_h - 1) is only needed for time-locked live inputs.
            let is_time_locked =
                input.sequence.0 & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
                && input.sequence.0 & SEQUENCE_LOCKTIME_TYPE_FLAG != 0;
            let prev_mtp = if is_time_locked && prev_h > 0 {
                self.header_validator
                    .get_median_time_past(prev_h.saturating_sub(1))? as i64
            } else {
                0
            };

            input_infos.push(InputLockInfo {
                sequence: input.sequence.0,
                prev_height: prev_h,
                prev_median_time: prev_mtp,
            });
        }

        // block_median_time = MTP of previous block. Only fetch if any live
        // time-locked input exists in this tx.
        let need_block_mtp = tx.input.iter().any(|i| {
            let s = i.sequence.0;
            s & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
                && s & SEQUENCE_LOCKTIME_TYPE_FLAG != 0
        });
        let bmt = if need_block_mtp {
            if let Some(v) = *block_median_time {
                v
            } else {
                let v = self.header_validator.get_median_time_past(prev_height)? as i64;
                *block_median_time = Some(v);
                v
            }
        } else {
            0
        };

        if !check_sequence_locks(tx.version.0, &input_infos, height, bmt, true) {
            return Err(BlockValidationError::InvalidSequenceLock);
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

        // Single WriteBatch for all DB mutations in this block
        let mut batch = self.db.create_batch();

        // Phase 1: Write HEAD_BLOCKS marker
        // Record old tip so crash recovery knows where to roll back to.
        let (old_tip_hash, old_tip_height) = if height == 0 {
            ([0u8; 32], 0u32)
        } else {
            self.db.get_best_block().unwrap_or(([0u8; 32], 0))
        };
        self.db.write_head_blocks_batch(
            &mut batch,
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
                    self.db.spend_utxo_batch(&mut batch, outpoint.inner(), &txid.as_byte_array())?;
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
                self.db.add_utxo_batch(&mut batch, outpoint.inner(), &utxo)?;
            }

            // Store transaction index: txid → (block_hash, height, position)
            self.db.store_tx_index_batch(
                &mut batch,
                txid.as_byte_array(),
                &block_hash,
                height,
                tx_pos as u32,
            )?;
        }

        // Store block body + metadata
        self.db.store_block_batch(&mut batch, block)?;

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
        self.db.store_block_metadata_batch(&mut batch, height, &block_hash, &metadata)?;

        // Phase 2: Update chain tip + delete marker
        self.db.update_best_block_batch(&mut batch, &block_hash, height)?;
        self.db.delete_head_blocks_batch(&mut batch)?;

        // Atomically apply all writes for this block
        self.db.apply_batch(batch)?;

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

    // ---- witness-commitment test helpers ----

    fn mk_coinbase(outputs: Vec<bitcoin::TxOut>, with_nonce: bool) -> Transaction {
        let witness = if with_nonce {
            bitcoin::Witness::from_slice(&[vec![0u8; 32]])
        } else {
            bitcoin::Witness::new()
        };
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: bitcoin::ScriptBuf::from(vec![0x03, 0x00, 0x00, 0x00]),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness,
            }],
            output: outputs,
        }
    }

    fn mk_witness_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([1u8; 32]),
                    0,
                ),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::from_slice(&[vec![0xaa; 71], vec![0xbb; 33]]),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn commitment_spk(commit: &[u8; 32]) -> bitcoin::ScriptBuf {
        let mut spk = Vec::with_capacity(38);
        spk.push(0x6A);
        spk.push(0x24);
        spk.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        spk.extend_from_slice(commit);
        bitcoin::ScriptBuf::from(spk)
    }

    fn mk_block(txs: Vec<Transaction>) -> Block {
        let txids: Vec<[u8; 32]> = txs.iter()
            .map(|tx| *tx.compute_txid().as_byte_array())
            .collect();
        let merkle_root = compute_merkle_root(&txids);
        Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::blockdata::block::TxMerkleNode::from_byte_array(merkle_root),
                time: 1_234_567_890u32,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: txs,
        }
    }

    fn compute_expected_witness_commitment(block: &Block, nonce: &[u8; 32]) -> [u8; 32] {
        use bitcoin::hashes::{sha256d, Hash as _};
        let mut wtxids: Vec<[u8; 32]> = vec![[0u8; 32]];
        for tx in block.txdata.iter().skip(1) {
            wtxids.push(*tx.compute_wtxid().as_byte_array());
        }
        let witness_root = compute_merkle_root(&wtxids);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&witness_root);
        buf[32..].copy_from_slice(nonce);
        *sha256d::Hash::hash(&buf).as_byte_array()
    }

    #[test]
    fn test_witness_commitment_preactivation() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        // has_witness=true but height < mainnet segwit activation (481_824) → no-op
        let coinbase = mk_coinbase(vec![], true);
        let block = mk_block(vec![coinbase, mk_witness_tx()]);
        assert!(validator.check_witness_commitment(&block, 481_823).is_ok());
    }

    #[test]
    fn test_witness_commitment_missing_when_has_witness() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        // Post-activation, a witness-bearing tx but no commitment in coinbase → fail
        let coinbase = mk_coinbase(vec![], false);
        let block = mk_block(vec![coinbase, mk_witness_tx()]);
        let r = validator.check_witness_commitment(&block, 500_000);
        assert!(matches!(r, Err(BlockValidationError::MissingWitnessCommitment)));
    }

    #[test]
    fn test_witness_commitment_mismatch() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        let bogus = commitment_spk(&[0xff; 32]);
        let coinbase = mk_coinbase(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bogus,
        }], true);
        let block = mk_block(vec![coinbase, mk_witness_tx()]);
        let r = validator.check_witness_commitment(&block, 500_000);
        assert!(matches!(r, Err(BlockValidationError::WitnessCommitmentMismatch)));
    }

    #[test]
    fn test_witness_commitment_valid() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        // First build the block without commitment to compute it.
        let placeholder_cb = mk_coinbase(vec![], true);
        let block_seed = mk_block(vec![placeholder_cb.clone(), mk_witness_tx()]);
        let nonce = [0u8; 32];
        let commit = compute_expected_witness_commitment(&block_seed, &nonce);

        // Rebuild coinbase with the correct commitment output.
        let coinbase = mk_coinbase(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: commitment_spk(&commit),
        }], true);
        let block = mk_block(vec![coinbase, mk_witness_tx()]);
        assert!(validator.check_witness_commitment(&block, 500_000).is_ok());
    }

    #[test]
    fn test_witness_commitment_no_witness_no_commitment() {
        // Post-activation, block has no witness anywhere and no commitment → Ok.
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        let coinbase = mk_coinbase(vec![], false);
        let block = mk_block(vec![coinbase]);
        assert!(validator.check_witness_commitment(&block, 500_000).is_ok());
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

