//! Block validation module

use std::sync::Arc;
use std::collections::HashSet;

use bitcoin::{Block, Network, OutPoint};
use bitcoin::hashes::Hash;
use thiserror::Error;

use crate::storage::{BlockchainDB, DbError};
use common::{BlockWrapper, BlockHeaderWrapper, BlockMetadata, BlockStatus, TransactionWrapper, OutPointWrapper, UTXO};
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

/// Maximum script size — matches Core's `MAX_SCRIPT_SIZE` in
/// `bitcoin-core/src/script/script.h:40`.  Outputs whose `scriptPubKey`
/// exceeds this length are provably unspendable (the script interpreter
/// rejects them at execution).
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Returns `true` for outputs that are provably unspendable and therefore
/// must NEVER enter the UTXO set.  Mirrors Core's
/// `CScript::IsUnspendable` (script.h:563-566):
///
/// ```text
///   bool IsUnspendable() const {
///       return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
///   }
/// ```
///
/// Used by `apply_block` and `connect_block_from_bytes` to filter outputs
/// before writing into `CHAINSTATE_CF`, which keeps `dumptxoutset` output
/// byte-identical to Core (e.g. the witness-commitment OP_RETURN in
/// segwit-coinbase blocks must NOT appear in the snapshot).
pub fn is_unspendable_script(script: &[u8]) -> bool {
    (!script.is_empty() && script[0] == 0x6a /* OP_RETURN */)
        || script.len() > MAX_SCRIPT_SIZE
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

        // W85 regression fix: collect each input's script_pubkey from the
        // UTXO fetch we already do here, so the sigop pass below can read
        // them out of memory instead of issuing 2 more `db.get_utxo()`
        // round-trips per input. Indexed by tx position; the coinbase
        // (index 0) gets an empty Vec since it has no real prevouts.
        let mut prefetched_input_scripts: Vec<Vec<bitcoin::ScriptBuf>> =
            Vec::with_capacity(inner.txdata.len());
        prefetched_input_scripts.push(Vec::new()); // coinbase

        for tx in inner.txdata.iter().skip(1) {
            let tx_wrapper = TransactionWrapper::new(tx.clone());
            let (fee, input_scripts) = self.tx_validator
                .validate_transaction_with_fee_and_scripts(&tx_wrapper, height, &intra_utxos)
                .map_err(BlockValidationError::TransactionValidation)?;
            total_fees = total_fees.checked_add(fee)
                .ok_or(BlockValidationError::CoinbaseAmountExceeded)?;
            prefetched_input_scripts.push(input_scripts);

            if enforce_bip68 && super::sequence_lock::bip68_version_active(tx.version.0) {
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

        // 8. Sigop cost limit with BIP141 witness discount.
        //    W85 fix: use prefetched script_pubkeys instead of re-fetching
        //    every input's UTXO from RocksDB inside `get_p2sh_sigop_count`
        //    + the witness loop.
        let (verify_p2sh, verify_witness) = self.get_sigop_flags(height);
        let total_sigop_cost = super::sigop::get_block_sigop_cost_with_prefetched_scripts(
            &inner.txdata,
            &prefetched_input_scripts,
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

    /// Check block weight limit (BIP141).
    ///
    /// Total block weight = sum of each tx's weight, where tx weight is
    /// `base_size * 3 + total_size` (non-witness bytes counted 4×, witness
    /// bytes counted 1×). Must not exceed MAX_BLOCK_WEIGHT (4_000_000).
    ///
    /// Matches Python `validation.py::_validate_block_limits` which sums
    /// `tx.get_weight()` across all transactions.
    fn check_size_limits(&self, block: &Block) -> Result<()> {
        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        if block.weight().to_wu() > MAX_BLOCK_WEIGHT {
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
    /// outputs in the UTXO set. Mirrors Bitcoin Core `Chainstate::ConnectBlock`
    /// (`validation.cpp:2392-2476`) + `IsBIP30Repeat` (`validation.cpp:6189-6193`):
    ///
    /// - **G(A) IsBIP30Repeat** — Mainnet blocks 91_842 / 91_880 are the two
    ///   historical grandfathered duplicate-coinbase blocks. The exemption
    ///   is keyed by **both height and hash** so that a fork block at the
    ///   same height does NOT inherit the exemption.
    /// - **G(B) BIP34 suppression** — Once BIP34 is active and the block at
    ///   the activation height matches `BIP34Hash`, coinbase uniqueness is
    ///   guaranteed by construction, so the UTXO scan can be skipped. For
    ///   testnet4 / signet / regtest, `BIP34Hash` is `uint256{}` (all zeros)
    ///   which can never match a real block hash, so BIP30 is ALWAYS
    ///   enforced on those networks.
    /// - **G(C) BIP34_IMPLIES_BIP30_LIMIT (1_983_702)** — Above this height
    ///   BIP30 is re-enabled on every chain, because pre-BIP34 coinbases
    ///   exist whose indicated heights reach this far.
    ///
    /// W93 fixes:
    ///   * Bug A — was `if self.network != Network::Bitcoin { return Ok(()); }`
    ///     which incorrectly skipped BIP30 on testnet4/signet/regtest, where
    ///     Core enforces it because `BIP34Hash = uint256{}`. Now per-network.
    ///   * Bug B — was a height-only window check, ignoring the canonical
    ///     ancestor hash. Now consults the on-disk ancestor at `BIP34Height`
    ///     and only suppresses BIP30 when it matches the canonical hash.
    ///   * Bug C — `BIP34_IMPLIES_BIP30_LIMIT` is enforced on every network
    ///     (Core gates by height, not by net).
    fn check_bip30(&self, block: &Block, height: u32) -> Result<()> {
        // G(C) — BIP34_IMPLIES_BIP30_LIMIT is a global height gate. Above it
        // BIP30 is re-enabled regardless of network or BIP34 status.
        const BIP30_RECHECK_HEIGHT: u32 = 1_983_702;

        // BIP30 canonical-hash tables (internal LE byte order). Stored as
        // hex strings so we can fall back to runtime decoding without a
        // hex_literal dep. Decoding here is one-shot and cheap.
        const BIP30_REPEAT_HASH_91842: &str =
            "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec";
        const BIP30_REPEAT_HASH_91880: &str =
            "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721";
        const BIP34_HASH_MAINNET: &str =
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8";
        const BIP34_HASH_TESTNET3: &str =
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8";

        fn decode_hash(s: &str) -> [u8; 32] {
            let bytes = hex::decode(s).expect("compile-time hex constant decodes");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }

        // G(A) — IsBIP30Repeat. Keyed on (height, block_hash). Only the two
        // canonical mainnet duplicates are exempt; a fork at the same height
        // is NOT.
        let block_hash = *block.block_hash().as_byte_array();
        if self.network == Network::Bitcoin && height < BIP30_RECHECK_HEIGHT
            && (height == 91_842 || height == 91_880)
        {
            let canonical = if height == 91_842 {
                decode_hash(BIP30_REPEAT_HASH_91842)
            } else {
                decode_hash(BIP30_REPEAT_HASH_91880)
            };
            if block_hash == canonical {
                return Ok(());
            }
            // Fall through — a fork at this height must be checked.
        }

        // G(B) — BIP34 suppression. Only applies between BIP34 activation
        // and BIP30_RECHECK, AND only when the ancestor at the BIP34 height
        // has the canonical hash.
        let bip34_height = crate::chain_params::bip_activation_heights(self.network).0;
        let bip34_canonical_hash: Option<[u8; 32]> = match self.network {
            Network::Bitcoin => Some(decode_hash(BIP34_HASH_MAINNET)),
            Network::Testnet => Some(decode_hash(BIP34_HASH_TESTNET3)),
            // testnet4 / signet / regtest: BIP34Hash = uint256{}. No
            // canonical-hash match is ever possible — BIP30 stays enforced.
            // Reference: bitcoin-core/src/kernel/chainparams.cpp:312, 456, 537
            _ => None,
        };

        let suppress_by_bip34 = if height < BIP30_RECHECK_HEIGHT
            && height >= bip34_height
        {
            match bip34_canonical_hash {
                Some(expected) => {
                    // Look up the block on the canonical chain at the BIP34
                    // height; only suppress when it matches the canonical
                    // hash. (Core: `pindexBIP34height->GetBlockHash() == BIP34Hash`.)
                    match self.db.get_block_by_height(bip34_height) {
                        Ok(Some(bw)) => {
                            *bw.block_hash().as_byte_array() == expected
                        }
                        // DB miss → conservatively keep enforcing BIP30.
                        _ => false,
                    }
                }
                None => false,
            }
        } else {
            false
        };

        if suppress_by_bip34 {
            return Ok(());
        }

        // Enforce BIP30.
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
            (true, Some(commit)) | (false, Some(commit)) => {
                // Core validation.cpp:3876-3885: whenever a witness commitment is
                // present in the coinbase, the coinbase witness stack MUST be
                // exactly one 32-byte item — unconditional on has_witness.
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
            (false, None) => Ok(()),
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
    /// Bitcoin subsidy starts at 50 BTC = 5_000_000_000 satoshis and halves
    /// every `consensusParams.nSubsidyHalvingInterval` blocks. The interval
    /// is **per-network**: 210_000 on mainnet/testnet/testnet4/signet, but
    /// **150 on regtest** (`kernel/chainparams.cpp:535`).
    ///
    /// W93 fix: prior implementation hardcoded 210_000, which silently
    /// over-estimated the regtest subsidy after the 150-block halving and
    /// would let a coinbase pay too much (a `bad-cb-amount` consensus split
    /// vs Core on regtest functional tests).
    ///
    /// Reference: Bitcoin Core validation.cpp::GetBlockSubsidy
    /// (`nSubsidy = 50 * COIN; nSubsidy >>= halvings;`).
    pub fn calculate_block_subsidy(&self, height: u32) -> u64 {
        let interval = crate::chain_params::subsidy_halving_interval(self.network);
        let halvings = height / interval;
        if halvings >= 64 {
            return 0;
        }
        5_000_000_000u64 >> halvings
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

        // UTXO mutations + transaction index.
        //
        // Special case: genesis block coinbase is unspendable per Core
        // (validation.cpp:2337-2343 — "Special case for the genesis
        // block, skipping connection of its transactions (its coinbase
        // is unspendable)"), so we never add height-0 outputs to the
        // chainstate.  We still maintain the tx index so RPCs that look
        // up the genesis coinbase by txid keep working.
        let store_utxos = height > 0;
        for (tx_pos, tx) in inner.txdata.iter().enumerate() {
            let txid = tx.compute_txid();

            if !tx.is_coinbase() {
                for input in &tx.input {
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    self.db.spend_utxo_batch(&mut batch, outpoint.inner(), &txid.as_byte_array())?;
                }
            }

            if store_utxos {
                for (vout, output) in tx.output.iter().enumerate() {
                    // Skip provably unspendable outputs (OP_RETURN /
                    // oversize script).  Mirrors Core's `AddCoins`
                    // skipping `out.scriptPubKey.IsUnspendable()`
                    // (coins.cpp:96-99) — keeps `dumptxoutset` byte-
                    // identical to Core.
                    if is_unspendable_script(output.script_pubkey.as_bytes()) {
                        continue;
                    }
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
        // FIX-33 (W109 BUG-22): set BLOCK_HAVE_DATA now that the block body has
        // been written to BLOCKS_CF via store_block_batch above.
        // Mirrors Core: validation.cpp:3784 pindexNew->nStatus |= BLOCK_HAVE_DATA.
        let mut status = BlockStatus::new();
        status.set_has_data();
        let metadata = BlockMetadata::with_status(height, chainwork, timestamp, status);
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
    ///
    /// W92 audit (validation.cpp:2149-2248): this helper mirrors the gate
    /// structure of the primary `BlockchainDB::disconnect_block_at_height_checked`
    /// path. Gates engaged here: G10 reverse-iterate txs, G12 IsUnspendable
    /// filter, G14 skip coinbase, G16 reverse-iterate vin. Gates G1/G8/G9/G11/
    /// G13/G15/G19 (UNCLEAN/FAILED signaling, BIP-30 exceptions, per-tx undo
    /// arity, per-output mismatch check) live in the primary path because
    /// this helper is invoked via the validator pipeline and signals errors
    /// up the stack rather than enforcing chainstate invariants directly.
    pub fn disconnect_block(&self, block: &BlockWrapper, height: u32) -> Result<()> {
        let inner = block.inner();

        // Process transactions in reverse order (G10).
        for tx in inner.txdata.iter().rev() {
            let txid = tx.compute_txid();
            let is_coinbase = tx.is_coinbase();

            // 1. Remove outputs created by this block (G12: skip unspendable).
            for (vout, output) in tx.output.iter().enumerate() {
                if is_unspendable_script(output.script_pubkey.as_bytes()) {
                    // Unspendable outputs were never written into the
                    // chainstate (see apply_block above) — skip the delete
                    // to avoid spurious tombstones. Mirrors Core's
                    // `!scriptPubKey.IsUnspendable()` gate.
                    continue;
                }
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                self.db.delete_utxo(outpoint.inner())?;
            }

            // 2. Restore inputs (G14: skip coinbase, G16: reverse-iterate vin).
            if !is_coinbase {
                for input_idx in (0..tx.input.len()).rev() {
                    let input = &tx.input[input_idx];
                    let outpoint = OutPointWrapper::new(input.previous_output);
                    // Read undo record from SPENT_CF.
                    match self.db.get_spent_utxo(outpoint.inner())? {
                        Some((_spending_txid, utxo)) => {
                            // Restore the UTXO to chainstate.
                            self.db.add_utxo(outpoint.inner(), &utxo)?;
                            // Remove the undo record.
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

            // 3. Remove transaction index entry.
            self.db.delete_tx_index(txid.as_byte_array())?;
        }

        // 4. Update best block to the previous block (G18).
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
    fn test_is_unspendable_script() {
        // Empty script: spendable (matches Core: size() > 0 required for OP_RETURN check)
        assert!(!is_unspendable_script(&[]));

        // Bare OP_RETURN: unspendable
        assert!(is_unspendable_script(&[0x6a]));
        // OP_RETURN <data>: unspendable (anything that *starts* with OP_RETURN)
        assert!(is_unspendable_script(&[0x6a, 0x01, 0x42]));
        // Witness-commitment shape (segwit coinbase OP_RETURN): unspendable
        let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        wc.extend(std::iter::repeat(0u8).take(32));
        assert!(is_unspendable_script(&wc));

        // P2PKH-ish (76 a9 14 <20-byte hash> 88 ac): spendable
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend(std::iter::repeat(0u8).take(20));
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert!(!is_unspendable_script(&p2pkh));

        // P2WSH (00 20 <32-byte hash>): spendable
        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend(std::iter::repeat(0u8).take(32));
        assert!(!is_unspendable_script(&p2wsh));

        // Exactly MAX_SCRIPT_SIZE non-OP_RETURN: spendable (boundary)
        let max_ok = vec![0x51u8; MAX_SCRIPT_SIZE]; // OP_1 repeated
        assert_eq!(max_ok.len(), MAX_SCRIPT_SIZE);
        assert!(!is_unspendable_script(&max_ok));

        // MAX_SCRIPT_SIZE + 1: unspendable (oversize)
        let oversize = vec![0x51u8; MAX_SCRIPT_SIZE + 1];
        assert!(is_unspendable_script(&oversize));

        // Single byte that is NOT OP_RETURN: spendable
        assert!(!is_unspendable_script(&[0x51])); // OP_1
        // Pushdata sequences that don't start with OP_RETURN: spendable
        assert!(!is_unspendable_script(&[0x4c, 0x01, 0x42]));
    }

    #[test]
    fn test_calculate_block_subsidy() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

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

    /// W93 — Regression test for the network-aware halving interval.
    ///
    /// Pre-fix the implementation hardcoded 210_000 for every network,
    /// which over-estimates the regtest subsidy after the 150-block
    /// halving and would cause a `bad-cb-amount` consensus split vs Core
    /// on regtest functional tests.
    /// Reference: `kernel/chainparams.cpp:535` (regtest interval = 150).
    #[test]
    fn test_calculate_block_subsidy_regtest_uses_short_interval() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Regtest);

        // Pre-halving (height < 150): full 50 BTC.
        assert_eq!(validator.calculate_block_subsidy(0), 5_000_000_000);
        assert_eq!(validator.calculate_block_subsidy(149), 5_000_000_000);

        // First halving fires at height 150 on regtest.
        assert_eq!(validator.calculate_block_subsidy(150), 2_500_000_000);
        assert_eq!(validator.calculate_block_subsidy(299), 2_500_000_000);

        // Second halving at height 300.
        assert_eq!(validator.calculate_block_subsidy(300), 1_250_000_000);
        assert_eq!(validator.calculate_block_subsidy(449), 1_250_000_000);

        // Third halving at 450.
        assert_eq!(validator.calculate_block_subsidy(450), 625_000_000);

        // 64 halvings → 0.
        assert_eq!(validator.calculate_block_subsidy(64 * 150), 0);
        assert_eq!(validator.calculate_block_subsidy(10_000_000), 0);
    }

    /// W93 — Regtest and mainnet must diverge starting at height 150.
    #[test]
    fn test_calculate_block_subsidy_regtest_diverges_from_mainnet() {
        let (_temp_dir, db) = create_test_db();
        let mainnet_v = BlockValidator::new(db.clone(), Network::Bitcoin);
        let regtest_v = BlockValidator::new(db, Network::Regtest);

        // At height 150 regtest is past its first halving, mainnet is not.
        assert_eq!(mainnet_v.calculate_block_subsidy(150), 5_000_000_000);
        assert_eq!(regtest_v.calculate_block_subsidy(150), 2_500_000_000);
        assert_ne!(
            mainnet_v.calculate_block_subsidy(150),
            regtest_v.calculate_block_subsidy(150),
        );

        // testnet4 and signet share the mainnet interval (210_000).
        let signet_v = BlockValidator::new(
            BlockchainDB::open(
                TempDir::new("bitcoin_block_test_signet").unwrap().path().to_str().unwrap(),
            ).unwrap().into(),
            Network::Signet,
        );
        assert_eq!(signet_v.calculate_block_subsidy(150), 5_000_000_000);
    }

    #[test]
    fn test_check_size_limits_accepts_normal_block() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: bitcoin::ScriptBuf::from(vec![0x03, 0x00, 0x00, 0x00]),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let block = Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::blockdata::block::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1234567890u32,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx],
        };

        assert!(block.weight().to_wu() < 4_000_000);
        assert!(validator.check_size_limits(&block).is_ok());
    }

    #[test]
    fn test_check_size_limits_rejects_overweight_block() {
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);

        // Build a coinbase whose single output carries a huge OP_RETURN-style
        // scriptPubKey so the base size (×4) exceeds 4M weight units.
        // 1_100_000 base-size bytes → 4.4M weight units → over the cap.
        let big_payload = vec![0u8; 1_100_000];
        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([0u8; 32]),
                    u32::MAX,
                ),
                script_sig: bitcoin::ScriptBuf::from(vec![0x03, 0x00, 0x00, 0x00]),
                sequence: bitcoin::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: bitcoin::ScriptBuf::from(big_payload),
            }],
        };

        let block = Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::blockdata::block::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1234567890u32,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx],
        };

        assert!(block.weight().to_wu() > 4_000_000);
        assert!(matches!(
            validator.check_size_limits(&block),
            Err(BlockValidationError::SizeExceeded)
        ));
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
    fn test_witness_commitment_present_but_no_witness_txs_no_nonce() {
        // Core validation.cpp:3876-3885: commitment present in coinbase is
        // unconditionally enforced — even when has_witness=false (no non-coinbase
        // tx carries witness data).  A coinbase with a commitment output but an
        // EMPTY coinbase witness stack must be rejected with
        // InvalidCoinbaseWitnessNonce.  The old (false, Some) → Ok() catch-all
        // was wrong; this test FAILS without the fix and PASSES with it.
        let (_temp_dir, db) = create_test_db();
        let validator = BlockValidator::new(db, Network::Bitcoin);
        // Coinbase has a commitment output, but with_nonce=false → empty witness.
        let coinbase = mk_coinbase(vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: commitment_spk(&[0xab; 32]),
        }], false);
        // No witness-bearing non-coinbase txs (has_witness will be false).
        let block = mk_block(vec![coinbase]);
        let r = validator.check_witness_commitment(&block, 500_000);
        assert!(
            matches!(r, Err(BlockValidationError::InvalidCoinbaseWitnessNonce)),
            "expected InvalidCoinbaseWitnessNonce, got {r:?}"
        );
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

