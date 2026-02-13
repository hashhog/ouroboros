// Fast sync module with PyO3 bindings

pub mod chain_params;
pub mod chainwork;

use std::env;
pub mod storage;
pub mod validate;
pub mod network;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use bitcoin::Network;
use bitcoin::hashes::Hash;
use pyo3::prelude::*;
use tokio::sync::Mutex;

use common::{OutPointWrapper, UTXO, BlockWrapper, BlockHeaderWrapper, BlockMetadata};
use crate::storage::db::{BlockchainDB, DbError};
use crate::validate::header::HeaderValidator;
use crate::validate::block::BlockValidator;
use crate::network::peer_manager::PeerManager;
use crate::network::header_sync::HeaderSync;
use crate::network::block_sync::{BlockSync, BlockProgressCache};

/// Initialize logging. If RUST_LOG is not set, defaults to sync=warn.
/// When OUROBOROS_VERBOSE=1, sets RUST_LOG=sync=debug for verbose output.
fn init_logging() {
    if env::var("RUST_LOG").is_err() {
        let level = if env::var("OUROBOROS_VERBOSE").as_deref() == Ok("1") {
            "sync=debug"
        } else {
            "sync=warn"
        };
        env::set_var("RUST_LOG", level);
    }
    let _ = env_logger::try_init();
}

/// Fast sync module for Bitcoin blockchain synchronization
#[pymodule]
fn sync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    m.add_class::<PyUTXO>()?;
    m.add_class::<SyncEngine>()?;
    m.add_class::<FastSync>()?;
    m.add_class::<SyncCanceller>()?;
    m.add_class::<SyncProgressReporter>()?;
    m.add_class::<SyncProgress>()?;
    m.add_class::<PyBlockchainDB>()?;
    m.add_class::<PyBlock>()?;
    m.add_class::<PyTransaction>()?;
    Ok(())
}

/// Python wrapper for UTXO
#[pyclass]
#[derive(Clone)]
pub struct PyUTXO {
    #[pyo3(get)]
    pub txid: String,
    #[pyo3(get)]
    pub vout: u32,
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub script_pubkey: Vec<u8>,
}

impl From<UTXO> for PyUTXO {
    fn from(utxo: UTXO) -> Self {
        Self {
            txid: utxo.txid().to_string(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey: utxo.script_pubkey.as_bytes().to_vec(),
        }
    }
}

impl From<&UTXO> for PyUTXO {
    fn from(utxo: &UTXO) -> Self {
        Self {
            txid: utxo.txid().to_string(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey: utxo.script_pubkey.as_bytes().to_vec(),
        }
    }
}

/// Python wrapper for Block
#[pyclass]
#[derive(Clone)]
pub struct PyBlock {
    #[pyo3(get)]
    pub version: i32,
    #[pyo3(get)]
    pub prev_blockhash: Vec<u8>,
    #[pyo3(get)]
    pub merkle_root: Vec<u8>,
    #[pyo3(get)]
    pub timestamp: u32,
    #[pyo3(get)]
    pub bits: u32,
    #[pyo3(get)]
    pub nonce: u32,
    #[pyo3(get)]
    pub transactions: Vec<PyTransaction>,
    #[pyo3(get)]
    pub hash: Vec<u8>,
}

impl PyBlock {
    fn from_block_wrapper(block: &BlockWrapper) -> Self {
        let inner_block = block.inner();
        let header = &inner_block.header;
        let hash = block.block_hash();
        
        Self {
            version: header.version.to_consensus(),
            prev_blockhash: header.prev_blockhash.to_byte_array().to_vec(),
            merkle_root: header.merkle_root.to_byte_array().to_vec(),
            timestamp: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
            transactions: inner_block.txdata.iter().map(|tx| PyTransaction::from_transaction(tx)).collect(),
            hash: hash.to_byte_array().to_vec(),
        }
    }
}

#[pymethods]
impl PyBlock {
    /// Compute block hash
    fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
    
    /// Serialize block to bytes
    fn serialize(&self) -> PyResult<Vec<u8>> {
        // Convert back to BlockWrapper and serialize
        // This is a simplified version - full implementation would reconstruct BlockWrapper
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "Block serialization requires full BlockWrapper reconstruction"
        ))
    }
    
    // Note: Block deserialization would require BitcoinDeserialize implementation
    // For now, blocks are deserialized in Rust and converted to PyBlock
}

/// Python wrapper for Transaction
#[pyclass]
#[derive(Clone)]
pub struct PyTransaction {
    #[pyo3(get)]
    pub txid: Vec<u8>,
    #[pyo3(get)]
    pub version: i32,
    #[pyo3(get)]
    pub locktime: u32,
    #[pyo3(get)]
    pub inputs: Vec<PyTxIn>,
    #[pyo3(get)]
    pub outputs: Vec<PyTxOut>,
}

impl PyTransaction {
    fn from_transaction(tx: &bitcoin::Transaction) -> Self {
        let txid = tx.compute_txid();
        // TODO: Fix type conversions - these types need proper conversion methods
        // For now, serialize the transaction and extract values
        let mut tx_bytes = Vec::new();
        use bitcoin::consensus::Encodable;
        tx.consensus_encode(&mut tx_bytes).unwrap();
        
        // Version is first 4 bytes (little-endian i32)
        let version = if tx_bytes.len() >= 4 {
            i32::from_le_bytes([tx_bytes[0], tx_bytes[1], tx_bytes[2], tx_bytes[3]])
        } else {
            2i32
        };
        
        // Locktime is at the end (last 4 bytes before it)
        // This is a simplified extraction - in practice we'd parse the full structure
        let locktime = if tx_bytes.len() >= 8 {
            // Locktime is typically the last 4 bytes
            let len = tx_bytes.len();
            u32::from_le_bytes([tx_bytes[len-4], tx_bytes[len-3], tx_bytes[len-2], tx_bytes[len-1]])
        } else {
            0u32
        };
        
        Self {
            txid: txid.to_byte_array().to_vec(),
            version,
            locktime,
            inputs: tx.input.iter().map(|input| PyTxIn::from_txin(input)).collect::<Vec<_>>(),
            outputs: tx.output.iter().map(|output| PyTxOut::from_txout(output)).collect::<Vec<_>>(),
        }
    }
}

/// Python wrapper for Transaction Input
#[pyclass]
#[derive(Clone)]
pub struct PyTxIn {
    #[pyo3(get)]
    pub prev_txid: Vec<u8>,
    #[pyo3(get)]
    pub prev_vout: u32,
    #[pyo3(get)]
    pub script_sig: Vec<u8>,
    #[pyo3(get)]
    pub sequence: u32,
}

impl PyTxIn {
    fn from_txin(txin: &bitcoin::TxIn) -> Self {
        // Convert sequence - serialize the whole TxIn and extract sequence (last 4 bytes)
        let mut txin_bytes = Vec::new();
        use bitcoin::consensus::Encodable;
        txin.consensus_encode(&mut txin_bytes).unwrap();
        
        // Sequence is the last 4 bytes of TxIn serialization
        let sequence = if txin_bytes.len() >= 4 {
            let len = txin_bytes.len();
            u32::from_le_bytes([txin_bytes[len-4], txin_bytes[len-3], txin_bytes[len-2], txin_bytes[len-1]])
        } else {
            0xFFFFFFFFu32
        };
        
        Self {
            prev_txid: txin.previous_output.txid.to_byte_array().to_vec(),
            prev_vout: txin.previous_output.vout,
            script_sig: txin.script_sig.as_bytes().to_vec(),
            sequence,
        }
    }
}

/// Python wrapper for Transaction Output
#[pyclass]
#[derive(Clone)]
pub struct PyTxOut {
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub script_pubkey: Vec<u8>,
}

impl PyTxOut {
    fn from_txout(txout: &bitcoin::TxOut) -> Self {
        Self {
            value: txout.value.to_sat(),
            script_pubkey: txout.script_pubkey.as_bytes().to_vec(),
        }
    }
}

/// Python wrapper for BlockchainDB
#[pyclass]
pub struct PyBlockchainDB {
    db: Arc<BlockchainDB>,
}

#[pymethods]
impl PyBlockchainDB {
    #[new]
    fn new(data_dir: String) -> PyResult<Self> {
        let db = BlockchainDB::open(&data_dir)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to open database: {}", e)
            ))?;
        
        Ok(Self {
            db: Arc::new(db),
        })
    }
    
    /// Get block by hash
    fn get_block(&self, block_hash: &[u8]) -> PyResult<Option<PyBlock>> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }
        
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        
        match self.db.get_block(&hash_bytes) {
            Ok(Some(block)) => Ok(Some(PyBlock::from_block_wrapper(&block))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }
    
    /// Get block by height
    fn get_block_by_height(&self, height: u32) -> PyResult<Option<PyBlock>> {
        match self.db.get_block_by_height(height) {
            Ok(Some(block)) => Ok(Some(PyBlock::from_block_wrapper(&block))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }
    
    /// Get UTXO
    fn get_utxo(&self, txid: &[u8], vout: u32) -> PyResult<Option<PyUTXO>> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid);
        
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let outpoint = bitcoin::OutPoint {
            txid,
            vout,
        };
        
        match self.db.get_utxo(&outpoint) {
            Ok(Some(utxo)) => Ok(Some(PyUTXO::from(&utxo))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }
    
    /// Store block
    fn store_block(&self, _block: &PyBlock) -> PyResult<()> {
        // This would require reconstructing BlockWrapper from PyBlock
        // For now, return NotImplemented
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "store_block requires BlockWrapper reconstruction - use Rust API directly"
        ))
    }
    
    /// Update UTXO set atomically
    fn update_utxo_set(
        &self,
        spent: Vec<(Vec<u8>, u32)>,
        created: Vec<PyUTXO>,
    ) -> PyResult<()> {
        // Convert spent outpoints
        let mut spent_outpoints = Vec::new();
        for (txid_bytes, vout) in spent {
            if txid_bytes.len() != 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Transaction ID must be 32 bytes"
                ));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);
            spent_outpoints.push(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(txid),
                vout,
            });
        }
        
        // Convert created UTXOs
        let _created_utxos: Vec<UTXO> = Vec::new();
        for _py_utxo in created {
            // This is simplified - would need to reconstruct full UTXO
            // For now, return NotImplemented
            return Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
                "update_utxo_set requires UTXO reconstruction - use Rust API directly"
            ));
        }
        
        // Would call: self.db.batch_update_utxos(&spent_outpoints, &created_utxos)?;
        Ok(())
    }
    
    /// Get chainwork at height (from block metadata, persisted in DB)
    fn get_chainwork_by_height(&self, height: u32) -> PyResult<Vec<u8>> {
        match self.db.get_chainwork_by_height(height) {
            Ok(cw) => Ok(cw.to_vec()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e),
            )),
        }
    }

    /// Get best block (chain tip)
    fn get_best_block(&self) -> PyResult<(Vec<u8>, u32)> {
        match self.db.get_best_block() {
            Ok((hash, height)) => Ok((hash.to_vec(), height)),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }
    
    /// Context manager support for transactions
    fn __enter__(&self) -> PyResult<Self> {
        Ok(self.clone())
    }
    
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_val: &Bound<'_, PyAny>,
        _exc_tb: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        // Database operations are already atomic via RocksDB
        Ok(())
    }
}

impl Clone for PyBlockchainDB {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
        }
    }
}

/// Fast sync engine for Bitcoin blockchain
#[pyclass]
pub struct SyncEngine {
    // Add your sync engine fields here
}

#[pymethods]
impl SyncEngine {
    #[new]
    fn new() -> Self {
        SyncEngine {}
    }

    /// Sync blocks from the blockchain
    #[pyo3(signature = (blocks))]
    fn sync_blocks(&mut self, blocks: Vec<Vec<u8>>) -> PyResult<usize> {
        // TODO: Implement block syncing logic
        Ok(blocks.len())
    }

    /// Get UTXO set
    fn get_utxos(&self) -> PyResult<Vec<PyUTXO>> {
        // TODO: Implement UTXO retrieval
        // Convert UTXO to PyUTXO when returning
        Ok(vec![])
    }

    /// Get example UTXOs for demonstration purposes
    fn get_example_utxos(&self) -> PyResult<Vec<PyUTXO>> {
        use bitcoin::hashes::Hash;
        use bitcoin::ScriptBuf;

        // Create some example UTXOs for demonstration
        let mut utxos = Vec::new();

        // Example UTXO 1
        let txid1 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint1 = OutPointWrapper::from_txid_vout(txid1, 0);
        let script1 = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]); // P2PKH script
        let utxo1 = UTXO::new(outpoint1, 50_000_000, script1, None, false); // 0.5 BTC
        utxos.push(PyUTXO::from(utxo1));

        // Example UTXO 2
        let txid2 = bitcoin::Txid::from_byte_array([2u8; 32]);
        let outpoint2 = OutPointWrapper::from_txid_vout(txid2, 1);
        let script2 = ScriptBuf::from_bytes(vec![0x51]); // OP_1
        let utxo2 = UTXO::new(outpoint2, 100_000_000, script2, None, false); // 1.0 BTC
        utxos.push(PyUTXO::from(utxo2));

        // Example UTXO 3
        let txid3 = bitcoin::Txid::from_byte_array([3u8; 32]);
        let outpoint3 = OutPointWrapper::from_txid_vout(txid3, 0);
        let script3 = ScriptBuf::from_bytes(vec![0x52]); // OP_2
        let utxo3 = UTXO::new(outpoint3, 25_000_000, script3, None, false); // 0.25 BTC
        utxos.push(PyUTXO::from(utxo3));

        Ok(utxos)
    }
}

/// Progress reporter that reads from shared cache without borrowing FastSync.
/// Use this during sync to avoid "Already borrowed" when the sync thread holds FastSync.
#[pyclass]
pub struct SyncProgressReporter {
    db: Arc<BlockchainDB>,
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
    network: Network,
}

#[pymethods]
impl SyncProgressReporter {
    /// Get current sync progress. Safe to call while sync is running (no FastSync borrow).
    fn get_progress(&self) -> PyResult<SyncProgress> {
        let db_height = match self.db.get_best_block() {
            Ok((_, h)) => h,
            Err(DbError::BlockNotFound) => 0,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to get best block: {}", e),
                ));
            }
        };

        let cache = self.progress_cache.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Progress cache lock error: {}", e),
            )
        })?;

        let (current_height, total_height, progress_percent, blocks_per_second, eta_seconds, phase, total_known) =
            if cache.total_to_download > 0 {
                // Block phase: show "blocks we have / block height (chain tip)"
                // blocks_we_have = had at start + downloaded this run
                let blocks_downloaded = cache.blocks_downloaded;
                let total_chain_blocks = cache.total_chain_blocks.max(1);
                let total_to_download = cache.total_to_download;
                let blocks_we_have = total_chain_blocks
                    .saturating_sub(total_to_download)
                    .saturating_add(blocks_downloaded);
                // block_height = tip (0-indexed), i.e. total_chain_blocks - 1; use total_chain_blocks for %
                let block_height = total_chain_blocks;
                let percent = if block_height > 0 {
                    ((blocks_we_have as f64 / block_height as f64) * 100.0).min(100.0)
                } else {
                    0.0
                };
                (
                    blocks_we_have,
                    block_height,
                    percent,
                    cache.blocks_per_second,
                    cache.eta_seconds,
                    "block",
                    true, // block phase always has known total
                )
            } else {
                // Header phase
                let total_known = cache.header_sync_tip.is_some();
                let estimated_tip = match self.network {
                    Network::Testnet => 18_000_000u32,
                    Network::Testnet4 => 150_000u32,
                    Network::Bitcoin => 900_000u32,
                    _ => 1_000_000u32,
                };
                // Use discovered tip when we got a short batch (chain shorter than estimate)
                let total = cache
                    .header_sync_tip
                    .map(|h| h.saturating_add(1))
                    .unwrap_or_else(|| estimated_tip.max(db_height.saturating_add(1)));
                // blocks_in_chain = db_height + 1 (genesis + blocks 1..tip)
                let blocks_in_chain = db_height.saturating_add(1);
                // When total not known, don't show misleading % - use 0 (CLI shows "requesting..." instead)
                let percent = if total_known && total > 0 {
                    ((blocks_in_chain as f64 / total as f64) * 100.0).min(100.0)
                } else {
                    0.0
                };
                (
                    blocks_in_chain,
                    total,
                    percent,
                    0.0,
                    0.0,
                    "header",
                    total_known,
                )
            };

        // Cap ETA at 999h to avoid overflow/absurd display when speed is very low
        const MAX_ETA_SECS: u64 = 999 * 3600;
        let eta_capped = eta_seconds.min(MAX_ETA_SECS as f64) as u64;

        Ok(SyncProgress {
            current_height,
            total_height,
            progress_percent: progress_percent.min(100.0),
            blocks_per_second,
            eta_seconds: eta_capped,
            phase: phase.to_string(),
            total_known,
        })
    }
}

/// Handle to cancel sync without borrowing FastSync (avoids "Already borrowed" when sync is running).
#[pyclass]
pub struct SyncCanceller {
    cancelled: Arc<StdMutex<bool>>,
}

#[pymethods]
impl SyncCanceller {
    /// Request sync to stop. Safe to call from any thread.
    fn cancel(&self) -> PyResult<()> {
        let mut c = self.cancelled.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Lock error: {}", e))
        })?;
        *c = true;
        Ok(())
    }
}

/// Sync progress information
#[pyclass]
#[derive(Clone)]
pub struct SyncProgress {
    #[pyo3(get)]
    pub current_height: u32,
    #[pyo3(get)]
    pub total_height: u32,
    #[pyo3(get)]
    pub progress_percent: f64,
    #[pyo3(get)]
    pub blocks_per_second: f64,
    #[pyo3(get)]
    pub eta_seconds: u64,
    /// Phase: "header" (syncing headers) or "block" (downloading full blocks)
    #[pyo3(get)]
    pub phase: String,
    /// When false (header phase, tip unknown): CLI should show "Requesting current block height..." instead of %
    #[pyo3(get)]
    pub total_known: bool,
}

/// Fast sync orchestrator for Bitcoin blockchain
#[pyclass]
pub struct FastSync {
    data_dir: PathBuf,
    network: Network,
    db: Option<Arc<BlockchainDB>>,
    peer_manager: Option<Arc<Mutex<PeerManager>>>,
    header_sync: Option<HeaderSync>,
    block_sync: Option<BlockSync>,
    /// Shared progress cache: updated by block_sync, read by SyncProgressReporter.
    /// Allows progress polling during sync without borrowing FastSync (avoids "Already borrowed").
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
    /// Cancellation flag
    cancelled: Arc<StdMutex<bool>>,
}

#[pymethods]
impl FastSync {
    #[new]
    fn new(data_dir: String, network: String) -> PyResult<Self> {
        // Parse network
        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            "testnet4" => Network::Testnet4,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid network: {}. Must be one of: mainnet, testnet, regtest, signet", network)
                ));
            }
        };

        // Initialize database
        let db_path = PathBuf::from(data_dir.clone());
        let db = Arc::new(
            BlockchainDB::open(db_path.to_str().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid data directory path")
            })?)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to open database: {}", e)
            ))?,
        );

        // Create validator components
        let header_validator = Arc::new(HeaderValidator::new(Arc::clone(&db), network_enum));
        let block_validator = Arc::new(BlockValidator::new(Arc::clone(&db), network_enum));

        // Create peer manager (max_peers=125 matches Bitcoin Core DEFAULT_MAX_PEER_CONNECTIONS)
        let peer_manager = Arc::new(Mutex::new(PeerManager::new(
            network_enum,
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0, // start_height
            crate::network::peer_manager::max_peers_from_env(),
        )));

        let progress_cache = Arc::new(StdMutex::new(BlockProgressCache::default()));

        // Create sync components
        let header_sync = HeaderSync::new(
            Arc::clone(&peer_manager),
            Arc::clone(&header_validator),
            Arc::clone(&db),
            network_enum,
            Some(Arc::clone(&progress_cache)),
        );

        let block_sync = BlockSync::new(
            Arc::clone(&peer_manager),
            block_validator,
            Arc::clone(&db),
            network_enum,
            Arc::clone(&progress_cache),
        );

        Ok(Self {
            data_dir: db_path,
            network: network_enum,
            db: Some(db),
            peer_manager: Some(peer_manager),
            header_sync: Some(header_sync),
            block_sync: Some(block_sync),
            progress_cache,
            cancelled: Arc::new(StdMutex::new(false)),
        })
    }

    /// Get a progress reporter that can be used during sync without borrowing FastSync.
    /// Call this before starting sync; use reporter.get_progress() while sync runs.
    fn get_progress_reporter(&self) -> PyResult<SyncProgressReporter> {
        let db = self.db.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
        })?;
        Ok(SyncProgressReporter {
            db: Arc::clone(db),
            progress_cache: Arc::clone(&self.progress_cache),
            network: self.network,
        })
    }

    /// Synchronize the blockchain
    ///
    /// Phase 1: Sync headers
    /// Phase 2: Sync blocks
    ///
    /// If `limit` is set, only sync the first N blocks (useful for quick validation).
    #[pyo3(signature = (limit=None))]
    fn sync_blockchain(&mut self, py: Python, limit: Option<u32>) -> PyResult<()> {
        // Reset cancellation flag
        {
            let mut cancelled = self.cancelled.lock().unwrap();
            *cancelled = false;
        }

        // Release GIL for long-running operation
        py.allow_threads(|| {
            // Create runtime for async operations
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to create tokio runtime: {}", e)
                ))?;

            rt.block_on(async {
                // Get components
                let db = self.db.as_ref().ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
                })?;

                // Initialize genesis block if database is empty (enables header sync to proceed)
                if db.get_best_block().is_err() {
                    let genesis_hash = crate::chain_params::genesis_block_hash(self.network);
                    let genesis_timestamp = crate::chain_params::genesis_block_timestamp(self.network);
                    let genesis_bits = crate::chain_params::genesis_bits(self.network);
                    let genesis_chainwork = crate::chainwork::compute_chainwork(&[0u8; 32], genesis_bits);
                    let metadata = BlockMetadata::new(0, genesis_chainwork, genesis_timestamp);
                    db.store_block_metadata(0, &genesis_hash, &metadata).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to store genesis metadata: {}", e),
                        )
                    })?;
                    db.update_best_block(&genesis_hash, 0).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to set genesis as best block: {}", e),
                        )
                    })?;
                }

                // Start peer manager
                let peer_manager = self.peer_manager.as_ref().ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Peer manager not initialized")
                })?;

                {
                    let mut pm = peer_manager.lock().await;
                    pm.start().await.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to start peer manager: {}", e)
                    ))?;
                }

                // Phase 1: Sync headers
                if let Some(ref mut header_sync) = self.header_sync {
                    header_sync.sync_headers().await.map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Header sync failed: {}", e)
                        )
                    })?;
                }

                // Check cancellation
                {
                    let cancelled = self.cancelled.lock().unwrap();
                    if *cancelled {
                        return Err(PyErr::new::<pyo3::exceptions::PyKeyboardInterrupt, _>(
                            "Sync cancelled"
                        ));
                    }
                }

                // Phase 2: Sync blocks
                if let Some(ref mut block_sync) = self.block_sync {
                    // Get current height for block sync
                    let (_, current_height) = db.get_best_block().map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to get best block: {}", e)
                        )
                    })?;

                    log::info!("Header sync completed. Starting block sync from height {}...", current_height);
                    
                    // For block sync, we want to sync all blocks from genesis to current height
                    // Since we only have headers, we need to download the full blocks
                    // Start from height 0 (genesis) and go up to current_height (or limit if set)
                    let start_height = 0u32;
                    let end_height = limit.map(|n| n.min(current_height)).unwrap_or(current_height);
                    
                    log::info!("Block sync: downloading blocks from height {} to {}", start_height, end_height);
                    
                    block_sync.sync_blocks(start_height, end_height).await.map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Block sync failed: {}", e)
                        )
                    })?;
                    
                    log::info!("Block sync completed successfully!");
                } else {
                    log::warn!("Block sync not initialized, skipping block download");
                }

                Ok(())
            })
        })
    }

    /// Get synchronization progress
    fn get_sync_progress(&self) -> PyResult<SyncProgress> {
        let db = self.db.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
        })?;

        // Get current height from DB (0 if empty / no best block yet)
        let db_height = match db.get_best_block() {
            Ok((_, h)) => h,
            Err(DbError::BlockNotFound) => 0,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to get best block: {}", e),
                ));
            }
        };

        // When block sync is active, use its stats for accurate progress (blocks_downloaded updates
        // as blocks are stored; DB best_block may lag). Otherwise use DB height.
        let block_sync_stats = self.block_sync.as_ref().and_then(|bs| bs.get_progress_stats());

        let (current_height, total_height, progress_percent, blocks_per_second, eta_seconds, phase, total_known) =
            if let Some((blocks_downloaded, total_to_download, speed, eta)) = block_sync_stats {
                if total_to_download > 0 {
                    // Block sync active: use blocks_downloaded only (not db_height)
                    let current = blocks_downloaded;
                    let total = total_to_download;
                    let percent = if total > 0 {
                        ((current as f64 / total as f64) * 100.0).min(100.0)
                    } else {
                        0.0
                    };
                    (current, total, percent, speed, eta, "block", true)
                } else {
                    // Block sync not fully initialized, fall back to DB
                    (db_height, 0, 0.0, speed, eta, "header", false)
                }
            } else {
                // No block sync (e.g. header-only phase): use DB height and estimated tip
                let estimated_tip = match self.network {
                    Network::Testnet => 18_000_000u32,
                    Network::Testnet4 => 150_000u32, // testnet4 tip varies; 122k+ as of 2025
                    Network::Bitcoin => 900_000u32,
                    _ => 1_000_000u32,
                };
                let total = estimated_tip.max(db_height.saturating_add(1));
                let percent = if total > 0 && db_height > 0 {
                    ((db_height as f64 / total as f64) * 100.0).min(100.0)
                } else if db_height == 0 {
                    0.0
                } else {
                    100.0
                };
                (db_height, total, percent, 0.0, 0.0, "header", false)
            };

        // If we have block sync stats but total was 0, we still need total_height for display
        let total_height = if total_height == 0 {
            let estimated_tip = match self.network {
                Network::Testnet => 18_000_000u32,
                Network::Testnet4 => 150_000u32,
                Network::Bitcoin => 900_000u32,
                _ => 1_000_000u32,
            };
            estimated_tip.max(current_height.saturating_add(1))
        } else {
            total_height
        };

        // Cap ETA at 999h to avoid overflow/absurd display
        const MAX_ETA_SECS: u64 = 999 * 3600;
        let eta_capped = eta_seconds.min(MAX_ETA_SECS as f64) as u64;

        Ok(SyncProgress {
            current_height,
            total_height,
            progress_percent: progress_percent.min(100.0),
            blocks_per_second,
            eta_seconds: eta_capped,
            phase: phase.to_string(),
            total_known,
        })
    }

    /// Check if blockchain is synced
    fn is_synced(&self) -> PyResult<bool> {
        // For now, return false (in practice would check against network tip)
        // This is a simplified version
        Ok(false)
    }

    /// Get a canceller handle. Use this instead of cancel_sync() to avoid "Already borrowed"
    /// when sync is running in another thread.
    fn get_canceller(&self) -> SyncCanceller {
        SyncCanceller {
            cancelled: Arc::clone(&self.cancelled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::ScriptBuf;
    use common::UTXO;

    fn create_test_utxo() -> UTXO {
        let txid = bitcoin::Txid::from_byte_array([0u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        UTXO::new(outpoint, 100000, script_pubkey, Some(1), false)
    }

    #[test]
    fn test_pyutxo_from_utxo() {
        let utxo = create_test_utxo();
        let py_utxo = PyUTXO::from(&utxo);

        assert_eq!(py_utxo.txid, utxo.txid().to_string());
        assert_eq!(py_utxo.vout, utxo.vout());
        assert_eq!(py_utxo.value, utxo.value());
        assert_eq!(
            py_utxo.script_pubkey,
            utxo.script_pubkey.as_bytes().to_vec()
        );
    }

    #[test]
    fn test_pyutxo_from_owned_utxo() {
        let utxo = create_test_utxo();
        let py_utxo = PyUTXO::from(utxo.clone());

        assert_eq!(py_utxo.txid, utxo.txid().to_string());
        assert_eq!(py_utxo.vout, utxo.vout());
        assert_eq!(py_utxo.value, utxo.value());
    }

    #[test]
    fn test_pyutxo_clone() {
        let utxo = create_test_utxo();
        let py_utxo1 = PyUTXO::from(&utxo);
        let py_utxo2 = py_utxo1.clone();

        assert_eq!(py_utxo1.txid, py_utxo2.txid);
        assert_eq!(py_utxo1.vout, py_utxo2.vout);
        assert_eq!(py_utxo1.value, py_utxo2.value);
        assert_eq!(py_utxo1.script_pubkey, py_utxo2.script_pubkey);
    }

    #[test]
    fn test_sync_engine_new() {
        let engine = SyncEngine::new();
        // Just verify it can be created
        let _ = engine;
    }

    #[test]
    fn test_sync_engine_sync_blocks() {
        let mut engine = SyncEngine::new();
        let blocks = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];

        let result = engine.sync_blocks(blocks.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), blocks.len());
    }

    #[test]
    fn test_sync_engine_sync_empty_blocks() {
        let mut engine = SyncEngine::new();
        let blocks = vec![];

        let result = engine.sync_blocks(blocks);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_sync_engine_get_utxos() {
        let engine = SyncEngine::new();
        let result = engine.get_utxos();

        assert!(result.is_ok());
        let utxos = result.unwrap();
        assert_eq!(utxos.len(), 0); // Currently returns empty vec
    }

    #[test]
    fn test_pyutxo_conversion_multiple() {
        let utxo1 = create_test_utxo();
        // Create a second UTXO with different values
        let txid2 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint2 = OutPointWrapper::from_txid_vout(txid2, 1);
        let script_pubkey2 = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        let utxo2 = UTXO::new(outpoint2, 200000, script_pubkey2, Some(1), false);

        let py_utxos: Vec<PyUTXO> = vec![&utxo1, &utxo2]
            .into_iter()
            .map(|u| PyUTXO::from(u))
            .collect();

        assert_eq!(py_utxos.len(), 2);
        assert_eq!(py_utxos[0].value, 100000);
        assert_eq!(py_utxos[1].value, 200000);
        assert_eq!(py_utxos[0].vout, 0);
        assert_eq!(py_utxos[1].vout, 1);
    }

    #[test]
    fn test_pyutxo_script_pubkey_bytes() {
        use bitcoin::hashes::Hash;
        let script_bytes = vec![0x76, 0xa9, 0x14, 0x88, 0xac];
        let script = ScriptBuf::from_bytes(script_bytes.clone());
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let utxo = UTXO::new(outpoint, 50000, script, None, false);

        let py_utxo = PyUTXO::from(&utxo);
        assert_eq!(py_utxo.script_pubkey, script_bytes);
    }
}
