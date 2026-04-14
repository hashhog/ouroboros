//! RocksDB database implementation for Bitcoin blockchain storage

use std::sync::Arc;

use bitcoin::OutPoint;
use bitcoin::hashes::Hash;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use thiserror::Error;

use common::{
    BitcoinDeserialize, BitcoinSerialize, BlockMetadata, BlockStatus, BlockWrapper, UTXO,
    SerializeError,
};

use crate::storage::schema::{
    decode_height, encode_block_hash, encode_height, encode_outpoint,
    get_column_families, meta_keys, BLOCK_INDEX_CF, BLOCKS_CF, CHAINSTATE_CF, META_CF, SPENT_CF,
    TX_INDEX_CF, UNDO_CF,
};
use crate::storage::undo::{BlockUndo, Coin, TxUndo};

/// Database error type
#[derive(Error, Debug)]
pub enum DbError {
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializeError),

    #[error("Block not found")]
    BlockNotFound,

    #[error("UTXO not found")]
    UtxoNotFound,

    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),

    #[error("Invalid data format: {0}")]
    InvalidData(String),
}

/// Result type for database operations
pub type Result<T> = std::result::Result<T, DbError>;

/// Blockchain database using RocksDB
pub struct BlockchainDB {
    db: Arc<DB>,
}

impl BlockchainDB {
    /// Attempt to repair a corrupted database at the given path.
    pub fn repair(path: &str) -> Result<()> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        DB::repair(&opts, path).map_err(DbError::RocksDb)
    }

    /// Open or create a new database at the given path
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Performance optimizations
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        opts.set_bloom_locality(10);
        opts.set_write_buffer_size(128 * 1024 * 1024); // 128MB (up from 64MB)
        opts.set_max_write_buffer_number(3);
        opts.set_min_write_buffer_number_to_merge(2);
        opts.set_target_file_size_base(128 * 1024 * 1024); // 128MB
        opts.set_max_bytes_for_level_base(512 * 1024 * 1024); // 512MB
        opts.set_max_open_files(512);
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.optimize_for_point_lookup(1024); // 1GB block cache (up from 10MB)

        // Create column family descriptors with optimized options
        let cf_opts = create_cf_options();
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = get_column_families()
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;

        Ok(Self { db: Arc::new(db) })
    }

    // ========== Block Storage Methods ==========

    /// Store a block in the database
    pub fn store_block(&self, block: &BlockWrapper) -> Result<()> {
        let hash = block.block_hash();
        let hash_bytes = encode_block_hash(&hash);

        // Serialize block
        let block_data = block.bitcoin_serialize()?;

        // Store in blocks column family
        let cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;
        self.db.put_cf(cf, hash_bytes, block_data)?;

        Ok(())
    }

    /// Store block metadata with block hash for height lookup
    pub fn store_block_metadata(&self, height: u32, hash: &[u8; 32], metadata: &BlockMetadata) -> Result<()> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);

        // Store as: [32-byte hash][BlockMetadata bytes]
        let metadata_bytes = metadata.to_bytes()
            .map_err(|e| DbError::Serialization(SerializeError::Encode(format!("{}", e))))?;
        let mut value = Vec::with_capacity(32 + metadata_bytes.len());
        value.extend_from_slice(hash);
        value.extend_from_slice(&metadata_bytes);

        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Get a block by its hash
    pub fn get_block(&self, hash: &[u8; 32]) -> Result<Option<BlockWrapper>> {
        let cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;

        match self.db.get_cf(cf, hash)? {
            Some(data) => {
                let (block, _) = BlockWrapper::bitcoin_deserialize(&data)
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize block: {}", e)))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Existence probe for a block body keyed by hash.
    ///
    /// Skips the `bitcoin_deserialize` on the value — important for callers
    /// that only need truthiness (e.g. validated-header scans in the Python
    /// sync loop). Uses `get_pinned_cf` so the value bytes are not copied
    /// into an owned `Vec<u8>`.
    pub fn has_block_hash(&self, hash: &[u8; 32]) -> Result<bool> {
        let cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;
        Ok(self.db.get_pinned_cf(cf, hash)?.is_some())
    }

    /// Get a block by its height
    ///
    /// Note: This requires storing the block hash when storing block metadata.
    /// We store it as a prefix in the BLOCK_INDEX_CF value: [32-byte hash][BlockMetadata bytes]
    pub fn get_block_by_height(&self, height: u32) -> Result<Option<BlockWrapper>> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                // First 32 bytes are the block hash, rest is BlockMetadata
                if data.len() < 32 {
                    return Err(DbError::InvalidData(
                        "Block index data too short".to_string(),
                    ));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data[0..32]);

                // Get block by hash
                self.get_block(&hash_bytes)
            }
            None => Ok(None),
        }
    }

    /// Get block hash by height (from header metadata)
    pub fn get_block_hash_by_height(&self, height: u32) -> Result<Option<[u8; 32]>> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                if data.len() < 32 {
                    return Err(DbError::InvalidData(
                        "Block index data too short".to_string(),
                    ));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data[0..32]);
                Ok(Some(hash_bytes))
            }
            None => Ok(None),
        }
    }

    /// Find the height of a block hash by searching backwards from max_height.
    /// Used for reorg detection: when headers don't connect, check if the peer's
    /// prev_blockhash exists in our chain (common ancestor).
    pub fn find_height_of_hash(&self, hash: &[u8; 32], max_height: u32) -> Result<Option<u32>> {
        for h in (0..=max_height).rev() {
            if let Ok(Some(stored_hash)) = self.get_block_hash_by_height(h) {
                if &stored_hash == hash {
                    return Ok(Some(h));
                }
            }
        }
        Ok(None)
    }

    // ========== Transaction Index Methods ==========

    /// Store a transaction's location in TX_INDEX_CF.
    ///
    /// Key: txid (32 bytes)
    /// Value: block_hash (32 bytes) || height (4 bytes LE) || tx_position (4 bytes LE)
    pub fn store_tx_index(
        &self,
        txid: &[u8; 32],
        block_hash: &[u8; 32],
        height: u32,
        tx_position: u32,
    ) -> Result<()> {
        let cf = self.db.cf_handle(TX_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(TX_INDEX_CF.to_string()))?;

        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(block_hash);
        value.extend_from_slice(&height.to_le_bytes());
        value.extend_from_slice(&tx_position.to_le_bytes());

        self.db.put_cf(cf, txid, &value)?;
        Ok(())
    }

    /// Look up a transaction's block location from TX_INDEX_CF.
    ///
    /// Returns `Some((block_hash, height, tx_position))` or `None`.
    pub fn get_tx_index(&self, txid: &[u8; 32]) -> Result<Option<([u8; 32], u32, u32)>> {
        let cf = self.db.cf_handle(TX_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(TX_INDEX_CF.to_string()))?;

        match self.db.get_cf(cf, txid)? {
            Some(data) => {
                if data.len() < 40 {
                    return Err(DbError::InvalidData(
                        format!("TX_INDEX data too short: {} bytes", data.len()),
                    ));
                }
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&data[0..32]);
                let height = u32::from_le_bytes(data[32..36].try_into().unwrap());
                let tx_position = u32::from_le_bytes(data[36..40].try_into().unwrap());
                Ok(Some((block_hash, height, tx_position)))
            }
            None => Ok(None),
        }
    }

    /// Delete a transaction's index entry (used during disconnect_block).
    pub fn delete_tx_index(&self, txid: &[u8; 32]) -> Result<()> {
        let cf = self.db.cf_handle(TX_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(TX_INDEX_CF.to_string()))?;
        self.db.delete_cf(cf, txid)?;
        Ok(())
    }

    // ========== UTXO Set Methods ==========

    /// Add a UTXO to the chainstate
    pub fn add_utxo(&self, outpoint: &OutPoint, utxo: &UTXO) -> Result<()> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        // Serialize UTXO
        let value = utxo.bitcoin_serialize()?;

        // Store in chainstate column family
        let cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        self.db.put_cf(cf, key, value)?;

        Ok(())
    }

    /// Spend a UTXO (remove from chainstate and store undo record in spent CF)
    ///
    /// The full serialized UTXO is stored in SPENT_CF so that
    /// `disconnect_block()` can restore it during a chain reorganization.
    ///
    /// SPENT_CF value format: `[32-byte spending_txid][serialized UTXO]`
    ///
    /// Returns the UTXO that was spent, or None if it didn't exist.
    pub fn spend_utxo(&self, outpoint: &OutPoint, spending_txid: &[u8; 32]) -> Result<Option<UTXO>> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let chainstate_cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        let spent_cf = self.db.cf_handle(SPENT_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(SPENT_CF.to_string()))?;

        // Get the raw UTXO bytes before removing — we need both the
        // deserialized struct (to return) and the raw bytes (for undo data).
        let utxo = match self.db.get_cf(chainstate_cf, &key)? {
            Some(data) => {
                let (utxo, _) = UTXO::bitcoin_deserialize(&data)
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize UTXO: {}", e)))?;
                Some((utxo, data))
            }
            None => None,
        };

        // Remove from chainstate
        self.db.delete_cf(chainstate_cf, &key)?;

        // Store full undo record: [spending_txid (32 bytes)][serialized UTXO]
        if let Some((ref _u, ref utxo_bytes)) = utxo {
            let mut undo_value = Vec::with_capacity(32 + utxo_bytes.len());
            undo_value.extend_from_slice(spending_txid);
            undo_value.extend_from_slice(utxo_bytes);
            self.db.put_cf(spent_cf, &key, &undo_value)?;
        }

        Ok(utxo.map(|(u, _)| u))
    }

    /// Retrieve an undo record from SPENT_CF.
    ///
    /// Returns `(spending_txid, UTXO)` if found.
    pub fn get_spent_utxo(&self, outpoint: &OutPoint) -> Result<Option<([u8; 32], UTXO)>> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let spent_cf = self.db.cf_handle(SPENT_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(SPENT_CF.to_string()))?;

        match self.db.get_cf(spent_cf, &key)? {
            Some(data) => {
                if data.len() < 33 {
                    return Err(DbError::InvalidData(
                        "Spent CF undo record too short".to_string(),
                    ));
                }
                let mut spending_txid = [0u8; 32];
                spending_txid.copy_from_slice(&data[..32]);
                let (utxo, _) = UTXO::bitcoin_deserialize(&data[32..])
                    .map_err(|e| DbError::InvalidData(
                        format!("Failed to deserialize undo UTXO: {}", e),
                    ))?;
                Ok(Some((spending_txid, utxo)))
            }
            None => Ok(None),
        }
    }

    /// Delete an undo record from SPENT_CF.
    pub fn delete_spent_record(&self, outpoint: &OutPoint) -> Result<()> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let spent_cf = self.db.cf_handle(SPENT_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(SPENT_CF.to_string()))?;
        self.db.delete_cf(spent_cf, &key)?;
        Ok(())
    }

    /// Delete a UTXO from chainstate without creating an undo record.
    ///
    /// Used by `disconnect_block()` to remove UTXOs created by the
    /// disconnected block.
    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        self.db.delete_cf(cf, &key)?;
        Ok(())
    }

    /// Get a UTXO by its outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UTXO>> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;

        match self.db.get_cf(cf, &key)? {
            Some(data) => {
                let (utxo, _) = UTXO::bitcoin_deserialize(&data)
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize UTXO: {}", e)))?;
                Ok(Some(utxo))
            }
            None => Ok(None),
        }
    }

    /// Check if a UTXO exists
    pub fn utxo_exists(&self, outpoint: &OutPoint) -> bool {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let cf = match self.db.cf_handle(CHAINSTATE_CF) {
            Some(cf) => cf,
            None => return false,
        };

        self.db.get_cf(cf, &key).map(|opt| opt.is_some()).unwrap_or(false)
    }

    /// Iterate all UTXOs in the chainstate (for address balance/scan).
    ///
    /// Returns a vector of (OutPoint, UTXO) pairs for the entire UTXO set.
    /// Used by snapshot dumping and balance scanning.
    pub fn iter_utxos(&self) -> Result<Vec<(OutPoint, UTXO)>> {
        let cf = self.db
            .cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;

        let mut utxos = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| DbError::RocksDb(e))?;
            if key.len() == 36 {
                if let Ok((utxo, _)) = UTXO::bitcoin_deserialize(&value) {
                    // Decode outpoint from key
                    let mut key_arr = [0u8; 36];
                    key_arr.copy_from_slice(&key);
                    let (txid_bytes, vout) = crate::storage::schema::decode_outpoint(&key_arr);
                    let txid = bitcoin::Txid::from_byte_array(txid_bytes);
                    let outpoint = OutPoint { txid, vout };
                    utxos.push((outpoint, utxo));
                }
            }
        }

        Ok(utxos)
    }

    /// Count the number of UTXOs in the chainstate.
    pub fn utxo_count(&self) -> Result<u64> {
        let cf = self.db
            .cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;

        let mut count = 0u64;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for item in iter {
            if item.is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Delete all entries from the chainstate (UTXO set) column family.
    ///
    /// Uses RocksDB `delete_range` to mark everything as deleted.  The actual
    /// disk space is reclaimed lazily by background compaction (no explicit
    /// compaction is triggered so the call returns quickly).
    pub fn clear_chainstate(&self) -> Result<()> {
        let cf = self.db
            .cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;

        // Delete the entire key range: [0x00..00] to [0xFF..FF]
        let start = [0u8; 36];
        let end = [0xFFu8; 36];
        self.db.delete_range_cf(cf, &start, &end)?;
        // delete_range is exclusive on the end key, so delete the max key too
        self.db.delete_cf(cf, &end)?;

        Ok(())
    }

    /// Expose the inner Arc<DB> for direct WriteBatch operations (e.g. bulk import).
    pub fn raw_db(&self) -> &Arc<DB> {
        &self.db
    }

    // ========== Chain State Methods ==========

    /// Get the best block hash and height
    pub fn get_best_block(&self) -> Result<([u8; 32], u32)> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;

        // Get best block hash
        let hash = match self.db.get_cf(cf, meta_keys::BEST_BLOCK_HASH)? {
            Some(data) => {
                if data.len() != 32 {
                    return Err(DbError::InvalidData(format!(
                        "Invalid block hash length: {}",
                        data.len()
                    )));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data);
                hash_bytes
            }
            None => return Err(DbError::BlockNotFound),
        };

        // Get best block height
        let height = match self.db.get_cf(cf, meta_keys::BEST_HEIGHT)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(DbError::InvalidData(format!(
                        "Invalid height length: {}",
                        data.len()
                    )));
                }
                let height_bytes: [u8; 4] = data.try_into().unwrap();
                decode_height(&height_bytes)
            }
            None => return Err(DbError::BlockNotFound),
        };

        Ok((hash, height))
    }

    /// Update the best block hash and height
    pub fn update_best_block(&self, hash: &[u8; 32], height: u32) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;

        // Store block hash
        self.db.put_cf(cf, meta_keys::BEST_BLOCK_HASH, hash)?;

        // Store height
        let height_bytes = encode_height(height);
        self.db.put_cf(cf, meta_keys::BEST_HEIGHT, height_bytes)?;

        Ok(())
    }

    /// Get chainwork at a given height (from block metadata).
    /// Returns chainwork as 32-byte big-endian, or zeros if not found.
    pub fn get_chainwork_by_height(&self, height: u32) -> Result<[u8; 32]> {
        match self.get_block_metadata(height)? {
            Some(meta) => Ok(meta.chainwork),
            None => Ok([0u8; 32]),
        }
    }

    /// Get block metadata by height
    pub fn get_block_metadata(&self, height: u32) -> Result<Option<BlockMetadata>> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);

        match self.db.get_cf(cf, key)? {
            Some(data) => {
                // First 32 bytes are the block hash, rest is BlockMetadata
                if data.len() < 32 {
                    return Err(DbError::InvalidData(
                        "Block index data too short".to_string(),
                    ));
                }
                let metadata = BlockMetadata::from_bytes(&data[32..])
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize metadata: {}", e)))?;
                Ok(Some(metadata))
            }
            None => Ok(None),
        }
    }

    // ========== Pruning Methods ==========

    /// Delete the raw block data for blocks at heights in [from_height, to_height].
    ///
    /// The block index (height -> hash + metadata) is preserved so the node
    /// can still serve headers and knows which blocks existed.  Only the full
    /// serialised block bytes in BLOCKS_CF are removed.
    ///
    /// This mirrors Bitcoin Core's `PruneOneBlockFile()` which deletes the
    /// block body but keeps the block-index entry (CBlockIndex).
    ///
    /// Returns the number of blocks actually pruned.
    pub fn prune_blocks_range(&self, from_height: u32, to_height: u32) -> Result<u32> {
        let blocks_cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;
        let index_cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;

        let mut removed = 0u32;

        for height in from_height..=to_height {
            let key = encode_height(height);
            // Look up the block hash from the index
            if let Some(data) = self.db.get_cf(index_cf, &key)? {
                if data.len() >= 32 {
                    let hash = &data[0..32];
                    // Delete block body from BLOCKS_CF (if it still exists)
                    if self.db.get_cf(blocks_cf, hash)?.is_some() {
                        self.db.delete_cf(blocks_cf, hash)?;
                        removed += 1;
                    }
                }
            }
        }

        // Persist the new prune height
        if removed > 0 {
            self.set_prune_height(to_height + 1)?;
        }

        Ok(removed)
    }

    /// Delete the raw block data for a single block height.
    /// Returns true if a block was actually deleted.
    pub fn prune_block_at_height(&self, height: u32) -> Result<bool> {
        let n = self.prune_blocks_range(height, height)?;
        Ok(n > 0)
    }

    /// Get the lowest height whose block data has NOT been pruned.
    /// Returns 0 if pruning has never run.
    pub fn get_prune_height(&self) -> Result<u32> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        match self.db.get_cf(cf, meta_keys::PRUNE_HEIGHT)? {
            Some(data) if data.len() == 4 => {
                Ok(u32::from_le_bytes(data.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Set the lowest unpruned height.
    fn set_prune_height(&self, height: u32) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        self.db.put_cf(cf, meta_keys::PRUNE_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }

    /// Check whether the block body exists for a given height.
    /// Returns false for pruned blocks (index exists but body doesn't).
    pub fn has_block_data(&self, height: u32) -> Result<bool> {
        let blocks_cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;
        let index_cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;

        let key = encode_height(height);
        match self.db.get_cf(index_cf, &key)? {
            Some(data) if data.len() >= 32 => {
                let hash = &data[0..32];
                Ok(self.db.get_cf(blocks_cf, hash)?.is_some())
            }
            _ => Ok(false),
        }
    }

    /// Estimate the total size in bytes of all block data in BLOCKS_CF.
    ///
    /// Uses RocksDB's SST file metadata for a fast (approximate) answer.
    /// Falls back to iterating if the property is unavailable.
    pub fn estimate_blocks_size(&self) -> Result<u64> {
        let cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;

        // Try the fast RocksDB property first
        if let Ok(Some(size_str)) = self.db.property_value_cf(cf, "rocksdb.estimate-live-data-size") {
            if let Ok(size) = size_str.parse::<u64>() {
                return Ok(size);
            }
        }

        // Fallback: iterate and sum value lengths
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut total: u64 = 0;
        for item in iter {
            let (_key, value) = item.map_err(DbError::RocksDb)?;
            total += value.len() as u64;
        }
        Ok(total)
    }

    // ========== Two-Phase Commit (Crash Recovery) ==========

    /// Write the HEAD_BLOCKS marker to META_CF (Phase 1 of apply_block).
    ///
    /// Format: `[old_tip_hash (32)][old_tip_height (4 LE)][new_block_hash (32)][new_height (4 LE)]`
    ///
    /// This marker tells `recover_from_crash()` that an apply is in progress.
    /// It is deleted once BEST_BLOCK_HASH / BEST_HEIGHT are updated (Phase 2).
    pub fn write_head_blocks(
        &self,
        old_tip_hash: &[u8; 32],
        old_tip_height: u32,
        new_block_hash: &[u8; 32],
        new_height: u32,
    ) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;

        let mut value = Vec::with_capacity(72);
        value.extend_from_slice(old_tip_hash);
        value.extend_from_slice(&old_tip_height.to_le_bytes());
        value.extend_from_slice(new_block_hash);
        value.extend_from_slice(&new_height.to_le_bytes());

        self.db.put_cf(cf, meta_keys::HEAD_BLOCKS, &value)?;
        Ok(())
    }

    /// Delete the HEAD_BLOCKS marker (Phase 2 complete — apply succeeded).
    pub fn delete_head_blocks(&self) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        self.db.delete_cf(cf, meta_keys::HEAD_BLOCKS)?;
        Ok(())
    }

    /// Read the HEAD_BLOCKS marker, if present.
    ///
    /// Returns `Some((old_tip_hash, old_tip_height, new_block_hash, new_height))`
    /// when a crash occurred mid-apply, or `None` if the database is clean.
    pub fn get_head_blocks(&self) -> Result<Option<([u8; 32], u32, [u8; 32], u32)>> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;

        match self.db.get_cf(cf, meta_keys::HEAD_BLOCKS)? {
            Some(data) => {
                if data.len() < 72 {
                    return Err(DbError::InvalidData(
                        format!("HEAD_BLOCKS data too short: {} bytes", data.len()),
                    ));
                }
                let mut old_tip_hash = [0u8; 32];
                old_tip_hash.copy_from_slice(&data[0..32]);
                let old_tip_height = u32::from_le_bytes(
                    data[32..36].try_into().unwrap(),
                );
                let mut new_block_hash = [0u8; 32];
                new_block_hash.copy_from_slice(&data[36..68]);
                let new_height = u32::from_le_bytes(
                    data[68..72].try_into().unwrap(),
                );
                Ok(Some((old_tip_hash, old_tip_height, new_block_hash, new_height)))
            }
            None => Ok(None),
        }
    }

    /// Check for and recover from a mid-apply crash.
    ///
    /// Called during database open.  If HEAD_BLOCKS exists, a crash happened
    /// between Phase 1 (UTXO mutations started) and Phase 2 (chain tip
    /// updated).  We disconnect the partially-applied block to restore the
    /// UTXO set to the old tip, then delete the marker.
    ///
    /// Returns `true` if a recovery was performed, `false` otherwise.
    pub fn recover_from_crash(&self) -> Result<bool> {
        let head = match self.get_head_blocks()? {
            Some(h) => h,
            None => return Ok(false),
        };

        let (old_tip_hash, old_tip_height, _new_block_hash, new_height) = head;

        log::warn!(
            "HEAD_BLOCKS marker found — crash detected during apply of block at height {}. \
             Rolling back to previous tip (height {}).",
            new_height,
            old_tip_height,
        );

        // Attempt to disconnect the partially-applied block.
        // Even if the block was only partially applied (some UTXOs modified),
        // disconnect_block_at_height will do its best — missing undo records
        // are logged as warnings.
        match self.disconnect_block_at_height(new_height) {
            Ok(_) => {
                log::info!("Successfully rolled back partial block at height {}", new_height);
            }
            Err(e) => {
                // If the block wasn't even stored (crash very early), just
                // reset the tip directly.
                log::warn!(
                    "Could not disconnect block at height {} ({}) — resetting tip directly",
                    new_height, e,
                );
                self.update_best_block(&old_tip_hash, old_tip_height)?;
            }
        }

        // Delete the HEAD_BLOCKS marker — database is now clean.
        self.delete_head_blocks()?;

        log::info!("Crash recovery complete. Chain tip: height {}", old_tip_height);
        Ok(true)
    }

    // ========== Undo Data Methods ==========

    /// Store undo data for a block.
    ///
    /// The undo data contains all UTXOs spent by the block's transactions,
    /// allowing the block to be disconnected during a chain reorganization.
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `block_undo` - Undo data for the block
    /// * `prev_block_hash` - Hash of the previous block (used for checksum)
    pub fn store_block_undo(
        &self,
        height: u32,
        block_undo: &BlockUndo,
        prev_block_hash: &[u8; 32],
    ) -> Result<()> {
        let cf = self.db.cf_handle(UNDO_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(UNDO_CF.to_string()))?;

        let key = encode_height(height);
        let undo_data = block_undo.serialize();
        let checksum = block_undo.compute_checksum(prev_block_hash);

        // Value: [undo_data][32-byte checksum]
        let mut value = Vec::with_capacity(undo_data.len() + 32);
        value.extend(undo_data);
        value.extend_from_slice(&checksum);

        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Get undo data for a block.
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `prev_block_hash` - Hash of the previous block (used to verify checksum)
    ///
    /// # Returns
    /// The BlockUndo data, or an error if not found or checksum mismatch.
    pub fn get_block_undo(
        &self,
        height: u32,
        prev_block_hash: &[u8; 32],
    ) -> Result<BlockUndo> {
        let cf = self.db.cf_handle(UNDO_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(UNDO_CF.to_string()))?;

        let key = encode_height(height);
        let data = self.db.get_cf(cf, key)?
            .ok_or(DbError::BlockNotFound)?;

        if data.len() < 32 {
            return Err(DbError::InvalidData(
                "Undo data too short (missing checksum)".to_string()
            ));
        }

        // Split undo data and checksum
        let undo_bytes = &data[..data.len() - 32];
        let mut stored_checksum = [0u8; 32];
        stored_checksum.copy_from_slice(&data[data.len() - 32..]);

        // Deserialize
        let (block_undo, _) = BlockUndo::deserialize(undo_bytes)
            .map_err(|e| DbError::InvalidData(format!("Failed to deserialize undo: {}", e)))?;

        // Verify checksum
        if !block_undo.verify_checksum(prev_block_hash, &stored_checksum) {
            return Err(DbError::InvalidData("Undo data checksum mismatch".to_string()));
        }

        Ok(block_undo)
    }

    /// Delete undo data for a block.
    pub fn delete_block_undo(&self, height: u32) -> Result<()> {
        let cf = self.db.cf_handle(UNDO_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(UNDO_CF.to_string()))?;

        let key = encode_height(height);
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Check if undo data exists for a block.
    pub fn has_block_undo(&self, height: u32) -> Result<bool> {
        let cf = self.db.cf_handle(UNDO_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(UNDO_CF.to_string()))?;

        let key = encode_height(height);
        Ok(self.db.get_cf(cf, key)?.is_some())
    }

    /// Build and store undo data for a block during connect_block.
    ///
    /// This should be called AFTER the UTXO set has been updated (spent UTXOs
    /// moved to SPENT_CF). It reads the undo data from SPENT_CF and stores
    /// it in UNDO_CF.
    ///
    /// # Arguments
    /// * `block` - The block being connected
    /// * `height` - Block height
    /// * `prev_block_hash` - Hash of the previous block
    pub fn build_and_store_undo_data(
        &self,
        block: &BlockWrapper,
        height: u32,
        prev_block_hash: &[u8; 32],
    ) -> Result<()> {
        let inner = block.inner();
        let mut tx_undo_list = Vec::new();

        // Skip coinbase (index 0) - it has no inputs to undo
        for tx in inner.txdata.iter().skip(1) {
            let mut prev_outputs = Vec::new();

            for input in &tx.input {
                let outpoint = input.previous_output;

                // Get the spent UTXO data from SPENT_CF
                if let Some((_spending_txid, utxo)) = self.get_spent_utxo(&outpoint)? {
                    prev_outputs.push(Coin::new(
                        utxo.amount,
                        utxo.script_pubkey.clone(),
                        utxo.height.unwrap_or(0),
                        utxo.is_coinbase,
                    ));
                } else {
                    // UTXO not found in SPENT_CF - this can happen if the block
                    // wasn't fully processed. Log a warning but continue.
                    log::warn!(
                        "Missing spent UTXO for input {:?}:{} at height {}",
                        outpoint.txid, outpoint.vout, height
                    );
                    // Store a placeholder with zero values
                    prev_outputs.push(Coin::new(
                        0,
                        bitcoin::ScriptBuf::new(),
                        0,
                        false,
                    ));
                }
            }

            tx_undo_list.push(TxUndo::with_outputs(prev_outputs));
        }

        let block_undo = BlockUndo::with_tx_undo(tx_undo_list);
        self.store_block_undo(height, &block_undo, prev_block_hash)?;

        Ok(())
    }

    // ========== Disconnect / Reorg Methods ==========

    /// Disconnect the block at the given height — reverse all UTXO changes.
    ///
    /// This method uses the structured undo data from UNDO_CF when available,
    /// falling back to SPENT_CF for backward compatibility.
    ///
    /// 1. Fetch the block at `height`.
    /// 2. Try to load BlockUndo from UNDO_CF.
    /// 3. For each transaction (reverse order):
    ///    a. Delete outputs (UTXOs created by this block) from chainstate.
    ///    b. Restore inputs (UTXOs spent by this block) from undo data.
    /// 4. Delete the undo data.
    /// 5. Update BEST_BLOCK_HASH / BEST_HEIGHT to the previous block.
    ///
    /// Returns the hash of the disconnected block on success.
    pub fn disconnect_block_at_height(&self, height: u32) -> Result<[u8; 32]> {
        // Fetch block
        let block = self.get_block_by_height(height)?
            .ok_or(DbError::BlockNotFound)?;
        let inner = block.inner();
        let block_hash = *block.block_hash().as_byte_array();
        let prev_block_hash = *inner.header.prev_blockhash.as_byte_array();

        // Try to load undo data from UNDO_CF
        let block_undo = self.get_block_undo(height, &prev_block_hash).ok();

        // Process transactions in reverse order
        for (tx_idx, tx) in inner.txdata.iter().enumerate().rev() {
            let txid = tx.compute_txid();

            // 1. Delete outputs created by this block
            for vout in 0..tx.output.len() {
                let outpoint = bitcoin::OutPoint { txid, vout: vout as u32 };
                self.delete_utxo(&outpoint)?;
            }

            // 2. Restore inputs spent by this block
            if !tx.is_coinbase() {
                // tx_undo_idx: coinbase is tx 0, so tx at index N (N >= 1) maps to tx_undo[N-1]
                let tx_undo_idx = tx_idx - 1;

                for (input_idx, input) in tx.input.iter().enumerate() {
                    let outpoint = input.previous_output;

                    // Try undo data from UNDO_CF first, fall back to SPENT_CF
                    let restored = if let Some(ref undo) = block_undo {
                        if let Some(tx_undo) = undo.tx_undo.get(tx_undo_idx) {
                            if let Some(coin) = tx_undo.prev_outputs.get(input_idx) {
                                // Reconstruct UTXO from Coin
                                let utxo = UTXO::new(
                                    common::OutPointWrapper::new(outpoint),
                                    coin.value,
                                    coin.script_pubkey.clone(),
                                    Some(coin.height),
                                    coin.is_coinbase,
                                );
                                self.add_utxo(&outpoint, &utxo)?;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !restored {
                        // Fall back to SPENT_CF
                        if let Some((_spending_txid, utxo)) = self.get_spent_utxo(&outpoint)? {
                            self.add_utxo(&outpoint, &utxo)?;
                        } else {
                            log::warn!(
                                "Missing undo data for input {:?}:{} at height {}",
                                outpoint.txid, outpoint.vout, height
                            );
                        }
                    }

                    // Clean up SPENT_CF record
                    self.delete_spent_record(&outpoint)?;
                }
            }
        }

        // Delete the undo data
        let _ = self.delete_block_undo(height);

        // Update chain tip to previous block
        if height > 0 {
            self.update_best_block(&prev_block_hash, height - 1)?;
        }

        Ok(block_hash)
    }

    // ========== Batch Operations ==========

    /// Create a new write batch
    pub fn create_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Apply a write batch atomically
    pub fn apply_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db.write(batch)?;
        Ok(())
    }

    // ========== Batch-aware write methods for connect_block ==========

    /// Add a UTXO to the chainstate via WriteBatch (no individual write).
    pub fn add_utxo_batch(&self, batch: &mut WriteBatch, outpoint: &OutPoint, utxo: &UTXO) -> Result<()> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);
        let value = utxo.bitcoin_serialize()?;
        let cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        batch.put_cf(cf, key, value);
        Ok(())
    }

    /// Spend a UTXO via WriteBatch: reads the UTXO from DB, queues delete + undo writes.
    /// Returns the spent UTXO (or None if it didn't exist).
    pub fn spend_utxo_batch(
        &self,
        batch: &mut WriteBatch,
        outpoint: &OutPoint,
        spending_txid: &[u8; 32],
    ) -> Result<Option<UTXO>> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let chainstate_cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        let spent_cf = self.db.cf_handle(SPENT_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(SPENT_CF.to_string()))?;

        let utxo = match self.db.get_cf(chainstate_cf, &key)? {
            Some(data) => {
                let (utxo, _) = UTXO::bitcoin_deserialize(&data)
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize UTXO: {}", e)))?;
                Some((utxo, data))
            }
            None => None,
        };

        // Queue delete from chainstate
        batch.delete_cf(chainstate_cf, &key);

        // Queue undo record
        if let Some((ref _u, ref utxo_bytes)) = utxo {
            let mut undo_value = Vec::with_capacity(32 + utxo_bytes.len());
            undo_value.extend_from_slice(spending_txid);
            undo_value.extend_from_slice(utxo_bytes);
            batch.put_cf(spent_cf, &key, &undo_value);
        }

        Ok(utxo.map(|(u, _)| u))
    }

    /// Store a transaction index entry via WriteBatch.
    pub fn store_tx_index_batch(
        &self,
        batch: &mut WriteBatch,
        txid: &[u8; 32],
        block_hash: &[u8; 32],
        height: u32,
        tx_position: u32,
    ) -> Result<()> {
        let cf = self.db.cf_handle(TX_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(TX_INDEX_CF.to_string()))?;
        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(block_hash);
        value.extend_from_slice(&height.to_le_bytes());
        value.extend_from_slice(&tx_position.to_le_bytes());
        batch.put_cf(cf, txid, &value);
        Ok(())
    }

    /// Store a block via WriteBatch.
    pub fn store_block_batch(&self, batch: &mut WriteBatch, block: &BlockWrapper) -> Result<()> {
        let hash = block.block_hash();
        let hash_bytes = encode_block_hash(&hash);
        let block_data = block.bitcoin_serialize()?;
        let cf = self.db.cf_handle(BLOCKS_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCKS_CF.to_string()))?;
        batch.put_cf(cf, hash_bytes, block_data);
        Ok(())
    }

    /// Store block metadata via WriteBatch.
    pub fn store_block_metadata_batch(
        &self,
        batch: &mut WriteBatch,
        height: u32,
        hash: &[u8; 32],
        metadata: &BlockMetadata,
    ) -> Result<()> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);
        let metadata_bytes = metadata.to_bytes()
            .map_err(|e| DbError::Serialization(SerializeError::Encode(format!("{}", e))))?;
        let mut value = Vec::with_capacity(32 + metadata_bytes.len());
        value.extend_from_slice(hash);
        value.extend_from_slice(&metadata_bytes);
        batch.put_cf(cf, key, value);
        Ok(())
    }

    /// Update best block hash and height via WriteBatch.
    pub fn update_best_block_batch(&self, batch: &mut WriteBatch, hash: &[u8; 32], height: u32) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        batch.put_cf(cf, meta_keys::BEST_BLOCK_HASH, hash);
        let height_bytes = encode_height(height);
        batch.put_cf(cf, meta_keys::BEST_HEIGHT, height_bytes);
        Ok(())
    }

    /// Write HEAD_BLOCKS marker via WriteBatch.
    pub fn write_head_blocks_batch(
        &self,
        batch: &mut WriteBatch,
        old_tip_hash: &[u8; 32],
        old_tip_height: u32,
        new_block_hash: &[u8; 32],
        new_height: u32,
    ) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        let mut value = Vec::with_capacity(72);
        value.extend_from_slice(old_tip_hash);
        value.extend_from_slice(&old_tip_height.to_le_bytes());
        value.extend_from_slice(new_block_hash);
        value.extend_from_slice(&new_height.to_le_bytes());
        batch.put_cf(cf, meta_keys::HEAD_BLOCKS, &value);
        Ok(())
    }

    /// Delete HEAD_BLOCKS marker via WriteBatch.
    pub fn delete_head_blocks_batch(&self, batch: &mut WriteBatch) -> Result<()> {
        let cf = self.db.cf_handle(META_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(META_CF.to_string()))?;
        batch.delete_cf(cf, meta_keys::HEAD_BLOCKS);
        Ok(())
    }

    // ========== Block Invalidation Methods ==========

    /// Update the status flags of a block at a given height.
    ///
    /// This persists the block's validity state (including BLOCK_FAILED_VALID
    /// and BLOCK_FAILED_CHILD flags) to disk.
    pub fn update_block_status(&self, height: u32, status: common::BlockStatus) -> Result<()> {
        let cf = self.db.cf_handle(BLOCK_INDEX_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(BLOCK_INDEX_CF.to_string()))?;
        let key = encode_height(height);

        // Get existing data
        let data = self.db.get_cf(cf, &key)?
            .ok_or(DbError::BlockNotFound)?;

        if data.len() < 32 {
            return Err(DbError::InvalidData("Block index data too short".to_string()));
        }

        // Extract hash and metadata
        let hash = &data[0..32];
        let mut metadata = BlockMetadata::from_bytes(&data[32..])
            .map_err(|e| DbError::InvalidData(format!("Failed to deserialize metadata: {}", e)))?;

        // Update status
        metadata.status = status;

        // Rewrite the entry
        let metadata_bytes = metadata.to_bytes()
            .map_err(|e| DbError::Serialization(SerializeError::Encode(format!("{}", e))))?;
        let mut value = Vec::with_capacity(32 + metadata_bytes.len());
        value.extend_from_slice(hash);
        value.extend_from_slice(&metadata_bytes);

        self.db.put_cf(cf, &key, &value)?;
        Ok(())
    }

    /// Mark a block as invalid (BLOCK_FAILED_VALID flag).
    ///
    /// This is called when `invalidateblock` RPC is invoked. The block and all
    /// its descendants will be marked invalid and excluded from chain selection.
    pub fn mark_block_invalid(&self, height: u32) -> Result<()> {
        if let Some(mut metadata) = self.get_block_metadata(height)? {
            metadata.status.set_failed_valid();
            self.update_block_status(height, metadata.status)?;
        }
        Ok(())
    }

    /// Mark a block as having an invalid ancestor (BLOCK_FAILED_CHILD flag).
    ///
    /// This is called on descendants of an invalidated block.
    pub fn mark_block_failed_child(&self, height: u32) -> Result<()> {
        if let Some(mut metadata) = self.get_block_metadata(height)? {
            metadata.status.set_failed_child();
            self.update_block_status(height, metadata.status)?;
        }
        Ok(())
    }

    /// Clear all failure flags from a block.
    ///
    /// This is called when `reconsiderblock` RPC is invoked to make a
    /// previously-invalidated block eligible for chain selection again.
    pub fn clear_block_invalid(&self, height: u32) -> Result<()> {
        if let Some(mut metadata) = self.get_block_metadata(height)? {
            metadata.status.clear_failed();
            self.update_block_status(height, metadata.status)?;
        }
        Ok(())
    }

    /// Check if a block at a given height is marked as invalid.
    pub fn is_block_invalid(&self, height: u32) -> Result<bool> {
        match self.get_block_metadata(height)? {
            Some(metadata) => Ok(metadata.is_invalid()),
            None => Ok(false),
        }
    }

    /// Invalidate a block and all its descendants.
    ///
    /// If the block is in the active chain, disconnects blocks back to the
    /// invalid block's parent.
    ///
    /// Returns the height of the new chain tip after invalidation.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block to invalidate
    ///
    /// # Reference
    /// Bitcoin Core: validation.cpp `InvalidateBlock()`
    pub fn invalidate_block(&self, block_hash: &[u8; 32]) -> Result<u32> {
        // Find the block by hash
        let (best_hash, best_height) = self.get_best_block()?;

        // Search for the block by scanning the index
        let target_height = self.find_height_of_hash(block_hash, best_height)?
            .ok_or_else(|| DbError::InvalidData(format!(
                "Block {} not found in index",
                hex::encode(block_hash)
            )))?;

        // Cannot invalidate genesis block
        if target_height == 0 {
            return Err(DbError::InvalidData("Cannot invalidate genesis block".to_string()));
        }

        log::info!(
            "Invalidating block at height {} (hash: {})",
            target_height,
            hex::encode(block_hash)
        );

        // Check if block is in the active chain
        let is_in_active_chain = if let Some(chain_hash) = self.get_block_hash_by_height(target_height)? {
            &chain_hash == block_hash
        } else {
            false
        };

        // If in active chain, disconnect blocks from tip down to target
        let new_tip_height = if is_in_active_chain {
            // Disconnect blocks from best_height down to target_height
            for height in (target_height..=best_height).rev() {
                log::debug!("Disconnecting block at height {}", height);
                self.disconnect_block_at_height(height)?;
            }
            // New tip is parent of invalidated block
            target_height.saturating_sub(1)
        } else {
            // Block not in active chain, just mark it invalid
            best_height
        };

        // Mark the target block as BLOCK_FAILED_VALID
        self.mark_block_invalid(target_height)?;

        // Mark all descendants as BLOCK_FAILED_CHILD
        // We need to scan all blocks after target_height
        for height in (target_height + 1)..=best_height {
            // Check if this block descends from the invalidated block
            // by checking if its prev_blockhash eventually leads to target
            if self.block_descends_from(height, target_height, block_hash)? {
                self.mark_block_failed_child(height)?;
                log::debug!("Marked block at height {} as BLOCK_FAILED_CHILD", height);
            }
        }

        log::info!(
            "Block invalidation complete. New chain tip height: {}",
            new_tip_height
        );

        Ok(new_tip_height)
    }

    /// Check if a block at `height` descends from a block at `ancestor_height` with `ancestor_hash`.
    fn block_descends_from(
        &self,
        height: u32,
        ancestor_height: u32,
        ancestor_hash: &[u8; 32],
    ) -> Result<bool> {
        if height <= ancestor_height {
            return Ok(false);
        }

        // Get the block at `height` and walk back to `ancestor_height`
        let mut current_height = height;
        while current_height > ancestor_height {
            if let Some(block) = self.get_block_by_height(current_height)? {
                let prev_hash = *block.inner().header.prev_blockhash.as_byte_array();
                current_height -= 1;
                // Check if we've reached the ancestor
                if current_height == ancestor_height {
                    return Ok(&prev_hash == ancestor_hash);
                }
            } else {
                // Block not found, can't determine ancestry
                return Ok(false);
            }
        }
        Ok(false)
    }

    /// Reconsider a previously-invalidated block.
    ///
    /// Removes the invalid flag from the block and its descendants/ancestors,
    /// allowing them to be considered for chain selection again. If the
    /// reconsidered chain has more work than the current chain, the node will
    /// switch to it.
    ///
    /// Returns the height of the chain tip after reconsideration (may change
    /// if the reconsidered chain is best).
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block to reconsider
    ///
    /// # Reference
    /// Bitcoin Core: rpc/blockchain.cpp `ReconsiderBlock()` and
    /// validation.cpp `ResetBlockFailureFlags()`
    pub fn reconsider_block(&self, block_hash: &[u8; 32]) -> Result<u32> {
        let (best_hash, best_height) = self.get_best_block()?;

        // Find the block by hash
        let target_height = self.find_height_of_hash(block_hash, best_height + 1000)?
            .ok_or_else(|| DbError::InvalidData(format!(
                "Block {} not found in index",
                hex::encode(block_hash)
            )))?;

        log::info!(
            "Reconsidering block at height {} (hash: {})",
            target_height,
            hex::encode(block_hash)
        );

        // Clear failure flags on the target block
        self.clear_block_invalid(target_height)?;

        // Clear failure flags on ancestors (blocks at lower heights with matching chain)
        for height in (0..target_height).rev() {
            if let Some(metadata) = self.get_block_metadata(height)? {
                if metadata.is_invalid() {
                    // Check if this is an ancestor by verifying chain continuity
                    if self.block_is_ancestor(height, target_height, block_hash)? {
                        self.clear_block_invalid(height)?;
                        log::debug!("Cleared invalid flag on ancestor at height {}", height);
                    }
                }
            }
        }

        // Clear failure flags on descendants
        // Scan forward from target_height to find all descendants
        let max_scan_height = best_height + 1000; // Scan some blocks ahead in case of orphans
        for height in (target_height + 1)..=max_scan_height {
            if let Some(metadata) = self.get_block_metadata(height)? {
                if metadata.is_invalid() {
                    // Check if this block descends from the reconsidered block
                    if self.block_descends_from(height, target_height, block_hash)? {
                        self.clear_block_invalid(height)?;
                        log::debug!("Cleared invalid flag on descendant at height {}", height);
                    }
                }
            } else {
                // No more blocks at this height
                break;
            }
        }

        // After clearing flags, check if we should switch chains
        // This would require comparing chainwork, which we defer to the sync logic
        // For now, return the current best height
        let (_, current_best_height) = self.get_best_block()?;

        log::info!(
            "Block reconsideration complete. Chain tip height: {}",
            current_best_height
        );

        Ok(current_best_height)
    }

    /// Check if a block at `height` is an ancestor of the block at `descendant_height`.
    fn block_is_ancestor(
        &self,
        height: u32,
        descendant_height: u32,
        descendant_hash: &[u8; 32],
    ) -> Result<bool> {
        if height >= descendant_height {
            return Ok(false);
        }

        // Walk back from descendant to potential ancestor
        let mut current_height = descendant_height;
        let mut current_hash = *descendant_hash;

        while current_height > height {
            if let Some(block) = self.get_block(&current_hash)? {
                current_hash = *block.inner().header.prev_blockhash.as_byte_array();
                current_height -= 1;
            } else {
                return Ok(false);
            }
        }

        // Check if the hash at `height` matches our walk
        if let Some(ancestor_hash) = self.get_block_hash_by_height(height)? {
            Ok(ancestor_hash == current_hash)
        } else {
            Ok(false)
        }
    }

    /// Get list of all invalid block heights.
    ///
    /// This is useful for debugging and for the `getchaintips` RPC to report
    /// invalid chain tips.
    pub fn get_invalid_blocks(&self) -> Result<Vec<(u32, [u8; 32])>> {
        let (_, best_height) = self.get_best_block()?;
        let mut invalid_blocks = Vec::new();

        for height in 0..=best_height {
            if let Some(metadata) = self.get_block_metadata(height)? {
                if metadata.is_invalid() {
                    if let Some(hash) = self.get_block_hash_by_height(height)? {
                        invalid_blocks.push((height, hash));
                    }
                }
            }
        }

        Ok(invalid_blocks)
    }
}

/// Create optimized column family options
fn create_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);

    // Enable bloom filters for faster lookups
    opts.set_bloom_locality(10);
    opts.set_memtable_prefix_bloom_ratio(0.1);

    // Optimize for point lookups (256MB block cache per CF)
    opts.optimize_for_point_lookup(256);

    opts
}
