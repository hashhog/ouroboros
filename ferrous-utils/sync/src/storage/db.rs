//! RocksDB database implementation for Bitcoin blockchain storage

use std::sync::Arc;

use bitcoin::OutPoint;
use bitcoin::hashes::Hash;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use thiserror::Error;

use common::{
    BitcoinDeserialize, BitcoinSerialize, BlockMetadata, BlockWrapper, UTXO,
    SerializeError,
};

use crate::storage::schema::{
    decode_height, encode_block_hash, encode_height, encode_outpoint,
    get_column_families, meta_keys, BLOCK_INDEX_CF, BLOCKS_CF, CHAINSTATE_CF, META_CF, SPENT_CF,
    TX_INDEX_CF,
};

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
    /// Open or create a new database at the given path
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Performance optimizations
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        opts.set_bloom_locality(10);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_min_write_buffer_number_to_merge(2);
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB
        opts.set_max_bytes_for_level_base(256 * 1024 * 1024); // 256MB
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.optimize_for_point_lookup(10); // 10MB block cache

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
    pub fn iter_utxos(&self) -> Result<Vec<UTXO>> {
        let cf = self.db
            .cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;

        let mut utxos = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for item in iter {
            let (_key, value) = item.map_err(|e| DbError::RocksDb(e))?;
            if let Ok((utxo, _)) = UTXO::bitcoin_deserialize(&value) {
                utxos.push(utxo);
            }
        }

        Ok(utxos)
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

    // ========== Disconnect / Reorg Methods ==========

    /// Disconnect the block at the given height — reverse all UTXO changes.
    ///
    /// 1. Fetch the block at `height`.
    /// 2. For each transaction (reverse order):
    ///    a. Delete outputs (UTXOs created by this block) from chainstate.
    ///    b. Restore inputs (UTXOs spent by this block) from SPENT_CF undo
    ///       records back into chainstate, then delete the undo records.
    /// 3. Update BEST_BLOCK_HASH / BEST_HEIGHT to the previous block.
    ///
    /// Returns the hash of the disconnected block on success.
    pub fn disconnect_block_at_height(&self, height: u32) -> Result<[u8; 32]> {
        // Fetch block
        let block = self.get_block_by_height(height)?
            .ok_or(DbError::BlockNotFound)?;
        let inner = block.inner();
        let block_hash = *block.block_hash().as_byte_array();

        // Process transactions in reverse order
        for tx in inner.txdata.iter().rev() {
            let txid = tx.compute_txid();

            // 1. Delete outputs created by this block
            for vout in 0..tx.output.len() {
                let outpoint = bitcoin::OutPoint { txid, vout: vout as u32 };
                self.delete_utxo(&outpoint)?;
            }

            // 2. Restore inputs spent by this block
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let outpoint = input.previous_output;
                    if let Some((_spending_txid, utxo)) = self.get_spent_utxo(&outpoint)? {
                        self.add_utxo(&outpoint, &utxo)?;
                        self.delete_spent_record(&outpoint)?;
                    }
                }
            }
        }

        // 3. Update chain tip to previous block
        if height > 0 {
            let prev_hash = *inner.header.prev_blockhash.as_byte_array();
            self.update_best_block(&prev_hash, height - 1)?;
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
}

/// Create optimized column family options
fn create_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);

    // Enable bloom filters for faster lookups
    opts.set_bloom_locality(10);
    opts.set_memtable_prefix_bloom_ratio(0.1);

    // Optimize for point lookups
    opts.optimize_for_point_lookup(10);

    opts
}
