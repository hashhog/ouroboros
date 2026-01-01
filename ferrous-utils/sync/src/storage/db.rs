//! RocksDB database implementation for Bitcoin blockchain storage

use std::sync::Arc;

use bitcoin::OutPoint;
use bitcoin::hashes::Hash;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use thiserror::Error;

use common::{
    BitcoinDeserialize, BitcoinSerialize, BlockMetadata, BlockWrapper, UTXO,
    SerializeError,
};

use crate::storage::schema::{
    decode_height, encode_block_hash, encode_height, encode_outpoint,
    get_column_families, meta_keys, BLOCK_INDEX_CF, BLOCKS_CF, CHAINSTATE_CF, META_CF, SPENT_CF,
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

    /// Spend a UTXO (remove from chainstate and track in spent CF)
    ///
    /// Returns the UTXO that was spent, or None if it didn't exist
    pub fn spend_utxo(&self, outpoint: &OutPoint, spending_txid: &[u8; 32]) -> Result<Option<UTXO>> {
        let txid_bytes = *outpoint.txid.as_byte_array();
        let key = encode_outpoint(&txid_bytes, outpoint.vout);

        let chainstate_cf = self.db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(CHAINSTATE_CF.to_string()))?;
        let spent_cf = self.db.cf_handle(SPENT_CF)
            .ok_or_else(|| DbError::ColumnFamilyNotFound(SPENT_CF.to_string()))?;

        // Get the UTXO before removing it
        let utxo = match self.db.get_cf(chainstate_cf, &key)? {
            Some(data) => {
                let (utxo, _) = UTXO::bitcoin_deserialize(&data)
                    .map_err(|e| DbError::InvalidData(format!("Failed to deserialize UTXO: {}", e)))?;
                Some(utxo)
            }
            None => None,
        };

        // Remove from chainstate
        self.db.delete_cf(chainstate_cf, &key)?;

        // Track in spent column family (store spending txid)
        if let Some(_utxo) = &utxo {
            self.db.put_cf(spent_cf, key, spending_txid)?;
        }

        Ok(utxo)
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
