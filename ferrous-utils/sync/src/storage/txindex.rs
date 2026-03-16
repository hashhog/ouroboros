//! Transaction Index (TxIndex) for fast transaction lookups by txid.
//!
//! This module implements an optional transaction index that maps txid to its
//! location in the block files. The index is stored in a dedicated RocksDB
//! column family and is built incrementally during `connect_block`.
//!
//! # Data Format
//!
//! **Key**: `txid` (32 bytes)
//! **Value**: `[file_number (4 bytes LE)][block_offset (4 bytes LE)][tx_offset (4 bytes LE)]`
//!
//! - `file_number`: The blk?????.dat file number containing this transaction
//! - `block_offset`: Position of the block data within the file (after header)
//! - `tx_offset`: Offset of the transaction within the block (after the compact
//!   size encoding of the tx count)
//!
//! # Reference
//!
//! See Bitcoin Core's `src/index/txindex.cpp` and `src/index/disktxpos.h`.

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

/// Error type for transaction index operations.
#[derive(Error, Debug)]
pub enum TxIndexError {
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Transaction not found: {0}")]
    TxNotFound(String),

    #[error("Invalid data format: {0}")]
    InvalidData(String),

    #[error("Index not enabled")]
    NotEnabled,
}

pub type Result<T> = std::result::Result<T, TxIndexError>;

/// Column family name for transaction index.
const TXINDEX_CF: &str = "txindex";

/// Transaction position on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskTxPos {
    /// Block file number (blk?????.dat).
    pub file_number: i32,
    /// Position of block data within file (after 8-byte header).
    pub block_offset: u32,
    /// Offset of transaction within block (after tx count varint).
    pub tx_offset: u32,
}

impl DiskTxPos {
    /// Create a new disk transaction position.
    pub fn new(file_number: i32, block_offset: u32, tx_offset: u32) -> Self {
        Self {
            file_number,
            block_offset,
            tx_offset,
        }
    }

    /// Serialize to bytes for storage.
    pub fn serialize(&self) -> [u8; 12] {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&self.file_number.to_le_bytes());
        data[4..8].copy_from_slice(&self.block_offset.to_le_bytes());
        data[8..12].copy_from_slice(&self.tx_offset.to_le_bytes());
        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self {
            file_number: i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            block_offset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            tx_offset: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// Transaction index for fast lookups by txid.
///
/// Maintains a mapping from txid to disk position, allowing O(1) retrieval
/// of any confirmed transaction.
pub struct TxIndex {
    db: Arc<DB>,
    enabled: bool,
}

impl TxIndex {
    /// Open or create a transaction index at the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory for the index database
    /// * `enabled` - Whether the index is enabled
    pub fn open<P: AsRef<Path>>(path: P, enabled: bool) -> Result<Self> {
        if !enabled {
            // Create a dummy instance that always returns NotEnabled
            return Ok(Self {
                db: Arc::new(Self::open_dummy_db(path)?),
                enabled: false,
            });
        }

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Performance optimizations
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(2);
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.optimize_for_point_lookup(64);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(TXINDEX_CF, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path.as_ref(), cf_descriptors)?;

        Ok(Self {
            db: Arc::new(db),
            enabled: true,
        })
    }

    fn open_dummy_db<P: AsRef<Path>>(path: P) -> Result<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(TXINDEX_CF, Options::default()),
        ];

        Ok(DB::open_cf_descriptors(&opts, path.as_ref(), cf_descriptors)?)
    }

    /// Check if the index is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Write a single transaction position to the index.
    pub fn write_tx(&self, txid: &Txid, pos: &DiskTxPos) -> Result<()> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let key = txid.as_byte_array();
        self.db.put_cf(cf, key, pos.serialize())?;
        Ok(())
    }

    /// Write multiple transaction positions in a batch.
    ///
    /// This is more efficient than writing one at a time during block connect.
    pub fn write_txs(&self, txs: &[(Txid, DiskTxPos)]) -> Result<()> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for (txid, pos) in txs {
            batch.put_cf(cf, txid.as_byte_array(), pos.serialize());
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Read a transaction position from the index.
    pub fn read_tx(&self, txid: &Txid) -> Result<Option<DiskTxPos>> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let key = txid.as_byte_array();
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                DiskTxPos::deserialize(&data)
                    .ok_or_else(|| TxIndexError::InvalidData(
                        format!("Invalid position data for txid {}", txid)
                    ))
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    /// Delete a transaction from the index (used during disconnect_block).
    pub fn delete_tx(&self, txid: &Txid) -> Result<()> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let key = txid.as_byte_array();
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Delete multiple transactions in a batch (used during disconnect_block).
    pub fn delete_txs(&self, txids: &[Txid]) -> Result<()> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for txid in txids {
            batch.delete_cf(cf, txid.as_byte_array());
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Check if a transaction exists in the index.
    pub fn has_tx(&self, txid: &Txid) -> Result<bool> {
        if !self.enabled {
            return Err(TxIndexError::NotEnabled);
        }

        let cf = self.db.cf_handle(TXINDEX_CF)
            .ok_or_else(|| TxIndexError::InvalidData("CF not found".to_string()))?;

        let key = txid.as_byte_array();
        Ok(self.db.get_cf(cf, key)?.is_some())
    }

    /// Flush pending writes.
    pub fn flush(&self) -> Result<()> {
        if self.enabled {
            self.db.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    #[test]
    fn test_disk_tx_pos_roundtrip() {
        let pos = DiskTxPos::new(42, 12345, 678);
        let data = pos.serialize();
        let restored = DiskTxPos::deserialize(&data).unwrap();

        assert_eq!(restored.file_number, 42);
        assert_eq!(restored.block_offset, 12345);
        assert_eq!(restored.tx_offset, 678);
    }

    #[test]
    fn test_txindex_disabled() {
        let temp = TempDir::new().unwrap();
        let index = TxIndex::open(temp.path().join("txindex"), false).unwrap();

        assert!(!index.is_enabled());

        let txid = test_txid(1);
        let pos = DiskTxPos::new(0, 100, 50);

        // All operations should return NotEnabled
        assert!(matches!(index.write_tx(&txid, &pos), Err(TxIndexError::NotEnabled)));
        assert!(matches!(index.read_tx(&txid), Err(TxIndexError::NotEnabled)));
        assert!(matches!(index.delete_tx(&txid), Err(TxIndexError::NotEnabled)));
        assert!(matches!(index.has_tx(&txid), Err(TxIndexError::NotEnabled)));
    }

    #[test]
    fn test_txindex_write_read() {
        let temp = TempDir::new().unwrap();
        let index = TxIndex::open(temp.path().join("txindex"), true).unwrap();

        assert!(index.is_enabled());

        let txid = test_txid(1);
        let pos = DiskTxPos::new(5, 1000, 200);

        // Write
        index.write_tx(&txid, &pos).unwrap();

        // Read back
        let read_pos = index.read_tx(&txid).unwrap().unwrap();
        assert_eq!(read_pos.file_number, 5);
        assert_eq!(read_pos.block_offset, 1000);
        assert_eq!(read_pos.tx_offset, 200);

        // Has
        assert!(index.has_tx(&txid).unwrap());

        // Delete
        index.delete_tx(&txid).unwrap();
        assert!(!index.has_tx(&txid).unwrap());
        assert!(index.read_tx(&txid).unwrap().is_none());
    }

    #[test]
    fn test_txindex_batch_operations() {
        let temp = TempDir::new().unwrap();
        let index = TxIndex::open(temp.path().join("txindex"), true).unwrap();

        let txs: Vec<(Txid, DiskTxPos)> = (0..10)
            .map(|i| (test_txid(i), DiskTxPos::new(i as i32, i as u32 * 100, i as u32 * 10)))
            .collect();

        // Batch write
        index.write_txs(&txs).unwrap();

        // Verify all written
        for (txid, expected_pos) in &txs {
            let pos = index.read_tx(txid).unwrap().unwrap();
            assert_eq!(pos.file_number, expected_pos.file_number);
            assert_eq!(pos.block_offset, expected_pos.block_offset);
            assert_eq!(pos.tx_offset, expected_pos.tx_offset);
        }

        // Batch delete
        let txids: Vec<Txid> = txs.iter().map(|(txid, _)| *txid).collect();
        index.delete_txs(&txids).unwrap();

        // Verify all deleted
        for txid in &txids {
            assert!(!index.has_tx(txid).unwrap());
        }
    }

    #[test]
    fn test_txindex_not_found() {
        let temp = TempDir::new().unwrap();
        let index = TxIndex::open(temp.path().join("txindex"), true).unwrap();

        let txid = test_txid(99);
        assert!(index.read_tx(&txid).unwrap().is_none());
        assert!(!index.has_tx(&txid).unwrap());
    }
}
