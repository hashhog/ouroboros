//! Storage module for RocksDB database operations and flat file block storage.
//!
//! This module provides two storage backends:
//!
//! 1. **RocksDB storage** (`db.rs`): Key-value store for blocks, UTXO set, and indexes.
//!
//! 2. **Flat file storage** (`blockstore.rs`): Bitcoin Core compatible blk*.dat/rev*.dat
//!    files for block data and undo data.
//!
//! 3. **UTXO cache** (`coins.rs`): In-memory UTXO cache with DIRTY/FRESH flags and
//!    periodic flush to the backing store (matches Bitcoin Core's CCoinsViewCache).
//!
//! 4. **Transaction index** (`txindex.rs`): Optional index for fast transaction lookups
//!    by txid, mapping to file position (BIP 157 style).

pub mod db;
pub mod schema;
pub mod undo;
pub mod flatfile;
pub mod blockstore;
pub mod coins;
pub mod txindex;

#[cfg(test)]
mod db_tests;

pub use db::{BlockchainDB, DbError, Result};
pub use undo::{BlockUndo, Coin, TxUndo, UndoError, UndoFileManager};
pub use flatfile::{FlatFilePos, FlatFileSeq, FlatFileError, MAX_BLOCKFILE_SIZE, STORAGE_HEADER_BYTES};
pub use blockstore::{BlockStore, BlockStoreError, BlockFileInfo, BlockPosition, PruneStats};
pub use coins::{CoinsCache, CacheStats, CachedCoin, CoinFlags, DEFAULT_DBCACHE_BYTES};
pub use txindex::{TxIndex, TxIndexError, DiskTxPos};
