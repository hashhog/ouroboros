//! Storage module for RocksDB database operations and flat file block storage.
//!
//! This module provides multiple storage backends:
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
//!
//! 5. **UTXO snapshots** (`snapshot.rs`): BIP305 assumeUTXO snapshot loading and creation
//!    for fast node startup.

pub mod db;
pub mod schema;
pub mod undo;
pub mod flatfile;
pub mod blockstore;
pub mod coins;
pub mod txindex;
pub mod snapshot;

#[cfg(test)]
mod db_tests;

pub use db::{BlockchainDB, DbError, Result};
pub use undo::{BlockUndo, Coin, TxUndo, UndoError, UndoFileManager};
pub use flatfile::{FlatFilePos, FlatFileSeq, FlatFileError, MAX_BLOCKFILE_SIZE, STORAGE_HEADER_BYTES};
pub use blockstore::{BlockStore, BlockStoreError, BlockFileInfo, BlockPosition, PruneStats};
pub use coins::{CoinsCache, CacheStats, CachedCoin, CoinFlags, DEFAULT_DBCACHE_BYTES};
pub use txindex::{TxIndex, TxIndexError, DiskTxPos};
pub use snapshot::{
    SnapshotError, SnapshotMetadata, AssumeutxoData,
    load_snapshot, dump_snapshot, compute_utxo_hash, validate_snapshot_hash,
    get_assumeutxo_data, get_assumeutxo_by_hash, get_available_snapshot_heights,
    SNAPSHOT_MAGIC, SNAPSHOT_VERSION,
};
