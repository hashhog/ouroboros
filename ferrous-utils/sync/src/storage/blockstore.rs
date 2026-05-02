//! Flat file block storage matching Bitcoin Core's blk*.dat format.
//!
//! This module implements block storage in flat files, where each block is
//! prefixed with network magic bytes and a size field. This format is
//! compatible with Bitcoin Core's block files.
//!
//! # File Format
//!
//! Each block in a `blk?????.dat` file:
//! ```text
//! +------------------+------------------+---------------------------+
//! | Magic Bytes (4)  | Block Size (4)   | Serialized Block (varies) |
//! +------------------+------------------+---------------------------+
//! ```
//!
//! - Magic bytes: Network-specific identifier (e.g., 0xD9B4BEF9 for mainnet)
//! - Block size: Little-endian u32, size of serialized block data
//! - Block data: Bitcoin-serialized block with witness data
//!
//! # Undo Data
//!
//! Each block's undo data is stored in a corresponding `rev?????.dat` file:
//! ```text
//! +------------------+------------------+---------------------------+------------------+
//! | Magic Bytes (4)  | Undo Size (4)    | Block Undo Data (varies)  | Checksum (32)    |
//! +------------------+------------------+---------------------------+------------------+
//! ```
//!
//! # Reference
//!
//! See Bitcoin Core's `src/node/blockstorage.cpp` for the canonical implementation.

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Block, BlockHash, Network};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

use super::flatfile::{
    FlatFileError, FlatFilePos, FlatFileSeq, MAX_BLOCKFILE_SIZE, STORAGE_HEADER_BYTES,
    UNDO_DATA_DISK_OVERHEAD,
};
use super::undo::BlockUndo;
use crate::network::messages::get_magic;

/// Column family for block file info.
const FILEINFO_CF: &str = "fileinfo";

/// Column family for block index (hash -> file position).
const BLOCKPOS_CF: &str = "blockpos";

/// Error type for block store operations.
#[derive(Error, Debug)]
pub enum BlockStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Flat file error: {0}")]
    FlatFile(#[from] FlatFileError),

    #[error("Database error: {0}")]
    Database(#[from] rocksdb::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid magic: expected {expected:08x}, got {actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("Block not found: {0}")]
    BlockNotFound(BlockHash),

    #[error("Invalid block size: {0}")]
    InvalidSize(u32),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Undo data not found for height {0}")]
    UndoNotFound(u32),
}

pub type Result<T> = std::result::Result<T, BlockStoreError>;

/// Information about a block file.
#[derive(Debug, Clone, Default)]
pub struct BlockFileInfo {
    /// Number of blocks stored in this file.
    pub num_blocks: u32,
    /// Number of bytes used in the block file.
    pub size: u32,
    /// Number of bytes used in the undo file.
    pub undo_size: u32,
    /// Lowest block height in this file.
    pub height_first: u32,
    /// Highest block height in this file.
    pub height_last: u32,
    /// Earliest block timestamp in this file.
    pub time_first: u64,
    /// Latest block timestamp in this file.
    pub time_last: u64,
}

impl BlockFileInfo {
    /// Serialize to bytes for storage.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&self.num_blocks.to_le_bytes());
        data.extend_from_slice(&self.size.to_le_bytes());
        data.extend_from_slice(&self.undo_size.to_le_bytes());
        data.extend_from_slice(&self.height_first.to_le_bytes());
        data.extend_from_slice(&self.height_last.to_le_bytes());
        data.extend_from_slice(&self.time_first.to_le_bytes());
        data.extend_from_slice(&self.time_last.to_le_bytes());
        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 36 {
            return None;
        }
        Some(Self {
            num_blocks: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            undo_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            height_first: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            height_last: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            time_first: u64::from_le_bytes([
                data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
            ]),
            time_last: u64::from_le_bytes([
                data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
            ]),
        })
    }
}

/// Position of a block in flat file storage.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockPosition {
    /// File number for block data.
    pub file: i32,
    /// Position in block file (after header).
    pub data_pos: u32,
    /// Position in undo file (after header), or 0 if no undo data.
    pub undo_pos: u32,
}

impl BlockPosition {
    /// Serialize to bytes for storage.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&self.file.to_le_bytes());
        data.extend_from_slice(&self.data_pos.to_le_bytes());
        data.extend_from_slice(&self.undo_pos.to_le_bytes());
        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self {
            file: i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            data_pos: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            undo_pos: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Check if block data is available.
    pub fn has_data(&self) -> bool {
        self.file >= 0 && self.data_pos > 0
    }

    /// Check if undo data is available.
    pub fn has_undo(&self) -> bool {
        self.undo_pos > 0
    }
}

/// State of the block store (current file positions).
#[derive(Debug, Clone)]
struct BlockStoreCursor {
    /// Current block file number.
    block_file: i32,
    /// Current position in block file.
    block_pos: u32,
    /// Current undo file position (tracks undo writes for current block file).
    undo_pos: u32,
}

impl Default for BlockStoreCursor {
    fn default() -> Self {
        Self {
            block_file: 0,
            block_pos: 0,
            undo_pos: 0,
        }
    }
}

/// Block store managing flat file block storage.
///
/// Writes blocks to `blk?????.dat` files and undo data to `rev?????.dat` files,
/// with a RocksDB index for looking up block positions by hash.
pub struct BlockStore {
    /// Directory for block files.
    blocks_dir: PathBuf,
    /// Network (for magic bytes).
    network: Network,
    /// Network magic bytes.
    magic: [u8; 4],
    /// Block file sequence.
    block_files: FlatFileSeq,
    /// Undo file sequence.
    undo_files: FlatFileSeq,
    /// LevelDB/RocksDB index.
    db: DB,
    /// Current cursor state.
    cursor: RwLock<BlockStoreCursor>,
    /// Block file info cache.
    file_info: RwLock<Vec<BlockFileInfo>>,
}

impl BlockStore {
    /// Create a new block store.
    ///
    /// # Arguments
    ///
    /// * `data_dir` - Base data directory (blocks stored in `data_dir/blocks/`)
    /// * `network` - Bitcoin network
    pub fn new<P: AsRef<Path>>(data_dir: P, network: Network) -> Result<Self> {
        let blocks_dir = data_dir.as_ref().join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;

        // Get magic bytes for network
        let magic_u32 = get_magic(network);
        let magic = magic_u32.to_le_bytes();

        // Create flat file sequences
        let block_files = FlatFileSeq::new(&blocks_dir, "blk", super::flatfile::BLOCKFILE_CHUNK_SIZE);
        let undo_files = FlatFileSeq::new(&blocks_dir, "rev", super::flatfile::UNDOFILE_CHUNK_SIZE);

        // Open RocksDB index
        let db_path = blocks_dir.join("index");
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Bumped 512 → 16384 to reduce SST mmap churn during IBD (parity
        // with the chainstate DB).  Safe under maxbox ulimit -n 524288.
        db_opts.set_max_open_files(16384);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(FILEINFO_CF, Options::default()),
            ColumnFamilyDescriptor::new(BLOCKPOS_CF, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors)?;

        let store = Self {
            blocks_dir,
            network,
            magic,
            block_files,
            undo_files,
            db,
            cursor: RwLock::new(BlockStoreCursor::default()),
            file_info: RwLock::new(Vec::new()),
        };

        // Load existing state
        store.load_state()?;

        Ok(store)
    }

    /// Load existing state from database.
    fn load_state(&self) -> Result<()> {
        let mut cursor = self.cursor.write().unwrap();
        let mut file_info = self.file_info.write().unwrap();

        // Load file info entries
        let cf = self.db.cf_handle(FILEINFO_CF);
        let mut max_file = -1i32;

        if let Some(cf) = cf {
            let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item?;
                if key.len() == 4 {
                    let file_num = i32::from_le_bytes([key[0], key[1], key[2], key[3]]);
                    if let Some(info) = BlockFileInfo::deserialize(&value) {
                        // Ensure vec is large enough
                        while file_info.len() <= file_num as usize {
                            file_info.push(BlockFileInfo::default());
                        }
                        file_info[file_num as usize] = info.clone();

                        if file_num > max_file {
                            max_file = file_num;
                            cursor.block_file = file_num;
                            cursor.block_pos = info.size;
                            cursor.undo_pos = info.undo_size;
                        }
                    }
                }
            }
        }

        // If no files found, start at file 0
        if max_file < 0 {
            cursor.block_file = 0;
            cursor.block_pos = 0;
            cursor.undo_pos = 0;
            file_info.push(BlockFileInfo::default());
        }

        Ok(())
    }

    /// Find position for next block, rolling over to new file if needed.
    fn find_next_block_pos(
        &self,
        block_size: u32,
        height: u32,
        timestamp: u64,
    ) -> Result<FlatFilePos> {
        let mut cursor = self.cursor.write().unwrap();
        let mut file_info = self.file_info.write().unwrap();

        let total_size = block_size + STORAGE_HEADER_BYTES as u32;

        // Check if we need a new file
        while cursor.block_pos as u64 + total_size as u64 >= MAX_BLOCKFILE_SIZE {
            // Finalize current file
            self.finalize_file(cursor.block_file, &file_info)?;

            // Move to next file
            cursor.block_file += 1;
            cursor.block_pos = 0;
            cursor.undo_pos = 0;

            // Initialize new file info
            while file_info.len() <= cursor.block_file as usize {
                file_info.push(BlockFileInfo::default());
            }
        }

        let pos = FlatFilePos::new(cursor.block_file, cursor.block_pos);

        // Update file info
        let info = &mut file_info[cursor.block_file as usize];
        if info.num_blocks == 0 {
            info.height_first = height;
            info.time_first = timestamp;
        }
        info.num_blocks += 1;
        info.height_last = height;
        info.time_last = timestamp;

        // Update cursor position (will be updated after write)
        Ok(pos)
    }

    /// Finalize a block file (flush and truncate).
    fn finalize_file(&self, file_num: i32, file_info: &[BlockFileInfo]) -> Result<()> {
        if file_num >= 0 && (file_num as usize) < file_info.len() {
            let info = &file_info[file_num as usize];
            let pos = FlatFilePos::new(file_num, info.size);
            self.block_files.flush(&pos, true)?;

            // Also finalize undo file if it has data
            if info.undo_size > 0 {
                let undo_pos = FlatFilePos::new(file_num, info.undo_size);
                self.undo_files.flush(&undo_pos, true)?;
            }
        }
        Ok(())
    }

    /// Write a block to disk.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to write
    /// * `height` - Block height
    ///
    /// # Returns
    ///
    /// Position where the block was written.
    pub fn write_block(&self, block: &Block, height: u32) -> Result<BlockPosition> {
        // Serialize block
        let mut block_data = Vec::new();
        block
            .consensus_encode(&mut block_data)
            .map_err(|e| BlockStoreError::Serialization(e.to_string()))?;

        let block_size = block_data.len() as u32;
        let timestamp = block.header.time as u64;

        // Find position
        let pos = self.find_next_block_pos(block_size, height, timestamp)?;

        // Allocate space
        self.block_files
            .allocate(&pos, block_size as u64 + STORAGE_HEADER_BYTES)?;

        // Write to file
        let mut file = self.block_files.open(&pos, false)?;

        // Write header: magic + size
        file.write_all(&self.magic)?;
        file.write_all(&block_size.to_le_bytes())?;

        // Write block data
        file.write_all(&block_data)?;
        file.sync_all()?;

        // Update cursor and file info
        let data_pos = pos.pos + STORAGE_HEADER_BYTES as u32;
        {
            let mut cursor = self.cursor.write().unwrap();
            let mut file_info = self.file_info.write().unwrap();

            cursor.block_pos = data_pos + block_size;

            let info = &mut file_info[pos.file as usize];
            info.size = cursor.block_pos;

            // Save file info to database
            self.save_file_info(pos.file, info)?;
        }

        // Save block position to index
        let block_hash = block.block_hash();
        let block_pos = BlockPosition {
            file: pos.file,
            data_pos,
            undo_pos: 0, // Will be set when undo data is written
        };
        self.save_block_pos(&block_hash, &block_pos)?;

        Ok(block_pos)
    }

    /// Write undo data for a block.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the block
    /// * `prev_block_hash` - Hash of the previous block (for checksum)
    /// * `undo` - Block undo data
    ///
    /// # Returns
    ///
    /// Updated block position with undo_pos set.
    pub fn write_block_undo(
        &self,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
        undo: &BlockUndo,
    ) -> Result<BlockPosition> {
        // Get current block position
        let mut block_pos = self.get_block_pos(block_hash)?
            .ok_or_else(|| BlockStoreError::BlockNotFound(*block_hash))?;

        // Serialize undo data
        let undo_data = undo.serialize();
        let undo_size = undo_data.len() as u32;

        // Compute checksum: SHA256d(prev_hash || undo_data)
        let mut hasher_data = Vec::with_capacity(32 + undo_data.len());
        hasher_data.extend_from_slice(prev_block_hash.as_byte_array());
        hasher_data.extend_from_slice(&undo_data);
        let checksum = sha256d::Hash::hash(&hasher_data);

        // Find position in undo file
        let total_size = undo_size + UNDO_DATA_DISK_OVERHEAD as u32;
        let undo_pos = {
            let cursor = self.cursor.read().unwrap();
            FlatFilePos::new(block_pos.file, cursor.undo_pos)
        };

        // Allocate space
        self.undo_files.allocate(&undo_pos, total_size as u64)?;

        // Write to file
        let mut file = self.undo_files.open(&undo_pos, false)?;

        // Write header: magic + size
        file.write_all(&self.magic)?;
        file.write_all(&undo_size.to_le_bytes())?;

        // Write undo data
        file.write_all(&undo_data)?;

        // Write checksum
        file.write_all(checksum.as_byte_array())?;
        file.sync_all()?;

        // Update cursor and file info
        let data_pos = undo_pos.pos + STORAGE_HEADER_BYTES as u32;
        {
            let mut cursor = self.cursor.write().unwrap();
            let mut file_info = self.file_info.write().unwrap();

            cursor.undo_pos = data_pos + undo_size + 32; // +32 for checksum

            let info = &mut file_info[block_pos.file as usize];
            info.undo_size = cursor.undo_pos;

            self.save_file_info(block_pos.file, info)?;
        }

        // Update block position with undo_pos
        block_pos.undo_pos = data_pos;
        self.save_block_pos(block_hash, &block_pos)?;

        Ok(block_pos)
    }

    /// Read a block from disk by hash.
    pub fn read_block(&self, block_hash: &BlockHash) -> Result<Option<Block>> {
        let pos = match self.get_block_pos(block_hash)? {
            Some(p) if p.has_data() => p,
            _ => return Ok(None),
        };

        self.read_block_at(pos.file, pos.data_pos)
    }

    /// Read a block from disk by file position.
    pub fn read_block_at(&self, file_num: i32, data_pos: u32) -> Result<Option<Block>> {
        // Position points to block data, so we need to read header first
        let header_pos = data_pos.saturating_sub(STORAGE_HEADER_BYTES as u32);
        let file_pos = FlatFilePos::new(file_num, header_pos);

        let mut file = match self.block_files.open(&file_pos, true) {
            Ok(f) => f,
            Err(FlatFileError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        // Read header
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            return Ok(None);
        }

        // Verify magic
        let magic = [header[0], header[1], header[2], header[3]];
        if magic != self.magic {
            return Err(BlockStoreError::InvalidMagic {
                expected: u32::from_le_bytes(self.magic),
                actual: u32::from_le_bytes(magic),
            });
        }

        // Read size
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if size > 4_000_000 {
            // MAX_BLOCK_SERIALIZED_SIZE
            return Err(BlockStoreError::InvalidSize(size));
        }

        // Read block data
        let mut block_data = vec![0u8; size as usize];
        file.read_exact(&mut block_data)?;

        // Deserialize block
        let block = Block::consensus_decode(&mut Cursor::new(&block_data))
            .map_err(|e| BlockStoreError::Serialization(e.to_string()))?;

        Ok(Some(block))
    }

    /// Read undo data for a block.
    pub fn read_block_undo(
        &self,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
    ) -> Result<Option<BlockUndo>> {
        let pos = match self.get_block_pos(block_hash)? {
            Some(p) if p.has_undo() => p,
            _ => return Ok(None),
        };

        // Position points to undo data, so we need to read header first
        let header_pos = pos.undo_pos.saturating_sub(STORAGE_HEADER_BYTES as u32);
        let file_pos = FlatFilePos::new(pos.file, header_pos);

        let mut file = match self.undo_files.open(&file_pos, true) {
            Ok(f) => f,
            Err(FlatFileError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        // Read header
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;

        // Verify magic
        let magic = [header[0], header[1], header[2], header[3]];
        if magic != self.magic {
            return Err(BlockStoreError::InvalidMagic {
                expected: u32::from_le_bytes(self.magic),
                actual: u32::from_le_bytes(magic),
            });
        }

        // Read size
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        // Read undo data
        let mut undo_data = vec![0u8; size as usize];
        file.read_exact(&mut undo_data)?;

        // Read checksum
        let mut checksum = [0u8; 32];
        file.read_exact(&mut checksum)?;

        // Verify checksum
        let mut hasher_data = Vec::with_capacity(32 + undo_data.len());
        hasher_data.extend_from_slice(prev_block_hash.as_byte_array());
        hasher_data.extend_from_slice(&undo_data);
        let expected_checksum = sha256d::Hash::hash(&hasher_data);

        if checksum != *expected_checksum.as_byte_array() {
            return Err(BlockStoreError::ChecksumMismatch);
        }

        // Deserialize undo data
        let (undo, _) = BlockUndo::deserialize(&undo_data)
            .map_err(|e| BlockStoreError::Serialization(e.to_string()))?;

        Ok(Some(undo))
    }

    /// Get block position from index.
    pub fn get_block_pos(&self, block_hash: &BlockHash) -> Result<Option<BlockPosition>> {
        let cf = self
            .db
            .cf_handle(BLOCKPOS_CF)
            .ok_or_else(|| BlockStoreError::Serialization("CF not found".to_string()))?;

        let key = block_hash.as_byte_array();
        match self.db.get_cf(cf, key)? {
            Some(data) => Ok(BlockPosition::deserialize(&data)),
            None => Ok(None),
        }
    }

    /// Save block position to index.
    fn save_block_pos(&self, block_hash: &BlockHash, pos: &BlockPosition) -> Result<()> {
        let cf = self
            .db
            .cf_handle(BLOCKPOS_CF)
            .ok_or_else(|| BlockStoreError::Serialization("CF not found".to_string()))?;

        let key = block_hash.as_byte_array();
        self.db.put_cf(cf, key, pos.serialize())?;
        Ok(())
    }

    /// Save file info to database.
    fn save_file_info(&self, file_num: i32, info: &BlockFileInfo) -> Result<()> {
        let cf = self
            .db
            .cf_handle(FILEINFO_CF)
            .ok_or_else(|| BlockStoreError::Serialization("CF not found".to_string()))?;

        let key = file_num.to_le_bytes();
        self.db.put_cf(cf, key, info.serialize())?;
        Ok(())
    }

    /// Get file info for a block file.
    pub fn get_file_info(&self, file_num: i32) -> Option<BlockFileInfo> {
        let file_info = self.file_info.read().unwrap();
        if file_num >= 0 && (file_num as usize) < file_info.len() {
            Some(file_info[file_num as usize].clone())
        } else {
            None
        }
    }

    /// Get current block file number.
    pub fn current_file(&self) -> i32 {
        self.cursor.read().unwrap().block_file
    }

    /// Get current position in block file.
    pub fn current_pos(&self) -> u32 {
        self.cursor.read().unwrap().block_pos
    }

    /// Check if a block exists in the store.
    pub fn has_block(&self, block_hash: &BlockHash) -> Result<bool> {
        Ok(self.get_block_pos(block_hash)?.map(|p| p.has_data()).unwrap_or(false))
    }

    /// Check if undo data exists for a block.
    pub fn has_undo(&self, block_hash: &BlockHash) -> Result<bool> {
        Ok(self.get_block_pos(block_hash)?.map(|p| p.has_undo()).unwrap_or(false))
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &Path {
        &self.blocks_dir
    }

    /// Get the network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Flush all pending writes.
    pub fn flush(&self) -> Result<()> {
        let cursor = self.cursor.read().unwrap();
        let pos = FlatFilePos::new(cursor.block_file, cursor.block_pos);
        self.block_files.flush(&pos, false)?;

        if cursor.undo_pos > 0 {
            let undo_pos = FlatFilePos::new(cursor.block_file, cursor.undo_pos);
            self.undo_files.flush(&undo_pos, false)?;
        }

        self.db.flush()?;
        Ok(())
    }

    // =========================================================================
    // Pruning Methods
    // =========================================================================

    /// Minimum number of blocks to keep for reorg safety (2 days of blocks).
    pub const MIN_BLOCKS_TO_KEEP: u32 = 288;

    /// Minimum prune target in bytes (550 MB).
    pub const MIN_DISK_SPACE_FOR_BLOCK_FILES: u64 = 550 * 1024 * 1024;

    /// Get the maximum block file number currently in use.
    pub fn max_blockfile_num(&self) -> i32 {
        self.cursor.read().unwrap().block_file
    }

    /// Get the number of block files.
    pub fn num_block_files(&self) -> usize {
        self.file_info.read().unwrap().len()
    }

    /// Calculate total disk usage of all block and undo files.
    pub fn calculate_current_usage(&self) -> u64 {
        let file_info = self.file_info.read().unwrap();
        file_info
            .iter()
            .map(|info| info.size as u64 + info.undo_size as u64)
            .sum()
    }

    /// Mark a single block file as pruned.
    ///
    /// This clears the file info and updates the database, but does NOT delete
    /// the actual files. Call `unlink_pruned_files` to delete files.
    ///
    /// Returns the number of bytes that will be freed when files are deleted.
    pub fn prune_one_file(&self, file_num: i32) -> Result<u64> {
        if file_num < 0 {
            return Ok(0);
        }

        let mut file_info = self.file_info.write().unwrap();
        if (file_num as usize) >= file_info.len() {
            return Ok(0);
        }

        let info = &file_info[file_num as usize];
        if info.size == 0 {
            return Ok(0);
        }

        let bytes_freed = info.size as u64 + info.undo_size as u64;

        // Reset file info to empty
        file_info[file_num as usize] = BlockFileInfo::default();

        // Save the empty file info to database
        self.save_file_info(file_num, &BlockFileInfo::default())?;

        log::info!(
            "Pruned block file {} ({} bytes to be freed)",
            file_num,
            bytes_freed
        );

        Ok(bytes_freed)
    }

    /// Find block files eligible for pruning.
    ///
    /// # Arguments
    ///
    /// * `last_block_can_prune` - Highest block height that can be pruned
    /// * `min_block_to_prune` - Lowest block height that can be pruned (usually 0)
    /// * `target_bytes` - Target disk usage in bytes (0 = no target, prune all eligible)
    ///
    /// # Returns
    ///
    /// Set of file numbers that can be pruned.
    pub fn find_files_to_prune(
        &self,
        last_block_can_prune: u32,
        min_block_to_prune: u32,
        target_bytes: u64,
    ) -> Vec<i32> {
        let file_info = self.file_info.read().unwrap();
        let mut files_to_prune = Vec::new();
        let mut current_usage = self.calculate_current_usage();

        // If we have a target and we're already below it, nothing to do
        if target_bytes > 0 && current_usage <= target_bytes {
            return files_to_prune;
        }

        // Process files in ascending order (oldest first)
        for file_num in 0..file_info.len() {
            let info = &file_info[file_num];

            // Skip empty files
            if info.size == 0 {
                continue;
            }

            // If we have a target and we're now below it, stop
            if target_bytes > 0 && current_usage <= target_bytes {
                break;
            }

            // Check if file's height range is within prunable range
            // File is prunable if ALL its blocks are below the prune limit
            if info.height_last > last_block_can_prune {
                continue;
            }
            if info.height_first < min_block_to_prune {
                continue;
            }

            let bytes_in_file = info.size as u64 + info.undo_size as u64;
            files_to_prune.push(file_num as i32);
            current_usage = current_usage.saturating_sub(bytes_in_file);
        }

        files_to_prune
    }

    /// Find files to prune for manual pruning (pruneblockchain RPC).
    ///
    /// Unlike automatic pruning, this prunes ALL eligible files without
    /// checking against a target size.
    ///
    /// # Arguments
    ///
    /// * `manual_prune_height` - Prune all files with blocks fully below this height
    pub fn find_files_to_prune_manual(&self, manual_prune_height: u32) -> Vec<i32> {
        self.find_files_to_prune(manual_prune_height, 0, 0)
    }

    /// Delete pruned block and undo files from disk.
    ///
    /// # Arguments
    ///
    /// * `file_nums` - Set of file numbers to delete
    ///
    /// # Returns
    ///
    /// Number of files successfully deleted.
    pub fn unlink_pruned_files(&self, file_nums: &[i32]) -> Result<usize> {
        let mut deleted = 0;

        for &file_num in file_nums {
            // Delete block file
            let blk_pos = FlatFilePos::new(file_num, 0);
            let blk_path = self.block_files.file_name(&blk_pos);
            if blk_path.exists() {
                if let Err(e) = std::fs::remove_file(&blk_path) {
                    log::warn!("Failed to delete block file {:?}: {}", blk_path, e);
                } else {
                    log::debug!("Deleted block file {:?}", blk_path);
                }
            }

            // Delete corresponding undo file
            let rev_pos = FlatFilePos::new(file_num, 0);
            let rev_path = self.undo_files.file_name(&rev_pos);
            if rev_path.exists() {
                if let Err(e) = std::fs::remove_file(&rev_path) {
                    log::warn!("Failed to delete undo file {:?}: {}", rev_path, e);
                } else {
                    log::debug!("Deleted undo file {:?}", rev_path);
                }
            }

            deleted += 1;
        }

        Ok(deleted)
    }

    /// Prune block files to meet a target size.
    ///
    /// # Arguments
    ///
    /// * `current_height` - Current best block height
    /// * `target_bytes` - Target disk usage (minimum 550MB)
    ///
    /// # Returns
    ///
    /// Tuple of (files_pruned, bytes_freed).
    pub fn prune_to_target(&self, current_height: u32, target_bytes: u64) -> Result<(usize, u64)> {
        let target = target_bytes.max(Self::MIN_DISK_SPACE_FOR_BLOCK_FILES);

        // Can't prune if chain is too short
        if current_height < Self::MIN_BLOCKS_TO_KEEP {
            return Ok((0, 0));
        }

        let last_block_can_prune = current_height - Self::MIN_BLOCKS_TO_KEEP;
        let files_to_prune = self.find_files_to_prune(last_block_can_prune, 0, target);

        if files_to_prune.is_empty() {
            return Ok((0, 0));
        }

        // Mark files as pruned and track bytes to free
        let mut total_bytes = 0u64;
        for &file_num in &files_to_prune {
            total_bytes += self.prune_one_file(file_num)?;
        }

        // Actually delete the files
        let deleted = self.unlink_pruned_files(&files_to_prune)?;

        log::info!(
            "Pruned {} file(s), freed {} bytes",
            deleted,
            total_bytes
        );

        Ok((deleted, total_bytes))
    }

    /// Prune block files up to a specific height (for pruneblockchain RPC).
    ///
    /// # Arguments
    ///
    /// * `target_height` - Prune all files with blocks fully below this height
    /// * `current_height` - Current best block height (for safety check)
    ///
    /// # Returns
    ///
    /// Tuple of (files_pruned, bytes_freed, actual_prune_height).
    pub fn prune_to_height(
        &self,
        target_height: u32,
        current_height: u32,
    ) -> Result<(usize, u64, u32)> {
        // Enforce minimum blocks to keep
        if current_height < Self::MIN_BLOCKS_TO_KEEP {
            return Ok((0, 0, 0));
        }

        let max_prune_height = current_height - Self::MIN_BLOCKS_TO_KEEP;
        let actual_target = target_height.min(max_prune_height);

        let files_to_prune = self.find_files_to_prune_manual(actual_target);

        if files_to_prune.is_empty() {
            return Ok((0, 0, actual_target));
        }

        // Mark files as pruned
        let mut total_bytes = 0u64;
        for &file_num in &files_to_prune {
            total_bytes += self.prune_one_file(file_num)?;
        }

        // Delete the files
        let deleted = self.unlink_pruned_files(&files_to_prune)?;

        log::info!(
            "Manual prune: {} file(s), {} bytes, up to height {}",
            deleted,
            total_bytes,
            actual_target
        );

        Ok((deleted, total_bytes, actual_target))
    }

    /// Get the lowest height that still has block data available.
    ///
    /// Scans file info to find the first file with data and returns its
    /// height_first value. Returns 0 if no pruning has occurred.
    pub fn get_prune_height(&self) -> u32 {
        let file_info = self.file_info.read().unwrap();

        // Find the first file that has data
        for info in file_info.iter() {
            if info.size > 0 {
                return info.height_first;
            }
        }

        // If all files are empty (shouldn't happen), return 0
        0
    }

    /// Check if block data is available for a given height.
    pub fn has_block_data_at_height(&self, height: u32) -> bool {
        let file_info = self.file_info.read().unwrap();

        for info in file_info.iter() {
            if info.size > 0 && height >= info.height_first && height <= info.height_last {
                return true;
            }
        }

        false
    }

    /// Get pruning statistics.
    pub fn get_prune_stats(&self) -> PruneStats {
        let file_info = self.file_info.read().unwrap();
        let cursor = self.cursor.read().unwrap();

        let total_files = cursor.block_file as usize + 1;
        let mut pruned_files = 0usize;
        let mut data_bytes = 0u64;
        let mut undo_bytes = 0u64;

        for (file_num, info) in file_info.iter().enumerate() {
            if info.size == 0 {
                // Only count as pruned if this file was written to (not current cursor)
                // and has height info (meaning blocks were actually in it)
                if (file_num as i32) < cursor.block_file && info.height_last > 0 {
                    pruned_files += 1;
                }
            } else {
                data_bytes += info.size as u64;
                undo_bytes += info.undo_size as u64;
            }
        }

        PruneStats {
            total_files,
            pruned_files,
            data_bytes,
            undo_bytes,
            prune_height: self.get_prune_height(),
        }
    }
}

/// Statistics about block storage and pruning state.
#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    /// Total number of block files ever created.
    pub total_files: usize,
    /// Number of files that have been pruned.
    pub pruned_files: usize,
    /// Total bytes of block data on disk.
    pub data_bytes: u64,
    /// Total bytes of undo data on disk.
    pub undo_bytes: u64,
    /// Lowest height with available block data.
    pub prune_height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::block::Header;
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode};
    use tempfile::TempDir;

    fn create_test_block() -> Block {
        // Create a minimal valid block
        let header = Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };

        // Create a simple coinbase transaction
        let coinbase = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        Block {
            header,
            txdata: vec![coinbase],
        }
    }

    #[test]
    fn test_blockstore_new() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        assert_eq!(store.current_file(), 0);
        assert_eq!(store.current_pos(), 0);
        assert_eq!(store.network(), Network::Regtest);
    }

    #[test]
    fn test_blockstore_write_read_block() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let block = create_test_block();
        let block_hash = block.block_hash();

        // Write block
        let pos = store.write_block(&block, 0).unwrap();
        assert!(pos.has_data());
        assert_eq!(pos.file, 0);

        // Read block back
        let read_block = store.read_block(&block_hash).unwrap().unwrap();
        assert_eq!(read_block.block_hash(), block_hash);
        assert_eq!(read_block.txdata.len(), 1);
    }

    #[test]
    fn test_blockstore_write_multiple_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let mut prev_hash = BlockHash::all_zeros();

        for i in 0..10 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;

            let block_hash = block.block_hash();
            store.write_block(&block, i).unwrap();

            // Verify block can be read
            let read_block = store.read_block(&block_hash).unwrap().unwrap();
            assert_eq!(read_block.block_hash(), block_hash);

            prev_hash = block_hash;
        }

        // Verify all blocks exist
        assert!(store.current_pos() > 0);
    }

    #[test]
    fn test_blockstore_block_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let fake_hash = BlockHash::from_byte_array([0xab; 32]);
        assert!(store.read_block(&fake_hash).unwrap().is_none());
    }

    #[test]
    fn test_blockstore_has_block() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let block = create_test_block();
        let block_hash = block.block_hash();

        assert!(!store.has_block(&block_hash).unwrap());

        store.write_block(&block, 0).unwrap();

        assert!(store.has_block(&block_hash).unwrap());
    }

    #[test]
    fn test_block_file_info_serialize() {
        let info = BlockFileInfo {
            num_blocks: 100,
            size: 50000,
            undo_size: 10000,
            height_first: 1000,
            height_last: 1099,
            time_first: 1600000000,
            time_last: 1600100000,
        };

        let data = info.serialize();
        let restored = BlockFileInfo::deserialize(&data).unwrap();

        assert_eq!(restored.num_blocks, info.num_blocks);
        assert_eq!(restored.size, info.size);
        assert_eq!(restored.undo_size, info.undo_size);
        assert_eq!(restored.height_first, info.height_first);
        assert_eq!(restored.height_last, info.height_last);
        assert_eq!(restored.time_first, info.time_first);
        assert_eq!(restored.time_last, info.time_last);
    }

    #[test]
    fn test_block_position_serialize() {
        let pos = BlockPosition {
            file: 5,
            data_pos: 12345,
            undo_pos: 6789,
        };

        let data = pos.serialize();
        let restored = BlockPosition::deserialize(&data).unwrap();

        assert_eq!(restored.file, pos.file);
        assert_eq!(restored.data_pos, pos.data_pos);
        assert_eq!(restored.undo_pos, pos.undo_pos);
        assert!(restored.has_data());
        assert!(restored.has_undo());
    }

    #[test]
    fn test_flat_file_pos() {
        let pos = FlatFilePos::new(1, 100);
        assert!(!pos.is_null());
        assert_eq!(pos.file, 1);
        assert_eq!(pos.pos, 100);

        let null_pos = FlatFilePos::null();
        assert!(null_pos.is_null());
    }

    // =========================================================================
    // Pruning Tests
    // =========================================================================

    #[test]
    fn test_prune_constants() {
        assert_eq!(BlockStore::MIN_BLOCKS_TO_KEEP, 288);
        assert_eq!(BlockStore::MIN_DISK_SPACE_FOR_BLOCK_FILES, 550 * 1024 * 1024);
    }

    #[test]
    fn test_prune_stats_empty_store() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let stats = store.get_prune_stats();
        assert_eq!(stats.total_files, 1); // File 0 always exists
        assert_eq!(stats.pruned_files, 0);
        assert_eq!(stats.data_bytes, 0);
        assert_eq!(stats.undo_bytes, 0);
        assert_eq!(stats.prune_height, 0);
    }

    #[test]
    fn test_calculate_current_usage_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        assert_eq!(store.calculate_current_usage(), 0);
    }

    #[test]
    fn test_calculate_current_usage_with_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Write some blocks
        let mut prev_hash = BlockHash::all_zeros();
        for i in 0..5 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            prev_hash = block.block_hash();
            store.write_block(&block, i).unwrap();
        }

        let usage = store.calculate_current_usage();
        assert!(usage > 0, "Usage should be positive after writing blocks");
    }

    #[test]
    fn test_find_files_to_prune_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let files = store.find_files_to_prune(1000, 0, 0);
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_files_to_prune_with_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Write blocks with heights 0-9
        let mut prev_hash = BlockHash::all_zeros();
        for i in 0..10 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            prev_hash = block.block_hash();
            store.write_block(&block, i).unwrap();
        }

        // Try to find files to prune up to height 5
        // Since all blocks are in file 0 and height_last is 9, no files can be pruned
        let files = store.find_files_to_prune(5, 0, 0);
        assert!(files.is_empty(), "Cannot prune file 0 because it contains blocks up to height 9");

        // If we prune up to height 10 (beyond all blocks), file 0 should be prunable
        let files = store.find_files_to_prune(10, 0, 0);
        assert_eq!(files, vec![0], "File 0 should be prunable when prune height exceeds all blocks");
    }

    #[test]
    fn test_prune_to_target_low_height() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // With current_height < MIN_BLOCKS_TO_KEEP, no pruning should occur
        let (files, bytes) = store.prune_to_target(100, 550 * 1024 * 1024).unwrap();
        assert_eq!(files, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_prune_to_height_low_height() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // With current_height < MIN_BLOCKS_TO_KEEP, no pruning should occur
        let (files, bytes, height) = store.prune_to_height(500, 100).unwrap();
        assert_eq!(files, 0);
        assert_eq!(bytes, 0);
        assert_eq!(height, 0);
    }

    #[test]
    fn test_get_prune_height_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        assert_eq!(store.get_prune_height(), 0);
    }

    #[test]
    fn test_has_block_data_at_height_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Empty store has no data at any height
        assert!(!store.has_block_data_at_height(0));
        assert!(!store.has_block_data_at_height(100));
    }

    #[test]
    fn test_has_block_data_at_height_with_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Write blocks at heights 5-10
        let mut prev_hash = BlockHash::all_zeros();
        for i in 5..=10 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            prev_hash = block.block_hash();
            store.write_block(&block, i).unwrap();
        }

        // Heights 5-10 should have data
        for h in 5..=10 {
            assert!(store.has_block_data_at_height(h), "Height {} should have data", h);
        }

        // Heights outside range should not have data
        assert!(!store.has_block_data_at_height(0));
        assert!(!store.has_block_data_at_height(4));
        assert!(!store.has_block_data_at_height(11));
    }

    #[test]
    fn test_prune_one_file_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Pruning empty file returns 0 bytes
        let bytes = store.prune_one_file(0).unwrap();
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_prune_one_file_with_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        // Write some blocks
        let mut prev_hash = BlockHash::all_zeros();
        for i in 0..5 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            prev_hash = block.block_hash();
            store.write_block(&block, i).unwrap();
        }

        let usage_before = store.calculate_current_usage();
        assert!(usage_before > 0);

        // Mark file 0 as pruned
        let bytes_freed = store.prune_one_file(0).unwrap();
        assert!(bytes_freed > 0);

        // Usage should now be 0 (file info reset)
        let usage_after = store.calculate_current_usage();
        assert_eq!(usage_after, 0);
    }

    #[test]
    fn test_prune_stats() {
        let temp_dir = TempDir::new().unwrap();
        let store = BlockStore::new(temp_dir.path(), Network::Regtest).unwrap();

        let stats = PruneStats::default();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.pruned_files, 0);
        assert_eq!(stats.data_bytes, 0);
        assert_eq!(stats.undo_bytes, 0);
        assert_eq!(stats.prune_height, 0);
    }
}
