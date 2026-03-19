//! Flat file sequence abstraction for blk*.dat and rev*.dat files.
//!
//! This module implements Bitcoin Core's `FlatFileSeq` abstraction for managing
//! sequences of flat data files with automatic rollover when files exceed a
//! maximum size.
//!
//! # File Format
//!
//! Files are named with a prefix and 5-digit zero-padded sequence number:
//! - Block files: `blk00000.dat`, `blk00001.dat`, ...
//! - Undo files: `rev00000.dat`, `rev00001.dat`, ...
//!
//! # Reference
//!
//! See Bitcoin Core's `src/flatfile.cpp` and `src/flatfile.h`.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Maximum size of a block file (128 MiB).
/// Bitcoin Core uses 0x8000000 = 134,217,728 bytes, but we use 128 MiB.
pub const MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024;

/// Pre-allocation chunk size for block files (16 MiB).
pub const BLOCKFILE_CHUNK_SIZE: u64 = 16 * 1024 * 1024;

/// Pre-allocation chunk size for undo files (1 MiB).
pub const UNDOFILE_CHUNK_SIZE: u64 = 1024 * 1024;

/// Header size before each record: 4-byte magic + 4-byte size.
pub const STORAGE_HEADER_BYTES: u64 = 8;

/// Undo data overhead: header (8 bytes) + checksum (32 bytes).
pub const UNDO_DATA_DISK_OVERHEAD: u64 = 40;

/// Position within a flat file sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlatFilePos {
    /// File number (-1 indicates invalid/null position).
    pub file: i32,
    /// Byte position within the file.
    pub pos: u32,
}

impl FlatFilePos {
    /// Create a new file position.
    pub fn new(file: i32, pos: u32) -> Self {
        Self { file, pos }
    }

    /// Create a null/invalid position.
    pub fn null() -> Self {
        Self { file: -1, pos: 0 }
    }

    /// Check if this position is null/invalid.
    pub fn is_null(&self) -> bool {
        self.file == -1
    }
}

/// Error type for flat file operations.
#[derive(Error, Debug)]
pub enum FlatFileError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid position: file {file}, pos {pos}")]
    InvalidPosition { file: i32, pos: u32 },

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Out of space")]
    OutOfSpace,

    #[error("Invalid magic: expected {expected:08x}, got {actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("Invalid size: {0}")]
    InvalidSize(u32),

    #[error("Read error: expected {expected} bytes, got {actual}")]
    ShortRead { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, FlatFileError>;

/// A sequence of flat files with automatic numbering.
///
/// Manages files named `{prefix}{nnnnn}.dat` where `nnnnn` is a 5-digit
/// zero-padded sequence number.
#[derive(Debug, Clone)]
pub struct FlatFileSeq {
    /// Directory containing the files.
    dir: PathBuf,
    /// File prefix ("blk" or "rev").
    prefix: String,
    /// Pre-allocation chunk size.
    chunk_size: u64,
}

impl FlatFileSeq {
    /// Create a new flat file sequence.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory containing the files
    /// * `prefix` - File prefix (e.g., "blk" or "rev")
    /// * `chunk_size` - Pre-allocation chunk size in bytes
    pub fn new<P: AsRef<Path>>(dir: P, prefix: &str, chunk_size: u64) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            prefix: prefix.to_string(),
            chunk_size,
        }
    }

    /// Get the file path for a given position.
    pub fn file_name(&self, pos: &FlatFilePos) -> PathBuf {
        self.dir
            .join(format!("{}{:05}.dat", self.prefix, pos.file))
    }

    /// Open a file for reading or writing.
    ///
    /// # Arguments
    ///
    /// * `pos` - Position to open at
    /// * `read_only` - If true, open for reading; otherwise for read/write
    ///
    /// # Returns
    ///
    /// File handle seeked to the specified position.
    pub fn open(&self, pos: &FlatFilePos, read_only: bool) -> Result<File> {
        if pos.is_null() {
            return Err(FlatFileError::InvalidPosition {
                file: pos.file,
                pos: pos.pos,
            });
        }

        let path = self.file_name(pos);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            create_directories_if_needed(parent)?;
        }

        let mut file = if read_only {
            OpenOptions::new().read(true).open(&path)?
        } else {
            // Try to open existing file for read/write
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => f,
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                    // Create new file
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&path)?
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Seek to position
        if pos.pos > 0 {
            file.seek(SeekFrom::Start(pos.pos as u64))?;
        }

        Ok(file)
    }

    /// Allocate space in a file, pre-allocating in chunks if needed.
    ///
    /// # Arguments
    ///
    /// * `pos` - Current position
    /// * `add_size` - Number of bytes to add
    ///
    /// # Returns
    ///
    /// Number of bytes allocated (may be 0 if no allocation needed).
    pub fn allocate(&self, pos: &FlatFilePos, add_size: u64) -> Result<u64> {
        let current_pos = pos.pos as u64;
        let new_pos = current_pos + add_size;

        // Calculate chunks
        let old_chunks = (current_pos + self.chunk_size - 1) / self.chunk_size;
        let new_chunks = (new_pos + self.chunk_size - 1) / self.chunk_size;

        if new_chunks > old_chunks {
            let path = self.file_name(pos);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)?;

            let new_size = new_chunks * self.chunk_size;
            file.set_len(new_size)?;

            Ok(new_size - (old_chunks * self.chunk_size))
        } else {
            Ok(0)
        }
    }

    /// Flush and optionally finalize a file.
    ///
    /// # Arguments
    ///
    /// * `pos` - Position in file
    /// * `finalize` - If true, truncate to exact size
    pub fn flush(&self, pos: &FlatFilePos, finalize: bool) -> Result<()> {
        if pos.is_null() {
            return Ok(());
        }

        let path = self.file_name(pos);
        if !path.exists() {
            return Ok(());
        }

        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        if finalize {
            // Truncate to exact size
            file.set_len(pos.pos as u64)?;
        }

        file.sync_all()?;
        Ok(())
    }

    /// Get the size of a file.
    pub fn file_size(&self, file_num: i32) -> Result<u64> {
        let pos = FlatFilePos::new(file_num, 0);
        let path = self.file_name(&pos);

        if path.exists() {
            Ok(std::fs::metadata(&path)?.len())
        } else {
            Ok(0)
        }
    }

    /// Check if a file exists.
    pub fn file_exists(&self, file_num: i32) -> bool {
        let pos = FlatFilePos::new(file_num, 0);
        self.file_name(&pos).exists()
    }

    /// Get the directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Get the file prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

/// Create directories if they don't exist.
fn create_directories_if_needed<P: AsRef<Path>>(path: P) -> io::Result<()> {
    if !path.as_ref().exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_flat_file_pos_new() {
        let pos = FlatFilePos::new(1, 100);
        assert_eq!(pos.file, 1);
        assert_eq!(pos.pos, 100);
        assert!(!pos.is_null());
    }

    #[test]
    fn test_flat_file_pos_null() {
        let pos = FlatFilePos::null();
        assert!(pos.is_null());
        assert_eq!(pos.file, -1);
    }

    #[test]
    fn test_flat_file_seq_file_name() {
        let temp_dir = TempDir::new().unwrap();
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", BLOCKFILE_CHUNK_SIZE);

        let pos = FlatFilePos::new(0, 0);
        let path = seq.file_name(&pos);
        assert!(path.ends_with("blk00000.dat"));

        let pos = FlatFilePos::new(12345, 0);
        let path = seq.file_name(&pos);
        assert!(path.ends_with("blk12345.dat"));
    }

    #[test]
    fn test_flat_file_seq_open_create() {
        let temp_dir = TempDir::new().unwrap();
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", BLOCKFILE_CHUNK_SIZE);

        let pos = FlatFilePos::new(0, 0);
        let mut file = seq.open(&pos, false).unwrap();

        // Write some data
        file.write_all(b"test data").unwrap();
        file.sync_all().unwrap();

        // Verify file was created
        assert!(seq.file_exists(0));
        assert!(seq.file_size(0).unwrap() > 0);
    }

    #[test]
    fn test_flat_file_seq_open_at_position() {
        let temp_dir = TempDir::new().unwrap();
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", BLOCKFILE_CHUNK_SIZE);

        // Create file with some data
        let pos = FlatFilePos::new(0, 0);
        let mut file = seq.open(&pos, false).unwrap();
        file.write_all(b"0123456789").unwrap();
        drop(file);

        // Open at position 5
        let pos = FlatFilePos::new(0, 5);
        let mut file = seq.open(&pos, true).unwrap();
        let mut buf = [0u8; 5];
        file.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"56789");
    }

    #[test]
    fn test_flat_file_seq_allocate() {
        let temp_dir = TempDir::new().unwrap();
        let chunk_size = 1024;
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", chunk_size);

        // Create file
        let pos = FlatFilePos::new(0, 0);
        let file = seq.open(&pos, false).unwrap();
        drop(file);

        // Allocate beyond first chunk
        let allocated = seq.allocate(&pos, 2000).unwrap();
        assert!(allocated > 0);

        // File should be at least 2 chunks
        let size = seq.file_size(0).unwrap();
        assert!(size >= chunk_size * 2);
    }

    #[test]
    fn test_flat_file_seq_flush_finalize() {
        let temp_dir = TempDir::new().unwrap();
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", 1024);

        // Create file with data
        let pos = FlatFilePos::new(0, 0);
        let mut file = seq.open(&pos, false).unwrap();
        file.write_all(b"test").unwrap();
        drop(file);

        // Allocate more space
        seq.allocate(&pos, 2048).unwrap();

        // File should be larger than 4 bytes
        let size_before = seq.file_size(0).unwrap();
        assert!(size_before >= 1024);

        // Finalize at position 4
        let final_pos = FlatFilePos::new(0, 4);
        seq.flush(&final_pos, true).unwrap();

        // File should now be exactly 4 bytes
        let size_after = seq.file_size(0).unwrap();
        assert_eq!(size_after, 4);
    }

    #[test]
    fn test_flat_file_seq_open_null_position() {
        let temp_dir = TempDir::new().unwrap();
        let seq = FlatFileSeq::new(temp_dir.path(), "blk", BLOCKFILE_CHUNK_SIZE);

        let pos = FlatFilePos::null();
        let result = seq.open(&pos, true);
        assert!(result.is_err());
    }
}
