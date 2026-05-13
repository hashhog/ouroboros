//! Undo data structures for chain reorganizations.
//!
//! This module implements Bitcoin Core's undo data format, which stores the
//! UTXOs consumed by each block's transactions. When a block is disconnected
//! during a chain reorganization, the undo data restores the spent UTXOs to
//! the chainstate.
//!
//! # Data Structures
//!
//! - [`Coin`]: A UTXO entry with metadata (value, scriptPubKey, height, is_coinbase)
//! - [`TxUndo`]: Undo data for a single transaction (the UTXOs it spent)
//! - [`BlockUndo`]: Undo data for a block (one `TxUndo` per non-coinbase tx)
//!
//! # File Format
//!
//! Undo data is stored in `rev{nnnnn}.dat` files alongside `blk{nnnnn}.dat`.
//! Each block's undo record has:
//! - Network magic (4 bytes)
//! - Undo data size (4 bytes LE)
//! - Block undo data (variable)
//! - Checksum: SHA256d(prev_block_hash || block_undo_data) (32 bytes)
//!
//! The checksum includes the previous block hash to tie the undo data to a
//! specific chain position, preventing replay attacks during reorgs.
//!
//! # Reference
//!
//! See Bitcoin Core's `src/undo.h` and `src/node/blockstorage.cpp` for the
//! canonical implementation.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

use common::decode_corevarint;

/// Encode a u64 as Bitcoin Core's MSB-base-128 VarInt and append to the buffer.
///
/// This is the format used by Core's TxInUndoFormatter / Coin::Serialize (undo.h, coins.h),
/// NOT the CompactSize (0xfd/0xfe/0xff prefix) used in P2P messages.
fn encode_corevarint(n: u64, buf: &mut Vec<u8>) {
    common::encode_corevarint(n, buf);
}

/// Error type for undo operations
#[derive(Error, Debug)]
pub enum UndoError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid undo data format: {0}")]
    InvalidFormat(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Block undo not found")]
    NotFound,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, UndoError>;

/// A UTXO (Coin) entry stored in undo data.
///
/// This mirrors Bitcoin Core's `Coin` class, storing all information needed
/// to restore a spent UTXO during chain reorganization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    /// Value in satoshis
    pub value: u64,
    /// Script public key
    pub script_pubkey: ScriptBuf,
    /// Block height where this UTXO was created
    pub height: u32,
    /// Whether this is a coinbase output
    pub is_coinbase: bool,
}

impl Coin {
    /// Create a new Coin
    pub fn new(value: u64, script_pubkey: ScriptBuf, height: u32, is_coinbase: bool) -> Self {
        Self {
            value,
            script_pubkey,
            height,
            is_coinbase,
        }
    }

    /// Serialize the Coin to bytes.
    ///
    /// Format matches Bitcoin Core's `TxInUndoFormatter` (undo.h):
    /// - VARINT(height * 2 + is_coinbase)   — MSB-base-128 VarInt (NOT CompactSize)
    /// - If height > 0: 1 byte dummy (0x00) for backward compatibility
    /// - Using<TxOutCompression>: VARINT(CompressAmount(value)) + compressed script
    ///   (script compression is out of scope here; raw script is stored for now
    ///    but code/value now use the correct Core VarInt encoding)
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Encode height and coinbase flag as a single Core VarInt
        let code = (self.height as u64) * 2 + if self.is_coinbase { 1 } else { 0 };
        encode_corevarint(code, &mut data);

        // Compatibility byte for height > 0
        if self.height > 0 {
            data.push(0x00);
        }

        // Encode value as VARINT(CompressAmount(value)) — matching TxOutCompression.
        let compressed_value = common::compress_amount(self.value);
        encode_corevarint(compressed_value, &mut data);

        // Encode script: length as Core VarInt + raw bytes.
        let script_bytes = self.script_pubkey.as_bytes();
        encode_corevarint(script_bytes.len() as u64, &mut data);
        data.extend_from_slice(script_bytes);

        data
    }

    /// Deserialize a Coin from bytes.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        // Decode height and coinbase flag using Core VarInt
        let (code, consumed) = decode_corevarint(&data[offset..])
            .map_err(|e| UndoError::InvalidFormat(format!("Failed to decode coin code: {}", e)))?;
        offset += consumed;

        let height = (code >> 1) as u32;
        let is_coinbase = (code & 1) == 1;

        // Skip compatibility byte for height > 0
        if height > 0 {
            if offset >= data.len() {
                return Err(UndoError::InvalidFormat(
                    "Missing compatibility byte".to_string(),
                ));
            }
            offset += 1;
        }

        // Decode value: VARINT(CompressAmount(value)) — decompress after decoding.
        let (compressed_value, consumed) = decode_corevarint(&data[offset..])
            .map_err(|e| UndoError::InvalidFormat(format!("Failed to decode value: {}", e)))?;
        offset += consumed;
        let value = common::decompress_amount(compressed_value);

        // Decode script length as Core VarInt
        let (script_len, consumed) = decode_corevarint(&data[offset..])
            .map_err(|e| UndoError::InvalidFormat(format!("Failed to decode script length: {}", e)))?;
        offset += consumed;

        if offset + script_len as usize > data.len() {
            return Err(UndoError::InvalidFormat(
                "Script extends beyond data".to_string(),
            ));
        }
        let script_pubkey = ScriptBuf::from_bytes(data[offset..offset + script_len as usize].to_vec());
        offset += script_len as usize;

        Ok((
            Self {
                value,
                script_pubkey,
                height,
                is_coinbase,
            },
            offset,
        ))
    }
}

/// Undo information for a single transaction.
///
/// Contains the `Coin` for each input the transaction spent.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TxUndo {
    /// The UTXOs spent by this transaction's inputs
    pub prev_outputs: Vec<Coin>,
}

impl TxUndo {
    /// Create a new empty TxUndo
    pub fn new() -> Self {
        Self {
            prev_outputs: Vec::new(),
        }
    }

    /// Create a TxUndo with the given spent outputs
    pub fn with_outputs(prev_outputs: Vec<Coin>) -> Self {
        Self { prev_outputs }
    }

    /// Serialize the TxUndo to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Number of prev_outputs — Core VarInt
        encode_corevarint(self.prev_outputs.len() as u64, &mut data);

        // Each prev_output
        for coin in &self.prev_outputs {
            data.extend(coin.serialize());
        }

        data
    }

    /// Deserialize a TxUndo from bytes.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        // Number of prev_outputs — Core VarInt
        let (count, consumed) = decode_corevarint(&data[offset..])
            .map_err(|e| UndoError::InvalidFormat(format!("Failed to decode tx undo count: {}", e)))?;
        offset += consumed;

        let mut prev_outputs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (coin, consumed) = Coin::deserialize(&data[offset..])?;
            offset += consumed;
            prev_outputs.push(coin);
        }

        Ok((Self { prev_outputs }, offset))
    }
}

/// Undo information for an entire block.
///
/// Contains a `TxUndo` for each non-coinbase transaction in the block.
/// The coinbase transaction has no inputs to spend, so it has no undo data.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlockUndo {
    /// Undo data for each non-coinbase transaction in the block
    pub tx_undo: Vec<TxUndo>,
}

impl BlockUndo {
    /// Create a new empty BlockUndo
    pub fn new() -> Self {
        Self { tx_undo: Vec::new() }
    }

    /// Create a BlockUndo with the given transaction undo data
    pub fn with_tx_undo(tx_undo: Vec<TxUndo>) -> Self {
        Self { tx_undo }
    }

    /// Check if the block undo is empty
    pub fn is_empty(&self) -> bool {
        self.tx_undo.is_empty()
    }

    /// Serialize the BlockUndo to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Number of tx_undo entries — Core VarInt
        encode_corevarint(self.tx_undo.len() as u64, &mut data);

        // Each tx_undo
        for tx_undo in &self.tx_undo {
            data.extend(tx_undo.serialize());
        }

        data
    }

    /// Deserialize a BlockUndo from bytes.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        // Number of tx_undo entries — Core VarInt
        let (count, consumed) = decode_corevarint(&data[offset..])
            .map_err(|e| UndoError::InvalidFormat(format!("Failed to decode block undo count: {}", e)))?;
        offset += consumed;

        let mut tx_undo = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (undo, consumed) = TxUndo::deserialize(&data[offset..])?;
            offset += consumed;
            tx_undo.push(undo);
        }

        Ok((Self { tx_undo }, offset))
    }

    /// Compute the checksum for this block undo data.
    ///
    /// The checksum is SHA256d(prev_block_hash || serialized_block_undo).
    /// This ties the undo data to its chain position.
    pub fn compute_checksum(&self, prev_block_hash: &[u8; 32]) -> [u8; 32] {
        let data = self.serialize();
        let mut to_hash = Vec::with_capacity(32 + data.len());
        to_hash.extend_from_slice(prev_block_hash);
        to_hash.extend(data);
        *sha256d::Hash::hash(&to_hash).as_byte_array()
    }

    /// Verify the checksum matches the expected value.
    pub fn verify_checksum(&self, prev_block_hash: &[u8; 32], expected: &[u8; 32]) -> bool {
        &self.compute_checksum(prev_block_hash) == expected
    }
}

/// Manager for reading and writing undo files (rev*.dat).
pub struct UndoFileManager {
    /// Base directory for undo files
    blocks_dir: PathBuf,
    /// Network magic bytes
    magic: [u8; 4],
}

impl UndoFileManager {
    /// Create a new UndoFileManager.
    ///
    /// # Arguments
    /// * `blocks_dir` - Directory containing blk*.dat and rev*.dat files
    /// * `magic` - Network magic bytes (mainnet: 0xf9beb4d9)
    pub fn new<P: AsRef<Path>>(blocks_dir: P, magic: [u8; 4]) -> Self {
        Self {
            blocks_dir: blocks_dir.as_ref().to_path_buf(),
            magic,
        }
    }

    /// Get the path to a rev*.dat file.
    fn rev_file_path(&self, file_num: u32) -> PathBuf {
        self.blocks_dir.join(format!("rev{:05}.dat", file_num))
    }

    /// Write a block's undo data to the appropriate rev*.dat file.
    ///
    /// Returns the file position (file_num, pos) where the data was written.
    pub fn write_block_undo(
        &self,
        file_num: u32,
        block_undo: &BlockUndo,
        prev_block_hash: &[u8; 32],
    ) -> Result<u64> {
        let path = self.rev_file_path(file_num);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Open file for appending
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let pos = file.seek(SeekFrom::End(0))?;

        // Serialize undo data
        let undo_data = block_undo.serialize();
        let checksum = block_undo.compute_checksum(prev_block_hash);

        // Write record: magic + size + undo_data + checksum
        file.write_all(&self.magic)?;
        file.write_all(&(undo_data.len() as u32).to_le_bytes())?;
        file.write_all(&undo_data)?;
        file.write_all(&checksum)?;

        file.sync_all()?;

        Ok(pos)
    }

    /// Read a block's undo data from a rev*.dat file.
    ///
    /// # Arguments
    /// * `file_num` - The rev file number
    /// * `pos` - Position within the file (after magic + size prefix)
    /// * `prev_block_hash` - Hash of the previous block, used to verify checksum
    pub fn read_block_undo(
        &self,
        file_num: u32,
        pos: u64,
        prev_block_hash: &[u8; 32],
    ) -> Result<BlockUndo> {
        let path = self.rev_file_path(file_num);
        let mut file = File::open(&path)?;

        // Seek to position
        file.seek(SeekFrom::Start(pos))?;

        // Read magic
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != self.magic {
            return Err(UndoError::InvalidFormat(format!(
                "Invalid magic: expected {:?}, got {:?}",
                self.magic, magic
            )));
        }

        // Read size
        let mut size_bytes = [0u8; 4];
        file.read_exact(&mut size_bytes)?;
        let size = u32::from_le_bytes(size_bytes) as usize;

        // Read undo data
        let mut undo_data = vec![0u8; size];
        file.read_exact(&mut undo_data)?;

        // Read checksum
        let mut checksum = [0u8; 32];
        file.read_exact(&mut checksum)?;

        // Deserialize
        let (block_undo, _) = BlockUndo::deserialize(&undo_data)?;

        // Verify checksum
        if !block_undo.verify_checksum(prev_block_hash, &checksum) {
            return Err(UndoError::ChecksumMismatch);
        }

        Ok(block_undo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use tempfile::tempdir;

    fn create_test_coin() -> Coin {
        Coin::new(
            50_000_000,
            ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]),
            100,
            false,
        )
    }

    /// TP-1 fix: code for height=127, is_coinbase=false is 254.
    /// Core writes VarInt(254) = [0x80, 0x7e]; old code wrote CompactSize(254) = [0xfd, 0xfe, 0x00].
    #[test]
    fn test_coin_serialize_uses_corevarint_not_compactsize() {
        let coin = Coin::new(
            1_000,  // small amount
            ScriptBuf::from_bytes(vec![0x51]),
            127,    // height=127 => code=254 — the canonical TP-1 divergence point
            false,
        );
        let serialized = coin.serialize();
        // First byte: VarInt(254) starts with 0x80 (continuation byte)
        assert_eq!(
            serialized[0], 0x80,
            "TP-1 fix: first byte of VarInt(254) must be 0x80 (Core format), not 0xfd (CompactSize)"
        );
        assert_eq!(
            serialized[1], 0x7e,
            "TP-1 fix: second byte of VarInt(254) must be 0x7e"
        );
        // Old CompactSize would have written [0xfd, 0xfe, 0x00] — verify it is NOT that.
        assert_ne!(serialized[0], 0xfd, "CompactSize prefix 0xfd must NOT appear for code=254");
    }

    /// VarInt(253) != CompactSize(253): canonical demonstration from audit test G11.
    #[test]
    fn test_corevarint_253_differs_from_compactsize() {
        let mut vi = Vec::new();
        encode_corevarint(253, &mut vi);
        // Core's VarInt(253) = [0x80, 0x7d]
        assert_eq!(vi, vec![0x80, 0x7d]);
        // CompactSize(253) = [0xfd, 0xfd, 0x00] — must NOT equal
        assert_ne!(vi, vec![0xfd_u8, 0xfd, 0x00]);
    }

    #[test]
    fn test_coin_serialize_roundtrip() {
        let coin = create_test_coin();
        let serialized = coin.serialize();
        let (deserialized, _) = Coin::deserialize(&serialized).unwrap();
        assert_eq!(coin, deserialized);
    }

    #[test]
    fn test_coin_coinbase() {
        let coin = Coin::new(
            5_000_000_000,
            ScriptBuf::from_bytes(vec![0x51]), // OP_1
            0,
            true,
        );
        let serialized = coin.serialize();
        let (deserialized, _) = Coin::deserialize(&serialized).unwrap();
        assert_eq!(coin, deserialized);
        assert!(deserialized.is_coinbase);
    }

    #[test]
    fn test_tx_undo_serialize_roundtrip() {
        let tx_undo = TxUndo::with_outputs(vec![
            create_test_coin(),
            Coin::new(100_000_000, ScriptBuf::from_bytes(vec![0x52]), 200, false),
        ]);
        let serialized = tx_undo.serialize();
        let (deserialized, _) = TxUndo::deserialize(&serialized).unwrap();
        assert_eq!(tx_undo, deserialized);
    }

    #[test]
    fn test_block_undo_serialize_roundtrip() {
        let block_undo = BlockUndo::with_tx_undo(vec![
            TxUndo::with_outputs(vec![create_test_coin()]),
            TxUndo::with_outputs(vec![
                Coin::new(10_000, ScriptBuf::from_bytes(vec![0x00]), 50, false),
                Coin::new(20_000, ScriptBuf::from_bytes(vec![0x51]), 60, false),
            ]),
        ]);
        let serialized = block_undo.serialize();
        let (deserialized, _) = BlockUndo::deserialize(&serialized).unwrap();
        assert_eq!(block_undo, deserialized);
    }

    #[test]
    fn test_block_undo_checksum() {
        let block_undo = BlockUndo::with_tx_undo(vec![TxUndo::with_outputs(vec![create_test_coin()])]);
        let prev_hash = [0xabu8; 32];

        let checksum = block_undo.compute_checksum(&prev_hash);
        assert!(block_undo.verify_checksum(&prev_hash, &checksum));

        // Wrong hash should fail
        let wrong_hash = [0xcdu8; 32];
        assert!(!block_undo.verify_checksum(&wrong_hash, &checksum));
    }

    #[test]
    fn test_undo_file_manager_write_read() {
        let dir = tempdir().unwrap();
        let manager = UndoFileManager::new(dir.path(), [0xf9, 0xbe, 0xb4, 0xd9]);

        let block_undo = BlockUndo::with_tx_undo(vec![
            TxUndo::with_outputs(vec![create_test_coin()]),
        ]);
        let prev_hash = [0x12u8; 32];

        // Write
        let pos = manager.write_block_undo(0, &block_undo, &prev_hash).unwrap();
        assert_eq!(pos, 0); // First entry in empty file

        // Read
        let read_undo = manager.read_block_undo(0, pos, &prev_hash).unwrap();
        assert_eq!(block_undo, read_undo);
    }

    #[test]
    fn test_undo_file_manager_checksum_verification() {
        let dir = tempdir().unwrap();
        let manager = UndoFileManager::new(dir.path(), [0xf9, 0xbe, 0xb4, 0xd9]);

        let block_undo = BlockUndo::with_tx_undo(vec![
            TxUndo::with_outputs(vec![create_test_coin()]),
        ]);
        let prev_hash = [0x12u8; 32];
        let wrong_hash = [0x34u8; 32];

        let pos = manager.write_block_undo(0, &block_undo, &prev_hash).unwrap();

        // Reading with wrong prev_hash should fail checksum
        let result = manager.read_block_undo(0, pos, &wrong_hash);
        assert!(matches!(result, Err(UndoError::ChecksumMismatch)));
    }

    #[test]
    fn test_empty_block_undo() {
        let block_undo = BlockUndo::new();
        assert!(block_undo.is_empty());

        let serialized = block_undo.serialize();
        let (deserialized, _) = BlockUndo::deserialize(&serialized).unwrap();
        assert_eq!(block_undo, deserialized);
        assert!(deserialized.is_empty());
    }
}
