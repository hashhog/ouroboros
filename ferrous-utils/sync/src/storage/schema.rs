//! RocksDB database schema for Bitcoin blockchain storage
//!
//! This module defines the column families and key encoding functions for storing
//! Bitcoin blockchain data in RocksDB.
//!
//! # Column Families
//!
//! ## BLOCKS_CF
//! Stores full block data by block hash.
//!
//! **Key**: `block_hash` (32 bytes, BlockHash as bytes)
//! **Value**: Serialized `BlockWrapper` (using Bitcoin consensus encoding)
//!
//! **Example**:
//! ```ignore
//! // Key: [32 bytes of block hash in internal byte order]
//! // Value: Serialized BlockWrapper
//! ```
//!
//! ## BLOCK_INDEX_CF
//! Maps block height to block metadata for the **active chain** — one entry
//! per height, pointing at whichever block is currently on the best chain.
//!
//! **Key**: `height` (4 bytes, u32 little-endian)
//! **Value**: `[32-byte block hash][Serialized BlockMetadata]`
//!
//! **Example**:
//! ```ignore
//! // Key: encode_height(100) -> [0x64, 0x00, 0x00, 0x00]
//! // Value: [32 bytes hash] ++ Serialized BlockMetadata { height: 100, ... }
//! ```
//!
//! ## BLOCK_INDEX_BY_HASH_CF
//! Maps **block hash** to block metadata — mirrors Bitcoin Core's
//! `BlockMap = std::unordered_map<uint256, CBlockIndex>`.  All known blocks
//! (active chain AND competing forks at the same height) have an entry here,
//! so a fork block submitted via `submitblock` is never silently discarded.
//!
//! **Key**: `block_hash` (32 bytes, internal byte order)
//! **Value**: Serialized `BlockMetadata` (44 bytes fixed-width)
//!
//! **Example**:
//! ```ignore
//! // Key: [32 bytes of block hash in internal byte order]
//! // Value: Serialized BlockMetadata { height: 100, chainwork: [...], timestamp: ... }
//! ```
//!
//! ## CHAINSTATE_CF
//! Stores the UTXO set (unspent transaction outputs).
//!
//! **Key**: `encode_outpoint(txid, vout)` (36 bytes: 32-byte txid + 4-byte vout)
//! **Value**: Serialized `UTXO` (outpoint, amount, script_pubkey, height, is_coinbase)
//!
//! **Example**:
//! ```ignore
//! // Key: encode_outpoint(txid, 0) -> [32 bytes txid] || [4 bytes vout]
//! // Value: Serialized UTXO
//! ```
//!
//! ## SPENT_CF
//! Tracks which transaction spent each UTXO (for handling reorganizations).
//!
//! **Key**: `encode_outpoint(txid, vout)` (36 bytes: 32-byte txid + 4-byte vout)
//! **Value**: Spending transaction ID (32 bytes, Txid as bytes)
//!
//! **Example**:
//! ```ignore
//! // Key: encode_outpoint(prev_txid, 0) -> [32 bytes prev_txid] || [4 bytes vout]
//! // Value: [32 bytes spending_txid]
//! ```
//!
//! ## META_CF
//! Stores database metadata (best block, chain state, etc.).
//!
//! **Key**: Metadata key (string)
//! **Value**: Metadata value (varies by key)
//!
//! **Common keys**:
//! - `"best_block_hash"`: Best block hash (32 bytes)
//! - `"best_height"`: Best block height (4 bytes, u32 little-endian)
//! - `"chainstate_version"`: Chainstate version (4 bytes, u32 little-endian)
//!
//! **Example**:
//! ```ignore
//! // Key: b"best_block_hash"
//! // Value: [32 bytes block hash]
//! // Key: b"best_height"
//! // Value: encode_height(100) -> [0x64, 0x00, 0x00, 0x00]
//! ```

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::Txid;

/// Column family name for storing full blocks
pub const BLOCKS_CF: &str = "blocks";

/// Column family name for block index (height -> BlockMetadata) — active chain only.
pub const BLOCK_INDEX_CF: &str = "block_index";

/// Column family name for hash-keyed block index — all known blocks including
/// competing forks.  Mirrors Core's `BlockMap = std::unordered_map<uint256, CBlockIndex>`.
///
/// Key:   block_hash (32 bytes, internal byte order)
/// Value: Serialized `BlockMetadata` (44 bytes, same encoding as BlockMetadata::to_bytes())
pub const BLOCK_INDEX_BY_HASH_CF: &str = "block_index_by_hash";

/// Column family name for chainstate (UTXO set)
pub const CHAINSTATE_CF: &str = "chainstate";

/// Column family name for spent outputs tracking (for reorgs)
pub const SPENT_CF: &str = "spent";

/// Column family name for metadata
pub const META_CF: &str = "meta";

/// Column family name for transaction index (txid -> block location)
///
/// **Key**: `txid` (32 bytes, Txid as bytes)
/// **Value**: `[block_hash (32 bytes)][height (4 bytes LE)][tx_position (4 bytes LE)]`
///
/// Enables O(1) lookup of any confirmed transaction by its txid.
/// Populated during `apply_block()`, removed during `disconnect_block()`.
pub const TX_INDEX_CF: &str = "tx_index";

/// Column family name for undo data (block height -> BlockUndo)
///
/// **Key**: `height` (4 bytes, u32 little-endian)
/// **Value**: `[serialized BlockUndo][32-byte checksum]`
///
/// Stores the UTXOs consumed by each block's transactions. Used during
/// chain reorganizations to restore spent UTXOs when disconnecting blocks.
///
/// The checksum is SHA256d(prev_block_hash || block_undo_data) to verify
/// the undo data matches the expected chain position.
pub const UNDO_CF: &str = "undo";

/// Column family name for header-only store (hash -> header data)
///
/// **Key**: `block_hash` (32 bytes, internal byte order)
/// **Value**: `[80-byte raw header][4-byte nTx u32 LE]`
///
/// Stores the 80-byte serialized block header plus the transaction count.
/// Populated from `connect_block_from_bytes` (full blocks) and from the
/// P2P headers-first sync path (headers without block bodies).  Allows
/// `getblockheader` to serve historical blocks whose full body is absent
/// from BLOCKS_CF (e.g. after an assumeutxo snapshot load).
///
/// The nTx field is 0 when only the header is available (no full block).
pub const HEADERS_CF: &str = "headers";

/// Metadata keys
pub mod meta_keys {
    /// Key for best block hash in META_CF
    pub const BEST_BLOCK_HASH: &[u8] = b"best_block_hash";

    /// Key for best block height in META_CF
    pub const BEST_HEIGHT: &[u8] = b"best_height";

    /// Key for chainstate version in META_CF
    pub const CHAINSTATE_VERSION: &[u8] = b"chainstate_version";

    /// Key for pruning state: lowest block height whose data is still available
    pub const PRUNE_HEIGHT: &[u8] = b"prune_height";

    /// Key for whether pruning is enabled
    pub const PRUNING_ENABLED: &[u8] = b"pruning_enabled";

    /// Key for two-phase commit crash recovery.
    ///
    /// Written before apply_block touches UTXO set (Phase 1), deleted after
    /// BEST_BLOCK_HASH/BEST_HEIGHT are updated (Phase 2).
    ///
    /// Value format: `[32-byte old_tip_hash][4-byte old_tip_height][32-byte new_block_hash][4-byte new_height]`
    /// (72 bytes total).
    ///
    /// If this key exists on startup, a crash occurred mid-apply and the
    /// database must be rolled back to `old_tip_hash` / `old_tip_height`.
    pub const HEAD_BLOCKS: &[u8] = b"head_blocks";

    /// Marker for assumeUTXO snapshot load in progress (FIX-D, chainstate
    /// atomicity family 2026-05-26).
    ///
    /// Written by `snapshot_load_begin` BEFORE per-coin UTXO writes begin,
    /// deleted by `snapshot_load_commit` AFTER the final tip + metadata
    /// batch lands. Distinct from `HEAD_BLOCKS` because the recovery action
    /// is different: a partial snapshot load cannot be "rolled back" to a
    /// prior tip (the per-coin chunks have already half-overwritten the
    /// chainstate), so recovery must `clear_chainstate()` entirely. The
    /// snapshot can then be re-loaded from the source file by the operator.
    ///
    /// Value format: `[32-byte base_blockhash][4-byte base_height]` (36 bytes).
    ///
    /// If this key exists on startup, the previous process crashed during
    /// `loadtxoutset` and the chainstate is in a mixed
    /// partial-snapshot / partial-old state. `recover_from_crash` clears
    /// the chainstate, deletes this marker, and logs loudly so the
    /// operator knows to re-run `loadtxoutset`.
    pub const SNAPSHOT_LOAD_IN_PROGRESS: &[u8] = b"snapshot_load_in_progress";
}

/// Encode a block hash as a 32-byte key
///
/// # Arguments
/// * `block_hash` - Block hash to encode
///
/// # Returns
/// 32-byte array containing the block hash in internal byte order
///
/// # Example
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::BlockHash;
/// use sync::storage::schema::encode_block_hash;
///
/// let hash = BlockHash::from_byte_array([0u8; 32]);
/// let key = encode_block_hash(&hash);
/// assert_eq!(key.len(), 32);
/// ```
pub fn encode_block_hash(block_hash: &BlockHash) -> [u8; 32] {
    *block_hash.as_byte_array()
}

/// Decode a block hash from a 32-byte key
///
/// # Arguments
/// * `bytes` - 32-byte array containing the block hash
///
/// # Returns
/// BlockHash decoded from the bytes
///
/// # Example
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::BlockHash;
/// use sync::storage::schema::{encode_block_hash, decode_block_hash};
///
/// let hash = BlockHash::from_byte_array([1u8; 32]);
/// let encoded = encode_block_hash(&hash);
/// let decoded = decode_block_hash(&encoded);
/// assert_eq!(decoded, hash);
/// ```
pub fn decode_block_hash(bytes: &[u8; 32]) -> BlockHash {
    BlockHash::from_byte_array(*bytes)
}

/// Encode a transaction ID as a 32-byte key
///
/// # Arguments
/// * `txid` - Transaction ID to encode
///
/// # Returns
/// 32-byte array containing the transaction ID in internal byte order
///
/// # Example
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::Txid;
/// use sync::storage::schema::encode_txid;
///
/// let txid = Txid::from_byte_array([0u8; 32]);
/// let key = encode_txid(&txid);
/// assert_eq!(key.len(), 32);
/// ```
pub fn encode_txid(txid: &Txid) -> [u8; 32] {
    *txid.as_byte_array()
}

/// Decode a transaction ID from a 32-byte key
///
/// # Arguments
/// * `bytes` - 32-byte array containing the transaction ID
///
/// # Returns
/// Txid decoded from the bytes
///
/// # Example
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::Txid;
/// use sync::storage::schema::{encode_txid, decode_txid};
///
/// let txid = Txid::from_byte_array([2u8; 32]);
/// let encoded = encode_txid(&txid);
/// let decoded = decode_txid(&encoded);
/// assert_eq!(decoded, txid);
/// ```
pub fn decode_txid(bytes: &[u8; 32]) -> Txid {
    Txid::from_byte_array(*bytes)
}

/// Encode an outpoint (txid + vout) as a 36-byte key
///
/// The key is constructed as: [32 bytes txid] || [4 bytes vout (little-endian)]
///
/// # Arguments
/// * `txid` - Transaction ID as 32-byte array
/// * `vout` - Output index (u32)
///
/// # Returns
/// 36-byte array: 32 bytes of txid followed by 4 bytes of vout (little-endian)
///
/// # Example
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::Txid;
/// use sync::storage::schema::{encode_outpoint, decode_outpoint};
///
/// let txid_obj = Txid::from_byte_array([1u8; 32]);
/// let txid_bytes = *txid_obj.as_byte_array();
/// let vout = 5u32;
/// let key = encode_outpoint(&txid_bytes, vout);
/// assert_eq!(key.len(), 36);
///
/// let (decoded_txid_bytes, decoded_vout) = decode_outpoint(&key);
/// assert_eq!(decoded_txid_bytes, txid_bytes);
/// assert_eq!(decoded_vout, vout);
/// ```
pub fn encode_outpoint(txid: &[u8; 32], vout: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..32].copy_from_slice(txid);
    key[32..36].copy_from_slice(&vout.to_le_bytes());
    key
}

/// Decode an outpoint from a 36-byte key
///
/// # Arguments
/// * `bytes` - 36-byte array: 32 bytes of txid followed by 4 bytes of vout (little-endian)
///
/// # Returns
/// Tuple of (txid as [u8; 32], vout as u32)
///
/// # Example
/// ```
/// use sync::storage::schema::{encode_outpoint, decode_outpoint};
///
/// let txid_bytes = [3u8; 32];
/// let vout = 10u32;
/// let encoded = encode_outpoint(&txid_bytes, vout);
/// let (decoded_txid_bytes, decoded_vout) = decode_outpoint(&encoded);
/// assert_eq!(decoded_txid_bytes, txid_bytes);
/// assert_eq!(decoded_vout, vout);
/// ```
pub fn decode_outpoint(bytes: &[u8; 36]) -> ([u8; 32], u32) {
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes[0..32]);

    let vout = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);

    (txid, vout)
}

/// Encode a block height as a 4-byte key (little-endian)
///
/// # Arguments
/// * `height` - Block height (u32)
///
/// # Returns
/// 4-byte array containing the height in little-endian format
///
/// # Example
/// ```
/// use sync::storage::schema::{encode_height, decode_height};
///
/// let height = 100u32;
/// let key = encode_height(height);
/// assert_eq!(key, [0x64, 0x00, 0x00, 0x00]);
///
/// let decoded = decode_height(&key);
/// assert_eq!(decoded, height);
/// ```
pub fn encode_height(height: u32) -> [u8; 4] {
    height.to_le_bytes()
}

/// Decode a block height from a 4-byte key (little-endian)
///
/// # Arguments
/// * `bytes` - 4-byte array containing the height in little-endian format
///
/// # Returns
/// Block height as u32
///
/// # Example
/// ```
/// use sync::storage::schema::{encode_height, decode_height};
///
/// let height = 12345u32;
/// let encoded = encode_height(height);
/// let decoded = decode_height(&encoded);
/// assert_eq!(decoded, height);
/// ```
pub fn decode_height(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// Get all column family names as a vector
///
/// This is useful for opening a RocksDB database with all column families.
///
/// # Returns
/// Vector of column family name strings
///
/// # Example
/// ```
/// use sync::storage::schema::get_column_families;
///
/// let cfs = get_column_families();
/// assert!(cfs.contains(&"blocks".to_string()));
/// assert!(cfs.contains(&"chainstate".to_string()));
/// ```
pub fn get_column_families() -> Vec<String> {
    vec![
        BLOCKS_CF.to_string(),
        BLOCK_INDEX_CF.to_string(),
        BLOCK_INDEX_BY_HASH_CF.to_string(),
        CHAINSTATE_CF.to_string(),
        SPENT_CF.to_string(),
        META_CF.to_string(),
        TX_INDEX_CF.to_string(),
        UNDO_CF.to_string(),
        HEADERS_CF.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_encode_decode_block_hash() {
        let hash = BlockHash::from_byte_array([0x12u8; 32]);
        let encoded = encode_block_hash(&hash);
        let decoded = decode_block_hash(&encoded);
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_encode_decode_txid() {
        let txid = Txid::from_byte_array([0x34u8; 32]);
        let encoded = encode_txid(&txid);
        let decoded = decode_txid(&encoded);
        assert_eq!(decoded, txid);
    }

    #[test]
    fn test_encode_decode_outpoint() {
        let txid_bytes = [0x56u8; 32];
        let vout = 42u32;

        let encoded = encode_outpoint(&txid_bytes, vout);
        assert_eq!(encoded.len(), 36);
        assert_eq!(&encoded[0..32], &txid_bytes);
        assert_eq!(
            u32::from_le_bytes([encoded[32], encoded[33], encoded[34], encoded[35]]),
            vout
        );

        let (decoded_txid, decoded_vout) = decode_outpoint(&encoded);
        assert_eq!(decoded_txid, txid_bytes);
        assert_eq!(decoded_vout, vout);
    }

    #[test]
    fn test_encode_decode_outpoint_edge_cases() {
        // Test vout = 0
        let txid_bytes = [0x78u8; 32];
        let encoded = encode_outpoint(&txid_bytes, 0);
        let (decoded_txid, decoded_vout) = decode_outpoint(&encoded);
        assert_eq!(decoded_txid, txid_bytes);
        assert_eq!(decoded_vout, 0);

        // Test vout = u32::MAX
        let encoded = encode_outpoint(&txid_bytes, u32::MAX);
        let (decoded_txid, decoded_vout) = decode_outpoint(&encoded);
        assert_eq!(decoded_txid, txid_bytes);
        assert_eq!(decoded_vout, u32::MAX);
    }

    #[test]
    fn test_encode_decode_height() {
        let height = 12345u32;
        let encoded = encode_height(height);
        assert_eq!(encoded, [0x39, 0x30, 0x00, 0x00]);

        let decoded = decode_height(&encoded);
        assert_eq!(decoded, height);
    }

    #[test]
    fn test_encode_decode_height_edge_cases() {
        // Test height = 0
        let encoded = encode_height(0);
        assert_eq!(encoded, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(decode_height(&encoded), 0);

        // Test height = u32::MAX
        let encoded = encode_height(u32::MAX);
        assert_eq!(encoded, [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(decode_height(&encoded), u32::MAX);
    }

    #[test]
    fn test_column_families() {
        let cfs = get_column_families();
        assert_eq!(cfs.len(), 9);
        assert!(cfs.contains(&BLOCKS_CF.to_string()));
        assert!(cfs.contains(&BLOCK_INDEX_CF.to_string()));
        assert!(cfs.contains(&BLOCK_INDEX_BY_HASH_CF.to_string()));
        assert!(cfs.contains(&CHAINSTATE_CF.to_string()));
        assert!(cfs.contains(&SPENT_CF.to_string()));
        assert!(cfs.contains(&META_CF.to_string()));
        assert!(cfs.contains(&TX_INDEX_CF.to_string()));
        assert!(cfs.contains(&UNDO_CF.to_string()));
    }

    #[test]
    fn test_meta_keys() {
        assert_eq!(meta_keys::BEST_BLOCK_HASH, b"best_block_hash");
        assert_eq!(meta_keys::BEST_HEIGHT, b"best_height");
        assert_eq!(meta_keys::CHAINSTATE_VERSION, b"chainstate_version");
        assert_eq!(meta_keys::HEAD_BLOCKS, b"head_blocks");
        assert_eq!(
            meta_keys::SNAPSHOT_LOAD_IN_PROGRESS,
            b"snapshot_load_in_progress",
        );
    }
}
