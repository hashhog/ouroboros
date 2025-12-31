// Bitcoin serialization with VarInt support

use crate::types::{
    BlockHeaderWrapper, BlockMetadata, BlockWrapper, OutPointWrapper, TransactionWrapper,
    TxInWrapper, TxOutWrapper, UTXO,
};
use bitcoin::{
    consensus::{Decodable, Encodable},
    Block, OutPoint, Transaction, TxIn, TxOut,
};

/// Error type for serialization operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializeError {
    /// Consensus encoding/decoding error
    Encode(String),
    /// Not enough data to decode
    InsufficientData,
    /// Invalid VarInt encoding
    InvalidVarInt,
    /// Custom error message
    Custom(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializeError::Encode(msg) => write!(f, "Encode error: {}", msg),
            SerializeError::InsufficientData => write!(f, "Insufficient data"),
            SerializeError::InvalidVarInt => write!(f, "Invalid VarInt encoding"),
            SerializeError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SerializeError {}

/// Encode a u64 as Bitcoin VarInt (compact size)
///
/// Bitcoin VarInt encoding:
/// - 0x00-0xfc: value is the number itself (1 byte)
/// - 0xfd: followed by 2 bytes (little-endian) for values 0xfd-0xffff
/// - 0xfe: followed by 4 bytes (little-endian) for values 0x10000-0xffffffff
/// - 0xff: followed by 8 bytes (little-endian) for values 0x100000000-0xffffffffffffffff
///
/// # Arguments
/// * `n` - The number to encode
///
/// # Returns
/// Encoded bytes
pub fn encode_varint(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut result = vec![0xfd];
            result.extend_from_slice(&(n as u16).to_le_bytes());
            result
        }
        0x10000..=0xffffffff => {
            let mut result = vec![0xfe];
            result.extend_from_slice(&(n as u32).to_le_bytes());
            result
        }
        _ => {
            let mut result = vec![0xff];
            result.extend_from_slice(&n.to_le_bytes());
            result
        }
    }
}

/// Decode a Bitcoin VarInt (compact size) from bytes
///
/// # Arguments
/// * `data` - The byte slice to decode from
///
/// # Returns
/// - `Ok((value, bytes_consumed))` on success
/// - `Err` if the data is invalid or insufficient
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), SerializeError> {
    if data.is_empty() {
        return Err(SerializeError::InsufficientData);
    }

    match data[0] {
        0x00..=0xfc => Ok((data[0] as u64, 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(SerializeError::InsufficientData);
            }
            let value = u16::from_le_bytes([data[1], data[2]]) as u64;
            if value < 0xfd {
                return Err(SerializeError::InvalidVarInt);
            }
            Ok((value, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(SerializeError::InsufficientData);
            }
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
            if value < 0x10000 {
                return Err(SerializeError::InvalidVarInt);
            }
            Ok((value, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(SerializeError::InsufficientData);
            }
            let value = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            if value < 0x100000000 {
                return Err(SerializeError::InvalidVarInt);
            }
            Ok((value, 9))
        }
    }
}

/// Trait for Bitcoin serialization
pub trait BitcoinSerialize {
    /// Serialize the type to bytes using Bitcoin consensus encoding
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError>;
}

/// Trait for Bitcoin deserialization
pub trait BitcoinDeserialize: Sized {
    /// Deserialize the type from bytes using Bitcoin consensus encoding
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError>;
}

// Implement BitcoinSerialize for all wrapper types

impl BitcoinSerialize for BlockHeaderWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for BlockHeaderWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let header = bitcoin::blockdata::block::Header::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((BlockHeaderWrapper::new(header), bytes_consumed))
    }
}

impl BitcoinSerialize for BlockWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for BlockWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let block = Block::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((BlockWrapper::new(block), bytes_consumed))
    }
}

impl BitcoinSerialize for TransactionWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for TransactionWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let tx = Transaction::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((TransactionWrapper::new(tx), bytes_consumed))
    }
}

impl BitcoinSerialize for TxInWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for TxInWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let txin = TxIn::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((TxInWrapper::new(txin), bytes_consumed))
    }
}

impl BitcoinSerialize for TxOutWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for TxOutWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let txout = TxOut::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((TxOutWrapper::new(txout), bytes_consumed))
    }
}

impl BitcoinSerialize for OutPointWrapper {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut encoder = Vec::new();
        self.inner()
            .consensus_encode(&mut encoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        Ok(encoder)
    }
}

impl BitcoinDeserialize for OutPointWrapper {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let mut decoder = &data[..];
        let outpoint = OutPoint::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let bytes_consumed = data.len() - decoder.len();
        Ok((OutPointWrapper::new(outpoint), bytes_consumed))
    }
}

impl BitcoinSerialize for UTXO {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        // Use the existing to_bytes implementation
        self.to_bytes()
            .map_err(|e| SerializeError::Encode(format!("{}", e)))
    }
}

impl BitcoinDeserialize for UTXO {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        // We need to track how many bytes were consumed
        let original_len = data.len();
        let mut decoder = &data[..];

        // Decode outpoint
        let outpoint = OutPoint::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let outpoint = OutPointWrapper::new(outpoint);

        let amount = u64::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let script_pubkey = bitcoin::ScriptBuf::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;

        // Decode Option<u32>
        let height = match u8::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?
        {
            0 => None,
            1 => Some(
                u32::consensus_decode(&mut decoder)
                    .map_err(|e| SerializeError::Encode(format!("{}", e)))?,
            ),
            _ => return Err(SerializeError::InvalidVarInt),
        };

        let is_coinbase = bool::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;

        let bytes_consumed = original_len - decoder.len();
        Ok((
            UTXO::new(outpoint, amount, script_pubkey, height, is_coinbase),
            bytes_consumed,
        ))
    }
}

impl BitcoinSerialize for BlockMetadata {
    fn bitcoin_serialize(&self) -> Result<Vec<u8>, SerializeError> {
        // Use the existing to_bytes implementation
        self.to_bytes()
            .map_err(|e| SerializeError::Encode(format!("{}", e)))
    }
}

impl BitcoinDeserialize for BlockMetadata {
    fn bitcoin_deserialize(data: &[u8]) -> Result<(Self, usize), SerializeError> {
        let original_len = data.len();
        let mut decoder = &data[..];

        let height = u32::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let chainwork = <[u8; 32]>::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;
        let timestamp = u32::consensus_decode(&mut decoder)
            .map_err(|e| SerializeError::Encode(format!("{}", e)))?;

        let bytes_consumed = original_len - decoder.len();
        Ok((
            BlockMetadata::new(height, chainwork, timestamp),
            bytes_consumed,
        ))
    }
}

// Helper functions

/// Serialize a type implementing BitcoinSerialize to a Vec<u8>
pub fn serialize_to_vec<T: BitcoinSerialize>(item: &T) -> Result<Vec<u8>, SerializeError> {
    item.bitcoin_serialize()
}

/// Deserialize a type implementing BitcoinDeserialize from a byte slice
pub fn deserialize_from_slice<T: BitcoinDeserialize>(data: &[u8]) -> Result<T, SerializeError> {
    let (result, _) = T::bitcoin_deserialize(data)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use hex;

    // Bitcoin Core test vectors
    // Genesis block header (first 80 bytes)
    const GENESIS_BLOCK_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    // Genesis coinbase transaction
    const GENESIS_COINBASE_TX_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[test]
    fn test_encode_varint() {
        // Test small values (1 byte)
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(1), vec![0x01]);
        assert_eq!(encode_varint(0xfc), vec![0xfc]);

        // Test medium values (3 bytes: 0xfd + 2 bytes)
        assert_eq!(encode_varint(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(encode_varint(0xffff), vec![0xfd, 0xff, 0xff]);

        // Test large values (5 bytes: 0xfe + 4 bytes)
        assert_eq!(encode_varint(0x10000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            encode_varint(0xffffffff),
            vec![0xfe, 0xff, 0xff, 0xff, 0xff]
        );

        // Test very large values (9 bytes: 0xff + 8 bytes)
        assert_eq!(
            encode_varint(0x100000000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_varint(0xffffffffffffffff),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn test_decode_varint() {
        // Test small values
        assert_eq!(decode_varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_varint(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_varint(&[0xfc]).unwrap(), (0xfc, 1));

        // Test medium values
        assert_eq!(decode_varint(&[0xfd, 0xfd, 0x00]).unwrap(), (0xfd, 3));
        assert_eq!(decode_varint(&[0xfd, 0xff, 0xff]).unwrap(), (0xffff, 3));

        // Test large values
        assert_eq!(
            decode_varint(&[0xfe, 0x00, 0x00, 0x01, 0x00]).unwrap(),
            (0x10000, 5)
        );
        assert_eq!(
            decode_varint(&[0xfe, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            (0xffffffff, 5)
        );

        // Test very large values
        assert_eq!(
            decode_varint(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap(),
            (0x100000000, 9)
        );
        assert_eq!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            (0xffffffffffffffff, 9)
        );
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = vec![
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffffffff,
            0x100000000,
            0xffffffffffffffff,
        ];

        for value in test_values {
            let encoded = encode_varint(value);
            let (decoded, bytes_consumed) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(bytes_consumed, encoded.len());
        }
    }

    #[test]
    fn test_decode_varint_errors() {
        // Insufficient data
        assert!(decode_varint(&[]).is_err());
        assert!(decode_varint(&[0xfd]).is_err());
        assert!(decode_varint(&[0xfe, 0x00]).is_err());
        assert!(decode_varint(&[0xff, 0x00, 0x00]).is_err());

        // Invalid encoding (value doesn't match prefix)
        assert!(decode_varint(&[0xfd, 0x00, 0x00]).is_err()); // 0 < 0xfd
        assert!(decode_varint(&[0xfe, 0xff, 0xff, 0x00, 0x00]).is_err()); // 0xffff < 0x10000
    }

    #[test]
    fn test_block_header_serialize() {
        // Test with genesis block header
        let header_bytes = hex::decode(GENESIS_BLOCK_HEADER_HEX).unwrap();
        let header =
            bitcoin::blockdata::block::Header::consensus_decode(&mut &header_bytes[..]).unwrap();
        let wrapper = BlockHeaderWrapper::new(header.clone());

        // Serialize
        let serialized = wrapper.bitcoin_serialize().unwrap();
        assert_eq!(serialized, header_bytes);

        // Deserialize
        let (deserialized, bytes_consumed) =
            BlockHeaderWrapper::bitcoin_deserialize(&serialized).unwrap();
        assert_eq!(bytes_consumed, serialized.len());
        assert_eq!(deserialized.block_hash(), wrapper.block_hash());
    }

    #[test]
    fn test_transaction_serialize() {
        // Test with genesis coinbase transaction
        let tx_bytes = hex::decode(GENESIS_COINBASE_TX_HEX).unwrap();
        let tx = Transaction::consensus_decode(&mut &tx_bytes[..]).unwrap();
        let wrapper = TransactionWrapper::new(tx.clone());

        // Serialize
        let serialized = wrapper.bitcoin_serialize().unwrap();
        assert_eq!(serialized, tx_bytes);

        // Deserialize
        let (deserialized, bytes_consumed) =
            TransactionWrapper::bitcoin_deserialize(&serialized).unwrap();
        assert_eq!(bytes_consumed, serialized.len());
        assert_eq!(deserialized.txid(), wrapper.txid());
    }

    #[test]
    fn test_utxo_serialize() {
        use bitcoin::ScriptBuf;
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        let utxo = UTXO::new(outpoint, 100000, script, Some(100), false);

        // Serialize
        let serialized = utxo.bitcoin_serialize().unwrap();
        assert!(!serialized.is_empty());

        // Deserialize
        let (deserialized, bytes_consumed) = UTXO::bitcoin_deserialize(&serialized).unwrap();
        assert_eq!(bytes_consumed, serialized.len());
        assert_eq!(deserialized.outpoint.txid(), utxo.outpoint.txid());
        assert_eq!(deserialized.amount, utxo.amount);
        assert_eq!(deserialized.height, utxo.height);
        assert_eq!(deserialized.is_coinbase, utxo.is_coinbase);
    }

    #[test]
    fn test_helper_functions() {
        use bitcoin::ScriptBuf;

        // Test serialize_to_vec
        let txid = bitcoin::Txid::from_byte_array([2u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 1);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let utxo = UTXO::new(outpoint, 50000, script, None, true);

        let serialized = serialize_to_vec(&utxo).unwrap();

        // Test deserialize_from_slice
        let deserialized: UTXO = deserialize_from_slice(&serialized).unwrap();
        assert_eq!(deserialized.outpoint.txid(), utxo.outpoint.txid());
        assert_eq!(deserialized.amount, utxo.amount);
    }

    #[test]
    fn test_block_metadata_serialize() {
        let chainwork = [1u8; 32];
        let metadata = BlockMetadata::new(100, chainwork, 1234567890);

        let serialized = metadata.bitcoin_serialize().unwrap();
        let (deserialized, bytes_consumed) =
            BlockMetadata::bitcoin_deserialize(&serialized).unwrap();

        assert_eq!(bytes_consumed, serialized.len());
        assert_eq!(deserialized.height, metadata.height);
        assert_eq!(deserialized.chainwork, metadata.chainwork);
        assert_eq!(deserialized.timestamp, metadata.timestamp);
    }
}
