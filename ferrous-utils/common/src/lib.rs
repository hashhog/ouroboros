// Shared Bitcoin types with custom wrappers and serialization

pub mod crypto;
pub mod serialize;
pub mod types;

// Re-export all types for convenience
pub use types::{
    BlockHeaderWrapper, BlockMetadata, BlockWrapper, OutPointWrapper, TransactionWrapper,
    TxInWrapper, TxOutWrapper, UTXO,
};

// Re-export crypto functions
pub use crypto::{
    bits_to_target, compute_merkle_root, double_sha256, hash160, target_to_bits,
    verify_ecdsa_signature,
};

// Re-export serialization functions
pub use serialize::{
    decode_varint, deserialize_from_slice, encode_varint, serialize_to_vec, BitcoinDeserialize,
    BitcoinSerialize, SerializeError,
};
