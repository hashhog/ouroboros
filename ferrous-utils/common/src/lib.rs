// Shared Bitcoin types with custom wrappers and serialization

pub mod types;
pub mod crypto;
pub mod serialize;

// Re-export all types for convenience
pub use types::{
    BlockHeaderWrapper, BlockWrapper, TransactionWrapper, TxInWrapper, TxOutWrapper,
    OutPointWrapper, UTXO, BlockMetadata,
};

// Re-export crypto functions
pub use crypto::{
    verify_ecdsa_signature, double_sha256, hash160, compute_merkle_root,
    bits_to_target, target_to_bits,
};

// Re-export serialization functions
pub use serialize::{
    BitcoinSerialize, BitcoinDeserialize, SerializeError,
    encode_varint, decode_varint,
    serialize_to_vec, deserialize_from_slice,
};
