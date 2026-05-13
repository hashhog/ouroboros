// Shared Bitcoin types with custom wrappers and serialization

pub mod crypto;
pub mod minisketch;
pub mod serialize;
pub mod types;

// Re-export all types for convenience
pub use types::{
    BlockHeaderWrapper, BlockMetadata, BlockStatus, BlockWrapper, OutPointWrapper,
    TransactionWrapper, TxInWrapper, TxOutWrapper, UTXO,
};

// Re-export crypto functions
pub use crypto::{
    bits_to_target, compute_merkle_root, double_sha256, hash160, target_to_bits,
    verify_ecdsa_signature, verify_ecdsa_signature_der,
};

// Re-export siphash for compact blocks
pub use crypto::siphash::{
    compute_siphash_key, siphash_2_4, PresaltedSipHasher, SipHasher,
};

// Re-export BIP324 types for v2 P2P transport
pub use crypto::bip324::{
    Bip324Cipher, Bip324Error, Bip324Session, EllSwiftPubKey, FSChaCha20, FSChaCha20Poly1305,
    HkdfSha256, compute_bip324_ecdh_secret, find_garbage_terminator, generate_garbage,
    ELLSWIFT_PUBKEY_LEN, GARBAGE_TERMINATOR_LEN, IGNORE_BIT, MAX_GARBAGE_LEN,
    PACKET_EXPANSION, POLY1305_TAGLEN, REKEY_INTERVAL, SESSION_ID_LEN,
};

// Re-export serialization functions
pub use serialize::{
    compress_amount, decode_corevarint, decode_varint, decompress_amount, deserialize_from_slice,
    encode_corevarint, encode_varint, serialize_to_vec, BitcoinDeserialize, BitcoinSerialize,
    SerializeError,
};

// Re-export minisketch for BIP330 Erlay
pub use minisketch::{
    compute_reconciliation_salt, compute_short_txid, estimate_sketch_capacity, gf_inv, gf_mul,
    gf_pow, gf_sq, Minisketch,
};
