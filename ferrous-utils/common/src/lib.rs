// Shared Bitcoin types with custom wrappers and serialization

pub mod types;

// Re-export all types for convenience
pub use types::{
    BlockHeaderWrapper, BlockWrapper, TransactionWrapper, TxInWrapper, TxOutWrapper,
    OutPointWrapper, UTXO, BlockMetadata,
};
