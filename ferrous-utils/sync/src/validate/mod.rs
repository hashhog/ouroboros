// Block validation modules

pub mod header;
pub mod pow;
pub mod transaction;
pub mod script;
pub mod block;
pub mod sighash;

// Re-export functions for convenience
pub use header::{HeaderValidator, HeaderValidationError};
pub use pow::*;
pub use transaction::*;
pub use script::{ScriptInterpreter, ScriptError, ScriptType, Stack, identify_script_type, verify_signature_in_script, verify_witness};
pub use block::{BlockValidator, BlockValidationError};
pub use sighash::{
    signature_hash_legacy, find_and_delete, remove_codeseparators,
    prepare_script_code, serialize_signature_push, script_code_from_codeseparator,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, OP_CODESEPARATOR,
};
