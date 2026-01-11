// Block validation modules

pub mod header;
pub mod pow;
pub mod transaction;
pub mod script;
pub mod block;

// Re-export functions for convenience
pub use header::{HeaderValidator, HeaderValidationError};
pub use pow::*;
pub use transaction::*;
pub use script::{ScriptInterpreter, ScriptError, ScriptType, Stack, identify_script_type, verify_signature_in_script, verify_witness};
pub use block::{BlockValidator, BlockValidationError};
