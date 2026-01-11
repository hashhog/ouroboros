// Block validation modules

pub mod header;
pub mod pow;
pub mod transaction;
pub mod script;

// Re-export functions for convenience
pub use header::{HeaderValidator, HeaderValidationError};
pub use pow::*;
pub use transaction::*;
pub use script::{ScriptInterpreter, ScriptError, ScriptType, Stack, identify_script_type, verify_signature_in_script, verify_witness};
