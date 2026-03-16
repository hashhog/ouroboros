// Block validation modules

pub mod header;
pub mod pow;
pub mod difficulty;
pub mod transaction;
pub mod script;
pub mod block;
pub mod sighash;
pub mod sequence_lock;
pub mod sigop;
pub mod headers_presync;

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
pub use sequence_lock::{
    SequenceLock, InputLockInfo,
    calculate_sequence_locks, evaluate_sequence_locks, check_sequence_locks,
    is_bip68_active, csv_activation_height, is_final_tx,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_GRANULARITY,
    SEQUENCE_FINAL, LOCKTIME_VERIFY_SEQUENCE, LOCKTIME_THRESHOLD,
};
pub use sigop::{
    get_transaction_sigop_cost, get_block_sigop_cost, get_legacy_sigop_count,
    get_p2sh_sigop_count, count_script_sigops, count_witness_sigops_for_input,
    MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR, MAX_PUBKEYS_PER_MULTISIG,
};
pub use difficulty::{
    get_next_work_required, calculate_next_work_required, calculate_next_work_required_bip94,
    permitted_difficulty_transition, target_to_bits, BlockIndexInfo,
    DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_TIMESPAN, TARGET_SPACING,
    POW_LIMIT_MAINNET, POW_LIMIT_TESTNET, POW_LIMIT_REGTEST,
};
pub use headers_presync::{
    HeadersSyncState, HeadersSyncPhase, HeadersSyncResult, CompressedHeader,
    MAX_HEADERS_PER_MESSAGE, MAX_FUTURE_BLOCK_TIME, MAX_BLOCKS_PER_SECOND,
};
