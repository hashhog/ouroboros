//! Signature operation (sigop) cost calculation for block weight enforcement.
//!
//! Implements BIP141 witness sigop discount: legacy/P2SH sigops cost 4 weight units
//! each (WITNESS_SCALE_FACTOR), while witness sigops cost 1 weight unit each.
//!
//! Reference: Bitcoin Core consensus/tx_verify.cpp GetTransactionSigOpCost()

use bitcoin::Transaction;
use crate::storage::BlockchainDB;

// ============================================================================
// Constants (from Bitcoin Core consensus/consensus.h)
// ============================================================================

/// Maximum block sigop cost (BIP141)
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;

/// Witness scale factor for weight calculations (BIP141)
pub const WITNESS_SCALE_FACTOR: i64 = 4;

/// Maximum number of public keys per CHECKMULTISIG (legacy)
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Size of witness v0 key hash (P2WPKH)
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;

/// Size of witness v0 script hash (P2WSH)
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

// ============================================================================
// Opcode byte constants (for raw script parsing)
// ============================================================================

const BYTE_OP_0: u8 = 0x00;
const BYTE_OP_1: u8 = 0x51;
const BYTE_OP_16: u8 = 0x60;
const BYTE_OP_PUSHDATA1: u8 = 0x4c;
const BYTE_OP_PUSHDATA2: u8 = 0x4d;
const BYTE_OP_PUSHDATA4: u8 = 0x4e;
const BYTE_OP_CHECKSIG: u8 = 0xac;
const BYTE_OP_CHECKSIGVERIFY: u8 = 0xad;
const BYTE_OP_CHECKMULTISIG: u8 = 0xae;
const BYTE_OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const BYTE_OP_HASH160: u8 = 0xa9;
const BYTE_OP_EQUAL: u8 = 0x87;

// ============================================================================
// Script pattern detection
// ============================================================================

/// Check if script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL
fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == BYTE_OP_HASH160
        && script[1] == 0x14  // push 20 bytes
        && script[22] == BYTE_OP_EQUAL
}

/// Check if script is a witness program (OP_0..OP_16 followed by 2-40 byte push)
///
/// Returns (version, program) if it's a witness program, None otherwise.
///
/// Reference: Bitcoin Core script/script.cpp CScript::IsWitnessProgram()
fn parse_witness_program(script: &[u8]) -> Option<(i32, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }

    // First byte must be OP_0 (0x00) or OP_1..OP_16 (0x51..0x60)
    let version_byte = script[0];
    let version = if version_byte == BYTE_OP_0 {
        0
    } else if version_byte >= BYTE_OP_1 && version_byte <= BYTE_OP_16 {
        (version_byte - BYTE_OP_1 + 1) as i32
    } else {
        return None;
    };

    // Second byte is the push length (must be 2-40)
    let push_len = script[1] as usize;
    if push_len < 2 || push_len > 40 {
        return None;
    }

    // Script must be exactly version_byte + push_len_byte + program
    if script.len() != 2 + push_len {
        return None;
    }

    Some((version, &script[2..]))
}

/// Check if script is push-only (for P2SH scriptSig validation)
fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        pc += 1;

        if opcode > BYTE_OP_16 {
            return false;
        }

        // Skip over pushed data
        let data_len = if opcode == 0 {
            0
        } else if opcode <= 0x4b {
            opcode as usize
        } else if opcode == BYTE_OP_PUSHDATA1 {
            if pc >= script.len() { return false; }
            let len = script[pc] as usize;
            pc += 1;
            len
        } else if opcode == BYTE_OP_PUSHDATA2 {
            if pc + 2 > script.len() { return false; }
            let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            len
        } else if opcode == BYTE_OP_PUSHDATA4 {
            if pc + 4 > script.len() { return false; }
            let len = u32::from_le_bytes([script[pc], script[pc + 1], script[pc + 2], script[pc + 3]]) as usize;
            pc += 4;
            len
        } else {
            // OP_1NEGATE, OP_RESERVED, OP_1..OP_16 - no data
            0
        };

        if pc + data_len > script.len() {
            return false;
        }
        pc += data_len;
    }
    true
}

/// Extract the last pushed data element from a push-only script.
///
/// For P2SH, this extracts the redeem script from the scriptSig.
fn get_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut pc = 0;
    let mut last_data = Vec::new();

    while pc < script.len() {
        let opcode = script[pc];
        pc += 1;

        if opcode == 0 {
            // OP_0: push empty
            last_data = Vec::new();
        } else if opcode <= 0x4b {
            // Direct push
            let len = opcode as usize;
            if pc + len > script.len() { return None; }
            last_data = script[pc..pc + len].to_vec();
            pc += len;
        } else if opcode == BYTE_OP_PUSHDATA1 {
            if pc >= script.len() { return None; }
            let len = script[pc] as usize;
            pc += 1;
            if pc + len > script.len() { return None; }
            last_data = script[pc..pc + len].to_vec();
            pc += len;
        } else if opcode == BYTE_OP_PUSHDATA2 {
            if pc + 2 > script.len() { return None; }
            let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            if pc + len > script.len() { return None; }
            last_data = script[pc..pc + len].to_vec();
            pc += len;
        } else if opcode == BYTE_OP_PUSHDATA4 {
            if pc + 4 > script.len() { return None; }
            let len = u32::from_le_bytes([
                script[pc], script[pc + 1], script[pc + 2], script[pc + 3]
            ]) as usize;
            pc += 4;
            if pc + len > script.len() { return None; }
            last_data = script[pc..pc + len].to_vec();
            pc += len;
        } else if opcode == 0x4f {
            // OP_1NEGATE: push -1
            last_data = vec![0x81];
        } else if opcode >= BYTE_OP_1 && opcode <= BYTE_OP_16 {
            // OP_1..OP_16: push 1..16
            last_data = vec![opcode - BYTE_OP_1 + 1];
        }
        // OP_RESERVED (0x50) doesn't push data
    }

    Some(last_data)
}

// ============================================================================
// Sigop counting functions
// ============================================================================

/// Count sigops in a script, optionally using accurate multisig counting.
///
/// When `accurate` is true, CHECKMULTISIG counts the actual number of pubkeys
/// based on the preceding OP_N opcode. When false, it counts MAX_PUBKEYS_PER_MULTISIG (20).
///
/// Reference: Bitcoin Core script/script.cpp CScript::GetSigOpCount()
pub fn count_script_sigops(script: &[u8], accurate: bool) -> usize {
    let mut count = 0;
    let mut pc = 0;
    let mut last_opcode: Option<u8> = None;

    while pc < script.len() {
        let opcode = script[pc];
        pc += 1;

        // Skip data for push opcodes
        let data_len = if opcode == 0 {
            0
        } else if opcode <= 0x4b {
            opcode as usize
        } else if opcode == BYTE_OP_PUSHDATA1 {
            if pc >= script.len() { break; }
            let len = script[pc] as usize;
            pc += 1;
            len
        } else if opcode == BYTE_OP_PUSHDATA2 {
            if pc + 2 > script.len() { break; }
            let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            len
        } else if opcode == BYTE_OP_PUSHDATA4 {
            if pc + 4 > script.len() { break; }
            let len = u32::from_le_bytes([
                script[pc], script[pc + 1], script[pc + 2], script[pc + 3]
            ]) as usize;
            pc += 4;
            len
        } else {
            0
        };

        if pc + data_len > script.len() {
            break;
        }
        pc += data_len;

        // Count sigops
        match opcode {
            BYTE_OP_CHECKSIG | BYTE_OP_CHECKSIGVERIFY => {
                count += 1;
            }
            BYTE_OP_CHECKMULTISIG | BYTE_OP_CHECKMULTISIGVERIFY => {
                if accurate {
                    // Check if preceding opcode is OP_1..OP_16
                    if let Some(prev) = last_opcode {
                        if prev >= BYTE_OP_1 && prev <= BYTE_OP_16 {
                            // Decode the number of pubkeys
                            count += (prev - BYTE_OP_1 + 1) as usize;
                        } else {
                            count += MAX_PUBKEYS_PER_MULTISIG;
                        }
                    } else {
                        count += MAX_PUBKEYS_PER_MULTISIG;
                    }
                } else {
                    count += MAX_PUBKEYS_PER_MULTISIG;
                }
            }
            _ => {}
        }

        last_opcode = Some(opcode);
    }

    count
}

/// Count legacy sigops in a transaction (from scriptSig and scriptPubKey).
///
/// This is the "old-fashioned" (pre-0.6) sigop count, not accurate for P2SH.
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetLegacySigOpCount()
pub fn get_legacy_sigop_count(tx: &Transaction) -> usize {
    let mut count = 0;

    // Count sigops in all inputs (scriptSig)
    for input in &tx.input {
        count += count_script_sigops(input.script_sig.as_bytes(), false);
    }

    // Count sigops in all outputs (scriptPubKey)
    for output in &tx.output {
        count += count_script_sigops(output.script_pubkey.as_bytes(), false);
    }

    count
}

/// Count P2SH sigops by extracting redeem scripts from scriptSigs.
///
/// For each input spending a P2SH output, extracts the redeem script
/// (last push in scriptSig) and counts sigops in it.
///
/// Returns 0 for coinbase transactions.
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetP2SHSigOpCount()
pub fn get_p2sh_sigop_count(tx: &Transaction, db: &BlockchainDB) -> usize {
    if tx.is_coinbase() {
        return 0;
    }

    let mut count = 0;

    for input in &tx.input {
        // Look up the previous output's scriptPubKey
        if let Ok(Some(utxo)) = db.get_utxo(&input.previous_output) {
            let script_pubkey = utxo.script_pubkey.as_bytes();

            // Check if it's P2SH
            if is_p2sh(script_pubkey) {
                let script_sig = input.script_sig.as_bytes();

                // scriptSig must be push-only for P2SH
                if is_push_only(script_sig) {
                    // Extract the redeem script (last push)
                    if let Some(redeem_script) = get_last_push(script_sig) {
                        // Count sigops in the redeem script (accurate mode)
                        count += count_script_sigops(&redeem_script, true);
                    }
                }
            }
        }
    }

    count
}

/// Count witness sigops for a single input.
///
/// For witness v0 (P2WPKH/P2WSH):
/// - P2WPKH (20-byte program): 1 sigop
/// - P2WSH (32-byte program): count sigops in witness script (last witness element)
///
/// Reference: Bitcoin Core script/interpreter.cpp WitnessSigOps()
fn count_witness_sigops(witness_version: i32, witness_program: &[u8], witness: &bitcoin::Witness) -> usize {
    if witness_version == 0 {
        // P2WPKH: 20-byte program = 1 sigop
        if witness_program.len() == WITNESS_V0_KEYHASH_SIZE {
            return 1;
        }

        // P2WSH: 32-byte program = count sigops in witness script
        if witness_program.len() == WITNESS_V0_SCRIPTHASH_SIZE && !witness.is_empty() {
            // The witness script is the last element on the witness stack
            if let Some(witness_script) = witness.last() {
                return count_script_sigops(witness_script, true);
            }
        }
    }

    // Future witness versions (v1+ for Taproot, etc.) return 0 for now
    // Taproot uses schnorr which is 1 sigop per signature but handled differently
    0
}

/// Count all witness sigops for an input, checking both native and P2SH-wrapped witness.
///
/// Reference: Bitcoin Core script/interpreter.cpp CountWitnessSigOps()
pub fn count_witness_sigops_for_input(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &bitcoin::Witness,
) -> usize {
    // Check for native witness program (scriptPubKey is witness program)
    if let Some((version, program)) = parse_witness_program(script_pubkey) {
        return count_witness_sigops(version, program, witness);
    }

    // Check for P2SH-wrapped witness program
    if is_p2sh(script_pubkey) && is_push_only(script_sig) {
        if let Some(redeem_script) = get_last_push(script_sig) {
            if let Some((version, program)) = parse_witness_program(&redeem_script) {
                return count_witness_sigops(version, program, witness);
            }
        }
    }

    0
}

// ============================================================================
// Main sigop cost calculation
// ============================================================================

/// Calculate the total signature operation cost for a transaction.
///
/// This implements the BIP141 witness sigop discount:
/// - Legacy sigops cost WITNESS_SCALE_FACTOR (4) weight units each
/// - P2SH redeem script sigops cost WITNESS_SCALE_FACTOR (4) weight units each
/// - Witness sigops cost 1 weight unit each
///
/// The total block sigop cost must not exceed MAX_BLOCK_SIGOPS_COST (80,000).
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetTransactionSigOpCost()
pub fn get_transaction_sigop_cost(
    tx: &Transaction,
    db: &BlockchainDB,
    verify_p2sh: bool,
    verify_witness: bool,
) -> i64 {
    // Start with legacy sigops * WITNESS_SCALE_FACTOR
    let mut sigop_cost = (get_legacy_sigop_count(tx) as i64) * WITNESS_SCALE_FACTOR;

    // Coinbase has no inputs to check
    if tx.is_coinbase() {
        return sigop_cost;
    }

    // Add P2SH sigops * WITNESS_SCALE_FACTOR
    if verify_p2sh {
        sigop_cost += (get_p2sh_sigop_count(tx, db) as i64) * WITNESS_SCALE_FACTOR;
    }

    // Add witness sigops (no multiplier - they're already "discounted")
    if verify_witness {
        for input in &tx.input {
            // Look up the previous output's scriptPubKey
            if let Ok(Some(utxo)) = db.get_utxo(&input.previous_output) {
                let script_pubkey = utxo.script_pubkey.as_bytes();
                let script_sig = input.script_sig.as_bytes();

                sigop_cost += count_witness_sigops_for_input(
                    script_sig,
                    script_pubkey,
                    &input.witness,
                ) as i64;
            }
        }
    }

    sigop_cost
}

/// Calculate total sigop cost for a block.
///
/// Returns the sum of sigop costs for all transactions in the block.
/// This value must not exceed MAX_BLOCK_SIGOPS_COST (80,000).
pub fn get_block_sigop_cost(
    transactions: &[Transaction],
    db: &BlockchainDB,
    verify_p2sh: bool,
    verify_witness: bool,
) -> i64 {
    let mut total_cost = 0i64;

    for tx in transactions {
        total_cost += get_transaction_sigop_cost(tx, db, verify_p2sh, verify_witness);
    }

    total_cost
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::{
        count_script_sigops, get_legacy_sigop_count, get_transaction_sigop_cost,
        get_block_sigop_cost, count_witness_sigops, is_p2sh, parse_witness_program,
        MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR,
    };
    use crate::storage::BlockchainDB;
    use bitcoin::{Amount, ScriptBuf, TxIn, TxOut, Transaction, Witness};
    use bitcoin::transaction::{Version, Sequence};
    use bitcoin::absolute::LockTime;
    use bitcoin::opcodes::all::*;
    use bitcoin::blockdata::script::Builder;
    use std::sync::Arc;
    use tempdir::TempDir;

    fn create_test_db() -> (TempDir, Arc<BlockchainDB>) {
        let temp_dir = TempDir::new("sigop_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        (temp_dir, db)
    }

    // -------------------------------------------------------------------------
    // count_script_sigops tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sigop_count_checksig() {
        // OP_CHECKSIG = 1 sigop
        let script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), false), 1);
        assert_eq!(count_script_sigops(script.as_bytes(), true), 1);
    }

    #[test]
    fn test_sigop_count_checksigverify() {
        // OP_CHECKSIGVERIFY = 1 sigop
        let script = Builder::new()
            .push_opcode(OP_CHECKSIGVERIFY)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), false), 1);
    }

    #[test]
    fn test_sigop_count_checkmultisig_inaccurate() {
        // OP_CHECKMULTISIG without accurate mode = 20 sigops
        let script = Builder::new()
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), false), 20);
    }

    #[test]
    fn test_sigop_count_checkmultisig_accurate_with_op_n() {
        // OP_3 OP_CHECKMULTISIG with accurate mode = 3 sigops
        let script = Builder::new()
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), true), 3);
    }

    #[test]
    fn test_sigop_count_checkmultisig_accurate_no_op_n() {
        // OP_CHECKMULTISIG alone with accurate mode = 20 sigops (fallback)
        let script = Builder::new()
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), true), 20);
    }

    #[test]
    fn test_sigop_count_2of3_multisig() {
        // Standard 2-of-3 multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        // The OP_3 before CHECKMULTISIG tells us there are 3 pubkeys
        let script = Builder::new()
            .push_int(2)
            .push_slice(&[0x02; 33])  // compressed pubkey 1
            .push_slice(&[0x02; 33])  // compressed pubkey 2
            .push_slice(&[0x02; 33])  // compressed pubkey 3
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        // Accurate mode: 3 sigops (from the OP_3)
        assert_eq!(count_script_sigops(script.as_bytes(), true), 3);
        // Inaccurate mode: 20 sigops (max)
        assert_eq!(count_script_sigops(script.as_bytes(), false), 20);
    }

    #[test]
    fn test_sigop_count_multiple_checksigs() {
        // Script with multiple CHECKSIG operations
        let script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), false), 3);
    }

    #[test]
    fn test_sigop_count_p2pkh() {
        // Standard P2PKH: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        let script = Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 20])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert_eq!(count_script_sigops(script.as_bytes(), false), 1);
    }

    // -------------------------------------------------------------------------
    // is_p2sh tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_p2sh() {
        // Valid P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 20])
            .push_opcode(OP_EQUAL)
            .into_script();
        assert!(is_p2sh(script.as_bytes()));
    }

    #[test]
    fn test_not_p2sh_wrong_length() {
        let script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 19])  // wrong length
            .push_opcode(OP_EQUAL)
            .into_script();
        assert!(!is_p2sh(script.as_bytes()));
    }

    // -------------------------------------------------------------------------
    // parse_witness_program tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_witness_v0_p2wpkh() {
        // P2WPKH: OP_0 <20 bytes>
        let script = Builder::new()
            .push_opcode(OP_PUSHBYTES_0)
            .push_slice(&[0u8; 20])
            .into_script();
        let result = parse_witness_program(script.as_bytes());
        assert!(result.is_some());
        let (version, program) = result.unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 20);
    }

    #[test]
    fn test_parse_witness_v0_p2wsh() {
        // P2WSH: OP_0 <32 bytes>
        let script = Builder::new()
            .push_opcode(OP_PUSHBYTES_0)
            .push_slice(&[0u8; 32])
            .into_script();
        let result = parse_witness_program(script.as_bytes());
        assert!(result.is_some());
        let (version, program) = result.unwrap();
        assert_eq!(version, 0);
        assert_eq!(program.len(), 32);
    }

    #[test]
    fn test_parse_witness_v1_taproot() {
        // Taproot: OP_1 <32 bytes>
        let script = Builder::new()
            .push_int(1)
            .push_slice(&[0u8; 32])
            .into_script();
        let result = parse_witness_program(script.as_bytes());
        assert!(result.is_some());
        let (version, program) = result.unwrap();
        assert_eq!(version, 1);
        assert_eq!(program.len(), 32);
    }

    // -------------------------------------------------------------------------
    // get_legacy_sigop_count tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_legacy_sigop_count_simple() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new().push_opcode(OP_CHECKSIG).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: Builder::new().push_opcode(OP_CHECKSIG).into_script(),
            }],
        };
        // 1 in input + 1 in output = 2
        assert_eq!(get_legacy_sigop_count(&tx), 2);
    }

    // -------------------------------------------------------------------------
    // Witness sigop tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_witness_sigops_p2wpkh() {
        // P2WPKH (20-byte program) = 1 sigop
        let program = [0u8; 20];
        let witness = Witness::from_slice(&[vec![0u8; 71], vec![0u8; 33]]);  // sig, pubkey
        assert_eq!(count_witness_sigops(0, &program, &witness), 1);
    }

    #[test]
    fn test_witness_sigops_p2wsh_checksig() {
        // P2WSH with witness script containing CHECKSIG = 1 sigop
        let witness_script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let program = [0u8; 32];  // 32-byte program = P2WSH
        let witness = Witness::from_slice(&[
            vec![0u8; 71],  // signature
            witness_script.to_bytes(),  // witness script (last element)
        ]);

        assert_eq!(count_witness_sigops(0, &program, &witness), 1);
    }

    #[test]
    fn test_witness_sigops_p2wsh_2of3_multisig() {
        // P2WSH with 2-of-3 multisig witness script
        let witness_script = Builder::new()
            .push_int(2)
            .push_slice(&[0x02; 33])
            .push_slice(&[0x02; 33])
            .push_slice(&[0x02; 33])
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let program = [0u8; 32];
        let witness = Witness::from_slice(&[
            vec![],  // dummy for CHECKMULTISIG bug
            vec![0u8; 71],  // sig1
            vec![0u8; 71],  // sig2
            witness_script.to_bytes(),
        ]);

        // Accurate counting: OP_3 before CHECKMULTISIG = 3 sigops
        assert_eq!(count_witness_sigops(0, &program, &witness), 3);
    }

    // -------------------------------------------------------------------------
    // Transaction sigop cost tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_transaction_sigop_cost_legacy_only() {
        let (_temp_dir, db) = create_test_db();

        // Transaction with only legacy sigops
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new().push_opcode(OP_CHECKSIG).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // 1 sigop * 4 (witness scale factor) = 4
        let cost = get_transaction_sigop_cost(&tx, &db, false, false);
        assert_eq!(cost, 4);
    }

    #[test]
    fn test_transaction_sigop_cost_coinbase() {
        let (_temp_dir, db) = create_test_db();

        // Coinbase transaction (has null prevout)
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),  // height encoding
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000_000),
                script_pubkey: Builder::new()
                    .push_opcode(OP_CHECKSIG)
                    .into_script(),
            }],
        };

        // Output has 1 CHECKSIG, input has none
        // 1 * 4 = 4
        let cost = get_transaction_sigop_cost(&tx, &db, true, true);
        assert_eq!(cost, 4);
    }

    // -------------------------------------------------------------------------
    // Block weight tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_block_sigop_cost_under_limit() {
        let (_temp_dir, db) = create_test_db();

        // Create some transactions with known sigop costs
        let tx1 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: Builder::new()
                    .push_opcode(OP_CHECKSIG)
                    .into_script(),
            }],
        };

        let transactions = vec![tx1];
        let cost = get_block_sigop_cost(&transactions, &db, false, false);

        // 1 CHECKSIG * 4 = 4
        assert_eq!(cost, 4);
        assert!(cost <= MAX_BLOCK_SIGOPS_COST);
    }

    #[test]
    fn test_max_block_sigops_constant() {
        assert_eq!(MAX_BLOCK_SIGOPS_COST, 80_000);
    }

    #[test]
    fn test_witness_scale_factor_constant() {
        assert_eq!(WITNESS_SCALE_FACTOR, 4);
    }
}
