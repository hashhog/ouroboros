//! Legacy (pre-segwit) signature hash computation
//!
//! Implements Bitcoin's legacy sighash algorithm including:
//! - FindAndDelete: removes signature from scriptCode before hashing
//! - OP_CODESEPARATOR handling: truncates scriptCode at last executed separator
//! - SIGHASH_NONE: zeros outputs and other input sequences
//! - SIGHASH_SINGLE: only signs corresponding output (or returns 1 if out of range)
//! - SIGHASH_ANYONECANPAY: only hashes the current input
//!
//! Reference: Bitcoin Core `script/interpreter.cpp` SignatureHash(), FindAndDelete()

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Transaction;

/// Sighash type constants (matches Bitcoin Core interpreter.h)
pub const SIGHASH_ALL: u32 = 1;
pub const SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// OP_CODESEPARATOR opcode value
pub const OP_CODESEPARATOR: u8 = 0xab;

/// Find and delete all occurrences of `needle` in `haystack`.
///
/// This operates on raw bytes and matches Bitcoin Core's FindAndDelete behavior.
/// Unlike Bitcoin Core which parses opcodes, we do byte-level matching which
/// is equivalent for finding serialized signatures (always push data).
///
/// Returns the number of occurrences deleted.
pub fn find_and_delete(script: &mut Vec<u8>, needle: &[u8]) -> usize {
    if needle.is_empty() || script.is_empty() {
        return 0;
    }

    let mut count = 0;
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;

    while i < script.len() {
        // Check if needle matches at current position
        if i + needle.len() <= script.len() && &script[i..i + needle.len()] == needle {
            // Skip the needle (delete it)
            i += needle.len();
            count += 1;
        } else {
            result.push(script[i]);
            i += 1;
        }
    }

    if count > 0 {
        *script = result;
    }

    count
}

/// Remove all OP_CODESEPARATOR (0xab) opcodes from a script.
///
/// In legacy sighash, OP_CODESEPARATORs are stripped from the scriptCode
/// before hashing. This matches the SerializeScriptCode behavior in
/// CTransactionSignatureSerializer.
pub fn remove_codeseparators(script: &[u8]) -> Vec<u8> {
    script
        .iter()
        .filter(|&&b| b != OP_CODESEPARATOR)
        .copied()
        .collect()
}

/// Get the scriptCode starting after the last executed OP_CODESEPARATOR.
///
/// During script execution, when OP_CODESEPARATOR is encountered, it updates
/// the position from which the scriptCode is taken. The scriptCode for
/// signature hashing starts after the last OP_CODESEPARATOR.
///
/// `codesep_pos` is the byte offset of the last OP_CODESEPARATOR, or None
/// if none has been executed.
pub fn script_code_from_codeseparator(script: &[u8], codesep_pos: Option<usize>) -> Vec<u8> {
    match codesep_pos {
        Some(pos) if pos < script.len() => {
            // Start after the OP_CODESEPARATOR byte
            script[pos + 1..].to_vec()
        }
        _ => script.to_vec(),
    }
}

/// Serialize a signature as a push operation (length-prefixed).
///
/// In FindAndDelete, we search for the serialized signature including
/// its push opcode. For signatures up to 75 bytes, this is a single
/// length byte followed by the data.
pub fn serialize_signature_push(sig: &[u8]) -> Vec<u8> {
    let len = sig.len();
    let mut result = Vec::with_capacity(len + 5);

    if len <= 75 {
        // OP_PUSHBYTES_N (0x01-0x4b)
        result.push(len as u8);
    } else if len <= 255 {
        // OP_PUSHDATA1
        result.push(0x4c);
        result.push(len as u8);
    } else if len <= 65535 {
        // OP_PUSHDATA2
        result.push(0x4d);
        result.push((len & 0xff) as u8);
        result.push((len >> 8) as u8);
    } else {
        // OP_PUSHDATA4 (extremely rare for signatures)
        result.push(0x4e);
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push(((len >> 16) & 0xff) as u8);
        result.push((len >> 24) as u8);
    }
    result.extend_from_slice(sig);
    result
}

/// Compute the legacy (pre-segwit) signature hash for a transaction.
///
/// This implements Bitcoin's original sighash algorithm used for P2PKH,
/// P2PK, P2SH (non-witness), and bare multisig.
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - The index of the input being signed
/// * `script_code` - The scriptCode (typically the spent output's scriptPubKey,
///                   or for P2SH, the redeemScript). Should already have
///                   OP_CODESEPARATORs removed and signature FindAndDelete applied.
/// * `hash_type` - The sighash type (SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
///                 optionally combined with SIGHASH_ANYONECANPAY)
///
/// # Returns
/// The 32-byte double-SHA256 hash to be signed.
///
/// # Special Cases
/// - SIGHASH_SINGLE with input_index >= outputs.len() returns [1, 0, 0, ..., 0]
pub fn signature_hash_legacy(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> [u8; 32] {
    // Extract sighash flags
    let base_type = hash_type & 0x1f;
    let anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    let hash_single = base_type == SIGHASH_SINGLE;
    let hash_none = base_type == SIGHASH_NONE;

    // SIGHASH_SINGLE with index >= outputs.len() returns uint256 == 1
    // This is a historical bug that became consensus
    if hash_single && input_index >= tx.output.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return result;
    }

    // Build the transaction data to hash
    let mut data = Vec::new();

    // Version (4 bytes, little-endian)
    tx.version.consensus_encode(&mut data).unwrap();

    // Inputs
    if anyone_can_pay {
        // Only serialize the input being signed
        data.push(1); // varint: 1 input
        serialize_input(
            &mut data,
            tx,
            input_index,
            script_code,
            input_index,
            hash_single,
            hash_none,
        );
    } else {
        // Serialize all inputs
        let num_inputs = tx.input.len();
        encode_varint(&mut data, num_inputs as u64);
        for i in 0..num_inputs {
            serialize_input(&mut data, tx, i, script_code, input_index, hash_single, hash_none);
        }
    }

    // Outputs
    if hash_none {
        // No outputs
        data.push(0);
    } else if hash_single {
        // Only outputs up to and including input_index
        let num_outputs = input_index + 1;
        encode_varint(&mut data, num_outputs as u64);
        for i in 0..num_outputs {
            if i == input_index {
                // Serialize the actual output
                serialize_output(&mut data, &tx.output[i]);
            } else {
                // Empty output: value -1 (0xffffffffffffffff), empty script
                data.extend_from_slice(&[0xff; 8]); // -1 as i64
                data.push(0); // empty script
            }
        }
    } else {
        // SIGHASH_ALL: all outputs
        let num_outputs = tx.output.len();
        encode_varint(&mut data, num_outputs as u64);
        for output in &tx.output {
            serialize_output(&mut data, output);
        }
    }

    // Locktime (4 bytes, little-endian)
    tx.lock_time.consensus_encode(&mut data).unwrap();

    // Hash type (4 bytes, little-endian as signed i32)
    data.extend_from_slice(&(hash_type as i32).to_le_bytes());

    // Double SHA-256
    sha256d::Hash::hash(&data).to_byte_array()
}

/// Serialize a transaction input for sighash computation.
fn serialize_input(
    data: &mut Vec<u8>,
    tx: &Transaction,
    index: usize,
    script_code: &[u8],
    signing_index: usize,
    hash_single: bool,
    hash_none: bool,
) {
    let input = &tx.input[index];

    // Previous output (txid + vout)
    input.previous_output.consensus_encode(data).unwrap();

    // Script
    if index == signing_index {
        // For the input being signed, use the scriptCode
        encode_varint(data, script_code.len() as u64);
        data.extend_from_slice(script_code);
    } else {
        // Blank out other inputs' scripts
        data.push(0);
    }

    // Sequence
    if index != signing_index && (hash_single || hash_none) {
        // For SIGHASH_NONE or SIGHASH_SINGLE, other inputs get sequence 0
        // (they can update at will)
        data.extend_from_slice(&[0u8; 4]);
    } else {
        input.sequence.consensus_encode(data).unwrap();
    }
}

/// Serialize a transaction output.
fn serialize_output(data: &mut Vec<u8>, output: &bitcoin::TxOut) {
    // Value (8 bytes, little-endian)
    data.extend_from_slice(&output.value.to_sat().to_le_bytes());

    // Script
    let script_bytes = output.script_pubkey.as_bytes();
    encode_varint(data, script_bytes.len() as u64);
    data.extend_from_slice(script_bytes);
}

/// Encode a variable-length integer (Bitcoin varint/CompactSize).
fn encode_varint(data: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        data.push(n as u8);
    } else if n <= 0xffff {
        data.push(0xfd);
        data.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        data.push(0xfe);
        data.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        data.push(0xff);
        data.extend_from_slice(&n.to_le_bytes());
    }
}

/// Prepare scriptCode for legacy sighash computation.
///
/// This combines the steps needed before calling signature_hash_legacy:
/// 1. Extract script from after last OP_CODESEPARATOR (if any)
/// 2. Remove any remaining OP_CODESEPARATORs
/// 3. FindAndDelete the signature being checked
///
/// # Arguments
/// * `script_pubkey` - The original script (or after codesep position)
/// * `codesep_pos` - Position of last executed OP_CODESEPARATOR, if any
/// * `signature` - The signature being checked (will be FindAndDeleted)
///
/// # Returns
/// The prepared scriptCode ready for hashing.
pub fn prepare_script_code(
    script_pubkey: &[u8],
    codesep_pos: Option<usize>,
    signature: &[u8],
) -> Vec<u8> {
    // Step 1: Get script after last OP_CODESEPARATOR
    let mut script_code = script_code_from_codeseparator(script_pubkey, codesep_pos);

    // Step 2: Remove OP_CODESEPARATORs
    script_code = remove_codeseparators(&script_code);

    // Step 3: FindAndDelete the signature (serialized as push)
    if !signature.is_empty() {
        let sig_push = serialize_signature_push(signature);
        find_and_delete(&mut script_code, &sig_push);
    }

    script_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;
    use std::io::Cursor;

    #[test]
    fn test_find_and_delete_basic() {
        // Simple case: delete a byte sequence
        let mut script = vec![0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x05];
        let deleted = find_and_delete(&mut script, &[0x02, 0x03]);
        assert_eq!(deleted, 2);
        assert_eq!(script, vec![0x01, 0x04, 0x05]);
    }

    #[test]
    fn test_find_and_delete_no_match() {
        let mut script = vec![0x01, 0x02, 0x03];
        let deleted = find_and_delete(&mut script, &[0x04, 0x05]);
        assert_eq!(deleted, 0);
        assert_eq!(script, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_find_and_delete_empty_needle() {
        let mut script = vec![0x01, 0x02, 0x03];
        let deleted = find_and_delete(&mut script, &[]);
        assert_eq!(deleted, 0);
        assert_eq!(script, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_find_and_delete_entire_script() {
        let mut script = vec![0x01, 0x02, 0x03];
        let deleted = find_and_delete(&mut script, &[0x01, 0x02, 0x03]);
        assert_eq!(deleted, 1);
        assert!(script.is_empty());
    }

    #[test]
    fn test_remove_codeseparators() {
        let script = vec![0x51, OP_CODESEPARATOR, 0x52, OP_CODESEPARATOR, 0x53];
        let result = remove_codeseparators(&script);
        assert_eq!(result, vec![0x51, 0x52, 0x53]);
    }

    #[test]
    fn test_remove_codeseparators_none() {
        let script = vec![0x51, 0x52, 0x53];
        let result = remove_codeseparators(&script);
        assert_eq!(result, vec![0x51, 0x52, 0x53]);
    }

    #[test]
    fn test_script_code_from_codeseparator() {
        let script = vec![0x51, OP_CODESEPARATOR, 0x52, 0x53];
        // Position 1 is where OP_CODESEPARATOR is
        let result = script_code_from_codeseparator(&script, Some(1));
        assert_eq!(result, vec![0x52, 0x53]);
    }

    #[test]
    fn test_script_code_from_codeseparator_none() {
        let script = vec![0x51, 0x52, 0x53];
        let result = script_code_from_codeseparator(&script, None);
        assert_eq!(result, vec![0x51, 0x52, 0x53]);
    }

    #[test]
    fn test_serialize_signature_push_small() {
        let sig = vec![0x30, 0x44]; // 2 bytes
        let result = serialize_signature_push(&sig);
        assert_eq!(result, vec![0x02, 0x30, 0x44]); // length + data
    }

    #[test]
    fn test_serialize_signature_push_pushdata1() {
        // 76 bytes requires OP_PUSHDATA1
        let sig = vec![0x30; 76];
        let result = serialize_signature_push(&sig);
        assert_eq!(result[0], 0x4c); // OP_PUSHDATA1
        assert_eq!(result[1], 76);
        assert_eq!(&result[2..], &sig[..]);
    }

    #[test]
    fn test_sighash_single_out_of_range() {
        // Create a transaction with 2 inputs and 1 output
        let tx_hex = "0100000002000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000001000000000000000000000000";
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let tx: Transaction = Transaction::consensus_decode(&mut Cursor::new(&tx_bytes)).unwrap();

        // SIGHASH_SINGLE with input_index=1 but only 1 output
        let hash = signature_hash_legacy(&tx, 1, &[], SIGHASH_SINGLE);

        // Should return uint256 == 1
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(hash, expected);
    }

    // Test vectors from Bitcoin Core's sighash.json
    // Format: [raw_tx, script, input_index, hash_type, expected_hash]
    #[test]
    fn test_bitcoin_core_sighash_vectors() {
        // Vector 1 from sighash.json
        let tx_hex = "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229";
        let script_hex = "";
        let input_index = 2usize;
        let hash_type = 1864164639u32;
        let expected_hex = "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e";

        run_sighash_test(tx_hex, script_hex, input_index, hash_type, expected_hex);
    }

    #[test]
    fn test_bitcoin_core_sighash_vector_2() {
        // Vector 2: with script
        let tx_hex = "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5";
        let script_hex = "65";
        let input_index = 0usize;
        let hash_type = (-1391424484i32) as u32;
        let expected_hex = "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175";

        run_sighash_test(tx_hex, script_hex, input_index, hash_type, expected_hex);
    }

    #[test]
    fn test_bitcoin_core_sighash_vector_3() {
        // Vector 3: longer script
        let tx_hex = "6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8";
        let script_hex = "acab655151";
        let input_index = 0usize;
        let hash_type = 479279909u32;
        let expected_hex = "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c";

        run_sighash_test(tx_hex, script_hex, input_index, hash_type, expected_hex);
    }

    #[test]
    fn test_bitcoin_core_sighash_vector_with_anyonecanpay() {
        // Vector with ANYONECANPAY flag
        let tx_hex = "d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000";
        let script_hex = "535251536aac536a";
        let input_index = 0usize;
        let hash_type = (-1960128125i32) as u32; // Includes ANYONECANPAY
        let expected_hex = "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a";

        run_sighash_test(tx_hex, script_hex, input_index, hash_type, expected_hex);
    }

    #[test]
    fn test_bitcoin_core_sighash_vector_sighash_none() {
        // Vector with SIGHASH_NONE
        let tx_hex = "e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000";
        let script_hex = "5300ac6a53ab6a";
        let input_index = 1usize;
        let hash_type = (-886562767i32) as u32; // SIGHASH_NONE variant
        let expected_hex = "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798";

        run_sighash_test(tx_hex, script_hex, input_index, hash_type, expected_hex);
    }

    fn run_sighash_test(
        tx_hex: &str,
        script_hex: &str,
        input_index: usize,
        hash_type: u32,
        expected_hex: &str,
    ) {
        let tx_bytes = hex::decode(tx_hex).expect("invalid tx hex");
        let tx: Transaction =
            Transaction::consensus_decode(&mut Cursor::new(&tx_bytes)).expect("invalid tx");

        let script_code = if script_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(script_hex).expect("invalid script hex")
        };

        // Remove OP_CODESEPARATORs (the test vectors expect this)
        let script_code = remove_codeseparators(&script_code);

        let hash = signature_hash_legacy(&tx, input_index, &script_code, hash_type);

        // The expected hash in Bitcoin Core test vectors is in display format
        // (reversed byte order, big-endian). Our hash is in raw format (little-endian).
        // Reverse the expected bytes to compare.
        let mut expected = hex::decode(expected_hex).expect("invalid expected hex");
        expected.reverse();

        assert_eq!(
            hash.to_vec(),
            expected,
            "sighash mismatch for input {} with hash_type {}",
            input_index,
            hash_type
        );
    }
}
