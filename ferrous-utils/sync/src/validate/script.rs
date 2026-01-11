//! Bitcoin Script validation and execution

use bitcoin::blockdata::script::{Script, Instruction};
use bitcoin::opcodes::all::*;
use common::{TransactionWrapper, crypto};
use thiserror::Error;

/// Script validation error types
#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Script execution failed: {0}")]
    ExecutionError(String),

    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u8),

    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Script validation failed")]
    ValidationFailed,

    #[error("Signature verification failed")]
    SignatureFailed,

    #[error("Invalid script type")]
    InvalidScriptType,

    #[error("Unsupported script pattern")]
    UnsupportedScript,

    #[error("Script too large")]
    ScriptTooLarge,

    #[error("Missing witness data")]
    MissingWitness,

    #[error("Invalid witness program")]
    InvalidWitnessProgram,
}

/// Result type for script operations
pub type Result<T> = std::result::Result<T, ScriptError>;

/// Script execution stack
#[derive(Debug, Clone)]
pub struct Stack(Vec<Vec<u8>>);

impl Stack {
    /// Create a new empty stack
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Push data onto the stack
    pub fn push(&mut self, data: Vec<u8>) {
        self.0.push(data);
    }

    /// Pop data from the stack
    pub fn pop(&mut self) -> Result<Vec<u8>> {
        self.0.pop().ok_or(ScriptError::StackUnderflow)
    }

    /// Peek at the top element without removing it
    pub fn peek(&self) -> Result<&Vec<u8>> {
        self.0.last().ok_or(ScriptError::StackUnderflow)
    }

    /// Get the stack size
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if stack is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get element at index (0 is top of stack)
    pub fn get(&self, index: usize) -> Result<&Vec<u8>> {
        if index >= self.0.len() {
            return Err(ScriptError::StackUnderflow);
        }
        Ok(&self.0[self.0.len() - 1 - index])
    }

    /// Duplicate the top stack element
    pub fn dup(&mut self) -> Result<()> {
        let top = self.peek()?.clone();
        self.push(top);
        Ok(())
    }
}

/// Bitcoin script types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay to Public Key Hash (P2PKH)
    P2PKH,
    /// Pay to Script Hash (P2SH)
    P2SH,
    /// Pay to Witness Public Key Hash (P2WPKH)
    P2WPKH,
    /// Pay to Witness Script Hash (P2WSH)
    P2WSH,
    /// Pay to Public Key (P2PK)
    P2PK,
    /// Multisig script
    Multisig,
    /// Non-standard script
    Nonstandard,
}

/// Bitcoin Script interpreter
pub struct ScriptInterpreter;

impl ScriptInterpreter {
    /// Evaluate a script
    ///
    /// Executes the script and returns whether it evaluates to true
    pub fn evaluate_script(script: &Script, stack: &mut Stack) -> Result<bool> {
        // Check script size limit (Bitcoin Core limit is 10,000 bytes)
        if script.len() > 10000 {
            return Err(ScriptError::ScriptTooLarge);
        }

        // For now, implement a basic interpreter
        // This is a simplified version - full Bitcoin Script implementation is very complex

        let instructions = script.instructions().collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ScriptError::ExecutionError("Invalid script".to_string()))?;

        for instruction in instructions {
            match instruction {
                Instruction::PushBytes(bytes) => {
                    stack.push(bytes.as_bytes().to_vec());
                }
                Instruction::Op(opcode) => {
                    Self::execute_opcode(opcode, stack)?;
                }
            }
        }

        // Script succeeds if stack is not empty and top element is truthy
        if stack.is_empty() {
            return Ok(false);
        }

        let top = stack.peek()?;
        Ok(!top.is_empty() && top[0] != 0)
    }

    /// Execute a single opcode
    fn execute_opcode(opcode: bitcoin::opcodes::Opcode, stack: &mut Stack) -> Result<()> {
        // Handle push operations for small integers
        let opcode_byte = opcode.to_u8();
        if opcode_byte >= 0x51 && opcode_byte <= 0x60 {
            // OP_1 to OP_16 (0x51 = 81, 0x60 = 96)
            let value = opcode_byte - 0x50; // OP_1 = 0x51, so 0x51 - 0x50 = 1
            stack.push(vec![value as u8]);
            return Ok(());
        }

        match opcode {
            OP_DUP => {
                stack.dup()?;
            }
            OP_HASH160 => {
                let data = stack.pop()?;
                let hash = crypto::hash160(&data);
                stack.push(hash.to_vec());
            }
            OP_SHA256 => {
                let data = stack.pop()?;
                let hash = crypto::double_sha256(&data);
                stack.push(hash.to_vec());
            }
            OP_EQUAL => {
                let a = stack.pop()?;
                let b = stack.pop()?;
                let equal = a == b;
                stack.push(if equal { vec![1] } else { vec![0] });
            }
            OP_EQUALVERIFY => {
                let a = stack.pop()?;
                let b = stack.pop()?;
                if a != b {
                    return Err(ScriptError::ValidationFailed);
                }
            }
            OP_VERIFY => {
                let value = stack.pop()?;
                if value.is_empty() || value[0] == 0 {
                    return Err(ScriptError::ValidationFailed);
                }
            }
            OP_RETURN => {
                return Err(ScriptError::ValidationFailed);
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                // Signature verification - this is a placeholder
                // In a full implementation, this would need access to the transaction
                // and input index to create the proper sighash
                let pubkey = stack.pop()?;
                let sig = stack.pop()?;

                // For now, just check that both are non-empty
                // Real implementation would verify the signature cryptographically
                let valid = !pubkey.is_empty() && !sig.is_empty();
                stack.push(if valid { vec![1] } else { vec![0] });

                if opcode == OP_CHECKSIGVERIFY && !valid {
                    return Err(ScriptError::ValidationFailed);
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                // Simplified multisig verification
                // This is complex - for now just return true
                stack.push(vec![1]);
            }
            OP_RIPEMD160 => {
                let data = stack.pop()?;
                let hash = crypto::hash160(&data); // RIPEMD160(SHA256(data))
                stack.push(hash.to_vec());
            }
            OP_HASH256 => {
                let data = stack.pop()?;
                let hash = crypto::double_sha256(&data);
                stack.push(hash.to_vec());
            }
            OP_SIZE => {
                let data = stack.peek()?.clone();
                let size = data.len() as u32;
                stack.push(size.to_le_bytes().to_vec());
            }
            OP_BOOLAND => {
                let a = stack.pop()?;
                let b = stack.pop()?;
                let result = (!a.is_empty() && a[0] != 0) && (!b.is_empty() && b[0] != 0);
                stack.push(if result { vec![1] } else { vec![0] });
            }
            OP_BOOLOR => {
                let a = stack.pop()?;
                let b = stack.pop()?;
                let result = (!a.is_empty() && a[0] != 0) || (!b.is_empty() && b[0] != 0);
                stack.push(if result { vec![1] } else { vec![0] });
            }
            OP_NUMEQUAL => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let equal = a == b;
                stack.push(if equal { vec![1] } else { vec![0] });
            }
            OP_NUMEQUALVERIFY => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                if a != b {
                    return Err(ScriptError::ValidationFailed);
                }
            }
            OP_NUMNOTEQUAL => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let not_equal = a != b;
                stack.push(if not_equal { vec![1] } else { vec![0] });
            }
            OP_LESSTHAN => {
                let right = Self::decode_num(&stack.pop()?)?; // Right operand (popped first)
                let left = Self::decode_num(&stack.pop()?)?;  // Left operand (popped second)
                let less = left < right;
                stack.push(if less { vec![1] } else { vec![0] });
            }
            OP_GREATERTHAN => {
                let right = Self::decode_num(&stack.pop()?)?; // Right operand (popped first)
                let left = Self::decode_num(&stack.pop()?)?;  // Left operand (popped second)
                let greater = left > right;
                stack.push(if greater { vec![1] } else { vec![0] });
            }
            OP_WITHIN => {
                let max_val = Self::decode_num(&stack.pop()?)?;
                let min_val = Self::decode_num(&stack.pop()?)?;
                let x = Self::decode_num(&stack.pop()?)?;
                let within = x >= min_val && x < max_val;
                stack.push(if within { vec![1] } else { vec![0] });
            }
            OP_ADD => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let result = a + b;
                stack.push(Self::encode_num(result));
            }
            OP_SUB => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let result = b - a; // Note: stack order
                stack.push(Self::encode_num(result));
            }
            OP_MUL => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let result = a * b;
                stack.push(Self::encode_num(result));
            }
            OP_DIV => {
                let divisor = Self::decode_num(&stack.pop()?)?;
                let dividend = Self::decode_num(&stack.pop()?)?;
                if divisor == 0 {
                    return Err(ScriptError::ExecutionError("Division by zero".to_string()));
                }
                let result = dividend / divisor;
                stack.push(Self::encode_num(result));
            }
            OP_MOD => {
                let modulus = Self::decode_num(&stack.pop()?)?;
                let value = Self::decode_num(&stack.pop()?)?;
                if modulus == 0 {
                    return Err(ScriptError::ExecutionError("Modulo by zero".to_string()));
                }
                let result = value % modulus;
                stack.push(Self::encode_num(result));
            }
            OP_LSHIFT => {
                let shift = Self::decode_num(&stack.pop()?)? as u32;
                let value = Self::decode_num(&stack.pop()?)?;
                let result = value << (shift & 31); // Limit shift to 31 bits
                stack.push(Self::encode_num(result));
            }
            OP_RSHIFT => {
                let shift = Self::decode_num(&stack.pop()?)? as u32;
                let value = Self::decode_num(&stack.pop()?)?;
                let result = value >> (shift & 31); // Limit shift to 31 bits
                stack.push(Self::encode_num(result));
            }
            OP_MIN => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let result = a.min(b);
                stack.push(Self::encode_num(result));
            }
            OP_MAX => {
                let a = Self::decode_num(&stack.pop()?)?;
                let b = Self::decode_num(&stack.pop()?)?;
                let result = a.max(b);
                stack.push(Self::encode_num(result));
            }
            OP_NEGATE => {
                let value = Self::decode_num(&stack.pop()?)?;
                let result = -value;
                stack.push(Self::encode_num(result));
            }
            OP_ABS => {
                let value = Self::decode_num(&stack.pop()?)?;
                let result = value.abs();
                stack.push(Self::encode_num(result));
            }
            OP_NOT => {
                let value = Self::decode_num(&stack.pop()?)?;
                let result = if value == 0 { 1 } else { 0 };
                stack.push(Self::encode_num(result));
            }
            OP_0NOTEQUAL => {
                let value = Self::decode_num(&stack.pop()?)?;
                let result = if value != 0 { 1 } else { 0 };
                stack.push(Self::encode_num(result));
            }
            _ => {
                // Unknown or unimplemented opcode
                return Err(ScriptError::InvalidOpcode(opcode.to_u8()));
            }
        }

        Ok(())
    }

    /// Decode a number from script format (little-endian, sign bit)
    fn decode_num(data: &[u8]) -> Result<i64> {
        if data.is_empty() {
            return Ok(0);
        }

        if data.len() > 8 {
            return Err(ScriptError::ExecutionError("Number too large".to_string()));
        }

        let mut result = 0i64;
        for (i, &byte) in data.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        // Check sign bit
        if data.len() > 0 && (data[data.len() - 1] & 0x80) != 0 {
            result |= -1i64 << (8 * data.len());
        }

        Ok(result)
    }

    /// Encode a number to script format (little-endian with sign bit)
    fn encode_num(mut value: i64) -> Vec<u8> {
        if value == 0 {
            return vec![];
        }

        let mut result = Vec::new();
        let negative = value < 0;
        value = value.abs();

        while value > 0 {
            result.push((value & 0xff) as u8);
            value >>= 8;
        }

        // If the highest bit is set, add a zero byte to indicate positive
        if !result.is_empty() && (result[result.len() - 1] & 0x80) != 0 {
            result.push(0);
        }

        // Set sign bit if negative
        if negative {
            if let Some(last) = result.last_mut() {
                *last |= 0x80;
            }
        }

        result
    }
}

/// Identify the type of a Bitcoin script
pub fn identify_script_type(script: &Script) -> ScriptType {
    let script_bytes = script.as_bytes();

    // Check for P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if script_bytes.len() == 25
        && script_bytes[0] == 0x76  // OP_DUP
        && script_bytes[1] == 0xa9  // OP_HASH160
        && script_bytes[2] == 0x14  // 20 bytes
        && script_bytes[23] == 0x88 // OP_EQUALVERIFY
        && script_bytes[24] == 0xac // OP_CHECKSIG
    {
        return ScriptType::P2PKH;
    }

    // Check for P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if script_bytes.len() == 23
        && script_bytes[0] == 0xa9  // OP_HASH160
        && script_bytes[1] == 0x14  // 20 bytes
        && script_bytes[22] == 0x87 // OP_EQUAL
    {
        return ScriptType::P2SH;
    }

    // Check for P2PK: <pubkey> OP_CHECKSIG
    // Script ends with OP_CHECKSIG and has at least one push operation before it
    if script_bytes.len() > 2
        && script_bytes[script_bytes.len() - 1] == 0xac // OP_CHECKSIG
        && script_bytes[0] >= 0x04 && script_bytes[0] <= 0x42 // Push 4-66 bytes (compressed/uncompressed pubkey)
    {
        return ScriptType::P2PK;
    }

    // Check for P2WPKH: OP_0 <20 bytes>
    if script_bytes.len() == 22
        && script_bytes[0] == 0x00 // OP_0
        && script_bytes[1] == 0x14 // 20 bytes
    {
        return ScriptType::P2WPKH;
    }

    // Check for P2WSH: OP_0 <32 bytes>
    if script_bytes.len() == 34
        && script_bytes[0] == 0x00 // OP_0
        && script_bytes[1] == 0x20 // 32 bytes
    {
        return ScriptType::P2WSH;
    }

    // Check for multisig patterns
    // This is a simplified check
    if script_bytes.len() > 10
        && script_bytes[script_bytes.len() - 1] == 0xae // OP_CHECKMULTISIG
    {
        return ScriptType::Multisig;
    }

    ScriptType::Nonstandard
}

/// Verify signature in script context
pub fn verify_signature_in_script(
    tx: &TransactionWrapper,
    input_idx: usize,
    script_pubkey: &Script,
) -> Result<bool> {
    let inner_tx = tx.inner();

    if input_idx >= inner_tx.input.len() {
        return Err(ScriptError::ValidationFailed);
    }

    let input = &inner_tx.input[input_idx];

    // For now, implement basic signature verification
    // This would need to be much more sophisticated for production use
    let script_sig = &input.script_sig;
    let script_type = identify_script_type(script_pubkey);

    match script_type {
        ScriptType::P2PKH => {
            // P2PKH signature verification
            verify_p2pkh_signature(tx, input_idx, script_sig, script_pubkey)
        }
        ScriptType::P2PK => {
            // P2PK signature verification
            verify_p2pk_signature(tx, input_idx, script_sig, script_pubkey)
        }
        ScriptType::P2SH => {
            // P2SH requires executing the redeem script
            // This is complex and simplified for now
            Ok(false)
        }
        _ => {
            // Other script types not implemented yet
            Ok(false)
        }
    }
}

/// Verify P2PKH signature
fn verify_p2pkh_signature(
    tx: &TransactionWrapper,
    input_idx: usize,
    script_sig: &Script,
    script_pubkey: &Script,
) -> Result<bool> {
    // Extract signature and pubkey from script_sig
    let sig_instructions: Vec<_> = script_sig.instructions().collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ScriptError::ExecutionError("Invalid script_sig".to_string()))?;

    if sig_instructions.len() != 2 {
        return Ok(false);
    }

    let sig_bytes = match &sig_instructions[0] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        _ => return Ok(false),
    };

    let pubkey_bytes = match &sig_instructions[1] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        _ => return Ok(false),
    };

    // Extract expected pubkey hash from script_pubkey
    let pk_instructions: Vec<_> = script_pubkey.instructions().collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ScriptError::ExecutionError("Invalid script_pubkey".to_string()))?;

    if pk_instructions.len() != 5 {
        return Ok(false);
    }

    let expected_hash = match &pk_instructions[2] {
        Instruction::PushBytes(bytes) if bytes.len() == 20 => bytes.as_bytes(),
        _ => return Ok(false),
    };

    // Verify pubkey hash matches
    let pubkey_hash = crypto::hash160(pubkey_bytes);
    if &pubkey_hash[..] != expected_hash {
        return Ok(false);
    }

    // For now, skip actual signature verification
    // In production, this would create the sighash and verify the signature
    // using secp256k1

    Ok(true)
}

/// Verify P2PK signature
fn verify_p2pk_signature(
    tx: &TransactionWrapper,
    input_idx: usize,
    script_sig: &Script,
    script_pubkey: &Script,
) -> Result<bool> {
    // Extract signature from script_sig
    let sig_instructions: Vec<_> = script_sig.instructions().collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ScriptError::ExecutionError("Invalid script_sig".to_string()))?;

    if sig_instructions.len() != 1 {
        return Ok(false);
    }

    let sig_bytes = match &sig_instructions[0] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        _ => return Ok(false),
    };

    // Extract pubkey from script_pubkey
    let pk_instructions: Vec<_> = script_pubkey.instructions().collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ScriptError::ExecutionError("Invalid script_pubkey".to_string()))?;

    if pk_instructions.len() != 2 {
        return Ok(false);
    }

    let pubkey_bytes = match &pk_instructions[0] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        _ => return Ok(false),
    };

    // For now, skip actual signature verification
    // In production, this would create the sighash and verify the signature

    Ok(!sig_bytes.is_empty() && !pubkey_bytes.is_empty())
}

/// Verify SegWit witness
/// Note: This is a simplified implementation.
/// In practice, SegWit verification requires access to witness data,
/// which is not directly part of the Transaction struct in the current bitcoin crate version.
pub fn verify_witness(_tx: &TransactionWrapper, _input_idx: usize) -> Result<bool> {
    // Placeholder implementation
    // Full SegWit verification would require:
    // 1. Access to witness data (stored separately or in extended transaction format)
    // 2. Witness program validation
    // 3. SegWit script execution
    // 4. SegWit signature verification with proper sighash

    // For now, return false to indicate SegWit is not supported in this simplified implementation
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::transaction::Transaction;
    use bitcoin::opcodes::all::*;
    use bitcoin::opcodes::OP_0;

    #[test]
    fn test_script_type_identification() {
        // Test P2PKH script
        let p2pkh_script = Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 20]) // dummy hash
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();

        assert_eq!(identify_script_type(&p2pkh_script), ScriptType::P2PKH);

        // Test P2SH script
        let p2sh_script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 20]) // dummy hash
            .push_opcode(OP_EQUAL)
            .into_script();

        assert_eq!(identify_script_type(&p2sh_script), ScriptType::P2SH);

        // Test P2WPKH script
        let p2wpkh_script = Builder::new()
            .push_opcode(OP_0)
            .push_slice(&[0u8; 20]) // dummy hash
            .into_script();

        assert_eq!(identify_script_type(&p2wpkh_script), ScriptType::P2WPKH);

        // Test P2WSH script
        let p2wsh_script = Builder::new()
            .push_opcode(OP_0)
            .push_slice(&[0u8; 32]) // dummy hash
            .into_script();

        assert_eq!(identify_script_type(&p2wsh_script), ScriptType::P2WSH);
    }

    #[test]
    fn test_stack_operations() {
        let mut stack = Stack::new();

        // Test push/pop
        stack.push(vec![1, 2, 3]);
        assert_eq!(stack.len(), 1);

        let popped = stack.pop().unwrap();
        assert_eq!(popped, vec![1, 2, 3]);
        assert_eq!(stack.len(), 0);

        // Test dup
        stack.push(vec![4, 5, 6]);
        stack.dup().unwrap();
        assert_eq!(stack.len(), 2);

        let top1 = stack.pop().unwrap();
        let top2 = stack.pop().unwrap();
        assert_eq!(top1, top2);
    }

    #[test]
    fn test_basic_script_execution() {
        let mut stack = Stack::new();

        // Simple script: push 1, push 1, OP_EQUAL
        let script = Builder::new()
            .push_int(1)
            .push_int(1)
            .push_opcode(OP_EQUAL)
            .into_script();

        let result = ScriptInterpreter::evaluate_script(&script, &mut stack);
        assert!(result.unwrap());
    }

    #[test]
    fn test_op_dup() {
        let mut stack = Stack::new();
        stack.push(vec![1, 2, 3]);

        // Execute OP_DUP
        ScriptInterpreter::execute_opcode(OP_DUP, &mut stack).unwrap();

        assert_eq!(stack.len(), 2);
        let top1 = stack.pop().unwrap();
        let top2 = stack.pop().unwrap();
        assert_eq!(top1, top2);
    }

    #[test]
    fn test_op_hash160() {
        let mut stack = Stack::new();
        stack.push(b"hello".to_vec());

        // Execute OP_HASH160
        ScriptInterpreter::execute_opcode(OP_HASH160, &mut stack).unwrap();

        assert_eq!(stack.len(), 1);
        let hash = stack.pop().unwrap();
        assert_eq!(hash.len(), 20); // HASH160 produces 20 bytes
    }

    #[test]
    fn test_signature_verification_placeholder() {
        // This is a placeholder test - full signature verification
        // requires proper transaction setup

        let tx = TransactionWrapper::new(Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        });

        let script = Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&[0u8; 20])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // For now, this should not panic
        let _result = verify_signature_in_script(&tx, 0, &script);
    }

    #[test]
    fn test_p2pk_script_type() {
        // Test P2PK script identification
        // Create a script manually: <65-byte pubkey> OP_CHECKSIG
        let mut script_bytes = vec![65u8]; // Push 65 bytes
        script_bytes.extend(vec![0x04u8; 65]); // 65 bytes of 0x04
        script_bytes.push(0xac); // OP_CHECKSIG
        let script = Script::from_bytes(&script_bytes);

        assert_eq!(identify_script_type(&script), ScriptType::P2PK);
    }

    #[test]
    fn test_multisig_script_type() {
        // Test multisig script identification
        let script = Builder::new()
            .push_int(2) // 2 of 3 multisig
            .push_slice(&[0x02; 33]) // pubkey 1
            .push_slice(&[0x03; 33]) // pubkey 2
            .push_slice(&[0x04; 33]) // pubkey 3
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        assert_eq!(identify_script_type(&script), ScriptType::Multisig);
    }

    #[test]
    fn test_nonstandard_script_type() {
        // Test non-standard script
        let script = Builder::new()
            .push_int(1)
            .push_opcode(OP_RETURN)
            .push_slice(b"non-standard")
            .into_script();

        assert_eq!(identify_script_type(&script), ScriptType::Nonstandard);
    }

    #[test]
    fn test_op_equal() {
        let mut stack = Stack::new();
        stack.push(vec![1, 2, 3]);
        stack.push(vec![1, 2, 3]);

        ScriptInterpreter::execute_opcode(OP_EQUAL, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);
    }

    #[test]
    fn test_op_equal_false() {
        let mut stack = Stack::new();
        stack.push(vec![1, 2, 3]);
        stack.push(vec![1, 2, 4]);

        ScriptInterpreter::execute_opcode(OP_EQUAL, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![0]);
    }

    #[test]
    fn test_op_verify_true() {
        let mut stack = Stack::new();
        stack.push(vec![1]);

        // Should succeed and not modify stack further
        ScriptInterpreter::execute_opcode(OP_VERIFY, &mut stack).unwrap();
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn test_op_verify_false() {
        let mut stack = Stack::new();
        stack.push(vec![0]);

        // Should fail
        let result = ScriptInterpreter::execute_opcode(OP_VERIFY, &mut stack);
        assert!(matches!(result, Err(ScriptError::ValidationFailed)));
    }

    #[test]
    fn test_op_return() {
        let mut stack = Stack::new();
        stack.push(vec![1]);

        // Should always fail
        let result = ScriptInterpreter::execute_opcode(OP_RETURN, &mut stack);
        assert!(matches!(result, Err(ScriptError::ValidationFailed)));
    }

    #[test]
    fn test_op_1_to_op_16() {
        let mut stack = Stack::new();

        // Test OP_1 (0x51) - push 1
        let op_1 = bitcoin::opcodes::Opcode::from(0x51);
        ScriptInterpreter::execute_opcode(op_1, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);

        // Test OP_2 (0x52) - push 2
        let op_2 = bitcoin::opcodes::Opcode::from(0x52);
        ScriptInterpreter::execute_opcode(op_2, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![2]);
    }

    #[test]
    fn test_arithmetic_operations() {
        let mut stack = Stack::new();

        // Test OP_ADD: 5 + 3 = 8
        stack.push(vec![5]);
        stack.push(vec![3]);
        ScriptInterpreter::execute_opcode(OP_ADD, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![8]);

        // Test OP_SUB: 10 - 4 = 6
        stack.push(vec![10]);
        stack.push(vec![4]);
        ScriptInterpreter::execute_opcode(OP_SUB, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![6]);

        // Test OP_MUL: 3 * 4 = 12
        stack.push(vec![3]);
        stack.push(vec![4]);
        ScriptInterpreter::execute_opcode(OP_MUL, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![12]);
    }

    #[test]
    fn test_bitwise_operations() {
        let mut stack = Stack::new();

        // Test OP_BOOLAND: 1 AND 1 = 1
        stack.push(vec![1]);
        stack.push(vec![1]);
        ScriptInterpreter::execute_opcode(OP_BOOLAND, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);

        // Test OP_BOOLAND: 1 AND 0 = 0
        stack.push(vec![1]);
        stack.push(vec![0]);
        ScriptInterpreter::execute_opcode(OP_BOOLAND, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![0]);

        // Test OP_BOOLOR: 1 OR 0 = 1
        stack.push(vec![1]);
        stack.push(vec![0]);
        ScriptInterpreter::execute_opcode(OP_BOOLOR, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);
    }

    #[test]
    fn test_comparison_operations() {
        let mut stack = Stack::new();

        // Test OP_NUMEQUAL: 5 == 5
        stack.push(vec![5]);
        stack.push(vec![5]);
        ScriptInterpreter::execute_opcode(OP_NUMEQUAL, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);

        // Test OP_NUMEQUAL: 5 == 6
        stack.push(vec![5]);
        stack.push(vec![6]);
        ScriptInterpreter::execute_opcode(OP_NUMEQUAL, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![0]);

        // Test OP_LESSTHAN: 3 < 5
        stack.push(vec![3]); // left operand
        stack.push(vec![5]); // right operand
        ScriptInterpreter::execute_opcode(OP_LESSTHAN, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);

        // Test OP_GREATERTHAN: 7 > 3
        stack.push(vec![7]); // left operand
        stack.push(vec![3]); // right operand
        ScriptInterpreter::execute_opcode(OP_GREATERTHAN, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);
    }

    #[test]
    fn test_stack_underflow() {
        let mut stack = Stack::new();

        // Try to pop from empty stack
        let result = stack.pop();
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));

        // Try to execute OP_ADD with insufficient stack items
        stack.push(vec![1]);
        let result = ScriptInterpreter::execute_opcode(OP_ADD, &mut stack);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_invalid_opcode() {
        let mut stack = Stack::new();

        // Create an invalid opcode (high value)
        let invalid_opcode = bitcoin::opcodes::Opcode::from(0xff);

        let result = ScriptInterpreter::execute_opcode(invalid_opcode, &mut stack);
        assert!(matches!(result, Err(ScriptError::InvalidOpcode(0xff))));
    }

    #[test]
    fn test_witness_verification() {
        // Test basic witness verification structure
        let tx = TransactionWrapper::new(Transaction {
            version: bitcoin::transaction::Version::TWO, // SegWit version
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::transaction::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(), // Empty for SegWit
                sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::from_slice(&[vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]]), // P2WPKH program
            }],
            output: vec![],
        });

        // For now, this should not panic
        let _result = verify_witness(&tx, 0);
    }

    #[test]
    fn test_script_size_limits() {
        // Test that very large scripts are rejected
        let large_script = vec![0u8; 10001]; // Over 10KB limit
        let script = Script::from_bytes(&large_script);

        let mut stack = Stack::new();
        let result = ScriptInterpreter::evaluate_script(&script, &mut stack);
        // Should fail due to invalid script
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_num() {
        // Test number decoding
        assert_eq!(ScriptInterpreter::decode_num(&[]).unwrap(), 0);
        assert_eq!(ScriptInterpreter::decode_num(&[1]).unwrap(), 1);
        assert_eq!(ScriptInterpreter::decode_num(&[0xff]).unwrap(), -1); // Negative numbers
        assert_eq!(ScriptInterpreter::decode_num(&[0xfe, 0xff]).unwrap(), -2);
    }

    #[test]
    fn test_encode_num() {
        // Test number encoding
        assert_eq!(ScriptInterpreter::encode_num(0), vec![0u8; 0]);
        assert_eq!(ScriptInterpreter::encode_num(1), vec![1u8]);
        assert_eq!(ScriptInterpreter::encode_num(-1), vec![0x81u8]);
        assert_eq!(ScriptInterpreter::encode_num(255), vec![0xffu8, 0x00u8]);
    }

    #[test]
    fn test_min_max_operations() {
        let mut stack = Stack::new();

        // Test OP_MIN: min(5, 3) = 3
        stack.push(vec![5]);
        stack.push(vec![3]);
        ScriptInterpreter::execute_opcode(OP_MIN, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![3]);

        // Test OP_MAX: max(5, 3) = 5
        stack.push(vec![5]);
        stack.push(vec![3]);
        ScriptInterpreter::execute_opcode(OP_MAX, &mut stack).unwrap();
        assert_eq!(stack.pop().unwrap(), vec![5]);
    }

    #[test]
    fn test_complex_script() {
        let mut stack = Stack::new();

        // Script: 2 3 OP_ADD 5 OP_EQUAL
        // Should evaluate to: (2 + 3) == 5 -> true
        let script = Builder::new()
            .push_int(2)
            .push_int(3)
            .push_opcode(OP_ADD)
            .push_int(5)
            .push_opcode(OP_EQUAL)
            .into_script();

        let result = ScriptInterpreter::evaluate_script(&script, &mut stack);
        assert!(result.unwrap());
    }
}
