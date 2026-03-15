//! Bitcoin Script validation and execution

use bitcoin::blockdata::script::{Script, Instruction};
use bitcoin::opcodes::all::*;
use common::{TransactionWrapper, crypto};
use thiserror::Error;

/// Script validation error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
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

    /// BIP146: Failed signature check with non-empty signature (NULLFAIL)
    #[error("Signature must be empty when verification fails (NULLFAIL)")]
    NullFail,

    /// BIP141: Non-compressed public key in witness v0 script
    #[error("Public key must be compressed in witness v0 scripts")]
    WitnessPubkeyType,

    /// BIP141: Witness script must leave exactly one element on the stack
    #[error("Script must leave exactly one element on the stack (CLEANSTACK)")]
    CleanStack,

    /// BIP141: Script evaluated to false
    #[error("Script evaluated to false")]
    EvalFalse,

    /// BIP16: P2SH scriptSig must contain only push operations
    #[error("scriptSig must be push-only for P2SH")]
    SigPushOnly,

    /// BIP141/Tapscript: OP_IF/OP_NOTIF argument must be empty or exactly 0x01
    #[error("OP_IF/OP_NOTIF argument must be empty or 0x01 (MINIMALIF)")]
    MinimalIf,

    /// Unbalanced conditional (OP_ENDIF without matching OP_IF/OP_NOTIF)
    #[error("Unbalanced conditional")]
    UnbalancedConditional,
}

/// Result type for script operations
pub type Result<T> = std::result::Result<T, ScriptError>;

// ============================================================================
// Script verification flags (mirrors Bitcoin Core's interpreter.h)
// ============================================================================

bitflags::bitflags! {
    /// Script verification flags controlling consensus and policy rules.
    ///
    /// These flags mirror Bitcoin Core's `script_verify_flags` in `script/interpreter.h`.
    /// Flags are applied cumulatively based on block height in `GetBlockScriptFlags()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ScriptVerifyFlags: u32 {
        /// No flags
        const NONE = 0;

        /// BIP16: Evaluate P2SH subscripts
        const P2SH = 1 << 0;

        /// Passing a non-strict-DER signature or pubkey fails
        const STRICTENC = 1 << 1;

        /// BIP66: Require strict DER signatures
        const DERSIG = 1 << 2;

        /// BIP62 rule 5: Require S values <= order/2
        const LOW_S = 1 << 3;

        /// BIP147: Require dummy element in CHECKMULTISIG to be null
        const NULLDUMMY = 1 << 4;

        /// BIP62 rule 2: scriptSig must be push-only
        const SIGPUSHONLY = 1 << 5;

        /// BIP62 rules 3/4: Require minimal encodings
        const MINIMALDATA = 1 << 6;

        /// Discourage upgradable NOPs (OP_NOP1-10)
        const DISCOURAGE_UPGRADABLE_NOPS = 1 << 7;

        /// BIP62 rule 6: Require exactly one stack element after execution
        const CLEANSTACK = 1 << 8;

        /// BIP65: Enable OP_CHECKLOCKTIMEVERIFY
        const CHECKLOCKTIMEVERIFY = 1 << 9;

        /// BIP112: Enable OP_CHECKSEQUENCEVERIFY
        const CHECKSEQUENCEVERIFY = 1 << 10;

        /// BIP141: Enable SegWit (witness programs)
        const WITNESS = 1 << 11;

        /// Discourage upgradable witness programs
        const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12;

        /// BIP141: Require minimal IF/NOTIF arguments (empty or 0x01)
        const MINIMALIF = 1 << 13;

        /// BIP146: Require signature to be empty if CHECKSIG/MULTISIG fails
        const NULLFAIL = 1 << 14;

        /// BIP141: Only compressed keys in P2WPKH/P2WSH
        const WITNESS_PUBKEYTYPE = 1 << 15;

        /// Making OP_CODESEPARATOR and FindAndDelete fail
        const CONST_SCRIPTCODE = 1 << 16;

        /// BIP341: Enable Taproot (version 1 witness programs)
        const TAPROOT = 1 << 17;

        /// Discourage upgradable Taproot versions
        const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18;

        /// Discourage OP_SUCCESS opcodes
        const DISCOURAGE_OP_SUCCESS = 1 << 19;

        /// Discourage upgradable pubkey types in Tapscript
        const DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20;
    }
}

/// SegWit activation heights per network
pub mod activation_heights {
    use bitcoin::Network;

    /// Returns the SegWit (BIP141) activation height for the given network.
    /// NULLFAIL (BIP146) is consensus-mandatory at the same height as SegWit.
    pub fn segwit_height(network: Network) -> u32 {
        match network {
            Network::Bitcoin => 481824,     // mainnet
            Network::Testnet => 834624,     // testnet3
            Network::Testnet4 => 0,         // active from genesis
            Network::Signet => 0,           // active from genesis
            Network::Regtest => 0,          // active from genesis
            _ => 0,                         // conservative default
        }
    }

    /// Returns the script verification flags for a given block height on the network.
    /// This mirrors Bitcoin Core's GetBlockScriptFlags() in validation.cpp.
    pub fn get_script_flags_for_height(height: u32, network: Network) -> super::ScriptVerifyFlags {
        use super::ScriptVerifyFlags;

        let mut flags = ScriptVerifyFlags::NONE;

        // BIP16 (P2SH) - activated at height 173805 on mainnet
        let bip16_height = match network {
            Network::Bitcoin => 173805,
            _ => 0, // active from genesis on testnets
        };
        if height >= bip16_height {
            flags |= ScriptVerifyFlags::P2SH;
        }

        // BIP66 (DERSIG) - activated at height 363725 on mainnet
        let bip66_height = match network {
            Network::Bitcoin => 363725,
            _ => 0,
        };
        if height >= bip66_height {
            flags |= ScriptVerifyFlags::DERSIG;
        }

        // BIP65 (CLTV) - activated at height 388381 on mainnet
        let bip65_height = match network {
            Network::Bitcoin => 388381,
            _ => 0,
        };
        if height >= bip65_height {
            flags |= ScriptVerifyFlags::CHECKLOCKTIMEVERIFY;
        }

        // BIP68/112 (CSV) - activated at height 419328 on mainnet
        let csv_height = match network {
            Network::Bitcoin => 419328,
            _ => 0,
        };
        if height >= csv_height {
            flags |= ScriptVerifyFlags::CHECKSEQUENCEVERIFY;
        }

        // SegWit (BIP141/143/147/146) - activated at height 481824 on mainnet
        // CRITICAL: NULLFAIL is consensus-mandatory at SegWit activation, NOT policy-only
        let segwit_height = segwit_height(network);
        if height >= segwit_height {
            flags |= ScriptVerifyFlags::WITNESS
                | ScriptVerifyFlags::NULLDUMMY
                | ScriptVerifyFlags::NULLFAIL  // BIP146: consensus-mandatory
                | ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        }

        // Taproot (BIP341/342) - activated at height 709632 on mainnet
        let taproot_height = match network {
            Network::Bitcoin => 709632,
            Network::Signet => 0,
            _ => 0,
        };
        if height >= taproot_height {
            flags |= ScriptVerifyFlags::TAPROOT;
        }

        flags
    }
}

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

// ============================================================================
// Public key encoding validation (BIP141)
// ============================================================================

/// Check if a public key is compressed (33 bytes, starting with 0x02 or 0x03).
///
/// Reference: Bitcoin Core interpreter.cpp IsCompressedPubKey()
pub fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    // Compressed public key: 33 bytes, first byte is 0x02 or 0x03
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Check if a public key is either compressed (33 bytes) or uncompressed (65 bytes).
///
/// Reference: Bitcoin Core interpreter.cpp IsCompressedOrUncompressedPubKey()
pub fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.len() < 33 {
        return false;
    }
    if pubkey[0] == 0x04 {
        // Uncompressed key: 65 bytes, starts with 0x04
        pubkey.len() == 65
    } else if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
        // Compressed key: 33 bytes, starts with 0x02 or 0x03
        pubkey.len() == 33
    } else {
        false
    }
}

/// Cast a script stack element to a boolean value.
///
/// This matches Bitcoin Core's `CastToBool` function exactly:
/// - Empty vector is false
/// - All-zero vector (including negative zero 0x80) is false
/// - Any other value is true
///
/// Reference: Bitcoin Core interpreter.cpp CastToBool()
pub fn cast_to_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Can be negative zero: last byte is 0x80 with all preceding bytes zero
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

// ============================================================================
// Push-only script validation (BIP16)
// ============================================================================

/// Opcode constants for push-only validation
/// Reference: Bitcoin Core script/script.h
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;  // 76 - next byte is length
const OP_PUSHDATA2: u8 = 0x4d;  // 77 - next 2 bytes are length (LE)
const OP_PUSHDATA4: u8 = 0x4e;  // 78 - next 4 bytes are length (LE)
const OP_1NEGATE: u8 = 0x4f;    // 79
const OP_RESERVED: u8 = 0x50;   // 80
const OP_1: u8 = 0x51;          // 81
const OP_16_CONST: u8 = 0x60;   // 96

/// Check if a script contains only push operations.
///
/// A script is "push-only" if every instruction is either:
/// - OP_0 (0x00) - push empty array
/// - Direct push (0x01-0x4b) - push 1-75 bytes
/// - OP_PUSHDATA1 (0x4c) - push up to 255 bytes
/// - OP_PUSHDATA2 (0x4d) - push up to 65535 bytes
/// - OP_PUSHDATA4 (0x4e) - push up to 4GB bytes
/// - OP_1NEGATE (0x4f) - push -1
/// - OP_RESERVED (0x50) - technically a push opcode (returns failure but counted as push)
/// - OP_1..OP_16 (0x51-0x60) - push small integers 1-16
///
/// This is consensus-critical for P2SH: the scriptSig must be push-only
/// before the redeem script is evaluated.
///
/// Reference: Bitcoin Core script/script.cpp CScript::IsPushOnly()
///
/// # Arguments
/// * `script` - The raw script bytes to check
///
/// # Returns
/// `true` if the script contains only push operations, `false` otherwise
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    let len = script.len();

    while pc < len {
        let opcode = script[pc];
        pc += 1;

        // Check if this is a push opcode (opcode <= OP_16)
        // Bitcoin Core: "IsPushOnly() *does* consider OP_RESERVED to be a push-type opcode"
        if opcode > OP_16_CONST {
            return false;
        }

        // Handle data pushes - need to skip over the data
        if opcode == OP_0 {
            // OP_0: push empty array, no data bytes
            continue;
        } else if opcode <= 0x4b {
            // Direct push: opcode is the number of bytes to push (1-75)
            let data_len = opcode as usize;
            if pc + data_len > len {
                // Script truncated, not a valid push-only script
                return false;
            }
            pc += data_len;
        } else if opcode == OP_PUSHDATA1 {
            // OP_PUSHDATA1: next byte is length
            if pc >= len {
                return false;
            }
            let data_len = script[pc] as usize;
            pc += 1;
            if pc + data_len > len {
                return false;
            }
            pc += data_len;
        } else if opcode == OP_PUSHDATA2 {
            // OP_PUSHDATA2: next 2 bytes are length (little-endian)
            if pc + 2 > len {
                return false;
            }
            let data_len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            if pc + data_len > len {
                return false;
            }
            pc += data_len;
        } else if opcode == OP_PUSHDATA4 {
            // OP_PUSHDATA4: next 4 bytes are length (little-endian)
            if pc + 4 > len {
                return false;
            }
            let data_len = u32::from_le_bytes([
                script[pc],
                script[pc + 1],
                script[pc + 2],
                script[pc + 3],
            ]) as usize;
            pc += 4;
            if pc + data_len > len {
                return false;
            }
            pc += data_len;
        }
        // OP_1NEGATE (0x4f), OP_RESERVED (0x50), OP_1..OP_16 (0x51-0x60)
        // These are all push opcodes with no additional data bytes
    }

    true
}

/// Check if a scriptPubKey is a P2SH output.
///
/// P2SH pattern: OP_HASH160 <20 bytes> OP_EQUAL
/// - Byte 0: OP_HASH160 (0xa9)
/// - Byte 1: OP_PUSHBYTES_20 (0x14)
/// - Bytes 2-21: 20-byte script hash
/// - Byte 22: OP_EQUAL (0x87)
///
/// Reference: Bitcoin Core script/script.cpp CScript::IsPayToScriptHash()
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == 0xa9  // OP_HASH160
        && script[1] == 0x14  // Push 20 bytes
        && script[22] == 0x87 // OP_EQUAL
}

/// Verify P2SH push-only constraint on scriptSig.
///
/// When spending a P2SH output, the scriptSig MUST contain only push operations.
/// This is a consensus rule since BIP16 activation and is enforced unconditionally
/// when `SCRIPT_VERIFY_P2SH` is set and the scriptPubKey is P2SH.
///
/// This check is separate from `SCRIPT_VERIFY_SIGPUSHONLY` which applies to ALL
/// scriptSigs. The P2SH push-only rule is consensus-critical and unconditional.
///
/// Reference: Bitcoin Core interpreter.cpp VerifyScript() lines 2054-2056
///
/// # Arguments
/// * `script_sig` - The scriptSig bytes to validate
/// * `script_pubkey` - The scriptPubKey being spent (to check if P2SH)
/// * `flags` - Script verification flags (P2SH must be set)
///
/// # Returns
/// `Ok(())` if valid, `Err(ScriptError::SigPushOnly)` if scriptSig is not push-only
pub fn verify_p2sh_push_only(
    script_sig: &[u8],
    script_pubkey: &[u8],
    flags: ScriptVerifyFlags,
) -> Result<()> {
    // Only check if P2SH flag is set
    if !flags.contains(ScriptVerifyFlags::P2SH) {
        return Ok(());
    }

    // Only check if the scriptPubKey is P2SH
    if !is_p2sh(script_pubkey) {
        return Ok(());
    }

    // scriptSig must be push-only for P2SH
    if !is_push_only(script_sig) {
        return Err(ScriptError::SigPushOnly);
    }

    Ok(())
}

/// Signature version for script execution context.
///
/// This determines which validation rules apply during script execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    /// Legacy (pre-SegWit) scripts
    Base,
    /// SegWit v0 (P2WPKH, P2WSH)
    WitnessV0,
    /// Tapscript (SegWit v1)
    Tapscript,
}

/// Check public key encoding based on flags and signature version.
///
/// Reference: Bitcoin Core interpreter.cpp CheckPubKeyEncoding()
///
/// - STRICTENC: Requires valid compressed or uncompressed key format
/// - WITNESS_PUBKEYTYPE: Requires compressed key for witness v0 scripts
pub fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: ScriptVerifyFlags,
    sigversion: SigVersion,
) -> Result<()> {
    // STRICTENC: require valid public key format
    if flags.contains(ScriptVerifyFlags::STRICTENC)
        && !is_compressed_or_uncompressed_pubkey(pubkey)
    {
        return Err(ScriptError::ExecutionError(
            "Non-canonical public key".to_string(),
        ));
    }

    // BIP141 WITNESS_PUBKEYTYPE: only compressed keys in witness v0
    if flags.contains(ScriptVerifyFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::WitnessPubkeyType);
    }

    Ok(())
}

/// Check MINIMALIF constraint on OP_IF/OP_NOTIF argument.
///
/// Reference: Bitcoin Core interpreter.cpp lines 611-627
///
/// For witness v0 with MINIMALIF flag, and unconditionally for tapscript:
/// The argument to OP_IF/OP_NOTIF must be either:
/// - Empty vector (false)
/// - Exactly `[0x01]` (true)
///
/// Any other value (including `[0x00]`, `[0x02]`, multi-byte values) is rejected.
///
/// # Arguments
/// * `value` - The stack element being used as the IF condition
/// * `flags` - Script verification flags
/// * `sigversion` - Signature version context
///
/// # Returns
/// `Ok(())` if valid, `Err(ScriptError::MinimalIf)` if value is not minimal
pub fn check_minimalif(
    value: &[u8],
    flags: ScriptVerifyFlags,
    sigversion: SigVersion,
) -> Result<()> {
    // Tapscript: MINIMALIF is unconditionally enforced as a consensus rule
    // Reference: Bitcoin Core interpreter.cpp lines 614-619
    if sigversion == SigVersion::Tapscript {
        if value.len() > 1 || (value.len() == 1 && value[0] != 1) {
            return Err(ScriptError::MinimalIf);
        }
    }

    // Witness v0: MINIMALIF is enforced when the flag is set
    // Reference: Bitcoin Core interpreter.cpp lines 621-627
    if sigversion == SigVersion::WitnessV0 && flags.contains(ScriptVerifyFlags::MINIMALIF) {
        if value.len() > 1 {
            return Err(ScriptError::MinimalIf);
        }
        if value.len() == 1 && value[0] != 1 {
            return Err(ScriptError::MinimalIf);
        }
    }

    Ok(())
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
    /// Executes the script and returns whether it evaluates to true.
    /// This is the legacy method that doesn't take verification flags.
    pub fn evaluate_script(script: &Script, stack: &mut Stack) -> Result<bool> {
        Self::evaluate_script_with_flags(script, stack, ScriptVerifyFlags::NONE)
    }

    /// Evaluate a script with verification flags
    ///
    /// Executes the script and returns whether it evaluates to true.
    /// The `flags` parameter controls which consensus rules are enforced.
    pub fn evaluate_script_with_flags(
        script: &Script,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
    ) -> Result<bool> {
        Self::evaluate_script_with_context(script, stack, flags, SigVersion::Base)
    }

    /// Evaluate a witness v0 script with full context
    ///
    /// This method enforces witness-specific rules including:
    /// - WITNESS_PUBKEYTYPE: public keys must be compressed (33 bytes)
    /// - Witness cleanstack (exactly one element after execution)
    ///
    /// After script execution, the stack MUST have exactly one element that
    /// evaluates to true. This is enforced unconditionally for all witness
    /// scripts (not gated by SCRIPT_VERIFY_CLEANSTACK flag).
    ///
    /// Reference: Bitcoin Core ExecuteWitnessScript() in interpreter.cpp
    pub fn evaluate_witness_v0_script(
        script: &Script,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
    ) -> Result<bool> {
        Self::execute_witness_script(script, stack, flags, SigVersion::WitnessV0)
    }

    /// Evaluate a tapscript (witness v1) with full context
    ///
    /// This method enforces tapscript-specific rules including:
    /// - Witness cleanstack (exactly one element after execution)
    ///
    /// After script execution, the stack MUST have exactly one element that
    /// evaluates to true. This is enforced unconditionally for all witness
    /// scripts (not gated by SCRIPT_VERIFY_CLEANSTACK flag).
    ///
    /// Reference: Bitcoin Core ExecuteWitnessScript() in interpreter.cpp
    pub fn evaluate_tapscript(
        script: &Script,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
    ) -> Result<bool> {
        Self::execute_witness_script(script, stack, flags, SigVersion::Tapscript)
    }

    /// Execute a witness script with cleanstack enforcement.
    ///
    /// This is the internal method that runs the script and enforces witness
    /// cleanstack rules. After execution:
    /// 1. Stack must have exactly one element (CleanStack error otherwise)
    /// 2. That element must cast to true (EvalFalse error otherwise)
    ///
    /// This check is NOT gated by the SCRIPT_VERIFY_CLEANSTACK flag — it is
    /// unconditionally enforced for all witness scripts (v0 and v1/tapscript).
    ///
    /// Reference: Bitcoin Core ExecuteWitnessScript() lines 1866-1868
    fn execute_witness_script(
        script: &Script,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
        sigversion: SigVersion,
    ) -> Result<bool> {
        // Check script size limit (Bitcoin Core limit is 10,000 bytes)
        if script.len() > 10000 {
            return Err(ScriptError::ScriptTooLarge);
        }

        // Parse and execute the script with control flow
        let instructions = script.instructions().collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ScriptError::ExecutionError("Invalid script".to_string()))?;

        // Control flow state: stack of booleans indicating whether we're executing
        // Each entry corresponds to an IF/NOTIF. True means we're in the executing branch.
        let mut exec_stack: Vec<bool> = Vec::new();

        for instruction in instructions {
            // Check if we should execute this instruction
            let executing = exec_stack.iter().all(|&b| b);

            match instruction {
                Instruction::PushBytes(bytes) => {
                    if executing {
                        stack.push(bytes.as_bytes().to_vec());
                    }
                }
                Instruction::Op(opcode) => {
                    // Handle control flow opcodes specially
                    match opcode {
                        OP_IF | OP_NOTIF => {
                            if executing {
                                if stack.is_empty() {
                                    return Err(ScriptError::StackUnderflow);
                                }
                                let value = stack.pop()?;

                                // MINIMALIF check for witness scripts
                                check_minimalif(&value, flags, sigversion)?;

                                let condition = cast_to_bool(&value);
                                let take_branch = if opcode == OP_IF { condition } else { !condition };
                                exec_stack.push(take_branch);
                            } else {
                                // Not executing, but still need to track nesting
                                exec_stack.push(false);
                            }
                        }
                        OP_ELSE => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            // Flip the execution state if the parent is executing
                            let parent_executing = exec_stack.len() <= 1 ||
                                exec_stack[..exec_stack.len()-1].iter().all(|&b| b);
                            if parent_executing {
                                let last = exec_stack.last_mut().unwrap();
                                *last = !*last;
                            }
                        }
                        OP_ENDIF => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            exec_stack.pop();
                        }
                        _ => {
                            if executing {
                                Self::execute_opcode_with_context(opcode, stack, flags, sigversion)?;
                            }
                        }
                    }
                }
            }
        }

        // Check for unbalanced conditionals
        if !exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        // Witness cleanstack: stack must have exactly one element
        // Reference: Bitcoin Core interpreter.cpp line 1867
        // "Scripts inside witness implicitly require cleanstack behaviour"
        if stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }

        // The single element must cast to true
        // Reference: Bitcoin Core interpreter.cpp line 1868
        let result = stack.peek()?;
        if !cast_to_bool(result) {
            return Err(ScriptError::EvalFalse);
        }

        Ok(true)
    }

    /// Evaluate a script with full context (flags and signature version)
    ///
    /// This is the core evaluation method that supports all script contexts.
    pub fn evaluate_script_with_context(
        script: &Script,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
        sigversion: SigVersion,
    ) -> Result<bool> {
        // Check script size limit (Bitcoin Core limit is 10,000 bytes)
        if script.len() > 10000 {
            return Err(ScriptError::ScriptTooLarge);
        }

        // Parse the script
        let instructions = script.instructions().collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ScriptError::ExecutionError("Invalid script".to_string()))?;

        // Control flow state: stack of booleans indicating whether we're executing
        // Each entry corresponds to an IF/NOTIF. True means we're in the executing branch.
        let mut exec_stack: Vec<bool> = Vec::new();

        for instruction in instructions {
            // Check if we should execute this instruction
            let executing = exec_stack.iter().all(|&b| b);

            match instruction {
                Instruction::PushBytes(bytes) => {
                    if executing {
                        stack.push(bytes.as_bytes().to_vec());
                    }
                }
                Instruction::Op(opcode) => {
                    // Handle control flow opcodes specially
                    match opcode {
                        OP_IF | OP_NOTIF => {
                            if executing {
                                if stack.is_empty() {
                                    return Err(ScriptError::StackUnderflow);
                                }
                                let value = stack.pop()?;

                                // MINIMALIF check (only for witness contexts)
                                check_minimalif(&value, flags, sigversion)?;

                                let condition = cast_to_bool(&value);
                                let take_branch = if opcode == OP_IF { condition } else { !condition };
                                exec_stack.push(take_branch);
                            } else {
                                // Not executing, but still need to track nesting
                                exec_stack.push(false);
                            }
                        }
                        OP_ELSE => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            // Flip the execution state if the parent is executing
                            let parent_executing = exec_stack.len() <= 1 ||
                                exec_stack[..exec_stack.len()-1].iter().all(|&b| b);
                            if parent_executing {
                                let last = exec_stack.last_mut().unwrap();
                                *last = !*last;
                            }
                        }
                        OP_ENDIF => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            exec_stack.pop();
                        }
                        _ => {
                            if executing {
                                Self::execute_opcode_with_context(opcode, stack, flags, sigversion)?;
                            }
                        }
                    }
                }
            }
        }

        // Check for unbalanced conditionals
        if !exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        // Script succeeds if stack is not empty and top element is truthy
        if stack.is_empty() {
            return Ok(false);
        }

        let top = stack.peek()?;
        Ok(!top.is_empty() && top[0] != 0)
    }

    /// Execute a single opcode (legacy, no flags)
    fn execute_opcode(opcode: bitcoin::opcodes::Opcode, stack: &mut Stack) -> Result<()> {
        Self::execute_opcode_with_context(opcode, stack, ScriptVerifyFlags::NONE, SigVersion::Base)
    }

    /// Execute a single opcode with verification flags (legacy context)
    fn execute_opcode_with_flags(
        opcode: bitcoin::opcodes::Opcode,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
    ) -> Result<()> {
        Self::execute_opcode_with_context(opcode, stack, flags, SigVersion::Base)
    }

    /// Execute a single opcode with full context (flags and signature version)
    ///
    /// This method enforces all context-dependent validation rules including
    /// WITNESS_PUBKEYTYPE for witness v0 scripts.
    fn execute_opcode_with_context(
        opcode: bitcoin::opcodes::Opcode,
        stack: &mut Stack,
        flags: ScriptVerifyFlags,
        sigversion: SigVersion,
    ) -> Result<()> {
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
                // Signature verification
                // In a full implementation, this would need access to the transaction
                // and input index to create the proper sighash
                let pubkey = stack.pop()?;
                let sig = stack.pop()?;

                // BIP141: WITNESS_PUBKEYTYPE enforcement
                // In witness v0 scripts, public keys must be compressed (33 bytes, 0x02/0x03 prefix).
                // This check happens BEFORE signature verification.
                // Reference: Bitcoin Core interpreter.cpp CheckPubKeyEncoding()
                check_pubkey_encoding(&pubkey, flags, sigversion)?;

                // For now, just check that both are non-empty
                // Real implementation would verify the signature cryptographically
                let valid = !pubkey.is_empty() && !sig.is_empty();

                // BIP146: NULLFAIL enforcement
                // If NULLFAIL flag is set and signature check fails, the signature
                // MUST be an empty byte vector, otherwise the script fails.
                // Reference: Bitcoin Core interpreter.cpp line 341-342
                if !valid && flags.contains(ScriptVerifyFlags::NULLFAIL) && !sig.is_empty() {
                    return Err(ScriptError::NullFail);
                }

                stack.push(if valid { vec![1] } else { vec![0] });

                if opcode == OP_CHECKSIGVERIFY && !valid {
                    return Err(ScriptError::ValidationFailed);
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                // CHECKMULTISIG: ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                // Reference: Bitcoin Core interpreter.cpp lines 1105-1215

                // Get number of public keys
                let n_keys_count = {
                    let n_keys_bytes = stack.pop()?;
                    Self::decode_num(&n_keys_bytes)? as i32
                };

                if n_keys_count < 0 || n_keys_count > 20 {
                    return Err(ScriptError::ExecutionError(
                        "Invalid pubkey count in CHECKMULTISIG".to_string(),
                    ));
                }

                // Collect public keys
                let mut pubkeys = Vec::new();
                for _ in 0..n_keys_count {
                    let pubkey = stack.pop()?;
                    // BIP141: WITNESS_PUBKEYTYPE enforcement for all pubkeys
                    // In witness v0 scripts, ALL public keys must be compressed.
                    // Reference: Bitcoin Core interpreter.cpp CheckPubKeyEncoding()
                    check_pubkey_encoding(&pubkey, flags, sigversion)?;
                    pubkeys.push(pubkey);
                }

                // Get number of signatures
                let n_sigs_count = {
                    let n_sigs_bytes = stack.pop()?;
                    Self::decode_num(&n_sigs_bytes)? as i32
                };

                if n_sigs_count < 0 || n_sigs_count > n_keys_count {
                    return Err(ScriptError::ExecutionError(
                        "Invalid signature count in CHECKMULTISIG".to_string(),
                    ));
                }

                // Collect signatures
                let mut signatures = Vec::new();
                for _ in 0..n_sigs_count {
                    signatures.push(stack.pop()?);
                }

                // Pop the dummy element (CHECKMULTISIG bug)
                let dummy = stack.pop()?;
                if flags.contains(ScriptVerifyFlags::NULLDUMMY) && !dummy.is_empty() {
                    return Err(ScriptError::ExecutionError(
                        "NULLDUMMY: dummy element must be empty".to_string(),
                    ));
                }

                // Simplified verification: for now, check all signatures are non-empty
                // and we have enough valid pubkeys.
                // Real implementation would verify each signature against pubkeys.
                let mut valid = true;
                let mut keys_remaining = n_keys_count;
                let mut sigs_checked = 0;

                for sig in &signatures {
                    if sig.is_empty() {
                        // Empty signature never matches
                        valid = false;
                        break;
                    }
                    sigs_checked += 1;
                    keys_remaining -= 1;

                    // If more signatures remain than keys, fail
                    if (n_sigs_count - sigs_checked) > keys_remaining {
                        valid = false;
                        break;
                    }
                }

                // BIP146: NULLFAIL enforcement for CHECKMULTISIG
                // If the operation failed, ALL signatures must be empty vectors.
                // Reference: Bitcoin Core interpreter.cpp lines 1183-1191
                if !valid && flags.contains(ScriptVerifyFlags::NULLFAIL) {
                    for sig in &signatures {
                        if !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                    }
                }

                stack.push(if valid { vec![1] } else { vec![0] });

                if opcode == OP_CHECKMULTISIGVERIFY && !valid {
                    return Err(ScriptError::ValidationFailed);
                }
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
            OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                return Err(ScriptError::ExecutionError(
                    format!("Disabled opcode: {:?}", opcode),
                ));
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
    }

    #[test]
    fn test_disabled_opcodes() {
        let mut stack = Stack::new();
        stack.push(vec![3]);
        stack.push(vec![4]);
        let result = ScriptInterpreter::execute_opcode(OP_MUL, &mut stack);
        assert!(result.is_err());

        let mut stack = Stack::new();
        stack.push(vec![4]);
        stack.push(vec![2]);
        let result = ScriptInterpreter::execute_opcode(OP_DIV, &mut stack);
        assert!(result.is_err());
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

    // =========================================================================
    // NULLFAIL (BIP146) Tests
    // =========================================================================

    #[test]
    fn test_nullfail_checksig_with_empty_sig_passes() {
        // When NULLFAIL is enabled and signature check fails with empty sig,
        // it should NOT error - just push false
        let mut stack = Stack::new();
        stack.push(vec![]); // empty signature (passes NULLFAIL)
        stack.push(vec![0x02; 33]); // valid-looking pubkey

        let result = ScriptInterpreter::execute_opcode_with_flags(
            OP_CHECKSIG,
            &mut stack,
            ScriptVerifyFlags::NULLFAIL,
        );

        // Should succeed (no NULLFAIL error), but push false
        assert!(result.is_ok());
        assert_eq!(stack.pop().unwrap(), vec![0]); // false
    }

    #[test]
    fn test_nullfail_checksig_with_nonempty_sig_fails() {
        // When NULLFAIL is enabled and signature check fails with non-empty sig,
        // it MUST return NullFail error
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // non-empty (invalid) signature
        stack.push(vec![]); // empty pubkey (causes check to fail)

        let result = ScriptInterpreter::execute_opcode_with_flags(
            OP_CHECKSIG,
            &mut stack,
            ScriptVerifyFlags::NULLFAIL,
        );

        // Should fail with NULLFAIL error
        assert!(matches!(result, Err(ScriptError::NullFail)));
    }

    #[test]
    fn test_nullfail_disabled_allows_nonempty_failed_sig() {
        // When NULLFAIL is NOT enabled, a failing signature with non-empty sig
        // should just push false, not error
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // non-empty (invalid) signature
        stack.push(vec![]); // empty pubkey (causes check to fail)

        let result = ScriptInterpreter::execute_opcode_with_flags(
            OP_CHECKSIG,
            &mut stack,
            ScriptVerifyFlags::NONE, // NULLFAIL not enabled
        );

        // Should succeed, pushing false
        assert!(result.is_ok());
        assert_eq!(stack.pop().unwrap(), vec![0]); // false
    }

    #[test]
    fn test_nullfail_checksigverify_with_nonempty_sig_fails() {
        // CHECKSIGVERIFY with NULLFAIL and non-empty failing sig
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // non-empty (invalid) signature
        stack.push(vec![]); // empty pubkey (causes check to fail)

        let result = ScriptInterpreter::execute_opcode_with_flags(
            OP_CHECKSIGVERIFY,
            &mut stack,
            ScriptVerifyFlags::NULLFAIL,
        );

        // NULLFAIL error takes precedence
        assert!(matches!(result, Err(ScriptError::NullFail)));
    }

    #[test]
    fn test_script_verify_flags_constants() {
        // Test that flag constants have correct values
        assert_eq!(ScriptVerifyFlags::NONE.bits(), 0);
        assert_eq!(ScriptVerifyFlags::P2SH.bits(), 1 << 0);
        assert_eq!(ScriptVerifyFlags::NULLFAIL.bits(), 1 << 14);
        assert_eq!(ScriptVerifyFlags::WITNESS.bits(), 1 << 11);
        assert_eq!(ScriptVerifyFlags::TAPROOT.bits(), 1 << 17);
    }

    #[test]
    fn test_script_verify_flags_combined() {
        // Test combining multiple flags
        let flags = ScriptVerifyFlags::P2SH
            | ScriptVerifyFlags::WITNESS
            | ScriptVerifyFlags::NULLFAIL;

        assert!(flags.contains(ScriptVerifyFlags::P2SH));
        assert!(flags.contains(ScriptVerifyFlags::WITNESS));
        assert!(flags.contains(ScriptVerifyFlags::NULLFAIL));
        assert!(!flags.contains(ScriptVerifyFlags::TAPROOT));
    }

    #[test]
    fn test_segwit_activation_heights() {
        use bitcoin::Network;

        // Test activation heights
        assert_eq!(activation_heights::segwit_height(Network::Bitcoin), 481824);
        assert_eq!(activation_heights::segwit_height(Network::Testnet), 834624);
        assert_eq!(activation_heights::segwit_height(Network::Testnet4), 0);
        assert_eq!(activation_heights::segwit_height(Network::Regtest), 0);
    }

    #[test]
    fn test_get_script_flags_for_height_mainnet() {
        use bitcoin::Network;

        // Before any softforks
        let flags = activation_heights::get_script_flags_for_height(0, Network::Bitcoin);
        assert_eq!(flags, ScriptVerifyFlags::NONE);

        // At P2SH activation (173805)
        let flags = activation_heights::get_script_flags_for_height(173805, Network::Bitcoin);
        assert!(flags.contains(ScriptVerifyFlags::P2SH));
        assert!(!flags.contains(ScriptVerifyFlags::NULLFAIL));

        // At SegWit activation (481824) - NULLFAIL must be enabled
        let flags = activation_heights::get_script_flags_for_height(481824, Network::Bitcoin);
        assert!(flags.contains(ScriptVerifyFlags::P2SH));
        assert!(flags.contains(ScriptVerifyFlags::WITNESS));
        assert!(flags.contains(ScriptVerifyFlags::NULLFAIL));
        assert!(flags.contains(ScriptVerifyFlags::NULLDUMMY));
        assert!(flags.contains(ScriptVerifyFlags::WITNESS_PUBKEYTYPE));

        // After Taproot activation (709632)
        let flags = activation_heights::get_script_flags_for_height(709632, Network::Bitcoin);
        assert!(flags.contains(ScriptVerifyFlags::NULLFAIL));
        assert!(flags.contains(ScriptVerifyFlags::TAPROOT));
    }

    #[test]
    fn test_get_script_flags_for_height_regtest() {
        use bitcoin::Network;

        // Regtest has all flags from genesis
        let flags = activation_heights::get_script_flags_for_height(0, Network::Regtest);
        assert!(flags.contains(ScriptVerifyFlags::P2SH));
        assert!(flags.contains(ScriptVerifyFlags::DERSIG));
        assert!(flags.contains(ScriptVerifyFlags::CHECKLOCKTIMEVERIFY));
        assert!(flags.contains(ScriptVerifyFlags::CHECKSEQUENCEVERIFY));
        assert!(flags.contains(ScriptVerifyFlags::WITNESS));
        assert!(flags.contains(ScriptVerifyFlags::NULLFAIL));
    }

    #[test]
    fn test_nullfail_error_type() {
        // Verify NullFail error is properly constructed
        let err = ScriptError::NullFail;
        assert_eq!(
            err.to_string(),
            "Signature must be empty when verification fails (NULLFAIL)"
        );
    }

    // =========================================================================
    // WITNESS_PUBKEYTYPE (BIP141) Tests
    // =========================================================================

    #[test]
    fn test_is_compressed_pubkey_valid() {
        // Valid compressed pubkey: 33 bytes, starts with 0x02
        let compressed_02 = [0x02; 33];
        assert!(is_compressed_pubkey(&compressed_02));

        // Valid compressed pubkey: 33 bytes, starts with 0x03
        let compressed_03 = [0x03; 33];
        assert!(is_compressed_pubkey(&compressed_03));
    }

    #[test]
    fn test_is_compressed_pubkey_invalid_uncompressed() {
        // Uncompressed pubkey: 65 bytes, starts with 0x04
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0u8; 64]);
        assert!(!is_compressed_pubkey(&uncompressed));
    }

    #[test]
    fn test_is_compressed_pubkey_invalid_length() {
        // Too short
        let too_short = [0x02; 32];
        assert!(!is_compressed_pubkey(&too_short));

        // Too long
        let too_long = [0x02; 34];
        assert!(!is_compressed_pubkey(&too_long));
    }

    #[test]
    fn test_is_compressed_pubkey_invalid_prefix() {
        // Wrong prefix (0x04 with 33 bytes)
        let wrong_prefix = [0x04; 33];
        assert!(!is_compressed_pubkey(&wrong_prefix));

        // Wrong prefix (0x01 with 33 bytes)
        let wrong_prefix_01 = [0x01; 33];
        assert!(!is_compressed_pubkey(&wrong_prefix_01));
    }

    #[test]
    fn test_is_compressed_or_uncompressed_pubkey() {
        // Compressed 0x02
        let compressed_02 = [0x02; 33];
        assert!(is_compressed_or_uncompressed_pubkey(&compressed_02));

        // Compressed 0x03
        let compressed_03 = [0x03; 33];
        assert!(is_compressed_or_uncompressed_pubkey(&compressed_03));

        // Uncompressed 0x04
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0u8; 64]);
        assert!(is_compressed_or_uncompressed_pubkey(&uncompressed));

        // Invalid: 0x04 with wrong length
        let mut invalid = vec![0x04];
        invalid.extend_from_slice(&[0u8; 32]);
        assert!(!is_compressed_or_uncompressed_pubkey(&invalid));
    }

    #[test]
    fn test_witness_pubkeytype_compressed_key_passes() {
        // A witness v0 CHECKSIG with compressed pubkey should pass
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // dummy signature
        stack.push([0x02; 33].to_vec()); // compressed pubkey

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKSIG,
            &mut stack,
            flags,
            SigVersion::WitnessV0,
        );

        // Should succeed (pubkey check passes)
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_pubkeytype_uncompressed_key_fails() {
        // A witness v0 CHECKSIG with uncompressed pubkey should fail
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // dummy signature
        let mut uncompressed_pubkey = vec![0x04];
        uncompressed_pubkey.extend_from_slice(&[0u8; 64]);
        stack.push(uncompressed_pubkey);

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKSIG,
            &mut stack,
            flags,
            SigVersion::WitnessV0,
        );

        // Should fail with WitnessPubkeyType error
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn test_witness_pubkeytype_legacy_allows_uncompressed() {
        // A legacy (non-witness) CHECKSIG with uncompressed pubkey should pass
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // dummy signature
        let mut uncompressed_pubkey = vec![0x04];
        uncompressed_pubkey.extend_from_slice(&[0u8; 64]);
        stack.push(uncompressed_pubkey);

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKSIG,
            &mut stack,
            flags,
            SigVersion::Base, // Legacy context
        );

        // Should succeed (WITNESS_PUBKEYTYPE only applies to witness v0)
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_pubkeytype_flag_disabled_allows_uncompressed() {
        // When WITNESS_PUBKEYTYPE flag is not set, uncompressed keys are allowed
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // dummy signature
        let mut uncompressed_pubkey = vec![0x04];
        uncompressed_pubkey.extend_from_slice(&[0u8; 64]);
        stack.push(uncompressed_pubkey);

        let flags = ScriptVerifyFlags::NONE; // No WITNESS_PUBKEYTYPE
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKSIG,
            &mut stack,
            flags,
            SigVersion::WitnessV0,
        );

        // Should succeed (flag not enabled)
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_pubkeytype_checkmultisig_compressed_passes() {
        // CHECKMULTISIG in witness v0 with all compressed pubkeys should pass
        let mut stack = Stack::new();
        stack.push(vec![]); // dummy element for CHECKMULTISIG bug
        stack.push(vec![0x30, 0x06]); // signature 1
        stack.push(vec![1]); // 1 signature required
        stack.push([0x02; 33].to_vec()); // compressed pubkey 1
        stack.push([0x03; 33].to_vec()); // compressed pubkey 2
        stack.push(vec![2]); // 2 pubkeys total

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKMULTISIG,
            &mut stack,
            flags,
            SigVersion::WitnessV0,
        );

        // Should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_pubkeytype_checkmultisig_uncompressed_fails() {
        // CHECKMULTISIG in witness v0 with uncompressed pubkey should fail
        let mut stack = Stack::new();
        stack.push(vec![]); // dummy element for CHECKMULTISIG bug
        stack.push(vec![0x30, 0x06]); // signature 1
        stack.push(vec![1]); // 1 signature required
        stack.push([0x02; 33].to_vec()); // compressed pubkey 1
        let mut uncompressed_pubkey = vec![0x04];
        uncompressed_pubkey.extend_from_slice(&[0u8; 64]);
        stack.push(uncompressed_pubkey); // uncompressed pubkey 2
        stack.push(vec![2]); // 2 pubkeys total

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::execute_opcode_with_context(
            OP_CHECKMULTISIG,
            &mut stack,
            flags,
            SigVersion::WitnessV0,
        );

        // Should fail with WitnessPubkeyType error
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn test_witness_pubkeytype_error_message() {
        let err = ScriptError::WitnessPubkeyType;
        assert_eq!(
            err.to_string(),
            "Public key must be compressed in witness v0 scripts"
        );
    }

    #[test]
    fn test_check_pubkey_encoding_witness_v0() {
        // Compressed key in witness v0 with flag should pass
        let compressed = [0x02; 33];
        let result = check_pubkey_encoding(
            &compressed,
            ScriptVerifyFlags::WITNESS_PUBKEYTYPE,
            SigVersion::WitnessV0,
        );
        assert!(result.is_ok());

        // Uncompressed key in witness v0 with flag should fail
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0u8; 64]);
        let result = check_pubkey_encoding(
            &uncompressed,
            ScriptVerifyFlags::WITNESS_PUBKEYTYPE,
            SigVersion::WitnessV0,
        );
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn test_evaluate_witness_v0_script_with_compressed_key() {
        // Test full script evaluation in witness v0 context with compressed key
        let script = Builder::new()
            .push_slice(&[0x30, 0x06]) // dummy sig
            .push_slice(&[0x02; 33])   // compressed pubkey
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Should succeed (compressed key passes)
        assert!(result.is_ok());
    }

    #[test]
    fn test_evaluate_witness_v0_script_with_uncompressed_key_fails() {
        // Test full script evaluation in witness v0 context with uncompressed key
        // Build the uncompressed key as a fixed-size array
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;

        let script = Builder::new()
            .push_slice([0x30, 0x06]) // dummy sig
            .push_slice(uncompressed) // uncompressed pubkey
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Should fail with WitnessPubkeyType error
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn test_sigversion_equality() {
        assert_eq!(SigVersion::Base, SigVersion::Base);
        assert_eq!(SigVersion::WitnessV0, SigVersion::WitnessV0);
        assert_eq!(SigVersion::Tapscript, SigVersion::Tapscript);
        assert_ne!(SigVersion::Base, SigVersion::WitnessV0);
        assert_ne!(SigVersion::WitnessV0, SigVersion::Tapscript);
    }

    // =========================================================================
    // cast_to_bool Tests
    // =========================================================================

    #[test]
    fn test_cast_to_bool_empty_is_false() {
        // Empty vector is false
        assert!(!cast_to_bool(&[]));
    }

    #[test]
    fn test_cast_to_bool_zero_is_false() {
        // Single zero byte is false
        assert!(!cast_to_bool(&[0]));
        // Multiple zero bytes are false
        assert!(!cast_to_bool(&[0, 0, 0]));
    }

    #[test]
    fn test_cast_to_bool_negative_zero_is_false() {
        // Negative zero (0x80) is false
        assert!(!cast_to_bool(&[0x80]));
        // Multiple zero bytes followed by 0x80 is false (negative zero)
        assert!(!cast_to_bool(&[0, 0, 0x80]));
    }

    #[test]
    fn test_cast_to_bool_nonzero_is_true() {
        // Any non-zero value is true
        assert!(cast_to_bool(&[1]));
        assert!(cast_to_bool(&[0xff]));
        assert!(cast_to_bool(&[0, 1]));
        assert!(cast_to_bool(&[0, 0, 1]));
    }

    #[test]
    fn test_cast_to_bool_nonzero_in_middle_is_true() {
        // Non-zero byte anywhere (except final 0x80) makes it true
        assert!(cast_to_bool(&[1, 0]));
        assert!(cast_to_bool(&[0, 1, 0]));
    }

    #[test]
    fn test_cast_to_bool_0x80_not_last_is_true() {
        // 0x80 is only negative zero if it's the last byte
        assert!(cast_to_bool(&[0x80, 0]));
        assert!(cast_to_bool(&[0x80, 0x80]));
    }

    // =========================================================================
    // Witness Cleanstack Tests (BIP141)
    // =========================================================================

    #[test]
    fn test_witness_cleanstack_single_true_element_passes() {
        // Script that leaves exactly one true element on the stack
        let script = Builder::new()
            .push_int(1) // Push 1 (true)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_witness_cleanstack_empty_stack_fails() {
        // Empty script leaves empty stack - should fail cleanstack
        let script = Builder::new().into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_multiple_elements_fails() {
        // Script that leaves two elements on the stack
        let script = Builder::new()
            .push_int(1)
            .push_int(2)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_three_elements_fails() {
        // Script that leaves three elements on the stack
        let script = Builder::new()
            .push_int(1)
            .push_int(2)
            .push_int(3)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_false_element_fails() {
        // Script that leaves exactly one element but it's false (zero)
        let script = Builder::new()
            .push_int(0) // Push 0 (false)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Cleanstack passes (1 element), but element is false
        assert!(matches!(result, Err(ScriptError::EvalFalse)));
    }

    #[test]
    fn test_witness_cleanstack_op_true_passes() {
        // OP_TRUE (OP_1) pushes 1 - should pass
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_cleanstack_op_true_op_true_fails() {
        // Two OP_TRUE leaves two elements - cleanstack fails
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_not_flag_gated() {
        // Witness cleanstack is NOT gated by SCRIPT_VERIFY_CLEANSTACK flag
        // It's always enforced for witness scripts

        // Script that leaves two elements
        let script = Builder::new()
            .push_int(1)
            .push_int(2)
            .into_script();

        // Even with CLEANSTACK flag NOT set, witness cleanstack is enforced
        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE; // No CLEANSTACK flag
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Should still fail - witness cleanstack is unconditional
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_equal_passes() {
        // Script: 1 1 OP_EQUAL leaves one true element
        let script = Builder::new()
            .push_int(1)
            .push_int(1)
            .push_opcode(OP_EQUAL)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_cleanstack_equal_false_fails() {
        // Script: 1 2 OP_EQUAL leaves one false element
        let script = Builder::new()
            .push_int(1)
            .push_int(2)
            .push_opcode(OP_EQUAL)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Cleanstack passes (1 element), but element is false
        assert!(matches!(result, Err(ScriptError::EvalFalse)));
    }

    #[test]
    fn test_witness_cleanstack_dup_fails() {
        // Script: 1 OP_DUP leaves two elements
        let script = Builder::new()
            .push_int(1)
            .push_opcode(OP_DUP)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_dup_equalverify_passes() {
        // Script: 1 OP_DUP OP_EQUALVERIFY leaves one element (the original 1)
        // Wait, that's wrong - EQUALVERIFY consumes both, then we need something left
        // Let's do: 1 OP_DUP 1 OP_EQUALVERIFY - leaves one element
        let script = Builder::new()
            .push_int(1)
            .push_opcode(OP_DUP)
            .push_opcode(OP_EQUALVERIFY) // Verifies top two are equal, removes both
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // 1 OP_DUP gives [1, 1], EQUALVERIFY checks and removes both
        // Stack is empty, so cleanstack fails
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_witness_cleanstack_add_passes() {
        // Script: 2 3 OP_ADD leaves one element (5)
        let script = Builder::new()
            .push_int(2)
            .push_int(3)
            .push_opcode(OP_ADD)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_cleanstack_with_initial_stack_elements() {
        // If stack already has elements before script execution,
        // they count towards the final cleanstack check

        let script = Builder::new()
            .push_int(1)
            .into_script();

        let mut stack = Stack::new();
        stack.push(vec![42]); // Pre-existing element

        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Two elements on stack (42 and 1) - cleanstack fails
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    // =========================================================================
    // Tapscript Cleanstack Tests
    // =========================================================================

    #[test]
    fn test_tapscript_cleanstack_single_true_element_passes() {
        let script = Builder::new()
            .push_int(1)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_tapscript(&script, &mut stack, flags);

        assert!(result.is_ok());
    }

    #[test]
    fn test_tapscript_cleanstack_multiple_elements_fails() {
        let script = Builder::new()
            .push_int(1)
            .push_int(2)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_tapscript(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_tapscript_cleanstack_false_element_fails() {
        let script = Builder::new()
            .push_int(0)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_tapscript(&script, &mut stack, flags);

        assert!(matches!(result, Err(ScriptError::EvalFalse)));
    }

    // =========================================================================
    // CleanStack Error Tests
    // =========================================================================

    #[test]
    fn test_cleanstack_error_message() {
        let err = ScriptError::CleanStack;
        assert_eq!(
            err.to_string(),
            "Script must leave exactly one element on the stack (CLEANSTACK)"
        );
    }

    #[test]
    fn test_eval_false_error_message() {
        let err = ScriptError::EvalFalse;
        assert_eq!(err.to_string(), "Script evaluated to false");
    }

    // =========================================================================
    // Witness Eval Combined Tests (cleanstack + other rules)
    // =========================================================================

    #[test]
    fn test_witness_eval_cleanstack_with_pubkeytype() {
        // Test that both cleanstack and WITNESS_PUBKEYTYPE are enforced

        // First, test that uncompressed key fails before cleanstack check
        let mut stack = Stack::new();
        stack.push(vec![0x30, 0x06]); // dummy signature
        let mut uncompressed_pubkey = vec![0x04];
        uncompressed_pubkey.extend_from_slice(&[0u8; 64]);
        stack.push(uncompressed_pubkey);

        let script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // Should fail with WitnessPubkeyType (checked before cleanstack)
        assert!(matches!(result, Err(ScriptError::WitnessPubkeyType)));
    }

    #[test]
    fn test_witness_eval_cleanstack_with_compressed_key_and_extra_element() {
        // Compressed key passes WITNESS_PUBKEYTYPE, but extra element fails cleanstack
        let script = Builder::new()
            .push_slice(&[0x30, 0x06]) // dummy sig
            .push_slice(&[0x02; 33])   // compressed pubkey
            .push_opcode(OP_CHECKSIG)
            .push_int(42) // Extra element that breaks cleanstack
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::WITNESS_PUBKEYTYPE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);

        // CHECKSIG leaves result, then 42 is pushed - 2 elements fails cleanstack
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    // =========================================================================
    // P2SH Push-Only Tests (BIP16)
    // =========================================================================

    #[test]
    fn test_is_push_only_empty_script() {
        // Empty script is push-only (vacuously true)
        assert!(is_push_only(&[]));
    }

    #[test]
    fn test_is_push_only_op_0() {
        // OP_0 (0x00) is a push opcode
        assert!(is_push_only(&[0x00]));
    }

    #[test]
    fn test_is_push_only_small_integers() {
        // OP_1..OP_16 (0x51-0x60) are push opcodes
        for opcode in 0x51..=0x60 {
            assert!(is_push_only(&[opcode]), "OP_{} should be push-only", opcode - 0x50);
        }
    }

    #[test]
    fn test_is_push_only_op_1negate() {
        // OP_1NEGATE (0x4f) is a push opcode
        assert!(is_push_only(&[0x4f]));
    }

    #[test]
    fn test_is_push_only_op_reserved() {
        // OP_RESERVED (0x50) is considered a push opcode by Bitcoin Core
        // even though it causes script failure when executed
        assert!(is_push_only(&[0x50]));
    }

    #[test]
    fn test_is_push_only_direct_push() {
        // Direct push: opcode 0x01-0x4b specifies length
        // Push 5 bytes: [0x05, byte1, byte2, byte3, byte4, byte5]
        let script = vec![0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(is_push_only(&script));

        // Push 75 bytes (max direct push)
        let mut script_75 = vec![0x4b]; // push 75 bytes
        script_75.extend_from_slice(&[0u8; 75]);
        assert!(is_push_only(&script_75));
    }

    #[test]
    fn test_is_push_only_pushdata1() {
        // OP_PUSHDATA1 (0x4c): next byte is length
        // Push 100 bytes
        let mut script = vec![0x4c, 100]; // OP_PUSHDATA1, length=100
        script.extend_from_slice(&[0u8; 100]);
        assert!(is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_pushdata2() {
        // OP_PUSHDATA2 (0x4d): next 2 bytes are length (little-endian)
        // Push 300 bytes
        let mut script = vec![0x4d, 0x2c, 0x01]; // OP_PUSHDATA2, length=300 (0x012c)
        script.extend_from_slice(&[0u8; 300]);
        assert!(is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_pushdata4() {
        // OP_PUSHDATA4 (0x4e): next 4 bytes are length (little-endian)
        // Push 100 bytes using PUSHDATA4
        let mut script = vec![0x4e, 0x64, 0x00, 0x00, 0x00]; // OP_PUSHDATA4, length=100
        script.extend_from_slice(&[0u8; 100]);
        assert!(is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_multiple_pushes() {
        // Multiple push operations
        let script = vec![
            0x00,             // OP_0
            0x51,             // OP_1
            0x03, 0xaa, 0xbb, 0xcc,  // push 3 bytes
            0x4f,             // OP_1NEGATE
            0x60,             // OP_16
        ];
        assert!(is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_fails_op_dup() {
        // OP_DUP (0x76) is NOT a push opcode
        assert!(!is_push_only(&[0x76]));
    }

    #[test]
    fn test_is_push_only_fails_op_hash160() {
        // OP_HASH160 (0xa9) is NOT a push opcode
        assert!(!is_push_only(&[0xa9]));
    }

    #[test]
    fn test_is_push_only_fails_op_checksig() {
        // OP_CHECKSIG (0xac) is NOT a push opcode
        assert!(!is_push_only(&[0xac]));
    }

    #[test]
    fn test_is_push_only_fails_op_equal() {
        // OP_EQUAL (0x87) is NOT a push opcode
        assert!(!is_push_only(&[0x87]));
    }

    #[test]
    fn test_is_push_only_fails_with_computation_in_middle() {
        // Script: push 1, OP_DUP, push 2
        // Even with valid pushes, a single non-push opcode fails
        let script = vec![0x51, 0x76, 0x52]; // OP_1, OP_DUP, OP_2
        assert!(!is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_fails_truncated_direct_push() {
        // Direct push claims 5 bytes but only 3 are present
        let script = vec![0x05, 0x01, 0x02, 0x03];
        assert!(!is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_fails_truncated_pushdata1() {
        // OP_PUSHDATA1 claims 100 bytes but only 10 are present
        let mut script = vec![0x4c, 100];
        script.extend_from_slice(&[0u8; 10]);
        assert!(!is_push_only(&script));
    }

    #[test]
    fn test_is_push_only_fails_truncated_pushdata2() {
        // OP_PUSHDATA2 with insufficient length bytes
        let script = vec![0x4d, 0x01]; // missing second length byte
        assert!(!is_push_only(&script));
    }

    #[test]
    fn test_is_p2sh_valid() {
        // Valid P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = vec![0xa9, 0x14]; // OP_HASH160, push 20 bytes
        script.extend_from_slice(&[0u8; 20]); // 20-byte hash
        script.push(0x87); // OP_EQUAL
        assert!(is_p2sh(&script));
    }

    #[test]
    fn test_is_p2sh_wrong_length() {
        // Wrong length (24 bytes instead of 23)
        let mut script = vec![0xa9, 0x15]; // OP_HASH160, push 21 bytes
        script.extend_from_slice(&[0u8; 21]); // 21-byte hash
        script.push(0x87); // OP_EQUAL
        assert!(!is_p2sh(&script));
    }

    #[test]
    fn test_is_p2sh_wrong_op() {
        // Wrong opcode at start
        let mut script = vec![0xaa, 0x14]; // OP_HASH256 instead of OP_HASH160
        script.extend_from_slice(&[0u8; 20]);
        script.push(0x87);
        assert!(!is_p2sh(&script));
    }

    #[test]
    fn test_verify_p2sh_push_only_passes_for_push_only_script() {
        // P2SH scriptPubKey
        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(&[0u8; 20]);
        script_pubkey.push(0x87);

        // Push-only scriptSig: <sig> <pubkey>
        let script_sig = vec![
            0x47, // push 71 bytes (typical signature)
        ];
        let mut sig = vec![0x47];
        sig.extend_from_slice(&[0x30; 71]); // 71 bytes of dummy sig
        sig.push(0x21); // push 33 bytes
        sig.extend_from_slice(&[0x02; 33]); // 33 bytes of pubkey

        let flags = ScriptVerifyFlags::P2SH;
        let result = verify_p2sh_push_only(&sig, &script_pubkey, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_p2sh_push_only_fails_for_non_push_script() {
        // P2SH scriptPubKey
        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(&[0u8; 20]);
        script_pubkey.push(0x87);

        // Non-push-only scriptSig: contains OP_DUP (0x76)
        let script_sig = vec![0x51, 0x76]; // OP_1, OP_DUP

        let flags = ScriptVerifyFlags::P2SH;
        let result = verify_p2sh_push_only(&script_sig, &script_pubkey, flags);
        assert!(matches!(result, Err(ScriptError::SigPushOnly)));
    }

    #[test]
    fn test_verify_p2sh_push_only_allows_non_push_for_non_p2sh() {
        // Non-P2SH scriptPubKey (P2PKH)
        let script_pubkey = vec![
            0x76, 0xa9, 0x14, // OP_DUP, OP_HASH160, push 20
        ];
        let mut spk = script_pubkey.clone();
        spk.extend_from_slice(&[0u8; 20]);
        spk.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY, OP_CHECKSIG

        // Non-push-only scriptSig
        let script_sig = vec![0x51, 0x76]; // OP_1, OP_DUP

        let flags = ScriptVerifyFlags::P2SH;
        // Should pass because scriptPubKey is not P2SH
        let result = verify_p2sh_push_only(&script_sig, &spk, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_p2sh_push_only_skips_without_p2sh_flag() {
        // P2SH scriptPubKey
        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(&[0u8; 20]);
        script_pubkey.push(0x87);

        // Non-push-only scriptSig
        let script_sig = vec![0x51, 0x76]; // OP_1, OP_DUP

        // Without P2SH flag, the check is skipped
        let flags = ScriptVerifyFlags::NONE;
        let result = verify_p2sh_push_only(&script_sig, &script_pubkey, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_p2sh_scriptsig_with_op_checksig_fails() {
        // A P2SH scriptSig containing OP_CHECKSIG must fail
        // This is a consensus-critical test case
        let mut script_pubkey = vec![0xa9, 0x14];
        script_pubkey.extend_from_slice(&[0u8; 20]);
        script_pubkey.push(0x87);

        // scriptSig with OP_CHECKSIG (0xac) embedded
        let script_sig = vec![
            0x03, 0xaa, 0xbb, 0xcc, // push 3 bytes
            0xac,                   // OP_CHECKSIG - NOT allowed!
        ];

        let flags = ScriptVerifyFlags::P2SH;
        let result = verify_p2sh_push_only(&script_sig, &script_pubkey, flags);
        assert!(matches!(result, Err(ScriptError::SigPushOnly)));
    }

    #[test]
    fn test_sig_push_only_error_message() {
        let err = ScriptError::SigPushOnly;
        assert_eq!(err.to_string(), "scriptSig must be push-only for P2SH");
    }

    // =========================================================================
    // MINIMALIF tests
    // =========================================================================

    #[test]
    fn test_minimalif_helper_accepts_empty_vector() {
        // Empty vector is always valid (false condition)
        let value: Vec<u8> = vec![];
        assert!(check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::WitnessV0).is_ok());
        assert!(check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::Tapscript).is_ok());
    }

    #[test]
    fn test_minimalif_helper_accepts_0x01() {
        // [0x01] is the only valid true value
        let value = vec![0x01];
        assert!(check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::WitnessV0).is_ok());
        assert!(check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::Tapscript).is_ok());
    }

    #[test]
    fn test_minimalif_helper_rejects_0x02_witness_v0() {
        // [0x02] is truthy but not minimal
        let value = vec![0x02];
        let result = check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_minimalif_helper_rejects_0x02_tapscript() {
        // [0x02] rejected unconditionally in tapscript
        let value = vec![0x02];
        let result = check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::Tapscript);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_minimalif_helper_rejects_0x00_single_byte() {
        // [0x00] is not minimal - should use empty vector for false
        let value = vec![0x00];
        // Witness v0 with MINIMALIF flag
        let result = check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
        // Tapscript (unconditional)
        let result = check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::Tapscript);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_minimalif_helper_rejects_multi_byte() {
        // Multi-byte values are never minimal
        let value = vec![0x01, 0x00];
        let result = check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::WitnessV0);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
        let result = check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::Tapscript);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_minimalif_not_enforced_legacy() {
        // MINIMALIF is NOT enforced for legacy scripts, even with flag set
        let value = vec![0x02];
        // Legacy context - should pass
        assert!(check_minimalif(&value, ScriptVerifyFlags::MINIMALIF, SigVersion::Base).is_ok());
    }

    #[test]
    fn test_minimalif_not_enforced_witness_v0_without_flag() {
        // Witness v0 without MINIMALIF flag - should pass
        let value = vec![0x02];
        assert!(check_minimalif(&value, ScriptVerifyFlags::NONE, SigVersion::WitnessV0).is_ok());
    }

    #[test]
    fn test_op_if_with_0x01_passes_witness_v0() {
        // Script: <0x01> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
        // Should take the IF branch and leave 1 on stack
        let script = Builder::new()
            .push_slice(&[0x01])
            .push_opcode(OP_IF)
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_op_if_with_empty_takes_else_branch() {
        // Script: <empty> OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF
        // Should take the ELSE branch and leave 1 on stack
        let script = Builder::new()
            .push_slice(&[])  // empty = false
            .push_opcode(OP_IF)
            .push_int(0)
            .push_opcode(OP_ELSE)
            .push_int(1)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_op_if_with_0x02_fails_minimalif_witness_v0() {
        // Script: <0x02> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
        // [0x02] is truthy but not minimal - should fail
        let script = Builder::new()
            .push_slice(&[0x02])
            .push_opcode(OP_IF)
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_op_if_with_0x02_fails_tapscript() {
        // Tapscript unconditionally enforces MINIMALIF
        let script = Builder::new()
            .push_slice(&[0x02])
            .push_opcode(OP_IF)
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;  // No flags needed for tapscript
        let result = ScriptInterpreter::evaluate_tapscript(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_op_notif_with_empty_takes_if_branch() {
        // Script: <empty> OP_NOTIF OP_1 OP_ELSE OP_0 OP_ENDIF
        // empty = false, NOTIF inverts, so we take the IF branch
        let script = Builder::new()
            .push_slice(&[])  // empty = false
            .push_opcode(OP_NOTIF)
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_op_notif_with_0x01_takes_else_branch() {
        // Script: <0x01> OP_NOTIF OP_0 OP_ELSE OP_1 OP_ENDIF
        // 0x01 = true, NOTIF inverts to false, so we take the ELSE branch
        let script = Builder::new()
            .push_slice(&[0x01])
            .push_opcode(OP_NOTIF)
            .push_int(0)
            .push_opcode(OP_ELSE)
            .push_int(1)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_op_notif_with_0x02_fails_minimalif() {
        // Script: <0x02> OP_NOTIF OP_0 OP_ELSE OP_1 OP_ENDIF
        // [0x02] is not minimal
        let script = Builder::new()
            .push_slice(&[0x02])
            .push_opcode(OP_NOTIF)
            .push_int(0)
            .push_opcode(OP_ELSE)
            .push_int(1)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::MinimalIf)));
    }

    #[test]
    fn test_nested_if_with_minimalif() {
        // Nested IF with valid minimal arguments
        // Script: <0x01> OP_IF <0x01> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF OP_ELSE OP_0 OP_ENDIF
        let script = Builder::new()
            .push_slice(&[0x01])
            .push_opcode(OP_IF)
            .push_slice(&[0x01])
            .push_opcode(OP_IF)
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unbalanced_if_fails() {
        // Script: <0x01> OP_IF OP_1 (missing ENDIF)
        let script = Builder::new()
            .push_slice(&[0x01])
            .push_opcode(OP_IF)
            .push_int(1)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::MINIMALIF;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_unbalanced_else_fails() {
        // Script: OP_ELSE (without IF)
        let script = Builder::new()
            .push_opcode(OP_ELSE)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_unbalanced_endif_fails() {
        // Script: OP_ENDIF (without IF)
        let script = Builder::new()
            .push_opcode(OP_ENDIF)
            .into_script();

        let mut stack = Stack::new();
        let flags = ScriptVerifyFlags::NONE;
        let result = ScriptInterpreter::evaluate_witness_v0_script(&script, &mut stack, flags);
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_minimalif_error_message() {
        let err = ScriptError::MinimalIf;
        assert_eq!(err.to_string(), "OP_IF/OP_NOTIF argument must be empty or 0x01 (MINIMALIF)");
    }

    #[test]
    fn test_unbalanced_conditional_error_message() {
        let err = ScriptError::UnbalancedConditional;
        assert_eq!(err.to_string(), "Unbalanced conditional");
    }
}
