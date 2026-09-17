//! Byte-exact port of Bitcoin Core's script interpreter.
//!
//! Reference: bitcoin-core/src/script/interpreter.cpp (EvalScript,
//! VerifyScript, VerifyWitnessProgram, ExecuteWitnessScript, SignatureHash,
//! SignatureHashSchnorr, GenericTransactionSignatureChecker), script.cpp
//! (GetScriptOp, CheckMinimalPush, IsWitnessProgram, IsPushOnly, IsOpSuccess),
//! script.h (CScriptNum) and pubkey.cpp (CPubKey::Verify, CheckLowS,
//! XOnlyPubKey::CheckTapTweak).
//!
//! This module deliberately does NOT reuse `validate::script` (which is built
//! on rust-bitcoin's instruction iterator and pre-dates the taproot rules) nor
//! rust-bitcoin's transaction type (whose decoder rejects encodings Core's
//! interpreter never sees, and whose `Amount` cannot carry out-of-range
//! values). Everything here walks raw bytes exactly the way Core does, so that
//! every decision, every error code and every stack result matches Core.
//!
//! It is exposed to Python (see `lib.rs`: `ScriptTx`, `script_verify`,
//! `script_eval`, `script_sighash_legacy`) and selected by the ouroboros node
//! only when `OUROBOROS_NATIVE_SCRIPT=1`; the pure-Python
//! `ouroboros.script.ScriptInterpreter` stays the default and the oracle.

use bitcoin_hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash as _, HashEngine as _};
use secp256k1::{ecdsa, schnorr, Message, Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Constants (script.h / interpreter.h)
// ---------------------------------------------------------------------------

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
pub const MAX_OPS_PER_SCRIPT: i32 = 201;
pub const MAX_PUBKEYS_PER_MULTISIG: i32 = 20;
pub const MAX_SCRIPT_SIZE: usize = 10000;
pub const MAX_STACK_SIZE: usize = 1000;
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000;

const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;

const VALIDATION_WEIGHT_OFFSET: i64 = 50;
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

pub const SIGHASH_DEFAULT: u8 = 0;
pub const SIGHASH_ALL: u8 = 1;
pub const SIGHASH_NONE: u8 = 2;
pub const SIGHASH_SINGLE: u8 = 3;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
const SIGHASH_OUTPUT_MASK: u8 = 3;
const SIGHASH_INPUT_MASK: u8 = 0x80;

const ANNEX_TAG: u8 = 0x50;
const TAPROOT_LEAF_MASK: u8 = 0xfe;
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
const WITNESS_V1_TAPROOT_SIZE: usize = 32;

// Script verification flags — bit positions are Core's
// `script_verify_flag_name` enum order (interpreter.h), which is also the
// layout `ouroboros/script.py` uses, so the Python bitmask passes straight
// through.
pub const SCRIPT_VERIFY_NONE: u32 = 0;
pub const SCRIPT_VERIFY_P2SH: u32 = 1 << 0;
pub const SCRIPT_VERIFY_STRICTENC: u32 = 1 << 1;
pub const SCRIPT_VERIFY_DERSIG: u32 = 1 << 2;
pub const SCRIPT_VERIFY_LOW_S: u32 = 1 << 3;
pub const SCRIPT_VERIFY_NULLDUMMY: u32 = 1 << 4;
pub const SCRIPT_VERIFY_SIGPUSHONLY: u32 = 1 << 5;
pub const SCRIPT_VERIFY_MINIMALDATA: u32 = 1 << 6;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 7;
pub const SCRIPT_VERIFY_CLEANSTACK: u32 = 1 << 8;
pub const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
pub const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
pub const SCRIPT_VERIFY_WITNESS: u32 = 1 << 11;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 12;
pub const SCRIPT_VERIFY_MINIMALIF: u32 = 1 << 13;
pub const SCRIPT_VERIFY_NULLFAIL: u32 = 1 << 14;
pub const SCRIPT_VERIFY_WITNESS_PUBKEYTYPE: u32 = 1 << 15;
pub const SCRIPT_VERIFY_CONST_SCRIPTCODE: u32 = 1 << 16;
pub const SCRIPT_VERIFY_TAPROOT: u32 = 1 << 17;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: u32 = 1 << 18;
pub const SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS: u32 = 1 << 19;
pub const SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: u32 = 1 << 20;

// Opcodes (script.h)
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_NOP: u8 = 0x61;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_RETURN: u8 = 0x6a;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_FROMALTSTACK: u8 = 0x6c;
const OP_2DROP: u8 = 0x6d;
const OP_2DUP: u8 = 0x6e;
const OP_3DUP: u8 = 0x6f;
const OP_2OVER: u8 = 0x70;
const OP_2ROT: u8 = 0x71;
const OP_2SWAP: u8 = 0x72;
const OP_IFDUP: u8 = 0x73;
const OP_DEPTH: u8 = 0x74;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_NIP: u8 = 0x77;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_ROT: u8 = 0x7b;
const OP_SWAP: u8 = 0x7c;
const OP_TUCK: u8 = 0x7d;
const OP_CAT: u8 = 0x7e;
const OP_SUBSTR: u8 = 0x7f;
const OP_LEFT: u8 = 0x80;
const OP_RIGHT: u8 = 0x81;
const OP_SIZE: u8 = 0x82;
const OP_INVERT: u8 = 0x83;
const OP_AND: u8 = 0x84;
const OP_OR: u8 = 0x85;
const OP_XOR: u8 = 0x86;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_1ADD: u8 = 0x8b;
const OP_1SUB: u8 = 0x8c;
const OP_2MUL: u8 = 0x8d;
const OP_2DIV: u8 = 0x8e;
const OP_NEGATE: u8 = 0x8f;
const OP_ABS: u8 = 0x90;
const OP_NOT: u8 = 0x91;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_ADD: u8 = 0x93;
const OP_SUB: u8 = 0x94;
const OP_MUL: u8 = 0x95;
const OP_DIV: u8 = 0x96;
const OP_MOD: u8 = 0x97;
const OP_LSHIFT: u8 = 0x98;
const OP_RSHIFT: u8 = 0x99;
const OP_BOOLAND: u8 = 0x9a;
const OP_BOOLOR: u8 = 0x9b;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_NUMNOTEQUAL: u8 = 0x9e;
const OP_LESSTHAN: u8 = 0x9f;
const OP_GREATERTHAN: u8 = 0xa0;
const OP_LESSTHANOREQUAL: u8 = 0xa1;
const OP_GREATERTHANOREQUAL: u8 = 0xa2;
const OP_MIN: u8 = 0xa3;
const OP_MAX: u8 = 0xa4;
const OP_WITHIN: u8 = 0xa5;
const OP_RIPEMD160: u8 = 0xa6;
const OP_SHA1: u8 = 0xa7;
const OP_SHA256: u8 = 0xa8;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CODESEPARATOR: u8 = 0xab;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_NOP1: u8 = 0xb0;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_NOP4: u8 = 0xb3;
const OP_NOP5: u8 = 0xb4;
const OP_NOP6: u8 = 0xb5;
const OP_NOP7: u8 = 0xb6;
const OP_NOP8: u8 = 0xb7;
const OP_NOP9: u8 = 0xb8;
const OP_NOP10: u8 = 0xb9;
const OP_CHECKSIGADD: u8 = 0xba;

// ---------------------------------------------------------------------------
// Error codes (script_error.h, same order so the numeric code is Core's)
// ---------------------------------------------------------------------------

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ScriptError {
    Ok = 0,
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptNum,
    // Max sizes
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    // Logical/Format/Canonical errors
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    // CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    NegativeLocktime,
    UnsatisfiedLocktime,
    // Malleability
    SigHashtype,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    SigNullFail,
    // softfork safeness
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,
    // segregated witness
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeyType,
    // Taproot
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultisig,
    TapscriptMinimalIf,
    TapscriptEmptyPubkey,
    // Constant scriptCode
    OpCodeseparator,
    SigFindAndDelete,
}

impl ScriptError {
    pub fn code(self) -> u32 {
        self as u32
    }

    /// Core's enumerator name (script_error.h).
    pub fn name(self) -> &'static str {
        use ScriptError::*;
        match self {
            Ok => "SCRIPT_ERR_OK",
            UnknownError => "SCRIPT_ERR_UNKNOWN_ERROR",
            EvalFalse => "SCRIPT_ERR_EVAL_FALSE",
            OpReturn => "SCRIPT_ERR_OP_RETURN",
            ScriptNum => "SCRIPT_ERR_SCRIPTNUM",
            ScriptSize => "SCRIPT_ERR_SCRIPT_SIZE",
            PushSize => "SCRIPT_ERR_PUSH_SIZE",
            OpCount => "SCRIPT_ERR_OP_COUNT",
            StackSize => "SCRIPT_ERR_STACK_SIZE",
            SigCount => "SCRIPT_ERR_SIG_COUNT",
            PubkeyCount => "SCRIPT_ERR_PUBKEY_COUNT",
            Verify => "SCRIPT_ERR_VERIFY",
            EqualVerify => "SCRIPT_ERR_EQUALVERIFY",
            CheckMultisigVerify => "SCRIPT_ERR_CHECKMULTISIGVERIFY",
            CheckSigVerify => "SCRIPT_ERR_CHECKSIGVERIFY",
            NumEqualVerify => "SCRIPT_ERR_NUMEQUALVERIFY",
            BadOpcode => "SCRIPT_ERR_BAD_OPCODE",
            DisabledOpcode => "SCRIPT_ERR_DISABLED_OPCODE",
            InvalidStackOperation => "SCRIPT_ERR_INVALID_STACK_OPERATION",
            InvalidAltstackOperation => "SCRIPT_ERR_INVALID_ALTSTACK_OPERATION",
            UnbalancedConditional => "SCRIPT_ERR_UNBALANCED_CONDITIONAL",
            NegativeLocktime => "SCRIPT_ERR_NEGATIVE_LOCKTIME",
            UnsatisfiedLocktime => "SCRIPT_ERR_UNSATISFIED_LOCKTIME",
            SigHashtype => "SCRIPT_ERR_SIG_HASHTYPE",
            SigDer => "SCRIPT_ERR_SIG_DER",
            MinimalData => "SCRIPT_ERR_MINIMALDATA",
            SigPushOnly => "SCRIPT_ERR_SIG_PUSHONLY",
            SigHighS => "SCRIPT_ERR_SIG_HIGH_S",
            SigNullDummy => "SCRIPT_ERR_SIG_NULLDUMMY",
            PubkeyType => "SCRIPT_ERR_PUBKEYTYPE",
            CleanStack => "SCRIPT_ERR_CLEANSTACK",
            MinimalIf => "SCRIPT_ERR_MINIMALIF",
            SigNullFail => "SCRIPT_ERR_SIG_NULLFAIL",
            DiscourageUpgradableNops => "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS",
            DiscourageUpgradableWitnessProgram => {
                "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
            }
            DiscourageUpgradableTaprootVersion => {
                "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"
            }
            DiscourageOpSuccess => "SCRIPT_ERR_DISCOURAGE_OP_SUCCESS",
            DiscourageUpgradablePubkeyType => "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
            WitnessProgramWrongLength => "SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH",
            WitnessProgramWitnessEmpty => "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY",
            WitnessProgramMismatch => "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            WitnessMalleated => "SCRIPT_ERR_WITNESS_MALLEATED",
            WitnessMalleatedP2sh => "SCRIPT_ERR_WITNESS_MALLEATED_P2SH",
            WitnessUnexpected => "SCRIPT_ERR_WITNESS_UNEXPECTED",
            WitnessPubkeyType => "SCRIPT_ERR_WITNESS_PUBKEYTYPE",
            SchnorrSigSize => "SCRIPT_ERR_SCHNORR_SIG_SIZE",
            SchnorrSigHashtype => "SCRIPT_ERR_SCHNORR_SIG_HASHTYPE",
            SchnorrSig => "SCRIPT_ERR_SCHNORR_SIG",
            TaprootWrongControlSize => "SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE",
            TapscriptValidationWeight => "SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT",
            TapscriptCheckMultisig => "SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG",
            TapscriptMinimalIf => "SCRIPT_ERR_TAPSCRIPT_MINIMALIF",
            TapscriptEmptyPubkey => "SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY",
            OpCodeseparator => "SCRIPT_ERR_OP_CODESEPARATOR",
            SigFindAndDelete => "SCRIPT_ERR_SIG_FINDANDDELETE",
        }
    }
}

type ScriptResult<T> = Result<T, ScriptError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    Base = 0,
    WitnessV0 = 1,
    Taproot = 2,
    Tapscript = 3,
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn sha256d_bytes(data: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(data).to_byte_array()
}

/// Streaming SHA256 writer mirroring Core's `HashWriter` serialization.
struct Hasher {
    engine: sha256::HashEngine,
}

impl Hasher {
    fn new() -> Self {
        Hasher {
            engine: sha256::Hash::engine(),
        }
    }

    /// `HashWriter{TaggedHash(tag)}`: SHA256(tag) fed twice (BIP340).
    fn tagged(tag: &str) -> Self {
        let th = sha256_bytes(tag.as_bytes());
        let mut h = Hasher::new();
        h.write(&th);
        h.write(&th);
        h
    }

    fn write(&mut self, data: &[u8]) {
        self.engine.input(data);
    }
    fn write_u8(&mut self, v: u8) {
        self.engine.input(&[v]);
    }
    fn write_u32(&mut self, v: u32) {
        self.engine.input(&v.to_le_bytes());
    }
    fn write_i32(&mut self, v: i32) {
        self.engine.input(&v.to_le_bytes());
    }
    fn write_i64(&mut self, v: i64) {
        self.engine.input(&v.to_le_bytes());
    }
    fn write_compact_size(&mut self, n: u64) {
        let mut buf = Vec::with_capacity(9);
        write_compact_size(&mut buf, n);
        self.engine.input(&buf);
    }
    /// `ss << std::vector<unsigned char>` / `ss << CScript`: length-prefixed.
    fn write_vec(&mut self, v: &[u8]) {
        self.write_compact_size(v.len() as u64);
        self.write(v);
    }
    fn write_txout(&mut self, out: &TxOut) {
        self.write_i64(out.value);
        self.write_vec(&out.script_pubkey);
    }
    fn write_outpoint(&mut self, inp: &TxIn) {
        self.write(&inp.prevout_hash);
        self.write_u32(inp.prevout_n);
    }
    /// `GetSHA256()`
    fn finish_single(self) -> [u8; 32] {
        sha256::Hash::from_engine(self.engine).to_byte_array()
    }
    /// `GetHash()` (double SHA256)
    fn finish_double(self) -> [u8; 32] {
        let single = sha256::Hash::from_engine(self.engine).to_byte_array();
        sha256_bytes(&single)
    }
}

fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(253);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(254);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn compact_size_len(n: u64) -> usize {
    if n < 253 {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

// ---------------------------------------------------------------------------
// Transaction model + transport decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prevout_hash: [u8; 32],
    pub prevout_n: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    /// Raw 64-bit value bits, as CAmount (int64). Out-of-range values are
    /// carried verbatim; the interpreter never interprets them.
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

#[derive(Debug)]
pub struct DecodeError(pub String);

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.data.len() - self.pos < n {
            return Err(DecodeError(format!(
                "truncated transaction: need {} bytes at offset {}, have {}",
                n,
                self.pos,
                self.data.len() - self.pos
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn compact_size(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        Ok(match first {
            0..=252 => first as u64,
            253 => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
            254 => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
            _ => u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
        })
    }
    fn var_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.compact_size()?;
        if n > (self.data.len() - self.pos) as u64 {
            return Err(DecodeError(format!(
                "truncated transaction: vector of {} bytes at offset {}",
                n, self.pos
            )));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
}

impl Tx {
    /// Decode the fixed "extended" transport encoding the Python side emits
    /// (`ouroboros.script._native_tx_bytes`): identical to the BIP-144 wire
    /// format except that the marker/flag and the per-input witness section
    /// are ALWAYS present, even when every witness stack is empty. That removes
    /// the has_witness ambiguity of the wire format: a `Transaction` object
    /// whose inputs carry witness stacks is transported faithfully whatever
    /// its `has_witness` attribute says.
    pub fn decode_extended(bytes: &[u8]) -> Result<Tx, DecodeError> {
        let mut c = Cursor {
            data: bytes,
            pos: 0,
        };
        let version = c.u32()?;
        let marker = c.u8()?;
        let flag = c.u8()?;
        if marker != 0 || flag != 1 {
            return Err(DecodeError(format!(
                "expected extended transport marker 00 01, got {:02x} {:02x}",
                marker, flag
            )));
        }
        let n_in = c.compact_size()?;
        if n_in > bytes.len() as u64 {
            return Err(DecodeError("input count exceeds buffer".into()));
        }
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let prevout_hash: [u8; 32] = c.take(32)?.try_into().unwrap();
            let prevout_n = c.u32()?;
            let script_sig = c.var_bytes()?;
            let sequence = c.u32()?;
            inputs.push(TxIn {
                prevout_hash,
                prevout_n,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }
        let n_out = c.compact_size()?;
        if n_out > bytes.len() as u64 {
            return Err(DecodeError("output count exceeds buffer".into()));
        }
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            let value = c.i64()?;
            let script_pubkey = c.var_bytes()?;
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        for inp in inputs.iter_mut() {
            let n_items = c.compact_size()?;
            if n_items > bytes.len() as u64 {
                return Err(DecodeError("witness item count exceeds buffer".into()));
            }
            let mut items = Vec::with_capacity(n_items as usize);
            for _ in 0..n_items {
                items.push(c.var_bytes()?);
            }
            inp.witness = items;
        }
        let locktime = c.u32()?;
        if c.pos != bytes.len() {
            return Err(DecodeError(format!(
                "{} trailing bytes after transaction",
                bytes.len() - c.pos
            )));
        }
        Ok(Tx {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

/// `::GetSerializeSize(witness.stack)` — CompactSize(n) + Σ(CompactSize(len) + len).
fn witness_serialize_size(stack: &[Vec<u8>]) -> i64 {
    let mut n = compact_size_len(stack.len() as u64) as i64;
    for item in stack {
        n += compact_size_len(item.len() as u64) as i64 + item.len() as i64;
    }
    n
}

// ---------------------------------------------------------------------------
// PrecomputedTransactionData
// ---------------------------------------------------------------------------

/// Per-transaction precomputation (Core `PrecomputedTransactionData`). Built
/// once per transaction and shared by every input's verification.
pub struct TxContext {
    pub tx: Tx,
    prevouts_single_hash: [u8; 32],
    sequences_single_hash: [u8; 32],
    outputs_single_hash: [u8; 32],
    // BIP143 (double-SHA256 of the above)
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
    // BIP341
    spent_outputs: Option<Vec<TxOut>>,
    spent_amounts_single_hash: [u8; 32],
    spent_scripts_single_hash: [u8; 32],
}

impl TxContext {
    /// `spent_outputs`, when given, MUST cover every input (Core asserts
    /// `m_spent_outputs.size() == txTo.vin.size()`); a mismatch is reported
    /// as an error rather than silently enabling a partial BIP341 cache.
    pub fn new(tx: Tx, spent_outputs: Option<Vec<TxOut>>) -> Result<TxContext, DecodeError> {
        if let Some(ref so) = spent_outputs {
            if so.len() != tx.inputs.len() {
                return Err(DecodeError(format!(
                    "spent outputs ({}) do not match input count ({})",
                    so.len(),
                    tx.inputs.len()
                )));
            }
        }
        let mut hp = Hasher::new();
        let mut hs = Hasher::new();
        for inp in &tx.inputs {
            hp.write_outpoint(inp);
            hs.write_u32(inp.sequence);
        }
        let mut ho = Hasher::new();
        for out in &tx.outputs {
            ho.write_txout(out);
        }
        let prevouts_single_hash = hp.finish_single();
        let sequences_single_hash = hs.finish_single();
        let outputs_single_hash = ho.finish_single();

        let (spent_amounts_single_hash, spent_scripts_single_hash) = match &spent_outputs {
            Some(so) => {
                let mut ha = Hasher::new();
                let mut hsc = Hasher::new();
                for out in so {
                    ha.write_i64(out.value);
                    hsc.write_vec(&out.script_pubkey);
                }
                (ha.finish_single(), hsc.finish_single())
            }
            None => ([0u8; 32], [0u8; 32]),
        };

        Ok(TxContext {
            hash_prevouts: sha256_bytes(&prevouts_single_hash),
            hash_sequence: sha256_bytes(&sequences_single_hash),
            hash_outputs: sha256_bytes(&outputs_single_hash),
            tx,
            prevouts_single_hash,
            sequences_single_hash,
            outputs_single_hash,
            spent_outputs,
            spent_amounts_single_hash,
            spent_scripts_single_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Script primitives (script.cpp / script.h)
// ---------------------------------------------------------------------------

/// `GetScriptOp`. On success returns the opcode and the byte range of its
/// immediate push data (empty for non-push opcodes) and leaves `pc` after the
/// instruction. On failure `pc` has been advanced exactly as Core's iterator
/// is (past the opcode byte and any size bytes that were readable) — several
/// callers (SerializeScriptCode, FindAndDelete) observe that position.
fn get_op(script: &[u8], pc: &mut usize) -> Option<(u8, usize, usize)> {
    let end = script.len();
    if *pc >= end {
        return None;
    }
    let opcode = script[*pc];
    *pc += 1;
    if opcode <= OP_PUSHDATA4 {
        let n_size: usize;
        if opcode < OP_PUSHDATA1 {
            n_size = opcode as usize;
        } else if opcode == OP_PUSHDATA1 {
            if end - *pc < 1 {
                return None;
            }
            n_size = script[*pc] as usize;
            *pc += 1;
        } else if opcode == OP_PUSHDATA2 {
            if end - *pc < 2 {
                return None;
            }
            n_size = u16::from_le_bytes([script[*pc], script[*pc + 1]]) as usize;
            *pc += 2;
        } else {
            if end - *pc < 4 {
                return None;
            }
            n_size = u32::from_le_bytes([
                script[*pc],
                script[*pc + 1],
                script[*pc + 2],
                script[*pc + 3],
            ]) as usize;
            *pc += 4;
        }
        if end - *pc < n_size {
            return None;
        }
        let start = *pc;
        *pc += n_size;
        return Some((opcode, start, start + n_size));
    }
    Some((opcode, *pc, *pc))
}

/// `CScript::operator<<(const std::vector<unsigned char>&)`
fn push_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    let n = data.len();
    if n < OP_PUSHDATA1 as usize {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// `CheckMinimalPush` (script.cpp)
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    debug_assert!(opcode <= OP_PUSHDATA4);
    if data.is_empty() {
        opcode == OP_0
    } else if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        false
    } else if data.len() == 1 && data[0] == 0x81 {
        false
    } else if data.len() <= 75 {
        opcode as usize == data.len()
    } else if data.len() <= 255 {
        opcode == OP_PUSHDATA1
    } else if data.len() <= 65535 {
        opcode == OP_PUSHDATA2
    } else {
        true
    }
}

/// `CScript::IsPushOnly`
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0usize;
    while pc < script.len() {
        match get_op(script, &mut pc) {
            None => return false,
            Some((opcode, _, _)) => {
                if opcode > OP_16 {
                    return false;
                }
            }
        }
    }
    true
}

/// `CScript::IsPayToScriptHash`
pub fn is_pay_to_script_hash(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

fn decode_op_n(opcode: u8) -> i32 {
    if opcode == OP_0 {
        return 0;
    }
    debug_assert!((OP_1..=OP_16).contains(&opcode));
    (opcode - (OP_1 - 1)) as i32
}

/// `CScript::IsWitnessProgram` -> (version, program)
pub fn is_witness_program(script: &[u8]) -> Option<(i32, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    if script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16) {
        return None;
    }
    if (script[1] as usize) + 2 == script.len() {
        return Some((decode_op_n(script[0]), &script[2..]));
    }
    None
}

/// `CScript::IsPayToAnchor(int version, program)`
fn is_pay_to_anchor(version: i32, program: &[u8]) -> bool {
    version == 1 && program.len() == 2 && program[0] == 0x4e && program[1] == 0x73
}

/// `IsOpSuccess` (script.cpp)
fn is_op_success(opcode: u8) -> bool {
    opcode == 80
        || opcode == 98
        || (126..=129).contains(&opcode)
        || (131..=134).contains(&opcode)
        || (137..=138).contains(&opcode)
        || (141..=142).contains(&opcode)
        || (149..=153).contains(&opcode)
        || (187..=254).contains(&opcode)
}

/// `CastToBool`
pub fn cast_to_bool(vch: &[u8]) -> bool {
    for (i, &b) in vch.iter().enumerate() {
        if b != 0 {
            // Can be negative zero
            if i == vch.len() - 1 && b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// `FindAndDelete` (interpreter.cpp). Walks `script` opcode-by-opcode and
/// deletes every occurrence of `b` found at an instruction boundary (matches
/// may chain: after a deletion the scan resumes at the byte after the match).
fn find_and_delete(script: &mut Vec<u8>, b: &[u8]) -> i32 {
    let mut n_found = 0;
    if b.is_empty() {
        return n_found;
    }
    let mut result: Vec<u8> = Vec::with_capacity(script.len());
    let end = script.len();
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while end - pc >= b.len() && script[pc..pc + b.len()] == *b {
            pc += b.len();
            n_found += 1;
        }
        pc2 = pc;
        if get_op(script, &mut pc).is_none() {
            break;
        }
    }
    if n_found > 0 {
        result.extend_from_slice(&script[pc2..end]);
        *script = result;
    }
    n_found
}

// ---------------------------------------------------------------------------
// CScriptNum (script.h)
// ---------------------------------------------------------------------------

struct ScriptNumError;

impl From<ScriptNumError> for ScriptError {
    fn from(_: ScriptNumError) -> ScriptError {
        ScriptError::ScriptNum
    }
}

fn scriptnum_decode(vch: &[u8], require_minimal: bool, max_num_size: usize) -> Result<i64, ScriptNumError> {
    if vch.len() > max_num_size {
        return Err(ScriptNumError);
    }
    if require_minimal && !vch.is_empty() {
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (vch[vch.len() - 1] & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit.
            if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
                return Err(ScriptNumError);
            }
        }
    }
    Ok(scriptnum_set_vch(vch))
}

fn scriptnum_set_vch(vch: &[u8]) -> i64 {
    if vch.is_empty() {
        return 0;
    }
    let mut result: i64 = 0;
    for (i, &b) in vch.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    // If the input vector's most significant byte is 0x80, remove it from
    // the result's msb and return a negative.
    if vch[vch.len() - 1] & 0x80 != 0 {
        let mask: u64 = 0x80u64 << (8 * (vch.len() - 1));
        return -(((result as u64) & !mask) as i64);
    }
    result
}

pub fn scriptnum_serialize(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(9);
    let neg = value < 0;
    let mut absvalue: u64 = if neg {
        (!(value as u64)).wrapping_add(1)
    } else {
        value as u64
    };
    while absvalue != 0 {
        result.push((absvalue & 0xff) as u8);
        absvalue >>= 8;
    }
    // - If the most significant byte is >= 0x80 and the value is positive, push a
    //   new zero-byte to make the significant byte < 0x80 again.
    // - If the most significant byte is >= 0x80 and the value is negative, push a
    //   new 0x80 byte that will be popped off when converting to an integral.
    // - If the most significant byte is < 0x80 and the value is negative, add
    //   0x80 to it, since it will be subtracted and interpreted as a negative when
    //   converting to an integral.
    let last = *result.last().unwrap();
    if last & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

/// `CScriptNum::getint()` — clamp to the C `int` range.
fn scriptnum_getint(v: i64) -> i32 {
    if v > i32::MAX as i64 {
        i32::MAX
    } else if v < i32::MIN as i64 {
        i32::MIN
    } else {
        v as i32
    }
}

// ---------------------------------------------------------------------------
// Signature / pubkey encoding checks (interpreter.cpp)
// ---------------------------------------------------------------------------

fn is_compressed_or_uncompressed_pubkey(pk: &[u8]) -> bool {
    if pk.len() < 33 {
        return false;
    }
    if pk[0] == 0x04 {
        if pk.len() != 65 {
            return false;
        }
    } else if pk[0] == 0x02 || pk[0] == 0x03 {
        if pk.len() != 33 {
            return false;
        }
    } else {
        return false;
    }
    true
}

fn is_compressed_pubkey(pk: &[u8]) -> bool {
    if pk.len() != 33 {
        return false;
    }
    if pk[0] != 0x02 && pk[0] != 0x03 {
        return false;
    }
    true
}

/// `IsValidSignatureEncoding` — strict DER + hashtype byte, BIP66.
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    if sig.len() < 9 {
        return false;
    }
    if sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && (sig[len_r + 7] & 0x80) == 0 {
        return false;
    }
    true
}

/// `CPubKey::CheckLowS`: lax-DER parse, then "already normalized".
fn check_low_s(sig_without_hashtype: &[u8]) -> bool {
    let sig = match ecdsa::Signature::from_der_lax(sig_without_hashtype) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut normalized = sig;
    normalized.normalize_s();
    normalized.serialize_compact() == sig.serialize_compact()
}

fn is_low_der_signature(sig: &[u8]) -> ScriptResult<()> {
    if !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    // an extra hashtype byte follows the actual signature data.
    let copy = &sig[..sig.len() - 1];
    if !check_low_s(copy) {
        return Err(ScriptError::SigHighS);
    }
    Ok(())
}

fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let n_hash_type = sig[sig.len() - 1] & !SIGHASH_ANYONECANPAY;
    if n_hash_type < SIGHASH_ALL || n_hash_type > SIGHASH_SINGLE {
        return false;
    }
    true
}

fn check_signature_encoding(sig: &[u8], flags: u32) -> ScriptResult<()> {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if sig.is_empty() {
        return Ok(());
    }
    if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0
        && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    } else if (flags & SCRIPT_VERIFY_LOW_S) != 0 {
        is_low_der_signature(sig)?;
    } else if (flags & SCRIPT_VERIFY_STRICTENC) != 0 && !is_defined_hashtype_signature(sig) {
        return Err(ScriptError::SigHashtype);
    }
    Ok(())
}

fn check_pubkey_encoding(pk: &[u8], flags: u32, sigversion: SigVersion) -> ScriptResult<()> {
    if (flags & SCRIPT_VERIFY_STRICTENC) != 0 && !is_compressed_or_uncompressed_pubkey(pk) {
        return Err(ScriptError::PubkeyType);
    }
    // Only compressed keys are accepted in segwit
    if (flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pk)
    {
        return Err(ScriptError::WitnessPubkeyType);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signature hashes
// ---------------------------------------------------------------------------

/// `CTransactionSignatureSerializer::SerializeScriptCode`: the scriptCode
/// with OP_CODESEPARATORs skipped, walking with GetOp. The declared length is
/// `size - nCodeSeparators`; the trailing segment is written up to the
/// iterator position where GetOp stopped, which for a script ending in a
/// truncated push is BEFORE the end of the script. Both quirks are Core's.
fn serialize_script_code(h: &mut Hasher, script_code: &[u8]) {
    let mut it = 0usize;
    let mut n_code_separators = 0usize;
    while let Some((opcode, _, _)) = get_op(script_code, &mut it) {
        if opcode == OP_CODESEPARATOR {
            n_code_separators += 1;
        }
    }
    h.write_compact_size((script_code.len() - n_code_separators) as u64);
    it = 0;
    let mut it_begin = 0usize;
    while let Some((opcode, _, _)) = get_op(script_code, &mut it) {
        if opcode == OP_CODESEPARATOR {
            h.write(&script_code[it_begin..it - 1]);
            it_begin = it;
        }
    }
    if it_begin != script_code.len() {
        h.write(&script_code[it_begin..it]);
    }
}

const UINT256_ONE: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

/// Legacy `SignatureHash(scriptCode, txTo, nIn, nHashType, ...)` for
/// `SigVersion::BASE`. `n_hash_type` is the raw int32 (the vector corpus
/// feeds negative values; the low bits select the mode and the full value
/// is serialized).
pub fn signature_hash_legacy(tx: &Tx, script_code: &[u8], n_in: usize, n_hash_type: i32) -> [u8; 32] {
    if n_in >= tx.inputs.len() {
        // Core asserts here (unreachable from VerifyScript); the historical
        // SignatureHashOld returned one.
        return UINT256_ONE;
    }
    let f_anyone_can_pay = (n_hash_type & SIGHASH_ANYONECANPAY as i32) != 0;
    let f_hash_single = (n_hash_type & 0x1f) == SIGHASH_SINGLE as i32;
    let f_hash_none = (n_hash_type & 0x1f) == SIGHASH_NONE as i32;

    // Check for invalid use of SIGHASH_SINGLE
    if f_hash_single && n_in >= tx.outputs.len() {
        return UINT256_ONE;
    }

    let mut ss = Hasher::new();
    // Serialize version
    ss.write_u32(tx.version);
    // Serialize vin
    let n_inputs = if f_anyone_can_pay { 1 } else { tx.inputs.len() };
    ss.write_compact_size(n_inputs as u64);
    for mut n_input in 0..n_inputs {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if f_anyone_can_pay {
            n_input = n_in;
        }
        let inp = &tx.inputs[n_input];
        ss.write_outpoint(inp);
        if n_input != n_in {
            // Blank out other inputs' signatures
            ss.write_compact_size(0);
        } else {
            serialize_script_code(&mut ss, script_code);
        }
        if n_input != n_in && (f_hash_single || f_hash_none) {
            // let the others update at will
            ss.write_i32(0);
        } else {
            ss.write_u32(inp.sequence);
        }
    }
    // Serialize vout
    let n_outputs = if f_hash_none {
        0
    } else if f_hash_single {
        n_in + 1
    } else {
        tx.outputs.len()
    };
    ss.write_compact_size(n_outputs as u64);
    for n_output in 0..n_outputs {
        if f_hash_single && n_output != n_in {
            // Do not lock-in the txout payee at other indices as txin
            ss.write_i64(-1);
            ss.write_compact_size(0);
        } else {
            ss.write_txout(&tx.outputs[n_output]);
        }
    }
    // Serialize nLockTime
    ss.write_u32(tx.locktime);
    // Add sighash type and hash.
    ss.write_i32(n_hash_type);
    ss.finish_double()
}

/// BIP143 `SignatureHash` for `SigVersion::WITNESS_V0`.
fn signature_hash_witness_v0(
    ctx: &TxContext,
    script_code: &[u8],
    n_in: usize,
    n_hash_type: i32,
    amount: i64,
) -> [u8; 32] {
    let tx = &ctx.tx;
    let base = n_hash_type & 0x1f;
    let mut hash_prevouts = [0u8; 32];
    let mut hash_sequence = [0u8; 32];
    let mut hash_outputs = [0u8; 32];

    if (n_hash_type & SIGHASH_ANYONECANPAY as i32) == 0 {
        hash_prevouts = ctx.hash_prevouts;
    }
    if (n_hash_type & SIGHASH_ANYONECANPAY as i32) == 0
        && base != SIGHASH_SINGLE as i32
        && base != SIGHASH_NONE as i32
    {
        hash_sequence = ctx.hash_sequence;
    }
    if base != SIGHASH_SINGLE as i32 && base != SIGHASH_NONE as i32 {
        hash_outputs = ctx.hash_outputs;
    } else if base == SIGHASH_SINGLE as i32 && n_in < tx.outputs.len() {
        let mut inner = Hasher::new();
        inner.write_txout(&tx.outputs[n_in]);
        hash_outputs = inner.finish_double();
    }

    let mut ss = Hasher::new();
    // Version
    ss.write_u32(tx.version);
    // Input prevouts/nSequence (none/all, depending on flags)
    ss.write(&hash_prevouts);
    ss.write(&hash_sequence);
    // The input being signed (replacing the scriptSig with scriptCode + amount)
    ss.write_outpoint(&tx.inputs[n_in]);
    ss.write_vec(script_code);
    ss.write_i64(amount);
    ss.write_u32(tx.inputs[n_in].sequence);
    // Outputs (none/one/all, depending on flags)
    ss.write(&hash_outputs);
    // Locktime
    ss.write_u32(tx.locktime);
    // Add sighash type and hash.
    ss.write_i32(n_hash_type);
    ss.finish_double()
}

/// Core `ScriptExecutionData`.
#[derive(Debug, Clone)]
pub struct ExecData {
    codeseparator_pos_init: bool,
    codeseparator_pos: u32,
    annex_init: bool,
    annex_present: bool,
    annex_hash: [u8; 32],
    tapleaf_hash_init: bool,
    tapleaf_hash: [u8; 32],
    validation_weight_left_init: bool,
    validation_weight_left: i64,
    output_hash: Option<[u8; 32]>,
}

impl ExecData {
    fn new() -> Self {
        ExecData {
            codeseparator_pos_init: false,
            codeseparator_pos: 0,
            annex_init: false,
            annex_present: false,
            annex_hash: [0u8; 32],
            tapleaf_hash_init: false,
            tapleaf_hash: [0u8; 32],
            validation_weight_left_init: false,
            validation_weight_left: 0,
            output_hash: None,
        }
    }
}

/// BIP341 `SignatureHashSchnorr`. `None` where Core returns false.
fn signature_hash_schnorr(
    execdata: &mut ExecData,
    ctx: &TxContext,
    in_pos: usize,
    hash_type: u8,
    sigversion: SigVersion,
) -> Option<[u8; 32]> {
    let (ext_flag, key_version): (u8, u8) = match sigversion {
        SigVersion::Taproot => (0, 0),
        SigVersion::Tapscript => (1, 0),
        _ => unreachable!("SignatureHashSchnorr with non-taproot sigversion"),
    };
    let tx = &ctx.tx;
    debug_assert!(in_pos < tx.inputs.len());
    let spent = ctx.spent_outputs.as_ref()?; // HandleMissingData(FAIL)

    let mut ss = Hasher::tagged("TapSighash");

    // Epoch
    ss.write_u8(0);

    // Hash type
    let output_type = if hash_type == SIGHASH_DEFAULT {
        SIGHASH_ALL
    } else {
        hash_type & SIGHASH_OUTPUT_MASK
    };
    let input_type = hash_type & SIGHASH_INPUT_MASK;
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }
    ss.write_u8(hash_type);

    // Transaction level data
    ss.write_u32(tx.version);
    ss.write_u32(tx.locktime);
    if input_type != SIGHASH_ANYONECANPAY {
        ss.write(&ctx.prevouts_single_hash);
        ss.write(&ctx.spent_amounts_single_hash);
        ss.write(&ctx.spent_scripts_single_hash);
        ss.write(&ctx.sequences_single_hash);
    }
    if output_type == SIGHASH_ALL {
        ss.write(&ctx.outputs_single_hash);
    }

    // Data about the input/prevout being spent
    debug_assert!(execdata.annex_init);
    let have_annex = execdata.annex_present;
    let spend_type: u8 = (ext_flag << 1) + if have_annex { 1 } else { 0 };
    ss.write_u8(spend_type);
    if input_type == SIGHASH_ANYONECANPAY {
        ss.write_outpoint(&tx.inputs[in_pos]);
        ss.write_txout(&spent[in_pos]);
        ss.write_u32(tx.inputs[in_pos].sequence);
    } else {
        ss.write_u32(in_pos as u32);
    }
    if have_annex {
        ss.write(&execdata.annex_hash);
    }

    // Data about the output (if only one).
    if output_type == SIGHASH_SINGLE {
        if in_pos >= tx.outputs.len() {
            return None;
        }
        if execdata.output_hash.is_none() {
            let mut sha_single_output = Hasher::new();
            sha_single_output.write_txout(&tx.outputs[in_pos]);
            execdata.output_hash = Some(sha_single_output.finish_single());
        }
        ss.write(&execdata.output_hash.unwrap());
    }

    // Additional data for BIP 342 signatures
    if sigversion == SigVersion::Tapscript {
        debug_assert!(execdata.tapleaf_hash_init);
        ss.write(&execdata.tapleaf_hash);
        ss.write_u8(key_version);
        debug_assert!(execdata.codeseparator_pos_init);
        ss.write_u32(execdata.codeseparator_pos);
    }

    Some(ss.finish_single())
}

// ---------------------------------------------------------------------------
// Signature checker (GenericTransactionSignatureChecker)
// ---------------------------------------------------------------------------

static SECP: OnceLock<Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();

fn secp() -> &'static Secp256k1<secp256k1::VerifyOnly> {
    SECP.get_or_init(Secp256k1::verification_only)
}

/// `CPubKey::GetLen`
fn pubkey_get_len(header: u8) -> usize {
    match header {
        2 | 3 => 33,
        4 | 6 | 7 => 65,
        _ => 0,
    }
}

/// `CPubKey(vch).IsValid()`
fn pubkey_is_valid(pk: &[u8]) -> bool {
    !pk.is_empty() && pubkey_get_len(pk[0]) == pk.len()
}

/// `CPubKey::Verify`: parse (accepts hybrid keys, as libsecp256k1 does),
/// lax-DER parse, normalize S, verify.
fn ecdsa_verify(pk: &[u8], sig_der: &[u8], hash: &[u8; 32]) -> bool {
    if !pubkey_is_valid(pk) {
        return false;
    }
    let pubkey = match PublicKey::from_slice(pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut sig = match ecdsa::Signature::from_der_lax(sig_der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // libsecp256k1's ECDSA verification requires lower-S signatures, which
    // have not historically been enforced in Bitcoin, so normalize them first.
    sig.normalize_s();
    let msg = Message::from_digest(*hash);
    secp().verify_ecdsa(msg, &sig, &pubkey).is_ok()
}

/// `XOnlyPubKey::VerifySchnorr`
fn schnorr_verify(pk32: &[u8], sig64: &[u8], hash: &[u8; 32]) -> bool {
    debug_assert_eq!(sig64.len(), 64);
    let pk: [u8; 32] = match pk32.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pubkey = match XOnlyPublicKey::from_byte_array(pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = sig64.try_into().unwrap();
    let sig = schnorr::Signature::from_byte_array(sig_arr);
    secp().verify_schnorr(&sig, &hash[..], &pubkey).is_ok()
}

pub struct Checker<'a> {
    ctx: &'a TxContext,
    n_in: usize,
    amount: i64,
}

impl<'a> Checker<'a> {
    pub fn new(ctx: &'a TxContext, n_in: usize, amount: i64) -> Self {
        Checker { ctx, n_in, amount }
    }

    /// `CheckECDSASignature`
    fn check_ecdsa_signature(&self, sig_in: &[u8], pubkey: &[u8], script_code: &[u8], sigversion: SigVersion) -> bool {
        if !pubkey_is_valid(pubkey) {
            return false;
        }
        // Hash type is one byte tacked on to the end of the signature
        if sig_in.is_empty() {
            return false;
        }
        let n_hash_type = sig_in[sig_in.len() - 1] as i32;
        let sig = &sig_in[..sig_in.len() - 1];

        // Witness sighashes need the amount.
        if sigversion == SigVersion::WitnessV0 && self.amount < 0 {
            return false;
        }

        let sighash = match sigversion {
            SigVersion::WitnessV0 => {
                signature_hash_witness_v0(self.ctx, script_code, self.n_in, n_hash_type, self.amount)
            }
            _ => signature_hash_legacy(&self.ctx.tx, script_code, self.n_in, n_hash_type),
        };
        ecdsa_verify(pubkey, sig, &sighash)
    }

    /// `CheckSchnorrSignature`
    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey_in: &[u8],
        sigversion: SigVersion,
        execdata: &mut ExecData,
    ) -> ScriptResult<()> {
        debug_assert!(sigversion == SigVersion::Taproot || sigversion == SigVersion::Tapscript);
        debug_assert_eq!(pubkey_in.len(), 32);
        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::SchnorrSigSize);
        }
        let mut hashtype = SIGHASH_DEFAULT;
        let mut sig = sig;
        if sig.len() == 65 {
            hashtype = sig[64];
            if hashtype == SIGHASH_DEFAULT {
                return Err(ScriptError::SchnorrSigHashtype);
            }
            sig = &sig[..64];
        }
        let sighash = match signature_hash_schnorr(execdata, self.ctx, self.n_in, hashtype, sigversion) {
            Some(h) => h,
            None => return Err(ScriptError::SchnorrSigHashtype),
        };
        if !schnorr_verify(pubkey_in, sig, &sighash) {
            return Err(ScriptError::SchnorrSig);
        }
        Ok(())
    }

    /// `CheckLockTime`
    fn check_lock_time(&self, n_lock_time: i64) -> bool {
        let tx_lock_time = self.ctx.tx.locktime as i64;
        if !((tx_lock_time < LOCKTIME_THRESHOLD && n_lock_time < LOCKTIME_THRESHOLD)
            || (tx_lock_time >= LOCKTIME_THRESHOLD && n_lock_time >= LOCKTIME_THRESHOLD))
        {
            return false;
        }
        if n_lock_time > tx_lock_time {
            return false;
        }
        if SEQUENCE_FINAL == self.ctx.tx.inputs[self.n_in].sequence {
            return false;
        }
        true
    }

    /// `CheckSequence`
    fn check_sequence(&self, n_sequence: i64) -> bool {
        let tx_to_sequence = self.ctx.tx.inputs[self.n_in].sequence as i64;
        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules. (version is uint32_t in Core.)
        if self.ctx.tx.version < 2 {
            return false;
        }
        if tx_to_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }
        let n_lock_time_mask: i64 = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_to_sequence_masked = tx_to_sequence & n_lock_time_mask;
        let n_sequence_masked = n_sequence & n_lock_time_mask;
        if !((tx_to_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG
            && n_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
            || (tx_to_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG
                && n_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG))
        {
            return false;
        }
        if n_sequence_masked > tx_to_sequence_masked {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// EvalScript
// ---------------------------------------------------------------------------

/// Core's optimized `ConditionStack`.
struct ConditionStack {
    stack_size: u32,
    first_false_pos: u32,
}

const NO_FALSE: u32 = u32::MAX;

impl ConditionStack {
    fn new() -> Self {
        ConditionStack {
            stack_size: 0,
            first_false_pos: NO_FALSE,
        }
    }
    fn empty(&self) -> bool {
        self.stack_size == 0
    }
    fn all_true(&self) -> bool {
        self.first_false_pos == NO_FALSE
    }
    fn push_back(&mut self, f: bool) {
        if self.first_false_pos == NO_FALSE && !f {
            self.first_false_pos = self.stack_size;
        }
        self.stack_size += 1;
    }
    fn pop_back(&mut self) {
        debug_assert!(self.stack_size > 0);
        self.stack_size -= 1;
        if self.first_false_pos == self.stack_size {
            self.first_false_pos = NO_FALSE;
        }
    }
    fn toggle_top(&mut self) {
        debug_assert!(self.stack_size > 0);
        if self.first_false_pos == NO_FALSE {
            self.first_false_pos = self.stack_size - 1;
        } else if self.first_false_pos == self.stack_size - 1 {
            self.first_false_pos = NO_FALSE;
        }
    }
}

type Stack = Vec<Vec<u8>>;

#[inline]
fn stacktop(stack: &Stack, i: usize) -> &Vec<u8> {
    // stacktop(-i)
    &stack[stack.len() - i]
}

#[inline]
fn popstack(stack: &mut Stack) {
    // Core throws (caught as UNKNOWN_ERROR) on an empty stack; every caller
    // checks the size first, so this is unreachable.
    stack.pop().expect("popstack(): stack empty");
}

/// `EvalChecksigPreTapscript`
fn eval_checksig_pre_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    script_code_span: &[u8],
    flags: u32,
    checker: &Checker,
    sigversion: SigVersion,
    f_success: &mut bool,
) -> ScriptResult<()> {
    debug_assert!(sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0);
    // Subset of script starting at the most recent codeseparator
    let mut script_code = script_code_span.to_vec();

    // Drop the signature in pre-segwit scripts but not segwit scripts
    if sigversion == SigVersion::Base {
        let found = find_and_delete(&mut script_code, &push_encode(sig));
        if found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0 {
            return Err(ScriptError::SigFindAndDelete);
        }
    }

    check_signature_encoding(sig, flags)?;
    check_pubkey_encoding(pubkey, flags, sigversion)?;
    *f_success = checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion);

    if !*f_success && (flags & SCRIPT_VERIFY_NULLFAIL) != 0 && !sig.is_empty() {
        return Err(ScriptError::SigNullFail);
    }
    Ok(())
}

/// `EvalChecksigTapscript`
fn eval_checksig_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    execdata: &mut ExecData,
    flags: u32,
    checker: &Checker,
    sigversion: SigVersion,
    success: &mut bool,
) -> ScriptResult<()> {
    debug_assert!(sigversion == SigVersion::Tapscript);
    // The following validation sequence is consensus critical (see Core).
    *success = !sig.is_empty();
    if *success {
        // Implement the sigops/witnesssize ratio test.
        debug_assert!(execdata.validation_weight_left_init);
        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if execdata.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }
    if pubkey.is_empty() {
        return Err(ScriptError::TapscriptEmptyPubkey);
    } else if pubkey.len() == 32 {
        if *success {
            checker.check_schnorr_signature(sig, pubkey, sigversion, execdata)?;
        }
    } else {
        // New public key version softforks should be defined before this `else` block.
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) != 0 {
            return Err(ScriptError::DiscourageUpgradablePubkeyType);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn eval_checksig(
    sig: &[u8],
    pubkey: &[u8],
    script_code_span: &[u8],
    execdata: &mut ExecData,
    flags: u32,
    checker: &Checker,
    sigversion: SigVersion,
    success: &mut bool,
) -> ScriptResult<()> {
    match sigversion {
        SigVersion::Base | SigVersion::WitnessV0 => eval_checksig_pre_tapscript(
            sig,
            pubkey,
            script_code_span,
            flags,
            checker,
            sigversion,
            success,
        ),
        SigVersion::Tapscript => {
            eval_checksig_tapscript(sig, pubkey, execdata, flags, checker, sigversion, success)
        }
        SigVersion::Taproot => unreachable!("key path spending has no script"),
    }
}

#[inline]
fn is_disabled_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
    )
}

/// `EvalScript` (the full six-argument version).
pub fn eval_script(
    stack: &mut Stack,
    script: &[u8],
    flags: u32,
    checker: &Checker,
    sigversion: SigVersion,
    execdata: &mut ExecData,
) -> ScriptResult<()> {
    let vch_false: Vec<u8> = Vec::new();
    let vch_true: Vec<u8> = vec![1];

    debug_assert!(sigversion != SigVersion::Taproot);
    let pre_tapscript = sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0;

    let mut pc = 0usize;
    let pend = script.len();
    let mut pbegincodehash = 0usize;
    let mut vf_exec = ConditionStack::new();
    let mut altstack: Stack = Vec::new();
    if pre_tapscript && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    let mut n_op_count: i32 = 0;
    let f_require_minimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    let mut opcode_pos: u32 = 0;
    execdata.codeseparator_pos = 0xFFFF_FFFF;
    execdata.codeseparator_pos_init = true;

    while pc < pend {
        let f_exec = vf_exec.all_true();

        //
        // Read instruction
        //
        let (opcode, push_start, push_end) = match get_op(script, &mut pc) {
            Some(x) => x,
            None => return Err(ScriptError::BadOpcode),
        };
        let vch_push_value = &script[push_start..push_end];
        if vch_push_value.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }

        if pre_tapscript {
            // Note how OP_RESERVED does not count towards the opcode limit.
            if opcode > OP_16 {
                n_op_count += 1;
                if n_op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }
        }

        if is_disabled_opcode(opcode) {
            return Err(ScriptError::DisabledOpcode); // Disabled opcodes (CVE-2010-5137).
        }

        // With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is rejected even in an unexecuted branch
        if opcode == OP_CODESEPARATOR
            && sigversion == SigVersion::Base
            && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0
        {
            return Err(ScriptError::OpCodeseparator);
        }

        if f_exec && opcode <= OP_PUSHDATA4 {
            if f_require_minimal && !check_minimal_push(vch_push_value, opcode) {
                return Err(ScriptError::MinimalData);
            }
            stack.push(vch_push_value.to_vec());
        } else if f_exec || (OP_IF <= opcode && opcode <= OP_ENDIF) {
            match opcode {
                //
                // Push value
                //
                OP_1NEGATE | OP_1..=OP_16 => {
                    // ( -- value)
                    let bn = (opcode as i64) - ((OP_1 - 1) as i64);
                    stack.push(scriptnum_serialize(bn));
                }

                //
                // Control
                //
                OP_NOP => {}

                OP_CHECKLOCKTIMEVERIFY => {
                    if (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        // 5-byte numeric operands (see Core comment)
                        let n_lock_time = scriptnum_decode(stacktop(stack, 1), f_require_minimal, 5)?;
                        if n_lock_time < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if !checker.check_lock_time(n_lock_time) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                    // else: not enabled; treat as a NOP2
                }

                OP_CHECKSEQUENCEVERIFY => {
                    if (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let n_sequence = scriptnum_decode(stacktop(stack, 1), f_require_minimal, 5)?;
                        if n_sequence < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        // To provide for future soft-fork extensibility, if the
                        // operand has the disabled lock-time flag set,
                        // CHECKSEQUENCEVERIFY behaves as a NOP.
                        if (n_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0 {
                            if !checker.check_sequence(n_sequence) {
                                return Err(ScriptError::UnsatisfiedLocktime);
                            }
                        }
                    }
                    // else: not enabled; treat as a NOP3
                }

                OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0 {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                }

                OP_IF | OP_NOTIF => {
                    // <expression> if [statements] [else [statements]] endif
                    let mut f_value = false;
                    if f_exec {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch = stacktop(stack, 1);
                        // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                        if sigversion == SigVersion::Tapscript {
                            if vch.len() > 1 || (vch.len() == 1 && vch[0] != 1) {
                                return Err(ScriptError::TapscriptMinimalIf);
                            }
                        }
                        // Under witness v0 rules it is only a policy rule, enabled through SCRIPT_VERIFY_MINIMALIF.
                        if sigversion == SigVersion::WitnessV0 && (flags & SCRIPT_VERIFY_MINIMALIF) != 0 {
                            if vch.len() > 1 {
                                return Err(ScriptError::MinimalIf);
                            }
                            if vch.len() == 1 && vch[0] != 1 {
                                return Err(ScriptError::MinimalIf);
                            }
                        }
                        f_value = cast_to_bool(vch);
                        if opcode == OP_NOTIF {
                            f_value = !f_value;
                        }
                        popstack(stack);
                    }
                    vf_exec.push_back(f_value);
                }

                OP_ELSE => {
                    if vf_exec.empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    vf_exec.toggle_top();
                }

                OP_ENDIF => {
                    if vf_exec.empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    vf_exec.pop_back();
                }

                OP_VERIFY => {
                    // (true -- ) or
                    // (false -- false) and return
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let f_value = cast_to_bool(stacktop(stack, 1));
                    if f_value {
                        popstack(stack);
                    } else {
                        return Err(ScriptError::Verify);
                    }
                }

                OP_RETURN => {
                    return Err(ScriptError::OpReturn);
                }

                //
                // Stack ops
                //
                OP_TOALTSTACK => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    altstack.push(stacktop(stack, 1).clone());
                    popstack(stack);
                }

                OP_FROMALTSTACK => {
                    if altstack.is_empty() {
                        return Err(ScriptError::InvalidAltstackOperation);
                    }
                    stack.push(stacktop(&altstack, 1).clone());
                    popstack(&mut altstack);
                }

                OP_2DROP => {
                    // (x1 x2 -- )
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    popstack(stack);
                    popstack(stack);
                }

                OP_2DUP => {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch1 = stacktop(stack, 2).clone();
                    let vch2 = stacktop(stack, 1).clone();
                    stack.push(vch1);
                    stack.push(vch2);
                }

                OP_3DUP => {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch1 = stacktop(stack, 3).clone();
                    let vch2 = stacktop(stack, 2).clone();
                    let vch3 = stacktop(stack, 1).clone();
                    stack.push(vch1);
                    stack.push(vch2);
                    stack.push(vch3);
                }

                OP_2OVER => {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch1 = stacktop(stack, 4).clone();
                    let vch2 = stacktop(stack, 3).clone();
                    stack.push(vch1);
                    stack.push(vch2);
                }

                OP_2ROT => {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if stack.len() < 6 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch1 = stacktop(stack, 6).clone();
                    let vch2 = stacktop(stack, 5).clone();
                    let n = stack.len();
                    stack.drain(n - 6..n - 4);
                    stack.push(vch1);
                    stack.push(vch2);
                }

                OP_2SWAP => {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = stack.len();
                    stack.swap(n - 4, n - 2);
                    stack.swap(n - 3, n - 1);
                }

                OP_IFDUP => {
                    // (x - 0 | x x)
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = stacktop(stack, 1).clone();
                    if cast_to_bool(&vch) {
                        stack.push(vch);
                    }
                }

                OP_DEPTH => {
                    // -- stacksize
                    stack.push(scriptnum_serialize(stack.len() as i64));
                }

                OP_DROP => {
                    // (x -- )
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    popstack(stack);
                }

                OP_DUP => {
                    // (x -- x x)
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = stacktop(stack, 1).clone();
                    stack.push(vch);
                }

                OP_NIP => {
                    // (x1 x2 -- x2)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = stack.len();
                    stack.remove(n - 2);
                }

                OP_OVER => {
                    // (x1 x2 -- x1 x2 x1)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = stacktop(stack, 2).clone();
                    stack.push(vch);
                }

                OP_PICK | OP_ROLL => {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = scriptnum_getint(scriptnum_decode(stacktop(stack, 1), f_require_minimal, 4)?);
                    popstack(stack);
                    if n < 0 || n as usize >= stack.len() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = n as usize;
                    let vch = stacktop(stack, n + 1).clone();
                    if opcode == OP_ROLL {
                        let len = stack.len();
                        stack.remove(len - n - 1);
                    }
                    stack.push(vch);
                }

                OP_ROT => {
                    // (x1 x2 x3 -- x2 x3 x1)
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = stack.len();
                    stack.swap(n - 3, n - 2);
                    stack.swap(n - 2, n - 1);
                }

                OP_SWAP => {
                    // (x1 x2 -- x2 x1)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = stack.len();
                    stack.swap(n - 2, n - 1);
                }

                OP_TUCK => {
                    // (x1 x2 -- x2 x1 x2)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = stacktop(stack, 1).clone();
                    let n = stack.len();
                    stack.insert(n - 2, vch);
                }

                OP_SIZE => {
                    // (in -- in size)
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn = stacktop(stack, 1).len() as i64;
                    stack.push(scriptnum_serialize(bn));
                }

                //
                // Bitwise logic
                //
                OP_EQUAL | OP_EQUALVERIFY => {
                    // (x1 x2 - bool)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let f_equal = stacktop(stack, 2) == stacktop(stack, 1);
                    popstack(stack);
                    popstack(stack);
                    stack.push(if f_equal { vch_true.clone() } else { vch_false.clone() });
                    if opcode == OP_EQUALVERIFY {
                        if f_equal {
                            popstack(stack);
                        } else {
                            return Err(ScriptError::EqualVerify);
                        }
                    }
                }

                //
                // Numeric
                //
                OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                    // (in -- out)
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut bn = scriptnum_decode(stacktop(stack, 1), f_require_minimal, 4)?;
                    match opcode {
                        OP_1ADD => bn += 1,
                        OP_1SUB => bn -= 1,
                        OP_NEGATE => bn = -bn,
                        OP_ABS => {
                            if bn < 0 {
                                bn = -bn
                            }
                        }
                        OP_NOT => bn = (bn == 0) as i64,
                        OP_0NOTEQUAL => bn = (bn != 0) as i64,
                        _ => unreachable!(),
                    }
                    popstack(stack);
                    stack.push(scriptnum_serialize(bn));
                }

                OP_ADD
                | OP_SUB
                | OP_BOOLAND
                | OP_BOOLOR
                | OP_NUMEQUAL
                | OP_NUMEQUALVERIFY
                | OP_NUMNOTEQUAL
                | OP_LESSTHAN
                | OP_GREATERTHAN
                | OP_LESSTHANOREQUAL
                | OP_GREATERTHANOREQUAL
                | OP_MIN
                | OP_MAX => {
                    // (x1 x2 -- out)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn1 = scriptnum_decode(stacktop(stack, 2), f_require_minimal, 4)?;
                    let bn2 = scriptnum_decode(stacktop(stack, 1), f_require_minimal, 4)?;
                    let bn: i64 = match opcode {
                        OP_ADD => bn1 + bn2,
                        OP_SUB => bn1 - bn2,
                        OP_BOOLAND => (bn1 != 0 && bn2 != 0) as i64,
                        OP_BOOLOR => (bn1 != 0 || bn2 != 0) as i64,
                        OP_NUMEQUAL => (bn1 == bn2) as i64,
                        OP_NUMEQUALVERIFY => (bn1 == bn2) as i64,
                        OP_NUMNOTEQUAL => (bn1 != bn2) as i64,
                        OP_LESSTHAN => (bn1 < bn2) as i64,
                        OP_GREATERTHAN => (bn1 > bn2) as i64,
                        OP_LESSTHANOREQUAL => (bn1 <= bn2) as i64,
                        OP_GREATERTHANOREQUAL => (bn1 >= bn2) as i64,
                        OP_MIN => {
                            if bn1 < bn2 {
                                bn1
                            } else {
                                bn2
                            }
                        }
                        OP_MAX => {
                            if bn1 > bn2 {
                                bn1
                            } else {
                                bn2
                            }
                        }
                        _ => unreachable!(),
                    };
                    popstack(stack);
                    popstack(stack);
                    stack.push(scriptnum_serialize(bn));

                    if opcode == OP_NUMEQUALVERIFY {
                        if cast_to_bool(stacktop(stack, 1)) {
                            popstack(stack);
                        } else {
                            return Err(ScriptError::NumEqualVerify);
                        }
                    }
                }

                OP_WITHIN => {
                    // (x min max -- out)
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn1 = scriptnum_decode(stacktop(stack, 3), f_require_minimal, 4)?;
                    let bn2 = scriptnum_decode(stacktop(stack, 2), f_require_minimal, 4)?;
                    let bn3 = scriptnum_decode(stacktop(stack, 1), f_require_minimal, 4)?;
                    let f_value = bn2 <= bn1 && bn1 < bn3;
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push(if f_value { vch_true.clone() } else { vch_false.clone() });
                }

                //
                // Crypto
                //
                OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                    // (in -- hash)
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = stacktop(stack, 1);
                    let vch_hash: Vec<u8> = match opcode {
                        OP_RIPEMD160 => ripemd160::Hash::hash(vch).to_byte_array().to_vec(),
                        OP_SHA1 => sha1::Hash::hash(vch).to_byte_array().to_vec(),
                        OP_SHA256 => sha256_bytes(vch).to_vec(),
                        OP_HASH160 => hash160::Hash::hash(vch).to_byte_array().to_vec(),
                        _ => sha256d_bytes(vch).to_vec(),
                    };
                    popstack(stack);
                    stack.push(vch_hash);
                }

                OP_CODESEPARATOR => {
                    // If SCRIPT_VERIFY_CONST_SCRIPTCODE flag is set, use of OP_CODESEPARATOR is rejected in pre-segwit
                    // script, even in an unexecuted branch (this is checked above the opcode case statement).

                    // Hash starts after the code separator
                    pbegincodehash = pc;
                    execdata.codeseparator_pos = opcode_pos;
                }

                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    // (sig pubkey -- bool)
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch_sig = stacktop(stack, 2).clone();
                    let vch_pubkey = stacktop(stack, 1).clone();

                    let mut f_success = true;
                    eval_checksig(
                        &vch_sig,
                        &vch_pubkey,
                        &script[pbegincodehash..pend],
                        execdata,
                        flags,
                        checker,
                        sigversion,
                        &mut f_success,
                    )?;
                    popstack(stack);
                    popstack(stack);
                    stack.push(if f_success { vch_true.clone() } else { vch_false.clone() });
                    if opcode == OP_CHECKSIGVERIFY {
                        if f_success {
                            popstack(stack);
                        } else {
                            return Err(ScriptError::CheckSigVerify);
                        }
                    }
                }

                OP_CHECKSIGADD => {
                    // OP_CHECKSIGADD is only available in Tapscript
                    if pre_tapscript {
                        return Err(ScriptError::BadOpcode);
                    }

                    // (sig num pubkey -- num)
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    let sig = stacktop(stack, 3).clone();
                    let num = scriptnum_decode(stacktop(stack, 2), f_require_minimal, 4)?;
                    let pubkey = stacktop(stack, 1).clone();

                    let mut success = true;
                    eval_checksig(
                        &sig,
                        &pubkey,
                        &script[pbegincodehash..pend],
                        execdata,
                        flags,
                        checker,
                        sigversion,
                        &mut success,
                    )?;
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push(scriptnum_serialize(num + if success { 1 } else { 0 }));
                }

                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    if sigversion == SigVersion::Tapscript {
                        return Err(ScriptError::TapscriptCheckMultisig);
                    }

                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    let mut i: i32 = 1;
                    if (stack.len() as i32) < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    let mut n_keys_count =
                        scriptnum_getint(scriptnum_decode(stacktop(stack, i as usize), f_require_minimal, 4)?);
                    if n_keys_count < 0 || n_keys_count > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::PubkeyCount);
                    }
                    n_op_count += n_keys_count;
                    if n_op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }
                    i += 1;
                    let mut ikey = i;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    let mut ikey2 = n_keys_count + 2;
                    i += n_keys_count;
                    if (stack.len() as i32) < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    let mut n_sigs_count =
                        scriptnum_getint(scriptnum_decode(stacktop(stack, i as usize), f_require_minimal, 4)?);
                    if n_sigs_count < 0 || n_sigs_count > n_keys_count {
                        return Err(ScriptError::SigCount);
                    }
                    i += 1;
                    let mut isig = i;
                    i += n_sigs_count;
                    if (stack.len() as i32) < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    // Subset of script starting at the most recent codeseparator
                    let mut script_code = script[pbegincodehash..pend].to_vec();

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for k in 0..n_sigs_count {
                        let vch_sig = stacktop(stack, (isig + k) as usize);
                        if sigversion == SigVersion::Base {
                            let found = find_and_delete(&mut script_code, &push_encode(vch_sig));
                            if found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0 {
                                return Err(ScriptError::SigFindAndDelete);
                            }
                        }
                    }

                    let mut f_success = true;
                    while f_success && n_sigs_count > 0 {
                        let vch_sig = stacktop(stack, isig as usize);
                        let vch_pubkey = stacktop(stack, ikey as usize);

                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        check_signature_encoding(vch_sig, flags)?;
                        check_pubkey_encoding(vch_pubkey, flags, sigversion)?;

                        // Check signature
                        let f_ok = checker.check_ecdsa_signature(vch_sig, vch_pubkey, &script_code, sigversion);

                        if f_ok {
                            isig += 1;
                            n_sigs_count -= 1;
                        }
                        ikey += 1;
                        n_keys_count -= 1;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if n_sigs_count > n_keys_count {
                            f_success = false;
                        }
                    }

                    // Clean up stack of actual arguments
                    loop {
                        // while (i-- > 1)
                        let cur = i;
                        i -= 1;
                        if cur <= 1 {
                            break;
                        }
                        // If the operation failed, we require that all signatures must be empty vector
                        if !f_success
                            && (flags & SCRIPT_VERIFY_NULLFAIL) != 0
                            && ikey2 == 0
                            && !stacktop(stack, 1).is_empty()
                        {
                            return Err(ScriptError::SigNullFail);
                        }
                        if ikey2 > 0 {
                            ikey2 -= 1;
                        }
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if (flags & SCRIPT_VERIFY_NULLDUMMY) != 0 && !stacktop(stack, 1).is_empty() {
                        return Err(ScriptError::SigNullDummy);
                    }
                    popstack(stack);

                    stack.push(if f_success { vch_true.clone() } else { vch_false.clone() });

                    if opcode == OP_CHECKMULTISIGVERIFY {
                        if f_success {
                            popstack(stack);
                        } else {
                            return Err(ScriptError::CheckMultisigVerify);
                        }
                    }
                }

                _ => return Err(ScriptError::BadOpcode),
            }
        }

        // Size limits
        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }

        opcode_pos += 1;
    }

    if !vf_exec.empty() {
        return Err(ScriptError::UnbalancedConditional);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Witness programs / taproot (interpreter.cpp)
// ---------------------------------------------------------------------------

/// `ExecuteWitnessScript`
fn execute_witness_script(
    stack_span: &[Vec<u8>],
    exec_script: &[u8],
    flags: u32,
    sigversion: SigVersion,
    checker: &Checker,
    execdata: &mut ExecData,
) -> ScriptResult<()> {
    let mut stack: Stack = stack_span.to_vec();

    if sigversion == SigVersion::Tapscript {
        // OP_SUCCESSx processing overrides everything, including stack element size limits
        let mut pc = 0usize;
        while pc < exec_script.len() {
            let (opcode, _, _) = match get_op(exec_script, &mut pc) {
                Some(x) => x,
                // Note how this condition would not be reached if an unknown OP_SUCCESSx was found
                None => return Err(ScriptError::BadOpcode),
            };
            // New opcodes will be listed here. May use a different sigversion to modify existing opcodes.
            if is_op_success(opcode) {
                if (flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS) != 0 {
                    return Err(ScriptError::DiscourageOpSuccess);
                }
                return Ok(());
            }
        }

        // Tapscript enforces initial stack size limits (altstack is empty here)
        if stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for elem in &stack {
        if elem.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }

    // Run the script interpreter.
    eval_script(&mut stack, exec_script, flags, checker, sigversion, execdata)?;

    // Scripts inside witness implicitly require cleanstack behaviour
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !cast_to_bool(stack.last().unwrap()) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

/// `ComputeTapleafHash`
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut h = Hasher::tagged("TapLeaf");
    h.write_u8(leaf_version);
    h.write_vec(script);
    h.finish_single()
}

/// `ComputeTapbranchHash`
fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::tagged("TapBranch");
    if a < b {
        h.write(a);
        h.write(b);
    } else {
        h.write(b);
        h.write(a);
    }
    h.finish_single()
}

/// `ComputeTaprootMerkleRoot`
fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &[u8; 32]) -> [u8; 32] {
    debug_assert!(control.len() >= TAPROOT_CONTROL_BASE_SIZE);
    debug_assert!(control.len() <= TAPROOT_CONTROL_MAX_SIZE);
    debug_assert!((control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0);

    let path_len = (control.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    let mut k = *tapleaf_hash;
    for i in 0..path_len {
        let start = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        let node: [u8; 32] = control[start..start + TAPROOT_CONTROL_NODE_SIZE].try_into().unwrap();
        k = compute_tapbranch_hash(&k, &node);
    }
    k
}

/// `XOnlyPubKey::CheckTapTweak` (pubkey.cpp): q == tweak(p, TapTweak(p || root))
/// with the given parity. libsecp's `xonly_pubkey_tweak_add_check` returns 0
/// for an unparsable internal key, a tweak >= the group order, or a mismatch;
/// each of those is `false` here.
fn check_tap_tweak(q: &[u8], p: &[u8], merkle_root: &[u8; 32], parity: bool) -> bool {
    let p_arr: [u8; 32] = match p.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let q_arr: [u8; 32] = match q.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let internal = match XOnlyPublicKey::from_byte_array(p_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // secp256k1_xonly_pubkey_tweak_add_check compares the serialized tweaked
    // key against the 32 raw bytes; an output key that is not a valid
    // x-coordinate can never compare equal.
    let output = match XOnlyPublicKey::from_byte_array(q_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut h = Hasher::tagged("TapTweak");
    h.write(&p_arr);
    h.write(merkle_root);
    let tweak_bytes = h.finish_single();
    let tweak = match Scalar::from_be_bytes(tweak_bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let parity = if parity { Parity::Odd } else { Parity::Even };
    internal.tweak_add_check(secp(), &output, parity, tweak)
}

/// `VerifyTaprootCommitment`
fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: &[u8; 32]) -> bool {
    debug_assert!(control.len() >= TAPROOT_CONTROL_BASE_SIZE);
    debug_assert!(program.len() >= 32);
    // The internal pubkey (x-only, so no Y coordinate parity).
    let p = &control[1..TAPROOT_CONTROL_BASE_SIZE];
    // Compute the Merkle root from the leaf and the provided path.
    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);
    // Verify that the output pubkey matches the tweaked internal pubkey, after correcting for parity.
    check_tap_tweak(program, p, &merkle_root, control[0] & 1 == 1)
}

/// `VerifyWitnessProgram`
#[allow(clippy::too_many_arguments)]
fn verify_witness_program(
    witness: &[Vec<u8>],
    witversion: i32,
    program: &[u8],
    flags: u32,
    checker: &Checker,
    is_p2sh: bool,
) -> ScriptResult<()> {
    let mut stack: &[Vec<u8>] = witness;
    let mut execdata = ExecData::new();

    if witversion == 0 {
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            // BIP141 P2WSH: 32-byte witness v0 program (which encodes SHA256(script))
            if stack.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let script_bytes = &stack[stack.len() - 1];
            stack = &stack[..stack.len() - 1];
            let hash_exec_script = sha256_bytes(script_bytes);
            if hash_exec_script[..] != program[..32] {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            execute_witness_script(stack, script_bytes, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else if program.len() == WITNESS_V0_KEYHASH_SIZE {
            // BIP141 P2WPKH: 20-byte witness v0 program (which encodes Hash160(pubkey))
            if stack.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch); // 2 items in witness
            }
            let mut exec_script = Vec::with_capacity(25);
            exec_script.push(OP_DUP);
            exec_script.push(OP_HASH160);
            exec_script.extend_from_slice(&push_encode(program));
            exec_script.push(OP_EQUALVERIFY);
            exec_script.push(OP_CHECKSIG);
            execute_witness_script(stack, &exec_script, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else {
            Err(ScriptError::WitnessProgramWrongLength)
        }
    } else if witversion == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        // BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
        if (flags & SCRIPT_VERIFY_TAPROOT) == 0 {
            return Ok(());
        }
        if stack.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }
        if stack.len() >= 2 && !stack[stack.len() - 1].is_empty() && stack[stack.len() - 1][0] == ANNEX_TAG {
            // Drop annex (this is non-standard; see IsWitnessStandard)
            let annex = &stack[stack.len() - 1];
            stack = &stack[..stack.len() - 1];
            let mut h = Hasher::new();
            h.write_vec(annex);
            execdata.annex_hash = h.finish_single();
            execdata.annex_present = true;
        } else {
            execdata.annex_present = false;
        }
        execdata.annex_init = true;
        if stack.len() == 1 {
            // Key path spending (stack size is 1 after removing optional annex)
            checker.check_schnorr_signature(&stack[0], program, SigVersion::Taproot, &mut execdata)?;
            Ok(())
        } else {
            // Script path spending (stack size is >1 after removing optional annex)
            let control = &stack[stack.len() - 1];
            let script = &stack[stack.len() - 2];
            stack = &stack[..stack.len() - 2];
            if control.len() < TAPROOT_CONTROL_BASE_SIZE
                || control.len() > TAPROOT_CONTROL_MAX_SIZE
                || ((control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) != 0
            {
                return Err(ScriptError::TaprootWrongControlSize);
            }
            execdata.tapleaf_hash = compute_tapleaf_hash(control[0] & TAPROOT_LEAF_MASK, script);
            if !verify_taproot_commitment(control, program, &execdata.tapleaf_hash) {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            execdata.tapleaf_hash_init = true;
            if (control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT {
                // Tapscript (leaf version 0xc0)
                execdata.validation_weight_left = witness_serialize_size(witness) + VALIDATION_WEIGHT_OFFSET;
                execdata.validation_weight_left_init = true;
                return execute_witness_script(stack, script, flags, SigVersion::Tapscript, checker, &mut execdata);
            }
            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) != 0 {
                return Err(ScriptError::DiscourageUpgradableTaprootVersion);
            }
            Ok(())
        }
    } else if !is_p2sh && is_pay_to_anchor(witversion, program) {
        Ok(())
    } else {
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0 {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        // Other version/size/p2sh combinations return true for future softfork compatibility
        Ok(())
    }
}

/// `VerifyScript`. Returns `Ok(())` on acceptance, else the Core error.
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: u32,
    checker: &Checker,
) -> ScriptResult<()> {
    let mut had_witness = false;

    if (flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !is_push_only(script_sig) {
        return Err(ScriptError::SigPushOnly);
    }

    // scriptSig and scriptPubKey must be evaluated sequentially on the same stack
    // rather than being simply concatenated (see CVE-2010-5141)
    let mut stack: Stack = Vec::new();
    let mut stack_copy: Stack = Vec::new();
    let mut execdata = ExecData::new();
    eval_script(&mut stack, script_sig, flags, checker, SigVersion::Base, &mut execdata)?;
    if (flags & SCRIPT_VERIFY_P2SH) != 0 {
        stack_copy = stack.clone();
    }
    let mut execdata = ExecData::new();
    eval_script(&mut stack, script_pubkey, flags, checker, SigVersion::Base, &mut execdata)?;
    if stack.is_empty() {
        return Err(ScriptError::EvalFalse);
    }
    if !cast_to_bool(stack.last().unwrap()) {
        return Err(ScriptError::EvalFalse);
    }

    // Bare witness programs
    if (flags & SCRIPT_VERIFY_WITNESS) != 0 {
        if let Some((witnessversion, witnessprogram)) = is_witness_program(script_pubkey) {
            had_witness = true;
            if !script_sig.is_empty() {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(witness, witnessversion, witnessprogram, flags, checker, false)?;
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.truncate(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if (flags & SCRIPT_VERIFY_P2SH) != 0 && is_pay_to_script_hash(script_pubkey) {
        // scriptSig must be literals-only or validation fails
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }

        // Restore stack.
        std::mem::swap(&mut stack, &mut stack_copy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        debug_assert!(!stack.is_empty());

        let pub_key2: Vec<u8> = stack.last().unwrap().clone();
        popstack(&mut stack);

        let mut execdata = ExecData::new();
        eval_script(&mut stack, &pub_key2, flags, checker, SigVersion::Base, &mut execdata)?;
        if stack.is_empty() {
            return Err(ScriptError::EvalFalse);
        }
        if !cast_to_bool(stack.last().unwrap()) {
            return Err(ScriptError::EvalFalse);
        }

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS) != 0 {
            if let Some((witnessversion, witnessprogram)) = is_witness_program(&pub_key2) {
                had_witness = true;
                if script_sig != push_encode(&pub_key2).as_slice() {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                verify_witness_program(witness, witnessversion, witnessprogram, flags, checker, true)?;
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.truncate(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if (flags & SCRIPT_VERIFY_CLEANSTACK) != 0 {
        // Core asserts P2SH and WITNESS are set here; we apply the rule as written.
        if stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS) != 0 {
        // Core asserts P2SH is set here.
        if !had_witness && !witness.is_empty() {
            return Err(ScriptError::WitnessUnexpected);
        }
    }

    Ok(())
}

/// Convenience: verify input `n_in` of the transaction in `ctx`.
pub fn verify_input(
    ctx: &TxContext,
    n_in: usize,
    script_sig: &[u8],
    script_pubkey: &[u8],
    flags: u32,
    amount: i64,
) -> Result<(), ScriptError> {
    if n_in >= ctx.tx.inputs.len() {
        return Err(ScriptError::UnknownError);
    }
    let checker = Checker::new(ctx, n_in, amount);
    let witness: &[Vec<u8>] = &ctx.tx.inputs[n_in].witness;
    verify_script(script_sig, script_pubkey, witness, flags, &checker)
}

/// Run one script (BASE / WITNESS_V0 semantics) over an initial stack and
/// return the resulting stack. Used by the Python-vs-native differential to
/// compare stack results, not by the node.
pub fn eval_script_standalone(
    ctx: &TxContext,
    n_in: usize,
    script: &[u8],
    flags: u32,
    sigversion: SigVersion,
    amount: i64,
    initial_stack: Vec<Vec<u8>>,
) -> (Result<(), ScriptError>, Vec<Vec<u8>>) {
    if n_in >= ctx.tx.inputs.len() {
        return (Err(ScriptError::UnknownError), initial_stack);
    }
    let checker = Checker::new(ctx, n_in, amount);
    let mut stack = initial_stack;
    let mut execdata = ExecData::new();
    let r = eval_script(&mut stack, script, flags, &checker, sigversion, &mut execdata);
    (r, stack)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scriptnum_roundtrip() {
        for v in [
            0i64, 1, -1, 127, 128, -128, 255, -255, 256, 32767, 32768, -32768, 65535, 2147483647,
            -2147483647, 2147483648, -2147483648, 549755813887, -549755813887,
        ] {
            let ser = scriptnum_serialize(v);
            let back = scriptnum_decode(&ser, true, 8).ok().unwrap();
            assert_eq!(back, v, "value {v} ser {ser:?}");
        }
        assert_eq!(scriptnum_serialize(-255), vec![0xff, 0x80]);
        assert_eq!(scriptnum_serialize(255), vec![0xff, 0x00]);
        assert_eq!(scriptnum_serialize(-1), vec![0x81]);
        // negative zero is rejected under minimal, accepted (as 0) otherwise
        assert!(scriptnum_decode(&[0x80], true, 4).is_err());
        assert_eq!(scriptnum_decode(&[0x80], false, 4).ok().unwrap(), 0);
        assert!(scriptnum_decode(&[0x00, 0x00, 0x00, 0x00, 0x00], true, 4).is_err());
    }

    #[test]
    fn cast_to_bool_negative_zero() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x80]));
        assert!(!cast_to_bool(&[0x00, 0x80]));
        assert!(cast_to_bool(&[0x80, 0x00]));
        assert!(cast_to_bool(&[0x01]));
    }

    #[test]
    fn find_and_delete_matches_core_semantics() {
        // Core's script_tests: FindAndDelete(CScript() << OP_1 << OP_2, CScript())
        let mut s = vec![0x51, 0x52];
        assert_eq!(find_and_delete(&mut s, &[]), 0);
        assert_eq!(s, vec![0x51, 0x52]);
        // deleting OP_2 in "OP_1 OP_2 OP_3" -> "OP_1 OP_3"
        let mut s = vec![0x51, 0x52, 0x53];
        assert_eq!(find_and_delete(&mut s, &[0x52]), 1);
        assert_eq!(s, vec![0x51, 0x53]);
        // a match inside push data is NOT deleted (only at op boundaries)
        let mut s = push_encode(&[0x52, 0x52]);
        assert_eq!(find_and_delete(&mut s, &[0x52]), 0);
        // repeated
        let mut s = vec![0x52, 0x52, 0x51];
        assert_eq!(find_and_delete(&mut s, &[0x52]), 2);
        assert_eq!(s, vec![0x51]);
        // Core test: "0x02ff03 0x02ff03" delete "0x02ff03" -> empty, 2 found
        let mut s = vec![0x02, 0xff, 0x03, 0x02, 0xff, 0x03];
        assert_eq!(find_and_delete(&mut s, &[0x02, 0xff, 0x03]), 2);
        assert!(s.is_empty());
        // Core test: <02ff03> <02ff03> delete 0x03 (matches only at boundaries) -> unchanged? no: 0x03 = push 3 bytes,
        // the needle must match at an op boundary and "0x03 0x02ff03" is a 3-byte push covering the rest.
        let mut s = vec![0x03, 0x02, 0xff, 0x03];
        assert_eq!(find_and_delete(&mut s, &[0x02, 0xff, 0x03]), 0);
    }

    #[test]
    fn push_encode_empty_is_op_0() {
        assert_eq!(push_encode(&[]), vec![0x00]);
        assert_eq!(push_encode(&[1]), vec![0x01, 0x01]);
        assert_eq!(push_encode(&[7u8; 76])[..2], [0x4c, 76]);
        assert_eq!(push_encode(&[7u8; 256])[..3], [0x4d, 0x00, 0x01]);
    }

    #[test]
    fn witness_program_detection() {
        let spk = [&[0x00u8, 0x14][..], &[0u8; 20][..]].concat();
        assert_eq!(is_witness_program(&spk).map(|(v, p)| (v, p.len())), Some((0, 20)));
        let spk = [&[0x51u8, 0x20][..], &[0u8; 32][..]].concat();
        assert_eq!(is_witness_program(&spk).map(|(v, p)| (v, p.len())), Some((1, 32)));
        assert!(is_witness_program(&[0x00, 0x01, 0x00]).is_none()); // too short
        // OP_2 <2 bytes> is a (version 2) witness program too: any 1-byte
        // OP_0/OP_1..16 followed by a 2..40-byte push qualifies.
        assert_eq!(is_witness_program(&[0x52, 0x02, 0x4e, 0x73]).map(|(v, p)| (v, p.len())), Some((2, 2)));
        assert!(is_witness_program(&[0x51, 0x02, 0x4e, 0x73]).is_some()); // P2A
    }

    fn decode_wire_tx_for_test(hex_tx: &str) -> Tx {
        // Convert a legacy (non-witness) wire tx into the extended transport
        // form by inserting marker/flag and empty witness stacks.
        let raw = hex::decode(hex_tx).unwrap();
        let mut c = Cursor { data: &raw, pos: 0 };
        let version = c.u32().unwrap();
        let n_in = c.compact_size().unwrap();
        let mut inputs = Vec::new();
        for _ in 0..n_in {
            let prevout_hash: [u8; 32] = c.take(32).unwrap().try_into().unwrap();
            let prevout_n = c.u32().unwrap();
            let script_sig = c.var_bytes().unwrap();
            let sequence = c.u32().unwrap();
            inputs.push(TxIn { prevout_hash, prevout_n, script_sig, sequence, witness: vec![] });
        }
        let n_out = c.compact_size().unwrap();
        let mut outputs = Vec::new();
        for _ in 0..n_out {
            let value = c.i64().unwrap();
            let script_pubkey = c.var_bytes().unwrap();
            outputs.push(TxOut { value, script_pubkey });
        }
        let locktime = c.u32().unwrap();
        Tx { version, inputs, outputs, locktime }
    }

    #[test]
    fn legacy_sighash_core_vectors() {
        // Rows from bitcoin-core/src/test/data/sighash.json (display-order expected hash).
        let rows: [(&str, &str, usize, i32, &str); 3] = [
            ("907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229",
             "", 2, 1864164639, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e"),
            ("a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5",
             "65", 0, -1391424484, "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175"),
            ("6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8",
             "acab655151", 0, 479279909, "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c"),
        ];
        for (tx_hex, script_hex, n_in, hash_type, expected) in rows {
            let tx = decode_wire_tx_for_test(tx_hex);
            let script = hex::decode(script_hex).unwrap();
            let got = signature_hash_legacy(&tx, &script, n_in, hash_type);
            let mut exp = hex::decode(expected).unwrap();
            exp.reverse();
            assert_eq!(got.to_vec(), exp, "sighash vector nin={n_in} type={hash_type}");
        }
    }

    #[test]
    fn extended_transport_roundtrip() {
        // version=1, one input with a 2-item witness, one output, locktime=0
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&[0x00, 0x01]);
        b.push(1);
        b.extend_from_slice(&[0xaa; 32]);
        b.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        b.push(2);
        b.extend_from_slice(&[0x00, 0x00]);
        b.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        b.push(1);
        b.extend_from_slice(&5000i64.to_le_bytes());
        b.push(3);
        b.extend_from_slice(&[0x51, 0x52, 0x87]);
        b.push(2);
        b.push(1);
        b.push(0x01);
        b.push(0);
        b.extend_from_slice(&0u32.to_le_bytes());
        let tx = Tx::decode_extended(&b).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].witness, vec![vec![0x01], vec![]]);
        assert_eq!(tx.outputs[0].value, 5000);
        assert_eq!(tx.outputs[0].script_pubkey, vec![0x51, 0x52, 0x87]);
        // trailing byte is an error
        b.push(0);
        assert!(Tx::decode_extended(&b).is_err());
    }

    #[test]
    fn simple_scripts_evaluate() {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prevout_hash: [0; 32],
                prevout_n: 0xffff_ffff,
                script_sig: vec![],
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 0, script_pubkey: vec![] }],
            locktime: 0,
        };
        let ctx = TxContext::new(tx, None).unwrap();
        // 1 2 ADD 3 EQUAL
        assert!(verify_input(&ctx, 0, &[0x51, 0x52], &[0x93, 0x53, 0x87], 0, 0).is_ok());
        // 1 2 ADD 4 EQUAL -> EVAL_FALSE
        assert_eq!(verify_input(&ctx, 0, &[0x51, 0x52], &[0x93, 0x54, 0x87], 0, 0), Err(ScriptError::EvalFalse));
        // OP_CAT disabled even unexecuted
        assert_eq!(verify_input(&ctx, 0, &[0x00], &[0x63, 0x7e, 0x68, 0x51], 0, 0), Err(ScriptError::DisabledOpcode));
        // OP_VERIF fails even in unexecuted branch
        assert_eq!(verify_input(&ctx, 0, &[0x00], &[0x63, 0x65, 0x68, 0x51], 0, 0), Err(ScriptError::BadOpcode));
        // CLEANSTACK
        assert_eq!(
            verify_input(&ctx, 0, &[0x51, 0x51], &[], SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, 0),
            Err(ScriptError::CleanStack)
        );
    }
}
