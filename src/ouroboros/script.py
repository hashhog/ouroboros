"""
Bitcoin script interpreter for transaction validation.

This module implements a Bitcoin script interpreter that can verify
standard script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, etc.), and also
provides script disassembly functionality for human-readable script
representation.

Taproot support (BIP 340/341/342):
- Schnorr signature verification via coincurve or Rust extension
- Key-path spending (single witness element = Schnorr sig)
- Script-path spending (witness = [...script inputs, script, control block])
- OP_CHECKSIGADD for tapscript multisig
- Taproot-specific sighash (epoch 0x00, tagged hashes)
"""

import hashlib
import struct
from enum import IntEnum

from ouroboros.database import Transaction


class SigVersion(IntEnum):
    """Script signature verification context."""
    BASE = 0          # Legacy pre-SegWit
    WITNESS_V0 = 1    # SegWit v0 (BIP 141/143)
    TAPSCRIPT = 2     # Tapscript (BIP 342)


# ---------------------------------------------------------------------------
# Script verification flags (src/script/interpreter.h)
# ---------------------------------------------------------------------------

SCRIPT_VERIFY_NONE = 0
SCRIPT_VERIFY_P2SH = (1 << 0)
SCRIPT_VERIFY_STRICTENC = (1 << 1)
SCRIPT_VERIFY_DERSIG = (1 << 2)          # BIP 66
SCRIPT_VERIFY_LOW_S = (1 << 3)           # BIP 62 rule 5
SCRIPT_VERIFY_NULLDUMMY = (1 << 4)       # BIP 147
SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)     # BIP 62 rule 2
SCRIPT_VERIFY_MINIMALDATA = (1 << 6)     # BIP 62 rule 3/4
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
SCRIPT_VERIFY_CLEANSTACK = (1 << 8)      # BIP 62 rule 6
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9)   # BIP 65
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10)  # BIP 112
SCRIPT_VERIFY_WITNESS = (1 << 11)        # BIP 141
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1 << 12)
SCRIPT_VERIFY_MINIMALIF = (1 << 13)
SCRIPT_VERIFY_NULLFAIL = (1 << 14)
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1 << 15)
SCRIPT_VERIFY_CONST_SCRIPTCODE = (1 << 16)
SCRIPT_VERIFY_TAPROOT = (1 << 17)        # BIP 341
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1 << 18)
SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = (1 << 19)
# BIP 342: in tapscript, fail on non-32-byte pubkeys
# (forward-compat with future Schnorr pubkey-versioning soft-forks).
# Mirrors Core SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
# (interpreter.h:146). Policy-only.
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1 << 20)

# Flags that are active on mainnet after all softfork activations.
# Used as the default for _execute_script so unit tests work without
# having to pass explicit flags.
SCRIPT_VERIFY_ALL_DEPLOYED = (
    SCRIPT_VERIFY_P2SH
    | SCRIPT_VERIFY_STRICTENC
    | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_LOW_S
    | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_MINIMALIF
    | SCRIPT_VERIFY_NULLFAIL
    | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    | SCRIPT_VERIFY_TAPROOT
)

# Maximum push data size in bytes
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_STACK_SIZE = 1000
MAX_SCRIPT_SIZE = 10000
MAX_OPS_PER_SCRIPT = 201
MAX_PUBKEYS_PER_MULTISIG = 20

# BIP-341 Taproot control-block geometry
# (bitcoin-core/src/script/interpreter.h:241-246).
ANNEX_TAG = 0x50
TAPROOT_LEAF_MASK = 0xfe
TAPROOT_LEAF_TAPSCRIPT = 0xc0
TAPROOT_CONTROL_BASE_SIZE = 33
TAPROOT_CONTROL_NODE_SIZE = 32
TAPROOT_CONTROL_MAX_NODE_COUNT = 128
TAPROOT_CONTROL_MAX_SIZE = (
    TAPROOT_CONTROL_BASE_SIZE
    + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT
)  # 33 + 32*128 = 4129
WITNESS_V1_TAPROOT_SIZE = 32

# Softfork activation heights (mainnet)
BIP16_ACTIVATION_HEIGHT = 173805
BIP34_ACTIVATION_HEIGHT = 227931
BIP65_ACTIVATION_HEIGHT = 388381
BIP66_ACTIVATION_HEIGHT = 363725
BIP68_ACTIVATION_HEIGHT = 419328
SEGWIT_ACTIVATION_HEIGHT = 481824
TAPROOT_ACTIVATION_HEIGHT = 709632

# Historical blocks that violate rules applied retroactively.
# Ref: Bitcoin Core kernel/chainparams.cpp:85-88 (mainnet), :210-211 (testnet3)
# — `consensus.script_flag_exceptions`.
#
# BYTE ORDER: keys are block hashes in INTERNAL byte order (little-endian) —
# the raw double-SHA256 digest, which is what `Block.hash` holds
# (database.py:178) and what `validation.py` passes down as `block_hash`.  The
# literals below are the *display* (big-endian) hashes from chainparams.cpp,
# reversed with [::-1].  Do NOT "fix" this to display order: the compare would
# then never match and the exceptions would silently stop firing.
# `tests/functional/test_script_flags.py` carries a byte-reversed negative
# control that fails if the orientation is flipped.
#
# The table is keyed by network exactly as Core keys it per-chainparams, so a
# testnet3 exception can never fire on mainnet (or vice versa).
_SCRIPT_FLAG_EXCEPTIONS: dict[str, dict[bytes, int]] = {
    "mainnet": {
        # BIP16 exception — mainnet height 170,060
        bytes.fromhex(
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        )[::-1]: SCRIPT_VERIFY_NONE,
        # Taproot exception — mainnet height 692,261
        bytes.fromhex(
            "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
        )[::-1]: SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
    },
    # BIP16 exception — testnet3 (chainparams.cpp:210-211)
    "testnet": {
        bytes.fromhex(
            "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
        )[::-1]: SCRIPT_VERIFY_NONE,
    },
    # testnet4 / signet / regtest declare no script_flag_exceptions.
}
_SCRIPT_FLAG_EXCEPTIONS["bitcoin"] = _SCRIPT_FLAG_EXCEPTIONS["mainnet"]
_SCRIPT_FLAG_EXCEPTIONS["testnet3"] = _SCRIPT_FLAG_EXCEPTIONS["testnet"]


def get_script_flag_exception(
    block_hash: bytes | None, network: str = "mainnet"
) -> int | None:
    """Look up *block_hash* in *network*'s ``script_flag_exceptions`` table.

    Returns the REPLACEMENT flag set on a hit, or ``None`` when the block is
    not an exception.  Core assigns rather than ORs on a hit
    (``flags = it->second;``, validation.cpp:2266).

    *block_hash* is in internal (little-endian) byte order.
    """
    if block_hash is None:
        return None
    table = _SCRIPT_FLAG_EXCEPTIONS.get(network.lower())
    if not table:
        return None
    return table.get(block_hash)

# secp256k1 curve order / 2, for low-S enforcement
SECP256K1_ORDER_HALF = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140 // 2
)


def get_flags_for_height(
    height: int,
    block_hash: bytes | None = None,
    network: str = "mainnet",
) -> int:
    """
    Consensus script verification flags for a block.

    Faithful port of Bitcoin Core's ``GetBlockScriptFlags()``
    (validation.cpp:2249-2289).  THREE steps, and the order is load-bearing:

    1. BASE — seed ``P2SH | WITNESS | TAPROOT`` UNCONDITIONALLY, for every
       block (:2262).  Core has had no ``BIP16Height`` and no ``taprootHeight``
       in this path since v23; only one historical block violated P2SH and one
       violated Taproot, and both are handled by the exception table below.  A
       height gate on any of these three flags is a consensus bug.
    2. EXCEPTION — on a block-hash hit in ``script_flag_exceptions``, REPLACE
       the whole flag set with the table's value (:2264-2267).  This is an
       assignment, NOT an early return.
    3. HEIGHT — OR the four still-height-gated flags ON TOP of step 2's result
       (:2268-2286): DERSIG (BIP66), CLTV (BIP65), CSV (BIP68/112/113) and
       NULLDUMMY (BIP147, which rides SegWit).

    Step 3 has to run AFTER step 2.  Block 692261's exception value is
    ``P2SH|WITNESS``; returning that directly would drop DERSIG|CLTV|CSV|
    NULLDUMMY — all four active at that height — and FALSE-ACCEPT scripts Core
    rejects under BIP-66/65/112/147.

    Policy-only flags (NULLFAIL, LOW_S, CLEANSTACK, SIGPUSHONLY, MINIMALDATA,
    MINIMALIF, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE,
    DISCOURAGE_UPGRADABLE_NOPS, ...) are STANDARD_SCRIPT_VERIFY_FLAGS
    (policy/policy.h:125) and must NEVER appear here — they belong in
    get_standard_script_flags() for mempool/relay only.

    Ref: Bitcoin Core validation.cpp:2249-2289 + policy/policy.h:105-111.

    Args:
        height: Block height
        block_hash: Block hash in INTERNAL (little-endian) byte order, used
            for the script_flag_exceptions lookup.  ``None`` skips step 2 and
            is only correct for callers that provably cannot be looking at an
            exception block (e.g. mempool acceptance at the tip).
        network: Network name (mainnet, testnet, testnet3, testnet4, regtest,
            signet)

    Returns:
        Combined consensus-only script verification flags
    """
    # --- Step 1: unconditional base set (validation.cpp:2262) ---------------
    flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT

    # --- Step 2: exception table REPLACES the base set (:2264-2267) ---------
    # NOT an early return — step 3 still runs on top of this value.
    exception_flags = get_script_flag_exception(block_hash, network)
    if exception_flags is not None:
        flags = exception_flags

    # --- Step 3: the four height-gated flags, OR'd on top (:2268-2286) ------
    # Import consensus module for deployment checks
    try:
        from ouroboros.consensus import is_buried_deployment_active
        use_consensus = True
    except ImportError:
        use_consensus = False

    if use_consensus:
        # BIP66 — strict DER signatures (DERSIG only; LOW_S is policy-only)
        if is_buried_deployment_active("bip66", height, network):
            flags |= SCRIPT_VERIFY_DERSIG

        # BIP65 — CHECKLOCKTIMEVERIFY
        if is_buried_deployment_active("bip65", height, network):
            flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY

        # BIP68/112/113 — CHECKSEQUENCEVERIFY
        if is_buried_deployment_active("csv", height, network):
            flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

        # BIP147 NULLDUMMY — activated simultaneously with SegWit.
        # NULLFAIL, CLEANSTACK, SIGPUSHONLY, MINIMALDATA, MINIMALIF,
        # WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_NOPS, CONST_SCRIPTCODE
        # are all STANDARD_SCRIPT_VERIFY_FLAGS (policy only).
        if is_buried_deployment_active("segwit", height, network):
            flags |= SCRIPT_VERIFY_NULLDUMMY

    else:
        # Fallback to hardcoded mainnet heights
        if height >= BIP66_ACTIVATION_HEIGHT:
            flags |= SCRIPT_VERIFY_DERSIG
        if height >= BIP65_ACTIVATION_HEIGHT:
            flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
        if height >= BIP68_ACTIVATION_HEIGHT:
            flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
        if height >= SEGWIT_ACTIVATION_HEIGHT:
            flags |= SCRIPT_VERIFY_NULLDUMMY

    return flags


def get_standard_script_flags(
    height: int,
    block_hash: bytes | None = None,
    network: str = "mainnet",
) -> int:
    """
    Standard (mempool/relay) script verification flags for *height*.

    Composes the consensus flags from get_flags_for_height() and adds the
    policy-only flags from STANDARD_SCRIPT_VERIFY_FLAGS that mempool uses
    to reject non-standard transactions.  Must NOT be used for block
    validation — use get_flags_for_height() there.

    Ref: Bitcoin Core policy/policy.h:119-132.
    """
    flags = get_flags_for_height(height, block_hash, network)

    # Add policy-only flags for mempool/relay standardness
    try:
        from ouroboros.consensus import is_buried_deployment_active
        use_consensus = True
    except ImportError:
        use_consensus = False

    if use_consensus:
        if is_buried_deployment_active("bip66", height, network):
            flags |= SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC
        if is_buried_deployment_active("segwit", height, network):
            flags |= (SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CLEANSTACK
                      | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA
                      | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
                      | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
                      | SCRIPT_VERIFY_CONST_SCRIPTCODE)
        if is_buried_deployment_active("taproot", height, network):
            flags |= (SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
                      | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)
    else:
        if height >= BIP66_ACTIVATION_HEIGHT:
            flags |= SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC
        if height >= SEGWIT_ACTIVATION_HEIGHT:
            flags |= (SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CLEANSTACK
                      | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA
                      | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
                      | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
                      | SCRIPT_VERIFY_CONST_SCRIPTCODE)
        if height >= TAPROOT_ACTIVATION_HEIGHT:
            flags |= (SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
                      | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)

    return flags


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _minimal_push_script(data: bytes) -> bytes:
    """Return the MINIMAL canonical CScript push of *data*.

    Mirrors CScript::operator<<(std::span<const value_type>) in
    bitcoin-core/src/script/script.h (AppendDataSize + AppendData).

    Length 0          -> 0x00 (OP_0)
    Length 1-75       -> <len_byte> <data>
    Length 76-255     -> OP_PUSHDATA1 (0x4c) <len_byte> <data>
    Length 256-65535  -> OP_PUSHDATA2 (0x4d) <len_le16> <data>
    Length 65536+     -> OP_PUSHDATA4 (0x4e) <len_le32> <data>

    P2WPKH (22-byte) and P2WSH (34-byte) redeemScripts always fall in the
    1-75 range, so their canonical scriptSig is simply ``bytes([22]) + W``
    or ``bytes([34]) + W`` — no OP_PUSHDATA1 prefix.
    """
    n = len(data)
    if n == 0:
        return b'\x00'
    if n <= 75:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([0x4c, n]) + data
    if n <= 0xffff:
        return bytes([0x4d]) + n.to_bytes(2, 'little') + data
    return bytes([0x4e]) + n.to_bytes(4, 'little') + data


def _is_push_only(script: bytes) -> bool:
    i = 0
    while i < len(script):
        opcode = script[i]
        i += 1
        if opcode > 0x60:  # OP_16 = 0x60
            return False
        if 1 <= opcode <= 75:
            i += opcode
        elif opcode == 0x4c:
            if i >= len(script):
                return False
            n = script[i]
            i += 1 + n
        elif opcode == 0x4d:
            if i + 2 > len(script):
                return False
            n = int.from_bytes(script[i:i+2], 'little')
            i += 2 + n
        elif opcode == 0x4e:
            if i + 4 > len(script):
                return False
            n = int.from_bytes(script[i:i+4], 'little')
            i += 4 + n
    return True


def _is_push_only_simple(script: bytes) -> bool:
    i = 0
    while i < len(script):
        opcode = script[i]
        i += 1
        if opcode == 0x00:
            continue
        if 0x01 <= opcode <= 0x4b:
            i += opcode
        elif opcode == 0x4c:
            if i >= len(script):
                return False
            n = script[i]
            i += 1 + n
        elif opcode == 0x4d:
            if i + 2 > len(script):
                return False
            n = int.from_bytes(script[i:i+2], 'little')
            i += 2 + n
        elif opcode == 0x4e:
            if i + 4 > len(script):
                return False
            n = int.from_bytes(script[i:i+4], 'little')
            i += 4 + n
        elif opcode == 0x4f:
            continue
        elif 0x51 <= opcode <= 0x60:
            continue
        else:
            return False
    return True


def _check_der_signature(sig: bytes) -> bool:
    """Validate strict DER encoding (BIP 66)."""
    if len(sig) < 9:
        return False
    if len(sig) > 73:
        return False
    if sig[0] != 0x30:
        return False
    if sig[1] != len(sig) - 3:
        return False
    len_r = sig[3]
    if 5 + len_r >= len(sig):
        return False
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != len(sig):
        return False
    if sig[2] != 0x02:
        return False
    if len_r == 0:
        return False
    if sig[4] & 0x80:
        return False
    if len_r > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        return False
    if sig[len_r + 4] != 0x02:
        return False
    if len_s == 0:
        return False
    if sig[len_r + 6] & 0x80:
        return False
    if len_s > 1 and sig[len_r + 6] == 0x00 and not (sig[len_r + 7] & 0x80):
        return False
    return True


# SIGHASH_ANYONECANPAY bitmask, matches Bitcoin Core src/script/script.h
SIGHASH_ANYONECANPAY = 0x80


def _is_defined_hashtype(sig: bytes) -> bool:
    """Return True iff the signature's hashtype byte is in the valid range.

    Mirrors Bitcoin Core IsDefinedHashtypeSignature (interpreter.cpp:190-199).
    Strips SIGHASH_ANYONECANPAY (0x80) before the range check; all other
    reserved bits (5-6) must be zero.  Valid base types: 1=ALL, 2=NONE, 3=SINGLE.
    """
    if not sig:
        return False
    nHashType = sig[-1] & (~SIGHASH_ANYONECANPAY & 0xFF)
    return 1 <= nHashType <= 3


def _check_low_s(sig_without_hashtype: bytes) -> bool:
    if len(sig_without_hashtype) < 6:
        return True
    if sig_without_hashtype[0] != 0x30:
        return True
    len_r = sig_without_hashtype[3]
    s_start = 6 + len_r
    len_s = sig_without_hashtype[5 + len_r]
    if s_start + len_s > len(sig_without_hashtype):
        return True
    s_bytes = sig_without_hashtype[s_start:s_start + len_s]
    s_val = int.from_bytes(s_bytes, 'big')
    return s_val <= SECP256K1_ORDER_HALF


def _check_pubkey_encoding(pubkey: bytes) -> bool:
    if len(pubkey) == 33 and pubkey[0] in (0x02, 0x03):
        return True
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        return True
    return False


def _check_compressed_pubkey(pubkey: bytes) -> bool:
    return len(pubkey) == 33 and pubkey[0] in (0x02, 0x03)


def _get_witness_version_and_program(script_pubkey: bytes) -> tuple[int, bytes] | None:
    if len(script_pubkey) < 4 or len(script_pubkey) > 42:
        return None
    version_opcode = script_pubkey[0]
    if version_opcode == 0x00:
        version = 0
    elif 0x51 <= version_opcode <= 0x60:
        version = version_opcode - 0x50
    else:
        return None
    program_len = script_pubkey[1]
    if program_len + 2 != len(script_pubkey):
        return None
    if program_len < 2 or program_len > 40:
        return None
    return version, script_pubkey[2:]


class ScriptInterpreter:
    """Interprets and verifies Bitcoin scripts"""

    def __init__(self):
        pass

    def verify(
        self,
        script_sig: bytes,
        script_pubkey: bytes,
        tx: Transaction,
        input_index: int,
        flags: int = SCRIPT_VERIFY_NONE,
        amount: int = 0,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
    ) -> bool:
        """
        Verify a script against the consensus rules indicated by *flags*.

        This follows Bitcoin Core's VerifyScript() logic:
        1. (optional) Check scriptSig is push-only (SIGPUSHONLY)
        2. Execute scriptSig -> stack
        3. Copy stack (for P2SH)
        4. Execute scriptPubKey with the stack
        5. Top of stack must be truthy
        6. If P2SH, deserialize and execute redeem script
        7. If witness program detected, verify witness
        8. Enforce clean stack
        """
        try:
            # SIGPUSHONLY: scriptSig must contain only data pushes
            if (flags & SCRIPT_VERIFY_SIGPUSHONLY) and not _is_push_only_simple(script_sig):
                return False

            # Step 1: Execute scriptSig
            stack = self._execute_script(
                script_sig, tx, input_index, script_pubkey, flags)

            # Step 2: Copy stack for P2SH evaluation later
            stack_copy = list(stack) if (flags & SCRIPT_VERIFY_P2SH) else []

            # Step 3: Execute scriptPubKey with the resulting stack
            stack = self._execute_script(
                script_pubkey, tx, input_index, script_pubkey, flags,
                initial_stack=stack)

            if not stack or not self._cast_to_bool(stack[-1]):
                return False

            # Step 4: Check for witness programs in scriptPubKey
            witness = None
            if hasattr(tx, 'inputs') and input_index < len(tx.inputs):
                witness = getattr(tx.inputs[input_index], 'witness', None)

            wp = _get_witness_version_and_program(script_pubkey)
            if (flags & SCRIPT_VERIFY_WITNESS) and wp is not None:
                version, program = wp
                if script_sig:
                    return False  # scriptSig must be empty for native witness
                if not self._verify_witness_program(
                    tx, input_index, version, program,
                    witness or [], flags, amount,
                    input_amounts, input_script_pubkeys,
                ):
                    return False
                # Witness programs define their own clean-stack semantics
                return True

            # Step 5: P2SH evaluation
            if (flags & SCRIPT_VERIFY_P2SH) and self._is_p2sh(script_pubkey):
                if not _is_push_only_simple(script_sig):
                    return False
                if not stack_copy:
                    return False
                redeem_script = stack_copy[-1]

                # Check for witness program inside P2SH (P2SH-P2WPKH, P2SH-P2WSH)
                wp_inner = _get_witness_version_and_program(redeem_script)
                if (flags & SCRIPT_VERIFY_WITNESS) and wp_inner is not None:
                    version, program = wp_inner
                    # Core interpreter.cpp:2082-2086: scriptSig must equal
                    # CScript() << redeemScript (the MINIMAL canonical push of
                    # the redeemScript bytes).  Any non-minimal encoding (e.g.
                    # OP_PUSHDATA1 for a <=75-byte redeemScript) is rejected as
                    # SCRIPT_ERR_WITNESS_MALLEATED_P2SH, even though it is
                    # push-only and would evaluate to the same stack value.
                    # MINIMALDATA is a policy flag only and is NOT in
                    # GetBlockScriptFlags, so this byte-exact check is the sole
                    # guard against non-canonical encodings in block validation.
                    if script_sig != _minimal_push_script(redeem_script):
                        return False
                    return self._verify_witness_program(
                        tx, input_index, version, program,
                        witness or [], flags, amount,
                        input_amounts, input_script_pubkeys,
                        is_p2sh=True,
                    )

                redeem_stack = self._execute_script(
                    redeem_script, tx, input_index, redeem_script, flags,
                    initial_stack=stack_copy[:-1])
                if not redeem_stack or not self._cast_to_bool(redeem_stack[-1]):
                    return False
                if (flags & SCRIPT_VERIFY_CLEANSTACK) and len(redeem_stack) != 1:
                    return False
                # WITNESS_UNEXPECTED in P2SH non-witness path
                if (flags & SCRIPT_VERIFY_WITNESS) and witness:
                    return False
                return True

            # WITNESS_UNEXPECTED: if WITNESS flag is set and we did NOT
            # enter a witness program above, the tx must not carry witness data.
            if flags & SCRIPT_VERIFY_WITNESS:
                if witness:
                    return False  # unexpected witness data

            # Step 6: Clean stack
            if (flags & SCRIPT_VERIFY_CLEANSTACK) and len(stack) != 1:
                return False

            return True

        except Exception:
            return False

    def _is_p2sh(self, script: bytes) -> bool:
        return (len(script) == 23
                and script[0] == 0xa9
                and script[1] == 0x14
                and script[22] == 0x87)

    def _verify_witness_program(
        self,
        tx: Transaction,
        input_index: int,
        version: int,
        program: bytes,
        witness: list[bytes],
        flags: int,
        amount: int = 0,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        is_p2sh: bool = False,
    ) -> bool:
        """Verify a segregated witness program (BIP 141).

        ``is_p2sh`` is True when the witness program is reached via a P2SH
        redeem-script (BIP-141 §"P2SH-of-witness-program"). Per
        bitcoin-core/src/script/interpreter.cpp:1947, the BIP-341 Taproot
        branch is gated on ``!is_p2sh`` — a v1/32B program inside a P2SH
        wrap is NOT a Taproot output, and the forward-compat success path
        applies instead (Core line 1996-1998). Pay-to-Anchor (BIP-431 / Core
        line 1990) is similarly carved out before the DISCOURAGE check so
        adversarial nodes can't reject standard P2A spends via policy.
        """
        if version == 0:
            if len(program) == 20:
                return self._verify_witness_v0_keyhash(
                    tx, input_index, program, witness, flags, amount)
            elif len(program) == 32:
                return self._verify_witness_v0_scripthash(
                    tx, input_index, program, witness, flags, amount)
            else:
                return False
        # BIP-341 Taproot: v1, 32-byte program, NOT inside P2SH wrap.
        # Mirrors Core interpreter.cpp:1947 (`!is_p2sh` gate).
        elif (
            version == 1
            and len(program) == WITNESS_V1_TAPROOT_SIZE
            and not is_p2sh
        ):
            if flags & SCRIPT_VERIFY_TAPROOT:
                spk = bytes([0x51, 0x20]) + program
                return self.verify_taproot(
                    tx, input_index, witness, spk,
                    input_amounts, input_script_pubkeys, flags)
            return True
        # BIP-431 Pay-to-Anchor (v1, OP_PUSHBYTES_2 0x4e73). Always valid,
        # bare only (Core interpreter.cpp:1990: `!is_p2sh && IsPayToAnchor`).
        elif (
            not is_p2sh
            and version == 1
            and len(program) == 2
            and program == b"\x4e\x73"
        ):
            return True
        elif flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            return False
        return True  # unknown witness version succeeds

    def _verify_witness_v0_keyhash(
        self, tx: Transaction, input_index: int,
        keyhash: bytes, witness: list[bytes],
        flags: int, amount: int,
    ) -> bool:
        """P2WPKH: witness = [sig, pubkey], keyhash = HASH160(pubkey)."""
        if len(witness) != 2:
            return False
        sig, pubkey = witness[0], witness[1]
        if self._hash160(pubkey) != keyhash:
            return False
        # WITNESS_PUBKEYTYPE: pubkeys in v0 witness must be compressed
        if (flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) and not _check_compressed_pubkey(pubkey):
            return False
        # Build implicit P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        script_code = (
            b'\x76\xa9\x14' + keyhash + b'\x88\xac'
        )
        if not sig:
            return False
        der_sig = sig[:-1]
        # DER check fires when DERSIG | LOW_S | STRICTENC is set
        # (Core CheckSignatureEncoding, interpreter.cpp:207).
        if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) and not _check_der_signature(sig):
            return False
        if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
            return False
        # STRICTENC: hashtype bits 5-6 must be zero (mask ~ANYONECANPAY only).
        if (flags & SCRIPT_VERIFY_STRICTENC) and not _is_defined_hashtype(sig):
            return False
        # STRICTENC: pubkey must be valid compressed or uncompressed encoding.
        if (flags & SCRIPT_VERIFY_STRICTENC) and not _check_pubkey_encoding(pubkey):
            return False
        sighash_type = sig[-1]
        msg = self._compute_segwit_v0_sighash(
            tx, input_index, script_code, amount, sighash_type)
        if not self._verify_ecdsa_signature(msg, der_sig, pubkey):
            # NULLFAIL: non-empty sig must not be present on failure.
            if flags & SCRIPT_VERIFY_NULLFAIL:
                return False
            return False
        return True

    def _verify_witness_v0_scripthash(
        self, tx: Transaction, input_index: int,
        scripthash: bytes, witness: list[bytes],
        flags: int, amount: int,
    ) -> bool:
        if len(witness) < 1:
            return False
        witness_script = witness[-1]
        if hashlib.sha256(witness_script).digest() != scripthash:
            return False
        if len(witness_script) > MAX_SCRIPT_SIZE:
            return False
        stack = list(witness[:-1])
        stack = self._execute_script(
            witness_script, tx, input_index, witness_script, flags,
            initial_stack=stack, is_witness_v0=True, witness_amount=amount)
        if not stack or not self._cast_to_bool(stack[-1]):
            return False
        if len(stack) != 1:
            return False
        return True

    def _compute_segwit_v0_sighash(
        self,
        tx: Transaction,
        input_index: int,
        script_code: bytes,
        amount: int,
        sighash_type: int,
    ) -> bytes:
        """BIP 143 sighash for SegWit v0 transactions."""
        base_type = sighash_type & 0x1f
        anyone_can_pay = (sighash_type & 0x80) != 0
        if base_type == 0:
            base_type = 0x01

        # hashPrevouts
        if not anyone_can_pay:
            prevouts = bytearray()
            for inp in tx.inputs:
                prevouts.extend(inp.prev_txid)
                prevouts.extend(struct.pack('<I', inp.prev_vout))
            hash_prevouts = hashlib.sha256(hashlib.sha256(bytes(prevouts)).digest()).digest()
        else:
            hash_prevouts = b'\x00' * 32

        # hashSequence
        if not anyone_can_pay and base_type not in (0x02, 0x03):
            seqs = bytearray()
            for inp in tx.inputs:
                seqs.extend(struct.pack('<I', inp.sequence))
            hash_sequence = hashlib.sha256(hashlib.sha256(bytes(seqs)).digest()).digest()
        else:
            hash_sequence = b'\x00' * 32

        # hashOutputs
        if base_type not in (0x02, 0x03):
            outs = bytearray()
            for out in tx.outputs:
                outs.extend(struct.pack('<q', out.value))
                outs.extend(self._encode_varint(len(out.script_pubkey)))
                outs.extend(out.script_pubkey)
            hash_outputs = hashlib.sha256(hashlib.sha256(bytes(outs)).digest()).digest()
        elif base_type == 0x03 and input_index < len(tx.outputs):
            out = tx.outputs[input_index]
            single_out = struct.pack('<q', out.value)
            single_out += self._encode_varint(len(out.script_pubkey))
            single_out += out.script_pubkey
            hash_outputs = hashlib.sha256(hashlib.sha256(single_out).digest()).digest()
        else:
            hash_outputs = b'\x00' * 32

        inp = tx.inputs[input_index]
        data = bytearray()
        data.extend(struct.pack('<i', tx.version))
        data.extend(hash_prevouts)
        data.extend(hash_sequence)
        data.extend(inp.prev_txid)
        data.extend(struct.pack('<I', inp.prev_vout))
        data.extend(self._encode_varint(len(script_code)))
        data.extend(script_code)
        data.extend(struct.pack('<q', amount))
        data.extend(struct.pack('<I', inp.sequence))
        data.extend(hash_outputs)
        data.extend(struct.pack('<I', tx.locktime))
        data.extend(struct.pack('<I', sighash_type))

        return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()

    def _execute_script(
        self,
        script: bytes,
        tx: Transaction,
        input_index: int,
        script_pubkey: bytes,
        flags: int = SCRIPT_VERIFY_ALL_DEPLOYED,
        initial_stack: list[bytes] | None = None,
        is_witness_v0: bool = False,
        witness_amount: int = 0,
        sig_version: "SigVersion" = SigVersion.BASE,
        # Tapscript-specific parameters (only used when sig_version == TAPSCRIPT)
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        annex: bytes | None = None,
        leaf_hash: bytes | None = None,
        default_sighash: bytes | None = None,
        witness_weight: int = 0,
    ) -> list[bytes]:
        """Execute a Bitcoin script."""
        is_tapscript = sig_version == SigVersion.TAPSCRIPT

        # Script size limit (10,000 bytes) — applies to all non-tapscript scripts
        if not is_tapscript and len(script) > MAX_SCRIPT_SIZE:
            raise ValueError("Script too long")

        # Tapscript OP_SUCCESS pre-check: scan for OP_SUCCESS opcodes before
        # executing anything.  If any is found, the script succeeds
        # unconditionally (BIP 342).
        if is_tapscript:
            j = 0
            while j < len(script):
                op = script[j]
                j += 1
                # skip push data
                if 1 <= op <= 75:
                    j += op
                elif op == 0x4C:  # OP_PUSHDATA1
                    dlen = script[j] if j < len(script) else 0
                    j += 1 + dlen
                elif op == 0x4D:  # OP_PUSHDATA2
                    if j + 2 <= len(script):
                        dlen = int.from_bytes(script[j:j + 2], "little")
                        j += 2 + dlen
                    else:
                        j += 2
                elif op == 0x4E:  # OP_PUSHDATA4
                    if j + 4 <= len(script):
                        dlen = int.from_bytes(script[j:j + 4], "little")
                        j += 4 + dlen
                    else:
                        j += 4
                elif op in _TAPSCRIPT_OP_SUCCESS:
                    if flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS:
                        raise ValueError(
                            f"DISCOURAGE_OP_SUCCESS: OP_SUCCESS opcode 0x{op:02x}"
                        )
                    return [b"\x01"]  # immediate success

        stack: list[bytes] = list(initial_stack) if initial_stack else []
        altstack: list[bytes] = []
        exec_stack: list[bool] = []
        op_count = 0
        # BIP143 / legacy CODESEPARATOR: sighash scriptCode starts at the
        # byte after the most recently executed OP_CODESEPARATOR.  Matches
        # Bitcoin Core's pbegincodehash (interpreter.cpp).
        script_code_start = 0

        # BIP-341/342 tapscript-only opcode position tracking (Core
        # interpreter.cpp:432-434): ``opcode_pos`` is the 0-based index of
        # the *current* opcode being executed; ``codesep_pos`` records the
        # ``opcode_pos`` of the most recent OP_CODESEPARATOR (sentinel
        # 0xFFFFFFFF = none seen yet), and is committed to the tapscript
        # sighash via SignatureHashSchnorr's "Extension" block
        # (interpreter.cpp:1564-1566).
        opcode_pos = 0
        codesep_pos = 0xFFFFFFFF

        # Initial witness-stack constraints (interpreter.cpp:1836-1861,
        # ExecuteWitnessScript):
        #
        #   * MAX_STACK_SIZE (1000) pre-execution cap:
        #     Core: `if (sigversion == SigVersion::TAPSCRIPT)` at line 1855.
        #     TAPSCRIPT-ONLY — Core does NOT apply this to witness-v0 P2WSH.
        #     A P2WSH with >1000 initial stack items is consensus-valid but
        #     will almost certainly fail later (EvalScript dynamic check).
        #
        #   * MAX_SCRIPT_ELEMENT_SIZE (520) per-element cap:
        #     Core: `for (const valtype& elem : stack)` at line 1858-1861.
        #     Applies to BOTH tapscript and witness-v0 P2WSH.
        if is_tapscript:
            if len(stack) > MAX_STACK_SIZE:
                raise ValueError("Stack size exceeded (initial witness stack)")
        if is_tapscript or is_witness_v0:
            for elem in stack:
                if len(elem) > MAX_SCRIPT_ELEMENT_SIZE:
                    raise ValueError(
                        f"Witness stack item exceeds {MAX_SCRIPT_ELEMENT_SIZE} bytes"
                    )

        # BIP-342 validation-weight budget (interpreter.cpp:1981):
        #   m_validation_weight_left = ::GetSerializeSize(witness.stack)
        #                              + VALIDATION_WEIGHT_OFFSET (50)
        # Caller passes ``witness_weight`` = GetSerializeSize(witness.stack);
        # we add the +50 OFFSET here. Each non-empty CHECKSIG /
        # CHECKSIGVERIFY / CHECKSIGADD then deducts
        # VALIDATION_WEIGHT_PER_SIGOP_PASSED (50) and aborts on negative.
        sigops_budget = 50 + witness_weight if is_tapscript else 0

        _DISABLED = frozenset([
            0x7e, 0x7f, 0x80, 0x81,  # CAT, SUBSTR, LEFT, RIGHT
            0x83, 0x84, 0x85, 0x86,  # INVERT, AND, OR, XOR
            0x8d, 0x8e,              # 2MUL, 2DIV
            0x95, 0x96, 0x97, 0x98, 0x99,  # MUL, DIV, MOD, LSHIFT, RSHIFT
        ])

        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1
            # BIP-341/342: record the 0-based index of the opcode being
            # processed (Core interpreter.cpp:433 — `++opcode_pos` at the
            # top of the for-loop, so the first opcode sees pos=0).
            # Push-data ops also advance, matching Core's unconditional
            # increment.  `codesep_pos` snapshots this value when
            # OP_CODESEPARATOR fires inside a tapscript.
            current_opcode_pos = opcode_pos
            opcode_pos += 1

            executing = not exec_stack or all(exec_stack)

            # OP_VERIF / OP_VERNOTIF are always invalid
            if opcode in (0x65, 0x66):
                raise ValueError(f"Invalid opcode 0x{opcode:02x}")

            # Data push (always consume bytes; only push when executing)
            push_data = None
            if 1 <= opcode <= 75:
                n = opcode
                if i + n > len(script):
                    raise ValueError("Invalid data push")
                push_data = script[i:i + n]
                i += n
            elif opcode == 0x4c:
                if i >= len(script):
                    raise ValueError("Invalid OP_PUSHDATA1")
                n = script[i]
                i += 1
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA1")
                push_data = script[i:i + n]
                i += n
            elif opcode == 0x4d:
                if i + 2 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2")
                n = int.from_bytes(script[i:i + 2], 'little')
                i += 2
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2")
                push_data = script[i:i + n]
                i += n
            elif opcode == 0x4e:
                if i + 4 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4")
                n = int.from_bytes(script[i:i + 4], 'little')
                i += 4
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4")
                push_data = script[i:i + n]
                i += n

            if push_data is not None:
                # PUSH_SIZE check applies even in non-executed branches
                if len(push_data) > MAX_SCRIPT_ELEMENT_SIZE:
                    raise ValueError(f"Push data exceeds {MAX_SCRIPT_ELEMENT_SIZE} bytes")
                if executing:
                    # MINIMALDATA: reject non-minimal push encodings
                    if flags & SCRIPT_VERIFY_MINIMALDATA:
                        n = len(push_data)
                        if n == 0:
                            # Empty data should use OP_0 (0x00), not a push
                            if opcode != 0x00:
                                raise ValueError("MINIMALDATA: empty push should use OP_0")
                        elif n == 1 and 1 <= push_data[0] <= 16:
                            # Single byte 1-16 should use OP_1..OP_16
                            raise ValueError("MINIMALDATA: should use OP_n")
                        elif n == 1 and push_data[0] == 0x81:
                            # -1 should use OP_1NEGATE
                            raise ValueError("MINIMALDATA: should use OP_1NEGATE")
                        elif n <= 75 and opcode > 75:
                            # Data fits in direct push but used OP_PUSHDATA1/2/4
                            raise ValueError("MINIMALDATA: non-minimal push encoding")
                        elif n <= 0xFF and opcode == 0x4d:
                            # Fits in OP_PUSHDATA1 but used OP_PUSHDATA2
                            raise ValueError("MINIMALDATA: non-minimal push encoding")
                        elif n <= 0xFFFF and opcode == 0x4e:
                            # Fits in OP_PUSHDATA2 but used OP_PUSHDATA4
                            raise ValueError("MINIMALDATA: non-minimal push encoding")
                    stack.append(push_data)
                    if len(stack) + len(altstack) > MAX_STACK_SIZE:
                        raise ValueError("Stack size exceeded")
                continue

            # Op count (opcodes > OP_16 only, regardless of exec state)
            # Tapscript removes the 201 op-count limit (BIP 342).
            if opcode > 0x60:
                op_count += 1
                if not is_tapscript and op_count > 201:
                    raise ValueError("Too many operations")

            if opcode in _DISABLED:
                raise ValueError(f"Disabled opcode 0x{opcode:02x}")

            # CONST_SCRIPTCODE: OP_CODESEPARATOR in BASE (legacy non-segwit)
            # scripts is rejected even in unexecuted branches when the flag is
            # set.  Mirrors Core interpreter.cpp:474-476, which fires BEFORE
            # the fExec gate.  Core checks `sigversion == SigVersion::BASE` —
            # not witness — because OP_CODESEPARATOR is valid in witness scripts.
            if opcode == 0xab and not is_witness_v0 and not is_tapscript:
                if flags & SCRIPT_VERIFY_CONST_SCRIPTCODE:
                    raise ValueError("CONST_SCRIPTCODE: OP_CODESEPARATOR in non-witness script")

            # Flow control (always processed for nesting)
            if opcode == 0x63:  # OP_IF
                val = False
                if executing:
                    if not stack:
                        raise ValueError("OP_IF: stack underflow")
                    top = stack.pop()
                    # MINIMALIF: enforce in tapscript (consensus) or segwit v0 (policy)
                    if (is_tapscript or (is_witness_v0 and (flags & SCRIPT_VERIFY_MINIMALIF))) and top not in (b"", b"\x01"):
                        raise ValueError("MINIMALIF: non-minimal OP_IF input")
                    val = self._cast_to_bool(top)
                exec_stack.append(val)
                continue
            if opcode == 0x64:  # OP_NOTIF
                val = False
                if executing:
                    if not stack:
                        raise ValueError("OP_NOTIF: stack underflow")
                    top = stack.pop()
                    # MINIMALIF: enforce in tapscript (consensus) or segwit v0 (policy)
                    if (is_tapscript or (is_witness_v0 and (flags & SCRIPT_VERIFY_MINIMALIF))) and top not in (b"", b"\x01"):
                        raise ValueError("MINIMALIF: non-minimal OP_NOTIF input")
                    val = not self._cast_to_bool(top)
                exec_stack.append(val)
                continue
            if opcode == 0x67:  # OP_ELSE
                if not exec_stack:
                    raise ValueError("OP_ELSE without OP_IF")
                exec_stack[-1] = not exec_stack[-1]
                continue
            if opcode == 0x68:  # OP_ENDIF
                if not exec_stack:
                    raise ValueError("OP_ENDIF without OP_IF")
                exec_stack.pop()
                continue

            if not executing:
                continue

            # From here on, the opcode is being executed.

            # Constants
            if opcode == 0x00:  # OP_0 / OP_FALSE
                stack.append(b'')
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x4f:  # OP_1NEGATE
                stack.append(b'\x81')
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if 0x51 <= opcode <= 0x60:  # OP_1 .. OP_16
                stack.append(bytes([opcode - 0x50]))
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue

            # Flow control
            if opcode == 0x61:  # OP_NOP
                continue
            if opcode == 0x69:  # OP_VERIFY
                if not stack:
                    raise ValueError("OP_VERIFY: stack underflow")
                if not self._cast_to_bool(stack.pop()):
                    raise ValueError("OP_VERIFY failed")
                continue
            if opcode == 0x6a:  # OP_RETURN
                raise ValueError("OP_RETURN encountered")

            # Reserved (fail when executed)
            if opcode in (0x50, 0x62, 0x89, 0x8a):
                raise ValueError(f"Reserved opcode 0x{opcode:02x}")

            # --- Stack manipulation ---
            if opcode == 0x6b:  # OP_TOALTSTACK
                if not stack:
                    raise ValueError("OP_TOALTSTACK: stack underflow")
                altstack.append(stack.pop())
                continue
            if opcode == 0x6c:  # OP_FROMALTSTACK
                if not altstack:
                    raise ValueError("OP_FROMALTSTACK: altstack empty")
                stack.append(altstack.pop())
                continue
            if opcode == 0x6d:  # OP_2DROP
                if len(stack) < 2:
                    raise ValueError("OP_2DROP: stack underflow")
                stack.pop()
                stack.pop()
                continue
            if opcode == 0x6e:  # OP_2DUP
                if len(stack) < 2:
                    raise ValueError("OP_2DUP: stack underflow")
                stack.extend(stack[-2:])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x6f:  # OP_3DUP
                if len(stack) < 3:
                    raise ValueError("OP_3DUP: stack underflow")
                stack.extend(stack[-3:])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x70:  # OP_2OVER
                if len(stack) < 4:
                    raise ValueError("OP_2OVER: stack underflow")
                stack.extend(stack[-4:-2])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x71:  # OP_2ROT
                if len(stack) < 6:
                    raise ValueError("OP_2ROT: stack underflow")
                pair = stack[-6:-4]
                del stack[-6:-4]
                stack.extend(pair)
                continue
            if opcode == 0x72:  # OP_2SWAP
                if len(stack) < 4:
                    raise ValueError("OP_2SWAP: stack underflow")
                stack[-4:] = stack[-2:] + stack[-4:-2]
                continue
            if opcode == 0x73:  # OP_IFDUP
                if not stack:
                    raise ValueError("OP_IFDUP: stack underflow")
                if self._cast_to_bool(stack[-1]):
                    stack.append(stack[-1])
                    if len(stack) + len(altstack) > MAX_STACK_SIZE:
                        raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x74:  # OP_DEPTH
                stack.append(self._encode_script_num(len(stack)))
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x75:  # OP_DROP
                if not stack:
                    raise ValueError("OP_DROP: stack underflow")
                stack.pop()
                continue
            if opcode == 0x76:  # OP_DUP
                if not stack:
                    raise ValueError("OP_DUP: stack underflow")
                stack.append(stack[-1])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x77:  # OP_NIP
                if len(stack) < 2:
                    raise ValueError("OP_NIP: stack underflow")
                del stack[-2]
                continue
            if opcode == 0x78:  # OP_OVER
                if len(stack) < 2:
                    raise ValueError("OP_OVER: stack underflow")
                stack.append(stack[-2])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue
            if opcode == 0x79:  # OP_PICK
                if not stack:
                    raise ValueError("OP_PICK: stack underflow")
                n = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if n < 0 or n >= len(stack):
                    raise ValueError("OP_PICK: index out of range")
                stack.append(stack[-(n + 1)])
                continue
            if opcode == 0x7a:  # OP_ROLL
                if not stack:
                    raise ValueError("OP_ROLL: stack underflow")
                n = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if n < 0 or n >= len(stack):
                    raise ValueError("OP_ROLL: index out of range")
                val = stack[-(n + 1)]
                del stack[-(n + 1)]
                stack.append(val)
                continue
            if opcode == 0x7b:  # OP_ROT
                if len(stack) < 3:
                    raise ValueError("OP_ROT: stack underflow")
                stack.append(stack[-3])
                del stack[-4]
                continue
            if opcode == 0x7c:  # OP_SWAP
                if len(stack) < 2:
                    raise ValueError("OP_SWAP: stack underflow")
                stack[-1], stack[-2] = stack[-2], stack[-1]
                continue
            if opcode == 0x7d:  # OP_TUCK
                if len(stack) < 2:
                    raise ValueError("OP_TUCK: stack underflow")
                stack.insert(-2, stack[-1])
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue

            # Splice
            if opcode == 0x82:  # OP_SIZE (does not pop)
                if not stack:
                    raise ValueError("OP_SIZE: stack underflow")
                stack.append(self._encode_script_num(len(stack[-1])))
                # MAX_STACK_SIZE enforced after the push, mirroring Core's
                # end-of-iteration check (interpreter.cpp:1221-1223): OP_SIZE
                # grows the stack and must fail at 1001 elements (1000 is OK).
                if len(stack) + len(altstack) > MAX_STACK_SIZE:
                    raise ValueError("Stack size exceeded")
                continue

            # Bitwise logic
            if opcode == 0x87:  # OP_EQUAL
                if len(stack) < 2:
                    raise ValueError("OP_EQUAL: stack underflow")
                a, b = stack.pop(), stack.pop()
                stack.append(b'\x01' if a == b else b'')
                continue
            if opcode == 0x88:  # OP_EQUALVERIFY
                if len(stack) < 2:
                    raise ValueError("OP_EQUALVERIFY: stack underflow")
                if stack.pop() != stack.pop():
                    raise ValueError("OP_EQUALVERIFY failed")
                continue

            # Arithmetic (unary)
            if opcode == 0x8b:  # OP_1ADD
                if not stack:
                    raise ValueError("OP_1ADD: stack underflow")
                stack.append(self._encode_script_num(self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA)) + 1))
                continue
            if opcode == 0x8c:  # OP_1SUB
                if not stack:
                    raise ValueError("OP_1SUB: stack underflow")
                stack.append(self._encode_script_num(self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA)) - 1))
                continue
            if opcode == 0x8f:  # OP_NEGATE
                if not stack:
                    raise ValueError("OP_NEGATE: stack underflow")
                stack.append(self._encode_script_num(-self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))))
                continue
            if opcode == 0x90:  # OP_ABS
                if not stack:
                    raise ValueError("OP_ABS: stack underflow")
                stack.append(self._encode_script_num(abs(self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA)))))
                continue
            if opcode == 0x91:  # OP_NOT
                if not stack:
                    raise ValueError("OP_NOT: stack underflow")
                stack.append(self._encode_script_num(int(self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA)) == 0)))
                continue
            if opcode == 0x92:  # OP_0NOTEQUAL
                if not stack:
                    raise ValueError("OP_0NOTEQUAL: stack underflow")
                stack.append(self._encode_script_num(int(self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA)) != 0)))
                continue

            # Arithmetic (binary)
            if opcode in (0x93, 0x94, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
                          0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4):
                if len(stack) < 2:
                    raise ValueError(f"Arithmetic opcode 0x{opcode:02x}: stack underflow")
                bn_b = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                bn_a = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if opcode == 0x93:    # OP_ADD
                    r = bn_a + bn_b
                elif opcode == 0x94:  # OP_SUB
                    r = bn_a - bn_b
                elif opcode == 0x9a:  # OP_BOOLAND
                    r = int(bn_a != 0 and bn_b != 0)
                elif opcode == 0x9b:  # OP_BOOLOR
                    r = int(bn_a != 0 or bn_b != 0)
                elif opcode == 0x9c:  # OP_NUMEQUAL
                    r = int(bn_a == bn_b)
                elif opcode == 0x9d:  # OP_NUMEQUALVERIFY
                    if bn_a != bn_b:
                        raise ValueError("OP_NUMEQUALVERIFY failed")
                    continue
                elif opcode == 0x9e:  # OP_NUMNOTEQUAL
                    r = int(bn_a != bn_b)
                elif opcode == 0x9f:  # OP_LESSTHAN
                    r = int(bn_a < bn_b)
                elif opcode == 0xa0:  # OP_GREATERTHAN
                    r = int(bn_a > bn_b)
                elif opcode == 0xa1:  # OP_LESSTHANOREQUAL
                    r = int(bn_a <= bn_b)
                elif opcode == 0xa2:  # OP_GREATERTHANOREQUAL
                    r = int(bn_a >= bn_b)
                elif opcode == 0xa3:  # OP_MIN
                    r = min(bn_a, bn_b)
                elif opcode == 0xa4:  # OP_MAX
                    r = max(bn_a, bn_b)
                else:
                    raise ValueError(f"Unknown arithmetic opcode 0x{opcode:02x}")
                stack.append(self._encode_script_num(r))
                continue

            if opcode == 0xa5:  # OP_WITHIN  (ternary: x min max)
                if len(stack) < 3:
                    raise ValueError("OP_WITHIN: stack underflow")
                mx = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                mn = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                x = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                stack.append(self._encode_script_num(int(mn <= x < mx)))
                continue

            # Crypto
            if opcode == 0xa6:  # OP_RIPEMD160
                if not stack:
                    raise ValueError("OP_RIPEMD160: stack underflow")
                stack.append(hashlib.new('ripemd160', stack.pop()).digest())
                continue
            if opcode == 0xa7:  # OP_SHA1
                if not stack:
                    raise ValueError("OP_SHA1: stack underflow")
                stack.append(hashlib.sha1(stack.pop()).digest())
                continue
            if opcode == 0xa8:  # OP_SHA256
                if not stack:
                    raise ValueError("OP_SHA256: stack underflow")
                stack.append(hashlib.sha256(stack.pop()).digest())
                continue
            if opcode == 0xa9:  # OP_HASH160
                if not stack:
                    raise ValueError("OP_HASH160: stack underflow")
                stack.append(self._hash160(stack.pop()))
                continue
            if opcode == 0xaa:  # OP_HASH256
                if not stack:
                    raise ValueError("OP_HASH256: stack underflow")
                stack.append(self._hash256(stack.pop()))
                continue

            # OP_CODESEPARATOR (0xab)
            # CONST_SCRIPTCODE check has already been applied above the fExec
            # gate (Core interpreter.cpp:474-476); here we just update state.
            #
            # Tapscript: also snapshot the 0-based opcode index so the
            # tapscript sighash extension block (interpreter.cpp:1564-1566)
            # commits to the right position. Without this every
            # CODESEPARATOR-using tapscript signed by the canonical bitcoin
            # ref impl would fail verification against ouroboros.
            if opcode == 0xab:
                script_code_start = i
                if is_tapscript:
                    codesep_pos = current_opcode_pos
                continue

            # Signature verification #
            if opcode == 0xac:  # OP_CHECKSIG
                if len(stack) < 2:
                    raise ValueError("OP_CHECKSIG: stack underflow")
                pubkey = stack.pop()
                sig = stack.pop()

                if is_tapscript:
                    # BIP 342 Schnorr CHECKSIG. Mirrors Core
                    # interpreter.cpp:347-385 (EvalChecksigTapscript).
                    #
                    # Order (consensus-critical):
                    #   1. success = !sig.empty()
                    #   2. if success: budget -= 50 (abort on negative)
                    #   3. if pubkey.empty(): TAPSCRIPT_EMPTY_PUBKEY  (ALWAYS)
                    #   4. elif pubkey.size() == 32: Schnorr verify (only if success)
                    #   5. else: DISCOURAGE_UPGRADABLE_PUBKEYTYPE check
                    #
                    # Notably step 3-5 fire even when sig is empty: an
                    # empty signature does NOT short-circuit past the
                    # empty-pubkey error or the upgradable-pubkey
                    # discouragement.
                    success = bool(sig)
                    if success:
                        sigops_budget -= 50
                        if sigops_budget < 0:
                            raise ValueError("Tapscript sigops budget exceeded")
                    if len(pubkey) == 0:
                        raise ValueError("OP_CHECKSIG: empty pubkey in tapscript")
                    if len(pubkey) != 32:
                        # Unknown pubkey type — Core's "upgradable public
                        # key version" branch (interpreter.cpp:373-382).
                        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                            raise ValueError(
                                "DISCOURAGE_UPGRADABLE_PUBKEYTYPE: "
                                "non-32-byte pubkey in tapscript"
                            )
                        # Forward-compat: push true on non-empty sig (would
                        # have been a real Schnorr success in a future
                        # softfork), push false on empty sig (success=false).
                        stack.append(b"\x01" if success else b"")
                        continue
                    if not success:
                        # 32-byte pubkey, empty sig: push false, no crypto.
                        stack.append(b"")
                        continue
                    sighash_type = 0x00
                    raw_sig = sig
                    if len(sig) == 65:
                        sighash_type = sig[-1]
                        raw_sig = sig[:-1]
                        if sighash_type == 0x00:
                            raise ValueError("OP_CHECKSIG: explicit 0x00 sighash in tapscript")
                    elif len(sig) != 64:
                        raise ValueError("OP_CHECKSIG: invalid Schnorr sig length")
                    if sighash_type != 0x00:
                        sh = self._compute_taproot_sighash(
                            tx, input_index, sighash_type,
                            input_amounts=input_amounts,
                            input_script_pubkeys=input_script_pubkeys,
                            annex=annex, ext_flag=1,
                            tap_leaf_hash=leaf_hash,
                            codesep_pos=codesep_pos,
                        )
                    else:
                        # SIGHASH_DEFAULT: callers may pre-compute the
                        # ext_flag=1 sighash without baking in the current
                        # codesep_pos.  If the script has actually executed
                        # an OP_CODESEPARATOR, recompute with the live pos
                        # so the BIP-342 §"sighash" commitment matches Core
                        # (interpreter.cpp:1565).
                        if codesep_pos != 0xFFFFFFFF:
                            sh = self._compute_taproot_sighash(
                                tx, input_index, 0x00,
                                input_amounts=input_amounts,
                                input_script_pubkeys=input_script_pubkeys,
                                annex=annex, ext_flag=1,
                                tap_leaf_hash=leaf_hash,
                                codesep_pos=codesep_pos,
                            )
                        else:
                            sh = default_sighash
                    # SCHNORR_SIG_HASHTYPE: invalid hashtype byte or
                    # SIGHASH_SINGLE-out-of-range (Core
                    # interpreter.cpp:1738) → script error.
                    if sh is None:
                        raise ValueError(
                            "OP_CHECKSIG: invalid Schnorr sighash type"
                        )
                    if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                        raise ValueError("OP_CHECKSIG: Schnorr verification failed")
                    stack.append(b"\x01")
                    continue

                # Legacy / SegWit v0 ECDSA CHECKSIG
                # Check signature encoding BEFORE checking for empty sig/pubkey
                # (Bitcoin Core checks DERSIG/STRICTENC first)
                # Core CheckSignatureEncoding: DER check fires when any of
                # DERSIG | LOW_S | STRICTENC is set (interpreter.cpp:207).
                if sig:
                    if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) and not _check_der_signature(sig):
                        raise ValueError("Non-DER signature")
                    der_sig_check = sig[:-1]
                    if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig_check):
                        raise ValueError("Non-low-S signature")
                    if (flags & SCRIPT_VERIFY_STRICTENC) and not _is_defined_hashtype(sig):
                        raise ValueError("STRICTENC: undefined hashtype")
                if (flags & SCRIPT_VERIFY_STRICTENC) and not _check_pubkey_encoding(pubkey):
                    raise ValueError("STRICTENC: invalid pubkey encoding")
                if is_witness_v0 and (flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) and not _check_compressed_pubkey(pubkey):
                    raise ValueError("WITNESS_PUBKEYTYPE: uncompressed pubkey in witness v0")
                if not sig:
                    stack.append(b'')
                    continue
                if len(pubkey) < 1:
                    if (flags & SCRIPT_VERIFY_NULLFAIL) and sig:
                        raise ValueError("NULLFAIL: non-empty sig for empty pubkey")
                    stack.append(b'')
                    continue
                der_sig = sig[:-1]
                sighash_type = sig[-1]
                # BIP143/legacy: scriptCode starts at the last executed
                # OP_CODESEPARATOR (script_code_start=0 if none has run).
                script_code = script[script_code_start:]
                try:
                    if is_witness_v0:
                        msg = self._compute_segwit_v0_sighash(
                            tx, input_index, script_code, witness_amount, sighash_type)
                    else:
                        # FindAndDelete: remove the signature from script
                        # code before hashing (legacy consensus rule).
                        # SCRIPT_VERIFY_CONST_SCRIPTCODE: if the signature is
                        # actually present in the scriptCode, reject — the
                        # scriptCode is supposed to be constant under the
                        # signature (Core interpreter.cpp:330-332).
                        cleaned, fad_found = self._find_and_delete_count(script_code, sig)
                        if fad_found > 0 and (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE):
                            raise ValueError("CONST_SCRIPTCODE: sig found in scriptCode (FindAndDelete)")
                        msg = self._calculate_signature_hash(
                            tx, input_index, cleaned, sighash_type)
                    ok = self._verify_ecdsa_signature(msg, der_sig, pubkey)
                    if not ok and (flags & SCRIPT_VERIFY_NULLFAIL):
                        raise ValueError("NULLFAIL: signature verification failed with non-empty sig")
                    # Per Bitcoin Core script.h: vchFalse is zero-length, vchTrue is single byte 0x01.
                    # Pushing b'\x00' would later trip MINIMALIF on patterns that branch on a
                    # CHECKSIG-produced false (e.g. multisig-fallthrough scripts).
                    stack.append(b'\x01' if ok else b'')
                except ValueError:
                    raise
                except Exception:
                    stack.append(b'')
                continue

            if opcode == 0xad:  # OP_CHECKSIGVERIFY
                if len(stack) < 2:
                    raise ValueError("OP_CHECKSIGVERIFY: stack underflow")
                pubkey = stack.pop()
                sig = stack.pop()

                if is_tapscript:
                    # BIP 342 CHECKSIGVERIFY = CHECKSIG + VERIFY.  Mirrors
                    # Core's EvalChecksigTapscript path
                    # (interpreter.cpp:347-385), then aborts if
                    # success=false.  Same ordering rules as CHECKSIG above:
                    # empty-pubkey error AND discourage-upgradable-pubkeytype
                    # check both fire even with empty sig.
                    success = bool(sig)
                    if success:
                        sigops_budget -= 50
                        if sigops_budget < 0:
                            raise ValueError("Tapscript sigops budget exceeded")
                    if len(pubkey) == 0:
                        raise ValueError(
                            "OP_CHECKSIGVERIFY: empty pubkey in tapscript"
                        )
                    if len(pubkey) != 32:
                        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                            raise ValueError(
                                "DISCOURAGE_UPGRADABLE_PUBKEYTYPE: "
                                "non-32-byte pubkey in tapscript"
                            )
                        # Forward-compat success — but CHECKSIGVERIFY still
                        # demands the underlying success=true, so an empty
                        # sig must fail here even with unknown pubkey type.
                        if not success:
                            raise ValueError(
                                "OP_CHECKSIGVERIFY failed in tapscript "
                                "(empty sig, upgradable pubkey)"
                            )
                        continue
                    if not success:
                        raise ValueError(
                            "OP_CHECKSIGVERIFY failed in tapscript (empty sig)"
                        )
                    sighash_type = 0x00
                    raw_sig = sig
                    if len(sig) == 65:
                        sighash_type = sig[-1]
                        raw_sig = sig[:-1]
                        if sighash_type == 0x00:
                            raise ValueError("Explicit 0x00 sighash in tapscript")
                    elif len(sig) != 64:
                        raise ValueError("Invalid Schnorr sig length")
                    if sighash_type == 0x00:
                        # SIGHASH_DEFAULT: recompute on the fly if a
                        # CODESEPARATOR has executed, so the position is
                        # committed (Core interpreter.cpp:1565).  No-op
                        # otherwise.
                        if codesep_pos != 0xFFFFFFFF:
                            sh = self._compute_taproot_sighash(
                                tx, input_index, 0x00,
                                input_amounts=input_amounts,
                                input_script_pubkeys=input_script_pubkeys,
                                annex=annex, ext_flag=1,
                                tap_leaf_hash=leaf_hash,
                                codesep_pos=codesep_pos,
                            )
                        else:
                            sh = default_sighash
                    else:
                        sh = self._compute_taproot_sighash(
                            tx, input_index, sighash_type,
                            input_amounts=input_amounts,
                            input_script_pubkeys=input_script_pubkeys,
                            annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                            codesep_pos=codesep_pos,
                        )
                    if sh is None:
                        raise ValueError(
                            "OP_CHECKSIGVERIFY: invalid Schnorr sighash type"
                        )
                    if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                        raise ValueError("OP_CHECKSIGVERIFY: Schnorr failed")
                    continue

                # Legacy / SegWit v0 ECDSA CHECKSIGVERIFY
                # Check encoding first (Bitcoin Core order).
                # Core CheckSignatureEncoding: DER check fires when any of
                # DERSIG | LOW_S | STRICTENC is set (interpreter.cpp:207).
                if sig:
                    if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) and not _check_der_signature(sig):
                        raise ValueError("Non-DER signature")
                    if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(sig[:-1]):
                        raise ValueError("Non-low-S signature")
                    if (flags & SCRIPT_VERIFY_STRICTENC) and not _is_defined_hashtype(sig):
                        raise ValueError("STRICTENC: undefined hashtype")
                if (flags & SCRIPT_VERIFY_STRICTENC) and not _check_pubkey_encoding(pubkey):
                    raise ValueError("STRICTENC: invalid pubkey encoding")
                if is_witness_v0 and (flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) and not _check_compressed_pubkey(pubkey):
                    raise ValueError("WITNESS_PUBKEYTYPE: uncompressed pubkey in witness v0")
                if not sig or len(pubkey) < 1:
                    raise ValueError("OP_CHECKSIGVERIFY failed")
                der_sig = sig[:-1]
                sighash_type = sig[-1]
                script_code = script[script_code_start:]
                try:
                    if is_witness_v0:
                        msg = self._compute_segwit_v0_sighash(
                            tx, input_index, script_code, witness_amount, sighash_type)
                    else:
                        # SCRIPT_VERIFY_CONST_SCRIPTCODE: reject if the sig is
                        # present in scriptCode (Core interpreter.cpp:330-332).
                        cleaned, fad_found = self._find_and_delete_count(script_code, sig)
                        if fad_found > 0 and (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE):
                            raise ValueError("CONST_SCRIPTCODE: sig found in scriptCode (FindAndDelete)")
                        msg = self._calculate_signature_hash(
                            tx, input_index, cleaned, sighash_type)
                    if not self._verify_ecdsa_signature(msg, der_sig, pubkey):
                        raise ValueError("OP_CHECKSIGVERIFY failed")
                except ValueError:
                    raise
                except Exception:
                    raise ValueError("OP_CHECKSIGVERIFY failed") from None
                continue

            # OP_CHECKSIGADD (0xba) — BIP 342, tapscript only
            if opcode == 0xba:
                if not is_tapscript:
                    raise ValueError("OP_CHECKSIGADD outside tapscript")
                if len(stack) < 3:
                    raise ValueError("OP_CHECKSIGADD: stack underflow")
                pubkey = stack.pop()
                # BIP-342: the `n` operand has a strict 4-byte numeric
                # bound (interpreter.cpp:1086-1094 — `CScriptNum(..., 4)`
                # constructor errors on >4 bytes).  Forwards-compatibility:
                # future soft-forks may widen the type.
                num_bytes = stack.pop()
                if len(num_bytes) > 4:
                    raise ValueError("OP_CHECKSIGADD: n is not a valid CScriptNum")
                # Core reads `n` as a signed CScriptNum (interpreter.cpp:1093:
                # `CScriptNum num(stacktop(-2), fRequireMinimal)`), NOT an
                # unsigned integer.  b'\x81' must decode to -1, not 129.
                n = self._read_signed_num(
                    num_bytes,
                    require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA),
                )
                sig = stack.pop()

                # BIP 342 CHECKSIGADD shares EvalChecksigTapscript with
                # CHECKSIG.  Same ordering rules — see CHECKSIG above for
                # the comment-block.
                success = bool(sig)
                if success:
                    sigops_budget -= 50
                    if sigops_budget < 0:
                        raise ValueError("Tapscript sigops budget exceeded")
                if len(pubkey) == 0:
                    raise ValueError("OP_CHECKSIGADD: empty pubkey in tapscript")
                if len(pubkey) != 32:
                    if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                        raise ValueError(
                            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE: "
                            "non-32-byte pubkey in tapscript"
                        )
                    # Forward-compat: push n+1 on non-empty sig (would have
                    # been a real Schnorr success), n unchanged on empty sig.
                    stack.append(
                        self._encode_script_num(n + 1 if success else n)
                    )
                    continue
                if not success:
                    stack.append(self._encode_script_num(n))
                    continue
                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]
                    raw_sig = sig[:-1]
                    if sighash_type == 0x00:
                        raise ValueError("Explicit 0x00 sighash in tapscript")
                elif len(sig) != 64:
                    raise ValueError("Invalid Schnorr sig length")
                if sighash_type == 0x00:
                    if codesep_pos != 0xFFFFFFFF:
                        sh = self._compute_taproot_sighash(
                            tx, input_index, 0x00,
                            input_amounts=input_amounts,
                            input_script_pubkeys=input_script_pubkeys,
                            annex=annex, ext_flag=1,
                            tap_leaf_hash=leaf_hash,
                            codesep_pos=codesep_pos,
                        )
                    else:
                        sh = default_sighash
                else:
                    sh = self._compute_taproot_sighash(
                        tx, input_index, sighash_type,
                        input_amounts=input_amounts,
                        input_script_pubkeys=input_script_pubkeys,
                        annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                        codesep_pos=codesep_pos,
                    )
                if sh is None:
                    raise ValueError(
                        "OP_CHECKSIGADD: invalid Schnorr sighash type"
                    )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    raise ValueError("OP_CHECKSIGADD: Schnorr failed")
                stack.append(self._encode_script_num(n + 1))
                continue

            if opcode == 0xae:  # OP_CHECKMULTISIG
                if is_tapscript:
                    raise ValueError("OP_CHECKMULTISIG disabled in tapscript")
                if len(stack) < 1:
                    raise ValueError("OP_CHECKMULTISIG: stack underflow")
                n = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if n < 0 or n > MAX_PUBKEYS_PER_MULTISIG:
                    raise ValueError("OP_CHECKMULTISIG n out of range")
                op_count += n
                if op_count > MAX_OPS_PER_SCRIPT:
                    raise ValueError("Too many operations")
                if len(stack) < n:
                    raise ValueError("OP_CHECKMULTISIG: stack underflow")
                pubkeys = [stack.pop() for _ in range(n)]
                if not stack:
                    raise ValueError("OP_CHECKMULTISIG: stack underflow")
                k = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if k < 0 or k > n:
                    raise ValueError("OP_CHECKMULTISIG k out of range")
                if len(stack) < k:
                    raise ValueError("OP_CHECKMULTISIG: stack underflow")
                sigs = [stack.pop() for _ in range(k)]
                if not stack:
                    raise ValueError("OP_CHECKMULTISIG: missing dummy")
                dummy = stack.pop()
                # BIP 147: NULLDUMMY - dummy element must be empty
                if (flags & SCRIPT_VERIFY_NULLDUMMY) and dummy:
                    raise ValueError("NULLDUMMY: dummy element is not empty")
                valid = self._verify_multisig(
                    sigs, pubkeys, k, tx, input_index, script[script_code_start:],
                    flags, is_witness_v0, witness_amount)
                if not valid and (flags & SCRIPT_VERIFY_NULLFAIL):
                    for s in sigs:
                        if s:
                            raise ValueError("NULLFAIL: non-empty sig in failed multisig")
                stack.append(b'\x01' if valid else b'')
                continue

            if opcode == 0xaf:  # OP_CHECKMULTISIGVERIFY
                if is_tapscript:
                    raise ValueError("OP_CHECKMULTISIGVERIFY disabled in tapscript")
                if not stack:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: stack underflow")
                n = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if n < 0 or n > MAX_PUBKEYS_PER_MULTISIG:
                    raise ValueError("OP_CHECKMULTISIGVERIFY n out of range")
                op_count += n
                if op_count > MAX_OPS_PER_SCRIPT:
                    raise ValueError("Too many operations")
                if len(stack) < n:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: stack underflow")
                pubkeys = [stack.pop() for _ in range(n)]
                if not stack:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: stack underflow")
                k = self._read_signed_num(stack.pop(), require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if k < 0 or k > n:
                    raise ValueError("OP_CHECKMULTISIGVERIFY k out of range")
                if len(stack) < k:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: stack underflow")
                sigs = [stack.pop() for _ in range(k)]
                if not stack:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: missing dummy")
                dummy = stack.pop()
                if (flags & SCRIPT_VERIFY_NULLDUMMY) and dummy:
                    raise ValueError("NULLDUMMY: dummy element is not empty")
                if not self._verify_multisig(
                    sigs, pubkeys, k, tx, input_index, script[script_code_start:],
                    flags, is_witness_v0, witness_amount):
                    raise ValueError("OP_CHECKMULTISIGVERIFY failed")
                continue

            # Timelocks (BIP 65 / BIP 112)
            if opcode == 0xb1:  # OP_CHECKLOCKTIMEVERIFY
                if not (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY):
                    # Treat as NOP2 when CLTV flag is not set
                    continue
                if not stack:
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: stack empty")
                lock_value = self._read_signed_num(stack[-1], max_len=5, require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if lock_value < 0:
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: negative locktime")
                LOCKTIME_THRESHOLD = 500_000_000
                tx_locktime = tx.locktime
                if not (
                    (tx_locktime < LOCKTIME_THRESHOLD and lock_value < LOCKTIME_THRESHOLD) or
                    (tx_locktime >= LOCKTIME_THRESHOLD and lock_value >= LOCKTIME_THRESHOLD)
                ):
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: locktime type mismatch")
                if lock_value > tx_locktime:
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: unsatisfied")
                if tx.inputs[input_index].sequence == 0xffffffff:
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: input is finalized")
                continue

            if opcode == 0xb2:  # OP_CHECKSEQUENCEVERIFY
                if not (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY):
                    # Treat as NOP3 when CSV flag is not set
                    continue
                if not stack:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: stack empty")
                lock_value = self._read_signed_num(stack[-1], max_len=5, require_minimal=bool(flags & SCRIPT_VERIFY_MINIMALDATA))
                if lock_value < 0:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: negative sequence")
                SEQ_DISABLE = 1 << 31
                SEQ_TYPE = 1 << 22
                SEQ_MASK = 0x0000ffff
                if lock_value & SEQ_DISABLE:
                    continue
                # Core stores nVersion as uint32_t and compares UNSIGNED:
                # ``if (txTo->nVersion < 2) return false;`` (interpreter.cpp:1790).
                # A Python/Rust signed i32 source would decode 0xFFFFFFFF as -1,
                # making the signed ``< 2`` check falsely reject a consensus-valid
                # spend.  Mask to uint32 semantics to match Core (BIP112 tx_valid
                # vector 165). Mirrors bip68_version_active() in validation.py but
                # inlined here to avoid a circular import (validation imports script).
                if (tx.version & 0xFFFFFFFF) < 2:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: tx version < 2")
                tx_seq = tx.inputs[input_index].sequence
                if tx_seq & SEQ_DISABLE:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: input disable flag set")
                mask = SEQ_TYPE | SEQ_MASK
                tx_masked = tx_seq & mask
                lock_masked = lock_value & mask
                if not (
                    (tx_masked < SEQ_TYPE and lock_masked < SEQ_TYPE) or
                    (tx_masked >= SEQ_TYPE and lock_masked >= SEQ_TYPE)
                ):
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: type mismatch")
                if lock_masked > tx_masked:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: unsatisfied")
                continue

            # Reserved NOPs
            if opcode in (0xb0, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9):
                if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                    raise ValueError(
                        f"DISCOURAGE_UPGRADABLE_NOPS: OP_NOP{opcode - 0xaf} "
                        f"(0x{opcode:02x})"
                    )
                continue

            raise ValueError(f"Unknown opcode 0x{opcode:02x}")

        if exec_stack:
            raise ValueError("Unbalanced OP_IF/OP_ENDIF")

        return stack

    @staticmethod
    def _cast_to_bool(data: bytes) -> bool:
        for idx in range(len(data)):
            if data[idx] != 0:
                if idx == len(data) - 1 and data[idx] == 0x80:
                    return False
                return True
        return False

    def _hash160(self, data: bytes) -> bytes:
        sha256_hash = hashlib.sha256(data).digest()
        return hashlib.new('ripemd160', sha256_hash).digest()

    def _hash256(self, data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def _read_num(self, data: bytes) -> int:
        if not data:
            return 0
        return int.from_bytes(data, 'little')

    def _read_signed_num(self, data: bytes, max_len: int = 4, require_minimal: bool = True) -> int:
        if not data:
            return 0
        if len(data) > max_len:
            raise ValueError(f"CScriptNum overflow ({len(data)} > {max_len})")

        # Minimal encoding check (always enforced by default, per Bitcoin Core CScriptNum)
        if require_minimal and len(data) > 0 and (data[-1] & 0x7f) == 0:
            if len(data) <= 1 or not (data[-2] & 0x80):
                raise ValueError("Non-minimal CScriptNum encoding")

        # Decode magnitude (little-endian, ignoring sign bit)
        result = int.from_bytes(data, 'little')
        if data[-1] & 0x80:
            # Negative: clear the sign bit and negate
            result &= ~(0x80 << ((len(data) - 1) * 8))
            result = -result
        return result

    def _encode_varint(self, value: int) -> bytes:
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')

    @staticmethod
    def _find_and_delete(script: bytes, sig: bytes) -> bytes:
        cleaned, _ = ScriptInterpreter._find_and_delete_count(script, sig)
        return cleaned

    @staticmethod
    def _find_and_delete_count(script: bytes, sig: bytes) -> tuple[bytes, int]:
        """
        Opcode-aligned FindAndDelete (mirrors Core interpreter.cpp:229-255).

        Builds `needle` = canonical push-serialisation of `sig`, then walks
        `script` opcode-by-opcode (GetOp-equivalent).  A needle occurrence is
        removed only when it begins exactly at an opcode boundary — bytes that
        happen to look like the needle but are embedded inside a larger push
        payload are NEVER matched.

        Reference: bitcoin-core/src/script/interpreter.cpp:229-255.
        """
        if not sig:
            return script, 0

        # Build the serialized push of the signature (needle).
        sig_len = len(sig)
        if sig_len < 0x4C:
            needle = bytes([sig_len]) + sig
        elif sig_len <= 0xFF:
            needle = bytes([0x4C, sig_len]) + sig
        elif sig_len <= 0xFFFF:
            needle = b"\x4d" + sig_len.to_bytes(2, "little") + sig
        else:
            needle = b"\x4e" + sig_len.to_bytes(4, "little") + sig

        needle_len = len(needle)
        script_len = len(script)
        result = bytearray()
        keep_start = 0
        pos = 0
        found = 0

        while pos < script_len:
            # --- opcode-boundary match (Core's inner while loop) ---
            while script_len - pos >= needle_len and \
                    script[pos:pos + needle_len] == needle:
                # Flush script[keep_start..pos] then skip over the needle.
                result.extend(script[keep_start:pos])
                pos += needle_len
                keep_start = pos
                found += 1

            # --- advance past the next opcode (Core's GetOp) ---
            if pos >= script_len:
                break
            op = script[pos]
            if op <= 0x4b:          # OP_0 (0) through OP_PUSHDATA direct (75)
                pos += 1 + op
            elif op == 0x4c:        # OP_PUSHDATA1: 1-byte length follows
                if pos + 1 >= script_len:
                    pos = script_len
                    break
                pos += 1 + 1 + script[pos + 1]
            elif op == 0x4d:        # OP_PUSHDATA2: 2-byte LE length follows
                if pos + 2 >= script_len:
                    pos = script_len
                    break
                pos += 1 + 2 + int.from_bytes(script[pos + 1:pos + 3], "little")
            elif op == 0x4e:        # OP_PUSHDATA4: 4-byte LE length follows
                if pos + 4 >= script_len:
                    pos = script_len
                    break
                pos += 1 + 4 + int.from_bytes(script[pos + 1:pos + 5], "little")
            else:
                pos += 1            # single-byte opcode (no data)

        if found > 0:
            result.extend(script[keep_start:])
            return bytes(result), found
        return script, 0

    def _calculate_signature_hash(
        self,
        transaction: Transaction,
        input_index: int,
        script_code: bytes,
        sighash_type: int
    ) -> bytes:
        """Calculate Bitcoin legacy SignatureHash for ECDSA verification."""
        # Strip OP_CODESEPARATOR (0xab) from script_code (FindAndDelete)
        # Must be opcode-aware: only remove standalone 0xab, not data push content
        cleaned = bytearray()
        pos = 0
        while pos < len(script_code):
            op = script_code[pos]
            if op == 0xab:  # OP_CODESEPARATOR - skip it
                pos += 1
                continue
            if op <= 0x4e:  # Data push opcodes
                if op == 0:
                    cleaned.append(op)
                    pos += 1
                elif op <= 75:
                    length = op
                    cleaned.extend(script_code[pos:pos + 1 + length])
                    pos += 1 + length
                elif op == 0x4c:  # OP_PUSHDATA1
                    if pos + 1 < len(script_code):
                        length = script_code[pos + 1]
                        cleaned.extend(script_code[pos:pos + 2 + length])
                        pos += 2 + length
                    else:
                        cleaned.append(op)
                        pos += 1
                elif op == 0x4d:  # OP_PUSHDATA2
                    if pos + 2 < len(script_code):
                        length = int.from_bytes(script_code[pos+1:pos+3], 'little')
                        cleaned.extend(script_code[pos:pos + 3 + length])
                        pos += 3 + length
                    else:
                        cleaned.append(op)
                        pos += 1
                elif op == 0x4e:  # OP_PUSHDATA4
                    if pos + 4 < len(script_code):
                        length = int.from_bytes(script_code[pos+1:pos+5], 'little')
                        cleaned.extend(script_code[pos:pos + 5 + length])
                        pos += 5 + length
                    else:
                        cleaned.append(op)
                        pos += 1
            else:
                cleaned.append(op)
                pos += 1
        script_code = bytes(cleaned)

        base_type = sighash_type & 0x1f
        anyone_can_pay = (sighash_type & 0x80) != 0

        data = bytearray()
        data.extend(transaction.version.to_bytes(4, 'little'))

        # Build inputs to serialize
        if anyone_can_pay:
            inputs_to_serialize = [(input_index, transaction.inputs[input_index])]
        else:
            inputs_to_serialize = list(enumerate(transaction.inputs))

        data.extend(self._encode_varint(len(inputs_to_serialize)))

        for i, tx_in in inputs_to_serialize:
            data.extend(tx_in.prev_txid)
            data.extend(tx_in.prev_vout.to_bytes(4, 'little'))
            if i == input_index:
                data.extend(self._encode_varint(len(script_code)))
                data.extend(script_code)
            else:
                data.extend(b'\x00')
            seq = 0 if base_type in (0x02, 0x03) and i != input_index else tx_in.sequence
            data.extend(seq.to_bytes(4, 'little'))

        if base_type == 0x02:  # SIGHASH_NONE
            data.extend(b'\x00')  # Zero outputs
        elif base_type == 0x03:  # SIGHASH_SINGLE
            if input_index >= len(transaction.outputs):
                return b'\x01' + b'\x00' * 31
            data.extend(self._encode_varint(input_index + 1))
            for j in range(input_index + 1):
                if j == input_index:
                    tx_out = transaction.outputs[j]
                    data.extend(tx_out.value.to_bytes(8, 'little'))
                    data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                    data.extend(tx_out.script_pubkey)
                else:
                    data.extend((-1).to_bytes(8, 'little', signed=True))
                    data.extend(b'\x00')
        else:  # SIGHASH_ALL (0x01) or any unknown type — default behavior
            data.extend(self._encode_varint(len(transaction.outputs)))
            for tx_out in transaction.outputs:
                data.extend(tx_out.value.to_bytes(8, 'little'))
                data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                data.extend(tx_out.script_pubkey)

        data.extend(transaction.locktime.to_bytes(4, 'little'))
        data.extend((sighash_type & 0xFFFFFFFF).to_bytes(4, 'little'))

        return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()

    @staticmethod
    def _lax_der_to_compact(der_sig: bytes, normalize_s: bool = True):
        """Parse a lax DER signature into 64-byte compact R||S format."""
        try:
            if len(der_sig) < 6:
                return None
            pos = 1  # skip SEQUENCE tag
            if der_sig[pos] & 0x80:
                pos += (der_sig[pos] & 0x7f) + 1
            else:
                pos += 1
            if pos >= len(der_sig) or der_sig[pos] != 0x02:
                return None
            pos += 1
            # R length — handle multi-byte length
            if der_sig[pos] & 0x80:
                num_len_bytes = der_sig[pos] & 0x7f
                pos += 1
                if pos + num_len_bytes > len(der_sig):
                    return None
                r_len = int.from_bytes(der_sig[pos:pos + num_len_bytes], 'big')
                pos += num_len_bytes
            else:
                r_len = der_sig[pos]
                pos += 1
            if pos + r_len > len(der_sig):
                return None
            r_bytes = der_sig[pos:pos + r_len]
            pos += r_len
            if pos >= len(der_sig) or der_sig[pos] != 0x02:
                return None
            pos += 1
            # S length — handle multi-byte length
            if pos >= len(der_sig):
                return None
            if der_sig[pos] & 0x80:
                num_len_bytes = der_sig[pos] & 0x7f
                pos += 1
                if pos + num_len_bytes > len(der_sig):
                    return None
                s_len = int.from_bytes(der_sig[pos:pos + num_len_bytes], 'big')
                pos += num_len_bytes
            else:
                s_len = der_sig[pos]
                pos += 1
            if pos + s_len > len(der_sig):
                return None
            s_bytes = der_sig[pos:pos + s_len]
            r_int = int.from_bytes(r_bytes, 'big') if r_bytes else 0
            s_int = int.from_bytes(s_bytes, 'big') if s_bytes else 0
            # Only normalize to low-S when requested (i.e. LOW_S flag is set)
            if normalize_s:
                order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                if s_int > order // 2:
                    s_int = order - s_int
            return r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big')
        except Exception:
            return None

    def _verify_ecdsa_signature(self, message_hash: bytes, der_sig: bytes, pubkey: bytes) -> bool:
        """Verify ECDSA signature using secp256k1 (Rust sync module or Python coincurve)."""
        if len(message_hash) != 32 or len(der_sig) < 1:
            return False
        if len(pubkey) not in (33, 65):
            return False

        # Try strict DER first (fast path via Rust sync or coincurve)
        try:
            import sync
            if sync.verify_ecdsa(der_sig, pubkey, message_hash):
                return True
            # Strict DER failed — fall through to lax parsing below
        except (ImportError, AttributeError, ValueError):
            pass
        else:
            # sync is available but returned False — try lax parsing via coincurve
            pass

        try:
            from coincurve import PublicKey
        except ImportError:
            return False

        # Invalid pubkeys (malformed encoding, not on curve) must return
        # False, not propagate.  Bitcoin Core's CPubKey::IsValid() check
        # does exactly this: CHECKSIG / CHECKMULTISIG get `false` and carry
        # on.  Counterparty-style fake pubkeys in bare-multisig outputs
        # rely on this to not wedge verification (block 851204 tx 26).
        try:
            pk = PublicKey(pubkey)
        except Exception:
            return False

        try:
            if pk.verify(der_sig, message_hash, hasher=None):
                return True
        except Exception:
            pass
        # Strict DER failed or returned False — try lax parsing
        # First try without S normalization (preserves original S)
        compact = self._lax_der_to_compact(der_sig, normalize_s=False)
        if compact is not None:
            try:
                from coincurve.ecdsa import cdata_to_der, deserialize_compact
                raw_sig = deserialize_compact(compact)
                canonical_der = cdata_to_der(raw_sig)
                if pk.verify(canonical_der, message_hash, hasher=None):
                    return True
            except Exception:
                pass
        # Try again with S normalization (for high-S sigs)
        compact_norm = self._lax_der_to_compact(der_sig, normalize_s=True)
        if compact_norm is not None and compact_norm != compact:
            try:
                from coincurve.ecdsa import cdata_to_der, deserialize_compact
                raw_sig2 = deserialize_compact(compact_norm)
                canonical_der2 = cdata_to_der(raw_sig2)
                if pk.verify(canonical_der2, message_hash, hasher=None):
                    return True
            except Exception:
                pass
        return False

    def _verify_multisig(
        self,
        sigs: list[bytes],
        pubkeys: list[bytes],
        k: int,
        tx: Transaction,
        input_index: int,
        script_pubkey: bytes,
        flags: int = SCRIPT_VERIFY_NONE,
        is_witness_v0: bool = False,
        witness_amount: int = 0,
    ) -> bool:
        """Verify k-of-n multisig."""
        if k == 0:
            return True
        if k > len(sigs) or k > len(pubkeys):
            return False

        script_code = script_pubkey

        # FindAndDelete: remove all signatures from script_code before hashing
        # (only for legacy, not witness v0).  Core does this per-signature and,
        # with SCRIPT_VERIFY_CONST_SCRIPTCODE, rejects if any sig is actually
        # present in scriptCode (interpreter.cpp:1142-1149).
        if not is_witness_v0:
            for sig in sigs:
                if sig:
                    script_code, fad_found = self._find_and_delete_count(script_code, sig)
                    if fad_found > 0 and (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE):
                        raise ValueError("CONST_SCRIPTCODE: sig found in scriptCode (FindAndDelete)")

        sig_idx = 0
        key_idx = 0
        matched = 0

        while sig_idx < len(sigs) and key_idx < len(pubkeys) and matched < k:
            sig = sigs[sig_idx]
            pubkey = pubkeys[key_idx]

            if len(sig) < 1:
                key_idx += 1
                continue

            # Core CheckSignatureEncoding: DER check fires when any of
            # DERSIG | LOW_S | STRICTENC is set (interpreter.cpp:207).
            if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) and not _check_der_signature(sig):
                raise ValueError("Non-DER signature")
            der_sig = sig[:-1]
            if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
                raise ValueError("Non-low-S signature")
            # STRICTENC hashtype: strip ANYONECANPAY (0x80) only; bits 5-6
            # must be zero (Core IsDefinedHashtypeSignature, interpreter.cpp:190-199).
            if (flags & SCRIPT_VERIFY_STRICTENC) and not _is_defined_hashtype(sig):
                raise ValueError("STRICTENC: undefined hashtype")
            if (flags & SCRIPT_VERIFY_STRICTENC) and not _check_pubkey_encoding(pubkey):
                raise ValueError("STRICTENC: invalid pubkey encoding")
            if is_witness_v0 and (flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) and not _check_compressed_pubkey(pubkey):
                raise ValueError("WITNESS_PUBKEYTYPE: uncompressed pubkey in witness v0")

            sighash_type = sig[-1]
            if is_witness_v0:
                message_hash = self._compute_segwit_v0_sighash(
                    tx, input_index, script_code, witness_amount, sighash_type)
            else:
                message_hash = self._calculate_signature_hash(
                    tx, input_index, script_code, sighash_type)
            if self._verify_ecdsa_signature(message_hash, der_sig, pubkey):
                sig_idx += 1
                matched += 1

            key_idx += 1

            # Early exit: if remaining keys < remaining sigs needed, give up
            sigs_remaining = k - matched
            keys_remaining = len(pubkeys) - key_idx
            if sigs_remaining > keys_remaining:
                break

        return matched == k

    # ------------------------------------------------------------------
    # Schnorr / Taproot (BIP 340, 341, 342)
    # ------------------------------------------------------------------

    def _verify_schnorr_signature(
        self, message_hash: bytes, signature: bytes, pubkey_x: bytes
    ) -> bool:
        """Verify a BIP-340 Schnorr signature.

        Reference:
            secp256k1/src/modules/schnorrsig/main_impl.h:224-270
                (``secp256k1_schnorrsig_verify``)
            BIP-340 §"Verification"

        Length gates per BIP-340:
          * signature: exactly 64 bytes (r || s)
          * pubkey:    exactly 32 bytes (x-only)
          * message:   exactly 32 bytes (TapSighash digest)

        The two underlying curve gates (``r < p`` for the field element and
        ``s < n`` for the scalar) and ``R != infinity`` / ``has_even_y(R)``
        are enforced inside libsecp256k1 (Rust fast path) or coincurve.

        Notes:
          * Calls the Rust accelerator ``crypto_verify_schnorr`` when present
            — historical bug: the Python wrapper used to invoke
            ``sync.verify_schnorr`` (wrong name → AttributeError) with the
            args in (msg, sig, pk) order; the fallback silently masked
            both, so the Rust fast path was dead. Fixed in W95.
          * Catches ``ValueError`` so malformed-input rejections from the
            Rust path map to ``False`` rather than raising — matches Core's
            ``secp256k1_schnorrsig_verify`` returning 0 for any pre-check
            failure (overflow, off-curve pubkey, …).
        """
        # BIP-340 length gates (all three must hold; defensive on msg too).
        if len(signature) != 64:
            return False
        if len(pubkey_x) != 32:
            return False
        if len(message_hash) != 32:
            return False

        # Fast path: rust-secp256k1 via the ferrous-utils ``sync`` module.
        try:
            import sync
            return sync.crypto_verify_schnorr(
                signature, pubkey_x, message_hash
            )
        except (ImportError, AttributeError):
            pass
        except ValueError:
            # Malformed sig / pubkey / msg — Rust raises, but BIP-340 verify
            # returns 0 in this case. Mirror that.
            return False

        # Fallback: pure-Python via coincurve.
        try:
            from coincurve import PublicKeyXOnly
            pk = PublicKeyXOnly(pubkey_x)
            return pk.verify(signature, message_hash)
        except ImportError:
            pass
        except Exception:
            return False

        return False

    def verify_taproot(
        self,
        tx: Transaction,
        input_index: int,
        witness: list[bytes],
        script_pubkey: bytes,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        flags: int = SCRIPT_VERIFY_NONE,
    ) -> bool:
        """
        Verify a Taproot (witness v1) spend.

        script_pubkey format: OP_1 <32-byte tweaked pubkey>
        Key-path: witness = [signature]
        Script-path: witness = [...inputs, script, control_block]

        Reference: BIP 341
        """
        if len(script_pubkey) != 34 or script_pubkey[0] != 0x51 or script_pubkey[1] != 0x20:
            return False

        output_pubkey = script_pubkey[2:]

        if not witness:
            return False

        # Annex detection: if last witness element starts with 0x50, it's the annex
        annex = None
        effective_witness = list(witness)
        if len(effective_witness) >= 2 and effective_witness[-1] and effective_witness[-1][0] == 0x50:
            annex = effective_witness.pop()

        if len(effective_witness) == 1:
            return self._verify_taproot_keypath(
                tx, input_index, effective_witness[0], output_pubkey,
                input_amounts, input_script_pubkeys, annex,
            )

        if len(effective_witness) >= 2:
            # Pass the ORIGINAL `witness` (annex INCLUDED) so the
            # BIP-342 validation-weight budget can be seeded from
            # ::GetSerializeSize(witness.stack) per Core's
            # interpreter.cpp:1981. effective_witness has the annex
            # popped, but Core's witness.stack does NOT.
            return self._verify_taproot_scriptpath(
                tx, input_index, effective_witness, output_pubkey,
                input_amounts, input_script_pubkeys, annex, flags,
                full_witness=witness,
            )

        return False

    def _verify_taproot_keypath(
        self,
        tx: Transaction,
        input_index: int,
        sig_element: bytes,
        output_pubkey: bytes,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        annex: bytes | None = None,
    ) -> bool:
        """Key-path spend: witness is a single Schnorr signature (64 or 65 bytes)."""
        sighash_type = 0x00
        sig = sig_element
        if len(sig) == 65:
            sighash_type = sig[-1]
            sig = sig[:-1]
            if sighash_type == 0x00:
                return False  # explicit 0x00 is invalid per BIP 341
        elif len(sig) != 64:
            return False

        sighash = self._compute_taproot_sighash(
            tx, input_index, sighash_type,
            input_amounts=input_amounts,
            input_script_pubkeys=input_script_pubkeys,
            annex=annex,
            ext_flag=0,
        )
        # Invalid hashtype byte or SIGHASH_SINGLE-out-of-range — Core
        # would surface SCRIPT_ERR_SCHNORR_SIG_HASHTYPE; we treat as
        # verification failure.
        if sighash is None:
            return False
        return self._verify_schnorr_signature(sighash, sig, output_pubkey)

    def _verify_taproot_scriptpath(
        self,
        tx: Transaction,
        input_index: int,
        witness: list[bytes],
        output_pubkey: bytes,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        annex: bytes | None = None,
        flags: int = SCRIPT_VERIFY_NONE,
        full_witness: list[bytes] | None = None,
    ) -> bool:
        """Script-path spend: witness = [...script_inputs, tapscript, control_block].

        `full_witness`, if supplied, is the ORIGINAL pre-strip witness stack
        (annex INCLUDED). Used to seed the BIP-342 validation-weight budget
        via ::GetSerializeSize(witness.stack) per Core's interpreter.cpp:1981.
        """
        if len(witness) < 2:
            return False

        control_block = witness[-1]
        tap_script = witness[-2]
        script_inputs = witness[:-2]

        # BIP-341 control-block geometry (interpreter.cpp:1970):
        #   size in [33, 33 + 32*128] = [33, 4129], with (size - 33) % 32 == 0.
        # The upper bound enforces the 128-deep Merkle path limit; without
        # it an attacker can craft an arbitrarily-large control block to
        # burn validator CPU on the Merkle walk before the tweak check fails.
        if (
            len(control_block) < TAPROOT_CONTROL_BASE_SIZE
            or len(control_block) > TAPROOT_CONTROL_MAX_SIZE
            or ((len(control_block) - TAPROOT_CONTROL_BASE_SIZE)
                % TAPROOT_CONTROL_NODE_SIZE) != 0
        ):
            return False

        leaf_version = control_block[0] & 0xfe
        internal_key = control_block[1:33]
        merkle_path = control_block[33:]

        # Compute tapleaf hash
        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([leaf_version]) + self._ser_script_size(tap_script) + tap_script,
        )

        # Walk up the Merkle path
        k = leaf_hash
        for i in range(0, len(merkle_path), 32):
            branch = merkle_path[i:i + 32]
            if k < branch:
                k = _tagged_hash("TapBranch", k + branch)
            else:
                k = _tagged_hash("TapBranch", branch + k)

        # Compute the tweaked key: P + hash(P || root) * G
        tweak = _tagged_hash("TapTweak", internal_key + k)

        tweaked = self._taproot_tweak_pubkey(internal_key, tweak)
        if tweaked is None:
            return False

        # The y-parity of the output key must match control_block[0] & 1
        tweaked_x, tweaked_parity = tweaked
        if tweaked_x != output_pubkey:
            return False
        if (control_block[0] & 1) != tweaked_parity:
            return False

        # Execute the tapscript (BIP 342) via the unified interpreter
        if leaf_version == 0xc0:
            sighash = self._compute_taproot_sighash(
                tx, input_index, 0x00,
                input_amounts=input_amounts,
                input_script_pubkeys=input_script_pubkeys,
                annex=annex,
                ext_flag=1,
                tap_leaf_hash=leaf_hash,
            )
            # BIP-342 validation-weight budget seed (interpreter.cpp:1981):
            #   m_validation_weight_left = ::GetSerializeSize(witness.stack)
            #                              + VALIDATION_WEIGHT_OFFSET (50)
            # `witness.stack` is the ORIGINAL pre-pop stack (annex INCLUDED,
            # control block + script INCLUDED, args INCLUDED). We pass
            # `full_witness` (ouroboros's pre-strip name); fall back to
            # post-strip `witness` if a caller didn't thread it.
            #
            # Note: `_execute_script` adds the +50 OFFSET itself; what we
            # compute here is the GetSerializeSize portion only, so the
            # naming `witness_weight` is now a slight misnomer — it's the
            # serialized size of the witness stack, including compact-size
            # prefixes for the count and per-item lengths.
            stack_for_budget = full_witness if full_witness is not None else witness
            w_weight = self._serialized_witness_stack_size(stack_for_budget)
            try:
                result_stack = self._execute_script(
                    tap_script,
                    tx,
                    input_index,
                    tap_script,  # script_pubkey (not used for tapscript sighash)
                    flags=flags,
                    initial_stack=list(script_inputs),
                    sig_version=SigVersion.TAPSCRIPT,
                    input_amounts=input_amounts,
                    input_script_pubkeys=input_script_pubkeys,
                    annex=annex,
                    leaf_hash=leaf_hash,
                    default_sighash=sighash,
                    witness_weight=w_weight,
                )
            except (ValueError, Exception):
                return False
            # Core interpreter.cpp:1866-1868 ExecuteWitnessScript:
            #   if (stack.size() != 1) return SCRIPT_ERR_CLEANSTACK;
            #   if (!CastToBool(stack.back())) return SCRIPT_ERR_EVAL_FALSE;
            if len(result_stack) != 1:
                return False
            return self._cast_to_bool(result_stack[-1])

        # DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: reject unknown leaf versions
        # when this policy flag is set (for relay/mempool).
        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION:
            return False

        # BIP 341: unknown leaf versions succeed unconditionally in consensus.
        # This ensures forward compatibility — future soft-forks can define new
        # leaf versions without old nodes rejecting blocks that use them.
        return True

    def _taproot_tweak_pubkey(
        self, internal_key: bytes, tweak: bytes
    ) -> tuple[bytes, int] | None:
        """Apply BIP-341 TapTweak to an x-only pubkey.

        Returns ``(tweaked_pubkey_x, parity)`` or ``None`` on failure.

        Note: the historical code had a second fallback to
        ``sync.taproot_tweak_pubkey``, but ferrous-utils ``sync`` does not
        export that symbol — the AttributeError was silently caught and the
        function returned None, so the fallback was a no-op. Removed in W95
        to make the data flow explicit.
        """
        try:
            from coincurve import PublicKeyXOnly
            pk = PublicKeyXOnly(internal_key)
            pk.tweak_add(tweak)  # mutates in-place, sets pk.parity
            return pk.format(), int(pk.parity)
        except ImportError:
            return None
        except Exception:
            return None

    def _ser_script_size(self, script: bytes) -> bytes:
        n = len(script)
        if n < 0xFD:
            return struct.pack('<B', n)
        elif n <= 0xFFFF:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xFFFFFFFF:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)

    @staticmethod
    def _compact_size_len(n: int) -> int:
        """Byte length of a Bitcoin compact-size encoding for ``n``.

        Mirrors Core's GetSizeOfCompactSize (serialize.h):
            < 0xfd            -> 1 byte
            <= 0xffff         -> 3 bytes (0xfd || u16)
            <= 0xffffffff     -> 5 bytes (0xfe || u32)
            else              -> 9 bytes (0xff || u64)
        """
        if n < 0xfd:
            return 1
        if n <= 0xffff:
            return 3
        if n <= 0xffffffff:
            return 5
        return 9

    @classmethod
    def _serialized_witness_stack_size(cls, items: list[bytes]) -> int:
        """Serialized byte-size of a witness stack, the way Core counts it.

        Mirrors ``::GetSerializeSize(witness.stack)``: a compact-size item
        count followed by, for each item, its compact-size length prefix
        and the item bytes themselves. Used to seed the BIP-342 tapscript
        validation-weight budget at the leaf entry point.
        """
        total = cls._compact_size_len(len(items))
        for it in items:
            total += cls._compact_size_len(len(it)) + len(it)
        return total

    def _compute_taproot_sighash(
        self,
        tx: Transaction,
        input_index: int,
        sighash_type: int,
        *,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        annex: bytes | None = None,
        ext_flag: int = 0,
        tap_leaf_hash: bytes | None = None,
        codesep_pos: int = 0xFFFFFFFF,
    ) -> bytes | None:
        """Compute the signature hash for a Taproot spend (BIP 341 §4).

        Returns the 32-byte TapSighash digest, or ``None`` if the inputs
        violate a BIP-341 §"Common signature message" constraint.  Mirrors
        Core's ``SignatureHashSchnorr`` (interpreter.cpp:1483-1570), which
        returns ``false`` rather than throwing so the caller can map it to
        ``SCRIPT_ERR_SCHNORR_SIG_HASHTYPE``.
        """
        # BIP-341: valid hash_type values are SIGHASH_DEFAULT (0x00),
        # SIGHASH_{ALL,NONE,SINGLE} (0x01..0x03), and their ANYONECANPAY
        # variants (0x81..0x83). Any other byte is invalid and Core
        # rejects via SCRIPT_ERR_SCHNORR_SIG_HASHTYPE
        # (interpreter.cpp:1516).
        if not (sighash_type <= 0x03
                or (0x81 <= sighash_type <= 0x83)):
            return None

        # Determine hash type components
        anyone_can_pay = (sighash_type & 0x80) != 0
        base_type = sighash_type & 0x03  # 0=default/all, 1=all, 2=none, 3=single
        if sighash_type == 0:
            base_type = 0  # SIGHASH_DEFAULT = SIGHASH_ALL

        data = bytearray()

        # Epoch (0x00)
        data.append(0x00)

        # Hash type
        data.append(sighash_type)

        # Transaction data
        data.extend(struct.pack('<i', tx.version))
        data.extend(struct.pack('<I', tx.locktime))

        if not anyone_can_pay:
            # sha_prevouts: SHA256 of all outpoints
            prevouts = bytearray()
            for inp in tx.inputs:
                prevouts.extend(inp.prev_txid)
                prevouts.extend(struct.pack('<I', inp.prev_vout))
            data.extend(hashlib.sha256(bytes(prevouts)).digest())

            # sha_amounts: SHA256 of all input amounts
            if input_amounts:
                amounts = bytearray()
                for amt in input_amounts:
                    amounts.extend(struct.pack('<q', amt))
                data.extend(hashlib.sha256(bytes(amounts)).digest())
            else:
                data.extend(b'\x00' * 32)

            # sha_scriptpubkeys: SHA256 of all input scriptPubKeys (compact-size prefixed)
            if input_script_pubkeys:
                spks = bytearray()
                for spk in input_script_pubkeys:
                    spks.extend(self._ser_script_size(spk))
                    spks.extend(spk)
                data.extend(hashlib.sha256(bytes(spks)).digest())
            else:
                data.extend(b'\x00' * 32)

            # sha_sequences: SHA256 of all sequences
            seqs = bytearray()
            for inp in tx.inputs:
                seqs.extend(struct.pack('<I', inp.sequence))
            data.extend(hashlib.sha256(bytes(seqs)).digest())

        if base_type not in (2, 3):  # not NONE and not SINGLE
            # sha_outputs: SHA256 of all outputs
            outs = bytearray()
            for out in tx.outputs:
                outs.extend(struct.pack('<q', out.value))
                outs.extend(self._ser_script_size(out.script_pubkey))
                outs.extend(out.script_pubkey)
            data.extend(hashlib.sha256(bytes(outs)).digest())

        # Spend type: (ext_flag << 1) | annex_present
        annex_present = 1 if annex else 0
        spend_type = (ext_flag << 1) | annex_present
        data.append(spend_type)

        if anyone_can_pay:
            inp = tx.inputs[input_index]
            data.extend(inp.prev_txid)
            data.extend(struct.pack('<I', inp.prev_vout))
            if input_amounts and input_index < len(input_amounts):
                data.extend(struct.pack('<q', input_amounts[input_index]))
            else:
                data.extend(struct.pack('<q', 0))
            if input_script_pubkeys and input_index < len(input_script_pubkeys):
                spk = input_script_pubkeys[input_index]
                data.extend(self._ser_script_size(spk))
                data.extend(spk)
            else:
                data.extend(b'\x00')
            data.extend(struct.pack('<I', inp.sequence))
        else:
            data.extend(struct.pack('<I', input_index))

        if annex:
            data.extend(hashlib.sha256(
                self._ser_script_size(annex) + annex
            ).digest())

        if base_type == 2:  # SIGHASH_NONE
            pass
        elif base_type == 3:  # SIGHASH_SINGLE
            # BIP-341: SIGHASH_SINGLE with in_pos >= vout.size() is invalid
            # (Core interpreter.cpp:1550 returns false; not the legacy
            # "uint256(1)" bug). Surface as None so the caller can flag
            # SCRIPT_ERR_SCHNORR_SIG_HASHTYPE.  Note that legacy SegWit-v0
            # SIGHASH_SINGLE-out-of-range *does* sign the all-ones hash for
            # historical reasons, but Taproot picked the saner semantics.
            if input_index >= len(tx.outputs):
                return None
            out = tx.outputs[input_index]
            out_data = (
                struct.pack('<q', out.value)
                + self._ser_script_size(out.script_pubkey)
                + out.script_pubkey
            )
            data.extend(hashlib.sha256(out_data).digest())

        # Extension (script path)
        if ext_flag == 1 and tap_leaf_hash:
            data.extend(tap_leaf_hash)
            data.append(0x00)  # key_version
            # BIP-341: codesep_pos is the 0-based opcode index of the last
            # executed OP_CODESEPARATOR, or 0xFFFFFFFF if none has fired.
            # Core writes `execdata.m_codeseparator_pos` as uint32 LE
            # (interpreter.cpp:1565).  Must use unsigned uint32, not signed int.
            data.extend(struct.pack('<I', codesep_pos & 0xFFFFFFFF))

        return _tagged_hash("TapSighash", bytes(data))

    def _execute_tapscript(
        self,
        script: bytes,
        witness_inputs: list[bytes],
        tx: Transaction,
        input_index: int,
        default_sighash: bytes,
        input_amounts: list[int] | None = None,
        input_script_pubkeys: list[bytes] | None = None,
        annex: bytes | None = None,
        leaf_hash: bytes | None = None,
    ) -> bool:
        """Execute a tapscript (BIP 342)."""
        stack: list[bytes] = list(witness_inputs)
        op_count = 0
        max_ops = 201
        # BIP-341/342: 0-based opcode index counter, committed to the tapscript
        # sigmsg when OP_CODESEPARATOR is encountered.  Mirrors Core's
        # `opcode_pos` (interpreter.cpp:433, incremented at the top of the
        # for-loop, so the first opcode sees opcode_pos=0).
        # Initialized to 0xFFFFFFFF (sentinel = no CODESEPARATOR executed).
        codesep_pos: int = 0xFFFFFFFF
        opcode_pos: int = 0

        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1
            # Capture the 0-based index of this opcode, then advance.
            # Placed before any `continue` so push-data ops also advance it,
            # matching Core's unconditional `++opcode_pos`.
            current_opcode_pos = opcode_pos
            opcode_pos += 1
            op_count += 1
            if op_count > max_ops:
                return False

            # Data pushes
            if 1 <= opcode <= 75:
                if i + opcode > len(script):
                    return False
                stack.append(script[i:i + opcode])
                i += opcode
                continue
            if opcode == 0x4c:  # OP_PUSHDATA1
                if i >= len(script):
                    return False
                dlen = script[i]
                i += 1
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen])
                i += dlen
                continue
            if opcode == 0x4d:  # OP_PUSHDATA2
                if i + 2 > len(script):
                    return False
                dlen = int.from_bytes(script[i:i+2], 'little')
                i += 2
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen])
                i += dlen
                continue

            if opcode == 0x00:  # OP_0
                stack.append(b'')
                continue
            if 0x51 <= opcode <= 0x60:  # OP_1 .. OP_16
                stack.append(bytes([opcode - 0x50]))
                continue

            # OP_DUP
            if opcode == 0x76:
                if not stack:
                    return False
                stack.append(stack[-1])
                continue
            # OP_DROP
            if opcode == 0x75:
                if not stack:
                    return False
                stack.pop()
                continue
            # OP_EQUAL
            if opcode == 0x87:
                if len(stack) < 2:
                    return False
                a, b = stack.pop(), stack.pop()
                stack.append(b'\x01' if a == b else b'')
                continue
            # OP_EQUALVERIFY
            if opcode == 0x88:
                if len(stack) < 2:
                    return False
                if stack.pop() != stack.pop():
                    return False
                continue
            # OP_HASH160
            if opcode == 0xa9:
                if not stack:
                    return False
                stack.append(self._hash160(stack.pop()))
                continue

            # OP_CODESEPARATOR in tapscript (0xab) — BIP 342
            if opcode == 0xab:
                # Record the 0-based opcode index for the tapscript sigmsg.
                # Mirrors Core: `execdata.m_codeseparator_pos = opcode_pos`
                # (interpreter.cpp:1055), committed at interpreter.cpp:1565.
                # CONST_SCRIPTCODE does NOT apply in tapscript (only BASE).
                codesep_pos = current_opcode_pos
                continue

            # OP_CHECKSIG — Schnorr in tapscript
            if opcode == 0xac:
                if len(stack) < 2:
                    return False
                pubkey = stack.pop()
                sig = stack.pop()
                if not sig:
                    stack.append(b'')
                    continue
                if len(pubkey) == 32:
                    sighash_type = 0x00
                    raw_sig = sig
                    if len(sig) == 65:
                        sighash_type = sig[-1]
                        raw_sig = sig[:-1]
                        if sighash_type == 0x00:
                            return False
                    elif len(sig) != 64:
                        return False

                    if sighash_type != 0x00:
                        sighash = self._compute_taproot_sighash(
                            tx, input_index, sighash_type,
                            input_amounts=input_amounts,
                            input_script_pubkeys=input_script_pubkeys,
                            annex=annex,
                            ext_flag=1,
                            tap_leaf_hash=leaf_hash,
                            codesep_pos=codesep_pos,
                        )
                    else:
                        # SIGHASH_DEFAULT: recompute if OP_CODESEPARATOR has
                        # fired (codesep_pos changed from sentinel 0xFFFFFFFF),
                        # since default_sighash was pre-computed with the
                        # sentinel value.  This matches Core: the sighash
                        # is computed on-demand with the live codesep_pos.
                        if codesep_pos == 0xFFFFFFFF:
                            sighash = default_sighash
                        else:
                            sighash = self._compute_taproot_sighash(
                                tx, input_index, 0x00,
                                input_amounts=input_amounts,
                                input_script_pubkeys=input_script_pubkeys,
                                annex=annex,
                                ext_flag=1,
                                tap_leaf_hash=leaf_hash,
                                codesep_pos=codesep_pos,
                            )

                    if not self._verify_schnorr_signature(sighash, raw_sig, pubkey):
                        return False
                    stack.append(b'\x01')
                else:
                    return False
                continue

            # OP_CHECKSIGVERIFY
            if opcode == 0xad:
                if len(stack) < 2:
                    return False
                pubkey = stack.pop()
                sig = stack.pop()
                if len(pubkey) != 32 or not sig:
                    return False
                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]
                    raw_sig = sig[:-1]
                    if sighash_type == 0x00:
                        return False
                elif len(sig) != 64:
                    return False
                if sighash_type == 0x00:
                    sh = default_sighash if codesep_pos == 0xFFFFFFFF else self._compute_taproot_sighash(
                        tx, input_index, 0x00,
                        input_amounts=input_amounts,
                        input_script_pubkeys=input_script_pubkeys,
                        annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                        codesep_pos=codesep_pos,
                    )
                else:
                    sh = self._compute_taproot_sighash(
                        tx, input_index, sighash_type,
                        input_amounts=input_amounts,
                        input_script_pubkeys=input_script_pubkeys,
                        annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                        codesep_pos=codesep_pos,
                    )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    return False
                continue

            # OP_CHECKSIGADD (0xba) — BIP 342
            if opcode == 0xba:
                if len(stack) < 3:
                    return False
                pubkey = stack.pop()
                n = self._read_num(stack.pop())
                sig = stack.pop()

                if not sig:
                    stack.append(self._encode_script_num(n))
                    continue
                if len(pubkey) != 32:
                    return False

                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]
                    raw_sig = sig[:-1]
                    if sighash_type == 0x00:
                        return False
                elif len(sig) != 64:
                    return False

                if sighash_type == 0x00:
                    sh = default_sighash if codesep_pos == 0xFFFFFFFF else self._compute_taproot_sighash(
                        tx, input_index, 0x00,
                        input_amounts=input_amounts,
                        input_script_pubkeys=input_script_pubkeys,
                        annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                        codesep_pos=codesep_pos,
                    )
                else:
                    sh = self._compute_taproot_sighash(
                        tx, input_index, sighash_type,
                        input_amounts=input_amounts,
                        input_script_pubkeys=input_script_pubkeys,
                        annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                        codesep_pos=codesep_pos,
                    )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    return False
                stack.append(self._encode_script_num(n + 1))
                continue

            # OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY are disabled in tapscript
            if opcode in (0xae, 0xaf):
                return False

            # OP_SUCCESS range: opcodes 80, 98, 126-129, 131-134, 137-138,
            # 141-142, 149-153, 187-254 — the script succeeds unconditionally
            if opcode in _TAPSCRIPT_OP_SUCCESS:
                return True

        if not stack:
            return False
        top = stack[-1]
        if isinstance(top, bytes):
            return len(top) > 0 and any(b != 0 for b in top)
        return bool(top)

    def _encode_script_num(self, n: int) -> bytes:
        if n == 0:
            return b''
        negative = n < 0
        absn = abs(n)
        result = bytearray()
        while absn > 0:
            result.append(absn & 0xFF)
            absn >>= 8
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        return bytes(result)


# Opcodes that trigger OP_SUCCESS in tapscript (BIP 342).
_TAPSCRIPT_OP_SUCCESS = frozenset(
    [80, 98]
    + list(range(126, 130))
    + list(range(131, 135))
    + [137, 138, 141, 142]
    + list(range(149, 154))
    + list(range(187, 255))
)


def disassemble_script(script: bytes) -> str:
    """
    Disassemble Bitcoin script to human-readable ASM format.

    Args:
        script: Script bytes

    Returns:
        Human-readable script assembly (e.g., "OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG")
    """
    if not script:
        return ""

    asm_parts = []
    i = 0

    while i < len(script):
        opcode = script[i]
        i += 1

        # Data push opcodes
        if opcode == 0x00:
            asm_parts.append("OP_0")
        elif 0x01 <= opcode <= 0x4b:
            # Direct push
            data_len = opcode
            if i + data_len > len(script):
                asm_parts.append("[error]")
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4c:  # OP_PUSHDATA1
            if i >= len(script):
                asm_parts.append("[error]")
                break
            data_len = script[i]
            i += 1
            if i + data_len > len(script):
                asm_parts.append("[error]")
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4d:  # OP_PUSHDATA2
            if i + 1 >= len(script):
                asm_parts.append("[error]")
                break
            data_len = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + data_len > len(script):
                asm_parts.append("[error]")
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4e:  # OP_PUSHDATA4
            if i + 3 >= len(script):
                asm_parts.append("[error]")
                break
            data_len = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + data_len > len(script):
                asm_parts.append("[error]")
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        else:
            # Opcode name
            opcode_name = _get_opcode_name(opcode)
            asm_parts.append(opcode_name)

    return " ".join(asm_parts)


def _get_opcode_name(opcode: int) -> str:
    """Get opcode name from opcode value"""
    opcode_names = {
        0x00: "OP_0",
        0x4f: "OP_1NEGATE",
        0x51: "OP_1", 0x52: "OP_2", 0x53: "OP_3", 0x54: "OP_4",
        0x55: "OP_5", 0x56: "OP_6", 0x57: "OP_7", 0x58: "OP_8",
        0x59: "OP_9", 0x5a: "OP_10", 0x5b: "OP_11", 0x5c: "OP_12",
        0x5d: "OP_13", 0x5e: "OP_14", 0x5f: "OP_15", 0x60: "OP_16",
        0x61: "OP_NOP",
        0x63: "OP_IF", 0x64: "OP_NOTIF",
        0x67: "OP_ELSE", 0x68: "OP_ENDIF",
        0x69: "OP_VERIFY", 0x6a: "OP_RETURN",
        0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK",
        0x6d: "OP_2DROP", 0x6e: "OP_2DUP", 0x6f: "OP_3DUP",
        0x70: "OP_2OVER", 0x71: "OP_2ROT", 0x72: "OP_2SWAP",
        0x73: "OP_IFDUP", 0x74: "OP_DEPTH",
        0x75: "OP_DROP", 0x76: "OP_DUP",
        0x77: "OP_NIP", 0x78: "OP_OVER",
        0x79: "OP_PICK", 0x7a: "OP_ROLL",
        0x7b: "OP_ROT", 0x7c: "OP_SWAP", 0x7d: "OP_TUCK",
        0x82: "OP_SIZE",
        0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
        0x8b: "OP_1ADD", 0x8c: "OP_1SUB",
        0x8f: "OP_NEGATE", 0x90: "OP_ABS",
        0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
        0x93: "OP_ADD", 0x94: "OP_SUB",
        0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR",
        0x9c: "OP_NUMEQUAL", 0x9d: "OP_NUMEQUALVERIFY",
        0x9e: "OP_NUMNOTEQUAL",
        0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
        0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
        0xa3: "OP_MIN", 0xa4: "OP_MAX", 0xa5: "OP_WITHIN",
        0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1",
        0xa8: "OP_SHA256", 0xa9: "OP_HASH160", 0xaa: "OP_HASH256",
        0xab: "OP_CODESEPARATOR",
        0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
        0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
        0xb0: "OP_NOP1",
        0xb1: "OP_CHECKLOCKTIMEVERIFY",
        0xb2: "OP_CHECKSEQUENCEVERIFY",
        0xb3: "OP_NOP4", 0xb4: "OP_NOP5", 0xb5: "OP_NOP6",
        0xb6: "OP_NOP7", 0xb7: "OP_NOP8",
        0xb8: "OP_NOP9", 0xb9: "OP_NOP10",
        0xba: "OP_CHECKSIGADD",
    }
    return opcode_names.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
