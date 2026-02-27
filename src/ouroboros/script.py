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
from typing import List, Tuple, Optional
from dataclasses import dataclass

from ouroboros.database import Transaction, TxIn


# ---------------------------------------------------------------------------
# Script verification flags (matching Bitcoin Core src/script/interpreter.h)
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

# Maximum push data size in bytes
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_STACK_SIZE = 1000
MAX_SCRIPT_SIZE = 10000
MAX_OPS_PER_SCRIPT = 201
MAX_PUBKEYS_PER_MULTISIG = 20

# Softfork activation heights (mainnet)
BIP16_ACTIVATION_HEIGHT = 173805
BIP34_ACTIVATION_HEIGHT = 227931
BIP65_ACTIVATION_HEIGHT = 388381
BIP66_ACTIVATION_HEIGHT = 363725
BIP68_ACTIVATION_HEIGHT = 419328
SEGWIT_ACTIVATION_HEIGHT = 481824
TAPROOT_ACTIVATION_HEIGHT = 709632

# secp256k1 curve order / 2, for low-S enforcement
SECP256K1_ORDER_HALF = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140 // 2
)


def get_flags_for_height(height: int) -> int:
    """Return the script verification flags appropriate for *height*."""
    flags = SCRIPT_VERIFY_NONE
    if height >= BIP16_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_P2SH
    if height >= BIP66_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S
    if height >= BIP65_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    if height >= BIP68_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    if height >= SEGWIT_ACTIVATION_HEIGHT:
        flags |= (SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_NULLDUMMY
                   | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CLEANSTACK
                   | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA
                   | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE)
    if height >= TAPROOT_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_TAPROOT
    return flags


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _is_push_only(script: bytes) -> bool:
    """Return True if *script* contains only push operations (BIP 62 rule 2)."""
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
            n = script[i]; i += 1 + n
        elif opcode == 0x4d:
            if i + 2 > len(script):
                return False
            n = int.from_bytes(script[i:i+2], 'little'); i += 2 + n
        elif opcode == 0x4e:
            if i + 4 > len(script):
                return False
            n = int.from_bytes(script[i:i+4], 'little'); i += 4 + n
    return True


def _is_push_only_simple(script: bytes) -> bool:
    """Simplified push-only check: only data pushes and OP_0 through OP_16."""
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
            n = script[i]; i += 1 + n
        elif opcode == 0x4d:
            if i + 2 > len(script):
                return False
            n = int.from_bytes(script[i:i+2], 'little'); i += 2 + n
        elif opcode == 0x4e:
            if i + 4 > len(script):
                return False
            n = int.from_bytes(script[i:i+4], 'little'); i += 4 + n
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


def _check_low_s(sig_without_hashtype: bytes) -> bool:
    """Check that S value in DER sig is in the lower half of the curve order."""
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


def _get_witness_version_and_program(script_pubkey: bytes) -> Optional[Tuple[int, bytes]]:
    """
    If script_pubkey is a witness program, return (version, program).
    Witness programs: OP_n <2..40 bytes>
    """
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
        """Initialize the script interpreter"""
        pass
    
    def verify(
        self,
        script_sig: bytes,
        script_pubkey: bytes,
        tx: Transaction,
        input_index: int,
        flags: int = SCRIPT_VERIFY_NONE,
        amount: int = 0,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
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
                    if script_sig != bytes([len(redeem_script)]) + redeem_script:
                        # scriptSig must be exactly a single push of the redeem script
                        if not _is_push_only_simple(script_sig):
                            return False
                    return self._verify_witness_program(
                        tx, input_index, version, program,
                        witness or [], flags, amount,
                        input_amounts, input_script_pubkeys,
                    )

                redeem_stack = self._execute_script(
                    redeem_script, tx, input_index, redeem_script, flags,
                    initial_stack=stack_copy[:-1])
                if not redeem_stack or not self._cast_to_bool(redeem_stack[-1]):
                    return False
                if (flags & SCRIPT_VERIFY_CLEANSTACK) and len(redeem_stack) != 1:
                    return False
                return True

            # Step 6: Clean stack
            if (flags & SCRIPT_VERIFY_CLEANSTACK) and len(stack) != 1:
                return False

            return True

        except Exception:
            return False

    def _is_p2sh(self, script: bytes) -> bool:
        """OP_HASH160 <20 bytes> OP_EQUAL"""
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
        witness: List[bytes],
        flags: int,
        amount: int = 0,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
    ) -> bool:
        """Verify a segregated witness program (BIP 141)."""
        if version == 0:
            if len(program) == 20:
                return self._verify_witness_v0_keyhash(
                    tx, input_index, program, witness, flags, amount)
            elif len(program) == 32:
                return self._verify_witness_v0_scripthash(
                    tx, input_index, program, witness, flags, amount)
            else:
                return False
        elif version == 1 and len(program) == 32:
            if flags & SCRIPT_VERIFY_TAPROOT:
                # Build the expected scriptPubKey: OP_1 <32-byte key>
                spk = bytes([0x51, 0x20]) + program
                return self.verify_taproot(
                    tx, input_index, witness, spk,
                    input_amounts, input_script_pubkeys)
            return True  # unknown witness version succeeds
        elif flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            return False
        return True  # unknown witness version succeeds

    def _verify_witness_v0_keyhash(
        self, tx: Transaction, input_index: int,
        keyhash: bytes, witness: List[bytes],
        flags: int, amount: int,
    ) -> bool:
        """P2WPKH: witness = [sig, pubkey], keyhash = HASH160(pubkey)."""
        if len(witness) != 2:
            return False
        sig, pubkey = witness[0], witness[1]
        if self._hash160(pubkey) != keyhash:
            return False
        # Build implicit P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        script_code = (
            b'\x76\xa9\x14' + keyhash + b'\x88\xac'
        )
        if not sig:
            return False
        sighash_type = sig[-1]
        der_sig = sig[:-1]
        if (flags & SCRIPT_VERIFY_DERSIG) and not _check_der_signature(sig):
            return False
        if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
            return False
        msg = self._compute_segwit_v0_sighash(
            tx, input_index, script_code, amount, sighash_type)
        if not self._verify_ecdsa_signature(msg, der_sig, pubkey):
            if flags & SCRIPT_VERIFY_NULLFAIL:
                return False
            return False
        return True

    def _verify_witness_v0_scripthash(
        self, tx: Transaction, input_index: int,
        scripthash: bytes, witness: List[bytes],
        flags: int, amount: int,
    ) -> bool:
        """P2WSH: witness = [...stack, witness_script], scripthash = SHA256(witness_script)."""
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
        flags: int = SCRIPT_VERIFY_NONE,
        initial_stack: Optional[List[bytes]] = None,
        is_witness_v0: bool = False,
        witness_amount: int = 0,
    ) -> List[bytes]:
        """
        Execute a Bitcoin script.

        Args:
            script: Script bytes to execute
            tx: Transaction context
            input_index: Index of input being verified
            script_pubkey: Script pubkey for signature hash calculation
            flags: Script verification flags
            initial_stack: Pre-populated stack (for P2SH / witness evaluation)
            is_witness_v0: True when executing inside a SegWit v0 context
            witness_amount: Input amount (needed for BIP 143 sighash)

        Returns:
            Stack after execution
        """
        stack: List[bytes] = list(initial_stack) if initial_stack else []
        altstack: List[bytes] = []
        exec_stack: List[bool] = []
        op_count = 0

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

            executing = not exec_stack or all(exec_stack)

            # OP_VERIF / OP_VERNOTIF are always invalid
            if opcode in (0x65, 0x66):
                raise ValueError(f"Invalid opcode 0x{opcode:02x}")

            # ── Data push (always consume bytes; only push when executing) ──
            push_data = None
            if 1 <= opcode <= 75:
                n = opcode
                if i + n > len(script):
                    raise ValueError("Invalid data push")
                push_data = script[i:i + n]; i += n
            elif opcode == 0x4c:
                if i >= len(script):
                    raise ValueError("Invalid OP_PUSHDATA1")
                n = script[i]; i += 1
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA1")
                push_data = script[i:i + n]; i += n
            elif opcode == 0x4d:
                if i + 2 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2")
                n = int.from_bytes(script[i:i + 2], 'little'); i += 2
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2")
                push_data = script[i:i + n]; i += n
            elif opcode == 0x4e:
                if i + 4 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4")
                n = int.from_bytes(script[i:i + 4], 'little'); i += 4
                if i + n > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4")
                push_data = script[i:i + n]; i += n

            if push_data is not None:
                if executing:
                    if len(push_data) > MAX_SCRIPT_ELEMENT_SIZE:
                        raise ValueError(f"Push data exceeds {MAX_SCRIPT_ELEMENT_SIZE} bytes")
                    stack.append(push_data)
                    if len(stack) + len(altstack) > MAX_STACK_SIZE:
                        raise ValueError("Stack size exceeded")
                continue

            # Op count (opcodes > OP_16 only, regardless of exec state)
            if opcode > 0x60:
                op_count += 1
                if op_count > 201:
                    raise ValueError("Too many operations")

            if opcode in _DISABLED:
                raise ValueError(f"Disabled opcode 0x{opcode:02x}")

            # ── Flow control (always processed for nesting) ─────────────
            if opcode == 0x63:  # OP_IF
                val = False
                if executing:
                    if not stack:
                        raise ValueError("OP_IF: stack underflow")
                    val = self._cast_to_bool(stack.pop())
                exec_stack.append(val)
                continue
            if opcode == 0x64:  # OP_NOTIF
                val = False
                if executing:
                    if not stack:
                        raise ValueError("OP_NOTIF: stack underflow")
                    val = not self._cast_to_bool(stack.pop())
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

            # ════════════════════════════════════════════════════════════
            #  From here on, the opcode is being executed.
            # ════════════════════════════════════════════════════════════

            # ── Constants ───────────────────────────────────────────────
            if opcode == 0x00:  # OP_0 / OP_FALSE
                stack.append(b'')
                continue
            if opcode == 0x4f:  # OP_1NEGATE
                stack.append(b'\x81')
                continue
            if 0x51 <= opcode <= 0x60:  # OP_1 .. OP_16
                stack.append(bytes([opcode - 0x50]))
                continue

            # ── Flow control ────────────────────────────────────────────
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

            # ── Reserved (fail when executed) ───────────────────────────
            if opcode in (0x50, 0x62, 0x89, 0x8a):
                raise ValueError(f"Reserved opcode 0x{opcode:02x}")

            # ── Stack manipulation ──────────────────────────────────────
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
                stack.pop(); stack.pop()
                continue
            if opcode == 0x6e:  # OP_2DUP
                if len(stack) < 2:
                    raise ValueError("OP_2DUP: stack underflow")
                stack.extend(stack[-2:])
                continue
            if opcode == 0x6f:  # OP_3DUP
                if len(stack) < 3:
                    raise ValueError("OP_3DUP: stack underflow")
                stack.extend(stack[-3:])
                continue
            if opcode == 0x70:  # OP_2OVER
                if len(stack) < 4:
                    raise ValueError("OP_2OVER: stack underflow")
                stack.extend(stack[-4:-2])
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
                continue
            if opcode == 0x74:  # OP_DEPTH
                stack.append(self._encode_script_num(len(stack)))
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
                continue
            if opcode == 0x79:  # OP_PICK
                if not stack:
                    raise ValueError("OP_PICK: stack underflow")
                n = self._read_signed_num(stack.pop())
                if n < 0 or n >= len(stack):
                    raise ValueError("OP_PICK: index out of range")
                stack.append(stack[-(n + 1)])
                continue
            if opcode == 0x7a:  # OP_ROLL
                if not stack:
                    raise ValueError("OP_ROLL: stack underflow")
                n = self._read_signed_num(stack.pop())
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
                continue

            # ── Splice ──────────────────────────────────────────────────
            if opcode == 0x82:  # OP_SIZE (does not pop)
                if not stack:
                    raise ValueError("OP_SIZE: stack underflow")
                stack.append(self._encode_script_num(len(stack[-1])))
                continue

            # ── Bitwise logic ───────────────────────────────────────────
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

            # ── Arithmetic (unary) ──────────────────────────────────────
            if opcode == 0x8b:  # OP_1ADD
                if not stack:
                    raise ValueError("OP_1ADD: stack underflow")
                stack.append(self._encode_script_num(self._read_signed_num(stack.pop()) + 1))
                continue
            if opcode == 0x8c:  # OP_1SUB
                if not stack:
                    raise ValueError("OP_1SUB: stack underflow")
                stack.append(self._encode_script_num(self._read_signed_num(stack.pop()) - 1))
                continue
            if opcode == 0x8f:  # OP_NEGATE
                if not stack:
                    raise ValueError("OP_NEGATE: stack underflow")
                stack.append(self._encode_script_num(-self._read_signed_num(stack.pop())))
                continue
            if opcode == 0x90:  # OP_ABS
                if not stack:
                    raise ValueError("OP_ABS: stack underflow")
                stack.append(self._encode_script_num(abs(self._read_signed_num(stack.pop()))))
                continue
            if opcode == 0x91:  # OP_NOT
                if not stack:
                    raise ValueError("OP_NOT: stack underflow")
                stack.append(self._encode_script_num(int(self._read_signed_num(stack.pop()) == 0)))
                continue
            if opcode == 0x92:  # OP_0NOTEQUAL
                if not stack:
                    raise ValueError("OP_0NOTEQUAL: stack underflow")
                stack.append(self._encode_script_num(int(self._read_signed_num(stack.pop()) != 0)))
                continue

            # ── Arithmetic (binary) ─────────────────────────────────────
            if opcode in (0x93, 0x94, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
                          0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4):
                if len(stack) < 2:
                    raise ValueError(f"Arithmetic opcode 0x{opcode:02x}: stack underflow")
                bn_b = self._read_signed_num(stack.pop())
                bn_a = self._read_signed_num(stack.pop())
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
                mx = self._read_signed_num(stack.pop())
                mn = self._read_signed_num(stack.pop())
                x = self._read_signed_num(stack.pop())
                stack.append(self._encode_script_num(int(mn <= x < mx)))
                continue

            # ── Crypto ──────────────────────────────────────────────────
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
            if opcode == 0xab:
                continue

            # ── Signature verification ──────────────────────────────────
            if opcode == 0xac:  # OP_CHECKSIG
                if len(stack) < 2:
                    raise ValueError("OP_CHECKSIG: stack underflow")
                pubkey = stack.pop()
                sig = stack.pop()
                if not sig:
                    stack.append(b'\x00')
                    continue
                if len(pubkey) < 1:
                    if (flags & SCRIPT_VERIFY_NULLFAIL) and sig:
                        raise ValueError("NULLFAIL: non-empty sig for empty pubkey")
                    stack.append(b'\x00')
                    continue
                if (flags & SCRIPT_VERIFY_DERSIG) and not _check_der_signature(sig):
                    raise ValueError("Non-DER signature")
                der_sig = sig[:-1]
                if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
                    raise ValueError("Non-low-S signature")
                sighash_type = sig[-1]
                try:
                    if is_witness_v0:
                        msg = self._compute_segwit_v0_sighash(
                            tx, input_index, script_pubkey, witness_amount, sighash_type)
                    else:
                        msg = self._calculate_signature_hash(
                            tx, input_index, script_pubkey, sighash_type)
                    ok = self._verify_ecdsa_signature(msg, der_sig, pubkey)
                    if not ok and (flags & SCRIPT_VERIFY_NULLFAIL):
                        raise ValueError("NULLFAIL: signature verification failed with non-empty sig")
                    stack.append(b'\x01' if ok else b'\x00')
                except ValueError:
                    raise
                except Exception:
                    stack.append(b'\x00')
                continue

            if opcode == 0xad:  # OP_CHECKSIGVERIFY
                if len(stack) < 2:
                    raise ValueError("OP_CHECKSIGVERIFY: stack underflow")
                pubkey = stack.pop()
                sig = stack.pop()
                if not sig or len(pubkey) < 1:
                    raise ValueError("OP_CHECKSIGVERIFY failed")
                if (flags & SCRIPT_VERIFY_DERSIG) and not _check_der_signature(sig):
                    raise ValueError("Non-DER signature")
                der_sig = sig[:-1]
                if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
                    raise ValueError("Non-low-S signature")
                sighash_type = sig[-1]
                try:
                    if is_witness_v0:
                        msg = self._compute_segwit_v0_sighash(
                            tx, input_index, script_pubkey, witness_amount, sighash_type)
                    else:
                        msg = self._calculate_signature_hash(
                            tx, input_index, script_pubkey, sighash_type)
                    if not self._verify_ecdsa_signature(msg, der_sig, pubkey):
                        raise ValueError("OP_CHECKSIGVERIFY failed")
                except ValueError:
                    raise
                except Exception:
                    raise ValueError("OP_CHECKSIGVERIFY failed")
                continue

            if opcode == 0xae:  # OP_CHECKMULTISIG
                if len(stack) < 1:
                    raise ValueError("OP_CHECKMULTISIG: stack underflow")
                n = self._read_num(stack.pop())
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
                k = self._read_num(stack.pop())
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
                    sigs, pubkeys, k, tx, input_index, script_pubkey,
                    flags, is_witness_v0, witness_amount)
                if not valid and (flags & SCRIPT_VERIFY_NULLFAIL):
                    for s in sigs:
                        if s:
                            raise ValueError("NULLFAIL: non-empty sig in failed multisig")
                stack.append(b'\x01' if valid else b'\x00')
                continue

            if opcode == 0xaf:  # OP_CHECKMULTISIGVERIFY
                if not stack:
                    raise ValueError("OP_CHECKMULTISIGVERIFY: stack underflow")
                n = self._read_num(stack.pop())
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
                k = self._read_num(stack.pop())
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
                    sigs, pubkeys, k, tx, input_index, script_pubkey,
                    flags, is_witness_v0, witness_amount):
                    raise ValueError("OP_CHECKMULTISIGVERIFY failed")
                continue

            # ── Timelocks (BIP 65 / BIP 112) ────────────────────────────
            if opcode == 0xb1:  # OP_CHECKLOCKTIMEVERIFY
                if not stack:
                    raise ValueError("OP_CHECKLOCKTIMEVERIFY: stack empty")
                lock_value = self._read_signed_num(stack[-1], max_len=5)
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
                if not stack:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: stack empty")
                lock_value = self._read_signed_num(stack[-1], max_len=5)
                if lock_value < 0:
                    raise ValueError("OP_CHECKSEQUENCEVERIFY: negative sequence")
                SEQ_DISABLE = 1 << 31
                SEQ_TYPE = 1 << 22
                SEQ_MASK = 0x0000ffff
                if lock_value & SEQ_DISABLE:
                    continue
                if tx.version < 2:
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

            # ── Reserved NOPs ───────────────────────────────────────────
            if opcode in (0xb0, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9):
                continue

            raise ValueError(f"Unknown opcode 0x{opcode:02x}")

        if exec_stack:
            raise ValueError("Unbalanced OP_IF/OP_ENDIF")

        return stack
    
    @staticmethod
    def _cast_to_bool(data: bytes) -> bool:
        """Bitcoin CastToBool: false iff all-zero bytes or negative zero (0x80)."""
        for idx in range(len(data)):
            if data[idx] != 0:
                if idx == len(data) - 1 and data[idx] == 0x80:
                    return False
                return True
        return False

    def _hash160(self, data: bytes) -> bytes:
        """Compute HASH160 (RIPEMD160(SHA256(data)))"""
        sha256_hash = hashlib.sha256(data).digest()
        return hashlib.new('ripemd160', sha256_hash).digest()
    
    def _hash256(self, data: bytes) -> bytes:
        """Compute double SHA256"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def _read_num(self, data: bytes) -> int:
        """Read script number from stack (empty = 0, else minimal little-endian)."""
        if not data:
            return 0
        return int.from_bytes(data, 'little')

    def _read_signed_num(self, data: bytes, max_len: int = 4) -> int:
        """
        Decode a CScriptNum: signed little-endian with the MSB of the
        last byte used as a sign bit.  Enforces minimal encoding.

        Bitcoin Core: ``CScriptNum(stacktop(-1), fRequireMinimal, max_len)``
        """
        if not data:
            return 0
        if len(data) > max_len:
            raise ValueError(f"CScriptNum overflow ({len(data)} > {max_len})")

        # Minimal encoding check (Bitcoin Core CScriptNum constructor)
        if data[-1] & 0x7f == 0:
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
        """Encode variable-length integer for script serialization."""
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')

    def _calculate_signature_hash(
        self,
        transaction: Transaction,
        input_index: int,
        script_code: bytes,
        sighash_type: int
    ) -> bytes:
        """
        Calculate Bitcoin legacy SignatureHash for ECDSA verification.

        Follows en.bitcoin.it/wiki/OP_CHECKSIG.
        Supports SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY.

        Args:
            transaction: The transaction being signed
            input_index: Index of the input being verified
            script_code: Script code (scriptPubKey for P2PKH)
            sighash_type: SIGHASH type (last byte of signature)

        Returns:
            32-byte hash for signature verification
        """
        base_type = sighash_type & 0x1f
        anyone_can_pay = (sighash_type & 0x80) != 0

        if base_type not in (0x01, 0, 0x02, 0x03):
            base_type = 0x01

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

        if base_type == 0x01 or base_type == 0:  # SIGHASH_ALL
            data.extend(self._encode_varint(len(transaction.outputs)))
            for tx_out in transaction.outputs:
                data.extend(tx_out.value.to_bytes(8, 'little'))
                data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                data.extend(tx_out.script_pubkey)
        elif base_type == 0x02:  # SIGHASH_NONE
            data.extend(b'\x00')  # Zero outputs
        elif base_type == 0x03:  # SIGHASH_SINGLE
            if input_index >= len(transaction.outputs):
                return bytes(32)
            data.extend(self._encode_varint(input_index + 1))
            for j, tx_out in enumerate(transaction.outputs):
                if j == input_index:
                    data.extend(tx_out.value.to_bytes(8, 'little'))
                    data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                    data.extend(tx_out.script_pubkey)
                else:
                    data.extend((-1).to_bytes(8, 'little', signed=True))
                    data.extend(b'\x00')

        data.extend(transaction.locktime.to_bytes(4, 'little'))
        data.extend(sighash_type.to_bytes(4, 'little'))

        return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()
    
    def _verify_ecdsa_signature(self, message_hash: bytes, der_sig: bytes, pubkey: bytes) -> bool:
        """
        Verify ECDSA signature using secp256k1 (Rust sync module or Python coincurve).

        Args:
            message_hash: 32-byte double-SHA256 of signed data
            der_sig: DER-encoded signature (without SIGHASH byte)
            pubkey: Public key (compressed 33 or uncompressed 65 bytes)

        Returns:
            True if signature is valid, False otherwise
        """
        if len(message_hash) != 32 or len(der_sig) < 8:
            return False
        if len(pubkey) not in (33, 65):
            return False

        try:
            import sync
            return sync.verify_ecdsa(der_sig, pubkey, message_hash)
        except (ImportError, AttributeError, ValueError):
            pass

        try:
            from coincurve import PublicKey
            pk = PublicKey(pubkey)
            return pk.verify(der_sig, message_hash)
        except ImportError:
            pass
        except Exception:
            return False

        return False

    def _verify_multisig(
        self,
        sigs: List[bytes],
        pubkeys: List[bytes],
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

        sig_idx = 0
        key_idx = 0
        matched = 0

        while sig_idx < len(sigs) and key_idx < len(pubkeys) and matched < k:
            sig = sigs[sig_idx]
            pubkey = pubkeys[key_idx]

            if len(sig) < 1:
                key_idx += 1
                continue

            if (flags & SCRIPT_VERIFY_DERSIG) and not _check_der_signature(sig):
                return False
            der_sig = sig[:-1]
            if (flags & SCRIPT_VERIFY_LOW_S) and not _check_low_s(der_sig):
                return False

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

        return matched == k

    # ------------------------------------------------------------------
    # Schnorr / Taproot (BIP 340, 341, 342)
    # ------------------------------------------------------------------

    def _verify_schnorr_signature(
        self, message_hash: bytes, signature: bytes, pubkey_x: bytes
    ) -> bool:
        """
        Verify a BIP 340 Schnorr signature.

        Args:
            message_hash: 32-byte sighash
            signature: 64-byte Schnorr signature
            pubkey_x: 32-byte x-only public key

        Reference: BIP 340
        """
        if len(signature) != 64 or len(pubkey_x) != 32:
            return False

        try:
            import sync
            return sync.verify_schnorr(message_hash, signature, pubkey_x)
        except (ImportError, AttributeError):
            pass

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
        witness: List[bytes],
        script_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
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
            return self._verify_taproot_scriptpath(
                tx, input_index, effective_witness, output_pubkey,
                input_amounts, input_script_pubkeys, annex,
            )

        return False

    def _verify_taproot_keypath(
        self,
        tx: Transaction,
        input_index: int,
        sig_element: bytes,
        output_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
    ) -> bool:
        """
        Key-path spend: witness is a single Schnorr signature (64 or 65 bytes).

        Reference: BIP 341 key path spending
        """
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
        return self._verify_schnorr_signature(sighash, sig, output_pubkey)

    def _verify_taproot_scriptpath(
        self,
        tx: Transaction,
        input_index: int,
        witness: List[bytes],
        output_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
    ) -> bool:
        """
        Script-path spend: witness = [...script_inputs, tapscript, control_block].

        Validates the control block Merkle proof against the output key,
        then executes the tapscript under BIP 342 rules.

        Reference: BIP 341 script path spending
        """
        if len(witness) < 2:
            return False

        control_block = witness[-1]
        tap_script = witness[-2]
        script_inputs = witness[:-2]

        if len(control_block) < 33 or (len(control_block) - 33) % 32 != 0:
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

        # Execute the tapscript (BIP 342)
        if leaf_version == 0xc0:
            sighash = self._compute_taproot_sighash(
                tx, input_index, 0x00,
                input_amounts=input_amounts,
                input_script_pubkeys=input_script_pubkeys,
                annex=annex,
                ext_flag=1,
                tap_leaf_hash=leaf_hash,
            )
            return self._execute_tapscript(
                tap_script, script_inputs, tx, input_index, sighash,
                input_amounts, input_script_pubkeys, annex, leaf_hash,
            )

        return False

    def _taproot_tweak_pubkey(
        self, internal_key: bytes, tweak: bytes
    ) -> Optional[Tuple[bytes, int]]:
        """
        Compute tweaked x-only pubkey: lift internal_key to a point, add
        tweak*G, return (x_bytes, parity).
        """
        try:
            from coincurve import PublicKeyXOnly
            pk = PublicKeyXOnly(internal_key)
            pk.tweak_add(tweak)  # mutates in-place, sets pk.parity
            return pk.format(), int(pk.parity)
        except (ImportError, AttributeError):
            pass
        except Exception:
            return None

        try:
            import sync
            result = sync.taproot_tweak_pubkey(internal_key, tweak)
            return result
        except (ImportError, AttributeError):
            pass
        except Exception:
            return None

        return None

    def _ser_script_size(self, script: bytes) -> bytes:
        """CompactSize-encode the length of a script."""
        n = len(script)
        if n < 0xFD:
            return struct.pack('<B', n)
        elif n <= 0xFFFF:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xFFFFFFFF:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)

    def _compute_taproot_sighash(
        self,
        tx: Transaction,
        input_index: int,
        sighash_type: int,
        *,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
        ext_flag: int = 0,
        tap_leaf_hash: Optional[bytes] = None,
    ) -> bytes:
        """
        Compute the signature hash for a Taproot spend (BIP 341 §4).

        Uses tagged hash "TapSighash" and commits to all inputs' amounts
        and scriptPubKeys (unlike BIP 143 which only commits to the
        current input's amount).

        Reference: BIP 341 §4 (Signature validation rules)
        """
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
            if input_index < len(tx.outputs):
                out = tx.outputs[input_index]
                out_data = struct.pack('<q', out.value) + self._ser_script_size(out.script_pubkey) + out.script_pubkey
                data.extend(hashlib.sha256(out_data).digest())
            else:
                data.extend(b'\x00' * 32)

        # Extension (script path)
        if ext_flag == 1 and tap_leaf_hash:
            data.extend(tap_leaf_hash)
            data.append(0x00)  # key_version
            data.extend(struct.pack('<i', -1))  # codesep_pos = -1 (none executed)

        return _tagged_hash("TapSighash", bytes(data))

    def _execute_tapscript(
        self,
        script: bytes,
        witness_inputs: List[bytes],
        tx: Transaction,
        input_index: int,
        default_sighash: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
        leaf_hash: Optional[bytes] = None,
    ) -> bool:
        """
        Execute a tapscript (BIP 342).

        Differences from legacy script:
        - OP_CHECKSIG uses Schnorr (not ECDSA)
        - OP_CHECKMULTISIG is disabled, replaced by OP_CHECKSIGADD
        - Signature validation failure is immediate script failure (not push 0)
        - Unknown leaf versions are treated as OP_SUCCESS
        """
        stack: List[bytes] = list(witness_inputs)
        op_count = 0
        max_ops = 201

        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1
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
                dlen = script[i]; i += 1
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen]); i += dlen
                continue
            if opcode == 0x4d:  # OP_PUSHDATA2
                if i + 2 > len(script):
                    return False
                dlen = int.from_bytes(script[i:i+2], 'little'); i += 2
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen]); i += dlen
                continue

            if opcode == 0x00:  # OP_0
                stack.append(b'')
                continue
            if 0x51 <= opcode <= 0x60:  # OP_1 .. OP_16
                stack.append(bytes([opcode - 0x50]))
                continue

            # OP_DUP
            if opcode == 0x76:
                if not stack: return False
                stack.append(stack[-1])
                continue
            # OP_DROP
            if opcode == 0x75:
                if not stack: return False
                stack.pop()
                continue
            # OP_EQUAL
            if opcode == 0x87:
                if len(stack) < 2: return False
                a, b = stack.pop(), stack.pop()
                stack.append(b'\x01' if a == b else b'')
                continue
            # OP_EQUALVERIFY
            if opcode == 0x88:
                if len(stack) < 2: return False
                if stack.pop() != stack.pop(): return False
                continue
            # OP_HASH160
            if opcode == 0xa9:
                if not stack: return False
                stack.append(self._hash160(stack.pop()))
                continue

            # OP_CHECKSIG — Schnorr in tapscript
            if opcode == 0xac:
                if len(stack) < 2: return False
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
                        )
                    else:
                        sighash = default_sighash

                    if not self._verify_schnorr_signature(sighash, raw_sig, pubkey):
                        return False
                    stack.append(b'\x01')
                else:
                    return False
                continue

            # OP_CHECKSIGVERIFY
            if opcode == 0xad:
                if len(stack) < 2: return False
                pubkey = stack.pop()
                sig = stack.pop()
                if len(pubkey) != 32 or not sig:
                    return False
                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]; raw_sig = sig[:-1]
                    if sighash_type == 0x00: return False
                elif len(sig) != 64:
                    return False
                sh = default_sighash if sighash_type == 0x00 else self._compute_taproot_sighash(
                    tx, input_index, sighash_type,
                    input_amounts=input_amounts,
                    input_script_pubkeys=input_script_pubkeys,
                    annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    return False
                continue

            # OP_CHECKSIGADD (0xba) — BIP 342
            if opcode == 0xba:
                if len(stack) < 3: return False
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
                    sighash_type = sig[-1]; raw_sig = sig[:-1]
                    if sighash_type == 0x00: return False
                elif len(sig) != 64:
                    return False

                sh = default_sighash if sighash_type == 0x00 else self._compute_taproot_sighash(
                    tx, input_index, sighash_type,
                    input_amounts=input_amounts,
                    input_script_pubkeys=input_script_pubkeys,
                    annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
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
        """Encode an integer as a Bitcoin script number (minimal CScriptNum)."""
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
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4c:  # OP_PUSHDATA1
            if i >= len(script):
                break
            data_len = script[i]
            i += 1
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4d:  # OP_PUSHDATA2
            if i + 1 >= len(script):
                break
            data_len = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4e:  # OP_PUSHDATA4
            if i + 3 >= len(script):
                break
            data_len = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + data_len > len(script):
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
