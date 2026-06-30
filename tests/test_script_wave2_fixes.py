"""
Wave-2 consensus-parity tests for ouroboros script.py fixes.

Finding 1: FindAndDelete opcode-aligned scan (sighash-corners).
Finding 2: MAX_STACK_SIZE initial-stack check tapscript-only gate (witness-structure).

References:
  bitcoin-core/src/script/interpreter.cpp:229-255  (FindAndDelete)
  bitcoin-core/src/script/interpreter.cpp:1836-1861 (ExecuteWitnessScript)
"""

import sys
import types

# Mock the sync module before any ouroboros imports.
if "sync" not in sys.modules:
    sync_mod = types.ModuleType("sync")
    sync_mod.PyUTXO = type("PyUTXO", (), {})
    sync_mod.SyncEngine = type("SyncEngine", (), {})
    sync_mod.PyBlockchainDB = type("PyBlockchainDB", (), {})
    sys.modules["sync"] = sync_mod

from ouroboros.database import Transaction  # noqa: E402
from ouroboros.script import ScriptInterpreter, SigVersion, MAX_SCRIPT_ELEMENT_SIZE  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Helper: minimal Transaction stub for _execute_script
# ─────────────────────────────────────────────────────────────────────────────

def _make_tx() -> Transaction:
    """Minimal Transaction stub; _execute_script only needs its shape."""
    return Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[],
        outputs=[],
    )


def _encode_push(data: bytes) -> bytes:
    """Serialize `data` as a minimal Bitcoin script push."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    elif n <= 0xFF:
        return bytes([0x4C, n]) + data
    elif n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + data
    else:
        return b"\x4e" + n.to_bytes(4, "little") + data


# ─────────────────────────────────────────────────────────────────────────────
# Finding 1: opcode-aligned FindAndDelete
# ─────────────────────────────────────────────────────────────────────────────

def test_find_and_delete_removes_at_opcode_boundary():
    """Needle at an opcode boundary is removed and count returned correctly."""
    sig = bytes([0x42])
    needle = _encode_push(sig)  # b'\x01\x42'

    # Script: [needle] [OP_DROP (0x75)]
    script = needle + b"\x75"
    out, count = ScriptInterpreter._find_and_delete_count(script, sig)
    assert count == 1, f"expected 1 deletion, got {count}"
    assert out == b"\x75", f"expected b'\\x75', got {out.hex()}"


def test_find_and_delete_does_not_remove_needle_inside_push_data():
    """
    Needle bytes embedded inside a larger push payload must NOT be removed.

    Core's FindAndDelete advances pc with GetOp so bytes inside a push data
    payload are never at an opcode boundary and thus never matched.

    Script: OP_3BYTE_PUSH [0x41 0x42 0x43]
    Needle: push(0x42) = b'\\x01\\x42'

    The byte sequence b'\\x01\\x42' does NOT appear inside the push data here
    (the data is 0x41 0x42 0x43), so this also tests that the opcode-walk
    correctly skips the 3 data bytes without matching at internal offsets.

    A stronger test: craft data that starts with the needle bytes (0x01 0x42):
    Script: OP_3BYTE_PUSH [0x01 0x42 0x43]  — needle appears at offset 1
    inside the push data payload, which starts at offset 1 in the opcode.
    Raw bytes of script: 0x03 0x01 0x42 0x43.
    The raw bytes of needle (0x01 0x42) appear at position 1..3 in the
    script, but they are inside the push data — NOT at an opcode boundary.
    """
    sig = bytes([0x42])
    needle = _encode_push(sig)  # b'\x01\x42'

    # 3-byte push whose data contains the needle bytes (0x01 0x42) at offset 0
    # inside the data payload, which is at offset 1 in the script.
    script = bytes([0x03, 0x01, 0x42, 0x43])  # OP_3 0x01 0x42 0x43
    out, count = ScriptInterpreter._find_and_delete_count(script, sig)
    assert count == 0, (
        f"needle inside push data must NOT be deleted (count={count}); "
        f"script={script.hex()}, result={out.hex()}"
    )
    assert out == script, f"script must be unchanged: {out.hex()} != {script.hex()}"


def test_find_and_delete_removes_multiple_at_boundaries():
    """Multiple occurrences at opcode boundaries are all removed."""
    sig = bytes([0xAB])
    needle = _encode_push(sig)  # b'\x01\xAB'

    # Script: [needle] [OP_NOP (0x61)] [needle]
    script = needle + b"\x61" + needle
    out, count = ScriptInterpreter._find_and_delete_count(script, sig)
    assert count == 2, f"expected 2 deletions, got {count}"
    assert out == b"\x61", f"expected b'\\x61', got {out.hex()}"


def test_find_and_delete_boundary_then_embedded():
    """
    One occurrence at boundary (removed), one embedded inside larger push (kept).

    The raw needle bytes (0x01 0x42) at offset 4 in the script are inside
    a 3-byte push payload — they must survive the scan.
    """
    sig = bytes([0x42])
    needle = _encode_push(sig)  # b'\x01\x42'

    # Script: [needle at boundary] [3-byte push: 0x41 0x01 0x42]
    #   Pos 0: needle = b'\x01\x42' → removed.
    #   Pos 2: 0x03 (OP_3) + data 0x41, 0x01, 0x42 → needle bytes embedded,
    #           but NOT at boundary → kept.
    script = needle + bytes([0x03, 0x41, 0x01, 0x42])
    out, count = ScriptInterpreter._find_and_delete_count(script, sig)
    assert count == 1, f"expected exactly 1 deletion (at boundary), got {count}"
    # The kept part is the 3-byte push (4 bytes: 0x03 + data)
    assert out == bytes([0x03, 0x41, 0x01, 0x42]), (
        f"embedded occurrence must survive: {out.hex()}"
    )


def test_find_and_delete_empty_sig():
    """Empty sig → no-op, script returned unchanged."""
    script = b"\x01\x02\x03"
    out, count = ScriptInterpreter._find_and_delete_count(script, b"")
    assert count == 0
    assert out == script


def test_find_and_delete_op_pushdata1():
    """Needle serialized via OP_PUSHDATA1 (sig_len 76–255) is matched at boundary."""
    sig = bytes([0xCC] * 76)  # 76-byte sig → uses 0x4C (OP_PUSHDATA1) prefix
    needle = _encode_push(sig)
    assert needle[0] == 0x4C, "expected OP_PUSHDATA1 prefix"

    # Script: [OP_NOP] [needle] [OP_NOP]
    script = b"\x61" + needle + b"\x61"
    out, count = ScriptInterpreter._find_and_delete_count(script, sig)
    assert count == 1, f"expected 1 deletion, got {count}"
    assert out == b"\x61\x61", f"expected two OP_NOPs, got {out.hex()}"


# ─────────────────────────────────────────────────────────────────────────────
# Finding 2: MAX_STACK_SIZE initial-stack check tapscript-only
# ─────────────────────────────────────────────────────────────────────────────

# MAX_STACK_SIZE is 1000 (same constant in both Core and ouroboros).
MAX_STACK_SIZE = 1000


def test_initial_stack_size_cap_does_not_apply_to_witness_v0():
    """
    P2WSH witness-v0 with >1000 initial stack items must NOT be rejected by
    the pre-execution MAX_STACK_SIZE cap.

    Core interpreter.cpp:1836-1856: the `if (sigversion == TAPSCRIPT)` block
    wraps the initial-stack-size check — witness-v0 P2WSH is NOT covered.
    The per-opcode MAX_STACK_SIZE check during EvalScript still applies, but
    the PRE-EXECUTION cap fires only for tapscript.

    We pass 1001 empty items and a trivial script.  The call may fail for
    other reasons (e.g. cleanstack requiring exactly 1 item on the stack),
    but must NOT raise the "Stack size exceeded (initial witness stack)" error.
    """
    interp = ScriptInterpreter()
    tx = _make_tx()

    big_stack = [b""] * (MAX_STACK_SIZE + 1)  # 1001 items
    # OP_NOP (0x61): does nothing, leaves stack unchanged.  Will fail cleanstack
    # since >1 item remains, but that's OK — we only care the pre-exec check
    # didn't fire first.
    script = bytes([0x61])

    try:
        interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=big_stack,
            is_witness_v0=True,
            sig_version=SigVersion.BASE,  # witness-v0 uses BASE sig version
            witness_weight=0,
        )
    except ValueError as exc:
        msg = str(exc)
        assert "Stack size exceeded (initial witness stack)" not in msg, (
            "Pre-execution MAX_STACK_SIZE cap MUST NOT fire for witness-v0 "
            f"(Core interpreter.cpp:1855 is tapscript-only), but got: {msg}"
        )
    except Exception:
        # Any other exception (cleanstack, etc.) is fine.
        pass


def test_initial_stack_size_cap_applies_to_tapscript():
    """
    Tapscript with >1000 initial stack items MUST be rejected before execution.

    Core interpreter.cpp:1854-1856 (inside `if (sigversion == TAPSCRIPT)`):
      `if (stack.size() > MAX_STACK_SIZE) return set_error(serror, SCRIPT_ERR_STACK_SIZE)`
    """
    interp = ScriptInterpreter()
    tx = _make_tx()

    big_stack = [b""] * (MAX_STACK_SIZE + 1)  # 1001 items
    # OP_1 (0x51): pushes 1 — but the pre-execution check fires before any opcode.
    script = bytes([0x51])

    try:
        interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=big_stack,
            is_witness_v0=False,
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=0,
            input_amounts=[0],
            input_script_pubkeys=[b""],
            annex=None,
            leaf_hash=b"\x00" * 32,
            default_sighash=b"\x00" * 32,
        )
        raise AssertionError(
            "Expected ValueError 'Stack size exceeded' for tapscript with 1001 "
            "initial items but got no exception"
        )
    except ValueError as exc:
        assert "Stack size exceeded" in str(exc), (
            f"Expected stack-size ValueError for tapscript, got: {exc}"
        )


def test_element_size_cap_applies_to_witness_v0():
    """
    A witness-v0 initial stack with a >520-byte item must be rejected.

    Core interpreter.cpp:1858-1861 (outside the TAPSCRIPT-only block):
      `for (const valtype& elem : stack) {
           if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE) return SCRIPT_ERR_PUSH_SIZE;
       }`
    This runs for BOTH tapscript and witness-v0.
    """
    interp = ScriptInterpreter()
    tx = _make_tx()

    # One stack item of 521 bytes (exceeds MAX_SCRIPT_ELEMENT_SIZE = 520).
    oversized_stack = [b"\x00" * (MAX_SCRIPT_ELEMENT_SIZE + 1)]
    script = bytes([0x61])  # OP_NOP

    try:
        interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=oversized_stack,
            is_witness_v0=True,
            sig_version=SigVersion.BASE,
            witness_weight=0,
        )
        raise AssertionError(
            "Expected ValueError for witness-v0 with >520-byte initial stack item"
        )
    except ValueError as exc:
        assert "Witness stack item exceeds" in str(exc), (
            f"Expected element-size error for witness-v0 initial stack, got: {exc}"
        )
