"""
Glassbox interpreter-parity regressions (2026-07-01 audit).

Two confirmed script-interpreter divergences vs Bitcoin Core:

  1. [HIGH] OP_SIZE did not enforce MAX_STACK_SIZE (1000).  A P2WSH v0
     witnessScript `OP_SIZE OP_DROP*1000` executed against a 1000-item
     initial stack grew the stack to 1001 with no error, then dropped back
     to 1 -> node ACCEPT.  Core runs the end-of-iteration
     `stack.size()+altstack.size() > MAX_STACK_SIZE` check after OP_SIZE
     (interpreter.cpp:1221-1223) -> SCRIPT_ERR_STACK_SIZE -> REJECT.

  2. [MED] OP_CHECKSIGADD read its `n` operand as an UNSIGNED integer
     (_read_num) instead of a signed CScriptNum.  For b'\x81', Core decodes
     -1 (interpreter.cpp:1093 `CScriptNum(stacktop(-2), fRequireMinimal)`);
     ouroboros decoded 129.  Tapscript
     `OP_1NEGATE <pubkey32> OP_CHECKSIGADD OP_1NEGATE OP_NUMEQUAL` with an
     empty-sig witness -> Core pushes -1, -1==-1 -> ACCEPT; ouroboros pushed
     129, 129!=-1 -> REJECT.

Both tests FAIL on the pre-fix code and PASS after the fix.
"""

import sys
import types

if "sync" not in sys.modules:
    sync = types.ModuleType("sync")
    sync.PyUTXO = type("PyUTXO", (), {})
    sync.SyncEngine = type("SyncEngine", (), {})
    sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    sys.modules["sync"] = sync

import pytest  # noqa: E402

from ouroboros.script import (  # noqa: E402
    SCRIPT_VERIFY_ALL_DEPLOYED,
    ScriptInterpreter,
    SigVersion,
)


def _cast_to_bool(data: bytes) -> bool:
    for idx in range(len(data)):
        if data[idx] != 0:
            if idx == len(data) - 1 and data[idx] == 0x80:
                return False
            return True
    return False


# NOTE ON THE EXPLOIT VECTOR:
# The findings-doc failing input used a witness-v0 P2WSH script
# `OP_SIZE OP_DROP*1000`.  In witness-v0 the 1000 OP_DROPs trip Core's (and
# ouroboros's) MAX_OPS_PER_SCRIPT=201 op-count limit, so that exact script is
# rejected by BOTH engines (just with different errors) — the OP_SIZE stack
# overflow is masked.  The GENUINE accept/reject divergence for the same
# OP_SIZE code path is in TAPSCRIPT, where BIP-342 removes the op-count limit:
# there the 1000 OP_DROPs run freely, so the missing MAX_STACK_SIZE check on
# OP_SIZE lets ouroboros ACCEPT (drops back to 1) while Core REJECTS at the
# OP_SIZE overflow (interpreter.cpp:1221-1223).  Same OP_SIZE handler, same
# fix; tapscript is the exploitable surface.


def test_op_size_enforces_max_stack_size():
    """OP_SIZE growing a 1000-item stack to 1001 must REJECT (Core parity).

    Pre-fix ouroboros ACCEPTs (OP_SIZE -> 1001 unchecked, then 1000 OP_DROPs
    reduce to a single truthy element); Core rejects at the OP_SIZE overflow.
    """
    interp = ScriptInterpreter()

    # tapscript = OP_SIZE (0x82) then 1000 x OP_DROP (0x75)
    script = bytes([0x82]) + bytes([0x75]) * 1000
    # 1000-item initial witness stack — exactly at the tapscript initial cap.
    initial_stack = [b"\x01"] + [b""] * 999

    with pytest.raises(ValueError, match="Stack size exceeded"):
        interp._execute_script(
            script,
            tx=None,
            input_index=0,
            script_pubkey=b"",
            flags=SCRIPT_VERIFY_ALL_DEPLOYED,
            initial_stack=initial_stack,
            sig_version=SigVersion.TAPSCRIPT,
            input_amounts=[0],
            input_script_pubkeys=[b""],
            leaf_hash=bytes(32),
            default_sighash=bytes(32),
        )


def test_op_size_at_exactly_1000_is_ok():
    """Boundary guard: reaching exactly 1000 elements must NOT reject."""
    interp = ScriptInterpreter()

    # OP_SIZE then one OP_DROP: 999-item stack -> OP_SIZE makes 1000 -> ok.
    script = bytes([0x82, 0x75])
    initial_stack = [b"\x01"] + [b""] * 998  # 999 items

    result = interp._execute_script(
        script,
        tx=None,
        input_index=0,
        script_pubkey=b"",
        flags=SCRIPT_VERIFY_ALL_DEPLOYED,
        initial_stack=initial_stack,
        sig_version=SigVersion.TAPSCRIPT,
        input_amounts=[0],
        input_script_pubkeys=[b""],
        leaf_hash=bytes(32),
        default_sighash=bytes(32),
    )
    # 999 -> OP_SIZE -> 1000 (boundary, OK) -> OP_DROP -> 999 remaining.
    assert len(result) == 999


def test_op_checksigadd_reads_n_as_signed_cscriptnum():
    """CHECKSIGADD must decode b'\\x81' as -1 (signed), not 129."""
    interp = ScriptInterpreter()

    pubkey = bytes(32)  # 32-byte x-only pubkey (content irrelevant: empty sig)
    # OP_1NEGATE  <push32 pubkey>  OP_CHECKSIGADD  OP_1NEGATE  OP_NUMEQUAL
    script = bytes([0x4F, 0x20]) + pubkey + bytes([0xBA, 0x4F, 0x9C])

    result = interp._execute_script(
        script,
        tx=None,
        input_index=0,
        script_pubkey=b"",
        flags=SCRIPT_VERIFY_ALL_DEPLOYED,
        initial_stack=[b""],  # empty signature -> success=False, no Schnorr
        sig_version=SigVersion.TAPSCRIPT,
        input_amounts=[0],
        input_script_pubkeys=[b""],
        leaf_hash=bytes(32),
        default_sighash=bytes(32),
    )

    # Core: n = CScriptNum(b'\x81') = -1; (-1)+0 pushed as -1; -1 == -1 -> true.
    assert result, "script left empty stack"
    assert _cast_to_bool(result[-1]), (
        "CHECKSIGADD decoded b'\\x81' as unsigned (129) instead of -1"
    )
