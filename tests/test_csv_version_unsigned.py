"""
Regression test: OP_CHECKSEQUENCEVERIFY must compare tx.version as uint32_t.

Bitcoin Core stores nVersion as uint32_t and the CSV gate is:
    if (txTo->nVersion < 2) return false;  // interpreter.cpp:1790
which is an UNSIGNED comparison.  Python/Rust decode the version as a signed
i32, so a high-bit version like 0xFFFFFFFF (= -1 as signed int32) would
wrongly fail ``tx.version < 2`` (signed), causing a false-reject on a
consensus-valid spend (BIP112 tx_valid vector 165).

Fix: the OP_CSV branch now uses ``(tx.version & 0xFFFFFFFF) < 2``, matching
Core's uint32_t semantics.

Scenarios:
  A. nVersion = 0xFFFFFFFF (-1 signed, 4294967295 unsigned): MUST PASS after
     fix (was false-rejected by signed ``< 2``).
  B. nVersion = 1 (below 2 both signed and unsigned): MUST FAIL.
  C. nVersion = 2 (baseline valid): MUST PASS.
  D. nVersion = 0x80000002 (high-bit set, >= 2 unsigned): MUST PASS.
  E. lock_value has SEQUENCE_LOCKTIME_DISABLE_FLAG: CSV is a NOP regardless
     of version — version gate never reached.
"""

from __future__ import annotations

import sys
import types

# Mock sync FFI before any ouroboros import
if "sync" not in sys.modules:
    _sync = types.ModuleType("sync")
    _sync.PyUTXO = type("PyUTXO", (), {})
    _sync.SyncEngine = type("SyncEngine", (), {})
    _sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    _sync.__file__ = "<test-mock>"
    sys.modules["sync"] = _sync

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, ScriptInterpreter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tx(version: int, sequence: int) -> Transaction:
    """Build a minimal transaction with one input whose sequence = *sequence*
    and whose nVersion field is the raw *version* integer (may be negative
    when stored as a signed Python int from a high-bit uint32)."""
    inp = TxIn(
        prev_txid=b"\x00" * 32,
        prev_vout=0,
        script_sig=b"",
        sequence=sequence,
    )
    out = TxOut(value=0, script_pubkey=b"")
    return Transaction(
        txid=b"\x00" * 32,
        version=version,
        locktime=0,
        inputs=[inp],
        outputs=[out],
    )


def _encode_script_num(n: int) -> bytes:
    """Minimal CScriptNum encoding (little-endian, no leading zeros)."""
    if n == 0:
        return b""
    negative = n < 0
    absval = abs(n)
    result = []
    while absval:
        result.append(absval & 0xFF)
        absval >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def _make_csv_scriptpubkey(lock_value: int) -> bytes:
    """scriptPubKey: <lock_value> OP_CSV OP_DROP OP_1

    Pushes lock_value onto the stack, then CSV checks it against the input
    sequence, pops it (DROP), leaves OP_1 as the valid top-of-stack result.
    """
    OP_CSV  = 0xb2
    OP_DROP = 0x75
    OP_1    = 0x51
    num = _encode_script_num(lock_value)
    assert len(num) <= 75, "lock_value too large for simple push"
    return bytes([len(num)]) + num + bytes([OP_CSV, OP_DROP, OP_1])


def _run_csv(version: int, sequence: int, lock_value: int) -> bool:
    """Run scriptSig=OP_1 + scriptPubKey=<lock_value> CSV DROP OP_1.

    Returns True if the script evaluates successfully, False on any error.
    """
    tx = _make_tx(version, sequence)
    interp = ScriptInterpreter()
    # scriptSig is OP_1 (pushes 1 as a dummy stack element; we need something
    # on the stack before the CSV scriptPubKey runs its OP_DROP).
    # Actually, CSV itself doesn't pop the stack — DROP does. So:
    # stack after scriptSig = [0x01], then CSV checks but leaves stack,
    # DROP pops, OP_1 pushes 0x01. Final stack = [0x01] = truthy.
    try:
        return interp.verify(
            script_sig=bytes([0x51]),          # OP_1
            script_pubkey=_make_csv_scriptpubkey(lock_value),
            tx=tx,
            input_index=0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            amount=0,
        )
    except (ValueError, Exception):
        return False


# Sequence value: 1-block relative lock-time (bit 31 clear, bit 22 clear → blocks)
_SEQ_1_BLOCK = 1


class TestCsvVersionUnsigned:
    """OP_CSV version gate uses (version & 0xFFFFFFFF) < 2, matching Core uint32_t."""

    def test_version_ffffffff_is_valid(self):
        """nVersion = 0xFFFFFFFF (-1 signed i32) is 4294967295 unsigned >= 2.

        Before the fix, ``tx.version < 2`` with signed -1 would raise a
        false-reject. After the fix, this must PASS.
        """
        signed_neg1 = -1  # same bits as 0xFFFFFFFF when masked to uint32
        result = _run_csv(version=signed_neg1, sequence=_SEQ_1_BLOCK, lock_value=1)
        assert result is True, (
            "nVersion=0xFFFFFFFF (-1 signed) with satisfied sequence must "
            "PASS OP_CSV after unsigned version fix (BIP112 vector 165)"
        )

    def test_version_2_passes(self):
        """nVersion = 2 is the baseline valid case for OP_CSV."""
        assert _run_csv(version=2, sequence=_SEQ_1_BLOCK, lock_value=1) is True

    def test_version_1_fails(self):
        """nVersion = 1 is below 2 both signed and unsigned → must FAIL."""
        assert _run_csv(version=1, sequence=_SEQ_1_BLOCK, lock_value=1) is False

    def test_version_0_fails(self):
        """nVersion = 0 is below 2 both signed and unsigned → must FAIL."""
        assert _run_csv(version=0, sequence=_SEQ_1_BLOCK, lock_value=1) is False

    def test_version_high_bit_set_above_2(self):
        """nVersion = 0x80000002 (-2147483646 signed, but >= 2 unsigned) must PASS."""
        signed_high = -2147483646  # 0x80000002 as Python int from signed i32
        result = _run_csv(version=signed_high, sequence=_SEQ_1_BLOCK, lock_value=1)
        assert result is True, (
            "nVersion=0x80000002 (high-bit set, >= 2 unsigned) must PASS OP_CSV"
        )

    def test_lock_disable_flag_is_nop_regardless_of_version(self):
        """lock_value with SEQUENCE_LOCKTIME_DISABLE_FLAG (bit 31): CSV is a NOP.

        The version gate is never reached when the disable-flag is set on the
        lock_value operand. Even version=1 must pass.
        """
        # BIP112: if (nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) → NOP3
        seq_disable = 1 << 31
        # Use version=1 which would normally fail — should PASS here since
        # the disable-flag short-circuits before the version check.
        result = _run_csv(version=1, sequence=_SEQ_1_BLOCK, lock_value=seq_disable)
        assert result is True, (
            "CSV with disable-flag in lock_value must be a NOP (no version check)"
        )
