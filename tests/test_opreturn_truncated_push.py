"""
Regression test: OP_RETURN with a truncated push must be classified
nonstandard, NOT nulldata, in both the RPC classifier and the mempool
policy gate.

W56 (297bc5c) fixed rpc_decodescript to emit "nonstandard" for such
scripts (via a local _is_push_only helper), but the fix was scoped to
rpc_decodescript only.  Two separate code paths still had the bug:

  1. RPCServer._classify_script (rpc.py:10372) — returned "nulldata" for
     any script starting with 0x6a, including ones with truncated pushes.
     Used by getrawtransaction, decoderawtransaction, etc.

  2. _is_standard_output_type (mempool.py:694) — same raw 0x6a check,
     accepted any OP_RETURN output as standard regardless of malformed tail.
     AND _is_standard_tx() never checked output types at all, so a tx with
     a nonstandard output sailed through the policy gate unchallenged.

Script under test: 6a 09 dead beef
  0x6a = OP_RETURN
  0x09 = PUSH 9 bytes of data
  dead beef = only 4 bytes (truncated — should be 9)

Reference: Bitcoin Core script/solver.cpp Solver() ~line 185:
  if (IsPushOnly(script.begin()+1, script.end())) return TX_NULL_DATA;
  // else falls through to TX_NONSTANDARD
"""

# Mock the Rust sync extension before any ouroboros imports so this test
# can run without building the ferrous-utils wheel.
import sys
import types

if "sync" not in sys.modules:
    _sync = types.ModuleType("sync")
    _sync.PyUTXO = type("PyUTXO", (), {})
    _sync.SyncEngine = type("SyncEngine", (), {})
    _sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    sys.modules["sync"] = _sync

import pytest  # noqa: E402

from ouroboros.mempool import (  # noqa: E402
    _is_push_only_from,
    _is_standard_output_type,
    _is_standard_tx,
)

# Script: OP_RETURN + PUSH9 opcode + only 4 data bytes (truncated)
TRUNCATED_OPRETURN = bytes.fromhex("6a09deadbeef")

# Well-formed OP_RETURN: OP_RETURN + PUSH4 + 4 data bytes
WELLFORMED_OPRETURN = bytes.fromhex("6a04deadbeef")

# Well-formed OP_RETURN with no data (bare OP_RETURN)
BARE_OPRETURN = bytes.fromhex("6a")

# Well-formed OP_RETURN with 80 data bytes (max relay size, PUSH 0x4c prefix)
OPRETURN_80 = bytes.fromhex("6a") + bytes([0x4c, 80]) + b"\xab" * 80


# ---------------------------------------------------------------------------
# _is_push_only_from unit tests
# ---------------------------------------------------------------------------

class TestIsPushOnlyFrom:
    def test_empty_is_push_only(self):
        """Empty tail is trivially push-only (vacuously true)."""
        assert _is_push_only_from(b"", 0) is True

    def test_bare_opreturn_tail_is_push_only(self):
        """OP_RETURN with no tail bytes — trivially push-only from pos 1."""
        assert _is_push_only_from(BARE_OPRETURN, 1) is True

    def test_wellformed_push4_is_push_only(self):
        """PUSH4 + 4 bytes — valid push, should return True."""
        assert _is_push_only_from(WELLFORMED_OPRETURN, 1) is True

    def test_truncated_push9_is_not_push_only(self):
        """PUSH9 opcode with only 4 data bytes is not push-only."""
        assert _is_push_only_from(TRUNCATED_OPRETURN, 1) is False

    def test_non_push_opcode_in_tail(self):
        """OP_CHECKSIG (0xac) in tail makes it not push-only."""
        script = bytes([0x6a, 0xac])
        assert _is_push_only_from(script, 1) is False

    def test_op0_is_push_only(self):
        """OP_0 (0x00) in tail is a valid push (pushes empty bytes)."""
        script = bytes([0x6a, 0x00])
        assert _is_push_only_from(script, 1) is True

    def test_op1_through_op16_are_push_only(self):
        """OP_1 through OP_16 (0x51–0x60) are valid push ops."""
        for op in range(0x51, 0x61):
            script = bytes([0x6a, op])
            assert _is_push_only_from(script, 1) is True, (
                f"OP_{op - 0x50} (0x{op:02x}) should be push-only"
            )

    def test_pushdata1_wellformed(self):
        """OP_PUSHDATA1 with correct length byte and data."""
        # PUSHDATA1 3 abc
        script = bytes([0x6a, 0x4c, 3, 0xaa, 0xbb, 0xcc])
        assert _is_push_only_from(script, 1) is True

    def test_pushdata1_truncated(self):
        """OP_PUSHDATA1 missing length byte."""
        script = bytes([0x6a, 0x4c])
        assert _is_push_only_from(script, 1) is False

    def test_pushdata1_data_truncated(self):
        """OP_PUSHDATA1 length says 5 but only 2 data bytes follow."""
        script = bytes([0x6a, 0x4c, 5, 0xaa, 0xbb])
        assert _is_push_only_from(script, 1) is False


# ---------------------------------------------------------------------------
# _is_standard_output_type tests
# ---------------------------------------------------------------------------

class TestIsStandardOutputTypeOpReturn:
    def test_wellformed_opreturn_is_standard(self):
        """OP_RETURN + valid push data is a standard nulldata output."""
        assert _is_standard_output_type(WELLFORMED_OPRETURN) is True

    def test_bare_opreturn_is_standard(self):
        """Bare OP_RETURN (no data) is standard."""
        assert _is_standard_output_type(BARE_OPRETURN) is True

    def test_opreturn_80_bytes_is_standard(self):
        """OP_RETURN + 80 bytes (PUSHDATA1) is standard."""
        assert _is_standard_output_type(OPRETURN_80) is True

    def test_truncated_opreturn_is_nonstandard(self):
        """6a09deadbeef: OP_RETURN + PUSH9 + only 4 bytes is nonstandard.

        This is the W56 regression vector: before the fix, this returned True
        because the check was just ``script[0] == 0x6a``.
        """
        assert _is_standard_output_type(TRUNCATED_OPRETURN) is False

    def test_opreturn_with_checksig_tail_is_nonstandard(self):
        """OP_RETURN followed by non-push opcode OP_CHECKSIG is nonstandard."""
        script = bytes([0x6a, 0xac])
        assert _is_standard_output_type(script) is False


# ---------------------------------------------------------------------------
# _is_standard_tx: mempool policy gate rejects tx with truncated OP_RETURN
# ---------------------------------------------------------------------------

class TestIsStandardTxOpReturn:
    """Assert that _is_standard_tx rejects a transaction whose output carries
    a nonstandard (truncated-push) OP_RETURN scriptPubKey.

    This tests the PATH B fix: before the fix, _is_standard_tx() never
    checked output script types, so such a tx would pass the policy gate.
    """

    def _make_tx(self, script_pubkey: bytes, value: int = 1000):
        """Build a minimal Transaction with one input and one output."""
        from ouroboros.database import Transaction, TxIn, TxOut
        return Transaction(
            txid=b"\x01" * 32,
            version=2,
            locktime=0,
            inputs=[TxIn(
                prev_txid=b"\x02" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=None,
            )],
            outputs=[TxOut(value=value, script_pubkey=script_pubkey)],
            has_witness=False,
        )

    def test_wellformed_p2wpkh_output_is_standard(self):
        """Sanity check: P2WPKH output passes the type gate."""
        script = bytes([0x00, 0x14]) + b"\xab" * 20  # OP_0 <20>
        tx = self._make_tx(script)
        ok, reason = _is_standard_tx(tx)
        assert ok is True, f"Expected standard, got: {reason}"

    def test_wellformed_opreturn_output_is_standard(self):
        """OP_RETURN + PUSH4 + 4 bytes passes the type gate."""
        tx = self._make_tx(WELLFORMED_OPRETURN, value=0)
        ok, reason = _is_standard_tx(tx)
        assert ok is True, f"Expected standard, got: {reason}"

    def test_truncated_opreturn_output_rejected(self):
        """6a09deadbeef in an output triggers non-standard rejection.

        This is the core PATH B assertion: the mempool policy gate MUST
        reject a tx with this script in vout.
        """
        tx = self._make_tx(TRUNCATED_OPRETURN, value=0)
        ok, reason = _is_standard_tx(tx)
        assert ok is False, (
            "Expected _is_standard_tx to reject tx with truncated OP_RETURN"
        )
        # Core's bare reject token for a nonstandard scriptPubKey
        # (policy/policy.cpp:141, IsStandardTx → "scriptpubkey").
        assert reason == "scriptpubkey", (
            f"Unexpected rejection reason: {reason!r}"
        )

    def test_opreturn_with_nopush_tail_rejected(self):
        """OP_RETURN + non-push opcode in an output is rejected."""
        script = bytes([0x6a, 0xac])  # OP_RETURN OP_CHECKSIG
        tx = self._make_tx(script, value=0)
        ok, _ = _is_standard_tx(tx)
        assert ok is False


# ---------------------------------------------------------------------------
# _classify_script in RPCServer also classifies truncated OP_RETURN correctly
# ---------------------------------------------------------------------------

class TestClassifyScriptOpReturn:
    """The _classify_script RPC helper must also return 'nonstandard' for
    a truncated OP_RETURN push.  Before the fix it returned 'nulldata'.
    """

    def _classify(self, script: bytes) -> str:
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        return rpc._classify_script(script)

    def test_wellformed_opreturn_classified_nulldata(self):
        """OP_RETURN + valid push → 'nulldata'."""
        assert self._classify(WELLFORMED_OPRETURN) == "nulldata"

    def test_bare_opreturn_classified_nulldata(self):
        """Bare OP_RETURN (no data) → 'nulldata'."""
        assert self._classify(BARE_OPRETURN) == "nulldata"

    def test_truncated_opreturn_classified_nonstandard(self):
        """6a09deadbeef (PUSH9 + only 4 bytes) → 'nonstandard', not 'nulldata'.

        W56 regression vector for _classify_script.
        """
        assert self._classify(TRUNCATED_OPRETURN) == "nonstandard"

    def test_opreturn_nopush_tail_classified_nonstandard(self):
        """OP_RETURN + non-push opcode → 'nonstandard'."""
        script = bytes([0x6a, 0xac])  # OP_RETURN OP_CHECKSIG
        assert self._classify(script) == "nonstandard"
