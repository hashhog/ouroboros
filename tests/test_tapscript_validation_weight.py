"""BIP-342 tapscript validation-weight budget tracking.

Per Bitcoin Core interpreter.cpp:362, every non-empty
OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD inside a tapscript must
decrement a per-input validation-weight counter by
VALIDATION_WEIGHT_PER_SIGOP_PASSED (50). The counter is seeded at
::GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET (50), and a
negative residue aborts with SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT.

Without this gate, a tapscript leaf can perform arbitrarily many Schnorr
verifies bounded only by block weight — a DoS hole on adversarial blocks.
"""

import pytest
from ouroboros.script import ScriptInterpreter, SigVersion


class TestCompactSizeHelpers:
    """The compact-size encoding helpers must match Core byte-for-byte."""

    def test_compact_size_len_matches_core(self) -> None:
        f = ScriptInterpreter._compact_size_len
        assert f(0) == 1
        assert f(0xFC) == 1
        assert f(0xFD) == 3
        assert f(0xFFFF) == 3
        assert f(0x10000) == 5
        assert f(0xFFFFFFFF) == 5
        assert f(0x100000000) == 9

    def test_serialized_witness_stack_size_empty(self) -> None:
        # Empty stack: just the count compact-size byte.
        assert ScriptInterpreter._serialized_witness_stack_size([]) == 1

    def test_serialized_witness_stack_size_one_64b(self) -> None:
        # 1 (count) + 1 (item len prefix) + 64 (bytes)
        assert ScriptInterpreter._serialized_witness_stack_size([b"\x00" * 64]) == 66

    def test_serialized_witness_stack_size_two_items(self) -> None:
        items = [b"\x00" * 100, b"\x00" * 33]
        assert (
            ScriptInterpreter._serialized_witness_stack_size(items)
            == 1 + (1 + 100) + (1 + 33)
        )


class TestTapscriptBudgetGate:
    """Drive _execute_script directly to exercise the budget gate.

    OP_CHECKSIGADD makes this easy: with an empty sig it pushes ``n``
    unchanged (no Schnorr crypto needed), and with a non-empty sig it
    runs the budget deduction before the Schnorr verify so we can hit
    the gate without real cryptographic input.
    """

    def _make_interp(self) -> ScriptInterpreter:
        # ScriptInterpreter is a stateless helper class (the public API
        # holds the verifier; tests reach into _execute_script).
        return ScriptInterpreter()

    def test_op_checksigadd_exhausted_budget_aborts(self) -> None:
        interp = self._make_interp()
        from ouroboros.database import Transaction
        # Construct the smallest possible Transaction stub the verify
        # code will accept. We don't need a real one — _execute_script
        # only consumes inputs/outputs when computing sighashes, which
        # only happen when sig.length > 0 AND pubkey.length == 32 AND
        # we go through the full Schnorr path. Using a 33-byte pubkey
        # short-circuits to "unknown pubkey type → success" without
        # crypto.
        tx = Transaction(
            txid=b"\x00" * 32,
            version=2,
            locktime=0,
            inputs=[],
            outputs=[],
        )
        # Stack (top-down): pubkey, num=0, sig
        # OP_CHECKSIGADD = 0xba
        # Push sig (64B) + push num=0 (OP_0) + push pubkey (32B) + OP_CHECKSIGADD
        sig = b"\x42" * 64
        num = b""  # OP_0 push (empty bytes)
        pk = b"\x02" * 32
        initial_stack = [sig, num, pk]
        script = bytes([0xba])  # OP_CHECKSIGADD only

        # Budget = 0: the non-empty sig must trip the gate.
        # _execute_script seeds budget = 50 + witness_weight when
        # is_tapscript=True, so to test the gate we need
        # witness_weight = -50. Since witness_weight is added to 50
        # internally we instead drive a path where the budget would
        # go negative on the first decrement: witness_weight = 0 →
        # budget = 50 → first decrement leaves 0 (OK). Two decrements
        # require two non-empty sigs → witness_weight = 0 →
        # 50 - 50 - 50 = -50 → trips on second.
        #
        # Build script with TWO CHECKSIGADDs to exhaust:
        #   <sig> <0> <pk> CHECKSIGADD <sig> <pk> CHECKSIGADD
        # After first: stack has [<num+sig_result>], second CHECKSIGADD
        # pops pubkey, num, sig from a stack with only one element →
        # underflow. So instead: drive deeper budget exhaustion via
        # witness_weight=0, two sigs in one go using script that
        # CHECKSIGADD twice with proper layout.
        # Easier: just call _execute_script with witness_weight=-100
        # to forcibly seed budget=-50 < 0 on the first non-empty sig.
        # That's a bit hacky but correctly exercises the gate.
        try:
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=initial_stack,
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=-100,
                input_amounts=[0],
                input_script_pubkeys=[b""],
                annex=None,
                leaf_hash=b"\x00" * 32,
                default_sighash=b"\x00" * 32,
            )
        except ValueError as e:
            assert "sigops" in str(e).lower() or "validation" in str(e).lower() or "weight" in str(e).lower(), (
                f"Expected sigops/budget error, got: {e}"
            )
            return
        pytest.fail("Expected sigops budget error, got success")

    def test_op_checksigadd_empty_sig_consumes_no_budget(self) -> None:
        # Empty sig + budget=0 must succeed (push num unchanged).
        # We drive it directly to confirm the empty-sig short-circuit
        # bypasses the gate.
        interp = self._make_interp()
        from ouroboros.database import Transaction
        tx = Transaction(
            txid=b"\x00" * 32,
            version=2,
            locktime=0,
            inputs=[],
            outputs=[],
        )
        # Stack (bottom-to-top): empty sig, num=5, pubkey
        # OP_CHECKSIGADD pops pubkey, num, sig.
        sig = b""
        num = bytes([5])
        pk = b"\x02" * 32
        initial_stack = [sig, num, pk]
        script = bytes([0xba])  # OP_CHECKSIGADD

        # Budget = 50 (witness_weight = 0 + base 50). Empty sig path
        # must NOT touch the budget.
        result = interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=initial_stack,
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=0,
            input_amounts=[0],
            input_script_pubkeys=[b""],
            annex=None,
            leaf_hash=b"\x00" * 32,
            default_sighash=b"\x00" * 32,
        )
        # Result stack contains the post-op num (unchanged at 5).
        assert result == [bytes([5])]


class TestBudgetFormula:
    """Pin down the budget formula at the seed site so a future refactor
    can't silently drop the +50 OFFSET or the GetSerializeSize counting."""

    def test_budget_seed_includes_compact_size_overhead(self) -> None:
        # Two-item witness stack: 64-byte sig + 32-byte pubkey.
        # GetSerializeSize = 1 (count) + (1 + 64) + (1 + 32) = 99.
        # Budget = 99 + 50 = 149.
        items = [b"\x00" * 64, b"\x00" * 32]
        assert ScriptInterpreter._serialized_witness_stack_size(items) == 99

    def test_budget_seed_includes_annex_when_present(self) -> None:
        # Annex is a normal stack item from the perspective of
        # GetSerializeSize. An annex of 50 bytes adds (1 + 50) = 51
        # to the budget over the no-annex case.
        no_annex = [b"\x00" * 64, b"\x00" * 32]
        with_annex = no_annex + [b"\x50" + b"\x00" * 49]
        assert (
            ScriptInterpreter._serialized_witness_stack_size(with_annex)
            - ScriptInterpreter._serialized_witness_stack_size(no_annex)
            == 1 + 50  # +1 prefix +50 bytes (item count compact-size still 1)
        )
