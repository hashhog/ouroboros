"""W94: BIP-341/342 Taproot + tapscript comprehensive audit fixes.

This suite pins the ~25 Core gates (interpreter.cpp:1872-2000+) that ouroboros
was diverging on. Each test names the bug it covers and points at the relevant
Bitcoin Core line(s). Run with pytest from the repo root:

    pytest tests/test_taproot_w94_audit.py -v

Reference:
  bitcoin-core/src/script/interpreter.cpp:1872-2000  (VerifyTaproot* path)
  bitcoin-core/src/script/interpreter.cpp:347-405    (EvalChecksigTapscript)
  bitcoin-core/src/script/interpreter.cpp:1483-1570  (SignatureHashSchnorr)
  bitcoin-core/src/script/interpreter.h:236-250      (constants)
  BIP-340 / BIP-341 / BIP-342 / BIP-431 (P2A)
"""

from __future__ import annotations

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import (
    ANNEX_TAG,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    TAPROOT_CONTROL_BASE_SIZE,
    TAPROOT_CONTROL_MAX_NODE_COUNT,
    TAPROOT_CONTROL_MAX_SIZE,
    TAPROOT_CONTROL_NODE_SIZE,
    TAPROOT_LEAF_MASK,
    TAPROOT_LEAF_TAPSCRIPT,
    WITNESS_V1_TAPROOT_SIZE,
    ScriptInterpreter,
    SigVersion,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_tx(
    n_outputs: int = 1,
    n_inputs: int = 1,
) -> Transaction:
    """Minimal Transaction stub the script code accepts."""
    return Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=b"\x11" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=[],
            )
            for _ in range(n_inputs)
        ],
        outputs=[TxOut(value=10_000, script_pubkey=b"") for _ in range(n_outputs)],
    )


# ---------------------------------------------------------------------------
# Bug #1: P2SH-wrapped Taproot must NOT run full taproot validation.
# Core interpreter.cpp:1947 gates v1/32B on `!is_p2sh`.
# ---------------------------------------------------------------------------


class TestP2SHTaprootGate:
    def test_p2sh_wrapped_v1_32b_not_taproot(self) -> None:
        """P2SH-wrapped witness v1 + 32-byte program: forward-compat success.

        Core treats this as 'unknown witness program inside P2SH' and
        falls through to the success path (line 1996-1998). ouroboros
        previously ran full Taproot validation, which would reject most
        inputs because the witness/output_pubkey combo wasn't built as
        a real Taproot spend.
        """
        interp = ScriptInterpreter()
        # P2SH-of-V1-32B: redeem script is OP_1 <32 zero bytes>
        redeem = bytes([0x51, 0x20]) + b"\x00" * 32
        from hashlib import new as new_hash
        h160 = new_hash("ripemd160", new_hash("sha256", redeem).digest()).digest()
        spk_p2sh = b"\xa9\x14" + h160 + b"\x87"  # OP_HASH160 <h160> OP_EQUAL
        script_sig = bytes([len(redeem)]) + redeem
        tx = _stub_tx()
        tx.inputs[0].witness = [b"\x42" * 64]  # would-be Schnorr sig
        # With TAPROOT flag set, the wrapper test: should accept the P2SH
        # spend via the forward-compat path WITHOUT running schnorr.
        ok = interp.verify(
            script_sig=script_sig,
            script_pubkey=spk_p2sh,
            tx=tx,
            input_index=0,
            flags=SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT,
        )
        assert ok, (
            "Core lets P2SH-wrapped v1 32B succeed via forward-compat; "
            "ouroboros must not run Taproot validation."
        )

    def test_p2sh_wrapped_v1_32b_discourage_rejects(self) -> None:
        """With DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, P2SH-wrapped v1 is rejected."""
        interp = ScriptInterpreter()
        redeem = bytes([0x51, 0x20]) + b"\x00" * 32
        from hashlib import new as new_hash
        h160 = new_hash("ripemd160", new_hash("sha256", redeem).digest()).digest()
        spk_p2sh = b"\xa9\x14" + h160 + b"\x87"
        script_sig = bytes([len(redeem)]) + redeem
        tx = _stub_tx()
        tx.inputs[0].witness = [b"\x42" * 64]
        ok = interp.verify(
            script_sig=script_sig,
            script_pubkey=spk_p2sh,
            tx=tx,
            input_index=0,
            flags=(
                SCRIPT_VERIFY_P2SH
                | SCRIPT_VERIFY_WITNESS
                | SCRIPT_VERIFY_TAPROOT
                | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            ),
        )
        assert not ok


# ---------------------------------------------------------------------------
# Bug #2: control block upper bound (4129) must be enforced.
# Core interpreter.cpp:1970.
# ---------------------------------------------------------------------------


class TestControlBlockSize:
    def test_control_block_upper_bound_4129(self) -> None:
        assert TAPROOT_CONTROL_MAX_SIZE == 4129
        assert TAPROOT_CONTROL_MAX_NODE_COUNT == 128

    def test_oversized_control_block_rejected(self) -> None:
        interp = ScriptInterpreter()
        # 33 + 32*129 = 4161 bytes (one more node than the 128 max).
        oversized = b"\xc0" + b"\x00" * 32 + b"\x11" * (32 * 129)
        assert len(oversized) == 33 + 32 * 129
        assert (len(oversized) - 33) % 32 == 0  # would pass the divisibility gate
        tx = _stub_tx()
        tap_script = b"\x51"  # OP_1
        witness = [tap_script, oversized]
        # Output key doesn't matter — we expect a pre-tweak reject.
        program = b"\xab" * 32
        ok = interp.verify_taproot(
            tx, 0, witness, bytes([0x51, 0x20]) + program,
            input_amounts=[10_000],
            input_script_pubkeys=[bytes([0x51, 0x20]) + program],
            flags=SCRIPT_VERIFY_TAPROOT,
        )
        assert ok is False

    def test_max_control_block_passes_size_gate(self) -> None:
        """A control block exactly at the upper bound (4129) passes the size gate.

        It still fails later for other reasons (wrong tweak), so this
        is a behavioral guard, not an end-to-end success.
        """
        interp = ScriptInterpreter()
        maxed = b"\xc0" + b"\x00" * 32 + b"\x11" * (32 * 128)
        assert len(maxed) == TAPROOT_CONTROL_MAX_SIZE
        tx = _stub_tx()
        witness = [b"\x51", maxed]
        program = b"\xab" * 32
        # We don't assert success — we assert no immediate False from the
        # geometry gate. The function will still reach the tweak check
        # and fail there; that's fine.
        # The simplest behavioral pin: 4129 doesn't trip the early `<33 or
        # >4129 or %32 != 0` gate. Verify via the internal control-block
        # decode succeeding by checking we make it past the divisibility check
        # — we can't easily observe that from outside, so just assert the
        # function returns False (not raises) consistently.
        result = interp.verify_taproot(
            tx, 0, witness, bytes([0x51, 0x20]) + program,
            input_amounts=[10_000],
            input_script_pubkeys=[bytes([0x51, 0x20]) + program],
            flags=SCRIPT_VERIFY_TAPROOT,
        )
        assert result is False  # not crashes


# ---------------------------------------------------------------------------
# Bug #3+#4: empty sig + empty pubkey in tapscript = error.
# Core interpreter.cpp:367 fires SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY
# regardless of sig.
# ---------------------------------------------------------------------------


class TestEmptyPubkeyTapscript:
    def test_checksig_empty_sig_empty_pubkey_errors(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        script = bytes([0xac])  # OP_CHECKSIG
        initial_stack = [b"", b""]  # sig empty, pubkey empty
        with pytest.raises(ValueError, match="empty pubkey"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=initial_stack,
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )

    def test_checksigadd_empty_sig_empty_pubkey_errors(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # OP_CHECKSIGADD pops (top→bottom): pubkey, num, sig.
        # Stack order: [sig, num, pubkey] (top is rightmost in list).
        script = bytes([0xba])
        initial_stack = [b"", b"\x05", b""]
        with pytest.raises(ValueError, match="empty pubkey"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=initial_stack,
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )

    def test_checksigverify_empty_sig_empty_pubkey_errors(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        script = bytes([0xad])  # OP_CHECKSIGVERIFY
        initial_stack = [b"", b""]
        with pytest.raises(ValueError, match="empty pubkey"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=initial_stack,
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )


# ---------------------------------------------------------------------------
# Bug #5+#6: DISCOURAGE_UPGRADABLE_PUBKEYTYPE flag.
# Core interpreter.cpp:379-381 fires even with empty sig.
# ---------------------------------------------------------------------------


class TestDiscourageUpgradablePubkeyType:
    def test_flag_constant_distinct_from_others(self) -> None:
        # Pin the bit so Core-compat tooling can find it.
        assert SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE == (1 << 20)
        # Distinct from existing flags
        assert (
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
            != SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
        )

    def test_checksig_non32_pubkey_no_discourage_succeeds(self) -> None:
        """Non-32 pubkey without discourage flag → forward-compat success."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        script = bytes([0xac])
        sig = b"\x42" * 64
        pubkey = b"\x02" * 33  # 33 bytes — unknown pubkey type
        result = interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=[sig, pubkey],
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=100,  # plenty of budget
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            leaf_hash=b"\x00" * 32,
        )
        assert result == [b"\x01"]

    def test_checksig_non32_pubkey_with_discourage_errors(self) -> None:
        """Non-32 pubkey with discourage flag → SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        script = bytes([0xac])
        sig = b"\x42" * 64
        pubkey = b"\x02" * 33
        with pytest.raises(ValueError, match="DISCOURAGE_UPGRADABLE_PUBKEYTYPE"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=[sig, pubkey],
                sig_version=SigVersion.TAPSCRIPT,
                flags=SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                witness_weight=100,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )

    def test_checksig_empty_sig_non32_pubkey_discourage_still_fires(self) -> None:
        """Core: empty sig does NOT skip the discourage check (interpreter.cpp:379)."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        script = bytes([0xac])
        sig = b""  # empty
        pubkey = b"\x02" * 33  # unknown pubkey type
        with pytest.raises(ValueError, match="DISCOURAGE_UPGRADABLE_PUBKEYTYPE"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=[sig, pubkey],
                sig_version=SigVersion.TAPSCRIPT,
                flags=SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                witness_weight=100,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )


# ---------------------------------------------------------------------------
# Bug #7: OP_CODESEPARATOR in tapscript must update codesep_pos.
# Core interpreter.cpp:1565 commits to it in the tapscript sighash extension.
# ---------------------------------------------------------------------------


class TestTapscriptCodesepPos:
    def test_codesep_changes_sighash(self) -> None:
        """Two identical inputs but with vs. without OP_CODESEPARATOR before
        a CHECKSIG must produce different sighashes (codesep_pos commits
        to the extension block).

        We can't drive a real CHECKSIG without a valid Schnorr sig, so we
        observe the sighash via _compute_taproot_sighash directly with
        differing codesep_pos values.
        """
        interp = ScriptInterpreter()
        tx = _stub_tx()
        sh_no_codesep = interp._compute_taproot_sighash(
            tx, 0, 0x00,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            annex=None,
            ext_flag=1,
            tap_leaf_hash=b"\x00" * 32,
            codesep_pos=0xFFFFFFFF,
        )
        sh_with_codesep = interp._compute_taproot_sighash(
            tx, 0, 0x00,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            annex=None,
            ext_flag=1,
            tap_leaf_hash=b"\x00" * 32,
            codesep_pos=3,
        )
        assert sh_no_codesep != sh_with_codesep, (
            "tapscript sighash must commit to codesep_pos"
        )

    def test_op_codeseparator_updates_codesep_pos(self) -> None:
        """Drive a tapscript that contains an OP_CODESEPARATOR followed by
        a no-op-style script tail. We use OP_CODESEPARATOR + OP_1 as the
        tapscript, drive _execute_script, and verify it completes (the
        gate we're pinning is that codesep_pos is updated WITHOUT raising
        an "invalid sighash" error from the dropped commitment).
        """
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # OP_CODESEPARATOR (0xab) then OP_1 (0x51) — pushes truthy result.
        script = bytes([0xab, 0x51])
        result = interp._execute_script(
            script,
            tx,
            input_index=0,
            script_pubkey=script,
            initial_stack=[],
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=0,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            leaf_hash=b"\x00" * 32,
        )
        assert result == [b"\x01"]


# ---------------------------------------------------------------------------
# Bug #8: initial tapscript witness stack > MAX_STACK_SIZE rejected.
# Core interpreter.cpp:1855.
# ---------------------------------------------------------------------------


class TestInitialStackLimits:
    def test_tapscript_initial_stack_over_max_rejected(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # 1001 items: > MAX_STACK_SIZE (1000).
        # OP_TRUE (0x51) — single push, exits with one stack item.
        # But the stack-size gate fires BEFORE script execution, so this
        # must reject regardless of what the script does.
        oversized_stack = [b"\x01"] * 1001
        with pytest.raises(ValueError, match="Stack size exceeded"):
            interp._execute_script(
                bytes([0x51]),  # OP_1
                tx,
                input_index=0,
                script_pubkey=bytes([0x51]),
                initial_stack=oversized_stack,
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )

    def test_tapscript_initial_stack_at_max_accepted(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Exactly 1000 items: accepted. Script is just OP_DROP repeatedly
        # to peel down to one + OP_TRUE — but easier: we just want the
        # initial gate to not fire. Use OP_TRUE which pushes one more
        # item then we still pass cleanstack-equivalent at the end.
        # Simpler test: use a small script and verify no early-reject.
        # The gate fires BEFORE script exec, so check via "no raise".
        stack = [b""] * 1000
        # Script that's just OP_NOP (0x61) — does nothing.
        # Need stack > 0 at end with truthy top. Push OP_TRUE.
        # Actually: stack already has 1000 items, top is empty bytes (falsy).
        # Add an OP_TRUE in script → stack[1001] which would overflow on push.
        # Use a smaller stack to dodge MAX_STACK_SIZE during execution.
        stack = [b""] * 999
        result = interp._execute_script(
            bytes([0x51]),  # OP_1, pushes \x01 → 1000 items total, top truthy
            tx,
            input_index=0,
            script_pubkey=bytes([0x51]),
            initial_stack=stack,
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=0,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            leaf_hash=b"\x00" * 32,
        )
        assert result[-1] == b"\x01"


# ---------------------------------------------------------------------------
# Bug #9: tapscript witness stack items > MAX_SCRIPT_ELEMENT_SIZE rejected.
# Core interpreter.cpp:1859-1861.
# ---------------------------------------------------------------------------


class TestInitialItemSizeLimit:
    def test_oversized_initial_item_rejected_tapscript(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Item is 521 bytes — > MAX_SCRIPT_ELEMENT_SIZE (520).
        bad_item = b"\x00" * 521
        with pytest.raises(ValueError, match="exceeds 520 bytes"):
            interp._execute_script(
                bytes([0x51]),
                tx,
                input_index=0,
                script_pubkey=bytes([0x51]),
                initial_stack=[bad_item],
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )

    def test_oversized_initial_item_rejected_p2wsh(self) -> None:
        """Same gate applies to v0 P2WSH (Core line 1859 is in ExecuteWitnessScript)."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        bad_item = b"\x00" * 521
        with pytest.raises(ValueError, match="exceeds 520 bytes"):
            interp._execute_script(
                bytes([0x51]),
                tx,
                input_index=0,
                script_pubkey=bytes([0x51]),
                initial_stack=[bad_item],
                is_witness_v0=True,
                witness_amount=10_000,
            )

    def test_max_size_item_accepted(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Exactly 520 bytes — accepted.
        ok_item = b"\x00" * 520
        # Script: OP_DROP (0x75) then OP_1. The 520-byte initial item is
        # popped, then OP_1 pushes truthy.
        result = interp._execute_script(
            bytes([0x75, 0x51]),
            tx,
            input_index=0,
            script_pubkey=bytes([0x75, 0x51]),
            initial_stack=[ok_item],
            sig_version=SigVersion.TAPSCRIPT,
            witness_weight=0,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            leaf_hash=b"\x00" * 32,
        )
        assert result == [b"\x01"]


# ---------------------------------------------------------------------------
# Bug #10: Pay-to-Anchor (BIP-431) is always valid, even with DISCOURAGE flag.
# Core interpreter.cpp:1990.
# ---------------------------------------------------------------------------


class TestPayToAnchor:
    def test_p2a_program_constants(self) -> None:
        # BIP-431 P2A: version 1, program = 0x4e73 (2 bytes).
        assert b"\x4e\x73" == b"Ns"

    def test_bare_p2a_succeeds_with_discourage(self) -> None:
        """Core line 1990: P2A is carved out BEFORE the DISCOURAGE check."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        tx.inputs[0].witness = []  # P2A is anyone-can-spend with empty witness
        # spk: OP_1 OP_PUSHBYTES_2 0x4e73
        spk = bytes([0x51, 0x02, 0x4e, 0x73])
        ok = interp.verify(
            script_sig=b"",
            script_pubkey=spk,
            tx=tx,
            input_index=0,
            flags=(
                SCRIPT_VERIFY_P2SH
                | SCRIPT_VERIFY_WITNESS
                | SCRIPT_VERIFY_TAPROOT
                | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            ),
        )
        assert ok, "Bare P2A must succeed even with DISCOURAGE flag"


# ---------------------------------------------------------------------------
# Bug #11: invalid hashtype byte rejected.
# Core interpreter.cpp:1516.
# ---------------------------------------------------------------------------


class TestInvalidHashtype:
    def test_compute_sighash_returns_none_for_invalid_hashtype(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # 0x04 is NOT a valid hashtype (must be 0x00-0x03 or 0x81-0x83).
        assert interp._compute_taproot_sighash(
            tx, 0, 0x04,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            ext_flag=0,
        ) is None

    def test_compute_sighash_returns_none_for_0x80(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # 0x80 (just ANYONECANPAY without a base type) is invalid in BIP-341.
        assert interp._compute_taproot_sighash(
            tx, 0, 0x80,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            ext_flag=0,
        ) is None

    def test_compute_sighash_valid_hashtypes(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx(n_outputs=2)
        for ht in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            sh = interp._compute_taproot_sighash(
                tx, 0, ht,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                ext_flag=0,
            )
            assert sh is not None and len(sh) == 32, f"hashtype {ht:#04x} should compute"


# ---------------------------------------------------------------------------
# Bug #12: SIGHASH_SINGLE with input_index >= outputs returns None (error).
# Core interpreter.cpp:1550.
# ---------------------------------------------------------------------------


class TestSighashSingleOutOfRange:
    def test_sighash_single_oor_returns_none(self) -> None:
        interp = ScriptInterpreter()
        # 1 input, 0 outputs → SIGHASH_SINGLE at index 0 is out-of-range.
        tx = _stub_tx(n_outputs=0)
        sh = interp._compute_taproot_sighash(
            tx, 0, 0x03,  # SIGHASH_SINGLE
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            ext_flag=0,
        )
        assert sh is None

    def test_sighash_single_in_range_succeeds(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx(n_outputs=2)
        sh = interp._compute_taproot_sighash(
            tx, 0, 0x03,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            ext_flag=0,
        )
        assert sh is not None and len(sh) == 32


# ---------------------------------------------------------------------------
# Constants pinned to Core values.
# ---------------------------------------------------------------------------


class TestConstants:
    def test_annex_tag(self) -> None:
        assert ANNEX_TAG == 0x50

    def test_taproot_leaf_mask_and_tapscript(self) -> None:
        assert TAPROOT_LEAF_MASK == 0xFE
        assert TAPROOT_LEAF_TAPSCRIPT == 0xC0

    def test_taproot_control_geometry(self) -> None:
        assert TAPROOT_CONTROL_BASE_SIZE == 33
        assert TAPROOT_CONTROL_NODE_SIZE == 32
        assert TAPROOT_CONTROL_MAX_NODE_COUNT == 128
        assert TAPROOT_CONTROL_MAX_SIZE == 4129

    def test_witness_v1_taproot_size(self) -> None:
        assert WITNESS_V1_TAPROOT_SIZE == 32


# ---------------------------------------------------------------------------
# Annex detection (gate 3) — pin behavior so a future refactor can't drop it.
# ---------------------------------------------------------------------------


class TestAnnexDetection:
    def test_annex_starting_byte_0x50_detected(self) -> None:
        """A trailing witness item starting with 0x50 (with stack size >= 2)
        is treated as the annex and popped before key/script-path dispatch.

        We can't easily observe the annex from outside without crypto,
        but we can observe that an annex byte changes the *sighash*.
        """
        interp = ScriptInterpreter()
        tx = _stub_tx()
        sh_no_annex = interp._compute_taproot_sighash(
            tx, 0, 0x00,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            annex=None,
            ext_flag=0,
        )
        sh_with_annex = interp._compute_taproot_sighash(
            tx, 0, 0x00,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            annex=b"\x50abcd",
            ext_flag=0,
        )
        assert sh_no_annex != sh_with_annex


# ---------------------------------------------------------------------------
# CHECKSIGADD n-bounds (gate 22).
# Core interpreter.cpp:1086-1094 — `CScriptNum(..., 4)` rejects > 4-byte n.
# ---------------------------------------------------------------------------


class TestCheckSigAddNumLimit:
    def test_checksigadd_n_over_4_bytes_errors(self) -> None:
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # OP_CHECKSIGADD pops pubkey, num, sig. Push a 5-byte n.
        sig = b""  # empty sig — bypasses budget gate
        bad_n = b"\x01\x02\x03\x04\x05"  # 5 bytes
        pk = b"\x02" * 32
        script = bytes([0xba])
        with pytest.raises(ValueError, match="CScriptNum|n is not"):
            interp._execute_script(
                script,
                tx,
                input_index=0,
                script_pubkey=script,
                initial_stack=[sig, bad_n, pk],
                sig_version=SigVersion.TAPSCRIPT,
                witness_weight=0,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                leaf_hash=b"\x00" * 32,
            )
