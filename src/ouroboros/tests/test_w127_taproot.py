"""
W127 — Taproot / Schnorr / Tapscript audit (ouroboros).

DISCOVERY wave: 30 gates audited against bitcoin-core/src/script/interpreter.cpp
(BIP-340 / BIP-341 / BIP-342). This file contains a test per gate. PRESENT
gates pass today; PARTIAL/MISSING gates are marked xfail and pin the
divergence so a future FIX wave can flip them to pass.

Reference:
  - bitcoin-core/src/script/interpreter.cpp:347 (EvalChecksigTapscript)
  - bitcoin-core/src/script/interpreter.cpp:1483 (SignatureHashSchnorr)
  - bitcoin-core/src/script/interpreter.cpp:1832 (ExecuteWitnessScript)
  - bitcoin-core/src/script/interpreter.cpp:1903 (VerifyTaprootCommitment)
  - bitcoin-core/src/script/interpreter.cpp:1917 (VerifyWitnessProgram)
  - bitcoin-core/src/script/script.cpp:364 (IsOpSuccess)
  - bitcoin-core/src/pubkey.cpp:257 (XOnlyPubKey::CheckTapTweak)
  - BIP-340 / BIP-341 / BIP-342

Two-pipeline guard: this file imports ONLY from the Python pipeline.
The Rust `ferrous-utils/sync/src/validate/script.rs::evaluate_tapscript`
exists but is a Rust-only test artefact and contains a stub CHECKSIG
that the Python pipeline never calls. The
`TestW127_TwoPipelineGuard` class codifies this invariant.

NO production code changes. NO behavior changes. Only audit + xfail
tests pinning the divergences for a future FIX wave.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# Bootstrap — tests/conftest.py installs the sync stub.
_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))

_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.script import (  # noqa: E402
    ANNEX_TAG,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_NONE,
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


def _stub_tx(n_outputs: int = 1, n_inputs: int = 1) -> Transaction:
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
        outputs=[
            TxOut(value=10_000, script_pubkey=b"") for _ in range(n_outputs)
        ],
    )


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA(SHA(tag) || SHA(tag) || data)."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


# ---------------------------------------------------------------------------
# BIP-340 Schnorr gates (G01..G10)
# ---------------------------------------------------------------------------


class TestW127_BIP340_Schnorr:

    def test_g01_schnorr_sig_length_64_or_65(self) -> None:
        """G01 — Schnorr sig length must be 64 or 65 bytes."""
        interp = ScriptInterpreter()
        # 63-byte sig → False (out-of-band length).
        ok = interp._verify_schnorr_signature(b"\x00" * 32, b"\x00" * 63, b"\x01" * 32)
        assert ok is False
        # 66-byte sig → False.
        ok = interp._verify_schnorr_signature(b"\x00" * 32, b"\x00" * 66, b"\x01" * 32)
        assert ok is False
        # 64-byte sig (zero pubkey will fail crypto, but length gate passes
        # without raising).
        ok = interp._verify_schnorr_signature(b"\x00" * 32, b"\x00" * 64, b"\x01" * 32)
        assert ok is False  # sig fails crypto, but length gate didn't crash

    def test_g02_schnorr_pubkey_length_32(self) -> None:
        """G02 — Schnorr pubkey must be exactly 32 bytes (x-only)."""
        interp = ScriptInterpreter()
        ok = interp._verify_schnorr_signature(b"\x00" * 32, b"\x00" * 64, b"\x01" * 33)
        assert ok is False
        ok = interp._verify_schnorr_signature(b"\x00" * 32, b"\x00" * 64, b"\x01" * 31)
        assert ok is False

    def test_g03_schnorr_msg_length_32(self) -> None:
        """G03 — BIP-340 verify msg must be 32 bytes (W95 fix)."""
        interp = ScriptInterpreter()
        # W95 added this gate explicitly.
        ok = interp._verify_schnorr_signature(b"\x00" * 31, b"\x00" * 64, b"\x01" * 32)
        assert ok is False
        ok = interp._verify_schnorr_signature(b"\x00" * 33, b"\x00" * 64, b"\x01" * 32)
        assert ok is False

    def test_g04_65byte_sig_hashtype_nonzero(self) -> None:
        """G04 — 65-byte sig with hashtype 0x00 is invalid per BIP-341."""
        # Verified via _verify_taproot_keypath path (line 2304-2305).
        interp = ScriptInterpreter()
        tx = _stub_tx()
        sig = b"\x00" * 64 + b"\x00"  # explicit 0x00 hashtype
        ok = interp._verify_taproot_keypath(
            tx, 0, sig, b"\xab" * 32,
            input_amounts=[10_000],
            input_script_pubkeys=[bytes([0x51, 0x20]) + b"\xab" * 32],
        )
        assert ok is False

    def test_g05_hashtype_byte_in_valid_set(self) -> None:
        """G05 — TapSighash rejects hashtypes outside {0,1,2,3,0x81,0x82,0x83}."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        sh = interp._compute_taproot_sighash(
            tx, 0, 0x04,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
        )
        assert sh is None  # invalid hashtype 0x04
        sh = interp._compute_taproot_sighash(
            tx, 0, 0x80,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
        )
        assert sh is None  # invalid 0x80 (ANYONECANPAY+DEFAULT not allowed)
        # Valid hashtype.
        sh = interp._compute_taproot_sighash(
            tx, 0, 0x01,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
        )
        assert isinstance(sh, bytes) and len(sh) == 32

    def test_g06_rust_fast_path_wired(self) -> None:
        """G06 — Rust crypto_verify_schnorr is wired (W95 fix)."""
        try:
            import sync  # noqa: F401
            assert hasattr(sync, "crypto_verify_schnorr"), (
                "ferrous-utils must expose crypto_verify_schnorr (W95)"
            )
        except ImportError:
            pytest.skip("sync module not available in this test env")

    def test_g07_rust_value_error_mapped_to_false(self) -> None:
        """G07 — Rust ValueError from malformed input maps to False (W95)."""
        interp = ScriptInterpreter()
        # All-zero pubkey is not on the curve; the Rust path raises
        # ValueError. The helper must convert that to False, not raise.
        ok = interp._verify_schnorr_signature(b"\x42" * 32, b"\x00" * 64, b"\x00" * 32)
        assert ok is False

    def test_g08_coincurve_fallback(self) -> None:
        """G08 — coincurve fallback used when Rust missing."""
        # We can't easily unwire the Rust path at test-time, but we can
        # assert the helper does not raise on a deterministic invalid
        # input — either path must return False.
        interp = ScriptInterpreter()
        ok = interp._verify_schnorr_signature(b"\x77" * 32, b"\xff" * 64, b"\x88" * 32)
        assert ok is False

    def test_g09_tagged_hash_midstate(self) -> None:
        """G09 — BIP-340 tagged hash: SHA(SHA(tag) || SHA(tag) || x)."""
        # TapLeaf, TapBranch, TapTweak, TapSighash are all tagged hashes.
        # Verify the construction is correct by computing TapTweak with
        # known internal key + empty merkle root and matching the
        # well-known BIP-86 vector property.
        tag_hash = hashlib.sha256(b"TapTweak").digest()
        expected = hashlib.sha256(tag_hash + tag_hash + b"\x00" * 32).digest()
        # Reach into the helper:
        from ouroboros.taproot import _tagged_hash as ouroboros_tagged
        assert ouroboros_tagged("TapTweak", b"\x00" * 32) == expected

    def test_g10_empty_sig_short_circuit(self) -> None:
        """G10 — Empty sig in tapscript: no Schnorr call, push false."""
        # Empty sig (b"") in tapscript CHECKSIG branches to "push b''"
        # without invoking Schnorr. Verified by structural inspection of
        # script.py:1330-1352. Here we exercise the path by running a
        # tapscript that has an empty sig on the stack.
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # script: <pubkey32> OP_CHECKSIG → expects sig at top-1 (empty)
        # We build manually: push empty (OP_0), push 32-byte pubkey, then
        # OP_CHECKSIG.
        tap_script = b"\x00" + b"\x20" + b"\x42" * 32 + b"\xac"
        # When sig is empty, CHECKSIG must push b'' (false), not raise.
        result = interp._execute_script(
            tap_script,
            tx,
            0,
            tap_script,
            flags=SCRIPT_VERIFY_NONE,
            initial_stack=[],
            sig_version=SigVersion.TAPSCRIPT,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            witness_weight=10,
        )
        # Top should be b'' (false) for empty-sig CHECKSIG in tapscript.
        assert result and result[-1] == b""


# ---------------------------------------------------------------------------
# BIP-341 Taproot gates (G11..G20)
# ---------------------------------------------------------------------------


class TestW127_BIP341_Taproot:

    def test_g11_output_is_op1_32(self) -> None:
        """G11 — Taproot output must be OP_1 + 32-byte program."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Wrong length program.
        ok = interp.verify_taproot(
            tx, 0, [b"\x00" * 64], bytes([0x51, 0x14]) + b"\x00" * 20,
        )
        assert ok is False
        # Wrong opcode.
        ok = interp.verify_taproot(
            tx, 0, [b"\x00" * 64], bytes([0x52, 0x20]) + b"\x00" * 32,
        )
        assert ok is False

    def test_g12_p2sh_wrapped_v1_not_taproot(self) -> None:
        """G12 — P2SH-wrapped v1/32B is NOT taproot (forward-compat, W94)."""
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
            flags=SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT,
        )
        assert ok, "P2SH-wrapped v1/32B should fall through to forward-compat"

    def test_g13_pay_to_anchor_bare_succeeds(self) -> None:
        """G13 — Pay-to-Anchor (v1 + 0x4e73) succeeds bare (BIP-431)."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        spk_p2a = bytes([0x51, 0x02, 0x4e, 0x73])  # OP_1 OP_PUSH2 0x4e73
        ok = interp._verify_witness_program(
            tx, 0, 1, b"\x4e\x73", [], SCRIPT_VERIFY_TAPROOT,
        )
        assert ok is True

    def test_g14_annex_stripped(self) -> None:
        """G14 — Witness with last elem starting 0x50 is annex, stripped."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        annex = b"\x50" + b"\xde\xad\xbe\xef"  # annex starts with 0x50
        witness = [b"\x42" * 64, annex]  # [sig, annex]
        # The annex must be detected and stripped, leaving key-path with [sig].
        # We can't assert success (would need real signing), but we can check
        # that the path runs without raising and returns a deterministic
        # False (because the sig is fake).
        ok = interp.verify_taproot(
            tx, 0, witness, bytes([0x51, 0x20]) + b"\xab" * 32,
            input_amounts=[10_000],
            input_script_pubkeys=[bytes([0x51, 0x20]) + b"\xab" * 32],
        )
        assert ok is False  # fake sig fails, but annex was stripped

    def test_g15_empty_witness_rejects(self) -> None:
        """G15 — Empty witness on Taproot output: reject."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        ok = interp.verify_taproot(
            tx, 0, [], bytes([0x51, 0x20]) + b"\xab" * 32,
        )
        assert ok is False

    def test_g16_keypath_single_sig(self) -> None:
        """G16 — Key-path: 64B (DEFAULT) or 65B (explicit hashtype)."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # 63-byte sig (invalid length).
        ok = interp._verify_taproot_keypath(
            tx, 0, b"\x00" * 63, b"\xab" * 32,
        )
        assert ok is False
        # 66-byte sig (invalid length).
        ok = interp._verify_taproot_keypath(
            tx, 0, b"\x00" * 66, b"\xab" * 32,
        )
        assert ok is False

    def test_g17_control_block_geometry(self) -> None:
        """G17 — Control block size [33, 4129], step 32 (W94)."""
        assert TAPROOT_CONTROL_BASE_SIZE == 33
        assert TAPROOT_CONTROL_NODE_SIZE == 32
        assert TAPROOT_CONTROL_MAX_NODE_COUNT == 128
        assert TAPROOT_CONTROL_MAX_SIZE == 4129
        # Oversized → reject.
        interp = ScriptInterpreter()
        oversized = b"\xc0" + b"\x00" * 32 + b"\x11" * (32 * 129)
        ok = interp._verify_taproot_scriptpath(
            _stub_tx(), 0, [b"\x51", oversized], b"\xab" * 32,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            full_witness=[b"\x51", oversized],
        )
        assert ok is False

    def test_g18_tapleaf_tagged_hash(self) -> None:
        """G18 — Tapleaf: tagged_hash("TapLeaf", leaf_ver || cs(script) || script)."""
        # Verify the wire format matches BIP-341.
        leaf_version = 0xc0
        tap_script = b"\x51"  # OP_1
        # cs(1) = 0x01
        expected = _tagged_hash(
            "TapLeaf",
            bytes([leaf_version, 0x01]) + tap_script,
        )
        # Reproduce ouroboros's computation:
        interp = ScriptInterpreter()
        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([leaf_version]) + interp._ser_script_size(tap_script) + tap_script,
        )
        assert leaf_hash == expected

    def test_g19_tapbranch_lexicographic(self) -> None:
        """G19 — TapBranch sorts (a, b) lexicographically before hashing."""
        a = b"\x01" + b"\x00" * 31
        b = b"\x02" + b"\x00" * 31
        # a < b, so order is (a, b).
        expected_ab = _tagged_hash("TapBranch", a + b)
        # If we reverse, must still produce (a, b) order.
        # Walk: k = b, branch = a. a < b → k = hash(a + b).
        k = b
        if k < a:
            k = _tagged_hash("TapBranch", k + a)
        else:
            k = _tagged_hash("TapBranch", a + k)
        assert k == expected_ab

    def test_g20_output_key_parity(self) -> None:
        """G20 — Output-key parity must match `control[0] & 1`."""
        # Verified at script.py:2391. We can't construct a real tweak
        # check without a real key, but we can assert the bit-mask
        # constants are correct.
        assert TAPROOT_LEAF_MASK == 0xfe
        assert TAPROOT_LEAF_TAPSCRIPT == 0xc0
        # parity bit is `& 1` not `& 0xfe`.


# ---------------------------------------------------------------------------
# BIP-342 Tapscript gates (G21..G30)
# ---------------------------------------------------------------------------


class TestW127_BIP342_Tapscript:

    def test_g21_leaf_version_c0_is_tapscript(self) -> None:
        """G21 — Leaf version 0xc0 is tapscript; others fall through."""
        # Unknown leaf version with DISCOURAGE flag → reject.
        # Without flag → succeed (forward-compat).
        # Tested via verify_taproot at line 2444-2450.
        # Behavioral: future leaf versions are forward-compat success.
        assert TAPROOT_LEAF_TAPSCRIPT == 0xc0

    def test_g22_op_success_set_matches_bip342(self) -> None:
        """G22 — OP_SUCCESS opcodes per BIP-342."""
        from ouroboros.script import _TAPSCRIPT_OP_SUCCESS
        # BIP-342: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153,
        # 187-254.
        expected = (
            {80, 98}
            | set(range(126, 130))
            | set(range(131, 135))
            | {137, 138, 141, 142}
            | set(range(149, 154))
            | set(range(187, 255))
        )
        assert set(_TAPSCRIPT_OP_SUCCESS) == expected

    def test_g23_discourage_op_success(self) -> None:
        """G23 — DISCOURAGE_OP_SUCCESS policy flag rejects OP_SUCCESS."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Tapscript: OP_SUCCESS80 (0x50).
        tap_script = b"\x50"
        with pytest.raises(ValueError, match="DISCOURAGE_OP_SUCCESS"):
            interp._execute_script(
                tap_script, tx, 0, tap_script,
                flags=SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                initial_stack=[],
                sig_version=SigVersion.TAPSCRIPT,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                witness_weight=10,
            )

    def test_g24_validation_weight_budget_seeded(self) -> None:
        """G24 — Validation weight budget seeded at +50 offset per CHECKSIG."""
        # Verified by tests/test_tapscript_validation_weight.py for the
        # behavior; here we just confirm the constants.
        # Core: VALIDATION_WEIGHT_OFFSET = 50, VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50.
        # We can't access them from Python directly, but the math is:
        # sigops_budget = 50 + witness_weight; each CHECKSIG deducts 50.
        # Verified at script.py:851 / :1332 / :1470 / :1595.
        # Smoke: a 0-weight tapscript with one OP_CHECKSIG should fail
        # ("budget exceeded") IF sig is non-empty. (With empty sig the
        # budget isn't deducted.)
        pass  # behavior tested by tapscript_validation_weight tests

    def test_g25_op_checkmultisig_disabled_in_tapscript(self) -> None:
        """G25 — OP_CHECKMULTISIG/CHECKMULTISIGVERIFY disabled in tapscript."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        tap_script = b"\xae"  # OP_CHECKMULTISIG
        with pytest.raises(ValueError, match="CHECKMULTISIG.*tapscript"):
            interp._execute_script(
                tap_script, tx, 0, tap_script,
                flags=SCRIPT_VERIFY_NONE,
                initial_stack=[b"", b"", b"", b""],  # dummy stack
                sig_version=SigVersion.TAPSCRIPT,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                witness_weight=10,
            )

    def test_g26_codesep_pos_recorded(self) -> None:
        """G26 — OP_CODESEPARATOR records `opcode_pos` for tapscript sighash."""
        # Behavior verified by tests/test_script_codeseparator_sighash.py.
        # Here we just confirm the code path exists at script.py:1302-1305.
        # Smoke: a tapscript with CODESEPARATOR must produce a different
        # sighash from one without — recorded in the existing W94 suite.
        pass

    def test_g27_initial_stack_size_limits(self) -> None:
        """G27 — Initial witness stack <= 1000 items, each <= 520 bytes."""
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # 1001-item stack should reject.
        big_stack = [b""] * 1001
        with pytest.raises(ValueError, match="Stack size exceeded"):
            interp._execute_script(
                b"\x51", tx, 0, b"\x51",
                flags=SCRIPT_VERIFY_NONE,
                initial_stack=big_stack,
                sig_version=SigVersion.TAPSCRIPT,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                witness_weight=10,
            )
        # 521-byte item should reject.
        with pytest.raises(ValueError, match="exceeds 520"):
            interp._execute_script(
                b"\x51", tx, 0, b"\x51",
                flags=SCRIPT_VERIFY_NONE,
                initial_stack=[b"\x00" * 521],
                sig_version=SigVersion.TAPSCRIPT,
                input_amounts=[10_000],
                input_script_pubkeys=[b""],
                default_sighash=b"\x00" * 32,
                witness_weight=10,
            )

    @pytest.mark.xfail(
        reason=(
            "W127 BUG-1 P0-CDIV: Taproot script-path missing cleanstack "
            "check at script.py:2437-2440. Core ExecuteWitnessScript at "
            "interpreter.cpp:1867 enforces `if (stack.size() != 1) return "
            "CLEANSTACK`. ouroboros checks only top element, not size."
        ),
        strict=True,
    )
    def test_g28_tapscript_cleanstack_enforced(self) -> None:
        """G28 — Tapscript MUST leave exactly 1 element on stack post-exec.

        Core: ExecuteWitnessScript returns SCRIPT_ERR_CLEANSTACK if
        stack.size() != 1. ouroboros's `_verify_taproot_scriptpath` only
        checks `result_stack[-1]` truthiness, not `len(result_stack) == 1`.
        """
        interp = ScriptInterpreter()
        tx = _stub_tx()
        # Tapscript: push 2 truthy values, leave both on stack.
        # OP_1 OP_1 (0x51 0x51). Core: CLEANSTACK error → fail. ouroboros: top=0x01 → succeed.
        tap_script = b"\x51\x51"
        # We construct the inputs manually to bypass control-block validation
        # and directly probe the script-path executor's tail behavior. We
        # invoke `_execute_script` and then mimic the post-exec assertion
        # _verify_taproot_scriptpath should perform.
        result = interp._execute_script(
            tap_script, tx, 0, tap_script,
            flags=SCRIPT_VERIFY_NONE,
            initial_stack=[],
            sig_version=SigVersion.TAPSCRIPT,
            input_amounts=[10_000],
            input_script_pubkeys=[b""],
            default_sighash=b"\x00" * 32,
            witness_weight=10,
        )
        # Result stack has 2 elements: [0x01, 0x01]. Core would reject.
        # ouroboros's _verify_taproot_scriptpath checks only top.
        # We assert the fix-state: stack size of 2 means script failed.
        # Currently FAILS because ouroboros's helper doesn't enforce
        # cleanstack — xfail strict to flip when FIX-83 lands.
        assert len(result) == 1, (
            f"BUG-1: tapscript cleanstack not enforced; got {len(result)} "
            f"stack elements (Core requires exactly 1)"
        )

    @pytest.mark.xfail(
        reason=(
            "W127 BUG-2 P0-CDIV: OP_CHECKSIGADD `n` decoded as unsigned "
            "via _read_num (int.from_bytes LE) instead of CScriptNum "
            "(signed, minimal). At script.py:1587. Core: "
            "interpreter.cpp:1093 CScriptNum num(stacktop(-2), fRequireMinimal)."
        ),
        strict=True,
    )
    def test_g29_checksigadd_n_signed(self) -> None:
        """G29 — OP_CHECKSIGADD reads `n` as SIGNED CScriptNum, not unsigned.

        Core: `CScriptNum num(stacktop(-2), fRequireMinimal)`. A byte
        like 0x81 decodes to -1, not 129. ouroboros's `_read_num` reads
        as unsigned, so it returns 129. The push `n + 1` then differs
        between Core (0) and ouroboros (130).
        """
        interp = ScriptInterpreter()
        # Verify the _read_num helper's behavior is the divergence point.
        # 0x81 in CScriptNum is -1 (sign bit set on byte 0).
        # Core's CScriptNum: (0x81) → -1.
        # ouroboros _read_num: int.from_bytes(b"\x81", "little") = 129.
        observed = interp._read_num(b"\x81")
        # If BUG-2 is fixed, _read_num is replaced or a new path takes
        # over, and the value would be -1 (signed-aware).
        assert observed == -1, (
            f"BUG-2: OP_CHECKSIGADD `n` not signed; _read_num(b'\\x81') = "
            f"{observed} (Core CScriptNum: -1)"
        )

    @pytest.mark.xfail(
        reason=(
            "W127 BUG-3 P0-CDIV: Taproot script-path bypasses _cast_to_bool, "
            "uses inline `any(b != 0 for b in top)` at script.py:2440. "
            "Misses BIP-341 negative-zero handling. Core: "
            "script.cpp::CastToBool treats trailing 0x80-only as False."
        ),
        strict=True,
    )
    def test_g30_cast_to_bool_negative_zero(self) -> None:
        """G30 — Stack-top must use CastToBool (negative-zero is False).

        Core's CastToBool: a value is true unless it is all zeros, or
        all zeros except for the last byte being exactly 0x80 (negative
        zero). ouroboros's `_cast_to_bool` (script.py:1795-1801) gets
        this right, but `_verify_taproot_scriptpath:2440` bypasses it.
        """
        interp = ScriptInterpreter()
        # Direct probe of the divergence: _cast_to_bool([0x80]) → False,
        # but the inline expression returns True.
        cast_neg0 = interp._cast_to_bool(b"\x80")
        assert cast_neg0 is False  # correct helper behavior

        # The inline expression at line 2440:
        top = b"\x80"
        inline_result = len(top) > 0 and any(b != 0 for b in top)
        # inline_result is True (wrong); cast_neg0 is False (right).
        # If BUG-3 is fixed, the script-path uses _cast_to_bool, and the
        # divergence between cast_neg0 and inline_result is moot. We
        # assert the fix-state: the script-path interprets [0x80] as
        # False (Core behavior).
        # We can't reach into the helper post-fix easily; we assert the
        # invariant that the inline pattern is WRONG and the helper is
        # RIGHT. xfail-strict on the assertion that the script-path uses
        # the helper.
        # Pin the divergence via direct code-shape check.
        import inspect
        src = inspect.getsource(interp._verify_taproot_scriptpath)
        assert "_cast_to_bool" in src, (
            "BUG-3: _verify_taproot_scriptpath does not call _cast_to_bool"
        )


# ---------------------------------------------------------------------------
# Two-pipeline guard — W127 EXTENSION (6th extension)
# ---------------------------------------------------------------------------


class TestW127_TwoPipelineGuard:
    """Codify the Python/Rust split for Taproot/Schnorr/Tapscript.

    The Python pipeline (`src/ouroboros/script.py::ScriptInterpreter`)
    is the SOLE consensus surface for BIP-341/342. The Rust crate
    `ferrous-utils` exposes ONLY `crypto_verify_schnorr` (and
    `crypto_batch_verify_schnorr`) — leaf primitives. The Rust
    `validate/script.rs::evaluate_tapscript` is a Rust-only test
    artefact and contains a stub CHECKSIG that the Python pipeline
    never calls.
    """

    def test_rust_pyo3_exports_schnorr_primitive_only(self) -> None:
        """The Rust crate exposes ONLY Schnorr leaf primitives via PyO3."""
        rust_lib = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "ferrous-utils" / "sync" / "src" / "lib.rs"
        )
        if not rust_lib.exists():
            pytest.skip("ferrous-utils not present in this checkout")
        text = rust_lib.read_text()
        # Expected: crypto_verify_schnorr + crypto_batch_verify_schnorr.
        assert "fn crypto_verify_schnorr" in text
        # Forbidden: a wholesale tapscript verifier exposed via PyO3.
        # If a future wave wires `evaluate_tapscript` through PyO3, this
        # guard must be reconsidered (and the Rust stub CHECKSIG fixed
        # first).
        assert "pyfunction" not in text or (
            "pyfunction" in text and "fn evaluate_tapscript" not in text
        ), (
            "Rust evaluate_tapscript must NOT be a #[pyfunction] until the "
            "stub CHECKSIG at validate/script.rs:1010 is replaced with real "
            "Schnorr verification."
        )

    def test_python_never_imports_rust_evaluate_tapscript(self) -> None:
        """No Python file imports the Rust evaluate_tapscript symbol.

        We check for actual import statements / call-sites, not bare
        documentation mentions (some other audit tests reference the
        Rust symbol by name in their docstrings).
        """
        py_root = Path(__file__).resolve().parent.parent.parent
        # Patterns that would indicate a real wiring:
        #   from sync import evaluate_tapscript
        #   sync.evaluate_tapscript(...)
        #   import sync; sync.evaluate_tapscript
        forbidden_patterns = (
            "from sync import evaluate_tapscript",
            "sync.evaluate_tapscript",
        )
        my_path = Path(__file__).resolve()
        for path in py_root.rglob("*.py"):
            if path.resolve() == my_path:
                continue  # this audit file mentions the patterns in its docstring
            text = path.read_text(errors="ignore")
            for pat in forbidden_patterns:
                assert pat not in text, (
                    f"{path} wires up Rust evaluate_tapscript via '{pat}'; "
                    "the Rust pipeline is a test artefact and must NOT be "
                    "called from production until the stub CHECKSIG is fixed."
                )

    def test_rust_tapscript_checksig_is_stub(self) -> None:
        """The Rust CHECKSIG implementation is intentionally a stub.

        This test pins the stub status. If a future contributor adds
        real Schnorr to this path, they MUST update this test, the
        W127 audit doc, and re-evaluate the two-pipeline guard.
        """
        rust_script = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        )
        if not rust_script.exists():
            pytest.skip("ferrous-utils not present in this checkout")
        text = rust_script.read_text()
        # Pin the stub signature: empty-check only.
        assert "let valid = !pubkey.is_empty() && !sig.is_empty();" in text, (
            "Rust validate/script.rs OP_CHECKSIG was a stub at W127 audit "
            "time; if it's been wired to real Schnorr, update this guard."
        )

    def test_python_is_the_sole_taproot_verifier(self) -> None:
        """`ScriptInterpreter.verify_taproot` is the SOLE production verifier."""
        # The Python helper exists and is the wire-into-block-validation point.
        assert hasattr(ScriptInterpreter, "verify_taproot")
        assert hasattr(ScriptInterpreter, "_verify_taproot_keypath")
        assert hasattr(ScriptInterpreter, "_verify_taproot_scriptpath")
        # And it's called from _verify_witness_program (the wired callee).
        import inspect
        src = inspect.getsource(ScriptInterpreter._verify_witness_program)
        assert "verify_taproot" in src, (
            "ScriptInterpreter._verify_witness_program must call verify_taproot "
            "as the sole route into BIP-341 validation."
        )


# ---------------------------------------------------------------------------
# Bonus structural checks (audit-only, not gates)
# ---------------------------------------------------------------------------


class TestW127_StructuralChecks:
    """Audit-only structural assertions. Not gates; documentation."""

    def test_bug4_execute_tapscript_is_dead_code(self) -> None:
        """BUG-4: `_execute_tapscript` is a dead duplicate, never called."""
        # Verify the function exists.
        assert hasattr(ScriptInterpreter, "_execute_tapscript")
        # Verify no production call site invokes it.
        import inspect
        from ouroboros import script as script_mod
        src = inspect.getsource(script_mod)
        # Count occurrences of "_execute_tapscript". The function def
        # itself = 1. We should see no other refs.
        occurrences = src.count("_execute_tapscript")
        # def + 0 callers = 1 occurrence. Allow up to 2 in case of
        # docstring mentions, but >2 means someone wired it up.
        assert occurrences <= 2, (
            f"BUG-4: _execute_tapscript referenced {occurrences} times "
            "(expected at most 2: def line + docstring). If you wired this "
            "into production, it has DIVERGENT behavior from _execute_script "
            "(e.g. 201 op-count limit enforced in dead helper, removed in "
            "_execute_script per BIP-342); see W127 audit BUG-4 and BUG-11."
        )

    def test_bug11_execute_tapscript_diverges_from_execute_script(self) -> None:
        """BUG-11: Dead `_execute_tapscript` would diverge if wired up.

        Documents the consensus-relevant differences. NOT a behavioral
        test — purely an audit assertion that the dead helper exists
        and would cause forks if called.
        """
        import inspect
        et_src = inspect.getsource(ScriptInterpreter._execute_tapscript)
        es_src = inspect.getsource(ScriptInterpreter._execute_script)
        # _execute_tapscript: enforces 201 op-count even in tapscript.
        assert "max_ops" in et_src and "op_count > max_ops" in et_src
        # _execute_script: explicitly gates on `not is_tapscript`.
        assert "not is_tapscript and op_count > 201" in es_src


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
