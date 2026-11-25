"""P2SH-wrapped witness program: the redeemScript must still be EVALUATED.

Item cffix-ouroboros-python-p2sh-witprog-evalfalse, from Claude Security scan
secscan2-ouroboros, finding A-F1 (2026-11-25).

Core ``VerifyScript`` (``script/interpreter.cpp``), P2SH branch::

    if (!EvalScript(stack, pubKey2, flags, checker, SigVersion::BASE, serror))
        return false;
    if (stack.empty()) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    // P2SH witness program
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) { ...

So a redeemScript that IS a witness program is first run as a script, and
its top stack item (the witness program bytes) must be true.  A program
made only of zero bytes (or zeros ending in 0x80, negative zero) is false,
and Core fails the spend with EVAL_FALSE before any witness check.

The pure-Python fallback (``OUROBOROS_NATIVE_SCRIPT=0``) jumps straight to
``_verify_witness_program`` for such a redeemScript (``script.py`` Step 5,
``wp_inner``).  For witness versions Core treats as upgradable (v1 under
P2SH, v2..v16, or v1 of a non-32 length) that returns True under block
flags, so the Python fallback ACCEPTS a spend Core REJECTS: an invalid
block is accepted (consensus split on the non-default interpreter).

The expected decisions below come from Core's rule as quoted above, not
from ouroboros.  When the compiled ``sync`` extension is built, the Rust
interpreter (the default path) is checked as a second oracle.
"""

from __future__ import annotations

import hashlib

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import (
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    ScriptInterpreter,
)

from ouroboros.segwit_v0 import sign_p2sh_p2wpkh_input
from ouroboros.wallet import WalletKey, _hash160

from tests._real_sync import load_real_sync, real_sync_installed

# Core GetBlockScriptFlags after taproot: no DISCOURAGE_UPGRADABLE_* (policy).
CONSENSUS_FLAGS = (
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
)
AMOUNT = 100_000


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _witprog(version_op: int, program: bytes) -> bytes:
    assert 2 <= len(program) <= 40
    return bytes([version_op, len(program)]) + program


# name -> (redeemScript, Core decision under block flags)
CASES = {
    # Program bytes are all zero: CastToBool false -> EVAL_FALSE in Core.
    "v1_len2_zero": (_witprog(0x51, b"\x00\x00"), False),
    "v1_len32_zero": (_witprog(0x51, bytes(32)), False),
    "v2_len20_zero": (_witprog(0x52, bytes(20)), False),
    "v16_len40_zero": (_witprog(0x60, bytes(40)), False),
    # Negative zero (0x00.. 0x80) is also false for CastToBool.
    "v1_len2_negzero": (_witprog(0x51, b"\x00\x80"), False),
    "v3_len32_negzero": (_witprog(0x53, bytes(31) + b"\x80"), False),
    # Positive controls: a non-zero program evaluates true, then the
    # upgradable witness version succeeds under consensus flags in Core.
    "v1_len2_nonzero": (_witprog(0x51, b"\x00\x01"), True),
    "v2_len20_nonzero": (_witprog(0x52, b"\x01" * 20), True),
    "v1_len32_nonzero": (_witprog(0x51, b"\x00" * 31 + b"\x01"), True),
}
IDS = list(CASES)


def _push(data: bytes) -> bytes:
    assert len(data) <= 75
    return bytes([len(data)]) + data


def _spend(redeem: bytes) -> tuple[Transaction, bytes, bytes]:
    spk = b"\xa9\x14" + hash160(redeem) + b"\x87"  # P2SH
    script_sig = _push(redeem)  # the minimal canonical push Core requires
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(range(32)), prev_vout=0,
                     script_sig=script_sig, sequence=0xFFFFFFFF, witness=[])],
        outputs=[TxOut(value=AMOUNT - 1_000, script_pubkey=b"\x51")],
    )
    return tx, script_sig, spk


def _verify_python(redeem: bytes) -> bool:
    tx, script_sig, spk = _spend(redeem)
    return ScriptInterpreter().verify_python(
        script_sig, spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
        input_amounts=[AMOUNT], input_script_pubkeys=[spk])


@pytest.mark.parametrize("name", IDS, ids=IDS)
def test_python_p2sh_witness_program_redeemscript_is_evaluated(name):
    """verify_python gives Core's decision: a false witness-program
    redeemScript fails with EVAL_FALSE before the witness check."""
    redeem, core_decision = CASES[name]
    assert _verify_python(redeem) is core_decision


def test_instrument_p2sh_hash_is_checked():
    """Negative control: the spend reaches the P2SH branch (a wrong redeem
    hash fails), so the positive controls are not passing on Step 3 alone."""
    redeem, _ = CASES["v1_len2_nonzero"]
    tx, script_sig, _spk = _spend(redeem)
    bad_spk = b"\xa9\x14" + bytes(20) + b"\x87"
    assert ScriptInterpreter().verify_python(
        script_sig, bad_spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
        input_amounts=[AMOUNT], input_script_pubkeys=[bad_spk]) is False


@pytest.mark.parametrize("name", IDS, ids=IDS)
def test_native_oracle_matches_core(name):
    """The default (Rust) interpreter gives Core's decision for each case."""
    real = load_real_sync()
    if real is None or not hasattr(real, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    redeem, core_decision = CASES[name]
    with real_sync_installed(real):
        tx, script_sig, spk = _spend(redeem)
        nat = ScriptInterpreter().verify_native(
            script_sig, spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
            input_amounts=[AMOUNT], input_script_pubkeys=[spk])
    assert nat is core_decision


# ---------------------------------------------------------------------------
# Valid P2SH-wrapped v0 programs: running the redeemScript first must not
# fail them.  A v0 program (``00 14 <20>`` / ``00 20 <32>``) leaves its
# program bytes on top of the stack; those are true unless all zero, so a
# real P2SH-P2WPKH / P2SH-P2WSH spend still reaches the witness check.
# ---------------------------------------------------------------------------


def _p2sh_p2wpkh_spend(corrupt_sig: bool = False):
    key = WalletKey((0xC0FFEE).to_bytes(32, "big"), network="regtest")
    redeem = b"\x00\x14" + _hash160(key.pubkey)
    spk = b"\xa9\x14" + hash160(redeem) + b"\x87"
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(range(32)), prev_vout=0,
                     script_sig=b"", sequence=0xFFFFFFFF, witness=[])],
        outputs=[TxOut(value=AMOUNT - 1_000, script_pubkey=b"\x51")],
        has_witness=True,
    )
    script_sig, witness = sign_p2sh_p2wpkh_input(tx, 0, key, AMOUNT, 0x01)
    if corrupt_sig:
        sig = bytearray(witness[0])
        sig[10] ^= 0x01  # inside r: a well-formed DER sig that does not verify
        witness = [bytes(sig), witness[1]]
    tx.inputs[0].script_sig = script_sig
    tx.inputs[0].witness = witness
    assert script_sig == _push(redeem)
    return tx, script_sig, spk


def _p2sh_p2wsh_optrue_spend():
    witness_script = b"\x51"  # OP_TRUE
    redeem = b"\x00\x20" + hashlib.sha256(witness_script).digest()
    spk = b"\xa9\x14" + hash160(redeem) + b"\x87"
    script_sig = _push(redeem)
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(range(32)), prev_vout=0,
                     script_sig=script_sig, sequence=0xFFFFFFFF,
                     witness=[witness_script])],
        outputs=[TxOut(value=AMOUNT - 1_000, script_pubkey=b"\x51")],
        has_witness=True,
    )
    return tx, script_sig, spk


V0_SPENDS = {
    "p2sh_p2wpkh_signed": (lambda: _p2sh_p2wpkh_spend(), True),
    "p2sh_p2wpkh_badsig": (lambda: _p2sh_p2wpkh_spend(corrupt_sig=True), False),
    "p2sh_p2wsh_optrue": (_p2sh_p2wsh_optrue_spend, True),
}
V0_IDS = list(V0_SPENDS)


def _run(interp_method, tx, script_sig, spk):
    return interp_method(
        script_sig, spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
        input_amounts=[AMOUNT], input_script_pubkeys=[spk])


@pytest.mark.parametrize("name", V0_IDS, ids=V0_IDS)
def test_python_p2sh_v0_witness_spend_unchanged(name):
    """A valid P2SH-P2WPKH (real signature) and P2SH-P2WSH spend still pass
    once the redeemScript is run first; a bad signature still fails, so the
    valid case is decided by the witness check and not by Step 5 alone."""
    build, core_decision = V0_SPENDS[name]
    tx, script_sig, spk = build()
    assert _run(ScriptInterpreter().verify_python, tx, script_sig, spk) is core_decision


@pytest.mark.parametrize("name", V0_IDS, ids=V0_IDS)
def test_native_oracle_matches_core_v0(name):
    """The default (Rust) interpreter agrees on the v0 spends."""
    real = load_real_sync()
    if real is None or not hasattr(real, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    build, core_decision = V0_SPENDS[name]
    with real_sync_installed(real):
        tx, script_sig, spk = build()
        nat = _run(ScriptInterpreter().verify_native, tx, script_sig, spk)
    assert nat is core_decision
