"""Legacy FindAndDelete runs for an EMPTY signature too, as in Core.

Core ``EvalScript`` (``script/interpreter.cpp``), OP_CHECKMULTISIG(VERIFY),
SigVersion::BASE::

    for (int k = 0; k < nSigsCount; k++) {
        valtype& vchSig = stacktop(-isig-k);
        int found = FindAndDelete(scriptCode, CScript() << vchSig);
        if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
            return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
    }

``CScript() << vchSig`` of an empty ``vchSig`` is the single byte ``00``
(OP_0), so an empty signature deletes every opcode-aligned OP_0 from the
scriptCode before any signature is checked.  ``EvalChecksigPreTapscript``
does the same for OP_CHECKSIG(VERIFY) before its encoding checks; there an
empty sig never reaches the sighash, so only CONST_SCRIPTCODE (policy) can
observe the deletion.

The pure-Python interpreter (``OUROBOROS_NATIVE_SCRIPT=0``) skipped the
deletion for empty sigs, in ``_verify_multisig`` (``if sig:``) and in
``_find_and_delete_count`` (``if not sig: return``).  That splits from Core
in both directions under block flags:

* forward: a block Core rejects (SIG_DER) is accepted;
* reverse: a block Core accepts is rejected.

Every signature here is made over a preimage this file builds itself (its
own legacy SignatureHash and BIP143 builders, its own OP_0 deletion), so the
expectation does not come from ouroboros' sighash or FindAndDelete code.
The native Rust interpreter already matches Core; each case is also run
through it so the two interpreters stay pinned together.
"""

from __future__ import annotations

import hashlib
import struct
from unittest.mock import MagicMock

import pytest
from coincurve import PrivateKey

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import (
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    ScriptInterpreter,
)

from tests._real_sync import load_real_sync, real_sync_installed

# Block-connect consensus flags after taproot activation (Core
# GetBlockScriptFlags).  NULLFAIL is policy only, which is what lets a
# failed CHECKMULTISIG with non-empty sigs push false instead of erroring.
CONSENSUS_FLAGS = (
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
)
CONST_FLAGS = CONSENSUS_FLAGS | SCRIPT_VERIFY_CONST_SCRIPTCODE

AMOUNT = 100_000
PREV_TXID = bytes(range(32))
SPK_OUT = b"\x51"

_KEYS = [PrivateKey(hashlib.sha256(b"psweep-fad-empty-sig-%d" % i).digest())
         for i in range(4)]
_PKS = [k.public_key.format(compressed=True) for k in _KEYS]

OP_0, OP_1, OP_3, OP_4 = b"\x00", b"\x51", b"\x53", b"\x54"
OP_DROP, OP_CHECKSIG, OP_CHECKSIGVERIFY = b"\x75", b"\xac", b"\xad"
OP_CHECKMULTISIG, OP_NOT = b"\xae", b"\x91"


# ---------------------------------------------------------------------------
# Independent builders
# ---------------------------------------------------------------------------

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _dsha256(b: bytes) -> bytes:
    return _sha256(_sha256(b))


def _push(data: bytes) -> bytes:
    """``CScript() << data`` (Core's size-based push, no minimal-int rule)."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + struct.pack("<H", n) + data


def _ser_script(s: bytes) -> bytes:
    assert len(s) < 0xFD
    return bytes([len(s)]) + s


def _legacy_sighash_all(tx: Transaction, script_code: bytes) -> bytes:
    """Core's legacy ``SignatureHash`` for SIGHASH_ALL, input 0."""
    ser = struct.pack("<I", tx.version) + bytes([len(tx.inputs)])
    for i, txin in enumerate(tx.inputs):
        ser += txin.prev_txid + struct.pack("<I", txin.prev_vout)
        ser += _ser_script(script_code) if i == 0 else b"\x00"
        ser += struct.pack("<I", txin.sequence)
    ser += bytes([len(tx.outputs)])
    for out in tx.outputs:
        ser += struct.pack("<q", out.value) + _ser_script(out.script_pubkey)
    ser += struct.pack("<I", tx.locktime) + struct.pack("<I", 1)
    return _dsha256(ser)


def _bip143_sighash_all(tx: Transaction, script_code: bytes, amount: int) -> bytes:
    txin = tx.inputs[0]
    prevouts = b"".join(i.prev_txid + struct.pack("<I", i.prev_vout) for i in tx.inputs)
    seqs = b"".join(struct.pack("<I", i.sequence) for i in tx.inputs)
    outs = b"".join(struct.pack("<q", o.value) + _ser_script(o.script_pubkey)
                    for o in tx.outputs)
    pre = (struct.pack("<I", tx.version) + _dsha256(prevouts) + _dsha256(seqs)
           + txin.prev_txid + struct.pack("<I", txin.prev_vout)
           + _ser_script(script_code) + struct.pack("<q", amount)
           + struct.pack("<I", txin.sequence) + _dsha256(outs)
           + struct.pack("<I", tx.locktime) + struct.pack("<I", 1))
    return _dsha256(pre)


def _tx(script_sig: bytes = b"", witness: list[bytes] | None = None) -> Transaction:
    return Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=PREV_TXID, prev_vout=0, script_sig=script_sig,
                     sequence=0xFFFFFFFF, witness=witness)],
        outputs=[TxOut(value=AMOUNT - 1_000, script_pubkey=SPK_OUT)],
    )


def _sign(key: PrivateKey, digest: bytes) -> bytes:
    return key.sign(digest, hasher=None) + b"\x01"


def _multisig_3of4_not(prefix: bytes) -> bytes:
    """``<prefix> 3 <pk1..pk4> 4 CHECKMULTISIG NOT``."""
    return prefix + OP_3 + b"".join(_push(p) for p in _PKS) + OP_4 + OP_CHECKMULTISIG + OP_NOT


def _sig_spend(spk: bytes, signed_script_code: bytes):
    """scriptSig ``00 00 01 01 <S>``: dummy, empty sig, sig ``01``, S.

    Stack top first the sigs are [S, 01, <empty>] and the keys
    [pk4, pk3, pk2, pk1], so S is checked against pk4 first.  S is pk4's
    signature over ``signed_script_code``.
    """
    tx = _tx()
    s = _sign(_KEYS[3], _legacy_sighash_all(tx, signed_script_code))
    script_sig = OP_0 + OP_0 + _push(b"\x01") + _push(s)
    tx.inputs[0].script_sig = script_sig
    return tx, script_sig, spk


# Each builder returns (tx, scriptSig, scriptPubKey).

def forward():
    # Core's scriptCode: the empty sig's FindAndDelete removed the leading
    # OP_0.  S matches pk4, then sig `01` fails DER -> SIG_DER.
    spk = _multisig_3of4_not(OP_0 + OP_DROP)
    return _sig_spend(spk, spk[1:])


def reverse():
    # S is valid only over the OP_0-bearing script, which Core never hashes:
    # S fails pk4 and pk3, CHECKMULTISIG is false, NOT -> true.
    spk = _multisig_3of4_not(OP_0 + OP_DROP)
    return _sig_spend(spk, spk)


def every_op0():
    # Every opcode-aligned OP_0 goes, not only the first.
    spk = _multisig_3of4_not(OP_0 + OP_DROP + OP_0 + OP_DROP)
    return _sig_spend(spk, OP_DROP + OP_DROP + spk[4:])


def op0_in_push_kept():
    # A 0x00 byte inside a push payload (`01 00` pushes one byte 0x00) is
    # not an opcode; it stays.  S over the whole script is valid -> SIG_DER.
    spk = _multisig_3of4_not(_push(b"\x00") + OP_DROP)
    return _sig_spend(spk, spk)


def plain_2of2():
    # Ordinary bare 2-of-2: no OP_0 in the scriptCode, nothing to delete.
    spk = b"\x52" + _push(_PKS[0]) + _push(_PKS[1]) + b"\x52" + OP_CHECKMULTISIG
    tx = _tx()
    digest = _legacy_sighash_all(tx, spk)
    script_sig = OP_0 + _push(_sign(_KEYS[0], digest)) + _push(_sign(_KEYS[1], digest))
    tx.inputs[0].script_sig = script_sig
    return tx, script_sig, spk


# (builder, flags, Core decision)
BLOCK_CASES = {
    "forward_sig_der": (forward, CONSENSUS_FLAGS, False),
    "reverse_core_accepts": (reverse, CONSENSUS_FLAGS, True),
    "every_opcode_aligned_op0": (every_op0, CONSENSUS_FLAGS, False),
    "control_op0_inside_push_kept": (op0_in_push_kept, CONSENSUS_FLAGS, False),
    "control_plain_2of2": (plain_2of2, CONSENSUS_FLAGS, True),
}


def _const_checksig():
    # <empty sig> | OP_0 DROP <pk> CHECKSIG NOT
    spk = OP_0 + OP_DROP + _push(_PKS[0]) + OP_CHECKSIG + OP_NOT
    return _tx(OP_0), OP_0, spk


def _const_checksig_no_op0():
    spk = _push(_PKS[0]) + OP_CHECKSIG + OP_NOT
    return _tx(OP_0), OP_0, spk


def _const_multisig():
    # <dummy> <empty sig> | OP_0 DROP 1 <pk> 1 CHECKMULTISIG NOT
    spk = OP_0 + OP_DROP + OP_1 + _push(_PKS[0]) + OP_1 + OP_CHECKMULTISIG + OP_NOT
    return _tx(OP_0 + OP_0), OP_0 + OP_0, spk


def _const_multisig_no_op0():
    spk = OP_1 + _push(_PKS[0]) + OP_1 + OP_CHECKMULTISIG + OP_NOT
    return _tx(OP_0 + OP_0), OP_0 + OP_0, spk


# CONST_SCRIPTCODE counts the empty sig's OP_0 deletion (policy flag).
CONST_CASES = {
    "checksig_const_scriptcode": (_const_checksig, CONST_FLAGS, False),
    "checksig_block_flags": (_const_checksig, CONSENSUS_FLAGS, True),
    "control_checksig_const_no_op0": (_const_checksig_no_op0, CONST_FLAGS, True),
    "multisig_const_scriptcode": (_const_multisig, CONST_FLAGS, False),
    "multisig_block_flags": (_const_multisig, CONSENSUS_FLAGS, True),
    "control_multisig_const_no_op0": (_const_multisig_no_op0, CONST_FLAGS, True),
}

ALL_CASES = {**BLOCK_CASES, **CONST_CASES}


def _verify_python(tx, script_sig, spk, flags) -> bool:
    return ScriptInterpreter().verify_python(
        script_sig, spk, tx, 0, flags=flags, amount=AMOUNT,
        input_amounts=[AMOUNT], input_script_pubkeys=[spk])


def _native_or_skip():
    real = load_real_sync()
    if real is None or not hasattr(real, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    return real


def _verify_native(real, name, flags):
    with real_sync_installed(real):
        tx, script_sig, spk = ALL_CASES[name][0]()
        interp = ScriptInterpreter()
        ok = interp.verify_native(
            script_sig, spk, tx, 0, flags=flags, amount=AMOUNT,
            input_amounts=[AMOUNT], input_script_pubkeys=[spk])
    return ok, interp.last_error


# ---------------------------------------------------------------------------
# Python interpreter (the OUROBOROS_NATIVE_SCRIPT=0 path)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(ALL_CASES))
def test_python_empty_sig_findanddelete(name):
    """verify_python gives Core's decision."""
    build, flags, core = ALL_CASES[name]
    tx, script_sig, spk = build()
    assert _verify_python(tx, script_sig, spk, flags) is core


def test_python_forward_fails_on_sig_der():
    """The forward case is rejected by sig ``01``'s DER check, i.e. S matched
    pk4 over Core's scriptCode (not by S failing)."""
    tx, script_sig, spk = forward()
    interp = ScriptInterpreter()
    # scriptSig = 00 00 01 01 <len> S
    assert script_sig[:4] == b"\x00\x00\x01\x01" and script_sig[4] == len(script_sig) - 5
    sigs = [script_sig[5:], b"\x01", b""]
    with pytest.raises(ValueError, match="Non-DER signature"):
        interp._verify_multisig(
            sigs, list(reversed(_PKS)), 3, tx, 0, spk, CONSENSUS_FLAGS)


def test_python_checksigverify_empty_sig_const_scriptcode_error():
    """CHECKSIGVERIFY with an empty sig fails either way; under
    CONST_SCRIPTCODE Core fails it with SIG_FINDANDDELETE first."""
    spk = OP_0 + OP_DROP + _push(_PKS[0]) + OP_CHECKSIGVERIFY + OP_1
    tx = _tx(OP_0)
    with pytest.raises(ValueError, match="CONST_SCRIPTCODE"):
        ScriptInterpreter()._execute_script(
            spk, tx, 0, spk, flags=CONST_FLAGS, initial_stack=[b""])


def test_python_dispatch_with_native_off(monkeypatch):
    """``verify`` with OUROBOROS_NATIVE_SCRIPT=0 (NATIVE_SCRIPT_ENABLED False)
    is the Python path: forward rejected, reverse accepted."""
    monkeypatch.setattr("ouroboros.script.NATIVE_SCRIPT_ENABLED", False)
    for build, core in ((forward, False), (reverse, True)):
        tx, script_sig, spk = build()
        ok = ScriptInterpreter().verify(
            script_sig, spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
            input_amounts=[AMOUNT], input_script_pubkeys=[spk])
        assert ok is core, build.__name__


def test_python_witness_v0_no_findanddelete():
    """Control: witness v0 (P2WSH) does no FindAndDelete.  S over the whole
    witness script (OP_0 included) is valid, so sig ``01`` fails DER."""
    ws = _multisig_3of4_not(OP_0 + OP_DROP)
    spk = b"\x00\x20" + _sha256(ws)
    tx = _tx()
    s = _sign(_KEYS[3], _bip143_sighash_all(tx, ws, AMOUNT))
    tx.inputs[0].witness = [b"", b"", b"\x01", s, ws]
    assert _verify_python(tx, b"", spk, CONSENSUS_FLAGS) is False
    # ... and a sig over the OP_0-stripped script is NOT valid there.
    tx2 = _tx()
    s2 = _sign(_KEYS[3], _bip143_sighash_all(tx2, ws[1:], AMOUNT))
    tx2.inputs[0].witness = [b"", b"", b"\x01", s2, ws]
    assert _verify_python(tx2, b"", spk, CONSENSUS_FLAGS) is True


def test_find_and_delete_count_empty_sig_removes_aligned_op0():
    """``_find_and_delete_count(script, b"")`` deletes opcode-aligned OP_0
    only (pattern ``00``), like Core's FindAndDelete."""
    script = OP_0 + OP_DROP + _push(b"\x00") + OP_0 + OP_1
    out, n = ScriptInterpreter._find_and_delete_count(script, b"")
    assert n == 2
    assert out == OP_DROP + _push(b"\x00") + OP_1


# ---------------------------------------------------------------------------
# Native interpreter (default): already Core-identical, pinned to Python
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(ALL_CASES))
def test_native_matches_core_and_python(name):
    real = _native_or_skip()
    build, flags, core = ALL_CASES[name]
    nat, err = _verify_native(real, name, flags)
    assert nat is core, err
    tx, script_sig, spk = build()
    assert _verify_python(tx, script_sig, spk, flags) is nat


def test_native_error_names():
    real = _native_or_skip()
    _, err = _verify_native(real, "forward_sig_der", CONSENSUS_FLAGS)
    assert err is not None and "SIG_DER" in err, err
    for name in ("checksig_const_scriptcode", "multisig_const_scriptcode"):
        _, err = _verify_native(real, name, CONST_FLAGS)
        assert err is not None and "FINDANDDELETE" in err, (name, err)


# ---------------------------------------------------------------------------
# Validation layer (block-connect path through TransactionValidator)
# ---------------------------------------------------------------------------

def _validator(spk: bytes):
    from ouroboros.validation import TransactionValidator

    utxo = {"value": AMOUNT, "script_pubkey": spk, "height": 800_000,
            "is_coinbase": False}
    db = MagicMock()
    db.get_utxo.return_value = utxo
    db.get_utxo_batch.side_effect = lambda ops: [utxo for _ in ops]
    return TransactionValidator(db=db, network="mainnet")


@pytest.mark.parametrize("name", list(BLOCK_CASES))
def test_transaction_validator_block_path(name, monkeypatch):
    """validate_transaction (block flags, Python interpreter) gives Core's
    decision."""
    import ouroboros.validation as validation

    monkeypatch.setattr(validation, "NATIVE_SCRIPT_ENABLED", False, raising=False)
    monkeypatch.setattr("ouroboros.script.NATIVE_SCRIPT_ENABLED", False)
    validation.SIG_CACHE.clear()
    build, _flags, core = BLOCK_CASES[name]
    tx, _script_sig, spk = build()
    ok, reason = _validator(spk).validate_transaction(
        tx, height=850_000, block_mtp=1_700_000_000)
    assert ok is core, reason
    if not core:
        assert reason == "Invalid signature for input 0", reason
