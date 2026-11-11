"""BIP143 / BIP341 sighash must serialize nVersion as uint32, like Core.

Core stores ``CTransaction::version`` as ``uint32_t``
(``primitives/transaction.h``) and writes it as four unsigned little-endian
bytes in both witness sighash algorithms:

* ``SignatureHash`` BIP143 branch (``script/interpreter.cpp``,
  ``ss << txTo.version``);
* ``SignatureHashSchnorr`` (``ss << tx_to.version``).

ouroboros' wire parser stores the version unsigned (``p2p_messages.py``), but
the pure-Python BIP143 and BIP341 builders packed it with ``struct.pack('<i')``.
Any version >= 0x80000000 then raised ``struct.error`` inside the sighash:

* P2WPKH / P2TR key-path spends with a valid signature were REJECTED
  (a Core-valid block is refused);
* in witness-v0 ``OP_CHECKSIG`` the exception pushed false, so
  ``<pk> OP_CHECKSIG OP_NOT`` with a VALID signature was ACCEPTED where Core
  rejects (an invalid block is accepted).

Every signature here is made over a preimage this file builds itself with
``(version).to_bytes(4, 'little')`` (unsigned), so the expectation does not
come from ouroboros' own sighash code.  When the compiled ``sync`` extension
is built, the Rust interpreter (which already encodes uint32) is used as a
second oracle.
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
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    ScriptInterpreter,
)

from tests._real_sync import load_real_sync, real_sync_installed

# Block-connect consensus flags after taproot activation (Core
# GetBlockScriptFlags).  NULLFAIL is policy only, which is what lets
# `<pk> CHECKSIG NOT` succeed with an empty signature and be decided by a
# valid one.
CONSENSUS_FLAGS = (
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
)

VERSIONS = [1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
AMOUNT = 100_000
PREV_TXID = bytes(range(32))
SPK_OUT = b"\x51"  # OP_TRUE output; irrelevant to the spend under test

_KEY = PrivateKey(hashlib.sha256(b"cffix-sighash-version-uint32").digest())
_PUB33 = _KEY.public_key.format(compressed=True)
_XONLY = _PUB33[1:]


# ---------------------------------------------------------------------------
# Independent sighash builders (uint32 version, as Core writes it)
# ---------------------------------------------------------------------------

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _dsha256(b: bytes) -> bytes:
    return _sha256(_sha256(b))


def _tagged(tag: str, msg: bytes) -> bytes:
    t = _sha256(tag.encode())
    return _sha256(t + t + msg)


def _ser_script(s: bytes) -> bytes:
    assert len(s) < 0xFD
    return bytes([len(s)]) + s


def _u32(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _bip143_sighash_all(tx: Transaction, script_code: bytes, amount: int) -> bytes:
    """BIP143 SIGHASH_ALL for input 0 of a 1-in tx."""
    inp = tx.inputs[0]
    prevouts = b"".join(i.prev_txid + _u32(i.prev_vout) for i in tx.inputs)
    sequences = b"".join(_u32(i.sequence) for i in tx.inputs)
    outputs = b"".join(struct.pack("<q", o.value) + _ser_script(o.script_pubkey)
                       for o in tx.outputs)
    pre = (
        _u32(tx.version)
        + _dsha256(prevouts) + _dsha256(sequences)
        + inp.prev_txid + _u32(inp.prev_vout)
        + _ser_script(script_code)
        + struct.pack("<q", amount)
        + _u32(inp.sequence)
        + _dsha256(outputs)
        + _u32(tx.locktime)
        + _u32(0x01)
    )
    return _dsha256(pre)


def _bip341_keypath_sighash_default(tx: Transaction, amounts: list[int],
                                    spks: list[bytes]) -> bytes:
    """BIP341 SIGHASH_DEFAULT, key path, no annex, input 0."""
    prevouts = b"".join(i.prev_txid + _u32(i.prev_vout) for i in tx.inputs)
    msg = (
        b"\x00"  # epoch
        + b"\x00"  # hash_type
        + _u32(tx.version)
        + _u32(tx.locktime)
        + _sha256(prevouts)
        + _sha256(b"".join(struct.pack("<q", a) for a in amounts))
        + _sha256(b"".join(_ser_script(s) for s in spks))
        + _sha256(b"".join(_u32(i.sequence) for i in tx.inputs))
        + _sha256(b"".join(struct.pack("<q", o.value) + _ser_script(o.script_pubkey)
                           for o in tx.outputs))
        + b"\x00"  # spend_type: key path, no annex
        + _u32(0)  # input_index
    )
    return _tagged("TapSighash", msg)


# ---------------------------------------------------------------------------
# Spends
# ---------------------------------------------------------------------------

def _tx(version: int, witness: list[bytes]) -> Transaction:
    return Transaction(
        txid=b"",
        version=version,
        locktime=0,
        inputs=[TxIn(prev_txid=PREV_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF, witness=witness)],
        outputs=[TxOut(value=AMOUNT - 1_000, script_pubkey=SPK_OUT)],
    )


def _ecdsa_sig(digest: bytes) -> bytes:
    return _KEY.sign(digest, hasher=None) + b"\x01"


def p2wpkh(version: int):
    h160 = hashlib.new("ripemd160", _sha256(_PUB33)).digest()
    spk = b"\x00\x14" + h160
    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
    tx = _tx(version, [])
    sig = _ecdsa_sig(_bip143_sighash_all(tx, script_code, AMOUNT))
    tx.inputs[0].witness = [sig, _PUB33]
    return tx, spk


def p2wsh_checksig_not(version: int):
    ws = b"\x21" + _PUB33 + b"\xac\x91"  # <pk> OP_CHECKSIG OP_NOT
    spk = b"\x00\x20" + _sha256(ws)
    tx = _tx(version, [])
    sig = _ecdsa_sig(_bip143_sighash_all(tx, ws, AMOUNT))
    tx.inputs[0].witness = [sig, ws]
    return tx, spk


def p2tr_keypath(version: int):
    spk = b"\x51\x20" + _XONLY
    tx = _tx(version, [])
    digest = _bip341_keypath_sighash_default(tx, [AMOUNT], [spk])
    tx.inputs[0].witness = [_KEY.sign_schnorr(digest, b"\x00" * 32)]
    return tx, spk


# (builder, Core decision for a correctly signed spend)
SPENDS = {
    "p2wpkh": (p2wpkh, True),
    "p2tr_keypath": (p2tr_keypath, True),
    # Signature is valid, CHECKSIG pushes true, NOT makes it false: Core
    # fails the script with EVAL_FALSE.
    "p2wsh_checksig_not": (p2wsh_checksig_not, False),
}

CASES = [(name, v) for name in SPENDS for v in VERSIONS]
IDS = [f"{name}-v{v:#010x}" for name, v in CASES]


def _verify_python(tx: Transaction, spk: bytes) -> bool:
    return ScriptInterpreter().verify_python(
        b"", spk, tx, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
        input_amounts=[AMOUNT], input_script_pubkeys=[spk])


# ---------------------------------------------------------------------------
# Script layer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,version", CASES, ids=IDS)
def test_python_witness_sighash_version_is_uint32(name, version):
    """verify_python gives Core's decision for every nVersion."""
    build, core_decision = SPENDS[name]
    tx, spk = build(version)
    assert _verify_python(tx, spk) is core_decision


@pytest.mark.parametrize("version", VERSIONS, ids=[f"v{v:#010x}" for v in VERSIONS])
def test_python_bip143_bip341_sighash_bytes_match_uint32_preimage(version):
    """The internal sighash builders hash the same bytes as the uint32 oracle."""
    interp = ScriptInterpreter()
    tx, spk = p2wpkh(version)
    script_code = b"\x76\xa9\x14" + spk[2:] + b"\x88\xac"
    assert interp._compute_segwit_v0_sighash(
        tx, 0, script_code, AMOUNT, 0x01) == _bip143_sighash_all(tx, script_code, AMOUNT)

    tx, spk = p2tr_keypath(version)
    assert interp._compute_taproot_sighash(
        tx, 0, 0x00, input_amounts=[AMOUNT], input_script_pubkeys=[spk],
        annex=None, ext_flag=0,
    ) == _bip341_keypath_sighash_default(tx, [AMOUNT], [spk])


def test_negative_control_bad_signature_is_rejected():
    """Instrument check: a P2WPKH spend signed over a DIFFERENT version
    (signed-int32 vs uint32 can't differ in bytes, so use version+1) must be
    rejected, proving the positive cases are decided by the signature."""
    tx, spk = p2wpkh(0x80000000)
    tx.version = 0x80000001
    assert _verify_python(tx, spk) is False
    tx, spk = p2tr_keypath(0x80000000)
    tx.version = 0x80000001
    assert _verify_python(tx, spk) is False


@pytest.mark.parametrize("name,version", CASES, ids=IDS)
def test_python_matches_native_oracle(name, version):
    """verify_python == verify_native (Rust already encodes uint32)."""
    real = load_real_sync()
    if real is None or not hasattr(real, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    build, core_decision = SPENDS[name]
    tx, spk = build(version)
    py = _verify_python(tx, spk)
    with real_sync_installed(real):
        tx_native, _ = build(version)
        nat = ScriptInterpreter().verify_native(
            b"", spk, tx_native, 0, flags=CONSENSUS_FLAGS, amount=AMOUNT,
            input_amounts=[AMOUNT], input_script_pubkeys=[spk])
    assert nat is core_decision
    assert py == nat


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


@pytest.mark.parametrize("name,version", CASES, ids=IDS)
def test_transaction_validator_block_path(name, version, monkeypatch):
    """validate_transaction (block flags, scripts on) gives Core's decision."""
    import ouroboros.validation as validation

    monkeypatch.setattr(validation, "NATIVE_SCRIPT_ENABLED", False, raising=False)
    monkeypatch.setattr("ouroboros.script.NATIVE_SCRIPT_ENABLED", False)
    # Only successful verifications are cached; start clean so a cached
    # True from another test can never decide this one.
    validation.SIG_CACHE.clear()
    build, core_decision = SPENDS[name]
    tx, spk = build(version)
    tv = _validator(spk)
    ok, reason = tv.validate_transaction(tx, height=850_000, block_mtp=1_700_000_000)
    assert ok is core_decision, reason
    if not core_decision:
        # Rejected by the input's script check, not by anything incidental
        # to the mocked chainstate.
        assert reason == "Invalid signature for input 0", reason
