"""Native CheckSignatureEncoding: STRICTENC hashtype check under LOW_S.

verify-neon-ouroboros-findings #1 (policy, default native interpreter).
Core v31.1 script/interpreter.cpp CheckSignatureEncoding:

    if ((flags & (DERSIG | LOW_S | STRICTENC)) && !IsValidSignatureEncoding) -> SIG_DER
    else if ((flags & LOW_S) && !IsLowDERSignature(vchSig, serror))      -> SIG_HIGH_S
    else if ((flags & STRICTENC) && !IsDefinedHashtypeSignature(vchSig)) -> SIG_HASHTYPE

A low-S signature falls through the second arm to the hashtype check.  The
Rust interpreter entered the LOW_S arm on the flag alone, so with the
mempool's flags (LOW_S and STRICTENC together) no low-S signature ever had
its hashtype checked: a spend signed with sighash byte 0x00 or 0x84 was
accepted to the mempool where Core refuses it.  Block validity is not
affected: neither flag is a consensus flag.

The signatures are real: each is made over the sighash Core computes for
that nHashType byte, so only the hashtype rule can reject (the consensus-flag
control proves it).  The tests need the compiled ``sync`` extension, not the
conftest stub.
"""

from __future__ import annotations

import hashlib
import struct
from unittest.mock import MagicMock

import pytest
from coincurve import PrivateKey

import ouroboros.script as S
from ouroboros.database import Transaction, TxIn, TxOut
from tests._real_sync import load_real_sync, real_sync_installed

KEY = PrivateKey(hashlib.sha256(b"verify-neon-ouroboros-findings-1").digest())
PUB = KEY.public_key.format(compressed=True)
H160 = hashlib.new("ripemd160", hashlib.sha256(PUB).digest()).digest()
P2PKH = b"\x76\xa9\x14" + H160 + b"\x88\xac"
P2WPKH = b"\x00\x14" + H160
AMOUNT = 100_000
PREV = bytes(range(32))
OUT_SPK = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"

TIP = 900_000
CONSENSUS = S.get_flags_for_height(TIP + 1, None, "mainnet")
STANDARD = S.get_standard_script_flags(TIP + 1, None, "mainnet")


def _d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _u32(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _ser(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def _tx() -> Transaction:
    return Transaction(
        txid=b"", version=2, locktime=0,
        inputs=[TxIn(prev_txid=PREV, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF, witness=[])],
        outputs=[TxOut(value=AMOUNT - 1000, script_pubkey=OUT_SPK)],
    )


def _legacy_sighash(tx, script_code, ht):
    # One input, one output, not NONE/SINGLE, no ANYONECANPAY: Core's
    # SignatureHash serializes everything and appends nHashType as 4 bytes.
    assert (ht & 0x1F) not in (2, 3) and not ht & 0x80
    i = tx.inputs[0]
    pre = (_u32(tx.version) + b"\x01" + i.prev_txid + _u32(i.prev_vout)
           + _ser(script_code) + _u32(i.sequence) + b"\x01"
           + struct.pack("<q", tx.outputs[0].value)
           + _ser(tx.outputs[0].script_pubkey) + _u32(tx.locktime) + _u32(ht))
    return _d(pre)


def _bip143_sighash(tx, script_code, amount, ht):
    assert (ht & 0x1F) not in (2, 3)
    i = tx.inputs[0]
    acp = bool(ht & 0x80)
    hp = bytes(32) if acp else _d(i.prev_txid + _u32(i.prev_vout))
    hs = bytes(32) if acp else _d(_u32(i.sequence))
    ho = _d(struct.pack("<q", tx.outputs[0].value) + _ser(tx.outputs[0].script_pubkey))
    pre = (_u32(tx.version) + hp + hs + i.prev_txid + _u32(i.prev_vout)
           + _ser(script_code) + struct.pack("<q", amount) + _u32(i.sequence)
           + ho + _u32(tx.locktime) + _u32(ht))
    return _d(pre)


def _sign(digest: bytes, ht: int) -> bytes:
    return KEY.sign(digest, hasher=None) + bytes([ht])  # coincurve signs low-S


def _p2pkh(ht):
    tx = _tx()
    tx.inputs[0].script_sig = _ser(_sign(_legacy_sighash(tx, P2PKH, ht), ht)) + _ser(PUB)
    return tx, P2PKH


def _p2wpkh(ht):
    tx = _tx()
    tx.inputs[0].witness = [_sign(_bip143_sighash(tx, P2PKH, AMOUNT, ht), ht), PUB]
    return tx, P2WPKH


SPENDS = {"p2pkh": _p2pkh, "p2wpkh": _p2wpkh}
UNDEFINED = [0x00, 0x04, 0x21, 0x80, 0x84, 0xFF]
CASES = [(n, ht) for n in SPENDS for ht in UNDEFINED
         if not (n == "p2pkh" and ht & 0x80)]
IDS = [f"{n}-{ht:#04x}" for n, ht in CASES]


@pytest.fixture(scope="module")
def real():
    mod = load_real_sync()
    if mod is None or not hasattr(mod, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    return mod


def _native(real, tx, spk, flags):
    with real_sync_installed(real):
        interp = S.ScriptInterpreter()
        ok = interp.verify_native(tx.inputs[0].script_sig, spk, tx, 0, flags=flags,
                                  amount=AMOUNT, input_amounts=[AMOUNT],
                                  input_script_pubkeys=[spk])
        return ok, interp.last_error


def test_standard_flags_carry_low_s_and_strictenc():
    assert STANDARD & S.SCRIPT_VERIFY_LOW_S and STANDARD & S.SCRIPT_VERIFY_STRICTENC


@pytest.mark.parametrize("name", list(SPENDS))
def test_sighash_all_control_accepted(real, name):
    tx, spk = SPENDS[name](0x01)
    assert _native(real, tx, spk, STANDARD) == (True, None)


@pytest.mark.parametrize("name,ht", CASES, ids=IDS)
def test_consensus_flags_accept_undefined_hashtype(real, name, ht):
    """Control: the signature is valid; the hashtype is not a consensus rule."""
    tx, spk = SPENDS[name](ht)
    assert _native(real, tx, spk, CONSENSUS)[0] is True


@pytest.mark.parametrize("name,ht", CASES, ids=IDS)
def test_strictenc_alone_rejects_undefined_hashtype(real, name, ht):
    """Control: without LOW_S the arm was already reached."""
    tx, spk = SPENDS[name](ht)
    assert _native(real, tx, spk, CONSENSUS | S.SCRIPT_VERIFY_STRICTENC) == (
        False, "SCRIPT_ERR_SIG_HASHTYPE")


@pytest.mark.parametrize("name,ht", CASES, ids=IDS)
def test_low_s_and_strictenc_reject_undefined_hashtype(real, name, ht):
    tx, spk = SPENDS[name](ht)
    flags = CONSENSUS | S.SCRIPT_VERIFY_STRICTENC | S.SCRIPT_VERIFY_LOW_S
    assert _native(real, tx, spk, flags) == (False, "SCRIPT_ERR_SIG_HASHTYPE")


@pytest.mark.parametrize("name,ht", CASES, ids=IDS)
def test_standard_flags_reject_undefined_hashtype(real, name, ht):
    tx, spk = SPENDS[name](ht)
    assert _native(real, tx, spk, STANDARD) == (False, "SCRIPT_ERR_SIG_HASHTYPE")


@pytest.mark.parametrize("name,ht", [("p2pkh", 0x00), ("p2wpkh", 0x84)])
def test_mempool_flag_delta_rejects_on_native_path(real, name, ht, monkeypatch):
    """The mempool's own call: validate_transaction with
    extra_script_flags = standard & ~consensus (mempool.py), native interpreter."""
    import ouroboros.validation as V
    from ouroboros.validation import TransactionValidator

    with real_sync_installed(real):
        monkeypatch.setattr(V, "NATIVE_SCRIPT_ENABLED", True, raising=False)
        monkeypatch.setattr(S, "NATIVE_SCRIPT_ENABLED", True)
        V.SIG_CACHE.clear()
        tx, spk = SPENDS[name](ht)
        utxo = {"value": AMOUNT, "script_pubkey": spk, "height": 800_000,
                "is_coinbase": False}
        db = MagicMock()
        db.get_utxo.return_value = utxo
        db.get_utxo_batch.side_effect = lambda ops: [utxo for _ in ops]
        tv = TransactionValidator(db=db, network="mainnet")
        ok, reason = tv.validate_transaction(
            tx, TIP + 1, 1_700_000_000, extra_script_flags=STANDARD & ~CONSENSUS)
        V.SIG_CACHE.clear()
    assert ok is False, f"undefined hashtype {ht:#04x} accepted: {reason!r}"
