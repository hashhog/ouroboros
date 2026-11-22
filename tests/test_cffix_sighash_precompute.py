"""BIP143 / BIP341 per-tx sighash hashes must be computed once per tx.

Core hashes the parts of the signature message that commit to the whole
transaction once, in ``PrecomputedTransactionData::Init``
(``src/script/interpreter.cpp``): BIP143 ``hashPrevouts`` /
``hashSequence`` / ``hashOutputs`` and BIP341 ``sha_prevouts`` /
``sha_amounts`` / ``sha_scriptpubkeys`` / ``sha_sequences`` /
``sha_outputs``.  ``SignatureHash`` and ``SignatureHashSchnorr`` only read
them.  ouroboros' pure-Python ``_compute_segwit_v0_sighash`` and
``_compute_taproot_sighash`` rebuilt them on every call, i.e. once per
CHECKSIG with an explicit hash type and once per CHECKMULTISIG key attempt,
so a script with S signature checks in a tx with N outputs cost O(S x N).

These tests count work instead of timing it: ``hashlib`` is shadowed in
``ouroboros.script`` by a proxy that counts how many times the serialized
output list of the transaction is fed to SHA256.  That blob is what
``hashOutputs`` / ``sha_outputs`` hash, so the count is the number of
times the aggregate was built.  On master it is one per signature check
(50 for the tapscript below); after the fix it is 1.

The second half checks the digests did not change: Core's
``bip341_wallet_vectors.json`` key-path sighashes (every hash type), the
BIP143 native-P2WPKH example, and an independent BIP143 builder over every
hash type, each through the cached path.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import struct
from unittest.mock import MagicMock

import pytest
from coincurve import PrivateKey, PublicKey

import ouroboros.script as script_mod
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

FLAGS = (
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
)

AMOUNT = 10_000_000
N_OUTPUTS = 200
N_CHECKSIGS = 50
OP_1 = 0x51
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE

_KEY = PrivateKey(hashlib.sha256(b"cffix-sighash-precompute").digest())
_PUB33 = _KEY.public_key.format(compressed=True)


# ---------------------------------------------------------------------------
# Independent serialization helpers (not ouroboros' own sighash code)
# ---------------------------------------------------------------------------

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _dsha256(b: bytes) -> bytes:
    return _sha256(_sha256(b))


def _tagged(tag: str, msg: bytes) -> bytes:
    t = _sha256(tag.encode())
    return _sha256(t + t + msg)


def _cs(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def _ser(s: bytes) -> bytes:
    return _cs(len(s)) + s


def _u32(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _ser_outputs(outs) -> bytes:
    return b"".join(struct.pack("<q", o.value) + _ser(o.script_pubkey) for o in outs)


def _many_outputs(n: int = N_OUTPUTS) -> list[TxOut]:
    # Distinct values so the serialized list is unique to this tx.
    return [TxOut(value=1_000 + i, script_pubkey=b"\x00\x14" + bytes([i % 256]) * 20)
            for i in range(n)]


def _tx(n_inputs: int, outputs: list[TxOut]) -> Transaction:
    return Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes([j]) * 32, prev_vout=j, script_sig=b"",
                     sequence=0xFFFFFFFD, witness=[]) for j in range(n_inputs)],
        outputs=outputs,
    )


def _bip143(tx: Transaction, idx: int, script_code: bytes, amount: int,
            hashtype: int) -> bytes:
    """BIP143 signature hash, written from the BIP text."""
    base = hashtype & 0x1F
    acp = bool(hashtype & 0x80)
    zero = b"\x00" * 32
    hp = zero if acp else _dsha256(
        b"".join(i.prev_txid + _u32(i.prev_vout) for i in tx.inputs))
    hs = zero if (acp or base in (2, 3)) else _dsha256(
        b"".join(_u32(i.sequence) for i in tx.inputs))
    if base not in (2, 3):
        ho = _dsha256(_ser_outputs(tx.outputs))
    elif base == 3 and idx < len(tx.outputs):
        ho = _dsha256(_ser_outputs([tx.outputs[idx]]))
    else:
        ho = zero
    inp = tx.inputs[idx]
    pre = (_u32(tx.version) + hp + hs + inp.prev_txid + _u32(inp.prev_vout)
           + _ser(script_code) + struct.pack("<q", amount) + _u32(inp.sequence)
           + ho + _u32(tx.locktime) + _u32(hashtype))
    return _dsha256(pre)


def _bip341_tapscript_all(tx: Transaction, idx: int, amounts, spks,
                          leaf_hash: bytes) -> bytes:
    """BIP341/342 SIGHASH_ALL (explicit 0x01) script-path message, no annex."""
    msg = (
        b"\x00" + b"\x01"
        + _u32(tx.version) + _u32(tx.locktime)
        + _sha256(b"".join(i.prev_txid + _u32(i.prev_vout) for i in tx.inputs))
        + _sha256(b"".join(struct.pack("<q", a) for a in amounts))
        + _sha256(b"".join(_ser(s) for s in spks))
        + _sha256(b"".join(_u32(i.sequence) for i in tx.inputs))
        + _sha256(_ser_outputs(tx.outputs))
        + b"\x02"  # spend_type: ext_flag=1, no annex
        + _u32(idx)
        + leaf_hash + b"\x00" + b"\xff\xff\xff\xff"
    )
    return _tagged("TapSighash", msg)


# ---------------------------------------------------------------------------
# The instrument: count SHA256 calls over the serialized output list
# ---------------------------------------------------------------------------

class _CountingHashlib:
    """Stands in for ``hashlib`` inside ``ouroboros.script``."""

    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        self.hits = 0

    def sha256(self, data=b"", *args, **kwargs):
        if bytes(data) == self.blob:
            self.hits += 1
        return hashlib.sha256(data, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(hashlib, name)


@pytest.fixture
def count_output_hashing(monkeypatch):
    """``count(tx)`` installs the counter for ``tx``'s outputs, returns it."""
    monkeypatch.setattr(script_mod, "NATIVE_SCRIPT_ENABLED", False)

    def install(tx: Transaction) -> _CountingHashlib:
        counter = _CountingHashlib(_ser_outputs(tx.outputs))
        monkeypatch.setattr(script_mod, "hashlib", counter)
        return counter

    return install


# ---------------------------------------------------------------------------
# Spends
# ---------------------------------------------------------------------------

def _tapscript_spend(n_inputs: int = 1):
    """n inputs, each a tapscript leaf of N_CHECKSIGS explicit-hashtype
    (SIGHASH_ALL) ``<pk> OP_CHECKSIGVERIFY`` followed by OP_1."""
    internal = PublicKey(b"\x02" + _PUB33[1:])
    xonly = _PUB33[1:]
    # coincurve's BIP340 signer negates the key for odd Y itself.
    key = _KEY
    leaf = (bytes([0x20]) + xonly + bytes([OP_CHECKSIGVERIFY])) * N_CHECKSIGS + bytes([OP_1])
    leaf_hash = _tagged("TapLeaf", b"\xc0" + _ser(leaf))
    tweak = _tagged("TapTweak", xonly + leaf_hash)
    q = internal.add(tweak).format(compressed=True)
    spk = b"\x51\x20" + q[1:]
    control = bytes([0xC0 | (q[0] & 1)]) + xonly
    tx = _tx(n_inputs, _many_outputs())
    amounts = [AMOUNT] * n_inputs
    spks = [spk] * n_inputs
    for idx in range(n_inputs):
        digest = _bip341_tapscript_all(tx, idx, amounts, spks, leaf_hash)
        sig = key.sign_schnorr(digest, b"\x00" * 32) + b"\x01"
        tx.inputs[idx].witness = [sig] * N_CHECKSIGS + [leaf, control]
    return tx, amounts, spks


def _p2wsh_checksigverify_spend(n_checks: int = 20):
    ws = (bytes([0x21]) + _PUB33 + bytes([OP_CHECKSIGVERIFY])) * n_checks + bytes([OP_1])
    spk = b"\x00\x20" + _sha256(ws)
    tx = _tx(1, _many_outputs())
    sig = _KEY.sign(_bip143(tx, 0, ws, AMOUNT, 0x01), hasher=None) + b"\x01"
    tx.inputs[0].witness = [sig] * n_checks + [ws]
    return tx, spk


def _p2wsh_multisig_spend():
    """1-of-15 CHECKMULTISIG, signing key in the middle: several key attempts."""
    others = [PrivateKey(hashlib.sha256(b"other%d" % i).digest()).public_key.format()
              for i in range(14)]
    keys = others[:7] + [_PUB33] + others[7:]
    ws = (bytes([OP_1]) + b"".join(bytes([0x21]) + k for k in keys)
          + bytes([0x5F, OP_CHECKMULTISIG]))  # OP_15
    spk = b"\x00\x20" + _sha256(ws)
    tx = _tx(1, _many_outputs())
    sig = _KEY.sign(_bip143(tx, 0, ws, AMOUNT, 0x01), hasher=None) + b"\x01"
    tx.inputs[0].witness = [b"", sig, ws]
    return tx, spk


def _verify(tx, idx, spk, amounts, spks, **kw) -> bool:
    return ScriptInterpreter().verify_python(
        b"", spk, tx, idx, flags=FLAGS, amount=amounts[idx],
        input_amounts=amounts, input_script_pubkeys=spks, **kw)


# ---------------------------------------------------------------------------
# Work: the aggregates are built once
# ---------------------------------------------------------------------------

def test_tapscript_50_checksigverify_hashes_outputs_once(count_output_hashing):
    """1 input, 200 outputs, 50 explicit-hashtype CHECKSIGVERIFYs: Core
    hashes sha_outputs once; master hashed it 50 times."""
    tx, amounts, spks = _tapscript_spend()
    counter = count_output_hashing(tx)
    assert _verify(tx, 0, spks[0], amounts, spks) is True
    assert counter.hits == 1, f"sha_outputs built {counter.hits} times"


def test_p2wsh_checksigverify_hashes_outputs_once(count_output_hashing):
    """BIP143: 20 CHECKSIGVERIFYs build hashOutputs once."""
    tx, spk = _p2wsh_checksigverify_spend()
    counter = count_output_hashing(tx)
    assert _verify(tx, 0, spk, [AMOUNT], [spk]) is True
    assert counter.hits == 1, f"hashOutputs built {counter.hits} times"


def test_p2wsh_checkmultisig_key_attempts_hash_outputs_once(count_output_hashing):
    """BIP143: each CHECKMULTISIG key attempt computes a sighash; hashOutputs
    is still built once."""
    tx, spk = _p2wsh_multisig_spend()
    counter = count_output_hashing(tx)
    assert _verify(tx, 0, spk, [AMOUNT], [spk]) is True
    assert counter.hits == 1, f"hashOutputs built {counter.hits} times"


def test_shared_txdata_hashes_outputs_once_across_inputs(count_output_hashing):
    """One PrecomputedTransactionData for every input of a tx (Core
    CheckInputScripts): 3 inputs x 50 checks -> one sha_outputs."""
    if "txdata" not in inspect.signature(ScriptInterpreter.verify_python).parameters:
        pytest.fail("verify_python takes no per-tx precomputed data (txdata)")
    tx, amounts, spks = _tapscript_spend(n_inputs=3)
    counter = count_output_hashing(tx)
    txdata = script_mod.PrecomputedTransactionData(tx, amounts, spks)
    for idx in range(3):
        assert _verify(tx, idx, spks[idx], amounts, spks, txdata=txdata) is True
    assert counter.hits == 1, f"sha_outputs built {counter.hits} times"


def _validator(spk: bytes):
    from ouroboros.validation import TransactionValidator

    utxo = {"value": AMOUNT, "script_pubkey": spk, "height": 800_000,
            "is_coinbase": False}
    db = MagicMock()
    db.get_utxo.return_value = utxo
    db.get_utxo_batch.side_effect = lambda ops: [utxo for _ in ops]
    return TransactionValidator(db=db, network="mainnet")


def test_validate_transaction_hashes_outputs_once_per_tx(count_output_hashing, monkeypatch):
    """Block path (validate_transaction, inline checks): a 3-input tapscript
    tx builds sha_outputs once, and is accepted."""
    import ouroboros.validation as validation

    monkeypatch.setattr(validation, "NATIVE_SCRIPT_ENABLED", False, raising=False)
    validation.SIG_CACHE.clear()
    tx, amounts, spks = _tapscript_spend(n_inputs=3)
    tv = _validator(spks[0])
    counter = count_output_hashing(tx)
    ok, reason = tv.validate_transaction(tx, height=850_000, block_mtp=1_700_000_000)
    assert ok is True, reason
    assert counter.hits == 1, f"sha_outputs built {counter.hits} times"


def test_script_check_queue_hashes_outputs_once_per_tx(count_output_hashing, monkeypatch):
    """Block path (deferred serial check queue): same, one build per tx."""
    import ouroboros.validation as validation

    monkeypatch.setattr(validation, "NATIVE_SCRIPT_ENABLED", False, raising=False)
    validation.SIG_CACHE.clear()
    tx, amounts, spks = _tapscript_spend(n_inputs=3)
    tv = _validator(spks[0])
    utxo = {"value": AMOUNT, "script_pubkey": spks[0]}
    queue = [(1, tx, tx.inputs[i], utxo, i, FLAGS, amounts, spks) for i in range(3)]
    counter = count_output_hashing(tx)
    assert tv.run_script_check_queue(queue, 1) is None
    assert counter.hits == 1, f"sha_outputs built {counter.hits} times"


# ---------------------------------------------------------------------------
# Decisions and digests are unchanged
# ---------------------------------------------------------------------------

def test_negative_control_wrong_output_rejected(count_output_hashing):
    """Instrument check: changing one output after signing must be rejected
    on both the tapscript and the BIP143 spends (the cached aggregates are
    built from the tx being verified, not reused from an earlier call)."""
    tx, amounts, spks = _tapscript_spend()
    assert _verify(tx, 0, spks[0], amounts, spks) is True
    tx.outputs[N_OUTPUTS - 1].value += 1
    assert _verify(tx, 0, spks[0], amounts, spks) is False

    tx, spk = _p2wsh_checksigverify_spend(n_checks=2)
    assert _verify(tx, 0, spk, [AMOUNT], [spk]) is True
    tx.outputs[0].value += 1
    assert _verify(tx, 0, spk, [AMOUNT], [spk]) is False


def test_negative_control_counter_sees_master_shape(count_output_hashing):
    """Instrument check: the counter does count every SHA256 of the output
    blob, so a builder that rehashed per call would be seen."""
    tx = _tx(1, _many_outputs())
    counter = count_output_hashing(tx)
    blob = _ser_outputs(tx.outputs)
    for _ in range(3):
        script_mod.hashlib.sha256(blob).digest()
    assert counter.hits == 3


def _parse_unsigned_tx(raw: bytes) -> Transaction:
    f = io.BytesIO(raw)

    def cs() -> int:
        b = f.read(1)[0]
        if b < 0xFD:
            return b
        return int.from_bytes(f.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[b]), "little")

    version = struct.unpack("<I", f.read(4))[0]
    inputs = []
    for _ in range(cs()):
        txid = f.read(32)
        vout = struct.unpack("<I", f.read(4))[0]
        ss = f.read(cs())
        seq = struct.unpack("<I", f.read(4))[0]
        inputs.append(TxIn(prev_txid=txid, prev_vout=vout, script_sig=ss,
                           sequence=seq, witness=[]))
    outputs = []
    for _ in range(cs()):
        value = struct.unpack("<q", f.read(8))[0]
        outputs.append(TxOut(value=value, script_pubkey=f.read(cs())))
    locktime = struct.unpack("<I", f.read(4))[0]
    return Transaction(txid=b"", version=version, locktime=locktime,
                       inputs=inputs, outputs=outputs)


# Core src/test/data/bip341_wallet_vectors.json, keyPathSpending[0]
# (given.rawUnsignedTx, given.utxosSpent, inputSpending[*].intermediary.sigHash).
_BIP341_RAW = (
    "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c"
    "010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b"
    "6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760"
    "d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83"
    "ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb746"
    "1d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d"
    "2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c"
    "32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e"
    "6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffff"
    "a778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000"
    "ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc"
    "88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a6"
    "63f78bab962b0065cd1d"
)
_BIP341_UTXOS = [
    ("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000),
    ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000),
    ("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000),
    ("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000),
    ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000),
    ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000),
    ("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000),
    ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000),
    ("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000),
]
_BIP341_SIGHASHES = [
    (0, 3, "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555"),
    (1, 131, "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d"),
    (3, 1, "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669"),
    (4, 0, "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef"),
    (6, 2, "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85"),
    (7, 130, "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10"),
    (8, 129, "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2"),
]


def _with_active_txdata(interp: ScriptInterpreter, txdata) -> None:
    """Install ``txdata`` the way verify_python does for its call."""
    import threading
    tls = interp.__dict__.get("_txdata_tls")
    if tls is None:
        tls = interp._txdata_tls = threading.local()
    tls.value = txdata


@pytest.mark.parametrize("cached", [False, True], ids=["direct", "precomputed"])
def test_bip341_wallet_vector_sighashes(cached):
    """Core's BIP341 key-path sighashes, all hash types, through the direct
    and the precomputed (one shared object for all 7 inputs) paths."""
    tx = _parse_unsigned_tx(bytes.fromhex(_BIP341_RAW))
    spks = [bytes.fromhex(s) for s, _ in _BIP341_UTXOS]
    amounts = [a for _, a in _BIP341_UTXOS]
    interp = ScriptInterpreter()
    if cached:
        if not hasattr(script_mod, "PrecomputedTransactionData"):
            pytest.fail("no PrecomputedTransactionData in ouroboros.script")
        _with_active_txdata(
            interp, script_mod.PrecomputedTransactionData(tx, amounts, spks))
    for idx, hashtype, expected in _BIP341_SIGHASHES:
        got = interp._compute_taproot_sighash(
            tx, idx, hashtype, input_amounts=amounts,
            input_script_pubkeys=spks, annex=None, ext_flag=0)
        assert got is not None and got.hex() == expected, (idx, hashtype)


# BIP143 "Native P2WPKH" example: unsigned tx, input 1, 6 BTC, SIGHASH_ALL.
_BIP143_RAW = (
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
    "f0167faa815988ac11000000"
)
_BIP143_SCRIPTCODE = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
_BIP143_SIGHASH = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"


@pytest.mark.parametrize("cached", [False, True], ids=["direct", "precomputed"])
def test_bip143_native_p2wpkh_example(cached):
    tx = _parse_unsigned_tx(bytes.fromhex(_BIP143_RAW))
    interp = ScriptInterpreter()
    if cached:
        if not hasattr(script_mod, "PrecomputedTransactionData"):
            pytest.fail("no PrecomputedTransactionData in ouroboros.script")
        _with_active_txdata(interp, script_mod.PrecomputedTransactionData(tx))
    got = interp._compute_segwit_v0_sighash(tx, 1, _BIP143_SCRIPTCODE, 600_000_000, 0x01)
    assert got.hex() == _BIP143_SIGHASH


HASHTYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x04, 0x41]


@pytest.mark.parametrize("cached", [False, True], ids=["direct", "precomputed"])
def test_bip143_every_hashtype_matches_independent_builder(cached):
    """All base types, ANYONECANPAY, undefined types, and SINGLE with no
    matching output (input 2 of 3 with 2 outputs)."""
    tx = _tx(3, _many_outputs(2))
    interp = ScriptInterpreter()
    if cached:
        if not hasattr(script_mod, "PrecomputedTransactionData"):
            pytest.fail("no PrecomputedTransactionData in ouroboros.script")
        _with_active_txdata(interp, script_mod.PrecomputedTransactionData(tx))
    code = b"\x51"
    for idx in range(3):
        for ht in HASHTYPES:
            assert interp._compute_segwit_v0_sighash(tx, idx, code, 1234, ht) == \
                _bip143(tx, idx, code, 1234, ht), (idx, hex(ht))
