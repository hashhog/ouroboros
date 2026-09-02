"""
-assumevalid=0 must be honoured on the RPC ``submitblock`` path, not only on
the P2P sync/drain path (Core parity).

Bug closed:
  ``--assumevalid 0`` only set ``BlockSync.force_full_scripts`` (node.py, the
  P2P drain).  ``rpc_submitblock`` -> ``accept_block(skip_scripts=False)``
  -> ``validator.validate_block(blk, height)`` WITHOUT ``force_check_scripts``
  -> ``sync.can_skip_scripts_for_block`` (purely "below the last checkpoint",
  mainnet 850000).  So with assumevalid=0 a block SUBMITTED via submitblock
  below the checkpoint still had its scripts SKIPPED: a tx carrying an invalid
  ECDSA signature was silently connected.

Core (validation.cpp ConnectBlock, :2345-2347 / :2494): assumevalid is ONE
node-wide setting.  ``-assumevalid=0`` => ``script_check_reason =
"assumevalid=0 (always verify)"`` => ``fScriptChecks`` true for EVERY block on
EVERY acceptance path, ProcessNewBlock-from-submitblock included.

Fix:
  ``BlockValidator.force_full_scripts`` (node-wide switch, default False) is
  set by ``Node.start`` from the operator's ``assumevalid`` config and
  consulted by ``validate_block`` alongside ``force_check_scripts``.  Every
  path that reaches the node's validator — ``rpc.accept_block`` (submitblock /
  submitblockbatch / generatetoaddress / submitblock-reorg connect), the P2P
  drain, the pure-Python reorg fallback — therefore honours assumevalid=0.

Pin (drives the REAL ``rpc.accept_block`` -> REAL ``BlockValidator.validate_block``
-> REAL script interpreter; only the DB and the header/coinbase gates that are
not under test are stubbed):
  A block at mainnet height 1000 (<< 850000, so the checkpoint heuristic
  skips) whose one non-coinbase tx spends a P2PK UTXO with a real
  secp256k1 signature that has ONE BYTE FLIPPED.

    * default (assumevalid unset)         -> accepted  (scripts skipped: CONTROL,
                                             proves the test reaches the skip
                                             decision and no earlier gate fires)
    * assumevalid=0 + flipped signature   -> REJECTED "Invalid signature for input 0"
    * assumevalid=0 + intact signature    -> accepted  (CONTROL: the interpreter
                                             runs and the reject above is the
                                             flipped byte, nothing else)
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sync = pytest.importorskip("sync")
coincurve = pytest.importorskip("coincurve")

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.rpc import accept_block  # noqa: E402
from ouroboros.validation import BlockValidator, assumevalid_disabled  # noqa: E402


BELOW_CHECKPOINT_HEIGHT = 1000  # << mainnet last checkpoint (850000)

# The checkpoint heuristic really does skip scripts at this height (and only
# there): the test below is meaningless unless this holds.
assert sync.can_skip_scripts_for_block("mainnet", BELOW_CHECKPOINT_HEIGHT, b"\x00" * 32) is True
assert sync.can_skip_scripts_for_block("mainnet", 900000, b"\x00" * 32) is False

FUNDING_TXID = b"\xaa" * 32
FUNDING_VALUE = 1_000_000
SIGHASH_ALL = 0x01
OP_CHECKSIG = 0xAC


def _dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _push(data: bytes) -> bytes:
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


_PRIV = coincurve.PrivateKey(b"\x01" * 32)
_PUB = _PRIV.public_key.format(compressed=True)
P2PK_SPK = _push(_PUB) + bytes([OP_CHECKSIG])


def _legacy_sighash_all(tx: Transaction, input_index: int, script_code: bytes) -> bytes:
    """Bitcoin legacy SignatureHash for SIGHASH_ALL (single input, so the
    other-inputs blanking is a no-op)."""
    ins = []
    for i, tx_in in enumerate(tx.inputs):
        ins.append(TxIn(
            prev_txid=tx_in.prev_txid, prev_vout=tx_in.prev_vout,
            script_sig=script_code if i == input_index else b"",
            sequence=tx_in.sequence,
        ))
    tmp = Transaction(txid=b"", version=tx.version, locktime=tx.locktime,
                      inputs=ins, outputs=list(tx.outputs))
    return _dsha256(tmp.serialize() + SIGHASH_ALL.to_bytes(4, "little"))


def _make_coinbase() -> Transaction:
    tx = Transaction(
        txid=b"", version=1, locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x04" + b"\x00" * 4, sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=50_00000000, script_pubkey=b"\x51")],
    )
    tx.txid = _dsha256(tx.serialize())
    return tx


def _make_p2pk_spend(*, flip_signature_byte: bool) -> Transaction:
    tx = Transaction(
        txid=b"", version=1, locktime=0,
        inputs=[TxIn(prev_txid=FUNDING_TXID, prev_vout=0, script_sig=b"", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=900_000, script_pubkey=b"\x51")],
    )
    sighash = _legacy_sighash_all(tx, 0, P2PK_SPK)
    der = _PRIV.sign(sighash, hasher=None)  # DER, low-S
    assert _PRIV.public_key.verify(der, sighash, hasher=None)
    if flip_signature_byte:
        # Flip one bit in the last byte of s: stays a well-formed DER
        # signature, is no longer valid for this sighash.
        der = der[:-1] + bytes([der[-1] ^ 0x01])
        assert not _PRIV.public_key.verify(der, sighash, hasher=None)
    tx.inputs[0].script_sig = _push(der + bytes([SIGHASH_ALL]))
    tx.txid = _dsha256(tx.serialize())
    return tx


def _build_block_bytes(*, flip_signature_byte: bool) -> bytes:
    cb = _make_coinbase()
    spend = _make_p2pk_spend(flip_signature_byte=flip_signature_byte)
    merkle = _dsha256(cb.txid + spend.txid)
    blk = Block(
        version=1, prev_blockhash=b"\x11" * 32, merkle_root=merkle,
        timestamp=1_600_001_000, bits=0x1D00FFFF, nonce=0,
        transactions=[cb, spend], hash=b"", height=BELOW_CHECKPOINT_HEIGHT,
    )
    raw = blk.serialize()
    # Round-trip sanity: the deserialised block must carry the txids and the
    # merkle root the validator will recompute.
    back = Block.deserialize(raw)
    assert [t.txid for t in back.transactions] == [cb.txid, spend.txid]
    assert back.merkle_root == merkle
    return raw


def _funding_utxo() -> dict:
    return {
        "txid": FUNDING_TXID, "vout": 0, "value": FUNDING_VALUE,
        "script_pubkey": P2PK_SPK, "height": 500, "is_coinbase": False,
    }


def _make_db() -> MagicMock:
    db = MagicMock()
    db.get_utxo.return_value = None                 # BIP-30 probe misses
    db.get_utxo_batch.return_value = [_funding_utxo()]
    db.validate_block_from_bytes.return_value = None  # Rust structural pass
    db.connect_block_from_bytes.return_value = b"\x22" * 32
    return db


def _make_node(db, *, assumevalid_zero: bool) -> SimpleNamespace:
    validator = BlockValidator(db, network="mainnet")
    if assumevalid_zero:
        # What Node.start does under --assumevalid 0 (see node.py).
        validator.force_full_scripts = True
    return SimpleNamespace(network="mainnet", validator=validator, mempool=None)


def _patched_gates(v: BlockValidator):
    """Stub the header / coinbase gates that are NOT under test (no real chain
    behind the mocked DB).  Merkle root, tx validation and the script
    interpreter stay REAL."""
    return (
        patch.object(v, "_validate_header", return_value=True),
        patch.object(v, "_validate_block_limits", return_value=(True, "")),
        patch.object(v, "_validate_witness_commitment", return_value=(True, "")),
        patch.object(v, "_validate_signet_solution", return_value=(True, "")),
        patch.object(v, "_validate_coinbase", return_value=True),
        patch.object(v, "_verify_coinbase_amount", return_value=True),
        patch.object(v.tx_validator, "_is_final_tx", return_value=True),
    )


def _submit(*, assumevalid_zero: bool, flip_signature_byte: bool):
    """Drive the REAL rpc.accept_block exactly as rpc_submitblock does
    (rpc.py: accept_block(db, node, block_bytes, best_height + 1,
    skip_scripts=False)).  Returns (accepted: bool, error: str, sig_calls)."""
    db = _make_db()
    node = _make_node(db, assumevalid_zero=assumevalid_zero)
    v = node.validator
    raw = _build_block_bytes(flip_signature_byte=flip_signature_byte)
    patches = _patched_gates(v)
    for p in patches:
        p.start()
    try:
        with patch.object(
            v.tx_validator, "_verify_input_signature",
            wraps=v.tx_validator._verify_input_signature,
        ) as spy:
            try:
                asyncio.run(accept_block(
                    db, node, raw, BELOW_CHECKPOINT_HEIGHT, skip_scripts=False,
                ))
                accepted, err = True, ""
            except ValueError as e:
                accepted, err = False, str(e)
            return accepted, err, spy.call_count, db
    finally:
        for p in patches:
            p.stop()


# ---------------------------------------------------------------------------
# CONTROL: default assumevalid — the block is accepted because scripts are
# skipped below the checkpoint.  Proves the fixture reaches the skip decision
# (no earlier structural gate fires) — without this the REJECT below could be
# anything.
# ---------------------------------------------------------------------------
def test_control_default_assumevalid_skips_scripts_and_accepts_bad_signature():
    accepted, err, sig_calls, db = _submit(assumevalid_zero=False, flip_signature_byte=True)
    assert accepted, f"default assumevalid must skip scripts below the checkpoint; got reject: {err!r}"
    assert sig_calls == 0, "assume-valid skip must NOT invoke the script interpreter"
    db.connect_block_from_bytes.assert_called_once()


# ---------------------------------------------------------------------------
# PIN: assumevalid=0 — the flipped-byte signature is REJECTED on the
# submitblock path.
# ---------------------------------------------------------------------------
def test_pin_assumevalid_zero_rejects_bad_signature_on_submitblock_path():
    accepted, err, sig_calls, db = _submit(assumevalid_zero=True, flip_signature_byte=True)
    assert not accepted, (
        "assumevalid=0 MUST verify scripts on the submitblock path below the "
        "checkpoint (Core: fScriptChecks true on every path under -assumevalid=0)"
    )
    assert "Invalid signature for input 0" in err, f"expected the interpreter's reject, got {err!r}"
    assert sig_calls >= 1, "the script interpreter must actually run"
    db.connect_block_from_bytes.assert_not_called()


# ---------------------------------------------------------------------------
# CONTROL: assumevalid=0 with the INTACT signature is accepted — the reject
# above is the flipped byte and nothing else.
# ---------------------------------------------------------------------------
def test_control_assumevalid_zero_accepts_good_signature():
    accepted, err, sig_calls, db = _submit(assumevalid_zero=True, flip_signature_byte=False)
    assert accepted, f"intact signature must pass full verification; got reject: {err!r}"
    assert sig_calls >= 1
    db.connect_block_from_bytes.assert_called_once()


# ---------------------------------------------------------------------------
# Wiring: Node.start resolves the operator's assumevalid setting and flips the
# validator's node-wide switch (the P2P BlockSync flag keeps its own copy).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    (None, False), ("", False), ("1", False),
    ("00000000000000000001d5e8fbe28e3f5ef2b5e1f5a8f8b1f4f3d9b8f6f2c1a0", False),
    ("0", True), (0, True), (" 0 ", True), ("false", True), ("no", True),
])
def test_assumevalid_disabled_parses_like_core(raw, expected):
    assert assumevalid_disabled(raw) is expected


def test_block_validator_default_is_skip_heuristic():
    v = BlockValidator(MagicMock(), network="mainnet")
    assert v.force_full_scripts is False


def test_node_start_wires_switch_into_validator():
    from ouroboros.node import BitcoinNode as Node
    src = inspect.getsource(Node.start)
    assert "force_full_scripts = assumevalid_disabled(self.config.get('assumevalid'))" in src
    assert "self.validator.force_full_scripts = force_full_scripts" in src
    assert "force_full_scripts=force_full_scripts" in src  # BlockSync keeps its copy
