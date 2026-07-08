"""W137 — mempool RPC reject-reason token parity (ouroboros).

Pins the bare Bitcoin Core reject-reason tokens surfaced by the mempool RPC
path (``testmempoolaccept`` / ``sendrawtransaction``) after the
``fix(rpc): emit Core bare reject tokens on mempool RPC path`` change.

Covers the cases called out in
``CORE-PARITY-AUDIT/_reason-code-parity-2026-07-08.md`` (ouroboros bullet):

  * CheckTransaction family — ``validation.py::_check_structure`` now returns
    the specific token (bad-txns-vin-empty / -vout-empty / -oversize /
    -vout-negative / -vout-toolarge / -txouttotal-toolarge / -inputs-duplicate
    / -prevout-null, bad-cb-length) instead of one opaque "Invalid structure".
  * IsStandardTx tokens — ``mempool.py::_is_standard_tx`` returns bare tokens
    (version / tx-size / tx-size-small / scriptsig-size / scriptsig-not-pushonly
    / scriptpubkey / datacarrier / dust), no "Non-standard transaction:" wrap.
  * non-final — ``validate_transaction`` emits the bare "non-final" token.
  * min relay fee not met / mempool min fee not met — bare tokens.
  * orphan → missing-inputs — remapped at the ``accept_to_memory_pool`` RPC
    boundary (Core rpc/mempool.cpp:400) while the internal "orphan" control
    token is preserved for node.py's tx handler.
  * txn-already-known — new coins-cache probe (Core validation.cpp:857-864).

References:
  bitcoin-core/src/consensus/tx_check.cpp:11-59  (CheckTransaction)
  bitcoin-core/src/policy/policy.cpp:100-162      (IsStandardTx)
  bitcoin-core/src/validation.cpp:705-866         (PreChecks)
  bitcoin-core/src/rpc/mempool.cpp:399-404        (TX_MISSING_INPUTS remap)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# Install the sync-module stub before importing ouroboros (mirrors
# test_check_tx_w84 / test_atmp_w96).
import tests.conftest  # noqa: F401

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool, _is_standard_tx
from ouroboros.validation import MAX_MONEY, TransactionValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NULL_TXID = bytes(32)


def _txid(tag: int) -> bytes:
    return tag.to_bytes(4, "little") + b"\x00" * 28


def _p2pkh(seed: int = 1) -> bytes:
    return b"\x76\xa9\x14" + bytes([seed]) * 20 + b"\x88\xac"


def _txin(prev_txid: bytes = _txid(99), prev_vout: int = 0,
          script_sig: bytes = b"", sequence: int = 0xFFFFFFFF) -> TxIn:
    return TxIn(prev_txid=prev_txid, prev_vout=prev_vout,
                script_sig=script_sig, sequence=sequence)


def _txout(value: int = 1_000, script_pubkey: bytes = b"\x51") -> TxOut:
    return TxOut(value=value, script_pubkey=script_pubkey)


def _tx(inputs=None, outputs=None, version: int = 2, locktime: int = 0) -> Transaction:
    if inputs is None:
        inputs = [_txin()]
    if outputs is None:
        outputs = [_txout()]
    return Transaction(txid=b"", version=version, locktime=locktime,
                       inputs=inputs, outputs=outputs)


def _validator() -> TransactionValidator:
    db = MagicMock()
    db.get_utxo.return_value = {
        "value": 100_000, "script_pubkey": b"\x51",
        "height": 1, "is_coinbase": False,
    }
    db.get_utxo_batch.return_value = [None]
    return TransactionValidator(db=db, network="mainnet")


class _StubDB:
    def __init__(self, utxos=None, mtp=0):
        self._utxos = utxos or {}
        self._mtp = mtp

    def get_utxo(self, txid, vout):
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self._utxos.get(op) for op in outpoints]

    def get_median_time_past(self, height):
        return self._mtp


class _StubValidator:
    """Consensus validator that always passes — isolates the mempool policy
    gates (orphan / txn-already-known / min-relay) from consensus checks."""

    def __init__(self, utxos=None, mtp=0):
        self.db = _StubDB(utxos, mtp)
        self.network = "mainnet"

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


def _pool(utxos=None, require_standard=False) -> Mempool:
    return Mempool(validator=_StubValidator(utxos or {}),
                   max_size=300_000_000,
                   require_standard=require_standard, full_rbf=True)


# ---------------------------------------------------------------------------
# CheckTransaction family — validation.py::_check_structure specific tokens
# ---------------------------------------------------------------------------

class TestCheckStructureTokens:
    def test_vin_empty(self):
        tv = _validator()
        tx = _tx(inputs=[])
        assert tv._check_structure(tx) == "bad-txns-vin-empty"

    def test_vout_empty(self):
        tv = _validator()
        tx = _tx(outputs=[])
        assert tv._check_structure(tx) == "bad-txns-vout-empty"

    def test_oversize(self):
        tv = _validator()
        tx = _tx(inputs=[_txin(script_sig=bytes(1_000_001))])
        assert tv._check_structure(tx) == "bad-txns-oversize"

    def test_vout_negative(self):
        tv = _validator()
        tx = _tx(outputs=[_txout(value=0xFFFFFFFFFFFFFFFF)])  # -1 signed
        assert tv._check_structure(tx) == "bad-txns-vout-negative"

    def test_vout_toolarge(self):
        tv = _validator()
        tx = _tx(outputs=[_txout(value=MAX_MONEY + 1)])
        assert tv._check_structure(tx) == "bad-txns-vout-toolarge"

    def test_txouttotal_toolarge(self):
        tv = _validator()
        tx = _tx(outputs=[_txout(value=MAX_MONEY), _txout(value=1)])
        assert tv._check_structure(tx) == "bad-txns-txouttotal-toolarge"

    def test_inputs_duplicate(self):
        tv = _validator()
        dup = _txin(prev_txid=_txid(7), prev_vout=0)
        tx = _tx(inputs=[dup, _txin(prev_txid=_txid(7), prev_vout=0)])
        assert tv._check_structure(tx) == "bad-txns-inputs-duplicate"

    def test_prevout_null_noncoinbase(self):
        tv = _validator()
        tx = _tx(inputs=[_txin(prev_txid=NULL_TXID, prev_vout=0xFFFFFFFF),
                         _txin(prev_txid=_txid(8), prev_vout=0)])
        assert tv._check_structure(tx) == "bad-txns-prevout-null"

    def test_cb_length(self):
        tv = _validator()
        cb = _tx(inputs=[_txin(prev_txid=NULL_TXID, prev_vout=0xFFFFFFFF,
                               script_sig=b"\x01")])  # len 1 < 2
        assert tv._check_structure(cb) == "bad-cb-length"

    def test_valid_structure_returns_none(self):
        tv = _validator()
        assert tv._check_structure(_tx()) is None


# ---------------------------------------------------------------------------
# non-final — validation.py::validate_transaction bare token
# ---------------------------------------------------------------------------

def test_non_final_token():
    tv = _validator()
    # height-based locktime in the future, non-final sequence → not final.
    tx = _tx(inputs=[_txin(sequence=0xFFFFFFFE)], locktime=1000)
    ok, reason = tv.validate_transaction(tx, height=100, block_mtp=1_700_000_000)
    assert not ok
    assert reason == "non-final"


# ---------------------------------------------------------------------------
# IsStandardTx — mempool.py::_is_standard_tx bare tokens
# ---------------------------------------------------------------------------

class TestStandardnessTokens:
    def test_version(self):
        ok, reason = _is_standard_tx(_tx(version=5))
        assert not ok and reason == "version"

    def test_tx_size_small(self):
        # A minimal tx serialises to < 65 non-witness bytes → tx-size-small.
        ok, reason = _is_standard_tx(_tx())
        assert not ok and reason == "tx-size-small"

    def test_scriptsig_size(self):
        tx = _tx(inputs=[_txin(script_sig=b"\x00" * 1651)])
        ok, reason = _is_standard_tx(tx)
        assert not ok and reason == "scriptsig-size"

    def test_scriptsig_not_pushonly(self):
        # OP_DUP (0x76) is not push-only; pad to clear the 65-byte floor.
        tx = _tx(inputs=[_txin(script_sig=b"\x76" + b"\x4b" + b"\x00" * 75)])
        ok, reason = _is_standard_tx(tx)
        assert not ok and reason == "scriptsig-not-pushonly"

    def test_scriptpubkey(self):
        # Non-standard output script type (bare OP_RETURN-less junk), padded
        # so the tx clears the size floor first.
        tx = _tx(inputs=[_txin(script_sig=b"\x00" * 80)],
                 outputs=[_txout(value=1_000, script_pubkey=b"\xff\xff\xff")])
        ok, reason = _is_standard_tx(tx)
        assert not ok and reason == "scriptpubkey"


# ---------------------------------------------------------------------------
# orphan → missing-inputs boundary remap + control-signal preservation
# ---------------------------------------------------------------------------

class TestMissingInputsRemap:
    def _orphan_tx(self):
        # Spends a prevout that is absent from the (empty) UTXO set.
        return _tx(inputs=[_txin(prev_txid=_txid(555), prev_vout=0,
                                 sequence=0xFFFFFFFD)],
                   outputs=[_txout(value=1_000, script_pubkey=_p2pkh())])

    def test_internal_control_token_preserved(self):
        """node.py branches on ``error == 'orphan'`` — must stay internal."""
        pool = _pool(utxos={})
        ok, err = pool.add_transaction(self._orphan_tx(), height=200)
        assert not ok
        assert err == "orphan"

    def test_testmempoolaccept_surfaces_missing_inputs(self):
        pool = _pool(utxos={})
        res = pool.accept_to_memory_pool(self._orphan_tx(), height=200,
                                         test_accept=True)
        assert res["accepted"] is False
        assert res["reject_reason"] == "missing-inputs"

    def test_rpc_reject_reason_helper(self):
        assert Mempool._rpc_reject_reason("orphan") == "missing-inputs"
        # Every other token passes through unchanged.
        for tok in ("dust", "version", "non-final", "coinbase",
                    "min relay fee not met", "bad-txns-vin-empty"):
            assert Mempool._rpc_reject_reason(tok) == tok


# ---------------------------------------------------------------------------
# txn-already-known — coins-cache probe (Core validation.cpp:857-864)
# ---------------------------------------------------------------------------

def test_txn_already_known():
    tx = _tx(inputs=[_txin(prev_txid=_txid(777), prev_vout=0,
                           sequence=0xFFFFFFFD)],
             outputs=[_txout(value=1_000, script_pubkey=_p2pkh())])
    own_txid = tx.get_txid()
    # Parent prevout absent (→ missing input) but THIS tx's own output is
    # already in the UTXO set (→ already confirmed in the chain).
    pool = _pool(utxos={(own_txid, 0): {"value": 1_000,
                                        "script_pubkey": _p2pkh(),
                                        "height": 1, "is_coinbase": False}})
    ok, err = pool.add_transaction(tx, height=200)
    assert not ok
    assert err == "txn-already-known"


# ---------------------------------------------------------------------------
# min relay fee not met — mempool.py bare token
# ---------------------------------------------------------------------------

def test_min_relay_fee_not_met():
    parent = _txid(321)
    utxos = {(parent, 0): {"value": 1_000, "script_pubkey": _p2pkh(),
                           "height": 1, "is_coinbase": False}}
    pool = _pool(utxos=utxos)
    # fee = 1_000 - 999 = 1 sat, far below the min-relay floor for the vsize.
    tx = _tx(inputs=[_txin(prev_txid=parent, prev_vout=0, sequence=0xFFFFFFFF)],
             outputs=[_txout(value=999, script_pubkey=_p2pkh())])
    res = pool.accept_to_memory_pool(tx, height=200, test_accept=True)
    assert res["accepted"] is False
    assert res["reject_reason"] == "min relay fee not met"
