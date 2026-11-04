"""Staged package acceptance, as Core's AcceptPackage / AcceptMultipleTransactions.

Item ouroboros-package-staging.  Core references:
  validation.cpp AcceptPackage (individual first, in-pool de-duplication,
  package-feerate retry of fee/missing-input failures),
  AcceptMultipleTransactionsInternal (package coin view, fail-fast),
  rpc/mempool.cpp testmempoolaccept (>1 tx = package test accept) and
  submitpackage (per-tx results keyed by wtxid, replaced-transactions).

Every test goes through an entry point that exists on master
(``Mempool.validate_package``, ``RPCServer.rpc_testmempoolaccept``,
``RPCServer.rpc_submitpackage``), so master runs them and fails on the
assertion.

The validator stub below is strict where the package path could make an
invalid tx valid: every input must resolve (chain, pool, or the
``intra_block_utxos`` overlay the mempool passes), outputs may not exceed
inputs, and a scriptSig of ``BAD`` fails like a script error.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402
from ouroboros.rpc import RpcError, RPCServer  # noqa: E402

SPK = bytes([0x51, 0x20]) + bytes(32)  # P2TR-shaped, 43 bytes


class _DB:
    def __init__(self):
        self.utxos: dict = {}

    def add(self, txid: bytes, vout: int, value: int):
        self.utxos[(txid, vout)] = {
            "txid": txid, "vout": vout, "value": value, "script_pubkey": SPK,
            "height": 1, "is_coinbase": False,
        }

    def get_utxo(self, txid, vout):
        return self.utxos.get((txid, vout))

    def get_median_time_past(self, height=None):
        return 1_600_000_000

    def get_best_block(self):
        return b"\x00" * 32, 100


class _StrictValidator:
    """Resolves every input or fails, checks value, fails scriptSig BAD."""

    network = "regtest"

    def __init__(self, db):
        self.db = db
        self.calls: list = []

    def validate_transaction(self, tx, height, mtp=None, extra_script_flags=None,
                             intra_block_utxos=None, **_kw):
        self.calls.append(tx.get_txid())
        total_in = 0
        for inp in tx.inputs:
            coin = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if coin is None and intra_block_utxos:
                coin = intra_block_utxos.get((inp.prev_txid, inp.prev_vout))
            if coin is None:
                return False, "bad-txns-inputs-missingorspent"
            if inp.script_sig == b"BAD":
                return False, "mandatory-script-verify-flag-failed"
            total_in += coin["value"]
        if sum(o.value for o in tx.outputs) > total_in:
            return False, "bad-txns-in-belowout"
        return True, ""


def _pool():
    db = _DB()
    return Mempool(validator=_StrictValidator(db), require_standard=False), db


def _tx(inputs, values, script_sig=b"\x51"):
    """A tx whose txid is the real hash: built, serialized and parsed back
    the way the RPC decodes it."""
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=t, prev_vout=v, script_sig=script_sig,
                     sequence=0xFFFFFFFD) for t, v in inputs],
        outputs=[TxOut(value=x, script_pubkey=SPK) for x in values],
    )
    return TxMessage.from_payload(tmp.serialize()).transaction


def _funded(db, n: int, value: int = 100_000) -> bytes:
    txid = bytes([n]) * 32
    db.add(txid, 0, value)
    return txid


def _rpc(pool, db):
    node = SimpleNamespace(mempool=pool, db=db)
    return SimpleNamespace(node=node)


def _hex(tx: Transaction) -> str:
    return tx.serialize().hex()


def _be(b: bytes) -> str:
    return b[::-1].hex()


# --------------------------------------------------------------------------
# Mempool.validate_package (submitpackage path, AcceptPackage)
# --------------------------------------------------------------------------

def test_package_parent_already_in_pool_is_deduplicated_not_rejected():
    """Core AcceptPackage: a package tx already in the pool is reported as a
    mempool entry and the rest of the package is still evaluated.  Master
    rejected the whole package ("already in mempool")."""
    pool, db = _pool()
    coin = _funded(db, 1)
    parent = _tx([(coin, 0)], [90_000])
    ok, err = pool.add_transaction(parent, 100)
    assert ok, err
    child = _tx([(parent.get_txid(), 0)], [80_000])
    ok, err = pool.validate_package([parent, child], 100)
    assert ok, err
    assert child.get_txid() in pool.transactions


def test_package_child_of_rejected_parent_not_admitted():
    """A parent failing for a non-fee reason (script) ends the package; the
    child must not get in through the package overlay."""
    pool, db = _pool()
    coin = _funded(db, 2)
    parent = _tx([(coin, 0)], [90_000], script_sig=b"BAD")
    child = _tx([(parent.get_txid(), 0)], [80_000])
    ok, _err = pool.validate_package([parent, child], 100)
    assert not ok
    assert parent.get_txid() not in pool.transactions
    assert child.get_txid() not in pool.transactions


def test_package_child_spending_missing_parent_output_rejected():
    """The overlay holds only outputs the parent really has: a child spending
    vout 5 of a one-output package parent fails, and is not admitted."""
    pool, db = _pool()
    coin = _funded(db, 3)
    parent = _tx([(coin, 0)], [100_000])  # fee 0: below min relay alone -> package eval
    child = _tx([(parent.get_txid(), 5)], [80_000])
    ok, _err = pool.validate_package([parent, child], 100)
    assert not ok
    assert child.get_txid() not in pool.transactions
    assert parent.get_txid() not in pool.transactions


def test_low_feerate_package_rejected_and_pool_unchanged():
    """Package feerate below the min relay fee: both rejected, nothing
    inserted (the insert pass skips the per-tx floors, so this proves the
    package-level check runs first)."""
    pool, db = _pool()
    coin = _funded(db, 4)
    parent = _tx([(coin, 0)], [100_000])          # fee 0
    child = _tx([(parent.get_txid(), 0)], [100_000])  # fee 0
    ok, _err = pool.validate_package([parent, child], 100)
    assert not ok
    assert len(pool.transactions) == 0


def test_cpfp_package_accepted():
    pool, db = _pool()
    coin = _funded(db, 5)
    parent = _tx([(coin, 0)], [99_999])               # fee 1: below relay alone
    child = _tx([(parent.get_txid(), 0)], [90_000])   # pays for both
    ok, err = pool.validate_package([parent, child], 100)
    assert ok, err
    assert parent.get_txid() in pool.transactions
    assert child.get_txid() in pool.transactions
    assert pool.wtxid_to_txid.get(child.get_wtxid()) == child.get_txid()


# --------------------------------------------------------------------------
# testmempoolaccept with more than one tx (package test accept)
# --------------------------------------------------------------------------

def test_testmempoolaccept_child_resolves_parent_from_package():
    """Core: >1 tx is ProcessNewPackage(test_accept=true); the child spends
    the package parent.  Master answered the child "missing-inputs"."""
    pool, db = _pool()
    coin = _funded(db, 6)
    parent = _tx([(coin, 0)], [99_000])
    child = _tx([(parent.get_txid(), 0)], [98_000])
    res = asyncio.run(RPCServer.rpc_testmempoolaccept(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert [r.get("allowed") for r in res] == [True, True], res
    for r, tx in zip(res, (parent, child), strict=True):
        assert r["txid"] == _be(tx.get_txid())
        assert "reject-reason" not in r
        assert r["vsize"] == tx.get_vsize()
        assert r["fees"]["base"] == 1_000 / 1e8
        assert r["fees"]["effective-includes"] == [_be(tx.get_wtxid())]
    assert len(pool.transactions) == 0  # a test accept changes nothing


def test_testmempoolaccept_package_first_failure_leaves_rest_unverdicted():
    """Core AcceptMultipleTransactions fails fast: the failing tx gets its
    reason, later txs only txid/wtxid."""
    pool, db = _pool()
    coin = _funded(db, 7)
    parent = _tx([(coin, 0)], [99_999])  # fee 1 < min relay
    child = _tx([(parent.get_txid(), 0)], [90_000])
    res = asyncio.run(RPCServer.rpc_testmempoolaccept(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert res[0]["allowed"] is False
    assert res[0]["reject-reason"] == "min relay fee not met"
    assert res[0]["reject-details"].startswith("min relay fee not met, 1 < ")
    assert set(res[1]) == {"txid", "wtxid"}


def test_testmempoolaccept_malformed_package_reports_package_error():
    pool, db = _pool()
    coin = _funded(db, 8)
    parent = _tx([(coin, 0)], [99_000])
    child = _tx([(parent.get_txid(), 0)], [98_000])
    res = asyncio.run(RPCServer.rpc_testmempoolaccept(
        _rpc(pool, db), [_hex(child), _hex(parent)]))
    assert [r.get("package-error") for r in res] == ["package-not-sorted"] * 2
    assert all("allowed" not in r for r in res)


# --------------------------------------------------------------------------
# submitpackage per-tx results
# --------------------------------------------------------------------------

def test_submitpackage_reports_per_tx_results_on_failure():
    """Core: parent accepted on its own stays in the pool and is reported;
    the child with a missing input gets bad-txns-inputs-missingorspent.
    Master returned tx-results {} and admitted nothing."""
    pool, db = _pool()
    coin = _funded(db, 9)
    parent = _tx([(coin, 0)], [99_000])
    child = _tx([(parent.get_txid(), 0), (b"\x22" * 32, 1)], [97_000])
    res = asyncio.run(RPCServer.rpc_submitpackage(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert res["package_msg"] == "transaction failed"
    assert res["replaced-transactions"] == []
    pr = res["tx-results"][_be(parent.get_wtxid())]
    assert pr["vsize"] == parent.get_vsize()
    assert pr["fees"]["effective-includes"] == [_be(parent.get_wtxid())]
    cr = res["tx-results"][_be(child.get_wtxid())]
    assert cr == {"txid": _be(child.get_txid()),
                  "error": "bad-txns-inputs-missingorspent"}
    assert parent.get_txid() in pool.transactions
    assert child.get_txid() not in pool.transactions


def test_submitpackage_cpfp_effective_feerate_is_package_feerate():
    pool, db = _pool()
    coin = _funded(db, 10)
    parent = _tx([(coin, 0)], [99_999])
    child = _tx([(parent.get_txid(), 0)], [79_999])
    res = asyncio.run(RPCServer.rpc_submitpackage(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert res["package_msg"] == "success", res
    total_vsize = parent.get_vsize() + child.get_vsize()
    rate = (20_001 * 1000 // total_vsize) / 1e8
    both = sorted([_be(parent.get_wtxid()), _be(child.get_wtxid())])
    for tx in (parent, child):
        fees = res["tx-results"][_be(tx.get_wtxid())]["fees"]
        assert fees["effective-feerate"] == pytest.approx(rate)
        assert sorted(fees["effective-includes"]) == both


def test_submitpackage_in_pool_parent_reported_without_effective_feerate():
    """Core MEMPOOL_ENTRY result: vsize and fees.base only."""
    pool, db = _pool()
    coin = _funded(db, 11)
    parent = _tx([(coin, 0)], [90_000])
    assert pool.add_transaction(parent, 100)[0]
    child = _tx([(parent.get_txid(), 0)], [80_000])
    res = asyncio.run(RPCServer.rpc_submitpackage(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert res["package_msg"] == "success", res
    pr = res["tx-results"][_be(parent.get_wtxid())]
    assert pr["fees"] == {"base": 10_000 / 1e8}
    assert child.get_txid() in pool.transactions


def test_submitpackage_parents_depending_on_each_other_is_rpc_error():
    """Core submitpackage: not child-with-parents-tree -> RPC error before
    validation (JSONRPCTransactionError INVALID_PACKAGE, -25)."""
    pool, db = _pool()
    coin = _funded(db, 12)
    a = _tx([(coin, 0)], [99_000])
    b = _tx([(a.get_txid(), 0)], [98_000])
    c = _tx([(b.get_txid(), 0)], [97_000])  # spends b only: a is no parent of c
    with pytest.raises(RpcError) as exc:
        asyncio.run(RPCServer.rpc_submitpackage(
            _rpc(pool, db), [_hex(a), _hex(b), _hex(c)]))
    assert exc.value.code == -25
    assert len(pool.transactions) == 0


def test_testmempoolaccept_script_failure_keeps_earlier_results():
    """Core AcceptMultipleTransactions: PreChecks for all txs, then script
    checks in order; in a test accept the txs before the script failure
    already have their (allowed) result."""
    pool, db = _pool()
    coin = _funded(db, 13)
    parent = _tx([(coin, 0)], [99_000])
    child = _tx([(parent.get_txid(), 0)], [98_000], script_sig=b"BAD")
    res = asyncio.run(RPCServer.rpc_testmempoolaccept(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert res[0]["allowed"] is True
    assert res[0]["vsize"] == parent.get_vsize()
    assert res[1]["allowed"] is False
    assert res[1]["reject-reason"] == "mandatory-script-verify-flag-failed"


def test_testmempoolaccept_later_prechecks_failure_beats_earlier_script_failure():
    """A later tx failing PreChecks (missing input) is reported instead of an
    earlier tx's script failure, as Core runs every PreChecks first."""
    pool, db = _pool()
    coin = _funded(db, 14)
    parent = _tx([(coin, 0)], [99_000], script_sig=b"BAD")
    child = _tx([(parent.get_txid(), 0), (b"\x33" * 32, 0)], [98_000])
    res = asyncio.run(RPCServer.rpc_testmempoolaccept(
        _rpc(pool, db), [_hex(parent), _hex(child)]))
    assert set(res[0]) == {"txid", "wtxid"}
    assert res[1]["allowed"] is False
    assert res[1]["reject-reason"] == "missing-inputs"
