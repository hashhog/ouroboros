"""Package RBF in submitpackage, as Core's PackageRBFChecks.

Item refill-20261114-ouroboros-policy (the core-regtest ``package_rbf``
group).  Core references:
  validation.cpp AcceptPackage (a tx that fails PaysForRBF or the feerate
  diagram on its own is TX_RECONSIDERABLE and is retried with the package),
  AcceptMultipleTransactionsInternal (PackageChildWithParents args allow
  replacement; PackageRBFChecks after the package feerate check),
  MemPoolAccept::PackageRBFChecks (1-parent-1-child, no in-pool ancestors,
  GetEntriesForConflicts, PaysForRBF over the package, package feerate above
  the parent's, CheckMemPoolPolicyLimits, ImprovesFeerateDiagram),
  policy/rbf.cpp PaysForRBF (debug strings, FormatMoney).

Every test goes through an entry point that exists on master
(``Mempool.accept_package``, ``Mempool.add_transaction``,
``RPCServer.rpc_submitpackage``), so master runs them and fails on the
assertion.  On master a package that needs package RBF was refused with
"Package conflicts with mempool: ... already spent" and no tx-results.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ouroboros.mempool as mempool_mod  # noqa: E402
from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402

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
    """Resolves every input (chain, then the package overlay) or fails,
    checks value, fails scriptSig BAD like a script error."""

    network = "regtest"

    def __init__(self, db):
        self.db = db

    def validate_transaction(self, tx, height, mtp=None, extra_script_flags=None,
                             intra_block_utxos=None, **_kw):
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
    return SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))


def _hex(tx) -> str:
    return tx.serialize().hex()


def _be(b: bytes) -> str:
    return b[::-1].hex()


def _conflict_and_descendant(pool, db, n: int):
    """``O`` spends coin *n* (fee 10_000), ``D`` spends ``O`` (fee 1_000)."""
    coin = _funded(db, n)
    o = _tx([(coin, 0)], [90_000])
    assert pool.add_transaction(o, 100)[0]
    d = _tx([(o.get_txid(), 0)], [89_000])
    assert pool.add_transaction(d, 100)[0]
    return coin, o, d


def _submit(pool, db, *txs):
    return asyncio.run(RPCServer.rpc_submitpackage(
        _rpc(pool, db), [_hex(t) for t in txs]))


def _untouched(pool, o, d, parent, child):
    assert o.get_txid() in pool.transactions
    assert d.get_txid() in pool.transactions
    assert parent.get_txid() not in pool.transactions
    assert child.get_txid() not in pool.transactions


def test_package_rbf_success_reports_core_tx_results():
    """The ``at-limit`` row shape: per-tx vsize and fees at the package
    feerate with both wtxids in effective-includes, and the replaced txs."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 40)
    parent = _tx([(coin, 0)], [94_000])                   # fee 6_000
    child = _tx([(parent.get_txid(), 0)], [44_000])       # fee 50_000
    res = _submit(pool, db, parent, child)
    assert res["package_msg"] == "success", res
    pr = res["tx-results"][_be(parent.get_wtxid())]
    cr = res["tx-results"][_be(child.get_wtxid())]
    assert pr["txid"] == _be(parent.get_txid())
    assert pr["fees"]["effective-includes"] == [
        _be(parent.get_wtxid()), _be(child.get_wtxid())]
    assert cr["fees"]["effective-includes"] == pr["fees"]["effective-includes"]
    assert pr["fees"]["effective-feerate"] == cr["fees"]["effective-feerate"]
    assert "error" not in pr and "error" not in cr
    assert sorted(res["replaced-transactions"]) == sorted(
        [_be(o.get_txid()), _be(d.get_txid())])
    assert o.get_txid() not in pool.transactions
    assert d.get_txid() not in pool.transactions
    assert parent.get_txid() in pool.transactions
    assert child.get_txid() in pool.transactions
    # The pool is consistent: the coin is now spent by the parent only.
    assert pool.spender_by_outpoint[(coin, 0)] == parent.get_txid()


def test_package_rbf_too_large_cluster_keeps_the_conflicts(monkeypatch):
    """The ``over`` row: the cluster limit on the new two-tx cluster decides.
    Core: package_msg "too-large-cluster" and the per-tx results are the
    individual ones -- the parent's PaysForRBF failure (Core's string, with
    its txid and FormatMoney amounts) and the child's missing inputs."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 41)
    parent = _tx([(coin, 0)], [94_000])
    child = _tx([(parent.get_txid(), 0)], [44_000])
    weight = parent.get_weight() + child.get_weight()
    monkeypatch.setattr(mempool_mod, "MAX_CLUSTER_SIZE_WEIGHT", weight - 1)
    res = _submit(pool, db, parent, child)
    assert res["package_msg"] == "too-large-cluster", res
    assert res["tx-results"][_be(parent.get_wtxid())] == {
        "txid": _be(parent.get_txid()),
        "error": (f"insufficient fee, rejecting replacement {_be(parent.get_txid())}, "
                  "less fees than conflicting txs; 0.00006 < 0.00011"),
    }
    assert res["tx-results"][_be(child.get_wtxid())] == {
        "txid": _be(child.get_txid()),
        "error": "bad-txns-inputs-missingorspent",
    }
    assert res["replaced-transactions"] == []
    _untouched(pool, o, d, parent, child)


def test_package_rbf_at_the_cluster_limit_is_accepted(monkeypatch):
    """The limit is strict ``>`` (txgraph): a cluster of exactly the limit
    replaces (the ``at-limit`` control)."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 42)
    parent = _tx([(coin, 0)], [94_000])
    child = _tx([(parent.get_txid(), 0)], [44_000])
    weight = parent.get_weight() + child.get_weight()
    monkeypatch.setattr(mempool_mod, "MAX_CLUSTER_SIZE_WEIGHT", weight)
    res = _submit(pool, db, parent, child)
    assert res["package_msg"] == "success", res
    assert o.get_txid() not in pool.transactions


def test_package_rbf_insufficient_anti_dos_fees():
    """PaysForRBF over the package (rule 3), attributed to the child."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 43)
    parent = _tx([(coin, 0)], [94_000])                   # fee 6_000
    child = _tx([(parent.get_txid(), 0)], [93_000])       # fee 1_000
    res = pool.accept_package([parent, child], 100)
    assert res.state == "policy"
    assert res.message == (
        "package RBF failed: insufficient anti-DoS fees, rejecting replacement "
        f"{_be(child.get_txid())}, less fees than conflicting txs; "
        "0.00007 < 0.00011")
    _untouched(pool, o, d, parent, child)


def test_package_rbf_child_must_raise_the_package_feerate():
    """A child that only pays the anti-DoS fees, at a lower feerate than its
    parent, is refused (Core: the package must be a chunk on its own)."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 44)
    parent = _tx([(coin, 0)], [89_500])                   # fee 10_500, small
    child = _tx([(parent.get_txid(), 0)], [48_500] + [1_000] * 40)  # fee 1_000, large
    res = pool.accept_package([parent, child], 100)
    assert res.state == "policy"
    assert res.message.startswith(
        "package RBF failed: package feerate is less than or equal to parent "
        "feerate, package feerate "), res.message
    assert " BTC/kvB <= parent feerate is " in res.message
    _untouched(pool, o, d, parent, child)


def test_package_rbf_must_improve_the_feerate_diagram():
    """Enough fees in total, child above parent, but the package's feerate is
    far below the conflicts' chunk: Core's ImprovesFeerateDiagram fails."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 45)
    parent = _tx([(coin, 0)], [37_000] + [1_000] * 60)    # fee 3_000, ~2.6 kvB
    child = _tx([(parent.get_txid(), 0)], [28_000])       # fee 9_000, small
    res = pool.accept_package([parent, child], 100)
    assert res.state == "policy"
    assert res.message == (
        "package RBF failed: insufficient feerate: does not improve feerate diagram")
    _untouched(pool, o, d, parent, child)


def test_package_rbf_only_for_one_parent_one_child():
    """Two parents and a child: Core refuses package RBF ("package must be
    1-parent-1-child") and the conflicts stay."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 46)
    rbf_parent = _tx([(coin, 0)], [94_000])               # fails RBF alone
    low_parent = _tx([(_funded(db, 47), 0)], [100_000])   # 0 fee: below min relay
    child = _tx([(rbf_parent.get_txid(), 0), (low_parent.get_txid(), 0)], [150_000])
    res = pool.accept_package([rbf_parent, low_parent, child], 100)
    assert res.state == "policy"
    assert res.message == "package RBF failed: package must be 1-parent-1-child"
    _untouched(pool, o, d, rbf_parent, child)
    assert low_parent.get_txid() not in pool.transactions


def test_package_rbf_invalid_child_replaces_nothing():
    """A child that fails its own validation cannot carry a replacement:
    the package fails on the child and the conflicts stay."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 48)
    parent = _tx([(coin, 0)], [94_000])
    child = _tx([(parent.get_txid(), 0)], [44_000], script_sig=b"BAD")
    res = pool.accept_package([parent, child], 100)
    assert res.state == "tx" and res.message == "transaction failed"
    _untouched(pool, o, d, parent, child)


def test_testmempoolaccept_package_still_refuses_conflicts():
    """Core's PackageTestAccept args disallow replacement: a multi-tx
    testmempoolaccept is not a package RBF and changes nothing."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 49)
    parent = _tx([(coin, 0)], [94_000])
    child = _tx([(parent.get_txid(), 0)], [44_000])
    res = pool.accept_package([parent, child], 100, test_accept=True)
    assert res.state == "tx"
    assert [r.reject_reason for r in res.results.values()] == [
        "bad-txns-spends-conflicting-tx"]
    _untouched(pool, o, d, parent, child)


def test_failed_insert_after_package_rbf_restores_the_conflicts(monkeypatch):
    """Core applies a package RBF's changeset atomically.  If the child
    cannot be inserted after the conflicts were evicted, the inserted parent
    is rolled back and the evicted txs are put back."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 50)
    parent = _tx([(coin, 0)], [94_000])
    child = _tx([(parent.get_txid(), 0)], [44_000])
    real = pool._add_transaction_inner

    def flaky(tx, *a, **kw):
        # Only the final insert of the package (package feerate, no
        # overlay, not a dry run); the child's individual try and the
        # package evaluation run normally.
        if (tx.get_txid() == child.get_txid() and kw.get("package_feerate")
                and not kw.get("test_accept") and kw.get("package_coins") is None):
            return False, "simulated insert failure"
        return real(tx, *a, **kw)

    monkeypatch.setattr(pool, "_add_transaction_inner", flaky)
    res = pool.accept_package([parent, child], 100)
    assert res.state == "tx" and res.message == "transaction failed"
    assert res.results[child.get_wtxid()].reject_reason == "simulated insert failure"
    _untouched(pool, o, d, parent, child)
    assert pool.spender_by_outpoint[(coin, 0)] == o.get_txid()
    assert pool.spender_by_outpoint[(o.get_txid(), 0)] == d.get_txid()


def test_single_rbf_fee_failure_uses_core_paysforrbf_string():
    """policy/rbf.cpp PaysForRBF: "rejecting replacement <txid>, less fees
    than conflicting txs; <FormatMoney> < <FormatMoney>", under the
    "insufficient fee" reject reason (validation.cpp ReplacementChecks)."""
    pool, db = _pool()
    coin, o, d = _conflict_and_descendant(pool, db, 51)
    r = _tx([(coin, 0)], [94_000])
    ok, err = pool.add_transaction(r, 100)
    assert not ok
    assert err == (f"insufficient fee, rejecting replacement {_be(r.get_txid())}, "
                   "less fees than conflicting txs; 0.00006 < 0.00011")


def test_format_money_matches_core():
    """util/moneystr.cpp FormatMoney: trailing zeros trimmed to two decimals."""
    fm = mempool_mod.format_money
    assert fm(6_000) == "0.00006"
    assert fm(21_000) == "0.00021"
    assert fm(100_000_000) == "1.00"
    assert fm(0) == "0.00"
    assert fm(123_456_789) == "1.23456789"
    assert fm(-5_000) == "-0.00005"
