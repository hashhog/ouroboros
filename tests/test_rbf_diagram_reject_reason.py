"""A single-tx replacement that fails the feerate diagram answers Core's reject.

Core validation.cpp MemPoolAccept::ReplacementChecks: after PaysForRBF,

    if (const auto err_string{ImprovesFeerateDiagram(*m_subpackage.m_changeset)}) {
        return state.Invalid(TxValidationResult::TX_RECONSIDERABLE,
                             "replacement-failed", err_string->second);
    }

and policy/rbf.cpp ImprovesFeerateDiagram's debug string is
"insufficient feerate: does not improve feerate diagram".  So
testmempoolaccept prints reject-reason "replacement-failed" and reject-details
"replacement-failed, insufficient feerate: does not improve feerate diagram"
(ValidationState::ToString), and sendrawtransaction throws -26 with that same
ToString (node/transaction.cpp HandleATMPError).

ouroboros answered "Replacement would worsen cluster feerate: 3.90 < 58.82
sat/vB" on both, and sendrawtransaction's reason mapper would have folded any
"insufficient feerate" text into "insufficient fee".  Core regtest rows
``rbf/diagram/accept:[0].reject-reason``, ``rbf/diagram/accept:[0].reject-details``
and ``rbf/diagram/submit:message``.

The scenario is the harness's ``diagram`` case: a 1-out spend paying 5_000
sats is replaced by a 40-out spend of the same coin paying 5_200.  PaysForRBF
passes (more fee, and 200 sats covers the incremental relay fee on ~1.8 kvB),
the feerate drops from ~50 to ~3 sat/vB, so the diagram gets worse.

Every test goes through an entry point that exists on master
(``Mempool.add_transaction``, ``Mempool.accept_package``,
``RPCServer.rpc_testmempoolaccept``, ``RPCServer.rpc_sendrawtransaction``).
"""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.rpc import RpcError, RPCServer  # noqa: E402
from tests.test_package_rbf_checks import _funded, _hex, _pool, _tx  # noqa: E402

CORE_REASON = "replacement-failed"
CORE_DETAILS = "replacement-failed, insufficient feerate: does not improve feerate diagram"
OUTPUTS = 40


def _diagram_case(coin_value: int = 100_000, n: int = 70):
    """Pool holding ``O`` (1 out, fee 5_000); ``R`` replaces it with 40
    outputs and fee 5_200, which passes PaysForRBF but not the diagram."""
    pool, db = _pool()
    coin = _funded(db, n, coin_value)
    o = _tx([(coin, 0)], [coin_value - 5_000])
    assert pool.add_transaction(o, 100)[0]
    spendable = coin_value - 5_200
    each = spendable // OUTPUTS
    values = [each + (spendable - each * OUTPUTS)] + [each] * (OUTPUTS - 1)
    r = _tx([(coin, 0)], values)
    return pool, db, o, r


def test_mempool_diagram_failure_is_core_reject_string():
    pool, _db, o, r = _diagram_case()
    ok, reason = pool.add_transaction(r, 100)
    assert not ok
    assert reason == "replacement-failed: insufficient feerate: does not improve feerate diagram"
    assert o.get_txid() in pool.transactions
    assert r.get_txid() not in pool.transactions


def test_testmempoolaccept_diagram_failure_reason_and_details():
    pool, db, o, r = _diagram_case(n=71)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))
    [row] = asyncio.run(RPCServer.rpc_testmempoolaccept(rpc, [_hex(r)]))
    assert row["allowed"] is False
    assert row["reject-reason"] == CORE_REASON
    assert row["reject-details"] == CORE_DETAILS
    assert o.get_txid() in pool.transactions


def test_sendrawtransaction_diagram_failure_is_minus_26_core_message():
    pool, db, o, r = _diagram_case(n=72)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db),
                          DEFAULT_MAX_RAW_TX_FEE_RATE=0.10)
    rpc._map_mempool_error_to_reject_reason = types.MethodType(
        RPCServer._map_mempool_error_to_reject_reason, rpc)
    with pytest.raises(RpcError) as exc:
        asyncio.run(RPCServer.rpc_sendrawtransaction(rpc, _hex(r)))
    assert exc.value.code == -26
    assert exc.value.message == CORE_DETAILS
    assert o.get_txid() in pool.transactions


def test_pays_for_rbf_failure_still_maps_to_insufficient_fee():
    """Guard: the new ``replacement-failed`` branch in the reason mapper must
    not swallow PaysForRBF's own "insufficient fee" reject."""
    mapper = types.MethodType(RPCServer._map_mempool_error_to_reject_reason,
                              SimpleNamespace())
    assert mapper("insufficient fee, rejecting replacement ab; new feerate "
                  "0.00001 <= old feerate 0.00002") == "insufficient fee"
    assert mapper("replacement-failed: insufficient feerate: does not improve "
                  "feerate diagram") == (
        "replacement-failed: insufficient feerate: does not improve feerate diagram")


def test_diagram_failure_alone_is_still_retried_with_the_package():
    """Core: a diagram failure is TX_RECONSIDERABLE, so AcceptPackage retries
    the parent with its child under PackageRBFChecks.  The parent fails the
    diagram alone; with a high-fee child the package beats ``O``'s chunk and
    replaces it.  Guards ``_needs_package_rbf`` against the new text."""
    pool, db, o, parent = _diagram_case(coin_value=10_000_000, n=73)
    child = _tx([(parent.get_txid(), 0)], [parent.outputs[0].value - 150_000])
    res = pool.accept_package([parent, child], 100)
    assert res.state == "valid", (res.state, getattr(res, "message", None))
    assert o.get_txid() not in pool.transactions
    assert parent.get_txid() in pool.transactions
    assert child.get_txid() in pool.transactions
