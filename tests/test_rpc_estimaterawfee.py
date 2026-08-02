"""
Tests for the estimaterawfee RPC handler.

Reference: bitcoin-core/src/rpc/fees.cpp estimaterawfee.

ouroboros's bucket-based ``FeeEstimator`` tracks three horizons (short /
medium / long — Core's shortStats / feeStats / longStats), so the response
object carries ``"short"``, ``"medium"`` and ``"long"`` keys.
"""

from __future__ import annotations

import pytest


class _StubNode:
    def __init__(self, fee_estimator):
        self.fee_estimator = fee_estimator


@pytest.fixture
def rpc_with_estimator():
    from ouroboros.fee_estimator import FeeEstimator
    from ouroboros.rpc import RPCServer

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = _StubNode(FeeEstimator())
    return rpc


@pytest.mark.asyncio
async def test_estimaterawfee_invalid_conf_target(rpc_with_estimator):
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        await rpc_with_estimator.rpc_estimaterawfee(0)
    with pytest.raises(HTTPException):
        await rpc_with_estimator.rpc_estimaterawfee(2000)


@pytest.mark.asyncio
async def test_estimaterawfee_invalid_threshold(rpc_with_estimator):
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        await rpc_with_estimator.rpc_estimaterawfee(6, threshold=-0.1)
    with pytest.raises(HTTPException):
        await rpc_with_estimator.rpc_estimaterawfee(6, threshold=1.5)


@pytest.mark.asyncio
async def test_estimaterawfee_no_data_returns_long_horizon_with_error(
    rpc_with_estimator,
):
    """With zero observations, every bucket fails the threshold; the result
    must report a ``long`` horizon with an ``errors`` array."""
    result = await rpc_with_estimator.rpc_estimaterawfee(6)
    assert "long" in result
    horizon = result["long"]
    assert "decay" in horizon
    assert "scale" in horizon
    assert "errors" in horizon
    assert horizon["errors"]
    assert "feerate" not in horizon


@pytest.mark.asyncio
async def test_estimaterawfee_returns_pass_bucket_with_data(
    rpc_with_estimator,
):
    """Inject confirmation data so a bucket meets the success threshold and
    confirm the response carries a ``pass`` bucket and a ``feerate``."""
    fe = rpc_with_estimator.node.fee_estimator
    # Force bucket 5 (10 sat/vB boundary) to a 100 % success rate at conf
    # target 6 by writing the running counters directly.  The estimator is
    # 3-horizon since W114/FIX-48 (6c0d1f4): counters live per horizon and
    # are indexed by *period*, so target 6 lands in LONG period
    # ceil(6 / 24) = 1 (one LONG period spans 24 blocks).
    bucket_idx = 5
    target = 6
    period = 1
    fe.long_totals[bucket_idx][period] = 50.0
    fe.long_stats[bucket_idx][period] = 50.0  # 100 % success

    result = await rpc_with_estimator.rpc_estimaterawfee(target, threshold=0.85)
    assert "long" in result
    horizon = result["long"]
    assert "feerate" in horizon
    assert "pass" in horizon
    pass_bucket = horizon["pass"]
    # Bucket 5 lower bound is 10 sat/vB.
    assert pass_bucket["startrange"] == pytest.approx(10.0)
    assert pass_bucket["withintarget"] == pytest.approx(50.0)
    assert pass_bucket["totalconfirmed"] == pytest.approx(50.0)
    # leftmempool is total - confirmed (after rounding).
    assert pass_bucket["leftmempool"] == pytest.approx(0.0)
    # feerate is sat/vB → BTC/kB.  10 sat/vB = 10*1000/1e8 = 1e-4 BTC/kB.
    assert horizon["feerate"] == pytest.approx(1e-4)


@pytest.mark.asyncio
async def test_estimaterawfee_no_estimator_returns_errors(rpc_with_estimator):
    """If the node has no fee estimator attached, the call must still return
    a long-horizon dict with an errors array (rather than exploding)."""
    rpc_with_estimator.node.fee_estimator = None
    result = await rpc_with_estimator.rpc_estimaterawfee(6)
    assert "long" in result
    assert "errors" in result["long"]
