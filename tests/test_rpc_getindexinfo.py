"""Tests for the ``getindexinfo`` RPC handler.

Mirrors Bitcoin Core ``rpc/node.cpp:363-410`` (getindexinfo) +
``:351-361`` (SummaryToJSON) + ``index/base.cpp:472-484`` (GetSummary).

The handler returns a dynamic JSON OBJECT keyed BY INDEX NAME (the literal
``GetName()`` string, e.g. ``txindex`` / ``basic block filter index``). Each
value has EXACTLY two keys, IN THIS ORDER: ``synced`` (bool) then
``best_block_height`` (int). No ``best_hash`` / ``best_block_hash``, no name
nested inside the value. Only ENABLED indexes appear.

Coverage:
- shape: dynamic key == index name; value keys + order + types.
- enabled-only: ouroboros has no coinstatsindex / txospenderindex, so those
  Core branches never appear; the block filter index appears only when wired.
- arg behaviour: empty/omitted -> all running indexes; a matching ``index_name``
  filters to just that entry; an unknown name -> ``{}`` (empty object, NOT an
  error -- SummaryToJSON:354).
- best_block_height == the index best height (== chain tip for the inline
  txindex); 0 when there is no best block.
"""
from __future__ import annotations

import pytest

from ouroboros.rpc import RPCServer


class _StubDb:
    """Minimal db exposing the surface getindexinfo probes.

    ``get_tx_index`` presence mirrors Core's ``if (g_txindex)`` always-on guard.
    ``get_best_block`` returns the ``(hash, height)`` tuple (database.py:760);
    the txindex is written inline with each connected block so its best height
    equals the chain tip.
    """

    def __init__(self, tip_height: int | None) -> None:
        self._tip_height = tip_height

    def get_tx_index(self, *_a, **_k):  # presence is what matters
        return None

    def get_best_block(self):
        return (b"\x00" * 32, self._tip_height)


class _StubBlockFilterIndex:
    def __init__(self, best_height: int | None, synced: bool) -> None:
        self.best_indexed_height = best_height
        self._synced = synced

    def is_synced(self, _tip_height: int) -> bool:
        return self._synced


def _make_rpc(
    tip_height: int | None = 5,
    *,
    with_db: bool = True,
    block_filter_index: _StubBlockFilterIndex | None = None,
) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = _StubDb(tip_height) if with_db else None
    node.block_filter_index = block_filter_index
    rpc.node = node
    return rpc


@pytest.mark.asyncio
async def test_shape_key_value_order_and_types() -> None:
    rpc = _make_rpc(tip_height=5)
    res = await rpc.rpc_getindexinfo()
    # Dynamic object keyed by the literal GetName() string.
    assert "txindex" in res
    val = res["txindex"]
    # EXACTLY two keys, in Core's order: synced, then best_block_height.
    assert list(val.keys()) == ["synced", "best_block_height"]
    assert val["synced"] is True
    assert val["best_block_height"] == 5
    # Types: synced is a real bool, height a plain int (not hex).
    assert isinstance(val["synced"], bool)
    assert isinstance(val["best_block_height"], int)
    # No best_hash / best_block_hash / nested name leaks into the value.
    assert "best_hash" not in val
    assert "best_block_hash" not in val
    assert "name" not in val


@pytest.mark.asyncio
async def test_enabled_only_no_coinstats_or_txospender() -> None:
    # ouroboros runs only txindex by default; coinstatsindex / txospenderindex
    # have no substrate, so they never appear (Core enabled-only semantics).
    rpc = _make_rpc(tip_height=5)
    res = await rpc.rpc_getindexinfo()
    assert set(res.keys()) == {"txindex"}
    assert "coinstatsindex" not in res
    assert "txospenderindex" not in res


@pytest.mark.asyncio
async def test_block_filter_index_appears_only_when_wired() -> None:
    bfi = _StubBlockFilterIndex(best_height=5, synced=True)
    rpc = _make_rpc(tip_height=5, block_filter_index=bfi)
    res = await rpc.rpc_getindexinfo()
    assert "basic block filter index" in res
    bf_val = res["basic block filter index"]
    assert list(bf_val.keys()) == ["synced", "best_block_height"]
    assert bf_val["synced"] is True
    assert bf_val["best_block_height"] == 5


@pytest.mark.asyncio
async def test_index_name_filters_to_single_entry() -> None:
    bfi = _StubBlockFilterIndex(best_height=5, synced=True)
    rpc = _make_rpc(tip_height=5, block_filter_index=bfi)
    only_tx = await rpc.rpc_getindexinfo("txindex")
    assert set(only_tx.keys()) == {"txindex"}
    only_bf = await rpc.rpc_getindexinfo("basic block filter index")
    assert set(only_bf.keys()) == {"basic block filter index"}


@pytest.mark.asyncio
async def test_unknown_index_name_returns_empty_object_not_error() -> None:
    rpc = _make_rpc(tip_height=5)
    # SummaryToJSON:354 -- a non-matching name drops every entry; the result is
    # an empty object, NOT an error.
    res = await rpc.rpc_getindexinfo("no-such-index")
    assert res == {}


@pytest.mark.asyncio
async def test_best_block_height_zero_when_no_best_block() -> None:
    # GetSummary: best_block_height = 0 when there is no best block index.
    rpc = _make_rpc(tip_height=None)
    res = await rpc.rpc_getindexinfo()
    assert res["txindex"]["best_block_height"] == 0
