"""Tests for the ``getchaintxstats`` RPC handler.

Mirrors Bitcoin Core ``rpc/blockchain.cpp:1809-1898`` (getchaintxstats) +
``chain.h`` GetMedianTimePast (11-block window) + ``chain.cpp`` GetAncestor.
Signature ``getchaintxstats ( nblocks "blockhash" )`` — both args optional.

The response is a JSON OBJECT whose keys appear in this exact order:
``time`` (int, RAW header nTime of the final block), ``txcount`` (int,
cumulative tx count genesis..final), ``window_final_block_hash`` (display hex
str), ``window_final_block_height`` (int), ``window_block_count`` (int); then,
ONLY when ``window_block_count > 0``: ``window_interval`` (int seconds, via
median-time-past) then ``window_tx_count`` (int); and ONLY when
``window_interval > 0``: ``txrate`` (float, tx/sec).

NOTE on field order: Core emits ``window_interval`` (blockchain.cpp:1885)
BEFORE ``window_tx_count`` (blockchain.cpp:1888). ouroboros matches Core, NOT
the order stated in the task prompt (which listed window_tx_count first).

Coverage (no real chain — a synthetic in-memory chain via stub node/db):
- default blockhash -> active tip; explicit valid blockhash.
- exact key ORDER + types via ``list(result.keys())``.
- nblocks=0 drops the three ``window_*`` extras.
- unknown blockhash -> -5 "Block not found".
- hash known but off the active chain -> -8 "Block is not in main chain".
- nblocks<0 and nblocks>=height -> -8
  "Invalid block count: should be between 0 and the block's height - 1".

This is the fast in-process complement to the differential shell harness at
``test-suite/chaintxstats/ouroboros_chaintxstats.sh``.
"""
from __future__ import annotations

import pytest

from ouroboros.rpc import (
    RPCServer,
    RpcError,
    RPC_INVALID_PARAMETER,
    RPC_INVALID_ADDRESS_OR_KEY,
    _CoreFloat,
)


class _StubBlock:
    """Minimal block exposing only the surface the handler touches.

    The handler reads ``.timestamp`` (RAW header nTime) and ``.transactions``
    (whose ``len`` feeds the cumulative tx-count prefix sum).
    """

    def __init__(self, timestamp: int, tx_count: int) -> None:
        self.timestamp = timestamp
        # len(transactions) is all the handler uses; the contents are opaque.
        self.transactions = [object()] * tx_count


class _StubDB:
    """A synthetic active chain of fixed-spacing, single-tx (empty) blocks.

    Block at height ``h`` has ``timestamp = base_time + h * spacing`` and a
    single (coinbase-only) transaction, so the cumulative tx count at height
    ``h`` is exactly ``h + 1`` — matching what Core reports for empty blocks.

    Internal (little-endian) block hashes are a deterministic 32-byte encoding
    of the height so that ``get_block_hash_by_height`` and the reverse lookup
    in ``_get_block_height`` stay consistent. Display hashes (what the RPC
    returns) are the byte-reverse of these.
    """

    def __init__(self, height: int, base_time: int = 1_700_000_000,
                 spacing: int = 600) -> None:
        self._height = height
        self._base_time = base_time
        self._spacing = spacing

    @staticmethod
    def _hash_for_height(h: int) -> bytes:
        # 32-byte little-endian internal hash; unique per height, never zero.
        return (h + 1).to_bytes(32, "little")

    def get_best_block(self) -> tuple[bytes, int]:
        return self._hash_for_height(self._height), self._height

    def get_block_hash_by_height(self, h: int) -> bytes | None:
        if 0 <= h <= self._height:
            return self._hash_for_height(h)
        return None

    def get_block_by_height(self, h: int) -> _StubBlock | None:
        if 0 <= h <= self._height:
            return _StubBlock(self._base_time + h * self._spacing, tx_count=1)
        return None


class _StubNode:
    """Node stub exposing ``db`` and ``get_median_time``.

    The handler computes ``window_interval`` from MEDIAN-TIME-PAST, not raw
    times. For a single-tx, fixed-spacing chain the MTP of height ``h`` is the
    median of the 11 raw times ending at ``h`` — but the handler only cares
    that ``MTP(final) - MTP(past)`` is a sane non-negative integer, so the stub
    returns the raw timestamp of height ``h`` (monotonic, deterministic).
    """

    def __init__(self, db: _StubDB) -> None:
        self.db = db

    def get_median_time(self, height: int | None = None) -> int:
        if height is None:
            height = self.db._height
        return self.db._base_time + height * self.db._spacing


def _make_rpc(height: int = 120) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = _StubNode(_StubDB(height))
    # Caches the handler / its helpers expect to exist on a constructed server.
    rpc._chain_tx_count = []
    rpc._side_branch_blocks = {}
    return rpc


def _display_hash(height: int) -> str:
    return _StubDB._hash_for_height(height)[::-1].hex()


EXPECTED_ORDER = [
    "time",
    "txcount",
    "window_final_block_hash",
    "window_final_block_height",
    "window_block_count",
    "window_interval",
    "window_tx_count",
    "txrate",
]


@pytest.mark.asyncio
async def test_default_blockhash_uses_tip() -> None:
    rpc = _make_rpc(height=120)
    res = await rpc.rpc_getchaintxstats()
    assert res["window_final_block_height"] == 120
    assert res["window_final_block_hash"] == _display_hash(120)
    # Cumulative tx count for a 120-height empty chain is height + 1.
    assert res["txcount"] == 121


@pytest.mark.asyncio
async def test_explicit_valid_blockhash() -> None:
    rpc = _make_rpc(height=120)
    target = _display_hash(50)
    res = await rpc.rpc_getchaintxstats(30, target)
    assert res["window_final_block_height"] == 50
    assert res["window_final_block_hash"] == target
    assert res["txcount"] == 51
    assert res["window_block_count"] == 30


@pytest.mark.asyncio
async def test_field_order_and_types_full_window() -> None:
    rpc = _make_rpc(height=120)
    res = await rpc.rpc_getchaintxstats(30)
    # All eight fields present, in Core's order (interval BEFORE tx_count).
    assert list(res.keys()) == EXPECTED_ORDER
    assert isinstance(res["time"], int)
    assert isinstance(res["txcount"], int)
    assert isinstance(res["window_final_block_hash"], str)
    assert len(res["window_final_block_hash"]) == 64
    assert isinstance(res["window_final_block_height"], int)
    assert isinstance(res["window_block_count"], int)
    assert isinstance(res["window_interval"], int)
    assert isinstance(res["window_tx_count"], int)
    # txrate is a Core double — wrapped in _CoreFloat for hex-free JSON output.
    assert isinstance(res["txrate"], _CoreFloat)


@pytest.mark.asyncio
async def test_window_values_match_synthetic_chain() -> None:
    rpc = _make_rpc(height=120)
    res = await rpc.rpc_getchaintxstats(30)
    assert res["window_block_count"] == 30
    # 30 blocks of one tx each.
    assert res["window_tx_count"] == 30
    # MTP spacing of 600s over a 30-block window.
    assert res["window_interval"] == 30 * 600
    # txrate = window_tx_count / window_interval (unwrap the _CoreFloat).
    assert res["txrate"].value == pytest.approx(30 / (30 * 600))
    # time is the RAW header nTime of the final (tip) block.
    assert res["time"] == 1_700_000_000 + 120 * 600


@pytest.mark.asyncio
async def test_interval_emitted_before_tx_count() -> None:
    rpc = _make_rpc(height=120)
    res = await rpc.rpc_getchaintxstats(30)
    keys = list(res.keys())
    assert keys.index("window_interval") < keys.index("window_tx_count")


@pytest.mark.asyncio
async def test_nblocks_zero_drops_window_extras() -> None:
    rpc = _make_rpc(height=120)
    res = await rpc.rpc_getchaintxstats(0)
    assert list(res.keys()) == [
        "time",
        "txcount",
        "window_final_block_hash",
        "window_final_block_height",
        "window_block_count",
    ]
    assert res["window_block_count"] == 0
    assert "window_interval" not in res
    assert "window_tx_count" not in res
    assert "txrate" not in res
    # Core still reports the final-block fields with nblocks=0.
    assert res["txcount"] == 121
    assert res["time"] == 1_700_000_000 + 120 * 600


@pytest.mark.asyncio
async def test_unknown_blockhash_raises_minus5() -> None:
    rpc = _make_rpc(height=120)
    bogus = "11" * 32  # well-formed 64-hex, not in the chain
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getchaintxstats(None, bogus)
    assert ei.value.code == RPC_INVALID_ADDRESS_OR_KEY
    assert ei.value.message == "Block not found"


@pytest.mark.asyncio
async def test_hash_not_in_main_chain_raises_minus8() -> None:
    # _get_block_height resolves side-branch hashes; such a hash is known but
    # not on the active chain -> -8 "Block is not in main chain".
    rpc = _make_rpc(height=120)
    side_internal = (9999).to_bytes(32, "little")
    # (prev_hash, height, block_bytes) — the handler only reads height.
    rpc._side_branch_blocks[side_internal] = (b"\x00" * 32, 60, b"")
    side_display = side_internal[::-1].hex()
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getchaintxstats(None, side_display)
    assert ei.value.code == RPC_INVALID_PARAMETER
    assert ei.value.message == "Block is not in main chain"


@pytest.mark.asyncio
async def test_negative_nblocks_raises_minus8() -> None:
    rpc = _make_rpc(height=120)
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getchaintxstats(-1)
    assert ei.value.code == RPC_INVALID_PARAMETER
    assert ei.value.message == (
        "Invalid block count: should be between 0 and the block's height - 1"
    )


@pytest.mark.asyncio
async def test_nblocks_at_or_above_height_raises_minus8() -> None:
    rpc = _make_rpc(height=120)
    # nblocks >= pindex_height (with nblocks > 0) is out of range.
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getchaintxstats(120)
    assert ei.value.code == RPC_INVALID_PARAMETER
    assert ei.value.message == (
        "Invalid block count: should be between 0 and the block's height - 1"
    )
