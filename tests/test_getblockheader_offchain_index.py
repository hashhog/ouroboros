"""getblockheader answers for a block off the active chain, like Core
(fleet item refill-20261106-ouroboros-consensus).

Core rpc/blockchain.cpp ``getblockheader`` looks the hash up in the block
index (``BlockManager::LookupBlockIndex``), which holds every block the node
has accepted, active or not, and reports it with ``confirmations: -1``,
its own ``nChainWork`` and no ``nextblockhash`` when it is off the active
chain.  Only a hash the index has never seen is -5 "Block not found".

Before the fix ouroboros resolved the height from the active chain and the
in-memory submitblock side-branch buffer only.  A block that
``invalidateblock`` disconnected is in neither, and after a restart the
buffer is empty, so getblockheader answered -5 for both
(tools/core-regtest rows ``failed_reorg/{c,d,e}-invalidate/displaced-header``,
``failed_reorg/e-restart-invalidated/displaced-header`` and
``failed_reorg/e-restart/displaced-header``).  The block's height is in the
hash-keyed block index (BLOCK_INDEX_BY_HASH_CF), which survives both.

These tests drive the production RPC handlers against the real Rust DB, the
way tools/core-regtest does.
"""

from __future__ import annotations

import asyncio

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from ouroboros.rpc import RpcError  # noqa: E402
from tests._f0_chain import BASE_TIME, COIN, build_block, coinbase_tx  # noqa: E402
from tests.test_invalidateblock_best_chain import (  # noqa: E402
    TIP,
    _block,
    _disp,
    _setup,
    _side_branch,
)


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _server(tmp_path):
    bdb, server, hashes = _setup(tmp_path)
    node = server.node
    # The fixture's node is a namespace; give getblockheader the node
    # helpers it calls.  get_chainwork_at_height keeps BitcoinNode's
    # contract: the ACTIVE chain's work at that height (fixture model
    # (h + 1) * 2), and zero above the tip, where no active block exists
    # (the live node answered chainwork 0 for the invalidated block above the
    # tip in core-regtest failed_reorg/d-invalidate before this fix).
    def _active_work(h: int) -> str:
        tip = bdb.get_best_block()[1]
        return f"{node._calculate_chainwork_at_height(h) if h <= tip else 0:064x}"

    node.get_chainwork_at_height = _active_work
    node.get_median_time = lambda h: 0
    node.get_difficulty = lambda bits: 1.0
    return bdb, server, hashes


def _header(server, h: bytes):
    return asyncio.run(server.rpc_getblockheader(_disp(h)))


def _restart_buffer(server):
    """What a restart loses: the side-branch buffer lives in memory only."""
    server._side_branch_blocks.clear()


def test_invalidated_block_header_is_served_off_chain(tmp_path):
    """failed_reorg/{c,d,e}-invalidate/displaced-header: invalidateblock
    moves the tip to the equal-work side branch; the invalidated block is
    still in Core's block index, confirmations -1."""
    bdb, server, hashes = _server(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x40)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (side[-1], TIP)
    hdr = _header(server, hashes[TIP])
    assert hdr["hash"] == _disp(hashes[TIP])
    assert hdr["height"] == TIP
    assert hdr["confirmations"] == -1
    assert hdr["previousblockhash"] == _disp(hashes[TIP - 1])
    assert "nextblockhash" not in hdr
    # Its own index entry's work (pindex->nChainWork), never zero.
    own = bytes(bdb._db.get_block_metadata_by_hash(hashes[TIP])[1]).hex()
    assert int(own, 16) > 0
    assert hdr["chainwork"] == own


def test_invalidated_parent_without_active_slot_is_served(tmp_path):
    """failed_reorg/d-invalidate/displaced-header: no side branch, so the
    tip falls back to the parent and the invalidated block's height is
    above the new tip."""
    bdb, server, hashes = _server(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (hashes[TIP - 1], TIP - 1)
    hdr = _header(server, hashes[TIP])
    assert (hdr["height"], hdr["confirmations"]) == (TIP, -1)
    assert "nextblockhash" not in hdr
    # Its own work, not the active chain's at that height (there is no
    # active block at TIP any more, so that would be zero).
    own = bytes(bdb._db.get_block_metadata_by_hash(hashes[TIP])[1]).hex()
    assert int(own, 16) == (TIP + 1) * 2
    assert server.node.get_chainwork_at_height(TIP) == "0" * 64
    assert hdr["chainwork"] == own


def test_invalidated_block_header_survives_restart(tmp_path):
    """failed_reorg/e-restart-invalidated/displaced-header."""
    bdb, server, hashes = _server(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x50)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    _restart_buffer(server)
    hdr = _header(server, hashes[TIP])
    assert (hdr["height"], hdr["confirmations"]) == (TIP, -1)
    assert bdb.get_best_block() == (side[-1], TIP)


def test_displaced_side_block_header_survives_restart(tmp_path):
    """failed_reorg/e-restart/displaced-header: a block that was connected
    and then displaced by a reorg is still indexed after a restart."""
    bdb, server, hashes = _server(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x60)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    asyncio.run(server.rpc_reconsiderblock(_disp(hashes[TIP])))
    best = bdb.get_best_block()[0]
    displaced = side[-1] if best == hashes[TIP] else hashes[TIP]
    _restart_buffer(server)
    hdr = _header(server, displaced)
    assert (hdr["height"], hdr["confirmations"]) == (TIP, -1)
    assert "nextblockhash" not in hdr


def test_active_block_header_unchanged(tmp_path):
    """Control: an active-chain block keeps its confirmations and next."""
    _bdb, server, hashes = _server(tmp_path)
    hdr = _header(server, hashes[TIP - 2])
    assert (hdr["height"], hdr["confirmations"]) == (TIP - 2, 3)
    assert hdr["nextblockhash"] == _disp(hashes[TIP - 1])
    # The active chain's work at that height (fixture model (h + 1) * 2).
    assert hdr["chainwork"] == f"{(TIP - 1) * 2:064x}"


def test_unknown_hash_is_still_block_not_found(tmp_path):
    """Control: a hash the index never saw is -5, as in Core."""
    _bdb, server, _hashes = _server(tmp_path)
    _raw, never = _block(b"\x11" * 32, TIP + 5, b"\x99\xb7")
    with pytest.raises(RpcError) as exc:
        _header(server, never)
    assert exc.value.code == -5
    assert exc.value.message == "Block not found"


def _median(times: list[int]) -> int:
    """Core CBlockIndex::GetMedianTimePast: sort, take [(n) / 2]."""
    times = sorted(times)
    return times[len(times) // 2]


def test_displaced_block_mediantime_is_its_own_ancestry(tmp_path):
    """mediantime of an off-chain block is the median over ITS OWN last 11
    blocks (Core pindex->GetMedianTimePast()), not the active chain's
    median at the same height.  Active 0..6, then 7..12 with timestamps far
    ahead (connected), then a heavier side branch 7'..13' off 6 with normal
    timestamps: 7..12 are displaced.  Block 12's own window (2..12) holds six
    far-ahead times, so its median is block 7's time; the active window at
    height 12 (2..6, 7'..12') holds none.  The node's real height-based
    get_median_time is bound here, not a stub."""
    import types

    from ouroboros.node import BitcoinNode

    bdb, server, hashes = _server(tmp_path)
    server.node.get_median_time = types.MethodType(BitcoinNode.get_median_time, server.node)

    far = BASE_TIME + 1_000_000
    prev, high = hashes[TIP], []
    for i, height in enumerate(range(TIP + 1, TIP + 7)):
        raw, h = build_block(prev, far + i * 600, [coinbase_tx(height, value=50 * COIN, tag=bytes([0x30 + i, 0xB8]))])
        assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
        prev = h
        high.append(h)
    assert bdb.get_best_block() == (high[-1], TIP + 6)

    prev = hashes[TIP]
    for i, height in enumerate(range(TIP + 1, TIP + 8)):
        raw, h = _block(prev, height, bytes([0x50 + i, 0xB8]))
        asyncio.run(server.rpc_submitblock(raw.hex()))
        prev = h
    assert bdb.get_best_block() == (prev, TIP + 7)

    displaced = high[-1]  # block 12
    hdr = _header(server, displaced)
    assert (hdr["height"], hdr["confirmations"]) == (TIP + 6, -1)

    # Independent window: walk block 12's own parents through raw headers.
    times, cur = [], displaced
    for _ in range(11):
        raw = bdb.get_block_bytes(cur)
        times.append(int.from_bytes(raw[68:72], "little"))
        cur = bytes(raw[4:36])
    own = _median(times)
    assert own == far  # block 7's time: six of the eleven are far ahead
    active_same_height = server.node.get_median_time(TIP + 6)
    assert active_same_height != own  # the scenario discriminates
    assert hdr["mediantime"] == own
