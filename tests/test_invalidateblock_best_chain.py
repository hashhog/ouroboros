"""invalidateblock activates the best remaining valid chain, like Core
(fleet item fix-ouroboros-invalidateblock-reorg, 2026-10-28).

Core validation.cpp ``Chainstate::InvalidateBlock`` disconnects the block
and everything above it, re-adds every block with at least the new tip's
work to ``setBlockIndexCandidates``, and the RPC then calls
``ActivateBestChain``: ``FindMostWorkChain`` picks the most-work candidate,
``ActivateBestChainStep`` connects it, a block that fails ``ConnectTip`` is
``InvalidBlockFound`` (BLOCK_FAILED_VALID, descendants FAILED_CHILD) and the
loop selects again -- so a valid prefix with more work than the parent of
the invalidated block becomes the tip.

Before the fix ouroboros stopped at the parent of the invalidated block and
never looked at the stored side branches (tools/core-regtest failed_reorg
scenario B: Core tip 4' at height 9, ouroboros 3a at height 8).  These tests
drive the production RPC handlers against the real Rust DB, the way
tools/core-regtest does.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import BASE_TIME, COIN, Chain, build_block, coinbase_tx  # noqa: E402

TIP = 6


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _setup(tmp_path):
    from ouroboros.block_sync import BlockSync
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    Chain(bdb._db, tip=TIP)
    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(str(tmp_path / "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=str(tmp_path))
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    server._side_branch_max_entries = 1024
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, server, hashes


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def _tips(server) -> dict[str, dict]:
    return {t["hash"]: t for t in asyncio.run(server.rpc_getchaintips())}


def _block(prev: bytes, height: int, tag: bytes, value: int = 50 * COIN):
    cb = coinbase_tx(height, value=value, tag=tag)
    return build_block(prev, BASE_TIME + height * 600 + 11, [cb])


def _side_branch(server, prev: bytes, first_height: int, n: int, tag: int,
                 bad_last: bool = False) -> list[bytes]:
    """Submit ``n`` side-branch blocks on ``prev``; every one stays off the
    tip (not more work than the active chain).  Returns their hashes."""
    out = []
    for i in range(n):
        bad = bad_last and i == n - 1
        raw, h = _block(prev, first_height + i, bytes([tag + i, 0xB7]),
                        value=51 * COIN if bad else 50 * COIN)
        assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
        out.append(h)
        prev = h
    return out


def test_invalidate_switches_to_heavier_side_branch(tmp_path):
    """Two forks off block 4: the active 5-6 and a stored side 5'-6' (equal
    work, so it stayed off the tip).  Once 6 is invalidated 6' has more work
    than 5, so Core connects 5'-6'."""
    bdb, server, hashes = _setup(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x40)
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    # 5' 6' (height 6) beats 5 (height 5).
    assert bdb.get_best_block() == (side[-1], TIP)
    tips = _tips(server)
    assert tips[_disp(side[-1])] == {
        "height": TIP, "hash": _disp(side[-1]), "branchlen": 0,
        "status": "active"}
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]), "branchlen": 2,
        "status": "invalid"}
    assert len(tips) == 2


def test_invalidate_keeps_valid_prefix_of_failed_branch(tmp_path):
    """failed_reorg scenario B: active 4-5-6, stored side 4'-5'-6'' off
    block 3 where 6'' fails ConnectBlock (bad-cb-amount).  invalidateblock 5:
    6'' is the most-work candidate, it fails, the valid prefix 4'-5' still
    has more work than 4, so Core ends on 5' with 6'' invalid (branchlen 1)
    and the invalidated branch's leaf 6 invalid with branchlen 3 (fork at 3).
    """
    bdb, server, hashes = _setup(tmp_path)
    side = _side_branch(server, hashes[TIP - 3], TIP - 2, 3, 0x50, bad_last=True)
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 1])))
    assert bdb.get_best_block() == (side[1], TIP - 1)
    assert bytes(bdb.get_block_hash_by_height(TIP - 2)) == side[0]
    tips = _tips(server)
    assert tips[_disp(side[1])] == {
        "height": TIP - 1, "hash": _disp(side[1]), "branchlen": 0,
        "status": "active"}
    assert tips.get(_disp(side[2])) == {
        "height": TIP, "hash": _disp(side[2]), "branchlen": 1,
        "status": "invalid"}
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]), "branchlen": 3,
        "status": "invalid"}
    assert len(tips) == 3


def test_invalidate_stays_on_parent_when_side_branch_is_not_heavier(tmp_path):
    """Equal work is not enough: a side 5' off block 4 ties the parent 5 of
    the invalidated 6, and 5 was received first, so Core stays on 5."""
    bdb, server, hashes = _setup(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 1, 0x60)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (hashes[TIP - 1], TIP - 1)
    tips = _tips(server)
    assert tips[_disp(side[0])]["status"] == "valid-headers"
    assert tips[_disp(hashes[TIP - 1])]["status"] == "active"


def test_invalidate_never_activates_a_descendant_of_the_invalidated_block(tmp_path):
    """A heavier side branch built ON the invalidated block is FAILED_CHILD
    in Core: it is never a candidate, the tip is the invalidated block's
    parent."""
    bdb, server, hashes = _setup(tmp_path)
    # 6'-7' off 5 is stored as a side branch only if it is not heavier;
    # build it as 6' off 5 (ties 6), then invalidate 5.
    side = _side_branch(server, hashes[TIP - 1], TIP, 1, 0x70)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 1])))
    assert bdb.get_best_block() == (hashes[TIP - 2], TIP - 2)
    assert side[0] not in server._side_branch_blocks
    tips = _tips(server)
    assert tips[_disp(side[0])]["status"] == "invalid"


def test_invalidate_off_chain_block_does_not_move_the_tip(tmp_path):
    """invalidateblock on a side-branch block: nothing is disconnected and
    the tip stays put (the branch was never more work)."""
    bdb, server, hashes = _setup(tmp_path)
    side = _side_branch(server, hashes[TIP - 2], TIP - 1, 2, 0x80)
    asyncio.run(server.rpc_invalidateblock(_disp(side[0])))
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    assert side[1] not in server._side_branch_blocks
