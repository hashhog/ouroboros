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


def _round_trip(server, hashes):
    """failed_reorg scenario C on the fixture tip: a7-a8 connected on 6,
    then the equal-work side 7'-8' off 6 is stored (submitted later)."""
    raw7, a7 = _block(hashes[TIP], TIP + 1, b"\x91\xb7")
    raw8, a8 = _block(a7, TIP + 2, b"\x92\xb7")
    assert asyncio.run(server.rpc_submitblock(raw7.hex())) is None
    assert asyncio.run(server.rpc_submitblock(raw8.hex())) is None
    side = _side_branch(server, hashes[TIP], TIP + 1, 2, 0xA0)
    return a7, a8, side


def test_reconsider_returns_to_equal_work_block_received_first(tmp_path):
    """Scenario C: invalidateblock 8 moves to 8' (more work than 7);
    reconsiderblock 8: 8 and 8' tie and 8 arrived first (lower
    nSequenceId), so Core goes back to 8 and 8' is a valid-fork tip."""
    bdb, server, hashes = _setup(tmp_path)
    a7, a8, side = _round_trip(server, hashes)
    assert bdb.get_best_block() == (a8, TIP + 2)
    asyncio.run(server.rpc_invalidateblock(_disp(a8)))
    assert bdb.get_best_block() == (side[-1], TIP + 2)
    asyncio.run(server.rpc_reconsiderblock(_disp(a8)))
    assert bdb.get_best_block() == (a8, TIP + 2)
    assert bytes(bdb.get_block_hash_by_height(TIP + 1)) == a7
    tips = _tips(server)
    assert tips[_disp(a8)]["status"] == "active"
    assert tips.get(_disp(side[-1])) == {
        "height": TIP + 2, "hash": _disp(side[-1]), "branchlen": 2,
        "status": "valid-fork"}
    assert len(tips) == 2


def test_reconsider_after_restart_keeps_the_tip_on_a_tie(tmp_path):
    """Scenario E: a restart resets the sequence ids (Core loads every block
    with the same id), so after it the tie no longer goes to 8: Core stays
    on 8'."""
    from tests.test_getchaintips_fleet_regtest import _restarted_server

    bdb, server, hashes = _setup(tmp_path)
    a7, a8, side = _round_trip(server, hashes)
    asyncio.run(server.rpc_invalidateblock(_disp(a8)))
    assert bdb.get_best_block() == (side[-1], TIP + 2)
    fresh = _restarted_server(server)
    asyncio.run(fresh.rpc_reconsiderblock(_disp(a8)))
    assert bdb.get_best_block() == (side[-1], TIP + 2)


def test_invalidate_prefers_equal_work_candidate_received_first(tmp_path):
    """After invalidateblock Core re-adds every block with at least the new
    tip's work and picks the lower nSequenceId on a tie.  a7-a8 arrive
    first, 7'-8' and 7''-8'' tie them, 9' on 8' reorgs onto the ' branch.
    invalidateblock 9': the tip is 8', and a8 (arrived before 8') beats it;
    8'' arrived after 8' and does not."""
    bdb, server, hashes = _setup(tmp_path)
    raw7, a7 = _block(hashes[TIP], TIP + 1, b"\x93\xb7")
    raw8, a8 = _block(a7, TIP + 2, b"\x94\xb7")
    for raw in (raw7, raw8):
        assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    side = _side_branch(server, hashes[TIP], TIP + 1, 2, 0xB0)
    _side_branch(server, hashes[TIP], TIP + 1, 2, 0xC0)
    raw9, s9 = _block(side[-1], TIP + 3, b"\xb9\xb7")
    assert asyncio.run(server.rpc_submitblock(raw9.hex())) is None
    assert bdb.get_best_block() == (s9, TIP + 3)
    asyncio.run(server.rpc_invalidateblock(_disp(s9)))
    assert bdb.get_best_block() == (a8, TIP + 2)
    assert bytes(bdb.get_block_hash_by_height(TIP + 1)) == a7


def test_invalidate_never_activates_a_branch_with_an_invalid_block(tmp_path):
    """Consensus guard: the heavier side branch 4'-5'-6' off 3 has an invalid
    FIRST block (4' pays 51 BTC).  invalidateblock 5 selects it, 4' fails
    ConnectBlock, and Core stays on 4 with 6' an invalid tip; nothing of the
    bad branch is connected or left as a candidate."""
    bdb, server, hashes = _setup(tmp_path)
    prev, side = hashes[TIP - 3], []
    for i in range(3):
        raw, h = _block(prev, TIP - 2 + i, bytes([0xD0 + i, 0xB7]),
                        value=51 * COIN if i == 0 else 50 * COIN)
        assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
        side.append(h)
        prev = h
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 1])))
    assert bdb.get_best_block() == (hashes[TIP - 2], TIP - 2)
    assert not any(h in server._side_branch_blocks for h in side)
    tips = _tips(server)
    assert tips[_disp(hashes[TIP - 2])]["status"] == "active"
    assert tips[_disp(side[-1])]["status"] == "invalid"


def test_reconsidered_block_off_the_active_chain_is_listed(tmp_path):
    """Scenario D: invalidateblock 8 with no side branch (tip 7), then a
    heavier 7'-8'-9' off 6 becomes the tip.  reconsiderblock 8: 9' has more
    work, Core stays on it, and 8 is back in m_block_index as a valid-fork
    tip (branchlen 2) -- its parent 7 has a child again and is not a tip."""
    bdb, server, hashes = _setup(tmp_path)
    raw7, a7 = _block(hashes[TIP], TIP + 1, b"\xe1\xb7")
    raw8, a8 = _block(a7, TIP + 2, b"\xe2\xb7")
    for raw in (raw7, raw8):
        assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    asyncio.run(server.rpc_invalidateblock(_disp(a8)))
    assert bdb.get_best_block() == (a7, TIP + 1)
    prev, side = hashes[TIP], []
    for i in range(3):
        raw, h = _block(prev, TIP + 1 + i, bytes([0xE8 + i, 0xB7]))
        asyncio.run(server.rpc_submitblock(raw.hex()))
        side.append(h)
        prev = h
    assert bdb.get_best_block() == (side[-1], TIP + 3)
    asyncio.run(server.rpc_reconsiderblock(_disp(a8)))
    assert bdb.get_best_block() == (side[-1], TIP + 3)
    tips = _tips(server)
    assert tips.get(_disp(a8)) == {
        "height": TIP + 2, "hash": _disp(a8), "branchlen": 2,
        "status": "valid-fork"}
    assert _disp(a7) not in tips
    assert len(tips) == 2
