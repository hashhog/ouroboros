"""getchaintips must list every block-index leaf, like Core (fleet item
done-fleet-regtest-getchaintips, 2026-10-25).

Core rpc/blockchain.cpp getchaintips: a tip is every m_block_index entry off
the active chain that is nobody's pprev, plus the active tip; branchlen is
``height - FindFork(active).height``; status is active / invalid
(BLOCK_FAILED_VALID) / headers-only (!HaveNumChainTxs) / valid-fork
(IsValid(BLOCK_VALID_SCRIPTS): connected once) / valid-headers.

Before the fix the handler looked for ``db.get_all_block_hashes`` /
``db.block_index``, which the database never had, so it only ever reported
the active tip: an invalidated block, a stored lesser-work sibling, a
reorged-away block, a fork header and a block that failed ConnectBlock were
all missing.  These tests drive the production RPC handlers against the real
Rust DB, the way tools/core-regtest does.
"""

from __future__ import annotations

import asyncio
import os
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
    chain = Chain(bdb._db, tip=TIP)
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
    return bdb, chain, bs, server, hashes


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def _tips(server) -> dict[str, dict]:
    return {t["hash"]: t for t in asyncio.run(server.rpc_getchaintips())}


def _block(prev: bytes, height: int, tag: bytes, value: int = 50 * COIN):
    cb = coinbase_tx(height, value=value, tag=tag)
    return build_block(prev, BASE_TIME + height * 600 + 7, [cb])


def test_invalidated_tip_is_listed_invalid(tmp_path):
    """chain/invalidate/tips: Core lists the invalidated block as an
    ``invalid`` tip with branchlen 1 next to the new active tip."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    tips = _tips(server)
    assert tips[_disp(hashes[TIP - 1])] == {
        "height": TIP - 1, "hash": _disp(hashes[TIP - 1]),
        "branchlen": 0, "status": "active"}
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]),
        "branchlen": 1, "status": "invalid"}
    assert len(tips) == 2


def test_invalidated_branch_reports_its_leaf(tmp_path):
    """Invalidating a deeper block: the leaf of the failed branch is the tip
    (the invalidated root has a child), branchlen counts to the fork."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 2])))
    tips = _tips(server)
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]),
        "branchlen": 3, "status": "invalid"}
    assert _disp(hashes[TIP - 2]) not in tips
    assert len(tips) == 2


def test_reconsider_removes_the_invalid_tip(tmp_path):
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    asyncio.run(server.rpc_reconsiderblock(_disp(hashes[TIP])))
    tips = _tips(server)
    assert list(tips) == [_disp(hashes[TIP])]
    assert tips[_disp(hashes[TIP])]["status"] == "active"


def test_lesser_work_sibling_is_valid_headers(tmp_path):
    """chain/tips/final 7c89...: a stored, never-connected sibling of block 1
    is ``valid-headers`` with branchlen 1."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw, side = _block(hashes[0], 1, b"\x11\xc5")
    asyncio.run(server.rpc_submitblock(raw.hex()))
    tips = _tips(server)
    assert tips.get(_disp(side)) == {
        "height": 1, "hash": _disp(side), "branchlen": 1,
        "status": "valid-headers"}
    assert tips[_disp(hashes[TIP])]["status"] == "active"


def test_failed_connect_on_tip_is_listed_invalid(tmp_path):
    """chain/tips/final 341e...: a tip child that fails ConnectBlock
    (bad-cb-amount) stays in Core's index as an ``invalid`` tip."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw, bad = _block(hashes[TIP], TIP + 1, b"\x62\xc5", value=51 * COIN)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-cb-amount"
    tips = _tips(server)
    assert tips.get(_disp(bad)) == {
        "height": TIP + 1, "hash": _disp(bad), "branchlen": 1,
        "status": "invalid"}


def test_failed_connect_record_changes_no_decision(tmp_path):
    """The getchaintips failed record is reporting-only: the block is not
    BLOCK_FAILED in block_sync, a resubmission is validated again exactly as
    before, and a valid sibling still connects."""
    _bdb, _chain, bs, server, hashes = _setup(tmp_path)
    raw, bad = _block(hashes[TIP], TIP + 1, b"\x62\xc5", value=51 * COIN)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-cb-amount"
    assert not bs.is_block_failed(bad)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-cb-amount"
    good, good_hash = _block(hashes[TIP], TIP + 1, b"\x63\xc5")
    assert asyncio.run(server.rpc_submitblock(good.hex())) is None
    assert server.node.db.get_best_block() == (good_hash, TIP + 1)
    tips = _tips(server)
    assert tips[_disp(good_hash)]["status"] == "active"
    assert tips[_disp(bad)] == {"height": TIP + 1, "hash": _disp(bad),
                                "branchlen": 1, "status": "invalid"}


def test_reorged_away_block_is_valid_fork(tmp_path):
    """A block that was the tip and lost a reorg was connected once:
    ``valid-fork``."""
    bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw1, s1 = _block(hashes[TIP - 1], TIP, b"\x21\xc5")
    raw2, s2 = _block(s1, TIP + 1, b"\x22\xc5")
    asyncio.run(server.rpc_submitblock(raw1.hex()))
    asyncio.run(server.rpc_submitblock(raw2.hex()))
    assert bdb.get_best_block() == (s2, TIP + 1)
    tips = _tips(server)
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]), "branchlen": 1,
        "status": "valid-fork"}
    assert tips[_disp(s2)]["status"] == "active"
    assert _disp(s1) not in tips


def test_failed_side_branch_reorg_lists_the_failed_leaf(tmp_path):
    """seed_invalidated_submit/after-failed-connect: a heavier side branch
    whose tip fails ConnectBlock.  Core lists the failed tip as ``invalid``
    (branchlen 2); its valid parent has a child, so it is not a tip."""
    bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw1, sib = _block(hashes[TIP - 1], TIP, b"\x61\xc5")
    raw2, bad = _block(sib, TIP + 1, b"\x62\xc5", value=51 * COIN)
    asyncio.run(server.rpc_submitblock(raw1.hex()))
    asyncio.run(server.rpc_submitblock(raw2.hex()))
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    tips = _tips(server)
    assert tips.get(_disp(bad)) == {
        "height": TIP + 1, "hash": _disp(bad), "branchlen": 2,
        "status": "invalid"}
    assert _disp(sib) not in tips
    assert len(tips) == 2


def test_fork_header_is_headers_only(tmp_path):
    """A header with no block data off the active chain: ``headers-only``."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw, fh = _block(hashes[TIP - 2], TIP - 1, b"\x71\xc5")
    asyncio.run(server.rpc_submitheader(raw[:80].hex()))
    tips = _tips(server)
    assert tips.get(_disp(fh)) == {
        "height": TIP - 1, "hash": _disp(fh), "branchlen": 1,
        "status": "headers-only"}


def test_header_past_the_tip_is_headers_only(tmp_path):
    """A header extending the active tip is a tip of its own (Core: tip
    stays active, the header is headers-only with branchlen 1)."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw, nh = _block(hashes[TIP], TIP + 1, b"\x72\xc5")
    asyncio.run(server.rpc_submitheader(raw[:80].hex()))
    tips = _tips(server)
    assert tips[_disp(hashes[TIP])]["status"] == "active"
    assert tips.get(_disp(nh)) == {
        "height": TIP + 1, "hash": _disp(nh), "branchlen": 1,
        "status": "headers-only"}


def _restarted_server(server):
    """Fresh RPCServer + BlockSync over the same DB/datadir: every in-memory
    set is gone, only what was persisted (invalidated roots, the record) is
    reloaded — what a process restart leaves."""
    from ouroboros.block_sync import BlockSync
    from ouroboros.rpc import RPCServer

    old = server.node
    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=old.db, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(os.path.join(old.data_dir, "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=old.db, block_sync=bs, data_dir=old.data_dir)
    fresh = RPCServer.__new__(RPCServer)
    fresh.node = node
    fresh.block_submission_paused = False
    fresh._side_branch_blocks = {}
    return fresh


def test_failed_tips_survive_a_restart(tmp_path):
    """Core keeps BLOCK_FAILED_VALID entries in the on-disk block index, so
    after a restart the invalidated branch's leaf and a block that failed
    ConnectBlock are still listed ``invalid`` — not the bare invalidated root
    (which has a child in Core's index)."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 1])))
    raw, bad = _block(hashes[TIP - 2], TIP - 1, b"\x62\xc5", value=51 * COIN)
    assert asyncio.run(server.rpc_submitblock(raw.hex())) == "bad-cb-amount"
    fresh = _restarted_server(server)
    tips = _tips(fresh)
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]), "branchlen": 2,
        "status": "invalid"}
    assert _disp(hashes[TIP - 1]) not in tips
    assert tips.get(_disp(bad)) == {
        "height": TIP - 1, "hash": _disp(bad), "branchlen": 1,
        "status": "invalid"}
    assert tips[_disp(hashes[TIP - 2])]["status"] == "active"


def test_reconsider_clears_the_persisted_record(tmp_path):
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 1])))
    asyncio.run(server.rpc_reconsiderblock(_disp(hashes[TIP - 1])))
    tips = _tips(_restarted_server(server))
    assert list(tips) == [_disp(hashes[TIP])]


def test_failed_side_branch_leaf_branchlen_after_restart(tmp_path):
    """failed_reorg A after the restart: the side-branch buffer is gone, but
    the failed leaf's parent (connected during the failed reorg, then rolled
    back) is still in the Rust hash index, as it is in Core's.  branchlen is
    still measured to the real fork point (2), not to the parent (1)."""
    bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw1, sib = _block(hashes[TIP - 1], TIP, b"\x61\xc5")
    raw2, bad = _block(sib, TIP + 1, b"\x62\xc5", value=51 * COIN)
    asyncio.run(server.rpc_submitblock(raw1.hex()))
    asyncio.run(server.rpc_submitblock(raw2.hex()))
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    tips = _tips(_restarted_server(server))
    assert tips.get(_disp(bad)) == {
        "height": TIP + 1, "hash": _disp(bad), "branchlen": 2,
        "status": "invalid"}
    assert len(tips) == 2
