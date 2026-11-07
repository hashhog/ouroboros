"""Side-branch blocks survive a restart, like Core's on-disk block index.

Core's AcceptBlock (validation.cpp ChainstateManager::AcceptBlock) writes a
side-branch block to disk (WriteBlock) and keeps its CBlockIndex entry with
BLOCK_HAVE_DATA; LoadBlockIndex reloads every entry at startup.  So after a
restart Core still lists such a block in getchaintips (a never-connected
sibling as ``valid-headers``, a reorged-away block as ``valid-fork``) and can
still reorg onto it when a child makes its branch the most-work chain.

ouroboros kept these blocks only in the in-memory ``_side_branch_blocks``
buffer, so a restart dropped them.  tools/core-regtest rows this pins:
``failed_reorg/e-restart*/tips`` and ``e-reconsider/tips`` (the reorged-away
c4s, ``valid-fork`` at 13) and ``warden_invalidated_submit/{restart,p2p-header}
/tips`` (the never-connected height-1 sibling 7c89..., ``valid-headers``).

The tests drive the production RPC handlers against the real Rust DB and
build the restarted server the way RPCServer.__init__ does.
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


def _server(bdb, data_dir: str):
    """An RPCServer over ``bdb`` whose side-branch buffer is opened the way
    ``RPCServer.__init__`` opens it (a plain dict before the fix)."""
    from ouroboros.block_sync import BlockSync
    from ouroboros.rpc import RPCServer

    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(os.path.join(data_dir, "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=data_dir)
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_max_entries = 1024
    opener = getattr(server, "_open_side_branch_buffer", None)
    server._side_branch_blocks = opener() if opener is not None else {}
    return server


def _setup(tmp_path):
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    Chain(bdb._db, tip=TIP)
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, _server(bdb, str(tmp_path)), hashes


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def _tips(server) -> dict[str, dict]:
    return {t["hash"]: t for t in asyncio.run(server.rpc_getchaintips())}


def _block(prev: bytes, height: int, tag: bytes, value: int = 50 * COIN):
    cb = coinbase_tx(height, value=value, tag=tag)
    return build_block(prev, BASE_TIME + height * 600 + 7, [cb])


def _submit(server, raw: bytes):
    return asyncio.run(server.rpc_submitblock(raw.hex()))


def test_stored_sibling_is_valid_headers_after_restart(tmp_path):
    """warden_invalidated_submit/restart/tips:7c89...: a stored,
    never-connected sibling of block 1 is still ``valid-headers`` after a
    restart."""
    bdb, server, hashes = _setup(tmp_path)
    raw, side = _block(hashes[0], 1, b"\x11\xc5")
    _submit(server, raw)
    assert _tips(server)[_disp(side)]["status"] == "valid-headers"
    tips = _tips(_server(bdb, str(tmp_path)))
    assert tips.get(_disp(side)) == {
        "height": 1, "hash": _disp(side), "branchlen": 1,
        "status": "valid-headers"}
    assert tips[_disp(hashes[TIP])]["status"] == "active"
    assert len(tips) == 2


def test_reorged_away_block_is_valid_fork_after_restart(tmp_path):
    """failed_reorg/e-restart/tips:795f...: a block that was the tip and lost
    a reorg is still ``valid-fork`` after a restart."""
    bdb, server, hashes = _setup(tmp_path)
    raw1, s1 = _block(hashes[TIP - 1], TIP, b"\x21\xc5")
    raw2, s2 = _block(s1, TIP + 1, b"\x22\xc5")
    _submit(server, raw1)
    _submit(server, raw2)
    assert bdb.get_best_block() == (s2, TIP + 1)
    tips = _tips(_server(bdb, str(tmp_path)))
    assert tips.get(_disp(hashes[TIP])) == {
        "height": TIP, "hash": _disp(hashes[TIP]), "branchlen": 1,
        "status": "valid-fork"}
    assert tips[_disp(s2)]["status"] == "active"
    assert len(tips) == 2


def test_reloaded_sibling_branch_can_still_win(tmp_path):
    """Valid stays valid: Core can reorg onto a side-branch block stored
    before a restart once a child makes its branch the most-work chain.  A
    child of the reloaded sibling is accepted as a side block, and the
    grandchild that out-works the active tip drives the reorg."""
    bdb, server, hashes = _setup(tmp_path)
    raw_s, s = _block(hashes[TIP - 1], TIP, b"\x31\xc5")
    assert _submit(server, raw_s) == "inconclusive"
    fresh = _server(bdb, str(tmp_path))
    raw_c, c = _block(s, TIP + 1, b"\x32\xc5")
    assert _submit(fresh, raw_c) is None
    assert bdb.get_best_block() == (c, TIP + 1)
    tips = _tips(fresh)
    assert tips[_disp(c)]["status"] == "active"
    assert tips[_disp(hashes[TIP])]["status"] == "valid-fork"


def test_reloaded_sibling_does_not_make_an_invalid_child_valid(tmp_path):
    """Invalid stays invalid: a child of a reloaded side block that overpays
    its coinbase is still rejected by ConnectBlock, and the tip is kept."""
    bdb, server, hashes = _setup(tmp_path)
    raw_s, s = _block(hashes[TIP - 1], TIP, b"\x41\xc5")
    _submit(server, raw_s)
    fresh = _server(bdb, str(tmp_path))
    raw_bad, bad = _block(s, TIP + 1, b"\x42\xc5", value=51 * COIN)
    assert _submit(fresh, raw_bad) == "bad-cb-amount"
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    tips = _tips(fresh)
    assert tips[_disp(bad)]["status"] == "invalid"
    assert tips[_disp(hashes[TIP])]["status"] == "active"


def test_buffer_file_that_does_not_match_its_key_is_not_reloaded(tmp_path):
    """Negative control for the reload: a stored file renamed to another
    block's key, or truncated, is skipped, so a damaged datadir cannot plant
    a block under a hash it does not have."""
    bdb, server, hashes = _setup(tmp_path)
    raw, side = _block(hashes[0], 1, b"\x51\xc5")
    _submit(server, raw)
    store = os.path.join(str(tmp_path), "side_branch_blocks")
    good = os.path.join(store, side.hex() + ".blk")
    assert os.path.exists(good)
    os.rename(good, os.path.join(store, (b"\x07" * 32).hex() + ".blk"))
    with open(os.path.join(store, (b"\x08" * 32).hex() + ".blk"), "wb") as f:
        f.write(b"OBSB1\x00" + b"\x00" * 10)
    fresh = _server(bdb, str(tmp_path))
    assert len(fresh._side_branch_blocks) == 0
    assert _disp(side) not in _tips(fresh)


def test_connected_side_block_leaves_the_store(tmp_path):
    """A side block the reorg connects is popped from the buffer and its
    file removed, so the store never re-lists an active block."""
    bdb, server, hashes = _setup(tmp_path)
    raw1, s1 = _block(hashes[TIP - 1], TIP, b"\x61\xc5")
    raw2, s2 = _block(s1, TIP + 1, b"\x62\xc5")
    _submit(server, raw1)
    store = os.path.join(str(tmp_path), "side_branch_blocks")
    assert os.path.exists(os.path.join(store, s1.hex() + ".blk"))
    _submit(server, raw2)
    assert bdb.get_best_block() == (s2, TIP + 1)
    assert not os.path.exists(os.path.join(store, s1.hex() + ".blk"))
    assert s1 not in _server(bdb, str(tmp_path))._side_branch_blocks
