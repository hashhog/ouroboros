"""getblockchaininfo bits / target / difficulty / time describe the ACTIVE TIP.

Core rpc/blockchain.cpp getblockchaininfo reads them off the tip's
CBlockIndex (``tip.nBits``, ``GetTarget(tip, pow_limit)``,
``GetDifficulty(tip)``, ``tip.GetBlockTime()``), so they are right after a
restart and after a disconnect.

ouroboros read them from ``BlockchainDatabase._tip_bits`` /
``_tip_timestamp``, plain attributes written only by
``connect_block_from_bytes``.  After a restart, before the next block
connected, they were the defaults ``0x1d00ffff`` / ``0`` (Core regtest rows
``warden_invalidated_submit/restart/info:{bits,target,difficulty,time}`` and
the same four under ``p2p-header/info``: Core ``207fffff`` / ``1700000208``,
ouroboros ``1d00ffff`` / ``0``).  After invalidateblock they still described
the block that was taken off.

These tests drive the real Rust DB the way tools/core-regtest does.
"""

from __future__ import annotations

import asyncio
import gc
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import BASE_TIME, REGTEST_BITS, Chain, build_block, coinbase_tx  # noqa: E402

TIP = 5
REGTEST_TARGET = "7fffff0000000000000000000000000000000000000000000000000000000000"


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _write_chain(path: str) -> bytes:
    """Chain 0..TIP through the Rust handle of a database that is then dropped."""
    from ouroboros.database import BlockchainDatabase

    return Chain(BlockchainDatabase(path)._db, tip=TIP).tip_hash


def _server(bdb, tmp_path):
    from ouroboros.block_sync import BlockSync
    from ouroboros.rpc import RPCServer

    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(str(tmp_path / "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=str(tmp_path),
                           config={"network": "regtest"})
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    server._side_branch_max_entries = 1024
    server._deployment_cache = {}
    server._deployment_cache_height = None
    server._deployment_cache_network = None
    return server


def _build(tmp_path):
    """Chain 0..TIP written, then the datadir reopened: the new
    ``BlockchainDatabase`` has connected nothing, as after a restart."""
    from ouroboros.database import BlockchainDatabase

    path = str(tmp_path / "db")
    tip_hash = _write_chain(path)
    gc.collect()  # release the first handle's RocksDB lock
    return BlockchainDatabase(path), tip_hash


def test_tip_fields_after_restart_are_the_tip_header(tmp_path):
    bdb, tip_hash = _build(tmp_path)
    assert bdb.get_best_block() == (tip_hash, TIP)
    assert bdb._tip_bits == REGTEST_BITS
    assert bdb._tip_timestamp == BASE_TIME + TIP * 600


def test_getblockchaininfo_after_restart_reports_tip_bits_and_time(tmp_path):
    bdb, _tip_hash = _build(tmp_path)
    server = _server(bdb, tmp_path)
    info = asyncio.run(server.rpc_getblockchaininfo())
    assert info["blocks"] == TIP
    assert info["bits"] == f"{REGTEST_BITS:08x}"
    assert info["target"] == REGTEST_TARGET
    assert info["time"] == BASE_TIME + TIP * 600
    # difficulty is node.get_difficulty(bits) (not on this fixture's node),
    # so it follows bits.


def test_tip_time_follows_invalidateblock(tmp_path):
    """Connect one block through the wrapper (so the last-connected cache
    holds it), invalidate it: the tip is its parent and so is the time."""
    bdb, tip_hash = _build(tmp_path)
    server = _server(bdb, tmp_path)
    height = TIP + 1
    raw, new_hash = build_block(
        tip_hash, BASE_TIME + height * 600 + 7,
        [coinbase_tx(height, tag=b"\x02T" + height.to_bytes(2, "little"))])
    bdb.connect_block_from_bytes(raw, height, "regtest")
    assert bdb.get_best_block() == (new_hash, height)
    assert bdb._tip_timestamp == BASE_TIME + height * 600 + 7
    asyncio.run(server.rpc_invalidateblock(new_hash[::-1].hex()))
    assert bdb.get_best_block() == (tip_hash, TIP)
    assert bdb._tip_timestamp == BASE_TIME + TIP * 600
    info = asyncio.run(server.rpc_getblockchaininfo())
    assert info["time"] == BASE_TIME + TIP * 600


def test_assigned_value_is_the_fallback_when_no_header_is_readable():
    """A database whose tip header cannot be read (no Rust handle: the
    ``__new__`` fixtures other tests use) keeps the assigned values."""
    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase.__new__(BlockchainDatabase)
    db._cached_tip = None
    db._tip_bits = 0x1d00ffff
    db._tip_timestamp = 0
    assert (db._tip_bits, db._tip_timestamp) == (0x1d00ffff, 0)
    db._tip_bits = 0x207fffff
    db._tip_timestamp = 1234
    assert (db._tip_bits, db._tip_timestamp) == (0x207fffff, 1234)
