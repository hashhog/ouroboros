"""getblockchaininfo.initialblockdownload follows Core's tip-age rule on regtest.

Core ChainstateManager::IsInitialBlockDownload (validation.cpp) stays true
while the tip is older than max_tip_age (24h) and latches false once a
recent tip is seen. Regtest only drops the minimum-chainwork test; it does
not drop the tip-age test. tools/core-regtest builds blocks stamped Nov 2023,
so Core reports true on every ``info`` row (21 baseline rows), while
ouroboros scoped the tip-age heuristic off for regtest and said false.
"""

from __future__ import annotations

import asyncio
import time
import types

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import BASE_TIME, build_block, coinbase_tx  # noqa: E402

from tests.test_tip_header_fields_after_restart import TIP, _build, _server  # noqa: E402,F401


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _with_core_ibd(server):
    from ouroboros.node import BitcoinNode

    node = server.node
    node.synced = False
    node.MAX_TIP_AGE = BitcoinNode.MAX_TIP_AGE
    node.is_initial_block_download = types.MethodType(
        BitcoinNode.is_initial_block_download, node)
    node._tip_time = types.MethodType(BitcoinNode._tip_time, node)
    return server


def test_regtest_stale_tip_is_initial_block_download(tmp_path):
    bdb, _ = _build(tmp_path)  # tip stamped 2023: older than 24h
    server = _with_core_ibd(_server(bdb, tmp_path))
    info = asyncio.run(server.rpc_getblockchaininfo())
    assert info["blocks"] == TIP
    assert info["initialblockdownload"] is True


def test_regtest_recent_tip_leaves_ibd_and_latches(tmp_path):
    bdb, tip_hash = _build(tmp_path)
    server = _with_core_ibd(_server(bdb, tmp_path))
    raw, new_hash = build_block(
        tip_hash, int(time.time()) - 60,
        [coinbase_tx(TIP + 1, tag=b"\x02I" + (TIP + 1).to_bytes(2, "little"))])
    bdb.connect_block_from_bytes(raw, TIP + 1, "regtest")
    info = asyncio.run(server.rpc_getblockchaininfo())
    assert info["initialblockdownload"] is False
    # Latch: an older tip afterwards (invalidateblock) does not re-enter IBD.
    asyncio.run(server.rpc_invalidateblock(new_hash[::-1].hex()))
    assert bdb._tip_timestamp == BASE_TIME + TIP * 600  # 2011 tip again
    info = asyncio.run(server.rpc_getblockchaininfo())
    assert info["initialblockdownload"] is False
