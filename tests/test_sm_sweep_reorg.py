"""sm-sweep-ouroboros, path (c) reorg / tip change outside the P2P drain.

C5  New tips that arrive through ``accept_block`` (rpc.py) are never
    announced to peers.  The only caller of ``_schedule_announce`` /
    ``_announce_block`` is the linear P2P drain (block_sync.py), and
    ``rpc_generatetoaddress`` broadcasts its own bare inv.  submitblock (the
    miner path), submitblockbatch and every reorg the engine
    ``_reorg_to_side_branch_tip`` performs (P2P fork bridge,
    invalidateblock / reconsiderblock / preciousblock activation) connect
    through ``accept_block``, which signals the tip notifier and the indexes
    but sends no inv / headers / cmpctblock.  A block mined on ouroboros is
    not relayed by ouroboros at all; after a reorg, peers are not told the
    new tip.
    Core: net_processing.cpp ``PeerManagerImpl::UpdatedBlockTip`` (validation
    interface, fired by ActivateBestChain for every tip change, any source)
    queues up to MAX_BLOCKS_TO_ANNOUNCE hashes into ``m_blocks_for_headers_relay``
    / inv for every peer; ``NewPoWValidBlock`` sends cmpctblock.

xfail(strict=True) until sm-fix-ouroboros-announce-accepted-tips lands.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests.test_invalidateblock_sticky import _setup  # noqa: E402


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


class _RelayPeer:
    host = "127.0.0.1"
    port = 18444
    wants_cmpctblock = False
    wants_headers = True

    def __init__(self):
        self.sent = []

    async def send_message(self, msg):
        self.sent.append(msg)


def _announced(peer: _RelayPeer) -> list[str]:
    return [m.command for m in peer.sent
            if m.command in ("headers", "inv", "cmpctblock")]


def _wire_peer(server, bs, peer):
    # One peer manager, reachable both as block_sync.peer_manager and
    # node.peer_manager, so a fix may announce through either, with any of
    # the repo's idioms: BlockSync._announce_block (get_all_ready_peers ->
    # peer.send_message) or PeerManager.broadcast (rpc_generatetoaddress).
    pm = bs.peer_manager
    pm.get_all_ready_peers.return_value = [peer]
    pm.network = "regtest"

    async def _broadcast(msg):
        for p in pm.get_all_ready_peers():
            await p.send_message(msg)

    pm.broadcast = AsyncMock(side_effect=_broadcast)
    server.node.peer_manager = pm


@pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros C5: a tip connected through accept_block "
    "(submitblock / reorg engine) is never announced to peers",
)
def test_sm_sweep_submitblock_tip_is_announced_to_peers(tmp_path):
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    peer = _RelayPeer()
    _wire_peer(server, bs, peer)
    raw, new_hash = chain.next_block([])  # child of the tip

    async def go():
        result = await server.rpc_submitblock(raw.hex())
        for _ in range(50):  # let any scheduled announce task run
            await asyncio.sleep(0)
        return result

    assert asyncio.run(go()) is None, "precondition: block accepted"
    assert bdb.get_best_block()[1] == max(hashes) + 1, "precondition: new tip"
    assert _announced(peer), "the new tip was not announced to any peer"


def test_sm_sweep_control_drain_announcer_reaches_the_peer(tmp_path):
    """Control: the announcer the drain uses does reach this stub peer."""
    bdb, chain, bs, server, hashes = _setup(tmp_path)
    peer = _RelayPeer()
    _wire_peer(server, bs, peer)
    tip = bdb.get_block(hashes[max(hashes)])
    asyncio.run(bs._announce_block(tip, hashes[max(hashes)]))
    assert _announced(peer) == ["headers"]


def test_sm_sweep_control_broadcast_idiom_reaches_the_peer(tmp_path):
    """Control: an announcement through node.peer_manager.broadcast (the
    rpc_generatetoaddress idiom) is also seen by the test."""
    from ouroboros.p2p_messages import INV_TYPE_BLOCK, InvMessage

    bdb, chain, bs, server, hashes = _setup(tmp_path)
    peer = _RelayPeer()
    _wire_peer(server, bs, peer)
    inv = InvMessage(inventory=[(INV_TYPE_BLOCK, hashes[max(hashes)])])
    asyncio.run(server.node.peer_manager.broadcast(inv.to_network_message("regtest")))
    assert _announced(peer) == ["inv"]


# --------------------------------------------------------------------------- #
# C1  BIP157 filter-header chain after a reorg
# --------------------------------------------------------------------------- #
#
# The reorg engine disconnects one block at a time and reconnects the new
# branch through ``accept_block`` -> ``bfi.add_block`` (rpc.py), which chains
# each new header off the index's *tip_header* file
# (PersistentBlockFilterIndex.add -> _get_tip_header, blockfilter.py) — the
# header of the last block ADDED, i.e. the old tip, not the fork point.  The
# reorg engine never calls ``bfi.remove`` / ``set_tip_header``.  Every filter
# header from the first new-branch block onward is then wrong, is served by
# cfheaders / cfcheckpt and getblockfilter, and survives restarts (the boot
# reconcile compares block hashes per height, which match).
# Core: index/base.cpp ``BaseIndex::BlockConnected`` rewinds the index to
# ``pindex->pprev`` when it is not the index tip, and
# ``BlockFilterIndex::CustomRemove`` restores the previous header.
#
# Fixed by sm-fix-ouroboros-filter-header-reorg: PersistentBlockFilterIndex.add
# chains each header off the block's parent (looked up by prev hash).


def _reorg_with_filter_index(tmp_path):
    from ouroboros.blockfilter import PersistentBlockFilterIndex
    from tests.test_invalidateblock_best_chain import TIP, _block
    from tests.test_invalidateblock_best_chain import _setup as _bc_setup

    bdb, server, hashes = _bc_setup(tmp_path)
    bfi = PersistentBlockFilterIndex(str(tmp_path / "bfi"))
    for h in range(TIP + 1):
        bfi.add_block(bdb.get_block_by_height(h), h, bdb)
    server.node.block_filter_index = bfi
    # Fork off TIP-1: side block at TIP (equal work, stored), then TIP+1
    # (more work than the active chain -> the engine reorgs onto it).
    raw1, s1 = _block(hashes[TIP - 1], TIP, bytes([0x51, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw1.hex())) == "inconclusive"
    raw2, s2 = _block(s1, TIP + 1, bytes([0x52, 0xB7]))
    assert asyncio.run(server.rpc_submitblock(raw2.hex())) is None
    assert bdb.get_best_block() == (s2, TIP + 1), "precondition: reorged"
    return bdb, bfi, hashes, TIP, s1, s2


def _expected_header(bdb, block_hash: bytes, prev_header: bytes) -> bytes:
    from ouroboros.blockfilter import build_basic_filter, compute_filter_header

    blk = bdb.get_block(block_hash)
    return compute_filter_header(build_basic_filter(blk, bdb), prev_header)


def test_sm_sweep_filter_header_after_reorg_chains_from_fork_point(tmp_path):
    bdb, bfi, hashes, tip, s1, s2 = _reorg_with_filter_index(tmp_path)
    fork_header = bfi.get_header(hashes[tip - 1])
    want1 = _expected_header(bdb, s1, fork_header)
    assert bfi.get_header(s1) == want1, (
        "first new-branch filter header is not chained off the fork point"
    )
    assert bfi.get_header(s2) == _expected_header(bdb, s2, want1)


def test_sm_sweep_control_linear_filter_headers_chain(tmp_path):
    """Control: without a reorg the same recomputation matches the index."""
    from ouroboros.blockfilter import PersistentBlockFilterIndex
    from tests.test_invalidateblock_best_chain import TIP
    from tests.test_invalidateblock_best_chain import _setup as _bc_setup

    bdb, server, hashes = _bc_setup(tmp_path)
    bfi = PersistentBlockFilterIndex(str(tmp_path / "bfi"))
    for h in range(TIP + 1):
        bfi.add_block(bdb.get_block_by_height(h), h, bdb)
    for h in range(1, TIP + 1):
        assert bfi.get_header(hashes[h]) == _expected_header(
            bdb, hashes[h], bfi.get_header(hashes[h - 1]))
