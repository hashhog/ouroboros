"""sm-fix-ouroboros-announce-accepted-tips: every tip change is announced.

Core: net_processing.cpp ``PeerManagerImpl::UpdatedBlockTip`` runs for every
tip change ActivateBestChain makes, whatever delivered the block (P2P,
submitblock, generatetoaddress, a reorg).  Unless the node is in initial
block download it walks from the new tip back to the fork point, at most
MAX_BLOCKS_TO_ANNOUNCE (8) hashes, and queues them oldest-first for every
peer; SendMessages then sends a header-preferring peer one ``headers``
message with those headers, and any other peer an ``inv`` of the tip only
(``fRevertToInv``).

Before the fix only the P2P drain announced.  A block connected through
``accept_block`` (submitblock, submitblockbatch, generatetoaddress) or by the
reorg engine ``_reorg_to_side_branch_tip`` was never relayed.  The first
case is pinned by ``test_sm_sweep_reorg.py::
test_sm_sweep_submitblock_tip_is_announced_to_peers``; this file pins the
reorg, the 8-block cap, the IBD gate and generatetoaddress.
"""

from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests._f0_chain import COIN, BASE_TIME, Chain, build_block, coinbase_tx  # noqa: E402

TIP = 10


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


class _Peer:
    host = "127.0.0.1"
    port = 18444
    wants_cmpctblock = False

    def __init__(self, wants_headers: bool = True):
        self.wants_headers = wants_headers
        self.sent = []

    async def send_message(self, msg):
        self.sent.append(msg)

    def announced(self) -> list:
        return [m for m in self.sent
                if m.command in ("headers", "inv", "cmpctblock")]


def _setup(tmp_path, peers, *, ibd: bool | None = None):
    from ouroboros.block_sync import BlockSync
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    Chain(bdb._db, tip=TIP)
    pm = MagicMock()
    pm.network = "regtest"
    pm.get_all_ready_peers.return_value = list(peers)

    async def _broadcast(msg):
        for p in pm.get_all_ready_peers():
            await p.send_message(msg)

    pm.broadcast = AsyncMock(side_effect=_broadcast)
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(str(tmp_path / "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, peer_manager=pm,
                           data_dir=str(tmp_path))
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    node.get_median_time = lambda h: 0
    if ibd is not None:
        node.is_initial_block_download = lambda: ibd
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    server._side_branch_max_entries = 1024
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, server, hashes


def _block(prev: bytes, height: int, tag: int):
    cb = coinbase_tx(height, value=50 * COIN, tag=bytes([tag, 0xB7]))
    return build_block(prev, BASE_TIME + height * 600 + 11, [cb])


async def _settle():
    for _ in range(50):  # let a scheduled announce task run
        await asyncio.sleep(0)


def _submit_side_branch(server, prev: bytes, first_height: int, n: int):
    """Submit ``n`` blocks on ``prev``; returns (hashes, results)."""
    out, results = [], []

    async def go():
        nonlocal prev
        for i in range(n):
            raw, h = _block(prev, first_height + i, 0x60 + i)
            results.append(await server.rpc_submitblock(raw.hex()))
            await _settle()
            out.append(h)
            prev = h

    asyncio.run(go())
    return out, results


def _header_hashes(msg) -> list[bytes]:
    from ouroboros.p2p_messages import HeadersMessage

    hm = HeadersMessage.from_payload(msg.payload)
    return [hashlib.sha256(hashlib.sha256(h.serialize()).digest()).digest()
            for h in hm.headers]


def test_reorg_announces_new_tip_headers_from_fork_point(tmp_path):
    """Side branch off TIP-1 overtakes the active chain: the side block at
    TIP (equal work, stored only) is not announced; the block that makes the
    side branch heavier reorgs, and the peer gets ONE headers message with
    both new-chain headers, oldest first."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    side, results = _submit_side_branch(server, hashes[TIP - 1], TIP, 2)
    assert results == ["inconclusive", None], "precondition: second block reorgs"
    assert bdb.get_best_block() == (side[-1], TIP + 1), "precondition: reorged"
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers"], msgs
    assert _header_hashes(msgs[0]) == side


def test_reorg_inv_peer_gets_only_the_new_tip(tmp_path):
    """Core fRevertToInv: a peer that did not send sendheaders gets an inv of
    the new tip only, not one inv per block of the reorg."""
    from ouroboros.p2p_messages import INV_TYPE_BLOCK, InvMessage

    peer = _Peer(wants_headers=False)
    bdb, server, hashes = _setup(tmp_path, [peer])
    side, results = _submit_side_branch(server, hashes[TIP - 1], TIP, 2)
    assert results == ["inconclusive", None]
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["inv"], msgs
    inv = InvMessage.from_payload(msgs[0].payload)
    assert [(t, bytes(h)) for t, h in inv.inventory] == [(INV_TYPE_BLOCK, side[-1])]


def test_long_reorg_announces_an_inv_of_the_tip(tmp_path):
    """Core MAX_BLOCKS_TO_ANNOUNCE: UpdatedBlockTip stops after 8 blocks, so
    for a longer reorg the first queued header's parent is a new-branch block
    the peer does not have; SendMessages finds no header that connects
    (PeerHasHeader(pindex->pprev) fails) and reverts to an inv of the tip,
    even for a sendheaders peer.  A headers message that does not connect
    would push the peer into its unconnecting-headers handling."""
    from ouroboros.p2p_messages import INV_TYPE_BLOCK, InvMessage

    from ouroboros import rpc

    # getattr, so the base commit fails on this assertion, not on import.
    assert getattr(rpc, "MAX_BLOCKS_TO_ANNOUNCE", None) == 8
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    # Fork off block 1: side heights 2..11 (10 blocks); only the 10th
    # (height 11) has more work than the active tip at 10.
    side, results = _submit_side_branch(server, hashes[1], 2, TIP)
    assert results[-1] is None and set(results[:-1]) == {"inconclusive"}
    assert bdb.get_best_block() == (side[-1], TIP + 1), "precondition: reorged"
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["inv"], msgs
    inv = InvMessage.from_payload(msgs[0].payload)
    assert [(t, bytes(h)) for t, h in inv.inventory] == [(INV_TYPE_BLOCK, side[-1])]


def test_eight_block_reorg_announces_all_eight_headers(tmp_path):
    """The cap's edge: a reorg of exactly 8 blocks reaches the fork point,
    which the peer has, so all 8 headers go in one headers message."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    # Fork off block 3: side heights 4..11 (8 blocks); the 8th overtakes.
    side, results = _submit_side_branch(server, hashes[3], 4, 8)
    assert results[-1] is None and set(results[:-1]) == {"inconclusive"}
    assert bdb.get_best_block() == (side[-1], TIP + 1), "precondition: reorged"
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers"], msgs
    assert _header_hashes(msgs[0]) == side


def test_linear_submitblock_announces_exactly_the_new_tip(tmp_path):
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    side, results = _submit_side_branch(server, hashes[TIP], TIP + 1, 2)
    assert results == [None, None]
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers", "headers"], msgs
    assert [_header_hashes(m) for m in msgs] == [[side[0]], [side[1]]]


def test_no_announce_while_in_initial_block_download(tmp_path):
    """Core UpdatedBlockTip returns early while fInitialDownload."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer], ibd=True)
    side, results = _submit_side_branch(server, hashes[TIP], TIP + 1, 1)
    assert results == [None], "precondition: block accepted"
    assert bdb.get_best_block() == (side[0], TIP + 1)
    assert peer.announced() == []


def test_announce_when_out_of_initial_block_download(tmp_path):
    """Control for the IBD gate: the same chain, latched out of IBD."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer], ibd=False)
    side, results = _submit_side_branch(server, hashes[TIP], TIP + 1, 1)
    assert results == [None]
    assert [m.command for m in peer.announced()] == ["headers"]


def test_rejected_block_is_not_announced(tmp_path):
    """A block accept_block rejects changes no tip and is not announced."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    cb = coinbase_tx(TIP + 1, value=51 * COIN, tag=b"\x02X")  # bad-cb-amount
    raw, _ = build_block(hashes[TIP], BASE_TIME + (TIP + 1) * 600 + 1, [cb])

    async def go():
        r = await server.rpc_submitblock(raw.hex())
        await _settle()
        return r

    assert asyncio.run(go()) not in (None, "inconclusive")
    assert bdb.get_best_block() == (hashes[TIP], TIP)
    assert peer.announced() == []


def test_generatetoaddress_announces_each_block_once(tmp_path):
    """generatetoaddress used to send its own bare inv; it now goes through
    the same announcer as every other tip change, once per block."""
    from ouroboros.address import script_pubkey_to_address

    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    addr = script_pubkey_to_address(bytes([0x00, 0x14]) + b"\x11" * 20, "regtest")

    async def go():
        r = await server.rpc_generatetoaddress(2, addr)
        await _settle()
        return r

    mined = asyncio.run(go())
    assert len(mined) == 2
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers", "headers"], msgs
    assert [_header_hashes(m)[0][::-1].hex() for m in msgs] == mined


def test_invalidateblock_switch_announces_the_side_tip_once(tmp_path):
    """invalidateblock activates a stored 1-block side branch.  That goes
    through the reorg engine's per-block path (accept_block with
    announce=False), and the switch is announced once, by the engine."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    side, results = _submit_side_branch(server, hashes[TIP - 1], TIP, 1)
    assert results == ["inconclusive"] and peer.announced() == []

    async def go():
        await server.rpc_invalidateblock(hashes[TIP][::-1].hex())
        await _settle()

    asyncio.run(go())
    assert bdb.get_best_block() == (side[0], TIP), "precondition: switched"
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers"], msgs
    assert _header_hashes(msgs[0]) == side


def test_submitblockbatch_announces_each_connected_block(tmp_path):
    """submitblockbatch connects each block through accept_block; each one
    is a tip change and is announced once, in order."""
    peer = _Peer()
    bdb, server, hashes = _setup(tmp_path, [peer])
    raw1, h1 = _block(hashes[TIP], TIP + 1, 0x70)
    raw2, h2 = _block(h1, TIP + 2, 0x71)

    async def go():
        r = await server.rpc_submitblockbatch([raw1.hex(), raw2.hex()])
        await _settle()
        return r

    assert asyncio.run(go()) == [None, None], "precondition: both accepted"
    assert bdb.get_best_block() == (h2, TIP + 2)
    msgs = peer.announced()
    assert [m.command for m in msgs] == ["headers", "headers"], msgs
    assert [_header_hashes(m) for m in msgs] == [[h1], [h2]]
