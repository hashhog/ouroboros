"""Inv-triggered block getdata is bounded per peer (cffix-ouroboros-inv-block-inflight-cap).

Core (net_processing.cpp, ProcessMessage INV branch) never sends getdata for
an unknown block inv: it records the hash and sends getheaders; bodies are then
fetched by FindNextBlocksToDownload, which hands a peer new blocks only while
it has fewer than MAX_BLOCKS_IN_FLIGHT_PER_PEER (16) in flight.

ouroboros keeps a direct inv->getdata shortcut (prompt relay from a mining
peer), but it was bounded only by the GLOBAL in-flight window (256).  One peer
announcing 300 random block hashes therefore took all 256 slots; the bodies
never arrive (notfound frees nothing), so the slots stay held until the
download timeout, and IBD's ``cap_inflight`` drops to zero.  The shortcut must
honour the same per-peer cap as every other block-download path.
"""

from __future__ import annotations

import asyncio
import os
import struct

from ouroboros.p2p_messages import (
    MSG_WITNESS_BLOCK,
    NODE_NETWORK,
    NODE_WITNESS,
    GetDataMessage,
    NetworkMessage,
    get_magic,
)
from ouroboros.peer import Peer

NET = "regtest"
PER_PEER_CAP = 16  # Core MAX_BLOCKS_IN_FLIGHT_PER_PEER


class _InvDB:
    """Knows no block, tip at height 10; every other call returns None."""

    def has_block_hash(self, h):
        return False

    def get_best_block(self):
        return (b"\x00" * 32, 10)

    def __getattr__(self, name):
        def _none(*a, **k):
            return None
        return _none


class _PM:
    network = NET

    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return list(self._peers)


def _run(coro):
    return asyncio.run(coro)


def _ready_witness_peer(i: int) -> Peer:
    from ouroboros.peer import PeerState
    p = Peer("10.9.1.%d" % i, 18444, NET, inbound=True)
    p.state = PeerState.READY
    p.services = NODE_NETWORK | NODE_WITNESS
    p.version = 70016
    p.handshake_complete = True
    p.sent = []

    async def _send(m):
        p.sent.append(m)

    p.send_message = _send
    return p


def _block_sync(peers):
    from ouroboros.block_sync import BlockSync
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=_InvDB(), validator=None,
                       peer_manager=_PM(peers), mempool=None)
    return bs


def _inv_blocks(hashes) -> NetworkMessage:
    assert len(hashes) < 0xFD
    payload = bytes([len(hashes)]) + b"".join(
        struct.pack("<I", 2) + h for h in hashes
    )
    return NetworkMessage(command="inv", payload=payload, magic=get_magic(NET))


def _inv_many(hashes) -> NetworkMessage:
    # CompactSize 0xFD prefix for 253..65535 items.
    payload = b"\xfd" + struct.pack("<H", len(hashes)) + b"".join(
        struct.pack("<I", 2) + h for h in hashes
    )
    return NetworkMessage(command="inv", payload=payload, magic=get_magic(NET))


def _getdata_block_items(peer):
    out = []
    for m in peer.sent:
        if m.command == "getdata":
            out += [h for t, h in GetDataMessage.from_payload(m.payload).inventory
                    if t & 0xFFFF == 2 or t == MSG_WITNESS_BLOCK]
    return out


def _random_hashes(n):
    return [os.urandom(32) for _ in range(n)]


def test_inv_300_random_blocks_one_peer_capped_at_16():
    peer = _ready_witness_peer(1)
    bs = _block_sync([peer])
    hashes = _random_hashes(300)
    _run(bs.handle_inv(_inv_many(hashes), peer))

    requested = _getdata_block_items(peer)
    assert len(requested) <= PER_PEER_CAP, len(requested)
    assert len(bs.requested_blocks) <= PER_PEER_CAP, len(bs.requested_blocks)
    # Every slot taken is attributed to the announcing peer.
    assert all(bs._block_request_peer.get(h) is peer for h in bs.requested_blocks)


def test_inv_repeated_batches_do_not_exceed_per_peer_cap():
    peer = _ready_witness_peer(2)
    bs = _block_sync([peer])
    for _ in range(5):
        _run(bs.handle_inv(_inv_blocks(_random_hashes(10)), peer))
    assert len(_getdata_block_items(peer)) <= PER_PEER_CAP
    assert len(bs.requested_blocks) <= PER_PEER_CAP


def test_inv_flood_from_one_peer_leaves_slots_for_another():
    flooder = _ready_witness_peer(3)
    honest = _ready_witness_peer(4)
    bs = _block_sync([flooder, honest])
    _run(bs.handle_inv(_inv_many(_random_hashes(300)), flooder))

    real = b"\x77" * 32
    _run(bs.handle_inv(_inv_blocks([real]), honest))
    assert _getdata_block_items(honest) == [real]
    assert bs._block_request_peer.get(real) is honest


def test_inv_single_block_still_fetched_directly():
    # The regtest mining-peer shortcut stays: one announced block is fetched.
    peer = _ready_witness_peer(5)
    bs = _block_sync([peer])
    h = b"\x55" * 32
    _run(bs.handle_inv(_inv_blocks([h]), peer))
    assert _getdata_block_items(peer) == [h]


def _age_all_requests(bs, seconds=100_000):
    for h in list(bs.requested_blocks):
        bs.requested_blocks[h] -= seconds


def _junk_load(bs, peer, junk):
    return sum(1 for h, p in bs._block_request_peer.items()
               if p is peer and h in junk and h in bs.requested_blocks)


def test_inv_junk_not_rerouted_to_honest_peers_on_timeout():
    # The finding's harm is slots held across timeout cycles: the timeout
    # sweep must not move one peer's headerless inv announces onto honest
    # peers, or the flood fills every peer's per-peer cap over a few cycles.
    flooder = _ready_witness_peer(10)
    honest = [_ready_witness_peer(11 + i) for i in range(4)]
    bs = _block_sync([flooder] + honest)
    junk: set[bytes] = set()
    for _cycle in range(8):
        batch = _random_hashes(300)
        junk.update(batch)
        _run(bs.handle_inv(_inv_many(batch), flooder))
        _age_all_requests(bs)
        _run(bs._handle_timeouts())
    for p in honest:
        assert _junk_load(bs, p, junk) == 0, _junk_load(bs, p, junk)
        assert _getdata_block_items(p) == []
    # Only the last cycle's fresh inv could still be in flight after a
    # final flood; after its timeout nothing junk remains.
    assert not (junk & set(bs.requested_blocks))


def test_inv_flood_from_many_peers_leaves_download_window():
    # 20 inbound flooders, each within its own per-peer cap, must not fill
    # the 256-slot window that IBD's cap_inflight is computed from.
    import ouroboros.block_sync as block_sync
    # 4 x MAX_BLOCKS_IN_FLIGHT_PER_PEER; read via getattr so this file still
    # imports on master and fails there on the assertion.
    inv_budget = getattr(block_sync, "INV_FETCH_MAX_IN_FLIGHT", 64)
    flooders = [_ready_witness_peer(50 + i) for i in range(20)]
    bs = _block_sync(flooders)
    for p in flooders:
        _run(bs.handle_inv(_inv_many(_random_hashes(300)), p))
    assert len(bs.requested_blocks) <= inv_budget
    assert bs._max_blocks_in_flight - len(bs.requested_blocks) >= 192


def test_inv_fetched_block_with_header_is_still_rerequested():
    # Guard against over-dropping: once the announced block's header is in
    # the validated-header queue it is a real download and a timeout
    # re-requests it from another peer, as for any queued block.
    first = _ready_witness_peer(80)
    second = _ready_witness_peer(81)
    bs = _block_sync([first, second])
    h = b"\x66" * 32
    _run(bs.handle_inv(_inv_blocks([h]), first))
    assert bs._block_request_peer.get(h) is first
    bs._validated_headers.append((h, None))
    _age_all_requests(bs)
    _run(bs._handle_timeouts())
    assert h in bs.requested_blocks
    assert bs._block_request_peer.get(h) is second
