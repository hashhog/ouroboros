"""At-tip block bodies are fetched from a peer that announced the block.

Mainnet 2026-11-14/15: a new tip header arrived the same second as Core,
but the H1 frontier getdata for tip+1 went to the top-SCORE ready peer.
75 of 157 frontier requests went to one inbound peer that
had never announced a single header, never delivered the body, and kept
score 100 (its pings are fast, so the -1 timeout penalty is undone by the
latency health check).  Each such block waited out the 128 s mainnet
HEAD_TIMEOUT before the re-request went to a peer that served it in under
a second: ~2m15s Core-to-connected on most blocks.

The peer stayed eligible because ``_can_serve_block_at`` treats a known
height of 0 as "no signal", and a peer with a bogus high VERSION
start_height would pass the same gate.

Bitcoin Core (net_processing.cpp) only fetches a block from a peer whose
``pindexBestKnownBlock`` (set by that peer's header / inv / cmpctblock
announcements via UpdateBlockAvailability, never by VERSION startHeight)
covers it, and on a new tip header does a direct fetch from the peer that
announced it (HeadersDirectFetchBlocks).  ouroboros' analogue of
pindexBestKnownBlock is ``Peer.synced_headers``.

Control: ``pytest tests/test_tip_body_from_announcer.py``
"""

from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import MSG_WITNESS_BLOCK, BlockSync
from ouroboros.p2p_messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    BlockHeader,
    GetDataMessage,
    HeadersMessage,
)
from ouroboros.peer import Peer, PeerState


class _StubBlk:
    def __init__(self, bits: int, timestamp: int):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = b"\x00" * 32


def _block_one() -> BlockHeader:
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    return BlockHeader(
        version=1,
        prev_blockhash=genesis_be[::-1],
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )


BLOCK_ONE_HASH = bytes.fromhex(
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
)[::-1]


def _tip_sync(monkeypatch) -> BlockSync:
    """BlockSync at tip = genesis that accepts mainnet block 1's header."""
    import sync as _sync_for_test

    genesis_le = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )[::-1]
    db = MagicMock()
    db.get_best_block.return_value = (genesis_le, 0)
    db.has_block_hash.return_value = False
    db.get_block_hash_by_height.return_value = None
    db.get_median_time_past.return_value = 1_700_000_000
    db.get_block_by_height.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    db.get_block.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    min_work = int(_sync_for_test.get_minimum_chain_work("mainnet"), 16)
    db.get_chainwork_by_height = MagicMock(return_value=min_work + (1 << 80))

    pm = MagicMock()
    pm.network = "mainnet"
    pm.misbehaving = MagicMock()
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)
    return bs


def _ready_peer(host: str, score: int, start_height: int) -> Peer:
    p = Peer(host, 8333, "mainnet")
    p.state = PeerState.READY
    p.services = NODE_NETWORK | NODE_WITNESS
    p.score = score
    p.start_height = start_height
    p.note_block_height(start_height)
    p.send_message = AsyncMock()
    p.is_connected = lambda: True
    return p


def _block_getdata_count(peer: Peer, block_hash: bytes) -> int:
    n = 0
    for call in peer.send_message.await_args_list:
        netmsg = call.args[0]
        if netmsg.command != "getdata":
            continue
        inv = GetDataMessage.from_payload(netmsg.payload).inventory
        n += sum(1 for item in inv if tuple(item) == (MSG_WITNESS_BLOCK, block_hash))
    return n


def _headers_msg(headers: list[BlockHeader]):
    msg = MagicMock()
    msg.payload = HeadersMessage(headers=headers).serialize_payload()
    return msg


async def _announce_tip(bs: BlockSync, announcer: Peer) -> None:
    await bs.handle_headers(_headers_msg([_block_one()]), announcer, min_pow_checked=False)
    assert [h for h, _ in bs._validated_headers] == [BLOCK_ONE_HASH]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "silent_start_height",
    [0, 2_000_000],
    ids=["silent-peer-no-height", "silent-peer-bogus-high-start-height"],
)
async def test_new_tip_body_requested_from_announcing_peer(
    monkeypatch, silent_start_height
) -> None:
    """A new tip header from peer A: the body getdata goes to A.

    The silent peer outranks A on score and is listed first, exactly the
    11-14/15 mainnet shape.  Pre-fix the frontier getdata went to it and
    the body waited out HEAD_TIMEOUT (128 s on mainnet-size blocks).
    """
    bs = _tip_sync(monkeypatch)
    silent = _ready_peer("198.51.100.24", score=100, start_height=silent_start_height)
    announcer = _ready_peer("192.0.2.7", score=90, start_height=0)
    bs.peer_manager.get_all_ready_peers.return_value = [silent, announcer]

    await _announce_tip(bs, announcer)
    # handle_headers schedules block requests itself; one more pass must
    # not move the frontier either.
    await bs._request_next_blocks()

    assert announcer.synced_headers == 1
    assert _block_getdata_count(silent, BLOCK_ONE_HASH) == 0, (
        "tip+1 body was requested from a peer that never announced it"
    )
    assert _block_getdata_count(announcer, BLOCK_ONE_HASH) == 1
    assert bs._block_request_peer.get(BLOCK_ONE_HASH) is announcer


@pytest.mark.asyncio
async def test_second_block_of_burst_requested_from_announcing_peer() -> None:
    """Two-block burst: tip+1 already in flight on the announcer, tip+2 just
    announced.  The HEAD pass must send tip+2 to the announcer too, not to
    the silent top-score peer (a two-block burst is what puts the node at
    lag 2)."""
    tip_hash = hashlib.sha256(b"tip").digest()
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, 900_000)
    db.get_block_hash_by_height.return_value = None
    pm = MagicMock()
    pm.network = "regtest"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    h1 = hashlib.sha256(b"tip+1").digest()
    h2 = hashlib.sha256(b"tip+2").digest()
    bs._validated_headers = [(h1, MagicMock()), (h2, MagicMock())]

    silent = _ready_peer("198.51.100.24", score=100, start_height=0)
    announcer = _ready_peer("192.0.2.7", score=90, start_height=0)
    announcer.update_synced_headers(900_002)
    pm.get_all_ready_peers.return_value = [silent, announcer]

    now = time.time()
    bs.requested_blocks[h1] = now
    bs._block_request_peer[h1] = announcer

    await bs._request_next_blocks()

    assert _block_getdata_count(silent, h2) == 0, (
        "tip+2 body was requested from a peer that never announced it"
    )
    assert _block_getdata_count(announcer, h2) == 1
    assert bs._block_request_peer.get(h2) is announcer


@pytest.mark.asyncio
async def test_tip_body_prefers_higher_score_among_announcers(monkeypatch) -> None:
    """Among peers that announced the block, score order still decides."""
    bs = _tip_sync(monkeypatch)
    low = _ready_peer("192.0.2.7", score=60, start_height=0)
    high = _ready_peer("192.0.2.8", score=95, start_height=0)
    bs.peer_manager.get_all_ready_peers.return_value = [low, high]

    await _announce_tip(bs, low)
    high.update_synced_headers(1)
    bs.requested_blocks.clear()
    bs._block_request_peer.clear()
    bs._h1_last_issue.clear()
    for p in (low, high):
        p.send_message.reset_mock()
    await bs._request_next_blocks()

    assert _block_getdata_count(high, BLOCK_ONE_HASH) == 1
    assert _block_getdata_count(low, BLOCK_ONE_HASH) == 0


@pytest.mark.asyncio
async def test_tip_body_falls_back_when_no_peer_announced(monkeypatch) -> None:
    """No announcer among the ready peers (e.g. it disconnected): the
    frontier still goes to the top-score servable peer, as before."""
    bs = _tip_sync(monkeypatch)
    gone = _ready_peer("192.0.2.7", score=90, start_height=0)
    a = _ready_peer("198.51.100.1", score=100, start_height=0)
    b = _ready_peer("198.51.100.2", score=80, start_height=0)
    bs.peer_manager.get_all_ready_peers.return_value = [b, a]

    await _announce_tip(bs, gone)
    assert _block_getdata_count(a, BLOCK_ONE_HASH) == 1
    assert _block_getdata_count(b, BLOCK_ONE_HASH) == 0


@pytest.mark.asyncio
async def test_ibd_frontier_ordering_unchanged(monkeypatch) -> None:
    """Far from tip (queue longer than the head window) the frontier keeps
    going to the top-score servable peer; this change is at-tip only."""
    tip_hash = hashlib.sha256(b"tip").digest()
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, 900_000)
    db.get_block_hash_by_height.return_value = None
    pm = MagicMock()
    pm.network = "regtest"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    hashes = [hashlib.sha256(f"slot-{i}".encode()).digest() for i in range(40)]
    bs._validated_headers = [(h, MagicMock()) for h in hashes]

    top = _ready_peer("198.51.100.1", score=100, start_height=0)
    announcer = _ready_peer("192.0.2.7", score=90, start_height=0)
    announcer.update_synced_headers(900_040)
    pm.get_all_ready_peers.return_value = [top, announcer]

    await bs._request_next_blocks()

    assert bs._block_request_peer.get(hashes[0]) is top
