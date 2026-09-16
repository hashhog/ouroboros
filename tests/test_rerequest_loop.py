"""Failing control for the high-range re-request/fork loop.

Receipt: receipts/ouroboros-rerequest-loop-high-range-2026-09-13.md
(QUEUES.md ouroboros item 0, 2026-09-13).

Range 481807→515000 ran 5.5h and never closed. The feeder served 38741
bodies for a 33193-block range because ouroboros:

1. H1-re-getdata'd an already in-flight frontier to the same single
   --connect feeder every FRONTIER_REQUEST_INTERVAL (log: "H1 frontier
   priority: re-requested tip+1" + "Requested N blocks (tip+0)").
2. After connect, left the just-connected header at slot 0 of
   ``_validated_headers`` across the next await (``asyncio.sleep(0)`` /
   index updates). ``_prune_validated_headers`` then saw
   slot0.prev != new tip and dropped the whole queue (630
   ``[slot-misalign]`` drops on that run). Fresh headers were stored as
   forks and their bodies re-downloaded.

Fix: advance the header queue on connect (before any yield); do not
H1-re-request an in-flight block whose holder is still live; an IBD-
queued / already-connected body is not consumed as a fork body.

The campaign range is the discovery method (hours). This file is the
in-repo control that must go red on current master and green after the
fix.
"""

from __future__ import annotations

import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import (
    FRONTIER_REQUEST_INTERVAL,
    MSG_WITNESS_BLOCK,
    BlockSync,
)
from ouroboros.p2p_messages import NODE_NETWORK, NODE_WITNESS, GetDataMessage
from ouroboros.peer import Peer


def _h(tag: int) -> bytes:
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


def _make_block_sync(tip_hash: bytes, tip_height: int) -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.get_block_hash_by_height.return_value = None
    db.find_height_of_hash.return_value = None
    db.has_block_hash.return_value = False
    db.get_block_bytes.return_value = None
    pm = MagicMock()
    pm.network = "regtest"
    return BlockSync(db=db, validator=MagicMock(), peer_manager=pm)


def _make_ready_peer(host: str, score: int = 100) -> MagicMock:
    peer = MagicMock(spec=Peer)
    peer.host = host
    peer.port = 8333
    peer.score = score
    peer.is_connected.return_value = True
    peer.services = NODE_NETWORK | NODE_WITNESS
    peer.start_height = 0
    peer.best_known_height = 0
    peer.send_message = AsyncMock()
    peer.adjust_score = MagicMock()
    return peer


def _frontier_sends(peer: MagicMock, frontier_hash: bytes) -> int:
    n = 0
    for call in peer.send_message.await_args_list:
        netmsg = call.args[0]
        gd = GetDataMessage.from_payload(netmsg.payload)
        inv = list(gd.inventory)
        if inv == [(MSG_WITNESS_BLOCK, frontier_hash)]:
            n += 1
    return n


def _hdr(prev: bytes):
    h = MagicMock()
    h.prev_blockhash = prev
    return h


# ---------------------------------------------------------------------------
# 1. Don't re-request an in-flight block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h1_does_not_rerequest_inflight_frontier_from_live_holder():
    """Control (red on master): a frontier already in-flight to a still-
    connected peer must NOT get another getdata when H1's interval elapses.

    Campaign ranges have exactly one --connect feeder, so H1 "rotation" is
    a duplicate getdata to the same peer. That is the served-count >
    range-size loop.
    """
    tip_hash = _h(0xDEAD)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [
        (_h(i), _hdr(tip_hash if i == 0 else _h(i - 1))) for i in range(0, 8)
    ]
    bs._ibd_block_buffer = {}

    holder = _make_ready_peer("127.0.0.1", score=100)
    bs.peer_manager.get_all_ready_peers.return_value = [holder]

    import time as _time

    stale = _time.time() - (FRONTIER_REQUEST_INTERVAL + 1.0)
    bs.requested_blocks[frontier] = stale
    bs._block_request_peer[frontier] = holder
    bs._h1_last_issue[frontier] = stale

    await bs._request_next_blocks()

    assert _frontier_sends(holder, frontier) == 0, (
        "H1 re-requested an in-flight frontier from its still-connected "
        "holder — the single-feeder re-request loop"
    )
    assert bs.requested_blocks[frontier] == stale
    assert bs._block_request_peer[frontier] is holder


@pytest.mark.asyncio
async def test_h1_rerequests_when_holder_is_gone():
    """Rotation still happens when the in-flight holder has disconnected.
    HEAD_TIMEOUT / a dead peer is the legitimate re-request path.
    """
    tip_hash = _h(0xBEEF)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [
        (_h(i), _hdr(tip_hash if i == 0 else _h(i - 1))) for i in range(0, 8)
    ]
    bs._ibd_block_buffer = {}

    dead = _make_ready_peer("10.0.0.1", score=100)
    dead.is_connected.return_value = False
    live = _make_ready_peer("10.0.0.2", score=40)
    # get_all_ready_peers returns only connected peers in production; the
    # departed holder is remembered only via _block_request_peer.
    bs.peer_manager.get_all_ready_peers.return_value = [live]

    import time as _time

    stale = _time.time() - (FRONTIER_REQUEST_INTERVAL + 1.0)
    bs.requested_blocks[frontier] = stale
    bs._block_request_peer[frontier] = dead

    await bs._request_next_blocks()

    assert _frontier_sends(live, frontier) == 1
    assert bs._block_request_peer[frontier] is live
    # In-flight timestamp must survive the re-issue (HEAD_TIMEOUT clock).
    assert bs.requested_blocks[frontier] == stale


@pytest.mark.asyncio
async def test_h1_does_not_rerequest_connecting_frontier():
    """handle_block pops requested_blocks before drain finishes. Without a
    connecting-hash set, H1 treats the frontier as missing and re-getdatas
    the block the drain is already connecting — the other half of the
    re-request loop.
    """
    tip_hash = _h(0xF00D)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [
        (_h(i), _hdr(tip_hash if i == 0 else _h(i - 1))) for i in range(0, 8)
    ]
    bs._ibd_block_buffer = {}
    bs.requested_blocks = {}

    holder = _make_ready_peer("127.0.0.1", score=100)
    bs.peer_manager.get_all_ready_peers.return_value = [holder]

    connecting = getattr(bs, "_connecting_hashes", None)
    if connecting is None:
        pytest.fail(
            "no _connecting_hashes — H1 cannot see a drain-in-progress "
            "frontier and will re-request it"
        )
    connecting.add(frontier)

    await bs._request_next_blocks()

    assert _frontier_sends(holder, frontier) == 0, (
        "H1/HEAD re-requested a frontier the drain is currently connecting"
    )
    assert frontier not in bs.requested_blocks


# ---------------------------------------------------------------------------
# 2. Advance the header queue on connect, before any yield
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_pops_connected_header_before_yield(monkeypatch):
    """Control (red on master): after connect, slot 0 must already be the
    NEW frontier before ``asyncio.sleep(0)``. Otherwise
    ``_prune_validated_headers`` (scheduled on that yield) sees
    slot0.prev != new tip and drops the whole queue — 630
    ``[slot-misalign]`` drops on 481807→515000, after which the feeder's
    re-sent headers are stored as forks.
    """
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")

    tip = _h(0)
    a = _h(1)
    b = _h(2)
    bs = _make_block_sync(tip, 100)
    bs.db.get_block_bytes.return_value = None
    bs._validated_headers = [(a, _hdr(tip)), (b, _hdr(a))]
    bs._buffer_put(a, (None, b"\x00" * 80))

    stub = MagicMock()
    stub.transactions = []
    stub.prev_blockhash = tip
    monkeypatch.setattr("ouroboros.block_sync.Block.deserialize", lambda _p: stub)
    bs.validator.validate_block.return_value = (True, "")

    def _connect(_payload, height, _network):
        bs.db.get_best_block.return_value = (a, height)

    bs.db.connect_block_from_bytes.side_effect = _connect

    orig_sleep = asyncio.sleep
    seen_during_yield: list[bytes] = []

    async def _sleep_and_prune(_dt):
        # The queue must already be advanced BEFORE this yield; otherwise
        # a skip-prune-while-drain-locked band-aid would hide the race.
        if bs._validated_headers:
            seen_during_yield.append(bs._validated_headers[0][0])
        bs._prune_validated_headers()
        await orig_sleep(0)

    monkeypatch.setattr("ouroboros.block_sync.asyncio.sleep", _sleep_and_prune)

    connected = await bs._drain_block_buffer()

    assert connected >= 1
    assert seen_during_yield and seen_during_yield[0] == b, (
        "drain yielded with the just-connected header still at slot 0; "
        f"slot0 during yield={seen_during_yield[:1]}"
    )
    assert bs._validated_headers, (
        "_prune_validated_headers dropped the queue (slot-misalign race)"
    )
    assert bs._validated_headers[0][0] == b
    assert bs._queue_anchored_to_tip() is True


# ---------------------------------------------------------------------------
# 3. IBD-queued / already-connected body is not a fork body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ibd_queued_body_is_not_consumed_as_fork(monkeypatch):
    """Control (red on master): a body whose hash is the IBD frontier must
    land in ``_ibd_block_buffer`` even if the same hash was also admitted
    to ``_fork_headers``. Pre-fix the fork path ran first and returned
    without buffering, so H1 kept re-requesting tip+1 forever.
    """
    tip = _h(0)
    bs = _make_block_sync(tip, 100)

    monkeypatch.setattr(bs, "_drain_block_buffer", AsyncMock(return_value=0))
    monkeypatch.setattr(bs, "_request_next_blocks", AsyncMock())
    monkeypatch.setattr(bs, "_on_fork_body_received", AsyncMock())

    header = b"\x11" * 80
    real_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    bs._validated_headers = [(real_hash, _hdr(tip))]
    bs._fork_headers[real_hash] = _hdr(tip)
    bs._fork_header_prev[real_hash] = tip
    bs.requested_blocks = {real_hash: 1.0}

    msg = MagicMock()
    msg.payload = header
    peer = _make_ready_peer("127.0.0.1")

    await bs.handle_block(msg, peer)

    assert real_hash in bs._ibd_block_buffer, (
        "IBD-queued body was consumed as a fork body and never buffered"
    )
    assert real_hash not in bs.requested_blocks
    bs._request_next_blocks.assert_awaited()
    bs._on_fork_body_received.assert_not_awaited()


def test_already_connected_header_is_not_stored_as_fork():
    """A header whose hash IS the active tip (or on the active chain) is a
    locator replay, not a competing fork. Pre-fix the 481807 run stored
    14 already-connected heights as fork headers the moment the queue
    was dropped, then re-downloaded their bodies.
    """
    tip = _h(0)
    replay = _h(9)
    bs = _make_block_sync(tip, 481_822)
    bs.db.get_best_block.return_value = (replay, 481_822)

    stored_before = bs._fork_headers_stored
    bs._store_fork_header(replay, _hdr(tip), tip)
    assert replay not in bs._fork_headers
    assert bs._fork_headers_stored == stored_before
