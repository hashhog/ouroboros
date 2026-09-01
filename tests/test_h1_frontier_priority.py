"""Regression tests for the H1 connect-frontier-priority scheduling fix.

Background — the H1 at-tip block-download wedge.  The strictly-in-order block
drain (``_drain_block_buffer_locked``) can only advance on the CONNECT FRONTIER
— slot 0 of ``_validated_headers`` == tip+1.  Peers reliably flood the IBD
buffer with FAR-AHEAD blocks, but the ONE connect-frontier block is frequently
NOT served by its single round-robin-assigned peer within the (size-aware, up
to 64 s) ``HEAD_TIMEOUT``, so the drain is head-of-line-blocked for minutes
while ~14 later blocks sit ready.  It is a SCHEDULING problem — budget is ample
(cap_inflight ~244, in_flight ~12) — not a budget/peer-count one.

Fix (H1 v2, ``_request_next_blocks``): each request cycle, re-issue the
frontier as a SINGLE getdata to the TOP-scoring ready peer, ROTATING to a
peer other than its current holder, on a ``FRONTIER_REQUEST_INTERVAL`` cadence
that is deliberately SHORTER than ``HEAD_TIMEOUT``.  Never a fan-out (the
reverted FIX-ATTEMPT-1 fanned the frontier to 4 peers with awaited sends and
caused a ``socket.send()`` flood that stalled the sync loop).

These tests pin the scheduling invariant:
  1. When the frontier is NOT in the buffer, a request cycle requests it and
     routes it to a ready peer.
  2. Exactly ONE frontier getdata is sent per cycle (no fan-out / duplicate).
  3. On repeated cycles past the interval, the frontier ROTATES to a peer other
     than the previous holder.
  4. The interval throttles re-issue (no re-send before the interval elapses),
     and is strictly shorter than the general HEAD_TIMEOUT.
  5. A send failure to a marginal peer does NOT drop a validly-tracked
     in-flight entry and does NOT block (the anti-flood discipline).
"""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import (
    FRONTIER_REQUEST_INTERVAL,
    MSG_WITNESS_BLOCK,
    BlockSync,
)
from ouroboros.p2p_messages import GetDataMessage
from ouroboros.p2p_messages import NODE_WITNESS
from ouroboros.peer import Peer


def _h(tag: int) -> bytes:
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


def _make_block_sync(tip_hash: bytes, tip_height: int) -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    # No queued slot is on the active chain → every slot is head-of-window
    # eligible, and slot 0 is the connect frontier.
    db.get_block_hash_by_height.return_value = None
    pm = MagicMock()
    pm.network = "regtest"
    return BlockSync(db=db, validator=MagicMock(), peer_manager=pm)


def _make_ready_peer(host: str, score: int = 100) -> MagicMock:
    peer = MagicMock(spec=Peer)
    peer.host = host
    peer.port = 8333
    peer.score = score
    peer.is_connected.return_value = True
    # block_sync._can_serve_witness_blocks() (Core CanServeWitnesses,
    # net_processing.cpp:1168) drops non-NODE_WITNESS peers from block download.
    peer.services = NODE_WITNESS
    peer.send_message = AsyncMock()
    peer.adjust_score = MagicMock()
    return peer


def _frontier_sends(peer: MagicMock, frontier_hash: bytes) -> int:
    """Count getdata sends on *peer* whose inventory is EXACTLY the frontier."""
    n = 0
    for call in peer.send_message.await_args_list:
        netmsg = call.args[0]
        gd = GetDataMessage.from_payload(netmsg.payload)
        inv = list(gd.inventory)
        if inv == [(MSG_WITNESS_BLOCK, frontier_hash)]:
            n += 1
    return n


# ---------------------------------------------------------------------------


def test_frontier_interval_shorter_than_head_timeout_cap():
    """The frontier re-request interval MUST be shorter than the general
    HEAD_TIMEOUT (whose cap is Core's 64 s BLOCK_STALLING_TIMEOUT_MAX) so a
    fresh peer is tried long before the general head rescue would fire."""
    assert FRONTIER_REQUEST_INTERVAL < 64.0
    # And comfortably below even the small-block HEAD_TIMEOUT floor region.
    assert 0 < FRONTIER_REQUEST_INTERVAL <= 10.0


@pytest.mark.asyncio
async def test_frontier_requested_and_single_send_when_absent_from_buffer():
    """Invariant 1 + 2: with the frontier (slot 0) NOT in the buffer, a request
    cycle assigns it to a ready peer via EXACTLY ONE getdata (no fan-out)."""
    tip_hash = _h(0xDEAD)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 40)]
    bs._ibd_block_buffer = {}
    bs.requested_blocks = {}

    peers = [_make_ready_peer(f"10.0.0.{i}", score=100 - i) for i in range(4)]
    bs.peer_manager.get_all_ready_peers.return_value = peers

    await bs._request_next_blocks()

    # Frontier is now tracked in-flight to exactly one peer.
    assert frontier in bs.requested_blocks
    holder = bs._block_request_peer[frontier]
    assert holder in peers

    # Exactly ONE frontier-only getdata was sent across the WHOLE fleet
    # (the H1 priority send) — never a duplicate / fan-out.
    total_frontier_sends = sum(_frontier_sends(p, frontier) for p in peers)
    assert total_frontier_sends == 1, (
        f"expected exactly 1 frontier getdata, got {total_frontier_sends} "
        "(fan-out / duplicate send — the FIX-ATTEMPT-1 regression)"
    )
    # The priority send went to the TOP-scoring peer (score desc → peers[0]).
    assert _frontier_sends(peers[0], frontier) == 1
    assert holder is peers[0]


@pytest.mark.asyncio
async def test_frontier_rotates_to_different_peer_on_repeat():
    """Invariant 3: when the interval has elapsed and the frontier is still
    unfilled, the next cycle ROTATES it to a peer OTHER than its current holder
    so one unresponsive peer cannot hold it hostage — still a single send."""
    tip_hash = _h(0xBEEF)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 40)]
    bs._ibd_block_buffer = {}

    peers = [_make_ready_peer(f"10.0.0.{i}", score=100) for i in range(4)]
    bs.peer_manager.get_all_ready_peers.return_value = peers

    # Simulate the frontier already in flight to peers[0], requested longer
    # ago than the interval (so it is DUE for a rotation this cycle).
    import time as _time
    stale = _time.time() - (FRONTIER_REQUEST_INTERVAL + 1.0)
    bs.requested_blocks[frontier] = stale
    bs._block_request_peer[frontier] = peers[0]

    await bs._request_next_blocks()

    new_holder = bs._block_request_peer[frontier]
    assert new_holder is not peers[0], (
        "H1 regression: frontier was re-requested from its CURRENT holder — "
        "an unresponsive peer would keep the drain wedged"
    )
    assert new_holder in peers
    # Still exactly one frontier send this cycle (no fan-out on rotation).
    total = sum(_frontier_sends(p, frontier) for p in peers)
    assert total == 1


@pytest.mark.asyncio
async def test_frontier_not_reissued_before_interval_elapses():
    """Invariant 4: a frontier requested only moments ago (within the
    interval) is NOT re-issued — the interval throttles the priority send so we
    rotate on a bounded cadence, never every 1 s tick."""
    tip_hash = _h(0xCAFE)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 40)]
    bs._ibd_block_buffer = {}

    peers = [_make_ready_peer(f"10.0.0.{i}", score=100) for i in range(4)]
    bs.peer_manager.get_all_ready_peers.return_value = peers

    import time as _time
    fresh = _time.time() - (FRONTIER_REQUEST_INTERVAL / 2.0)
    bs.requested_blocks[frontier] = fresh
    bs._block_request_peer[frontier] = peers[0]

    await bs._request_next_blocks()

    # Holder unchanged and NO new frontier-only send happened.
    assert bs._block_request_peer[frontier] is peers[0]
    total = sum(_frontier_sends(p, frontier) for p in peers)
    assert total == 0, "frontier re-issued before its interval elapsed"


@pytest.mark.asyncio
async def test_frontier_skipped_when_already_in_buffer():
    """The frontier already sitting in the IBD buffer (received, awaiting
    drain) is NOT re-requested — re-fetching data we already hold is wasted
    (Core FindNextBlocks skips blocks with BLOCK_HAVE_DATA)."""
    tip_hash = _h(0xF00D)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 40)]
    # Park the buffer at buffer_target (cap_buffer == 0 → the TAIL pass is off)
    # with the frontier as one resident, so the ONLY path that could touch the
    # frontier is the H1 priority / HEAD pass — both of which must skip a
    # block already in the buffer.
    buffer_target = int(bs._max_ibd_buffer * 0.75)
    bs._ibd_block_buffer = {
        _h(10_000 + i): (None, b"resident") for i in range(buffer_target - 1)
    }
    bs._ibd_block_buffer[frontier] = (None, b"resident")  # frontier received
    assert len(bs._ibd_block_buffer) == buffer_target
    bs.requested_blocks = {}

    peers = [_make_ready_peer(f"10.0.0.{i}", score=100) for i in range(4)]
    bs.peer_manager.get_all_ready_peers.return_value = peers

    await bs._request_next_blocks()

    # No frontier-only priority send (it is already in the buffer), and the
    # buffered frontier was NOT re-requested by any path.
    total = sum(_frontier_sends(p, frontier) for p in peers)
    assert total == 0
    assert frontier not in bs.requested_blocks


@pytest.mark.asyncio
async def test_frontier_send_failure_is_nonblocking_and_preserves_inflight():
    """Invariant 5 (anti-flood): if the rotation send to a marginal peer
    raises, the cycle does NOT block and does NOT drop the frontier's existing
    valid in-flight tracking — it will time out / retry normally.  This is the
    exact discipline that keeps FIX-ATTEMPT-1's socket.send() flood from
    recurring: one exception-guarded send, no awaited drain on a stuck peer."""
    tip_hash = _h(0x1234)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 40)]
    bs._ibd_block_buffer = {}

    good = _make_ready_peer("10.0.0.0", score=50)   # current holder
    marginal = _make_ready_peer("10.0.0.1", score=100)  # top score → rotation target
    marginal.send_message = AsyncMock(side_effect=OSError("socket.send() raised"))
    peers = [marginal, good]  # marginal is top-scoring
    bs.peer_manager.get_all_ready_peers.return_value = peers

    import time as _time
    stale = _time.time() - (FRONTIER_REQUEST_INTERVAL + 1.0)
    bs.requested_blocks[frontier] = stale
    bs._block_request_peer[frontier] = good  # currently held by `good`

    # Must not raise.
    await bs._request_next_blocks()

    # Frontier tracking survives (still in-flight to its prior holder); the
    # failed rotation did not orphan it.
    assert frontier in bs.requested_blocks
    assert bs._block_request_peer[frontier] is good
    # The marginal peer was penalized, mirroring the normal-path failure path.
    marginal.adjust_score.assert_called_with(-2)
