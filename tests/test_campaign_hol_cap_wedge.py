"""Failing control: campaign HOL-cap blocking halves connect rate.

QUEUES.md ouroboros item 0 (2026-09-18, amended 11:50Z).  A controlled
one-peer replay rig (range 852000→875000) logged:

    Requested 1 blocks (tip+0, in-flight: 15+1/256, deferred 28
        (all peers at cap) [W93 throttle: buf=725+inflight=1]

for ≥6 minutes of ZERO connects while holding 725 already-downloaded
bodies.  It then resumed unaided at ≈36 blk/min.  Lifetime average on
that range was 19.5 blk/min — the defect costs roughly half the
throughput through intermittent multi-minute stalls; it is not a
terminal wedge.

``98ac21b`` made the connect cursor getdata under the per-peer cap
(eventual completion).  That is not enough: evicting ONE far-ahead
slot leaves tip+1 behind the remaining 15 in-flight bodies.  A local
replay feeder serves getdata FIFO, so HOL waits for those 15 (minutes
at mainnet size) — which is exactly the halved-rate signature.  A
test that only checks "did HOL get requested / did it eventually
finish" passes on that code.

Asks (blockbrew ``09695ad`` / Core ``FindNextBlocksToDownload``):
  (a) Never let one peer's in-flight cap block the connect cursor —
      when tip+1 would be deferred because the only peer is at cap,
      evict far-ahead in-flight so HOL is the next body that peer
      delivers, not the 16th.
  (b) Size the HOL timeout for a real body at a real byte rate.
  (c) Do not treat a request that is still legitimately in flight as
      a stall.
  (d) Assert a RATE, not just eventual completion.

Receipt: ``receipts/ouroboros-campaign-wedge-866210-2026-09-18.md``.

Correction (2026-09-26): ask (a) as implemented by ``98ac21b`` /
``7e55946`` -- "evict far-ahead in-flight so HOL is the next body" --
is impossible on a real wire.  A getdata cannot be withdrawn: the peer
serves every body it was asked for, in order.  "Evicting" only removed
the hashes from ``requested_blocks``, so the tail pass re-getdata'd them
on the next ``_request_next_blocks`` (which runs on every delivery).
R4 slices: the replay feeder served 131,859 blocks for 10,706 connected
(632k) and 31,889 for 1,069 (650k).  The old rate tests modelled the
peer as serving "the oldest block we still track", which is exactly the
fiction that made eviction look effective.  The tests below model the
peer as a FIFO of every getdata sent, and assert Core's invariant: a
block that is in flight or held is never requested again
(net_processing.cpp FindNextBlocksToDownload; re-request only after a
stall timeout).
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import (
    MAX_BLOCKS_IN_FLIGHT_PER_PEER,
    BlockSync,
)
from ouroboros.p2p_messages import NODE_NETWORK, NODE_WITNESS, GetDataMessage
from ouroboros.peer import Peer, PeerState

# blockbrew 09695ad live soak: block 967495 / 967513-967519.
NEAR_MAX_BODY_BYTES = 1_539_532
MIN_LIVE_BLOCK_THROUGHPUT = 32 * 1024  # bytes/s
NEAR_MAX_FETCH_S = NEAR_MAX_BODY_BYTES / MIN_LIVE_BLOCK_THROUGHPUT  # ≈47.0
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MAX_WEIGHT_FETCH_S = MAX_BLOCK_SERIALIZED_SIZE / MIN_LIVE_BLOCK_THROUGHPUT  # ≈122
BUFFERED_FAR_AHEAD = 725  # live W93 log
TIP_HEIGHT = 866_210


def _h(tag: int) -> bytes:
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


class _StubPM:
    network = "regtest"

    def __init__(self, peers):
        self._peers = list(peers)

    def get_all_ready_peers(self):
        return list(self._peers)


def _peer(host: str = "127.0.0.1", *, known_height: int = 875_000) -> Peer:
    p = Peer(host, 18444, network="regtest")
    p.state = PeerState.READY
    p.services = NODE_NETWORK | NODE_WITNESS
    p.start_height = known_height
    p.best_known_height = known_height
    p.score = 100
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    return p


def _fresh(peers: list[Peer], tip_height: int = TIP_HEIGHT) -> BlockSync:
    tip = _h(-1)
    db = MagicMock()
    db.get_best_block.return_value = (tip, tip_height)
    db.get_block_hash_by_height.return_value = None
    db.has_block_hash.return_value = False
    return BlockSync(db=db, validator=MagicMock(), peer_manager=_StubPM(peers))


def _getdata_hashes(peer: Peer) -> list[bytes]:
    out = []
    for m in peer.sent:
        if getattr(m, "command", None) != "getdata":
            continue
        gd = GetDataMessage.from_payload(m.payload)
        out.extend(h for _t, h in gd.inventory)
    return out


def _load(bs: BlockSync, peer: Peer) -> int:
    return sum(1 for p in bs._block_request_peer.values() if p is peer)


def _queue(bs: BlockSync, n: int) -> list[bytes]:
    hashes = [_h(i) for i in range(n)]
    bs._validated_headers = [(h, MagicMock()) for h in hashes]
    return hashes


def _assign(bs: BlockSync, peer: Peer, hashes: list[bytes], *, age_s: float) -> None:
    now = time.time()
    for h in hashes:
        bs.requested_blocks[h] = now - age_s
        bs._block_request_peer[h] = peer
        bs._record_first_request_time(h, now - age_s)


# ---------------------------------------------------------------------------
# (a) one peer at cap must not defer the connect cursor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_peer_at_cap_still_requests_connect_cursor():
    """Live campaign wedge: one replay peer, 16 far-ahead in-flight, 725
    buffered, connect cursor (tip+1) not in-flight.

    The connect cursor must be getdata'd (not deferred as "all peers at
    cap"), and NOTHING already in flight may be dropped from tracking:
    those 16 bodies are on the wire and will arrive regardless, so
    forgetting them only makes the tail pass request them a second time.
    tip+1 takes at most one slot above the cap.
    """
    peer = _peer()
    bs = _fresh([peer])
    queued = _queue(bs, BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 16)
    hol = queued[0]
    for h in queued[8 : 8 + BUFFERED_FAR_AHEAD]:
        bs._ibd_block_buffer[h] = (None, b"x")
    far_inflight = queued[
        8 + BUFFERED_FAR_AHEAD : 8 + BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER
    ]
    _assign(bs, peer, far_inflight, age_s=1.0)

    assert _load(bs, peer) == MAX_BLOCKS_IN_FLIGHT_PER_PEER
    assert hol not in bs.requested_blocks

    peer.sent.clear()
    await bs._request_next_blocks()

    assert hol in bs.requested_blocks, (
        "connect cursor (tip+1) was not requested while the only peer "
        "sat at the in-flight cap — campaign wedge 866210 "
        "('deferred (all peers at cap)', buf=725)"
    )
    assert hol in _getdata_hashes(peer), (
        "connect cursor was tracked in-flight but no getdata went out"
    )
    assert bs._block_request_peer.get(hol) is peer
    assert _load(bs, peer) <= MAX_BLOCKS_IN_FLIGHT_PER_PEER + 1
    dropped = [h for h in far_inflight if h not in bs._block_request_peer]
    assert not dropped, (
        f"{len(dropped)} far-ahead in-flight request(s) were dropped from "
        "tracking while their getdata is still on the wire — the next "
        "request cycle re-getdatas them (the R4 12-30x re-download)"
    )
    again = [h for h in _getdata_hashes(peer) if h in far_inflight]
    assert not again, f"re-getdata'd {len(again)} in-flight far-ahead bodies"


# ---------------------------------------------------------------------------
# (b) HOL timeout sized for a real body at 32 KiB/s
# ---------------------------------------------------------------------------


def test_head_timeout_covers_near_max_body_at_32kib():
    """1.54 MB at 32 KiB/s takes ~47 s.  Pre-fix HEAD_TIMEOUT is
    ``max(2, min(64, ema*25))`` → 38.5 s at ema=1.54, which aborts a
    healthy fetch (blockbrew 09695ad soak: p90 38.1 s / worst 56.0 s).
    """
    bs = _fresh([_peer()])
    timeout = bs._compute_head_timeout(NEAR_MAX_BODY_BYTES / (1024.0 * 1024.0))
    assert timeout > NEAR_MAX_FETCH_S, (
        f"HEAD_TIMEOUT {timeout:.1f}s does not cover a {NEAR_MAX_BODY_BYTES}-byte "
        f"body at {MIN_LIVE_BLOCK_THROUGHPUT} B/s ({NEAR_MAX_FETCH_S:.1f}s) — "
        "the timeout is the bug, not the peer"
    )
    max_weight = bs._compute_head_timeout(MAX_BLOCK_SERIALIZED_SIZE / (1024.0 * 1024.0))
    assert max_weight >= MAX_WEIGHT_FETCH_S, (
        f"HEAD_TIMEOUT {max_weight:.1f}s does not cover a 4 MiB body at "
        f"32 KiB/s ({MAX_WEIGHT_FETCH_S:.1f}s); blockbrew BaseStallTimeout "
        "is 128 s, Core BLOCK_DOWNLOAD_TIMEOUT_BASE is 600 s"
    )


# ---------------------------------------------------------------------------
# (c) in-flight HOL inside that budget is not a stall
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inflight_hol_inside_realistic_fetch_is_not_stalled():
    """A HOL body that has been in-flight for the 47 s a 1.54 MB transfer
    takes at 32 KiB/s is still arriving.  ``_handle_timeouts`` must leave
    it on the same peer with the original timestamp — not reclaim and
    re-getdata (the 967495 abort: in-flight reset every tick, retries=0).
    """
    peer = _peer()
    bs = _fresh([peer])
    bs._w95_block_mb_ema = NEAR_MAX_BODY_BYTES / (1024.0 * 1024.0)
    queued = _queue(bs, 40)
    hol = queued[0]
    _assign(bs, peer, [hol], age_s=NEAR_MAX_FETCH_S)
    orig_t = bs.requested_blocks[hol]
    peer.sent.clear()

    await bs._handle_timeouts()

    assert hol in bs.requested_blocks, (
        "HOL download was dropped mid-fetch "
        f"(elapsed={NEAR_MAX_FETCH_S:.1f}s at ema={bs._w95_block_mb_ema:.2f} MB)"
    )
    assert bs._block_request_peer.get(hol) is peer
    assert bs.requested_blocks[hol] == orig_t, (
        "HOL in-flight timestamp was reset — treated a still-arriving body "
        f"as a stall (elapsed={NEAR_MAX_FETCH_S:.1f}s, "
        "blockbrew 09695ad: 1.54 MB @ 32 KiB/s)"
    )
    assert hol not in _getdata_hashes(peer), (
        "re-getdata of a live in-flight HOL — do not treat a request that "
        "is still legitimately in flight as a stall"
    )


# ---------------------------------------------------------------------------
# (d) RATE and REDUNDANCY on a truthful FIFO wire
#
# The peer model is the campaign feeder (tools/blk-replay-server.py): it
# serves every getdata it has received, in order, one body per tick,
# including requests we have since stopped tracking.  After each
# delivery the harness does what handle_block does -- pop the request
# maps, buffer or connect, then run _request_next_blocks.
# ---------------------------------------------------------------------------


def _fresh_chain(peer: Peer, tip_height: int, n_headers: int):
    """BlockSync whose tip/height mocks can advance as the test connects."""
    state = {
        "hash": _h(-1),
        "height": tip_height,
        "by_h": {},
    }
    db = MagicMock()
    db.get_best_block.side_effect = lambda: (state["hash"], state["height"])
    db.get_block_hash_by_height.side_effect = lambda h: state["by_h"].get(h)
    db.has_block_hash.return_value = False
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=_StubPM([peer]))
    hashes = _queue(bs, n_headers)
    return bs, state, hashes


def _drain(bs: BlockSync, state: dict) -> int:
    """Connect tip+1 while it is buffered (the in-order drain)."""
    n = 0
    while bs._validated_headers and bs._validated_headers[0][0] in bs._ibd_block_buffer:
        h, _ = bs._validated_headers.pop(0)
        state["height"] += 1
        state["hash"] = h
        state["by_h"][state["height"]] = h
        bs._ibd_block_buffer.pop(h, None)
        n += 1
    return n


class _FifoWire:
    """Every getdata the node ever sent, served strictly in order."""

    def __init__(self, peer: Peer, preloaded: list[bytes]):
        self.peer = peer
        self.queue: list[bytes] = list(preloaded)
        self.requested_total = list(preloaded)
        self._seen_msgs = 0

    def pull(self) -> None:
        new = self.peer.sent[self._seen_msgs:]
        self._seen_msgs = len(self.peer.sent)
        for m in new:
            if getattr(m, "command", None) != "getdata":
                continue
            for _t, h in GetDataMessage.from_payload(m.payload).inventory:
                self.queue.append(h)
                self.requested_total.append(h)

    def deliver(self) -> bytes | None:
        self.pull()
        return self.queue.pop(0) if self.queue else None


async def _run_fifo(bs, state, wire, ticks):
    served = 0
    connects = 0
    first_connect_at = None
    for tick in range(ticks):
        h = wire.deliver()
        if h is None:
            await bs._request_next_blocks()
            continue
        served += 1
        # handle_block: pop request maps, buffer (a delivery we already
        # hold or have connected is simply discarded), drain, refill.
        bs.requested_blocks.pop(h, None)
        bs._block_request_peer.pop(h, None)
        bs._h1_last_issue.pop(h, None)
        if any(h == q for q, _ in bs._validated_headers):
            bs._ibd_block_buffer[h] = (None, b"x")
        n = _drain(bs, state)
        if n and first_connect_at is None:
            first_connect_at = tick + 1
        connects += n
        await bs._request_next_blocks()
    wire.pull()
    return served, connects, first_connect_at


@pytest.mark.asyncio
async def test_fifo_feeder_never_serves_a_block_twice():
    """R4 slice shape: one FIFO feeder, window already full of far-ahead,
    HOL missing.  Every hash may be getdata'd at most once, and the feeder
    must not serve materially more bodies than the node connects.

    538c517 (evict-all-far-ahead): every delivery evicted the peer's
    in-flight far-ahead and the tail pass re-requested them -- ~15
    duplicate getdata per delivery.
    """
    peer = _peer()
    n_headers = 400
    bs, state, queued = _fresh_chain(peer, TIP_HEIGHT, n_headers)
    far_inflight = queued[64 : 64 + MAX_BLOCKS_IN_FLIGHT_PER_PEER]
    _assign(bs, peer, far_inflight, age_s=1.0)
    wire = _FifoWire(peer, far_inflight)

    served, connects, first = await _run_fifo(bs, state, wire, 300)

    counts = Counter(wire.requested_total)
    dups = {h: c for h, c in counts.items() if c > 1}
    assert not dups, (
        f"{len(dups)} hashes getdata'd more than once (worst "
        f"{max(dups.values())}x); served={served} connected={connects}.  "
        "An in-flight block was re-requested without a stall timeout."
    )
    assert connects >= 250, (
        f"only {connects} connects for {served} deliveries (first at "
        f"tick {first}) — the connect cursor is starved"
    )
    assert served <= connects + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 8, (
        f"served {served} bodies for {connects} connected"
    )


@pytest.mark.asyncio
async def test_connect_cursor_rate_when_only_peer_is_at_cap():
    """16 far-ahead already on the wire, HOL missing, empty buffer.

    On a FIFO wire those 16 bodies arrive first no matter what the node
    does; the most a scheduler can do is ask for tip+1 immediately and
    keep the window in order afterwards.  Require: tip+1 requested in the
    first cycle, first connect no later than the 17th delivery, then about
    one connect per delivery, and no duplicate getdata.
    """
    peer = _peer()
    ticks = 96
    n_headers = ticks + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 64
    bs, state, queued = _fresh_chain(peer, TIP_HEIGHT, n_headers)
    far_inflight = queued[32 : 32 + MAX_BLOCKS_IN_FLIGHT_PER_PEER]
    _assign(bs, peer, far_inflight, age_s=1.0)
    wire = _FifoWire(peer, far_inflight)

    await bs._request_next_blocks()
    assert queued[0] in bs.requested_blocks, "tip+1 not requested at cap"

    served, connects, first = await _run_fifo(bs, state, wire, ticks)
    assert first is not None and first <= MAX_BLOCKS_IN_FLIGHT_PER_PEER + 1, (
        f"first connect at delivery {first}; tip+1 should be right behind "
        "the bodies that were already on the wire"
    )
    assert connects >= ticks - MAX_BLOCKS_IN_FLIGHT_PER_PEER - 8, (
        f"connects={connects}/{ticks} deliveries (first={first})"
    )
    dups = [h for h, c in Counter(wire.requested_total).items() if c > 1]
    assert not dups, f"{len(dups)} duplicate getdata"


@pytest.mark.asyncio
async def test_campaign_buffer_shape_does_not_stall_the_cursor():
    """The 866210 shape: 725 buffered far-ahead, 16 far in-flight, HOL
    missing.  tip+1 is requested in the first cycle; once the bodies
    already on the wire are through, the hole fills and the 725 buffered
    bodies drain.  No block is requested twice.
    """
    peer = _peer()
    bs, state, queued = _fresh_chain(
        peer, TIP_HEIGHT, BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 64
    )
    hol = queued[0]
    for h in queued[8 : 8 + BUFFERED_FAR_AHEAD]:
        bs._ibd_block_buffer[h] = (None, b"x")
    far_inflight = queued[
        8 + BUFFERED_FAR_AHEAD : 8 + BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER
    ]
    _assign(bs, peer, far_inflight, age_s=1.0)
    wire = _FifoWire(peer, far_inflight)

    await bs._request_next_blocks()
    assert hol in bs.requested_blocks, "tip+1 deferred in the campaign shape"

    served, connects, first = await _run_fifo(
        bs, state, wire, MAX_BLOCKS_IN_FLIGHT_PER_PEER + 16
    )
    assert connects >= BUFFERED_FAR_AHEAD, (
        f"hole never filled: connects={connects} served={served} first={first}"
    )
    dups = [h for h, c in Counter(wire.requested_total).items() if c > 1]
    assert not dups, f"{len(dups)} duplicate getdata in the campaign shape"
