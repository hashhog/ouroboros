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
"""

from __future__ import annotations

import hashlib
import time
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

    Pre-fix, ``_request_next_blocks`` either defers tip+1 ("all peers at
    cap") or getdata's it as a 17th in-flight.  Either way the cursor
    does not get a real slot: the feeder is already at 16 and the drain
    cannot advance on the 725 far-ahead bodies.

    After: tip+1 is getdata'd AND a far-ahead slot is evicted so the
    per-peer load stays <= 16.
    """
    peer = _peer()
    bs = _fresh([peer])
    queued = _queue(bs, BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 16)
    hol = queued[0]
    # Head-of-window is slots 0..7.  Park 725 far-ahead bodies in the
    # buffer the way the live log did (slots 8..732), and fill the only
    # peer's cap with still-further-ahead in-flight (not HOL, not buffered).
    for h in queued[8 : 8 + BUFFERED_FAR_AHEAD]:
        bs._ibd_block_buffer[h] = (None, b"x")
    far_inflight = queued[
        8 + BUFFERED_FAR_AHEAD : 8 + BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER
    ]
    _assign(bs, peer, far_inflight, age_s=1.0)

    assert len(bs._ibd_block_buffer) == BUFFERED_FAR_AHEAD
    assert _load(bs, peer) == MAX_BLOCKS_IN_FLIGHT_PER_PEER
    assert hol not in bs.requested_blocks
    assert hol not in bs._ibd_block_buffer

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
    assert _load(bs, peer) <= MAX_BLOCKS_IN_FLIGHT_PER_PEER, (
        f"HOL was requested as in-flight #{_load(bs, peer)} on the only "
        f"peer (cap {MAX_BLOCKS_IN_FLIGHT_PER_PEER}); a 17th getdata is "
        "how the campaign feeder never delivered tip+1.  Evict a "
        "far-ahead slot so the cursor fits under the cap."
    )
    still_far = [h for h in far_inflight if h in bs._block_request_peer]
    assert len(still_far) < MAX_BLOCKS_IN_FLIGHT_PER_PEER, (
        "no far-ahead in-flight slot was evicted to make room for tip+1"
    )


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
# (d) RATE, not eventual completion
#
# 98ac21b evicts one far-ahead slot so HOL is requested under the cap.
# The campaign feeder (tools/blk-replay-server.py) then still serves the
# remaining far-ahead getdata FIFO before the HOL getdata — minutes of
# zero connects with 725 bodies already buffered.  Model the peer as
# delivering the oldest currently-assigned in-flight body each tick
# (the scheduler's view of what that peer is working on).  HEAD_TIMEOUT
# is 128 s and is not consulted: a timeout rescue is the stall.
# ---------------------------------------------------------------------------

TICKS = 32  # well under HEAD_TIMEOUT_MAX_WEIGHT (128 s); 1 delivery/tick
# Healthy is 1 connect per delivery.  The live defect was ~half that.
# Require 3/4 so "eventual completion after 15 far-ahead drain" stays red.
MIN_CONNECT_RATE = (TICKS * 3) // 4  # 24


def _oldest_inflight(bs: BlockSync) -> bytes | None:
    """Oldest assigned in-flight hash (timestamp, then insertion order)."""
    if not bs.requested_blocks:
        return None
    # min() is stable: equal timestamps keep dict insertion order.
    return min(bs.requested_blocks, key=bs.requested_blocks.get)


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


def _connect_frontier(bs: BlockSync, state: dict, block_hash: bytes) -> int:
    """Connect *block_hash* as tip+1 and drain any now-consecutive buffer.

    Returns how many headers were consumed (1 + drained).
    """
    n = 0
    while bs._validated_headers and (
        bs._validated_headers[0][0] == block_hash
        or bs._validated_headers[0][0] in bs._ibd_block_buffer
    ):
        h, _ = bs._validated_headers.pop(0)
        state["height"] += 1
        state["hash"] = h
        state["by_h"][state["height"]] = h
        bs._ibd_block_buffer.pop(h, None)
        bs.requested_blocks.pop(h, None)
        bs._block_request_peer.pop(h, None)
        bs._h1_last_issue.pop(h, None)
        n += 1
        block_hash = None  # only the first call may connect a just-delivered hash
    return n


@pytest.mark.asyncio
async def test_next_inflight_delivery_is_the_connect_cursor():
    """After one request cycle, the oldest in-flight body on the only
    peer must be tip+1.  Pre-fix the 16 far-ahead keep older timestamps
    so FIFO delivers them first — HOL is requested (98ac21b) but is the
    16th delivery, which is the rate bug not the hang.
    """
    peer = _peer()
    bs, _state, queued = _fresh_chain(peer, TIP_HEIGHT, BUFFERED_FAR_AHEAD + 32)
    hol = queued[0]
    far_inflight = queued[16 : 16 + MAX_BLOCKS_IN_FLIGHT_PER_PEER]
    _assign(bs, peer, far_inflight, age_s=1.0)
    assert _load(bs, peer) == MAX_BLOCKS_IN_FLIGHT_PER_PEER
    assert hol not in bs.requested_blocks

    peer.sent.clear()
    await bs._request_next_blocks()

    assert hol in bs.requested_blocks, (
        "connect cursor was not requested — 98ac21b eventual-completion "
        "path regressed"
    )
    oldest = _oldest_inflight(bs)
    assert oldest == hol, (
        "next FIFO delivery on the only peer is "
        f"{queued.index(oldest) if oldest in queued else oldest!r}, not "
        f"tip+1 (slot 0).  HOL is in-flight but behind far-ahead — that "
        f"is the halved-throughput stall (campaign 866210, buf=725, "
        f"in-flight 15+1).  load={_load(bs, peer)}"
    )


@pytest.mark.asyncio
async def test_connect_cursor_rate_when_only_peer_is_at_cap():
    """32 deliveries, one per tick, no timeout rescue.

    Empty buffer so filling a hole cannot dump 725 buffered bodies and
    masquerade as a healthy rate.  Far-ahead occupies the only peer's
    16-slot cap.  Broken scheduler: ~1 connect per 16 deliveries
    (far-ahead FIFO, then the hole).  Healthy: ~1 connect per delivery.
    """
    peer = _peer()
    n_headers = TICKS + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 16
    bs, state, queued = _fresh_chain(peer, TIP_HEIGHT, n_headers)
    far_inflight = queued[TICKS : TICKS + MAX_BLOCKS_IN_FLIGHT_PER_PEER]
    _assign(bs, peer, far_inflight, age_s=1.0)

    connects = 0
    first_connect_at = None
    longest_zero = 0
    zero_run = 0

    for tick in range(TICKS):
        await bs._request_next_blocks()
        delivered = _oldest_inflight(bs)
        n_this = 0
        if delivered is not None:
            bs.requested_blocks.pop(delivered, None)
            bs._block_request_peer.pop(delivered, None)
            bs._h1_last_issue.pop(delivered, None)
            if bs._validated_headers and bs._validated_headers[0][0] == delivered:
                n_this = _connect_frontier(bs, state, delivered)
            else:
                bs._ibd_block_buffer[delivered] = (None, b"x")
                n_this = _connect_frontier(bs, state, None)
        if n_this:
            connects += n_this
            if first_connect_at is None:
                first_connect_at = tick + 1
            zero_run = 0
        else:
            zero_run += 1
            longest_zero = max(longest_zero, zero_run)

    assert first_connect_at is not None and first_connect_at <= 2, (
        f"first connect at tick {first_connect_at} — connect cursor waited "
        f"behind far-ahead FIFO (campaign stall is minutes of zero connects "
        f"with bodies already buffered).  connects={connects}/{TICKS} "
        f"longest_zero={longest_zero}"
    )
    assert longest_zero <= 2, (
        f"longest zero-connect run is {longest_zero} ticks; the live "
        f"defect was multi-minute stalls, not a hang.  connects="
        f"{connects}/{TICKS} first={first_connect_at}"
    )
    assert connects >= MIN_CONNECT_RATE, (
        f"connect rate {connects}/{TICKS} blk/tick is the halved-"
        f"throughput defect (healthy ≈{TICKS}; 98ac21b eventual-"
        f"completion tests pass on this).  first_connect={first_connect_at} "
        f"longest_zero={longest_zero}"
    )


@pytest.mark.asyncio
async def test_campaign_buffer_shape_does_not_stall_the_cursor():
    """The 866210 shape: 725 buffered far-ahead, 16 far in-flight, HOL
    missing.  Eventual completion is free once the hole fills — those
    725 drain in one go — so total-connects is the wrong metric.  The
    next FIFO delivery after one request cycle must be tip+1, and the
    first 8 ticks must not be a zero-connect stall.
    """
    peer = _peer()
    bs, state, queued = _fresh_chain(
        peer, TIP_HEIGHT, BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER + 16
    )
    hol = queued[0]
    for h in queued[8 : 8 + BUFFERED_FAR_AHEAD]:
        bs._ibd_block_buffer[h] = (None, b"x")
    far_inflight = queued[
        8 + BUFFERED_FAR_AHEAD : 8 + BUFFERED_FAR_AHEAD + MAX_BLOCKS_IN_FLIGHT_PER_PEER
    ]
    _assign(bs, peer, far_inflight, age_s=1.0)

    await bs._request_next_blocks()
    oldest = _oldest_inflight(bs)
    assert oldest == hol, (
        "campaign shape: 725 buffered, peer at cap, next FIFO delivery "
        f"is slot {queued.index(oldest) if oldest in queued else oldest!r} "
        f"not tip+1 — HOL waits behind far-ahead (6 min of zero connects)"
    )

    connects = 0
    longest_zero = 0
    zero_run = 0
    for _tick in range(8):
        await bs._request_next_blocks()
        delivered = _oldest_inflight(bs)
        n_this = 0
        if delivered is not None:
            bs.requested_blocks.pop(delivered, None)
            bs._block_request_peer.pop(delivered, None)
            bs._h1_last_issue.pop(delivered, None)
            if bs._validated_headers and bs._validated_headers[0][0] == delivered:
                n_this = _connect_frontier(bs, state, delivered)
            else:
                bs._ibd_block_buffer[delivered] = (None, b"x")
                n_this = _connect_frontier(bs, state, None)
        if n_this:
            connects += n_this
            zero_run = 0
        else:
            zero_run += 1
            longest_zero = max(longest_zero, zero_run)

    assert longest_zero == 0, (
        f"campaign shape stalled {longest_zero} ticks before the hole "
        f"moved; live was ≥6 min of zero connects at 866210.  "
        f"connects={connects}"
    )
    assert connects >= 8, (
        f"first 8 deliveries connected {connects} blocks; healthy is 8 "
        f"(then the 725 buffered bodies drain).  longest_zero={longest_zero}"
    )
