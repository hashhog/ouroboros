"""Failing control: campaign range 852000→875000 wedged at 866210.

QUEUES.md ouroboros item 0 (2026-09-18).  A controlled one-peer replay
rig ran 12h40m and froze at connect height 866210 of 875000.  Sampled
three times over six minutes with zero blocks connected.  It was not
idle:

    Requested 1 blocks (tip+0, in-flight: 15+1/256, deferred 28
        (all peers at cap) [W93 throttle: buf=725+inflight=1]

725 bodies sat in the IBD buffer.  The drain can only advance on the
connect cursor (slot 0 of ``_validated_headers`` == tip+1).  That one
block was either never getdata'd or was aborted while still arriving,
because the only peer was at ``MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16``
with far-ahead in-flight.

``tests/test_peer_rotation_catchup.py`` (``83ebe6b``) does not cover
this: every case has a second peer to rotate onto, and every peer
answers.  The campaign rig has exactly one peer, which is why it
wedges.

Asks (blockbrew ``09695ad`` / Core ``FindNextBlocksToDownload``):
  (a) Never let one peer's in-flight cap block the connect cursor —
      when tip+1 would be deferred because the only peer is at cap,
      evict a far-ahead slot (or grant HOL one slot above the cap)
      so the getdata actually goes out under the cap.
  (b) Size the HOL timeout for a real body at a real byte rate.
      1.54 MB at 32 KiB/s = 47 s; the old ``ema*25`` budget is ~37 s
      at 1.47 MB and aborts a healthy fetch.  4 MiB at 32 KiB/s = 128 s
      (blockbrew ``BaseStallTimeout``).  Core's
      ``BLOCK_DOWNLOAD_TIMEOUT_BASE`` is 600 s.
  (c) Do not treat a request that is still legitimately in flight as
      a stall — a HOL body that has been in-flight for the 47 s a
      1.54 MB transfer takes at 32 KiB/s must not be reclaimed.

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
