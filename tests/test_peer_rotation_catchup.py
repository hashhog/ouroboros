"""Failing control: catch-up wedges after a long gap (peer rotation / cap).

QUEUES.md ouroboros item 0, observed live 2026-09-18 after the header-loop
fix (``982670d``).  A restart advanced ~46 blocks and re-wedged within 30
minutes:

    block requests timed out (head=7/8@37s, general=26 [W95 avg_mb=1.47],
        failed peers: 1
    Requested 32 blocks (tip+0, in-flight: 87+32/256, deferred 137
        (all peers at cap))

Seven of eight head-of-window getdatas timed out, every live peer sat at
the per-peer in-flight cap, and ZERO blocks connected.  CLAUDE.md Known
Issues since 2026-03-28: block downloads time out because the node
re-requests from a single peer instead of rotating
(``src/ouroboros/block_sync.py``).

This file is the in-repo control.  It must go red on current master and
green after the fix.  The operator-visible case is a >1000-block gap with
one peer deliberately withholding bodies.

Asks (Core ``BLOCK_STALLING_TIMEOUT`` / ``FindNextBlocksToDownload``,
``net_processing.cpp``):
  1. On a head-of-line timeout, re-request that block from a DIFFERENT
     peer and penalise the stalling one.
  2. In-flight accounting must reclaim slots for requests that already
     timed out — "all peers at cap" with 137 deferred is leaked
     accounting: deferred heads stay assigned to the staller, occupying
     its 16-slot cap, so they are never retried.
  3. After a 1001-header gap, with one of two peers withholding, the
     connect-frontier getdata must land on the serving peer once the
     withholder hits HEAD_TIMEOUT.

Ref: Bitcoin Core ``MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16``,
``BLOCK_STALLING_TIMEOUT`` (net_processing.cpp:133-135, 6093-6107),
``FindNextBlocksToDownload`` (net_processing.cpp:1394).
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

LONG_GAP = 1001  # operator-visible 8-day resume was 1171 headers
HEAD_OF_WINDOW = 8
# Size-aware HEAD_TIMEOUT = max(2, min(64, ema_mb * 25)).  Live log was
# avg_mb=1.47 → ~37 s.  Elapsed must beat that.
LIVE_EMA_MB = 1.47
STALE_S = 40.0


def _h(tag: int) -> bytes:
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


class _StubPM:
    network = "regtest"

    def __init__(self, peers):
        self._peers = list(peers)

    def get_all_ready_peers(self):
        return list(self._peers)


def _peer(host: str, score: int = 100, *, known_height: int = 100_000) -> Peer:
    p = Peer(host, 18444, network="regtest")
    p.state = PeerState.READY
    p.services = NODE_NETWORK | NODE_WITNESS
    # Must be >= the connect-frontier or `_can_serve_block_at` drops the
    # peer and `_handle_timeouts` takes the "0 available peers" branch —
    # which is a different bug and a false green for this control.
    p.start_height = known_height
    p.best_known_height = known_height
    p.score = score
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    return p


def _fresh(peers: list[Peer], tip_height: int = 10_000) -> BlockSync:
    tip = _h(-1)
    db = MagicMock()
    db.get_best_block.return_value = (tip, tip_height)
    db.get_block_hash_by_height.return_value = None
    db.has_block_hash.return_value = False
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=_StubPM(peers))
    bs._w95_block_mb_ema = LIVE_EMA_MB
    return bs


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
# 1. HOL timeout must rotate AND penalise (ASK 1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_head_timeout_rotates_off_staller_when_others_at_cap():
    """Live wedge: heads time out on one peer, every other peer is at the
    per-peer cap with far-ahead in-flight.  Pre-fix, re-request defers
    ("all peers at cap") and the heads stay assigned to the staller.

    After: each timed-out head is getdata'd from a DIFFERENT peer (evicting
    a far-ahead slot if needed) and the staller is penalised.
    """
    staller = _peer("10.0.0.1", score=100)
    others = [_peer(f"10.0.0.{i}", score=90) for i in range(2, 7)]
    bs = _fresh([staller, *others])
    queued = _queue(bs, HEAD_OF_WINDOW + 5 * MAX_BLOCKS_IN_FLIGHT_PER_PEER)
    heads = queued[:HEAD_OF_WINDOW]
    rest = queued[HEAD_OF_WINDOW:]

    _assign(bs, staller, heads, age_s=STALE_S)
    for i, p in enumerate(others):
        chunk = rest[i * MAX_BLOCKS_IN_FLIGHT_PER_PEER : (i + 1) * MAX_BLOCKS_IN_FLIGHT_PER_PEER]
        _assign(bs, p, chunk, age_s=1.0)

    assert _load(bs, staller) == HEAD_OF_WINDOW
    for p in others:
        assert _load(bs, p) == MAX_BLOCKS_IN_FLIGHT_PER_PEER

    staller_score_before = staller.score
    await bs._handle_timeouts()

    for h in heads:
        holder = bs._block_request_peer.get(h)
        assert holder is not None, (
            f"head {h[:4].hex()} dropped from in-flight instead of rotating"
        )
        assert holder is not staller, (
            "head-of-line timeout re-requested from the SAME stalling peer "
            "(CLAUDE.md peer-rotation bug). holder="
            f"{getattr(holder, 'host', holder)}"
        )
        assert h in _getdata_hashes(holder), (
            f"rotated holder {holder.host} was not sent getdata for timed-out "
            f"head {h[:4].hex()}"
        )

    assert staller.score < staller_score_before, (
        "HOL stalling peer was not penalised "
        f"(score stayed {staller.score})"
    )


# ---------------------------------------------------------------------------
# 2. Timed-out requests must free in-flight slots (ASK 2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timed_out_heads_reclaim_staller_inflight_slots():
    """Leaked accounting: deferred HOL re-requests stay in
    ``_block_request_peer`` on the staller, so the next
    ``_request_next_blocks`` sees that peer (and, with the far-ahead
    fill, every peer) at cap and defers 137 more.

    After a HOL timeout the staller's in-flight count must not still
    include those dead head requests.
    """
    staller = _peer("10.0.0.1")
    helper = _peer("10.0.0.2", score=80)
    bs = _fresh([staller, helper])
    queued = _queue(bs, HEAD_OF_WINDOW + MAX_BLOCKS_IN_FLIGHT_PER_PEER)
    heads = queued[:HEAD_OF_WINDOW]
    far = queued[HEAD_OF_WINDOW:]

    _assign(bs, staller, heads, age_s=STALE_S)
    _assign(bs, helper, far, age_s=1.0)

    await bs._handle_timeouts()

    assert _load(bs, staller) == 0, (
        f"staller still holds {_load(bs, staller)} in-flight after HOL "
        "timeout — those slots are leaked and produce 'all peers at cap'"
    )
    for h in heads:
        assert bs._block_request_peer.get(h) is not staller


@pytest.mark.asyncio
async def test_unassigned_general_timeouts_reclaim_global_inflight():
    """General (non-head) timeouts that cannot be re-sent must leave
    ``requested_blocks`` so they stop occupying the 256-slot window.

    Pre-fix they stay in the map with their original timestamp, which is
    the 87-in-flight / 137-deferred live shape.
    """
    staller = _peer("10.0.0.1")
    helper = _peer("10.0.0.2")
    bs = _fresh([staller, helper])
    # Only 2 queued heads so the rest of the timed-out hashes are GENERAL.
    queued = _queue(bs, 2)
    general = [_h(1000 + i) for i in range(MAX_BLOCKS_IN_FLIGHT_PER_PEER)]
    _assign(bs, staller, queued, age_s=1.0)  # heads, NOT timed out
    _assign(bs, staller, general, age_s=1000.0)  # well past general timeout
    _assign(
        bs,
        helper,
        [_h(2000 + i) for i in range(MAX_BLOCKS_IN_FLIGHT_PER_PEER)],
        age_s=1.0,
    )

    before = len(bs.requested_blocks)
    await bs._handle_timeouts()

    still = [h for h in general if h in bs.requested_blocks]
    # Either re-assigned to a peer with a fresh timestamp, or dropped.
    # They must not sit as deferred-on-staller occupying the cap.
    for h in still:
        assert bs._block_request_peer.get(h) is not staller, (
            "timed-out general request still assigned to the stalling peer"
        )
    assert len(bs.requested_blocks) <= before
    # The staller's dead general slots must be gone.
    for h in general:
        if h not in bs.requested_blocks:
            assert h not in bs._block_request_peer


# ---------------------------------------------------------------------------
# 3. Long-gap catch-up with one peer withholding (ASK 3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_long_gap_withholder_rotates_frontier_after_head_timeout():
    """Operator-visible control: stored tip, 1001 headers already queued
    (the 8-day gap), two peers, one of which withholds every body.

    After HEAD_TIMEOUT the connect-frontier (tip+1) must be getdata'd
    from the OTHER peer.  A restart is not a fix — the same withholder
    wins the first round-robin again unless timeout rotates.
    """
    assert LONG_GAP > 1000

    withholder = _peer("10.0.0.9", score=100)
    helper = _peer("10.0.0.8", score=50)
    bs = _fresh([withholder, helper], tip_height=10_000)
    queued = _queue(bs, LONG_GAP)
    frontier = queued[0]
    window = queued[:HEAD_OF_WINDOW]

    _assign(bs, withholder, window, age_s=STALE_S)
    # Fill the helper to cap with far-ahead of the same gap so the
    # pre-fix path cannot round-robin onto it.
    far = queued[HEAD_OF_WINDOW : HEAD_OF_WINDOW + MAX_BLOCKS_IN_FLIGHT_PER_PEER]
    _assign(bs, helper, far, age_s=1.0)

    helper.sent.clear()
    withholder.sent.clear()
    await bs._handle_timeouts()

    assert frontier in _getdata_hashes(helper), (
        "after a 1001-header gap, a HEAD_TIMEOUT on the withholding peer "
        "must re-request tip+1 from the other peer; "
        f"helper_getdata={len(_getdata_hashes(helper))} "
        f"holder={getattr(bs._block_request_peer.get(frontier), 'host', None)}"
    )
    assert bs._block_request_peer.get(frontier) is helper
    assert withholder.score < 100
