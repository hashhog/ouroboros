"""Regression tests for the W100/W101 head-of-window buffer-admission wedge.

Background — the 946044 buffer-admission deadlock.  During IBD the
download window (``_max_blocks_in_flight = 256``) outpaced the drain, so the
IBD receive buffer (``_ibd_block_buffer``, cap ``_max_ibd_buffer = 1024``)
filled with FAR-AHEAD blocks while the one block the drain actually needs in
slot 0 — tip+1 — could not be obtained.  Two complementary fixes, both pinned
here:

W100 (REQUEST side, ``_request_next_blocks``):
    The W93 buffer throttle (``cap_buffer = buffer_target - buffer_used -
    in_flight``) reaches 0 once the buffer sits at ``buffer_target`` (768) and
    in-flight has drained to 0.  At that point NEITHER path re-requests tip+1
    (``_handle_timeouts`` only iterates ``requested_blocks``, which is empty).
    Deadlock.  The fix adds a HEAD pass that requests the head-of-window
    (first ``HEAD_OF_WINDOW`` = 8 not-yet-connected headers from tip+1) gated
    only by ``cap_inflight`` + the per-peer cap, bypassing ``cap_buffer``.
    Core-faithful: FindNextBlocks always fetches the window-head, gated only
    by in-flight count, never by a receive buffer (net_processing.cpp).

W101 (RECEIVE side, ``handle_block``):
    The old flat ``len(buffer) < _max_ibd_buffer`` admission let the 256
    in-flight far-ahead arrivals fill the buffer (768 target + 256 in-flight
    == 1024 cap exactly), leaving ZERO room to ADMIT tip+1.  The fix reserves
    ``HEAD_OF_WINDOW`` slots: a contiguous-from-tip (head-of-window) block is
    ALWAYS admittable, evicting the FARTHEST-height resident far-ahead block
    if the buffer is at the hard cap.  Never drops a head-ward block to keep a
    farther one (the W85 invariant).

Both sites share the same head_set primitive: a slot is "head-of-window" iff
``db.get_block_hash_by_height(tip+1+i)`` does NOT already equal the queued
hash (i.e. not yet on the active chain), using get_block_hash_by_height rather
than has_block_hash so rollback-orphans don't shadow the genuine head (the
938231 wedge guard).  ``HEAD_OF_WINDOW`` MUST be identical at both sites — a
divergence silently reclassifies tip+1 as far-ahead at one site and re-opens
the wedge; ``test_head_of_window_constant_matches_across_sites`` pins that.
"""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import (
    MAX_BLOCKS_IN_FLIGHT_PER_PEER,
    BlockSync,
)
from ouroboros.p2p_messages import NODE_WITNESS
from ouroboros.peer import Peer

# Must match the HEAD_OF_WINDOW literal in both _request_next_blocks and
# handle_block.  If the production constant changes, update this and the
# cross-site assertion test below together.
HEAD_OF_WINDOW = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _h(tag: int) -> bytes:
    """Deterministic distinct 32-byte hash for a slot index."""
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


def _make_block_sync(tip_hash: bytes, tip_height: int) -> BlockSync:
    """A BlockSync wired to a MagicMock db / peer_manager, with the active
    tip pinned.  ``get_block_hash_by_height`` defaults to None for every
    height (no slot is on the active chain) so the entire validated-header
    queue is treated as head-of-window-eligible unless a test overrides it."""
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    # No queued slot is already on the active chain → every slot is a
    # candidate for the head_set (bounded to HEAD_OF_WINDOW at the call site).
    db.get_block_hash_by_height.return_value = None
    pm = MagicMock()
    pm.network = "regtest"
    return BlockSync(db=db, validator=MagicMock(), peer_manager=pm)


def _make_ready_peer(host: str = "10.0.0.1", port: int = 8333) -> MagicMock:
    """A peer that passes the ``isinstance(p, Peer)`` + ``is_connected()``
    gate in _request_next_blocks and records its sent getdata payloads."""
    peer = MagicMock(spec=Peer)
    peer.host = host
    peer.port = port
    peer.score = 100
    peer.is_connected.return_value = True
    # block_sync._can_serve_witness_blocks() (Core CanServeWitnesses,
    # net_processing.cpp:1168) drops non-NODE_WITNESS peers from block download.
    peer.services = NODE_WITNESS
    peer.send_message = AsyncMock()
    peer.adjust_score = MagicMock()
    return peer


# ===========================================================================
# W100 — REQUEST side: head-of-window bypasses cap_buffer.
# ===========================================================================


@pytest.mark.asyncio
async def test_w100_tip_plus_one_requested_when_cap_buffer_zero():
    """The exact 946044 wedge on the REQUEST side.

    Buffer parked at ``buffer_target`` (768) and ``requested_blocks`` empty
    (in_flight == 0) ⇒ ``cap_buffer == 0``.  Pre-W100, the TAIL pass is the
    only requester and its budget is ``min(cap_inflight, cap_buffer) == 0``,
    so tip+1 is never requested and the drain starves forever.  Post-W100 the
    HEAD pass requests tip+1 regardless of cap_buffer.
    """
    tip_hash = _h(0xDEAD)
    tip_height = 800_000
    bs = _make_block_sync(tip_hash, tip_height)

    # Validated-header queue: slot 0 == tip+1 (the wedge block), slots 1..768
    # are far-ahead headers.  None of them is on the active chain
    # (get_block_hash_by_height → None), so head_set = first 8 slots.
    tip_plus_one = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 769)]

    # Buffer parked at buffer_target (int(1024 * 0.75) == 768) with the
    # FAR-AHEAD blocks (slots 1..768) — NOT tip+1.  tip+1 absent from the
    # buffer is the precondition that lets the HEAD pass request it (Core
    # FindNextBlocks skips data it already holds).
    buffer_target = int(bs._max_ibd_buffer * 0.75)
    assert buffer_target == 768
    bs._ibd_block_buffer = {_h(i): (None, b"x") for i in range(1, 1 + buffer_target)}
    assert len(bs._ibd_block_buffer) == buffer_target

    # in_flight == 0 ⇒ cap_buffer = max(0, 768 - 768 - 0) == 0.
    bs.requested_blocks = {}

    peer = _make_ready_peer()
    bs.peer_manager.get_all_ready_peers.return_value = [peer]

    await bs._request_next_blocks()

    # tip+1 MUST have been requested despite cap_buffer == 0.
    assert tip_plus_one in bs.requested_blocks, (
        "W100 regression: tip+1 was not requested while cap_buffer==0 — "
        "the head-of-window pass failed to bypass the W93 buffer throttle"
    )
    # And a getdata carrying tip+1 was actually dispatched to the peer.
    peer.send_message.assert_awaited()
    # The head block was routed to a real connected peer.
    assert bs._block_request_peer[tip_plus_one] is peer


@pytest.mark.asyncio
async def test_w100_far_ahead_tail_still_throttled_when_cap_buffer_zero():
    """The W85 over-fetch guard must survive W100: with cap_buffer == 0 the
    TAIL pass requests NOTHING beyond the head-of-window.  Only the (<= 8)
    head-of-window slots not already buffered/in-flight get requested."""
    tip_hash = _h(0xBEEF)
    bs = _make_block_sync(tip_hash, 800_000)

    # 100-slot queue, none buffered, none in flight, cap_buffer forced to 0
    # by parking the buffer at buffer_target with UNRELATED hashes.
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(100)]
    buffer_target = int(bs._max_ibd_buffer * 0.75)
    bs._ibd_block_buffer = {_h(10_000 + i): (None, b"x") for i in range(buffer_target)}
    bs.requested_blocks = {}

    peer = _make_ready_peer()
    bs.peer_manager.get_all_ready_peers.return_value = [peer]

    await bs._request_next_blocks()

    # Exactly the head-of-window (8) slots requested — TAIL stayed throttled.
    assert len(bs.requested_blocks) == HEAD_OF_WINDOW, (
        f"expected only the {HEAD_OF_WINDOW} head-of-window slots requested "
        f"under cap_buffer==0, got {len(bs.requested_blocks)}"
    )
    requested_slots = {bs._validated_headers[i][0] for i in range(HEAD_OF_WINDOW)}
    assert set(bs.requested_blocks) == requested_slots


@pytest.mark.asyncio
async def test_w100_head_pass_skips_slots_already_buffered_or_in_flight():
    """Core FindNextBlocks does not re-fetch data it already holds.  A
    head-of-window slot already sitting in ``_ibd_block_buffer`` (received
    out of order) or already in ``requested_blocks`` (in flight) is NOT
    re-requested; only the genuinely-missing head slots are."""
    tip_hash = _h(0xF00D)
    bs = _make_block_sync(tip_hash, 800_000)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(20)]

    # Park buffer at target with unrelated hashes (cap_buffer == 0), but also
    # mark slot 0 already buffered and slot 1 already in flight.
    buffer_target = int(bs._max_ibd_buffer * 0.75)
    bs._ibd_block_buffer = {_h(10_000 + i): (None, b"x") for i in range(buffer_target)}
    bs._ibd_block_buffer[_h(0)] = (None, b"x")  # slot 0 already received
    bs.requested_blocks = {_h(1): 1.0}  # slot 1 already in flight

    peer = _make_ready_peer()
    bs.peer_manager.get_all_ready_peers.return_value = [peer]

    await bs._request_next_blocks()

    # Slot 0 (buffered) not re-requested; slot 1 already in flight stays.
    assert _h(0) not in bs.requested_blocks or _h(0) in bs._ibd_block_buffer
    newly = set(bs.requested_blocks) - {_h(1)}
    assert _h(0) not in newly
    assert _h(1) in bs.requested_blocks  # pre-existing in-flight untouched
    # The remaining head-of-window slots (2..) up to HEAD_OF_WINDOW distinct
    # head members are what got newly requested.
    assert newly  # something WAS requested (the wedge is broken)


# ===========================================================================
# W101 — RECEIVE side: head-reserving admission evicts the farthest resident.
# ===========================================================================


def _seed_far_ahead_buffer(bs: BlockSync, tip_height: int, count: int):
    """Build a validated-header queue with slot 0 == tip+1 (absent from the
    buffer) and slots 1..count far-ahead headers ALL resident in the buffer.

    Far-ahead residents are seeded directly into ``_ibd_block_buffer`` (they
    do not go through the admission gate), modelling the 256 in-flight
    arrivals that filled the buffer.  Returns ``(tip_plus_one_hash,
    farthest_hash)``.
    """
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, count + 1)]
    tip_plus_one = _h(0)
    # Residents = slots 1..count (tip+1 deliberately absent).
    bs._ibd_block_buffer = {_h(i): (None, b"resident") for i in range(1, count + 1)}
    farthest = _h(count)  # largest slot index == farthest height above tip
    return tip_plus_one, farthest


def _deliver(bs: BlockSync, block_hash: bytes, payload: bytes, peer):
    """Wrap a raw 80+ byte payload whose double-SHA256(header) == block_hash.

    handle_block hashes ``payload[:80]`` to identify the block, so we cannot
    use an arbitrary hash AND arbitrary bytes.  Instead we let the caller pin
    the buffer key by pre-inserting into ``requested_blocks`` and asserting on
    the COMPUTED hash.  This helper returns the computed hash for the payload.
    """
    msg = MagicMock()
    msg.payload = payload
    return msg


@pytest.mark.asyncio
async def test_w101_tip_plus_one_admitted_at_hard_cap_evicting_farthest(monkeypatch):
    """The exact 946044 wedge on the RECEIVE side.

    Buffer is at the HARD cap (``_max_ibd_buffer`` == 1024) full of far-ahead
    residents; tip+1 is absent.  A solicited tip+1 delivery must be ADMITTED
    by evicting the FARTHEST-height resident — pre-W101's flat
    ``len < _max_ibd_buffer`` cap would have dropped tip+1 on the floor and
    the drain would starve forever.
    """
    tip_height = 800_000
    # tip+1's hash is the double-SHA256 of an 80-byte header we control.
    header = b"\x11" * 80
    tip_plus_one = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    payload = header + b"\x00" * 200  # > 80 bytes; body is irrelevant here

    bs = _make_block_sync(_h(0xCAFE), tip_height)

    # Hard-cap buffer: 1024 far-ahead residents, slots 1..1024.  Slot 0 is
    # tip+1 (the real computed hash), deliberately absent from the buffer.
    cap = bs._max_ibd_buffer
    assert cap == 1024
    bs._validated_headers = [(tip_plus_one, MagicMock())] + [
        (_h(i), MagicMock()) for i in range(1, cap + 1)
    ]
    bs._ibd_block_buffer = {_h(i): (None, b"resident") for i in range(1, cap + 1)}
    assert len(bs._ibd_block_buffer) == cap
    farthest = _h(cap)  # slot `cap` == farthest height above tip

    # Solicited: was_requested True ⇒ bypasses the fTooFarAhead drop and the
    # has_block_hash duplicate guard, and clears from requested_blocks.
    bs.requested_blocks[tip_plus_one] = 1.0
    bs.db.has_block_hash.return_value = False

    # Isolate the admission decision: stub the drain so the test pins ONLY
    # the W101 buffer logic, not the (heavy) connect pipeline.
    drain = AsyncMock(return_value=0)
    monkeypatch.setattr(bs, "_drain_block_buffer", drain)

    peer = _make_ready_peer()
    msg = MagicMock()
    msg.payload = payload

    await bs.handle_block(msg, peer)

    # tip+1 ADMITTED into the buffer ...
    assert tip_plus_one in bs._ibd_block_buffer, (
        "W101 regression: tip+1 was dropped at the hard cap instead of "
        "evicting a far-ahead resident — the buffer-admission deadlock"
    )
    # ... the FARTHEST-height resident was evicted to make room ...
    assert farthest not in bs._ibd_block_buffer, (
        "W101 regression: tip+1 admitted but the farthest far-ahead resident "
        "was not the one evicted"
    )
    # ... the buffer stayed bounded at the hard cap (1 in, 1 out) ...
    assert len(bs._ibd_block_buffer) == cap
    # ... the eviction-drop was counted, in-flight was cleared, and the drain
    # was invoked so the freshly-admitted slot 0 can connect.
    assert bs._blk_buffer_full == 1
    assert tip_plus_one not in bs.requested_blocks
    drain.assert_awaited()


@pytest.mark.asyncio
async def test_w101_admitting_tip_plus_one_lets_drain_advance(monkeypatch):
    """End-to-end intent: admission is only useful if the drain can then
    consume slot 0.  After W101 admits tip+1 at the hard cap, the drain's
    slot-0 precondition (``_validated_headers[0][0] in _ibd_block_buffer``)
    holds, so a connect-modelling drain advances by one block.

    We model "connect" with a lightweight stub that pops slot 0 if present
    (mirroring _drain_block_buffer_locked's ``next_hash not in buffer → break``
    gate) so the test stays pure-Python and never touches deserialisation /
    validation / DB mutation.  Pre-W101 the stub would find slot 0 ABSENT and
    return 0 (no progress) — the wedge.
    """
    tip_height = 800_000
    header = b"\x22" * 80
    tip_plus_one = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    payload = header + b"\x00" * 200

    bs = _make_block_sync(_h(0x1234), tip_height)
    cap = bs._max_ibd_buffer
    bs._validated_headers = [(tip_plus_one, MagicMock())] + [
        (_h(i), MagicMock()) for i in range(1, cap + 1)
    ]
    bs._ibd_block_buffer = {_h(i): (None, b"resident") for i in range(1, cap + 1)}
    bs.requested_blocks[tip_plus_one] = 1.0
    bs.db.has_block_hash.return_value = False

    advanced = {"n": 0}

    async def _drain_stub() -> int:
        # Faithful to _drain_block_buffer_locked's slot-0 gate: only advance
        # if the next expected block (slot 0) is actually in the buffer.
        slot0 = bs._validated_headers[0][0]
        if slot0 in bs._ibd_block_buffer:
            bs._ibd_block_buffer.pop(slot0)
            advanced["n"] += 1
            return 1
        return 0

    monkeypatch.setattr(bs, "_drain_block_buffer", _drain_stub)

    peer = _make_ready_peer()
    msg = MagicMock()
    msg.payload = payload

    await bs.handle_block(msg, peer)

    assert advanced["n"] == 1, (
        "W101 regression: tip+1 was not admitted, so the drain found slot 0 "
        "absent and made no progress (the 946044 deadlock)"
    )


@pytest.mark.asyncio
async def test_w101_admits_into_reserved_slot_below_hard_cap(monkeypatch):
    """When the buffer is in the reserved band (>= cap - HEAD_OF_WINDOW) but
    below the hard cap, a head-of-window block uses a reserved slot directly —
    no eviction needed, buffer simply grows by one."""
    tip_height = 800_000
    header = b"\x33" * 80
    tip_plus_one = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    payload = header + b"\x00" * 200

    bs = _make_block_sync(_h(0x9999), tip_height)
    cap = bs._max_ibd_buffer
    # Buffer at cap - 4: inside the reserved band (cap - 8) .. cap, below cap.
    resident_count = cap - 4
    bs._validated_headers = [(tip_plus_one, MagicMock())] + [
        (_h(i), MagicMock()) for i in range(1, resident_count + 1)
    ]
    bs._ibd_block_buffer = {
        _h(i): (None, b"resident") for i in range(1, resident_count + 1)
    }
    assert len(bs._ibd_block_buffer) == resident_count
    bs.requested_blocks[tip_plus_one] = 1.0
    bs.db.has_block_hash.return_value = False
    monkeypatch.setattr(bs, "_drain_block_buffer", AsyncMock(return_value=0))

    peer = _make_ready_peer()
    msg = MagicMock()
    msg.payload = payload

    await bs.handle_block(msg, peer)

    assert tip_plus_one in bs._ibd_block_buffer
    # Grew by one (reserved slot used) — nothing evicted.
    assert len(bs._ibd_block_buffer) == resident_count + 1
    assert bs._blk_buffer_full == 0


@pytest.mark.asyncio
async def test_w101_far_ahead_dropped_in_reserved_band(monkeypatch):
    """The complement: while in the reserved band, a NON-head (far-ahead)
    solicited block is dropped (it is re-requestable via the TAIL pass and is
    not what the drain is waiting for).  Asserts the reserve is for the head
    only, not a general overflow allowance."""
    tip_height = 800_000
    header = b"\x44" * 80
    far_ahead_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    payload = header + b"\x00" * 200

    bs = _make_block_sync(_h(0x7777), tip_height)
    cap = bs._max_ibd_buffer
    resident_count = cap - 4  # reserved band, below hard cap

    # Put the delivered hash at a FAR slot (so it is NOT in the head_set of
    # the first 8 unconnected slots).  Slots 0..7 are the head-of-window.
    far_slot = 500
    headers = [(_h(i), MagicMock()) for i in range(0, resident_count + 1)]
    headers[far_slot] = (far_ahead_hash, MagicMock())
    bs._validated_headers = headers
    # Residents: every slot 0..resident_count EXCEPT the far one we're about
    # to deliver, so the buffer is in the reserved band and far_ahead absent.
    bs._ibd_block_buffer = {
        _h(i): (None, b"resident")
        for i in range(0, resident_count + 1)
        if i != far_slot
    }
    bs.requested_blocks[far_ahead_hash] = 1.0
    bs.db.has_block_hash.return_value = False
    before = len(bs._ibd_block_buffer)
    monkeypatch.setattr(bs, "_drain_block_buffer", AsyncMock(return_value=0))

    peer = _make_ready_peer()
    msg = MagicMock()
    msg.payload = payload

    await bs.handle_block(msg, peer)

    # Far-ahead block in the reserved band was dropped, not admitted.
    assert far_ahead_hash not in bs._ibd_block_buffer
    assert len(bs._ibd_block_buffer) == before
    assert bs._blk_buffer_full == 1


# ===========================================================================
# Cross-site invariant: HEAD_OF_WINDOW must be identical at both sites.
# ===========================================================================


def test_head_of_window_constant_matches_across_sites():
    """W100 (_request_next_blocks) and W101 (handle_block) BOTH hardcode
    ``HEAD_OF_WINDOW = 8``.  A divergence silently reclassifies tip+1 as
    far-ahead at one site and re-opens the wedge.  Pin the literal by reading
    it out of the function source so a future edit to either site fails here.
    """
    import inspect

    req_src = inspect.getsource(BlockSync._request_next_blocks)
    hb_src = inspect.getsource(BlockSync.handle_block)
    assert "HEAD_OF_WINDOW = 8" in req_src, (
        "_request_next_blocks no longer pins HEAD_OF_WINDOW = 8"
    )
    assert "HEAD_OF_WINDOW = 8" in hb_src, (
        "handle_block no longer pins HEAD_OF_WINDOW = 8"
    )
    assert HEAD_OF_WINDOW == 8


def test_core_per_peer_cap_value():
    """Sanity anchor shared with test_block_request_distribution: the
    per-peer in-flight cap matches Core's MAX_BLOCKS_IN_FLIGHT_PER_PEER."""
    assert MAX_BLOCKS_IN_FLIGHT_PER_PEER == 16
