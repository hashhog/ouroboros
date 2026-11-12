"""Unrequested ``block`` bodies whose header is not queued are never buffered.

Finding (cffix-ouroboros-unknown-header-body-buffered, 2026-11-09 security
audit): ``handle_block`` applied its fTooFarAhead gate only when the body's
header sat in ``_validated_headers``.  An unrequested body with an unknown
header skipped every check and went straight into ``_ibd_block_buffer``: no
PoW, prev or work check, no penalty.  One peer could hold ~1016 x 4 MB there
until the 600 s orphan sweep, and the full buffer then crowded out the IBD
bodies the drain actually needs.

Core runs ``AcceptBlockHeader`` before it keeps any body
(``validation.cpp`` ``ChainstateManager::AcceptBlock``): an unknown prev is
``prev-blk-not-found`` (BLOCK_MISSING_PREV), which ``MaybePunishNodeForBlock``
answers with Misbehaving; an unrequested body is kept only with
fHasMoreOrSameWork and not fTooFarAhead.

These tests pin: (1) 1100 unrequested random-header bodies from one peer leave
the buffer empty and score that peer; (2) an unrequested body whose prev IS
known is dropped without a penalty; (3) a requested body with an unqueued
header is still buffered; (4) an unrequested body whose header IS queued is
still buffered (the existing path).
"""

from __future__ import annotations

import hashlib
import os
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import BlockSync

TIP_HASH = b"\x11" * 32
TIP_HEIGHT = 800_000


class _StubPeer:
    def __init__(self, host: str = "203.0.113.7", port: int = 8333):
        self.host = host
        self.port = port
        self.inbound = True
        self.score = 100
        self.score_deltas: list[int] = []
        self.synced: list[int] = []

    def adjust_score(self, delta: int) -> None:
        self.score_deltas.append(delta)
        self.score = max(0, min(100, self.score + delta))

    def update_synced_blocks(self, height: int) -> None:
        self.synced.append(height)

    def note_block_height(self, height: int) -> None:
        self.synced.append(height)


class _Msg:
    def __init__(self, payload: bytes):
        self.payload = payload


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (TIP_HASH, TIP_HEIGHT)
    db.has_block_hash.return_value = False
    db.get_block_index_entry.return_value = None
    db.get_block_hash_by_height.return_value = None
    pm = MagicMock()
    pm.misbehaving = MagicMock(return_value=False)
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    # Isolate admission: the drain / refill are not under test here.
    bs._drain_block_buffer = AsyncMock(return_value=0)
    bs._request_next_blocks = AsyncMock(return_value=None)
    return bs


def _header(prev: bytes) -> bytes:
    return (
        struct.pack("<I", 0x20000000)
        + prev
        + os.urandom(32)  # merkle root
        + struct.pack("<III", 1_700_000_000, 0x1D00FFFF, 0)
    )


def _block_hash(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload[:80]).digest()).digest()


def _payload(prev: bytes, body_len: int = 1024) -> bytes:
    return _header(prev) + os.urandom(body_len)


def _prev_not_found_calls(bs: BlockSync) -> list:
    return [
        c for c in bs.peer_manager.misbehaving.call_args_list
        if "prev-blk-not-found" in str(c)
    ]


@pytest.mark.asyncio
async def test_unrequested_random_header_bodies_are_not_buffered_and_peer_is_penalised():
    bs = _make_block_sync()
    peer = _StubPeer()
    for _ in range(1100):
        await bs.handle_block(_Msg(_payload(os.urandom(32))), peer)

    assert len(bs._ibd_block_buffer) == 0
    assert len(bs._ibd_block_buffer_ts) == 0
    # Penalised for prev-blk-not-found (not via the generic error path).
    calls = _prev_not_found_calls(bs)
    assert calls, "peer was never scored for prev-blk-not-found"
    assert all(c.args[0] == "203.0.113.7:8333" for c in calls)
    assert peer.score == 0


@pytest.mark.asyncio
async def test_unrequested_body_with_known_prev_is_dropped_without_penalty():
    bs = _make_block_sync()
    peer = _StubPeer()
    await bs.handle_block(_Msg(_payload(TIP_HASH)), peer)

    assert len(bs._ibd_block_buffer) == 0
    assert _prev_not_found_calls(bs) == []
    assert peer.score_deltas == []


@pytest.mark.asyncio
async def test_requested_body_with_unqueued_header_is_still_buffered():
    bs = _make_block_sync()
    peer = _StubPeer()
    payload = _payload(os.urandom(32))
    h = _block_hash(payload)
    bs.requested_blocks[h] = 0.0
    await bs.handle_block(_Msg(payload), peer)

    assert h in bs._ibd_block_buffer
    assert _prev_not_found_calls(bs) == []


@pytest.mark.asyncio
async def test_unrequested_body_with_queued_header_is_still_buffered():
    bs = _make_block_sync()
    peer = _StubPeer()
    payload = _payload(TIP_HASH)
    h = _block_hash(payload)
    bs._validated_headers = [(h, MagicMock())]
    await bs.handle_block(_Msg(payload), peer)

    assert h in bs._ibd_block_buffer
    assert _prev_not_found_calls(bs) == []
    assert peer.synced == [TIP_HEIGHT + 1]
