"""Unrequested fork bodies with less work than the tip are not kept in RAM.

Finding (cffix-ouroboros-fork-body-intake-gate, 2026-11-09 security audit):
``handle_block`` stored the raw bytes of ANY body whose hash sat in
``_fork_headers`` into ``_fork_block_bytes`` with no was_requested and no
work check.  A forked header that is not heavier than the tip is "stored
only" (``_maybe_trigger_fork_download``), and nothing ever discards its body,
so on regtest / testnet4 (cheap min-difficulty siblings) a peer could park
up to the fork-store cap (2048) x 4 MB of bodies in RAM.

Core (``validation.cpp`` ``ChainstateManager::AcceptBlock``): an unrequested
block whose header does not have ``nChainWork >= ActiveTip()->nChainWork``
(``fHasMoreOrSameWork``) is not processed and not stored.

These tests pin: (1) 50 unrequested 100 KB bodies for low-work sibling fork
headers leave ``_fork_block_bytes`` empty; (2) a REQUESTED fork body is still
kept (the GAP2 download path); (3) an unrequested body whose header has the
SAME work as the tip is kept (Core keeps more-OR-same work); (4) an
unrequested body on a heavier fork is kept; (5) a body for a hash we sent a
getdata for recently (in-flight entry since cleared) is kept.
"""

from __future__ import annotations

import hashlib
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import BlockHeader

REGTEST_BITS = 0x207FFFFF
TIP_HEIGHT = 110


def _work(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0x007FFFFF
    target = mant << (8 * (exp - 3)) if exp > 3 else mant >> (8 * (3 - exp))
    return (1 << 256) // (target + 1)


WORK = _work(REGTEST_BITS)


def _active_hash(h: int) -> bytes:
    return hashlib.sha256(b"active-%d" % h).digest()


class _StubDB:
    """Active chain 0..TIP_HEIGHT of regtest-difficulty blocks."""

    def __init__(self):
        self._by_height = {h: _active_hash(h) for h in range(TIP_HEIGHT + 1)}

    def get_best_block(self):
        return self._by_height[TIP_HEIGHT], TIP_HEIGHT

    def get_block_hash_by_height(self, height: int):
        return self._by_height.get(height)

    def get_chainwork_by_height(self, height: int) -> int:
        return WORK * (height + 1)

    def has_block_hash(self, block_hash: bytes) -> bool:
        return block_hash in self._by_height.values()

    def get_block_index_entry(self, block_hash: bytes):
        return None


class _StubPeer:
    def __init__(self, host: str = "203.0.113.9", port: int = 18444):
        self.host = host
        self.port = port
        self.inbound = True
        self.score = 100
        self.score_deltas: list[int] = []

    def adjust_score(self, delta: int) -> None:
        self.score_deltas.append(delta)
        self.score = max(0, min(100, self.score + delta))

    def update_synced_blocks(self, height: int) -> None:
        pass

    def note_block_height(self, height: int) -> None:
        pass


class _Msg:
    def __init__(self, payload: bytes):
        self.payload = payload


def _make_block_sync() -> BlockSync:
    pm = MagicMock()
    pm.network = "regtest"
    pm.misbehaving = MagicMock(return_value=False)
    bs = BlockSync(db=_StubDB(), validator=MagicMock(), peer_manager=pm)
    # The bridge driver (download / reorg) is not under test: intake only.
    bs._on_fork_body_received = AsyncMock(return_value=None)
    bs._drain_block_buffer = AsyncMock(return_value=0)
    bs._request_next_blocks = AsyncMock(return_value=None)
    return bs


def _fork_header(prev: bytes) -> BlockHeader:
    return BlockHeader(
        version=0x20000000,
        prev_blockhash=prev,
        merkle_root=os.urandom(32),
        timestamp=1_700_000_000,
        bits=REGTEST_BITS,
        nonce=0,
    )


def _admit(bs: BlockSync, prev: bytes) -> tuple[bytes, bytes]:
    """Admit a fork header on top of *prev*; return (hash, 100 KB body)."""
    hdr = _fork_header(prev)
    raw = hdr.serialize()
    h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    bs._store_fork_header(h, hdr, prev)
    assert h in bs._fork_headers
    return h, raw + os.urandom(100_000)


@pytest.mark.asyncio
async def test_unrequested_lowwork_sibling_fork_bodies_are_not_retained():
    bs = _make_block_sync()
    peer = _StubPeer()
    # 50 siblings forking at height 100: each has 10 blocks' less work than
    # the tip, so none is ever a reorg candidate.
    anchor = _active_hash(100)
    bodies = [_admit(bs, anchor) for _ in range(50)]
    assert len(bs._fork_headers) == 50
    for _h, payload in bodies:
        await bs.handle_block(_Msg(payload), peer)

    assert len(bs._fork_block_bytes) == 0
    assert all(h not in bs._ibd_block_buffer for h, _ in bodies)
    # The headers stay (Core keeps the index entry); only the body is dropped.
    assert len(bs._fork_headers) == 50
    # Core does not punish a low-work unrequested block.
    assert peer.score_deltas == []


@pytest.mark.asyncio
async def test_requested_lowwork_fork_body_is_still_retained():
    bs = _make_block_sync()
    peer = _StubPeer()
    h, payload = _admit(bs, _active_hash(100))
    bs.requested_blocks[h] = 0.0
    await bs.handle_block(_Msg(payload), peer)

    assert bs._fork_block_bytes.get(h) == payload
    bs._on_fork_body_received.assert_awaited()


@pytest.mark.asyncio
async def test_unrequested_equal_work_fork_body_is_retained():
    bs = _make_block_sync()
    peer = _StubPeer()
    # Sibling of the tip: same height, same work (fHasMoreOrSameWork).
    h, payload = _admit(bs, _active_hash(TIP_HEIGHT - 1))
    await bs.handle_block(_Msg(payload), peer)

    assert bs._fork_block_bytes.get(h) == payload


@pytest.mark.asyncio
async def test_unrequested_heavier_fork_body_is_retained():
    bs = _make_block_sync()
    peer = _StubPeer()
    h1, _p1 = _admit(bs, _active_hash(TIP_HEIGHT - 1))
    h2, p2 = _admit(bs, h1)  # one block more work than the tip
    await bs.handle_block(_Msg(p2), peer)

    assert bs._fork_block_bytes.get(h2) == p2


@pytest.mark.asyncio
async def test_recently_requested_lowwork_fork_body_is_retained():
    bs = _make_block_sync()
    peer = _StubPeer()
    h, payload = _admit(bs, _active_hash(100))
    bs.note_block_requested(h)
    assert h not in bs.requested_blocks
    await bs.handle_block(_Msg(payload), peer)

    assert bs._fork_block_bytes.get(h) == payload
