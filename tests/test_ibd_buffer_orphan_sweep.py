"""Regression tests for the 2026-06-06 at-tip RSS-leak fix — BUG 2.

Background — ``BlockSync._ibd_block_buffer`` is the out-of-order block buffer:
``handle_block`` inserts ``hash -> (block, raw_payload)`` for a block that
arrived before its parent connected, and the drain
(``_drain_block_buffer_locked``) pops a hash ONLY once it appears contiguously
from the connect frontier in ``_validated_headers``.

A buffered block whose hash is NOT (or no longer) in ``_validated_headers`` — a
stale / competing / fork block a peer delivered out of band, or a leftover from
a ``_validated_headers`` rebuild — is never popped by the drain and retains its
full ~1-2 MB raw payload forever.  The near-full eviction band only reclaims
*far-ahead* entries while admitting new blocks, so a quiet-at-tip buffer that
stays below the band never reclaims orphans at all.  This is the second at-tip
RSS-leak driver (the first was ``PeerManager._partial_cmpct_blocks``; same OOM
family, 2026-06-02/03).

The fix mirrors ``_sweep_partial_cmpct_blocks``: a sibling insertion-time map
``_ibd_block_buffer_ts`` (kept in lockstep with the buffer via the
``_buffer_put`` / ``_buffer_remove`` chokepoints), plus a periodic
``_sweep_ibd_block_buffer`` (driven from ``sync_loop``) that drops any buffer
entry that is (a) not currently in ``_validated_headers`` AND (b) older than
``IBD_BUFFER_ORPHAN_TTL``.

These tests pin:
  (a) a fresh orphan is NOT swept (TTL window protects in-flight blocks),
  (b) an aged orphan IS reclaimed (buffer, ts map, and source-addr map all),
  (c) an aged block that IS in ``_validated_headers`` is NEVER swept (it is
      legitimately awaited by the drain),
  (d) the timestamp map stays in lockstep with the buffer across put/remove,
  (e) the sweep keeps the buffer bounded under repeated orphan insertion,
  (f) sweeping an empty buffer is a no-op.

Pure unit tests — a bare ``BlockSync`` with MagicMock db/validator/peer_manager
(same construction as ``test_w75_watchdog.py``); we drive ``_validated_headers``
and the buffer directly and rewrite timestamps to simulate ageing.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import IBD_BUFFER_ORPHAN_TTL, BlockSync


def _make_block_sync() -> BlockSync:
    """A bare BlockSync wired with the minimum mocks the sweep touches."""
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 800_000)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def _hash(n: int) -> bytes:
    return bytes([n & 0xFF]) + b"\x00" * 31


def _put_orphan(bs: BlockSync, h: bytes, *, age: float = 0.0, addr: str = "1.2.3.4:8333") -> None:
    """Insert an out-of-order block via the buffer chokepoint, then optionally
    backdate its timestamp by *age* seconds to simulate it sitting unreclaimed.
    Records a source-addr like the real handle_block insert sites do."""
    bs._buffer_put(h, (None, b"raw-payload-" + h))
    bs._block_source_peer_addr[h] = addr
    if age:
        bs._ibd_block_buffer_ts[h] = time.monotonic() - age


@pytest.mark.asyncio
async def test_fresh_orphan_is_not_swept():
    """A just-arrived orphan (not yet in validated_headers) is protected by the
    TTL window — it may still be awaiting an in-flight header batch."""
    bs = _make_block_sync()
    bs._validated_headers = []  # nothing wanted yet
    h = _hash(1)
    _put_orphan(bs, h)  # age 0

    swept = await bs._sweep_ibd_block_buffer()

    assert swept == 0
    assert h in bs._ibd_block_buffer
    assert h in bs._ibd_block_buffer_ts


@pytest.mark.asyncio
async def test_aged_orphan_is_reclaimed():
    """An orphan older than IBD_BUFFER_ORPHAN_TTL that never lined up with
    validated_headers is reclaimed from the buffer, the ts map, AND the
    source-addr map.  With the pre-fix code (no sweep) this entry would leak
    its ~1-2 MB payload forever."""
    bs = _make_block_sync()
    bs._validated_headers = []  # this hash is NOT wanted
    h = _hash(2)
    _put_orphan(bs, h, age=IBD_BUFFER_ORPHAN_TTL + 1)

    swept = await bs._sweep_ibd_block_buffer()

    assert swept == 1
    assert h not in bs._ibd_block_buffer
    assert h not in bs._ibd_block_buffer_ts
    assert h not in bs._block_source_peer_addr


@pytest.mark.asyncio
async def test_aged_block_in_validated_headers_is_never_swept():
    """An aged buffered block that IS in validated_headers (legitimately awaited
    by the drain) must NEVER be swept — only orphans are reclaimed."""
    bs = _make_block_sync()
    h = _hash(3)
    # The block is the connect-frontier head: present in validated_headers.
    bs._validated_headers = [(h, MagicMock())]
    _put_orphan(bs, h, age=IBD_BUFFER_ORPHAN_TTL * 10)  # very old, but wanted

    swept = await bs._sweep_ibd_block_buffer()

    assert swept == 0
    assert h in bs._ibd_block_buffer
    assert h in bs._ibd_block_buffer_ts


@pytest.mark.asyncio
async def test_mixed_buffer_only_aged_orphans_swept():
    """A realistic buffer: one wanted head, one fresh orphan, one aged orphan.
    Only the aged orphan is reclaimed."""
    bs = _make_block_sync()
    wanted, fresh_orphan, aged_orphan = _hash(10), _hash(11), _hash(12)
    bs._validated_headers = [(wanted, MagicMock())]
    _put_orphan(bs, wanted, age=IBD_BUFFER_ORPHAN_TTL * 5)   # old but wanted
    _put_orphan(bs, fresh_orphan, age=1.0)                   # orphan, fresh
    _put_orphan(bs, aged_orphan, age=IBD_BUFFER_ORPHAN_TTL + 5)  # orphan, aged

    swept = await bs._sweep_ibd_block_buffer()

    assert swept == 1
    assert wanted in bs._ibd_block_buffer
    assert fresh_orphan in bs._ibd_block_buffer
    assert aged_orphan not in bs._ibd_block_buffer
    assert aged_orphan not in bs._ibd_block_buffer_ts


@pytest.mark.asyncio
async def test_empty_buffer_sweep_is_noop():
    """Sweeping an empty buffer returns 0 and does not raise."""
    bs = _make_block_sync()
    assert await bs._sweep_ibd_block_buffer() == 0


def test_timestamp_map_stays_in_lockstep_with_buffer():
    """_buffer_put records a timestamp; _buffer_remove drops both; a re-put
    keeps the ORIGINAL timestamp (a bouncing block still ages toward the TTL
    rather than resetting its clock forever)."""
    bs = _make_block_sync()
    h = _hash(20)

    bs._buffer_put(h, (None, b"raw"))
    assert h in bs._ibd_block_buffer
    assert h in bs._ibd_block_buffer_ts
    first_ts = bs._ibd_block_buffer_ts[h]

    # Re-put (e.g. the transient "Previous block not found" requeue) keeps the
    # original insertion time (setdefault), so the orphan clock does not reset.
    bs._buffer_put(h, (None, b"raw2"))
    assert bs._ibd_block_buffer_ts[h] == first_ts
    assert bs._ibd_block_buffer[h] == (None, b"raw2")

    # Remove drops both maps and returns the value.
    popped = bs._buffer_remove(h)
    assert popped == (None, b"raw2")
    assert h not in bs._ibd_block_buffer
    assert h not in bs._ibd_block_buffer_ts

    # Removing an absent hash is a safe no-op returning None.
    assert bs._buffer_remove(h) is None


@pytest.mark.asyncio
async def test_repeated_orphan_insertion_stays_bounded_after_sweeps():
    """A peer that keeps delivering distinct never-connecting orphans cannot
    grow the buffer without bound: once each orphan ages past the TTL it is
    swept.  We simulate batches arriving over time and assert the buffer
    collapses back to (near) empty after the orphans age out."""
    bs = _make_block_sync()
    bs._validated_headers = []  # nothing these orphans line up with

    # 200 distinct orphans, all aged past the TTL.
    n = 200
    for i in range(n):
        _put_orphan(bs, _hash_wide(i), age=IBD_BUFFER_ORPHAN_TTL + 10)

    assert len(bs._ibd_block_buffer) == n
    swept = await bs._sweep_ibd_block_buffer()

    assert swept == n
    assert bs._ibd_block_buffer == {}
    assert bs._ibd_block_buffer_ts == {}


def _hash_wide(n: int) -> bytes:
    """A distinct 32-byte hash for index *n* (supports n far beyond 255)."""
    import struct
    return struct.pack("<I", n) + b"\x00" * 28


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
