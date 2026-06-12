"""Non-vacuous live-TimerHandle repro for the v2/v1-recv RSS-burst leak.

Root cause (tracemalloc at the 4.7 G knee, captures armed 2026-06-12): the v1
receive path armed a fresh ``asyncio.timeout`` per blocking read, and the
cancelled ``TimerHandle`` objects accumulate in ``BaseEventLoop._scheduled``.
``TimerHandle.cancel()`` only flips ``_cancelled``; the bulk purge lives in
``_run_once`` and starves under load (it heapify-rebuilds only when
``_timer_cancelled_count > 100`` AND cancelled/total > 0.5, and otherwise only
cheaply pops handles at the heap ROOT).  ``receive_message`` calls
``_read_exactly`` twice per v1 message (24 B header + payload), so a flood of N
messages armed ~2N cancelled-but-retained timers -> ~750 MB at 1.42 M handles.

The fix (attempt-5, Core parity — net.cpp arms NO per-read timer; inactivity is
the coarse ``CConnman::InactivityCheck``) makes ``_read_exactly`` a plain
``await readexactly`` with ZERO ``asyncio.timeout``.  A stalled peer is caught by
the per-node sweeper (``PeerManager.maintain_connections`` ->
``Peer.is_recv_stalled``) instead.

NON-VACUOUS DESIGN.  The trigger for the leak is a read whose bytes are not yet
in the public ``StreamReader`` buffer at ``_read_exactly`` entry — exactly the
real-socket case where data has not been drained into ``_buffer`` between
readiness events.  The prior partial fix (attempt-4: arm a per-read timer ONLY
when the buffer is empty/short) STILL armed on every such blocked read, so it
still leaked ~2N — just at lower volume than the original always-arm code.

``_BlockingReader`` reproduces that condition deterministically: its public
``_buffer`` reports empty when ``_read_exactly`` is entered (so the pre-fix
code takes the arm branch), then the read completes synchronously and we do NOT
yield to ``_run_once`` between messages, so the cancelled-timer purge stays
starved — the production accumulation condition.

  * ``test_v1_recv_flood_bounded_timerhandles`` — the PRODUCTION
    ``_read_exactly`` (attempt-5) stays bounded (delta ~0) on the flood.
  * ``test_prefix_attempt4_per_read_timeout_leaks`` — replays the SAME flood
    through the actual pre-fix ``_read_exactly`` body (attempt-4: arm-when-
    blocked) and asserts it leaks ~2N.  This proves the harness genuinely
    observes the leak on the code the fix replaced, so the bounded test above
    FAILS on the current peer.py and PASSES on the fix (non-vacuous).
"""

from __future__ import annotations

import asyncio
import gc
import types

import pytest

from ouroboros.p2p_messages import NetworkMessage, get_magic
from ouroboros.peer import Peer, PeerState


N_MESSAGES = 400


def _count_live_timer_handles() -> int:
    """Number of live ``asyncio.TimerHandle`` objects reachable from the GC.

    This is the exact object class that piled up in ``loop._scheduled`` at the
    4.7 G knee (tracemalloc base_events.py:816 -> events.py TimerHandle)."""
    gc.collect()
    return sum(
        1 for obj in gc.get_objects()
        if type(obj).__name__ == "TimerHandle"
    )


def _frames(n: int, network: str = "regtest") -> bytes:
    """``n`` valid v1 ``ping`` frames back-to-back.

    Each frame is magic(4) + command(12) + length(4) + checksum(4) + 8 B nonce
    payload — exactly what the v1 ``receive_message`` parser consumes, so both
    ``_read_exactly`` calls per message (header + payload) run."""
    magic = get_magic(network)
    blob = bytearray()
    for i in range(n):
        payload = (i & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        blob += NetworkMessage(command="ping", payload=payload,
                               magic=magic).serialize()
    return bytes(blob)


class _BlockingReader:
    """Reader whose public ``_buffer`` is EMPTY at ``_read_exactly`` entry.

    Mirrors a real socket where bytes have not yet been drained into the public
    StreamReader buffer between readiness events — the condition under which the
    pre-fix code armed a per-read ``asyncio.timeout``.  The bytes are then fed
    inline and the inner ``readexactly`` completes; we never yield to
    ``_run_once`` between reads, so the cancelled-timer purge stays starved (the
    production accumulation condition)."""

    def __init__(self, blob: bytes):
        self._sr = asyncio.StreamReader()
        self._all = blob
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if len(self._sr._buffer) < n:
            chunk = self._all[self._pos:self._pos + n]
            self._pos += n
            self._sr.feed_data(chunk)
        return await self._sr.readexactly(n)

    @property
    def _buffer(self) -> bytearray:
        # Reports the public buffer, which is empty right before each blocking
        # read — so attempt-4's "arm only when buffer empty/short" check fires.
        return self._sr._buffer


def _make_ready_v1_peer(reader) -> Peer:
    peer = Peer("127.0.0.1", 18444, "regtest", transport_version=1)
    peer.reader = reader
    peer.state = PeerState.READY
    return peer


async def _drain_flood(peer: Peer, n: int) -> int:
    received = 0
    for _ in range(n):
        msg = await peer.receive_message(timeout=60.0)
        assert msg.command == "ping"
        received += 1
    return received


# --- the pre-fix _read_exactly body (attempt-4), verbatim, for the guard ----
async def _attempt4_read_exactly(self, n: int) -> bytes:
    buf = getattr(self.reader, "_buffer", None)
    if buf is not None and len(buf) >= n:
        return await self.reader.readexactly(n)
    async with asyncio.timeout(self._read_timeout):
        return await self.reader.readexactly(n)


@pytest.mark.asyncio
async def test_v1_recv_flood_bounded_timerhandles():
    """FIX assertion: the production v1 receive path arms ~0 TimerHandles even
    under a blocking flood of N valid messages (Core parity, no per-read timer).
    """
    peer = _make_ready_v1_peer(_BlockingReader(_frames(N_MESSAGES)))

    before = _count_live_timer_handles()
    received = await _drain_flood(peer, N_MESSAGES)
    after = _count_live_timer_handles()

    assert received == N_MESSAGES
    delta = after - before
    assert delta <= N_MESSAGES // 10, (
        f"v1 receive path leaked {delta} live TimerHandles over {N_MESSAGES} "
        f"blocking messages (expected ~0 — Core arms no per-read timer; this "
        f"FAILS on the pre-fix attempt-4 code, which leaks ~2N)"
    )


@pytest.mark.asyncio
async def test_prefix_attempt4_per_read_timeout_leaks():
    """NON-VACUOUS guard: the actual pre-fix ``_read_exactly`` body (attempt-4,
    arm-when-blocked) leaks ~2N live TimerHandles on the SAME flood — proving
    the harness observes the leak the fix removes."""
    peer = _make_ready_v1_peer(_BlockingReader(_frames(N_MESSAGES)))
    peer._read_exactly = types.MethodType(_attempt4_read_exactly, peer)

    before = _count_live_timer_handles()
    received = await _drain_flood(peer, N_MESSAGES)
    after = _count_live_timer_handles()

    assert received == N_MESSAGES
    delta = after - before
    # 2 blocking reads per message, each arms a cancelled-but-retained timer.
    assert delta >= N_MESSAGES, (
        f"pre-fix attempt-4 only leaked {delta} TimerHandles over {N_MESSAGES} "
        f"messages (expected >= {N_MESSAGES} ~ 2N); the harness is not "
        f"observing the leak, so the bounded test would be vacuous"
    )


def test_is_recv_stalled_threshold(monkeypatch):
    """The coarse inactivity check (replacing the per-read timer) flags a peer
    whose last successful read is older than its stall timeout, and clears once
    a read updates the monotonic clock."""
    peer = Peer("127.0.0.1", 18444, "regtest", transport_version=1)
    peer._read_timeout = 60.0

    import ouroboros.peer as peer_mod
    fake_now = [1000.0]
    monkeypatch.setattr(peer_mod.time, "monotonic", lambda: fake_now[0])

    peer._last_recv_monotonic = fake_now[0]
    assert not peer.is_recv_stalled()

    fake_now[0] += 61.0
    assert peer.is_recv_stalled()

    peer._last_recv_monotonic = fake_now[0]
    assert not peer.is_recv_stalled()
