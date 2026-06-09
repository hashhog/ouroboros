"""Regression test for the at-tip v2-receive RSS burst — VALID-message variant
(tracemalloc burst #2, mainnet ouroboros, 2026-06-09).

This is the case the FIRST fix (50fdc48) MISSED.  50fdc48 bounded the
*consecutive decoy/unknown* spin and yielded only on those sub-branches.  But
the live driver is the per-receive event-loop-timer churn under a high-rate
flood of *VALID* v2 messages, which never touches the decoy/unknown branches.

Mechanism (confirmed by a standalone Python 3.13 asyncio repro):
``Peer._receive_v2_message`` reads each packet with a timeout.  Both
``asyncio.wait_for(read, timeout)`` AND ``async with asyncio.timeout(timeout):
read`` arm a timeout via ``loop.call_at`` -> a ``TimerHandle`` pushed onto
``BaseEventLoop._scheduled``.  When ``readexactly`` returns SYNCHRONOUSLY (the
StreamReader buffer already holds the bytes — a high-rate buffered flood of
valid messages), the timeout context CANCELS the timer.  But
``TimerHandle.cancel()`` only flips ``_cancelled``; it does NOT remove the
handle from the ``_scheduled`` heap.  The cancelled-timer purge lives ONLY in
``BaseEventLoop._run_once``.  ``listen() -> receive_message ->
_receive_v2_message`` is a tight loop that RETURNS on the first valid message
and immediately re-reads the next buffered one, never suspending back to
``_run_once`` — so cancelled ``TimerHandle``s (plus the per-call ``wait_for``
Task / coro cyclic garbage) accumulate MONOTONICALLY in ``_scheduled`` and RSS
climbs toward the cgroup cap.

The fix forces the receive hot path to periodically ``await asyncio.sleep(0)``
on the VALID-message path too (``V2_RECV_YIELD_EVERY``), so ``_run_once``
bulk-purges the cancelled handles (and the cyclic GC reclaims the Task/coro
chain).  The migration of the hot reads from ``wait_for`` to
``asyncio.timeout`` removes the per-call wrapper Task (secondary), but is NOT
sufficient on its own — the repro proves ``asyncio.timeout`` arms the identical
``call_at`` timer and accumulates ``_scheduled`` just as badly (in fact a touch
worse, two timers per packet) without the periodic yield.

What this test proves:
  * BEFORE (a faithful re-impl of the old wait_for/no-yield receive loop):
    ``len(loop._scheduled)`` grows ~linearly with the number of valid messages
    processed -> the leak.
  * AFTER (the real, fixed ``_receive_v2_message`` driven through ``listen()``
    over thousands of valid messages): ``len(loop._scheduled)`` stays BOUNDED
    (well under the message count), and the number of live ``asyncio.Task``
    objects (via ``gc.get_objects``) does NOT grow with iteration count.

Self-contained: no node, no sockets, no regtest.  Uses a fake StreamReader that
hands back valid encrypted-v2 packet bytes synchronously, plus a fake
``_v2_transport`` that decodes them to real messages.
"""

import asyncio
import gc
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.peer import (  # noqa: E402
    V2_RECV_YIELD_EVERY,
    Peer,
    PeerState,
)
from ouroboros.transport_v2 import (  # noqa: E402
    CHACHA20POLY1305_EXPANSION,
    HEADER_LEN,
    LENGTH_FIELD_LEN,
    decode_v2_contents,
    encode_v2_contents,
)


# A real, well-formed v2 "ping" message — decodes to a non-decoy, known type.
_PING_PAYLOAD = b"\x11\x22\x33\x44\x55\x66\x77\x88"
_PING_CONTENTS = encode_v2_contents("ping", _PING_PAYLOAD)
assert decode_v2_contents(_PING_CONTENTS) == ("ping", _PING_PAYLOAD)


def _count_live_tasks() -> int:
    """Number of asyncio.Task objects currently alive in the interpreter."""
    return sum(1 for o in gc.get_objects() if isinstance(o, asyncio.Task))


class _SyncValidReader:
    """StreamReader stand-in whose readexactly returns SYNCHRONOUSLY (the
    pathological pre-buffered-flood case).  Always hands back ``n`` zero bytes —
    the fake transport below ignores the actual bytes and decodes a fixed valid
    message, so what matters here is only that the read never suspends."""

    def __init__(self):
        self.reads = 0

    async def readexactly(self, n: int) -> bytes:
        self.reads += 1
        return b"\x00" * n


class _ValidMessageTransport:
    """Fake _v2_transport: every packet decodes as the SAME valid 'ping'
    message (never a decoy, never unknown).  So _receive_v2_message returns one
    real message per call without ever touching the decoy/unknown branches —
    exactly the flood 50fdc48 did not bound."""

    CONTENTS_LEN = len(_PING_CONTENTS)

    def decrypt_length(self, enc_length: bytes) -> int:
        assert len(enc_length) == LENGTH_FIELD_LEN
        return self.CONTENTS_LEN

    def decrypt_contents(self, aead_ct: bytes, contents_len: int):
        assert len(aead_ct) == HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        return _PING_CONTENTS, False  # (contents, is_decoy=False)


def _make_v2_peer() -> Peer:
    p = Peer("10.0.0.9", 8333, network="mainnet")
    p.state = PeerState.READY
    p.handshake_complete = True
    p._v2_transport = _ValidMessageTransport()
    p.reader = _SyncValidReader()
    return p


# --- BEFORE: faithful re-impl of the pre-fix hot read loop --------------------
# This intentionally reproduces the OLD pattern: asyncio.wait_for per read, with
# NO periodic yield on the valid path.  It is NOT imported from peer.py — it is
# a minimal stand-in so the test can demonstrate the leak the fix removes.

async def _old_receive_loop_no_yield(reader, n_messages: int):
    """Pre-fix shape: two wait_for reads per message, return per message, no
    yield.  Driven n_messages times back-to-back (as listen() would)."""
    for _ in range(n_messages):
        # length read + body read — both complete synchronously here.
        await asyncio.wait_for(reader.readexactly(LENGTH_FIELD_LEN), timeout=60.0)
        await asyncio.wait_for(reader.readexactly(64), timeout=60.0)
        # (return-per-message; listen() loops straight back in — no suspension)


class TestV2ValidFloodNoLeak(unittest.IsolatedAsyncioTestCase):
    async def test_before_old_pattern_accumulates_timers(self):
        """Sanity / before-state: the OLD wait_for/no-yield receive loop grows
        loop._scheduled ~linearly with the valid-message count.  This is the
        leak the fix removes — asserted here so a future regression that drops
        the yield is caught against this baseline."""
        loop = asyncio.get_running_loop()
        reader = _SyncValidReader()

        n = 20_000
        before = len(loop._scheduled)
        await _old_receive_loop_no_yield(reader, n)
        grew = len(loop._scheduled) - before

        # Two cancelled TimerHandles per message pile up in the heap because we
        # never re-entered _run_once.  Expect ~2*n; assert it grew by at least
        # ~1 per message (huge, unbounded with n) — the bug signature.
        self.assertGreaterEqual(
            grew, n,
            f"expected the old no-yield pattern to accumulate >= {n} cancelled "
            f"timers for {n} messages, got {grew}",
        )

        # A single yield drains the cancelled-handle heap back down — proving
        # the residue is heap-pinned cancelled timers purged only by _run_once.
        await asyncio.sleep(0)
        self.assertLess(
            len(loop._scheduled), 200,
            "one await sleep(0) should let _run_once purge the cancelled-timer "
            "heap; if it did not, the residue is something else",
        )

    async def test_after_valid_flood_keeps_scheduled_bounded(self):
        """AFTER (the real fix): drive the actual _receive_v2_message over a
        HIGH-RATE buffered flood of VALID messages and assert loop._scheduled
        stays BOUNDED (does not grow with the message count) and live Tasks do
        not accumulate.  This is the case 50fdc48 missed."""
        loop = asyncio.get_running_loop()
        p = _make_v2_peer()

        # Drain any pre-existing scheduled handles so our delta is clean.
        await asyncio.sleep(0)
        sched_before = len(loop._scheduled)
        tasks_before = _count_live_tasks()

        n_messages = 20_000
        peak_scheduled = sched_before
        for _ in range(n_messages):
            msg = await p._receive_v2_message(timeout=60.0)
            self.assertEqual(msg.command, "ping")
            self.assertEqual(msg.payload, _PING_PAYLOAD)
            if len(loop._scheduled) > peak_scheduled:
                peak_scheduled = len(loop._scheduled)

        sched_after = len(loop._scheduled)
        tasks_after = _count_live_tasks()

        # We processed 20k valid messages = 40k timeout-armed reads.  With the
        # periodic yield, _scheduled must stay BOUNDED — far below the message
        # count.  Generous ceiling: a few yield-windows' worth of residue plus
        # slack.  (Pre-fix this would be ~40_000.)
        bound = 4 * V2_RECV_YIELD_EVERY + 200
        self.assertLessEqual(
            peak_scheduled, bound,
            f"loop._scheduled peaked at {peak_scheduled} over {n_messages} "
            f"valid messages; expected bounded <= {bound}. The valid-message "
            f"path is not yielding to the event loop (the burst-#2 leak).",
        )

        # And it must NOT scale with the message count: doubling messages should
        # not double the residue (it stays in the same small band).
        self.assertLess(
            sched_after, n_messages // 10,
            f"loop._scheduled ({sched_after}) scaled with message count "
            f"({n_messages}); the receive loop is leaking cancelled timers.",
        )

        # Live Task objects must not accumulate with iteration count either
        # (asyncio.timeout does not wrap each read in a Task, and any transient
        # coro/Task garbage is collected once we yield to the loop).
        task_growth = tasks_after - tasks_before
        self.assertLess(
            task_growth, 50,
            f"live asyncio.Task count grew by {task_growth} over {n_messages} "
            f"valid receives; expected ~0 (no per-receive Task accumulation).",
        )

    async def test_after_scales_flat_with_message_count(self):
        """Stronger before/after contrast: the fixed loop's residue at 10k and
        40k messages stays in the same band (flat), proving no per-message
        accumulation — whereas the old pattern's residue would 4x with the
        count."""
        loop = asyncio.get_running_loop()

        async def residue_for(n_messages: int) -> int:
            p = _make_v2_peer()
            await asyncio.sleep(0)
            base = len(loop._scheduled)
            peak = base
            for _ in range(n_messages):
                await p._receive_v2_message(timeout=60.0)
                if len(loop._scheduled) > peak:
                    peak = len(loop._scheduled)
            return peak - base

        peak_10k = await residue_for(10_000)
        peak_40k = await residue_for(40_000)

        # Each v2 message does 2 timeout-armed reads (length + body) and the
        # yield budget advances once per packet, so a full yield window holds
        # up to ~2 * V2_RECV_YIELD_EVERY cancelled handles before _run_once
        # purges them.  Bounded — and independent of the message count.
        band = 2 * V2_RECV_YIELD_EVERY + 50
        self.assertLessEqual(peak_10k, band)
        self.assertLessEqual(peak_40k, band)
        # 4x the messages must NOT meaningfully grow the residue.
        self.assertLess(
            peak_40k, peak_10k + V2_RECV_YIELD_EVERY,
            f"residue grew with message count (10k->{peak_10k}, 40k->{peak_40k}); "
            f"expected flat — the valid-message path must yield periodically.",
        )

    async def test_listen_drives_valid_flood_without_unbounded_scheduled(self):
        """End-to-end through listen(): a finite buffered flood of valid 'ping'
        messages is processed (auto-ponged) and listen()'s per-message yield
        keeps loop._scheduled bounded.  Confirms the belt-and-suspenders yield
        in listen() works for the dispatched path too."""
        loop = asyncio.get_running_loop()

        n_messages = 5_000
        processed = 0

        class _FiniteValidTransport(_ValidMessageTransport):
            pass

        p = _make_v2_peer()
        p._v2_transport = _FiniteValidTransport()

        # Stop after n_messages by flipping state to DISCONNECTED from a handler.
        # listen() auto-handles 'ping' (sends pong), so we hook send_message to
        # count and to terminate the loop.
        sent_pongs = 0

        async def _fake_send(msg):
            nonlocal sent_pongs, processed
            sent_pongs += 1
            processed += 1
            if processed >= n_messages:
                p.state = PeerState.DISCONNECTED

        p.send_message = _fake_send

        class _DummyWriter:
            def close(self):
                pass

            async def wait_closed(self):
                return None

        p.writer = _DummyWriter()
        p._listen_task = None
        p._ping_task = None

        await asyncio.sleep(0)
        base = len(loop._scheduled)
        peak = base

        # Run listen() but watch _scheduled growth via a poller task.
        async def _watch():
            nonlocal peak
            while p.state == PeerState.READY:
                if len(loop._scheduled) > peak:
                    peak = len(loop._scheduled)
                await asyncio.sleep(0)

        watcher = asyncio.ensure_future(_watch())
        await asyncio.wait_for(p.listen(), timeout=10.0)
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError:
            pass

        self.assertEqual(sent_pongs, n_messages)
        residue = peak - base
        bound = 4 * V2_RECV_YIELD_EVERY + 200
        self.assertLessEqual(
            residue, bound,
            f"listen() let loop._scheduled grow by {residue} over {n_messages} "
            f"valid messages; expected bounded <= {bound}.",
        )


if __name__ == "__main__":
    unittest.main()
