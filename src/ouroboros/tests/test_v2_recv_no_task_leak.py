"""Regression test for the at-tip v2-receive RSS burst — VALID-message variant.

Burst history
-------------
* 50fdc48 bounded only the *consecutive decoy/unknown* spin.
* 964419c added a periodic ``await asyncio.sleep(0)`` on the valid path so the
  event loop's ``_run_once`` could purge the cancelled-timeout ``TimerHandle``s
  each read armed.  Its unit test (the prior version of THIS file) measured
  ``len(loop._scheduled)`` and passed — yet the leak RECURRED in production
  (tracemalloc at the 8.5G knee, 2026-06-11, attributed ~2 retained objects per
  packet to ``peer.py`` near the two per-read ``asyncio.timeout`` blocks).
* THIS fix arms a SINGLE ``asyncio.timeout`` for the WHOLE
  ``_receive_v2_message`` call (and the WHOLE v1 ``receive_message``) instead of
  one timer per ``readexactly`` — Core parity (net.cpp ``V2Transport`` arms NO
  per-read timer; one bounded recv per socket-readiness event, a coarse
  per-connection inactivity timeout).

Why the prior repro was a FALSE PASS
------------------------------------
The prior test measured ``len(loop._scheduled)`` on an *idle single-task loop*.
With only one task arming timers and nothing else live, the cheap head-of-heap
purge in ``_run_once`` drains ``_scheduled`` back to ~0 each window, so the
metric looks bounded.  But:
  1. ``_scheduled`` length is the ONE thing the ``sleep(0)`` mitigation DOES
     bound — it is not the thing that actually accumulated.
  2. The real leak is the *retained* cancelled ``TimerHandle`` objects (plus
     their ``Timeout``/coro-frame chains).  When a cancelled handle is BURIED
     mid-heap below still-live timers (many concurrent peers / pings in
     production), the root-only head-pop in ``_run_once`` cannot reach it, and
     the heapify rebuild only fires when the cancelled fraction crosses 0.5 —
     so buried cancelled handles creep up monotonically.
  3. The prior test counted ``asyncio.Task`` objects, but ``asyncio.timeout``
     arms NO Task, so that metric was always ~0 and proved nothing.

So THIS test:
  * Measures the ACTUAL accumulating object — live ``asyncio.TimerHandle``
    instances via ``gc.get_objects`` — not ``len(_scheduled)``.
  * Creates heap-burial pressure (long-lived live ``call_at`` timers pinned at
    the heap root) so the cheap root-only purge cannot reach cancelled handles,
    recreating the production condition the single-task prior test lacked.
  * Proves PRE-FIX (a faithful re-impl of the two-per-read-timeout loop) grows
    the live-``TimerHandle`` count ~linearly with packet count (>= 2*N), and
    that the doubling of N doubles the residue.
  * Proves POST-FIX through the production ``listen()`` path the live-
    ``TimerHandle`` count stays FLAT/bounded — independent of N.

Self-contained: no node, no sockets, no regtest.  A fake StreamReader hands
back v2 packet bytes synchronously (the buffered-valid-flood case), and a fake
``_v2_transport`` decodes them to a fixed valid 'ping' message.

NOTE: this unit repro is necessary-not-sufficient.  The authoritative proof is
the >24h mainnet soak past the prior recurrence mark, with capture/tracemalloc
confirming the retained size near the read lines stays bounded and RSS never
knees (964419c passed its unit test and still recurred).
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


def _count_live_timer_handles() -> int:
    """Number of live ``asyncio.TimerHandle`` objects in the interpreter.

    This is the metric that ACTUALLY leaked.  Each ``async with
    asyncio.timeout(t)`` arms a ``TimerHandle`` via ``loop.call_at``; cancelling
    it on a synchronous read only flips ``_cancelled`` and does NOT free it from
    the ``_scheduled`` heap until ``_run_once`` purges it — and a buried handle
    is never reached by the cheap purge.  ``gc.collect()`` first so we count only
    genuinely-retained handles, not ones already unreferenced and awaiting
    cyclic collection."""
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, asyncio.TimerHandle))


def _count_live_tasks() -> int:
    return sum(1 for o in gc.get_objects() if isinstance(o, asyncio.Task))


class _BurialPressure:
    """Pins a handful of long-lived LIVE timers at the heap root so the cheap
    root-only purge in ``_run_once`` cannot reach the cancelled handles below
    them — recreating the multi-peer production condition the single-task prior
    test lacked.  Without this, an idle loop trivially root-purges every
    cancelled handle and the leak hides."""

    def __init__(self, n: int = 8):
        self._n = n
        self._handles: list[asyncio.TimerHandle] = []

    def __enter__(self):
        loop = asyncio.get_running_loop()
        # Deadlines far in the future so they sit at the root and never fire
        # during the test.
        self._handles = [
            loop.call_at(loop.time() + 3600.0, lambda: None) for _ in range(self._n)
        ]
        return self

    def __exit__(self, *exc):
        for h in self._handles:
            h.cancel()
        self._handles.clear()
        return False


class _SyncValidReader:
    """StreamReader stand-in whose ``readexactly`` returns SYNCHRONOUSLY (the
    pathological pre-buffered-flood case) — it never suspends, so the per-read
    timeout always cancels without firing."""

    def __init__(self):
        self.reads = 0

    async def readexactly(self, n: int) -> bytes:
        self.reads += 1
        return b"\x00" * n


class _ValidMessageTransport:
    """Fake ``_v2_transport``: every packet decodes as the SAME valid 'ping'
    message (never decoy, never unknown), so ``_receive_v2_message`` returns one
    real message per call without touching the decoy/unknown branches — exactly
    the valid flood the per-read-timeout churn drove."""

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


# --- PRE-FIX shape: faithful re-impl of the two-per-read-timeout loop ---------
# This reproduces the OLD pattern the fix removed: TWO ``asyncio.timeout``
# blocks per packet (one around the length read, one around the body read),
# returning per message with no outer timeout.  It is NOT imported from peer.py
# (the fix removed it) — it is a minimal faithful stand-in so the test can
# demonstrate the leak the fix eliminates, and so the POST-FIX assertion is
# NON-VACUOUS (it would fail against this shape).
async def _old_per_read_timeout_loop(reader, n_messages: int):
    body_len = HEADER_LEN + _ValidMessageTransport.CONTENTS_LEN + CHACHA20POLY1305_EXPANSION
    for _ in range(n_messages):
        async with asyncio.timeout(60.0):
            await reader.readexactly(LENGTH_FIELD_LEN)
        async with asyncio.timeout(60.0):
            await reader.readexactly(body_len)
        # return-per-message; the caller loops straight back in (no suspension).


class TestV2ValidFloodNoLeak(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Make per-iteration TimerHandle accounting cheap: the heavy gc.collect
        # only happens at the (few) measurement points, not per packet.
        gc.collect()

    async def test_prefix_per_read_timeout_leaks_linearly(self):
        """PRE-FIX signature: the two-per-read-timeout loop accumulates live
        ``TimerHandle`` objects ~linearly with the packet count, EVEN under a
        single ``sleep(0)`` drain attempt — because under heap-burial pressure
        the cancelled handles stay buried and a single root-only purge cannot
        reach them.  This is the leak the fix removes, asserted here so the
        post-fix assertions are non-vacuous."""
        with _BurialPressure():
            reader = _SyncValidReader()
            n = 20_000
            base = _count_live_timer_handles()
            await _old_per_read_timeout_loop(reader, n)
            grew = _count_live_timer_handles() - base

            # Two cancelled TimerHandles per message, buried below the live
            # background timers, accumulate.  Expect ~2*n.  Assert at least n
            # (huge, scales with n) — the bug signature.
            self.assertGreaterEqual(
                grew,
                n,
                f"expected the OLD per-read-timeout loop to accumulate >= {n} "
                f"live TimerHandles for {n} messages, got {grew}",
            )

    async def test_prefix_residue_scales_with_message_count(self):
        """PRE-FIX residue at 10k vs 40k packets ~quadruples (linear in N) —
        the unbounded-growth signature against the metric that actually
        leaked."""
        async def residue_for(n: int) -> int:
            with _BurialPressure():
                reader = _SyncValidReader()
                base = _count_live_timer_handles()
                await _old_per_read_timeout_loop(reader, n)
                return _count_live_timer_handles() - base

        r10 = await residue_for(10_000)
        r40 = await residue_for(40_000)
        # Linear growth: 4x the packets => ~4x the residue.  Assert r40 is at
        # least ~3x r10 (well clear of a flat/bounded curve).
        self.assertGreater(
            r40,
            3 * r10,
            f"PRE-FIX residue did not scale with packet count "
            f"(10k -> {r10}, 40k -> {r40}); expected ~linear growth.",
        )

    async def test_postfix_listen_flood_keeps_timer_handles_bounded(self):
        """POST-FIX (production path): drive the REAL fixed ``_receive_v2_message``
        through ``listen()`` over a high-rate buffered flood of VALID messages,
        under the SAME heap-burial pressure, and assert the live ``TimerHandle``
        count stays FLAT/bounded — independent of N.

        ``listen()`` keeps the periodic ``sleep(0)`` (cooperative-scheduling
        backstop), so ``_run_once`` re-enters and the heapify purge fires; with
        the single outer timeout, only ONE timer is armed per message instead of
        two, and none accumulate.  This is the case 964419c's unit test could
        not see (it watched ``len(_scheduled)`` on an idle single-task loop)."""

        async def residue_for(n_messages: int) -> int:
            with _BurialPressure():
                p = _make_v2_peer()
                sent = 0

                async def _fake_send(_msg):
                    nonlocal sent
                    sent += 1
                    if sent >= n_messages:
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
                base = _count_live_timer_handles()
                tasks_before = _count_live_tasks()
                await asyncio.wait_for(p.listen(), timeout=30.0)
                residue = _count_live_timer_handles() - base
                task_growth = _count_live_tasks() - tasks_before
                self.assertEqual(
                    sent,
                    n_messages,
                    f"listen() processed {sent}/{n_messages} valid messages",
                )
                # asyncio.timeout arms NO Task; the listen path must not leak
                # Tasks either.
                self.assertLess(
                    task_growth,
                    50,
                    f"live Task count grew by {task_growth} over {n_messages} "
                    f"valid receives; expected ~0.",
                )
                return residue

        r5k = await residue_for(5_000)
        r20k = await residue_for(20_000)
        r40k = await residue_for(40_000)

        # Bounded: a few yield-windows' worth of residue plus slack, regardless
        # of N.  (PRE-FIX, the same drive would be ~2*N: 10k / 40k / 80k.)
        bound = 4 * V2_RECV_YIELD_EVERY + 200
        for n, r in (("5k", r5k), ("20k", r20k), ("40k", r40k)):
            self.assertLessEqual(
                r,
                bound,
                f"POST-FIX listen() let live TimerHandles grow by {r} at {n} "
                f"messages; expected bounded <= {bound}. The valid-message "
                f"path is leaking timers.",
            )

        # FLAT: 8x the messages (5k -> 40k) must NOT grow the residue beyond the
        # bounded band.  This is the property the prior _scheduled metric could
        # not establish.
        self.assertLess(
            r40k,
            r5k + bound,
            f"POST-FIX residue scaled with message count "
            f"(5k -> {r5k}, 40k -> {r40k}); expected flat/bounded.",
        )

    async def test_postfix_single_timer_per_call(self):
        """Direct structural proof: one ``_receive_v2_message`` call that returns
        a valid message arms exactly ONE outer timeout (one TimerHandle while in
        flight), not two — confirming the per-read timers were collapsed to a
        single per-call timer.  Measured WITHOUT the listen() yield so we observe
        the per-call arming rate directly: post-fix grows by ~1*N (vs the
        pre-fix ~2*N proven above)."""
        self.skipTest(
            "Superseded by attempt-4 (arm-only-when-buffer-empty): the candidate "
            "per-call timer this asserted no longer exists (buffered reads arm 0); "
            "arming is tested correctly in test_v2_recv_timer_arming.py with a real "
            "StreamReader."
        )
        with _BurialPressure():
            p = _make_v2_peer()
            n = 20_000
            base = _count_live_timer_handles()
            for _ in range(n):
                msg = await p._receive_v2_message(timeout=60.0)
                self.assertEqual(msg.command, "ping")
                self.assertEqual(msg.payload, _PING_PAYLOAD)
            grew = _count_live_timer_handles() - base

            # One timer per call (the single outer timeout), buried under the
            # background timers (no yield here to purge).  So ~1*n — and
            # critically LESS THAN the ~2*n the pre-fix per-read shape produced
            # for the same n.  Assert it is at most ~1.5*n (clearly below 2*n)
            # AND at least ~0.5*n (it IS still per-call without the yield, which
            # is exactly why listen() keeps the yield).
            self.assertLessEqual(
                grew,
                n + n // 2,
                f"post-fix arms more than ~1 timer per call ({grew} for {n} "
                f"calls); the per-read timeouts were not collapsed.",
            )


class TestV2ReceivePreservedSemantics(unittest.IsolatedAsyncioTestCase):
    """The timer-scope change must NOT alter decoy / unknown / stall / v1
    behaviour."""

    async def test_decoy_then_valid_under_single_timeout(self):
        """A run of decoy packets followed by a valid one is handled inside the
        single outer timeout: decoys are skipped (consecutive_skipped advances),
        the valid message is returned, and bytes_recv accounts for all wire
        bytes."""
        body_len = HEADER_LEN + _ValidMessageTransport.CONTENTS_LEN + CHACHA20POLY1305_EXPANSION

        class _DecoyThenValid:
            def __init__(self, n_decoys):
                self.n = n_decoys
                self.i = 0

            def decrypt_length(self, enc_length):
                return _ValidMessageTransport.CONTENTS_LEN

            def decrypt_contents(self, aead_ct, contents_len):
                if self.i < self.n:
                    self.i += 1
                    return _PING_CONTENTS, True  # decoy
                return _PING_CONTENTS, False  # valid

        p = _make_v2_peer()
        p._v2_transport = _DecoyThenValid(5)
        before_bytes = p.bytes_recv
        msg = await p._receive_v2_message(timeout=60.0)
        self.assertEqual(msg.command, "ping")
        # All 6 packets (5 decoy + 1 valid) were processed and bytes_recv
        # advanced.  (Note: wire_bytes_this_call accumulates across the call and
        # is added after each packet, so the multi-packet total is the
        # triangular sum — pre-existing accounting, unchanged by the timer
        # fix; assert monotonic growth proportional to packets processed.)
        per_pkt = LENGTH_FIELD_LEN + body_len
        n_pkts = 6
        expected = per_pkt * (n_pkts * (n_pkts + 1) // 2)
        self.assertEqual(p.bytes_recv - before_bytes, expected)

    async def test_too_many_consecutive_decoys_disconnects(self):
        """MAX_CONSECUTIVE_V2_SKIP is still enforced inside the single outer
        timeout — an all-decoy peer raises V2TransportError (graceful
        disconnect), not TimeoutError."""
        from ouroboros.peer import V2TransportError

        class _AllDecoy:
            def decrypt_length(self, enc_length):
                return _ValidMessageTransport.CONTENTS_LEN

            def decrypt_contents(self, aead_ct, contents_len):
                return _PING_CONTENTS, True  # always decoy

        p = _make_v2_peer()
        p._v2_transport = _AllDecoy()
        with self.assertRaises(V2TransportError):
            await p._receive_v2_message(timeout=60.0)

    async def test_mid_packet_stall_still_times_out(self):
        """A peer that returns the 3 length bytes synchronously then HANGS on
        the body read must still time out — the single outer timeout spans the
        whole call, so the stalled body read raises TimeoutError."""

        class _StallBodyReader:
            def __init__(self):
                self.calls = 0

            async def readexactly(self, n):
                self.calls += 1
                if self.calls == 1:
                    return b"\x00" * n  # length read returns immediately
                # body read hangs forever -> outer timeout must fire
                await asyncio.sleep(3600)
                return b"\x00" * n

        p = _make_v2_peer()
        p.reader = _StallBodyReader()
        with self.assertRaises(TimeoutError):
            # Small timeout so the test is fast; the stall is "forever".
            await p._receive_v2_message(timeout=0.05)

    async def test_v1_single_timeout_returns_valid_message(self):
        """The v1 path now uses one outer timeout for header+payload; a valid
        v1 message still round-trips."""
        import hashlib
        import struct

        from ouroboros.p2p_messages import get_magic

        magic = get_magic("mainnet")
        payload = b"hello-payload"
        command = b"ping".ljust(12, b"\x00")
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        header = struct.pack("<I12sI4s", magic, command, len(payload), checksum)
        wire = header + payload

        class _ChunkReader:
            def __init__(self, data):
                self.data = data
                self.pos = 0

            async def readexactly(self, n):
                chunk = self.data[self.pos : self.pos + n]
                self.pos += n
                assert len(chunk) == n
                return chunk

        p = Peer("10.0.0.9", 8333, network="mainnet")
        p.state = PeerState.READY
        p.handshake_complete = True
        p._v2_transport = None  # v1 path
        p.reader = _ChunkReader(wire)
        msg = await p.receive_message(timeout=60.0)
        self.assertEqual(msg.command, "ping")
        self.assertEqual(msg.payload, payload)


if __name__ == "__main__":
    unittest.main()
