"""Arming-count regression for the at-tip v2-receive RSS burst — the
NON-VACUOUS metric.

Why a new file (do NOT fold into test_v2_recv_no_task_leak.py)
-------------------------------------------------------------
``test_v2_recv_no_task_leak.py`` (committed in the FAILED candidate ef28190)
measures TimerHandle *survival* — how many cancelled ``TimerHandle`` objects
remain live after a drive.  That metric is vacuous for proving the fix: a single
``await asyncio.sleep(0)`` re-enters ``_run_once`` and root-purges survivors even
on the leaky code, so "survival" can look bounded while the code still ARMS a
timer per read.  The thing that actually drove the production leak is the rate of
timer ARMING on the buffered-flood path — each ``async with asyncio.timeout(t)``
arms a ``TimerHandle`` via ``loop.call_at(deadline, ...)``, and on a synchronous
(already-buffered) ``readexactly`` that handle is cancelled-but-retained until a
purge that never fires under steady multi-peer load.

So THIS test counts ``loop.call_at`` invocations (== timers armed) while driving
``_receive_v2_message`` over a real ``asyncio.StreamReader`` PRE-LOADED with N
back-to-back well-formed v2 packets (the buffered-flood / leak case).  It is the
three-way discriminator the survival metric could not be:

  * ORIGINAL shape (one ``asyncio.timeout`` per read: length + body) arms ~2N.
  * FAILED candidate (one ``asyncio.timeout`` per call) arms ~N (1/msg).
  * THE FIX (``_read_exactly`` arms a timer ONLY when the buffer is short) arms
    ~0 over a fully-buffered flood — Core parity (net.cpp ``V2Transport`` arms NO
    per-read timer; the only recv-path timeout is the coarse per-connection
    ``CConnman::InactivityCheck``).

The test FAILS on BOTH the original and candidate shapes (faithful local
stand-ins below) and PASSES only on the fix, plus a scaling assertion that the
fix's arming is FLAT (independent of N) while the candidate scales ~linearly.

A stall test (empty/short buffer that never fills -> the fix still arms a timer
and ``TimeoutError`` fires) guarantees the leak elimination did not blunt the
real stall/inactivity guard.

Self-contained: no node, no sockets, no regtest.  Real ``asyncio.StreamReader``
pre-fed with packet bytes; a fake ``_v2_transport`` decodes each to a fixed valid
'ping'.

NOTE: this unit repro is necessary-not-sufficient.  The authoritative proof is a
>24h mainnet soak past the prior recurrence mark with tracemalloc/RSS flat
(964419c and ef28190 each passed a unit test and still recurred).
"""

import asyncio
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.peer import (  # noqa: E402
    Peer,
    PeerState,
    V2TransportError,
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

# Wire framing of one buffered v2 packet as seen by the reader:
#   enc_length (LENGTH_FIELD_LEN)  +  AEAD body (HEADER_LEN + contents + tag)
_CONTENTS_LEN = len(_PING_CONTENTS)
_AEAD_LEN = HEADER_LEN + _CONTENTS_LEN + CHACHA20POLY1305_EXPANSION
# The bytes are decoded by the FAKE transport (which ignores them), so any
# content of the right LENGTH is fine — the reader just needs to hand back the
# right number of bytes synchronously.
_ONE_PACKET = b"\x00" * (LENGTH_FIELD_LEN + _AEAD_LEN)


class _ValidMessageTransport:
    """Fake ``_v2_transport``: every packet decodes as the SAME valid 'ping'
    message (never decoy, never unknown), so ``_receive_v2_message`` returns one
    real message per call — exactly the valid flood the per-read-timeout churn
    drove."""

    CONTENTS_LEN = _CONTENTS_LEN

    def decrypt_length(self, enc_length: bytes) -> int:
        assert len(enc_length) == LENGTH_FIELD_LEN
        return self.CONTENTS_LEN

    def decrypt_contents(self, aead_ct: bytes, contents_len: int):
        assert len(aead_ct) == HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        return _PING_CONTENTS, False  # (contents, is_decoy=False)


def _make_v2_peer(reader) -> Peer:
    p = Peer("10.0.0.9", 8333, network="mainnet")
    p.state = PeerState.READY
    p.handshake_complete = True
    p._v2_transport = _ValidMessageTransport()
    p.reader = reader
    return p


def _buffered_reader(n_packets: int) -> asyncio.StreamReader:
    """A REAL asyncio.StreamReader pre-fed with N back-to-back v2 packets so
    every read in the drive is satisfied SYNCHRONOUSLY from ``_buffer`` (the
    buffered-flood / leak case).  feed_eof so a short read raises
    IncompleteReadError rather than hanging if the framing ever drifts."""
    r = asyncio.StreamReader()
    r.feed_data(_ONE_PACKET * n_packets)
    return r


class _CallAtCounter:
    """Monkeypatch the running loop's ``call_at`` to count timer arms.

    ``asyncio.timeout`` arms its ``TimerHandle`` via ``loop.call_at(deadline,
    ...)``, so each ``call_at`` invocation == one timer armed.  We wrap (not
    replace) the real method so the loop keeps working."""

    def __init__(self, loop):
        self._loop = loop
        self._orig = loop.call_at
        self.count = 0

    def __enter__(self):
        def _counting_call_at(when, callback, *args, **kwargs):
            self.count += 1
            return self._orig(when, callback, *args, **kwargs)

        self._loop.call_at = _counting_call_at
        return self

    def reset(self):
        self.count = 0

    def __exit__(self, *exc):
        self._loop.call_at = self._orig
        return False


# --- Faithful local stand-ins for the two SUPERSEDED shapes -------------------
# These are NOT imported from peer.py (the fix removed them).  They let the test
# prove it is NON-VACUOUS: restoring either shape makes the fix's arming bound
# FAIL (arming jumps from ~0 to ~N or ~2N).


async def _orig_two_per_read_loop(reader, transport):
    """ORIGINAL shape: one ``asyncio.timeout`` per READ (length read + body
    read) — ~2 timers armed per message."""
    while True:
        async with asyncio.timeout(60.0):
            enc_length = await reader.readexactly(LENGTH_FIELD_LEN)
        contents_len = transport.decrypt_length(enc_length)
        aead_len = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        async with asyncio.timeout(60.0):
            aead_ct = await reader.readexactly(aead_len)
        contents, is_decoy = transport.decrypt_contents(aead_ct, contents_len)
        if is_decoy:
            continue
        decoded = decode_v2_contents(contents)
        if decoded is None:
            continue
        return decoded


async def _candidate_one_per_call_loop(reader, transport):
    """FAILED candidate (ef28190): one ``asyncio.timeout`` around the whole
    while-loop — ~1 timer armed per message."""
    async with asyncio.timeout(60.0):
        while True:
            enc_length = await reader.readexactly(LENGTH_FIELD_LEN)
            contents_len = transport.decrypt_length(enc_length)
            aead_len = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
            aead_ct = await reader.readexactly(aead_len)
            contents, is_decoy = transport.decrypt_contents(aead_ct, contents_len)
            if is_decoy:
                continue
            decoded = decode_v2_contents(contents)
            if decoded is None:
                continue
            return decoded


class TestV2RecvTimerArming(unittest.IsolatedAsyncioTestCase):
    async def _drive_fix(self, n: int) -> int:
        """Drive the REAL fixed ``_receive_v2_message`` N times over a fully
        buffered reader and return the number of timers armed."""
        reader = _buffered_reader(n)
        transport = _ValidMessageTransport()
        p = _make_v2_peer(reader)
        p._v2_transport = transport
        loop = asyncio.get_running_loop()
        with _CallAtCounter(loop) as counter:
            # Pre-roll any one-shot loop machinery, then reset.
            await asyncio.sleep(0)
            counter.reset()
            for _ in range(n):
                msg = await p._receive_v2_message(timeout=60.0)
                self.assertEqual(msg.command, "ping")
                self.assertEqual(msg.payload, _PING_PAYLOAD)
            return counter.count

    async def _drive_shape(self, loop_fn, n: int) -> int:
        reader = _buffered_reader(n)
        transport = _ValidMessageTransport()
        loop = asyncio.get_running_loop()
        with _CallAtCounter(loop) as counter:
            await asyncio.sleep(0)
            counter.reset()
            for _ in range(n):
                decoded = await loop_fn(reader, transport)
                self.assertEqual(decoded, ("ping", _PING_PAYLOAD))
            return counter.count

    async def test_fix_arms_zero_on_buffered_flood(self):
        """THE FIX: a fully-buffered flood arms ZERO timers (every read is
        synchronous, so ``_read_exactly`` skips ``asyncio.timeout`` entirely).
        Assert O(1), not O(N)."""
        n = 5_000
        armed = await self._drive_fix(n)
        self.assertLessEqual(
            armed,
            2,
            f"FIX armed {armed} timers over {n} fully-buffered messages; "
            f"expected ~0 (buffered reads must arm NO timer — Core parity).",
        )

    async def test_fix_arming_is_flat_in_n(self):
        """THE FIX: arming is FLAT — independent of N (the property the survival
        metric could not establish).  5k and 40k buffered messages arm the same
        (~0) count."""
        a5k = await self._drive_fix(5_000)
        a40k = await self._drive_fix(40_000)
        self.assertLessEqual(a5k, 2, f"fix armed {a5k} at N=5k; expected ~0")
        self.assertLessEqual(a40k, 2, f"fix armed {a40k} at N=40k; expected ~0")
        self.assertEqual(
            a40k,
            a5k,
            f"FIX arming scaled with N (5k -> {a5k}, 40k -> {a40k}); expected FLAT.",
        )

    async def test_candidate_shape_arms_linearly_one_per_msg(self):
        """NON-VACUOUS guard: restoring the FAILED candidate (one timeout per
        call) arms ~N — clearly O(N), which would BREAK the fix's O(1) bound.
        Proves the fix's assertion is not trivially satisfied by any shape."""
        n = 5_000
        armed = await self._drive_shape(_candidate_one_per_call_loop, n)
        self.assertGreaterEqual(
            armed,
            n // 2,
            f"candidate armed {armed} over {n} messages; expected ~N (1/msg).",
        )
        # And it is NOT ~2N — clearly one per message, below the original shape.
        self.assertLess(
            armed,
            2 * n,
            f"candidate armed {armed}; expected ~N (1/msg), well below 2N.",
        )

    async def test_original_shape_arms_two_per_read(self):
        """NON-VACUOUS guard: restoring the ORIGINAL per-read shape arms ~2N
        (one timer per read: length + body) — strictly MORE than the candidate's
        ~N and far above the fix's ~0."""
        n = 5_000
        armed = await self._drive_shape(_orig_two_per_read_loop, n)
        self.assertGreaterEqual(
            armed,
            n,
            f"original shape armed {armed} over {n} messages; expected ~2N.",
        )

    async def test_three_way_ordering_orig_gt_candidate_gt_fix(self):
        """The full discriminator the survival metric could not be:
        original (~2N)  >  candidate (~N)  >  fix (~0).  All measured at the
        SAME N over the SAME buffered flood."""
        n = 4_000
        fix = await self._drive_fix(n)
        candidate = await self._drive_shape(_candidate_one_per_call_loop, n)
        orig = await self._drive_shape(_orig_two_per_read_loop, n)

        self.assertLessEqual(fix, 2, f"fix arming {fix} not ~0")
        self.assertGreaterEqual(candidate, n // 2, f"candidate arming {candidate} not ~N")
        self.assertGreater(
            candidate, fix, f"candidate ({candidate}) must arm strictly more than fix ({fix})"
        )
        self.assertGreater(
            orig, candidate, f"original ({orig}) must arm strictly more than candidate ({candidate})"
        )
        self.assertGreaterEqual(orig, n, f"original arming {orig} not ~2N (>= N)")


class TestV2RecvStallPreserved(unittest.IsolatedAsyncioTestCase):
    """The leak elimination must NOT blunt the real stall/inactivity guard: a
    read that genuinely blocks must still arm a timer and raise TimeoutError."""

    async def test_empty_buffer_blocking_read_arms_and_times_out(self):
        """Empty buffer that never fills: the first (enc_length) read sees
        ``len(_buffer) < n`` -> ``_read_exactly`` arms ``asyncio.timeout`` ->
        ``readexactly`` suspends on never-fed data -> the timer fires ->
        TimeoutError.  Assert EXACTLY ONE timer was armed (the single blocking
        read), and that it raised."""
        reader = asyncio.StreamReader()  # empty, never fed
        p = _make_v2_peer(reader)
        loop = asyncio.get_running_loop()
        with _CallAtCounter(loop) as counter:
            await asyncio.sleep(0)
            counter.reset()
            with self.assertRaises(TimeoutError):
                await p._receive_v2_message(timeout=0.05)
            self.assertEqual(
                counter.count,
                1,
                f"empty-buffer stall armed {counter.count} timers; expected "
                f"exactly 1 (the blocking enc_length read).",
            )

    async def test_partial_then_stall_arms_on_body_read(self):
        """Realistic adversary: send only the 3 enc_length bytes (buffered, so
        the first read arms 0 timers) then HANG.  The AEAD-body read sees
        ``len(_buffer) < aead_len`` -> arms a timer -> suspends -> fires ->
        TimeoutError.  Proves the per-read buffer check still bounds an
        intra-message stall even when the message STARTS buffered — the
        call-spanning timeout the fix removed is not needed."""
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00" * LENGTH_FIELD_LEN)  # only the length prefix; body never arrives
        p = _make_v2_peer(reader)
        loop = asyncio.get_running_loop()
        with _CallAtCounter(loop) as counter:
            await asyncio.sleep(0)
            counter.reset()
            with self.assertRaises(TimeoutError):
                await p._receive_v2_message(timeout=0.05)
            # enc_length read was buffered (0 timers); body read blocked (1).
            self.assertEqual(
                counter.count,
                1,
                f"partial-then-stall armed {counter.count} timers; expected "
                f"exactly 1 (only the blocking AEAD-body read).",
            )

    async def test_too_many_consecutive_decoys_still_raises_v2error(self):
        """Decoy skip + MAX_CONSECUTIVE_V2_SKIP still raises V2TransportError
        (graceful disconnect), NOT TimeoutError — those raises live in untimed
        parse code, unchanged by the timer-scope fix."""

        class _AllDecoy:
            def decrypt_length(self, enc_length):
                return _CONTENTS_LEN

            def decrypt_contents(self, aead_ct, contents_len):
                return _PING_CONTENTS, True  # always decoy

        # Enough buffered decoy packets to exceed MAX_CONSECUTIVE_V2_SKIP.
        from ouroboros.peer import MAX_CONSECUTIVE_V2_SKIP

        reader = _buffered_reader(MAX_CONSECUTIVE_V2_SKIP + 5)
        p = _make_v2_peer(reader)
        p._v2_transport = _AllDecoy()
        with self.assertRaises(V2TransportError):
            await p._receive_v2_message(timeout=60.0)


if __name__ == "__main__":
    unittest.main()
