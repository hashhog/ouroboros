"""Regression test for the at-tip v2-receive memory burst (tracemalloc, 2026-06-09).

Root cause: ``Peer._receive_v2_message`` (peer.py) has an inner ``while True:``
that loops once per BIP 324 decoy / unknown-short-id packet.  ``readexactly``
returns SYNCHRONOUSLY whenever the asyncio StreamReader buffer already holds the
bytes, so a peer that pre-buffers a flood of decoy / unknown / zero-length v2
packets turned ONE ``_receive_v2_message`` call into an unbounded CPU-bound
spin: it never yielded to the event loop (starving cyclic GC and other peers)
and allocated a ``wait_for`` Task per iteration.  Live tracemalloc on mainnet
captured ~5.18M retained {readexactly coro, _receive_v2_message coro, wait_for
Task} triples growing in lock-step at ~4,800/sec, RSS climbing ~3.7 GB / 5 min
toward the cgroup cap.

Bitcoin Core can never busy-spin on decoys: ``V2Transport::ReceivedBytes``
consumes only the bytes delivered by ONE bounded ``Recv`` per socket-readiness
event (net.cpp:2183, 64 KiB), ignores decoys (net.cpp:1248 ``if (!ignore)``)
and drops unknown message types while keeping the connection (net.cpp:1474-1477),
then returns to the poll loop.

The fix bounds the consecutive non-message run per call to
``MAX_CONSECUTIVE_V2_SKIP`` and ``await asyncio.sleep(0)``s on each skip:
  * decoys are still silently dropped, unknown short-ids still drop-and-keep,
    real messages are still returned (correct v2 behavior preserved);
  * an honest interleave never trips the bound (a real message ``return``s out
    of the call, resetting the counter on the next call);
  * an EXCESSIVE flood raises ``V2TransportError``, which ``listen()`` already
    turns into a graceful disconnect (peer.py except V2TransportError arm).

This test drives ``_receive_v2_message`` with an effectively-infinite buffered
flood of decoy packets and asserts it (a) does NOT spin unboundedly — it stops
after ~MAX_CONSECUTIVE_V2_SKIP reads — and (b) raises ``V2TransportError`` so
the listen loop disconnects.  A second case interleaves a real message before
the bound and asserts it is returned normally (no false trip).
"""

import asyncio
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.peer import (  # noqa: E402
    MAX_CONSECUTIVE_V2_SKIP,
    Peer,
    PeerState,
    V2TransportError,
)
from ouroboros.transport_v2 import (  # noqa: E402
    CHACHA20POLY1305_EXPANSION,
    HEADER_LEN,
    LENGTH_FIELD_LEN,
)


class _FloodReader:
    """Stand-in StreamReader that hands back already-buffered v2 packet bytes
    synchronously (never suspends) — exactly the pathological case where
    readexactly does not yield to the event loop.  ``reads`` counts how many
    readexactly calls were served so we can prove the loop is BOUNDED."""

    def __init__(self):
        self.reads = 0

    async def readexactly(self, n: int) -> bytes:
        self.reads += 1
        # Synchronous return — mimics a pre-filled buffer (no await suspension).
        return b"\x00" * n


class _DecoyTransport:
    """Fake _v2_transport: every packet decodes as a (well-formed) decoy, so
    _receive_v2_message takes the is_decoy ``continue`` branch every time."""

    # contents_len 0: a minimal decoy is HEADER_LEN + 0 + tag bytes.
    CONTENTS_LEN = 0

    def decrypt_length(self, enc_length: bytes) -> int:
        assert len(enc_length) == LENGTH_FIELD_LEN
        return self.CONTENTS_LEN

    def decrypt_contents(self, aead_ct: bytes, contents_len: int):
        assert len(aead_ct) == HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        # (contents, is_decoy=True)
        return b"", True


class _RealMessageAfterTransport(_DecoyTransport):
    """Like _DecoyTransport but the Nth decrypt_contents returns a real (non
    decoy) packet so we can prove a real message ends the call cleanly."""

    def __init__(self, real_after: int):
        self._calls = 0
        self._real_after = real_after

    def decrypt_contents(self, aead_ct: bytes, contents_len: int):
        self._calls += 1
        if self._calls >= self._real_after:
            return self._real_contents, False
        return b"", True


def _make_v2_peer(transport) -> Peer:
    p = Peer("10.0.0.9", 8333, network="mainnet")
    p.state = PeerState.READY
    p.handshake_complete = True
    p._v2_transport = transport
    p.reader = _FloodReader()
    return p


class TestV2DecoyFloodBound(unittest.IsolatedAsyncioTestCase):
    async def test_decoy_flood_does_not_spin_unboundedly(self):
        """A peer flooding buffered decoy packets must NOT spin
        _receive_v2_message unboundedly; it must raise V2TransportError after
        the bounded consecutive-skip budget so listen() disconnects."""
        p = _make_v2_peer(_DecoyTransport())

        # Guard against a true infinite spin: if the bound is broken, the
        # synchronous reader would loop forever and wait_for trips at 2 s.
        with self.assertRaises(V2TransportError):
            await asyncio.wait_for(p._receive_v2_message(timeout=60.0), timeout=2.0)

        # Two readexactly per iteration (length + body); we must stop right
        # after exceeding the skip budget, never having looped unboundedly.
        max_expected_reads = 2 * (MAX_CONSECUTIVE_V2_SKIP + 1) + 2
        self.assertLessEqual(
            p.reader.reads, max_expected_reads,
            f"loop should stop after ~{MAX_CONSECUTIVE_V2_SKIP} decoys, "
            f"but served {p.reader.reads} reads",
        )
        # And it really did read roughly the whole budget (didn't stop early).
        self.assertGreaterEqual(p.reader.reads, 2 * MAX_CONSECUTIVE_V2_SKIP)

    async def test_decoy_flood_disconnects_via_listen(self):
        """End-to-end: the V2TransportError raised by the bound flows up
        through listen()'s existing handler and disconnects the peer."""
        p = _make_v2_peer(_DecoyTransport())

        class _DummyWriter:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

            async def wait_closed(self):
                return None

        p.writer = _DummyWriter()
        p._listen_task = None
        p._ping_task = None

        await asyncio.wait_for(p.listen(), timeout=2.0)
        self.assertEqual(p.state, PeerState.DISCONNECTED)

    async def test_real_message_before_bound_is_returned(self):
        """An honest interleave (some decoys then a real message) must NOT trip
        the bound — the real message is returned and the call ends, resetting
        the per-call counter."""
        # A real, well-formed v2 contents: short-id for "ping" + payload.
        from ouroboros.transport_v2 import decode_v2_contents, encode_v2_contents

        real_contents = encode_v2_contents("ping", b"\x01\x02\x03\x04\x05\x06\x07\x08")
        # sanity: it round-trips to a real message, not a decoy/unknown.
        assert decode_v2_contents(real_contents) is not None

        # Decoy for the first (MAX//2) packets, then a real message — well
        # under the bound, so no disconnect.
        real_after = MAX_CONSECUTIVE_V2_SKIP // 2
        transport = _RealMessageAfterTransport(real_after=real_after)
        transport._real_contents = real_contents

        p = _make_v2_peer(transport)
        msg = await asyncio.wait_for(
            p._receive_v2_message(timeout=60.0), timeout=2.0
        )
        self.assertEqual(msg.command, "ping")
        self.assertEqual(msg.payload, b"\x01\x02\x03\x04\x05\x06\x07\x08")


if __name__ == "__main__":
    unittest.main()
