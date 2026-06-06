"""Regression test for the at-tip EOF/dead-socket spin in Peer.listen().

Root cause (residual at-tip RSS leak after the block-request-map fix
893bbc7): when a peer hangs up, ``asyncio.StreamReader.readexactly`` raises
``asyncio.IncompleteReadError`` (a subclass of ``EOFError``) IMMEDIATELY and
forever — once the stream is at EOF the read never blocks again.  The
``listen()`` loop previously caught that in the generic ``except Exception``
arm, which only docked the peer's score by 5 and ``continue``d.  Score starts
at 100, so a hung-up peer spun the receive loop ~20 times back-to-back (each
iteration re-reading EOF instantly + allocating an exception + a formatted log
line) before the score finally clamped to 0 and the peer disconnected.

At chain tip, where peers churn constantly, that hot-spin + per-iteration
allocation churn was a steady CPU/RSS drain, and — worse — it delayed the
``disconnect()`` call that fires the per-peer cleanup hook
(``_handle_peer_disconnected`` -> ``_cleanup_peer_state``), so zombie Peer
state (trickle queues, transport buffers, BIP-324 state) lingered.

The fix adds a dedicated ``except`` arm for EOF / dead-socket errors
(``IncompleteReadError`` / ``EOFError`` / ``ConnectionError`` /
``ConnectionResetError`` / ``BrokenPipeError`` / ``OSError``) that calls
``disconnect()`` and ``break``s immediately — mirroring Bitcoin Core's
``CConnman::SocketHandler`` (``nBytes == 0`` => disconnect at once), instead
of spinning until the score clamps.

This test asserts that on EOF the loop (a) terminates promptly, (b) calls
``receive_message`` only ONCE (no hot spin), and (c) disconnects the peer.
"""

import asyncio
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.peer import Peer, PeerState  # noqa: E402


class _DummyWriter:
    """Minimal asyncio.StreamWriter stand-in for disconnect()."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _make_ready_peer() -> Peer:
    p = Peer("10.0.0.1", 8333, network="mainnet")
    p.state = PeerState.READY
    p.handshake_complete = True
    # disconnect() touches reader/writer; give it harmless stand-ins.
    p.reader = object()
    p.writer = _DummyWriter()
    # No listener/ping tasks to cancel in the unit test.
    p._listen_task = None
    p._ping_task = None
    return p


class TestPeerEofDisconnect(unittest.IsolatedAsyncioTestCase):
    async def test_eof_disconnects_without_spin(self):
        """An EOF on the wire must disconnect the peer on the FIRST read,
        not spin the receive loop ~20 times until the score clamps."""
        p = _make_ready_peer()

        calls = {"recv": 0, "score": 0}

        async def _recv(timeout=60.0):
            calls["recv"] += 1
            # Simulate a hung-up peer: readexactly(24) raises this the instant
            # the stream is at EOF, and would keep raising it on every retry.
            raise asyncio.IncompleteReadError(partial=b"", expected=24)

        # If the loop ever falls into the generic score-docking arm we want to
        # see it; the EOF arm must not touch the score.
        orig_adjust = p.adjust_score

        def _adjust(delta):
            calls["score"] += 1
            return orig_adjust(delta)

        p.receive_message = _recv
        p.adjust_score = _adjust

        # listen() must return promptly; guard against an infinite spin.
        await asyncio.wait_for(p.listen(), timeout=2.0)

        self.assertEqual(
            calls["recv"], 1,
            "EOF should disconnect on the first read, not spin the loop "
            f"(got {calls['recv']} receive_message calls)",
        )
        self.assertEqual(
            calls["score"], 0,
            "EOF path must not dock score / route through the slow "
            "score-clamp disconnect",
        )
        self.assertEqual(p.state, PeerState.DISCONNECTED)
        self.assertTrue(p.writer is None or p._disconnect_started)

    async def test_connection_reset_disconnects(self):
        """A ConnectionResetError (peer RST) is also a dead socket and must
        disconnect immediately rather than spin."""
        p = _make_ready_peer()
        calls = {"recv": 0}

        async def _recv(timeout=60.0):
            calls["recv"] += 1
            raise ConnectionResetError("peer reset")

        p.receive_message = _recv
        await asyncio.wait_for(p.listen(), timeout=2.0)

        self.assertEqual(calls["recv"], 1)
        self.assertEqual(p.state, PeerState.DISCONNECTED)

    async def test_fires_disconnect_cleanup_hook_on_eof(self):
        """The EOF path must reach disconnect(), which fires the per-peer
        cleanup hook PeerManager wires in — this is what tears down the
        zombie per-peer caches (trickle queue, erlay, transport buffers)
        that drove the leak.  Pre-fix the hook fired only after the slow
        score-clamp (or the 30 s maintain_connections poll)."""
        fired = []
        p = Peer(
            "10.0.0.2", 8333, network="mainnet",
            on_disconnect=lambda addr: fired.append(addr),
        )
        p.state = PeerState.READY
        p.handshake_complete = True
        p.reader = object()
        p.writer = _DummyWriter()
        p._listen_task = None
        p._ping_task = None

        async def _recv(timeout=60.0):
            raise asyncio.IncompleteReadError(partial=b"", expected=24)

        p.receive_message = _recv
        await asyncio.wait_for(p.listen(), timeout=2.0)

        self.assertEqual(fired, ["10.0.0.2:8333"])
        self.assertEqual(p.state, PeerState.DISCONNECTED)


if __name__ == "__main__":
    unittest.main()
