"""One slow-reading peer must not park trickled tx INV relay for every peer.

``PeerManager._trickle_loop`` used to ``await peer.send_message`` inline, peer
after peer.  ``Peer._bounded_drain`` waits while a paused transport's buffer is
still shrinking (it re-arms its stall window whenever *any* progress was made),
so a peer that reads a trickle of bytes holds the whole loop: every peer behind
it in the iteration waits until the slow buffer drains.

Core: ``CConnman::SocketSendData`` is non-blocking.  A full send buffer sets
``fPauseSend`` on THAT peer only; ``SendMessages`` for the other peers carries
on.  The fix dispatches each peer's trickle send as its own task and skips a
peer whose previous trickle send is still in flight (its queue stays due, as
Core leaves a paused peer's inventory timer expired).

No sockets: both peers use fake writers whose transport reports a buffer size.
"""
from __future__ import annotations

import asyncio
import time

import tests.conftest  # noqa: F401  (installs the sync stub first)
from ouroboros.p2p import PeerManager, TrickleQueue
from ouroboros.peer import Peer, PeerState

HIGH_WATER = 65536


class _FakeTransport:
    def __init__(self, unsent: int) -> None:
        self.unsent = unsent

    def get_write_buffer_size(self) -> int:
        return self.unsent

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return (HIGH_WATER // 4, HIGH_WATER)

    def abort(self) -> None:
        self.unsent = 0

    def close(self) -> None:
        pass

    def is_closing(self) -> bool:
        return False


class _FakeWriter:
    """StreamWriter stand-in. ``drain`` returns once the buffer is below the
    high-water mark; a shrinker task models a peer reading slowly."""

    def __init__(self, unsent: int) -> None:
        self.transport = _FakeTransport(unsent)
        self.writes: list[tuple[float, bytes]] = []

    def write(self, data: bytes) -> None:
        self.writes.append((time.monotonic(), data))

    async def drain(self) -> None:
        while self.transport.unsent > HIGH_WATER:
            await asyncio.sleep(0.005)

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass

    def is_closing(self) -> bool:
        return False

    def get_extra_info(self, *_a, **_k):
        return None


def _ready_peer(host: str, writer: _FakeWriter) -> Peer:
    peer = Peer(host, 8333, network="mainnet")
    peer.writer = writer
    peer.state = PeerState.READY
    peer.relay_txs = True
    peer._send_stall_timeout = 0.05
    return peer


def _due_queue(seed: int) -> TrickleQueue:
    q = TrickleQueue(is_inbound=True)
    q.add_tx(bytes([seed]) * 32, bytes([seed + 1]) * 32)
    q.next_send_time = 0.0
    return q


def test_slow_peer_does_not_park_trickle_for_honest_peer():
    async def run():
        pm = PeerManager(network="mainnet", listen=False, dns_seed=False)
        # 60 windows x 200 B above high water: ~3 s of slow-but-moving drain.
        slow_w = _FakeWriter(HIGH_WATER + 200 * 60)
        honest_w = _FakeWriter(0)
        slow = _ready_peer("203.0.113.1", slow_w)
        honest = _ready_peer("203.0.113.2", honest_w)
        slow_addr, honest_addr = "203.0.113.1:8333", "203.0.113.2:8333"
        pm.inbound_peers[slow_addr] = slow
        pm.inbound_peers[honest_addr] = honest
        # The slow peer is first in iteration order.
        pm._trickle_queues[slow_addr] = _due_queue(1)
        pm._trickle_queues[honest_addr] = _due_queue(3)

        async def shrink():
            while slow_w.transport.unsent > 0:
                await asyncio.sleep(0.05)
                slow_w.transport.unsent = max(0, slow_w.transport.unsent - 200)

        shrinker = asyncio.ensure_future(shrink())
        pm.running = True
        pm._trickle_interval = 0.01
        start = time.monotonic()
        loop_task = asyncio.ensure_future(pm._trickle_loop())
        try:
            while not honest_w.writes and time.monotonic() - start < 1.0:
                await asyncio.sleep(0.01)
            served_after = (honest_w.writes[0][0] - start
                            if honest_w.writes else None)
            assert served_after is not None and served_after < 1.0, (
                "honest peer's trickled INV was not sent within 1 s: the "
                "trickle loop is parked behind a slow-reading peer's drain")
            # The slow peer got its INV written too (it is slow, not dropped).
            assert slow_w.writes, "slow peer never got its trickled INV"
            assert slow.state == PeerState.READY
        finally:
            pm.running = False
            loop_task.cancel()
            shrinker.cancel()
            for t in (loop_task, shrinker):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
            for t in list(getattr(pm, "_trickle_send_tasks", {}).values()):
                t.cancel()
    asyncio.run(run())


def test_peer_with_send_in_flight_is_not_sent_again():
    """While a peer's trickle send is still draining, the loop must not stack
    another send on it; its queue stays due and is sent once it unblocks.

    Guards the fix's in-flight bookkeeping; the inline-await code on master
    satisfies it trivially, so it is a regression pin, not the repro."""
    async def run():
        pm = PeerManager(network="mainnet", listen=False, dns_seed=False)
        slow_w = _FakeWriter(HIGH_WATER + 200 * 10)
        slow = _ready_peer("203.0.113.1", slow_w)
        slow._send_stall_timeout = 5.0   # no progress, but well inside 5 s
        addr = "203.0.113.1:8333"
        pm.inbound_peers[addr] = slow
        pm._trickle_queues[addr] = _due_queue(1)
        pm.running = True
        pm._trickle_interval = 0.01
        loop_task = asyncio.ensure_future(pm._trickle_loop())
        try:
            await asyncio.sleep(0.05)
            assert len(slow_w.writes) == 1
            # A new tx becomes due while the first send is still draining.
            q = pm._trickle_queues[addr]
            q.add_tx(b"\x07" * 32, b"\x08" * 32)
            q.next_send_time = 0.0
            await asyncio.sleep(0.1)
            assert len(slow_w.writes) == 1, "second send stacked on a blocked peer"
            assert q.pending_count == 1
            slow_w.transport.unsent = 0          # the peer catches up
            for _ in range(100):
                if len(slow_w.writes) == 2:
                    break
                await asyncio.sleep(0.01)
            assert len(slow_w.writes) == 2, "queued INV never sent after unblock"
        finally:
            pm.running = False
            loop_task.cancel()
            try:
                await loop_task
            except (asyncio.CancelledError, Exception):
                pass
            for t in list(getattr(pm, "_trickle_send_tasks", {}).values()):
                t.cancel()
    asyncio.run(run())
