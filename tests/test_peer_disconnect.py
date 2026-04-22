"""
Regression tests for Peer.disconnect() — self-await and double-call safety.

Bug observed in mainnet log 2026-04-22: disconnect() was awaiting
self._listen_task from inside the listener coroutine, which IS that
task.  A task cannot await itself, and the concurrent double-call
path compounded the issue; asyncio reported:

    future: <Task finished ... coro=<Peer.disconnect() ...>
            exception=RuntimeError("await wasn't used with future")>
"""

import asyncio

import pytest

from ouroboros.peer import Peer, PeerState


@pytest.fixture
def peer():
    return Peer("10.0.0.1", 8333, "regtest")


async def test_disconnect_idempotent(peer):
    """Double-call should no-op the second time, not raise."""
    await peer.disconnect()
    assert peer.state == PeerState.DISCONNECTED
    # Second call must not raise (previously could if _listen_task was set).
    await peer.disconnect()
    assert peer.state == PeerState.DISCONNECTED


async def test_disconnect_from_within_own_listen_task(peer):
    """
    When disconnect() is invoked from a coroutine that IS _listen_task,
    we must skip awaiting it (a task cannot await itself).  Before the
    fix this path raised RuntimeError("await wasn't used with future").
    """
    ran = asyncio.Event()

    async def fake_listen():
        ran.set()
        # Simulate the listener calling disconnect() on itself after an
        # error — same path as peer.py:1007 (`except Exception: await
        # self.disconnect()`).
        await peer.disconnect()

    peer._listen_task = asyncio.create_task(fake_listen())
    await peer._listen_task
    await ran.wait()
    assert peer.state == PeerState.DISCONNECTED


async def test_disconnect_cancels_external_listen_task(peer):
    """When disconnect is called from a DIFFERENT task, _listen_task is cancelled and awaited."""
    started = asyncio.Event()

    async def external_listen():
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            raise

    peer._listen_task = asyncio.create_task(external_listen())
    await started.wait()
    await peer.disconnect()
    assert peer.state == PeerState.DISCONNECTED
    assert peer._listen_task.done()


async def test_disconnect_concurrent_double_call(peer):
    """Two disconnect()s scheduled together must both succeed without RuntimeError."""
    started = asyncio.Event()

    async def external_listen():
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            raise

    peer._listen_task = asyncio.create_task(external_listen())
    await started.wait()
    # Schedule both in the same event-loop tick.
    results = await asyncio.gather(
        peer.disconnect(), peer.disconnect(), return_exceptions=True
    )
    for r in results:
        assert not isinstance(r, Exception), f"disconnect raised: {r!r}"
    assert peer.state == PeerState.DISCONNECTED
