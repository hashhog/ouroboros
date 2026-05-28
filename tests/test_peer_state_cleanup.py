"""
Regression tests for ouroboros #146 — per-peer state cleanup on disconnect.

Pre-#146, every per-peer dict in PeerManager and BlockSync grew unbounded
over the process lifetime:

  - PeerManager._erlay_peers / _erlay_local_salts / _erlay_pending_recon
  - PeerManager.cmpct_peers / _package_peers
  - PeerManager._addr_relay_counts / _addr_relay_day
  - PeerManager.retry_counts / last_retry_time
  - BlockSync._peer_handlers (worst — held closures capturing the Peer
    instance, so the zombie Peer with all its buffers stayed alive)
  - BlockSync._unconnecting_headers_count
  - BlockSync._presync_states

In combination with the TrickleQueue.known_filter unbounded set (the
larger leak), this drove the wedge of PID 1771536 (RSS 58 GB / swap
89 GB / load 99).  This test pins the cleanup so a future refactor
cannot silently re-introduce the leak.
"""

import pytest

from ouroboros.p2p import PeerManager
from ouroboros.peer import Peer


@pytest.fixture
def peer_manager(tmp_path):
    return PeerManager(network="regtest", data_dir=str(tmp_path))


def _seed_per_peer_state(pm: PeerManager, addr: str) -> None:
    """Populate every per-addr dict in PeerManager with a dummy entry so
    the cleanup helper has something to drop."""
    pm._trickle_queues[addr] = object()  # standin
    pm._erlay_peers[addr] = object()
    pm._erlay_local_salts[addr] = 0xDEADBEEF
    pm._erlay_pending_recon[addr] = False
    pm.cmpct_peers.add(addr)
    pm._package_peers.add(addr)
    pm._addr_relay_counts[addr] = 7
    pm._addr_relay_day[addr] = 1_700_000_000.0
    pm.retry_counts[addr] = 3
    pm.last_retry_time[addr] = 1_700_000_000.0


def test_cleanup_peer_state_drops_all_per_addr_dicts(peer_manager):
    """_cleanup_peer_state must drop the entry from EVERY per-addr dict."""
    addr = "203.0.113.7:8333"
    _seed_per_peer_state(peer_manager, addr)

    peer_manager._cleanup_peer_state(addr)

    assert addr not in peer_manager._trickle_queues
    assert addr not in peer_manager._erlay_peers
    assert addr not in peer_manager._erlay_local_salts
    assert addr not in peer_manager._erlay_pending_recon
    assert addr not in peer_manager.cmpct_peers
    assert addr not in peer_manager._package_peers
    assert addr not in peer_manager._addr_relay_counts
    assert addr not in peer_manager._addr_relay_day
    assert addr not in peer_manager.retry_counts
    assert addr not in peer_manager.last_retry_time


def test_cleanup_peer_state_is_idempotent_for_unknown_addr(peer_manager):
    """Cleanup must be a no-op on an addr that was never tracked."""
    # Should not raise.
    peer_manager._cleanup_peer_state("198.51.100.42:8333")


def test_cleanup_peer_state_delegates_to_block_sync():
    """When PeerManager.block_sync is wired, cleanup_peer_state must
    delegate the per-peer-Peer cleanup to BlockSync.cleanup_peer."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        pm = PeerManager(network="regtest", data_dir=td)

        observed: list[str] = []

        class _FakeBlockSync:
            def cleanup_peer(self, addr: str) -> None:
                observed.append(addr)

        pm.block_sync = _FakeBlockSync()
        pm._cleanup_peer_state("192.0.2.1:8333")

        assert observed == ["192.0.2.1:8333"]


def test_block_sync_cleanup_peer_drops_peer_handlers_and_state():
    """BlockSync.cleanup_peer must drop the Peer-keyed _peer_handlers
    entry (the biggest single retention hazard — closures hold the
    Peer instance with all its buffers) and the per-peer header-state
    dicts.
    """
    from unittest.mock import Mock

    from ouroboros.block_sync import BlockSync

    bs = BlockSync(db=Mock(), validator=Mock(), peer_manager=Mock())

    peer = Peer("192.0.2.7", 8333, "regtest")
    addr = "192.0.2.7:8333"

    # Simulate the registered-handler state we'd see during a live connection.
    bs._peer_handlers[peer] = {"inv": lambda m: None}
    bs._unconnecting_headers_count[addr] = 4
    bs._presync_states[("192.0.2.7", 8333)] = object()

    bs.cleanup_peer(addr)

    assert peer not in bs._peer_handlers
    assert addr not in bs._unconnecting_headers_count
    assert ("192.0.2.7", 8333) not in bs._presync_states


def test_block_sync_cleanup_peer_is_idempotent():
    """Calling cleanup_peer twice must not raise."""
    from unittest.mock import Mock

    from ouroboros.block_sync import BlockSync

    bs = BlockSync(db=Mock(), validator=Mock(), peer_manager=Mock())
    bs.cleanup_peer("192.0.2.5:8333")
    bs.cleanup_peer("192.0.2.5:8333")  # no-op on second call


def test_block_sync_cleanup_peer_handles_malformed_addr():
    """Malformed addr (no colon, non-int port, ...) must not raise."""
    from unittest.mock import Mock

    from ouroboros.block_sync import BlockSync

    bs = BlockSync(db=Mock(), validator=Mock(), peer_manager=Mock())
    bs.cleanup_peer("not-an-addr")
    bs.cleanup_peer("192.0.2.5:not-a-port")


# ---------------------------------------------------------------------------
# 2026-05-28: event-driven cleanup trigger regression tests.
#
# Background — Peer.disconnect() now invokes an on_disconnect callback
# wired by PeerManager that runs _cleanup_peer_state synchronously at
# the disconnect event.  Before this change the only cleanup trigger
# was the 30 s maintain_connections poll, which observed 1 of 1497
# disconnects in the 2026-05-28 wedge of PID 1252927 (~0.07 % hit rate).
# These tests pin the new event-driven path so a refactor cannot
# silently regress back to poll-only.
# ---------------------------------------------------------------------------


async def test_peer_disconnect_fires_on_disconnect_callback_exactly_once():
    """``Peer.disconnect`` must invoke ``on_disconnect(addr)`` exactly once,
    even if disconnect() is called multiple times.  This is the contract
    PeerManager relies on for event-driven cleanup; if disconnect double-fires
    the callback we'd risk double-clean state we just re-populated on reconnect.
    """
    calls: list[str] = []

    def cb(addr: str) -> None:
        calls.append(addr)

    peer = Peer("203.0.113.42", 18333, "regtest", on_disconnect=cb)

    await peer.disconnect()
    # Second call is a no-op per the existing latch (_disconnect_started)
    # and must not re-fire the callback.
    await peer.disconnect()

    assert calls == ["203.0.113.42:18333"]


async def test_peer_disconnect_swallows_callback_exception():
    """A buggy cleanup callback MUST NOT block socket teardown.
    Without this guarantee, a single transient cleanup failure could
    leave a peer half-disconnected with sockets still open.
    """

    def cb(addr: str) -> None:
        raise RuntimeError("simulated cleanup bug")

    peer = Peer("203.0.113.43", 18333, "regtest", on_disconnect=cb)
    # Must not raise.
    await peer.disconnect()
    from ouroboros.peer import PeerState
    assert peer.state == PeerState.DISCONNECTED


async def test_peer_manager_event_driven_cleanup_drops_state_on_disconnect(
    peer_manager,
):
    """End-to-end: a Peer constructed by PeerManager must, on disconnect,
    pop itself from the inbound bucket AND drop all per-addr state via the
    event-driven hook — without any poll-loop tick.
    """
    addr = "198.51.100.99:8333"
    host, port = "198.51.100.99", 8333

    # Construct the peer the way PeerManager does in _handle_inbound_connection,
    # wiring the on_disconnect callback into the manager.
    peer = Peer(
        host, port, "regtest",
        inbound=True,
        on_disconnect=peer_manager._handle_peer_disconnected,
    )

    # Place into the inbound bucket and seed all per-addr caches.
    peer_manager.inbound_peers[addr] = peer
    _seed_per_peer_state(peer_manager, addr)

    await peer.disconnect()

    # Bucket: removed by the event-driven hook (no maintain_connections poll
    # ran here — the cleanup happened synchronously inside disconnect()).
    assert addr not in peer_manager.inbound_peers

    # Per-addr caches: all dropped via _cleanup_peer_state.
    assert addr not in peer_manager._trickle_queues
    assert addr not in peer_manager._erlay_peers
    assert addr not in peer_manager._erlay_local_salts
    assert addr not in peer_manager._erlay_pending_recon
    assert addr not in peer_manager.cmpct_peers
    assert addr not in peer_manager._package_peers
    assert addr not in peer_manager._addr_relay_counts
    assert addr not in peer_manager._addr_relay_day
    assert addr not in peer_manager.retry_counts
    assert addr not in peer_manager.last_retry_time


async def test_peer_manager_event_driven_cleanup_fires_exactly_once(peer_manager):
    """Idempotence: calling disconnect twice must drive the cleanup exactly
    once, not twice — otherwise the cleanup could clobber state set up by
    a reconnect under the same addr that raced in between calls.
    """
    addr = "198.51.100.77:8333"
    host, port = "198.51.100.77", 8333

    cleanup_calls: list[str] = []
    original_cleanup = peer_manager._cleanup_peer_state

    def counting_cleanup(a: str) -> None:
        cleanup_calls.append(a)
        original_cleanup(a)

    peer_manager._cleanup_peer_state = counting_cleanup  # type: ignore[method-assign]

    peer = Peer(
        host, port, "regtest",
        inbound=True,
        on_disconnect=peer_manager._handle_peer_disconnected,
    )
    peer_manager.inbound_peers[addr] = peer

    await peer.disconnect()
    await peer.disconnect()  # second call no-ops

    assert cleanup_calls == [addr]


async def test_event_driven_cleanup_handles_peer_not_in_any_bucket(peer_manager):
    """A Peer whose addr was already popped from the bucket (e.g. by
    _on_peer_banned or _evict_inbound_peer, both of which pop BEFORE
    scheduling disconnect) must still trigger the per-addr cleanup —
    the bucket pop is best-effort, the state cleanup is what matters.
    """
    addr = "198.51.100.55:8333"
    host, port = "198.51.100.55", 8333

    # Seed per-addr state but DO NOT add to any bucket; this simulates the
    # bucket-already-popped path.
    _seed_per_peer_state(peer_manager, addr)

    peer = Peer(
        host, port, "regtest",
        inbound=True,
        on_disconnect=peer_manager._handle_peer_disconnected,
    )
    # NOTE: peer was never added to peer_manager.inbound_peers.

    await peer.disconnect()

    # Cleanup still ran — the bucket pop was a no-op but the state cleanup
    # fired anyway.
    assert addr not in peer_manager._trickle_queues
    assert addr not in peer_manager._erlay_peers


async def test_event_driven_cleanup_delegates_to_block_sync(peer_manager):
    """The event-driven cleanup must reach BlockSync.cleanup_peer too
    — that's where _peer_handlers (the closure-retention hazard that
    caused the ~6-10 GB leak in PID 1252927) lives.
    """
    addr = "198.51.100.88:8333"
    host, port = "198.51.100.88", 8333

    observed: list[str] = []

    class _FakeBlockSync:
        def cleanup_peer(self, a: str) -> None:
            observed.append(a)

    peer_manager.block_sync = _FakeBlockSync()

    peer = Peer(
        host, port, "regtest",
        inbound=True,
        on_disconnect=peer_manager._handle_peer_disconnected,
    )
    peer_manager.inbound_peers[addr] = peer

    await peer.disconnect()

    assert observed == [addr]


async def test_peer_disconnect_without_callback_is_noop():
    """Backwards compatibility: a Peer constructed without on_disconnect
    must disconnect cleanly without invoking any callback (unit tests
    that build a bare Peer relied on this for years).
    """
    peer = Peer("203.0.113.1", 8333, "regtest")  # no on_disconnect
    await peer.disconnect()  # must not raise
