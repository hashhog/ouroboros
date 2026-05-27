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
