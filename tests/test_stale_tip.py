"""
Tests for stale tip detection and peer eviction.

Reference: Bitcoin Core net_processing.cpp TipMayBeStale(), ConsiderEviction(),
EvictExtraOutboundPeers()
"""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock

from ouroboros.sync_manager import (
    MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
    MINIMUM_CONNECT_TIME,
    STALE_TIP_AGE_THRESHOLD,
    STALE_TIP_TIMESTAMP_THRESHOLD,
    PeerChainSyncState,
    StaleTipDetector,
)


def _make_mock_peer(
    host: str = "10.0.0.1",
    port: int = 8333,
    connected: bool = True,
    connected_at: float = 0.0,
) -> MagicMock:
    """Create a mock Peer object for testing."""
    peer = MagicMock()
    peer.host = host
    peer.port = port
    peer.connected_at = connected_at or time.time()
    peer.is_connected = MagicMock(return_value=connected)
    peer.disconnect = AsyncMock()
    peer.send_message = AsyncMock()
    return peer


def _make_mock_peer_manager(num_peers: int = 8) -> MagicMock:
    """Create a mock PeerManager with configurable number of outbound peers."""
    pm = MagicMock()
    pm.network = "regtest"
    pm.peers = {}

    for i in range(num_peers):
        addr = f"10.0.0.{i + 1}:8333"
        pm.peers[addr] = _make_mock_peer(
            host=f"10.0.0.{i + 1}",
            connected_at=time.time() - (num_peers - i) * 100,
        )

    pm.block_relay_peers = {}
    pm.inbound_peers = {}
    pm.get_all_ready_peers = MagicMock(
        return_value=list(pm.peers.values())
    )
    return pm


def _make_mock_db(best_height: int = 100, best_hash: bytes = b"\x00" * 32) -> MagicMock:
    """Create a mock BlockchainDatabase."""
    db = MagicMock()
    db.get_best_block = MagicMock(return_value=(best_hash, best_height))
    db.get_block_hash_by_height = MagicMock(return_value=b"\x01" * 32)
    return db


# ── TipMayBeStale ─────────────────────────────────────────────────────


class TestTipMayBeStale(unittest.TestCase):
    """Tests for StaleTipDetector.tip_may_be_stale()."""

    def test_fresh_tip_not_stale(self):
        """A recently updated tip should not be considered stale."""
        detector = StaleTipDetector()
        now = time.time()

        # Update tip with recent timestamp
        detector.update_tip(100, int(now) - 60)

        self.assertFalse(detector.tip_may_be_stale())

    def test_old_update_but_recent_timestamp_not_stale(self):
        """Tip with old update time but recent timestamp is not stale.

        This prevents false positives during initial sync - even if we
        haven't received a new block in a while, if the tip timestamp
        is recent, we're probably near the chain tip.
        """
        detector = StaleTipDetector()
        now = time.time()

        # Set last update to long ago
        detector._last_tip_update = now - (STALE_TIP_AGE_THRESHOLD + 100)
        detector._last_tip_height = 100
        # But tip timestamp is recent (within 24 hours)
        detector._last_tip_timestamp = int(now) - 3600  # 1 hour old

        self.assertFalse(detector.tip_may_be_stale())

    def test_old_update_and_old_timestamp_is_stale(self):
        """Tip with old update time AND old timestamp is stale."""
        detector = StaleTipDetector()
        now = time.time()

        # Set last update to > 30 min ago
        detector._last_tip_update = now - (STALE_TIP_AGE_THRESHOLD + 100)
        detector._last_tip_height = 100
        # And tip timestamp is > 24 hours old
        detector._last_tip_timestamp = int(now) - (STALE_TIP_TIMESTAMP_THRESHOLD + 100)

        self.assertTrue(detector.tip_may_be_stale())

    def test_update_tip_resets_staleness(self):
        """Calling update_tip() resets the stale state."""
        detector = StaleTipDetector()
        now = time.time()

        # Make tip stale
        detector._last_tip_update = now - (STALE_TIP_AGE_THRESHOLD + 100)
        detector._last_tip_timestamp = int(now) - (STALE_TIP_TIMESTAMP_THRESHOLD + 100)
        detector._last_tip_height = 100

        self.assertTrue(detector.tip_may_be_stale())

        # Update tip advances things
        detector.update_tip(101, int(now))

        self.assertFalse(detector.tip_may_be_stale())


# ── PeerChainSyncState ─────────────────────────────────────────────────


class TestPeerChainSyncState(unittest.TestCase):
    """Tests for PeerChainSyncState dataclass."""

    def test_initial_state(self):
        """Initial state has no timeout set."""
        state = PeerChainSyncState()
        self.assertEqual(state.timeout, 0.0)
        self.assertEqual(state.work_header_height, 0)
        self.assertFalse(state.sent_getheaders)
        self.assertFalse(state.protect)

    def test_reset_clears_timeout(self):
        """reset() clears all timeout state."""
        state = PeerChainSyncState(
            timeout=time.time() + 100,
            work_header_height=500,
            sent_getheaders=True,
        )

        state.reset()

        self.assertEqual(state.timeout, 0.0)
        self.assertEqual(state.work_header_height, 0)
        self.assertFalse(state.sent_getheaders)


# ── ConsiderEviction ─────────────────────────────────────────────────────


class TestConsiderEviction(unittest.TestCase):
    """Tests for StaleTipDetector.consider_eviction()."""

    def test_peer_at_tip_not_evicted(self):
        """Peer at or ahead of our tip is not evicted."""
        detector = StaleTipDetector(peer_manager=_make_mock_peer_manager())
        detector._last_tip_height = 100

        loop = asyncio.new_event_loop()
        try:
            # Peer at same height
            result = loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=100)
            )
            self.assertFalse(result)

            # Peer ahead
            result = loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=105)
            )
            self.assertFalse(result)
        finally:
            loop.close()

    def test_peer_behind_sets_timeout(self):
        """First time noticing peer behind sets a timeout."""
        detector = StaleTipDetector(peer_manager=_make_mock_peer_manager())
        detector._last_tip_height = 100

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=50)
            )
            self.assertFalse(result)  # Not evicted yet

            # Timeout should be set
            state = detector._peer_sync_states.get("10.0.0.1:8333")
            self.assertIsNotNone(state)
            self.assertGreater(state.timeout, time.time())
            self.assertEqual(state.work_header_height, 100)
            self.assertFalse(state.sent_getheaders)
        finally:
            loop.close()

    def test_peer_catching_up_resets_timeout(self):
        """Peer catching up to our tip resets the timeout."""
        detector = StaleTipDetector(peer_manager=_make_mock_peer_manager())
        detector._last_tip_height = 100

        loop = asyncio.new_event_loop()
        try:
            # First, set a timeout
            loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=50)
            )
            state = detector._peer_sync_states.get("10.0.0.1:8333")
            self.assertGreater(state.timeout, 0)

            # Peer catches up
            loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=100)
            )
            self.assertEqual(state.timeout, 0.0)
        finally:
            loop.close()

    def test_protected_peer_not_evicted(self):
        """Protected peers are never evicted."""
        detector = StaleTipDetector(peer_manager=_make_mock_peer_manager())
        detector._last_tip_height = 100

        # Mark peer as protected
        detector._peer_sync_states["10.0.0.1:8333"] = PeerChainSyncState(
            protect=True
        )

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                detector.consider_eviction("10.0.0.1:8333", peer_height=0)
            )
            self.assertFalse(result)
        finally:
            loop.close()


# ── record_peer_block ─────────────────────────────────────────────────


class TestRecordPeerBlock(unittest.TestCase):
    """Tests for StaleTipDetector.record_peer_block()."""

    def test_records_block_time_and_height(self):
        """record_peer_block updates tracking for peer."""
        detector = StaleTipDetector()

        detector.record_peer_block("10.0.0.1:8333", 100)

        block_time, height = detector._peer_block_times.get("10.0.0.1:8333")
        self.assertAlmostEqual(block_time, time.time(), delta=2.0)
        self.assertEqual(height, 100)

    def test_higher_height_updates(self):
        """Higher block height updates the record."""
        detector = StaleTipDetector()

        detector.record_peer_block("10.0.0.1:8333", 100)
        _, height1 = detector._peer_block_times.get("10.0.0.1:8333")

        detector.record_peer_block("10.0.0.1:8333", 105)
        _, height2 = detector._peer_block_times.get("10.0.0.1:8333")

        self.assertEqual(height1, 100)
        self.assertEqual(height2, 105)

    def test_lower_height_does_not_update(self):
        """Lower block height does not update the record."""
        detector = StaleTipDetector()

        detector.record_peer_block("10.0.0.1:8333", 100)
        _, height1 = detector._peer_block_times.get("10.0.0.1:8333")

        detector.record_peer_block("10.0.0.1:8333", 90)
        _, height2 = detector._peer_block_times.get("10.0.0.1:8333")

        self.assertEqual(height1, 100)
        self.assertEqual(height2, 100)  # Should not change

    def test_resets_sync_timeout_when_caught_up(self):
        """Recording a block resets sync timeout if peer caught up."""
        detector = StaleTipDetector()
        detector._last_tip_height = 100

        # Set a timeout for the peer
        detector._peer_sync_states["10.0.0.1:8333"] = PeerChainSyncState(
            timeout=time.time() + 1000,
            work_header_height=95,
        )

        # Peer provides block at our tip height
        detector.record_peer_block("10.0.0.1:8333", 100)

        state = detector._peer_sync_states.get("10.0.0.1:8333")
        self.assertEqual(state.timeout, 0.0)


# ── EvictExtraOutboundPeers ─────────────────────────────────────────────


class TestEvictExtraOutboundPeers(unittest.TestCase):
    """Tests for StaleTipDetector._evict_extra_outbound_peers()."""

    def test_no_eviction_when_at_limit(self):
        """No eviction when at or below the connection limit."""
        pm = _make_mock_peer_manager(num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)
        detector = StaleTipDetector(peer_manager=pm)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                detector._evict_extra_outbound_peers(time.time())
            )
            # All peers should still be present
            self.assertEqual(
                len(pm.peers), MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
            )
        finally:
            loop.close()

    def test_evicts_when_over_limit(self):
        """Evicts worst peer when over the connection limit."""
        pm = _make_mock_peer_manager(
            num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + 1
        )
        detector = StaleTipDetector(peer_manager=pm)

        # Record different block times for each peer
        now = time.time()
        for i, addr in enumerate(pm.peers.keys()):
            detector._peer_block_times[addr] = (now - (i * 100), 100)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                detector._evict_extra_outbound_peers(now)
            )
            # One peer should have been removed
            self.assertEqual(
                len(pm.peers), MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
            )
        finally:
            loop.close()

    def test_evicts_peer_with_oldest_block_time(self):
        """Evicts the peer that least recently provided a block."""
        pm = _make_mock_peer_manager(
            num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + 1
        )
        detector = StaleTipDetector(peer_manager=pm)

        now = time.time()
        # All peers have minimum connect time
        for _, peer in pm.peers.items():
            peer.connected_at = now - MINIMUM_CONNECT_TIME - 10

        # Set block times - oldest is 10.0.0.5
        oldest_addr = None
        for i, addr in enumerate(pm.peers.keys()):
            if i == 4:
                detector._peer_block_times[addr] = (now - 10000, 100)  # Very old
                oldest_addr = addr
            else:
                detector._peer_block_times[addr] = (now - i * 10, 100)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                detector._evict_extra_outbound_peers(now)
            )
            # The oldest peer should be evicted
            self.assertNotIn(oldest_addr, pm.peers)
        finally:
            loop.close()

    def test_respects_minimum_connect_time(self):
        """Does not evict peers connected less than MINIMUM_CONNECT_TIME."""
        pm = _make_mock_peer_manager(
            num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + 1
        )
        detector = StaleTipDetector(peer_manager=pm)

        now = time.time()
        # All peers just connected (below minimum time)
        for _addr, peer in pm.peers.items():
            peer.connected_at = now - 5  # Only 5 seconds

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                detector._evict_extra_outbound_peers(now)
            )
            # No peers should be evicted (all too recently connected)
            self.assertEqual(
                len(pm.peers), MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + 1
            )
        finally:
            loop.close()


# ── should_try_extra_outbound ─────────────────────────────────────────────


class TestShouldTryExtraOutbound(unittest.TestCase):
    """Tests for StaleTipDetector.should_try_extra_outbound()."""

    def test_returns_false_when_not_stale(self):
        """Returns False when tip is not stale."""
        detector = StaleTipDetector(
            peer_manager=_make_mock_peer_manager(num_peers=8)
        )
        detector._try_extra_outbound = False

        self.assertFalse(detector.should_try_extra_outbound())

    def test_returns_true_when_stale_and_room(self):
        """Returns True when tip is stale and we have room."""
        pm = _make_mock_peer_manager(num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)
        detector = StaleTipDetector(peer_manager=pm)
        detector._try_extra_outbound = True

        self.assertTrue(detector.should_try_extra_outbound())

    def test_returns_false_when_already_over_limit(self):
        """Returns False when already at limit+1."""
        pm = _make_mock_peer_manager(
            num_peers=MAX_OUTBOUND_FULL_RELAY_CONNECTIONS + 1
        )
        detector = StaleTipDetector(peer_manager=pm)
        detector._try_extra_outbound = True

        self.assertFalse(detector.should_try_extra_outbound())


# ── cleanup_peer ─────────────────────────────────────────────────────────


class TestCleanupPeer(unittest.TestCase):
    """Tests for StaleTipDetector.cleanup_peer()."""

    def test_removes_sync_state(self):
        """cleanup_peer removes peer sync state."""
        detector = StaleTipDetector()
        detector._peer_sync_states["10.0.0.1:8333"] = PeerChainSyncState()

        detector.cleanup_peer("10.0.0.1:8333")

        self.assertNotIn("10.0.0.1:8333", detector._peer_sync_states)

    def test_removes_block_times(self):
        """cleanup_peer removes peer block time tracking."""
        detector = StaleTipDetector()
        detector._peer_block_times["10.0.0.1:8333"] = (time.time(), 100)

        detector.cleanup_peer("10.0.0.1:8333")

        self.assertNotIn("10.0.0.1:8333", detector._peer_block_times)

    def test_handles_unknown_peer(self):
        """cleanup_peer handles unknown peer gracefully."""
        detector = StaleTipDetector()

        # Should not raise
        detector.cleanup_peer("unknown:8333")


# ── update_tip extra outbound flag ─────────────────────────────────────────


class TestUpdateTipClearsExtraOutbound(unittest.TestCase):
    """Tests that update_tip clears the extra outbound flag."""

    def test_clears_flag_on_height_advance(self):
        """Advancing tip height clears the extra outbound flag."""
        detector = StaleTipDetector()
        detector._last_tip_height = 100
        detector._try_extra_outbound = True

        detector.update_tip(101, int(time.time()))

        self.assertFalse(detector._try_extra_outbound)

    def test_does_not_clear_on_same_height(self):
        """Same height does not clear the flag."""
        detector = StaleTipDetector()
        detector._last_tip_height = 100
        detector._try_extra_outbound = True

        detector.update_tip(100, int(time.time()))

        # Flag unchanged (height didn't increase)
        self.assertTrue(detector._try_extra_outbound)


if __name__ == "__main__":
    unittest.main()
