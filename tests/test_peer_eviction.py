"""
Tests for inbound peer eviction logic.

Verifies the PeerManager eviction algorithm modelled after Bitcoin Core's
``SelectNodeToEvict()`` in ``net.cpp``.
"""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock

from ouroboros.p2p import MAX_INBOUND, PeerManager
from ouroboros.peer import Peer, PeerState


def _make_peer(
    host: str = "10.0.0.1",
    port: int = 8333,
    latency: float = 0.0,
    score: int = 100,
    last_block_time: float = 0.0,
    connected_at: float = 0.0,
    connected: bool = True,
) -> Peer:
    """Create a lightweight mock-like Peer for testing eviction selection."""
    peer = Peer(host, port, "regtest", inbound=True)
    peer.latency = latency
    peer.score = score
    peer.last_block_time = last_block_time
    peer.connected_at = connected_at
    if connected:
        peer.state = PeerState.READY
    else:
        peer.state = PeerState.DISCONNECTED
    # Stub out disconnect so it doesn't touch real sockets
    peer.disconnect = AsyncMock()
    return peer


# ── Netgroup ────────────────────────────────────────────────────────


class TestNetgroup(unittest.TestCase):
    """Tests for PeerManager._netgroup()."""

    def test_ipv4_returns_first_two_octets(self):
        self.assertEqual(PeerManager._netgroup("192.168.1.5"), "192.168")

    def test_different_subnets(self):
        self.assertEqual(PeerManager._netgroup("10.0.0.1"), "10.0")
        self.assertEqual(PeerManager._netgroup("172.16.5.20"), "172.16")

    def test_non_ipv4_returns_host(self):
        self.assertEqual(PeerManager._netgroup("my-hostname"), "my-hostname")

    def test_partial_ipv4(self):
        # Only 3 octets — not IPv4
        self.assertEqual(PeerManager._netgroup("10.0.1"), "10.0.1")


# ── Eviction candidate selection ────────────────────────────────────


class TestSelectEvictionCandidate(unittest.TestCase):
    """Tests for PeerManager._select_eviction_candidate()."""

    def _make_manager(self) -> PeerManager:
        return PeerManager(network="regtest", listen=False)

    def test_empty_inbound_returns_none(self):
        pm = self._make_manager()
        self.assertIsNone(pm._select_eviction_candidate())

    def test_four_or_fewer_all_protected_by_latency(self):
        """With ≤ 4 connected inbound peers, all are protected by the
        lowest-latency rule and no eviction candidate is returned."""
        pm = self._make_manager()
        for i in range(4):
            addr = f"10.0.0.{i}:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.0.0.{i}",
                latency=0.01 * (i + 1),
                connected_at=float(i),
            )
        self.assertIsNone(pm._select_eviction_candidate())

    def test_low_latency_peers_protected(self):
        """The 4 peers with lowest latency should never be evicted."""
        pm = self._make_manager()
        base_time = 1000.0

        # 25 peers; peers 0–3 have the best (lowest) latency.
        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=0.001 * (i + 1),
                score=50,
                last_block_time=0.0,
                connected_at=base_time + i,
            )

        victim = pm._select_eviction_candidate()
        protected_addrs = {f"10.{i}.0.1:8333" for i in range(4)}
        self.assertNotIn(victim, protected_addrs)

    def test_high_score_peers_protected(self):
        """The 4 peers with highest score should never be evicted."""
        pm = self._make_manager()
        base_time = 1000.0

        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=1.0,
                score=100 - i,
                last_block_time=0.0,
                connected_at=base_time + i,
            )

        victim = pm._select_eviction_candidate()
        self.assertIsNotNone(victim)
        # The top-4 scorers (indices 0–3) must survive.  After the latency
        # round removes 4 arbitrary peers (all have the same latency), the
        # score round protects the 4 highest scorers that remain.
        # The victim should therefore not be one of the top-4 scorers.
        top_score_addrs = {f"10.{i}.0.1:8333" for i in range(4)}
        self.assertNotIn(victim, top_score_addrs)

    def test_recent_block_relay_peers_protected(self):
        """The 4 peers with most recent block relay should be protected."""
        pm = self._make_manager()
        now = time.time()

        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=1.0,
                score=50,
                last_block_time=now - 1000 + i * 10,
                connected_at=1000.0 + i,
            )

        victim = pm._select_eviction_candidate()
        recent_block_addrs = {f"10.{i}.0.1:8333" for i in range(21, 25)}
        self.assertNotIn(victim, recent_block_addrs)

    def test_unique_netgroup_peers_protected(self):
        """Up to 4 peers from unique netgroups should be protected."""
        pm = self._make_manager()

        # 21 peers: first 17 share 10.0.x.x netgroup, last 4 each unique /16
        for i in range(21):
            if i < 17:
                host = f"10.0.0.{i + 1}"
            else:
                host = f"{20 + i}.1.0.1"
            addr = f"{host}:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=host,
                latency=1.0,
                score=50,
                last_block_time=0.0,
                connected_at=1000.0 + i,
            )

        victim = pm._select_eviction_candidate()
        self.assertIsNotNone(victim)

    def test_recently_connected_peers_protected(self):
        """The 4 most recently connected peers should be protected."""
        pm = self._make_manager()

        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=1.0,
                score=50,
                last_block_time=0.0,
                connected_at=1000.0 + i,
            )

        victim = pm._select_eviction_candidate()
        recent_addrs = {f"10.{i}.0.1:8333" for i in range(21, 25)}
        self.assertNotIn(victim, recent_addrs)

    def test_evicts_longest_connected_from_remaining(self):
        """After all protection rounds, the longest-connected candidate is evicted.

        We build 25 peers sharing the SAME /16 netgroup, equal latency, equal
        score, and zero block-relay activity.  This means:
          - Latency round: protects 4 arbitrary peers (all equal latency=1.0)
          - Score round: protects 4 more (all equal score=50)
          - Block-relay round: protects 4 more (all equal last_block_time=0)
          - Netgroup round: protects only 1 (one unique netgroup "10.0")
          - Recent-connect round: protects 4 most recently connected
        After removing ~17 protected peers, the remaining candidates are
        evicted by longest-connected.
        """
        pm = self._make_manager()

        # All peers in the SAME /16 (10.0.x.x) so netgroup protects only 1
        for i in range(25):
            addr = f"10.0.0.{i + 1}:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.0.0.{i + 1}",
                latency=1.0,
                score=50,
                last_block_time=0.0,
                connected_at=1000.0 + i,  # 0 → earliest, 24 → latest
            )

        victim = pm._select_eviction_candidate()
        self.assertIsNotNone(victim)

        victim_peer = pm.inbound_peers[victim]
        # The 4 most recently connected (connected_at 1021-1024) are always
        # protected in the final round. The victim should never be among them.
        self.assertLess(victim_peer.connected_at, 1021.0)
        # The victim must be the longest-connected remaining candidate.
        self.assertGreaterEqual(victim_peer.connected_at, 1000.0)

    def test_disconnected_peers_excluded(self):
        """Disconnected inbound peers are not candidates for eviction."""
        pm = self._make_manager()
        for i in range(5):
            addr = f"10.0.0.{i}:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.0.0.{i}",
                connected=False,
            )
        self.assertIsNone(pm._select_eviction_candidate())

    def test_all_protected_returns_none(self):
        """If every peer is protected through the 5 protection rounds,
        _select_eviction_candidate returns None."""
        pm = self._make_manager()
        # 20 peers = 4 latency + 4 score + 4 block + 4 netgroup + 4 recent
        for i in range(20):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=0.001 * (i + 1),
                score=100 - i,
                last_block_time=float(i),
                connected_at=1000.0 + i,
            )
        self.assertIsNone(pm._select_eviction_candidate())


# ── _evict_inbound_peer ─────────────────────────────────────────────


class TestEvictInboundPeer(unittest.TestCase):
    """Tests for PeerManager._evict_inbound_peer()."""

    def test_evict_removes_peer_and_disconnects(self):
        pm = PeerManager(network="regtest", listen=False)

        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i}.0.1",
                latency=1.0,
                score=50,
                connected_at=1000.0 + i,
            )

        initial_count = len(pm.inbound_peers)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(pm._evict_inbound_peer())
        finally:
            loop.close()

        self.assertTrue(result)
        self.assertEqual(len(pm.inbound_peers), initial_count - 1)

    def test_evicted_peer_is_disconnected(self):
        pm = PeerManager(network="regtest", listen=False)

        peers = {}
        for i in range(25):
            addr = f"10.{i}.0.1:8333"
            p = _make_peer(
                host=f"10.{i}.0.1",
                latency=1.0,
                score=50,
                connected_at=1000.0 + i,
            )
            pm.inbound_peers[addr] = p
            peers[addr] = p

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(pm._evict_inbound_peer())
        finally:
            loop.close()

        # Exactly one peer should have had disconnect() called
        evicted = [a for a, p in peers.items() if a not in pm.inbound_peers]
        self.assertEqual(len(evicted), 1)
        peers[evicted[0]].disconnect.assert_awaited_once()

    def test_no_candidates_returns_false(self):
        pm = PeerManager(network="regtest", listen=False)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(pm._evict_inbound_peer())
        finally:
            loop.close()
        self.assertFalse(result)


# ── Integration: inbound limit + eviction ────────────────────────────


class TestHandleInboundEviction(unittest.TestCase):
    """Integration-style tests for the eviction path in _handle_inbound_connection."""

    def test_eviction_candidate_found_when_full(self):
        """When inbound slots are full with enough peers, eviction finds a candidate."""
        pm = PeerManager(network="regtest", listen=False)

        for i in range(MAX_INBOUND):
            addr = f"10.{i // 256}.{i % 256}.1:8333"
            pm.inbound_peers[addr] = _make_peer(
                host=f"10.{i // 256}.{i % 256}.1",
                latency=1.0,
                score=50,
                connected_at=1000.0 + i,
            )

        self.assertEqual(len(pm.inbound_peers), MAX_INBOUND)
        candidate = pm._select_eviction_candidate()
        self.assertIsNotNone(candidate)

    def test_no_eviction_when_below_limit(self):
        """When below MAX_INBOUND, no eviction is needed."""
        pm = PeerManager(network="regtest", listen=False)
        pm.inbound_peers["10.0.0.1:8333"] = _make_peer(host="10.0.0.1")
        self.assertLess(len(pm.inbound_peers), MAX_INBOUND)


# ── Peer attribute defaults ──────────────────────────────────────────


class TestPeerAttributes(unittest.TestCase):
    """Verify that Peer has the attributes used by eviction."""

    def test_connected_at_set_on_creation(self):
        now = time.time()
        peer = Peer("10.0.0.1", 8333, "regtest", inbound=True)
        self.assertAlmostEqual(peer.connected_at, now, delta=2.0)

    def test_last_block_time_defaults_to_zero(self):
        peer = Peer("10.0.0.1", 8333, "regtest", inbound=True)
        self.assertEqual(peer.last_block_time, 0.0)

    def test_latency_defaults_to_zero(self):
        peer = Peer("10.0.0.1", 8333, "regtest", inbound=True)
        self.assertEqual(peer.latency, 0.0)


if __name__ == "__main__":
    unittest.main()
