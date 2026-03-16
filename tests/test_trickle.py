"""
Tests for transaction trickling (privacy-preserving relay).

Tests cover:
- TrickleQueue add/mark_known/get_invs_to_send
- Poisson delay scheduling
- WTXID relay preference (MSG_WTX type 5)
- Integration with PeerManager
"""

import pytest
import time
import random
from unittest.mock import MagicMock, AsyncMock, patch

from ouroboros.p2p import (
    TrickleQueue,
    TrickleEntry,
    INBOUND_INVENTORY_BROADCAST_INTERVAL,
    OUTBOUND_INVENTORY_BROADCAST_INTERVAL,
    INVENTORY_BROADCAST_TARGET,
    INVENTORY_BROADCAST_MAX,
)
from ouroboros.p2p_messages import INV_TYPE_TX, MSG_WTX


class TestTrickleQueue:
    """Tests for TrickleQueue class."""

    def test_init_outbound(self):
        """Outbound peers use 2s interval."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        assert queue.is_inbound is False
        assert queue.avg_interval == OUTBOUND_INVENTORY_BROADCAST_INTERVAL
        assert queue.pending_count == 0

    def test_init_inbound(self):
        """Inbound peers use 5s interval."""
        queue = TrickleQueue(is_inbound=True, wtxid_relay=False)
        assert queue.is_inbound is True
        assert queue.avg_interval == INBOUND_INVENTORY_BROADCAST_INTERVAL

    def test_add_tx_new(self):
        """Adding a new transaction returns True."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        result = queue.add_tx(txid, wtxid)

        assert result is True
        assert queue.pending_count == 1
        assert wtxid in queue.pending_wtxids

    def test_add_tx_duplicate(self):
        """Adding same transaction twice returns False."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        queue.add_tx(txid, wtxid)
        result = queue.add_tx(txid, wtxid)

        assert result is False
        assert queue.pending_count == 1

    def test_add_tx_known(self):
        """Adding known transaction returns False."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        # Mark as known first
        queue.mark_known(txid, wtxid)

        result = queue.add_tx(txid, wtxid)
        assert result is False
        assert queue.pending_count == 0

    def test_mark_known_removes_from_pending(self):
        """Marking a tx as known removes it from pending."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        queue.add_tx(txid, wtxid)
        assert queue.pending_count == 1

        queue.mark_known(txid, wtxid)
        assert queue.pending_count == 0

    def test_should_send_no_pending(self):
        """should_send returns False with no pending txs."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        queue.next_send_time = 0

        result = queue.should_send(time.time())
        assert result is False

    def test_should_send_not_time_yet(self):
        """should_send returns False before scheduled time."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        queue.add_tx(b"a" * 32, b"b" * 32)
        queue.next_send_time = time.time() + 100  # far future

        result = queue.should_send(time.time())
        assert result is False

    def test_should_send_time_reached(self):
        """should_send returns True when time reached."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        queue.add_tx(b"a" * 32, b"b" * 32)
        queue.next_send_time = time.time() - 1  # past

        result = queue.should_send(time.time())
        assert result is True


class TestTrickleQueueInvTypes:
    """Tests for INV type selection (txid vs wtxid)."""

    def test_inv_type_txid_legacy(self):
        """Non-wtxid-relay peers get MSG_TX with txid."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("11" * 32)
        wtxid = bytes.fromhex("22" * 32)

        queue.add_tx(txid, wtxid)
        invs = queue.get_invs_to_send()

        assert len(invs) == 1
        inv_type, inv_hash = invs[0]
        assert inv_type == INV_TYPE_TX  # type 1
        assert inv_hash == txid

    def test_inv_type_wtxid_bip339(self):
        """BIP339 wtxid-relay peers get MSG_WTX with wtxid."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=True)
        txid = bytes.fromhex("11" * 32)
        wtxid = bytes.fromhex("22" * 32)

        queue.add_tx(txid, wtxid)
        invs = queue.get_invs_to_send()

        assert len(invs) == 1
        inv_type, inv_hash = invs[0]
        assert inv_type == MSG_WTX  # type 5
        assert inv_hash == wtxid


class TestTrickleQueueBatching:
    """Tests for INV batching and limits."""

    def test_batches_up_to_target(self):
        """Queue sends up to INVENTORY_BROADCAST_TARGET items."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        # Add more than target
        for i in range(100):
            txid = i.to_bytes(32, "big")
            queue.add_tx(txid, txid)

        invs = queue.get_invs_to_send()

        # Should return target amount (70)
        assert len(invs) <= INVENTORY_BROADCAST_TARGET

    def test_removes_sent_from_pending(self):
        """Sent items are removed from pending set."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        queue.add_tx(txid, wtxid)
        assert queue.pending_count == 1

        queue.get_invs_to_send()
        assert queue.pending_count == 0

    def test_adds_sent_to_known_filter(self):
        """Sent items are added to known filter."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)

        queue.add_tx(txid, txid)
        queue.get_invs_to_send()

        # Can't add same tx again
        result = queue.add_tx(txid, txid)
        assert result is False


class TestPoissonDelay:
    """Tests for Poisson-distributed delays."""

    def test_schedule_next_send_uses_expovariate(self):
        """schedule_next_send uses Poisson timing."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        current_time = time.time()

        # Seed for reproducibility
        random.seed(42)

        queue.schedule_next_send(current_time)

        # Should be scheduled in the future
        assert queue.next_send_time > current_time

    def test_inbound_delay_longer(self):
        """Inbound peers have longer average delays."""
        random.seed(12345)

        outbound = TrickleQueue(is_inbound=False, wtxid_relay=False)
        inbound = TrickleQueue(is_inbound=True, wtxid_relay=False)

        # Generate many samples
        outbound_delays = []
        inbound_delays = []

        for _ in range(1000):
            current = time.time()
            outbound.schedule_next_send(current)
            outbound_delays.append(outbound.next_send_time - current)

            inbound.schedule_next_send(current)
            inbound_delays.append(inbound.next_send_time - current)

        avg_outbound = sum(outbound_delays) / len(outbound_delays)
        avg_inbound = sum(inbound_delays) / len(inbound_delays)

        # Inbound average should be ~5s, outbound ~2s
        # Allow some variance
        assert 1.5 < avg_outbound < 2.5
        assert 4.0 < avg_inbound < 6.0


class TestRelayDelayIntegration:
    """Integration tests for relay delay behavior."""

    def test_multiple_txs_randomized_order(self):
        """Multiple transactions are sent in randomized order."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        txids = [i.to_bytes(32, "big") for i in range(10)]
        for txid in txids:
            queue.add_tx(txid, txid)

        # Get INVs multiple times with different seeds
        random.seed(1)
        invs1 = queue.get_invs_to_send(max_count=5)
        hashes1 = [h for _, h in invs1]

        # Reset queue
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        for txid in txids:
            queue.add_tx(txid, txid)

        random.seed(2)
        invs2 = queue.get_invs_to_send(max_count=5)
        hashes2 = [h for _, h in invs2]

        # Different seeds should give different orders
        # (probabilistically - with 10 items, very unlikely to be same)
        assert hashes1 != hashes2 or len(txids) < 2

    def test_clear_removes_all_pending(self):
        """clear() removes all pending announcements."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        for i in range(10):
            txid = i.to_bytes(32, "big")
            queue.add_tx(txid, txid)

        assert queue.pending_count == 10

        queue.clear()

        assert queue.pending_count == 0
        assert len(queue.wtxid_to_txid) == 0


class TestInvBroadcastConstants:
    """Tests that constants match Bitcoin Core values."""

    def test_inbound_interval(self):
        """INBOUND_INVENTORY_BROADCAST_INTERVAL is 5 seconds."""
        assert INBOUND_INVENTORY_BROADCAST_INTERVAL == 5.0

    def test_outbound_interval(self):
        """OUTBOUND_INVENTORY_BROADCAST_INTERVAL is 2 seconds."""
        assert OUTBOUND_INVENTORY_BROADCAST_INTERVAL == 2.0

    def test_broadcast_target(self):
        """INVENTORY_BROADCAST_TARGET is 70 (14 * 5)."""
        assert INVENTORY_BROADCAST_TARGET == 70

    def test_broadcast_max(self):
        """INVENTORY_BROADCAST_MAX is 1000."""
        assert INVENTORY_BROADCAST_MAX == 1000
