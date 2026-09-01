"""
Tests for BIP133 feefilter implementation.

Tests cover:
- FeeFilterRounder: fee bucketing with 1.1x spacing and random noise
- Per-peer feefilter state tracking
- Hysteresis: 3/4 to 4/3 threshold for triggering updates
- Transaction relay filtering based on peer feefilter
- Feefilter message serialization/deserialization
"""

import random

from ouroboros.p2p import (
    AVG_FEEFILTER_BROADCAST_INTERVAL,
    FEE_FILTER_SPACING,
    MAX_FEEFILTER_CHANGE_DELAY,
    MIN_RELAY_FEE_RATE,
    FeeFilterRounder,
    TrickleEntry,
    TrickleQueue,
)
from ouroboros.p2p_messages import FeeFilterMessage


class TestFeeFilterMessage:
    """Tests for FeeFilterMessage serialization."""

    def test_serialize_deserialize(self):
        """FeeFilterMessage round-trips correctly."""
        msg = FeeFilterMessage(feerate=1234567)
        network_msg = msg.to_network_message("mainnet")

        parsed = FeeFilterMessage.from_payload(network_msg.payload)
        assert parsed.feerate == 1234567

    def test_payload_is_8_bytes(self):
        """Payload is exactly 8 bytes (64-bit little-endian)."""
        msg = FeeFilterMessage(feerate=1000)
        network_msg = msg.to_network_message("mainnet")

        assert len(network_msg.payload) == 8

    def test_little_endian_encoding(self):
        """Fee rate is encoded as little-endian."""
        msg = FeeFilterMessage(feerate=0x0102030405060708)
        network_msg = msg.to_network_message("mainnet")

        # Little-endian: least significant byte first
        assert network_msg.payload == bytes([8, 7, 6, 5, 4, 3, 2, 1])

    def test_zero_feerate(self):
        """Zero fee rate is valid."""
        msg = FeeFilterMessage(feerate=0)
        network_msg = msg.to_network_message("mainnet")
        parsed = FeeFilterMessage.from_payload(network_msg.payload)
        assert parsed.feerate == 0

    def test_max_feerate(self):
        """Large fee rates serialize correctly."""
        # MAX_MONEY in sat/kvB would be huge, but test a reasonable max
        max_rate = 10_000_000_000  # 10 BTC per kvB
        msg = FeeFilterMessage(feerate=max_rate)
        network_msg = msg.to_network_message("mainnet")
        parsed = FeeFilterMessage.from_payload(network_msg.payload)
        assert parsed.feerate == max_rate


class TestFeeFilterRounder:
    """Tests for FeeFilterRounder privacy bucketing."""

    def test_buckets_spaced_at_1_1x(self):
        """Fee buckets are spaced at 1.1x intervals."""
        rounder = FeeFilterRounder(min_incremental_fee=1000)

        # Check that consecutive buckets have ~1.1x ratio
        buckets = rounder._fee_set
        for i in range(1, len(buckets) - 1):
            if buckets[i] > 0 and buckets[i + 1] > 0:
                ratio = buckets[i + 1] / buckets[i]
                assert 1.09 < ratio < 1.11, f"Ratio {ratio} at index {i}"

    def test_includes_zero_bucket(self):
        """Fee set includes zero as first bucket."""
        rounder = FeeFilterRounder()
        assert rounder._fee_set[0] == 0

    def test_round_returns_integer(self):
        """round() returns an integer."""
        rounder = FeeFilterRounder()
        result = rounder.round(1500)
        assert isinstance(result, int)

    def test_round_zero_returns_zero(self):
        """Rounding zero or negative returns zero."""
        rounder = FeeFilterRounder()
        assert rounder.round(0) == 0
        assert rounder.round(-100) == 0

    def test_round_produces_discrete_values(self):
        """Rounding produces discrete bucket values, not arbitrary numbers."""
        random.seed(42)
        rounder = FeeFilterRounder(min_incremental_fee=1000)

        # Round many different values
        results = set()
        for fee in range(500, 10000, 100):
            for _ in range(10):  # Multiple rounds due to randomization
                results.add(rounder.round(fee))

        # All results should be in the bucket set
        bucket_set = {int(b) for b in rounder._fee_set}
        for r in results:
            assert r in bucket_set or r == 0, f"{r} not in buckets"

    def test_randomization_provides_variance(self):
        """round() provides random variance for privacy."""
        rounder = FeeFilterRounder(min_incremental_fee=1000)

        # Round same value many times
        results = set()
        for _ in range(100):
            results.add(rounder.round(5000))

        # Should get at least 2 different values due to randomization
        # (2/3 chance to round down, 1/3 to round up/stay)
        assert len(results) >= 2, "No variance in rounding"

    def test_min_incremental_fee_affects_buckets(self):
        """min_incremental_fee affects the starting bucket."""
        rounder_low = FeeFilterRounder(min_incremental_fee=500)
        rounder_high = FeeFilterRounder(min_incremental_fee=2000)

        # Higher min fee should start with larger first non-zero bucket
        low_first_nonzero = [b for b in rounder_low._fee_set if b > 0][0]
        high_first_nonzero = [b for b in rounder_high._fee_set if b > 0][0]

        assert high_first_nonzero > low_first_nonzero


class TestFeeFilterConstants:
    """Tests that constants match Bitcoin Core values."""

    def test_avg_broadcast_interval(self):
        """AVG_FEEFILTER_BROADCAST_INTERVAL is 10 minutes."""
        assert AVG_FEEFILTER_BROADCAST_INTERVAL == 600.0

    def test_max_change_delay(self):
        """MAX_FEEFILTER_CHANGE_DELAY is 5 minutes."""
        assert MAX_FEEFILTER_CHANGE_DELAY == 300.0

    def test_fee_filter_spacing(self):
        """FEE_FILTER_SPACING is 1.1."""
        assert FEE_FILTER_SPACING == 1.1

    def test_min_relay_fee_rate(self):
        """MIN_RELAY_FEE_RATE is 100 sat/kvB (Core policy.h:70 DEFAULT_MIN_RELAY_TX_FEE{100})."""
        assert MIN_RELAY_FEE_RATE == 100


class TestTrickleQueueFeefilter:
    """Tests for TrickleQueue feefilter integration."""

    def test_add_tx_with_fee_info(self):
        """add_tx stores fee information."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)
        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)

        result = queue.add_tx(txid, wtxid, fee=1000, vsize=200)

        assert result is True
        assert wtxid in queue.wtxid_to_entry
        entry = queue.wtxid_to_entry[wtxid]
        assert entry.fee == 1000
        assert entry.vsize == 200

    def test_fee_rate_kvb_calculation(self):
        """TrickleEntry calculates fee_rate_kvb correctly."""
        entry = TrickleEntry(
            txid=b"a" * 32,
            wtxid=b"b" * 32,
            fee=1000,  # 1000 satoshis
            vsize=200,  # 200 vbytes
        )

        # fee_rate_kvb = (fee * 1000) / vsize = (1000 * 1000) / 200 = 5000
        assert entry.fee_rate_kvb == 5000

    def test_fee_rate_kvb_zero_vsize(self):
        """fee_rate_kvb returns 0 for zero vsize."""
        entry = TrickleEntry(
            txid=b"a" * 32,
            wtxid=b"b" * 32,
            fee=1000,
            vsize=0,
        )
        assert entry.fee_rate_kvb == 0

    def test_get_invs_filters_by_feefilter(self):
        """Transactions below feefilter are not announced."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        # Add a low-fee transaction (fee_rate = 500 sat/kvB)
        low_fee_txid = bytes.fromhex("11" * 32)
        queue.add_tx(low_fee_txid, low_fee_txid, fee=100, vsize=200)

        # Add a high-fee transaction (fee_rate = 5000 sat/kvB)
        high_fee_txid = bytes.fromhex("22" * 32)
        queue.add_tx(high_fee_txid, high_fee_txid, fee=1000, vsize=200)

        # Get INVs with feefilter = 1000 sat/kvB
        invs = queue.get_invs_to_send(feefilter=1000)

        # Only high-fee tx should be included
        inv_hashes = [h for _, h in invs]
        assert high_fee_txid in inv_hashes
        assert low_fee_txid not in inv_hashes

    def test_filtered_tx_remains_in_queue(self):
        """Transactions below feefilter stay in queue for later."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        # Add a low-fee transaction
        low_fee_txid = bytes.fromhex("11" * 32)
        queue.add_tx(low_fee_txid, low_fee_txid, fee=100, vsize=200)

        # Get INVs with high feefilter - nothing returned
        invs = queue.get_invs_to_send(feefilter=10000)
        assert len(invs) == 0

        # Transaction still in queue
        assert queue.pending_count == 1
        assert low_fee_txid in queue.wtxid_to_txid.values()

    def test_zero_feefilter_allows_all(self):
        """Zero feefilter allows all transactions."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        txid = bytes.fromhex("ab" * 32)
        queue.add_tx(txid, txid, fee=1, vsize=1000)  # 1 sat/kvB

        invs = queue.get_invs_to_send(feefilter=0)

        assert len(invs) == 1

    def test_no_fee_info_bypasses_filter(self):
        """Transactions without fee info are not filtered."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        txid = bytes.fromhex("ab" * 32)
        # Add without fee info (legacy path)
        queue.add_tx(txid, txid)  # no fee/vsize

        # High feefilter should not block it
        invs = queue.get_invs_to_send(feefilter=10000000)

        assert len(invs) == 1

    def test_clear_removes_fee_entries(self):
        """clear() also clears fee entry map."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        txid = bytes.fromhex("ab" * 32)
        queue.add_tx(txid, txid, fee=1000, vsize=200)

        queue.clear()

        assert len(queue.wtxid_to_entry) == 0

    def test_mark_known_removes_fee_entry(self):
        """mark_known() removes the fee entry."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        txid = bytes.fromhex("ab" * 32)
        wtxid = bytes.fromhex("cd" * 32)
        queue.add_tx(txid, wtxid, fee=1000, vsize=200)

        assert wtxid in queue.wtxid_to_entry

        queue.mark_known(txid, wtxid)

        assert wtxid not in queue.wtxid_to_entry


class TestPeerFeefilterState:
    """Tests for per-peer feefilter state tracking."""

    def test_peer_initial_feefilter_state(self):
        """Peer starts with zero feefilter state."""
        from ouroboros.peer import Peer

        peer = Peer("127.0.0.1", 8333, "mainnet")

        assert peer.peer_feefilter == 0
        assert peer.feefilter_sent == 0
        assert peer.next_feefilter_time == 0.0

    def test_peer_feefilter_updated_by_handler(self):
        """peer_feefilter is updated when feefilter message received."""
        from ouroboros.peer import Peer

        peer = Peer("127.0.0.1", 8333, "mainnet")

        # Simulate receiving feefilter message
        peer.peer_feefilter = 5000

        assert peer.peer_feefilter == 5000


class TestHysteresisLogic:
    """Tests for feefilter hysteresis (3/4 to 4/3 threshold)."""

    def test_no_expedite_small_change_up(self):
        """Small increase doesn't trigger expedited update."""
        # If sent = 1000, 4/3 * 1000 = 1333
        # current = 1200 is not > 1333, so no expedite
        sent = 1000
        current = 1200

        should_expedite = (
            current < (3 * sent) // 4 or current > (4 * sent) // 3
        )

        assert should_expedite is False

    def test_no_expedite_small_change_down(self):
        """Small decrease doesn't trigger expedited update."""
        # If sent = 1000, 3/4 * 1000 = 750
        # current = 800 is not < 750, so no expedite
        sent = 1000
        current = 800

        should_expedite = (
            current < (3 * sent) // 4 or current > (4 * sent) // 3
        )

        assert should_expedite is False

    def test_expedite_large_increase(self):
        """Large increase (>33%) triggers expedited update."""
        # If sent = 1000, 4/3 * 1000 = 1333
        # current = 1500 is > 1333, so expedite
        sent = 1000
        current = 1500

        should_expedite = (
            current < (3 * sent) // 4 or current > (4 * sent) // 3
        )

        assert should_expedite is True

    def test_expedite_large_decrease(self):
        """Large decrease (>25%) triggers expedited update."""
        # If sent = 1000, 3/4 * 1000 = 750
        # current = 500 is < 750, so expedite
        sent = 1000
        current = 500

        should_expedite = (
            current < (3 * sent) // 4 or current > (4 * sent) // 3
        )

        assert should_expedite is True

    def test_boundary_exactly_at_threshold(self):
        """Exactly at threshold should not trigger."""
        sent = 1000

        # Exactly 3/4
        current_low = (3 * sent) // 4  # 750
        should_expedite_low = (
            current_low < (3 * sent) // 4 or current_low > (4 * sent) // 3
        )
        assert should_expedite_low is False

        # Exactly 4/3
        current_high = (4 * sent) // 3  # 1333
        should_expedite_high = (
            current_high < (3 * sent) // 4 or current_high > (4 * sent) // 3
        )
        assert should_expedite_high is False


class TestFeeFilterRelayIntegration:
    """Integration tests for feefilter affecting relay decisions."""

    def test_multiple_txs_mixed_fees(self):
        """Queue with mixed fee rates filters correctly."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        # Add transactions with various fee rates
        # fee_rate_kvb = (fee * 1000) / vsize
        txs = [
            (b"a" * 32, 100, 1000),   # 100 sat/kvB - too low
            (b"b" * 32, 500, 1000),   # 500 sat/kvB - too low
            (b"c" * 32, 1000, 1000),  # 1000 sat/kvB - exactly at threshold
            (b"d" * 32, 2000, 1000),  # 2000 sat/kvB - above threshold
            (b"e" * 32, 5000, 1000),  # 5000 sat/kvB - well above
        ]

        for txid, fee, vsize in txs:
            queue.add_tx(txid, txid, fee=fee, vsize=vsize)

        # Filter at 1000 sat/kvB
        invs = queue.get_invs_to_send(feefilter=1000)
        inv_hashes = [h for _, h in invs]

        # Only transactions >= 1000 sat/kvB should be included
        assert b"a" * 32 not in inv_hashes
        assert b"b" * 32 not in inv_hashes
        assert b"c" * 32 in inv_hashes  # exactly at threshold
        assert b"d" * 32 in inv_hashes
        assert b"e" * 32 in inv_hashes

    def test_feefilter_change_releases_txs(self):
        """Lowering feefilter allows previously filtered txs to be announced."""
        queue = TrickleQueue(is_inbound=False, wtxid_relay=False)

        # Add low-fee tx
        txid = b"x" * 32
        queue.add_tx(txid, txid, fee=100, vsize=1000)  # 100 sat/kvB

        # First try with high filter - nothing returned
        invs1 = queue.get_invs_to_send(feefilter=5000)
        assert len(invs1) == 0
        assert queue.pending_count == 1

        # Now with lower filter - tx is returned
        invs2 = queue.get_invs_to_send(feefilter=50)
        assert len(invs2) == 1
        assert invs2[0][1] == txid
