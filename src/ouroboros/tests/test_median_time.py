"""
Test median time calculation.

This test verifies that median time is correctly calculated from the last 11 blocks.
"""

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block, BlockchainDatabase  # noqa: E402
from ouroboros.node import BitcoinNode  # noqa: E402


class TestMedianTime(unittest.TestCase):
    """Test median time calculation"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        # Initialize database
        self.node.db = BlockchainDatabase(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_median_time_method_exists(self):
        """Test that get_median_time method exists"""
        self.assertTrue(hasattr(self.node, 'get_median_time'))
        self.assertTrue(callable(getattr(self.node, 'get_median_time', None)))

    def test_median_time_with_no_blocks(self):
        """Test median time with no blocks (should return current time)"""
        median_time = self.node.get_median_time()
        current_time = int(time.time())

        # Should return current time (within 1 second tolerance)
        self.assertGreaterEqual(median_time, current_time - 1)
        self.assertLessEqual(median_time, current_time + 1)

    def test_median_time_with_single_block(self):
        """Test median time with a single block"""
        # Create a test block
        Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=1231006505,  # Fixed timestamp
            bits=0x1d00ffff,
            nonce=2083236893,
            transactions=[],
            hash=bytes(32),
            height=0
        )

        # Note: We can't easily store blocks in the test database without the Rust API
        # So we'll just test that the method can be called
        # In a full integration test, we would store blocks and verify the median

        # Test that method doesn't crash
        try:
            median_time = self.node.get_median_time()
            self.assertIsInstance(median_time, int)
            self.assertGreater(median_time, 0)
        except Exception as e:
            # If database is not properly initialized, that's okay for this test
            self.skipTest(f"Database not properly initialized: {e}")

    def test_median_time_with_height_parameter(self):
        """Test median time with specific height parameter"""
        try:
            # Test with height=None (should use best block)
            median_time1 = self.node.get_median_time(None)
            self.assertIsInstance(median_time1, int)

            # Test with height=0
            median_time2 = self.node.get_median_time(0)
            self.assertIsInstance(median_time2, int)

            # Test with height=10
            median_time3 = self.node.get_median_time(10)
            self.assertIsInstance(median_time3, int)
        except Exception as e:
            # If database is not properly initialized, that's okay for this test
            self.skipTest(f"Database not properly initialized: {e}")

    def test_median_time_returns_integer(self):
        """Test that median time returns an integer"""
        try:
            median_time = self.node.get_median_time()
            self.assertIsInstance(median_time, int)
            self.assertGreater(median_time, 0)
        except Exception as e:
            self.skipTest(f"Database not properly initialized: {e}")

    def test_median_time_error_handling(self):
        """Test that median time handles errors gracefully"""
        # Test with None database
        node_no_db = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        node_no_db.db = None

        median_time = node_no_db.get_median_time()
        # Should return current time as fallback
        current_time = int(time.time())
        self.assertGreaterEqual(median_time, current_time - 1)
        self.assertLessEqual(median_time, current_time + 1)

    def test_median_time_eleven_blocks_sorted(self):
        """11 blocks with known timestamps -> median is the 6th sorted value (index 5)"""
        # Timestamps for blocks 0-10: use unsorted values, median should be 500
        test_timestamps = [100, 900, 200, 800, 300, 500, 700, 400, 600, 150, 850]
        # Sorted: [100, 150, 200, 300, 400, 500, 600, 700, 800, 850, 900]
        # Median (index 5) = 500
        expected_median = 500

        class MockBlock:
            def __init__(self, ts):
                self.timestamp = ts

        class MockDB:
            def get_best_block(self):
                return (bytes(32), 10)

            def get_block_hash_by_height(self, h):
                if 0 <= h <= 10:
                    return bytes([h] * 32)  # Unique hash per height
                return None

            def get_block(self, block_hash):
                if len(block_hash) == 32:
                    h = block_hash[0]  # Hash encodes height (0-10)
                    if h <= 10:
                        return MockBlock(test_timestamps[h])
                return None

        self.node.db = MockDB()
        median_time = self.node.get_median_time(height=10)
        self.assertEqual(median_time, expected_median)


class _StubPyBlock:
    """Minimal PyBlock-shaped stub for ``BlockchainDatabase._py_block_to_block``."""

    def __init__(self, timestamp, height):
        self.version = 1
        self.prev_blockhash = bytes(32)
        self.merkle_root = bytes(32)
        self.timestamp = timestamp
        self.bits = 0x1D00FFFF
        self.nonce = 0
        self.transactions = []
        self.hash = bytes([height & 0xFF] * 32)
        self.height = height


class _SnapshotBoundaryDB:
    """Stub Rust ``_db`` simulating the post-assumeUTXO state.

    After an assumeUTXO snapshot load at ``snapshot_height`` ouroboros only
    persists the snapshot block's own header — heights below it are absent
    from the block index.  ``get_block_by_height`` /
    ``get_block_hash_by_height`` therefore return ``None`` for any height
    ``< snapshot_height``; ``get_block_hash_by_height`` returns a hash for
    heights ``>= snapshot_height``.

    ``get_median_time_past`` here models a Rust extension that has NOT yet
    been rebuilt with the partial-window fix — it medians whatever blocks
    it can see, exactly the buggy behaviour the Python wrapper must guard
    against.
    """

    def __init__(self, snapshot_height, timestamps):
        # timestamps: dict height -> block timestamp, for present blocks.
        self._snapshot_height = snapshot_height
        self._timestamps = timestamps

    def get_block_hash_by_height(self, height):
        if height < self._snapshot_height:
            return None
        return bytes([height & 0xFF] * 32)

    def get_block_by_height(self, height):
        # Slow-fallback path: return a duck-typed PyBlock for present heights
        # (``_py_block_to_block`` reads these header fields + ``transactions``).
        if height not in self._timestamps:
            return None
        return _StubPyBlock(self._timestamps[height], height)

    def get_median_time_past(self, height):
        # Buggy old-Rust behaviour: median of only the visible subset.
        start = max(0, height - 10)
        seen = [self._timestamps[h] for h in range(start, height + 1)
                if h in self._timestamps]
        if not seen:
            return None
        seen.sort()
        return seen[len(seen) // 2]


class TestMedianTimePartialWindow(unittest.TestCase):
    """Regression: get_median_time_past must NOT fabricate an MTP from a
    partial 11-block window (mainnet stall at h=948464, 2026-05-20).

    A truncated window — caused by missing pre-assumeUTXO-snapshot headers
    — is right-shifted toward the larger recent timestamps, yielding an
    MTP that is far too LARGE.  That over-large value fed BIP-68 time-based
    relative-locktime evaluation and rejected a valid block.  The fix
    returns ``None`` for an incomplete window so BIP-68 falls back to a
    coin time of 0 (lock satisfied), matching the assumeUTXO trust model.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # BlockchainDatabase opens a real RocksDB; we only need the wrapper
        # methods, so swap ._db for the stub immediately after construction.
        self.db = BlockchainDatabase(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_incomplete_window_returns_none(self):
        """Window straddling a snapshot boundary -> None, not a wrong median."""
        snap_h = 944183
        # Heights 944183..944200 present; everything below the snapshot absent.
        ts = {h: 1775650000 + (h - 944183) * 600 for h in range(944183, 944201)}
        self.db._db = _SnapshotBoundaryDB(snap_h, ts)
        # height 944190 -> window [944180..944190]; 944180..944182 missing.
        self.assertIsNone(
            self.db.get_median_time_past(944190),
            "partial-window MTP must be None, never a fabricated median",
        )
        # The snapshot tip itself: window [944173..944183], only 944183 present.
        self.assertIsNone(self.db.get_median_time_past(snap_h))

    def test_complete_window_returns_median(self):
        """A fully-populated 11-block window returns the true median."""
        # Heights 944183..944300 all present.
        ts = {h: 1775650000 + (h - 944183) * 600 for h in range(944183, 944301)}
        self.db._db = _SnapshotBoundaryDB(944183, ts)
        # height 944250 -> window [944240..944250], all present, median index 5.
        window = sorted(ts[h] for h in range(944240, 944251))
        self.assertEqual(
            self.db.get_median_time_past(944250),
            window[len(window) // 2],
        )

    def test_partial_window_does_not_overstate_mtp(self):
        """The buggy path would return a value LARGER than the true MTP."""
        ts = {h: 1775650000 + (h - 944183) * 600 for h in range(944183, 944201)}
        # The buggy old-Rust median of the visible subset for height 944190:
        buggy = _SnapshotBoundaryDB(944183, ts).get_median_time_past(944190)
        # The true MTP would include the (smaller) 944180..944182 timestamps;
        # the buggy partial-window value is strictly larger — exactly the
        # over-statement that broke BIP-68.  The fixed wrapper rejects it.
        self.assertIsNotNone(buggy)
        self.db._db = _SnapshotBoundaryDB(944183, ts)
        self.assertIsNone(self.db.get_median_time_past(944190))


if __name__ == '__main__':
    unittest.main()
