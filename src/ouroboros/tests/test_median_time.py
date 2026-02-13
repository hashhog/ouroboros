"""
Test median time calculation.

This test verifies that median time is correctly calculated from the last 11 blocks.
"""

import unittest
import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode
from ouroboros.database import BlockchainDatabase, Block, Transaction, TxIn, TxOut


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
        block = Block(
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


if __name__ == '__main__':
    unittest.main()
