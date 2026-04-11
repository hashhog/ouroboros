"""
Test difficulty calculation (_bits_to_difficulty).

Verifies that difficulty matches Bitcoin Core GetDifficulty formula.
Ref: bitcoin/src/rpc/blockchain.cpp GetDifficulty()
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode  # noqa: E402


class TestBitsToDifficulty(unittest.TestCase):
    """Test _bits_to_difficulty against known difficulty values."""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.node.db = None  # Not needed for _bits_to_difficulty

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_difficulty_one(self):
        """Bits 0x1d00ffff = difficulty 1.0 (genesis / min difficulty)"""
        bits = 0x1D00FFFF
        diff = self.node._bits_to_difficulty(bits)
        self.assertAlmostEqual(diff, 1.0, places=5)

    def test_early_bitcoin_block(self):
        """Bits 0x1b0404cb = ~16307 (early Bitcoin mainnet block)"""
        bits = 0x1B0404CB
        diff = self.node._bits_to_difficulty(bits)
        self.assertAlmostEqual(diff, 16307.0, delta=1.0)

    def test_zero_mantissa_returns_inf(self):
        """Zero mantissa (invalid) returns infinity"""
        bits = 0x1D000000  # exponent 29, mantissa 0
        diff = self.node._bits_to_difficulty(bits)
        self.assertEqual(diff, float("inf"))

    def test_higher_difficulty(self):
        """Larger mantissa (harder target) = lower difficulty"""
        # 0x1d00ffff = 1.0, 0x1d007fff = ~2.0
        bits_easy = 0x1D00FFFF
        bits_harder = 0x1D007FFF
        self.assertGreater(
            self.node._bits_to_difficulty(bits_harder),
            self.node._bits_to_difficulty(bits_easy),
        )


if __name__ == "__main__":
    unittest.main()
