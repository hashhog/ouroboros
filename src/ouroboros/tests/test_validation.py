"""
Test block and transaction validation.

Verifies BlockValidator._validate_header() including proof-of-work.
Ref: bitcoin/src/pow.cpp CheckProofOfWork
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import BlockchainDatabase, Block
from ouroboros.validation import BlockValidator, _bits_to_target


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional whitespace) to bytes."""
    return bytes.fromhex(hex_str.replace("\n", "").replace(" ", ""))


# Bitcoin mainnet genesis block
GENESIS_HEX = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49"
    "ffff001d1dac2b7c"
    "01"
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
    "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75"
    "7420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55482719"
    "67f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51e"
    "c112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)


class TestPowValidation(unittest.TestCase):
    """Test proof-of-work validation in BlockValidator._validate_header"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.db = BlockchainDatabase(data_dir=self.temp_dir)
        self.validator = BlockValidator(self.db)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_prev_block(self, timestamp: int = 0) -> Block:
        """Create a minimal block for use as previous block in validation."""
        return Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=timestamp,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[],
            hash=bytes(32),
        )

    def test_genesis_block_passes_pow(self):
        """Genesis block (bits 0x1d00ffff) passes PoW validation"""
        block = Block.deserialize(hex_to_bytes(GENESIS_HEX))
        prev_block = self._make_prev_block(timestamp=0)
        # Genesis has timestamp 1231006505, so prev_block with 0 is valid
        self.assertTrue(
            self.validator._validate_header(block, prev_block),
            "Genesis block with valid PoW should pass _validate_header",
        )

    def test_block_with_hash_above_target_fails_pow(self):
        """Block with hash exceeding target fails PoW validation"""
        block = Block.deserialize(hex_to_bytes(GENESIS_HEX))
        # Use very hard target (bits=0x03000001 -> target=1)
        # Genesis header hashes to a large value, so hash > 1
        block_hard = Block(
            version=block.version,
            prev_blockhash=block.prev_blockhash,
            merkle_root=block.merkle_root,
            timestamp=block.timestamp,
            bits=0x03000001,
            nonce=block.nonce,
            transactions=block.transactions,
            hash=block.hash,
        )
        prev_block = self._make_prev_block(timestamp=0)
        self.assertFalse(
            self.validator._validate_header(block_hard, prev_block),
            "Block with hash > target should fail _validate_header",
        )


class TestBitsToTarget(unittest.TestCase):
    """Test _bits_to_target helper"""

    def test_genesis_bits(self):
        """0x1d00ffff (genesis) produces valid target"""
        target = _bits_to_target(0x1D00FFFF)
        self.assertGreater(target, 0)
        self.assertLessEqual(target, 2**256 - 1)

    def test_hard_target(self):
        """Very hard bits produce small target"""
        target = _bits_to_target(0x03000001)
        self.assertEqual(target, 1)
