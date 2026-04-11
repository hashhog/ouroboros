"""
Test block serialization and deserialization.

Verifies Block.serialize() and Block.deserialize() correctly handle
Bitcoin wire format: header(80) + tx_count(varint) + [serialized tx for each].
"""

import sys
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block  # noqa: E402
from ouroboros.p2p_messages import BlockMessage  # noqa: E402


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional whitespace) to bytes."""
    return bytes.fromhex(hex_str.replace('\n', '').replace(' ', ''))


# Bitcoin mainnet genesis block (full block with 1 coinbase tx)
GENESIS_HEX = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49"
    "ffff001d1dac2b7c"
    "01"  # 1 transaction
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
    "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75"
    "7420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55482719"
    "67f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51e"
    "c112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)


class TestBlockSerialize(unittest.TestCase):
    """Test Block.serialize() and Block.deserialize()"""

    def test_block_serialize_method_exists(self):
        """Block.serialize exists and is callable"""
        self.assertTrue(hasattr(Block, 'serialize'))
        self.assertTrue(callable(getattr(Block, 'serialize', None)))

    def test_block_deserialize_method_exists(self):
        """Block.deserialize exists and is callable"""
        self.assertTrue(hasattr(Block, 'deserialize'))
        self.assertTrue(callable(getattr(Block, 'deserialize', None)))

    def test_genesis_block_roundtrip(self):
        """Deserialize and serialize genesis block - round-trip matches"""
        payload = hex_to_bytes(GENESIS_HEX)
        block = Block.deserialize(payload)
        serialized = block.serialize()
        self.assertEqual(payload, serialized, "Round-trip must produce identical bytes")

    def test_genesis_block_structure(self):
        """Genesis block has expected structure"""
        payload = hex_to_bytes(GENESIS_HEX)
        block = Block.deserialize(payload)
        self.assertEqual(block.version, 1)
        self.assertEqual(len(block.transactions), 1)
        self.assertTrue(block.transactions[0].is_coinbase)
        self.assertEqual(block.transactions[0].outputs[0].value, 50_0000_0000)
        self.assertEqual(len(block.hash), 32)

    def test_block_message_to_network_message(self):
        """BlockMessage.to_network_message produces valid NetworkMessage"""
        payload = hex_to_bytes(GENESIS_HEX)
        block = Block.deserialize(payload)
        block_msg = BlockMessage(block=block)
        msg = block_msg.to_network_message("mainnet")
        self.assertEqual(msg.command, "block")
        self.assertEqual(msg.payload, block.serialize())
        self.assertGreater(len(msg.payload), 80)

    def test_deserialize_too_short_raises(self):
        """Block data too short raises ValueError"""
        with self.assertRaises(ValueError) as ctx:
            Block.deserialize(b'\x01' * 79)
        self.assertIn('short', str(ctx.exception).lower())


if __name__ == '__main__':
    unittest.main()
