"""
Test transaction deserialization.

Verifies TxMessage.from_payload() correctly parses Bitcoin wire format:
- Non-SegWit: coinbase and P2PKH transactions
- SegWit: transactions with witness data (marker 0x00, flag 0x01)
"""

import unittest
import sys
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.p2p_messages import TxMessage


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional whitespace) to bytes."""
    return bytes.fromhex(hex_str.replace('\n', '').replace(' ', ''))


class TestTransactionDeserialize(unittest.TestCase):
    """Test transaction deserialization via TxMessage.from_payload()"""

    def test_tx_message_from_payload_exists(self):
        """TxMessage.from_payload exists and is callable"""
        self.assertTrue(hasattr(TxMessage, 'from_payload'))
        self.assertTrue(callable(getattr(TxMessage, 'from_payload', None)))

    def test_deserialize_coinbase(self):
        """Deserialize coinbase transaction (Bitcoin testnet-style)"""
        # Real coinbase tx: version 1, 1 input (prev_txid=0, prev_vout=0xffffffff),
        # 1 output P2PKH
        hex_tx = """
            01000000010000000000000000000000000000000000000000000000000000000000000000
            ffffffff1d030f8d13049faa805a063538706f6f6c0c00010000fe22030000000000ffffff
            ff015341cb04000000001976a914f11298ce777cb5db5c09250cad4eb856b1e366ef88ac00
            000000
        """
        payload = hex_to_bytes(hex_tx)
        tx_msg = TxMessage.from_payload(payload)
        tx = tx_msg.transaction

        self.assertEqual(tx.version, 1)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(len(tx.outputs), 1)
        self.assertTrue(tx.is_coinbase)
        self.assertEqual(tx.outputs[0].value, 80429395)
        self.assertEqual(tx.locktime, 0)
        self.assertEqual(len(tx.txid), 32)

    def test_deserialize_p2pkh(self):
        """Deserialize standard P2PKH transaction (non-SegWit)"""
        # Bitcoin Core test vector: txcreatesignv1.hex
        hex_tx = (
            "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d"
            "000000008a4730440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d5027"
            "8380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a218"
            "8e96e01410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
            "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8fffffff"
            "f01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00"
            "000000"
        )
        payload = hex_to_bytes(hex_tx)
        tx_msg = TxMessage.from_payload(payload)
        tx = tx_msg.transaction

        self.assertEqual(tx.version, 1)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(len(tx.outputs), 1)
        self.assertFalse(tx.is_coinbase)
        self.assertEqual(tx.outputs[0].value, 100000)  # 0xa08601 little-endian
        self.assertEqual(len(tx.inputs[0].script_sig), 0x8a)
        self.assertEqual(len(tx.txid), 32)

    def test_deserialize_segwit(self):
        """Deserialize SegWit transaction (marker 0x00, flag 0x01)"""
        # Bitcoin Core test vector: txcreatesignsegwit1.hex
        hex_tx = (
            "02000000000101ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433"
            "2211000000000000ffffffff01a0860100000000001976a9145834479edbbe0539b31f"
            "fd3a8f8ebadc2165ed0188ac0247304402202e8d8677912f73909ffbdb3ee87d10cce41d"
            "398ee206e534fa18330b566ece34022004f944f018a03c9f5b4cf0e9b0ae4f14049b55e"
            "7b6810a6ac26cd67cb4dcb31f01210279be667ef9dcbbac55a06295ce870b07029bfcdb"
            "2dce28d959f2815b16f8179800000000"
        )
        payload = hex_to_bytes(hex_tx)
        tx_msg = TxMessage.from_payload(payload)
        tx = tx_msg.transaction

        self.assertEqual(tx.version, 2)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(len(tx.outputs), 1)
        self.assertFalse(tx.is_coinbase)
        self.assertTrue(tx.has_witness)
        self.assertEqual(tx.inputs[0].script_sig, b'')  # SegWit: script_sig empty
        self.assertIsNotNone(tx.inputs[0].witness)
        self.assertEqual(len(tx.inputs[0].witness), 2)  # signature + pubkey
        self.assertEqual(tx.outputs[0].value, 100000)
        self.assertEqual(tx.locktime, 0)
        self.assertEqual(len(tx.txid), 32)

    def test_payload_too_short_raises(self):
        """Payload too short raises ValueError"""
        with self.assertRaises(ValueError) as ctx:
            TxMessage.from_payload(b'\x01\x00\x00')  # < 4 bytes for version
        self.assertIn('short', str(ctx.exception).lower())

    def test_invalid_empty_payload_raises(self):
        """Empty payload raises ValueError"""
        with self.assertRaises(ValueError):
            TxMessage.from_payload(b'')


if __name__ == '__main__':
    unittest.main()
