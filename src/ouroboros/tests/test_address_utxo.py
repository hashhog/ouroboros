"""
Test address decoding and UTXO querying.
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))


class TestAddressDecoding(unittest.TestCase):
    """Test address_to_script_pubkey."""

    def test_p2pkh_address(self):
        """P2PKH address decodes to correct script_pubkey."""
        from ouroboros.address import address_to_script_pubkey

        # Satoshi's address (mainnet P2PKH)
        spk = address_to_script_pubkey("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        self.assertEqual(len(spk), 25)
        self.assertEqual(spk[0], 0x76)  # OP_DUP
        self.assertEqual(spk[1], 0xA9)  # OP_HASH160
        self.assertEqual(spk[2], 0x14)  # push 20 bytes
        self.assertEqual(spk[23], 0x88)  # OP_EQUALVERIFY
        self.assertEqual(spk[24], 0xAC)  # OP_CHECKSIG

    def test_p2wpkh_address(self):
        """P2WPKH (bech32) address decodes to correct script_pubkey."""
        from ouroboros.address import address_to_script_pubkey

        spk = address_to_script_pubkey("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        self.assertEqual(len(spk), 22)
        self.assertEqual(spk[0], 0x00)  # OP_0
        self.assertEqual(spk[1], 0x14)  # push 20 bytes
        self.assertEqual(len(spk[2:]), 20)

    def test_invalid_address_raises(self):
        """Invalid address raises ValueError."""
        from ouroboros.address import address_to_script_pubkey

        with self.assertRaises(ValueError):
            address_to_script_pubkey("not-an-address")
        with self.assertRaises(ValueError):
            address_to_script_pubkey("")


class TestBalanceAndListUnspent(unittest.TestCase):
    """Test get_balance and list_unspent_by_address (requires sync module)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_balance_empty_db(self):
        """get_balance returns 0 for empty DB."""
        try:
            from ouroboros.database import BlockchainDatabase

            db = BlockchainDatabase(self.temp_dir)
            balance = db.get_balance("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
            self.assertEqual(balance, 0)
        except ImportError:
            self.skipTest("sync module not available (Rust not built)")

    def test_list_unspent_empty(self):
        """list_unspent_by_address returns [] for empty DB."""
        try:
            from ouroboros.database import BlockchainDatabase

            db = BlockchainDatabase(self.temp_dir)
            utxos = db.list_unspent_by_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
            self.assertEqual(utxos, [])
        except ImportError:
            self.skipTest("sync module not available (Rust not built)")


if __name__ == "__main__":
    unittest.main()
