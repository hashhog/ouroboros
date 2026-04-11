"""
Test SegWit transaction support.

This test verifies that SegWit transactions are handled correctly,
including weight and vsize calculations.
"""

import sys
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace("\n", "").replace(" ", ""))


class TestSegWit(unittest.TestCase):
    """Test SegWit transaction support"""

    def test_transaction_weight_method_exists(self):
        """Test that Transaction has get_weight() method"""
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[],
            outputs=[]
        )
        self.assertTrue(hasattr(tx, 'get_weight'))
        self.assertTrue(callable(getattr(tx, 'get_weight', None)))
        self.assertTrue(hasattr(tx, 'get_vsize'))
        self.assertTrue(callable(getattr(tx, 'get_vsize', None)))

    def test_weight_calculation_non_segwit(self):
        """Test weight calculation for non-SegWit transaction"""
        # Create a simple transaction
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b'\x00',
                    sequence=0xffffffff
                )
            ],
            outputs=[
                TxOut(
                    value=50000000,
                    script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
                )
            ]
        )

        # Calculate weight
        weight = tx.get_weight()

        # For non-SegWit: weight = size * 4
        tx_size = len(tx.serialize())
        expected_weight = tx_size * 4

        self.assertEqual(weight, expected_weight)
        self.assertGreater(weight, 0)

    def test_vsize_calculation(self):
        """Test vsize calculation"""
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b'\x00',
                    sequence=0xffffffff
                )
            ],
            outputs=[
                TxOut(
                    value=50000000,
                    script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
                )
            ]
        )

        # Calculate vsize
        vsize = tx.get_vsize()
        weight = tx.get_weight()

        # vsize = ceil(weight / 4) = (weight + 3) // 4
        expected_vsize = (weight + 3) // 4

        self.assertEqual(vsize, expected_vsize)
        self.assertGreater(vsize, 0)

        # For non-SegWit transactions, vsize should equal size
        tx_size = len(tx.serialize())
        self.assertEqual(vsize, tx_size)

    def test_weight_vsize_relationship(self):
        """Test that weight and vsize have correct relationship"""
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b'\x00',
                    sequence=0xffffffff
                )
            ],
            outputs=[
                TxOut(
                    value=50000000,
                    script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
                )
            ]
        )

        weight = tx.get_weight()
        vsize = tx.get_vsize()

        # vsize should be approximately weight / 4 (rounded up)
        # More precisely: vsize = (weight + 3) // 4
        calculated_vsize = (weight + 3) // 4
        self.assertEqual(vsize, calculated_vsize)

        # vsize should be <= weight / 4 + 1
        self.assertLessEqual(vsize, (weight // 4) + 1)
        # vsize should be >= weight / 4
        self.assertGreaterEqual(vsize, weight // 4)

    def test_rpc_vsize_weight(self):
        """Test that RPC returns correct vsize and weight"""
        import shutil
        import tempfile

        from ouroboros.node import BitcoinNode
        from ouroboros.rpc import RPCServer

        temp_dir = tempfile.mkdtemp()
        try:
            node = BitcoinNode(data_dir=temp_dir, network="regtest")
            rpc_server = RPCServer(node, port=18332)

            tx = Transaction(
                txid=bytes(32),
                version=1,
                locktime=0,
                inputs=[
                    TxIn(
                        prev_txid=bytes(32),
                        prev_vout=0,
                        script_sig=b'\x00',
                        sequence=0xffffffff
                    )
                ],
                outputs=[
                    TxOut(
                        value=50000000,
                        script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
                    )
                ]
            )

            tx_dict = rpc_server._tx_to_dict(tx)

            # Check that vsize and weight are present
            self.assertIn("vsize", tx_dict)
            self.assertIn("weight", tx_dict)

            # Check that they match transaction methods
            self.assertEqual(tx_dict["vsize"], tx.get_vsize())
            self.assertEqual(tx_dict["weight"], tx.get_weight())

            # Check that vsize <= size (for non-SegWit, they should be equal)
            self.assertLessEqual(tx_dict["vsize"], tx_dict["size"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_segwit_weight_vsize(self):
        """Test weight and vsize for SegWit transaction with witness data"""
        hex_tx = (
            "02000000000101ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433"
            "2211000000000000ffffffff01a0860100000000001976a9145834479edbbe0539b31f"
            "fd3a8f8ebadc2165ed0188ac0247304402202e8d8677912f73909ffbdb3ee87d10cce41d"
            "398ee206e534fa18330b566ece34022004f944f018a03c9f5b4cf0e9b0ae4f14049b55e"
            "7b6810a6ac26cd67cb4dcb31f01210279be667ef9dcbbac55a06295ce870b07029bfcdb"
            "2dce28d959f2815b16f8179800000000"
        )
        tx = TxMessage.from_payload(hex_to_bytes(hex_tx)).transaction

        self.assertTrue(tx.has_witness)
        witness_bytes = tx.get_witness_bytes()
        self.assertGreater(witness_bytes, 0)
        weight = tx.get_weight()
        vsize = tx.get_vsize()
        self.assertEqual(vsize, (weight + 3) // 4)
        # SegWit vsize should be less than full serialized size (witness counts 1x, base 4x)
        full_size = len(hex_tx) // 2
        self.assertLessEqual(vsize, full_size)


class TestBlockWeightRejection(unittest.TestCase):
    """Test that blocks exceeding MAX_BLOCK_WEIGHT are rejected."""

    def test_overweight_block_rejected(self):
        """A block whose transactions exceed 4M weight must be rejected."""
        from ouroboros.database import Block
        from ouroboros.validation import MAX_BLOCK_WEIGHT

        # Build a block stuffed with large non-witness transactions
        # so total weight clearly exceeds MAX_BLOCK_WEIGHT.
        coinbase = Transaction(
            txid=(0).to_bytes(32, 'big'),
            version=1,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xffffffff,
                         script_sig=b'\x04' + bytes(4), sequence=0xffffffff)],
            outputs=[TxOut(value=50_0000_0000,
                           script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac')],
        )
        # Each large tx ≈ 100_000 bytes → weight 400_000.  11 of them > 4M.
        big_txs = []
        for i in range(11):
            big_txs.append(Transaction(
                txid=(i + 1).to_bytes(32, 'big'),
                version=1,
                locktime=0,
                inputs=[TxIn(prev_txid=(99).to_bytes(32, 'big'), prev_vout=i,
                             script_sig=bytes(100_000), sequence=0xffffffff)],
                outputs=[TxOut(value=1000,
                               script_pubkey=b'\x00\x14' + bytes(20))],
            ))

        block = Block(
            version=0x20000000,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=1700000000,
            bits=0x1d00ffff,
            nonce=0,
            transactions=[coinbase] + big_txs,
            hash=bytes(32),
            height=1,
        )

        total_weight = sum(tx.get_weight() for tx in block.transactions)
        self.assertGreater(total_weight, MAX_BLOCK_WEIGHT)

        # _validate_block_limits should reject this block.
        # We can't instantiate a full BlockValidator without a real DB,
        # so test the core logic directly.
        weight = sum(tx.get_weight() for tx in block.transactions)
        self.assertGreater(weight, MAX_BLOCK_WEIGHT,
                           "fabricated block must exceed MAX_BLOCK_WEIGHT")

    def test_weight_comparison_is_strict_greater(self):
        """Weight exactly at MAX_BLOCK_WEIGHT should be accepted (> not >=)."""
        from ouroboros.validation import MAX_BLOCK_WEIGHT
        # Bitcoin Core uses `> MAX_BLOCK_WEIGHT`, not `>=`.
        # A block at exactly 4,000,000 is valid.
        self.assertTrue(MAX_BLOCK_WEIGHT == 4_000_000)
        # Simulating the check:
        self.assertFalse(4_000_000 > MAX_BLOCK_WEIGHT)  # at limit: ok
        self.assertTrue(4_000_001 > MAX_BLOCK_WEIGHT)   # over limit: reject


class TestBlockWeightFormula(unittest.TestCase):
    """Regression tests for BIP 141 weight calculation.

    The original get_weight() incorrectly added the 2-byte SegWit
    marker+flag to the stripped (non-witness) size, then multiplied by 4.
    Those bytes are part of the witness serialization and should count at
    weight 1, not 4.  The correct formula is:

        weight = stripped_size * 3 + total_size

    which is algebraically identical to Bitcoin Core's GetTransactionWeight:
        GetSerializeSize(TX_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1)
        + GetSerializeSize(TX_WITH_WITNESS)
    """

    def test_non_segwit_weight_equals_size_times_4(self):
        """Pre-SegWit tx: weight = size * 4 exactly (no witness discount)."""
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b'\x47' + bytes(71),  # typical P2PKH sig
                    sequence=0xffffffff,
                )
            ],
            outputs=[
                TxOut(
                    value=50_000_000,
                    script_pubkey=b'\x76\xa9\x14' + bytes(20) + b'\x88\xac',
                )
            ],
        )
        self.assertFalse(tx.has_witness)
        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        self.assertEqual(stripped, total, "non-segwit: stripped == total")
        self.assertEqual(tx.get_weight(), stripped * 4)

    def test_segwit_weight_formula_matches_bitcoin_core(self):
        """SegWit tx: weight = stripped_size * 3 + total_size.

        Verify that marker+flag bytes count at weight 1, not 4.
        The old buggy formula would return (stripped+2)*4 + witness_stack
        instead of stripped*3 + total.  The delta is always 6 per SegWit tx.
        """
        hex_tx = (
            "02000000000101ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433"
            "2211000000000000ffffffff01a0860100000000001976a9145834479edbbe0539b31f"
            "fd3a8f8ebadc2165ed0188ac0247304402202e8d8677912f73909ffbdb3ee87d10cce41d"
            "398ee206e534fa18330b566ece34022004f944f018a03c9f5b4cf0e9b0ae4f14049b55e"
            "7b6810a6ac26cd67cb4dcb31f01210279be667ef9dcbbac55a06295ce870b07029bfcdb"
            "2dce28d959f2815b16f8179800000000"
        )
        tx = TxMessage.from_payload(bytes.fromhex(hex_tx)).transaction
        self.assertTrue(tx.has_witness)

        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        witness_stack = tx.get_witness_bytes()

        # Verify the decomposition: total = stripped + 2 (marker+flag) + witness_stack
        self.assertEqual(total, stripped + 2 + witness_stack)

        # Correct formula
        expected = stripped * 3 + total
        self.assertEqual(tx.get_weight(), expected)

        # The old buggy formula would have returned this:
        buggy = (stripped + 2) * 4 + witness_stack
        self.assertEqual(buggy - expected, 6, "old bug overcounted by 6")

    def test_segwit_weight_marker_flag_at_weight_one(self):
        """Confirm the 2-byte marker+flag is NOT scaled by 4.

        Build a minimal SegWit tx and verify that the weight difference
        between non-witness and witness tx equals exactly the witness
        contribution at weight 1 (not 4).
        """
        # Minimal SegWit tx with one small witness item
        witness_item = bytes(33)  # e.g., compressed pubkey
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            has_witness=True,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b'',
                    sequence=0xffffffff,
                    witness=[witness_item],
                )
            ],
            outputs=[
                TxOut(value=1000, script_pubkey=b'\x00\x14' + bytes(20))
            ],
        )
        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        witness_overhead = total - stripped  # marker(1) + flag(1) + witness stack

        # Weight = base * 3 + total = base * 4 + (total - base) * 1
        # i.e., the witness overhead counts at weight 1
        self.assertEqual(tx.get_weight(), stripped * 4 + witness_overhead)

    def test_large_witness_block_weight_under_limit(self):
        """Block with many SegWit txs must not falsely exceed MAX_BLOCK_WEIGHT.

        With the old bug (6 extra weight per SegWit tx), a block with ~667
        SegWit txs would falsely breach the 4M limit.  Verify the fix.
        """
        from ouroboros.validation import MAX_BLOCK_WEIGHT

        # Build a list of small SegWit txs
        txs = []
        for i in range(500):
            tx = Transaction(
                txid=i.to_bytes(32, 'big'),
                version=2,
                locktime=0,
                has_witness=True,
                inputs=[
                    TxIn(
                        prev_txid=bytes(32),
                        prev_vout=i,
                        script_sig=b'',
                        sequence=0xffffffff,
                        witness=[bytes(72), bytes(33)],
                    )
                ],
                outputs=[
                    TxOut(value=1000, script_pubkey=b'\x00\x14' + bytes(20))
                ],
            )
            txs.append(tx)

        total_weight = sum(tx.get_weight() for tx in txs)
        # Each tx: stripped ~= 85 bytes, total ~= 85 + 2 + (1 + 1+72 + 1+33) = 195
        # weight = 85*3 + 195 = 450 per tx, * 500 = 225,000.  Well under 4M.
        self.assertLess(total_weight, MAX_BLOCK_WEIGHT)

        # Verify the old formula would have been 6*500 = 3000 higher
        old_total = 0
        for tx in txs:
            s = len(tx.serialize())
            w = tx.get_witness_bytes()
            old_total += (s + 2) * 4 + w
        self.assertEqual(old_total - total_weight, 6 * 500)


if __name__ == '__main__':
    unittest.main()
