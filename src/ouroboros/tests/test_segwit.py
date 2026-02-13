"""
Test SegWit transaction support.

This test verifies that SegWit transactions are handled correctly,
including weight and vsize calculations.
"""

import unittest
import sys
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.p2p_messages import TxMessage


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
        from ouroboros.rpc import RPCServer
        from ouroboros.node import BitcoinNode
        import tempfile
        import shutil
        
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


if __name__ == '__main__':
    unittest.main()
