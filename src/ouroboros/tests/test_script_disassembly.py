"""
Test script disassembly.

This test verifies that Bitcoin scripts are correctly disassembled
to human-readable ASM format.
"""

import unittest
import sys
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.script import disassemble_script


class TestScriptDisassembly(unittest.TestCase):
    """Test script disassembly"""
    
    def test_disassemble_p2pkh_script(self):
        """Test disassembling a P2PKH script"""
        # P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        # Example: 76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac
        script = bytes.fromhex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
        
        asm = disassemble_script(script)
        
        # Should contain OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
        self.assertIn("OP_DUP", asm)
        self.assertIn("OP_HASH160", asm)
        self.assertIn("OP_EQUALVERIFY", asm)
        self.assertIn("OP_CHECKSIG", asm)
        # Should contain the pubkey hash
        self.assertIn("89abcdefabbaabbaabbaabbaabbaabbaabbaabba", asm)
    
    def test_disassemble_empty_script(self):
        """Test disassembling an empty script"""
        script = b""
        asm = disassemble_script(script)
        self.assertEqual(asm, "")
    
    def test_disassemble_op_0(self):
        """Test disassembling OP_0"""
        script = bytes([0x00])
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_0")
    
    def test_disassemble_op_numbers(self):
        """Test disassembling OP_1 through OP_16"""
        for i in range(1, 17):
            opcode = 0x50 + i
            script = bytes([opcode])
            asm = disassemble_script(script)
            self.assertEqual(asm, f"OP_{i}")
    
    def test_disassemble_data_push(self):
        """Test disassembling data push opcodes"""
        # Direct push of 3 bytes
        data = b"abc"
        script = bytes([len(data)]) + data
        asm = disassemble_script(script)
        
        # Should contain the hex representation of the data
        self.assertIn(data.hex(), asm)
    
    def test_disassemble_op_return(self):
        """Test disassembling OP_RETURN"""
        script = bytes([0x6a])  # OP_RETURN
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_RETURN")
    
    def test_disassemble_common_opcodes(self):
        """Test disassembling common opcodes"""
        # OP_DUP
        script = bytes([0x76])
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_DUP")
        
        # OP_HASH160
        script = bytes([0xa9])
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_HASH160")
        
        # OP_CHECKSIG
        script = bytes([0xac])
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_CHECKSIG")
        
        # OP_EQUAL
        script = bytes([0x87])
        asm = disassemble_script(script)
        self.assertEqual(asm, "OP_EQUAL")
    
    def test_disassemble_unknown_opcode(self):
        """Test disassembling unknown opcode"""
        script = bytes([0xff])  # Unknown opcode
        asm = disassemble_script(script)
        # Should return OP_UNKNOWN_ff or similar
        self.assertIn("OP_UNKNOWN", asm)
    
    def test_disassemble_p2sh_script(self):
        """Test disassembling a P2SH script"""
        # P2SH script: OP_HASH160 <scripthash> OP_EQUAL
        # Example: a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87
        script = bytes.fromhex("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")
        
        asm = disassemble_script(script)
        
        # Should contain OP_HASH160 and OP_EQUAL
        self.assertIn("OP_HASH160", asm)
        self.assertIn("OP_EQUAL", asm)
        # Should contain the script hash
        self.assertIn("89abcdefabbaabbaabbaabbaabbaabbaabbaabba", asm)
    
    def test_disassemble_op_pushdata1(self):
        """Test disassembling OP_PUSHDATA1"""
        # OP_PUSHDATA1 followed by length byte and data
        data = b"test" * 10  # 40 bytes
        script = bytes([0x4c, len(data)]) + data
        asm = disassemble_script(script)
        
        # Should contain the data
        self.assertIn(data.hex(), asm)
    
    def test_rpc_integration(self):
        """Test that RPC uses script disassembly"""
        from ouroboros.rpc import RPCServer
        from ouroboros.node import BitcoinNode
        from ouroboros.database import TxIn, TxOut
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        try:
            node = BitcoinNode(data_dir=temp_dir, network="regtest")
            rpc_server = RPCServer(node, port=18332)
            
            # Test _vin_to_dict
            vin = TxIn(
                prev_txid=bytes(32),
                prev_vout=0,
                script_sig=bytes.fromhex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
                sequence=0xffffffff
            )
            
            vin_dict = rpc_server._vin_to_dict(vin, 0, None)
            self.assertIn("asm", vin_dict["scriptSig"])
            self.assertNotEqual(vin_dict["scriptSig"]["asm"], "")
            self.assertIn("OP_DUP", vin_dict["scriptSig"]["asm"])
            
            # Test _vout_to_dict
            vout = TxOut(
                value=50000000,
                script_pubkey=bytes.fromhex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
            )
            
            vout_dict = rpc_server._vout_to_dict(vout, 0)
            self.assertIn("asm", vout_dict["scriptPubKey"])
            self.assertNotEqual(vout_dict["scriptPubKey"]["asm"], "")
            self.assertIn("OP_DUP", vout_dict["scriptPubKey"]["asm"])
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
