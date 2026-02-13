"""
Test new RPC methods.

This test verifies that the new RPC methods (getrawmempool, getblockheader, gettxout)
are implemented and work correctly.
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode
from ouroboros.rpc import RPCServer


class TestRPCMethods(unittest.TestCase):
    """Test new RPC methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc_server = RPCServer(self.node, port=18332)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_getrawmempool_method_exists(self):
        """Test that getrawmempool method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_getrawmempool'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_getrawmempool', None)))
    
    def test_getrawmempool_returns_list(self):
        """Test that getrawmempool returns a list when verbose=False"""
        import asyncio
        
        async def test():
            result = await self.rpc_server.rpc_getrawmempool(verbose=False)
            self.assertIsInstance(result, list)
        
        asyncio.run(test())
    
    def test_getrawmempool_verbose_returns_dict(self):
        """Test that getrawmempool returns a dict when verbose=True"""
        import asyncio
        
        async def test():
            result = await self.rpc_server.rpc_getrawmempool(verbose=True)
            self.assertIsInstance(result, dict)
        
        asyncio.run(test())
    
    def test_getblockheader_method_exists(self):
        """Test that getblockheader method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_getblockheader'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_getblockheader', None)))
    
    def test_getblockheader_handles_invalid_hash(self):
        """Test that getblockheader handles invalid hash"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_getblockheader("invalid_hash", verbose=True)
        
        asyncio.run(test())
    
    def test_getblockheader_handles_not_found(self):
        """Test that getblockheader handles block not found"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            # Use a valid hex string but non-existent block
            fake_hash = "0" * 64
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_getblockheader(fake_hash, verbose=True)
        
        asyncio.run(test())
    
    def test_gettxout_method_exists(self):
        """Test that gettxout method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_gettxout'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_gettxout', None)))
    
    def test_gettxout_handles_invalid_txid(self):
        """Test that gettxout handles invalid transaction ID"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_gettxout("invalid_txid", 0, includemempool=True)
        
        asyncio.run(test())
    
    def test_gettxout_returns_none_for_nonexistent(self):
        """Test that gettxout returns None for non-existent UTXO"""
        import asyncio
        
        async def test():
            # Use a valid hex string but non-existent transaction
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=True)
            # Should return None, not raise an exception
            self.assertIsNone(result)
        
        asyncio.run(test())
    
    def test_gettxout_with_mempool(self):
        """Test that gettxout checks mempool when includemempool=True"""
        import asyncio
        
        async def test():
            # Even if mempool is empty, should not raise exception
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=True)
            self.assertIsNone(result)
        
        asyncio.run(test())
    
    def test_gettxout_without_mempool(self):
        """Test that gettxout skips mempool when includemempool=False"""
        import asyncio

        async def test():
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=False)
            self.assertIsNone(result)

        asyncio.run(test())

    def test_sendrawtransaction_method_exists(self):
        """Test that sendrawtransaction method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_sendrawtransaction'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_sendrawtransaction', None)))

    def test_sendrawtransaction_invalid_hex(self):
        """Test sendrawtransaction rejects invalid hex"""
        import asyncio
        from fastapi import HTTPException

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction("nothex")
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Invalid hex", ctx.exception.detail)

        asyncio.run(test())

    def test_sendrawtransaction_coinbase_rejected(self):
        """Test sendrawtransaction rejects coinbase transactions"""
        import asyncio
        from fastapi import HTTPException

        # Genesis block coinbase tx hex
        coinbase_hex = (
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff1d030f8d13049faa805a063538706f6f6c0c00010000fe22030000000000ffffff"
            "ff015341cb04000000001976a914f11298ce777cb5db5c09250cad4eb856b1e366ef88ac"
            "00000000"
        )

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction(coinbase_hex)
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Coinbase", ctx.exception.detail)

        asyncio.run(test())

    def test_sendrawtransaction_mempool_unavailable(self):
        """Test sendrawtransaction when mempool is not available"""
        import asyncio
        from fastapi import HTTPException

        # Valid non-coinbase tx (P2PKH from Bitcoin Core test)
        tx_hex = (
            "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d"
            "000000008a4730440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d5027"
            "8380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a218"
            "8e96e01410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
            "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8fffffff"
            "f01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00"
            "000000"
        )

        async def test():
            # Node has no mempool (not started) -> 500
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction(tx_hex)
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("Mempool", ctx.exception.detail)

        asyncio.run(test())


if __name__ == '__main__':
    unittest.main()
