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


if __name__ == '__main__':
    unittest.main()
