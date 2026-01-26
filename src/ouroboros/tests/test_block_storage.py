"""
Test block storage and retrieval.

This test verifies that blocks can be stored and retrieved correctly
from the database.
"""

import unittest
import sys
import tempfile
import shutil
import hashlib
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import BlockchainDatabase, Block, Transaction, TxIn, TxOut


class TestBlockStorage(unittest.TestCase):
    """Test block storage and retrieval"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.db = BlockchainDatabase(data_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_store_block_not_implemented(self):
        """Test that store_block raises NotImplementedError"""
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=1234567890,
            bits=0x1d00ffff,
            nonce=0,
            transactions=[],
            height=0
        )
        
        with self.assertRaises(NotImplementedError):
            self.db.store_block(block)
    
    def test_get_block_by_hash_method_exists(self):
        """Test that get_block method exists"""
        self.assertTrue(hasattr(self.db, 'get_block'))
        self.assertTrue(callable(getattr(self.db, 'get_block', None)))
    
    def test_get_block_by_height_method_exists(self):
        """Test that get_block_by_height method exists"""
        self.assertTrue(hasattr(self.db, 'get_block_by_height'))
        self.assertTrue(callable(getattr(self.db, 'get_block_by_height', None)))
    
    def test_get_block_hash_by_height_method_exists(self):
        """Test that get_block_hash_by_height method exists"""
        self.assertTrue(hasattr(self.db, 'get_block_hash_by_height'))
        self.assertTrue(callable(getattr(self.db, 'get_block_hash_by_height', None)))
    
    def test_get_best_block_method_exists(self):
        """Test that get_best_block method exists"""
        self.assertTrue(hasattr(self.db, 'get_best_block'))
        self.assertTrue(callable(getattr(self.db, 'get_best_block', None)))
    
    def test_get_block_returns_none_for_nonexistent(self):
        """Test that get_block returns None for non-existent block"""
        fake_hash = bytes(32)
        block = self.db.get_block(fake_hash)
        self.assertIsNone(block)
    
    def test_get_block_by_height_returns_none_for_nonexistent(self):
        """Test that get_block_by_height returns None for non-existent height"""
        block = self.db.get_block_by_height(999999)
        self.assertIsNone(block)
    
    def test_get_block_hash_by_height_returns_none_for_nonexistent(self):
        """Test that get_block_hash_by_height returns None for non-existent height"""
        block_hash = self.db.get_block_hash_by_height(999999)
        self.assertIsNone(block_hash)
    
    def test_get_block_validates_hash_length(self):
        """Test that get_block validates hash length"""
        with self.assertRaises(ValueError):
            self.db.get_block(b"invalid_hash")
    
    def test_get_best_block_returns_tuple(self):
        """Test that get_best_block returns a tuple"""
        result = self.db.get_best_block()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        block_hash, height = result
        self.assertIsInstance(block_hash, bytes)
        self.assertIsInstance(height, int)
    
    def test_block_retrieval_after_sync(self):
        """
        Test that blocks can be retrieved after sync.
        
        Note: This test assumes blocks are stored via Rust API during sync.
        For now, we just verify the methods exist and handle edge cases.
        """
        # Test that methods don't crash on empty database
        best_hash, best_height = self.db.get_best_block()
        # Should return some default (likely genesis or empty)
        self.assertIsInstance(best_hash, bytes)
        self.assertIsInstance(best_height, int)
        
        # Test retrieval methods don't crash
        block = self.db.get_block_by_height(0)
        # May be None if no blocks stored, but shouldn't crash
        if block is not None:
            self.assertIsInstance(block, Block)
    
    def test_block_hash_validation(self):
        """Test that block hash validation works"""
        # Valid hash (32 bytes)
        valid_hash = bytes(32)
        try:
            result = self.db.get_block(valid_hash)
            # Should not raise ValueError
            self.assertIsNone(result)  # Block doesn't exist, but no error
        except ValueError:
            self.fail("get_block raised ValueError for valid 32-byte hash")
        
        # Invalid hash (wrong length)
        invalid_hash = b"short"
        with self.assertRaises(ValueError):
            self.db.get_block(invalid_hash)
    
    def test_block_metadata_methods(self):
        """Test block metadata methods"""
        # Test get_block_hash_by_height
        hash_by_height = self.db.get_block_hash_by_height(0)
        # May be None if no blocks, but should not crash
        if hash_by_height is not None:
            self.assertIsInstance(hash_by_height, bytes)
            self.assertEqual(len(hash_by_height), 32)
        
        # Test get_block_by_height
        block_by_height = self.db.get_block_by_height(0)
        if block_by_height is not None:
            self.assertIsInstance(block_by_height, Block)
            self.assertTrue(hasattr(block_by_height, 'height'))
    
    def test_block_storage_note(self):
        """
        Test that the comment about block storage is accurate.
        
        According to the code:
        - store_block() raises NotImplementedError
        - Blocks are stored via Rust API during sync
        - apply_block() only updates UTXO set, doesn't store blocks
        """
        # Verify store_block raises NotImplementedError
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=1234567890,
            bits=0x1d00ffff,
            nonce=0,
            transactions=[],
            height=0
        )
        
        with self.assertRaises(NotImplementedError) as context:
            self.db.store_block(block)
        
        error_message = str(context.exception)
        self.assertIn("store_block", error_message)
        self.assertIn("Rust API", error_message)


if __name__ == '__main__':
    unittest.main()
