"""
Test signature verification cache.

Verifies SigCache behavior: lookup, insert, eviction, clear, and thread safety.
"""

import random
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.sig_cache import SigCache  # noqa: E402


class TestSigCacheBasic(unittest.TestCase):
    """Test basic SigCache operations."""

    def test_lookup_miss(self):
        """lookup returns False for missing keys."""
        cache = SigCache(max_entries=100)
        key = ("abc123", 0, 0)
        self.assertFalse(cache.lookup(key))

    def test_insert_and_lookup_hit(self):
        """insert followed by lookup returns True."""
        cache = SigCache(max_entries=100)
        key = ("abc123", 0, 0)

        cache.insert(key)
        self.assertTrue(cache.lookup(key))

    def test_different_keys_independent(self):
        """Different keys are independent in the cache."""
        cache = SigCache(max_entries=100)
        key1 = ("tx1", 0, 0)
        key2 = ("tx2", 0, 0)
        key3 = ("tx1", 1, 0)  # same txid, different input index
        key4 = ("tx1", 0, 1)  # same txid and index, different flags

        cache.insert(key1)

        self.assertTrue(cache.lookup(key1))
        self.assertFalse(cache.lookup(key2))
        self.assertFalse(cache.lookup(key3))
        self.assertFalse(cache.lookup(key4))

    def test_flags_matter(self):
        """Cache keys with different flags are separate."""
        cache = SigCache(max_entries=100)
        key_no_witness = ("txid", 0, 0)
        key_with_witness = ("txid", 0, 1)  # different flags

        cache.insert(key_no_witness)

        self.assertTrue(cache.lookup(key_no_witness))
        self.assertFalse(cache.lookup(key_with_witness))

    def test_clear_removes_all(self):
        """clear() removes all entries."""
        cache = SigCache(max_entries=100)
        keys = [("tx1", 0, 0), ("tx2", 1, 0), ("tx3", 2, 1)]

        for key in keys:
            cache.insert(key)

        self.assertEqual(len(cache), 3)

        cache.clear()

        self.assertEqual(len(cache), 0)
        for key in keys:
            self.assertFalse(cache.lookup(key))

    def test_len(self):
        """__len__ returns correct count."""
        cache = SigCache(max_entries=100)
        self.assertEqual(len(cache), 0)

        cache.insert(("tx1", 0, 0))
        self.assertEqual(len(cache), 1)

        cache.insert(("tx2", 0, 0))
        self.assertEqual(len(cache), 2)

        # Re-inserting same key doesn't increase count
        cache.insert(("tx1", 0, 0))
        self.assertEqual(len(cache), 2)

    def test_duplicate_insert_no_increase(self):
        """Inserting the same key twice doesn't increase count."""
        cache = SigCache(max_entries=100)
        key = ("abc123", 0, 0)

        cache.insert(key)
        self.assertEqual(len(cache), 1)

        cache.insert(key)
        self.assertEqual(len(cache), 1)


class TestSigCacheEviction(unittest.TestCase):
    """Test LRU eviction behavior."""

    def test_eviction_at_boundary(self):
        """Oldest entries are evicted when max_entries exceeded."""
        max_entries = 10
        cache = SigCache(max_entries=max_entries)

        # Insert max_entries items
        for i in range(max_entries):
            cache.insert((f"tx{i}", 0, 0))

        self.assertEqual(len(cache), max_entries)

        # All should be present
        for i in range(max_entries):
            self.assertTrue(cache.lookup((f"tx{i}", 0, 0)))

        # Insert one more - should evict oldest (tx0)
        cache.insert(("tx_new", 0, 0))

        self.assertEqual(len(cache), max_entries)
        self.assertFalse(cache.lookup(("tx0", 0, 0)))  # evicted
        self.assertTrue(cache.lookup(("tx_new", 0, 0)))  # present

        # tx1-tx9 should still be present
        for i in range(1, max_entries):
            self.assertTrue(cache.lookup((f"tx{i}", 0, 0)))

    def test_lru_ordering(self):
        """Recently accessed items are not evicted first."""
        max_entries = 5
        cache = SigCache(max_entries=max_entries)

        # Insert 5 items: tx0, tx1, tx2, tx3, tx4
        for i in range(5):
            cache.insert((f"tx{i}", 0, 0))

        # Access tx0 (moves to end of LRU queue)
        self.assertTrue(cache.lookup(("tx0", 0, 0)))

        # Insert 2 more items - should evict tx1, tx2 (oldest unused)
        cache.insert(("tx5", 0, 0))
        cache.insert(("tx6", 0, 0))

        # tx0 should still be present (was accessed)
        self.assertTrue(cache.lookup(("tx0", 0, 0)))
        # tx1, tx2 should be evicted (oldest unused)
        self.assertFalse(cache.lookup(("tx1", 0, 0)))
        self.assertFalse(cache.lookup(("tx2", 0, 0)))
        # tx3, tx4 should still be present
        self.assertTrue(cache.lookup(("tx3", 0, 0)))
        self.assertTrue(cache.lookup(("tx4", 0, 0)))

    def test_max_entries_one(self):
        """Cache with max_entries=1 works correctly."""
        cache = SigCache(max_entries=1)

        cache.insert(("tx1", 0, 0))
        self.assertEqual(len(cache), 1)
        self.assertTrue(cache.lookup(("tx1", 0, 0)))

        cache.insert(("tx2", 0, 0))
        self.assertEqual(len(cache), 1)
        self.assertTrue(cache.lookup(("tx2", 0, 0)))
        self.assertFalse(cache.lookup(("tx1", 0, 0)))


class TestSigCacheThreadSafety(unittest.TestCase):
    """Test thread safety of SigCache."""

    def test_concurrent_inserts(self):
        """Concurrent inserts don't corrupt cache."""
        cache = SigCache(max_entries=1000)
        num_threads = 10
        inserts_per_thread = 100

        def insert_keys(thread_id):
            for i in range(inserts_per_thread):
                cache.insert((f"tx_{thread_id}_{i}", 0, 0))

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(insert_keys, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        # All keys should be present (1000 total, max_entries=1000)
        self.assertEqual(len(cache), num_threads * inserts_per_thread)

    def test_concurrent_lookups(self):
        """Concurrent lookups don't corrupt cache."""
        cache = SigCache(max_entries=1000)
        num_keys = 100

        # Insert keys
        for i in range(num_keys):
            cache.insert((f"tx{i}", 0, 0))

        # Concurrent lookups
        hits = [0]
        lock = threading.Lock()

        def lookup_keys():
            local_hits = 0
            for i in range(num_keys):
                if cache.lookup((f"tx{i}", 0, 0)):
                    local_hits += 1
            with lock:
                hits[0] += local_hits

        threads = [threading.Thread(target=lookup_keys) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All lookups should have been hits
        self.assertEqual(hits[0], 10 * num_keys)

    def test_concurrent_mixed_operations(self):
        """Concurrent insert/lookup/clear operations are safe."""
        cache = SigCache(max_entries=100)
        operations = 1000
        errors = []

        def random_operations():
            try:
                for _ in range(operations):
                    op = random.choice(["insert", "lookup", "clear", "len"])
                    key = (f"tx{random.randint(0, 50)}", random.randint(0, 3), 0)
                    if op == "insert":
                        cache.insert(key)
                    elif op == "lookup":
                        cache.lookup(key)
                    elif op == "clear":
                        cache.clear()
                    elif op == "len":
                        len(cache)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=random_operations) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should have occurred
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")


class TestSigCacheIntegration(unittest.TestCase):
    """Test cache integration patterns."""

    def test_verification_workflow(self):
        """Simulate typical verification workflow."""
        cache = SigCache(max_entries=50_000)

        # Transaction with 2 inputs
        txid = "abcd1234" * 8
        flags = 0x0001  # Some flags

        # First verification - cache miss
        self.assertFalse(cache.lookup((txid, 0, flags)))
        self.assertFalse(cache.lookup((txid, 1, flags)))

        # Simulate successful verification
        cache.insert((txid, 0, flags))
        cache.insert((txid, 1, flags))

        # Second verification (mempool->block) - cache hit
        self.assertTrue(cache.lookup((txid, 0, flags)))
        self.assertTrue(cache.lookup((txid, 1, flags)))

    def test_reorg_clear_workflow(self):
        """Cache is cleared on reorg."""
        cache = SigCache(max_entries=1000)

        # Insert some verifications
        for i in range(100):
            cache.insert((f"tx{i}", 0, 0))

        self.assertEqual(len(cache), 100)

        # Simulate reorg - clear cache
        cache.clear()

        self.assertEqual(len(cache), 0)

        # All previous entries are gone
        for i in range(100):
            self.assertFalse(cache.lookup((f"tx{i}", 0, 0)))


if __name__ == "__main__":
    unittest.main()
