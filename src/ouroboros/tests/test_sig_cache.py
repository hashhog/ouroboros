"""
Test signature verification cache.

Verifies SigCache behavior: lookup, insert, eviction, clear, and thread safety.
API (post W105 G7+G8+G9 fix): lookup/insert take (sighash, pubkey, sig, flags).
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


# ---------------------------------------------------------------------------
# Helpers — produce distinct test material
# ---------------------------------------------------------------------------

def _key(sighash_tag: str, pubkey_tag: str, sig_tag: str, flags: int = 0):
    """Return (sighash, pubkey, sig, flags) tuples for test use."""
    return (
        sighash_tag.encode().ljust(32, b'\x00'),
        pubkey_tag.encode().ljust(33, b'\x00'),
        sig_tag.encode().ljust(64, b'\x00'),
        flags,
    )


class TestSigCacheBasic(unittest.TestCase):
    """Test basic SigCache operations."""

    def test_lookup_miss(self):
        """lookup returns False for missing keys."""
        cache = SigCache(max_entries=100)
        sh, pk, sig, fl = _key("sh_abc", "pk_abc", "sig_abc")
        self.assertFalse(cache.lookup(sh, pk, sig, fl))

    def test_insert_and_lookup_hit(self):
        """insert followed by lookup returns True."""
        cache = SigCache(max_entries=100)
        sh, pk, sig, fl = _key("sh1", "pk1", "sig1")
        cache.insert(sh, pk, sig, fl)
        self.assertTrue(cache.lookup(sh, pk, sig, fl))

    def test_different_sighashes_are_independent(self):
        """Different sighashes produce distinct cache entries."""
        cache = SigCache(max_entries=100)
        sh1, pk, sig, fl = _key("sh_A", "pk_same", "sig_same")
        sh2, *_ = _key("sh_B", "pk_same", "sig_same")

        cache.insert(sh1, pk, sig, fl)

        self.assertTrue(cache.lookup(sh1, pk, sig, fl))
        self.assertFalse(cache.lookup(sh2, pk, sig, fl),
            "Different sighash must not hit the same cache entry")

    def test_different_pubkeys_are_independent(self):
        """Different pubkeys produce distinct cache entries."""
        cache = SigCache(max_entries=100)
        sh, pk1, sig, fl = _key("sh_same", "pk_A", "sig_same")
        _, pk2, _, _ = _key("sh_same", "pk_B", "sig_same")

        cache.insert(sh, pk1, sig, fl)

        self.assertTrue(cache.lookup(sh, pk1, sig, fl))
        self.assertFalse(cache.lookup(sh, pk2, sig, fl),
            "Different pubkey must not hit the same cache entry")

    def test_different_sigs_are_independent(self):
        """Different signatures produce distinct cache entries."""
        cache = SigCache(max_entries=100)
        sh, pk, sig1, fl = _key("sh_same", "pk_same", "sig_A")
        _, _, sig2, _ = _key("sh_same", "pk_same", "sig_B")

        cache.insert(sh, pk, sig1, fl)

        self.assertTrue(cache.lookup(sh, pk, sig1, fl))
        self.assertFalse(cache.lookup(sh, pk, sig2, fl),
            "Different sig must not hit the same cache entry")

    def test_flags_matter(self):
        """Cache entries with different flags are separate."""
        cache = SigCache(max_entries=100)
        sh, pk, sig, _ = _key("sh_x", "pk_x", "sig_x")

        cache.insert(sh, pk, sig, 0)

        self.assertTrue(cache.lookup(sh, pk, sig, 0))
        self.assertFalse(cache.lookup(sh, pk, sig, 1),
            "Different flags must not hit the same cache entry")

    def test_clear_removes_all(self):
        """clear() removes all entries."""
        cache = SigCache(max_entries=100)
        entries = [_key(f"sh{i}", f"pk{i}", f"sig{i}") for i in range(3)]

        for sh, pk, sig, fl in entries:
            cache.insert(sh, pk, sig, fl)

        self.assertEqual(len(cache), 3)
        cache.clear()
        self.assertEqual(len(cache), 0)

        for sh, pk, sig, fl in entries:
            self.assertFalse(cache.lookup(sh, pk, sig, fl))

    def test_len(self):
        """__len__ returns correct count."""
        cache = SigCache(max_entries=100)
        self.assertEqual(len(cache), 0)

        sh1, pk1, sig1, fl1 = _key("sh1", "pk1", "sig1")
        sh2, pk2, sig2, fl2 = _key("sh2", "pk2", "sig2")

        cache.insert(sh1, pk1, sig1, fl1)
        self.assertEqual(len(cache), 1)

        cache.insert(sh2, pk2, sig2, fl2)
        self.assertEqual(len(cache), 2)

        # Re-inserting same material doesn't increase count
        cache.insert(sh1, pk1, sig1, fl1)
        self.assertEqual(len(cache), 2)

    def test_duplicate_insert_no_increase(self):
        """Inserting the same material twice doesn't increase count."""
        cache = SigCache(max_entries=100)
        sh, pk, sig, fl = _key("sh_dup", "pk_dup", "sig_dup")

        cache.insert(sh, pk, sig, fl)
        self.assertEqual(len(cache), 1)

        cache.insert(sh, pk, sig, fl)
        self.assertEqual(len(cache), 1)


class TestSigCacheEviction(unittest.TestCase):
    """Test LRU eviction behavior."""

    def test_eviction_at_boundary(self):
        """Oldest entries are evicted when max_entries exceeded."""
        max_entries = 10
        cache = SigCache(max_entries=max_entries)

        entries = [_key(f"sh{i}", f"pk{i}", f"sig{i}") for i in range(max_entries)]
        for sh, pk, sig, fl in entries:
            cache.insert(sh, pk, sig, fl)

        self.assertEqual(len(cache), max_entries)

        # All should be present
        for sh, pk, sig, fl in entries:
            self.assertTrue(cache.lookup(sh, pk, sig, fl))

        # Insert one more - should evict oldest (entries[0])
        sh_new, pk_new, sig_new, fl_new = _key("sh_new", "pk_new", "sig_new")
        cache.insert(sh_new, pk_new, sig_new, fl_new)

        self.assertEqual(len(cache), max_entries)
        sh0, pk0, sig0, fl0 = entries[0]
        self.assertFalse(cache.lookup(sh0, pk0, sig0, fl0),  # evicted
            "Oldest entry should be evicted")
        self.assertTrue(cache.lookup(sh_new, pk_new, sig_new, fl_new))

        for sh, pk, sig, fl in entries[1:]:
            self.assertTrue(cache.lookup(sh, pk, sig, fl))

    def test_lru_ordering(self):
        """Recently accessed items are not evicted first."""
        max_entries = 5
        cache = SigCache(max_entries=max_entries)

        entries = [_key(f"sh{i}", f"pk{i}", f"sig{i}") for i in range(5)]
        for sh, pk, sig, fl in entries:
            cache.insert(sh, pk, sig, fl)

        # Access entries[0] (moves to end of LRU queue)
        sh0, pk0, sig0, fl0 = entries[0]
        self.assertTrue(cache.lookup(sh0, pk0, sig0, fl0))

        # Insert 2 more items - should evict entries[1], entries[2]
        sh5, pk5, sig5, fl5 = _key("sh5", "pk5", "sig5")
        sh6, pk6, sig6, fl6 = _key("sh6", "pk6", "sig6")
        cache.insert(sh5, pk5, sig5, fl5)
        cache.insert(sh6, pk6, sig6, fl6)

        # entries[0] should still be present (was accessed)
        self.assertTrue(cache.lookup(sh0, pk0, sig0, fl0))
        # entries[1], entries[2] should be evicted (oldest unused)
        sh1, pk1, sig1, fl1 = entries[1]
        sh2, pk2, sig2, fl2 = entries[2]
        self.assertFalse(cache.lookup(sh1, pk1, sig1, fl1))
        self.assertFalse(cache.lookup(sh2, pk2, sig2, fl2))
        # entries[3], entries[4] should still be present
        sh3, pk3, sig3, fl3 = entries[3]
        sh4, pk4, sig4, fl4 = entries[4]
        self.assertTrue(cache.lookup(sh3, pk3, sig3, fl3))
        self.assertTrue(cache.lookup(sh4, pk4, sig4, fl4))

    def test_max_entries_one(self):
        """Cache with max_entries=1 works correctly."""
        cache = SigCache(max_entries=1)

        sh1, pk1, sig1, fl1 = _key("sh1", "pk1", "sig1")
        sh2, pk2, sig2, fl2 = _key("sh2", "pk2", "sig2")

        cache.insert(sh1, pk1, sig1, fl1)
        self.assertEqual(len(cache), 1)
        self.assertTrue(cache.lookup(sh1, pk1, sig1, fl1))

        cache.insert(sh2, pk2, sig2, fl2)
        self.assertEqual(len(cache), 1)
        self.assertTrue(cache.lookup(sh2, pk2, sig2, fl2))
        self.assertFalse(cache.lookup(sh1, pk1, sig1, fl1))


class TestSigCacheThreadSafety(unittest.TestCase):
    """Test thread safety of SigCache."""

    def test_concurrent_inserts(self):
        """Concurrent inserts don't corrupt cache."""
        cache = SigCache(max_entries=1000)
        num_threads = 10
        inserts_per_thread = 100

        def insert_keys(thread_id):
            for i in range(inserts_per_thread):
                sh, pk, sig, fl = _key(f"sh_{thread_id}_{i}", f"pk_{thread_id}_{i}",
                                       f"sig_{thread_id}_{i}")
                cache.insert(sh, pk, sig, fl)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(insert_keys, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        self.assertEqual(len(cache), num_threads * inserts_per_thread)

    def test_concurrent_lookups(self):
        """Concurrent lookups don't corrupt cache."""
        cache = SigCache(max_entries=1000)
        num_keys = 100

        entries = [_key(f"sh{i}", f"pk{i}", f"sig{i}") for i in range(num_keys)]
        for sh, pk, sig, fl in entries:
            cache.insert(sh, pk, sig, fl)

        hits = [0]
        lock = threading.Lock()

        def lookup_keys():
            local_hits = 0
            for sh, pk, sig, fl in entries:
                if cache.lookup(sh, pk, sig, fl):
                    local_hits += 1
            with lock:
                hits[0] += local_hits

        threads = [threading.Thread(target=lookup_keys) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

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
                    i = random.randint(0, 50)
                    sh, pk, sig, fl = _key(f"sh{i}", f"pk{i}", f"sig{i}")
                    if op == "insert":
                        cache.insert(sh, pk, sig, fl)
                    elif op == "lookup":
                        cache.lookup(sh, pk, sig, fl)
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

        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")


class TestSigCacheIntegration(unittest.TestCase):
    """Test cache integration patterns."""

    def test_verification_workflow(self):
        """Simulate typical verification workflow."""
        cache = SigCache(max_entries=50_000)

        sighash = b"sighash_for_tx_abc" + bytes(14)
        pubkey0 = b"pubkey_input_0" + bytes(19)
        sig0 = b"sig_input_0" + bytes(53)
        pubkey1 = b"pubkey_input_1" + bytes(19)
        sig1 = b"sig_input_1" + bytes(53)
        flags = 0x0001

        # First verification - cache miss
        self.assertFalse(cache.lookup(sighash, pubkey0, sig0, flags))
        self.assertFalse(cache.lookup(sighash, pubkey1, sig1, flags))

        # Simulate successful verification
        cache.insert(sighash, pubkey0, sig0, flags)
        cache.insert(sighash, pubkey1, sig1, flags)

        # Second verification (mempool->block) - cache hit
        self.assertTrue(cache.lookup(sighash, pubkey0, sig0, flags))
        self.assertTrue(cache.lookup(sighash, pubkey1, sig1, flags))

    def test_reorg_clear_workflow(self):
        """Cache is cleared on reorg."""
        cache = SigCache(max_entries=1000)

        entries = [_key(f"sh{i}", f"pk{i}", f"sig{i}") for i in range(100)]
        for sh, pk, sig, fl in entries:
            cache.insert(sh, pk, sig, fl)

        self.assertEqual(len(cache), 100)

        # Simulate reorg - clear cache
        cache.clear()

        self.assertEqual(len(cache), 0)

        for sh, pk, sig, fl in entries:
            self.assertFalse(cache.lookup(sh, pk, sig, fl))


if __name__ == "__main__":
    unittest.main()
