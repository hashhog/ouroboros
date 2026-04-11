"""
Signature verification cache.

Avoids redundant script verification during block connection and mempool acceptance.
Successful verifications are cached; failures are never cached to ensure safety.

Key format: (txid_hex, input_index, flags) where:
  - txid_hex: the transaction id as a hex string
  - input_index: which input was verified
  - flags: script verification flags used

Reference: bitcoin/src/script/sigcache.h
"""

from collections import OrderedDict
from threading import Lock

# Type alias for cache keys
CacheKey = tuple[str, int, int]  # (txid_hex, input_index, flags)


class SigCache:
    """
    Bounded LRU cache for successful script verifications.

    Only successful verifications are cached. The cache key includes
    script verification flags because stricter flags (e.g. WITNESS)
    may reject scripts that pass with looser flags.

    Thread-safe via a lock around all mutations.
    """

    def __init__(self, max_entries: int = 50_000):
        """
        Initialize the cache.

        Args:
            max_entries: Maximum number of entries before LRU eviction.
                         Default 50,000 matches Bitcoin Core's default.
        """
        self._max_entries = max_entries
        self._cache: OrderedDict[CacheKey, bool] = OrderedDict()
        self._lock = Lock()

    def lookup(self, key: CacheKey) -> bool:
        """
        Check if a verification result is cached.

        Args:
            key: Tuple of (txid_hex, input_index, flags)

        Returns:
            True if the verification was previously cached as successful,
            False otherwise.
        """
        with self._lock:
            if key in self._cache:
                # Move to end for LRU ordering
                self._cache.move_to_end(key)
                return True
            return False

    def insert(self, key: CacheKey) -> None:
        """
        Cache a successful verification.

        Args:
            key: Tuple of (txid_hex, input_index, flags)
        """
        with self._lock:
            if key in self._cache:
                # Already cached, just move to end
                self._cache.move_to_end(key)
                return

            # Insert new entry
            self._cache[key] = True

            # Evict oldest entries if over capacity
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        """
        Clear all cached entries.

        Called on reorg to prevent stale entries from an invalidated chain.
        """
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Return the current number of cached entries."""
        with self._lock:
            return len(self._cache)
