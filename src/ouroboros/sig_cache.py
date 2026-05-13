"""
Signature verification cache.

Avoids redundant script verification during block connection and mempool acceptance.
Successful verifications are cached; failures are never cached to ensure safety.

Key format: SHA256(nonce || sighash || pubkey || sig || flags_le32)[:8]
  - nonce:   32-byte random value generated at __init__ (per-process secret)
  - sighash: the serialised sighash bytes covering this input
  - pubkey:  the public key bytes
  - sig:     the signature bytes
  - flags:   script verification flags (little-endian uint32)

The nonce prevents adversarial pre-image attacks: an attacker who can observe
txids / input indices in the mempool cannot predict cache keys and craft
collisions.

Reference: bitcoin/src/script/sigcache.h — GetRandHash nonce + CSHA256 salted
           ComputeEntryECDSA / ComputeEntrySchnorr
"""

import hashlib
import os
import struct
from collections import OrderedDict
from threading import Lock

# Type alias for the internal (hashed) cache key stored in the OrderedDict.
CacheKey = bytes  # 8-byte prefix of SHA256(nonce||material)


class SigCache:
    """
    Bounded LRU cache for successful script verifications.

    Only successful verifications are cached. The cache key includes
    the actual cryptographic material (sighash, pubkey, sig) plus the
    script verification flags, all salted with a per-process random
    nonce so that keys are unpredictable to external observers.

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
        # Per-process random nonce — prevents adversarial cache-key prediction.
        # Mirrors Core's GetRandHash() call in SignatureCache constructor
        # (sigcache.cpp:22-32).
        self.nonce: bytes = os.urandom(32)
        self._cache: OrderedDict[CacheKey, bool] = OrderedDict()
        self._lock = Lock()

    def _make_key(self, sighash: bytes, pubkey: bytes, sig: bytes, flags: int) -> CacheKey:
        """Derive the 8-byte cache key from cryptographic material."""
        digest = hashlib.sha256(
            self.nonce + sighash + pubkey + sig + struct.pack("<I", flags)
        ).digest()
        return digest[:8]

    def lookup(self, sighash: bytes, pubkey: bytes, sig: bytes, flags: int) -> bool:
        """
        Check if a verification result is cached.

        Args:
            sighash: Serialised sighash bytes for this input.
            pubkey:  Public key bytes.
            sig:     Signature bytes.
            flags:   Script verification flags.

        Returns:
            True if the verification was previously cached as successful,
            False otherwise.
        """
        key = self._make_key(sighash, pubkey, sig, flags)
        with self._lock:
            if key in self._cache:
                # Move to end for LRU ordering
                self._cache.move_to_end(key)
                return True
            return False

    def insert(self, sighash: bytes, pubkey: bytes, sig: bytes, flags: int) -> None:
        """
        Cache a successful verification.

        Args:
            sighash: Serialised sighash bytes for this input.
            pubkey:  Public key bytes.
            sig:     Signature bytes.
            flags:   Script verification flags.
        """
        key = self._make_key(sighash, pubkey, sig, flags)
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
