"""
BIP 158 Compact Block Filters.

Implements basic block filters (filter type 0) for light-client support.
Each filter is a Golomb-coded set (GCS) encoding scriptPubKeys from all
outputs created in the block and all outputs spent by inputs in the block.

Parameters (BIP 158 basic filter):
    P = 19   (Golomb-Rice coding parameter)
    M = 784931  (false positive rate parameter: 1/M ≈ fp rate)

Construction:
    1. Collect all scriptPubKeys from outputs and spent inputs (excluding
       OP_RETURN outputs and the coinbase input's empty prevout).
    2. Derive a 16-byte SipHash key from the block hash (first 16 bytes of
       the block hash in *internal* byte order, i.e. little-endian).
    3. For each item, compute ``SipHash-2-4(key, item) mod (N * M)`` where
       N is the number of items in the set.
    4. Sort the hashed values.
    5. Compute deltas between consecutive sorted values.
    6. Golomb-Rice encode each delta with parameter P.
    7. Prefix the encoded bitstream with N as a CompactSize (varint).

Filter header (for chaining):
    ``filter_header = dSHA256(filter_hash || prev_filter_header)``
    where ``filter_hash = dSHA256(filter_bytes)``.

Reference:
    https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

from ouroboros.compact_blocks import _siphash_2_4

if TYPE_CHECKING:
    from ouroboros.database import Block, BlockchainDatabase

# ---------------------------------------------------------------------------
# BIP 158 basic filter parameters
# ---------------------------------------------------------------------------

BASIC_FILTER_TYPE = 0
GCS_P = 19                   # Golomb-Rice coding parameter (bits)
GCS_M = 784931               # False-positive rate parameter
OP_RETURN = 0x6A             # OP_RETURN opcode


# ---------------------------------------------------------------------------
# Varint (CompactSize) helpers
# ---------------------------------------------------------------------------

def _encode_compact_size(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack('<B', n)
    elif n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def _decode_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    first = data[offset]
    if first < 0xFD:
        return first, 1
    elif first == 0xFD:
        return struct.unpack_from('<H', data, offset + 1)[0], 3
    elif first == 0xFE:
        return struct.unpack_from('<I', data, offset + 1)[0], 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], 9


# ---------------------------------------------------------------------------
# Bitwriter / Bitreader for Golomb-Rice coding
# ---------------------------------------------------------------------------

class _BitWriter:
    """Accumulates individual bits and flushes to a byte buffer."""

    __slots__ = ('_buf', '_accum', '_nbits')

    def __init__(self) -> None:
        self._buf = bytearray()
        self._accum = 0
        self._nbits = 0

    def write_bit(self, bit: int) -> None:
        self._accum = (self._accum << 1) | (bit & 1)
        self._nbits += 1
        if self._nbits == 8:
            self._buf.append(self._accum)
            self._accum = 0
            self._nbits = 0

    def write_bits_be(self, value: int, nbits: int) -> None:
        """Write *nbits* from *value* in big-endian (MSB first) order."""
        for i in range(nbits - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def flush(self) -> bytes:
        """Pad remaining bits with zeros and return the byte string."""
        if self._nbits > 0:
            self._accum <<= (8 - self._nbits)
            self._buf.append(self._accum)
            self._accum = 0
            self._nbits = 0
        return bytes(self._buf)


class _BitReader:
    """Read individual bits from a byte buffer."""

    __slots__ = ('_data', '_byte_pos', '_bit_pos')

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._byte_pos = 0
        self._bit_pos = 0

    def read_bit(self) -> int:
        if self._byte_pos >= len(self._data):
            raise ValueError("BitReader: out of data")
        bit = (self._data[self._byte_pos] >> (7 - self._bit_pos)) & 1
        self._bit_pos += 1
        if self._bit_pos == 8:
            self._bit_pos = 0
            self._byte_pos += 1
        return bit

    def read_bits_be(self, nbits: int) -> int:
        """Read *nbits* in big-endian (MSB first) order."""
        value = 0
        for _ in range(nbits):
            value = (value << 1) | self.read_bit()
        return value


# ---------------------------------------------------------------------------
# Golomb-Rice coding
# ---------------------------------------------------------------------------

def _golomb_rice_encode(deltas: list[int], p: int) -> bytes:
    w = _BitWriter()
    for d in deltas:
        q = d >> p
        r = d & ((1 << p) - 1)
        # Unary-encode quotient: q ones followed by a zero
        for _ in range(q):
            w.write_bit(1)
        w.write_bit(0)
        # Write remainder in P bits, big-endian
        w.write_bits_be(r, p)
    return w.flush()


def _golomb_rice_decode(data: bytes, n: int, p: int) -> list[int]:
    reader = _BitReader(data)
    deltas: list[int] = []
    for _ in range(n):
        # Read unary quotient
        q = 0
        while reader.read_bit() == 1:
            q += 1
        # Read P-bit remainder
        r = reader.read_bits_be(p)
        deltas.append((q << p) | r)
    return deltas


# ---------------------------------------------------------------------------
# SipHash key derivation
# ---------------------------------------------------------------------------

def _block_filter_siphash_key(block_hash: bytes) -> bytes:
    """First 16 bytes of the block hash in *internal* (little-endian) byte
    order.  Mirrors Bitcoin Core ``blockfilter.cpp`` ``BuildParams`` which
    reads ``m_siphash_k0 = block_hash.GetUint64(0)`` /
    ``m_siphash_k1 = block_hash.GetUint64(1)`` directly off the raw 32-byte
    hash without any reversal — and Core's ``uint256`` is stored in
    internal/LE order.

    ``Block.hash`` (set by ``Block.deserialize`` via ``dSHA256(header)``) is
    already in internal byte order, so we slice the leading 16 bytes
    unmodified.  Callers that hold a *display-order* hash (e.g. RPC input)
    must reverse it before invoking this helper.
    """
    return block_hash[:16]


# ---------------------------------------------------------------------------
# GCS filter construction and matching
# ---------------------------------------------------------------------------

def _hash_to_range(key: bytes, item: bytes, f: int) -> int:
    h = _siphash_2_4(key, item)
    # Fast-range reduction: (h * f) >> 64
    return (h * f) >> 64


def construct_gcs_filter(
    items: list[bytes],
    key: bytes,
    p: int = GCS_P,
    m: int = GCS_M,
) -> bytes:
    """Build a GCS filter from a list of byte-string items (BIP 158)."""
    n = len(items)
    if n == 0:
        return _encode_compact_size(0)

    f = n * m  # Range for hashing

    # Step 1: Hash each item into [0, f)
    hashed = sorted(_hash_to_range(key, item, f) for item in items)

    # Step 2: Compute deltas between consecutive sorted values
    deltas: list[int] = []
    prev = 0
    for val in hashed:
        deltas.append(val - prev)
        prev = val

    # Step 3: Golomb-Rice encode the deltas
    encoded = _golomb_rice_encode(deltas, p)

    # Step 4: Prefix with N (CompactSize)
    return _encode_compact_size(n) + encoded


def gcs_match(
    filter_bytes: bytes,
    key: bytes,
    target: bytes,
    p: int = GCS_P,
    m: int = GCS_M,
) -> bool:
    """Check whether *target* is probably in the GCS filter (may false-positive)."""
    offset = 0
    n, sz = _decode_compact_size(filter_bytes, offset)
    offset += sz

    if n == 0:
        return False

    f = n * m
    target_val = _hash_to_range(key, target, f)

    # Decode deltas and reconstruct sorted values
    encoded_data = filter_bytes[offset:]
    deltas = _golomb_rice_decode(encoded_data, n, p)

    val = 0
    for d in deltas:
        val += d
        if val == target_val:
            return True
        if val > target_val:
            return False
    return False


def gcs_match_any(
    filter_bytes: bytes,
    key: bytes,
    targets: list[bytes],
    p: int = GCS_P,
    m: int = GCS_M,
) -> bool:
    """Check whether any of *targets* matches the GCS filter (sorted intersection)."""
    if not targets:
        return False

    offset = 0
    n, sz = _decode_compact_size(filter_bytes, offset)
    offset += sz

    if n == 0:
        return False

    f = n * m

    # Hash and sort all targets
    target_vals = sorted({_hash_to_range(key, t, f) for t in targets})

    # Decode the filter and walk both sorted lists
    encoded_data = filter_bytes[offset:]
    deltas = _golomb_rice_decode(encoded_data, n, p)

    val = 0
    t_idx = 0
    for d in deltas:
        val += d
        # Advance target pointer past any values below current filter value
        while t_idx < len(target_vals) and target_vals[t_idx] < val:
            t_idx += 1
        if t_idx >= len(target_vals):
            return False
        if target_vals[t_idx] == val:
            return True
    return False


# ---------------------------------------------------------------------------
# Basic block filter (BIP 158 filter type 0)
# ---------------------------------------------------------------------------

def _is_op_return(script: bytes) -> bool:
    return len(script) > 0 and script[0] == OP_RETURN


def collect_block_scripts(
    block: Block,
    db: BlockchainDatabase | None = None,
) -> list[bytes]:
    """
    Collect the scriptPubKeys that go into a basic block filter.

    Per BIP 158 the *basic* filter includes:
    - The scriptPubKey of every output in the block, **except** OP_RETURN
      outputs and empty scripts.
    - The scriptPubKey of every output *spent* by the block's inputs,
      **except** the coinbase input (which has no real prevout).  Requires
      UTXO data (via *db*) to look up the prevout scripts.

    Duplicate scripts are kept (deduplication happens during GCS hashing
    via the ``set`` built into ``build_basic_filter``).
    """
    scripts: list[bytes] = []

    for tx in block.transactions:
        # --- Outputs ---
        for out in tx.outputs:
            spk = out.script_pubkey
            if spk and not _is_op_return(spk):
                scripts.append(bytes(spk))

        # --- Inputs (skip coinbase) ---
        if tx.is_coinbase:
            continue
        for inp in tx.inputs:
            if db is not None:
                utxo = db.get_utxo(inp.prev_txid, inp.prev_vout)
                if utxo is not None:
                    spk = utxo['script_pubkey']
                    if spk and not _is_op_return(spk):
                        scripts.append(bytes(spk))

    return scripts


def build_basic_filter(
    block: Block,
    db: BlockchainDatabase | None = None,
) -> bytes:
    """Build a BIP 158 basic block filter for *block*.

    Pass *db* to also include scripts from spent prevouts.
    """
    scripts = collect_block_scripts(block, db)

    # Deduplicate
    unique_scripts: list[bytes] = list(set(scripts))

    # Derive SipHash key from block hash
    key = _block_filter_siphash_key(block.hash)

    return construct_gcs_filter(unique_scripts, key, GCS_P, GCS_M)


# ---------------------------------------------------------------------------
# Filter header chain
# ---------------------------------------------------------------------------

def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_filter_hash(filter_bytes: bytes) -> bytes:
    """dSHA256 of the filter bytes, used for filter header chaining."""
    return _dsha256(filter_bytes)


def compute_filter_header(
    filter_bytes: bytes,
    prev_header: bytes,
) -> bytes:
    """
    Compute the filter header for chain linking.

    ``filter_header = dSHA256(filter_hash || prev_filter_header)``

    For the genesis block, *prev_header* should be 32 zero bytes.
    """
    fhash = compute_filter_hash(filter_bytes)
    return _dsha256(fhash + prev_header)


# ---------------------------------------------------------------------------
# Block filter index (persistent storage helper)
# ---------------------------------------------------------------------------

class BlockFilterIndex:
    """
    In-memory index mapping block hash / height to basic block filters
    and filter headers.

    In a production node this would be backed by persistent storage; this
    implementation stores everything in dictionaries for simplicity and
    testing.
    """

    def __init__(self) -> None:
        # block_hash (bytes) -> serialized filter bytes
        self._filters: dict[bytes, bytes] = {}
        # block_hash (bytes) -> filter header (32 bytes)
        self._headers: dict[bytes, bytes] = {}
        # height (int) -> block_hash (bytes)
        self._height_to_hash: dict[int, bytes] = {}
        # The most-recently-indexed filter header (for chaining)
        self._tip_header: bytes = b'\x00' * 32

    # -- public API --

    def add(
        self,
        block: Block,
        db: BlockchainDatabase | None = None,
        prev_header: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Build, store, and return ``(filter_bytes, filter_header)`` for *block*."""
        filt = build_basic_filter(block, db)

        if prev_header is None:
            prev_header = self._tip_header

        fheader = compute_filter_header(filt, prev_header)

        block_hash = block.hash
        self._filters[block_hash] = filt
        self._headers[block_hash] = fheader
        if block.height is not None:
            self._height_to_hash[block.height] = block_hash
        self._tip_header = fheader

        return filt, fheader

    def get_filter(self, block_hash: bytes) -> bytes | None:
        """Return the raw filter for *block_hash*, or None."""
        return self._filters.get(block_hash)

    def get_header(self, block_hash: bytes) -> bytes | None:
        """Return the filter header for *block_hash*, or None."""
        return self._headers.get(block_hash)

    def get_by_height(self, height: int) -> tuple[bytes, bytes] | None:
        """Return ``(filter, header)`` for a block at *height*, or None."""
        bh = self._height_to_hash.get(height)
        if bh is None:
            return None
        filt = self._filters.get(bh)
        fhdr = self._headers.get(bh)
        if filt is None or fhdr is None:
            return None
        return filt, fhdr

    @property
    def tip_header(self) -> bytes:
        """The current filter header chain tip."""
        return self._tip_header

    def remove(self, block_hash: bytes) -> bool:
        """
        Remove a filter entry (used during disconnect_block for reorgs).

        Returns True if the entry was found and removed.
        """
        found = block_hash in self._filters
        self._filters.pop(block_hash, None)
        self._headers.pop(block_hash, None)

        # Also remove from height mapping if present
        heights_to_remove = [
            h for h, bh in self._height_to_hash.items() if bh == block_hash
        ]
        for h in heights_to_remove:
            del self._height_to_hash[h]

        return found

    def set_tip_header(self, prev_header: bytes) -> None:
        """Set the tip header (used after reorg to restore previous state)."""
        self._tip_header = prev_header

    # -- BIP 157 helper API --

    def add_block(
        self,
        block: Block,
        height: int | None = None,
        db: BlockchainDatabase | None = None,
    ) -> tuple[bytes, bytes]:
        """Convenience wrapper used by the node block-connect hook.

        Stamps *height* onto the block (so :meth:`add` records the height
        mapping), then delegates to :meth:`add`.  Idempotent — repeat calls
        for the same block hash overwrite the cached entry.
        """
        if height is not None:
            block.height = height
        return self.add(block, db=db)

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        """Return the indexed block hash at *height*, or ``None``."""
        return self._height_to_hash.get(height)


# ---------------------------------------------------------------------------
# Persistent Block Filter Index
# ---------------------------------------------------------------------------

class PersistentBlockFilterIndex:
    """
    Persistent block filter index for BIP 157/158 compact filters.

    Stores BIP 158 basic block filters and their headers durably under
    ``<data_dir>/blockfilter/`` so they survive node restarts (the entire
    point of having an "index").

    Phase 1 storage layout (file-per-block sharded by hash prefix):

    ::

        <data_dir>/blockfilter/
            VERSION                    # text file with schema version
            meta/tip_header            # 32-byte tip filter header
            meta/params.json           # P, M, filter type for sanity check
            filters/<aa>/<hash>.flt    # GCS filter bytes (sharded by hash[:1])
            headers/<aa>/<hash>.hdr    # 32-byte filter header
            height/<8-digit>.h         # 32-byte block_hash

    All writes use the *write-then-rename* idiom (``os.replace`` is atomic
    on POSIX) so a crash mid-write cannot leave a half-written filter on
    disk.  An in-memory LRU cache (default 8192 entries) accelerates the
    hot path used by the BIP-157 P2P handlers; the cache is populated on
    write and on miss.

    A single ``threading.Lock`` serialises ``add`` / ``remove`` /
    ``set_tip_header`` so concurrent ``asyncio.to_thread`` calls cannot
    interleave the read-modify-write of the tip header — which would
    otherwise break the chain `H_n = dSHA256(filter_hash_n || H_{n-1})`.

    Phase 2 will migrate the on-disk format to a dedicated RocksDB CF
    (``BlockFilters``) in the ferrous-utils crate; the public API of this
    class is intentionally kept narrow so the swap is internal.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        data_dir: str,
        enabled: bool = True,
        cache_capacity: int = 8192,
    ) -> None:
        """
        Initialize the persistent block filter index.

        Args:
            data_dir: Node data directory (the index lives under
                ``<data_dir>/blockfilter``).
            enabled: When False, fall back to a transient in-memory index;
                this is what the constructor in node.py uses to model the
                "off" state without forcing every caller to None-check.
            cache_capacity: Maximum number of cached
                ``(filter, header)`` pairs kept in RAM.  0 disables the
                cache (read-through every call).
        """
        self._enabled = enabled
        self._data_dir = data_dir
        self._lock = threading.Lock()
        self._cache_capacity = max(0, int(cache_capacity))
        self._filter_cache: OrderedDict[bytes, bytes] = OrderedDict()
        self._header_cache: OrderedDict[bytes, bytes] = OrderedDict()
        self._height_cache: OrderedDict[int, bytes] = OrderedDict()

        if not enabled:
            # Use in-memory fallback when disabled
            self._memory_index = BlockFilterIndex()
            self._db = None
            return

        try:
            filter_db_path = os.path.join(data_dir, "blockfilter")
            os.makedirs(filter_db_path, exist_ok=True)

            self._root_path = filter_db_path
            self._filters_path = os.path.join(filter_db_path, "filters")
            self._headers_path = os.path.join(filter_db_path, "headers")
            self._height_path = os.path.join(filter_db_path, "height")
            self._meta_path = os.path.join(filter_db_path, "meta")
            os.makedirs(self._filters_path, exist_ok=True)
            os.makedirs(self._headers_path, exist_ok=True)
            os.makedirs(self._height_path, exist_ok=True)
            os.makedirs(self._meta_path, exist_ok=True)

            # Write schema VERSION + parameter sanity-check file once; if
            # they already exist with a different version we keep them
            # untouched (a future migration would handle the transition).
            self._init_schema_metadata()

            self._db = True
            self._memory_index = None
        except ImportError:
            # Fall back to in-memory when filesystem init fails for any
            # reason (e.g. read-only datadir in some CI sandboxes).
            self._memory_index = BlockFilterIndex()
            self._db = None

    def _init_schema_metadata(self) -> None:
        """Stamp the schema version + filter parameters under meta/.

        This is a one-shot hint for tooling (and for Phase 2 migration);
        the on-disk parameters are not consulted on every read so a
        mismatch is logged-only at open time.
        """
        version_path = os.path.join(self._root_path, "VERSION")
        if not os.path.exists(version_path):
            try:
                with open(version_path, 'w', encoding='utf-8') as f:
                    f.write(f"{self.SCHEMA_VERSION}\n")
            except OSError:
                pass

        params_path = os.path.join(self._meta_path, "params.json")
        if not os.path.exists(params_path):
            try:
                with open(params_path, 'w', encoding='utf-8') as f:
                    json.dump(
                        {
                            "filter_type": BASIC_FILTER_TYPE,
                            "P": GCS_P,
                            "M": GCS_M,
                            "schema_version": self.SCHEMA_VERSION,
                        },
                        f,
                    )
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Internal helpers — atomic IO + cache management
    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        """Write *data* to *path* atomically (write-then-rename)."""
        tmp_path = path + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # Some test filesystems (tmpfs in CI) don't support fsync;
                # the rename below still gives us atomic visibility.
                pass
        os.replace(tmp_path, path)

    def _shard_dir(self, base: str, block_hash: bytes) -> str:
        """Return base/<aa>/ where aa is the first byte of the hash hex.

        Sharding keeps directory entry counts manageable (≤ 256 entries
        in the top level, ~3500 entries per shard at the mainnet tip
        of ~900k blocks).  Plain flat dirs blow up readdir() at >100k
        entries on ext4.
        """
        prefix = block_hash[:1].hex()  # 'aa' style
        path = os.path.join(base, prefix)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass
        return path

    def _filter_path(self, block_hash: bytes) -> str:
        return os.path.join(
            self._shard_dir(self._filters_path, block_hash),
            block_hash.hex() + ".flt",
        )

    def _header_path(self, block_hash: bytes) -> str:
        return os.path.join(
            self._shard_dir(self._headers_path, block_hash),
            block_hash.hex() + ".hdr",
        )

    def _legacy_filter_path(self, block_hash: bytes) -> str:
        # Pre-shard layout used in the very first persistent build.  Read
        # path falls back here so existing datadirs don't have to be
        # migrated to see their stored filters.
        return os.path.join(self._filters_path, block_hash.hex())

    def _legacy_header_path(self, block_hash: bytes) -> str:
        return os.path.join(self._headers_path, block_hash.hex())

    def _cache_put(
        self,
        which: OrderedDict,
        key,
        value,
    ) -> None:
        if self._cache_capacity == 0:
            return
        which[key] = value
        which.move_to_end(key)
        while len(which) > self._cache_capacity:
            which.popitem(last=False)

    def _cache_get(self, which: OrderedDict, key):
        if self._cache_capacity == 0:
            return None
        if key in which:
            which.move_to_end(key)
            return which[key]
        return None

    @property
    def is_enabled(self) -> bool:
        """Check if the index is enabled."""
        return self._enabled

    def _height_to_filename(self, height: int) -> str:
        """Convert height to a fixed-width filename for natural sorting."""
        return f"{height:08d}.h"

    def _height_path_for(self, height: int) -> str:
        return os.path.join(self._height_path, self._height_to_filename(height))

    # ------------------------------------------------------------------
    # add / get / remove
    # ------------------------------------------------------------------

    def add(
        self,
        block: Block,
        db: BlockchainDatabase | None = None,
        prev_header: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Build, store, and return ``(filter_bytes, filter_header)`` for *block*.

        Idempotent: re-adding the same ``block_hash`` overwrites the
        existing entry.  Atomic-on-disk: each file is written via
        write-then-rename so a crash in the middle of a connect cannot
        leave a corrupt filter.  Thread-safe: a single lock serialises
        the read-modify-write of the tip header.
        """
        if self._memory_index is not None:
            return self._memory_index.add(block, db, prev_header)

        # Filter construction is pure / read-only; do it outside the lock
        # so concurrent connect threads can build their filters in
        # parallel.  Persistence + tip-header update happens under the
        # lock to keep the chain monotonic.
        filt = build_basic_filter(block, db)
        block_hash = block.hash

        with self._lock:
            if prev_header is None:
                # If we've already indexed this block (idempotent retry),
                # reuse its existing previous-header so the chain doesn't
                # double-tick when connect_block is called twice.
                existing_header = self._read_header(block_hash)
                if existing_header is not None:
                    # Recompute prev_header by inverting the chain rule
                    # is impossible (dSHA256 is one-way) — instead we just
                    # short-circuit: this block was already indexed, return
                    # the cached values without retouching the tip header.
                    cached_filter = self._read_filter(block_hash)
                    if cached_filter is not None:
                        self._cache_put(self._filter_cache, block_hash, cached_filter)
                        self._cache_put(self._header_cache, block_hash, existing_header)
                        return cached_filter, existing_header
                prev_header = self._get_tip_header()

            fheader = compute_filter_header(filt, prev_header)

            self._atomic_write(self._filter_path(block_hash), filt)
            self._atomic_write(self._header_path(block_hash), fheader)

            if block.height is not None:
                self._atomic_write(self._height_path_for(block.height), block_hash)
                self._cache_put(self._height_cache, block.height, block_hash)

            self._set_tip_header(fheader)

            self._cache_put(self._filter_cache, block_hash, filt)
            self._cache_put(self._header_cache, block_hash, fheader)

        return filt, fheader

    def _get_tip_header(self) -> bytes:
        """Get the current tip filter header (must be called under lock)."""
        tip_path = os.path.join(self._meta_path, "tip_header")
        try:
            with open(tip_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return b'\x00' * 32

    def _set_tip_header(self, header: bytes) -> None:
        """Set the tip filter header (must be called under lock)."""
        tip_path = os.path.join(self._meta_path, "tip_header")
        self._atomic_write(tip_path, header)

    # -- lockless raw readers (used internally from add / public getters) --

    def _read_filter(self, block_hash: bytes) -> bytes | None:
        path = self._filter_path(block_hash)
        try:
            with open(path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            pass
        # Backward-compat with the very first flat layout
        try:
            with open(self._legacy_filter_path(block_hash), 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _read_header(self, block_hash: bytes) -> bytes | None:
        path = self._header_path(block_hash)
        try:
            with open(path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            pass
        try:
            with open(self._legacy_header_path(block_hash), 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def get_filter(self, block_hash: bytes) -> bytes | None:
        """Return the raw filter for *block_hash*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_filter(block_hash)
        cached = self._cache_get(self._filter_cache, block_hash)
        if cached is not None:
            return cached
        data = self._read_filter(block_hash)
        if data is not None:
            self._cache_put(self._filter_cache, block_hash, data)
        return data

    def get_header(self, block_hash: bytes) -> bytes | None:
        """Return the filter header for *block_hash*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_header(block_hash)
        cached = self._cache_get(self._header_cache, block_hash)
        if cached is not None:
            return cached
        data = self._read_header(block_hash)
        if data is not None:
            self._cache_put(self._header_cache, block_hash, data)
        return data

    def get_by_height(self, height: int) -> tuple[bytes, bytes] | None:
        """Return ``(filter, header)`` for a block at *height*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_by_height(height)

        block_hash = self._cache_get(self._height_cache, height)
        if block_hash is None:
            block_hash = self.get_block_hash_by_height(height)
            if block_hash is None:
                return None
            self._cache_put(self._height_cache, height, block_hash)

        filt = self.get_filter(block_hash)
        fhdr = self.get_header(block_hash)
        if filt is None or fhdr is None:
            return None
        return filt, fhdr

    @property
    def tip_header(self) -> bytes:
        """The current filter header chain tip."""
        if self._memory_index is not None:
            return self._memory_index.tip_header
        with self._lock:
            return self._get_tip_header()

    def remove(self, block_hash: bytes, height: int | None = None) -> bool:
        """Remove a filter entry (used during disconnect_block for reorgs).

        Returns True if the entry was found and removed.  Phase 1 does
        *not* attempt to roll back the tip filter header — callers that
        need reorg-aware tip rollback should use :meth:`set_tip_header`
        explicitly with the previous header.  Phase 2 will record undo
        deltas alongside the undo CF for true atomic disconnect.
        """
        if self._memory_index is not None:
            return self._memory_index.remove(block_hash)

        with self._lock:
            found = False
            for path in (
                self._filter_path(block_hash),
                self._legacy_filter_path(block_hash),
                self._header_path(block_hash),
                self._legacy_header_path(block_hash),
            ):
                try:
                    os.remove(path)
                    found = True
                except FileNotFoundError:
                    pass

            if height is not None:
                try:
                    os.remove(self._height_path_for(height))
                except FileNotFoundError:
                    pass
                self._height_cache.pop(height, None)

            self._filter_cache.pop(block_hash, None)
            self._header_cache.pop(block_hash, None)

            return found

    def set_tip_header(self, prev_header: bytes) -> None:
        """Set the tip header (used after reorg to restore previous state)."""
        if self._memory_index is not None:
            self._memory_index.set_tip_header(prev_header)
            return
        with self._lock:
            self._set_tip_header(prev_header)

    # -- BIP 157 helper API --

    def add_block(
        self,
        block: Block,
        height: int | None = None,
        db: BlockchainDatabase | None = None,
    ) -> tuple[bytes, bytes]:
        """Convenience wrapper used by the node block-connect hook.

        Stamps *height* onto the block (so :meth:`add` records the height
        mapping), then delegates to :meth:`add`.  When the persistent path
        is in use this also writes the height -> hash mapping to disk.

        Idempotent — repeat calls for the same block hash overwrite the
        cached entry; the prev_header is taken from the on-disk tip header
        so re-application after restart still chains correctly when called
        in canonical order.
        """
        if height is not None:
            block.height = height
        return self.add(block, db=db)

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        """Return the indexed block hash at *height*, or ``None``."""
        if self._memory_index is not None:
            return self._memory_index.get_block_hash_by_height(height)
        cached = self._cache_get(self._height_cache, height)
        if cached is not None:
            return cached
        try:
            with open(self._height_path_for(height), 'rb') as f:
                data = f.read()
                self._cache_put(self._height_cache, height, data)
                return data
        except FileNotFoundError:
            # Older datadirs used `.../<8-digit>` (no extension) — fall
            # back so we don't lose existing index data after this
            # filename-suffix change.
            legacy = os.path.join(self._height_path, f"{height:08d}")
            try:
                with open(legacy, 'rb') as f:
                    return f.read()
            except FileNotFoundError:
                return None

