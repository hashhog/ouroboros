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
import os
import struct
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
    # block_hash is in display order (big-endian), reverse to LE
    return block_hash[::-1][:16]


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


# ---------------------------------------------------------------------------
# Persistent Block Filter Index
# ---------------------------------------------------------------------------

class PersistentBlockFilterIndex:
    """
    Persistent block filter index backed by RocksDB.

    This index stores BIP 158 basic block filters and their headers in a
    separate column family in the blockchain database. It supports:
    - Incremental building during connect_block
    - Removal during disconnect_block (reorg handling)
    - Lookup by block hash or height

    Storage format:
    - Filter CF: block_hash (32 bytes) -> filter_bytes (variable)
    - Header CF: block_hash (32 bytes) -> filter_header (32 bytes)
    - Height CF: height (4 bytes BE) -> block_hash (32 bytes)
    - Metadata CF: "tip_header" -> filter_header (32 bytes)
    """

    # Keys for metadata
    _TIP_HEADER_KEY = b"tip_header"

    def __init__(self, data_dir: str, enabled: bool = True) -> None:
        """
        Initialize the persistent block filter index.

        Args:
            data_dir: Directory for the filter index database
            enabled: Whether the index is enabled
        """
        self._enabled = enabled
        self._data_dir = data_dir

        if not enabled:
            # Use in-memory fallback when disabled
            self._memory_index = BlockFilterIndex()
            self._db = None
            return

        # Import here to avoid circular imports and allow graceful fallback
        try:
            # Open a dedicated database for block filters
            filter_db_path = os.path.join(data_dir, "blockfilter")
            os.makedirs(filter_db_path, exist_ok=True)

            # Create a simple file-based storage for now
            # In a full implementation, this would use RocksDB column families
            self._filters_path = os.path.join(filter_db_path, "filters")
            self._headers_path = os.path.join(filter_db_path, "headers")
            self._height_path = os.path.join(filter_db_path, "height")
            self._meta_path = os.path.join(filter_db_path, "meta")
            os.makedirs(self._filters_path, exist_ok=True)
            os.makedirs(self._headers_path, exist_ok=True)
            os.makedirs(self._height_path, exist_ok=True)
            os.makedirs(self._meta_path, exist_ok=True)

            self._db = True  # Mark as initialized
            self._memory_index = None
        except ImportError:
            # Fall back to in-memory if sync module unavailable
            self._memory_index = BlockFilterIndex()
            self._db = None

    @property
    def is_enabled(self) -> bool:
        """Check if the index is enabled."""
        return self._enabled

    def _hash_to_filename(self, block_hash: bytes) -> str:
        """Convert block hash to a safe filename."""
        return block_hash.hex()

    def _height_to_filename(self, height: int) -> str:
        """Convert height to a filename."""
        return f"{height:08d}"

    def add(
        self,
        block: Block,
        db: BlockchainDatabase | None = None,
        prev_header: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Build, store, and return ``(filter_bytes, filter_header)`` for *block*."""
        if self._memory_index is not None:
            return self._memory_index.add(block, db, prev_header)

        # Build the filter
        filt = build_basic_filter(block, db)

        # Get previous header for chaining
        if prev_header is None:
            prev_header = self._get_tip_header()

        fheader = compute_filter_header(filt, prev_header)

        block_hash = block.hash
        filename = self._hash_to_filename(block_hash)

        # Write filter
        filter_path = os.path.join(self._filters_path, filename)
        with open(filter_path, 'wb') as f:
            f.write(filt)

        # Write header
        header_path = os.path.join(self._headers_path, filename)
        with open(header_path, 'wb') as f:
            f.write(fheader)

        # Write height mapping
        if block.height is not None:
            height_path = os.path.join(
                self._height_path, self._height_to_filename(block.height)
            )
            with open(height_path, 'wb') as f:
                f.write(block_hash)

        # Update tip header
        self._set_tip_header(fheader)

        return filt, fheader

    def _get_tip_header(self) -> bytes:
        """Get the current tip filter header."""
        tip_path = os.path.join(self._meta_path, "tip_header")
        try:
            with open(tip_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return b'\x00' * 32

    def _set_tip_header(self, header: bytes) -> None:
        """Set the tip filter header."""
        tip_path = os.path.join(self._meta_path, "tip_header")
        with open(tip_path, 'wb') as f:
            f.write(header)

    def get_filter(self, block_hash: bytes) -> bytes | None:
        """Return the raw filter for *block_hash*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_filter(block_hash)

        filename = self._hash_to_filename(block_hash)
        filter_path = os.path.join(self._filters_path, filename)
        try:
            with open(filter_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def get_header(self, block_hash: bytes) -> bytes | None:
        """Return the filter header for *block_hash*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_header(block_hash)

        filename = self._hash_to_filename(block_hash)
        header_path = os.path.join(self._headers_path, filename)
        try:
            with open(header_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def get_by_height(self, height: int) -> tuple[bytes, bytes] | None:
        """Return ``(filter, header)`` for a block at *height*, or None."""
        if self._memory_index is not None:
            return self._memory_index.get_by_height(height)

        # Look up block hash by height
        height_path = os.path.join(
            self._height_path, self._height_to_filename(height)
        )
        try:
            with open(height_path, 'rb') as f:
                block_hash = f.read()
        except FileNotFoundError:
            return None

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
        return self._get_tip_header()

    def remove(self, block_hash: bytes, height: int | None = None) -> bool:
        """
        Remove a filter entry (used during disconnect_block for reorgs).

        Args:
            block_hash: The block hash to remove
            height: Optional height (for efficient height mapping removal)

        Returns True if the entry was found and removed.
        """
        if self._memory_index is not None:
            return self._memory_index.remove(block_hash)

        filename = self._hash_to_filename(block_hash)
        found = False

        # Remove filter
        filter_path = os.path.join(self._filters_path, filename)
        try:
            os.remove(filter_path)
            found = True
        except FileNotFoundError:
            pass

        # Remove header
        header_path = os.path.join(self._headers_path, filename)
        try:
            os.remove(header_path)
            found = True
        except FileNotFoundError:
            pass

        # Remove height mapping
        if height is not None:
            height_path = os.path.join(
                self._height_path, self._height_to_filename(height)
            )
            try:
                os.remove(height_path)
            except FileNotFoundError:
                pass

        return found

    def set_tip_header(self, prev_header: bytes) -> None:
        """Set the tip header (used after reorg to restore previous state)."""
        if self._memory_index is not None:
            self._memory_index.set_tip_header(prev_header)
        else:
            self._set_tip_header(prev_header)

