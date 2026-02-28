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
    Bitcoin Core: src/blockfilter.cpp
"""

from __future__ import annotations

import hashlib
import io
import struct
from typing import List, Optional, Set, TYPE_CHECKING

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
    """Encode an integer as a Bitcoin CompactSize (varint)."""
    if n < 0xFD:
        return struct.pack('<B', n)
    elif n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def _decode_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a CompactSize varint, returning (value, bytes_consumed)."""
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

def _golomb_rice_encode(deltas: List[int], p: int) -> bytes:
    """
    Golomb-Rice encode a list of non-negative integer deltas.

    For each delta *d*:
        q = d >> p            (quotient)
        r = d & ((1 << p) - 1)  (remainder)
        Write q ones followed by a zero (unary), then r in P bits.
    """
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


def _golomb_rice_decode(data: bytes, n: int, p: int) -> List[int]:
    """
    Decode *n* Golomb-Rice coded deltas from *data*.

    Returns list of decoded delta values.
    """
    reader = _BitReader(data)
    deltas: List[int] = []
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
    """
    Derive the 16-byte SipHash key for block filter construction.

    Per BIP 158 the key is the first 16 bytes of the block hash in
    *internal* byte order (little-endian / wire order).  In this codebase
    ``Block.hash`` is stored in display (big-endian) order, so we reverse.
    """
    # block_hash is in display order (big-endian), reverse to LE
    return block_hash[::-1][:16]


# ---------------------------------------------------------------------------
# GCS filter construction and matching
# ---------------------------------------------------------------------------

def _hash_to_range(key: bytes, item: bytes, f: int) -> int:
    """
    Map *item* to the range ``[0, f)`` using SipHash-2-4.

    ``f`` is typically ``N * M`` where N = number of items.

    Per BIP 158 the mapping is:
        ``(SipHash(key, item) * f) >> 64``
    which produces a uniform value in [0, f).
    """
    h = _siphash_2_4(key, item)
    # Fast-range reduction: (h * f) >> 64
    return (h * f) >> 64


def construct_gcs_filter(
    items: List[bytes],
    key: bytes,
    p: int = GCS_P,
    m: int = GCS_M,
) -> bytes:
    """
    Build a GCS (Golomb-coded set) filter from a set of byte-string items.

    Args:
        items: List of byte strings (scriptPubKeys) to include in the filter.
        key: 16-byte SipHash key.
        p: Golomb-Rice coding parameter (default: 19 per BIP 158).
        m: False-positive rate parameter (default: 784931 per BIP 158).

    Returns:
        Serialized filter bytes: ``CompactSize(N) || GCS-encoded data``.
    """
    n = len(items)
    if n == 0:
        return _encode_compact_size(0)

    f = n * m  # Range for hashing

    # Step 1: Hash each item into [0, f)
    hashed = sorted(_hash_to_range(key, item, f) for item in items)

    # Step 2: Compute deltas between consecutive sorted values
    deltas: List[int] = []
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
    """
    Check whether *target* is (probably) in the GCS filter.

    Returns True if the target matches (with possible false positive),
    False if definitely not in the set.
    """
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
    targets: List[bytes],
    p: int = GCS_P,
    m: int = GCS_M,
) -> bool:
    """
    Check whether *any* of the *targets* match the GCS filter.

    Uses a sorted intersection approach for efficiency.
    """
    if not targets:
        return False

    offset = 0
    n, sz = _decode_compact_size(filter_bytes, offset)
    offset += sz

    if n == 0:
        return False

    f = n * m

    # Hash and sort all targets
    target_vals = sorted(set(_hash_to_range(key, t, f) for t in targets))

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
    """Return True if the script starts with OP_RETURN."""
    return len(script) > 0 and script[0] == OP_RETURN


def collect_block_scripts(
    block: "Block",
    db: Optional["BlockchainDatabase"] = None,
) -> List[bytes]:
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
    scripts: List[bytes] = []

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
    block: "Block",
    db: Optional["BlockchainDatabase"] = None,
) -> bytes:
    """
    Build a BIP 158 basic block filter for *block*.

    Args:
        block: A fully-parsed Block (with transactions).
        db: Optional blockchain database for looking up spent prevout
            scriptPubKeys.  If None, only output scripts are included.

    Returns:
        The serialized GCS filter bytes (CompactSize(N) || encoded data).
    """
    scripts = collect_block_scripts(block, db)

    # Deduplicate
    unique_scripts: List[bytes] = list(set(scripts))

    # Derive SipHash key from block hash
    key = _block_filter_siphash_key(block.hash)

    return construct_gcs_filter(unique_scripts, key, GCS_P, GCS_M)


# ---------------------------------------------------------------------------
# Filter header chain
# ---------------------------------------------------------------------------

def _dsha256(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_filter_hash(filter_bytes: bytes) -> bytes:
    """Hash a filter for header chain computation: dSHA256(filter_bytes)."""
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
        block: "Block",
        db: Optional["BlockchainDatabase"] = None,
        prev_header: Optional[bytes] = None,
    ) -> tuple[bytes, bytes]:
        """
        Build, store, and return the filter and filter header for *block*.

        Args:
            block: Block to index.
            db: Optional database for prevout lookups.
            prev_header: Previous filter header; if None, uses the
                internally tracked tip header.

        Returns:
            ``(filter_bytes, filter_header)``
        """
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

    def get_filter(self, block_hash: bytes) -> Optional[bytes]:
        """Return the raw filter for *block_hash*, or None."""
        return self._filters.get(block_hash)

    def get_header(self, block_hash: bytes) -> Optional[bytes]:
        """Return the filter header for *block_hash*, or None."""
        return self._headers.get(block_hash)

    def get_by_height(self, height: int) -> Optional[tuple[bytes, bytes]]:
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
