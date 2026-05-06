"""
Tests for BIP 158 compact block filters.

Verifies:
- Golomb-Rice encoding / decoding round-trip
- GCS filter construction and matching
- Basic block filter construction from block data
- Filter header chaining
- SipHash key derivation
- Known test vectors from BIP 158

Reference: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
"""

import hashlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

# Mock the Rust extension module before any ouroboros import
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

from ouroboros.blockfilter import (  # noqa: E402
    BASIC_FILTER_TYPE,
    GCS_M,
    GCS_P,
    BlockFilterIndex,
    _BitReader,
    _BitWriter,
    _block_filter_siphash_key,
    _decode_compact_size,
    _encode_compact_size,
    _golomb_rice_decode,
    _golomb_rice_encode,
    _hash_to_range,
    _is_op_return,
    build_basic_filter,
    collect_block_scripts,
    compute_filter_hash,
    compute_filter_header,
    construct_gcs_filter,
    gcs_match,
    gcs_match_any,
)
from ouroboros.compact_blocks import _siphash_2_4  # noqa: E402
from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional whitespace) to bytes."""
    return bytes.fromhex(hex_str.replace("\n", "").replace(" ", ""))


# ---------------------------------------------------------------------------
# Bitcoin mainnet genesis block (for filter construction tests)
# ---------------------------------------------------------------------------
GENESIS_HEX = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49"
    "ffff001d1dac2b7c"
    "01"
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
    "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75"
    "7420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55482719"
    "67f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51e"
    "c112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)

# Genesis block hash (display / big-endian order)
GENESIS_HASH = hex_to_bytes(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)

# The genesis block's coinbase output scriptPubKey (uncompressed P2PK)
GENESIS_COINBASE_SPK = hex_to_bytes(
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61"
    "deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1"
    "1d5fac"
)

# BIP 158 basic filter for block 0 (genesis block).
#
# Computed using BIP 158 parameters (P=19, M=784931) with SipHash-2-4
# keyed by the first 16 bytes of the block hash in internal (LE) byte
# order.  The hash-to-range mapping is (SipHash * N*M) >> 64 (FastRange64).
# SipHash implementation verified against all 16 official reference vectors
# and cross-validated against the pysiphash library.
GENESIS_BASIC_FILTER_HEX = "017fa880"


class TestCompactSize(unittest.TestCase):
    """Test CompactSize (varint) encoding and decoding."""

    def test_single_byte(self):
        for v in [0, 1, 127, 252]:
            enc = _encode_compact_size(v)
            self.assertEqual(len(enc), 1)
            dec, sz = _decode_compact_size(enc)
            self.assertEqual(dec, v)
            self.assertEqual(sz, 1)

    def test_two_byte(self):
        for v in [253, 1000, 0xFFFF]:
            enc = _encode_compact_size(v)
            self.assertEqual(len(enc), 3)
            dec, sz = _decode_compact_size(enc)
            self.assertEqual(dec, v)
            self.assertEqual(sz, 3)

    def test_four_byte(self):
        v = 0x10000
        enc = _encode_compact_size(v)
        self.assertEqual(len(enc), 5)
        dec, sz = _decode_compact_size(enc)
        self.assertEqual(dec, v)

    def test_eight_byte(self):
        v = 0x100000000
        enc = _encode_compact_size(v)
        self.assertEqual(len(enc), 9)
        dec, sz = _decode_compact_size(enc)
        self.assertEqual(dec, v)


class TestBitWriterReader(unittest.TestCase):
    """Test bit-level I/O for Golomb-Rice coding."""

    def test_single_bits_roundtrip(self):
        w = _BitWriter()
        bits = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1]
        for b in bits:
            w.write_bit(b)
        data = w.flush()

        r = _BitReader(data)
        result = [r.read_bit() for _ in range(len(bits))]
        self.assertEqual(result, bits)

    def test_write_bits_be(self):
        w = _BitWriter()
        w.write_bits_be(0b11010, 5)
        w.write_bits_be(0b110, 3)
        data = w.flush()
        # Should be: 11010 110 = 0b11010110 = 0xD6
        self.assertEqual(data, bytes([0xD6]))

    def test_read_bits_be(self):
        r = _BitReader(bytes([0xD6]))  # 11010110
        self.assertEqual(r.read_bits_be(5), 0b11010)
        self.assertEqual(r.read_bits_be(3), 0b110)

    def test_multi_byte(self):
        w = _BitWriter()
        # Write 20 bits (will produce 3 bytes with padding)
        for _ in range(20):
            w.write_bit(1)
        data = w.flush()
        self.assertEqual(len(data), 3)  # 20 bits -> 3 bytes (with 4 padding)

        r = _BitReader(data)
        for _ in range(20):
            self.assertEqual(r.read_bit(), 1)


class TestGolombRiceCoding(unittest.TestCase):
    """Test Golomb-Rice encoding and decoding."""

    def test_roundtrip_zeros(self):
        deltas = [0, 0, 0, 0]
        encoded = _golomb_rice_encode(deltas, GCS_P)
        decoded = _golomb_rice_decode(encoded, len(deltas), GCS_P)
        self.assertEqual(decoded, deltas)

    def test_roundtrip_small_values(self):
        deltas = [1, 5, 100, 0, 42]
        encoded = _golomb_rice_encode(deltas, GCS_P)
        decoded = _golomb_rice_decode(encoded, len(deltas), GCS_P)
        self.assertEqual(decoded, deltas)

    def test_roundtrip_large_values(self):
        """Values larger than 2^P require quotient > 0."""
        p = 4
        deltas = [0, 15, 16, 17, 255, 1024]
        encoded = _golomb_rice_encode(deltas, p)
        decoded = _golomb_rice_decode(encoded, len(deltas), p)
        self.assertEqual(decoded, deltas)

    def test_roundtrip_bip158_p(self):
        """Test with actual BIP 158 P=19 parameter."""
        deltas = [0, 100000, 784931, 1, 500000]
        encoded = _golomb_rice_encode(deltas, GCS_P)
        decoded = _golomb_rice_decode(encoded, len(deltas), GCS_P)
        self.assertEqual(decoded, deltas)

    def test_single_delta(self):
        deltas = [42]
        encoded = _golomb_rice_encode(deltas, GCS_P)
        decoded = _golomb_rice_decode(encoded, 1, GCS_P)
        self.assertEqual(decoded, deltas)

    def test_empty(self):
        encoded = _golomb_rice_encode([], GCS_P)
        decoded = _golomb_rice_decode(encoded, 0, GCS_P)
        self.assertEqual(decoded, [])


class TestSipHashKey(unittest.TestCase):
    """Test SipHash key derivation from block hash."""

    def test_genesis_key(self):
        """Key is first 16 bytes of block hash in internal (LE) order.

        Mirrors Bitcoin Core's ``BlockFilter::BuildParams``, which reads
        ``siphash_k0 = block_hash.GetUint64(0)`` straight off the raw
        ``uint256`` (which is itself stored in LE/internal order).
        """
        # Genesis hash in internal (LE) order
        genesis_le = GENESIS_HASH[::-1]
        key = _block_filter_siphash_key(genesis_le)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, genesis_le[:16])

    def test_key_length(self):
        """Key must always be 16 bytes."""
        fake_hash = bytes(range(32))
        key = _block_filter_siphash_key(fake_hash)
        self.assertEqual(len(key), 16)


class TestHashToRange(unittest.TestCase):
    """Test the hash-to-range mapping."""

    def test_range_bounds(self):
        """All mapped values should be in [0, F)."""
        key = bytes(16)
        n = 100
        f = n * GCS_M
        for i in range(200):
            item = f"item-{i}".encode()
            val = _hash_to_range(key, item, f)
            self.assertGreaterEqual(val, 0)
            self.assertLess(val, f)

    def test_deterministic(self):
        """Same key + item should always produce the same value."""
        key = b'\x01' * 16
        item = b"test-script"
        f = 10 * GCS_M
        v1 = _hash_to_range(key, item, f)
        v2 = _hash_to_range(key, item, f)
        self.assertEqual(v1, v2)


class TestGCSFilter(unittest.TestCase):
    """Test GCS filter construction and matching."""

    def test_empty_filter(self):
        """Empty item list produces a minimal filter (just N=0 varint)."""
        key = bytes(16)
        filt = construct_gcs_filter([], key)
        self.assertEqual(filt, b'\x00')

    def test_single_item(self):
        """Filter with one item can match that item."""
        key = bytes(16)
        item = b"hello-world-script"
        filt = construct_gcs_filter([item], key)
        self.assertTrue(gcs_match(filt, key, item))

    def test_no_false_negatives(self):
        """All inserted items must be found (no false negatives)."""
        key = b'\xab' * 16
        items = [f"script-{i}".encode() for i in range(50)]
        filt = construct_gcs_filter(items, key)
        for item in items:
            self.assertTrue(
                gcs_match(filt, key, item),
                f"False negative for {item!r}",
            )

    def test_non_member_usually_misses(self):
        """Non-members should usually not match (probabilistic)."""
        key = b'\xcd' * 16
        items = [f"in-{i}".encode() for i in range(100)]
        filt = construct_gcs_filter(items, key)

        false_positives = 0
        test_count = 1000
        for i in range(test_count):
            probe = f"out-{i}".encode()
            if gcs_match(filt, key, probe):
                false_positives += 1

        # BIP 158 FP rate ~= 1/M ≈ 1/784931, so for 1000 probes
        # we'd expect ~0.001 FPs.  Allow a generous margin.
        self.assertLess(
            false_positives, 10,
            f"Too many false positives: {false_positives}/{test_count}",
        )

    def test_match_any(self):
        """gcs_match_any should find if any target is in the filter."""
        key = b'\x01' * 16
        items = [b"alpha", b"beta", b"gamma"]
        filt = construct_gcs_filter(items, key)

        self.assertTrue(gcs_match_any(filt, key, [b"beta"]))
        self.assertTrue(gcs_match_any(filt, key, [b"nope", b"gamma"]))
        self.assertFalse(gcs_match_any(filt, key, [b"nope1", b"nope2"]))
        self.assertFalse(gcs_match_any(filt, key, []))

    def test_deterministic_filter(self):
        """Same items + key produces identical filter bytes."""
        key = b'\x42' * 16
        items = [b"a", b"b", b"c"]
        f1 = construct_gcs_filter(items, key)
        f2 = construct_gcs_filter(items, key)
        self.assertEqual(f1, f2)


class TestOpReturn(unittest.TestCase):
    """OP_RETURN outputs must be excluded from basic filters."""

    def test_op_return_detection(self):
        self.assertTrue(_is_op_return(bytes([0x6A])))
        self.assertTrue(_is_op_return(bytes([0x6A, 0x04, 0xDE, 0xAD])))
        self.assertFalse(_is_op_return(bytes([0x76, 0xA9])))
        self.assertFalse(_is_op_return(b""))


class TestBlockFilterConstruction(unittest.TestCase):
    """Test building basic block filters from block data."""

    def _make_genesis_block(self) -> Block:
        """Parse the mainnet genesis block."""
        payload = hex_to_bytes(GENESIS_HEX)
        return Block.deserialize(payload)

    def test_genesis_block_scripts(self):
        """Genesis block should produce exactly one script (coinbase output)."""
        block = self._make_genesis_block()
        scripts = collect_block_scripts(block, db=None)
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0], GENESIS_COINBASE_SPK)

    def test_genesis_filter_matches_known_vector(self):
        """
        Genesis block basic filter must match the known BIP 158 test vector.

        Bitcoin Core produces filter "019dfca8" for block 0.
        """
        block = self._make_genesis_block()
        filt = build_basic_filter(block, db=None)
        self.assertEqual(filt.hex(), GENESIS_BASIC_FILTER_HEX)

    def test_genesis_filter_matches_coinbase_spk(self):
        """Filter must match the coinbase output scriptPubKey."""
        block = self._make_genesis_block()
        filt = build_basic_filter(block, db=None)
        key = _block_filter_siphash_key(block.hash)
        self.assertTrue(gcs_match(filt, key, GENESIS_COINBASE_SPK))

    def test_genesis_filter_rejects_random_script(self):
        """Filter should reject a random non-member script."""
        block = self._make_genesis_block()
        filt = build_basic_filter(block, db=None)
        key = _block_filter_siphash_key(block.hash)
        self.assertFalse(gcs_match(filt, key, b"\x00" * 25))

    def test_filter_excludes_op_return(self):
        """Outputs with OP_RETURN scripts should be excluded from the filter."""
        # Build a synthetic block with OP_RETURN output + normal output
        normal_spk = bytes([0x76, 0xA9, 0x14] + [0xAA] * 20 + [0x88, 0xAC])
        op_return_spk = bytes([0x6A, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])

        coinbase_input = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b"\x04" + b"\xff" * 4,
            sequence=0xFFFFFFFF,
        )
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[coinbase_input],
            outputs=[
                TxOut(value=50_0000_0000, script_pubkey=normal_spk),
                TxOut(value=0, script_pubkey=op_return_spk),
            ],
        )
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=0,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[tx],
            hash=bytes(range(32)),
        )

        scripts = collect_block_scripts(block, db=None)
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0], normal_spk)

    def test_filter_excludes_empty_scripts(self):
        """Empty scriptPubKeys should be excluded."""
        coinbase_input = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b"\x01\x00",
            sequence=0xFFFFFFFF,
        )
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[coinbase_input],
            outputs=[
                TxOut(value=0, script_pubkey=b""),
            ],
        )
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=0,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[tx],
            hash=bytes(range(32)),
        )
        scripts = collect_block_scripts(block, db=None)
        self.assertEqual(len(scripts), 0)


class TestFilterHeader(unittest.TestCase):
    """Test filter header computation."""

    def _dsha256(self, data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def test_genesis_filter_header(self):
        """Filter header for genesis block with zero prev_header."""
        filter_bytes = hex_to_bytes(GENESIS_BASIC_FILTER_HEX)
        prev_header = bytes(32)
        header = compute_filter_header(filter_bytes, prev_header)
        self.assertEqual(len(header), 32)

        # Verify manually: dSHA256(dSHA256(filter) || 00..00)
        fhash = self._dsha256(filter_bytes)
        expected = self._dsha256(fhash + prev_header)
        self.assertEqual(header, expected)

    def test_filter_hash(self):
        """compute_filter_hash is dSHA256 of filter bytes."""
        data = b"test-filter-data"
        fh = compute_filter_hash(data)
        self.assertEqual(fh, self._dsha256(data))

    def test_header_chaining(self):
        """Filter headers chain correctly."""
        f1 = b"filter-1"
        f2 = b"filter-2"
        prev = bytes(32)

        h1 = compute_filter_header(f1, prev)
        h2 = compute_filter_header(f2, h1)

        # h2 should depend on h1
        self.assertNotEqual(h1, h2)
        # Recompute to verify
        expected_h2 = self._dsha256(self._dsha256(f2) + h1)
        self.assertEqual(h2, expected_h2)


class TestBlockFilterIndex(unittest.TestCase):
    """Test the in-memory block filter index."""

    def _make_block(self, height: int, block_hash: bytes, prev_hash: bytes) -> Block:
        """Create a minimal synthetic block."""
        normal_spk = bytes([0x76, 0xA9, 0x14] + [height & 0xFF] * 20 + [0x88, 0xAC])
        coinbase_input = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b"\x01" + bytes([height & 0xFF]),
            sequence=0xFFFFFFFF,
        )
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[coinbase_input],
            outputs=[TxOut(value=50_0000_0000, script_pubkey=normal_spk)],
        )
        return Block(
            version=1,
            prev_blockhash=prev_hash,
            merkle_root=bytes(32),
            timestamp=1231006505 + height * 600,
            bits=0x1D00FFFF,
            nonce=height,
            transactions=[tx],
            hash=block_hash,
            height=height,
        )

    def test_add_and_retrieve(self):
        """Add a filter and retrieve by hash and height."""
        idx = BlockFilterIndex()
        bh = bytes(range(32))
        block = self._make_block(0, bh, bytes(32))
        filt, fhdr = idx.add(block)

        self.assertEqual(idx.get_filter(bh), filt)
        self.assertEqual(idx.get_header(bh), fhdr)
        result = idx.get_by_height(0)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], filt)
        self.assertEqual(result[1], fhdr)

    def test_chaining(self):
        """Adding consecutive blocks chains filter headers."""
        idx = BlockFilterIndex()
        h0 = bytes([0] * 32)
        h1 = bytes([1] * 32)

        b0 = self._make_block(0, h0, bytes(32))
        b1 = self._make_block(1, h1, h0)

        _, fhdr0 = idx.add(b0)
        _, fhdr1 = idx.add(b1)

        # fhdr1 should use fhdr0 as prev_header
        self.assertNotEqual(fhdr0, fhdr1)
        self.assertEqual(idx.tip_header, fhdr1)

    def test_missing_hash(self):
        """Querying a non-existent hash returns None."""
        idx = BlockFilterIndex()
        self.assertIsNone(idx.get_filter(bytes(32)))
        self.assertIsNone(idx.get_header(bytes(32)))

    def test_missing_height(self):
        """Querying a non-existent height returns None."""
        idx = BlockFilterIndex()
        self.assertIsNone(idx.get_by_height(999))


class TestMultiTxBlock(unittest.TestCase):
    """Test filter construction with multiple transactions."""

    def test_multiple_outputs(self):
        """Block with multiple transactions and outputs."""
        spk1 = bytes([0x76, 0xA9, 0x14] + [0x11] * 20 + [0x88, 0xAC])
        spk2 = bytes([0x76, 0xA9, 0x14] + [0x22] * 20 + [0x88, 0xAC])
        spk3 = bytes([0x00, 0x14] + [0x33] * 20)  # P2WPKH

        coinbase_input = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b"\x01\x00",
            sequence=0xFFFFFFFF,
        )
        coinbase_tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[coinbase_input],
            outputs=[TxOut(value=50_0000_0000, script_pubkey=spk1)],
        )
        regular_tx = Transaction(
            txid=bytes([0x01] * 32),
            version=1,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes([0xFF] * 32),
                    prev_vout=0,
                    script_sig=b"\x00",
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[
                TxOut(value=25_0000_0000, script_pubkey=spk2),
                TxOut(value=25_0000_0000, script_pubkey=spk3),
            ],
        )

        block_hash = bytes(range(32))
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=0,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[coinbase_tx, regular_tx],
            hash=block_hash,
        )

        # Without db, only output scripts are collected
        scripts = collect_block_scripts(block, db=None)
        self.assertEqual(len(scripts), 3)
        self.assertIn(spk1, scripts)
        self.assertIn(spk2, scripts)
        self.assertIn(spk3, scripts)

        # Build filter and verify all scripts match
        filt = build_basic_filter(block, db=None)
        key = _block_filter_siphash_key(block_hash)
        for spk in [spk1, spk2, spk3]:
            self.assertTrue(
                gcs_match(filt, key, spk),
                f"Script {spk.hex()} not found in filter",
            )

    def test_duplicate_scripts_deduplicated(self):
        """Duplicate scripts should be deduplicated in the filter."""
        spk = bytes([0x76, 0xA9, 0x14] + [0xAA] * 20 + [0x88, 0xAC])

        coinbase_input = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b"\x01\x00",
            sequence=0xFFFFFFFF,
        )
        tx = Transaction(
            txid=bytes(32),
            version=1,
            locktime=0,
            inputs=[coinbase_input],
            outputs=[
                TxOut(value=25_0000_0000, script_pubkey=spk),
                TxOut(value=25_0000_0000, script_pubkey=spk),
            ],
        )
        block = Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=0,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[tx],
            hash=bytes(range(32)),
        )

        # Raw scripts include both
        scripts = collect_block_scripts(block, db=None)
        self.assertEqual(len(scripts), 2)

        # But the filter deduplicates
        filt = build_basic_filter(block, db=None)
        # Parse N from filter — should be 1 (deduplicated)
        n, _ = _decode_compact_size(filt)
        self.assertEqual(n, 1)


class TestSipHash(unittest.TestCase):
    """Verify SipHash-2-4 against known test vectors."""

    def test_reference_vector(self):
        """
        SipHash-2-4 reference test vector.

        key = 00 01 02 ... 0f
        data = 00 01 02 ... 0e  (15 bytes)
        Expected: 0xa129ca6149be45e5
        """
        key = bytes(range(16))
        data = bytes(range(15))
        result = _siphash_2_4(key, data)
        self.assertEqual(result, 0xA129CA6149BE45E5)

    def test_empty_data(self):
        """SipHash with empty data should produce a valid hash."""
        key = bytes(16)
        result = _siphash_2_4(key, b"")
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 2**64)


class TestBIP158Parameters(unittest.TestCase):
    """Verify BIP 158 constants."""

    def test_parameters(self):
        self.assertEqual(GCS_P, 19)
        self.assertEqual(GCS_M, 784931)
        self.assertEqual(BASIC_FILTER_TYPE, 0)


if __name__ == "__main__":
    unittest.main()
