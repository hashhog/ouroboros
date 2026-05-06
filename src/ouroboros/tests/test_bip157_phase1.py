"""
BIP 157 / 158 Phase 1 wire-up tests.

Covers the integration layer that turns ``blockfilter.py`` from a
library into a production index:

- ``PersistentBlockFilterIndex`` survives a restart (filters + headers
  + height mapping + tip header all read back correctly after
  re-opening the same data directory).
- The on-disk layout uses atomic writes (no ``*.tmp`` litter after a
  successful add).
- ``getcfilters`` / ``getcfheaders`` / ``getcfcheckpt`` payload encoders
  round-trip cleanly and the wire-format byte sequences match the
  BIP-157 spec.
- The ``getblockfilter`` RPC structure is what light clients expect
  (``{"filter": <hex>, "header": <hex>}``).
- ``--blockfilterindex`` -> NODE_COMPACT_FILTERS service-bit linkage.

These tests deliberately avoid spinning up a full Ouroboros node — they
exercise the building blocks that the dispatch wired together.
"""

import os
import sys
import tempfile
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
    PersistentBlockFilterIndex,
    build_basic_filter,
    compute_filter_hash,
    compute_filter_header,
)
from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.p2p_messages import (  # noqa: E402
    CFCHECKPT_INTERVAL,
    MAX_GETCFHEADERS_SIZE,
    MAX_GETCFILTERS_SIZE,
    NODE_COMPACT_FILTERS,
    CFCheckptMessage,
    CFHeadersMessage,
    CFilterMessage,
    GetCFCheckptMessage,
    GetCFHeadersMessage,
    GetCFiltersMessage,
)


def _hex(s: str) -> bytes:
    return bytes.fromhex(s.replace("\n", "").replace(" ", ""))


# Mainnet genesis block (same as test_blockfilter.py).  Used for
# end-to-end persistence tests so the indexed payload is a known-good
# BIP-158 vector.
_GENESIS_HEX = (
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
_GENESIS_BASIC_FILTER_HEX = "017fa880"


def _make_genesis_block() -> Block:
    return Block.deserialize(_hex(_GENESIS_HEX))


def _make_synthetic_block(seed: int, prev_blockhash: bytes) -> Block:
    """Tiny coinbase-only block; deterministic from *seed*."""
    spk = bytes([0x76, 0xA9, 0x14] + [seed & 0xFF] * 20 + [0x88, 0xAC])
    coinbase = Transaction(
        txid=bytes([(seed + 1) & 0xFF] * 32),
        version=1,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=bytes(32),
                prev_vout=0xFFFFFFFF,
                script_sig=bytes([0x04]) + seed.to_bytes(4, "little"),
                sequence=0xFFFFFFFF,
            ),
        ],
        outputs=[TxOut(value=50_0000_0000, script_pubkey=spk)],
    )
    return Block(
        version=1,
        prev_blockhash=prev_blockhash,
        merkle_root=bytes(32),
        timestamp=0,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[coinbase],
        hash=bytes([(seed + 0x80) & 0xFF] * 32),
    )


# =============================================================================
# Test 1 — Filter byte-correctness vs BIP-158 vector (genesis)
# =============================================================================

class TestFilterByteCorrectness(unittest.TestCase):
    """The mainnet genesis block must match the BIP-158 published vector."""

    def test_genesis_block_filter_matches_bip158_vector(self):
        block = _make_genesis_block()
        filt = build_basic_filter(block, db=None)
        self.assertEqual(filt.hex(), _GENESIS_BASIC_FILTER_HEX)

    def test_genesis_filter_header_chains_from_zero(self):
        block = _make_genesis_block()
        filt = build_basic_filter(block, db=None)
        header = compute_filter_header(filt, b"\x00" * 32)
        self.assertEqual(len(header), 32)
        # Pure dSHA256(filter_hash || zeros) — sanity that the index
        # implementation hasn't reinvented the chaining rule.
        import hashlib
        fhash = hashlib.sha256(hashlib.sha256(filt).digest()).digest()
        expected = hashlib.sha256(
            hashlib.sha256(fhash + b"\x00" * 32).digest()
        ).digest()
        self.assertEqual(header, expected)


# =============================================================================
# Test 2 — Persistence: index survives a restart
# =============================================================================

class TestPersistentBlockFilterIndexRestart(unittest.TestCase):
    """Filter / header / height / tip-header all survive process restart."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="ouroboros-bfi-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_filter_and_header_persist_across_restart(self):
        block = _make_genesis_block()
        block.height = 0

        # First run: write the filter
        idx1 = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        filt1, header1 = idx1.add_block(block, height=0, db=None)
        del idx1  # Simulate process exit

        # Second run: re-open the same datadir, must read same bytes
        idx2 = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        filt2 = idx2.get_filter(block.hash)
        header2 = idx2.get_header(block.hash)

        self.assertEqual(filt1, filt2)
        self.assertEqual(header1, header2)
        self.assertEqual(filt2.hex(), _GENESIS_BASIC_FILTER_HEX)
        self.assertEqual(idx2.get_block_hash_by_height(0), block.hash)
        self.assertEqual(idx2.tip_header, header1)

    def test_chain_extends_after_restart(self):
        """tip_header must advance correctly when adding a second block
        after re-opening the index from disk."""
        b0 = _make_genesis_block()
        b0.height = 0

        idx1 = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        _, h0 = idx1.add_block(b0, height=0, db=None)
        del idx1

        idx2 = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        # tip header must come back as h0 (NOT zero, NOT recomputed)
        self.assertEqual(idx2.tip_header, h0)

        b1 = _make_synthetic_block(seed=1, prev_blockhash=b0.hash)
        b1.height = 1
        f1, h1 = idx2.add_block(b1, height=1, db=None)

        # New tip = dSHA256(dSHA256(f1) || h0)
        expected_h1 = compute_filter_header(f1, h0)
        self.assertEqual(h1, expected_h1)
        self.assertEqual(idx2.tip_header, h1)

    def test_no_tmp_files_after_atomic_write(self):
        """Successful add must not leave .tmp scratch files behind."""
        block = _make_genesis_block()
        block.height = 0
        idx = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        idx.add_block(block, height=0, db=None)

        for root, _, files in os.walk(self._tmpdir):
            for name in files:
                self.assertFalse(
                    name.endswith(".tmp"),
                    f"Stray tmp file {os.path.join(root, name)} after atomic write",
                )

    def test_idempotent_readd_does_not_duplicate_chain_tick(self):
        """Re-adding the same block must not advance tip_header twice."""
        block = _make_genesis_block()
        block.height = 0
        idx = PersistentBlockFilterIndex(self._tmpdir, enabled=True)
        _, h0 = idx.add_block(block, height=0, db=None)
        _, h0_again = idx.add_block(block, height=0, db=None)
        self.assertEqual(h0, h0_again)
        self.assertEqual(idx.tip_header, h0)


# =============================================================================
# Test 3 — P2P getcfilters / getcfheaders / getcfcheckpt round-trip
# =============================================================================

class TestBIP157P2PMessages(unittest.TestCase):
    """Wire-format round-trip for the 6 BIP-157 P2P messages."""

    def test_getcfilters_roundtrip(self):
        original = GetCFiltersMessage(
            filter_type=BASIC_FILTER_TYPE,
            start_height=12345,
            stop_hash=bytes(range(32)),
        )
        msg = original.to_network_message("mainnet")
        decoded = GetCFiltersMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.start_height, original.start_height)
        self.assertEqual(decoded.stop_hash, original.stop_hash)
        # Wire payload size is exactly 1 + 4 + 32 bytes per BIP-157
        self.assertEqual(len(msg.payload), 1 + 4 + 32)
        self.assertEqual(msg.command, "getcfilters")

    def test_cfilter_roundtrip(self):
        original = CFilterMessage(
            filter_type=BASIC_FILTER_TYPE,
            block_hash=bytes(range(32)),
            filter_bytes=_hex(_GENESIS_BASIC_FILTER_HEX),
        )
        msg = original.to_network_message("mainnet")
        decoded = CFilterMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.block_hash, original.block_hash)
        self.assertEqual(decoded.filter_bytes, original.filter_bytes)
        self.assertEqual(msg.command, "cfilter")

    def test_getcfheaders_roundtrip(self):
        original = GetCFHeadersMessage(
            filter_type=BASIC_FILTER_TYPE,
            start_height=0,
            stop_hash=bytes(range(32)),
        )
        msg = original.to_network_message("mainnet")
        decoded = GetCFHeadersMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.start_height, original.start_height)
        self.assertEqual(decoded.stop_hash, original.stop_hash)
        self.assertEqual(msg.command, "getcfheaders")

    def test_cfheaders_roundtrip(self):
        hashes = [bytes([i] * 32) for i in range(5)]
        original = CFHeadersMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
            previous_filter_header=bytes([0xAB] * 32),
            filter_hashes=hashes,
        )
        msg = original.to_network_message("mainnet")
        decoded = CFHeadersMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.stop_hash, original.stop_hash)
        self.assertEqual(decoded.previous_filter_header, original.previous_filter_header)
        self.assertEqual(decoded.filter_hashes, original.filter_hashes)
        self.assertEqual(msg.command, "cfheaders")

    def test_getcfcheckpt_roundtrip(self):
        original = GetCFCheckptMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
        )
        msg = original.to_network_message("mainnet")
        decoded = GetCFCheckptMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.stop_hash, original.stop_hash)
        self.assertEqual(len(msg.payload), 1 + 32)
        self.assertEqual(msg.command, "getcfcheckpt")

    def test_cfcheckpt_roundtrip_with_intervals(self):
        n = 3  # represents heights 1000, 2000, 3000
        headers = [bytes([i] * 32) for i in range(n)]
        original = CFCheckptMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
            filter_headers=headers,
        )
        msg = original.to_network_message("mainnet")
        decoded = CFCheckptMessage.from_payload(msg.payload)
        self.assertEqual(decoded.filter_type, original.filter_type)
        self.assertEqual(decoded.stop_hash, original.stop_hash)
        self.assertEqual(decoded.filter_headers, original.filter_headers)
        self.assertEqual(msg.command, "cfcheckpt")


# =============================================================================
# Test 4 — Service bit + protocol limits
# =============================================================================

class TestBIP157Constants(unittest.TestCase):
    """Service bit and protocol limits must match BIP-157 wire spec."""

    def test_node_compact_filters_service_bit(self):
        # BIP-157: NODE_COMPACT_FILTERS = 1 << 6 = 0x40
        self.assertEqual(NODE_COMPACT_FILTERS, 0x40)
        self.assertEqual(NODE_COMPACT_FILTERS, 1 << 6)

    def test_protocol_limits(self):
        # BIP-157 / Bitcoin Core src/net_processing.cpp
        self.assertEqual(MAX_GETCFILTERS_SIZE, 1000)
        self.assertEqual(MAX_GETCFHEADERS_SIZE, 2000)
        self.assertEqual(CFCHECKPT_INTERVAL, 1000)

    def test_basic_filter_parameters(self):
        # BIP-158 basic filter: P=19, M=784931, type=0x00
        self.assertEqual(BASIC_FILTER_TYPE, 0)
        self.assertEqual(GCS_P, 19)
        self.assertEqual(GCS_M, 784931)


# =============================================================================
# Test 5 — getblockfilter RPC payload shape
# =============================================================================

class TestGetBlockFilterRPCShape(unittest.TestCase):
    """RPC ``getblockfilter`` produces the structure light clients expect."""

    def test_response_keys_and_hex_encoding(self):
        # Exercise the bare combinators (filter + header) the way the
        # RPC handler does.  We don't spin up FastAPI here — the goal is
        # to verify the byte→hex shape, not the HTTP layer.
        block = _make_genesis_block()
        filt = build_basic_filter(block, db=None)
        header = compute_filter_header(filt, b"\x00" * 32)

        response = {
            "filter": filt.hex(),
            "header": header.hex(),
        }
        self.assertIn("filter", response)
        self.assertIn("header", response)
        # Hex-encoded, no 0x prefix, no whitespace
        self.assertTrue(all(c in "0123456789abcdef" for c in response["filter"]))
        self.assertTrue(all(c in "0123456789abcdef" for c in response["header"]))
        # Header must be exactly 64 hex chars (32 bytes)
        self.assertEqual(len(response["header"]), 64)
        # Filter is variable but starts with N as CompactSize
        self.assertEqual(response["filter"], _GENESIS_BASIC_FILTER_HEX)


# =============================================================================
# Test 6 — Filter hash chain integrity
# =============================================================================

class TestFilterChainIntegrity(unittest.TestCase):
    """``compute_filter_hash`` is dSHA256, ``compute_filter_header`` chains."""

    def test_filter_hash_is_dsha256(self):
        import hashlib
        data = b"BIP-158 test"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        self.assertEqual(compute_filter_hash(data), expected)

    def test_chain_two_blocks(self):
        b0 = _make_genesis_block()
        f0 = build_basic_filter(b0, db=None)
        h0 = compute_filter_header(f0, b"\x00" * 32)

        b1 = _make_synthetic_block(seed=1, prev_blockhash=b0.hash)
        f1 = build_basic_filter(b1, db=None)
        h1 = compute_filter_header(f1, h0)

        # h1 must depend on both f1 and h0 — flipping either breaks it
        h1_alt = compute_filter_header(f1, b"\x00" * 32)
        self.assertNotEqual(h1, h1_alt)
        h1_alt2 = compute_filter_header(f0, h0)
        self.assertNotEqual(h1, h1_alt2)


if __name__ == "__main__":
    unittest.main()
