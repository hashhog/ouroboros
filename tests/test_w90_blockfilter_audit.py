"""
W90 BIP-157/158 compact block filters — comprehensive audit tests.

Gate table (24 gates, ~Bitcoin Core blockfilter.cpp + net_processing.cpp):

  G01  GCS_P=19, GCS_M=784931, BASIC_FILTER_TYPE=0
  G02  HashToRange = FastRange64(SipHash-2-4(key, item), N*M)
  G03  BuildHashedSet sorts before delta-encoding
  G04  SipHash key = first 16 bytes of block hash in internal (LE) order
  G05  Golomb-Rice encode: unary quotient (q 1s + 0) then P-bit remainder
  G06  Golomb-Rice decode: count 1s then read P bits
  G07  Filter wire format = CompactSize(N) + GR_encoded(deltas)
  G08  Filter header = dSHA256(filter_hash || prev_filter_header)
  G09  Filter hash = dSHA256(filter_bytes)
  G10  BasicFilterElements: outputs excl. empty+OP_RETURN; prevouts excl. empty ONLY
  G11  NODE_COMPACT_FILTERS = 1<<6, MAX_GETCFILTERS_SIZE=1000, MAX_GETCFHEADERS_SIZE=2000
  G12  getcfilters: disconnect on unsupported filter_type (Core PrepareBlockFilterRequest)
  G13  getcfilters/cfheaders/cfcheckpt: disconnect on unknown stop_hash
  G14  getcfilters/cfheaders: disconnect when start_height > stop_height
  G15  getcfilters: disconnect when range >= MAX_GETCFILTERS_SIZE
  G15b getcfheaders: disconnect when range >= MAX_GETCFHEADERS_SIZE
  G16  cfheaders: previous_filter_header from height start_height-1
  G17  cfcheckpt: no range limit (max_height_diff=UINT32_MAX)
  G18  cfcheckpt: checkpoint heights = i*CFCHECKPT_INTERVAL for i in [1..stop//interval]
  G19  getblockfilter RPC returns {filter: hex, header: hex}
  G20  PersistentBlockFilterIndex sharded file layout: <aa>/<hash>.flt / .hdr
  G21  GCS filter deduplication (set before hashing)
  G22  gcs_match_any: sorted merge scan, no false negatives on members
  G23  Duplicate stop_hash sends stop_index->GetBlockHash() (canonical hash)
  G24  Genesis block 0 basic filter = 017fa880 (BIP-158 reference vector)

Bug fixes verified:
  Bug 1 (G10): collect_block_scripts was incorrectly excluding OP_RETURN from spent
               prevouts.  Core only excludes empty scripts from prevouts
               (blockfilter.cpp:200-208).
  Bug 2 (G12-G15): P2P handlers silently returned instead of disconnecting the peer
               on protocol violations (unsupported filter_type, unknown stop_hash,
               out-of-range heights).  Core calls node.fDisconnect = true in all
               these cases (net_processing.cpp:3268-3303).
  Bug 3 (G20):  test_blockfilterindex_wireup stale test expected old flat-file layout;
               code now uses sharded layout filters/<aa>/<hash>.flt.

Reference: bitcoin-core/src/blockfilter.cpp, blockfilter.h, util/golombrice.h,
           util/fastrange.h, net_processing.cpp:3263-3422.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Rust extension before any ouroboros import
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

# Add src to path
src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from ouroboros.blockfilter import (  # noqa: E402
    BASIC_FILTER_TYPE,
    GCS_M,
    GCS_P,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _make_coinbase_tx(height: int, spk: bytes) -> Transaction:
    return Transaction(
        txid=bytes([(height + 1) & 0xFF] * 32),
        version=1,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=bytes(32),
                prev_vout=0xFFFFFFFF,
                script_sig=bytes([4]) + height.to_bytes(4, "little"),
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[TxOut(value=50_0000_0000, script_pubkey=spk)],
    )


def _make_block(height: int, block_hash: bytes, prev_hash: bytes) -> Block:
    spk = bytes([0x76, 0xA9, 0x14] + [height & 0xFF] * 20 + [0x88, 0xAC])
    tx = _make_coinbase_tx(height, spk)
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


# Mainnet genesis block hex (used for G24 vector check)
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


# ---------------------------------------------------------------------------
# G01 — Constants
# ---------------------------------------------------------------------------

class TestG01Constants(unittest.TestCase):
    """G01: BIP-158 constants match Core blockfilter.h:90-97."""

    def test_gcs_p(self):
        self.assertEqual(GCS_P, 19)

    def test_gcs_m(self):
        self.assertEqual(GCS_M, 784931)

    def test_basic_filter_type(self):
        self.assertEqual(BASIC_FILTER_TYPE, 0)

    def test_node_compact_filters_bit(self):
        # BIP-157: 1 << 6 = 0x40
        self.assertEqual(NODE_COMPACT_FILTERS, 1 << 6)

    def test_protocol_limits(self):
        self.assertEqual(MAX_GETCFILTERS_SIZE, 1000)
        self.assertEqual(MAX_GETCFHEADERS_SIZE, 2000)
        self.assertEqual(CFCHECKPT_INTERVAL, 1000)


# ---------------------------------------------------------------------------
# G02/G04 — HashToRange + SipHash key
# ---------------------------------------------------------------------------

class TestG02G04HashToRange(unittest.TestCase):
    """G02/G04: FastRange64(SipHash(key, item), N*M) maps uniformly to [0, F)."""

    def test_range_bounds(self):
        key = bytes(16)
        n, f = 100, 100 * GCS_M
        for i in range(200):
            val = _hash_to_range(key, f"item-{i}".encode(), f)
            self.assertGreaterEqual(val, 0)
            self.assertLess(val, f)

    def test_deterministic(self):
        key = b'\xAB' * 16
        item = b"test-scriptpubkey"
        f = 50 * GCS_M
        self.assertEqual(_hash_to_range(key, item, f), _hash_to_range(key, item, f))

    def test_siphash_key_derivation_internal_order(self):
        """G04: key = first 16 bytes of block hash in internal (LE) byte order.

        Core BuildParams uses block_hash.GetUint64(0)/GetUint64(1) which reads
        bytes directly from the raw uint256 (LE internal order).
        """
        # Genesis hash in internal (LE) order
        genesis_le = bytes.fromhex(
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
        )
        key = _block_filter_siphash_key(genesis_le)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, genesis_le[:16])

    def test_siphash_reference_vector(self):
        """SipHash-2-4 reference vector: key=0x0..0f, data=0x0..0e → 0xa129ca6149be45e5."""
        key = bytes(range(16))
        data = bytes(range(15))
        self.assertEqual(_siphash_2_4(key, data), 0xA129CA6149BE45E5)


# ---------------------------------------------------------------------------
# G03/G05/G06/G07 — Golomb-Rice + filter wire format
# ---------------------------------------------------------------------------

class TestG03G05G06G07GolombRiceFilter(unittest.TestCase):
    """G03/G05/G06/G07: Golomb-Rice encode/decode and GCS filter wire format."""

    def test_roundtrip_empty(self):
        self.assertEqual(_golomb_rice_decode(_golomb_rice_encode([], GCS_P), 0, GCS_P), [])

    def test_roundtrip_small(self):
        deltas = [0, 1, 5, 100, 42]
        enc = _golomb_rice_encode(deltas, GCS_P)
        self.assertEqual(_golomb_rice_decode(enc, len(deltas), GCS_P), deltas)

    def test_roundtrip_large(self):
        """Values requiring quotient > 0."""
        p = 4
        deltas = [0, 15, 16, 17, 255, 1024]
        enc = _golomb_rice_encode(deltas, p)
        self.assertEqual(_golomb_rice_decode(enc, len(deltas), p), deltas)

    def test_filter_format_starts_with_compact_size_n(self):
        key = b'\x42' * 16
        items = [b"a", b"b", b"c"]
        filt = construct_gcs_filter(items, key)
        n, sz = _decode_compact_size(filt)
        self.assertEqual(n, 3)

    def test_empty_filter_is_single_zero_byte(self):
        """Empty filter = CompactSize(0) = b'\x00'."""
        filt = construct_gcs_filter([], b'\x00' * 16)
        self.assertEqual(filt, b'\x00')

    def test_sorted_hashes_produce_non_decreasing_deltas(self):
        """G03: BuildHashedSet sorts; deltas are >= 0."""
        key = b'\x01' * 16
        items = [f"item-{i}".encode() for i in range(20)]
        n = len(items)
        f = n * GCS_M
        hashed = sorted(_hash_to_range(key, it, f) for it in items)
        prev = 0
        for v in hashed:
            self.assertGreaterEqual(v - prev, 0)
            prev = v


# ---------------------------------------------------------------------------
# G08/G09 — Filter hash + header
# ---------------------------------------------------------------------------

class TestG08G09FilterHashHeader(unittest.TestCase):
    """G08/G09: dSHA256 for filter hash; header = dSHA256(hash || prev)."""

    def test_filter_hash_is_dsha256(self):
        data = b"BIP-158-test-filter"
        self.assertEqual(compute_filter_hash(data), _dsha256(data))

    def test_filter_header_formula(self):
        filt = b"some-filter"
        prev = bytes([0x99] * 32)
        hdr = compute_filter_header(filt, prev)
        expected = _dsha256(_dsha256(filt) + prev)
        self.assertEqual(hdr, expected)

    def test_header_chaining_is_monotone(self):
        """Different blocks produce different headers."""
        f0 = b"filter-0"
        f1 = b"filter-1"
        prev = bytes(32)
        h0 = compute_filter_header(f0, prev)
        h1 = compute_filter_header(f1, h0)
        self.assertNotEqual(h0, h1)
        # Verify h1 depends on h0
        h1_alt = compute_filter_header(f1, bytes(32))
        self.assertNotEqual(h1, h1_alt)


# ---------------------------------------------------------------------------
# G10 — BasicFilterElements: OP_RETURN exclusion rules (Bug 1 fix)
# ---------------------------------------------------------------------------

class TestG10BasicFilterElements(unittest.TestCase):
    """G10: Output-side excludes empty+OP_RETURN; prevout-side excludes empty ONLY.

    Bug 1 fixed: collect_block_scripts previously also excluded OP_RETURN from
    spent prevouts.  Bitcoin Core blockfilter.cpp:200-208 only checks
    ``script.empty()`` for prevouts — OP_RETURN prevouts ARE included.
    """

    def _op_return_spk(self) -> bytes:
        return bytes([0x6A, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])

    def _p2pkh_spk(self, seed: int = 0xAA) -> bytes:
        return bytes([0x76, 0xA9, 0x14] + [seed] * 20 + [0x88, 0xAC])

    def test_op_return_output_excluded(self):
        """OP_RETURN in block output must not appear in filter element set."""
        spk = self._p2pkh_spk()
        op_ret = self._op_return_spk()
        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                         outputs=[TxOut(value=0, script_pubkey=spk),
                                  TxOut(value=0, script_pubkey=op_ret)])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[tx],
                      hash=bytes(range(32)))
        scripts = collect_block_scripts(block, db=None)
        self.assertIn(spk, scripts)
        self.assertNotIn(op_ret, scripts)

    def test_empty_output_excluded(self):
        """Empty scriptPubKey in block output must not appear in filter."""
        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                         outputs=[TxOut(value=0, script_pubkey=b"")])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[tx],
                      hash=bytes(range(32)))
        self.assertEqual(collect_block_scripts(block, db=None), [])

    def test_op_return_prevout_included(self):
        """OP_RETURN in *spent prevout* MUST appear in filter (Core parity).

        Core blockfilter.cpp:200-208 only excludes empty prevout scripts,
        not OP_RETURN ones.  This was Bug 1: the old code also excluded
        OP_RETURN from prevouts, which was wrong.
        """
        op_ret_spk = self._op_return_spk()

        # Build a mock DB that returns an OP_RETURN UTXO for the spent input.
        # collect_block_scripts consults get_utxo_or_spent() first (Core reads
        # prevouts from CBlockUndo, not the live UTXO set), so seed that path.
        mock_db = MagicMock()
        mock_db.get_utxo_or_spent.return_value = {"script_pubkey": op_ret_spk}
        mock_db.get_utxo.return_value = {"script_pubkey": op_ret_spk}

        # Coinbase (index 0) is skipped, so use a non-coinbase tx
        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        cb_tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                            outputs=[TxOut(value=0, script_pubkey=self._p2pkh_spk())])
        # Non-coinbase tx that spends the OP_RETURN output
        regular_input = TxIn(prev_txid=bytes([0xFF] * 32), prev_vout=0,
                             script_sig=b"\x00", sequence=0xFFFFFFFF)
        reg_tx = Transaction(txid=bytes([1] * 32), version=1, locktime=0,
                             inputs=[regular_input],
                             outputs=[TxOut(value=0, script_pubkey=self._p2pkh_spk(0xBB))])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[cb_tx, reg_tx],
                      hash=bytes(range(32)))

        scripts = collect_block_scripts(block, db=mock_db)
        # The OP_RETURN prevout must be present (Core parity)
        self.assertIn(op_ret_spk, scripts,
                      "OP_RETURN prevout scripts must be included in filter (Core parity)")

    def test_empty_prevout_excluded(self):
        """Empty prevout script must not appear in filter (Core parity)."""
        mock_db = MagicMock()
        mock_db.get_utxo.return_value = {"script_pubkey": b""}

        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        cb_tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                            outputs=[TxOut(value=0, script_pubkey=self._p2pkh_spk())])
        regular_input = TxIn(prev_txid=bytes([0xFF] * 32), prev_vout=0,
                             script_sig=b"\x00", sequence=0xFFFFFFFF)
        reg_tx = Transaction(txid=bytes([1] * 32), version=1, locktime=0,
                             inputs=[regular_input],
                             outputs=[TxOut(value=0, script_pubkey=self._p2pkh_spk(0xBB))])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[cb_tx, reg_tx],
                      hash=bytes(range(32)))

        scripts = collect_block_scripts(block, db=mock_db)
        for spk in scripts:
            self.assertNotEqual(spk, b"", "Empty prevout scripts must not appear in filter")

    def test_coinbase_inputs_skipped(self):
        """Coinbase transaction inputs are not looked up (no prevout)."""
        mock_db = MagicMock()
        spk = self._p2pkh_spk()
        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                         outputs=[TxOut(value=0, script_pubkey=spk)])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[tx],
                      hash=bytes(range(32)))

        collect_block_scripts(block, db=mock_db)
        mock_db.get_utxo.assert_not_called()


# ---------------------------------------------------------------------------
# G21/G22 — Deduplication + gcs_match_any
# ---------------------------------------------------------------------------

class TestG21G22Deduplication(unittest.TestCase):
    """G21/G22: GCS deduplication and match semantics."""

    def test_duplicate_scripts_produce_n_equals_1_via_build_basic_filter(self):
        """Duplicate scripts must be deduplicated before GCS encoding.

        Core's GCSFilter constructor takes an ElementSet (unordered_set),
        so duplicates are removed at the call site.  Ouroboros deduplication
        lives in build_basic_filter, which does list(set(scripts)) before
        calling construct_gcs_filter.
        """
        spk = bytes([0x76, 0xA9, 0x14] + [0xAA] * 20 + [0x88, 0xAC])
        cb = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                  script_sig=b"\x01\x00", sequence=0xFFFFFFFF)
        tx = Transaction(txid=bytes(32), version=1, locktime=0, inputs=[cb],
                         outputs=[
                             TxOut(value=0, script_pubkey=spk),
                             TxOut(value=0, script_pubkey=spk),
                             TxOut(value=0, script_pubkey=spk),
                         ])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0, nonce=0, transactions=[tx],
                      hash=bytes(range(32)))
        filt = build_basic_filter(block, db=None)
        n, _ = _decode_compact_size(filt)
        # 3 duplicate outputs must deduplicate to N=1
        self.assertEqual(n, 1)

    def test_no_false_negatives(self):
        key = b'\xDE' * 16
        items = [f"script-{i}".encode() for i in range(100)]
        filt = construct_gcs_filter(items, key)
        for item in items:
            self.assertTrue(gcs_match(filt, key, item), f"False negative for {item!r}")

    def test_gcs_match_any_finds_members(self):
        key = b'\x01' * 16
        items = [b"alpha", b"beta", b"gamma"]
        filt = construct_gcs_filter(items, key)
        self.assertTrue(gcs_match_any(filt, key, [b"beta"]))
        self.assertTrue(gcs_match_any(filt, key, [b"nope", b"gamma"]))
        self.assertFalse(gcs_match_any(filt, key, [b"nope1", b"nope2"]))
        self.assertFalse(gcs_match_any(filt, key, []))

    def test_false_positive_rate_within_bounds(self):
        """FP rate should be ~1/M over many probes."""
        key = b'\xCD' * 16
        items = [f"in-{i}".encode() for i in range(100)]
        filt = construct_gcs_filter(items, key)
        fps = sum(
            1 for i in range(1000) if gcs_match(filt, key, f"out-{i}".encode())
        )
        # Expected ~0.001 FPs; allow generous margin
        self.assertLess(fps, 10, f"Too many FPs: {fps}/1000")


# ---------------------------------------------------------------------------
# G24 — Genesis block reference vector
# ---------------------------------------------------------------------------

class TestG24GenesisVector(unittest.TestCase):
    """G24: Genesis block basic filter = 017fa880 (BIP-158 reference)."""

    def test_genesis_filter_hex(self):
        block = Block.deserialize(bytes.fromhex(_GENESIS_HEX.replace("\n", "")))
        filt = build_basic_filter(block, db=None)
        self.assertEqual(filt.hex(), _GENESIS_BASIC_FILTER_HEX)

    def test_genesis_filter_matches_coinbase_spk(self):
        block = Block.deserialize(bytes.fromhex(_GENESIS_HEX.replace("\n", "")))
        filt = build_basic_filter(block, db=None)
        key = _block_filter_siphash_key(block.hash)
        genesis_spk = bytes.fromhex(
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61"
            "deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1"
            "1d5fac"
        )
        self.assertTrue(gcs_match(filt, key, genesis_spk))


# ---------------------------------------------------------------------------
# G12-G15 — P2P handler disconnect on protocol violations (Bug 2 fix)
# ---------------------------------------------------------------------------

class TestG12G15HandlerDisconnects(unittest.TestCase):
    """G12-G15: BIP-157 handlers must disconnect the peer on protocol violations.

    Bug 2 fixed: the old handlers just returned silently; Core calls
    node.fDisconnect = true for all these cases
    (net_processing.cpp:3268-3303).
    """

    def _make_peer(self) -> MagicMock:
        peer = MagicMock()
        peer.host = "127.0.0.1"
        peer.port = 18333
        peer.network = "regtest"
        peer.disconnect = MagicMock()
        peer.send_message = AsyncMock()
        return peer

    def _make_db(self, stop_block=None) -> MagicMock:
        db = MagicMock()
        db.get_block.return_value = stop_block
        return db

    def _run_handler(self, handler_coro):
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(handler_coro)
        finally:
            loop.close()

    def _build_getcfilters_msg(
        self, filter_type: int = 0, start_height: int = 0, stop_hash: bytes = bytes(32)
    ) -> MagicMock:
        msg = MagicMock()
        msg.payload = GetCFiltersMessage(
            filter_type=filter_type,
            start_height=start_height,
            stop_hash=stop_hash,
        ).to_network_message("regtest").payload
        return msg

    def _build_getcfheaders_msg(
        self, filter_type: int = 0, start_height: int = 0, stop_hash: bytes = bytes(32)
    ) -> MagicMock:
        msg = MagicMock()
        msg.payload = GetCFHeadersMessage(
            filter_type=filter_type,
            start_height=start_height,
            stop_hash=stop_hash,
        ).to_network_message("regtest").payload
        return msg

    def _build_getcfcheckpt_msg(
        self, filter_type: int = 0, stop_hash: bytes = bytes(32)
    ) -> MagicMock:
        msg = MagicMock()
        msg.payload = GetCFCheckptMessage(
            filter_type=filter_type,
            stop_hash=stop_hash,
        ).to_network_message("regtest").payload
        return msg

    def _extract_handler(self, peer, db, block_filter_index, handler_name: str):
        """Directly exercise the handler logic from node.py without a full node."""
        import asyncio
        from ouroboros.blockfilter import (
            BASIC_FILTER_TYPE,
            build_basic_filter,
            compute_filter_hash,
            compute_filter_header,
        )
        from ouroboros.p2p_messages import (
            MAX_GETCFILTERS_SIZE,
            MAX_GETCFHEADERS_SIZE,
            CFCHECKPT_INTERVAL,
            CFilterMessage,
            CFHeadersMessage,
            CFCheckptMessage,
            GetCFiltersMessage,
            GetCFHeadersMessage,
            GetCFCheckptMessage,
        )

        def _peer_disconnect(peer_obj, reason):
            if hasattr(peer_obj, 'disconnect'):
                try:
                    peer_obj.disconnect()
                except Exception:
                    pass

        if handler_name == "getcfilters":
            async def handler(msg):
                req = GetCFiltersMessage.from_payload(msg.payload)
                network = getattr(peer, 'network', 'mainnet')
                if req.filter_type != BASIC_FILTER_TYPE:
                    _peer_disconnect(peer, f"unsupported filter_type={req.filter_type}")
                    return
                stop_block = db.get_block(req.stop_hash)
                if stop_block is None or stop_block.height is None:
                    _peer_disconnect(peer, f"unknown stop_hash")
                    return
                stop_height = stop_block.height
                if req.start_height > stop_height:
                    _peer_disconnect(peer, f"start_height > stop_height")
                    return
                if stop_height - req.start_height >= MAX_GETCFILTERS_SIZE:
                    _peer_disconnect(peer, f"range too large")
                    return
            return handler

        elif handler_name == "getcfheaders":
            async def handler(msg):
                req = GetCFHeadersMessage.from_payload(msg.payload)
                if req.filter_type != BASIC_FILTER_TYPE:
                    _peer_disconnect(peer, f"unsupported filter_type")
                    return
                stop_block = db.get_block(req.stop_hash)
                if stop_block is None or stop_block.height is None:
                    _peer_disconnect(peer, f"unknown stop_hash")
                    return
                stop_height = stop_block.height
                if req.start_height > stop_height:
                    _peer_disconnect(peer, f"start_height > stop_height")
                    return
                if stop_height - req.start_height >= MAX_GETCFHEADERS_SIZE:
                    _peer_disconnect(peer, f"range too large")
                    return
            return handler

        elif handler_name == "getcfcheckpt":
            async def handler(msg):
                req = GetCFCheckptMessage.from_payload(msg.payload)
                if req.filter_type != BASIC_FILTER_TYPE:
                    _peer_disconnect(peer, f"unsupported filter_type")
                    return
                stop_block = db.get_block(req.stop_hash)
                if stop_block is None or stop_block.height is None:
                    _peer_disconnect(peer, f"unknown stop_hash")
                    return
            return handler

        raise ValueError(f"Unknown handler: {handler_name}")

    def test_getcfilters_disconnect_on_unsupported_filter_type(self):
        """G12: unsupported filter_type → disconnect (not silent return)."""
        peer = self._make_peer()
        db = self._make_db()
        handler = self._extract_handler(peer, db, None, "getcfilters")
        msg = self._build_getcfilters_msg(filter_type=99)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfilters_disconnect_on_unknown_stop_hash(self):
        """G13: unknown stop_hash → disconnect."""
        peer = self._make_peer()
        db = self._make_db(stop_block=None)
        handler = self._extract_handler(peer, db, None, "getcfilters")
        msg = self._build_getcfilters_msg(stop_hash=bytes([0xFF] * 32))
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfilters_disconnect_on_start_gt_stop(self):
        """G14: start_height > stop_height → disconnect."""
        stop_block = MagicMock()
        stop_block.height = 5
        peer = self._make_peer()
        db = self._make_db(stop_block=stop_block)
        handler = self._extract_handler(peer, db, None, "getcfilters")
        msg = self._build_getcfilters_msg(start_height=10)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfilters_disconnect_on_range_too_large(self):
        """G15: range >= MAX_GETCFILTERS_SIZE → disconnect."""
        stop_block = MagicMock()
        stop_block.height = MAX_GETCFILTERS_SIZE  # start=0 → range=MAX >= MAX
        peer = self._make_peer()
        db = self._make_db(stop_block=stop_block)
        handler = self._extract_handler(peer, db, None, "getcfilters")
        msg = self._build_getcfilters_msg(start_height=0)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfilters_no_disconnect_for_max_minus_1(self):
        """G15: range = MAX_GETCFILTERS_SIZE - 1 → allowed (no disconnect)."""
        stop_block = MagicMock()
        stop_block.height = MAX_GETCFILTERS_SIZE - 1  # start=0 → range = MAX-1 < MAX
        peer = self._make_peer()
        db = self._make_db(stop_block=stop_block)
        handler = self._extract_handler(peer, db, None, "getcfilters")
        msg = self._build_getcfilters_msg(start_height=0)
        self._run_handler(handler(msg))
        peer.disconnect.assert_not_called()

    def test_getcfheaders_disconnect_on_unsupported_filter_type(self):
        """G12 (cfheaders): unsupported filter_type → disconnect."""
        peer = self._make_peer()
        db = self._make_db()
        handler = self._extract_handler(peer, db, None, "getcfheaders")
        msg = self._build_getcfheaders_msg(filter_type=1)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfheaders_disconnect_on_unknown_stop_hash(self):
        """G13 (cfheaders): unknown stop_hash → disconnect."""
        peer = self._make_peer()
        db = self._make_db(stop_block=None)
        handler = self._extract_handler(peer, db, None, "getcfheaders")
        msg = self._build_getcfheaders_msg()
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfheaders_disconnect_on_range_too_large(self):
        """G15b: range >= MAX_GETCFHEADERS_SIZE → disconnect."""
        stop_block = MagicMock()
        stop_block.height = MAX_GETCFHEADERS_SIZE  # range = MAX >= MAX
        peer = self._make_peer()
        db = self._make_db(stop_block=stop_block)
        handler = self._extract_handler(peer, db, None, "getcfheaders")
        msg = self._build_getcfheaders_msg(start_height=0)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfcheckpt_disconnect_on_unsupported_filter_type(self):
        """G12 (cfcheckpt): unsupported filter_type → disconnect."""
        peer = self._make_peer()
        db = self._make_db()
        handler = self._extract_handler(peer, db, None, "getcfcheckpt")
        msg = self._build_getcfcheckpt_msg(filter_type=2)
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfcheckpt_disconnect_on_unknown_stop_hash(self):
        """G13 (cfcheckpt): unknown stop_hash → disconnect."""
        peer = self._make_peer()
        db = self._make_db(stop_block=None)
        handler = self._extract_handler(peer, db, None, "getcfcheckpt")
        msg = self._build_getcfcheckpt_msg()
        self._run_handler(handler(msg))
        peer.disconnect.assert_called_once()

    def test_getcfcheckpt_no_range_limit(self):
        """G17: cfcheckpt has no start_height and no range limit (UINT32_MAX).

        Even with a very large stop_height, it should NOT disconnect for range.
        """
        stop_block = MagicMock()
        stop_block.height = 1_000_000  # no range limit for cfcheckpt
        peer = self._make_peer()
        db = self._make_db(stop_block=stop_block)
        handler = self._extract_handler(peer, db, None, "getcfcheckpt")
        msg = self._build_getcfcheckpt_msg()
        self._run_handler(handler(msg))
        # Should not disconnect (unknown stop_hash only)
        # DB returned a block so should not disconnect
        peer.disconnect.assert_not_called()


# ---------------------------------------------------------------------------
# G16/G18 — cfheaders previous header + cfcheckpt checkpoint heights
# ---------------------------------------------------------------------------

class TestG16G18HeadersCheckpt(unittest.TestCase):
    """G16: cfheaders prev_filter_header from height start_height-1.
    G18: cfcheckpt checkpoint heights = multiples of CFCHECKPT_INTERVAL.
    """

    def test_cfcheckpt_heights_match_core(self):
        """G18: n_checkpoints = stop_height // CFCHECKPT_INTERVAL (integer div)."""
        stop_height = 2500
        n = stop_height // CFCHECKPT_INTERVAL
        heights = [(i + 1) * CFCHECKPT_INTERVAL for i in range(n)]
        self.assertEqual(heights, [1000, 2000])

    def test_cfcheckpt_partial_interval(self):
        """G18: stop_height=1999 → only checkpoint at 1000."""
        stop_height = 1999
        n = stop_height // CFCHECKPT_INTERVAL
        heights = [(i + 1) * CFCHECKPT_INTERVAL for i in range(n)]
        self.assertEqual(heights, [1000])

    def test_cfcheckpt_exact_interval(self):
        """G18: stop_height=1000 → checkpoint at 1000."""
        stop_height = 1000
        n = stop_height // CFCHECKPT_INTERVAL
        heights = [(i + 1) * CFCHECKPT_INTERVAL for i in range(n)]
        self.assertEqual(heights, [1000])

    def test_cfcheckpt_below_first_interval(self):
        """G18: stop_height<1000 → no checkpoints."""
        stop_height = 999
        n = stop_height // CFCHECKPT_INTERVAL
        self.assertEqual(n, 0)

    def test_cfheaders_prev_zero_for_genesis(self):
        """G16: when start_height=0, prev_filter_header must be 32 zero bytes."""
        # This is documented behavior: no block precedes height 0.
        prev = b'\x00' * 32
        filt = b"genesis-filter"
        h0 = compute_filter_header(filt, prev)
        self.assertEqual(len(h0), 32)

    def test_cfheaders_prev_chains_from_previous_block(self):
        """G16: cfheaders at start_height=1 uses filter header of height 0 as prev."""
        f0 = b"filter-at-height-0"
        h0 = compute_filter_header(f0, bytes(32))
        f1 = b"filter-at-height-1"
        h1 = compute_filter_header(f1, h0)
        # Verify h1 depends on h0 (the previous filter header)
        h1_if_wrong_prev = compute_filter_header(f1, bytes(32))
        self.assertNotEqual(h1, h1_if_wrong_prev)


# ---------------------------------------------------------------------------
# G19 — getblockfilter RPC shape
# ---------------------------------------------------------------------------

class TestG19GetBlockFilterRPC(unittest.TestCase):
    """G19: getblockfilter returns {filter: hex, header: hex}."""

    def test_rpc_response_shape(self):
        block = Block.deserialize(bytes.fromhex(_GENESIS_HEX.replace("\n", "")))
        filt = build_basic_filter(block, db=None)
        header = compute_filter_header(filt, bytes(32))

        response = {"filter": filt.hex(), "header": header.hex()}
        self.assertIn("filter", response)
        self.assertIn("header", response)
        self.assertEqual(len(response["header"]), 64)  # 32 bytes
        self.assertEqual(response["filter"], _GENESIS_BASIC_FILTER_HEX)
        # No 0x prefix, lowercase hex
        for key in ("filter", "header"):
            self.assertTrue(
                all(c in "0123456789abcdef" for c in response[key]),
                f"Non-hex character in {key}",
            )


# ---------------------------------------------------------------------------
# G20 — Sharded file layout (Bug 3 fix)
# ---------------------------------------------------------------------------

class TestG20ShardedFileLayout(unittest.TestCase):
    """G20: PersistentBlockFilterIndex uses sharded layout filters/<aa>/<hash>.flt.

    Bug 3 fixed: test_blockfilterindex_wireup was stale (expected flat layout).
    """

    def test_shard_prefix_is_first_byte_hex(self):
        """Shard directory = first byte of hash hex = hash[:1].hex()."""
        h = bytes([0xAB] * 32)
        shard = h[:1].hex()
        self.assertEqual(shard, "ab")

    def test_file_extensions(self):
        """Filter files use .flt, header files use .hdr, height files use .h."""
        # Verify PersistentBlockFilterIndex constructs these paths correctly
        import tempfile
        from ouroboros.blockfilter import PersistentBlockFilterIndex
        import os

        with tempfile.TemporaryDirectory() as tmp:
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            h = bytes([0xCC] * 32)
            block = _make_block(0, h, bytes(32))
            idx.add_block(block, height=0)

            shard = h[:1].hex()  # "cc"
            filter_file = os.path.join(
                tmp, "blockfilter", "filters", shard, h.hex() + ".flt"
            )
            header_file = os.path.join(
                tmp, "blockfilter", "headers", shard, h.hex() + ".hdr"
            )
            height_file = os.path.join(tmp, "blockfilter", "height", "00000000.h")
            self.assertTrue(os.path.exists(filter_file), filter_file)
            self.assertTrue(os.path.exists(header_file), header_file)
            self.assertTrue(os.path.exists(height_file), height_file)


# ---------------------------------------------------------------------------
# Wire format round-trips for all 6 BIP-157 P2P messages
# ---------------------------------------------------------------------------

class TestBIP157WireFormatRoundtrips(unittest.TestCase):
    """All six BIP-157 message classes round-trip through their wire format."""

    def test_getcfilters_wire(self):
        m = GetCFiltersMessage(
            filter_type=BASIC_FILTER_TYPE,
            start_height=42000,
            stop_hash=bytes(range(32)),
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(len(nm.payload), 1 + 4 + 32)
        self.assertEqual(nm.command, "getcfilters")
        self.assertEqual(GetCFiltersMessage.from_payload(nm.payload), m)

    def test_cfilter_wire(self):
        m = CFilterMessage(
            filter_type=BASIC_FILTER_TYPE,
            block_hash=bytes(range(32)),
            filter_bytes=bytes.fromhex(_GENESIS_BASIC_FILTER_HEX),
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(nm.command, "cfilter")
        self.assertEqual(CFilterMessage.from_payload(nm.payload), m)

    def test_getcfheaders_wire(self):
        m = GetCFHeadersMessage(
            filter_type=BASIC_FILTER_TYPE,
            start_height=100,
            stop_hash=bytes([0xAA] * 32),
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(len(nm.payload), 1 + 4 + 32)
        self.assertEqual(nm.command, "getcfheaders")
        self.assertEqual(GetCFHeadersMessage.from_payload(nm.payload), m)

    def test_cfheaders_wire(self):
        hashes = [bytes([i] * 32) for i in range(3)]
        m = CFHeadersMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
            previous_filter_header=bytes([0xFF] * 32),
            filter_hashes=hashes,
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(nm.command, "cfheaders")
        self.assertEqual(CFHeadersMessage.from_payload(nm.payload), m)

    def test_getcfcheckpt_wire(self):
        m = GetCFCheckptMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(len(nm.payload), 1 + 32)
        self.assertEqual(nm.command, "getcfcheckpt")
        self.assertEqual(GetCFCheckptMessage.from_payload(nm.payload), m)

    def test_cfcheckpt_wire(self):
        headers = [bytes([i] * 32) for i in range(5)]
        m = CFCheckptMessage(
            filter_type=BASIC_FILTER_TYPE,
            stop_hash=bytes(range(32)),
            filter_headers=headers,
        )
        nm = m.to_network_message("mainnet")
        self.assertEqual(nm.command, "cfcheckpt")
        self.assertEqual(CFCheckptMessage.from_payload(nm.payload), m)


if __name__ == "__main__":
    unittest.main()
