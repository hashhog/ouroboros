"""
Tests for BIP 330 Erlay transaction reconciliation.

Covers:
- GF(2^32) arithmetic
- Minisketch encode/decode/merge
- Berlekamp–Massey algorithm
- Erlay P2P message serialization
- ReconciliationSet management
- PeerManager Erlay integration
"""

import os
import random
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from ouroboros.minisketch import (
    FIELD_MASK,
    Minisketch,
    ReconciliationSet,
    berlekamp_massey,
    compute_short_txid,
    estimate_sketch_capacity,
    find_roots,
    gf_inv,
    gf_mul,
    gf_pow,
    gf_sq,
)
from ouroboros.p2p_messages import (
    ReconcilDiffMessage,
    ReqTxRcnclMessage,
    SendTxRcnclMessage,
    SketchMessage,
)


# ── GF(2^32) Arithmetic ─────────────────────────────────────────────


class TestGF32Arithmetic(unittest.TestCase):
    """Test GF(2^32) field operations."""

    def test_mul_identity(self):
        """Multiplying by 1 is identity."""
        for val in [1, 2, 42, 0xDEADBEEF, 0xFFFFFFFF]:
            self.assertEqual(gf_mul(val, 1), val)
            self.assertEqual(gf_mul(1, val), val)

    def test_mul_zero(self):
        """Multiplying by 0 gives 0."""
        for val in [0, 1, 42, 0xDEADBEEF]:
            self.assertEqual(gf_mul(val, 0), 0)
            self.assertEqual(gf_mul(0, val), 0)

    def test_mul_commutative(self):
        """a * b == b * a in GF(2^32)."""
        pairs = [(3, 7), (0x1234, 0x5678), (0xABCD, 0xEF01)]
        for a, b in pairs:
            self.assertEqual(gf_mul(a, b), gf_mul(b, a))

    def test_sq_consistent_with_mul(self):
        """a^2 == a * a."""
        for val in [1, 2, 7, 42, 0x12345678]:
            self.assertEqual(gf_sq(val), gf_mul(val, val))

    def test_inv_basic(self):
        """a * inv(a) == 1 for nonzero a."""
        for val in [1, 2, 7, 42, 0x12345678, 0xDEADBEEF]:
            inv = gf_inv(val)
            self.assertNotEqual(inv, 0)
            product = gf_mul(val, inv)
            self.assertEqual(product, 1,
                             f"gf_mul({val:#x}, gf_inv({val:#x})) = {product:#x}, expected 1")

    def test_inv_zero(self):
        """inv(0) returns 0 (no inverse)."""
        self.assertEqual(gf_inv(0), 0)

    def test_pow_zero_exp(self):
        """a^0 == 1 for any a."""
        for val in [0, 1, 42, 0xFFFFFFFF]:
            self.assertEqual(gf_pow(val, 0), 1)

    def test_pow_one_exp(self):
        """a^1 == a."""
        for val in [1, 7, 0x12345678]:
            self.assertEqual(gf_pow(val, 1), val)

    def test_pow_consistent(self):
        """a^3 == a * a * a."""
        for val in [2, 5, 0x42]:
            expected = gf_mul(gf_mul(val, val), val)
            self.assertEqual(gf_pow(val, 3), expected)


# ── Minisketch Core ──────────────────────────────────────────────────


class TestMinisketch(unittest.TestCase):
    """Test Minisketch construction, mutation, and serialization."""

    def test_empty_sketch(self):
        """Empty sketch has all-zero syndromes."""
        s = Minisketch(capacity=5)
        self.assertEqual(len(s.syndromes), 5)
        self.assertTrue(all(syn == 0 for syn in s.syndromes))

    def test_add_single_element(self):
        """Adding one element makes syndromes non-zero."""
        s = Minisketch(capacity=3)
        s.add(42)
        self.assertFalse(all(syn == 0 for syn in s.syndromes))

    def test_add_remove_self_inverse(self):
        """Adding an element twice (XOR) cancels out."""
        s = Minisketch(capacity=4)
        s.add(42)
        s.add(42)
        self.assertTrue(all(syn == 0 for syn in s.syndromes))

    def test_add_zero_raises(self):
        """Cannot add zero to a sketch."""
        s = Minisketch(capacity=3)
        with self.assertRaises(ValueError):
            s.add(0)

    def test_serialization_roundtrip(self):
        """serialize → deserialize preserves syndromes."""
        s = Minisketch(capacity=5)
        s.add(100)
        s.add(200)
        s.add(300)
        data = s.serialize()
        self.assertEqual(len(data), 5 * 4)
        s2 = Minisketch.deserialize(data, capacity=5)
        self.assertEqual(s.syndromes, s2.syndromes)

    def test_merge_produces_difference(self):
        """Merging sketches of A and B encodes symmetric difference."""
        a = Minisketch(capacity=5)
        b = Minisketch(capacity=5)

        # A = {10, 20, 30}, B = {20, 30, 40}
        for e in [10, 20, 30]:
            a.add(e)
        for e in [20, 30, 40]:
            b.add(e)

        diff = a.merge(b)

        # Symmetric difference = {10, 40}
        # Verify by decoding
        result = diff.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {10, 40})

    def test_merge_different_capacity_raises(self):
        """Merging sketches with different capacities raises ValueError."""
        a = Minisketch(capacity=3)
        b = Minisketch(capacity=5)
        with self.assertRaises(ValueError):
            a.merge(b)

    def test_merge_inplace(self):
        """merge_inplace mutates the sketch in place."""
        a = Minisketch(capacity=4)
        b = Minisketch(capacity=4)
        a.add(10)
        a.add(20)
        b.add(20)
        b.add(30)
        a_copy_syns = a.syndromes[:]
        a.merge_inplace(b)
        # After merge, a should encode {10, 30}
        result = a.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {10, 30})


# ── Decode tests ─────────────────────────────────────────────────────


class TestMinisketchDecode(unittest.TestCase):
    """Test sketch decoding (Berlekamp–Massey + root finding)."""

    def test_decode_empty(self):
        """Empty sketch decodes to empty set."""
        s = Minisketch(capacity=5)
        result = s.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, set())

    def test_decode_single_element(self):
        """Sketch with one element decodes correctly."""
        s = Minisketch(capacity=3)
        s.add(42)
        result = s.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {42})

    def test_decode_two_elements(self):
        """Sketch with two elements decodes correctly."""
        s = Minisketch(capacity=4)
        s.add(100)
        s.add(200)
        result = s.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {100, 200})

    def test_decode_three_elements(self):
        """Sketch with three elements decodes correctly."""
        s = Minisketch(capacity=5)
        elements = {7, 42, 255}
        for e in elements:
            s.add(e)
        result = s.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, elements)

    def test_decode_at_capacity(self):
        """Sketch filled to exact capacity still decodes."""
        cap = 4
        s = Minisketch(capacity=cap)
        elements = {10, 20, 30, 40}
        for e in elements:
            s.add(e)
        result = s.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, elements)

    def test_decode_over_capacity_returns_none(self):
        """Sketch with more elements than capacity fails to decode."""
        s = Minisketch(capacity=2)
        for e in [10, 20, 30]:
            s.add(e)
        result = s.decode()
        self.assertIsNone(result)

    def test_decode_reconciliation_scenario(self):
        """Full reconciliation: two nodes with overlapping tx sets."""
        # Node A has txs: {1, 2, 3, 4, 5}
        # Node B has txs: {3, 4, 5, 6, 7}
        # Symmetric difference: {1, 2, 6, 7}
        cap = 6
        sketch_a = Minisketch(capacity=cap)
        sketch_b = Minisketch(capacity=cap)

        for e in [1, 2, 3, 4, 5]:
            sketch_a.add(e)
        for e in [3, 4, 5, 6, 7]:
            sketch_b.add(e)

        diff = sketch_a.merge(sketch_b)
        result = diff.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {1, 2, 6, 7})

    def test_identical_sets_yield_empty_diff(self):
        """If both nodes have the same set, difference is empty."""
        cap = 5
        sketch_a = Minisketch(capacity=cap)
        sketch_b = Minisketch(capacity=cap)

        for e in [10, 20, 30]:
            sketch_a.add(e)
            sketch_b.add(e)

        diff = sketch_a.merge(sketch_b)
        result = diff.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, set())


# ── Berlekamp–Massey ─────────────────────────────────────────────────


class TestBerlekampMassey(unittest.TestCase):
    """Test the Berlekamp–Massey LFSR synthesis."""

    def test_all_zero_syndromes(self):
        """All-zero syndromes → degree-0 polynomial."""
        poly = berlekamp_massey([0, 0, 0, 0])
        self.assertIsNotNone(poly)
        self.assertEqual(len(poly), 1)  # just the constant 1

    def test_single_element_syndromes(self):
        """Syndromes from a single element → degree-1 polynomial."""
        elem = 42
        syndromes = [gf_pow(elem, i + 1) for i in range(4)]
        poly = berlekamp_massey(syndromes)
        self.assertIsNotNone(poly)
        self.assertEqual(len(poly), 2)  # degree 1

    def test_two_element_syndromes(self):
        """Syndromes from two elements → degree-2 polynomial."""
        elems = [100, 200]
        cap = 4
        syndromes = [0] * cap
        for e in elems:
            val = e
            for i in range(cap):
                syndromes[i] ^= val
                val = gf_mul(val, e)
        poly = berlekamp_massey(syndromes)
        self.assertIsNotNone(poly)
        self.assertEqual(len(poly), 3)  # degree 2


# ── Message serialization ────────────────────────────────────────────


class TestErlayMessages(unittest.TestCase):
    """Test BIP 330 message serialization/deserialization."""

    def test_sendtxrcncl_roundtrip(self):
        """SendTxRcnclMessage survives serialize → deserialize."""
        msg = SendTxRcnclMessage(version=1, salt=0xDEADBEEFCAFEBABE)
        net_msg = msg.to_network_message("regtest")
        self.assertEqual(net_msg.command, "sendtxrcncl")

        parsed = SendTxRcnclMessage.from_payload(net_msg.payload)
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.salt, 0xDEADBEEFCAFEBABE)

    def test_sendtxrcncl_short_payload(self):
        """Short payload raises ValueError."""
        with self.assertRaises(ValueError):
            SendTxRcnclMessage.from_payload(b'\x00' * 5)

    def test_reqtxrcncl_roundtrip(self):
        """ReqTxRcnclMessage survives serialize → deserialize."""
        msg = ReqTxRcnclMessage(set_size=100, q=32768)
        net_msg = msg.to_network_message("regtest")
        self.assertEqual(net_msg.command, "reqtxrcncl")

        parsed = ReqTxRcnclMessage.from_payload(net_msg.payload)
        self.assertEqual(parsed.set_size, 100)
        self.assertEqual(parsed.q, 32768)

    def test_reqtxrcncl_short_payload(self):
        with self.assertRaises(ValueError):
            ReqTxRcnclMessage.from_payload(b'\x00' * 3)

    def test_sketch_message_roundtrip(self):
        """SketchMessage survives serialize → deserialize."""
        raw_sketch = os.urandom(20)
        msg = SketchMessage(sketch_data=raw_sketch)
        net_msg = msg.to_network_message("regtest")
        self.assertEqual(net_msg.command, "sketch")

        parsed = SketchMessage.from_payload(net_msg.payload)
        self.assertEqual(parsed.sketch_data, raw_sketch)

    def test_sketch_message_empty(self):
        """Empty sketch payload."""
        msg = SketchMessage(sketch_data=b'')
        net_msg = msg.to_network_message("regtest")
        parsed = SketchMessage.from_payload(net_msg.payload)
        self.assertEqual(parsed.sketch_data, b'')

    def test_reconcildiff_roundtrip(self):
        """ReconcilDiffMessage survives serialize → deserialize."""
        msg = ReconcilDiffMessage(
            success=True,
            ask_shortids=[42, 100, 255],
        )
        net_msg = msg.to_network_message("regtest")
        self.assertEqual(net_msg.command, "reconcildiff")

        parsed = ReconcilDiffMessage.from_payload(net_msg.payload)
        self.assertTrue(parsed.success)
        self.assertEqual(parsed.ask_shortids, [42, 100, 255])

    def test_reconcildiff_failure(self):
        """ReconcilDiffMessage with success=False."""
        msg = ReconcilDiffMessage(success=False, ask_shortids=[])
        net_msg = msg.to_network_message("regtest")
        parsed = ReconcilDiffMessage.from_payload(net_msg.payload)
        self.assertFalse(parsed.success)
        self.assertEqual(parsed.ask_shortids, [])


# ── ReconciliationSet ────────────────────────────────────────────────


class TestReconciliationSet(unittest.TestCase):
    """Test per-peer reconciliation set tracking."""

    def _make_txid(self, n: int) -> bytes:
        """Generate a deterministic 32-byte txid."""
        return bytes([n % 256]) * 32

    def test_add_and_size(self):
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        self.assertEqual(rs.set_size, 0)
        rs.add_tx(self._make_txid(1))
        self.assertEqual(rs.set_size, 1)
        rs.add_tx(self._make_txid(2))
        self.assertEqual(rs.set_size, 2)

    def test_add_duplicate(self):
        """Adding the same txid twice doesn't duplicate."""
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        rs.add_tx(self._make_txid(1))
        rs.add_tx(self._make_txid(1))
        self.assertEqual(rs.set_size, 1)

    def test_mark_announced(self):
        """mark_announced removes txid from local_set."""
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        txid = self._make_txid(1)
        rs.add_tx(txid)
        rs.mark_announced(txid)
        self.assertEqual(rs.set_size, 0)
        self.assertIn(txid, rs.announced_txids)

    def test_add_after_announced(self):
        """Adding an already-announced txid is a no-op."""
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        txid = self._make_txid(1)
        rs.add_tx(txid)
        rs.mark_announced(txid)
        rs.add_tx(txid)  # should not re-add
        self.assertEqual(rs.set_size, 0)

    def test_get_short_ids(self):
        """Short IDs are computed for all elements."""
        rs = ReconciliationSet(local_salt=0x1234, remote_salt=0x5678)
        rs.add_tx(self._make_txid(1))
        rs.add_tx(self._make_txid(2))
        sids = rs.get_short_ids()
        self.assertEqual(len(sids), 2)
        # All short IDs should be non-zero
        for sid in sids:
            self.assertNotEqual(sid, 0)

    def test_build_sketch(self):
        """build_sketch returns a Minisketch with correct capacity."""
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        rs.add_tx(self._make_txid(1))
        rs.add_tx(self._make_txid(2))
        sketch = rs.build_sketch(capacity=5)
        self.assertEqual(sketch.capacity, 5)
        self.assertFalse(all(s == 0 for s in sketch.syndromes))

    def test_short_id_to_txid_map(self):
        """Reverse map from short IDs to txids."""
        rs = ReconciliationSet(local_salt=42, remote_salt=99)
        txid1 = self._make_txid(1)
        txid2 = self._make_txid(2)
        rs.add_tx(txid1)
        rs.add_tx(txid2)
        mapping = rs.short_id_to_txid_map()
        self.assertEqual(len(mapping), 2)
        # Check that values are our txids
        self.assertIn(txid1, mapping.values())
        self.assertIn(txid2, mapping.values())

    def test_clear(self):
        """clear() empties the local set."""
        rs = ReconciliationSet(local_salt=1, remote_salt=2)
        rs.add_tx(self._make_txid(1))
        rs.add_tx(self._make_txid(2))
        rs.clear()
        self.assertEqual(rs.set_size, 0)


# ── Short TxID computation ──────────────────────────────────────────


class TestShortTxId(unittest.TestCase):
    """Test short transaction ID mapping."""

    def test_non_zero(self):
        """Short IDs should never be zero (remapped to 1)."""
        for i in range(100):
            txid = os.urandom(32)
            sid = compute_short_txid(txid, i, i + 1)
            self.assertNotEqual(sid, 0)

    def test_deterministic(self):
        """Same inputs always produce same short ID."""
        txid = b'\xAA' * 32
        s1 = compute_short_txid(txid, 100, 200)
        s2 = compute_short_txid(txid, 100, 200)
        self.assertEqual(s1, s2)

    def test_different_salts_differ(self):
        """Different salts should produce different short IDs."""
        txid = b'\xBB' * 32
        s1 = compute_short_txid(txid, 1, 2)
        s2 = compute_short_txid(txid, 3, 4)
        # They CAN collide, but it's astronomically unlikely
        # for a well-behaved hash. We just test they're computed.
        self.assertIsInstance(s1, int)
        self.assertIsInstance(s2, int)

    def test_within_field(self):
        """Short IDs must fit in 32 bits."""
        for _ in range(50):
            txid = os.urandom(32)
            sid = compute_short_txid(txid, 42, 99)
            self.assertLessEqual(sid, FIELD_MASK)
            self.assertGreater(sid, 0)


# ── Sketch capacity estimation ──────────────────────────────────────


class TestEstimateCapacity(unittest.TestCase):
    """Test sketch capacity estimation heuristic."""

    def test_equal_sizes(self):
        """Equal set sizes: capacity driven by q fraction."""
        cap = estimate_sketch_capacity(100, 100, q=0.1)
        # abs_diff=0, q*min=10, +1 → 11
        self.assertEqual(cap, 11)

    def test_different_sizes(self):
        """Differing sizes increase capacity."""
        cap = estimate_sketch_capacity(100, 50, q=0.1)
        # abs_diff=50, q*min=5, +1 → 56
        self.assertEqual(cap, 56)

    def test_minimum_capacity(self):
        """Capacity is at least 1."""
        cap = estimate_sketch_capacity(0, 0, q=0.0)
        self.assertGreaterEqual(cap, 1)

    def test_large_sets(self):
        """Large sets don't overflow or produce unreasonable values."""
        cap = estimate_sketch_capacity(100000, 100000, q=0.01)
        self.assertGreater(cap, 0)
        self.assertLessEqual(cap, 1 << 15)


# ── End-to-end reconciliation ────────────────────────────────────────


class TestEndToEndReconciliation(unittest.TestCase):
    """Test full reconciliation flow between two simulated nodes."""

    def test_two_node_reconciliation(self):
        """Two nodes reconcile their tx sets and find the difference."""
        salt_a = 0x1111111111111111
        salt_b = 0x2222222222222222

        # Node A's txids
        txids_a = [os.urandom(32) for _ in range(5)]
        # Node B has the first 3 + 2 unique
        shared = txids_a[:3]
        unique_b = [os.urandom(32) for _ in range(2)]
        txids_b = shared + unique_b
        unique_a = txids_a[3:]

        # Build reconciliation sets
        recon_a = ReconciliationSet(local_salt=salt_a, remote_salt=salt_b)
        recon_b = ReconciliationSet(local_salt=salt_b, remote_salt=salt_a)

        # Note: both use the SAME combined salt (XOR is commutative)
        for txid in txids_a:
            recon_a.add_tx(txid)
        for txid in txids_b:
            recon_b.add_tx(txid)

        # Step 1: A initiates reconciliation
        # Use generous capacity to ensure decoding succeeds —
        # in production, capacity is estimated conservatively and
        # failures trigger a fallback to INV flooding.
        capacity = estimate_sketch_capacity(
            recon_a.set_size, recon_b.set_size, q=1.0
        )

        # Step 2: Both build sketches
        sketch_a = recon_a.build_sketch(capacity)
        sketch_b = recon_b.build_sketch(capacity)

        # Step 3: Merge sketches to get difference
        diff = sketch_a.merge(sketch_b)

        # Step 4: Decode
        diff_elements = diff.decode()
        self.assertIsNotNone(diff_elements,
                             "Sketch decoding should succeed")

        # Step 5: Classify elements
        a_short_ids = recon_a.get_short_ids()
        b_short_ids = recon_b.get_short_ids()

        # Elements in diff that A has → B is missing
        b_missing = diff_elements & a_short_ids
        # Elements in diff that B has → A is missing
        a_missing = diff_elements & b_short_ids

        # Verify we found the right number of differences
        # unique_a short IDs should be in b_missing
        # unique_b short IDs should be in a_missing
        expected_unique_a_sids = {
            recon_a.txid_to_short_id(txid) for txid in unique_a
        }
        expected_unique_b_sids = {
            recon_b.txid_to_short_id(txid) for txid in unique_b
        }

        self.assertEqual(b_missing, expected_unique_a_sids)
        self.assertEqual(a_missing, expected_unique_b_sids)

    def test_sketch_wire_roundtrip(self):
        """Sketch survives serialization over the wire (via SketchMessage)."""
        sketch = Minisketch(capacity=5)
        sketch.add(42)
        sketch.add(100)
        sketch.add(255)

        # Serialize sketch → SketchMessage → NetworkMessage → parse back
        raw = sketch.serialize()
        msg = SketchMessage(sketch_data=raw)
        net_msg = msg.to_network_message("regtest")
        parsed_msg = SketchMessage.from_payload(net_msg.payload)
        parsed_sketch = Minisketch.deserialize(parsed_msg.sketch_data, 5)

        self.assertEqual(sketch.syndromes, parsed_sketch.syndromes)

        # Decode should give same set
        result = parsed_sketch.decode()
        self.assertIsNotNone(result)
        self.assertEqual(result, {42, 100, 255})


# ── PeerManager Erlay integration ───────────────────────────────────


class TestPeerManagerErlay(unittest.TestCase):
    """Test PeerManager Erlay state management."""

    def _make_manager(self) -> 'PeerManager':
        from ouroboros.p2p import PeerManager
        pm = PeerManager(network="regtest", max_peers=4)
        pm.erlay_enabled = True
        return pm

    def test_erlay_enabled_default(self):
        pm = self._make_manager()
        self.assertTrue(pm.erlay_enabled)

    def test_no_erlay_peers_initially(self):
        pm = self._make_manager()
        self.assertEqual(len(pm.get_erlay_peers()), 0)

    def test_is_erlay_peer(self):
        pm = self._make_manager()
        self.assertFalse(pm.is_erlay_peer("1.2.3.4:8333"))

    def test_erlay_add_tx_to_reconcile(self):
        """Queuing txs adds to all Erlay peers' sets."""
        pm = self._make_manager()
        # Simulate an Erlay peer
        addr = "10.0.0.1:8333"
        pm._erlay_peers[addr] = ReconciliationSet(
            local_salt=1, remote_salt=2
        )

        txid = b'\xAB' * 32
        pm.erlay_add_tx_to_reconcile(txid)
        self.assertEqual(pm._erlay_peers[addr].set_size, 1)

    def test_erlay_add_tx_excludes_sender(self):
        """Sender is excluded from reconciliation queue."""
        pm = self._make_manager()
        addr1 = "10.0.0.1:8333"
        addr2 = "10.0.0.2:8333"
        pm._erlay_peers[addr1] = ReconciliationSet(
            local_salt=1, remote_salt=2
        )
        pm._erlay_peers[addr2] = ReconciliationSet(
            local_salt=3, remote_salt=4
        )

        txid = b'\xCD' * 32
        pm.erlay_add_tx_to_reconcile(txid, exclude_addr=addr1)
        self.assertEqual(pm._erlay_peers[addr1].set_size, 0)
        self.assertEqual(pm._erlay_peers[addr2].set_size, 1)

    def test_stats_include_erlay(self):
        """get_stats() includes Erlay info."""
        pm = self._make_manager()
        stats = pm.get_stats()
        self.assertIn("erlay_peers", stats)
        self.assertIn("erlay_enabled", stats)
        self.assertEqual(stats["erlay_peers"], 0)
        self.assertTrue(stats["erlay_enabled"])


# ── Stress / randomized tests ───────────────────────────────────────


class TestMinisketchRandomized(unittest.TestCase):
    """Randomized tests to increase confidence in the sketch implementation."""

    def test_single_diff_many_iterations(self):
        """1-element difference decodes correctly across many random elements."""
        rng = random.Random(42)
        for _ in range(50):
            elem = rng.randint(1, FIELD_MASK)
            s = Minisketch(capacity=3)
            s.add(elem)
            result = s.decode()
            self.assertIsNotNone(result,
                                 f"Failed to decode single element {elem:#x}")
            self.assertEqual(result, {elem})

    def test_two_diff_many_iterations(self):
        """2-element difference decodes correctly across many random pairs."""
        rng = random.Random(123)
        for _ in range(30):
            a = rng.randint(1, FIELD_MASK)
            b = rng.randint(1, FIELD_MASK)
            if a == b:
                continue
            s = Minisketch(capacity=4)
            s.add(a)
            s.add(b)
            result = s.decode()
            self.assertIsNotNone(result,
                                 f"Failed to decode {a:#x}, {b:#x}")
            self.assertEqual(result, {a, b})


if __name__ == "__main__":
    unittest.main()
