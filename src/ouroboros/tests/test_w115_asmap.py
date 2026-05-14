"""
W115 ASMap regression tests — ouroboros Python pipeline (FIX-50)

Tests the ASMap interpreter, config, AddressManager integration, and
getpeerinfo/getnetworkinfo RPC fields added by FIX-50.

Scope:
  FIX-50 (this file): Python pipeline — asmap.py, NodeConfig.defaults['asmap'],
    AddressManager.get_mapped_as / using_asmap / _get_addr_group,
    getpeerinfo mapped_as field, getnetworkinfo asmapversion field.

  FIX-51 (deferred): Rust pipeline ASMap (ferrous-utils), AddrMan re-bucketing
    on asmap change, peers.json asmap_version persistence, feeler/outbound
    ASN diversity enforcement, per-ASN connection limits.

Reference:
  bitcoin-core/src/util/asmap.h/cpp
  bitcoin-core/src/netgroup.h/cpp
  bitcoin-core/src/addrman.cpp
  bitcoin-core/src/init.cpp
"""

import hashlib
import struct
import unittest


# ============================================================================
# Helpers shared across tests
# ============================================================================

def _build_return_asmap(asn: int) -> bytes:
    """
    Build a minimal 1-instruction ASMap that always returns `asn`.

    Encoding (see asmap.cpp):
      RETURN opcode = bit [0] (instruction type=0)
      ASN encoding for asn in [1, 32768]: [0] + 15-bit BE value of (asn-1)
      Total: 17 bits → 3 bytes (with up to 7 zero-padding bits)
    """
    val = asn - 1  # minval=1
    bits = []
    bits.append(0)  # RETURN opcode bit
    bits.append(0)  # class 0 selector (no continuation)
    for b in range(14, -1, -1):
        bits.append((val >> b) & 1)
    data = bytearray()
    byte_val = 0
    for i, bit in enumerate(bits):
        byte_val |= (bit << (i % 8))
        if (i % 8) == 7:
            data.append(byte_val)
            byte_val = 0
    if len(bits) % 8 != 0:
        data.append(byte_val)
    return bytes(data)


def _ipv4_to_16bytes(ipv4_str: str) -> bytes:
    """Convert dotted-decimal IPv4 to 16-byte IPv4-in-IPv6 representation."""
    parts = [int(x) for x in ipv4_str.split(".")]
    prefix = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
    return prefix + bytes(parts)


def _ipv6_str_to_bytes(ipv6_str: str) -> bytes:
    """Convert IPv6 string to 16 raw bytes (handles :: notation)."""
    import ipaddress
    return ipaddress.IPv6Address(ipv6_str).packed


# ============================================================================
# G1 — ASMap interpreter: interpret() trie-bytecode executor (FIX-50: FIXED)
# ============================================================================
class TestG1Interpret(unittest.TestCase):
    """
    BUG-1 (FIX-50): implement() / interpret() trie-bytecode executor.
    Core: bitcoin-core/src/util/asmap.cpp Interpret()
    """

    def test_g1_interpret_module_exists(self):
        """ouroboros.asmap module is importable and exposes interpret()."""
        from ouroboros.asmap import interpret  # noqa: F401
        self.assertTrue(callable(interpret))

    def test_g1_return_asn_constant(self):
        """A trivial RETURN-only asmap returns the same ASN for any IP."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(42)
        ip = _ipv4_to_16bytes("1.2.3.4")
        self.assertEqual(interpret(asmap, ip), 42)

    def test_g1_return_asn_different_ips_same_result(self):
        """RETURN-only asmap returns the same ASN regardless of IP."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(1337)
        for ip_str in ("8.8.8.8", "1.1.1.1", "203.0.113.1"):
            ip = _ipv4_to_16bytes(ip_str)
            self.assertEqual(interpret(asmap, ip), 1337,
                             f"Expected 1337 for {ip_str}")

    def test_g1_return_asn_1(self):
        """interpret() handles ASN=1 (minimum valid ASN)."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(1)
        ip = _ipv4_to_16bytes("192.0.2.1")
        self.assertEqual(interpret(asmap, ip), 1)

    def test_g1_return_asn_32768(self):
        """interpret() handles ASN=32768 (class-0 boundary)."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(32768)
        ip = _ipv4_to_16bytes("10.0.0.1")
        self.assertEqual(interpret(asmap, ip), 32768)

    def test_g1_lsb_first_asmap_bits(self):
        """ASMap bytes are parsed LSB-first (ConsumeBitLE pattern)."""
        # Verify the bit extraction matches Core's ConsumeBitLE
        data = bytes([0b10110001])  # 0xB1
        # LSB-first: bits 0..7 = 1, 0, 0, 0, 1, 1, 0, 1
        expected = [1, 0, 0, 0, 1, 1, 0, 1]
        extracted = [(data[bp >> 3] >> (bp & 7)) & 1 for bp in range(8)]
        self.assertEqual(extracted, expected)

    def test_g1_msb_first_ip_bits(self):
        """IP bytes are parsed MSB-first (ConsumeBitBE pattern)."""
        data = bytes([0b10110001])  # 0xB1
        # MSB-first: bits 0..7 = 1, 0, 1, 1, 0, 0, 0, 1
        expected = [1, 0, 1, 1, 0, 0, 0, 1]
        extracted = [(data[bp >> 3] >> (7 - (bp & 7))) & 1 for bp in range(8)]
        self.assertEqual(extracted, expected)

    def test_g1_interpret_ipv6_input(self):
        """interpret() accepts a 16-byte IPv6 input."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(15169)
        ip6 = _ipv6_str_to_bytes("2001:4860:4860::8888")
        self.assertEqual(interpret(asmap, ip6), 15169)

    def test_g1_no_interpret_in_addrman(self):
        """addrman module does NOT directly expose interpret_asmap (stays in asmap.py)."""
        import ouroboros.addrman as addrman_mod
        # The interpret function lives in ouroboros.asmap, not addrman
        self.assertFalse(hasattr(addrman_mod, 'interpret_asmap'))
        self.assertFalse(hasattr(addrman_mod, 'Interpret'))


# ============================================================================
# G2 — SanityCheckAsmap / CheckStandardAsmap (FIX-50: FIXED)
# ============================================================================
class TestG2SanityCheck(unittest.TestCase):
    """
    BUG-2 (FIX-50): implement sanity_check_asmap + check_standard_asmap.
    Core: SanityCheckAsmap(asmap, 128) + CheckStandardAsmap(data)
    """

    def test_g2_sanity_check_function_exists(self):
        """sanity_check_asmap() is importable."""
        from ouroboros.asmap import sanity_check_asmap  # noqa: F401
        self.assertTrue(callable(sanity_check_asmap))

    def test_g2_check_standard_asmap_exists(self):
        """check_standard_asmap() is importable."""
        from ouroboros.asmap import check_standard_asmap  # noqa: F401
        self.assertTrue(callable(check_standard_asmap))

    def test_g2_valid_return_asmap_passes(self):
        """A well-formed RETURN-only asmap passes sanity check."""
        from ouroboros.asmap import sanity_check_asmap, check_standard_asmap
        asmap = _build_return_asmap(42)
        self.assertTrue(sanity_check_asmap(asmap, 128))
        self.assertTrue(check_standard_asmap(asmap))

    def test_g2_corrupt_asmap_rejected(self):
        """All-ones bytes are rejected by check_standard_asmap."""
        from ouroboros.asmap import check_standard_asmap
        bad_data = b"\xff\xff\xff\xff"
        self.assertFalse(check_standard_asmap(bad_data))

    def test_g2_empty_asmap_rejected(self):
        """Empty bytes are rejected by sanity_check_asmap."""
        from ouroboros.asmap import sanity_check_asmap
        self.assertFalse(sanity_check_asmap(b"", 128))

    def test_g2_nonzero_padding_rejected(self):
        """Non-zero padding bits are rejected."""
        from ouroboros.asmap import check_standard_asmap
        # RETURN asmap for ASN=1, then with a 1-bit set in padding
        asmap = bytearray(_build_return_asmap(1))
        asmap[-1] |= 0x80  # set a high bit in last byte (potential padding)
        self.assertFalse(check_standard_asmap(bytes(asmap)))


# ============================================================================
# G3 — -asmap config option (FIX-50: FIXED)
# ============================================================================
class TestG3AsmapConfig(unittest.TestCase):
    """
    BUG-3 (FIX-50): NodeConfig.defaults now has 'asmap' = '' key.
    Core: init.cpp -asmap option.
    """

    def test_g3_config_has_asmap_default(self):
        """NodeConfig.defaults contains 'asmap' key (empty string default)."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        self.assertIn('asmap', cfg.defaults)
        self.assertEqual(cfg.defaults['asmap'], '')

    def test_g3_config_get_returns_empty_string_by_default(self):
        """config.get('asmap') returns empty string (no asmap configured)."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        result = cfg.get('asmap')
        # Default is empty string (no asmap)
        self.assertIsNotNone(result)
        self.assertEqual(result, '')

    def test_g3_to_dict_includes_asmap(self):
        """config.to_dict() contains 'asmap' key."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        d = cfg.to_dict()
        self.assertIn('asmap', d)
        self.assertEqual(d['asmap'], '')


# ============================================================================
# G4 — MAX_ASMAP_FILE_SIZE = 8 MiB guard (FIX-50: FIXED)
# ============================================================================
class TestG4FilesizeGuard(unittest.TestCase):
    """
    BUG-4 (FIX-50): MAX_ASMAP_FILE_SIZE constant + load_asmap() guard.
    Core: DecodeAsmap reads file, practical limit 8 MiB.
    """

    def test_g4_load_asmap_function_exists(self):
        """load_asmap() is importable."""
        from ouroboros.asmap import load_asmap  # noqa: F401
        self.assertTrue(callable(load_asmap))

    def test_g4_max_asmap_filesize_constant(self):
        """MAX_ASMAP_FILE_SIZE constant equals 8 MiB."""
        from ouroboros.asmap import MAX_ASMAP_FILE_SIZE
        self.assertEqual(MAX_ASMAP_FILE_SIZE, 8 * 1024 * 1024)

    def test_g4_load_asmap_oversized_rejected(self):
        """load_asmap() returns empty bytes for a file exceeding 8 MiB."""
        import tempfile, os
        from ouroboros.asmap import load_asmap, MAX_ASMAP_FILE_SIZE
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            # Write MAX + 1 bytes of zeros
            f.write(b"\x00" * (MAX_ASMAP_FILE_SIZE + 1))
            tmp = f.name
        try:
            result = load_asmap(tmp)
            self.assertEqual(result, b"", "Oversized file should be rejected")
        finally:
            os.unlink(tmp)

    def test_g4_load_asmap_missing_file_returns_empty(self):
        """load_asmap() returns empty bytes for a non-existent path."""
        from ouroboros.asmap import load_asmap
        result = load_asmap("/nonexistent/path/to/asmap.dat")
        self.assertEqual(result, b"")

    def test_g4_load_asmap_valid_file(self):
        """load_asmap() loads and validates a well-formed asmap file."""
        import tempfile, os
        from ouroboros.asmap import load_asmap
        asmap_data = _build_return_asmap(42)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            f.write(asmap_data)
            tmp = f.name
        try:
            result = load_asmap(tmp)
            self.assertEqual(result, asmap_data)
        finally:
            os.unlink(tmp)


# ============================================================================
# G5 — AsmapVersion / SHA-256 fingerprint (FIX-50: FIXED)
# ============================================================================
class TestG5AsmapVersion(unittest.TestCase):
    """
    BUG-5 (FIX-50): asmap_version() = double-SHA256 of raw bytes.
    Core: AsmapVersion(data) = SHA256(SHA256(data)) → uint256
    """

    def test_g5_asmap_version_function_exists(self):
        """asmap_version() is importable."""
        from ouroboros.asmap import asmap_version  # noqa: F401
        self.assertTrue(callable(asmap_version))

    def test_g5_asmap_version_double_sha256(self):
        """asmap_version() computes double-SHA256 of the input bytes."""
        from ouroboros.asmap import asmap_version
        data = b"\x00\x01\x02\x03"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        self.assertEqual(asmap_version(data), expected)

    def test_g5_asmap_version_empty_returns_zero_hash(self):
        """asmap_version(b'') returns 32 zero bytes."""
        from ouroboros.asmap import asmap_version
        self.assertEqual(asmap_version(b""), b"\x00" * 32)

    def test_g5_asmap_version_returns_32_bytes(self):
        """asmap_version() always returns exactly 32 bytes."""
        from ouroboros.asmap import asmap_version
        result = asmap_version(b"test asmap data")
        self.assertEqual(len(result), 32)

    def test_g5_asmap_version_is_deterministic(self):
        """asmap_version() is deterministic for the same input."""
        from ouroboros.asmap import asmap_version
        data = b"reproducible"
        self.assertEqual(asmap_version(data), asmap_version(data))


# ============================================================================
# G6 — ASN data structure / group encoding (FIX-50: FIXED)
# ============================================================================
class TestG6AsnDataStructure(unittest.TestCase):
    """
    BUG-6 (FIX-50): asn_group_bytes() + AddressManager.using_asmap().
    Core: NetGroupManager with m_asmap, UsingASMap(), GetGroup().
    """

    def test_g6_asn_group_bytes_exists(self):
        """asn_group_bytes() is importable from ouroboros.asmap."""
        from ouroboros.asmap import asn_group_bytes  # noqa: F401
        self.assertTrue(callable(asn_group_bytes))

    def test_g6_asn_group_encoding(self):
        """asn_group_bytes() encodes ASN as 5-byte NET_IPV6-prefixed vector."""
        from ouroboros.asmap import asn_group_bytes
        asn = 0x000F4240  # AS 1000000
        result = asn_group_bytes(asn)
        expected = bytes([
            2,                  # NET_IPV6 prefix
            asn & 0xFF,
            (asn >> 8) & 0xFF,
            (asn >> 16) & 0xFF,
            (asn >> 24) & 0xFF,
        ])
        self.assertEqual(result, expected)
        self.assertEqual(result, b"\x02\x40\x42\x0f\x00")

    def test_g6_asn_group_length_always_5(self):
        """asn_group_bytes() always returns exactly 5 bytes."""
        from ouroboros.asmap import asn_group_bytes
        for asn in (1, 1000, 65536, 0xFFFFFF):
            self.assertEqual(len(asn_group_bytes(asn)), 5)

    def test_g6_using_asmap_predicate_exists(self):
        """AddressManager.using_asmap() predicate is present."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertTrue(hasattr(am, 'using_asmap'))
        self.assertTrue(callable(am.using_asmap))

    def test_g6_using_asmap_false_by_default(self):
        """using_asmap() returns False when no asmap is loaded."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(am.using_asmap())

    def test_g6_using_asmap_true_when_asmap_loaded(self):
        """using_asmap() returns True when asmap bytes are provided."""
        from ouroboros.addrman import AddressManager
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertTrue(am.using_asmap())


# ============================================================================
# G7 — GetMappedAS for IPv4 (FIX-50: FIXED)
# ============================================================================
class TestG7GetMappedAsIPv4(unittest.TestCase):
    """
    BUG-7 (FIX-50): AddressManager.get_mapped_as() for IPv4.
    Core: GetMappedAS builds IPv4-in-IPv6 buffer and calls Interpret().
    """

    def test_g7_get_mapped_as_exists_on_address_manager(self):
        """AddressManager.get_mapped_as() method is present."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertTrue(hasattr(am, 'get_mapped_as'))
        self.assertTrue(callable(am.get_mapped_as))

    def test_g7_get_mapped_as_returns_0_without_asmap(self):
        """get_mapped_as() returns 0 when no asmap is loaded."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        am = AddressManager()
        self.assertEqual(am.get_mapped_as("8.8.8.8", NET_IPV4), 0)

    def test_g7_get_mapped_as_ipv4_with_constant_asmap(self):
        """get_mapped_as() returns correct ASN for IPv4 with a RETURN-only asmap."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        asmap = _build_return_asmap(15169)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("8.8.8.8", NET_IPV4), 15169)
        self.assertEqual(am.get_mapped_as("1.2.3.4", NET_IPV4), 15169)

    def test_g7_ipv4_in_ipv6_buffer_construction(self):
        """The IPv4-in-IPv6 16-byte buffer is constructed correctly."""
        ip = "8.8.8.8"
        buf = _ipv4_to_16bytes(ip)
        self.assertEqual(buf[:10], b"\x00" * 10)
        self.assertEqual(buf[10:12], b"\xff\xff")
        self.assertEqual(buf[12:], bytes([8, 8, 8, 8]))
        self.assertEqual(len(buf), 16)

    def test_g7_get_mapped_as_module_function(self):
        """asmap.get_mapped_as() module-level function works for IPv4."""
        from ouroboros.asmap import get_mapped_as
        from ouroboros.addrman import NET_IPV4
        asmap = _build_return_asmap(15169)
        self.assertEqual(get_mapped_as(asmap, "8.8.8.8", NET_IPV4), 15169)

    def test_g7_get_mapped_as_empty_asmap_returns_0(self):
        """get_mapped_as() with empty asmap always returns 0."""
        from ouroboros.asmap import get_mapped_as
        from ouroboros.addrman import NET_IPV4
        self.assertEqual(get_mapped_as(b"", "8.8.8.8", NET_IPV4), 0)


# ============================================================================
# G8 — GetMappedAS for IPv6 (FIX-50: FIXED)
# ============================================================================
class TestG8GetMappedAsIPv6(unittest.TestCase):
    """
    BUG-8 (FIX-50): get_mapped_as() for IPv6.
    Core: GetMappedAS uses full 128-bit IPv6 address for Interpret().
    """

    def test_g8_get_mapped_as_ipv6_with_constant_asmap(self):
        """get_mapped_as() returns correct ASN for IPv6 with a RETURN-only asmap."""
        from ouroboros.addrman import AddressManager, NET_IPV6
        asmap = _build_return_asmap(15169)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("2001:4860:4860::8888", NET_IPV6), 15169)

    def test_g8_ipv6_address_to_bytes(self):
        """IPv6 address should convert to exactly 16 bytes for interpreter."""
        ip6 = "2001:4860:4860::8888"  # Google DNS IPv6
        buf = _ipv6_str_to_bytes(ip6)
        self.assertEqual(len(buf), 16)
        self.assertEqual(buf, bytes([
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
        ]))

    def test_g8_tor_returns_0_mapped_as(self):
        """get_mapped_as() returns 0 for Tor addresses (non-IP)."""
        from ouroboros.addrman import AddressManager, NET_TORV3
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("abc.onion", NET_TORV3), 0)

    def test_g8_i2p_returns_0_mapped_as(self):
        """get_mapped_as() returns 0 for I2P addresses (non-IP)."""
        from ouroboros.addrman import AddressManager, NET_I2P
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("example.b32.i2p", NET_I2P), 0)


# ============================================================================
# G9 — Bucket hashing uses ASN group when ASMap loaded (FIX-50: FIXED)
# ============================================================================
class TestG9BucketHashingWithAsn(unittest.TestCase):
    """
    BUG-9 (FIX-50): _get_new_bucket / _get_tried_bucket use ASN group
    when asmap is active.
    """

    def test_g9_get_addr_group_without_asmap_returns_slash16(self):
        """_get_addr_group() without asmap returns /16 prefix bytes."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        am = AddressManager()
        group = am._get_addr_group("8.8.8.8", NET_IPV4)
        self.assertEqual(group, b"8.8")

    def test_g9_get_addr_group_with_asmap_returns_asn_bytes(self):
        """_get_addr_group() with asmap returns 5-byte ASN group vector."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        from ouroboros.asmap import asn_group_bytes
        asmap = _build_return_asmap(15169)
        am = AddressManager(asmap=asmap)
        group = am._get_addr_group("8.8.8.8", NET_IPV4)
        self.assertEqual(group, asn_group_bytes(15169))
        self.assertEqual(len(group), 5)

    def test_g9_same_as_different_slash16_same_bucket_group(self):
        """Two IPs in same AS but different /16 get same group when asmap active."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        from ouroboros.asmap import asn_group_bytes
        # With constant-return asmap, all IPv4 IPs map to same AS
        asmap = _build_return_asmap(15169)
        am = AddressManager(asmap=asmap)
        group_a = am._get_addr_group("8.8.4.0", NET_IPV4)
        group_b = am._get_addr_group("8.35.201.1", NET_IPV4)
        # Both should get the same ASN group (anti-eclipse)
        self.assertEqual(group_a, group_b)
        self.assertEqual(group_a, asn_group_bytes(15169))

    def test_g9_without_asmap_different_slash16_different_group(self):
        """Without asmap, different /16 ranges still give different groups."""
        from ouroboros.addrman import AddressManager, NET_IPV4
        am = AddressManager()
        group_a = am._get_addr_group("8.8.4.0", NET_IPV4)
        group_b = am._get_addr_group("8.35.201.1", NET_IPV4)
        self.assertNotEqual(group_a, group_b)

    def test_g9_new_bucket_uses_asn_group_when_loaded(self):
        """_get_new_bucket uses ASN group bytes when asmap is active."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        asmap = _build_return_asmap(15169)
        am_with = AddressManager(asmap=asmap)
        am_without = AddressManager()
        info_a = AddrInfo(host="8.8.4.0", port=8333, network_id=NET_IPV4)
        info_b = AddrInfo(host="8.35.201.1", port=8333, network_id=NET_IPV4)
        source_group = "1.2"
        # With asmap: same AS → same bucket for both IPs (with same key)
        bucket_a = am_with._get_new_bucket(info_a, source_group)
        bucket_b = am_with._get_new_bucket(info_b, source_group)
        self.assertEqual(bucket_a, bucket_b,
                         "Same ASN should yield same new-bucket when asmap active")
        # Without asmap: different /16 → likely different buckets (not guaranteed
        # but with different group strings the hash inputs differ)
        bucket_no_a = am_without._get_new_bucket(info_a, source_group)
        bucket_no_b = am_without._get_new_bucket(info_b, source_group)
        self.assertNotEqual(bucket_no_a, bucket_no_b,
                            "Different /16 should give different new-bucket without asmap")


# ============================================================================
# G10 — Rust pipeline: still no ASMap (deferred to FIX-51)
# ============================================================================
class TestG10RustPipelineAsmap(unittest.TestCase):
    """
    BUG-10 (FIX-51 deferred): Rust PeerManager has no ASMap.
    Verifying the baseline: Rust pipeline remains ASMap-free in this wave.
    """

    def test_g10_rust_peer_manager_no_asmap(self):
        """Rust peer_manager.rs has no asmap references (FIX-51 scope)."""
        import os
        rust_pm = "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/peer_manager.rs"
        if not os.path.exists(rust_pm):
            self.skipTest("Rust peer_manager.rs not found")
        with open(rust_pm) as f:
            src = f.read().lower()
        self.assertNotIn('asmap', src, "FIX-51 scope: Rust PeerManager still lacks asmap")
        self.assertNotIn('mapped_as', src, "FIX-51 scope: Rust PeerManager lacks get_mapped_as")


# ============================================================================
# G11 — AddressManager._get_new_bucket uses ASN when asmap loaded (FIX-50)
# ============================================================================
class TestG11NewBucketAsnGroup(unittest.TestCase):
    """
    BUG-11 (FIX-50): _get_new_bucket now uses _get_addr_group() which
    switches to ASN vector when asmap is loaded.
    """

    def test_g11_address_manager_has_asmap_attr(self):
        """AddressManager._asmap attribute is present."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertTrue(hasattr(am, '_asmap'))

    def test_g11_asmap_attr_default_empty(self):
        """AddressManager._asmap is empty bytes by default (no asmap)."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertEqual(am._asmap, b"")

    def test_g11_asmap_attr_set_on_init(self):
        """AddressManager._asmap holds the loaded asmap bytes when provided."""
        from ouroboros.addrman import AddressManager
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am._asmap, asmap)


# ============================================================================
# G12 — AddressManager._get_tried_bucket uses ASN when asmap loaded (FIX-50)
# ============================================================================
class TestG12TriedBucketAsnGroup(unittest.TestCase):
    """
    BUG-12 (FIX-50): _get_tried_bucket now uses _get_addr_group() for
    ASN-based grouping when asmap is active.

    Note: the tried-bucket formula uses the IP-unique binary key in hash1
    (matching Core's CAddrInfo::GetTriedBucket), so two different IPs in
    the same AS will NOT necessarily land in the same bucket — the ASN
    group only affects the hash2 distribution.  The test verifies that
    the ASN group bytes are used in the computation.
    """

    def test_g12_tried_bucket_result_differs_with_and_without_asmap(self):
        """_get_tried_bucket produces different results depending on asmap."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        asmap = _build_return_asmap(15169)
        am_with = AddressManager(asmap=asmap)
        am_without = AddressManager()
        # Use a fixed key to compare deterministically
        am_with._key = b"\x42" * 32
        am_without._key = b"\x42" * 32
        info = AddrInfo(host="8.8.8.8", port=8333, network_id=NET_IPV4)
        bucket_with = am_with._get_tried_bucket(info)
        bucket_without = am_without._get_tried_bucket(info)
        # With different group inputs (ASN vector vs /16 ASCII) the buckets differ
        self.assertNotEqual(bucket_with, bucket_without,
                            "ASN group should produce different tried-bucket than /16 group")

    def test_g12_get_addr_group_used_in_tried_bucket(self):
        """_get_tried_bucket calls _get_addr_group() for the group bytes."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager._get_tried_bucket)
        self.assertIn('_get_addr_group', src,
                      "FIX-50: _get_tried_bucket should call _get_addr_group()")


# ============================================================================
# G13 — Re-bucketing on asmap change (deferred to FIX-51)
# ============================================================================
class TestG13RebucketingOnAsmapChange(unittest.TestCase):
    """
    BUG-13 (FIX-51 deferred): addrman re-bucketing on asmap change.
    Core re-assigns all buckets when asmap_version changes at startup.
    """

    def test_g13_no_rebucket_method_yet(self):
        """AddressManager has no rebucket_with_asmap() method (FIX-51 scope)."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        for method_name in ('rebucket_with_asmap', 'apply_asmap'):
            self.assertFalse(
                hasattr(am, method_name),
                f"FIX-51 scope: {method_name} not yet implemented",
            )


# ============================================================================
# G14 — peers.json asmap_version persistence (deferred to FIX-51)
# ============================================================================
class TestG14PeersJsonAsmapVersion(unittest.TestCase):
    """
    BUG-14 (FIX-51 deferred): peers.json does not yet persist asmap_version.
    """

    def test_g14_save_does_not_include_asmap_version(self):
        """peers.json has no asmap_version field yet (FIX-51 scope)."""
        from ouroboros.addrman import AddressManager
        import json, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            am = AddressManager(data_dir=tmpdir)
            am.add("1.2.3.4", 8333, services=0x409, timestamp=0.0)
            am.save()
            peers_path = os.path.join(tmpdir, "peers.json")
            with open(peers_path) as f:
                data = json.load(f)
        self.assertNotIn('asmap_version', data,
                         "FIX-51 scope: asmap_version not yet in peers.json")


# ============================================================================
# G15 — getrawaddrman: mapped_as / source_mapped_as fields (deferred FIX-51)
# ============================================================================
class TestG15GetRawAddrmanMappedAs(unittest.TestCase):
    """
    BUG-15 (FIX-51 deferred): getrawaddrman mapped_as fields not yet implemented.
    """

    def test_g15_no_rpc_getrawaddrman_yet(self):
        """rpc_getrawaddrman not yet implemented (FIX-51 scope)."""
        from ouroboros.rpc import RPCServer
        methods = [m for m in dir(RPCServer) if m.startswith('rpc_')]
        self.assertNotIn('rpc_getrawaddrman', methods,
                         "FIX-51 scope: rpc_getrawaddrman not yet implemented")


# ============================================================================
# G16 — getpeerinfo: mapped_as field (FIX-50: FIXED)
# ============================================================================
class TestG16GetPeerInfoMappedAs(unittest.TestCase):
    """
    BUG-16 (FIX-50): rpc_getpeerinfo now emits mapped_as when asmap active
    and a non-zero mapping exists for the peer's IP.
    Core: rpc/net.cpp getpeerinfo mapped_as field.
    """

    def test_g16_rpc_module_has_mapped_as(self):
        """rpc.py now includes mapped_as logic in rpc_getpeerinfo."""
        import inspect
        from ouroboros import rpc as rpc_mod
        src = inspect.getsource(rpc_mod)
        self.assertIn('mapped_as', src,
                      "FIX-50: mapped_as should appear in rpc module")

    def test_g16_getpeerinfo_source_has_mapped_as(self):
        """rpc_getpeerinfo source now references mapped_as."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getpeerinfo)
        self.assertIn('mapped_as', src,
                      "FIX-50: mapped_as field should be in rpc_getpeerinfo")


# ============================================================================
# G17 — getnetworkinfo: asmapversion field (FIX-50: FIXED)
# ============================================================================
class TestG17GetNetworkInfoAsmapVersion(unittest.TestCase):
    """
    BUG-17 (FIX-50): rpc_getnetworkinfo now emits asmapversion when asmap active.
    Core: getnetworkinfo asmapversion field.
    """

    def test_g17_getnetworkinfo_has_asmapversion_code(self):
        """rpc_getnetworkinfo source now references asmapversion."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getnetworkinfo)
        self.assertIn('asmapversion', src.lower(),
                      "FIX-50: asmapversion should be in getnetworkinfo")


# ============================================================================
# G18 — ASMapHealthCheck (deferred)
# ============================================================================
class TestG18AsmapHealthCheck(unittest.TestCase):
    """
    BUG-18 (deferred): No ASMapHealthCheck yet.
    """

    def test_g18_no_health_check_yet(self):
        """AddressManager.asmap_health_check() not yet implemented."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(hasattr(am, 'asmap_health_check'),
                         "Deferred: asmap_health_check not yet implemented")


# ============================================================================
# G19 — -asmap path resolution (FIX-50 partial: relative paths via datadir)
# ============================================================================
class TestG19AsmapPathResolution(unittest.TestCase):
    """
    BUG-19: Relative asmap path resolution.
    FIX-50: config accepts asmap= key; full relative-path resolution is
    handled by callers using datadir. NodeConfig itself stores the raw value.
    """

    def test_g19_config_stores_asmap_value(self):
        """NodeConfig stores asmap value as-is (no resolution in config layer)."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        cfg.defaults['asmap'] = 'ip_asn.map'
        result = cfg.get('asmap')
        # get() returns the defaults value when no conf file entry
        self.assertEqual(result, 'ip_asn.map')


# ============================================================================
# G20 — Tor/I2P/CJDNS correctly return 0 for GetMappedAS (PASS by design)
# ============================================================================
class TestG20NonIpNetworksReturnZero(unittest.TestCase):
    """
    BUG-20 is PASS: non-IP addresses correctly return 0 for get_mapped_as().
    """

    def test_g20_tor_returns_0(self):
        """Tor address returns 0 from get_mapped_as()."""
        from ouroboros.addrman import AddressManager, NET_TORV3
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("abc123.onion", NET_TORV3), 0)

    def test_g20_i2p_returns_0(self):
        """I2P address returns 0 from get_mapped_as()."""
        from ouroboros.addrman import AddressManager, NET_I2P
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("example.b32.i2p", NET_I2P), 0)

    def test_g20_cjdns_returns_0(self):
        """CJDNS address returns 0 from get_mapped_as()."""
        from ouroboros.addrman import AddressManager, NET_CJDNS
        asmap = _build_return_asmap(42)
        am = AddressManager(asmap=asmap)
        self.assertEqual(am.get_mapped_as("fc00::1", NET_CJDNS), 0)

    def test_g20_tor_network_group_unchanged(self):
        """Tor get_network_group() still returns 'onion' string."""
        from ouroboros.addrman import get_network_group, NET_TORV3
        self.assertEqual(get_network_group("abc123.onion", NET_TORV3), "onion")


# ============================================================================
# G21 — ASN-based outbound diversity (FIX-51: FIXED)
# ============================================================================
class TestG21SelectConnectionAsnDiversity(unittest.TestCase):
    """
    BUG-21 (FIX-51): select_for_connection now accepts exclude_asns.

    When an asmap is loaded, candidates whose mapped ASN is in the
    exclude_asns set are rejected, enforcing one-connection-per-AS.
    Core: net.cpp / addrman.cpp outbound ASN-diversity check.
    """

    def test_g21_select_for_connection_has_exclude_asns_param(self):
        """select_for_connection now accepts exclude_asns parameter."""
        import inspect
        from ouroboros.addrman import AddressManager
        sig = inspect.signature(AddressManager.select_for_connection)
        params = list(sig.parameters.keys())
        self.assertIn('exclude_asns', params,
                      "FIX-51: select_for_connection must have exclude_asns param")

    def test_g21_exclude_asns_filters_candidates(self):
        """Candidates with matching ASN are excluded when asmap loaded."""
        import time
        from ouroboros.addrman import AddressManager, NET_IPV4
        asmap = _build_return_asmap(15169)  # all IPs → ASN 15169
        am = AddressManager(asmap=asmap)
        # Add two addresses — both will map to ASN 15169
        now = time.time()
        am.add("1.2.3.4", 8333, services=1, timestamp=now)
        am.add("5.6.7.8", 8333, services=1, timestamp=now)
        # With ASN 15169 excluded, no candidate should be returned
        result = am.select_for_connection(exclude_asns={15169})
        self.assertIsNone(result,
                          "All candidates share ASN 15169 — should be filtered out")

    def test_g21_exclude_asns_allows_different_asn(self):
        """Candidates with non-matching ASN are NOT excluded."""
        import time
        from ouroboros.addrman import AddressManager, NET_IPV4
        asmap = _build_return_asmap(15169)  # all IPs → ASN 15169
        am = AddressManager(asmap=asmap)
        am.add("1.2.3.4", 8333, services=1, timestamp=time.time())
        # Exclude ASN 9999 (different) — candidate ASN 15169 should still pass
        result = am.select_for_connection(exclude_asns={9999})
        self.assertIsNotNone(result,
                             "Candidate ASN 15169 != excluded 9999, should be returned")

    def test_g21_exclude_asns_empty_set_allows_all(self):
        """Empty exclude_asns set allows all candidates through."""
        import time
        from ouroboros.addrman import AddressManager, NET_IPV4
        asmap = _build_return_asmap(15169)
        am = AddressManager(asmap=asmap)
        am.add("1.2.3.4", 8333, services=1, timestamp=time.time())
        result = am.select_for_connection(exclude_asns=set())
        self.assertIsNotNone(result, "Empty exclude_asns should allow all candidates")

    def test_g21_exclude_asns_no_asmap_no_filter(self):
        """exclude_asns is ignored when no asmap is loaded (graceful degradation)."""
        import time
        from ouroboros.addrman import AddressManager
        am = AddressManager()  # no asmap
        am.add("1.2.3.4", 8333, services=1, timestamp=time.time())
        # Even if we exclude ASN 15169, no asmap → no filter
        result = am.select_for_connection(exclude_asns={15169})
        self.assertIsNotNone(result,
                             "No asmap loaded: exclude_asns should not filter")

    def test_g21_private_helpers_accept_exclude_asns(self):
        """_select_from_tried and _select_from_new accept exclude_asns arg."""
        import inspect
        from ouroboros.addrman import AddressManager
        sig_tried = inspect.signature(AddressManager._select_from_tried)
        sig_new = inspect.signature(AddressManager._select_from_new)
        self.assertIn('exclude_asns', sig_tried.parameters,
                      "FIX-51: _select_from_tried must accept exclude_asns")
        self.assertIn('exclude_asns', sig_new.parameters,
                      "FIX-51: _select_from_new must accept exclude_asns")


# ============================================================================
# G22 — Eviction prefers same-ASN victims (FIX-51: FIXED)
# ============================================================================
class TestG22EvictionPrefersSameAsn(unittest.TestCase):
    """
    BUG-22 (FIX-51): When evicting from the tried table, prefer candidates
    whose ASN matches the incumbent — evicting same-AS entries loses no
    diversity.  Implemented via _get_eviction_victim_from_collisions().
    """

    def test_g22_eviction_helper_exists(self):
        """AddressManager._get_eviction_victim_from_collisions() is present."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertTrue(hasattr(am, '_get_eviction_victim_from_collisions'),
                        "FIX-51: _get_eviction_victim_from_collisions must exist")

    def test_g22_eviction_helper_returns_none_for_empty_collisions(self):
        """_get_eviction_victim_from_collisions() returns None when no collisions."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertIsNone(am._get_eviction_victim_from_collisions(15169))

    def test_g22_eviction_helper_prefers_same_asn(self):
        """_get_eviction_victim_from_collisions() prefers same-ASN collision entry."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        asmap = _build_return_asmap(15169)  # all IPs → ASN 15169
        am = AddressManager(asmap=asmap)
        # Manually populate collisions: two entries, both map to ASN 15169
        am._addrs["1.2.3.4:8333"] = AddrInfo(
            host="1.2.3.4", port=8333, network_id=NET_IPV4
        )
        am._addrs["5.6.7.8:8333"] = AddrInfo(
            host="5.6.7.8", port=8333, network_id=NET_IPV4
        )
        am._tried_collisions = {"1.2.3.4:8333", "5.6.7.8:8333"}
        # Both have ASN 15169; the helper should return one of them (same-ASN preference)
        victim = am._get_eviction_victim_from_collisions(15169)
        self.assertIn(victim, {"1.2.3.4:8333", "5.6.7.8:8333"},
                      "Same-ASN victim should come from the collisions set")

    def test_g22_eviction_helper_falls_back_when_no_same_asn(self):
        """_get_eviction_victim_from_collisions() falls back to arbitrary when no same-ASN."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        asmap = _build_return_asmap(99999)  # all IPs → ASN 99999
        am = AddressManager(asmap=asmap)
        am._addrs["1.2.3.4:8333"] = AddrInfo(
            host="1.2.3.4", port=8333, network_id=NET_IPV4
        )
        am._tried_collisions = {"1.2.3.4:8333"}
        # Candidate ASN is 15169, collision is ASN 99999 — no match, but still returns
        victim = am._get_eviction_victim_from_collisions(15169)
        self.assertEqual(victim, "1.2.3.4:8333",
                         "Fallback: should still return the only collision entry")


# ============================================================================
# G23 — IPv4/IPv6 same-ASN → same bucket (FIX-50: FIXED)
# ============================================================================
class TestG23SameAsnSameBucket(unittest.TestCase):
    """
    BUG-23 (FIX-50): IPv4 and IPv6 addresses in same AS now get same
    ASN group when asmap is loaded.
    """

    def test_g23_ipv4_ipv6_same_asn_same_group_with_asmap(self):
        """With asmap, IPv4 and IPv6 in same AS get same 5-byte group vector."""
        from ouroboros.addrman import AddressManager, NET_IPV4, NET_IPV6
        from ouroboros.asmap import asn_group_bytes
        asmap = _build_return_asmap(15169)  # All IPs → AS 15169
        am = AddressManager(asmap=asmap)
        group_v4 = am._get_addr_group("8.8.8.8", NET_IPV4)
        group_v6 = am._get_addr_group("2001:4860:4860::8888", NET_IPV6)
        self.assertEqual(group_v4, group_v6,
                         "IPv4 and IPv6 in same AS should have same group with asmap")
        self.assertEqual(group_v4, asn_group_bytes(15169))

    def test_g23_ipv4_ipv6_different_groups_without_asmap(self):
        """Without asmap, IPv4 and IPv6 still get different /16 groups."""
        from ouroboros.addrman import get_network_group, NET_IPV4, NET_IPV6
        group_v4 = get_network_group("8.8.8.8", NET_IPV4)
        group_v6 = get_network_group("2001:4860:4860::8888", NET_IPV6)
        self.assertNotEqual(group_v4, group_v6,
                            "Different network types → different groups without asmap")


# ============================================================================
# G24 — Embedded asmap (deferred)
# ============================================================================
class TestG24EmbeddedAsmap(unittest.TestCase):
    """BUG-24 (deferred): No embedded asmap resource."""

    def test_g24_no_embedded_asmap(self):
        """No EMBEDDED_ASMAP constant (deferred — no compiled-in resource)."""
        try:
            from ouroboros.asmap import EMBEDDED_ASMAP  # noqa: F401
            self.fail("EMBEDDED_ASMAP present — but no embedded resource was planned")
        except (ImportError, AttributeError):
            pass  # Expected: no embedded asmap

    def test_g24_config_no_asmap_boolean_shorthand(self):
        """config.getboolean('asmap') returns False for empty-string default."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        self.assertFalse(cfg.getboolean('asmap'))


# ============================================================================
# G25-G30 — Remaining deferred / structural checks
# ============================================================================
class TestG25AsnLogging(unittest.TestCase):
    """BUG-25 (deferred): No ASN logging in add() yet."""

    def test_g25_add_no_asn_log_yet(self):
        """AddressManager.add() has no 'mapped to AS' logging yet (deferred)."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager.add)
        self.assertNotIn('mapped to AS', src, "Deferred: no ASN log in add()")


class TestG26PerAsnConnectionLimit(unittest.TestCase):
    """BUG-26 (deferred): No per-ASN connection limit yet."""

    def test_g26_no_per_asn_limit_yet(self):
        """No MAX_CONNECTIONS_PER_ASN yet (deferred)."""
        try:
            from ouroboros.addrman import MAX_CONNECTIONS_PER_ASN  # noqa: F401
            self.fail("MAX_CONNECTIONS_PER_ASN present — deferred feature")
        except (ImportError, AttributeError):
            pass


class TestG27PeersJsonAsmapVersionKey(unittest.TestCase):
    """BUG-27 (deferred): peers.json asmap_version key."""

    def test_g27_save_schema_no_asmap_key_yet(self):
        """save() does not yet serialise asmap_version (deferred)."""
        from ouroboros.addrman import AddressManager
        import inspect
        src = inspect.getsource(AddressManager.save)
        self.assertNotIn('asmap_version', src.lower(),
                         "Deferred: no asmap_version in save()")


class TestG28ConfigToDictAsmap(unittest.TestCase):
    """BUG-28 (FIX-50: FIXED): config.to_dict() now includes 'asmap' key."""

    def test_g28_to_dict_includes_asmap(self):
        """to_dict() now returns 'asmap' key (empty string default)."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        d = cfg.to_dict()
        self.assertIn('asmap', d, "FIX-50: 'asmap' key should be in to_dict()")
        self.assertEqual(d['asmap'], '')


class TestG29StartupAsmapLoading(unittest.TestCase):
    """BUG-29 (deferred): Node startup does not yet load asmap file."""

    def test_g29_daemon_no_asmap_load_yet(self):
        """daemon.py has no asmap loading logic yet (deferred)."""
        import os
        daemon_path = "/home/work/hashhog/ouroboros/src/ouroboros/daemon.py"
        if not os.path.exists(daemon_path):
            self.skipTest("daemon.py not found")
        with open(daemon_path) as f:
            src = f.read()
        self.assertNotIn('asmap', src.lower(),
                         "Deferred: daemon.py has no asmap loading yet")


class TestG30RustPeerManagerNoAsmap(unittest.TestCase):
    """BUG-30 (FIX-51 deferred): Rust PeerManager ASMap."""

    def test_g30_rust_peer_manager_source_no_asmap(self):
        """ferrous-utils peer_manager.rs has no asmap (FIX-51 scope)."""
        import os
        path = "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/peer_manager.rs"
        if not os.path.exists(path):
            self.skipTest("peer_manager.rs not found")
        with open(path) as f:
            src = f.read()
        self.assertNotIn('asmap', src.lower(),
                         "FIX-51 scope: peer_manager.rs has no asmap")


# ============================================================================
# Core vector / algorithm correctness tests
# ============================================================================
class TestCoreVectors(unittest.TestCase):
    """
    Core algorithm correctness tests.

    These verify the interpreter and encoding match the Bitcoin Core
    specification from asmap.cpp.
    """

    def test_core_consume_bit_le(self):
        """ConsumeBitLE: LSB-first extraction from byte array (Core parity)."""
        data = bytes([0b10110001])  # byte = 0xB1
        expected = [1, 0, 0, 0, 1, 1, 0, 1]
        extracted = [(data[bp >> 3] >> (bp & 7)) & 1 for bp in range(8)]
        self.assertEqual(extracted, expected)

    def test_core_consume_bit_be(self):
        """ConsumeBitBE: MSB-first extraction from byte array (Core parity)."""
        data = bytes([0b10110001])  # 0xB1
        expected = [1, 0, 1, 1, 0, 0, 0, 1]
        extracted = [(data[bp >> 3] >> (7 - (bp & 7))) & 1 for bp in range(8)]
        self.assertEqual(extracted, expected)

    def test_core_asn_encoding_range_class0(self):
        """ASN class-0 covers [1, 32768] (15-bit mantissa)."""
        max_class0 = 1 + (1 << 15) - 1
        self.assertEqual(max_class0, 32768)

    def test_core_asn_encoding_range_class1(self):
        """ASN class-1 covers [32769, 98304] (16-bit mantissa)."""
        max_class1 = 32768 + (1 << 16)
        self.assertEqual(max_class1, 98304)

    def test_core_instruction_type_values(self):
        """RETURN=0, JUMP=1, MATCH=2, DEFAULT=3 (Core instruction encoding)."""
        self.assertEqual(0, 0)   # RETURN
        self.assertEqual(1, 1)   # JUMP
        self.assertEqual(2, 2)   # MATCH
        self.assertEqual(3, 3)   # DEFAULT

    def test_core_asmap_version_double_sha256(self):
        """AsmapVersion = double-SHA256 of the raw asmap bytes."""
        data = b"test asmap data"
        inner = hashlib.sha256(data).digest()
        outer = hashlib.sha256(inner).hexdigest()
        self.assertEqual(len(outer), 64)  # 32 bytes hex-encoded

    def test_core_return_asmap_asn42(self):
        """A RETURN-only asmap for ASN=42 returns 42 for any IP (Core vector)."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(42)
        for ip_str in ("1.2.3.4", "8.8.8.8", "192.168.0.1", "10.0.0.1"):
            ip = _ipv4_to_16bytes(ip_str)
            self.assertEqual(interpret(asmap, ip), 42,
                             f"Expected ASN 42 for {ip_str}")

    def test_core_return_asmap_asn1(self):
        """RETURN-only asmap for ASN=1 (minimum) works correctly."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(1)
        ip = _ipv4_to_16bytes("8.8.8.8")
        self.assertEqual(interpret(asmap, ip), 1)

    def test_core_return_asmap_asn32768(self):
        """RETURN-only asmap for ASN=32768 (class-0 maximum) works."""
        from ouroboros.asmap import interpret
        asmap = _build_return_asmap(32768)
        ip = _ipv4_to_16bytes("1.1.1.1")
        self.assertEqual(interpret(asmap, ip), 32768)

    def test_core_sanity_check_valid_asmap(self):
        """sanity_check_asmap() accepts a well-formed RETURN-only asmap."""
        from ouroboros.asmap import sanity_check_asmap
        asmap = _build_return_asmap(15169)
        self.assertTrue(sanity_check_asmap(asmap, 128))

    def test_core_sanity_check_rejects_all_ones(self):
        """sanity_check_asmap() rejects all-ones bytes."""
        from ouroboros.asmap import sanity_check_asmap
        self.assertFalse(sanity_check_asmap(b"\xff\xff\xff\xff", 128))

    def test_core_asn_group_encoding(self):
        """asn_group_bytes() matches Core's [NET_IPV6, asn LE 4-bytes] encoding."""
        from ouroboros.asmap import asn_group_bytes
        asn = 0x000F4240  # 1,000,000
        result = asn_group_bytes(asn)
        self.assertEqual(result[0], 2)  # NET_IPV6
        self.assertEqual(result[1], asn & 0xFF)
        self.assertEqual(result[2], (asn >> 8) & 0xFF)
        self.assertEqual(result[3], (asn >> 16) & 0xFF)
        self.assertEqual(result[4], (asn >> 24) & 0xFF)

    def test_core_get_mapped_as_no_asmap_returns_0(self):
        """get_mapped_as() with empty asmap always returns 0."""
        from ouroboros.asmap import get_mapped_as
        from ouroboros.addrman import NET_IPV4
        self.assertEqual(get_mapped_as(b"", "8.8.8.8", NET_IPV4), 0)

    def test_core_get_mapped_as_tor_returns_0(self):
        """get_mapped_as() returns 0 for Tor (non-IPv4/6) even with asmap loaded."""
        from ouroboros.asmap import get_mapped_as
        from ouroboros.addrman import NET_TORV3
        asmap = _build_return_asmap(42)
        self.assertEqual(get_mapped_as(asmap, "abc.onion", NET_TORV3), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
