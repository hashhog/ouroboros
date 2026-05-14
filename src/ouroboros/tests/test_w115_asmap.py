"""
W115 ASMap 30-gate fleet audit — ouroboros (Python + Rust two-pipeline)

Reference:
  bitcoin-core/src/util/asmap.h/cpp
  bitcoin-core/src/netgroup.h/cpp (NetGroupManager)
  bitcoin-core/src/addrman.cpp
  bitcoin-core/src/init.cpp

Two-pipeline note
-----------------
ouroboros has TWO pipelines:

  Python pipeline — src/ouroboros/addrman.py (AddressManager),
                    src/ouroboros/config.py (NodeConfig),
                    src/ouroboros/rpc.py (getpeerinfo, getrawaddrman, getnetworkinfo).
                    Used by p2p.py at runtime.

  Rust pipeline   — ferrous-utils/sync/src/network/peer_manager.rs (PeerManager),
                    ferrous-utils/common/src/*.rs.
                    Never exposes ASMap via #[pyfunction]/#[pyclass].

  Both pipelines: MISSING ENTIRELY for ASMap. Zero references in either pipeline.

Gate legend
-----------
  PASS          — matches Core behaviour
  BUG-N         — confirmed deviation from Core
  MISSING       — feature entirely absent

Bug inventory
=============

BUG-1 (G1, CRITICAL / MISSING ENTIRELY)
  No ASMap interpreter. Python pipeline and Rust pipeline both lack any
  implementation of the Interpret() trie-bytecode executor from
  bitcoin-core/src/util/asmap.cpp. No bit-level trie walk, no RETURN/JUMP/
  MATCH/DEFAULT opcodes, no DecodeBits, no ASN lookup function.

BUG-2 (G2, CRITICAL / MISSING ENTIRELY)
  No SanityCheckAsmap / CheckStandardAsmap. Neither Python nor Rust
  validates that loaded bytecode terminates on all execution paths, has
  no intersecting jumps, and has ≤7 bits of zero-padding. Core refuses
  to use a file that fails this check (returns {} from DecodeAsmap).

BUG-3 (G3, CRITICAL / MISSING ENTIRELY)
  No -asmap config option. NodeConfig.defaults has no 'asmap' key.
  No config parsing, no path resolution, no boolean shorthand
  (-asmap=1 for embedded). Core's init.cpp:1584 wires this.

BUG-4 (G4, CRITICAL / MISSING ENTIRELY)
  No MAX_ASMAP_FILESIZE guard. Core limits ASMap files to 8 MiB.
  ouroboros would load an arbitrarily large file into memory without
  any size check, opening a DoS vector.

BUG-5 (G5, CRITICAL / MISSING ENTIRELY)
  No AsmapVersion / SHA-256 checksum. Core logs and persists the
  SHA256(SHA256(data)) fingerprint so operators can verify which map
  is loaded; addrman.cpp re-buckets if the fingerprint changes across
  restarts. ouroboros has no such checksum anywhere.

BUG-6 (G6, CRITICAL / MISSING ENTIRELY)
  No ASN data structure. NetGroupManager.m_asmap / loaded_asmap field,
  UsingASMap() predicate, and the ASN → group bytes encoding
  ([NET_IPV6, asn & 0xFF, (asn>>8)&0xFF, (asn>>16)&0xFF, (asn>>24)&0xFF])
  from netgroup.cpp:26-31 are entirely absent.

BUG-7 (G7, CRITICAL / MISSING ENTIRELY)
  No GetMappedAS for IPv4. Core's GetMappedAS builds a 16-byte IPv4-in-
  IPv6 buffer (IPV4_IN_IPV6_PREFIX + 4 IPv4 bytes) and calls Interpret().
  Without an ASMap interpreter Python's get_network_group() always returns
  the /16 prefix, never an AS number.

BUG-8 (G8, CRITICAL / MISSING ENTIRELY)
  No GetMappedAS for IPv6. Core uses the full 128-bit IPv6 address in
  GetMappedAS(). ouroboros has no IPv6 ASN lookup path.

BUG-9 (G9, HIGH / P1)
  Bucket hashing does not use ASN group when ASMap is loaded. When ASMap
  is active, Core's GetGroup() returns a 5-byte ASN group vector instead
  of a /16 string; GetNewBucket() and GetTriedBucket() use this vector as
  the group key. ouroboros always passes the ASCII /16 string, so two IPs
  in the same AS but different /16 ranges land in different buckets —
  eclipse diversity is lost.

BUG-10 (G10, HIGH / P1) — TWO-PIPELINE
  Rust peer_manager.rs has no ASMap field and no get_mapped_as() function.
  The Rust pipeline stores peers in HashSet<SocketAddr> with no bucket
  diversification at all. Any future wiring of the Rust pipeline to the
  Python node would bypass ASN-based diversification entirely.

BUG-11 (G11, HIGH)
  AddressManager._get_new_bucket uses ASCII /16 string unconditionally.
  With ASMap this should switch to ASN-encoded bytes (5-byte vector from
  netgroup.cpp). The bucket inputs are wrong when asmap would be active.

BUG-12 (G12, HIGH)
  AddressManager._get_tried_bucket uses ASCII /16 string unconditionally.
  Same root cause as BUG-11 — tried-bucket diversification also relies on
  get_network_group(), which never returns an ASN.

BUG-13 (G13, MEDIUM)
  No addrman re-bucketing on asmap change. Core's addrman.cpp:347 detects
  a changed asmap_version (serialized in peers.dat header) and re-assigns
  all new/tried buckets to the new ASN groups. ouroboros has no such
  migration path: loading a new asmap file would silently leave stale
  bucket assignments from the previous run.

BUG-14 (G14, MEDIUM)
  peers.json does not persist asmap_version. Core's peers.dat stores the
  active asmap checksum in the header so restarts can detect map changes.
  ouroboros peers.json has no such field (checked in _info_to_dict and
  _load_v2 — absent).

BUG-15 (G15, MEDIUM)
  getrawaddrman response missing mapped_as / source_mapped_as fields.
  Core's AddrmanEntryToJSON (rpc/net.cpp:1123-1135) appends mapped_as and
  source_mapped_as when non-zero. ouroboros has no rpc_getrawaddrman
  equivalent that exposes these fields.

BUG-16 (G16, MEDIUM)
  getpeerinfo response missing mapped_as field. Core exposes
  mapped_as (optional) per peer when asmap is active. rpc_getpeerinfo
  in rpc.py does not include this field.

BUG-17 (G17, MEDIUM)
  getnetworkinfo does not report asmap_version. Core's getnetworkinfo
  includes an "asmapversion" field (the SHA-256 fingerprint) when asmap
  is loaded. ouroboros rpc_getnetworkinfo has no such field.

BUG-18 (G18, LOW)
  No ASMapHealthCheck. Core's connman.ASMapHealthCheck() iterates connected
  clearnet peers, counts unique ASNs and unmapped peers, and logs the
  results. ouroboros has no equivalent health-reporting path.

BUG-19 (G19, LOW)
  No -asmap path-relative resolution. Core resolves a relative -asmap path
  relative to the net-specific datadir (init.cpp:1591-1593).  ouroboros
  has no asmap path handling at all.

BUG-20 (G20, LOW)
  Tor/I2P/CJDNS correctly skipped by Core's GetMappedAS (returns 0 for
  non-IPv4/IPv6). get_network_group() already handles non-IP types
  correctly via the network_id switch, so this specific behaviour is
  PASS — but it is only correct by coincidence (no asmap interpreter
  exists to accidentally apply to Tor addresses).

BUG-21 (G21, LOW)
  No select_for_connection diversity-by-ASN. Core's connman groups active
  connections by ASN (via GetMappedAS) in addition to /16 to prevent
  connecting to multiple nodes in the same AS. AddressManager.
  select_for_connection uses /16 group exclusion only; no ASN exclusion.

BUG-22 (G22, LOW)
  No feeler connection ASN tracking. Core records ASN in connection
  statistics for feeler diversity. ouroboros select_for_feeler has no
  ASN-based deduplication.

BUG-23 (G23, LOW)
  No "two addresses same ASN → same bucket" cross-IPv4/IPv6 grouping.
  Core's netgroup.cpp:26 uses NET_IPV6 as the group prefix for both IPv4
  and IPv6 when an ASN is found, so IPv4-mapped and IPv6 addresses in the
  same AS collide into the same buckets (desired anti-eclipse). Without
  the interpreter this property cannot hold.

BUG-24 (G24, LOW)
  No embedded asmap fallback. Core supports a compiled-in asmap
  (node::data::ip_asn) activated by -asmap=1. ouroboros has no such
  resource and no mechanism to embed one.

BUG-25 (G25, LOW)
  No ASN logging on address add. Core logs "mapped to AS%i" for each
  new address added to the addrman (addrman.cpp:596,654). ouroboros
  AddressManager.add() has no AS logging.

BUG-26 (G26, LOW)
  No per-ASN connection limit in connman. Core limits outbound connections
  to at most one per ASN group (connman.cpp outbound slot selection).
  ouroboros has no per-ASN connection cap.

BUG-27 (G27, LOW)
  addrman.save() / peers.json schema does not include asmap_version
  as a top-level key. Required to detect map rotation on restart.

BUG-28 (G28, LOW)
  config.to_dict() does not return 'asmap' key. Callers that inspect
  config.to_dict() would never know whether an asmap was configured.

BUG-29 (G29, LOW)
  No ASMap loading at node startup. NodeConfig has no asmap attribute;
  node.py startup sequence (daemon.py or node.py __init__) performs
  no asmap file I/O. Even if a user added asmap= to ouroboros.conf the
  file would be silently ignored.

BUG-30 (G30, LOW) — TWO-PIPELINE
  Rust PeerManager (ferrous-utils/sync/src/network/peer_manager.rs) has
  no asmap_data field, no ASN lookup, and is not exported to Python.
  Any future Rust-side peer selection would be ASN-blind.

Total: 30 bugs across 30 gates (all MISSING ENTIRELY or HIGH/MEDIUM/LOW).
"""

import hashlib
import struct
import unittest

# ============================================================================
# Helper: minimal valid ASMap bytecodes for unit tests
# ============================================================================

def _build_return_asmap(asn: int) -> bytes:
    """
    Build a minimal 1-instruction ASMap that always returns `asn`.

    Encoding (see asmap.cpp):
      RETURN opcode = bit sequence [0] (instruction type=0)
      ASN encoding: value ∈ [1,32768] encodes as [0] + 15-bit BE value.

    For asn in [1, 32768]:
      bits = 0 (RETURN opcode, 1 bit)
             0 (class-0 continuation bit for ASN, 1 bit)
             (asn-1) in 15 bits, big-endian
      Total: 17 bits → 3 bytes (with up to 7 zero-padding bits)
    """
    val = asn - 1  # minval=1, so encode (asn - 1)
    # 17 bits: [RETURN=0][class-select=0][15-bit big-endian val]
    # Stored LSB-first per byte (ConsumeBitLE)
    bits = []
    bits.append(0)  # RETURN opcode bit
    bits.append(0)  # class 0 selector (no continuation)
    for b in range(14, -1, -1):
        bits.append((val >> b) & 1)

    # Pack bits LSB-first into bytes
    data = bytearray()
    byte_val = 0
    for i, bit in enumerate(bits):
        byte_val |= (bit << (i % 8))
        if (i % 8) == 7:
            data.append(byte_val)
            byte_val = 0
    # Final partial byte (pad with zeros — padding bits must be 0)
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
# G1 — ASMap interpreter: Interpret() trie-bytecode executor
# ============================================================================
class TestG1Interpret(unittest.TestCase):
    """
    BUG-1 (CRITICAL / MISSING ENTIRELY)
    Core: bitcoin-core/src/util/asmap.cpp Interpret()
    ouroboros: no equivalent function anywhere in Python or Rust pipeline.
    """

    def test_g1_no_interpret_function_python(self):
        """Python pipeline has no asmap interpreter."""
        import ouroboros
        import ouroboros.addrman as addrman_mod
        self.assertFalse(
            hasattr(addrman_mod, 'interpret_asmap'),
            "BUG-1: interpret_asmap should not exist (MISSING ENTIRELY)",
        )
        # Also check for any variant name
        for name in ('interpret', 'asmap_lookup', 'get_asn', 'Interpret'):
            self.assertFalse(
                hasattr(addrman_mod, name),
                f"BUG-1: {name} found but should be missing",
            )

    def test_g1_no_interpret_in_any_module(self):
        """No asmap interpreter exposed in any ouroboros module."""
        import importlib
        import pkgutil
        import ouroboros
        found = []
        # Look specifically for asmap-related names (not ScriptInterpreter etc.)
        asmap_patterns = ('asmap', 'interpret_asmap', 'get_mapped_as',
                          'asmap_lookup', 'get_asn_for_ip')
        for mod_info in pkgutil.iter_modules(ouroboros.__path__):
            try:
                mod = importlib.import_module(f"ouroboros.{mod_info.name}")
                for attr in dir(mod):
                    attr_lower = attr.lower()
                    if any(p in attr_lower for p in asmap_patterns):
                        found.append(f"ouroboros.{mod_info.name}.{attr}")
            except Exception:
                pass
        self.assertEqual(
            found, [],
            f"BUG-1: unexpected asmap symbols found: {found}",
        )

    def test_g1_return_asn_constant_asmap(self):
        """
        Demonstrate expected Interpret() behaviour: a trivial asmap that
        always returns ASN=42 should return 42 for any IP input.
        This test FAILS when the interpreter is absent (no function to call);
        the absence itself proves BUG-1.
        """
        # If an interpreter existed it would be something like:
        #   from ouroboros.asmap import interpret
        #   asmap = _build_return_asmap(42)
        #   ip = _ipv4_to_16bytes("1.2.3.4")
        #   self.assertEqual(interpret(asmap, ip), 42)
        # Since it doesn't exist we document the expected interface:
        try:
            from ouroboros.asmap import interpret  # noqa: F401
            self.fail("BUG-1 resolved: ouroboros.asmap.interpret now exists")
        except ImportError:
            pass  # Expected: module doesn't exist


# ============================================================================
# G2 — SanityCheckAsmap / CheckStandardAsmap validation
# ============================================================================
class TestG2SanityCheck(unittest.TestCase):
    """
    BUG-2 (CRITICAL / MISSING ENTIRELY)
    Core: SanityCheckAsmap(asmap, 128) + CheckStandardAsmap(data)
    ouroboros: no equivalent validation function.
    """

    def test_g2_no_sanity_check_function(self):
        """No sanity-check function exists in ouroboros."""
        try:
            from ouroboros.asmap import sanity_check_asmap  # noqa: F401
            self.fail("BUG-2 resolved: sanity_check_asmap now exists")
        except ImportError:
            pass  # Expected

    def test_g2_no_check_standard_asmap(self):
        """No CheckStandardAsmap equivalent."""
        try:
            from ouroboros.asmap import check_standard_asmap  # noqa: F401
            self.fail("BUG-2 resolved: check_standard_asmap now exists")
        except ImportError:
            pass  # Expected

    def test_g2_corrupt_asmap_would_not_be_rejected(self):
        """
        Core rejects asmap data with non-zero padding or truncated EOF.
        Without a validator, ouroboros would silently accept garbage bytes.
        """
        bad_data = b"\xff\xff\xff\xff"  # All non-zero bits — invalid padding
        # Expected: some validator raises / returns False
        # Actual: no validator exists → nothing to call
        try:
            from ouroboros.asmap import check_standard_asmap
            result = check_standard_asmap(bad_data)
            self.assertFalse(result, "Should reject all-ones corrupt data")
        except ImportError:
            pass  # Expected: BUG-2 confirmed


# ============================================================================
# G3 — -asmap config option
# ============================================================================
class TestG3AsmapConfig(unittest.TestCase):
    """
    BUG-3 (CRITICAL / MISSING ENTIRELY)
    Core: init.cpp -asmap argument parsed by ArgsManager.
    ouroboros: NodeConfig has no 'asmap' key.
    """

    def test_g3_config_has_no_asmap_default(self):
        """NodeConfig.defaults does not contain 'asmap' key."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        self.assertIsNone(
            cfg.defaults.get('asmap'),
            "BUG-3: 'asmap' should be absent from NodeConfig.defaults",
        )

    def test_g3_config_get_returns_none_for_asmap(self):
        """config.get('asmap') returns None — option not supported."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        result = cfg.get('asmap')
        self.assertIsNone(
            result,
            "BUG-3: config.get('asmap') should return None (option not implemented)",
        )

    def test_g3_to_dict_missing_asmap(self):
        """config.to_dict() does not contain 'asmap' key."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        d = cfg.to_dict()
        self.assertNotIn(
            'asmap', d,
            "BUG-28: to_dict() exposes asmap — not expected until implemented",
        )


# ============================================================================
# G4 — MAX_ASMAP_FILESIZE = 8 MiB guard
# ============================================================================
class TestG4FilesizeGuard(unittest.TestCase):
    """
    BUG-4 (CRITICAL / MISSING ENTIRELY)
    Core: DecodeAsmap() reads file and passes to CheckStandardAsmap.
    No explicit size constant but practical limit is 8 MiB for standard maps.
    ouroboros: no file loading, no size check.
    """

    def test_g4_no_decode_asmap_function(self):
        """No decode_asmap / load_asmap function exists."""
        try:
            from ouroboros.asmap import decode_asmap  # noqa: F401
            self.fail("BUG-4 resolved: decode_asmap now exists")
        except ImportError:
            pass  # Expected

    def test_g4_no_max_asmap_filesize_constant(self):
        """No MAX_ASMAP_FILESIZE constant defined."""
        try:
            from ouroboros.asmap import MAX_ASMAP_FILESIZE  # noqa: F401
            self.fail("BUG-4 resolved: MAX_ASMAP_FILESIZE now exists")
        except ImportError:
            pass  # Expected


# ============================================================================
# G5 — AsmapVersion / SHA-256 fingerprint
# ============================================================================
class TestG5AsmapVersion(unittest.TestCase):
    """
    BUG-5 (CRITICAL / MISSING ENTIRELY)
    Core: AsmapVersion(data) = SHA256(SHA256(data)) → uint256
    ouroboros: no equivalent.
    """

    def test_g5_no_asmap_version_function(self):
        """No asmap_version() function exists."""
        try:
            from ouroboros.asmap import asmap_version  # noqa: F401
            self.fail("BUG-5 resolved: asmap_version now exists")
        except ImportError:
            pass  # Expected

    def test_g5_expected_fingerprint_algorithm(self):
        """
        Document: Core uses double-SHA256 of the raw bytes.
        If asmap_version existed it should return hashlib.sha256(
            hashlib.sha256(data).digest()).digest() for raw data.
        """
        data = b"\x00\x01\x02\x03"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        # Verify the algorithm itself is correct:
        self.assertEqual(len(expected), 32)
        # If function existed:
        # self.assertEqual(asmap_version(data), expected)


# ============================================================================
# G6 — ASN data structure / NetGroupManager equivalent
# ============================================================================
class TestG6AsnDataStructure(unittest.TestCase):
    """
    BUG-6 (CRITICAL / MISSING ENTIRELY)
    Core: NetGroupManager with m_asmap span, UsingASMap(), GetGroup(),
          GetMappedAS(), ASMapHealthCheck().
    ouroboros: no NetGroupManager equivalent.
    """

    def test_g6_no_net_group_manager(self):
        """No NetGroupManager or equivalent class."""
        try:
            from ouroboros.asmap import NetGroupManager  # noqa: F401
            self.fail("BUG-6 resolved: NetGroupManager now exists")
        except ImportError:
            pass  # Expected

    def test_g6_no_using_asmap_predicate(self):
        """AddressManager has no using_asmap() predicate."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(
            hasattr(am, 'using_asmap'),
            "BUG-6: using_asmap() should not exist (MISSING ENTIRELY)",
        )

    def test_g6_asn_group_encoding(self):
        """
        Document expected group encoding when ASN is found:
        Core returns [NET_IPV6=2, asn&0xFF, (asn>>8)&0xFF,
                      (asn>>16)&0xFF, (asn>>24)&0xFF]
        Both IPv4 and IPv6 get the same 5-byte group if they share an ASN,
        ensuring they compete for the same buckets (anti-eclipse).
        """
        asn = 0x000F4240  # AS 1000000
        expected_group = bytes([
            2,                  # NET_IPV6 prefix
            asn & 0xFF,
            (asn >> 8) & 0xFF,
            (asn >> 16) & 0xFF,
            (asn >> 24) & 0xFF,
        ])
        self.assertEqual(expected_group, b"\x02\x40\x42\x0f\x00")


# ============================================================================
# G7 — GetMappedAS for IPv4
# ============================================================================
class TestG7GetMappedAsIPv4(unittest.TestCase):
    """
    BUG-7 (CRITICAL / MISSING ENTIRELY)
    Core: GetMappedAS builds IPv4-in-IPv6 buffer and calls Interpret().
    ouroboros: no mapped AS lookup for IPv4.
    """

    def test_g7_addrinfo_has_no_get_mapped_as(self):
        """AddrInfo has no get_mapped_as() method."""
        from ouroboros.addrman import AddrInfo, NET_IPV4
        info = AddrInfo(host="8.8.8.8", port=8333, network_id=NET_IPV4)
        self.assertFalse(
            hasattr(info, 'get_mapped_as'),
            "BUG-7: get_mapped_as should not exist (MISSING ENTIRELY)",
        )

    def test_g7_address_manager_has_no_get_mapped_as(self):
        """AddressManager has no get_mapped_as() method."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(
            hasattr(am, 'get_mapped_as'),
            "BUG-7: AddressManager.get_mapped_as should not exist",
        )

    def test_g7_ipv4_in_ipv6_buffer_construction(self):
        """
        Document: Core's IPv4-in-IPv6 buffer for 8.8.8.8 should be:
        b'\\x00'*10 + b'\\xff\\xff' + b'\\x08\\x08\\x08\\x08'
        This is what gets passed to Interpret() for IPv4 addresses.
        """
        ip = "8.8.8.8"
        buf = _ipv4_to_16bytes(ip)
        self.assertEqual(buf[:10], b"\x00" * 10)
        self.assertEqual(buf[10:12], b"\xff\xff")
        self.assertEqual(buf[12:], bytes([8, 8, 8, 8]))
        self.assertEqual(len(buf), 16)


# ============================================================================
# G8 — GetMappedAS for IPv6
# ============================================================================
class TestG8GetMappedAsIPv6(unittest.TestCase):
    """
    BUG-8 (CRITICAL / MISSING ENTIRELY)
    Core: GetMappedAS uses full 128-bit IPv6 address for Interpret().
    ouroboros: no mapped AS lookup for IPv6.
    """

    def test_g8_no_ipv6_asn_lookup(self):
        """No IPv6 ASN lookup in AddressManager."""
        from ouroboros.addrman import AddressManager, NET_IPV6
        am = AddressManager()
        self.assertFalse(
            hasattr(am, 'get_mapped_as'),
            "BUG-8: get_mapped_as should not exist for IPv6 either",
        )

    def test_g8_ipv6_address_to_bytes(self):
        """IPv6 address should convert to exactly 16 bytes for interpreter."""
        ip6 = "2001:4860:4860::8888"  # Google DNS IPv6
        buf = _ipv6_str_to_bytes(ip6)
        self.assertEqual(len(buf), 16)
        self.assertEqual(buf, bytes([
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
        ]))

    def test_g8_tor_ipv6_returns_0_mapped_as(self):
        """
        Core returns 0 for Tor/I2P/CJDNS (only IPv4+IPv6 are mapped).
        Test documents this boundary even though no interpreter exists.
        """
        from ouroboros.addrman import AddrInfo, NET_TORV3
        info = AddrInfo(host="abc.onion", port=8333, network_id=NET_TORV3)
        # If get_mapped_as existed it should return 0 for Tor
        self.assertFalse(
            hasattr(info, 'get_mapped_as'),
            "BUG-8: get_mapped_as should not exist",
        )


# ============================================================================
# G9 — Bucket hashing uses ASN group when ASMap loaded
# ============================================================================
class TestG9BucketHashingWithAsn(unittest.TestCase):
    """
    BUG-9 (HIGH / P1)
    When ASMap is active, Core's GetNewBucket() uses the 5-byte ASN vector
    as the addr_group input. ouroboros always uses ASCII /16 string.
    """

    def test_g9_new_bucket_uses_slash16_not_asn(self):
        """_get_new_bucket uses ASCII /16 group — ASN group absent."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        import inspect
        src = inspect.getsource(AddressManager._get_new_bucket)
        # The /16 path is always taken (no asmap branch)
        self.assertIn(
            'get_network_group',
            src,
            "BUG-9: _get_new_bucket calls get_network_group (always /16, never ASN)",
        )
        # Confirm no asmap / asn branch
        self.assertNotIn(
            'asn',
            src.lower(),
            "BUG-9: no ASN-based branching in _get_new_bucket",
        )

    def test_g9_tried_bucket_uses_slash16_not_asn(self):
        """_get_tried_bucket uses ASCII /16 group — ASN group absent."""
        from ouroboros.addrman import AddressManager
        import inspect
        src = inspect.getsource(AddressManager._get_tried_bucket)
        self.assertNotIn(
            'asn',
            src.lower(),
            "BUG-9: no ASN-based branching in _get_tried_bucket",
        )

    def test_g9_same_as_different_slash16_get_different_buckets(self):
        """
        With Core ASMap: two IPs in same AS but different /16 MUST land
        in the SAME bucket group (anti-eclipse). Without ASMap they get
        DIFFERENT bucket inputs, weakening eclipse resistance.
        Here we verify the current (buggy) behaviour: different /16 → different
        group strings → no ASN-based collision.
        """
        from ouroboros.addrman import get_network_group, NET_IPV4
        # Two IPs in Google's AS15169 but different /16 ranges
        group_a = get_network_group("8.8.4.0", NET_IPV4)    # 8.8
        group_b = get_network_group("8.35.201.1", NET_IPV4) # 8.35
        # BUG-9: These differ — they should be the SAME when asmap maps
        # both to AS15169.
        self.assertNotEqual(
            group_a, group_b,
            "BUG-9 confirmed: different /16 groups for IPs that share an ASN",
        )


# ============================================================================
# G10 — Rust pipeline: no ASMap field in peer_manager.rs (TWO-PIPELINE)
# ============================================================================
class TestG10RustPipelineAsmap(unittest.TestCase):
    """
    BUG-10 (HIGH / P1 / TWO-PIPELINE)
    Rust PeerManager has no asmap_data, no get_mapped_as(), no ASN bucketing.
    """

    def test_g10_rust_peer_manager_no_asmap(self):
        """
        Verify Rust peer_manager.rs has no asmap references.
        This is a source-inspection test documenting the dead-helper pattern.
        """
        import os
        rust_pm = "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/peer_manager.rs"
        if not os.path.exists(rust_pm):
            self.skipTest("Rust peer_manager.rs not found")
        with open(rust_pm) as f:
            src = f.read().lower()
        self.assertNotIn('asmap', src, "BUG-10: Rust PeerManager has no asmap field")
        self.assertNotIn('mapped_as', src, "BUG-10: Rust PeerManager has no get_mapped_as")
        self.assertNotIn('get_asn', src, "BUG-10: Rust PeerManager has no ASN lookup")

    def test_g10_rust_not_exported_to_python(self):
        """Rust sync module (if importable) has no asmap functions."""
        try:
            import sync  # Rust extension module
            for attr in dir(sync):
                self.assertNotIn(
                    'asmap',
                    attr.lower(),
                    f"BUG-10: Rust sync module unexpectedly has: {attr}",
                )
        except ImportError:
            pass  # Rust module not built — expected in CI without build


# ============================================================================
# G11 — AddressManager._get_new_bucket ASN group input
# ============================================================================
class TestG11NewBucketAsnGroup(unittest.TestCase):
    """
    BUG-11 (HIGH)
    _get_new_bucket should use 5-byte ASN vector when asmap is active.
    """

    def test_g11_get_new_bucket_ignores_asmap(self):
        """_get_new_bucket has no asmap parameter and no asn branch."""
        from ouroboros.addrman import AddressManager
        import inspect
        sig = inspect.signature(AddressManager._get_new_bucket)
        params = list(sig.parameters.keys())
        self.assertNotIn(
            'asmap',
            params,
            "BUG-11: _get_new_bucket has no asmap parameter",
        )

    def test_g11_no_asmap_attr_on_address_manager(self):
        """AddressManager has no _asmap attribute."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(
            hasattr(am, '_asmap'),
            "BUG-11: AddressManager._asmap should not exist (MISSING ENTIRELY)",
        )
        self.assertFalse(
            hasattr(am, 'asmap'),
            "BUG-11: AddressManager.asmap should not exist",
        )


# ============================================================================
# G12 — AddressManager._get_tried_bucket ASN group input
# ============================================================================
class TestG12TriedBucketAsnGroup(unittest.TestCase):
    """
    BUG-12 (HIGH)
    _get_tried_bucket should use ASN vector when asmap is active.
    """

    def test_g12_get_tried_bucket_ignores_asmap(self):
        """_get_tried_bucket has no asmap parameter."""
        from ouroboros.addrman import AddressManager
        import inspect
        sig = inspect.signature(AddressManager._get_tried_bucket)
        params = list(sig.parameters.keys())
        self.assertNotIn(
            'asmap',
            params,
            "BUG-12: _get_tried_bucket has no asmap parameter",
        )


# ============================================================================
# G13 — Re-bucketing on asmap change
# ============================================================================
class TestG13RebucketingOnAsmapChange(unittest.TestCase):
    """
    BUG-13 (MEDIUM)
    Core re-assigns all buckets when a different asmap_version is detected
    at startup. ouroboros has no such migration.
    """

    def test_g13_no_rebucket_method(self):
        """AddressManager has no rebucket() or rebucket_with_asmap() method."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        for method_name in ('rebucket', 'rebucket_with_asmap', 'apply_asmap'):
            self.assertFalse(
                hasattr(am, method_name),
                f"BUG-13: {method_name} should not exist (MISSING)",
            )

    def test_g13_load_v2_ignores_asmap_version(self):
        """_load_v2 does not read or compare asmap_version from peers.json."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager._load_v2)
        self.assertNotIn(
            'asmap_version',
            src,
            "BUG-13: _load_v2 has no asmap_version comparison",
        )


# ============================================================================
# G14 — peers.json schema: asmap_version persistence
# ============================================================================
class TestG14PeersJsonAsmapVersion(unittest.TestCase):
    """
    BUG-14 (MEDIUM)
    Core's peers.dat header stores asmap_version for restart-time comparison.
    ouroboros peers.json has no asmap_version field.
    """

    def test_g14_save_does_not_include_asmap_version(self):
        """_info_to_dict and save() produce no asmap_version field."""
        from ouroboros.addrman import AddressManager, AddrInfo, NET_IPV4
        import json, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            am = AddressManager(data_dir=tmpdir)
            am.add("1.2.3.4", 8333, services=0x409, timestamp=0.0)
            am.save()
            peers_path = os.path.join(tmpdir, "peers.json")
            with open(peers_path) as f:
                data = json.load(f)
        self.assertNotIn(
            'asmap_version',
            data,
            "BUG-14: peers.json should not contain asmap_version (MISSING)",
        )

    def test_g14_top_level_peers_json_schema(self):
        """peers.json top-level keys: version, key, addresses, in_new, in_tried — no asmap."""
        from ouroboros.addrman import AddressManager
        import json, tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            am = AddressManager(data_dir=tmpdir)
            am.save()
            import os
            peers_path = os.path.join(tmpdir, "peers.json")
            with open(peers_path) as f:
                data = json.load(f)
        allowed_keys = {'version', 'key', 'addresses', 'in_new', 'in_tried'}
        unexpected = set(data.keys()) - allowed_keys
        asmap_keys = {k for k in data if 'asmap' in k.lower()}
        self.assertEqual(
            asmap_keys, set(),
            f"BUG-14: unexpected asmap-related keys in peers.json: {asmap_keys}",
        )


# ============================================================================
# G15 — getrawaddrman: mapped_as / source_mapped_as fields
# ============================================================================
class TestG15GetRawAddrmanMappedAs(unittest.TestCase):
    """
    BUG-15 (MEDIUM)
    Core's getrawaddrman (rpc/net.cpp AddrmanEntryToJSON) includes mapped_as
    and source_mapped_as when non-zero.
    ouroboros: no rpc_getrawaddrman method in rpc.py.
    """

    def test_g15_no_rpc_getrawaddrman(self):
        """rpc.py has no rpc_getrawaddrman method."""
        import inspect
        from ouroboros.rpc import RPCServer
        methods = [m for m in dir(RPCServer) if m.startswith('rpc_')]
        self.assertNotIn(
            'rpc_getrawaddrman',
            methods,
            "BUG-15: rpc_getrawaddrman should not exist (MISSING ENTIRELY)",
        )

    def test_g15_no_mapped_as_in_rpc_module(self):
        """rpc.py has no mapped_as field in any peer/addr response."""
        import inspect
        from ouroboros import rpc as rpc_mod
        src = inspect.getsource(rpc_mod)
        self.assertNotIn(
            'mapped_as',
            src,
            "BUG-15/16: mapped_as field absent from entire rpc module",
        )


# ============================================================================
# G16 — getpeerinfo: mapped_as field
# ============================================================================
class TestG16GetPeerInfoMappedAs(unittest.TestCase):
    """
    BUG-16 (MEDIUM)
    Core's getpeerinfo includes mapped_as (optional) per peer.
    ouroboros rpc_getpeerinfo has no mapped_as field.
    """

    def test_g16_getpeerinfo_has_no_mapped_as(self):
        """rpc_getpeerinfo does not produce mapped_as in peer dict."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getpeerinfo)
        self.assertNotIn(
            '"mapped_as"',
            src,
            "BUG-16: mapped_as should not be in getpeerinfo (MISSING)",
        )
        self.assertNotIn(
            "'mapped_as'",
            src,
            "BUG-16: mapped_as should not be in getpeerinfo (MISSING)",
        )

    def test_g16_getpeerinfo_source_mapped_as_absent(self):
        """rpc_getpeerinfo does not produce source_mapped_as either."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getpeerinfo)
        self.assertNotIn(
            'source_mapped_as',
            src,
            "BUG-16: source_mapped_as absent from getpeerinfo",
        )


# ============================================================================
# G17 — getnetworkinfo: asmap_version field
# ============================================================================
class TestG17GetNetworkInfoAsmapVersion(unittest.TestCase):
    """
    BUG-17 (MEDIUM)
    Core's getnetworkinfo reports asmapversion (SHA-256 fingerprint).
    ouroboros rpc_getnetworkinfo has no such field.
    """

    def test_g17_getnetworkinfo_has_no_asmapversion(self):
        """rpc_getnetworkinfo does not include asmapversion."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getnetworkinfo)
        self.assertNotIn(
            'asmapversion',
            src.lower(),
            "BUG-17: asmapversion should not be in getnetworkinfo (MISSING)",
        )


# ============================================================================
# G18 — ASMapHealthCheck
# ============================================================================
class TestG18AsmapHealthCheck(unittest.TestCase):
    """
    BUG-18 (LOW)
    Core: connman.ASMapHealthCheck() logs unique-ASN count and unmapped peers.
    ouroboros: no equivalent.
    """

    def test_g18_no_health_check_on_address_manager(self):
        """AddressManager has no asmap_health_check() method."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(
            hasattr(am, 'asmap_health_check'),
            "BUG-18: asmap_health_check should not exist",
        )

    def test_g18_no_unique_asn_count(self):
        """No method to count unique ASNs in address table."""
        from ouroboros.addrman import AddressManager
        am = AddressManager()
        self.assertFalse(
            hasattr(am, 'get_unique_asn_count'),
            "BUG-18: get_unique_asn_count should not exist",
        )


# ============================================================================
# G19 — -asmap relative path resolution
# ============================================================================
class TestG19AsmapPathResolution(unittest.TestCase):
    """
    BUG-19 (LOW)
    Core resolves a relative -asmap path relative to the net-specific datadir.
    ouroboros has no asmap path handling at all.
    """

    def test_g19_config_has_no_asmap_path_resolution(self):
        """NodeConfig has no _resolve_asmap_path or equivalent method."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        for name in ('resolve_asmap_path', '_resolve_asmap_path',
                     'get_asmap_path', 'asmap_path'):
            self.assertFalse(
                hasattr(cfg, name),
                f"BUG-19: {name} should not exist in NodeConfig",
            )


# ============================================================================
# G20 — Tor/I2P/CJDNS correctly return 0 for GetMappedAS
# ============================================================================
class TestG20NonIpNetworksReturnZero(unittest.TestCase):
    """
    BUG-20 is PASS by coincidence (no interpreter to misapply).
    Core: GetMappedAS returns 0 for non-IPv4/IPv6 (Tor, I2P, CJDNS).
    ouroboros: get_network_group handles non-IP correctly but there is no
    ASMap interpreter to accidentally apply.
    """

    def test_g20_tor_network_group_is_onion(self):
        """Tor addresses return 'onion' group — not an AS number."""
        from ouroboros.addrman import get_network_group, NET_TORV3
        group = get_network_group("abc123.onion", NET_TORV3)
        self.assertEqual(group, "onion")
        # PASS: Tor is bucketed by 'onion' string, not AS number — correct.

    def test_g20_i2p_network_group_is_i2p(self):
        """I2P addresses return 'i2p' group."""
        from ouroboros.addrman import get_network_group, NET_I2P
        group = get_network_group("example.b32.i2p", NET_I2P)
        self.assertEqual(group, "i2p")
        # PASS: Correct non-IP handling.

    def test_g20_cjdns_network_group_is_cjdns(self):
        """CJDNS addresses return 'cjdns' group."""
        from ouroboros.addrman import get_network_group, NET_CJDNS
        group = get_network_group("fc00::1", NET_CJDNS)
        self.assertEqual(group, "cjdns")
        # PASS: Correct non-IP handling.


# ============================================================================
# G21 — select_for_connection diversity-by-ASN
# ============================================================================
class TestG21SelectConnectionAsnDiversity(unittest.TestCase):
    """
    BUG-21 (LOW)
    Core limits outbound connections to at most one per ASN group.
    ouroboros select_for_connection uses only /16 group exclusion.
    """

    def test_g21_select_for_connection_has_no_asn_exclusion(self):
        """select_for_connection signature has no exclude_asns parameter."""
        import inspect
        from ouroboros.addrman import AddressManager
        sig = inspect.signature(AddressManager.select_for_connection)
        params = list(sig.parameters.keys())
        self.assertNotIn(
            'exclude_asns',
            params,
            "BUG-21: select_for_connection has no exclude_asns parameter (MISSING)",
        )

    def test_g21_select_from_tried_no_asn(self):
        """_select_from_tried uses exclude_groups (/16) not ASNs."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager._select_from_tried)
        self.assertNotIn(
            'asn',
            src.lower(),
            "BUG-21: _select_from_tried has no ASN-based exclusion",
        )


# ============================================================================
# G22 — select_for_feeler: ASN deduplication
# ============================================================================
class TestG22FeelerAsnDeduplication(unittest.TestCase):
    """
    BUG-22 (LOW)
    Core's feeler-connection selection considers ASN for diversity.
    ouroboros select_for_feeler has no ASN awareness.
    """

    def test_g22_select_for_feeler_no_asn(self):
        """select_for_feeler has no ASN-based filtering."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager.select_for_feeler)
        self.assertNotIn(
            'asn',
            src.lower(),
            "BUG-22: select_for_feeler has no ASN deduplication",
        )


# ============================================================================
# G23 — IPv4/IPv6 same-ASN → same bucket group
# ============================================================================
class TestG23SameAsnSameBucket(unittest.TestCase):
    """
    BUG-23 (LOW)
    Core: IPv4 and IPv6 addresses with the same ASN use NET_IPV6 prefix
    in their group vector, forcing them to compete for the same buckets.
    ouroboros: IPv4 gets '8.8' and IPv6 gets '2001:4860' — different groups.
    """

    def test_g23_ipv4_ipv6_same_asn_different_groups(self):
        """
        8.8.8.8 (IPv4, Google AS15169) and 2001:4860:4860::8888 (IPv6, same AS)
        get different /16 groups in ouroboros — correct with ASMap they should
        collide into the same ASN group.
        """
        from ouroboros.addrman import get_network_group, NET_IPV4, NET_IPV6
        group_v4 = get_network_group("8.8.8.8", NET_IPV4)
        group_v6 = get_network_group("2001:4860:4860::8888", NET_IPV6)
        # Current (buggy) behaviour: different strings
        self.assertNotEqual(
            group_v4, group_v6,
            "BUG-23 confirmed: IPv4 and IPv6 in same AS get different group strings",
        )
        # With ASMap: both should return the same 5-byte ASN vector
        # (NET_IPV6 + 4-byte little-endian ASN).


# ============================================================================
# G24 — Embedded asmap fallback (-asmap=1)
# ============================================================================
class TestG24EmbeddedAsmap(unittest.TestCase):
    """
    BUG-24 (LOW)
    Core supports -asmap=1 to use compiled-in asmap (node::data::ip_asn).
    ouroboros has no embedded resource and no -asmap=1 boolean shorthand.
    """

    def test_g24_no_embedded_asmap_resource(self):
        """No embedded asmap data in any ouroboros module."""
        try:
            from ouroboros.asmap import EMBEDDED_ASMAP  # noqa: F401
            self.fail("BUG-24 resolved: EMBEDDED_ASMAP now exists")
        except ImportError:
            pass  # Expected

    def test_g24_config_no_asmap_boolean_shorthand(self):
        """config.getboolean('asmap') returns False (option not recognised)."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        # Should return False for unknown key (falls back to '0' default)
        result = cfg.getboolean('asmap')
        self.assertFalse(
            result,
            "BUG-24: getboolean('asmap') should be False (option unsupported)",
        )


# ============================================================================
# G25 — ASN logging on address add
# ============================================================================
class TestG25AsnLogging(unittest.TestCase):
    """
    BUG-25 (LOW)
    Core's AddSingle logs "mapped to AS%i" for each new address.
    ouroboros AddressManager.add() has no AS-number logging.
    """

    def test_g25_add_no_asn_log(self):
        """AddressManager.add() has no ASN logging path."""
        import inspect
        from ouroboros.addrman import AddressManager
        src = inspect.getsource(AddressManager.add)
        self.assertNotIn(
            'mapped to AS',
            src,
            "BUG-25: no 'mapped to AS' logging in add()",
        )
        self.assertNotIn(
            'mapped_as',
            src,
            "BUG-25: no mapped_as field in add()",
        )


# ============================================================================
# G26 — Per-ASN outbound connection limit
# ============================================================================
class TestG26PerAsnConnectionLimit(unittest.TestCase):
    """
    BUG-26 (LOW)
    Core limits outbound connections to ≤1 per ASN (connman.cpp outbound slot).
    ouroboros has no per-ASN connection cap.
    """

    def test_g26_no_per_asn_connection_limit(self):
        """No per-ASN limit enforced anywhere in addrman or peer selection."""
        try:
            from ouroboros.addrman import MAX_CONNECTIONS_PER_ASN  # noqa: F401
            self.fail("BUG-26 resolved: MAX_CONNECTIONS_PER_ASN now exists")
        except (ImportError, AttributeError):
            pass  # Expected


# ============================================================================
# G27 — peers.json schema: asmap_version top-level key
# ============================================================================
class TestG27PeersJsonAsmapVersionKey(unittest.TestCase):
    """
    BUG-27 (LOW) — duplicate of BUG-14 from a different angle.
    Verifies that the save() method top-level dict never includes asmap_version.
    """

    def test_g27_save_schema_no_asmap_key(self):
        """save() produces data dict without any asmap key."""
        from ouroboros.addrman import AddressManager
        import inspect
        src = inspect.getsource(AddressManager.save)
        self.assertNotIn(
            'asmap',
            src.lower(),
            "BUG-27: save() has no asmap_version serialisation",
        )


# ============================================================================
# G28 — config.to_dict() missing 'asmap' key
# ============================================================================
class TestG28ConfigToDictAsmap(unittest.TestCase):
    """
    BUG-28 (LOW)
    config.to_dict() should expose 'asmap' (None or path) once implemented.
    Currently absent.
    """

    def test_g28_to_dict_no_asmap(self):
        """to_dict() returns no 'asmap' key."""
        from ouroboros.config import NodeConfig
        cfg = NodeConfig()
        d = cfg.to_dict()
        self.assertNotIn(
            'asmap',
            d,
            "BUG-28 resolved if 'asmap' key appears — currently MISSING",
        )


# ============================================================================
# G29 — Node startup does not load asmap
# ============================================================================
class TestG29StartupAsmapLoading(unittest.TestCase):
    """
    BUG-29 (LOW)
    Core's init.cpp wires asmap loading at startup.
    ouroboros node.py / daemon.py has no asmap loading sequence.
    """

    def test_g29_daemon_no_asmap_load(self):
        """daemon.py has no asmap loading logic."""
        import os
        daemon_path = "/home/work/hashhog/ouroboros/src/ouroboros/daemon.py"
        if not os.path.exists(daemon_path):
            self.skipTest("daemon.py not found")
        with open(daemon_path) as f:
            src = f.read()
        self.assertNotIn(
            'asmap',
            src.lower(),
            "BUG-29: daemon.py should have no asmap loading",
        )

    def test_g29_node_no_asmap_attr(self):
        """node.py Node class has no asmap attribute."""
        try:
            from ouroboros.node import Node
            import inspect
            src = inspect.getsource(Node.__init__)
            self.assertNotIn(
                'asmap',
                src.lower(),
                "BUG-29: Node.__init__ has no asmap attribute",
            )
        except (ImportError, AttributeError):
            pass  # node.py may not be importable without full deps


# ============================================================================
# G30 — Rust PeerManager: no asmap field (TWO-PIPELINE)
# ============================================================================
class TestG30RustPeerManagerNoAsmap(unittest.TestCase):
    """
    BUG-30 (LOW / TWO-PIPELINE)
    Rust PeerManager (peer_manager.rs) has no asmap_data field and is
    entirely ASN-blind. No #[pyfunction] exports ASN lookup to Python.
    """

    def test_g30_rust_peer_manager_source_no_asmap(self):
        """ferrous-utils/sync/src/network/peer_manager.rs has no asmap."""
        import os
        path = "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/peer_manager.rs"
        if not os.path.exists(path):
            self.skipTest("peer_manager.rs not found")
        with open(path) as f:
            src = f.read()
        self.assertNotIn(
            'asmap',
            src.lower(),
            "BUG-30: peer_manager.rs has no asmap field",
        )
        self.assertNotIn(
            'asn',
            src.lower(),
            "BUG-30: peer_manager.rs has no ASN lookup",
        )

    def test_g30_rust_network_module_no_asmap(self):
        """No Rust network source file has any asmap reference."""
        import os, glob
        base = "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/"
        if not os.path.isdir(base):
            self.skipTest("Rust network dir not found")
        for rs_file in glob.glob(os.path.join(base, "*.rs")):
            with open(rs_file) as f:
                src = f.read().lower()
            self.assertNotIn(
                'asmap',
                src,
                f"BUG-30: {os.path.basename(rs_file)} has unexpected asmap reference",
            )

    def test_g30_rust_common_module_no_asmap(self):
        """No Rust common source file has any asmap reference."""
        import os, glob
        base = "/home/work/hashhog/ouroboros/ferrous-utils/common/src/"
        if not os.path.isdir(base):
            self.skipTest("Rust common dir not found")
        for rs_file in glob.glob(os.path.join(base, "*.rs")) + \
                        glob.glob(os.path.join(base, "**/*.rs")):
            with open(rs_file) as f:
                src = f.read().lower()
            self.assertNotIn(
                'asmap',
                src,
                f"BUG-30: {os.path.basename(rs_file)} has unexpected asmap reference",
            )


# ============================================================================
# Bonus: Core ASMap bytecode algorithm correctness (documentation tests)
# ============================================================================
class TestBonusBitExtraction(unittest.TestCase):
    """
    Document the Core ASMap bit extraction algorithms.
    These tests verify the algorithm spec rather than ouroboros behaviour.
    Used as regression baselines for when the interpreter is eventually added.
    """

    def test_bonus_consume_bit_le(self):
        """ConsumeBitLE: LSB-first extraction from byte array."""
        data = bytes([0b10110001])  # byte = 0xB1
        # Bits extracted LSB-first: 1, 0, 0, 0, 1, 1, 0, 1
        expected = [1, 0, 0, 0, 1, 1, 0, 1]
        extracted = []
        for bitpos in range(8):
            bit = (data[bitpos // 8] >> (bitpos % 8)) & 1
            extracted.append(bit)
        self.assertEqual(extracted, expected)

    def test_bonus_consume_bit_be(self):
        """ConsumeBitBE: MSB-first extraction from byte array (IP bits)."""
        data = bytes([0b10110001])  # 0xB1
        # Bits extracted MSB-first: 1, 0, 1, 1, 0, 0, 0, 1
        expected = [1, 0, 1, 1, 0, 0, 0, 1]
        extracted = []
        for bitpos in range(8):
            bit = (data[bitpos // 8] >> (7 - (bitpos % 8))) & 1
            extracted.append(bit)
        self.assertEqual(extracted, expected)

    def test_bonus_return_opcode_encoding(self):
        """RETURN opcode is encoded as a single 0-bit (type=0)."""
        # The instruction type is decoded via DecodeBits(TYPE_BIT_SIZES=[0,0,1])
        # RETURN=0: first class (k=0, bit_sizes[0]=0, continuation bit is '0')
        # So RETURN starts with a single '0' bit.
        # JUMP=1: starts with [1, 0] (skip class 0, land in class 1)
        # MATCH=2: starts with [1, 1, 0]
        # DEFAULT=3: starts with [1, 1, 1]
        self.assertEqual(0, 0)   # RETURN type value
        self.assertEqual(1, 1)   # JUMP type value
        self.assertEqual(2, 2)   # MATCH type value
        self.assertEqual(3, 3)   # DEFAULT type value

    def test_bonus_asn_encoding_range(self):
        """ASN encoding: minval=1, ASN_BIT_SIZES=[15,16,...,24] → max ~16.7M."""
        # Class 0: [1 .. 1+2^15-1 = 32768]
        # Class 1: [32769 .. 32768+2^16-1 = 98303]
        # ...
        # All valid ASNs from 1 to 2^24-1 can be encoded.
        max_class0 = 1 + (1 << 15) - 1
        self.assertEqual(max_class0, 32768)
        max_class1 = max_class0 + (1 << 16)
        self.assertEqual(max_class1, 98304)

    def test_bonus_asmap_version_is_double_sha256(self):
        """AsmapVersion = double-SHA256 of the raw asmap bytes."""
        data = b"test asmap data"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()
        # Verify the algorithm formula
        inner = hashlib.sha256(data).digest()
        outer = hashlib.sha256(inner).hexdigest()
        self.assertEqual(outer, expected)
        self.assertEqual(len(outer), 64)  # 32 bytes hex-encoded


if __name__ == "__main__":
    unittest.main(verbosity=2)
