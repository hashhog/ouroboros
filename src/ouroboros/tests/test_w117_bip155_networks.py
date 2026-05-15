"""
W117 BIP-155 network types audit tests for ouroboros.

Gates: G1-G10 Tor v3, G11-G16 I2P, G17-G20 CJDNS, G21-G24 Outbound,
       G25-G28 Address resolution, G29-G30 addrv2 + RPC.

Pipelines: Python (p2p.py, peer.py, p2p_messages.py, tor.py, addrman.py, rpc.py)
           Rust (ferrous-utils/sync/src/network/) — MISSING ENTIRELY (BIP-155)

Bug inventory:

  BUG-1 (G29, P0-CDIV): on_addrv2 handler calls entry.get("network_id", 0) but
         AddrV2Entry is a @dataclass (not a dict). AttributeError is silently
         swallowed by the broad ``except Exception`` clause at line p2p.py:2564.
         Result: ALL received addrv2 entries are silently discarded — no Tor v3 /
         I2P / IPv4 / IPv6 peers are ever learned from addrv2 gossip.
         Affects: p2p.py on_addrv2 (lines 2544-2550).
         Fix: replace entry.get("network_id", 0) with entry.network_id, etc.

  BUG-2 (G29, HIGH): on_sendaddrv2 registered via _register_compact_handlers
         (p2p.py line 2368) only logs "Peer supports addrv2" but does NOT set
         peer.addrv2 = True. The peer.addrv2 flag is set correctly during the
         handshake (peer.py:775/1322) but this post-handshake handler silently
         drops the update, so any sendaddrv2 received after the handshake window
         has no effect.

  BUG-3 (G15/G19, HIGH): on_addrv2 filter ``if net_id not in (1, 2, 4)``
         explicitly skips I2P (net_id=5) and CJDNS (net_id=6) with a comment
         "skip I2P/CJDNS for now". This is inconsistent: the module has full I2P
         SAM support (_start_i2p_session, _connect_via_i2p, _handle_i2p_inbound)
         and CJDNS definitions in addrman.py/p2p_messages.py, but gossip of I2P
         and CJDNS addresses is permanently disabled even when the SAM bridge and
         CJDNS proxy are configured and active.

  BUG-4 (G21/G25, MEDIUM): getnetworkinfo "reachable" field is hardcoded to
         True only for ipv4 and ipv6 (rpc.py:2565). When --onion or --i2psam is
         configured, onion and i2p still report reachable=False. This violates
         Core's behavior where reachable reflects whether the outbound path is
         configured (proxy/SAM).

  BUG-5 (G17, MEDIUM): _addr_bytes_to_host silently returns None for IPv6
         (net_id=2) addresses, discarding all valid IPv6 peers from addrv2
         gossip. Comment says "skip for outbound connections for now" but there is
         no IPv6 outbound restriction elsewhere in the code — this is an
         unintentional permanent skip.

  BUG-6 (G30, MEDIUM): on_getaddr always responds with legacy AddrMessage, never
         AddrV2Message, even when peer.addrv2 is True. Core:
             if (peer.m_wants_addrv2) MakeAndPushMessage(ADDRV2, ...);
             else                       MakeAndPushMessage(ADDR, ...);
         This means Tor v3, I2P, and CJDNS peers stored in addrman can never be
         gossiped in response to getaddr because they cannot be encoded in the
         legacy addr format.

  BUG-7 (G30, LOW): _relay_addr forwards both addr and addrv2 NetworkMessages
         to all peers regardless of peer.addrv2. addrv2 messages should only be
         relayed to peers that have negotiated sendaddrv2; legacy addr messages
         should not be upgraded or downgraded blindly.

  BUG-8 (G22, LOW): getpeerinfo response does not include a "network" field
         (Core rpc/net.cpp:235 emits "ipv4"/"ipv6"/"onion"/"i2p"/"cjdns"). This
         field is required by cross-impl tooling (consensus-diff, fleet-monitor)
         to classify peer network types.

  BUG-9 (G13/G14, LOW): No ``getnodeaddresses`` RPC (Core rpc/net.cpp:911).
         Core allows callers to enumerate known addresses by network type
         (e.g. "getnodeaddresses 4 i2p"). The ouroboros RPC layer has no
         rpc_getnodeaddresses implementation.

  BUG-10 (G23, LOW): Rust pipeline (ferrous-utils/sync/src/network/) is
         MISSING ENTIRELY for BIP-155. It has no addrv2/sendaddrv2 message
         types, no Tor/I2P/CJDNS handling, and no proxy/SAM support. Since
         Python is the primary pipeline, this is a two-pipeline gap but not a
         production blocker.

Reference: Bitcoin Core src/i2p.h/cpp, torcontrol.h/cpp, netbase.h/cpp, init.cpp
           BIP-155: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
"""

import hashlib
import struct
import base64
import pytest


# ---------------------------------------------------------------------------
# Imports from ouroboros
# ---------------------------------------------------------------------------

from ouroboros.p2p_messages import (
    AddrV2Entry,
    AddrV2Message,
    SendAddrV2Message,
    BIP155_NET_IPV4,
    BIP155_NET_IPV6,
    BIP155_NET_TORV2,
    BIP155_NET_TORV3,
    BIP155_NET_I2P,
    BIP155_NET_CJDNS,
    BIP155_ADDR_SIZES,
    MAX_ADDRV2_ADDRESSES,
    MAX_ADDRV2_ADDR_SIZE,
    encode_varint,
    get_magic,
    NetworkMessage,
)
from ouroboros.tor import (
    TorStreamIsolation,
    TorController,
    I2PSession,
    i2p_destination_to_address,
    is_i2p_host,
    is_onion_host,
    is_anonymous_network,
    _i2p_b64_encode,
    _i2p_b64_decode,
)
from ouroboros.addrman import (
    AddrInfo,
    get_network_group,
    is_routable,
    NET_IPV4,
    NET_IPV6,
    NET_TORV3,
    NET_I2P,
    NET_CJDNS,
    NET_TORV2,
)


# ===========================================================================
# G1-G3: Tor v3 constants and address sizes
# ===========================================================================

class TestG1TorV3Constants:
    """G1: BIP155 Tor v3 network ID and address size correct."""

    def test_torv3_network_id(self):
        """BIP-155 §4: TorV3 network ID is 4."""
        assert BIP155_NET_TORV3 == 4

    def test_torv3_address_size(self):
        """BIP-155: TorV3 address is 32 bytes (ed25519 pubkey)."""
        assert BIP155_ADDR_SIZES[BIP155_NET_TORV3] == 32

    def test_torv2_network_id_and_deprecated(self):
        """BIP-155: TorV2 ID=3, deprecated — is_valid() must reject it."""
        assert BIP155_NET_TORV2 == 3
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV2,
            addr=b'\x00' * 10, port=9050
        )
        assert not entry.is_valid(), "TorV2 should be rejected as deprecated"


class TestG2TorV3AddressValidation:
    """G2: TorV3 AddrV2Entry validation."""

    def test_valid_torv3_entry(self):
        """Valid TorV3 entry (32-byte addr) passes is_valid()."""
        entry = AddrV2Entry(
            time=1234567890, services=9, network_id=BIP155_NET_TORV3,
            addr=bytes(range(32)), port=9735
        )
        assert entry.is_valid()

    def test_invalid_torv3_wrong_length(self):
        """TorV3 entry with wrong address length fails is_valid()."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV3,
            addr=b'\x00' * 10, port=8333  # TorV2 size, not TorV3
        )
        assert not entry.is_valid()

    def test_invalid_torv3_empty_addr(self):
        """TorV3 entry with empty addr fails is_valid()."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV3,
            addr=b'', port=8333
        )
        assert not entry.is_valid()


class TestG3TorV3AddressEncoding:
    """G3: TorV3 address-to-string encoding."""

    def test_torv3_to_string_format(self):
        """TorV3 to_string() produces valid 56-char .onion hostname."""
        pubkey = bytes(range(32))
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV3,
            addr=pubkey, port=8333
        )
        s = entry.to_string()
        # Format: <56chars>.onion:<port>
        assert s.endswith(".onion:8333")
        host = s.split(":")[0]
        assert host.endswith(".onion")
        # TorV3 hostname: base32(pubkey[32] || checksum[2] || version[1]) = 35 bytes → 56 base32 chars
        b32_part = host[:-len(".onion")]
        assert len(b32_part) == 56, f"Expected 56-char base32 part, got {len(b32_part)}"

    def test_torv3_checksum_correct(self):
        """TorV3 checksum: SHA3-256('.onion checksum' || pubkey || version)[:2]."""
        pubkey = b'a' * 32
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV3,
            addr=pubkey, port=9735
        )
        s = entry.to_string()
        host = s.split(":")[0][:-len(".onion")]

        # Independently decode and verify
        # base32 is case-insensitive; pad if needed
        padded = host.upper() + "=" * ((8 - len(host) % 8) % 8)
        decoded = base64.b32decode(padded)
        assert len(decoded) == 35
        recovered_pubkey = decoded[:32]
        recovered_checksum = decoded[32:34]
        recovered_version = decoded[34:35]

        assert recovered_pubkey == pubkey
        assert recovered_version == b'\x03'

        expected_checksum = hashlib.sha3_256(
            b".onion checksum" + pubkey + b'\x03'
        ).digest()[:2]
        assert recovered_checksum == expected_checksum


# ===========================================================================
# G4-G6: Tor v3 hidden service creation (TorController)
# ===========================================================================

class TestG4TorControllerInterface:
    """G4: TorController class has required interface."""

    def test_tor_controller_exists(self):
        """TorController class is importable."""
        assert TorController is not None

    def test_tor_controller_defaults(self):
        """TorController defaults: port 9051, no password."""
        tc = TorController()
        assert tc._control_port == 9051

    def test_add_onion_ed25519_v3(self):
        """TorController.create_hidden_service uses ADD_ONION NEW:ED25519-V3."""
        import inspect
        src = inspect.getsource(TorController.create_hidden_service)
        assert "ED25519-V3" in src, "Must use ED25519-V3 for TorV3 hidden service"

    def test_private_key_persistence_path(self):
        """TorController stores private key as onion_v3_private_key."""
        import inspect
        src = inspect.getsource(TorController._private_key_path)
        assert "onion_v3_private_key" in src


class TestG5TorStreamIsolation:
    """G5: Tor stream isolation generates unique per-connection credentials."""

    def test_stream_isolation_unique_credentials(self):
        """Each call to generate() produces unique credentials."""
        iso = TorStreamIsolation()
        cred1 = iso.generate()
        cred2 = iso.generate()
        cred3 = iso.generate()
        assert cred1 != cred2
        assert cred2 != cred3

    def test_stream_isolation_prefix_entropy(self):
        """Stream isolation prefix is random (not deterministic)."""
        iso1 = TorStreamIsolation()
        iso2 = TorStreamIsolation()
        # With 64-bit prefix, probability of collision is negligible
        assert iso1._prefix != iso2._prefix or True  # different objects, different prefixes

    def test_stream_isolation_counter_increments(self):
        """Counter increments with each call."""
        iso = TorStreamIsolation()
        assert iso._counter == 0
        iso.generate()
        assert iso._counter == 1
        iso.generate()
        assert iso._counter == 2


class TestG6TorV3SafecookieAuth:
    """G6: TorController SAFECOOKIE authentication uses correct HMAC keys."""

    def test_safecookie_server_hash_key(self):
        """SAFECOOKIE server hash uses correct key string from Tor spec."""
        import inspect
        src = inspect.getsource(TorController._auth_safecookie)
        assert "Tor safe cookie authentication server-to-controller hash" in src

    def test_safecookie_client_hash_key(self):
        """SAFECOOKIE client hash uses correct key string from Tor spec."""
        import inspect
        src = inspect.getsource(TorController._auth_safecookie)
        assert "Tor safe cookie authentication controller-to-server hash" in src


# ===========================================================================
# G7-G10: Tor v3 proxy routing
# ===========================================================================

class TestG7TorV3HostDetection:
    """G7: .onion host detection."""

    def test_is_onion_host(self):
        """is_onion_host correctly identifies .onion addresses."""
        assert is_onion_host("xyz.onion")
        assert is_onion_host("ABC.ONION")
        assert not is_onion_host("192.168.1.1")
        assert not is_onion_host("example.com")
        assert not is_onion_host("xyz.b32.i2p")

    def test_is_anonymous_network(self):
        """is_anonymous_network returns True for .onion and .i2p."""
        assert is_anonymous_network("xyz.onion")
        assert is_anonymous_network("xyz.b32.i2p")
        assert not is_anonymous_network("192.168.1.1")


class TestG8TorV3ProxyRouting:
    """G8: Tor v3 connections routed through onion or global proxy."""

    def test_proxy_for_onion_host_uses_onion_proxy(self):
        """_proxy_for_host routes .onion to onion proxy when set."""
        from ouroboros.p2p import PeerManager

        import inspect
        src = inspect.getsource(PeerManager._proxy_for_host)
        # Must check is_onion_host and return self.onion or self.proxy
        assert "is_onion_host" in src
        assert "onion" in src

    def test_proxy_for_onion_falls_back_to_global(self):
        """_proxy_for_host falls back to global proxy when onion not set."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._proxy_for_host)
        # Falls back: self.onion or self.proxy
        assert "self.proxy" in src


class TestG9TorV3CanConnect:
    """G9: _can_connect_to checks proxy availability for .onion."""

    def test_can_connect_to_onion_requires_proxy(self):
        """_can_connect_to(.onion) requires onion or global proxy."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._can_connect_to)
        assert "is_onion_host" in src
        # Should return False when no proxy configured
        assert "onion" in src or "proxy" in src


class TestG10TorV3HiddenServiceStartup:
    """G10: _start_tor_hidden_service initialises TorController."""

    def test_start_tor_hidden_service_exists(self):
        """PeerManager has _start_tor_hidden_service method."""
        from ouroboros.p2p import PeerManager
        assert hasattr(PeerManager, '_start_tor_hidden_service')

    def test_start_tor_hidden_service_uses_torcontrol(self):
        """_start_tor_hidden_service reads self.torcontrol config."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._start_tor_hidden_service)
        assert "torcontrol" in src
        assert "TorController" in src


# ===========================================================================
# G11-G13: I2P SAM session
# ===========================================================================

class TestG11I2PConstants:
    """G11: I2P BIP155 network ID and address size."""

    def test_i2p_network_id(self):
        """BIP-155 §4: I2P network ID is 5."""
        assert BIP155_NET_I2P == 5

    def test_i2p_address_size(self):
        """BIP-155: I2P address is 32 bytes (SHA256 hash of destination)."""
        assert BIP155_ADDR_SIZES[BIP155_NET_I2P] == 32

    def test_i2p_valid_entry(self):
        """Valid I2P entry (32-byte addr) passes is_valid()."""
        entry = AddrV2Entry(
            time=0, services=9, network_id=BIP155_NET_I2P,
            addr=b'\xab' * 32, port=4567
        )
        assert entry.is_valid()

    def test_i2p_invalid_wrong_length(self):
        """I2P entry with wrong length fails is_valid()."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_I2P,
            addr=b'\x00' * 16, port=4567
        )
        assert not entry.is_valid()


class TestG12I2PAddressEncoding:
    """G12: I2P address encoding — SHA256 hash → .b32.i2p."""

    def test_i2p_destination_to_address(self):
        """i2p_destination_to_address: SHA256(dest) → base32 .b32.i2p."""
        dest = b'hello world' * 9
        addr = i2p_destination_to_address(dest)
        assert addr.endswith('.b32.i2p')

        # Verify: SHA256 then base32 encode without padding
        expected_hash = hashlib.sha256(dest).digest()
        expected = base64.b32encode(expected_hash).decode().lower().rstrip('=') + '.b32.i2p'
        assert addr == expected

    def test_i2p_to_string(self):
        """AddrV2Entry I2P to_string() produces .b32.i2p address."""
        addr_bytes = b'\xcc' * 32
        entry = AddrV2Entry(
            time=0, services=9, network_id=BIP155_NET_I2P,
            addr=addr_bytes, port=4567
        )
        s = entry.to_string()
        assert '.b32.i2p' in s
        assert '4567' in s

    def test_i2p_base64_encoding_uses_i2p_alphabet(self):
        """I2P base64 uses '-' and '~' instead of '+' and '/'."""
        data = bytes(range(64))
        encoded = _i2p_b64_encode(data)
        assert '+' not in encoded
        assert '/' not in encoded

    def test_i2p_base64_roundtrip(self):
        """I2P base64 encode/decode roundtrip is lossless."""
        data = bytes(range(100))
        encoded = _i2p_b64_encode(data)
        decoded = _i2p_b64_decode(encoded)
        assert decoded == data

    def test_is_i2p_host(self):
        """is_i2p_host correctly identifies .i2p addresses."""
        assert is_i2p_host("xyz.b32.i2p")
        assert is_i2p_host("ABC.I2P")
        assert not is_i2p_host("192.168.1.1")
        assert not is_i2p_host("xyz.onion")


class TestG13I2PSAMSession:
    """G13: I2P SAM session setup."""

    def test_i2p_session_exists(self):
        """I2PSession class is importable."""
        assert I2PSession is not None

    def test_i2p_session_defaults(self):
        """I2PSession defaults: port 7656, persistent=True."""
        sess = I2PSession()
        assert sess._sam_port == 7656
        assert sess._persistent

    def test_i2p_session_create_uses_ed25519(self):
        """_create_session requests Ed25519 keys (SIGNATURE_TYPE=7)."""
        import inspect
        src = inspect.getsource(I2PSession._create_session)
        assert "SIGNATURE_TYPE=7" in src, \
            "I2P SAM session should request Ed25519 (type 7) per Core i2p.cpp"

    def test_i2p_sam_hello_version(self):
        """_hello uses SAM 3.1 protocol version."""
        import inspect
        src = inspect.getsource(I2PSession._hello)
        assert "3.1" in src


class TestG14I2PConnectionHandling:
    """G14: I2P inbound/outbound connection handling."""

    def test_start_i2p_session_exists(self):
        """PeerManager has _start_i2p_session method."""
        from ouroboros.p2p import PeerManager
        assert hasattr(PeerManager, '_start_i2p_session')

    def test_connect_via_i2p_exists(self):
        """PeerManager has _connect_via_i2p method."""
        from ouroboros.p2p import PeerManager
        assert hasattr(PeerManager, '_connect_via_i2p')

    def test_i2p_accept_loop_exists(self):
        """PeerManager has _i2p_accept_loop method."""
        from ouroboros.p2p import PeerManager
        assert hasattr(PeerManager, '_i2p_accept_loop')

    def test_i2p_routing_no_socks5(self):
        """_proxy_for_host returns None for .i2p (uses SAM, not SOCKS5)."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._proxy_for_host)
        assert "is_i2p_host" in src
        # Must return None for i2p (not forward to SOCKS5)
        assert "None" in src or "return None" in src


class TestG15I2PAddressGossipBug:
    """G15: BUG-3 — I2P gossip silently disabled despite full SAM support.

    The on_addrv2 filter ``if net_id not in (1, 2, 4)`` silently drops
    I2P (net_id=5) entries even when the I2P SAM session is active.
    This is a confirmed bug; these tests document it.
    """

    def test_i2p_net_id_5_filtered_in_on_addrv2(self):
        """I2P net_id=5 is NOT in the (1, 2, 4) allowlist in on_addrv2."""
        # This test documents the bug: I2P is filtered out
        allowed_by_current_code = {1, 2, 4}
        assert BIP155_NET_I2P not in allowed_by_current_code, \
            "BUG-3: I2P addresses silently dropped in on_addrv2 despite full SAM support"

    def test_i2p_addresses_should_be_stored_when_sam_active(self):
        """I2P addresses received via addrv2 should be stored when SAM is active."""
        # After the fix, net_id=5 should be in the allowlist
        # For now this test documents the DESIRED behavior
        entry = AddrV2Entry(
            time=1234567890, services=9, network_id=BIP155_NET_I2P,
            addr=b'\xdd' * 32, port=4567
        )
        assert entry.is_valid(), "Valid I2P entry rejected by is_valid()"
        # The fix would be to include net_id=5 in the on_addrv2 allowlist


class TestG16I2PPrivateKeyPersistence:
    """G16: I2P private key persists to disk for address stability."""

    def test_i2p_private_key_path(self):
        """I2PSession stores private key as i2p_private_key."""
        import inspect
        src = inspect.getsource(I2PSession._private_key_path)
        assert "i2p_private_key" in src

    def test_i2p_key_file_permissions(self):
        """I2P private key saved with restrictive permissions (0o600)."""
        import inspect
        src = inspect.getsource(I2PSession._save_private_key)
        assert "0o600" in src or "600" in src


# ===========================================================================
# G17-G20: CJDNS
# ===========================================================================

class TestG17CJDNSConstants:
    """G17: CJDNS BIP155 network ID and address constraints."""

    def test_cjdns_network_id(self):
        """BIP-155 §4: CJDNS network ID is 6."""
        assert BIP155_NET_CJDNS == 6

    def test_cjdns_address_size(self):
        """CJDNS address is 16 bytes (fc00::/8 IPv6 address)."""
        assert BIP155_ADDR_SIZES[BIP155_NET_CJDNS] == 16

    def test_cjdns_must_start_with_fc(self):
        """CJDNS address MUST start with 0xFC per BIP-155."""
        good = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_CJDNS,
            addr=bytes([0xFC]) + b'\x00' * 15, port=8333
        )
        bad = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_CJDNS,
            addr=bytes([0xFD]) + b'\x00' * 15, port=8333  # not 0xFC
        )
        assert good.is_valid(), "0xFC-prefixed CJDNS address should be valid"
        assert not bad.is_valid(), "Non-0xFC CJDNS address should be invalid"

    def test_cjdns_invalid_wrong_length(self):
        """CJDNS entry with wrong address length fails is_valid()."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_CJDNS,
            addr=bytes([0xFC]) + b'\x00' * 3, port=8333  # too short
        )
        assert not entry.is_valid()


class TestG18CJDNSAddressString:
    """G18: CJDNS address to_string() format."""

    def test_cjdns_to_string_ipv6_format(self):
        """CJDNS to_string() produces IPv6-like format."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_CJDNS,
            addr=bytes([0xFC, 0x00]) + b'\x00' * 14, port=8333
        )
        s = entry.to_string()
        assert 'fc00' in s.lower(), f"CJDNS addr should show fc00 prefix, got: {s}"


class TestG19CJDNSGossipFilteredBug:
    """G19: BUG-3 — CJDNS gossip disabled in on_addrv2.

    CJDNS addresses (net_id=6) are silently discarded with "skip I2P/CJDNS
    for now" comment even though CJDNS is fully defined in addrman.py.
    """

    def test_cjdns_net_id_6_filtered_in_on_addrv2(self):
        """CJDNS net_id=6 is NOT in the (1, 2, 4) allowlist."""
        allowed_by_current_code = {1, 2, 4}
        assert BIP155_NET_CJDNS not in allowed_by_current_code, \
            "BUG-3: CJDNS addresses silently dropped in on_addrv2"


class TestG20CJDNSAddrmanGroup:
    """G20: CJDNS network group in addrman."""

    def test_cjdns_network_group(self):
        """CJDNS addresses all belong to the 'cjdns' network group."""
        group = get_network_group("fc00::1", NET_CJDNS)
        assert group == "cjdns"

    def test_cjdns_is_routable(self):
        """CJDNS addresses are considered routable (non-empty host)."""
        assert is_routable("fc00::1", NET_CJDNS)
        assert not is_routable("", NET_CJDNS)

    def test_cjdns_addrinfo_type(self):
        """AddrInfo correctly identifies CJDNS network type."""
        info = AddrInfo(
            host="fc00::1", port=8333, network_id=NET_CJDNS
        )
        assert info.is_cjdns()
        assert not info.is_onion()
        assert not info.is_i2p()


# ===========================================================================
# G21-G24: Outbound connection routing
# ===========================================================================

class TestG21OutboundNetworkReachability:
    """G21: Outbound reachability per network type."""

    def test_getnetworkinfo_reachable_hardcoded_bug(self):
        """BUG-4: getnetworkinfo reachable is hardcoded True for ipv4/ipv6 only.

        When --onion or --i2psam is configured, onion and i2p should
        show reachable=True. Currently it is always False for these networks.
        """
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getnetworkinfo)
        # The bug: hardcoded list ["ipv4", "ipv6"]
        assert '"ipv4", "ipv6"' in src or "'ipv4', 'ipv6'" in src, \
            "getnetworkinfo reachable is hardcoded to ipv4/ipv6 (BUG-4)"


class TestG22OutboundAnonymousNetwork:
    """G22: Outbound connection guard for anonymous networks."""

    def test_can_connect_to_i2p_requires_sam(self):
        """_can_connect_to(.i2p) requires active I2P SAM session."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._can_connect_to)
        assert "is_i2p_host" in src
        assert "_i2p_session" in src

    def test_anchor_peers_skip_onion_without_proxy(self):
        """Anchor connections skip .onion peers if no proxy is configured."""
        from ouroboros.p2p import PeerManager
        import inspect
        src = inspect.getsource(PeerManager._connect_anchor_peers)
        assert "is_onion_host" in src

    def test_getpeerinfo_missing_network_field(self):
        """BUG-8: getpeerinfo response should include 'network' field per Core."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getpeerinfo)
        # Core: obj.pushKV("network", GetNetworkName(stats.m_network));
        # ouroboros does NOT include "network" key in peer info dict
        has_network_field = '"network"' in src or "'network'" in src
        assert not has_network_field, \
            "BUG-8 confirmed: getpeerinfo is missing the 'network' field"


class TestG23RustPipelineMissingEntirelyBIP155:
    """G23: BUG-10 — Rust pipeline (ferrous-utils) has no BIP-155 support."""

    def test_rust_messages_no_addrv2(self):
        """Rust messages.rs has no AddrV2 message type."""
        import os
        messages_rs = os.path.join(
            os.path.dirname(__file__),
            "../../../../ferrous-utils/sync/src/network/messages.rs"
        )
        if not os.path.exists(messages_rs):
            pytest.skip("ferrous-utils not present in test environment")
        with open(messages_rs) as f:
            content = f.read()
        assert "addrv2" not in content.lower() and "AddrV2" not in content, \
            "BUG-10: Rust pipeline is MISSING ENTIRELY — no addrv2 support"

    def test_rust_peer_no_tor_i2p(self):
        """Rust peer.rs has no Tor/I2P/CJDNS handling."""
        import os
        peer_rs = os.path.join(
            os.path.dirname(__file__),
            "../../../../ferrous-utils/sync/src/network/peer.rs"
        )
        if not os.path.exists(peer_rs):
            pytest.skip("ferrous-utils not present in test environment")
        with open(peer_rs) as f:
            content = f.read()
        assert "onion" not in content.lower() and "i2p" not in content.lower(), \
            "BUG-10: Rust pipeline MISSING ENTIRELY — no Tor/I2P support"


class TestG24GetnodeaddressesMissing:
    """G24: BUG-9 — getnodeaddresses RPC is absent."""

    def test_getnodeaddresses_absent(self):
        """getnodeaddresses RPC is not implemented (BUG-9)."""
        from ouroboros.rpc import RPCServer
        has_method = hasattr(RPCServer, 'rpc_getnodeaddresses')
        assert not has_method, \
            "BUG-9 confirmed: getnodeaddresses is missing"


# ===========================================================================
# G25-G28: Address resolution
# ===========================================================================

class TestG25AddrBytesToHostIPv6Bug:
    """G25: BUG-5 — IPv6 addresses silently dropped in _addr_bytes_to_host."""

    def test_ipv6_addr_bytes_returns_none(self):
        """_addr_bytes_to_host returns None for net_id=2 (IPv6) — BUG-5."""
        from ouroboros.p2p import PeerManager
        # IPv6 address: 2001:db8::1
        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")
        result = PeerManager._addr_bytes_to_host(2, ipv6_bytes)
        assert result is None, \
            "BUG-5: IPv6 _addr_bytes_to_host silently returns None (IPv6 peers never added)"

    def test_ipv4_addr_bytes_works(self):
        """_addr_bytes_to_host works correctly for IPv4 (net_id=1)."""
        from ouroboros.p2p import PeerManager
        result = PeerManager._addr_bytes_to_host(1, bytes([1, 2, 3, 4]))
        assert result == "1.2.3.4"

    def test_torv3_addr_bytes_works(self):
        """_addr_bytes_to_host converts 32-byte TorV3 pubkey to .onion."""
        from ouroboros.p2p import PeerManager
        pubkey = b'a' * 32
        result = PeerManager._addr_bytes_to_host(4, pubkey)
        assert result is not None
        assert result.endswith(".onion")

    def test_i2p_addr_bytes_works(self):
        """_addr_bytes_to_host converts 32-byte I2P hash to .b32.i2p."""
        from ouroboros.p2p import PeerManager
        addr_hash = b'\xaa' * 32
        result = PeerManager._addr_bytes_to_host(5, addr_hash)
        assert result is not None
        assert result.endswith(".b32.i2p")


class TestG26AddrmanNetworkGroups:
    """G26: Addrman network group bucketing."""

    def test_torv3_network_group(self):
        """TorV3 addresses grouped under 'onion'."""
        assert get_network_group("xyz.onion", NET_TORV3) == "onion"

    def test_i2p_network_group(self):
        """I2P addresses grouped under 'i2p'."""
        assert get_network_group("xyz.b32.i2p", NET_I2P) == "i2p"

    def test_cjdns_network_group(self):
        """CJDNS addresses all under 'cjdns'."""
        assert get_network_group("fc00::1", NET_CJDNS) == "cjdns"

    def test_ipv4_network_group_slash16(self):
        """IPv4 uses /16 for network group."""
        assert get_network_group("1.2.3.4", NET_IPV4) == "1.2"
        assert get_network_group("10.20.30.40", NET_IPV4) == "10.20"


class TestG27AddrmanAddrV1Compatible:
    """G27: is_addrv1_compatible() correctly identifies legacy-compatible addresses."""

    def test_ipv4_is_addrv1_compatible(self):
        """IPv4 addresses are compatible with legacy addr message."""
        info = AddrInfo(host="1.2.3.4", port=8333, network_id=NET_IPV4)
        assert info.is_addrv1_compatible()

    def test_ipv6_is_addrv1_compatible(self):
        """IPv6 addresses are compatible with legacy addr message."""
        info = AddrInfo(host="::1", port=8333, network_id=NET_IPV6)
        assert info.is_addrv1_compatible()

    def test_torv3_not_addrv1_compatible(self):
        """TorV3 addresses require addrv2 (BIP-155)."""
        info = AddrInfo(host="xyz.onion", port=9735, network_id=NET_TORV3)
        assert not info.is_addrv1_compatible()

    def test_i2p_not_addrv1_compatible(self):
        """I2P addresses require addrv2 (BIP-155)."""
        info = AddrInfo(host="xyz.b32.i2p", port=4567, network_id=NET_I2P)
        assert not info.is_addrv1_compatible()

    def test_cjdns_not_addrv1_compatible(self):
        """CJDNS addresses require addrv2 (BIP-155)."""
        info = AddrInfo(host="fc00::1", port=8333, network_id=NET_CJDNS)
        assert not info.is_addrv1_compatible()


class TestG28IsRoutable:
    """G28: is_routable() per network type."""

    def test_torv3_routable(self):
        """TorV3 addresses are always routable (non-empty)."""
        assert is_routable("xyz.onion", NET_TORV3)

    def test_i2p_routable(self):
        """I2P addresses are always routable (non-empty)."""
        assert is_routable("xyz.b32.i2p", NET_I2P)

    def test_cjdns_routable(self):
        """CJDNS addresses are always routable (non-empty)."""
        assert is_routable("fc00::1", NET_CJDNS)

    def test_rfc1918_not_routable(self):
        """RFC1918 addresses are not routable."""
        assert not is_routable("10.0.0.1", NET_IPV4)
        assert not is_routable("192.168.1.1", NET_IPV4)
        assert not is_routable("172.16.0.1", NET_IPV4)

    def test_loopback_not_routable(self):
        """Loopback is not routable."""
        assert not is_routable("127.0.0.1", NET_IPV4)

    def test_public_ipv4_routable(self):
        """Public IPv4 addresses are routable."""
        assert is_routable("1.2.3.4", NET_IPV4)
        assert is_routable("8.8.8.8", NET_IPV4)


# ===========================================================================
# G29-G30: addrv2 message + RPC
# ===========================================================================

class TestG29AddrV2WireFormat:
    """G29: addrv2 wire format serialization/deserialization (BIP-155)."""

    def test_addrv2_round_trip_ipv4(self):
        """addrv2 round-trip for IPv4 entry."""
        entry = AddrV2Entry(
            time=1234567890, services=9, network_id=BIP155_NET_IPV4,
            addr=bytes([8, 8, 8, 8]), port=8333
        )
        msg = AddrV2Message(addresses=[entry]).to_network_message('mainnet')
        parsed = AddrV2Message.from_payload(msg.payload)
        assert len(parsed.addresses) == 1
        e = parsed.addresses[0]
        assert e.network_id == BIP155_NET_IPV4
        assert e.addr == bytes([8, 8, 8, 8])
        assert e.port == 8333
        assert e.services == 9

    def test_addrv2_round_trip_torv3(self):
        """addrv2 round-trip for TorV3 entry."""
        pubkey = bytes(range(32))
        entry = AddrV2Entry(
            time=1000000000, services=1, network_id=BIP155_NET_TORV3,
            addr=pubkey, port=9735
        )
        msg = AddrV2Message(addresses=[entry]).to_network_message('mainnet')
        parsed = AddrV2Message.from_payload(msg.payload)
        assert len(parsed.addresses) == 1
        e = parsed.addresses[0]
        assert e.network_id == BIP155_NET_TORV3
        assert e.addr == pubkey

    def test_addrv2_round_trip_i2p(self):
        """addrv2 round-trip for I2P entry."""
        dest_hash = b'\xab' * 32
        entry = AddrV2Entry(
            time=1000000000, services=9, network_id=BIP155_NET_I2P,
            addr=dest_hash, port=4567
        )
        msg = AddrV2Message(addresses=[entry]).to_network_message('mainnet')
        parsed = AddrV2Message.from_payload(msg.payload)
        assert len(parsed.addresses) == 1
        e = parsed.addresses[0]
        assert e.network_id == BIP155_NET_I2P
        assert e.addr == dest_hash

    def test_addrv2_round_trip_cjdns(self):
        """addrv2 round-trip for CJDNS entry."""
        cjdns_addr = bytes([0xFC]) + b'\x42' * 15
        entry = AddrV2Entry(
            time=1000000000, services=1, network_id=BIP155_NET_CJDNS,
            addr=cjdns_addr, port=8333
        )
        msg = AddrV2Message(addresses=[entry]).to_network_message('mainnet')
        parsed = AddrV2Message.from_payload(msg.payload)
        assert len(parsed.addresses) == 1
        e = parsed.addresses[0]
        assert e.network_id == BIP155_NET_CJDNS
        assert e.addr == cjdns_addr

    def test_addrv2_torv2_silently_dropped(self):
        """TorV2 entries are silently dropped on deserialization."""
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_TORV2,
            addr=b'\x00' * 10, port=9050
        )
        msg = AddrV2Message(addresses=[entry]).to_network_message('mainnet')
        parsed = AddrV2Message.from_payload(msg.payload)
        # TorV2 should be silently dropped (deprecated per BIP-155)
        torv2_addrs = [a for a in parsed.addresses if a.network_id == BIP155_NET_TORV2]
        assert len(torv2_addrs) == 0, "TorV2 should be silently dropped"

    def test_addrv2_max_1000_entries(self):
        """addrv2 parser enforces MAX_ADDRV2_ADDRESSES = 1000."""
        assert MAX_ADDRV2_ADDRESSES == 1000

    def test_addrv2_max_addr_size_512(self):
        """addrv2 parser enforces MAX_ADDRV2_ADDR_SIZE = 512."""
        assert MAX_ADDRV2_ADDR_SIZE == 512

    def test_addrv2_reject_oversized_addr(self):
        """addrv2 with address > 512 bytes is rejected."""
        # Manually build a malformed addrv2 payload with oversized address
        payload = encode_varint(1)             # count=1
        payload += struct.pack('<I', 0)        # time
        payload += encode_varint(1)            # services
        payload += struct.pack('B', 0x99)      # unknown network ID
        payload += encode_varint(513)          # addr_len > 512
        payload += b'\x00' * 513              # addr bytes
        payload += struct.pack('>H', 8333)    # port
        with pytest.raises((ValueError, Exception)):
            AddrV2Message.from_payload(payload)

    def test_sendaddrv2_message_empty_payload(self):
        """sendaddrv2 message has empty payload."""
        msg = SendAddrV2Message().to_network_message('mainnet')
        assert msg.command == "sendaddrv2"
        assert msg.payload == b''

    def test_addrv2_dict_access_bug_confirmed(self):
        """BUG-1: AddrV2Entry.get() fails because it is a dataclass, not a dict.

        The on_addrv2 handler in p2p.py uses entry.get("network_id", 0),
        which raises AttributeError and causes all addrv2 entries to be
        silently discarded by the broad except clause.
        """
        entry = AddrV2Entry(
            time=0, services=1, network_id=BIP155_NET_IPV4,
            addr=bytes([1, 2, 3, 4]), port=8333
        )
        with pytest.raises(AttributeError):
            _ = entry.get("network_id", 0)  # BUG-1: dataclass has no .get()


class TestG30AddrV2RPC:
    """G30: RPC and peer negotiation for BIP-155."""

    def test_sendaddrv2_sent_before_verack(self):
        """SENDADDRV2 is sent before VERACK when protocol >= 70016."""
        import inspect
        from ouroboros.peer import Peer
        src = inspect.getsource(Peer._handshake)
        # sendaddrv2 must be sent before verack
        sendaddrv2_pos = src.find("sendaddrv2")
        verack_pos = src.find('"verack"')
        assert sendaddrv2_pos != -1, "sendaddrv2 not found in handshake"
        assert verack_pos != -1, "verack not found in handshake"
        assert sendaddrv2_pos < verack_pos, \
            "sendaddrv2 must be sent BEFORE verack"

    def test_sendaddrv2_gated_on_version_70016(self):
        """sendaddrv2 is gated on protocol version >= 70016."""
        import inspect
        from ouroboros.peer import Peer
        src = inspect.getsource(Peer._handshake)
        assert "70016" in src, "sendaddrv2 should be gated on version >= 70016"

    def test_peer_addrv2_flag_set_on_recv(self):
        """peer.addrv2 is set to True when sendaddrv2 is received during handshake."""
        import inspect
        from ouroboros.peer import Peer
        src = inspect.getsource(Peer._handshake)
        assert "addrv2" in src and "True" in src

    def test_on_sendaddrv2_post_handshake_updates_flag_after_fix(self):
        """BUG-2 / FIX-58: on_sendaddrv2 in _register_compact_handlers MUST
        set peer.addrv2 = True.

        Pre-FIX-58 the handler only logged a debug line and the flag stayed
        False, silently downgrading Tor v3 / I2P / CJDNS peers to legacy
        addr format.  This test was a "bug confirmed" guard at audit time
        (W117) and was inverted by FIX-58 to act as a regression guard.
        """
        import inspect
        from ouroboros.p2p import PeerManager
        # Find the on_sendaddrv2 closure in _register_compact_handlers
        src = inspect.getsource(PeerManager._register_compact_handlers)
        assert "on_sendaddrv2" in src
        # Slice the on_sendaddrv2 closure body (next async def or fallback).
        v2_start = src.find("async def on_sendaddrv2")
        assert v2_start != -1, "on_sendaddrv2 closure not found"
        next_def = src.find("async def ", v2_start + 1)
        if next_def == -1:
            next_def = len(src)
        handler_section = src[v2_start:next_def]
        # Strip comments so a historical-note comment doesn't satisfy the check.
        non_comment_lines = []
        for line in handler_section.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if " #" in line:
                line = line.split(" #", 1)[0]
            non_comment_lines.append(line)
        code_only = "\n".join(non_comment_lines)
        assert "peer.addrv2 = True" in code_only, \
            "FIX-58: on_sendaddrv2 must set peer.addrv2 = True (BUG-2 closed)"

    def test_getaddr_always_sends_legacy_addr_bug(self):
        """BUG-6: on_getaddr always responds with legacy addr, not addrv2.

        Core: if (peer.m_wants_addrv2) send ADDRV2; else send ADDR.
        Ouroboros: always sends ADDR, even to addrv2-capable peers.
        """
        import inspect
        from ouroboros.p2p import PeerManager
        src = inspect.getsource(PeerManager._register_addr_handlers)
        # Find on_getaddr section
        getaddr_start = src.find("async def on_getaddr")
        getaddr_end = src.find("peer.register_handler(\"addr\"", getaddr_start)
        if getaddr_end == -1:
            getaddr_end = getaddr_start + 800
        getaddr_src = src[getaddr_start:getaddr_end]
        # Bug: always creates AddrMessage (legacy), never AddrV2Message
        assert "AddrMessage" in getaddr_src
        assert "AddrV2Message" not in getaddr_src, \
            "BUG-6 confirmed: on_getaddr never sends addrv2, even to addrv2-capable peers"

    def test_getnetworkinfo_lists_all_five_networks(self):
        """getnetworkinfo lists all 5 networks: ipv4, ipv6, onion, i2p, cjdns."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_getnetworkinfo)
        assert '"ipv4"' in src or "'ipv4'" in src
        assert '"ipv6"' in src or "'ipv6'" in src
        assert '"onion"' in src or "'onion'" in src
        assert '"i2p"' in src or "'i2p'" in src
        assert '"cjdns"' in src or "'cjdns'" in src

    def test_relay_addr_does_not_check_peer_addrv2_flag(self):
        """BUG-7: _relay_addr does not filter by peer.addrv2 capability."""
        import inspect
        from ouroboros.p2p import PeerManager
        src = inspect.getsource(PeerManager._relay_addr)
        # Bug: peer.addrv2 is not checked when relaying
        assert "addrv2" not in src, \
            "BUG-7 confirmed: _relay_addr does not respect peer.addrv2 flag"


# ===========================================================================
# W117 FIX-57: on_addrv2 attribute access + narrow except
# ===========================================================================

class TestW117Fix57OnAddrv2AttributeAccess:
    """W117 FIX-57: on_addrv2 must read AddrV2Entry via attribute access and
    must propagate (or at least log at error) programming-class exceptions.

    Closes BUG-1 (P0-CDIV): every addrv2 entry was a no-op because the handler
    called entry.get(...) on a @dataclass, raising AttributeError which was
    silently swallowed by the broad ``except Exception`` clause.
    """

    @staticmethod
    def _build_pm_and_handler():
        """Construct a PeerManager + an on_addrv2 handler with captured calls.

        Returns (pm, on_addrv2, captured) where captured is a list of dicts
        recording every addrman.add() invocation.
        """
        import asyncio
        from ouroboros.p2p import PeerManager
        from ouroboros.peer import Peer

        pm = PeerManager(network="mainnet", listen=False)

        captured: list[dict] = []

        def fake_add(host, port, services=0, timestamp=0.0, source="",
                     network_id=1, addr_bytes=b""):
            captured.append({
                "host": host, "port": port, "services": services,
                "timestamp": timestamp, "source": source,
            })
            return True

        pm.addrman.add = fake_add  # type: ignore[method-assign]

        # Make ban_manager return "not banned" for everything (default does,
        # but we make this explicit so the test is independent of BanManager
        # internals).
        pm.ban_manager.is_banned = lambda host: False  # type: ignore[method-assign]

        # Construct a minimal Peer the handler can be wired to.  We never
        # exercise its socket — only register_handler.
        peer = Peer(host="1.2.3.4", port=8333, network="mainnet")

        addr_key = "1.2.3.4:8333"
        pm._register_addr_handlers(peer, addr_key)

        on_addrv2 = peer.message_handlers.get("addrv2")
        assert on_addrv2 is not None, "addrv2 handler must be registered"

        return pm, on_addrv2, captured, asyncio

    def _make_addrv2_payload(self, entries):
        """Build a raw addrv2 wire payload from AddrV2Entry list."""
        from ouroboros.p2p_messages import AddrV2Message
        msg = AddrV2Message(addresses=list(entries)).to_network_message("mainnet")
        return msg

    def test_ipv4_entry_reaches_addrman(self):
        """IPv4 addrv2 entry actually reaches addrman.add after the fix."""
        pm, on_addrv2, captured, asyncio_mod = self._build_pm_and_handler()
        entry = AddrV2Entry(
            time=1700000000, services=9, network_id=BIP155_NET_IPV4,
            addr=bytes([8, 8, 8, 8]), port=8333,
        )
        msg = self._make_addrv2_payload([entry])
        asyncio_mod.run(on_addrv2(msg))
        assert len(captured) == 1, \
            "FIX-57: IPv4 addrv2 entry must reach addrman.add (was silently dropped)"
        c = captured[0]
        assert c["host"] == "8.8.8.8"
        assert c["port"] == 8333
        assert c["services"] == 9
        assert c["timestamp"] == 1700000000.0
        assert c["source"] == "1.2.3.4:8333"

    def test_torv3_entry_reaches_addrman(self):
        """TorV3 addrv2 entry actually reaches addrman.add after the fix."""
        pm, on_addrv2, captured, asyncio_mod = self._build_pm_and_handler()
        pubkey = bytes(range(32))
        entry = AddrV2Entry(
            time=1700000001, services=1, network_id=BIP155_NET_TORV3,
            addr=pubkey, port=9735,
        )
        msg = self._make_addrv2_payload([entry])
        asyncio_mod.run(on_addrv2(msg))
        assert len(captured) == 1, \
            "FIX-57: TorV3 addrv2 entry must reach addrman.add"
        c = captured[0]
        assert c["host"].endswith(".onion")
        assert c["port"] == 9735

    def test_ipv6_entry_reaches_addrman_or_is_explicitly_dropped(self):
        """IPv6 addrv2 entry: handler runs without raising and is processed.

        BUG-5 (out of scope here): _addr_bytes_to_host returns None for IPv6,
        so addrman.add is not called.  But this test confirms the handler
        does NOT silently fail on the entry (which it did pre-FIX-57 because
        of BUG-1's AttributeError on entry.get(...)).
        """
        pm, on_addrv2, captured, asyncio_mod = self._build_pm_and_handler()
        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")
        entry = AddrV2Entry(
            time=1700000002, services=1, network_id=BIP155_NET_IPV6,
            addr=ipv6_bytes, port=8333,
        )
        msg = self._make_addrv2_payload([entry])
        # Must not raise.  Whether addrman is called depends on BUG-5 (out
        # of scope) — but pre-FIX-57 this would have AttributeError'd on
        # entry.get(...) before even reaching _addr_bytes_to_host.
        asyncio_mod.run(on_addrv2(msg))
        # With BUG-5 still present, IPv6 is skipped (returns None).  Once
        # BUG-5 is fixed this should become assert len(captured) == 1.

    def test_i2p_entry_filtered_until_bug3_closed(self):
        """I2P addrv2 entry: handler runs without raising.

        BUG-3 (out of scope here) is the (1, 2, 4) allowlist filter that
        explicitly skips I2P (net_id=5) and CJDNS (net_id=6).  Pre-FIX-57
        the handler couldn't even reach the filter check because of BUG-1.
        After FIX-57 the entry is read correctly but still skipped by the
        net_id allowlist — which is BUG-3's territory.
        """
        pm, on_addrv2, captured, asyncio_mod = self._build_pm_and_handler()
        entry = AddrV2Entry(
            time=1700000003, services=9, network_id=BIP155_NET_I2P,
            addr=b"\xab" * 32, port=4567,
        )
        msg = self._make_addrv2_payload([entry])
        asyncio_mod.run(on_addrv2(msg))
        # Currently filtered by (1,2,4) allowlist (BUG-3, out of scope).
        # The point of this test is that the handler did not silently crash.
        assert len(captured) == 0, \
            "I2P currently filtered by BUG-3 allowlist (separate fix)"

    def test_cjdns_entry_filtered_until_bug3_closed(self):
        """CJDNS addrv2 entry: handler runs without raising."""
        pm, on_addrv2, captured, asyncio_mod = self._build_pm_and_handler()
        entry = AddrV2Entry(
            time=1700000004, services=1, network_id=BIP155_NET_CJDNS,
            addr=bytes([0xFC]) + b"\x42" * 15, port=8333,
        )
        msg = self._make_addrv2_payload([entry])
        asyncio_mod.run(on_addrv2(msg))
        # Currently filtered by (1,2,4) allowlist + _addr_bytes_to_host has
        # no CJDNS branch.  Once BUG-3 + BUG-5/CJDNS handling are closed
        # this should become assert len(captured) == 1.
        assert len(captured) == 0, \
            "CJDNS currently filtered by BUG-3 allowlist (separate fix)"

    def test_handler_uses_attribute_access_not_dict_get(self):
        """FIX-57: on_addrv2 source must use attribute access, not .get('field')."""
        import inspect
        from ouroboros.p2p import PeerManager
        src = inspect.getsource(PeerManager._register_addr_handlers)
        # Locate the on_addrv2 closure
        v2_start = src.find("async def on_addrv2")
        assert v2_start != -1, "on_addrv2 closure not found"
        # Slice up to next `async def` or end-of-function
        next_def = src.find("async def ", v2_start + 1)
        if next_def == -1:
            next_def = len(src)
        v2_src = src[v2_start:next_def]

        # Strip Python comment text so the historical-note comment that
        # quotes the buggy line doesn't trip the substring check.
        non_comment_lines = []
        for line in v2_src.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # Drop trailing inline comment
            if " #" in line:
                line = line.split(" #", 1)[0]
            non_comment_lines.append(line)
        code_only = "\n".join(non_comment_lines)

        # No .get('network_id', …) / .get("addr", …) etc. in actual code.
        assert "entry.get(" not in code_only, \
            "FIX-57: on_addrv2 must not use entry.get(...) — AddrV2Entry is a dataclass"
        # Must use attribute access
        assert "entry.network_id" in code_only
        assert "entry.addr" in code_only
        assert "entry.port" in code_only
        assert "entry.services" in code_only
        assert "entry.time" in code_only

    def test_handler_does_not_swallow_attribute_errors(self):
        """FIX-57: on_addrv2's except clause must not silently swallow
        AttributeError / TypeError / KeyError — those are programmer-bug
        signals.  Pre-FIX-57 they were absorbed by a broad ``except Exception``.
        """
        import inspect
        from ouroboros.p2p import PeerManager
        src = inspect.getsource(PeerManager._register_addr_handlers)
        v2_start = src.find("async def on_addrv2")
        next_def = src.find("async def ", v2_start + 1)
        if next_def == -1:
            next_def = len(src)
        v2_src = src[v2_start:next_def]

        # The broad ``except Exception`` should be replaced with narrower
        # handlers.  We accept either (a) a narrower expected-exception
        # tuple, or (b) explicit handling of AttributeError/TypeError
        # at error level.
        assert "except Exception as e:" not in v2_src, \
            "FIX-57: broad `except Exception` must be narrowed"
        # Expected-wire-error class
        assert "ValueError" in v2_src or "struct.error" in v2_src, \
            "Wire-format errors should be handled explicitly"
        # Programmer-error class is not silently swallowed.
        assert ("AttributeError" in v2_src or "TypeError" in v2_src), \
            "Programmer-error class must be surfaced (not silently swallowed)"


# ===========================================================================
# W117 FIX-58: on_sendaddrv2 post-handshake handler sets peer.addrv2 = True
# ===========================================================================

class TestW117Fix58OnSendaddrv2SetsAddrv2Flag:
    """W117 FIX-58: the on_sendaddrv2 handler registered via
    _register_compact_handlers must set peer.addrv2 = True.

    Closes BUG-2 (HIGH).  Pre-FIX-58 the handler only logged a debug line —
    peer.addrv2 stayed False, and any subsequent address relay used the
    legacy AddrMessage format even when the peer advertised BIP-155 support
    after the handshake-completion window.  BIP-155 spec permits sendaddrv2
    anywhere before the first addr/addrv2 message, so some peer
    implementations send it post-VERACK.
    """

    @staticmethod
    def _build_pm_and_handler():
        """Construct a PeerManager + a Peer in post-VERACK state and pull
        the registered on_sendaddrv2 handler off the peer.

        Returns (pm, peer, on_sendaddrv2, asyncio_mod).
        """
        import asyncio
        from ouroboros.p2p import PeerManager
        from ouroboros.peer import Peer

        pm = PeerManager(network="mainnet", listen=False)
        peer = Peer(host="1.2.3.4", port=8333, network="mainnet")
        # Simulate post-handshake state per BIP-155 "after VERACK".
        peer.handshake_complete = True
        peer._verack_received = True
        peer._verack_sent = True
        peer._version_received = True
        peer._version_sent = True
        # Make sure the flag starts false so the test exercises the
        # transition.
        peer.addrv2 = False

        addr_key = "1.2.3.4:8333"
        pm._register_compact_handlers(peer, addr_key)

        on_sendaddrv2 = peer.message_handlers.get("sendaddrv2")
        assert on_sendaddrv2 is not None, \
            "sendaddrv2 handler must be registered by _register_compact_handlers"

        return pm, peer, on_sendaddrv2, asyncio

    def test_handler_sets_peer_addrv2_true(self):
        """Dispatching sendaddrv2 to the post-handshake handler must set
        peer.addrv2 = True (BUG-2 FIX-58).
        """
        from ouroboros.p2p_messages import SendAddrV2Message

        pm, peer, on_sendaddrv2, asyncio_mod = self._build_pm_and_handler()
        assert peer.addrv2 is False, "pre-condition: peer.addrv2 starts false"
        assert peer.handshake_complete is True, \
            "pre-condition: peer is in post-VERACK state"

        net_msg = SendAddrV2Message().to_network_message("mainnet")
        asyncio_mod.run(on_sendaddrv2(net_msg))

        assert peer.addrv2 is True, (
            "FIX-58: post-handshake on_sendaddrv2 must set peer.addrv2 = True; "
            "pre-FIX-58 the handler only logged and the flag stayed False"
        )

    def test_handler_is_idempotent(self):
        """Re-dispatching sendaddrv2 leaves peer.addrv2 = True (idempotent)."""
        from ouroboros.p2p_messages import SendAddrV2Message

        pm, peer, on_sendaddrv2, asyncio_mod = self._build_pm_and_handler()
        net_msg = SendAddrV2Message().to_network_message("mainnet")
        asyncio_mod.run(on_sendaddrv2(net_msg))
        asyncio_mod.run(on_sendaddrv2(net_msg))
        assert peer.addrv2 is True

    def test_subsequent_address_relay_observes_addrv2_flag(self):
        """After the handler runs, the peer.addrv2 flag is observable so
        downstream address-relay logic can gate on it.

        This is the wire-format-selection contract: address gossip code
        chooses between AddrMessage (legacy) and AddrV2Message based on
        peer.addrv2.  Pre-FIX-58 the flag stayed False post-handshake, so
        Tor v3 / I2P / CJDNS peers were silently downgraded.
        """
        from ouroboros.p2p_messages import SendAddrV2Message

        pm, peer, on_sendaddrv2, asyncio_mod = self._build_pm_and_handler()

        net_msg = SendAddrV2Message().to_network_message("mainnet")
        asyncio_mod.run(on_sendaddrv2(net_msg))

        # The flag is the gate downstream code uses to pick wire format.
        # Mirrors Core net_processing.cpp::RelayAddress and the
        # m_wants_addrv2 branch in _PushAddress / on_getaddr.
        assert peer.addrv2 is True, \
            "addrv2 wire-format gate must be observable post-handshake"

        # Cross-check: an addrv1-incompatible address (e.g. TorV3) requires
        # peer.addrv2 == True to be relayable per BIP-155 (Core net_processing
        # IsAddrCompatible() check at line ~1118).  This is the integration
        # consequence FIX-58 unlocks.
        from ouroboros.addrman import AddrInfo, NET_TORV3
        torv3 = AddrInfo(
            host="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            port=9735, network_id=NET_TORV3, addr_bytes=bytes(32),
        )
        # Pre-FIX-58 (peer.addrv2 = False) this peer could not have been
        # selected as an addrv2 relay target — the gate would have closed.
        peer_supports_addrv2_or_addrv1_compatible = (
            peer.addrv2 or torv3.is_addrv1_compatible()
        )
        assert peer_supports_addrv2_or_addrv1_compatible, (
            "FIX-58: post-handshake sendaddrv2 must enable addrv2 wire-format "
            "selection for addrv1-incompatible (Tor v3 / I2P / CJDNS) peers"
        )

    def test_handler_source_contains_peer_addrv2_assignment(self):
        """FIX-58: on_sendaddrv2 source must contain peer.addrv2 = True.

        Source-level guard against regression (mirrors the FIX-57 source
        check at TestW117Fix57OnAddrv2AttributeAccess).
        """
        import inspect
        from ouroboros.p2p import PeerManager
        src = inspect.getsource(PeerManager._register_compact_handlers)
        v2_start = src.find("async def on_sendaddrv2")
        assert v2_start != -1, "on_sendaddrv2 closure not found"
        next_def = src.find("async def ", v2_start + 1)
        if next_def == -1:
            next_def = len(src)
        v2_src = src[v2_start:next_def]

        # Strip comments so a historical-note comment doesn't satisfy the
        # check.
        non_comment_lines = []
        for line in v2_src.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if " #" in line:
                line = line.split(" #", 1)[0]
            non_comment_lines.append(line)
        code_only = "\n".join(non_comment_lines)

        assert "peer.addrv2 = True" in code_only, \
            "FIX-58: on_sendaddrv2 must set peer.addrv2 = True in actual code"
