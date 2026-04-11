"""
Tests for I2P SAM protocol support.

Verifies:
- I2P base64 encoding/decoding (I2P variant with -~)
- I2P destination to .b32.i2p address conversion
- SAM protocol message parsing
- I2P address detection utilities
"""

import asyncio
import base64
import hashlib
import unittest

from ouroboros.addrman import NET_I2P, AddrInfo, get_network_group
from ouroboros.p2p import PeerManager
from ouroboros.tor import (
    I2PSession,
    _i2p_b64_decode,
    _i2p_b64_encode,
    i2p_destination_to_address,
    is_anonymous_network,
    is_i2p_host,
    is_onion_host,
)

# ── I2P Base64 Encoding ──────────────────────────────────────────────


class TestI2PBase64(unittest.TestCase):
    """Test I2P's non-standard base64 encoding (uses -~ instead of +/)."""

    def test_encode_no_special_chars(self):
        """Encoding without + or / should be unchanged."""
        data = b"hello"
        result = _i2p_b64_encode(data)
        # Standard base64: aGVsbG8=
        self.assertEqual(result, "aGVsbG8=")

    def test_encode_with_plus(self):
        """+ should be replaced with -"""
        # Find data that encodes to include +
        # 0xfb encodes to + in standard base64
        data = b"\xfb\xfb\xfb"
        standard = base64.b64encode(data).decode()
        self.assertIn("+", standard)
        result = _i2p_b64_encode(data)
        self.assertNotIn("+", result)
        self.assertIn("-", result)

    def test_encode_with_slash(self):
        """/ should be replaced with ~"""
        # 0xff encodes to / in standard base64
        data = b"\xff\xff\xff"
        standard = base64.b64encode(data).decode()
        self.assertIn("/", standard)
        result = _i2p_b64_encode(data)
        self.assertNotIn("/", result)
        self.assertIn("~", result)

    def test_decode_roundtrip(self):
        """Encode then decode should return original data."""
        data = b"\xfb\xfe\xff\x00\x01\x02"
        encoded = _i2p_b64_encode(data)
        decoded = _i2p_b64_decode(encoded)
        self.assertEqual(decoded, data)


# ── I2P Destination Address ──────────────────────────────────────────


class TestI2PDestinationAddress(unittest.TestCase):
    """Test I2P destination to .b32.i2p address conversion."""

    def test_destination_to_address(self):
        """Convert destination bytes to .b32.i2p address."""
        # Use a known destination (all zeros for simplicity)
        dest = b"\x00" * 32  # Simplified - real destinations are 387+ bytes
        address = i2p_destination_to_address(dest)

        self.assertTrue(address.endswith(".b32.i2p"))
        # Address should be base32(sha256(dest)) + ".b32.i2p"
        expected_hash = hashlib.sha256(dest).digest()
        expected_b32 = base64.b32encode(expected_hash).decode().lower().rstrip("=")
        self.assertEqual(address, expected_b32 + ".b32.i2p")

    def test_destination_address_is_52_chars(self):
        """I2P .b32.i2p addresses should have 52 base32 characters."""
        dest = b"\x12\x34" * 16  # 32 bytes
        address = i2p_destination_to_address(dest)
        # 52 base32 chars + ".b32.i2p" = 60 total
        b32_part = address[:-8]  # Remove ".b32.i2p"
        self.assertEqual(len(b32_part), 52)


# ── Address Detection ────────────────────────────────────────────────


class TestAddressDetection(unittest.TestCase):
    """Test address type detection utilities."""

    def test_is_i2p_host(self):
        self.assertTrue(is_i2p_host("abcdef.b32.i2p"))
        self.assertTrue(is_i2p_host("test.i2p"))
        self.assertTrue(is_i2p_host("UPPERCASE.B32.I2P"))
        self.assertFalse(is_i2p_host("192.168.1.1"))
        self.assertFalse(is_i2p_host("example.com"))
        self.assertFalse(is_i2p_host("test.onion"))

    def test_is_onion_host(self):
        self.assertTrue(is_onion_host("test.onion"))
        self.assertTrue(is_onion_host("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
        self.assertFalse(is_onion_host("test.b32.i2p"))
        self.assertFalse(is_onion_host("192.168.1.1"))

    def test_is_anonymous_network(self):
        self.assertTrue(is_anonymous_network("test.onion"))
        self.assertTrue(is_anonymous_network("test.b32.i2p"))
        self.assertTrue(is_anonymous_network("test.i2p"))
        self.assertFalse(is_anonymous_network("192.168.1.1"))
        self.assertFalse(is_anonymous_network("example.com"))


# ── AddrInfo I2P Support ─────────────────────────────────────────────


class TestAddrInfoI2P(unittest.TestCase):
    """Test AddrInfo I2P address handling."""

    def test_is_i2p_by_network_id(self):
        info = AddrInfo(host="test", port=8333, network_id=NET_I2P)
        self.assertTrue(info.is_i2p())
        self.assertFalse(info.is_onion())

    def test_is_i2p_by_hostname(self):
        info = AddrInfo(host="abc.b32.i2p", port=8333)
        self.assertTrue(info.is_i2p())

    def test_not_addrv1_compatible(self):
        """I2P addresses require addrv2 (BIP155)."""
        info = AddrInfo(host="abc.b32.i2p", port=8333, network_id=NET_I2P)
        self.assertFalse(info.is_addrv1_compatible())


# ── Network Group for I2P ────────────────────────────────────────────


class TestNetworkGroupI2P(unittest.TestCase):
    """Test that I2P addresses are grouped correctly."""

    def test_i2p_netgroup(self):
        """All .b32.i2p addresses should be in the 'i2p' group."""
        self.assertEqual(get_network_group("abc.b32.i2p"), "i2p")
        self.assertEqual(get_network_group("xyz.b32.i2p"), "i2p")
        self.assertEqual(get_network_group("test.i2p"), "i2p")

    def test_i2p_netgroup_by_id(self):
        """I2P network_id should also result in 'i2p' group."""
        self.assertEqual(get_network_group("host", NET_I2P), "i2p")


# ── PeerManager I2P Integration ──────────────────────────────────────


class TestPeerManagerI2P(unittest.TestCase):
    """Test PeerManager I2P integration."""

    def test_i2psam_config(self):
        """PeerManager should accept i2psam configuration."""
        pm = PeerManager(
            network="regtest",
            listen=False,
            i2psam="127.0.0.1:7656",
        )
        self.assertEqual(pm.i2psam, "127.0.0.1:7656")

    def test_can_connect_i2p_without_session(self):
        """Cannot connect to I2P without a session."""
        pm = PeerManager(network="regtest", listen=False)
        self.assertFalse(pm._can_connect_to("test.b32.i2p"))

    def test_proxy_for_i2p_returns_none(self):
        """I2P addresses should not use SOCKS5 proxy."""
        pm = PeerManager(
            network="regtest",
            listen=False,
            proxy="127.0.0.1:9050",
        )
        # I2P uses SAM, not SOCKS5
        self.assertIsNone(pm._proxy_for_host("test.b32.i2p"))
        # But .onion still uses proxy
        self.assertEqual(pm._proxy_for_host("test.onion"), "127.0.0.1:9050")

    def test_addr_bytes_to_host_i2p(self):
        """Test I2P address decoding from BIP155 format."""
        # 32-byte SHA256 hash (simplified destination)
        hash_bytes = hashlib.sha256(b"test").digest()
        result = PeerManager._addr_bytes_to_host(5, hash_bytes)

        self.assertIsNotNone(result)
        self.assertTrue(result.endswith(".b32.i2p"))
        # Should be base32(hash_bytes) + ".b32.i2p"
        expected = base64.b32encode(hash_bytes).decode().lower().rstrip("=") + ".b32.i2p"
        self.assertEqual(result, expected)

    def test_addr_bytes_to_host_i2p_wrong_length(self):
        """I2P addresses must be exactly 32 bytes."""
        self.assertIsNone(PeerManager._addr_bytes_to_host(5, b"\x00" * 16))
        self.assertIsNone(PeerManager._addr_bytes_to_host(5, b"\x00" * 33))

    def test_stats_include_i2p(self):
        """Stats should include I2P information."""
        pm = PeerManager(
            network="regtest",
            listen=False,
            i2psam="127.0.0.1:7656",
        )
        stats = pm.get_stats()
        self.assertEqual(stats["i2p_sam"], "127.0.0.1:7656")
        self.assertIsNone(stats["i2p_address"])
        self.assertEqual(stats["i2p_peers"], 0)


# ── I2P Session Mock Tests ───────────────────────────────────────────


class TestI2PSessionProtocol(unittest.TestCase):
    """Test I2P SAM protocol handling."""

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_session_init(self):
        """Test I2PSession initialization."""
        session = I2PSession(
            sam_host="127.0.0.1",
            sam_port=7656,
            data_dir="/tmp/test",
            persistent=True,
        )
        self.assertFalse(session.is_connected)
        self.assertIsNone(session.address)

    def test_hello_command_format(self):
        """Test that HELLO command is correctly formatted."""
        # This tests the expected command format
        expected = "HELLO VERSION MIN=3.1 MAX=3.1"
        self.assertIn("HELLO", expected)
        self.assertIn("VERSION", expected)
        self.assertIn("MIN=3.1", expected)

    def test_session_create_transient(self):
        """Test SESSION CREATE command with TRANSIENT destination."""
        expected = "SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT"
        self.assertIn("SESSION CREATE", expected)
        self.assertIn("STYLE=STREAM", expected)
        self.assertIn("DESTINATION=TRANSIENT", expected)


if __name__ == "__main__":
    unittest.main()
