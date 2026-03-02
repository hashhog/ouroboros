"""
Tests for Tor / SOCKS5 proxy support.

Verifies:
- SOCKS5 handshake and connection tunnelling (peer.py)
- .onion address parsing from addrv2 messages (p2p.py)
- Proxy configuration options (config.py)
- PeerManager proxy routing logic (p2p.py)
"""

import asyncio
import base64
import hashlib
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from ouroboros.peer import (
    Peer,
    PeerState,
    is_onion_host,
    parse_proxy_addr,
    socks5_connect,
    SOCKS5_VERSION,
    SOCKS5_AUTH_NONE,
    SOCKS5_CMD_CONNECT,
    SOCKS5_ATYP_DOMAINNAME,
    SOCKS5_ATYP_IPV4,
    SOCKS5_REPLY_SUCCESS,
)
from ouroboros.p2p import PeerManager
from ouroboros.config import NodeConfig


# ── Helper utilities ─────────────────────────────────────────────────


def _make_socks5_greeting_response() -> bytes:
    """Server greeting: accept no-auth."""
    return struct.pack("BB", SOCKS5_VERSION, SOCKS5_AUTH_NONE)


def _make_socks5_connect_response(
    status: int = SOCKS5_REPLY_SUCCESS,
) -> bytes:
    """Server CONNECT response with IPv4 bind address 0.0.0.0:0."""
    return struct.pack(
        "!BBBB4sH",
        SOCKS5_VERSION,
        status,
        0x00,
        SOCKS5_ATYP_IPV4,
        b"\x00\x00\x00\x00",
        0,
    )


# ── is_onion_host ────────────────────────────────────────────────────


class TestIsOnionHost(unittest.TestCase):
    def test_v3_onion(self):
        addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
        self.assertTrue(is_onion_host(addr))

    def test_uppercase(self):
        self.assertTrue(is_onion_host("SOMETHING.ONION"))

    def test_not_onion(self):
        self.assertFalse(is_onion_host("192.168.1.1"))
        self.assertFalse(is_onion_host("example.com"))

    def test_empty_string(self):
        self.assertFalse(is_onion_host(""))


# ── parse_proxy_addr ─────────────────────────────────────────────────


class TestParseProxyAddr(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(parse_proxy_addr("127.0.0.1:9050"), ("127.0.0.1", 9050))

    def test_hostname(self):
        self.assertEqual(parse_proxy_addr("tor-proxy:9050"), ("tor-proxy", 9050))

    def test_ipv6_bracket(self):
        self.assertEqual(parse_proxy_addr("[::1]:9050"), ("::1", 9050))

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            parse_proxy_addr("")

    def test_no_port_raises(self):
        with self.assertRaises((ValueError, IndexError)):
            parse_proxy_addr("127.0.0.1")


# ── SOCKS5 handshake (socks5_connect) ────────────────────────────────


class TestSocks5Connect(unittest.TestCase):
    """Test the SOCKS5 tunnel establishment at the protocol level."""

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_successful_tunnel(self):
        """Full SOCKS5 handshake with a mock proxy that responds correctly."""
        greeting = _make_socks5_greeting_response()
        connect_resp = _make_socks5_connect_response()
        mock_data = greeting + connect_resp

        mock_reader = AsyncMock()
        mock_reader.readexactly = AsyncMock(side_effect=[
            greeting,           # greeting response (2 bytes)
            connect_resp[:4],   # CONNECT reply header (4 bytes)
            connect_resp[4:],   # bind addr + port (6 bytes)
        ])

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("ouroboros.peer.asyncio.open_connection",
                    new_callable=AsyncMock,
                    return_value=(mock_reader, mock_writer)):
            reader, writer = self._run(
                socks5_connect("127.0.0.1", 9050, "example.onion", 8333)
            )

        self.assertIs(reader, mock_reader)
        self.assertIs(writer, mock_writer)

        # Verify the greeting was sent
        first_write = mock_writer.write.call_args_list[0][0][0]
        self.assertEqual(first_write, struct.pack("BBB", 0x05, 1, 0x00))

        # Verify the CONNECT request includes the domain name
        connect_write = mock_writer.write.call_args_list[1][0][0]
        self.assertIn(b"example.onion", connect_write)

    def test_connect_failure_status(self):
        """SOCKS5 proxy returns a non-success status for CONNECT."""
        greeting = _make_socks5_greeting_response()
        # status 0x05 = Connection refused
        connect_resp = _make_socks5_connect_response(status=0x05)

        mock_reader = AsyncMock()
        mock_reader.readexactly = AsyncMock(side_effect=[
            greeting,
            connect_resp[:4],
        ])

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("ouroboros.peer.asyncio.open_connection",
                    new_callable=AsyncMock,
                    return_value=(mock_reader, mock_writer)):
            with self.assertRaises(Exception) as ctx:
                self._run(
                    socks5_connect("127.0.0.1", 9050, "fail.onion", 8333)
                )
            self.assertIn("CONNECT failed", str(ctx.exception))

    def test_auth_rejected(self):
        """SOCKS5 proxy rejects no-auth method."""
        bad_greeting = struct.pack("BB", SOCKS5_VERSION, 0xFF)

        mock_reader = AsyncMock()
        mock_reader.readexactly = AsyncMock(return_value=bad_greeting)

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("ouroboros.peer.asyncio.open_connection",
                    new_callable=AsyncMock,
                    return_value=(mock_reader, mock_writer)):
            with self.assertRaises(Exception) as ctx:
                self._run(
                    socks5_connect("127.0.0.1", 9050, "test.onion", 8333)
                )
            self.assertIn("rejected no-auth", str(ctx.exception))


# ── Peer with proxy ──────────────────────────────────────────────────


class TestPeerProxy(unittest.TestCase):
    """Verify Peer stores and exposes the proxy parameter."""

    def test_proxy_stored(self):
        p = Peer("test.onion", 8333, proxy="127.0.0.1:9050")
        self.assertEqual(p.proxy, "127.0.0.1:9050")

    def test_proxy_default_none(self):
        p = Peer("10.0.0.1", 8333)
        self.assertIsNone(p.proxy)

    def test_onion_network_address(self):
        """_create_network_address for .onion should return all-zero IP."""
        p = Peer("test.onion", 8333, proxy="127.0.0.1:9050")
        na = p._create_network_address("test.onion", 8333)
        self.assertEqual(na.ip, b'\x00' * 16)


# ── _addr_bytes_to_host (Tor v3 parsing) ─────────────────────────────


class TestAddrBytesToHostTorV3(unittest.TestCase):
    """Test decoding of Tor v3 (net_id=4) addresses from addrv2."""

    def test_tor_v3_encoding(self):
        """A 32-byte ed25519 pubkey should produce a valid *.onion address."""
        # Use a known test pubkey (all zeros for simplicity)
        pubkey = b"\x00" * 32
        result = PeerManager._addr_bytes_to_host(4, pubkey)

        self.assertIsNotNone(result)
        self.assertTrue(result.endswith(".onion"))

        # Verify the address is 56 chars + ".onion"
        onion_part = result[:-6]  # strip ".onion"
        self.assertEqual(len(onion_part), 56)  # base32 of 35 bytes

        # Decode and verify checksum
        decoded = base64.b32decode(onion_part.upper())
        self.assertEqual(len(decoded), 35)
        self.assertEqual(decoded[:32], pubkey)

        # Verify checksum (SHA3-256 of ".onion checksum" + pubkey + version)
        version_byte = b"\x03"
        h = hashlib.sha3_256(b".onion checksum" + pubkey + version_byte).digest()
        expected_checksum = h[:2]
        self.assertEqual(decoded[32:34], expected_checksum)
        self.assertEqual(decoded[34:35], version_byte)

    def test_tor_v3_wrong_length(self):
        """net_id=4 with wrong byte count should return None."""
        self.assertIsNone(PeerManager._addr_bytes_to_host(4, b"\x00" * 16))
        self.assertIsNone(PeerManager._addr_bytes_to_host(4, b"\x00" * 33))

    def test_ipv4_still_works(self):
        result = PeerManager._addr_bytes_to_host(1, bytes([192, 168, 1, 1]))
        self.assertEqual(result, "192.168.1.1")

    def test_ipv6_returns_none(self):
        result = PeerManager._addr_bytes_to_host(2, b"\x00" * 16)
        self.assertIsNone(result)

    def test_unknown_net_id_returns_none(self):
        self.assertIsNone(PeerManager._addr_bytes_to_host(99, b"\x00" * 32))


# ── PeerManager proxy routing ───────────────────────────────────────


class TestPeerManagerProxy(unittest.TestCase):
    """Test PeerManager._proxy_for_host() routing logic."""

    def test_no_proxy_configured(self):
        pm = PeerManager(network="regtest", listen=False)
        self.assertIsNone(pm._proxy_for_host("10.0.0.1"))
        self.assertIsNone(pm._proxy_for_host("test.onion"))

    def test_global_proxy_used_for_all(self):
        pm = PeerManager(network="regtest", listen=False, proxy="127.0.0.1:9050")
        self.assertEqual(pm._proxy_for_host("10.0.0.1"), "127.0.0.1:9050")
        self.assertEqual(pm._proxy_for_host("test.onion"), "127.0.0.1:9050")

    def test_onion_proxy_used_for_onion_only(self):
        pm = PeerManager(
            network="regtest", listen=False,
            onion="127.0.0.1:9150",
        )
        # Clearnet: no global proxy → None
        self.assertIsNone(pm._proxy_for_host("10.0.0.1"))
        # .onion: use dedicated onion proxy
        self.assertEqual(pm._proxy_for_host("test.onion"), "127.0.0.1:9150")

    def test_both_proxies_set(self):
        pm = PeerManager(
            network="regtest", listen=False,
            proxy="127.0.0.1:9050",
            onion="127.0.0.1:9150",
        )
        # Clearnet gets global proxy
        self.assertEqual(pm._proxy_for_host("10.0.0.1"), "127.0.0.1:9050")
        # .onion gets dedicated onion proxy
        self.assertEqual(pm._proxy_for_host("test.onion"), "127.0.0.1:9150")

    def test_onion_falls_back_to_global_proxy(self):
        pm = PeerManager(
            network="regtest", listen=False,
            proxy="127.0.0.1:9050",
        )
        # .onion falls back to global proxy when no onion-specific proxy
        self.assertEqual(pm._proxy_for_host("test.onion"), "127.0.0.1:9050")


# ── PeerManager netgroup for .onion ──────────────────────────────────


class TestNetgroupOnion(unittest.TestCase):
    """Test that .onion addresses share the 'onion' netgroup."""

    def test_onion_netgroup(self):
        self.assertEqual(PeerManager._netgroup("test.onion"), "onion")
        self.assertEqual(
            PeerManager._netgroup(
                "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
            ),
            "onion",
        )

    def test_ipv4_netgroup_unchanged(self):
        self.assertEqual(PeerManager._netgroup("192.168.1.1"), "192.168")


# ── PeerManager stats include proxy info ─────────────────────────────


class TestPeerManagerStats(unittest.TestCase):
    def test_stats_include_proxy_fields(self):
        pm = PeerManager(
            network="regtest", listen=False,
            proxy="127.0.0.1:9050", onion="127.0.0.1:9150",
        )
        stats = pm.get_stats()
        self.assertEqual(stats["proxy"], "127.0.0.1:9050")
        self.assertEqual(stats["onion_proxy"], "127.0.0.1:9150")
        self.assertEqual(stats["onion_peers"], 0)


# ── NodeConfig proxy/onion/listen ────────────────────────────────────


class TestConfigProxyOptions(unittest.TestCase):
    """Test that config.py exposes proxy, onion, and listen options."""

    def test_defaults_are_none_or_enabled(self):
        cfg = NodeConfig()
        d = cfg.to_dict()
        self.assertIsNone(d["proxy"])
        self.assertIsNone(d["onion"])
        self.assertTrue(d["listen"])

    def test_proxy_from_env(self):
        import os
        os.environ["OUROBOROS_PROXY"] = "127.0.0.1:9050"
        os.environ["OUROBOROS_ONION"] = "127.0.0.1:9150"
        os.environ["OUROBOROS_LISTEN"] = "0"
        try:
            cfg = NodeConfig()
            d = cfg.to_dict()
            self.assertEqual(d["proxy"], "127.0.0.1:9050")
            self.assertEqual(d["onion"], "127.0.0.1:9150")
            self.assertFalse(d["listen"])
        finally:
            del os.environ["OUROBOROS_PROXY"]
            del os.environ["OUROBOROS_ONION"]
            del os.environ["OUROBOROS_LISTEN"]


if __name__ == "__main__":
    unittest.main()
