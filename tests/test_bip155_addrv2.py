"""
Tests for BIP155 addrv2 support.

Phase 33: BIP155 addrv2 Support
- addrv2 message format with network IDs
- sendaddrv2 negotiation during handshake
- Variable-length address storage in addrman
- Support for TorV3, I2P, and CJDNS addresses
"""

import struct
import time
import unittest

from ouroboros.p2p_messages import (
    AddrV2Message,
    AddrV2Entry,
    SendAddrV2Message,
    encode_varint,
    decode_varint,
    BIP155_NET_IPV4,
    BIP155_NET_IPV6,
    BIP155_NET_TORV2,
    BIP155_NET_TORV3,
    BIP155_NET_I2P,
    BIP155_NET_CJDNS,
    BIP155_ADDR_SIZES,
    MAX_ADDRV2_ADDRESSES,
)
from ouroboros.addrman import (
    AddressManager,
    AddrInfo,
    get_network_group,
    NET_IPV4,
    NET_IPV6,
    NET_TORV3,
    NET_I2P,
    NET_CJDNS,
)


class TestBIP155Constants(unittest.TestCase):
    """Test BIP155 network ID constants."""

    def test_network_ids(self):
        """Network IDs should match BIP155 specification."""
        self.assertEqual(BIP155_NET_IPV4, 1)
        self.assertEqual(BIP155_NET_IPV6, 2)
        self.assertEqual(BIP155_NET_TORV2, 3)
        self.assertEqual(BIP155_NET_TORV3, 4)
        self.assertEqual(BIP155_NET_I2P, 5)
        self.assertEqual(BIP155_NET_CJDNS, 6)

    def test_address_sizes(self):
        """Address sizes should match BIP155 specification."""
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_IPV4], 4)
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_IPV6], 16)
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_TORV2], 10)
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_TORV3], 32)
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_I2P], 32)
        self.assertEqual(BIP155_ADDR_SIZES[BIP155_NET_CJDNS], 16)


class TestAddrV2Entry(unittest.TestCase):
    """Test AddrV2Entry validation and serialization."""

    def test_ipv4_entry_valid(self):
        """Valid IPv4 entry should pass validation."""
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_IPV4,
            addr=bytes([192, 168, 1, 1]),
            port=8333,
        )
        self.assertTrue(entry.is_valid())

    def test_ipv4_wrong_length_invalid(self):
        """IPv4 entry with wrong address length should be invalid."""
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_IPV4,
            addr=bytes([192, 168, 1]),  # 3 bytes instead of 4
            port=8333,
        )
        self.assertFalse(entry.is_valid())

    def test_ipv6_entry_valid(self):
        """Valid IPv6 entry should pass validation."""
        # ::1 in IPv6 format
        ipv6_addr = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_IPV6,
            addr=ipv6_addr,
            port=8333,
        )
        self.assertTrue(entry.is_valid())

    def test_torv2_deprecated(self):
        """TorV2 entries should be invalid (deprecated)."""
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_TORV2,
            addr=bytes(10),  # 10 bytes for TorV2
            port=8333,
        )
        self.assertFalse(entry.is_valid())

    def test_torv3_entry_valid(self):
        """Valid TorV3 entry should pass validation."""
        # 32-byte ed25519 pubkey
        tor_pubkey = bytes(32)
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_TORV3,
            addr=tor_pubkey,
            port=8333,
        )
        self.assertTrue(entry.is_valid())

    def test_i2p_entry_valid(self):
        """Valid I2P entry should pass validation."""
        # 32-byte destination hash
        i2p_hash = bytes(32)
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_I2P,
            addr=i2p_hash,
            port=0,  # I2P SAM 3.1 uses port 0
        )
        self.assertTrue(entry.is_valid())

    def test_cjdns_entry_valid(self):
        """Valid CJDNS entry should pass validation (starts with 0xFC)."""
        # CJDNS address must start with 0xFC
        cjdns_addr = bytes([0xFC]) + bytes(15)
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_CJDNS,
            addr=cjdns_addr,
            port=8333,
        )
        self.assertTrue(entry.is_valid())

    def test_cjdns_wrong_prefix_invalid(self):
        """CJDNS entry not starting with 0xFC should be invalid."""
        # Wrong prefix
        cjdns_addr = bytes([0x20]) + bytes(15)
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_CJDNS,
            addr=cjdns_addr,
            port=8333,
        )
        self.assertFalse(entry.is_valid())

    def test_unknown_network_invalid(self):
        """Unknown network ID should be invalid."""
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=99,  # Unknown
            addr=bytes(16),
            port=8333,
        )
        self.assertFalse(entry.is_valid())

    def test_ipv4_to_string(self):
        """IPv4 entry should convert to dotted-decimal format."""
        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_IPV4,
            addr=bytes([192, 168, 1, 100]),
            port=8333,
        )
        self.assertEqual(entry.to_string(), "192.168.1.100:8333")


class TestAddrV2Message(unittest.TestCase):
    """Test AddrV2Message serialization and deserialization."""

    def test_serialize_single_ipv4(self):
        """Serialize a single IPv4 address."""
        entry = AddrV2Entry(
            time=1234567890,
            services=1,
            network_id=BIP155_NET_IPV4,
            addr=bytes([10, 0, 0, 1]),
            port=8333,
        )
        msg = AddrV2Message(addresses=[entry])
        net_msg = msg.to_network_message("mainnet")

        self.assertEqual(net_msg.command, "addrv2")

        # Deserialize and verify
        parsed = AddrV2Message.from_payload(net_msg.payload)
        self.assertEqual(len(parsed.addresses), 1)
        self.assertEqual(parsed.addresses[0].time, 1234567890)
        self.assertEqual(parsed.addresses[0].services, 1)
        self.assertEqual(parsed.addresses[0].network_id, BIP155_NET_IPV4)
        self.assertEqual(parsed.addresses[0].addr, bytes([10, 0, 0, 1]))
        self.assertEqual(parsed.addresses[0].port, 8333)

    def test_serialize_multiple_addresses(self):
        """Serialize multiple addresses of different types."""
        entries = [
            AddrV2Entry(
                time=int(time.time()),
                services=1,
                network_id=BIP155_NET_IPV4,
                addr=bytes([192, 168, 1, 1]),
                port=8333,
            ),
            AddrV2Entry(
                time=int(time.time()),
                services=1,
                network_id=BIP155_NET_IPV6,
                addr=bytes(16),
                port=8333,
            ),
            AddrV2Entry(
                time=int(time.time()),
                services=1,
                network_id=BIP155_NET_TORV3,
                addr=bytes(32),
                port=8333,
            ),
        ]
        msg = AddrV2Message(addresses=entries)
        net_msg = msg.to_network_message("mainnet")

        parsed = AddrV2Message.from_payload(net_msg.payload)
        self.assertEqual(len(parsed.addresses), 3)
        self.assertEqual(parsed.addresses[0].network_id, BIP155_NET_IPV4)
        self.assertEqual(parsed.addresses[1].network_id, BIP155_NET_IPV6)
        self.assertEqual(parsed.addresses[2].network_id, BIP155_NET_TORV3)

    def test_deserialize_skips_invalid(self):
        """Deserialization should skip invalid entries (TorV2, wrong length)."""
        # Manually construct payload with invalid TorV2 entry
        now = int(time.time())
        payload = encode_varint(2)  # 2 addresses

        # Valid IPv4
        payload += struct.pack('<I', now)
        payload += encode_varint(1)  # services
        payload += bytes([BIP155_NET_IPV4])
        payload += encode_varint(4)
        payload += bytes([10, 0, 0, 1])
        payload += struct.pack('>H', 8333)

        # Invalid TorV2 (deprecated)
        payload += struct.pack('<I', now)
        payload += encode_varint(1)
        payload += bytes([BIP155_NET_TORV2])
        payload += encode_varint(10)
        payload += bytes(10)
        payload += struct.pack('>H', 8333)

        parsed = AddrV2Message.from_payload(payload)
        # Should only have the valid IPv4 entry
        self.assertEqual(len(parsed.addresses), 1)
        self.assertEqual(parsed.addresses[0].network_id, BIP155_NET_IPV4)

    def test_max_addresses_limit(self):
        """Deserialization should reject messages with too many addresses."""
        # Construct payload claiming 1001 addresses (over limit)
        payload = encode_varint(MAX_ADDRV2_ADDRESSES + 1)

        with self.assertRaises(ValueError) as ctx:
            AddrV2Message.from_payload(payload)
        self.assertIn("max is", str(ctx.exception))


class TestSendAddrV2Message(unittest.TestCase):
    """Test sendaddrv2 message (negotiation)."""

    def test_serialize_empty_payload(self):
        """sendaddrv2 should have empty payload."""
        msg = SendAddrV2Message()
        net_msg = msg.to_network_message("mainnet")

        self.assertEqual(net_msg.command, "sendaddrv2")
        self.assertEqual(net_msg.payload, b"")

    def test_deserialize_empty_payload(self):
        """Deserializing empty payload should work."""
        parsed = SendAddrV2Message.from_payload(b"")
        self.assertIsInstance(parsed, SendAddrV2Message)


class TestAddrInfoBIP155(unittest.TestCase):
    """Test AddrInfo with BIP155 network types."""

    def test_default_network_id(self):
        """Default network_id should be NET_IPV4."""
        info = AddrInfo(host="192.168.1.1", port=8333)
        self.assertEqual(info.network_id, NET_IPV4)

    def test_torv3_network_id(self):
        """AddrInfo should store TorV3 network_id."""
        info = AddrInfo(
            host="example.onion",
            port=8333,
            network_id=NET_TORV3,
            addr_bytes=bytes(32),
        )
        self.assertEqual(info.network_id, NET_TORV3)
        self.assertTrue(info.is_onion())
        self.assertFalse(info.is_addrv1_compatible())

    def test_i2p_network_id(self):
        """AddrInfo should store I2P network_id."""
        info = AddrInfo(
            host="example.b32.i2p",
            port=0,
            network_id=NET_I2P,
            addr_bytes=bytes(32),
        )
        self.assertEqual(info.network_id, NET_I2P)
        self.assertTrue(info.is_i2p())
        self.assertFalse(info.is_addrv1_compatible())

    def test_cjdns_network_id(self):
        """AddrInfo should store CJDNS network_id."""
        cjdns_addr = bytes([0xFC]) + bytes(15)
        info = AddrInfo(
            host="fc00::1",
            port=8333,
            network_id=NET_CJDNS,
            addr_bytes=cjdns_addr,
        )
        self.assertEqual(info.network_id, NET_CJDNS)
        self.assertTrue(info.is_cjdns())
        self.assertFalse(info.is_addrv1_compatible())

    def test_ipv4_addrv1_compatible(self):
        """IPv4 addresses should be addrv1 compatible."""
        info = AddrInfo(host="192.168.1.1", port=8333, network_id=NET_IPV4)
        self.assertTrue(info.is_addrv1_compatible())

    def test_ipv6_addrv1_compatible(self):
        """IPv6 addresses should be addrv1 compatible."""
        info = AddrInfo(host="::1", port=8333, network_id=NET_IPV6)
        self.assertTrue(info.is_addrv1_compatible())


class TestNetworkGroup(unittest.TestCase):
    """Test network group computation for bucket diversification."""

    def test_ipv4_group(self):
        """IPv4 addresses should use /16 group."""
        group = get_network_group("192.168.1.1", NET_IPV4)
        self.assertEqual(group, "192.168")

    def test_ipv6_group(self):
        """IPv6 addresses should use /32 prefix."""
        group = get_network_group("2001:db8::1", NET_IPV6)
        self.assertEqual(group, "2001:db8")

    def test_onion_group(self):
        """Onion addresses should use 'onion' group."""
        group = get_network_group("example.onion", NET_TORV3)
        self.assertEqual(group, "onion")

    def test_i2p_group(self):
        """I2P addresses should use 'i2p' group."""
        group = get_network_group("example.b32.i2p", NET_I2P)
        self.assertEqual(group, "i2p")

    def test_cjdns_group(self):
        """CJDNS addresses should use 'cjdns' group."""
        group = get_network_group("fc00::1", NET_CJDNS)
        self.assertEqual(group, "cjdns")


class TestAddressManagerBIP155(unittest.TestCase):
    """Test AddressManager with BIP155 addresses."""

    def test_add_torv3_address(self):
        """AddressManager should store TorV3 addresses."""
        addrman = AddressManager()

        result = addrman.add(
            host="example.onion",
            port=8333,
            services=1,
            timestamp=time.time(),
            network_id=NET_TORV3,
            addr_bytes=bytes(32),
        )

        self.assertTrue(result)
        self.assertEqual(addrman.size(), 1)

        info = addrman.get_addr_info("example.onion", 8333)
        self.assertIsNotNone(info)
        self.assertEqual(info.network_id, NET_TORV3)
        self.assertEqual(len(info.addr_bytes), 32)

    def test_add_i2p_address(self):
        """AddressManager should store I2P addresses."""
        addrman = AddressManager()

        result = addrman.add(
            host="example.b32.i2p",
            port=0,
            services=1,
            timestamp=time.time(),
            network_id=NET_I2P,
            addr_bytes=bytes(32),
        )

        self.assertTrue(result)
        info = addrman.get_addr_info("example.b32.i2p", 0)
        self.assertIsNotNone(info)
        self.assertEqual(info.network_id, NET_I2P)

    def test_add_from_addrv2_entry(self):
        """AddressManager should accept AddrV2Entry objects."""
        addrman = AddressManager()

        entry = AddrV2Entry(
            time=int(time.time()),
            services=1,
            network_id=BIP155_NET_IPV4,
            addr=bytes([10, 0, 0, 1]),
            port=8333,
        )

        result = addrman.add_from_addrv2(entry, source="192.168.1.1:8333")

        self.assertTrue(result)
        self.assertEqual(addrman.size(), 1)


if __name__ == "__main__":
    unittest.main()
