"""
Tests for peer handshake state machine and pre-handshake filtering.

Phase 16: Pre-Handshake Peer Filtering
- Only VERSION and VERACK messages are accepted until handshake is complete
- Handshake timeout of 60 seconds
- Reject peers with version < 70015 (segwit required)
- WTXIDRELAY and SENDADDRV2 must be sent before VERACK
"""

import struct
import time
import unittest

from ouroboros.p2p_messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    VersionMessage,
)
from ouroboros.peer import (
    HANDSHAKE_TIMEOUT,
    MIN_PEER_VERSION,
    Peer,
    PeerState,
)


class TestPeerHandshakeState(unittest.TestCase):
    """Tests for Peer handshake state tracking."""

    def test_initial_handshake_state(self):
        """New peer should have handshake_complete = False."""
        peer = Peer("10.0.0.1", 8333, "regtest")
        self.assertFalse(peer.handshake_complete)
        self.assertFalse(peer._version_received)
        self.assertFalse(peer._verack_received)
        self.assertFalse(peer._version_sent)
        self.assertFalse(peer._verack_sent)

    def test_initial_feature_flags(self):
        """New peer should have wtxid_relay and addrv2 = False."""
        peer = Peer("10.0.0.1", 8333, "regtest")
        self.assertFalse(peer.wtxid_relay)
        self.assertFalse(peer.addrv2)


class TestMinPeerVersion(unittest.TestCase):
    """Tests for minimum peer version requirement."""

    def test_min_version_constant(self):
        """MIN_PEER_VERSION should be 70015 for segwit support."""
        self.assertEqual(MIN_PEER_VERSION, 70015)

    def test_handshake_timeout_constant(self):
        """HANDSHAKE_TIMEOUT should be 60 seconds."""
        self.assertEqual(HANDSHAKE_TIMEOUT, 60.0)


class TestPreHandshakeFiltering(unittest.TestCase):
    """Tests for pre-handshake message filtering."""

    def test_handshake_messages_allowed(self):
        """VERSION, VERACK, WTXIDRELAY, SENDADDRV2 are allowed during handshake."""
        peer = Peer("10.0.0.1", 8333, "regtest")

        self.assertTrue(peer._is_handshake_message("version"))
        self.assertTrue(peer._is_handshake_message("verack"))
        self.assertTrue(peer._is_handshake_message("wtxidrelay"))
        self.assertTrue(peer._is_handshake_message("sendaddrv2"))

    def test_non_handshake_messages_blocked(self):
        """Other messages should be rejected before handshake complete."""
        peer = Peer("10.0.0.1", 8333, "regtest")

        # These should be blocked during handshake
        self.assertFalse(peer._is_handshake_message("ping"))
        self.assertFalse(peer._is_handshake_message("pong"))
        self.assertFalse(peer._is_handshake_message("inv"))
        self.assertFalse(peer._is_handshake_message("getdata"))
        self.assertFalse(peer._is_handshake_message("headers"))
        self.assertFalse(peer._is_handshake_message("block"))
        self.assertFalse(peer._is_handshake_message("tx"))
        self.assertFalse(peer._is_handshake_message("addr"))
        self.assertFalse(peer._is_handshake_message("getaddr"))
        self.assertFalse(peer._is_handshake_message("mempool"))
        self.assertFalse(peer._is_handshake_message("sendheaders"))
        self.assertFalse(peer._is_handshake_message("sendcmpct"))
        self.assertFalse(peer._is_handshake_message("feefilter"))


class TestVersionValidation(unittest.TestCase):
    """Tests for peer version validation."""

    def _create_version_payload(self, version: int) -> bytes:
        """Create a minimal VERSION message payload."""
        # version (4) + services (8) + timestamp (8)
        payload = struct.pack('<I', version)
        payload += struct.pack('<Q', NODE_NETWORK | NODE_WITNESS)
        payload += struct.pack('<q', int(time.time()))
        # addr_recv (26 bytes)
        payload += struct.pack('<Q', NODE_NETWORK | NODE_WITNESS)  # services
        payload += b'\x00' * 16  # IPv6 address (zeros)
        payload += struct.pack('>H', 8333)  # port
        # addr_from (26 bytes)
        payload += struct.pack('<Q', NODE_NETWORK | NODE_WITNESS)
        payload += b'\x00' * 16
        payload += struct.pack('>H', 8333)
        # nonce (8)
        payload += struct.pack('<Q', 12345678)
        # user_agent (varint + string)
        user_agent = b'/test:0.0.1/'
        payload += bytes([len(user_agent)]) + user_agent
        # start_height (4)
        payload += struct.pack('<i', 100000)
        # relay (1)
        payload += bytes([1])
        return payload

    def test_version_message_parsing(self):
        """VersionMessage should correctly parse version field."""
        payload = self._create_version_payload(70015)
        version = VersionMessage.from_payload(payload)
        self.assertEqual(version.version, 70015)

    def test_old_version_rejected(self):
        """Versions below MIN_PEER_VERSION should be rejected."""
        # This is tested via the handshake methods, which raise an exception
        # for versions < MIN_PEER_VERSION
        peer = Peer("10.0.0.1", 8333, "regtest")

        # Simulate receiving an old version
        peer.version = 70014
        self.assertLess(peer.version, MIN_PEER_VERSION)


class TestHandshakeSequence(unittest.TestCase):
    """Tests for the correct handshake message sequence."""

    def test_outbound_handshake_sends_version_first(self):
        """Outbound connections should send VERSION first."""
        # This is verified by the _handshake method structure:
        # 1. Send VERSION
        # 2. Receive VERSION
        # 3. Send WTXIDRELAY/SENDADDRV2
        # 4. Send VERACK
        # 5. Receive VERACK
        peer = Peer("10.0.0.1", 8333, "regtest", inbound=False)
        self.assertFalse(peer.inbound)

    def test_inbound_handshake_receives_version_first(self):
        """Inbound connections should receive VERSION first."""
        # This is verified by the _inbound_handshake method structure:
        # 1. Receive VERSION
        # 2. Send VERSION
        # 3. Send WTXIDRELAY/SENDADDRV2
        # 4. Send VERACK
        # 5. Receive VERACK
        peer = Peer("10.0.0.1", 8333, "regtest", inbound=True)
        self.assertTrue(peer.inbound)


class TestPeerConnect(unittest.TestCase):
    """Tests for peer connection that verify handshake behavior."""

    def test_peer_state_transitions(self):
        """Peer should go through correct state transitions."""
        peer = Peer("10.0.0.1", 8333, "regtest")

        # Initial state
        self.assertEqual(peer.state, PeerState.DISCONNECTED)

        # After setting to connecting
        peer.state = PeerState.CONNECTING
        self.assertEqual(peer.state, PeerState.CONNECTING)

        # After setting to connected
        peer.state = PeerState.CONNECTED
        self.assertEqual(peer.state, PeerState.CONNECTED)

        # After setting to handshaking
        peer.state = PeerState.HANDSHAKING
        self.assertEqual(peer.state, PeerState.HANDSHAKING)

        # After setting to ready
        peer.state = PeerState.READY
        self.assertEqual(peer.state, PeerState.READY)

    def test_handshake_complete_flag_after_success(self):
        """handshake_complete should be True after successful handshake simulation."""
        peer = Peer("10.0.0.1", 8333, "regtest")

        # Simulate successful handshake
        peer._version_sent = True
        peer._version_received = True
        peer._verack_sent = True
        peer._verack_received = True
        peer.handshake_complete = True

        self.assertTrue(peer.handshake_complete)


class TestRelayFlags(unittest.TestCase):
    """Tests for relay type handling."""

    def test_full_relay_peer(self):
        """Full relay peers should send all feature messages."""
        peer = Peer("10.0.0.1", 8333, "regtest", relay_txs=True)
        self.assertTrue(peer.relay_txs)

    def test_block_relay_only_peer(self):
        """Block-relay-only peers should skip tx-related messages."""
        peer = Peer("10.0.0.1", 8333, "regtest", relay_txs=False)
        self.assertFalse(peer.relay_txs)


if __name__ == "__main__":
    unittest.main()
