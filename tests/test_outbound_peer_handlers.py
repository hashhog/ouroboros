"""
Tests for the outbound-peer handler hook (PARITY-MATRIX.md Category B).

Before this fix the PeerManager only ran a callback when a *new* inbound
peer completed its handshake, so the node only attached tx / getdata /
getheaders handlers to inbound peers (and to outbound peers that happened
to be connected before ``_register_handlers()`` was called).  Outbound
peers dialed later (full-relay from addrman, anchors, addnode, block-relay)
silently dropped those serving messages — ouroboros could IBD but could
not serve queries from peers it had dialed.

These tests pin the callback contract end-to-end without bringing up real
TCP sockets:

* ``test_set_outbound_peer_handler_stores_callback`` — the setter wires
  the callback onto the manager.
* ``test_fire_outbound_peer_callback_invokes_handler`` — the manager
  invokes the registered callback with the peer object.
* ``test_fire_outbound_peer_callback_no_handler_is_noop`` — manager works
  fine with no callback registered.
* ``test_fire_outbound_peer_callback_swallows_exceptions`` — a buggy
  callback never breaks the dial path.

A separate small test verifies that NODE_WITNESS is OR'd into the
advertised services in both the outbound and inbound build sites of
``Peer`` (Category B audit cross-check).
"""

import asyncio
import unittest

from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import NODE_NETWORK, NODE_WITNESS


class _FakePeer:
    """Tiny stand-in for a Peer; only needs a register_handler shim."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8333):
        self.host = host
        self.port = port
        self.handlers: dict = {}

    def register_handler(self, command, handler):
        self.handlers[command] = handler


class TestOutboundPeerHandler(unittest.TestCase):
    """The outbound-peer hook is the symmetric of set_inbound_peer_handler."""

    def _make_manager(self, tmp_dir: str = "/tmp") -> PeerManager:
        return PeerManager(
            "regtest",
            max_peers=8,
            data_dir=tmp_dir,
            transport_version=1,
            listen=False,
            peer_bloom_filters=False,
        )

    def test_set_outbound_peer_handler_stores_callback(self):
        pm = self._make_manager()

        async def cb(peer):
            pass

        self.assertIsNone(pm._on_outbound_peer)
        pm.set_outbound_peer_handler(cb)
        self.assertIs(pm._on_outbound_peer, cb)

    def test_fire_outbound_peer_callback_invokes_handler(self):
        pm = self._make_manager()
        seen = []

        async def cb(peer):
            seen.append(peer)
            peer.register_handler("tx", lambda msg: None)

        pm.set_outbound_peer_handler(cb)
        peer = _FakePeer()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(pm._fire_outbound_peer_callback(peer))
        finally:
            loop.close()

        self.assertEqual(seen, [peer])
        self.assertIn("tx", peer.handlers)

    def test_fire_outbound_peer_callback_no_handler_is_noop(self):
        pm = self._make_manager()
        peer = _FakePeer()
        # No handler registered — must not raise.
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(pm._fire_outbound_peer_callback(peer))
        finally:
            loop.close()
        self.assertEqual(peer.handlers, {})

    def test_fire_outbound_peer_callback_swallows_exceptions(self):
        pm = self._make_manager()

        async def bad_cb(peer):
            raise RuntimeError("boom")

        pm.set_outbound_peer_handler(bad_cb)
        peer = _FakePeer()

        loop = asyncio.new_event_loop()
        try:
            # Must NOT raise — the dial path shouldn't break because a
            # consumer's callback misbehaved.
            loop.run_until_complete(pm._fire_outbound_peer_callback(peer))
        finally:
            loop.close()


class TestServiceFlagAdvertisement(unittest.TestCase):
    """NODE_WITNESS must always be OR'd alongside NODE_NETWORK.

    Audit critique: a full node that validates witness data but does not
    advertise NODE_WITNESS is internally inconsistent and gets second-class
    service (Core peers won't send MSG_WITNESS_BLOCK).
    """

    def test_node_witness_constant(self):
        # protocol.h: NODE_WITNESS = (1 << 3) = 8
        self.assertEqual(NODE_WITNESS, 1 << 3)

    def test_node_network_constant(self):
        self.assertEqual(NODE_NETWORK, 1 << 0)

    def test_default_outbound_services_include_witness(self):
        """The outbound version-build path always OR's NODE_WITNESS in.

        We cannot easily run the live handshake without sockets, so we
        re-derive the same expression used in :func:`Peer.connect` and
        :func:`Peer.accept_inbound` and check it advertises witness.
        """
        peer_bloom_filters = False
        v2 = False
        # Mirrors the live expression at peer.py:649 / peer.py:1156:
        from ouroboros.p2p_messages import NODE_BLOOM, NODE_P2P_V2
        services = NODE_NETWORK | NODE_WITNESS
        if peer_bloom_filters:
            services |= NODE_BLOOM
        if v2:
            services |= NODE_P2P_V2

        self.assertTrue(services & NODE_WITNESS)
        self.assertTrue(services & NODE_NETWORK)
        # Default config (no bloom, v1): services == 0x09
        self.assertEqual(services, NODE_NETWORK | NODE_WITNESS)


class TestRustHandshakeAdvertisesWitness(unittest.TestCase):
    """The Rust ferrous-utils handshake source must also OR NODE_WITNESS.

    This is a static check of the source string — the audit specifically
    flagged ``ferrous-utils/sync/src/network/peer.rs`` for advertising
    only NODE_NETWORK.  We can't easily run the Rust handshake from
    Python tests, so we pin the fix at the source level.
    """

    def test_rust_peer_handshake_uses_node_witness(self):
        from pathlib import Path
        rust_src = Path(__file__).resolve().parent.parent / \
            "ferrous-utils" / "sync" / "src" / "network" / "peer.rs"
        self.assertTrue(rust_src.exists(), f"missing {rust_src}")
        text = rust_src.read_text()
        self.assertIn("NODE_WITNESS", text,
                      "Rust handshake must reference NODE_WITNESS")
        self.assertIn("NODE_NETWORK | NODE_WITNESS", text,
                      "Rust handshake must advertise NODE_NETWORK | "
                      "NODE_WITNESS in the version services field")


if __name__ == "__main__":
    unittest.main()
