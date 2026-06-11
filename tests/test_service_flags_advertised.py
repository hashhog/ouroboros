"""Service-flags advertisement tests (service-flags campaign, 2026-06-11).

Verifies the bitset ouroboros advertises in its ``version`` handshake matches
Bitcoin Core's ``g_local_services`` for a full (non-pruned) witness node.

Core reference (bitcoin-core/src/init.cpp):
  - line 863: g_local_services = NODE_NETWORK_LIMITED | NODE_WITNESS  (UNCONDITIONAL)
  - line 1950: g_local_services |= NODE_NETWORK    (only when NOT pruning)
  - line 989:  g_local_services |= NODE_P2P_V2     (when v2 transport enabled)

So a full non-pruned node's base set is:
  NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400) = 0x409

Regression target: before the 2026-06-11 fix, NODE_NETWORK_LIMITED was gated on
``self.node_network_limited`` (set from prune>0, default False), so a default
full node advertised only 0x9 and falsely withheld the NODE_NETWORK_LIMITED bit.
"""

import unittest

from ouroboros.p2p_messages import (
    NODE_BLOOM,
    NODE_COMPACT_FILTERS,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
    NODE_WITNESS,
)
from ouroboros.peer import Peer

FULL_NODE_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED  # 0x409


class TestAdvertisedServiceFlags(unittest.TestCase):
    """The advertised services bitset must match Core's full-node set."""

    def test_constants_have_canonical_values(self):
        self.assertEqual(NODE_NETWORK, 0x1)
        self.assertEqual(NODE_WITNESS, 0x8)
        self.assertEqual(NODE_NETWORK_LIMITED, 0x400)
        self.assertEqual(NODE_P2P_V2, 0x800)
        self.assertEqual(FULL_NODE_SERVICES, 0x409)

    def test_default_full_node_advertises_0x409(self):
        """A default (non-pruned, v1) full node advertises exactly 0x409."""
        peer = Peer("10.0.0.1", 8333, "mainnet")
        services = peer._assemble_our_services()
        self.assertEqual(
            services,
            FULL_NODE_SERVICES,
            f"expected 0x409, got {services:#x}",
        )

    def test_network_limited_advertised_unconditionally(self):
        """NODE_NETWORK_LIMITED is set even when node_network_limited is False.

        This is the core of the fix: the bit must NOT be gated on prune mode.
        """
        peer = Peer("10.0.0.1", 8333, "mainnet", node_network_limited=False)
        self.assertFalse(peer.node_network_limited)
        services = peer._assemble_our_services()
        self.assertTrue(
            services & NODE_NETWORK_LIMITED,
            "NODE_NETWORK_LIMITED must be advertised by a full node regardless "
            "of prune mode",
        )

    def test_network_and_witness_always_present(self):
        peer = Peer("10.0.0.1", 8333, "mainnet")
        services = peer._assemble_our_services()
        self.assertTrue(services & NODE_NETWORK, "NODE_NETWORK missing")
        self.assertTrue(services & NODE_WITNESS, "NODE_WITNESS missing")

    def test_prune_flag_does_not_change_advertised_set(self):
        """Whether or not the prune-derived flag is set, 0x409 is advertised.

        (Core would drop NODE_NETWORK when actually pruning, but ouroboros's
        node_network_limited flag historically only toggled the LIMITED bit;
        the fix makes LIMITED unconditional so both inputs yield 0x409.)
        """
        peer_off = Peer("10.0.0.1", 8333, "mainnet", node_network_limited=False)
        peer_on = Peer("10.0.0.2", 8333, "mainnet", node_network_limited=True)
        self.assertEqual(peer_off._assemble_our_services(), FULL_NODE_SERVICES)
        self.assertEqual(peer_on._assemble_our_services(), FULL_NODE_SERVICES)

    def test_no_bloom_or_compact_filters_by_default(self):
        """Default node does not advertise NODE_BLOOM / NODE_COMPACT_FILTERS."""
        peer = Peer("10.0.0.1", 8333, "mainnet")
        services = peer._assemble_our_services()
        self.assertFalse(services & NODE_BLOOM, "NODE_BLOOM should be off by default")
        self.assertFalse(
            services & NODE_COMPACT_FILTERS,
            "NODE_COMPACT_FILTERS should be off by default",
        )

    def test_p2p_v2_advertised_only_on_v2_transport(self):
        """NODE_P2P_V2 is honest: set iff this connection negotiated v2."""
        peer_v1 = Peer("10.0.0.1", 8333, "mainnet", transport_version=1)
        peer_v2 = Peer("10.0.0.2", 8333, "mainnet", transport_version=2)
        self.assertFalse(
            peer_v1._assemble_our_services() & NODE_P2P_V2,
            "v1 connection must not advertise NODE_P2P_V2",
        )
        self.assertTrue(
            peer_v2._assemble_our_services() & NODE_P2P_V2,
            "v2 connection must advertise NODE_P2P_V2",
        )
        # With v2, the full set is 0xC09.
        self.assertEqual(
            peer_v2._assemble_our_services(),
            FULL_NODE_SERVICES | NODE_P2P_V2,
        )

    def test_assembled_services_match_emitted_version_message(self):
        """The helper output is what gets stamped onto self.our_services.

        Guards against the helper drifting from the value the handshake
        actually writes onto the wire (both _handshake and _inbound_handshake
        set self.our_services = self._assemble_our_services()).
        """
        peer = Peer("10.0.0.1", 8333, "mainnet")
        peer.our_services = peer._assemble_our_services()
        self.assertEqual(peer.our_services, FULL_NODE_SERVICES)


if __name__ == "__main__":
    unittest.main()
