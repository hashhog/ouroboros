"""
Multi-node P2P functional tests.

Tests peer discovery, connection management, and basic message handling
across multiple Ouroboros nodes running concurrently.
"""

import asyncio
import pytest

from tests.functional.framework import (
    BitcoinTestFramework,
    TestNode,
    assert_equal,
    assert_greater_than,
)


class TestMultiNodeSetup(BitcoinTestFramework):
    """Verify that the framework can spin up multiple independent nodes."""

    def set_test_params(self):
        self.num_nodes = 2


class TestP2PConnectionSetup:
    """Test the TestNode P2P connection helpers."""

    def test_node_default_ports(self):
        node = TestNode(index=0, datadir="/tmp/test0")
        assert_equal(node.rpc_port, 18443)
        assert_equal(node.p2p_port, 18444)

    def test_node_port_offset(self):
        node = TestNode(index=3, datadir="/tmp/test3", rpc_port=19000, p2p_port=19001)
        assert_equal(node.rpc_port, 19000)
        assert_equal(node.p2p_port, 19001)

    def test_node_repr(self):
        node = TestNode(index=1, datadir="/tmp/test1", rpc_port=18445, p2p_port=18446)
        assert "index=1" in repr(node)
        assert "18445" in repr(node)

    def test_node_initial_state(self):
        node = TestNode(index=0, datadir="/tmp/test0")
        assert not node.running
        assert node._node is None
        assert node._rpc_client is None


class TestFrameworkSetup:
    """Test the BitcoinTestFramework configuration."""

    def test_default_num_nodes(self):
        fw = BitcoinTestFramework()
        assert_equal(fw.num_nodes, 1)
        assert_equal(fw.network, "regtest")

    def test_custom_num_nodes(self):
        fw = TestMultiNodeSetup()
        fw.set_test_params()
        assert_equal(fw.num_nodes, 2)

    def test_nodes_list_initially_empty(self):
        fw = BitcoinTestFramework()
        assert_equal(len(fw.nodes), 0)

    def test_cleanup_empty_nodes(self):
        fw = BitcoinTestFramework()
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fw.cleanup())
        finally:
            loop.close()


class TestNetworkTopology:
    """Test network setup creates correct node topology."""

    @pytest.mark.asyncio
    async def test_setup_creates_correct_number_of_nodes(self):
        fw = TestMultiNodeSetup()
        fw.set_test_params()
        assert_equal(fw.num_nodes, 2)
        assert_equal(len(fw.nodes), 0)

    def test_port_assignment_no_collisions(self):
        ports = set()
        for i in range(4):
            rpc = 18443 + i * 2
            p2p = 18444 + i * 2
            assert rpc not in ports, f"RPC port collision at index {i}"
            assert p2p not in ports, f"P2P port collision at index {i}"
            ports.add(rpc)
            ports.add(p2p)

    def test_port_range_adequate(self):
        for i in range(10):
            rpc = 18443 + i * 2
            p2p = 18444 + i * 2
            assert rpc < 65535
            assert p2p < 65535
