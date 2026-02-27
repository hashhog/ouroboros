"""
Functional test: basic RPC operations.

Tests that a single node can start, respond to RPC calls, and serve
blockchain information.
"""

import asyncio
import pytest
from tests.functional.framework import (
    BitcoinTestFramework, assert_equal, assert_greater_than,
)


class RPCBasicsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    async def run_test(self):
        node = self.nodes[0]

        # getblockchaininfo
        info = await node.rpc("getblockchaininfo")
        assert info is not None, "getblockchaininfo returned None"
        assert "chain" in info, "Missing 'chain' in blockchaininfo"

        # getblockcount
        count = await node.rpc("getblockcount")
        assert isinstance(count, int), f"Expected int, got {type(count)}"

        # getmempoolinfo
        mempool = await node.rpc("getmempoolinfo")
        assert mempool is not None
        assert "size" in mempool

        # getnetworkinfo
        netinfo = await node.rpc("getnetworkinfo")
        assert netinfo is not None
        assert "version" in netinfo

        # help
        help_text = await node.rpc("help")
        assert help_text is not None
        assert "getblockchaininfo" in help_text

        # uptime
        uptime = await node.rpc("uptime")
        assert isinstance(uptime, int)

        # validateaddress
        result = await node.rpc("validateaddress", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result is not None
        assert "isvalid" in result

        # estimatesmartfee
        fee = await node.rpc("estimatesmartfee", 6)
        assert fee is not None

        self.log.info("All basic RPC tests passed")


@pytest.mark.asyncio
@pytest.mark.skipif(
    not __import__("os").environ.get("OUROBOROS_LIVE_TESTS"),
    reason="Requires running node (set OUROBOROS_LIVE_TESTS=1)",
)
async def test_rpc_basics():
    """Run the RPC basics test as a pytest."""
    test = RPCBasicsTest()
    test.set_test_params()
    try:
        await test.setup_network()
        await test.run_test()
    finally:
        await test.cleanup()


if __name__ == "__main__":
    RPCBasicsTest().main()
