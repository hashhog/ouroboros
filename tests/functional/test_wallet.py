"""
Functional test: wallet operations.

Tests address generation, balance queries, and wallet info.
"""

import pytest

from tests.functional.framework import BitcoinTestFramework


class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    async def run_test(self):
        node = self.nodes[0]

        # getnewaddress
        addr = await node.rpc("getnewaddress")
        assert addr is not None, "getnewaddress returned None"
        self.log.info(f"Generated address: {addr}")

        # getwalletinfo
        info = await node.rpc("getwalletinfo")
        assert info is not None
        assert "walletname" in info

        # listwallets
        wallets = await node.rpc("listwallets")
        assert isinstance(wallets, list)

        # getaddressinfo
        addr_info = await node.rpc("getaddressinfo", addr)
        assert addr_info is not None
        assert "address" in addr_info

        # listunspent
        unspent = await node.rpc("listunspent")
        assert isinstance(unspent, list)

        self.log.info("All wallet tests passed")


@pytest.mark.asyncio
@pytest.mark.skipif(
    not __import__("os").environ.get("OUROBOROS_LIVE_TESTS"),
    reason="Requires running node (set OUROBOROS_LIVE_TESTS=1)",
)
async def test_wallet():
    """Run wallet test as pytest."""
    test = WalletTest()
    test.set_test_params()
    try:
        await test.setup_network()
        await test.run_test()
    finally:
        await test.cleanup()


if __name__ == "__main__":
    WalletTest().main()
