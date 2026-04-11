"""
Functional test framework for Ouroboros Bitcoin node.

Provides TestNode and BitcoinTestFramework for multi-node functional tests,
similar to Bitcoin Core's test/functional/test_framework/.

Usage:
    class MyTest(BitcoinTestFramework):
        def set_test_params(self):
            self.num_nodes = 2

        async def run_test(self):
            node0 = self.nodes[0]
            node1 = self.nodes[1]
            # ... test logic ...

    if __name__ == "__main__":
        MyTest().main()
"""

import asyncio
import logging
import shutil
import tempfile
import time
from typing import Any

import httpx

logger = logging.getLogger("functional_test")


class TestNode:
    """A single Ouroboros node for functional testing."""

    def __init__(
        self,
        index: int,
        datadir: str,
        network: str = "regtest",
        rpc_port: int = 18443,
        p2p_port: int = 18444,
        extra_config: dict[str, Any] | None = None,
    ):
        self.index = index
        self.datadir = datadir
        self.network = network
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.config = extra_config or {}
        self._node = None
        self._task = None
        self._rpc_client: httpx.AsyncClient | None = None
        self._rpc_user = "testuser"
        self._rpc_pass = "testpass"
        self.running = False

    async def start(self):
        """Start the node."""
        from ouroboros.node import BitcoinNode

        self.config.update({
            "rpc_port": self.rpc_port,
            "p2p_port": self.p2p_port,
            "rpc_username": self._rpc_user,
            "rpc_password": self._rpc_pass,
        })

        self._node = BitcoinNode(
            data_dir=self.datadir,
            network=self.network,
            config=self.config,
        )
        self._node.start_time = time.time()

        self._task = asyncio.create_task(
            self._node.start(
                rpc_port=self.rpc_port,
                p2p_port=self.p2p_port,
            )
        )
        self.running = True

        self._rpc_client = httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{self.rpc_port}",
            auth=(self._rpc_user, self._rpc_pass),
            timeout=30.0,
        )

        # Wait for RPC to be ready
        for _ in range(30):
            try:
                result = await self.rpc("getblockchaininfo")
                if result is not None:
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)

    async def stop(self):
        """Stop the node."""
        if self._node:
            try:
                await self._node.stop()
            except Exception:
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._rpc_client:
            await self._rpc_client.aclose()
        self.running = False

    async def rpc(self, method: str, *params) -> Any:
        """Make an RPC call to this node."""
        if self._rpc_client is None:
            raise RuntimeError("Node not started")

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": list(params),
            "id": 1,
        }

        try:
            response = await self._rpc_client.post("/", json=payload)
            data = response.json()
            if data.get("error"):
                raise RuntimeError(f"RPC error: {data['error']}")
            return data.get("result")
        except httpx.ConnectError:
            return None

    async def generate(self, nblocks: int, address: str = None) -> list[str]:
        """Generate blocks (regtest only)."""
        if address is None:
            address = await self.rpc("getnewaddress")
        return await self.rpc("generatetoaddress", nblocks, address) or []

    async def getblockcount(self) -> int:
        result = await self.rpc("getblockcount")
        return result or 0

    async def getbalance(self) -> float:
        result = await self.rpc("getbalance")
        return result or 0.0

    def __repr__(self):
        return f"TestNode(index={self.index}, port={self.rpc_port})"


class BitcoinTestFramework:
    """
    Base class for functional tests.

    Subclass and implement set_test_params() and run_test().
    """

    def __init__(self):
        self.num_nodes = 1
        self.nodes: list[TestNode] = []
        self._tmpdirs: list[str] = []
        self.network = "regtest"
        self.log = logging.getLogger(self.__class__.__name__)

    def set_test_params(self):
        """Override to configure test parameters (num_nodes, etc.)."""
        pass

    async def setup_chain(self):
        """Override to set up the blockchain before node start."""
        pass

    async def setup_network(self):
        """Create and start nodes."""
        for i in range(self.num_nodes):
            tmpdir = tempfile.mkdtemp(prefix=f"ouroboros_test_{i}_")
            self._tmpdirs.append(tmpdir)

            node = TestNode(
                index=i,
                datadir=tmpdir,
                network=self.network,
                rpc_port=18443 + i * 2,
                p2p_port=18444 + i * 2,
            )
            self.nodes.append(node)

        for node in self.nodes:
            await node.start()

    async def run_test(self):
        """Override with actual test logic."""
        raise NotImplementedError

    async def cleanup(self):
        """Stop all nodes and clean up."""
        for node in self.nodes:
            try:
                await node.stop()
            except Exception as e:
                self.log.warning(f"Error stopping node {node.index}: {e}")

        for tmpdir in self._tmpdirs:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    def main(self):
        """Entry point for running the test."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        )

        self.set_test_params()

        async def _run():
            try:
                await self.setup_chain()
                await self.setup_network()
                self.log.info("Running test...")
                await self.run_test()
                self.log.info("Test PASSED")
            except Exception as e:
                self.log.error(f"Test FAILED: {e}")
                raise
            finally:
                await self.cleanup()

        asyncio.run(_run())


# ── Assertions ────────────────────────────────────────────────────────


def assert_equal(thing1, thing2, msg=""):
    if thing1 != thing2:
        raise AssertionError(
            f"{msg}: {thing1!r} != {thing2!r}" if msg else f"{thing1!r} != {thing2!r}"
        )


def assert_greater_than(thing1, thing2, msg=""):
    if thing1 <= thing2:
        raise AssertionError(
            f"{msg}: {thing1!r} <= {thing2!r}" if msg else f"{thing1!r} <= {thing2!r}"
        )


def assert_raises_rpc_error(code, message, fun, *args, **kwargs):
    """Assert that an RPC call raises an error with the given code and message."""
    try:
        result = fun(*args, **kwargs)
        raise AssertionError(f"Expected RPC error but got result: {result}")
    except RuntimeError as e:
        error_str = str(e)
        if message and message not in error_str:
            raise AssertionError(
                f"Expected error containing '{message}' but got: {error_str}"
            ) from None
