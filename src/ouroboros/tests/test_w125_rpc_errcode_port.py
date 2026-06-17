"""
W125 FIX wave — JSON-RPC error-code parity (ouroboros), ported from the
verified rustoshi fixes.

These four cases each map a bad-input RPC to the specific Bitcoin Core
JSON-RPC error code from bitcoin-core/src/rpc/protocol.h:

  1. getblockhash, out-of-range height
       -> RPC_INVALID_PARAMETER (-8) "Block height out of range"
       Core rpc/blockchain.cpp getblockhash (blockchain.cpp:590-591);
       rustoshi ee86d76.
  2. addnode "add" an already-added node
       -> RPC_CLIENT_NODE_ALREADY_ADDED (-23) "Error: Node already added";
     addnode "remove" a node not on the added list
       -> RPC_CLIENT_NODE_NOT_ADDED (-24)
          "Error: Node could not be removed. It has not been added previously."
       Core rpc/net.cpp addnode (net.cpp:359-369; protocol.h:60-61);
       rustoshi 7b94ef1.
  3. setban with an invalid IP/subnet string
       -> RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) "Error: Invalid IP/Subnet"
       Core rpc/net.cpp setban (net.cpp:776-781; protocol.h:63);
       rustoshi 980a31d.
  4. disconnectnode for a peer not currently connected
       -> RPC_CLIENT_NODE_NOT_CONNECTED (-29) "Node not found in connected nodes"
       Core rpc/net.cpp disconnectnode (net.cpp:458-482; protocol.h:62);
       rustoshi 845f7e4.

Each test drives the request through the real RPCServer dispatcher
(`_execute_single_rpc`) so the RpcError -> JSON-RPC error-envelope mapping is
exercised end-to-end. Lightweight stubs supply only the handler surface each
RPC touches (a fake db / peer_manager), keeping the tests fast and hermetic
while running the real handler logic. WITHOUT the fix each handler returns the
generic -32603 (or silent success), so each assertion fails on the unfixed tree
— see the mutation-check in the porting report.
"""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))

_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))
import conftest  # noqa: E402,F401  - installs sync stub

from ouroboros.banman import BanManager  # noqa: E402
from ouroboros.node import BitcoinNode  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402

# Bitcoin Core RPC error codes (bitcoin-core/src/rpc/protocol.h).
RPC_INVALID_PARAMETER = -8
RPC_CLIENT_NODE_ALREADY_ADDED = -23
RPC_CLIENT_NODE_NOT_ADDED = -24
RPC_CLIENT_NODE_NOT_CONNECTED = -29
RPC_CLIENT_INVALID_IP_OR_SUBNET = -30
RPC_INTERNAL_ERROR = -32603


# --------------------------------------------------------------------------
# Lightweight stubs — only the surface each handler reaches.
# --------------------------------------------------------------------------

class _DbStub:
    """Minimal db with a fixed tip height for getblockhash range checks."""

    def __init__(self, tip_height: int):
        self._tip_height = tip_height

    def get_best_block(self):
        # Core's getblockhash compares against active_chain.Height(); the
        # in-range lookup itself never fires for the out-of-range case.
        return (b"\x00" * 32, self._tip_height)

    def get_block_by_height(self, height):
        return None


class _PeerStub:
    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


class _PeerManagerStub:
    """Peer manager exposing the connected-peer maps + a real BanManager."""

    def __init__(self, peers=None):
        self.peers = dict(peers or {})
        self.block_relay_peers = {}
        self.inbound_peers = {}
        self.ban_manager = BanManager()  # no data_dir -> in-memory only


def _make_server():
    temp = tempfile.mkdtemp()
    node = BitcoinNode(data_dir=temp, network="regtest")
    rpc = RPCServer(node, port=18332)
    return rpc, node


def _dispatch(rpc, method, params):
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    return asyncio.run(rpc._execute_single_rpc(req))


def _code(resp):
    err = resp.get("error")
    if err is not None:
        return err.get("code")
    return None


class TestW125PortedErrorCodes(unittest.TestCase):

    def setUp(self):
        self.rpc, self.node = _make_server()

    # ---- Fix 1: getblockhash out-of-range -> -8 ---------------------------

    def test_getblockhash_above_tip_invalid_parameter(self):
        """Height beyond the tip -> RPC_INVALID_PARAMETER (-8) with Core's
        static 'Block height out of range' message (blockchain.cpp:590-591).
        """
        self.node.db = _DbStub(tip_height=100)
        resp = _dispatch(self.rpc, "getblockhash", [99999])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertEqual(resp["error"]["message"], "Block height out of range")

    def test_getblockhash_negative_invalid_parameter(self):
        """Negative height -> -8 (Core: height < 0 branch)."""
        self.node.db = _DbStub(tip_height=100)
        resp = _dispatch(self.rpc, "getblockhash", [-1])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)

    def test_getblockhash_in_range_not_param_error(self):
        """Success-path guard: an in-range height must NOT be turned into a
        -8 by the new bound check (it falls through to the lookup, which the
        stub reports absent -> the pre-existing not-found path, NOT -8).
        """
        self.node.db = _DbStub(tip_height=100)
        resp = _dispatch(self.rpc, "getblockhash", [50])
        self.assertNotEqual(_code(resp), RPC_INVALID_PARAMETER)

    # ---- Fix 2: addnode duplicate-add / remove-unknown -> -23 / -24 -------

    def test_addnode_add_then_duplicate_already_added(self):
        """Second 'add' of the same node -> RPC_CLIENT_NODE_ALREADY_ADDED
        (-23) 'Error: Node already added' (net.cpp:362; protocol.h:60).
        """
        self.node.peer_manager = _PeerManagerStub()
        first = _dispatch(self.rpc, "addnode", ["127.0.0.1:12345", "add"])
        self.assertIsNone(_code(first))  # first add succeeds
        second = _dispatch(self.rpc, "addnode", ["127.0.0.1:12345", "add"])
        self.assertEqual(_code(second), RPC_CLIENT_NODE_ALREADY_ADDED)
        self.assertEqual(second["error"]["message"], "Error: Node already added")

    def test_addnode_remove_unknown_node_not_added(self):
        """'remove' of a never-added node -> RPC_CLIENT_NODE_NOT_ADDED (-24)
        with Core's exact message (net.cpp:368; protocol.h:61).
        """
        self.node.peer_manager = _PeerManagerStub()
        resp = _dispatch(self.rpc, "addnode", ["127.0.0.1:9999", "remove"])
        self.assertEqual(_code(resp), RPC_CLIENT_NODE_NOT_ADDED)
        self.assertEqual(
            resp["error"]["message"],
            "Error: Node could not be removed. "
            "It has not been added previously.",
        )

    def test_addnode_add_then_remove_succeeds(self):
        """Success-path guard: add then remove of the same node both succeed
        (no spurious error)."""
        self.node.peer_manager = _PeerManagerStub()
        _dispatch(self.rpc, "addnode", ["127.0.0.1:5555", "add"])
        resp = _dispatch(self.rpc, "addnode", ["127.0.0.1:5555", "remove"])
        self.assertIsNone(_code(resp))

    # ---- Fix 3: setban invalid IP/subnet -> -30 --------------------------

    def test_setban_invalid_ip_invalid_ip_or_subnet(self):
        """A bare hostname/garbage subnet -> RPC_CLIENT_INVALID_IP_OR_SUBNET
        (-30) 'Error: Invalid IP/Subnet' (net.cpp:780; protocol.h:63).
        """
        self.node.peer_manager = _PeerManagerStub()
        resp = _dispatch(self.rpc, "setban", ["not-an-ip", "add"])
        self.assertEqual(_code(resp), RPC_CLIENT_INVALID_IP_OR_SUBNET)
        self.assertEqual(resp["error"]["message"], "Error: Invalid IP/Subnet")

    def test_setban_bad_octet_invalid_ip_or_subnet(self):
        """An out-of-range octet is also rejected at the parse boundary."""
        self.node.peer_manager = _PeerManagerStub()
        resp = _dispatch(self.rpc, "setban", ["999.1.1.1", "add"])
        self.assertEqual(_code(resp), RPC_CLIENT_INVALID_IP_OR_SUBNET)

    def test_setban_valid_ip_succeeds(self):
        """Success-path guard: a valid bare IP and a valid CIDR subnet both
        ban cleanly (no -30)."""
        self.node.peer_manager = _PeerManagerStub()
        r1 = _dispatch(self.rpc, "setban", ["192.168.0.6", "add"])
        self.assertIsNone(_code(r1))
        r2 = _dispatch(self.rpc, "setban", ["10.0.0.0/24", "add"])
        self.assertIsNone(_code(r2))

    # ---- Fix 4: disconnectnode of an unconnected peer -> -29 -------------

    def test_disconnectnode_unknown_not_connected(self):
        """disconnectnode for a peer that is not in any connected-peer map ->
        RPC_CLIENT_NODE_NOT_CONNECTED (-29) 'Node not found in connected
        nodes' (net.cpp:478; protocol.h:62).
        """
        self.node.peer_manager = _PeerManagerStub()  # no peers connected
        resp = _dispatch(self.rpc, "disconnectnode", ["127.0.0.1:65535", -1])
        self.assertEqual(_code(resp), RPC_CLIENT_NODE_NOT_CONNECTED)
        self.assertEqual(
            resp["error"]["message"], "Node not found in connected nodes"
        )

    def test_disconnectnode_connected_peer_succeeds(self):
        """Success-path guard: disconnecting a genuinely-connected peer
        severs it and returns success (no -29)."""
        peer = _PeerStub()
        pm = _PeerManagerStub(peers={"127.0.0.1:8333": peer})
        self.node.peer_manager = pm
        resp = _dispatch(self.rpc, "disconnectnode", ["127.0.0.1:8333", -1])
        self.assertIsNone(_code(resp))
        self.assertTrue(peer.disconnected)
        self.assertNotIn("127.0.0.1:8333", pm.peers)


if __name__ == "__main__":
    unittest.main()
