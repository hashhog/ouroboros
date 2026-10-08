"""
Release gate 8 (R5 operator subset) -- the seven T1 methods ouroboros missed
in the 2026-10-04 and 2026-10-08 regtest-lane measurements. Each expected
(code, message) / shape was read off a regtest bitcoind v31.99 (build-wallet)
on 2026-10-08:

  getblocktemplate [{}]                -> -8 "getblocktemplate must be called with
                                          the segwit rule set (call with {"rules": ["segwit"]})"
  getblocktemplate [{"mode": 5}]       -> -8 "Invalid mode"
  getblocktemplate [{"mode": "foo", "rules": ["segwit"]}] -> -8 "Invalid mode"
  getblocktemplate [{"rules": [5]}]    -> -3
  testmempoolaccept [["deadbeef"]]     -> -22 "TX decode failed: deadbeef Make sure
                                          the tx has at least one input."
  testmempoolaccept [[]]               -> -8 "Array must contain between 1 and 25 transactions."
  testmempoolaccept rows carry txid AND wtxid (rpc/mempool.cpp:353-354)
  sendrawtransaction ["deadbeef"]      -> -22 "TX decode failed. Make sure the tx
                                          has at least one input."
  addnode [addr, "notacommand"]        -> -1, message = help (starts with the signature)
  disconnectnode []                    -> -32602 "Only one of address and nodeid should be provided."
  disconnectnode [addr, -1]            -> -32602 (both given)
  disconnectnode [addr]                -> -29 (not connected)
  disconnectnode [null, 5]             -> -29 (by id, not connected)
  getnettotals                         -> has uploadtarget {timeframe 86400, target 0,
                                          target_reached false, serve_historical_blocks true,
                                          bytes_left_in_cycle 0, time_left_in_cycle 0}
  getrpcinfo                           -> {"active_commands": [{"method": "getrpcinfo",
                                          "duration": N}], "logpath": "<abs path>"}

Every request goes through the real dispatcher (_execute_single_rpc) so the
RpcError -> JSON-RPC envelope mapping is exercised end to end.
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

# The R5 probe's missing-inputs transaction (tools/r5-probes.jsonl): a segwit
# output, no witness, so wtxid == txid.
MISSING_INPUTS_TX = (
    "020000000101000000000000000000000000000000000000000000000000000000000000"
    "000000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3"
    "a323f1433bd600000000"
)
MISSING_INPUTS_TXID = "5df91f99045afe09848faea0ccad4f30937be5775bf19044c4ba1fbedca54a62"


class _PeerManagerStub:
    def __init__(self):
        self.peers = {}
        self.block_relay_peers = {}
        self.inbound_peers = {}
        self.ban_manager = BanManager()


def _make_server():
    node = BitcoinNode(data_dir=tempfile.mkdtemp(), network="regtest")
    return RPCServer(node, port=18332), node


def _dispatch(rpc, method, params):
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    return asyncio.run(rpc._execute_single_rpc(req))


def _err(resp):
    e = resp.get("error")
    return (e["code"], e["message"]) if e else None


class TestGetBlockTemplateRequest(unittest.TestCase):
    def setUp(self):
        self.rpc, self.node = _make_server()

    def test_missing_segwit_rule(self):
        self.assertEqual(
            _err(_dispatch(self.rpc, "getblocktemplate", [{}])),
            (-8, 'getblocktemplate must be called with the segwit rule set '
                 '(call with {"rules": ["segwit"]})'))

    def test_rules_not_an_array_is_ignored(self):
        code, _ = _err(_dispatch(self.rpc, "getblocktemplate", [{"rules": "segwit"}]))
        self.assertEqual(code, -8)

    def test_non_string_rule(self):
        code, _ = _err(_dispatch(self.rpc, "getblocktemplate", [{"rules": [5]}]))
        self.assertEqual(code, -3)

    def test_invalid_mode(self):
        self.assertEqual(_err(_dispatch(self.rpc, "getblocktemplate", [{"mode": 5}])),
                         (-8, "Invalid mode"))
        self.assertEqual(
            _err(_dispatch(self.rpc, "getblocktemplate",
                           [{"mode": "foo", "rules": ["segwit"]}])),
            (-8, "Invalid mode"))

    def test_null_request_is_type_error(self):
        code, _ = _err(_dispatch(self.rpc, "getblocktemplate", [None]))
        self.assertEqual(code, -3)


class TestTestMempoolAccept(unittest.TestCase):
    def setUp(self):
        self.rpc, self.node = _make_server()

    def test_decode_error(self):
        self.assertEqual(
            _err(_dispatch(self.rpc, "testmempoolaccept", [["deadbeef"]])),
            (-22, "TX decode failed: deadbeef Make sure the tx has at least one input."))

    def test_one_bad_entry_fails_whole_call(self):
        code, _ = _err(_dispatch(self.rpc, "testmempoolaccept",
                                 [[MISSING_INPUTS_TX, "zz"]]))
        self.assertEqual(code, -22)

    def test_array_size(self):
        self.assertEqual(
            _err(_dispatch(self.rpc, "testmempoolaccept", [[]])),
            (-8, "Array must contain between 1 and 25 transactions."))

    def test_rows_carry_wtxid(self):
        resp = _dispatch(self.rpc, "testmempoolaccept", [[MISSING_INPUTS_TX]])
        self.assertIsNone(resp.get("error"))
        row = resp["result"][0]
        self.assertEqual(row["txid"], MISSING_INPUTS_TXID)
        self.assertEqual(row["wtxid"], MISSING_INPUTS_TXID)


class TestSendRawTransactionDecode(unittest.TestCase):
    def test_decode_error(self):
        rpc, _ = _make_server()
        for bad in ("deadbeef", "zz"):
            self.assertEqual(
                _err(_dispatch(rpc, "sendrawtransaction", [bad])),
                (-22, "TX decode failed. Make sure the tx has at least one input."))


class TestAddNodeCommand(unittest.TestCase):
    def test_invalid_command(self):
        rpc, node = _make_server()
        node.peer_manager = _PeerManagerStub()
        code, msg = _err(_dispatch(rpc, "addnode", ["192.0.2.1:8333", "notacommand"]))
        self.assertEqual(code, -1)
        self.assertTrue(msg.startswith('addnode "node" "command" ( v2transport )'))


class TestDisconnectNodeArgs(unittest.TestCase):
    def setUp(self):
        self.rpc, self.node = _make_server()
        self.node.peer_manager = _PeerManagerStub()

    def test_no_target(self):
        self.assertEqual(
            _err(_dispatch(self.rpc, "disconnectnode", [])),
            (-32602, "Only one of address and nodeid should be provided."))

    def test_both_targets(self):
        code, _ = _err(_dispatch(self.rpc, "disconnectnode", ["127.0.0.1:8333", -1]))
        self.assertEqual(code, -32602)

    def test_by_address_not_connected(self):
        code, _ = _err(_dispatch(self.rpc, "disconnectnode", ["127.0.0.1:8333"]))
        self.assertEqual(code, -29)

    def test_by_id_not_connected(self):
        code, _ = _err(_dispatch(self.rpc, "disconnectnode", [None, 5]))
        self.assertEqual(code, -29)
        code, _ = _err(_dispatch(self.rpc, "disconnectnode", ["", 5]))
        self.assertEqual(code, -29)


class TestGetNetTotals(unittest.TestCase):
    def test_uploadtarget(self):
        rpc, _ = _make_server()
        resp = _dispatch(rpc, "getnettotals", [])
        r = resp["result"]
        for k in ("totalbytesrecv", "totalbytessent", "timemillis"):
            self.assertIsInstance(r[k], int)
        self.assertEqual(r["uploadtarget"], {
            "timeframe": 86400, "target": 0, "target_reached": False,
            "serve_historical_blocks": True, "bytes_left_in_cycle": 0,
            "time_left_in_cycle": 0,
        })

    def test_totals_are_process_wide(self):
        from ouroboros import peer as peer_mod
        rpc, _ = _make_server()
        before = _dispatch(rpc, "getnettotals", [])["result"]
        peer_mod.NET_TOTALS["recv"] += 7
        peer_mod.NET_TOTALS["sent"] += 11
        after = _dispatch(rpc, "getnettotals", [])["result"]
        self.assertEqual(after["totalbytesrecv"] - before["totalbytesrecv"], 7)
        self.assertEqual(after["totalbytessent"] - before["totalbytessent"], 11)


class TestGetRpcInfo(unittest.TestCase):
    def test_shape(self):
        rpc, _ = _make_server()
        r = _dispatch(rpc, "getrpcinfo", [])["result"]
        self.assertEqual([c["method"] for c in r["active_commands"]], ["getrpcinfo"])
        self.assertIsInstance(r["active_commands"][0]["duration"], int)
        self.assertIsInstance(r["logpath"], str)

    def test_finished_calls_leave_the_list(self):
        rpc, _ = _make_server()
        _dispatch(rpc, "getnettotals", [])
        r = _dispatch(rpc, "getrpcinfo", [])["result"]
        self.assertEqual([c["method"] for c in r["active_commands"]], ["getrpcinfo"])


if __name__ == "__main__":
    unittest.main()
