"""ParseHashV error-code parity (ouroboros) — malformed txid/blockhash.

Bitcoin Core rejects a malformed txid/blockhash RPC argument at the PARSE
boundary, BEFORE any lookup, with RPC_INVALID_PARAMETER (-8):

  * wrong length  -> "<name> must be of length 64 (not N, for '<hex>')"
  * right length, non-hex -> "<name> must be hexadecimal string (not '<hex>')"

Reference:
  bitcoin-core/src/rpc/util.cpp:117  ParseHashV
  bitcoin-core/src/rpc/protocol.h    RPC_INVALID_PARAMETER = -8,
                                     RPC_INVALID_ADDRESS_OR_KEY = -5
  call sites:
    getrawtransaction  rawtransaction.cpp:287/300  "parameter 1"/"parameter 3"
    gettxout           blockchain.cpp:1224          "txid"
    getblock           blockchain.cpp:842           "blockhash"
    getblockheader     blockchain.cpp:639           "hash"
    getmempoolentry    mempool.cpp:880              "txid"

The KEY distinction this file pins (both directions, per method):
  (a) malformed arg               -> error code -8
  (b) well-formed-but-absent hash -> still -5 (or null for gettxout)
"""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap — tests/conftest.py installs the `sync` Rust stub.
# ---------------------------------------------------------------------------
_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))
_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))
import conftest  # noqa: E402,F401  - installs sync stub

from ouroboros.node import BitcoinNode  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402

# Core RPC error codes (protocol.h).
RPC_INVALID_ADDRESS_OR_KEY = -5
RPC_INVALID_PARAMETER = -8
RPC_INTERNAL_ERROR = -32603

ZERO64 = "0" * 64          # well-formed, 64-hex, but absent from any store
SHORT_HEX = "abc"          # too short (3 chars)
NONHEX64 = "z" * 64        # right length, non-hex chars


# ---------------------------------------------------------------------------
# Minimal stores so the well-formed-but-absent path reaches the handler's
# Core-coded not-found branch (-5 / null) instead of an "unavailable" guard.
# Every lookup returns "absent".
# ---------------------------------------------------------------------------
class _RawDB:
    def get_raw_header_with_chainwork(self, h):
        return None


class _AbsentDB:
    def __init__(self):
        self._db = _RawDB()

    def get_block(self, h):
        return None

    def get_block_bytes(self, h):
        return None

    def get_best_block(self):
        return (b"\x00" * 32, 0)

    def get_utxo(self, txid, n):
        return None

    def get_block_hash_by_height(self, height):
        return None


class _AbsentMempool:
    def has_transaction(self, txid):
        return False

    def get_transaction(self, txid):
        return None

    def get_transaction_entry(self, txid):
        return None


def _make_server():
    temp = tempfile.mkdtemp()
    node = BitcoinNode(data_dir=temp, network="regtest")
    node.db = _AbsentDB()
    node.mempool = _AbsentMempool()
    rpc = RPCServer(node, port=18332)
    return rpc, node, temp


def _dispatch(rpc, method, params):
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    return asyncio.run(rpc._execute_single_rpc(req))


def _code(resp):
    if "error" in resp and resp["error"] is not None:
        return resp["error"].get("code")
    return None


def _result(resp):
    return resp.get("result")


class TestParseHashVErrorCodes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rpc, cls.node, cls.tempdir = _make_server()

    # -- gettxout (txid) ---------------------------------------------------
    def test_gettxout_malformed_short(self):
        resp = _dispatch(self.rpc, "gettxout", [SHORT_HEX, 0])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("must be of length 64", resp["error"]["message"])

    def test_gettxout_malformed_nonhex(self):
        resp = _dispatch(self.rpc, "gettxout", [NONHEX64, 0])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("hexadecimal string", resp["error"]["message"])

    def test_gettxout_wellformed_absent_is_null(self):
        # Core: gettxout for an unknown-but-well-formed outpoint -> null.
        resp = _dispatch(self.rpc, "gettxout", [ZERO64, 0])
        self.assertIsNone(_code(resp))
        self.assertIsNone(_result(resp))

    # -- getblock (blockhash) ---------------------------------------------
    def test_getblock_malformed_short(self):
        resp = _dispatch(self.rpc, "getblock", [SHORT_HEX, 1])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("must be of length 64", resp["error"]["message"])

    def test_getblock_malformed_nonhex(self):
        resp = _dispatch(self.rpc, "getblock", [NONHEX64, 1])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("hexadecimal string", resp["error"]["message"])

    def test_getblock_wellformed_absent_is_minus5(self):
        # Core: getblock(unknown well-formed hash) -> -5 "Block not found".
        resp = _dispatch(self.rpc, "getblock", [ZERO64, 1])
        self.assertEqual(_code(resp), RPC_INVALID_ADDRESS_OR_KEY)

    # -- getblockheader (hash) --------------------------------------------
    def test_getblockheader_malformed_short(self):
        resp = _dispatch(self.rpc, "getblockheader", [SHORT_HEX])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("must be of length 64", resp["error"]["message"])

    def test_getblockheader_malformed_nonhex(self):
        resp = _dispatch(self.rpc, "getblockheader", [NONHEX64])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("hexadecimal string", resp["error"]["message"])

    def test_getblockheader_wellformed_absent_is_minus5(self):
        resp = _dispatch(self.rpc, "getblockheader", [ZERO64])
        self.assertEqual(_code(resp), RPC_INVALID_ADDRESS_OR_KEY)

    # -- getmempoolentry (txid) -------------------------------------------
    def test_getmempoolentry_malformed_short(self):
        resp = _dispatch(self.rpc, "getmempoolentry", [SHORT_HEX])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("must be of length 64", resp["error"]["message"])

    def test_getmempoolentry_malformed_nonhex(self):
        resp = _dispatch(self.rpc, "getmempoolentry", [NONHEX64])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)
        self.assertIn("hexadecimal string", resp["error"]["message"])

    def test_getmempoolentry_wellformed_absent_is_minus5(self):
        # Core: getmempoolentry(unknown txid) -> -5 "Transaction not in mempool".
        resp = _dispatch(self.rpc, "getmempoolentry", [ZERO64])
        self.assertEqual(_code(resp), RPC_INVALID_ADDRESS_OR_KEY)

    # -- getrawtransaction (txid) — AUDIT-NOOP, already -8 ------------------
    def test_getrawtransaction_malformed_short(self):
        resp = _dispatch(self.rpc, "getrawtransaction", [SHORT_HEX])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)

    def test_getrawtransaction_malformed_nonhex(self):
        resp = _dispatch(self.rpc, "getrawtransaction", [NONHEX64])
        self.assertEqual(_code(resp), RPC_INVALID_PARAMETER)

    def test_getrawtransaction_wellformed_absent_is_minus5(self):
        # No -txindex / no block hash -> Core -5 not-found family.
        resp = _dispatch(self.rpc, "getrawtransaction", [ZERO64])
        self.assertEqual(_code(resp), RPC_INVALID_ADDRESS_OR_KEY)


if __name__ == "__main__":
    unittest.main()
