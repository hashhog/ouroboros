"""
W125 — JSON-RPC error code parity audit (ouroboros).

DISCOVERY wave: 30 gates audited against bitcoin-core/src/rpc/protocol.h.
This file contains an xfail test per Core-divergent gate, asserting the
Core-expected `error.code` for a representative call. As the fleet
closes the audit gaps in a future FIX wave each xfail will flip to pass.

Reference: bitcoin-core/src/rpc/protocol.h enum RPCErrorCode
           bitcoin-core/src/rpc/request.cpp::JSONRPCError
           bitcoin-core/src/rpc/{blockchain,rawtransaction,mempool,
                                mining,net,fees,util}.cpp call sites

Two-pipeline guard: this file imports only `RPCServer` from the Python
pipeline. The Rust `ferrous-utils/` crate doesn't serve JSON-RPC so the
audit has no Rust surface to touch.

NO production code changes. NO behavior changes. Only audit + xfail
tests.
"""

import asyncio
import re
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Bootstrap — tests/conftest.py installs the sync stub. We do the same
# import-once dance here so the file is self-contained when pytest
# collects it.
# ---------------------------------------------------------------------------
_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))

# Use the tests/conftest.py mock if present (it installs `sync` mock).
_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))
import conftest  # noqa: E402,F401  - installs sync stub

from ouroboros.node import BitcoinNode  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402


# ---------------------------------------------------------------------------
# Bitcoin Core's RPC error codes per bitcoin-core/src/rpc/protocol.h.
# Mirrored as plain ints because ouroboros does not expose an enum.
# ---------------------------------------------------------------------------
RPC_INVALID_REQUEST            = -32600
RPC_METHOD_NOT_FOUND           = -32601
RPC_INVALID_PARAMS             = -32602
RPC_INTERNAL_ERROR             = -32603
RPC_PARSE_ERROR                = -32700

RPC_MISC_ERROR                 = -1
RPC_TYPE_ERROR                 = -3
RPC_WALLET_ERROR               = -4
RPC_INVALID_ADDRESS_OR_KEY     = -5
RPC_WALLET_INSUFFICIENT_FUNDS  = -6
RPC_OUT_OF_MEMORY              = -7
RPC_INVALID_PARAMETER          = -8
RPC_CLIENT_NOT_CONNECTED       = -9
RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10
RPC_WALLET_INVALID_LABEL_NAME  = -11
RPC_WALLET_KEYPOOL_RAN_OUT     = -12
RPC_WALLET_UNLOCK_NEEDED       = -13
RPC_WALLET_PASSPHRASE_INCORRECT = -14
RPC_WALLET_WRONG_ENC_STATE     = -15
RPC_WALLET_ENCRYPTION_FAILED   = -16
RPC_WALLET_ALREADY_UNLOCKED    = -17
RPC_WALLET_NOT_FOUND           = -18
RPC_WALLET_NOT_SPECIFIED       = -19
RPC_DATABASE_ERROR             = -20
RPC_DESERIALIZATION_ERROR      = -22
RPC_CLIENT_NODE_ALREADY_ADDED  = -23
RPC_CLIENT_NODE_NOT_ADDED      = -24
RPC_VERIFY_ERROR               = -25
RPC_VERIFY_REJECTED            = -26
RPC_VERIFY_ALREADY_IN_UTXO_SET = -27
RPC_IN_WARMUP                  = -28
RPC_CLIENT_NODE_NOT_CONNECTED  = -29
RPC_CLIENT_INVALID_IP_OR_SUBNET = -30
RPC_CLIENT_P2P_DISABLED        = -31
RPC_METHOD_DEPRECATED          = -32
RPC_CLIENT_MEMPOOL_DISABLED    = -33
RPC_CLIENT_NODE_CAPACITY_REACHED = -34
RPC_WALLET_ALREADY_LOADED      = -35
RPC_WALLET_ALREADY_EXISTS      = -36


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_server():
    temp = tempfile.mkdtemp()
    node = BitcoinNode(data_dir=temp, network="regtest")
    rpc = RPCServer(node, port=18332)
    return rpc, node, temp


class _PeerManagerStub:
    """Minimal peer manager exposing the connected-peer maps + a real
    BanManager, for the net-management error-code gates (G24/G25/G29/G30b)."""

    def __init__(self, peers=None):
        from ouroboros.banman import BanManager
        self.peers = dict(peers or {})
        self.block_relay_peers = {}
        self.inbound_peers = {}
        self.ban_manager = BanManager()  # no data_dir -> in-memory only


def _dispatch(rpc, method, params, id_=1):
    """Drive a single JSON-RPC request through the dispatcher and
    return the response dict the wire client would see.
    """
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": id_}
    return asyncio.run(rpc._execute_single_rpc(req))


def _error_code(resp):
    """Extract the error code from a JSON-RPC response, taking into
    account the F3 wrapping bug (some wallet RPCs wrap the error in
    `result` instead of `error`). Returns None if no error code was
    found anywhere — meaning "ouroboros silently succeeded".
    """
    if "error" in resp and resp["error"] is not None:
        return resp["error"].get("code")
    # F3 wrapping bug: error nested under result.
    nested = resp.get("result")
    if hasattr(nested, "error") and nested.error is not None:
        return nested.error.get("code")
    if isinstance(nested, dict) and "error" in nested and nested["error"]:
        return nested["error"].get("code")
    return None


# ---------------------------------------------------------------------------
# Gate tests
# ---------------------------------------------------------------------------

class TestW125_RpcErrorParity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rpc, cls.node, cls.tempdir = _make_server()

    def setUp(self):
        # The addnode added-node list lives on the shared RPCServer; reset it
        # per-test so the net-management gates (G24/G25) don't bleed across
        # test ordering.
        if hasattr(self.rpc, "_added_nodes"):
            self.rpc._added_nodes = set()

    # G1 — RPC_INVALID_REQUEST: missing method ----------------------------
    def test_g1_invalid_request_missing_method(self):
        """Core RPC_INVALID_REQUEST (-32600) for missing-method request."""
        resp = asyncio.run(self.rpc._execute_single_rpc(
            {"jsonrpc": "2.0", "params": [], "id": 1}
        ))
        self.assertEqual(_error_code(resp), RPC_INVALID_REQUEST)

    # G2 — RPC_METHOD_NOT_FOUND -------------------------------------------
    def test_g2_method_not_found(self):
        resp = _dispatch(self.rpc, "no_such_method_xyz_123", [])
        self.assertEqual(_error_code(resp), RPC_METHOD_NOT_FOUND)

    # G3 — RPC_INVALID_PARAMS (params not array/object) -------------------
    @pytest.mark.xfail(reason="W125 BUG-6: ouroboros never emits -32602; "
                              "wrong arity → -32603 via Exception catch-all",
                       strict=False)
    def test_g3_invalid_params_wrong_arity(self):
        """JSON-RPC 2.0 §5.1 mandates -32602 for invalid params (wrong
        arity, type mismatch). ouroboros's dispatcher invokes the handler
        with the params and lets the TypeError bubble — caught by the
        Exception catch-all → -32603.
        """
        # getblockcount takes 0 args; supply 2.
        resp = _dispatch(self.rpc, "getblockcount", [1, 2])
        self.assertEqual(_error_code(resp), RPC_INVALID_PARAMS)

    # G4 — RPC_INTERNAL_ERROR -- inverted: must NOT be used for known cases
    # FIXED 2026-06-12 (ParseHashV alignment): gettxout now runs a Core-style
    # ParseHashV guard at the parse boundary, so a malformed txid -> -8 (was
    # -32603). xfail removed — this is a real, passing assertion now.
    def test_g4_invalid_txid_not_internal_error(self):
        """Core uses RPC_INVALID_PARAMETER (-8) for ParseHashV failures,
        NOT RPC_INTERNAL_ERROR (-32603). gettxout with a non-hex txid must
        emit -8 at the parse boundary, before any lookup.
        """
        resp = _dispatch(self.rpc, "gettxout", ["nothex", 0])
        self.assertEqual(_error_code(resp), RPC_INVALID_PARAMETER)

    # G5 — RPC_PARSE_ERROR -------------------------------------------------
    def test_g5_parse_error_present_at_dispatcher_layer(self):
        """RPC_PARSE_ERROR is wired correctly at the HTTP layer
        (rpc.py:1110). This test asserts the code constant is used
        somewhere in the dispatcher source.
        """
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("-32700", rpc_py)

    # G6 — RPC_MISC_ERROR (-1) ---------------------------------------------
    @pytest.mark.xfail(reason="W125 BUG-1: generic Exception bubbles "
                              "into dispatcher's catch-all → -32603; "
                              "Core wraps std::exception → -1",
                       strict=False)
    def test_g6_misc_error_via_generic_exception(self):
        """Core's JSONRPCExecOne (rpc/server.cpp) catches std::exception
        and wraps as RPC_MISC_ERROR (-1) with the exception what() as the
        message. ouroboros's dispatcher catches Exception and emits
        -32603 instead.
        """
        # prioritisetransaction raises ValueError when dummy != 0.
        resp = _dispatch(self.rpc, "prioritisetransaction",
                         ["0" * 64, 1.5, 0])
        self.assertEqual(_error_code(resp), RPC_MISC_ERROR)

    # G7 — RPC_TYPE_ERROR (-3) ---------------------------------------------
    @pytest.mark.xfail(reason="W125 BUG-1: ouroboros never emits -3; "
                              "type mismatches surface as -32603",
                       strict=False)
    def test_g7_type_error_on_non_string_arg(self):
        """Core's getblocktemplate proposal-mode raises RPC_TYPE_ERROR
        ("Missing data String key for proposal"). decoderawtransaction
        with a non-string hex param raises RPC_TYPE_ERROR. ouroboros
        emits -32603.
        """
        resp = _dispatch(self.rpc, "decoderawtransaction", [12345])
        self.assertEqual(_error_code(resp), RPC_TYPE_ERROR)

    # G8 — RPC_INVALID_ADDRESS_OR_KEY (-5) ---------------------------------
    @pytest.mark.xfail(reason="W125 BUG-1: getblock 'block not found' "
                              "emits -32603; Core emits -5",
                       strict=False)
    def test_g8_invalid_address_or_key_block_not_found(self):
        """Core throws RPC_INVALID_ADDRESS_OR_KEY (-5) for
        getblock(unknown_hash). ouroboros raises HTTPException 404 →
        dispatcher collapses to -32603.
        """
        resp = _dispatch(self.rpc, "getblock",
                         ["0" * 64, 1])  # all-zero hash, will not exist
        self.assertEqual(_error_code(resp), RPC_INVALID_ADDRESS_OR_KEY)

    # G9 — RPC_OUT_OF_MEMORY (-7) ------------------------------------------
    @pytest.mark.xfail(reason="W125 BUG-1: -7 never emitted by ouroboros",
                       strict=False)
    def test_g9_out_of_memory_constant_absent(self):
        """ouroboros has no emission of -7 anywhere. This test asserts
        the constant is *present* in the source — the audit gate flips
        when a fix wave wires it (e.g. gettxoutsetinfo OOM path).
        """
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("-7", rpc_py)  # crude — would match negative literals
        self.assertTrue(re.search(r"\bRPC_OUT_OF_MEMORY\b", rpc_py))

    # G10 — RPC_INVALID_PARAMETER (-8) -------------------------------------
    # FIXED (W125 FIX wave, ported from rustoshi ee86d76): getblockhash for a
    # negative or out-of-range height now raises RPC_INVALID_PARAMETER (-8)
    # "Block height out of range" at the parameter boundary (Core
    # blockchain.cpp:590-591), instead of collapsing to -32603. xfail removed.
    # Full behavioral coverage (in-range success-path guard, exact message,
    # above-tip case) lives in test_w125_rpc_errcode_port.py.
    def test_g10_invalid_parameter_bad_hex_to_sendrawtransaction(self):
        """getblockhash(-1) — negative height -> RPC_INVALID_PARAMETER (-8)."""

        class _Db:
            def get_best_block(self):
                return (b"\x00" * 32, 100)

            def get_block_by_height(self, h):
                return None

        self.node.db = _Db()
        resp = _dispatch(self.rpc, "getblockhash", [-1])
        self.assertEqual(_error_code(resp), RPC_INVALID_PARAMETER)

    # G11 — RPC_CLIENT_NOT_CONNECTED (-9) ----------------------------------
    @pytest.mark.xfail(reason="W125 BUG-4: getblocktemplate has no "
                              "connected-peer gate",
                       strict=False)
    def test_g11_client_not_connected_for_gbt(self):
        """Core mining.cpp:769 — RPC_CLIENT_NOT_CONNECTED if peer
        count is zero. ouroboros serves a template anyway.
        """
        # Test node has no connected peers → expect -9.
        resp = _dispatch(self.rpc, "getblocktemplate",
                         [{"rules": ["segwit"]}])
        # If gbt returns a template (success), this is wrong;
        # if it returns -32603, also wrong.
        self.assertEqual(_error_code(resp), RPC_CLIENT_NOT_CONNECTED)

    # G12 — RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) ---------------------------
    @pytest.mark.xfail(reason="W125 BUG-3 P0: getblocktemplate has no "
                              "IBD gate",
                       strict=False)
    def test_g12_client_in_initial_download_for_gbt(self):
        """Core mining.cpp:773 — RPC_CLIENT_IN_INITIAL_DOWNLOAD if
        the chain is still syncing. ouroboros has no equivalent.
        """
        resp = _dispatch(self.rpc, "getblocktemplate",
                         [{"rules": ["segwit"]}])
        self.assertEqual(_error_code(resp), RPC_CLIENT_IN_INITIAL_DOWNLOAD)

    # G13 — RPC_WALLET_INVALID_LABEL_NAME (-11) ----------------------------
    @pytest.mark.xfail(reason="W125 BUG-1: label validation absent",
                       strict=False)
    def test_g13_wallet_invalid_label_name_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertTrue(re.search(r"\bRPC_WALLET_INVALID_LABEL_NAME\b",
                                  rpc_py))

    # G14 — RPC_WALLET_KEYPOOL_RAN_OUT (-12) -------------------------------
    @pytest.mark.xfail(reason="W125 BUG-17: HD wallet auto-derives, no "
                              "keypool emission path",
                       strict=False)
    def test_g14_wallet_keypool_ran_out_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertTrue(re.search(r"\bRPC_WALLET_KEYPOOL_RAN_OUT\b",
                                  rpc_py))

    # G15 — RPC_WALLET_UNLOCK_NEEDED (-13) ---------------------------------
    @pytest.mark.xfail(reason="W125 BUG-5 P0: locked wallet → -32603 in "
                              "walletcreatefundedpsbt / bumpfee / sendtoaddress",
                       strict=False)
    def test_g15_wallet_unlock_needed_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        # ouroboros has -13 nowhere in source.
        self.assertIn("RPC_WALLET_UNLOCK_NEEDED", rpc_py)

    # G16 — RPC_WALLET_PASSPHRASE_INCORRECT (-14) — F3 wrapping bug --------
    @pytest.mark.xfail(reason="W125 BUG-2 (F3): -14 wrapped in result body "
                              "instead of top-level error",
                       strict=False)
    def test_g16_wallet_passphrase_incorrect_top_level_error(self):
        """ouroboros emits -14 literally but inside a JSONRPCResponse
        returned as `result`, not as the top-level `error`. JSON-RPC 2.0
        clients won't see it as an error.
        """
        # No wallet loaded → expect -18 at top level (this is the
        # behavior with no wallet attached). The F3 test is verified
        # below in G20.
        resp = _dispatch(self.rpc, "walletpassphrase", ["wrong", 60])
        # top-level error MUST be present (not wrapped in result)
        self.assertIn("error", resp)
        self.assertIsNotNone(resp.get("error"))
        # No-wallet case: code should be -18 RPC_WALLET_NOT_FOUND
        # (Core: -18). Failing here proves F3.
        self.assertEqual(resp.get("error", {}).get("code"), RPC_WALLET_NOT_FOUND)

    # G17 — RPC_WALLET_WRONG_ENC_STATE (-15) -------------------------------
    @pytest.mark.xfail(reason="W125 BUG-2 (F3): -15 wrapped in result body",
                       strict=False)
    def test_g17_wallet_wrong_enc_state_top_level(self):
        """Same shape as G16 — the -15 path is wrapped instead of
        surfaced as an error.
        """
        resp = _dispatch(self.rpc, "encryptwallet", ["passphrase"])
        self.assertIn("error", resp)
        self.assertIsNotNone(resp.get("error"))

    # G18 — RPC_WALLET_ENCRYPTION_FAILED (-16) -----------------------------
    @pytest.mark.xfail(reason="W125 BUG-18: -16 absent", strict=False)
    def test_g18_wallet_encryption_failed_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_WALLET_ENCRYPTION_FAILED", rpc_py)

    # G19 — RPC_WALLET_ALREADY_UNLOCKED (-17) ------------------------------
    @pytest.mark.xfail(reason="W125 BUG-19: no already-unlocked check",
                       strict=False)
    def test_g19_wallet_already_unlocked_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_WALLET_ALREADY_UNLOCKED", rpc_py)

    # G20 — RPC_WALLET_NOT_FOUND (-18) — F3 wrapping bug ------------------
    @pytest.mark.xfail(reason="W125 BUG-2 (F3): no-wallet emits "
                              "JSONRPCResponse-as-result; "
                              "top-level error is null + code is hidden under result",
                       strict=False)
    def test_g20_wallet_not_found_top_level_error(self):
        """The F3 root-cause test: walletpassphrase without a wallet
        loaded should emit top-level `error.code == -18`. ouroboros
        emits the error nested under `result`.
        """
        resp = _dispatch(self.rpc, "walletpassphrase", ["x", 60])
        # JSON-RPC 2.0 spec §5.1 — error response MUST contain top-level
        # `error` member. Top-level error MUST NOT be None.
        self.assertIn("error", resp)
        self.assertIsNotNone(resp.get("error"))
        self.assertEqual(resp.get("error", {}).get("code"), RPC_WALLET_NOT_FOUND)

    # G21 — RPC_WALLET_NOT_SPECIFIED (-19) --------------------------------
    @pytest.mark.xfail(reason="W125 BUG-14: multi-wallet ambiguity → -32603",
                       strict=False)
    def test_g21_wallet_not_specified(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_WALLET_NOT_SPECIFIED", rpc_py)

    # G22 — RPC_DATABASE_ERROR (-20) --------------------------------------
    @pytest.mark.xfail(reason="W125 BUG-16: DB errors collapse to -32603",
                       strict=False)
    def test_g22_database_error_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_DATABASE_ERROR", rpc_py)

    # G23 — RPC_DESERIALIZATION_ERROR (-22) -------------------------------
    @pytest.mark.xfail(reason="W125 BUG-12: bad hex to sendrawtransaction "
                              "emits -32603; Core -22",
                       strict=False)
    def test_g23_deserialization_error_bad_hex(self):
        resp = _dispatch(self.rpc, "sendrawtransaction", ["notvalidhex"])
        self.assertEqual(_error_code(resp), RPC_DESERIALIZATION_ERROR)

    # G24 — RPC_CLIENT_NODE_ALREADY_ADDED (-23) ---------------------------
    # FIXED (W125 FIX wave, ported from rustoshi 7b94ef1): addnode keeps an
    # added-node list (Core CConnman::m_added_nodes); a duplicate 'add' now
    # raises RPC_CLIENT_NODE_ALREADY_ADDED (-23) (net.cpp:362). xfail removed.
    def test_g24_node_already_added_absent(self):
        """Second 'add' of the same node -> -23 (and constant present)."""
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_CLIENT_NODE_ALREADY_ADDED", rpc_py)
        self.node.peer_manager = _PeerManagerStub()
        _dispatch(self.rpc, "addnode", ["127.0.0.1:12345", "add"])
        resp = _dispatch(self.rpc, "addnode", ["127.0.0.1:12345", "add"])
        self.assertEqual(_error_code(resp), RPC_CLIENT_NODE_ALREADY_ADDED)

    # G25 — RPC_CLIENT_NODE_NOT_ADDED (-24) -------------------------------
    # FIXED (W125 FIX wave, ported from rustoshi 7b94ef1): 'remove' of a node
    # never added now raises RPC_CLIENT_NODE_NOT_ADDED (-24) instead of a
    # ValueError->-32603 (net.cpp:368). xfail removed.
    def test_g25_node_not_added_via_remove(self):
        self.node.peer_manager = _PeerManagerStub()
        resp = _dispatch(self.rpc, "addnode",
                         ["127.0.0.1:12345", "remove"])
        self.assertEqual(_error_code(resp), RPC_CLIENT_NODE_NOT_ADDED)

    # G26 — RPC_VERIFY_ERROR / RPC_VERIFY_REJECTED -----------------------
    @pytest.mark.xfail(reason="W125 BUG-8: sendrawtransaction reject → -32603; "
                              "Core: -25 / -26",
                       strict=False)
    def test_g26_verify_error_emits_25_or_26(self):
        """Core's sendrawtransaction policy/consensus reject throws
        RPC_VERIFY_ERROR (-25) for ban-worthy errors or
        RPC_VERIFY_REJECTED (-26) for policy. ouroboros emits -32603.

        Trigger: coinbase tx submitted to sendrawtransaction (rpc.py:2441
        rejects with "coinbase" reject reason).
        """
        # Minimal coinbase tx: version, 1 input (null prevout), no outs,
        # locktime. ouroboros will reject before deserializing scriptSig.
        # Just send a malformed tx that gets through hex decode but
        # fails mempool admission with rpc.py:2441 "coinbase" reject.
        # Even simpler: any non-tx hex that decodes but fails.
        # We use a real coinbase-shaped tx prefix.
        coinbase_hex = (
            "02000000"  # version
            "0001"       # marker + flag (segwit)
            "01"         # 1 input
            + "00" * 32  # null prevout
            + "ffffffff" # prev_n = -1 (coinbase marker)
            + "00"        # empty scriptSig
            + "ffffffff" # sequence
            + "00"        # 0 outputs
            + "00"        # empty witness
            + "00000000" # locktime
        )
        resp = _dispatch(self.rpc, "sendrawtransaction", [coinbase_hex])
        code = _error_code(resp)
        self.assertIn(code, (RPC_VERIFY_ERROR, RPC_VERIFY_REJECTED))

    # G27 — RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) --------------------------
    @pytest.mark.xfail(reason="W125 BUG-7: sendrawtransaction returns "
                              "success on already-known tx; Core: -27",
                       strict=False)
    def test_g27_verify_already_in_utxo_set_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_VERIFY_ALREADY_IN_UTXO_SET", rpc_py)

    # G28 — RPC_IN_WARMUP (-28) ------------------------------------------
    @pytest.mark.xfail(reason="W125 BUG-13: no warmup state machine",
                       strict=False)
    def test_g28_in_warmup_absent(self):
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        self.assertIn("RPC_IN_WARMUP", rpc_py)

    # G29 — RPC_CLIENT_NODE_NOT_CONNECTED (-29) ---------------------------
    # FIXED (W125 FIX wave, ported from rustoshi 845f7e4): disconnectnode for a
    # peer not in any connected-peer map now raises RPC_CLIENT_NODE_NOT_CONNECTED
    # (-29) instead of silently returning null (net.cpp:478). Use a peer manager
    # with zero connected peers (the genuine miss path), not the no-pm degenerate
    # path. xfail removed.
    def test_g29_node_not_connected_via_disconnectnode(self):
        """disconnectnode on a non-connected peer emits -29."""
        self.node.peer_manager = _PeerManagerStub()  # no peers connected
        resp = _dispatch(self.rpc, "disconnectnode",
                         ["127.0.0.1:65535", -1])
        self.assertEqual(_error_code(resp), RPC_CLIENT_NODE_NOT_CONNECTED)

    # G30 — RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) and other operator-surface
    @pytest.mark.xfail(reason="W125 BUG-10/18/19: -30/-35/-36 all collapse "
                              "to -32603",
                       strict=False)
    def test_g30_operator_surface_codes_present(self):
        """Aggregate gate for the operator-surface codes that should all
        appear once the dispatcher is unified: -30 / -31 / -32 / -33 /
        -34 / -35 / -36.
        """
        rpc_py = (_src / "ouroboros" / "rpc.py").read_text()
        # All 7 should be referenced once the fix lands; today: zero.
        self.assertTrue(re.search(r"\bRPC_CLIENT_INVALID_IP_OR_SUBNET\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_CLIENT_P2P_DISABLED\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_METHOD_DEPRECATED\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_CLIENT_MEMPOOL_DISABLED\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_CLIENT_NODE_CAPACITY_REACHED\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_WALLET_ALREADY_LOADED\b", rpc_py))
        self.assertTrue(re.search(r"\bRPC_WALLET_ALREADY_EXISTS\b", rpc_py))

    # G30b — RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) on setban --------------
    # FIXED (W125 FIX wave, ported from rustoshi 980a31d): setban with an
    # un-parseable IP/subnet now raises RPC_CLIENT_INVALID_IP_OR_SUBNET (-30)
    # "Error: Invalid IP/Subnet" (Core net.cpp:780), instead of -32603. This is
    # the focused behavioral gate; the G30 aggregate above tracks the remaining
    # operator-surface codes (-31/-32/-33/-34/-35/-36) which are still absent.
    def test_g30b_setban_invalid_ip_subnet(self):
        self.node.peer_manager = _PeerManagerStub()
        resp = _dispatch(self.rpc, "setban", ["not-an-ip", "add"])
        self.assertEqual(_error_code(resp), RPC_CLIENT_INVALID_IP_OR_SUBNET)
        self.assertEqual(resp["error"]["message"], "Error: Invalid IP/Subnet")


# ---------------------------------------------------------------------------
# Two-pipeline guard
# ---------------------------------------------------------------------------

class TestW125_TwoPipelineGuard(unittest.TestCase):
    """Assert the Rust ferrous-utils pipeline has zero JSON-RPC surface
    so the audit's findings + fixes are entirely Python-side.
    """

    def test_ferrous_utils_has_no_rpc_error_code_strings(self):
        ferrous = _src.parent / "ferrous-utils"
        if not ferrous.exists():
            self.skipTest("ferrous-utils not present in checkout")
        # Walk *.rs files and assert none contain RPC error code names.
        offenders = []
        for path in ferrous.rglob("*.rs"):
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if re.search(r"\bRPC_INVALID_\w+\b|\bRPC_WALLET_\w+\b|"
                         r"\bRPC_VERIFY_\w+\b|\bRPC_CLIENT_\w+\b|"
                         r"\bRPCErrorCode\b|\bJSONRPCError\b",
                         text):
                offenders.append(str(path))
        self.assertEqual(offenders, [],
                         "ferrous-utils must not host JSON-RPC error code "
                         "constants — RPC lives only in the Python pipeline")

    def test_ferrous_utils_has_no_rpc_handler_exports(self):
        ferrous = _src.parent / "ferrous-utils"
        if not ferrous.exists():
            self.skipTest("ferrous-utils not present in checkout")
        offenders = []
        for path in ferrous.rglob("*.rs"):
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            # ouroboros's Python handlers are named rpc_*; check the Rust
            # side never exports a function with that prefix to the
            # Python boundary.
            if re.search(r"#\[pyfunction\][^\n]*\n\s*(?:pub\s+)?fn\s+rpc_", text):
                offenders.append(str(path))
        self.assertEqual(offenders, [],
                         "Rust pipeline must not export rpc_* handlers")


if __name__ == "__main__":
    unittest.main()
