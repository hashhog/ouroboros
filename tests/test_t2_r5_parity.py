"""Control for QUEUES.md ouroboros item 4: T2 R5 probe parity.

Encodes the T2 FAILs from the 2026-09-01 r5_probe sweep
(tools/diff-test-artifacts/r5-probe/20260901T182642Z.json ouroboros T2 14/41).

Probes are the live-lane definitions in tools/r5-probes.d (calibrated against
Bitcoin Core). Dispatch goes through ``RPCServer._execute_single_rpc`` so a
handler that raises a bare Exception / HTTPException (wire code -32603) or
is missing (wire code -32601) fails these.

CONTROL: ``pytest tests/test_t2_r5_parity.py``
"""

from __future__ import annotations

import asyncio
import types

from ouroboros.rpc import RPCServer

# Canonical R5 fixtures (tools/r5-probes.d/rawtx-psbt.jsonl, util.jsonl).
PSBT_A = (
    "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9"
    "////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
)
RAW_HEX = (
    "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d4"
    "54941c45d1b3a323f1433bd600000000"
)
WIF_PRIV1 = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
KEY1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
KEY2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
DESC_NO_CSUM = "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)"
DESC_CSUM = DESC_NO_CSUM + "#e72f49hy"
CORE_SIG = (
    "HANWTfmfhMdsuje52nPqOD/Q4QXfl6q188p2LpAG4ICJONIllahpDidMpe8n2TWE+VV2kR2cHd3gAv6n+jtRWV0="
)
ZERO_WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU"
P2PKH_ADDR = "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S"
ZERO64 = "0" * 64
ABSENT64 = "0" * 63 + "1"


class _EmptyMempool:
    transactions: dict = {}

    def get_transaction(self, _txid):
        return None

    def get_transaction_entry(self, _txid):
        return None

    def _get_ancestors(self, _tx):
        return []

    def _collect_descendants(self, _txid):
        return set()

    def prioritise_transaction(self, _txid, _delta):
        return None


class _AbsentDB:
    def get_block(self, _h):
        return None

    def get_block_bytes(self, _h):
        return None

    def get_best_block(self):
        return (b"\x00" * 32, 0)

    def get_utxo(self, _txid, _n):
        return None

    def get_block_hash_by_height(self, _height):
        return None

    def get_tx_index(self, *_a, **_k):
        return None


def _make_rpc(*, db=None, mempool=None, network: str = "mainnet") -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)
    node = types.SimpleNamespace(
        network=network,
        config={"network": network},
        db=db if db is not None else _AbsentDB(),
        mempool=mempool if mempool is not None else _EmptyMempool(),
        pruner=None,
        block_filter_index=None,
    )
    rpc.node = node
    rpc._side_branch_blocks = {}
    rpc._deployment_cache = {}
    rpc._current_wallet_name = None
    return rpc


def _dispatch(rpc: RPCServer, method: str, params):
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    return asyncio.run(rpc._execute_single_rpc(req))


def _err(resp) -> tuple[int | None, str]:
    err = resp.get("error")
    if not err:
        return None, ""
    return err.get("code"), err.get("message") or ""


def _ok(resp):
    assert resp.get("error") is None, resp
    return resp.get("result")


# ---------------------------------------------------------------------------
# decoderawtransaction / decodescript / converttopsbt
# ---------------------------------------------------------------------------


def test_decoderawtransaction_nonhex_is_minus22() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "decoderawtransaction", ["zz"]))
    assert code == -22
    assert msg == "TX decode failed"


def test_decodescript_nonhex_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "decodescript", ["zz"]))
    assert code == -8
    assert msg == "argument must be hexadecimal string (not 'zz')"


def test_converttopsbt_nonhex_is_minus22() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "converttopsbt", ["zz"]))
    assert code == -22


# ---------------------------------------------------------------------------
# validateaddress
# ---------------------------------------------------------------------------


def test_validateaddress_exact_invalid_matches_core() -> None:
    res = _ok(_dispatch(_make_rpc(), "validateaddress", ["notanaddress"]))
    assert res["isvalid"] is False
    assert res["error"] == ("Invalid checksum or length of Base58 address (P2PKH or P2SH)")


def test_validateaddress_exact_valid_bech32() -> None:
    res = _ok(
        _dispatch(
            _make_rpc(),
            "validateaddress",
            ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],
        )
    )
    assert res["isvalid"] is True
    assert res["address"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


# ---------------------------------------------------------------------------
# getdeploymentinfo / getmempoolancestors / getmempooldescendants
# ---------------------------------------------------------------------------


def test_getdeploymentinfo_notfound_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "getdeploymentinfo", [ABSENT64]))
    assert code == -5
    assert msg == "Block not found"


def test_getmempoolancestors_not_in_mempool_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "getmempoolancestors", [ZERO64]))
    assert code == -5
    assert msg == "Transaction not in mempool"


def test_getmempooldescendants_not_in_mempool_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "getmempooldescendants", [ZERO64]))
    assert code == -5
    assert msg == "Transaction not in mempool"


# ---------------------------------------------------------------------------
# verifytxoutproof / prioritisetransaction / scantxoutset / pruneblockchain
# ---------------------------------------------------------------------------


def test_verifytxoutproof_nonhex_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "verifytxoutproof", ["zz"]))
    assert code == -8
    assert msg == "proof must be hexadecimal string (not 'zz')"


def test_prioritisetransaction_bad_txid_is_minus8() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "prioritisetransaction", ["zz", 0, 1000]))
    assert code == -8


def test_scantxoutset_bogus_action_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "scantxoutset", ["bogus"]))
    assert code == -8
    assert msg == "Invalid action 'bogus'"


def test_pruneblockchain_string_height_is_minus3_before_prune_mode() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "pruneblockchain", ["zz"]))
    assert code == -3
    assert "not of expected type number" in msg


# ---------------------------------------------------------------------------
# importmempool / getindexinfo
# ---------------------------------------------------------------------------


def test_importmempool_missing_file_is_minus1() -> None:
    code, msg = _err(
        _dispatch(
            _make_rpc(),
            "importmempool",
            ["/nonexistent/r5-probe-no-such-file.dat"],
        )
    )
    assert code == -1
    assert msg == "Unable to import mempool file, see debug log for details."


def test_getindexinfo_numeric_arg_is_minus3() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "getindexinfo", [123]))
    assert code == -3
    assert "not of expected type string" in msg


# ---------------------------------------------------------------------------
# combinerawtransaction / createpsbt / analyzepsbt / utxoupdatepsbt
# ---------------------------------------------------------------------------


def test_combinerawtransaction_unknown_input_is_minus25() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "combinerawtransaction", [[RAW_HEX, RAW_HEX]]))
    assert code == -25
    assert msg == "Input not found or already spent"


def test_createpsbt_canonical_exact_matches_core() -> None:
    inputs = [{"txid": "a" * 64, "vout": 0}]
    outputs = {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001}
    res = _ok(_dispatch(_make_rpc(), "createpsbt", [inputs, outputs]))
    assert res == PSBT_A


def test_createpsbt_bad_txid_is_minus8() -> None:
    inputs = [{"txid": "zz", "vout": 0}]
    outputs = {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001}
    code, _msg = _err(_dispatch(_make_rpc(), "createpsbt", [inputs, outputs]))
    assert code == -8


def test_analyzepsbt_analyze_exact_matches_core() -> None:
    res = _ok(_dispatch(_make_rpc(), "analyzepsbt", [PSBT_A]))
    assert res == {
        "inputs": [
            {"has_utxo": False, "is_final": False, "next": "updater"},
        ],
        "next": "updater",
    }


def test_analyzepsbt_bad_base64_is_minus22() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "analyzepsbt", ["notbase64!!"]))
    assert code == -22


def test_utxoupdatepsbt_bad_base64_is_minus22() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "utxoupdatepsbt", ["notbase64!!"]))
    assert code == -22


def test_utxoupdatepsbt_unknown_inputs_passthrough_is_psbt_string() -> None:
    res = _ok(_dispatch(_make_rpc(), "utxoupdatepsbt", [PSBT_A]))
    assert isinstance(res, str)
    assert res.startswith("cHNidP8")


# ---------------------------------------------------------------------------
# descriptorprocesspsbt / signrawtransactionwithkey / submitpackage
# ---------------------------------------------------------------------------


def test_descriptorprocesspsbt_bad_descriptor_is_minus5() -> None:
    code, _msg = _err(
        _dispatch(
            _make_rpc(),
            "descriptorprocesspsbt",
            [PSBT_A, ["nonsense(desc)"]],
        )
    )
    assert code == -5


def test_descriptorprocesspsbt_update_unknown_input_complete_false() -> None:
    res = _ok(
        _dispatch(
            _make_rpc(),
            "descriptorprocesspsbt",
            [PSBT_A, [f"wpkh({WIF_PRIV1})"]],
        )
    )
    assert res["complete"] is False
    assert isinstance(res["psbt"], str)
    assert res["psbt"].startswith("cHNidP8")


def test_signrawtransactionwithkey_bad_privkey_is_minus5() -> None:
    code, _msg = _err(
        _dispatch(
            _make_rpc(),
            "signrawtransactionwithkey",
            [RAW_HEX, ["notakey"]],
        )
    )
    assert code == -5


def test_signrawtransactionwithkey_sign_complete() -> None:
    prev = [
        {
            "txid": "a" * 64,
            "vout": 0,
            "scriptPubKey": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            "amount": 0.002,
        }
    ]
    res = _ok(
        _dispatch(
            _make_rpc(),
            "signrawtransactionwithkey",
            [RAW_HEX, [WIF_PRIV1], prev],
        )
    )
    assert res["complete"] is True
    assert "hex" in res


def test_submitpackage_empty_array_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "submitpackage", [[]]))
    assert code == -8
    assert msg.startswith("Array must contain between 1 and")


def test_submitpackage_nonhex_is_minus22() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "submitpackage", [["zz"]]))
    assert code == -22


# ---------------------------------------------------------------------------
# createmultisig / deriveaddresses / getdescriptorinfo
# ---------------------------------------------------------------------------


def test_createmultisig_invalid_pubkey_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "createmultisig", [1, ["deadbeef"]]))
    assert code == -5
    assert "33 or 65 bytes" in msg


def test_createmultisig_not_enough_keys_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "createmultisig", [3, [KEY1, KEY2]]))
    assert code == -8
    assert "not enough keys supplied" in msg


def test_deriveaddresses_missing_checksum_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "deriveaddresses", [DESC_NO_CSUM]))
    assert code == -5
    assert msg == "Missing checksum"


def test_deriveaddresses_range_on_unranged_is_minus8() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "deriveaddresses", [DESC_CSUM, [0, 2]]))
    assert code == -8
    assert msg == "Range should not be specified for an un-ranged descriptor"


def test_getdescriptorinfo_invalid_descriptor_is_minus5() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "getdescriptorinfo", ["notadescriptor"]))
    assert code == -5


def test_getdescriptorinfo_bad_checksum_is_minus5() -> None:
    code, _msg = _err(_dispatch(_make_rpc(), "getdescriptorinfo", [DESC_NO_CSUM + "#00000000"]))
    assert code == -5


def test_getdescriptorinfo_success_exact_single() -> None:
    res = _ok(_dispatch(_make_rpc(), "getdescriptorinfo", [DESC_NO_CSUM]))
    assert res["descriptor"] == DESC_CSUM
    assert res["checksum"] == "e72f49hy"
    assert res["isrange"] is False
    assert res["issolvable"] is True
    assert res["hasprivatekeys"] is False


# ---------------------------------------------------------------------------
# signmessagewithprivkey / verifymessage
# ---------------------------------------------------------------------------


def test_signmessagewithprivkey_zero_privkey_is_minus5() -> None:
    code, msg = _err(_dispatch(_make_rpc(), "signmessagewithprivkey", [ZERO_WIF, "x"]))
    assert code == -5
    assert msg == "Invalid private key"


def test_signmessagewithprivkey_success_exact_sig() -> None:
    res = _ok(
        _dispatch(
            _make_rpc(),
            "signmessagewithprivkey",
            ["5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "hashhog r5 probe"],
        )
    )
    assert res == CORE_SIG


def test_verifymessage_malformed_sig_is_minus3() -> None:
    code, msg = _err(
        _dispatch(
            _make_rpc(),
            "verifymessage",
            [P2PKH_ADDR, "not-base64!!", "hashhog r5 probe"],
        )
    )
    assert code == -3
    assert msg == "Malformed base64 encoding"


def test_verifymessage_invalid_address_is_minus5() -> None:
    code, msg = _err(
        _dispatch(
            _make_rpc(),
            "verifymessage",
            ["notanaddress", CORE_SIG, "hashhog r5 probe"],
        )
    )
    assert code == -5
    assert msg == "Invalid address"


def test_verifymessage_exact_true() -> None:
    res = _ok(
        _dispatch(
            _make_rpc(),
            "verifymessage",
            [P2PKH_ADDR, CORE_SIG, "hashhog r5 probe"],
        )
    )
    assert res is True


def test_verifymessage_exact_false_tampered() -> None:
    res = _ok(
        _dispatch(
            _make_rpc(),
            "verifymessage",
            [P2PKH_ADDR, CORE_SIG, "tampered message"],
        )
    )
    assert res is False


# ---------------------------------------------------------------------------
# getblockstats invalid-stat (needs a resolvable block)
# ---------------------------------------------------------------------------


def test_getblockstats_invalid_stat_is_minus8() -> None:
    from ouroboros.database import Block, Transaction, TxIn, TxOut

    block_hash = b"\x22" * 32
    coinbase = Transaction(
        txid=b"\x33" * 32,
        version=1,
        locktime=0,
        inputs=[
            TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF, script_sig=b"", sequence=0xFFFFFFFF)
        ],
        outputs=[TxOut(value=50_0000_0000, script_pubkey=b"\x00\x14" + b"\x00" * 20)],
    )
    block = Block(
        version=1,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1231006505,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[coinbase],
        hash=block_hash,
        height=1,
    )

    class _DB(_AbsentDB):
        def get_block(self, h):
            return block if h == block_hash else None

        def get_best_block(self):
            return (block_hash, 1)

        def get_block_hash_by_height(self, height):
            return block_hash if height == 1 else None

    rpc = _make_rpc(db=_DB())
    code, msg = _err(_dispatch(rpc, "getblockstats", [block_hash[::-1].hex(), ["bogusstat"]]))
    assert code == -8
    assert "Invalid selected statistic" in msg
