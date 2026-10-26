"""scantxoutset ``unspents[].desc`` is Core's InferDescriptor of the coin's own
scriptPubKey (``addr(...)#csum``), not the scan-object string the caller sent
(rpc/blockchain.cpp scantxoutset).

CONTROL: ``pytest tests/test_scantxoutset_desc.py``
"""

from __future__ import annotations

import asyncio
import types

from ouroboros.rpc import RPCServer

P2SH_SPK = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"
P2SH_ADDR = "2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN"
P2SH_DESC = "addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8"


class _DB:
    def get_best_block(self):
        return (b"\x07" * 32, 1)

    def iter_utxos(self):
        yield types.SimpleNamespace(
            txid=b"\x09" * 32, vout=0, amount=5000,
            script_pubkey=bytes.fromhex(P2SH_SPK), height=1, is_coinbase=False,
        )

    def get_block_hash_by_height(self, _height):
        return b"\x07" * 32


def _scan(scanobject: str):
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = types.SimpleNamespace(
        network="regtest", config={"network": "regtest"}, db=_DB(),
    )
    req = {"jsonrpc": "2.0", "method": "scantxoutset",
           "params": ["start", [scanobject]], "id": 1}
    resp = asyncio.run(rpc._execute_single_rpc(req))
    assert resp.get("error") is None, resp
    return resp["result"]["unspents"]


def test_scantxoutset_desc_for_raw_scanobject_is_inferred_addr() -> None:
    assert _scan(f"raw({P2SH_SPK})")[0]["desc"] == P2SH_DESC


def test_scantxoutset_desc_for_addr_scanobject_keeps_checksum() -> None:
    assert _scan(f"addr({P2SH_ADDR})")[0]["desc"] == P2SH_DESC
