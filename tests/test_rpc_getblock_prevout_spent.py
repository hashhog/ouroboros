"""getblock verbosity 3 reports ``vin[].prevout`` for already-spent outputs.

Core fills ``prevout`` from the block's undo data (rpc/blockchain.cpp
blockToJSON, TxVerbosity::SHOW_DETAILS_AND_PREVOUT), so it is present for
every non-coinbase input of a connected block, whether or not the output is
still unspent. ouroboros looked the output up in the live UTXO set only, so
any input whose output had since been spent had no ``prevout`` at all.
Core's shape is {generated, height, value, scriptPubKey}.
"""

from __future__ import annotations

import asyncio
import struct

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.rpc import RPCServer

SPK = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
PREV_TXID = b"\x42" * 32


class _Block:
    def __init__(self, txs):
        self.version = 1
        self.prev_blockhash = b"\x00" * 32
        self.merkle_root = b"\x11" * 32
        self.timestamp = 1_700_000_000
        self.bits = 0x207FFFFF
        self.nonce = 0
        self.transactions = txs

    def serialize(self) -> bytes:
        return self.raw()

    def raw(self) -> bytes:
        header = struct.pack("<i", 1) + self.prev_blockhash + self.merkle_root
        header += struct.pack("<III", self.timestamp, self.bits, self.nonce)
        body = bytes([len(self.transactions)])
        for t in self.transactions:
            body += t.serialize_with_witness()
        return header + body


class _DB:
    def __init__(self, block, h):
        self.block, self.h = block, h

    def get_block(self, bh):
        return self.block if bytes(bh) == self.h else None

    def get_block_bytes(self, bh):
        return self.block.raw() if bytes(bh) == self.h else None

    def get_best_block(self):
        return (self.h, 2)

    def get_block_hash_by_height(self, height):
        return self.h if height == 2 else None

    def get_utxo(self, txid, vout):
        return None  # the output has been spent: not in the live set

    def get_utxo_or_spent(self, txid, vout):
        if bytes(txid) == PREV_TXID and vout == 0:
            return {"value": 5_000_000_000, "script_pubkey": SPK,
                    "height": 1, "is_coinbase": True}
        return None


def _rpc(db):
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        network = "regtest"

    node = _Node()
    node.db = db
    node.get_median_time = lambda h: 1_700_000_000
    node.get_chainwork_at_height = lambda h: "0" * 64
    node.get_difficulty = lambda bits: 1.0
    rpc.node = node
    rpc._current_wallet_name = None
    rpc._side_branch_blocks = {}
    rpc._side_branch_max_entries = 1024
    return rpc


def test_getblock_v3_prevout_for_spent_output() -> None:
    cb = Transaction(
        txid=b"\x01" * 32, version=2, locktime=0,
        inputs=[TxIn(bytes(32), 0xFFFFFFFF, b"\x01\x02", 0xFFFFFFFF)],
        outputs=[TxOut(5_000_000_000, SPK)],
    )
    spend = Transaction(
        txid=b"\x02" * 32, version=2, locktime=0,
        inputs=[TxIn(PREV_TXID, 0, b"", 0xFFFFFFFD)],
        outputs=[TxOut(4_999_990_000, SPK)],
    )
    block = _Block([cb, spend])
    h = b"A" + bytes(31)
    rpc = _rpc(_DB(block, h))
    res = asyncio.run(rpc.rpc_getblock(h[::-1].hex(), verbosity=3))

    assert "prevout" not in res["tx"][0]["vin"][0]  # coinbase has none
    prev = res["tx"][1]["vin"][0]["prevout"]
    assert list(prev) == ["generated", "height", "value", "scriptPubKey"]
    assert prev["generated"] is True
    assert prev["height"] == 1
    assert prev["value"].text == "50.00000000"
    assert prev["scriptPubKey"]["hex"] == SPK.hex()
    assert prev["scriptPubKey"]["type"] == "witness_v0_keyhash"
