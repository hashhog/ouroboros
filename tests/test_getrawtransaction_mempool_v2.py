"""getrawtransaction verbosity 2 on a mempool tx, and scriptSig asm numbers.

Core (rpc/rawtransaction.cpp) only passes undo data to TxToJSON when the tx
was found in a block, so a mempool tx never gets ``fee`` or ``vin[].prevout``
at verbosity 2.  Core's ScriptToAsmStr (core_io.cpp:371-373) prints a push of
<= 4 bytes as a CScriptNum integer, not as hex.
"""
import pytest

from ouroboros.psbt import _script_asm_sighash
from tests.test_getrawtx import (
    MockDatabase, MockMempool, MockNode, MockTransaction, MockTxIn, MockTxOut,
)


class UtxoDatabase(MockDatabase):
    def get_utxo_or_spent(self, txid, vout):
        return {"value": 100_000_000, "height": 111, "is_coinbase": False,
                "script_pubkey": b"\xa9\x14" + b"\x11" * 20 + b"\x87"}


def _node_with_mempool_tx():
    node = MockNode()
    node.db = UtxoDatabase()
    tx = MockTransaction(
        txid=bytes.fromhex("a" * 64),
        inputs=[MockTxIn(prev_txid=bytes.fromhex("1" * 64), prev_vout=0)],
        outputs=[MockTxOut(value=99_990_000, script_pubkey=b"\x00\x14" + b"\x00" * 20)],
    )
    node.mempool.transactions[tx.get_txid()] = tx
    return node, tx


@pytest.mark.asyncio
@pytest.mark.parametrize("verbosity", [1, 2])
async def test_mempool_tx_has_no_fee_or_prevout(verbosity):
    from ouroboros.rpc import RPCServer
    node, tx = _node_with_mempool_tx()
    rpc = RPCServer.__new__(RPCServer)
    rpc._side_branch_blocks = {}
    rpc.node = node
    result = await rpc.rpc_getrawtransaction(tx.get_txid().hex(), verbose=verbosity)
    assert "fee" not in result
    assert all("prevout" not in vin for vin in result["vin"])


@pytest.mark.parametrize("script,expected", [
    (b"\x01\x51", "81"),               # push of 0x51 -> 81, not "51"
    (b"\x01\x80", "0"),                # negative zero
    (b"\x01\x81", "-1"),
    (b"\x02\xff\x7f", "32767"),
    (b"\x04\x01\x02\x03\x04", str(0x04030201)),
    (b"\x4c\x00", "0"),                # empty PUSHDATA1
    (b"\x05\x01\x02\x03\x04\x05", "0102030405"),   # > 4 bytes stays hex
    (b"\x51\x00", "1 0"),
])
def test_scriptsig_asm_small_push_is_number(script, expected):
    assert _script_asm_sighash(script) == expected
