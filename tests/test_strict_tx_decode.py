"""Raw-transaction hex must decode EXACTLY, like Core's DecodeHexTx.

Core core_io.cpp DecodeHexTx deserializes and then requires the stream to be
empty ("ssData.empty()"), so a transaction followed by even one extra byte is
"TX decode failed".  ``decoderawtransaction`` with ``iswitness=false`` parses
only the legacy (no-witness) serialization, so a segwit-serialized tx (marker
0x00, flag 0x01 where the input count goes) fails there too.

Core regtest rows: operator/decoderawtransaction/{trailing,
segwit-iswitness-false}, operator/testmempoolaccept/trailing,
operator/sendrawtransaction/trailing.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402
from ouroboros.rpc import RpcError, RPCServer  # noqa: E402
from ouroboros.validation import TransactionValidator  # noqa: E402

OP_TRUE = b"\x51"
PREV = bytes([0x77]) * 32


def _tx(witness: bool) -> Transaction:
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=PREV, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=1000, script_pubkey=OP_TRUE)],
    )
    tx = TxMessage.from_payload(tmp.serialize()).transaction
    if witness:
        tx.inputs[0].witness = [b"\x01\x02"]
        tx.has_witness = True
    return tx


def _hex(tx: Transaction, witness: bool) -> str:
    return (tx.serialize_with_witness() if witness else tx.serialize()).hex()


class _DB:
    def get_utxo(self, txid, vout):
        return None

    def get_utxo_batch(self, outpoints):
        return [None for _ in outpoints]

    def get_median_time_past(self, height=None):
        return 1_700_000_000

    def get_best_block(self):
        return bytes(32), 200


def _rpc():
    db = _DB()
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    return SimpleNamespace(
        node=SimpleNamespace(mempool=pool, db=db, network="regtest"),
        DEFAULT_MAX_RAW_TX_FEE_RATE=0.10,
    )


def _run(coro):
    return asyncio.run(coro)


def test_decoderawtransaction_rejects_trailing_byte():
    h = _hex(_tx(True), True)
    with pytest.raises(RpcError) as ei:
        _run(RPCServer.rpc_decoderawtransaction(_rpc(), h + "00"))
    assert (ei.value.code, ei.value.message) == (-22, "TX decode failed")


def test_decoderawtransaction_iswitness_false_rejects_segwit_serialization():
    h = _hex(_tx(True), True)
    with pytest.raises(RpcError) as ei:
        _run(RPCServer.rpc_decoderawtransaction(_rpc(), h, False))
    assert (ei.value.code, ei.value.message) == (-22, "TX decode failed")


def test_decoderawtransaction_legacy_and_segwit_still_decode():
    # Negative controls: the strictness must not reject valid encodings.
    rpc = _rpc()
    seg = _run(RPCServer.rpc_decoderawtransaction(rpc, _hex(_tx(True), True)))
    assert seg["txid"] == _tx(True).get_txid()[::-1].hex()
    leg = _tx(False)
    for iswitness in (True, False):
        out = _run(RPCServer.rpc_decoderawtransaction(rpc, _hex(leg, False), iswitness))
        assert out["txid"] == leg.get_txid()[::-1].hex()


def test_testmempoolaccept_trailing_byte_is_decode_failure():
    h = _hex(_tx(False), False) + "00"
    with pytest.raises(RpcError) as ei:
        _run(RPCServer.rpc_testmempoolaccept(_rpc(), [h]))
    assert ei.value.code == -22
    assert ei.value.message == f"TX decode failed: {h} Make sure the tx has at least one input."


def test_sendrawtransaction_trailing_byte_is_decode_failure():
    h = _hex(_tx(False), False) + "00"
    with pytest.raises(RpcError) as ei:
        _run(RPCServer.rpc_sendrawtransaction(_rpc(), h))
    assert (ei.value.code, ei.value.message) == (
        -22, "TX decode failed. Make sure the tx has at least one input.")
