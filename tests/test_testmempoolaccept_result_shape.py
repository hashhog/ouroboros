"""testmempoolaccept: the shape of an ALLOWED row and the rawtxs type error.

Core rpc/mempool.cpp testmempoolaccept: an allowed result carries ``vsize`` and
``fees`` {base, effective-feerate, effective-includes} and has NO
``reject-reason`` key; ``reject-reason`` appears only on a rejected row.  A
non-array first argument fails Core's RPCArg type check:
``Wrong type passed:\\n{\\n    "Position 1 (rawtxs)": "JSON value of type
string is not of expected type array"\\n}`` (RPC_TYPE_ERROR, -3).

Core regtest rows: operator/testmempoolaccept/{valid,maxfeerate-zero}:[0].
{fees,vsize,reject-reason} and operator/testmempoolaccept/not-an-array:message.
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
COINBASE_TXID = bytes([0x77]) * 32
COIN_VALUE = 50 * 100_000_000
FEE = 10_000


class _ChainDB:
    def __init__(self, tip: int = 200):
        self.tip = tip

    def get_utxo(self, txid, vout):
        if (bytes(txid), vout) == (COINBASE_TXID, 0):
            return {"txid": COINBASE_TXID, "vout": 0, "value": COIN_VALUE,
                    "script_pubkey": OP_TRUE, "height": 1, "is_coinbase": True}
        return None

    def get_utxo_batch(self, outpoints):
        return [self.get_utxo(t, v) for t, v in outpoints]

    def get_median_time_past(self, height=None):
        return 1_700_000_000

    def get_best_block(self):
        return bytes([self.tip % 256]) * 32, self.tip


def _spend() -> Transaction:
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=COINBASE_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=COIN_VALUE - FEE, script_pubkey=OP_TRUE)],
    )
    return TxMessage.from_payload(tmp.serialize()).transaction


def _call(*args):
    db = _ChainDB()
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))
    return asyncio.run(RPCServer.rpc_testmempoolaccept(rpc, *args)), pool


def test_allowed_row_has_vsize_and_fees_and_no_reject_reason():
    tx = _spend()
    [row], pool = _call([tx.serialize().hex()])
    assert not pool.transactions, "test_accept must not add to the pool"
    vsize = tx.get_vsize()
    assert row["allowed"] is True, row
    assert "reject-reason" not in row
    assert row["vsize"] == vsize
    assert row["fees"] == {
        "base": FEE / 1e8,
        "effective-feerate": (FEE * 1000 // vsize) / 1e8,
        "effective-includes": [tx.get_wtxid()[::-1].hex()],
    }


def test_maxfeerate_zero_allowed_row_has_same_shape():
    tx = _spend()
    [row], _ = _call([tx.serialize().hex()], 0)
    assert row["allowed"] is True and "reject-reason" not in row
    assert row["vsize"] == tx.get_vsize() and row["fees"]["base"] == FEE / 1e8


def test_fee_above_maxfeerate_is_max_fee_exceeded():
    tx = _spend()
    # 10_000 sat over ~ 60 vB is far above 0.00001 BTC/kvB.
    [row], _ = _call([tx.serialize().hex()], 0.00001)
    assert row["allowed"] is False
    assert row["reject-reason"] == "max-fee-exceeded"
    assert "vsize" not in row and "fees" not in row


def test_rejected_row_keeps_reject_reason():
    # Negative control: an unknown coin is still a reject with a reason.
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=bytes([9]) * 32, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=1000, script_pubkey=OP_TRUE)],
    )
    tx = TxMessage.from_payload(tmp.serialize()).transaction
    [row], _ = _call([tx.serialize().hex()])
    assert row["allowed"] is False
    assert row["reject-reason"] == "missing-inputs"
    assert "vsize" not in row and "fees" not in row


def test_rawtxs_not_an_array_is_core_wrong_type_message():
    with pytest.raises(RpcError) as ei:
        _call(_spend().serialize().hex())
    assert ei.value.code == -3
    assert ei.value.message == (
        'Wrong type passed:\n{\n    "Position 1 (rawtxs)": '
        '"JSON value of type string is not of expected type array"\n}'
    )


def test_replacement_dry_run_reports_fee_and_vsize():
    # rbf/simple/accept: an allowed replacement must report the REPLACEMENT's
    # fee and vsize, not the zeros of a dry-run that returned before computing them.
    db = _ChainDB()
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    first = _spend()
    ok, why = pool.add_transaction(first, 200)
    assert ok, why
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=COINBASE_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=COIN_VALUE - 3 * FEE, script_pubkey=OP_TRUE)],
    )
    repl = TxMessage.from_payload(tmp.serialize()).transaction
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db))
    [row] = asyncio.run(RPCServer.rpc_testmempoolaccept(rpc, [repl.serialize().hex()]))
    assert row["allowed"] is True, row
    assert row["vsize"] == repl.get_vsize() > 0
    assert row["fees"]["base"] == 3 * FEE / 1e8
    assert pool.transactions.get(first.get_txid()) is not None, "dry run must not evict"
