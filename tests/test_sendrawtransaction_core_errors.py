"""sendrawtransaction error paths, as Core's rpc/mempool.cpp + node/transaction.cpp.

* A tx whose outputs already exist in the UTXO set (it is confirmed and not
  spent) is RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) "Transaction outputs already
  in utxo set" -- not a silent success returning the txid.
* A tx spending an unknown/spent coin is TransactionError::MISSING_INPUTS ->
  RPC_VERIFY_ERROR (-25) "bad-txns-inputs-missingorspent".
* A non-numeric maxfeerate fails AmountFromValue: RPC_TYPE_ERROR (-3)
  "Invalid amount", not a Python TypeError surfacing as -32603.

Core regtest rows: operator/sendrawtransaction/{confirmed,missing-inputs,
bad-maxfeerate}.
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


def _tx(prev=PREV) -> Transaction:
    tmp = Transaction(
        txid=bytes(32), version=2, locktime=0,
        inputs=[TxIn(prev_txid=prev, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=1000, script_pubkey=OP_TRUE)],
    )
    return TxMessage.from_payload(tmp.serialize()).transaction


class _DB:
    """Chain with one unspent coin (PREV:0) and, optionally, an unspent output of ``confirmed``."""

    def __init__(self, confirmed_txid: bytes | None = None):
        self.confirmed_txid = confirmed_txid

    def get_utxo(self, txid, vout):
        if (bytes(txid), vout) == (PREV, 0):
            return {"txid": PREV, "vout": 0, "value": 10_000, "script_pubkey": OP_TRUE,
                    "height": 1, "is_coinbase": False}
        if self.confirmed_txid is not None and (bytes(txid), vout) == (self.confirmed_txid, 0):
            return {"txid": txid, "vout": 0, "value": 1000, "script_pubkey": OP_TRUE,
                    "height": 5, "is_coinbase": False}
        return None

    def get_utxo_batch(self, outpoints):
        return [self.get_utxo(t, v) for t, v in outpoints]

    def get_tx_index(self, txid):
        return None  # no -txindex: must not matter

    def get_median_time_past(self, height=None):
        return 1_700_000_000

    def get_best_block(self):
        return bytes(32), 200


def _send(tx, *args, db=None):
    db = db or _DB()
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db),
                          DEFAULT_MAX_RAW_TX_FEE_RATE=0.10)
    return asyncio.run(RPCServer.rpc_sendrawtransaction(rpc, tx.serialize().hex(), *args))


def test_confirmed_tx_outputs_in_utxo_set_is_minus_27():
    tx = _tx()
    with pytest.raises(RpcError) as ei:
        _send(tx, db=_DB(confirmed_txid=tx.get_txid()))
    assert (ei.value.code, ei.value.message) == (-27, "Transaction outputs already in utxo set")


def test_missing_inputs_is_minus_25_with_core_token():
    with pytest.raises(RpcError) as ei:
        _send(_tx(prev=bytes([0x22]) * 32))
    assert (ei.value.code, ei.value.message) == (-25, "bad-txns-inputs-missingorspent")


@pytest.mark.parametrize("bad, msg", [
    ("x", "Invalid amount"),
    (True, "Amount is not a number or string"),
    ([1], "Amount is not a number or string"),
    ({"a": 1}, "Amount is not a number or string"),
    ("nan", "Invalid amount"),
    ("inf", "Invalid amount"),
    (0.123456789, "Invalid amount"),
    (-1, "Amount out of range"),
    (21_000_001, "Amount out of range"),
    (1e30, "Amount out of range"),
    ("1e30", "Amount out of range"),
    ("1_0", "Invalid amount"),
    (" 1", "Invalid amount"),
    ("", "Invalid amount"),
    ("+1", "Invalid amount"),
    (".5", "Invalid amount"),
    ("1.", "Invalid amount"),
    ("01", "Invalid amount"),
    ("1e-9", "Invalid amount"),
])
def test_non_numeric_maxfeerate_is_core_amount_error(bad, msg):
    # Core AmountFromValue (core_io / rpc/util.cpp): neither number nor string
    # -> "Amount is not a number or string"; an unparseable string ->
    # "Invalid amount"; both RPC_TYPE_ERROR (-3).
    with pytest.raises(RpcError) as ei:
        _send(_tx(), bad)
    assert (ei.value.code, ei.value.message) == (-3, msg)


def test_malformed_maxfeerate_is_refused_even_for_a_tx_already_in_the_mempool():
    # Core parses maxfeerate before consulting the mempool.
    tx = _tx()
    db = _DB()
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    ok, why = pool.add_transaction(tx, 200)
    assert ok, why
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db),
                          DEFAULT_MAX_RAW_TX_FEE_RATE=0.10)
    with pytest.raises(RpcError) as ei:
        asyncio.run(RPCServer.rpc_sendrawtransaction(rpc, tx.serialize().hex(), "x"))
    assert (ei.value.code, ei.value.message) == (-3, "Invalid amount")
    # ...and with a valid maxfeerate the same call is the idempotent success.
    assert asyncio.run(
        RPCServer.rpc_sendrawtransaction(rpc, tx.serialize().hex(), 0.1)
    ) == tx.get_txid()[::-1].hex()


def test_unchanged_behaviour_default_and_numeric_maxfeerate():
    # True negative control (passes on base too): omitted and plain numeric
    # maxfeerate keep accepting a good spend.
    tx = _tx()
    assert _send(tx) == tx.get_txid()[::-1].hex()
    tx2 = _tx()
    assert _send(tx2, 0.5) == tx2.get_txid()[::-1].hex()


def test_valid_spend_still_accepted_and_numeric_string_maxfeerate_parses():
    # Negative controls: the checks must not break a good send.
    tx = _tx()
    assert _send(tx, 0) == tx.get_txid()[::-1].hex()
    tx2 = _tx()
    assert _send(tx2, "0") == tx2.get_txid()[::-1].hex()
