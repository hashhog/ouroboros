"""sendrawtransaction mempool rejects are RPC_VERIFY_REJECTED (-26) "<reason>, <details>".

Core node/transaction.cpp BroadcastTransaction -> HandleATMPError: a tx the
mempool refuses (anything but missing inputs) throws
JSONRPCError(RPC_TRANSACTION_REJECTED = -26, state.ToString()), and
ValidationState::ToString is "<reject-reason>, <debug-message>" (bare reason
when no debug message). ouroboros raised an HTTPException, so the client saw
-32603 with a colon-joined message. Core regtest rows
``*/maturity/tip99-send:{code,message}`` and ``rbf/diagram/submit:code``.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from tests.test_sendrawtransaction_core_errors import (
    OP_TRUE, PREV, RpcError, RPCServer, SimpleNamespace, Mempool,
    TransactionValidator, _DB, _tx,
)


class _CoinbaseDB(_DB):
    """PREV:0 is a coinbase output whose height leaves it immature."""

    def get_utxo(self, txid, vout):
        coin = super().get_utxo(txid, vout)
        if coin is not None and (bytes(txid), vout) == (PREV, 0):
            coin = dict(coin, height=150, is_coinbase=True)
        return coin


def _send_raw(tx, db):
    pool = Mempool(validator=TransactionValidator(db, network="regtest"),
                   require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db),
                          DEFAULT_MAX_RAW_TX_FEE_RATE=0.10)
    rpc._map_mempool_error_to_reject_reason = types.MethodType(
        RPCServer._map_mempool_error_to_reject_reason, rpc)
    return asyncio.run(RPCServer.rpc_sendrawtransaction(rpc, tx.serialize().hex()))


def test_immature_coinbase_spend_is_minus_26_with_core_message():
    with pytest.raises(RpcError) as exc:
        _send_raw(_tx(), _CoinbaseDB())
    assert exc.value.code == -26
    assert exc.value.message.startswith(
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth ")


def test_mempool_missing_inputs_stays_minus_25():
    # An input that vanishes between the pre-check and ATMP is still Core's
    # TransactionError::MISSING_INPUTS (-25), never -26.
    class _Pool(Mempool):
        def add_transaction(self, tx, height):
            return False, "orphan: missing inputs"

    class _DB2(_DB):
        pass

    db = _DB2()
    pool = _Pool(validator=TransactionValidator(db, network="regtest"),
                 require_standard=False)
    rpc = SimpleNamespace(node=SimpleNamespace(mempool=pool, db=db),
                          DEFAULT_MAX_RAW_TX_FEE_RATE=0.10)
    rpc._map_mempool_error_to_reject_reason = types.MethodType(
        RPCServer._map_mempool_error_to_reject_reason, rpc)
    with pytest.raises(RpcError) as exc:
        asyncio.run(RPCServer.rpc_sendrawtransaction(rpc, _tx().serialize().hex()))
    assert exc.value.code == -25
    assert exc.value.message == "bad-txns-inputs-missingorspent"
