"""sendtoaddress with no fee estimate must follow Core's -fallbackfee rule.

Core (wallet/fees.cpp + spend.cpp): with no estimate and -fallbackfee=0 (the
default) the send fails with RPC_WALLET_ERROR "Fee estimation failed.
Fallbackfee is disabled. ...".  With -fallbackfee set, that rate is used.
"""
from types import SimpleNamespace

import pytest

from ouroboros.rpc import RPCServer, RpcError, RPC_WALLET_ERROR

CORE_MSG = (
    "Fee estimation failed. Fallbackfee is disabled. "
    "Wait a few blocks or enable -fallbackfee."
)


class _Estimator:
    def __init__(self, rate):
        self.rate = rate

    def estimate_fee(self, target):
        return self.rate


class _Wallet:
    def __init__(self):
        self.rates = []

    async def send_transaction(self, address, amount, fee_rate):
        self.rates.append(fee_rate)
        return "00"


def _make(config, estimator=None):
    rpc = RPCServer.__new__(RPCServer)
    wallet = _Wallet()
    rpc.node = SimpleNamespace(config=config, fee_estimator=estimator)
    rpc._require_wallet = lambda: wallet
    rpc._decode_dest = lambda address: b""

    async def _send_raw(raw_hex):
        return "ab" * 32

    rpc.rpc_sendrawtransaction = _send_raw
    return rpc, wallet


async def test_sendtoaddress_no_estimate_no_fallbackfee_errors_like_core():
    rpc, wallet = _make({})
    with pytest.raises(RpcError) as exc:
        await rpc.rpc_sendtoaddress("bcrt1qdest", 0.1)
    assert exc.value.code == RPC_WALLET_ERROR
    assert exc.value.message == CORE_MSG
    assert wallet.rates == []


async def test_sendtoaddress_fallbackfee_zero_is_disabled():
    rpc, wallet = _make({"fallbackfee": 0.0}, _Estimator(None))
    with pytest.raises(RpcError) as exc:
        await rpc.rpc_sendtoaddress("bcrt1qdest", 0.1)
    assert exc.value.message == CORE_MSG


async def test_sendtoaddress_uses_fallbackfee_when_no_estimate():
    # 0.0002 BTC/kvB == 20 sat/vB
    rpc, wallet = _make({"fallbackfee": 0.0002}, _Estimator(None))
    assert await rpc.rpc_sendtoaddress("bcrt1qdest", 0.1) == "ab" * 32
    assert wallet.rates == [20]


async def test_sendtoaddress_estimate_wins_over_fallbackfee():
    rpc, wallet = _make({"fallbackfee": 0.0002}, _Estimator(7))
    await rpc.rpc_sendtoaddress("bcrt1qdest", 0.1)
    assert wallet.rates == [7]
