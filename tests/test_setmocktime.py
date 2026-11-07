"""setmocktime (regtest only), mirroring Bitcoin Core rpc/node.cpp setmocktime.

Core: not a mockable chain -> runtime error; time < 0 -> RPC_INVALID_PARAMETER
"Mocktime must be in the range [0, max], not N."; 0 returns to system time;
returns null.  The mocked clock must reach the mempool (entry time, expiry,
rolling-fee decay) and the time-too-new header gate.
"""

import asyncio
import time
import types

import pytest

from ouroboros.rpc import RPCServer, RpcError


def make_rpc(network="regtest"):
    node = types.SimpleNamespace(network=network)
    return RPCServer(node, port=18451)


@pytest.fixture(autouse=True)
def _reset_clock():
    yield
    try:
        from ouroboros import clock
    except ImportError:  # base commit: no clock module yet
        return
    clock.set_mock_time(0)


def run(coro):
    return asyncio.run(coro)


def test_setmocktime_sets_and_clears_clock():
    from ouroboros import clock

    rpc = make_rpc()
    assert run(rpc.rpc_setmocktime(1_700_100_000)) is None
    assert clock.now() == 1_700_100_000
    assert int(time.time()) != 1_700_100_000
    assert run(rpc.rpc_setmocktime(0)) is None
    assert abs(clock.now() - time.time()) < 5


def test_setmocktime_negative_is_invalid_parameter():
    rpc = make_rpc()
    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_setmocktime(-1))
    assert ei.value.code == -8
    assert ei.value.message.startswith("Mocktime must be in the range [0, ")
    assert ei.value.message.endswith(", not -1.")


def test_setmocktime_rejected_off_regtest():
    rpc = make_rpc("mainnet")
    with pytest.raises(Exception) as ei:
        run(rpc.rpc_setmocktime(1_700_100_000))
    assert "setmocktime is for regression testing (-regtest mode) only" in str(ei.value)
    from ouroboros import clock
    assert abs(clock.now() - time.time()) < 5


def test_setmocktime_type_error():
    rpc = make_rpc()
    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_setmocktime("x"))
    assert ei.value.code == -3


def _regtest_validator():
    from unittest.mock import MagicMock
    from ouroboros.validation import BlockValidator

    v = BlockValidator.__new__(BlockValidator)
    v.network = "regtest"
    v.db = MagicMock()
    v.db.get_block_by_height.return_value = None
    return v


def _hdr(timestamp):
    from unittest.mock import MagicMock

    b = MagicMock()
    b.bits = 0x207FFFFF
    b.timestamp = timestamp
    b.version = 4
    b.serialize.return_value = b"\x00" * 80
    return b


def test_mocked_clock_moves_time_too_new_bound():
    """Header at mock+7200 is accepted; mock+7201 is time-too-new.

    Without the mock the same timestamps (2023) are far in the past of the real
    clock, so both would be accepted; pinning the clock to 1_000_000 makes the
    boundary observable and proves the validator reads the mockable clock.
    """
    from ouroboros import clock

    v = _regtest_validator()
    prev = _hdr(900_000)
    mock = 1_000_000
    clock.set_mock_time(mock)
    ok = v._validate_header(_hdr(mock + 7200), prev, block_mtp=0, height=1, skip_pow=True)
    bad = v._validate_header(_hdr(mock + 7201), prev, block_mtp=0, height=1, skip_pow=True)
    assert ok is True
    assert bad is False


def _mempool_with_old_tx(time_added):
    from tests.test_mempool_eviction import _inject, _make_tx, _pool, _txid

    pool = _pool()
    txid = _txid(1)
    _inject(pool, _make_tx(txid, [(_txid(0), 0)], [50_000]), fee=1000, time_added=time_added)
    return pool, txid


def test_mempool_expiry_reads_mock_clock():
    from ouroboros import clock
    from ouroboros.mempool import MEMPOOL_EXPIRY_HOURS

    added = 1_700_000_000
    pool, txid = _mempool_with_old_tx(added)
    expiry = MEMPOOL_EXPIRY_HOURS * 3600
    clock.set_mock_time(added + expiry - 10)
    assert pool.expire_old_transactions() == 0
    assert txid in pool.transactions
    clock.set_mock_time(added + expiry + 10)
    assert pool.expire_old_transactions() == 1
    assert txid not in pool.transactions
