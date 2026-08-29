"""RPC integer arguments must be read at Core's width — and honoured.

THE DEFECT (pinned here)
------------------------
Core reads every numeric RPC argument through ``UniValue::getInt<T>()``
(src/univalue/include/univalue.h), which runs ``std::from_chars`` INTO THE
DESTINATION WIDTH.  The width check therefore lives INSIDE the conversion and
fires BEFORE the handler's own domain test:

    out of width / fractional   ->  RPC_MISC_ERROR (-1) "JSON integer out of
                                    range"  (rpc/server.cpp:514-515)
    converts, violates the range->  RPC_INVALID_PARAMETER (-8)

Python's ``int`` is arbitrary-precision, so nothing wraps and nothing raises —
the handler simply ACTS on a value Core refuses.  Measured against a regtest
Bitcoin Core oracle (tools/rpc-arg-differential.py), ouroboros ACCEPTED 16 such
arguments across four methods.

Two were not merely unbounded but FABRICATIONS — an argument read and then not
honoured:

  * ``estimatesmartfee`` CLAMPED conf_target into [1, 1008], so a request for a
    99999-block estimate came back as a 1008-block one, reported as success.
    Core's ``ParseConfirmTarget`` (rpc/util.cpp) rejects.  ``estimate_mode`` was
    ignored entirely; Core validates it with ``FeeModeFromString``
    (common/messages.cpp), case-insensitively.
  * ``getnetworkhashps`` CLAMPED an out-of-range height to the tip and read
    every nblocks <= 0 as "the current epoch".  Core's ``GetNetworkHashPS``
    (rpc/mining.cpp) rejects nblocks 0 / < -1 and a height above the tip, and
    reads -1 (only) as "since the last difficulty change".

TEETH
-----
Every assertion above is a rejection, and a handler that rejected everything
would satisfy all of them.  Each block therefore carries a CONTROL that must
still SUCCEED, and ``bool`` is checked explicitly because in Python
``isinstance(True, int)`` is True — a naive numeric guard accepts ``true``.
"""

from __future__ import annotations

import pytest

from ouroboros.rpc import RpcError, RPCServer

OUT_OF_INT32 = [2147483648, -2147483649, 4294967296, -4294967297]


@pytest.fixture
def rpc():
    """A bare RPCServer: argument validation runs before any node access."""
    return RPCServer.__new__(RPCServer)


async def _err(coro) -> tuple[int, str]:
    """(code, message) for a call expected to be rejected."""
    try:
        await coro
    except RpcError as e:
        return e.code, e.message
    except Exception as e:  # noqa: BLE001
        return -32603, str(e)
    return 0, "(no error - call succeeded)"


def _range_error(pair):
    assert pair == (-1, "JSON integer out of range"), pair


class _FakeDB:
    """Minimum surface getnetworkhashps touches before it can reject."""

    def get_best_block(self):
        return (b"\x00" * 32, 300)


class _NodeWithDB:
    db = _FakeDB()


# --------------------------------------------------------------- wait family

@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_waitforblockheight_height_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_waitforblockheight(value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_waitforblockheight_timeout_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_waitforblockheight(1, value)))


@pytest.mark.asyncio
async def test_waitforblockheight_negative_timeout_keeps_core_message(rpc):
    """CONTROL for the ORDER: an in-range negative timeout converts fine and
    reaches the handler's own domain message."""
    assert await _err(rpc.rpc_waitforblockheight(1, -1)) == (-1, "Negative timeout")


# ---------------------------------------------------------- getnodeaddresses

@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getnodeaddresses_count_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_getnodeaddresses(value)))


@pytest.mark.asyncio
async def test_getnodeaddresses_negative_count_is_domain_error(rpc):
    """CONTROL for the ORDER: -1 converts, so it reaches Core's -8."""
    assert await _err(rpc.rpc_getnodeaddresses(-1)) == (
        -8, "Address count out of range")


@pytest.mark.asyncio
async def test_getnodeaddresses_bool_is_not_a_count(rpc):
    """bool is a subclass of int in Python; Core reads it as a type error."""
    code, _ = await _err(rpc.rpc_getnodeaddresses(True))
    assert code == -3, code


# ---------------------------------------------------------- estimatesmartfee

@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_estimatesmartfee_conf_target_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_estimatesmartfee(value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [99999, 1009, 0, -1])
async def test_estimatesmartfee_conf_target_out_of_domain_is_rejected(rpc, value):
    assert await _err(rpc.rpc_estimatesmartfee(value)) == (
        -8, "Invalid conf_target, must be between 1 and 1008")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["", "garbage", "ECONOMICALLY"])
async def test_estimatesmartfee_unknown_estimate_mode_is_rejected(rpc, mode):
    assert await _err(rpc.rpc_estimatesmartfee(6, mode)) == (
        -8,
        'Invalid estimate_mode parameter, must be one of: '
        '"unset", "economical", "conservative"',
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["unset", "economical", "CONSERVATIVE", "Economical"])
async def test_estimatesmartfee_valid_modes_still_answer(rpc, mode):
    """CONTROL: a valid target and mode get past validation and produce a
    result.  The bare server has no fee estimator, so Core's own
    "not available" shape is what a successful pass-through looks like."""
    rpc.node = _NodeWithDB()   # no fee_estimator attribute: Core's
                               # "not available" shape, i.e. a clean
                               # pass-through rather than an argument error
    result = await rpc.rpc_estimatesmartfee(6, mode)
    assert result["blocks"] == 6


# ---------------------------------------------------------- getnetworkhashps

@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getnetworkhashps_nblocks_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_getnetworkhashps(value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getnetworkhashps_height_out_of_int32(rpc, value):
    _range_error(await _err(rpc.rpc_getnetworkhashps(1, value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -2, -1000])
async def test_getnetworkhashps_degenerate_nblocks_is_rejected(rpc, value):
    assert await _err(rpc.rpc_getnetworkhashps(value)) == (
        -8, "Invalid nblocks. Must be a positive number or -1.")


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [301, 99999999])
async def test_getnetworkhashps_height_above_tip_is_rejected(rpc, value):
    """Was CLAMPED to the tip: every call answered for the tip, whatever
    height was asked for."""
    rpc.node = _NodeWithDB()
    assert await _err(rpc.rpc_getnetworkhashps(120, value)) == (
        -8, "Block does not exist at specified height")


@pytest.mark.asyncio
async def test_getnetworkhashps_nblocks_minus_one_is_accepted(rpc):
    """CONTROL: -1 is the DOCUMENTED "since the last difficulty change" value
    and must survive the new nblocks check."""
    rpc.node = _NodeWithDB()
    code, msg = await _err(rpc.rpc_getnetworkhashps(-1))
    assert code != -8, (code, msg)
