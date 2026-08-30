"""The integer CONVERSION runs before the lookup, and setban matches Core.

#81 fixed the arguments ouroboros ACCEPTED out of range.  This is the other
half: arguments ouroboros REJECTED, but with the wrong error, because the width
check ran after -- or instead of -- the conversion.  Measured against a regtest
Core oracle (tools/rpc-arg-differential.py): 16 findings, all four hostile
widths on each of

  getblockhash <h>              -> -8 "Block height out of range"   (Core -1)
  getblock <hash> <verbosity>   -> -5 "Block not found"             (Core -1)
  getrawtransaction <t> <verb>  -> -5 "No such mempool or ..."      (Core -1)
  getchaintxstats <nblocks>     -> -8 "Invalid block count..."      (Core -1)

Core's ``UniValue::getInt<T>`` runs ``std::from_chars`` INTO THE DESTINATION
WIDTH, so the width check fires inside the conversion and only surviving values
reach the lookup or the domain test.  Python's int is unbounded, so nothing
overflowed -- ``int(height)`` and ``int(nblocks)`` succeeded and carried a value
Core refuses straight into a lookup Core never performs.

setban came from the differential's CONTROL -- a call Core ANSWERS -- not from
a hostile integer (bitcoin-core/src/rpc/net.cpp):
  * an ABSOLUTE bantime already in the past was ACCEPTED; Core refuses it with
    -8, comparing strictly ``banTime < GetTime()``;
  * there was no already-banned check at all (Core: -23, and Core runs that
    check BEFORE bantime is read);
  * a failed unban surfaced a bare ValueError, which the dispatcher collapses
    to -32603, where Core answers -30 with its own wording.

TEETH: every assertion here is a rejection, and a handler that rejected
everything would satisfy all of them.  Each block carries a CONTROL that must
still SUCCEED or reach the REAL domain error, and ``bool`` is checked
explicitly because ``isinstance(True, int)`` is True in Python -- a naive
numeric guard would reject ``getblock(h, True)``.
"""

from __future__ import annotations

import time

import pytest

from ouroboros.rpc import RpcError, RPCServer

OUT_OF_INT32 = [2147483648, -2147483649, 4294967296, -4294967297]
ABSENT_HASH = "00" * 31 + "ff"
SOME_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


class _FakeDB:
    """Enough surface for the handlers to reach their lookup -- and miss."""

    def get_best_block(self):
        return (b"\x00" * 32, 300)

    def get_block(self, _h):
        return None

    def get_block_bytes(self, _h):
        return None


class _Node:
    db = _FakeDB()


@pytest.fixture
def rpc():
    server = RPCServer.__new__(RPCServer)
    server.node = _Node()
    return server


async def _err(coro) -> tuple[int, str]:
    try:
        await coro
    except RpcError as e:
        return e.code, e.message
    except Exception as e:  # noqa: BLE001
        return -32603, str(e)
    return 0, "(no error - call succeeded)"


def _range_error(pair):
    assert pair == (-1, "JSON integer out of range"), pair


# ------------------------------------------- the conversion beats the lookup

@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getblockhash_height_conversion_beats_range_test(rpc, value):
    _range_error(await _err(rpc.rpc_getblockhash(value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getblock_verbosity_conversion_beats_lookup(rpc, value):
    _range_error(await _err(rpc.rpc_getblock(ABSENT_HASH, value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getrawtransaction_verbosity_conversion_beats_lookup(rpc, value):
    _range_error(await _err(rpc.rpc_getrawtransaction(SOME_TXID, value)))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", OUT_OF_INT32)
async def test_getchaintxstats_nblocks_conversion_beats_domain_test(rpc, value):
    _range_error(await _err(rpc.rpc_getchaintxstats(value)))


# ------------------------------------------------------------------ CONTROLS

@pytest.mark.asyncio
async def test_control_in_range_height_reaches_the_domain_error(rpc):
    """An in-range but out-of-chain height must still be Core's -8."""
    assert await _err(rpc.rpc_getblockhash(-1)) == (-8, "Block height out of range")


@pytest.mark.asyncio
async def test_control_absent_hash_still_reaches_block_not_found(rpc):
    assert await _err(rpc.rpc_getblock(ABSENT_HASH, 1)) == (-5, "Block not found")


@pytest.mark.asyncio
async def test_control_bool_verbosity_is_not_an_integer_argument(rpc):
    """isinstance(True, int) is True in Python: a naive numeric guard would
    convert `verbosity=True` and could reject it.  It must reach the lookup."""
    assert await _err(rpc.rpc_getblock(ABSENT_HASH, True)) == (-5, "Block not found")


# -------------------------------------------------------------------- setban

class _BanManager:
    def __init__(self):
        self.banned: dict[str, float] = {}
        self.calls: list[tuple] = []

    def is_banned(self, ip):
        return ip in self.banned and self.banned[ip] > time.time()

    def setban(self, subnet, command, bantime, absolute):
        self.calls.append((subnet, command, bantime, absolute))
        if command == "add":
            until = bantime if absolute else time.time() + (bantime or 86400)
            self.banned[subnet] = until
            return True
        if subnet in self.banned:
            del self.banned[subnet]
            return True
        return False


class _PeerManager:
    def __init__(self):
        self.ban_manager = _BanManager()


@pytest.fixture
def rpc_with_bans(rpc):
    rpc.node.peer_manager = _PeerManager()
    return rpc


@pytest.mark.asyncio
async def test_setban_absolute_timestamp_in_the_past_is_refused(rpc_with_bans):
    got = await _err(
        rpc_with_bans.rpc_setban("1.2.3.4", "add", 1, True)
    )
    assert got == (-8, "Error: Absolute timestamp is in the past"), got
    # ...and nothing was recorded: the refusal happens before the ban call.
    assert rpc_with_bans.node.peer_manager.ban_manager.calls == []


@pytest.mark.asyncio
async def test_setban_rebanning_is_minus_23_before_bantime_is_read(rpc_with_bans):
    assert await _err(rpc_with_bans.rpc_setban("1.2.3.4", "add")) == (
        0,
        "(no error - call succeeded)",
    )
    assert await _err(rpc_with_bans.rpc_setban("1.2.3.4", "add")) == (
        -23,
        "Error: IP/Subnet already banned",
    )
    # bantime is not even looked at on the already-banned path: an absolute
    # timestamp in the past would otherwise have been the -8 above.
    assert await _err(rpc_with_bans.rpc_setban("1.2.3.4", "add", 1, True)) == (
        -23,
        "Error: IP/Subnet already banned",
    )


@pytest.mark.asyncio
async def test_setban_failed_unban_is_minus_30_with_cores_wording(rpc_with_bans):
    assert await _err(rpc_with_bans.rpc_setban("9.9.9.9", "remove")) == (
        -30,
        "Error: Unban failed. Requested address/subnet was not previously "
        "manually banned.",
    )


@pytest.mark.asyncio
async def test_control_absolute_timestamp_in_the_future_is_accepted(rpc_with_bans):
    future = int(time.time()) + 3600
    assert await _err(
        rpc_with_bans.rpc_setban("5.6.7.8", "add", future, True)
    ) == (0, "(no error - call succeeded)")
    bm = rpc_with_bans.node.peer_manager.ban_manager
    assert bm.is_banned("5.6.7.8")
    # Teeth: the absolute flag reached the ban manager as absolute.
    assert bm.calls[-1] == ("5.6.7.8", "add", future, True)


@pytest.mark.asyncio
async def test_control_unbanning_something_banned_still_succeeds(rpc_with_bans):
    await rpc_with_bans.rpc_setban("7.7.7.7", "add")
    assert await _err(rpc_with_bans.rpc_setban("7.7.7.7", "remove")) == (
        0,
        "(no error - call succeeded)",
    )
    assert not rpc_with_bans.node.peer_manager.ban_manager.is_banned("7.7.7.7")
