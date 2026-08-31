"""#103 -- Core's central argument-count gate.

Core validates argument COUNT in one place, after the method lookup and before
any handler runs (rpc/util.cpp:644 -> IsValidNumArgs, :733):

    num_required <= n <= num_declared

A violation throws the help text, which surfaces as error -1. ouroboros
dispatched straight into ``handler(*params)``, so a surplus positional argument
raised a Python TypeError that came back as -32603, and a missing required one
produced whatever the handler happened to say.

Verified read-only against the live Core oracle on 2026-08-31:

    getblockhash []            -> code=-1  "getblockhash height"
    getblockcount ["surplus"]  -> code=-1  "getblockcount"
    getblockhash [1]           -> OK (control)
"""

import pytest

from ouroboros.rpc import _core_arity_for


def test_table_is_populated():
    """Guards every assertion below.

    A table that failed to load is an empty dict, which makes the gate fail
    open and every other test here vacuous. Check the denominator first.
    """
    assert _core_arity_for("savemempool") == (0, 0)
    assert _core_arity_for("clearbanned") == (0, 0)
    assert _core_arity_for("gettxout") == (2, 3)
    assert _core_arity_for("sendrawtransaction") == (1, 3)


def test_unknown_method_fails_open():
    """Coverage is 87 of 103. An unlisted method must NOT be treated as
    zero-arg -- that would reject calls Core accepts, which is worse than the
    gap being open."""
    assert _core_arity_for("definitely-not-an-rpc") is None


def _violates(method, n):
    a = _core_arity_for(method)
    assert a is not None, f"{method} missing from the table"
    return not (a[0] <= n <= a[1])


@pytest.mark.parametrize(
    "method,n",
    [
        ("savemempool", 1),          # Core's savemempool takes NO arguments
        ("clearbanned", 1),
        ("getblockcount", 1),
        ("gettxout", 1),             # one too few
        ("gettxout", 4),             # one too many
        ("sendrawtransaction", 0),   # missing the required hexstring
        ("getblockhash", 0),
        ("getblockhash", 2),
    ],
)
def test_out_of_range_arg_counts_are_violations(method, n):
    assert _violates(method, n)


@pytest.mark.parametrize(
    "method,n",
    [
        ("savemempool", 0),
        ("clearbanned", 0),
        ("getblockcount", 0),
        ("gettxout", 2),             # required
        ("gettxout", 3),             # declared
        ("sendrawtransaction", 1),
        ("sendrawtransaction", 2),
        ("sendrawtransaction", 3),
        ("getblockhash", 1),
    ],
)
def test_control_every_legal_count_is_accepted(method, n):
    """The CONTROLS. Without these a gate that refused everything would pass
    the rejection tests above. Every count from required..declared inclusive
    must be allowed."""
    assert not _violates(method, n)


# ---------------------------------------------------------------------------
# The gate must be WIRED INTO DISPATCH, not merely present as a helper.
# ---------------------------------------------------------------------------
# The tests above prove the table is correct. They would all still pass if the
# check were never called. These drive the real _execute_single_rpc code path
# on a stand-in `self`, so removing the gate makes them fail: without it,
# handler(*params) is invoked with the surplus argument and the TypeError comes
# back as -32603 rather than -1.


class _StubServer:
    """Minimal stand-in for RPCServer.

    Only what _execute_single_rpc actually touches: a settable
    _current_wallet_name and the handler attributes it looks up by name.
    """

    def __init__(self):
        self._current_wallet_name = None
        self.calls = []

    async def rpc_savemempool(self):
        self.calls.append(("savemempool", ()))
        return {"filename": "/dev/null"}

    async def rpc_gettxout(self, txid, n, include_mempool=True):
        self.calls.append(("gettxout", (txid, n, include_mempool)))
        return None


async def _call(stub, method, params):
    from ouroboros.rpc import RPCServer

    return await RPCServer._execute_single_rpc(
        stub, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )


@pytest.mark.asyncio
async def test_dispatch_rejects_surplus_argument_with_minus_one():
    stub = _StubServer()
    resp = await _call(stub, "savemempool", ["/tmp/somewhere"])
    assert resp["error"]["code"] == -1, resp
    # ...and the handler must never have run.
    assert stub.calls == []


@pytest.mark.asyncio
async def test_dispatch_rejects_missing_required_argument_with_minus_one():
    stub = _StubServer()
    resp = await _call(stub, "gettxout", ["ab"])
    assert resp["error"]["code"] == -1, resp
    assert stub.calls == []


@pytest.mark.asyncio
async def test_control_dispatch_still_reaches_the_handler():
    """CONTROL. Without this, a gate that refused everything would satisfy both
    tests above. Assert the ANSWER, not just the absence of an error."""
    stub = _StubServer()
    resp = await _call(stub, "savemempool", [])
    assert resp.get("error") is None, resp
    assert resp["result"] == {"filename": "/dev/null"}
    assert stub.calls == [("savemempool", ())]

    resp = await _call(stub, "gettxout", ["ab", 0])
    assert resp.get("error") is None, resp
    assert stub.calls[-1] == ("gettxout", ("ab", 0, True))


@pytest.mark.asyncio
async def test_control_unknown_method_is_still_method_not_found():
    """Ordering: Core looks the method up first, so an unknown name is -32601,
    never -1 from the arity gate."""
    stub = _StubServer()
    resp = await _call(stub, "definitely-not-an-rpc", ["a", "b"])
    assert resp["error"]["code"] == -32601, resp
