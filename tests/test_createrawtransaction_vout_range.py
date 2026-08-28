"""createrawtransaction — vout/sequence/locktime must be validated Core's way.

THE DEFECT (regression pinned by this suite)
--------------------------------------------
``rpc_createrawtransaction`` did no range checking of its own.  It handed the
caller's ``vout`` straight to ``database.Transaction.serialize()``, which does
``prev_vout.to_bytes(4, 'little')``, and let the serializer decide the outcome:

    vout 2147483648 (2^31)  ->  ACCEPTED, serialized as outpoint index
                                0x80000000.  Bitcoin Core REJECTS this value.
    vout 4294967296 (2^32)  ->  -32603 "int too big to convert"
    vout -1                 ->  -32603 "can't convert negative int to unsigned"
    locktime -1             ->  -32603 "can't convert negative int to unsigned"

The last three are raw CPython exception strings escaping onto the wire.  An
RPC error message is supposed to describe the CALLER'S REQUEST; those describe
ouroboros's internals instead, and they carry -32603 ("internal error"), which
tells a client the node broke rather than that the request was invalid.

The 2^31 case is worse than a bad message: it is a SILENT ACCEPT of an input
Core refuses, so ouroboros would build and hand back a transaction that Core's
own ``createrawtransaction`` would never produce.

WHAT BITCOIN CORE DOES
----------------------
``AddInputs`` (bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45) reads the
field with ``find_value(o, "vout").getInt<int>()`` — ``int``, i.e. THIRTY-TWO
bits.  ``UniValue::getInt<Int>`` (src/univalue/include/univalue.h:139-150)
converts with ``std::from_chars`` into the destination width and throws
``std::runtime_error("JSON integer out of range")`` when the token does not
fit; rpc/server.cpp:514-515 turns that into RPC_MISC_ERROR (-1).

THE ORDERING IS UNIVALUE'S, NOT THE HANDLER'S: the width check lives inside the
*conversion*, so it runs BEFORE ``if (nOutput < 0) throw ... "vout cannot be
negative"``.  That is why -1 gets the vout-specific -8 message while
2147483648 — equally "not a valid vout" to a human — gets the generic -1
"JSON integer out of range".  Matching Core means matching that order, not just
the two checks.  ``vout -2147483649`` is the case that pins it: negative AND
out of int32 range, and Core answers -1, not -8.

TEETH
-----
Every case above is a rejection, and a handler that rejected EVERY input would
satisfy all of them.  The two CONTROL tests make that impossible: they drive
the real handler to success and then DECODE the returned hex with the node's
own deserializer (``ouroboros.psbt._deserialize_tx``), asserting the outpoint
index that actually reached the wire bytes.  The int32-MAX control (2147483647)
fails loudly if the new bound is off by one in the tight direction.  Both
controls pass BEFORE the fix as well as after — that is what makes them
controls.

References:
  bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45   AddInputs
  bitcoin-core/src/rpc/rawtransaction_util.cpp:151-156 ConstructTransaction
  bitcoin-core/src/univalue/include/univalue.h:139-150 getInt<Int>
  bitcoin-core/src/rpc/util.cpp:117-125                ParseHashV
  bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
                                                       RPC_INVALID_PARAMETER = -8
"""

from __future__ import annotations

import pytest

from ouroboros.psbt import _deserialize_tx
from ouroboros.rpc import RpcError, RPCServer

# Well-formed 64-hex txid.  Its content is irrelevant: createrawtransaction
# builds an UNSIGNED transaction from its arguments alone and never looks the
# outpoint up, so no chainstate is involved.
TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

INT32_MAX = 2147483647
INT32_MAX_PLUS_1 = 2147483648
INT32_MIN_MINUS_1 = -2147483649
TWO_POW_32 = 4294967296
TWO_POW_33 = 8589934592

# A single OP_RETURN output.  Deliberately data-only so the test never touches
# address encoding or the network params — a failure here can only mean the
# INPUT parser, never the output parser (and no node/chainstate is needed).
OUTPUTS = {"data": "deadbeef"}


@pytest.fixture
def rpc():
    """A bare RPCServer.  createrawtransaction is pure argument-processing, so
    the real handler runs with no node, db, mempool or wallet attached."""
    return RPCServer.__new__(RPCServer)


async def _call(rpc, inputs, **kwargs):
    return await rpc.rpc_createrawtransaction(inputs, OUTPUTS, **kwargs)


async def _err(rpc, inputs, **kwargs) -> tuple[int, str]:
    """Run the real handler and return (code, message).

    A call that SUCCEEDS is reported as a distinctive sentinel rather than
    silently passing, and any non-RpcError exception is reported with the code
    the dispatcher would actually have emitted for it (-32603), so the
    pre-fix "raw CPython text at -32603" behaviour is visible in the failure
    output instead of being swallowed as an error.
    """
    try:
        await _call(rpc, inputs, **kwargs)
    except RpcError as e:
        return e.code, e.message
    except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
        return -32603, str(e)
    return 0, "(no error - call succeeded)"


async def _first_vout(rpc, inputs, **kwargs) -> int:
    """Decode the returned hex with the node's own deserializer and report the
    outpoint index that actually landed in the transaction bytes."""
    raw_hex = await _call(rpc, inputs, **kwargs)
    tx = _deserialize_tx(bytes.fromhex(raw_hex))
    assert len(tx.inputs) == 1, "expected exactly one input in the built tx"
    return tx.inputs[0].prev_vout


# --------------------------------------------------------------------------
# THE REGRESSION: vout is an int32 in Core, and the range check comes FIRST.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vout",
    [
        pytest.param(TWO_POW_32, id="2^32"),
        pytest.param(TWO_POW_33, id="2^33"),
        # The exact boundary: one past what Core's getInt<int> can hold.  This
        # value was ACCEPTED before the fix and written as 0x80000000.
        pytest.param(INT32_MAX_PLUS_1, id="int32max+1"),
        # Negative AND out of int32 range.  Core's range check lives inside the
        # conversion, so it wins over the "cannot be negative" message: this is
        # the ORDERING assertion.
        pytest.param(INT32_MIN_MINUS_1, id="int32min-1-range-beats-sign"),
    ],
)
async def test_vout_outside_int32_is_misc_error(rpc, vout):
    code, msg = await _err(rpc, [{"txid": TXID, "vout": vout}])
    assert (code, msg) == (-1, "JSON integer out of range")


# --------------------------------------------------------------------------
# Neighbouring guards must report Core's own codes and wording.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vout_negative_in_int32_range_is_invalid_parameter(rpc):
    """-1 fits in an int32, so the range check passes and the sign test speaks."""
    code, msg = await _err(rpc, [{"txid": TXID, "vout": -1}])
    assert (code, msg) == (-8, "Invalid parameter, vout cannot be negative")


@pytest.mark.asyncio
async def test_missing_vout_key(rpc):
    code, msg = await _err(rpc, [{"txid": TXID}])
    assert (code, msg) == (-8, "Invalid parameter, missing vout key")


@pytest.mark.asyncio
@pytest.mark.parametrize("seq", [TWO_POW_32, -1], ids=["2^32", "negative"])
async def test_sequence_out_of_range(rpc, seq):
    code, msg = await _err(rpc, [{"txid": TXID, "vout": 0, "sequence": seq}])
    assert (code, msg) == (
        -8, "Invalid parameter, sequence number is out of range",
    )


@pytest.mark.asyncio
async def test_locktime_negative(rpc):
    code, msg = await _err(rpc, [{"txid": TXID, "vout": 0}], locktime=-1)
    assert (code, msg) == (-8, "Invalid parameter, locktime out of range")


@pytest.mark.asyncio
async def test_malformed_txid_uses_parsehashv_wording(rpc):
    """Core runs ParseHashO BEFORE it looks at vout, so a malformed txid is
    reported as a txid problem with ParseHashV's exact wording."""
    code, msg = await _err(rpc, [{"txid": "abc", "vout": 0}])
    assert (code, msg) == (-8, "txid must be of length 64 (not 3, for 'abc')")


@pytest.mark.asyncio
async def test_non_numeric_sequence_is_ignored(rpc):
    """Core guards the sequence read with `if (sequenceObj.isNum())`, so a
    present-but-non-numeric sequence is IGNORED and the default applies
    (replaceable defaults true -> MAX_BIP125_RBF_SEQUENCE 0xFFFFFFFD)."""
    raw_hex = await _call(rpc, [{"txid": TXID, "vout": 0, "sequence": "nope"}])
    tx = _deserialize_tx(bytes.fromhex(raw_hex))
    assert tx.inputs[0].sequence == 0xFFFFFFFD


# --------------------------------------------------------------------------
# CONTROLS — these must pass BOTH before and after the fix.  Without them the
# suite above is satisfiable by a handler that rejects everything, and an
# over-tight bound would slip through.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_control_int32_max_is_accepted_and_lands_in_the_bytes(rpc):
    """Proves the new upper bound is `> INT32_MAX`, not `>=` or some smaller
    cap.  Fails loudly if the guard is over-tight by even one."""
    assert await _first_vout(rpc, [{"txid": TXID, "vout": INT32_MAX}]) == INT32_MAX


@pytest.mark.asyncio
async def test_control_ordinary_vout_is_accepted_and_lands_in_the_bytes(rpc):
    """Proves the handler still does its normal job, so the rejection tests
    above cannot be satisfied by a reject-everything stub."""
    assert await _first_vout(rpc, [{"txid": TXID, "vout": 7}]) == 7
