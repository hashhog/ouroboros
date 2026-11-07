"""getblockheader's ``verbose`` must be a JSON bool, like Core.

Core type-checks the argument before running the handler (rpc/util.cpp
RPCTypeCheckArgument), so ``getblockheader <hash> "x"`` is -3
"Wrong type passed" rather than a header object.
"""

from __future__ import annotations

import asyncio

import pytest

from ouroboros.rpc import RPCServer, RpcError


def _rpc() -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    rpc.node = _Node()
    rpc._current_wallet_name = None
    return rpc


@pytest.mark.parametrize(
    "bad, typename",
    [("x", "string"), (1, "number"), (0, "number"), ([], "array"), ({}, "object")],
)
def test_getblockheader_rejects_non_bool_verbose(bad, typename) -> None:
    with pytest.raises(RpcError) as ei:
        asyncio.run(_rpc().rpc_getblockheader("00" * 32, bad))
    assert ei.value.code == -3
    assert ei.value.message == (
        'Wrong type passed:\n{\n    "Position 2 (verbose)": '
        f'"JSON value of type {typename} is not of expected type bool"\n}}'
    )
