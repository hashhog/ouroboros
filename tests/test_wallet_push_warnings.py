"""createwallet / loadwallet / restorewallet / unloadwallet warnings shape.

Item refill-20261114-ouroboros-policy (core-regtest row
``wallet/create/wallet:warning``).  Core pushes a ``warnings`` array only
when there is at least one warning (rpc/util.cpp PushWarnings, called from
wallet/rpc/wallet.cpp createwallet / loadwallet / unloadwallet and
wallet/rpc/backup.cpp restorewallet) and has no ``warning`` string field.
ouroboros always answered ``"warning": ""``.

Every test calls an RPC method that exists on master, so master runs them
and fails on the assertion.
"""

from __future__ import annotations

import asyncio

import pytest

from ouroboros.rpc import RPCServer
from ouroboros.wallet import WalletManager


class _DB:
    def get_best_block(self):
        return b"\x00" * 32, 0

    def get_utxo(self, txid, vout):
        return None


class _Node:
    def __init__(self, datadir):
        self.db = _DB()
        self.network = "regtest"
        self.mempool = None
        self.wallet = None
        self.wallet_manager = WalletManager(str(datadir), "regtest")


@pytest.fixture
def server(tmp_path):
    return RPCServer(_Node(tmp_path / "datadir"), port=18399, rate_limit=False)


def _run(coro):
    return asyncio.run(coro)


def test_createwallet_has_no_warning_field(server):
    assert _run(server.rpc_createwallet("w1")) == {"name": "w1"}


def test_unload_and_load_wallet_have_no_warning_field(server):
    _run(server.rpc_createwallet("w1"))
    assert _run(server.rpc_unloadwallet("w1")) == {}
    assert _run(server.rpc_loadwallet("w1")) == {"name": "w1"}


def test_restorewallet_has_no_warning_field(server, tmp_path):
    _run(server.rpc_createwallet("w1"))
    backup = tmp_path / "w1.bak"
    server.node.wallet_manager.get_wallet("w1").backup(str(backup))
    assert _run(server.rpc_restorewallet("w2", str(backup))) == {"name": "w2"}


def test_warnings_are_an_array_when_present():
    from ouroboros.rpc import _push_warnings
    assert _push_warnings({"name": "w"}, ["a", "b"]) == {"name": "w", "warnings": ["a", "b"]}
    assert _push_warnings({}, []) == {}
