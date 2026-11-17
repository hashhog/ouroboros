"""getaddressinfo ``labels`` as Core v31.1 answers it.

Item refill-20261116-ouroboros-policy, core-regtest row
``wallet/address/info:labels[0]`` (Core ``""``, ouroboros ``<missing>``).

Core (wallet/rpc/addresses.cpp getaddressinfo) pushes the label of the
address-book entry, the default label "" included, and an empty array when
the address has no entry.  getnewaddress always makes an entry; change
addresses never count (FindAddressBookEntry with allow_change=false); an
address outside the wallet has none.  ouroboros answered [] for every
address whose label was "".

Every test calls RPC methods that exist on master, so master runs them and
fails on the assertion.
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
    node = _Node(tmp_path)
    return RPCServer(node, port=18399, rate_limit=False)


def _run(coro):
    return asyncio.run(coro)


def test_getaddressinfo_lists_the_default_label(server):
    _run(server.rpc_createwallet("w1"))
    addr = _run(server.rpc_getnewaddress())
    info = _run(server.rpc_getaddressinfo(addr))
    assert info["ismine"] is True
    assert info["labels"] == [""]
    assert info["label"] == ""


def test_getaddressinfo_lists_a_named_label(server):
    _run(server.rpc_createwallet("w1"))
    addr = _run(server.rpc_getnewaddress("savings"))
    info = _run(server.rpc_getaddressinfo(addr))
    assert info["labels"] == ["savings"]
    assert info["label"] == "savings"


def test_getaddressinfo_change_address_has_no_labels(server):
    # Guard (passes on master too): a change address must not gain the
    # default label.
    _run(server.rpc_createwallet("w1"))
    addr = _run(server.rpc_getrawchangeaddress())
    assert _run(server.rpc_getaddressinfo(addr))["labels"] == []


def test_getaddressinfo_foreign_address_has_no_labels(server):
    # Guard (passes on master too): no address-book entry, no label.
    _run(server.rpc_createwallet("w1"))
    foreign = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    assert _run(server.rpc_getaddressinfo(foreign))["labels"] == []


def test_getaddressinfo_rescan_adopted_change_key_has_no_labels(server):
    # Guard (passes on master too; fails if the fix drops its ischange
    # test, see the negative control in the PR).  A rescan adopts a funded change key into wallet.keys with label "".
    # Core keeps change out of ``labels`` (allow_change=false), so this one
    # must stay [] even though the key now has a stored "" label.
    _run(server.rpc_createwallet("w1"))
    addr = _run(server.rpc_getrawchangeaddress())
    wallet = server._get_wallet_for_rpc()
    kp = wallet._key_pool
    found = None
    for purpose in (44, 49, 84, 86):
        for idx, key in kp._pools.get((purpose, True), []):
            for getter in (key.get_p2wpkh_address, key.get_p2pkh_address,
                           key.get_p2sh_p2wpkh_address, key.get_p2tr_address):
                try:
                    if getter() == addr:
                        found = (purpose, idx, key)
                except Exception:
                    continue
    assert found is not None
    purpose, idx, key = found
    assert wallet._adopt_key(
        {"key": key, "purpose": purpose, "is_change": True, "index": idx}
    )
    assert _run(server.rpc_getaddressinfo(addr))["labels"] == []
