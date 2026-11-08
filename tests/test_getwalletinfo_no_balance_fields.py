"""getwalletinfo carries no balance fields, like Core v31.

Core v31.1 wallet/rpc/wallet.cpp getwalletinfo returns walletname,
walletversion, format, txcount, keypoolsize, ... flags, and no
``balance`` / ``unconfirmed_balance`` / ``immature_balance``: balances are
reported by getbalances (and getbalance).  ouroboros still emitted all three,
and filled two of them with a constant 0.0 whatever the wallet held
(tools/core-regtest rows ``wallet/receive/getwalletinfo:balance``,
``:immature_balance`` and ``:unconfirmed_balance``, Core ``<absent>``).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from ouroboros.rpc import RPCServer


class _Wallet:
    name = "w"
    is_hd = False
    is_encrypted = False
    is_locked = False
    _tx_history: dict = {}

    # Only base's getwalletinfo calls this (to fill "balance"); it is kept so
    # the test runs on base and fails there on its assertion, by name.
    async def get_balance(self):
        return 50 * 100_000_000

    def get_keypool_size(self):
        return 1000


def _info():
    wallet = _Wallet()
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(db=None)
    server._require_wallet = lambda: wallet
    return asyncio.run(server.rpc_getwalletinfo())


def test_getwalletinfo_has_no_balance_fields():
    info = _info()
    for key in ("balance", "unconfirmed_balance", "immature_balance"):
        assert key not in info, f"getwalletinfo still reports {key!r}: Core v31 has no such field"


def test_getwalletinfo_keeps_core_fields():
    """Control: the fields Core v31 does return are still there."""
    info = _info()
    for key in ("walletname", "walletversion", "format", "txcount", "keypoolsize",
                "private_keys_enabled", "avoid_reuse", "scanning", "descriptors",
                "external_signer", "blank", "flags", "lastprocessedblock"):
        assert key in info, key
    assert info["walletname"] == "w"
