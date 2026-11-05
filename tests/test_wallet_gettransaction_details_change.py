"""gettransaction ``details`` match Core v31.1 CachedTxGetAmounts.

Core wallet/receive.cpp CachedTxGetAmounts: on a tx the wallet funded the
change output is skipped (OutputIsChange), and every other output is a
"send" -- a payment to one of the wallet's own addresses as well, which is
then ALSO a "receive".  ouroboros listed the change as a receive and the
self-payment only as a receive.

Core v31.1 regtest rows: wallet/confirm/gettransaction:details (reached
once getmempoolentry stops raising, hashhog/ouroboros#132).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tests._f0_chain import COIN


def _tx(wire):
    from ouroboros.p2p_messages import TxMessage
    return TxMessage.from_payload(wire, 0).transaction


def test_wallet_details_skip_change_and_list_self_payment_as_send(tmp_path):
    """Core gettransaction details for 1 BTC to the wallet's own second
    address from a 50 BTC coin: [receive 1, send -1]; the 49 BTC change is
    not listed.  ouroboros listed [receive 1, receive 49]."""
    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import Wallet

    wdir = tmp_path / "wallets" / "w"
    wdir.mkdir(parents=True)
    w = Wallet(data_dir=str(tmp_path), network="regtest", name="w", wallet_dir=str(wdir))
    w.init_hd(seed=bytes(range(32)))
    addr_a = asyncio.run(w.generate_new_address(address_type="bech32"))
    addr_b = asyncio.run(w.generate_new_address(address_type="bech32"))
    spk_a = address_to_script_pubkey(addr_a, w.network)

    fund_txid = b"\x33" * 32
    fund_tx = SimpleNamespace(
        inputs=[], outputs=[SimpleNamespace(value=50 * COIN, script_pubkey=spk_a)],
        is_coinbase=False, get_txid=lambda: fund_txid,
        serialize_with_witness=lambda: b"\x00",
    )
    w.scan_block_connect(SimpleNamespace(hash=b"\x01" * 32, timestamp=1, transactions=[fund_tx]), 101)

    class _DB:
        def get_best_block(self):
            return b"\x01" * 32, 101

        def list_unspent_by_address(self, addr, network):
            if addr != addr_a:
                return []
            return [{"txid": fund_txid[::-1].hex(), "vout": 0, "value": 50 * COIN,
                     "height": 101, "is_coinbase": False, "script_pubkey": spk_a.hex()}]

    w.db = _DB()
    raw = asyncio.run(w.send_transaction(addr_b, 1 * COIN, 2))
    tx = _tx(bytes.fromhex(raw))
    assert len(tx.outputs) == 2, "fixture must have a change output"
    w.scan_block_connect(SimpleNamespace(hash=b"\x02" * 32, timestamp=2, transactions=[tx]), 102)
    got = w.gettransaction_entry(tx.get_txid()[::-1].hex())
    details = sorted((d["category"], d["amount"]) for d in got["details"])
    assert details == [("receive", 1.0), ("send", -1.0)]
