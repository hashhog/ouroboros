"""getdata reply serialization per inv type (BIP144 / BIP339, Core parity).

Bitcoin Core net_processing.cpp ProcessGetData:

    // WTX and WITNESS_TX imply we serialize with witness
    const auto maybe_with_witness = (inv.IsMsgTx() ? TX_NO_WITNESS : TX_WITH_WITNESS);

and for blocks ``IsMsgBlk() -> TX_NO_WITNESS``, ``IsMsgWitnessBlk() ->
TX_WITH_WITNESS``.

Regression: ouroboros answered EVERY tx getdata with
``transaction.serialize()`` (witness-stripped), including MSG_WTX(5) and
MSG_WITNESS_TX.  A Core peer that fetched a segwit tx from us by wtxid got the
stripped form and rejected it ("mempool-script-verify-flag-failed (Witness
program hash mismatch)"), so segwit txs submitted to ouroboros never
propagated.  Reproduced on regtest against bitcoind before the fix.

The handler tests drive the REAL getdata closure built by
``Node._register_handlers`` (not a re-implementation of it), so they pin the
code the node actually runs.
"""
from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

from ouroboros.database import Block, Transaction, TxIn, TxOut
from ouroboros.p2p_messages import (
    INV_TYPE_BLOCK,
    INV_TYPE_TX,
    MSG_WITNESS_BLOCK,
    MSG_WITNESS_TX,
    MSG_WTX,
    GetDataMessage,
    TxMessage,
)


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _segwit_tx() -> Transaction:
    """A P2WPKH-shaped spend: empty scriptSig, 2-item witness."""
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=bytes(range(32)),
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFD,
                witness=[b"\x30" * 71, b"\x02" + b"\x11" * 32],
            )
        ],
        outputs=[TxOut(value=4_999_900_000, script_pubkey=b"\x00\x14" + b"\x22" * 20)],
        has_witness=True,
    )
    tx.txid = _dsha(tx.serialize())
    return tx


def _legacy_tx() -> Transaction:
    tx = Transaction(
        txid=b"",
        version=1,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"\x51", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
        has_witness=False,
    )
    tx.txid = _dsha(tx.serialize())
    return tx


def _block_with(txs: list[Transaction]) -> Block:
    return Block(
        version=0x20000000,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1_700_000_000,
        bits=0x207FFFFF,
        nonce=0,
        transactions=txs,
        hash=b"\xab" * 32,
    )


# ---------------------------------------------------------------------------
# TxMessage.for_inv — the serialization choice itself
# ---------------------------------------------------------------------------


def test_segwit_tx_serializations_differ():
    """Sanity: the fixture really has a witness to strip (else every test
    below would pass vacuously)."""
    tx = _segwit_tx()
    assert tx.serialize_with_witness() != tx.serialize()
    assert tx.get_wtxid() != tx.get_txid()


@pytest.mark.parametrize(
    "inv_type,with_witness",
    [(INV_TYPE_TX, False), (MSG_WITNESS_TX, True), (MSG_WTX, True)],
)
def test_tx_message_for_inv(inv_type, with_witness):
    tx = _segwit_tx()
    payload = TxMessage.for_inv(tx, inv_type).to_network_message("regtest").payload
    expected = tx.serialize_with_witness() if with_witness else tx.serialize()
    assert payload == expected


# ---------------------------------------------------------------------------
# The real getdata handler (node._register_handlers closure)
# ---------------------------------------------------------------------------


class _FakePeer:
    def __init__(self):
        self.host, self.port, self.network = "127.0.0.1", 18444, "regtest"
        self.handlers = {}
        self.sent = []

    def register_handler(self, command, fn):
        self.handlers[command] = fn

    async def send_message(self, msg):
        self.sent.append(msg)


class _FakeMempool:
    def __init__(self, txs):
        self.by_txid = {t.get_txid(): t for t in txs}
        self.by_wtxid = {t.get_wtxid(): t for t in txs}

    def __len__(self):
        return len(self.by_txid)

    def get_transaction(self, txid):
        return self.by_txid.get(txid)

    def get_transaction_by_wtxid(self, wtxid):
        return self.by_wtxid.get(wtxid)


class _FakeDB:
    def __init__(self, block):
        self.block = block

    def get_block(self, h):
        return self.block if h == self.block.hash else None

    def get_block_bytes(self, h):
        # Real DB returns the stored raw consensus bytes (witness-preserving).
        return self.block.serialize_with_witness() if h == self.block.hash else None

    def get_best_block(self):
        return (self.block.hash, 200)


def _getdata_handler(mempool_txs, block):
    from ouroboros.node import BitcoinNode

    peer = _FakePeer()
    fake = SimpleNamespace(
        peer_manager=SimpleNamespace(
            get_all_ready_peers=lambda: [peer],
            set_inbound_peer_handler=lambda fn: None,
        ),
        block_filter_index=None,
        mempool=_FakeMempool(mempool_txs),
        db=_FakeDB(block),
        pruner=None,
    )
    BitcoinNode._register_handlers(fake)
    return peer, peer.handlers["getdata"]


def _request(inv_type, h, mempool_txs, block):
    peer, handler = _getdata_handler(mempool_txs, block)
    msg = GetDataMessage(inventory=[(inv_type, h)]).to_network_message("regtest")
    asyncio.run(handler(msg))
    assert len(peer.sent) == 1, [m.command for m in peer.sent]
    return peer.sent[0]


@pytest.mark.parametrize(
    "inv_type,key,with_witness",
    [
        (INV_TYPE_TX, "txid", False),        # legacy MSG_TX -> TX_NO_WITNESS
        (MSG_WITNESS_TX, "txid", True),      # MSG_WITNESS_TX -> TX_WITH_WITNESS
        (MSG_WTX, "wtxid", True),            # BIP339 MSG_WTX -> TX_WITH_WITNESS
    ],
)
def test_getdata_tx_reply_serialization(inv_type, key, with_witness):
    tx = _segwit_tx()
    h = tx.get_txid() if key == "txid" else tx.get_wtxid()
    out = _request(inv_type, h, [tx], _block_with([_legacy_tx()]))
    assert out.command == "tx"
    expected = tx.serialize_with_witness() if with_witness else tx.serialize()
    assert out.payload == expected, (
        f"inv type {inv_type:#x}: expected "
        f"{'witness' if with_witness else 'stripped'} serialization"
    )


@pytest.mark.parametrize("inv_type", [INV_TYPE_TX, MSG_WITNESS_TX])
def test_getdata_legacy_tx_identical_either_way(inv_type):
    tx = _legacy_tx()
    out = _request(inv_type, tx.get_txid(), [tx], _block_with([tx]))
    assert out.payload == tx.serialize()


@pytest.mark.parametrize(
    "inv_type,with_witness",
    [(INV_TYPE_BLOCK, False), (MSG_WITNESS_BLOCK, True)],
)
def test_getdata_block_reply_serialization(inv_type, with_witness):
    block = _block_with([_segwit_tx()])
    assert block.serialize() != block.serialize_with_witness()
    out = _request(inv_type, block.hash, [], block)
    assert out.command == "block"
    expected = block.serialize_with_witness() if with_witness else block.serialize()
    assert bytes(out.payload) == expected
