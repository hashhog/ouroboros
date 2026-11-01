"""sec-ouroboros-cmpct-parse-stall (security audit C1, 2026-10-30).

``CompactBlock.deserialize`` and ``BlockTransactions.deserialize`` parsed each
transaction with ``TxMessage.from_payload(payload[off:])``: a copy of the whole
remaining payload per transaction, so a 4 MB message holding ~65,000 minimal
transactions copied ~127 GB.  Both ran synchronously on the asyncio loop, and
``on_blocktxn`` parsed the full body before looking up whether any compact
block with that hash was pending.  Measured on regtest: one 4 MB cmpctblock
stalled RPC for 4.2 s, one unsolicited blocktxn for 3.1 s.

Core parses both with its linear stream deserializer
(``blockencodings.h`` SERIALIZE_METHODS), and an unsolicited blocktxn is a
lookup miss in ``mapBlocksInFlight`` (``ProcessCompactBlockTxns``).

These tests pin:
  * the parse copies O(payload) bytes, not O(payload * tx_count);
  * an over-count cmpctblock is refused before any short id is read;
  * ``on_blocktxn`` for an unknown block hash never parses the body;
  * both handlers run their deserializer off the event-loop thread;
  * the round trip (segwit and non-segwit prefilled txs) is unchanged.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.compact_blocks import (
    BlockTransactions,
    CompactBlock,
    PrefilledTransaction,
    compute_siphash_key,
    short_txid,
)
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import BlockTxnMessage, CmpctBlockMessage, encode_varint


class _CopyCountingBytes(bytes):
    """``bytes`` that tallies how many bytes its slices copy."""

    copied = 0

    def __getitem__(self, key):
        out = super().__getitem__(key)
        if isinstance(key, slice):
            type(self).copied += len(out)
        return out


def _counting(payload: bytes) -> _CopyCountingBytes:
    _CopyCountingBytes.copied = 0
    return _CopyCountingBytes(payload)


def _header(tag: int) -> bytes:
    h = bytearray(80)
    struct.pack_into("<I", h, 72, 0x207FFFFF)
    struct.pack_into("<I", h, 76, tag)
    return bytes(h)


def _minimal_tx_bytes(i: int) -> bytes:
    """A 60-byte legacy tx: 1 input with empty scriptSig, 1 output, empty
    scriptPubKey.  Distinct per ``i`` through the prevout txid."""
    return (
        struct.pack("<I", 1)
        + b"\x01" + struct.pack("<32sI", i.to_bytes(32, "little"), 0) + b"\x00"
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x01" + struct.pack("<q", 0) + b"\x00"
        + struct.pack("<I", 0)
    )


def _flood_cmpctblock(n_prefilled: int) -> bytes:
    """The audit's attack shape: no short ids, ``n_prefilled`` minimal
    prefilled txs at consecutive indices (diff varint 0 each)."""
    body = bytearray(_header(1))
    body += struct.pack("<Q", 7)
    body += encode_varint(0)
    body += encode_varint(n_prefilled)
    for i in range(n_prefilled):
        body += b"\x00"
        body += _minimal_tx_bytes(i)
    return bytes(body)


def _flood_blocktxn(n_txs: int, block_hash: bytes = b"\xab" * 32) -> bytes:
    body = bytearray(block_hash)
    body += encode_varint(n_txs)
    for i in range(n_txs):
        body += _minimal_tx_bytes(i)
    return bytes(body)


# ---------------------------------------------------------------------------
# Linear parse
# ---------------------------------------------------------------------------


def test_cmpctblock_65000_prefilled_parse_copies_linear_bytes():
    payload = _flood_cmpctblock(65_000)
    assert len(payload) > 3_900_000
    p = _counting(payload)
    cb = CompactBlock.deserialize(p)
    assert len(cb.prefilled_txs) == 65_000
    assert cb.prefilled_txs[-1].index == 64_999
    # Quadratic tail copies would be ~len*n/2 ~ 1.3e11 bytes.  A linear parse
    # copies each field once: well under 2x the payload.
    assert _CopyCountingBytes.copied < 2 * len(payload), _CopyCountingBytes.copied


def test_blocktxn_64000_txs_parse_copies_linear_bytes():
    payload = _flood_blocktxn(64_000)
    assert len(payload) > 3_800_000
    p = _counting(payload)
    bt = BlockTransactions.deserialize(p)
    assert len(bt.transactions) == 64_000
    assert bt.block_hash == b"\xab" * 32
    assert _CopyCountingBytes.copied < 2 * len(payload), _CopyCountingBytes.copied


def test_cmpctblock_overcount_refused_before_reading_short_ids():
    """sid_count alone above the uint16 ceiling is refused before the short
    id loop runs (Core: "indexes overflowed 16 bits" during deserialize)."""
    payload = _header(2) + struct.pack("<Q", 0) + encode_varint(0x10000) + b"\x00" * 600_000
    p = _counting(payload)
    with pytest.raises(ValueError, match="overflows uint16_t"):
        CompactBlock.deserialize(p)
    # Only the header/nonce/varint were touched, not 65,536 short-id slices.
    assert _CopyCountingBytes.copied < 200, _CopyCountingBytes.copied


def test_cmpctblock_truncated_prefilled_tx_still_raises():
    payload = _flood_cmpctblock(3)[:-5]
    with pytest.raises(ValueError):
        CompactBlock.deserialize(payload)


def test_blocktxn_truncated_tx_still_raises():
    payload = _flood_blocktxn(3)[:-5]
    with pytest.raises(ValueError):
        BlockTransactions.deserialize(payload)


def _segwit_tx(tag: int) -> Transaction:
    tx = Transaction(
        txid=bytes(32), version=2, locktime=tag,
        inputs=[TxIn(prev_txid=hashlib.sha256(bytes([tag])).digest(), prev_vout=1,
                     script_sig=b"", sequence=0xFFFFFFFD,
                     witness=[b"\x30" * 71, b"\x02" * 33])],
        outputs=[TxOut(value=12345 + tag, script_pubkey=b"\x00\x14" + bytes(20))],
        has_witness=True,
    )
    raw = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return tx


def _legacy_tx(tag: int) -> Transaction:
    tx = Transaction(
        txid=bytes(32), version=1, locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x03" + bytes([tag, 0, 0]), sequence=0xFFFFFFFF,
                     witness=None)],
        outputs=[TxOut(value=50 * 10**8, script_pubkey=b"\x51")],
        has_witness=False,
    )
    raw = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return tx


def test_round_trip_mixed_segwit_prefilled_and_blocktxn_unchanged():
    header = _header(3)
    key = compute_siphash_key(header, 99)
    txs = [_legacy_tx(1), _segwit_tx(2), _segwit_tx(3), _legacy_tx(4), _segwit_tx(5)]
    cb = CompactBlock(
        header=header, nonce=99,
        short_ids=[short_txid(key, txs[1].get_wtxid()), short_txid(key, txs[3].get_wtxid())],
        prefilled_txs=[PrefilledTransaction(0, txs[0]), PrefilledTransaction(2, txs[2]),
                       PrefilledTransaction(4, txs[4])],
    )
    wire = cb.serialize()
    back = CompactBlock.deserialize(wire)
    assert back.serialize() == wire
    assert [pf.index for pf in back.prefilled_txs] == [0, 2, 4]
    assert [pf.tx.txid for pf in back.prefilled_txs] == [txs[0].txid, txs[2].txid, txs[4].txid]
    assert [pf.tx.get_wtxid() for pf in back.prefilled_txs] == [
        txs[0].get_wtxid(), txs[2].get_wtxid(), txs[4].get_wtxid()]

    bt = BlockTransactions(block_hash=b"\x11" * 32, transactions=txs)
    wire = bt.serialize()
    back_bt = BlockTransactions.deserialize(wire)
    assert back_bt.serialize() == wire
    assert [t.get_wtxid() for t in back_bt.transactions] == [t.get_wtxid() for t in txs]


# ---------------------------------------------------------------------------
# Handlers: no parse for an unknown blocktxn, parse off the loop
# ---------------------------------------------------------------------------


def _peer() -> MagicMock:
    peer = MagicMock()
    peer.host = "10.9.9.9"
    peer.port = 8333
    peer.services = 0x09  # NODE_NETWORK | NODE_WITNESS
    peer.message_handlers = {}
    peer.register_handler = lambda cmd, fn: peer.message_handlers.__setitem__(cmd, fn)
    peer.send_message = AsyncMock()
    peer.is_connected.return_value = True
    return peer


def _wired():
    pm = PeerManager(network="regtest", listen=False, dns_seed=False)
    peer = _peer()
    pm._register_compact_handlers(peer, "10.9.9.9:8333")
    return pm, peer


@pytest.mark.asyncio
async def test_on_blocktxn_unknown_hash_never_deserializes(monkeypatch):
    pm, peer = _wired()
    calls = []
    real = BlockTransactions.deserialize.__func__

    def spy(cls, payload):
        calls.append(len(payload))
        return real(cls, payload)

    monkeypatch.setattr(BlockTransactions, "deserialize", classmethod(spy))
    msg = BlockTxnMessage(payload_bytes=_flood_blocktxn(2_000)).to_network_message(pm.network)
    await peer.message_handlers["blocktxn"](msg)
    assert calls == []
    assert pm._partial_cmpct_blocks == {}
    peer.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_blocktxn_short_payload_ignored_without_parse(monkeypatch):
    pm, peer = _wired()
    calls = []
    monkeypatch.setattr(BlockTransactions, "deserialize",
                        classmethod(lambda cls, p: calls.append(p)))
    msg = BlockTxnMessage(payload_bytes=b"\x00" * 10).to_network_message(pm.network)
    await peer.message_handlers["blocktxn"](msg)
    assert calls == []


def _pending_cmpct():
    header = _header(4)
    key = compute_siphash_key(header, 5)
    coinbase, missing = _legacy_tx(9), _segwit_tx(10)
    cb = CompactBlock(header=header, nonce=5,
                      short_ids=[short_txid(key, missing.get_wtxid())],
                      prefilled_txs=[PrefilledTransaction(0, coinbase)])
    return cb, coinbase, missing


@pytest.mark.asyncio
async def test_both_deserializers_run_off_the_event_loop_thread(monkeypatch):
    pm, peer = _wired()
    loop_thread = threading.get_ident()
    seen = {}
    real_cb = CompactBlock.deserialize.__func__
    real_bt = BlockTransactions.deserialize.__func__

    def spy_cb(cls, payload):
        seen["cmpctblock"] = threading.get_ident()
        return real_cb(cls, payload)

    def spy_bt(cls, payload):
        seen["blocktxn"] = threading.get_ident()
        return real_bt(cls, payload)

    monkeypatch.setattr(CompactBlock, "deserialize", classmethod(spy_cb))
    monkeypatch.setattr(BlockTransactions, "deserialize", classmethod(spy_bt))

    delivered = []
    pm._on_compact_block = lambda h, hdr, txs: delivered.append((h, txs))

    cb, coinbase, missing = _pending_cmpct()
    await peer.message_handlers["cmpctblock"](
        CmpctBlockMessage(payload_bytes=cb.serialize()).to_network_message(pm.network))
    assert cb.block_hash in pm._partial_cmpct_blocks

    bt = BlockTransactions(block_hash=cb.block_hash, transactions=[missing])
    await peer.message_handlers["blocktxn"](
        BlockTxnMessage(payload_bytes=bt.serialize()).to_network_message(pm.network))

    assert seen["cmpctblock"] != loop_thread
    assert seen["blocktxn"] != loop_thread
    # Happy path unchanged: the block is assembled and handed on.
    assert len(delivered) == 1
    h, txs = delivered[0]
    assert h == cb.block_hash
    assert [t.get_wtxid() for t in txs] == [coinbase.get_wtxid(), missing.get_wtxid()]
    assert pm._partial_cmpct_blocks == {}
