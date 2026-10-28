"""Serving side of BIP 152: cmpctblock on getdata(MSG_CMPCT_BLOCK), blocktxn on
getblocktxn.  Core: net_processing.cpp ProcessGetBlockData / SendBlockTransactions,
blockencodings.cpp CBlockHeaderAndShortTxIDs.

The block is built as raw witness bytes with one segwit spend, because the
stored-block round trip drops witnesses and a short ID must hash the WTXID.
"""
import hashlib
import struct

from ouroboros.compact_blocks import (
    BlockTransactions,
    CompactBlock,
    MAX_BLOCKTXN_DEPTH,
    MAX_CMPCTBLOCK_DEPTH,
    compute_siphash_key,
    short_txid,
)


def _dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _vi(n):
    return bytes([n])


def _coinbase():
    return (struct.pack("<I", 2) + _vi(1) + bytes(32) + b"\xff\xff\xff\xff"
            + _vi(2) + b"\x01\x01" + b"\xff\xff\xff\xff" + _vi(1)
            + struct.pack("<q", 50 * 10**8) + _vi(1) + b"\x51" + bytes(4))


def _segwit_tx():
    return (struct.pack("<I", 2) + b"\x00\x01" + _vi(1) + b"\x11" * 32
            + struct.pack("<I", 0) + _vi(0) + b"\xff\xff\xff\xff" + _vi(1)
            + struct.pack("<q", 1000) + _vi(1) + b"\x51"
            + _vi(2) + _vi(3) + b"abc" + _vi(2) + b"de" + bytes(4))


def _raw_block():
    hdr = struct.pack("<i", 0x20000000) + bytes(32) + bytes(32) \
        + struct.pack("<III", 1700000000, 0x207fffff, 7)
    return hdr + _vi(2) + _coinbase() + _segwit_tx()


def test_cmpctblock_prefills_coinbase_and_uses_wtxid_short_ids():
    from ouroboros.compact_blocks import build_cmpctblock_payload
    raw = _raw_block()
    cb = CompactBlock.deserialize(build_cmpctblock_payload(raw, nonce=12345))
    assert cb.header == raw[:80] and cb.nonce == 12345
    assert [p.index for p in cb.prefilled_txs] == [0]
    assert len(cb.short_ids) == 1
    # wtxid = dsha(full witness serialization); the stripped txid would differ
    key = compute_siphash_key(raw[:80], 12345)
    assert cb.short_ids[0] == short_txid(key, _dsha(_segwit_tx()))


def test_cmpctblock_nonce_is_random_by_default():
    from ouroboros.compact_blocks import build_cmpctblock_payload
    raw = _raw_block()
    a = CompactBlock.deserialize(build_cmpctblock_payload(raw)).nonce
    b = CompactBlock.deserialize(build_cmpctblock_payload(raw)).nonce
    assert a != b


def test_blocktxn_keeps_witness_and_rejects_out_of_range():
    from ouroboros.compact_blocks import build_blocktxn_payload
    raw = _raw_block()
    h = _dsha(raw[:80])
    bt = BlockTransactions.deserialize(build_blocktxn_payload(raw, h, [1]))
    assert bt.block_hash == h and len(bt.transactions) == 1
    assert bt.transactions[0].serialize_with_witness() == _segwit_tx()
    assert build_blocktxn_payload(raw, h, [2]) is None


def test_depth_constants_match_core():
    assert (MAX_CMPCTBLOCK_DEPTH, MAX_BLOCKTXN_DEPTH) == (5, 10)
