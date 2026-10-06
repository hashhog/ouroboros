"""Regtest chain builder over the REAL compiled ``sync`` extension (F0 tests).

Blocks are built by hand (legacy encoding, bare OP_TRUE outputs) and connected
through the production ``PyBlockchainDB.connect_block_from_bytes`` path, so the
coins the tests reason about are real CHAINSTATE_CF rows.  All 32-byte ids are
in internal byte order (what the PyO3 surface takes and returns).
"""

from __future__ import annotations

import hashlib
import struct

REGTEST_BITS = 0x207FFFFF
OP_TRUE = b"\x51"
OP_RETURN = b"\x6a"
COIN = 100_000_000
BASE_TIME = 1296688800
TIP_HEIGHT = 2
FUNDING = 50 * COIN


def dsha(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_tx(inputs, outputs, version: int = 1, locktime: int = 0) -> bytes:
    """``inputs``: [(prev_txid, vout, script_sig, sequence)], ``outputs``: [(value, spk)]."""
    blob = struct.pack("<I", version) + varint(len(inputs))
    for prev_txid, vout, script_sig, sequence in inputs:
        blob += prev_txid + struct.pack("<I", vout) + varint(len(script_sig)) + script_sig
        blob += struct.pack("<I", sequence)
    blob += varint(len(outputs))
    for value, spk in outputs:
        blob += struct.pack("<Q", value) + varint(len(spk)) + spk
    return blob + struct.pack("<I", locktime)


def spend(prev_txid: bytes, vout: int, outputs) -> bytes:
    return ser_tx([(prev_txid, vout, b"", 0xFFFFFFFF)], outputs)


def merkle_root(txids):
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [dsha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def coinbase_tx(height: int, value: int = 50 * COIN, tag: bytes = b"\x01\x00") -> bytes:
    # BIP34 height push exactly as Core's CScript() << nHeight: OP_1..OP_16
    # for 1..16, else a minimal little-endian push.
    if 1 <= height <= 16:
        h_push = bytes([0x50 + height])
    else:
        h_bytes = height.to_bytes((height.bit_length() + 8) // 8, "little")
        h_push = bytes([len(h_bytes)]) + h_bytes
    script_sig = h_push + tag
    return ser_tx([(b"\x00" * 32, 0xFFFFFFFF, script_sig, 0xFFFFFFFF)], [(value, OP_TRUE)])


def build_block(prev_hash: bytes, timestamp: int, txs):
    root = merkle_root([dsha(tx) for tx in txs])
    for nonce in range(4_000_000):
        header = (struct.pack("<i", 0x20000000) + prev_hash + root
                  + struct.pack("<III", timestamp, REGTEST_BITS, nonce))
        h = dsha(header)
        if h[31] < 0x7F:
            return header + varint(len(txs)) + b"".join(txs), h
    raise RuntimeError("could not solve regtest header")  # pragma: no cover


def regtest_genesis_bytes() -> bytes:
    merkle = bytes.fromhex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")[::-1]
    cb = bytes.fromhex(
        "01000000" "01" + "00" * 32 + "ffffffff" "4d"
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
        "39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
        "ffffffff" "01" "00f2052a01000000" "43"
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
        "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        "00000000")
    header = (struct.pack("<i", 1) + b"\x00" * 32 + merkle
              + struct.pack("<III", 1296688602, REGTEST_BITS, 2))
    return header + b"\x01" + cb


class Chain:
    """genesis + coinbase-only blocks 1..``tip`` on a fresh real DB, plus
    ``n_fund`` mature non-coinbase OP_TRUE coins (``fund[i]``, vout 0,
    ``FUNDING`` sats, height 1) written straight into CHAINSTATE_CF with
    ``add_utxo_raw`` — a short chain keeps the fsync count (one per connect)
    low; nothing under test depends on how the funding coins got there."""

    def __init__(self, db, tip: int = TIP_HEIGHT, n_fund: int = 4):
        self.db = db
        self.db.connect_block_from_bytes(regtest_genesis_bytes(), 0)
        self.tip_hash, h = self.db.get_best_block()
        assert h == 0
        for height in range(1, tip + 1):
            cb = coinbase_tx(height, tag=b"\x02F" + height.to_bytes(2, "little"))
            raw, bh = build_block(self.tip_hash, BASE_TIME + height * 600, [cb])
            self.db.connect_block_from_bytes(raw, height, "regtest")
            self.tip_hash = bh
        self.tip_height = tip
        assert self.db.get_best_block() == (self.tip_hash, tip)
        self.fund = [dsha(b"f0-funding" + bytes([i])) for i in range(n_fund)]
        for txid in self.fund:
            self.db.add_utxo_raw(txid, 0, FUNDING, OP_TRUE, 1, False)
            assert self.db.get_utxo(txid, 0) is not None

    def next_block(self, txs, tag: bytes = b"\x02N", prev: bytes | None = None,
                   height: int | None = None):
        """Block on top of the tip (or ``prev``/``height``): [coinbase] + ``txs``."""
        height = self.tip_height + 1 if height is None else height
        prev = self.tip_hash if prev is None else prev
        cb = coinbase_tx(height, tag=tag)
        return build_block(prev, BASE_TIME + height * 600 + 1, [cb] + list(txs))
