"""
BIP 152 Compact Block Relay.

Compact blocks allow a node to reconstruct a full block from a compact
representation (header + short transaction IDs) by matching short IDs
against its mempool, drastically reducing bandwidth at the chain tip.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
           bitcoin/src/blockencodings.cpp
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from ouroboros.p2p_messages import encode_varint, decode_varint

if TYPE_CHECKING:
    from ouroboros.database import Block, Transaction
    from ouroboros.mempool import Mempool


def _siphash_2_4(key: bytes, data: bytes) -> int:
    """
    SipHash-2-4 keyed hash (returns 64-bit integer).

    Pure-Python implementation following the reference C code.
    key: 16 bytes (k0 || k1, little-endian u64s).
    data: arbitrary bytes.
    """
    assert len(key) == 16
    k0 = int.from_bytes(key[0:8], "little")
    k1 = int.from_bytes(key[8:16], "little")

    MASK64 = 0xFFFFFFFFFFFFFFFF

    def rotl(x, b):
        return ((x << b) | (x >> (64 - b))) & MASK64

    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    length = len(data)
    blocks = length // 8

    for i in range(blocks):
        m = int.from_bytes(data[i * 8:(i + 1) * 8], "little")
        v3 ^= m
        for _ in range(2):
            v0 = (v0 + v1) & MASK64; v1 = rotl(v1, 13); v1 ^= v0
            v0 = rotl(v0, 32)
            v2 = (v2 + v3) & MASK64; v3 = rotl(v3, 16); v3 ^= v2
            v0 = (v0 + v3) & MASK64; v3 = rotl(v3, 21); v3 ^= v0
            v2 = (v2 + v1) & MASK64; v1 = rotl(v1, 17); v1 ^= v2
            v2 = rotl(v2, 32)
        v0 ^= m

    tail = data[blocks * 8:]
    m = (length & 0xFF) << 56
    for j in range(len(tail)):
        m |= tail[j] << (j * 8)

    v3 ^= m
    for _ in range(2):
        v0 = (v0 + v1) & MASK64; v1 = rotl(v1, 13); v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & MASK64; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK64; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & MASK64; v1 = rotl(v1, 17); v1 ^= v2
        v2 = rotl(v2, 32)
    v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0 = (v0 + v1) & MASK64; v1 = rotl(v1, 13); v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & MASK64; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK64; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & MASK64; v1 = rotl(v1, 17); v1 ^= v2
        v2 = rotl(v2, 32)

    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def compute_siphash_key(header: bytes, nonce: int) -> bytes:
    """
    Derive the 16-byte SipHash key from a block header and nonce.

    key = SHA256(header(80 bytes) || nonce(8 bytes LE))[0:16]
    """
    h = hashlib.sha256(header + struct.pack("<Q", nonce)).digest()
    return h[:16]


def short_txid(siphash_key: bytes, txid: bytes) -> int:
    """
    Compute a 6-byte (48-bit) short transaction ID.

    short_id = SipHash-2-4(key, txid) & 0xFFFFFFFFFFFF
    """
    return _siphash_2_4(siphash_key, txid) & 0xFFFFFFFFFFFF


@dataclass
class PrefilledTransaction:
    """A transaction pre-filled in the compact block (index + full tx)."""
    index: int
    tx: 'Transaction'


@dataclass
class CompactBlock:
    """
    BIP 152 compact block representation.

    A compact block contains:
    - The 80-byte block header
    - A 64-bit nonce for SipHash key derivation
    - A list of 6-byte short transaction IDs
    - Pre-filled transactions (at minimum the coinbase)
    """
    header: bytes
    nonce: int
    short_ids: List[int]
    prefilled_txs: List[PrefilledTransaction]

    @property
    def block_hash(self) -> bytes:
        """Double-SHA256 of the 80-byte header."""
        return hashlib.sha256(hashlib.sha256(self.header).digest()).digest()

    def siphash_key(self) -> bytes:
        return compute_siphash_key(self.header, self.nonce)

    def reconstruct(
        self, mempool: 'Mempool'
    ) -> Tuple[Optional[List['Transaction']], List[int]]:
        """
        Attempt to reconstruct the full transaction list from the mempool.

        Returns:
            (txs, missing_indices)
            - If all transactions are found, txs is the ordered list and
              missing_indices is empty.
            - Otherwise, txs is None and missing_indices lists the
              compact-block indices that could not be resolved (the caller
              should send ``getblocktxn``).
        """
        key = self.siphash_key()

        total_tx_count = len(self.short_ids) + len(self.prefilled_txs)
        txs: List[Optional['Transaction']] = [None] * total_tx_count

        # Place pre-filled transactions
        offset = 0
        for pf in self.prefilled_txs:
            abs_idx = pf.index + offset
            if abs_idx >= total_tx_count:
                return None, list(range(total_tx_count))
            txs[abs_idx] = pf.tx
            offset = abs_idx + 1

        # Build short_id → mempool tx lookup
        mempool_by_short: Dict[int, 'Transaction'] = {}
        for entry in mempool.transactions.values():
            tx = entry.tx
            wtxid = tx.get_wtxid()
            sid = short_txid(key, wtxid)
            mempool_by_short[sid] = tx

        # Fill remaining slots from mempool
        sid_iter = iter(self.short_ids)
        missing: List[int] = []
        for i in range(total_tx_count):
            if txs[i] is not None:
                continue
            sid = next(sid_iter)
            matched = mempool_by_short.get(sid)
            if matched is not None:
                txs[i] = matched
            else:
                missing.append(i)

        if missing:
            return None, missing
        return txs, []  # type: ignore[return-value]

    # ── Wire-format serialization / deserialization ─────────────────

    def serialize(self) -> bytes:
        """Serialize to BIP 152 ``cmpctblock`` payload."""
        data = bytearray()
        data.extend(self.header)
        data.extend(struct.pack("<Q", self.nonce))

        data.extend(encode_varint(len(self.short_ids)))
        for sid in self.short_ids:
            data.extend(struct.pack("<Q", sid)[:6])

        data.extend(encode_varint(len(self.prefilled_txs)))
        last_idx = -1
        for pf in self.prefilled_txs:
            diff = pf.index - (last_idx + 1)
            data.extend(encode_varint(diff))
            data.extend(pf.tx.serialize_with_witness())
            last_idx = pf.index

        return bytes(data)

    @classmethod
    def deserialize(cls, payload: bytes) -> 'CompactBlock':
        """Deserialize from ``cmpctblock`` payload."""
        from ouroboros.p2p_messages import TxMessage

        if len(payload) < 88:
            raise ValueError("cmpctblock payload too short")

        header = payload[:80]
        nonce = struct.unpack("<Q", payload[80:88])[0]
        off = 88

        sid_count, consumed = decode_varint(payload, off); off += consumed
        short_ids = []
        for _ in range(sid_count):
            if off + 6 > len(payload):
                raise ValueError("cmpctblock: short_id truncated")
            raw = payload[off:off + 6] + b'\x00\x00'
            short_ids.append(struct.unpack("<Q", raw)[0])
            off += 6

        pf_count, consumed = decode_varint(payload, off); off += consumed
        prefilled: List[PrefilledTransaction] = []
        last_idx = -1
        for _ in range(pf_count):
            diff, consumed = decode_varint(payload, off); off += consumed
            abs_idx = last_idx + 1 + diff

            tx_msg = TxMessage.from_payload(payload[off:])
            tx = tx_msg.transaction
            tx_len = len(tx.serialize_with_witness())
            off += tx_len

            prefilled.append(PrefilledTransaction(index=abs_idx, tx=tx))
            last_idx = abs_idx

        return cls(
            header=header, nonce=nonce,
            short_ids=short_ids, prefilled_txs=prefilled,
        )

    @classmethod
    def from_block(
        cls, block: 'Block', nonce: int, *, prefill_coinbase: bool = True
    ) -> 'CompactBlock':
        """
        Build a CompactBlock from a full block.

        Used when *we* relay a compact block to a peer.
        """
        header = block.serialize()[:80]
        key = compute_siphash_key(header, nonce)

        prefilled: List[PrefilledTransaction] = []
        sids: List[int] = []

        for i, tx in enumerate(block.transactions):
            if prefill_coinbase and i == 0:
                prefilled.append(PrefilledTransaction(index=0, tx=tx))
            else:
                wtxid = tx.get_wtxid()
                sids.append(short_txid(key, wtxid))

        return cls(
            header=header, nonce=nonce,
            short_ids=sids, prefilled_txs=prefilled,
        )


@dataclass
class BlockTransactionsRequest:
    """``getblocktxn`` — request missing transactions from a compact block."""
    block_hash: bytes
    indices: List[int]

    def serialize(self) -> bytes:
        data = bytearray(self.block_hash)
        data.extend(encode_varint(len(self.indices)))
        last = -1
        for idx in self.indices:
            diff = idx - (last + 1)
            data.extend(encode_varint(diff))
            last = idx
        return bytes(data)

    @classmethod
    def deserialize(cls, payload: bytes) -> 'BlockTransactionsRequest':
        if len(payload) < 33:
            raise ValueError("getblocktxn payload too short")
        block_hash = payload[:32]
        off = 32
        count, consumed = decode_varint(payload, off); off += consumed
        indices: List[int] = []
        last = -1
        for _ in range(count):
            diff, consumed = decode_varint(payload, off); off += consumed
            abs_idx = last + 1 + diff
            indices.append(abs_idx)
            last = abs_idx
        return cls(block_hash=block_hash, indices=indices)


@dataclass
class BlockTransactions:
    """``blocktxn`` — response with the requested missing transactions."""
    block_hash: bytes
    transactions: List['Transaction']

    def serialize(self) -> bytes:
        data = bytearray(self.block_hash)
        data.extend(encode_varint(len(self.transactions)))
        for tx in self.transactions:
            data.extend(tx.serialize_with_witness())
        return bytes(data)

    @classmethod
    def deserialize(cls, payload: bytes) -> 'BlockTransactions':
        from ouroboros.p2p_messages import TxMessage
        if len(payload) < 33:
            raise ValueError("blocktxn payload too short")
        block_hash = payload[:32]
        off = 32
        count, consumed = decode_varint(payload, off); off += consumed
        txs = []
        for _ in range(count):
            tx_msg = TxMessage.from_payload(payload[off:])
            tx = tx_msg.transaction
            tx_len = len(tx.serialize_with_witness())
            off += tx_len
            txs.append(tx)
        return cls(block_hash=block_hash, transactions=txs)
