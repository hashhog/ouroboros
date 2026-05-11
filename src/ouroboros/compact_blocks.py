"""
BIP 152 Compact Block Relay.

Compact blocks allow a node to reconstruct a full block from a compact
representation (header + short transaction IDs) by matching short IDs
against its mempool, drastically reducing bandwidth at the chain tip.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
           bitcoin/src/blockencodings.cpp
           bitcoin/src/net_processing.cpp
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from ouroboros.p2p_messages import decode_varint, encode_varint

if TYPE_CHECKING:
    from ouroboros.database import Block, Transaction
    from ouroboros.mempool import Mempool

# Bitcoin Core net_processing.cpp: static constexpr uint64_t CMPCTBLOCKS_VERSION{2};
CMPCTBLOCKS_VERSION: int = 2

# Bitcoin Core net_processing.cpp: MAX_CMPCTBLOCK_DEPTH = 5
# Compact block announcements deeper than this are treated as plain headers.
MAX_CMPCTBLOCK_DEPTH: int = 5

# Bitcoin Core net_processing.cpp: MAX_BLOCKTXN_DEPTH = 10
# Do not serve getblocktxn responses for blocks older than this depth.
MAX_BLOCKTXN_DEPTH: int = 10

# Bitcoin Core blockencodings.cpp (consensus/consensus.h):
#   MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 4_000_000 / 40
# Maximum number of transactions (short IDs + prefilled) in a valid cmpctblock.
MAX_CMPCTBLOCK_TX_COUNT: int = 100_000  # 4_000_000 // 40

# Bitcoin Core blockencodings.cpp: bucket-size limit used in InitData to
# detect pathologically skewed short-id distributions (DoS protection).
# P(max_bucket > 12) <= ~1e-6 per block transfer per peer.
MAX_SHORT_ID_BUCKET_SIZE: int = 12


class ReadStatus(IntEnum):
    """Mirror of Bitcoin Core's ReadStatus_t (blockencodings.h)."""
    OK = 0
    INVALID = 1   # bogus cmpctblock — disconnect or ban
    FAILED = 2    # reconstructed block mutation / short-ID collision


def _siphash_2_4(key: bytes, data: bytes) -> int:
    """SipHash-2-4 keyed hash (returns 64-bit integer)."""
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
            v0 = (v0 + v1) & MASK64
            v1 = rotl(v1, 13)
            v1 ^= v0
            v0 = rotl(v0, 32)
            v2 = (v2 + v3) & MASK64
            v3 = rotl(v3, 16)
            v3 ^= v2
            v0 = (v0 + v3) & MASK64
            v3 = rotl(v3, 21)
            v3 ^= v0
            v2 = (v2 + v1) & MASK64
            v1 = rotl(v1, 17)
            v1 ^= v2
            v2 = rotl(v2, 32)
        v0 ^= m

    tail = data[blocks * 8:]
    m = (length & 0xFF) << 56
    for j in range(len(tail)):
        m |= tail[j] << (j * 8)

    v3 ^= m
    for _ in range(2):
        v0 = (v0 + v1) & MASK64
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & MASK64
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & MASK64
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & MASK64
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)
    v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0 = (v0 + v1) & MASK64
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & MASK64
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & MASK64
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & MASK64
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)

    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def compute_siphash_key(header: bytes, nonce: int) -> bytes:
    """Derive the 16-byte SipHash key: SHA256(header || nonce_le64)[:16]."""
    h = hashlib.sha256(header + struct.pack("<Q", nonce)).digest()
    return h[:16]


def short_txid(siphash_key: bytes, txid: bytes) -> int:
    """Compute a 48-bit short tx ID via SipHash-2-4."""
    return _siphash_2_4(siphash_key, txid) & 0xFFFFFFFFFFFF


@dataclass
class PrefilledTransaction:
    """A transaction pre-filled in the compact block (index + full tx)."""
    index: int
    tx: Transaction


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
    short_ids: list[int]
    prefilled_txs: list[PrefilledTransaction]

    @property
    def block_hash(self) -> bytes:
        """Double-SHA256 of the 80-byte header."""
        return hashlib.sha256(hashlib.sha256(self.header).digest()).digest()

    def siphash_key(self) -> bytes:
        return compute_siphash_key(self.header, self.nonce)

    def validate(self) -> ReadStatus:
        """
        Validate the compact block structure before reconstruction.

        Mirrors Bitcoin Core's PartiallyDownloadedBlock::InitData checks
        (blockencodings.cpp lines 62-116).  In Core, PrefilledTransaction.index
        stores the *differential* wire value.  Here .index stores the *absolute*
        position (set by from_block() or deserialize()), so the gap checks are
        expressed in terms of absolute indices.

        Gates checked:
        1. header must not be null-zeroed AND at least one of (short_ids,
           prefilled_txs) must be non-empty.
        2. Total tx count must not exceed 100 000
           (MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT).
        3. Prefilled tx absolute index must not overflow uint16_t (65535).
        4. Prefilled tx absolute index must not jump beyond the available
           shorttxid + prefilled slots (gap check): index <= shorttxids + i.
        5. Short IDs must all be distinct (no duplicate short IDs).
        6. No SipHash bucket may contain more than 12 entries (DoS gate).
        """
        # Gate 1 — header null / both lists empty
        # Core's CBlockHeader::IsNull() checks nBits==0; an all-zero 80-byte
        # header has nBits at offset 72 which will be zero.
        null_header = (self.header == bytes(80))
        if null_header or (not self.short_ids and not self.prefilled_txs):
            return ReadStatus.INVALID

        # Gate 2 — total tx count limit (blockencodings.cpp line 64)
        total = len(self.short_ids) + len(self.prefilled_txs)
        if total > MAX_CMPCTBLOCK_TX_COUNT:
            return ReadStatus.INVALID

        # Gates 3 & 4 — prefilled index overflow and gap check
        # (blockencodings.cpp lines 73-86)
        # .index is absolute; check each in order.
        for i, pf in enumerate(self.prefilled_txs):
            if pf.index > 0xFFFF:  # uint16_t overflow
                return ReadStatus.INVALID
            # Absolute position must not exceed available slots
            # (shorttxids seen so far) + (prefilled seen so far).
            if pf.index > len(self.short_ids) + i:
                return ReadStatus.INVALID
            # Indices must be strictly increasing
            if i > 0 and pf.index <= self.prefilled_txs[i - 1].index:
                return ReadStatus.INVALID

        # Gates 5 & 6 — short ID uniqueness and bucket-size DoS protection
        # (blockencodings.cpp lines 94-116)
        # Core uses std::unordered_map with default load-factor 1.0 so the
        # bucket count equals the number of short IDs. Bucket index =
        # sid % bucket_count.  We replicate the same distribution.
        n_sids = len(self.short_ids)
        if n_sids > 0:
            sid_map: dict[int, int] = {}
            bucket_counts: dict[int, int] = {}
            for sid in self.short_ids:
                bucket = sid % n_sids
                bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
                if bucket_counts[bucket] > MAX_SHORT_ID_BUCKET_SIZE:
                    return ReadStatus.FAILED  # skewed distribution → DoS
                if sid in sid_map:
                    return ReadStatus.FAILED  # duplicate short ID
                sid_map[sid] = sid  # value irrelevant; presence check only

        return ReadStatus.OK

    def reconstruct(
        self, mempool: Mempool
    ) -> tuple[list[Transaction] | None, list[int]]:
        """Reconstruct the tx list from the mempool.

        Returns ``(txs, missing_indices)``.  If all short IDs matched,
        *missing_indices* is empty; otherwise *txs* is None and
        *missing_indices* lists slots the caller should fetch via ``getblocktxn``.

        Validates the compact block structure (mirroring InitData) before
        attempting reconstruction.  Returns (None, []) on protocol violations.
        """
        status = self.validate()
        if status != ReadStatus.OK:
            return None, []

        key = self.siphash_key()

        total_tx_count = len(self.short_ids) + len(self.prefilled_txs)
        txs: list[Transaction | None] = [None] * total_tx_count

        # Place pre-filled transactions at their absolute indices.
        # .index is the absolute position (set by from_block / deserialize).
        for pf in self.prefilled_txs:
            txs[pf.index] = pf.tx

        # Use mempool's matching function (handles short-ID collisions)
        matched_txs, _ = mempool.match_compact_block(self.short_ids, key)

        # Fill remaining slots from matched mempool transactions
        sid_iter = iter(matched_txs)
        missing: list[int] = []
        for i in range(total_tx_count):
            if txs[i] is not None:
                continue
            matched = next(sid_iter)
            if matched is not None:
                txs[i] = matched
            else:
                missing.append(i)

        if missing:
            return None, missing
        return txs, []  # type: ignore[return-value]

    # Wire-format serialization / deserialization

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
    def deserialize(cls, payload: bytes) -> CompactBlock:
        """Deserialize from ``cmpctblock`` payload.

        Raises ValueError on obviously malformed input (truncated wire data).
        The deeper structural checks (index overflows, DoS gates) are performed
        by validate() / reconstruct() so that the caller can apply the same
        READ_STATUS_INVALID / READ_STATUS_FAILED distinction as Core.
        """
        from ouroboros.p2p_messages import TxMessage

        if len(payload) < 88:
            raise ValueError("cmpctblock payload too short")

        header = payload[:80]
        nonce = struct.unpack("<Q", payload[80:88])[0]
        off = 88

        sid_count, consumed = decode_varint(payload, off)
        off += consumed
        short_ids = []
        for _ in range(sid_count):
            if off + 6 > len(payload):
                raise ValueError("cmpctblock: short_id truncated")
            raw = payload[off:off + 6] + b'\x00\x00'
            short_ids.append(struct.unpack("<Q", raw)[0])
            off += 6

        pf_count, consumed = decode_varint(payload, off)
        off += consumed

        # Bitcoin Core CBlockHeaderAndShortTxIDs deserialization check
        # (blockencodings.h SERIALIZE_METHODS, line 125):
        #   if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max())
        #       throw std::ios_base::failure("indexes overflowed 16 bits")
        if sid_count + pf_count > 0xFFFF:
            raise ValueError(
                f"cmpctblock: BlockTxCount {sid_count + pf_count} overflows uint16_t"
            )

        prefilled: list[PrefilledTransaction] = []
        # Differential encoding: each stored diff is offset-from-last+1.
        # last_abs tracks the last *absolute* position placed.
        last_abs = -1
        for _ in range(pf_count):
            diff, consumed = decode_varint(payload, off)
            off += consumed
            abs_idx = last_abs + 1 + diff

            tx_msg = TxMessage.from_payload(payload[off:])
            tx = tx_msg.transaction
            tx_len = len(tx.serialize_with_witness())
            off += tx_len

            # Store the absolute position in .index (consistent with
            # from_block() which stores 0 for the coinbase).
            prefilled.append(PrefilledTransaction(index=abs_idx, tx=tx))
            last_abs = abs_idx

        return cls(
            header=header, nonce=nonce,
            short_ids=short_ids, prefilled_txs=prefilled,
        )

    @classmethod
    def from_block(
        cls, block: Block, nonce: int, *, prefill_coinbase: bool = True
    ) -> CompactBlock:
        """
        Build a CompactBlock from a full block.

        Used when *we* relay a compact block to a peer.
        """
        header = block.serialize()[:80]
        key = compute_siphash_key(header, nonce)

        prefilled: list[PrefilledTransaction] = []
        sids: list[int] = []

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
    indices: list[int]

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
    def deserialize(cls, payload: bytes) -> BlockTransactionsRequest:
        if len(payload) < 33:
            raise ValueError("getblocktxn payload too short")
        block_hash = payload[:32]
        off = 32
        count, consumed = decode_varint(payload, off)
        off += consumed
        indices: list[int] = []
        last = -1
        for _ in range(count):
            diff, consumed = decode_varint(payload, off)
            off += consumed
            abs_idx = last + 1 + diff
            indices.append(abs_idx)
            last = abs_idx
        return cls(block_hash=block_hash, indices=indices)


@dataclass
class BlockTransactions:
    """``blocktxn`` — response with the requested missing transactions."""
    block_hash: bytes
    transactions: list[Transaction]

    def serialize(self) -> bytes:
        data = bytearray(self.block_hash)
        data.extend(encode_varint(len(self.transactions)))
        for tx in self.transactions:
            data.extend(tx.serialize_with_witness())
        return bytes(data)

    @classmethod
    def deserialize(cls, payload: bytes) -> BlockTransactions:
        from ouroboros.p2p_messages import TxMessage
        if len(payload) < 33:
            raise ValueError("blocktxn payload too short")
        block_hash = payload[:32]
        off = 32
        count, consumed = decode_varint(payload, off)
        off += consumed
        txs = []
        for _ in range(count):
            tx_msg = TxMessage.from_payload(payload[off:])
            tx = tx_msg.transaction
            tx_len = len(tx.serialize_with_witness())
            off += tx_len
            txs.append(tx)
        return cls(block_hash=block_hash, transactions=txs)
