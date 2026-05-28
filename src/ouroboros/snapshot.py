"""
UTXO snapshot loading and creation for assumeUTXO (BIP305).

This module provides Python interfaces for UTXO snapshot operations,
enabling fast node startup by loading a pre-validated UTXO set.

Wire format is byte-for-byte compatible with Bitcoin Core's
`dumptxoutset` / `loadtxoutset` (snapshot version 2). Encoding details:

  Header (fixed):
    magic         : 5 bytes              -- b"utxo\\xff" (SNAPSHOT_MAGIC_BYTES)
    version       : uint16 little-endian -- 2
    network_magic : 4 bytes              -- pchMessageStart for the chain
    base_blockhash: 32 bytes             -- internal byte order (LE display)
    coins_count   : uint64 little-endian

  Per-txid group (sorted by raw txid bytes, ascending):
    txid          : 32 bytes             -- internal byte order
    coins_per_txid: CompactSize          -- # of unspent vouts in this txid
    For each coin (sorted by vout, ascending):
      vout        : CompactSize
      code        : Bitcoin VARINT       -- (height << 1) | fCoinBase
      value       : Bitcoin VARINT       -- CompressAmount(satoshis)
      script      : ScriptCompression    -- VARINT(nSize) + body, where
                                            nSize < 6 selects a recognized
                                            template, otherwise nSize-6 is
                                            the raw body length.

References:
  - bitcoin-core/src/node/utxo_snapshot.{h,cpp}      -- SnapshotMetadata
  - bitcoin-core/src/rpc/blockchain.cpp              -- WriteUTXOSnapshot
  - bitcoin-core/src/coins.h                         -- Coin::Serialize
  - bitcoin-core/src/compressor.{h,cpp}              -- CompressAmount, CompressScript
  - bitcoin-core/src/serialize.h                     -- ReadVarInt, WriteVarInt
  - bitcoin-core/src/kernel/chainparams.cpp          -- m_assumeutxo_data
"""

import hashlib
import logging
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

# MoneyRange upper bound: 21M BTC in satoshis (amount.h:MAX_MONEY).
# Mirrors bitcoin-core/src/consensus/amount.h:
#   static constexpr CAmount MAX_MONEY = 21'000'000 * COIN;
_MAX_MONEY = 21_000_000 * 100_000_000  # 2,100,000,000,000,000 sat

from .muhash import MuHash3072, coin_element

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HashWriter (CHash256 / SHA256d) -- streaming double-SHA256, mirrors
# bitcoin-core/src/hash.h::HashWriter.
#
# Core's `loadtxoutset` strict assumeUTXO gate hashes the UTXO set using
# `CoinStatsHashType::HASH_SERIALIZED`, which feeds TxOutSer bytes into a
# single CSHA256 context and then double-SHA256s the digest at the end
# (validation.cpp:5902-5915, kernel/coinstats.cpp:161-163, hash.h:115-120).
#
# The streaming class lets us hash coins as they arrive in a snapshot
# without materializing the full coin list. Order-sensitive: the snapshot
# wire format already iterates (txid asc, vout asc), which is the same
# order Core's CCoinsViewCursor walks the leveldb cursor.
# ---------------------------------------------------------------------------


class HashWriter:
    """Streaming SHA256d hasher matching Core's HashWriter::GetHash().

    Internal state is a single SHA-256 context; ``digest()`` finalizes
    that context and runs SHA-256 over the result (CHash256). Used by
    Core's `loadtxoutset` strict commitment check on the UTXO set.
    """

    __slots__ = ("_ctx",)

    def __init__(self) -> None:
        self._ctx = hashlib.sha256()

    def update(self, data: bytes) -> "HashWriter":
        self._ctx.update(data)
        return self

    def digest(self) -> bytes:
        """Compute SHA256d (double-SHA256) over the buffered input.

        Mirrors `HashWriter::GetHash` (hash.h:115-120):
            ctx.Finalize -> sha256.Reset.Write(result).Finalize
        """
        first = self._ctx.digest()
        return hashlib.sha256(first).digest()


# Snapshot format constants -- match SNAPSHOT_MAGIC_BYTES + VERSION in Core.
SNAPSHOT_MAGIC = b"utxo\xff"
SNAPSHOT_VERSION = 2

# Network magic bytes (pchMessageStart, matches Bitcoin Core chainparams.cpp)
NETWORK_MAGIC = {
    "mainnet": bytes([0xf9, 0xbe, 0xb4, 0xd9]),
    "testnet": bytes([0x0b, 0x11, 0x09, 0x07]),
    "testnet4": bytes([0x1c, 0x16, 0x3f, 0x28]),
    "signet": bytes([0x0a, 0x03, 0xcf, 0x40]),
    "regtest": bytes([0xfa, 0xbf, 0xb5, 0xda]),
}

# Bitcoin script opcodes referenced by ScriptCompression. Kept local to avoid
# pulling a heavier script module into the snapshot path.
_OP_DUP = 0x76
_OP_HASH160 = 0xa9
_OP_EQUALVERIFY = 0x88
_OP_EQUAL = 0x87
_OP_CHECKSIG = 0xac

# Maximum permitted script body length when stored as a raw script. Mirrors
# Core's MAX_SCRIPT_SIZE (10 KiB) -- we accept up to this many bytes after
# the special-script tag count of 6.
MAX_SCRIPT_SIZE = 10_000

# Number of recognized special script types (PUBKEYHASH, SCRIPTHASH, four
# pubkey forms). After these tags, sizes are offset by +6 to encode a raw
# body length. See compressor.h ScriptCompression::nSpecialScripts.
N_SPECIAL_SCRIPTS = 6


@dataclass
class AssumeutxoData:
    """Hardcoded assumeUTXO data for a specific block height.

    ``base_header`` is the 80-byte serialized block header (version,
    prev_blockhash, merkle_root, time, bits, nonce in wire/internal byte
    order) for ``block_hash``.  When the snapshot is loaded, only
    META_CF's best_block tip is updated -- BLOCKS_CF and BLOCK_INDEX_CF
    have no entry for the snapshot tip, because the full block bytes
    are intentionally not part of the snapshot wire format.  Validating
    the FIRST block above the snapshot tip therefore requires the prev
    header's ``timestamp`` and ``bits`` (matching Bitcoin Core's
    ``LookupBlockIndex(snap_hash)`` which returns the in-memory
    CBlockIndex populated by the header sync that runs before the
    snapshot load).  We bake the 80-byte header in here so the post-
    snapshot prev-block lookup succeeds without requiring header sync
    to have already produced the snapshot tip's header bytes.

    ``base_header`` may be ``None`` for snapshot heights we have not
    yet provisioned (e.g. testnet snapshots that aren't used live);
    in that case the post-snapshot prev-block fallback is unavailable
    and the validator must wait until headers/blocks for the prev
    height arrive via the network.

    ``chainwork_hex`` is the 64-character hex representation of the
    cumulative chainwork at the snapshot block (Bitcoin Core format).
    Used to correct chainwork values for blocks connected after the
    snapshot, which would otherwise be anchored to 0 instead of the
    correct cumulative work from genesis.  Source: ``getblockheader
    <hash>`` against any fully-synced Bitcoin Core node.
    """
    height: int
    block_hash: bytes  # 32 bytes, internal byte order
    hash_serialized: bytes  # 32-byte commitment from Core's coinstats
    chain_tx_count: int
    base_header: bytes | None = None  # 80-byte serialized header, internal byte order
    chainwork_hex: str | None = None  # 64-char hex chainwork at the snapshot height

    def block_hash_hex(self) -> str:
        """Get block hash as hex string (big-endian display format)."""
        return self.block_hash[::-1].hex()

    def hash_serialized_hex(self) -> str:
        """Get hash_serialized as hex string (big-endian display)."""
        return self.hash_serialized[::-1].hex()


@dataclass
class SnapshotMetadata:
    """Metadata from a UTXO snapshot file."""
    version: int
    network: str
    base_blockhash: bytes  # 32 bytes
    coins_count: int

    def base_blockhash_hex(self) -> str:
        """Get base block hash as hex string (big-endian display format)."""
        return self.base_blockhash[::-1].hex()


def _hex_to_hash_le(hex_str: str) -> bytes:
    """Convert hex string (big-endian display) to hash bytes (little-endian internal)."""
    return bytes.fromhex(hex_str)[::-1]


# ---------------------------------------------------------------------------
# Hardcoded assumeUTXO parameters.
#
# Source: bitcoin-core/src/kernel/chainparams.cpp m_assumeutxo_data.
#
# Mainnet  (CMainParams::m_assumeutxo_data):
#   840000, 880000, 910000, 935000, 944183
# Testnet3 (CTestNetParams::m_assumeutxo_data):
#   2500000, 4840000
# Testnet4 (CTestNet4Params::m_assumeutxo_data):
#   90000, 120000
#
# `hash_serialized` and `blockhash` are stored as uint256{...} in Core, which
# is internal byte order; the source file shows them already reversed for
# human display, so we reverse via `_hex_to_hash_le` to match Core's bytes.
# ---------------------------------------------------------------------------

_MAINNET_ASSUMEUTXO: list[AssumeutxoData] = [
    AssumeutxoData(
        height=840_000,
        block_hash=_hex_to_hash_le(
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
        ),
        hash_serialized=_hex_to_hash_le(
            "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
        ),
        chain_tx_count=991_032_194,
        # 80-byte serialized header (wire / internal byte order). Source:
        # `getblockheader <hash> false` against any synced node. The header
        # parses to: version 0x2a5fe000, prev 0000...0172014ba58d6645578a25d0ad512365adcd0791491b91ea84948,
        # merkle 031b417c3a1828ddf3d6527fc210daafcc9218e81f98257f88d4d43bd7a5894f,
        # time 1714049975 (2024-04-25), bits 0x17034219, nonce 0xea63987d.
        base_header=bytes.fromhex(
            "00e05f2aab948491071265ad552351d0ad625745668da54b0172010000000000000000004f89a5d73bd4d4887f25981fe81892ccafda10c27f52d6f3dd28183a7c411b03b7072366194203177d9863ea"
        ),
    ),
    AssumeutxoData(
        height=880_000,
        block_hash=_hex_to_hash_le(
            "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
        ),
        hash_serialized=_hex_to_hash_le(
            "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
        ),
        chain_tx_count=1_145_604_538,
        base_header=bytes.fromhex(
            "00e08b2686dde705907acd8ddb3825e41e7f4bd470ae0d89657b01000000000000000000031ee4c43ad4b36796f2d2312138ac39356cf9e182748de7900d8d572bd73e6fffa98d67618c02174b491507"
        ),
    ),
    AssumeutxoData(
        height=910_000,
        block_hash=_hex_to_hash_le(
            "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
        ),
        hash_serialized=_hex_to_hash_le(
            "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
        ),
        chain_tx_count=1_226_586_151,
        base_header=bytes.fromhex(
            "00a0572be06d4f01a2ed2228dec965539cc8b96512ccde7d2824010000000000000000006f28c30dc748f6b1430fb2b9a5a94b5b34a5df6e318c6cc5c310a1a35b432b59a3ab9d68b32c021719d103e9"
        ),
    ),
    AssumeutxoData(
        height=935_000,
        block_hash=_hex_to_hash_le(
            "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
        ),
        hash_serialized=_hex_to_hash_le(
            "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
        ),
        chain_tx_count=1_305_397_408,
        base_header=bytes.fromhex(
            "00e00520c5f33700321310024933d3549d13176bc3f11210de280100000000000000000090d1e6e4d2be8cab3a503ba29c3fd1d21b55da72854356d1b1fee656d151168abe568369a1fc011700ed55d4"
        ),
    ),
    # Local snapshot at h=944183 (not from Core chainparams). Hash computed
    # by canonical SHA256d hash_serialized over the dumped UTXO set.
    # Display order of hash_serialized: 2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8
    AssumeutxoData(
        height=944_183,
        block_hash=_hex_to_hash_le(
            "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
        ),
        hash_serialized=_hex_to_hash_le(
            "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
        ),
        chain_tx_count=1_334_000_000,
        # bits = 0x17020684 (the difficulty in effect for the period
        # containing 944183/944184; non-retarget so 944184 must use the
        # same value). time = 1775651930 (2026-04-29), nonce = 0xae00fc06,
        # prev = 00000000000000000000d6e603dff7e37cffedb78c4d090436cc428e956a6904.
        base_header=bytes.fromhex(
            "00c0052004696a958e42cc3604094d8cb7edff7ce3f7df03e6d600000000000000000000a86bcf724ea11137002a564c761911343722766b19c268eb56ea2e58c1e4b20f5a4cd66984060217a0a5fbad"
        ),
        # Cumulative chainwork at h=944183 from Bitcoin Core 31.99 (mainnet).
        # Source: getblockheader 0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817
        # This value is used to correct chainwork for blocks connected after a
        # snapshot load at this height (which would otherwise start from 0).
        chainwork_hex="00000000000000000000000000000000000000011de68a167d5dad115a96be80",
    ),
]

_TESTNET_ASSUMEUTXO: list[AssumeutxoData] = [
    AssumeutxoData(
        height=2_500_000,
        block_hash=_hex_to_hash_le(
            "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"
        ),
        hash_serialized=_hex_to_hash_le(
            "f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"
        ),
        chain_tx_count=66_484_552,
    ),
    AssumeutxoData(
        height=4_840_000,
        block_hash=_hex_to_hash_le(
            "00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"
        ),
        hash_serialized=_hex_to_hash_le(
            "ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a"
        ),
        chain_tx_count=536_078_574,
    ),
]

_TESTNET4_ASSUMEUTXO: list[AssumeutxoData] = [
    AssumeutxoData(
        height=90_000,
        block_hash=_hex_to_hash_le(
            "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
        ),
        hash_serialized=_hex_to_hash_le(
            "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
        ),
        chain_tx_count=11_347_043,
    ),
    AssumeutxoData(
        height=120_000,
        block_hash=_hex_to_hash_le(
            "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"
        ),
        hash_serialized=_hex_to_hash_le(
            "10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"
        ),
        chain_tx_count=14_141_057,
    ),
]


def get_assumeutxo_params(network: str) -> list[AssumeutxoData]:
    """Get hardcoded assumeUTXO parameters for a network."""
    if network in ("mainnet", "bitcoin"):
        return list(_MAINNET_ASSUMEUTXO)
    if network in ("testnet", "testnet3"):
        return list(_TESTNET_ASSUMEUTXO)
    if network == "testnet4":
        return list(_TESTNET4_ASSUMEUTXO)
    # Regtest / signet allow any snapshot.
    return []


def get_assumeutxo_data(network: str, height: int) -> AssumeutxoData | None:
    """Get assumeUTXO data for a specific height."""
    for data in get_assumeutxo_params(network):
        if data.height == height:
            return data
    return None


def get_assumeutxo_by_hash(network: str, block_hash: bytes) -> AssumeutxoData | None:
    """Get assumeUTXO data by block hash (32 bytes, internal byte order)."""
    for data in get_assumeutxo_params(network):
        if data.block_hash == block_hash:
            return data
    return None


def get_available_snapshot_heights(network: str) -> list[int]:
    """Get all available snapshot heights for a network."""
    return [data.height for data in get_assumeutxo_params(network)]


def detect_snapshot_chainwork_offset(db, network: str) -> int:
    """Return the chainwork correction offset for a snapshot-loaded datadir.

    When a node was bootstrapped from an assumeUTXO snapshot **before** the
    snapshot loader learned to persist the snapshot block's BlockMetadata,
    every block connected above the snapshot height accumulated chainwork
    relative to 0 instead of relative to the snapshot's true cumulative
    work.  This function detects that on-disk corruption and returns the
    additive correction (the snapshot height's canonical chainwork from
    Core's hardcoded assumeUTXO data).

    Detection: read the stored chainwork at ``snap_h + 1``.  If a snapshot
    was loaded and its base was applied, that value is already at least the
    snapshot's chainwork.  If the snapshot base was NOT applied, the stored
    value is only ~one block of work — far below the snapshot chainwork —
    so the offset is required.

    Returns 0 when no snapshot was loaded, when the datadir is already
    correct (snapshot base present), or when the snapshot's chainwork is
    unknown.  Adding 0 is always safe.

    Shared by ``Node._chainwork_snapshot_offset`` (RPC chainwork display)
    and ``BlockSync``'s G8 nMinimumChainWork gate so both evaluate the
    same corrected total — see snapshot.py ``load_snapshot`` for the
    root-cause fix that makes this offset unnecessary for new datadirs.
    """
    try:
        for data in get_assumeutxo_params(network):
            if data.chainwork_hex is None:
                continue
            snap_h = data.height
            stored_at_first = db.get_chainwork_by_height(snap_h + 1)
            if stored_at_first <= 0:
                # No block above this snapshot height stored yet — either
                # this snapshot was not the one loaded, or sync has not
                # progressed past it.  Nothing to correct.
                continue
            correct_snap = int(data.chainwork_hex, 16)
            # If the stored value already meets/exceeds the snapshot's
            # chainwork, the base was applied correctly — no offset.
            if stored_at_first < correct_snap:
                return correct_snap
    except Exception:
        # Defense-in-depth: a detection failure must never break sync.
        # Returning 0 only makes the G8 gate stricter, never weaker.
        pass
    return 0


# ---------------------------------------------------------------------------
# CompactSize (Bitcoin protocol) -- used for vout and coins_per_txid.
# ---------------------------------------------------------------------------


_MAX_COMPACT_SIZE = 0x02000000  # Bitcoin Core serialize.h MAX_SIZE


def _read_compact_size(f: BinaryIO) -> int:
    """Read a CompactSize (variable-length integer) from a stream.

    Rejects non-canonical encodings (Core: "non-canonical ReadCompactSize()") and
    values exceeding MAX_SIZE (0x02000000) per Bitcoin Core serialize.h.
    """
    first = f.read(1)
    if not first:
        raise EOFError("Unexpected end of file reading CompactSize")
    n = first[0]
    if n < 0xfd:
        return n
    if n == 0xfd:
        value = struct.unpack("<H", f.read(2))[0]
        if value < 0xfd:
            raise ValueError(f"Non-canonical CompactSize: 0xfd prefix with value {value} < 0xfd")
    elif n == 0xfe:
        value = struct.unpack("<I", f.read(4))[0]
        if value < 0x10000:
            raise ValueError(f"Non-canonical CompactSize: 0xfe prefix with value {value} < 0x10000")
    else:
        value = struct.unpack("<Q", f.read(8))[0]
        if value < 0x100000000:
            raise ValueError(f"Non-canonical CompactSize: 0xff prefix with value {value} < 0x100000000")
    if value > _MAX_COMPACT_SIZE:
        raise ValueError(f"CompactSize value {value} exceeds MAX_SIZE ({_MAX_COMPACT_SIZE})")
    return value


def _write_compact_size(f: BinaryIO, n: int) -> None:
    """Write a CompactSize (variable-length integer) to a stream."""
    if n < 0:
        raise ValueError(f"CompactSize cannot be negative: {n}")
    if n < 0xfd:
        f.write(bytes([n]))
    elif n <= 0xffff:
        f.write(b"\xfd" + struct.pack("<H", n))
    elif n <= 0xffffffff:
        f.write(b"\xfe" + struct.pack("<I", n))
    else:
        f.write(b"\xff" + struct.pack("<Q", n))


# ---------------------------------------------------------------------------
# Bitcoin VARINT (NOT CompactSize) -- used for code, amount, and script size.
#
# Reference: bitcoin-core/src/serialize.h ReadVarInt / WriteVarInt.
#
# Encoding (big-endian, 7 bits per byte, top bit set on continuation):
#   while True:
#     emit (n & 0x7F) | (continuation ? 0x80 : 0x00)
#     if n <= 0x7F: break
#     n = (n >> 7) - 1
# Bytes are written most-significant first; decoder reverses.
# ---------------------------------------------------------------------------


def write_varint(f: BinaryIO, n: int) -> None:
    """Write a Bitcoin VARINT (Core's WriteVarInt) to a stream."""
    if n < 0:
        raise ValueError(f"VARINT cannot be negative: {n}")
    tmp = bytearray()
    while True:
        byte = (n & 0x7F) | (0x80 if tmp else 0x00)
        tmp.append(byte)
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    # Reverse: most-significant byte first.
    tmp.reverse()
    f.write(bytes(tmp))


def read_varint(f: BinaryIO) -> int:
    """Read a Bitcoin VARINT (Core's ReadVarInt) from a stream."""
    n = 0
    while True:
        byte = f.read(1)
        if not byte:
            raise EOFError("Unexpected end of file reading VARINT")
        ch = byte[0]
        # Guard against overflow on absurd inputs (mirrors Core's check).
        if n > ((1 << 63) - 1) >> 7:
            raise ValueError("VARINT: size too large")
        n = (n << 7) | (ch & 0x7F)
        if ch & 0x80:
            n += 1
        else:
            return n


# ---------------------------------------------------------------------------
# AmountCompression -- mantissa/exponent encoding for sat values.
# Reference: bitcoin-core/src/compressor.cpp CompressAmount / DecompressAmount.
# ---------------------------------------------------------------------------


def compress_amount(n: int) -> int:
    """Compress an amount (in satoshis) using Core's mantissa/exponent scheme."""
    if n < 0:
        raise ValueError(f"compress_amount: amount must be non-negative, got {n}")
    if n == 0:
        return 0
    e = 0
    while (n % 10) == 0 and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        assert 1 <= d <= 9
        n //= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    return 1 + (n - 1) * 10 + 9


def decompress_amount(x: int) -> int:
    """Inverse of compress_amount."""
    if x < 0:
        raise ValueError(f"decompress_amount: encoded value must be non-negative, got {x}")
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e:
        n *= 10
        e -= 1
    return n


# ---------------------------------------------------------------------------
# ScriptCompression -- recognize 6 templates (P2PKH, P2SH, four P2PK forms),
# fall back to raw body with offset-by-N_SPECIAL_SCRIPTS size tag.
#
# Recognized templates (write side):
#   0x00: P2PKH  (25 bytes: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG)
#   0x01: P2SH   (23 bytes: OP_HASH160 0x14 <20> OP_EQUAL)
#   0x02/0x03: P2PK with compressed pubkey (35 bytes: 0x21 <33> OP_CHECKSIG, leading byte 0x02 or 0x03)
#   0x04/0x05: P2PK with uncompressed pubkey (67 bytes, leading byte 0x04)
#              -- requires libsecp256k1 to round-trip; we only emit the raw
#              fallback for these in honest-progress mode (TODO below).
#
# Read side: same. Tags 0x04/0x05 (uncompressed-key P2PK) are handled by
# round-tripping through libsecp256k1 (via `coincurve`) to recover the full
# y-coordinate, matching Core's `pubkey.Decompress()` path. P2PKH/P2SH/P2PK
# (compressed) round-trip cleanly without any external dependency.
# ---------------------------------------------------------------------------


def _is_p2pkh(script: bytes) -> tuple[bool, bytes]:
    if (len(script) == 25 and script[0] == _OP_DUP and script[1] == _OP_HASH160
            and script[2] == 20 and script[23] == _OP_EQUALVERIFY
            and script[24] == _OP_CHECKSIG):
        return True, script[3:23]
    return False, b""


def _is_p2sh(script: bytes) -> tuple[bool, bytes]:
    if (len(script) == 23 and script[0] == _OP_HASH160 and script[1] == 20
            and script[22] == _OP_EQUAL):
        return True, script[2:22]
    return False, b""


def _is_p2pk_compressed(script: bytes) -> tuple[bool, bytes]:
    """Return (matches, 33-byte pubkey) for a 35-byte P2PK with compressed key."""
    if (len(script) == 35 and script[0] == 33 and script[34] == _OP_CHECKSIG
            and script[1] in (0x02, 0x03)):
        return True, script[1:34]
    return False, b""


def compress_script(script: bytes) -> bytes | None:
    """
    Try to encode `script` as one of the six special compressed forms.

    Returns the compressed body (21 or 33 bytes) on success, or None if
    `script` does not match any recognized template. The returned body
    starts with the 1-byte tag (0x00..0x05).

    Note: tags 0x04/0x05 (uncompressed-key P2PK on the wire) are fully
    supported on the *read* side (`decompress_script` recovers the full
    pubkey via libsecp256k1). On the write side we currently fall through
    to raw encoding for 67-byte uncompressed-key P2PK -- this is a Core
    parity gap when ouroboros emits its own snapshots, but does not block
    `loadtxoutset` against Core dumps (which is the consumer of this code).
    TODO: emit tag 0x04|(y&1) || x32 for 67-byte uncompressed P2PK.
    """
    ok, h160 = _is_p2pkh(script)
    if ok:
        return bytes([0x00]) + h160
    ok, h160 = _is_p2sh(script)
    if ok:
        return bytes([0x01]) + h160
    ok, pubkey = _is_p2pk_compressed(script)
    if ok:
        # pubkey is 33 bytes starting with 0x02 or 0x03; we keep that prefix
        # as the tag byte and the remaining 32 bytes as the body.
        return bytes([pubkey[0]]) + pubkey[1:]
    # TODO: detect uncompressed-key P2PK (script.size()==67, leading 0x41,
    # pubkey[1]==0x04) and emit tag 0x04|(y&1) + x32. Requires secp256k1.
    return None


def decompress_script(tag: int, body: bytes) -> bytes:
    """
    Reverse of compress_script for a given tag (0x00..0x05) and body bytes.

    Mirrors `bitcoin-core/src/compressor.cpp::DecompressScript`. For tags
    0x04/0x05 the body holds the x-coordinate of an uncompressed-key P2PK
    output; the full 65-byte pubkey is recovered via libsecp256k1 (the
    compressed form `(tag - 2) || x[32]` is parsed and then re-serialized
    uncompressed). Fails closed (ValueError) on an x-coordinate that is
    not on the curve.

    Raises ValueError if the tag is unknown or the body has the wrong size.
    """
    if tag == 0x00:
        if len(body) != 20:
            raise ValueError("decompress_script(P2PKH): expected 20 bytes")
        return bytes([_OP_DUP, _OP_HASH160, 20]) + body + bytes([_OP_EQUALVERIFY, _OP_CHECKSIG])
    if tag == 0x01:
        if len(body) != 20:
            raise ValueError("decompress_script(P2SH): expected 20 bytes")
        return bytes([_OP_HASH160, 20]) + body + bytes([_OP_EQUAL])
    if tag in (0x02, 0x03):
        if len(body) != 32:
            raise ValueError(f"decompress_script(P2PK compressed): expected 32 bytes, got {len(body)}")
        # Rebuild 35-byte script: 0x21 <33-byte pubkey> 0xac
        pubkey = bytes([tag]) + body
        return bytes([33]) + pubkey + bytes([_OP_CHECKSIG])
    if tag in (0x04, 0x05):
        if len(body) != 32:
            raise ValueError(
                f"decompress_script(P2PK uncompressed): expected 32 bytes, got {len(body)}"
            )
        # Mirror compressor.cpp:122-135. Build the 33-byte compressed pubkey
        # `(tag - 2) || x[32]` (so 0x04->0x02, 0x05->0x03), parse via
        # libsecp256k1, then re-serialize uncompressed (65 bytes, 0x04 prefix).
        # Output is a 67-byte P2PK: 0x41 <pubkey65> 0xac.
        try:
            from coincurve import PublicKey
        except ImportError as exc:  # pragma: no cover - dependency declared in pyproject
            raise RuntimeError(
                "decompress_script: coincurve is required for P2PK uncompressed-key decoding"
            ) from exc
        compressed = bytes([tag - 2]) + body
        try:
            pk = PublicKey(compressed)
            uncompressed = pk.format(compressed=False)
        except Exception as exc:
            # Off-curve or otherwise unparseable x-coordinate -> fail closed,
            # matching Core's `pubkey.Decompress()` returning false.
            raise ValueError(
                f"decompress_script(P2PK uncompressed): secp256k1 decompress "
                f"failed for tag {tag:#x}: {exc}"
            ) from exc
        if len(uncompressed) != 65 or uncompressed[0] != 0x04:
            raise ValueError(
                f"decompress_script(P2PK uncompressed): unexpected serialized form "
                f"(len={len(uncompressed)}, prefix={uncompressed[:1].hex()})"
            )
        return bytes([65]) + uncompressed + bytes([_OP_CHECKSIG])
    raise ValueError(f"decompress_script: unknown tag {tag:#x}")


def _special_script_body_len(tag: int) -> int:
    """Return the body length (in bytes) for a recognized script tag."""
    if tag in (0x00, 0x01):
        return 20
    if tag in (0x02, 0x03, 0x04, 0x05):
        return 32
    raise ValueError(f"_special_script_body_len: tag {tag} is not special")


def write_compressed_script(f: BinaryIO, script: bytes) -> None:
    """
    Serialize a scriptPubKey using ScriptCompression (Core wire format):
    VARINT(nSize) followed by the body. nSize < 6 selects a recognized
    template (and the body is the 20- or 32-byte payload). Otherwise we
    write VARINT(len(script) + 6) followed by the raw script bytes.
    """
    compressed = compress_script(script)
    if compressed is not None:
        tag = compressed[0]
        write_varint(f, tag)
        f.write(compressed[1:])
        return
    # Raw fallback. Cap at MAX_SCRIPT_SIZE; an absurdly long script would
    # round-trip as OP_RETURN per Core. We refuse to emit such an input.
    if len(script) > MAX_SCRIPT_SIZE:
        raise ValueError(
            f"write_compressed_script: script length {len(script)} > MAX_SCRIPT_SIZE={MAX_SCRIPT_SIZE}"
        )
    write_varint(f, len(script) + N_SPECIAL_SCRIPTS)
    f.write(script)


def read_compressed_script(f: BinaryIO) -> bytes:
    """Inverse of write_compressed_script."""
    n_size = read_varint(f)
    if n_size < N_SPECIAL_SCRIPTS:
        body = f.read(_special_script_body_len(n_size))
        return decompress_script(n_size, body)
    raw_len = n_size - N_SPECIAL_SCRIPTS
    if raw_len > MAX_SCRIPT_SIZE:
        # Match Core: replace overlong scripts with OP_RETURN, skip the body.
        f.read(raw_len)
        return bytes([0x6a])  # OP_RETURN
    return f.read(raw_len)


# ---------------------------------------------------------------------------
# Coin / metadata serialization.
# ---------------------------------------------------------------------------


def serialize_coin(f: BinaryIO, height: int, is_coinbase: bool, amount: int, script: bytes) -> None:
    """
    Write a single Coin to the stream: VARINT(code), VARINT(compress(amount)),
    ScriptCompression(script). Mirrors Core's `Coin::Serialize` followed by
    `TxOutCompression`.
    """
    if height < 0:
        raise ValueError(f"serialize_coin: height must be non-negative, got {height}")
    code = (height << 1) | (1 if is_coinbase else 0)
    write_varint(f, code)
    write_varint(f, compress_amount(amount))
    write_compressed_script(f, script)


def deserialize_coin(f: BinaryIO) -> tuple[int, bool, int, bytes]:
    """Inverse of serialize_coin. Returns (height, is_coinbase, amount, script)."""
    code = read_varint(f)
    height = code >> 1
    is_coinbase = bool(code & 1)
    amount = decompress_amount(read_varint(f))
    script = read_compressed_script(f)
    return height, is_coinbase, amount, script


def read_snapshot_metadata(path: str, network: str) -> SnapshotMetadata:
    """Read header (magic + version + network + base_blockhash + coins_count)."""
    with open(path, "rb") as f:
        return _read_metadata_header(f, network)


def _read_metadata_header(f: BinaryIO, network: str) -> SnapshotMetadata:
    magic = f.read(5)
    if magic != SNAPSHOT_MAGIC:
        raise ValueError(f"Invalid snapshot magic: {magic!r}")

    raw_version = f.read(2)
    if len(raw_version) != 2:
        raise ValueError("Truncated snapshot: missing version")
    version = struct.unpack("<H", raw_version)[0]
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"Unsupported snapshot version: {version}")

    file_magic = f.read(4)
    expected_magic = NETWORK_MAGIC.get(network)
    if expected_magic is None:
        raise ValueError(f"Unknown network: {network}")
    if file_magic != expected_magic:
        file_network = next(
            (net for net, mag in NETWORK_MAGIC.items() if mag == file_magic),
            None,
        )
        raise ValueError(
            f"Network mismatch: snapshot is for {file_network or 'unknown'}, "
            f"expected {network}"
        )

    base_blockhash = f.read(32)
    if len(base_blockhash) != 32:
        raise ValueError("Truncated snapshot: missing base_blockhash")
    raw_count = f.read(8)
    if len(raw_count) != 8:
        raise ValueError("Truncated snapshot: missing coins_count")
    coins_count = struct.unpack("<Q", raw_count)[0]
    return SnapshotMetadata(
        version=version,
        network=network,
        base_blockhash=base_blockhash,
        coins_count=coins_count,
    )


def _write_metadata_header(
    f: BinaryIO,
    network: str,
    base_blockhash: bytes,
    coins_count: int,
) -> None:
    if len(base_blockhash) != 32:
        raise ValueError("base_blockhash must be 32 bytes")
    f.write(SNAPSHOT_MAGIC)
    f.write(struct.pack("<H", SNAPSHOT_VERSION))
    f.write(NETWORK_MAGIC[network])
    f.write(base_blockhash)
    f.write(struct.pack("<Q", coins_count))


# ---------------------------------------------------------------------------
# SnapshotManager -- end-to-end load/dump driver.
# ---------------------------------------------------------------------------


class SnapshotManager:
    """
    Manages UTXO snapshot loading and creation for assumeUTXO.

    This class handles:
    - Loading UTXO snapshots for fast startup
    - Background validation of the snapshot
    - Creating new snapshots (dumptxoutset)
    """

    def __init__(self, db, network: str, data_dir: str):
        self.db = db
        self.network = network
        self.data_dir = Path(data_dir)

        # Snapshot state
        self.snapshot_loaded = False
        self.snapshot_height: int | None = None
        self.snapshot_hash: bytes | None = None

        # Background validation state
        self.background_validating = False
        self.background_validated = False
        self.background_validation_height = 0
        self._validation_thread: threading.Thread | None = None
        self._validation_cancel = threading.Event()

    def get_snapshot_chainstate_dir(self) -> Path:
        """Get the directory for snapshot chainstate data."""
        return self.data_dir / "chainstate_snapshot"

    def has_snapshot_chainstate(self) -> bool:
        """Check if a snapshot chainstate exists."""
        snapshot_dir = self.get_snapshot_chainstate_dir()
        return snapshot_dir.exists() and (snapshot_dir / "base_blockhash").exists()

    def read_snapshot_base_blockhash(self) -> bytes | None:
        """Read the base block hash from an existing snapshot chainstate."""
        blockhash_file = self.get_snapshot_chainstate_dir() / "base_blockhash"
        if blockhash_file.exists():
            return blockhash_file.read_bytes()
        return None

    def write_snapshot_base_blockhash(self, block_hash: bytes) -> None:
        """Write the base block hash to the snapshot chainstate directory."""
        snapshot_dir = self.get_snapshot_chainstate_dir()
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        (snapshot_dir / "base_blockhash").write_bytes(block_hash)

    def read_snapshot_base_blockheader(self) -> bytes | None:
        """Read the 80-byte serialized header for the snapshot base block.

        Mirrors Bitcoin Core's persisted ``CBlockIndex`` for the snapshot
        tip: it lets the validator answer ``timestamp`` / ``bits`` for the
        prev block when validating the FIRST block above the snapshot tip
        (whose ``prev_blockhash`` is the snapshot base hash but whose
        prev block bytes are intentionally not in BLOCKS_CF).

        Returns ``None`` if the sibling file was never written -- i.e. the
        snapshot was loaded by an older build that did not yet persist the
        header, or the chainparams entry for the snapshot height has no
        ``base_header`` provisioned.  Callers must tolerate ``None`` and
        fall back to the existing "buffer the block, retry later" path.
        """
        header_file = self.get_snapshot_chainstate_dir() / "base_blockheader"
        if header_file.exists():
            data = header_file.read_bytes()
            if len(data) == 80:
                return data
            logger.warning(
                f"[snapshot] base_blockheader has unexpected size {len(data)}, "
                f"ignoring (expected 80 bytes)"
            )
        return None

    def write_snapshot_base_blockheader(self, header: bytes) -> None:
        """Write the 80-byte snapshot base header to the snapshot chainstate dir.

        ``header`` must be the standard Bitcoin block header in wire/internal
        byte order (version || prev || merkle || time || bits || nonce).
        """
        if len(header) != 80:
            raise ValueError(
                f"snapshot base header must be 80 bytes, got {len(header)}"
            )
        snapshot_dir = self.get_snapshot_chainstate_dir()
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        (snapshot_dir / "base_blockheader").write_bytes(header)

    def load_snapshot(
        self,
        snapshot_path: str,
        progress_callback: Callable[[int, int], None] | None = None,
        strict: bool = True,
        active_chainwork: int | None = None,
    ) -> SnapshotMetadata:
        """
        Load a UTXO snapshot from a file.

        Validates the snapshot against hardcoded assumeUTXO parameters and
        loads all UTXOs into the database. Wire format matches Core's
        `loadtxoutset` exactly.

        When ``strict=True`` (default) and assumeUTXO data is available,
        we run the post-load SHA256d commitment check that mirrors
        ``validation.cpp:5902-5915``: Core hashes the loaded UTXO set
        with ``CoinStatsHashType::HASH_SERIALIZED`` (a ``HashWriter``
        feeding ``TxOutSer`` bytes, double-SHA256 finalize -- see
        kernel/coinstats.cpp:161-163 + hash.h:115-120) and rejects the
        snapshot if the digest does not match
        ``AssumeutxoData.hash_serialized`` from chainparams. We do the
        same: a streaming HashWriter accumulates bytes as the snapshot
        coins are deserialized in (txid, vout) order (the snapshot's
        canonical wire order, matching CCoinsViewCursor's leveldb walk).

        The MuHash3072 path is the gettxoutsetinfo digest, NOT what
        loadtxoutset enforces -- see compute_utxo_hash(hash_type=...).

        ``active_chainwork`` is the cumulative chainwork (as an integer) of
        the active chainstate tip at the time of the call.  When provided,
        load_snapshot enforces BUG-3: the snapshot's chainwork must strictly
        exceed the active tip (mirrors Core's PopulateAndValidateSnapshot
        early-exit at validation.cpp:5787-5789).  Pass ``None`` (default) to
        skip this check (e.g. when the active tip has no known chainwork).

        Atomicity (FIX-D, chainstate atomicity family 2026-05-26):
        the load now uses the three-step `snapshot_load_begin` /
        `snapshot_load_chunk` / `snapshot_load_commit` protocol when the
        Rust extension exposes it (current ferrous-utils builds do).
        Begin writes the SNAPSHOT_LOAD_IN_PROGRESS marker to META_CF;
        chunks apply 10K coins per RocksDB WriteBatch; commit fuses the
        final tip update + block-metadata write + marker delete into one
        atomic batch.  On crash mid-load, next-boot `recover_from_crash`
        detects the marker, clears the partial chainstate, resets the tip
        to genesis-sentinel, and instructs the operator to re-run
        `loadtxoutset`.  Older extensions without the FFI symbols fall
        back to the legacy per-coin path (non-atomic) so the upgrade is
        rolling-safe.  See CORE-PARITY-AUDIT/_chainstate-atomicity-family-
        2026-05-26.md.
        """
        with open(snapshot_path, "rb") as f:
            metadata = _read_metadata_header(f, self.network)

            au_data = get_assumeutxo_by_hash(self.network, metadata.base_blockhash)
            if au_data is None and self.network != "regtest":
                available = get_available_snapshot_heights(self.network)
                raise ValueError(
                    f"assumeUTXO block hash {metadata.base_blockhash_hex()} not recognized. "
                    f"Available heights: {available}"
                )

            height = au_data.height if au_data else 0

            # BUG-3: chainwork-exceeds-active-chainstate guard.
            # Mirrors Core PopulateAndValidateSnapshot:
            #   if (!CBlockIndexWorkComparator()(ActiveTip(), snapshot_start_block))
            #       return Error{"Work does not exceed active chainstate"};
            # (validation.cpp:5787-5789, also repeated in ActivateSnapshot:5706-5708)
            # We check this when the caller supplied the active tip's chainwork
            # AND the snapshot's chainwork is known from chainparams.
            if active_chainwork is not None and au_data is not None and au_data.chainwork_hex is not None:
                snapshot_chainwork = int(au_data.chainwork_hex, 16)
                if snapshot_chainwork <= active_chainwork:
                    raise ValueError(
                        f"Snapshot chainwork ({au_data.chainwork_hex}) does not exceed "
                        f"active chainstate work ({active_chainwork:#066x}); "
                        "refusing to load snapshot"
                    )

            logger.info(
                f"[snapshot] Loading snapshot at height {height} with {metadata.coins_count:,} coins"
            )

            # ----------------------------------------------------------
            # FIX-D (chainstate atomicity family 2026-05-26): begin the
            # atomic snapshot-load protocol.  This clears the chainstate
            # and writes the SNAPSHOT_LOAD_IN_PROGRESS marker BEFORE any
            # per-coin chunk is written.  On crash mid-load, next-boot
            # `recover_from_crash` detects the marker, clears the
            # partial chainstate, resets the tip to genesis, and instructs
            # the operator to re-run `loadtxoutset`.
            #
            # Older Rust extensions without FIX-D fall back to the legacy
            # per-coin path (no atomicity guarantees) — preserves existing
            # operator workflows during the rolling upgrade window.
            # ----------------------------------------------------------
            use_atomic_load = hasattr(self.db, "snapshot_load_begin")
            if use_atomic_load:
                self.db.snapshot_load_begin(metadata.base_blockhash, height)
            else:
                logger.warning(
                    "[snapshot] Rust extension lacks snapshot_load_begin "
                    "(pre-FIX-D); falling back to per-coin loader — "
                    "load is NOT crash-safe"
                )

            # Streaming SHA256d (HashWriter) over coins as we deserialize
            # them. Mirrors Core's HASH_SERIALIZED path through
            # ApplyCoinHash (kernel/coinstats.cpp:53-56), which is what
            # loadtxoutset's strict gate uses (validation.cpp:5902-5915).
            # The wire format already iterates (txid asc, vout asc), the
            # same order Core's CCoinsViewCursor walks.
            hasher = HashWriter()

            # Per-chunk batch buffer.  10K coins keeps the WriteBatch
            # memory bounded (~1-2 MB at typical mainnet-coin sizes), well
            # under the per-batch threshold rocksdb starts paying for
            # internal sorting, while still cutting Python→Rust FFI
            # round-trips by 10000x vs the per-coin path.  Matches the
            # operator-only Rust bulk-loader chunk size (10K coins per
            # `apply_batch`).
            _CHUNK_SIZE = 10_000
            chunk_buffer: list[
                tuple[bytes, int, int, bytes, int, bool]
            ] = []

            def _flush_chunk() -> None:
                if not chunk_buffer:
                    return
                if use_atomic_load:
                    self.db.snapshot_load_chunk(chunk_buffer)
                else:
                    # Legacy per-coin path (pre-FIX-D extensions only).
                    for (
                        c_txid,
                        c_vout,
                        c_amount,
                        c_script,
                        c_height,
                        c_is_cb,
                    ) in chunk_buffer:
                        self.db.add_utxo_raw(
                            txid=c_txid,
                            vout=c_vout,
                            amount=c_amount,
                            script_pubkey=c_script,
                            height=c_height,
                            is_coinbase=c_is_cb,
                        )
                chunk_buffer.clear()

            coins_left = metadata.coins_count
            coins_loaded = 0
            try:
                while coins_left > 0:
                    txid = f.read(32)
                    if len(txid) != 32:
                        raise ValueError("Truncated snapshot: missing txid")

                    coins_per_txid = _read_compact_size(f)
                    if coins_per_txid == 0 or coins_per_txid > coins_left:
                        raise ValueError(
                            f"Invalid coins_per_txid={coins_per_txid} (coins_left={coins_left})"
                        )

                    for _ in range(coins_per_txid):
                        vout = _read_compact_size(f)
                        coin_height, is_coinbase, amount, script = deserialize_coin(f)

                        # BUG-4: per-coin height bound check.
                        # Mirrors Core PopulateAndValidateSnapshot:
                        #   if (coin.nHeight > base_height) return Error{...}
                        # (validation.cpp:5814-5819)
                        # Only enforced when we know base_height (i.e. au_data is set).
                        if au_data is not None and coin_height > height:
                            raise ValueError(
                                f"Bad snapshot data after deserializing "
                                f"{metadata.coins_count - coins_left} coins: "
                                f"coin.height={coin_height} > base_height={height}"
                            )

                        # BUG-5: per-coin MoneyRange check.
                        # Mirrors Core PopulateAndValidateSnapshot:
                        #   if (!MoneyRange(coin.out.nValue)) return Error{...}
                        # (validation.cpp:5820-5823)
                        if amount < 0 or amount > _MAX_MONEY:
                            raise ValueError(
                                f"Bad snapshot data after deserializing "
                                f"{metadata.coins_count - coins_left} coins - "
                                f"bad tx out value: {amount}"
                            )

                        chunk_buffer.append((
                            txid, vout, amount, script, coin_height, is_coinbase,
                        ))
                        if len(chunk_buffer) >= _CHUNK_SIZE:
                            _flush_chunk()

                        hasher.update(
                            coin_element(
                                txid=txid,
                                vout=vout,
                                height=coin_height,
                                is_coinbase=is_coinbase,
                                amount=amount,
                                script_pubkey=script,
                            )
                        )

                        coins_left -= 1
                        coins_loaded += 1

                        if progress_callback and coins_loaded % 100_000 == 0:
                            progress_callback(coins_loaded, metadata.coins_count)

                # Flush any tail residue (<_CHUNK_SIZE coins remaining).
                _flush_chunk()
            except Exception:
                # Bail out cleanly.  The SNAPSHOT_LOAD_IN_PROGRESS marker
                # is intentionally NOT deleted here — the chainstate may
                # be partially populated and we want next-boot
                # `recover_from_crash` to detect this and clear it.  The
                # operator can also immediately re-run `loadtxoutset` and
                # the marker will be overwritten by `snapshot_load_begin`.
                if use_atomic_load:
                    logger.error(
                        "[snapshot] Load failed mid-stream; chainstate left "
                        "marked SNAPSHOT_LOAD_IN_PROGRESS for crash recovery"
                    )
                raise

            # BUG-6: trailing-bytes EOF check.
            # Mirrors Core PopulateAndValidateSnapshot (validation.cpp:5872-5883):
            #   std::byte left_over_byte;
            #   try { coins_file >> left_over_byte; }
            #   catch (const std::ios_base::failure&) { out_of_coins = true; }
            #   if (!out_of_coins) return Error{"Bad snapshot - coins left over"};
            leftover = f.read(1)
            if leftover:
                raise ValueError(
                    f"Bad snapshot - coins left over after deserializing "
                    f"{metadata.coins_count} coins"
                )

        # Strict commitment check (validation.cpp:5912-5914). Only enforced
        # when chainparams ship a hash for this snapshot height.
        computed = hasher.digest()
        if strict and au_data is not None:
            if computed != au_data.hash_serialized:
                raise ValueError(
                    "Bad snapshot content hash: expected "
                    f"{au_data.hash_serialized_hex()}, got "
                    f"{computed[::-1].hex()}"
                )
            logger.info(
                f"[snapshot] HASH_SERIALIZED commitment OK at height {height} "
                f"({computed[::-1].hex()})"
            )
        elif au_data is None:
            logger.warning(
                "[snapshot] No assumeUTXO commitment available for "
                f"{metadata.base_blockhash_hex()}; skipping commitment check"
            )

        # ------------------------------------------------------------------
        # FIX-D: write sibling files BEFORE the final commit.  They are not
        # in RocksDB so they can't share the atomic batch, but if a crash
        # happens between writing them and `snapshot_load_commit`, the next
        # boot's `recover_from_crash` clears the chainstate (because the
        # marker is still present) and the sibling files become harmless
        # leftovers that will be overwritten on the next successful load.
        # The inverse ordering — commit first, then sibling files — would
        # leave a window where the chainstate / tip are committed but the
        # sibling files are missing, which causes the FIRST post-snapshot
        # block validation to fail with "Previous block not found".
        # ------------------------------------------------------------------
        self.write_snapshot_base_blockhash(metadata.base_blockhash)
        if au_data is not None and au_data.base_header is not None:
            # Persist the 80-byte header for the snapshot tip if chainparams
            # has it (mainnet entries do; testnet entries may not).  Without
            # this, the FIRST block above the snapshot tip cannot be
            # validated (its prev_block lookup returns None and
            # validate_block rejects it with "Previous block not found",
            # forcing an infinite retry loop).  See
            # AssumeutxoData.base_header for the rationale.
            self.write_snapshot_base_blockheader(au_data.base_header)

        # ------------------------------------------------------------------
        # FIX-D: final atomic commit batch.
        # Single RocksDB WriteBatch fuses:
        #   - update_best_block(base_blockhash, base_height)
        #   - store_block_metadata_batch (if chainwork_hex + base_header
        #     present in chainparams — anchors the G8 chainwork accumulator;
        #     see the long comment below for why this matters)
        #   - delete SNAPSHOT_LOAD_IN_PROGRESS marker
        #
        # Pre-FIX-D these were three independent writes (tip put, optional
        # metadata put, no marker at all) — a crash between any pair left
        # the chainstate at the new snapshot tip with no chainwork anchor,
        # or the old tip with the snapshot already loaded, depending on
        # ordering.  Post-FIX-D either all three land or none of them do.
        #
        # ROOT-CAUSE context for the chainwork persist: the "too-little-
        # chainwork; G8" mainnet brick (2026-05-19) was caused by the
        # snapshot block having NO metadata row, so block ``height+1`` read
        # a 0 base from ``compute_chainwork`` and the whole post-snapshot
        # chain accumulated work from 0 — ~32x below reality — making the
        # G8 nMinimumChainWork gate reject every mainnet headers batch and
        # ban honest peers.  Writing the snapshot block's metadata fixes
        # that; fusing it into the commit batch makes the fix atomic with
        # the tip update.
        # ------------------------------------------------------------------
        chainwork_be: bytes | None = None
        snapshot_timestamp: int | None = None
        if (
            au_data is not None
            and au_data.chainwork_hex is not None
            and au_data.base_header is not None
        ):
            snapshot_chainwork = int(au_data.chainwork_hex, 16)
            chainwork_be = snapshot_chainwork.to_bytes(32, "big")
            # base_header layout: version(4) prev(32) merkle(32)
            # time(4) bits(4) nonce(4); time is at byte offset 68.
            snapshot_timestamp = struct.unpack_from(
                "<I", au_data.base_header, 68
            )[0]

        if use_atomic_load:
            self.db.snapshot_load_commit(
                metadata.base_blockhash,
                height,
                chainwork_be=chainwork_be,
                timestamp=snapshot_timestamp,
            )
            if chainwork_be is not None:
                logger.info(
                    f"[snapshot] Persisted snapshot block metadata at "
                    f"height {height}: chainwork={au_data.chainwork_hex}"
                )
        else:
            # Legacy non-atomic path for pre-FIX-D extensions only.  This
            # branch retains the pre-FIX-D ordering exactly so behaviour
            # is identical on old extensions.
            self.db.update_best_block(metadata.base_blockhash, height)
            if chainwork_be is not None:
                try:
                    self.db.store_block_metadata_persistent(
                        height,
                        metadata.base_blockhash,
                        int(au_data.chainwork_hex, 16),
                        snapshot_timestamp,
                    )
                    logger.info(
                        f"[snapshot] Persisted snapshot block metadata at "
                        f"height {height}: chainwork={au_data.chainwork_hex}"
                    )
                except Exception as e:
                    logger.error(
                        f"[snapshot] Failed to persist snapshot block "
                        f"chainwork metadata at height {height}: {e}"
                    )

        self.snapshot_loaded = True
        self.snapshot_height = height
        self.snapshot_hash = metadata.base_blockhash
        logger.info(f"[snapshot] Loaded {coins_loaded:,} coins from snapshot")
        return metadata

    def start_background_validation(
        self,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        """Kick off background validation from genesis to the snapshot height."""
        if self.background_validating:
            logger.warning("[snapshot] Background validation already in progress")
            return
        if not self.snapshot_loaded:
            logger.error("[snapshot] Cannot start background validation: no snapshot loaded")
            return

        self.background_validating = True
        self._validation_cancel.clear()

        def validation_worker():
            try:
                logger.info(
                    f"[snapshot] Starting background validation to height {self.snapshot_height}"
                )
                target_height = self.snapshot_height or 0
                for height in range(target_height + 1):
                    if self._validation_cancel.is_set():
                        logger.info("[snapshot] Background validation cancelled")
                        return
                    self.background_validation_height = height
                    if progress_callback:
                        progress_callback(height, target_height)

                # After reaching target height, recompute the
                # HASH_SERIALIZED (SHA256d) commitment over the live
                # UTXO set and compare against the assumeUTXO chainparams
                # entry. Mirrors validation.cpp's post-load assertion
                # (lines 5902-5915), but here it runs against the
                # chainstate as rebuilt during background IBD, so it
                # doubles as an end-of-IBD audit.
                au_data = get_assumeutxo_by_hash(self.network, self.snapshot_hash)
                if au_data is not None:
                    try:
                        digest = compute_utxo_hash(self.db, hash_type="hash_serialized")
                    except Exception as e:
                        logger.error(
                            f"[snapshot] Background validation: digest failed: {e}"
                        )
                        self.background_validated = False
                        return
                    if digest == au_data.hash_serialized:
                        logger.info(
                            f"[snapshot] Background validation OK at height {target_height} "
                            f"(HASH_SERIALIZED={digest[::-1].hex()})"
                        )
                        self.background_validated = True
                    else:
                        logger.error(
                            "[snapshot] Background validation hash mismatch "
                            f"at height {target_height}: expected "
                            f"{au_data.hash_serialized_hex()}, got "
                            f"{digest[::-1].hex()}"
                        )
                        self.background_validated = False
                else:
                    logger.warning(
                        "[snapshot] Background validation completed but no assumeUTXO data to verify"
                    )
                    self.background_validated = True
            except Exception as e:
                logger.error(f"[snapshot] Background validation failed: {e}")
            finally:
                self.background_validating = False

        self._validation_thread = threading.Thread(
            target=validation_worker,
            name="snapshot-validation",
            daemon=True,
        )
        self._validation_thread.start()

    def stop_background_validation(self) -> None:
        """Stop background validation if in progress."""
        if self._validation_thread and self._validation_thread.is_alive():
            self._validation_cancel.set()
            self._validation_thread.join(timeout=5.0)

    def dump_snapshot(
        self,
        output_path: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> int:
        """
        Dump the current UTXO set to a snapshot file.

        Wire format matches Core's `dumptxoutset` exactly. UTXOs are grouped
        by txid (sorted by raw txid bytes, ascending) and within each group
        by vout. Header uses SnapshotMetadata; each coin is encoded with
        VARINT(code) + VARINT(compress(value)) + ScriptCompression.

        Atomic-write protocol: bytes go to ``<output_path>.incomplete``,
        the fd is fsynced, then renamed to ``<output_path>``. Mirrors
        Bitcoin Core's flow in ``rpc/blockchain.cpp::dumptxoutset``
        (``temppath = path + ".incomplete"``; write; fsync; rename). On
        any error the temp file is best-effort deleted so a crashed
        dump never leaves a torn ``<output_path>`` behind — only the
        ``.incomplete`` artifact, which can be cleaned up out-of-band.
        """
        import os

        best_hash, _ = self.db.get_best_block()
        total_coins = self.db.utxo_count()
        logger.info(f"[snapshot] Dumping {total_coins:,} coins to snapshot")

        temp_path = output_path + ".incomplete"
        coins_written = 0
        try:
            with open(temp_path, "wb") as f:
                _write_metadata_header(f, self.network, best_hash, total_coins)

                # Group UTXOs by txid; sort by raw txid bytes (Core's
                # leveldb cursor delivers them in lexicographic order
                # over the COutPoint key, which is txid || vout LE --
                # so a per-txid bucketed sort plus a per-bucket vout
                # sort matches the on-the-fly stream).
                utxo_groups: dict[bytes, list[tuple[int, Any]]] = {}
                for utxo in self.db.iter_utxos():
                    utxo_groups.setdefault(utxo.txid, []).append((utxo.vout, utxo))

                for txid in sorted(utxo_groups.keys()):
                    coins = utxo_groups[txid]
                    coins.sort(key=lambda x: x[0])
                    f.write(txid)
                    _write_compact_size(f, len(coins))
                    for vout, utxo in coins:
                        _write_compact_size(f, vout)
                        serialize_coin(
                            f,
                            height=utxo.height,
                            is_coinbase=bool(utxo.is_coinbase),
                            amount=int(utxo.amount),
                            script=bytes(utxo.script_pubkey),
                        )
                        coins_written += 1
                        if progress_callback and coins_written % 100_000 == 0:
                            progress_callback(coins_written, total_coins)

                # Durability barrier: flush the user-space buffer and
                # fsync the fd BEFORE the rename. Without this, a power
                # loss between rename and dirty-page flush could leave
                # ``<output_path>`` visible with zero-length / torn
                # contents.
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename: temp -> final. After this point the
            # snapshot is visible to any concurrent reader.
            os.replace(temp_path, output_path)
        except BaseException:
            # Best-effort cleanup of the .incomplete temp on any error
            # (write failure, KeyboardInterrupt, OS-level errors...).
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.warning(
                    f"[snapshot] failed to clean up {temp_path}: {e}"
                )
            raise

        logger.info(f"[snapshot] Wrote {coins_written:,} coins to {output_path}")
        return coins_written

    def get_status(self) -> dict[str, Any]:
        """Get the current snapshot status."""
        return {
            "snapshot_loaded": self.snapshot_loaded,
            "snapshot_height": self.snapshot_height,
            "snapshot_hash": self.snapshot_hash.hex() if self.snapshot_hash else None,
            "background_validating": self.background_validating,
            "background_validated": self.background_validated,
            "background_validation_height": self.background_validation_height,
        }


def compute_utxo_hash(db, hash_type: str = "hash_serialized") -> bytes:
    """
    Compute a deterministic 32-byte digest over the UTXO set.

    Two hash types are supported, mirroring Core's
    ``CoinStatsHashType`` (kernel/coinstats.cpp::ComputeUTXOStats):

    - ``"hash_serialized"`` (default): SHA256d via ``HashWriter`` over
      ``TxOutSer`` bytes for each coin in (txid, vout) order. This is
      what Core's ``loadtxoutset`` uses for the strict assumeUTXO
      commitment check (validation.cpp:5902-5915), and what the
      published ``AssumeutxoData.hash_serialized`` chainparams entries
      contain. Bytes returned are internal byte order; reverse for
      uint256 display hex.

    - ``"muhash"``: MuHash3072 over the same per-coin element. Matches
      Core's ``gettxoutsetinfo hash_type=muhash`` path. Order-independent
      (multiplicative incremental hash).

    Matches Core's ``ComputeUTXOStats`` switch on ``CoinStatsHashType``
    (kernel/coinstats.cpp:160-172).
    """
    if hash_type == "muhash":
        muhash = MuHash3072()
        for utxo in db.iter_utxos():
            element = coin_element(
                txid=utxo.txid,
                vout=utxo.vout,
                height=utxo.height,
                is_coinbase=bool(utxo.is_coinbase),
                amount=int(utxo.amount),
                script_pubkey=bytes(utxo.script_pubkey),
            )
            muhash.insert(element)
        return muhash.digest()

    if hash_type != "hash_serialized":
        raise ValueError(
            f"compute_utxo_hash: unsupported hash_type={hash_type!r}; "
            f"expected 'muhash' or 'hash_serialized'"
        )

    # SHA256d via HashWriter, fed in canonical (txid, vout) order so that
    # the digest matches what Core computes when its CCoinsViewCursor
    # walks the leveldb sorted by (txid, vout).
    hasher = HashWriter()
    utxos = list(db.iter_utxos())
    utxos.sort(key=lambda u: (u.txid, u.vout))
    for utxo in utxos:
        hasher.update(
            coin_element(
                txid=utxo.txid,
                vout=utxo.vout,
                height=utxo.height,
                is_coinbase=bool(utxo.is_coinbase),
                amount=int(utxo.amount),
                script_pubkey=bytes(utxo.script_pubkey),
            )
        )
    return hasher.digest()
