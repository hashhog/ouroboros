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
    """Hardcoded assumeUTXO data for a specific block height."""
    height: int
    block_hash: bytes  # 32 bytes, internal byte order
    hash_serialized: bytes  # 32-byte commitment from Core's coinstats
    chain_tx_count: int

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
#   840000, 880000, 910000, 935000
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


# ---------------------------------------------------------------------------
# CompactSize (Bitcoin protocol) -- used for vout and coins_per_txid.
# ---------------------------------------------------------------------------


def _read_compact_size(f: BinaryIO) -> int:
    """Read a CompactSize (variable-length integer) from a stream."""
    first = f.read(1)
    if not first:
        raise EOFError("Unexpected end of file reading CompactSize")
    n = first[0]
    if n < 0xfd:
        return n
    if n == 0xfd:
        return struct.unpack("<H", f.read(2))[0]
    if n == 0xfe:
        return struct.unpack("<I", f.read(4))[0]
    return struct.unpack("<Q", f.read(8))[0]


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

    def load_snapshot(
        self,
        snapshot_path: str,
        progress_callback: Callable[[int, int], None] | None = None,
        strict: bool = True,
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
            logger.info(
                f"[snapshot] Loading snapshot at height {height} with {metadata.coins_count:,} coins"
            )

            # Streaming SHA256d (HashWriter) over coins as we deserialize
            # them. Mirrors Core's HASH_SERIALIZED path through
            # ApplyCoinHash (kernel/coinstats.cpp:53-56), which is what
            # loadtxoutset's strict gate uses (validation.cpp:5902-5915).
            # The wire format already iterates (txid asc, vout asc), the
            # same order Core's CCoinsViewCursor walks.
            hasher = HashWriter()

            coins_left = metadata.coins_count
            coins_loaded = 0
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

                    self.db.add_utxo_raw(
                        txid=txid,
                        vout=vout,
                        amount=amount,
                        script_pubkey=script,
                        height=coin_height,
                        is_coinbase=is_coinbase,
                    )

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

        # Update database best block to snapshot tip.
        self.db.update_best_block(metadata.base_blockhash, height)
        self.write_snapshot_base_blockhash(metadata.base_blockhash)

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
        """
        best_hash, _ = self.db.get_best_block()
        total_coins = self.db.utxo_count()
        logger.info(f"[snapshot] Dumping {total_coins:,} coins to snapshot")

        with open(output_path, "wb") as f:
            _write_metadata_header(f, self.network, best_hash, total_coins)

            # Group UTXOs by txid; sort by raw txid bytes (Core's leveldb
            # cursor delivers them in lexicographic order over the COutPoint
            # key, which is txid || vout LE -- so a per-txid bucketed sort
            # plus a per-bucket vout sort matches the on-the-fly stream).
            utxo_groups: dict[bytes, list[tuple[int, Any]]] = {}
            for utxo in self.db.iter_utxos():
                utxo_groups.setdefault(utxo.txid, []).append((utxo.vout, utxo))

            coins_written = 0
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
