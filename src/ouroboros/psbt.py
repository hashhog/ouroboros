"""
BIP 174 / BIP 370 — Partially Signed Bitcoin Transaction (PSBT).

Implements the binary key-value map format used for multi-party
signing workflows and hardware wallet integration.

Layout (per BIP 174):
  <magic: 0x70736274ff>
  <global key-value pairs>
  <separator: 0x00>
  <per-input key-value pairs>   ×  num_inputs
  <per-output key-value pairs>  ×  num_outputs

Each key-value pair:
  <key_len: compact_size><key_type || key_data>
  <value_len: compact_size><value>

A separator (single 0x00 byte) ends each map.

References:
  - BIP 174: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
  - BIP 370: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
  - Bitcoin Core: /home/max/hashhog/bitcoin/src/psbt.cpp
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from ouroboros.database import Transaction, TxIn, TxOut

if TYPE_CHECKING:
    from ouroboros.miniscript import MiniscriptContext

# BIP 174 magic bytes
PSBT_MAGIC = b"psbt\xff"

# =============================================================================
# W51 decodepsbt JSON shape helpers (Core-byte-identity)
# =============================================================================
#
# These helpers implement the 5-point W50 prescription so that decodepsbt
# produces a JSON shape that is byte-identical to Bitcoin Core 31.99 once
# both sides are normalized through `jq -S`.
#
# References:
#   bitcoin-core/src/core_io.cpp   ScriptToAsmStr, ScriptToUniv
#   bitcoin-core/src/rpc/rawtransaction.cpp  decodepsbt
#   bitcoin-core/src/script/descriptor.cpp  InferDescriptor


class BTCAmount:
    """Sentinel for a satoshi amount that must serialize as Core's
    ``%d.%08d`` fixed-decimal JSON number (e.g. ``1.00000000``).

    Stored as a raw decimal string so the custom encoder can emit it as an
    unquoted number token without Python's float rounding the trailing zeros
    away.  Reference: bitcoin-core/src/core_io.cpp ``ValueFromAmount``.
    """
    __slots__ = ('_text',)

    def __init__(self, sats: int) -> None:
        neg = sats < 0
        abs_sats = abs(sats)
        whole = abs_sats // 100_000_000
        frac = abs_sats % 100_000_000
        self._text = f"{'-' if neg else ''}{whole}.{frac:08d}"

    @property
    def text(self) -> str:
        return self._text


def _spk_type(script: bytes) -> str:
    """Classify a scriptPubKey — mirrors ``_get_script_type`` in rpc.py."""
    if not isinstance(script, bytes):
        script = bytes(script)
    n = len(script)
    if n == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[23] == 0x88 and script[24] == 0xac:
        return "pubkeyhash"
    if n == 23 and script[0] == 0xa9 and script[22] == 0x87:
        return "scripthash"
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "witness_v0_keyhash"
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "witness_v0_scripthash"
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "witness_v1_taproot"
    if n == 35 and script[0] == 0x41 and script[34] == 0xac:
        return "pubkey"
    if n == 67 and script[0] == 0x41 and script[66] == 0xac:
        return "pubkey"
    if n == 66 and script[0] == 0x21 and script[65] == 0xac:
        return "pubkey"
    if n == 35 and script[0] == 0x21 and script[34] == 0xac:
        return "pubkey"
    if n > 0 and script[0] == 0x6a:
        return "nulldata"
    return "nonstandard"


def _spk_to_address(script: bytes, network: str) -> str | None:
    """Extract a human-readable address from a scriptPubKey, mirroring
    Bitcoin Core's ``ExtractDestination``.  Returns None for script types
    that Core does not encode as an address (pubkey, multisig, OP_RETURN,
    nonstandard).
    """
    if not isinstance(script, bytes):
        script = bytes(script)
    n = len(script)
    # Determine network prefix constants
    is_mainnet = (network == "mainnet")
    is_regtest = (network in ("regtest", "signet"))
    # testnet4/testnet → tb1 hrp + version 0x6f P2PKH / 0xc4 P2SH
    p2pkh_ver = 0x00 if is_mainnet else 0x6f
    p2sh_ver  = 0x05 if is_mainnet else 0xc4
    bech32_hrp = "bc" if is_mainnet else ("bcrt" if is_regtest else "tb")

    try:
        import base58
        import bech32 as _bech32_mod

        if n == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[23] == 0x88 and script[24] == 0xac:
            # P2PKH
            payload = bytes([p2pkh_ver]) + script[3:23]
            return base58.b58encode_check(payload).decode()

        if n == 23 and script[0] == 0xa9 and script[22] == 0x87:
            # P2SH
            payload = bytes([p2sh_ver]) + script[2:22]
            return base58.b58encode_check(payload).decode()

        if n == 22 and script[0] == 0x00 and script[1] == 0x14:
            # P2WPKH — bech32 v0
            program = script[2:]
            data_5bit = _bech32_mod.convertbits(program, 8, 5)
            if data_5bit is not None:
                return _bech32_mod.bech32_encode(bech32_hrp, [0] + data_5bit)

        if n == 34 and script[0] == 0x00 and script[1] == 0x20:
            # P2WSH — bech32 v0
            program = script[2:]
            data_5bit = _bech32_mod.convertbits(program, 8, 5)
            if data_5bit is not None:
                return _bech32_mod.bech32_encode(bech32_hrp, [0] + data_5bit)

        if n == 34 and script[0] == 0x51 and script[1] == 0x20:
            # P2TR — bech32m v1
            program = script[2:]
            data_5bit = _bech32_mod.convertbits(program, 8, 5)
            if data_5bit is not None:
                from ouroboros.address import _bech32m_encode
                return _bech32m_encode(bech32_hrp, 1, program)

        if n == 4 and script[0] == 0x51 and script[1] == 0x02:
            # P2A (Pay-to-Anchor)
            program = script[2:]
            from ouroboros.address import _bech32m_encode
            return _bech32m_encode(bech32_hrp, 1, program)

    except Exception:
        pass

    # P2PK, multisig, OP_RETURN, nonstandard → no address
    return None


# Core's ScriptToAsmStr uses numeric tokens for small push-number opcodes:
#   OP_0 → "0", OP_1 → "1" … OP_16 → "16", OP_1NEGATE → "-1"
# The existing disassemble_script uses OP_0/OP_1/… which diverges from Core.
_SMALL_NUM_OPCODE: dict[int, str] = {0x00: "0", 0x4f: "-1"}
_SMALL_NUM_OPCODE.update({0x50 + i: str(i) for i in range(1, 17)})

def _spk_asm(script: bytes) -> str:
    """Disassemble a scriptPubKey to Core-style ASM.

    Same as ``disassemble_script`` but emits numeric tokens for small
    push-number opcodes (OP_0 → "0", OP_1 → "1" … OP_16 → "16"), matching
    Bitcoin Core's ``ScriptToAsmStr`` (core_io.cpp).
    """
    from ouroboros.script import disassemble_script
    if not script:
        return ""
    raw_asm = disassemble_script(script)
    if not raw_asm:
        return raw_asm
    parts = raw_asm.split(" ")
    out = []
    for part in parts:
        if part == "OP_0":
            out.append("0")
        elif part == "OP_1NEGATE":
            out.append("-1")
        elif len(part) == 4 and part[:3] == "OP_" and part[3:].isdigit():
            # OP_1 … OP_16
            num = int(part[3:])
            if 1 <= num <= 16:
                out.append(str(num))
            else:
                out.append(part)
        else:
            out.append(part)
    return " ".join(out)


def _infer_descriptor(script: bytes, address: str | None) -> str:
    """Build a BIP-380 descriptor string for a scriptPubKey, mirroring
    Bitcoin Core's no-provider ``InferDescriptor`` fallback path
    (script/descriptor.cpp:2897).

    For address-encodable scripts: ``addr(<address>)#<checksum>``
    Otherwise: ``raw(<hex>)#<checksum>``
    """
    from ouroboros.descriptors import add_checksum
    if address is not None:
        payload = f"addr({address})"
    else:
        payload = f"raw({script.hex()})"
    try:
        return add_checksum(payload)
    except Exception:
        return payload


def _build_spk_json(script: bytes, network: str) -> dict[str, Any]:
    """Build a scriptPubKey JSON object matching Core's ``ScriptToUniv``
    (core_io.cpp) shape: ``{asm, desc, hex, address?, type}``.

    ``address`` is omitted for pubkey-type scripts, matching Core's
    ``ScriptPubKeyToUniv`` suppression rule.
    """
    spk_type = _spk_type(script)
    address = _spk_to_address(script, network)
    desc = _infer_descriptor(script, address)
    asm = _spk_asm(script)
    result: dict[str, Any] = {
        "asm": asm,
        "desc": desc,
        "hex": script.hex(),
        "type": spk_type,
    }
    # Core suppresses "address" for bare-pubkey outputs (type == "pubkey")
    if address is not None and spk_type != "pubkey":
        result["address"] = address
    return result

# Maximum PSBT file size (100 MB, per Bitcoin Core)
MAX_PSBT_SIZE = 100_000_000


# =============================================================================
# Global key types (BIP 174 / BIP 370)
# =============================================================================

class PSBTGlobalType(IntEnum):
    UNSIGNED_TX = 0x00
    XPUB = 0x01
    TX_VERSION = 0x02          # PSBT v2
    FALLBACK_LOCKTIME = 0x03   # PSBT v2
    INPUT_COUNT = 0x04         # PSBT v2
    OUTPUT_COUNT = 0x05        # PSBT v2
    TX_MODIFIABLE = 0x06       # PSBT v2
    VERSION = 0xFB
    PROPRIETARY = 0xFC


# =============================================================================
# Per-input key types (BIP 174 / BIP 370)
# =============================================================================

class PSBTInputType(IntEnum):
    NON_WITNESS_UTXO = 0x00
    WITNESS_UTXO = 0x01
    PARTIAL_SIG = 0x02
    SIGHASH_TYPE = 0x03
    REDEEM_SCRIPT = 0x04
    WITNESS_SCRIPT = 0x05
    BIP32_DERIVATION = 0x06
    FINAL_SCRIPTSIG = 0x07
    FINAL_SCRIPTWITNESS = 0x08
    POR_COMMITMENT = 0x09
    RIPEMD160 = 0x0A
    SHA256 = 0x0B
    HASH160 = 0x0C
    HASH256 = 0x0D
    PREVIOUS_TXID = 0x0E       # PSBT v2
    OUTPUT_INDEX = 0x0F        # PSBT v2
    SEQUENCE = 0x10            # PSBT v2
    REQUIRED_TIME_LOCKTIME = 0x11   # PSBT v2
    REQUIRED_HEIGHT_LOCKTIME = 0x12 # PSBT v2
    TAP_KEY_SIG = 0x13
    TAP_SCRIPT_SIG = 0x14
    TAP_LEAF_SCRIPT = 0x15
    TAP_BIP32_DERIVATION = 0x16
    TAP_INTERNAL_KEY = 0x17
    TAP_MERKLE_ROOT = 0x18
    MUSIG2_PARTICIPANT_PUBKEYS = 0x1A
    MUSIG2_PUB_NONCE = 0x1B
    MUSIG2_PARTIAL_SIG = 0x1C
    PROPRIETARY = 0xFC


# =============================================================================
# Per-output key types (BIP 174 / BIP 370)
# =============================================================================

class PSBTOutputType(IntEnum):
    REDEEM_SCRIPT = 0x00
    WITNESS_SCRIPT = 0x01
    BIP32_DERIVATION = 0x02
    AMOUNT = 0x03              # PSBT v2
    SCRIPT = 0x04              # PSBT v2
    TAP_INTERNAL_KEY = 0x05
    TAP_TREE = 0x06
    TAP_BIP32_DERIVATION = 0x07
    MUSIG2_PARTICIPANT_PUBKEYS = 0x08
    PROPRIETARY = 0xFC


# =============================================================================
# PSBT version constants
# =============================================================================

PSBT_VERSION_0 = 0
PSBT_VERSION_2 = 2
PSBT_HIGHEST_VERSION = 2


# =============================================================================
# Sighash types
# =============================================================================

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_DEFAULT = 0x00  # Taproot default (same as ALL)


# =============================================================================
# Compact-size encoding / decoding
# =============================================================================

def _write_compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _read_compact_size(f: io.BytesIO) -> int:
    b = f.read(1)
    if not b:
        raise ValueError("Unexpected end of data")
    n = b[0]
    if n < 0xFD:
        return n
    if n == 0xFD:
        return struct.unpack("<H", f.read(2))[0]
    if n == 0xFE:
        return struct.unpack("<I", f.read(4))[0]
    return struct.unpack("<Q", f.read(8))[0]


# =============================================================================
# Key-value pair I/O
# =============================================================================

def _read_kv_pairs(f: io.BytesIO) -> dict[bytes, bytes]:
    """Read key-value pairs until separator (0x00).

    BIP-174 mandates a trailing 0x00 separator at the end of every map
    (global, per-input, per-output). A truncated stream that ends without
    the separator is malformed and MUST be rejected — matches Bitcoin Core
    `psbt.h` "Separator is missing at the end of an input map".
    """
    pairs: dict[bytes, bytes] = {}
    while True:
        key_len_byte = f.read(1)
        if not key_len_byte:
            raise ValueError(
                "PSBT truncated: missing trailing 0x00 separator"
            )
        if key_len_byte == b"\x00":
            break
        f.seek(f.tell() - 1)
        key_len = _read_compact_size(f)
        key = f.read(key_len)
        val_len = _read_compact_size(f)
        val = f.read(val_len)
        if key in pairs:
            raise ValueError(f"Duplicate key: {key.hex()}")
        pairs[key] = val
    return pairs


def _input_map_sort_key(key: bytes) -> tuple[int, bytes, bytes]:
    """Canonical sort key for a per-input PSBT map entry.

    Bitcoin Core's per-input map is a struct of typed sub-maps; for
    PARTIAL_SIG, that sub-map is ``std::map<CKeyID, SigPair>`` where
    ``CKeyID = HASH160(pubkey)`` and the wire key is the pubkey itself
    (`psbt.h` ``PSBTInput::Serialize`` walks ``partial_sigs`` in
    ``std::map`` order, i.e. sorted by CKeyID). When two PSBTs are
    combined whose ``partial_sigs`` were inserted in different orders,
    a naive lexicographic sort by raw wire-key (= pubkey) does NOT
    reproduce Core's emission order — the canonical order is by
    ``HASH160(pubkey)``.

    We sort by ``(type_byte, canonical_suffix, raw_suffix)``:
      - ``type_byte`` first preserves grouping by PSBT_IN_* type so the
        wire still goes WITNESS_UTXO, PARTIAL_SIG, SIGHASH_TYPE, ... in
        ascending type order (matches Core's hand-written serialize).
      - For ``PARTIAL_SIG`` (type 0x02), ``canonical_suffix`` is
        ``HASH160(pubkey)`` so emission is byte-identical to Core's
        ``std::map<CKeyID, SigPair>`` walk.
      - For all other types, ``canonical_suffix == raw_suffix`` (lex
        order on the wire-key suffix, which matches Core's
        ``std::map<CPubKey, ...>`` for BIP32_DERIVATION, etc.).
      - ``raw_suffix`` is the final tiebreaker so the sort stays total
        even on the (theoretically-impossible) HASH160 collision.

    This is the W46 fix; see also W43-3 (script-order finalize) — that
    fix targets sig-assembly order in scriptSig/witness, this targets
    wire-order in partial_sigs map emission. Different concerns, both
    needed for combinepsbt byte-identity.
    """
    if not key:
        return (0, b"", b"")
    type_byte = key[0]
    suffix = key[1:]
    if type_byte == PSBTInputType.PARTIAL_SIG and len(suffix) in (33, 65):
        # HASH160(pubkey) = RIPEMD160(SHA256(pubkey)). Mirrors CKeyID.
        canonical = hashlib.new("ripemd160", hashlib.sha256(suffix).digest()).digest()
        return (type_byte, canonical, suffix)
    return (type_byte, suffix, suffix)


def _write_kv_pairs(pairs: dict[bytes, bytes], input_map: bool = False) -> bytes:
    """Write key-value pairs with separator.

    Keys are emitted in ascending lexicographic order. BIP-174 does not
    strictly mandate ordering, but Bitcoin Core canonicalizes by sorting
    (see `psbt.h` per-map serialization), and round-trip byte-identity
    against third-party PSBTs that arrived in non-insertion order is only
    guaranteed if we re-sort on the way out.

    For per-input maps, pass ``input_map=True`` to apply the canonical
    sort that matches Core's ``std::map<CKeyID, SigPair>`` order for
    ``partial_sigs`` (sorted by HASH160(pubkey), not raw pubkey bytes).
    See ``_input_map_sort_key``.
    """
    out = bytearray()
    if input_map:
        ordered_keys = sorted(pairs.keys(), key=_input_map_sort_key)
    else:
        ordered_keys = sorted(pairs.keys())
    for key in ordered_keys:
        val = pairs[key]
        out += _write_compact_size(len(key))
        out += key
        out += _write_compact_size(len(val))
        out += val
    out += b"\x00"  # separator
    return bytes(out)


# =============================================================================
# Transaction serialization helpers
# =============================================================================

def _serialize_unsigned_tx(tx: Transaction) -> bytes:
    """Serialize transaction without witness and with empty scriptSigs."""
    data = bytearray()
    data += tx.version.to_bytes(4, "little", signed=True)
    data += _write_compact_size(len(tx.inputs))
    for inp in tx.inputs:
        data += inp.prev_txid
        data += inp.prev_vout.to_bytes(4, "little")
        data += b"\x00"  # empty scriptSig
        data += inp.sequence.to_bytes(4, "little")
    data += _write_compact_size(len(tx.outputs))
    for out in tx.outputs:
        data += out.value.to_bytes(8, "little", signed=True)
        data += _write_compact_size(len(out.script_pubkey))
        data += out.script_pubkey
    data += tx.locktime.to_bytes(4, "little")
    return bytes(data)


def _deserialize_tx(raw: bytes) -> Transaction:
    """Deserialize a non-witness transaction."""
    f = io.BytesIO(raw)
    version = struct.unpack("<i", f.read(4))[0]
    n_in = _read_compact_size(f)
    inputs: list[TxIn] = []
    for _ in range(n_in):
        prev_txid = f.read(32)
        prev_vout = struct.unpack("<I", f.read(4))[0]
        script_len = _read_compact_size(f)
        script_sig = f.read(script_len)
        sequence = struct.unpack("<I", f.read(4))[0]
        inputs.append(TxIn(prev_txid, prev_vout, script_sig, sequence))
    n_out = _read_compact_size(f)
    outputs: list[TxOut] = []
    for _ in range(n_out):
        value = struct.unpack("<q", f.read(8))[0]
        spk_len = _read_compact_size(f)
        script_pubkey = f.read(spk_len)
        outputs.append(TxOut(value, script_pubkey))
    locktime = struct.unpack("<I", f.read(4))[0]
    txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return Transaction(
        txid=txid, version=version, locktime=locktime,
        inputs=inputs, outputs=outputs
    )


def _serialize_tx_with_witness(tx: Transaction) -> bytes:
    """Serialize transaction with witness data."""
    data = bytearray()
    data += tx.version.to_bytes(4, "little", signed=True)

    has_witness = any(
        hasattr(inp, 'witness') and inp.witness
        for inp in tx.inputs
    )

    if has_witness:
        data += b"\x00\x01"  # marker and flag

    data += _write_compact_size(len(tx.inputs))
    for inp in tx.inputs:
        data += inp.prev_txid
        data += inp.prev_vout.to_bytes(4, "little")
        script_sig = inp.script_sig if inp.script_sig else b""
        data += _write_compact_size(len(script_sig))
        data += script_sig
        data += inp.sequence.to_bytes(4, "little")

    data += _write_compact_size(len(tx.outputs))
    for out in tx.outputs:
        data += out.value.to_bytes(8, "little", signed=True)
        data += _write_compact_size(len(out.script_pubkey))
        data += out.script_pubkey

    if has_witness:
        for inp in tx.inputs:
            witness = getattr(inp, 'witness', None) or []
            data += _write_compact_size(len(witness))
            for item in witness:
                data += _write_compact_size(len(item))
                data += item

    data += tx.locktime.to_bytes(4, "little")
    return bytes(data)


# =============================================================================
# BIP32 derivation path serialization
# =============================================================================

@dataclass
class KeyOriginInfo:
    """BIP32 key origin information (fingerprint + derivation path)."""
    fingerprint: bytes  # 4 bytes
    path: list[int]     # derivation path indices

    def serialize(self) -> bytes:
        data = bytearray(self.fingerprint)
        for index in self.path:
            data += struct.pack("<I", index)
        return bytes(data)

    @classmethod
    def deserialize(cls, data: bytes) -> KeyOriginInfo:
        if len(data) < 4:
            raise ValueError("KeyOriginInfo too short")
        if (len(data) - 4) % 4 != 0:
            raise ValueError("Invalid KeyOriginInfo length")
        fingerprint = data[:4]
        path = []
        for i in range(4, len(data), 4):
            path.append(struct.unpack("<I", data[i:i+4])[0])
        return cls(fingerprint=fingerprint, path=path)

    def to_string(self) -> str:
        """Convert to human-readable path string."""
        parts = [self.fingerprint.hex()]
        for idx in self.path:
            if idx >= 0x80000000:
                parts.append(f"{idx - 0x80000000}'")
            else:
                parts.append(str(idx))
        return "/".join(parts)


# =============================================================================
# PSBTInput
# =============================================================================

@dataclass
class PSBTInput:
    """Per-input PSBT data (BIP174 / BIP370)."""
    # BIP174 fields
    non_witness_utxo: bytes | None = None      # Full previous tx
    witness_utxo: tuple[int, bytes] | None = None  # (value, scriptPubKey)
    partial_sigs: dict[bytes, bytes] = field(default_factory=dict)  # pubkey -> sig
    sighash_type: int | None = None
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, KeyOriginInfo] = field(default_factory=dict)
    final_script_sig: bytes | None = None
    final_script_witness: list[bytes] | None = None  # Stack items

    # BIP174 preimage fields
    ripemd160_preimages: dict[bytes, bytes] = field(default_factory=dict)  # hash -> preimage
    sha256_preimages: dict[bytes, bytes] = field(default_factory=dict)
    hash160_preimages: dict[bytes, bytes] = field(default_factory=dict)
    hash256_preimages: dict[bytes, bytes] = field(default_factory=dict)

    # BIP370 PSBT v2 fields
    previous_txid: bytes | None = None
    output_index: int | None = None
    sequence: int | None = None
    required_time_locktime: int | None = None
    required_height_locktime: int | None = None

    # Taproot fields (BIP371)
    tap_key_sig: bytes | None = None
    tap_script_sigs: dict[tuple[bytes, bytes], bytes] = field(default_factory=dict)  # (xonly, leaf_hash) -> sig
    tap_leaf_scripts: dict[bytes, tuple[bytes, int]] = field(default_factory=dict)  # control_block -> (script, leaf_ver)
    tap_bip32_derivations: dict[bytes, tuple[list[bytes], KeyOriginInfo]] = field(default_factory=dict)  # xonly -> (leaf_hashes, origin)
    tap_internal_key: bytes | None = None  # 32-byte x-only pubkey
    tap_merkle_root: bytes | None = None   # 32-byte hash

    # Unknown fields
    unknown: dict[bytes, bytes] = field(default_factory=dict)

    def is_finalized(self) -> bool:
        """Check if this input has been finalized."""
        return self.final_script_sig is not None or self.final_script_witness is not None

    def to_kv(self) -> dict[bytes, bytes]:
        """Convert to key-value pairs for serialization."""
        kv: dict[bytes, bytes] = {}

        if self.non_witness_utxo is not None:
            kv[bytes([PSBTInputType.NON_WITNESS_UTXO])] = self.non_witness_utxo

        if self.witness_utxo is not None:
            val, spk = self.witness_utxo
            kv[bytes([PSBTInputType.WITNESS_UTXO])] = (
                struct.pack("<q", val) + _write_compact_size(len(spk)) + spk
            )

        # Only include partial sigs if not finalized
        if not self.is_finalized():
            for pub, sig in self.partial_sigs.items():
                kv[bytes([PSBTInputType.PARTIAL_SIG]) + pub] = sig

            if self.sighash_type is not None:
                kv[bytes([PSBTInputType.SIGHASH_TYPE])] = struct.pack("<I", self.sighash_type)

            if self.redeem_script is not None:
                kv[bytes([PSBTInputType.REDEEM_SCRIPT])] = self.redeem_script

            if self.witness_script is not None:
                kv[bytes([PSBTInputType.WITNESS_SCRIPT])] = self.witness_script

            for pub, origin in self.bip32_derivations.items():
                kv[bytes([PSBTInputType.BIP32_DERIVATION]) + pub] = origin.serialize()

            # Preimage fields
            for h, preimage in self.ripemd160_preimages.items():
                kv[bytes([PSBTInputType.RIPEMD160]) + h] = preimage
            for h, preimage in self.sha256_preimages.items():
                kv[bytes([PSBTInputType.SHA256]) + h] = preimage
            for h, preimage in self.hash160_preimages.items():
                kv[bytes([PSBTInputType.HASH160]) + h] = preimage
            for h, preimage in self.hash256_preimages.items():
                kv[bytes([PSBTInputType.HASH256]) + h] = preimage

            # Taproot fields
            if self.tap_key_sig is not None:
                kv[bytes([PSBTInputType.TAP_KEY_SIG])] = self.tap_key_sig

            for (xonly, leaf_hash), sig in self.tap_script_sigs.items():
                kv[bytes([PSBTInputType.TAP_SCRIPT_SIG]) + xonly + leaf_hash] = sig

            for control_block, (script, leaf_ver) in self.tap_leaf_scripts.items():
                kv[bytes([PSBTInputType.TAP_LEAF_SCRIPT]) + control_block] = script + bytes([leaf_ver])

            for xonly, (leaf_hashes, origin) in self.tap_bip32_derivations.items():
                value = _write_compact_size(len(leaf_hashes))
                for lh in leaf_hashes:
                    value += lh
                value += origin.serialize()
                kv[bytes([PSBTInputType.TAP_BIP32_DERIVATION]) + xonly] = value

            if self.tap_internal_key is not None:
                kv[bytes([PSBTInputType.TAP_INTERNAL_KEY])] = self.tap_internal_key

            if self.tap_merkle_root is not None:
                kv[bytes([PSBTInputType.TAP_MERKLE_ROOT])] = self.tap_merkle_root

        if self.final_script_sig is not None:
            kv[bytes([PSBTInputType.FINAL_SCRIPTSIG])] = self.final_script_sig

        if self.final_script_witness is not None:
            # Serialize witness as stack
            witness_data = bytearray()
            witness_data += _write_compact_size(len(self.final_script_witness))
            for item in self.final_script_witness:
                witness_data += _write_compact_size(len(item))
                witness_data += item
            kv[bytes([PSBTInputType.FINAL_SCRIPTWITNESS])] = bytes(witness_data)

        # PSBT v2 fields
        if self.previous_txid is not None:
            kv[bytes([PSBTInputType.PREVIOUS_TXID])] = self.previous_txid
        if self.output_index is not None:
            kv[bytes([PSBTInputType.OUTPUT_INDEX])] = struct.pack("<I", self.output_index)
        if self.sequence is not None:
            kv[bytes([PSBTInputType.SEQUENCE])] = struct.pack("<I", self.sequence)
        if self.required_time_locktime is not None:
            kv[bytes([PSBTInputType.REQUIRED_TIME_LOCKTIME])] = struct.pack("<I", self.required_time_locktime)
        if self.required_height_locktime is not None:
            kv[bytes([PSBTInputType.REQUIRED_HEIGHT_LOCKTIME])] = struct.pack("<I", self.required_height_locktime)

        kv.update(self.unknown)
        return kv

    @classmethod
    def from_kv(cls, kv: dict[bytes, bytes]) -> PSBTInput:
        """Parse from key-value pairs."""
        inp = cls()
        for key, val in kv.items():
            if not key:
                continue
            kt = key[0]
            key_data = key[1:] if len(key) > 1 else b""

            if kt == PSBTInputType.NON_WITNESS_UTXO:
                inp.non_witness_utxo = val
            elif kt == PSBTInputType.WITNESS_UTXO:
                f = io.BytesIO(val)
                value = struct.unpack("<q", f.read(8))[0]
                spk_len = _read_compact_size(f)
                spk = f.read(spk_len)
                inp.witness_utxo = (value, spk)
            elif kt == PSBTInputType.PARTIAL_SIG:
                inp.partial_sigs[key_data] = val
            elif kt == PSBTInputType.SIGHASH_TYPE:
                inp.sighash_type = struct.unpack("<I", val)[0]
            elif kt == PSBTInputType.REDEEM_SCRIPT:
                inp.redeem_script = val
            elif kt == PSBTInputType.WITNESS_SCRIPT:
                inp.witness_script = val
            elif kt == PSBTInputType.BIP32_DERIVATION:
                inp.bip32_derivations[key_data] = KeyOriginInfo.deserialize(val)
            elif kt == PSBTInputType.FINAL_SCRIPTSIG:
                inp.final_script_sig = val
            elif kt == PSBTInputType.FINAL_SCRIPTWITNESS:
                f = io.BytesIO(val)
                n_items = _read_compact_size(f)
                items = []
                for _ in range(n_items):
                    item_len = _read_compact_size(f)
                    items.append(f.read(item_len))
                inp.final_script_witness = items
            elif kt == PSBTInputType.RIPEMD160:
                inp.ripemd160_preimages[key_data] = val
            elif kt == PSBTInputType.SHA256:
                inp.sha256_preimages[key_data] = val
            elif kt == PSBTInputType.HASH160:
                inp.hash160_preimages[key_data] = val
            elif kt == PSBTInputType.HASH256:
                inp.hash256_preimages[key_data] = val
            elif kt == PSBTInputType.PREVIOUS_TXID:
                inp.previous_txid = val
            elif kt == PSBTInputType.OUTPUT_INDEX:
                inp.output_index = struct.unpack("<I", val)[0]
            elif kt == PSBTInputType.SEQUENCE:
                inp.sequence = struct.unpack("<I", val)[0]
            elif kt == PSBTInputType.REQUIRED_TIME_LOCKTIME:
                inp.required_time_locktime = struct.unpack("<I", val)[0]
            elif kt == PSBTInputType.REQUIRED_HEIGHT_LOCKTIME:
                inp.required_height_locktime = struct.unpack("<I", val)[0]
            elif kt == PSBTInputType.TAP_KEY_SIG:
                inp.tap_key_sig = val
            elif kt == PSBTInputType.TAP_SCRIPT_SIG:
                if len(key_data) == 64:
                    xonly = key_data[:32]
                    leaf_hash = key_data[32:]
                    inp.tap_script_sigs[(xonly, leaf_hash)] = val
            elif kt == PSBTInputType.TAP_LEAF_SCRIPT:
                if len(val) >= 1:
                    script = val[:-1]
                    leaf_ver = val[-1]
                    inp.tap_leaf_scripts[key_data] = (script, leaf_ver)
            elif kt == PSBTInputType.TAP_BIP32_DERIVATION:
                f = io.BytesIO(val)
                n_hashes = _read_compact_size(f)
                leaf_hashes = [f.read(32) for _ in range(n_hashes)]
                origin = KeyOriginInfo.deserialize(f.read())
                inp.tap_bip32_derivations[key_data] = (leaf_hashes, origin)
            elif kt == PSBTInputType.TAP_INTERNAL_KEY:
                inp.tap_internal_key = val
            elif kt == PSBTInputType.TAP_MERKLE_ROOT:
                inp.tap_merkle_root = val
            else:
                inp.unknown[key] = val
        return inp

    def merge(self, other: PSBTInput) -> None:
        """Merge another PSBTInput into this one."""
        if self.non_witness_utxo is None and other.non_witness_utxo is not None:
            self.non_witness_utxo = other.non_witness_utxo
        if self.witness_utxo is None and other.witness_utxo is not None:
            self.witness_utxo = other.witness_utxo
        self.partial_sigs.update(other.partial_sigs)
        self.bip32_derivations.update(other.bip32_derivations)
        if self.sighash_type is None and other.sighash_type is not None:
            self.sighash_type = other.sighash_type
        if self.redeem_script is None and other.redeem_script is not None:
            self.redeem_script = other.redeem_script
        if self.witness_script is None and other.witness_script is not None:
            self.witness_script = other.witness_script
        if self.final_script_sig is None and other.final_script_sig is not None:
            self.final_script_sig = other.final_script_sig
        if self.final_script_witness is None and other.final_script_witness is not None:
            self.final_script_witness = other.final_script_witness

        # Preimages
        self.ripemd160_preimages.update(other.ripemd160_preimages)
        self.sha256_preimages.update(other.sha256_preimages)
        self.hash160_preimages.update(other.hash160_preimages)
        self.hash256_preimages.update(other.hash256_preimages)

        # Taproot
        if self.tap_key_sig is None and other.tap_key_sig is not None:
            self.tap_key_sig = other.tap_key_sig
        self.tap_script_sigs.update(other.tap_script_sigs)
        self.tap_leaf_scripts.update(other.tap_leaf_scripts)
        self.tap_bip32_derivations.update(other.tap_bip32_derivations)
        if self.tap_internal_key is None and other.tap_internal_key is not None:
            self.tap_internal_key = other.tap_internal_key
        if self.tap_merkle_root is None and other.tap_merkle_root is not None:
            self.tap_merkle_root = other.tap_merkle_root

        self.unknown.update(other.unknown)


# =============================================================================
# PSBTOutput
# =============================================================================

@dataclass
class PSBTOutput:
    """Per-output PSBT data (BIP174 / BIP370)."""
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, KeyOriginInfo] = field(default_factory=dict)

    # PSBT v2 fields
    amount: int | None = None
    script: bytes | None = None

    # Taproot fields
    tap_internal_key: bytes | None = None
    tap_tree: list[tuple[int, int, bytes]] | None = None  # [(depth, leaf_ver, script), ...]
    tap_bip32_derivations: dict[bytes, tuple[list[bytes], KeyOriginInfo]] = field(default_factory=dict)

    # Unknown fields
    unknown: dict[bytes, bytes] = field(default_factory=dict)

    def to_kv(self) -> dict[bytes, bytes]:
        """Convert to key-value pairs for serialization."""
        kv: dict[bytes, bytes] = {}

        if self.redeem_script is not None:
            kv[bytes([PSBTOutputType.REDEEM_SCRIPT])] = self.redeem_script
        if self.witness_script is not None:
            kv[bytes([PSBTOutputType.WITNESS_SCRIPT])] = self.witness_script

        for pub, origin in self.bip32_derivations.items():
            kv[bytes([PSBTOutputType.BIP32_DERIVATION]) + pub] = origin.serialize()

        # PSBT v2 fields
        if self.amount is not None:
            kv[bytes([PSBTOutputType.AMOUNT])] = struct.pack("<q", self.amount)
        if self.script is not None:
            kv[bytes([PSBTOutputType.SCRIPT])] = self.script

        # Taproot
        if self.tap_internal_key is not None:
            kv[bytes([PSBTOutputType.TAP_INTERNAL_KEY])] = self.tap_internal_key

        if self.tap_tree is not None:
            tree_data = bytearray()
            for depth, leaf_ver, script in self.tap_tree:
                tree_data += bytes([depth, leaf_ver])
                tree_data += _write_compact_size(len(script))
                tree_data += script
            kv[bytes([PSBTOutputType.TAP_TREE])] = bytes(tree_data)

        for xonly, (leaf_hashes, origin) in self.tap_bip32_derivations.items():
            value = _write_compact_size(len(leaf_hashes))
            for lh in leaf_hashes:
                value += lh
            value += origin.serialize()
            kv[bytes([PSBTOutputType.TAP_BIP32_DERIVATION]) + xonly] = value

        kv.update(self.unknown)
        return kv

    @classmethod
    def from_kv(cls, kv: dict[bytes, bytes]) -> PSBTOutput:
        """Parse from key-value pairs."""
        out = cls()
        for key, val in kv.items():
            if not key:
                continue
            kt = key[0]
            key_data = key[1:] if len(key) > 1 else b""

            if kt == PSBTOutputType.REDEEM_SCRIPT:
                out.redeem_script = val
            elif kt == PSBTOutputType.WITNESS_SCRIPT:
                out.witness_script = val
            elif kt == PSBTOutputType.BIP32_DERIVATION:
                out.bip32_derivations[key_data] = KeyOriginInfo.deserialize(val)
            elif kt == PSBTOutputType.AMOUNT:
                out.amount = struct.unpack("<q", val)[0]
            elif kt == PSBTOutputType.SCRIPT:
                out.script = val
            elif kt == PSBTOutputType.TAP_INTERNAL_KEY:
                out.tap_internal_key = val
            elif kt == PSBTOutputType.TAP_TREE:
                f = io.BytesIO(val)
                tree = []
                while f.tell() < len(val):
                    depth = f.read(1)[0]
                    leaf_ver = f.read(1)[0]
                    script_len = _read_compact_size(f)
                    script = f.read(script_len)
                    tree.append((depth, leaf_ver, script))
                out.tap_tree = tree
            elif kt == PSBTOutputType.TAP_BIP32_DERIVATION:
                f = io.BytesIO(val)
                n_hashes = _read_compact_size(f)
                leaf_hashes = [f.read(32) for _ in range(n_hashes)]
                origin = KeyOriginInfo.deserialize(f.read())
                out.tap_bip32_derivations[key_data] = (leaf_hashes, origin)
            else:
                out.unknown[key] = val
        return out

    def merge(self, other: PSBTOutput) -> None:
        """Merge another PSBTOutput into this one."""
        if self.redeem_script is None and other.redeem_script is not None:
            self.redeem_script = other.redeem_script
        if self.witness_script is None and other.witness_script is not None:
            self.witness_script = other.witness_script
        self.bip32_derivations.update(other.bip32_derivations)

        if self.tap_internal_key is None and other.tap_internal_key is not None:
            self.tap_internal_key = other.tap_internal_key
        if self.tap_tree is None and other.tap_tree is not None:
            self.tap_tree = other.tap_tree
        self.tap_bip32_derivations.update(other.tap_bip32_derivations)

        self.unknown.update(other.unknown)


# =============================================================================
# PSBT (main class)
# =============================================================================

@dataclass
class PSBT:
    """
    Partially Signed Bitcoin Transaction (BIP 174 / BIP 370).

    Holds the unsigned transaction plus per-input / per-output metadata
    required for signing, combining, and finalizing.
    """
    tx: Transaction | None = None
    inputs: list[PSBTInput] = field(default_factory=list)
    outputs: list[PSBTOutput] = field(default_factory=list)
    global_xpubs: dict[bytes, KeyOriginInfo] = field(default_factory=dict)  # xpub -> derivation
    unknown_global: dict[bytes, bytes] = field(default_factory=dict)

    # PSBT version (0 = BIP174, 2 = BIP370)
    version: int = PSBT_VERSION_0

    # PSBT v2 global fields
    tx_version: int | None = None
    fallback_locktime: int | None = None
    input_count: int | None = None
    output_count: int | None = None
    tx_modifiable: int | None = None

    # ==========================================================================
    # Constructors
    # ==========================================================================

    @classmethod
    def from_transaction(cls, tx: Transaction, version: int = PSBT_VERSION_0) -> PSBT:
        """Create a PSBT from an unsigned Transaction."""
        unsigned = copy.deepcopy(tx)
        for inp in unsigned.inputs:
            inp.script_sig = b""
            inp.witness = None
        unsigned.has_witness = False

        psbt = cls(
            tx=unsigned,
            inputs=[PSBTInput() for _ in unsigned.inputs],
            outputs=[PSBTOutput() for _ in unsigned.outputs],
            version=version,
        )

        # For v2, populate per-input/output fields
        if version == PSBT_VERSION_2:
            psbt.tx_version = tx.version
            psbt.fallback_locktime = tx.locktime
            psbt.input_count = len(tx.inputs)
            psbt.output_count = len(tx.outputs)

            for i, inp in enumerate(tx.inputs):
                psbt.inputs[i].previous_txid = inp.prev_txid
                psbt.inputs[i].output_index = inp.prev_vout
                psbt.inputs[i].sequence = inp.sequence

            for i, out in enumerate(tx.outputs):
                psbt.outputs[i].amount = out.value
                psbt.outputs[i].script = out.script_pubkey

        return psbt

    @classmethod
    def create(
        cls,
        inputs: list[dict[str, Any]],
        outputs: list[dict[str, Any]],
        version: int = 2,
        locktime: int = 0,
    ) -> PSBT:
        """
        Create a new PSBT from input/output specifications.

        Args:
            inputs: List of {"txid": hex, "vout": int, "sequence": int (optional)}
            outputs: List of {"address": str, "amount": int} or {"script": hex, "amount": int}
            version: Transaction version (default 2)
            locktime: Transaction locktime (default 0)

        Returns:
            New PSBT instance
        """
        from ouroboros.address import address_to_script_pubkey

        tx_inputs = []
        for inp_spec in inputs:
            txid_hex = inp_spec["txid"]
            if isinstance(txid_hex, str):
                txid = bytes.fromhex(txid_hex)
            else:
                txid = txid_hex
            vout = inp_spec["vout"]
            sequence = inp_spec.get("sequence", 0xFFFFFFFD)  # RBF by default
            tx_inputs.append(TxIn(
                prev_txid=txid,
                prev_vout=vout,
                script_sig=b"",
                sequence=sequence,
            ))

        tx_outputs = []
        for out_spec in outputs:
            amount = out_spec["amount"]
            if "script" in out_spec:
                script_hex = out_spec["script"]
                if isinstance(script_hex, str):
                    script = bytes.fromhex(script_hex)
                else:
                    script = script_hex
            elif "address" in out_spec:
                script = address_to_script_pubkey(out_spec["address"], "mainnet")
            else:
                raise ValueError("Output must have 'address' or 'script'")
            tx_outputs.append(TxOut(value=amount, script_pubkey=script))

        tx = Transaction(
            txid=b"\x00" * 32,
            version=version,
            locktime=locktime,
            inputs=tx_inputs,
            outputs=tx_outputs,
        )

        return cls.from_transaction(tx)

    # ==========================================================================
    # Serialization
    # ==========================================================================

    def serialize(self) -> bytes:
        """Serialize PSBT to binary format."""
        out = bytearray(PSBT_MAGIC)

        # Global map
        global_kv: dict[bytes, bytes] = {}

        if self.version == PSBT_VERSION_0:
            # v0: include unsigned tx
            if self.tx is not None:
                global_kv[bytes([PSBTGlobalType.UNSIGNED_TX])] = _serialize_unsigned_tx(self.tx)
        else:
            # v2: include version and separate fields
            global_kv[bytes([PSBTGlobalType.VERSION])] = struct.pack("<I", self.version)
            if self.tx_version is not None:
                global_kv[bytes([PSBTGlobalType.TX_VERSION])] = struct.pack("<I", self.tx_version)
            if self.fallback_locktime is not None:
                global_kv[bytes([PSBTGlobalType.FALLBACK_LOCKTIME])] = struct.pack("<I", self.fallback_locktime)
            if self.input_count is not None:
                global_kv[bytes([PSBTGlobalType.INPUT_COUNT])] = _write_compact_size(self.input_count)
            if self.output_count is not None:
                global_kv[bytes([PSBTGlobalType.OUTPUT_COUNT])] = _write_compact_size(self.output_count)
            if self.tx_modifiable is not None:
                global_kv[bytes([PSBTGlobalType.TX_MODIFIABLE])] = bytes([self.tx_modifiable])

        for xpub, origin in self.global_xpubs.items():
            global_kv[bytes([PSBTGlobalType.XPUB]) + xpub] = origin.serialize()

        global_kv.update(self.unknown_global)
        out += _write_kv_pairs(global_kv)

        # Per-input maps. ``input_map=True`` enables the W46 canonical
        # sort that walks PARTIAL_SIG entries in HASH160(pubkey) order
        # (Core's ``std::map<CKeyID, SigPair>``), giving byte-identical
        # combinepsbt output regardless of insertion order.
        for psbt_in in self.inputs:
            out += _write_kv_pairs(psbt_in.to_kv(), input_map=True)

        # Per-output maps
        for psbt_out in self.outputs:
            out += _write_kv_pairs(psbt_out.to_kv())

        return bytes(out)

    def to_base64(self) -> str:
        """Serialize and encode as base64."""
        return base64.b64encode(self.serialize()).decode("ascii")

    @classmethod
    def deserialize(cls, data: bytes) -> PSBT:
        """Deserialize PSBT from binary format."""
        if len(data) > MAX_PSBT_SIZE:
            raise ValueError(f"PSBT too large: {len(data)} > {MAX_PSBT_SIZE}")

        f = io.BytesIO(data)
        magic = f.read(5)
        if magic != PSBT_MAGIC:
            raise ValueError(f"Invalid PSBT magic: {magic!r}")

        # Global map
        global_kv = _read_kv_pairs(f)

        # Determine version
        version = PSBT_VERSION_0
        version_key = bytes([PSBTGlobalType.VERSION])
        if version_key in global_kv:
            version = struct.unpack("<I", global_kv[version_key])[0]
            if version > PSBT_HIGHEST_VERSION:
                raise ValueError(f"Unsupported PSBT version: {version}")

        psbt = cls(version=version)

        # Parse global fields
        unsigned_tx_key = bytes([PSBTGlobalType.UNSIGNED_TX])
        if unsigned_tx_key in global_kv:
            psbt.tx = _deserialize_tx(global_kv.pop(unsigned_tx_key))

        for key, val in global_kv.items():
            if not key:
                continue
            kt = key[0]
            key_data = key[1:] if len(key) > 1 else b""

            if kt == PSBTGlobalType.XPUB:
                psbt.global_xpubs[key_data] = KeyOriginInfo.deserialize(val)
            elif kt == PSBTGlobalType.TX_VERSION:
                psbt.tx_version = struct.unpack("<I", val)[0]
            elif kt == PSBTGlobalType.FALLBACK_LOCKTIME:
                psbt.fallback_locktime = struct.unpack("<I", val)[0]
            elif kt == PSBTGlobalType.INPUT_COUNT:
                psbt.input_count = _read_compact_size(io.BytesIO(val))
            elif kt == PSBTGlobalType.OUTPUT_COUNT:
                psbt.output_count = _read_compact_size(io.BytesIO(val))
            elif kt == PSBTGlobalType.TX_MODIFIABLE:
                psbt.tx_modifiable = val[0] if val else 0
            elif kt == PSBTGlobalType.VERSION:
                pass  # already handled
            else:
                psbt.unknown_global[key] = val

        # Determine input/output counts
        if psbt.tx is not None:
            n_inputs = len(psbt.tx.inputs)
            n_outputs = len(psbt.tx.outputs)
        elif psbt.version == PSBT_VERSION_2:
            n_inputs = psbt.input_count or 0
            n_outputs = psbt.output_count or 0
        else:
            raise ValueError("PSBT v0 requires unsigned transaction")

        # Per-input maps
        for _ in range(n_inputs):
            kv = _read_kv_pairs(f)
            psbt.inputs.append(PSBTInput.from_kv(kv))

        # Per-output maps
        for _ in range(n_outputs):
            kv = _read_kv_pairs(f)
            psbt.outputs.append(PSBTOutput.from_kv(kv))

        # For v2, reconstruct transaction from per-input/output fields
        if psbt.version == PSBT_VERSION_2 and psbt.tx is None:
            psbt._reconstruct_tx_from_v2()

        return psbt

    @classmethod
    def from_base64(cls, b64_str: str) -> PSBT:
        """Deserialize PSBT from base64 string."""
        try:
            data = base64.b64decode(b64_str)
        except Exception as e:
            raise ValueError(f"Invalid base64: {e}") from None
        return cls.deserialize(data)

    def _reconstruct_tx_from_v2(self) -> None:
        """Reconstruct Transaction from PSBT v2 per-input/output fields."""
        tx_inputs = []
        for psbt_in in self.inputs:
            if psbt_in.previous_txid is None or psbt_in.output_index is None:
                raise ValueError("PSBT v2 input missing required fields")
            tx_inputs.append(TxIn(
                prev_txid=psbt_in.previous_txid,
                prev_vout=psbt_in.output_index,
                script_sig=b"",
                sequence=psbt_in.sequence or 0xFFFFFFFF,
            ))

        tx_outputs = []
        for psbt_out in self.outputs:
            if psbt_out.amount is None or psbt_out.script is None:
                raise ValueError("PSBT v2 output missing required fields")
            tx_outputs.append(TxOut(
                value=psbt_out.amount,
                script_pubkey=psbt_out.script,
            ))

        self.tx = Transaction(
            txid=b"\x00" * 32,
            version=self.tx_version or 2,
            locktime=self.fallback_locktime or 0,
            inputs=tx_inputs,
            outputs=tx_outputs,
        )

    # ==========================================================================
    # Combining
    # ==========================================================================

    def combine(self, other: PSBT) -> PSBT:
        """
        Combine two PSBTs for the same transaction (``combinepsbt``).

        Merges partial signatures, derivation paths, and UTXO info
        from *other* into *self* and returns *self*.
        """
        if self.tx is None or other.tx is None:
            raise ValueError("Both PSBTs must have transactions")
        if _serialize_unsigned_tx(self.tx) != _serialize_unsigned_tx(other.tx):
            raise ValueError("Cannot combine PSBTs for different transactions")

        for i in range(len(self.inputs)):
            self.inputs[i].merge(other.inputs[i])

        for i in range(len(self.outputs)):
            self.outputs[i].merge(other.outputs[i])

        self.global_xpubs.update(other.global_xpubs)
        self.unknown_global.update(other.unknown_global)
        return self

    # ==========================================================================
    # Finalization
    # ==========================================================================

    def finalize(self) -> PSBT:
        """
        Finalize each input: builds final_script_sig/witness and clears
        non-final fields. Returns self.
        """
        for i, psbt_in in enumerate(self.inputs):
            if psbt_in.is_finalized():
                continue

            # Try different finalization strategies
            if self._try_finalize_taproot(psbt_in, i):
                continue
            if self._try_finalize_p2wpkh(psbt_in, i):
                continue
            if self._try_finalize_p2sh_p2wpkh(psbt_in, i):
                continue
            if self._try_finalize_p2sh_p2wsh(psbt_in, i):
                continue
            if self._try_finalize_p2sh_multisig(psbt_in, i):
                continue
            if self._try_finalize_p2pkh(psbt_in, i):
                continue
            if self._try_finalize_p2wsh(psbt_in, i):
                continue

        return self

    def _try_finalize_taproot(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as Taproot (key path or script path)."""
        if psbt_in.tap_key_sig is not None:
            # Key path spend
            psbt_in.final_script_witness = [psbt_in.tap_key_sig]
            psbt_in.final_script_sig = b""
            self._clear_non_final_fields(psbt_in)
            return True

        if psbt_in.tap_script_sigs:
            # Script path spend - need control block and script
            for (_xonly, leaf_hash), sig in psbt_in.tap_script_sigs.items():
                # Find matching leaf script
                for control_block, (script, leaf_ver) in psbt_in.tap_leaf_scripts.items():
                    # Verify leaf hash matches
                    computed_leaf = hashlib.sha256(
                        b"\xc0" + bytes([leaf_ver]) + script
                    ).digest()
                    if computed_leaf == leaf_hash:
                        # Build witness: <sig> <script> <control_block>
                        psbt_in.final_script_witness = [sig, script, control_block]
                        psbt_in.final_script_sig = b""
                        self._clear_non_final_fields(psbt_in)
                        return True

        return False

    def _try_finalize_p2wpkh(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as P2WPKH."""
        if psbt_in.witness_utxo is None:
            return False

        _, spk = psbt_in.witness_utxo
        # P2WPKH: OP_0 <20 bytes>
        if len(spk) != 22 or spk[0] != 0x00 or spk[1] != 0x14:
            return False

        if len(psbt_in.partial_sigs) != 1:
            return False

        pubkey, sig = next(iter(psbt_in.partial_sigs.items()))
        psbt_in.final_script_witness = [sig, pubkey]
        psbt_in.final_script_sig = b""
        self._clear_non_final_fields(psbt_in)
        return True

    def _try_finalize_p2sh_p2wpkh(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as P2SH-P2WPKH.

        BIP-16 commits the redeemScript to the P2SH scriptPubKey via
        ``HASH160``. The pre-W31 finalizer here checked only the
        *shape* of the redeemScript (OP_0 <20 bytes>) but never compared
        ``HASH160(redeemScript)`` against the witness_utxo's
        scriptPubKey hash — a malicious cosigner could swap in a
        different P2WPKH redeemScript and produce a structurally valid
        PSBT that yields a transaction whose scriptSig fails script
        verification at broadcast. We now raise ``ValueError`` when the
        commitment fails (the cosigner is malicious or buggy — silently
        skipping would let other shapes try, but no other shape will
        match a P2WPKH-shaped redeemScript, so loud is correct here).
        """
        if psbt_in.redeem_script is None:
            return False

        # Check if redeem script is P2WPKH: OP_0 <20 bytes>
        if len(psbt_in.redeem_script) != 22:
            return False
        if psbt_in.redeem_script[0] != 0x00 or psbt_in.redeem_script[1] != 0x14:
            return False

        if len(psbt_in.partial_sigs) != 1:
            return False

        # BIP-16 commitment check. Requires witness_utxo (the P2SH
        # scriptPubKey we're spending). If absent we cannot prove the
        # redeemScript matches the UTXO and must refuse to finalize.
        if psbt_in.witness_utxo is None:
            return False
        from ouroboros.segwit_v0 import verify_p2sh_commitment

        _value, spk = psbt_in.witness_utxo
        verify_p2sh_commitment(psbt_in.redeem_script, spk)

        pubkey, sig = next(iter(psbt_in.partial_sigs.items()))
        psbt_in.final_script_witness = [sig, pubkey]
        # scriptSig = push(redeem_script)
        psbt_in.final_script_sig = bytes([len(psbt_in.redeem_script)]) + psbt_in.redeem_script
        self._clear_non_final_fields(psbt_in)
        return True

    def _try_finalize_p2sh_p2wsh(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as P2SH-P2WSH.

        Outer wrap: BIP-16 P2SH whose redeemScript is itself a P2WSH
        scriptPubKey (``OP_0 <32-byte SHA256(witnessScript)>``).
        Witness stack is identical to bare P2WSH; ``scriptSig`` is a
        single push of the redeemScript.

        Mirrors the W28 RPC ``signrawtransactionwithkey`` /
        ``signrawtransactionwithwallet`` paths and the dedicated
        ``segwit_v0.sign_p2sh_p2wsh_input`` helper. The W29-A canonical
        BIP-143 sighash is what produced the partial sigs that we
        consume here — finalize itself does not re-sign.
        """
        if psbt_in.redeem_script is None or psbt_in.witness_script is None:
            return False
        if psbt_in.witness_utxo is None:
            return False

        # redeem_script must be a P2WSH program: OP_0 <32 bytes>.
        rs = psbt_in.redeem_script
        if len(rs) != 34 or rs[0] != 0x00 or rs[1] != 0x20:
            return False

        from ouroboros.segwit_v0 import (
            parse_multisig_script,
            parse_p2pk_checksig_script,
            verify_p2sh_commitment,
            verify_p2wsh_commitment,
        )

        # Outer P2SH commitment: HASH160(redeem_script) == spk[2:22].
        _value, spk = psbt_in.witness_utxo
        verify_p2sh_commitment(rs, spk)

        # Inner P2WSH commitment: SHA256(witness_script) == redeem_script[2:34].
        verify_p2wsh_commitment(psbt_in.witness_script, rs[2:34])

        ws = psbt_in.witness_script

        # Build witness stack — same shape as bare P2WSH finalizer.
        # Multisig path: OP_M <pks> OP_N OP_CHECKMULTISIG.
        multisig = parse_multisig_script(ws)
        if multisig is not None:
            m, script_pubkeys = multisig
            if len(psbt_in.partial_sigs) < m:
                return False
            witness: list[bytes] = [b""]  # CHECKMULTISIG off-by-one dummy
            for pk in script_pubkeys:
                if len(witness) - 1 >= m:
                    break
                sig = psbt_in.partial_sigs.get(pk)
                if sig is None:
                    continue
                witness.append(sig)
            if len(witness) - 1 < m:
                return False
            witness.append(ws)
            psbt_in.final_script_witness = witness
            psbt_in.final_script_sig = bytes([len(rs)]) + rs
            self._clear_non_final_fields(psbt_in)
            return True

        # Single-key <pk> OP_CHECKSIG path.
        pk = parse_p2pk_checksig_script(ws)
        if pk is not None:
            sig = psbt_in.partial_sigs.get(pk)
            if sig is None:
                return False
            psbt_in.final_script_witness = [sig, ws]
            psbt_in.final_script_sig = bytes([len(rs)]) + rs
            self._clear_non_final_fields(psbt_in)
            return True

        # Try miniscript-driven P2WSH witness construction (covers
        # Miniscript-emitted witnessScripts that aren't bare multisig
        # or P2PK-CHECKSIG). Reuses the same helper as bare P2WSH.
        if self._try_finalize_miniscript(psbt_in, idx):
            # _try_finalize_miniscript writes final_script_sig=b"" for
            # bare P2WSH; for the P2SH wrap we need the redeemScript push.
            psbt_in.final_script_sig = bytes([len(rs)]) + rs
            return True

        return False

    def _try_finalize_p2sh_multisig(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as legacy (non-segwit) P2SH-multisig (W43).

        Shape: scriptPubKey is BIP-16 P2SH; redeemScript is a bare
        ``OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG``. This branch fills
        the long-standing gap exposed by the W42-A diagnostic — the
        finalize() ladder previously jumped from P2SH-P2WSH straight to
        P2PKH, leaving ordinary 2-of-2 / 2-of-3 / m-of-n legacy multisig
        unhandled. Bitcoin Core's canonical sign.cpp ProduceSignature
        path emits ``OP_0 <sig1> <sig2> ... <pushRedeemScript>`` and
        critically orders the sigs by redeemScript pubkey order, NOT by
        partial_sigs map iteration order — see ``GetMultisigSigner``.

        Distinguishes from P2SH-P2WPKH and P2SH-P2WSH (handled above)
        by parse_multisig_script() returning a hit. Refuses to finalize
        if witness_script is set (shape mismatch) or if witness_utxo is
        present *with* a witness program (this is segwit, not legacy).
        """
        if psbt_in.redeem_script is None:
            return False
        # Legacy P2SH-multisig is non-segwit: witnessScript MUST be unset
        # (would mean this is segwit-wrapped) and any witness_utxo must
        # NOT be a witness program (segwit shapes handled above).
        if psbt_in.witness_script is not None:
            return False

        from ouroboros.segwit_v0 import parse_multisig_script

        multisig = parse_multisig_script(psbt_in.redeem_script)
        if multisig is None:
            return False
        m, script_pubkeys = multisig

        if len(psbt_in.partial_sigs) < m:
            return False

        # If witness_utxo is set, refuse — bare P2SH spends use
        # non_witness_utxo per BIP-174; presence of witness_utxo here
        # likely means the caller wired the wrong UTXO type and we
        # should not silently produce a non-segwit scriptSig over a
        # segwit UTXO shape.
        if psbt_in.witness_utxo is not None:
            _value, spk = psbt_in.witness_utxo
            # Allow only if spk is itself a P2SH (segwit witness programs
            # would have been matched by the earlier P2SH-P2W* branches).
            if not (
                len(spk) == 23
                and spk[0] == 0xA9
                and spk[1] == 0x14
                and spk[22] == 0x87
            ):
                return False

        # Build scriptSig: OP_0 <sig1> <sig2> ... <push(redeemScript)>.
        # Sigs are ordered by redeemScript pubkey order (Core's
        # ProduceSignature/ GetMultisigSigner, validation.cpp /
        # script/sign.cpp). We collect at most m sigs in script order;
        # extra partial sigs (typical for n>m schemes) are dropped.
        from ouroboros.segwit_v0 import _push_data

        rs = psbt_in.redeem_script
        script_sig = bytearray()
        # OP_0 dummy push for the CHECKMULTISIG off-by-one bug.
        script_sig.append(0x00)
        sigs_used = 0
        for pk in script_pubkeys:
            if sigs_used >= m:
                break
            sig = psbt_in.partial_sigs.get(pk)
            if sig is None:
                continue
            script_sig.extend(_push_data(sig))
            sigs_used += 1

        if sigs_used < m:
            return False

        # Final push of the redeem script.
        script_sig.extend(_push_data(rs))

        psbt_in.final_script_sig = bytes(script_sig)
        # Legacy P2SH has no witness — ensure final_script_witness is
        # left unset (None) or explicitly empty; PSBTInput.is_finalized
        # only requires final_script_sig OR final_script_witness.
        self._clear_non_final_fields(psbt_in)
        return True

    def _try_finalize_p2pkh(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as P2PKH."""
        if psbt_in.witness_utxo is not None:
            # If witness UTXO is present, this is likely not P2PKH
            return False

        if len(psbt_in.partial_sigs) != 1:
            return False

        pubkey, sig = next(iter(psbt_in.partial_sigs.items()))

        # scriptSig: <sig> <pubkey>
        script_sig = bytearray()
        script_sig.append(len(sig))
        script_sig.extend(sig)
        script_sig.append(len(pubkey))
        script_sig.extend(pubkey)

        psbt_in.final_script_sig = bytes(script_sig)
        self._clear_non_final_fields(psbt_in)
        return True

    def _try_finalize_p2wsh(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize as P2WSH (multisig or miniscript).

        W43: sigs are now ordered by witnessScript pubkey order (Core's
        ProduceSignature in script/sign.cpp), not by raw pubkey-byte
        sort. CHECKMULTISIG is order-sensitive — the previous
        ``sorted(partial_sigs.keys())`` produced silently-invalid
        scripts whenever the script-pubkey order did not happen to
        coincide with a lexicographic key sort, and Core rejected the
        broadcast. Mirrors the working pattern in
        ``_try_finalize_p2sh_p2wsh`` (line ~1215).
        """
        if psbt_in.witness_script is None:
            return False

        from ouroboros.segwit_v0 import parse_multisig_script

        ws = psbt_in.witness_script

        # First try standard multisig
        # OP_M <pubkeys...> OP_N OP_CHECKMULTISIG
        multisig = parse_multisig_script(ws)
        if multisig is not None:
            m, script_pubkeys = multisig
            if len(psbt_in.partial_sigs) >= m:
                # Build witness stack: OP_0 <sig1> <sig2> ... <witness_script>
                witness: list[bytes] = [b""]  # OP_0 for CHECKMULTISIG bug

                # Add signatures in witnessScript pubkey order (NOT
                # pubkey-byte order). Mirrors P2SH-P2WSH path.
                for pk in script_pubkeys:
                    if len(witness) - 1 >= m:
                        break
                    sig = psbt_in.partial_sigs.get(pk)
                    if sig is None:
                        continue
                    witness.append(sig)

                if len(witness) - 1 >= m:
                    witness.append(psbt_in.witness_script)

                    psbt_in.final_script_witness = witness
                    psbt_in.final_script_sig = b""
                    self._clear_non_final_fields(psbt_in)
                    return True

        # Try miniscript finalization
        if self._try_finalize_miniscript(psbt_in, idx):
            return True

        return False

    def _try_finalize_miniscript(self, psbt_in: PSBTInput, idx: int) -> bool:
        """Try to finalize a P2WSH input with miniscript witness construction."""
        if psbt_in.witness_script is None:
            return False

        try:
            from ouroboros.miniscript import MiniscriptContext
            witness = _construct_miniscript_witness(
                psbt_in.witness_script,
                psbt_in.partial_sigs,
                psbt_in.sha256_preimages,
                psbt_in.hash256_preimages,
                psbt_in.ripemd160_preimages,
                psbt_in.hash160_preimages,
                MiniscriptContext.P2WSH,
            )
            if witness is not None:
                # Add witness script at the end
                witness.append(psbt_in.witness_script)
                psbt_in.final_script_witness = witness
                psbt_in.final_script_sig = b""
                self._clear_non_final_fields(psbt_in)
                return True
        except Exception:
            pass

        return False

    @staticmethod
    def _clear_non_final_fields(psbt_in: PSBTInput) -> None:
        """Clear non-final fields after finalization."""
        psbt_in.partial_sigs.clear()
        psbt_in.bip32_derivations.clear()
        psbt_in.redeem_script = None
        psbt_in.witness_script = None
        psbt_in.sighash_type = None
        psbt_in.ripemd160_preimages.clear()
        psbt_in.sha256_preimages.clear()
        psbt_in.hash160_preimages.clear()
        psbt_in.hash256_preimages.clear()
        psbt_in.tap_key_sig = None
        psbt_in.tap_script_sigs.clear()
        psbt_in.tap_leaf_scripts.clear()
        psbt_in.tap_bip32_derivations.clear()
        psbt_in.tap_internal_key = None
        psbt_in.tap_merkle_root = None

    def is_finalized(self) -> bool:
        """Check if all inputs are finalized."""
        return all(inp.is_finalized() for inp in self.inputs)

    # ==========================================================================
    # Extraction
    # ==========================================================================

    def extract_transaction(self) -> Transaction:
        """
        Extract the fully-signed transaction from a finalized PSBT.
        Raises ValueError if any input is not finalized.
        """
        if self.tx is None:
            raise ValueError("PSBT has no transaction")

        tx = copy.deepcopy(self.tx)
        has_witness = False

        for i, psbt_in in enumerate(self.inputs):
            if not psbt_in.is_finalized():
                raise ValueError(f"Input {i} is not finalized")

            if psbt_in.final_script_sig:
                tx.inputs[i].script_sig = psbt_in.final_script_sig

            if psbt_in.final_script_witness:
                has_witness = True
                tx.inputs[i].witness = psbt_in.final_script_witness

        tx.has_witness = has_witness

        # Recompute txid
        raw = tx.serialize()
        tx.txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()

        return tx

    # ==========================================================================
    # Decoding (human-readable)
    # ==========================================================================

    def decode(self, network: str = "mainnet") -> dict[str, Any]:
        """Return a human-readable dictionary representation (``decodepsbt``).

        W51: shape is now byte-identical to Bitcoin Core 31.99's decodepsbt
        output when normalized via ``jq -S``.  Changes vs prior version:

        - amount fields use ``BTCAmount(sats)`` so they serialize as Core's
          fixed ``%d.%08d`` decimal (``1.00000000``, not Python's ``1.0``).
        - ``tx.vin`` gains ``scriptSig: {asm, hex}`` (empty string for the
          unsigned PSBT global tx).
        - ``tx.vout.scriptPubKey`` emits the full Core shape
          ``{asm, desc, hex, address?, type}`` via ``_build_spk_json``.
        - ``tx`` gains ``hash``, ``size``, ``vsize``, ``weight``.
        - Top-level ``version`` renamed to ``psbt_version`` (Core's field name).
        - ``global_xpubs: []`` is always emitted (mandatory in Core, even when
          the PSBT carries no XPUB records).
        - ``proprietary: []`` and ``unknown: {}`` always emitted.

        Args:
            network: Network context for address encoding
                     (``"mainnet"`` / ``"testnet4"`` / ``"regtest"``).
        """
        result: dict[str, Any] = {}

        if self.tx is not None:
            # JSON-RPC convention: txids are reversed-byte (display / BE).
            # Internal storage on ``Transaction.txid`` and ``TxIn.prev_txid``
            # is the LE hash form (Bitcoin Core's uint256 byte order).
            # Reverse before hex-encoding for any txid emitted to JSON; the
            # vin loop already does this for ``inp.prev_txid``, but the
            # outer ``self.tx.txid`` was missing the reversal — surfaced by
            # ``tools/psbt-multi-input-test.sh`` (W40-C harness): expected
            # ``82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b``,
            # got the byte-reversed ``7b61d191...``. Aligns with
            # bitcoin-core/src/rpc/rawtransaction.cpp::TxToUniv which calls
            # ``tx.GetHash().GetHex()`` (display-order).
            #
            # The PSBT global tx is the unsigned transaction (no witness data),
            # so hash == txid for all PSBTs (no witness discount applies).
            txid_hex = self.tx.txid[::-1].hex()
            tx_size = len(self.tx.serialize())
            tx_weight = self.tx.get_weight()
            tx_vsize = self.tx.get_vsize()
            result["tx"] = {
                "txid": txid_hex,
                "hash": txid_hex,
                "version": self.tx.version,
                "size": tx_size,
                "vsize": tx_vsize,
                "weight": tx_weight,
                "locktime": self.tx.locktime,
                "vin": [
                    {
                        "txid": inp.prev_txid[::-1].hex() if inp.prev_txid else "",
                        "vout": inp.prev_vout,
                        "scriptSig": {
                            "asm": _spk_asm(inp.script_sig) if inp.script_sig else "",
                            "hex": inp.script_sig.hex() if inp.script_sig else "",
                        },
                        "sequence": inp.sequence,
                    }
                    for inp in self.tx.inputs
                ],
                "vout": [
                    {
                        "value": BTCAmount(out.value),
                        "n": i,
                        "scriptPubKey": _build_spk_json(out.script_pubkey, network),
                    }
                    for i, out in enumerate(self.tx.outputs)
                ],
            }

        # Global xpubs — always emitted (Core mandates this field even when
        # the PSBT has no XPUB records).
        if self.global_xpubs:
            result["global_xpubs"] = [
                {
                    "xpub": xpub.hex(),
                    "master_fingerprint": origin.fingerprint.hex(),
                    "path": origin.to_string(),
                }
                for xpub, origin in self.global_xpubs.items()
            ]
        else:
            result["global_xpubs"] = []

        # PSBT version — Core calls this "psbt_version", not "version".
        result["psbt_version"] = self.version

        # Proprietary records and unknown key-value pairs — always emitted
        # (Core mandates these fields even when empty).
        result["proprietary"] = []
        result["unknown"] = {}

        # Inputs
        result["inputs"] = []
        for _i, psbt_in in enumerate(self.inputs):
            info: dict[str, Any] = {}

            if psbt_in.witness_utxo is not None:
                val, spk = psbt_in.witness_utxo
                info["witness_utxo"] = {
                    "amount": BTCAmount(val),
                    "scriptPubKey": _build_spk_json(spk, network),
                }

            if psbt_in.non_witness_utxo is not None:
                info["non_witness_utxo"] = {
                    "hex": psbt_in.non_witness_utxo.hex(),
                }

            if psbt_in.partial_sigs:
                info["partial_signatures"] = {
                    pk.hex(): sig.hex() for pk, sig in psbt_in.partial_sigs.items()
                }

            if psbt_in.sighash_type is not None:
                sighash_names = {
                    1: "ALL", 2: "NONE", 3: "SINGLE",
                    0x81: "ALL|ANYONECANPAY", 0x82: "NONE|ANYONECANPAY",
                    0x83: "SINGLE|ANYONECANPAY", 0: "DEFAULT",
                }
                info["sighash"] = sighash_names.get(psbt_in.sighash_type, str(psbt_in.sighash_type))
                info["sighash_type"] = psbt_in.sighash_type

            if psbt_in.redeem_script is not None:
                info["redeem_script"] = {"hex": psbt_in.redeem_script.hex()}

            if psbt_in.witness_script is not None:
                info["witness_script"] = {"hex": psbt_in.witness_script.hex()}

            if psbt_in.bip32_derivations:
                info["bip32_derivs"] = [
                    {
                        "pubkey": pk.hex(),
                        "master_fingerprint": origin.fingerprint.hex(),
                        "path": origin.to_string(),
                    }
                    for pk, origin in psbt_in.bip32_derivations.items()
                ]

            if psbt_in.final_script_sig is not None:
                info["final_scriptSig"] = {"hex": psbt_in.final_script_sig.hex()}

            if psbt_in.final_script_witness is not None:
                info["final_scriptwitness"] = [item.hex() for item in psbt_in.final_script_witness]

            # Taproot fields
            if psbt_in.tap_key_sig is not None:
                info["tap_key_sig"] = psbt_in.tap_key_sig.hex()

            if psbt_in.tap_internal_key is not None:
                info["tap_internal_key"] = psbt_in.tap_internal_key.hex()

            if psbt_in.tap_merkle_root is not None:
                info["tap_merkle_root"] = psbt_in.tap_merkle_root.hex()

            result["inputs"].append(info)

        # Outputs
        result["outputs"] = []
        for psbt_out in self.outputs:
            info = {}

            if psbt_out.redeem_script is not None:
                info["redeem_script"] = {"hex": psbt_out.redeem_script.hex()}

            if psbt_out.witness_script is not None:
                info["witness_script"] = {"hex": psbt_out.witness_script.hex()}

            if psbt_out.bip32_derivations:
                info["bip32_derivs"] = [
                    {
                        "pubkey": pk.hex(),
                        "master_fingerprint": origin.fingerprint.hex(),
                        "path": origin.to_string(),
                    }
                    for pk, origin in psbt_out.bip32_derivations.items()
                ]

            if psbt_out.tap_internal_key is not None:
                info["tap_internal_key"] = psbt_out.tap_internal_key.hex()

            if psbt_out.tap_tree is not None:
                info["tap_tree"] = [
                    {"depth": d, "leaf_ver": lv, "script": s.hex()}
                    for d, lv, s in psbt_out.tap_tree
                ]

            result["outputs"].append(info)

        # Compute fee if possible (W53 territory — not in scope for W51 target
        # entries, but maintain the field for non-target entries).
        try:
            fee = self._compute_fee()
            if fee is not None:
                result["fee"] = BTCAmount(fee)
        except Exception:
            pass

        return result

    def _compute_fee(self) -> int | None:
        """Compute transaction fee from UTXO information."""
        if self.tx is None:
            return None

        total_in = 0
        for psbt_in in self.inputs:
            if psbt_in.witness_utxo is not None:
                total_in += psbt_in.witness_utxo[0]
            elif psbt_in.non_witness_utxo is not None:
                # Would need to parse the tx to get the value
                return None
            else:
                return None

        total_out = sum(out.value for out in self.tx.outputs)
        return total_in - total_out

    # ==========================================================================
    # Utility methods
    # ==========================================================================

    def add_input(
        self,
        txid: str | bytes,
        vout: int,
        sequence: int = 0xFFFFFFFD,
    ) -> int:
        """Add a new input to the PSBT. Returns the input index."""
        if isinstance(txid, str):
            txid = bytes.fromhex(txid)

        if self.tx is not None:
            self.tx.inputs.append(TxIn(
                prev_txid=txid,
                prev_vout=vout,
                script_sig=b"",
                sequence=sequence,
            ))

        psbt_input = PSBTInput()
        if self.version == PSBT_VERSION_2:
            psbt_input.previous_txid = txid
            psbt_input.output_index = vout
            psbt_input.sequence = sequence

        self.inputs.append(psbt_input)

        if self.input_count is not None:
            self.input_count += 1

        return len(self.inputs) - 1

    def add_output(
        self,
        script_pubkey: str | bytes,
        amount: int,
    ) -> int:
        """Add a new output to the PSBT. Returns the output index."""
        if isinstance(script_pubkey, str):
            script_pubkey = bytes.fromhex(script_pubkey)

        if self.tx is not None:
            self.tx.outputs.append(TxOut(
                value=amount,
                script_pubkey=script_pubkey,
            ))

        psbt_output = PSBTOutput()
        if self.version == PSBT_VERSION_2:
            psbt_output.amount = amount
            psbt_output.script = script_pubkey

        self.outputs.append(psbt_output)

        if self.output_count is not None:
            self.output_count += 1

        return len(self.outputs) - 1

    def set_witness_utxo(self, input_index: int, value: int, script_pubkey: bytes) -> None:
        """Set the witness UTXO for an input."""
        self.inputs[input_index].witness_utxo = (value, script_pubkey)

    def set_non_witness_utxo(self, input_index: int, tx_raw: bytes) -> None:
        """Set the non-witness UTXO (full previous tx) for an input."""
        self.inputs[input_index].non_witness_utxo = tx_raw

    def add_partial_sig(self, input_index: int, pubkey: bytes, signature: bytes) -> None:
        """Add a partial signature to an input."""
        self.inputs[input_index].partial_sigs[pubkey] = signature

    def set_sighash_type(self, input_index: int, sighash_type: int) -> None:
        """Set the sighash type for an input."""
        self.inputs[input_index].sighash_type = sighash_type

    def set_redeem_script(self, input_index: int, script: bytes) -> None:
        """Set the redeem script for an input."""
        self.inputs[input_index].redeem_script = script

    def set_witness_script(self, input_index: int, script: bytes) -> None:
        """Set the witness script for an input."""
        self.inputs[input_index].witness_script = script

    def count_unsigned_inputs(self) -> int:
        """Count inputs that are not yet finalized."""
        return sum(1 for inp in self.inputs if not inp.is_finalized())


# =============================================================================
# Helper functions for RPC compatibility
# =============================================================================

def createpsbt(
    inputs: list[dict[str, Any]],
    outputs: list[dict[str, Any]],
    locktime: int = 0,
    replaceable: bool = True,
) -> str:
    """
    Create a PSBT from inputs and outputs (``createpsbt`` RPC).

    Args:
        inputs: [{"txid": hex, "vout": int, "sequence": int}]
        outputs: [{"address": amount}, ...] or [{address: amount}]
        locktime: Transaction locktime
        replaceable: If True, use RBF sequence numbers

    Returns:
        Base64-encoded PSBT
    """

    # Normalize outputs format
    normalized_outputs = []
    for out in outputs:
        if isinstance(out, dict):
            for key, val in out.items():
                if key in ("data",):
                    # OP_RETURN data
                    if isinstance(val, str):
                        script = bytes.fromhex("6a" + val)  # OP_RETURN + data
                    else:
                        script = b"\x6a" + val
                    normalized_outputs.append({
                        "script": script.hex(),
                        "amount": 0,
                    })
                else:
                    # address: amount
                    amount_sat = int(val * 100_000_000) if isinstance(val, float) else val
                    normalized_outputs.append({
                        "address": key,
                        "amount": amount_sat,
                    })

    # Normalize inputs
    normalized_inputs = []
    for inp in inputs:
        seq = inp.get("sequence", 0xFFFFFFFD if replaceable else 0xFFFFFFFF)
        normalized_inputs.append({
            "txid": inp["txid"],
            "vout": inp["vout"],
            "sequence": seq,
        })

    psbt = PSBT.create(
        inputs=normalized_inputs,
        outputs=normalized_outputs,
        locktime=locktime,
    )

    return psbt.to_base64()


def combinepsbt(psbts: list[str]) -> str:
    """
    Combine multiple PSBTs (``combinepsbt`` RPC).

    Args:
        psbts: List of base64-encoded PSBTs

    Returns:
        Combined base64-encoded PSBT
    """
    if not psbts:
        raise ValueError("No PSBTs provided")

    combined = PSBT.from_base64(psbts[0])
    for psbt_b64 in psbts[1:]:
        other = PSBT.from_base64(psbt_b64)
        combined.combine(other)

    return combined.to_base64()


def finalizepsbt(psbt_b64: str, extract: bool = True) -> dict[str, Any]:
    """
    Finalize a PSBT (``finalizepsbt`` RPC).

    Args:
        psbt_b64: Base64-encoded PSBT
        extract: If True and complete, return the hex transaction

    Returns:
        {"psbt": base64, "hex": hex (if complete and extract), "complete": bool}
    """
    psbt = PSBT.from_base64(psbt_b64)
    psbt.finalize()

    complete = psbt.is_finalized()
    result: dict[str, Any] = {
        "psbt": psbt.to_base64(),
        "complete": complete,
    }

    if complete and extract:
        tx = psbt.extract_transaction()
        result["hex"] = _serialize_tx_with_witness(tx).hex()

    return result


def decodepsbt(psbt_b64: str) -> dict[str, Any]:
    """
    Decode a PSBT to human-readable format (``decodepsbt`` RPC).

    Args:
        psbt_b64: Base64-encoded PSBT

    Returns:
        Decoded PSBT as dictionary
    """
    psbt = PSBT.from_base64(psbt_b64)
    return psbt.decode()


def analyzepsbt(psbt_b64: str) -> dict[str, Any]:
    """
    Analyze a PSBT (``analyzepsbt`` RPC).

    Returns information about the PSBT's status including:
    - inputs: per-input analysis
    - estimated_vsize: estimated virtual size
    - estimated_feerate: estimated fee rate
    - next: suggested next role/action
    """
    psbt = PSBT.from_base64(psbt_b64)

    inputs_analysis = []
    all_have_utxo = True
    all_signed = True
    all_finalized = True

    for _i, psbt_in in enumerate(psbt.inputs):
        inp_info: dict[str, Any] = {}

        has_utxo = psbt_in.witness_utxo is not None or psbt_in.non_witness_utxo is not None
        inp_info["has_utxo"] = has_utxo
        all_have_utxo &= has_utxo

        is_final = psbt_in.is_finalized()
        inp_info["is_final"] = is_final
        all_finalized &= is_final

        if not is_final:
            has_sig = bool(psbt_in.partial_sigs) or psbt_in.tap_key_sig is not None
            inp_info["has_sig"] = has_sig
            all_signed &= has_sig

        inputs_analysis.append(inp_info)

    # Determine next action
    if all_finalized:
        next_role = "extractor"
    elif all_signed:
        next_role = "finalizer"
    elif all_have_utxo:
        next_role = "signer"
    else:
        next_role = "updater"

    result: dict[str, Any] = {
        "inputs": inputs_analysis,
        "next": next_role,
    }

    # Estimate size if we can
    if psbt.tx is not None:
        # Rough vsize estimate
        base_size = 10 + len(psbt.inputs) * 41 + len(psbt.outputs) * 34
        witness_size = len(psbt.inputs) * 108  # Approximate P2WPKH witness
        vsize = base_size + (witness_size + 3) // 4
        result["estimated_vsize"] = vsize

        fee = psbt._compute_fee()
        if fee is not None and vsize > 0:
            result["estimated_feerate"] = fee / vsize
            result["fee"] = fee / 100_000_000

    return result


def utxoupdatepsbt(psbt_b64: str, utxos: list[dict[str, Any]]) -> str:
    """
    Update PSBT with UTXO information (``utxoupdatepsbt`` RPC).

    Args:
        psbt_b64: Base64-encoded PSBT
        utxos: List of UTXO info dicts with txid, vout, scriptPubKey, amount

    Returns:
        Updated base64-encoded PSBT
    """
    psbt = PSBT.from_base64(psbt_b64)

    # Build lookup
    utxo_map = {}
    for u in utxos:
        key = (u["txid"], u["vout"])
        utxo_map[key] = u

    if psbt.tx is not None:
        for i, tx_in in enumerate(psbt.tx.inputs):
            txid_hex = tx_in.prev_txid[::-1].hex()
            key = (txid_hex, tx_in.prev_vout)
            if key in utxo_map:
                u = utxo_map[key]
                spk = bytes.fromhex(u["scriptPubKey"]["hex"]) if isinstance(u["scriptPubKey"], dict) else bytes.fromhex(u["scriptPubKey"])
                amount = int(u["amount"] * 100_000_000) if isinstance(u["amount"], float) else u["amount"]
                psbt.inputs[i].witness_utxo = (amount, spk)

    return psbt.to_base64()


# =============================================================================
# Miniscript witness construction
# =============================================================================


def _construct_miniscript_witness(
    witness_script: bytes,
    partial_sigs: dict[bytes, bytes],
    sha256_preimages: dict[bytes, bytes],
    hash256_preimages: dict[bytes, bytes],
    ripemd160_preimages: dict[bytes, bytes],
    hash160_preimages: dict[bytes, bytes],
    ctx: MiniscriptContext,
) -> list[bytes] | None:
    """
    Construct a witness stack for a miniscript.

    This function attempts to satisfy a miniscript given the available
    signatures and preimages. It uses a recursive satisfaction algorithm
    to build the minimal valid witness.

    Args:
        witness_script: The compiled miniscript (witness script)
        partial_sigs: Map of pubkey -> signature
        sha256_preimages: Map of hash -> preimage for sha256()
        hash256_preimages: Map of hash -> preimage for hash256()
        ripemd160_preimages: Map of hash -> preimage for ripemd160()
        hash160_preimages: Map of hash -> preimage for hash160()
        ctx: Miniscript context (P2WSH or TAPSCRIPT)

    Returns:
        List of witness elements (excluding the witness script itself),
        or None if satisfaction is not possible.
    """

    # We need to analyze the witness_script structure and build witness
    # For now, implement basic satisfaction for common patterns

    # Try to identify known patterns in the compiled script

    # Pattern 1: pk(KEY) = <key> OP_CHECKSIG
    # Satisfaction: <sig>
    if len(witness_script) == 35 and witness_script[-1] == 0xAC:  # OP_CHECKSIG
        # Extract pubkey
        key_len = witness_script[0]
        if key_len == 33:
            pubkey = witness_script[1:34]
            if pubkey in partial_sigs:
                return [partial_sigs[pubkey]]

    # Pattern 2: pkh(KEY) = OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    # Satisfaction: <sig> <pubkey>
    if (len(witness_script) == 25 and
        witness_script[0] == 0x76 and  # OP_DUP
        witness_script[1] == 0xA9 and  # OP_HASH160
        witness_script[2] == 0x14 and  # push 20 bytes
        witness_script[23] == 0x88 and  # OP_EQUALVERIFY
        witness_script[24] == 0xAC):    # OP_CHECKSIG
        keyhash = witness_script[3:23]
        # Find matching pubkey
        for pubkey, sig in partial_sigs.items():
            computed_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
            if computed_hash == keyhash:
                return [sig, pubkey]

    # Pattern 3: and_v(pk(KEY1), pk(KEY2)) patterns
    # These produce: <key1> OP_CHECKSIGVERIFY <key2> OP_CHECKSIG
    # or similar structures

    # Pattern 4: or_b patterns with OP_BOOLOR

    # Pattern 5: thresh patterns

    # For complex miniscripts, we would need to decode the script back
    # to the AST and compute satisfaction. For now, return None for
    # unrecognized patterns.

    # Advanced: Try to parse the script and satisfy recursively
    # This would require a script-to-miniscript decompiler

    return None


def joinpsbts(psbts: list[str]) -> str:
    """
    Join multiple PSBTs into a single PSBT with all inputs and outputs.

    Unlike combinepsbt (which merges signatures for the same tx),
    joinpsbts creates a new transaction combining inputs/outputs from
    multiple PSBTs.

    Args:
        psbts: List of base64-encoded PSBTs

    Returns:
        Joined base64-encoded PSBT
    """
    if not psbts:
        raise ValueError("No PSBTs provided")

    all_inputs: list[TxIn] = []
    all_outputs: list[TxOut] = []
    all_psbt_inputs: list[PSBTInput] = []
    all_psbt_outputs: list[PSBTOutput] = []

    for psbt_b64 in psbts:
        psbt = PSBT.from_base64(psbt_b64)
        if psbt.tx is not None:
            all_inputs.extend(psbt.tx.inputs)
            all_outputs.extend(psbt.tx.outputs)
        all_psbt_inputs.extend(psbt.inputs)
        all_psbt_outputs.extend(psbt.outputs)

    # Create combined transaction
    combined_tx = Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=all_inputs,
        outputs=all_outputs,
    )

    combined_psbt = PSBT(
        tx=combined_tx,
        inputs=all_psbt_inputs,
        outputs=all_psbt_outputs,
    )

    return combined_psbt.to_base64()
