"""
BIP 174 — Partially Signed Bitcoin Transaction (PSBT).

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

Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

import copy
import hashlib
import io
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ouroboros.database import Transaction, TxIn, TxOut

# ── BIP 174 magic ────────────────────────────────────────────────────

PSBT_MAGIC = b"psbt\xff"

# ── Global key types ─────────────────────────────────────────────────

PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_VERSION = 0xFB

# ── Per-input key types ──────────────────────────────────────────────

PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08

# ── Per-output key types ─────────────────────────────────────────────

PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02


# ── compact-size encoding / decoding ─────────────────────────────────

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


# ── key-value pair I/O ───────────────────────────────────────────────

def _read_kv_pairs(f: io.BytesIO) -> Dict[bytes, bytes]:
    """Read key-value pairs until the 0x00 separator."""
    pairs: Dict[bytes, bytes] = {}
    while True:
        key_len_byte = f.read(1)
        if not key_len_byte or key_len_byte == b"\x00":
            break
        f.seek(f.tell() - 1)
        key_len = _read_compact_size(f)
        key = f.read(key_len)
        val_len = _read_compact_size(f)
        val = f.read(val_len)
        pairs[key] = val
    return pairs


def _write_kv_pairs(pairs: Dict[bytes, bytes]) -> bytes:
    out = bytearray()
    for key, val in pairs.items():
        out += _write_compact_size(len(key))
        out += key
        out += _write_compact_size(len(val))
        out += val
    out += b"\x00"
    return bytes(out)


# ── Helper: serialise unsigned tx (no witness, no scriptSig) ─────────

def _serialize_unsigned_tx(tx: Transaction) -> bytes:
    """Serialise the unsigned transaction (BIP 174 global field)."""
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
    """Minimal tx deserialiser (non-witness only, for PSBT global)."""
    f = io.BytesIO(raw)
    version = struct.unpack("<i", f.read(4))[0]
    n_in = _read_compact_size(f)
    inputs: List[TxIn] = []
    for _ in range(n_in):
        prev_txid = f.read(32)
        prev_vout = struct.unpack("<I", f.read(4))[0]
        script_len = _read_compact_size(f)
        script_sig = f.read(script_len)
        sequence = struct.unpack("<I", f.read(4))[0]
        inputs.append(TxIn(prev_txid, prev_vout, script_sig, sequence))
    n_out = _read_compact_size(f)
    outputs: List[TxOut] = []
    for _ in range(n_out):
        value = struct.unpack("<q", f.read(8))[0]
        spk_len = _read_compact_size(f)
        script_pubkey = f.read(spk_len)
        outputs.append(TxOut(value, script_pubkey))
    locktime = struct.unpack("<I", f.read(4))[0]
    txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return Transaction(txid=txid, version=version, locktime=locktime,
                       inputs=inputs, outputs=outputs)


# ── PSBTInput / PSBTOutput ───────────────────────────────────────────

@dataclass
class PSBTInput:
    """Per-input PSBT data."""
    non_witness_utxo: Optional[bytes] = None      # raw tx bytes
    witness_utxo: Optional[Tuple[int, bytes]] = None  # (value, scriptPubKey)
    partial_sigs: Dict[bytes, bytes] = field(default_factory=dict)  # pubkey -> sig
    sighash_type: Optional[int] = None
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, bytes] = field(default_factory=dict)  # pubkey -> derivation
    final_script_sig: Optional[bytes] = None
    final_script_witness: Optional[bytes] = None
    unknown: Dict[bytes, bytes] = field(default_factory=dict)

    def to_kv(self) -> Dict[bytes, bytes]:
        kv: Dict[bytes, bytes] = {}
        if self.non_witness_utxo is not None:
            kv[bytes([PSBT_IN_NON_WITNESS_UTXO])] = self.non_witness_utxo
        if self.witness_utxo is not None:
            val, spk = self.witness_utxo
            kv[bytes([PSBT_IN_WITNESS_UTXO])] = (
                struct.pack("<q", val) + _write_compact_size(len(spk)) + spk
            )
        for pub, sig in self.partial_sigs.items():
            kv[bytes([PSBT_IN_PARTIAL_SIG]) + pub] = sig
        if self.sighash_type is not None:
            kv[bytes([PSBT_IN_SIGHASH_TYPE])] = struct.pack("<I", self.sighash_type)
        if self.redeem_script is not None:
            kv[bytes([PSBT_IN_REDEEM_SCRIPT])] = self.redeem_script
        if self.witness_script is not None:
            kv[bytes([PSBT_IN_WITNESS_SCRIPT])] = self.witness_script
        for pub, drv in self.bip32_derivations.items():
            kv[bytes([PSBT_IN_BIP32_DERIVATION]) + pub] = drv
        if self.final_script_sig is not None:
            kv[bytes([PSBT_IN_FINAL_SCRIPTSIG])] = self.final_script_sig
        if self.final_script_witness is not None:
            kv[bytes([PSBT_IN_FINAL_SCRIPTWITNESS])] = self.final_script_witness
        kv.update(self.unknown)
        return kv

    @classmethod
    def from_kv(cls, kv: Dict[bytes, bytes]) -> "PSBTInput":
        inp = cls()
        for key, val in kv.items():
            kt = key[0]
            if kt == PSBT_IN_NON_WITNESS_UTXO:
                inp.non_witness_utxo = val
            elif kt == PSBT_IN_WITNESS_UTXO:
                f = io.BytesIO(val)
                value = struct.unpack("<q", f.read(8))[0]
                spk_len = _read_compact_size(f)
                spk = f.read(spk_len)
                inp.witness_utxo = (value, spk)
            elif kt == PSBT_IN_PARTIAL_SIG:
                inp.partial_sigs[key[1:]] = val
            elif kt == PSBT_IN_SIGHASH_TYPE:
                inp.sighash_type = struct.unpack("<I", val)[0]
            elif kt == PSBT_IN_REDEEM_SCRIPT:
                inp.redeem_script = val
            elif kt == PSBT_IN_WITNESS_SCRIPT:
                inp.witness_script = val
            elif kt == PSBT_IN_BIP32_DERIVATION:
                inp.bip32_derivations[key[1:]] = val
            elif kt == PSBT_IN_FINAL_SCRIPTSIG:
                inp.final_script_sig = val
            elif kt == PSBT_IN_FINAL_SCRIPTWITNESS:
                inp.final_script_witness = val
            else:
                inp.unknown[key] = val
        return inp


@dataclass
class PSBTOutput:
    """Per-output PSBT data."""
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, bytes] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(default_factory=dict)

    def to_kv(self) -> Dict[bytes, bytes]:
        kv: Dict[bytes, bytes] = {}
        if self.redeem_script is not None:
            kv[bytes([PSBT_OUT_REDEEM_SCRIPT])] = self.redeem_script
        if self.witness_script is not None:
            kv[bytes([PSBT_OUT_WITNESS_SCRIPT])] = self.witness_script
        for pub, drv in self.bip32_derivations.items():
            kv[bytes([PSBT_OUT_BIP32_DERIVATION]) + pub] = drv
        kv.update(self.unknown)
        return kv

    @classmethod
    def from_kv(cls, kv: Dict[bytes, bytes]) -> "PSBTOutput":
        out = cls()
        for key, val in kv.items():
            kt = key[0]
            if kt == PSBT_OUT_REDEEM_SCRIPT:
                out.redeem_script = val
            elif kt == PSBT_OUT_WITNESS_SCRIPT:
                out.witness_script = val
            elif kt == PSBT_OUT_BIP32_DERIVATION:
                out.bip32_derivations[key[1:]] = val
            else:
                out.unknown[key] = val
        return out


# ── PSBT ─────────────────────────────────────────────────────────────

@dataclass
class PSBT:
    """
    A Partially Signed Bitcoin Transaction (BIP 174).

    Holds the unsigned transaction plus per-input / per-output metadata
    required for signing, combining, and finalising.
    """
    tx: Transaction
    inputs: List[PSBTInput] = field(default_factory=list)
    outputs: List[PSBTOutput] = field(default_factory=list)
    global_xpubs: Dict[bytes, bytes] = field(default_factory=dict)
    unknown_global: Dict[bytes, bytes] = field(default_factory=dict)

    # ── constructors ──────────────────────────────────────────────

    @classmethod
    def from_transaction(cls, tx: Transaction) -> "PSBT":
        """Create a PSBT from an unsigned Transaction."""
        unsigned = copy.deepcopy(tx)
        for inp in unsigned.inputs:
            inp.script_sig = b""
            inp.witness = None
        unsigned.has_witness = False
        return cls(
            tx=unsigned,
            inputs=[PSBTInput() for _ in unsigned.inputs],
            outputs=[PSBTOutput() for _ in unsigned.outputs],
        )

    # ── binary serialisation (BIP 174) ────────────────────────────

    def serialize(self) -> bytes:
        out = bytearray(PSBT_MAGIC)

        # Global map
        global_kv: Dict[bytes, bytes] = {}
        global_kv[bytes([PSBT_GLOBAL_UNSIGNED_TX])] = _serialize_unsigned_tx(self.tx)
        for xpub, derivation in self.global_xpubs.items():
            global_kv[bytes([PSBT_GLOBAL_XPUB]) + xpub] = derivation
        global_kv.update(self.unknown_global)
        out += _write_kv_pairs(global_kv)

        # Per-input maps
        for psbt_in in self.inputs:
            out += _write_kv_pairs(psbt_in.to_kv())

        # Per-output maps
        for psbt_out in self.outputs:
            out += _write_kv_pairs(psbt_out.to_kv())

        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "PSBT":
        f = io.BytesIO(data)
        magic = f.read(5)
        if magic != PSBT_MAGIC:
            raise ValueError(f"Invalid PSBT magic: {magic!r}")

        # Global map
        global_kv = _read_kv_pairs(f)
        unsigned_tx_key = bytes([PSBT_GLOBAL_UNSIGNED_TX])
        if unsigned_tx_key not in global_kv:
            raise ValueError("PSBT missing unsigned transaction")
        tx = _deserialize_tx(global_kv.pop(unsigned_tx_key))

        global_xpubs: Dict[bytes, bytes] = {}
        unknown_global: Dict[bytes, bytes] = {}
        for key, val in global_kv.items():
            if key[0] == PSBT_GLOBAL_XPUB:
                global_xpubs[key[1:]] = val
            else:
                unknown_global[key] = val

        # Per-input maps
        inputs: List[PSBTInput] = []
        for _ in range(len(tx.inputs)):
            kv = _read_kv_pairs(f)
            inputs.append(PSBTInput.from_kv(kv))

        # Per-output maps
        outputs: List[PSBTOutput] = []
        for _ in range(len(tx.outputs)):
            kv = _read_kv_pairs(f)
            outputs.append(PSBTOutput.from_kv(kv))

        return cls(tx=tx, inputs=inputs, outputs=outputs,
                   global_xpubs=global_xpubs, unknown_global=unknown_global)

    # ── combine ───────────────────────────────────────────────────

    def combine(self, other: "PSBT") -> "PSBT":
        """
        Combine two PSBTs for the same transaction (``combinepsbt``).

        Merges partial signatures, derivation paths, and UTXO info
        from *other* into *self* and returns *self*.
        """
        if _serialize_unsigned_tx(self.tx) != _serialize_unsigned_tx(other.tx):
            raise ValueError("Cannot combine PSBTs for different transactions")

        for i in range(len(self.inputs)):
            mine = self.inputs[i]
            theirs = other.inputs[i]
            if mine.non_witness_utxo is None and theirs.non_witness_utxo is not None:
                mine.non_witness_utxo = theirs.non_witness_utxo
            if mine.witness_utxo is None and theirs.witness_utxo is not None:
                mine.witness_utxo = theirs.witness_utxo
            mine.partial_sigs.update(theirs.partial_sigs)
            mine.bip32_derivations.update(theirs.bip32_derivations)
            if mine.sighash_type is None and theirs.sighash_type is not None:
                mine.sighash_type = theirs.sighash_type
            if mine.redeem_script is None and theirs.redeem_script is not None:
                mine.redeem_script = theirs.redeem_script
            if mine.witness_script is None and theirs.witness_script is not None:
                mine.witness_script = theirs.witness_script
            mine.unknown.update(theirs.unknown)

        for i in range(len(self.outputs)):
            mine = self.outputs[i]
            theirs = other.outputs[i]
            if mine.redeem_script is None and theirs.redeem_script is not None:
                mine.redeem_script = theirs.redeem_script
            if mine.witness_script is None and theirs.witness_script is not None:
                mine.witness_script = theirs.witness_script
            mine.bip32_derivations.update(theirs.bip32_derivations)
            mine.unknown.update(theirs.unknown)

        self.global_xpubs.update(other.global_xpubs)
        self.unknown_global.update(other.unknown_global)
        return self

    # ── finalize ──────────────────────────────────────────────────

    def finalize(self) -> "PSBT":
        """
        Finalise each input (``finalizepsbt``).

        For P2WPKH inputs: builds final_script_witness from the single
        partial signature.  For P2PKH/bare: builds final_script_sig.
        Clears non-final fields after finalisation.
        """
        for i, psbt_in in enumerate(self.inputs):
            if psbt_in.final_script_sig is not None or psbt_in.final_script_witness is not None:
                continue  # already finalised

            if not psbt_in.partial_sigs:
                continue  # nothing to finalise yet

            if psbt_in.witness_utxo is not None:
                self._finalize_p2wpkh(psbt_in)
            else:
                self._finalize_p2pkh(psbt_in)

        return self

    @staticmethod
    def _finalize_p2wpkh(psbt_in: PSBTInput) -> None:
        """Finalise a P2WPKH input."""
        if len(psbt_in.partial_sigs) != 1:
            return
        pubkey, sig = next(iter(psbt_in.partial_sigs.items()))
        witness = bytearray()
        witness += _write_compact_size(2)  # 2 stack items
        witness += _write_compact_size(len(sig))
        witness += sig
        witness += _write_compact_size(len(pubkey))
        witness += pubkey
        psbt_in.final_script_witness = bytes(witness)
        psbt_in.final_script_sig = b""
        psbt_in.partial_sigs.clear()
        psbt_in.bip32_derivations.clear()
        psbt_in.redeem_script = None
        psbt_in.witness_script = None
        psbt_in.sighash_type = None

    @staticmethod
    def _finalize_p2pkh(psbt_in: PSBTInput) -> None:
        """Finalise a P2PKH input."""
        if len(psbt_in.partial_sigs) != 1:
            return
        pubkey, sig = next(iter(psbt_in.partial_sigs.items()))
        script_sig = bytearray()
        script_sig += bytes([len(sig)])
        script_sig += sig
        script_sig += bytes([len(pubkey)])
        script_sig += pubkey
        psbt_in.final_script_sig = bytes(script_sig)
        psbt_in.partial_sigs.clear()
        psbt_in.bip32_derivations.clear()
        psbt_in.redeem_script = None
        psbt_in.witness_script = None
        psbt_in.sighash_type = None

    # ── extract ───────────────────────────────────────────────────

    def extract_transaction(self) -> Transaction:
        """
        Extract the fully-signed transaction from a finalised PSBT.

        Raises ``ValueError`` if any input is not finalised.
        """
        tx = copy.deepcopy(self.tx)
        has_witness = False

        for i, psbt_in in enumerate(self.inputs):
            if psbt_in.final_script_sig is None and psbt_in.final_script_witness is None:
                raise ValueError(f"Input {i} is not finalised")
            if psbt_in.final_script_sig:
                tx.inputs[i].script_sig = psbt_in.final_script_sig
            if psbt_in.final_script_witness:
                has_witness = True
                f = io.BytesIO(psbt_in.final_script_witness)
                n_items = _read_compact_size(f)
                items: List[bytes] = []
                for _ in range(n_items):
                    item_len = _read_compact_size(f)
                    items.append(f.read(item_len))
                tx.inputs[i].witness = items

        tx.has_witness = has_witness
        tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
        return tx

    # ── decode (human-readable) ───────────────────────────────────

    def decode(self) -> Dict:
        """
        Return a human-readable dictionary representation (``decodepsbt``).
        """
        result: Dict = {
            "tx": {
                "txid": self.tx.txid.hex(),
                "version": self.tx.version,
                "locktime": self.tx.locktime,
                "inputs": [
                    {
                        "prev_txid": inp.prev_txid.hex(),
                        "prev_vout": inp.prev_vout,
                        "sequence": inp.sequence,
                    }
                    for inp in self.tx.inputs
                ],
                "outputs": [
                    {
                        "value": out.value,
                        "script_pubkey": out.script_pubkey.hex(),
                    }
                    for out in self.tx.outputs
                ],
            },
            "inputs": [],
            "outputs": [],
        }

        for psbt_in in self.inputs:
            info: Dict = {}
            if psbt_in.witness_utxo is not None:
                val, spk = psbt_in.witness_utxo
                info["witness_utxo"] = {"value": val, "script_pubkey": spk.hex()}
            if psbt_in.non_witness_utxo is not None:
                info["non_witness_utxo_size"] = len(psbt_in.non_witness_utxo)
            if psbt_in.partial_sigs:
                info["partial_sigs"] = {
                    pk.hex(): sig.hex() for pk, sig in psbt_in.partial_sigs.items()
                }
            if psbt_in.sighash_type is not None:
                info["sighash_type"] = psbt_in.sighash_type
            if psbt_in.final_script_sig is not None:
                info["final_script_sig"] = psbt_in.final_script_sig.hex()
            if psbt_in.final_script_witness is not None:
                info["final_script_witness"] = psbt_in.final_script_witness.hex()
            if psbt_in.bip32_derivations:
                info["bip32_derivations"] = {
                    pk.hex(): drv.hex()
                    for pk, drv in psbt_in.bip32_derivations.items()
                }
            result["inputs"].append(info)

        for psbt_out in self.outputs:
            info = {}
            if psbt_out.redeem_script is not None:
                info["redeem_script"] = psbt_out.redeem_script.hex()
            if psbt_out.witness_script is not None:
                info["witness_script"] = psbt_out.witness_script.hex()
            if psbt_out.bip32_derivations:
                info["bip32_derivations"] = {
                    pk.hex(): drv.hex()
                    for pk, drv in psbt_out.bip32_derivations.items()
                }
            result["outputs"].append(info)

        return result
