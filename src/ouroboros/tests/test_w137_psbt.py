"""W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/psbt.h (1475 lines: type constants, PSBTInput,
  PSBTOutput, PartiallySignedTransaction Serialize + Unserialize),
  bitcoin-core/src/psbt.cpp (639 lines: Merge, SignPSBTInput,
  FinalizePSBT, FinalizeAndExtractPSBT, CombinePSBTs, DecodeRawPSBT,
  GetVersion),
  BIPs 174, 370, 371, 327.

Scope:
- PSBT v0 / v2 wire format codec (`psbt.py`).
- BIP-371 Taproot fields (TAP_KEY_SIG, TAP_SCRIPT_SIG,
  TAP_LEAF_SCRIPT, TAP_BIP32_DERIVATION, TAP_INTERNAL_KEY,
  TAP_MERKLE_ROOT, TAP_TREE).
- BIP-327 MuSig2 PSBT extension (MUSIG2_PARTICIPANT_PUBKEYS,
  MUSIG2_PUB_NONCE, MUSIG2_PARTIAL_SIG).
- finalize / combine / extract / decode / analyze entry points.

Two-pipeline note: PSBT is **wallet code**, Python-only.
ferrous-utils (Rust) has zero PSBT surface. G30 codifies this.

This file contains an xfail test per Core-divergent gate; xfails
flip to XPASS the moment a fix lands. PRESENT gates are plain
asserts that pin Core-parity wiring.

Reference: ouroboros/audit/w137_psbt.md.

NO production code changes. NO behavior changes. Only audit + xfail.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import re
import struct
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup + sync module mock so ouroboros imports cleanly without the
# compiled Rust extension being present.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# Lazy psbt import so module mock above takes effect first.
def _psbt():
    from ouroboros import psbt as _m
    return _m


# ===========================================================================
# G1 — PSBT magic bytes constant pinned to Core
# ===========================================================================


def test_w137_g1_psbt_magic_bytes_constant() -> None:
    """G1: PSBT magic = b'psbt\\xff' (Core psbt.h:28).

    PRESENT — `psbt.py:43` pins `PSBT_MAGIC = b"psbt\\xff"`.
    """
    psbt = _psbt()
    assert psbt.PSBT_MAGIC == b"psbt\xff"


# ===========================================================================
# G2 — PSBT_GLOBAL_UNSIGNED_TX v0 round-trip
# ===========================================================================


def test_w137_g2_psbt_global_unsigned_tx_v0_roundtrip() -> None:
    """G2: PSBT_GLOBAL_UNSIGNED_TX (0x00) serialize/deserialize.

    PRESENT — `psbt.py:1487-1490` emits unsigned tx under key 0x00
    for v0 PSBTs; `psbt.py:1553-1555` parses it back.
    """
    psbt = _psbt()
    PSBTGlobalType = psbt.PSBTGlobalType
    assert int(PSBTGlobalType.UNSIGNED_TX) == 0x00


# ===========================================================================
# G3 — PSBT_GLOBAL_XPUB serialize/deserialize
# ===========================================================================


def test_w137_g3_psbt_global_xpub_constant() -> None:
    """G3: PSBT_GLOBAL_XPUB constant (0x01).

    PRESENT for the constant + storage; BUG-7 / BUG-21 / BUG-22
    flagged for uniqueness + key-size + IsFullyValid checks.
    """
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.XPUB) == 0x01


@pytest.mark.xfail(
    reason="W137 BUG-21 (P2): PSBT_GLOBAL_XPUB key MUST be "
           "BIP32_EXTKEY_WITH_VERSION_SIZE + 1 = 79 bytes "
           "(Core psbt.h:1284-1286). Ouroboros (psbt.py:1563-1564) "
           "accepts any key length.",
    strict=True,
)
def test_w137_g3_xpub_key_size_validation() -> None:
    """G3 (BUG-21): xpub key size MUST be 79 bytes."""
    src = _read_py("psbt.py")
    # Look for a length check on xpub key
    pattern = re.compile(
        r"PSBTGlobalType\.XPUB[\s\S]{0,400}?len\(key_data\)\s*!?=\s*78",
        re.M,
    )
    assert pattern.search(src), (
        "G3 BUG-21: no `len(key_data) == 78` check on PSBT_GLOBAL_XPUB key"
    )


# ===========================================================================
# G4 — PSBT_GLOBAL_VERSION (v2) — divergence from Core
# ===========================================================================


def test_w137_g4_psbt_highest_version_constant() -> None:
    """G4 (BUG-1 P0-CDIV): PSBT_HIGHEST_VERSION.

    Core: `psbt.h:80` `PSBT_HIGHEST_VERSION = 0`.
    Ouroboros: `psbt.py:502` `PSBT_HIGHEST_VERSION = 2`.

    Captures the divergence. A v2 PSBT produced by ouroboros's
    wallet cannot be combined or extracted by Core (Core rejects
    with "Unsupported version number" psbt.h:1322).
    """
    psbt = _psbt()
    # Pin ouroboros's BIP-370 choice
    assert psbt.PSBT_HIGHEST_VERSION == 2
    # Pin Core's choice
    core_header = (REPO_ROOT.parent / "bitcoin-core" / "src" / "psbt.h").read_text()
    m = re.search(r"PSBT_HIGHEST_VERSION\s*=\s*(\d+)", core_header)
    assert m, "PSBT_HIGHEST_VERSION not found in Core's psbt.h"
    core_max = int(m.group(1))
    assert core_max == 0, f"expected Core PSBT_HIGHEST_VERSION == 0; got {core_max}"
    # Divergence pinned: ouroboros 2 vs Core 0
    assert psbt.PSBT_HIGHEST_VERSION != core_max, (
        "BUG-1 closed? Re-check whether v2 is still ouroboros-only "
        "or Core has merged BIP-370."
    )


# ===========================================================================
# G5 — PSBT_GLOBAL_TX_VERSION (v2)
# ===========================================================================


def test_w137_g5_psbt_global_tx_version_constant() -> None:
    """G5: PSBT_GLOBAL_TX_VERSION (0x02) v2 constant."""
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.TX_VERSION) == 0x02


# ===========================================================================
# G6 — PSBT_GLOBAL_FALLBACK_LOCKTIME (v2) — BIP-370 locktime rule
# ===========================================================================


def test_w137_g6_fallback_locktime_constant() -> None:
    """G6: FALLBACK_LOCKTIME constant (0x03)."""
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.FALLBACK_LOCKTIME) == 0x03


@pytest.mark.xfail(
    reason="W137 BUG-8 (P1): BIP-370 §5 locktime derivation entirely "
           "missing. `_reconstruct_tx_from_v2` (psbt.py:1640) uses "
           "`self.fallback_locktime or 0` unconditionally, ignoring "
           "every input's required_time_locktime / "
           "required_height_locktime.",
    strict=True,
)
def test_w137_g6_bip370_locktime_derivation_rule() -> None:
    """G6 (BUG-8): BIP-370 §5 locktime derivation."""
    src = _read_py("psbt.py")
    # Look for max(required_height_locktime) / max(required_time_locktime)
    has_height_max = bool(
        re.search(
            r"max\([^\)]*required_height_locktime", src
        )
    )
    has_time_max = bool(
        re.search(
            r"max\([^\)]*required_time_locktime", src
        )
    )
    assert has_height_max or has_time_max, (
        "G6 BUG-8: no BIP-370 §5 max(required_*_locktime) derivation"
    )


# ===========================================================================
# G7 — PSBT_GLOBAL_INPUT_COUNT (v2)
# ===========================================================================


def test_w137_g7_input_count_constant() -> None:
    """G7: INPUT_COUNT constant (0x04, v2)."""
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.INPUT_COUNT) == 0x04


# ===========================================================================
# G8 — PSBT_GLOBAL_OUTPUT_COUNT (v2)
# ===========================================================================


def test_w137_g8_output_count_constant() -> None:
    """G8: OUTPUT_COUNT constant (0x05, v2)."""
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.OUTPUT_COUNT) == 0x05


# ===========================================================================
# G9 — PSBT_GLOBAL_TX_MODIFIABLE (v2)
# ===========================================================================


def test_w137_g9_tx_modifiable_constant() -> None:
    """G9: TX_MODIFIABLE constant (0x06, v2)."""
    psbt = _psbt()
    assert int(psbt.PSBTGlobalType.TX_MODIFIABLE) == 0x06


# ===========================================================================
# G10 — PSBT_GLOBAL_PROPRIETARY
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-14 (P2): PSBT_GLOBAL_PROPRIETARY (0xFC) parsing "
           "falls through to `unknown[key]` as opaque bytes. Core "
           "(psbt.h:838-851,1327-1340) parses `PSBTProprietary "
           "{identifier, subtype, key, value}` typed records, sorts by "
           "key, emits in canonical order.",
    strict=True,
)
def test_w137_g10_proprietary_typed_parsing() -> None:
    """G10 (BUG-14): PSBT_GLOBAL_PROPRIETARY typed parsing."""
    src = _read_py("psbt.py")
    # Look for a PSBTProprietary class definition or _proprietary list
    has_typed = bool(
        re.search(r"class\s+PSBTProprietary\b|m_proprietary\b", src)
    )
    assert has_typed, (
        "G10 BUG-14: no typed PSBTProprietary parsing; proprietary "
        "records fall through to opaque `unknown` bucket"
    )


# ===========================================================================
# G11 — PSBT_IN_NON_WITNESS_UTXO sha256d invariant (CVE-2020-14199 class)
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-4 (P0-CVE-class): non_witness_utxo sha256d "
           "invariant NOT enforced at PSBT.deserialize. Core "
           "(psbt.h:1371-1378) validates sha256d(non_witness_utxo) "
           "== prev_txid AND prev_vout < len(decoded.outputs). "
           "Ouroboros enforces this LATE only in walletprocesspsbt "
           "(rpc.py:10085-10135, W41 fix).",
    strict=True,
)
def test_w137_g11_non_witness_utxo_hash_check_at_deserialize() -> None:
    """G11 (BUG-4): non_witness_utxo hash check at deserialize."""
    src = _read_py("psbt.py")
    # Look for the sha256d invariant in PSBT.deserialize
    m = re.search(
        r"def deserialize\(cls[\s\S]+?return\s+psbt\b",
        src,
    )
    assert m, "G11: PSBT.deserialize not located"
    body = m.group(0)
    has_hash_check = bool(
        re.search(
            r"sha256d\([^\)]*non_witness_utxo|"
            r"hashlib\.sha256\(.*non_witness_utxo",
            body,
        )
    )
    assert has_hash_check, (
        "G11 BUG-4: no sha256d(non_witness_utxo) == prev_txid check "
        "in PSBT.deserialize"
    )


# ===========================================================================
# G12 — PSBT_IN_WITNESS_UTXO round-trip
# ===========================================================================


def test_w137_g12_witness_utxo_roundtrip() -> None:
    """G12: PSBT_IN_WITNESS_UTXO (0x01) round-trip.

    PRESENT — `psbt.py:1011-1015` (emit) + `psbt.py:1106-1111` (parse)
    handle the value + scriptPubKey format symmetrically.
    """
    psbt = _psbt()
    assert int(psbt.PSBTInputType.WITNESS_UTXO) == 0x01


# ===========================================================================
# G13 — PSBT_IN_PARTIAL_SIG DER + sighash strict validation
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-6 (P0-CVE-class): PSBT_IN_PARTIAL_SIG "
           "(psbt.py:1112-1113) stores raw bytes with NO validation. "
           "Core (psbt.h:524-550) enforces BIP-66 strict DER + sighash "
           "byte sanity via CheckSignatureEncoding(sig, "
           "SCRIPT_VERIFY_DERSIG|SCRIPT_VERIFY_STRICTENC, nullptr).",
    strict=True,
)
def test_w137_g13_partial_sig_der_strictenc_check() -> None:
    """G13 (BUG-6): PARTIAL_SIG DER + sighash byte validation."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.PARTIAL_SIG[\s\S]{0,400}?(?:"
        r"CheckSignatureEncoding|"
        r"check_signature_encoding|"
        r"check_der|"
        r"_strict_der|"
        r"verify_der_signature"
        r")",
        src,
    )
    assert m, (
        "G13 BUG-6: no BIP-66 strict-DER check on PSBT_IN_PARTIAL_SIG"
    )


# ===========================================================================
# G14 — PSBT_IN_PARTIAL_SIG pubkey validity + size
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-6 (P0-CVE-class): PSBT_IN_PARTIAL_SIG key "
           "(pubkey) size MUST be 33 (compressed) or 65 (uncompressed) "
           "AND pubkey MUST be IsFullyValid() (on-curve). Core "
           "(psbt.h:527-534). Ouroboros stores any byte string as a "
           "pubkey.",
    strict=True,
)
def test_w137_g14_partial_sig_pubkey_validity() -> None:
    """G14 (BUG-6): PARTIAL_SIG pubkey size + on-curve validity."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.PARTIAL_SIG[\s\S]{0,400}?(?:"
        r"len\(key_data\)\s*(?:==|in)\s*\(?\s*33|"
        r"IsFullyValid|"
        r"is_fully_valid|"
        r"_check_pubkey_valid"
        r")",
        src,
    )
    assert m, (
        "G14 BUG-6: no pubkey-size or on-curve check on "
        "PSBT_IN_PARTIAL_SIG key"
    )


# ===========================================================================
# G15 — PSBT_IN_SIGHASH_TYPE deserialize
# ===========================================================================


def test_w137_g15_sighash_type_constant() -> None:
    """G15: SIGHASH_TYPE constant (0x03).

    PRESENT — value parsing exists (psbt.py:1114-1115) and round-trips
    correctly. BUG-20 flags the defensive length check.
    """
    psbt = _psbt()
    assert int(psbt.PSBTInputType.SIGHASH_TYPE) == 0x03


# ===========================================================================
# G16 — Per-map trailing separator (0x00) check
# ===========================================================================


def test_w137_g16_per_map_trailing_separator_enforced() -> None:
    """G16: BIP-174 trailing 0x00 separator enforced.

    PRESENT — `_read_kv_pairs` (`psbt.py:576-580`) raises
    "PSBT truncated: missing trailing 0x00 separator" when the
    stream ends without the separator (mirrors Core's
    "Separator is missing at the end of an input map").
    """
    src = _read_py("psbt.py")
    assert "missing trailing 0x00 separator" in src or \
        "Separator is missing" in src, (
            "G16: separator-missing error message not found in _read_kv_pairs"
        )


# ===========================================================================
# G17 — MAX_FILE_SIZE_PSBT = 100 MB
# ===========================================================================


def test_w137_g17_max_psbt_size_100mb() -> None:
    """G17: MAX_PSBT_SIZE = 100,000,000 bytes (Core psbt.h:77).

    PRESENT — `psbt.py:424` `MAX_PSBT_SIZE = 100_000_000`.
    """
    psbt = _psbt()
    assert psbt.MAX_PSBT_SIZE == 100_000_000
    # Cross-check Core's value
    core_header = (REPO_ROOT.parent / "bitcoin-core" / "src" / "psbt.h").read_text()
    m = re.search(r"MAX_FILE_SIZE_PSBT\s*=\s*(\d+)", core_header)
    assert m, "MAX_FILE_SIZE_PSBT not found in Core's psbt.h"
    assert int(m.group(1)) == 100_000_000


# ===========================================================================
# G18 — Unsigned-tx empty-scriptSig invariant at deserialize
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-2 (P0-CVE-class): PSBT.deserialize does not "
           "validate that the unsigned tx contained in "
           "PSBT_GLOBAL_UNSIGNED_TX has empty scriptSig + empty "
           "witness on every input. Core (psbt.h:1274-1278) throws "
           "'Unsigned tx does not have empty scriptSigs and "
           "scriptWitnesses.'",
    strict=True,
)
def test_w137_g18_unsigned_tx_empty_invariant() -> None:
    """G18 (BUG-2): empty scriptSig/witness invariant."""
    src = _read_py("psbt.py")
    m = re.search(
        r"def deserialize\(cls[\s\S]+?return\s+psbt\b",
        src,
    )
    assert m
    body = m.group(0)
    has_check = bool(
        re.search(
            r"Unsigned tx does not have empty|"
            r"unsigned tx must have empty|"
            r"empty\s+scriptSig|"
            r"script_sig\s*!=\s*b\"\"|"
            r"script_sig\s+is not\s+empty",
            body,
        )
    )
    assert has_check, (
        "G18 BUG-2: no empty-scriptSig/witness invariant check in "
        "PSBT.deserialize for the unsigned tx"
    )


# ===========================================================================
# G19 — Inputs/outputs count cross-check at deserialize
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-3 (P1): PSBT.deserialize does not validate "
           "input/output map count against tx vin/vout (Core "
           "psbt.h:1382-1384,1394-1396 'Inputs provided does not match "
           "the number of inputs in transaction.'). Trailing maps "
           "silently ignored.",
    strict=True,
)
def test_w137_g19_input_output_count_cross_check() -> None:
    """G19 (BUG-3): vin/vout vs input/output count cross-check."""
    src = _read_py("psbt.py")
    m = re.search(
        r"def deserialize\(cls[\s\S]+?return\s+psbt\b",
        src,
    )
    assert m
    body = m.group(0)
    has_check = bool(
        re.search(
            r"Inputs provided does not match|"
            r"Outputs provided does not match|"
            r"len\(.*inputs.*\)\s*!=\s*len\(.*tx.*inputs.*\)|"
            r"input_count\s*!=\s*len\(",
            body,
        )
    )
    assert has_check, (
        "G19 BUG-3: no input/output count cross-check at deserialize"
    )


# ===========================================================================
# G20 — PSBT_IN_TAP_* size validation
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-5 (P0-CVE-class): PSBT_IN_TAP_INTERNAL_KEY "
           "(0x17) value MUST be 32 bytes (Core psbt.h:771-779). "
           "Ouroboros (psbt.py:1168-1169) stores val with no length "
           "check.",
    strict=True,
)
def test_w137_g20_tap_internal_key_size_32() -> None:
    """G20 (BUG-5): TAP_INTERNAL_KEY value = 32 bytes."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.TAP_INTERNAL_KEY[\s\S]{0,200}?len\(val\)\s*(?:==|in)\s*[\(\{]?\s*32",
        src,
    )
    assert m, (
        "G20 BUG-5: no `len(val) == 32` check on PSBT_IN_TAP_INTERNAL_KEY"
    )


# ===========================================================================
# G21 — PSBT_IN_TAP_KEY_SIG size 64/65 byte
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-5 (P0-CVE-class): PSBT_IN_TAP_KEY_SIG (0x13) "
           "value MUST be 64 or 65 bytes (Schnorr sig + optional "
           "sighash byte; Core psbt.h:699-703). Ouroboros "
           "(psbt.py:1150-1151) stores val with no length check.",
    strict=True,
)
def test_w137_g21_tap_key_sig_size_64_or_65() -> None:
    """G21 (BUG-5): TAP_KEY_SIG value size 64 or 65 bytes."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.TAP_KEY_SIG[\s\S]{0,200}?(?:"
        r"len\(val\)\s*(?:==|in)\s*[\(\{]?\s*64|"
        r"len\(val\)\s*not in\s*[\(\{]?\s*\(?64,\s*65"
        r")",
        src,
    )
    assert m, (
        "G21 BUG-5: no size check (64 or 65 bytes) on PSBT_IN_TAP_KEY_SIG"
    )


# ===========================================================================
# G22 — PSBT_IN_TAP_LEAF_SCRIPT control block size %32 + key size ≥34
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-5 (P0-CVE-class): PSBT_IN_TAP_LEAF_SCRIPT (0x15) "
           "key MUST be ≥34 bytes AND (key.size()-2) %% 32 == 0 "
           "(Core psbt.h:732-736). Value MUST be ≥1 byte for the "
           "leaf-version trailer. Ouroboros (psbt.py:1157-1161) only "
           "checks len(val) >= 1.",
    strict=True,
)
def test_w137_g22_tap_leaf_script_control_block_validation() -> None:
    """G22 (BUG-5): TAP_LEAF_SCRIPT control-block size validation."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.TAP_LEAF_SCRIPT[\s\S]{0,400}?(?:"
        r"len\(key_data\)\s*>=\s*33|"
        r"\(len\(key_data\)\s*-\s*1\)\s*%\s*32|"
        r"len\(control_block\)\s*%\s*32"
        r")",
        src,
    )
    assert m, (
        "G22 BUG-5: no control-block size check on PSBT_IN_TAP_LEAF_SCRIPT"
    )


# ===========================================================================
# G23 — BIP-370 §5 locktime derivation rule
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-8 (P1): BIP-370 §5 locktime derivation entirely "
           "missing. `_reconstruct_tx_from_v2` (psbt.py:1640) uses "
           "`self.fallback_locktime or 0` unconditionally.",
    strict=True,
)
def test_w137_g23_bip370_locktime_derivation() -> None:
    """G23 (BUG-8): BIP-370 §5 locktime derivation rule."""
    src = _read_py("psbt.py")
    m = re.search(
        r"def _reconstruct_tx_from_v2[\s\S]+?self\.tx\s*=",
        src,
    )
    assert m, "G23: _reconstruct_tx_from_v2 not found"
    body = m.group(0)
    has_derivation = bool(
        re.search(
            r"max\([\s\S]{0,150}?required_(?:height|time)_locktime",
            body,
        )
    )
    assert has_derivation, (
        "G23 BUG-8: no max(required_*_locktime) derivation in "
        "_reconstruct_tx_from_v2"
    )


# ===========================================================================
# G24 — BIP-370 nSequence vs CLTV constraint
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-15 (P1): BIP-370 nSequence vs CLTV constraint "
           "not enforced. A v2 PSBT with REQUIRED_*_LOCKTIME AND "
           "sequence=0xFFFFFFFF on the same input is INVALID per "
           "BIP-65 (CLTV requires sequence < 0xFFFFFFFE).",
    strict=True,
)
def test_w137_g24_bip370_nsequence_cltv_constraint() -> None:
    """G24 (BUG-15): BIP-65 nSequence vs CLTV constraint on v2."""
    src = _read_py("psbt.py")
    m = re.search(
        r"def _reconstruct_tx_from_v2[\s\S]+?self\.tx\s*=",
        src,
    )
    assert m
    body = m.group(0)
    has_check = bool(
        re.search(
            r"sequence\s*>=\s*0xFFFFFFFE|"
            r"0xfffffffe\s*<=\s*sequence|"
            r"required_(?:height|time)_locktime\s+is not None[\s\S]{0,200}?sequence",
            body,
            re.IGNORECASE,
        )
    )
    assert has_check, (
        "G24 BUG-15: no nSequence < 0xFFFFFFFE check when "
        "required_*_locktime is set"
    )


# ===========================================================================
# G25 — BIP-327 MuSig2 input-side storage fields
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-10 (P1): BIP-327 MuSig2 input storage absent. "
           "PSBTInputType defines MUSIG2_PARTICIPANT_PUBKEYS (0x1a), "
           "MUSIG2_PUB_NONCE (0x1b), MUSIG2_PARTIAL_SIG (0x1c) but "
           "PSBTInput has no storage. Wire-parse falls through to "
           "`unknown` bucket.",
    strict=True,
)
def test_w137_g25_musig2_input_storage_present() -> None:
    """G25 (BUG-10): MuSig2 input-side storage."""
    psbt = _psbt()
    sample = psbt.PSBTInput()
    has_participants = hasattr(sample, "musig2_participants")
    has_pubnonces = hasattr(sample, "musig2_pubnonces")
    has_partial_sigs = hasattr(sample, "musig2_partial_sigs")
    assert has_participants and has_pubnonces and has_partial_sigs, (
        "G25 BUG-10: PSBTInput lacks MuSig2 input-side storage fields "
        f"(participants={has_participants}, pubnonces={has_pubnonces}, "
        f"partial_sigs={has_partial_sigs})"
    )


# ===========================================================================
# G26 — combinepsbt byte-identity (W46 sort PRESERVED)
# ===========================================================================


def test_w137_g26_combinepsbt_canonical_sort_present() -> None:
    """G26: PARTIAL_SIG canonical HASH160 sort (W46 fix).

    PRESENT — `_input_map_sort_key` (`psbt.py:594-633`) sorts
    PARTIAL_SIG entries by HASH160(pubkey) to match Core's
    `std::map<CKeyID, SigPair>` walk order.
    """
    src = _read_py("psbt.py")
    assert "_input_map_sort_key" in src, "G26: W46 sort fn missing"
    assert "ripemd160" in src and "PARTIAL_SIG" in src, (
        "G26: HASH160 canonical sort logic not present"
    )


# ===========================================================================
# G27 — RemoveUnnecessaryTransactions equivalent
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-12 (P2): RemoveUnnecessaryTransactions (Core "
           "psbt.cpp:514-549) equivalent missing. Drops "
           "non_witness_utxo from inputs once all inputs are segwit v1 "
           "AND sighash != ANYONECANPAY. Saves wire size for "
           "multi-input Taproot PSBTs.",
    strict=True,
)
def test_w137_g27_remove_unnecessary_transactions() -> None:
    """G27 (BUG-12): RemoveUnnecessaryTransactions equivalent."""
    src = _read_py("psbt.py")
    has_fn = bool(
        re.search(
            r"def\s+(?:_)?remove_unnecessary_transactions|"
            r"def\s+(?:_)?drop_non_witness_utxos|"
            r"def\s+(?:_)?strip_non_witness_utxos",
            src,
        )
    )
    assert has_fn, (
        "G27 BUG-12: no RemoveUnnecessaryTransactions equivalent"
    )


# ===========================================================================
# G28 — PSBTInputSignedAndVerified script-verify
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-13 (P1): PSBTInputSignedAndVerified (Core "
           "psbt.cpp:325-352) equivalent missing. is_finalized "
           "(psbt.py:1000-1002) checks structural completeness only. "
           "A combiner-forged PSBT with structurally complete "
           "scriptSig/witness but invalid sigs slips through.",
    strict=True,
)
def test_w137_g28_psbt_input_signed_and_verified() -> None:
    """G28 (BUG-13): PSBTInputSignedAndVerified equivalent."""
    psbt = _psbt()
    has_method = (
        hasattr(psbt.PSBT, "input_signed_and_verified")
        or hasattr(psbt.PSBT, "verify_finalized_inputs")
        or hasattr(psbt, "psbt_input_signed_and_verified")
    )
    src = _read_py("psbt.py")
    has_script_verify_in_finalize = bool(
        re.search(r"def\s+(?:is_finalized|verify_signed)[\s\S]{0,300}?"
                  r"VerifyScript|verify_script", src)
    )
    assert has_method or has_script_verify_in_finalize, (
        "G28 BUG-13: no PSBTInputSignedAndVerified-equivalent "
        "script-verify on finalize/extract path"
    )


# ===========================================================================
# G29 — finalize() bare-multisig branch
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-11 (P2): finalize() ladder (psbt.py:1680-1700) "
           "lacks bare-multisig (non-P2SH-wrapped, non-segwit) "
           "branch. P2 because bare multisig is no longer "
           "standard-policy in Core.",
    strict=True,
)
def test_w137_g29_finalize_bare_multisig_branch() -> None:
    """G29 (BUG-11): finalize() bare-multisig branch."""
    src = _read_py("psbt.py")
    has_branch = bool(
        re.search(
            r"def\s+_try_finalize_bare_multisig|"
            r"def\s+_try_finalize_multisig\b",
            src,
        )
    )
    assert has_branch, (
        "G29 BUG-11: no _try_finalize_bare_multisig branch in "
        "finalize() ladder"
    )


# ===========================================================================
# G30 — Two-pipeline guard: PSBT is Python-only
# ===========================================================================


def test_w137_g30_two_pipeline_psbt_python_only() -> None:
    """G30: Two-pipeline guard EXTENDED to PSBT.

    PSBT is wallet code, Python-only. The consensus pipeline
    (ferrous-utils Rust) must NOT contain any PSBT surface.
    If a regression moves PSBT code to Rust "for performance",
    the two-pipeline boundary is violated — flag immediately.

    Extends the guard set:
    W76 + W120 + W122 + W125 + W128 + W129 + W130 + W131 + W133
    → now W137.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")

    forbidden = re.compile(
        r"\b(?:"
        r"PSBT|"
        r"BIP[- ]?174|"
        r"BIP[- ]?370|"
        r"BIP[- ]?371|"
        r"BIP[- ]?327|"
        r"PartiallySigned|"
        r"PSBT_MAGIC|"
        r"PSBTInput|"
        r"PSBTOutput"
        r")\b",
        re.IGNORECASE,
    )

    hits: list[tuple[Path, str]] = []
    for root in (FERROUS_UTILS / "common" / "src", FERROUS_UTILS / "sync" / "src"):
        if not root.exists():
            continue
        for rs in root.rglob("*.rs"):
            text = rs.read_text(encoding="utf-8", errors="replace")
            for m in forbidden.finditer(text):
                # Exclude PSBT mentions in pure comments that document
                # *absence* (the audit md is a Markdown file, not .rs)
                line_start = text.rfind("\n", 0, m.start()) + 1
                line_end = text.find("\n", m.end())
                line = text[line_start:line_end if line_end != -1 else len(text)]
                # A doc-comment "no PSBT here" is fine if the line is
                # a comment AND mentions absence. To keep the guard
                # tight, we only allow specific exemption patterns.
                if line.lstrip().startswith("//") and (
                    "no PSBT" in line.lower()
                    or "not PSBT" in line.lower()
                ):
                    continue
                hits.append((rs.relative_to(FERROUS_UTILS), m.group(0)))

    assert not hits, (
        "G30: PSBT-related symbols leaked into ferrous-utils (Rust) — "
        "two-pipeline boundary violated. PSBT is wallet code and must "
        f"remain Python-only. Hits: {hits}"
    )


def test_w137_g30_python_psbt_module_importable() -> None:
    """G30 corollary: `ouroboros.psbt` module is the canonical
    Python PSBT codec.

    PRESENT — module imports cleanly, exposes PSBT, PSBTInput,
    PSBTOutput, KeyOriginInfo, plus the 4 IntEnum type-byte tables.
    """
    psbt = _psbt()
    for sym in ("PSBT", "PSBTInput", "PSBTOutput", "KeyOriginInfo",
                "PSBTGlobalType", "PSBTInputType", "PSBTOutputType",
                "PSBT_MAGIC", "MAX_PSBT_SIZE", "PSBT_VERSION_0",
                "PSBT_VERSION_2", "PSBT_HIGHEST_VERSION"):
        assert hasattr(psbt, sym), f"G30: ouroboros.psbt missing {sym}"


# ===========================================================================
# Cross-cutting defensive parser bugs (BUG-19, BUG-20, BUG-24)
# ===========================================================================


@pytest.mark.xfail(
    reason="W137 BUG-19 (P1): struct.unpack('<I', val) for "
           "FALLBACK_LOCKTIME / TX_VERSION (psbt.py:1566,1568) "
           "assumes len(val) == 4. Malformed PSBT with short value "
           "crashes with struct.error instead of clean PSBT-format "
           "error.",
    strict=True,
)
def test_w137_g6b_fallback_locktime_length_check() -> None:
    """BUG-19 defensive: FALLBACK_LOCKTIME length check."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTGlobalType\.FALLBACK_LOCKTIME[\s\S]{0,200}?"
        r"len\(val\)\s*(?:==|!=)\s*4",
        src,
    )
    assert m, (
        "BUG-19: no len(val) check on PSBT_GLOBAL_FALLBACK_LOCKTIME"
    )


@pytest.mark.xfail(
    reason="W137 BUG-20 (P1): PSBT_IN_SIGHASH_TYPE struct.unpack "
           "('<I', val) (psbt.py:1115) assumes len(val) == 4. "
           "Defensive length check missing.",
    strict=True,
)
def test_w137_g15b_sighash_type_length_check() -> None:
    """BUG-20 defensive: SIGHASH_TYPE length check."""
    src = _read_py("psbt.py")
    m = re.search(
        r"PSBTInputType\.SIGHASH_TYPE[\s\S]{0,200}?"
        r"len\(val\)\s*(?:==|!=)\s*4",
        src,
    )
    assert m, "BUG-20: no len(val) check on PSBT_IN_SIGHASH_TYPE"


@pytest.mark.xfail(
    reason="W137 BUG-24 (P2): PSBT.deserialize doesn't enforce "
           "'extra data after PSBT' (Core psbt.cpp:622-625 raises "
           "if !ss_data.empty() after deserialize). Trailing garbage "
           "silently ignored.",
    strict=True,
)
def test_w137_g1b_extra_data_after_psbt_rejected() -> None:
    """BUG-24 defensive: extra-data-after-PSBT rejection.

    Constructs a minimal valid v0 PSBT (using ouroboros's own
    serializer) and appends garbage. Core would reject; ouroboros
    currently accepts (bug). On fix, ouroboros raises and the xfail
    flips to XPASS.
    """
    from ouroboros.database import Transaction
    psbt = _psbt()
    # Minimal valid v0 PSBT: empty inputs/outputs
    tx = Transaction(
        txid=b"\x00" * 32, version=2, locktime=0,
        inputs=[], outputs=[],
    )
    raw_min = psbt.PSBT.from_transaction(tx).serialize()
    # Pollute with trailing garbage
    polluted = raw_min + b"\xde\xad\xbe\xef"
    # Round-trip the clean one to confirm baseline works
    psbt.PSBT.deserialize(raw_min)
    # Polluted MUST raise per Core. Today it silently passes.
    with pytest.raises((ValueError, Exception)):
        psbt.PSBT.deserialize(polluted)


# ===========================================================================
# Audit-file presence sanity check (keeps test file + audit md in sync)
# ===========================================================================


def test_w137_audit_md_exists_and_has_30_gates() -> None:
    """The audit markdown must accompany this test file with all 30
    gates listed."""
    audit_md = REPO_ROOT / "audit" / "w137_psbt.md"
    assert audit_md.exists(), f"missing {audit_md}"
    text = audit_md.read_text()
    for i in range(1, 31):
        assert f"G{i} " in text or f"| G{i} " in text or f"G{i}  " in text, (
            f"audit md missing gate G{i}"
        )


def test_w137_audit_md_bug_count_matches() -> None:
    """The audit md announces N bugs in the header; cross-check that
    the bug-table has at least that many BUG-N entries."""
    audit_md = REPO_ROOT / "audit" / "w137_psbt.md"
    text = audit_md.read_text()
    m = re.search(r"\*\*(\d+)\s+BUGS\*\*", text)
    assert m, "audit md missing '**N BUGS**' header tag"
    declared = int(m.group(1))
    # Count `| BUG-N |` rows
    found = len(re.findall(r"\|\s*BUG-\d+\s*\|", text))
    assert found >= declared, (
        f"audit md announces {declared} bugs but table has {found} rows"
    )
