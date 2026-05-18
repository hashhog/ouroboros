"""W138 — assumeUTXO snapshots audit (ouroboros, Python + Rust).

DISCOVERY wave. 30 gates audited against
  bitcoin-core/src/node/utxo_snapshot.{h,cpp}
    - SNAPSHOT_MAGIC_BYTES = b"utxo\\xff"        @ utxo_snapshot.h:28
    - SnapshotMetadata Serialize/Unserialize     @ utxo_snapshot.h:63-105
    - SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash" @ utxo_snapshot.h:113
    - SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"   @ utxo_snapshot.h:128
    - FindAssumeutxoChainstateDir                @ utxo_snapshot.cpp:83-92
    - Read/WriteSnapshotBaseBlockhash            @ utxo_snapshot.cpp:22-81
  bitcoin-core/src/validation.cpp
    - ActivateSnapshot                           @ 5588-5728
    - PopulateAndValidateSnapshot                @ 5754-5953
    - MaybeValidateSnapshot                      @ 5967-6077
    - LoadAssumeutxoChainstate                   @ 6151-6168
    - AddChainstate (target_blockhash transfer)  @ 6170-6187
    - InvalidateCoinsDBOnDisk                    @ 6201-6231
    - ValidatedSnapshotCleanup                   @ 6280-6345
  bitcoin-core/src/rpc/blockchain.cpp
    - loadtxoutset                               @ 3368-3447
    - getchainstates                             @ 3462-3519
    - dumptxoutset                               @ 3078-3367
  bitcoin-core/src/kernel/chainparams.cpp
    - m_assumeutxo_data (mainnet/testnet3/testnet4) @ 158-389
    - GetAvailableSnapshotHeights                @ 677-686

Scope: snapshot codec + RPC handlers + two-chainstate handshake +
       background validation + Rust pipeline two-codepath divergence.

Two-pipeline note: assumeUTXO is the **most legitimately Rust-touching**
subsystem in ouroboros (the bulk UTXO loader is hot-path Rust). G29
audits the Python-vs-Rust DIVERGENCE that the parallel codepath
creates. G30 codifies the operator-only contract on the Rust path.
This is the 10th extension of the two-pipeline guard set.

This file contains one xfail per BUG-marked gate; xfails flip to XPASS
the moment a fix lands. PRESENT gates are plain asserts that pin
Core-parity wiring.

Reference: ouroboros/audit/w138_assumeutxo.md.

NO production code changes. Only audit + xfail.
"""

from __future__ import annotations

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


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# Lazy import so the sync module mock takes effect first.
def _snapshot():
    from ouroboros import snapshot as _m
    return _m


# ===========================================================================
# G1 — SNAPSHOT_MAGIC bytes constant pinned to Core
# ===========================================================================


def test_w138_g1_snapshot_magic_bytes() -> None:
    """G1: SNAPSHOT_MAGIC = b"utxo\\xff" (Core utxo_snapshot.h:28).

    PRESENT — `snapshot.py:101` pins it; Rust `snapshot.rs:43` matches.
    """
    snap = _snapshot()
    assert snap.SNAPSHOT_MAGIC == b"utxo\xff"
    # Cross-check Rust binding
    rust_src = _read_rust("sync/src/storage/snapshot.rs")
    assert rust_src, "Rust snapshot.rs not present"
    assert b'SNAPSHOT_MAGIC' in rust_src.encode() or 'SNAPSHOT_MAGIC' in rust_src
    assert 'b"utxo\\xff"' in rust_src or '"utxo\\xff"' in rust_src or "utxo\\xff" in rust_src


# ===========================================================================
# G2 — SNAPSHOT_VERSION = 2
# ===========================================================================


def test_w138_g2_snapshot_version_constant() -> None:
    """G2: SNAPSHOT_VERSION = 2 (Core utxo_snapshot.h:39).

    PRESENT — `snapshot.py:102`.
    """
    snap = _snapshot()
    assert snap.SNAPSHOT_VERSION == 2


# ===========================================================================
# G3 — Network magic table covers mainnet/testnet/testnet4/signet/regtest
# ===========================================================================


def test_w138_g3_network_magic_table() -> None:
    """G3: NETWORK_MAGIC table matches Core pchMessageStart.

    PRESENT — `snapshot.py:105-111`. Cross-checked against Core
    `chainparams.cpp`.
    """
    snap = _snapshot()
    assert snap.NETWORK_MAGIC["mainnet"] == bytes([0xF9, 0xBE, 0xB4, 0xD9])
    assert snap.NETWORK_MAGIC["testnet"] == bytes([0x0B, 0x11, 0x09, 0x07])
    assert snap.NETWORK_MAGIC["testnet4"] == bytes([0x1C, 0x16, 0x3F, 0x28])
    assert snap.NETWORK_MAGIC["signet"] == bytes([0x0A, 0x03, 0xCF, 0x40])
    assert snap.NETWORK_MAGIC["regtest"] == bytes([0xFA, 0xBF, 0xB5, 0xDA])


# ===========================================================================
# G4 — SnapshotMetadata codec round-trips byte-for-byte
# ===========================================================================


def test_w138_g4_snapshot_metadata_roundtrip() -> None:
    """G4: SnapshotMetadata serialize/deserialize matches Core
    utxo_snapshot.h:63-105 byte format.

    PRESENT — Python `_read_metadata_header` / `_write_metadata_header`
    round-trip cleanly.
    """
    import io

    snap = _snapshot()
    buf = io.BytesIO()
    base_hash = bytes(range(32))
    snap._write_metadata_header(buf, "mainnet", base_hash, 991_032_194)
    raw = buf.getvalue()
    # Header is 5 + 2 + 4 + 32 + 8 = 51 bytes
    assert len(raw) == 51
    # Magic
    assert raw[:5] == b"utxo\xff"
    # Version LE16
    assert struct.unpack("<H", raw[5:7])[0] == 2
    # Network magic
    assert raw[7:11] == bytes([0xF9, 0xBE, 0xB4, 0xD9])
    # Base blockhash
    assert raw[11:43] == base_hash
    # Coins count LE64
    assert struct.unpack("<Q", raw[43:51])[0] == 991_032_194

    # Round-trip parse
    parsed = snap._read_metadata_header(io.BytesIO(raw), "mainnet")
    assert parsed.version == 2
    assert parsed.network == "mainnet"
    assert parsed.base_blockhash == base_hash
    assert parsed.coins_count == 991_032_194


# ===========================================================================
# G5 — Mainnet m_assumeutxo_data table matches Core verbatim
# ===========================================================================


def test_w138_g5_mainnet_assumeutxo_table_matches_core() -> None:
    """G5: mainnet entries at 840k/880k/910k/935k match Core's
    `chainparams.cpp:158-183`.

    PRESENT — `snapshot.py:214-271`.
    """
    snap = _snapshot()
    params = snap.get_assumeutxo_params("mainnet")
    heights = [p.height for p in params]
    # Core's 4 mainnet entries + ouroboros local 944183 entry
    for required in (840_000, 880_000, 910_000, 935_000):
        assert required in heights, f"Missing mainnet snapshot at h={required}"

    # Pin canonical hash_serialized for h=840000
    h840 = next(p for p in params if p.height == 840_000)
    # Display hex is the reversed internal byte order
    expected = bytes.fromhex(
        "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
    )[::-1]
    assert h840.hash_serialized == expected, (
        "Mainnet h=840k hash_serialized does not match Core "
        "chainparams.cpp:161"
    )


# ===========================================================================
# G6 — testnet3 m_assumeutxo_data table — values match but base_header/
#      chainwork_hex are unprovisioned (BUG-1, P2)
# ===========================================================================


def test_w138_g6_testnet3_table_present() -> None:
    """G6 (PRESENT-PART): testnet3 entries at 2.5M / 4.84M exist with
    correct heights + hashes.
    """
    snap = _snapshot()
    params = snap.get_assumeutxo_params("testnet")
    heights = [p.height for p in params]
    assert 2_500_000 in heights
    assert 4_840_000 in heights


@pytest.mark.xfail(
    reason="W138 BUG-1 (P2): testnet3 entries lack base_header and "
    "chainwork_hex; cross-restart chainwork correction + first-block-"
    "above-snapshot validation rely on these fields when assumeutxo "
    "is used. Cosmetic for live mainnet (which has them) but "
    "documented gap.",
    strict=True,
)
def test_w138_g6_testnet3_base_header_provisioned() -> None:
    """G6 (BUG-1): testnet3 entries should have base_header populated."""
    snap = _snapshot()
    params = snap.get_assumeutxo_params("testnet")
    for p in params:
        assert p.base_header is not None and len(p.base_header) == 80, (
            f"testnet3 h={p.height} missing 80-byte base_header"
        )
        assert p.chainwork_hex is not None, (
            f"testnet3 h={p.height} missing chainwork_hex"
        )


# ===========================================================================
# G7 — testnet4 m_assumeutxo_data table (BUG-2, P1)
# ===========================================================================


def test_w138_g7_testnet4_table_matches_core() -> None:
    """G7 (PRESENT-PART): testnet4 entries at 90k / 120k match Core
    `chainparams.cpp:376-389`."""
    snap = _snapshot()
    params = snap.get_assumeutxo_params("testnet4")
    heights = [p.height for p in params]
    assert 90_000 in heights
    assert 120_000 in heights

    # Pin h=90000 hash_serialized matches Core
    h90 = next(p for p in params if p.height == 90_000)
    expected = bytes.fromhex(
        "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
    )[::-1]
    assert h90.hash_serialized == expected


@pytest.mark.xfail(
    reason="W138 BUG-2 (P1): testnet4 entries lack base_header + "
    "chainwork_hex. The post-snapshot prev-block synthesis path "
    "(`validation.py:_synthesize_snapshot_prev_block`) will return "
    "None for testnet4 snapshots, forcing infinite retry of the "
    "FIRST block above the snapshot tip until headers/blocks for "
    "the prev height arrive.",
    strict=True,
)
def test_w138_g7_testnet4_base_header_provisioned() -> None:
    """G7 (BUG-2): testnet4 entries should have base_header populated."""
    snap = _snapshot()
    params = snap.get_assumeutxo_params("testnet4")
    for p in params:
        assert p.base_header is not None and len(p.base_header) == 80, (
            f"testnet4 h={p.height} missing 80-byte base_header"
        )


# ===========================================================================
# G8 — Per-coin VARINT(code) + CompressAmount + ScriptCompression
# ===========================================================================


def test_w138_g8_coin_codec_roundtrip() -> None:
    """G8: per-coin VARINT(code) + VARINT(compress(amount)) +
    ScriptCompression matches Core `coins.h::Coin::Serialize` +
    `compressor.cpp::TxOutCompression`.

    PRESENT — `serialize_coin` / `deserialize_coin` round-trip.
    """
    import io

    snap = _snapshot()
    buf = io.BytesIO()
    snap.serialize_coin(
        buf,
        height=840_000,
        is_coinbase=False,
        amount=50_000_000,
        script=b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac",
    )
    buf.seek(0)
    h, cb, amt, script = snap.deserialize_coin(buf)
    assert h == 840_000
    assert cb is False
    assert amt == 50_000_000
    assert script[0] == 0x76 and script[1] == 0xA9
    assert len(script) == 25


# ===========================================================================
# G9 — Non-canonical CompactSize rejection
# ===========================================================================


def test_w138_g9_compact_size_canonical() -> None:
    """G9: `_read_compact_size` rejects non-canonical encodings
    (Core `serialize.h`).

    PRESENT — `snapshot.py:387-413`. Rust matches `snapshot.rs:291-344`.
    """
    import io

    snap = _snapshot()
    # 0xfd-prefixed value < 0xfd (non-canonical)
    buf = io.BytesIO(b"\xfd\x00\x00")
    with pytest.raises(ValueError, match="[Nn]on-canonical"):
        snap._read_compact_size(buf)
    # 0xfe-prefixed value < 0x10000 (non-canonical)
    buf = io.BytesIO(b"\xfe\xff\xff\x00\x00")
    with pytest.raises(ValueError, match="[Nn]on-canonical"):
        snap._read_compact_size(buf)
    # 0xff-prefixed value < 0x100000000 (non-canonical)
    buf = io.BytesIO(b"\xff" + b"\x00" * 8)
    with pytest.raises(ValueError, match="[Nn]on-canonical"):
        snap._read_compact_size(buf)


# ===========================================================================
# G10 — HASH_SERIALIZED commitment check on snapshot load
# ===========================================================================


def test_w138_g10_hash_serialized_commitment_strict_path() -> None:
    """G10: After loading coins, the SHA256d HashWriter digest is
    compared to `au_data.hash_serialized` (Core `validation.cpp:5912-
    5915`). Rejects with "Bad snapshot content hash: ..." on mismatch.

    PRESENT — `snapshot.py:1046-1059`.
    """
    src = _read_py("snapshot.py")
    # The "strict" branch must compare against au_data.hash_serialized
    pattern = re.compile(
        r"if strict and au_data is not None:\s*"
        r"if computed != au_data\.hash_serialized",
        re.S,
    )
    assert pattern.search(src), (
        "G10: HASH_SERIALIZED commitment check not located at expected "
        "site in load_snapshot"
    )


# ===========================================================================
# G11 — mempool-empty precondition
# ===========================================================================


def test_w138_g11_mempool_empty_precondition() -> None:
    """G11: rpc_loadtxoutset refuses to load when mempool is non-empty
    (Core `validation.cpp:5626-5629`).

    PRESENT — `rpc.py:10685-10695`.
    """
    src = _read_py("rpc.py")
    # The exact Core error message must be reproduced verbatim
    assert "Can't activate a snapshot when mempool not empty" in src, (
        "G11: mempool-empty precondition message not found"
    )


# ===========================================================================
# G12 — Per-coin height + MoneyRange bounds
# ===========================================================================


def test_w138_g12_per_coin_height_and_money_range() -> None:
    """G12: per-coin `coin.nHeight > base_height` rejected;
    `MoneyRange(coin.out.nValue)` enforced (Core
    `validation.cpp:5814-5823`).

    PRESENT — `snapshot.py:984-1004`.
    """
    src = _read_py("snapshot.py")
    # height check
    assert re.search(
        r"if au_data is not None and coin_height > height:",
        src,
    ), "G12: per-coin height bound check missing"
    # MoneyRange check (against _MAX_MONEY = 21,000,000 * 1e8)
    assert re.search(
        r"if amount < 0 or amount > _MAX_MONEY:",
        src,
    ), "G12: per-coin MoneyRange check missing"
    # _MAX_MONEY constant matches Core's MAX_MONEY (21M * COIN)
    snap = _snapshot()
    assert snap._MAX_MONEY == 21_000_000 * 100_000_000


# ===========================================================================
# G13 — Trailing-bytes EOF check
# ===========================================================================


def test_w138_g13_trailing_bytes_check() -> None:
    """G13: After loading `coins_count` coins, reading any further byte
    must raise "Bad snapshot - coins left over" (Core
    `validation.cpp:5872-5883`).

    PRESENT — `snapshot.py:1033-1044`.
    """
    src = _read_py("snapshot.py")
    assert "Bad snapshot - coins left over" in src, (
        "G13: trailing-bytes check message not found"
    )


# ===========================================================================
# G14 — chainstate_snapshot/ persistence of base_blockhash + base_blockheader
# ===========================================================================


def test_w138_g14_base_blockhash_persistence_partial() -> None:
    """G14 (PRESENT-PART): base_blockhash file written + base_blockheader
    written when chainparams ships it (`snapshot.py:1068-1077`).
    """
    src = _read_py("snapshot.py")
    assert "write_snapshot_base_blockhash" in src
    assert "write_snapshot_base_blockheader" in src


@pytest.mark.xfail(
    reason="W138 BUG-21 (P1): no `validated` boolean persisted to "
    "chainstate_snapshot/. After restart, `getchainstates` cannot "
    "report whether background validation completed in a prior "
    "process.",
    strict=True,
)
def test_w138_g14_validated_flag_persisted() -> None:
    """G14 (BUG-21): a `validated` marker file must be written when
    background validation completes successfully.
    """
    src = _read_py("snapshot.py")
    assert re.search(r"write[^a-zA-Z_]*validated[^a-zA-Z_]*flag", src) or \
        re.search(r'\"validated\"\s*:\s*True[\s\S]{0,200}\.write_bytes', src), (
        "G14 BUG-21: no validated-marker file written in snapshot.py"
    )


# ===========================================================================
# G15 — "Can't activate a snapshot-based chainstate more than once"
#       cross-restart guard (BUG-7, P0-CDIV)
# ===========================================================================


def test_w138_g15_load_already_loaded_inprocess() -> None:
    """G15 (PRESENT-PART): in-process `snapshot_loaded` flag rejects
    second loadtxoutset call.
    """
    src = _read_py("rpc.py")
    assert "Snapshot already loaded" in src, (
        "G15: in-process already-loaded rejection text missing"
    )


@pytest.mark.xfail(
    reason="W138 BUG-7 (P0-CDIV): `sm.snapshot_loaded` is process-local "
    "(`snapshot.py:817`). On restart it resets to False; a second "
    "loadtxoutset call against a datadir that already contains "
    "chainstate_snapshot/base_blockhash is silently allowed and "
    "clobbers the existing snapshot. Core "
    "(`validation.cpp:5600-5602`) checks "
    "`CurrentChainstate().m_from_snapshot_blockhash` which is "
    "REHYDRATED from disk via `LoadAssumeutxoChainstate`.",
    strict=True,
)
def test_w138_g15_load_already_loaded_cross_restart() -> None:
    """G15 (BUG-7): a cross-restart guard must check
    `has_snapshot_chainstate()` AND match the loaded-vs-requested
    base_blockhash before accepting a new loadtxoutset call.
    """
    src = _read_py("rpc.py")
    # Look for cross-restart check: any reference to has_snapshot_chainstate
    # or read_snapshot_base_blockhash from inside rpc_loadtxoutset
    m = re.search(
        r"async def rpc_loadtxoutset[\s\S]*?(?=async def )", src
    )
    assert m, "G15: rpc_loadtxoutset not located"
    body = m.group(0)
    has_disk_check = (
        "has_snapshot_chainstate" in body
        or "read_snapshot_base_blockhash" in body
    )
    assert has_disk_check, (
        "G15 BUG-7: rpc_loadtxoutset has no on-disk chainstate_snapshot "
        "check before accepting a new load"
    )


# ===========================================================================
# G16 — getchainstates response shape (BUG-8, P0-CDIV)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-8 (P0-CDIV): `rpc_getchainstates` returns "
    "{id, validated_height, validated_hash, validated, active, "
    "snapshot_blockhash, snapshot_height, from_snapshot} but Core's "
    "`getchainstates` (`rpc/blockchain.cpp:3462-3519`) returns "
    "{blocks, bestblockhash, bits, target, difficulty, "
    "verificationprogress, snapshot_blockhash (optional), "
    "coins_db_cache_bytes, coins_tip_cache_bytes, validated}. "
    "Cross-impl test suites and Core RPC clients hitting ouroboros "
    "see KeyError on every expected field.",
    strict=True,
)
def test_w138_g16_getchainstates_core_field_names() -> None:
    """G16 (BUG-8): rpc_getchainstates must emit Core's canonical
    field names.
    """
    src = _read_py("rpc.py")
    # All Core fields must be pushed into the chainstate dict
    expected = (
        "blocks",
        "bestblockhash",
        "bits",
        "target",
        "difficulty",
        "verificationprogress",
        "coins_db_cache_bytes",
        "coins_tip_cache_bytes",
    )
    m = re.search(
        r"async def rpc_getchainstates[\s\S]*?(?=async def )", src
    )
    assert m, "G16: rpc_getchainstates not located"
    body = m.group(0)
    missing = [f for f in expected if f'"{f}"' not in body and f"'{f}'" not in body]
    assert not missing, f"G16 BUG-8: missing Core fields in response: {missing}"


# ===========================================================================
# G17 — FindAssumeutxoChainstateDir / cross-restart snapshot_height
#       re-init (BUG-9, P1)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-9 (P1): on restart, `node.py:_load_snapshot_if_needed` "
    "calls `start_background_validation` if a chainstate_snapshot/ "
    "exists, but does NOT repopulate `sm.snapshot_height` from disk. "
    "Core's `LoadAssumeutxoChainstate` (`validation.cpp:6151-6168`) "
    "reads the on-disk base_blockhash and reconstructs the in-memory "
    "snapshot chainstate.",
    strict=True,
)
def test_w138_g17_cross_restart_snapshot_height_init() -> None:
    """G17 (BUG-9): node.py should populate sm.snapshot_height on
    restart from the on-disk base_blockhash → assumeutxo lookup.
    """
    src = _read_py("node.py")
    m = re.search(
        r"async def _load_snapshot_if_needed[\s\S]*?(?=async def |def )", src
    )
    assert m, "G17: _load_snapshot_if_needed not located"
    body = m.group(0)
    # On the early-return path (`has_snapshot_chainstate`), we should
    # repopulate snapshot_height via chainparams lookup.
    has_repopulate = (
        "get_assumeutxo_by_hash" in body
        and "snapshot_height" in body
        and "existing_hash" in body
    )
    assert has_repopulate, (
        "G17 BUG-9: cross-restart re-init does not repopulate "
        "snapshot_height from disk"
    )


# ===========================================================================
# G18 — MaybeValidateSnapshot fatal-on-mismatch (BUG-10, P0-CONSENSUS)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-10 (P0-CONSENSUS): when background validation "
    "reaches the snapshot tip and the recomputed UTXO hash does NOT "
    "match `au_data.hash_serialized`, ouroboros only logs an error "
    "and sets `background_validated = False`. Core's "
    "`handle_invalid_snapshot` (`validation.cpp:5987-6018`) RENAMES "
    "the chainstate dir to `<dir>_INVALID`, calls `fatalError`, and "
    "shuts down — explicit fatal-stop to prevent serving a corrupted "
    "snapshot. ouroboros continues serving.",
    strict=True,
)
def test_w138_g18_background_validation_fatal_on_mismatch() -> None:
    """G18 (BUG-10): background validation hash mismatch must trigger
    a directory rename to `<chainstate_snapshot>_INVALID` and a
    fatal-error path that stops the node.
    """
    src = _read_py("snapshot.py")
    # Look for an `_INVALID` rename or a fatal-error invocation in the
    # validation_worker.
    has_invalid_rename = bool(
        re.search(r"_INVALID|InvalidateCoinsDBOnDisk", src)
    )
    has_fatal_path = bool(
        re.search(r"sys\.exit|fatal[_\-]?error|shut[a-zA-Z_]*down", src)
    )
    assert has_invalid_rename and has_fatal_path, (
        "G18 BUG-10: no chainstate_snapshot_INVALID rename + no "
        "fatal-error path on background-validation mismatch"
    )


# ===========================================================================
# G19 — ValidatedSnapshotCleanup chainstate dir swap (BUG-11, P1)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-11 (P1): after successful background validation, "
    "Core's `ValidatedSnapshotCleanup` "
    "(`validation.cpp:6280-6345`) MOVES `chainstate/` → "
    "`chainstate_todelete`, MOVES `chainstate_snapshot/` → "
    "`chainstate/`, deletes the old. ouroboros keeps "
    "`chainstate_snapshot/` indefinitely; every restart "
    "re-detects `has_snapshot_chainstate() == True`.",
    strict=True,
)
def test_w138_g19_validated_snapshot_cleanup_dir_swap() -> None:
    """G19 (BUG-11): on successful background validation, the
    snapshot chainstate dir must be promoted to the canonical
    chainstate dir.
    """
    src = _read_py("snapshot.py")
    # Look for an os.rename / os.replace of chainstate_snapshot → chainstate
    has_swap = bool(
        re.search(
            r"os\.(rename|replace)\([^,]+chainstate_snapshot[^,]+,[^,]+chainstate",
            src,
        )
    )
    assert has_swap, (
        "G19 BUG-11: no chainstate_snapshot → chainstate directory "
        "swap on successful background validation"
    )


# ===========================================================================
# G20 — Background validation worker re-validates blocks (BUG-12,
#       P0-CONSENSUS)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-12 (P0-CONSENSUS): `validation_worker` "
    "(`snapshot.py:1100-1112`) iterates `range(target_height + 1)` "
    "and counts heights; it does NOT actually re-validate any "
    "block. Core's background chainstate "
    "(`validation.cpp:6398-6404`) calls `ActivateBestChain` which "
    "re-runs `ConnectBlock` end-to-end for every block from genesis "
    "to the snapshot tip. A corrupted snapshot would never be "
    "detected by ouroboros's stub.",
    strict=True,
)
def test_w138_g20_background_validation_actually_validates() -> None:
    """G20 (BUG-12): the validation worker must invoke real block
    validation (e.g. `BlockValidator.validate_block`) for each
    height from 0 to the snapshot tip.
    """
    src = _read_py("snapshot.py")
    m = re.search(r"def validation_worker[\s\S]*?finally:", src)
    assert m, "G20: validation_worker not located"
    body = m.group(0)
    # Must call into real validation
    invokes_validator = bool(
        re.search(
            r"validate_block\(|connect_block\(|BlockValidator", body
        )
    )
    assert invokes_validator, (
        "G20 BUG-12: validation_worker does not invoke "
        "validate_block / connect_block — it is a stub counter"
    )


# ===========================================================================
# G21 — Per-coin vout < uint32::max bound (BUG-13, P2)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-13 (P2): Core "
    "`PopulateAndValidateSnapshot:5811` rejects "
    "`outpoint.n >= numeric_limits<uint32>::max()` to avoid "
    "wraparound in coinstats. ouroboros relies on the looser "
    "MAX_SIZE = 0x02000000 CompactSize cap; an explicit uint32-max "
    "check is missing.",
    strict=True,
)
def test_w138_g21_vout_uint32_max_check() -> None:
    """G21 (BUG-13): per-coin vout must be checked against
    uint32::max explicitly.
    """
    src = _read_py("snapshot.py")
    # Look for any uint32::max check or 0xffffffff comparison on vout
    has_check = bool(
        re.search(r"vout\s*>=?\s*(0xffffffff|0xFFFFFFFF|2\s*\*\*\s*32)", src)
    )
    assert has_check, (
        "G21 BUG-13: no explicit `vout >= 0xFFFFFFFF` check on coin "
        "outpoint"
    )


# ===========================================================================
# G22 — Periodic FlushSnapshotToDisk during load (BUG-14, P1)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-14 (P1): Core "
    "`PopulateAndValidateSnapshot:5840-5856` checks "
    "`GetCoinsCacheSizeState()` every 120,000 coins and flushes "
    "leveldb if `CRITICAL`. ouroboros's loader writes per-coin via "
    "`db.add_utxo_raw` with NO periodic flush / NO checkpoint. "
    "Process kill mid-load leaves an inconsistent partial "
    "chainstate.",
    strict=True,
)
def test_w138_g22_periodic_flush_during_load() -> None:
    """G22 (BUG-14): the load_snapshot path must call a flush-to-disk
    primitive periodically (every N coins).
    """
    src = _read_py("snapshot.py")
    m = re.search(
        r"def load_snapshot[\s\S]*?return metadata", src
    )
    assert m, "G22: load_snapshot not located"
    body = m.group(0)
    has_periodic_flush = bool(
        re.search(
            r"%\s*120_?000\s*==\s*0|flush\(|FlushSnapshotToDisk",
            body,
        )
    )
    assert has_periodic_flush, (
        "G22 BUG-14: load_snapshot has no periodic flush in the "
        "per-coin loop"
    )


# ===========================================================================
# G23 — m_chain_tx_count propagated to block index (BUG-15, P1)
# ===========================================================================


def test_w138_g23_chain_tx_count_field_exists() -> None:
    """G23 (PRESENT-PART): AssumeutxoData carries `chain_tx_count`."""
    snap = _snapshot()
    h840 = next(
        p for p in snap.get_assumeutxo_params("mainnet") if p.height == 840_000
    )
    assert h840.chain_tx_count == 991_032_194


@pytest.mark.xfail(
    reason="W138 BUG-15 (P1): `AssumeutxoData.chain_tx_count` is "
    "defined but no code reads it into the block index. Core "
    "`validation.cpp:5949` writes "
    "`index->m_chain_tx_count = au_data.m_chain_tx_count`. "
    "ouroboros's `getblockchaininfo` / `getchaintxstats` / "
    "`getblockstats` will report wrong cumulative tx counts on a "
    "snapshot-loaded node.",
    strict=True,
)
def test_w138_g23_chain_tx_count_written_to_block_index() -> None:
    """G23 (BUG-15): snapshot load must write `chain_tx_count` into
    the snapshot tip's block index entry.
    """
    src_snap = _read_py("snapshot.py")
    src_node = _read_py("node.py")
    src_rpc = _read_py("rpc.py")
    full = src_snap + src_node + src_rpc
    # Look for any read of au_data.chain_tx_count → db setter
    has_write = bool(
        re.search(
            r"\.chain_tx_count[^\n]{0,200}(set_chain_tx_count|write_chain_tx|"
            r"update_block_index|m_chain_tx_count)",
            full,
        )
    )
    assert has_write, (
        "G23 BUG-15: chain_tx_count is never written into the block "
        "index after snapshot load"
    )


# ===========================================================================
# G24 — BLOCK_OPT_WITNESS / nStatus propagation (BUG-16, P2)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-16 (P2): Core "
    "`PopulateAndValidateSnapshot:5930-5945` walks the block index "
    "from AFTER_GENESIS_START to snapshot tip and sets "
    "`BLOCK_OPT_WITNESS` flag for segwit-active heights. ouroboros "
    "has no nStatus flag system; documented divergence from Core.",
    strict=True,
)
def test_w138_g24_block_opt_witness_propagation() -> None:
    """G24 (BUG-16): block index entries from AFTER_GENESIS_START to
    snapshot tip should carry a SegWit-active marker (Core's
    BLOCK_OPT_WITNESS).
    """
    src = _read_py("snapshot.py")
    has_segwit_walk = bool(
        re.search(
            r"BLOCK_OPT_WITNESS|DEPLOYMENT_SEGWIT|deployment.*segwit",
            src,
            re.I,
        )
    )
    assert has_segwit_walk, (
        "G24 BUG-16: no SegWit-active flag propagation walk after "
        "snapshot load"
    )


# ===========================================================================
# G25 — NetworkDisable applies to P2P, not just submitblock (BUG-17, P1)
# ===========================================================================


def test_w138_g25_network_disable_submitblock_gate() -> None:
    """G25 (PRESENT-PART): `block_submission_paused` flag gates
    rpc_submitblock during dumptxoutset rollback.
    """
    src = _read_py("rpc.py")
    assert "block_submission_paused" in src
    assert "NetworkDisable" in src, (
        "G25: NetworkDisable reference comment missing"
    )


@pytest.mark.xfail(
    reason="W138 BUG-17 (P1): `block_submission_paused` only gates "
    "`rpc_submitblock` + batch-submit; outbound P2P messaging "
    "(getheaders, getdata, etc.) continues during a rollback dump. "
    "Core's `NetworkDisable` "
    "(`rpc/blockchain.cpp:dumptxoutset:3155-3159`) disables P2P "
    "wholesale via `connman.OptionsForNetwork()`. A peer querying "
    "mid-dump can read inconsistent state.",
    strict=True,
)
def test_w138_g25_network_disable_p2p_gate() -> None:
    """G25 (BUG-17): `block_submission_paused` must also gate P2P
    outbound message dispatch during a rollback dump.
    """
    src = _read_py("p2p.py") + _read_py("peer.py") + _read_py("node.py")
    has_p2p_gate = bool(
        re.search(
            r"block_submission_paused[\s\S]{0,200}(send_|outbound|getheaders|"
            r"getdata|inv|block)",
            src,
        )
    )
    assert has_p2p_gate, (
        "G25 BUG-17: no P2P-side check of `block_submission_paused` "
        "to gate outbound message dispatch during rollback dumps"
    )


# ===========================================================================
# G26 — Pruned-mode pre-check before rollback dump
# ===========================================================================


def test_w138_g26_pruned_pre_check_before_rollback() -> None:
    """G26: pre-check rejects a rollback target below the prune
    horizon (Core `rpc/blockchain.cpp:dumptxoutset` pruned-mode
    check).

    PRESENT — `rpc.py:11015-11038`.
    """
    src = _read_py("rpc.py")
    assert "Block height" in src and "(pruned data)" in src, (
        "G26: pruned-data rollback rejection message missing"
    )


# ===========================================================================
# G27 — reactivate_best_chain silent fallback (BUG-18, P1)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-18 (P1): When the Rust DB binding lacks "
    "`reactivate_best_chain`, the Python dumptxoutset path logs a "
    "warning and returns `chain_restored=False`. Core has no such "
    "fallback — the entire dump operation should error out cleanly "
    "(operator gets an actionable failure). Silent success with "
    "stuck chain is a foot-gun.",
    strict=True,
)
def test_w138_g27_reactivate_best_chain_hard_fail() -> None:
    """G27 (BUG-18): a missing `reactivate_best_chain` Rust binding
    must produce a hard RPC failure, not a silent success with
    `chain_restored=False`.
    """
    src = _read_py("rpc.py")
    # Look for an HTTPException raised on missing reactivate_best_chain
    m = re.search(
        r"hasattr\(rust_db,\s*[\"']reactivate_best_chain[\"']\)",
        src,
    )
    assert m, "G27: reactivate_best_chain branch not located"
    # The else-branch should raise, not just log+warn
    # Find the surrounding ~400 chars to see the else
    start = max(0, m.start() - 200)
    end = min(len(src), m.end() + 600)
    block = src[start:end]
    raises_on_missing = bool(
        re.search(r"raise HTTPException", block)
    )
    assert raises_on_missing, (
        "G27 BUG-18: missing reactivate_best_chain is downgraded to "
        "a warning instead of raising HTTPException"
    )


# ===========================================================================
# G28 — Mempool transfer between chainstates (BUG-19, P2)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-19 (P2): Core's `AddChainstate` "
    "(`validation.cpp:6181-6185`) TRANSFERS the mempool from the "
    "IBD chainstate to the snapshot chainstate via `std::swap`. "
    "ouroboros has no chainstate-level mempool; the mempool is "
    "attached to the Node. Race window: a tx accepted in the same "
    "instant as loadtxoutset fires lands in mempool while the "
    "loader is mid-flight.",
    strict=True,
)
def test_w138_g28_mempool_chainstate_transfer() -> None:
    """G28 (BUG-19): on snapshot activation, the mempool must be
    paused or transferred to the new chainstate.
    """
    src = _read_py("snapshot.py") + _read_py("node.py") + _read_py("rpc.py")
    has_transfer = bool(
        re.search(
            r"mempool[\s\S]{0,80}(transfer|swap|pause|lock).*snapshot",
            src,
            re.I,
        )
    )
    assert has_transfer, (
        "G28 BUG-19: no mempool transfer/pause around snapshot load"
    )


# ===========================================================================
# G29 — Two-pipeline divergence (BUG-20 a/b/c/d, P0-CDIV)
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-20a (P0-CDIV): Rust pipeline ships placeholder "
    "AssumeutxoData with INVENTED hash_serialized "
    "(`2d6b0d7a5c4e8f90a3b5c7d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0` "
    "instead of Core's "
    "`a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96` "
    "at mainnet h=840000), and fake testnet4 h=50000 entry that "
    "doesn't exist in Core. Any caller of the Rust binding gets "
    "garbage.",
    strict=True,
)
def test_w138_g29_rust_assumeutxo_data_matches_core() -> None:
    """G29 (BUG-20a): Rust `get_assumeutxo_params` must return the
    same entries (and same `hash_serialized` values) as Core's
    `m_assumeutxo_data`.
    """
    rust_src = _read_rust("sync/src/storage/snapshot.rs")
    # Verify Core's canonical mainnet h=840000 hash_serialized is
    # present in the Rust placeholder table.
    canonical = "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
    placeholder = "2d6b0d7a5c4e8f90a3b5c7d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
    if placeholder in rust_src.lower():
        pytest.fail(
            "G29 BUG-20a: Rust snapshot.rs still ships placeholder "
            f"hash_serialized {placeholder!r}; expected Core's "
            f"{canonical!r} for mainnet h=840000."
        )
    assert canonical in rust_src.lower(), (
        "G29 BUG-20a: canonical Core hash_serialized for mainnet "
        f"h=840000 not found in Rust snapshot.rs"
    )


@pytest.mark.xfail(
    reason="W138 BUG-20b (P0-CVE-class): "
    "`PyBlockchainDB::import_core_snapshot` "
    "(`lib.rs:4679-4881`) is the operator-facing fast path. It "
    "validates ONLY snapshot magic + version + (optional) network "
    "magic. Skips: per-coin `coin_height > base_height`, "
    "MoneyRange, trailing-bytes-after-coins, HASH_SERIALIZED "
    "commitment. An operator running "
    "`ouroboros import-snapshot` against a malicious file gets "
    "their chainstate poisoned with no warning.",
    strict=True,
)
def test_w138_g29_import_core_snapshot_enforces_per_coin_bounds() -> None:
    """G29 (BUG-20b): import_core_snapshot must enforce the same
    per-coin bounds as the Python loader.
    """
    rust_src = _read_rust("sync/src/lib.rs")
    m = re.search(
        r"fn import_core_snapshot[\s\S]*?Ok\(\(block_hash_hex",
        rust_src,
    )
    assert m, "G29: import_core_snapshot not located in lib.rs"
    body = m.group(0)
    # Look for per-coin height bound, MoneyRange, and trailing-bytes
    has_height_bound = bool(re.search(r"coin_height\s*>\s*base_height", body))
    has_money_range = bool(re.search(r"MAX_MONEY|MoneyRange", body))
    has_trailing = bool(re.search(r"leftover|left[\s_]*over|left.over", body, re.I))
    has_hash_commit = bool(re.search(r"hash_serialized", body))
    missing = []
    if not has_height_bound:
        missing.append("per-coin height>base_height")
    if not has_money_range:
        missing.append("MoneyRange")
    if not has_trailing:
        missing.append("trailing-bytes")
    if not has_hash_commit:
        missing.append("HASH_SERIALIZED commitment")
    assert not missing, (
        f"G29 BUG-20b: import_core_snapshot missing checks: {missing}"
    )


@pytest.mark.xfail(
    reason="W138 BUG-20d (P1): Rust `compute_utxo_hash` "
    "(`snapshot.rs:646-684`) uses non-Core element encoding "
    "(u64-LE code + LE value + u32-LE script_len) and single "
    "SHA-256. Core's `TxOutSer` (`coinstats.cpp:46-51`) uses "
    "VARINT(code) + raw value + VARINT(script_len) + script, and "
    "SHA256d. The Rust digest will NEVER match Core's "
    "`hashSerialized` for the same UTXO set.",
    strict=True,
)
def test_w138_g29_rust_compute_utxo_hash_matches_core() -> None:
    """G29 (BUG-20d): Rust `compute_utxo_hash` must implement
    Core's TxOutSer + SHA256d.
    """
    rust_src = _read_rust("sync/src/storage/snapshot.rs")
    m = re.search(
        r"pub fn compute_utxo_hash[\s\S]*?Ok\(hash\.to_byte_array\(\)\)",
        rust_src,
    )
    assert m, "G29: compute_utxo_hash not located"
    body = m.group(0)
    # Must use VARINT encoding for code + script_len, not LE bytes
    uses_varint = bool(re.search(r"varint|VarInt|encode_corevarint", body))
    # Must double-hash (SHA256d), not single SHA-256
    is_sha256d = bool(
        re.search(r"sha256d|SHA256d|finalize.*sha256.*sha256", body, re.I)
    )
    assert uses_varint and is_sha256d, (
        "G29 BUG-20d: Rust compute_utxo_hash uses non-Core encoding "
        f"(varint={uses_varint}, sha256d={is_sha256d})"
    )


# ===========================================================================
# G30 — Two-pipeline guard: Rust import_core_snapshot is operator-only
#       (10th extension of the ouroboros two-pipeline guard set)
# ===========================================================================


def test_w138_g30_two_pipeline_assumeutxo_rust_isolation() -> None:
    """G30: TWO-PIPELINE GUARD (10th extension).

    The Rust pipeline's `import_core_snapshot` symbol may be invoked
    ONLY from `cli.py` (operator CLI path). No other Python module
    under `src/ouroboros/` may use it. The authoritative path for
    live ouroboros runs is `SnapshotManager.load_snapshot` (Python).

    Additionally pins the OPEN-BUG observation: the Rust
    `AssumeutxoData` table (`snapshot.rs:118-152`) is documented as
    stale/placeholder. Future regression that switches Python live
    code to consume Rust's `get_assumeutxo_*` would trip this guard
    and force a re-evaluation (the cleanup is BUG-20a/c/d under
    W138 — either delete the Rust table or repopulate it).

    Extends the guard set:
      W76 + W120 + W122 + W125 + W128 + W129 + W130 + W131 +
      W133 + W137 → W138 (10th extension).
    """
    violations = []

    # 1. import_core_snapshot may only be invoked from cli.py.
    for py in SRC_OUROBOROS.rglob("*.py"):
        if py.name in {"cli.py"}:
            continue
        if "tests" in py.parts:
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        if "import_core_snapshot" in text:
            violations.append(
                f"{py}: imports / references import_core_snapshot outside cli.py"
            )

    # 2. Rust `get_assumeutxo_data` / `get_assumeutxo_by_blockhash` /
    #    `get_available_snapshot_heights` (the PyO3 bindings) must NOT
    #    be imported from Python. Python uses the in-process
    #    `ouroboros.snapshot.get_assumeutxo_*` helpers.
    forbidden_rust_imports = (
        "sync.get_assumeutxo_data",
        "sync.get_assumeutxo_by_blockhash",
        "sync.get_available_snapshot_heights",
        "from sync import get_assumeutxo_data",
        "from sync import get_assumeutxo_by_blockhash",
        "from sync import get_available_snapshot_heights",
    )
    for py in SRC_OUROBOROS.rglob("*.py"):
        if "tests" in py.parts:
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        for forbidden in forbidden_rust_imports:
            if forbidden in text:
                violations.append(f"{py}: imports forbidden Rust binding {forbidden!r}")

    # 3. Rust `compute_utxo_hash` (snapshot.rs) must NOT be called
    #    from Python. Python uses `ouroboros.snapshot.compute_utxo_hash`.
    for py in SRC_OUROBOROS.rglob("*.py"):
        if "tests" in py.parts:
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        # Only flag the Rust binding; the Python compute_utxo_hash is fine.
        if re.search(r"\bsync\.compute_utxo_hash\b", text):
            violations.append(f"{py}: calls Rust sync.compute_utxo_hash")

    assert not violations, (
        "G30 W138 two-pipeline guard (10th extension) violations:\n"
        + "\n".join(f"  - {v}" for v in violations)
        + "\n\nassumeUTXO live runs MUST use the Python "
        "SnapshotManager. The Rust import_core_snapshot path is "
        "operator-only (cli.py). Re-evaluate this guard if/when the "
        "Rust pipeline's AssumeutxoData table is repopulated from "
        "Core (BUG-20a/c/d closure)."
    )


# ===========================================================================
# Trailer: BUG-22 dumped-snapshot byte-identity assumption
# ===========================================================================


@pytest.mark.xfail(
    reason="W138 BUG-22 (P2): `dump_snapshot` "
    "(`snapshot.py:1207-1226`) sorts UTXOs grouped by txid + within "
    "group by vout. The inter-group ordering assumes "
    "RocksDB iter_utxos yields entries in `txid LE 32 || vout LE 4` "
    "key order (matching Core's CCoinsViewCursor over leveldb). "
    "This is true today but UNTESTED — no regression guard.",
    strict=True,
)
def test_w138_bug22_dump_inter_txid_order_documented() -> None:
    """BUG-22 documentation: the inter-txid sort order should have a
    regression test that compares output against a known-good Core
    snapshot byte-for-byte.
    """
    src = _read_py("snapshot.py")
    # Look for an explicit sort-key on raw txid bytes for inter-group
    # ordering.
    has_sort = bool(
        re.search(
            r"sorted\(\s*utxo_groups\.keys\(\)\s*\)|sort_by_key.*txid",
            src,
        )
    )
    assert has_sort, (
        "BUG-22: no explicit inter-txid sort assertion in dump_snapshot"
    )
    # Look for a tools/snapshot-byte-identity.sh reference or a
    # regression-test marker.
    has_byte_identity_test = bool(
        re.search(r"snapshot[-_]byte[-_]identity|byte_identity", src)
    )
    assert has_byte_identity_test, (
        "BUG-22: no byte-identity regression test referenced"
    )
