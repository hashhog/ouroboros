"""Regression tests for the assumeUTXO-snapshot chainwork undercounting bug.

Incident (2026-05-19): ouroboros was bricked on mainnet — every headers
batch was rejected with ``too-little-chainwork; G8`` and 1500+ honest peers
were banned.  Root cause: a node bootstrapped from an assumeUTXO snapshot at
height 944183 never persisted the snapshot block's ``BlockMetadata``.  The
Rust ``connect_block_from_bytes`` derives every block's chainwork as
``compute_chainwork(prev_block_metadata.chainwork, bits)`` and falls back to a
0 base when the parent's metadata is missing — so the whole post-snapshot
chain accumulated proof-of-work from 0 instead of from the snapshot's true
cumulative work.  The stored cumulative chainwork at the tip ended up ~32x
below reality, falling under ``nMinimumChainWork``.

This was bug **(A) undercounting**, NOT a wrong ``nMinimumChainWork``
constant — ouroboros's constant exactly matches Bitcoin Core's mainnet
``kernel/chainparams.cpp`` value.

Fixes verified here:
  * ``snapshot.load_snapshot`` now persists the snapshot block's chainwork
    metadata (root cause — future syncs accumulate correctly).
  * ``snapshot.detect_snapshot_chainwork_offset`` detects an already-corrupt
    datadir and returns the additive correction.
  * The G8 gate in ``block_sync`` applies that offset so an existing bricked
    datadir is un-bricked without a full re-sync.

These tests are pure Python (no compiled Rust extension required).
"""

from __future__ import annotations

import struct
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path + sync-module mock so `ouroboros` imports without the Rust extension.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

from ouroboros.snapshot import (  # noqa: E402
    detect_snapshot_chainwork_offset,
    get_assumeutxo_data,
    get_assumeutxo_params,
)


# ---------------------------------------------------------------------------
# Ground-truth constants.
# ---------------------------------------------------------------------------

# Bitcoin Core mainnet consensus.nMinimumChainWork — verbatim from
# bitcoin-core/src/kernel/chainparams.cpp:109 (Core 28.x line).
CORE_MAINNET_MIN_CHAIN_WORK = int(
    "0000000000000000000000000000000000000001128750f82f4c366153a3a030", 16
)

# Observed state from the live incident log
# (/data/nvme1/hashhog-mainnet/logs/ouroboros.log, 2026-05-20 08:30):
#   node tip height = 948464
#   stored DB-tip "base" chainwork (undercounted, ~32x too small)
INCIDENT_TIP_HEIGHT = 948_464
INCIDENT_STORED_BASE = int(
    "0000000000000000000000000000000000000000000813a54077e0ad0d8039eea3"[-64:],
    16,
)
# headers term of one rejected batch (1770 headers) — correctly computed
INCIDENT_HEADERS_WORK = int(
    "00000000000000000000000000000000000000000034b4e4ac275145d913d22ba"[-64:],
    16,
)


# ---------------------------------------------------------------------------
# Bitcoin Core's GetBitsProof — reference implementation for cross-checking.
# Mirrors bitcoin-core/src/chain.cpp:121-134.
# ---------------------------------------------------------------------------


def _core_bits_to_work(bits: int) -> int:
    """Reference: work = (~target / (target + 1)) + 1 over 256-bit ints."""
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF
    if mantissa == 0:
        return 0
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target <= 0:
        return 0
    not_target = ((1 << 256) - 1) - target
    return (not_target // (target + 1)) + 1


# ---------------------------------------------------------------------------
# Part 1 — it is bug (A), not bug (B): the nMinimumChainWork constant is right.
# ---------------------------------------------------------------------------


def test_minimum_chain_work_constant_matches_core_mainnet() -> None:
    """The Rust mainnet nMinimumChainWork equals Core's chainparams value.

    ``chain_params.rs`` stores it as a truncated hex literal
    (``"0001128750f82f4c366153a3a030"``) parsed into a U256; zero-extended
    to 256 bits that is byte-identical to Core's mainnet constant.  This
    pins that the incident was undercounting (A), never a bad constant (B).
    """
    rust_src = (
        REPO_ROOT / "ferrous-utils" / "sync" / "src" / "chain_params.rs"
    ).read_text(encoding="utf-8")
    # The mainnet arm parses this hex literal.
    assert '"0001128750f82f4c366153a3a030"' in rust_src, (
        "mainnet nMinimumChainWork literal missing/changed in chain_params.rs"
    )
    parsed = int("0001128750f82f4c366153a3a030", 16)
    assert parsed == CORE_MAINNET_MIN_CHAIN_WORK, (
        f"ouroboros mainnet nMinimumChainWork {parsed:#x} != "
        f"Core {CORE_MAINNET_MIN_CHAIN_WORK:#x}"
    )


# ---------------------------------------------------------------------------
# Part 2 — the per-block work formula is correct (the bug is NOT here).
# ---------------------------------------------------------------------------


def test_bits_to_work_matches_core_genesis() -> None:
    """GetBlockProof for the genesis difficulty matches the known value.

    Bitcoin Core: chainwork at genesis (bits 0x1d00ffff) = 0x0000000100010001.
    """
    work = _core_bits_to_work(0x1D00FFFF)
    assert work == 0x0000000100010001, f"genesis work wrong: {work:#x}"


def test_bits_to_work_matches_recent_mainnet_block() -> None:
    """GetBlockProof for a recent mainnet target is in the expected range.

    The snapshot at h=944183 uses bits 0x17020684.  Its per-block work must
    be a 256-bit value of the right magnitude (~5e23), confirming the
    formula does not lose a power-of-two of precision.
    """
    work = _core_bits_to_work(0x17020684)
    # Sanity band: recent mainnet blocks contribute ~3-8 x 10^23 work each.
    assert 3 * 10**23 < work < 9 * 10**23, f"recent block work off-band: {work}"


def test_block_sync_bits_to_work_agrees_with_core() -> None:
    """``BlockSync._bits_to_work`` (the G8 gate's per-block fn) == Core.

    Imported directly from the production module to guard against drift.
    """
    from ouroboros.block_sync import BlockSync

    for bits in (0x1D00FFFF, 0x1B0404CB, 0x1A05DB8B, 0x17020684, 0x17030CE9):
        assert BlockSync._bits_to_work(bits) == _core_bits_to_work(bits), (
            f"_bits_to_work disagrees with Core for bits {bits:#010x}"
        )


# ---------------------------------------------------------------------------
# Part 3 — the snapshot carries a chainwork well above nMinimumChainWork.
# ---------------------------------------------------------------------------


def test_mainnet_snapshot_chainwork_exceeds_minimum() -> None:
    """The h=944183 snapshot's chainwork is far above nMinimumChainWork.

    A correct node at any height >= 944183 therefore MUST report cumulative
    work above nMinimumChainWork — exactly what the incident node failed to
    do because the snapshot base was dropped.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None, "mainnet 944183 assumeUTXO entry missing"
    assert au.chainwork_hex is not None, "snapshot chainwork_hex unset"
    snap_work = int(au.chainwork_hex, 16)
    assert snap_work > CORE_MAINNET_MIN_CHAIN_WORK, (
        f"snapshot chainwork {snap_work:#x} should exceed "
        f"nMinimumChainWork {CORE_MAINNET_MIN_CHAIN_WORK:#x}"
    )


def test_mainnet_snapshot_base_header_timestamp_parses() -> None:
    """The snapshot base_header is 80 bytes and its timestamp is sane.

    ``load_snapshot`` reads the snapshot block's timestamp from byte
    offset 68 of ``base_header`` when persisting BlockMetadata.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.base_header is not None
    assert len(au.base_header) == 80
    ts = struct.unpack_from("<I", au.base_header, 68)[0]
    bits = struct.unpack_from("<I", au.base_header, 72)[0]
    # 2026-04-29-ish; comfortably between 2025 and 2030.
    assert 1_700_000_000 < ts < 1_900_000_000, f"snapshot ts off-band: {ts}"
    assert bits == 0x17020684, f"snapshot bits unexpected: {bits:#x}"


# ---------------------------------------------------------------------------
# Part 4 — detect_snapshot_chainwork_offset behaviour.
# ---------------------------------------------------------------------------


class _FakeDB:
    """Minimal stand-in exposing only get_chainwork_by_height."""

    def __init__(self, chainwork_by_height: dict[int, int]):
        self._cw = chainwork_by_height

    def get_chainwork_by_height(self, height: int) -> int:
        return self._cw.get(height, 0)


def test_offset_detected_for_corrupt_snapshot_datadir() -> None:
    """A datadir that dropped the snapshot base is detected; offset returned.

    Simulate the incident: the block at snap_h+1 stored only ~one block of
    work (because it chained from a 0 base).  The detector must return the
    snapshot height's canonical chainwork as the correction.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    snap_h = au.height
    correct_snap_work = int(au.chainwork_hex, 16)

    # Stored value at snap_h+1 is tiny — only the first post-snapshot block.
    db = _FakeDB({snap_h + 1: _core_bits_to_work(0x17020684)})
    offset = detect_snapshot_chainwork_offset(db, "mainnet")
    assert offset == correct_snap_work, (
        f"offset {offset:#x} should equal snapshot chainwork "
        f"{correct_snap_work:#x}"
    )


def test_no_offset_for_correct_datadir() -> None:
    """A datadir whose snapshot base WAS applied needs no correction.

    When the stored chainwork at snap_h+1 already exceeds the snapshot
    chainwork (base applied), the detector returns 0.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    snap_h = au.height
    correct_snap_work = int(au.chainwork_hex, 16)

    # Correct datadir: snap_h+1 holds snapshot work + one block's work.
    db = _FakeDB(
        {snap_h + 1: correct_snap_work + _core_bits_to_work(0x17020684)}
    )
    assert detect_snapshot_chainwork_offset(db, "mainnet") == 0


def test_no_offset_when_no_block_above_snapshot() -> None:
    """No correction when sync has not progressed past the snapshot height
    AND we cannot establish the tip height (legacy _FakeDB has no
    get_best_block, so the detector falls through to the Case-2 snap_h+1
    probe, which sees nothing stored)."""
    db = _FakeDB({})  # nothing stored, no get_best_block
    assert detect_snapshot_chainwork_offset(db, "mainnet") == 0


class _FreshSnapshotDB(_FakeDB):
    """assumeUTXO datadir freshly bootstrapped via the Rust import-utxo CLI.

    The Rust ``import_core_snapshot`` sets the chain tip to the snapshot
    height with ``update_best_block`` but NEVER persists a BLOCK_INDEX_CF
    metadata row for the snapshot block — so every height (including the
    snapshot height itself) reads chainwork 0, and there is NO block above
    the snapshot yet because forward-sync has not started.  This is the
    exact on-disk state behind the 2026-05-29 phaseb snapshot-confirm
    DIVERGENCE: the node held at 944183, every headers batch was rejected
    ``too-little-chainwork; G8``, and every honest peer that served headers
    was banned until the addrman drained to 0 connections.
    """

    def __init__(self, tip_height: int, chainwork_by_height: dict[int, int]):
        super().__init__(chainwork_by_height)
        self._tip_height = tip_height

    def get_best_block(self):
        return (b"\x00" * 32, self._tip_height)


def test_offset_detected_on_fresh_import_utxo_bootstrap() -> None:
    """Case 1 regression: tip == snap_h, NO metadata anywhere.

    Before the fix the detector probed only ``snap_h + 1`` — which does not
    exist on a fresh bootstrap (it is the very block we are about to
    forward-sync) — saw 0, and returned a 0 offset.  The G8 gate then ran
    with base==0 and rejected every honest headers batch, banning the peer
    that served them.  After the fix, a tip sitting exactly at the snapshot
    height with chainwork 0 there yields the canonical snapshot chainwork as
    the offset, so the G8 base term is non-zero and headers connect.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    snap_h = au.height
    correct_snap_work = int(au.chainwork_hex, 16)

    # Rust import-utxo state: tip at snap_h, no metadata row at any height.
    db = _FreshSnapshotDB(tip_height=snap_h, chainwork_by_height={})
    offset = detect_snapshot_chainwork_offset(db, "mainnet")
    assert offset == correct_snap_work, (
        f"fresh-bootstrap offset {offset:#x} should equal snapshot "
        f"chainwork {correct_snap_work:#x} (was 0 pre-fix → G8 brick)"
    )


def test_no_offset_on_fresh_bootstrap_with_correct_base_metadata() -> None:
    """Case 1, correct datadir: the Python load_snapshot path DID persist
    the snapshot block's chainwork at snap_h, so no offset is needed even
    though the tip sits exactly at the snapshot height."""
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    snap_h = au.height
    correct_snap_work = int(au.chainwork_hex, 16)

    db = _FreshSnapshotDB(
        tip_height=snap_h, chainwork_by_height={snap_h: correct_snap_work}
    )
    assert detect_snapshot_chainwork_offset(db, "mainnet") == 0


def test_no_offset_for_networks_without_snapshot_chainwork() -> None:
    """regtest/signet have no chainwork-bearing snapshot — always 0."""
    db = _FakeDB({1: 10**30})
    assert detect_snapshot_chainwork_offset(db, "regtest") == 0
    assert detect_snapshot_chainwork_offset(db, "signet") == 0


def test_offset_detection_never_raises_on_bad_db() -> None:
    """A DB whose get_chainwork_by_height throws must yield 0, not crash.

    Defense-in-depth: the G8 gate must never break header sync.
    """

    class _ExplodingDB:
        def get_chainwork_by_height(self, height: int) -> int:
            raise RuntimeError("simulated DB failure")

    assert detect_snapshot_chainwork_offset(_ExplodingDB(), "mainnet") == 0


# ---------------------------------------------------------------------------
# Part 5 — end-to-end: with the offset applied the G8 gate would now PASS.
# ---------------------------------------------------------------------------


def test_g8_gate_arithmetic_passes_after_offset_correction() -> None:
    """base + offset + headers must exceed nMinimumChainWork.

    Reproduces the rejected batch from the incident log and proves the
    corrected total clears the gate.  Pre-fix: base alone (~32x too small)
    + headers < nMinimumChainWork → reject every batch.  Post-fix:
    base + snapshot_offset + headers > nMinimumChainWork → accept.
    """
    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    offset = int(au.chainwork_hex, 16)

    # Pre-fix behaviour: the gate as it was — rejected.
    pre_fix_total = INCIDENT_STORED_BASE + INCIDENT_HEADERS_WORK
    assert pre_fix_total < CORE_MAINNET_MIN_CHAIN_WORK, (
        "incident precondition: uncorrected total must be below the minimum"
    )

    # Post-fix behaviour: same batch, snapshot offset added — accepted.
    post_fix_total = INCIDENT_STORED_BASE + offset + INCIDENT_HEADERS_WORK
    assert post_fix_total > CORE_MAINNET_MIN_CHAIN_WORK, (
        f"post-fix total {post_fix_total:#x} must exceed nMinimumChainWork "
        f"{CORE_MAINNET_MIN_CHAIN_WORK:#x} — G8 gate would still reject"
    )


def test_load_snapshot_persists_chainwork_metadata() -> None:
    """``load_snapshot`` calls store_block_metadata_persistent for the
    snapshot block with the canonical chainwork (root-cause fix).

    Source-level guard: the persistence call exists in the loader body and
    is wired to ``au_data.chainwork_hex``.
    """
    src = (
        REPO_ROOT / "src" / "ouroboros" / "snapshot.py"
    ).read_text(encoding="utf-8")
    assert "store_block_metadata_persistent" in src, (
        "load_snapshot must persist the snapshot block's BlockMetadata"
    )
    # The call must be fed from the snapshot's hardcoded chainwork.
    assert "int(au_data.chainwork_hex, 16)" in src


def test_database_wrapper_exposes_persistent_metadata_store() -> None:
    """``BlockchainDatabase`` exposes store_block_metadata_persistent.

    Without the wrapper the snapshot loader cannot reach the Rust
    ``store_block_metadata_raw`` symbol.
    """
    from ouroboros.database import BlockchainDatabase

    assert hasattr(BlockchainDatabase, "store_block_metadata_persistent")


def test_block_sync_g8_gate_applies_snapshot_offset() -> None:
    """The G8 gate computes a snapshot-offset-corrected base.

    Source-level guard against regressing to the raw uncorrected base that
    caused the brick.
    """
    src = (
        REPO_ROOT / "src" / "ouroboros" / "block_sync.py"
    ).read_text(encoding="utf-8")
    assert "_snapshot_chainwork_offset" in src
    # The corrected offset must be added into the G8 base term.
    assert "base_chain_work += " in src
