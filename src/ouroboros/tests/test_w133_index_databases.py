"""W133 — Index databases audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/index/base.{h,cpp},
  bitcoin-core/src/index/txindex.{h,cpp},
  bitcoin-core/src/index/coinstatsindex.{h,cpp},
  bitcoin-core/src/index/disktxpos.h,
  bitcoin-core/src/index/db_key.h.

Scope:
- txindex (Rust live path in ferrous-utils/sync/src/storage/db.rs +
  dead-code alternate in ferrous-utils/sync/src/storage/txindex.rs)
- coinstatsindex (entirely absent in both pipelines)
- BaseIndex abstraction (sync thread, locator, m_synced flag,
  prune lock, IndexSummary, BlockUntilSyncedToCurrentChain)

Excludes: blockfilterindex (W121).

This file contains an xfail test per Core-divergent gate; xfails
flip to XPASS the moment a fix lands. PRESENT gates are plain
asserts that pin Core-parity wiring (or pin the dead-code state
until BUG-1 is closed).

Reference: ouroboros/audit/w133_index_databases.md.

NO production code changes. NO behavior changes. Only audit + xfail.
"""

from __future__ import annotations

import inspect
import re
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
    """Read a file from ferrous-utils, returning empty string if absent
    (e.g. when ferrous-utils is not in the sdist)."""
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# ===========================================================================
# G1-G7 — BaseIndex abstraction surface
# ===========================================================================


@pytest.mark.xfail(
    reason="W133 BUG-2 (P1): No BaseIndex abstraction. tx_index writes are "
           "inline in connect_block_from_bytes; cannot reindex independently "
           "of chainstate, cannot start in background. See base.h:54-182.",
    strict=True,
)
def test_w133_g1_base_index_abstraction_present() -> None:
    """G1: A BaseIndex-like abstraction exists.

    Core: `class BaseIndex : public CValidationInterface` in
    `index/base.h:54` provides shared sync thread, m_synced flag,
    Init/Sync/Stop API, locator persistence, prune lock.

    Looks for an actual DEFINITION (struct/trait/class) not mere
    string mentions in comments — many doc comments in
    ouroboros reference Core's `BaseIndex::IsSynced` semantics.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")

    found = False
    for rs in FERROUS_UTILS.rglob("*.rs"):
        # Skip the dead-code alternate (storage/txindex.rs); it
        # defines its OWN local TxIndex struct unrelated to BaseIndex.
        text = rs.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^(pub\s+)?(struct|trait|enum)\s+BaseIndex\b", text, re.M):
            found = True
            break
        if re.search(r"^(pub\s+)?trait\s+Index\b", text, re.M):
            found = True
            break
    if not found:
        # Also check Python side
        for py in SRC_OUROBOROS.rglob("*.py"):
            if py.parts[-2] == "tests":
                continue
            text = py.read_text(encoding="utf-8", errors="replace")
            if re.search(r"^class\s+BaseIndex\b", text, re.M):
                found = True
                break
    assert found, (
        "G1: no BaseIndex abstraction in either pipeline; tx_index "
        "writes are inline in connect_block_from_bytes."
    )


@pytest.mark.xfail(
    reason="W133 BUG-6 (P1): No m_synced flag, no sync thread, no "
           "BlockConnected/ChainStateFlushed dispatch (base.cpp:328-422).",
    strict=True,
)
def test_w133_g2_sync_thread_and_synced_flag() -> None:
    """G2: Background sync thread + m_synced flag.

    Core: `m_thread_sync` runs `Sync()` (`base.cpp:201`); `m_synced`
    flag (`base.h:88`) latches true when the index catches up.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")
    rust_lib = _read_rust("sync/src/lib.rs")
    rust_db = _read_rust("sync/src/storage/db.rs")
    combined = rust_lib + rust_db
    has_synced = "m_synced" in combined or "is_synced" in combined or "index_synced" in combined
    has_thread = "thread_sync" in combined or "IndexThread" in combined
    assert has_synced and has_thread, (
        "G2: no m_synced flag and/or no sync thread for index"
    )


@pytest.mark.xfail(
    reason="W133 BUG-7 (P1): No BlockUntilSyncedToCurrentChain API; "
           "RPC callers cannot block on index catch-up (base.cpp:424-446).",
    strict=True,
)
def test_w133_g3_block_until_synced_to_current_chain() -> None:
    """G3: BlockUntilSyncedToCurrentChain RPC-level API.

    Core: `BaseIndex::BlockUntilSyncedToCurrentChain()` is the
    canonical caller-side wait for index catch-up. ouroboros exposes
    no equivalent.
    """
    import ouroboros.database as db_mod
    assert hasattr(db_mod.BlockchainDatabase, "block_until_synced_to_current_chain"), (
        "G3: BlockchainDatabase lacks block_until_synced_to_current_chain"
    )


def test_w133_g4_rpc_getindexinfo_empty_bug3() -> None:
    """G4 (BUG-3 P1, NOW FIXED): rpc_getindexinfo emits per-index status so
    operators can verify each running index is caught up.

    Core (src/rpc/node.cpp:363-410 + SummaryToJSON:351-361): getindexinfo
    returns a dynamic object keyed by index name; each value has EXACTLY
    ``{ "synced": bool, "best_block_height": int }`` (in that order) and an
    index appears only when running. The previous stub returned ``{}``; this
    test now pins the FIXED Core-shaped handler.
    """
    src = _read_py("rpc.py")
    m = re.search(
        r"async def rpc_getindexinfo[\s\S]+?(?=\n    async def |\n    def |\Z)",
        src,
    )
    assert m, "G4: rpc_getindexinfo not found"
    body = m.group(0)
    # The fixed handler emits the Core per-index value fields.
    assert '"synced"' in body, (
        "G4 REGRESSION: getindexinfo no longer emits the 'synced' field"
    )
    assert '"best_block_height"' in body, (
        "G4 REGRESSION: getindexinfo no longer emits 'best_block_height'"
    )
    # Honours the optional index_name filter (positional arg 0).
    assert "index_name" in body, (
        "G4 REGRESSION: getindexinfo dropped the index_name filter arg"
    )
    # Wires the real txindex substrate (must not be a hardcoded stub).
    assert "txindex" in body, (
        "G4 REGRESSION: getindexinfo no longer reports the txindex"
    )
    # Bug signature must be gone: the body is no longer a bare ``return {}``
    # stub (it now builds and returns a populated result dict).
    assert re.search(r"\"\"\"\s*\n\s*return \{\}\s*$", body) is None, (
        "G4 BUG-3 regressed: getindexinfo is back to the empty-dict stub"
    )


@pytest.mark.xfail(
    reason="W133 BUG-4 (P1): No per-index DB_BEST_BLOCK CBlockLocator "
           "persistence; index relies on META_CF::BEST_BLOCK_HASH "
           "(base.cpp:78-93,270-288).",
    strict=True,
)
def test_w133_g5_db_best_block_locator() -> None:
    """G5: Per-index `DB_BEST_BLOCK` locator persistence.

    Core writes a CBlockLocator (not just a hash) so the index can
    recover its catch-up point across restarts where the chainstate
    may have rewound or advanced.
    """
    rust = _read_rust("sync/src/storage/db.rs")
    assert "DB_BEST_BLOCK" in rust or "block_locator" in rust.lower(), (
        "G5: no DB_BEST_BLOCK / block_locator key for the index"
    )


@pytest.mark.xfail(
    reason="W133 BUG-8 (P2): No per-index DB obfuscation key. Core "
           "wraps DB in CDBWrapper{.obfuscate=true} (base.cpp:68-76).",
    strict=True,
)
def test_w133_g6_db_obfuscation_for_index() -> None:
    """G6: Per-index DB obfuscation (bytes-at-rest non-trivially
    inspectable)."""
    rust = _read_rust("sync/src/storage/db.rs")
    assert "obfuscat" in rust.lower(), (
        "G6: no obfuscation key in storage layer"
    )


def test_w133_g7_tx_index_cf_present() -> None:
    """G7 (PRESENT): TX_INDEX_CF is defined in the live storage layer.

    Pins the live path against accidental rename/removal.
    """
    schema = _read_rust("sync/src/storage/schema.rs")
    assert 'TX_INDEX_CF: &str = "tx_index"' in schema, (
        "G7: TX_INDEX_CF constant missing from storage/schema.rs"
    )
    db = _read_rust("sync/src/storage/db.rs")
    assert "fn store_tx_index_batch(" in db
    assert "fn get_tx_index(" in db
    assert "fn delete_tx_index(" in db


# ===========================================================================
# G8-G12 — TxIndex semantics + storage shape
# ===========================================================================


@pytest.mark.xfail(
    reason="W133 BUG-14 (P1): tx_index writes the genesis coinbase txid. "
           "Core's TxIndex::CustomAppend returns early on height==0 "
           "(txindex.cpp:76-77). Cross-impl divergence on "
           "getrawtransaction <genesis-coinbase>.",
    strict=True,
)
def test_w133_g8_txindex_skips_genesis() -> None:
    """G8: tx_index must skip the genesis-block coinbase tx.

    Core: `if (block.height == 0) return true;` is the first line of
    `TxIndex::CustomAppend` (`txindex.cpp:77`). ouroboros writes the
    genesis txid into tx_index — see `validate/block.rs:838-840`
    comment that acknowledges the deliberate deviation.
    """
    block_rs = _read_rust("sync/src/validate/block.rs")
    lib_rs = _read_rust("sync/src/lib.rs")
    # Bug signature: the connect path writes tx_index unconditionally,
    # not gated on `height > 0`. Look for the call site, then verify
    # no surrounding `if height > 0` guard.
    # In validate/block.rs the store_tx_index_batch is at ~874; check
    # the preceding ~30 lines for a height==0 short-circuit.
    m = re.search(
        r"(.{0,800})self\.db\.store_tx_index_batch",
        block_rs,
    )
    assert m, "G8: store_tx_index_batch call site not found in validate/block.rs"
    preceding = m.group(1)
    # Must contain a height==0 early return / continue guard
    has_genesis_skip = bool(re.search(r"if\s+height\s*==\s*0\s*\{[^}]*return", preceding))
    assert has_genesis_skip, (
        "G8: tx_index write path does not skip height==0 (Core does)"
    )


def test_w133_g9_disk_tx_pos_byte_offset_partial_bug15() -> None:
    """G9 (BUG-15 P1): live tx_index stores tx_position as array
    INDEX, not byte offset.

    Core's CDiskTxPos = (file_number, block_offset, tx_byte_offset).
    ouroboros's live shape = (block_hash, height, tx_array_index).

    The unused `storage/txindex.rs` HAS the Core-shape DiskTxPos —
    pin that asymmetry here.
    """
    # Live shape: 32 + 4 + 4 = 40 bytes per row (block_hash + height + tx_pos)
    db = _read_rust("sync/src/storage/db.rs")
    assert "Vec::with_capacity(40)" in db, (
        "G9: live tx_index value layout changed from 40 bytes — "
        "audit framing may be stale"
    )
    # The dead-code alternate has the Core shape
    txindex_rs = _read_rust("sync/src/storage/txindex.rs")
    assert "file_number: i32" in txindex_rs and "tx_offset: u32" in txindex_rs, (
        "G9: dead-code storage/txindex.rs has been touched — re-audit"
    )


@pytest.mark.xfail(
    reason="W133 BUG-16 (P2): tx_index value uses fixed 4 LE bytes for "
           "tx_position; Core uses VARINT (disktxpos.h:17) yielding "
           "~12 bytes vs 40 bytes per row.",
    strict=True,
)
def test_w133_g10_disk_tx_pos_varint_serialize() -> None:
    """G10: CDiskTxPos serialized with VARINT for the nTxOffset field.

    Core: `READWRITE(AsBase<FlatFilePos>(obj), VARINT(obj.nTxOffset))`
    (`disktxpos.h:17`). ouroboros: fixed 4-byte LE encoding wastes
    ~28 bytes per row for small offsets.
    """
    db = _read_rust("sync/src/storage/db.rs")
    # Either uses VARINT/varint or has a comment justifying the
    # fixed-width choice with a reference to Core's encoding
    assert "varint" in db.lower() or "VARINT" in db, (
        "G10: no VARINT encoding for tx_position offset"
    )


@pytest.mark.xfail(
    reason="W133 BUG-17 (P1): No file-seek path for getrawtransaction; "
           "ouroboros reads full block + traverses txdata. Core's "
           "FindTx reads header + seeks nTxOffset (txindex.cpp:93-120).",
    strict=True,
)
def test_w133_g11_find_tx_file_seek_path() -> None:
    """G11: A file-seek tx lookup path exists (header read + seek + tx
    deserialize)."""
    rpc = _read_py("rpc.py")
    # Bug signature: lookup iterates `for block_tx in block.transactions`
    # rather than seeking by offset. A future fix would add a path that
    # seeks into the block file by tx_offset.
    assert "seek_to_tx_offset" in rpc or "find_tx_by_seek" in rpc, (
        "G11: no file-seek path for tx lookup"
    )


def test_w133_g12_dead_code_storage_txindex_rs_bug1() -> None:
    """G12 (PRESENT, BUG-1 P1 DEAD-CODE): the unused
    `storage/txindex.rs` module + PyTxIndex/PyDiskTxPos exist but are
    never instantiated.

    Pins the dead-code state until BUG-1 is closed (by either wiring
    it in OR deleting it).
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")
    txindex_rs = FERROUS_UTILS / "sync/src/storage/txindex.rs"
    assert txindex_rs.exists(), (
        "G12 BUG-1 may be closed: storage/txindex.rs was deleted — "
        "update audit to mark BUG-1 closed."
    )
    # No call site in Python that opens it
    py_database = _read_py("database.py")
    assert "PyTxIndex" not in py_database, (
        "G12 BUG-1 may be closed: PyTxIndex is now referenced in "
        "database.py — update audit"
    )
    # Confirm pyclass exists in Rust lib.rs
    lib_rs = _read_rust("sync/src/lib.rs")
    assert "pub struct PyTxIndex" in lib_rs, (
        "G12 BUG-1 may be partially fixed: PyTxIndex pyclass was "
        "removed; verify replacement"
    )


# ===========================================================================
# G13-G18 — Configuration + lifecycle: opt-in flag, reorg, prune lock
# ===========================================================================


@pytest.mark.xfail(
    reason="W133 BUG-13 (P2): No -txindex/-coinstatsindex opt-in flag. "
           "tx_index is always populated regardless of operator intent.",
    strict=True,
)
def test_w133_g13_txindex_optin_flag() -> None:
    """G13: -txindex opt-in flag honored.

    Core: `DEFAULT_TXINDEX{false}` (`txindex.h:19`); operator must
    pass `-txindex` to enable. ouroboros has no flag; tx_index is
    always written.
    """
    config_py = _read_py("config.py")
    cli_py = _read_py("cli.py")
    has_flag = "txindex" in config_py.lower() and "--txindex" in cli_py
    assert has_flag, (
        "G13: no -txindex flag in config.py / cli.py"
    )


def test_w133_g14_txindex_reorg_no_delete() -> None:
    """G14 (PRESENT — Core parity): tx_index entries are NOT deleted during
    reorg disconnect.

    Bitcoin Core's TxIndex has no CustomRemove override; the BaseIndex
    default (base.h:136) is a no-op, so txindex entries survive reorgs.
    getrawtransaction can therefore still resolve a tx from a disconnected
    block.  Ouroboros must match this behaviour.

    Reference:
      - bitcoin-core/src/index/txindex.cpp  (no CustomRemove method)
      - bitcoin-core/src/index/base.h:136   (CustomRemove returns true; no-op)
    """
    db = _read_rust("sync/src/storage/db.rs")
    # The per-block disconnect path must NOT call delete_tx_index
    assert "self.delete_tx_index(txid.as_byte_array())" not in db, (
        "G14 REGRESSION: disconnect path calls delete_tx_index — "
        "Core TxIndex keeps entries across reorgs (base.h:136 no-op)."
    )
    # The atomic batch disconnect path must NOT delete tx_index entries
    assert "batch.delete_cf(tx_index_cf, txid.as_byte_array())" not in db, (
        "G14 REGRESSION: atomic disconnect batch deletes tx_index entries — "
        "Core TxIndex keeps entries across reorgs (base.h:136 no-op)."
    )
    # validate/block.rs disconnect_block must NOT delete either
    block_rs = _read_rust("sync/src/validate/block.rs")
    assert "self.db.delete_tx_index(txid.as_byte_array())" not in block_rs, (
        "G14 REGRESSION: validate/block.rs::disconnect_block deletes "
        "tx_index entries — Core TxIndex keeps entries across reorgs."
    )


def test_w133_g15_txindex_atomic_with_chainstate() -> None:
    """G15 (PRESENT): tx_index writes are in the same WriteBatch as
    chainstate updates, so the index is never observably out of sync.

    Pins the architectural property that distinguishes ouroboros from
    Core (Core uses a separate sync thread + locator; ouroboros uses
    inline-atomic-batch).
    """
    lib_rs = _read_rust("sync/src/lib.rs")
    # connect path: store_tx_index_batch must appear inside the
    # same batch as the rest of the apply, before apply_batch
    # Look for both call sites
    assert lib_rs.count("self.db.store_tx_index_batch(&mut batch") >= 1, (
        "G15: store_tx_index_batch must use the shared batch parameter"
    )
    assert "self.db.apply_batch(batch)" in lib_rs, (
        "G15: apply_batch missing from connect path"
    )


@pytest.mark.xfail(
    reason="W133 BUG-5 (P1): No CopyHeightIndexToHashIndex reorg pattern. "
           "Latent today (txid-keyed tx_index doesn't need it) but blocks "
           "adding any height-keyed index like coinstatsindex (db_key.h:72-93).",
    strict=True,
)
def test_w133_g16_copy_height_to_hash_reorg_pattern() -> None:
    """G16: CopyHeightIndexToHashIndex pattern (Core's reorg-retention
    primitive) exists somewhere in the storage layer."""
    rust = _read_rust("sync/src/storage/db.rs")
    has_pattern = (
        "CopyHeightIndex" in rust
        or "copy_height_to_hash" in rust
        or "DBHashKey" in rust
    )
    assert has_pattern, (
        "G16: no CopyHeightIndexToHashIndex pattern in storage layer"
    )


@pytest.mark.xfail(
    reason="W133 BUG-12 (P2): No -prune + -txindex incompatibility "
           "check at startup. Core (init.cpp) refuses; ouroboros silently "
           "produces stale tx_index pointing at pruned blocks.",
    strict=True,
)
def test_w133_g17_prune_txindex_incompat_guard() -> None:
    """G17: Startup guard refuses `-prune` + `-txindex` combo.

    Core's `AppInitParameterInteraction` (`init.cpp`) emits an
    InitError refusing the combination. Without this, tx_index lookups
    after a prune yield `get_block(hash) == None` and the RPC silently
    fails.
    """
    config_py = _read_py("config.py")
    node_py = _read_py("node.py")
    # Bug signature: no guard whatsoever
    guard_present = re.search(
        r"prune.*txindex|txindex.*prune",
        config_py + node_py,
        re.IGNORECASE,
    )
    assert guard_present is not None, (
        "G17: no prune + txindex incompatibility guard"
    )


@pytest.mark.xfail(
    reason="W133 BUG-18 (P2): No PruneLockInfo plumbing. Core's "
           "SetBestBlockIndex writes prune lock keyed by index name "
           "(base.cpp:487-503).",
    strict=True,
)
def test_w133_g18_prune_lock_for_txindex() -> None:
    """G18: tx_index participates in the prune lock so the pruner
    doesn't drop block files needed by the index."""
    pruning_py = _read_py("pruning.py")
    assert "PruneLockInfo" in pruning_py or "prune_lock" in pruning_py, (
        "G18: no PruneLockInfo plumbing"
    )


# ===========================================================================
# G19-G24 — CoinStatsIndex absence (P0-CDIV cluster)
# ===========================================================================


def test_w133_g19_coinstatsindex_class_present() -> None:
    """G19 (NOW PRESENT): CoinStatsIndex class implemented in the Python pipeline.

    Core: `class CoinStatsIndex final : public BaseIndex`
    (`coinstatsindex.h:30`). Maintains MuHash3072 + per-block DBVal
    so `gettxoutsetinfo` is O(1).

    BUG-9 WAS: class entirely absent.  NOW: ouroboros.coinstatsindex.CoinStatsIndex
    exists in Python.  This test is a PRESENT (regression) guard.

    The check uses anchored definition patterns (line-start
    `class/struct/trait CoinStatsIndex`) to avoid matching audit
    comments in test files / docs.
    """
    if not FERROUS_UTILS.exists() and not SRC_OUROBOROS.exists():
        pytest.skip("source trees not present")

    found = False
    for tree in (FERROUS_UTILS, SRC_OUROBOROS):
        if not tree.exists():
            continue
        for path in tree.rglob("*.py"):
            if path.parts[-2] == "tests":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"^class\s+CoinStatsIndex\b", text, re.M):
                found = True
                break
        if found:
            break
        for path in tree.rglob("*.rs"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"^(pub\s+)?(struct|trait)\s+CoinStatsIndex\b", text, re.M):
                found = True
                break
        if found:
            break

    assert found, (
        "G19 P0-CDIV: no CoinStatsIndex class found in either pipeline"
    )


def test_w133_g20_gettxoutsetinfo_honors_hash_or_height() -> None:
    """G20 (NOW PRESENT): gettxoutsetinfo honors `hash_or_height` parameter.

    BUG-10 WAS: parameter silently discarded (`_ = hash_or_height`).
    NOW: hash_or_height is used; the coinstatsindex lookup is wired.

    Core: looks up cached entry from coinstatsindex at the specified
    height/hash.
    """
    rpc = _read_py("rpc.py")
    m = re.search(
        r"async def rpc_gettxoutsetinfo[\s\S]+?(?=\n    async def |\n    def |\Z)",
        rpc,
    )
    assert m, "G20: rpc_gettxoutsetinfo not found"
    body = m.group(0)
    # Bug signature: the parameter is discarded via `_ = hash_or_height`
    has_discard = "_ = hash_or_height" in body
    assert not has_discard, (
        "G20 P0-CDIV: hash_or_height is silently discarded"
    )


@pytest.mark.xfail(
    reason="W133 BUG-11 (P1): gettxoutsetinfo use_index parameter "
           "accepted then ignored; no fast path via coinstatsindex.",
    strict=True,
)
def test_w133_g21_gettxoutsetinfo_use_index_fast_path() -> None:
    """G21: gettxoutsetinfo `use_index=True` takes the fast path
    (coinstatsindex lookup) instead of walking chainstate."""
    rpc = _read_py("rpc.py")
    m = re.search(
        r"async def rpc_gettxoutsetinfo[\s\S]+?(?=\n    async def |\n    def |\Z)",
        rpc,
    )
    assert m
    body = m.group(0)
    # Bug signature: `_ = use_index`
    assert "_ = use_index" not in body, (
        "G21: use_index is silently discarded; no fast path"
    )


@pytest.mark.xfail(
    reason="W133 BUG-19 (P1): MuHash3072 not maintained as cumulative "
           "state per block. CoinStatsIndex would need ApplyCoinHash + "
           "RemoveCoinHash on every connect (coinstatsindex.cpp:145-167).",
    strict=True,
)
def test_w133_g22_muhash_cumulative_state() -> None:
    """G22: A cumulative MuHash3072 state is updated per block.

    Core: `m_muhash` is a `MuHash3072` member of `CoinStatsIndex`,
    updated on every connect/disconnect via `ApplyCoinHash` /
    `RemoveCoinHash` (`kernel/coinstats.cpp`).
    """
    import ouroboros.muhash as muhash_mod
    # Bug signature: no apply_block / revert_block helper that
    # incrementally updates a stored MuHash
    has_cumulative = (
        hasattr(muhash_mod, "CumulativeMuHash")
        or hasattr(muhash_mod, "IncrementalMuHash")
    )
    assert has_cumulative, (
        "G22: no cumulative-MuHash class for coinstatsindex"
    )


@pytest.mark.xfail(
    reason="W133 BUG-20 (P2): No m_total_unspendables_* counters "
           "(coinstats DBVal). Latent until coinstatsindex is added.",
    strict=True,
)
def test_w133_g23_total_unspendables_counters() -> None:
    """G23: Per-block counters for unspendable subtotals
    (genesis_block, bip30, scripts, unclaimed_rewards) exist somewhere.
    """
    snapshot_py = _read_py("snapshot.py")
    rpc_py = _read_py("rpc.py")
    combined = snapshot_py + rpc_py
    has_counters = (
        "total_unspendables_genesis_block" in combined
        and "total_unspendables_bip30" in combined
    )
    assert has_counters, (
        "G23: no unspendables counters family for coinstatsindex"
    )


@pytest.mark.xfail(
    reason="W133 BUG-21 (P2): No 'old indexes/coinstats' folder warning "
           "(coinstatsindex.cpp:95-101). Cosmetic until anyone has the "
           "legacy path.",
    strict=True,
)
def test_w133_g24_old_coinstats_folder_warning() -> None:
    """G24: Startup warns if a stale `indexes/coinstats/` folder exists
    (Core legacy path)."""
    node_py = _read_py("node.py")
    daemon_py = _read_py("daemon.py")
    combined = node_py + daemon_py
    assert "indexes/coinstats" in combined or "legacy coinstats" in combined.lower(), (
        "G24: no warning about legacy indexes/coinstats folder"
    )


# ===========================================================================
# G25-G27 — Key encoding + missing RPCs
# ===========================================================================


@pytest.mark.xfail(
    reason="W133 BUG-22 (P2): No big-endian height key encoding. "
           "Core's DBHeightKey uses ser_writedata32be (db_key.h:41) "
           "for sequential range scans; ouroboros uses LE everywhere.",
    strict=True,
)
def test_w133_g25_dbheightkey_big_endian() -> None:
    """G25: Heights encoded big-endian for index height keys.

    Core: `ser_writedata32be(s, height)` so iteration yields blocks
    in chain order. ouroboros `encode_height` is LE
    (`schema.rs:353`).
    """
    schema = _read_rust("sync/src/storage/schema.rs")
    # Bug signature: `to_le_bytes()`
    assert "to_be_bytes()" in schema, (
        "G25: encode_height uses LE — incompatible with Core sequential "
        "iteration order"
    )


@pytest.mark.xfail(
    reason="W133 BUG-23 (P1): No typed DBHashKey discriminator. Core "
           "uses 's'/'t' prefixes to coexist height + hash in one CF "
           "(db_key.h:29-30). Needed for any future per-height index.",
    strict=True,
)
def test_w133_g26_dbhashkey_typed_prefix() -> None:
    """G26: DBHashKey + DBHeightKey typed-prefix discriminator exists
    so the same CF can host both."""
    rust = _read_rust("sync/src/storage/db.rs")
    schema = _read_rust("sync/src/storage/schema.rs")
    combined = rust + schema
    assert "DB_BLOCK_HASH" in combined or "DBHashKey" in combined, (
        "G26: no DBHashKey discriminator"
    )


def test_w133_g27_scanblocks_scantxoutset_rpc() -> None:
    """G27 (NOW PRESENT): scanblocks + scantxoutset RPCs implemented.

    BUG-24 WAS: both RPCs absent.  NOW: rpc.py exports rpc_scanblocks
    and rpc_scantxoutset.  This is a PRESENT (regression) guard.
    """
    rpc = _read_py("rpc.py")
    has_scanblocks = "async def rpc_scanblocks" in rpc
    has_scantxoutset = "async def rpc_scantxoutset" in rpc
    assert has_scanblocks and has_scantxoutset, (
        "G27: scanblocks and/or scantxoutset RPC missing"
    )


# ===========================================================================
# G28-G29 — Functional sanity (PRESENT) + semantic confirmation
# ===========================================================================


def test_w133_g28_tx_position_is_array_index_not_byte_offset_bug15() -> None:
    """G28 (BUG-15 P1): live `tx_position` is the txdata-array index,
    not a byte offset.

    Pins the divergence so that any future change to the storage
    shape (e.g. byte-offset variant) is visible in this test.
    """
    lib_rs = _read_rust("sync/src/lib.rs")
    # The connect path passes tx_pos as the enumerate() index
    assert "tx_pos as u32" in lib_rs, (
        "G28: tx_pos no longer derived from enumerate index — "
        "shape may have shifted to byte offset, re-audit"
    )
    # The Rust storage routine declares the parameter `tx_position`
    db = _read_rust("sync/src/storage/db.rs")
    assert "tx_position: u32" in db, (
        "G28: tx_position parameter renamed or removed"
    )


def test_w133_g29_python_db_wrapper_present() -> None:
    """G29 (PRESENT, partial substitute for Core CustomOptions): the
    Python wrapper exposes `get_tx_index` returning the (hash, height,
    tx_pos) tuple."""
    import ouroboros.database as db_mod
    assert hasattr(db_mod.BlockchainDatabase, "get_tx_index"), (
        "G29 REGRESSION: BlockchainDatabase.get_tx_index removed"
    )
    sig = inspect.signature(db_mod.BlockchainDatabase.get_tx_index)
    # (self, txid: bytes) -> tuple | None
    assert "txid" in sig.parameters


# ===========================================================================
# G30 — Two-pipeline guard (PRESENT, extends W76+W120+W122+W125+W128+W129+W130)
# ===========================================================================


def test_w133_g30_two_pipeline_txindex_live_in_rust_only() -> None:
    """G30 (PRESENT): tx_index live path is Rust-side; no Python file
    defines its own tx_index storage.

    Extends the two-pipeline guard set with W133 coverage. Future
    regressions (e.g. an attempt to add Python-side SQLite txindex)
    trip this guard.
    """
    if not SRC_OUROBOROS.exists():
        pytest.skip("src/ouroboros tree not present")

    forbidden_python_identifiers = [
        # If any Python file gains these, the two-pipeline boundary
        # is violated: tx_index storage moves out of Rust into Python.
        # NOTE: "class CoinStatsIndex" is intentionally absent here —
        # the Python-layer CoinStatsIndex (coinstatsindex.py) is a
        # legitimate Python implementation of the index (analogous to
        # blockfilterindex.py), not a boundary violation.  The two-pipeline
        # rule only covers the live *tx_index* (txid→DiskTxPos) path.
        "class TxIndex",
        "store_tx_index",  # writing tx_index from Python = wrong
        "TX_INDEX_CF",     # column-family name in Python = wrong
    ]
    offenders: list[tuple[str, str]] = []
    for py_path in SRC_OUROBOROS.rglob("*.py"):
        # Skip the tests dir — they can mention these identifiers
        # in assertions/audit text.
        if py_path.parts[-2] == "tests":
            continue
        text = py_path.read_text(encoding="utf-8", errors="replace")
        for ident in forbidden_python_identifiers:
            if ident in text:
                # Allow strings inside comments / docstrings: filter
                # out lines that are pure comments or are in a known
                #-safe context (RPC help text mentions these in
                # English prose only).
                lines = text.splitlines()
                for lineno, line in enumerate(lines, 1):
                    if ident not in line:
                        continue
                    stripped = line.split("#", 1)[0]
                    # If the bare identifier appears in non-comment
                    # code, that's a violation.
                    if ident in stripped:
                        # Allow the audit's documented RPC comments
                        # that reference store_tx_index_batch by NAME
                        # (RPC help / inline doc that doesn't define
                        # a Python store_tx_index function).
                        if ident == "store_tx_index" and "store_tx_index_batch" in line:
                            continue
                        offenders.append((str(py_path.relative_to(SRC_OUROBOROS)), f"{ident}@L{lineno}"))
    assert not offenders, (
        f"G30 two-pipeline guard tripped: Python files define tx_index "
        f"storage primitives that belong in Rust: {offenders}"
    )


def test_w133_g30_two_pipeline_dead_code_alternate_pinned() -> None:
    """G30 (PRESENT): document the dead-code state of
    `ferrous-utils/sync/src/storage/txindex.rs` until BUG-1 is closed.

    The alternate `TxIndex` struct + `PyTxIndex`/`PyDiskTxPos` are
    DEAD-CODE. This test pins their existence so that if/when BUG-1
    is closed by deletion, the test fails LOUDLY (forcing the audit
    to be updated).

    If BUG-1 is closed by WIRING (replacing live shape with file-pos
    shape), this test still pins the existence — fixer must update
    audit framing first.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")
    txindex_rs = (FERROUS_UTILS / "sync/src/storage/txindex.rs")
    assert txindex_rs.exists(), (
        "G30 BUG-1 may be closed by deletion: storage/txindex.rs "
        "no longer exists; update W133 audit (BUG-1 closed) and "
        "remove this test."
    )
    # Confirm the pyclass wrapping still exists
    lib_rs = _read_rust("sync/src/lib.rs")
    assert "pub struct PyTxIndex" in lib_rs, (
        "G30 BUG-1 partially closed: PyTxIndex removed; check that "
        "the live tx_index path is still the only one and update "
        "the audit accordingly."
    )
    # Confirm no Python file instantiates PyTxIndex
    py_database = _read_py("database.py")
    assert "PyTxIndex" not in py_database, (
        "G30 BUG-1 may be closed: database.py now uses PyTxIndex; "
        "update audit to mark BUG-1 closed (wired path)"
    )


def test_w133_g30_coinstatsindex_in_python() -> None:
    """G30 (NOW PRESENT): CoinStatsIndex is implemented in the Python pipeline.

    BUG-9/BUG-19 WAS: class entirely absent, no MuHash per-block state.
    NOW: ouroboros.coinstatsindex.CoinStatsIndex exists in Python and
    maintains an incremental MuHash3072 commitment.  This test is a
    PRESENT (regression) guard — if CoinStatsIndex disappears, it fails.
    """
    if not SRC_OUROBOROS.exists():
        pytest.skip("src/ouroboros tree not present")

    found_python = False
    for path in SRC_OUROBOROS.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^class\s+CoinStatsIndex\b", text, re.M):
            found_python = True
            break

    assert found_python, (
        "G30 REGRESSION: CoinStatsIndex class no longer present in Python pipeline. "
        "BUG-9 was resolved by adding ouroboros.coinstatsindex.CoinStatsIndex."
    )


# ===========================================================================
# Cross-pipeline sanity: live txindex path is wired
# ===========================================================================


def test_w133_rust_live_path_three_call_sites() -> None:
    """Sanity: the live tx_index write path has three call sites
    (single-connect, batch-connect, validator-pipeline). Regression
    here would mean one path no longer maintains the index."""
    lib_rs = _read_rust("sync/src/lib.rs")
    block_rs = _read_rust("sync/src/validate/block.rs")
    n_lib = lib_rs.count("self.db.store_tx_index_batch(")
    n_block = block_rs.count("self.db.store_tx_index_batch(")
    assert n_lib >= 2, (
        f"Expected 2 store_tx_index_batch sites in lib.rs, found {n_lib}"
    )
    assert n_block >= 1, (
        f"Expected ≥1 store_tx_index_batch site in validate/block.rs, "
        f"found {n_block}"
    )


def test_w133_rust_disconnect_path_no_txindex_delete() -> None:
    """Sanity (Core parity): the live tx_index disconnect path does NOT
    delete txindex entries — Core TxIndex has no CustomRemove (base.h:136
    no-op), so entries survive reorgs.  The connect path still writes them.

    A failure here means the delete was re-introduced (Pattern C0 regression)
    or the connect write was accidentally removed.
    """
    db_rs = _read_rust("sync/src/storage/db.rs")
    block_rs = _read_rust("sync/src/validate/block.rs")
    # delete must NOT be present in any of the three disconnect paths
    assert "self.delete_tx_index_batch(&mut batch, txid.as_byte_array())" not in db_rs, (
        "REGRESSION: per-block disconnect path calls delete_tx_index_batch"
    )
    assert "batch.delete_cf(tx_index_cf, txid.as_byte_array())" not in db_rs, (
        "REGRESSION: atomic batch disconnect path deletes txindex entries"
    )
    assert "self.db.delete_tx_index(txid.as_byte_array())" not in block_rs, (
        "REGRESSION: validate/block.rs disconnect deletes txindex entries"
    )
    # connect path must still be present
    assert "store_tx_index_batch" in db_rs or "store_tx_index_batch" in block_rs, (
        "REGRESSION: store_tx_index_batch missing — txindex no longer written on connect"
    )


def test_w133_python_wrapper_thin() -> None:
    """Sanity: `BlockchainDatabase.get_tx_index` is a thin wrapper
    that delegates to the Rust live path (no Python-side storage).
    Boundary regression = Python pretends to own tx_index data.
    """
    import ouroboros.database as db_mod
    src = inspect.getsource(db_mod.BlockchainDatabase.get_tx_index)
    assert "self._db.get_tx_index" in src, (
        "Python get_tx_index no longer delegates to Rust _db.get_tx_index"
    )
    # Bug signature: defensive shape conversion is fine; new SQLite/etc
    # would be a violation
    forbidden = ["sqlite", "sqlite3", "lmdb", "leveldb", "open_db("]
    for f in forbidden:
        assert f not in src.lower(), (
            f"BUG: Python wrapper appears to embed {f} storage — "
            "two-pipeline boundary violated"
        )
