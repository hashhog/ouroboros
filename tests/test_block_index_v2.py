"""Hash-keyed block index v2: every entry carries its header (so its parent
link) and nTx, and an existing datadir is migrated in place at open.

Core keeps one ``CBlockIndex`` per known block, keyed by hash, holding the
header fields (``pprev`` included), height, chain work, ``nStatus`` and
``nTx`` (chain.h; ``BlockManager::AddToBlockIndex``,
node/blockstorage.cpp; ``LoadBlockIndexDB`` rebuilds ``pprev`` from the
stored ``hashPrev``).  ouroboros' BLOCK_INDEX_BY_HASH_CF held height,
chain work, timestamp and status only, so no block off the active chain
could be linked to its parent without a second store.  This is step R1 of
the block-index rework: the record, its writers and the migration.  Nothing
reads it yet.

The migration test runs on copies of two regtest datadirs written by
ouroboros at dcf7338 (master before this change), each synced by Bitcoin
Core v31.1's ``core-regtest`` harness and stopped cleanly; see
``tests/fixtures/block_index_v2/README.md``.

Every test needs the compiled extension, and goes through
``tests/_real_sync.py`` so it cannot pass against the conftest stub.
"""

from __future__ import annotations

import gc
import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests._f0_chain import Chain  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "block_index_v2" / "regtest-datadirs-dcf7338.tar.xz"
EXPECTED = json.loads((FIXTURE.parent / "expected.json").read_text())
EXPECTED_SHA256 = (FIXTURE.parent / "SHA256").read_text().split()[0]

BLOCK_HAVE_DATA = 8
BLOCK_FAILED_MASK = 32 | 64


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def index_entry(db, block_hash: bytes):
    """The v2 entry for ``block_hash``.  The getattr keeps this test
    importable and failing on its assertion against a build without v2."""
    fn = getattr(db, "get_block_index_entry", None)
    assert fn is not None, (
        "PyBlockchainDB.get_block_index_entry is missing: the hash index has "
        "no header / parent link (block index v2 not built)"
    )
    return fn(block_hash)


def unpack(tmp_path: Path, name: str) -> str:
    """A fresh copy of one fixture datadir; the committed tarball is never opened in place."""
    with tarfile.open(FIXTURE) as tar:
        members = [m for m in tar.getmembers() if m.name.startswith(name + "/")]
        tar.extractall(tmp_path, members=members, filter="data")
    return str(tmp_path / name)


def test_connect_writes_header_and_parent_into_hash_index(tmp_path):
    """Every connected block's hash-index entry carries the header that
    hashes to its key, so its parent is one read away (Core: pprev)."""
    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    chain = Chain(db, tip=6)
    hashes = [db.get_block_hash_by_height(h) for h in range(chain.tip_height + 1)]
    for height, bh in enumerate(hashes):
        e = index_entry(db, bh)
        assert e is not None, f"height {height}: no hash-index entry"
        e_height, _cw, _ts, status, header, n_tx = e
        assert e_height == height
        assert header is not None, f"height {height}: entry written by connect has no header"
        assert dsha(bytes(header)) == bh, "header must hash to the key"
        prev = bytes(header)[4:36]
        assert prev == (hashes[height - 1] if height else b"\x00" * 32)
        assert n_tx == 1
        assert status & BLOCK_HAVE_DATA


def test_status_change_keeps_header_in_hash_index(tmp_path):
    """invalidate/reconsider rewrite an entry's status; the header must survive."""
    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    chain = Chain(db, tip=4)
    tip = chain.tip_hash
    db.invalidate_block(tip)
    e = index_entry(db, tip)
    assert e[3] & BLOCK_FAILED_MASK
    assert e[4] is not None and dsha(bytes(e[4])) == tip
    db.reconsider_block(tip)
    e = index_entry(db, tip)
    assert not e[3] & BLOCK_FAILED_MASK
    assert e[4] is not None and dsha(bytes(e[4])) == tip


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_migrates_copy_of_synced_regtest_datadir_in_place(tmp_path, name):
    """Open a datadir written by the previous binary: the open upgrades the
    hash index in place (no resync), keeps the tip and every entry's
    height / work / status, and links every active block and every stored
    side-branch block to its parent."""
    want = EXPECTED[name]
    path = unpack(tmp_path, name)

    db = sync.PyBlockchainDB(path)
    stats_fn = getattr(db, "block_index_open_migration_stats", None)
    assert stats_fn is not None, "no block index v2 migration in this build"
    stats = stats_fn()
    assert stats is not None, "opening a pre-v2 datadir must run the migration"
    assert stats["scanned"] == want["entries"]
    assert stats["already_v2"] == 0, "the fixture predates v2"
    assert stats["hash_mismatch"] == 0
    assert stats["malformed"] == 0
    assert stats["from_headers"] + stats["from_body"] + stats["no_header"] == want["entries"]
    assert stats["no_header"] == want["no_header"]
    assert db.block_index_summary() == (want["entries"], want["entries"] - want["no_header"],
                                        want["no_header"])

    # The tip did not move and the active chain is intact.
    tip_hash, tip_height = db.get_best_block()
    assert (bytes(tip_hash)[::-1].hex(), tip_height) == (want["tip"], want["tip_height"])
    prev = b"\x00" * 32
    for height in range(tip_height + 1):
        bh = bytes(db.get_block_hash_by_height(height))
        e = index_entry(db, bh)
        assert e is not None and e[0] == height
        if e[4] is None:
            assert height in want["active_without_header"], height
        else:
            assert dsha(bytes(e[4])) == bh
            assert bytes(e[4])[4:36] == prev, f"height {height}: parent link"
        prev = bh

    # Side-branch and failed blocks: entry kept, status kept, parent linked.
    for disp, exp in want["side"].items():
        bh = bytes.fromhex(disp)[::-1]
        e = index_entry(db, bh)
        assert e is not None, f"{disp}: entry lost"
        assert (e[0], e[3]) == (exp["height"], exp["status"]), f"{disp}: metadata changed"
        assert e[4] is not None, f"{disp}: side block not linked"
        assert dsha(bytes(e[4])) == bh
        assert bytes(e[4])[4:36][::-1].hex() == exp["prev"]
    # Blocks master never stored in the hash index stay absent: the
    # migration upgrades entries, it does not invent them.
    for disp in want["absent"]:
        assert index_entry(db, bytes.fromhex(disp)[::-1]) is None, disp
    del db, stats_fn  # the bound method holds the handle (RocksDB LOCK) too
    gc.collect()

    # One-time: a second open finds the marker and does nothing.
    db = sync.PyBlockchainDB(path)
    assert db.block_index_open_migration_stats() is None
    assert db.migrate_block_index_v2() is None
    tip_hash2, tip_height2 = db.get_best_block()
    assert (bytes(tip_hash2), tip_height2) == (bytes(tip_hash), tip_height)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_migrated_datadir_boots_through_database_wrapper(tmp_path, name):
    """The node's own open path (``ouroboros.database.BlockchainDatabase``) on a
    migrated copy: tip, block bodies and the new entry accessor all answer."""
    from ouroboros.database import BlockchainDatabase

    want = EXPECTED[name]
    path = unpack(tmp_path, name)
    db = BlockchainDatabase(path)
    tip_hash, tip_height = db.get_best_block()
    assert (bytes(tip_hash)[::-1].hex(), tip_height) == (want["tip"], want["tip_height"])
    blk = db.get_block_by_height(tip_height)
    assert blk is not None
    get_entry = getattr(db, "get_block_index_entry", None)
    assert get_entry is not None, "BlockchainDatabase.get_block_index_entry is missing"
    e = get_entry(bytes(tip_hash))
    assert e is not None and e["height"] == tip_height
    assert e["header"] is not None and dsha(e["header"]) == bytes(tip_hash)
    parent = db.get_block_hash_by_height(tip_height - 1)
    assert e["prev_hash"] == bytes(parent)


def test_fixture_is_untouched_by_the_suite():
    """The committed tarball is only ever unpacked into tmp_path."""
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == EXPECTED_SHA256

