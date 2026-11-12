"""Read-only dry run of the block index v2 migration.

The block index v2 migration (ouroboros#146) rewrites BLOCK_INDEX_BY_HASH_CF
in place at the first open of a v2 build and logs its counts, including
``no_header=N`` (entries no store holds a header for, which stay legacy).  On
the mainnet node N is unknown until that open.  These tests pin a probe that
gives the same counts beforehand without touching the datadir:

* ``PyBlockchainDB.open_secondary`` opens a datadir as a RocksDB secondary
  instance: no lock, no write, no migration, own files in a scratch dir;
* ``dry_run_block_index_v2`` runs the migration's scan with the writes
  replaced by counting;
* ``tools/block_index_v2_dryrun.py`` is the operator command around both.

They run on copies of the two master-written regtest datadirs from
``tests/fixtures/block_index_v2`` (see its README), the same fixture the
migration tests use.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

FIXTURE = Path(__file__).parent / "fixtures" / "block_index_v2" / "regtest-datadirs-dcf7338.tar.xz"
EXPECTED = json.loads((FIXTURE.parent / "expected.json").read_text())
TOOL = Path(__file__).resolve().parent.parent / "tools" / "block_index_v2_dryrun.py"
STATS_KEYS = ("scanned", "already_v2", "from_headers", "from_body", "no_header",
              "hash_mismatch", "malformed")
V2_EXTRA = 80 + 4  # header + nTx appended to the 44-byte BlockMetadata


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def unpack(tmp_path: Path, name: str) -> str:
    with tarfile.open(FIXTURE) as tar:
        members = [m for m in tar.getmembers() if m.name.startswith(name + "/")]
        tar.extractall(tmp_path, members=members, filter="data")
    return str(tmp_path / name)


def manifest(path: str) -> dict[str, tuple[int, int, str]]:
    """(size, mtime_ns, sha256) of every file under ``path``."""
    out = {}
    for root, _dirs, files in os.walk(path):
        for f in files:
            p = os.path.join(root, f)
            st = os.stat(p)
            with open(p, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            out[os.path.relpath(p, path)] = (st.st_size, st.st_mtime_ns, digest)
    return out


def open_secondary(path: str, scratch: str):
    fn = getattr(sync.PyBlockchainDB, "open_secondary", None)
    assert fn is not None, (
        "PyBlockchainDB.open_secondary is missing: no read-only way to probe a "
        "live datadir before the v2 migration"
    )
    return fn(path, scratch)


def dry_run(db) -> dict:
    fn = getattr(db, "dry_run_block_index_v2", None)
    assert fn is not None, "PyBlockchainDB.dry_run_block_index_v2 is missing"
    return dict(fn())


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_dry_run_predicts_the_migration_and_writes_nothing(tmp_path, name):
    """On a legacy datadir the dry run's counts are exactly the counts the
    real migration then reports, and the datadir is byte-for-byte unchanged
    by the dry run.  The negative control: the real open does change it, so
    the manifest comparison can see a write."""
    path = unpack(tmp_path, name)
    before = manifest(path)

    sec = open_secondary(path, str(tmp_path / "secondary"))
    r = dry_run(sec)
    del sec
    gc.collect()
    assert manifest(path) == before, "the dry run wrote to the datadir"

    assert r["migrated"] == 0
    assert r["ntx_reconciled"] == 1, "fixture datadirs were written after the nTx reconcile"
    assert r["scanned"] == EXPECTED[name]["entries"]
    assert r["no_header"] == EXPECTED[name]["no_header"]
    upgraded = r["from_headers"] + r["from_body"]
    assert upgraded > 0
    assert r["extra_bytes"] == V2_EXTRA * upgraded

    db = sync.PyBlockchainDB(path)
    real = db.block_index_open_migration_stats()
    total, v2, legacy = db.block_index_summary()
    del db
    gc.collect()
    assert real is not None, "the real open did not migrate"
    assert {k: real[k] for k in STATS_KEYS} == {k: r[k] for k in STATS_KEYS}
    assert (total, v2, legacy) == (r["scanned"], r["already_v2"] + upgraded,
                                   r["scanned"] - r["already_v2"] - upgraded)
    assert manifest(path) != before, "negative control: a real open must change the datadir"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_dry_run_after_migration_reports_marker_and_nothing_to_do(tmp_path, name):
    path = unpack(tmp_path, name)
    db = sync.PyBlockchainDB(path)
    total, _v2, _legacy = db.block_index_summary()
    del db
    gc.collect()

    sec = open_secondary(path, str(tmp_path / "secondary"))
    r = dry_run(sec)
    del sec
    gc.collect()
    assert r["migrated"] == 1
    assert r["scanned"] == total
    assert r["from_headers"] + r["from_body"] == 0
    assert r["extra_bytes"] == 0


def test_dry_run_beside_an_open_primary_and_refuses_writes(tmp_path):
    """The node may be running: a secondary opens while the primary holds
    the RocksDB lock, sees its data, and any write through it is refused."""
    path = unpack(tmp_path, sorted(EXPECTED)[0])
    primary = sync.PyBlockchainDB(path)
    tip_hash, tip_height = primary.get_best_block()
    total, _v2, _legacy = primary.block_index_summary()

    sec = open_secondary(path, str(tmp_path / "secondary"))
    assert tuple(sec.get_best_block()) == (tip_hash, tip_height)
    r = dry_run(sec)
    assert r["scanned"] == total and r["migrated"] == 1
    # The same call succeeds on a primary (test_block_index_v2.py's
    # status test); through the secondary RocksDB itself refuses it.
    with pytest.raises(Exception, match="secondary mode"):
        sec.invalidate_block(bytes(tip_hash))
    del sec
    gc.collect()
    # The refused write did not reach the primary.
    assert tuple(primary.get_best_block()) == (tip_hash, tip_height)
    del primary
    gc.collect()


def _run_tool(*args: str) -> subprocess.CompletedProcess:
    # A fresh interpreter: it imports the real extension from the same
    # PYTHONPATH / venv as this run, never the conftest stub.
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True,
                          text=True, timeout=120)


def test_operator_tool_prints_the_counts_and_leaves_the_datadir_alone(tmp_path):
    name = sorted(EXPECTED)[-1]
    path = unpack(tmp_path, name)
    before = manifest(path)
    p = _run_tool("--datadir", path, "--secondary-dir", str(tmp_path / "scratch"), "--json")
    assert p.returncode == 0, p.stderr
    r = json.loads(p.stdout)
    assert r["sync_module"] and "open_seconds" in r and "scan_seconds" in r
    assert manifest(path) == before
    db = sync.PyBlockchainDB(path)
    real = db.block_index_open_migration_stats()
    del db
    gc.collect()
    assert {k: real[k] for k in STATS_KEYS} == {k: r[k] for k in STATS_KEYS}


def test_operator_tool_refuses_a_scratch_dir_inside_the_datadir(tmp_path):
    path = unpack(tmp_path, sorted(EXPECTED)[0])
    before = manifest(path)
    p = _run_tool("--datadir", path, "--secondary-dir", os.path.join(path, "scratch"))
    assert p.returncode == 2 and "outside the datadir" in p.stderr
    p = _run_tool("--datadir", str(tmp_path), "--secondary-dir", str(tmp_path / "x"))
    assert p.returncode == 2 and "CURRENT" in p.stderr
    assert manifest(path) == before
