"""Tests for the PyBlockchainDB.has_block_hash existence probe.

These run against the REAL Rust ``sync`` extension (ferrous-utils).  The
suite's conftest.py installs a pure-Python stub as ``sys.modules['sync']``
before anything imports it, so ``import sync`` here would only ever see the
stub (which has no ``has_block_hash``).  Instead, locate the built extension
in site-packages and load it under the private name ``sync.sync`` — the
PyO3 init symbol is ``PyInit_sync`` so the last path component is what
matters — without displacing the stub the rest of the suite relies on.
"""

import glob
import importlib.util
import os
import site
import sys
import tempfile

import pytest


def _load_real_sync():
    dirs = [site.getusersitepackages(), *site.getsitepackages()]
    for d in dirs:
        for so in sorted(glob.glob(os.path.join(d, "sync", "sync*.so"))):
            spec = importlib.util.spec_from_file_location("sync.sync", so)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            sys.modules.pop("sync.sync", None)  # leave no trace for other tests
            if hasattr(mod, "PyBlockchainDB"):
                return mod
    return None


_real_sync = _load_real_sync()

pytestmark = pytest.mark.skipif(
    _real_sync is None,
    reason=(
        "ENV-ouroboros-1: real Rust sync extension not found in site-packages "
        "(conftest.py's sys.modules['sync'] stub has no has_block_hash); "
        "run `maturin develop --release` / reinstall_ouroboros.sh first"
    ),
)


@pytest.fixture
def empty_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        # PyBlockchainDB writes into the directory directly.
        db_dir = os.path.join(tmpdir, "db")
        os.makedirs(db_dir)
        yield _real_sync.PyBlockchainDB(db_dir)


def test_random_hash_returns_false(empty_db):
    """A random 32-byte hash on an empty DB returns False."""
    random_hash = bytes(range(32))
    assert empty_db.has_block_hash(random_hash) is False


def test_zero_hash_returns_false(empty_db):
    """The all-zero hash on an empty DB returns False."""
    assert empty_db.has_block_hash(bytes(32)) is False


def test_bad_length_raises_value_error(empty_db):
    """has_block_hash must reject non-32-byte inputs with ValueError."""
    with pytest.raises(ValueError):
        empty_db.has_block_hash(b"too short")
    with pytest.raises(ValueError):
        empty_db.has_block_hash(bytes(31))
    with pytest.raises(ValueError):
        empty_db.has_block_hash(bytes(33))


def test_agrees_with_get_block_when_absent(empty_db):
    """has_block_hash and get_block must agree on absent blocks."""
    h = bytes([0x42] * 32)
    assert empty_db.get_block(h) is None
    assert empty_db.has_block_hash(h) is False


# The "known-present hash returns True" case is covered in
# ferrous-utils/sync/src/storage/db_tests.rs::test_has_block_hash at the
# Rust layer. Inserting a real block here would require driving
# connect_block_from_bytes with a serialised block, which is heavier
# machinery than this targeted unit test warrants.
