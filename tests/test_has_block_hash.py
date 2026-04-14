"""Tests for the PyBlockchainDB.has_block_hash existence probe."""

import os
import tempfile

import pytest

try:
    import sync
    HAS_SYNC = True
except ImportError:
    HAS_SYNC = False


pytestmark = pytest.mark.skipif(
    not HAS_SYNC,
    reason="sync module not available (run `maturin develop --release` first)",
)


@pytest.fixture
def empty_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        # PyBlockchainDB writes into the directory directly.
        db_dir = os.path.join(tmpdir, "db")
        os.makedirs(db_dir)
        yield sync.PyBlockchainDB(db_dir)


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
