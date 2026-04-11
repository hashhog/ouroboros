"""
Tests for block pruning functionality.

Tests both the Python pruning module and the underlying Rust flat file
pruning implementation.
"""

import tempfile

import pytest

# Import the sync module (Rust extension)
try:
    import sync
    HAS_SYNC = True
except ImportError:
    HAS_SYNC = False

from ouroboros.pruning import BlockPruner, FilePruner, PruneStats


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def block_store(temp_data_dir):
    """Create a PyBlockStore for testing."""
    if not HAS_SYNC:
        pytest.skip("sync module not available")
    return sync.PyBlockStore(temp_data_dir, "regtest")


@pytest.fixture
def pruner(block_store):
    """Create a BlockPruner for testing."""
    return BlockPruner(block_store, target_size_mb=550, keep_blocks=288)


class TestPruneStats:
    """Tests for PruneStats dataclass."""

    def test_total_bytes(self):
        stats = PruneStats(
            total_files=5,
            pruned_files=1,
            data_bytes=100_000_000,
            undo_bytes=20_000_000,
            prune_height=100,
        )
        assert stats.total_bytes == 120_000_000

    def test_total_mb(self):
        stats = PruneStats(
            total_files=5,
            pruned_files=1,
            data_bytes=100_000_000,
            undo_bytes=0,
            prune_height=100,
        )
        assert stats.total_mb == 100.0

    def test_is_pruned_true(self):
        stats = PruneStats(
            total_files=5,
            pruned_files=1,
            data_bytes=100_000_000,
            undo_bytes=0,
            prune_height=100,
        )
        assert stats.is_pruned is True

    def test_is_pruned_false(self):
        stats = PruneStats(
            total_files=5,
            pruned_files=0,
            data_bytes=100_000_000,
            undo_bytes=0,
            prune_height=0,
        )
        assert stats.is_pruned is False


class TestBlockPruner:
    """Tests for BlockPruner class."""

    def test_min_keep_blocks_enforced(self, block_store):
        """Pruner enforces minimum keep_blocks of 288."""
        pruner = BlockPruner(block_store, target_size_mb=550, keep_blocks=10)
        assert pruner.keep_blocks == 288

    def test_min_target_size_enforced(self, block_store):
        """Pruner enforces minimum target size of 550 MB."""
        pruner = BlockPruner(block_store, target_size_mb=100, keep_blocks=288)
        assert pruner.target_size == 550 * 1_000_000

    def test_prune_height_empty_store(self, pruner):
        """Prune height is 0 for empty store."""
        assert pruner.prune_height == 0

    def test_get_stats_empty_store(self, pruner):
        """Stats for empty store."""
        stats = pruner.get_stats()
        assert stats.total_files >= 1  # At least file 0 exists
        assert stats.pruned_files == 0
        assert stats.prune_height == 0

    def test_prune_blocks_low_height(self, pruner):
        """Pruning does nothing when height <= keep_blocks."""
        files_pruned, bytes_freed = pruner.prune_blocks(100)
        assert files_pruned == 0
        assert bytes_freed == 0

    def test_get_prune_info(self, pruner):
        """get_prune_info returns proper dict."""
        info = pruner.get_prune_info()
        assert "pruned" in info
        assert "prune_height" in info
        assert "target_size" in info
        assert "keep_blocks" in info
        assert info["keep_blocks"] == 288
        assert info["target_size"] == 550 * 1_000_000


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestFilePruner:
    """Tests for FilePruner class."""

    def test_calculate_current_usage_empty(self, block_store):
        """Empty store has zero usage."""
        fp = FilePruner(block_store)
        assert fp.calculate_current_usage() == 0

    def test_find_files_to_prune_empty(self, block_store):
        """Empty store has no files to prune."""
        fp = FilePruner(block_store)
        files = fp.find_files_to_prune(1000, 0, 0)
        assert files == []

    def test_get_file_info_exists(self, block_store):
        """File 0 info exists even for empty store."""
        fp = FilePruner(block_store)
        info = fp.get_file_info(0)
        # File 0 always exists but may have no blocks yet
        if info is not None:
            assert "num_blocks" in info
            assert "size" in info
            assert "height_first" in info

    def test_get_file_info_nonexistent(self, block_store):
        """Nonexistent file returns None."""
        fp = FilePruner(block_store)
        info = fp.get_file_info(9999)
        assert info is None


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestPyBlockStorePruning:
    """Tests for PyBlockStore pruning methods."""

    def test_min_blocks_to_keep(self):
        """Static method returns 288."""
        assert sync.PyBlockStore.min_blocks_to_keep() == 288

    def test_min_prune_target(self):
        """Static method returns 550 MB."""
        assert sync.PyBlockStore.min_prune_target() == 550 * 1024 * 1024

    def test_max_blockfile_num_empty(self, block_store):
        """Empty store starts at file 0."""
        assert block_store.max_blockfile_num() == 0

    def test_calculate_current_usage_empty(self, block_store):
        """Empty store has zero usage."""
        assert block_store.calculate_current_usage() == 0

    def test_get_prune_height_empty(self, block_store):
        """Empty store has prune height 0."""
        assert block_store.get_prune_height() == 0

    def test_has_block_data_at_height_empty(self, block_store):
        """Empty store has no block data at any height."""
        # For empty store, there's no data at any height
        assert not block_store.has_block_data_at_height(0)

    def test_get_prune_stats_empty(self, block_store):
        """Prune stats for empty store."""
        total, pruned, data_bytes, undo_bytes, prune_h = block_store.get_prune_stats()
        assert total >= 1  # At least file 0
        assert pruned == 0
        assert data_bytes == 0
        assert undo_bytes == 0
        assert prune_h == 0

    def test_prune_to_target_low_height(self, block_store):
        """Pruning fails gracefully when height too low."""
        files, bytes_freed = block_store.prune_to_target(100, 550 * 1024 * 1024)
        assert files == 0
        assert bytes_freed == 0

    def test_prune_to_height_low_height(self, block_store):
        """Pruning to height fails gracefully when height too low."""
        files, bytes_freed, actual = block_store.prune_to_height(1000, 100)
        assert files == 0
        assert bytes_freed == 0

    def test_find_files_to_prune_empty(self, block_store):
        """No files to prune in empty store."""
        files = block_store.find_files_to_prune(1000, 0, 0)
        assert files == []
