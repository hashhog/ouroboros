"""
Tests for checkpoint functionality.

Checkpoints are hardcoded (height, block_hash) pairs that:
1. Prevent DoS by rejecting forks that branch before the last checkpoint
2. Speed up IBD by allowing script validation to be skipped for covered blocks
"""

import pytest

# Skip all tests if Rust sync module is not available
pytest.importorskip("sync")
import sync


class TestCheckpointRetrieval:
    """Tests for retrieving checkpoint data."""

    def test_get_mainnet_checkpoints(self):
        """Mainnet should have multiple checkpoints."""
        checkpoints = sync.get_network_checkpoints("mainnet")
        assert len(checkpoints) > 10, "Mainnet should have many checkpoints"

        # First mainnet checkpoint is at height 11111
        assert checkpoints[0].height == 11111

        # Checkpoints should be in ascending order
        for i in range(1, len(checkpoints)):
            assert checkpoints[i].height > checkpoints[i - 1].height

    def test_get_testnet_checkpoints(self):
        """Testnet3 should have at least one checkpoint."""
        checkpoints = sync.get_network_checkpoints("testnet")
        assert len(checkpoints) >= 1
        assert checkpoints[0].height == 546

    def test_get_regtest_checkpoints(self):
        """Regtest should have no checkpoints."""
        checkpoints = sync.get_network_checkpoints("regtest")
        assert len(checkpoints) == 0

    def test_checkpoint_hash_format(self):
        """Checkpoint hashes should be 32 bytes."""
        checkpoints = sync.get_network_checkpoints("mainnet")
        for cp in checkpoints:
            assert len(cp.hash) == 32, f"Checkpoint at {cp.height} has invalid hash length"

    def test_checkpoint_hash_hex(self):
        """Checkpoint hash_hex() should return big-endian display format."""
        checkpoints = sync.get_network_checkpoints("mainnet")
        cp = checkpoints[0]  # Height 11111

        hex_str = cp.hash_hex()
        assert len(hex_str) == 64, "Hex string should be 64 characters"
        assert hex_str.startswith("0000000069e244f7"), "First checkpoint hash should start with 0000000069e244f7"

    def test_invalid_network(self):
        """Invalid network should raise ValueError."""
        with pytest.raises(ValueError):
            sync.get_network_checkpoints("invalid_network")


class TestLastCheckpoint:
    """Tests for get_last_network_checkpoint."""

    def test_mainnet_last_checkpoint(self):
        """Mainnet should have a high last checkpoint."""
        last_cp = sync.get_last_network_checkpoint("mainnet")
        assert last_cp is not None
        assert last_cp.height > 800_000, "Last mainnet checkpoint should be recent"

    def test_testnet_last_checkpoint(self):
        """Testnet should have a last checkpoint."""
        last_cp = sync.get_last_network_checkpoint("testnet")
        assert last_cp is not None
        assert last_cp.height == 546

    def test_regtest_no_checkpoint(self):
        """Regtest should have no last checkpoint."""
        last_cp = sync.get_last_network_checkpoint("regtest")
        assert last_cp is None


class TestIsBelowCheckpoint:
    """Tests for check_is_below_checkpoint."""

    def test_mainnet_below_checkpoint(self):
        """Heights below last checkpoint should return True."""
        assert sync.check_is_below_checkpoint("mainnet", 100) is True
        assert sync.check_is_below_checkpoint("mainnet", 500_000) is True

    def test_mainnet_at_checkpoint(self):
        """Height equal to last checkpoint should return True (inclusive)."""
        last_cp = sync.get_last_network_checkpoint("mainnet")
        assert sync.check_is_below_checkpoint("mainnet", last_cp.height) is True

    def test_mainnet_above_checkpoint(self):
        """Heights above last checkpoint should return False."""
        last_cp = sync.get_last_network_checkpoint("mainnet")
        assert sync.check_is_below_checkpoint("mainnet", last_cp.height + 1) is False
        assert sync.check_is_below_checkpoint("mainnet", 999_999_999) is False

    def test_regtest_always_false(self):
        """Regtest has no checkpoints, so always False."""
        assert sync.check_is_below_checkpoint("regtest", 0) is False
        assert sync.check_is_below_checkpoint("regtest", 100) is False
        assert sync.check_is_below_checkpoint("regtest", 1_000_000) is False


class TestVerifyCheckpoint:
    """Tests for verify_block_checkpoint."""

    def test_verify_valid_checkpoint(self):
        """Verify returns True for correct checkpoint hash."""
        checkpoints = sync.get_network_checkpoints("mainnet")
        cp = checkpoints[0]  # Height 11111

        result = sync.verify_block_checkpoint("mainnet", cp.height, cp.hash)
        assert result is True

    def test_verify_invalid_hash(self):
        """Verify returns False for incorrect hash at checkpoint height."""
        wrong_hash = bytes(32)  # All zeros
        result = sync.verify_block_checkpoint("mainnet", 11111, wrong_hash)
        assert result is False

    def test_verify_non_checkpoint_height(self):
        """Verify returns None for heights without checkpoints."""
        result = sync.verify_block_checkpoint("mainnet", 12345, bytes(32))
        assert result is None

    def test_verify_invalid_hash_length(self):
        """Invalid hash length should raise ValueError."""
        with pytest.raises(ValueError):
            sync.verify_block_checkpoint("mainnet", 11111, bytes(16))


class TestCanSkipScripts:
    """Tests for can_skip_scripts_for_block."""

    def test_skip_below_checkpoint(self):
        """Blocks below last checkpoint can skip scripts."""
        # Use a known checkpoint hash
        checkpoints = sync.get_network_checkpoints("mainnet")
        cp = checkpoints[0]

        assert sync.can_skip_scripts_for_block("mainnet", cp.height, cp.hash) is True

    def test_no_skip_above_checkpoint(self):
        """Blocks above last checkpoint cannot skip scripts."""
        last_cp = sync.get_last_network_checkpoint("mainnet")
        # Height above checkpoint, any hash
        result = sync.can_skip_scripts_for_block("mainnet", last_cp.height + 1, bytes(32))
        assert result is False

    def test_no_skip_wrong_hash_at_checkpoint(self):
        """Wrong hash at checkpoint height cannot skip scripts."""
        wrong_hash = bytes(32)
        result = sync.can_skip_scripts_for_block("mainnet", 11111, wrong_hash)
        assert result is False

    def test_skip_non_checkpoint_height_below_last(self):
        """Non-checkpoint heights below last checkpoint can skip scripts."""
        # Height 12345 is not a checkpoint but is below last checkpoint
        any_hash = bytes(32)  # Hash doesn't matter for non-checkpoint heights
        result = sync.can_skip_scripts_for_block("mainnet", 12345, any_hash)
        assert result is True


class TestChainParamsIntegration:
    """Test ChainParams class from config module."""

    def test_chain_params_checkpoints(self):
        """ChainParams should provide checkpoint access."""
        from ouroboros.config import ChainParams

        params = ChainParams("mainnet")
        checkpoints = params.get_checkpoints()
        assert len(checkpoints) > 0

    def test_chain_params_last_checkpoint(self):
        """ChainParams should provide last checkpoint."""
        from ouroboros.config import ChainParams

        params = ChainParams("mainnet")
        last_height = params.get_last_checkpoint_height()
        assert last_height is not None
        assert last_height > 800_000

    def test_chain_params_is_below_checkpoint(self):
        """ChainParams.is_below_checkpoint should work."""
        from ouroboros.config import ChainParams

        params = ChainParams("mainnet")
        assert params.is_below_checkpoint(100) is True
        assert params.is_below_checkpoint(999_999_999) is False

    def test_chain_params_minimum_chain_work(self):
        """ChainParams should provide minimum chain work."""
        from ouroboros.config import ChainParams

        params = ChainParams("mainnet")
        min_work = params.get_minimum_chain_work()
        assert min_work is not None
        assert len(min_work) > 0  # Hex string


class TestSyncManagerCheckpoints:
    """Test SyncManager checkpoint methods."""

    def test_sync_manager_checkpoint_height(self):
        """SyncManager should know last checkpoint height."""
        import tempfile
        from ouroboros.sync_manager import SyncManager

        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SyncManager(tmpdir, "mainnet")
            height = mgr.get_last_checkpoint_height()
            assert height is not None
            assert height > 800_000

    def test_sync_manager_is_below_checkpoint(self):
        """SyncManager.is_below_checkpoint should work."""
        import tempfile
        from ouroboros.sync_manager import SyncManager

        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SyncManager(tmpdir, "mainnet")
            assert mgr.is_below_checkpoint(100) is True
            assert mgr.is_below_checkpoint(999_999_999) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
