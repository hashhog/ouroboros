"""
Tests for BIP68 sequence lock validation.

Tests the Rust implementation exposed via PyO3 bindings.
"""

import pytest


class TestSequenceLockConstants:
    """Test that BIP68 constants are correctly exposed."""

    def test_constants_exist(self):
        from sync import PySequenceLockConstants

        # Verify constants match expected BIP68 values
        assert PySequenceLockConstants.DISABLE_FLAG == 0x80000000
        assert PySequenceLockConstants.TYPE_FLAG == 0x00400000
        assert PySequenceLockConstants.MASK == 0x0000FFFF
        assert PySequenceLockConstants.GRANULARITY == 9
        assert PySequenceLockConstants.FINAL == 0xFFFFFFFF


class TestBIP68ActivationHeight:
    """Test BIP68/CSV activation height lookups."""

    def test_mainnet_activation(self):
        from sync import bip68_activation_height

        assert bip68_activation_height("mainnet") == 419328
        assert bip68_activation_height("bitcoin") == 419328

    def test_testnet4_active_from_genesis(self):
        from sync import bip68_activation_height

        assert bip68_activation_height("testnet4") == 0

    def test_regtest_active_from_genesis(self):
        from sync import bip68_activation_height

        assert bip68_activation_height("regtest") == 0

    def test_invalid_network_raises(self):
        from sync import bip68_activation_height

        with pytest.raises(ValueError):
            bip68_activation_height("invalidnetwork")


class TestIsBIP68Active:
    """Test BIP68 activation status checks."""

    def test_mainnet_before_activation(self):
        from sync import is_bip68_active

        assert not is_bip68_active(419327, "mainnet")

    def test_mainnet_at_activation(self):
        from sync import is_bip68_active

        assert is_bip68_active(419328, "mainnet")

    def test_mainnet_after_activation(self):
        from sync import is_bip68_active

        assert is_bip68_active(500000, "mainnet")

    def test_testnet4_always_active(self):
        from sync import is_bip68_active

        assert is_bip68_active(0, "testnet4")
        assert is_bip68_active(100, "testnet4")

    def test_regtest_always_active(self):
        from sync import is_bip68_active

        assert is_bip68_active(0, "regtest")


class TestCalculateSequenceLocks:
    """Test sequence lock calculation."""

    def test_version_1_tx_no_locks(self):
        """Version 1 transactions ignore sequence locks."""
        from sync import calculate_sequence_locks

        # Even with a non-disabled sequence, version 1 ignores it
        inputs = [(100, 1000, 1600000000)]  # (sequence, prev_height, prev_mtp)
        min_height, min_time = calculate_sequence_locks(1, inputs)

        assert min_height == -1
        assert min_time == -1

    def test_disabled_sequence(self):
        """Sequence with disable flag set should not create locks."""
        from sync import calculate_sequence_locks

        # Sequence with bit 31 set (disable flag)
        inputs = [(0x80000064, 1000, 1600000000)]  # 0x80000000 | 100
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == -1
        assert min_time == -1

    def test_final_sequence(self):
        """SEQUENCE_FINAL (0xFFFFFFFF) has disable flag set."""
        from sync import calculate_sequence_locks

        inputs = [(0xFFFFFFFF, 1000, 1600000000)]
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == -1
        assert min_time == -1

    def test_height_based_lock(self):
        """Height-based relative lock (bit 22 = 0)."""
        from sync import calculate_sequence_locks

        # Sequence = 100 (100 blocks relative lock)
        # prev_height = 1000
        # Expected: min_height = 1000 + 100 - 1 = 1099 (last invalid height)
        inputs = [(100, 1000, 1600000000)]
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == 1099
        assert min_time == -1

    def test_time_based_lock(self):
        """Time-based relative lock (bit 22 = 1)."""
        from sync import calculate_sequence_locks

        # Sequence = 0x00400001 (TYPE_FLAG | 1)
        # 1 unit = 512 seconds
        # prev_mtp = 1600000000
        # Expected: min_time = 1600000000 + 512 - 1 = 1600000511
        inputs = [(0x00400001, 1000, 1600000000)]
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == -1
        assert min_time == 1600000511

    def test_multiple_inputs_takes_max(self):
        """Multiple inputs: take the maximum lock requirement."""
        from sync import calculate_sequence_locks

        inputs = [
            (50, 1000, 1600000000),   # Height lock: 1000 + 50 - 1 = 1049
            (100, 900, 1599000000),   # Height lock: 900 + 100 - 1 = 999
            (0x80000000, 800, 0),     # Disabled
        ]
        min_height, min_time = calculate_sequence_locks(2, inputs)

        # Max of 1049 and 999 is 1049
        assert min_height == 1049
        assert min_time == -1

    def test_mixed_height_and_time(self):
        """Both height-based and time-based locks in same tx."""
        from sync import calculate_sequence_locks

        inputs = [
            (100, 1000, 1600000000),        # Height: 1000 + 100 - 1 = 1099
            (0x0040000A, 1000, 1600000000), # Time: 1600000000 + (10 * 512) - 1 = 1600005119
        ]
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == 1099
        assert min_time == 1600005119


class TestCheckSequenceLocks:
    """Test the combined sequence lock check."""

    def test_height_lock_not_satisfied(self):
        """Block height below required minimum fails."""
        from sync import check_sequence_locks

        # Requires height > 1099 to be valid
        inputs = [(100, 1000, 0)]

        # Block at height 1099: should fail (min_height = 1099, need > 1099)
        assert not check_sequence_locks(2, inputs, 1099, 0, True)

        # Block at height 1000: should fail
        assert not check_sequence_locks(2, inputs, 1000, 0, True)

    def test_height_lock_satisfied(self):
        """Block height at or above required minimum passes."""
        from sync import check_sequence_locks

        inputs = [(100, 1000, 0)]

        # Block at height 1100: should pass
        assert check_sequence_locks(2, inputs, 1100, 0, True)

        # Block at height 1200: should pass
        assert check_sequence_locks(2, inputs, 1200, 0, True)

    def test_time_lock_not_satisfied(self):
        """Block MTP below required minimum fails."""
        from sync import check_sequence_locks

        # 1 unit of 512 seconds
        inputs = [(0x00400001, 1000, 1600000000)]

        # MTP = 1600000511: should fail (need > 1600000511)
        assert not check_sequence_locks(2, inputs, 2000, 1600000511, True)

        # MTP = 1600000500: should fail
        assert not check_sequence_locks(2, inputs, 2000, 1600000500, True)

    def test_time_lock_satisfied(self):
        """Block MTP at or above required minimum passes."""
        from sync import check_sequence_locks

        inputs = [(0x00400001, 1000, 1600000000)]

        # MTP = 1600000512: should pass
        assert check_sequence_locks(2, inputs, 2000, 1600000512, True)

        # MTP = 1700000000: should pass
        assert check_sequence_locks(2, inputs, 2000, 1700000000, True)

    def test_bip68_not_enforced(self):
        """When BIP68 is not enforced, all sequences are allowed."""
        from sync import check_sequence_locks

        # This would normally require height > 1099
        inputs = [(100, 1000, 0)]

        # With enforce_bip68=False, any height should pass
        assert check_sequence_locks(2, inputs, 1, 0, False)
        assert check_sequence_locks(2, inputs, 100, 0, False)

    def test_version_1_always_passes(self):
        """Version 1 transactions always pass sequence checks."""
        from sync import check_sequence_locks

        inputs = [(100, 1000, 0)]

        # Version 1 ignores sequence locks even when BIP68 enforced
        assert check_sequence_locks(1, inputs, 1, 0, True)


class TestSequenceLockEdgeCases:
    """Edge cases and boundary conditions."""

    def test_zero_relative_lock(self):
        """Sequence of 0 means valid immediately after confirmation."""
        from sync import calculate_sequence_locks, check_sequence_locks

        # Sequence = 0 (0 blocks relative lock)
        # min_height = prev_height + 0 - 1 = 999
        inputs = [(0, 1000, 0)]
        min_height, min_time = calculate_sequence_locks(2, inputs)
        assert min_height == 999

        # Should be valid at height 1000 (one block after the UTXO)
        assert check_sequence_locks(2, inputs, 1000, 0, True)

    def test_max_relative_lock(self):
        """Maximum lock value (65535) works correctly."""
        from sync import calculate_sequence_locks

        # Sequence = 0xFFFF (max 16-bit value = 65535 blocks)
        inputs = [(0xFFFF, 1000, 0)]
        min_height, _ = calculate_sequence_locks(2, inputs)

        # min_height = 1000 + 65535 - 1 = 66534
        assert min_height == 66534

    def test_empty_inputs(self):
        """Transaction with no inputs has no locks."""
        from sync import calculate_sequence_locks

        inputs = []
        min_height, min_time = calculate_sequence_locks(2, inputs)

        assert min_height == -1
        assert min_time == -1
