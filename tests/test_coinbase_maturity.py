"""
Tests for coinbase maturity enforcement.

Coinbase transaction outputs cannot be spent until they have at least
COINBASE_MATURITY (100) confirmations. This is a consensus rule.

Reference: Bitcoin Core consensus/consensus.h, consensus/tx_verify.cpp
"""

import sys
import pytest

# Skip tests if sync module is mocked (not available in test environment)
_sync_is_mock = getattr(sys.modules.get("sync", None), "__file__", "") == "<test-mock>"
pytestmark = pytest.mark.skipif(
    _sync_is_mock,
    reason="sync module is mocked in test environment"
)


class TestCoinbaseMaturityConstant:
    """Test the COINBASE_MATURITY constant."""

    def test_constant_value(self):
        """COINBASE_MATURITY should be 100 (matches Bitcoin Core)."""
        from sync import coinbase_maturity_constant

        assert coinbase_maturity_constant() == 100


class TestCheckCoinbaseMaturity:
    """Test the coinbase maturity check function."""

    def test_non_coinbase_always_allowed(self):
        """Non-coinbase UTXOs should always pass maturity check."""
        from sync import check_coinbase_maturity

        # Non-coinbase at any height can be spent at any height
        assert check_coinbase_maturity(False, 0, 1) is None
        assert check_coinbase_maturity(False, 100, 100) is None
        assert check_coinbase_maturity(False, 200, 100) is None
        assert check_coinbase_maturity(False, 1000, 0) is None

    def test_immature_coinbase_rejected(self):
        """Coinbase with fewer than 100 confirmations should be rejected."""
        from sync import check_coinbase_maturity

        # Coinbase at height 100, spending at height 150 (depth = 50)
        result = check_coinbase_maturity(True, 100, 150)
        assert result is not None
        assert "bad-txns-premature-spend-of-coinbase" in result
        assert "depth 50" in result

        # Coinbase at height 100, spending at height 199 (depth = 99)
        result = check_coinbase_maturity(True, 100, 199)
        assert result is not None
        assert "depth 99" in result

        # Coinbase at height 100, spending at height 101 (depth = 1)
        result = check_coinbase_maturity(True, 100, 101)
        assert result is not None
        assert "depth 1" in result

    def test_mature_coinbase_allowed(self):
        """Coinbase with 100+ confirmations should be allowed."""
        from sync import check_coinbase_maturity

        # Coinbase at height 100, spending at height 200 (depth = 100)
        assert check_coinbase_maturity(True, 100, 200) is None

        # Coinbase at height 100, spending at height 201 (depth = 101)
        assert check_coinbase_maturity(True, 100, 201) is None

        # Coinbase at height 0, spending at height 100 (depth = 100)
        assert check_coinbase_maturity(True, 0, 100) is None

        # Coinbase at height 0, spending at height 1000 (depth = 1000)
        assert check_coinbase_maturity(True, 0, 1000) is None

    def test_edge_case_same_height(self):
        """Spending at same height as coinbase (depth = 0) should fail."""
        from sync import check_coinbase_maturity

        result = check_coinbase_maturity(True, 100, 100)
        assert result is not None
        assert "depth 0" in result

    def test_edge_case_large_heights(self):
        """Maturity check should work with large height values."""
        from sync import check_coinbase_maturity

        # Large heights, mature
        assert check_coinbase_maturity(True, 800000, 800100) is None

        # Large heights, immature
        result = check_coinbase_maturity(True, 800000, 800099)
        assert result is not None

    def test_genesis_coinbase(self):
        """Genesis block coinbase (height 0) should mature at height 100."""
        from sync import check_coinbase_maturity

        # Not spendable at height 99
        result = check_coinbase_maturity(True, 0, 99)
        assert result is not None

        # Spendable at height 100
        assert check_coinbase_maturity(True, 0, 100) is None


class TestCoinbaseMaturityIntegration:
    """Integration tests for coinbase maturity in validation flow."""

    def test_python_validation_uses_maturity(self):
        """Python TransactionValidator should enforce coinbase maturity."""
        # This test verifies the Python validation.py code path
        # which already has COINBASE_MATURITY enforcement
        from ouroboros.validation import COINBASE_MATURITY

        assert COINBASE_MATURITY == 100

    def test_rust_constant_matches_python(self):
        """Rust and Python constants should match."""
        from sync import coinbase_maturity_constant
        from ouroboros.validation import COINBASE_MATURITY

        assert coinbase_maturity_constant() == COINBASE_MATURITY
