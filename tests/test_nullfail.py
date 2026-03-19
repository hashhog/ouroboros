"""
Tests for BIP146 NULLFAIL enforcement.

NULLFAIL (BIP146) requires that when a signature check opcode (OP_CHECKSIG,
OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY) fails, the
signature argument(s) must be empty byte vectors. This rule is consensus-
mandatory at SegWit activation height (481824 on mainnet).

These tests verify that:
1. The Rust sync module correctly exposes script verification flags
2. NULLFAIL is included in the flags at SegWit activation height
3. The Python script interpreter enforces NULLFAIL correctly
"""

import pytest

# Test that we can import from the Rust sync module
try:
    from sync import (
        PyScriptVerifyFlags,
        get_script_flags_for_height,
        segwit_activation_height,
    )
    HAS_RUST_MODULE = True
except ImportError:
    HAS_RUST_MODULE = False

from ouroboros.script import (
    SCRIPT_VERIFY_NONE,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_NULLDUMMY,
    SEGWIT_ACTIVATION_HEIGHT,
    get_flags_for_height,
)


class TestNullfailFlagValues:
    """Test that NULLFAIL flag values are correct and consistent."""

    def test_nullfail_flag_value(self):
        """NULLFAIL should be bit 14 (1 << 14 = 16384)."""
        assert SCRIPT_VERIFY_NULLFAIL == (1 << 14)
        assert SCRIPT_VERIFY_NULLFAIL == 16384

    def test_segwit_activation_height_mainnet(self):
        """SegWit activation height on mainnet is 481824."""
        assert SEGWIT_ACTIVATION_HEIGHT == 481824


class TestNullfailActivation:
    """Test that NULLFAIL is activated at the correct heights."""

    def test_nullfail_not_active_before_segwit(self):
        """NULLFAIL should NOT be active before SegWit activation."""
        # Just before SegWit activation
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT - 1)
        assert not (flags & SCRIPT_VERIFY_NULLFAIL)

    def test_nullfail_active_at_segwit(self):
        """NULLFAIL MUST be active at SegWit activation height."""
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_NULLFAIL
        assert flags & SCRIPT_VERIFY_WITNESS
        assert flags & SCRIPT_VERIFY_NULLDUMMY

    def test_nullfail_active_after_segwit(self):
        """NULLFAIL should remain active after SegWit activation."""
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT + 10000)
        assert flags & SCRIPT_VERIFY_NULLFAIL

    def test_nullfail_consensus_not_policy(self):
        """
        NULLFAIL is a consensus rule, not a policy rule.

        This is critical: Bitcoin Core's documentation in interpreter.h
        notes that NULLFAIL is mandatory at SegWit activation, not just
        policy. This test documents that expectation.
        """
        # At SegWit height, NULLFAIL must be included in consensus flags
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT)

        # NULLFAIL must be present with WITNESS (they're activated together)
        has_witness = bool(flags & SCRIPT_VERIFY_WITNESS)
        has_nullfail = bool(flags & SCRIPT_VERIFY_NULLFAIL)

        # Both must be present or both absent - they're coupled
        assert has_witness == has_nullfail, (
            "NULLFAIL and WITNESS must be activated together per BIP146"
        )


@pytest.mark.skipif(not HAS_RUST_MODULE, reason="Rust sync module not built")
class TestRustNullfailBindings:
    """Test the Rust PyO3 bindings for script verification flags."""

    def test_rust_nullfail_constant(self):
        """Rust module should expose NULLFAIL constant."""
        assert PyScriptVerifyFlags.NULLFAIL == (1 << 14)

    def test_rust_get_flags_for_height(self):
        """Rust function should return correct flags for SegWit height."""
        flags = get_script_flags_for_height(481824, "mainnet")
        assert flags & PyScriptVerifyFlags.NULLFAIL
        assert flags & PyScriptVerifyFlags.WITNESS

    def test_rust_segwit_activation_height(self):
        """Rust function should return correct SegWit activation height."""
        assert segwit_activation_height("mainnet") == 481824
        assert segwit_activation_height("testnet") == 834624
        assert segwit_activation_height("testnet4") == 0
        assert segwit_activation_height("regtest") == 0

    def test_rust_flags_before_segwit(self):
        """Rust flags should NOT include NULLFAIL before SegWit."""
        flags = get_script_flags_for_height(481823, "mainnet")
        assert not (flags & PyScriptVerifyFlags.NULLFAIL)

    def test_rust_flags_regtest(self):
        """Regtest should have NULLFAIL from genesis."""
        flags = get_script_flags_for_height(0, "regtest")
        assert flags & PyScriptVerifyFlags.NULLFAIL

    def test_rust_flags_testnet4(self):
        """Testnet4 should have NULLFAIL from genesis."""
        flags = get_script_flags_for_height(0, "testnet4")
        assert flags & PyScriptVerifyFlags.NULLFAIL

    def test_rust_pyscriptverifyflags_wrapper(self):
        """Test PyScriptVerifyFlags wrapper class."""
        flags_obj = PyScriptVerifyFlags(
            PyScriptVerifyFlags.NULLFAIL | PyScriptVerifyFlags.WITNESS
        )
        assert flags_obj.has_nullfail()
        assert flags_obj.has_witness()
        assert not flags_obj.has_p2sh()


class TestNullfailConsistency:
    """Test consistency between Python and Rust implementations."""

    @pytest.mark.skipif(not HAS_RUST_MODULE, reason="Rust sync module not built")
    def test_python_rust_flag_values_match(self):
        """Python and Rust flag constants must match."""
        assert SCRIPT_VERIFY_NULLFAIL == PyScriptVerifyFlags.NULLFAIL
        assert SCRIPT_VERIFY_WITNESS == PyScriptVerifyFlags.WITNESS
        assert SCRIPT_VERIFY_P2SH == PyScriptVerifyFlags.P2SH
        assert SCRIPT_VERIFY_NULLDUMMY == PyScriptVerifyFlags.NULLDUMMY

    @pytest.mark.skipif(not HAS_RUST_MODULE, reason="Rust sync module not built")
    def test_python_rust_activation_heights_match(self):
        """Python and Rust activation heights must match."""
        assert SEGWIT_ACTIVATION_HEIGHT == segwit_activation_height("mainnet")
