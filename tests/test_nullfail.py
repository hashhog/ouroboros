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
        get_block_script_flags,
        segwit_activation_height,
    )
    HAS_RUST_MODULE = True
except ImportError:
    HAS_RUST_MODULE = False

from ouroboros.script import (
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SEGWIT_ACTIVATION_HEIGHT,
    get_flags_for_height,
    get_standard_script_flags,
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
    """Where NULLFAIL belongs: the STANDARD (policy) flag set, not consensus.

    UPDATED 2026-07: these assertions previously demanded NULLFAIL inside
    ``get_flags_for_height()``, the block-validation (consensus) flag set.
    That is wrong.  In Bitcoin Core NULLFAIL is a member of
    STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:125) and appears nowhere in
    ``GetBlockScriptFlags()`` (validation.cpp:2249-2289), whose only outputs
    are P2SH, WITNESS, TAPROOT, DERSIG, CLTV, CSV and NULLDUMMY.  Putting
    NULLFAIL in the consensus set would make the node reject historical blocks
    Core accepts.  The rule itself is still enforced for relay — it just rides
    ``get_standard_script_flags()``.
    """

    def test_nullfail_not_in_consensus_flags(self):
        """NULLFAIL must NEVER be in the consensus (block-validation) flags."""
        for height in (
            SEGWIT_ACTIVATION_HEIGHT - 1,
            SEGWIT_ACTIVATION_HEIGHT,
            SEGWIT_ACTIVATION_HEIGHT + 10000,
        ):
            flags = get_flags_for_height(height)
            assert not (flags & SCRIPT_VERIFY_NULLFAIL), (
                f"NULLFAIL is policy-only (policy/policy.h:125) but leaked "
                f"into consensus flags at height {height}"
            )

    def test_nulldummy_is_the_consensus_flag_that_rides_segwit(self):
        """BIP147 NULLDUMMY — not NULLFAIL — is what SegWit gates in consensus.

        Ref: validation.cpp:2283-2286.
        """
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT - 1)
        assert not (flags & SCRIPT_VERIFY_NULLDUMMY)

        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_NULLDUMMY
        assert flags & SCRIPT_VERIFY_WITNESS

    def test_nullfail_not_active_before_segwit_in_standard_flags(self):
        """NULLFAIL should NOT be active before SegWit activation."""
        flags = get_standard_script_flags(SEGWIT_ACTIVATION_HEIGHT - 1)
        assert not (flags & SCRIPT_VERIFY_NULLFAIL)

    def test_nullfail_active_at_segwit_in_standard_flags(self):
        """NULLFAIL MUST be enforced for relay from SegWit activation height."""
        flags = get_standard_script_flags(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_NULLFAIL
        assert flags & SCRIPT_VERIFY_WITNESS
        assert flags & SCRIPT_VERIFY_NULLDUMMY

    def test_nullfail_active_after_segwit_in_standard_flags(self):
        """NULLFAIL should remain active after SegWit activation."""
        flags = get_standard_script_flags(SEGWIT_ACTIVATION_HEIGHT + 10000)
        assert flags & SCRIPT_VERIFY_NULLFAIL

    def test_nullfail_couples_to_witness_in_standard_flags(self):
        """NULLFAIL and WITNESS are activated together per BIP146 (policy set)."""
        flags = get_standard_script_flags(SEGWIT_ACTIVATION_HEIGHT)
        has_witness = bool(flags & SCRIPT_VERIFY_WITNESS)
        has_nullfail = bool(flags & SCRIPT_VERIFY_NULLFAIL)
        assert has_witness == has_nullfail, (
            "NULLFAIL and WITNESS must be activated together per BIP146"
        )


@pytest.mark.skipif(not HAS_RUST_MODULE, reason="Rust sync module not built")
class TestRustNullfailBindings:
    """Test the Rust PyO3 bindings for script verification flags."""

    def test_rust_nullfail_constant(self):
        """Rust module should expose NULLFAIL constant."""
        assert PyScriptVerifyFlags.NULLFAIL == (1 << 14)

    def test_rust_block_script_flags(self):
        """Rust GetBlockScriptFlags port: consensus set at SegWit height.

        UPDATED 2026-07: previously asserted NULLFAIL here.  NULLFAIL is
        policy-only (policy/policy.h:125) and must not appear in a consensus
        flag set — the Rust helper used to leak it (plus WITNESS_PUBKEYTYPE).
        """
        flags = get_block_script_flags(481824, "mainnet")
        assert not (flags & PyScriptVerifyFlags.NULLFAIL)
        assert flags & PyScriptVerifyFlags.WITNESS
        assert flags & PyScriptVerifyFlags.P2SH

    def test_rust_segwit_activation_height(self):
        """Rust function should return correct SegWit activation height.

        UPDATED 2026-07: testnet4/signet are 1 in Core (chainparams.cpp:316,
        :460), matching BURIED_DEPLOYMENTS on the Python side; they were 0.
        Only the genesis block is affected and genesis is never
        script-validated.
        """
        assert segwit_activation_height("mainnet") == 481824
        assert segwit_activation_height("testnet") == 834624
        assert segwit_activation_height("testnet4") == 1
        assert segwit_activation_height("signet") == 1
        assert segwit_activation_height("regtest") == 0

    def test_rust_taproot_exception_block_692261(self):
        """Rust port honours script_flag_exceptions and still ORs step 3."""
        block_hash = bytes.fromhex(
            "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
        )[::-1]  # internal (little-endian) order
        flags = get_block_script_flags(692261, "mainnet", block_hash)

        assert not (flags & PyScriptVerifyFlags.TAPROOT), "TAPROOT is stripped"
        assert flags & PyScriptVerifyFlags.P2SH
        assert flags & PyScriptVerifyFlags.WITNESS
        # Control: any other hash at the same height KEEPS taproot.
        other = bytearray(block_hash)
        other[0] ^= 0x01
        assert get_block_script_flags(692261, "mainnet", bytes(other)) & (
            PyScriptVerifyFlags.TAPROOT
        )

    def test_rust_bip16_exception_block_170060(self):
        """[170060] -> SCRIPT_VERIFY_NONE in the Rust port too."""
        block_hash = bytes.fromhex(
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        )[::-1]
        assert get_block_script_flags(170060, "mainnet", block_hash) == 0

    def test_rust_flags_base_is_unconditional(self):
        """P2SH/WITNESS/TAPROOT are on for every block, incl. pre-activation."""
        flags = get_block_script_flags(0, "mainnet")
        assert flags & PyScriptVerifyFlags.P2SH
        assert flags & PyScriptVerifyFlags.WITNESS
        assert not (flags & PyScriptVerifyFlags.NULLFAIL)

    def test_rust_flags_regtest(self):
        """Regtest: no NULLFAIL in the consensus set at any height."""
        flags = get_block_script_flags(0, "regtest")
        assert not (flags & PyScriptVerifyFlags.NULLFAIL)
        assert flags & PyScriptVerifyFlags.P2SH

    def test_rust_flags_testnet4(self):
        """Testnet4: no NULLFAIL in the consensus set at any height."""
        flags = get_block_script_flags(0, "testnet4")
        assert not (flags & PyScriptVerifyFlags.NULLFAIL)
        assert flags & PyScriptVerifyFlags.P2SH

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
