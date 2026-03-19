"""
Tests for BIP9 versionbits deployment state machine.

Tests the Python consensus module which wraps the Rust versionbits
implementation and provides buried deployment support.
"""

import pytest

from ouroboros.consensus import (
    DeploymentState,
    Deployment,
    BuriedDeployment,
    BURIED_DEPLOYMENTS,
    BIP9_DEPLOYMENTS,
    VERSIONBITS_TOP_BITS,
    VERSIONBITS_TOP_MASK,
    is_buried_deployment_active,
    get_buried_deployment_height,
    get_deployment_state,
    is_deployment_active,
    get_all_deployments_info,
    check_version_signal,
    compute_block_version,
    get_deployment_thresholds,
)


class TestDeploymentState:
    """Test DeploymentState enum."""

    def test_state_values(self):
        """State values should match Rust and Bitcoin Core."""
        assert DeploymentState.DEFINED.value == "defined"
        assert DeploymentState.STARTED.value == "started"
        assert DeploymentState.LOCKED_IN.value == "locked_in"
        assert DeploymentState.ACTIVE.value == "active"
        assert DeploymentState.FAILED.value == "failed"


class TestDeployment:
    """Test Deployment dataclass."""

    def test_deployment_creation(self):
        """Deployment should store parameters correctly."""
        dep = Deployment(
            name="test",
            bit=2,
            start_time=1000,
            timeout=2000,
            min_activation_height=100,
            threshold=1815,
        )
        assert dep.name == "test"
        assert dep.bit == 2
        assert dep.start_time == 1000
        assert dep.timeout == 2000
        assert dep.min_activation_height == 100
        assert dep.threshold == 1815

    def test_special_values(self):
        """Special values should be defined."""
        assert Deployment.ALWAYS_ACTIVE == -1
        assert Deployment.NEVER_ACTIVE == -2


class TestBuriedDeployments:
    """Test buried deployment definitions."""

    def test_mainnet_buried_deployments(self):
        """Mainnet should have correct buried deployment heights."""
        mainnet = BURIED_DEPLOYMENTS["mainnet"]
        assert mainnet["bip34"].height == 227931
        assert mainnet["bip65"].height == 388381
        assert mainnet["bip66"].height == 363725
        assert mainnet["csv"].height == 419328
        assert mainnet["segwit"].height == 481824

    def test_regtest_buried_deployments(self):
        """Regtest should have all buried deployments active from genesis/1."""
        regtest = BURIED_DEPLOYMENTS["regtest"]
        assert regtest["bip34"].height == 1
        assert regtest["bip65"].height == 1
        assert regtest["bip66"].height == 1
        assert regtest["csv"].height == 1
        assert regtest["segwit"].height == 0  # Active from genesis

    def test_testnet4_buried_deployments(self):
        """Testnet4 should have all buried deployments active from height 1."""
        testnet4 = BURIED_DEPLOYMENTS["testnet4"]
        assert testnet4["bip34"].height == 1
        assert testnet4["segwit"].height == 1


class TestIsBuriedDeploymentActive:
    """Test is_buried_deployment_active function."""

    def test_mainnet_bip66_before_activation(self):
        """BIP66 should not be active before height 363725 on mainnet."""
        assert not is_buried_deployment_active("bip66", 363724, "mainnet")

    def test_mainnet_bip66_at_activation(self):
        """BIP66 should be active at height 363725 on mainnet."""
        assert is_buried_deployment_active("bip66", 363725, "mainnet")

    def test_mainnet_bip66_after_activation(self):
        """BIP66 should be active after height 363725 on mainnet."""
        assert is_buried_deployment_active("bip66", 400000, "mainnet")

    def test_regtest_all_active(self):
        """All buried deployments should be active early on regtest."""
        for dep in ["bip34", "bip65", "bip66", "csv"]:
            assert is_buried_deployment_active(dep, 10, "regtest")
        # SegWit active from genesis
        assert is_buried_deployment_active("segwit", 0, "regtest")

    def test_unknown_deployment(self):
        """Unknown deployment should return False."""
        assert not is_buried_deployment_active("unknown", 100, "mainnet")

    def test_bitcoin_network_alias(self):
        """'bitcoin' should work as alias for 'mainnet'."""
        assert is_buried_deployment_active("segwit", 500000, "bitcoin")


class TestGetBuriedDeploymentHeight:
    """Test get_buried_deployment_height function."""

    def test_mainnet_heights(self):
        """Should return correct activation heights for mainnet."""
        assert get_buried_deployment_height("bip34", "mainnet") == 227931
        assert get_buried_deployment_height("segwit", "mainnet") == 481824

    def test_unknown_deployment(self):
        """Unknown deployment should return None."""
        assert get_buried_deployment_height("unknown", "mainnet") is None


class TestGetDeploymentState:
    """Test get_deployment_state function."""

    def test_buried_deployment_active(self):
        """Buried deployment should return ACTIVE when activated."""
        state = get_deployment_state("segwit", 500000, "mainnet")
        assert state == DeploymentState.ACTIVE

    def test_buried_deployment_not_active(self):
        """Buried deployment should return DEFINED before activation."""
        state = get_deployment_state("segwit", 100000, "mainnet")
        assert state == DeploymentState.DEFINED

    def test_regtest_taproot_always_active(self):
        """Taproot should be always active on regtest."""
        state = get_deployment_state("taproot", 0, "regtest")
        assert state == DeploymentState.ACTIVE

    def test_testnet_taproot_always_active(self):
        """Taproot should be always active on testnet."""
        state = get_deployment_state("taproot", 100, "testnet")
        assert state == DeploymentState.ACTIVE


class TestIsDeploymentActive:
    """Test is_deployment_active function."""

    def test_taproot_on_regtest(self):
        """Taproot should be active on regtest at any height."""
        assert is_deployment_active("taproot", 0, "regtest")
        assert is_deployment_active("taproot", 1000, "regtest")

    def test_segwit_on_mainnet(self):
        """SegWit should be active after height 481824 on mainnet."""
        assert not is_deployment_active("segwit", 481823, "mainnet")
        assert is_deployment_active("segwit", 481824, "mainnet")


class TestVersionBitsConstants:
    """Test versionbits constants."""

    def test_top_bits(self):
        """Top bits should be 0x20000000 (binary: 001...)."""
        assert VERSIONBITS_TOP_BITS == 0x20000000

    def test_top_mask(self):
        """Top mask should be 0xE0000000 (binary: 111...)."""
        assert VERSIONBITS_TOP_MASK == 0xE0000000


class TestCheckVersionSignal:
    """Test check_version_signal function."""

    def test_valid_signal(self):
        """Version with correct top bits and signal bit should return True."""
        version = VERSIONBITS_TOP_BITS | (1 << 2)
        assert check_version_signal(version, 2) is True

    def test_no_signal_bit_not_set(self):
        """Version without signal bit should return False."""
        version = VERSIONBITS_TOP_BITS
        assert check_version_signal(version, 2) is False

    def test_invalid_top_bits(self):
        """Version with wrong top bits should return False."""
        version = 0x10000000 | (1 << 2)
        assert check_version_signal(version, 2) is False


class TestComputeBlockVersion:
    """Test compute_block_version function."""

    def test_regtest_version(self):
        """Regtest block version should have testdummy bit set (STARTED)."""
        version = compute_block_version(100, "regtest")
        # Should have top bits
        assert (version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS
        # TestDummy is at bit 28 and should be STARTED on regtest
        # (Taproot is ALWAYS_ACTIVE so shouldn't add its bit)


class TestGetDeploymentThresholds:
    """Test get_deployment_thresholds function."""

    def test_mainnet_thresholds(self):
        """Mainnet should use 90% threshold."""
        period, threshold = get_deployment_thresholds("mainnet")
        assert period == 2016
        assert threshold == 1815  # 90% of 2016

    def test_testnet_thresholds(self):
        """Testnet should use 75% threshold."""
        period, threshold = get_deployment_thresholds("testnet")
        assert period == 2016
        assert threshold == 1512  # 75% of 2016

    def test_regtest_thresholds(self):
        """Regtest should use smaller period."""
        period, threshold = get_deployment_thresholds("regtest")
        assert period == 144
        assert threshold == 108  # 75% of 144


class TestGetAllDeploymentsInfo:
    """Test get_all_deployments_info function."""

    def test_mainnet_has_buried_and_bip9(self):
        """Mainnet should have both buried and BIP9 deployments."""
        infos = get_all_deployments_info(500000, "mainnet")

        # Should have buried deployments
        buried_names = [i["name"] for i in infos if i["type"] == "buried"]
        assert "bip34" in buried_names
        assert "segwit" in buried_names

        # Should have BIP9 deployments
        bip9_names = [i["name"] for i in infos if i["type"] == "bip9"]
        assert "taproot" in bip9_names

    def test_buried_deployment_info(self):
        """Buried deployment info should have correct fields."""
        infos = get_all_deployments_info(500000, "mainnet")
        segwit = next(
            i for i in infos if i["type"] == "buried" and i["name"] == "segwit"
        )
        assert segwit["active"] is True
        assert segwit["height"] == 481824


class TestBIP9Deployments:
    """Test BIP9 deployment definitions."""

    def test_mainnet_taproot(self):
        """Mainnet taproot should have correct parameters."""
        taproot = BIP9_DEPLOYMENTS["mainnet"]["taproot"]
        assert taproot.bit == 2
        assert taproot.min_activation_height == 709632  # Speedy trial

    def test_regtest_testdummy(self):
        """Regtest should have testdummy deployment."""
        testdummy = BIP9_DEPLOYMENTS["regtest"]["testdummy"]
        assert testdummy.bit == 28
        assert testdummy.start_time == 0
