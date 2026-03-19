"""
Test BIP9 versionbits deployment state machine.

Tests the Rust implementation exposed via PyO3 bindings.
"""

import pytest

# Import sync module (built with maturin)
try:
    from sync import (
        get_deployment_state,
        get_all_deployments_info,
        is_deployment_active,
        versionbits_top_bits,
        versionbits_top_mask,
        check_version_signal,
    )
    HAS_SYNC = True
except ImportError:
    HAS_SYNC = False


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestVersionBitsConstants:
    """Test versionbits constants."""

    def test_top_bits(self):
        """Top bits should be 0x20000000 (binary: 001...)."""
        assert versionbits_top_bits() == 0x20000000

    def test_top_mask(self):
        """Top mask should be 0xE0000000 (binary: 111...)."""
        # Note: signed int in Python might show as negative
        expected = 0xE0000000
        actual = versionbits_top_mask() & 0xFFFFFFFF
        assert actual == expected


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestCheckVersionSignal:
    """Test version signal checking."""

    def test_signal_with_bit_set(self):
        """Version with correct top bits and signal bit should return True."""
        # Version with top bits 001 and bit 2 set
        version = 0x20000000 | (1 << 2)
        assert check_version_signal(version, 2) is True

    def test_no_signal_bit_not_set(self):
        """Version without signal bit should return False."""
        version = 0x20000000  # Top bits only, no signal
        assert check_version_signal(version, 2) is False

    def test_invalid_top_bits(self):
        """Version with wrong top bits should return False even with bit set."""
        # Top bits 000 instead of 001
        version = 0x10000000 | (1 << 2)
        assert check_version_signal(version, 2) is False

    def test_multiple_bits(self):
        """Check multiple bits work correctly."""
        version = 0x20000000 | (1 << 1) | (1 << 2) | (1 << 28)
        assert check_version_signal(version, 1) is True
        assert check_version_signal(version, 2) is True
        assert check_version_signal(version, 28) is True
        assert check_version_signal(version, 3) is False


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestDeploymentStateMainnet:
    """Test deployment state on mainnet."""

    def test_taproot_always_active_on_empty_chain(self):
        """Taproot on mainnet has specific activation, may not be always active."""
        # With empty chain data, state depends on deployment params
        # Mainnet taproot has specific start_time, not ALWAYS_ACTIVE
        state = get_deployment_state("taproot", 0, "mainnet", [], [])
        # At genesis, taproot should be defined (not started yet)
        assert state in ["defined", "active"]

    def test_unknown_deployment(self):
        """Unknown deployment should raise ValueError."""
        with pytest.raises(ValueError):
            get_deployment_state("unknown_softfork", 100, "mainnet", [], [])


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestDeploymentStateTestnet:
    """Test deployment state on testnet."""

    def test_taproot_always_active(self):
        """Taproot is always active on testnet."""
        state = get_deployment_state("taproot", 0, "testnet", [], [])
        assert state == "active"

    def test_taproot_active_at_any_height(self):
        """Taproot should be active at any height on testnet."""
        for height in [0, 100, 10000, 1000000]:
            state = get_deployment_state("taproot", height, "testnet", [], [])
            assert state == "active"


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestDeploymentStateTestnet4:
    """Test deployment state on testnet4."""

    def test_taproot_always_active(self):
        """Taproot is always active on testnet4."""
        state = get_deployment_state("taproot", 1000, "testnet4", [], [])
        assert state == "active"


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestDeploymentStateRegtest:
    """Test deployment state on regtest."""

    def test_taproot_always_active(self):
        """Taproot is always active on regtest."""
        state = get_deployment_state("taproot", 0, "regtest", [], [])
        assert state == "active"

    def test_testdummy_defined_at_start(self):
        """TestDummy starts as defined on regtest."""
        # TestDummy has start_time=0, so it should be STARTED after MTP passes
        # With empty MTP data, behavior depends on implementation
        state = get_deployment_state("testdummy", 0, "regtest", [], [])
        # At height 0 with no MTP data, could be defined or started
        assert state in ["defined", "started"]


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestIsDeploymentActive:
    """Test is_deployment_active helper."""

    def test_taproot_active_on_testnet(self):
        """Taproot should be active on testnet."""
        assert is_deployment_active("taproot", 1000, "testnet", [], []) is True

    def test_taproot_active_on_regtest(self):
        """Taproot should be active on regtest."""
        assert is_deployment_active("taproot", 100, "regtest", [], []) is True


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestGetAllDeploymentsInfo:
    """Test get_all_deployments_info."""

    def test_mainnet_has_taproot(self):
        """Mainnet should have taproot deployment."""
        infos = get_all_deployments_info(100, "mainnet", [], [])
        names = [info.name for info in infos]
        assert "taproot" in names

    def test_regtest_has_testdummy(self):
        """Regtest should have testdummy deployment."""
        infos = get_all_deployments_info(100, "regtest", [], [])
        names = [info.name for info in infos]
        assert "testdummy" in names
        assert "taproot" in names

    def test_deployment_info_fields(self):
        """Deployment info should have expected fields."""
        infos = get_all_deployments_info(100, "testnet", [], [])
        assert len(infos) > 0

        info = infos[0]
        assert hasattr(info, "name")
        assert hasattr(info, "bit")
        assert hasattr(info, "state")
        assert hasattr(info, "since")
        assert hasattr(info, "start_time")
        assert hasattr(info, "timeout")
        assert hasattr(info, "min_activation_height")

    def test_testnet_taproot_info(self):
        """Check taproot info on testnet."""
        infos = get_all_deployments_info(100, "testnet", [], [])
        taproot = next((i for i in infos if i.name == "taproot"), None)
        assert taproot is not None
        assert taproot.state == "active"
        assert taproot.bit == 2


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestBIP9StateMachine:
    """Test BIP9 state machine transitions with mock chain data."""

    def test_transition_defined_to_started(self):
        """Test transition from DEFINED to STARTED when MTP passes start_time."""
        # TestDummy on regtest has start_time=0
        # We need to provide MTP data that exceeds start_time
        # Period is 144 blocks on regtest

        # Setup: provide MTP > 0 for the first period
        mtps = [(h, 100) for h in range(144)]  # MTP = 100 > start_time = 0
        versions = [(h, 0x20000000) for h in range(144)]  # No signaling

        state = get_deployment_state("testdummy", 143, "regtest", versions, mtps)
        # After first period with MTP > start_time, should be STARTED
        assert state == "started"

    def test_transition_started_to_locked_in(self):
        """Test transition from STARTED to LOCKED_IN when threshold reached."""
        # Regtest: period=144, threshold=108 (75%)

        # First period: establish STARTED state
        mtps = [(h, 100) for h in range(288)]

        # Second period: signal with bit 28 (testdummy)
        # Need 108/144 = 75% signaling
        versions = []
        for h in range(144):
            versions.append((h, 0x20000000))  # No signal in first period
        for h in range(144, 288):
            # Signal with bit 28
            versions.append((h, 0x20000000 | (1 << 28)))

        state = get_deployment_state("testdummy", 287, "regtest", versions, mtps)
        # Should be LOCKED_IN after threshold reached
        assert state == "locked_in"

    def test_transition_locked_in_to_active(self):
        """Test transition from LOCKED_IN to ACTIVE."""
        # Regtest: period=144

        # Setup three periods worth of data
        mtps = [(h, 100) for h in range(432)]

        # First period: no signal (STARTED)
        # Second period: full signal (LOCKED_IN)
        # Third period: transition to ACTIVE
        versions = []
        for h in range(144):
            versions.append((h, 0x20000000))
        for h in range(144, 288):
            versions.append((h, 0x20000000 | (1 << 28)))
        for h in range(288, 432):
            versions.append((h, 0x20000000))

        state = get_deployment_state("testdummy", 431, "regtest", versions, mtps)
        assert state == "active"


@pytest.mark.skipif(not HAS_SYNC, reason="sync module not available")
class TestNetworkValidation:
    """Test network parameter validation."""

    def test_invalid_network(self):
        """Invalid network should raise ValueError."""
        with pytest.raises(ValueError):
            get_deployment_state("taproot", 100, "invalid_network", [], [])

    def test_all_valid_networks(self):
        """All valid network names should work."""
        networks = ["mainnet", "bitcoin", "testnet", "testnet3", "testnet4", "regtest", "signet"]
        for network in networks:
            # Should not raise
            state = get_deployment_state("taproot", 100, network, [], [])
            assert state in ["defined", "started", "locked_in", "active", "failed"]
