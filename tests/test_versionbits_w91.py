"""
W91 BIP-9 versionbits + ComputeBlockVersion comprehensive audit tests.

Tests the pure-Python BIP-9 state machine and all constants added/fixed
in the W91 audit pass against Bitcoin Core versionbits.cpp / versionbits.h
/ consensus/params.h.

Bug fixes verified by these tests:
  Bug 1: VERSIONBITS_NUM_BITS (29) added — Core versionbits.h:25
  Bug 2: VERSIONBITS_LAST_OLD_BLOCK_VERSION (4) added — Core versionbits.h:19
  Bug 3: NO_TIMEOUT / VERSIONBITS_NO_TIMEOUT added — Core consensus/params.h:70
  Bug 4: Deployment.threshold default corrected 1815→1916 — Core params.h:67
  Bug 5: compute_block_version evaluated state at height instead of height-1
  Bug 6: check_version_signal did not reject bits >= VERSIONBITS_NUM_BITS
  Bug 7: get_deployment_state Python fallback used broken proxy; replaced with
         full pure-Python state machine (_bip9_state_for_pindexPrev)
"""

import sys
import pytest

from ouroboros.consensus import (
    BIP9_DEPLOYMENTS,
    DIFFICULTYPERIOD,
    VERSIONBITS_LAST_OLD_BLOCK_VERSION,
    VERSIONBITS_NO_TIMEOUT,
    VERSIONBITS_NUM_BITS,
    VERSIONBITS_TOP_BITS,
    VERSIONBITS_TOP_MASK,
    Deployment,
    DeploymentState,
    _bip9_state_for_pindexPrev,
    check_version_signal,
    compute_block_version,
    get_deployment_state,
    get_deployment_thresholds,
    is_deployment_active,
)


# ---------------------------------------------------------------------------
# Bug 1: VERSIONBITS_NUM_BITS
# ---------------------------------------------------------------------------

class TestVersionbitsNumBits:
    """VERSIONBITS_NUM_BITS = 29 must be present and correct (Bug 1)."""

    def test_value(self):
        """Core versionbits.h:25 — total bits available = 29."""
        assert VERSIONBITS_NUM_BITS == 29

    def test_bit_28_is_valid_last_bit(self):
        """Bit 28 (testdummy) must be strictly less than VERSIONBITS_NUM_BITS."""
        assert 28 < VERSIONBITS_NUM_BITS

    def test_bit_29_is_out_of_range(self):
        """Bit 29 must be out of valid range."""
        assert not (0 <= 29 < VERSIONBITS_NUM_BITS)


# ---------------------------------------------------------------------------
# Bug 2: VERSIONBITS_LAST_OLD_BLOCK_VERSION
# ---------------------------------------------------------------------------

class TestLastOldBlockVersion:
    """VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4 must be present (Bug 2)."""

    def test_value(self):
        """Core versionbits.h:19 — last pre-BIP9 block version = 4."""
        assert VERSIONBITS_LAST_OLD_BLOCK_VERSION == 4

    def test_version_4_is_old(self):
        """Block version 4 is the last old-style version."""
        assert VERSIONBITS_LAST_OLD_BLOCK_VERSION == 4

    def test_version_5_is_new(self):
        """Block version >= 5 must exceed VERSIONBITS_LAST_OLD_BLOCK_VERSION."""
        assert 5 > VERSIONBITS_LAST_OLD_BLOCK_VERSION


# ---------------------------------------------------------------------------
# Bug 3: NO_TIMEOUT / VERSIONBITS_NO_TIMEOUT
# ---------------------------------------------------------------------------

class TestNoTimeout:
    """NO_TIMEOUT constant must be present and equal int64::max (Bug 3)."""

    def test_versionbits_no_timeout(self):
        """VERSIONBITS_NO_TIMEOUT = 2^63 - 1 (int64 max)."""
        assert VERSIONBITS_NO_TIMEOUT == (1 << 63) - 1

    def test_deployment_no_timeout(self):
        """Deployment.NO_TIMEOUT must equal VERSIONBITS_NO_TIMEOUT."""
        assert Deployment.NO_TIMEOUT == VERSIONBITS_NO_TIMEOUT

    def test_mainnet_testdummy_uses_no_timeout(self):
        """DEPLOYMENT_TESTDUMMY on mainnet must use NO_TIMEOUT."""
        dep = BIP9_DEPLOYMENTS["mainnet"]["testdummy"]
        assert dep.timeout == VERSIONBITS_NO_TIMEOUT

    def test_regtest_testdummy_uses_no_timeout(self):
        """DEPLOYMENT_TESTDUMMY on regtest must use NO_TIMEOUT."""
        dep = BIP9_DEPLOYMENTS["regtest"]["testdummy"]
        assert dep.timeout == VERSIONBITS_NO_TIMEOUT


# ---------------------------------------------------------------------------
# Bug 4: Deployment.threshold default
# ---------------------------------------------------------------------------

class TestDeploymentThresholdDefault:
    """Deployment.threshold default must be 1916 (95%), not 1815 (Bug 4)."""

    def test_default_threshold_is_1916(self):
        """Core consensus/params.h:67 — BIP9Deployment::threshold default = 1916."""
        dep = Deployment(name="x", bit=0, start_time=0, timeout=1)
        assert dep.threshold == 1916

    def test_taproot_explicit_threshold_1815(self):
        """Mainnet taproot uses 1815 explicitly (not the default)."""
        dep = BIP9_DEPLOYMENTS["mainnet"]["taproot"]
        assert dep.threshold == 1815

    def test_regtest_testdummy_threshold_108(self):
        """Regtest testdummy uses 108 (75% of 144)."""
        dep = BIP9_DEPLOYMENTS["regtest"]["testdummy"]
        assert dep.threshold == 108

    def test_testnet_taproot_threshold_1512(self):
        """Testnet taproot uses 1512 (75% of 2016)."""
        dep = BIP9_DEPLOYMENTS["testnet"]["taproot"]
        assert dep.threshold == 1512

    def test_testnet4_testdummy_threshold_1512(self):
        """Testnet4 testdummy uses 1512 (75% of 2016)."""
        dep = BIP9_DEPLOYMENTS["testnet4"]["testdummy"]
        assert dep.threshold == 1512


# ---------------------------------------------------------------------------
# Bug 6: check_version_signal bit range validation
# ---------------------------------------------------------------------------

class TestCheckVersionSignalBitRange:
    """check_version_signal must reject bits outside 0..28 (Bug 6)."""

    def test_bit_0_valid(self):
        """Bit 0 is valid."""
        version = VERSIONBITS_TOP_BITS | (1 << 0)
        assert check_version_signal(version, 0) is True

    def test_bit_28_valid(self):
        """Bit 28 (DEPLOYMENT_TESTDUMMY) is the last valid bit."""
        version = VERSIONBITS_TOP_BITS | (1 << 28)
        assert check_version_signal(version, 28) is True

    def test_bit_29_out_of_range(self):
        """Bit 29 is out of range; must return False even with bit set."""
        version = VERSIONBITS_TOP_BITS | (1 << 29)
        assert check_version_signal(version, 29) is False

    def test_bit_negative_out_of_range(self):
        """Negative bit must return False."""
        assert check_version_signal(VERSIONBITS_TOP_BITS, -1) is False

    def test_bit_31_out_of_range(self):
        """Bit 31 is used by the sign bit; must be rejected."""
        assert check_version_signal(0xFFFFFFFF, 31) is False

    def test_all_bits_0_to_28_valid_when_set(self):
        """All bits 0..28 should work when top bits are correct."""
        for bit in range(VERSIONBITS_NUM_BITS):
            version = VERSIONBITS_TOP_BITS | (1 << bit)
            assert check_version_signal(version, bit) is True, f"bit {bit} failed"

    def test_wrong_top_bits_rejects_valid_range(self):
        """Wrong top bits must cause rejection regardless of bit position."""
        for bit in range(VERSIONBITS_NUM_BITS):
            version = 0x10000000 | (1 << bit)
            assert check_version_signal(version, bit) is False, f"bit {bit} should be rejected"


# ---------------------------------------------------------------------------
# Pure-Python BIP-9 state machine (_bip9_state_for_pindexPrev)
# Ref: Bitcoin Core versionbits.cpp:26-117
# ---------------------------------------------------------------------------

def _make_testdummy_regtest() -> Deployment:
    """Return the regtest testdummy deployment (period=144, threshold=108)."""
    return BIP9_DEPLOYMENTS["regtest"]["testdummy"]


def _fill_period(base_height: int, period: int,
                 signal_count: int, bit: int) -> dict[int, int]:
    """
    Build a versions_map for one period of blocks.
    The first `signal_count` blocks in the period signal for `bit`.
    """
    versions = {}
    for i in range(period):
        h = base_height + i
        if i < signal_count:
            versions[h] = VERSIONBITS_TOP_BITS | (1 << bit)
        else:
            versions[h] = VERSIONBITS_TOP_BITS
    return versions


def _fill_mtp(base_height: int, count: int, mtp_value: int) -> dict[int, int]:
    """Build an mtps_map where all blocks have the given MTP."""
    return {base_height + i: mtp_value for i in range(count)}


class TestBIP9StateMachineCore:
    """Tests for the pure-Python BIP-9 state machine against Core semantics."""

    def test_genesis_is_defined(self):
        """The genesis block (prev=-1 / nullptr) is always DEFINED.
        Ref: Bitcoin Core versionbits.cpp:52-55."""
        dep = _make_testdummy_regtest()
        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, -1, {}, {}, cache)
        assert state == DeploymentState.DEFINED

    def test_always_active_shortcircuits(self):
        """ALWAYS_ACTIVE returns ACTIVE immediately (Core versionbits.cpp:34-37)."""
        dep = BIP9_DEPLOYMENTS["regtest"]["taproot"]
        assert dep.start_time == Deployment.ALWAYS_ACTIVE
        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 1000, {}, {}, cache)
        assert state == DeploymentState.ACTIVE

    def test_never_active_shortcircuits(self):
        """NEVER_ACTIVE returns FAILED immediately (Core versionbits.cpp:39-42)."""
        dep = BIP9_DEPLOYMENTS["mainnet"]["testdummy"]
        assert dep.start_time == Deployment.NEVER_ACTIVE
        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 1000, {}, {}, cache)
        assert state == DeploymentState.FAILED

    def test_before_start_time_stays_defined(self):
        """All blocks with MTP < start_time are DEFINED.
        Ref: Bitcoin Core versionbits.cpp:56-61 (optimisation branch)."""
        dep = _make_testdummy_regtest()
        assert dep.start_time == 0  # regtest: start_time=0
        # MTP = -1 < 0 → should remain DEFINED
        mtps = {h: -1 for h in range(200)}
        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 143, {}, mtps, cache)
        assert state == DeploymentState.DEFINED

    def test_defined_to_started_when_mtp_passes_start_time(self):
        """DEFINED transitions to STARTED when MTP >= start_time at end of period.
        Ref: Bitcoin Core versionbits.cpp:76-80."""
        dep = _make_testdummy_regtest()
        # period=144, start_time=0.  MTP = 100 > 0 → STARTED after period 0.
        mtps = _fill_mtp(0, 200, mtp_value=100)
        cache: dict = {}
        # At the last block of period 0 (height 143), prev_height=142
        # aligned_prev = 142 - ((142+1) % 144) = 142 - 143 = -1? No:
        # aligned_prev = prev_height - ((prev_height + 1) % period)
        # = 143 - ((143 + 1) % 144) = 143 - (144 % 144) = 143 - 0 = 143
        # That is the last block of period 0.
        state = _bip9_state_for_pindexPrev(dep, 143, {}, mtps, cache)
        assert state == DeploymentState.STARTED

    def test_started_to_locked_in_with_full_signalling(self):
        """STARTED transitions to LOCKED_IN when signal count >= threshold.
        Ref: Bitcoin Core versionbits.cpp:83-96."""
        dep = _make_testdummy_regtest()  # period=144, threshold=108
        mtps = _fill_mtp(0, 300, mtp_value=100)
        # Period 0 (heights 0..143): no signalling → DEFINED → STARTED
        # Period 1 (heights 144..287): full signalling
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))    # period 0: no signal
        versions.update(_fill_period(144, 144, 144, dep.bit))  # period 1: all signal

        cache: dict = {}
        # At end of period 1 (height 287), state should be LOCKED_IN
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.LOCKED_IN

    def test_started_stays_started_below_threshold(self):
        """STARTED stays STARTED when signal count < threshold.
        Ref: Bitcoin Core versionbits.cpp:83-96."""
        dep = _make_testdummy_regtest()  # threshold=108
        mtps = _fill_mtp(0, 300, mtp_value=100)
        # Signal only 107 out of 144 in period 1 (below threshold)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 107, dep.bit))

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.STARTED

    def test_threshold_boundary_exactly_at_threshold(self):
        """Exactly threshold signals should lock in.
        Ref: Bitcoin Core versionbits.cpp:93 — count >= nThreshold."""
        dep = _make_testdummy_regtest()  # threshold=108
        mtps = _fill_mtp(0, 300, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 108, dep.bit))  # exactly threshold

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.LOCKED_IN

    def test_threshold_boundary_one_below(self):
        """One below threshold must not lock in."""
        dep = _make_testdummy_regtest()  # threshold=108
        mtps = _fill_mtp(0, 300, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 107, dep.bit))  # threshold - 1

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.STARTED

    def test_started_to_failed_on_timeout(self):
        """STARTED transitions to FAILED when MTP >= timeout without enough signals.
        Ref: Bitcoin Core versionbits.cpp:95-96."""
        dep_params = BIP9_DEPLOYMENTS["regtest"]["testdummy"]
        # Create a copy with a finite timeout
        dep = Deployment(
            name="testdummy_finite",
            bit=dep_params.bit,
            start_time=0,
            timeout=500,          # timeout at MTP=500
            min_activation_height=0,
            threshold=dep_params.threshold,
            period=dep_params.period,
        )
        # Period 0: MTP=100, no signal → STARTED
        # Period 1: MTP=600 >= timeout → FAILED (no enough signals)
        mtps = {}
        mtps.update(_fill_mtp(0, 144, 100))    # period 0: MTP < timeout
        mtps.update(_fill_mtp(144, 144, 600))  # period 1: MTP >= timeout
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 0, dep.bit))

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.FAILED

    def test_locked_in_to_active_after_one_period(self):
        """LOCKED_IN transitions to ACTIVE after next period (no min_activation_height).
        Ref: Bitcoin Core versionbits.cpp:100-103."""
        dep = _make_testdummy_regtest()
        mtps = _fill_mtp(0, 450, mtp_value=100)
        # Period 0: no signal → STARTED
        # Period 1: full signal → LOCKED_IN
        # Period 2: any versions → ACTIVE
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 144, dep.bit))
        versions.update(_fill_period(288, 144, 0, dep.bit))

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 431, versions, mtps, cache)
        assert state == DeploymentState.ACTIVE

    def test_locked_in_respects_min_activation_height(self):
        """LOCKED_IN must not activate until min_activation_height is reached.
        Ref: Bitcoin Core versionbits.cpp:102 — pindexPrev->nHeight + 1 >= min."""
        dep = Deployment(
            name="test_min_height",
            bit=1,
            start_time=0,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=500,  # must not activate before height 500
            threshold=108,
            period=144,
        )
        mtps = _fill_mtp(0, 450, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))    # STARTED
        versions.update(_fill_period(144, 144, 144, dep.bit))  # LOCKED_IN
        versions.update(_fill_period(288, 144, 0, dep.bit))   # still LOCKED_IN (height 431 < 500)

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 431, versions, mtps, cache)
        # At height 432 the new block is built, pindexPrev->nHeight+1 = 432 < 500
        assert state == DeploymentState.LOCKED_IN

    def test_active_is_terminal(self):
        """ACTIVE is a terminal state; additional periods don't change it.
        Ref: Bitcoin Core versionbits.cpp:107-110."""
        dep = _make_testdummy_regtest()
        mtps = _fill_mtp(0, 1000, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))      # STARTED
        versions.update(_fill_period(144, 144, 144, dep.bit))  # LOCKED_IN
        versions.update(_fill_period(288, 144, 0, dep.bit))    # ACTIVE

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 431, versions, mtps, cache)
        assert state == DeploymentState.ACTIVE

        # Many more periods later — still ACTIVE
        versions.update(_fill_period(432, 144 * 5, 0, dep.bit))
        state2 = _bip9_state_for_pindexPrev(dep, 431 + 144 * 5, versions, mtps, cache)
        assert state2 == DeploymentState.ACTIVE

    def test_failed_is_terminal(self):
        """FAILED is a terminal state.
        Ref: Bitcoin Core versionbits.cpp:107-110."""
        dep = Deployment(
            name="doomed",
            bit=1,
            start_time=0,
            timeout=200,   # expires quickly
            min_activation_height=0,
            threshold=108,
            period=144,
        )
        mtps = _fill_mtp(0, 500, mtp_value=300)  # always >= timeout
        versions = _fill_period(0, 500, 0, dep.bit)  # no signals

        cache: dict = {}
        state = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state == DeploymentState.FAILED

        # More periods — still FAILED
        state2 = _bip9_state_for_pindexPrev(dep, 431, versions, mtps, cache)
        assert state2 == DeploymentState.FAILED

    def test_cache_is_populated_after_call(self):
        """The cache should be populated for looked-up periods (performance).
        Ref: Bitcoin Core versionbits.cpp:112-113 — cache[pindexPrev] = state."""
        dep = _make_testdummy_regtest()
        mtps = _fill_mtp(0, 200, mtp_value=100)
        versions = _fill_period(0, 200, 0, dep.bit)

        cache: dict = {}
        _bip9_state_for_pindexPrev(dep, 143, versions, mtps, cache)
        # Cache should have at least one entry
        assert len(cache) > 0

    def test_second_call_uses_cache(self):
        """A second call with the same cache should not recompute.
        Results must be identical."""
        dep = _make_testdummy_regtest()
        mtps = _fill_mtp(0, 300, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, dep.bit))
        versions.update(_fill_period(144, 144, 144, dep.bit))

        cache: dict = {}
        state1 = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        state2 = _bip9_state_for_pindexPrev(dep, 287, versions, mtps, cache)
        assert state1 == state2 == DeploymentState.LOCKED_IN

    def test_period_alignment(self):
        """State at any block within a period should equal the state at the
        period boundary.  Ref: versionbits.cpp:44-47 — period alignment."""
        dep = _make_testdummy_regtest()  # period=144
        mtps = _fill_mtp(0, 300, mtp_value=100)
        versions = _fill_period(0, 300, 0, dep.bit)

        cache: dict = {}
        # Block 144 and block 200 are in the same period (period 1).
        # Both should report the same state (STARTED).
        state_at_144 = _bip9_state_for_pindexPrev(dep, 144, versions, mtps, cache)
        state_at_200 = _bip9_state_for_pindexPrev(dep, 200, versions, mtps, cache)
        assert state_at_144 == state_at_200


# ---------------------------------------------------------------------------
# Bug 5: compute_block_version pindexPrev semantics
# ---------------------------------------------------------------------------

class TestComputeBlockVersionPindexPrev:
    """compute_block_version must evaluate state at height-1 (Bug 5).

    Core versionbits.cpp:265-279 — ComputeBlockVersion receives pindexPrev
    (the parent of the block being built).  For the new block at height N,
    pindexPrev is at height N-1.
    """

    def test_returns_top_bits_when_no_signalling(self):
        """Without any active deployments, version is just VERSIONBITS_TOP_BITS."""
        # Use mainnet; taproot ALWAYS_ACTIVE is not in the signalling set
        # (it returns ACTIVE, not STARTED/LOCKED_IN).
        v = compute_block_version(100, "mainnet")
        assert (v & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS

    def test_testdummy_bit_set_when_started(self):
        """Bit 28 (testdummy) should be set when the deployment is STARTED.
        Use regtest where testdummy has start_time=0."""
        # Period=144, testdummy starts immediately (start_time=0).
        # Build a chain where MTP > 0 so testdummy is STARTED.
        mtps = _fill_mtp(0, 200, mtp_value=100)
        versions = _fill_period(0, 200, 0, 28)  # no signalling

        # State at height 145 (prev=144) should be STARTED.
        v = compute_block_version(145, "regtest", list(versions.items()), list(mtps.items()))
        assert (v & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS
        assert (v & (1 << 28)) != 0, "testdummy bit 28 should be set when STARTED"

    def test_testdummy_bit_clear_when_active(self):
        """Bit 28 should NOT be set once ACTIVE (only STARTED and LOCKED_IN signal).
        Ref: Bitcoin Core versionbits.cpp:273."""
        mtps = _fill_mtp(0, 600, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, 28))      # STARTED
        versions.update(_fill_period(144, 144, 144, 28))  # LOCKED_IN
        versions.update(_fill_period(288, 144, 0, 28))    # ACTIVE

        # After ACTIVE, bit 28 must be clear.
        v = compute_block_version(433, "regtest", list(versions.items()), list(mtps.items()))
        assert (v & (1 << 28)) == 0, "testdummy bit 28 should be clear when ACTIVE"

    def test_testdummy_bit_set_when_locked_in(self):
        """Bit 28 should be set when LOCKED_IN.
        Ref: Bitcoin Core versionbits.cpp:273."""
        mtps = _fill_mtp(0, 400, mtp_value=100)
        versions = {}
        versions.update(_fill_period(0, 144, 0, 28))      # STARTED
        versions.update(_fill_period(144, 144, 144, 28))  # LOCKED_IN
        # height 289: state for parent 288 is LOCKED_IN (just locked in)
        v = compute_block_version(289, "regtest", list(versions.items()), list(mtps.items()))
        assert (v & (1 << 28)) != 0, "testdummy bit 28 should be set when LOCKED_IN"


# ---------------------------------------------------------------------------
# get_deployment_state integration with the full state machine
# ---------------------------------------------------------------------------

class TestGetDeploymentStateFullMachine:
    """Test get_deployment_state delegates correctly to the Python state machine."""

    def test_always_active_returns_active(self):
        """ALWAYS_ACTIVE deployments return ACTIVE immediately."""
        state = get_deployment_state("taproot", 0, "regtest")
        assert state == DeploymentState.ACTIVE

    def test_never_active_returns_failed(self):
        """NEVER_ACTIVE deployments return FAILED immediately."""
        state = get_deployment_state("testdummy", 1000, "mainnet")
        assert state == DeploymentState.FAILED

    def test_regtest_testdummy_defined_before_mtp(self):
        """testdummy is DEFINED before MTP > start_time on regtest."""
        # MTP = -1 < 0 (start_time) → DEFINED
        mtps = [(h, -1) for h in range(200)]
        versions = [(h, VERSIONBITS_TOP_BITS) for h in range(200)]
        state = get_deployment_state("testdummy", 144, "regtest", versions, mtps)
        assert state == DeploymentState.DEFINED

    def test_regtest_testdummy_started_after_mtp(self):
        """testdummy moves to STARTED once MTP >= 0 on regtest."""
        mtps = [(h, 100) for h in range(200)]
        versions = [(h, VERSIONBITS_TOP_BITS) for h in range(200)]
        state = get_deployment_state("testdummy", 145, "regtest", versions, mtps)
        assert state == DeploymentState.STARTED

    def test_regtest_testdummy_locked_in_after_full_signalling(self):
        """testdummy locks in after sufficient signals in a STARTED period."""
        mtps = [(h, 100) for h in range(300)]
        versions = {}
        versions.update(_fill_period(0, 144, 0, 28))      # STARTED period
        versions.update(_fill_period(144, 144, 144, 28))  # full signal → LOCKED_IN

        state = get_deployment_state(
            "testdummy", 288, "regtest",
            list(versions.items()), mtps
        )
        assert state == DeploymentState.LOCKED_IN

    def test_regtest_testdummy_active_after_lock_in(self):
        """testdummy becomes ACTIVE after one full period in LOCKED_IN."""
        mtps = [(h, 100) for h in range(450)]
        versions = {}
        versions.update(_fill_period(0, 144, 0, 28))
        versions.update(_fill_period(144, 144, 144, 28))
        versions.update(_fill_period(288, 144, 0, 28))

        state = get_deployment_state(
            "testdummy", 432, "regtest",
            list(versions.items()), mtps
        )
        assert state == DeploymentState.ACTIVE

    def test_unknown_deployment_raises(self):
        """Unknown deployment must raise ValueError."""
        with pytest.raises(ValueError):
            get_deployment_state("xyzzy_does_not_exist", 100, "mainnet")


# ---------------------------------------------------------------------------
# Deployment constants / definitions
# ---------------------------------------------------------------------------

class TestDeploymentDefinitions:
    """Validate per-network deployment definitions match Core chainparams."""

    def test_mainnet_taproot_params(self):
        """Mainnet taproot parameters match Core chainparams.cpp."""
        dep = BIP9_DEPLOYMENTS["mainnet"]["taproot"]
        assert dep.bit == 2
        assert dep.start_time == 1619222400    # April 24, 2021
        assert dep.timeout == 1628640000       # August 11, 2021
        assert dep.min_activation_height == 709632
        assert dep.threshold == 1815
        assert dep.period == 2016

    def test_mainnet_testdummy_never_active(self):
        """DEPLOYMENT_TESTDUMMY is NEVER_ACTIVE on mainnet per chainparams.cpp:103."""
        dep = BIP9_DEPLOYMENTS["mainnet"]["testdummy"]
        assert dep.start_time == Deployment.NEVER_ACTIVE

    def test_regtest_testdummy_params(self):
        """Regtest testdummy: start_time=0, period=144, threshold=108."""
        dep = BIP9_DEPLOYMENTS["regtest"]["testdummy"]
        assert dep.bit == 28
        assert dep.start_time == 0
        assert dep.period == 144
        assert dep.threshold == 108   # 75% of 144

    def test_testnet_taproot_always_active(self):
        """Taproot is ALWAYS_ACTIVE on testnet, testnet3, testnet4, signet, regtest."""
        for net in ("testnet", "testnet3", "testnet4", "signet", "regtest"):
            dep = BIP9_DEPLOYMENTS[net]["taproot"]
            assert dep.start_time == Deployment.ALWAYS_ACTIVE, f"failed for {net}"

    def test_testnet4_threshold_1512(self):
        """Testnet4 taproot uses threshold=1512 (75% of 2016) per chainparams.cpp:229."""
        dep = BIP9_DEPLOYMENTS["testnet4"]["taproot"]
        assert dep.threshold == 1512

    def test_signet_threshold_1815(self):
        """Signet testdummy uses threshold=1815 (90%) per chainparams.cpp:472."""
        dep = BIP9_DEPLOYMENTS["signet"]["testdummy"]
        assert dep.threshold == 1815


# ---------------------------------------------------------------------------
# VERSIONBITS_TOP_BITS / VERSIONBITS_TOP_MASK correctness
# ---------------------------------------------------------------------------

class TestVersionBitsTopConstants:
    """TOP_BITS and TOP_MASK correctness — sanity check."""

    def test_top_bits(self):
        """Ref: Bitcoin Core versionbits.h:21."""
        assert VERSIONBITS_TOP_BITS == 0x20000000

    def test_top_mask(self):
        """Ref: Bitcoin Core versionbits.h:23."""
        assert VERSIONBITS_TOP_MASK == 0xE0000000

    def test_top_bits_matches_mask(self):
        """VERSIONBITS_TOP_BITS must satisfy its own mask check."""
        assert (VERSIONBITS_TOP_BITS & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS

    def test_difficultyperiod(self):
        """DIFFICULTYPERIOD = 2016 (mainnet retarget interval)."""
        assert DIFFICULTYPERIOD == 2016
