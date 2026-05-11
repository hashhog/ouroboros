"""
BIP9 versionbits deployment state machine for soft fork activation.

This module provides a Python interface to the Rust versionbits implementation,
along with buried deployment support for soft forks that have been activated
long ago and are now enforced by block height rather than version bits.

Reference: Bitcoin Core versionbits.cpp, BIP9
https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki

W91 audit: 7 bugs fixed vs Bitcoin Core versionbits.cpp / versionbits.h:
  Bug 1: VERSIONBITS_NUM_BITS (29) was missing — Core versionbits.h:25
  Bug 2: VERSIONBITS_LAST_OLD_BLOCK_VERSION (4) was missing — Core versionbits.h:19
  Bug 3: NO_TIMEOUT constant was missing — Core consensus/params.h:70
  Bug 4: Deployment.threshold default was 1815 (90%), correct default is 1916 (95%)
         — Core BIP9Deployment::threshold defaults to 1916 (params.h:67)
  Bug 5: compute_block_version passed height (new block) instead of height-1
         (pindexPrev); Core always calls GetStateFor(pindexPrev) — versionbits.cpp:272
  Bug 6: check_version_signal did not validate bit in range 0..VERSIONBITS_NUM_BITS-1
  Bug 7: Full pure-Python BIP9 state machine missing; Python fallback in
         get_deployment_state was wrong for non-ALWAYS_ACTIVE deployments (used
         min_activation_height as a height proxy instead of the real state machine)
"""

from dataclasses import dataclass
from enum import Enum
import sys


class DeploymentState(Enum):
    """
    BIP9 deployment states.

    The state machine transitions:
    DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
           or -> FAILED (on timeout without activation)
    """
    DEFINED = "defined"
    STARTED = "started"
    LOCKED_IN = "locked_in"
    ACTIVE = "active"
    FAILED = "failed"


@dataclass
class Deployment:
    """
    BIP9 soft fork deployment parameters.

    Attributes:
        name: Human-readable deployment name (e.g., "taproot")
        bit: Version bit position (0-28) used for signaling
        start_time: Unix timestamp when signaling starts (MTP comparison)
        timeout: Unix timestamp when deployment fails if not locked in
        min_activation_height: Minimum height for activation (speedy trial)
        threshold: Required signaling blocks per period
        period: Signalling period length in blocks
    """
    name: str
    bit: int
    start_time: int
    timeout: int
    min_activation_height: int = 0
    # Bug 4 fix: Core's BIP9Deployment::threshold default is 1916 (95%), not 1815.
    # Ref: Bitcoin Core consensus/params.h:67
    # Per-deployment configs that want 1815 (90%) or 108 (75%) must set it explicitly.
    threshold: int = 1916
    period: int = 2016

    # Special values for start_time
    # Ref: Bitcoin Core consensus/params.h:76, 81
    ALWAYS_ACTIVE = -1
    NEVER_ACTIVE = -2

    # Special value for timeout meaning "never expires"
    # Ref: Bitcoin Core consensus/params.h:70 — std::numeric_limits<int64_t>::max()
    NO_TIMEOUT = (1 << 63) - 1


# Difficulty period (retarget interval)
DIFFICULTYPERIOD = 2016

# Version bits constants
# Ref: Bitcoin Core versionbits.h:21-25
VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_TOP_MASK = 0xE0000000
# Bug 1 fix: VERSIONBITS_NUM_BITS was missing.
# Total bits available for versionbits (bits 0..28).
# Ref: Bitcoin Core versionbits.h:25
VERSIONBITS_NUM_BITS = 29
# Bug 2 fix: VERSIONBITS_LAST_OLD_BLOCK_VERSION was missing.
# Block versions below this predate BIP9 versionbits.
# Ref: Bitcoin Core versionbits.h:19
VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4
# Bug 3 fix: NO_TIMEOUT constant was missing.
# Ref: Bitcoin Core consensus/params.h:70
VERSIONBITS_NO_TIMEOUT = (1 << 63) - 1


# =============================================================================
# Buried Deployments
# =============================================================================
# Soft forks that activated long ago are "buried" - their activation is
# enforced by height rather than version bits (BIP90).

@dataclass
class BuriedDeployment:
    """
    A buried deployment is one where activation height is hardcoded.

    These soft forks activated long ago and no longer need BIP9 checks.
    """
    name: str
    height: int  # Activation height on mainnet


# Buried deployment heights (mainnet)
# Ref: Bitcoin Core consensus/params.h, chainparams.cpp
BURIED_DEPLOYMENTS = {
    "mainnet": {
        "bip34": BuriedDeployment("bip34", 227931),   # Height in coinbase
        "bip65": BuriedDeployment("bip65", 388381),   # CHECKLOCKTIMEVERIFY
        "bip66": BuriedDeployment("bip66", 363725),   # Strict DER signatures
        "csv": BuriedDeployment("csv", 419328),       # BIP68/112/113
        "segwit": BuriedDeployment("segwit", 481824), # BIP141/143/147
    },
    "testnet": {
        "bip34": BuriedDeployment("bip34", 21111),
        "bip65": BuriedDeployment("bip65", 581885),
        "bip66": BuriedDeployment("bip66", 330776),
        "csv": BuriedDeployment("csv", 770112),
        "segwit": BuriedDeployment("segwit", 834624),
    },
    "testnet3": {
        "bip34": BuriedDeployment("bip34", 21111),
        "bip65": BuriedDeployment("bip65", 581885),
        "bip66": BuriedDeployment("bip66", 330776),
        "csv": BuriedDeployment("csv", 770112),
        "segwit": BuriedDeployment("segwit", 834624),
    },
    "testnet4": {
        # All buried deployments active from genesis on testnet4
        "bip34": BuriedDeployment("bip34", 1),
        "bip65": BuriedDeployment("bip65", 1),
        "bip66": BuriedDeployment("bip66", 1),
        "csv": BuriedDeployment("csv", 1),
        "segwit": BuriedDeployment("segwit", 1),
    },
    "signet": {
        # All buried deployments active from genesis on signet
        "bip34": BuriedDeployment("bip34", 1),
        "bip65": BuriedDeployment("bip65", 1),
        "bip66": BuriedDeployment("bip66", 1),
        "csv": BuriedDeployment("csv", 1),
        "segwit": BuriedDeployment("segwit", 1),
    },
    "regtest": {
        # All buried deployments active from genesis on regtest
        "bip34": BuriedDeployment("bip34", 1),
        "bip65": BuriedDeployment("bip65", 1),
        "bip66": BuriedDeployment("bip66", 1),
        "csv": BuriedDeployment("csv", 1),
        "segwit": BuriedDeployment("segwit", 0),  # Active from genesis
    },
}

# =============================================================================
# BIP30 / BIP34 canonical-chain hashes
# =============================================================================
# Bitcoin Core validation.cpp:2460-2462:
#   CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(params.GetConsensus().BIP34Height);
#   fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height ||
#       !(pindexBIP34height->GetBlockHash() == params.GetConsensus().BIP34Hash));
#
# The BIP30 check can be skipped once BIP34 is provably active on the
# canonical chain — verified by confirming the block at BIP34Height has
# the expected hash.  If BIP34Hash is all-zeros (testnet4 / signet /
# regtest), the hash comparison always fails, so BIP30 is always enforced
# on those networks (which is correct: they have no 91842/91880 exceptions
# either, so every block must be checked).
#
# Ref: Bitcoin Core kernel/chainparams.cpp
BIP34_HASHES: dict[str, bytes] = {
    # mainnet: block 227931 hash (big-endian display form, stored as bytes)
    # Ref: kernel/chainparams.cpp:90
    "mainnet": bytes.fromhex(
        "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
    ),
    # testnet3: block 21111 hash
    # Ref: kernel/chainparams.cpp:213
    "testnet": bytes.fromhex(
        "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
    ),
    "testnet3": bytes.fromhex(
        "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
    ),
    # testnet4 / signet / regtest: BIP34Hash = uint256{} (all zeros).
    # The zero hash will never match a real block hash, so
    # fEnforceBIP30 stays True on these networks — BIP30 is always enforced.
    # Ref: kernel/chainparams.cpp:312, 456, 537
    "testnet4": bytes(32),
    "signet": bytes(32),
    "regtest": bytes(32),
}

# =============================================================================
# BIP30 "repeat" block exceptions (IsBIP30Repeat in validation.cpp:6189-6193)
# =============================================================================
# Two historical mainnet blocks contain coinbase transactions that duplicate
# an earlier block's coinbase.  Bitcoin Core exempts these blocks from the
# BIP30 UTXO-collision check.  The exception is keyed by *both* height AND
# block hash — a fork block at the same height does NOT get the exception.
#
# Block hashes are stored as 32-byte little-endian (internal byte order,
# matching get_txid() / block.hash throughout ouroboros).
#
# Ref: Bitcoin Core validation.cpp:6189-6193
BIP30_REPEAT_EXCEPTIONS: dict[int, bytes] = {
    91842: bytes.fromhex(
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    ),
    91880: bytes.fromhex(
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    ),
}

# BIP9 deployments by network
# Ref: Bitcoin Core kernel/chainparams.cpp
#
# Note: taproot is now a *buried* deployment in current Bitcoin Core (it was
# de-listed from vDeployments and enforced by height instead).  We keep it
# here as a BIP9 entry only for networks where it was activated via BIP9
# signalling (mainnet) or is marked ALWAYS_ACTIVE (testnets).  The Python
# state machine handles ALWAYS_ACTIVE directly without signalling.
BIP9_DEPLOYMENTS = {
    "mainnet": {
        # Taproot (BIP340/341/342) — activated via speedy trial BIP9.
        # Ref: kernel/chainparams.cpp (historical; now buried at height 709632)
        # threshold=1815 (90% of 2016) — explicitly set per chainparams.cpp:106
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=1619222400,    # April 24, 2021 00:00:00 UTC
            timeout=1628640000,       # August 11, 2021 00:00:00 UTC
            min_activation_height=709632,  # Speedy trial
            threshold=1815,           # 90% of 2016 — explicit per chainparams
            period=2016,
        ),
        # DEPLOYMENT_TESTDUMMY is NEVER_ACTIVE on mainnet.
        # threshold=1815, period=2016 — chainparams.cpp:106
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=Deployment.NEVER_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1815,
            period=2016,
        ),
    },
    "testnet": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,   # 75% of 2016 — testnet default
            period=2016,
        ),
        # DEPLOYMENT_TESTDUMMY on testnet3/testnet: NEVER_ACTIVE per chainparams
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=Deployment.NEVER_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,
            period=2016,
        ),
    },
    "testnet3": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,
            period=2016,
        ),
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=Deployment.NEVER_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,
            period=2016,
        ),
    },
    "testnet4": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,   # 75% of 2016 — testnet4 default per chainparams.cpp:229
            period=2016,
        ),
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=Deployment.NEVER_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1512,
            period=2016,
        ),
    },
    "signet": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1815,   # signet uses 90% per chainparams.cpp:472
            period=2016,
        ),
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=Deployment.NEVER_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=1815,
            period=2016,
        ),
    },
    "regtest": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=108,    # 75% of 144
            period=144,
        ),
        # DEPLOYMENT_TESTDUMMY on regtest: start_time=0 (active from genesis MTP>0)
        # threshold=108 (75% of 144), period=144 — chainparams.cpp:550-555
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=0,
            timeout=VERSIONBITS_NO_TIMEOUT,
            min_activation_height=0,
            threshold=108,    # 75% of 144 — chainparams.cpp:554
            period=144,       # Faster than mainnet for regtest — chainparams.cpp:555
        ),
    },
}


def is_buried_deployment_active(
    deployment: str, height: int, network: str = "mainnet"
) -> bool:
    """
    Check if a buried deployment is active at the given height.

    Buried deployments are soft forks activated long ago, enforced by height.

    Args:
        deployment: Deployment name (bip34, bip65, bip66, csv, segwit)
        height: Block height to check
        network: Network name

    Returns:
        True if the deployment is active at the given height
    """
    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    buried = BURIED_DEPLOYMENTS.get(network_lower, {})
    dep = buried.get(deployment.lower())

    if dep is None:
        return False

    return height >= dep.height


def get_buried_deployment_height(
    deployment: str, network: str = "mainnet"
) -> int | None:
    """
    Get the activation height for a buried deployment.

    Args:
        deployment: Deployment name
        network: Network name

    Returns:
        Activation height, or None if not a buried deployment
    """
    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    buried = BURIED_DEPLOYMENTS.get(network_lower, {})
    dep = buried.get(deployment.lower())

    return dep.height if dep else None


def _bip9_state_for_pindexPrev(
    dep: Deployment,
    prev_height: int,
    versions_map: dict[int, int],
    mtps_map: dict[int, int],
    cache: dict[int | None, DeploymentState],
) -> DeploymentState:
    """
    Pure-Python implementation of AbstractThresholdConditionChecker::GetStateFor.

    Computes the BIP9 state for the block *after* prev_height (i.e. the block
    whose parent is at prev_height).  Mirrors Bitcoin Core versionbits.cpp:26-117
    exactly, including period-boundary alignment and the signal-counting loop.

    Args:
        dep: Deployment parameters.
        prev_height: Height of pindexPrev (parent of the block being evaluated).
                     Pass -1 to represent nullptr (before genesis).
        versions_map: {height: version} for all known blocks.
        mtps_map: {height: mtp} for all known blocks.
        cache: Mutable dict that maps pindexPrev height (or None) to state.
               Acts as the ThresholdConditionCache in Core.  Callers share the
               same cache across multiple calls for performance.

    Returns:
        DeploymentState for the block at prev_height+1.

    Ref: Bitcoin Core versionbits.cpp:26-117
    """
    nPeriod = dep.period
    nThreshold = dep.threshold
    min_activation_height = dep.min_activation_height
    nTimeStart = dep.start_time
    nTimeTimeout = dep.timeout

    # Fast path: ALWAYS_ACTIVE / NEVER_ACTIVE (Core versionbits.cpp:34-42)
    if nTimeStart == Deployment.ALWAYS_ACTIVE:
        return DeploymentState.ACTIVE
    if nTimeStart == Deployment.NEVER_ACTIVE:
        return DeploymentState.FAILED

    # Align pindexPrev to the start of its retarget period.
    # Core: pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod))
    # Ref: versionbits.cpp:45-47
    if prev_height >= 0:
        aligned_prev = prev_height - ((prev_height + 1) % nPeriod)
    else:
        aligned_prev = -1  # nullptr

    # Walk backwards collecting periods that need computation.
    # Core: versionbits.cpp:49-64
    vToCompute: list[int] = []
    cursor = aligned_prev

    while cursor not in cache:
        if cursor < 0:
            # Genesis block is always DEFINED.
            cache[cursor] = DeploymentState.DEFINED
            break
        cursor_mtp = mtps_map.get(cursor, 0)
        if cursor_mtp < nTimeStart:
            # Optimisation: blocks before start_time are always DEFINED.
            # Ref: versionbits.cpp:56-61
            cache[cursor] = DeploymentState.DEFINED
            break
        vToCompute.append(cursor)
        # Step back one full period.
        cursor = cursor - nPeriod

    # Walk forward, computing transitions.
    # Core: versionbits.cpp:70-114
    state = cache[cursor]

    for period_end in reversed(vToCompute):
        state_next = state

        period_end_mtp = mtps_map.get(period_end, 0)

        if state == DeploymentState.DEFINED:
            if period_end_mtp >= nTimeStart:
                state_next = DeploymentState.STARTED

        elif state == DeploymentState.STARTED:
            # Count signalling blocks in this period.
            # Core: versionbits.cpp:83-91 — walk backwards nPeriod blocks.
            count = 0
            for i in range(nPeriod):
                h = period_end - i
                if h < 0:
                    break
                v = versions_map.get(h, 0)
                # Condition: top bits == VERSIONBITS_TOP_BITS and dep bit set.
                # Ref: versionbits_impl.h:79-82
                if ((v & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS and
                        (v & (1 << dep.bit)) != 0):
                    count += 1

            if count >= nThreshold:
                state_next = DeploymentState.LOCKED_IN
            elif period_end_mtp >= nTimeTimeout:
                state_next = DeploymentState.FAILED

        elif state == DeploymentState.LOCKED_IN:
            # Transition to ACTIVE if min_activation_height is satisfied.
            # Core: versionbits.cpp:101-103
            # pindexPrev->nHeight + 1 >= min_activation_height
            if period_end + 1 >= min_activation_height:
                state_next = DeploymentState.ACTIVE

        # ACTIVE and FAILED are terminal; state_next == state.

        cache[period_end] = state_next
        state = state_next

    return state


def get_deployment_state(
    deployment: str,
    height: int,
    network: str = "mainnet",
    block_versions: list[tuple[int, int]] | None = None,
    block_mtps: list[tuple[int, int]] | None = None,
) -> DeploymentState:
    """
    Get the BIP9 deployment state at the given height.

    This function handles both buried deployments (by height) and
    BIP9 deployments.  The Rust sync module is used when available;
    otherwise the full pure-Python state machine (_bip9_state_for_pindexPrev)
    is used.  The old "min_activation_height as proxy" fallback has been
    replaced with the correct implementation.

    Args:
        deployment: Deployment name (taproot, csv, segwit, bip65, etc.)
        height: Block height to check (the block itself, not its parent)
        network: Network name
        block_versions: List of (height, version) tuples for BIP9 signal counting
        block_mtps: List of (height, mtp) tuples for time-based transitions

    Returns:
        DeploymentState enum value

    Ref: Bitcoin Core versionbits.cpp:26-117, AbstractThresholdConditionChecker::GetStateFor
    """
    deployment_lower = deployment.lower()
    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    # Check if this is a buried deployment first
    if deployment_lower in ("bip34", "bip65", "bip66", "csv", "segwit"):
        if is_buried_deployment_active(deployment_lower, height, network_lower):
            return DeploymentState.ACTIVE
        else:
            return DeploymentState.DEFINED

    # For BIP9 deployments, prefer the Rust implementation when available.
    try:
        from sync import get_deployment_state as rust_get_deployment_state

        versions = block_versions or []
        mtps = block_mtps or []

        state_str = rust_get_deployment_state(
            deployment_lower, height, network_lower, versions, mtps
        )
        return DeploymentState(state_str)

    except ImportError:
        pass

    # Bug 7 fix: use the full pure-Python BIP9 state machine instead of the
    # old broken "min_activation_height as proxy" fallback.
    # Ref: Bitcoin Core versionbits.cpp:26-117
    deployments = BIP9_DEPLOYMENTS.get(network_lower, {})
    dep = deployments.get(deployment_lower)

    if dep is None:
        raise ValueError(f"Unknown deployment: {deployment}")

    # Fast path for special start_time values (also handled inside the state machine,
    # but explicit here for clarity and to avoid building maps unnecessarily).
    if dep.start_time == Deployment.ALWAYS_ACTIVE:
        return DeploymentState.ACTIVE
    if dep.start_time == Deployment.NEVER_ACTIVE:
        return DeploymentState.FAILED

    # Build lookup maps from the provided chain data.
    versions_map: dict[int, int] = dict(block_versions or [])
    mtps_map: dict[int, int] = dict(block_mtps or [])

    # GetStateFor takes pindexPrev (the parent of the block being evaluated).
    # For a block at `height`, pindexPrev is at height-1.
    prev_height = height - 1
    cache: dict[int | None, DeploymentState] = {}

    return _bip9_state_for_pindexPrev(dep, prev_height, versions_map, mtps_map, cache)


def is_deployment_active(
    deployment: str,
    height: int,
    network: str = "mainnet",
    block_versions: list[tuple[int, int]] | None = None,
    block_mtps: list[tuple[int, int]] | None = None,
) -> bool:
    """
    Check if a deployment is active at the given height.

    Args:
        deployment: Deployment name
        height: Block height
        network: Network name
        block_versions: Block version data for BIP9 counting
        block_mtps: Block MTP data for time-based transitions

    Returns:
        True if the deployment is active
    """
    state = get_deployment_state(
        deployment, height, network, block_versions, block_mtps
    )
    return state == DeploymentState.ACTIVE


def get_all_deployments_info(
    height: int,
    network: str = "mainnet",
    block_versions: list[tuple[int, int]] | None = None,
    block_mtps: list[tuple[int, int]] | None = None,
) -> list[dict]:
    """
    Get info about all deployments at a given height.

    Used by getblockchaininfo RPC.

    Args:
        height: Block height
        network: Network name
        block_versions: Block version data
        block_mtps: Block MTP data

    Returns:
        List of deployment info dictionaries
    """
    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    result = []

    # Add buried deployments
    buried = BURIED_DEPLOYMENTS.get(network_lower, {})
    for name, dep in buried.items():
        active = height >= dep.height
        result.append({
            "type": "buried",
            "name": name,
            "active": active,
            "height": dep.height,
        })

    # Add BIP9 deployments via Rust
    try:
        from sync import get_all_deployments_info as rust_get_all_deployments_info

        versions = block_versions or []
        mtps = block_mtps or []

        rust_infos = rust_get_all_deployments_info(height, network_lower, versions, mtps)

        for info in rust_infos:
            result.append({
                "type": "bip9",
                "name": info.name,
                "bit": info.bit,
                "state": info.state,
                "since": info.since,
                "start_time": info.start_time,
                "timeout": info.timeout,
                "min_activation_height": info.min_activation_height,
            })

    except ImportError:
        # Fallback: use the full Python BIP9 state machine (Bug 7 fix also
        # applies here — we no longer use start_time as a proxy for state).
        deployments = BIP9_DEPLOYMENTS.get(network_lower, {})
        versions_map: dict[int, int] = dict(block_versions or [])
        mtps_map: dict[int, int] = dict(block_mtps or [])

        for name, dep in deployments.items():
            cache: dict[int | None, DeploymentState] = {}
            state_enum = _bip9_state_for_pindexPrev(
                dep, height - 1, versions_map, mtps_map, cache
            )
            result.append({
                "type": "bip9",
                "name": name,
                "bit": dep.bit,
                "state": state_enum.value,
                "since": 0,
                "start_time": dep.start_time,
                "timeout": dep.timeout,
                "min_activation_height": dep.min_activation_height,
            })

    return result


def check_version_signal(version: int, bit: int) -> bool:
    """
    Check if a block version signals for a deployment bit.

    BIP9 version signaling requires:
    1. Top 3 bits are 001 (0x20000000)
    2. The specific deployment bit is set
    3. The bit must be in range 0..VERSIONBITS_NUM_BITS-1 (0..28)

    Args:
        version: Block version (nVersion field)
        bit: Deployment bit position (0-28)

    Returns:
        True if the version signals for the deployment

    Ref: Bitcoin Core versionbits_impl.h:79-82 (VersionBitsConditionChecker::Condition)
    """
    # Bug 6 fix: validate bit is within allowed range.
    # Core uses bits 0..VERSIONBITS_NUM_BITS-1 only.
    # Ref: Bitcoin Core versionbits.h:25, versionbits_impl.h:77
    if not (0 <= bit < VERSIONBITS_NUM_BITS):
        return False

    # Top 3 bits must be 001 (VERSIONBITS_TOP_BITS)
    # Ref: Bitcoin Core versionbits_impl.h:81
    if (version & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS:
        return False

    # Check the specific bit (the "mask")
    # Ref: Bitcoin Core versionbits_impl.h:77, 82
    return (version & (1 << bit)) != 0


def compute_block_version(
    height: int,
    network: str = "mainnet",
    block_versions: list[tuple[int, int]] | None = None,
    block_mtps: list[tuple[int, int]] | None = None,
) -> int:
    """
    Compute the block version to use for a new block at the given height.

    Sets version bits for deployments that are STARTED or LOCKED_IN.

    The state is evaluated at pindexPrev (height - 1), not at height itself.
    Bitcoin Core's ComputeBlockVersion calls GetStateFor(pindexPrev, caches[pos])
    where pindexPrev is the parent of the block being built.

    Args:
        height: Block height for the *new* block being assembled (next block).
        network: Network name
        block_versions: Historical block version data
        block_mtps: Historical block MTP data

    Returns:
        Block version with appropriate bits set

    Ref: Bitcoin Core versionbits.cpp:265-279 (ComputeBlockVersion)
         — iterates deployments, calls GetStateFor(pindexPrev, ...) at each.
    """
    nVersion = VERSIONBITS_TOP_BITS

    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    # Get deployments for this network
    deployments = BIP9_DEPLOYMENTS.get(network_lower, {})

    # Bug 5 fix: evaluate state at pindexPrev (height - 1), not at height.
    # Core: static ComputeBlockVersion(pindexPrev, params, caches) — the caller
    # passes pindexPrev (parent), so GetStateFor receives the *parent* block.
    # get_deployment_state(name, h) internally uses prev_height = h - 1, so
    # to get the parent-based state we must pass height (our new block's height)
    # which causes get_deployment_state to use height-1 as pindexPrev.
    # This is correct: state for building block N = GetStateFor(block N-1).
    for name, dep in deployments.items():
        state = get_deployment_state(
            name, height, network_lower, block_versions, block_mtps
        )

        # Signal for STARTED and LOCKED_IN states.
        # Ref: Bitcoin Core versionbits.cpp:273
        if state in (DeploymentState.STARTED, DeploymentState.LOCKED_IN):
            nVersion |= (1 << dep.bit)

    return nVersion


# =============================================================================
# Deployment thresholds by network
# =============================================================================

def get_deployment_thresholds(network: str) -> tuple[int, int]:
    """
    Get the deployment period and threshold for a network.

    Args:
        network: Network name

    Returns:
        Tuple of (period, threshold)
    """
    network_lower = network.lower()
    if network_lower in ("bitcoin", "mainnet"):
        return (2016, 1815)  # 90%
    elif network_lower in ("testnet", "testnet3", "testnet4"):
        return (2016, 1512)  # 75%
    elif network_lower == "regtest":
        return (144, 108)    # 75%
    elif network_lower == "signet":
        return (2016, 1815)  # 90%
    else:
        return (2016, 1815)  # Default to mainnet
