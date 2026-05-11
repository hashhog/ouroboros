"""
BIP9 versionbits deployment state machine for soft fork activation.

This module provides a Python interface to the Rust versionbits implementation,
along with buried deployment support for soft forks that have been activated
long ago and are now enforced by block height rather than version bits.

Reference: Bitcoin Core versionbits.cpp, BIP9
https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
"""

from dataclasses import dataclass
from enum import Enum


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
        threshold: Required signaling blocks per period (default 1815/2016 = 90%)
    """
    name: str
    bit: int
    start_time: int
    timeout: int
    min_activation_height: int = 0
    threshold: int = 1815  # Default 90% of 2016

    # Special values for start_time
    ALWAYS_ACTIVE = -1
    NEVER_ACTIVE = -2


# Difficulty period (retarget interval)
DIFFICULTYPERIOD = 2016

# Version bits constants
VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_TOP_MASK = 0xE0000000


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
# These use the full BIP9 state machine via the Rust implementation
BIP9_DEPLOYMENTS = {
    "mainnet": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=1619222400,    # April 24, 2021 00:00:00 UTC
            timeout=1628640000,       # August 11, 2021 00:00:00 UTC
            min_activation_height=709632,  # Speedy trial
            threshold=1815,           # 90%
        ),
    },
    "testnet": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
        ),
    },
    "testnet3": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
        ),
    },
    "testnet4": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
        ),
    },
    "signet": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
        ),
    },
    "regtest": {
        "taproot": Deployment(
            name="taproot",
            bit=2,
            start_time=Deployment.ALWAYS_ACTIVE,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
        ),
        "testdummy": Deployment(
            name="testdummy",
            bit=28,
            start_time=0,
            timeout=0x7FFFFFFFFFFFFFFF,
            min_activation_height=0,
            threshold=108,  # 75% of 144
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
    BIP9 deployments (via the Rust versionbits state machine).

    Args:
        deployment: Deployment name (taproot, csv, segwit, bip65, etc.)
        height: Block height to check
        network: Network name
        block_versions: List of (height, version) tuples for BIP9 signal counting
        block_mtps: List of (height, mtp) tuples for time-based transitions

    Returns:
        DeploymentState enum value
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

    # For BIP9 deployments, use the Rust implementation
    try:
        from sync import get_deployment_state as rust_get_deployment_state

        versions = block_versions or []
        mtps = block_mtps or []

        state_str = rust_get_deployment_state(
            deployment_lower, height, network_lower, versions, mtps
        )
        return DeploymentState(state_str)

    except ImportError:
        # Fallback: check if deployment is ALWAYS_ACTIVE or use min_activation_height
        deployments = BIP9_DEPLOYMENTS.get(network_lower, {})
        dep = deployments.get(deployment_lower)

        if dep is None:
            raise ValueError(f"Unknown deployment: {deployment}") from None

        if dep.start_time == Deployment.ALWAYS_ACTIVE:
            return DeploymentState.ACTIVE
        elif dep.start_time == Deployment.NEVER_ACTIVE:
            return DeploymentState.FAILED
        elif dep.min_activation_height is not None and height >= dep.min_activation_height:
            # Without Rust versionbits, use the known activation height as a proxy.
            # This is correct for all deployments that activated at their
            # min_activation_height (e.g. taproot via speedy trial at 709632).
            return DeploymentState.ACTIVE
        else:
            # Without Rust, we can't compute the full state machine
            # Return DEFINED as a safe fallback
            return DeploymentState.DEFINED


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
        # Fallback: add BIP9 deployment info from Python definitions
        deployments = BIP9_DEPLOYMENTS.get(network_lower, {})
        for name, dep in deployments.items():
            if dep.start_time == Deployment.ALWAYS_ACTIVE:
                state = "active"
            elif dep.start_time == Deployment.NEVER_ACTIVE:
                state = "failed"
            else:
                state = "defined"

            result.append({
                "type": "bip9",
                "name": name,
                "bit": dep.bit,
                "state": state,
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

    Args:
        version: Block version (nVersion field)
        bit: Deployment bit position (0-28)

    Returns:
        True if the version signals for the deployment
    """
    # Top 3 bits must be 001
    if (version & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS:
        return False

    # Check the specific bit
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

    Args:
        height: Block height for the new block
        network: Network name
        block_versions: Historical block version data
        block_mtps: Historical block MTP data

    Returns:
        Block version with appropriate bits set
    """
    version = VERSIONBITS_TOP_BITS

    network_lower = network.lower()
    if network_lower == "bitcoin":
        network_lower = "mainnet"

    # Get deployments for this network
    deployments = BIP9_DEPLOYMENTS.get(network_lower, {})

    for name, dep in deployments.items():
        state = get_deployment_state(
            name, height, network_lower, block_versions, block_mtps
        )

        # Signal for STARTED and LOCKED_IN states
        if state in (DeploymentState.STARTED, DeploymentState.LOCKED_IN):
            version |= (1 << dep.bit)

    return version


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
