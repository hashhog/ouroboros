"""
Regtest test: deployment state must surface in exactly one RPC —
getdeploymentinfo.deployments — and must agree with the consensus registry
(BURIED_DEPLOYMENTS / BIP9_DEPLOYMENTS) that feeds it.

Core v23+ nested all softfork state under getdeploymentinfo's "deployments"
object (type/bip9/height/active fields) and Core v27 REMOVED the top-level
"softforks" object from getblockchaininfo entirely.  Ouroboros matches that
shape (byte-exact with the Core v31.99 oracle, commit 9c6ed81), so the old
"getblockchaininfo.softforks vs getdeploymentinfo.deployments" bridge is now
pinned as: getblockchaininfo carries NO deployment state at all, and
getdeploymentinfo.deployments cannot disagree with the consensus parameters
because RPCServer._build_deployment_state() projects directly from them.

Reference: Bitcoin Core src/rpc/blockchain.cpp — getblockchaininfo (v31.99
has no "softforks"/"deployments" keys) and getdeploymentinfo (DeploymentInfo()
/ SoftForkDescPushBack() emit one entry per consensus deployment).
"""

import asyncio
import shutil
import sys
import tempfile

import pytest

from ouroboros.consensus import BIP9_DEPLOYMENTS, BURIED_DEPLOYMENTS, Deployment
from ouroboros.node import BitcoinNode
from ouroboros.rpc import RPCServer

# BIP9 threshold-state strings emitted by Core's SoftForkDescPushBack
# (rpc/blockchain.cpp) and mirrored by _build_deployment_state.
_BIP9_STATUSES = {"defined", "started", "locked_in", "active", "failed"}


@pytest.fixture
def regtest_rpc():
    """Create a regtest RPCServer backed by the conftest stub DB.

    rpc_getblockchaininfo requires node.db to be set, so we attach the same
    _StubDB that conftest.py installs in sys.modules['sync'].
    """
    import sync as _sync_mock  # provided by conftest.py test-mock

    tmp = tempfile.mkdtemp()
    node = BitcoinNode(data_dir=tmp, config={"network": "regtest"})
    # Attach a stub DB so rpc_getblockchaininfo's DB presence checks pass.
    node.db = _sync_mock.PyBlockchainDB()
    rpc = RPCServer(node, port=18443)
    yield rpc
    shutil.rmtree(tmp, ignore_errors=True)


class TestSoftforksBridge:
    """Assert that deployment state lives only in getdeploymentinfo.deployments
    and that every entry there agrees with the consensus registry."""

    def test_getblockchaininfo_has_no_softforks_key(self, regtest_rpc):
        """getblockchaininfo must NOT emit a top-level 'softforks' object.

        Core v27 removed it; deployment state moved to getdeploymentinfo.
        Reference: rpc/blockchain.cpp getblockchaininfo (v31.99 shape).
        """
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        assert "softforks" not in gbi, (
            "getblockchaininfo unexpectedly carries a 'softforks' object — "
            "Core v27+ removed it (deployments moved to getdeploymentinfo)"
        )

    def test_getblockchaininfo_has_no_deployments_key(self, regtest_rpc):
        """getblockchaininfo must NOT emit a 'deployments' object either.

        With zero deployment state in getblockchaininfo the two RPCs can
        never diverge — getdeploymentinfo is the single surface.
        """
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        assert "deployments" not in gbi, (
            "getblockchaininfo unexpectedly carries a 'deployments' object — "
            "deployment state belongs to getdeploymentinfo only"
        )

    def test_active_field_matches(self, regtest_rpc):
        """'active' must agree with the consensus registry / BIP9 status.

        Buried: active iff tip height >= buried activation height.
        BIP9:   active iff bip9.status == 'active' (Core SoftForkDescPushBack
        sets active = (thresholdState == ThresholdState::ACTIVE)).
        """
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        deployments = gdi["deployments"]
        tip_height = gdi["height"]
        buried_reg = BURIED_DEPLOYMENTS["regtest"]

        for name, dep in deployments.items():
            if dep["type"] == "buried":
                expected = tip_height >= buried_reg[name].height
            else:
                expected = dep["bip9"]["status"] == "active"
            assert dep["active"] is expected, (
                f"Deployment '{name}': deployments.active={dep['active']} "
                f"but consensus registry expects active={expected}"
            )

    def test_type_field_matches(self, regtest_rpc):
        """'type' must agree with the consensus registry.

        A name configured under BIP9_DEPLOYMENTS reports type 'bip9'
        (it overwrites the buried entry in _build_deployment_state, matching
        Core where e.g. regtest taproot is a BIP9 deployment); everything
        else from BURIED_DEPLOYMENTS reports type 'buried'.
        """
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        deployments = gdi["deployments"]
        bip9_reg = BIP9_DEPLOYMENTS["regtest"]
        buried_reg = BURIED_DEPLOYMENTS["regtest"]

        for name, dep in deployments.items():
            expected = "bip9" if name in bip9_reg else "buried"
            assert name in bip9_reg or name in buried_reg, (
                f"Deployment '{name}' is not in the regtest consensus registry"
            )
            assert dep["type"] == expected, (
                f"Deployment '{name}': deployments.type='{dep['type']}' "
                f"but consensus registry expects type='{expected}'"
            )

    def test_min_activation_height_matches(self, regtest_rpc):
        """min_activation_height must agree with the consensus registry.

        Buried: equals the buried activation height.  BIP9: equals the
        configured min_activation_height parameter (speedy trial).
        """
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        deployments = gdi["deployments"]
        bip9_reg = BIP9_DEPLOYMENTS["regtest"]
        buried_reg = BURIED_DEPLOYMENTS["regtest"]

        for name, dep in deployments.items():
            if dep["type"] == "buried":
                expected = buried_reg[name].height
            else:
                expected = bip9_reg[name].min_activation_height
            assert dep.get("min_activation_height") == expected, (
                f"Deployment '{name}': deployments.min_activation_height="
                f"{dep.get('min_activation_height')} but consensus registry "
                f"expects {expected}"
            )

    def test_bip9_status_matches(self, regtest_rpc):
        """For BIP9 deployments, bip9.status must be a valid threshold state,
        and ALWAYS_ACTIVE deployments must report status 'active'."""
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        deployments = gdi["deployments"]
        bip9_reg = BIP9_DEPLOYMENTS["regtest"]

        for name, dep in deployments.items():
            if dep["type"] != "bip9":
                continue
            bip9 = dep.get("bip9")
            assert bip9 is not None, f"BIP9 deployment '{name}' has no bip9 sub-object"
            for field in ("status", "bit", "start_time", "timeout", "since", "min_activation_height"):
                assert field in bip9, f"BIP9 deployment '{name}': bip9 sub-object missing '{field}'"
            status = bip9["status"]
            assert status in _BIP9_STATUSES, (
                f"BIP9 deployment '{name}': unknown bip9.status='{status}'"
            )
            if bip9_reg[name].start_time == Deployment.ALWAYS_ACTIVE:
                assert status == "active", (
                    f"BIP9 deployment '{name}' is ALWAYS_ACTIVE in the consensus "
                    f"registry but reports bip9.status='{status}'"
                )

    def test_regtest_has_buried_and_bip9_in_softforks(self, regtest_rpc):
        """getdeploymentinfo.deployments must include both buried (segwit) and
        BIP9 (taproot) deployments on regtest — not just BIP9."""
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        deployments = gdi["deployments"]

        assert "segwit" in deployments, (
            "getdeploymentinfo.deployments is missing the buried 'segwit' deployment"
        )
        assert deployments["segwit"]["type"] == "buried"
        assert "taproot" in deployments, (
            "getdeploymentinfo.deployments is missing the BIP9 'taproot' deployment"
        )
        assert deployments["taproot"]["type"] == "bip9"

    def test_deployment_sets_are_identical(self, regtest_rpc):
        """The deployment name set must be identical to the consensus registry
        (BURIED_DEPLOYMENTS ∪ BIP9_DEPLOYMENTS for regtest)."""
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        di_names = set(gdi["deployments"].keys())
        registry_names = (
            set(BURIED_DEPLOYMENTS["regtest"]) | set(BIP9_DEPLOYMENTS["regtest"])
        )

        assert di_names == registry_names, (
            f"Deployment name sets differ.\n"
            f"  Only in deployments: {di_names - registry_names}\n"
            f"  Only in registry:    {registry_names - di_names}"
        )
