"""
Regtest test: getdeploymentinfo.deployments must be exactly the projection of
the single RPCServer._build_deployment_state() helper.

Core v31.99 (rpc/blockchain.cpp:1420 getblockchaininfo) DROPPED the top-level
"softforks" object; deployment state is only reported by getdeploymentinfo
(rpc/blockchain.cpp DeploymentInfo() / SoftForkDescPushBack()).  ouroboros
mirrors that: getblockchaininfo carries no "softforks" key and
getdeploymentinfo projects from _build_deployment_state, so the two can never
read from different data sources.
"""

import asyncio
import shutil
import tempfile

import pytest

from ouroboros.node import BitcoinNode
from ouroboros.rpc import RPCServer


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


def _state_and_deployments(rpc):
    gdi = asyncio.run(rpc.rpc_getdeploymentinfo())
    state = rpc._build_deployment_state(gdi["height"], "regtest")
    return state, gdi["deployments"]


class TestSoftforksBridge:
    """Assert getblockchaininfo has no softforks (Core v31.99) and that
    getdeploymentinfo.deployments is the projection of _build_deployment_state."""

    def test_getblockchaininfo_has_no_softforks(self, regtest_rpc):
        """Core v31.99 getblockchaininfo (rpc/blockchain.cpp:1420) has no
        'softforks' key — it moved to getdeploymentinfo."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        assert "softforks" not in gbi

    def test_deployments_is_subset_of_state(self, regtest_rpc):
        """Every deployment reported must come from _build_deployment_state."""
        state, deployments = _state_and_deployments(regtest_rpc)
        for name in deployments:
            assert name in state, (
                f"Deployment '{name}' is in getdeploymentinfo.deployments but "
                f"absent from _build_deployment_state"
            )

    def test_active_field_matches(self, regtest_rpc):
        """The 'active' field must agree with _build_deployment_state."""
        state, deployments = _state_and_deployments(regtest_rpc)
        for name, dep in deployments.items():
            assert dep["active"] == state[name]["active"], name

    def test_type_field_matches(self, regtest_rpc):
        """The 'type' field must agree with _build_deployment_state."""
        state, deployments = _state_and_deployments(regtest_rpc)
        for name, dep in deployments.items():
            assert dep["type"] == state[name]["type"], name

    def test_min_activation_height_matches(self, regtest_rpc):
        """min_activation_height must agree with _build_deployment_state."""
        state, deployments = _state_and_deployments(regtest_rpc)
        for name, dep in deployments.items():
            assert dep.get("min_activation_height") == state[name].get(
                "min_activation_height"
            ), name

    def test_bip9_status_matches(self, regtest_rpc):
        """For BIP9 deployments, bip9.status must agree with the state helper."""
        state, deployments = _state_and_deployments(regtest_rpc)
        for name, dep in deployments.items():
            if dep.get("type") != "bip9":
                continue
            assert dep.get("bip9", {}).get("status") == state[name].get(
                "bip9", {}
            ).get("status"), name

    def test_regtest_has_buried_and_bip9_in_deployments(self, regtest_rpc):
        """getdeploymentinfo.deployments must include both buried (segwit) and
        BIP9 (taproot) deployments on regtest — not just BIP9."""
        _state, deployments = _state_and_deployments(regtest_rpc)
        assert "segwit" in deployments, (
            "getdeploymentinfo.deployments is missing the buried 'segwit' deployment"
        )
        assert deployments["segwit"]["type"] == "buried"
        assert "taproot" in deployments, (
            "getdeploymentinfo.deployments is missing the BIP9 'taproot' deployment"
        )
        assert deployments["taproot"]["type"] == "bip9"

    def test_deployment_sets_are_identical(self, regtest_rpc):
        """The set of deployment names must be identical to the state helper's."""
        state, deployments = _state_and_deployments(regtest_rpc)
        assert set(deployments) == set(state), (
            f"Deployment name sets differ.\n"
            f"  Only in deployments: {set(deployments) - set(state)}\n"
            f"  Only in state:       {set(state) - set(deployments)}"
        )
