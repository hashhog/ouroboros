"""
Regtest test: getblockchaininfo.softforks and getdeploymentinfo.deployments
must agree on every deployment that appears in both responses.

Both RPCs now delegate to the single RPCServer._build_deployment_state()
helper so they can never read from different data sources.

Reference: Bitcoin Core src/rpc/blockchain.cpp — both getblockchaininfo and
getdeploymentinfo call the same DeploymentInfo() / SoftForkDescPushBack()
helpers internally.
"""

import asyncio
import shutil
import sys
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


class TestSoftforksBridge:
    """Assert that getblockchaininfo.softforks and getdeploymentinfo.deployments
    share one data source and therefore agree on every common deployment."""

    def test_softforks_is_subset_of_deployments(self, regtest_rpc):
        """Every deployment in softforks must also appear in deployments."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in softforks:
            assert name in deployments, (
                f"Deployment '{name}' is in getblockchaininfo.softforks but "
                f"absent from getdeploymentinfo.deployments"
            )

    def test_deployments_is_subset_of_softforks(self, regtest_rpc):
        """Every deployment in deployments must also appear in softforks."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in deployments:
            assert name in softforks, (
                f"Deployment '{name}' is in getdeploymentinfo.deployments but "
                f"absent from getblockchaininfo.softforks"
            )

    def test_active_field_matches(self, regtest_rpc):
        """The 'active' field must agree for every shared deployment."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in softforks:
            if name not in deployments:
                continue
            sf_active = softforks[name]["active"]
            di_active = deployments[name]["active"]
            assert sf_active == di_active, (
                f"Deployment '{name}': getblockchaininfo.softforks.active="
                f"{sf_active} but getdeploymentinfo.deployments.active={di_active}"
            )

    def test_type_field_matches(self, regtest_rpc):
        """The 'type' field must agree for every shared deployment."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in softforks:
            if name not in deployments:
                continue
            sf_type = softforks[name]["type"]
            di_type = deployments[name]["type"]
            assert sf_type == di_type, (
                f"Deployment '{name}': getblockchaininfo.softforks.type="
                f"'{sf_type}' but getdeploymentinfo.deployments.type='{di_type}'"
            )

    def test_min_activation_height_matches(self, regtest_rpc):
        """min_activation_height must agree for every shared deployment."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in softforks:
            if name not in deployments:
                continue
            sf_mah = softforks[name].get("min_activation_height")
            di_mah = deployments[name].get("min_activation_height")
            assert sf_mah == di_mah, (
                f"Deployment '{name}': getblockchaininfo.softforks.min_activation_height="
                f"{sf_mah} but getdeploymentinfo.deployments.min_activation_height={di_mah}"
            )

    def test_bip9_status_matches(self, regtest_rpc):
        """For BIP9 deployments, bip9.status must agree between both RPCs."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        softforks = gbi["softforks"]
        deployments = gdi["deployments"]

        for name in softforks:
            if name not in deployments:
                continue
            if softforks[name].get("type") != "bip9":
                continue
            sf_status = softforks[name].get("bip9", {}).get("status")
            di_status = deployments[name].get("bip9", {}).get("status")
            assert sf_status == di_status, (
                f"BIP9 deployment '{name}': getblockchaininfo bip9.status="
                f"'{sf_status}' but getdeploymentinfo bip9.status='{di_status}'"
            )

    def test_regtest_has_buried_and_bip9_in_softforks(self, regtest_rpc):
        """getblockchaininfo.softforks must include both buried (segwit) and
        BIP9 (taproot) deployments on regtest — not just BIP9."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        softforks = gbi["softforks"]

        assert "segwit" in softforks, (
            "getblockchaininfo.softforks is missing the buried 'segwit' deployment"
        )
        assert softforks["segwit"]["type"] == "buried"
        assert "taproot" in softforks, (
            "getblockchaininfo.softforks is missing the BIP9 'taproot' deployment"
        )
        assert softforks["taproot"]["type"] == "bip9"

    def test_deployment_sets_are_identical(self, regtest_rpc):
        """The set of deployment names must be identical across both RPCs."""
        gbi = asyncio.run(regtest_rpc.rpc_getblockchaininfo())
        gdi = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())

        sf_names = set(gbi["softforks"].keys())
        di_names = set(gdi["deployments"].keys())

        assert sf_names == di_names, (
            f"Deployment name sets differ.\n"
            f"  Only in softforks:   {sf_names - di_names}\n"
            f"  Only in deployments: {di_names - sf_names}"
        )
