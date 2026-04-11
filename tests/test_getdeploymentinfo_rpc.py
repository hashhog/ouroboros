"""
Regression tests for the getdeploymentinfo RPC.

Verifies that rpc_getdeploymentinfo returns a non-empty deployments dict on
regtest with at least segwit (buried) and taproot (bip9) present.

These tests are intentionally free of live-node requirements: they exercise
the pure-Python logic via a BitcoinNode initialised without a running DB.
The Rust sync module is used if available; if absent the Python fallback path
is exercised instead.
"""

import asyncio
import shutil
import tempfile

import pytest

from ouroboros.node import BitcoinNode
from ouroboros.rpc import RPCServer


@pytest.fixture
def regtest_rpc():
    """Create a regtest RPCServer with no running DB."""
    tmp = tempfile.mkdtemp()
    # Pass network through config so BitcoinNode.config picks it up.
    node = BitcoinNode(data_dir=tmp, config={"network": "regtest"})
    rpc = RPCServer(node, port=18443)
    yield rpc
    shutil.rmtree(tmp, ignore_errors=True)


class TestGetDeploymentInfoRPC:
    """Regression tests for rpc_getdeploymentinfo on regtest."""

    def test_method_exists(self, regtest_rpc):
        """rpc_getdeploymentinfo must be present and callable."""
        assert hasattr(regtest_rpc, "rpc_getdeploymentinfo")
        assert callable(getattr(regtest_rpc, "rpc_getdeploymentinfo", None))

    def test_returns_deployments_dict(self, regtest_rpc):
        """Result must be a dict containing a non-empty 'deployments' key."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert isinstance(result, dict)
        assert "deployments" in result
        assert isinstance(result["deployments"], dict)
        assert len(result["deployments"]) > 0

    def test_has_hash_and_height(self, regtest_rpc):
        """Top-level result must include 'hash' and 'height' fields."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert "hash" in result
        assert "height" in result

    def test_has_segwit(self, regtest_rpc):
        """'segwit' deployment must be present on regtest."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert "segwit" in result["deployments"]

    def test_has_taproot(self, regtest_rpc):
        """'taproot' deployment must be present on regtest."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert "taproot" in result["deployments"]

    def test_segwit_is_buried(self, regtest_rpc):
        """segwit must have type='buried'."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert result["deployments"]["segwit"]["type"] == "buried"

    def test_taproot_is_bip9(self, regtest_rpc):
        """taproot must have type='bip9'."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert result["deployments"]["taproot"]["type"] == "bip9"

    def test_segwit_active_on_regtest(self, regtest_rpc):
        """segwit is active from height 0 on regtest."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert result["deployments"]["segwit"]["active"] is True

    def test_taproot_active_on_regtest(self, regtest_rpc):
        """taproot is ALWAYS_ACTIVE on regtest, so active must be True."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        assert result["deployments"]["taproot"]["active"] is True

    def test_taproot_has_bip9_subobject(self, regtest_rpc):
        """taproot bip9 entry must include required sub-fields."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        bip9 = result["deployments"]["taproot"].get("bip9")
        assert bip9 is not None
        for field in ("status", "bit", "start_time", "timeout", "since", "min_activation_height"):
            assert field in bip9, f"bip9 sub-object missing '{field}'"

    def test_buried_deployments_have_required_fields(self, regtest_rpc):
        """Every buried deployment must have type, active, height, min_activation_height."""
        result = asyncio.run(regtest_rpc.rpc_getdeploymentinfo())
        buried_names = {"bip34", "bip65", "bip66", "csv", "segwit"}
        deployments = result["deployments"]
        for name in buried_names:
            if name in deployments:
                dep = deployments[name]
                for field in ("type", "active", "height", "min_activation_height"):
                    assert field in dep, f"{name} missing '{field}'"

    def test_invalid_blockhash_raises(self, regtest_rpc):
        """Passing a non-hex blockhash must raise HTTPException (400)."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(regtest_rpc.rpc_getdeploymentinfo(blockhash="not_valid_hex!!"))
        assert exc_info.value.status_code == 400
