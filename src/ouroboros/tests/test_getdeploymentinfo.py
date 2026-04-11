"""
Tests for getdeploymentinfo RPC.

Verifies that getdeploymentinfo returns non-empty deployments on regtest,
with at minimum segwit (buried) and taproot (bip9) present.
"""

import asyncio
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402


class TestGetDeploymentInfo(unittest.TestCase):
    """Unit tests for rpc_getdeploymentinfo on regtest."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Pass network via config dict; the BitcoinNode constructor prefers
        # self.config.get('network', network) so config overrides the keyword arg.
        self.node = BitcoinNode(data_dir=self.temp_dir, config={"network": "regtest"})
        self.rpc_server = RPCServer(self.node, port=18443)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_method_exists(self):
        """rpc_getdeploymentinfo must be present and callable."""
        self.assertTrue(hasattr(self.rpc_server, "rpc_getdeploymentinfo"))
        self.assertTrue(callable(getattr(self.rpc_server, "rpc_getdeploymentinfo", None)))

    def test_returns_non_empty_deployments(self):
        """getdeploymentinfo must return a non-empty deployments dict."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        self.assertIsInstance(result, dict)
        self.assertIn("deployments", result)
        deployments = result["deployments"]
        self.assertIsInstance(deployments, dict)
        self.assertGreater(len(deployments), 0, "deployments dict must not be empty")

    def test_has_segwit_deployment(self):
        """getdeploymentinfo must include a 'segwit' entry on regtest."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        deployments = result["deployments"]
        self.assertIn("segwit", deployments, "segwit deployment must be present")

    def test_has_taproot_deployment(self):
        """getdeploymentinfo must include a 'taproot' entry on regtest."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        deployments = result["deployments"]
        self.assertIn("taproot", deployments, "taproot deployment must be present")

    def test_segwit_is_buried_type(self):
        """segwit must be reported as type 'buried'."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        segwit = result["deployments"]["segwit"]
        self.assertEqual(segwit.get("type"), "buried")

    def test_taproot_is_bip9_type(self):
        """taproot must be reported as type 'bip9'."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        taproot = result["deployments"]["taproot"]
        self.assertEqual(taproot.get("type"), "bip9")

    def test_taproot_active_on_regtest(self):
        """taproot must be active on regtest (ALWAYS_ACTIVE)."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        taproot = result["deployments"]["taproot"]
        self.assertTrue(taproot.get("active"), "taproot must be active on regtest")

    def test_segwit_active_on_regtest(self):
        """segwit must be active on regtest (height 0)."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        segwit = result["deployments"]["segwit"]
        self.assertTrue(segwit.get("active"), "segwit must be active on regtest")

    def test_taproot_has_bip9_sub_object(self):
        """taproot bip9 entry must have required sub-fields."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        taproot = result["deployments"]["taproot"]
        bip9 = taproot.get("bip9")
        self.assertIsNotNone(bip9, "taproot must have a bip9 sub-object")
        for field in ("status", "bit", "start_time", "timeout", "since", "min_activation_height"):
            self.assertIn(field, bip9, f"bip9 sub-object must contain '{field}'")

    def test_result_has_hash_and_height(self):
        """Top-level result must include hash and height fields."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        self.assertIn("hash", result)
        self.assertIn("height", result)

    def test_buried_deployment_has_required_fields(self):
        """Buried deployments must have type, active, height, min_activation_height."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        # Check all buried deployments
        buried_names = {"bip34", "bip65", "bip66", "csv", "segwit"}
        deployments = result["deployments"]
        for name in buried_names:
            if name in deployments:
                dep = deployments[name]
                self.assertIn("type", dep, f"{name} missing 'type'")
                self.assertIn("active", dep, f"{name} missing 'active'")
                self.assertIn("height", dep, f"{name} missing 'height'")
                self.assertIn("min_activation_height", dep, f"{name} missing 'min_activation_height'")

    def test_no_blockhash_uses_tip(self):
        """Calling without blockhash must succeed (uses chain tip)."""
        result = asyncio.run(self.rpc_server.rpc_getdeploymentinfo())
        self.assertIsNotNone(result)

    def test_invalid_blockhash_raises(self):
        """Passing an invalid blockhash must raise an HTTPException."""
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            asyncio.run(self.rpc_server.rpc_getdeploymentinfo(blockhash="not_valid_hex"))


if __name__ == "__main__":
    unittest.main()
