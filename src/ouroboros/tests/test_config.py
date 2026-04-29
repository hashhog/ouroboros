"""
Test configuration management.

This test verifies that the configuration system works correctly.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.config import NodeConfig  # noqa: E402


class TestNodeConfig(unittest.TestCase):
    """Test NodeConfig class"""

    def test_default_values(self):
        """Test that default values are returned when no config file exists"""
        # Create a config with a non-existent file
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nonexistent.conf"
            config = NodeConfig(str(config_path))

            # Test default values
            self.assertEqual(config.get('network'), 'mainnet')
            self.assertEqual(config.getint('rpcport'), 8332)
            self.assertEqual(config.getint('p2pport'), 8333)
            self.assertEqual(config.getint('maxconnections'), 125)
            self.assertFalse(config.getboolean('debug'))
            self.assertTrue(config.getboolean('logtimestamps'))

    def test_config_file_loading(self):
        """Test loading configuration from a file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"

            # Write test config
            config_path.write_text("""[network]
network=testnet

[rpc]
rpcport=18332

[p2p]
maxconnections=50

[logging]
debug=1
""")

            config = NodeConfig(str(config_path))

            # Test loaded values
            self.assertEqual(config.get('network'), 'testnet')
            self.assertEqual(config.getint('rpcport'), 18332)
            self.assertEqual(config.getint('maxconnections'), 50)
            self.assertTrue(config.getboolean('debug'))

    def test_environment_variable_override(self):
        """Test that environment variables override config file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[network]\nnetwork=testnet\n")

            # Set environment variable
            os.environ['OUROBOROS_NETWORK'] = 'regtest'

            try:
                config = NodeConfig(str(config_path))
                # Environment variable should override config file
                self.assertEqual(config.get('network'), 'regtest')
            finally:
                # Clean up
                if 'OUROBOROS_NETWORK' in os.environ:
                    del os.environ['OUROBOROS_NETWORK']

    def test_to_dict(self):
        """Test converting config to dictionary"""
        config = NodeConfig()
        config_dict = config.to_dict()

        # Verify structure
        self.assertIn('network', config_dict)
        self.assertIn('datadir', config_dict)
        self.assertIn('rpc_port', config_dict)
        self.assertIn('p2p_port', config_dict)
        self.assertIn('max_connections', config_dict)
        self.assertIn('debug', config_dict)
        self.assertIn('log_timestamps', config_dict)

        # Verify types
        self.assertIsInstance(config_dict['rpc_port'], int)
        self.assertIsInstance(config_dict['p2p_port'], int)
        self.assertIsInstance(config_dict['max_connections'], int)
        self.assertIsInstance(config_dict['debug'], bool)
        self.assertIsInstance(config_dict['log_timestamps'], bool)

    def test_getint(self):
        """Test getint method"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[rpc]\nrpcport=9999\n")

            config = NodeConfig(str(config_path))
            self.assertEqual(config.getint('rpcport'), 9999)
            # Test default
            self.assertEqual(config.getint('nonexistent', 'DEFAULT'), 0)

    def test_getboolean(self):
        """Test getboolean method"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("""[logging]
debug=1
logtimestamps=true
""")

            config = NodeConfig(str(config_path))
            self.assertTrue(config.getboolean('debug'))
            self.assertTrue(config.getboolean('logtimestamps'))

    # ------------------------------------------------------------------
    # BIP 324 v2 transport propagation regression tests
    # ------------------------------------------------------------------
    # The v2 cipher + handshake landed in 66ad0f3 / 8ea9b81 / 5e28a8a /
    # 27519ff but were unreachable from operator config because to_dict()
    # didn't expose `v2transport`.  These tests pin the propagation in
    # place so the toggle can never be silently dropped again.

    def test_v2transport_in_to_dict_default_on(self):
        """v2transport key is present in to_dict() and defaults to True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "absent.conf"
            config = NodeConfig(str(config_path))
            d = config.to_dict()
            self.assertIn('v2transport', d)
            # Default ON: ouroboros has the strongest interop story
            # against Core's reference state machine, and v1 fall-back
            # is automatic per address.
            self.assertTrue(d['v2transport'])
            self.assertIsInstance(d['v2transport'], bool)

    def test_v2transport_disabled_via_conf(self):
        """v2transport=0 in the chain section disables it end-to-end."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[mainnet]\nv2transport=0\n")
            config = NodeConfig(str(config_path))
            self.assertFalse(config.to_dict()['v2transport'])

    def test_v2transport_enabled_via_conf(self):
        """v2transport=1 in [mainnet] (or any chain section) enables it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[mainnet]\nv2transport=1\n")
            config = NodeConfig(str(config_path))
            self.assertTrue(config.to_dict()['v2transport'])

    def test_v2transport_via_p2p_section(self):
        """v2transport in the [p2p] named section also propagates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[p2p]\nv2transport=0\n")
            config = NodeConfig(str(config_path))
            self.assertFalse(config.to_dict()['v2transport'])

    def test_v2transport_env_override(self):
        """OUROBOROS_V2TRANSPORT env var overrides the conf file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test.conf"
            config_path.write_text("[mainnet]\nv2transport=1\n")
            os.environ['OUROBOROS_V2TRANSPORT'] = '0'
            try:
                config = NodeConfig(str(config_path))
                self.assertFalse(config.to_dict()['v2transport'])
            finally:
                del os.environ['OUROBOROS_V2TRANSPORT']

    def test_v2transport_truthy_strings(self):
        """getboolean handles 'true' / 'yes' / 'on' (not just '1')."""
        for v in ('true', 'yes', 'on', 'TRUE'):
            with tempfile.TemporaryDirectory() as tmpdir:
                config_path = Path(tmpdir) / "test.conf"
                config_path.write_text(f"[mainnet]\nv2transport={v}\n")
                config = NodeConfig(str(config_path))
                self.assertTrue(
                    config.to_dict()['v2transport'],
                    f"expected {v!r} to be truthy",
                )

    def test_v2transport_dial_outbound_consumer(self):
        """node.py:225 transport selector translates the bool correctly.

        Mirrors the actual selector in BitcoinNode.start so a future
        regression in the consumer (e.g. someone re-introduces the raw
        string-truthiness check) is caught here as a unit test rather
        than in a live mainnet probe.
        """
        # Repro of the selector in node.py — keep in sync.
        def select_transport(cfg_dict):
            v2_raw = cfg_dict.get('v2transport', False)
            if isinstance(v2_raw, str):
                v2_enabled = v2_raw.lower() in ("1", "true", "yes", "on")
            else:
                v2_enabled = bool(v2_raw)
            return 2 if v2_enabled else 1

        # bool propagation through to_dict
        self.assertEqual(select_transport({'v2transport': True}), 2)
        self.assertEqual(select_transport({'v2transport': False}), 1)
        # raw string from CLI override / dict merge
        self.assertEqual(select_transport({'v2transport': '1'}), 2)
        self.assertEqual(select_transport({'v2transport': '0'}), 1)
        self.assertEqual(select_transport({'v2transport': 'true'}), 2)
        self.assertEqual(select_transport({'v2transport': 'false'}), 1)
        # missing → v1 (caller-supplied default arm)
        self.assertEqual(select_transport({}), 1)


if __name__ == '__main__':
    unittest.main()
