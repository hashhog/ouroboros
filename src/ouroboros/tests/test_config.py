"""
Test configuration management.

This test verifies that the configuration system works correctly.
"""

import unittest
import sys
import os
import tempfile
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.config import NodeConfig


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


if __name__ == '__main__':
    unittest.main()
