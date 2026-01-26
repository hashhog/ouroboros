"""
Configuration management for Bitcoin node.

This module provides configuration file support for the Bitcoin node,
allowing users to configure network settings, RPC options, and other parameters
via a configuration file or environment variables.
"""

import configparser
import os
from pathlib import Path
from typing import Optional, Dict, Any


class NodeConfig:
    """Node configuration manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_path: Path to config file (default: ~/.ouroboros/ouroboros.conf)
        """
        if config_path is None:
            config_dir = Path.home() / ".ouroboros"
            config_path = config_dir / "ouroboros.conf"
        
        self.config_path = Path(config_path)
        self.config = configparser.ConfigParser()
        
        # Get network from config file or environment to set appropriate defaults
        network = os.environ.get('OUROBOROS_NETWORK', 'mainnet')
        if self.config_path.exists():
            try:
                temp_config = configparser.ConfigParser()
                temp_config.read(self.config_path)
                network = temp_config.get('DEFAULT', 'network', fallback=network)
            except:
                pass
        
        # Default ports based on network
        if network == 'testnet':
            default_rpc_port = '18332'
            default_p2p_port = '18333'
        elif network == 'regtest':
            default_rpc_port = '18443'
            default_p2p_port = '18444'
        else:  # mainnet
            default_rpc_port = '8332'
            default_p2p_port = '8333'
        
        # Default values
        self.defaults = {
            'network': 'mainnet',
            'datadir': str(Path.home() / ".ouroboros"),
            'rpcport': default_rpc_port,
            'rpcuser': None,
            'rpcpassword': None,
            'rpcallowip': '127.0.0.1',
            'rpcbind': '127.0.0.1',
            'p2pport': default_p2p_port,
            'maxconnections': '125',
            'debug': '0',
            'logtimestamps': '1',
        }
        
        # Load config if exists
        if self.config_path.exists():
            try:
                self.config.read(self.config_path)
                # Update network-based defaults after loading config
                network = self.get('network', 'DEFAULT') or 'mainnet'
                if network == 'testnet':
                    self.defaults['rpcport'] = '18332'
                    self.defaults['p2pport'] = '18333'
                elif network == 'regtest':
                    self.defaults['rpcport'] = '18443'
                    self.defaults['p2pport'] = '18444'
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error reading config file {self.config_path}: {e}")
    
    def get(self, key: str, section: str = 'DEFAULT') -> Optional[str]:
        """
        Get config value.
        
        Priority order:
        1. Environment variable (OUROBOROS_<KEY>)
        2. Config file value
        3. Default value
        
        Args:
            key: Config key
            section: Config section (default: 'DEFAULT')
            
        Returns:
            Config value or default
        """
        # Check environment variable first
        env_key = f"OUROBOROS_{key.upper()}"
        env_value = os.environ.get(env_key)
        if env_value:
            return env_value
        
        # Check config file
        try:
            # Try specified section first
            if self.config.has_section(section):
                if self.config.has_option(section, key):
                    return self.config.get(section, key)
            
            # Try DEFAULT section
            if self.config.has_section('DEFAULT'):
                if self.config.has_option('DEFAULT', key):
                    return self.config.get('DEFAULT', key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            pass
        
        # Return default
        return self.defaults.get(key)
    
    def getint(self, key: str, section: str = 'DEFAULT') -> int:
        """
        Get config value as integer.
        
        Args:
            key: Config key
            section: Config section
            
        Returns:
            Integer value or default
        """
        value = self.get(key, section)
        if value is None:
            default = self.defaults.get(key, '0')
            try:
                return int(default)
            except ValueError:
                return 0
        try:
            return int(value)
        except ValueError:
            return 0
    
    def getboolean(self, key: str, section: str = 'DEFAULT') -> bool:
        """
        Get config value as boolean.
        
        Args:
            key: Config key
            section: Config section
            
        Returns:
            Boolean value or default
        """
        value = self.get(key, section)
        if value is None:
            default = self.defaults.get(key, '0')
            return default == '1' or default.lower() in ('true', 'yes', 'on')
        return value.lower() in ('1', 'true', 'yes', 'on')
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert config to dictionary.
        
        Returns:
            Dictionary with all configuration values
        """
        return {
            'network': self.get('network'),
            'datadir': self.get('datadir'),
            'rpc_port': self.getint('rpcport'),
            'rpc_username': self.get('rpcuser'),
            'rpc_password': self.get('rpcpassword'),
            'rpc_allow_ip': self.get('rpcallowip'),
            'rpc_bind': self.get('rpcbind'),
            'p2p_port': self.getint('p2pport'),
            'max_connections': self.getint('maxconnections'),
            'debug': self.getboolean('debug'),
            'log_timestamps': self.getboolean('logtimestamps'),
        }
