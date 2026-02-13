"""
Configuration management for Bitcoin node.

This module provides configuration file support for the Bitcoin node,
allowing users to configure network settings, RPC options, and other parameters
via a configuration file (ouroboros.conf) or environment variables.

Bitcoin-style format: key=value, one per line; [section] for chain-specific
options (e.g. [testnet4]). Environment variables OROBOROS_<KEY> override config.
"""

import configparser
import os
from pathlib import Path
from typing import Optional, Dict, Any

# Chain sections (Bitcoin-style: [main], [test], [testnet4], [regtest], [signet])
CHAIN_SECTIONS = ('main', 'mainnet', 'test', 'testnet', 'testnet3', 'testnet4', 'regtest', 'signet')


def _ports_for_network(network: str) -> tuple:
    """Return (rpc_port, p2p_port) for network."""
    if network == 'testnet':
        return '18332', '18333'
    if network == 'regtest':
        return '18443', '18444'
    return '8332', '8333'


class NodeConfig:
    """Node configuration manager"""
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        """
        Initialize configuration.
        
        Args:
            config_path: Path to config file. If None, uses data_dir/ouroboros.conf
                        or ~/.ouroboros/ouroboros.conf.
            data_dir: Data directory (for resolving config_path when config_path is None).
                      OROBOROS_DATADIR env var overrides this.
        """
        # Resolve data_dir: env overrides parameter
        data_dir = os.environ.get('OUROBOROS_DATADIR') or data_dir or str(Path.home() / ".ouroboros")
        data_dir = str(Path(data_dir).expanduser())
        
        if config_path is None:
            config_path = Path(data_dir) / "ouroboros.conf"
        
        self.config_path = Path(config_path)
        self.data_dir_default = data_dir
        self.config = configparser.ConfigParser()
        
        # Get network from config file or environment to set appropriate defaults
        network = os.environ.get('OUROBOROS_NETWORK', 'mainnet')
        if self.config_path.exists():
            try:
                temp_config = configparser.ConfigParser()
                temp_config.read(self.config_path)
                for sec in ('DEFAULT',) + CHAIN_SECTIONS:
                    if temp_config.has_section(sec) and temp_config.has_option(sec, 'network'):
                        network = temp_config.get(sec, 'network')
                        break
            except Exception:
                pass
        
        default_rpc_port, default_p2p_port = _ports_for_network(network)
        self.defaults = {
            'network': 'mainnet',
            'datadir': data_dir,
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
        
        if self.config_path.exists():
            try:
                self.config.read(self.config_path)
                network = self._get_without_env('network') or 'mainnet'
                rpc, p2p = _ports_for_network(network)
                self.defaults['rpcport'] = rpc
                self.defaults['p2pport'] = p2p
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error reading config file {self.config_path}: {e}")

    def _get_without_env(self, key: str) -> Optional[str]:
        """Get value from config file only (no env). Used during init."""
        for sec in ('DEFAULT',) + CHAIN_SECTIONS:
            try:
                if self.config.has_section(sec) and self.config.has_option(sec, key):
                    return self.config.get(sec, key)
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass
        return self.defaults.get(key)
    
    def get(self, key: str, section: Optional[str] = None) -> Optional[str]:
        """
        Get config value.
        
        Priority order:
        1. Environment variable (OUROBOROS_<KEY>) - overrides all
        2. Config file: chain section (e.g. [testnet4]), then DEFAULT
        3. Default value
        
        Args:
            key: Config key
            section: Optional section to check first. If None, uses chain section
                     based on current network, then DEFAULT.
            
        Returns:
            Config value or default
        """
        # 1. Environment variable overrides config (OUROBOROS_DATADIR, etc.)
        env_key = f"OUROBOROS_{key.upper().replace('-', '_')}"
        env_value = os.environ.get(env_key)
        if env_value is not None and env_value != '':
            return env_value
        
        # 2. Config file
        sections_to_try = []
        if section:
            sections_to_try.append(section)
        else:
            # Chain section first: get network from defaults (avoid recursion)
            network = self.defaults.get('network', 'mainnet')
            try:
                if self.config.has_section('DEFAULT') and self.config.has_option('DEFAULT', 'network'):
                    network = self.config.get('DEFAULT', 'network')
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass
            if network in CHAIN_SECTIONS:
                sections_to_try.append(network)
            # Then named sections, then DEFAULT
            for sec in ('network', 'rpc', 'p2p', 'logging'):
                if sec not in sections_to_try and self.config.has_section(sec):
                    sections_to_try.append(sec)
            sections_to_try.append('DEFAULT')
        
        for sec in sections_to_try:
            try:
                if self.config.has_section(sec) and self.config.has_option(sec, key):
                    return self.config.get(sec, key)
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass
        
        # 3. Default
        return self.defaults.get(key)
    
    def getint(self, key: str, section: Optional[str] = None) -> int:
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
    
    def getboolean(self, key: str, section: Optional[str] = None) -> bool:
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
