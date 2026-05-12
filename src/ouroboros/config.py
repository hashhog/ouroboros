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
import time as _time
from pathlib import Path
from typing import Any

# Chain sections (Bitcoin-style: [main], [test], [testnet4], [regtest], [signet])
CHAIN_SECTIONS = ('main', 'mainnet', 'test', 'testnet', 'testnet3', 'testnet4', 'regtest', 'signet')

# Minimum number of blocks to keep in the block store / lookahead window.
# Mirrors Bitcoin Core's MIN_BLOCKS_TO_KEEP (validation.cpp / validation.h).
# Used by the fTooFarAhead gate: an unrequested block whose claimed height
# exceeds (ActiveHeight + MIN_BLOCKS_TO_KEEP) is silently dropped without
# buffering, preventing memory-DoS via large-height block spam.
MIN_BLOCKS_TO_KEEP: int = 288


def _ports_for_network(network: str) -> tuple:
    """Return (rpc_port, p2p_port) for a given network."""
    if network in ('testnet', 'testnet3'):
        return '18332', '18333'
    if network == 'testnet4':
        return '48332', '48333'
    if network == 'regtest':
        return '18443', '18444'
    if network == 'signet':
        return '38332', '38333'
    return '8332', '8333'


# =============================================================================
# Regtest-specific configuration
# =============================================================================

class RegtestConfig:
    """
    Configuration specific to regtest mode.

    Regtest (regression test) mode is a local-only chain for automated testing:
    - No DNS seeds or peer discovery
    - Minimum difficulty (blocks found instantly)
    - All soft forks active from genesis
    - Mock time support for time-dependent tests
    """

    # Genesis block parameters (matches Bitcoin Core CRegTestParams)
    GENESIS_TIME = 1296688602  # Same as testnet3
    GENESIS_NONCE = 2
    GENESIS_BITS = 0x207fffff  # Minimum difficulty
    GENESIS_HASH = bytes.fromhex(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )[::-1]  # Internal byte order

    # Network parameters
    NETWORK_MAGIC = bytes([0xfa, 0xbf, 0xb5, 0xda])
    DEFAULT_P2P_PORT = 18444
    DEFAULT_RPC_PORT = 18443

    # Consensus parameters
    SUBSIDY_HALVING_INTERVAL = 150  # Much shorter for testing
    POW_NO_RETARGETING = True  # No difficulty adjustment
    POW_ALLOW_MIN_DIFFICULTY = True

    # All soft forks active from genesis/height 1
    BIP34_HEIGHT = 1
    BIP65_HEIGHT = 1
    BIP66_HEIGHT = 1
    CSV_HEIGHT = 1
    SEGWIT_HEIGHT = 0  # Active from genesis
    TAPROOT_ALWAYS_ACTIVE = True

    # No minimum chain work (testing)
    MIN_CHAIN_WORK = 0

    # No checkpoints
    CHECKPOINTS = []

    # No DNS seeds
    DNS_SEEDS = []

    @classmethod
    def is_regtest(cls, network: str) -> bool:
        """Check if the given network is regtest."""
        return network.lower() == 'regtest'

    @classmethod
    def get_pow_limit(cls) -> int:
        """
        Get the PoW limit (maximum target) for regtest.

        Returns the target corresponding to nBits=0x207fffff.
        This is the easiest possible difficulty.
        """
        # 0x207fffff decodes to: 0x7fffff << (8 * (0x20 - 3))
        # = 0x7fffff << (8 * 29) = 0x7fffff << 232
        return 0x7fffff << (8 * (0x20 - 3))


class NodeConfig:
    """Node configuration manager"""

    def __init__(
        self,
        config_path: str | None = None,
        data_dir: str | None = None,
    ):
        """Initialize configuration."""
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
            # SOCKS5 proxy for all outbound P2P connections (host:port)
            'proxy': None,
            # SOCKS5 proxy specifically for .onion connections (host:port).
            # Falls back to 'proxy' when not set.
            'onion': None,
            # Whether to accept inbound P2P connections (1/0)
            'listen': '1',
            # Enable REST interface (1/0)
            'rest': '0',
            # ZMQ notification endpoints (per-topic, Bitcoin Core style)
            # Each option specifies the endpoint for that topic.
            # Multiple topics can share the same endpoint.
            'zmqpubhashblock': None,
            'zmqpubhashtx': None,
            'zmqpubrawblock': None,
            'zmqpubrawtx': None,
            'zmqpubsequence': None,
            # I2P SAM bridge for I2P connections (host:port)
            'i2psam': None,
            # Tor control port for hidden service creation (host:port)
            'torcontrol': None,
            # Tor control password (for HASHEDPASSWORD auth)
            'torpassword': None,
            # BIP 324 v2 encrypted transport (1=enabled, 0=v1-only).
            # Defaults ON: the cipher + handshake have been verified
            # Core-compatible (commits 8ea9b81 + 5e28a8a + 27519ff) and
            # outbound v1 fall-back is wired (commit 66ad0f3) — peers
            # that don't speak v2 are detected and re-dialled with v1
            # on a fresh socket.  Set v2transport=0 to force v1-only.
            'v2transport': '1',
            # BIP 111 NODE_BLOOM advertisement (1=advertise, 0=do not).
            # Mirrors Bitcoin Core's -peerbloomfilters option, whose
            # DEFAULT_PEERBLOOMFILTERS = false (net_processing.h:44).
            # When disabled (the Core-parity default) the node neither
            # advertises NODE_BLOOM in its `version` message nor services
            # BIP-35 MEMPOOL requests (gated in p2p.py on_mempool).
            'peerbloomfilters': '0',
            # BIP 157/158 compact block filter index (1=enabled, 0=off).
            # Mirrors Bitcoin Core's -blockfilterindex option, default off.
            # When enabled the node builds a basic-filter index alongside
            # block validation, advertises NODE_COMPACT_FILTERS (1<<6) in
            # its `version` services bitfield, and serves the BIP-157 P2P
            # message family (getcfilters/cfilter/getcfheaders/cfheaders/
            # getcfcheckpt/cfcheckpt).  When disabled (the default) the
            # node behaves identically to before this option was added.
            'blockfilterindex': '0',
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

    def _get_without_env(self, key: str) -> str | None:
        for sec in ('DEFAULT',) + CHAIN_SECTIONS:
            try:
                if self.config.has_section(sec) and self.config.has_option(sec, key):
                    return self.config.get(sec, key)
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass
        return self.defaults.get(key)

    def get(self, key: str, section: str | None = None) -> str | None:
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

    def getint(self, key: str, section: str | None = None) -> int:
        """Get a config value as an integer."""
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

    def getboolean(self, key: str, section: str | None = None) -> bool:
        """Get a config value as a boolean."""
        value = self.get(key, section)
        if value is None:
            default = self.defaults.get(key, '0')
            return default == '1' or default.lower() in ('true', 'yes', 'on')
        return value.lower() in ('1', 'true', 'yes', 'on')

    def to_dict(self) -> dict[str, Any]:
        """Return all config values as a dictionary."""
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
            'proxy': self.get('proxy'),
            'onion': self.get('onion'),
            'listen': self.getboolean('listen'),
            'i2psam': self.get('i2psam'),
            'torcontrol': self.get('torcontrol'),
            'torpassword': self.get('torpassword'),
            # BIP 324 v2 encrypted transport toggle.  Coerced to bool here
            # so consumers (node.py initial PeerManager wiring) don't have
            # to reinterpret the raw "0"/"1"/"true" string — and to avoid
            # the classic "0"-string-is-truthy footgun that previously
            # silently dropped v2transport=0 in conf.
            'v2transport': self.getboolean('v2transport'),
            # BIP 111 NODE_BLOOM advertisement (Core: -peerbloomfilters).
            # Same string-coercion note applies.  Default false to match
            # Core's DEFAULT_PEERBLOOMFILTERS.
            'peerbloomfilters': self.getboolean('peerbloomfilters'),
            # BIP 157/158 compact block filter index (Core: -blockfilterindex).
            # Default false (Core parity).  When true the node builds the
            # filter index, serves BIP-157 P2P queries, and advertises
            # NODE_COMPACT_FILTERS in version handshakes.
            'blockfilterindex': self.getboolean('blockfilterindex'),
        }


# =============================================================================
# Chain Parameters
# =============================================================================

class ChainParams:
    """
    Chain parameters for a Bitcoin network.

    Wraps the Rust chainparams module to provide access to:
    - Checkpoints: known-good (height, block_hash) pairs
    - Minimum chain work: anti-DoS threshold for header sync
    - Network-specific consensus parameters
    """

    def __init__(self, network: str = "mainnet"):
        """
        Initialize chain parameters for a network.

        Args:
            network: One of "mainnet", "testnet", "testnet4", "regtest", "signet"
        """
        self.network = network.lower()
        self._sync_module = None
        try:
            import sync
            self._sync_module = sync
        except ImportError:
            pass

    def get_checkpoints(self) -> list:
        """
        Get all checkpoints for this network.

        Returns:
            List of checkpoint objects with height and hash attributes.
            Empty list if Rust module is not available.
        """
        if self._sync_module is None:
            return []
        return self._sync_module.get_network_checkpoints(self.network)

    def get_last_checkpoint(self) -> Any | None:
        """
        Get the last checkpoint for this network.

        Returns:
            Checkpoint object with height and hash, or None if no checkpoints.
        """
        if self._sync_module is None:
            return None
        return self._sync_module.get_last_network_checkpoint(self.network)

    def get_last_checkpoint_height(self) -> int | None:
        """
        Get the height of the last checkpoint.

        Returns:
            Height as int, or None if no checkpoints.
        """
        cp = self.get_last_checkpoint()
        return cp.height if cp else None

    def is_below_checkpoint(self, height: int) -> bool:
        """
        Check if a height is at or below the last checkpoint.

        Used to determine if script validation can be skipped during IBD.

        Args:
            height: Block height to check

        Returns:
            True if height is at or below the last checkpoint
        """
        if self._sync_module is None:
            return False
        return self._sync_module.check_is_below_checkpoint(self.network, height)

    def verify_checkpoint(self, height: int, block_hash: bytes) -> bool | None:
        """
        Verify a block hash matches the checkpoint at a given height.

        Args:
            height: Block height
            block_hash: 32-byte block hash (internal byte order)

        Returns:
            True if checkpoint exists and matches,
            False if checkpoint exists but doesn't match,
            None if no checkpoint at this height
        """
        if self._sync_module is None:
            return None
        return self._sync_module.verify_block_checkpoint(self.network, height, block_hash)

    def can_skip_script_validation(self, height: int, block_hash: bytes) -> bool:
        """
        Check if script validation can be skipped for a block during IBD.

        Blocks at or below the last checkpoint can skip script validation
        (only PoW and merkle root need to be verified).

        Args:
            height: Block height
            block_hash: 32-byte block hash (internal byte order)

        Returns:
            True if scripts can be skipped
        """
        if self._sync_module is None:
            return False
        return self._sync_module.can_skip_scripts_for_block(self.network, height, block_hash)

    def get_minimum_chain_work(self) -> str | None:
        """
        Get the minimum chain work for this network.

        Returns:
            Hex string representing the minimum chain work, or None if unavailable.
        """
        if self._sync_module is None:
            return None
        return self._sync_module.get_minimum_chain_work(self.network)

    def is_regtest(self) -> bool:
        """Check if this is regtest network."""
        return self.network == "regtest"

    def all_forks_active_from_genesis(self) -> bool:
        """
        Check if all soft forks are active from genesis.

        Returns True for regtest, testnet4, and signet.
        """
        return self.network in ("regtest", "testnet4", "signet")


# =============================================================================
# Mock Time Support (for regtest)
# =============================================================================

# Global mock time state
_mock_time: int | None = None


def get_mock_time() -> int | None:
    """
    Get the current mock time, if set.

    Returns:
        Mock time as Unix timestamp, or None if not mocked.
    """
    return _mock_time


def set_mock_time(timestamp: int | None) -> None:
    """
    Set the mock time for testing.

    This affects all time-dependent operations in the node when in regtest mode.
    Pass None to disable mock time and use real time.

    Args:
        timestamp: Unix timestamp to use, or None to use real time.
    """
    global _mock_time
    _mock_time = timestamp


def get_time() -> int:
    """
    Get the current time, respecting mock time if set.

    Returns:
        Current time as Unix timestamp.
    """
    if _mock_time is not None:
        return _mock_time
    return int(_time.time())


def clear_mock_time() -> None:
    """Clear mock time and use real time."""
    global _mock_time
    _mock_time = None
