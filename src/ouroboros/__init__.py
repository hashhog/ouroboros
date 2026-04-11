"""Ouroboros - A Bitcoin node implementation in Python with Rust extensions."""

__version__ = "0.1.0"

# Core modules
# Rust extension module
from sync import PyUTXO, SyncEngine  # noqa: F401

from ouroboros.block_sync import BlockSync
from ouroboros.config import NodeConfig
from ouroboros.consensus import (
    BuriedDeployment,
    Deployment,
    DeploymentState,
    get_all_deployments_info,
    get_deployment_state,
    is_buried_deployment_active,
    is_deployment_active,
)
from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool, MempoolEntry
from ouroboros.node import BitcoinNode
from ouroboros.p2p import P2PManager, PeerManager
from ouroboros.p2p_messages import (
    INV_TYPE_BLOCK,
    INV_TYPE_TX,
    MAGIC_MAINNET,
    MAGIC_REGTEST,
    MAGIC_TESTNET,
    BlockHeader,
    BlockMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    InvMessage,
    NetworkAddress,
    NetworkMessage,
    PingMessage,
    PongMessage,
    TxMessage,
    VersionMessage,
)
from ouroboros.peer import Peer, PeerState
from ouroboros.rpc import RPCServer
from ouroboros.script import ScriptInterpreter
from ouroboros.sync_manager import SyncManager, SyncProgress
from ouroboros.validation import BlockValidator, TransactionValidator, ValidationError
from ouroboros.wallet import Wallet

# Alias for backward compatibility
Database = BlockchainDatabase

__all__ = [
    "__version__",
    "BitcoinNode",
    "PeerManager",
    "P2PManager",
    "Mempool",
    "MempoolEntry",
    "BlockValidator",
    "TransactionValidator",
    "ValidationError",
    "ScriptInterpreter",
    "NetworkMessage",
    "VersionMessage",
    "InvMessage",
    "GetDataMessage",
    "BlockMessage",
    "TxMessage",
    "GetHeadersMessage",
    "HeadersMessage",
    "PingMessage",
    "PongMessage",
    "NetworkAddress",
    "BlockHeader",
    "Peer",
    "PeerState",
    "BlockSync",
    "MAGIC_MAINNET",
    "MAGIC_TESTNET",
    "MAGIC_REGTEST",
    "INV_TYPE_TX",
    "INV_TYPE_BLOCK",
    "Database",
    "BlockchainDatabase",
    "Wallet",
    "RPCServer",
    "SyncManager",
    "SyncProgress",
    "SyncEngine",
    "PyUTXO",
    "NodeConfig",
    "DeploymentState",
    "Deployment",
    "BuriedDeployment",
    "get_deployment_state",
    "is_deployment_active",
    "is_buried_deployment_active",
    "get_all_deployments_info",
]
