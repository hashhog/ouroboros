"""Ouroboros - A Bitcoin node implementation in Python with Rust extensions."""

__version__ = "0.1.0"

# Core modules
from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool, MempoolEntry
from ouroboros.node import BitcoinNode
from ouroboros.p2p import PeerManager, P2PManager
from ouroboros.peer import Peer, PeerState
from ouroboros.block_sync import BlockSync
from ouroboros.rpc import RPCServer
from ouroboros.validation import BlockValidator, TransactionValidator, ValidationError
from ouroboros.script import ScriptInterpreter
from ouroboros.p2p_messages import (
    NetworkMessage,
    VersionMessage,
    InvMessage,
    GetDataMessage,
    BlockMessage,
    TxMessage,
    GetHeadersMessage,
    HeadersMessage,
    PingMessage,
    PongMessage,
    NetworkAddress,
    BlockHeader,
    MAGIC_MAINNET,
    MAGIC_TESTNET,
    MAGIC_REGTEST,
    INV_TYPE_TX,
    INV_TYPE_BLOCK,
)
from ouroboros.wallet import Wallet
from ouroboros.sync_manager import SyncManager, SyncProgress

# Rust extension module
from sync import PyUTXO, SyncEngine  # noqa: F401

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
]
