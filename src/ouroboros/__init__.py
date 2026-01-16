"""Ouroboros - A Bitcoin node implementation in Python with Rust extensions."""

__version__ = "0.1.0"

# Core modules
from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool
from ouroboros.node import BitcoinNode
from ouroboros.p2p import P2PManager
from ouroboros.rpc import RPCServer
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.wallet import Wallet
from ouroboros.sync_manager import SyncManager, SyncProgress

# Rust extension module
from sync import PyUTXO, SyncEngine  # noqa: F401

# Alias for backward compatibility
Database = BlockchainDatabase

__all__ = [
    "__version__",
    "BitcoinNode",
    "P2PManager",
    "Mempool",
    "BlockValidator",
    "TransactionValidator",
    "Database",
    "BlockchainDatabase",
    "Wallet",
    "RPCServer",
    "SyncManager",
    "SyncProgress",
    "SyncEngine",
    "PyUTXO",
]
