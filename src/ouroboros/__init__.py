"""Ouroboros - A Bitcoin node implementation in Python with Rust extensions."""

__version__ = "0.1.0"

# Core modules
from ouroboros.database import Database
from ouroboros.mempool import Mempool
from ouroboros.node import BitcoinNode
from ouroboros.p2p import P2PManager
from ouroboros.rpc import RPCServer
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.wallet import Wallet

# Rust extension module (if available)
try:
    from sync import PyUTXO, SyncEngine  # noqa: F401

    _RUST_EXTENSION_AVAILABLE = True
except ImportError:
    _RUST_EXTENSION_AVAILABLE = False

__all__ = [
    "__version__",
    "BitcoinNode",
    "P2PManager",
    "Mempool",
    "BlockValidator",
    "TransactionValidator",
    "Database",
    "Wallet",
    "RPCServer",
]

if _RUST_EXTENSION_AVAILABLE:
    __all__.extend(["SyncEngine", "PyUTXO"])
