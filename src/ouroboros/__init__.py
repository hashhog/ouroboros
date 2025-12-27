"""Ouroboros - A Bitcoin node implementation in Python with Rust extensions."""

__version__ = "0.1.0"

# Core modules
from ouroboros.node import BitcoinNode
from ouroboros.p2p import P2PManager
from ouroboros.mempool import Mempool
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.database import Database
from ouroboros.wallet import Wallet
from ouroboros.rpc import RPCServer

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

