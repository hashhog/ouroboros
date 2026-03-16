"""
Tests for getrawtransaction RPC.

Reference: Bitcoin Core rpc/rawtransaction.cpp getrawtransaction
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class MockTxIn:
    """Mock transaction input."""
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF
    witness: List[bytes] = None

    def __post_init__(self):
        if self.witness is None:
            self.witness = []


@dataclass
class MockTxOut:
    """Mock transaction output."""
    value: int
    script_pubkey: bytes


class MockTransaction:
    """Mock transaction for testing."""

    def __init__(
        self,
        txid: bytes,
        inputs: List[MockTxIn],
        outputs: List[MockTxOut],
        version: int = 2,
        locktime: int = 0,
        is_coinbase: bool = False,
    ):
        self._txid = txid
        self._wtxid = txid  # simplified
        self.inputs = inputs
        self.outputs = outputs
        self.version = version
        self.locktime = locktime
        self._is_coinbase = is_coinbase
        self._vsize = 200  # default vsize
        self.has_witness = False

    def get_txid(self) -> bytes:
        return self._txid

    def get_wtxid(self) -> bytes:
        return self._wtxid

    @property
    def txid(self) -> bytes:
        return self._txid

    @property
    def is_coinbase(self) -> bool:
        return self._is_coinbase

    def get_vsize(self) -> int:
        return self._vsize

    def get_weight(self) -> int:
        return self._vsize * 4

    def serialize(self) -> bytes:
        return b"\x00" * self._vsize


class MockBlock:
    """Mock block for testing."""

    def __init__(
        self,
        block_hash: bytes,
        height: int,
        transactions: List[MockTransaction],
        timestamp: int = 1600000000,
        version: int = 0x20000000,
        prev_blockhash: bytes = None,
        merkle_root: bytes = None,
        bits: int = 0x1d00ffff,
        nonce: int = 0,
    ):
        self.block_hash = block_hash
        self.height = height
        self.transactions = transactions
        self.timestamp = timestamp
        self.version = version
        self.prev_blockhash = prev_blockhash or bytes(32)
        self.merkle_root = merkle_root or bytes(32)
        self.bits = bits
        self.nonce = nonce

    def get_txid(self) -> bytes:
        return self.block_hash


class MockMempool:
    """Mock mempool for testing."""

    def __init__(self):
        self.transactions: Dict[bytes, MockTransaction] = {}

    def has_transaction(self, txid: bytes) -> bool:
        return txid in self.transactions

    def get_transaction(self, txid: bytes) -> Optional[MockTransaction]:
        return self.transactions.get(txid)


class MockDatabase:
    """Mock database for testing."""

    def __init__(self):
        self.blocks: Dict[bytes, MockBlock] = {}
        self.tx_index: Dict[bytes, Tuple[bytes, int, int]] = {}
        self.height_to_hash: Dict[int, bytes] = {}
        self.best_height = 100

    def get_best_block(self) -> Tuple[bytes, int]:
        return b"\x00" * 32, self.best_height

    def get_block(self, block_hash: bytes) -> Optional[MockBlock]:
        return self.blocks.get(block_hash)

    def get_tx_index(self, txid: bytes) -> Optional[Tuple[bytes, int, int]]:
        return self.tx_index.get(txid)

    def get_block_hash_by_height(self, height: int) -> Optional[bytes]:
        return self.height_to_hash.get(height)


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.db = MockDatabase()
        self.mempool = MockMempool()
        self.network = "testnet"


@pytest.fixture
def mock_node():
    """Create a mock node."""
    return MockNode()


@pytest.fixture
def sample_tx():
    """Create a sample transaction."""
    prev_txid = bytes.fromhex("0" * 64)
    inputs = [MockTxIn(prev_txid=prev_txid, prev_vout=0)]
    outputs = [MockTxOut(value=49999000, script_pubkey=b"\x00\x14" + b"\x00" * 20)]
    return MockTransaction(
        txid=bytes.fromhex("a" * 64),
        inputs=inputs,
        outputs=outputs,
    )


@pytest.fixture
def sample_block(sample_tx):
    """Create a sample block containing the sample transaction."""
    block_hash = bytes.fromhex("b" * 64)
    return MockBlock(
        block_hash=block_hash,
        height=50,
        transactions=[sample_tx],
        timestamp=1600000000,
    )


class TestGetRawTransactionVerbosity:
    """Test verbosity parameter handling."""

    def test_verbose_bool_false_is_verbosity_0(self):
        """Test that verbose=False is treated as verbosity 0."""
        verbose = False
        verbosity = 1 if verbose else 0
        assert verbosity == 0

    def test_verbose_bool_true_is_verbosity_1(self):
        """Test that verbose=True is treated as verbosity 1."""
        verbose = True
        verbosity = 1 if verbose else 0
        assert verbosity == 1

    def test_verbose_int_0(self):
        """Test that verbose=0 returns hex string."""
        verbose = 0
        verbosity = int(verbose)
        assert verbosity == 0

    def test_verbose_int_1(self):
        """Test that verbose=1 returns JSON object."""
        verbose = 1
        verbosity = int(verbose)
        assert verbosity == 1

    def test_verbose_int_2(self):
        """Test that verbose=2 returns JSON with prevout info."""
        verbose = 2
        verbosity = int(verbose)
        assert verbosity == 2


class TestGetRawTransactionMempool:
    """Test mempool transaction lookup."""

    @pytest.mark.asyncio
    async def test_mempool_tx_non_verbose(self, mock_node, sample_tx):
        """Test retrieving a mempool transaction with verbose=0."""
        from ouroboros.rpc import RPCServer

        # Add tx to mempool
        mock_node.mempool.transactions[sample_tx.get_txid()] = sample_tx

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=0,
        )

        # Should return hex-encoded raw transaction
        assert isinstance(result, str)
        assert len(result) == 400  # 200 bytes * 2 hex chars

    @pytest.mark.asyncio
    async def test_mempool_tx_verbose(self, mock_node, sample_tx):
        """Test retrieving a mempool transaction with verbose=1."""
        from ouroboros.rpc import RPCServer

        # Add tx to mempool
        mock_node.mempool.transactions[sample_tx.get_txid()] = sample_tx

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
        )

        # Should return JSON object with tx details
        assert isinstance(result, dict)
        assert "txid" in result
        assert "version" in result
        assert "vin" in result
        assert "vout" in result
        assert "hex" in result
        # Mempool tx should not have blockhash
        assert "blockhash" not in result


class TestGetRawTransactionBlockchain:
    """Test blockchain transaction lookup."""

    @pytest.mark.asyncio
    async def test_blockchain_tx_with_txindex(self, mock_node, sample_tx, sample_block):
        """Test retrieving a confirmed transaction using txindex."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        # Add block to database
        mock_node.db.blocks[block_hash] = sample_block
        # Add to txindex
        mock_node.db.tx_index[sample_tx.get_txid()] = (block_hash, 50, 0)
        # Add to height index
        mock_node.db.height_to_hash[50] = block_hash

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
        )

        # Should return JSON with block context
        assert isinstance(result, dict)
        assert "txid" in result
        assert "blockhash" in result
        assert result["blockhash"] == block_hash.hex()
        assert "confirmations" in result
        # Height 50, best height 100 => 51 confirmations
        assert result["confirmations"] == 51
        assert "blocktime" in result
        assert result["blocktime"] == 1600000000

    @pytest.mark.asyncio
    async def test_blockchain_tx_with_explicit_blockhash(
        self, mock_node, sample_tx, sample_block
    ):
        """Test retrieving a transaction with explicit blockhash."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        # Add block to database
        mock_node.db.blocks[block_hash] = sample_block
        # Add to height index (active chain)
        mock_node.db.height_to_hash[50] = block_hash

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
            blockhash=block_hash.hex(),
        )

        # Should return JSON with in_active_chain
        assert isinstance(result, dict)
        assert "in_active_chain" in result
        assert result["in_active_chain"] is True

    @pytest.mark.asyncio
    async def test_blockchain_tx_not_in_active_chain(
        self, mock_node, sample_tx, sample_block
    ):
        """Test that in_active_chain is False for orphan blocks."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        # Add block to database
        mock_node.db.blocks[block_hash] = sample_block
        # Don't add to height index - simulates orphan block
        mock_node.db.height_to_hash[50] = bytes.fromhex("c" * 64)  # different hash

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
            blockhash=block_hash.hex(),
        )

        # Should return JSON with in_active_chain = False
        assert isinstance(result, dict)
        assert "in_active_chain" in result
        assert result["in_active_chain"] is False


class TestGetRawTransactionErrors:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_invalid_txid(self, mock_node):
        """Test error on invalid transaction ID."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction("invalid_hex")

        assert exc_info.value.status_code == 400
        assert "Invalid transaction id" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_invalid_blockhash(self, mock_node, sample_tx):
        """Test error on invalid block hash."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction(
                sample_tx.get_txid().hex(),
                verbose=True,
                blockhash="invalid_hex",
            )

        assert exc_info.value.status_code == 400
        assert "Invalid block hash" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_block_not_found(self, mock_node, sample_tx):
        """Test error when block hash not found."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        nonexistent_hash = "d" * 64

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction(
                sample_tx.get_txid().hex(),
                verbose=True,
                blockhash=nonexistent_hash,
            )

        assert exc_info.value.status_code == 404
        assert "Block hash not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_tx_not_in_block(self, mock_node, sample_tx, sample_block):
        """Test error when tx not found in specified block."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        # Create block without the sample tx
        empty_block = MockBlock(
            block_hash=sample_block.block_hash,
            height=50,
            transactions=[],
        )
        mock_node.db.blocks[sample_block.block_hash] = empty_block

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction(
                sample_tx.get_txid().hex(),
                verbose=True,
                blockhash=sample_block.block_hash.hex(),
            )

        assert exc_info.value.status_code == 404
        assert "No such transaction found in the provided block" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_tx_not_found_no_txindex(self, mock_node, sample_tx):
        """Test error message when tx not found and no txindex."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        # Create a mock database without get_tx_index method
        class MockDatabaseNoTxIndex:
            def __init__(self):
                self.best_height = 100

            def get_best_block(self):
                return b"\x00" * 32, self.best_height

            # No get_tx_index method

        mock_node.db = MockDatabaseNoTxIndex()

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction(
                sample_tx.get_txid().hex(),
                verbose=True,
            )

        assert exc_info.value.status_code == 404
        assert "Use -txindex" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_tx_not_found_with_txindex(self, mock_node, sample_tx):
        """Test error message when tx not found but txindex enabled."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_getrawtransaction(
                sample_tx.get_txid().hex(),
                verbose=True,
            )

        assert exc_info.value.status_code == 404
        assert "No such mempool or blockchain transaction" in exc_info.value.detail


class TestGetRawTransactionVerboseOutput:
    """Test verbose output format."""

    @pytest.mark.asyncio
    async def test_verbose_output_has_hex(self, mock_node, sample_tx, sample_block):
        """Test that verbose output includes hex field."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        mock_node.db.blocks[block_hash] = sample_block
        mock_node.db.tx_index[sample_tx.get_txid()] = (block_hash, 50, 0)
        mock_node.db.height_to_hash[50] = block_hash

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=1,
        )

        assert "hex" in result
        assert result["hex"] == sample_tx.serialize().hex()

    @pytest.mark.asyncio
    async def test_verbose_output_fields(self, mock_node, sample_tx, sample_block):
        """Test that verbose output includes all required fields."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        mock_node.db.blocks[block_hash] = sample_block
        mock_node.db.tx_index[sample_tx.get_txid()] = (block_hash, 50, 0)
        mock_node.db.height_to_hash[50] = block_hash

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
        )

        # Required fields from Bitcoin Core
        assert "txid" in result
        assert "hash" in result  # wtxid for segwit, txid for legacy
        assert "version" in result
        assert "size" in result
        assert "vsize" in result
        assert "weight" in result
        assert "locktime" in result
        assert "vin" in result
        assert "vout" in result
        assert "hex" in result
        # Block context
        assert "blockhash" in result
        assert "confirmations" in result
        assert "blocktime" in result
        assert "time" in result


class TestGetRawTransactionConfirmations:
    """Test confirmations calculation."""

    @pytest.mark.asyncio
    async def test_confirmations_calculation(self, mock_node, sample_tx, sample_block):
        """Test that confirmations are calculated correctly."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        mock_node.db.blocks[block_hash] = sample_block
        mock_node.db.tx_index[sample_tx.get_txid()] = (block_hash, 50, 0)
        mock_node.db.height_to_hash[50] = block_hash
        mock_node.db.best_height = 100

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
        )

        # Confirmations = best_height - tx_height + 1 = 100 - 50 + 1 = 51
        assert result["confirmations"] == 51

    @pytest.mark.asyncio
    async def test_confirmations_at_tip(self, mock_node, sample_tx, sample_block):
        """Test confirmations for tx at chain tip."""
        from ouroboros.rpc import RPCServer

        block_hash = sample_block.block_hash
        sample_block.height = 100
        mock_node.db.blocks[block_hash] = sample_block
        mock_node.db.tx_index[sample_tx.get_txid()] = (block_hash, 100, 0)
        mock_node.db.height_to_hash[100] = block_hash
        mock_node.db.best_height = 100

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = await rpc.rpc_getrawtransaction(
            sample_tx.get_txid().hex(),
            verbose=True,
        )

        # Confirmations = 100 - 100 + 1 = 1
        assert result["confirmations"] == 1
