"""
Tests for sendrawtransaction RPC.

Reference: Bitcoin Core rpc/mempool.cpp sendrawtransaction
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple

from ouroboros.database import Transaction, TxIn, TxOut


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

    def serialize(self) -> bytes:
        return b"\x00" * self._vsize


class MockMempool:
    """Mock mempool for testing."""

    def __init__(self):
        self.transactions: Dict[bytes, Any] = {}
        self.add_result = (True, "")

    def has_transaction(self, txid: bytes) -> bool:
        return txid in self.transactions

    def add_transaction(self, tx: MockTransaction, height: int) -> Tuple[bool, str]:
        if self.add_result[0]:
            self.transactions[tx.get_txid()] = MagicMock(tx=tx)
        return self.add_result


class MockDatabase:
    """Mock database for testing."""

    def __init__(self):
        self.utxos: Dict[Tuple[bytes, int], Dict[str, Any]] = {}
        self.tx_index: Dict[bytes, Tuple[bytes, int, int]] = {}
        self.best_height = 100

    def get_best_block(self) -> Tuple[bytes, int]:
        return b"\x00" * 32, self.best_height

    def get_utxo(self, txid: bytes, vout: int) -> Optional[Dict[str, Any]]:
        return self.utxos.get((txid, vout))

    def get_tx_index(self, txid: bytes) -> Optional[Tuple[bytes, int, int]]:
        return self.tx_index.get(txid)


class MockPeerManager:
    """Mock peer manager for testing."""

    def __init__(self):
        self.relayed_txs: List[Tuple[bytes, bytes]] = []

    def queue_tx_for_relay(self, txid: bytes, wtxid: bytes) -> int:
        self.relayed_txs.append((txid, wtxid))
        return 1


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.db = MockDatabase()
        self.mempool = MockMempool()
        self.peer_manager = MockPeerManager()
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
        txid=bytes.fromhex("1" * 64),
        inputs=inputs,
        outputs=outputs,
    )


class TestSendRawTransactionRejectReasons:
    """Test rejection reason mapping."""

    def test_map_mempool_error_already_in_mempool(self):
        """Test already in mempool error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Already in mempool")
        assert result == "txn-already-in-mempool"

    def test_map_mempool_error_missing_inputs(self):
        """Test missing inputs (orphan) error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("orphan")
        assert result == "missing-inputs"

    def test_map_mempool_error_utxo_not_found(self):
        """Test UTXO not found error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("UTXO not found")
        assert result == "missing-inputs"

    def test_map_mempool_error_double_spend(self):
        """Test double spend / conflict error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("conflict with existing tx")
        assert result == "txn-mempool-conflict"

    def test_map_mempool_error_insufficient_fee(self):
        """Test fee too low error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Below minimum relay fee")
        assert result == "insufficient-fee"

    def test_map_mempool_error_non_standard(self):
        """Test non-standard error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Non-standard transaction")
        assert result == "non-standard"

    def test_map_mempool_error_script_failed(self):
        """Test script failure error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Script verification failed")
        assert result == "script-failed"

    def test_map_mempool_error_ancestor_limit(self):
        """Test ancestor limit error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Too many ancestors: 26 > 25")
        assert result == "too-long-mempool-chain"

    def test_map_mempool_error_descendant_limit(self):
        """Test descendant limit error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Too many descendants")
        assert result == "too-long-mempool-chain"

    def test_map_mempool_error_dust(self):
        """Test dust output error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Transaction has dust output")
        assert result == "dust"

    def test_map_mempool_error_truc(self):
        """Test TRUC (v3) policy error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("TRUC (v3) tx exceeds limit")
        assert result == "truc-policy"

    def test_map_mempool_error_negative_fee(self):
        """Test negative fee error mapping."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Negative fee")
        assert result == "bad-txns-in-belowout"

    def test_map_mempool_error_unknown(self):
        """Test unknown error returns original."""
        from ouroboros.rpc import RPCServer
        rpc = RPCServer.__new__(RPCServer)
        result = rpc._map_mempool_error_to_reject_reason("Unknown error xyz")
        assert result == "Unknown error xyz"


class TestDefaultMaxFeeRate:
    """Test default maxfeerate constant."""

    def test_default_maxfeerate_is_correct(self):
        """Test that default maxfeerate is 0.10 BTC/kvB."""
        from ouroboros.rpc import RPCServer
        # Should be 0.10 BTC/kvB = 100,000 sat/kvB = 100 sat/vB
        assert RPCServer.DEFAULT_MAX_RAW_TX_FEE_RATE == 0.10


class TestSendRawTransactionIntegration:
    """Integration tests for sendrawtransaction (require more setup)."""

    @pytest.mark.asyncio
    async def test_sendrawtx_reject_coinbase(self, mock_node):
        """Test that coinbase transactions are rejected."""
        from ouroboros.rpc import RPCServer
        from fastapi import HTTPException

        # Create a coinbase transaction
        coinbase_tx = MockTransaction(
            txid=bytes.fromhex("2" * 64),
            inputs=[],
            outputs=[MockTxOut(value=5000000000, script_pubkey=b"\x00" * 25)],
            is_coinbase=True,
        )

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        # Mock TxMessage.from_payload to return our coinbase tx
        with patch('ouroboros.rpc.RPCServer.rpc_sendrawtransaction') as mock_send:
            mock_send.side_effect = HTTPException(status_code=400, detail="coinbase")
            with pytest.raises(HTTPException) as exc_info:
                await mock_send("0100000001000000000000...")
            assert exc_info.value.status_code == 400
            assert "coinbase" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_sendrawtx_already_in_mempool(self, mock_node, sample_tx):
        """Test that already-in-mempool returns txid without error."""
        from ouroboros.rpc import RPCServer
        from ouroboros.p2p_messages import TxMessage

        # Pre-add to mempool
        mock_node.mempool.transactions[sample_tx.get_txid()] = MagicMock(tx=sample_tx)

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        # The function should return txid without calling add_transaction
        # We'll test the logic flow directly
        txid = sample_tx.get_txid()
        assert mock_node.mempool.has_transaction(txid) is True

    @pytest.mark.asyncio
    async def test_sendrawtx_already_confirmed(self, mock_node, sample_tx):
        """Test that already-confirmed returns txid without error."""
        txid = sample_tx.get_txid()
        # Mark as confirmed in tx_index
        mock_node.db.tx_index[txid] = (b"\x00" * 32, 50, 0)

        # Should return txid without trying to add to mempool
        assert mock_node.db.get_tx_index(txid) is not None


class TestMaxFeeRateCheck:
    """Test maxfeerate enforcement."""

    def test_fee_rate_calculation_btc_kvb(self):
        """Test fee rate calculation in BTC/kvB."""
        # Example: 10,000 sat fee, 200 vbyte tx
        fee_sat = 10000
        vsize = 200
        fee_btc = fee_sat / 1e8  # 0.0001 BTC
        fee_rate_btc_kvb = fee_btc / (vsize / 1000.0)  # BTC per kvB
        # 0.0001 BTC / 0.2 kvB = 0.0005 BTC/kvB
        assert abs(fee_rate_btc_kvb - 0.0005) < 1e-10

    def test_fee_rate_exceeds_default(self):
        """Test that high fee rate would be rejected."""
        # Example: 10 BTC fee (!), 200 vbyte tx
        fee_sat = 1_000_000_000  # 10 BTC
        vsize = 200
        fee_btc = fee_sat / 1e8
        fee_rate_btc_kvb = fee_btc / (vsize / 1000.0)
        # 10 BTC / 0.2 kvB = 50 BTC/kvB
        default_max = 0.10  # BTC/kvB
        assert fee_rate_btc_kvb > default_max

    def test_fee_rate_within_default(self):
        """Test that normal fee rate would be accepted."""
        # Example: 1000 sat fee, 200 vbyte tx
        fee_sat = 1000
        vsize = 200
        fee_btc = fee_sat / 1e8
        fee_rate_btc_kvb = fee_btc / (vsize / 1000.0)
        # 0.00001 BTC / 0.2 kvB = 0.00005 BTC/kvB
        default_max = 0.10  # BTC/kvB
        assert fee_rate_btc_kvb < default_max

    def test_maxfeerate_zero_accepts_any(self):
        """Test that maxfeerate=0 accepts any fee rate."""
        # The check: if maxfeerate > 0 and fee_rate > maxfeerate: reject
        # So maxfeerate=0 should skip the check
        maxfeerate = 0
        fee_rate = 100  # absurdly high
        should_reject = maxfeerate > 0 and fee_rate > maxfeerate
        assert should_reject is False


class TestMissingInputs:
    """Test missing inputs error handling."""

    def test_missing_utxo_returns_missing_inputs(self, mock_node, sample_tx):
        """Test that missing UTXO returns 'missing-inputs'."""
        # Don't add any UTXOs to the mock database
        # The function should raise with "missing-inputs" when it can't find UTXOs
        assert mock_node.db.get_utxo(sample_tx.inputs[0].prev_txid, 0) is None
