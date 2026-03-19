"""
Tests for BIP 152 Compact Block Relay.

Tests the SipHash short txid computation, compact block serialization,
and block reconstruction from mempool.
"""

import hashlib
import struct
import pytest

from ouroboros.compact_blocks import (
    CompactBlock,
    PrefilledTransaction,
    BlockTransactionsRequest,
    BlockTransactions,
    compute_siphash_key,
    short_txid,
    _siphash_2_4,
)
from ouroboros.p2p_messages import (
    SendCmpctMessage,
    CmpctBlockMessage,
    GetBlockTxnMessage,
    BlockTxnMessage,
)
from ouroboros.database import Transaction, TxIn, TxOut


# --- SipHash Tests ---


def test_siphash_consistency():
    """SipHash should produce consistent results for same inputs."""
    key = bytes(16)  # All zeros
    data = b"test data"

    hash1 = _siphash_2_4(key, data)
    hash2 = _siphash_2_4(key, data)

    assert hash1 == hash2
    assert isinstance(hash1, int)
    assert hash1 >= 0
    assert hash1 < 2**64


def test_siphash_different_keys():
    """Different keys should produce different hashes."""
    key1 = bytes(16)
    key2 = b'\x01' + bytes(15)
    data = b"test"

    hash1 = _siphash_2_4(key1, data)
    hash2 = _siphash_2_4(key2, data)

    assert hash1 != hash2


def test_siphash_different_data():
    """Different data should produce different hashes."""
    key = bytes(16)

    hash1 = _siphash_2_4(key, b"data1")
    hash2 = _siphash_2_4(key, b"data2")

    assert hash1 != hash2


def test_compute_siphash_key():
    """Test SipHash key derivation from header and nonce."""
    header = bytes(80)  # All zeros
    nonce = 0

    key = compute_siphash_key(header, nonce)

    assert len(key) == 16
    # Should be deterministic
    assert key == compute_siphash_key(header, nonce)


def test_compute_siphash_key_different_nonce():
    """Different nonces should produce different keys."""
    header = bytes(80)

    key1 = compute_siphash_key(header, 0)
    key2 = compute_siphash_key(header, 1)

    assert key1 != key2


def test_short_txid():
    """Short txid should be 48 bits (6 bytes)."""
    key = bytes(16)
    txid = bytes(32)

    sid = short_txid(key, txid)

    assert isinstance(sid, int)
    assert sid >= 0
    assert sid <= 0xFFFFFFFFFFFF  # 48 bits max


def test_short_txid_consistency():
    """Same key and txid should produce same short id."""
    key = compute_siphash_key(bytes(80), 12345)
    txid = hashlib.sha256(b"test tx").digest()

    sid1 = short_txid(key, txid)
    sid2 = short_txid(key, txid)

    assert sid1 == sid2


# --- CompactBlock Tests ---


def make_test_tx(value: int = 50000, is_coinbase: bool = False) -> Transaction:
    """Create a minimal test transaction."""
    if is_coinbase:
        # Coinbase tx has null prev_txid and prev_vout=0xffffffff
        inputs = [TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=b'\x04' + struct.pack('<I', 100),  # height
            sequence=0xFFFFFFFF,
            witness=None,
        )]
    else:
        # Witness is a list of bytes (stack items): [signature, pubkey]
        inputs = [TxIn(
            prev_txid=hashlib.sha256(struct.pack('<Q', value)).digest(),
            prev_vout=0,
            script_sig=b'',
            sequence=0xFFFFFFFF,
            witness=[b'\x30' * 72, b'\x02' * 33],
        )]

    outputs = [TxOut(value=value, script_pubkey=b'\x76\xa9' + bytes(20) + b'\x88\xac')]

    return Transaction(
        txid=bytes(32),  # Will be computed
        version=1,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=not is_coinbase,
    )


def test_compact_block_creation():
    """Test creating a CompactBlock from components."""
    header = bytes(80)
    nonce = 12345
    short_ids = [0x123456789ABC, 0xDEF012345678]
    prefilled = [PrefilledTransaction(index=0, tx=make_test_tx(is_coinbase=True))]

    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=short_ids,
        prefilled_txs=prefilled,
    )

    assert cb.header == header
    assert cb.nonce == nonce
    assert len(cb.short_ids) == 2
    assert len(cb.prefilled_txs) == 1


def test_compact_block_block_hash():
    """Test block hash computation from header."""
    header = bytes(80)
    cb = CompactBlock(header=header, nonce=0, short_ids=[], prefilled_txs=[])

    expected = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    assert cb.block_hash == expected


def test_compact_block_serialize_deserialize():
    """Test roundtrip serialization of compact block."""
    header = bytes(80)
    nonce = 0x1234567890ABCDEF
    coinbase = make_test_tx(is_coinbase=True)

    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=[0x112233445566, 0xAABBCCDDEEFF],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )

    serialized = cb.serialize()
    assert isinstance(serialized, bytes)
    assert len(serialized) > 80 + 8  # Header + nonce minimum

    # Deserialize and verify
    cb2 = CompactBlock.deserialize(serialized)

    assert cb2.header == cb.header
    assert cb2.nonce == cb.nonce
    assert cb2.short_ids == cb.short_ids
    assert len(cb2.prefilled_txs) == len(cb.prefilled_txs)


# --- BlockTransactionsRequest Tests ---


def test_block_transactions_request():
    """Test getblocktxn message serialization."""
    block_hash = hashlib.sha256(b"test block").digest()
    indices = [1, 5, 10]

    req = BlockTransactionsRequest(block_hash=block_hash, indices=indices)
    serialized = req.serialize()

    # Deserialize and verify
    req2 = BlockTransactionsRequest.deserialize(serialized)

    assert req2.block_hash == block_hash
    assert req2.indices == indices


def test_block_transactions_request_differential_encoding():
    """Test that indices use differential encoding."""
    block_hash = bytes(32)
    # Indices [1, 5, 10] should be encoded as diffs [1, 3, 4]
    # (diff from last+1: 1-0=1, 5-2=3, 10-6=4)
    indices = [1, 5, 10]

    req = BlockTransactionsRequest(block_hash=block_hash, indices=indices)
    serialized = req.serialize()

    # Roundtrip
    req2 = BlockTransactionsRequest.deserialize(serialized)
    assert req2.indices == indices


# --- BlockTransactions Tests ---


def test_block_transactions():
    """Test blocktxn message serialization."""
    block_hash = bytes(32)
    txs = [make_test_tx(1000), make_test_tx(2000)]

    bt = BlockTransactions(block_hash=block_hash, transactions=txs)
    serialized = bt.serialize()

    # Deserialize and verify
    bt2 = BlockTransactions.deserialize(serialized)

    assert bt2.block_hash == block_hash
    assert len(bt2.transactions) == 2


# --- P2P Message Tests ---


def test_sendcmpct_message():
    """Test sendcmpct message creation."""
    msg = SendCmpctMessage(announce=True, version=2)
    net_msg = msg.to_network_message("regtest")

    assert net_msg.command == "sendcmpct"

    # Parse it back
    msg2 = SendCmpctMessage.from_payload(net_msg.payload)
    assert msg2.announce == True
    assert msg2.version == 2


def test_sendcmpct_low_bandwidth():
    """Test sendcmpct with low-bandwidth mode."""
    msg = SendCmpctMessage(announce=False, version=1)
    net_msg = msg.to_network_message("mainnet")

    msg2 = SendCmpctMessage.from_payload(net_msg.payload)
    assert msg2.announce == False
    assert msg2.version == 1


def test_cmpctblock_message():
    """Test cmpctblock message wrapper."""
    payload = bytes(100)  # Dummy payload
    msg = CmpctBlockMessage(payload_bytes=payload)
    net_msg = msg.to_network_message("regtest")

    assert net_msg.command == "cmpctblock"
    assert net_msg.payload == payload


def test_getblocktxn_message():
    """Test getblocktxn message wrapper."""
    block_hash = bytes(32)
    req = BlockTransactionsRequest(block_hash=block_hash, indices=[0, 1, 2])
    payload = req.serialize()

    msg = GetBlockTxnMessage(payload_bytes=payload)
    net_msg = msg.to_network_message("regtest")

    assert net_msg.command == "getblocktxn"

    # Parse request from message
    req2 = msg.to_request()
    assert req2.block_hash == block_hash
    assert req2.indices == [0, 1, 2]


def test_blocktxn_message():
    """Test blocktxn message wrapper."""
    block_hash = bytes(32)
    bt = BlockTransactions(block_hash=block_hash, transactions=[make_test_tx()])
    payload = bt.serialize()

    msg = BlockTxnMessage(payload_bytes=payload)
    net_msg = msg.to_network_message("regtest")

    assert net_msg.command == "blocktxn"

    # Parse response from message
    bt2 = msg.to_block_transactions()
    assert bt2.block_hash == block_hash


# --- Integration Tests ---


class MockMempoolEntry:
    """Mock mempool entry for testing."""
    def __init__(self, tx):
        self.tx = tx


class MockMempool:
    """Mock mempool for compact block reconstruction tests."""

    def __init__(self, txs=None):
        self.transactions = {}
        if txs:
            for tx in txs:
                self.transactions[tx.get_txid()] = MockMempoolEntry(tx)

    def match_compact_block(self, short_ids, siphash_key):
        """Match short txids against mempool."""
        from ouroboros.compact_blocks import short_txid

        # Build lookup
        wtxid_to_tx = {}
        for entry in self.transactions.values():
            tx = entry.tx
            sid = short_txid(siphash_key, tx.get_wtxid())
            wtxid_to_tx[sid] = tx

        # Match
        matched = []
        missing = []
        for i, sid in enumerate(short_ids):
            tx = wtxid_to_tx.get(sid)
            matched.append(tx)
            if tx is None:
                missing.append(i)

        return matched, missing


def test_compact_block_reconstruct_all_in_mempool():
    """Test reconstruction when all txs are in mempool."""
    # Create transactions
    coinbase = make_test_tx(5000000000, is_coinbase=True)
    tx1 = make_test_tx(1000)
    tx2 = make_test_tx(2000)

    # Create compact block
    header = bytes(80)
    nonce = 42
    key = compute_siphash_key(header, nonce)

    sid1 = short_txid(key, tx1.get_wtxid())
    sid2 = short_txid(key, tx2.get_wtxid())

    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=[sid1, sid2],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )

    # Create mempool with the transactions
    mempool = MockMempool([tx1, tx2])

    # Reconstruct
    txs, missing = cb.reconstruct(mempool)

    assert missing == []
    assert txs is not None
    assert len(txs) == 3  # coinbase + 2 txs


def test_compact_block_reconstruct_missing_tx():
    """Test reconstruction when some txs are missing."""
    coinbase = make_test_tx(5000000000, is_coinbase=True)
    tx1 = make_test_tx(1000)
    tx2 = make_test_tx(2000)  # Not in mempool

    header = bytes(80)
    nonce = 42
    key = compute_siphash_key(header, nonce)

    sid1 = short_txid(key, tx1.get_wtxid())
    sid2 = short_txid(key, tx2.get_wtxid())

    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=[sid1, sid2],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )

    # Mempool only has tx1
    mempool = MockMempool([tx1])

    # Reconstruct
    txs, missing = cb.reconstruct(mempool)

    assert missing == [2]  # tx2's position (index 2)
    assert txs is None  # Can't complete reconstruction


def test_compact_block_reconstruct_empty_mempool():
    """Test reconstruction with empty mempool."""
    coinbase = make_test_tx(5000000000, is_coinbase=True)
    tx1 = make_test_tx(1000)

    header = bytes(80)
    nonce = 42
    key = compute_siphash_key(header, nonce)

    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=[short_txid(key, tx1.get_wtxid())],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )

    mempool = MockMempool([])

    txs, missing = cb.reconstruct(mempool)

    assert missing == [1]  # tx1's position
    assert txs is None


def test_compact_block_only_coinbase():
    """Test compact block with only coinbase (prefilled)."""
    coinbase = make_test_tx(5000000000, is_coinbase=True)

    header = bytes(80)
    cb = CompactBlock(
        header=header,
        nonce=0,
        short_ids=[],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )

    mempool = MockMempool([])

    txs, missing = cb.reconstruct(mempool)

    assert missing == []
    assert txs is not None
    assert len(txs) == 1
