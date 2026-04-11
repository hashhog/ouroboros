"""
Tests for the REST interface.

Reference: Bitcoin Core rest.cpp
"""


import pytest
from fastapi.testclient import TestClient


# Mock node with database
class MockBlock:
    """Mock block for testing."""

    def __init__(
        self,
        hash_bytes: bytes = b'\x00' * 32,
        height: int = 0,
        version: int = 1,
        prev_blockhash: bytes = b'\x00' * 32,
        merkle_root: bytes = b'\x00' * 32,
        timestamp: int = 1231006505,
        bits: int = 0x1d00ffff,
        nonce: int = 0,
        transactions: list = None,
    ):
        self.hash = hash_bytes
        self.height = height
        self.version = version
        self.prev_blockhash = prev_blockhash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.transactions = transactions or []

    def get_hash(self):
        return self.hash

    def serialize(self):
        # 80-byte header
        import struct
        header = struct.pack('<I', self.version)
        header += self.prev_blockhash
        header += self.merkle_root
        header += struct.pack('<I', self.timestamp)
        header += struct.pack('<I', self.bits)
        header += struct.pack('<I', self.nonce)
        # Simplified: just the header for testing
        return header


class MockTxIn:
    """Mock transaction input."""

    def __init__(self, prev_txid=None, prev_vout=0, script_sig=b'', sequence=0xffffffff):
        self.prev_txid = prev_txid or b'\x00' * 32
        self.prev_vout = prev_vout
        self.script_sig = script_sig
        self.sequence = sequence


class MockTxOut:
    """Mock transaction output."""

    def __init__(self, value=0, script_pubkey=b''):
        self.value = value
        self.script_pubkey = script_pubkey


class MockTx:
    """Mock transaction for testing."""

    def __init__(
        self,
        txid: bytes = None,
        version: int = 2,
        locktime: int = 0,
        is_coinbase: bool = False,
        inputs: list = None,
        outputs: list = None,
    ):
        self._txid = txid or b'\x01' * 32
        self.version = version
        self.locktime = locktime
        self.is_coinbase = is_coinbase
        self.inputs = inputs or [MockTxIn()]
        self.outputs = outputs or [MockTxOut(value=50_0000_0000, script_pubkey=b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')]
        self.witnesses = []

    def get_txid(self):
        return self._txid

    def serialize_with_witness(self) -> bytes:
        # Minimal stub: return a plausible serialized transaction length
        return b'\x00' * 200

    def get_wtxid(self):
        return self._txid

    def get_vsize(self):
        return 100

    def get_weight(self):
        return 400

    def serialize(self):
        # Simplified serialization
        return b'\x01' * 100


class MockDB:
    """Mock database for testing."""

    def __init__(self):
        self.blocks = {}
        self.blocks_by_height = {}
        self.utxos = {}
        self.tx_index = {}
        self.best_hash = b'\xab' * 32
        self.best_height = 100

        # Add genesis block
        genesis = MockBlock(hash_bytes=b'\x00' * 32, height=0)
        genesis.transactions = [MockTx(is_coinbase=True)]
        self.blocks[genesis.hash] = genesis
        self.blocks_by_height[0] = genesis

        # Add tip block
        tip = MockBlock(
            hash_bytes=self.best_hash,
            height=self.best_height,
            prev_blockhash=b'\x00' * 32,
        )
        tip.transactions = [
            MockTx(txid=b'\xaa' * 32, is_coinbase=True),
            MockTx(txid=b'\xbb' * 32),
        ]
        self.blocks[tip.hash] = tip
        self.blocks_by_height[self.best_height] = tip

    def get_best_block(self):
        return self.best_hash, self.best_height

    def get_block(self, block_hash):
        return self.blocks.get(block_hash)

    def get_block_by_height(self, height):
        return self.blocks_by_height.get(height)

    def get_block_hash_by_height(self, height):
        blk = self.blocks_by_height.get(height)
        return blk.hash if blk else None

    def get_utxo(self, txid, vout):
        return self.utxos.get((txid.hex() if isinstance(txid, bytes) else txid, vout))

    def get_tx_index(self, txid):
        return self.tx_index.get(txid.hex() if isinstance(txid, bytes) else txid)


class MockMempool:
    """Mock mempool for testing."""

    def __init__(self):
        self.txs = {}
        self.entries = {}
        self.spent = set()
        self.max_size = 300_000_000

    def get_transaction(self, txid):
        return self.txs.get(txid.hex() if isinstance(txid, bytes) else txid)

    def size(self):
        return len(self.txs)

    def is_spent(self, txid, vout):
        key = (txid.hex() if isinstance(txid, bytes) else txid, vout)
        return key in self.spent

    def get_all_entries(self):
        return list(self.entries.items())

    def get_total_bytes(self):
        return 0

    def get_memory_usage(self):
        return 0

    def get_total_fee(self):
        return 0

    def get_min_fee(self):
        return 0.00001


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.db = MockDB()
        self.mempool = MockMempool()
        self.network = 'regtest'
        self.config = {'network': 'regtest'}

    def get_difficulty(self, bits):
        return 1.0

    def get_current_difficulty(self):
        return 1.0

    def get_median_time(self, height=None):
        return 1231006505

    def get_chainwork(self):
        return '0' * 64

    def get_chainwork_at_height(self, height):
        return '0' * 64


@pytest.fixture
def mock_node():
    """Create a mock node for testing."""
    return MockNode()


@pytest.fixture
def rest_client(mock_node):
    """Create a test client with REST interface enabled."""
    from ouroboros.rpc import RPCServer

    server = RPCServer(
        mock_node,
        port=8332,
        username=None,
        password=None,
        rate_limit=False,
        enable_rest=True,
    )
    return TestClient(server.app)


class TestRESTChaininfo:
    """Tests for /rest/chaininfo endpoint."""

    def test_chaininfo_json(self, rest_client):
        """Test chaininfo returns valid JSON."""
        response = rest_client.get('/rest/chaininfo.json')
        assert response.status_code == 200
        data = response.json()
        assert 'chain' in data
        assert 'blocks' in data
        assert 'bestblockhash' in data
        assert data['chain'] == 'regtest'
        assert data['blocks'] == 100


class TestRESTBlockhashByHeight:
    """Tests for /rest/blockhashbyheight endpoint."""

    def test_blockhash_by_height_json(self, rest_client, mock_node):
        """Test getting block hash by height in JSON format."""
        response = rest_client.get('/rest/blockhashbyheight/0.json')
        assert response.status_code == 200
        data = response.json()
        assert 'blockhash' in data
        assert data['blockhash'] == '00' * 32

    def test_blockhash_by_height_hex(self, rest_client):
        """Test getting block hash by height in hex format."""
        response = rest_client.get('/rest/blockhashbyheight/0.hex')
        assert response.status_code == 200
        assert response.text.strip() == '00' * 32

    def test_blockhash_by_height_bin(self, rest_client):
        """Test getting block hash by height in binary format."""
        response = rest_client.get('/rest/blockhashbyheight/0.bin')
        assert response.status_code == 200
        assert len(response.content) == 32

    def test_blockhash_invalid_height(self, rest_client):
        """Test error for invalid height."""
        response = rest_client.get('/rest/blockhashbyheight/abc.json')
        assert response.status_code == 400

    def test_blockhash_height_out_of_range(self, rest_client):
        """Test error for height out of range."""
        response = rest_client.get('/rest/blockhashbyheight/999999.json')
        assert response.status_code == 404


class TestRESTBlock:
    """Tests for /rest/block endpoint."""

    def test_block_json(self, rest_client, mock_node):
        """Test getting block in JSON format."""
        # Get the tip block hash
        block_hash = mock_node.db.best_hash.hex()
        response = rest_client.get(f'/rest/block/{block_hash}.json')
        assert response.status_code == 200
        data = response.json()
        assert data['hash'] == block_hash
        assert 'tx' in data
        assert isinstance(data['tx'], list)

    def test_block_hex(self, rest_client, mock_node):
        """Test getting block in hex format."""
        block_hash = mock_node.db.best_hash.hex()
        response = rest_client.get(f'/rest/block/{block_hash}.hex')
        assert response.status_code == 200
        # Should be hex-encoded block data
        assert all(c in '0123456789abcdef\n' for c in response.text)

    def test_block_bin(self, rest_client, mock_node):
        """Test getting block in binary format."""
        block_hash = mock_node.db.best_hash.hex()
        response = rest_client.get(f'/rest/block/{block_hash}.bin')
        assert response.status_code == 200
        assert len(response.content) >= 80  # At least header size

    def test_block_not_found(self, rest_client):
        """Test error for non-existent block."""
        response = rest_client.get(f'/rest/block/{"ff" * 32}.json')
        assert response.status_code == 404

    def test_block_invalid_hash(self, rest_client):
        """Test error for invalid hash."""
        response = rest_client.get('/rest/block/invalid.json')
        assert response.status_code == 400


class TestRESTBlockNoTxDetails:
    """Tests for /rest/block/notxdetails endpoint."""

    def test_block_notxdetails_json(self, rest_client, mock_node):
        """Test getting block without tx details returns txids only."""
        block_hash = mock_node.db.best_hash.hex()
        response = rest_client.get(f'/rest/block/notxdetails/{block_hash}.json')
        assert response.status_code == 200
        data = response.json()
        assert 'tx' in data
        # Should be list of txid strings, not full tx objects
        for tx in data['tx']:
            assert isinstance(tx, str)
            assert len(tx) == 64  # 32 bytes hex


class TestRESTHeaders:
    """Tests for /rest/headers endpoint."""

    def test_headers_json(self, rest_client, mock_node):
        """Test getting headers in JSON format."""
        block_hash = '00' * 32  # Genesis hash
        response = rest_client.get(f'/rest/headers/{block_hash}.json?count=1')
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert 'hash' in data[0]

    def test_headers_hex(self, rest_client):
        """Test getting headers in hex format."""
        block_hash = '00' * 32
        response = rest_client.get(f'/rest/headers/{block_hash}.hex?count=1')
        assert response.status_code == 200
        # Should be multiple of 160 hex chars (80 bytes per header)
        content = response.text.strip()
        assert len(content) >= 160

    def test_headers_deprecated_path(self, rest_client):
        """Test deprecated path format: /rest/headers/<count>/<hash>."""
        block_hash = '00' * 32
        response = rest_client.get(f'/rest/headers/1/{block_hash}.json')
        assert response.status_code == 200

    def test_headers_invalid_count(self, rest_client):
        """Test error for invalid header count."""
        block_hash = '00' * 32
        response = rest_client.get(f'/rest/headers/{block_hash}.json?count=0')
        assert response.status_code == 400

    def test_headers_count_too_high(self, rest_client):
        """Test error for count exceeding maximum."""
        block_hash = '00' * 32
        response = rest_client.get(f'/rest/headers/{block_hash}.json?count=3000')
        assert response.status_code == 400


class TestRESTTx:
    """Tests for /rest/tx endpoint."""

    def test_tx_not_found(self, rest_client):
        """Test error for non-existent transaction."""
        response = rest_client.get(f'/rest/tx/{"ff" * 32}.json')
        assert response.status_code == 404

    def test_tx_invalid_format(self, rest_client):
        """Test error for missing format suffix."""
        response = rest_client.get(f'/rest/tx/{"aa" * 32}')
        assert response.status_code == 404


class TestRESTGetUTXOs:
    """Tests for /rest/getutxos endpoint."""

    def test_getutxos_empty_request(self, rest_client):
        """Test error for empty UTXO request."""
        response = rest_client.get('/rest/getutxos/.json')
        assert response.status_code == 400

    def test_getutxos_parse_error(self, rest_client):
        """Test error for invalid outpoint format."""
        response = rest_client.get('/rest/getutxos/invalid.json')
        assert response.status_code == 400

    def test_getutxos_valid_format(self, rest_client, mock_node):
        """Test valid UTXO query returns proper structure."""
        txid = 'aa' * 32
        response = rest_client.get(f'/rest/getutxos/{txid}-0.json')
        assert response.status_code == 200
        data = response.json()
        assert 'chainHeight' in data
        assert 'chaintipHash' in data
        assert 'bitmap' in data
        assert 'utxos' in data

    def test_getutxos_checkmempool(self, rest_client):
        """Test UTXO query with checkmempool flag."""
        txid = 'aa' * 32
        response = rest_client.get(f'/rest/getutxos/checkmempool/{txid}-0.json')
        assert response.status_code == 200
        data = response.json()
        assert 'bitmap' in data

    def test_getutxos_max_outpoints(self, rest_client):
        """Test error when exceeding max outpoints."""
        # Create 16 outpoints (more than MAX_GETUTXOS_OUTPOINTS=15)
        outpoints = '/'.join([f'{"aa" * 32}-{i}' for i in range(16)])
        response = rest_client.get(f'/rest/getutxos/{outpoints}.json')
        assert response.status_code == 400
        assert 'max outpoints exceeded' in response.json()['detail']


class TestRESTMempool:
    """Tests for /rest/mempool endpoints."""

    def test_mempool_info(self, rest_client):
        """Test mempool info endpoint."""
        response = rest_client.get('/rest/mempool/info.json')
        assert response.status_code == 200
        data = response.json()
        assert 'size' in data
        assert 'loaded' in data
        assert data['loaded'] is True

    def test_mempool_contents(self, rest_client):
        """Test mempool contents endpoint."""
        response = rest_client.get('/rest/mempool/contents.json')
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    def test_mempool_contents_non_verbose(self, rest_client):
        """Test mempool contents with verbose=false."""
        response = rest_client.get('/rest/mempool/contents.json?verbose=false')
        assert response.status_code == 200
        data = response.json()
        # Non-verbose returns list of txids
        assert isinstance(data, list)

    def test_mempool_verbose_with_sequence_error(self, rest_client):
        """Test error when both verbose and mempool_sequence are true."""
        response = rest_client.get('/rest/mempool/contents.json?verbose=true&mempool_sequence=true')
        assert response.status_code == 400


class TestRESTFormatParsing:
    """Tests for format suffix parsing."""

    def test_no_format_suffix(self, rest_client):
        """Test error when format suffix is missing."""
        response = rest_client.get(f'/rest/block/{"aa" * 32}')
        assert response.status_code == 404

    def test_invalid_format_suffix(self, rest_client):
        """Test error for unsupported format suffix."""
        response = rest_client.get(f'/rest/block/{"aa" * 32}.xml')
        assert response.status_code == 404


class TestRESTNoAuth:
    """Tests verifying REST endpoints don't require authentication."""

    def test_rest_no_auth_required(self, mock_node):
        """Test REST endpoints work without auth even when RPC requires it."""
        from ouroboros.rpc import RPCServer

        # Create server with auth required for RPC
        server = RPCServer(
            mock_node,
            port=8332,
            username='testuser',
            password='testpass',
            rate_limit=False,
            enable_rest=True,
        )
        client = TestClient(server.app)

        # REST endpoint should work without auth
        response = client.get('/rest/chaininfo.json')
        assert response.status_code == 200

        # RPC endpoint should require auth
        response = client.post('/', json={
            'jsonrpc': '2.0',
            'method': 'getblockcount',
            'id': 1,
        })
        # Without auth, should get authentication error (401 or error field)
        assert response.status_code == 401 or response.json().get('error') is not None


class TestRESTDisabled:
    """Tests for when REST interface is disabled."""

    def test_rest_disabled_by_default(self, mock_node):
        """Test REST endpoints are not available when disabled."""
        from ouroboros.rpc import RPCServer

        server = RPCServer(
            mock_node,
            port=8332,
            username=None,
            password=None,
            rate_limit=False,
            enable_rest=False,  # Disabled
        )
        client = TestClient(server.app)

        # REST endpoint should return 404
        response = client.get('/rest/chaininfo.json')
        assert response.status_code == 404
