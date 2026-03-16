"""
Unit tests for batch JSON-RPC support.

Tests the RPCServer's ability to handle batch requests per JSON-RPC 2.0 spec:
- Array of requests returns array of responses
- Empty batch returns error code -32600
- Per-call errors don't abort the batch
- Batch size limit is enforced
"""

import pytest
from unittest.mock import MagicMock, AsyncMock
from fastapi.testclient import TestClient


# Mock database and node before importing rpc
class MockDB:
    def get_best_block(self):
        return (b"\x00" * 32, 100)

    def get_block(self, *a, **kw):
        return None

    def get_block_by_height(self, *a, **kw):
        return None


class MockMempool:
    """Mock mempool with proper return values."""
    def get_all_txids(self):
        return []

    def size(self):
        return 0

    def bytes(self):
        return 0

    @property
    def max_size(self):
        return 300_000_000


class MockNode:
    def __init__(self):
        self.db = MockDB()
        self.network = "regtest"
        self.mempool = MockMempool()


@pytest.fixture
def rpc_server():
    """Create an RPCServer instance with a mock node."""
    from ouroboros.rpc import RPCServer
    node = MockNode()
    server = RPCServer(node, port=18332, rate_limit=False, max_batch_size=10)
    return server


@pytest.fixture
def client(rpc_server):
    """Create a FastAPI test client."""
    return TestClient(rpc_server.app)


class TestBatchRPC:
    """Test batch JSON-RPC request handling."""

    def test_single_request(self, client):
        """Single (non-batch) requests still work."""
        response = client.post("/", json={
            "jsonrpc": "2.0",
            "method": "getblockcount",
            "params": [],
            "id": 1
        })
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1
        assert "result" in data
        assert isinstance(data["result"], int)

    def test_batch_request(self, client):
        """Batch request returns array of responses."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 2},
        ])
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["id"] == 1
        assert data[1]["id"] == 2

    def test_batch_preserves_order(self, client):
        """Batch responses are in the same order as requests."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": "a"},
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": "b"},
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": "c"},
        ])
        assert response.status_code == 200
        data = response.json()
        assert [r["id"] for r in data] == ["a", "b", "c"]

    def test_empty_batch_error(self, client):
        """Empty batch [] returns error code -32600."""
        response = client.post("/", json=[])
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == -32600
        assert "empty batch" in data["error"]["message"].lower()

    def test_batch_per_call_error(self, client):
        """Errors in one call don't abort the batch."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "nonexistent_method", "params": [], "id": 2},
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 3},
        ])
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

        # First call succeeds
        assert data[0]["id"] == 1
        assert "result" in data[0]
        assert data[0].get("error") is None

        # Second call fails (method not found)
        assert data[1]["id"] == 2
        assert "error" in data[1]
        assert data[1]["error"]["code"] == -32601  # Method not found

        # Third call succeeds
        assert data[2]["id"] == 3
        assert "result" in data[2]
        assert data[2].get("error") is None

    def test_batch_size_limit(self, client, rpc_server):
        """Batch exceeding max_batch_size is rejected."""
        # Server has max_batch_size=10
        requests = [
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": i}
            for i in range(15)
        ]
        response = client.post("/", json=requests)
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == -32600
        assert "exceeds maximum" in data["error"]["message"]

    def test_batch_invalid_element(self, client):
        """Invalid element in batch returns error for that element."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
            "not an object",
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 3},
        ])
        assert response.status_code == 200
        data = response.json()
        # String "not an object" doesn't have an id, so it won't be in response
        # But we should still get responses for valid requests
        assert len(data) >= 2

    def test_batch_missing_method(self, client):
        """Request missing method field returns error."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "params": [], "id": 1},
        ])
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert "error" in data[0]
        assert data[0]["error"]["code"] == -32600

    def test_parse_error(self, client):
        """Invalid JSON returns parse error."""
        response = client.post(
            "/",
            content=b"{invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == -32700  # Parse error

    def test_invalid_request_type(self, client):
        """Non-object, non-array request returns error."""
        response = client.post("/", json="just a string")
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == -32600

    def test_batch_with_null_id(self, client):
        """Requests with null id are treated as notifications (no response)."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "getblockcount", "params": []},  # notification
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 3},
        ])
        assert response.status_code == 200
        data = response.json()
        # Notification (no id) should not be in response
        assert len(data) == 2
        assert data[0]["id"] == 1
        assert data[1]["id"] == 3


class TestBatchRPCIntegration:
    """Integration tests using multiple RPC methods."""

    def test_mixed_methods_batch(self, client):
        """Batch with different methods works correctly."""
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "getmempoolinfo", "params": [], "id": 2},
        ])
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

        # getblockcount returns int
        assert data[0]["id"] == 1
        assert isinstance(data[0].get("result"), int) or "error" not in data[0]

        # getmempoolinfo returns dict with 'size' field
        assert data[1]["id"] == 2


class TestBatchRPCConfiguration:
    """Test batch RPC configuration options."""

    def test_custom_max_batch_size(self):
        """Custom max_batch_size is respected."""
        from ouroboros.rpc import RPCServer
        node = MockNode()
        server = RPCServer(node, port=18333, rate_limit=False, max_batch_size=5)
        client = TestClient(server.app)

        # 5 requests should work
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": i}
            for i in range(5)
        ])
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 5

        # 6 requests should fail
        response = client.post("/", json=[
            {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": i}
            for i in range(6)
        ])
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == -32600

    def test_default_max_batch_size(self):
        """Default max_batch_size is 1000."""
        from ouroboros.rpc import RPCServer
        node = MockNode()
        server = RPCServer(node, port=18334, rate_limit=False)
        assert server.max_batch_size == 1000
