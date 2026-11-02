"""Audit H5: the RPC port must not answer without credentials or send CORS.

Core routes every request on the RPC port through RPCAuthorized
(httprpc.cpp) and sends no CORS headers; REST is a separate opt-in
surface (-rest). ouroboros used to register GET /health, /getblockstats
and /getblockfilter straight on the app, outside _handle_rpc_common's
auth and rate limit, and installed CORSMiddleware(allow_origins=["*"],
allow_credentials=True), which reflects any Origin with
Access-Control-Allow-Credentials: true.  Together they let any web page
the operator visits make the node walk blocks and read the answers.
"""

import pytest
from fastapi.testclient import TestClient

EVIL = "https://evil.com"


class _DB:
    def get_best_block(self):
        return (b"\x00" * 32, 0)

    def get_block(self, *a, **kw):
        return None

    def get_block_by_height(self, *a, **kw):
        return None


class _Mempool:
    def get_all_txids(self):
        return []

    def size(self):
        return 0

    def bytes(self):
        return 0

    @property
    def max_size(self):
        return 300_000_000


class _Node:
    def __init__(self):
        self.db = _DB()
        self.network = "regtest"
        self.mempool = _Mempool()


def _refused(r):
    # 401 from the auth layer, or the router's own "no such route" answer.
    # A 404 that carries the route's own detail (e.g. "Block not found at
    # height 0") means the handler ran, so it does not count.
    if r.status_code in (401, 405):
        return True
    return r.status_code == 404 and r.json() == {"detail": "Not Found"}


def _gone(r):
    return r.status_code == 405 or (
        r.status_code == 404 and r.json() == {"detail": "Not Found"}
    )


@pytest.fixture
def client():
    from ouroboros.rpc import RPCServer

    server = RPCServer(
        _Node(), port=18332, username="u", password="p", rate_limit=False
    )
    return TestClient(server.app)


@pytest.mark.parametrize(
    "path",
    [
        "/health",
        "/getblockstats?hash_or_height=0",
        "/getblockfilter?blockhash=" + "00" * 32,
    ],
)
def test_unauthenticated_get_routes_are_refused(client, path):
    r = client.get(path)
    assert _refused(r), (path, r.status_code, r.text)


@pytest.mark.parametrize(
    "path",
    [
        "/health",
        "/getblockstats?hash_or_height=0",
        "/getblockfilter?blockhash=" + "00" * 32,
    ],
)
def test_authenticated_get_routes_are_gone(client, path):
    # The data stays reachable through JSON-RPC; the bespoke GET surface
    # is removed rather than authenticated, as Core has no such routes.
    r = client.get(path, auth=("u", "p"))
    assert _gone(r), (path, r.status_code, r.text)


def test_cors_preflight_gets_no_allow_origin(client):
    r = client.options(
        "/",
        headers={
            "Origin": EVIL,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert "access-control-allow-origin" not in r.headers, dict(r.headers)
    assert "access-control-allow-credentials" not in r.headers, dict(r.headers)


def test_cross_origin_post_gets_no_allow_origin(client):
    r = client.post(
        "/",
        json={"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
        headers={"Origin": EVIL},
        auth=("u", "p"),
    )
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers, dict(r.headers)
    assert "access-control-allow-credentials" not in r.headers, dict(r.headers)


def test_post_without_credentials_still_401(client):
    # Control: proves the client is talking to an auth-enforcing server, so
    # the 401/404 above is not an artefact of a broken fixture.
    r = client.post(
        "/",
        json={"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
    )
    assert r.status_code == 401


def test_jsonrpc_getblockstats_still_dispatched(client):
    # The JSON-RPC method stays; only the GET route goes.
    r = client.post(
        "/",
        json={"jsonrpc": "2.0", "method": "getblockstats", "params": [0], "id": 1},
        auth=("u", "p"),
    )
    body = r.json()
    err = body.get("error") or {}
    assert err.get("code") != -32601, body
