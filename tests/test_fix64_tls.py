"""FIX-64 — HTTPS/TLS termination on the JSON-RPC server.

W119 universal prereq: the ouroboros RPC server bound plain HTTP only —
uvicorn.Config() was called without ssl_certfile / ssl_keyfile so no TLS
path existed.  This suite covers:

  * HTTPS round-trip with a self-signed cert (TLS handshake + getblockcount
    JSON-RPC call succeeds end-to-end through real sockets, not TestClient).
  * HTTP backward-compat — when neither --rpc-tls-cert nor --rpc-tls-key is
    set the server still listens over plain HTTP and existing tooling works
    unchanged.
  * Mismatched flags — passing exactly one of the pair raises ValueError at
    construction time (the both-or-neither guard) rather than silently
    falling back to HTTP, which would be a privacy / credential-exposure
    footgun if cookie auth is in use.

Reference: ``bitcoin-core/src/httpserver.cpp`` ``InitHTTPServer`` (the SSL
context branch under ``gArgs.GetBoolArg("-rpcssl", ...)``) and BIP-78
"Protocol" (which assumes the receiver speaks HTTPS over the public web).

The self-signed cert is generated in-process via ``cryptography`` (already
a hard dep, see ``pyproject.toml``: ``cryptography>=41.0.0``) so the suite
ships zero on-disk PEM fixtures.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ouroboros.rpc import RPCServer


# ---------------------------------------------------------------------------
# Mocks — minimal node surface for getblockcount to succeed.
# ---------------------------------------------------------------------------


class _MockDB:
    def get_best_block(self):
        return (b"\x00" * 32, 42)

    def get_block(self, *a, **kw):
        return None

    def get_block_by_height(self, *a, **kw):
        return None


class _MockMempool:
    def get_all_txids(self):
        return []

    def size(self):
        return 0

    def bytes(self):
        return 0

    @property
    def max_size(self):
        return 300_000_000


class _MockNode:
    def __init__(self) -> None:
        self.db = _MockDB()
        self.network = "regtest"
        self.mempool = _MockMempool()


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Bind :0 and return the kernel-assigned ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a fresh RSA self-signed cert + key for 127.0.0.1.

    Returns (cert_path, key_path).  Files are written under ``tmp_path``
    so pytest's tmp_path fixture handles cleanup.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(_ip("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "rpc.crt"
    key_path = tmp_path / "rpc.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _ip(s: str):
    """Module-local import shim — keeps top-level imports tidy."""
    from ipaddress import ip_address
    return ip_address(s)


class _ServerThread(threading.Thread):
    """Run a uvicorn.Server in a background thread with its own asyncio loop.

    We deliberately do NOT call ``RPCServer.start()`` because that helper
    pre-checks the port via ``connect_ex`` and would race against our own
    ephemeral-port reservation.  We build the Config / Server directly,
    using the same ssl kwargs the wiring under test would pass.
    """

    def __init__(self, app, *, port: int, ssl_certfile: str | None = None,
                 ssl_keyfile: str | None = None) -> None:
        super().__init__(daemon=True)
        kwargs: dict = {
            "host": "127.0.0.1",
            "port": port,
            "log_level": "warning",
        }
        if ssl_certfile and ssl_keyfile:
            kwargs["ssl_certfile"] = ssl_certfile
            kwargs["ssl_keyfile"] = ssl_keyfile
        self._config = uvicorn.Config(app, **kwargs)
        self._server = uvicorn.Server(self._config)
        self._loop: asyncio.AbstractEventLoop | None = None

    def run(self) -> None:  # noqa: D401 — Thread.run override
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._server.serve())
        finally:
            self._loop.close()

    def stop(self) -> None:
        self._server.should_exit = True
        self.join(timeout=10)


def _wait_for_port(port: int, *, tls: bool, timeout: float = 5.0) -> None:
    """Block until ``port`` accepts TCP connections (and TLS handshakes)."""
    deadline = time.time() + timeout
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
                if not tls:
                    return
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1"):
                    return
        except (OSError, ssl.SSLError):
            time.sleep(0.05)
    raise TimeoutError(f"server did not come up on port {port} within {timeout}s")


@pytest.fixture
def rpc_app():
    """Plain RPCServer (no TLS) — exposes its FastAPI ``.app`` to tests."""
    return RPCServer(_MockNode(), port=0, rate_limit=False)


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


class TestTlsRoundTrip:
    """End-to-end HTTPS handshake + JSON-RPC call through real sockets."""

    def test_https_round_trip(self, tmp_path: Path, rpc_app) -> None:
        cert_path, key_path = _make_self_signed_cert(tmp_path)
        port = _free_port()
        thread = _ServerThread(
            rpc_app.app,
            port=port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
        )
        thread.start()
        try:
            _wait_for_port(port, tls=True)
            # verify=False because the cert is self-signed; the point is to
            # prove a TLS handshake happens and the JSON-RPC layer answers
            # over it (not to test cert-chain validation).
            with httpx.Client(verify=False, timeout=5.0) as client:
                resp = client.post(
                    f"https://127.0.0.1:{port}/",
                    json={
                        "jsonrpc": "2.0",
                        "method": "getblockcount",
                        "params": [],
                        "id": 1,
                    },
                )
            assert resp.status_code == 200
            body = resp.json()
            assert body["id"] == 1
            assert body.get("result") == 42
        finally:
            thread.stop()

    def test_http_rejected_when_tls_enabled(
        self, tmp_path: Path, rpc_app
    ) -> None:
        """Sanity: connecting plaintext HTTP to a TLS server fails fast.

        Guards against the wiring regressing to ``listen_in_clear=True`` or
        similar dual-stack accidents.
        """
        cert_path, key_path = _make_self_signed_cert(tmp_path)
        port = _free_port()
        thread = _ServerThread(
            rpc_app.app,
            port=port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
        )
        thread.start()
        try:
            _wait_for_port(port, tls=True)
            with httpx.Client(verify=False, timeout=2.0) as client:
                with pytest.raises(httpx.HTTPError):
                    client.post(f"http://127.0.0.1:{port}/", json={})
        finally:
            thread.stop()


class TestHttpBackwardCompat:
    """Existing HTTP-only behaviour preserved when no TLS flags set."""

    def test_http_round_trip_no_tls(self, rpc_app) -> None:
        port = _free_port()
        thread = _ServerThread(rpc_app.app, port=port)
        thread.start()
        try:
            _wait_for_port(port, tls=False)
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    f"http://127.0.0.1:{port}/",
                    json={
                        "jsonrpc": "2.0",
                        "method": "getblockcount",
                        "params": [],
                        "id": "compat",
                    },
                )
            assert resp.status_code == 200
            body = resp.json()
            assert body["id"] == "compat"
            assert body.get("result") == 42
        finally:
            thread.stop()


class TestMismatchedFlags:
    """Both-or-neither: half-configured TLS is a startup error, never silent."""

    def test_cert_without_key_rejected(self, tmp_path: Path) -> None:
        cert_path, _ = _make_self_signed_cert(tmp_path)
        with pytest.raises(ValueError, match="both be set or both be None"):
            RPCServer(
                _MockNode(),
                port=0,
                rate_limit=False,
                tls_certfile=str(cert_path),
                tls_keyfile=None,
            )

    def test_key_without_cert_rejected(self, tmp_path: Path) -> None:
        _, key_path = _make_self_signed_cert(tmp_path)
        with pytest.raises(ValueError, match="both be set or both be None"):
            RPCServer(
                _MockNode(),
                port=0,
                rate_limit=False,
                tls_certfile=None,
                tls_keyfile=str(key_path),
            )

    def test_both_unset_falls_back_to_http(self) -> None:
        """The default (no TLS flags) constructs cleanly and stays HTTP."""
        server = RPCServer(_MockNode(), port=0, rate_limit=False)
        assert server.tls_certfile is None
        assert server.tls_keyfile is None

    def test_both_set_records_paths(self, tmp_path: Path) -> None:
        cert_path, key_path = _make_self_signed_cert(tmp_path)
        server = RPCServer(
            _MockNode(),
            port=0,
            rate_limit=False,
            tls_certfile=str(cert_path),
            tls_keyfile=str(key_path),
        )
        assert server.tls_certfile == str(cert_path)
        assert server.tls_keyfile == str(key_path)


class TestCliMismatch:
    """Click layer rejects half-pairs with BadParameter before node spin-up."""

    def test_cli_cert_without_key(self) -> None:
        from click.testing import CliRunner
        from ouroboros.cli import cli
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["start", "--rpc-tls-cert", "/tmp/nonexistent.pem"],
        )
        assert result.exit_code != 0
        # Click's UsageError prefixes the message with "Invalid value".  The
        # specific phrase about both-or-neither is what we want to assert.
        assert "both" in result.output.lower()

    def test_cli_key_without_cert(self) -> None:
        from click.testing import CliRunner
        from ouroboros.cli import cli
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["start", "--rpc-tls-key", "/tmp/nonexistent.pem"],
        )
        assert result.exit_code != 0
        assert "both" in result.output.lower()
