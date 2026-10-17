"""The two HEADERS_CF populate tools must refuse to run.

Both filled ouroboros's header store from Bitcoin Core's RPC, including
``nTx`` (and, for the corpus tool, chainwork/height/mediantime/nexthash),
none of which is proof-of-work self-verifying. Serving that as our own answer
is an R3 violation, so the tools are disarmed: they exit 2 with a refusal,
never open the datadir and never dial an RPC endpoint.

The negative control is a local HTTP listener standing in for Core: the old
populate_headers_cf.py opened the datadir and called getblockcount on it
before doing anything else, so a working tool shows up as a connection and
a created datadir.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"


def _listener() -> tuple[socket.socket, list[int]]:
    """A TCP listener that counts accepted connections and closes them."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    hits: list[int] = []

    def _accept() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            hits.append(1)
            conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    return srv, hits


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO,
    )


def test_populate_headers_cf_refuses(tmp_path: Path) -> None:
    datadir = tmp_path / "ouroboros-datadir"
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:00")
    srv, hits = _listener()
    try:
        port = srv.getsockname()[1]
        proc = _run([
            str(TOOLS / "populate_headers_cf.py"),
            "--data-dir", str(datadir),
            "--core-rpc", f"http://127.0.0.1:{port}",
            "--core-cookie", str(cookie),
            "--start-height", "0",
        ])
    finally:
        srv.close()
    assert proc.returncode == 2, (proc.returncode, proc.stderr[-2000:])
    assert "REFUSED" in proc.stderr
    assert hits == [], "disarmed tool must not dial the Core RPC endpoint"
    assert not datadir.exists(), "disarmed tool must not open/create the datadir"


def test_populate_corpus_headers_refuses(tmp_path: Path) -> None:
    datadir = tmp_path / "ouroboros-datadir"
    proc = _run([str(TOOLS / "populate_corpus_headers.py"), str(datadir)])
    assert proc.returncode == 2, (proc.returncode, proc.stderr[-2000:])
    assert "REFUSED" in proc.stderr
    assert not datadir.exists(), "disarmed tool must not open/create the datadir"
