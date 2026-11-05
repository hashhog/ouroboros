"""A crash inside loadtxoutset must not wedge the node (security audit H8, L12).

``loadtxoutset`` sets SNAPSHOT_LOAD_IN_PROGRESS, clears the chainstate and
streams coins in.  If the process dies before the final commit, the next open
runs ``recover_from_crash``.  That recovery used to clear the chainstate and
write an all-zero best-block hash at height 0.  Boot only connects genesis
when reading the tip *raises* (``node.py``), and a zero hash reads fine, so
the node came up at ``0000...0000`` and every block 1 failed with "Previous
block hash mismatch": wedged until an operator intervened.  The same recovery
runs after a crash in ``replace_chainstate_with_ssts`` (``import-utxo``).

These tests drive the real thing: a regtest ouroboros process, a crash
simulated with the same FFI calls ``loadtxoutset`` makes followed by
``os._exit`` (no destructors, like SIGKILL), and a restart.

* ``test_restart_after_snapshot_load_crash_is_at_genesis``: after the
  restart the tip is the regtest genesis and ``generatetoaddress 1`` works.
* ``test_restart_after_snapshot_load_crash_resyncs_from_peer``: the node
  syncs its old chain back from a peer, though it still stores those blocks.
* ``test_restart_after_snapshot_load_crash_twice``: the recovered datadir
  survives a second crash/restart cycle (recovery is repeatable).
* ``test_zero_tip_datadir_refuses_to_start``: a datadir that an older build
  already left at the all-zero tip, with blocks still in it, is an unknown
  tip; boot refuses instead of serving it.
* ``test_legacy_zero_tip_sentinel_is_healed``: the exact state the old
  recovery left (zero tip, height 0, empty chainstate) is recognised and
  restarted from genesis, so nodes already wedged by it recover.

L12 (a failed recovery must fail the boot, not "continue anyway") is pinned in
Rust, ``ferrous-utils/sync/src/storage/snapshot_recovery_tests.rs``, which
calls the ``PyBlockchainDB`` constructor boot uses: the malformed marker that
makes recovery fail cannot be written through the Python FFI.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_SRC = Path(__file__).resolve().parents[1] / "src"
REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
ZERO_HASH = "00" * 32
# P2WPKH to a fixed 20-byte program, encoded for regtest (bcrt1...).
MINE_TO_SPK = bytes([0x00, 0x14]) + bytes([0x11]) * 20


def _env() -> dict:
    """Child env: this tree's ``src`` first, the caller's PYTHONPATH after.

    Keeping the caller's PYTHONPATH lets a run point at a freshly built
    ``sync`` wheel instead of whatever is installed in the venv.
    """
    extra = os.environ.get("PYTHONPATH", "")
    path = str(REPO_SRC) + (os.pathsep + extra if extra else "")
    return dict(os.environ, PYTHONPATH=path)


def _real_sync_available() -> bool:
    probe = subprocess.run(
        [sys.executable, "-c", "import sync; sync.PyBlockchainDB"],
        env=_env(), capture_output=True,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _real_sync_available(),
    reason="the compiled Rust `sync` extension is not built; this test runs a real node",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mine_address() -> str:
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; from ouroboros.address import script_pubkey_to_address as f; "
         f"print(f(bytes.fromhex('{MINE_TO_SPK.hex()}'), 'regtest'))"],
        env=_env(), capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


class Node:
    """One regtest ouroboros process on its own datadir."""

    def __init__(self, datadir: Path, connect: str = "127.0.0.1:1", listen: bool = False):
        self.datadir = datadir
        self.cookie = datadir / ".cookie"
        self.rpc_port = _free_port()
        self.p2p_port = _free_port()
        self.log = datadir / "test-node.log"
        datadir.mkdir(parents=True, exist_ok=True)
        args = [
            sys.executable, "-m", "ouroboros.cli",
            f"--data-dir={datadir}", "--network=regtest",
            "start", "--force",
            f"--rpc-port={self.rpc_port}", f"--p2p-port={self.p2p_port}",
            *(["--listen", "--bind=127.0.0.1"] if listen else ["--nolisten"]),
            "--nodnsseed", "--nodiscover", f"--connect={connect}",
        ]
        if self.cookie.exists():
            self.cookie.unlink()
        self._fh = open(self.log, "ab")
        self.proc = subprocess.Popen(args, stdout=self._fh, stderr=subprocess.STDOUT, env=_env())

    def wait_rpc(self, timeout: float = 180) -> None:
        deadline = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError(f"node exited rc={self.proc.returncode}: {self.tail()}")
            if self.cookie.exists():
                try:
                    self.call("getblockcount", timeout=5)
                    return
                except Exception:
                    pass
            if time.time() > deadline:
                self.close()
                raise RuntimeError(f"RPC not up in {timeout}s: {self.tail()}")
            time.sleep(0.5)

    def wait_exit(self, timeout: float = 90) -> int | None:
        """Exit code, or None if the node was still running at the deadline."""
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        finally:
            self.close()

    def call(self, method: str, *params, timeout: float = 60.0):
        auth = base64.b64encode(self.cookie.read_text().strip().encode()).decode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpc_port}/",
            data=json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                             "params": list(params)}).encode(),
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read())
        if body.get("error"):
            raise RuntimeError(f"{method}: {body['error']}")
        return body["result"]

    def tail(self) -> str:
        try:
            return self.log.read_text(errors="replace")[-3000:]
        except OSError:
            return ""

    def stop(self) -> None:
        try:
            self.call("stop", timeout=10)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass
        self.close()

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        if not self._fh.closed:
            self._fh.close()


def _db_script(datadir: Path, body: str) -> subprocess.CompletedProcess:
    """Run ``body`` against the datadir's DB in a fresh process.

    ``db`` is the opened ``sync.PyBlockchainDB``.  The script ends with
    ``os._exit(9)`` so no destructor runs, which is what a SIGKILL leaves.
    """
    code = "import os, sys, sync\n" + f"db = sync.PyBlockchainDB({str(datadir)!r})\n"
    code += textwrap.dedent(body) + "\nsys.stdout.flush()\nos._exit(9)\n"
    return subprocess.run([sys.executable, "-c", code], env=_env(),
                          capture_output=True, text=True, timeout=120)


def _crash_mid_snapshot_load(datadir: Path) -> None:
    """``loadtxoutset``'s FFI sequence, killed after the first chunk."""
    r = _db_script(datadir, """
        db.snapshot_load_begin(bytes([0xCD]) * 32, 10)
        coins = [(bytes([0xAB]) * 32, v, 50_0000_0000, bytes([0x51]), 1, False) for v in range(3)]
        db.snapshot_load_chunk(coins)
        print("marker", db.has_snapshot_load_marker(), "utxos", db.utxo_count())
    """)
    assert r.returncode == 9, r.stderr
    assert "marker True" in r.stdout, r.stdout + r.stderr


def _mine(node: Node, n: int) -> list[str]:
    return node.call("generatetoaddress", n, _mine_address())


@pytest.fixture
def mined_datadir(tmp_path):
    """A stopped regtest datadir with 5 blocks on top of genesis."""
    datadir = tmp_path / "node"
    node = Node(datadir)
    try:
        node.wait_rpc()
        assert node.call("getbestblockhash") == REGTEST_GENESIS
        _mine(node, 5)
        assert node.call("getblockcount") == 5
    finally:
        node.stop()
    return datadir


def _assert_restarts_at_genesis_and_mines(datadir: Path) -> None:
    node = Node(datadir)
    try:
        node.wait_rpc()
        tip = node.call("getbestblockhash")
        assert tip == REGTEST_GENESIS, f"restarted at tip {tip}, not genesis"
        assert node.call("getblockcount") == 0
        hashes = _mine(node, 1)
        assert len(hashes) == 1
        assert node.call("getblockcount") == 1
        assert node.call("getbestblockhash") == hashes[0]
        assert node.call("getblockhash", 0) == REGTEST_GENESIS
    finally:
        node.stop()


def test_restart_after_snapshot_load_crash_is_at_genesis(mined_datadir):
    _crash_mid_snapshot_load(mined_datadir)
    _assert_restarts_at_genesis_and_mines(mined_datadir)


def test_restart_after_snapshot_load_crash_resyncs_from_peer(tmp_path):
    """After recovery the node must sync its old chain back from a peer.

    Its block store still holds blocks 1..5 (recovery clears only the UTXO
    set and the tip), which is the state the audit saw stall over P2P with
    ``accept_block at h=1 failed: inconclusive``.  The peer is a copy of the
    same datadir taken before the crash.
    """
    import shutil

    datadir = tmp_path / "node"
    node = Node(datadir)
    try:
        node.wait_rpc()
        hashes = _mine(node, 5)
    finally:
        node.stop()
    peer_dir = tmp_path / "peer"
    shutil.copytree(datadir, peer_dir)

    _crash_mid_snapshot_load(datadir)

    peer = Node(peer_dir, listen=True)
    try:
        peer.wait_rpc()
        assert peer.call("getblockcount") == 5
        node = Node(datadir, connect=f"127.0.0.1:{peer.p2p_port}")
        try:
            node.wait_rpc()
            deadline = time.time() + 120
            while time.time() < deadline and node.call("getblockcount") < 5:
                time.sleep(1)
            assert node.call("getblockcount") == 5, node.tail()
            assert node.call("getbestblockhash") == hashes[-1]
            assert node.call("gettxoutsetinfo")["txouts"] >= 5
        finally:
            node.stop()
    finally:
        peer.stop()


def test_restart_after_snapshot_load_crash_twice(mined_datadir):
    _crash_mid_snapshot_load(mined_datadir)
    _assert_restarts_at_genesis_and_mines(mined_datadir)
    _crash_mid_snapshot_load(mined_datadir)
    _assert_restarts_at_genesis_and_mines(mined_datadir)


def test_zero_tip_datadir_refuses_to_start(mined_datadir):
    """An all-zero tip over a non-empty chainstate is not a state any code
    path produces on purpose; boot must not serve it as a chain."""
    r = _db_script(mined_datadir, """
        db.update_best_block(bytes(32), 0)
        print("utxos", db.utxo_count())
    """)
    assert r.returncode == 9, r.stderr
    assert "utxos 0" not in r.stdout, r.stdout

    node = Node(mined_datadir)
    rc = node.wait_exit()
    assert rc is not None, "node booted and kept running on an all-zero tip"
    assert rc != 0, node.tail()
    assert "all-zero" in node.tail(), node.tail()


def test_legacy_zero_tip_sentinel_is_healed(mined_datadir):
    """The exact state older builds' recovery left behind: chainstate empty,
    tip ``0000...0000`` at height 0, markers gone."""
    r = _db_script(mined_datadir, """
        # Clear the chainstate and drop the marker the way the old recovery
        # did: an empty snapshot load committed at the zero sentinel tip.
        db.snapshot_load_begin(bytes([0xCD]) * 32, 10)
        db.snapshot_load_commit(bytes(32), 0, None, None)
        db.update_best_block(bytes(32), 0)
        print("marker", db.has_snapshot_load_marker(), "utxos", db.utxo_count(),
              "tip", bytes(db.get_best_block()[0]).hex(), db.get_best_block()[1])
    """)
    assert r.returncode == 9, r.stderr
    assert f"marker False utxos 0 tip {ZERO_HASH} 0" in r.stdout, r.stdout + r.stderr
    _assert_restarts_at_genesis_and_mines(mined_datadir)
