"""A multi-block reorg must run script checks on blocks 2..n (QUEUES latent P1).

The gate-6 agent found (2026-10-04) that the batch arm of
``RPCServer._reorg_to_side_branch_tip`` skips every script check from the
first transaction in blocks 2..n that spends an output created earlier in
the batch, and ``connect_blocks_atomic`` checks no scripts at all.  The
design receipt of the same day showed that arm is unreachable in production:
it is gated on ``hasattr(db, "connect_blocks_atomic")`` and
``BlockchainDatabase`` has no such method, so every live reorg goes through
the per-block ``accept_block`` arm.  The tests that covered the batch arm
used a MagicMock db, which has every attribute, so none of them reached the
object production uses.  This file drives the real thing instead: a regtest
ouroboros process, fed over submitblock and over P2P.

Chain (every coinbase pays bare OP_TRUE)::

    G-1-...-100-A101                       active, first seen
                \\-X101-X102               side branch, heavier

X101 spends the coinbase of block 1 into ``OP_2 OP_EQUAL``.  X102 spends
that output, which exists only on the side branch.  In the bad branch its
scriptSig pushes 3 (EVAL_FALSE), in the good branch 2.  Nothing but script
execution tells the two apart: amounts, maturity, sigops, sizes and
locktimes are identical.

Bitcoin Core v31.1 (measured, see ``CORE_*`` below and the opt-in oracle
test at the end): submitblock X101 answers ``inconclusive`` (equal work,
stored, not connected); submitblock X102 reorgs to X101, fails X102 in
ConnectBlock with the script error, and returns to A101 (equal work, first
seen).  Over P2P the same blocks leave Core on A101 with X102 ``invalid``.
The good branch moves Core to X102 on both paths.

What each test proves:

* ``test_*_rejects_invalid_script_branch``: ouroboros ends on A101, never
  on X102, and (submitblock) answers with a script-failure reason.  These
  fail by name if reorg connect skips scripts in blocks 2..n.
* ``test_*_accepts_valid_script_branch``: the positive control.  Without it
  a node that refused every 2-block reorg (the fail-closed shape the design
  receipt predicts if the batch arm were armed with the real Rust helper)
  would pass the reject tests.
* ``test_core_oracle_matches_pins``: runs the same four scenarios on
  Bitcoin Core when ``OUROBOROS_TEST_BITCOIND`` names a bitcoind binary, and
  checks the pinned Core outcomes above are still what Core does.

The node is a separate process on regtest with its own datadir under
pytest's tmp_path, so it imports the compiled ``sync`` extension, not the
conftest stub.  The module skips when that extension is not built.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_SRC = Path(__file__).resolve().parents[1] / "src"

# --------------------------------------------------------------------------
# Deterministic regtest blocks
# --------------------------------------------------------------------------

GENESIS_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
# Far enough after genesis to clear MTP and in the past on every host, so
# nothing depends on the wall clock.
BASE_TIME = 1_700_000_000
REGTEST_BITS = 0x207FFFFF
COIN = 100_000_000
SUBSIDY = 50 * COIN  # regtest halves every 150 blocks; this chain stays below
FORK_HEIGHT = 100
FEE = 1000

OP_TRUE = b"\x51"
OP_2_EQUAL = b"\x52\x87"
GOOD_SCRIPTSIG = b"\x52"  # pushes 2: 2 == 2
BAD_SCRIPTSIG = b"\x53"  # pushes 3: 3 != 2, SCRIPT_ERR_EVAL_FALSE


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def script_num(height: int) -> bytes:
    """BIP34 height push, as ``CScript() << nHeight`` encodes it."""
    if height <= 16:
        return bytes([0x50 + height])
    enc = bytearray()
    v = height
    while v:
        enc.append(v & 0xFF)
        v >>= 8
    if enc[-1] & 0x80:
        enc.append(0)
    return bytes([len(enc)]) + bytes(enc)


def tx(inputs: list[tuple[bytes, int, bytes]], outputs: list[tuple[int, bytes]]) -> bytes:
    """Legacy (non-witness) serialization; inputs are (txid_le, vout, scriptSig)."""
    raw = struct.pack("<i", 2) + compact_size(len(inputs))
    for txid_le, vout, sig in inputs:
        raw += txid_le + struct.pack("<I", vout) + compact_size(len(sig)) + sig
        raw += struct.pack("<I", 0xFFFFFFFF)
    raw += compact_size(len(outputs))
    for value, spk in outputs:
        raw += struct.pack("<q", value) + compact_size(len(spk)) + spk
    return raw + struct.pack("<I", 0)


def coinbase(height: int, tag: int) -> bytes:
    sig = script_num(height) + bytes([0x01, tag])
    return tx([(b"\x00" * 32, 0xFFFFFFFF, sig)], [(SUBSIDY, OP_TRUE)])


def merkle_root(hashes: list[bytes]) -> bytes:
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def make_block(prev_le: bytes, height: int, tag: int, txs: list[bytes] = ()) -> bytes:
    body = [coinbase(height, tag), *txs]
    merkle = merkle_root([sha256d(t) for t in body])
    prefix = (
        struct.pack("<i", 0x20000000)
        + prev_le
        + merkle
        + struct.pack("<II", BASE_TIME + height * 600 + tag, REGTEST_BITS)
    )
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(1 << 24):
        header = prefix + struct.pack("<I", nonce)
        if int.from_bytes(sha256d(header), "little") <= target:
            break
    return header + compact_size(len(body)) + b"".join(body)


def bhash_le(block: bytes) -> bytes:
    return sha256d(block[:80])


def bhash(block: bytes) -> str:
    return bhash_le(block)[::-1].hex()


def build_chain(good: bool) -> dict:
    """Shared prefix 1..100, A101 on it, and the X101-X102 side branch."""
    base: list[bytes] = []
    prev = bytes.fromhex(GENESIS_HASH)[::-1]
    for h in range(1, FORK_HEIGHT + 1):
        blk = make_block(prev, h, 0x10)
        base.append(blk)
        prev = bhash_le(blk)
    fork_le = prev
    a101 = make_block(fork_le, FORK_HEIGHT + 1, 0xA1)

    cb1_txid = sha256d(coinbase(1, 0x10))
    tx1 = tx([(cb1_txid, 0, b"")], [(SUBSIDY - FEE, OP_2_EQUAL)])
    x101 = make_block(fork_le, FORK_HEIGHT + 1, 0xB1, [tx1])
    tx2 = tx(
        [(sha256d(tx1), 0, GOOD_SCRIPTSIG if good else BAD_SCRIPTSIG)],
        [(SUBSIDY - 2 * FEE, OP_TRUE)],
    )
    x102 = make_block(bhash_le(x101), FORK_HEIGHT + 2, 0xB2, [tx2])
    return {"base": base, "a101": a101, "x101": x101, "x102": x102}


# Built once per module; PoW on regtest is ~2 hashes a block.
_CHAINS: dict[bool, dict] = {}


def chain(good: bool) -> dict:
    if good not in _CHAINS:
        _CHAINS[good] = build_chain(good)
    return _CHAINS[good]


# --------------------------------------------------------------------------
# Pinned Bitcoin Core v31.1 outcomes (re-checked by test_core_oracle_matches_pins)
# --------------------------------------------------------------------------

CORE_X101_SUBMIT = "inconclusive"
# Core's ConnectBlock reason; ouroboros must at least name a script failure.
CORE_X102_BAD_SUBMIT = (
    "block-script-verify-flag-failed "
    "(Script evaluated without error but finished with a false/empty top stack element)"
)
CORE_X102_GOOD_SUBMIT = None  # null: accepted and connected


# --------------------------------------------------------------------------
# Processes and RPC
# --------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Rpc:
    def __init__(self, port: int, cookie: Path):
        self.url = f"http://127.0.0.1:{port}/"
        self.cookie = cookie

    def call(self, method: str, *params, timeout: float = 60.0):
        auth = base64.b64encode(self.cookie.read_text().strip().encode()).decode()
        req = urllib.request.Request(
            self.url,
            data=json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode(),
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


class Proc:
    """One regtest node process: ouroboros or bitcoind."""

    def __init__(self, kind: str, datadir: Path, binary: str | None = None):
        self.kind = kind
        self.datadir = datadir
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        self.log = datadir / "test-node.log"
        datadir.mkdir(parents=True, exist_ok=True)
        if kind == "ouroboros":
            args = [
                sys.executable, "-m", "ouroboros.cli",
                f"--data-dir={datadir}", "--network=regtest",
                "start", "--force",
                f"--rpc-port={self.rpc_port}", f"--p2p-port={self.p2p_port}",
                "--listen", "--bind=127.0.0.1",
                "--nodnsseed", "--nodiscover", "--connect=127.0.0.1:1",
            ]
            env = dict(os.environ, PYTHONPATH=str(REPO_SRC))
            self.cookie = datadir / ".cookie"
        else:
            args = [
                binary, "-regtest", f"-datadir={datadir}",
                f"-rpcport={self.rpc_port}", f"-port={self.p2p_port}",
                "-bind=127.0.0.1", "-listen=1", "-connect=0", "-dnsseed=0",
                "-fixedseeds=0", "-maxtipage=2000000000", "-printtoconsole=0",
            ]
            env = dict(os.environ)
            self.cookie = datadir / "regtest" / ".cookie"
        self._fh = open(self.log, "wb")
        self.proc = subprocess.Popen(args, stdout=self._fh, stderr=subprocess.STDOUT, env=env)
        self.rpc = Rpc(self.rpc_port, self.cookie)
        deadline = time.time() + 180
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{kind} exited rc={self.proc.returncode}: {self.tail()}")
            if self.cookie.exists():
                try:
                    self.rpc.call("getblockcount", timeout=5)
                    break
                except Exception:
                    pass
            if time.time() > deadline:
                self.close()
                raise RuntimeError(f"{kind} RPC not up in 180s: {self.tail()}")
            time.sleep(0.5)

    def tail(self) -> str:
        try:
            return self.log.read_text(errors="replace")[-3000:]
        except OSError:
            return ""

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._fh.close()


# --------------------------------------------------------------------------
# P2P feeder: announce headers, serve getdata, as a real peer would
# --------------------------------------------------------------------------

REGTEST_MAGIC = bytes.fromhex("fabfb5da")
MSG_BLOCK = 2
MSG_WITNESS_FLAG = 1 << 30


def p2p_msg(cmd: str, payload: bytes = b"") -> bytes:
    return (
        REGTEST_MAGIC + cmd.encode().ljust(12, b"\x00")
        + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload
    )


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_msg(sock: socket.socket) -> tuple[str, bytes]:
    hdr = _recv_exact(sock, 24)
    assert hdr[:4] == REGTEST_MAGIC, hdr[:4].hex()
    cmd = hdr[4:16].split(b"\x00", 1)[0].decode()
    (length,) = struct.unpack("<I", hdr[16:20])
    return cmd, _recv_exact(sock, length) if length else b""


def version_payload(start_height: int) -> bytes:
    addr = struct.pack("<Q", 0) + b"\x00" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", 0)
    agent = b"/forkfeed-test:0.1/"
    return (
        struct.pack("<iQq", 70016, 1 | 8, int(time.time()))  # NODE_NETWORK | NODE_WITNESS
        + addr + addr + struct.pack("<Q", 0x5EED_F00D_CAFE_0001)
        + compact_size(len(agent)) + agent
        + struct.pack("<i", start_height) + b"\x00"
    )


def p2p_feed(port: int, blocks: list[bytes], start_height: int, until, timeout_s: float = 90.0) -> list[str]:
    """Announce ``blocks`` as headers and serve them until ``until()`` is true.

    Returns a log of what the node asked for.  The node may ask for the
    headers chain (getheaders) and for the blocks (getdata); both are
    answered from ``blocks`` only.
    """
    by_hash = {bhash_le(b): b for b in blocks}
    seen: list[str] = []
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(p2p_msg("version", version_payload(start_height)))
        handshake = False
        announced = False
        deadline = time.time() + timeout_s
        sock.settimeout(0.5)
        while time.time() < deadline:
            if handshake and not announced:
                hdrs = b"".join(b[:80] + b"\x00" for b in blocks)
                sock.sendall(p2p_msg("headers", compact_size(len(blocks)) + hdrs))
                announced = True
            if announced and until():
                return seen
            try:
                cmd, payload = read_msg(sock)
            except TimeoutError:
                continue
            except (ConnectionError, OSError):
                # Core disconnects a peer that served an invalid block; that
                # close is part of the rejection, not a feeder failure.
                seen.append("<closed>")
                return seen
            seen.append(cmd)
            if cmd == "version":
                sock.sendall(p2p_msg("verack"))
            elif cmd == "verack":
                handshake = True
            elif cmd == "ping":
                sock.sendall(p2p_msg("pong", payload))
            elif cmd == "getdata":
                count, off = payload[0], 1  # always < 0xfd here
                for _ in range(count):
                    inv_type, = struct.unpack("<I", payload[off:off + 4])
                    h = payload[off + 4:off + 36]
                    off += 36
                    if inv_type & ~MSG_WITNESS_FLAG == MSG_BLOCK and h in by_hash:
                        seen.append(f"served:{h[::-1].hex()}")
                        sock.sendall(p2p_msg("block", by_hash[h]))
        return seen
    finally:
        sock.close()


# --------------------------------------------------------------------------
# The scenario, node-agnostic
# --------------------------------------------------------------------------


def setup_base(node: Proc, c: dict) -> None:
    for blk in c["base"]:
        res = node.rpc.call("submitblock", blk.hex())
        assert res is None, f"base block rejected: {res}"
    assert node.rpc.call("submitblock", c["a101"].hex()) is None
    assert node.rpc.call("getbestblockhash") == bhash(c["a101"])


def run_submitblock(node: Proc, good: bool) -> dict:
    c = chain(good)
    setup_base(node, c)
    r1 = node.rpc.call("submitblock", c["x101"].hex())
    r2 = node.rpc.call("submitblock", c["x102"].hex())
    tips = {t["hash"]: t["status"] for t in node.rpc.call("getchaintips")}
    return {"x101": r1, "x102": r2, "best": node.rpc.call("getbestblockhash"),
            "count": node.rpc.call("getblockcount"), "x102_status": tips.get(bhash(c["x102"]))}


def run_p2p(node: Proc, good: bool, settle_s: float = 20.0) -> dict:
    """Feed X101, X102 over P2P.  For the bad branch nothing moves the tip,
    so the feeder waits until the node has asked for both blocks and then a
    settle period, long enough to process the reorg and its rollback."""
    c = chain(good)
    setup_base(node, c)
    want = bhash(c["x102"])
    asked_at: list[float] = []

    def done() -> bool:
        if node.rpc.call("getbestblockhash") == want:
            return True
        tips = {t["hash"]: t["status"] for t in node.rpc.call("getchaintips")}
        if tips.get(want) == "invalid":
            if not asked_at:
                asked_at.append(time.time())
            return time.time() - asked_at[0] > 2.0
        return False

    seen = p2p_feed(node.p2p_port, [c["x101"], c["x102"]], FORK_HEIGHT + 1, done)
    # The feeder returns early if the node hangs up.  Give the node the
    # settle period to finish the reorg (or its rollback) before the verdict.
    deadline = time.time() + settle_s
    while not done() and time.time() < deadline:
        time.sleep(0.5)
    tips = {t["hash"]: t["status"] for t in node.rpc.call("getchaintips")}
    return {"best": node.rpc.call("getbestblockhash"), "count": node.rpc.call("getblockcount"),
            "x102_status": tips.get(want), "seen": seen}


# --------------------------------------------------------------------------
# ouroboros
# --------------------------------------------------------------------------


def _real_sync_available() -> bool:
    probe = subprocess.run(
        [sys.executable, "-c", "import sync; sync.PyBlockchainDB"],
        env=dict(os.environ, PYTHONPATH=str(REPO_SRC)), capture_output=True,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _real_sync_available(),
    reason="the compiled Rust `sync` extension is not built; this test runs a real node",
)


@pytest.fixture
def ouroboros_node(tmp_path):
    node = Proc("ouroboros", tmp_path / "ouroboros")
    try:
        yield node
    finally:
        node.close()


def _token(reason) -> str:
    """The BIP-22 token without Core's parenthesised debug message."""
    return str(reason).split(" (", 1)[0]


def test_submitblock_rejects_invalid_script_branch(ouroboros_node):
    c = chain(False)
    out = run_submitblock(ouroboros_node, good=False)
    assert out["best"] == bhash(c["a101"]), (out, ouroboros_node.tail())
    assert out["count"] == FORK_HEIGHT + 1, out
    assert out["x102"] is not None, f"invalid-script X102 accepted: {out}"
    assert _token(out["x102"]) == _token(CORE_X102_BAD_SUBMIT), f"X102 rejected for a non-script reason: {out}"
    tips = {t["hash"]: t["status"] for t in ouroboros_node.rpc.call("getchaintips")}
    assert tips.get(bhash(c["x102"])) != "active", tips


def test_submitblock_accepts_valid_script_branch(ouroboros_node):
    c = chain(True)
    out = run_submitblock(ouroboros_node, good=True)
    assert out["x102"] == CORE_X102_GOOD_SUBMIT, (out, ouroboros_node.tail())
    assert out["best"] == bhash(c["x102"]), out
    assert out["count"] == FORK_HEIGHT + 2, out


def test_p2p_rejects_invalid_script_branch(ouroboros_node):
    c = chain(False)
    out = run_p2p(ouroboros_node, good=False)
    # The instrument: a node that never fetched X102 would also stay on A101.
    assert f"served:{bhash(c['x102'])}" in out["seen"], f"node never fetched X102: {out}"
    assert out["best"] == bhash(c["a101"]), (out, ouroboros_node.tail())
    assert out["count"] == FORK_HEIGHT + 1, out
    assert out["x102_status"] != "active", out


def test_p2p_accepts_valid_script_branch(ouroboros_node):
    c = chain(True)
    out = run_p2p(ouroboros_node, good=True)
    assert f"served:{bhash(c['x102'])}" in out["seen"], f"node never fetched X102: {out}"
    assert out["best"] == bhash(c["x102"]), (out, ouroboros_node.tail())
    assert out["count"] == FORK_HEIGHT + 2, out


# --------------------------------------------------------------------------
# Core oracle (opt-in: OUROBOROS_TEST_BITCOIND=/path/to/bitcoind)
# --------------------------------------------------------------------------

BITCOIND = os.environ.get("OUROBOROS_TEST_BITCOIND") or ""


@pytest.mark.skipif(
    not (BITCOIND and shutil.which(BITCOIND)),
    reason="set OUROBOROS_TEST_BITCOIND to a Bitcoin Core v31.1 bitcoind to re-check the pins",
)
def test_core_oracle_matches_pins(tmp_path):
    results = {}
    for name, fn, good in (
        ("submit-bad", run_submitblock, False),
        ("submit-good", run_submitblock, True),
        ("p2p-bad", run_p2p, False),
        ("p2p-good", run_p2p, True),
    ):
        core = Proc("bitcoind", tmp_path / name, BITCOIND)
        try:
            results[name] = fn(core, good)
        finally:
            core.close()
    bad, good = chain(False), chain(True)
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "seen"} for k, v in results.items()}, indent=1))
    assert results["submit-bad"]["x101"] == CORE_X101_SUBMIT
    assert results["submit-bad"]["x102"] == CORE_X102_BAD_SUBMIT
    assert results["submit-bad"]["best"] == bhash(bad["a101"])
    assert results["submit-good"]["x101"] == CORE_X101_SUBMIT
    assert results["submit-good"]["x102"] == CORE_X102_GOOD_SUBMIT
    assert results["submit-good"]["best"] == bhash(good["x102"])
    assert results["p2p-bad"]["best"] == bhash(bad["a101"])
    assert results["p2p-bad"]["x102_status"] == "invalid"
    assert results["p2p-good"]["best"] == bhash(good["x102"])
