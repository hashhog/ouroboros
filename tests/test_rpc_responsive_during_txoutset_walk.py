"""RPC liveness while a whole-UTXO-set walk runs (freeze gate 3a, OU-1).

docs/FREEZE-READINESS-2026-10-08.md marks ouroboros red on "GIL held across
the walk".  ``gettxoutsetinfo`` hashes in Rust with the GIL released;
``dumptxoutset`` streams the set through ``visit_utxo_txid_groups``, which
calls back into Python once per txid group.  Either way the asyncio event
loop (which serves getblockcount / getpeerinfo / stop) must keep turning.

Instrument: a heartbeat coroutine on the event loop records the worst gap
between ticks while the walk runs, and a real ``rpc_getblockcount`` is
awaited every tick.  Negative control: ``test_probe_detects_a_stall`` holds
the GIL on a worker for 1 s and asserts the probe sees it.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from types import SimpleNamespace

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

#: Longest tolerated gap between two event-loop ticks during a walk.
MAX_LOOP_STALL_S = 0.25
import os
N_COINS = int(os.environ.get("TXOUTSET_PROBE_COINS", "1500000"))


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _seed(db, n: int) -> None:
    raw = db._db
    for i in range(n):
        txid = hashlib.sha256(i.to_bytes(8, "little")).digest()
        spk = b"\x76\xa9\x14" + txid[:20] + b"\x88\xac"
        raw.add_utxo_raw(txid, 0, 1000 + i, spk, 1 + i % 500, False)
    db.update_best_block(b"\x22" * 32, 500)


def _server(db, tmp_path):
    from ouroboros.rpc import RPCServer
    from ouroboros.snapshot import SnapshotManager

    node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=db)
    node.snapshot_manager = SnapshotManager(db, "regtest", str(tmp_path / "sm"))
    srv = RPCServer.__new__(RPCServer)
    srv.node = node
    srv.block_submission_paused = False
    srv._current_wallet_name = None
    return srv


async def _measure(srv, walk) -> tuple[float, float, int]:
    """Run ``walk()`` while probing the loop; return (max_gap, max_rpc, ticks)."""
    done = asyncio.Event()
    stats = {"gap": 0.0, "rpc": 0.0, "ticks": 0}

    async def probe():
        last = time.monotonic()
        while not done.is_set():
            await asyncio.sleep(0.005)
            now = time.monotonic()
            stats["gap"] = max(stats["gap"], now - last)
            t0 = time.monotonic()
            await srv.rpc_getblockcount()
            stats["rpc"] = max(stats["rpc"], time.monotonic() - t0)
            stats["ticks"] += 1
            last = time.monotonic()

    p = asyncio.create_task(probe())
    await asyncio.sleep(0.05)
    try:
        await walk()
    finally:
        done.set()
        await p
    return stats["gap"], stats["rpc"], stats["ticks"]


@pytest.fixture
def seeded(tmp_path):
    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase(str(tmp_path / "db"))
    _seed(db, N_COINS)
    return db, _server(db, tmp_path)


@pytest.mark.asyncio
async def test_probe_detects_a_stall(seeded) -> None:
    """Negative control: a GIL-holding worker must trip the instrument."""
    _, srv = seeded

    def hog():
        # A single C call never reaches the eval loop, so the GIL is held
        # throughout (a pure-Python spin would yield every 5 ms).
        end = time.monotonic() + 1.0
        while time.monotonic() < end:
            sum(range(2_000_000))

    gap, _, _ = await _measure(srv, lambda: asyncio.to_thread(hog))
    assert gap > 0.02, f"probe missed a GIL hog (gap={gap:.3f}s)"


@pytest.mark.asyncio
async def test_getblockcount_responsive_during_gettxoutsetinfo(seeded) -> None:
    _, srv = seeded
    gap, rpc, ticks = await _measure(srv, srv.rpc_gettxoutsetinfo)
    print(f"gettxoutsetinfo: max loop gap {gap*1000:.0f}ms, max getblockcount "
          f"{rpc*1000:.0f}ms, ticks {ticks}")
    assert ticks > 3
    assert gap < MAX_LOOP_STALL_S and rpc < MAX_LOOP_STALL_S


@pytest.mark.asyncio
async def test_getblockcount_responsive_during_dumptxoutset(seeded, tmp_path) -> None:
    _, srv = seeded
    out = str(tmp_path / "utxo.dat")
    gap, rpc, ticks = await _measure(srv, lambda: srv.rpc_dumptxoutset(out))
    print(f"dumptxoutset: max loop gap {gap*1000:.0f}ms, max getblockcount "
          f"{rpc*1000:.0f}ms, ticks {ticks}")
    assert ticks > 3, "dump finished before the probe could observe it"
    assert gap < MAX_LOOP_STALL_S and rpc < MAX_LOOP_STALL_S
