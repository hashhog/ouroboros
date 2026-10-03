"""gettxoutsetinfo must be one RocksDB snapshot, walked off the GIL.

Bitcoin Core opens a coins-DB cursor (a snapshot), labels the reply with
that cursor's best block, and does not hold cs_main across the scan
(rpc/blockchain.cpp gettxoutsetinfo, kernel/coinstats.cpp ComputeUTXOStats).

Before the fix, ouroboros sampled ``get_best_block`` and then iterated the
live chainstate on a worker that held the GIL for the whole Rust walk
(``visit_utxo_txid_groups`` calls back into Python per txid group). A
commit landing in that window was hashed into the set but the reply still
carried the earlier tip.

Control: this file. Without ``sync.arm_utxo_stats_walk_gate`` the tear
below fails. With the gate, a commit while the walk is paused must not
change height, bestblock, txouts, or hash_serialized_3, and the pausing
thread must be able to run Python (the GIL is released).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from ouroboros.database import BlockchainDatabase
from ouroboros.rpc import RPCServer
from ouroboros.snapshot import compute_utxo_hash
from tests._real_sync import real_sync_installed, real_sync_or_skip

# conftest.py installs a stub under the name ``sync``. The tear and the
# gate both need the compiled extension (RocksDB + the walk).
_REAL_SYNC = real_sync_or_skip()


def _p2pkh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def _make_rpc(db: BlockchainDatabase) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    node.network = "regtest"
    rpc.node = node
    rpc._current_wallet_name = None
    rpc.block_submission_paused = False
    return rpc


def _seed(db: BlockchainDatabase) -> tuple[bytes, int]:
    tip = b"\x11" * 32
    db._db.add_utxo_raw(b"\xaa" * 32, 0, 50_000_000, _p2pkh(b"\x01" * 20), 1, True)
    db._db.add_utxo_raw(b"\xbb" * 32, 1, 25_000_000, _p2pkh(b"\x02" * 20), 1, False)
    db.update_best_block(tip, 1)
    return tip, 1


async def _tear_tip_window(db: BlockchainDatabase, rpc: RPCServer) -> dict:
    """Commit a coin after the tip read and before the cursor opens.

    The handler reads ``get_best_block`` once, then walks. Patching that
    read to commit first reproduces the window without a sleep.
    """
    original = db.get_best_block
    tip, height = original()

    def patched():
        db.get_best_block = original
        db._db.add_utxo_raw(b"\xee" * 32, 0, 9, _p2pkh(b"\x09" * 20), height + 1, False)
        db.update_best_block(bytes(range(32)), height + 1)
        # Report the tip from BEFORE the commit. update_best_block stored
        # the new one in the Python cache; put the old one back so the
        # value this call returns is the pre-commit tip.
        db._cached_tip = (tip, height)
        return tip, height

    db.get_best_block = patched
    return await rpc.rpc_gettxoutsetinfo()


@pytest.mark.asyncio
async def test_gettxoutsetinfo_snapshot_consistent_and_off_gil(tmp_path) -> None:
    sync = _REAL_SYNC
    with real_sync_installed(sync):
        await _run(tmp_path, sync)


async def _run(tmp_path, sync) -> None:
    db = BlockchainDatabase(str(tmp_path / "chain"))
    _seed(db)
    rpc = _make_rpc(db)

    if not hasattr(sync, "arm_utxo_stats_walk_gate"):
        torn = await _tear_tip_window(db, rpc)
        assert torn["height"] == 1 and torn["txouts"] == 2, (
            f"TORN walk: height={torn['height']} txouts={torn['txouts']} "
            f"transactions={torn['transactions']} bestblock={torn['bestblock']} "
            "— tip was sampled before the live cursor, so a commit in between "
            "is inside the hashed set but not in the label. The Rust walk "
            "also holds the GIL (no snapshot gate)."
        )
        pytest.fail("walk has no snapshot gate and holds the GIL")

    quiet = await rpc.rpc_gettxoutsetinfo()
    assert quiet["height"] == 1
    assert quiet["txouts"] == 2
    assert quiet["transactions"] == 2
    assert quiet["bestblock"] == (b"\x11" * 32)[::-1].hex()
    assert quiet["hash_serialized_3"] == compute_utxo_hash(db, "hash_serialized")[::-1].hex()
    mu = await rpc.rpc_gettxoutsetinfo(hash_type="muhash")
    assert mu["muhash"] == compute_utxo_hash(db, "muhash")[::-1].hex()
    assert "hash_serialized_3" not in mu
    none = await rpc.rpc_gettxoutsetinfo(hash_type="none")
    assert "hash_serialized_3" not in none and "muhash" not in none
    assert none["txouts"] == 2

    sync.arm_utxo_stats_walk_gate()
    task = asyncio.create_task(rpc.rpc_gettxoutsetinfo())
    try:
        deadline = time.monotonic() + 15.0
        phase = 0
        while True:
            phase = sync.utxo_stats_walk_phase()
            if phase == 1:
                break
            if phase == 3 or time.monotonic() > deadline:
                pytest.fail(f"walk never paused with the GIL released (phase={phase})")
            await asyncio.sleep(0.005)

        # Python bytecode here requires the GIL. Reaching this line while
        # the walk is inside its pause means the scan is not holding it.
        db._db.add_utxo_raw(b"\xee" * 32, 0, 9, _p2pkh(b"\x09" * 20), 2, False)
        new_tip = bytes(range(32))
        db.update_best_block(new_tip, 2)
        sync.release_utxo_stats_walk_gate()
        mid = await task
    finally:
        sync.release_utxo_stats_walk_gate()
        if not task.done():
            await asyncio.wait_for(task, timeout=12)

    assert mid["height"] == quiet["height"]
    assert mid["bestblock"] == quiet["bestblock"]
    assert mid["txouts"] == quiet["txouts"]
    assert mid["transactions"] == quiet["transactions"]
    assert mid["bogosize"] == quiet["bogosize"]
    assert mid["hash_serialized_3"] == quiet["hash_serialized_3"]
    assert mid["total_amount"].text == quiet["total_amount"].text

    after = await rpc.rpc_gettxoutsetinfo()
    assert after["height"] == 2
    assert after["txouts"] == 3
    assert after["transactions"] == 3
    assert after["bestblock"] == new_tip[::-1].hex()
    assert after["hash_serialized_3"] != quiet["hash_serialized_3"]
