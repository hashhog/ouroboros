"""Unit tests for plan-W96 PendingBlockStore.

The store backs the disk-on-receipt block buffer — it replaces
`block_sync.BlockSync._ibd_block_buffer` (a RAM dict with a 1024-slot
cap and a full→drop policy that caused the wedge mode in
`project_w85_ouroboros_route_to_rust_regression.md` and
`project_ouroboros_hard_wedge_post_w85.md`).

These tests pin:

- save/load/has/delete round-trips,
- idempotence on duplicate save and missing delete,
- atomic write semantics (no partial file visible on load),
- crash-recovery (construct a fresh store against an existing dir and
  see prior saves),
- gc() keeps-set semantics (prune reorg leftovers),
- the out-of-order-arrival pattern that W96 exists to solve: saves
  happen in shuffled order but a drain walking the canonical chain
  order finds each block exactly when its parent would be ready.
"""

from __future__ import annotations

import os
import random
import tempfile

from ouroboros.database import PendingBlockStore


def _fake_raw(seed: int, size: int = 512) -> bytes:
    """Deterministic fake block payload — distinct per seed so tests
    assert byte-for-byte round-trip fidelity."""
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def _fake_hash(seed: int) -> bytes:
    return seed.to_bytes(32, "big")


def test_save_load_has_round_trip():
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        h = _fake_hash(1)
        raw = _fake_raw(1)
        assert not s.has(h)
        assert s.load(h) is None
        s.save(h, raw)
        assert s.has(h)
        assert s.load(h) == raw


def test_save_is_idempotent_on_duplicate_hash():
    """Re-saving the same hash must not error or duplicate-write.
    Covers the re-delivery-from-rotated-peer case."""
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        h = _fake_hash(7)
        s.save(h, _fake_raw(7))
        # Second save (with different bytes, simulating a malicious peer
        # re-sending garbage for the same hash) must not overwrite —
        # the first-write-wins semantic is how we stay crash-safe.
        s.save(h, b"\xff" * 64)
        assert s.load(h) == _fake_raw(7)


def test_delete_is_idempotent_on_missing_hash():
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        s.delete(_fake_hash(999))  # never saved — must not raise
        assert not s.has(_fake_hash(999))


def test_delete_after_save_clears_both_disk_and_index():
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        h = _fake_hash(2)
        s.save(h, _fake_raw(2))
        s.delete(h)
        assert not s.has(h)
        assert s.load(h) is None
        # Directory must be empty (no .blk nor .tmp leftovers).
        assert os.listdir(os.path.join(d, "pending_blocks")) == []


def test_recovery_rebuilds_index_from_directory():
    """Crash scenario: store was populated, process died before delete,
    fresh process starts and constructs a new store.  The in-memory
    set must be rebuilt from on-disk .blk files so has() is honest
    and drain can find the recovered blocks."""
    with tempfile.TemporaryDirectory() as d:
        s1 = PendingBlockStore(d)
        h1, h2 = _fake_hash(10), _fake_hash(11)
        s1.save(h1, _fake_raw(10))
        s1.save(h2, _fake_raw(11))

        s2 = PendingBlockStore(d)
        assert s2.has(h1)
        assert s2.has(h2)
        assert s2.load(h1) == _fake_raw(10)
        assert s2.load(h2) == _fake_raw(11)
        assert len(s2) == 2


def test_recovery_ignores_junk_files():
    """Startup scan must tolerate stray files (leftover .tmp from a
    crashed atomic-write, operator-dropped notes, other tools) without
    blowing up or mis-registering them as blocks."""
    with tempfile.TemporaryDirectory() as d:
        pending = os.path.join(d, "pending_blocks")
        os.makedirs(pending)
        # Junk files we must tolerate:
        with open(os.path.join(pending, "README"), "w") as f:
            f.write("not a block")
        with open(os.path.join(pending, "abc.tmp"), "wb") as f:
            f.write(b"partial write aborted")
        with open(os.path.join(pending, "nothex.blk"), "wb") as f:
            f.write(b"")
        with open(os.path.join(pending, "ab.blk"), "wb") as f:
            # valid hex but not 32 bytes
            f.write(b"")

        s = PendingBlockStore(d)
        assert len(s) == 0


def test_gc_prunes_hashes_not_in_keep_set():
    """After a reorg, pending blocks on the abandoned branch are no
    longer in the validated header queue.  gc() drops them."""
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        hashes = [_fake_hash(i) for i in range(5)]
        for i, h in enumerate(hashes):
            s.save(h, _fake_raw(i))
        keep = {hashes[0], hashes[2]}
        removed = s.gc(keep)
        assert removed == 3
        assert s.has(hashes[0])
        assert not s.has(hashes[1])
        assert s.has(hashes[2])
        assert not s.has(hashes[3])
        assert not s.has(hashes[4])
        assert len(s) == 2


def test_out_of_order_arrival_drains_in_chain_order():
    """The wedge-pattern regression test.

    Scenario: 100 blocks arrive in shuffled order (typical IBD).  A
    drain walking the canonical chain order (0, 1, 2, …) must find
    each block at exactly the point it's ready to be connected.  The
    store's guarantee is that save() in arbitrary order does not
    impact whether load() finds a block whose slot has been reached.
    """
    N = 100
    chain_hashes = [_fake_hash(i) for i in range(N)]
    chain_raws = [_fake_raw(i) for i in range(N)]

    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)

        # Shuffle arrival order — what the peer network does in practice.
        arrival_order = list(range(N))
        random.Random(42).shuffle(arrival_order)
        for idx in arrival_order:
            s.save(chain_hashes[idx], chain_raws[idx])

        # Drain in chain order.  Every canonical slot must resolve with
        # the correct payload; the drain completes all N steps without
        # ever finding a missing block (because the full set was saved
        # before drain started — mirroring the pathological "buffer
        # fills up, tip+1 still missing" state that pre-W96 code
        # wedged on).
        drained: list[bytes] = []
        for i in range(N):
            assert s.has(chain_hashes[i]), f"chain slot {i} missing after full save"
            raw = s.load(chain_hashes[i])
            assert raw == chain_raws[i], f"payload mismatch at chain slot {i}"
            drained.append(raw)
            s.delete(chain_hashes[i])

        assert drained == chain_raws
        assert len(s) == 0


def test_load_handles_external_unlink_gracefully():
    """Defensive: if the file is yanked out from under us between the
    has()/load() pair (manual cleanup, aggressive fs scrubber), load()
    must return None rather than raising FileNotFoundError into the
    drain loop."""
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        h = _fake_hash(42)
        s.save(h, _fake_raw(42))
        # External unlink (not via store.delete()).
        os.unlink(os.path.join(d, "pending_blocks", h.hex() + ".blk"))
        # In-memory set still says yes, but load() must notice the drift
        # and self-correct.
        assert s.load(h) is None
        assert not s.has(h)


def test_atomic_write_leaves_no_tmp_on_success():
    """Successful save() must clean up the tmp file via rename.  A
    leftover .tmp would accumulate over time and confuse the recovery
    scan (see test_recovery_ignores_junk_files)."""
    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        s.save(_fake_hash(1), _fake_raw(1))
        files = os.listdir(os.path.join(d, "pending_blocks"))
        assert all(not f.endswith(".tmp") for f in files), files


def test_concurrent_save_of_same_hash_does_not_race_rename():
    """Two threads calling save() on the same block_hash must both
    return cleanly.  Pre-fix: both entered past the has() guard, both
    wrote to a shared ``<hash>.blk.tmp`` path, first rename won,
    second rename raised FileNotFoundError — handle_block then dropped
    the block and the scheduler re-requested it.  Observed live on
    mainnet 2026-04-23 minutes after the plan-W98 deploy.  The fix
    makes the tmp name per-thread so concurrent saves can't collide."""
    import threading

    with tempfile.TemporaryDirectory() as d:
        s = PendingBlockStore(d)
        h = _fake_hash(42)
        raw = _fake_raw(42)

        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def save_once():
            try:
                barrier.wait()
                s.save(h, raw)
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=save_once) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"concurrent save raised: {errors}"
        assert s.has(h)
        assert s.load(h) == raw
        files = os.listdir(os.path.join(d, "pending_blocks"))
        assert all(not f.endswith(".tmp") and ".tmp." not in f for f in files), (
            f"stale tmp files left behind: {files}"
        )
