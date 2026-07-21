"""Regression test: ouroboros _recheck_forks CPU spin
(receipts/BUG-ouroboros-recheck-forks-spin-2026-07-20.md).

Asserts the three fix legs, without a full node:
  1. _resolve_active_height MISS is bounded to the reorg window
     (<= MAX_REORG_DEPTH+2 DB reads, not O(tip_height) ~905k).
  2. Memoization: repeat probes and repeat _fork_tip_height walks cost
     ZERO additional DB reads while tip + fork store are unchanged.
  3. _recheck_forks backs off per fork tip (skips tips not yet due),
     yields to the event loop, and discards a never-anchoring fork after
     the attempt cap / TTL instead of re-scanning forever.
  4. Wall-time: a full _recheck_forks tick with an unanchored fork at
     mainnet-scale tip height stays under 50ms (spec asks <10ms/tick for
     the steady state; the FIRST cold tick does the one bounded scan).
"""

from __future__ import annotations

import asyncio
import sys
import time
import types
from unittest.mock import AsyncMock, MagicMock

# Mock the Rust FFI module before any ouroboros import (same pattern as
# ouroboros/tests/test_chainwork_fork_select.py).
if "sync" not in sys.modules:
    _sync = types.ModuleType("sync")
    _sync.PyUTXO = type("PyUTXO", (), {})
    _sync.SyncEngine = type("SyncEngine", (), {})
    _sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    _sync.__file__ = "<test-mock>"
    sys.modules["sync"] = _sync

from ouroboros.block_sync import (  # noqa: E402
    MAX_REORG_DEPTH,
    BlockSync as SyncManager,
)
from ouroboros.p2p_messages import BlockHeader  # noqa: E402

MAINNET_TIP = 905_000  # ~mainnet scale from the bug report


class _CountingDB:
    """DB stub that counts get_block_hash_by_height point reads."""

    def __init__(self, tip_hash: bytes, tip_height: int):
        self._tip = (tip_hash, tip_height)
        self._hash_by_height: dict[int, bytes] = {tip_height: tip_hash}
        self.reads = 0

    def get_best_block(self):
        return self._tip

    def get_chainwork_by_height(self, height: int) -> int:
        return 0

    def get_block_hash_by_height(self, height: int):
        self.reads += 1
        return self._hash_by_height.get(height)


def _hash(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _make_header(prev: bytes) -> BlockHeader:
    return BlockHeader(
        version=2,
        prev_blockhash=prev,
        merkle_root=b"\x00" * 32,
        timestamp=0,
        bits=0x207FFFFF,
        nonce=0,
    )


def _make_sm(tip_height: int = MAINNET_TIP):
    db = _CountingDB(_hash(1), tip_height)
    sm = SyncManager(db=db, validator=MagicMock(), peer_manager=MagicMock())
    peer = MagicMock()
    peer.host, peer.port = "127.0.0.1", 8333
    peer.is_connected.return_value = True
    sm._header_sync_peer = peer
    # Don't exercise the getheaders wire path here.
    sm._maybe_send_fork_getheaders = AsyncMock()
    return sm, db, peer


def _add_unanchored_fork(sm, tip_n: int = 99, prev_n: int = 50) -> bytes:
    fork_tip = _hash(tip_n)
    unknown_prev = _hash(prev_n)  # never on the active chain, never bridged
    sm._fork_headers[fork_tip] = _make_header(unknown_prev)
    sm._fork_header_prev[fork_tip] = unknown_prev
    return fork_tip


# ---------------------------------------------------------------------------
# 1. Bounded scan
# ---------------------------------------------------------------------------

def test_resolve_active_height_miss_is_bounded():
    sm, db, _ = _make_sm()
    assert sm._resolve_active_height(_hash(1234)) is None
    assert db.reads <= MAX_REORG_DEPTH + 2, (
        f"miss scanned {db.reads} heights; pre-fix this was "
        f"{MAINNET_TIP + 1} (full chain)"
    )
    assert db.reads > 0, "expected the bounded fallback scan to run"


def test_resolve_active_height_hit_within_window():
    sm, db, _ = _make_sm()
    anchor = _hash(7)
    db._hash_by_height[MAINNET_TIP - 5] = anchor
    assert sm._resolve_active_height(anchor) == MAINNET_TIP - 5


# ---------------------------------------------------------------------------
# 2. Memoization (negative results included)
# ---------------------------------------------------------------------------

def test_resolve_active_height_miss_is_memoized():
    sm, db, _ = _make_sm()
    probe = _hash(1234)
    sm._resolve_active_height(probe)
    cold = db.reads
    for _ in range(10):
        assert sm._resolve_active_height(probe) is None
    assert db.reads == cold, "repeat misses must not re-scan the DB"


def test_memo_invalidated_on_tip_change():
    sm, db, _ = _make_sm()
    probe = _hash(1234)
    assert sm._resolve_active_height(probe) is None
    # Tip advances and the probe hash becomes the new tip's parent.
    db._hash_by_height[MAINNET_TIP] = probe  # reorged: probe now active
    db._tip = (_hash(2), MAINNET_TIP + 1)
    db._hash_by_height[MAINNET_TIP + 1] = _hash(2)
    assert sm._resolve_active_height(probe) == MAINNET_TIP, (
        "stale negative cache survived a tip change"
    )


def test_fork_tip_height_is_memoized():
    sm, db, _ = _make_sm()
    fork_tip = _add_unanchored_fork(sm)
    assert sm._fork_tip_height(fork_tip) is None
    cold = db.reads
    for _ in range(10):
        assert sm._fork_tip_height(fork_tip) is None
    assert db.reads == cold, "repeat fork-tip walks must be dict lookups"
    # A new bridging edge must invalidate the memo: the missing header
    # _hash(50) arrives, with prev = the active tip _hash(1).  The fork is
    # now tip -> _hash(50) -> _hash(99)=fork_tip, so fork height = tip + 2.
    bridge = _hash(50)
    sm._fork_headers[bridge] = _make_header(_hash(1))
    sm._fork_header_prev[bridge] = _hash(1)
    sm._fork_store_generation += 1  # what _store_fork_header does
    assert sm._fork_tip_height(fork_tip) == MAINNET_TIP + 2


# ---------------------------------------------------------------------------
# 3. _recheck_forks: backoff, yield, discard
# ---------------------------------------------------------------------------

def test_recheck_backs_off_between_ticks():
    sm, db, _ = _make_sm()
    fork_tip = _add_unanchored_fork(sm)
    asyncio.run(sm._recheck_forks())
    assert fork_tip in sm._fork_recheck_state
    first_seen, attempts, next_retry = sm._fork_recheck_state[fork_tip]
    assert attempts == 1
    assert next_retry > time.monotonic(), "a failed tip must get a future retry time"
    reads_after_first = db.reads
    chases = sm._maybe_send_fork_getheaders.await_count
    # Immediate next ticks (the 1s sync_loop cadence) must skip the tip.
    for _ in range(5):
        asyncio.run(sm._recheck_forks())
    assert db.reads == reads_after_first, "backing-off tip was re-evaluated"
    assert sm._maybe_send_fork_getheaders.await_count == chases
    assert sm._fork_recheck_state[fork_tip][1] == 1, "attempts grew during backoff"


def test_recheck_discards_unanchored_after_attempt_cap():
    sm, db, _ = _make_sm()
    fork_tip = _add_unanchored_fork(sm)
    for _ in range(sm._fork_unanchored_max_attempts):
        # Force each backoff window to have elapsed.
        st = sm._fork_recheck_state.get(fork_tip)
        if st is not None:
            sm._fork_recheck_state[fork_tip] = (st[0], st[1], 0.0)
        asyncio.run(sm._recheck_forks())
    assert fork_tip not in sm._fork_headers, (
        "unanchored fork tip must be discarded after the attempt cap"
    )
    assert fork_tip not in sm._fork_recheck_state


def test_recheck_discards_unanchored_after_ttl():
    sm, db, _ = _make_sm()
    fork_tip = _add_unanchored_fork(sm)
    asyncio.run(sm._recheck_forks())
    st = sm._fork_recheck_state[fork_tip]
    # Backdate first_seen past the TTL and make the tip due.
    sm._fork_recheck_state[fork_tip] = (
        st[0] - sm._fork_unanchored_ttl - 1.0, st[1], 0.0
    )
    asyncio.run(sm._recheck_forks())
    assert fork_tip not in sm._fork_headers


def test_recheck_keeps_anchored_but_lighter_fork():
    sm, db, _ = _make_sm()
    # Anchored fork: prev IS on the active chain, but fork is not heavier
    # (same height as tip under the height fallback).
    anchor = _hash(60)
    db._hash_by_height[MAINNET_TIP - 1] = anchor
    fork_tip = _hash(61)
    sm._fork_headers[fork_tip] = _make_header(anchor)
    sm._fork_header_prev[fork_tip] = anchor
    for _ in range(sm._fork_unanchored_max_attempts + 2):
        st = sm._fork_recheck_state.get(fork_tip)
        if st is not None:
            sm._fork_recheck_state[fork_tip] = (st[0], st[1], 0.0)
        asyncio.run(sm._recheck_forks())
    assert fork_tip in sm._fork_headers, (
        "anchored (merely not-heavier) forks must NOT be TTL-discarded"
    )


def test_recheck_yields_to_event_loop():
    """The recheck loop must hit the event loop at least once per tip."""
    sm, db, _ = _make_sm()
    _add_unanchored_fork(sm, 99, 50)
    _add_unanchored_fork(sm, 98, 51)

    ticks = 0

    async def _counter():
        nonlocal ticks
        for _ in range(200):
            ticks += 1
            await asyncio.sleep(0)

    async def _run():
        t = asyncio.ensure_future(_counter())
        await sm._recheck_forks()
        t.cancel()

    asyncio.run(_run())
    assert ticks >= 2, "recheck loop never yielded to concurrent tasks"


# ---------------------------------------------------------------------------
# 4. Wall-time bound at mainnet scale
# ---------------------------------------------------------------------------

def test_recheck_tick_wall_time_bounded():
    sm, db, _ = _make_sm()
    _add_unanchored_fork(sm)
    t0 = time.perf_counter()
    asyncio.run(sm._recheck_forks())          # cold: one bounded scan
    cold_ms = (time.perf_counter() - t0) * 1000
    # Force the tip due again to measure the warm (memoized) path.
    st = sm._fork_recheck_state[list(sm._fork_recheck_state)[0]]
    for k in list(sm._fork_recheck_state):
        sm._fork_recheck_state[k] = (st[0], st[1], 0.0)
    t0 = time.perf_counter()
    asyncio.run(sm._recheck_forks())
    warm_ms = (time.perf_counter() - t0) * 1000
    assert cold_ms < 50, f"cold recheck tick took {cold_ms:.1f}ms"
    assert warm_ms < 10, f"warm recheck tick took {warm_ms:.1f}ms (spec <10ms)"


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
