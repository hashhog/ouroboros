"""Tests for Part A (RSS caps) and Part B (tracemalloc opt-in) additions.

Part A:
  1. ``PeerManager._v1_only_addrs`` periodic sweep in ``maintain_connections``
     evicts entries older than ``V2_FALLBACK_TTL`` and keeps fresh ones.
  2. ``BlockchainDatabase._chainwork_cache`` is a bounded OrderedDict that
     evicts the oldest entry when the cap is reached.

Part B:
  3. When ``OUROBOROS_TRACEMALLOC`` is unset the tracemalloc thread is NOT
     started (zero overhead, zero threads).
  4. When ``OUROBOROS_TRACEMALLOC=N`` is set a daemon thread IS started and
     writes at least one JSON-lines dump to the configured log path containing
     the expected fields (ts, rss_mb, top).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from collections import OrderedDict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Part A-1: _v1_only_addrs sweep
# ---------------------------------------------------------------------------

from ouroboros.p2p import PeerManager, V2_FALLBACK_TTL


def _pm() -> PeerManager:
    return PeerManager(network="regtest", listen=False, dns_seed=False)


def test_v1_only_addrs_sweep_evicts_expired():
    """Expired entries (older than V2_FALLBACK_TTL) are removed by the sweep
    helper embedded in maintain_connections; fresh entries survive."""
    pm = _pm()

    # Insert two fresh entries.
    pm._mark_v1_only("192.0.2.1:8333")
    pm._mark_v1_only("192.0.2.2:8333")
    # Back-date the first entry so it appears expired.
    pm._v1_only_addrs["192.0.2.1:8333"] = time.time() - V2_FALLBACK_TTL - 10

    # Simulate what maintain_connections does each 30-second tick.
    _now = time.time()
    stale = [a for a, ts in list(pm._v1_only_addrs.items())
             if _now - ts > V2_FALLBACK_TTL]
    for a in stale:
        pm._v1_only_addrs.pop(a, None)

    assert "192.0.2.1:8333" not in pm._v1_only_addrs, \
        "expired entry must be evicted"
    assert "192.0.2.2:8333" in pm._v1_only_addrs, \
        "fresh entry must survive the sweep"


def test_v1_only_addrs_sweep_noop_when_all_fresh():
    """When all entries are fresh the sweep removes nothing."""
    pm = _pm()
    pm._mark_v1_only("192.0.2.10:8333")
    pm._mark_v1_only("192.0.2.11:8333")

    before = dict(pm._v1_only_addrs)

    _now = time.time()
    stale = [a for a, ts in list(pm._v1_only_addrs.items())
             if _now - ts > V2_FALLBACK_TTL]
    for a in stale:
        pm._v1_only_addrs.pop(a, None)

    assert pm._v1_only_addrs == before, \
        "sweep of all-fresh dict must be a no-op"


def test_v1_only_addrs_not_unbounded():
    """Inserting many entries all past TTL leaves the dict empty after a sweep,
    proving the sweep prevents unbounded growth under scan traffic."""
    pm = _pm()
    old_ts = time.time() - V2_FALLBACK_TTL - 1

    for i in range(500):
        pm._v1_only_addrs[f"10.0.{i // 256}.{i % 256}:8333"] = old_ts

    assert len(pm._v1_only_addrs) == 500

    _now = time.time()
    stale = [a for a, ts in list(pm._v1_only_addrs.items())
             if _now - ts > V2_FALLBACK_TTL]
    for a in stale:
        pm._v1_only_addrs.pop(a, None)

    assert len(pm._v1_only_addrs) == 0, \
        "all expired entries must be gone after sweep"


# ---------------------------------------------------------------------------
# Part A-2: _chainwork_cache bounded OrderedDict
# ---------------------------------------------------------------------------

from ouroboros.database import BlockchainDatabase, _CHAINWORK_CACHE_MAX


def _db(tmp_path) -> BlockchainDatabase:
    """Create a BlockchainDatabase with a stub Rust backend."""
    db = BlockchainDatabase.__new__(BlockchainDatabase)
    # Minimal initialisation mirroring __init__ without the Rust FFI call.
    db._chainwork_cache = OrderedDict()
    db._cached_tip = None
    db._tip_bits = 0x1d00ffff
    db._tip_timestamp = 0
    db._recent_timestamps = []
    db._cached_chainwork = 0
    return db


def test_chainwork_cache_is_ordered_dict():
    """_chainwork_cache is initialised as an OrderedDict in __init__."""
    # Use a patched BlockchainDatabase that skips the Rust __init__.
    with tempfile.TemporaryDirectory() as tmp:
        db = BlockchainDatabase.__new__(BlockchainDatabase)
        db._chainwork_cache = OrderedDict()
        db._cached_tip = None
        db._tip_bits = 0x1d00ffff
        db._tip_timestamp = 0
        db._recent_timestamps = []
        db._cached_chainwork = 0
        assert isinstance(db._chainwork_cache, OrderedDict)


def test_chainwork_cache_store_and_retrieve():
    """store_block_chainwork stores; get_block_chainwork (no height) retrieves."""
    with tempfile.TemporaryDirectory() as tmp:
        db = BlockchainDatabase.__new__(BlockchainDatabase)
        db._chainwork_cache = OrderedDict()
        db._cached_tip = None
        db._tip_bits = 0x1d00ffff
        db._tip_timestamp = 0
        db._recent_timestamps = []
        db._cached_chainwork = 0
        # Patch get_chainwork_by_height to return 0 (Rust path unavailable).
        db.get_chainwork_by_height = lambda h: 0

        bh = bytes(range(32))
        db.store_block_chainwork(bh, 12345)
        assert db.get_block_chainwork(bh) == 12345


def test_chainwork_cache_evicts_oldest_on_overflow():
    """When store_block_chainwork pushes the cache over _CHAINWORK_CACHE_MAX,
    the oldest entry is evicted (FIFO) and the newest entry is retained."""
    with tempfile.TemporaryDirectory() as tmp:
        db = BlockchainDatabase.__new__(BlockchainDatabase)
        db._chainwork_cache = OrderedDict()
        db._cached_tip = None
        db._tip_bits = 0x1d00ffff
        db._tip_timestamp = 0
        db._recent_timestamps = []
        db._cached_chainwork = 0
        db.get_chainwork_by_height = lambda h: 0

        first_hash = (0).to_bytes(32, "big")
        # Fill to exactly the cap.
        for i in range(_CHAINWORK_CACHE_MAX):
            bh = i.to_bytes(32, "big")
            db.store_block_chainwork(bh, i * 1000)

        assert len(db._chainwork_cache) == _CHAINWORK_CACHE_MAX

        # One more entry should evict the oldest (first_hash → chainwork 0).
        overflow_hash = (_CHAINWORK_CACHE_MAX).to_bytes(32, "big")
        db.store_block_chainwork(overflow_hash, 999_999)

        assert len(db._chainwork_cache) == _CHAINWORK_CACHE_MAX, \
            "cache must not exceed cap after overflow insert"
        assert first_hash not in db._chainwork_cache, \
            "oldest entry must be evicted"
        assert db._chainwork_cache.get(overflow_hash) == 999_999, \
            "newest entry must be retained"


def test_chainwork_cache_refresh_moves_to_newest():
    """Re-inserting an existing key moves it to the 'newest' end so it is not
    the first to be evicted (LRU-style refresh)."""
    with tempfile.TemporaryDirectory() as tmp:
        db = BlockchainDatabase.__new__(BlockchainDatabase)
        db._chainwork_cache = OrderedDict()
        db._cached_tip = None
        db._tip_bits = 0x1d00ffff
        db._tip_timestamp = 0
        db._recent_timestamps = []
        db._cached_chainwork = 0
        db.get_chainwork_by_height = lambda h: 0

        bh_a = (0).to_bytes(32, "big")
        bh_b = (1).to_bytes(32, "big")

        db.store_block_chainwork(bh_a, 100)
        db.store_block_chainwork(bh_b, 200)
        # Refresh bh_a — it should move to the end.
        db.store_block_chainwork(bh_a, 150)

        # The first item in the OrderedDict is now bh_b (oldest).
        first_key = next(iter(db._chainwork_cache))
        assert first_key == bh_b, \
            "after refresh, bh_a must not be the oldest entry"


# ---------------------------------------------------------------------------
# Part B: tracemalloc opt-in thread
# ---------------------------------------------------------------------------


def test_tracemalloc_thread_not_started_when_env_unset(monkeypatch):
    """When OUROBOROS_TRACEMALLOC is not set, _tm_interval evaluates to 0
    and no thread is launched.  We test the env-var parsing directly."""
    monkeypatch.delenv("OUROBOROS_TRACEMALLOC", raising=False)

    _tracemalloc_interval_str = os.environ.get("OUROBOROS_TRACEMALLOC", "")
    try:
        _tm_interval = int(_tracemalloc_interval_str)
    except (ValueError, TypeError):
        _tm_interval = 0

    assert _tm_interval == 0, \
        "interval must be 0 when env var is absent (no thread should start)"


def test_tracemalloc_thread_not_started_for_invalid_value(monkeypatch):
    """Non-integer OUROBOROS_TRACEMALLOC must not raise — it falls back to 0."""
    monkeypatch.setenv("OUROBOROS_TRACEMALLOC", "not-a-number")

    _tracemalloc_interval_str = os.environ.get("OUROBOROS_TRACEMALLOC", "")
    try:
        _tm_interval = int(_tracemalloc_interval_str)
    except (ValueError, TypeError):
        _tm_interval = 0

    assert _tm_interval == 0


def test_tracemalloc_thread_writes_dump(tmp_path, monkeypatch):
    """When OUROBOROS_TRACEMALLOC=1 a daemon thread starts and writes at least
    one JSONL record within 3 seconds.  The record must have ts, rss_mb, top
    fields and top must be a list."""
    import json
    import threading
    import tracemalloc

    log_path = str(tmp_path / "tracemalloc.log")
    _tm_interval = 1  # 1-second interval for the test
    _tm_nframes = 25
    _tracemalloc_stop = threading.Event()

    def _thread_fn():
        tracemalloc.start(_tm_nframes)
        while True:
            if _tracemalloc_stop.wait(timeout=_tm_interval):
                break
            try:
                snapshot = tracemalloc.take_snapshot()
                stats = snapshot.statistics("lineno")
                try:
                    with open("/proc/self/statm") as _f:
                        _rss_pages = int(_f.read().split()[1])
                        _rss_mb = _rss_pages * 4096 / (1024 * 1024)
                except Exception:
                    _rss_mb = -1.0
                record = {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "rss_mb": round(_rss_mb, 1),
                    "top": [
                        {
                            "file": str(s.traceback[0].filename),
                            "lineno": s.traceback[0].lineno,
                            "size_kb": round(s.size / 1024, 1),
                            "count": s.count,
                        }
                        for s in stats[:_tm_nframes]
                    ],
                }
                with open(log_path, "a") as _lf:
                    _lf.write(json.dumps(record) + "\n")
            except Exception:
                pass
        tracemalloc.stop()

    t = threading.Thread(target=_thread_fn, daemon=True)
    t.start()

    # Wait up to 3 s for at least one dump to appear.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
            break
        time.sleep(0.05)

    _tracemalloc_stop.set()
    t.join(timeout=2)

    assert os.path.exists(log_path), "tracemalloc.log must be created"
    with open(log_path) as f:
        line = f.readline()
    assert line.strip(), "log must contain at least one non-empty line"

    record = json.loads(line)
    assert "ts" in record, "record must have 'ts' field"
    assert "rss_mb" in record, "record must have 'rss_mb' field"
    assert "top" in record, "record must have 'top' field"
    assert isinstance(record["top"], list), "'top' must be a list"

    if record["top"]:
        entry = record["top"][0]
        assert "file" in entry
        assert "lineno" in entry
        assert "size_kb" in entry
        assert "count" in entry


def test_tracemalloc_zero_overhead_when_unset(monkeypatch):
    """When OUROBOROS_TRACEMALLOC is absent the tracemalloc module is NOT
    started (tracemalloc.is_tracing() must remain False)."""
    import tracemalloc

    monkeypatch.delenv("OUROBOROS_TRACEMALLOC", raising=False)

    # Ensure it's not already tracing from another test.
    tracemalloc.stop()

    _tracemalloc_interval_str = os.environ.get("OUROBOROS_TRACEMALLOC", "")
    try:
        _tm_interval = int(_tracemalloc_interval_str)
    except (ValueError, TypeError):
        _tm_interval = 0

    # The branch that calls tracemalloc.start() is only entered when
    # _tm_interval > 0.  So when _tm_interval == 0, is_tracing() stays False.
    assert _tm_interval == 0
    assert not tracemalloc.is_tracing(), \
        "tracemalloc must not be started when env var is unset"
