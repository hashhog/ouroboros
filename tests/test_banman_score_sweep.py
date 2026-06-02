"""Regression tests for the banman score-table leak fix (2026-06-02).

``BanManager.scores`` accreted one ``MisbehaviorRecord`` per unique
below-threshold misbehaving IP, and each record's ``events`` list grew one
string per event — with NO expiry path and NO periodic caller for
``sweep_expired`` (which only pruned ``banned``).  Under inbound churn from
peers that reconnect under new ephemeral ports this was a slow unbounded leak.

The fix:
  - ``sweep_expired`` now also drops score records whose ``last_event`` is
    older than ``SCORE_RECORD_TTL`` (its ban-pruning contract is unchanged —
    it still returns the number of *bans* removed),
  - ``record_misbehavior`` caps each record's ``events`` ring at
    ``SCORE_EVENTS_MAX``,
  - the PeerManager maintenance loop now calls ``sweep_expired`` (wired
    separately; see ``maintain_connections``).
"""

from __future__ import annotations

import time

from ouroboros.banman import (
    SCORE_EVENTS_MAX,
    SCORE_RECORD_TTL,
    BanManager,
)


def _bm() -> BanManager:
    # No data_dir → no disk persistence (pure in-memory unit test).
    return BanManager()


def test_events_ring_is_capped():
    """A single IP emitting many below-threshold events keeps only the most
    recent SCORE_EVENTS_MAX reason strings, not an unbounded list."""
    bm = _bm()
    ip = "10.1.0.1"
    for i in range(SCORE_EVENTS_MAX * 3):
        # score=1 (orphan-tx severity) stays well below the ban threshold so
        # the record survives and its events list keeps growing.
        bm.record_misbehavior(ip, 1, f"event-{i}")
    rec = bm.scores[ip]
    assert len(rec.events) == SCORE_EVENTS_MAX
    # The ring retains the LATEST events.
    assert rec.events[-1] == f"event-{SCORE_EVENTS_MAX * 3 - 1}"


def test_sweep_drops_stale_score_records():
    """A below-threshold score record idle longer than SCORE_RECORD_TTL is
    reclaimed by sweep_expired; a fresh one is retained."""
    bm = _bm()
    bm.record_misbehavior("10.1.0.2", 1, "old")
    bm.record_misbehavior("10.1.0.3", 1, "fresh")
    assert len(bm.scores) == 2

    # Age the first record's last_event past the TTL.
    bm.scores["10.1.0.2"].last_event = time.time() - SCORE_RECORD_TTL - 1

    removed_bans = bm.sweep_expired()
    # Return value is the number of BANS removed (none here) — contract intact.
    assert removed_bans == 0
    assert "10.1.0.2" not in bm.scores   # stale record reclaimed
    assert "10.1.0.3" in bm.scores       # fresh record retained


def test_sweep_still_prunes_expired_bans_and_returns_count():
    """The original sweep_expired contract is preserved: expired bans are
    dropped and their count is returned."""
    bm = _bm()
    bm.ban("10.1.0.4", duration=10_000)   # active
    bm.banned["10.1.0.5"] = time.time() - 1  # already expired

    removed = bm.sweep_expired()
    assert removed == 1
    assert "10.1.0.5" not in bm.banned
    assert "10.1.0.4" in bm.banned


def test_sweep_keeps_recent_score_records():
    """sweep_expired must not drop a recently-active score record (no
    over-eager reclaim of live state)."""
    bm = _bm()
    bm.record_misbehavior("10.1.0.6", 5, "recent")
    bm.sweep_expired()
    assert "10.1.0.6" in bm.scores
