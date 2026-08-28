"""Every ban must be attributable (2026-08-28, task #77B).

During a live ouroboros stall the node emitted 413 `Banned <ip> for 86400 s`
lines in three hours and NOT ONE could be attributed to a cause: the
misbehaviour that triggers a ban was logged at DEBUG (invisible at the
daemons' INFO level) while `ban()` logged at WARNING without the reason.
755 bans accumulated, each lasting 24h and persisted to disk — a slow-acting
eclipse risk that an operator had no way to diagnose.

These pin the fix: the reason travels INTO ban() and reaches the WARNING log.
"""
import logging

from ouroboros.banman import BanManager


def test_ban_logs_the_reason_at_warning(caplog):
    bm = BanManager()
    with caplog.at_level(logging.WARNING, logger="ouroboros.banman"):
        bm.ban("203.0.113.7", reason="sent an invalid header")
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
    assert warnings, "ban() must emit a WARNING"
    assert any("sent an invalid header" in m for m in warnings), (
        "the ban WARNING must carry the reason — without it an operator sees "
        f"only that a ban happened, never why. Got: {warnings}")


def test_misbehaviour_ban_propagates_its_trigger(caplog):
    """A threshold-tripping misbehaviour must name itself in the ban line."""
    bm = BanManager()
    big = max(bm.DISCOURAGEMENT_THRESHOLD, bm.ban_threshold)
    with caplog.at_level(logging.WARNING, logger="ouroboros.banman"):
        banned = bm.misbehaving("203.0.113.9", big, "bogus merkle root")
    assert banned, "a score at/above the threshold must ban"
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
    assert any("bogus merkle root" in m for m in warnings), (
        "record_misbehavior logs the reason at DEBUG only; the ban itself must "
        f"surface it at WARNING or the ban is unattributable. Got: {warnings}")


def test_reasonless_ban_is_marked_as_such(caplog):
    """A caller that supplies no reason must be visible, not silently blank."""
    bm = BanManager()
    with caplog.at_level(logging.WARNING, logger="ouroboros.banman"):
        bm.ban("203.0.113.11")
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
    assert any("no reason supplied" in m for m in warnings), (
        "an un-attributed ban must say so explicitly, so the gap is visible "
        f"in the log rather than inferred from absence. Got: {warnings}")
