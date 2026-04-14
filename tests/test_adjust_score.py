"""Regression tests for Peer.adjust_score → BanManager wiring.

Background: prior to wave3-2026-04-14 the Peer.adjust_score() clamp at
score == 0 was log-only; the peer was never disconnected and never
recorded with the BanManager.  See OUROBOROS-PEER-TIMEOUT-DIAG.md.

These tests verify:
  1. Repeated adjust_score(-N) eventually crosses the clamp and triggers
     exactly one ban (the latch protects against the spammy re-entry the
     diag observed: one peer "banned" 537x in 43 minutes).
  2. The peer's host lands in BanManager.banned after the threshold.
  3. The on_ban callback wired into BanManager fires exactly once for
     that peer (mirrors PeerManager._on_peer_banned scheduling
     peer.disconnect()).
  4. When no BanManager is supplied the legacy log-only behaviour is
     preserved (so unit tests that build a bare Peer don't crash).
"""

from __future__ import annotations

from ouroboros.banman import BanManager
from ouroboros.peer import Peer


def _make_peer_with_banman(host: str = "203.0.113.42",
                            port: int = 8333) -> tuple[Peer, BanManager, list[str]]:
    """Construct a Peer wired to a fresh BanManager that records callbacks."""
    fired: list[str] = []
    bm = BanManager(
        ban_threshold=100,
        ban_duration=3600,
        on_ban=lambda ip: fired.append(ip),
    )
    peer = Peer(host, port, network="mainnet", ban_manager=bm)
    return peer, bm, fired


def test_adjust_score_clamps_and_bans_after_threshold():
    """N stall penalties (-1 each) eventually clamp to 0 and ban the host."""
    peer, bm, fired = _make_peer_with_banman()

    # Score starts at 100; each -1 reduces it.  Only the call that
    # actually crosses to 0 should trigger the ban.
    for _ in range(99):
        peer.adjust_score(-1)
        assert peer.score > 0
        assert peer.host not in bm.banned
        assert fired == []

    # The 100th -1 lands at zero and must trigger the ban.
    peer.adjust_score(-1)
    assert peer.score == 0
    assert peer.host in bm.banned, "host must be in BanManager.banned set"
    assert fired == [peer.host], "on_ban callback must fire exactly once"


def test_adjust_score_repeated_calls_at_zero_do_not_re_ban():
    """Latch: once banned, further adjust_score calls must not re-fire."""
    peer, bm, fired = _make_peer_with_banman()

    # Drop straight to 0 with one big penalty.
    peer.adjust_score(-100)
    assert peer.score == 0
    assert fired == [peer.host]

    # Hammer adjust_score the way block_sync._handle_timeouts does — every
    # cycle the same peer would be penalised again.  Pre-fix, this caused
    # 537 "banned" log lines for a single peer; post-fix the latch
    # suppresses repeat ban records.
    for _ in range(50):
        peer.adjust_score(-1)

    assert fired == [peer.host], (
        f"on_ban must fire exactly once per Peer (got {len(fired)} fires)"
    )
    # And the ban entry should still be present (not removed by the
    # repeated calls).
    assert peer.host in bm.banned


def test_adjust_score_without_ban_manager_is_log_only():
    """Bare Peer (no ban_manager) preserves the original observable shape."""
    peer = Peer("198.51.100.7", 8333, network="mainnet")
    # Should not raise even though there's no manager wired in.
    peer.adjust_score(-100)
    assert peer.score == 0
    # The latch still flips so we don't keep emitting WARNINGs forever.
    assert peer._ban_recorded is True


def test_adjust_score_positive_delta_does_not_trigger_ban():
    """Sanity: positive deltas don't accidentally reach the clamp."""
    peer, bm, fired = _make_peer_with_banman()
    peer.adjust_score(+5)
    assert peer.score == 100  # already at ceiling
    assert fired == []
    assert peer.host not in bm.banned
