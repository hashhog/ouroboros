"""Regression tests for the ``PeerManager.known_addrs`` FIFO cap (2026-06-02).

``known_addrs`` is a parallel record of every host:port ever gossiped.
addrman itself is bucket-bounded, but this set had no cap and grew even when
addrman dedupes/rejects an address (the ``.add()`` sites sit OUTSIDE the
``addrman.add()`` guard) — a slow contributor to the at-tip RSS climb.

The fix routes all insert sites through ``_add_known_addr``, which caps the
set at ``KNOWN_ADDRS_MAX_ENTRIES`` via a companion insertion-order deque,
evicting the oldest still-resident entry when full.  Membership / discard /
set-difference semantics at the read sites are unchanged.
"""

from __future__ import annotations

from ouroboros.p2p import PeerManager


def _pm() -> PeerManager:
    return PeerManager(network="regtest", listen=False, dns_seed=False)


def test_add_known_addr_is_bounded_fifo(monkeypatch):
    """Repeated inserts past the cap keep the set at the cap and evict oldest
    first (FIFO)."""
    pm = _pm()
    # Shrink the cap for a fast test.
    monkeypatch.setattr("ouroboros.p2p.KNOWN_ADDRS_MAX_ENTRIES", 100)

    for i in range(500):
        pm._add_known_addr(f"10.0.0.{i}:8333")

    assert len(pm.known_addrs) == 100
    # The oldest 400 were evicted; the newest 100 remain.
    assert "10.0.0.0:8333" not in pm.known_addrs
    assert "10.0.0.499:8333" in pm.known_addrs
    assert "10.0.0.400:8333" in pm.known_addrs


def test_add_known_addr_is_idempotent():
    """Re-adding an existing addr does not grow the set or the order deque."""
    pm = _pm()
    pm._add_known_addr("10.0.0.1:8333")
    pm._add_known_addr("10.0.0.1:8333")
    pm._add_known_addr("10.0.0.1:8333")
    assert len(pm.known_addrs) == 1
    assert len(pm._known_addrs_order) == 1


def test_discard_then_evict_skips_stale_order_entry():
    """An addr discarded out-of-band (ban / connect-failure) leaves a stale
    order entry; the FIFO eviction must tolerate it and not under-count."""
    pm = _pm()
    pm._add_known_addr("10.0.0.1:8333")
    pm._add_known_addr("10.0.0.2:8333")
    # Out-of-band removal (mirrors ban / connect-failure .discard sites).
    pm.known_addrs.discard("10.0.0.1:8333")
    assert len(pm.known_addrs) == 1
    # Adding more must still work and not raise on the stale order entry.
    for i in range(3, 10):
        pm._add_known_addr(f"10.0.0.{i}:8333")
    assert "10.0.0.2:8333" in pm.known_addrs
    assert len(pm.known_addrs) == 8  # addr2 + 7 new
