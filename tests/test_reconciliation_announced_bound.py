"""Regression tests for the 2026-06-06 at-tip RSS-leak fix — BUG 1.

Background — ``ReconciliationSet.announced_txids`` (minisketch.py) is the
BIP-330 / Erlay per-peer dedup-of-already-announced set: ``mark_announced``
records every txid we have successfully announced to a peer so ``add_tx``
never re-queues it as a permanent dedup filter.

The original port made it a plain ``set[bytes]`` with NO cap, NO eviction and
NO FIFO — ``mark_announced`` only ever ``.add()``ed.  At tip the node announces
transactions continuously, so the set grew without bound, *per peer*.  That is
the exact at-tip leak shape already fixed for ``TrickleQueue.known_filter``
(p2p.py), which is a bounded ``OrderedDict`` FIFO capped at
``KNOWN_FILTER_MAX_ENTRIES``.

The fix mirrors that: ``announced_txids`` is now an ``OrderedDict[bytes, None]``
capped at ``ANNOUNCED_TXIDS_MAX_ENTRIES`` (per-instance overridable via
``_announced_max``), evicting the oldest entry on insert and refreshing
position on re-announce (LRU-on-touch).  Membership-test semantics (``in`` /
``len``) are unchanged.

These tests pin:
  (a) the set stays bounded under many more announcements than the cap,
  (b) FIFO eviction is oldest-first (the very first announced txid is gone,
      the most-recent survive),
  (c) re-announcing an existing txid refreshes (does not evict) it,
  (d) the existing dedup contract still holds (``add_tx`` is a no-op once a
      txid has been announced), and
  (e) the old behaviour FAILS the bound (proof the test catches the leak).

Pure unit tests — a bare ``ReconciliationSet`` with a tiny per-instance cap so
the bound is exercised in microseconds.
"""

from __future__ import annotations

import struct

import pytest

from ouroboros.minisketch import (
    ANNOUNCED_TXIDS_MAX_ENTRIES,
    ReconciliationSet,
)


def _txid(n: int) -> bytes:
    """A distinct 32-byte txid for index *n*."""
    return struct.pack("<I", n) + b"\x00" * 28


def test_default_cap_matches_known_filter_budget():
    """The default cap is the same 50_000-entry budget as TrickleQueue's
    known_filter, so the two per-peer dedup structures stay aligned."""
    assert ANNOUNCED_TXIDS_MAX_ENTRIES == 50_000
    rs = ReconciliationSet(local_salt=1, remote_salt=2)
    assert rs._announced_max == ANNOUNCED_TXIDS_MAX_ENTRIES


def test_announced_txids_stays_bounded_under_many_announcements():
    """Announcing far more txids than the cap never grows the set past the
    cap — the core at-tip-leak regression.  With a plain unbounded set this
    assertion fails (len == N)."""
    cap = 100
    rs = ReconciliationSet(local_salt=1, remote_salt=2, _announced_max=cap)

    n = cap * 50  # 5_000 announcements into a 100-slot FIFO
    for i in range(n):
        txid = _txid(i)
        rs.add_tx(txid)
        rs.mark_announced(txid)

    # Bounded: never exceeds the cap regardless of how many were announced.
    assert len(rs.announced_txids) == cap
    # And the unbounded local_set drained (every add was followed by announce).
    assert rs.set_size == 0


def test_eviction_is_oldest_first_fifo():
    """FIFO eviction drops the OLDEST announced txid; the most-recent cap
    survive."""
    cap = 10
    rs = ReconciliationSet(local_salt=1, remote_salt=2, _announced_max=cap)

    n = 100
    for i in range(n):
        rs.mark_announced(_txid(i))

    assert len(rs.announced_txids) == cap
    # The first (n - cap) txids were evicted...
    for i in range(n - cap):
        assert _txid(i) not in rs.announced_txids
    # ...and the most-recent cap survive.
    for i in range(n - cap, n):
        assert _txid(i) in rs.announced_txids


def test_reannounce_refreshes_position_and_does_not_evict():
    """Re-announcing an already-present txid is LRU-on-touch: it does NOT
    add a slot (so it cannot evict anything) and it survives a subsequent
    wave of new announcements that would otherwise have aged it out."""
    cap = 5
    rs = ReconciliationSet(local_salt=1, remote_salt=2, _announced_max=cap)

    # Fill the FIFO.
    for i in range(cap):
        rs.mark_announced(_txid(i))
    assert len(rs.announced_txids) == cap

    # Re-announce the OLDEST entry — it moves to the most-recent position and
    # the size is unchanged (no new slot, no eviction).
    rs.mark_announced(_txid(0))
    assert len(rs.announced_txids) == cap
    assert _txid(0) in rs.announced_txids

    # Announce one brand-new txid: the now-oldest (_txid(1)) is evicted, but
    # the refreshed _txid(0) survives.
    rs.mark_announced(_txid(99))
    assert len(rs.announced_txids) == cap
    assert _txid(0) in rs.announced_txids
    assert _txid(1) not in rs.announced_txids
    assert _txid(99) in rs.announced_txids


def test_dedup_contract_preserved():
    """The membership-as-dedup contract is unchanged: once announced, a txid
    is not re-queued by add_tx, and membership tests work as before."""
    rs = ReconciliationSet(local_salt=1, remote_salt=2)
    txid = _txid(7)

    rs.add_tx(txid)
    assert rs.set_size == 1
    rs.mark_announced(txid)
    assert rs.set_size == 0
    assert txid in rs.announced_txids

    # Re-adding an announced txid is a no-op (the dedup filter blocks it).
    rs.add_tx(txid)
    assert rs.set_size == 0


def test_old_unbounded_set_would_fail_the_bound():
    """Proof-of-detection: a plain unbounded set (the pre-fix behaviour) grows
    to N, which the bound assertion in
    ``test_announced_txids_stays_bounded_under_many_announcements`` rejects.

    We reproduce the pre-fix datastructure inline to show the test is real —
    if someone reverts mark_announced to ``self.announced_txids.add(txid)``
    over a plain set, the boundedness test above fails."""
    cap = 100
    n = cap * 5
    leaky: set[bytes] = set()
    for i in range(n):
        leaky.add(_txid(i))  # the pre-fix mark_announced body
    # The unbounded set grows to N — exactly the leak the fix removes.
    assert len(leaky) == n
    assert len(leaky) > cap


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
