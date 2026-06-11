"""Tests for the fixed-seed last-resort fallback (2026-06-10).

Mirrors Bitcoin Core net.cpp:2607-2643 (ThreadOpenConnections fixed-seed
trigger).  When every other peer source (DNS / addnode / seednode) has
produced nothing and the address book is empty, ouroboros injects a curated
set of mainnet IPv4 :8333 seeds as a one-shot last resort, layered AFTER the
normal DNS bootstrap — it never replaces or bypasses DNS.

Predicate (all must hold):
  (1) ENABLED   — mainnet, non-empty fixed-seed list, not -connect.
  (2) BOOK EMPTY — known_addrs is empty.
  (3) TIMING    — >60 s since start OR DNS seeding disabled (fire now).
After firing, the one-shot guard latches so subsequent ticks are no-ops.
"""

from __future__ import annotations

import ipaddress

import pytest

from ouroboros.p2p import FIXED_SEEDS_MAINNET, PeerManager


def _pm(**kw) -> PeerManager:
    defaults = dict(network="mainnet", listen=False, dns_seed=False)
    defaults.update(kw)
    return PeerManager(**defaults)


# ---------------------------------------------------------------------------
# (A) The 40 curated entries parse as routable public IPv4 :8333.
# ---------------------------------------------------------------------------


def test_fixed_seeds_are_40_routable_ipv4_8333():
    assert len(FIXED_SEEDS_MAINNET) == 40
    assert len(set(FIXED_SEEDS_MAINNET)) == 40  # no duplicates

    for entry in FIXED_SEEDS_MAINNET:
        ip_str, _, port_str = entry.rpartition(":")
        assert port_str == "8333", f"{entry} not on :8333"
        ip = ipaddress.ip_address(ip_str)
        assert ip.version == 4, f"{entry} not IPv4"
        # Routable public address: not loopback / private / link-local /
        # multicast / reserved / unspecified (Core IsRoutable parity).
        assert ip.is_global, f"{entry} not globally routable"
        assert not ip.is_private
        assert not ip.is_loopback
        assert not ip.is_link_local
        assert not ip.is_multicast


# ---------------------------------------------------------------------------
# (B) add_fixed_seeds actually lands the routable entries in the address pool.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_fixed_seeds_populates_book():
    pm = _pm()
    assert len(pm.known_addrs) == 0
    added = await pm.add_fixed_seeds()
    # All 40 are routable public IPv4, so all 40 land in addrman.
    assert added == 40
    assert len(pm.known_addrs) == 40
    # Tagged with the "fixedseeds" internal source.
    for entry in FIXED_SEEDS_MAINNET:
        assert entry in pm.known_addrs


@pytest.mark.asyncio
async def test_add_fixed_seeds_noop_off_mainnet():
    pm = _pm(network="testnet4")
    added = await pm.add_fixed_seeds()
    assert added == 0
    assert len(pm.known_addrs) == 0


# ---------------------------------------------------------------------------
# (C) Predicate: fires on empty book + DNS disabled (immediate).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fires_on_empty_book_dns_disabled():
    pm = _pm(dns_seed=False)  # DNS off -> immediate-fire branch
    assert not pm._fixed_seeds_added
    fired = await pm.maybe_add_fixed_seeds()
    assert fired is True
    assert pm._fixed_seeds_added is True
    assert len(pm.known_addrs) == 40


# ---------------------------------------------------------------------------
# (D) Predicate: does NOT fire when the book is non-empty.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_fire_on_non_empty_book():
    pm = _pm(dns_seed=False)
    # Simulate DNS / gossip having populated the pool.
    pm._add_known_addr("198.51.100.7:8333")
    before = set(pm.known_addrs)
    fired = await pm.maybe_add_fixed_seeds()
    assert fired is False
    assert pm._fixed_seeds_added is False  # guard NOT latched -> can fire later
    assert set(pm.known_addrs) == before  # no fixed seeds injected


# ---------------------------------------------------------------------------
# (E) Predicate: does NOT fire in -connect mode (pinned peers).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_fire_in_connect_mode():
    pm = _pm(connect_addrs=[("203.0.113.5", 8333)])
    assert pm._connect_only is True
    assert len(pm.known_addrs) == 0
    fired = await pm.maybe_add_fixed_seeds()
    assert fired is False
    assert len(pm.known_addrs) == 0


# ---------------------------------------------------------------------------
# (F) Predicate: with DNS enabled and book empty, does NOT fire before 60 s,
#     and DOES fire once the grace window elapses.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dns_enabled_waits_60s_grace():
    import time

    pm = _pm(dns_seed=True)
    assert pm._dns_seed_enabled is True
    # Anchor start "now" — within the grace window.
    pm._start_ts = time.time()
    fired = await pm.maybe_add_fixed_seeds()
    assert fired is False
    assert len(pm.known_addrs) == 0

    # Now pretend >60 s have elapsed.
    pm._start_ts = time.time() - 61.0
    fired = await pm.maybe_add_fixed_seeds()
    assert fired is True
    assert len(pm.known_addrs) == 40


# ---------------------------------------------------------------------------
# (G) One-shot: a second call after firing is a no-op (guard latched).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_one_shot_guard():
    pm = _pm(dns_seed=False)
    assert await pm.maybe_add_fixed_seeds() is True
    n = len(pm.known_addrs)
    # Empty the book again to prove the *guard* (not the book) is what stops it.
    pm.known_addrs.clear()
    assert await pm.maybe_add_fixed_seeds() is False
    assert len(pm.known_addrs) == 0


# ---------------------------------------------------------------------------
# (H) Banned fixed seeds are filtered out on add.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_banned_fixed_seed_filtered(monkeypatch):
    pm = _pm()
    banned_entry = FIXED_SEEDS_MAINNET[0]
    banned_ip = banned_entry.rpartition(":")[0]

    real_is_banned = pm.ban_manager.is_banned

    def fake_is_banned(target: str) -> bool:
        if target == banned_entry or target == banned_ip:
            return True
        return real_is_banned(target)

    monkeypatch.setattr(pm.ban_manager, "is_banned", fake_is_banned)

    added = await pm.add_fixed_seeds()
    assert added == 39
    assert banned_entry not in pm.known_addrs
