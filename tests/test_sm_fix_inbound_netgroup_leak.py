"""sm-fix-ouroboros-inbound-netgroup-leak.

``_evict_inbound_peer`` and ``_on_peer_banned`` popped the peer from its
bucket themselves before ``disconnect()``, so the disconnect callback
(``_handle_peer_disconnected``) found no entry and skipped the netgroup
bookkeeping: one ``_inbound_netgroups`` count leaked per eviction or ban, and
a banned outbound peer's group stayed in ``_outbound_netgroups``.  Both pop
sites now go through ``PeerManager._remove_peer_from_bucket``, the same helper
the callback uses.

Core keeps no counter at all (node/eviction.cpp ``SelectNodeToEvict``
recomputes netgroups from the live peers), so the invariant pinned here is:
the counters always equal what the live buckets imply.

The two headline cases are in tests/test_sm_sweep_peers.py
(``test_sm_sweep_inbound_eviction_releases_netgroup``,
``test_sm_sweep_inbound_ban_releases_netgroup``); this file adds the
neighbouring paths.
"""

from __future__ import annotations

import asyncio
from collections import Counter

import pytest

from ouroboros.p2p import PeerManager
from ouroboros.peer import Peer, PeerState


@pytest.fixture
def pm(tmp_path):
    return PeerManager(network="regtest", data_dir=str(tmp_path), listen=False)


def _peer(pm: PeerManager, host: str, port: int, *, inbound: bool) -> Peer:
    peer = Peer(
        host, port, "regtest", inbound=inbound,
        on_disconnect=pm._handle_peer_disconnected,
    )
    peer.state = PeerState.READY
    return peer


def _add_inbound(pm: PeerManager, host: str, port: int) -> Peer:
    peer = _peer(pm, host, port, inbound=True)
    pm.inbound_peers[f"{host}:{port}"] = peer
    # Mirrors the accept path (p2p.py _handle_inbound_connection).
    group = pm._netgroup(host)
    pm._inbound_netgroups[group] = pm._inbound_netgroups.get(group, 0) + 1
    return peer


def _add_outbound(pm: PeerManager, host: str, port: int) -> Peer:
    peer = _peer(pm, host, port, inbound=False)
    pm.peers[f"{host}:{port}"] = peer
    pm._update_outbound_netgroups()
    return peer


def _live_inbound_groups(pm: PeerManager) -> dict[str, int]:
    return dict(Counter(pm._netgroup(p.host) for p in pm.inbound_peers.values()))


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_sm_fix_eviction_decrements_once_when_group_shared(pm, monkeypatch):
    """Two inbound peers in one /16; evicting one leaves the count at 1.

    Guards both directions: the leak (count stays 2) and a double decrement
    (helper at the pop site AND the disconnect callback -> count 0 while a
    peer from that group is still connected)."""
    _add_inbound(pm, "198.51.100.20", 40010)
    _add_inbound(pm, "198.51.100.21", 40011)
    group = pm._netgroup("198.51.100.20")
    assert pm._inbound_netgroups[group] == 2
    monkeypatch.setattr(
        pm, "_select_eviction_candidate", lambda: "198.51.100.20:40010"
    )
    assert await pm._evict_inbound_peer()
    await _settle()
    assert list(pm.inbound_peers) == ["198.51.100.21:40011"]
    assert pm._inbound_netgroups == _live_inbound_groups(pm) == {group: 1}


@pytest.mark.asyncio
async def test_sm_fix_ban_releases_outbound_netgroup(pm):
    """A banned full-relay outbound peer's group leaves _outbound_netgroups,
    so the group is dialable again for diversity once the ban lapses."""
    _add_outbound(pm, "203.0.113.30", 8333)
    group = pm._netgroup("203.0.113.30")
    assert group in pm._outbound_netgroups
    pm._on_peer_banned("203.0.113.30")
    await _settle()
    assert not pm.peers
    assert group not in pm._outbound_netgroups, (
        f"stale outbound netgroup after ban: {pm._outbound_netgroups!r}"
    )


@pytest.mark.asyncio
async def test_sm_fix_local_addr_ban_releases_inbound_netgroup(pm):
    """The local-address branch of _on_peer_banned (disconnect only, no
    discourage) also pops before disconnect; it must release the count too."""
    _add_inbound(pm, "127.0.0.5", 40012)
    pm._on_peer_banned("127.0.0.5")
    await _settle()
    assert not pm.inbound_peers
    assert pm._inbound_netgroups == {}, (
        f"netgroup counter leaked: {pm._inbound_netgroups!r}"
    )


@pytest.mark.asyncio
async def test_sm_fix_control_noban_peer_keeps_its_count(pm):
    """Control: a noban peer is skipped by _on_peer_banned, stays connected,
    and keeps its netgroup count."""
    peer = _add_inbound(pm, "198.51.100.40", 40013)
    peer.noban = True
    pm._on_peer_banned("198.51.100.40")
    await _settle()
    assert list(pm.inbound_peers) == ["198.51.100.40:40013"]
    assert pm._inbound_netgroups == _live_inbound_groups(pm) == {
        pm._netgroup("198.51.100.40"): 1
    }


@pytest.mark.asyncio
async def test_sm_fix_repeated_evictions_do_not_accumulate(pm, monkeypatch):
    """The reported failure mode: churn through one /16 by eviction.  Each
    leaked count made the group look permanently present to is_new_group."""
    group = pm._netgroup("198.51.100.50")
    for i in range(5):
        addr = f"198.51.100.50:{41000 + i}"
        _add_inbound(pm, "198.51.100.50", 41000 + i)
        monkeypatch.setattr(pm, "_select_eviction_candidate", lambda a=addr: a)
        assert await pm._evict_inbound_peer()
        await _settle()
    assert not pm.inbound_peers
    assert group not in pm._inbound_netgroups, (
        f"netgroup counter leaked: {pm._inbound_netgroups!r}"
    )
