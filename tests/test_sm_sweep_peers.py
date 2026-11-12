"""sm-sweep-ouroboros, path (d) peer connection states.

D2  Misbehaviour bans are keyed by ``host:port``.  Most callers pass
    ``f"{peer.host}:{peer.port}"`` to ``PeerManager.misbehaving`` (e.g.
    block_sync.py invalid-headers / unconnecting paths, node.py invalid-tx
    path), and ``BanManager.record_misbehavior`` bans that literal key.  The
    inbound gate (p2p.py ``_handle_inbound_connection``) checks
    ``is_banned(host) or is_banned(host:newport)``, so the same IP
    reconnecting from a new ephemeral port is accepted at once; the addrman
    dial path never sees the ban either.
    Core: net_processing.cpp ``MaybeDiscourageAndDisconnect`` ->
    ``m_banman->Discourage(pnode.addr)`` (CNetAddr, no port) and net.cpp
    ``AcceptConnection`` / ``OpenNetworkConnection`` check the address.

D4  ``_evict_inbound_peer`` and ``_on_peer_banned`` pop the peer out of
    ``inbound_peers`` BEFORE ``disconnect()``.  The disconnect callback
    ``_handle_peer_disconnected`` then finds no bucket entry and skips the
    ``_inbound_netgroups`` decrement, so the counter leaks one per
    eviction / ban and the group never again counts as "new" for the
    reserved inbound slots (p2p.py ``is_new_group``).
    Core: CConnman tracks no such counter; eviction (node/eviction.cpp)
    recomputes netgroups from the live peer set on every call.

D2 fixed by sm-fix-ouroboros-ban-address-key (bans keyed by address).
D4: xfail(strict=True) until its fix item lands.
"""

from __future__ import annotations

import asyncio

import pytest

from ouroboros.p2p import PeerManager
from ouroboros.peer import Peer, PeerState


@pytest.fixture
def pm(tmp_path):
    return PeerManager(network="regtest", data_dir=str(tmp_path), listen=False)


# --------------------------------------------------------------------------- #
# D2
# --------------------------------------------------------------------------- #


def test_sm_sweep_misbehaving_host_port_bans_the_address(pm):
    banned = pm.misbehaving("198.51.100.7:51234", 100, "invalid block")
    assert banned, "precondition: score 100 triggers a ban"
    # Same IP, next inbound connection from a fresh ephemeral port.
    assert pm.ban_manager.is_banned("198.51.100.7"), (
        "a ban for 198.51.100.7:51234 must cover 198.51.100.7"
    )


def test_sm_sweep_control_misbehaving_host_bans_the_address(pm):
    """Control: the one caller that passes a bare host (p2p.py oversized
    addr) does produce an address-level ban."""
    assert pm.misbehaving("198.51.100.8", 100, "addr message size")
    assert pm.ban_manager.is_banned("198.51.100.8")


# --------------------------------------------------------------------------- #
# D4
# --------------------------------------------------------------------------- #


def _inbound_peer(pm: PeerManager, host: str, port: int) -> Peer:
    peer = Peer(
        host, port, "regtest", inbound=True,
        on_disconnect=pm._handle_peer_disconnected,
    )
    peer.state = PeerState.READY
    addr = f"{host}:{port}"
    pm.inbound_peers[addr] = peer
    # Mirrors the accept path's increment (p2p.py _handle_inbound_connection,
    # ``self._inbound_netgroups[peer_group] = ... + 1``).
    group = pm._netgroup(host)
    pm._inbound_netgroups[group] = pm._inbound_netgroups.get(group, 0) + 1
    return peer


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0)


@pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros D4: _evict_inbound_peer pops before "
    "disconnect, the netgroup decrement is skipped",
)
@pytest.mark.asyncio
async def test_sm_sweep_inbound_eviction_releases_netgroup(pm, monkeypatch):
    _inbound_peer(pm, "198.51.100.9", 40000)
    monkeypatch.setattr(pm, "_select_eviction_candidate", lambda: "198.51.100.9:40000")
    assert await pm._evict_inbound_peer()
    await _settle()
    assert not pm.inbound_peers
    assert pm._netgroup("198.51.100.9") not in pm._inbound_netgroups, (
        f"netgroup counter leaked: {pm._inbound_netgroups!r}"
    )


@pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros D4: _on_peer_banned pops before disconnect, "
    "the netgroup decrement is skipped",
)
@pytest.mark.asyncio
async def test_sm_sweep_inbound_ban_releases_netgroup(pm):
    _inbound_peer(pm, "198.51.100.10", 40001)
    pm._on_peer_banned("198.51.100.10")
    await _settle()
    assert not pm.inbound_peers
    assert pm._netgroup("198.51.100.10") not in pm._inbound_netgroups, (
        f"netgroup counter leaked: {pm._inbound_netgroups!r}"
    )


@pytest.mark.asyncio
async def test_sm_sweep_control_plain_disconnect_releases_netgroup(pm):
    """Control: a peer that disconnects by itself does release its group."""
    peer = _inbound_peer(pm, "198.51.100.11", 40002)
    await peer.disconnect()
    await _settle()
    assert not pm.inbound_peers
    assert pm._netgroup("198.51.100.11") not in pm._inbound_netgroups
