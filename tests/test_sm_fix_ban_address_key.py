"""sm-fix-ouroboros-ban-address-key: misbehaviour bans are keyed by address.

Callers hand ``PeerManager.misbehaving`` a connection key, usually
``f"{peer.host}:{peer.port}"`` (block_sync.py invalid-headers / unconnecting
paths, node.py invalid-tx path).  ``BanManager`` used to ban that literal
string, so the same IP reconnecting from a fresh ephemeral port passed the
inbound gate (p2p.py ``_handle_inbound_connection``) and the dial paths, which
check the bare host or a different ``host:port``.

Core: net_processing.cpp ``MaybeDiscourageAndDisconnect`` calls
``m_banman->Discourage(pnode.addr)`` -- a CNetAddr, no port -- and net.cpp
``AcceptConnection`` / ``OpenNetworkConnection`` check ``IsDiscouraged`` /
``IsBanned`` on the address.  The port never takes part in a ban.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ouroboros.banman import BanManager
from ouroboros.p2p import PeerManager
from ouroboros.peer import Peer, PeerState


@pytest.fixture
def pm(tmp_path):
    return PeerManager(network="regtest", data_dir=str(tmp_path), listen=False)


def _inbound_peer(pm: PeerManager, host: str, port: int, key: str | None = None) -> Peer:
    peer = Peer(
        host, port, "regtest", inbound=True,
        on_disconnect=pm._handle_peer_disconnected,
    )
    peer.state = PeerState.READY
    pm.inbound_peers[key or f"{host}:{port}"] = peer
    return peer


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0)


def test_ban_by_host_port_blocks_same_ip_on_a_new_port(pm):
    """Inbound gate checks ``host`` and ``host:newport``; both must be banned."""
    assert pm.misbehaving("198.51.100.7:51234", 100, "invalid block")
    assert pm.ban_manager.is_banned("198.51.100.7")
    assert pm.ban_manager.is_banned("198.51.100.7:40000")
    assert pm.ban_manager.is_banned("198.51.100.7:51234")


def test_ban_by_host_port_is_seen_by_the_dial_path(pm):
    """add_peer_address / the addrman dial checks a ``host:8333`` key."""
    pm.misbehaving("198.51.100.12:51234", 100, "invalid block")
    pm.add_peer_address("198.51.100.12:18444")
    assert "198.51.100.12:18444" not in pm.known_addrs


def test_bracketed_ipv6_host_port_bans_the_address(pm):
    assert pm.misbehaving("[2001:db8::7]:8333", 100, "invalid block")
    assert pm.ban_manager.is_banned("2001:db8::7")
    assert pm.ban_manager.is_banned("[2001:db8::7]:9999")


@pytest.mark.asyncio
async def test_unbracketed_ipv6_connection_key_bans_the_peer_host(pm):
    """``f"{peer.host}:{peer.port}"`` for an IPv6 peer is not parseable on
    its own (``2001:db8::9:8333`` is itself a valid address), so the key is
    resolved through the connected peer that owns it."""
    _inbound_peer(pm, "2001:db8::9", 8333)
    assert pm.misbehaving("2001:db8::9:8333", 100, "invalid block")
    assert pm.ban_manager.is_banned("2001:db8::9")
    assert pm.ban_manager.is_banned("[2001:db8::9]:41000")
    await _settle()


def test_scores_accumulate_per_address_across_ports(pm):
    """Below-threshold events from two connections of one IP share a score."""
    assert not pm.misbehaving("198.51.100.13:40001", 20, "bad headers")
    assert not pm.misbehaving("198.51.100.13:40002", 20, "bad headers")
    assert pm.ban_manager.get_score("198.51.100.13") == 40
    assert not pm.ban_manager.is_banned("198.51.100.13")


@pytest.mark.asyncio
async def test_ban_disconnects_same_ip_only_not_a_prefix_match(pm):
    """Banning 198.51.100.7 disconnects 198.51.100.7 on any port, but not
    198.51.100.70, which the old ``startswith`` match would have hit."""
    same_a = _inbound_peer(pm, "198.51.100.7", 40000)
    same_b = _inbound_peer(pm, "198.51.100.7", 40001)
    other = _inbound_peer(pm, "198.51.100.70", 40002)
    pm.misbehaving("198.51.100.7:40000", 100, "invalid block")
    await _settle()
    assert "198.51.100.70:40002" in pm.inbound_peers
    assert other.state == PeerState.READY
    assert "198.51.100.7:40000" not in pm.inbound_peers
    assert "198.51.100.7:40001" not in pm.inbound_peers
    assert same_a.state != PeerState.READY
    assert same_b.state != PeerState.READY


def test_legacy_host_port_ban_in_bans_json_loads_as_address_ban(tmp_path):
    """bans.json written before this fix holds ``host:port`` keys."""
    import time

    until = time.time() + 3600
    (tmp_path / "bans.json").write_text(json.dumps({"198.51.100.14:51234": until}))
    bm = BanManager(data_dir=str(tmp_path))
    assert bm.is_banned("198.51.100.14")
    assert bm.is_banned("198.51.100.14:8333")


def test_control_subnet_and_bare_host_keys_unchanged():
    """Control: setban subnets and bare hosts keep their own key."""
    bm = BanManager()
    bm.setban("10.0.0.0/8")
    bm.setban("2001:db8::/32")
    bm.setban("198.51.100.15")
    assert set(bm.list_banned()) == {"10.0.0.0/8", "2001:db8::/32", "198.51.100.15"}
    assert bm.setban("198.51.100.15", "remove")
    assert not bm.is_banned("198.51.100.15")


def test_control_below_threshold_does_not_ban(pm):
    assert not pm.misbehaving("198.51.100.16:40000", 10, "invalid tx")
    assert not pm.ban_manager.is_banned("198.51.100.16")


# --- Warden review of #186: Core's MaybeDiscourageAndDisconnect exemptions ---
#
# net_processing.cpp MaybeDiscourageAndDisconnect returns before
# ``m_banman->Discourage`` for a NoBan peer and for a manual connection, and
# for an ``addr.IsLocal()`` peer it sets ``fDisconnect`` on that one node and
# does NOT discourage ("since that would discourage all peers on the same
# local address").  With bans keyed by address, storing a ban for any of
# these would refuse the next connection from that address at the inbound
# gate, which checks ``is_banned(host)`` before any noban flag is known.


def _outbound_peer(pm: PeerManager, host: str, port: int) -> Peer:
    peer = Peer(
        host, port, "regtest",
        on_disconnect=pm._handle_peer_disconnected,
    )
    peer.state = PeerState.READY
    pm.peers[f"{host}:{port}"] = peer
    return peer


@pytest.mark.asyncio
async def test_local_peer_is_disconnected_but_not_discouraged(pm):
    bad = _inbound_peer(pm, "127.0.0.1", 18444)
    good = _inbound_peer(pm, "127.0.0.1", 18445)
    assert pm.misbehaving("127.0.0.1:18444", 100, "invalid block")
    await _settle()
    assert pm.ban_manager.list_banned() == {}
    assert not pm.ban_manager.is_banned("127.0.0.1")
    assert not pm.ban_manager.is_banned("127.0.0.1:18446")
    # only the peer that misbehaved goes
    assert bad.state != PeerState.READY
    assert "127.0.0.1:18444" not in pm.inbound_peers
    assert good.state == PeerState.READY
    assert "127.0.0.1:18445" in pm.inbound_peers


def test_local_address_without_a_connected_peer_is_not_discouraged(pm):
    pm.misbehaving("127.0.0.1:18444", 100, "invalid block")
    pm.misbehaving("[::1]:18444", 100, "invalid block")
    assert not pm.ban_manager.is_banned("127.0.0.1")
    assert not pm.ban_manager.is_banned("::1")


@pytest.mark.asyncio
async def test_noban_peer_is_neither_banned_nor_disconnected(pm):
    peer = _inbound_peer(pm, "198.51.100.9", 8333)
    peer.noban = True
    assert not pm.misbehaving("198.51.100.9:8333", 100, "invalid block")
    await _settle()
    assert not pm.ban_manager.is_banned("198.51.100.9")
    assert pm.ban_manager.list_banned() == {}
    assert peer.state == PeerState.READY
    assert "198.51.100.9:8333" in pm.inbound_peers


@pytest.mark.asyncio
async def test_manual_peer_is_neither_banned_nor_disconnected(pm):
    peer = _outbound_peer(pm, "198.51.100.8", 8333)
    peer.is_manual = True
    assert not pm.misbehaving("198.51.100.8:8333", 100, "invalid block")
    await _settle()
    assert not pm.ban_manager.is_banned("198.51.100.8")
    assert pm.ban_manager.list_banned() == {}
    assert peer.state == PeerState.READY
    assert "198.51.100.8:8333" in pm.peers


@pytest.mark.asyncio
async def test_oversize_addr_from_noban_peer_is_not_banned(pm):
    """``_misbehave_oversize_addr`` used to pass the bare host; it must
    still find the connected noban peer and leave its address unbanned."""
    from ouroboros.p2p import AddrCountExceeded

    peer = _inbound_peer(pm, "198.51.100.10", 8333)
    peer.noban = True
    pm._misbehave_oversize_addr(peer, AddrCountExceeded("addr", 1001))
    await _settle()
    assert not pm.ban_manager.is_banned("198.51.100.10")
    assert peer.state == PeerState.READY


@pytest.mark.asyncio
async def test_control_ordinary_peer_next_to_noban_peer_is_still_banned(pm):
    """Control: the exemption is per peer, not per address."""
    plain = _inbound_peer(pm, "203.0.113.5", 40000)
    exempt = _inbound_peer(pm, "203.0.113.5", 40001)
    exempt.noban = True
    assert pm.misbehaving("203.0.113.5:40000", 100, "invalid block")
    await _settle()
    assert pm.ban_manager.is_banned("203.0.113.5")
    assert plain.state != PeerState.READY
    # _on_peer_banned keeps its existing noban skip for the other connection
    assert exempt.state == PeerState.READY
