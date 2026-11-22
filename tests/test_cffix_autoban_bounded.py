"""Automatic misbehaviour punishment is a bounded, unpersisted discourage.

Core (src/banman.h) keeps discouraged addresses in
``CRollingBloomFilter m_discouraged{50000, 0.000001}``: bounded, in memory,
never written to banlist.json.  net_processing.cpp
MaybeDiscourageAndDisconnect calls ``Discourage``, not ``Ban``.

ouroboros put every automatic punishment in the persisted ``banned`` dict and
rewrote all of bans.json synchronously on each one, so N fresh source
addresses (cheap with IPv6) grew the table without bound and cost O(N^2)
bytes of disk writes on the event loop.
"""

import json
import os

from ouroboros.banman import BanManager


def _v6(i: int) -> str:
    return f"2001:db8:{(i >> 16) & 0xffff:x}:{i & 0xffff:x}::1"


def test_autoban_does_not_rewrite_bans_json_and_is_bounded(tmp_path):
    bm = BanManager(data_dir=str(tmp_path))
    writes = 0

    def counting_save():  # count, skip the O(N^2) I/O master would do
        nonlocal writes
        writes += 1

    bm._save_bans = counting_save
    n = 60_000
    for i in range(n):
        assert bm.record_misbehavior(_v6(i), 100, "oversize addr") is True

    assert writes == 0, f"bans.json rewritten {writes} times for automatic punishment"
    assert not (tmp_path / "bans.json").exists()
    assert bm.banned == {}, "automatic punishment must not enter the persisted ban list"
    discouraged = getattr(bm, "discouraged", None)
    assert discouraged is not None and len(discouraged) <= 50_000
    # The newest offender is still refused; the oldest rolled out.
    is_disc = getattr(bm, "is_discouraged", lambda _ip: False)
    assert is_disc(_v6(n - 1))
    assert not is_disc(_v6(0))


def test_autoban_real_file_untouched_and_not_reloaded(tmp_path):
    bm = BanManager(data_dir=str(tmp_path))
    bm.setban("198.51.100.1", "add")  # operator ban: persisted, as in Core
    path = tmp_path / "bans.json"
    before = (path.stat().st_mtime_ns, path.stat().st_size, path.read_text())
    os.utime(path, ns=(1, 1))
    for i in range(200):
        bm.record_misbehavior(f"[{_v6(i)}]:8333", 100, "oversize addr")
    assert path.stat().st_mtime_ns == 1
    assert path.read_text() == before[2]
    assert list(json.loads(path.read_text())) == ["198.51.100.1"]

    is_disc = getattr(bm, "is_discouraged", lambda _ip: False)
    assert is_disc(_v6(5)) and is_disc(f"[{_v6(5)}]:18333")
    gate = getattr(bm, "is_banned_or_discouraged", bm.is_banned)
    assert gate(f"[{_v6(5)}]:1")
    # Discouragement is not a ban: listbanned stays operator-only.
    assert [b["address"] for b in bm.list_banned_detailed()] == ["198.51.100.1"]

    # Not persisted: a restart forgets discouragement but keeps setban.
    bm2 = BanManager(data_dir=str(tmp_path))
    assert bm2.is_banned("198.51.100.1")
    assert not getattr(bm2, "is_discouraged", lambda _ip: False)(_v6(5))


def test_discourage_fires_disconnect_callback_and_clears_score(tmp_path):
    hit = []
    bm = BanManager(data_dir=str(tmp_path), on_ban=hit.append)
    assert bm.record_misbehavior("203.0.113.9:4444", 30, "a") is False
    assert hit == []
    assert bm.record_misbehavior("203.0.113.9:5555", 70, "b") is True
    assert hit == ["203.0.113.9"]
    assert bm.get_score("203.0.113.9") == 0
    assert not bm.is_banned("203.0.113.9")
    assert getattr(bm, "is_discouraged", lambda _ip: False)("203.0.113.9")


def test_control_below_threshold_neither_bans_nor_discourages(tmp_path):
    bm = BanManager(data_dir=str(tmp_path))
    assert bm.record_misbehavior("203.0.113.10", 10, "minor") is False
    assert not bm.is_banned("203.0.113.10")
    assert not getattr(bm, "is_discouraged", lambda _ip: False)("203.0.113.10")


class _FakeWriter:
    def __init__(self, host: str, port: int):
        self._peername = (host, port)
        self.closed = False

    def get_extra_info(self, name, default=None):
        return self._peername if name == "peername" else default

    def close(self):
        self.closed = True


def _inbound_pm(tmp_path, monkeypatch, max_inbound=None):
    """A listen-less PeerManager whose handshake only records who reached it
    (and whether the Peer was marked prefer_evict when it got there)."""
    from ouroboros import p2p as p2p_mod
    from ouroboros.p2p import PeerManager

    handshakes = []

    async def fake_accept(self, reader, writer, start_height):
        handshakes.append((self.host, getattr(self, "prefer_evict", False)))
        return False

    monkeypatch.setattr(p2p_mod.Peer, "accept_inbound", fake_accept)
    pm = PeerManager(network="regtest", data_dir=str(tmp_path), listen=False,
                     max_inbound=max_inbound)
    return pm, handshakes


def _inbound(pm, host, port):
    import asyncio

    w = _FakeWriter(host, port)
    asyncio.run(pm._handle_inbound_connection(None, w))
    return w


def test_inbound_discouraged_with_free_slots_reaches_handshake_prefer_evict(
        tmp_path, monkeypatch):
    """Core net.cpp AcceptConnection drops a discouraged address only when
    ``nInbound + 1 >= m_max_inbound``; with room left it is accepted and the
    CNode gets ``prefer_evict = discouraged``.  The address moved from
    ``banned`` to ``discouraged``, so it must not be refused like a ban."""
    pm, handshakes = _inbound_pm(tmp_path, monkeypatch)
    assert not pm.inbound_peers
    # Control: an unpunished address reaches the handshake, not prefer_evict.
    _inbound(pm, "198.51.100.41", 1)
    assert handshakes == [("198.51.100.41", False)]

    assert pm.misbehaving("198.51.100.40:51000", 100, "invalid block")
    assert pm.ban_manager.is_discouraged("198.51.100.40")
    assert not pm.ban_manager.is_banned("198.51.100.40")
    assert not (tmp_path / "bans.json").exists()
    _inbound(pm, "198.51.100.40", 52000)
    assert handshakes[-1] == ("198.51.100.40", True), (
        "discouraged inbound with free slots must reach the handshake, "
        "marked prefer_evict")


def test_inbound_discouraged_refused_when_inbound_almost_full(
        tmp_path, monkeypatch):
    """``len(inbound_peers) + pending + 1 >= max_inbound``: the discouraged
    address is closed before the handshake, while an unpunished address at
    the same fill still gets in (control)."""
    from types import SimpleNamespace

    pm, handshakes = _inbound_pm(tmp_path, monkeypatch, max_inbound=2)
    pm.inbound_peers["192.0.2.1:1"] = SimpleNamespace(
        host="192.0.2.1", is_connected=lambda: True)
    assert pm.misbehaving("198.51.100.40:51000", 100, "invalid block")
    w = _inbound(pm, "198.51.100.40", 52000)
    assert w.closed
    assert handshakes == [], "discouraged inbound must be dropped when almost full"
    # Control: same fill, not discouraged -> handshake.
    _inbound(pm, "203.0.113.7", 3)
    assert handshakes == [("203.0.113.7", False)]


def test_inbound_setban_address_refused_even_with_free_slots(
        tmp_path, monkeypatch):
    """A banned (setban) address is always dropped (Core: ``banned`` check
    has no slot condition), whatever port it arrives from."""
    pm, handshakes = _inbound_pm(tmp_path, monkeypatch)
    assert not pm.inbound_peers
    pm.ban_manager.setban("198.51.100.60", "add")
    w = _inbound(pm, "198.51.100.60", 40000)
    assert w.closed
    assert handshakes == []


def _cand(i, prefer=False):
    from types import SimpleNamespace

    return SimpleNamespace(host="10.0.0.1", latency=0, score=0,
                           last_block_time=0, connected_at=float(i),
                           prefer_evict=prefer, is_connected=lambda: True)


def test_eviction_prefers_prefer_evict_after_protections(tmp_path):
    """Core eviction.cpp SelectNodeToEvict: after every protection, if any
    remaining candidate has prefer_evict, only those stay eligible."""
    from ouroboros.p2p import PeerManager

    pm = PeerManager(network="regtest", data_dir=str(tmp_path), listen=False)
    # Insert newest first so the stable-sort protections take the newest;
    # 30 peers leave peers 0..12 unprotected, oldest = 0.
    for i in reversed(range(30)):
        pm.inbound_peers[f"10.0.0.1:{i}"] = _cand(i)
    assert pm._select_eviction_candidate() == "10.0.0.1:0"  # control
    pm.inbound_peers["10.0.0.1:5"].prefer_evict = True
    assert pm._select_eviction_candidate() == "10.0.0.1:5", (
        "an unprotected prefer_evict (discouraged) inbound must be evicted first")
    # A prefer_evict peer inside a protected group is still protected.
    pm.inbound_peers["10.0.0.1:5"].prefer_evict = False
    pm.inbound_peers["10.0.0.1:29"].prefer_evict = True
    assert pm._select_eviction_candidate() == "10.0.0.1:0"


def test_clearbanned_clears_bans_but_not_discouragement(tmp_path):
    """Core BanMan::ClearBanned clears m_banned only (banman.cpp); the
    discouraged filter survives, so a discouraged address stays refused."""
    import asyncio
    from types import SimpleNamespace

    from ouroboros.rpc import RPCServer

    bm = BanManager(data_dir=str(tmp_path))
    bm.setban("198.51.100.50", "add")
    bm.record_misbehavior("198.51.100.51:4000", 100, "invalid block")
    fake = SimpleNamespace(node=SimpleNamespace(
        peer_manager=SimpleNamespace(ban_manager=bm)))
    asyncio.run(RPCServer.rpc_clearbanned(fake))
    assert not bm.is_banned("198.51.100.50")
    assert getattr(bm, "is_discouraged", lambda _ip: False)("198.51.100.51")
