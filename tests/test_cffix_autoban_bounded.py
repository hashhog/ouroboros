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


def test_inbound_gate_refuses_discouraged_address_on_a_new_port(tmp_path, monkeypatch):
    """The gate must still see an automatically punished address: it moved
    from ``banned`` to ``discouraged``, so a gate that only consulted
    ``is_banned`` would let it straight back in."""
    import asyncio

    from ouroboros.p2p import PeerManager

    from ouroboros import p2p as p2p_mod

    handshakes = []

    async def fake_accept(self, reader, writer, start_height):
        handshakes.append(self.host)
        return False

    monkeypatch.setattr(p2p_mod.Peer, "accept_inbound", fake_accept)

    pm = PeerManager(network="regtest", data_dir=str(tmp_path), listen=False)
    # Control: an unpunished address does reach the handshake.
    asyncio.run(pm._handle_inbound_connection(None, _FakeWriter("198.51.100.41", 1)))
    assert handshakes == ["198.51.100.41"]

    assert pm.misbehaving("198.51.100.40:51000", 100, "invalid block")
    assert not (tmp_path / "bans.json").exists()
    w = _FakeWriter("198.51.100.40", 52000)
    asyncio.run(pm._handle_inbound_connection(None, w))
    assert w.closed
    assert handshakes == ["198.51.100.41"], (
        "discouraged address must be refused at the inbound gate, before the handshake")


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
