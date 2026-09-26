"""Self-address advertisement (Core MaybeSendAddr / -externalip / -discover).

Pins:
* the routable filter (Core CNetAddr::IsRoutable, reused from addrman);
* discovery from an outbound peer's VERSION addr_recv, stored with OUR listen
  port, scored by distinct peer netgroups, gated at score >= 2, 3h TTL, cap 8,
  inbound peers only bump;
* the addr / addrv2 self-announcement contents (single entry, our services,
  time now, the LISTEN port);
* the IBD gate (no send while in IBD, first send once out) and the latching
  Node.is_initial_block_download;
* never to block-relay-only or feeler connections; Poisson re-send timer;
* VERSION addr_from is Core's empty CService (no hardcoded 8333).
"""

import asyncio
import time

import pytest

from ouroboros.localaddr import (
    DISCOVERED_LOCAL_ADDR_TTL,
    LOCAL_MANUAL,
    MAX_DISCOVERED_LOCAL_ADDRS,
    LocalAddrTable,
    build_self_announcement,
    ip_from_netaddr_bytes,
    is_routable_ip,
    local_addr_for_peer,
    parse_externalip,
    parse_externalip_list,
)
from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import (
    AddrMessage,
    AddrV2Message,
    NetworkAddress,
    NODE_NETWORK,
    NODE_WITNESS,
)
from ouroboros.peer import Peer

LISTEN_PORT = 39123  # deliberately not 8333 / 18444


# ---------------------------------------------------------------- routable


@pytest.mark.parametrize("ip,expected", [
    ("1.2.3.4", True),
    ("8.8.8.8", True),
    ("76.38.7.169", True),
    ("2600:1f18::1", True),
    ("::ffff:1.2.3.4", True),      # IPv4-mapped normalises to 1.2.3.4
    ("127.0.0.1", False),
    ("0.0.0.0", False),
    ("10.1.2.3", False),
    ("172.16.0.1", False),
    ("192.168.1.128", False),
    ("169.254.1.1", False),
    ("100.64.0.1", False),         # RFC6598 CGNAT
    ("192.0.2.1", False),          # RFC5737 documentation
    ("::1", False),
    ("::", False),
    ("fe80::1", False),
    ("fd00::1", False),
    ("example.com", False),
    ("", False),
    (None, False),
])
def test_routable_filter(ip, expected):
    assert is_routable_ip(ip) is expected


def test_ip_from_netaddr_bytes():
    assert ip_from_netaddr_bytes(b"\x00" * 10 + b"\xff\xff" + bytes([1, 2, 3, 4])) == "1.2.3.4"
    assert ip_from_netaddr_bytes(b"\x00" * 16) == "::"
    assert ip_from_netaddr_bytes(b"\x01") is None


# ---------------------------------------------------------------- -externalip


def test_parse_externalip():
    assert parse_externalip("1.2.3.4") == ("1.2.3.4", 0)
    assert parse_externalip("1.2.3.4:9000") == ("1.2.3.4", 9000)
    assert parse_externalip("[2001:db8::1]:8333") == ("2001:db8::1", 8333)
    assert parse_externalip("2001:db8::1") == ("2001:db8::1", 0)
    assert parse_externalip_list(["1.2.3.4,5.6.7.8:1", "9.9.9.9"]) == [
        ("1.2.3.4", 0), ("5.6.7.8", 1), ("9.9.9.9", 0)]
    with pytest.raises(ValueError):
        parse_externalip("not-an-ip")


def test_manual_rejects_unroutable():
    t = LocalAddrTable()
    assert not t.add_manual("192.168.1.5", LISTEN_PORT)
    assert t.add_manual("1.2.3.4", LISTEN_PORT)
    [row] = t.list()
    assert (row.address, row.port, row.score) == ("1.2.3.4", LISTEN_PORT, LOCAL_MANUAL)


# ---------------------------------------------------------------- discovery table


def test_discovery_needs_two_netgroups():
    t = LocalAddrTable()
    now = 1_000_000.0
    assert t.confirm("5.6.7.8", LISTEN_PORT, "11.22", create=True, now=now)
    assert t.best(None, now) is None            # score 1: not advertised
    t.confirm("5.6.7.8", LISTEN_PORT, "11.22", create=True, now=now)
    assert t.list(now)[0].score == 1            # same netgroup does not count twice
    t.confirm("5.6.7.8", LISTEN_PORT, "33.44", create=True, now=now)
    best = t.best(None, now)
    assert (best.address, best.port, best.score) == ("5.6.7.8", LISTEN_PORT, 2)


def test_inbound_only_bumps_existing():
    t = LocalAddrTable()
    now = 1_000_000.0
    assert not t.confirm("5.6.7.8", LISTEN_PORT, "11.22", create=False, now=now)
    assert t.list(now) == []
    t.confirm("5.6.7.8", LISTEN_PORT, "11.22", create=True, now=now)
    assert t.confirm("5.6.7.8", LISTEN_PORT, "33.44", create=False, now=now)
    assert t.list(now)[0].score == 2


def test_discovered_ttl_and_cap():
    t = LocalAddrTable()
    now = 1_000_000.0
    t.add_manual("1.2.3.4", LISTEN_PORT)
    t.confirm("5.6.7.8", LISTEN_PORT, "g1", create=True, now=now)
    assert len(t.list(now)) == 2
    later = now + DISCOVERED_LOCAL_ADDR_TTL + 1
    assert [a.address for a in t.list(later)] == ["1.2.3.4"]  # manual never expires
    for i in range(MAX_DISCOVERED_LOCAL_ADDRS + 5):
        t.confirm(f"9.9.{i}.1", LISTEN_PORT, "g", create=True, now=later + i)
    discovered = [a for a in t.list(later + 100) if a.address != "1.2.3.4"]
    assert len(discovered) == MAX_DISCOVERED_LOCAL_ADDRS


def test_local_addr_for_peer_outbound_keeps_listen_port():
    t = LocalAddrTable()
    # Nothing known, peer sees us at a routable IP: use the IP, OUR listen port.
    got = local_addr_for_peer(
        t, peer_ip="8.8.8.8", peer_inbound=False,
        addr_local=("5.6.7.8", 51234), listen_port=LISTEN_PORT, discover=True)
    assert got == ("5.6.7.8", LISTEN_PORT)
    # Inbound peer dialed our listening port -> it saw the port too.
    got = local_addr_for_peer(
        t, peer_ip="8.8.8.8", peer_inbound=True,
        addr_local=("5.6.7.8", 40000), listen_port=LISTEN_PORT, discover=True)
    assert got == ("5.6.7.8", 40000)
    # discover off / unroutable view / nothing known -> nothing to advertise.
    assert local_addr_for_peer(
        t, peer_ip="8.8.8.8", peer_inbound=False,
        addr_local=("5.6.7.8", 1), listen_port=LISTEN_PORT, discover=False) is None
    assert local_addr_for_peer(
        t, peer_ip="127.0.0.1", peer_inbound=False,
        addr_local=("127.0.0.1", 1), listen_port=LISTEN_PORT, discover=True) is None


# ---------------------------------------------------------------- message contents


def test_addr_v1_contents():
    services = NODE_NETWORK | NODE_WITNESS
    msg = build_self_announcement("1.2.3.4", LISTEN_PORT, services, 1_700_000_000,
                                  addrv2=False, network="regtest")
    assert msg.command == "addr"
    am = AddrMessage.from_payload(msg.payload)
    assert len(am.addresses) == 1
    ts, na = am.addresses[0]
    assert ts == 1_700_000_000
    assert na.services == services
    assert ip_from_netaddr_bytes(na.ip) == "1.2.3.4"
    assert na.port == LISTEN_PORT


def test_addrv2_contents():
    services = NODE_NETWORK | NODE_WITNESS
    msg = build_self_announcement("1.2.3.4", LISTEN_PORT, services, 1_700_000_000,
                                  addrv2=True, network="regtest")
    assert msg.command == "addrv2"
    am = AddrV2Message.from_payload(msg.payload)
    assert len(am.addresses) == 1
    e = am.addresses[0]
    assert (e.time, e.services, e.network_id, e.addr, e.port) == (
        1_700_000_000, services, 1, bytes([1, 2, 3, 4]), LISTEN_PORT)
    v6 = AddrV2Message.from_payload(build_self_announcement(
        "2600:1f18::1", LISTEN_PORT, services, 1, addrv2=True).payload).addresses[0]
    assert v6.network_id == 2 and v6.port == LISTEN_PORT


# ---------------------------------------------------------------- PeerManager wiring


class _FakePeer:
    def __init__(self, host="8.8.8.8", port=8333, inbound=False, relay_txs=True,
                 addrv2=False, addr_local=None):
        self.host = host
        self.port = port
        self.inbound = inbound
        self.relay_txs = relay_txs
        self.addrv2 = addrv2
        self.addr_local = addr_local
        self.our_services = NODE_NETWORK | NODE_WITNESS
        self.next_local_addr_send = 0.0
        self.sent = []

    def is_connected(self):
        return True

    async def send_message(self, msg):
        self.sent.append(msg)


def _pm(ibd=False, external=(("1.2.3.4", 0),), discover=False):
    state = {"ibd": ibd}
    pm = PeerManager(network="regtest", external_ips=list(external),
                     discover=discover, is_ibd=lambda: state["ibd"])
    pm._self_listen_port = lambda: LISTEN_PORT
    pm._add_external_ips()
    return pm, state


def _full_relay(pm, peer):
    pm.peers[f"{peer.host}:{peer.port}"] = peer
    return peer


def test_externalip_bare_ip_gets_listen_port():
    pm, _ = _pm()
    assert pm.local_addresses == [
        {"address": "1.2.3.4", "port": LISTEN_PORT, "score": LOCAL_MANUAL}]


@pytest.mark.parametrize("addrv2", [False, True])
async def test_sends_one_self_announcement_with_listen_port(addrv2):
    pm, _ = _pm()
    peer = _full_relay(pm, _FakePeer(addrv2=addrv2))
    assert await pm._maybe_send_local_addr(peer)
    assert len(peer.sent) == 1
    msg = peer.sent[0]
    if addrv2:
        assert msg.command == "addrv2"
        [e] = AddrV2Message.from_payload(msg.payload).addresses
        assert (bytes(e.addr), e.port, e.services) == (
            bytes([1, 2, 3, 4]), LISTEN_PORT, peer.our_services)
        assert abs(e.time - time.time()) < 60
    else:
        assert msg.command == "addr"
        [(ts, na)] = AddrMessage.from_payload(msg.payload).addresses
        assert (ip_from_netaddr_bytes(na.ip), na.port, na.services) == (
            "1.2.3.4", LISTEN_PORT, peer.our_services)
        assert abs(ts - time.time()) < 60
    # Poisson timer armed: an immediate second pass sends nothing.
    assert peer.next_local_addr_send > time.monotonic()
    assert not await pm._maybe_send_local_addr(peer)
    assert len(peer.sent) == 1


async def test_ibd_gate_defers_first_send():
    pm, state = _pm(ibd=True)
    peer = _full_relay(pm, _FakePeer())
    assert not await pm._maybe_send_local_addr(peer)
    assert peer.sent == [] and peer.next_local_addr_send == 0.0  # timer untouched
    state["ibd"] = False                                          # next tick
    assert await pm._maybe_send_local_addr(peer)
    assert len(peer.sent) == 1


async def test_never_to_block_relay_only_or_feeler():
    pm, _ = _pm()
    bro = _FakePeer(host="9.9.9.9", relay_txs=False)
    pm.block_relay_peers["9.9.9.9:8333"] = bro
    feeler = _FakePeer(host="7.7.7.7", relay_txs=False)
    pm._feeler_peer = feeler
    assert not await pm._maybe_send_local_addr(bro)
    assert not await pm._maybe_send_local_addr(feeler)
    assert bro.sent == [] and feeler.sent == []
    inbound = _FakePeer(host="6.6.6.6", inbound=True)
    pm.inbound_peers["6.6.6.6:5000"] = inbound
    assert await pm._maybe_send_local_addr(inbound)


async def test_not_listening_sends_nothing():
    pm, _ = _pm()
    pm._self_listen_port = lambda: 0
    peer = _full_relay(pm, _FakePeer())
    assert not await pm._maybe_send_local_addr(peer)


def test_discovery_from_outbound_addr_recv_uses_listen_port():
    pm, _ = _pm(external=(), discover=True)
    pm._note_version_addr_recv(_FakePeer(host="8.8.8.8", addr_local=("5.6.7.8", 51111)))
    [row] = pm.local_addresses
    assert row == {"address": "5.6.7.8", "port": LISTEN_PORT, "score": 1}
    # unroutable peer or unroutable view: ignored
    pm._note_version_addr_recv(_FakePeer(host="10.0.0.1", addr_local=("5.6.7.8", 1)))
    pm._note_version_addr_recv(_FakePeer(host="9.9.9.9", addr_local=("192.168.1.2", 1)))
    assert pm.local_addresses[0]["score"] == 1
    # inbound from a new netgroup bumps; a second outbound netgroup would too
    pm._note_version_addr_recv(_FakePeer(host="4.4.4.4", inbound=True,
                                         addr_local=("5.6.7.8", 1)))
    assert pm.local_addresses[0]["score"] == 2
    # discover off: nothing learned
    pm2, _ = _pm(external=(), discover=False)
    pm2._note_version_addr_recv(_FakePeer(host="8.8.8.8", addr_local=("5.6.7.8", 1)))
    assert pm2.local_addresses == []


# ---------------------------------------------------------------- VERSION + IBD


def test_version_addr_from_is_empty_cservice():
    na = Peer._version_addr_from(NODE_NETWORK | NODE_WITNESS)
    assert na.ip == b"\x00" * 16 and na.port == 0
    assert na.services == NODE_NETWORK | NODE_WITNESS


def test_peer_records_addr_recv():
    p = Peer("8.8.8.8", 8333, network="regtest")
    p._note_addr_local(NetworkAddress.from_ipv4("5.6.7.8", 40000))
    assert p.addr_local == ("5.6.7.8", 40000)
    p._note_addr_local(NetworkAddress())
    assert p.addr_local == ("::", 0)


class _FakeDB:
    def __init__(self, ts):
        self._tip_timestamp = ts


def test_node_ibd_latches():
    from ouroboros.node import BitcoinNode as Node  # noqa: N813
    n = Node.__new__(Node)
    n.network = "regtest"
    n.synced = False
    n.db = _FakeDB(1296688602)  # regtest genesis (2011): in IBD
    assert n.is_initial_block_download()
    n.db._tip_timestamp = int(time.time())  # a block was mined
    assert not n.is_initial_block_download()
    n.db._tip_timestamp = 1296688602
    assert not n.is_initial_block_download()  # latched
    m = Node.__new__(Node)
    m.network = "mainnet"
    m.synced = False
    m.db = _FakeDB(int(time.time()))
    assert m.is_initial_block_download()      # mainnet also needs the sync gate
    m.synced = True
    assert not m.is_initial_block_download()
