"""getaddr responses are served from a per-network cache and skip terrible entries.

Core ``CConnman::GetAddresses(CNode& requestor, ...)`` (net.cpp:3702-3737)
answers getaddr from ``m_addr_response_caches``, keyed by the requestor's
``m_network_key`` (the local address the connection came in on), and refreshes
an entry only after 21 h + rand(6 h).  The cached vector itself comes from
addrman ``GetAddr_(..., filtered=true)`` (addrman.cpp:792-831), which skips
``IsTerrible`` entries.

Before this fix ouroboros' ``on_getaddr`` drew a fresh 23% shuffle of addrman
for every connection, so a peer that reconnected and asked again got a new
sample each time and could enumerate addrman (and correlate onion and clearnet
identities through the stored timestamps).  Terrible entries were shared too.
"""

import asyncio
import time

from ouroboros.addrman import HORIZON
from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import AddrMessage, NetworkMessage
from ouroboros.peer import Peer

LOCAL_BIND = ("10.0.0.1", 18444)
TERRIBLE_HOST = "9.9.9.9"


def _seeded_manager() -> PeerManager:
    pm = PeerManager(network="regtest", listen=False)
    now = time.time()
    # Many distinct /16 groups so bucketing keeps most of them and a 23% sample
    # of the table is a real subset (two fresh samples would differ).
    for i in range(400):
        pm.addrman.add(f"{11 + i // 200}.{i % 200}.1.1", 8333, timestamp=now)
    pm.addrman.add(TERRIBLE_HOST, 8333, timestamp=now - HORIZON - 3600)
    return pm


def _inbound(pm: PeerManager, host: str, bind=LOCAL_BIND) -> Peer:
    peer = Peer(host, 40000, "regtest", inbound=True)
    peer.addr_bind = bind
    sent: list[NetworkMessage] = []

    async def _send(msg):
        sent.append(msg)

    peer.send_message = _send
    peer.sent = sent
    key = f"{host}:40000"
    pm.inbound_peers[key] = peer
    pm._register_addr_handlers(peer, key)
    return peer


def _getaddr_response(pm: PeerManager, peer: Peer) -> set[str]:
    getaddr = NetworkMessage(command="getaddr", payload=b"")
    asyncio.run(peer.message_handlers["getaddr"](getaddr))
    addrs = [m for m in peer.sent if m.command == "addr"]
    assert len(addrs) == 1, f"expected one addr reply, got {peer.sent!r}"
    msg = AddrMessage.from_payload(addrs[0].payload)
    return {".".join(str(b) for b in na.ip[-4:]) for _ts, na in msg.addresses}


def test_two_inbound_peers_get_identical_getaddr_response():
    pm = _seeded_manager()
    first = _getaddr_response(pm, _inbound(pm, "93.184.216.34"))
    second = _getaddr_response(pm, _inbound(pm, "93.184.216.35"))
    assert first, "the reply must not be empty"
    assert first == second, (
        "Core GetAddresses serves one cached reply per network for 21h+rand(6h); "
        f"two peers got different samples ({len(first ^ second)} entries differ)"
    )


def test_getaddr_response_excludes_terrible_entries():
    pm = _seeded_manager()
    seen: set[str] = set()
    # 23% samples: 60 fresh draws all missing one entry is ~1e-7 on master.
    for i in range(60):
        # A different local bind each time forces a fresh cache entry.
        peer = _inbound(pm, f"93.184.{216 + i // 200}.{i % 200}", bind=("10.0.0.1", 20000 + i))
        seen |= _getaddr_response(pm, peer)
    assert TERRIBLE_HOST not in seen, (
        "addrman GetAddr_(filtered=true) skips IsTerrible entries"
    )


def test_sharing_sample_skips_terrible_deterministically():
    pm = _seeded_manager()
    # max_pct=0 / max_addresses=0 disable both caps, so the walk visits every
    # entry: the terrible one is in the result unless it is filtered.
    hosts = {a.host for a in pm.addrman.get_addresses_for_sharing(
        max_addresses=0, max_pct=0)}
    assert hosts, "addrman must hold the seeded entries"
    assert TERRIBLE_HOST not in hosts


def test_cache_is_per_local_network_and_expires():
    pm = _seeded_manager()
    a = _getaddr_response(pm, _inbound(pm, "93.184.216.50"))
    # A second local listener gets its own entry, drawn separately.
    other = ("10.0.0.2", 18444)
    _getaddr_response(pm, _inbound(pm, "93.184.216.52", bind=other))
    assert set(pm._addr_response_caches) == {LOCAL_BIND, other}
    assert (pm._addr_response_caches[LOCAL_BIND][0]
            is not pm._addr_response_caches[other][0])
    # The cache must expire: force expiry and the next reply is re-drawn.
    for entry in pm._addr_response_caches.values():
        entry[1] = 0.0
    b = _getaddr_response(pm, _inbound(pm, "93.184.216.51"))
    assert a and b
    # Expiry lies 21h..27h ahead, as Core's 21h + rand(6h).
    expiry = pm._addr_response_caches[LOCAL_BIND][1]
    ahead = expiry - time.time()
    assert 21 * 3600 - 5 <= ahead <= 27 * 3600 + 5


def test_cached_reply_is_a_snapshot_of_addrman():
    pm = _seeded_manager()
    p1 = _inbound(pm, "93.184.216.60")
    _getaddr_response(pm, p1)
    first = AddrMessage.from_payload(p1.sent[0].payload).addresses
    # addrman learns newer timestamps afterwards; the cached reply must not
    # change until it expires (Core caches CAddress values).
    for info in pm.addrman._addrs.values():
        info.last_seen += 1000
    p2 = _inbound(pm, "93.184.216.61")
    _getaddr_response(pm, p2)
    second = AddrMessage.from_payload(p2.sent[0].payload).addresses
    assert [ts for ts, _ in first] == [ts for ts, _ in second]


def test_inbound_accept_records_local_bind(monkeypatch):
    """The cache key comes from the accepted socket's local address."""
    pm = PeerManager(network="regtest", listen=False)
    seen = []

    async def _fake_accept(self, reader, writer, start_height):
        seen.append(self.addr_bind)
        return False

    monkeypatch.setattr(Peer, "accept_inbound", _fake_accept)

    class _Writer:
        def get_extra_info(self, name):
            return {"peername": ("93.184.216.70", 40000),
                    "sockname": ("10.0.0.1", 18444)}.get(name)

        def close(self):
            pass

    asyncio.run(pm._handle_inbound_connection(None, _Writer()))
    assert seen == [LOCAL_BIND]


def test_onion_loopback_listener_and_clearnet_listener_do_not_share_a_reply():
    """Tor hands onion inbound to us on 127.0.0.1 (tor.py ADD_ONION target);
    clearnet inbound arrives on the public interface.  Each gets its own cache
    entry, so one reply cannot be matched across the two identities."""
    pm = _seeded_manager()
    onion_bind = ("127.0.0.1", 18444)
    clear_bind = ("203.0.113.7", 18444)
    _getaddr_response(pm, _inbound(pm, "127.0.0.1", bind=onion_bind))
    _getaddr_response(pm, _inbound(pm, "93.184.216.80", bind=clear_bind))
    caches = pm._addr_response_caches
    assert onion_bind in caches and clear_bind in caches
    assert caches[onion_bind][0] is not caches[clear_bind][0]
