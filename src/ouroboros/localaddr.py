"""Self-address advertisement (Bitcoin Core parity).

A listening node must tell the network where it can be reached, or nobody
ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
only gossip source for OUR address is us.  Core does this in three parts,
mirrored here (design follows blockbrew internal/p2p/localaddr.go):

1. A table of local addresses (Core net.cpp ``mapLocalHost`` / ``AddLocal`` /
   ``SeenLocal``).  Entries come from ``--externalip`` (score LOCAL_MANUAL)
   and from discovery: an OUTBOUND peer's VERSION carries ``addr_recv``, the
   address it sees us at.  A discovered entry's score is the number of
   DISTINCT peer netgroups that confirmed it, so one peer (or one /16) cannot
   talk us into advertising an address; it needs
   ``MIN_DISCOVERED_LOCAL_SCORE`` confirmations before it is used, and ages
   out after ``DISCOVERED_LOCAL_ADDR_TTL`` without a fresh confirmation, so a
   changed public IP replaces the old one.  Inbound peers only score an
   existing entry (Core ``SeenLocal``).
2. The per-peer choice of which address to advertise (Core net.cpp
   ``GetLocalAddrForPeer``, 240-268).
3. The send (Core net_processing.cpp ``MaybeSendAddr``, 5445-5479): only when
   listening and out of IBD, one addr/addrv2 carrying just our address right
   after the handshake, then again on a Poisson timer averaging 24h
   (``AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL``).  Never to block-relay-only or
   feeler connections.  The send itself lives in ``p2p.PeerManager``; this
   module holds the pure, unit-testable pieces.

Every stored address is Core's CService: IP plus OUR LISTEN PORT — never the
peer's ephemeral source port and never a chain-default 8333.
"""

from __future__ import annotations

import ipaddress
import math
import random
import threading
import time
from dataclasses import dataclass, field

from ouroboros.addrman import NET_IPV4, NET_IPV6, is_routable

# Local address scores (Core net.h enum LOCAL_NONE..LOCAL_MANUAL).
LOCAL_NONE = 0     # unknown / discovered
LOCAL_IF = 1       # address a local interface listens on
LOCAL_BIND = 2     # address explicitly bound to
LOCAL_MAPPED = 3   # address reported by PCP/NAT-PMP
LOCAL_MANUAL = 4   # address explicitly specified (-externalip=)

# Mean of the exponential delay between self-announcements to one peer
# (Core net_processing.cpp:158 AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h).
AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 60 * 60.0

# How often the timer loop looks for peers whose next self-announcement is
# due.  Coarse is fine against a 24h mean; also bounds how long after IBD
# ends the first (IBD-suppressed) announcement goes out.
LOCAL_ADDR_CHECK_INTERVAL = 60.0

# A discovered (non-manual) entry not confirmed by any peer for this long is
# dropped, so a changed public IP takes over.
DISCOVERED_LOCAL_ADDR_TTL = 3 * 60 * 60.0

# Distinct peer netgroups that must confirm a discovered address before it is
# advertised to OTHER peers.
MIN_DISCOVERED_LOCAL_SCORE = 2

# Cap on discovered entries; the weakest is evicted.
MAX_DISCOVERED_LOCAL_ADDRS = 8

# Cap on the per-entry confirmer set (score ceiling).
MAX_LOCAL_ADDR_CONFIRMERS = 64

_V4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"


def normalize_ip(ip: str | None) -> str | None:
    """Canonical text form of an IP (IPv4-mapped IPv6 -> dotted IPv4).

    Returns None for anything that is not a literal IPv4/IPv6 address
    (hostnames, .onion, .i2p, empty).
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def ip_from_netaddr_bytes(ip_bytes: bytes) -> str | None:
    """Text IP from a 16-byte v1 NetworkAddress ``ip`` field."""
    if len(ip_bytes) != 16:
        return None
    if ip_bytes[:12] == _V4_MAPPED_PREFIX:
        return str(ipaddress.IPv4Address(ip_bytes[12:]))
    return normalize_ip(str(ipaddress.IPv6Address(ip_bytes)))


def is_ipv4(ip: str) -> bool:
    return ":" not in ip


def is_routable_ip(ip: str | None) -> bool:
    """Core ``CNetAddr::IsRoutable`` for a literal IP (reuses addrman's check)."""
    norm = normalize_ip(ip)
    if norm is None:
        return False
    return is_routable(norm, NET_IPV4 if is_ipv4(norm) else NET_IPV6)


def parse_externalip(spec: str) -> tuple[str, int]:
    """Parse one ``--externalip`` value: ``ip``, ``ip:port``, ``[v6]:port``.

    Returns ``(ip, port)`` where port 0 means "use the P2P listen port".
    Raises ValueError on a malformed value.
    """
    s = spec.strip()
    if not s:
        raise ValueError("empty -externalip")
    port = 0
    host = s
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(f"bad -externalip {spec!r}")
        host = s[1:end]
        rest = s[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"bad -externalip {spec!r}")
            port = int(rest[1:])
    elif s.count(":") == 1:
        host, port_s = s.rsplit(":", 1)
        port = int(port_s)
    ip = normalize_ip(host)
    if ip is None:
        raise ValueError(f"-externalip {spec!r} is not an IP address")
    if not 0 <= port <= 65535:
        raise ValueError(f"-externalip {spec!r} port out of range")
    return ip, port


def parse_externalip_list(values) -> list[tuple[str, int]]:
    """Flatten repeatable / comma-separated ``--externalip`` values."""
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[tuple[str, int]] = []
    for v in values:
        for part in str(v).split(","):
            if part.strip():
                out.append(parse_externalip(part))
    return out


def next_local_addr_delay(rng: random.Random | None = None) -> float:
    """Poisson inter-announcement delay (seconds), mean 24h."""
    r = (rng or random).random()
    return -math.log(1.0 - r) * AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL


@dataclass
class LocalAddress:
    """One row of getnetworkinfo.localaddresses."""
    address: str
    port: int
    score: int

    def to_dict(self) -> dict:
        return {"address": self.address, "port": self.port, "score": self.score}


@dataclass
class _Entry:
    ip: str
    port: int
    manual: bool = False
    base_score: int = LOCAL_NONE
    confirmers: set[str] = field(default_factory=set)
    last_seen: float = 0.0

    def score(self) -> int:
        return self.base_score + len(self.confirmers)

    def usable(self) -> bool:
        return self.manual or len(self.confirmers) >= MIN_DISCOVERED_LOCAL_SCORE


class LocalAddrTable:
    """The node's known local addresses (Core ``mapLocalHost``), keyed by IP."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    def add_manual(self, ip: str, port: int) -> bool:
        """Record an operator-specified address.  Non-routable is refused
        (Core ``AddLocal`` refuses it too)."""
        norm = normalize_ip(ip)
        if norm is None or not is_routable_ip(norm) or not port:
            return False
        with self._lock:
            e = self._entries.get(norm)
            if e is None:
                e = _Entry(ip=norm, port=port)
                self._entries[norm] = e
            e.manual = True
            e.base_score = LOCAL_MANUAL
            e.port = port
        return True

    def confirm(self, ip: str, port: int, group: str, create: bool,
                now: float | None = None) -> bool:
        """A peer in netgroup ``group`` sees us at ``ip``.

        ``create=False`` (inbound peer, Core SeenLocal) only scores an existing
        entry; ``create=True`` (outbound addr_recv discovery) may add one with
        ``port`` (our listen port).
        """
        now = time.time() if now is None else now
        norm = normalize_ip(ip)
        if norm is None or not is_routable_ip(norm):
            return False
        with self._lock:
            self._expire_locked(now)
            e = self._entries.get(norm)
            if e is None:
                if not create or not port:
                    return False
                self._make_room_locked()
                e = _Entry(ip=norm, port=port)
                self._entries[norm] = e
            if len(e.confirmers) < MAX_LOCAL_ADDR_CONFIRMERS:
                e.confirmers.add(group)
            e.last_seen = now
        return True

    def _expire_locked(self, now: float) -> None:
        for k in [k for k, e in self._entries.items()
                  if not e.manual and now - e.last_seen > DISCOVERED_LOCAL_ADDR_TTL]:
            del self._entries[k]

    def _make_room_locked(self) -> None:
        discovered = [(k, e) for k, e in self._entries.items() if not e.manual]
        if len(discovered) >= MAX_DISCOVERED_LOCAL_ADDRS:
            worst_key, _ = min(discovered, key=lambda ke: (ke[1].score(), ke[1].last_seen))
            del self._entries[worst_key]

    def best(self, peer_ip: str | None = None,
             now: float | None = None) -> LocalAddress | None:
        """Best usable address for a peer (Core ``GetLocal``): same family as
        the peer first, then highest score, then most recently confirmed."""
        now = time.time() if now is None else now
        peer_norm = normalize_ip(peer_ip) if peer_ip else None
        with self._lock:
            self._expire_locked(now)

            def key(e: _Entry):
                reach = 0
                if peer_norm is not None and is_ipv4(e.ip) == is_ipv4(peer_norm):
                    reach = 1
                return (reach, e.score(), e.last_seen)

            cands = [e for e in self._entries.values() if e.usable()]
            if not cands:
                return None
            b = max(cands, key=key)
            return LocalAddress(b.ip, b.port, b.score())

    def score_of(self, ip: str) -> int:
        norm = normalize_ip(ip)
        with self._lock:
            e = self._entries.get(norm) if norm else None
            return e.score() if e else 0

    def list(self, now: float | None = None) -> list[LocalAddress]:
        """Every entry, highest score first (getnetworkinfo)."""
        now = time.time() if now is None else now
        with self._lock:
            self._expire_locked(now)
            out = [LocalAddress(e.ip, e.port, e.score()) for e in self._entries.values()]
        out.sort(key=lambda a: (-a.score, a.address))
        return out


def local_addr_for_peer(
    table: LocalAddrTable,
    *,
    peer_ip: str | None,
    peer_inbound: bool,
    addr_local: tuple[str, int] | None,
    listen_port: int,
    discover: bool,
    now: float | None = None,
    rng: random.Random | None = None,
) -> tuple[str, int] | None:
    """Pick the address to advertise to one peer (Core GetLocalAddrForPeer).

    ``addr_local`` is the peer's VERSION ``addr_recv`` — its view of us.
    Returns ``(ip, port)`` or None when nothing routable is known.
    """
    rng = rng or random
    local = table.best(peer_ip, now)
    if local is not None:
        ip, port, score = local.address, local.port, local.score
    else:
        ip, port, score = None, listen_port, 0
    seen_ip = normalize_ip(addr_local[0]) if addr_local else None
    peer_good = discover and is_routable_ip(peer_ip) and is_routable_ip(seen_ip)
    if peer_good:
        bits = 3 if score > LOCAL_MANUAL else 1
        if local is None or rng.getrandbits(bits) == 0:
            ip = seen_ip
            if peer_inbound and addr_local:
                # The peer dialed our listening port, so it saw it too.
                port = addr_local[1]
    if not is_routable_ip(ip) or not port:
        return None
    return ip, port


def build_self_announcement(ip: str, port: int, services: int, timestamp: int,
                            addrv2: bool, network: str = "mainnet"):
    """The one-entry addr/addrv2 carrying our own address (Core MaybeSendAddr:
    ``CAddress{local_service, peer.m_our_services, Now()}`` pushed as ADDRV2
    when the peer sent sendaddrv2, else ADDR)."""
    from ouroboros.p2p_messages import (
        AddrMessage,
        AddrV2Entry,
        AddrV2Message,
        NetworkAddress,
    )

    norm = normalize_ip(ip)
    if norm is None:
        raise ValueError(f"not an IP: {ip!r}")
    packed = ipaddress.ip_address(norm).packed
    if addrv2:
        entry = AddrV2Entry(
            time=int(timestamp), services=int(services),
            network_id=1 if len(packed) == 4 else 2,  # BIP155 IPV4 / IPV6
            addr=packed, port=int(port),
        )
        return AddrV2Message(addresses=[entry]).to_network_message(network)
    if len(packed) == 4:
        na = NetworkAddress.from_ipv4(norm, int(port), services=int(services))
    else:
        na = NetworkAddress(services=int(services), ip=packed, port=int(port))
    return AddrMessage(addresses=[(int(timestamp), na)]).to_network_message(network)
