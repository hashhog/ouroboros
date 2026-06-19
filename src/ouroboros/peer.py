"""
Bitcoin peer connection management.

This module implements peer-to-peer connection management with asyncio,
including connection, handshake, message handling, and error recovery.
Supports SOCKS5 proxy connections for Tor (.onion) and general proxying.
"""

import asyncio
import hashlib
import logging
import os
import random
import struct
import time
from collections.abc import Callable
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ouroboros.banman import BanManager

from ouroboros.p2p_messages import (
    NODE_BLOOM,
    NODE_COMPACT_FILTERS,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
    NODE_WITNESS,
    NetworkAddress,
    NetworkMessage,
    PingMessage,
    PongMessage,
    VersionMessage,
    get_magic,
)
from ouroboros.transport_v2 import V2Handshake, V2Transport

logger = logging.getLogger(__name__)


class V2TransportError(Exception):
    """Raised when a peer appears to use BIP 324 v2 encrypted transport
    but we attempted to parse its message as v1 plaintext.  The caller
    should disconnect gracefully without penalising the peer's score."""
    pass


class V2NegotiationFailed(Exception):
    """Raised when the BIP 324 v2 outbound handshake fails (peer probably
    speaks v1 only, dropped the connection, or is otherwise unreachable
    over v2).  The caller should:

      1. Close the (now-corrupt) socket — we have already sent 64 bytes of
         ElligatorSwift garbage that the peer interpreted as a partial v1
         message header, so this socket cannot be salvaged for a v1
         handshake.
      2. Mark the peer-address as v1-only via PeerManager so subsequent
         retries skip the v2 probe.
      3. Reconnect on a fresh socket with ``transport_version=1``.

    Mirrors Bitcoin Core's ``V2Transport::ShouldReconnectV1()`` flow
    (net.cpp ~1555–1570 + the m_reconnections queue at ~1949)."""
    pass


# SOCKS5 constants (RFC 1928)

SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCESS = 0x00


# Bitcoin Core net.h:86 MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000
MAX_PROTOCOL_MESSAGE_LENGTH = 4_000_000

# Upper bound on how many consecutive non-message v2 packets (BIP 324 decoys
# or unknown/short-id packets) we read inside a SINGLE _receive_v2_message
# call before treating the peer as misbehaving and disconnecting.
#
# BIP 324 explicitly permits decoy packets (and Core silently ignores them —
# net.cpp:1248 ``if (!ignore)``; unknown message types are dropped but the
# connection is kept — net.cpp:1474-1477).  But Core can never busy-spin on
# them: V2Transport::ReceivedBytes only consumes the bytes delivered by ONE
# bounded ``Recv`` per socket-readiness event (net.cpp:2183, 64 KiB), then
# returns to the poll loop.  Ouroboros's StreamReader can have a whole burst
# of decoy/unknown packets already buffered, so the inner read loop would
# otherwise spin synchronously over all of them in one call — never yielding
# to the event loop and allocating a wait_for Task per iteration.  We mirror
# Core's per-readiness bound + net_processing misbehavior posture: tolerate a
# generous run of decoys, then disconnect a peer that floods them.  256 is far
# above any plausible honest interleave of decoys with real messages.
MAX_CONSECUTIVE_V2_SKIP = 256

# How often the message-receive hot path yields control back to the event loop
# (``await asyncio.sleep(0)``).  This is the LOAD-BEARING fix for the at-tip
# RSS burst (tracemalloc 2026-06-09 burst #2): every ``asyncio.wait_for`` /
# ``async with asyncio.timeout`` read arms a timeout timer via
# ``loop.call_at`` -> a ``TimerHandle`` on ``BaseEventLoop._scheduled``.  When a
# read completes SYNCHRONOUSLY (StreamReader buffer already holds the bytes — a
# high-rate flood of VALID v2 messages), the timeout context cancels the timer,
# but ``TimerHandle.cancel()`` only flips ``_cancelled`` — it does NOT remove the
# handle from the ``_scheduled`` heap.  The cancelled-timer purge lives ONLY
# inside ``BaseEventLoop._run_once`` (base_events.py), which never runs while the
# receive loop spins synchronously without re-entering the loop.  Result: the
# ``_scheduled`` heap (plus the per-call ``wait_for`` Task / coro cyclic
# garbage) grows MONOTONICALLY toward the RSS cap.  A single ``await
# asyncio.sleep(0)`` returns control to ``_run_once``, which bulk-purges the
# cancelled handles AND lets the cyclic GC reclaim the Task/coro chain.  The
# first fix (50fdc48) yielded only on the decoy/unknown sub-branches, so a flood
# of VALID messages never yielded — and recurred.  We now yield on the valid
# path too, every N packets (a per-packet yield is correct but we batch to
# amortize the sleep(0) cost; a local Python 3.13 repro showed batching at N
# bounds ``_scheduled`` to ~N reads-per-window regardless of total iterations,
# vs unbounded ~linear growth at N=0 — proven by the regression test, which the
# pre-fix behavior fails).  This mirrors Core's bounded-work-per-readiness-event
# model (net.cpp V2Transport never processes an unbounded buffered burst in one
# go before returning to the poll loop).
V2_RECV_YIELD_EVERY = 256


def is_onion_host(host: str) -> bool:
    """Return True if *host* is a Tor v3 .onion address."""
    return host.lower().endswith(".onion")


def is_local_addr(host: str) -> bool:
    """Return True if *host* is a local/loopback address.

    Mirrors Bitcoin Core CNetAddr::IsLocal() which covers 127.0.0.0/8 and
    ::1.  Used by _on_peer_banned to choose disconnect-only (no discourage)
    for local addresses, matching Core MaybeDiscourageAndDisconnect @5083.
    """
    # Strip IPv6 bracket notation if present
    clean = host.strip("[]")
    return clean.startswith("127.") or clean == "::1" or clean == "localhost"


def parse_proxy_addr(proxy_str: str) -> tuple[str, int]:
    """Parse a ``host:port`` proxy string and return ``(host, port)``; raises ValueError if invalid."""
    if not proxy_str:
        raise ValueError("empty proxy string")
    # Handle IPv6 bracket notation [::1]:9050
    if proxy_str.startswith("["):
        bracket_end = proxy_str.index("]")
        host = proxy_str[1:bracket_end]
        port_str = proxy_str[bracket_end + 2:]  # skip ']:'
    else:
        parts = proxy_str.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid proxy address: {proxy_str}")
        host, port_str = parts
    return host, int(port_str)


async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Establish a TCP connection through a SOCKS5 proxy (RFC 1928, no-auth, CONNECT).

    Sends *dest_host* as a domain name so the proxy (Tor) resolves .onion addresses.
    Returns ``(reader, writer)`` connected to *dest_host:dest_port* via the proxy.
    """
    # 1. TCP connect to the proxy
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        # 2. SOCKS5 greeting: version + 1 auth method (no-auth)
        writer.write(struct.pack("BBB", SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE))
        await writer.drain()

        # 3. Read server's chosen auth method
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected version {resp[0]}")
        if resp[1] != SOCKS5_AUTH_NONE:
            raise Exception(f"SOCKS5: server rejected no-auth (method={resp[1]:#x})")

        # 4. CONNECT request
        # Use domain name addressing so Tor can resolve .onion addresses
        host_bytes = dest_host.encode("ascii")
        connect_req = struct.pack(
            "!BBBB",
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,  # reserved
            SOCKS5_ATYP_DOMAINNAME,
        )
        connect_req += struct.pack("B", len(host_bytes)) + host_bytes
        connect_req += struct.pack("!H", dest_port)
        writer.write(connect_req)
        await writer.drain()

        # 5. Read CONNECT reply (minimum 10 bytes for IPv4 bind addr)
        reply_header = await asyncio.wait_for(
            reader.readexactly(4), timeout=timeout
        )
        if reply_header[0] != SOCKS5_VERSION:
            raise Exception(f"SOCKS5: unexpected reply version {reply_header[0]}")
        if reply_header[1] != SOCKS5_REPLY_SUCCESS:
            raise Exception(
                f"SOCKS5: CONNECT failed with status {reply_header[1]:#x}"
            )

        # Consume the bind address (we don't need it but must drain it)
        atyp = reply_header[3]
        if atyp == SOCKS5_ATYP_IPV4:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_IPV6:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            domain_len_bytes = await asyncio.wait_for(
                reader.readexactly(1), timeout=timeout
            )
            await asyncio.wait_for(
                reader.readexactly(domain_len_bytes[0] + 2), timeout=timeout
            )
        else:
            raise Exception(f"SOCKS5: unknown bind address type {atyp:#x}")

        logger.debug(
            f"SOCKS5 tunnel established to {dest_host}:{dest_port} "
            f"via {proxy_host}:{proxy_port}"
        )
        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


class PeerState(Enum):
    """Peer connection state"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    HANDSHAKING = 3
    READY = 4


# Minimum protocol version for segwit support (BIP 144)
MIN_PEER_VERSION = 70015

# Handshake timeout in seconds
HANDSHAKE_TIMEOUT = 60.0


class _PrefixedStreamReader:
    """Adapter that prepends a fixed prefix to an :class:`asyncio.StreamReader`.

    Inbound BIP 324 detection requires reading and classifying the first
    4 bytes off the wire (network magic ⇒ v1, otherwise an ElligatorSwift
    pubkey ⇒ v2).  When we classify v1, those 4 bytes are still part of
    the v1 message header, so we wrap the reader in this adapter to
    yield the consumed prefix back before delegating to the real
    reader.  Only the methods used by ``Peer.receive_message`` need to
    be implemented (``readexactly`` is the only one in practice).

    Mirrors the equivalent peek-based design in ``clearbit/src/peer.zig``
    (``peekBytes`` + classify) — Python's asyncio.StreamReader does not
    expose MSG_PEEK, so we consume-then-prepend instead.
    """

    def __init__(self, reader: asyncio.StreamReader, prefix: bytes):
        self._reader = reader
        self._prefix = bytes(prefix)

    async def readexactly(self, n: int) -> bytes:
        if not self._prefix:
            return await self._reader.readexactly(n)
        if n <= len(self._prefix):
            head = self._prefix[:n]
            self._prefix = self._prefix[n:]
            return head
        head = self._prefix
        self._prefix = b""
        tail = await self._reader.readexactly(n - len(head))
        return head + tail

    async def read(self, n: int = -1) -> bytes:
        if self._prefix and (n < 0 or n >= len(self._prefix)):
            head = self._prefix
            self._prefix = b""
            if n < 0:
                tail = await self._reader.read(-1)
            else:
                tail = await self._reader.read(n - len(head))
            return head + tail
        if self._prefix:
            head = self._prefix[:n]
            self._prefix = self._prefix[n:]
            return head
        return await self._reader.read(n)

    def at_eof(self) -> bool:
        if self._prefix:
            return False
        return self._reader.at_eof()

    def __getattr__(self, name):
        # Delegate any other attribute (feed_eof, exception, etc.) to
        # the underlying reader so callers that introspect the stream
        # see the real connection state.
        return getattr(self._reader, name)


class RelayType(Enum):
    """Peer relay type — determines what messages we exchange."""
    FULL_RELAY = "full_relay"
    BLOCK_RELAY_ONLY = "block_relay_only"


class Peer:
    """Manages connection to a single Bitcoin peer"""

    def __init__(
        self,
        host: str,
        port: int,
        network: str = "mainnet",
        transport_version: int = 1,
        inbound: bool = False,
        relay_txs: bool = True,
        proxy: str | None = None,
        ban_manager: "BanManager | None" = None,
        peer_bloom_filters: bool = False,
        node_compact_filters: "bool | Callable[[], bool]" = False,
        node_network_limited: bool = False,
        on_disconnect: "Callable[[str], None] | None" = None,
    ):
        """Initialize peer connection."""
        self.host = host
        self.port = port
        self.network = network
        self.transport_version = transport_version
        self.inbound = inbound
        self.relay_txs = relay_txs
        self.proxy = proxy  # SOCKS5 proxy "host:port" or None
        # BIP 111 NODE_BLOOM advertisement toggle.  Mirrors Bitcoin Core's
        # -peerbloomfilters option (DEFAULT_PEERBLOOMFILTERS = false in
        # net_processing.h:44).  When True we OR NODE_BLOOM into the
        # advertised services in our `version` message and service BIP-35
        # MEMPOOL requests; when False (the Core-parity default) we do
        # neither.
        self.peer_bloom_filters = peer_bloom_filters
        # BIP 157 NODE_COMPACT_FILTERS advertisement gate.  Mirrors
        # Bitcoin Core's two-part predicate from ``init.cpp``: the
        # service bit is set ONLY when ``-blockfilterindex`` is enabled
        # AND the BlockFilterIndex thread has caught up to the active
        # chain tip (``BaseIndex::IsSynced``).  Before FIX-71 this was a
        # static bool captured at peer construction; that caused
        # ouroboros to advertise the bit pre-sync (W121 BUG-5).  We now
        # accept either a static bool (legacy callers / direct tests)
        # OR a callable ``() -> bool`` which is re-evaluated on every
        # version handshake (the actual sender path consults
        # :meth:`_should_advertise_node_compact_filters`).
        self.node_compact_filters = node_compact_filters
        # BIP-159 NODE_NETWORK_LIMITED advertisement toggle.  Set when
        # prune mode is on (`prune > 0` in node config).  When True we
        # OR NODE_NETWORK_LIMITED (1<<10 = 0x400) into the advertised
        # services; mirrors Core's `init.cpp` (`nLocalServices |=
        # NODE_NETWORK_LIMITED` when `IsPruneMode()` is true).
        self.node_network_limited = node_network_limited
        # Optional reference to PeerManager's BanManager so that adjust_score
        # clamping at 0 can route the peer through the existing ban
        # callback (which removes the peer + closes the socket).  Without
        # this, score==0 was log-only — see wave3-2026-04-14/
        # OUROBOROS-PEER-TIMEOUT-DIAG.md (Lever 1).
        self.ban_manager = ban_manager
        # Latch so that we only invoke the ban path once per Peer instance,
        # even if adjust_score is called repeatedly after the clamp.
        self._ban_recorded: bool = False
        # Disconnect callback wired by PeerManager so that per-peer state
        # cleanup fires deterministically *at the disconnect event*, not
        # via a 30 s poll in maintain_connections.  Pre-2026-05-28 the
        # cleanup was poll-based and fired for ~0.07% of disconnects
        # (1 of 1497 in the wedge of PID 1252927); the bulk of zombie
        # Peer state stayed live and drove the 65 GB RSS leak.  See
        # CORE-PARITY-AUDIT/_ouroboros-down-20260528-2026-05-28.md.
        # Signature: ``on_disconnect(addr: str) -> None`` where
        # ``addr == f"{self.host}:{self.port}"``.  Synchronous; callback
        # exceptions are caught and logged so a buggy cleanup never
        # blocks socket teardown.
        self._on_disconnect: "Callable[[str], None] | None" = on_disconnect
        # Latch so the disconnect callback fires at most once per Peer
        # instance even if disconnect() is invoked repeatedly.
        self._on_disconnect_fired: bool = False
        # W99 G2: noban/manual flags for Core-canonical ban exemptions.
        # noban: peer has NoBan permission (e.g. whitelisted via -whitelist).
        #        MaybeDiscourageAndDisconnect skips this peer entirely.
        # is_manual: peer was added via addnode RPC / -addnode config.
        #        Manual connections are never auto-banned (they are
        #        reconnected on disconnect anyway).
        # Reference: net_processing.cpp MaybeDiscourageAndDisconnect @5083.
        self.noban: bool = False
        self.is_manual: bool = False
        self.relay_type = (
            RelayType.FULL_RELAY if relay_txs else RelayType.BLOCK_RELAY_ONLY
        )
        self.state = PeerState.DISCONNECTED

        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

        # Per-read stall bound (seconds) used by ``_read_exactly`` when a read
        # would actually BLOCK.  Core parity (net.cpp V2Transport): a recv whose
        # bytes are already buffered arms NO timer; only a read that would block
        # is bounded, and that bound plays the role of Core's coarse
        # per-connection inactivity timeout (CConnman::InactivityCheck @2013 —
        # one check per socket-handler pass, never per packet).  The per-call
        # ``timeout`` argument to receive_message/_receive_v2_message is threaded
        # into this field at call entry so the existing HANDSHAKE_TIMEOUT/60.0
        # callers keep their deadline semantics.
        self._read_timeout: float = 30.0

        # Whole-connection idle-reaper threshold — DISTINCT from _read_timeout
        # (the per-read deadline). Core's CConnman::InactivityCheck uses
        # TIMEOUT_INTERVAL = 20 min (net.h:59), comfortably larger than the
        # keepalive ping cadence (120 s here), so a peer that is merely quiet
        # between blocks is NOT reaped before its own ping/pong refreshes
        # _last_recv_monotonic. is_recv_stalled() previously defaulted to
        # _read_timeout (60 s once listening) < the 120 s ping interval, so every
        # quiet peer (block-relay-only peers, and full-relay peers between blocks)
        # was GUARANTEED reaped on each 30 s sweep — constant peer churn + v1/v2
        # re-dial + addrman burn. Decoupled to Core's 1200 s.
        self._inactivity_timeout: float = 1200.0

        # BIP 324 v2 transport (set after successful negotiation)
        self._v2_transport: V2Transport | None = None
        self._v2_recv_buffer: bytes = b""
        # Latched True when an outbound v2 handshake fails — the caller
        # (PeerManager) inspects this after ``connect()`` returns False
        # to mark the address v1-only and reconnect with v1.
        self.v2_negotiation_failed: bool = False

        self.version: int | None = None
        self.services: int = 0
        # Services we advertise to this peer in our `version` message.
        # Mirrors Bitcoin Core's `Peer::m_our_services`. Used as the
        # source of truth for BIP-35 (mempool) gating — see Core
        # net_processing.cpp ~4855: the MEMPOOL handler is gated on
        # `peer.m_our_services & NODE_BLOOM`, independent of BIP-37
        # fRelay.
        self.our_services: int = 0
        self.user_agent: str = ""
        # ``start_height`` is the peer's chain height as advertised in its
        # ``version`` handshake.  It is a ONE-TIME snapshot captured at
        # connect (peer.py _inbound_handshake / _handshake) and is NEVER
        # refreshed afterwards — the peer keeps extending its chain but this
        # field stays frozen.  Do NOT use it for header-sync peer selection;
        # it causes the stale-start_height starvation pattern (a peer that
        # was level with us at handshake then advances past us is never
        # picked because ``start_height > our_height`` stays false).  Use
        # ``best_known_height`` for that — it tracks the highest block the
        # peer has actually revealed to us at runtime (Core's
        # CNodeState::pindexBestKnownBlock, net_processing.cpp:441).
        self.start_height: int = 0

        # Live best-known chain height for this peer, updated whenever the
        # peer reveals a higher tip via headers / inv / block (mirrors
        # Bitcoin Core's CNodeState::pindexBestKnownBlock — Core tracks the
        # best-known *block* by chain work; ouroboros' header-sync selector
        # is height-based, so we track the height directly).  Seeded from
        # ``start_height`` at handshake (see _inbound_handshake / _handshake)
        # then advanced monotonically by ``note_block_height``.  Never
        # decreases.
        self.best_known_height: int = 0

        self.last_ping: float = 0
        self.latency: float = 0
        self.score: int = 100  # Reputation score (0-100)

        self.message_handlers: dict[str, Callable] = {}
        self._listen_task: asyncio.Task | None = None
        self._ping_task: asyncio.Task | None = None

        # Peer announcement preferences (set by sendheaders / sendcmpct)
        self.wants_headers: bool = False      # BIP 130: prefer headers announcements
        self.wants_cmpctblock: bool = False    # BIP 152: announce via cmpctblock

        # BIP 133: peer's minimum fee rate for tx relay (sat/kvB)
        # peer_feefilter: received from peer, used to filter our INV announcements
        # feefilter_sent: what we last sent to this peer
        # next_feefilter_time: when to send the next feefilter update
        self.peer_feefilter: int = 0
        self.feefilter_sent: int = 0
        self.next_feefilter_time: float = 0.0

        # BIP 330: Erlay reconciliation support
        self.erlay_enabled: bool = False       # Set to True when sendtxrcncl exchanged
        # If the peer sent us sendtxrcncl during the pre-verack window we
        # cache the raw payload here so the post-handshake on_sendtxrcncl
        # handler in p2p.py can replay it once it has been registered.
        self._pending_sendtxrcncl_payload: bytes | None = None

        # BIP 331: package relay (sendpackages negotiation)
        # ``package_relay_version`` is 0 until we receive a sendpackages from
        # the peer.  ``package_max_count`` and ``package_max_weight`` mirror
        # the sender-side limits the peer advertised.  Both sides must send
        # ``sendpackages`` for package relay to be active for the connection.
        self.package_relay_version: int = 0
        self.package_max_count: int = 0
        self.package_max_weight: int = 0
        self._sendpackages_sent: bool = False
        self._sendpackages_received: bool = False

        # Timestamps used by the inbound eviction algorithm
        self.connected_at: float = time.time()
        self.last_block_time: float = 0.0  # last useful block relay activity

        # Connection retry settings
        self._retry_count = 0
        self._max_retries = 3
        self._retry_delay = 5.0  # seconds

        # Handshake state tracking (Phase 16)
        # The handshake is complete only after both VERSION and VERACK are exchanged
        self.handshake_complete: bool = False
        self._version_received: bool = False
        self._verack_received: bool = False
        self._version_sent: bool = False
        self._verack_sent: bool = False

        # BIP 339: peer supports wtxid relay
        self.wtxid_relay: bool = False
        # BIP 155: peer supports addrv2
        self.addrv2: bool = False

        # ---- getaddr / addr anti-DoS state (Core net_processing.cpp Peer) ----
        # GETADDR-once: whether we have already answered a ``getaddr`` from this
        # peer.  Core ``peer.m_getaddr_recvd`` (net_processing.cpp:4833): only the
        # FIRST getaddr per connection is answered; later ones are ignored to
        # discourage addr stamping / addrman-draining DoS.
        self.getaddr_recvd: bool = False
        # INBOUND-addr token bucket (Core ``peer.m_addr_token_bucket``, init 1.0,
        # net_processing.cpp:380).  Refilled by ``elapsed * MAX_ADDR_RATE_PER_SECOND``
        # (0.1 tok/s), soft-capped at ``MAX_ADDR_PROCESSING_TOKEN_BUCKET`` (1000);
        # each processed address costs one token and addresses are dropped once
        # the bucket runs dry.  ``addr_token_timestamp`` (Core
        # ``m_addr_token_timestamp``) is the monotonic time of the last refill.
        self.addr_token_bucket: float = 1.0
        self.addr_token_timestamp: float = time.monotonic()
        # RPC getpeerinfo counters (Core ``m_addr_processed`` /
        # ``m_addr_rate_limited``): running totals of addresses we processed vs
        # dropped for rate-limiting, surfaced by getpeerinfo.
        self.addr_processed: int = 0
        self.addr_rate_limited: int = 0

        # RPC getpeerinfo counters (populated by send_message / receive_message
        # so `bytessent`, `bytesrecv`, `lastsend`, `lastrecv` stop reporting 0
        # for every peer).  Wire-bytes, not decrypted-bytes, so the numbers
        # include v1 header framing and v2 AEAD tags.
        self.bytes_sent: int = 0
        self.bytes_recv: int = 0
        self.last_send: float = 0.0
        self.last_recv: float = 0.0
        # Coarse per-connection inactivity clock (Core parity:
        # ``CNode::m_last_recv``, net.cpp:623/667).  Updated on every successful
        # wire read in ``_read_exactly`` (a monotonic clock so it is immune to
        # wall-clock jumps).  The receive path arms NO per-read ``asyncio.timeout``
        # (that was the v2-recv RSS-burst leak: cancelled ``TimerHandle``s pile up
        # in ``loop._scheduled`` — one or two per message).  Instead a single
        # per-node periodic sweeper (PeerManager.maintain_connections) disconnects
        # any peer whose ``_last_recv_monotonic`` is older than its stall timeout,
        # exactly as Core's coarse ``CConnman::InactivityCheck`` (net.cpp:2013)
        # runs once per socket-handler pass — never per packet.  Seeded to "now"
        # at construction so a freshly-accepted peer is not swept before its first
        # read.
        self._last_recv_monotonic: float = time.monotonic()
        # Connection-age stamp for the inactivity-check grace window — mirrors
        # Core ShouldRunInactivityChecks (net.cpp): skip the recv-idle reap for
        # the first 60 s after connect so the handshake window is never swept.
        self._connected_monotonic: float = time.monotonic()
        # Running count of messages/packets received since we last yielded
        # control to the event loop.  See V2_RECV_YIELD_EVERY: a high-rate
        # flood of VALID, already-buffered messages otherwise spins the receive
        # path (listen -> receive_message, one valid message per call) without
        # re-entering BaseEventLoop._run_once, so the cancelled timeout
        # TimerHandles each read arms accumulate unboundedly in loop._scheduled
        # (the 2026-06-09 RSS burst).  The counter persists ACROSS
        # receive_message calls because each valid call returns after a single
        # packet, so a per-call check could never fire on the valid path.
        self._recv_since_yield: int = 0
        # Clock-skew at handshake: peer_version_timestamp - our_unix_time_at_receipt.
        # Set once per peer when VERSION arrives; stays constant over the connection.
        # Matches Bitcoin Core CNode::nTimeOffset semantics (seconds).
        self.time_offset: int = 0

    def _should_advertise_node_compact_filters(self) -> bool:
        """Re-evaluate NODE_COMPACT_FILTERS advertisement (FIX-71 / W121 BUG-5).

        Bitcoin Core gates the bit on ``-blockfilterindex`` AND
        ``BaseIndex::IsSynced`` together (``init.cpp`` + ``base.cpp``).
        Mid-IBD nodes that advertise the bit pre-sync return invalid
        cfheaders (zero-anchored prev_filter_header, missing heights)
        and are effectively lying peers from a light-client's POV.

        We accept either a static bool (legacy callers, tests that
        explicitly want a fixed-on advertisement) OR a callable
        ``() -> bool`` (the production path, where the node passes a
        closure that consults ``block_filter_index.is_synced(tip)``).
        The callable is invoked **at handshake time**, not at peer
        construction, so a peer that was constructed mid-IBD will
        correctly observe the flipped state once the index catches up.

        If the callable raises we fall back to False (don't advertise) —
        that's the safer side of the failure mode.
        """
        gate = self.node_compact_filters
        if callable(gate):
            try:
                return bool(gate())
            except Exception as exc:
                # Best-effort: never let a buggy closure block handshake.
                # Log at debug because this can be very noisy under tests.
                logger.debug(
                    "node_compact_filters callable raised %r; "
                    "withholding NODE_COMPACT_FILTERS bit",
                    exc,
                )
                return False
        return bool(gate)

    def _assemble_our_services(self) -> int:
        """Build the service-flags bitset we advertise in our ``version``.

        Mirrors Bitcoin Core's ``g_local_services`` (init.cpp). A full
        (non-pruned) witness node advertises at minimum::

            NODE_NETWORK (0x1) | NODE_WITNESS (0x8) | NODE_NETWORK_LIMITED (0x400)
            = 0x409

        - NODE_NETWORK_LIMITED is set UNCONDITIONALLY — it only promises the
          last 288 blocks, which a full node also serves (Core init.cpp:863
          sets it on g_local_services unconditionally; NODE_NETWORK is the
          bit gated on not-pruning at init.cpp:1950). It is NOT prune-only.
        - NODE_BLOOM only when -peerbloomfilters is on (default off).
        - NODE_COMPACT_FILTERS only when -blockfilterindex is on AND synced.
        - NODE_P2P_V2 only when this connection negotiated v2 transport
          (BIP-324). ouroboros's v2 responder is genuinely default-on, so
          advertising the bit when transport_version >= 2 is honest.
        """
        our_services = NODE_NETWORK | NODE_WITNESS
        # BIP 111 NODE_BLOOM is advertised only when peer_bloom_filters
        # is enabled (mirrors Bitcoin Core's -peerbloomfilters, default
        # false; init.cpp:1104). BIP-35 MEMPOOL servicing is gated on
        # this flag in p2p.py (matches Core net_processing.cpp ~4855).
        if self.peer_bloom_filters:
            our_services |= NODE_BLOOM
        # FIX-71 / W121 BUG-5: NODE_COMPACT_FILTERS is gated on
        # ``-blockfilterindex AND index-synced'' at handshake time, not
        # at peer construction. See _should_advertise_node_compact_filters.
        if self._should_advertise_node_compact_filters():
            our_services |= NODE_COMPACT_FILTERS
        # BIP-159: advertised unconditionally by every full node (see docstring).
        our_services |= NODE_NETWORK_LIMITED
        # BIP-324: honest only because ouroboros's v2 responder is default-on.
        if self.transport_version >= 2:
            our_services |= NODE_P2P_V2
        return our_services

    async def connect(self, start_height: int = 0, retry: bool = True) -> bool:
        """Connect to the peer, complete the version handshake, and start background tasks."""
        max_attempts = self._max_retries + 1 if retry else 1

        for attempt in range(max_attempts):
            try:
                logger.info(f"Connecting to {self.host}:{self.port} (attempt {attempt + 1}/{max_attempts})")
                self.state = PeerState.CONNECTING

                # Establish TCP connection with timeout
                # Use SOCKS5 proxy for .onion addresses or when proxy is
                # configured for all outbound connections.
                use_proxy = self.proxy and (
                    is_onion_host(self.host) or self.proxy
                )
                if use_proxy:
                    proxy_host, proxy_port = parse_proxy_addr(self.proxy)
                    logger.info(
                        f"Connecting via SOCKS5 proxy {proxy_host}:{proxy_port} "
                        f"to {self.host}:{self.port}"
                    )
                    self.reader, self.writer = await socks5_connect(
                        proxy_host, proxy_port,
                        self.host, self.port,
                        timeout=10.0,
                    )
                else:
                    # Clearnet TCP connect timeout. Bitcoin Core uses 5s
                    # (CConnman::OpenNetworkConnection). Matching that here
                    # halves refill-loop latency when addrman batches are
                    # full of stale addrs — the W51 peer-starvation mode.
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port),
                        timeout=5.0
                    )

                self.state = PeerState.CONNECTED

                # BIP 324 v2 transport negotiation (before version handshake)
                if self.transport_version == 2:
                    try:
                        await self._negotiate_v2()
                    except V2NegotiationFailed as v2_err:
                        # Socket has 64 bytes of v2 garbage written to it
                        # already; v1 cannot be retried on the same stream.
                        # Set the flag, close cleanly, and stop retrying —
                        # PeerManager will inspect ``v2_negotiation_failed``
                        # and reconnect with transport_version=1 on a
                        # fresh socket.  Mirrors Bitcoin Core's
                        # m_reconnections queue (net.cpp ~1949).
                        logger.info(
                            f"v2 transport negotiation failed with "
                            f"{self.host}:{self.port} ({v2_err}); "
                            "flagging peer v1-only for fresh-socket retry"
                        )
                        self._v2_transport = None
                        self.v2_negotiation_failed = True
                        await self.disconnect()
                        return False
                    except Exception as v2_err:  # pragma: no cover
                        # Defensive: any other failure path should be
                        # treated as a v2 negotiation failure to avoid a
                        # half-encrypted v1 handshake on a corrupt stream.
                        logger.warning(
                            f"v2 transport negotiation raised unexpected "
                            f"{type(v2_err).__name__} from "
                            f"{self.host}:{self.port}: {v2_err}"
                        )
                        self._v2_transport = None
                        self.v2_negotiation_failed = True
                        await self.disconnect()
                        return False

                # Perform handshake under a SINGLE per-connection deadline.
                #
                # The version/verack reads inside ``_handshake`` go through
                # ``receive_message`` -> ``_read_exactly``, which (attempt-5,
                # Core parity) is a PLAIN ``await readexactly`` arming ZERO
                # per-read ``asyncio.timeout`` timers.  The coarse inactivity
                # sweeper (PeerManager.maintain_connections) only iterates
                # REGISTERED peers, and a peer is registered ONLY AFTER this
                # call returns — so a peer that completes TCP connect (and any
                # v2 negotiation) then hangs mid version/verack would await
                # forever here, leaking a slot/coroutine/fd.  Bound the whole
                # version handshake with ONE ``asyncio.timeout`` (one timer per
                # connection ATTEMPT, cancelled on success — O(connections),
                # NOT O(messages), so it does NOT reintroduce the per-read
                # TimerHandle churn the leak fix removed).  On timeout the
                # context raises ``TimeoutError``, which the ``except
                # TimeoutError`` arm below turns into the normal connect-failure
                # cleanup (disconnect, slot freed) — mirroring the pre-attempt-5
                # behaviour where the per-read ``asyncio.timeout`` self-bounded
                # these handshake reads.  (The 5 s TCP connect above and the v2
                # negotiation reads are already individually bounded via
                # ``asyncio.wait_for`` and are intentionally left outside this
                # window.)
                async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                    await self._handshake(start_height)

                self.state = PeerState.READY
                self._retry_count = 0

                logger.info(
                    f"Connected to {self.host}:{self.port} - "
                    f"{self.user_agent} (version {self.version})"
                )

                # Start listening for messages
                self._listen_task = asyncio.create_task(self.listen())

                # Start periodic ping
                self._ping_task = asyncio.create_task(self._ping_loop())

                return True

            except TimeoutError:
                logger.warning(
                    f"Connection timeout to {self.host}:{self.port} "
                    f"(attempt {attempt + 1}/{max_attempts})"
                )
                await self.disconnect()
                if attempt < max_attempts - 1:
                    await asyncio.sleep(self._retry_delay)

            except Exception as e:
                logger.error(
                    f"Failed to connect to {self.host}:{self.port} "
                    f"(attempt {attempt + 1}/{max_attempts}): {e}"
                )
                await self.disconnect()
                if attempt < max_attempts - 1:
                    await asyncio.sleep(self._retry_delay)

        logger.error(f"Failed to connect to {self.host}:{self.port} after {max_attempts} attempts")
        return False

    async def accept_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        start_height: int = 0,
    ) -> bool:
        """Accept an already-established inbound connection and complete the reversed handshake.

        When ``transport_version >= 2`` the wire is classified by reading
        and inspecting the first 4 bytes: a match against the network
        magic means v1 plaintext, otherwise the bytes are the head of
        the peer's 64-byte ElligatorSwift pubkey and the BIP 324
        responder handshake is driven.  Mirrors clearbit's peek+classify
        flow (``clearbit/src/peer.zig:880-930``).

        After a v2 handshake, falls through to the application
        version/verack handshake on the encrypted transport.
        """
        try:
            self.reader = reader
            self.writer = writer
            self.state = PeerState.CONNECTED

            # BIP 324 inbound classification: only when v2 is enabled.
            # The 16-byte read is "destructive" (asyncio.StreamReader has
            # no MSG_PEEK), so on the v1 path we wrap the reader with a
            # ``_PrefixedStreamReader`` that yields the consumed bytes
            # back ahead of the underlying socket data.
            #
            # Core uses V1_PREFIX_LEN=16: 4-byte network magic followed by
            # "version\x00\x00\x00\x00\x00" (net.h:465, net.cpp:1091-1094).
            # We MUST read all 16 bytes before deciding v1 vs v2 and before
            # sending our own ellswift pubkey (BIP-324 MAYBE_V1 state).
            if self.transport_version >= 2:
                # Build the expected 16-byte v1 prefix: magic (4) + command (12).
                _magic_bytes = get_magic(self.network).to_bytes(4, "little")
                _v1_prefix = _magic_bytes + b"version\x00\x00\x00\x00\x00"
                try:
                    prefix = await asyncio.wait_for(
                        self.reader.readexactly(16),
                        timeout=HANDSHAKE_TIMEOUT,
                    )
                except (asyncio.IncompleteReadError, ConnectionResetError,
                        BrokenPipeError, OSError, TimeoutError) as e:
                    raise Exception(
                        f"inbound classify-read failed: {e}"
                    ) from e
                if prefix == _v1_prefix:
                    # v1: re-wrap reader so the v1 handshake sees the
                    # consumed bytes at the head of the stream.  Also
                    # downgrade transport_version so the version message
                    # we send back to the peer doesn't advertise
                    # NODE_P2P_V2 when the actual transport is v1.
                    self.reader = _PrefixedStreamReader(
                        self.reader, prefix
                    )
                    self.transport_version = 1
                else:
                    # v2: drive the responder handshake.  ``prefix`` is
                    # the first 16 bytes of the peer's 64-byte ellswift
                    # pubkey; ``_negotiate_v2_inbound`` reads the
                    # remaining 48 itself.  Sending our pubkey is also
                    # deferred into _negotiate_v2_inbound so it happens
                    # only after the 16-byte decision (G20 fix).
                    await self._negotiate_v2_inbound(initial_prefix=prefix)

            # Inbound handshake: receive version first, then send ours.
            #
            # Bound it with a SINGLE per-connection ``asyncio.timeout`` for the
            # same reason as the outbound path in ``connect`` (see that comment):
            # the version/verack reads here go through ``receive_message`` ->
            # ``_read_exactly``, a plain timer-free ``await``, and the inbound
            # peer is NOT registered (p2p.py:_handle_inbound) until this returns
            # True, so the coarse sweeper cannot see — let alone disconnect — a
            # peer that hangs mid version/verack.  Without this bound such a
            # peer would await forever, leaking a slot/coroutine/fd (inbound DoS).
            # One timer per accepted connection, cancelled on success
            # (O(connections), not O(messages)).  On timeout the context raises
            # ``TimeoutError``, caught by the ``except Exception`` arm below,
            # which disconnects and returns False so the peer is never
            # registered — slot freed.  (The 16-byte v1/v2 classify-read and the
            # v2 inbound negotiation reads above are already individually bounded
            # via ``asyncio.wait_for``.)
            async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                await self._inbound_handshake(start_height)

            self.state = PeerState.READY

            logger.info(
                f"Accepted inbound peer {self.host}:{self.port} - "
                f"{self.user_agent} (version {self.version})"
            )

            # Start background tasks
            self._listen_task = asyncio.create_task(self.listen())
            self._ping_task = asyncio.create_task(self._ping_loop())

            return True
        except Exception as e:
            logger.warning(
                f"Inbound handshake failed from {self.host}:{self.port}: {e}"
            )
            await self.disconnect()
            return False

    async def _inbound_handshake(self, start_height: int):
        """Perform version handshake as the responder (inbound).

        Message sequence (matching Bitcoin Core net_processing.cpp):
        1. Receive VERSION from peer
        2. Validate peer version (must be >= MIN_PEER_VERSION for segwit)
        3. Send our VERSION
        4. Send WTXIDRELAY (BIP 339) if version >= 70016
        5. Send SENDADDRV2 (BIP 155) if version >= 70016
        6. Send VERACK
        7. Receive VERACK -> handshake complete
        """
        self.state = PeerState.HANDSHAKING

        from ouroboros.p2p_messages import (
            FeeFilterMessage,
            SendAddrV2Message,
            SendCmpctMessage,
            SendHeadersMessage,
            WtxidRelayMessage,
        )

        # 1. Receive version from remote peer with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")

        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        # Seed the live best-known-height from the handshake snapshot.  It is
        # only ever advanced from here (note_block_height); it is the value
        # header-sync peer selection reads, NOT the frozen start_height.
        self.note_block_height(version.start_height)
        self.time_offset = int(version.timestamp - time.time())
        self._version_received = True

        # Reject peers with version < MIN_PEER_VERSION (no segwit support)
        if self.version < MIN_PEER_VERSION:
            raise Exception(
                f"Inbound peer {self.host}:{self.port} version {self.version} < {MIN_PEER_VERSION} "
                "(segwit required)"
            )

        # Validate peer service flags
        if not (self.services & NODE_NETWORK):
            logger.warning(
                f"Inbound peer {self.host}:{self.port} lacks NODE_NETWORK — "
                "may not serve full blocks"
            )
        if not (self.services & NODE_WITNESS):
            logger.warning(
                f"Inbound peer {self.host}:{self.port} lacks NODE_WITNESS — "
                "will not relay witness data"
            )

        # 2. Send our version
        addr_recv = self._create_network_address(self.host, self.port)
        addr_from = self._create_network_address("0.0.0.0", 8333)

        # Assemble the services we advertise (see _assemble_our_services).
        our_services = self._assemble_our_services()
        self.our_services = our_services
        version_msg = VersionMessage(
            version=70016,
            services=our_services,
            timestamp=int(time.time()),
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=self._generate_nonce(),
            user_agent='/ouroboros:0.1.0/',
            start_height=start_height,
            relay=self.relay_txs,
        )
        await self.send_message(version_msg.to_network_message(self.network))
        self._version_sent = True

        # Calculate greatest common version for feature negotiation
        greatest_common_version = min(70016, self.version)

        # 3. BIP 339: Send WTXIDRELAY before VERACK if version >= 70016
        if greatest_common_version >= 70016 and self.relay_txs:
            try:
                await self.send_message(
                    WtxidRelayMessage().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send wtxidrelay: {e}")

        # 4. BIP 155: Send SENDADDRV2 before VERACK if version >= 70016
        if greatest_common_version >= 70016:
            try:
                await self.send_message(
                    SendAddrV2Message().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send sendaddrv2: {e}")

        # 5. Send verack
        verack = NetworkMessage(
            command="verack", payload=b"", magic=get_magic(self.network)
        )
        await self.send_message(verack)
        self._verack_sent = True

        # 6. Receive verack with handshake timeout.
        # The remote peer may send any of the legal pre-verack negotiation
        # messages (BIP 339 wtxidrelay, BIP 155 sendaddrv2, BIP 330
        # sendtxrcncl) before its verack.  Per bitcoin-core
        # net_processing.cpp ProcessMessage, anything else received before
        # verack is logged and ignored (NOT a disconnect-worthy offense).
        for _attempt in range(20):
            msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
            if msg.command == "verack":
                break
            if msg.command == "wtxidrelay":
                self.wtxid_relay = True
                logger.debug(f"Received wtxidrelay from {self.host}:{self.port} during inbound handshake")
                continue
            if msg.command == "sendaddrv2":
                self.addrv2 = True
                logger.debug(f"Received sendaddrv2 from {self.host}:{self.port} during inbound handshake")
                continue
            if msg.command == "sendtxrcncl":
                # BIP 330: peer is offering Erlay reconciliation.  Mark
                # the peer; the actual salt-exchange handler is wired
                # post-handshake in p2p.py (_register_erlay_handlers).
                # Stash the raw payload so the handler can replay it
                # once the peer transitions to the connected state.
                self.erlay_enabled = True
                self._pending_sendtxrcncl_payload = msg.payload
                logger.debug(f"Received sendtxrcncl from {self.host}:{self.port} during inbound handshake")
                continue
            # Unknown / unsupported pre-verack message.  Match Core
            # behaviour: log and ignore rather than disconnecting,
            # which keeps us forward-compatible with new BIPs.
            logger.debug(
                f"Ignoring unsupported pre-verack message {msg.command!r} "
                f"from {self.host}:{self.port}"
            )
        else:
            raise Exception("Did not receive verack within expected message count")
        self._verack_received = True

        # Handshake is now complete
        self.handshake_complete = True

        # Post-handshake feature negotiation (sent AFTER verack exchange)
        try:
            await self.send_message(
                SendHeadersMessage().to_network_message(self.network))
            if self.relay_txs:
                await self.send_message(
                    SendCmpctMessage(announce=False, version=2).to_network_message(self.network))
                await self.send_message(
                    FeeFilterMessage(feerate=1000).to_network_message(self.network))
            else:
                logger.debug(
                    f"Block-relay-only inbound peer {self.host}:{self.port} — "
                    "skipping sendcmpct/feefilter"
                )
        except Exception as feat_err:
            logger.debug(f"Feature negotiation error (non-fatal): {feat_err}")

    async def _negotiate_v2(self) -> None:
        """Drive the outbound BIP 324 v2 ElligatorSwift handshake.

        Wire layout (initiator side, per BIP 324 § "Wire format" and
        ``bitcoin-core/src/net.cpp`` V2Transport state machine):

            ->  64 bytes ElligatorSwift pubkey || sent_garbage (0..N bytes)
            <-  64 bytes ElligatorSwift pubkey || recv_garbage  (0..MAX_GARBAGE_LEN bytes)
            ->  send_garbage_terminator (16) || version-packet (AAD = sent_garbage)
            <-  recv_garbage_terminator (16) || decoy*+version-packet (first AEAD AAD = recv_garbage)

        We then transition to the application phase; subsequent packets
        carry empty AAD on both directions.

        v1 fallback heuristic: peek the first 4 bytes of the response.
        A v1-only peer that received our 64 bytes will either disconnect
        (raising IncompleteReadError) or — on some implementations — send
        back a v1-framed reject message starting with the network magic.
        Either case is detected and re-raised as ``V2NegotiationFailed``
        so the caller can mark this address v1-only and reconnect.

        Mirrors Bitcoin Core ``V2Transport`` initiator behaviour
        (net.cpp:989 StartSendingHandshake; net.cpp:1143 ProcessReceivedKeyBytes;
        net.cpp:1180 ProcessReceivedGarbageBytes; BIP-324 spec section
        "Overall handshake pseudocode").
        """
        if not self.reader or not self.writer:
            raise V2NegotiationFailed("Not connected")

        from ouroboros.transport_v2 import (
            CHACHA20POLY1305_EXPANSION,
            GARBAGE_TERMINATOR_LEN,
            HEADER_LEN,
            LENGTH_FIELD_LEN,
            MAX_GARBAGE_LEN,
        )

        handshake = V2Handshake(initiator=True, network=self.network)

        # Generate small random garbage to send after our ellswift pubkey.
        # Spec allows 0..MAX_GARBAGE_LEN; Core picks uniform-random in that
        # full range, but a small bound (0..32) keeps the wire-overhead
        # minimal while still proving we exercise the AAD-binding path.
        sent_garbage = os.urandom(random.randint(0, 32))

        # 1. Send 64-byte ellswift pubkey + garbage in a single write.
        try:
            self.writer.write(handshake.local_pubkey_bytes + sent_garbage)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            raise V2NegotiationFailed(
                f"write failed during v2 ellswift+garbage send: {e}"
            ) from e

        # 2. Read first 4 bytes with a short timeout; we use this to fail
        # fast against v1-only peers that respond with a v1 header
        # (network magic) instead of an ElligatorSwift pubkey.  The peer's
        # 64-byte ellswift is uniformly random, so a coincidental match
        # against the 4-byte network magic happens with probability 2^-32.
        expected_magic = get_magic(self.network).to_bytes(4, "little")
        try:
            head = await asyncio.wait_for(
                self.reader.readexactly(4),
                timeout=5.0,
            )
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 read of first 4 bytes failed (peer probably v1-only): {e}"
            ) from e

        if head == expected_magic:
            raise V2NegotiationFailed(
                "peer replied with v1 network magic — speaks v1 only"
            )

        # 3. Read the remaining 60 bytes of the ElligatorSwift response.
        try:
            tail = await asyncio.wait_for(
                self.reader.readexactly(60),
                timeout=10.0,
            )
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 read of remaining 60 bytes failed: {e}"
            ) from e

        remote_pubkey = head + tail
        try:
            handshake.receive_remote_pubkey(remote_pubkey)
            self._v2_transport = V2Transport.from_handshake(handshake)
        except Exception as e:
            raise V2NegotiationFailed(
                f"v2 key derivation failed: {e}"
            ) from e

        # 4. Send the garbage terminator + version packet (empty contents,
        # AAD = sent_garbage).  We bundle them in one write so the peer
        # can decode in a single pass, matching Core net.cpp:1159-1173.
        send_term = self._v2_transport.send_garbage_terminator
        version_packet = self._v2_transport.encrypt_message(
            b"", aad=sent_garbage
        )
        try:
            self.writer.write(send_term + version_packet)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            raise V2NegotiationFailed(
                f"write failed during v2 terminator+version send: {e}"
            ) from e

        # 5. Scan incoming bytes for the recv_garbage_terminator.  Bound
        # the scan at MAX_GARBAGE_LEN + 16 — Core treats the absence of a
        # terminator within that window as a protocol violation and
        # disconnects (net.cpp:1192 ProcessReceivedGarbageBytes).
        recv_term = self._v2_transport.recv_garbage_terminator
        recv_garbage = b""
        try:
            # Read the first 16 bytes (smallest case: zero-length garbage,
            # peer sent the terminator immediately).
            window = await asyncio.wait_for(
                self.reader.readexactly(GARBAGE_TERMINATOR_LEN),
                timeout=10.0,
            )
            while True:
                if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                    recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
                    break
                if len(window) >= MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN:
                    raise V2NegotiationFailed(
                        f"recv_garbage_terminator not seen within "
                        f"{MAX_GARBAGE_LEN} bytes — protocol violation"
                    )
                # Slide the window forward one byte and look again.  Core
                # also processes one byte at a time here (net.cpp:1297
                # GetMaxBytesToProcess returns 1 in GARB_GARBTERM state)
                # because the terminator may begin at any offset.
                next_byte = await asyncio.wait_for(
                    self.reader.readexactly(1),
                    timeout=10.0,
                )
                window += next_byte
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 garbage-terminator scan failed: {e}"
            ) from e

        # 6. Drain incoming AEAD packets until we receive a non-decoy
        # packet (the peer's version packet).  The first decryption uses
        # AAD = recv_garbage; all subsequent decryptions during this drain
        # use empty AAD (Core net.cpp:1243 ClearShrink(m_recv_aad) after
        # the first successful decrypt — even decoys clear it).
        next_aad: bytes = recv_garbage
        try:
            for _attempt in range(1024):  # generous decoy bound
                enc_length = await asyncio.wait_for(
                    self.reader.readexactly(LENGTH_FIELD_LEN),
                    timeout=10.0,
                )
                contents_len = self._v2_transport.decrypt_length(enc_length)
                if contents_len > MAX_PROTOCOL_MESSAGE_LENGTH:
                    raise V2NegotiationFailed(
                        f"v2 version-phase packet too large: {contents_len}"
                    )
                aead_len = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
                aead_ct = await asyncio.wait_for(
                    self.reader.readexactly(aead_len),
                    timeout=10.0,
                )
                _payload, is_decoy = self._v2_transport.decrypt_contents(
                    aead_ct, contents_len, aad=next_aad
                )
                # AAD is consumed by the first decrypt regardless of decoy.
                next_aad = b""
                if not is_decoy:
                    # Version packet contents are reserved for future
                    # extensions; Core currently ignores them entirely.
                    break
            else:  # pragma: no cover — we'd never see 1024 decoys in practice
                raise V2NegotiationFailed(
                    "v2 version drain exceeded 1024 decoy packets"
                )
        except V2NegotiationFailed:
            raise
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 version-packet drain failed: {e}"
            ) from e
        except Exception as e:
            raise V2NegotiationFailed(
                f"v2 version-packet decrypt failed: {e}"
            ) from e

        logger.info(
            f"BIP 324 v2 handshake complete (initiator) — {self.host}:{self.port} "
            f"(sent_garbage={len(sent_garbage)}B, recv_garbage={len(recv_garbage)}B)"
        )

    async def _negotiate_v2_inbound(self, initial_prefix: bytes) -> None:
        """Drive the BIP 324 v2 responder handshake.

        Symmetric to :meth:`_negotiate_v2` but with ``initiator=False``;
        used by :meth:`accept_inbound` once the wire has been classified
        as non-v1.  ``initial_prefix`` MUST be the 16 bytes already
        consumed by the classifier (head of the peer's 64-byte
        ElligatorSwift pubkey).  Receiving and classifying 16 bytes before
        sending our own pubkey mirrors Bitcoin Core's MAYBE_V1 state
        (net.h:465 V1_PREFIX_LEN=16, net.cpp:1091-1101).

        Wire layout (responder side, per BIP 324 § "Wire format" and
        ``bitcoin-core/src/net.cpp`` V2Transport state machine):

            <-  64 bytes ElligatorSwift pubkey || recv_garbage  (0..MAX_GARBAGE_LEN bytes)
            ->  64 bytes ElligatorSwift pubkey || sent_garbage  (0..N bytes)
            <-  recv_garbage_terminator (16) || decoy*+version-packet (first AEAD AAD = recv_garbage)
            ->  send_garbage_terminator (16) || version-packet (AAD = sent_garbage)

        Mirrors Bitcoin Core ``V2Transport`` responder behaviour
        (net.cpp:1143 ProcessReceivedKeyBytes; net.cpp:1180
        ProcessReceivedGarbageBytes; BIP-324 spec section "Overall
        handshake pseudocode").
        """
        if not self.reader or not self.writer:
            raise V2NegotiationFailed("Not connected")
        if len(initial_prefix) != 16:
            raise V2NegotiationFailed(
                f"initial_prefix must be exactly 16 bytes, got {len(initial_prefix)}"
            )

        from ouroboros.transport_v2 import (
            CHACHA20POLY1305_EXPANSION,
            GARBAGE_TERMINATOR_LEN,
            HEADER_LEN,
            LENGTH_FIELD_LEN,
            MAX_GARBAGE_LEN,
        )

        handshake = V2Handshake(initiator=False, network=self.network)

        # 1. Finish reading the peer's 64-byte ellswift pubkey (we have
        # 16 bytes from the classifier; read the remaining 48).
        try:
            tail = await asyncio.wait_for(
                self.reader.readexactly(48),
                timeout=10.0,
            )
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 read of remaining 48 bytes failed: {e}"
            ) from e
        remote_pubkey = initial_prefix + tail
        try:
            handshake.receive_remote_pubkey(remote_pubkey)
            self._v2_transport = V2Transport.from_handshake(handshake)
        except Exception as e:
            raise V2NegotiationFailed(
                f"v2 key derivation failed (responder): {e}"
            ) from e

        # 2. Send our ellswift pubkey + (small random) garbage AND
        # immediately stage our terminator + version-packet behind it.
        # Both sides send these without waiting on the other; the
        # initiator's outbound path mirrors this order (ellswift then
        # terminator+version, then read).  Sending terminator+version
        # before reading the peer's avoids a deadlock when the peer's
        # asyncio writer hasn't drained yet.  Same 0..32-byte garbage
        # bound as the initiator path.
        sent_garbage = os.urandom(random.randint(0, 32))
        try:
            self.writer.write(handshake.local_pubkey_bytes + sent_garbage)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            raise V2NegotiationFailed(
                f"write failed during v2 ellswift+garbage send: {e}"
            ) from e

        send_term = self._v2_transport.send_garbage_terminator
        version_packet = self._v2_transport.encrypt_message(
            b"", aad=sent_garbage
        )
        try:
            self.writer.write(send_term + version_packet)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            raise V2NegotiationFailed(
                f"write failed during v2 terminator+version send: {e}"
            ) from e

        # 3. Scan incoming bytes for the recv_garbage_terminator (peer's
        # garbage came after their pubkey; same MAX_GARBAGE_LEN bound as
        # the initiator path — net.cpp:1192 ProcessReceivedGarbageBytes).
        recv_term = self._v2_transport.recv_garbage_terminator
        recv_garbage = b""
        try:
            window = await asyncio.wait_for(
                self.reader.readexactly(GARBAGE_TERMINATOR_LEN),
                timeout=10.0,
            )
            while True:
                if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                    recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
                    break
                if len(window) >= MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN:
                    raise V2NegotiationFailed(
                        f"recv_garbage_terminator not seen within "
                        f"{MAX_GARBAGE_LEN} bytes — protocol violation"
                    )
                next_byte = await asyncio.wait_for(
                    self.reader.readexactly(1),
                    timeout=10.0,
                )
                window += next_byte
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 garbage-terminator scan failed (responder): {e}"
            ) from e

        # 5. Drain incoming AEAD packets until we receive a non-decoy
        # version packet.  AAD on the first decrypt is the peer's
        # sent_garbage (== our recv_garbage); subsequent decrypts use
        # empty AAD per net.cpp:1243 ClearShrink.
        next_aad: bytes = recv_garbage
        try:
            for _attempt in range(1024):
                enc_length = await asyncio.wait_for(
                    self.reader.readexactly(LENGTH_FIELD_LEN),
                    timeout=10.0,
                )
                contents_len = self._v2_transport.decrypt_length(enc_length)
                if contents_len > MAX_PROTOCOL_MESSAGE_LENGTH:
                    raise V2NegotiationFailed(
                        f"v2 version-phase packet too large: {contents_len}"
                    )
                aead_len = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
                aead_ct = await asyncio.wait_for(
                    self.reader.readexactly(aead_len),
                    timeout=10.0,
                )
                _payload, is_decoy = self._v2_transport.decrypt_contents(
                    aead_ct, contents_len, aad=next_aad
                )
                next_aad = b""
                if not is_decoy:
                    break
            else:  # pragma: no cover
                raise V2NegotiationFailed(
                    "v2 version drain exceeded 1024 decoy packets"
                )
        except V2NegotiationFailed:
            raise
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, TimeoutError) as e:
            raise V2NegotiationFailed(
                f"v2 version-packet drain failed (responder): {e}"
            ) from e
        except Exception as e:
            raise V2NegotiationFailed(
                f"v2 version-packet decrypt failed (responder): {e}"
            ) from e

        logger.info(
            f"BIP 324 v2 handshake complete (responder) — inbound peer "
            f"{self.host}:{self.port} "
            f"(sent_garbage={len(sent_garbage)}B, recv_garbage={len(recv_garbage)}B)"
        )

    async def _handshake(self, start_height: int):
        """Perform version handshake (outbound connection).

        Message sequence (matching Bitcoin Core net_processing.cpp):
        1. Send VERSION
        2. Receive VERSION
        3. Validate peer version (must be >= MIN_PEER_VERSION for segwit)
        4. Send WTXIDRELAY (BIP 339) if version >= 70016
        5. Send SENDADDRV2 (BIP 155) if version >= 70016
        6. Send VERACK
        7. Receive VERACK -> handshake complete
        """
        self.state = PeerState.HANDSHAKING

        from ouroboros.p2p_messages import (
            FeeFilterMessage,
            SendAddrV2Message,
            SendCmpctMessage,
            SendHeadersMessage,
            WtxidRelayMessage,
        )

        # Create network addresses
        addr_recv = self._create_network_address(self.host, self.port)
        addr_from = self._create_network_address("0.0.0.0", 8333)

        # Send version message
        # Block-relay-only connections set relay=False (BIP 37) to signal
        # that we do not want transaction relay on this connection.
        # Assemble the services we advertise (see _assemble_our_services).
        our_services = self._assemble_our_services()
        self.our_services = our_services
        version_msg = VersionMessage(
            version=70016,
            services=our_services,
            timestamp=int(time.time()),
            addr_recv=addr_recv,
            addr_from=addr_from,
            nonce=self._generate_nonce(),
            user_agent="/ouroboros:0.1.0/",
            start_height=start_height,
            relay=self.relay_txs,
        )

        await self.send_message(version_msg.to_network_message(self.network))
        self._version_sent = True

        # Receive version message with handshake timeout
        msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")

        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        # Seed the live best-known-height from the handshake snapshot.  It is
        # only ever advanced from here (note_block_height); it is the value
        # header-sync peer selection reads, NOT the frozen start_height.
        self.note_block_height(version.start_height)
        self.time_offset = int(version.timestamp - time.time())
        self._version_received = True

        # Reject peers with version < MIN_PEER_VERSION (no segwit support)
        if self.version < MIN_PEER_VERSION:
            raise Exception(
                f"Peer {self.host}:{self.port} version {self.version} < {MIN_PEER_VERSION} "
                "(segwit required)"
            )

        # Validate peer service flags
        if not (self.services & NODE_NETWORK):
            logger.warning(
                f"Peer {self.host}:{self.port} lacks NODE_NETWORK — "
                "may not serve full blocks"
            )
        if not (self.services & NODE_WITNESS):
            logger.warning(
                f"Peer {self.host}:{self.port} lacks NODE_WITNESS — "
                "will not relay witness data"
            )

        # Calculate greatest common version for feature negotiation
        greatest_common_version = min(70016, self.version)

        # BIP 339: Send WTXIDRELAY before VERACK if version >= 70016
        # (must be sent during handshake, not after)
        if greatest_common_version >= 70016 and self.relay_txs:
            try:
                await self.send_message(
                    WtxidRelayMessage().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send wtxidrelay: {e}")

        # BIP 155: Send SENDADDRV2 before VERACK if version >= 70016
        if greatest_common_version >= 70016:
            try:
                await self.send_message(
                    SendAddrV2Message().to_network_message(self.network))
            except Exception as e:
                logger.debug(f"Failed to send sendaddrv2: {e}")

        # Send verack
        verack = NetworkMessage(command="verack", payload=b"", magic=get_magic(self.network))
        await self.send_message(verack)
        self._verack_sent = True

        # Receive verack with handshake timeout.
        # The remote peer may send any of the legal pre-verack negotiation
        # messages (BIP 339 wtxidrelay, BIP 155 sendaddrv2, BIP 330
        # sendtxrcncl) before its verack.  Per bitcoin-core
        # net_processing.cpp ProcessMessage, anything else received before
        # verack is logged and ignored (NOT a disconnect-worthy offense).
        for _attempt in range(20):  # safety bound
            msg = await self.receive_message(timeout=HANDSHAKE_TIMEOUT)
            if msg.command == "verack":
                break
            if msg.command == "wtxidrelay":
                self.wtxid_relay = True
                logger.debug(f"Received wtxidrelay from {self.host}:{self.port} during handshake")
                continue
            if msg.command == "sendaddrv2":
                self.addrv2 = True
                logger.debug(f"Received sendaddrv2 from {self.host}:{self.port} during handshake")
                continue
            if msg.command == "sendtxrcncl":
                # BIP 330: peer is offering Erlay reconciliation.  Mark
                # the peer; the actual salt-exchange handler is wired
                # post-handshake in p2p.py (_register_erlay_handlers).
                # Stash the raw payload so the handler can replay it
                # once the peer transitions to the connected state.
                self.erlay_enabled = True
                self._pending_sendtxrcncl_payload = msg.payload
                logger.debug(f"Received sendtxrcncl from {self.host}:{self.port} during handshake")
                continue
            # Unknown / unsupported pre-verack message.  Match Core
            # behaviour: log and ignore rather than disconnecting,
            # which keeps us forward-compatible with new BIPs.
            logger.debug(
                f"Ignoring unsupported pre-verack message {msg.command!r} "
                f"from {self.host}:{self.port}"
            )
        else:
            raise Exception("Did not receive verack within expected message count")
        self._verack_received = True

        # Handshake is now complete
        self.handshake_complete = True

        # Post-handshake feature negotiation messages
        # These are sent AFTER verack exchange
        try:
            # sendheaders is always sent — we want header announcements
            # even on block-relay-only connections
            await self.send_message(
                SendHeadersMessage().to_network_message(self.network))

            if self.relay_txs:
                # Full-relay peers get the complete feature set
                await self.send_message(
                    SendCmpctMessage(announce=False, version=2).to_network_message(self.network))
                await self.send_message(
                    FeeFilterMessage(feerate=1000).to_network_message(self.network))
            else:
                logger.debug(
                    f"Block-relay-only peer {self.host}:{self.port} — "
                    "skipping sendcmpct/feefilter"
                )
        except Exception as feat_err:
            logger.debug(f"Feature negotiation error (non-fatal): {feat_err}")

    def _create_network_address(self, host: str, port: int) -> NetworkAddress:
        """Create network address from host and port."""
        # NODE_BLOOM advertised iff peer_bloom_filters enabled (Core parity).
        # NODE_COMPACT_FILTERS advertised iff -blockfilterindex AND
        # BlockFilterIndex.is_synced() (FIX-71 / W121 BUG-5).
        # NODE_NETWORK_LIMITED advertised iff prune mode is on (BIP-159).
        our_services = NODE_NETWORK | NODE_WITNESS
        if self.peer_bloom_filters:
            our_services |= NODE_BLOOM
        if self._should_advertise_node_compact_filters():
            our_services |= NODE_COMPACT_FILTERS
        if self.node_network_limited:
            our_services |= NODE_NETWORK_LIMITED

        # .onion addresses — use all-zeros IP (the real routing happens
        # via the SOCKS5 proxy; the version message just needs a valid
        # NetworkAddress structure).
        if is_onion_host(host):
            return NetworkAddress(services=our_services, ip=b'\x00' * 16, port=port)

        # Try to parse as IPv4
        try:
            parts = host.split('.')
            if len(parts) == 4:
                # Validate all parts are integers
                for p in parts:
                    int(p)
                return NetworkAddress.from_ipv4(host, port, services=our_services)
        except (ValueError, AttributeError):
            pass

        # TODO: handle IPv6
        # Default to all zeros (unknown address)
        return NetworkAddress(services=our_services, ip=b'\x00' * 16, port=port)

    async def send_message(self, msg: NetworkMessage):
        """Serialize and write *msg* to the peer (encrypted if BIP 324 v2 is active).

        v1 wire format: 24-byte magic|cmd|len|checksum header + payload.
        v2 wire format: BIP 324 packet whose *contents* are
        ``[short_id (1B) | 0x00 + 12B cmd] + payload`` — the v1 24-byte
        header is NOT included, it is the v1 framing that v2 replaces
        (Core net.cpp:1484-1514 ``V2Transport::SetMessageToSend``).
        """
        if self.state != PeerState.READY and self.state != PeerState.HANDSHAKING:
            raise Exception(f"Cannot send message in state {self.state}")

        if not self.writer:
            raise Exception("Not connected")

        if self._v2_transport is not None:
            # v2 path — strip the v1 24-byte header (do NOT call
            # msg.serialize()).  Build BIP 324 contents from the bare
            # (command, payload) pair, then AEAD-encrypt the packet.
            from ouroboros.transport_v2 import encode_v2_contents
            contents = encode_v2_contents(msg.command, msg.payload)
            data = self._v2_transport.encrypt_message(contents)
        else:
            # v1 path — the legacy magic|cmd|len|checksum frame.
            data = msg.serialize()

        self.writer.write(data)
        await self.writer.drain()

        self.bytes_sent += len(data)
        self.last_send = time.time()

        logger.debug(f"Sent {msg.command} to {self.host}:{self.port}")

    async def _read_exactly(self, n: int) -> bytes:
        """Read exactly ``n`` bytes with NO per-read timeout (Core parity).

        Core (bitcoin-core/src/net.cpp ``V2Transport`` /
        ``SocketHandlerConnected``) arms NO per-read timer at all: it does one
        bounded ``recv`` per socket-readiness event, updates ``m_last_recv``, and
        a SEPARATE coarse per-connection ``CConnman::InactivityCheck``
        (net.cpp:2013) — run once per socket-handler pass, never per packet —
        disconnects a peer whose ``m_last_recv`` is older than ``TIMEOUT_INTERVAL``.

        Attempt-5 mirrors that exactly.  ``_read_exactly`` is a PLAIN
        ``await reader.readexactly(n)``: it arms ZERO ``asyncio.timeout`` /
        ``TimerHandle`` objects regardless of whether the bytes are already
        buffered or the read blocks.  This eliminates the v2-recv RSS-burst leak
        at its root — every prior variant (one timer per read, or one per
        ``receive_message`` call) still armed O(messages) ``TimerHandle``s, and
        ``TimerHandle.cancel()`` only flips ``_cancelled`` without removing the
        handle from ``loop._scheduled``; under steady multi-peer load the
        cancelled-handle purge in ``_run_once`` starves (it only heapify-rebuilds
        when ``_timer_cancelled_count > 100`` AND cancelled/total > 0.5), so the
        cancelled handles creep up monotonically toward the RSS cap (tracemalloc
        at the 4.7 G knee: 1.42 M TimerHandles + 1.42 M readexactly objects).

        On every successful read we stamp ``_last_recv_monotonic`` so the coarse
        sweeper (PeerManager.maintain_connections) can disconnect a genuinely
        stalled peer.  A peer that sends a valid header then hangs mid-payload
        leaves this clock frozen and is disconnected on the next sweep pass —
        the stall-disconnect semantics are preserved, just enforced coarsely
        (bounded number of timers: ZERO on the read path) instead of per read.

        Historical note (do NOT reintroduce): earlier attempts arming
        ``asyncio.timeout`` only when the buffer was empty/short still leaked,
        because under a real flood the buffer is frequently empty between
        readiness events, so the supposedly leak-free fast path armed a timer on
        most reads anyway.  The only zero-timer design is to arm none at all and
        let the coarse sweeper handle stalls (Option A)."""
        # NO asyncio.timeout here — Core parity, zero per-read TimerHandles.
        data = await self.reader.readexactly(n)
        # Stamp the coarse per-connection inactivity clock (Core m_last_recv).
        self._last_recv_monotonic = time.monotonic()
        return data

    def is_recv_stalled(self, stall_timeout: float | None = None) -> bool:
        """True if no wire bytes have arrived within ``stall_timeout`` seconds.

        Coarse per-connection inactivity check — the analogue of Core's
        ``CConnman::InactivityCheck`` recv arm (net.cpp:2046, ``now > last_recv +
        TIMEOUT_INTERVAL``).  Evaluated by the per-node periodic sweeper
        (PeerManager.maintain_connections) once per pass, NEVER per read, so it
        costs zero ``TimerHandle``s on the hot receive path.  ``stall_timeout``
        defaults to ``self._inactivity_timeout`` (Core's TIMEOUT_INTERVAL = 20 min,
        net.h:59) — the WHOLE-CONNECTION idle bound, which MUST exceed the keepalive
        ping cadence (120 s) so a merely-quiet peer is refreshed by its own pong
        before being reaped. (It deliberately does NOT default to ``_read_timeout``,
        the 60 s per-read deadline; reusing that as the reaper window inverted the
        Core relationship and churned every quiet peer each sweep.) A 60 s
        post-connect grace mirrors Core ShouldRunInactivityChecks so the handshake
        window is never swept."""
        if stall_timeout is None:
            stall_timeout = self._inactivity_timeout
        # Don't reap during the first 60 s after connect (handshake window).
        if (time.monotonic() - self._connected_monotonic) <= 60.0:
            return False
        return (time.monotonic() - self._last_recv_monotonic) > stall_timeout

    async def receive_message(self, timeout: float = 30.0) -> NetworkMessage:
        """Read and parse the next message from the peer (v1 or BIP 324 v2); raises on timeout or bad format."""
        if not self.reader:
            raise Exception("Not connected")

        # v2 encrypted path
        if self._v2_transport is not None:
            return await self._receive_v2_message(timeout)

        # v1 plaintext path
        # NO per-read AND no call-spanning timeout (attempt-5, Core parity).
        # ``_read_exactly`` is a plain ``await readexactly`` that arms ZERO
        # ``asyncio.timeout`` / ``TimerHandle`` objects — Core's net.cpp recv
        # path arms none either (one bounded recv per readiness event; the only
        # recv timeout is the COARSE per-connection ``CConnman::InactivityCheck``
        # @net.cpp:2013, run once per socket-handler pass).  A buffered flood of
        # N valid messages therefore arms ZERO timers (both the 24 B header read
        # @ ~L1700 and the payload read @ ~L1740 are plain awaits), eliminating
        # the cancelled-TimerHandle accumulation that every prior variant
        # incurred (two per message originally, one per message after attempt-3,
        # still O(N)).  A genuine mid-message stall is caught by the per-node
        # sweeper (PeerManager.maintain_connections -> Peer.is_recv_stalled):
        # a peer that sends a valid header then hangs mid-payload leaves
        # ``_last_recv_monotonic`` frozen, so the next sweep pass disconnects it.
        # ``timeout`` is still recorded as the stall threshold the sweeper uses.
        self._read_timeout = timeout

        header = await self._read_exactly(24)

        # Parse header
        magic, command_bytes, length, checksum = struct.unpack('<I12sI4s', header)

        # Verify magic bytes FIRST — if wrong, the stream is desynchronised
        # (e.g. we read into the middle of a previous payload) or the peer
        # truly switched to v2.  Either way the connection is unrecoverable.
        # These V2TransportError / desync exceptions are raised in untimed parse
        # code, so they propagate unchanged (never rewritten to TimeoutError) —
        # listen()'s handlers and the v1-fallback path stay correct.
        expected_magic = get_magic(self.network)
        if magic != expected_magic:
            # Check if this could be a genuine BIP 324 v2 negotiation
            # (only plausible on the very first message exchange).
            try:
                command_bytes.rstrip(b'\x00').decode('ascii')
            except UnicodeDecodeError:
                raise V2TransportError(
                    f"Peer {self.host}:{self.port} appears to use v2 transport, "
                    f"disconnecting gracefully"
                ) from None
            raise Exception(
                f"Invalid magic bytes from {self.host}:{self.port}: "
                f"expected {expected_magic:08x}, got {magic:08x} — stream desync"
            )

        try:
            command = command_bytes.rstrip(b'\x00').decode('ascii')
        except UnicodeDecodeError as exc:
            # Magic was correct but command is non-ASCII — this is a stream
            # framing error, NOT v2 transport.  Raise a normal exception so
            # the score-based handling can decide whether to disconnect.
            raise Exception(
                f"Non-ASCII command bytes from {self.host}:{self.port} "
                f"(likely stream desync): {command_bytes!r}"
            ) from exc

        # Read payload — its own per-read stall bound via _read_exactly, so a
        # peer that sends a valid header then stalls mid-payload still times out.
        payload = b''
        if length > 0:
            if length > MAX_PROTOCOL_MESSAGE_LENGTH:  # Core net.h MAX_PROTOCOL_MESSAGE_LENGTH
                raise Exception(f"Payload too large: {length} bytes")

            payload = await self._read_exactly(length)

        # Verify checksum
        expected_checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        if checksum != expected_checksum:
            raise Exception(f"Checksum mismatch for {command}")

        logger.debug(f"Received {command} from {self.host}:{self.port} ({len(payload)} bytes)")

        self.bytes_recv += 24 + len(payload)
        self.last_recv = time.time()

        return NetworkMessage(command=command, payload=payload, magic=magic)

    async def _receive_v2_message(self, timeout: float) -> NetworkMessage:
        """Receive and decrypt a BIP 324 v2 packet.

        Wire layout per BIP 324 (bitcoin-core/src/bip324.h):
          enc_length         3 bytes (FSChaCha20-encrypted u24, no auth tag)
          ciphertext         1 byte header + contents + 16-byte Poly1305 tag

        Decoy packets (header byte high bit set) are silently dropped and
        the read loops to the next packet.
        """
        from ouroboros.p2p_messages import get_magic
        from ouroboros.transport_v2 import (
            CHACHA20POLY1305_EXPANSION,
            HEADER_LEN,
            LENGTH_FIELD_LEN,
            decode_v2_contents,
        )

        wire_bytes_this_call = 0
        consecutive_skipped = 0
        # NO per-read AND no call-spanning timeout (attempt-5, Core parity).
        # Every wire read goes through ``_read_exactly``, which is a plain
        # ``await readexactly`` arming ZERO ``asyncio.timeout`` / ``TimerHandle``
        # objects.
        #
        # ROOT CAUSE of the v2-recv RSS burst (tracemalloc at the 4.7 G knee,
        # captures armed 2026-06-12): EVERY prior variant armed O(messages)
        # timers — the original two per packet, attempt-3 one per packet/call,
        # attempt-4 one per BLOCKED read.  Under a buffered VALID-message flood
        # ``readexactly`` returns SYNCHRONOUSLY (the StreamReader buffer already
        # holds the bytes), so the timer never fires and the context cancels it —
        # but ``TimerHandle.cancel()`` only flips ``_cancelled``; it does NOT
        # remove the handle from ``BaseEventLoop._scheduled``.  The purge runs
        # only in ``_run_once`` and (a) cheaply pops only handles at the heap
        # ROOT, (b) heapify-rebuilds only when ``_timer_cancelled_count > 100``
        # AND the cancelled fraction crosses 0.5.  Under steady multi-peer load a
        # cancelled handle stays BURIED mid-heap below still-live timers and
        # never reaches the root — so the cancelled TimerHandles (each retaining
        # callback -> Timeout -> task -> coroutine -> readexactly-bytes) creep up
        # monotonically (1.42 M TimerHandles + 1.42 M readexactly objects at the
        # knee).  Even attempt-4's "arm only when blocked" leaked, because under
        # a real flood the StreamReader buffer is frequently empty between
        # readiness events, so most reads still armed a timer.
        #
        # FIX = Core parity, ZERO timers.  Core's V2Transport (net.cpp
        # SocketHandlerConnected -> ReceivedBytes) arms NO per-read timer at all:
        # one bounded recv per socket-readiness event and a bounded consume loop;
        # the only recv-path timeout is the COARSE per-CONNECTION
        # ``CConnman::InactivityCheck`` (net.cpp:2013), never per packet.  So a
        # buffered burst of N packets (decoy/unknown skips inside one call) arms
        # ZERO TimerHandles.  A genuine mid-packet stall is caught by the per-node
        # sweeper (PeerManager.maintain_connections -> Peer.is_recv_stalled): a
        # peer that sends the 3 length bytes then hangs leaves
        # ``_last_recv_monotonic`` frozen, so the next sweep pass disconnects it.
        # Per-call packet count is bounded by MAX_CONSECUTIVE_V2_SKIP, so a
        # slow-drip decoy peer cannot hold the call open beyond a bounded skip
        # run.  ``timeout`` is recorded as the stall threshold the sweeper uses.
        self._read_timeout = timeout
        while True:
            # Read the 3-byte encrypted length prefix (no auth tag — the
            # length cipher is plain FSChaCha20, not AEAD; the contents
            # cipher's Poly1305 covers the body).
            enc_length = await self._read_exactly(LENGTH_FIELD_LEN)
            wire_bytes_this_call += LENGTH_FIELD_LEN

            try:
                contents_len = self._v2_transport.decrypt_length(enc_length)
            except Exception as e:
                raise V2TransportError(
                    f"v2 length decrypt failed for {self.host}:{self.port}: {e}"
                ) from e

            if contents_len > MAX_PROTOCOL_MESSAGE_LENGTH:
                raise Exception(f"v2 payload too large: {contents_len} bytes")

            # Read the AEAD-encrypted body: HEADER_LEN + contents_len + tag.
            aead_len = HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
            aead_ct = await self._read_exactly(aead_len)
            wire_bytes_this_call += aead_len

            try:
                contents, is_decoy = self._v2_transport.decrypt_contents(
                    aead_ct, contents_len
                )
            except Exception as e:
                raise V2TransportError(
                    f"v2 contents decrypt failed for {self.host}:{self.port}: {e}"
                ) from e

            self.bytes_recv += wire_bytes_this_call
            self.last_recv = time.time()

            if is_decoy:
                # Decoy packets count against bytes_recv because the wire
                # bytes were real — the decoder just throws them away.
                logger.debug(f"Discarded decoy packet from {self.host}:{self.port}")
                consecutive_skipped += 1
                if consecutive_skipped > MAX_CONSECUTIVE_V2_SKIP:
                    raise V2TransportError(
                        f"v2: too many consecutive decoy/unknown packets "
                        f"from {self.host}:{self.port} "
                        f"(>{MAX_CONSECUTIVE_V2_SKIP}) — disconnecting"
                    )
                # Yield to the event loop so the cyclic GC and other peers'
                # coroutines run instead of spinning on a buffered burst of
                # decoys.  (Per-read _read_exactly already eliminated the
                # TimerHandle churn that 964419c's periodic yield was working
                # around — this sleep(0) is now ONLY about cooperative
                # scheduling on the skip path, not timer purge.)
                await asyncio.sleep(0)
                continue

            # BIP 324 contents = (1B short_id | 0x00+12B cmd) + payload.
            # The v1 24-byte header is NOT present (Core net.cpp:1415-1453
            # ``V2Transport::GetMessageType``).
            decoded = decode_v2_contents(contents)
            if decoded is None:
                # Unknown short ID or malformed long form — Core drops the
                # message but keeps the connection (net.cpp:1474-1477).
                # We mirror that, but loop to read the next packet.
                logger.debug(
                    f"v2: dropping packet with unknown/invalid type prefix "
                    f"from {self.host}:{self.port} ({contents_len} bytes)"
                )
                consecutive_skipped += 1
                if consecutive_skipped > MAX_CONSECUTIVE_V2_SKIP:
                    raise V2TransportError(
                        f"v2: too many consecutive decoy/unknown packets "
                        f"from {self.host}:{self.port} "
                        f"(>{MAX_CONSECUTIVE_V2_SKIP}) — disconnecting"
                    )
                # Yield to the event loop (cooperative scheduling on the
                # unknown-skip path — see decoy branch above).
                await asyncio.sleep(0)
                continue

            command, payload = decoded
            return NetworkMessage(
                command=command,
                payload=payload,
                magic=get_magic(self.network),
            )

    def _is_handshake_message(self, command: str) -> bool:
        """Check if message is allowed during handshake (before handshake_complete)."""
        # Bitcoin Core net_processing.cpp: only version/verack/wtxidrelay/sendaddrv2
        # are allowed before handshake completes
        return command in ("version", "verack", "wtxidrelay", "sendaddrv2")

    async def listen(self):
        """Message receive loop: dispatches to registered handlers until disconnected.

        Pre-handshake filtering: If handshake_complete is False, only accept
        VERSION, VERACK, WTXIDRELAY, and SENDADDRV2 messages. All other messages
        are dropped/ignored per Bitcoin Core's net_processing.cpp behavior.
        """
        # Cooperative-scheduling backstop for the at-tip valid-message flood.
        # The per-packet TimerHandle leak is now gone (receive_message arms a
        # SINGLE outer asyncio.timeout per message for BOTH v1 and v2 — see
        # _receive_v2_message / the v1 path — instead of one timer per read), so
        # this is NO LONGER about purging cancelled timers.  But a high-rate
        # flood of VALID pre-buffered messages still returns one message per
        # receive_message call and loops straight back in (readexactly satisfied
        # synchronously from the StreamReader buffer), which could spin this
        # loop CPU-bound without ever yielding to other peers or the cyclic GC.
        # So we yield every V2_RECV_YIELD_EVERY messages here to preserve fair
        # scheduling — mirroring Core's bounded-work-per-readiness posture
        # (net.cpp SocketHandlerConnected processes a bounded recv then returns
        # to the selector).  The counter advances once per dispatched message.
        try:
            while self.state == PeerState.READY:
                try:
                    msg = await self.receive_message(timeout=60.0)

                    self._recv_since_yield += 1
                    if self._recv_since_yield >= V2_RECV_YIELD_EVERY:
                        self._recv_since_yield = 0
                        await asyncio.sleep(0)

                    # Pre-handshake message filtering (Phase 16)
                    # Should not normally happen since listen() starts after
                    # handshake, but included for safety and protocol correctness
                    if not self.handshake_complete:
                        if not self._is_handshake_message(msg.command):
                            logger.warning(
                                f"Dropping non-handshake message '{msg.command}' "
                                f"before handshake complete from {self.host}:{self.port}"
                            )
                            self.adjust_score(-10)
                            continue

                    # Handle feature negotiation messages (BIP 339, BIP 155)
                    # These can arrive after VERACK but we still track them
                    if msg.command == "wtxidrelay":
                        if self.handshake_complete:
                            # Per BIP 339, wtxidrelay must be sent before VERACK
                            # If received after, Bitcoin Core disconnects
                            logger.warning(
                                f"wtxidrelay received after verack from "
                                f"{self.host}:{self.port}, ignoring"
                            )
                        else:
                            self.wtxid_relay = True
                            logger.debug(f"Peer {self.host}:{self.port} supports wtxid relay")
                        continue

                    if msg.command == "sendaddrv2":
                        if self.handshake_complete:
                            # Per BIP 155, sendaddrv2 must be sent before VERACK
                            logger.warning(
                                f"sendaddrv2 received after verack from "
                                f"{self.host}:{self.port}, ignoring"
                            )
                        else:
                            self.addrv2 = True
                            logger.debug(f"Peer {self.host}:{self.port} supports addrv2")
                        continue

                    # Handle ping/pong automatically
                    if msg.command == "ping":
                        ping = PingMessage.from_payload(msg.payload)
                        pong = PongMessage(nonce=ping.nonce)
                        pong_msg = pong.to_network_message(self.network)
                        await self.send_message(pong_msg)
                        continue

                    if msg.command == "pong":
                        pong = PongMessage.from_payload(msg.payload)
                        if self.last_ping > 0:
                            self.latency = time.time() - self.last_ping
                            logger.debug(
                                f"Pong from {self.host}:{self.port} - "
                                f"latency: {self.latency:.3f}s"
                            )
                        continue

                    # Dispatch to handler
                    if msg.command in self.message_handlers:
                        try:
                            await self.message_handlers[msg.command](msg)
                        except Exception as e:
                            logger.error(
                                f"Error in handler for {msg.command} "
                                f"from {self.host}:{self.port}: {e}"
                            )
                    else:
                        logger.debug(
                            f"No handler for {msg.command} from {self.host}:{self.port}"
                        )

                except TimeoutError:
                    # Timeout is normal, just continue listening
                    logger.debug(f"Receive timeout from {self.host}:{self.port}")
                    continue

                except (asyncio.IncompleteReadError, EOFError,
                        ConnectionResetError, ConnectionError,
                        BrokenPipeError, OSError) as e:
                    # The socket is closed / half-closed: a peer that hung up
                    # makes ``readexactly`` raise ``IncompleteReadError``
                    # (subclass of ``EOFError``) immediately and forever — it
                    # never blocks once the stream is at EOF.  The generic
                    # ``except Exception`` below only docks score and ``continue``s,
                    # so a hung-up peer spun the receive loop ~20 times back-to-
                    # back (each iteration re-reading EOF instantly, allocating an
                    # exception + a formatted log line) before the score finally
                    # clamped to 0.  At chain tip, where peers churn constantly,
                    # that hot-spin + per-iteration allocation churn was a steady
                    # RSS/CPU drain.  Treat EOF / dead-socket the way Bitcoin Core
                    # does in ``CConnman::SocketHandler`` (``nBytes == 0`` ⇒
                    # disconnect immediately) — close and break, do NOT spin.
                    logger.info(
                        f"Peer {self.host}:{self.port} closed the connection "
                        f"(EOF/socket error: {type(e).__name__}: {e})"
                    )
                    await self.disconnect()
                    break

                except V2TransportError as e:
                    # Peer speaks v2 transport but we parsed as v1 —
                    # disconnect gracefully without score penalty (same
                    # behaviour as Bitcoin Core, see net.cpp).
                    logger.info(str(e))
                    await self.disconnect()
                    break

                except Exception as e:
                    logger.error(
                        f"Error receiving message from {self.host}:{self.port}: {e}"
                    )
                    # Don't disconnect on single message error, but adjust score
                    self.adjust_score(-5)
                    if self.score <= 0:
                        await self.disconnect()
                        break

        except asyncio.CancelledError:
            logger.info(f"Peer {self.host}:{self.port} listener cancelled")
        except Exception as e:
            logger.error(f"Error in peer {self.host}:{self.port} listener: {e}")
            await self.disconnect()

    async def _ping_loop(self):
        try:
            while self.state == PeerState.READY:
                await asyncio.sleep(120.0)  # Ping every 2 minutes
                if self.state == PeerState.READY:
                    await self.ping()
        except asyncio.CancelledError:
            logger.debug(f"Ping loop cancelled for {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Error in ping loop for {self.host}:{self.port}: {e}")

    def register_handler(self, command: str, handler: Callable):
        """Register *handler* to be called when a message with *command* is received."""
        self.message_handlers[command] = handler
        logger.debug(f"Registered handler for {command} on {self.host}:{self.port}")

    def note_block_height(self, height: int) -> None:
        """Record that this peer has revealed knowledge of a block at *height*.

        Advances ``best_known_height`` monotonically.  Called from the
        block-sync handlers whenever the peer reveals a higher tip via a
        ``headers`` batch, a block ``inv`` for a block already in our index,
        or a delivered ``block`` whose height we know.  This is ouroboros'
        analogue of Bitcoin Core's ``UpdateBlockAvailability`` /
        ``ProcessBlockAvailability`` (net_processing.cpp:1360,1375), which
        keep ``CNodeState::pindexBestKnownBlock`` current so the block-fetch
        scheduler never relies on the frozen handshake ``nStartingHeight``.

        Idempotent and never decreasing — passing a height at or below the
        current best is a no-op.
        """
        try:
            h = int(height)
        except (TypeError, ValueError):
            return
        if h > self.best_known_height:
            self.best_known_height = h

    async def ping(self):
        """Send ping to peer"""
        nonce = self._generate_nonce()
        self.last_ping = time.time()
        ping = PingMessage(nonce=nonce)
        ping_msg = ping.to_network_message(self.network)
        await self.send_message(ping_msg)
        logger.debug(f"Sent ping to {self.host}:{self.port}")

    async def disconnect(self):
        """Disconnect from peer"""
        if getattr(self, "_disconnect_started", False):
            return
        self._disconnect_started = True
        logger.info(f"Disconnecting from {self.host}:{self.port}")

        self.state = PeerState.DISCONNECTED

        current = asyncio.current_task()

        # Cancel tasks.  If disconnect() was invoked from inside
        # _listen_task or _ping_task (e.g. the listener's own
        # `except Exception: await self.disconnect()` path), skip the
        # await — a task cannot await itself, and asyncio raises
        # `RuntimeError: await wasn't used with future` if we try.
        # The task is still cancelled on its way out.
        if self._listen_task and self._listen_task is not current:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass

        if self._ping_task and self._ping_task is not current:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass

        # Close connection
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing connection to {self.host}:{self.port}: {e}")

        self.reader = None
        self.writer = None

        # Event-driven per-peer cleanup hook.  Fires exactly once per Peer
        # instance after the socket is torn down.  PeerManager wires this
        # to ``_handle_peer_disconnected(addr)`` which (a) pops the peer
        # from whichever of ``peers`` / ``block_relay_peers`` /
        # ``inbound_peers`` holds it and (b) calls ``_cleanup_peer_state``
        # to drop the per-addr caches (trickle queue, erlay state, sync
        # bookkeeping, block_sync handler closures, ...).  Before this
        # hook the cleanup ran only when ``maintain_connections`` polled
        # every 30 s and observed ``is_connected() == False``; the audit
        # of 2026-05-28 measured the poll catching only 1 of 1497
        # disconnects in a 16 h window, with the rest leaking ~6-10 GB
        # of zombie Peer + transport-buffer state.
        if self._on_disconnect is not None and not self._on_disconnect_fired:
            self._on_disconnect_fired = True
            cb = self._on_disconnect
            addr = f"{self.host}:{self.port}"
            try:
                cb(addr)
            except Exception as exc:
                # Cleanup must never block teardown.  Log loudly so the
                # operator notices but let the socket teardown finish.
                logger.error(
                    "on_disconnect callback raised for %s: %r", addr, exc
                )

    def _generate_nonce(self) -> int:
        return random.randint(0, 2**64 - 1)

    def adjust_score(self, delta: int):
        """Adjust the peer's reputation score by *delta* (result clamped to [0, 100]).

        When the score clamps at 0 we route the peer through the
        BanManager (if one was supplied) which (a) records the host as
        banned for the configured ban duration and (b) fires the
        manager's on_ban callback — that callback is responsible for
        removing the peer from PeerManager's dict and scheduling
        ``peer.disconnect()``.

        Prior to this change ``adjust_score`` was log-only at the clamp,
        so a misbehaving peer was never disconnected and would re-trip
        the WARNING every cycle.  See
        wave3-2026-04-14/OUROBOROS-PEER-TIMEOUT-DIAG.md (Lever 1) — one
        peer emitted 537 "banned" lines in 43 minutes without ever being
        evicted.

        ``adjust_score`` remains synchronous; the on_ban callback uses
        ``asyncio.ensure_future(peer.disconnect())`` so the caller does
        not need to await anything and may assume the peer object is
        still safe to reference (its socket may close shortly afterward).
        """
        self.score = max(0, min(100, self.score + delta))
        if self.score == 0 and not self._ban_recorded:
            self._ban_recorded = True
            if self.ban_manager is not None:
                # Idempotent: BanManager.ban() updates banned[host] and
                # invokes _on_peer_banned which closes the socket and
                # removes the peer from PeerManager.peers.  We use the
                # latch above so we never call this twice for the same
                # Peer instance.
                ban_count = len(self.ban_manager.banned) + 1
                logger.warning(
                    f"Disconnecting peer {self.host}:{self.port} after "
                    f"score clamp (ban count={ban_count})"
                )
                try:
                    self.ban_manager.ban(self.host)
                except Exception as exc:  # never let bookkeeping crash the loop
                    logger.error(
                        f"BanManager.ban failed for {self.host}: {exc}"
                    )
            else:
                # Fallback: no manager wired in (e.g. unit tests with a
                # bare Peer).  Preserve the original observable behaviour.
                logger.warning(
                    f"Peer {self.host}:{self.port} banned (score=0)"
                )

    def is_connected(self) -> bool:
        """Check if peer is connected and ready"""
        return self.state == PeerState.READY

    def __repr__(self) -> str:
        direction = "in" if self.inbound else "out"
        relay = "block-only" if not self.relay_txs else "full"
        return f"Peer({self.host}:{self.port}, {direction}, {relay}, state={self.state.name}, score={self.score})"
