"""
Peer-to-peer networking module.

This module implements peer discovery, connection management, and peer scoring
for the Bitcoin P2P network.
"""

import asyncio
import base64
import socket
import random
import time
import logging
from typing import List, Dict, Set, Optional
from collections import defaultdict

from ouroboros.peer import Peer, PeerState, RelayType, is_onion_host
from ouroboros.p2p_messages import (
    NetworkMessage, SendCmpctMessage, CmpctBlockMessage,
    GetBlockTxnMessage, BlockTxnMessage,
    AddrMessage, AddrV2Message, GetAddrMessage,
    SendTxRcnclMessage, ReqTxRcnclMessage, SketchMessage,
    ReconcilDiffMessage, InvMessage, INV_TYPE_TX,
)
from ouroboros.minisketch import (
    Minisketch, ReconciliationSet, estimate_sketch_capacity,
    compute_short_txid,
)
from ouroboros.banman import (
    BanManager,
    SCORE_INVALID_BLOCK,
    SCORE_INVALID_HEADERS,
    SCORE_INVALID_TX,
    SCORE_UNREQUESTED_DATA,
)
from ouroboros.addrman import AddressManager

logger = logging.getLogger(__name__)

# DNS seeds for mainnet
DNS_SEEDS_MAINNET = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
]

# DNS seeds for testnet
DNS_SEEDS_TESTNET = [
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.org",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
]


MAX_INBOUND = 117  # Bitcoin Core default max inbound connections

# Bitcoin Core maintains 2 additional outbound connections that relay only
# blocks (no transactions, no addr gossip).  These protect against eclipse
# attacks by increasing the number of independent peers that can announce
# new blocks to us.
MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2


class PeerManager:
    """Manages peer connections and discovery"""

    def __init__(
        self,
        network: str = "mainnet",
        max_peers: int = 8,
        max_block_relay_only: int = MAX_BLOCK_RELAY_ONLY_CONNECTIONS,
        data_dir: Optional[str] = None,
        transport_version: int = 1,
        listen: bool = True,
        proxy: Optional[str] = None,
        onion: Optional[str] = None,
    ):
        """Initialize peer manager."""
        self.network = network
        self.max_peers = max_peers
        self.max_block_relay_only = max_block_relay_only
        self.transport_version = transport_version
        self._listen_enabled = listen
        self.proxy = proxy    # global SOCKS5 proxy for all outbound
        self.onion = onion    # SOCKS5 proxy specifically for .onion peers

        self.peers: Dict[str, Peer] = {}  # addr -> Peer (full-relay outbound)
        self.block_relay_peers: Dict[str, Peer] = {}  # addr -> Peer (block-relay-only outbound)
        self.inbound_peers: Dict[str, Peer] = {}  # addr -> Peer (inbound)
        self.known_addrs: Set[str] = set()

        self.ban_manager = BanManager(
            data_dir=data_dir,
            on_ban=self._on_peer_banned,
        )

        # Connection retry tracking (addr -> retry_count)
        self.retry_counts: Dict[str, int] = defaultdict(int)
        self.last_retry_time: Dict[str, float] = {}

        self.running = False
        self._maintenance_task: Optional[asyncio.Task] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._start_height: int = 0

        # Callback for registering handlers on newly accepted inbound peers
        self._on_inbound_peer: Optional[asyncio.coroutines] = None

        # Address manager for peer gossip
        self.addrman = AddressManager(data_dir=data_dir)

        # Per-peer rate limiting for addr relay (addr -> last relay epoch)
        self._addr_relay_counts: Dict[str, int] = defaultdict(int)
        self._addr_relay_day: Dict[str, float] = {}

        # BIP 152 compact-block state
        self.compact_block_version: int = 2
        self.cmpct_peers: Set[str] = set()
        self._mempool = None
        self._on_compact_block = None

        # BIP 330 Erlay reconciliation state
        self.erlay_enabled: bool = True  # whether we support Erlay
        self._erlay_peers: Dict[str, ReconciliationSet] = {}  # addr -> recon set
        self._erlay_local_salts: Dict[str, int] = {}  # addr -> our salt
        self._erlay_pending_recon: Dict[str, bool] = {}  # addr -> recon in progress
        self._reconciliation_task: Optional[asyncio.Task] = None
        self._reconciliation_interval: float = 2.0  # seconds between rounds
    
    async def start(self, start_height: int = 0, p2p_port: int = 0):
        """
        Start peer manager.

        Args:
            start_height: Our blockchain height for version messages
            p2p_port: Port to listen on for inbound connections (0 = default)
        """
        if self.running:
            logger.warning("PeerManager already running")
            return

        self.running = True
        self._start_height = start_height
        logger.info(f"Starting PeerManager for {self.network} (max_peers={self.max_peers})")

        # Start listening for inbound connections
        if self._listen_enabled and p2p_port:
            await self._start_listening(p2p_port)

        # Discover peers from DNS seeds
        await self.discover_peers()

        # Connect to full-relay outbound peers
        await self.connect_to_peers(start_height)

        # Connect to block-relay-only outbound peers
        await self._connect_block_relay_peers(start_height)

        # Start maintenance task
        self._maintenance_task = asyncio.create_task(
            self.maintain_connections(start_height)
        )

        # Start Erlay reconciliation loop
        if self.erlay_enabled:
            self._reconciliation_task = asyncio.create_task(
                self._reconciliation_loop()
            )
    
    async def stop(self):
        """Stop peer manager and disconnect all peers"""
        if not self.running:
            return

        logger.info("Stopping PeerManager...")
        self.running = False

        # Stop listening server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel maintenance task
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass

        # Cancel reconciliation task
        if self._reconciliation_task:
            self._reconciliation_task.cancel()
            try:
                await self._reconciliation_task
            except asyncio.CancelledError:
                pass

        # Disconnect all peers (full-relay + block-relay-only + inbound)
        all_peers = (
            list(self.peers.values())
            + list(self.block_relay_peers.values())
            + list(self.inbound_peers.values())
        )
        disconnect_tasks = [peer.disconnect() for peer in all_peers]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)

        self.peers.clear()
        self.block_relay_peers.clear()
        self.inbound_peers.clear()

        # Persist address manager
        self.addrman.save()

        logger.info("PeerManager stopped")

    # Inbound eviction logic

    @staticmethod
    def _netgroup(host: str) -> str:
        if is_onion_host(host):
            return "onion"
        parts = host.split(".")
        if len(parts) == 4:
            try:
                int(parts[0])
                int(parts[1])
                return f"{parts[0]}.{parts[1]}"
            except ValueError:
                pass
        # TODO: handle IPv6 addresses (they share a /48 netgroup in Bitcoin Core)
        return host  # non-IPv4 — use entire host as its own group

    def _select_eviction_candidate(self) -> Optional[str]:
        """Select the worst inbound peer for eviction."""
        # Build candidate list: [(addr, peer), ...]
        candidates = [
            (addr, peer) for addr, peer in self.inbound_peers.items()
            if peer.is_connected()
        ]

        if not candidates:
            return None

        # Step 2 — Protect 4 with lowest latency
        # Peers with latency == 0 haven't been measured yet; sort them last.
        candidates.sort(
            key=lambda ap: ap[1].latency if ap[1].latency > 0 else float("inf")
        )
        candidates = candidates[4:]  # remove the 4 best-latency peers

        if not candidates:
            return None

        # Step 3 — Protect 4 with highest score (proxy for upload volume)
        candidates.sort(key=lambda ap: ap[1].score, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 4 — Protect 4 with most recent block relay activity
        candidates.sort(key=lambda ap: ap[1].last_block_time, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 5 — Protect up to 4 from unique /16 netgroups
        seen_groups: set = set()
        protected_netgroup: list = []
        for addr, peer in candidates:
            group = self._netgroup(peer.host)
            if group not in seen_groups and len(protected_netgroup) < 4:
                seen_groups.add(group)
                protected_netgroup.append(addr)
        candidates = [
            (a, p) for a, p in candidates if a not in protected_netgroup
        ]

        if not candidates:
            return None

        # Step 6 — Protect 4 most recently connected
        candidates.sort(key=lambda ap: ap[1].connected_at, reverse=True)
        candidates = candidates[4:]

        if not candidates:
            return None

        # Step 7 — From remaining, evict the one connected longest
        candidates.sort(key=lambda ap: ap[1].connected_at)
        return candidates[0][0]

    async def _evict_inbound_peer(self) -> bool:
        victim_addr = self._select_eviction_candidate()
        if victim_addr is None:
            return False

        victim = self.inbound_peers.pop(victim_addr, None)
        if victim is not None:
            logger.info(f"Evicting inbound peer {victim_addr} to make room")
            await victim.disconnect()
            return True
        return False

    # Inbound connection handling

    async def _start_listening(self, port: int):
        try:
            self._server = await asyncio.start_server(
                self._handle_inbound_connection,
                host="0.0.0.0",
                port=port,
            )
            logger.info(f"Listening for inbound connections on port {port}")
        except OSError as e:
            logger.warning(f"Failed to listen on port {port}: {e}")

    async def _handle_inbound_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Callback for each new inbound TCP connection."""
        peername = writer.get_extra_info("peername")
        if not peername:
            writer.close()
            return
        host, port = peername[0], peername[1]
        addr = f"{host}:{port}"

        # Check ban list
        if self.ban_manager.is_banned(host) or self.ban_manager.is_banned(addr):
            logger.debug(f"Rejected banned inbound peer {addr}")
            writer.close()
            return

        # Check inbound limit — try to evict the worst peer first
        if len(self.inbound_peers) >= MAX_INBOUND:
            if not await self._evict_inbound_peer():
                logger.debug(f"Rejected inbound peer {addr}: max inbound reached, no eviction candidate")
                writer.close()
                return

        logger.info(f"New inbound connection from {addr}")

        peer = Peer(host, port, self.network, inbound=True)
        if await peer.accept_inbound(reader, writer, self._start_height):
            self.inbound_peers[addr] = peer
            self._register_compact_handlers(peer, addr)
            self._register_addr_handlers(peer, addr)
            asyncio.ensure_future(self.negotiate_compact_blocks(peer))
            # Negotiate Erlay for inbound peers
            if self.erlay_enabled:
                self._register_erlay_handlers(peer, addr)
                asyncio.ensure_future(self._negotiate_erlay(peer, addr))

            # Notify node so it can register tx/getdata handlers
            if self._on_inbound_peer:
                try:
                    await self._on_inbound_peer(peer)
                except Exception as e:
                    logger.error(f"Error in inbound peer callback: {e}")

            logger.info(
                f"Inbound peer {addr} ready "
                f"({len(self.inbound_peers)} inbound)"
            )

    def set_inbound_peer_handler(self, handler) -> None:
        """Register an async callback invoked when an inbound peer completes
        its handshake.  ``handler(peer: Peer) -> None``."""
        self._on_inbound_peer = handler
    
    async def discover_peers(self):
        """Discover peers from DNS seeds"""
        logger.info("Discovering peers from DNS seeds...")
        
        seeds = (
            DNS_SEEDS_MAINNET if self.network == "mainnet"
            else DNS_SEEDS_TESTNET if self.network == "testnet"
            else []
        )
        
        if not seeds:
            logger.warning(f"No DNS seeds configured for {self.network}")
            return
        
        port = 8333 if self.network == "mainnet" else 18333  # XXX: not sure this handles testnet4 correctly

        # Resolve DNS seeds in parallel
        tasks = [self._resolve_dns_seed(seed, port) for seed in seeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        total_discovered = 0
        for seed, result in zip(seeds, results):
            if isinstance(result, Exception):
                logger.warning(f"Failed to resolve {seed}: {result}")
            else:
                count = result
                total_discovered += count
                logger.info(f"Discovered {count} peers from {seed}")
        
        logger.info(f"Total known peers: {len(self.known_addrs)}")
    
    async def _resolve_dns_seed(self, seed: str, port: int) -> int:
        """Resolve DNS seed and add addresses to known_addrs."""
        try:
            # Use asyncio to resolve DNS (non-blocking)
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(
                seed,
                port,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )
            
            count = 0
            for addr_info in addrs:
                ip = addr_info[4][0]
                addr = f"{ip}:{port}"
                if not self.ban_manager.is_banned(addr):
                    self.known_addrs.add(addr)
                    self.addrman.add(ip, port, source=seed)
                    count += 1

            return count
            
        except Exception as e:
            logger.debug(f"Error resolving {seed}: {e}")
            return 0
    
    def _proxy_for_host(self, host: str) -> Optional[str]:
        if is_onion_host(host):
            return self.onion or self.proxy
        return self.proxy

    def _all_outbound_addrs(self) -> Set[str]:
        return set(self.peers.keys()) | set(self.block_relay_peers.keys())

    async def connect_to_peers(self, start_height: int = 0):
        """Connect to full-relay peers up to max_peers."""
        while len(self.peers) < self.max_peers and self.known_addrs:
            # Get available addresses (not already connected, not banned)
            available = (
                self.known_addrs
                - self._all_outbound_addrs()
                - {a for a in self.known_addrs if self.ban_manager.is_banned(a)}
            )

            if not available:
                break

            # Pick random peer
            addr = random.choice(list(available))

            # Check exponential backoff
            if not self._should_retry(addr):
                continue

            # Try to connect (full-relay: relay_txs=True)
            host, port = addr.split(':')

            # Determine proxy — .onion peers require a SOCKS5 proxy
            peer_proxy = self._proxy_for_host(host)
            if is_onion_host(host) and not peer_proxy:
                logger.debug(f"Skipping .onion peer {addr}: no proxy configured")
                continue

            peer = Peer(host, int(port), self.network,
                        transport_version=self.transport_version, relay_txs=True,
                        proxy=peer_proxy)

            if await peer.connect(start_height, retry=False):
                self.peers[addr] = peer
                self.retry_counts[addr] = 0  # Reset retry count on success
                self.addrman.mark_good(host, int(port))
                self._register_compact_handlers(peer, addr)
                self._register_addr_handlers(peer, addr)
                asyncio.ensure_future(self.negotiate_compact_blocks(peer))
                # Request addresses from new outbound peers
                asyncio.ensure_future(self._send_getaddr(peer))
                # Negotiate Erlay reconciliation for full-relay peers
                if self.erlay_enabled:
                    self._register_erlay_handlers(peer, addr)
                    asyncio.ensure_future(self._negotiate_erlay(peer, addr))
                logger.info(f"Connected to full-relay peer {addr} ({len(self.peers)}/{self.max_peers})")
            else:
                # Failed to connect
                self.retry_counts[addr] += 1
                self.last_retry_time[addr] = time.time()
                self.addrman.mark_attempt(host, int(port))

                # Remove from known if too many failures
                if self.retry_counts[addr] >= 3:
                    self.known_addrs.discard(addr)
                    logger.debug(f"Removed {addr} from known addresses after {self.retry_counts[addr]} failures")

    async def _connect_block_relay_peers(self, start_height: int = 0):
        """Connect block-relay-only outbound peers up to max_block_relay_only."""
        while len(self.block_relay_peers) < self.max_block_relay_only and self.known_addrs:
            available = (
                self.known_addrs
                - self._all_outbound_addrs()
                - {a for a in self.known_addrs if self.ban_manager.is_banned(a)}
            )

            if not available:
                break

            addr = random.choice(list(available))

            if not self._should_retry(addr):
                continue

            host, port = addr.split(':')

            # Determine proxy — .onion peers require a SOCKS5 proxy
            peer_proxy = self._proxy_for_host(host)
            if is_onion_host(host) and not peer_proxy:
                logger.debug(f"Skipping .onion block-relay peer {addr}: no proxy configured")
                continue

            peer = Peer(host, int(port), self.network,
                        transport_version=self.transport_version, relay_txs=False,
                        proxy=peer_proxy)

            if await peer.connect(start_height, retry=False):
                self.block_relay_peers[addr] = peer
                self.retry_counts[addr] = 0
                self.addrman.mark_good(host, int(port))
                # Register only the compact-block *receive* handlers (for
                # unsolicited cmpctblock messages) but do NOT send sendcmpct
                # and do NOT register addr handlers or request addresses.
                self._register_compact_handlers(peer, addr)
                # Explicitly skip: negotiate_compact_blocks, _register_addr_handlers, _send_getaddr
                logger.info(
                    f"Connected to block-relay-only peer {addr} "
                    f"({len(self.block_relay_peers)}/{self.max_block_relay_only})"
                )
            else:
                self.retry_counts[addr] += 1
                self.last_retry_time[addr] = time.time()
                self.addrman.mark_attempt(host, int(port))
                if self.retry_counts[addr] >= 3:
                    self.known_addrs.discard(addr)
                    logger.debug(
                        f"Removed {addr} from known addresses after "
                        f"{self.retry_counts[addr]} failures"
                    )
    
    def _should_retry(self, addr: str) -> bool:
        retry_count = self.retry_counts.get(addr, 0)
        if retry_count == 0:
            return True
        
        last_retry = self.last_retry_time.get(addr, 0)
        elapsed = time.time() - last_retry
        
        # Exponential backoff: 2^retry_count seconds
        backoff_time = min(2 ** retry_count, 300)  # Max 5 minutes
        
        return elapsed >= backoff_time
    
    async def maintain_connections(self, start_height: int):
        """Maintain peer connections"""
        while self.running:
            try:
                # Remove disconnected full-relay outbound peers
                disconnected = [
                    a for a, p in list(self.peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected:
                    del self.peers[addr]
                    logger.info(f"Removed disconnected full-relay peer {addr}")

                # Remove disconnected block-relay-only outbound peers
                disconnected_bro = [
                    a for a, p in list(self.block_relay_peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected_bro:
                    del self.block_relay_peers[addr]
                    logger.info(f"Removed disconnected block-relay-only peer {addr}")

                # Remove disconnected inbound peers
                disconnected_in = [
                    a for a, p in list(self.inbound_peers.items())
                    if not p.is_connected()
                ]
                for addr in disconnected_in:
                    del self.inbound_peers[addr]
                    logger.info(f"Removed disconnected inbound peer {addr}")

                # Refill full-relay outbound slots
                if len(self.peers) < self.max_peers:
                    await self.connect_to_peers(start_height)

                # Refill block-relay-only outbound slots
                if len(self.block_relay_peers) < self.max_block_relay_only:
                    await self._connect_block_relay_peers(start_height)

                # Health check all peers (outbound + block-relay-only + inbound)
                all_peers = (
                    list(self.peers.values())
                    + list(self.block_relay_peers.values())
                    + list(self.inbound_peers.values())
                )
                for peer in all_peers:
                    if not peer.is_connected():
                        continue
                    if peer.latency > 5.0:
                        peer.adjust_score(-1)
                    elif peer.latency > 0 and peer.latency < 0.5:
                        peer.adjust_score(1)

                # Update feefilter for full-relay peers only (skip block-relay-only)
                await self._broadcast_feefilter()

                # Wait before next maintenance
                await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in maintain_connections: {e}")
                await asyncio.sleep(30)
    
    # BIP 133 Fee Filter

    async def _broadcast_feefilter(self) -> None:
        if self._mempool is None:
            return
        try:
            stats = self._mempool.get_stats()
            # min_fee_rate from mempool is in sat/vB; feefilter is sat/kB
            min_rate = stats.get("min_fee_rate", 0)
            feerate = max(int(min_rate * 1000), 1000)  # floor at 1000 sat/kB
        except Exception:
            return

        from ouroboros.p2p_messages import FeeFilterMessage
        msg = FeeFilterMessage(feerate=feerate).to_network_message(self.network)
        for p in self.get_all_ready_peers():
            if not p.relay_txs:
                continue  # skip block-relay-only peers
            try:
                await p.send_message(msg)
            except Exception:
                pass

    # BIP 152 Compact Blocks #

    def set_mempool(self, mempool) -> None:
        """Provide the mempool for compact block reconstruction."""
        self._mempool = mempool

    def set_compact_block_handler(self, handler) -> None:
        """Register a callback for incoming compact blocks.

        handler(block_hash: bytes, txs: Optional[List[Transaction]],
                missing_indices: List[int]) -> None
        """
        self._on_compact_block = handler

    async def negotiate_compact_blocks(self, peer: Peer) -> None:
        """Send ``sendcmpct`` to a newly-connected peer."""
        msg = SendCmpctMessage(announce=False, version=self.compact_block_version)
        try:
            await peer.send_message(msg.to_network_message(self.network))
            logger.debug(f"Sent sendcmpct (v{self.compact_block_version}) to "
                         f"{peer.host}:{peer.port}")
        except Exception as e:
            logger.warning(f"Failed to send sendcmpct to {peer.host}:{peer.port}: {e}")

    def _register_compact_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up compact-block message handlers on a peer."""
        async def on_sendcmpct(msg: NetworkMessage):
            sc = SendCmpctMessage.from_payload(msg.payload)
            if sc.version in (1, 2):
                self.cmpct_peers.add(addr)
                if sc.announce:
                    peer.wants_cmpctblock = True
                logger.info(f"Peer {addr} supports compact blocks v{sc.version}"
                            f"{' (announce)' if sc.announce else ''}")

        async def on_cmpctblock(msg: NetworkMessage):
            from ouroboros.compact_blocks import CompactBlock
            cb = CompactBlock.deserialize(msg.payload)
            if self._mempool is not None:
                txs, missing = cb.reconstruct(self._mempool)
            else:
                txs, missing = None, list(range(
                    len(cb.short_ids) + len(cb.prefilled_txs)))
            if self._on_compact_block:
                self._on_compact_block(cb.block_hash, txs, missing)
            if missing:
                from ouroboros.compact_blocks import BlockTransactionsRequest
                req = BlockTransactionsRequest(
                    block_hash=cb.block_hash, indices=missing)
                gbt = GetBlockTxnMessage(payload_bytes=req.serialize())
                try:
                    await peer.send_message(
                        gbt.to_network_message(self.network))
                except Exception as e:
                    logger.warning(f"Failed to send getblocktxn to {addr}: {e}")

        async def on_blocktxn(msg: NetworkMessage):
            from ouroboros.compact_blocks import BlockTransactions
            bt = BlockTransactions.deserialize(msg.payload)
            if self._on_compact_block:
                self._on_compact_block(bt.block_hash, bt.transactions, [])

        async def on_sendheaders(msg: NetworkMessage):
            peer.wants_headers = True
            logger.debug(f"Peer {addr} wants headers announcements")

        async def on_feefilter(msg: NetworkMessage):
            from ouroboros.p2p_messages import FeeFilterMessage
            ff = FeeFilterMessage.from_payload(msg.payload)
            peer.peer_feefilter = ff.feerate
            logger.debug(f"Peer {addr} feefilter: {ff.feerate} sat/kB")

        async def on_wtxidrelay(msg: NetworkMessage):
            logger.debug(f"Peer {addr} supports wtxid relay")

        async def on_sendaddrv2(msg: NetworkMessage):
            logger.debug(f"Peer {addr} supports addrv2")

        async def on_notfound(msg: NetworkMessage):
            from ouroboros.p2p_messages import NotFoundMessage
            nf = NotFoundMessage.from_payload(msg.payload)
            logger.debug(f"Peer {addr} notfound: {len(nf.inventory)} items")

        async def on_mempool(msg: NetworkMessage):
            # Block-relay-only peers must not receive transaction INVs
            if not peer.relay_txs:
                logger.debug(f"Ignoring mempool request from block-relay-only peer {addr}")
                return
            if self._mempool is not None:
                all_txids = list(self._mempool.transactions.keys())
                if all_txids:
                    from ouroboros.p2p_messages import InvMessage, INV_TYPE_TX
                    inv = InvMessage([(INV_TYPE_TX, txid) for txid in all_txids[:50000]])
                    try:
                        await peer.send_message(inv.to_network_message(self.network))
                    except Exception as e:
                        logger.warning(f"Failed to send mempool inv to {addr}: {e}")

        peer.register_handler("sendcmpct", on_sendcmpct)
        peer.register_handler("cmpctblock", on_cmpctblock)
        peer.register_handler("blocktxn", on_blocktxn)
        peer.register_handler("sendheaders", on_sendheaders)
        peer.register_handler("feefilter", on_feefilter)
        peer.register_handler("wtxidrelay", on_wtxidrelay)
        peer.register_handler("sendaddrv2", on_sendaddrv2)
        peer.register_handler("notfound", on_notfound)
        peer.register_handler("mempool", on_mempool)

    # Address gossip (addr / addrv2 / getaddr)

    def _register_addr_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up addr/addrv2/getaddr handlers on a peer."""

        async def on_addr(msg: NetworkMessage):
            try:
                am = AddrMessage.from_payload(msg.payload)
                if not self._rate_limit_addr_relay(addr, len(am.addresses)):
                    return
                added = 0
                for ts, net_addr in am.addresses:
                    host_str = self._netaddr_to_host(net_addr)
                    if host_str and not self.ban_manager.is_banned(host_str):
                        if self.addrman.add(
                            host_str, net_addr.port,
                            services=net_addr.services,
                            timestamp=float(ts),
                            source=addr,
                        ):
                            added += 1
                        self.known_addrs.add(f"{host_str}:{net_addr.port}")
                if added:
                    logger.debug(f"Learned {added} new addresses from {addr}")
                    # Relay to 1-2 random peers
                    self._relay_addr(msg, exclude=addr)
            except Exception as e:
                logger.debug(f"Error parsing addr from {addr}: {e}")

        async def on_addrv2(msg: NetworkMessage):
            try:
                am = AddrV2Message.from_payload(msg.payload)
                if not self._rate_limit_addr_relay(addr, len(am.addresses)):
                    return
                added = 0
                for entry in am.addresses:
                    net_id = entry.get("network_id", 0)
                    if net_id not in (1, 2, 4):
                        continue  # skip I2P/CJDNS for now (1=IPv4, 2=IPv6, 4=Tor v3)
                    addr_bytes = entry.get("addr", b"")
                    port = entry.get("port", 0)
                    services = entry.get("services", 0)
                    ts = entry.get("time", 0)
                    host_str = self._addr_bytes_to_host(net_id, addr_bytes)
                    if host_str and not self.ban_manager.is_banned(host_str):
                        if self.addrman.add(
                            host_str, port,
                            services=services,
                            timestamp=float(ts),
                            source=addr,
                        ):
                            added += 1
                        self.known_addrs.add(f"{host_str}:{port}")
                if added:
                    logger.debug(f"Learned {added} new addresses (v2) from {addr}")
                    self._relay_addr(msg, exclude=addr)
            except Exception as e:
                logger.debug(f"Error parsing addrv2 from {addr}: {e}")

        async def on_getaddr(msg: NetworkMessage):
            try:
                infos = self.addrman.get_addresses(count=1000)
                if not infos:
                    return
                from ouroboros.p2p_messages import NetworkAddress
                addresses = []
                for info in infos:
                    try:
                        net_addr = NetworkAddress.from_ipv4(
                            info.host, info.port, services=info.services,
                        )
                        addresses.append((int(info.last_seen), net_addr))
                    except (ValueError, AttributeError):
                        continue
                if addresses:
                    resp = AddrMessage(addresses=addresses)
                    await peer.send_message(
                        resp.to_network_message(self.network)
                    )
                    logger.debug(
                        f"Sent {len(addresses)} addresses to {addr}"
                    )
            except Exception as e:
                logger.debug(f"Error handling getaddr from {addr}: {e}")

        peer.register_handler("addr", on_addr)
        peer.register_handler("addrv2", on_addrv2)
        peer.register_handler("getaddr", on_getaddr)

    async def _send_getaddr(self, peer: Peer) -> None:
        try:
            msg = GetAddrMessage().to_network_message(self.network)
            await peer.send_message(msg)
            logger.debug(f"Sent getaddr to {peer.host}:{peer.port}")
        except Exception as e:
            logger.debug(f"Failed to send getaddr to {peer.host}:{peer.port}: {e}")

    def _relay_addr(self, msg: NetworkMessage, exclude: str = "") -> None:
        all_items = list(self.peers.items()) + list(self.inbound_peers.items())
        candidates = [
            p for a, p in all_items
            if a != exclude and p.is_connected() and p.relay_txs
        ]
        targets = random.sample(candidates, min(2, len(candidates)))
        for p in targets:
            try:
                asyncio.ensure_future(p.send_message(msg))
            except Exception:
                pass

    def _rate_limit_addr_relay(self, addr: str, count: int) -> bool:
        now = time.time()
        day_start = self._addr_relay_day.get(addr, 0)
        if now - day_start > 86400:
            self._addr_relay_counts[addr] = 0
            self._addr_relay_day[addr] = now
        self._addr_relay_counts[addr] += count
        return self._addr_relay_counts[addr] <= 1000

    @staticmethod
    def _netaddr_to_host(net_addr) -> Optional[str]:
        ip_bytes = net_addr.ip
        # IPv4-mapped IPv6: ::ffff:a.b.c.d
        if ip_bytes[:12] == b"\x00" * 10 + b"\xff\xff":
            return ".".join(str(b) for b in ip_bytes[12:16])
        # Pure IPv4 (shouldn't happen in protocol, but be safe)
        if len(ip_bytes) == 4:
            return ".".join(str(b) for b in ip_bytes)
        return None

    @staticmethod
    def _addr_bytes_to_host(net_id: int, addr_bytes: bytes) -> Optional[str]:
        if net_id == 1 and len(addr_bytes) == 4:
            return ".".join(str(b) for b in addr_bytes)
        if net_id == 2 and len(addr_bytes) == 16:
            # IPv6 — skip for outbound connections for now
            return None
        if net_id == 4 and len(addr_bytes) == 32:
            # Tor v3: 32-byte ed25519 pubkey → base32-encode with checksum
            # Onion v3 address = base32(pubkey || checksum || version)
            # checksum = first 2 bytes of SHA3-256(".onion checksum" || pubkey || version)
            import hashlib as _hl
            version_byte = b"\x03"
            checksum_prefix = b".onion checksum"
            h = _hl.sha3_256(checksum_prefix + addr_bytes + version_byte).digest()
            checksum = h[:2]
            onion_body = addr_bytes + checksum + version_byte
            onion_host = base64.b32encode(onion_body).decode("ascii").lower() + ".onion"
            return onion_host
        return None

    # --- BIP 330 Erlay Reconciliation ---

    async def _negotiate_erlay(self, peer: Peer, addr: str) -> None:
        if not peer.relay_txs:
            # Block-relay-only peers don't participate in tx reconciliation
            return
        try:
            salt = random.getrandbits(64)
            self._erlay_local_salts[addr] = salt
            msg = SendTxRcnclMessage(version=1, salt=salt)
            await peer.send_message(msg.to_network_message(self.network))
            logger.debug(
                f"Sent sendtxrcncl (salt={salt:#018x}) to {addr}"
            )
        except Exception as e:
            logger.warning(f"Failed to send sendtxrcncl to {addr}: {e}")

    def _register_erlay_handlers(self, peer: Peer, addr: str) -> None:
        """Wire up BIP 330 Erlay message handlers on a peer."""

        async def on_sendtxrcncl(msg: NetworkMessage):
            """Handle incoming sendtxrcncl — complete Erlay negotiation."""
            try:
                rcncl = SendTxRcnclMessage.from_payload(msg.payload)
                if rcncl.version < 1:
                    logger.debug(
                        f"Peer {addr} sendtxrcncl version {rcncl.version} "
                        "not supported, ignoring"
                    )
                    return

                our_salt = self._erlay_local_salts.get(addr)
                if our_salt is None:
                    # We haven't sent our sendtxrcncl yet — this is the
                    # peer initiating.  Send ours in reply.
                    our_salt = random.getrandbits(64)
                    self._erlay_local_salts[addr] = our_salt
                    reply = SendTxRcnclMessage(version=1, salt=our_salt)
                    await peer.send_message(
                        reply.to_network_message(self.network)
                    )

                # Erlay is now active on this connection
                recon_set = ReconciliationSet(
                    local_salt=our_salt,
                    remote_salt=rcncl.salt,
                )
                self._erlay_peers[addr] = recon_set
                self._erlay_pending_recon[addr] = False
                logger.info(
                    f"Erlay negotiated with {addr} "
                    f"(version={rcncl.version}, "
                    f"remote_salt={rcncl.salt:#018x})"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling sendtxrcncl from {addr}: {e}"
                )

        async def on_reqtxrcncl(msg: NetworkMessage):
            """Handle incoming reconciliation request — respond with a
            sketch of our local reconciliation set."""
            try:
                req = ReqTxRcnclMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    logger.debug(
                        f"Ignoring reqtxrcncl from non-Erlay peer {addr}"
                    )
                    return

                # Estimate capacity from both sides
                local_size = recon.set_size
                q_frac = req.q / (1 << 15)
                capacity = estimate_sketch_capacity(
                    local_size, req.set_size, q=max(q_frac, 0.1)
                )

                # Build and send our sketch
                sketch = recon.build_sketch(capacity)
                sketch_msg = SketchMessage(sketch_data=sketch.serialize())
                await peer.send_message(
                    sketch_msg.to_network_message(self.network)
                )
                logger.debug(
                    f"Sent sketch (cap={capacity}) to {addr} "
                    f"(local_set={local_size}, remote_set={req.set_size})"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling reqtxrcncl from {addr}: {e}"
                )

        async def on_sketch(msg: NetworkMessage):
            """Handle incoming sketch — decode the difference and send
            reconcildiff with the results."""
            try:
                sketch_msg = SketchMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    logger.debug(
                        f"Ignoring sketch from non-Erlay peer {addr}"
                    )
                    return

                # Determine capacity from sketch size
                capacity = len(sketch_msg.sketch_data) // 4
                if capacity == 0:
                    return

                # Build our local sketch with the same capacity
                local_sketch = recon.build_sketch(capacity)

                # Deserialize the remote sketch
                remote_sketch = Minisketch.deserialize(
                    sketch_msg.sketch_data, capacity
                )

                # Merge (XOR) to get the difference sketch
                diff_sketch = local_sketch.merge(remote_sketch)

                # Decode the symmetric difference
                diff_elements = diff_sketch.decode()

                if diff_elements is None:
                    # Decoding failed — fall back to full INV flood
                    logger.debug(
                        f"Sketch decode failed with {addr}, "
                        "falling back to INV"
                    )
                    diff_msg = ReconcilDiffMessage(
                        success=False, ask_shortids=[]
                    )
                    await peer.send_message(
                        diff_msg.to_network_message(self.network)
                    )
                    # Flood our pending txs via INV as fallback
                    await self._flood_pending_invs(peer, addr)
                    self._erlay_pending_recon[addr] = False
                    return

                # Separate: which elements are ours (peer missing) vs
                # theirs (we're missing)
                local_short_ids = recon.get_short_ids()
                sid_to_txid = recon.short_id_to_txid_map()

                # Elements in diff that we have → peer is missing
                peer_missing_sids = diff_elements & local_short_ids
                # Elements in diff that we don't have → we're missing
                we_missing_sids = diff_elements - local_short_ids

                # Send INVs for txids the peer is missing
                inv_items = []
                for sid in peer_missing_sids:
                    txid = sid_to_txid.get(sid)
                    if txid:
                        inv_items.append((INV_TYPE_TX, txid))
                        recon.mark_announced(txid)

                if inv_items:
                    inv_msg = InvMessage(inv_items)
                    await peer.send_message(
                        inv_msg.to_network_message(self.network)
                    )
                    logger.debug(
                        f"Sent {len(inv_items)} INVs to {addr} "
                        "after reconciliation"
                    )

                # Ask peer for txids we're missing
                diff_msg = ReconcilDiffMessage(
                    success=True,
                    ask_shortids=list(we_missing_sids),
                )
                await peer.send_message(
                    diff_msg.to_network_message(self.network)
                )

                # Clear reconciled transactions
                for sid in peer_missing_sids:
                    txid = sid_to_txid.get(sid)
                    if txid:
                        recon.mark_announced(txid)

                self._erlay_pending_recon[addr] = False
                logger.debug(
                    f"Reconciliation with {addr}: "
                    f"peer_missing={len(peer_missing_sids)}, "
                    f"we_missing={len(we_missing_sids)}, "
                    f"diff_size={len(diff_elements)}"
                )
            except Exception as e:
                logger.warning(
                    f"Error handling sketch from {addr}: {e}"
                )
                self._erlay_pending_recon[addr] = False

        async def on_reconcildiff(msg: NetworkMessage):
            """Handle incoming reconcildiff — the initiator tells us
            what short IDs it wants (txids we have that it lacks)."""
            try:
                diff = ReconcilDiffMessage.from_payload(msg.payload)
                recon = self._erlay_peers.get(addr)
                if recon is None:
                    return

                if not diff.success:
                    # Reconciliation failed on their side — fall back to INV
                    logger.debug(
                        f"Peer {addr} reports reconciliation failure"
                    )
                    await self._flood_pending_invs(peer, addr)
                    return

                # The peer wants us to send INVs for these short IDs
                if diff.ask_shortids:
                    sid_to_txid = recon.short_id_to_txid_map()
                    inv_items = []
                    for sid in diff.ask_shortids:
                        txid = sid_to_txid.get(sid)
                        if txid:
                            inv_items.append((INV_TYPE_TX, txid))
                            recon.mark_announced(txid)
                    if inv_items:
                        inv_msg = InvMessage(inv_items)
                        await peer.send_message(
                            inv_msg.to_network_message(self.network)
                        )
                        logger.debug(
                            f"Sent {len(inv_items)} INVs to {addr} "
                            "in response to reconcildiff"
                        )
            except Exception as e:
                logger.warning(
                    f"Error handling reconcildiff from {addr}: {e}"
                )

        peer.register_handler("sendtxrcncl", on_sendtxrcncl)
        peer.register_handler("reqtxrcncl", on_reqtxrcncl)
        peer.register_handler("sketch", on_sketch)
        peer.register_handler("reconcildiff", on_reconcildiff)

    async def _reconciliation_loop(self) -> None:
        """Periodically reconcile transaction sets with Erlay peers."""
        try:
            while self.running:
                await asyncio.sleep(self._reconciliation_interval)
                if not self.running:
                    break

                for addr, recon in list(self._erlay_peers.items()):
                    # Skip peers with no pending transactions
                    if recon.set_size == 0:
                        continue
                    # Skip if reconciliation already in progress
                    if self._erlay_pending_recon.get(addr, False):
                        continue

                    peer = self.get_peer_by_addr(addr)
                    if peer is None or not peer.is_connected():
                        continue

                    try:
                        self._erlay_pending_recon[addr] = True
                        # Send reqtxrcncl to initiate
                        q_coeff = 1  # q = 1/2^15 ≈ minimal estimate
                        req = ReqTxRcnclMessage(
                            set_size=recon.set_size,
                            q=q_coeff,
                        )
                        await peer.send_message(
                            req.to_network_message(self.network)
                        )
                        logger.debug(
                            f"Initiated reconciliation with {addr} "
                            f"(set_size={recon.set_size})"
                        )
                    except Exception as e:
                        self._erlay_pending_recon[addr] = False
                        logger.warning(
                            f"Failed to initiate reconciliation "
                            f"with {addr}: {e}"
                        )
        except asyncio.CancelledError:
            logger.debug("Reconciliation loop cancelled")
        except Exception as e:
            logger.error(f"Error in reconciliation loop: {e}")

    def erlay_add_tx_to_reconcile(self, txid: bytes, exclude_addr: str = "") -> None:
        """
        Queue a transaction for reconciliation with all Erlay peers.

        Instead of immediately broadcasting an INV to every peer, the
        transaction is added to each peer's reconciliation set and will
        be announced during the next reconciliation round.

        For non-Erlay peers, the caller should still send INV directly.

        Args:
            txid: 32-byte transaction hash
            exclude_addr: peer address to exclude (e.g. who sent us the tx)
        """
        for addr, recon in self._erlay_peers.items():
            if addr == exclude_addr:
                continue
            recon.add_tx(txid)

    def is_erlay_peer(self, addr: str) -> bool:
        """Check if a peer has Erlay negotiated."""
        return addr in self._erlay_peers

    def get_erlay_peers(self) -> List[str]:
        """Return addresses of all Erlay-capable peers."""
        return list(self._erlay_peers.keys())

    async def _flood_pending_invs(self, peer: Peer, addr: str) -> None:
        recon = self._erlay_peers.get(addr)
        if recon is None or recon.set_size == 0:
            return
        inv_items = [(INV_TYPE_TX, txid) for txid in list(recon.local_set)]
        if inv_items:
            try:
                inv_msg = InvMessage(inv_items)
                await peer.send_message(
                    inv_msg.to_network_message(self.network)
                )
                logger.debug(
                    f"Flooded {len(inv_items)} INVs to {addr} (fallback)"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to flood INVs to {addr}: {e}"
                )
        # Mark all as announced
        for txid in list(recon.local_set):
            recon.mark_announced(txid)

    def get_best_peer(self) -> Optional[Peer]:
        """
        Get peer with lowest latency.
        
        Returns:
            Best peer or None if no peers available
        """
        ready_peers = [
            p for p in self.peers.values()
            if p.is_connected()
        ]
        
        if not ready_peers:
            return None
        
        # Sort by latency (or score if latency not available)
        return min(
            ready_peers,
            key=lambda p: (
                p.latency if p.latency > 0 else 999,
                -p.score  # Higher score is better
            )
        )
    
    def get_all_ready_peers(self) -> List[Peer]:
        """
        Get all ready peers (full-relay outbound + block-relay-only + inbound).

        Returns:
            List of connected peers
        """
        all_peers = (
            list(self.peers.values())
            + list(self.block_relay_peers.values())
            + list(self.inbound_peers.values())
        )
        return [p for p in all_peers if p.is_connected()]
    
    def get_peer_by_addr(self, addr: str) -> Optional[Peer]:
        """
        Get peer by address (searches full-relay, block-relay-only, and inbound).

        Args:
            addr: Peer address (host:port)

        Returns:
            Peer instance or None
        """
        return (
            self.peers.get(addr)
            or self.block_relay_peers.get(addr)
            or self.inbound_peers.get(addr)
        )
    
    async def broadcast(self, msg: NetworkMessage):
        """
        Broadcast message to all ready peers.
        
        Args:
            msg: NetworkMessage to broadcast
        """
        ready_peers = self.get_all_ready_peers()
        if not ready_peers:
            logger.warning("No peers available for broadcast")
            return
        
        # Send to all peers in parallel
        tasks = []
        for peer in ready_peers:
            async def send_to_peer(p):
                try:
                    await p.send_message(msg)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {p.host}:{p.port}: {e}")
                    p.adjust_score(-5)  # Penalize for send failure
            
            tasks.append(send_to_peer(peer))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug(f"Broadcast {msg.command} to {len(ready_peers)} peers")
    
    def ban_peer(self, addr: str, duration: int = 86400):
        """
        Ban a peer temporarily.
        
        Args:
            addr: Peer address (host:port)
            duration: Ban duration in seconds (default: 24 hours)
        """
        self.ban_manager.ban_duration = duration
        self.ban_manager.ban(addr)

    def _on_peer_banned(self, ip: str) -> None:
        # Full-relay outbound
        matching = [a for a in list(self.peers) if a.startswith(ip)]
        for addr in matching:
            peer = self.peers.pop(addr, None)
            if peer:
                asyncio.ensure_future(peer.disconnect())
        # Block-relay-only outbound
        matching_bro = [a for a in list(self.block_relay_peers) if a.startswith(ip)]
        for addr in matching_bro:
            peer = self.block_relay_peers.pop(addr, None)
            if peer:
                asyncio.ensure_future(peer.disconnect())
        # Inbound
        matching_in = [a for a in list(self.inbound_peers) if a.startswith(ip)]
        for addr in matching_in:
            peer = self.inbound_peers.pop(addr, None)
            if peer:
                asyncio.ensure_future(peer.disconnect())
        self.known_addrs.discard(ip)

    def record_misbehavior(self, addr: str, score: int, reason: str) -> bool:
        """Record misbehavior for a peer; auto-bans at threshold.

        Returns True if the peer was banned.
        """
        return self.ban_manager.record_misbehavior(addr, score, reason)

    def misbehaving(self, peer_id: str, score: int, reason: str) -> bool:
        """Record misbehavior for a peer (Bitcoin Core API compatibility).

        This method adds misbehavior points to a peer. When the cumulative
        score reaches the ban threshold (default 100), the peer is automatically
        disconnected and banned for the ban duration (default 24 hours).

        Common scores (from Bitcoin Core net_processing.cpp):
            - Invalid block: 100 (instant ban)
            - Invalid headers: 20
            - Invalid tx: 10
            - Unrequested data: 20

        Args:
            peer_id: Peer identifier (IP address or IP:port)
            score: Misbehavior score to add
            reason: Human-readable reason

        Returns:
            True if the peer was banned as a result
        """
        return self.ban_manager.misbehaving(peer_id, score, reason)

    def unban_peer(self, addr: str):
        """
        Unban a peer.
        
        Args:
            addr: Peer address (host:port)
        """
        self.ban_manager.unban(addr)
    
    def add_peer_address(self, addr: str):
        """
        Add a peer address to known addresses.
        
        Args:
            addr: Peer address (host:port)
        """
        if not self.ban_manager.is_banned(addr):
            self.known_addrs.add(addr)
            logger.debug(f"Added peer address: {addr}")
    
    def get_peer_count(self) -> int:
        """Get total number of connected peers (outbound + block-relay-only + inbound)"""
        return len(self.peers) + len(self.block_relay_peers) + len(self.inbound_peers)

    def get_ready_peer_count(self) -> int:
        """Get number of ready peers"""
        return len(self.get_all_ready_peers())

    def get_stats(self) -> Dict:
        """
        Get peer manager statistics.

        Returns:
            Dictionary with statistics
        """
        ready_peers = self.get_all_ready_peers()
        avg_latency = (
            sum(p.latency for p in ready_peers if p.latency > 0) / len(ready_peers)
            if ready_peers else 0
        )
        avg_score = (
            sum(p.score for p in ready_peers) / len(ready_peers)
            if ready_peers else 0
        )

        onion_peers = sum(
            1 for p in ready_peers if is_onion_host(p.host)
        )

        return {
            "connected": len(self.peers) + len(self.block_relay_peers) + len(self.inbound_peers),
            "outbound": len(self.peers),
            "block_relay_only": len(self.block_relay_peers),
            "inbound": len(self.inbound_peers),
            "ready": len(ready_peers),
            "known": len(self.known_addrs),
            "banned": len(self.ban_manager.list_banned()),
            "avg_latency": avg_latency,
            "avg_score": avg_score,
            "erlay_peers": len(self._erlay_peers),
            "erlay_enabled": self.erlay_enabled,
            "proxy": self.proxy,
            "onion_proxy": self.onion,
            "onion_peers": onion_peers,
        }


# Alias for backward compatibility
P2PManager = PeerManager
