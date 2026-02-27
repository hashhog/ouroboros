"""
Peer-to-peer networking module.

This module implements peer discovery, connection management, and peer scoring
for the Bitcoin P2P network.
"""

import asyncio
import socket
import random
import time
import logging
from typing import List, Dict, Set, Optional
from collections import defaultdict

from ouroboros.peer import Peer, PeerState
from ouroboros.p2p_messages import (
    NetworkMessage, SendCmpctMessage, CmpctBlockMessage,
    GetBlockTxnMessage, BlockTxnMessage,
)
from ouroboros.banman import BanManager

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


class PeerManager:
    """Manages peer connections and discovery"""
    
    def __init__(
        self,
        network: str = "mainnet",
        max_peers: int = 8,
        data_dir: Optional[str] = None,
        transport_version: int = 1,
    ):
        """
        Initialize peer manager.
        
        Args:
            network: Network name (mainnet, testnet, regtest)
            max_peers: Maximum number of connected peers
            data_dir: Data directory for persisting bans
            transport_version: Default P2P transport version for new peers
                               (1 = plaintext v1, 2 = BIP 324 encrypted)
        """
        self.network = network
        self.max_peers = max_peers
        self.transport_version = transport_version
        
        self.peers: Dict[str, Peer] = {}  # addr -> Peer
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

        # BIP 152 compact-block state
        self.compact_block_version: int = 2
        self.cmpct_peers: Set[str] = set()
        self._mempool = None
        self._on_compact_block = None
    
    async def start(self, start_height: int = 0):
        """
        Start peer manager.
        
        Args:
            start_height: Our blockchain height for version messages
        """
        if self.running:
            logger.warning("PeerManager already running")
            return
        
        self.running = True
        logger.info(f"Starting PeerManager for {self.network} (max_peers={self.max_peers})")
        
        # Discover peers from DNS seeds
        await self.discover_peers()
        
        # Connect to initial peers
        await self.connect_to_peers(start_height)
        
        # Start maintenance task
        self._maintenance_task = asyncio.create_task(
            self.maintain_connections(start_height)
        )
    
    async def stop(self):
        """Stop peer manager and disconnect all peers"""
        if not self.running:
            return
        
        logger.info("Stopping PeerManager...")
        self.running = False
        
        # Cancel maintenance task
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
        
        # Disconnect all peers
        disconnect_tasks = [
            peer.disconnect() for peer in list(self.peers.values())
        ]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
        
        self.peers.clear()
        logger.info("PeerManager stopped")
    
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
        
        port = 8333 if self.network == "mainnet" else 18333
        
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
        """
        Resolve DNS seed and add addresses to known_addrs.
        
        Args:
            seed: DNS seed hostname
            port: Port number
            
        Returns:
            Number of addresses discovered
        """
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
                    count += 1
            
            return count
            
        except Exception as e:
            logger.debug(f"Error resolving {seed}: {e}")
            return 0
    
    async def connect_to_peers(self, start_height: int = 0):
        """Connect to peers up to max_peers"""
        while len(self.peers) < self.max_peers and self.known_addrs:
            # Get available addresses (not already connected, not banned)
            available = (
                self.known_addrs
                - set(self.peers.keys())
                - {a for a in self.known_addrs if self.ban_manager.is_banned(a)}
            )
            
            if not available:
                break
            
            # Pick random peer
            addr = random.choice(list(available))
            
            # Check exponential backoff
            if not self._should_retry(addr):
                continue
            
            # Try to connect
            host, port = addr.split(':')
            peer = Peer(host, int(port), self.network, transport_version=self.transport_version)
            
            if await peer.connect(start_height, retry=False):
                self.peers[addr] = peer
                self.retry_counts[addr] = 0  # Reset retry count on success
                self._register_compact_handlers(peer, addr)
                asyncio.ensure_future(self.negotiate_compact_blocks(peer))
                logger.info(f"Connected to peer {addr} ({len(self.peers)}/{self.max_peers})")
            else:
                # Failed to connect
                self.retry_counts[addr] += 1
                self.last_retry_time[addr] = time.time()
                
                # Remove from known if too many failures
                if self.retry_counts[addr] >= 3:
                    self.known_addrs.discard(addr)
                    logger.debug(f"Removed {addr} from known addresses after {self.retry_counts[addr]} failures")
    
    def _should_retry(self, addr: str) -> bool:
        """
        Check if we should retry connecting to an address (exponential backoff).
        
        Args:
            addr: Peer address
            
        Returns:
            True if we should retry, False otherwise
        """
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
                # Remove disconnected peers
                disconnected = []
                for addr, peer in list(self.peers.items()):
                    if not peer.is_connected():
                        disconnected.append(addr)
                
                for addr in disconnected:
                    del self.peers[addr]
                    logger.info(f"Removed disconnected peer {addr}")
                
                # Connect to more peers if needed
                if len(self.peers) < self.max_peers:
                    await self.connect_to_peers(start_height)
                
                # Ping all peers periodically (handled by Peer class)
                # Just check their health
                for peer in list(self.peers.values()):
                    if not peer.is_connected():
                        # Peer disconnected, will be removed in next iteration
                        continue
                    
                    # Adjust score based on latency
                    if peer.latency > 5.0:  # Very high latency
                        peer.adjust_score(-1)
                    elif peer.latency > 0 and peer.latency < 0.5:  # Good latency
                        peer.adjust_score(1)
                
                # Wait before next maintenance
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in maintain_connections: {e}")
                await asyncio.sleep(30)
    
    # ── BIP 152 Compact Blocks ───────────────────────────────────────

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
                logger.info(f"Peer {addr} supports compact blocks v{sc.version}")

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
            logger.debug(f"Peer {addr} wants headers announcements")

        async def on_feefilter(msg: NetworkMessage):
            from ouroboros.p2p_messages import FeeFilterMessage
            ff = FeeFilterMessage.from_payload(msg.payload)
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
        Get all ready peers.
        
        Returns:
            List of connected peers
        """
        return [
            p for p in self.peers.values()
            if p.is_connected()
        ]
    
    def get_peer_by_addr(self, addr: str) -> Optional[Peer]:
        """
        Get peer by address.
        
        Args:
            addr: Peer address (host:port)
            
        Returns:
            Peer instance or None
        """
        return self.peers.get(addr)
    
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
        """Callback from BanManager — disconnect and forget the peer."""
        matching = [a for a in list(self.peers) if a.startswith(ip)]
        for addr in matching:
            peer = self.peers.pop(addr, None)
            if peer:
                asyncio.ensure_future(peer.disconnect())
        self.known_addrs.discard(ip)

    def record_misbehavior(self, addr: str, score: int, reason: str) -> None:
        """Record misbehavior for a peer; auto-bans at threshold."""
        self.ban_manager.record_misbehavior(addr, score, reason)

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
        """Get number of connected peers"""
        return len(self.peers)
    
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
        
        return {
            "connected": len(self.peers),
            "ready": len(ready_peers),
            "known": len(self.known_addrs),
            "banned": len(self.ban_manager.list_banned()),
            "avg_latency": avg_latency,
            "avg_score": avg_score,
        }


# Alias for backward compatibility
P2PManager = PeerManager
