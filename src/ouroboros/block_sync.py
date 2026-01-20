"""
Ongoing block synchronization from the Bitcoin network.

This module implements continuous block synchronization after initial sync,
handling new block announcements, validation, and chain reorganization.
"""

import asyncio
import time
import logging
from typing import Dict, Set, Optional, List, Tuple, Callable
from collections import defaultdict

from ouroboros.database import BlockchainDatabase, Block
from ouroboros.validation import BlockValidator
from ouroboros.p2p_messages import (
    NetworkMessage,
    InvMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    BlockMessage,
    INV_TYPE_BLOCK,
)
from ouroboros.peer import Peer

logger = logging.getLogger(__name__)


class BlockSync:
    """Synchronizes new blocks from network"""
    
    def __init__(
        self,
        db: BlockchainDatabase,
        validator: BlockValidator,
        peer_manager,  # PeerManager or compatible interface
    ):
        """
        Initialize block synchronizer.
        
        Args:
            db: Blockchain database
            validator: Block validator
            peer_manager: Peer manager instance (must have get_all_ready_peers, 
                         get_best_peer, broadcast methods)
        """
        self.db = db
        self.validator = validator
        self.peer_manager = peer_manager
        
        # Track requested blocks (hash -> request_time)
        self.requested_blocks: Dict[bytes, float] = {}
        
        # Track received blocks (hash -> Block)
        self.received_blocks: Dict[bytes, Block] = {}
        
        # Track pending headers requests
        self.pending_headers: Dict[bytes, float] = {}  # locator_hash -> request_time
        
        # Reorg detection
        self.last_best_hash: Optional[bytes] = None
        self.reorg_depth: int = 0
        
        self.running = False
        self._sync_task: Optional[asyncio.Task] = None
        
        # Message handlers per peer (peer -> handler_dict)
        self._peer_handlers: Dict[Peer, Dict[str, Callable]] = defaultdict(dict)
    
    async def start(self):
        """Start block synchronization"""
        if self.running:
            logger.warning("BlockSync already running")
            return
        
        self.running = True
        logger.info("Starting block synchronization")
        
        # Register message handlers for existing peers
        await self._register_handlers()
        
        # Start sync task
        self._sync_task = asyncio.create_task(self.sync_loop())
    
    async def stop(self):
        """Stop block synchronization"""
        if not self.running:
            return
        
        logger.info("Stopping block synchronization")
        self.running = False
        
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        
        # Unregister handlers
        for peer in list(self._peer_handlers.keys()):
            await self._unregister_handlers(peer)
    
    async def _register_handlers(self):
        """Register message handlers for all ready peers"""
        # Get all ready peers (assuming peer_manager has this method)
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            # Fallback: try to get peers from peer_manager.peers
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = [p for p in peers.values() if hasattr(p, 'is_connected') and p.is_connected()]
            elif not isinstance(peers, list):
                peers = []
        
        for peer in peers:
            if not isinstance(peer, Peer):
                continue
            
            # Register handlers
            peer.register_handler("inv", self._make_inv_handler(peer))
            peer.register_handler("block", self._make_block_handler(peer))
            peer.register_handler("headers", self._make_headers_handler(peer))
            
            self._peer_handlers[peer] = {
                "inv": self._make_inv_handler(peer),
                "block": self._make_block_handler(peer),
                "headers": self._make_headers_handler(peer),
            }
    
    async def _unregister_handlers(self, peer: Peer):
        """Unregister message handlers for a peer"""
        # Note: Peer class doesn't have unregister_handler, so we just remove from tracking
        if peer in self._peer_handlers:
            del self._peer_handlers[peer]
    
    def _make_inv_handler(self, peer: Peer):
        """Create inv message handler for a specific peer"""
        async def handler(msg: NetworkMessage):
            await self.handle_inv(msg, peer)
        return handler
    
    def _make_block_handler(self, peer: Peer):
        """Create block message handler for a specific peer"""
        async def handler(msg: NetworkMessage):
            await self.handle_block(msg, peer)
        return handler
    
    def _make_headers_handler(self, peer: Peer):
        """Create headers message handler for a specific peer"""
        async def handler(msg: NetworkMessage):
            await self.handle_headers(msg, peer)
        return handler
    
    async def sync_loop(self):
        """Main synchronization loop"""
        while self.running:
            try:
                # Check if we're behind
                best_hash, best_height = self.db.get_best_block()
                
                # Detect reorgs
                if self.last_best_hash and self.last_best_hash != best_hash:
                    # Check if this is a reorg
                    current_block = self.db.get_block(best_hash)
                    if current_block:
                        prev_block = self.db.get_block(current_block.prev_blockhash)
                        if prev_block and prev_block.height and best_height:
                            if prev_block.height < best_height - 1:
                                logger.warning(
                                    f"Possible reorg detected: height {best_height}, "
                                    f"prev height {prev_block.height}"
                                )
                                await self._handle_reorg(best_height)
                
                self.last_best_hash = best_hash
                
                # Get peer with highest block
                best_peer = self._get_peer_with_highest_block()
                if best_peer and hasattr(best_peer, 'start_height'):
                    if best_peer.start_height > best_height:
                        logger.info(
                            f"Behind by {best_peer.start_height - best_height} blocks"
                        )
                        await self._catch_up(best_peer, best_height)
                
                # Handle timeouts
                await self._handle_timeouts()
                
            except Exception as e:
                logger.error(f"Error in sync loop: {e}", exc_info=True)
            
            await asyncio.sleep(10)
    
    async def handle_inv(self, msg: NetworkMessage, peer: Peer):
        """Handle inventory announcement"""
        try:
            inv = InvMessage.from_payload(msg.payload)
            
            # Request blocks we don't have
            to_request = []
            for inv_type, inv_hash in inv.inventory:
                if inv_type == INV_TYPE_BLOCK:
                    # Check if we already have this block
                    existing_block = self.db.get_block(inv_hash)
                    if not existing_block:
                        # Check if we've already requested it
                        if inv_hash not in self.requested_blocks:
                            to_request.append((inv_type, inv_hash))
                            self.requested_blocks[inv_hash] = time.time()
            
            if to_request:
                # Send getdata
                getdata = GetDataMessage(inventory=to_request)
                getdata_msg = getdata.to_network_message(self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet")
                
                try:
                    await peer.send_message(getdata_msg)
                    logger.info(f"Requested {len(to_request)} blocks from {peer.host}:{peer.port}")
                except Exception as e:
                    logger.error(f"Failed to send getdata to {peer.host}:{peer.port}: {e}")
                    peer.adjust_score(-5)
        
        except Exception as e:
            logger.error(f"Error handling inv from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)
    
    async def handle_block(self, msg: NetworkMessage, peer: Peer):
        """Handle block delivery"""
        try:
            # Note: BlockMessage.from_payload requires full Bitcoin protocol decoding
            # For now, we'll need to use the Rust layer or implement proper deserialization
            # This is a placeholder that shows the structure
            
            # In a real implementation, you would:
            # block_msg = BlockMessage.from_payload(msg.payload)
            # block = block_msg.block
            
            # For now, we'll log that we received a block
            logger.debug(f"Received block message from {peer.host}:{peer.port} ({len(msg.payload)} bytes)")
            
            # TODO: Deserialize block using Rust BlockWrapper or implement full deserialization
            # block_hash = block.hash()
            
            # Remove from requested
            # if block_hash in self.requested_blocks:
            #     del self.requested_blocks[block_hash]
            
            # Validate block
            # valid, error = self.validator.validate_block(block)
            
            # if valid:
            #     # Apply to database
            #     self.validator.apply_block(block)
            #     logger.info(f"✓ New block {block.height}: {block_hash.hex()[:16]}...")
            
            #     # Broadcast to other peers
            #     inv = InvMessage(inventory=[(INV_TYPE_BLOCK, block_hash)])
            #     if hasattr(self.peer_manager, 'broadcast'):
            #         await self.peer_manager.broadcast(inv.to_network_message(...))
            # else:
            #     logger.warning(f"✗ Invalid block: {error}")
            #     peer.adjust_score(-10)  # Penalize for invalid block
            #     if hasattr(self.peer_manager, 'ban_peer'):
            #         addr = f"{peer.host}:{peer.port}"
            #         self.peer_manager.ban_peer(addr, duration=3600)
        
        except Exception as e:
            logger.error(f"Error handling block from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-5)
    
    async def handle_headers(self, msg: NetworkMessage, peer: Peer):
        """Handle headers message"""
        try:
            headers_msg = HeadersMessage.from_payload(msg.payload)
            
            if not headers_msg.headers:
                return
            
            logger.info(f"Received {len(headers_msg.headers)} headers from {peer.host}:{peer.port}")
            
            # Process headers and request blocks
            for header in headers_msg.headers:
                # Check if we have this block
                # Note: We'd need to compute block hash from header
                # For now, this is a placeholder
                pass
            
            # TODO: Request blocks for headers we don't have
        
        except Exception as e:
            logger.error(f"Error handling headers from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)
    
    async def _catch_up(self, peer: Peer, our_height: int):
        """Request blocks to catch up"""
        try:
            # Build locator
            locator = self._build_locator(our_height)
            
            if not locator:
                logger.warning("Could not build locator for catch-up")
                return
            
            # Request headers
            getheaders = GetHeadersMessage(
                version=70015,
                locator_hashes=locator,
                hash_stop=b'\x00' * 32
            )
            
            network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
            getheaders_msg = getheaders.to_network_message(network)
            
            await peer.send_message(getheaders_msg)
            logger.info(f"Requested headers from {peer.host}:{peer.port} (locator: {len(locator)} hashes)")
            
        except Exception as e:
            logger.error(f"Error in catch_up: {e}")
            peer.adjust_score(-2)
    
    def _build_locator(self, height: int) -> List[bytes]:
        """
        Build block locator (exponential spacing).
        
        Args:
            height: Current block height
            
        Returns:
            List of block hashes for locator
        """
        locator = []
        step = 1
        current_height = height
        
        while current_height > 0:
            block = self.db.get_block_by_height(current_height)
            if block:
                block_hash = block.hash
                if isinstance(block_hash, bytes) and len(block_hash) == 32:
                    locator.append(block_hash)
            
            # Exponential spacing: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, ...
            if len(locator) >= 10:
                step *= 2
            
            current_height -= step
            
            # Limit to reasonable depth
            if current_height < 0:
                break
        
        # Always include genesis
        genesis = self.db.get_block_by_height(0)
        if genesis:
            genesis_hash = genesis.hash
            if isinstance(genesis_hash, bytes) and len(genesis_hash) == 32:
                if genesis_hash not in locator:
                    locator.append(genesis_hash)
        
        return locator
    
    def _get_peer_with_highest_block(self) -> Optional[Peer]:
        """Get peer with highest block height"""
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = [p for p in peers.values() if hasattr(p, 'is_connected') and p.is_connected()]
            elif not isinstance(peers, list):
                peers = []
        
        if not peers:
            return None
        
        # Filter to Peer instances with start_height
        valid_peers = [p for p in peers if isinstance(p, Peer) and hasattr(p, 'start_height')]
        if not valid_peers:
            return None
        
        return max(valid_peers, key=lambda p: p.start_height)
    
    async def _handle_timeouts(self):
        """Re-request blocks that timed out"""
        now = time.time()
        timeout = 30.0
        
        timed_out = [
            block_hash for block_hash, request_time in self.requested_blocks.items()
            if now - request_time > timeout
        ]
        
        for block_hash in timed_out:
            logger.warning(f"Block request timed out: {block_hash.hex()[:16]}...")
            del self.requested_blocks[block_hash]
            
            # Re-request from different peer
            if hasattr(self.peer_manager, 'get_best_peer'):
                peer = self.peer_manager.get_best_peer()
            else:
                # Fallback
                peers = getattr(self.peer_manager, 'peers', [])
                if isinstance(peers, dict):
                    peers = list(peers.values())
                peer = peers[0] if peers else None
            
            if peer and isinstance(peer, Peer):
                try:
                    getdata = GetDataMessage(inventory=[(INV_TYPE_BLOCK, block_hash)])
                    network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
                    getdata_msg = getdata.to_network_message(network)
                    await peer.send_message(getdata_msg)
                    self.requested_blocks[block_hash] = now
                    logger.info(f"Re-requested block from {peer.host}:{peer.port}")
                except Exception as e:
                    logger.error(f"Failed to re-request block: {e}")
    
    async def _handle_reorg(self, current_height: int):
        """
        Handle blockchain reorganization.
        
        Args:
            current_height: Current block height
        """
        logger.warning(f"Handling reorg at height {current_height}")
        
        # For now, just log the reorg
        # In a full implementation, we would:
        # 1. Find the fork point
        # 2. Disconnect blocks from the old chain
        # 3. Re-request blocks from the new chain
        # 4. Update UTXO set
        
        self.reorg_depth += 1
        logger.warning(f"Reorg detected (depth: {self.reorg_depth})")
        
        # TODO: Implement full reorg handling
        # This requires:
        # - Finding common ancestor
        # - Disconnecting invalid blocks
        # - Re-requesting correct chain
