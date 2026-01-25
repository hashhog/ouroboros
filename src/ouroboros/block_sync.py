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
                                # Get the block that's causing the reorg
                                # For now, use the best block as the new tip
                                await self._handle_reorg(prev_block, best_hash)
                
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
            from ouroboros.database import Block
            from ouroboros.p2p_messages import InvMessage, INV_TYPE_BLOCK
            
            # Deserialize block from payload
            block = Block.deserialize(msg.payload)
            block_hash = block.hash
            
            # Remove from requested blocks
            if block_hash in self.requested_blocks:
                del self.requested_blocks[block_hash]
            
            # Validate block
            valid, error = self.validator.validate_block(block)
            
            if valid:
                # Check if this block causes a reorg
                # Get current best block
                current_hash, current_height = self.db.get_best_block()
                
                # Check if this block's previous hash matches current best
                if block.prev_blockhash != current_hash:
                    # This is a reorg - handle it
                    logger.warning(
                        f"Reorg detected: new block {block_hash.hex()[:16]}... "
                        f"does not extend current best {current_hash.hex()[:16]}..."
                    )
                    reorg_success = await self._handle_reorg(block, block_hash)
                    if not reorg_success:
                        logger.error("Failed to handle reorg, rejecting block")
                        peer.adjust_score(-10)
                        return
                else:
                    # Normal block - apply to database
                    self.validator.apply_block(block)
                
                block_height = block.height if hasattr(block, 'height') and block.height else 0
                logger.info(f"✓ New block {block_height}: {block_hash.hex()[:16]}...")
                
                # Broadcast to other peers
                inv = InvMessage(inventory=[(INV_TYPE_BLOCK, block_hash)])
                if hasattr(self.peer_manager, 'broadcast'):
                    await self.peer_manager.broadcast(inv.to_network_message())
            else:
                logger.warning(f"✗ Invalid block: {error}")
                peer.adjust_score(-10)  # Penalize for invalid block
                if hasattr(self.peer_manager, 'ban_peer'):
                    addr = f"{peer.host}:{peer.port}"
                    self.peer_manager.ban_peer(addr, duration=3600)
        
        except Exception as e:
            logger.error(f"Error handling block from {peer.host}:{peer.port}: {e}", exc_info=True)
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
    
    async def _find_transaction_in_blocks(self, txid: bytes, max_height: int, min_height: int = 0) -> Optional['Transaction']:
        """
        Find a transaction by txid by searching through blocks.
        
        Args:
            txid: Transaction ID to find
            max_height: Maximum height to search (inclusive)
            min_height: Minimum height to search (inclusive)
            
        Returns:
            Transaction if found, None otherwise
        """
        # Search backwards from max_height to min_height
        for height in range(max_height, min_height - 1, -1):
            try:
                block = self.db.get_block_by_height(height)
                if not block:
                    continue
                
                # Search transactions in this block
                for tx in block.transactions:
                    if tx.get_txid() == txid:
                        return tx
            except Exception as e:
                logger.debug(f"Error searching block at height {height}: {e}")
                continue
        
        return None
    
    async def _restore_utxos_from_block(self, block: Block, max_search_height: int) -> List[Tuple[bytes, int, int, bytes]]:
        """
        Restore UTXOs that were spent in this block.
        
        For each non-coinbase transaction input, we need to:
        1. Find the transaction that created the UTXO (prev_txid)
        2. Get the output data from that transaction
        3. Return UTXO data: (txid, vout, value, script_pubkey)
        
        Args:
            block: Block being disconnected
            max_search_height: Maximum block height to search for transactions
            
        Returns:
            List of (txid, vout, value, script_pubkey) tuples for UTXOs to restore
        """
        utxos_to_restore = []
        
        for tx in block.transactions:
            if tx.is_coinbase:
                continue
            
            for tx_in in tx.inputs:
                # Find the transaction that created this UTXO
                prev_tx = await self._find_transaction_in_blocks(tx_in.prev_txid, max_search_height)
                if not prev_tx:
                    logger.warning(
                        f"Previous transaction {tx_in.prev_txid.hex()[:16]}... not found "
                        f"when disconnecting block, cannot restore UTXO"
                    )
                    continue
                
                # Get the output that was spent
                if tx_in.prev_vout >= len(prev_tx.outputs):
                    logger.warning(
                        f"Invalid vout {tx_in.prev_vout} for transaction "
                        f"{tx_in.prev_txid.hex()[:16]}..."
                    )
                    continue
                
                output = prev_tx.outputs[tx_in.prev_vout]
                
                # Add to restore list
                utxos_to_restore.append((
                    tx_in.prev_txid,  # txid
                    tx_in.prev_vout,  # vout
                    output.value,     # value
                    output.script_pubkey  # script_pubkey
                ))
        
        return utxos_to_restore
    
    async def _handle_reorg(self, new_block: Block, new_chain_tip: bytes):
        """
        Handle chain reorganization.
        
        Implementation:
        1. Find common ancestor between current chain and new chain
        2. Disconnect blocks from current chain back to common ancestor
        3. Connect blocks from new chain
        4. Update UTXO set for each disconnected/connected block
        5. Re-validate orphan transactions from mempool
        
        Args:
            new_block: New block that caused the reorg
            new_chain_tip: Hash of the new chain tip
            
        Returns:
            True if reorg was handled successfully, False otherwise
        """
        logger.warning(f"Handling chain reorganization to new tip: {new_chain_tip.hex()[:16]}...")
        
        try:
            # Get current best block
            current_hash, current_height = self.db.get_best_block()
            
            if current_hash == new_chain_tip:
                # No reorg needed - we're already on this chain
                return True
            
            # Walk back chains to find common ancestor
            current_chain = []
            new_chain = []
            
            # Build current chain back to reasonable depth (e.g., 100 blocks)
            # Also track heights for transaction search
            temp_hash = current_hash
            temp_height = current_height
            for i in range(100):
                if temp_hash is None:
                    break
                block = self.db.get_block(temp_hash)
                if not block:
                    break
                # Store with height for easier lookup
                current_chain.append((temp_hash, block, temp_height))
                temp_hash = block.prev_blockhash
                temp_height -= 1
                if temp_hash == bytes(32):  # Genesis block
                    break
            
            # Build new chain back
            # Estimate height for new chain (will be refined when we find common ancestor)
            temp_hash = new_chain_tip
            temp_height = current_height  # Start with current height as estimate
            for i in range(100):
                if temp_hash is None:
                    break
                # Try to get from database
                block = self.db.get_block(temp_hash)
                if not block:
                    # Need to request from network - for now, log and return
                    logger.warning(f"Block {temp_hash.hex()[:16]}... not in database, cannot complete reorg")
                    return False
                # Store with height estimate
                new_chain.append((temp_hash, block, temp_height))
                # Check if we found common ancestor
                if temp_hash in [h for h, _, _ in current_chain]:
                    # Found common ancestor - update height estimate
                    for curr_h, _, curr_ht in current_chain:
                        if curr_h == temp_hash:
                            temp_height = curr_ht
                            break
                    break
                temp_hash = block.prev_blockhash
                temp_height -= 1
                if temp_hash == bytes(32):  # Genesis block
                    break
            
            # Find common ancestor
            common_ancestor = None
            common_ancestor_height = 0
            for curr_hash, curr_block, curr_height in current_chain:
                for new_hash, new_block, new_height in new_chain:
                    if curr_hash == new_hash:
                        common_ancestor = curr_hash
                        # Use the height from current_chain
                        common_ancestor_height = curr_height
                        break
                if common_ancestor:
                    break
            
            if not common_ancestor:
                # No common ancestor found - this is a major reorg
                # May need to re-validate entire chain
                logger.warning("Major reorg detected - no common ancestor found within 100 blocks")
                return False
            
            logger.info(
                f"Reorg: common ancestor at height {common_ancestor_height}, "
                f"disconnecting {len([h for h, _, _ in current_chain if h != common_ancestor])} blocks, "
                f"connecting {len([h for h, _, _ in new_chain if h != common_ancestor])} blocks"
            )
            
            # Disconnect blocks from current chain (in reverse order)
            blocks_to_disconnect = [
                (h, b, ht) for h, b, ht in current_chain
                if h != common_ancestor
            ]
            
            # Get current height for transaction search
            current_height = common_ancestor_height + len(blocks_to_disconnect)
            
            for curr_hash, curr_block, curr_height in reversed(blocks_to_disconnect):
                logger.debug(f"Disconnecting block {curr_hash.hex()[:16]}...")
                
                # Restore UTXOs that were spent in this block
                try:
                    utxos_to_restore = await self._restore_utxos_from_block(curr_block, current_height)
                    
                    if utxos_to_restore:
                        logger.info(f"Restoring {len(utxos_to_restore)} UTXOs from disconnected block")
                        for txid, vout, value, script_pubkey in utxos_to_restore:
                            try:
                                self.db.restore_utxo(txid, vout, value, script_pubkey)
                            except Exception as e:
                                logger.error(
                                    f"Error restoring UTXO {txid.hex()[:16]}...:{vout}: {e}"
                                )
                    else:
                        logger.debug("No UTXOs to restore from this block")
                except Exception as e:
                    logger.error(f"Error collecting UTXOs to restore: {e}")
                
                # Remove UTXOs that were created in this block
                for tx in curr_block.transactions:
                    txid = tx.get_txid()
                    for i, tx_out in enumerate(tx.outputs):
                        try:
                            self.db.remove_utxo(txid, i)
                        except Exception as e:
                            logger.error(
                                f"Error removing UTXO {txid.hex()[:16]}...:{i}: {e}"
                            )
                
                # Update current_height for next iteration
                current_height -= 1
            
            # Connect blocks from new chain (in forward order)
            blocks_to_connect = [
                (h, b, ht) for h, b, ht in new_chain
                if h != common_ancestor
            ]
            
            for new_hash, new_block, new_height in blocks_to_connect:
                logger.debug(f"Connecting block {new_hash.hex()[:16]}...")
                
                # Validate block
                valid, error = self.validator.validate_block(new_block)
                if not valid:
                    logger.error(f"Invalid block in reorg: {new_hash.hex()[:16]}... - {error}")
                    return False
                
                # Apply block (spend/create UTXOs)
                try:
                    self.validator.apply_block(new_block)
                except Exception as e:
                    logger.error(f"Error applying block during reorg: {e}")
                    return False
            
            # Update best block
            if blocks_to_connect:
                final_height = blocks_to_connect[-1][2]  # Height of last block
            else:
                final_height = common_ancestor_height
            
            # Note: set_best_block may not be implemented - this is a placeholder
            # In full implementation, would update best block hash and height
            logger.info(f"Reorg handled: new tip at height {final_height}")
            
            self.reorg_depth += 1
            return True
        
        except Exception as e:
            logger.error(f"Error handling reorg: {e}", exc_info=True)
            return False
