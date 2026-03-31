"""
Ongoing block synchronization from the Bitcoin network.

This module implements continuous block synchronization after initial sync,
handling new block announcements, validation, and chain reorganization.
"""

import asyncio
import hashlib
import random
import time
import logging
from typing import Dict, Set, Optional, List, Tuple, Callable
from collections import defaultdict

from ouroboros.database import BlockchainDatabase, Block
from ouroboros.validation import BlockValidator, SIG_CACHE
from ouroboros.p2p_messages import (
    NetworkMessage,
    InvMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    BlockHeader,
    BlockMessage,
    CmpctBlockMessage,
    TxMessage,
    INV_TYPE_TX,
    INV_TYPE_BLOCK,
    MSG_WITNESS_TX,
    MSG_WTX,
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
        mempool=None,  # Optional mempool for re-adding txs after reorg
        fee_estimator=None,  # Optional FeeEstimator to feed confirmed-block fee data
    ):
        """Initialize block synchronizer."""
        self.db = db
        self.validator = validator
        self.peer_manager = peer_manager
        self.mempool = mempool
        self.fee_estimator = fee_estimator
        
        # Track requested blocks (hash -> request_time)
        # FIXME: race condition if called from multiple threads?
        self.requested_blocks: Dict[bytes, float] = {}

        # Track which peer each block was last requested from (hash -> Peer)
        self._block_request_peer: Dict[bytes, Peer] = {}

        # Track requested transactions (hash -> request_time)
        self._requested_txs: Dict[bytes, float] = {}
        
        # Track received blocks (hash -> Block)
        self.received_blocks: Dict[bytes, Block] = {}
        
        # Orphan blocks: hash -> Block (blocks whose parent is not in our chain)
        # Ref: bitcoin/src/net_processing.cpp orphan_work_set, ProcessOrphanTx
        self.orphan_blocks: Dict[bytes, Block] = {}
        self._max_orphans = 200
        
        # Track pending headers requests
        self.pending_headers: Dict[bytes, float] = {}  # locator_hash -> request_time
        
        # Reorg detection
        self.last_best_hash: Optional[bytes] = None
        self.reorg_depth: int = 0
        
        self._zmq_publisher = None

        self.running = False
        self._sync_task: Optional[asyncio.Task] = None
        
        # Message handlers per peer (peer -> handler_dict)
        self._peer_handlers: Dict[Peer, Dict[str, Callable]] = defaultdict(dict)

        # Headers-first sync: validated header chain waiting for block download.
        # List of (block_hash, header) in chain order (oldest first).
        self._validated_headers: List[Tuple[bytes, 'BlockHeader']] = []
        # Max blocks to have in-flight at once during headers-first sync.
        self._max_blocks_in_flight: int = 64

        # IBD block buffer: blocks that arrived out of order are held here
        # keyed by block_hash until their parent is connected.  After each
        # successful connect, _drain_block_buffer() processes buffered
        # children sequentially.
        self._ibd_block_buffer: Dict[bytes, Block] = {}
        self._max_ibd_buffer: int = 1024
    
    def set_zmq_publisher(self, publisher) -> None:
        """Attach a ZMQPublisher for real-time block/tx notifications."""
        self._zmq_publisher = publisher

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
        # Note: Peer class doesn't have unregister_handler, so we just remove from tracking
        if peer in self._peer_handlers:
            del self._peer_handlers[peer]
    
    def _make_inv_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            await self.handle_inv(msg, peer)
        return handler
    
    def _make_block_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            await self.handle_block(msg, peer)
        return handler
    
    def _make_headers_handler(self, peer: Peer):
        async def handler(msg: NetworkMessage):
            await self.handle_headers(msg, peer)
        return handler
    
    def _register_new_peers(self):
        """Register handlers for any newly connected peers."""
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = list(peers.values())
        new_count = 0
        for peer in peers:
            if not isinstance(peer, Peer):
                continue
            if peer in self._peer_handlers:
                continue
            peer.register_handler("inv", self._make_inv_handler(peer))
            peer.register_handler("block", self._make_block_handler(peer))
            peer.register_handler("headers", self._make_headers_handler(peer))
            self._peer_handlers[peer] = {
                "inv": self._make_inv_handler(peer),
                "block": self._make_block_handler(peer),
                "headers": self._make_headers_handler(peer),
            }
            new_count += 1
        if new_count:
            logger.info(f"Registered block_sync handlers for {new_count} new peers (total: {len(self._peer_handlers)})")

    async def sync_loop(self):
        """Main synchronization loop"""
        while self.running:
            try:
                # Register handlers for any new peers
                self._register_new_peers()

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
                
                # Get a peer that's ahead of us (rotate to avoid getting stuck).
                # Skip if we already have a header queue in progress — the
                # handle_headers continuation handles fetching the rest.
                # Sending another getheaders from the DB tip while headers
                # are already streaming just produces duplicate responses.
                sync_peer = self._get_sync_peer(best_height)
                if sync_peer and hasattr(sync_peer, 'start_height'):
                    if sync_peer.start_height > best_height and not self._validated_headers:
                        logger.info(
                            f"Behind by {sync_peer.start_height - best_height} blocks"
                        )
                        await self._catch_up(sync_peer, best_height)
                
                # Handle timeouts
                await self._handle_timeouts()

                # Drain any buffered blocks that can now be connected.
                await self._drain_block_buffer()

                # Advance headers-first download window (in case blocks
                # connected between sync_loop iterations).
                await self._request_next_blocks()

                # Prune validated headers that have been downloaded and connected.
                self._prune_validated_headers()

            except Exception as e:
                logger.error(f"Error in sync loop: {e}", exc_info=True)

            await asyncio.sleep(10)
    
    async def handle_inv(self, msg: NetworkMessage, peer: Peer):
        """Handle inventory announcement (blocks + transactions)."""
        try:
            inv = InvMessage.from_payload(msg.payload)
            # logger.debug(f'inv from {peer.host}:{peer.port}, {len(inv.inventory)} items')

            blocks_to_request = []
            txs_to_request = []

            # Expire stale tx requests (>60 s)
            now = time.time()
            stale = [h for h, t in self._requested_txs.items() if now - t > 60]
            for h in stale:
                self._requested_txs.pop(h, None)

            has_new_blocks = False
            for inv_type, inv_hash in inv.inventory:
                if inv_type == INV_TYPE_BLOCK:
                    existing_block = self.db.get_block(inv_hash)
                    if not existing_block:
                        has_new_blocks = True
                        # Directly request the block if not already in-flight.
                        # This is critical for receiving blocks from mining
                        # peers promptly (e.g., regtest mesh tests) rather
                        # than waiting for the full headers-first round-trip.
                        if inv_hash not in self.requested_blocks:
                            blocks_to_request.append((INV_TYPE_BLOCK, inv_hash))
                            self.requested_blocks[inv_hash] = now

                elif inv_type in (INV_TYPE_TX, MSG_WITNESS_TX, MSG_WTX):
                    # Request transactions we don't already have
                    if (
                        self.mempool
                        and not self.mempool.get_transaction(inv_hash)
                        and inv_hash not in self._requested_txs
                    ):
                        txs_to_request.append((MSG_WITNESS_TX, inv_hash))
                        self._requested_txs[inv_hash] = now

            network = (
                self.peer_manager.network
                if hasattr(self.peer_manager, "network")
                else "mainnet"
            )

            if has_new_blocks:
                # Also send getheaders so we learn the full chain structure
                # (headers-first approach for longer forks / initial sync).
                best_hash, best_height = self.db.get_best_block()
                locator = self._build_locator(best_height)
                if locator:
                    try:
                        getheaders = GetHeadersMessage(
                            version=70015,
                            locator_hashes=locator,
                            hash_stop=b'\x00' * 32,
                        )
                        await peer.send_message(getheaders.to_network_message(network))
                        logger.info(
                            f"Block inv from {peer.host}:{peer.port} — "
                            f"requesting headers (headers-first sync)"
                        )
                    except Exception as e:
                        logger.error(f"Failed to send getheaders: {e}")
                        peer.adjust_score(-5)

            if blocks_to_request:
                getdata = GetDataMessage(inventory=blocks_to_request)
                try:
                    await peer.send_message(getdata.to_network_message(network))
                    for _, bh in blocks_to_request:
                        self._block_request_peer[bh] = peer
                    logger.info(
                        f"Requested {len(blocks_to_request)} blocks directly "
                        f"from {peer.host}:{peer.port} (inv-triggered)"
                    )
                except Exception as e:
                    logger.error(f"Failed to request blocks: {e}")

            if txs_to_request:
                getdata = GetDataMessage(inventory=txs_to_request)
                try:
                    await peer.send_message(getdata.to_network_message(network))
                    logger.debug(
                        f"Requested {len(txs_to_request)} txs from "
                        f"{peer.host}:{peer.port}"
                    )
                except Exception as e:
                    logger.error(f"Failed to request txs: {e}")

        except Exception as e:
            logger.error(f"Error handling inv from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)
    
    async def handle_block(self, msg: NetworkMessage, peer: Peer):
        """Handle block delivery.

        During IBD (headers-first), blocks often arrive out of order from
        multiple peers.  Instead of treating out-of-order blocks as orphans
        (which breaks bootstrapping), we buffer them keyed by hash and
        drain the buffer sequentially after each successful connect.
        """
        try:
            from ouroboros.database import Block

            block = Block.deserialize(msg.payload)
            block_hash = block.hash

            # Remove from in-flight tracking
            if block_hash in self.requested_blocks:
                del self.requested_blocks[block_hash]
            self._block_request_peer.pop(block_hash, None)

            # Already have this block?
            if self.db.get_block(block_hash):
                return

            # Buffer the block (keyed by hash) for sequential processing.
            if len(self._ibd_block_buffer) < self._max_ibd_buffer:
                self._ibd_block_buffer[block_hash] = (block, msg.payload)
            else:
                logger.debug(
                    f"IBD buffer full ({self._max_ibd_buffer}), dropping "
                    f"{block_hash.hex()[:16]}..."
                )
                return

            # Try to drain buffered blocks in chain order.
            connected = await self._drain_block_buffer()

            if connected > 0:
                # Advance download window after connecting blocks.
                await self._request_next_blocks()

        except Exception as e:
            logger.error(f"Error handling block from {peer.host}:{peer.port}: {e}", exc_info=True)
            peer.adjust_score(-5)

    async def _drain_block_buffer(self) -> int:
        """Connect buffered blocks in chain order.

        Walks the validated header queue starting from the current tip,
        checking if the next expected block is in the buffer.  Connects
        as many sequential blocks as possible.

        Returns the number of blocks connected.
        """
        connected = 0
        current_hash, current_height = self.db.get_best_block()

        # Build a quick lookup: hash -> (block, raw_payload) from the buffer.
        while True:
            # Find the next expected block hash from the header chain.
            next_hash = None
            for bh, _hdr in self._validated_headers:
                if self.db.get_block(bh):
                    continue  # already connected
                next_hash = bh
                break

            if next_hash is None:
                break  # no more headers to process

            # Is the next block in our buffer?
            if next_hash not in self._ibd_block_buffer:
                break  # need to wait for download

            block, raw_payload = self._ibd_block_buffer.pop(next_hash)

            # Validate
            new_height = current_height + 1
            valid, error = self.validator.validate_block(block, known_height=new_height)
            if not valid:
                logger.warning(
                    f"✗ Invalid block at height {new_height}: {error}"
                )
                # Don't ban — might be our validation bug. Just skip.
                break

            # Connect block
            try:
                if hasattr(self.db._db, 'connect_block_from_bytes'):
                    self.db._db.connect_block_from_bytes(raw_payload, new_height)
                else:
                    self.validator.apply_block(block)
            except Exception as e:
                logger.error(f"Failed to connect block at height {new_height}: {e}")
                break

            connected += 1
            current_height = new_height
            current_hash = next_hash

            # Feed fee estimator
            if self.fee_estimator is not None:
                try:
                    self.fee_estimator.process_block(block, new_height, self.mempool)
                except Exception:
                    pass

            # Remove confirmed txs from mempool
            if self.mempool is not None:
                self.mempool.remove_block_transactions(block)

            if self._zmq_publisher:
                self._zmq_publisher.notify_block(block)

            # Log progress every 1000 blocks
            if new_height % 1000 == 0 or connected == 1:
                logger.info(
                    f"✓ Block {new_height} connected "
                    f"(buffer={len(self._ibd_block_buffer)}, "
                    f"in-flight={len(self.requested_blocks)})"
                )

        return connected
    
    def _header_to_block_hash(self, header) -> bytes:
        header_bytes = header.serialize()
        block_hash_raw = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
        return block_hash_raw  # internal byte order — matches DB and wire

    async def handle_headers(self, msg: NetworkMessage, peer: Peer):
        """Handle headers message — headers-first sync.

        Validates that received headers form a chain connecting to our
        current tip (or to the end of already-validated headers), then
        queues them for block download in a limited window.  This mirrors
        Bitcoin Core's approach in net_processing.cpp where block data is
        only requested after headers have been validated and connected.
        """
        try:
            headers_msg = HeadersMessage.from_payload(msg.payload)

            if not headers_msg.headers:
                return

            logger.info(f"Received {len(headers_msg.headers)} headers from {peer.host}:{peer.port}")

            # Determine expected prev_hash: either last validated header or our DB tip.
            if self._validated_headers:
                expected_prev = self._validated_headers[-1][0]  # hash of last queued header
            else:
                best_hash, _ = self.db.get_best_block()
                expected_prev = best_hash

            accepted = 0
            for header in headers_msg.headers:
                block_hash = self._header_to_block_hash(header)

                # Skip headers we already have in the DB.
                if self.db.get_block(block_hash):
                    expected_prev = block_hash
                    continue

                # Skip duplicates already in our validated queue.
                known_hashes = {h for h, _ in self._validated_headers}
                if block_hash in known_hashes:
                    expected_prev = block_hash
                    continue

                # Validate chain continuity: header must extend expected_prev.
                header_prev = header.prev_blockhash if hasattr(header, 'prev_blockhash') else None
                if header_prev != expected_prev:
                    logger.warning(
                        f"Header {block_hash.hex()[:16]}... does not connect "
                        f"(expected prev {expected_prev.hex()[:16]}..., "
                        f"got {header_prev.hex()[:16] if header_prev else 'None'}...) — "
                        f"dropping remaining {len(headers_msg.headers) - accepted} headers"
                    )
                    break

                self._validated_headers.append((block_hash, header))
                expected_prev = block_hash
                accepted += 1

            if accepted:
                logger.info(
                    f"Validated {accepted} new headers (queue: {len(self._validated_headers)})"
                )
                # Kick off block downloads for the next window.
                await self._request_next_blocks()

                # If we received a full batch (2000 headers), ask for more.
                # Only send continuation when we actually accepted new headers;
                # otherwise duplicate responses (from sync_loop's periodic
                # getheaders) each spawn their own continuation, creating an
                # exponential flood of redundant requests that drowns out the
                # one legitimate continuation.
                if len(headers_msg.headers) >= 2000:
                    network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
                    last_hash = self._validated_headers[-1][0]
                    getheaders = GetHeadersMessage(
                        version=70015,
                        locator_hashes=[last_hash],
                        hash_stop=b'\x00' * 32,
                    )
                    try:
                        await peer.send_message(getheaders.to_network_message(network))
                        logger.info(f"Requesting more headers after {last_hash.hex()[:16]}...")
                    except Exception as e:
                        logger.error(f"Failed to request continuation headers: {e}")

        except Exception as e:
            logger.error(f"Error handling headers from {peer.host}:{peer.port}: {e}")
            peer.adjust_score(-2)
            if hasattr(self.peer_manager, 'misbehaving'):
                addr = f"{peer.host}:{peer.port}"
                self.peer_manager.misbehaving(addr, 20, f"invalid headers: {e}")

    async def _request_next_blocks(self):
        """Request blocks from the validated header queue up to the in-flight limit.

        Anchored to the connected tip: only requests blocks that are within
        _max_blocks_in_flight of the last block we've actually stored in the
        DB.  This ensures blocks arrive roughly in order and can chain
        sequentially, avoiding orphan cascades.
        """
        if not self._validated_headers:
            return

        network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"

        # Find where our connected tip sits in the header queue.
        # After pruning, index 0 is the first header not yet in the DB
        # (or already in DB if pruning hasn't run yet).
        tip_idx = -1
        for i, (bh, _) in enumerate(self._validated_headers):
            if self.db.get_block(bh):
                tip_idx = i
            else:
                break  # Headers are in order; first missing = end of connected chain.

        # Request blocks starting just after the connected tip, up to window size.
        start = tip_idx + 1
        in_flight = len(self.requested_blocks)
        available = max(0, self._max_blocks_in_flight - in_flight)
        if available == 0:
            return

        to_request: List[Tuple[int, bytes]] = []
        for i in range(start, min(start + available, len(self._validated_headers))):
            block_hash, _ = self._validated_headers[i]
            if block_hash not in self.requested_blocks and not self.db.get_block(block_hash):
                to_request.append((INV_TYPE_BLOCK, block_hash))
                self.requested_blocks[block_hash] = time.time()

        if not to_request:
            return

        # Distribute across connected peers round-robin.
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            candidates = [p for p in self.peer_manager.get_all_ready_peers()
                          if isinstance(p, Peer) and p.is_connected()]
        else:
            candidates = []
        if not candidates:
            return

        per_peer: dict[Peer, list] = {c: [] for c in candidates}
        for i, item in enumerate(to_request):
            target = candidates[i % len(candidates)]
            per_peer[target].append(item)

        for target_peer, items in per_peer.items():
            if not items:
                continue
            try:
                getdata = GetDataMessage(inventory=items)
                await target_peer.send_message(getdata.to_network_message(network))
                for _, bh in items:
                    self._block_request_peer[bh] = target_peer
            except Exception as e:
                logger.error(f"Failed to send getdata to {target_peer.host}:{target_peer.port}: {e}")
                target_peer.adjust_score(-2)

        logger.info(f"Requested {len(to_request)} blocks (tip+{start}, in-flight: {in_flight}+{len(to_request)}/{self._max_blocks_in_flight})")

    def _prune_validated_headers(self):
        """Remove validated headers that have already been connected to the chain."""
        if not self._validated_headers:
            return
        # Find how many leading headers are now in the DB.
        prune_count = 0
        for block_hash, _ in self._validated_headers:
            if self.db.get_block(block_hash):
                prune_count += 1
            else:
                break
        if prune_count > 0:
            self._validated_headers = self._validated_headers[prune_count:]

    async def _announce_block(
        self, block: Block, block_hash: bytes, exclude_peer: Peer | None = None,
    ) -> None:
        """Announce a validated block to peers based on their preferences."""
        if not hasattr(self.peer_manager, 'get_all_ready_peers'):
            return
        network = getattr(self.peer_manager, 'network', 'mainnet')

        for p in self.peer_manager.get_all_ready_peers():
            if p is exclude_peer:
                continue
            try:
                if p.wants_cmpctblock:
                    import os
                    from ouroboros.compact_blocks import CompactBlock
                    nonce = int.from_bytes(os.urandom(8), 'little')
                    cb = CompactBlock.from_block(block, nonce)
                    msg = CmpctBlockMessage(payload_bytes=cb.serialize())
                    await p.send_message(msg.to_network_message(network))
                elif p.wants_headers:
                    hdr = BlockHeader(
                        version=block.version,
                        prev_blockhash=block.prev_blockhash,
                        merkle_root=block.merkle_root,
                        timestamp=block.timestamp,
                        bits=block.bits,
                        nonce=block.nonce,
                    )
                    msg = HeadersMessage(headers=[hdr])
                    await p.send_message(msg.to_network_message(network))
                else:
                    inv = InvMessage(inventory=[(INV_TYPE_BLOCK, block_hash)])
                    await p.send_message(inv.to_network_message(network))
            except Exception as e:
                logger.debug(f"Failed to announce block to {p.host}:{p.port}: {e}")

    async def _process_orphans(self, applied_block_hash: bytes) -> None:
        """Process orphan blocks that may now have their parent in our chain."""
        to_process = [
            (h, b) for h, b in self.orphan_blocks.items()
            if b.prev_blockhash == applied_block_hash
        ]
        
        for block_hash, block in to_process:
            del self.orphan_blocks[block_hash]
            
            valid, error = self.validator.validate_block(block)
            if not valid:
                logger.warning(f"Orphan block {block_hash.hex()[:16]}... invalid: {error}")
                continue
            
            # Orphan extends the block we just applied; check if it matches current tip
            current_hash, _ = self.db.get_best_block()
            if block.prev_blockhash != current_hash:
                # Orphan's parent is not current tip; might need reorg
                reorg_success = await self._handle_reorg(block, block_hash)
                if not reorg_success:
                    logger.error("Failed to handle reorg for orphan")
                else:
                    await self._process_orphans(block_hash)
            else:
                self.validator.apply_block(block)
                block_height = block.height if hasattr(block, 'height') and block.height else 0
                logger.info(f"✓ Connected orphan block {block_height}: {block_hash.hex()[:16]}...")
                
                await self._announce_block(block, block_hash)
                await self._process_orphans(block_hash)

    async def _catch_up(self, peer: Peer, our_height: int):
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
        """Build block locator (exponential spacing)."""
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
    
    def _get_sync_peer(self, our_height: int) -> Optional[Peer]:
        """Pick a random peer that's ahead of us for header requests."""
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
        else:
            peers = getattr(self.peer_manager, 'peers', [])
            if isinstance(peers, dict):
                peers = list(peers.values())
        candidates = [
            p for p in peers
            if isinstance(p, Peer) and hasattr(p, 'start_height')
            and p.start_height > our_height and p.is_connected()
        ]
        if not candidates:
            return None
        return random.choice(candidates)

    def _get_peer_with_highest_block(self) -> Optional[Peer]:
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
        """Re-request blocks that timed out, rotating to a different peer each time."""
        now = time.time()
        timeout = 60.0

        timed_out = [
            block_hash for block_hash, request_time in self.requested_blocks.items()
            if now - request_time > timeout
        ]

        if not timed_out:
            return

        # Get all connected peers once for the whole batch
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            all_peers = [p for p in self.peer_manager.get_all_ready_peers()
                         if isinstance(p, Peer)]
        else:
            raw = getattr(self.peer_manager, 'peers', [])
            if isinstance(raw, dict):
                raw = list(raw.values())
            all_peers = [p for p in raw if isinstance(p, Peer)]

        # Penalize each failed peer only ONCE per cycle (not per block)
        failed_peers = set()
        for block_hash in timed_out:
            failed_peer = self._block_request_peer.get(block_hash)
            if failed_peer is not None:
                failed_peers.add(failed_peer)
        for peer in failed_peers:
            peer.adjust_score(-1)

        connected_peers = [p for p in all_peers if p.is_connected()]

        # If no peers available, clear all in-flight requests so they re-queue on reconnect
        if not connected_peers:
            logger.warning(
                f"{len(timed_out)} block requests timed out with 0 available peers, "
                f"clearing in-flight requests for re-queue"
            )
            for block_hash in timed_out:
                del self.requested_blocks[block_hash]
                self._block_request_peer.pop(block_hash, None)
            return

        logger.warning(
            f"{len(timed_out)} block requests timed out "
            f"(failed peers: {len(failed_peers)}, available peers: {len(connected_peers)})"
        )

        # Batch re-requests: round-robin across available peers, preferring non-failed ones
        preferred = [p for p in connected_peers if p not in failed_peers]
        if not preferred:
            preferred = connected_peers

        # Group re-requests by target peer for batched getdata messages
        peer_batches: dict = {}
        for i, block_hash in enumerate(timed_out):
            peer = preferred[i % len(preferred)]
            peer_batches.setdefault(peer, []).append(block_hash)

        network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"

        for peer, block_hashes in peer_batches.items():
            try:
                inventory = [(INV_TYPE_BLOCK, bh) for bh in block_hashes]
                getdata = GetDataMessage(inventory=inventory)
                getdata_msg = getdata.to_network_message(network)
                await peer.send_message(getdata_msg)
                for bh in block_hashes:
                    self.requested_blocks[bh] = now
                    self._block_request_peer[bh] = peer
                logger.info(f"Re-requested {len(block_hashes)} blocks from {peer.host}:{peer.port}")
            except Exception as e:
                logger.error(f"Failed to re-request {len(block_hashes)} blocks from {peer.host}:{peer.port}: {e}")
                for bh in block_hashes:
                    del self.requested_blocks[bh]
                    self._block_request_peer.pop(bh, None)
    
    async def _find_transaction_in_blocks(self, txid: bytes, max_height: int, min_height: int = 0) -> Optional['Transaction']:
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
        """Restore UTXOs that were spent in this block."""
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
        """Handle chain reorganization."""
        logger.warning(f"Handling chain reorganization to new tip: {new_chain_tip.hex()[:16]}...")

        # Clear signature cache on reorg to prevent stale entries from invalidated chain
        SIG_CACHE.clear()

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
            
            # Build new chain back (new_block is the tip we received, may not be in db yet)
            temp_hash = new_chain_tip
            temp_height = current_height
            for i in range(100):
                if temp_hash is None:
                    break
                # Use the block we received if it's the tip; otherwise get from db
                if temp_hash == new_chain_tip and new_block.hash == new_chain_tip:
                    block = new_block
                else:
                    block = self.db.get_block(temp_hash)
                if not block:
                    logger.warning(
                        f"Block {temp_hash.hex()[:16]}... not in database, cannot complete reorg"
                    )
                    return False
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
            
            # Connect blocks from new chain (ancestor+1 to tip; new_chain is tip-first so reverse)
            blocks_to_connect = [
                (h, b, ht) for h, b, ht in new_chain
                if h != common_ancestor
            ]
            blocks_to_connect = list(reversed(blocks_to_connect))

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
                
                # Remove transactions now in block from mempool
                if self.mempool:
                    self.mempool.remove_block_transactions(new_block)
                
                # Process orphans that may now have their parent
                await self._process_orphans(new_hash)
            
            # Update best block
            if blocks_to_connect:
                final_hash = blocks_to_connect[-1][0]
                final_height = blocks_to_connect[-1][2]
                try:
                    self.db.update_best_block(final_hash, final_height)
                except Exception as e:
                    logger.error(f"Failed to update best block after reorg: {e}")
                    return False
            else:
                final_height = common_ancestor_height
                final_hash = common_ancestor

            # Re-add transactions from disconnected blocks to mempool (re-validate)
            if self.mempool:
                for curr_hash, curr_block, _ in reversed(blocks_to_disconnect):
                    for tx in curr_block.transactions:
                        if not tx.is_coinbase:
                            _, best_h = self.db.get_best_block()
                            success, _ = self.mempool.add_transaction(tx, best_h)
                            if success:
                                logger.debug(
                                    f"Re-added tx {tx.get_txid().hex()[:16]}... to mempool"
                                )

            logger.info(f"Reorg handled: new tip at height {final_height}")
            self.reorg_depth += 1
            return True
        
        except Exception as e:
            logger.error(f"Error handling reorg: {e}", exc_info=True)
            return False
