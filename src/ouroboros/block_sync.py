"""
Ongoing block synchronization from the Bitcoin network.

This module implements continuous block synchronization after initial sync,
handling new block announcements, validation, and chain reorganization.
"""

import asyncio
import hashlib
import logging
import random
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Optional

# Bitcoin Core net_processing.cpp: MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16.
# Bounds the damage a single slow peer can do during IBD — without this,
# the global 256-slot window divided across ~8 peers gives each peer ~32
# concurrent requests, so one peer stalling holds 32 blocks hostage for
# the full 20s timeout window.
MAX_BLOCKS_IN_FLIGHT_PER_PEER = 16

from ouroboros.database import Block, BlockchainDatabase, Transaction
from ouroboros.p2p_messages import (
    INV_TYPE_BLOCK,
    INV_TYPE_TX,
    MSG_WITNESS_BLOCK,
    MSG_WITNESS_TX,
    MSG_WTX,
    BlockHeader,
    CmpctBlockMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    InvMessage,
    NetworkMessage,
)
from ouroboros.peer import Peer
from ouroboros.validation import SIG_CACHE, BlockValidator

logger = logging.getLogger(__name__)


def _distribute_blocks_round_robin(
    items: list,
    candidates: list,
    peer_load: dict,
    max_per_peer: int,
) -> tuple[dict, list]:
    """Round-robin distribute items across candidates, respecting per-peer cap.

    ``peer_load`` is mutated in place to reflect new assignments so callers
    can chain multiple distribution passes.  Returns ``(per_peer, assigned)``
    where ``per_peer`` is a ``candidate -> [items]`` dict covering every
    candidate (possibly with empty lists) and ``assigned`` is the subset of
    ``items`` that was placed.  Any remaining items are deferred — all
    candidates were at cap when iteration stopped.
    """
    per_peer: dict = {c: [] for c in candidates}
    assigned: list = []
    if not candidates:
        return per_peer, assigned
    n = len(candidates)
    peer_idx = 0
    for item in items:
        for attempt in range(n):
            target = candidates[(peer_idx + attempt) % n]
            if peer_load.get(target, 0) < max_per_peer:
                per_peer[target].append(item)
                peer_load[target] = peer_load.get(target, 0) + 1
                assigned.append(item)
                peer_idx = (peer_idx + attempt + 1) % n
                break
        else:
            # All candidates at cap — stop trying further items this round.
            break
    return per_peer, assigned


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
        self.requested_blocks: dict[bytes, float] = {}

        # Track which peer each block was last requested from (hash -> Peer)
        self._block_request_peer: dict[bytes, Peer] = {}

        # Track requested transactions (hash -> request_time)
        self._requested_txs: dict[bytes, float] = {}

        # Track received blocks (hash -> Block)
        self.received_blocks: dict[bytes, Block] = {}

        # Orphan blocks: hash -> Block (blocks whose parent is not in our chain)
        # Ref: bitcoin/src/net_processing.cpp orphan_work_set, ProcessOrphanTx
        self.orphan_blocks: dict[bytes, Block] = {}
        self._max_orphans = 200

        # Track pending headers requests
        self.pending_headers: dict[bytes, float] = {}  # locator_hash -> request_time

        # Reorg detection
        self.last_best_hash: bytes | None = None
        self.reorg_depth: int = 0

        self._zmq_publisher = None

        self.running = False
        self._sync_task: asyncio.Task | None = None

        # Message handlers per peer (peer -> handler_dict)
        self._peer_handlers: dict[Peer, dict[str, Callable]] = defaultdict(dict)

        # Headers-first sync: validated header chain waiting for block download.
        # List of (block_hash, header) in chain order (oldest first).
        self._validated_headers: list[tuple[bytes, BlockHeader]] = []
        # Max blocks to have in-flight at once during headers-first sync.
        self._max_blocks_in_flight: int = 256

        # Single sync peer for header downloads (Bitcoin Core pattern).
        # Only one peer is sent getheaders at a time to prevent out-of-order
        # header batches.  Switches to a different peer after a stall.
        self._header_sync_peer: Peer | None = None
        self._header_sync_time: float = 0.0  # When the last getheaders was sent
        self._header_sync_stall_timeout: float = 30.0  # Switch peer after 30s

        # IBD block buffer: blocks that arrived out of order are held here
        # keyed by block_hash until their parent is connected.  After each
        # successful connect, _drain_block_buffer() processes buffered
        # children sequentially.
        self._ibd_block_buffer: dict[bytes, Block] = {}
        self._max_ibd_buffer: int = 1024

        # Drain-loop stage timings (W60 B0 instrumentation).
        # Accumulates wall-clock ns spent in each stage since the last
        # summary log.  Emitted every _drain_log_every blocks connected,
        # then reset.  Used to choose between B1/B2/B3 pipelining designs.
        self._drain_stat_count: int = 0
        self._drain_stat_deserialize_ns: int = 0
        self._drain_stat_validate_ns: int = 0
        self._drain_stat_connect_ns: int = 0
        self._drain_log_every: int = 1000

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

                # Single-peer header sync (Bitcoin Core pattern).
                # Send getheaders to ONE designated peer at a time.
                # Switch peer if the current one stalls (no headers in 30s).
                now = time.time()
                if self._header_sync_peer and not self._header_sync_peer.is_connected():
                    self._header_sync_peer = None  # Peer disconnected

                if self._header_sync_peer and (now - self._header_sync_time > self._header_sync_stall_timeout):
                    # Sync peer stalled — switch to a different one
                    logger.info(f"Header sync peer {self._header_sync_peer.host} stalled, switching")
                    # Score misbehavior for stalling block downloads (+50)
                    if self.peer_manager:
                        from ouroboros.banman import SCORE_BLOCK_DOWNLOAD_STALL
                        self.peer_manager.misbehaving(
                            self._header_sync_peer.host, SCORE_BLOCK_DOWNLOAD_STALL,
                            "block download stalling")
                    self._header_sync_peer = None

                if not self._header_sync_peer:
                    self._header_sync_peer = self._get_sync_peer(best_height)
                    if self._header_sync_peer:
                        self._header_sync_time = now

                if self._header_sync_peer:
                    await self._catch_up(self._header_sync_peer, best_height)

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

            # During IBD, tick fast so timeout handling / re-requests don't
            # wait 10s.  After IBD (header queue drained), slow down.
            if self._validated_headers:
                await asyncio.sleep(1)
            else:
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
                    if not self.db.has_block_hash(inv_hash):
                        has_new_blocks = True
                        # Directly request the block if not already in-flight.
                        # This is critical for receiving blocks from mining
                        # peers promptly (e.g., regtest mesh tests) rather
                        # than waiting for the full headers-first round-trip.
                        if inv_hash not in self.requested_blocks:
                            blocks_to_request.append((MSG_WITNESS_BLOCK, inv_hash))
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
                # Don't send getheaders here — let the sync_loop's single-peer
                # approach handle it.  Sending getheaders to the inv peer AND
                # the sync peer creates overlapping header batches that arrive
                # out of order and get dropped.  Instead, just designate this
                # peer as the sync peer if we don't have one.
                if not self._header_sync_peer or not self._header_sync_peer.is_connected():
                    self._header_sync_peer = peer
                    self._header_sync_time = time.time()
                    logger.info(
                        f"Block inv from {peer.host}:{peer.port} — "
                        f"set as header sync peer"
                    )

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

        Perf: the block hash is computed from the 80-byte header only (cheap
        double-SHA256).  Full Python-side `Block.deserialize` is deferred to
        `_drain_block_buffer` where it runs inside `asyncio.to_thread`, so
        the event loop is not stalled by a ~1 MB per-block deser each time a
        peer delivers a block.  This is the primary bottleneck per py-spy
        (W13): every inbound block held the GIL-owning MainThread for the
        length of `Block.deserialize`, starving timeout handling, RPC, and
        peer message dispatch — including blocks already sitting in the OS
        socket buffer from other peers.
        """
        try:
            payload = msg.payload
            if len(payload) < 80:
                logger.error(f"Block payload too short from {peer.host}:{peer.port}")
                peer.adjust_score(-5)
                return

            # Compute block hash from the 80-byte header only.  This matches
            # wire / DB internal byte order used elsewhere in the codebase
            # (see `_header_to_block_hash`).
            block_hash = hashlib.sha256(
                hashlib.sha256(payload[:80]).digest()
            ).digest()

            # Remove from in-flight tracking
            if block_hash in self.requested_blocks:
                del self.requested_blocks[block_hash]
            self._block_request_peer.pop(block_hash, None)

            # Already have this block?
            if self.db.has_block_hash(block_hash):
                return

            # Buffer the raw payload (keyed by hash) for sequential
            # processing.  `None` sentinel means "not yet deserialized" —
            # the drainer will deserialize lazily in a worker thread when it
            # actually needs to validate/connect this block.
            if len(self._ibd_block_buffer) < self._max_ibd_buffer:
                self._ibd_block_buffer[block_hash] = (None, payload)
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

        # Find the first unconnected header index by scanning once, then
        # advance linearly.  The old code re-scanned from index 0 and
        # called db.get_block() for every already-connected header on
        # each iteration, which was O(n^2).
        header_idx = 0
        for i, (bh, _hdr) in enumerate(self._validated_headers):
            if self.db.has_block_hash(bh):
                header_idx = i + 1
            else:
                break

        while header_idx < len(self._validated_headers):
            next_hash, _ = self._validated_headers[header_idx]

            # Is the next block in our buffer?
            if next_hash not in self._ibd_block_buffer:
                break  # need to wait for download

            block, raw_payload = self._ibd_block_buffer.pop(next_hash)

            # Lazy-deserialize: `handle_block` defers the ~1 MB Python-side
            # `Block.deserialize` here so it runs in a worker thread and
            # does not stall the event loop on block arrival.  Sentinel
            # `None` means "not yet deserialized".
            deserialize_ns = 0
            if block is None:
                t0 = time.perf_counter_ns()
                try:
                    block = await asyncio.to_thread(Block.deserialize, raw_payload)
                except Exception as e:
                    logger.warning(
                        f"Failed to deserialize buffered block "
                        f"{next_hash.hex()[:16]}...: {e}"
                    )
                    # Deserialization failure is unrecoverable for this block —
                    # the bytes are corrupt.  Drop it and let the timeout handler
                    # re-fetch from a different peer.
                    break
                deserialize_ns = time.perf_counter_ns() - t0

            # Validate and connect in a thread to avoid blocking the event
            # loop.  Individual block validations at higher heights can take
            # seconds (Rust FFI + DB writes).  Running them in a thread lets
            # the event loop service RPC requests and peer messages meanwhile.
            new_height = current_height + 1
            t_val = time.perf_counter_ns()
            valid, error = await asyncio.to_thread(
                self.validator.validate_block, block, known_height=new_height
            )
            validate_ns = time.perf_counter_ns() - t_val
            if not valid:
                logger.warning(
                    f"✗ Invalid block at height {new_height}: {error}"
                )
                # "Previous block not found" is a transient ordering error —
                # the block data is good but the parent is not yet in the DB.
                # Put the block back in the buffer so the next drain attempt
                # can try again once the parent has been connected.
                # Any other validation error is a permanent failure: the block
                # bytes are bogus (sent by a misbehaving peer).  Drop it so
                # the timeout handler re-fetches from a different peer.
                if error == "Previous block not found":
                    self._ibd_block_buffer[next_hash] = (block, raw_payload)
                break

            # Connect block
            t_con = time.perf_counter_ns()
            try:
                if hasattr(self.db, 'connect_block_from_bytes'):
                    await asyncio.to_thread(
                        self.db.connect_block_from_bytes, raw_payload, new_height
                    )
                else:
                    await asyncio.to_thread(self.validator.apply_block, block)
            except Exception as e:
                logger.error(f"Failed to connect block at height {new_height}: {e}")
                # DB connect failure is also transient (e.g. chain-tip mismatch
                # due to a concurrent update).  Put the block back so we retry.
                self._ibd_block_buffer[next_hash] = (block, raw_payload)
                break
            connect_ns = time.perf_counter_ns() - t_con

            # W60 B0: accumulate per-stage timings.  Summary emitted every
            # _drain_log_every blocks to characterise the drain-loop
            # bottleneck (deserialize vs validate vs connect) without
            # per-block log spam.  Chosen pipelining design (B1–B5) depends
            # on this histogram.
            self._drain_stat_count += 1
            self._drain_stat_deserialize_ns += deserialize_ns
            self._drain_stat_validate_ns += validate_ns
            self._drain_stat_connect_ns += connect_ns
            if self._drain_stat_count >= self._drain_log_every:
                n = self._drain_stat_count
                ds_ms = self._drain_stat_deserialize_ns / n / 1_000_000
                va_ms = self._drain_stat_validate_ns / n / 1_000_000
                co_ms = self._drain_stat_connect_ns / n / 1_000_000
                total_ms = ds_ms + va_ms + co_ms
                logger.info(
                    f"drain stats (last {n} blk): "
                    f"deserialize={ds_ms:.1f}ms "
                    f"validate={va_ms:.1f}ms "
                    f"connect={co_ms:.1f}ms "
                    f"total={total_ms:.1f}ms/blk "
                    f"(~{3600_000 / total_ms:.0f} blk/hr if drain-bound)"
                )
                self._drain_stat_count = 0
                self._drain_stat_deserialize_ns = 0
                self._drain_stat_validate_ns = 0
                self._drain_stat_connect_ns = 0

            connected += 1
            current_height = new_height
            header_idx += 1

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

            # Yield to the event loop after each block so that RPC handlers,
            # peer message processing, and other coroutines are not starved
            # during IBD.  Without this, the while loop holds the event loop
            # for the entire drain (potentially hundreds of blocks), causing
            # multi-second RPC latency spikes.
            await asyncio.sleep(0)

        # Prune connected headers to prevent unbounded growth
        if connected > 0:
            self._prune_validated_headers()

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

            # Throttle header accumulation: if we already have a huge backlog
            # of validated headers waiting for block download, skip processing
            # more until we catch up.  This prevents unbounded memory growth
            # and keeps the set-dedup cost manageable.
            _MAX_HEADER_QUEUE = 50_000
            if len(self._validated_headers) > _MAX_HEADER_QUEUE:
                logger.debug(
                    f"Header queue at {len(self._validated_headers)}, "
                    f"skipping batch until blocks catch up"
                )
                return

            # Determine expected prev_hash: either last validated header or our DB tip.
            if self._validated_headers:
                expected_prev = self._validated_headers[-1][0]  # hash of last queued header
            else:
                best_hash, _ = self.db.get_best_block()
                expected_prev = best_hash

            accepted = 0
            # Build the known-hash set ONCE before the loop instead of
            # rebuilding it for every header.  With 200K+ queued headers
            # this was O(n*m) and burned 97% CPU, starving RPC.
            known_hashes = {h for h, _ in self._validated_headers}
            for header in headers_msg.headers:
                block_hash = self._header_to_block_hash(header)

                # Skip headers we already have in the DB.
                if self.db.has_block_hash(block_hash):
                    expected_prev = block_hash
                    continue

                # Skip duplicates already in our validated queue.
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
                known_hashes.add(block_hash)
                expected_prev = block_hash
                accepted += 1

            if accepted:
                logger.info(
                    f"Validated {accepted} new headers (queue: {len(self._validated_headers)})"
                )
                # Reset sync peer stall timer on successful headers
                if peer == self._header_sync_peer:
                    self._header_sync_time = time.time()
                # Kick off block downloads for the next window.
                await self._request_next_blocks()

                # If we received a full batch (2000 headers), ask for more.
                # Only send continuation when we actually accepted new headers;
                # otherwise duplicate responses (from sync_loop's periodic
                # getheaders) each spawn their own continuation, creating an
                # exponential flood of redundant requests that drowns out the
                # one legitimate continuation.
                if len(headers_msg.headers) >= 2000:
                    # Send continuation to the SAME peer (which is the sync
                    # peer).  This ensures sequential header batches from one
                    # peer, avoiding out-of-order interleaving.
                    target = self._header_sync_peer if self._header_sync_peer and self._header_sync_peer.is_connected() else peer
                    network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"
                    last_hash = self._validated_headers[-1][0]
                    getheaders = GetHeadersMessage(
                        version=70015,
                        locator_hashes=[last_hash],
                        hash_stop=b'\x00' * 32,
                    )
                    try:
                        await target.send_message(getheaders.to_network_message(network))
                        self._header_sync_time = time.time()
                        logger.info(f"Requesting more headers after {last_hash.hex()[:16]}... from {target.host}")
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
            if self.db.has_block_hash(bh):
                tip_idx = i
            else:
                break  # Headers are in order; first missing = end of connected chain.

        # Request blocks starting just after the connected tip, up to window size.
        start = tip_idx + 1
        in_flight = len(self.requested_blocks)
        available = max(0, self._max_blocks_in_flight - in_flight)
        if available == 0:
            return

        to_request: list[tuple[int, bytes]] = []
        for i in range(start, min(start + available, len(self._validated_headers))):
            block_hash, _ = self._validated_headers[i]
            if block_hash not in self.requested_blocks and not self.db.has_block_hash(block_hash):
                to_request.append((MSG_WITNESS_BLOCK, block_hash))

        if not to_request:
            return

        # Distribute across connected peers round-robin, respecting the
        # per-peer in-flight cap.
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            candidates = [p for p in self.peer_manager.get_all_ready_peers()
                          if isinstance(p, Peer) and p.is_connected()]
        else:
            candidates = []
        if not candidates:
            return

        peer_load = Counter(self._block_request_peer.values())
        per_peer, assigned = _distribute_blocks_round_robin(
            to_request, candidates, peer_load, MAX_BLOCKS_IN_FLIGHT_PER_PEER,
        )

        if not assigned:
            return

        now = time.time()
        for _, bh in assigned:
            self.requested_blocks[bh] = now

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
                # Un-mark blocks we failed to dispatch so another peer can try them.
                for _, bh in items:
                    self.requested_blocks.pop(bh, None)
                    self._block_request_peer.pop(bh, None)

        deferred = len(to_request) - len(assigned)
        extra = f", deferred {deferred} (all peers at cap)" if deferred else ""
        logger.info(
            f"Requested {len(assigned)} blocks (tip+{start}, "
            f"in-flight: {in_flight}+{len(assigned)}/{self._max_blocks_in_flight}"
            f"{extra})"
        )

    def _prune_validated_headers(self):
        """Remove validated headers that have already been connected to the chain."""
        if not self._validated_headers:
            return
        # Find how many leading headers are now in the DB.
        prune_count = 0
        for block_hash, _ in self._validated_headers:
            if self.db.has_block_hash(block_hash):
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

    def _build_locator(self, height: int) -> list[bytes]:
        """Build block locator (exponential spacing).

        Uses the cheap Rust-side ``get_block_hash_by_height`` which returns the
        32-byte hash directly, instead of the full block (which would force a
        complete tx-by-tx deserialisation of a ~1MB block through PyO3 just to
        read ``block.hash``). The locator is rebuilt every ``sync_loop`` tick
        (1s during IBD) so the savings are substantial at high tip heights.
        """
        locator = []
        step = 1
        current_height = height

        while current_height > 0:
            block_hash = self.db.get_block_hash_by_height(current_height)
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
        genesis_hash = self.db.get_block_hash_by_height(0)
        if isinstance(genesis_hash, bytes) and len(genesis_hash) == 32:
            if genesis_hash not in locator:
                locator.append(genesis_hash)

        return locator

    def _get_sync_peer(self, our_height: int) -> Peer | None:
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

    def _get_peer_with_highest_block(self) -> Peer | None:
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
        timeout = 20.0  # Reduced from 60s for faster IBD peer rotation

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

        # Group re-requests by target peer, respecting the per-peer in-flight
        # cap.  `peer_load` starts from the live in-flight map minus the blocks
        # we're about to re-assign (they're still in _block_request_peer but
        # their old peer slot no longer counts toward capacity).
        peer_load = Counter(self._block_request_peer.values())
        for bh in timed_out:
            old_peer = self._block_request_peer.get(bh)
            if old_peer is not None and peer_load[old_peer] > 0:
                peer_load[old_peer] -= 1

        to_items = [(MSG_WITNESS_BLOCK, bh) for bh in timed_out]
        per_peer, assigned = _distribute_blocks_round_robin(
            to_items, preferred, peer_load, MAX_BLOCKS_IN_FLIGHT_PER_PEER,
        )
        assigned_hashes = {bh for _, bh in assigned}
        peer_batches: dict = {peer: [bh for _, bh in items] for peer, items in per_peer.items()}

        deferred_count = len(timed_out) - len(assigned_hashes)
        if deferred_count:
            # Leave deferred blocks' timestamps alone so the next cycle re-tries
            # them as soon as a peer frees a slot; don't drop them from the
            # in-flight map (they're still "ours" to reassign).
            logger.debug(
                f"Deferring re-request of {deferred_count} blocks: all peers "
                f"at per-peer cap ({MAX_BLOCKS_IN_FLIGHT_PER_PEER})"
            )

        network = self.peer_manager.network if hasattr(self.peer_manager, 'network') else "mainnet"

        for peer, block_hashes in peer_batches.items():
            if not block_hashes:
                continue
            try:
                inventory = [(MSG_WITNESS_BLOCK, bh) for bh in block_hashes]
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
                    self.requested_blocks.pop(bh, None)
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

    async def _restore_utxos_from_block(self, block: Block, max_search_height: int) -> list[tuple[bytes, int, int, bytes]]:
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
            for _ in range(100):
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
            for _ in range(100):
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
            for curr_hash, _, curr_height in current_chain:
                for new_hash, _, _new_height in new_chain:
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

            for curr_hash, curr_block, _ in reversed(blocks_to_disconnect):
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
                    for i, _tx_out in enumerate(tx.outputs):
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

            for new_hash, new_block, _new_height in blocks_to_connect:
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
                for _, curr_block, _ in reversed(blocks_to_disconnect):
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
