"""
Python sync manager that wraps Rust FastSync.

This module provides a high-level Python interface for blockchain synchronization
with progress reporting, error recovery, and graceful cancellation.

Stale Tip Detection (Bitcoin Core net_processing.cpp TipMayBeStale/ConsiderEviction):
- If the chain tip hasn't updated for 30 minutes AND the tip's timestamp is > 24 hours old,
  the tip is considered stale.
- When stale: send getheaders to all peers, try connecting to extra outbound peer,
  evict worst outbound peer if a better chain is found.
"""

from typing import Callable, Optional, List, TYPE_CHECKING
import time
import threading
import logging
import asyncio
from dataclasses import dataclass

if TYPE_CHECKING:
    from ouroboros.p2p import PeerManager
    from ouroboros.database import BlockchainDatabase

try:
    import sync  # Rust extension module
except ImportError:
    sync = None
    logging.warning("Rust sync module not available. Install with: maturin develop")

logger = logging.getLogger(__name__)


@dataclass
class SyncProgress:
    """Sync progress information"""
    current_height: int
    total_height: int
    progress_percent: float
    blocks_per_second: float
    eta_seconds: int
    phase: str = "header"  # "header" or "block"
    total_known: bool = True  # False in header phase until we know actual chain tip
    peer_count: int = 0
    
    def __str__(self) -> str:
        if self.total_height == 0:
            return "Syncing... (unknown total)"
        
        percent = self.progress_percent
        current = self.current_height
        total = self.total_height
        speed = self.blocks_per_second
        
        # Format ETA
        if self.eta_seconds < 60:
            eta_str = f"{self.eta_seconds}s"
        elif self.eta_seconds < 3600:
            eta_str = f"{self.eta_seconds // 60}m {self.eta_seconds % 60}s"
        else:
            hours = self.eta_seconds // 3600
            minutes = (self.eta_seconds % 3600) // 60
            eta_str = f"{hours}h {minutes}m"
        
        return (
            f"Progress: {percent:.2f}% ({current:,}/{total:,} blocks) | "
            f"Speed: {speed:.1f} blocks/s | ETA: {eta_str}"
        )


class SyncManager:
    """Manages initial blockchain synchronization"""
    
    def __init__(self, data_dir: str, network: str = "mainnet"):
        if sync is None:
            raise ImportError(
                "Rust sync module not available. "
                "Install with: maturin develop"
            )
        
        self.fast_sync = sync.FastSync(data_dir, network)
        # Progress reporter reads from shared cache without borrowing FastSync.
        self._progress_reporter = self.fast_sync.get_progress_reporter()
        # Canceller avoids "Already borrowed" - don't call fast_sync methods while sync runs
        self._canceller = self.fast_sync.get_canceller()
        self.data_dir = data_dir
        self.network = network
        self._sync_thread: Optional[threading.Thread] = None
        self._is_running = False
        self._sync_error: Optional[Exception] = None
        self._last_progress: Optional[SyncProgress] = None
        
    def perform_initial_sync(self,
                            progress_callback: Optional[Callable[[SyncProgress], None]] = None,
                            cancel_check: Optional[Callable[[], bool]] = None,
                            progress_interval: float = 5.0,
                            limit: Optional[int] = None) -> bool:
        """Run initial blockchain sync; returns True on completion, False if cancelled or on error.

        *progress_callback* receives :class:`SyncProgress` updates every *progress_interval* seconds.
        """
        if self._is_running:
            logger.warning("Sync already in progress")
            return False
        
        self._is_running = True
        self._sync_error = None
        self._last_progress = None
        
        try:
            # Start sync in a separate thread to allow progress monitoring
            sync_complete = threading.Event()
            sync_exception = [None]  # Use list to allow modification in nested function
            
            def sync_worker():
                """Worker thread that runs the sync"""
                try:
                    # Run sync (this blocks until complete or cancelled)
                    self.fast_sync.sync_blockchain(limit=limit)
                    sync_complete.set()
                except KeyboardInterrupt:
                    # Expected when user cancels - don't log noisy traceback
                    sync_exception[0] = KeyboardInterrupt("Sync cancelled")
                    sync_complete.set()
                except Exception as e:
                    logger.error(f"Sync error: {e}", exc_info=True)
                    sync_exception[0] = e
                    sync_complete.set()
            
            # Start sync thread
            self._sync_thread = threading.Thread(target=sync_worker, daemon=True)
            self._sync_thread.start()
            
            # Monitor progress - do initial update immediately so user sees progress from start
            last_progress_time = 0.0  # Ensures first callback fires right away
            cancelled = False
            
            if progress_callback is not None:
                try:
                    progress = self.get_progress()
                    if progress is not None:
                        progress_callback(progress)
                        self._last_progress = progress
                except Exception:
                    pass  # Ignore initial errors (e.g. DB not yet initialized)
            
            while not sync_complete.is_set():
                # Check for cancellation
                if cancel_check is not None:
                    try:
                        if cancel_check():
                            logger.info("Sync cancelled by user")
                            try:
                                self._canceller.cancel()
                            except Exception as e:
                                logger.warning(f"Error cancelling sync: {e}")
                            cancelled = True
                            break
                    except Exception as e:
                        logger.warning(f"Error in cancel_check: {e}")
                
                # Report progress periodically
                current_time = time.time()
                if (progress_callback is not None and 
                    current_time - last_progress_time >= progress_interval):
                    try:
                        progress = self.get_progress()
                        if progress is not None:
                            progress_callback(progress)
                            self._last_progress = progress
                            last_progress_time = current_time
                    except Exception as e:
                        # Log progress errors occasionally to help debug
                        # But don't spam - only log every 10 seconds
                        if int(current_time) % 10 == 0:
                            logger.debug(f"Progress update error: {e}")
                        # Continue - the sync will keep working
                        pass
                
                # Sleep briefly to avoid busy-waiting
                sync_complete.wait(timeout=0.5)
            
            # Wait for sync thread to finish
            if self._sync_thread.is_alive():
                self._sync_thread.join(timeout=10.0)
            
            # Check for exceptions
            if sync_exception[0] is not None:
                self._sync_error = sync_exception[0]
                logger.error(f"Sync failed: {sync_exception[0]}")
                return False
            
            if cancelled:
                # Still do final progress update so user sees accurate state (e.g. 100% if at tip)
                if progress_callback is not None:
                    try:
                        progress = self.get_progress()
                        if progress is not None:
                            progress_callback(progress)
                    except Exception as e:
                        logger.debug(f"Error in final progress_callback after cancel: {e}")
                return False

            # Final progress report
            if progress_callback is not None:
                try:
                    progress = self.get_progress()
                    if progress is not None:
                        progress_callback(progress)
                except Exception as e:
                    logger.warning(f"Error in final progress_callback: {e}")
            
            logger.info("Sync completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Sync manager error: {e}", exc_info=True)
            self._sync_error = e
            return False
        finally:
            self._is_running = False
            self._sync_thread = None
    
    def is_synced(self) -> bool:
        """Return True when the blockchain has caught up to the network tip."""
        try:
            return self.fast_sync.is_synced()
        except Exception as e:
            logger.warning(f"Error checking sync status: {e}")
            return False
    
    def get_progress(self) -> Optional[SyncProgress]:
        """Return the latest :class:`SyncProgress` from the shared cache, or None if unavailable."""
        try:
            rust_progress = self._progress_reporter.get_progress()
            if rust_progress is None:
                return self._last_progress

            # Convert Rust SyncProgress to Python SyncProgress
            progress = SyncProgress(
                current_height=rust_progress.current_height,
                total_height=rust_progress.total_height,
                progress_percent=rust_progress.progress_percent,
                blocks_per_second=rust_progress.blocks_per_second,
                eta_seconds=rust_progress.eta_seconds,
                phase=getattr(rust_progress, "phase", "header"),
                total_known=getattr(rust_progress, "total_known", True),
                peer_count=getattr(rust_progress, "peer_count", 0),
            )

            # When total_known is False we intentionally use 0% (CLI shows "Requesting...").
            # Do not recalculate - that would show a misleading percentage.
            if progress.total_known and progress.current_height > 0 and progress.progress_percent == 0.0:
                if progress.total_height > 0:
                    progress.progress_percent = (progress.current_height / progress.total_height) * 100.0

            return progress
        except Exception as e:
            if self._last_progress is None:
                logger.debug(f"Progress update error (will retry): {e}")
            return self._last_progress
    
    def cancel_sync(self) -> None:
        """Request graceful cancellation of the ongoing sync (stops at the next safe checkpoint)."""
        if not self._is_running:
            logger.warning("No sync in progress")
            return

        try:
            self._canceller.cancel()
            logger.info("Sync cancellation requested")
        except Exception as e:
            logger.error(f"Error cancelling sync: {e}")
    
    def wait_for_sync(self, timeout: Optional[float] = None) -> bool:
        """Block until sync completes (or *timeout* seconds elapse); returns True on success."""
        if not self._is_running or self._sync_thread is None:
            return self.is_synced()
        
        if timeout is None:
            self._sync_thread.join()
        else:
            self._sync_thread.join(timeout=timeout)
        
        return not self._sync_thread.is_alive() and self._sync_error is None
    
    @property
    def is_running(self) -> bool:
        """Check if sync is currently running"""
        return self._is_running
    
    @property
    def last_error(self) -> Optional[Exception]:
        """Get last sync error, if any"""
        return self._sync_error
    
    @property
    def last_progress(self) -> Optional[SyncProgress]:
        """Get last reported progress"""
        return self._last_progress


# ─────────────────────────────────────────────────────────────────────────────
# Stale Tip Detection and Eviction
# Reference: Bitcoin Core net_processing.cpp TipMayBeStale(), ConsiderEviction(),
# EvictExtraOutboundPeers(), CheckForStaleTipAndEvictPeers()
# ─────────────────────────────────────────────────────────────────────────────

# Constants from Bitcoin Core (net_processing.cpp)
STALE_CHECK_INTERVAL = 600  # 10 minutes between stale checks
CHAIN_SYNC_TIMEOUT = 1200  # 20 minutes timeout for outbound peers to sync
HEADERS_RESPONSE_TIME = 120  # 2 minutes to respond to getheaders
MINIMUM_CONNECT_TIME = 30  # 30 seconds minimum before eviction
MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8  # Bitcoin Core default

# Stale tip thresholds
STALE_TIP_AGE_THRESHOLD = 30 * 60  # 30 minutes since last tip update
STALE_TIP_TIMESTAMP_THRESHOLD = 24 * 60 * 60  # 24 hours old tip timestamp


@dataclass
class PeerChainSyncState:
    """Tracks chain sync state for an outbound peer.

    Reference: Bitcoin Core CNodeState::ChainSyncTimeoutState
    """
    timeout: float = 0.0  # When to timeout (0 = no timeout set)
    work_header_height: int = 0  # Height of tip when timeout was set
    sent_getheaders: bool = False  # Have we sent getheaders to check?
    protect: bool = False  # Protected from eviction?

    def reset(self) -> None:
        """Reset timeout state (peer caught up)."""
        self.timeout = 0.0
        self.work_header_height = 0
        self.sent_getheaders = False


class StaleTipDetector:
    """Detects stale chain tips and manages peer eviction.

    Implements Bitcoin Core's stale tip detection from net_processing.cpp:
    - TipMayBeStale(): Check if tip hasn't updated in 30min and is >24h old
    - ConsiderEviction(): Evict outbound peers that don't sync to our tip
    - EvictExtraOutboundPeers(): Remove extra outbound when better chain found

    When stale tip detected:
    1. Send getheaders to all peers to check for longer chains
    2. Try connecting to additional outbound peer (up to MAX+1)
    3. If new peer provides better chain, evict worst existing outbound
    """

    def __init__(
        self,
        peer_manager: Optional["PeerManager"] = None,
        db: Optional["BlockchainDatabase"] = None,
    ):
        self.peer_manager = peer_manager
        self.db = db

        # Tip tracking
        self._last_tip_update: float = time.time()
        self._last_tip_height: int = 0
        self._last_tip_timestamp: int = 0

        # Stale check scheduling
        self._next_stale_check: float = time.time() + STALE_CHECK_INTERVAL
        self._try_extra_outbound: bool = False

        # Per-peer chain sync state (addr -> PeerChainSyncState)
        self._peer_sync_states: dict = {}

        # Track when each peer last provided a useful block
        # addr -> (last_block_time, best_known_height)
        self._peer_block_times: dict = {}

        self._running = False
        self._check_task: Optional[asyncio.Task] = None

    def update_tip(self, height: int, timestamp: int) -> None:
        """Called when chain tip changes.

        Args:
            height: New tip height
            timestamp: New tip block timestamp (Unix epoch)
        """
        if height > self._last_tip_height:
            self._last_tip_update = time.time()
            self._last_tip_height = height
            self._last_tip_timestamp = timestamp

            # Reset try-extra-outbound flag when tip advances
            if self._try_extra_outbound:
                self._try_extra_outbound = False
                logger.debug("Tip advanced, clearing extra outbound flag")

    def record_peer_block(self, addr: str, height: int) -> None:
        """Record that a peer provided a block at the given height.

        Args:
            addr: Peer address (host:port)
            height: Height of block provided
        """
        now = time.time()
        prev_time, prev_height = self._peer_block_times.get(addr, (0.0, 0))

        if height >= prev_height:
            self._peer_block_times[addr] = (now, height)

            # Reset chain sync timeout if peer caught up to our tip
            state = self._peer_sync_states.get(addr)
            if state and height >= self._last_tip_height:
                state.reset()

    def tip_may_be_stale(self) -> bool:
        """Check if our chain tip may be stale.

        Reference: Bitcoin Core TipMayBeStale()

        Returns True if:
        - Last tip update was more than 30 minutes ago (3 * 10min block interval)
        - AND there are no blocks in flight

        For simplicity, we check if tip timestamp is > 24 hours old as a
        secondary indicator.
        """
        now = time.time()

        # Initialize on first call
        if self._last_tip_update == 0:
            self._last_tip_update = now
            return False

        # Check if tip update is stale (>30 min)
        time_since_update = now - self._last_tip_update
        if time_since_update < STALE_TIP_AGE_THRESHOLD:
            return False

        # Also check if tip timestamp is old (>24 hours)
        # This prevents false positives during initial sync
        if self._last_tip_timestamp > 0:
            tip_age = now - self._last_tip_timestamp
            if tip_age < STALE_TIP_TIMESTAMP_THRESHOLD:
                return False

        return True

    async def check_for_stale_tip_and_evict(self) -> None:
        """Periodic check for stale tip and peer eviction.

        Reference: Bitcoin Core CheckForStaleTipAndEvictPeers()
        """
        now = time.time()

        # Run eviction checks
        await self._evict_extra_outbound_peers(now)

        # Check for stale tip at scheduled intervals
        if now > self._next_stale_check:
            if self.tip_may_be_stale():
                await self._handle_stale_tip(now)
            elif self._try_extra_outbound:
                # Tip is no longer stale, disable extra outbound
                self._try_extra_outbound = False

            self._next_stale_check = now + STALE_CHECK_INTERVAL

    async def _handle_stale_tip(self, now: float) -> None:
        """Handle stale tip detection.

        Actions:
        1. Log stale tip event
        2. Send getheaders to all peers to check for longer chains
        3. Enable extra outbound connection
        """
        time_since_update = now - self._last_tip_update

        logger.warning(
            f"Potential stale tip detected, will try using extra outbound peer "
            f"(last tip update: {int(time_since_update)} seconds ago)"
        )

        # Record stale tip metric
        try:
            from ouroboros.metrics import record_stale_tip_detected
            record_stale_tip_detected()
        except ImportError:
            pass

        # Send getheaders to all peers
        await self._send_getheaders_to_all()

        # Enable extra outbound connection
        self._try_extra_outbound = True

    async def _send_getheaders_to_all(self) -> None:
        """Send getheaders to all connected peers.

        This probes peers for any chains with more work than ours.
        """
        if not self.peer_manager:
            return

        try:
            from ouroboros.p2p_messages import GetHeadersMessage

            # Build locator from our chain tip
            locator = self._build_block_locator()
            if not locator:
                return

            msg = GetHeadersMessage(
                version=70016,
                locator_hashes=locator,
                stop_hash=b'\x00' * 32,
            )

            all_peers = self.peer_manager.get_all_ready_peers()
            for peer in all_peers:
                try:
                    await peer.send_message(
                        msg.to_network_message(self.peer_manager.network)
                    )
                    logger.debug(
                        f"Sent getheaders to {peer.host}:{peer.port} "
                        f"to check for better chain"
                    )
                except Exception as e:
                    logger.debug(f"Failed to send getheaders to peer: {e}")

        except Exception as e:
            logger.error(f"Error sending getheaders to peers: {e}")

    def _build_block_locator(self) -> List[bytes]:
        """Build a block locator from our chain tip.

        Returns list of block hashes exponentially spaced back from tip.
        """
        if not self.db:
            return []

        try:
            best_hash, best_height = self.db.get_best_block()
            if best_height <= 0:
                return [best_hash] if best_hash else []

            locator = []
            step = 1
            height = best_height

            while height >= 0:
                block_hash = self.db.get_block_hash_by_height(height)
                if block_hash:
                    locator.append(block_hash)

                if len(locator) >= 10:
                    step *= 2

                height -= step
                if height < 0 and locator:
                    break

            return locator

        except Exception as e:
            logger.debug(f"Error building block locator: {e}")
            return []

    async def consider_eviction(self, addr: str, peer_height: int) -> bool:
        """Consider evicting an outbound peer based on chain sync.

        Reference: Bitcoin Core ConsiderEviction()

        Args:
            addr: Peer address
            peer_height: Best known height of peer's chain

        Returns:
            True if peer should be evicted
        """
        if not self.peer_manager:
            return False

        now = time.time()

        # Get or create sync state for this peer
        if addr not in self._peer_sync_states:
            self._peer_sync_states[addr] = PeerChainSyncState()
        state = self._peer_sync_states[addr]

        # Skip protected peers
        if state.protect:
            return False

        # Check if peer has caught up to our tip
        if peer_height >= self._last_tip_height:
            if state.timeout != 0:
                state.reset()
                logger.debug(f"Peer {addr} caught up to our tip, clearing timeout")
            return False

        # Peer is behind our tip
        if state.timeout == 0:
            # First time noticing peer is behind - set timeout
            state.timeout = now + CHAIN_SYNC_TIMEOUT
            state.work_header_height = self._last_tip_height
            state.sent_getheaders = False
            logger.debug(
                f"Peer {addr} is behind (height={peer_height}, ours={self._last_tip_height}), "
                f"setting {CHAIN_SYNC_TIMEOUT}s timeout"
            )
            return False

        # Check if timeout has expired
        if now > state.timeout:
            if state.sent_getheaders:
                # Already sent getheaders and timed out - evict
                logger.info(
                    f"Evicting outbound peer {addr}: chain sync timeout "
                    f"(best={peer_height}, expected>={state.work_header_height})"
                )
                try:
                    from ouroboros.metrics import record_peer_evicted
                    record_peer_evicted("chain_sync_timeout")
                except ImportError:
                    pass
                return True
            else:
                # Send getheaders and extend timeout
                await self._send_getheaders_to_peer(addr)
                state.sent_getheaders = True
                state.timeout = now + HEADERS_RESPONSE_TIME
                logger.debug(
                    f"Sent getheaders to {addr} to verify chain work, "
                    f"extended timeout by {HEADERS_RESPONSE_TIME}s"
                )

        return False

    async def _send_getheaders_to_peer(self, addr: str) -> None:
        """Send getheaders to a specific peer."""
        if not self.peer_manager:
            return

        try:
            from ouroboros.p2p_messages import GetHeadersMessage

            # Find the peer
            peer = self.peer_manager.peers.get(addr)
            if not peer:
                peer = self.peer_manager.block_relay_peers.get(addr)
            if not peer or not peer.is_connected():
                return

            locator = self._build_block_locator()
            if not locator:
                return

            msg = GetHeadersMessage(
                version=70016,
                locator_hashes=locator,
                stop_hash=b'\x00' * 32,
            )

            await peer.send_message(
                msg.to_network_message(self.peer_manager.network)
            )

        except Exception as e:
            logger.debug(f"Error sending getheaders to {addr}: {e}")

    async def _evict_extra_outbound_peers(self, now: float) -> None:
        """Evict extra outbound peers if we have too many.

        Reference: Bitcoin Core EvictExtraOutboundPeers()

        When we temporarily connect an extra outbound peer to find a better
        chain (stale tip recovery), we need to evict one once we've synced.
        We evict the peer that least recently provided a useful block.
        """
        if not self.peer_manager:
            return

        # Count current outbound full-relay peers
        num_outbound = len(self.peer_manager.peers)

        # Check if we have extra peers
        if num_outbound <= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS:
            return

        # Find peer to evict - the one that least recently provided a block
        worst_addr: Optional[str] = None
        worst_time: float = float('inf')

        for addr, peer in self.peer_manager.peers.items():
            if not peer.is_connected():
                continue

            # Check minimum connect time
            if now - peer.connected_at < MINIMUM_CONNECT_TIME:
                continue

            last_block_time, _ = self._peer_block_times.get(addr, (0.0, 0))
            if last_block_time < worst_time:
                worst_time = last_block_time
                worst_addr = addr

        if worst_addr:
            logger.info(
                f"Evicting extra outbound peer {worst_addr} "
                f"(last block: {int(now - worst_time)}s ago)"
            )

            try:
                from ouroboros.metrics import record_peer_evicted
                record_peer_evicted("extra_outbound")
            except ImportError:
                pass

            # Disconnect the peer
            peer = self.peer_manager.peers.get(worst_addr)
            if peer:
                await peer.disconnect()
                self.peer_manager.peers.pop(worst_addr, None)

    def should_try_extra_outbound(self) -> bool:
        """Check if we should try connecting an extra outbound peer.

        Returns True when stale tip detected and we haven't exceeded limit+1.
        """
        if not self._try_extra_outbound:
            return False

        if not self.peer_manager:
            return False

        num_outbound = len(self.peer_manager.peers)
        return num_outbound <= MAX_OUTBOUND_FULL_RELAY_CONNECTIONS

    def cleanup_peer(self, addr: str) -> None:
        """Clean up state for a disconnected peer.

        Args:
            addr: Peer address
        """
        self._peer_sync_states.pop(addr, None)
        self._peer_block_times.pop(addr, None)

    async def start(self) -> None:
        """Start the background stale tip check loop."""
        if self._running:
            return

        self._running = True
        self._check_task = asyncio.create_task(self._check_loop())
        logger.debug("Stale tip detector started")

    async def stop(self) -> None:
        """Stop the background check loop."""
        self._running = False
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
            self._check_task = None
        logger.debug("Stale tip detector stopped")

    async def _check_loop(self) -> None:
        """Background loop for periodic stale tip checks."""
        try:
            while self._running:
                await asyncio.sleep(60)  # Check every minute
                if self._running:
                    await self.check_for_stale_tip_and_evict()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in stale tip check loop: {e}")
