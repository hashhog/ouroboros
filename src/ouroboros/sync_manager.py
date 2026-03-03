"""
Python sync manager that wraps Rust FastSync.

This module provides a high-level Python interface for blockchain synchronization
with progress reporting, error recovery, and graceful cancellation.
"""

from typing import Callable, Optional
import time
import threading
import logging
from dataclasses import dataclass

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

