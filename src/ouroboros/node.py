"""
Main Bitcoin full node class.

This module implements the main Bitcoin node that orchestrates all components:
database, validation, mempool, peer management, block synchronization, and RPC server.
"""

import asyncio
import signal
import logging
from typing import Optional
from pathlib import Path

from ouroboros.database import BlockchainDatabase
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.mempool import Mempool
from ouroboros.p2p import PeerManager
from ouroboros.block_sync import BlockSync
from ouroboros.rpc import RPCServer
from ouroboros.sync_manager import SyncManager

logger = logging.getLogger(__name__)


class BitcoinNode:
    """Main Bitcoin full node"""
    
    def __init__(self, data_dir: str = "~/.ouroboros", network: str = "mainnet", config: dict = None):
        """
        Initialize Bitcoin node.
        
        Args:
            data_dir: Data directory path
            network: Network name (mainnet, testnet, regtest)
            config: Additional configuration dictionary
        """
        self.data_dir = str(Path(data_dir).expanduser())
        self.network = network
        self.config = config or {}
        
        # Core components
        self.db: Optional[BlockchainDatabase] = None
        self.validator: Optional[BlockValidator] = None
        self.tx_validator: Optional[TransactionValidator] = None
        self.mempool: Optional[Mempool] = None
        
        # Network components
        self.peer_manager: Optional[PeerManager] = None
        self.block_sync: Optional[BlockSync] = None
        
        # RPC server
        self.rpc_server: Optional[RPCServer] = None
        
        # Sync manager
        self.sync_manager: Optional[SyncManager] = None
        
        # State
        self.running = False
        self.synced = False
        self._rpc_task: Optional[asyncio.Task] = None
        self._shutdown_event: Optional[asyncio.Event] = None
    
    async def start(self, rpc_port: int = 8332, p2p_port: int = 8333):
        """
        Start the Bitcoin node.
        
        Args:
            rpc_port: RPC server port
            p2p_port: P2P network port (currently not used, but kept for API compatibility)
        """
        logger.info(f"Starting Bitcoin Hybrid Node ({self.network})")
        
        # Setup signal handlers for graceful shutdown
        self._shutdown_event = asyncio.Event()
        loop = asyncio.get_event_loop()
        
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self._shutdown_event.set()
            # Schedule stop in event loop
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self.stop()))
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Initialize database
            logger.info(f"Initializing database at {self.data_dir}")
            self.db = BlockchainDatabase(self.data_dir)
            
            # Initialize validators
            logger.info("Initializing validators...")
            self.tx_validator = TransactionValidator(self.db)
            self.validator = BlockValidator(self.db)
            
            # Initialize mempool
            logger.info("Initializing mempool...")
            self.mempool = Mempool(self.tx_validator)
            
            # Check if blockchain is synced
            self.synced = self._check_synced()
            
            if not self.synced:
                logger.warning("Blockchain not fully synced. Run 'sync' command first.")
                logger.info("You can use SyncManager to perform initial sync.")
                # Optionally auto-start sync here
                # For now, we'll allow the node to start and sync later
                # return
            
            # Initialize peer manager
            _, best_height = self.db.get_best_block()
            logger.info(f"Initializing peer manager (current height: {best_height})...")
            self.peer_manager = PeerManager(self.network, max_peers=8)
            await self.peer_manager.start(best_height)
            
            # Initialize block sync
            logger.info("Initializing block synchronization...")
            self.block_sync = BlockSync(self.db, self.validator, self.peer_manager)
            await self.block_sync.start()
            
            # Start RPC server
            logger.info(f"Starting RPC server on port {rpc_port}...")
            rpc_username = self.config.get('rpc_username')
            rpc_password = self.config.get('rpc_password')
            self.rpc_server = RPCServer(
                self,
                port=rpc_port,
                username=rpc_username,
                password=rpc_password,
                rate_limit=True
            )
            self._rpc_task = asyncio.create_task(self.rpc_server.start())
            
            # Register message handlers
            self._register_handlers()
            
            self.running = True
            logger.info("Bitcoin node started successfully")
            
            # Main loop (will exit when shutdown event is set)
            await self._main_loop()
            
        except Exception as e:
            logger.error(f"Error starting node: {e}", exc_info=True)
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the Bitcoin node"""
        if not self.running:
            return
        
        logger.info("Stopping Bitcoin node...")
        self.running = False
        
        try:
            # Stop block sync
            if self.block_sync:
                logger.info("Stopping block synchronization...")
                await self.block_sync.stop()
            
            # Stop peer manager
            if self.peer_manager:
                logger.info("Stopping peer manager...")
                await self.peer_manager.stop()
            
            # Stop RPC server
            if self._rpc_task:
                logger.info("Stopping RPC server...")
                self._rpc_task.cancel()
                try:
                    await self._rpc_task
                except asyncio.CancelledError:
                    pass
            
            logger.info("Bitcoin node stopped")
            
        except Exception as e:
            logger.error(f"Error stopping node: {e}", exc_info=True)
    
    async def _main_loop(self):
        """Main node loop"""
        while self.running:
            try:
                # Check for shutdown event
                if self._shutdown_event and self._shutdown_event.is_set():
                    logger.info("Shutdown event received, exiting main loop")
                    break
                
                # Periodic tasks
                await self._periodic_tasks()
                
                # Sleep, but check shutdown event more frequently
                for _ in range(60):  # Check every second for 60 seconds
                    if self._shutdown_event and self._shutdown_event.is_set():
                        break
                    await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                await asyncio.sleep(10)
    
    async def _periodic_tasks(self):
        """Periodic maintenance tasks"""
        try:
            # Check sync status
            if not self.synced:
                self.synced = self._check_synced()
                if self.synced:
                    logger.info("Blockchain is now fully synced")
            
            # Log statistics
            if self.db:
                best_hash, best_height = self.db.get_best_block()
                peer_count = (
                    len(self.peer_manager.get_all_ready_peers())
                    if self.peer_manager
                    else 0
                )
                mempool_size = (
                    len(self.mempool.transactions)
                    if self.mempool
                    else 0
                )
                
                logger.info(
                    f"Height: {best_height}, "
                    f"Peers: {peer_count}, "
                    f"Mempool: {mempool_size} txs"
                )
        
        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}", exc_info=True)
    
    def _check_synced(self) -> bool:
        """
        Check if blockchain is synced.
        
        Returns:
            True if synced, False otherwise
        """
        if not self.db:
            return False
        
        try:
            # Check if we have blocks
            _, height = self.db.get_best_block()
            
            # If we have a sync manager, use it to check sync status
            if self.sync_manager:
                return self.sync_manager.is_synced()
            
            # Simplified check: we're synced if we have blocks
            # In production, this should check against network
            return height > 0
        
        except Exception:
            return False
    
    def _register_handlers(self):
        """Register message handlers with peers"""
        if not self.peer_manager or not self.mempool:
            return
        
        async def handle_tx(msg):
            """Handle incoming transaction"""
            try:
                from ouroboros.p2p_messages import TxMessage
                
                # Deserialize transaction
                tx_msg = TxMessage.from_payload(msg.payload)
                tx = tx_msg.transaction
                
                # Add to mempool
                _, height = self.db.get_best_block()
                success, error = self.mempool.add_transaction(tx, height)
                
                if success:
                    logger.info(f"Added transaction {tx.get_txid().hex()[:16]}... to mempool")
                else:
                    logger.debug(f"Rejected transaction: {error}")
            
            except Exception as e:
                logger.error(f"Error handling transaction: {e}", exc_info=True)
        
        # Register with all peers
        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
            for peer in peers:
                if hasattr(peer, 'register_handler'):
                    peer.register_handler("tx", handle_tx)
        
        # Also register for new peers that connect
        logger.info("Transaction handlers registered")
    
    def is_synced(self) -> bool:
        """
        Check if node is synced.
        
        Returns:
            True if synced, False otherwise
        """
        return self.synced
    
    def _bits_to_difficulty(self, bits: int) -> float:
        """
        Convert compact target (bits) to difficulty.
        
        Formula: difficulty = difficulty_1_target / target
        Where target is decoded from compact representation (bits).
        Difficulty 1 corresponds to target 0x1d00ffff.
        
        Args:
            bits: Compact target (32-bit integer)
            
        Returns:
            Difficulty value
        """
        # Extract mantissa and exponent from bits
        mantissa = bits & 0x007fffff
        exponent = (bits >> 24) & 0xff
        
        if mantissa == 0:
            return float('inf')
        
        # Calculate target: mantissa * 2^(8*(exponent-3))
        if exponent <= 3:
            target = mantissa >> (8 * (3 - exponent))
        else:
            target = mantissa << (8 * (exponent - 3))
        
        # Handle zero target (infinite difficulty)
        if target == 0:
            return float('inf')
        
        # Difficulty 1 corresponds to target 0x1d00ffff
        # For 0x1d00ffff: exponent=0x1d (29), mantissa=0x00ffff
        # target = 0x00ffff * 256^(29-3) = 0x00ffff * 256^26
        difficulty_1_target = 0x00ffff * (256 ** 26)
        
        # Calculate difficulty = difficulty_1_target / target
        difficulty = difficulty_1_target / target
        
        return difficulty
    
    def get_current_difficulty(self) -> float:
        """
        Get current difficulty from best block.
        
        Returns:
            Current difficulty
        """
        if not self.db:
            return 1.0
        
        try:
            # Get best block from database
            best_hash, best_height = self.db.get_best_block()
            block = self.db.get_block(best_hash)
            
            if not block:
                return 1.0
            
            # Extract bits field from block header
            bits = block.bits
            return self._bits_to_difficulty(bits)
        
        except Exception as e:
            logger.error(f"Error calculating current difficulty: {e}", exc_info=True)
            return 1.0
    
    def get_median_time(self, height: Optional[int] = None) -> int:
        """
        Get median time of last 11 blocks.
        
        Implementation:
        1. If height is None, get best block height
        2. Get timestamps of blocks from max(0, height-10) to height (11 blocks)
        3. Sort timestamps
        4. Return median (6th element, index 5)
        
        Args:
            height: Block height (None for current best)
            
        Returns:
            Median timestamp (Unix epoch)
        """
        if not self.db:
            return 0
        
        try:
            if height is None:
                _, height = self.db.get_best_block()
            
            # Get timestamps of last 11 blocks (or fewer if not enough blocks)
            timestamps = []
            start_height = max(0, height - 10)
            
            for h in range(start_height, height + 1):
                block = self.db.get_block_by_height(h)
                if block and hasattr(block, 'timestamp'):
                    timestamps.append(block.timestamp)
            
            if not timestamps:
                return 0
            
            # Sort and return median
            timestamps.sort()
            median_index = len(timestamps) // 2
            return timestamps[median_index]
        
        except Exception as e:
            logger.error(f"Error calculating median time at height {height}: {e}", exc_info=True)
            return 0
    
    def _calculate_block_work(self, bits: int) -> int:
        """
        Calculate proof-of-work for a block.
        
        Formula: work = (2^256) / (target + 1)
        Where target is decoded from bits.
        
        Args:
            bits: Compact target (32-bit integer)
            
        Returns:
            Work value as integer (can be very large)
        """
        # Extract target from bits (same as difficulty calculation)
        mantissa = bits & 0x007fffff
        exponent = (bits >> 24) & 0xff
        
        if mantissa == 0:
            return 0
        
        # Calculate target: mantissa * 2^(8*(exponent-3))
        if exponent <= 3:
            target = mantissa >> (8 * (3 - exponent))
        else:
            target = mantissa << (8 * (exponent - 3))
        
        # Calculate work = (2^256) / (target + 1)
        # Use Python's integer math for precision
        max_target = 2**256
        work = max_target // (target + 1)
        
        return work
    
    def _calculate_chainwork_at_height(self, height: int) -> int:
        """
        Calculate cumulative chainwork up to height.
        
        This recursively calculates chainwork from genesis, caching results.
        
        Args:
            height: Block height
            
        Returns:
            Cumulative chainwork at this height
        """
        if not self.db:
            return 0
        
        try:
            # Check cache first
            block = self.db.get_block_by_height(height)
            if not block:
                return 0
            
            block_hash = block.hash if hasattr(block, 'hash') else self.db.get_block_hash_by_height(height)
            if not block_hash:
                return 0
            
            cached_chainwork = self.db.get_block_chainwork(block_hash)
            if cached_chainwork > 0:
                return cached_chainwork
            
            # Calculate chainwork
            if height == 0:
                # Genesis block
                work = self._calculate_block_work(block.bits)
                chainwork = work
            else:
                # Get previous block chainwork
                prev_block = self.db.get_block_by_height(height - 1)
                if not prev_block:
                    # Need to calculate from genesis
                    prev_chainwork = self._calculate_chainwork_at_height(height - 1)
                else:
                    prev_hash = prev_block.hash if hasattr(prev_block, 'hash') else self.db.get_block_hash_by_height(height - 1)
                    if prev_hash:
                        prev_chainwork = self.db.get_block_chainwork(prev_hash)
                        if prev_chainwork == 0:
                            # Calculate recursively
                            prev_chainwork = self._calculate_chainwork_at_height(height - 1)
                    else:
                        prev_chainwork = self._calculate_chainwork_at_height(height - 1)
                
                # Calculate current block work
                work = self._calculate_block_work(block.bits)
                chainwork = prev_chainwork + work
            
            # Cache chainwork
            self.db.store_block_chainwork(block_hash, chainwork)
            
            return chainwork
        
        except Exception as e:
            logger.error(f"Error calculating chainwork at height {height}: {e}", exc_info=True)
            return 0
    
    def get_chainwork(self) -> str:
        """
        Get chain work (hex).
        
        Returns:
            Chain work as hex string
        """
        if not self.db:
            return "0x0"
        
        try:
            _, best_height = self.db.get_best_block()
            chainwork = self._calculate_chainwork_at_height(best_height)
            return f"0x{chainwork:x}"
        except Exception as e:
            logger.error(f"Error getting chainwork: {e}", exc_info=True)
            return "0x0"
    
    def get_confirmations(self, height: int) -> int:
        """
        Get confirmations for block at height.
        
        Args:
            height: Block height
            
        Returns:
            Number of confirmations
        """
        if not self.db:
            return 0
        
        try:
            _, best_height = self.db.get_best_block()
            return max(0, best_height - height + 1)
        except:
            return 0
    
    def get_difficulty(self, bits: int) -> float:
        """
        Get difficulty from bits.
        
        Args:
            bits: Compact difficulty target
            
        Returns:
            Difficulty value
        """
        return self._bits_to_difficulty(bits)
    
    def get_chainwork_at_height(self, height: int) -> str:
        """
        Get chain work at height.
        
        Args:
            height: Block height
            
        Returns:
            Chain work as hex string
        """
        if not self.db:
            return "0x0"
        
        try:
            chainwork = self._calculate_chainwork_at_height(height)
            return f"0x{chainwork:x}"
        except Exception as e:
            logger.error(f"Error getting chainwork at height {height}: {e}", exc_info=True)
            return "0x0"
    
    async def run(self) -> None:
        """
        Run the Bitcoin node (start and keep running).
        
        This is a convenience method that starts the node and waits for shutdown.
        """
        await self.start()
