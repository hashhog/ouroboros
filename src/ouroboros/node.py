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

from rich.console import Console
from rich.panel import Panel

from ouroboros.database import BlockchainDatabase
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.mempool import Mempool
from ouroboros.p2p import PeerManager
from ouroboros.block_sync import BlockSync
from ouroboros.rpc import RPCServer
from ouroboros.sync_manager import SyncManager
from ouroboros.config import NodeConfig

logger = logging.getLogger(__name__)


class BitcoinNode:
    """Main Bitcoin full node"""
    
    def __init__(self, data_dir: str = "~/.ouroboros", network: str = "mainnet", config: dict = None):
        """
        Initialize Bitcoin node.
        
        Args:
            data_dir: Data directory path (can be overridden by config file)
            network: Network name (mainnet, testnet, regtest) (can be overridden by config file)
            config: Additional configuration dictionary (overrides config file)
        """
        # Load configuration file
        config_file = config.get('config_file') if config else None
        self.node_config = NodeConfig(config_file)
        
        # Merge config file with provided config (provided config takes precedence)
        config_dict = self.node_config.to_dict()
        if config:
            config_dict.update(config)
        self.config = config_dict
        
        # Set data_dir and network from config (with fallback to parameters)
        self.data_dir = str(Path(self.config.get('datadir', data_dir)).expanduser())
        self.network = self.config.get('network', network)
        
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
            rpc_port: RPC server port (can be overridden by config)
            p2p_port: P2P network port (can be overridden by config)
        """
        # Use config values if available, otherwise use parameters
        rpc_port = self.config.get('rpc_port', rpc_port)
        p2p_port = self.config.get('p2p_port', p2p_port)
        
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
            logger.info("Database initialized")
            
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
            max_peers = self.config.get('max_connections', 8)
            self.peer_manager = PeerManager(self.network, max_peers=max_peers)
            await self.peer_manager.start(best_height)
            peer_count = len(self.peer_manager.get_all_ready_peers()) if self.peer_manager else 0
            logger.info(f"Peer manager started ({peer_count} peers)")
            
            # Initialize block sync
            logger.info("Initializing block synchronization...")
            self.block_sync = BlockSync(
                self.db, self.validator, self.peer_manager, mempool=self.mempool
            )
            await self.block_sync.start()
            
            # Start RPC server
            logger.info(f"RPC server listening on 127.0.0.1:{rpc_port}")
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

            # Print status block to terminal
            self._print_startup_status(rpc_port, p2p_port)

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
    
    def _print_startup_status(self, rpc_port: int, p2p_port: int) -> None:
        """Print a clear status block to the terminal when node starts."""
        console = Console()
        try:
            best_hash, best_height = self.db.get_best_block()
            hash_hex = best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash)
            hash_truncated = f"{hash_hex[:16]}..." if len(hash_hex) > 16 else hash_hex
        except Exception:
            best_height = 0
            hash_truncated = "—"

        # Check sync status via SyncManager for accuracy
        try:
            sync_mgr = SyncManager(self.data_dir, self.network)
            is_synced = sync_mgr.is_synced()
        except Exception:
            is_synced = self.synced

        lines = [
            f"Network: [cyan]{self.network}[/cyan]",
            f"Data directory: [cyan]{self.data_dir}[/cyan]",
            f"Best block height: [cyan]{best_height:,}[/cyan]",
            f"Best block hash: [cyan]{hash_truncated}[/cyan]",
            f"RPC port: [cyan]{rpc_port}[/cyan]",
            f"P2P port: [cyan]{p2p_port}[/cyan]",
        ]
        if not is_synced:
            lines.append("")
            lines.append("[yellow]⚠ Blockchain not fully synced — run 'ouroboros sync' first[/yellow]")
        lines.append("")
        lines.append("[bold green]Node is running. Press Ctrl+C to stop.[/bold green]")

        console.print(Panel.fit(
            "\n".join(lines),
            title="[bold]Ouroboros Node Status[/bold]",
            border_style="green",
        ))

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
        if not self.peer_manager:
            return

        async def handle_tx(msg):
            """Handle incoming transaction"""
            if not self.mempool:
                return
            try:
                from ouroboros.p2p_messages import TxMessage

                tx_msg = TxMessage.from_payload(msg.payload)
                tx = tx_msg.transaction

                _, height = self.db.get_best_block()
                success, error = self.mempool.add_transaction(tx, height)

                if success:
                    logger.info(f"Added transaction {tx.get_txid().hex()[:16]}... to mempool")
                else:
                    logger.debug(f"Rejected transaction: {error}")

            except Exception as e:
                logger.error(f"Error handling transaction: {e}", exc_info=True)

        def _make_getdata_handler(peer):
            """Handle getdata: respond with tx from mempool or block from db"""
            async def handler(msg):
                try:
                    from ouroboros.p2p_messages import (
                        GetDataMessage,
                        TxMessage,
                        InvMessage,
                        INV_TYPE_TX,
                        INV_TYPE_BLOCK,
                    )

                    getdata = GetDataMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')

                    for inv_type, inv_hash in getdata.inventory:
                        if inv_type == INV_TYPE_TX and self.mempool:
                            tx = self.mempool.get_transaction(inv_hash)
                            if tx:
                                tx_msg = TxMessage(transaction=tx)
                                await peer.send_message(tx_msg.to_network_message(network))
                                logger.debug(f"Sent tx {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                        elif inv_type == INV_TYPE_BLOCK:
                            block = self.db.get_block(inv_hash)
                            if block:
                                from ouroboros.p2p_messages import BlockMessage
                                block_msg = BlockMessage(block=block)
                                await peer.send_message(block_msg.to_network_message(network))
                                logger.debug(f"Sent block {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                except Exception as e:
                    logger.error(f"Error handling getdata from {peer.host}:{peer.port}: {e}")

            return handler

        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
            for peer in peers:
                if hasattr(peer, 'register_handler'):
                    peer.register_handler("tx", handle_tx)
                    peer.register_handler("getdata", _make_getdata_handler(peer))

        logger.info("Transaction and getdata handlers registered")
    
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

        Uses Bitcoin Core GetDifficulty formula from rpc/blockchain.cpp:
        - nShift = (nBits >> 24) & 0xff
        - dDiff = 0x0000ffff / (nBits & 0x00ffffff)
        - while nShift < 29: dDiff *= 256; nShift += 1
        - while nShift > 29: dDiff /= 256; nShift -= 1

        Difficulty 1 corresponds to bits 0x1d00ffff.

        Args:
            bits: Compact target (32-bit integer)

        Returns:
            Difficulty value
        """
        n_shift = (bits >> 24) & 0xFF
        mantissa = bits & 0x00FFFFFF

        if mantissa == 0:
            return float("inf")

        d_diff = 0x0000FFFF / float(mantissa)

        while n_shift < 29:
            d_diff *= 256.0
            n_shift += 1
        while n_shift > 29:
            d_diff /= 256.0
            n_shift -= 1

        return d_diff
    
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
        
        The median time is the median timestamp of the last 11 blocks (or fewer
        if not enough blocks exist). This is used in Bitcoin to prevent timestamp
        manipulation attacks.
        
        Implementation:
        1. If height is None, get best block height
        2. Get blocks from max(0, height-10) to height (11 blocks total)
        3. Extract timestamps from each block
        4. Sort timestamps
        5. Return median (middle value, index 5 for 11 blocks)
        
        Args:
            height: Block height (None for current best block)
            
        Returns:
            Median timestamp (Unix epoch seconds)
        """
        import time
        
        if not self.db:
            return int(time.time())
        
        try:
            # Get height if not provided
            if height is None:
                _, height = self.db.get_best_block()
            
            # Get timestamps of last 11 blocks (or fewer if not enough blocks)
            timestamps = []
            for h in range(max(0, height - 10), height + 1):
                try:
                    block_hash = self.db.get_block_hash_by_height(h)
                    if not block_hash:
                        continue
                    block = self.db.get_block(block_hash)
                    if block:
                        timestamps.append(block.timestamp)
                except Exception as e:
                    logger.debug(f"Error getting block at height {h} for median time: {e}")
                    continue
            
            if not timestamps:
                # No blocks found, return current time as fallback
                return int(time.time())
            
            # Sort and get median (middle of last 11 blocks, index 5 for 11 blocks)
            timestamps.sort()
            median_index = len(timestamps) // 2
            return timestamps[median_index]

        except Exception as e:
            logger.error(f"Error calculating median time at height {height}: {e}", exc_info=True)
            return int(time.time())  # Fallback when DB empty or error
    
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
            # Prefer persisted chainwork from Rust BlockMetadata (computed during sync)
            persisted_chainwork = self.db.get_chainwork_by_height(height)
            if persisted_chainwork > 0:
                return persisted_chainwork

            # Fallback: compute and cache (for blocks synced before chainwork persistence)
            block = self.db.get_block_by_height(height)
            if not block:
                return 0

            block_hash = block.hash if hasattr(block, "hash") else self.db.get_block_hash_by_height(height)
            if not block_hash:
                return 0

            cached_chainwork = self.db.get_block_chainwork(block_hash, height)
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
                    prev_hash = prev_block.hash if hasattr(prev_block, "hash") else self.db.get_block_hash_by_height(height - 1)
                    if prev_hash:
                        prev_chainwork = self.db.get_block_chainwork(prev_hash, height - 1)
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
