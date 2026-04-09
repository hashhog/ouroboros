"""
Main Bitcoin full node class.

This module implements the main Bitcoin node that orchestrates all components:
database, validation, mempool, peer management, block synchronization, and RPC server.
"""

import asyncio
import os
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
from ouroboros.fee_estimator import FeeEstimator
from ouroboros.wallet import Wallet, WalletManager
from ouroboros.cookie_auth import generate_cookie, delete_cookie
from ouroboros.zmq_notifier import ZMQNotifier
from ouroboros.pruning import BlockPruner
from ouroboros.metrics import (
    init_metrics,
    update_chain_metrics,
    update_mempool_metrics,
    NODE_INFO,
)
from ouroboros.snapshot import SnapshotManager, read_snapshot_metadata

logger = logging.getLogger(__name__)


class BitcoinNode:
    """Main Bitcoin full node"""
    
    def __init__(self, data_dir: str = "~/.ouroboros", network: str = "mainnet", config: dict = None):
        """Initialize Bitcoin node."""
        # Load configuration file (--config or datadir/ouroboros.conf)
        config_path = config.get('config_path') or config.get('config_file') if config else None
        data_dir_for_config = config.get('datadir', data_dir) if config else data_dir
        self.node_config = NodeConfig(config_path=config_path, data_dir=data_dir_for_config)
        
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
        
        # Fee estimator
        self.fee_estimator: Optional[FeeEstimator] = None

        # Wallet manager (multi-wallet support)
        self.wallet_manager: Optional[WalletManager] = None
        # Legacy single wallet reference (for backwards compatibility)
        self.wallet: Optional[Wallet] = None

        # Network components
        self.peer_manager: Optional[PeerManager] = None
        self.block_sync: Optional[BlockSync] = None
        
        # RPC server
        self.rpc_server: Optional[RPCServer] = None
        
        # Sync manager
        self.sync_manager: Optional[SyncManager] = None
        
        # Block pruner
        self.pruner: Optional[BlockPruner] = None

        # ZMQ notifier (replaces the older zmq_publisher)
        self.zmq_notifier: Optional[ZMQNotifier] = None

        # Snapshot manager for assumeUTXO
        self.snapshot_manager: Optional[SnapshotManager] = None

        # State
        self.running = False
        self.synced = False
        self._rpc_task: Optional[asyncio.Task] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._rpc_username: Optional[str] = None
        self._rpc_password: Optional[str] = None
    
    async def start(self, rpc_port: int = 8332, p2p_port: int = 8333):
        """Start the Bitcoin node (config file values override the port defaults)."""
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

            # RPC authentication: explicit config > cookie file
            # Write the cookie file early (before the RPC server binds) so
            # that external tools polling with curl can read it as soon as
            # the port opens — matching Bitcoin Core's init order.
            rpc_username = self.config.get('rpc_username')
            rpc_password = self.config.get('rpc_password')
            if not (rpc_username and rpc_password):
                rpc_username, rpc_password = generate_cookie(self.data_dir)
            self._rpc_username = rpc_username
            self._rpc_password = rpc_password

            # Initialize snapshot manager for assumeUTXO
            self.snapshot_manager = SnapshotManager(self.db, self.network, self.data_dir)

            # Check for assumeutxo option and load snapshot if specified
            assumeutxo_path = self.config.get('assumeutxo')
            if assumeutxo_path:
                await self._load_snapshot_if_needed(assumeutxo_path)

            # Initialize validators
            logger.info("Initializing validators...")
            self.tx_validator = TransactionValidator(self.db)
            self.validator = BlockValidator(self.db, network=self.network)
            
            # Initialize mempool
            logger.info("Initializing mempool...")
            self.mempool = Mempool(self.tx_validator)

            # Reload persisted mempool (if available)
            mempool_path = os.path.join(self.data_dir, "mempool.dat")
            try:
                _, chain_height = self.db.get_best_block()
            except RuntimeError:
                # Empty database — initialize genesis block
                logger.info("Empty database, initializing genesis block...")
                self._init_genesis_block()
                _, chain_height = self.db.get_best_block()
            self.mempool.load_from_file(mempool_path, chain_height)

            # Initialize fee estimator
            self.fee_estimator = FeeEstimator()
            fee_est_path = os.path.join(self.data_dir, "fee_estimates.json")
            if self.fee_estimator.load_from_file(fee_est_path):
                logger.info("Loaded fee estimation data from %s", fee_est_path)

            # Initialize wallet manager (multi-wallet support)
            self.wallet_manager = WalletManager(self.data_dir, self.network)
            self.wallet_manager.set_database(self.db)
            self.wallet_manager.set_mempool(self.mempool)

            # Load wallets configured for startup, or create default wallet
            self.wallet_manager.load_startup_wallets()
            if not self.wallet_manager.list_loaded_wallets():
                # Create a default wallet if none configured
                try:
                    self.wallet_manager.create_wallet("default")
                    logger.info("Created default wallet")
                except ValueError:
                    # Wallet already exists; try to load it
                    try:
                        self.wallet_manager.load_wallet("default")
                        logger.info("Loaded default wallet")
                    except Exception as e:
                        logger.warning(f"Could not load default wallet: {e}")

            # Set legacy wallet reference for backwards compatibility
            self.wallet = self.wallet_manager.get_default_wallet()
            
            # Initialize block pruner (optional — enabled when prune=<MB> is set)
            prune_target = self.config.get('prune')
            if prune_target:
                prune_mb = int(prune_target)
                keep = int(self.config.get('prune_keep_blocks', 288))
                self.pruner = BlockPruner(
                    db=self.db,
                    target_size_mb=prune_mb,
                    keep_blocks=keep,
                )
                logger.info(
                    f"Block pruning enabled (target {prune_mb} MB, "
                    f"keep {self.pruner.keep_blocks} blocks)"
                )

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
            p2p_transport = 2 if self.config.get('v2transport') else 1
            listen_enabled = self.config.get('listen', True)
            # Treat explicit "0" or False as disabled
            if str(listen_enabled).lower() in ("0", "false", "no"):
                listen_enabled = False
            self.peer_manager = PeerManager(
                self.network,
                max_peers=max_peers,
                data_dir=self.data_dir,
                transport_version=p2p_transport,
                listen=bool(listen_enabled),
            )
            # BIP 152: Provide mempool and database for compact block relay
            self.peer_manager.set_mempool(self.mempool)
            self.peer_manager.set_database(self.db)
            try:
                await self.peer_manager.start(best_height, p2p_port=p2p_port)
            except Exception as e:
                logger.warning(f"Peer manager start error (node continues): {e}")
            # Connect to explicitly specified peers (--connect flag)
            connect_peers = self.config.get('connect', [])
            for addr_str in connect_peers:
                try:
                    if ':' in addr_str:
                        host, port_s = addr_str.rsplit(':', 1)
                        cport = int(port_s)
                    else:
                        host = addr_str
                        cport = 8333
                    # Register for automatic reconnection
                    self.peer_manager._connect_addrs.append((host, cport))
                    logger.info(f"Connecting to specified peer {host}:{cport}")
                    await self.peer_manager.connect_to_node(host, cport)
                except Exception as e:
                    logger.warning(f"Failed to connect to specified peer {addr_str}: {e}")
            peer_count = len(self.peer_manager.get_all_ready_peers()) if self.peer_manager else 0
            logger.info(f"Peer manager started ({peer_count} peers)")

            # Initialize block sync
            logger.info("Initializing block synchronization...")
            self.block_sync = BlockSync(
                self.db, self.validator, self.peer_manager,
                mempool=self.mempool,
                fee_estimator=self.fee_estimator,
            )
            try:
                await self.block_sync.start()
            except Exception as e:
                logger.warning(f"Block sync start error (node continues): {e}")
            
            # Start RPC server (with optional REST interface)
            rest_enabled = str(self.config.get('rest', '0')).lower() in ('1', 'true', 'yes', 'on')
            logger.info(f"RPC server listening on 127.0.0.1:{rpc_port}")
            if rest_enabled:
                logger.info("REST interface enabled at /rest/*")
            self.rpc_server = RPCServer(
                self,
                port=rpc_port,
                username=self._rpc_username,
                password=self._rpc_password,
                rate_limit=True,
                enable_rest=rest_enabled,
            )
            async def _safe_rpc_start():
                try:
                    await self.rpc_server.start()
                except SystemExit as e:
                    logger.error(
                        f"RPC server exited with code {e.code}. "
                        "Node continues without RPC."
                    )
                except Exception as e:
                    logger.error(f"RPC server error: {e}. Node continues without RPC.")

            self._rpc_task = asyncio.create_task(_safe_rpc_start())

            # ZMQ notifier (optional — per-topic configuration)
            # Configure endpoints for each ZMQ topic
            self.zmq_notifier = ZMQNotifier()
            zmq_topics = [
                ('hashblock', self.config.get('zmqpubhashblock')),
                ('hashtx', self.config.get('zmqpubhashtx')),
                ('rawblock', self.config.get('zmqpubrawblock')),
                ('rawtx', self.config.get('zmqpubrawtx')),
                ('sequence', self.config.get('zmqpubsequence')),
            ]
            # Also support legacy zmq_endpoint config
            legacy_endpoint = self.config.get('zmq_endpoint')
            for topic, endpoint in zmq_topics:
                if endpoint:
                    self.zmq_notifier.configure_endpoint(topic, endpoint)
                elif legacy_endpoint and topic in ('hashblock', 'hashtx', 'rawblock', 'rawtx'):
                    # Legacy: apply zmq_endpoint to all hash/raw topics
                    self.zmq_notifier.configure_endpoint(topic, legacy_endpoint)

            if self.zmq_notifier._topic_endpoints:
                await self.zmq_notifier.start()
                if self.block_sync:
                    self.block_sync.set_zmq_notifier(self.zmq_notifier)

            # Prometheus metrics (best-effort; disabled if prometheus_client not installed)
            metrics_port = int(self.config.get('metrics_port', 9332))
            if init_metrics(port=metrics_port):
                from ouroboros.metrics import NODE_INFO as _node_info
                if _node_info is not None:
                    _node_info.info({"version": "0.1.0", "network": self.network})
            
            # Register message handlers
            self._register_handlers()
            
            self.running = True
            logger.info("Bitcoin node started successfully")

            # Print status block to terminal (best-effort; never fatal)
            try:
                self._print_startup_status(rpc_port, p2p_port)
            except Exception as e:
                logger.warning(f"Could not print startup status: {e}")

            # Main loop — runs indefinitely until shutdown signal
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
            
            # Stop ZMQ notifier
            if self.zmq_notifier:
                logger.info("Stopping ZMQ notifier...")
                await self.zmq_notifier.stop()

            # Persist fee estimator state
            if self.fee_estimator:
                fee_est_path = os.path.join(self.data_dir, "fee_estimates.json")
                try:
                    self.fee_estimator.save_to_file(fee_est_path)
                    logger.info("Saved fee estimation data to %s", fee_est_path)
                except Exception as e:
                    logger.warning("Failed to save fee estimates: %s", e)

            # Persist mempool to disk
            if self.mempool:
                mempool_path = os.path.join(self.data_dir, "mempool.dat")
                self.mempool.dump_to_file(mempool_path)

            # Remove cookie file on clean shutdown
            delete_cookie(self.data_dir)

            logger.info("Bitcoin node stopped")
            
        except Exception as e:
            logger.error(f"Error stopping node: {e}", exc_info=True)
    
    async def _main_loop(self):
        """Run indefinitely until an explicit shutdown signal is received.

        The node MUST stay alive even when there are zero connected peers
        (matching Bitcoin Core behaviour).  Only SIGINT, SIGTERM, or an
        RPC ``stop`` command should cause the loop to exit.
        """
        while self.running:
            try:
                # Check for shutdown event
                if self._shutdown_event and self._shutdown_event.is_set():
                    logger.info("Shutdown event received, exiting main loop")
                    break

                # Periodic tasks
                try:
                    await self._periodic_tasks()
                except Exception as e:
                    logger.error(f"Error in periodic tasks: {e}", exc_info=True)

                # Sleep, but check shutdown event more frequently
                for _ in range(60):  # Check every second for 60 seconds
                    if self._shutdown_event and self._shutdown_event.is_set():
                        break
                    await asyncio.sleep(1)

            except asyncio.CancelledError:
                break
            except SystemExit:
                # Never let a stray sys.exit() (e.g. from uvicorn) tear
                # down the node — only explicit shutdown signals should
                # stop us.
                logger.warning("Caught SystemExit in main loop, ignoring")
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt in main loop, shutting down")
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
            
            # Log statistics and update Prometheus gauges
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

                update_chain_metrics(best_height, self.get_current_difficulty(), peer_count)
                update_mempool_metrics(self.mempool.total_size if self.mempool else 0, mempool_size)

                # Run block pruning if enabled
                if self.pruner is not None:
                    try:
                        removed = self.pruner.prune_to_target(best_height)
                        if removed > 0:
                            logger.info(f"Pruned {removed} old block(s)")
                    except Exception as prune_err:
                        logger.debug(f"Pruning error: {prune_err}")

        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}", exc_info=True)
    
    async def _load_snapshot_if_needed(self, snapshot_path: str) -> None:
        """Load a UTXO snapshot if specified via -assumeutxo option.

        This enables fast startup by loading a pre-validated UTXO set,
        then starting background validation from genesis.

        Args:
            snapshot_path: Path to the snapshot file
        """
        if not os.path.exists(snapshot_path):
            logger.error(f"[assumeutxo] Snapshot file not found: {snapshot_path}")
            return

        try:
            # Check if we already have a snapshot chainstate
            if self.snapshot_manager.has_snapshot_chainstate():
                existing_hash = self.snapshot_manager.read_snapshot_base_blockhash()
                if existing_hash:
                    logger.info(
                        f"[assumeutxo] Snapshot chainstate already exists at "
                        f"height {self.snapshot_manager.snapshot_height or 'unknown'}"
                    )
                    # Resume background validation if not completed
                    if not self.snapshot_manager.background_validated:
                        self.snapshot_manager.start_background_validation()
                    return

            # Read snapshot metadata first to validate
            metadata = read_snapshot_metadata(snapshot_path, self.network)
            logger.info(
                f"[assumeutxo] Loading snapshot with {metadata.coins_count:,} coins "
                f"at block {metadata.base_blockhash_hex()[:16]}..."
            )

            # Load the snapshot
            def progress_callback(loaded: int, total: int):
                pct = (loaded / total) * 100
                logger.info(f"[assumeutxo] Loading snapshot: {loaded:,}/{total:,} ({pct:.1f}%)")

            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.snapshot_manager.load_snapshot(snapshot_path, progress_callback),
            )

            logger.info(
                f"[assumeutxo] Snapshot loaded. Node ready to serve at height "
                f"{self.snapshot_manager.snapshot_height}"
            )

            # Start background validation from genesis
            self.snapshot_manager.start_background_validation()

        except Exception as e:
            logger.error(f"[assumeutxo] Failed to load snapshot: {e}")
            raise

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

        # Use the already-computed sync flag; do NOT create a SyncManager
        # here — its constructor opens a second RocksDB handle on the same
        # data directory, which can corrupt state or crash via lock conflict.
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

    def _init_genesis_block(self):
        """Initialize the chain tip to the genesis block for the current network.

        When the database is empty (fresh datadir), we set the best-block
        pointer to the well-known genesis hash at height 0 so the node can
        start without requiring a prior ``ouroboros sync`` run.

        If the Rust extension exposes ``connect_block_from_bytes`` (full
        block storage including UTXO set), we use that.  Otherwise we fall
        back to ``update_best_block`` which only sets the chain-tip pointer
        — enough for RPC / mining to work on regtest.
        """
        import struct

        # Genesis block hashes (internal / little-endian byte order)
        GENESIS_HASHES = {
            'regtest':  bytes.fromhex(
                '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f'),
            'testnet':  bytes.fromhex(
                '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
            'testnet3': bytes.fromhex(
                '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'),
            'testnet4': bytes.fromhex(
                '43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000'),
            'signet':   bytes.fromhex(
                'f61eee3b63a380a477a063af32b2bbc9f7990f1f2c4225e973988181080000'),
            'mainnet':  bytes.fromhex(
                '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'),
        }

        genesis_hash = GENESIS_HASHES.get(self.network)
        if genesis_hash is None:
            logger.warning(f"Unknown network '{self.network}', cannot init genesis")
            return

        # --- Try full connect_block_from_bytes first (stores block + UTXO) ---
        if hasattr(self.db._db, 'connect_block_from_bytes'):
            prev_block = b'\x00' * 32

            if self.network == 'testnet4':
                # Testnet4 (BIP 94) uses a different coinbase message and
                # a 33-byte null pubkey instead of the Satoshi pubkey.
                merkle_root = bytes.fromhex(
                    '7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e'
                )[::-1]
                ts, bits, nonce = 1714777860, 0x1d00ffff, 393743547
                coinbase_tx = bytes.fromhex(
                    '01000000'                                          # version
                    '01'                                                # 1 input
                    '0000000000000000000000000000000000000000000000000000000000000000'
                    'ffffffff'                                          # prevout
                    '55'                                                # scriptSig len (85)
                    '04ffff001d0104'                                    # nBits push + CScriptNum(4)
                    '4c4c'                                              # OP_PUSHDATA1 + 76
                    '30332f4d61792f323032342030303030303030303030303030'
                    '303030303030303165626435386332343439373062336161'
                    '396437383362623030313031316662653865613865393865303065'
                    'ffffffff'                                          # sequence
                    '01'                                                # 1 output
                    '00f2052a01000000'                                  # 50 BTC
                    '23'                                                # scriptPubKey len (35)
                    '21' '000000000000000000000000000000000000000000000000000000000000000000'
                    'ac'                                                # OP_CHECKSIG
                    '00000000'                                          # locktime
                )
            else:
                # Mainnet, testnet3, regtest, signet all share the original
                # Satoshi coinbase (different header params).
                merkle_root = bytes.fromhex(
                    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
                )[::-1]
                if self.network == 'regtest':
                    ts, bits, nonce = 1296688602, 0x207fffff, 2
                elif self.network in ('testnet', 'testnet3'):
                    ts, bits, nonce = 1296688602, 0x1d00ffff, 414098458
                elif self.network == 'signet':
                    ts, bits, nonce = 1598918400, 0x1e0377ae, 52613770
                else:
                    ts, bits, nonce = 1231006505, 0x1d00ffff, 2083236893
                coinbase_tx = bytes.fromhex(
                    '01000000'
                    '01'
                    '0000000000000000000000000000000000000000000000000000000000000000'
                    'ffffffff'
                    '4d'
                    '04ffff001d0104455468652054696d65732030332f4a616e2f323030'
                    '39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73'
                    'ffffffff'
                    '01'
                    '00f2052a01000000'
                    '43'
                    '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac'
                    '00000000'
                )

            header = struct.pack('<i', 1) + prev_block + merkle_root
            header += struct.pack('<III', ts, bits, nonce)
            block_bytes = header + b'\x01' + coinbase_tx
            try:
                self.db._db.connect_block_from_bytes(block_bytes, 0)
                logger.info("Genesis block stored (full connect)")
                return
            except Exception as e:
                logger.warning(f"connect_block_from_bytes failed: {e}, falling back")

        # --- Fallback: just set the chain-tip pointer ---
        self.db._db.update_best_block(genesis_hash, 0)
        logger.info("Genesis block tip set (lightweight init)")

    def _check_synced(self) -> bool:
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

        def _make_tx_handler(sender_peer):
            """Create a per-peer tx handler that relays accepted txs."""
            async def handler(msg):
                if not self.mempool:
                    return
                try:
                    from ouroboros.p2p_messages import (
                        TxMessage, InvMessage, MSG_WITNESS_TX,
                    )

                    tx_msg = TxMessage.from_payload(msg.payload)
                    tx = tx_msg.transaction

                    _, height = self.db.get_best_block()
                    success, error = self.mempool.add_transaction(tx, height)

                    if error == "orphan":
                        txid = tx.get_txid()
                        logger.debug(
                            f"Stored orphan tx {txid.hex()[:16]}... "
                            f"(missing parents)"
                        )
                    elif success:
                        txid = tx.get_txid()
                        logger.info(
                            f"Added transaction {txid.hex()[:16]}... to mempool"
                        )
                        if self.zmq_publisher:
                            self.zmq_publisher.notify_transaction(tx)

                        # Relay INV to all peers except the sender
                        if hasattr(self, "peer_manager") and self.peer_manager:
                            inv = InvMessage(
                                inventory=[(MSG_WITNESS_TX, txid)]
                            )
                            inv_msg = inv.to_network_message(self.network)
                            # Convert mempool fee rate (sat/vB) to sat/kB for
                            # comparison against BIP 133 feefilter values.
                            entry = self.mempool.transactions.get(txid)
                            tx_feerate_per_kb = int(
                                entry.fee_rate * 1000
                            ) if entry else 0
                            for p in self.peer_manager.get_all_ready_peers():
                                if p is not sender_peer:
                                    # Skip peers whose feefilter exceeds
                                    # this tx's fee rate (BIP 133)
                                    if p.peer_feefilter > tx_feerate_per_kb:
                                        continue
                                    try:
                                        await p.send_message(inv_msg)
                                    except Exception:
                                        pass
                    else:
                        logger.debug(f"Rejected transaction: {error}")
                        # Record misbehavior for invalid transactions
                        # Invalid tx = 10 points (requires 10 violations to ban)
                        if hasattr(self, "peer_manager") and self.peer_manager:
                            addr = f"{sender_peer.host}:{sender_peer.port}"
                            self.peer_manager.misbehaving(
                                addr, 10, f"invalid tx: {error}"
                            )

                except Exception as e:
                    logger.error(
                        f"Error handling transaction: {e}", exc_info=True
                    )
            return handler

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
                        MSG_WITNESS_TX,
                        MSG_WITNESS_BLOCK,
                    )

                    getdata = GetDataMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')

                    for inv_type, inv_hash in getdata.inventory:
                        if inv_type in (INV_TYPE_TX, MSG_WITNESS_TX) and self.mempool:
                            tx = self.mempool.get_transaction(inv_hash)
                            if tx:
                                tx_msg = TxMessage(transaction=tx)
                                await peer.send_message(tx_msg.to_network_message(network))
                                logger.debug(f"Sent tx {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                        elif inv_type in (INV_TYPE_BLOCK, MSG_WITNESS_BLOCK):
                            block = self.db.get_block(inv_hash)
                            if block:
                                from ouroboros.p2p_messages import BlockMessage
                                block_msg = BlockMessage(block=block)
                                await peer.send_message(block_msg.to_network_message(network))
                                logger.debug(f"Sent block {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                except Exception as e:
                    logger.error(f"Error handling getdata from {peer.host}:{peer.port}: {e}")

            return handler

        def _make_getheaders_handler(peer):
            """Handle getheaders: respond with headers from our chain."""
            async def handler(msg):
                try:
                    from ouroboros.p2p_messages import (
                        GetHeadersMessage,
                        HeadersMessage,
                        BlockHeader,
                    )

                    getheaders = GetHeadersMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')

                    # Find the fork point: walk through the locator hashes
                    # and find the first one we have in our chain.
                    start_height = 0
                    for locator_hash in getheaders.locator_hashes:
                        block = self.db.get_block(locator_hash)
                        if block is not None:
                            start_height = (block.height if block.height else 0) + 1
                            break

                    # Collect up to 2000 headers starting from start_height.
                    _, best_height = self.db.get_best_block()
                    headers = []
                    for h in range(start_height, min(start_height + 2000, best_height + 1)):
                        block = self.db.get_block_by_height(h)
                        if block is None:
                            break
                        header = BlockHeader(
                            version=block.version,
                            prev_blockhash=block.prev_blockhash,
                            merkle_root=block.merkle_root,
                            timestamp=block.timestamp,
                            bits=block.bits,
                            nonce=block.nonce,
                        )
                        headers.append(header)

                        # Stop if we've reached hash_stop.
                        if getheaders.hash_stop != b'\x00' * 32:
                            block_hash = block.hash
                            if block_hash == getheaders.hash_stop:
                                break

                    if headers:
                        headers_msg = HeadersMessage(headers=headers)
                        await peer.send_message(headers_msg.to_network_message(network))
                        logger.debug(
                            f"Sent {len(headers)} headers to "
                            f"{peer.host}:{peer.port} (from height {start_height})"
                        )
                    else:
                        # Send empty headers message (signals "no new headers").
                        headers_msg = HeadersMessage(headers=[])
                        await peer.send_message(headers_msg.to_network_message(network))

                except Exception as e:
                    logger.error(f"Error handling getheaders from {peer.host}:{peer.port}: {e}")

            return handler

        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
            for peer in peers:
                if hasattr(peer, 'register_handler'):
                    peer.register_handler("tx", _make_tx_handler(peer))
                    peer.register_handler("getdata", _make_getdata_handler(peer))
                    peer.register_handler("getheaders", _make_getheaders_handler(peer))

        # Register callback for future inbound peers so they get handlers too
        async def _on_inbound_peer(peer):
            peer.register_handler("tx", _make_tx_handler(peer))
            peer.register_handler("getdata", _make_getdata_handler(peer))
            peer.register_handler("getheaders", _make_getheaders_handler(peer))

        self.peer_manager.set_inbound_peer_handler(_on_inbound_peer)

        logger.info("Transaction, getdata, and getheaders handlers registered")
    
    def is_synced(self) -> bool:
        """Return True when the node has completed initial block synchronisation."""
        return self.synced
    
    def _bits_to_difficulty(self, bits: int) -> float:
        """Convert compact target (bits) to difficulty."""
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
        """Return the proof-of-work difficulty of the current chain tip."""
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
        """Median timestamp of the 11 blocks ending at *height* (or the chain tip when None)."""
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
        """Calculate proof-of-work for a block."""
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
        """Calculate cumulative chainwork up to height."""
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
        """Return cumulative chain work at the tip as a hex string."""
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
        """Return the number of confirmations for a block at *height*."""
        if not self.db:
            return 0
        
        try:
            _, best_height = self.db.get_best_block()
            return max(0, best_height - height + 1)
        except:
            return 0
    
    def get_difficulty(self, bits: int) -> float:
        """Convert compact *bits* target to difficulty."""
        return self._bits_to_difficulty(bits)
    
    def get_chainwork_at_height(self, height: int) -> str:
        """Return cumulative chain work up to *height* as a hex string."""
        if not self.db:
            return "0x0"
        
        try:
            chainwork = self._calculate_chainwork_at_height(height)
            return f"0x{chainwork:x}"
        except Exception as e:
            logger.error(f"Error getting chainwork at height {height}: {e}", exc_info=True)
            return "0x0"
    
    async def run(self) -> None:
        """Start the node and block until shutdown (convenience wrapper for ``start()``)."""
        try:
            await self.start()
        finally:
            # Ensure clean shutdown (cookie deletion, DB flush, etc.) even
            # when start() returns normally after _main_loop exits.
            await self.stop()
