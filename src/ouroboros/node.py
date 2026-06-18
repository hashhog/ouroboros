"""
Main Bitcoin full node class.

This module implements the main Bitcoin node that orchestrates all components:
database, validation, mempool, peer management, block synchronization, and RPC server.
"""

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from ouroboros.block_sync import BlockSync
from ouroboros.config import NodeConfig
from ouroboros.cookie_auth import delete_cookie, generate_cookie
from ouroboros.database import BlockchainDatabase
from ouroboros.fee_estimator import FeeEstimator
from ouroboros.mempool import Mempool
from ouroboros.metrics import (
    init_metrics,
    update_chain_metrics,
    update_mempool_metrics,
)
from ouroboros.p2p import PeerManager
from ouroboros.pruning import BlockPruner
from ouroboros.rpc import RPCServer
from ouroboros.snapshot import SnapshotManager, read_snapshot_metadata
from ouroboros.sync_manager import SyncManager
from ouroboros.validation import BlockValidator, TransactionValidator
from ouroboros.wallet import Wallet, WalletManager
from ouroboros.zmq_notifier import ZMQNotifier

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BIP-157 stop-hash ancestor walk (FIX-75 / W121 #3 — P2P-handler side of the
# universal "active-chain walk vs stop-hash ancestor" pattern, follow-on to
# FIX-74 a4cebff which closed the reorg-bookkeeping side).
# ---------------------------------------------------------------------------
# Mirrors Bitcoin Core ``CBlockIndex::GetAncestor(int height)`` from
# src/chain.{cpp,h}: walks ``pprev`` back from the index until it reaches the
# requested height.  In ouroboros the "pprev" link is ``block.prev_blockhash``
# resolved via ``db.get_block(hash)``.  Compact filters are indexed by block
# hash regardless of fork membership, so a getcfilters/getcfheaders/getcfcheckpt
# probe with an orphan stop_hash must walk *that fork*, not the active chain
# (see net_processing.cpp ``PrepareBlockFilterRequest`` /
# ``ProcessGetCFilters`` / ``ProcessGetCFHeaders`` — no ``chain.Contains``
# check; LookupBlockIndex by hash then GetAncestor walks pprev).
def _get_ancestor(db, block, target_height: int):
    """Return the ancestor of ``block`` at ``target_height``, or ``None``.

    Walks ``prev_blockhash`` pointers via ``db.get_block`` until the height
    matches.  Returns ``None`` if:
      - ``block`` is ``None`` or has no known height,
      - ``target_height`` is negative or greater than ``block.height``,
      - the chain walk runs off the end (db inconsistency / pruned).

    Crucially: this does NOT consult ``db.get_block_by_height`` — that walks
    the *active* chain and would silently serve active-chain filters for a
    stale-fork stop_hash (signed-but-lying response; see W121 #3).  Match
    Core's behavior: serve the fork the peer asked about.
    """
    if block is None:
        return None
    if block.height is None:
        return None
    if target_height < 0 or target_height > block.height:
        return None
    cur = block
    # Bounded by block.height - target_height iterations; cap at a generous
    # upper bound to avoid infinite loops if the db ever returns a cycle.
    max_steps = block.height - target_height + 1
    steps = 0
    while cur is not None and cur.height is not None and cur.height > target_height:
        if steps > max_steps:
            return None
        cur = db.get_block(cur.prev_blockhash)
        steps += 1
    if cur is None or cur.height != target_height:
        return None
    return cur


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
        self.db: BlockchainDatabase | None = None
        self.validator: BlockValidator | None = None
        self.tx_validator: TransactionValidator | None = None
        self.mempool: Mempool | None = None

        # Fee estimator
        self.fee_estimator: FeeEstimator | None = None

        # Wallet manager (multi-wallet support)
        self.wallet_manager: WalletManager | None = None
        # Legacy single wallet reference (for backwards compatibility)
        self.wallet: Wallet | None = None

        # Network components
        self.peer_manager: PeerManager | None = None
        self.block_sync: BlockSync | None = None

        # RPC server
        self.rpc_server: RPCServer | None = None

        # Sync manager
        self.sync_manager: SyncManager | None = None

        # Block pruner
        self.pruner: BlockPruner | None = None

        # ZMQ notifier (replaces the older zmq_publisher)
        self.zmq_notifier: ZMQNotifier | None = None

        # Snapshot manager for assumeUTXO
        self.snapshot_manager: SnapshotManager | None = None

        # BIP 157/158 compact block filter index (-blockfilterindex).
        # Lazily instantiated in start() when the flag is enabled; remains
        # None otherwise (RPC + P2P handlers fall back to the legacy
        # build-on-demand path used before this option was added).
        self.block_filter_index = None

        # Coin-stats index (-coinstatsindex).  Lazily instantiated in start()
        # when the flag is enabled; remains None otherwise (gettxoutsetinfo
        # then errors -8 on a non-tip hash_or_height, matching Core).
        self.coinstats_index = None

        # Txo spender index (-txospenderindex).  Lazily instantiated in start()
        # when the flag is enabled; remains None otherwise (gettxspendingprevout
        # then only answers the mempool form, matching Core's
        # DEFAULT_TXOSPENDERINDEX{false}).
        self.txospender_index = None

        # State
        self.running = False
        self.synced = False
        # Last wall-clock time the mempool/orphan TTL sweep ran.  The status
        # loop fires ~every 60s; gate the sweep to ORPHAN_TX_EXPIRE_INTERVAL
        # (Core net_processing: 5 min) so we don't scan the pool every tick.
        self._last_mempool_expire: float = 0.0
        self._rpc_task: asyncio.Task | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._rpc_username: str | None = None
        self._rpc_password: str | None = None

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

            # Self-heal a snapshot-bootstrapped datadir whose base block index
            # was never persisted (the Rust ``import-utxo`` CLI path writes only
            # the UTXO set + tip pointer; older builds did too).  If the tip
            # sits exactly at a known snapshot height, the snapshot base has no
            # full block body in BLOCKS_CF, and the sibling header files are
            # missing, persist them now — otherwise the FIRST block above the
            # snapshot fails forever with "Previous block not found".  Cheap,
            # idempotent, and avoids forcing a full UTXO re-import.
            self._heal_snapshot_base_index()

            # Check for assumeutxo option and load snapshot if specified
            assumeutxo_path = self.config.get('assumeutxo')
            if assumeutxo_path:
                await self._load_snapshot_if_needed(assumeutxo_path)

            # Initialize validators
            logger.info("Initializing validators...")
            # The mempool's TransactionValidator also needs the snapshot
            # manager so the BIP-68 stopgap (OUROBOROS_BIP68_STOPGAP=1)
            # can detect pre-snapshot prevouts on relayed/mempool tx
            # validation paths -- not just block-validation paths.  The
            # BlockValidator below propagates ``snapshot_manager`` to a
            # *separate* TransactionValidator instance it owns, so we
            # must wire it here too (the two instances do not share).
            self.tx_validator = TransactionValidator(
                self.db, network=self.network, snapshot_manager=self.snapshot_manager,
            )
            # Pass the snapshot manager so the validator can synthesize a
            # prev block for the snapshot tip (the FIRST block above the
            # snapshot base would otherwise fail with "Previous block not
            # found" forever -- BLOCKS_CF has no entry for the snapshot
            # tip and the loadtxoutset wire format does not carry the tip
            # block's bytes).  See BlockValidator._synthesize_snapshot_prev_block.
            self.validator = BlockValidator(
                self.db,
                network=self.network,
                snapshot_manager=self.snapshot_manager,
            )

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

            # Rebuild each loaded wallet's in-memory tx history from the chain
            # in the BACKGROUND. The wallet file persists keys/seed/keypool
            # durably, but the per-tx history is in-memory only (Core rebuilds
            # mapWallet from a rescan on load). Without this, listtransactions /
            # balance-by-history are empty after a restart until a manual
            # rescanblockchain.
            #
            # CRITICAL: this rescan walks every block from 0 to the tip. Running
            # it synchronously here blocks the rest of node startup — the RPC
            # server is not bound until ~250 lines below — so on a fully synced
            # mainnet (~950k blocks) the node spins for many minutes with RPC
            # refused and never finishes booting (the restart-wedge that kept
            # this node down). Core keeps RPC responsive while the wallet
            # rescans (getwalletinfo.scanning) — mirror that: offload the
            # CPU-bound scan to a worker thread so the event loop, P2P sync and
            # RPC all come up immediately and wallet history fills in
            # concurrently. Best-effort: a wallet fault must never block startup.
            async def _bg_wallet_reconcile():
                try:
                    await asyncio.to_thread(self.wallet_manager.reconcile_on_load)
                    logger.info("Wallet startup reconcile complete")
                except Exception as e:
                    logger.warning(f"Wallet startup reconcile failed: {e}")
            self._wallet_reconcile_task = asyncio.create_task(_bg_wallet_reconcile())

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
            # v2transport may arrive as bool (NodeConfig.to_dict normalises)
            # or as a raw "0"/"1"/"true"/"false" string (CLI/dict override
            # before normalisation).  Treat the same way we handle ``listen``
            # below to avoid the "string '0' is truthy" footgun that used
            # to silently keep v2transport=0 enabled.
            v2_raw = self.config.get('v2transport', False)
            if isinstance(v2_raw, str):
                v2_enabled = v2_raw.lower() in ("1", "true", "yes", "on")
            else:
                v2_enabled = bool(v2_raw)
            p2p_transport = 2 if v2_enabled else 1
            logger.info(
                f"BIP 324 v2 transport: {'enabled' if v2_enabled else 'disabled (v1-only)'}"
            )
            listen_enabled = self.config.get('listen', True)
            # Treat explicit "0" or False as disabled
            if str(listen_enabled).lower() in ("0", "false", "no"):
                listen_enabled = False
            # BIP 111 -peerbloomfilters (Core parity, default false).  Same
            # string-coerce dance as v2transport so a conf value of "0"
            # disables advertisement.
            pbf_raw = self.config.get('peerbloomfilters', False)
            if isinstance(pbf_raw, str):
                peer_bloom_filters = pbf_raw.lower() in ("1", "true", "yes", "on")
            else:
                peer_bloom_filters = bool(pbf_raw)
            logger.info(
                f"BIP 111 NODE_BLOOM advertisement: "
                f"{'enabled' if peer_bloom_filters else 'disabled (Core parity default)'}"
            )
            # BIP 157/158 -blockfilterindex (Core parity, default false).
            bfi_raw = self.config.get('blockfilterindex', False)
            if isinstance(bfi_raw, str):
                block_filter_index_enabled = bfi_raw.lower() in ("1", "true", "yes", "on")
            else:
                block_filter_index_enabled = bool(bfi_raw)
            if block_filter_index_enabled:
                from ouroboros.blockfilter import PersistentBlockFilterIndex
                try:
                    self.block_filter_index = PersistentBlockFilterIndex(
                        data_dir=self.data_dir, enabled=True,
                    )
                    # The BIP 157 filter-header chain MUST start at the
                    # genesis block: height 1's header is
                    # dSHA256(dSHA256(filter_1) || filter_header_0), where
                    # filter_header_0 = dSHA256(dSHA256(filter_0) || 0^32).
                    # Bitcoin Core's BlockFilterIndex indexes the genesis
                    # block like any other (BaseIndex starts at the genesis
                    # CBlockIndex).  The genesis is stored via
                    # _init_genesis_block but is NEVER fed through the
                    # block-connect hook (which only fires for heights >= 1),
                    # so seed it here.  Without this the index tip_header
                    # starts at 0^32 and EVERY subsequent header is off by
                    # the genesis link.  Idempotent on restart.
                    self._index_genesis_filter()
                    # Crash-safety reconcile (Core BaseIndex::Init parity).
                    # The chainstate commit is atomic but the filter index is
                    # written from a separate thread AFTER it, so an unclean
                    # restart (or a rollback/reorg) can leave the index AHEAD
                    # of / forked from the chainstate.  Rewind the index to the
                    # active chain BEFORE the peer manager starts advertising
                    # NODE_COMPACT_FILTERS, so we never serve cfilters for
                    # blocks that are not on our active chain.
                    try:
                        rewound = self.block_filter_index.reconcile_to_chainstate(
                            self.db
                        )
                        if rewound:
                            logger.warning(
                                f"BIP 157/158 block filter index: startup "
                                f"reconcile rewound {rewound} height(s) to match "
                                f"chainstate"
                            )
                    except Exception as e:
                        logger.warning(
                            f"BIP 157/158 block filter index: startup reconcile "
                            f"failed ({e}); index may be ahead of chainstate"
                        )
                    logger.info(
                        "BIP 157/158 block filter index: enabled "
                        "(NODE_COMPACT_FILTERS advertisement is gated on "
                        "index-synced-to-tip; see FIX-71 / W121 BUG-5)"
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to open block filter index ({e}); "
                        "continuing without -blockfilterindex"
                    )
                    self.block_filter_index = None
                    block_filter_index_enabled = False
            else:
                logger.info(
                    "BIP 157/158 block filter index: disabled (Core parity default)"
                )

            # -coinstatsindex (Core parity, default false).  Maintains a
            # per-height running MuHash3072 commitment over the UTXO set so
            # gettxoutsetinfo can answer for a historical hash_or_height.
            csi_raw = self.config.get('coinstatsindex', False)
            if isinstance(csi_raw, str):
                coinstats_index_enabled = csi_raw.lower() in ("1", "true", "yes", "on")
            else:
                coinstats_index_enabled = bool(csi_raw)
            if coinstats_index_enabled:
                from ouroboros.coinstatsindex import CoinStatsIndex
                try:
                    self.coinstats_index = CoinStatsIndex(
                        data_dir=self.data_dir, enabled=True,
                    )
                    # Seed the genesis height (height 0).  Core's
                    # CoinStatsIndex indexes the genesis block, but its single
                    # coinbase output is provably unspendable and never enters
                    # the UTXO set, so the height-0 snapshot is an EMPTY set
                    # (matching Core's coinstats at genesis).  The genesis is
                    # never fed through the block-connect hook (which fires
                    # only for heights >= 1), so seed it here.  Idempotent on
                    # restart.
                    self._index_genesis_coinstats()
                    # Crash-safety reconcile (Core BaseIndex::Init parity):
                    # rewind the index to the active chain if an unclean
                    # restart / reorg left it ahead of or forked from the
                    # chainstate.
                    try:
                        rewound = self.coinstats_index.reconcile_to_chainstate(
                            self.db
                        )
                        if rewound:
                            logger.warning(
                                f"coinstatsindex: startup reconcile rewound "
                                f"{rewound} height(s) to match chainstate"
                            )
                    except Exception as e:
                        logger.warning(
                            f"coinstatsindex: startup reconcile failed ({e}); "
                            "index may be ahead of chainstate"
                        )
                    logger.info("coin-stats index: enabled")
                except Exception as e:
                    logger.warning(
                        f"Failed to open coin-stats index ({e}); "
                        "continuing without -coinstatsindex"
                    )
                    self.coinstats_index = None
                    coinstats_index_enabled = False
            else:
                logger.info(
                    "coin-stats index: disabled (Core parity default)"
                )

            # -txospenderindex (Core parity, default false).  Maintains a
            # spent-outpoint -> spending-tx index so gettxspendingprevout can
            # resolve confirmed spends.  Same plumbing as -coinstatsindex.
            tsi_raw = self.config.get('txospenderindex', False)
            if isinstance(tsi_raw, str):
                txospender_index_enabled = tsi_raw.lower() in ("1", "true", "yes", "on")
            else:
                txospender_index_enabled = bool(tsi_raw)
            if txospender_index_enabled:
                from ouroboros.txospenderindex import TxoSpenderIndex
                try:
                    self.txospender_index = TxoSpenderIndex(
                        data_dir=self.data_dir, enabled=True,
                    )
                    # Crash-safety reconcile (Core BaseIndex::Init parity):
                    # rewind the index to the active chain if an unclean
                    # restart / reorg left it ahead of or forked from the
                    # chainstate.  Then catch up forward to the chain tip so a
                    # node enabled with an already-synced chain backfills the
                    # spend keys it missed (Core builds the index from genesis).
                    try:
                        self.txospender_index.reconcile_to_chainstate(self.db)
                        connected = self.txospender_index.resync_to_chainstate(
                            self.db
                        )
                        if connected:
                            logger.info(
                                f"txospenderindex: built {connected} height(s) "
                                f"forward to chainstate tip on startup"
                            )
                    except Exception as e:
                        logger.warning(
                            f"txospenderindex: startup reconcile/catch-up "
                            f"failed ({e}); index may lag chainstate"
                        )
                    logger.info("txo spender index: enabled")
                except Exception as e:
                    logger.warning(
                        f"Failed to open txo spender index ({e}); "
                        "continuing without -txospenderindex"
                    )
                    self.txospender_index = None
                    txospender_index_enabled = False
            else:
                logger.info(
                    "txo spender index: disabled (Core parity default)"
                )

            # FIX-71 / W121 BUG-5: pass a callable that re-evaluates the
            # NODE_COMPACT_FILTERS gate on every handshake.  The
            # predicate is two-part, matching Bitcoin Core's
            # ``init.cpp`` + ``BaseIndex::IsSynced`` semantics:
            #   1. ``-blockfilterindex`` enabled, AND
            #   2. ``BlockFilterIndex.is_synced(active_chain_tip_height)``.
            # When the index is mid-IBD (or rewinding through a reorg)
            # the callable returns False so the bit stays UN-advertised
            # — peers that try to query compact filters from us in that
            # window would otherwise receive zero-anchored cfheaders
            # (BUG-4 collateral).
            # Core/clearbit -connect peer-pinning + independent -dnsseed.
            # Parse the --connect list here so the PeerManager learns the pins
            # at construction time (before start() runs its discover/auto-fill
            # paths).  A non-empty list switches the manager into connect-only
            # mode: dial ONLY these peers, no DNS seeding, no auto-outbound.
            connect_addrs: list[tuple[str, int]] = []
            for addr_str in self.config.get('connect', []) or []:
                try:
                    if ':' in addr_str:
                        host, port_s = addr_str.rsplit(':', 1)
                        cport = int(port_s)
                    else:
                        host = addr_str
                        cport = 8333
                    connect_addrs.append((host, cport))
                except Exception as e:
                    logger.warning(f"Ignoring malformed --connect {addr_str!r}: {e}")
            # -dnsseed / -nodnsseed (default on).  Independent suppression of
            # DNS-seed resolution; -connect forces it off regardless inside
            # PeerManager.  Accept bool or "0"/"false" string from conf/CLI.
            dns_raw = self.config.get('dnsseed', True)
            if isinstance(dns_raw, str):
                dns_seed_enabled = dns_raw.lower() in ("1", "true", "yes", "on")
            else:
                dns_seed_enabled = bool(dns_raw)
            self.peer_manager = PeerManager(
                self.network,
                max_peers=max_peers,
                data_dir=self.data_dir,
                transport_version=p2p_transport,
                listen=bool(listen_enabled),
                peer_bloom_filters=peer_bloom_filters,
                node_compact_filters=self._compact_filters_advertised,
                connect_addrs=connect_addrs,
                dns_seed=dns_seed_enabled,
            )
            # BIP 152: Provide mempool and database for compact block relay
            self.peer_manager.set_mempool(self.mempool)
            self.peer_manager.set_database(self.db)
            try:
                # PeerManager.start() now handles the --connect pins itself
                # (dials only them, skips DNS + auto-outbound) because the pin
                # list was passed at construction.  No post-start dialing loop
                # is needed; the pins reconnect via maintain_connections().
                await self.peer_manager.start(best_height, p2p_port=p2p_port)
            except Exception as e:
                logger.warning(f"Peer manager start error (node continues): {e}")
            peer_count = len(self.peer_manager.get_all_ready_peers()) if self.peer_manager else 0
            logger.info(f"Peer manager started ({peer_count} peers)")

            # Initialize block sync
            logger.info("Initializing block synchronization...")
            self.block_sync = BlockSync(
                self.db, self.validator, self.peer_manager,
                mempool=self.mempool,
                fee_estimator=self.fee_estimator,
                block_filter_index=self.block_filter_index,
                coinstats_index=self.coinstats_index,
                txospender_index=self.txospender_index,
                # Feed every canonically-connected/disconnected block to the
                # wallet manager so loaded wallets track their own txs in
                # lock-step with the chain (Core CWallet::blockConnected).
                wallet_notifier=self.wallet_manager,
            )
            # Reverse wiring: PeerManager._cleanup_peer_state delegates
            # per-peer state cleanup on disconnect to block_sync.cleanup_peer
            # (and sync_manager.cleanup_peer when present).  Pre-#146 this
            # back-edge was missing, so block_sync._peer_handlers retained
            # the closures (and therefore the entire Peer instance, with
            # its socket buffers + BIP-324 transport state) for every peer
            # that ever disconnected.
            self.peer_manager.block_sync = self.block_sync
            try:
                await self.block_sync.start()
            except Exception as e:
                logger.warning(f"Block sync start error (node continues): {e}")

            # BIP 152 (FIX-41 / W112 BUG-1): wire the compact block handler so
            # that reconstructed blocks are submitted to the block sync pipeline.
            # Without this call, _on_compact_block is permanently None and every
            # compact block reconstruction result is silently discarded.
            _block_sync_ref = self.block_sync
            def _compact_block_handler(block_hash: bytes, header: bytes, txs: list) -> None:
                """Serialize header + txs and feed into the block sync buffer."""
                try:
                    from ouroboros.p2p_messages import encode_varint
                    # Assemble wire-format block: 80-byte header + varint tx count + txs
                    raw = bytearray(header)
                    raw.extend(encode_varint(len(txs)))
                    for tx in txs:
                        raw.extend(tx.serialize_with_witness())
                    raw_bytes = bytes(raw)
                    # Feed into the IBD buffer directly — bypasses the
                    # duplicate-check / fTooFarAhead guard that apply to unsolicited
                    # P2P blocks.  Compact blocks are always solicited (we sent
                    # getblocktxn or received cmpctblock from a sendcmpct peer).
                    if len(_block_sync_ref._ibd_block_buffer) < _block_sync_ref._max_ibd_buffer:
                        _block_sync_ref._ibd_block_buffer[block_hash] = (None, raw_bytes)
                        _block_sync_ref._blk_buffered += 1
                        logger.debug(
                            f"compact block buffered "
                            f"{block_hash.hex()[:16]}... ({len(txs)} txs)"
                        )
                        # Schedule a drain — run on the event loop since
                        # _compact_block_handler is called from a sync context.
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                loop.create_task(_block_sync_ref._drain_block_buffer())
                        except RuntimeError:
                            pass
                    else:
                        logger.debug(
                            f"compact block dropped (buffer full): "
                            f"{block_hash.hex()[:16]}..."
                        )
                except Exception as e:
                    logger.error(f"compact block handler error: {e}", exc_info=True)
            self.peer_manager.set_compact_block_handler(_compact_block_handler)
            logger.debug("BIP 152: compact block handler registered")

            # Start RPC server (with optional REST interface and HTTPS/TLS)
            rest_enabled = str(self.config.get('rest', '0')).lower() in ('1', 'true', 'yes', 'on')
            # TLS termination (W119 / FIX-64).  Operators may pass
            # --rpc-tls-cert + --rpc-tls-key on the CLI (both-or-neither;
            # mismatch raises in RPCServer.__init__).  When both are unset
            # the server falls back to plain HTTP for backward compat with
            # cookie / curl tooling that doesn't speak TLS.
            tls_certfile = self.config.get('rpc_tls_cert') or None
            tls_keyfile = self.config.get('rpc_tls_key') or None
            scheme = "https" if (tls_certfile and tls_keyfile) else "http"
            logger.info(f"RPC server listening on {scheme}://127.0.0.1:{rpc_port}")
            if rest_enabled:
                logger.info("REST interface enabled at /rest/*")
            self.rpc_server = RPCServer(
                self,
                port=rpc_port,
                username=self._rpc_username,
                password=self._rpc_password,
                rate_limit=True,
                enable_rest=rest_enabled,
                tls_certfile=tls_certfile,
                tls_keyfile=tls_keyfile,
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

            # P2P-reorg route-through wiring (GAP3): now that BOTH block_sync
            # and rpc_server exist, inject the RPC server's submitblock
            # side-branch reorg methods (_attach_side_branch_block /
            # _reorg_to_side_branch_tip) into block_sync via a callback
            # closure.  This routes a P2P-discovered heavier fork through the
            # SAME tested reorg path submitblock uses, without block_sync
            # importing rpc at module top (which would create an import cycle).
            try:
                if self.block_sync is not None and self.rpc_server is not None:
                    self.block_sync.set_reorg_handler(self.rpc_server)
                    logger.debug("P2P fork reorg handler wired into block_sync")
            except Exception as e:
                logger.warning(
                    f"Failed to wire P2P fork reorg handler "
                    f"(P2P reorg disabled, node continues): {e}"
                )

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

            # Optional tracemalloc profiling thread — OPT-IN only.
            #
            # Set OUROBOROS_TRACEMALLOC=<N> (integer seconds) to start a
            # background daemon thread that takes a heap snapshot every N
            # seconds and appends the top-25 tracemalloc statistics (grouped
            # by source line) to <datadir>/tracemalloc.log, each entry tagged
            # with the current wall-clock time and process RSS (from
            # /proc/self/statm).  When N is not set (or ≤ 0) this block is a
            # complete no-op — zero overhead, zero threads, zero imports.
            #
            # Usage on maxbox:
            #   OUROBOROS_TRACEMALLOC=60 python3 -m ouroboros.cli start ...
            #
            # The dumps just before the RSS knee finger the burst site.  Each
            # dump is one JSON-lines record so `jq` can slice the log later.
            _tracemalloc_interval_str = os.environ.get("OUROBOROS_TRACEMALLOC", "")
            try:
                _tm_interval = int(_tracemalloc_interval_str)
            except (ValueError, TypeError):
                _tm_interval = 0

            if _tm_interval > 0:
                import json
                import threading
                import tracemalloc

                _tm_log_path = os.path.join(self.data_dir, "tracemalloc.log")
                _tm_nframes = 25

                def _tracemalloc_thread() -> None:
                    tracemalloc.start(_tm_nframes)
                    logger.info(
                        "tracemalloc: profiling started (interval=%ds, "
                        "log=%s, frames=%d)",
                        _tm_interval,
                        _tm_log_path,
                        _tm_nframes,
                    )
                    while True:
                        # Check a stop event rather than spinning forever so
                        # the thread wakes promptly on shutdown.
                        if _tracemalloc_stop.wait(timeout=_tm_interval):
                            break

                        try:
                            snapshot = tracemalloc.take_snapshot()
                            stats = snapshot.statistics("lineno")

                            # RSS from /proc/self/statm (field 1 = RSS pages)
                            try:
                                with open("/proc/self/statm") as _f:
                                    _rss_pages = int(_f.read().split()[1])
                                    _rss_mb = _rss_pages * 4096 / (1024 * 1024)
                            except Exception:
                                _rss_mb = -1.0

                            record = {
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                    time.gmtime()),
                                "rss_mb": round(_rss_mb, 1),
                                "top": [
                                    {
                                        "file": str(s.traceback[0].filename),
                                        "lineno": s.traceback[0].lineno,
                                        "size_kb": round(s.size / 1024, 1),
                                        "count": s.count,
                                    }
                                    for s in stats[:_tm_nframes]
                                ],
                            }
                            with open(_tm_log_path, "a") as _lf:
                                _lf.write(json.dumps(record) + "\n")
                        except Exception as _e:
                            logger.debug("tracemalloc snapshot error: %s", _e)

                    tracemalloc.stop()
                    logger.info("tracemalloc: profiling stopped")

                _tracemalloc_stop = threading.Event()
                _tm_thread = threading.Thread(
                    target=_tracemalloc_thread,
                    name="ouroboros-tracemalloc",
                    daemon=True,
                )
                _tm_thread.start()
                logger.info(
                    "tracemalloc: daemon thread started (interval=%ds, log=%s)",
                    _tm_interval,
                    _tm_log_path,
                )
            else:
                _tracemalloc_stop = None  # no-op reference

            # Print status block to terminal (best-effort; never fatal)
            try:
                self._print_startup_status(rpc_port, p2p_port)
            except Exception as e:
                logger.warning(f"Could not print startup status: {e}")

            # Main loop — runs indefinitely until shutdown signal
            await self._main_loop()

            # Signal tracemalloc thread to stop when the main loop exits.
            if _tracemalloc_stop is not None:
                _tracemalloc_stop.set()

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

                # Periodic mempool + orphan-pool TTL sweep.  The status loop
                # ticks ~every 60s; gate the sweep to ORPHAN_TX_EXPIRE_INTERVAL
                # (Core net_processing.cpp: 5 min) so we don't scan the pool
                # every tick.  expire_old_transactions() removes mempool txs
                # past the 2-week expiry AND internally calls
                # orphan_pool.expire() (the 20-min orphan TTL).  Before this
                # call existed neither sweep had a live caller — both the
                # mempool-expiry and orphan-TTL were dead code on the running
                # node (Core LimitOrphans / periodic Expire equivalent).
                ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60  # seconds (Core: 5 min)
                if self.mempool is not None:
                    now = time.time()
                    if now - self._last_mempool_expire >= ORPHAN_TX_EXPIRE_INTERVAL:
                        self._last_mempool_expire = now
                        try:
                            self.mempool.expire_old_transactions(now)
                        except Exception as exp_err:
                            logger.debug(f"Mempool/orphan expiry error: {exp_err}")

                # Run block pruning if enabled
                if self.pruner is not None:
                    try:
                        # prune_to_target returns (files_pruned, bytes_freed).
                        # Previously this code did `if removed > 0` on the
                        # tuple, which raises TypeError on every trigger and
                        # was silently swallowed by the surrounding except —
                        # so auto-pruning never actually fired in production.
                        # See _pruning-cross-impl-audit-2026-05-05.md (Bug 3).
                        removed_files, bytes_freed = self.pruner.prune_to_target(
                            best_height
                        )
                        if removed_files > 0:
                            logger.info(
                                f"Pruned {removed_files} old block file(s) "
                                f"({bytes_freed / 1_000_000:.1f} MB freed)"
                            )
                    except Exception as prune_err:
                        logger.debug(f"Pruning error: {prune_err}")

        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}", exc_info=True)

    def _heal_snapshot_base_index(self) -> None:
        """Persist a missing snapshot-base block index on a bootstrapped datadir.

        See the call site in ``start()``.  This recovers datadirs that were
        bootstrapped by the Rust ``import-utxo`` CLI (or an older loader) which
        wrote only the UTXO set + tip pointer but not the snapshot base's
        connectable index — leaving the first post-snapshot block to be
        rejected with "Previous block not found" indefinitely.
        """
        from ouroboros.snapshot import get_available_snapshot_heights

        try:
            tip_hash, tip_height = self.db.get_best_block()
        except Exception:
            # Empty DB (genesis bootstrap) — nothing to heal.
            return

        if tip_height not in get_available_snapshot_heights(self.network):
            return  # Tip is not a known snapshot height; normal IBD/synced node.

        # If the sibling files already exist the base is already connectable.
        if self.snapshot_manager.has_snapshot_chainstate():
            return

        # If the base block has a full body in BLOCKS_CF this is a normally
        # synced node that merely happens to be paused at a snapshot height —
        # don't synthesize anything.
        try:
            if self.db.get_block(tip_hash) is not None:
                return
        except Exception:
            pass

        logger.warning(
            "[snapshot] Datadir tip is at snapshot height %d but the snapshot "
            "base index is missing (import-utxo / legacy loader). Persisting "
            "base header + chainwork now so the first post-snapshot block can "
            "connect.",
            tip_height,
        )
        try:
            healed = self.snapshot_manager.persist_snapshot_base_index(tip_hash)
            if healed:
                # Reflect the recovered state on the manager so RPC/validation
                # treat this as a loaded snapshot.
                self.snapshot_manager.snapshot_loaded = True
                self.snapshot_manager.snapshot_height = tip_height
                self.snapshot_manager.snapshot_hash = tip_hash
                logger.info(
                    "[snapshot] Snapshot base index healed at height %d.",
                    tip_height,
                )
        except Exception as e:
            logger.error(
                "[snapshot] Failed to heal snapshot base index at height %d: %s",
                tip_height, e,
            )

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
        if hasattr(self.db, 'connect_block_from_bytes'):
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
                self.db.connect_block_from_bytes(block_bytes, 0)
                logger.info("Genesis block stored (full connect)")
                return
            except Exception as e:
                logger.warning(f"connect_block_from_bytes failed: {e}, falling back")

        # --- Fallback: just set the chain-tip pointer ---
        self.db.update_best_block(genesis_hash, 0)
        logger.info("Genesis block tip set (lightweight init)")

    def _index_genesis_filter(self):
        """Seed the BIP 157/158 filter index with the genesis block.

        The filter-header chain is anchored at the genesis: every height-1
        header chains off ``filter_header_0``, which itself chains off the
        all-zero prev-header.  Bitcoin Core's BlockFilterIndex indexes the
        genesis block exactly like any other (its BaseIndex begins at the
        genesis CBlockIndex).  In ouroboros the genesis is connected via
        :meth:`_init_genesis_block` but is never routed through the
        block-connect index hook (which only runs for heights >= 1), so the
        genesis filter/header would otherwise be missing and the chain would
        start from 0^32 — making every height-1+ header diverge from Core.

        Idempotent: if the genesis filter is already indexed (e.g. on
        restart) this is a no-op.  Best-effort: any failure is logged and
        swallowed so it can never block node startup.
        """
        bfi = self.block_filter_index
        if bfi is None or self.db is None:
            return
        try:
            genesis = self.db.get_block_by_height(0)
            if genesis is None:
                return
            # Already indexed? get_header returns the stored 32-byte header.
            if bfi.get_header(genesis.hash) is not None:
                return
            # add_block builds the filter and chains the header off the
            # current tip header.  For a fresh index the tip header is 0^32
            # (the genesis's parent), which is exactly Core's anchor.
            bfi.add_block(genesis, height=0, db=self.db)
            logger.info("BIP 157/158 filter index: seeded genesis filter")
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Failed to seed genesis filter into index: {e}")

    def _index_genesis_coinstats(self):
        """Seed the coin-stats index with the genesis height (height 0).

        Bitcoin Core's CoinStatsIndex indexes the genesis block like any
        other, but the genesis coinbase output is provably unspendable and
        never enters the UTXO set, so the height-0 coinstats snapshot is the
        EMPTY set: txouts=0, total_amount=0, MuHash3072 of the empty multiset.
        ``add_block`` at height 0 computes exactly this (the genesis coinbase
        output is skipped by IsUnspendable on regtest/mainnet/testnet).

        The genesis is connected via :meth:`_init_genesis_block` but never
        routed through the block-connect index hook (heights >= 1 only), so
        seed it here.  Idempotent on restart; best-effort.
        """
        csi = self.coinstats_index
        if csi is None or self.db is None:
            return
        try:
            if csi.get_at_height(0) is not None:
                return
            genesis = self.db.get_block_by_height(0)
            if genesis is None:
                return
            csi.add_block(genesis, height=0, db=self.db)
            logger.info("coin-stats index: seeded genesis snapshot")
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Failed to seed genesis coinstats snapshot: {e}")

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
                        INV_TYPE_TX,
                        MSG_WTX,
                        InvMessage,
                        TxMessage,
                    )

                    tx_msg = TxMessage.from_payload(msg.payload)
                    tx = tx_msg.transaction

                    _, height = self.db.get_best_block()
                    # Off-load ATMP to a worker thread so the asyncio event
                    # loop stays responsive while script verification + UTXO
                    # lookups + ancestor/descendant graph walks run.  Without
                    # this, every inbound TxMsg blocks the loop for the
                    # ~50ms-3s duration of ``mempool.add_transaction`` —
                    # under a steady tx flood the LISTEN backlog on the RPC
                    # port (8359) fills up and the node appears unresponsive
                    # to curl/getblockcount even though it is alive.
                    # Mirrors camlcoin's #134/#135 fix (Validation_worker
                    # Domain for post-IBD blocks + Lwt.pause around ATMP).
                    # The Mempool already uses a re-entrant lock around the
                    # critical section, so dispatching from multiple worker
                    # threads is safe (only one ATMP can execute at a time).
                    # Attribute the orphan (if this tx turns out to be one) to
                    # the announcing peer so OrphanPool.erase_for_peer can drop
                    # it the instant the peer disconnects (Core EraseForPeer).
                    sender_addr = f"{sender_peer.host}:{sender_peer.port}"
                    success, error = await asyncio.to_thread(
                        self.mempool.add_transaction, tx, height, sender_addr,
                    )

                    if error == "orphan":
                        txid = tx.get_txid()
                        logger.debug(
                            f"Stored orphan tx {txid.hex()[:16]}... "
                            f"(missing parents)"
                        )
                    elif success:
                        txid = tx.get_txid()
                        wtxid = tx.get_wtxid()
                        logger.info(
                            f"Added transaction {txid.hex()[:16]}... to mempool"
                        )
                        if self.zmq_publisher:
                            self.zmq_publisher.notify_transaction(tx)

                        # Relay INV to all peers except the sender.
                        # BIP-339: wtxid-relay peers get MSG_WTX(5)+wtxid;
                        # legacy peers get MSG_TX(1)+txid.
                        if hasattr(self, "peer_manager") and self.peer_manager:
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
                                        if getattr(p, "wtxid_relay", False):
                                            inv = InvMessage(
                                                inventory=[(MSG_WTX, wtxid)]
                                            )
                                        else:
                                            inv = InvMessage(
                                                inventory=[(INV_TYPE_TX, txid)]
                                            )
                                        await p.send_message(
                                            inv.to_network_message(self.network)
                                        )
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
            """Handle getdata: respond with tx from mempool or block from db.

            BIP-159 peer-served-blocks gate: when prune mode is on, refuse
            to serve blocks below tip - 288 (NODE_NETWORK_LIMITED_MIN_BLOCKS).
            Mirrors Core's net_processing.cpp short-circuit; emits notfound
            rather than reading a possibly-deleted block file.
            """
            async def handler(msg):
                try:
                    from ouroboros.p2p_messages import (
                        INV_TYPE_BLOCK,
                        INV_TYPE_TX,
                        MSG_WITNESS_BLOCK,
                        MSG_WITNESS_TX,
                        GetDataMessage,
                        NotFoundMessage,
                        TxMessage,
                    )

                    getdata = GetDataMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')

                    # Compute prune horizon once for the whole batch.
                    MIN_BLOCKS_TO_KEEP = 288
                    prune_horizon = -1
                    if self.pruner is not None:
                        try:
                            _, best_h = self.db.get_best_block()
                            if best_h is not None and best_h > MIN_BLOCKS_TO_KEEP:
                                prune_horizon = best_h - MIN_BLOCKS_TO_KEEP
                        except Exception:
                            prune_horizon = -1

                    not_found = []
                    for inv_type, inv_hash in getdata.inventory:
                        if inv_type in (INV_TYPE_TX, MSG_WITNESS_TX) and self.mempool:
                            tx = self.mempool.get_transaction(inv_hash)
                            if tx:
                                tx_msg = TxMessage(transaction=tx)
                                await peer.send_message(tx_msg.to_network_message(network))
                                logger.debug(f"Sent tx {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                            else:
                                not_found.append((inv_type, inv_hash))
                        elif inv_type in (INV_TYPE_BLOCK, MSG_WITNESS_BLOCK):
                            # Off-load the full-block FFI deserialize
                            # (~1 MB PyO3 round-trip per call) to a worker
                            # thread.  Otherwise a peer requesting a
                            # batch of recent blocks holds the asyncio
                            # loop for hundreds of ms per block, starving
                            # RPC + other peer dispatch (the camlcoin
                            # #134 pattern in the block-serving direction).
                            block = await asyncio.to_thread(
                                self.db.get_block, inv_hash,
                            )
                            if block is not None and prune_horizon >= 0:
                                # Decline pre-prune-horizon blocks per BIP-159.
                                bh = getattr(block, 'height', None)
                                if bh is not None and bh < prune_horizon:
                                    not_found.append((inv_type, inv_hash))
                                    continue
                            if block:
                                # BIP144: a MSG_WITNESS_BLOCK getdata MUST be
                                # answered with the segwit (witness) block
                                # serialization.  The coinbase witness reserved
                                # value (nonce) is part of it, and a peer
                                # connecting the block runs
                                # CheckWitnessCommitment — which rejects
                                # "bad-witness-nonce-size" when the witness is
                                # stripped.  The Python Block round-trip drops
                                # witnesses (see Database.get_block_bytes), so
                                # BlockMessage(block).serialize() serves a
                                # witness-LESS block; this broke P2P block
                                # download from ouroboros (e.g. a peer fetching
                                # a competing fork's bodies for a reorg).  Prefer
                                # the stored raw consensus bytes (byte-exact,
                                # witness-preserving); fall back to an explicit
                                # witness serialization of the Block; only a
                                # legacy MSG_BLOCK request gets the stripped form.
                                from ouroboros.p2p_messages import BlockMessage
                                payload = None
                                if inv_type == MSG_WITNESS_BLOCK:
                                    payload = await asyncio.to_thread(
                                        self.db.get_block_bytes, inv_hash,
                                    )
                                    if payload is None:
                                        try:
                                            payload = block.serialize_with_witness()
                                        except Exception:
                                            payload = None
                                if payload is not None:
                                    from ouroboros.p2p_messages import (
                                        NetworkMessage, get_magic,
                                    )
                                    msg_out = NetworkMessage(
                                        command="block",
                                        payload=bytes(payload),
                                        magic=get_magic(network),
                                    )
                                    await peer.send_message(msg_out)
                                else:
                                    await peer.send_message(
                                        BlockMessage(block=block).to_network_message(network)
                                    )
                                logger.debug(f"Sent block {inv_hash.hex()[:16]}... to {peer.host}:{peer.port}")
                            else:
                                not_found.append((inv_type, inv_hash))

                    if not_found:
                        try:
                            nf_msg = NotFoundMessage(inventory=not_found)
                            await peer.send_message(nf_msg.to_network_message(network))
                        except Exception:
                            # NotFoundMessage may not exist in older builds; silently drop.
                            pass
                except Exception as e:
                    logger.error(f"Error handling getdata from {peer.host}:{peer.port}: {e}")

            return handler

        def _make_getheaders_handler(peer):
            """Handle getheaders: respond with headers from our chain."""
            async def handler(msg):
                try:
                    from ouroboros.p2p_messages import (
                        BlockHeader,
                        GetHeadersMessage,
                        HeadersMessage,
                    )

                    getheaders = GetHeadersMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')

                    # Find the fork point: walk through the locator hashes
                    # and find the first one we have in our chain.
                    # Off-load each FFI get_block to a worker thread —
                    # a long locator can otherwise stall the loop for
                    # tens of ms per probe.
                    start_height = 0
                    for locator_hash in getheaders.locator_hashes:
                        block = await asyncio.to_thread(
                            self.db.get_block, locator_hash,
                        )
                        if block is not None:
                            start_height = (block.height if block.height else 0) + 1
                            break

                    # Collect up to 2000 headers starting from start_height.
                    # Each db.get_block_by_height call is a full Rust-side
                    # block materialise + PyO3 deserialise; serving the
                    # max 2000-block batch synchronously holds the event
                    # loop for several seconds and is the most expensive
                    # single P2P handler.  Run inside a worker thread so
                    # RPC + other peer dispatch continues meanwhile.
                    _, best_height = self.db.get_best_block()
                    headers = []
                    for h in range(start_height, min(start_height + 2000, best_height + 1)):
                        block = await asyncio.to_thread(
                            self.db.get_block_by_height, h,
                        )
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

        # BIP 157/158 — getcfilters / getcfheaders / getcfcheckpt handlers.
        # Active only when the node has --blockfilterindex enabled (the
        # constructor in start() leaves block_filter_index = None when the
        # flag is off, in which case we skip handler registration entirely
        # so peers do not see NODE_COMPACT_FILTERS or any cfilter response).
        def _peer_disconnect(peer_obj, reason: str) -> None:
            """Disconnect a peer for BIP-157 protocol violation.

            Mirrors Bitcoin Core PrepareBlockFilterRequest which sets
            ``node.fDisconnect = true`` for all protocol errors:
            unsupported filter type, unknown stop_hash, out-of-range
            heights.  See net_processing.cpp:3268-3303.
            """
            logger.debug(
                f"Disconnecting peer {peer_obj.host}:{peer_obj.port} "
                f"(BIP-157 violation: {reason})"
            )
            if hasattr(peer_obj, 'disconnect'):
                try:
                    peer_obj.disconnect()
                except Exception:
                    pass

        def _make_getcfilters_handler(peer):
            async def handler(msg):
                try:
                    from ouroboros.blockfilter import (
                        BASIC_FILTER_TYPE,
                        build_basic_filter,
                        compute_filter_header,
                    )
                    from ouroboros.p2p_messages import (
                        MAX_GETCFILTERS_SIZE,
                        CFilterMessage,
                        GetCFiltersMessage,
                    )

                    req = GetCFiltersMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')
                    # Core: disconnect peer for unsupported filter type
                    # (net_processing.cpp:3268-3276).
                    if req.filter_type != BASIC_FILTER_TYPE:
                        _peer_disconnect(peer, f"unsupported filter_type={req.filter_type}")
                        return
                    stop_block = self.db.get_block(req.stop_hash)
                    # Core: disconnect if stop_hash unknown (net_processing.cpp:3283-3288).
                    if stop_block is None or stop_block.height is None:
                        _peer_disconnect(peer, f"unknown stop_hash={req.stop_hash.hex()}")
                        return
                    stop_height = stop_block.height
                    # Core: disconnect for out-of-range / too-large requests
                    # (net_processing.cpp:3292-3303).
                    if req.start_height > stop_height:
                        _peer_disconnect(
                            peer,
                            f"start_height={req.start_height} > stop_height={stop_height}",
                        )
                        return
                    if stop_height - req.start_height >= MAX_GETCFILTERS_SIZE:
                        _peer_disconnect(
                            peer,
                            f"range {stop_height - req.start_height + 1} > MAX_GETCFILTERS_SIZE",
                        )
                        return
                    bfi = self.block_filter_index
                    # FIX-75 / W121 #3: walk from stop_block via prev_blockhash
                    # (Core CBlockIndex::GetAncestor) rather than
                    # db.get_block_by_height which walks the active chain.
                    # Compact filters are indexed by block hash regardless of
                    # fork membership; an orphan stop_hash gets the filters
                    # from its fork, not the active-chain block at the same
                    # height.  See net_processing.cpp PrepareBlockFilterRequest
                    # — no chain.Contains check.
                    for h in range(req.start_height, stop_height + 1):
                        ancestor = _get_ancestor(self.db, stop_block, h)
                        if ancestor is None:
                            # Mirror Core: abort the entire response on any
                            # ancestor-walk failure (LookupFilterRange returns
                            # false → handler returns silently).
                            return
                        block_hash = ancestor.hash
                        filter_bytes: bytes | None = None
                        if bfi is not None:
                            filter_bytes = bfi.get_filter(block_hash)
                        if filter_bytes is None:
                            blk = self.db.get_block(block_hash)
                            if blk is None:
                                # Core: LookupFilterRange returns false on
                                # first miss; handler aborts whole response
                                # (net_processing.cpp:3333-3337) — abort
                                # cleanly, do not emit a partial cfilter
                                # stream.  (FIX-75 incidental closure of
                                # W121 BUG-3 from the stop-hash-ancestor
                                # refactor.)
                                return
                            filter_bytes = await asyncio.to_thread(
                                build_basic_filter, blk, self.db,
                            )
                        out = CFilterMessage(
                            filter_type=BASIC_FILTER_TYPE,
                            block_hash=block_hash,
                            filter_bytes=filter_bytes,
                        )
                        await peer.send_message(out.to_network_message(network))
                    # silence unused-import warning when prev_header path
                    # not exercised; reserved for future header-only stub.
                    _ = compute_filter_header
                except Exception as e:
                    logger.error(
                        f"Error handling getcfilters from "
                        f"{peer.host}:{peer.port}: {e}"
                    )

            return handler

        def _make_getcfheaders_handler(peer):
            async def handler(msg):
                try:
                    from ouroboros.blockfilter import (
                        BASIC_FILTER_TYPE,
                        build_basic_filter,
                        compute_filter_hash,
                        compute_filter_header,
                    )
                    from ouroboros.p2p_messages import (
                        MAX_GETCFHEADERS_SIZE,
                        CFHeadersMessage,
                        GetCFHeadersMessage,
                    )

                    req = GetCFHeadersMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')
                    # Core: disconnect peer for unsupported filter type
                    # (net_processing.cpp:3268-3276).
                    if req.filter_type != BASIC_FILTER_TYPE:
                        _peer_disconnect(peer, f"unsupported filter_type={req.filter_type}")
                        return
                    stop_block = self.db.get_block(req.stop_hash)
                    # Core: disconnect if stop_hash unknown (net_processing.cpp:3283-3288).
                    if stop_block is None or stop_block.height is None:
                        _peer_disconnect(peer, f"unknown stop_hash={req.stop_hash.hex()}")
                        return
                    stop_height = stop_block.height
                    # Core: disconnect for out-of-range / too-large requests
                    # (net_processing.cpp:3292-3303).
                    if req.start_height > stop_height:
                        _peer_disconnect(
                            peer,
                            f"start_height={req.start_height} > stop_height={stop_height}",
                        )
                        return
                    if stop_height - req.start_height >= MAX_GETCFHEADERS_SIZE:
                        _peer_disconnect(
                            peer,
                            f"range {stop_height - req.start_height + 1} > MAX_GETCFHEADERS_SIZE",
                        )
                        return
                    bfi = self.block_filter_index

                    # FIX-75 / W121 #3: resolve the previous-filter-header
                    # block via the ancestor walk anchored at stop_block, NOT
                    # via db.get_block_by_height (which walks the active
                    # chain).  When the peer's stop_hash is on a stale fork,
                    # the prev block at (start_height - 1) on that fork can
                    # differ from the active-chain block at the same height;
                    # serving the active-chain prev_filter_header would
                    # produce a signed-but-lying response.
                    #
                    # FIX-79 / W121 BUG-4 (G28): when start_height > 0 and we
                    # cannot look up the prev block's filter header (either
                    # the ancestor walk fails, or bfi.get_header() returns
                    # None because the block was removed from the index by
                    # FIX-74's reorg-disconnect hook), do NOT fall back to
                    # the all-zeros sentinel — that would produce a wire-
                    # valid cfheaders message rooted at a fake genesis,
                    # indistinguishable on the wire from an honest response
                    # until a light client cross-checks against another peer.
                    # Mirrors Bitcoin Core's ProcessGetCFHeaders behavior
                    # (net_processing.cpp:3361-3369): on LookupFilterHeader
                    # failure, log and return WITHOUT sending a response.
                    # The peer will time out and retry — typically from
                    # another peer who has the orphan block indexed.
                    prev_filter_header = b'\x00' * 32
                    if req.start_height > 0:
                        prev_ancestor = _get_ancestor(
                            self.db, stop_block, req.start_height - 1,
                        )
                        if prev_ancestor is None or bfi is None:
                            # prev_filter_header is None — abort getcfheaders
                            # without sending a response (Core parity).
                            logger.debug(
                                f"getcfheaders: no prev_filter_header for "
                                f"start_height={req.start_height} on fork "
                                f"stop_hash={req.stop_hash.hex()[:16]}... — "
                                f"ancestor walk failed; not responding"
                            )
                            return
                        ph = bfi.get_header(prev_ancestor.hash)
                        if ph is None:
                            # prev_filter_header is None — bfi.get_header miss
                            # on the orphan-fork prev block.  Abort without
                            # zero-fallback (Core ProcessGetCFHeaders +
                            # LookupFilterHeader at net_processing.cpp:3365).
                            logger.debug(
                                f"getcfheaders: no prev_filter_header for "
                                f"prev_block="
                                f"{prev_ancestor.hash.hex()[:16]}... at "
                                f"height={req.start_height - 1} — bfi "
                                f"index miss (orphan fork or unsynced); "
                                f"not responding"
                            )
                            return
                        prev_filter_header = ph

                    filter_hashes: list[bytes] = []
                    for h in range(req.start_height, stop_height + 1):
                        # FIX-75 / W121 #3: walk from stop_block via
                        # prev_blockhash rather than active-chain
                        # get_block_by_height.  See _get_ancestor docstring.
                        ancestor = _get_ancestor(self.db, stop_block, h)
                        if ancestor is None:
                            # Core: LookupFilterHashesRange returns false on
                            # any miss; handler returns silently
                            # (net_processing.cpp:3371-3376).
                            return
                        block_hash = ancestor.hash
                        filt: bytes | None = None
                        if bfi is not None:
                            filt = bfi.get_filter(block_hash)
                        if filt is None:
                            blk = self.db.get_block(block_hash)
                            if blk is None:
                                return
                            filt = await asyncio.to_thread(
                                build_basic_filter, blk, self.db,
                            )
                        filter_hashes.append(compute_filter_hash(filt))

                    out = CFHeadersMessage(
                        filter_type=BASIC_FILTER_TYPE,
                        stop_hash=req.stop_hash,
                        previous_filter_header=prev_filter_header,
                        filter_hashes=filter_hashes,
                    )
                    await peer.send_message(out.to_network_message(network))
                    _ = compute_filter_header
                except Exception as e:
                    logger.error(
                        f"Error handling getcfheaders from "
                        f"{peer.host}:{peer.port}: {e}"
                    )

            return handler

        def _make_getcfcheckpt_handler(peer):
            async def handler(msg):
                try:
                    from ouroboros.blockfilter import BASIC_FILTER_TYPE
                    from ouroboros.p2p_messages import (
                        CFCHECKPT_INTERVAL,
                        CFCheckptMessage,
                        GetCFCheckptMessage,
                    )

                    req = GetCFCheckptMessage.from_payload(msg.payload)
                    network = getattr(peer, 'network', 'mainnet')
                    # Core: disconnect peer for unsupported filter type
                    # (net_processing.cpp:3268-3276).
                    if req.filter_type != BASIC_FILTER_TYPE:
                        _peer_disconnect(peer, f"unsupported filter_type={req.filter_type}")
                        return
                    stop_block = self.db.get_block(req.stop_hash)
                    # Core: disconnect if stop_hash unknown (net_processing.cpp:3283-3288).
                    # getcfcheckpt uses max_height_diff=UINT32_MAX so no range limit.
                    if stop_block is None or stop_block.height is None:
                        _peer_disconnect(peer, f"unknown stop_hash={req.stop_hash.hex()}")
                        return
                    stop_height = stop_block.height
                    bfi = self.block_filter_index

                    # FIX-75 / W121 #3: walk from stop_block via prev_blockhash
                    # rather than bfi.get_block_hash_by_height (active-chain
                    # mapping).  Checkpoints must come from the stop_hash's
                    # fork, not the active chain — see net_processing.cpp
                    # ProcessGetCFCheckPt which calls LookupFilterHeader on
                    # stop_index->GetAncestor(...).
                    headers: list[bytes] = []
                    n_checkpoints = stop_height // CFCHECKPT_INTERVAL
                    for i in range(1, n_checkpoints + 1):
                        h = i * CFCHECKPT_INTERVAL
                        if bfi is None:
                            return
                        ancestor = _get_ancestor(self.db, stop_block, h)
                        if ancestor is None:
                            return
                        ph = bfi.get_header(ancestor.hash)
                        if ph is None:
                            return
                        headers.append(ph)

                    out = CFCheckptMessage(
                        filter_type=BASIC_FILTER_TYPE,
                        stop_hash=req.stop_hash,
                        filter_headers=headers,
                    )
                    await peer.send_message(out.to_network_message(network))
                except Exception as e:
                    logger.error(
                        f"Error handling getcfcheckpt from "
                        f"{peer.host}:{peer.port}: {e}"
                    )

            return handler

        # Register cfilter handlers on every peer (always — so an external
        # peer that wrongly probes us still gets a non-crashing response).
        # The handlers themselves no-op cleanly when the index is disabled.
        cfilter_enabled = self.block_filter_index is not None

        if hasattr(self.peer_manager, 'get_all_ready_peers'):
            peers = self.peer_manager.get_all_ready_peers()
            for peer in peers:
                if hasattr(peer, 'register_handler'):
                    peer.register_handler("tx", _make_tx_handler(peer))
                    peer.register_handler("getdata", _make_getdata_handler(peer))
                    peer.register_handler("getheaders", _make_getheaders_handler(peer))
                    if cfilter_enabled:
                        peer.register_handler("getcfilters", _make_getcfilters_handler(peer))
                        peer.register_handler("getcfheaders", _make_getcfheaders_handler(peer))
                        peer.register_handler("getcfcheckpt", _make_getcfcheckpt_handler(peer))

        # Register callback for future inbound peers so they get handlers too
        async def _on_inbound_peer(peer):
            peer.register_handler("tx", _make_tx_handler(peer))
            peer.register_handler("getdata", _make_getdata_handler(peer))
            peer.register_handler("getheaders", _make_getheaders_handler(peer))
            if cfilter_enabled:
                peer.register_handler("getcfilters", _make_getcfilters_handler(peer))
                peer.register_handler("getcfheaders", _make_getcfheaders_handler(peer))
                peer.register_handler("getcfcheckpt", _make_getcfcheckpt_handler(peer))

        self.peer_manager.set_inbound_peer_handler(_on_inbound_peer)

        # Mirror the same wiring on every newly-dialed outbound peer.  Without
        # this hook, post-startup outbound peers (full-relay dials picked from
        # addrman, anchors, addnode, block-relay-only) silently dropped tx /
        # getdata / getheaders messages because handlers were only registered
        # for peers already connected when _register_handlers() ran (typically
        # only the --connect peers).  See PARITY-MATRIX.md Category B.
        if hasattr(self.peer_manager, "set_outbound_peer_handler"):
            async def _on_outbound_peer(peer):
                peer.register_handler("tx", _make_tx_handler(peer))
                peer.register_handler("getdata", _make_getdata_handler(peer))
                peer.register_handler("getheaders", _make_getheaders_handler(peer))
                if cfilter_enabled:
                    peer.register_handler("getcfilters", _make_getcfilters_handler(peer))
                    peer.register_handler("getcfheaders", _make_getcfheaders_handler(peer))
                    peer.register_handler("getcfcheckpt", _make_getcfcheckpt_handler(peer))

            self.peer_manager.set_outbound_peer_handler(_on_outbound_peer)

        logger.info("Transaction, getdata, and getheaders handlers registered")

    def is_synced(self) -> bool:
        """Return True when the node has completed initial block synchronisation."""
        return self.synced

    def _active_chain_tip_height(self) -> int | None:
        """Return the active chain tip height, or ``None`` if unknown.

        Used by the NODE_COMPACT_FILTERS sync gate (FIX-71).  We prefer
        the database's best-block height because it reflects the
        connected chain; the sync_manager's notion of "synced" is a
        higher-level "caught up to network tip" check that we don't want
        to entangle here.
        """
        try:
            if self.db is None:
                return None
            _, height = self.db.get_best_block()
            if height is None:
                return None
            return int(height)
        except Exception:
            return None

    def _compact_filters_advertised(self) -> bool:
        """NODE_COMPACT_FILTERS service-bit predicate (FIX-71 / W121 BUG-5).

        Mirrors Bitcoin Core ``init.cpp`` (``-blockfilterindex`` flag) +
        ``BaseIndex::IsSynced`` (``m_synced`` reaches True only when the
        index thread has caught up to the active chain tip).

        Returns False when:
          - ``-blockfilterindex`` is disabled (no index in memory),
          - the index has never observed a block (fresh datadir),
          - the index's best_indexed_height < active chain tip
            (mid-IBD or rewinding through a reorg).

        Invoked by ``Peer._should_advertise_node_compact_filters`` on
        every version handshake (outbound dial + inbound accept), so a
        peer that was constructed before sync correctly observes the
        flipped state once the index catches up.
        """
        bfi = self.block_filter_index
        if bfi is None:
            return False
        tip_height = self._active_chain_tip_height()
        if tip_height is None:
            return False
        try:
            return bool(bfi.is_synced(tip_height))
        except Exception:
            # Defensive: never raise out of a handshake-time predicate.
            return False

    def _bits_to_difficulty(self, bits: int) -> float | int:
        """Convert compact target (bits) to difficulty.

        Returns an int when the difficulty is a whole number (e.g. genesis = 1),
        matching Bitcoin Core's JSON output which uses C++ double → UniValue
        serialization that emits ``1`` not ``1.0`` for integral values.
        Reference: bitcoin-core/src/rpc/blockchain.cpp GetDifficulty.
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

        # Return int when the value has no fractional part, mirroring Core's
        # double → JSON serialization which outputs "1" not "1.0".
        if d_diff == int(d_diff):
            return int(d_diff)
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

    def get_median_time(self, height: int | None = None) -> int:
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

    @property
    def _chainwork_snapshot_offset(self) -> int:
        """Return the chainwork correction offset for snapshot-loaded datadirs.

        When a node is bootstrapped from an assumeutxo snapshot, blocks
        connected after the snapshot start accumulate chainwork relative to 0
        instead of relative to the snapshot height's correct chainwork. This
        method computes the correction needed: the correct cumulative chainwork
        at the snapshot height (from Core's hardcoded assumeutxo data).

        Returns 0 if no snapshot was loaded or if the snapshot's chainwork is
        not available.
        """
        if not hasattr(self, "_chainwork_offset_cache"):
            from ouroboros.snapshot import detect_snapshot_chainwork_offset
            network = getattr(self, "network", "mainnet")
            self._chainwork_offset_cache = detect_snapshot_chainwork_offset(
                self.db, network
            )
        return self._chainwork_offset_cache

    def _calculate_chainwork_at_height(self, height: int) -> int:
        """Calculate cumulative chainwork up to height."""
        if not self.db:
            return 0

        try:
            # Prefer persisted chainwork from Rust BlockMetadata (computed during sync)
            persisted_chainwork = self.db.get_chainwork_by_height(height)
            if persisted_chainwork > 0:
                # Apply snapshot correction offset if needed.  When a node was
                # bootstrapped from an assumeutxo snapshot, the stored chainwork
                # was computed from 0 (not from the snapshot height's cumulative
                # work). The offset corrects this by adding the canonical
                # chainwork at the snapshot height to every stored value.
                offset = self._chainwork_snapshot_offset
                return persisted_chainwork + offset

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
        """Return cumulative chain work at the tip as a 64-char lowercase hex string.

        Bitcoin Core format: 64 lowercase hex characters, zero-padded, no "0x" prefix.
        Reference: bitcoin-core/src/rpc/blockchain.cpp GetBlockchainInfo.
        """
        if not self.db:
            return "0" * 64

        try:
            _, best_height = self.db.get_best_block()
            chainwork = self._calculate_chainwork_at_height(best_height)
            return f"{chainwork:064x}"
        except Exception as e:
            logger.error(f"Error getting chainwork: {e}", exc_info=True)
            return "0" * 64

    def get_confirmations(self, height: int) -> int:
        """Return the number of confirmations for a block at *height*."""
        if not self.db:
            return 0

        try:
            _, best_height = self.db.get_best_block()
            return max(0, best_height - height + 1)
        except Exception:
            return 0

    def get_difficulty(self, bits: int) -> float:
        """Convert compact *bits* target to difficulty."""
        return self._bits_to_difficulty(bits)

    def get_chainwork_at_height(self, height: int) -> str:
        """Return cumulative chain work up to *height* as a 64-char lowercase hex string.

        Bitcoin Core format: 64 lowercase hex characters, zero-padded, no "0x" prefix.
        Reference: bitcoin-core/src/rpc/blockchain.cpp GetBlockchainInfo / getblockheader.
        """
        if not self.db:
            return "0" * 64

        try:
            chainwork = self._calculate_chainwork_at_height(height)
            return f"{chainwork:064x}"
        except Exception as e:
            logger.error(f"Error getting chainwork at height {height}: {e}", exc_info=True)
            return "0" * 64

    async def run(self) -> None:
        """Start the node and block until shutdown (convenience wrapper for ``start()``)."""
        try:
            await self.start()
        finally:
            # Ensure clean shutdown (cookie deletion, DB flush, etc.) even
            # when start() returns normally after _main_loop exits.
            await self.stop()
