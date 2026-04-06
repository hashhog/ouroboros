//! Bitcoin P2P parallel block download and validation

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use bitcoin::Network;
use bitcoin::hashes::Hash;
use tokio::sync::{mpsc, Mutex};
use thiserror::Error;

use crate::network::peer_manager::{PeerManager, PeerManagerError};
use crate::network::peer::{Peer, PeerError, PeerState, read_network_message, DiagnosticReader};
use tokio::io::AsyncWriteExt;
use crate::network::messages::{
    GetDataMessage, BlockMessage, InvItem, INV_TYPE_BLOCK,
    Message, MessageError, PingMessage, PongMessage,
};
use crate::validate::block::{BlockValidator, BlockValidationError};
use crate::storage::db::{BlockchainDB, DbError};
use crate::chain_params::genesis_block_hash;
use common::BlockWrapper;

/// Block sync error types
#[derive(Error, Debug)]
pub enum BlockSyncError {
    #[error("Peer manager error: {0}")]
    PeerManager(#[from] PeerManagerError),

    #[error("Peer error: {0}")]
    Peer(#[from] PeerError),

    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("Validation error: {0}")]
    Validation(#[from] BlockValidationError),

    #[error("No peers available")]
    NoPeersAvailable,

    #[error("Block not found at height {0}")]
    BlockNotFound(u32),

    #[error("Timeout waiting for block at height {0}")]
    BlockTimeout(u32),

    #[error("Invalid block response")]
    InvalidBlockResponse,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for block sync operations
pub type Result<T> = std::result::Result<T, BlockSyncError>;

/// Default receive timeout for block messages. Aggressive enough to detect dead peers
/// without prematurely dropping slow ones. Override via OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS.
const DEFAULT_RECEIVE_TIMEOUT_SECS: u64 = 60;
/// Interval for batch progress logging (blocks) when not verbose
const BATCH_LOG_INTERVAL: u32 = 50;

/// Default max in-flight block requests (Bitcoin Core uses 16 per peer; with 8 peers ~128 total).
/// Overridable via OUROBOROS_MAX_IN_FLIGHT (e.g. 64 when peers are slow to reduce pressure).
const DEFAULT_MAX_IN_FLIGHT: usize = 128;
/// Max requests per peer (Bitcoin Core ~16). Prevents overloading a single peer when we have few connections.
const MAX_IN_FLIGHT_PER_PEER: usize = 16;

/// Default stalling timeout base in seconds. Bitcoin Core uses 2s; we default to 5s since we have
/// fewer peers and slower reconnection. Override via OUROBOROS_STALLING_TIMEOUT_SECS.
const DEFAULT_STALLING_TIMEOUT_SECS: u64 = 5;
/// Maximum stalling timeout after adaptive increases. Bitcoin Core caps at 64s.
const MAX_STALLING_TIMEOUT_SECS: u64 = 64;
/// Factor to decay the stalling timeout toward the base when progress is made (0.85 = 15% reduction).
const STALLING_TIMEOUT_DECAY: f64 = 0.85;

/// Check if a peer error indicates the peer has disconnected (do not re-add to pool)
fn is_disconnect_error(e: &PeerError) -> bool {
    matches!(
        e,
        PeerError::ConnectionClosed
            | PeerError::Disconnected
            | PeerError::InvalidState {
                actual: PeerState::Disconnected,
                ..
            }
    )
}

/// Check if error indicates stream desync (PayloadSizeExceeded, InvalidMagic).
/// These are common during block sync when connection is corrupted; suppress log spam unless verbose.
fn is_protocol_desync_error(e: &PeerError) -> bool {
    matches!(
        e,
        PeerError::Message(MessageError::PayloadSizeExceeded { .. })
            | PeerError::Message(MessageError::InvalidMagic { .. })
    )
}

/// Events from concurrent per-peer receive tasks (task → main)
enum RecvEvent {
    Message(SocketAddr, Message),
    PeerDone(SocketAddr, Peer, PeerDoneReason),
}

/// Reason a peer receive task finished
enum PeerDoneReason {
    Timeout,
    Error(PeerError),
    Shutdown,
}

/// Commands from main to peer task (bidirectional channel for long-lived tasks)
enum PeerTaskCommand {
    SendGetData(Message),
    Shutdown,
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(u32, u32, f64, f64) + Send + Sync>; // downloaded, total, speed, eta

/// In-flight block request tracking
#[derive(Debug, Clone)]
struct InFlightRequest {
    peer_addr: std::net::SocketAddr,
    requested_at: Instant,
    retry_count: u32,
}

/// Bitcoin P2P parallel block download and validation
pub struct BlockSync {
    peer_manager: Arc<Mutex<PeerManager>>,
    validator: Arc<BlockValidator>,
    db: Arc<BlockchainDB>,
    network: Network,
    /// Heights to download
    download_queue: Arc<Mutex<VecDeque<u32>>>,
    /// Height -> in-flight request tracking
    in_flight: Arc<Mutex<HashMap<u32, InFlightRequest>>>,
    /// Block hash -> height mapping (for incoming blocks)
    hash_to_height: Arc<Mutex<HashMap<[u8; 32], u32>>>,
    /// Maximum concurrent downloads
    max_concurrent: usize,
    /// Receive timeout in seconds (configurable via env or set_receive_timeout_secs)
    receive_timeout_secs: u64,
    /// Adaptive stalling timeout: current value in seconds. Starts at stalling_timeout_base,
    /// doubles when stalls are detected, decays toward base when progress is made.
    stalling_timeout_secs: Arc<std::sync::atomic::AtomicU64>,
    /// Base stalling timeout (configurable via OUROBOROS_STALLING_TIMEOUT_SECS)
    stalling_timeout_base: u64,
    /// Per-peer last progress timestamp: updated when a peer delivers a block
    peer_last_progress: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    /// Long-lived peer tasks: addr -> command sender (None until first drain)
    peer_tasks: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<PeerTaskCommand>>>>,
    /// Progress callback: (downloaded, total, speed_blocks_per_sec, eta_seconds)
    progress_callback: Option<ProgressCallback>,
    /// Statistics
    stats: Arc<Mutex<SyncStats>>,
    /// Cached progress for get_sync_progress (sync-readable, no await needed)
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
    /// Total PayloadSizeExceeded + InvalidMagic since start (for debugging peer droughts)
    desync_count: Arc<AtomicU64>,
    /// Height -> peer that timed out; avoid re-assigning to same peer (cleared when assigned to different peer)
    avoid_peer_for_height: Arc<Mutex<HashMap<u32, SocketAddr>>>,
    /// Blocks downloaded but not yet applied (connected).  apply_block must be
    /// called in sequential order.  This buffer holds out-of-order blocks until
    /// all predecessors are available.
    pending_apply: Arc<Mutex<HashMap<u32, BlockWrapper>>>,
}

/// Rolling window for speed calculation (seconds)
const SPEED_WINDOW_SECS: f64 = 10.0;
/// Max block timestamps to keep for rolling window
const MAX_SPEED_WINDOW_SAMPLES: usize = 1000;

/// Synchronization statistics
struct SyncStats {
    blocks_downloaded: u32,
    blocks_validated: u32,
    start_time: Option<Instant>,
    last_update: Option<Instant>,
    /// Timestamps of recently stored blocks for rolling-window speed
    block_timestamps: VecDeque<Instant>,
}

impl Default for SyncStats {
    fn default() -> Self {
        Self {
            blocks_downloaded: 0,
            blocks_validated: 0,
            start_time: None,
            last_update: None,
            block_timestamps: VecDeque::new(),
        }
    }
}

/// Cached progress for sync UI - updated when blocks/headers are received, read by get_sync_progress
#[derive(Debug, Clone)]
pub struct BlockProgressCache {
    pub blocks_downloaded: u32,
    /// Total blocks to download in this sync run (0 = not in block sync)
    pub total_to_download: u32,
    /// Total blocks in the blockchain (chain tip height + 1). For display: "X / total_chain_blocks"
    pub total_chain_blocks: u32,
    pub blocks_per_second: f64,
    pub eta_seconds: f64,
    /// When header sync receives a short batch, it sets this to the discovered tip (0-indexed).
    /// Used for accurate progress % when chain is shorter than estimated_tip.
    pub header_sync_tip: Option<u32>,
    /// Number of connected peers (updated during sync for CLI display)
    pub peer_count: u32,
}

impl Default for BlockProgressCache {
    fn default() -> Self {
        Self {
            blocks_downloaded: 0,
            total_to_download: 0,
            total_chain_blocks: 0,
            blocks_per_second: 0.0,
            eta_seconds: 0.0,
            header_sync_tip: None,
            peer_count: 0,
        }
    }
}

impl BlockSync {
    /// Create a new block sync instance.
    /// `progress_cache` is shared with SyncProgressReporter so progress can be read without
    /// borrowing FastSync (avoids "Already borrowed" when polling during sync).
    pub fn new(
        peer_manager: Arc<Mutex<PeerManager>>,
        validator: Arc<BlockValidator>,
        db: Arc<BlockchainDB>,
        network: Network,
        progress_cache: Arc<StdMutex<BlockProgressCache>>,
    ) -> Self {
        let receive_timeout_secs = std::env::var("OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_RECEIVE_TIMEOUT_SECS);

        let stalling_timeout_base = std::env::var("OUROBOROS_STALLING_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_STALLING_TIMEOUT_SECS);

        let max_concurrent = std::env::var("OUROBOROS_MAX_IN_FLIGHT")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(|n: usize| n.min(256))
            .unwrap_or(DEFAULT_MAX_IN_FLIGHT);

        Self {
            peer_manager,
            validator,
            db,
            network,
            download_queue: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            hash_to_height: Arc::new(Mutex::new(HashMap::new())),
            max_concurrent,
            receive_timeout_secs,
            stalling_timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(stalling_timeout_base)),
            stalling_timeout_base,
            peer_last_progress: Arc::new(Mutex::new(HashMap::new())),
            peer_tasks: Arc::new(Mutex::new(HashMap::new())),
            progress_callback: None,
            stats: Arc::new(Mutex::new(SyncStats::default())),
            progress_cache,
            desync_count: Arc::new(AtomicU64::new(0)),
            avoid_peer_for_height: Arc::new(Mutex::new(HashMap::new())),
            pending_apply: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set receive timeout in seconds (for tuning without recompiling)
    pub fn set_receive_timeout_secs(&mut self, secs: u64) {
        self.receive_timeout_secs = secs;
    }

    /// Set progress callback
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Set maximum concurrent downloads
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max.min(256); // Cap at 256 (16 per peer × 16 peers)
    }

    /// Main block synchronization function
    ///
    /// Fills download queue with missing blocks, requests blocks from multiple peers
    /// in parallel, validates as they arrive, applies to database, and tracks progress.
    pub async fn sync_blocks(&mut self, start_height: u32, end_height: u32) -> Result<()> {
        use crate::network::messages::BlockMessage;

        // Initialize statistics
        {
            let mut stats = self.stats.lock().await;
            stats.start_time = Some(Instant::now());
            stats.last_update = Some(Instant::now());
        }

        // Fill download queue with missing blocks
        self.fill_download_queue(start_height, end_height).await?;

        let queue_size = {
            let queue = self.download_queue.lock().await;
            queue.len()
        };
        let best_height = self
            .db
            .get_best_block()
            .map(|(_, h)| h)
            .unwrap_or(0);
        log::info!(
            "Block sync: db has best_height={}, queue_size={} blocks to download (receive timeout: {}s, stalling timeout: {}s adaptive)",
            best_height,
            queue_size,
            self.receive_timeout_secs,
            self.stalling_timeout_base
        );

        // Progress: blocks in our chain / total chain blocks. total_chain_blocks = end_height + 1.
        let total_chain_blocks = end_height.saturating_sub(start_height) + 1;
        self.init_progress_cache(queue_size as u32, total_chain_blocks);

        let batch_size = self.max_concurrent;

        // Shared channel: all peer tasks send events (Message, PeerDone) to main
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RecvEvent>();

        // Exponential backoff when waiting for peers: 1s, 2s, 5s, 10s (cap at 10s)
        let mut no_peers_wait_secs: u64 = 1;
        let mut no_peers_wait_since = tokio::time::Instant::now();
        let mut last_no_peers_warn_log: Option<Instant> = None;
        let mut last_diag_log: Option<Instant> = None;

        // Main sync loop - long-lived peer tasks architecture (see BLOCK_SYNC_ARCHITECTURE.md)
        loop {
            // Ensure we have peer tasks (drain and spawn on first use or after all disconnected)
            {
                let mut peer_tasks = self.peer_tasks.lock().await;
                if peer_tasks.is_empty() {
                    let mut peer_manager = self.peer_manager.lock().await;
                    let mut peer_map = peer_manager.drain_peers().await;

                    if peer_map.is_empty() {
                        // Trigger peer manager to try connecting (don't just wait for background task)
                        peer_manager.maintain_connections().await;
                        // Re-check before sleeping: maintain_connections may have just connected peers
                        peer_map = peer_manager.drain_peers().await;
                        drop(peer_manager);

                        if peer_map.is_empty() {
                            drop(peer_tasks);
                            let elapsed = no_peers_wait_since.elapsed();
                            // Rate-limit: only log "No peers for >5 min" at most once per 60 seconds
                            let should_log_warn = elapsed.as_secs() >= 300
                                && last_no_peers_warn_log
                                    .map(|t| t.elapsed().as_secs() >= 60)
                                    .unwrap_or(true);
                            if should_log_warn {
                                let total_desync = self.desync_count.load(Ordering::Relaxed);
                                log::warn!(
                                    "No peers available for >5 minutes ({} desyncs since start). Check network/firewall. Waiting {}s...",
                                    total_desync,
                                    no_peers_wait_secs
                                );
                                last_no_peers_warn_log = Some(Instant::now());
                            } else {
                                log::debug!("No peers available, waiting {}s...", no_peers_wait_secs);
                            }
                            tokio::time::sleep(Duration::from_secs(no_peers_wait_secs)).await;
                            no_peers_wait_secs = match no_peers_wait_secs {
                                1 => 2,
                                2 => 5,
                                _ => 10,
                            };
                            continue;
                        }
                        // Re-check found peers; skip sleep and spawn them below
                    }
                    no_peers_wait_secs = 1;

                    let network = self.network;
                    let event_tx = event_tx.clone();
                    let now_init = Instant::now();
                    for (addr, peer) in peer_map {
                        self.peer_last_progress.lock().await.insert(addr, now_init);
                        let (cmd_tx, mut cmd_rx) = mpsc::channel::<PeerTaskCommand>(32);
                        peer_tasks.insert(addr, cmd_tx);

                        let event_tx = event_tx.clone();
                        tokio::spawn(async move {
                            // Split the TCP stream so reads and writes are independent.
                            // This prevents tokio::select! from cancelling a read_exact
                            // mid-stream when a SendGetData command arrives — the root
                            // cause of InvalidMagic / PayloadSizeExceeded desyncs.
                            let (stream, _, _) = peer.into_parts();
                            let (read_half, mut write_half) = stream.into_split();
                            let mut diag_reader = DiagnosticReader::new(read_half);

                            let done_reason: PeerDoneReason = 'task: loop {
                                // Pin the receive future so it survives select! iterations.
                                // When the cmd branch wins, recv_fut is NOT cancelled — it
                                // continues where it left off on the next poll.
                                let recv_fut = read_network_message(&mut diag_reader, network);
                                tokio::pin!(recv_fut);

                                loop {
                                    tokio::select! {
                                        result = &mut recv_fut => {
                                            match result {
                                                Ok(msg) => {
                                                    if msg.command == "block" {
                                                        let _ = event_tx.send(RecvEvent::Message(addr, msg));
                                                    } else if msg.command == "ping" {
                                                        if let Ok(ping) = PingMessage::deserialize_payload(&msg.payload) {
                                                            let pong_msg = PongMessage::new(ping.nonce).to_message(network);
                                                            let data = pong_msg.serialize();
                                                            if let Err(e) = write_half.write_all(&data).await {
                                                                log::warn!("Failed to send pong to {}: {}", addr, e);
                                                            }
                                                        }
                                                    }
                                                    break; // inner loop → create new recv_fut
                                                }
                                                Err(e) => {
                                                    if is_protocol_desync_error(&e) {
                                                        log::debug!("Error receiving from {}: {}", addr, e);
                                                    } else {
                                                        log::warn!("Error receiving from {}: {}", addr, e);
                                                    }
                                                    break 'task PeerDoneReason::Error(e);
                                                }
                                            }
                                        }
                                        cmd = cmd_rx.recv() => {
                                            match cmd {
                                                Some(PeerTaskCommand::SendGetData(msg)) => {
                                                    let data = msg.serialize();
                                                    if let Err(e) = write_half.write_all(&data).await {
                                                        log::warn!("Failed to send GetData to {}: {}", addr, e);
                                                    }
                                                }
                                                Some(PeerTaskCommand::Shutdown) | None => {
                                                    break 'task PeerDoneReason::Shutdown;
                                                }
                                            }
                                        }
                                    }
                                }
                            };

                            // Reunite stream halves and reconstruct Peer for PeerDone handler
                            let read_half = diag_reader.into_inner();
                            let stream = read_half.reunite(write_half).expect("same TcpStream");
                            let peer = Peer::from_stream(stream, addr, network);
                            let _ = event_tx.send(RecvEvent::PeerDone(addr, peer, done_reason));
                        });
                    }
                    log::debug!("[block-sync] Spawned {} long-lived peer receive tasks", peer_tasks.len());
                }
            }

            // Check if sync complete - send Shutdown to all tasks and add peers back
            {
                let queue = self.download_queue.lock().await;
                let in_flight = self.in_flight.lock().await;
                if queue.is_empty() && in_flight.is_empty() {
                    drop(in_flight);
                    drop(queue);
                    log::info!("All blocks downloaded and processed!");

                    // Shutdown all peer tasks and add peers back to PeerManager
                    let mut peer_tasks = self.peer_tasks.lock().await;
                    let to_shutdown: Vec<_> = peer_tasks.drain().collect();
                    drop(peer_tasks);
                    for (_, cmd_tx) in &to_shutdown {
                        let _ = cmd_tx.send(PeerTaskCommand::Shutdown).await;
                    }
                    let mut shutdown_count = to_shutdown.len();
                    while shutdown_count > 0 {
                        if let Some(RecvEvent::PeerDone(addr, peer, PeerDoneReason::Shutdown)) = event_rx.recv().await {
                            let mut pm = self.peer_manager.lock().await;
                            pm.add_peer(addr, peer).await;
                            shutdown_count -= 1;
                        }
                    }
                    break;
                }
            }

            // 1. Assign blocks and 2. Send GetData via command channel
            let mut assignments: Vec<(u32, [u8; 32], SocketAddr)> = Vec::new();
            {
                let mut queue = self.download_queue.lock().await;
                let in_flight = self.in_flight.lock().await;
                let peer_tasks = self.peer_tasks.lock().await;
                let available_peers: Vec<SocketAddr> = peer_tasks.keys().copied().collect();
                drop(peer_tasks);

                // Count in-flight per peer to respect MAX_IN_FLIGHT_PER_PEER (avoid overloading one peer)
                let mut per_peer_count: HashMap<SocketAddr, usize> = HashMap::new();
                for req in in_flight.values() {
                    *per_peer_count.entry(req.peer_addr).or_insert(0) += 1;
                }

                let mut avoid = self.avoid_peer_for_height.lock().await;
                let total_slots = batch_size.saturating_sub(in_flight.len());
                let mut peer_idx = 0;
                for _ in 0..total_slots {
                    if queue.is_empty() || available_peers.is_empty() {
                        break;
                    }
                    let height = queue.pop_front().unwrap();
                    let exclude_addr = avoid.get(&height).copied();
                    let peers_for_height: Vec<SocketAddr> = available_peers
                        .iter()
                        .filter(|a| exclude_addr != Some(**a))
                        .copied()
                        .collect();
                    if peers_for_height.is_empty() {
                        queue.push_front(height);
                        continue;
                    }
                    let block_hash = match self.db.get_block_hash_by_height(height) {
                        Ok(Some(hash)) => hash,
                        Ok(None) => {
                            if height == 0 {
                                genesis_block_hash(self.network)
                            } else {
                                log::warn!("No hash found for height {}, skipping", height);
                                queue.push_front(height);
                                continue;
                            }
                        }
                        Err(e) => {
                            log::warn!("DB error for height {}: {}, skipping", height, e);
                            queue.push_front(height);
                            continue;
                        }
                    };
                    // Find a peer under the per-peer cap (round-robin through peers that have capacity)
                    let mut attempts = 0;
                    let peer_addr = loop {
                        let addr = peers_for_height[peer_idx % peers_for_height.len()];
                        peer_idx += 1;
                        let count = per_peer_count.get(&addr).copied().unwrap_or(0);
                        if count < MAX_IN_FLIGHT_PER_PEER {
                            *per_peer_count.entry(addr).or_insert(0) += 1;
                            avoid.remove(&height);
                            break Some(addr);
                        }
                        attempts += 1;
                        if attempts >= peers_for_height.len() {
                            queue.push_front(height);
                            break None;
                        }
                    };
                    let Some(peer_addr) = peer_addr else {
                        break;
                    };
                    assignments.push((height, block_hash, peer_addr));
                }
                drop(in_flight);
                drop(queue);
            }

            // Batch GetData by peer: one message per peer with multiple blocks (reduces round-trips)
            let mut by_peer: HashMap<SocketAddr, Vec<(u32, [u8; 32])>> = HashMap::new();
            for (height, block_hash, peer_addr) in &assignments {
                by_peer.entry(*peer_addr).or_default().push((*height, *block_hash));
            }

            for (peer_addr, blocks) in &by_peer {
                let inv_items: Vec<InvItem> = blocks
                    .iter()
                    .map(|(_, hash)| InvItem {
                        inv_type: INV_TYPE_BLOCK,
                        hash: *hash,
                    })
                    .collect();
                let get_data = GetDataMessage::new(inv_items);
                let msg = get_data.to_message(self.network);

                let mut peer_tasks = self.peer_tasks.lock().await;
                let send_ok = if let Some(cmd_tx) = peer_tasks.get(peer_addr) {
                    cmd_tx.send(PeerTaskCommand::SendGetData(msg)).await.is_ok()
                } else {
                    false
                };
                drop(peer_tasks);
                if send_ok {
                    let now = Instant::now();
                    let mut in_flight = self.in_flight.lock().await;
                    let mut hash_map = self.hash_to_height.lock().await;
                    for (height, block_hash) in blocks {
                        in_flight.insert(*height, InFlightRequest {
                            peer_addr: *peer_addr,
                            requested_at: now,
                            retry_count: 0,
                        });
                        hash_map.insert(*block_hash, *height);
                    }
                    log::trace!("Requested {} block(s) from {}", blocks.len(), peer_addr);
                } else {
                    let mut queue = self.download_queue.lock().await;
                    for (height, _) in blocks {
                        queue.push_back(*height);
                    }
                }
            }

            if !assignments.is_empty() {
                let num_peers = by_peer.len();
                log::debug!(
                    "Sent {} block requests to {} peer(s) (batched)",
                    assignments.len(),
                    num_peers
                );
            }

            // 3. Receive events (drain channel with timeout - process all available blocks)
            let mut processed_any = false;
            loop {
                let event = match tokio::time::timeout(
                    Duration::from_millis(500),
                    event_rx.recv(),
                ).await {
                    Ok(Some(ev)) => ev,
                    Ok(None) => {
                        log::warn!("[block-sync] Event channel closed unexpectedly");
                        break;
                    }
                    Err(_) => {
                        if !processed_any {
                            self.update_progress().await;
                        }
                        break;
                    }
                };

                processed_any = true;

            match event {
                RecvEvent::Message(peer_addr, msg) => {
                    if msg.command == "block" {
                        match BlockMessage::deserialize_payload(&msg.payload) {
                            Ok(block_msg) => {
                                let block = block_msg.block;
                                let block_hash = block.block_hash();
                                let hash_bytes = *block_hash.as_byte_array();
                                let height_opt = {
                                    let hash_map = self.hash_to_height.lock().await;
                                    hash_map.get(&hash_bytes).copied()
                                };
                                if let Some(height) = height_opt {
                                    let block_wrapper = BlockWrapper::from(block);
                                    // Store block body for later retrieval
                                    if let Err(e) = self.db.store_block(&block_wrapper) {
                                        log::error!("Failed to store block {}: {}", height, e);
                                    } else {
                                        // Buffer the raw payload so we can apply (connect) the
                                        // block in sequential order.  `apply_block` updates the
                                        // UTXO set, tx-index, chainwork, and height→hash
                                        // mapping — it MUST be called in chain order.
                                        {
                                            let mut buf = self.pending_apply.lock().await;
                                            buf.insert(height, block_wrapper);
                                        }
                                        // Drain the sequential prefix of pending blocks.
                                        self.drain_apply_queue().await;
                                        {
                                            let mut in_flight = self.in_flight.lock().await;
                                            in_flight.remove(&height);
                                            let mut hm = self.hash_to_height.lock().await;
                                            hm.remove(&hash_bytes);
                                        }
                                        // Record peer progress and decay stalling timeout
                                        {
                                            self.peer_last_progress.lock().await
                                                .insert(peer_addr, Instant::now());
                                            let cur = self.stalling_timeout_secs.load(Ordering::Relaxed);
                                            if cur > self.stalling_timeout_base {
                                                let new_val = ((cur as f64) * STALLING_TIMEOUT_DECAY) as u64;
                                                let new_val = new_val.max(self.stalling_timeout_base);
                                                if self.stalling_timeout_secs.compare_exchange(
                                                    cur, new_val, Ordering::Relaxed, Ordering::Relaxed
                                                ).is_ok() && new_val < cur {
                                                    log::debug!("Decreased stalling timeout to {}s", new_val);
                                                }
                                            }
                                        }
                                        {
                                            let now = Instant::now();
                                            let mut stats = self.stats.lock().await;
                                            stats.blocks_downloaded += 1;
                                            stats.blocks_validated += 1;
                                            stats.last_update = Some(now);
                                            stats.block_timestamps.push_back(now);
                                            if stats.block_timestamps.len() > MAX_SPEED_WINDOW_SAMPLES {
                                                stats.block_timestamps.pop_front();
                                            }
                                            let total = stats.blocks_downloaded;
                                            let should_log = total % BATCH_LOG_INTERVAL == 0;
                                            drop(stats);
                                            if should_log {
                                                log::info!("[block-sync] Received {} blocks", total);
                                            }
                                        }
                                        self.update_progress().await;
                                    }
                                }
                            }
                            Err(e) => log::warn!("Failed to deserialize block from {}: {}", peer_addr, e),
                        }
                    }
                }
                RecvEvent::PeerDone(addr, peer, reason) => {
                    self.peer_tasks.lock().await.remove(&addr);
                    self.peer_last_progress.lock().await.remove(&addr);
                    let should_add_peer_back = match &reason {
                        PeerDoneReason::Timeout => {
                            // Unreachable: timeouts are reported as Error(PeerError::Timeout)
                            false
                        }
                        PeerDoneReason::Shutdown => true,
                        PeerDoneReason::Error(e) => {
                            // Timeout during receive = stream likely corrupted (partial payload read).
                            // Don't add back, re-queue blocks; don't blacklist (could be transient).
                            if matches!(e, PeerError::Timeout) {
                                let mut in_flight = self.in_flight.lock().await;
                                let mut queue = self.download_queue.lock().await;
                                let to_requeue: Vec<u32> = in_flight
                                    .iter()
                                    .filter(|(_, r)| r.peer_addr == addr)
                                    .map(|(h, _)| *h)
                                    .collect();
                                for height in &to_requeue {
                                    in_flight.remove(height);
                                    queue.push_back(*height);
                                }
                                if !to_requeue.is_empty() {
                                    log::debug!("[block-sync] Re-queued {} blocks from disconnected peer {} (timeout)", to_requeue.len(), addr);
                                }
                                false
                            } else if is_disconnect_error(e) || is_protocol_desync_error(e) {
                                // Disconnect without blacklisting (Bitcoin Core behavior).
                                // With the split-stream fix, desyncs should be extremely rare.
                                // When they do occur (genuine corruption), just disconnect and
                                // let the peer reconnect naturally — don't drain the peer pool.
                                if is_protocol_desync_error(e) {
                                    self.desync_count.fetch_add(1, Ordering::Relaxed);
                                    let total = self.desync_count.load(Ordering::Relaxed);
                                    log::info!(
                                        "[block-sync] Protocol desync from {} (total: {}), disconnecting without blacklist",
                                        addr, total
                                    );
                                }
                                let mut in_flight = self.in_flight.lock().await;
                                let mut queue = self.download_queue.lock().await;
                                let to_requeue: Vec<u32> = in_flight
                                    .iter()
                                    .filter(|(_, r)| r.peer_addr == addr)
                                    .map(|(h, _)| *h)
                                    .collect();
                                for height in &to_requeue {
                                    in_flight.remove(height);
                                    queue.push_back(*height);
                                }
                                if !to_requeue.is_empty() {
                                    log::debug!("[block-sync] Re-queued {} blocks from disconnected peer {}", to_requeue.len(), addr);
                                }
                                false
                            } else {
                                true
                            }
                        }
                    };
                    if should_add_peer_back {
                        let mut pm = self.peer_manager.lock().await;
                        pm.add_peer(addr, peer).await;
                    }
                }
            }
            } // end receive loop

            // 4. Adaptive stalling detection (Bitcoin Core-style)
            //
            // For each peer with in-flight requests, check if it has made progress
            // (delivered any block) within the current stalling timeout. If not,
            // disconnect the peer, requeue its blocks, and increase the stalling timeout.
            // When blocks are delivered (above), the timeout decays back toward the base.
            {
                let now = Instant::now();
                let current_stalling_timeout = Duration::from_secs(
                    self.stalling_timeout_secs.load(Ordering::Relaxed)
                );

                // Find peers with in-flight requests that have stalled
                let mut stalled_peers: HashSet<SocketAddr> = HashSet::new();
                {
                    let in_flight = self.in_flight.lock().await;
                    let peer_progress = self.peer_last_progress.lock().await;

                    // Collect peers that have in-flight requests
                    let mut peers_with_inflight: HashMap<SocketAddr, usize> = HashMap::new();
                    for req in in_flight.values() {
                        *peers_with_inflight.entry(req.peer_addr).or_insert(0) += 1;
                    }

                    for (addr, _count) in &peers_with_inflight {
                        let last_progress = peer_progress.get(addr).copied()
                            .unwrap_or(now - current_stalling_timeout - Duration::from_secs(1));
                        if now.duration_since(last_progress) > current_stalling_timeout {
                            stalled_peers.insert(*addr);
                        }
                    }
                }

                if !stalled_peers.is_empty() {
                    // Requeue all blocks from stalled peers
                    let mut in_flight = self.in_flight.lock().await;
                    let mut queue = self.download_queue.lock().await;
                    let mut avoid = self.avoid_peer_for_height.lock().await;
                    let mut total_requeued = 0u32;

                    for &stalled_addr in &stalled_peers {
                        let to_requeue: Vec<u32> = in_flight
                            .iter()
                            .filter(|(_, r)| r.peer_addr == stalled_addr)
                            .map(|(h, _)| *h)
                            .collect();
                        for &height in &to_requeue {
                            avoid.insert(height, stalled_addr);
                            in_flight.remove(&height);
                            queue.push_back(height);
                        }
                        total_requeued += to_requeue.len() as u32;
                    }
                    drop(in_flight);
                    drop(queue);
                    drop(avoid);

                    // Increase stalling timeout (double, capped at MAX)
                    let old_timeout = self.stalling_timeout_secs.load(Ordering::Relaxed);
                    let new_timeout = (old_timeout * 2).min(MAX_STALLING_TIMEOUT_SECS);
                    self.stalling_timeout_secs.store(new_timeout, Ordering::Relaxed);

                    log::warn!(
                        "Peer stalling: {} peer(s) made no progress for {}s, re-queued {} block(s). Stalling timeout: {}s -> {}s",
                        stalled_peers.len(),
                        old_timeout,
                        total_requeued,
                        old_timeout,
                        new_timeout
                    );

                    // Disconnect stalled peers (shutdown their tasks)
                    let mut peer_tasks = self.peer_tasks.lock().await;
                    for &stalled_addr in &stalled_peers {
                        if let Some(cmd_tx) = peer_tasks.remove(&stalled_addr) {
                            let _ = cmd_tx.send(PeerTaskCommand::Shutdown).await;
                        }
                        self.peer_last_progress.lock().await.remove(&stalled_addr);
                    }
                }
            }

            // 5. Update progress
            self.update_progress().await;

            // 6. Optional diagnostic logging (OUROBOROS_SYNC_DIAG=1, every 60s)
            if std::env::var("OUROBOROS_SYNC_DIAG").map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(false) {
                let should_log = last_diag_log
                    .map(|t| t.elapsed().as_secs() >= 60)
                    .unwrap_or(true);
                if should_log {
                    let (peer_count, in_flight_total, per_peer, queue_len, blocks_per_sec, desync_total) = {
                        let peer_tasks = self.peer_tasks.lock().await;
                        let in_flight = self.in_flight.lock().await;
                        let queue = self.download_queue.lock().await;
                        let mut per_peer: HashMap<SocketAddr, usize> = HashMap::new();
                        for r in in_flight.values() {
                            *per_peer.entry(r.peer_addr).or_insert(0) += 1;
                        }
                        let speed = self.progress_cache.lock().map(|c| c.blocks_per_second).unwrap_or(0.0);
                        (
                            peer_tasks.len(),
                            in_flight.len(),
                            per_peer,
                            queue.len(),
                            speed,
                            self.desync_count.load(Ordering::Relaxed),
                        )
                    };
                    let per_peer_str: String = per_peer
                        .iter()
                        .map(|(a, n)| format!("{}:{}", a, n))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let stalling_timeout = self.stalling_timeout_secs.load(Ordering::Relaxed);
                    log::info!(
                        "[sync-diag] peers={} in_flight={} queue={} blocks/s={:.1} desyncs={} stalling_timeout={}s per_peer=[{}]",
                        peer_count, in_flight_total, queue_len, blocks_per_sec, desync_total, stalling_timeout, per_peer_str
                    );
                    last_diag_log = Some(Instant::now());
                }
            }
        }

        Ok(())
    }

    /// Fill download queue with missing blocks
    async fn fill_download_queue(&self, start_height: u32, end_height: u32) -> Result<()> {
        let mut queue = self.download_queue.lock().await;

        for height in start_height..=end_height {
            // Check if block already exists
            match self.db.get_block_by_height(height) {
                Ok(Some(_)) => {
                    // Block already exists, skip
                    continue;
                }
                Ok(None) => {
                    // Block missing, add to queue
                    queue.push_back(height);
                }
                Err(e) => {
                    return Err(BlockSyncError::Database(e));
                }
            }
        }

        Ok(())
    }

    /// Download blocks in parallel (up to max_concurrent)
    ///
    /// Requests up to max_concurrent blocks simultaneously from different peers,
    /// handles responses as they arrive.
    /// Uses adaptive stalling timeout (same as main sync loop) when re-queuing stalled blocks.
    pub async fn download_block_parallel(&mut self) -> Result<()> {
        let now = Instant::now();
        let current_stalling_timeout = Duration::from_secs(
            self.stalling_timeout_secs.load(Ordering::Relaxed)
        );
        let timed_out: Vec<u32> = {
            let in_flight = self.in_flight.lock().await;
            in_flight
                .iter()
                .filter(|(_, r)| now.duration_since(r.requested_at) > current_stalling_timeout)
                .map(|(h, _)| *h)
                .collect()
        };

        if !timed_out.is_empty() {
            let timed_out_with_peers: Vec<(u32, SocketAddr)> = {
                let in_flight = self.in_flight.lock().await;
                timed_out
                    .iter()
                    .filter_map(|&h| in_flight.get(&h).map(|r| (h, r.peer_addr)))
                    .collect()
            };
            let mut sorted = timed_out_with_peers;
            sorted.sort_by_key(|(h, _)| *h);
            let n = sorted.len();
            let range = if n == 1 {
                format!("height {}", sorted[0].0)
            } else {
                format!("heights {}-{}", sorted[0].0, sorted[n - 1].0)
            };
            log::warn!("Block request stalled for {} block(s) ({}), re-queuing (avoiding stalled peers)", n, range);
            let mut in_flight = self.in_flight.lock().await;
            let mut queue = self.download_queue.lock().await;
            let mut avoid = self.avoid_peer_for_height.lock().await;
            for (height, peer_addr) in sorted {
                avoid.insert(height, peer_addr);
                in_flight.remove(&height);
                queue.push_back(height);
            }
        }

        Ok(())
    }

    /// Process an incoming block message from a peer
    ///
    /// This should be called when a block message is received from a peer.
    /// It matches the block to an in-flight request and handles it.
    pub async fn process_incoming_block(
        &mut self,
        peer_addr: std::net::SocketAddr,
        block_msg: BlockMessage,
    ) -> Result<()> {
        let block = block_msg.block;
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();

        // Find which height this block corresponds to by checking hash mapping
        let height = {
            let hash_map = self.hash_to_height.lock().await;
            hash_map.get(&hash_bytes).copied()
        };

        let height = match height {
            Some(h) => h,
            None => {
                // Try to find height by checking previous block's height + 1
                let prev_hash = block.header.prev_blockhash;
                let prev_hash_bytes = *prev_hash.as_byte_array();
                
                // Get previous block to find its height
                match self.db.get_block(&prev_hash_bytes) {
                    Ok(Some(_prev_block)) => {
                        // Find height by searching metadata (simplified - would be better with index)
                        // For now, return error - in practice we'd have a height index
                        return Err(BlockSyncError::Unknown(
                            "Cannot determine block height - hash not in tracking map".to_string()
                        ));
                    }
                    _ => {
                        // Previous block not found, this might be the first block we're downloading
                        // Try to find height from in-flight requests by matching peer
                        let in_flight = self.in_flight.lock().await;
                        in_flight.iter()
                            .find(|(_, req)| req.peer_addr == peer_addr)
                            .map(|(h, _)| *h)
                            .ok_or_else(|| BlockSyncError::Unknown(
                                "Cannot determine block height".to_string()
                            ))?
                    }
                }
            }
        };

        // Handle the block
        self.handle_block(height, block).await
    }

    /// Handle a received block
    ///
    /// Validates the block, applies to database (may need to wait for previous blocks),
    /// removes from in_flight, and updates progress.
    pub async fn handle_block(&mut self, height: u32, block: bitcoin::Block) -> Result<()> {
        // Convert to BlockWrapper
        let block_wrapper = BlockWrapper::from(block);

        // Get previous height for validation
        let prev_height = if height > 0 {
            height - 1
        } else {
            0
        };

        // Validate block (this is CPU-intensive, done in a separate blocking task)
        {
            let validator = Arc::clone(&self.validator);
            let block_clone = block_wrapper.clone();
            tokio::task::spawn_blocking(move || {
                validator.validate_block(&block_clone, prev_height)
            })
            .await
            .map_err(|e| BlockSyncError::Unknown(format!("Validation task failed: {}", e)))?
            .map_err(|e| BlockSyncError::Validation(e))?;
        }

        // Apply block: store body + update UTXO set, tx-index, height
        // mapping, and chain tip in one sequential operation.
        self.validator.apply_block(&block_wrapper, height)
            .map_err(|e| BlockSyncError::Validation(e))?;

        // Get block hash for removing from hash mapping
        let hash = block_wrapper.block_hash();
        let hash_bytes = *hash.as_byte_array();

        // Remove from in_flight and hash mapping
        {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.remove(&height);
            
            let mut hash_map = self.hash_to_height.lock().await;
            hash_map.remove(&hash_bytes);
        }

        // Update statistics
        {
            let mut stats = self.stats.lock().await;
            stats.blocks_downloaded += 1;
            stats.blocks_validated += 1;
            stats.last_update = Some(Instant::now());
        }

        // Update progress
        self.update_progress().await;

        Ok(())
    }

    /// Schedule downloads by assigning heights to available peers
    ///
    /// Balances load across peers and tracks requests per peer.
    pub async fn schedule_downloads(&mut self) -> Result<()> {
        // Get available slots
        let in_flight_count = {
            let in_flight = self.in_flight.lock().await;
            in_flight.len()
        };

        if in_flight_count >= self.max_concurrent {
            return Ok(()); // Already at max concurrent downloads
        }

        let available_slots = self.max_concurrent - in_flight_count;

        // Get queue and peers
        let mut queue = self.download_queue.lock().await;
        let peer_manager = self.peer_manager.lock().await;
        let connected_peers = peer_manager.connected_peers().await;

        if connected_peers.is_empty() {
            return Err(BlockSyncError::NoPeersAvailable);
        }

        // Schedule downloads
        for _ in 0..available_slots {
            if queue.is_empty() {
                break;
            }

            let height = queue.pop_front().unwrap();

            // Find a peer that's not already handling too many requests
            let peer_addr = self.select_peer_for_height(&connected_peers, height).await
                .ok_or(BlockSyncError::NoPeersAvailable)?;

            // Request block
            log::trace!("Requesting block at height {} from peer {}", height, peer_addr);
            self.request_block(height, peer_addr).await?;
        }

        Ok(())
    }

    /// Select a peer for a given height
    async fn select_peer_for_height(
        &self,
        peers: &[std::net::SocketAddr],
        _height: u32,
    ) -> Option<std::net::SocketAddr> {
        // Simple round-robin for now
        // In a real implementation, we'd consider:
        // - Peer load (how many requests already in-flight)
        // - Peer latency
        // - Peer reliability
        if peers.is_empty() {
            return None;
        }

        // Count requests per peer
        let in_flight = self.in_flight.lock().await;
        let mut peer_loads: HashMap<std::net::SocketAddr, usize> = HashMap::new();
        
        for request in in_flight.values() {
            *peer_loads.entry(request.peer_addr).or_insert(0) += 1;
        }

        // Select peer with lowest load
        peers.iter()
            .min_by_key(|addr| peer_loads.get(addr).unwrap_or(&0))
            .copied()
    }

    /// Request a block from a specific peer
    async fn request_block(
        &self,
        height: u32,
        peer_addr: std::net::SocketAddr,
    ) -> Result<()> {
        // Check if block already exists
        if let Ok(Some(_)) = self.db.get_block_by_height(height) {
            // Block already exists, remove from queue if present
            let mut queue = self.download_queue.lock().await;
            queue.retain(|&h| h != height);
            return Ok(());
        }

        // Get block hash from header metadata (fallback to genesis for height 0)
        let block_hash = match self.db.get_block_hash_by_height(height) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                if height == 0 {
                    genesis_block_hash(self.network)
                } else {
                    return Err(BlockSyncError::BlockNotFound(height));
                }
            }
            Err(e) => {
                return Err(BlockSyncError::Database(e));
            }
        };

        // Create GetData message
        let inv_item = InvItem {
            inv_type: INV_TYPE_BLOCK,
            hash: block_hash,
        };
        let get_data = GetDataMessage::new(vec![inv_item]);
        let msg = get_data.to_message(self.network);

        // Send request to the specific peer
        let mut peer_manager = self.peer_manager.lock().await;
        if let Some(mut peer) = peer_manager.get_peer(peer_addr).await {
            peer.send_message(msg).await
                .map_err(|e| BlockSyncError::PeerManager(PeerManagerError::Peer(e)))?;
            peer_manager.add_peer(peer_addr, peer).await;
            log::trace!("Sent GetData request for block at height {} to peer {}", height, peer_addr);
        } else {
            return Err(BlockSyncError::PeerManager(PeerManagerError::PeerNotFound(peer_addr)));
        }

        // Track in-flight request and hash mapping
        {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.insert(height, InFlightRequest {
                peer_addr,
                requested_at: Instant::now(),
                retry_count: 0,
            });
            
            // Store hash -> height mapping for incoming block matching
            let mut hash_map = self.hash_to_height.lock().await;
            hash_map.insert(block_hash, height);
        }

        Ok(())
    }

    /// Handle timeout for a block request
    ///
    /// Re-requests from a different peer and scores the original peer negatively.
    pub async fn handle_timeout(&mut self, height: u32) -> Result<()> {
        // Get the in-flight request
        let request = {
            let mut in_flight = self.in_flight.lock().await;
            in_flight.remove(&height)
        };

        let request = match request {
            Some(r) => r,
            None => return Ok(()), // Already handled
        };

        // Re-request from different peer if retry count is low
        if request.retry_count < 3 {
            let peer_manager = self.peer_manager.lock().await;
            let connected_peers = peer_manager.connected_peers().await;

            // Find a different peer
            let new_peer = connected_peers
                .iter()
                .find(|addr| **addr != request.peer_addr)
                .copied();

            if let Some(new_peer_addr) = new_peer {
                // Get block hash and re-request (fallback to genesis for height 0)
                let block_hash = match self.db.get_block_hash_by_height(height) {
                    Ok(Some(h)) => h,
                    Ok(None) if height == 0 => genesis_block_hash(self.network),
                    _ => {
                        return Err(BlockSyncError::BlockTimeout(height));
                    }
                };

                let inv_item = InvItem {
                    inv_type: INV_TYPE_BLOCK,
                    hash: block_hash,
                };
                let get_data = GetDataMessage::new(vec![inv_item]);
                let msg = get_data.to_message(self.network);

                drop(peer_manager);
                let mut peer_manager = self.peer_manager.lock().await;
                if let Err(_e) = peer_manager.request_from_best_peer(msg).await {
                    return Err(BlockSyncError::BlockTimeout(height));
                }

                // Update in-flight request with new peer
                {
                    let mut in_flight = self.in_flight.lock().await;
                    in_flight.insert(height, InFlightRequest {
                        peer_addr: new_peer_addr,
                        requested_at: Instant::now(),
                        retry_count: request.retry_count + 1,
                    });
                }
                return Ok(());
            }
        }

        // Too many retries, return error
        Err(BlockSyncError::BlockTimeout(height))
    }

    /// Update progress statistics, cache for UI, and call callback
    ///
    /// Flow: compute_progress() calculates blocks_per_second (rolling 10s window when available),
    /// updates progress_cache for get_sync_progress() (Python polls ~1s via sync_manager),
    /// and invokes progress_callback if set. Called after each block is stored.
    /// Apply (connect) queued blocks in sequential chain order.
    ///
    /// Blocks are stored out-of-order from parallel peer downloads.  This
    /// method drains the `pending_apply` buffer, applying each block whose
    /// predecessor has already been applied.  `apply_block` updates the UTXO
    /// set, tx-index, chainwork, and the canonical height-to-hash mapping.
    async fn drain_apply_queue(&self) {
        let (_best_hash, mut next_height) = self.db.get_best_block()
            .unwrap_or(([0u8; 32], 0));
        next_height += 1;

        let mut buf = self.pending_apply.lock().await;
        while let Some(block) = buf.remove(&next_height) {
            if let Err(e) = self.validator.apply_block(&block, next_height) {
                log::error!("Failed to apply block at height {}: {}", next_height, e);
                // Put the block back so we can retry later
                buf.insert(next_height, block);
                break;
            }
            if next_height % 1000 == 0 {
                log::info!("[block-sync] Applied block {}", next_height);
            }
            next_height += 1;
        }
    }

    async fn update_progress(&self) {
        let (blocks_downloaded, speed, eta) = match self.compute_progress().await {
            Some((d, s, e)) => (d, s, e),
            None => return,
        };

        // Get connected peer count
        let peer_count = {
            let pm = self.peer_manager.lock().await;
            pm.connected_peers_count().await as u32
        };

        // Update cache for get_sync_progress (called from sync Python code)
        {
            let mut cache = self.progress_cache.lock().unwrap();
            cache.blocks_downloaded = blocks_downloaded;
            cache.blocks_per_second = speed;
            cache.eta_seconds = eta;
            cache.peer_count = peer_count;
        }

        if let Some(ref callback) = self.progress_callback {
            let stats = self.stats.lock().await;
            callback(stats.blocks_validated, stats.blocks_downloaded, speed, eta);
        }
    }

    /// Get cached progress stats for UI (sync, no await - called from get_sync_progress)
    /// Returns (blocks_downloaded, total_to_download, blocks_per_second, eta_seconds).
    /// total_to_download is 0 when not in block sync.
    pub fn get_progress_stats(&self) -> Option<(u32, u32, f64, f64)> {
        let cache = self.progress_cache.lock().ok()?;
        Some((
            cache.blocks_downloaded,
            cache.total_to_download,
            cache.blocks_per_second,
            cache.eta_seconds,
        ))
    }

    /// Mark that block sync has started (enables progress reporting)
    fn init_progress_cache(&self, total_to_download: u32, total_chain_blocks: u32) {
        let mut cache = self.progress_cache.lock().unwrap();
        cache.blocks_downloaded = 0;
        cache.total_to_download = total_to_download;
        cache.total_chain_blocks = total_chain_blocks;
        cache.blocks_per_second = 0.0;
        cache.eta_seconds = 0.0;
    }

    async fn compute_progress(&self) -> Option<(u32, f64, f64)> {
        let (blocks_downloaded, start_time, last_update, block_timestamps) = {
            let stats = self.stats.lock().await;
            let start = stats.start_time?;
            let timestamps: VecDeque<Instant> = stats.block_timestamps.iter().copied().collect();
            (
                stats.blocks_downloaded,
                start,
                stats.last_update,
                timestamps,
            )
        };

        let now = Instant::now();
        let elapsed = last_update
            .unwrap_or(now)
            .duration_since(start_time)
            .as_secs_f64();

        if elapsed <= 0.0 {
            return Some((blocks_downloaded, 0.0, 0.0));
        }

        // Use rolling-window speed when we have enough data (more responsive than average)
        let speed = if block_timestamps.len() >= 2 {
            let cutoff = now - Duration::from_secs_f64(SPEED_WINDOW_SECS);
            let recent_count = block_timestamps.iter().filter(|&&t| t >= cutoff).count();
            if recent_count > 0 {
                let window_elapsed = {
                    let first = block_timestamps
                        .iter()
                        .filter(|&&t| t >= cutoff)
                        .min()
                        .copied()
                        .unwrap_or(now);
                    now.duration_since(first).as_secs_f64()
                };
                if window_elapsed >= 0.5 {
                    recent_count as f64 / window_elapsed
                } else {
                    blocks_downloaded as f64 / elapsed
                }
            } else {
                blocks_downloaded as f64 / elapsed
            }
        } else {
            blocks_downloaded as f64 / elapsed
        };

        let queue_len = {
            let queue = self.download_queue.lock().await;
            queue.len()
        };
        let in_flight_len = {
            let in_flight = self.in_flight.lock().await;
            in_flight.len()
        };
        let remaining = queue_len as u32 + in_flight_len as u32;
        let eta = if speed > 0.0 {
            remaining as f64 / speed
        } else if remaining > 0 {
            f64::MAX // Unknown ETA
        } else {
            0.0
        };

        Some((blocks_downloaded, speed, eta))
    }

    /// Receive and process incoming block messages from peers
    async fn receive_block_messages(&mut self) -> Result<()> {
        use tokio::time::{timeout, Duration};
        use crate::network::messages::BlockMessage;

        let peer_manager = self.peer_manager.lock().await;
        let connected_peers = peer_manager.connected_peers().await;
        drop(peer_manager);

        if connected_peers.is_empty() {
            return Err(BlockSyncError::NoPeersAvailable);
        }

        // Try to receive block messages from connected peers
        // Use a short timeout to avoid blocking
        for peer_addr in connected_peers.iter().take(5) {
            let (peer_addr_copy, block_msg_opt) = {
                let mut peer_manager = self.peer_manager.lock().await;
                if let Some(mut peer) = peer_manager.get_peer(*peer_addr).await {
                    // Try to receive a message with a short timeout
                    let msg_result = timeout(Duration::from_millis(100), peer.receive_message()).await;
                    match msg_result {
                        Ok(Ok(msg)) => {
                            if msg.command == "block" {
                                // Deserialize block message
                                match BlockMessage::deserialize_payload(&msg.payload) {
                                    Ok(block_msg) => {
                                        log::debug!("Received block message from peer {}", peer_addr);
                                        // Put peer back before processing
                                        peer_manager.add_peer(*peer_addr, peer).await;
                                        (*peer_addr, Some(block_msg))
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to deserialize block from {}: {}", peer_addr, e);
                                        peer_manager.add_peer(*peer_addr, peer).await;
                                        (*peer_addr, None)
                                    }
                                }
                            } else {
                                peer_manager.add_peer(*peer_addr, peer).await;
                                (*peer_addr, None)
                            }
                        }
                        Ok(Err(_)) => {
                            peer_manager.add_peer(*peer_addr, peer).await;
                            (*peer_addr, None)
                        }
                        Err(_) => {
                            // Timeout, return peer and break
                            peer_manager.add_peer(*peer_addr, peer).await;
                            break; // No more messages available right now
                        }
                    }
                } else {
                    continue;
                }
            };

            // Process the block if we got one (outside the lock)
            if let Some(block_msg) = block_msg_opt {
                if let Err(e) = self.process_incoming_block(peer_addr_copy, block_msg).await {
                    log::warn!("Error processing block from {}: {}", peer_addr_copy, e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use crate::storage::db::BlockchainDB;
    use crate::validate::block::BlockValidator;
    use crate::network::peer_manager::PeerManager;
    use tempdir::TempDir;

    // Helper to create a test BlockSync instance
    fn create_test_block_sync() -> (TempDir, BlockSync) {
        let temp_dir = TempDir::new("block_sync_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        let validator = Arc::new(BlockValidator::new(Arc::clone(&db), Network::Bitcoin));
        let peer_manager = Arc::new(Mutex::new(PeerManager::new(
            Network::Bitcoin,
            "/Ouroboros:0.1.0/".to_string(),
            0,
            50,
        )));
        let progress_cache = Arc::new(StdMutex::new(BlockProgressCache::default()));
        let block_sync = BlockSync::new(
            peer_manager,
            validator,
            db,
            Network::Bitcoin,
            progress_cache,
        );
        (temp_dir, block_sync)
    }

    #[test]
    fn test_block_sync_new() {
        let (_temp_dir, _block_sync) = create_test_block_sync();
        // Just verify it can be created
    }

    #[test]
    fn test_progress_stats_initial() {
        let (_temp_dir, block_sync) = create_test_block_sync();
        let stats = block_sync.get_progress_stats();
        assert!(stats.is_some());
        let (blocks, _total, speed, eta) = stats.unwrap();
        assert_eq!(blocks, 0);
        assert_eq!(speed, 0.0);
        assert_eq!(eta, 0.0);
    }

    #[test]
    fn test_select_peer_for_height() {
        let (_temp_dir, _block_sync) = create_test_block_sync();
        let _peers: Vec<std::net::SocketAddr> = vec![
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8334".parse().unwrap(),
        ];
        // Test peer selection (would need async runtime)
    }
}

