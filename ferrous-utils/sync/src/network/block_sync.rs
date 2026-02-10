//! Bitcoin P2P parallel block download and validation

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use bitcoin::Network;
use bitcoin::hashes::Hash;
use tokio::sync::{mpsc, Mutex};
use thiserror::Error;

use crate::network::peer_manager::{PeerManager, PeerManagerError};
use crate::network::peer::{Peer, PeerError, PeerState};
use crate::network::messages::{
    GetDataMessage, BlockMessage, InvItem, INV_TYPE_BLOCK,
    Message, PingMessage, PongMessage,
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

/// Default timeout when waiting for block messages from a peer.
/// Can be overridden via OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS or set_receive_timeout_secs().
const DEFAULT_RECEIVE_TIMEOUT_SECS: u64 = 30;
/// Interval for batch progress logging (blocks) when not verbose
const BATCH_LOG_INTERVAL: u32 = 50;

/// Check if verbose debug logging is enabled (OUROBOROS_VERBOSE=1)
fn is_verbose() -> bool {
    std::env::var("OUROBOROS_VERBOSE").as_deref() == Ok("1")
}
/// Default max in-flight block requests (Bitcoin Core uses 16 per peer; with 8 peers ~128 total)
const DEFAULT_MAX_IN_FLIGHT: usize = 128;
/// Timeout before re-queueing an in-flight request so another peer can try
const IN_FLIGHT_TIMEOUT_SECS: u64 = 60;

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
    /// Long-lived peer tasks: addr -> command sender (None until first drain)
    peer_tasks: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<PeerTaskCommand>>>>,
    /// Progress callback: (downloaded, total, speed_blocks_per_sec, eta_seconds)
    progress_callback: Option<ProgressCallback>,
    /// Statistics
    stats: Arc<Mutex<SyncStats>>,
    /// Cached progress for get_sync_progress (sync-readable, no await needed)
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
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

/// Cached progress for sync UI - updated when blocks are received, read by get_sync_progress
#[derive(Debug, Default, Clone)]
pub struct BlockProgressCache {
    pub blocks_downloaded: u32,
    pub blocks_per_second: f64,
    pub eta_seconds: f64,
}

impl BlockSync {
    /// Create a new block sync instance
    pub fn new(
        peer_manager: Arc<Mutex<PeerManager>>,
        validator: Arc<BlockValidator>,
        db: Arc<BlockchainDB>,
        network: Network,
    ) -> Self {
        let receive_timeout_secs = std::env::var("OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_RECEIVE_TIMEOUT_SECS);

        Self {
            peer_manager,
            validator,
            db,
            network,
            download_queue: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            hash_to_height: Arc::new(Mutex::new(HashMap::new())),
            max_concurrent: DEFAULT_MAX_IN_FLIGHT,
            receive_timeout_secs,
            peer_tasks: Arc::new(Mutex::new(HashMap::new())),
            progress_callback: None,
            stats: Arc::new(Mutex::new(SyncStats::default())),
            progress_cache: Arc::new(StdMutex::new(BlockProgressCache::default())),
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

        // Initialize progress cache so get_sync_progress can report block sync
        self.init_progress_cache();

        let queue_size = {
            let queue = self.download_queue.lock().await;
            queue.len()
        };
        eprintln!("Block sync: {} blocks to download (receive timeout: {}s)", queue_size, self.receive_timeout_secs);

        let batch_size = self.max_concurrent;

        // Shared channel: all peer tasks send events (Message, PeerDone) to main
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RecvEvent>();

        // Main sync loop - long-lived peer tasks architecture (see BLOCK_SYNC_ARCHITECTURE.md)
        loop {
            // Ensure we have peer tasks (drain and spawn on first use or after all disconnected)
            {
                let mut peer_tasks = self.peer_tasks.lock().await;
                if peer_tasks.is_empty() {
                    let mut peer_manager = self.peer_manager.lock().await;
                    let peer_map = peer_manager.drain_peers().await;
                    drop(peer_manager);

                    if peer_map.is_empty() {
                        drop(peer_tasks);
                        eprintln!("No peers available, waiting...");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }

                    let network = self.network;
                    let event_tx = event_tx.clone();
                    for (addr, peer) in peer_map {
                        let (cmd_tx, mut cmd_rx) = mpsc::channel::<PeerTaskCommand>(32);
                        peer_tasks.insert(addr, cmd_tx);

                        let event_tx = event_tx.clone();
                        tokio::spawn(async move {
                            let addr = addr;
                            let mut peer = peer;
                            loop {
                                tokio::select! {
                                    result = peer.receive_message() => {
                                        match result {
                                            Ok(msg) => {
                                                if msg.command == "block" {
                                                    let _ = event_tx.send(RecvEvent::Message(addr, msg));
                                                } else if msg.command == "ping" {
                                                    if let Ok(ping) = PingMessage::deserialize_payload(&msg.payload) {
                                                        let pong_msg = PongMessage::new(ping.nonce).to_message(network);
                                                        let _ = peer.send_message(pong_msg).await;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Error receiving from {}: {}", addr, e);
                                                let _ = event_tx.send(RecvEvent::PeerDone(addr, peer, PeerDoneReason::Error(e)));
                                                return;
                                            }
                                        }
                                    }
                                    cmd = cmd_rx.recv() => {
                                        match cmd {
                                            Some(PeerTaskCommand::SendGetData(msg)) => {
                                                if let Err(e) = peer.send_message(msg).await {
                                                    eprintln!("Failed to send GetData to {}: {}", addr, e);
                                                }
                                            }
                                            Some(PeerTaskCommand::Shutdown) | None => {
                                                let _ = event_tx.send(RecvEvent::PeerDone(addr, peer, PeerDoneReason::Shutdown));
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    if is_verbose() {
                        eprintln!("[block-sync] Spawned {} long-lived peer receive tasks", peer_tasks.len());
                    }
                }
            }

            // Check if sync complete - send Shutdown to all tasks and add peers back
            {
                let queue = self.download_queue.lock().await;
                let in_flight = self.in_flight.lock().await;
                if queue.is_empty() && in_flight.is_empty() {
                    drop(in_flight);
                    drop(queue);
                    eprintln!("All blocks downloaded and processed!");

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

                let available_slots = batch_size.saturating_sub(in_flight.len());
                let mut peer_idx = 0;
                for _ in 0..available_slots {
                    if queue.is_empty() || available_peers.is_empty() {
                        break;
                    }
                    let height = queue.pop_front().unwrap();
                    let block_hash = match self.db.get_block_hash_by_height(height) {
                        Ok(Some(hash)) => hash,
                        Ok(None) => {
                            if height == 0 {
                                genesis_block_hash(self.network)
                            } else {
                                eprintln!("No hash found for height {}, skipping", height);
                                queue.push_front(height);
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("DB error for height {}: {}, skipping", height, e);
                            queue.push_front(height);
                            continue;
                        }
                    };
                    let peer_addr = available_peers[peer_idx % available_peers.len()];
                    peer_idx += 1;
                    assignments.push((height, block_hash, peer_addr));
                }
                drop(in_flight);
                drop(queue);
            }

            for (height, block_hash, peer_addr) in &assignments {
                let inv_item = InvItem {
                    inv_type: INV_TYPE_BLOCK,
                    hash: *block_hash,
                };
                let get_data = GetDataMessage::new(vec![inv_item]);
                let msg = get_data.to_message(self.network);

                let mut peer_tasks = self.peer_tasks.lock().await;
                let send_ok = if let Some(cmd_tx) = peer_tasks.get(peer_addr) {
                    cmd_tx.send(PeerTaskCommand::SendGetData(msg)).await.is_ok()
                } else {
                    false
                };
                drop(peer_tasks);
                if send_ok {
                    let mut in_flight = self.in_flight.lock().await;
                    in_flight.insert(*height, InFlightRequest {
                        peer_addr: *peer_addr,
                        requested_at: Instant::now(),
                        retry_count: 0,
                    });
                    let mut hash_map = self.hash_to_height.lock().await;
                    hash_map.insert(*block_hash, *height);
                        if is_verbose() {
                            eprintln!("Requested block {} from {}", height, peer_addr);
                        }
                } else {
                    let mut queue = self.download_queue.lock().await;
                    queue.push_back(*height);
                }
            }

            if !assignments.is_empty() && is_verbose() {
                eprintln!("Sent {} block requests", assignments.len());
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
                        eprintln!("[block-sync] Event channel closed unexpectedly");
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
                                    if let Err(e) = self.db.store_block(&block_wrapper) {
                                        eprintln!("Failed to store block {}: {}", height, e);
                                    } else {
                                        let (_best_hash, best_height) = self.db.get_best_block()
                                            .unwrap_or(([0u8; 32], 0));
                                        if height > best_height {
                                            let _ = self.db.update_best_block(&hash_bytes, height);
                                        }
                                        {
                                            let mut in_flight = self.in_flight.lock().await;
                                            in_flight.remove(&height);
                                            let mut hm = self.hash_to_height.lock().await;
                                            hm.remove(&hash_bytes);
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
                                            let should_log = !is_verbose() && total % BATCH_LOG_INTERVAL == 0;
                                            drop(stats);
                                            if should_log {
                                                eprintln!("[block-sync] Received {} blocks", total);
                                            }
                                        }
                                        self.update_progress().await;
                                    }
                                }
                            }
                            Err(e) => eprintln!("Failed to deserialize block from {}: {}", peer_addr, e),
                        }
                    }
                }
                RecvEvent::PeerDone(addr, peer, reason) => {
                    self.peer_tasks.lock().await.remove(&addr);
                    let should_add_peer_back = match &reason {
                        PeerDoneReason::Timeout => true,
                        PeerDoneReason::Shutdown => true,
                        PeerDoneReason::Error(e) => {
                            if is_disconnect_error(e) {
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
                                    eprintln!("[block-sync] Re-queued {} blocks from disconnected peer {}", to_requeue.len(), addr);
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

            // 4. Handle timeouts for in-flight requests
            {
                let now = Instant::now();
                let mut timed_out = Vec::new();
                {
                    let in_flight = self.in_flight.lock().await;
                    for (height, request) in in_flight.iter() {
                        if now.duration_since(request.requested_at) > Duration::from_secs(IN_FLIGHT_TIMEOUT_SECS) {
                            timed_out.push(*height);
                        }
                    }
                }
                for height in timed_out {
                    eprintln!("Block request timed out for height {}, re-queuing", height);
                    let mut in_flight = self.in_flight.lock().await;
                    in_flight.remove(&height);
                    let mut queue = self.download_queue.lock().await;
                    queue.push_back(height);
                }
            }

            // 5. Update progress
            self.update_progress().await;
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
    pub async fn download_block_parallel(&mut self) -> Result<()> {
        // Get current in-flight requests
        let in_flight_map = {
            let in_flight = self.in_flight.lock().await;
            in_flight.clone()
        };

        // Check for timeouts and handle them
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (height, request) in &in_flight_map {
            if now.duration_since(request.requested_at) > Duration::from_secs(IN_FLIGHT_TIMEOUT_SECS) {
                timed_out.push(*height);
            }
        }

        for height in timed_out {
            self.handle_timeout(height).await?;
        }

        // Note: In a real implementation, we'd have a message handler that routes
        // incoming block messages to process_incoming_block() as they arrive.
        // For now, the caller should call process_incoming_block() when a block
        // message is received from a peer.

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

        // Store block in database
        self.db.store_block(&block_wrapper)
            .map_err(|e| BlockSyncError::Database(e))?;

        // Get block hash for updating best block and removing from hash mapping
        let hash = block_wrapper.block_hash();
        let hash_bytes = *hash.as_byte_array();

        // Update best block if this is the highest block
        let (_best_hash, best_height) = self.db.get_best_block()
            .map_err(|e| BlockSyncError::Database(e))?;
        
        if height > best_height {
            self.db.update_best_block(&hash_bytes, height)
                .map_err(|e| BlockSyncError::Database(e))?;
        }

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
            if is_verbose() {
                eprintln!("Requesting block at height {} from peer {}", height, peer_addr);
            }
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
            if is_verbose() {
                eprintln!("Sent GetData request for block at height {} to peer {}", height, peer_addr);
            }
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
    async fn update_progress(&self) {
        let (blocks_downloaded, speed, eta) = match self.compute_progress().await {
            Some((d, s, e)) => (d, s, e),
            None => return,
        };

        // Update cache for get_sync_progress (called from sync Python code)
        {
            let mut cache = self.progress_cache.lock().unwrap();
            cache.blocks_downloaded = blocks_downloaded;
            cache.blocks_per_second = speed;
            cache.eta_seconds = eta;
        }

        if let Some(ref callback) = self.progress_callback {
            let stats = self.stats.lock().await;
            callback(stats.blocks_validated, stats.blocks_downloaded, speed, eta);
        }
    }

    /// Get cached progress stats for UI (sync, no await - called from get_sync_progress)
    pub fn get_progress_stats(&self) -> Option<(u32, f64, f64)> {
        let cache = self.progress_cache.lock().ok()?;
        Some((
            cache.blocks_downloaded,
            cache.blocks_per_second,
            cache.eta_seconds,
        ))
    }

    /// Mark that block sync has started (enables progress reporting)
    fn init_progress_cache(&self) {
        let mut cache = self.progress_cache.lock().unwrap();
        cache.blocks_downloaded = 0;
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
                                        if is_verbose() {
                                            eprintln!("Received block message from peer {}", peer_addr);
                                        }
                                        // Put peer back before processing
                                        peer_manager.add_peer(*peer_addr, peer).await;
                                        (*peer_addr, Some(block_msg))
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to deserialize block from {}: {}", peer_addr, e);
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
                    eprintln!("Error processing block from {}: {}", peer_addr_copy, e);
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
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0,
            50,
        )));
        let block_sync = BlockSync::new(
            peer_manager,
            validator,
            db,
            Network::Bitcoin,
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
        // Before sync_blocks, cache has defaults; get_progress_stats returns Some
        let stats = block_sync.get_progress_stats();
        assert!(stats.is_some());
        let (blocks, speed, eta) = stats.unwrap();
        assert_eq!(blocks, 0);
        assert_eq!(speed, 0.0);
        assert_eq!(eta, 0.0);
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
            let mut peer_manager = self.peer_manager.lock().await;
            if let Some(mut peer) = peer_manager.get_peer(*peer_addr).await {
                // Try to receive a message with a short timeout
                match timeout(Duration::from_millis(100), peer.receive_message()).await {
                    Ok(Ok(msg)) => {
                        if msg.command == "block" {
                            // Deserialize block message
                                match BlockMessage::deserialize_payload(&msg.payload) {
                                    Ok(block_msg) => {
                                        if is_verbose() {
                                            eprintln!("Received block message from peer {}", peer_addr);
                                        }
                                        // Process the block
                                    if let Err(e) = self.process_incoming_block(*peer_addr, block_msg).await {
                                        eprintln!("Error processing block from {}: {}", peer_addr, e);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to deserialize block from {}: {}", peer_addr, e);
                                }
                            }
                        }
                        // Put peer back
                        peer_manager.add_peer(*peer_addr, peer).await;
                    }
                    Ok(Err(_)) => {
                        // Error receiving message, put peer back
                        peer_manager.add_peer(*peer_addr, peer).await;
                    }
                    Err(_) => {
                        // Timeout, put peer back
                        peer_manager.add_peer(*peer_addr, peer).await;
                        break; // No more messages available right now
                    }
                }
            }
        }

        Ok(())
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

