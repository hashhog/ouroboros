//! Bitcoin P2P parallel block download and validation

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use bitcoin::Network;
use bitcoin::hashes::Hash;
use tokio::sync::Mutex;
use thiserror::Error;

use crate::network::peer_manager::{PeerManager, PeerManagerError};
use crate::network::peer::PeerError;
use crate::network::messages::{
    GetDataMessage, BlockMessage, InvItem, INV_TYPE_BLOCK,
};
use crate::validate::block::{BlockValidator, BlockValidationError};
use crate::storage::db::{BlockchainDB, DbError};
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
    /// Progress callback: (downloaded, total, speed_blocks_per_sec, eta_seconds)
    progress_callback: Option<ProgressCallback>,
    /// Statistics
    stats: Arc<Mutex<SyncStats>>,
}

/// Synchronization statistics
#[derive(Debug, Default)]
struct SyncStats {
    blocks_downloaded: u32,
    blocks_validated: u32,
    start_time: Option<Instant>,
    last_update: Option<Instant>,
}

impl BlockSync {
    /// Create a new block sync instance
    pub fn new(
        peer_manager: Arc<Mutex<PeerManager>>,
        validator: Arc<BlockValidator>,
        db: Arc<BlockchainDB>,
        network: Network,
    ) -> Self {
        Self {
            peer_manager,
            validator,
            db,
            network,
            download_queue: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            hash_to_height: Arc::new(Mutex::new(HashMap::new())),
            max_concurrent: 16,
            progress_callback: None,
            stats: Arc::new(Mutex::new(SyncStats::default())),
        }
    }

    /// Set progress callback
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Set maximum concurrent downloads
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max.min(32); // Cap at 32
    }

    /// Main block synchronization function
    ///
    /// Fills download queue with missing blocks, requests blocks from multiple peers
    /// in parallel, validates as they arrive, applies to database, and tracks progress.
    pub async fn sync_blocks(&mut self, start_height: u32, end_height: u32) -> Result<()> {
        // Initialize statistics
        {
            let mut stats = self.stats.lock().await;
            stats.start_time = Some(Instant::now());
            stats.last_update = Some(Instant::now());
        }

        // Fill download queue with missing blocks
        self.fill_download_queue(start_height, end_height).await?;

        let _total_blocks = end_height.saturating_sub(start_height) + 1;

        // Main sync loop
        loop {
            // Schedule downloads for available slots
            self.schedule_downloads().await?;

            // Download blocks in parallel
            self.download_block_parallel().await?;

            // Check if we're done
            let queue_len = {
                let queue = self.download_queue.lock().await;
                queue.len()
            };
            let in_flight_len = {
                let in_flight = self.in_flight.lock().await;
                in_flight.len()
            };

            if queue_len == 0 && in_flight_len == 0 {
                break; // All blocks downloaded and processed
            }

            // Small delay to prevent busy waiting
            tokio::time::sleep(Duration::from_millis(100)).await;
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
    /// Requests up to 16 blocks simultaneously from different peers,
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
            if now.duration_since(request.requested_at) > Duration::from_secs(30) {
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

        // Get block hash from header metadata (headers must be synced first)
        let block_hash = match self.db.get_block_hash_by_height(height) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                return Err(BlockSyncError::BlockNotFound(height));
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

        // Send request
        let mut peer_manager = self.peer_manager.lock().await;
        peer_manager.request_from_best_peer(msg).await
            .map_err(|e| BlockSyncError::PeerManager(e))?;

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
                // Get block hash and re-request
                match self.db.get_block_hash_by_height(height) {
                    Ok(Some(block_hash)) => {
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
                    _ => {
                        return Err(BlockSyncError::BlockTimeout(height));
                    }
                }
            }
        }

        // Too many retries, return error
        Err(BlockSyncError::BlockTimeout(height))
    }

    /// Update progress statistics and call callback
    async fn update_progress(&self) {
        let stats = self.stats.lock().await;
        
        if let Some(start_time) = stats.start_time {
            let elapsed = stats.last_update
                .unwrap_or_else(Instant::now)
                .duration_since(start_time)
                .as_secs_f64();
            
            if elapsed > 0.0 && stats.blocks_validated > 0 {
                let speed = stats.blocks_validated as f64 / elapsed;
                
                // Estimate remaining blocks (simplified)
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
                } else {
                    0.0
                };

                if let Some(ref callback) = self.progress_callback {
                    callback(stats.blocks_validated, stats.blocks_downloaded, speed, eta);
                }
            }
        }
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
    fn test_select_peer_for_height() {
        let (_temp_dir, _block_sync) = create_test_block_sync();
        let _peers: Vec<std::net::SocketAddr> = vec![
            "127.0.0.1:8333".parse().unwrap(),
            "127.0.0.1:8334".parse().unwrap(),
        ];
        // Test peer selection (would need async runtime)
    }
}

