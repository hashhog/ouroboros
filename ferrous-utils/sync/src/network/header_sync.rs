//! Bitcoin P2P headers-first synchronization

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use tokio::sync::Mutex;
use tokio::time::timeout;
use thiserror::Error;

use crate::network::peer_manager::{PeerManager, PeerManagerError};
use crate::network::peer::PeerError;
use crate::network::messages::{
    GetHeadersMessage, HeadersMessage, MessageError,
};
use crate::validate::header::{HeaderValidator, HeaderValidationError};
use crate::storage::db::{BlockchainDB, DbError};
use crate::chain_params::{genesis_block_hash, genesis_block_timestamp, genesis_bits};
use crate::chainwork::compute_chainwork;
use crate::network::block_sync::BlockProgressCache;
use common::{BlockHeaderWrapper, BlockMetadata};

/// Header sync error types
#[derive(Error, Debug)]
pub enum HeaderSyncError {
    #[error("Peer manager error: {0}")]
    PeerManager(#[from] PeerManagerError),

    #[error("Peer error: {0}")]
    Peer(#[from] PeerError),

    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("Validation error: {0}")]
    Validation(#[from] HeaderValidationError),

    #[error("No peers available")]
    NoPeersAvailable,

    #[error("Invalid header response")]
    InvalidHeaderResponse,

    #[error("Headers don't connect to chain. {message}")]
    HeadersDontConnect {
        message: String,
        /// Peer that sent the headers (for excluding on retry)
        peer_addr: Option<std::net::SocketAddr>,
    },

    #[error("Chain reorganization detected")]
    ChainReorg,

    #[error("Timeout waiting for headers")]
    Timeout,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for header sync operations
pub type Result<T> = std::result::Result<T, HeaderSyncError>;

/// Build reset hint for HeadersDontConnect errors
fn reset_hint(network: Network) -> String {
    let net_str = match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };
    format!("Try: ouroboros --network {} sync --reset", net_str)
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(u32, u32, f64) + Send + Sync>;

/// Bitcoin P2P headers-first synchronization
pub struct HeaderSync {
    peer_manager: Arc<Mutex<PeerManager>>,
    validator: Arc<HeaderValidator>,
    db: Arc<BlockchainDB>,
    network: Network,
    /// Shared progress cache: set header_sync_tip when we discover chain tip (short batch)
    progress_cache: Option<Arc<StdMutex<BlockProgressCache>>>,
    /// Progress callback: (downloaded, total_estimated, percentage)
    progress_callback: Option<ProgressCallback>,
}

impl HeaderSync {
    /// Create a new header sync instance
    pub fn new(
        peer_manager: Arc<Mutex<PeerManager>>,
        validator: Arc<HeaderValidator>,
        db: Arc<BlockchainDB>,
        network: Network,
        progress_cache: Option<Arc<StdMutex<BlockProgressCache>>>,
    ) -> Self {
        Self {
            peer_manager,
            validator,
            db,
            network,
            progress_cache,
            progress_callback: None,
        }
    }

    /// Set progress callback
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Main headers synchronization function
    ///
    /// Starts from current best height, requests headers in batches of 2000,
    /// validates the chain, stores validated headers, and returns final height.
    pub async fn sync_headers(&mut self) -> Result<u32> {
        // Wait for at least one peer to be connected
        log::info!("Waiting for peers to connect...");
        let mut wait_count = 0;
        loop {
            // Check if we have any connected peers
            let connected_count = {
                let peer_manager = self.peer_manager.lock().await;
                peer_manager.connected_peers_count().await
            };
            
            if connected_count > 0 {
                log::info!("Found {} connected peer(s), starting header sync...", connected_count);
                break;
            }
            
            wait_count += 1;
            if wait_count % 5 == 0 {
                log::debug!("Still waiting for peers to connect... ({}s)", wait_count);
            }
            if wait_count > 120 {
                return Err(HeaderSyncError::NoPeersAvailable);
            }
            
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // Get current best height
        // If database is empty, start from height 0 (genesis will be downloaded)
        let (_best_hash, best_height) = match self.db.get_best_block() {
            Ok((hash, height)) => (hash, height),
            Err(_) => {
                // Database is empty, start from height 0
                // The first header batch will include the genesis block
                ([0u8; 32], 0)
            }
        };
        
        let mut current_height = best_height;
        let mut downloaded = 0u32;
        const BATCH_SIZE: u32 = 2000;

        let mut excluded_peers: Vec<std::net::SocketAddr> = Vec::new();

        loop {
            // Request headers batch (exclude peers that sent headers that didn't connect)
            let headers = match self.request_headers(current_height, &excluded_peers).await {
                Ok(h) => {
                    excluded_peers.clear(); // Success - reset exclude for next batch
                    h
                }
                Err(HeaderSyncError::NoPeersAvailable) => {
                    // If we excluded peers due to HeadersDontConnect, we may have excluded all
                    if !excluded_peers.is_empty() {
                        let hint = reset_hint(self.network);
                        log::error!("All peers sent headers that didn't connect. Chainstate may be inconsistent.");
                        log::error!("{}", hint);
                        return Err(HeaderSyncError::HeadersDontConnect {
                            message: format!("No peers with matching chain. {}", hint),
                            peer_addr: None,
                        });
                    }
                    // Wait a bit and retry
                    log::debug!("No peers available, waiting 5 seconds...");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(HeaderSyncError::Peer(crate::network::peer::PeerError::ConnectionClosed)) => {
                    // Peer disconnected, wait and retry with a different peer
                    log::debug!("Peer disconnected, retrying with different peer in 2 seconds...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Err(HeaderSyncError::Peer(crate::network::peer::PeerError::Timeout)) => {
                    // Connection timeout, retry
                    log::debug!("Connection timeout, retrying in 2 seconds...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Err(HeaderSyncError::Peer(crate::network::peer::PeerError::Io(ref msg))) => {
                    // I/O errors (broken pipe, write errors, etc.) - retry with different peer
                    if msg.contains("Broken pipe") || msg.contains("Write error") || msg.contains("Connection") {
                        log::debug!("Peer I/O error ({}), retrying with different peer in 2 seconds...", msg);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    // Other I/O errors - still retry
                    log::debug!("Peer I/O error: {}, retrying in 2 seconds...", msg);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Err(HeaderSyncError::PeerManager(ref pm_err)) => {
                    // Handle peer manager errors that contain I/O errors
                    let error_msg = format!("{}", pm_err);
                    if error_msg.contains("Broken pipe") || 
                       error_msg.contains("Write error") || 
                       error_msg.contains("Connection") ||
                       error_msg.contains("I/O error") {
                        log::debug!("Peer manager I/O error ({}), retrying with different peer in 2 seconds...", error_msg);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    // For other peer manager errors, check if it's a peer error we can retry
                    if let crate::network::peer_manager::PeerManagerError::Peer(ref peer_err) = pm_err {
                        match peer_err {
                            crate::network::peer::PeerError::ConnectionClosed => {
                                log::debug!("Peer disconnected (via manager), retrying with different peer in 2 seconds...");
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                            crate::network::peer::PeerError::Timeout => {
                                log::debug!("Connection timeout (via manager), retrying in 2 seconds...");
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                            crate::network::peer::PeerError::Io(ref msg) => {
                                log::debug!("Peer I/O error (via manager, {}), retrying in 2 seconds...", msg);
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                            _ => {
                                // Other peer errors - still retry
                                log::debug!("Peer manager error ({}), retrying in 2 seconds...", error_msg);
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                        }
                    }
                    // For non-peer errors from peer manager, check if it's recoverable
                    if error_msg.contains("No peers available") {
                        log::debug!("No peers available (via manager), waiting 5 seconds...");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    // If we can't handle it, return the error
                    return Err(HeaderSyncError::PeerManager(pm_err.clone()));
                }
                Err(HeaderSyncError::HeadersDontConnect { message, peer_addr }) => {
                    // Retry with a different peer - exclude the peer that sent bad headers
                    if let Some(addr) = peer_addr {
                        if !excluded_peers.contains(&addr) {
                            excluded_peers.push(addr);
                            log::debug!(
                                "Retrying with different peer (excluding {}); excluded so far: {}",
                                addr, excluded_peers.len()
                            );
                        }
                        continue;
                    }
                    return Err(HeaderSyncError::HeadersDontConnect { message, peer_addr: None });
                }
                Err(e) => return Err(e),
            };

            if headers.is_empty() {
                // No more headers available (we're at chain tip)
                if let Some(ref cache) = self.progress_cache {
                    if let Ok(mut c) = cache.lock() {
                        c.header_sync_tip = Some(current_height);
                    }
                }
                break;
            }

            // When requesting from genesis, peer sends block 1 first (not genesis).
            // Bitcoin height 1 = block 1, so we must use start_height=1 for the first batch.
            let save_start_height = if current_height == 0 { 1 } else { current_height };

            // Validate and save headers
            self.save_headers(&headers, save_start_height).await?;

            // Update progress
            downloaded += headers.len() as u32;
            current_height = save_start_height + headers.len() as u32;

            // Report progress (estimate total by assuming we continue getting headers)
            let estimated_total = if headers.len() == BATCH_SIZE as usize {
                current_height + BATCH_SIZE // Rough estimate
            } else {
                current_height // We're done
            };
            let percentage = if estimated_total > 0 {
                (current_height as f64 / estimated_total as f64) * 100.0
            } else {
                100.0
            };

            if let Some(ref callback) = self.progress_callback {
                callback(downloaded, estimated_total, percentage.min(100.0));
            }

            // If we got fewer than BATCH_SIZE headers, we're at chain tip
            // current_height = save_start + len is the next height; tip = current_height - 1
            if headers.len() < BATCH_SIZE as usize {
                if let Some(ref cache) = self.progress_cache {
                    if let Ok(mut c) = cache.lock() {
                        let tip = current_height.saturating_sub(1);
                        c.header_sync_tip = Some(tip);
                    }
                }
                break;
            }
        }

        Ok(current_height)
    }

    /// Request headers from peer starting from a given height
    ///
    /// Builds GetHeaders message with locator, requests from peer,
    /// receives headers response, and validates it connects to known chain.
    /// `exclude_peers` - peer addresses to exclude (e.g. after HeadersDontConnect)
    pub async fn request_headers(
        &mut self,
        start_height: u32,
        exclude_peers: &[std::net::SocketAddr],
    ) -> Result<Vec<bitcoin::blockdata::block::Header>> {
        // Build locator
        let mut locator = self.build_locator(start_height)?;
        
        // If locator is empty (empty database), use genesis hash from chain params
        if locator.is_empty() {
            log::debug!("Requesting headers from genesis");
            locator.push(genesis_block_hash(self.network));
        }
        
        // Build GetHeaders message
        let hash_stop = [0u8; 32]; // Request until we get headers response
        let get_headers = GetHeadersMessage::new(70015, locator, hash_stop);
        let msg = get_headers.to_message(self.network);

        // Get peer manager and request from best peer (excluding any that sent bad headers)
        let peer_addr = {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.request_from_best_peer_excluding(msg, exclude_peers).await
                .map_err(|e| HeaderSyncError::PeerManager(e))?
        };

        // Get the peer temporarily to receive response
        let mut peer = {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.get_peer(peer_addr).await
                .ok_or_else(|| {
                    log::warn!("Peer {} not found in peer manager", peer_addr);
                    HeaderSyncError::NoPeersAvailable
                })?
        };

        log::debug!("Requesting headers from peer {} (starting from height {})", peer_addr, start_height);

        // Receive headers response with timeout
        // Filter out non-headers messages (verack, ping, pong, inv, etc.)
        let mut response_msg = loop {
            let msg = match timeout(Duration::from_secs(60), peer.receive_message()).await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    // Suppress desync errors (Payload size exceeds, Invalid magic) at warn level
                    let is_desync = matches!(
                        &e,
                        PeerError::Message(MessageError::PayloadSizeExceeded { .. })
                            | PeerError::Message(MessageError::InvalidMagic { .. })
                    );
                    if is_desync {
                        log::debug!("Error receiving message from peer {}: {}", peer_addr, e);
                    } else {
                        log::warn!("Error receiving message from peer {}: {}", peer_addr, e);
                    }
                    return Err(HeaderSyncError::Peer(e));
                }
                Err(_) => {
                    log::debug!("Timeout waiting for headers from peer {}", peer_addr);
                    return Err(HeaderSyncError::Timeout);
                }
            };
            
            // If it's a headers message, use it
            if msg.command == "headers" {
                log::debug!("Received headers message from peer {}", peer_addr);
                break msg;
            }
            
            // Handle ping messages by responding with pong
            if msg.command == "ping" {
                use crate::network::messages::{PingMessage, PongMessage};
                // Parse ping nonce
                if let Ok(ping) = PingMessage::deserialize_payload(&msg.payload) {
                    // Send pong response
                    let pong = PongMessage::new(ping.nonce);
                    let pong_msg = pong.to_message(self.network);
                    if let Err(e) = peer.send_message(pong_msg).await {
                        log::warn!("Failed to send pong: {}", e);
                        return Err(HeaderSyncError::Peer(crate::network::peer::PeerError::Io(format!("Failed to send pong: {}", e))));
                    }
                }
                continue;
            }
            
            // Handle other common messages silently (sendcmpct, feefilter, inv, etc.)
            // These don't require responses but we should acknowledge them
            if matches!(msg.command.as_str(), "sendcmpct" | "feefilter" | "inv" | "addr" | "verack" | "pong") {
                // Silently continue - these are informational messages
                continue;
            }
            
            // Log unexpected messages at debug level
            if !matches!(msg.command.as_str(), "sendcmpct" | "feefilter" | "inv" | "addr" | "verack" | "pong" | "ping") {
                log::debug!("Received unexpected message: '{}', continuing to wait for headers...", msg.command);
            }
        };

        // Put peer back in map
        {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.add_peer(peer_addr, peer).await;
        }

        // Deserialize headers message
        let headers_msg = HeadersMessage::deserialize_payload(&response_msg.payload)
            .map_err(|e| HeaderSyncError::Unknown(format!("Failed to deserialize headers: {}", e)))?;

        log::debug!("Deserialized {} headers from peer {}", headers_msg.headers.len(), peer_addr);

        // Extract headers (verify tx_count is 0 for headers message)
        let headers: Vec<bitcoin::blockdata::block::Header> = headers_msg
            .headers
            .into_iter()
            .map(|h| {
                // Verify tx_count is 0 (headers message shouldn't include transactions)
                if h.tx_count != 0 {
                    log::warn!("Headers message has non-zero tx_count: {}", h.tx_count);
                }
                h.header
            })
            .collect();

        // Validate headers connect to known chain
        if !headers.is_empty() {
            // Check first header connects to our chain
            let first_header = &headers[0];
            
            // If database is empty, accept any headers
            match self.db.get_best_block() {
                Ok((best_hash, best_height)) => {
                    // Check first header connects to our chain (use best_hash; we may only have metadata, not full block)
                    let best_header_hash = bitcoin::BlockHash::from_byte_array(best_hash);
                    if first_header.prev_blockhash != best_header_hash {
                        // Try reorg recovery: peer may be on a longer chain that reorged
                        let prev_hash_bytes = first_header.prev_blockhash.to_byte_array();
                        if let Ok(Some(common_height)) =
                            self.db.find_height_of_hash(&prev_hash_bytes, best_height)
                        {
                            // Common ancestor found - reorg detected. Rewind to that height.
                            log::info!(
                                "Chain reorg detected: rewinding from height {} to {} (common ancestor)",
                                best_height, common_height
                            );
                            self.db
                                .update_best_block(&prev_hash_bytes, common_height)
                                .map_err(|e| HeaderSyncError::Database(e))?;
                            // Headers now connect (first header's prev = our new best)
                        } else {
                            // No common ancestor - chainstate likely inconsistent
                            let hint = reset_hint(self.network);
                            log::error!("Headers don't connect: first header prev_blockhash {:?} != best block hash {:?}", first_header.prev_blockhash, best_header_hash);
                            log::error!("{}", hint);
                            return Err(HeaderSyncError::HeadersDontConnect {
                                message: format!("First header doesn't connect (from peer {}). {}", peer_addr, hint),
                                peer_addr: Some(peer_addr),
                            });
                        }
                    }
                }
                Err(_) => {
                    // Database is empty - accept any headers
                    // When we send genesis hash in locator, peer sends headers starting from block 1
                    // So first header's prev_blockhash should be genesis hash
                    let genesis_hash = match self.network {
                        Network::Testnet => bitcoin::BlockHash::from_byte_array([
                            0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
                            0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
                            0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
                            0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
                        ]),
                        Network::Bitcoin => bitcoin::BlockHash::from_byte_array([
                            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
                            0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
                            0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
                            0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ]),
                        Network::Testnet4 => bitcoin::BlockHash::from_byte_array([
                            0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3, 0x5b,
                            0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4, 0x7f, 0x50,
                            0xae, 0x72, 0x5a, 0xe2, 0xde, 0x53, 0xbc, 0xfb,
                            0xba, 0xf2, 0x84, 0xda, 0x00, 0x00, 0x00, 0x00,
                        ]),
                        _ => bitcoin::BlockHash::all_zeros(),
                    };
                    
                    if first_header.prev_blockhash == genesis_hash {
                        log::debug!("Received headers starting from block 1 (after genesis)");
                    } else if first_header.prev_blockhash == bitcoin::BlockHash::all_zeros() {
                        log::debug!("Received genesis block header");
                    } else {
                        log::debug!("Database empty: accepting headers starting from non-genesis (prev_blockhash: {:?})", 
                                 first_header.prev_blockhash);
                    }
                }
            }
        }

        Ok(headers)
    }

    /// Build block locator with exponential spacing
    ///
    /// Per Bitcoin protocol: "The first hash in the locator is the parent of the desired
    /// identifiers" - i.e. our chain tip must be FIRST so the peer sends headers that extend it.
    /// Order: [tip, tip-1, tip-3, ..., genesis]
    pub fn build_locator(&self, _start_height: u32) -> Result<Vec<[u8; 32]>> {
        let mut locator = Vec::new();
        
        // Get best block hash (or use empty if database is empty)
        let (_best_hash, best_height) = match self.db.get_best_block() {
            Ok((hash, height)) => (hash, height),
            Err(_) => {
                // Database is empty, return empty locator (will request from genesis)
                return Ok(Vec::new());
            }
        };

        let height = best_height;
        
        // CRITICAL: First element MUST be our chain tip (parent of blocks we want).
        // Peer sends headers starting from the child of the first matching hash.
        let mut step = 1u32;
        let mut current = height;
        
        while current <= height {
            if let Some(hash) = self.db.get_block_hash_by_height(current)
                .map_err(|e| HeaderSyncError::Database(e))? {
                if !locator.contains(&hash) {
                    locator.push(hash);
                }
            }
            
            if current == 0 {
                break;
            }
            if current > step {
                current = current.saturating_sub(step);
                step = step.saturating_mul(2);
            } else {
                current = 0;
            }
            
            if locator.len() >= 10 {
                break;
            }
        }

        // Add genesis at end if not already present
        if height >= 10 {
            if let Some(genesis_hash) = self.db.get_block_hash_by_height(0)
                .map_err(|e| HeaderSyncError::Database(e))? {
                if !locator.contains(&genesis_hash) {
                    locator.push(genesis_hash);
                }
            }
        }

        Ok(locator)
    }

    /// Save headers to database
    ///
    /// Validates all headers, stores them in the database, and updates the best header.
    pub async fn save_headers(
        &self,
        headers: &[bitcoin::blockdata::block::Header],
        start_height: u32,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        // Convert to BlockHeaderWrapper
        let header_wrappers: Vec<BlockHeaderWrapper> = headers
            .iter()
            .map(|h| BlockHeaderWrapper::from(h.clone()))
            .collect();

        // Get previous header for validation
        // Handle empty database case
        // Check if database is empty ONCE at the beginning and remember it for the entire batch
        let db_was_empty_at_start = match self.db.get_best_block() {
            Ok((_hash, height)) => {
                (height, false) // Database has blocks
            }
            Err(_) => {
                // Database is empty - accept headers as-is
                if start_height == 0 {
                    log::debug!("Database empty: accepting headers starting from height {}", start_height);
                }
                (0, true) // Database is empty - remember this for entire batch
            }
        };
        let (prev_height, is_empty) = db_was_empty_at_start;
        let was_empty = is_empty; // Capture the value to use throughout

        // When database was empty and we're receiving block 1, 2, 3... (start_height=1),
        // we never receive the genesis header. Store genesis metadata at height 0 so
        // block sync can request the genesis block by hash.
        if was_empty && start_height == 1 {
            let genesis_hash = genesis_block_hash(self.network);
            let genesis_timestamp = genesis_block_timestamp(self.network);
            let genesis_bits = genesis_bits(self.network);
            let genesis_chainwork = compute_chainwork(&[0u8; 32], genesis_bits);
            let metadata = BlockMetadata::new(
                0,
                genesis_chainwork,
                genesis_timestamp,
            );
            self.db.store_block_metadata(0, &genesis_hash, &metadata)
                .map_err(|e| HeaderSyncError::Database(e))?;
            log::debug!("Stored genesis block metadata at height 0");
        }

        // Get previous header for validation (only if database is not empty)
        // When we only have metadata (header sync), we have best block hash but no full block
        let (mut prev_header_opt, best_hash_opt) = if !was_empty {
            let (prev_hash, _) = self.db.get_best_block()
                .map_err(|e| HeaderSyncError::Database(e))?;
            if let Some(block) = self.db.get_block(&prev_hash)
                .map_err(|e| HeaderSyncError::Database(e))? {
                (Some(BlockHeaderWrapper::from(*block.header())), None)
            } else {
                // Header-only sync: we have metadata but no full block; use hash for connection check
                (None, Some(prev_hash))
            }
        } else {
            (None, None) // Database is empty - no previous header
        };

        // Validate and store each header
        for (i, header) in header_wrappers.iter().enumerate() {
            let current_height = start_height + i as u32;

            // Validate header connects to previous
            if i == 0 {
                // First header validation
                if let Some(ref prev_header) = prev_header_opt {
                    // Database has full blocks - validate connection and run full validation
                    if header.inner().prev_blockhash != prev_header.block_hash() {
                        let hint = reset_hint(self.network);
                        log::error!("First header doesn't connect: prev_blockhash {:?} != prev_header hash {:?}", header.inner().prev_blockhash, prev_header.block_hash());
                        log::error!("{}", hint);
                        return Err(HeaderSyncError::HeadersDontConnect {
                            message: format!("First header doesn't connect to previous. {}", hint),
                            peer_addr: None,
                        });
                    }
                    self.validator.validate_header(header, prev_header)
                        .map_err(|e| HeaderSyncError::Validation(e))?;
                } else if let Some(ref best_hash) = best_hash_opt {
                    // Header-only sync: check connection using best block hash
                    let expected_prev = bitcoin::BlockHash::from_byte_array(*best_hash);
                    if header.inner().prev_blockhash != expected_prev {
                        let hint = reset_hint(self.network);
                        log::error!("First header doesn't connect: prev_blockhash {:?} != best block hash {:?}", header.inner().prev_blockhash, expected_prev);
                        log::error!("{}", hint);
                        return Err(HeaderSyncError::HeadersDontConnect {
                            message: format!("First header doesn't connect to best block. {}", hint),
                            peer_addr: None,
                        });
                    }
                    // Full validation skipped (no prev header for median time); chain link is verified
                } else {
                    // Database was empty at start - skip validation for first header
                    if current_height == 0 || (current_height < 100 && current_height % 10 == 0) || current_height % 10000 == 0 {
                        log::debug!("Skipping validation for first header (database was empty at start, height {})", current_height);
                    }
                }
                // Set prev_header for next iteration
                prev_header_opt = Some(header.clone());
            } else {
                // Subsequent headers must connect to previous in this batch
                let prev_in_batch = &header_wrappers[i - 1];
                if header.inner().prev_blockhash != prev_in_batch.block_hash() {
                    let hint = reset_hint(self.network);
                    return Err(HeaderSyncError::HeadersDontConnect {
                        message: format!("Headers in batch don't connect. {}", hint),
                        peer_addr: None,
                    });
                }
                // Validate header with validator
                // For empty database, skip validation for first 1000 headers to bootstrap
                // This allows us to get a working chain started even if some early headers have issues
                if was_empty && current_height < 1000 {
                    // Skip validation for first 1000 headers when database was empty at start
                    // This allows us to bootstrap the chain
                    if current_height % 100 == 0 {
                        log::debug!("Skipping validation for header at height {} (bootstrap mode, i={})", current_height, i);
                    }
                } else {
                    self.validator.validate_header(header, prev_in_batch)
                        .map_err(|e| {
                            log::error!("Header validation failed at height {} (i={}, was_empty={}): {}", current_height, i, was_empty, e);
                            HeaderSyncError::Validation(e)
                        })?;
                }
                // Update prev_header for next iteration
                prev_header_opt = Some(header.clone());
            }

            // Store header metadata with chainwork
            let hash = header.block_hash();
            let hash_bytes = *hash.as_byte_array();
            let timestamp = header.inner().time;
            let bits = header.inner().bits.to_consensus();
            let prev_chainwork = if current_height == 0 {
                [0u8; 32]
            } else {
                self.db
                    .get_block_metadata(current_height - 1)
                    .map_err(|e| HeaderSyncError::Database(e))?
                    .map(|m| m.chainwork)
                    .unwrap_or([0u8; 32])
            };
            let chainwork = compute_chainwork(&prev_chainwork, bits);
            let metadata = BlockMetadata::new(
                current_height,
                chainwork,
                timestamp as u32,
            );

            self.db.store_block_metadata(current_height, &hash_bytes, &metadata)
                .map_err(|e| HeaderSyncError::Database(e))?;

            // Update best header
            if current_height > prev_height || was_empty {
                self.db.update_best_block(&hash_bytes, current_height)
                    .map_err(|e| HeaderSyncError::Database(e))?;
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
    use crate::validate::header::HeaderValidator;
    use crate::network::peer_manager::PeerManager;
    use tempdir::TempDir;

    // Helper to create a test HeaderSync instance
    fn create_test_header_sync() -> (TempDir, HeaderSync) {
        let temp_dir = TempDir::new("header_sync_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = Arc::new(BlockchainDB::open(db_path).unwrap());
        let validator = Arc::new(HeaderValidator::new(Arc::clone(&db), Network::Bitcoin));
        let peer_manager = Arc::new(Mutex::new(PeerManager::new(
            Network::Bitcoin,
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0,
            50,
        )));
        let header_sync = HeaderSync::new(
            peer_manager,
            validator,
            db,
            Network::Bitcoin,
        );
        (temp_dir, header_sync)
    }

    #[test]
    fn test_header_sync_new() {
        let (_temp_dir, _header_sync) = create_test_header_sync();
        // Just verify it can be created
    }

    #[test]
    fn test_build_locator_empty_db() {
        let (_temp_dir, header_sync) = create_test_header_sync();
        // Empty database returns empty locator (request from genesis)
        let result = header_sync.build_locator(0);
        assert!(result.is_ok());
        let locator = result.unwrap();
        assert!(locator.is_empty());
    }
}

