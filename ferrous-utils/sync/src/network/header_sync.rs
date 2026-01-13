//! Bitcoin P2P headers-first synchronization

use std::sync::Arc;
use std::time::Duration;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use tokio::sync::Mutex;
use tokio::time::timeout;
use thiserror::Error;

use crate::network::peer_manager::{PeerManager, PeerManagerError};
use crate::network::peer::PeerError;
use crate::network::messages::{
    GetHeadersMessage, HeadersMessage,
};
use crate::validate::header::{HeaderValidator, HeaderValidationError};
use crate::storage::db::{BlockchainDB, DbError};
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

    #[error("Headers don't connect to chain")]
    HeadersDontConnect,

    #[error("Chain reorganization detected")]
    ChainReorg,

    #[error("Timeout waiting for headers")]
    Timeout,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for header sync operations
pub type Result<T> = std::result::Result<T, HeaderSyncError>;

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(u32, u32, f64) + Send + Sync>;

/// Bitcoin P2P headers-first synchronization
pub struct HeaderSync {
    peer_manager: Arc<Mutex<PeerManager>>,
    validator: Arc<HeaderValidator>,
    db: Arc<BlockchainDB>,
    network: Network,
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
    ) -> Self {
        Self {
            peer_manager,
            validator,
            db,
            network,
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
        // Get current best height
        let (_best_hash, best_height) = self.db.get_best_block()
            .map_err(|e| HeaderSyncError::Database(e))?;
        
        let mut current_height = best_height;
        let mut downloaded = 0u32;
        const BATCH_SIZE: u32 = 2000;

        loop {
            // Request headers batch
            let headers = match self.request_headers(current_height).await {
                Ok(h) => h,
                Err(HeaderSyncError::NoPeersAvailable) => {
                    // Wait a bit and retry
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };

            if headers.is_empty() {
                // No more headers available (we're synced)
                break;
            }

            // Validate and save headers
            self.save_headers(&headers, current_height).await?;

            // Update progress
            downloaded += headers.len() as u32;
            current_height += headers.len() as u32;

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

            // If we got fewer than BATCH_SIZE headers, we're done
            if headers.len() < BATCH_SIZE as usize {
                break;
            }
        }

        Ok(current_height)
    }

    /// Request headers from peer starting from a given height
    ///
    /// Builds GetHeaders message with locator, requests from peer,
    /// receives headers response, and validates it connects to known chain.
    pub async fn request_headers(&mut self, start_height: u32) -> Result<Vec<bitcoin::blockdata::block::Header>> {
        // Build locator
        let locator = self.build_locator(start_height)?;
        
        // Build GetHeaders message
        let hash_stop = [0u8; 32]; // Request until we get headers response
        let get_headers = GetHeadersMessage::new(70015, locator, hash_stop);
        let msg = get_headers.to_message(self.network);

        // Get peer manager and request from best peer
        let peer_addr = {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.request_from_best_peer(msg).await
                .map_err(|e| HeaderSyncError::PeerManager(e))?
        };

        // Get the peer temporarily to receive response
        let mut peer = {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.get_peer(peer_addr).await
                .ok_or(HeaderSyncError::NoPeersAvailable)?
        };

        // Receive headers response with timeout
        let response_msg = match timeout(Duration::from_secs(30), peer.receive_message()).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(e)) => return Err(HeaderSyncError::Peer(e)),
            Err(_) => return Err(HeaderSyncError::Timeout),
        };

        // Put peer back in map
        {
            let mut peer_manager = self.peer_manager.lock().await;
            peer_manager.add_peer(peer_addr, peer).await;
        }

        // Validate it's a headers message
        if response_msg.command != "headers" {
            return Err(HeaderSyncError::InvalidHeaderResponse);
        }

        // Deserialize headers message
        let headers_msg = HeadersMessage::deserialize_payload(&response_msg.payload)
            .map_err(|e| HeaderSyncError::Unknown(format!("Failed to deserialize headers: {}", e)))?;

        // Extract headers (verify tx_count is 0 for headers message)
        let headers: Vec<bitcoin::blockdata::block::Header> = headers_msg
            .headers
            .into_iter()
            .map(|h| {
                // Verify tx_count is 0 (headers message shouldn't include transactions)
                if h.tx_count != 0 {
                    // Log warning but continue
                    eprintln!("Warning: Headers message has non-zero tx_count: {}", h.tx_count);
                }
                h.header
            })
            .collect();

        // Validate headers connect to known chain
        if !headers.is_empty() {
            // Check first header connects to our chain
            let first_header = &headers[0];
            let (best_hash, _best_height) = self.db.get_best_block()
                .map_err(|e| HeaderSyncError::Database(e))?;

            // Get best block to check prev_blockhash
            if let Some(best_block) = self.db.get_block(&best_hash)
                .map_err(|e| HeaderSyncError::Database(e))? {
                let best_header_hash = best_block.block_hash();
                if first_header.prev_blockhash != best_header_hash {
                    return Err(HeaderSyncError::HeadersDontConnect);
                }
            }
        }

        Ok(headers)
    }

    /// Build block locator with exponential spacing
    ///
    /// Creates a block locator that includes genesis, recent blocks, and exponentially spaced blocks.
    pub fn build_locator(&self, start_height: u32) -> Result<Vec<[u8; 32]>> {
        let mut locator = Vec::new();
        
        // Get best block hash
        let (_best_hash, best_height) = self.db.get_best_block()
            .map_err(|e| HeaderSyncError::Database(e))?;

        // Start from genesis or best_height if it's lower
        let height = best_height.min(start_height);
        
        // Add genesis block (height 0)
        if height >= 10 {
            // Get genesis block hash
            if let Some(genesis_block) = self.db.get_block_by_height(0)
                .map_err(|e| HeaderSyncError::Database(e))? {
                let hash = genesis_block.block_hash();
                locator.push(*hash.as_byte_array());
            }
        }

        // Add exponentially spaced blocks
        let mut step = 1u32;
        let mut current = height;
        
        while current > 0 && locator.len() < 10 {
            // Clamp to available height
            if current > height {
                current = height;
            }
            
            if let Some(block) = self.db.get_block_by_height(current)
                .map_err(|e| HeaderSyncError::Database(e))? {
                let hash = block.block_hash();
                locator.push(*hash.as_byte_array());
            }

            // Exponential spacing: reduce step when approaching height
            if current > step {
                current = current.saturating_sub(step);
                step *= 2; // Double the step for exponential spacing
            } else {
                current = 0;
            }
        }

        // Add most recent blocks (up to 10)
        let recent_start = if height > 10 { height - 10 } else { 0 };
        for h in recent_start..=height {
            if let Some(block) = self.db.get_block_by_height(h)
                .map_err(|e| HeaderSyncError::Database(e))? {
                let hash = block.block_hash();
                // Avoid duplicates
                let hash_bytes = *hash.as_byte_array();
                if !locator.contains(&hash_bytes) {
                    locator.push(hash_bytes);
                }
            }
        }

        // Reverse to get chronological order (oldest first)
        locator.reverse();

        if locator.is_empty() {
            // Fallback: use genesis hash
            return Err(HeaderSyncError::Unknown("No blocks available for locator".to_string()));
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
        let (prev_hash, prev_height) = self.db.get_best_block()
            .map_err(|e| HeaderSyncError::Database(e))?;

        let mut prev_header = if let Some(block) = self.db.get_block(&prev_hash)
            .map_err(|e| HeaderSyncError::Database(e))? {
            BlockHeaderWrapper::from(*block.header())
        } else {
            // If no previous header, we'll validate the first header against itself
            // This is a special case for initial sync
            header_wrappers[0].clone()
        };

        // Validate and store each header
        for (i, header) in header_wrappers.iter().enumerate() {
            let current_height = start_height + i as u32;

            // Validate header connects to previous
            if i == 0 {
                // First header must connect to previous header
                if header.inner().prev_blockhash != prev_header.block_hash() {
                    return Err(HeaderSyncError::HeadersDontConnect);
                }
            } else {
                // Subsequent headers must connect to previous in this batch
                let prev_in_batch = &header_wrappers[i - 1];
                if header.inner().prev_blockhash != prev_in_batch.block_hash() {
                    return Err(HeaderSyncError::HeadersDontConnect);
                }
            }

            // Validate header with validator
            self.validator.validate_header(header, &prev_header)
                .map_err(|e| HeaderSyncError::Validation(e))?;

            // Store header metadata
            let hash = header.block_hash();
            let hash_bytes = *hash.as_byte_array();
            let timestamp = header.inner().time;
            let metadata = BlockMetadata::new(
                current_height,
                [0u8; 32], // TODO: Calculate chainwork
                timestamp as u32,
            );

            self.db.store_block_metadata(current_height, &hash_bytes, &metadata)
                .map_err(|e| HeaderSyncError::Database(e))?;

            // Update best header
            if current_height > prev_height {
                self.db.update_best_block(&hash_bytes, current_height)
                    .map_err(|e| HeaderSyncError::Database(e))?;
            }

            prev_header = header.clone();
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
        // Should handle empty database gracefully
        let result = header_sync.build_locator(0);
        assert!(result.is_err()); // Should error with no blocks
    }
}

