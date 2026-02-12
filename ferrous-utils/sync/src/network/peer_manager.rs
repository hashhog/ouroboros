//! Bitcoin P2P peer manager for discovery and connection management

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use bitcoin::Network;
use tokio::net::lookup_host;
use tokio::sync::Mutex;
use tokio::time::interval;
use thiserror::Error;

use crate::network::peer::{Peer, PeerError, PeerState};
use crate::network::messages::Message;

/// Peer manager error types
#[derive(Error, Debug, Clone)]
pub enum PeerManagerError {
    #[error("Peer error: {0}")]
    Peer(#[from] PeerError),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("No peers available")]
    NoPeersAvailable,

    #[error("Peer not found: {0}")]
    PeerNotFound(SocketAddr),

    #[error("Connection limit reached")]
    ConnectionLimitReached,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for peer manager operations
pub type Result<T> = std::result::Result<T, PeerManagerError>;

/// Check if IPv4-only mode is requested (OUROBOROS_PREFER_IPV4=1)
fn prefer_ipv4_only() -> bool {
    std::env::var("OUROBOROS_PREFER_IPV4").as_deref() == Ok("1")
}

/// Sort and optionally filter peer addresses: IPv4 first, IPv6 second.
/// When OUROBOROS_PREFER_IPV4=1, filters out IPv6 entirely.
fn sort_addrs_prefer_ipv4(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if prefer_ipv4_only() {
        addrs.retain(|a| a.is_ipv4());
    }
    addrs.sort_by(|a, b| {
        let a_v4 = a.is_ipv4();
        let b_v4 = b.is_ipv4();
        a_v4.cmp(&b_v4).reverse() // IPv4 (true) before IPv6 (false)
    });
    addrs
}

/// Peer ban information
#[derive(Debug, Clone)]
struct BannedPeer {
    until: Instant,
    backoff_until: Option<Instant>,
    backoff_duration: Duration,
}

impl BannedPeer {
    fn new(duration: Duration) -> Self {
        Self {
            until: Instant::now() + duration,
            backoff_until: None,
            backoff_duration: Duration::from_secs(1),
        }
    }

    fn is_banned(&self) -> bool {
        Instant::now() < self.until
    }

    fn is_backed_off(&self) -> bool {
        if let Some(backoff_until) = self.backoff_until {
            Instant::now() < backoff_until
        } else {
            false
        }
    }

    fn record_failed_connection(&mut self) {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
        self.backoff_duration = (self.backoff_duration * 2).min(Duration::from_secs(60));
        self.backoff_until = Some(Instant::now() + self.backoff_duration);
    }

    fn reset_backoff(&mut self) {
        self.backoff_until = None;
        self.backoff_duration = Duration::from_secs(1);
    }
}

/// Expiry for desync blacklist (5 minutes)
const DESYNC_BLACKLIST_SECS: u64 = 300;

/// Bitcoin P2P peer manager
pub struct PeerManager {
    /// Active peer connections
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    /// Maximum number of peers
    max_peers: usize,
    /// Known peer addresses (not necessarily connected)
    known_addrs: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Banned peers with ban duration
    banned_peers: Arc<Mutex<HashMap<SocketAddr, BannedPeer>>>,
    /// Peers that sent corrupted data (Payload size exceeds, Invalid magic). Expires after 5 min.
    desync_blacklist: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    /// Bitcoin network
    network: Network,
    /// User agent string
    user_agent: String,
    /// Starting block height
    start_height: i32,
    /// Minimum number of peers to maintain
    min_peers: usize,
    /// Maximum number of peers to maintain
    target_peers: usize,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(
        network: Network,
        user_agent: String,
        start_height: i32,
        max_peers: usize,
    ) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            max_peers,
            known_addrs: Arc::new(Mutex::new(HashSet::new())),
            banned_peers: Arc::new(Mutex::new(HashMap::new())),
            desync_blacklist: Arc::new(Mutex::new(HashMap::new())),
            network,
            user_agent,
            start_height,
            min_peers: 8,
            target_peers: 10,
        }
    }

    /// Blacklist a peer that sent corrupted data (Payload size exceeds, Invalid magic).
    /// Peer won't be reconnected for 5 minutes.
    pub async fn blacklist_peer_desync(&mut self, addr: SocketAddr) {
        let mut list = self.desync_blacklist.lock().await;
        list.insert(addr, Instant::now());
    }

    /// Check if peer is blacklisted for desync (and prune expired entries)
    fn is_desync_blacklisted(blacklist: &mut HashMap<SocketAddr, Instant>, addr: SocketAddr) -> bool {
        let now = Instant::now();
        let expiry = Duration::from_secs(DESYNC_BLACKLIST_SECS);
        let before = blacklist.len();
        blacklist.retain(|_, t| now.duration_since(*t) < expiry);
        let removed = before.saturating_sub(blacklist.len());
        if removed > 0 {
            log::debug!("Desync blacklist: {} peer(s) expired after {}s cooldown, can retry", removed, DESYNC_BLACKLIST_SECS);
        }
        blacklist
            .get(&addr)
            .map(|t| now.duration_since(*t) < expiry)
            .unwrap_or(false)
    }

    /// Start the peer manager
    ///
    /// Connects to DNS seeds, resolves addresses, connects to initial peers,
    /// and starts the peer maintenance task.
    pub async fn start(&mut self) -> Result<()> {
        // Connect to DNS seeds
        self.connect_to_seeds().await?;

        // Start peer maintenance task
        let peers = Arc::clone(&self.peers);
        let known_addrs = Arc::clone(&self.known_addrs);
        let banned_peers = Arc::clone(&self.banned_peers);
        let desync_blacklist = Arc::clone(&self.desync_blacklist);
        let network = self.network;
        let user_agent = self.user_agent.clone();
        let start_height = self.start_height;
        let min_peers = self.min_peers;
        let target_peers = self.target_peers;
        let max_peers = self.max_peers;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Run every 30 seconds normally
            let mut fast_interval = tokio::time::interval(Duration::from_secs(10)); // Run every 10s when low on peers
            fast_interval.tick().await; // skip first immediate tick
            let mut dns_retry_interval = tokio::time::interval(Duration::from_secs(60)); // Retry DNS every 60 seconds
            let mut dns_retry_count = 0u32;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::maintain_connections_internal(
                            &peers,
                            &known_addrs,
                            &banned_peers,
                            &desync_blacklist,
                            network,
                            &user_agent,
                            start_height,
                            min_peers,
                            target_peers,
                            max_peers,
                        )
                        .await;
                    }
                    _ = fast_interval.tick() => {
                        // When low on peers, run maintenance more frequently for faster recovery
                        let count = peers.lock().await.len();
                        if count < min_peers {
                            Self::maintain_connections_internal(
                                &peers,
                                &known_addrs,
                                &banned_peers,
                                &desync_blacklist,
                                network,
                                &user_agent,
                                start_height,
                                min_peers,
                                target_peers,
                                max_peers,
                            )
                            .await;
                        }
                    }
                    _ = dns_retry_interval.tick() => {
                        // Periodically retry DNS seeds, especially for testnet4
                        let peers_map = peers.lock().await;
                        let connected_count = peers_map.len();
                        drop(peers_map);
                        
                        // Retry DNS if we have no or very few peers
                        if connected_count < min_peers {
                            dns_retry_count += 1;
                            if dns_retry_count == 1 || dns_retry_count % 5 == 0 {
                                log::debug!("Retrying DNS seed resolution (attempt {})...", dns_retry_count);
                            }
                            
                            // Retry DNS seed resolution
                            let dns_seeds = match network {
                                Network::Bitcoin => vec![
                                    "seed.bitcoin.sipa.be:8333",
                                    "dnsseed.bluematt.me:8333",
                                    "dnsseed.bitcoin.dashjr.org:8333",
                                ],
                                Network::Testnet => vec![
                                    "testnet-seed.bitcoin.jonasschnelli.ch:18333",
                                    "seed.tbtc.petertodd.org:18333",
                                    "seed.testnet.bitcoin.sprovoost.nl:18333",
                                ],
                                Network::Testnet4 => vec![
                                    "seed.testnet4.bitcoin.sprovoost.nl:48333",
                                    "seed.testnet4.wiz.biz:48333",
                                ],
                                Network::Signet => vec![
                                    "seed.signet.bitcoin.sprovoost.nl:38333",
                                ],
                                Network::Regtest => vec![],
                            };
                            
                            let mut new_addrs = Vec::new();
                            for seed in dns_seeds {
                                match lookup_host(seed).await {
                                    Ok(addrs) => {
                                        for addr in addrs {
                                            new_addrs.push(addr);
                                        }
                                    }
                                    Err(e) => {
                                        if dns_retry_count % 5 == 0 { // Log every 5th attempt
                                            log::warn!("DNS seed {} still not resolving: {}", seed, e);
                                        }
                                    }
                                }
                            }
                            
                            // Add newly resolved addresses
                            if !new_addrs.is_empty() {
                                let mut known = known_addrs.lock().await;
                                for addr in &new_addrs {
                                    known.insert(*addr);
                                }
                                log::debug!("Resolved {} new peer address(es) from DNS seeds", new_addrs.len());
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Connect to DNS seeds and resolve peer addresses
    ///
    /// DNS seeds for mainnet:
    /// - seed.bitcoin.sipa.be
    /// - dnsseed.bluematt.me
    /// - dnsseed.bitcoin.dashjr.org
    pub async fn connect_to_seeds(&mut self) -> Result<()> {
        let dns_seeds = match self.network {
            Network::Bitcoin => vec![
                "seed.bitcoin.sipa.be:8333",
                "dnsseed.bluematt.me:8333",
                "dnsseed.bitcoin.dashjr.org:8333",
            ],
            Network::Testnet => vec![
                "testnet-seed.bitcoin.jonasschnelli.ch:18333",
                "seed.tbtc.petertodd.org:18333",
                "seed.testnet.bitcoin.sprovoost.nl:18333",
            ],
            Network::Regtest => {
                // Regtest doesn't use DNS seeds
                return Ok(());
            }
            Network::Signet => vec![
                "seed.signet.bitcoin.sprovoost.nl:38333",
            ],
            Network::Testnet4 => vec![
                "seed.testnet4.bitcoin.sprovoost.nl:48333",
                "seed.testnet4.wiz.biz:48333",
            ],
        };

        let mut resolved_addrs = Vec::new();

        // Resolve DNS seeds
        for seed in dns_seeds {
            match lookup_host(seed).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_addrs.push(addr);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }

        // Add hardcoded peers for networks that might have DNS issues
        // Testnet4 is newer and might not have reliable DNS seeds
        let hardcoded_peers: Vec<&str> = match self.network {
            Network::Testnet4 => vec![
                // Add known testnet4 peers here if available
                // For now, we'll rely on DNS seeds and peer discovery
            ],
            _ => vec![],
        };

        // Resolve hardcoded peers
        for peer in hardcoded_peers {
            match lookup_host(peer).await {
                Ok(addrs) => {
                    for addr in addrs {
                        resolved_addrs.push(addr);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to resolve hardcoded peer {}: {}", peer, e);
                }
            }
        }

        // Prefer IPv4 (Testnet4 and others: IPv6 often fails to connect)
        if prefer_ipv4_only() {
            log::info!("Using IPv4-only mode (OUROBOROS_PREFER_IPV4=1)");
        }
        resolved_addrs = sort_addrs_prefer_ipv4(resolved_addrs);

        // Add resolved addresses to known addresses
        {
            let mut known = self.known_addrs.lock().await;
            for addr in &resolved_addrs {
                known.insert(*addr);
            }
        }

        // If we have no resolved addresses, log a warning but don't fail
        // The peer manager will continue to try to discover peers through other means
        if resolved_addrs.is_empty() {
            log::warn!("No peers resolved from DNS seeds. Peer discovery may be limited.");
        }

        // Connect to up to 8 peers (IPv4 first when sorted)
        let mut connected = 0;
        for addr in resolved_addrs.into_iter().take(8) {
            if self.connect_to_peer(addr).await.is_ok() {
                connected += 1;
            }
        }

        // For testnet4, be more lenient - allow starting even if no peers initially
        // The peer manager will continue to try to discover peers
        if connected == 0 {
            if self.network == Network::Testnet4 {
                log::warn!("No peers resolved for testnet4. Will retry peer discovery.");
                // Don't fail immediately for testnet4 - allow retries
                return Ok(());
            }
            return Err(PeerManagerError::NoPeersAvailable);
        }

        Ok(())
    }

    /// Connect to a specific peer
    async fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<()> {
        // Check if peer is banned
        {
            let banned = self.banned_peers.lock().await;
            if let Some(banned_peer) = banned.get(&addr) {
                if banned_peer.is_banned() || banned_peer.is_backed_off() {
                    return Err(PeerManagerError::Peer(PeerError::Disconnected));
                }
            }
        }

        // Check desync blacklist (peer sent corrupted data recently)
        {
            let mut list = self.desync_blacklist.lock().await;
            if Self::is_desync_blacklisted(&mut list, addr) {
                return Err(PeerManagerError::Peer(PeerError::Disconnected));
            }
        }

        // Check connection limit
        {
            let peers = self.peers.lock().await;
            if peers.len() >= self.max_peers {
                return Err(PeerManagerError::ConnectionLimitReached);
            }
            if peers.contains_key(&addr) {
                return Ok(()); // Already connected
            }
        }

        // Attempt connection
        match Peer::connect(
            addr,
            self.network,
            self.user_agent.clone(),
            self.start_height,
        )
        .await
        {
            Ok(mut peer) => {
                // Reset backoff on successful connection
                {
                    let mut banned = self.banned_peers.lock().await;
                    if let Some(banned_peer) = banned.get_mut(&addr) {
                        banned_peer.reset_backoff();
                    }
                }

                // Add to peers map
                {
                    let mut peers = self.peers.lock().await;
                    peers.insert(addr, peer);
                }

                Ok(())
            }
            Err(e) => {
                // Record failed connection for exponential backoff
                {
                    let mut banned = self.banned_peers.lock().await;
                    banned
                        .entry(addr)
                        .or_insert_with(|| BannedPeer::new(Duration::ZERO))
                        .record_failed_connection();
                }

                Err(PeerManagerError::Peer(e))
            }
        }
    }

    /// Maintain peer connections
    ///
    /// Keeps 8-10 outbound connections, replaces disconnected peers,
    /// and disconnects misbehaving peers. Actively connects to known addresses when below target.
    async fn maintain_connections_internal(
        peers: &Arc<Mutex<HashMap<SocketAddr, Peer>>>,
        known_addrs: &Arc<Mutex<HashSet<SocketAddr>>>,
        banned_peers: &Arc<Mutex<HashMap<SocketAddr, BannedPeer>>>,
        desync_blacklist: &Arc<Mutex<HashMap<SocketAddr, Instant>>>,
        network: Network,
        user_agent: &str,
        start_height: i32,
        min_peers: usize,
        target_peers: usize,
        max_peers: usize,
    ) {
        // Remove disconnected peers
        {
            let mut peers_map = peers.lock().await;
            let mut to_remove = Vec::new();

            for (addr, peer) in peers_map.iter() {
                if peer.state() != PeerState::Connected {
                    to_remove.push(*addr);
                }
            }

            for addr in to_remove {
                peers_map.remove(&addr);
            }
        }

        // Disconnect misbehaving peers (low reliability)
        {
            let mut peers_map = peers.lock().await;
            let mut to_remove = Vec::new();

            for (addr, peer) in peers_map.iter() {
                let score = peer.score();
                if score.reliability() < 0.5 && peers_map.len() > min_peers {
                    to_remove.push(*addr);
                }
            }

            for addr in to_remove {
                if let Some(mut peer) = peers_map.remove(&addr) {
                    peer.disconnect().await;
                }
            }
        }

        // Connect to new peers if below target
        {
            let peers_map = peers.lock().await;
            let current_peers = peers_map.len();
            let connected_addrs: HashSet<SocketAddr> = peers_map.keys().copied().collect();
            drop(peers_map);

            if current_peers >= target_peers || current_peers >= max_peers {
                return;
            }

            let needed = (target_peers - current_peers).min(max_peers - current_peers);

            let known = known_addrs.lock().await;
            let banned = banned_peers.lock().await;

            // Find candidates that are not connected, not banned, not backed off, not desync-blacklisted
            let mut candidates: Vec<SocketAddr> = known
                .iter()
                .filter(|addr| {
                    !connected_addrs.contains(addr)
                        && !banned
                            .get(addr)
                            .map(|b| b.is_banned() || b.is_backed_off())
                            .unwrap_or(false)
                })
                .copied()
                .collect();

            drop(known);
            drop(banned);

            // Filter out desync-blacklisted peers
            {
                let mut list = desync_blacklist.lock().await;
                candidates.retain(|addr| !Self::is_desync_blacklisted(&mut list, *addr));
            }

            // Prefer IPv4 (IPv6 often fails on Testnet4 and restricted networks)
            candidates = sort_addrs_prefer_ipv4(candidates);
            candidates.truncate(needed);

            // Attempt to connect to candidates
            for addr in candidates {
                match Peer::connect(addr, network, user_agent.to_string(), start_height).await {
                    Ok(mut peer) => {
                        {
                            let mut banned = banned_peers.lock().await;
                            if let Some(banned_peer) = banned.get_mut(&addr) {
                                banned_peer.reset_backoff();
                            }
                        }
                        let mut peers_map = peers.lock().await;
                        if peers_map.len() < max_peers && !peers_map.contains_key(&addr) {
                            peers_map.insert(addr, peer);
                            log::debug!("Connected to peer: {}", addr);
                        }
                    }
                    Err(_) => {
                        let mut banned = banned_peers.lock().await;
                        banned
                            .entry(addr)
                            .or_insert_with(|| BannedPeer::new(Duration::ZERO))
                            .record_failed_connection();
                    }
                }
            }
        }
    }

    /// Maintain connections (public wrapper)
    pub async fn maintain_connections(&mut self) {
        Self::maintain_connections_internal(
            &self.peers,
            &self.known_addrs,
            &self.banned_peers,
            &self.desync_blacklist,
            self.network,
            &self.user_agent,
            self.start_height,
            self.min_peers,
            self.target_peers,
            self.max_peers,
        )
        .await;
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&mut self, msg: Message) -> Result<()> {
        // Collect addresses first to avoid borrowing issues
        let connected_addrs: Vec<SocketAddr> = {
            let peers_map = self.peers.lock().await;
            peers_map
                .iter()
                .filter(|(_, peer)| peer.state() == PeerState::Connected)
                .map(|(addr, _)| *addr)
                .collect()
        };

        let total_peers = connected_addrs.len();
        let mut errors = Vec::new();

        // Send message to each peer
        for addr in connected_addrs {
            let mut peers_map = self.peers.lock().await;
            if let Some(peer) = peers_map.get_mut(&addr) {
                if let Err(e) = peer.send_message(msg.clone()).await {
                    errors.push((addr, e));
                }
            }
            drop(peers_map);
        }

        if !errors.is_empty() && total_peers == errors.len() {
            return Err(PeerManagerError::NoPeersAvailable);
        }

        Ok(())
    }

    /// Send a request to the best peer (lowest latency)
    ///
    /// Returns the address of the peer that received the message.
    pub async fn request_from_best_peer(&mut self, msg: Message) -> Result<SocketAddr> {
        self.request_from_best_peer_excluding(msg, &[]).await
    }

    /// Send a request to the best peer, excluding specific peers.
    ///
    /// Returns the address of the peer that received the message.
    pub async fn request_from_best_peer_excluding(
        &mut self,
        msg: Message,
        exclude: &[SocketAddr],
    ) -> Result<SocketAddr> {
        let exclude_set: std::collections::HashSet<SocketAddr> = exclude.iter().copied().collect();
        // Find peer with lowest latency, excluding specified peers
        let best_addr = {
            let peers_map = self.peers.lock().await;
            peers_map
                .iter()
                .filter(|(addr, peer)| {
                    peer.state() == PeerState::Connected && !exclude_set.contains(addr)
                })
                .min_by(|(_, a), (_, b)| {
                    a.score()
                        .avg_latency_ms
                        .partial_cmp(&b.score().avg_latency_ms)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(addr, _)| *addr)
        };

        match best_addr {
            Some(addr) => {
                let mut peers_map = self.peers.lock().await;
                if let Some(peer) = peers_map.get_mut(&addr) {
                    peer.send_message(msg).await?;
                    Ok(addr)
                } else {
                    Err(PeerManagerError::PeerNotFound(addr))
                }
            }
            None => Err(PeerManagerError::NoPeersAvailable),
        }
    }

    /// Ban a peer for a specific duration
    ///
    /// Disconnects the peer if it's currently connected.
    pub async fn ban_peer(&mut self, addr: SocketAddr, duration: Duration) {
        // Disconnect if connected
        {
            let mut peers_map = self.peers.lock().await;
            if let Some(mut peer) = peers_map.remove(&addr) {
                peer.disconnect().await;
            }
        }

        // Add to ban list
        {
            let mut banned = self.banned_peers.lock().await;
            banned.insert(addr, BannedPeer::new(duration));
        }
    }

    /// Add a known peer address
    pub async fn add_known_addr(&mut self, addr: SocketAddr) {
        let mut known = self.known_addrs.lock().await;
        known.insert(addr);
    }

    /// Get the number of connected peers
    pub async fn connected_peers_count(&self) -> usize {
        let peers = self.peers.lock().await;
        peers.len()
    }

    /// Get all connected peer addresses
    pub async fn connected_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.lock().await;
        peers.keys().copied().collect()
    }

    /// Get a peer by address (removes from map)
    pub async fn get_peer(&mut self, addr: SocketAddr) -> Option<Peer> {
        let mut peers = self.peers.lock().await;
        peers.remove(&addr)
    }

    /// Add a peer back to the map (for use after temporarily removing it)
    pub async fn add_peer(&mut self, addr: SocketAddr, peer: Peer) {
        let mut peers = self.peers.lock().await;
        peers.insert(addr, peer);
    }

    /// Remove all peers from the map (for concurrent receive - caller must add them back)
    pub async fn drain_peers(&mut self) -> HashMap<SocketAddr, Peer> {
        let mut peers = self.peers.lock().await;
        std::mem::take(&mut *peers)
    }

    /// Add multiple peers back to the map
    pub async fn add_peers(&mut self, peer_map: HashMap<SocketAddr, Peer>) {
        let mut peers = self.peers.lock().await;
        for (addr, peer) in peer_map {
            peers.insert(addr, peer);
        }
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&mut self, addr: SocketAddr) -> Result<()> {
        let mut peers = self.peers.lock().await;
        if let Some(mut peer) = peers.remove(&addr) {
            peer.disconnect().await;
            Ok(())
        } else {
            Err(PeerManagerError::PeerNotFound(addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_new() {
        let manager = PeerManager::new(
            Network::Bitcoin,
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0,
            50,
        );
        assert_eq!(manager.max_peers, 50);
        assert_eq!(manager.min_peers, 8);
        assert_eq!(manager.target_peers, 10);
    }

    #[tokio::test]
    async fn test_peer_manager_known_addrs() {
        let mut manager = PeerManager::new(
            Network::Bitcoin,
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0,
            50,
        );

        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        manager.add_known_addr(addr).await;

        // Note: We can't easily test connection without a real peer
        // This test just verifies the structure works
    }

    #[test]
    fn test_banned_peer() {
        let mut banned = BannedPeer::new(Duration::from_secs(60));
        assert!(banned.is_banned());

        // Test exponential backoff
        banned.record_failed_connection();
        assert!(banned.is_backed_off());
        assert_eq!(banned.backoff_duration, Duration::from_secs(2));

        banned.record_failed_connection();
        assert_eq!(banned.backoff_duration, Duration::from_secs(4));

        // Test backoff reset
        banned.reset_backoff();
        assert!(!banned.is_backed_off());
        assert_eq!(banned.backoff_duration, Duration::from_secs(1));
    }
}

