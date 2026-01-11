//! Bitcoin P2P peer connection and communication

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use bitcoin::Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use thiserror::Error;

use crate::network::messages::{
    Message, MessageError, VersionMessage, VerAckMessage, PingMessage, PongMessage,
    NetworkAddress,
};

/// Peer connection error types
#[derive(Error, Debug, Clone)]
pub enum PeerError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Message error: {0}")]
    Message(#[from] MessageError),

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid peer state: expected {expected:?}, got {actual:?}")]
    InvalidState { expected: PeerState, actual: PeerState },

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Peer disconnected")]
    Disconnected,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for peer operations
pub type Result<T> = std::result::Result<T, PeerError>;

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Connected,
    Disconnected,
}

/// Peer scoring information
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Number of successful messages sent
    pub messages_sent: u64,
    /// Number of successful messages received
    pub messages_received: u64,
    /// Number of failed operations
    pub failures: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Last successful operation timestamp
    pub last_success: Option<Instant>,
    /// Last failure timestamp
    pub last_failure: Option<Instant>,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            messages_sent: 0,
            messages_received: 0,
            failures: 0,
            avg_latency_ms: 0.0,
            last_success: None,
            last_failure: None,
        }
    }
}

impl PeerScore {
    /// Record a successful message send
    pub fn record_send(&mut self, latency_ms: f64) {
        self.messages_sent += 1;
        self.record_success(latency_ms);
    }

    /// Record a successful message receive
    pub fn record_receive(&mut self) {
        self.messages_received += 1;
        self.record_success(0.0);
    }

    /// Record a successful operation
    fn record_success(&mut self, latency_ms: f64) {
        self.last_success = Some(Instant::now());
        
        // Update average latency (exponential moving average)
        if self.messages_sent + self.messages_received == 1 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = (self.avg_latency_ms * 0.9) + (latency_ms * 0.1);
        }
    }

    /// Record a failure
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
    }

    /// Calculate reliability score (0.0 to 1.0)
    pub fn reliability(&self) -> f64 {
        let total_ops = self.messages_sent + self.messages_received + self.failures;
        if total_ops == 0 {
            return 1.0;
        }
        let successful_ops = self.messages_sent + self.messages_received;
        successful_ops as f64 / total_ops as f64
    }

    /// Get overall score (combination of reliability and latency)
    pub fn score(&self) -> f64 {
        let reliability = self.reliability();
        // Lower latency is better, so invert it (max 1000ms)
        let latency_score = (1000.0 - self.avg_latency_ms.min(1000.0)) / 1000.0;
        (reliability * 0.7) + (latency_score * 0.3)
    }
}

/// Bitcoin P2P peer connection
pub struct Peer {
    addr: SocketAddr,
    stream: TcpStream,
    version: Option<i32>,
    services: u64,
    state: PeerState,
    network: Network,
    score: PeerScore,
    /// Default timeout for operations (30 seconds)
    default_timeout: Duration,
}

impl Peer {
    /// Connect to a peer and perform handshake
    ///
    /// # Arguments
    /// * `addr` - Peer socket address
    /// * `network` - Bitcoin network (mainnet, testnet, etc.)
    /// * `user_agent` - User agent string
    /// * `start_height` - Starting block height
    pub async fn connect(
        addr: SocketAddr,
        network: Network,
        user_agent: String,
        start_height: i32,
    ) -> Result<Self> {
        // Establish TCP connection with timeout
        let connect_timeout = Duration::from_secs(10);
        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| PeerError::Timeout)?
            .map_err(|e| PeerError::Io(format!("Connection failed: {}", e)))?;

        let mut peer = Self {
            addr,
            stream,
            version: None,
            services: 0,
            state: PeerState::Connecting,
            network,
            score: PeerScore::default(),
            default_timeout: Duration::from_secs(30),
        };

        // Perform handshake
        peer.handshake(user_agent, start_height).await?;

        Ok(peer)
    }

    /// Perform version handshake
    ///
    /// Sends version message, waits for version reply, then exchanges verack messages.
    async fn handshake(&mut self, user_agent: String, start_height: i32) -> Result<()> {
        if self.state != PeerState::Connecting {
            return Err(PeerError::InvalidState {
                expected: PeerState::Connecting,
                actual: self.state,
            });
        }

        // Create and send version message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create local and remote addresses (simplified - use IPv4 mapped to IPv6)
        let local_addr = self.stream.local_addr()
            .map_err(|e| PeerError::Io(format!("Failed to get local addr: {}", e)))?;
        let remote_addr = NetworkAddress::from_ipv4(
            match local_addr {
                SocketAddr::V4(v4) => v4.ip().octets(),
                SocketAddr::V6(_) => [127, 0, 0, 1], // Default for IPv6
            },
            local_addr.port(),
            0,
        );

        let addr_recv = NetworkAddress::from_ipv4(
            match self.addr {
                SocketAddr::V4(v4) => v4.ip().octets(),
                SocketAddr::V6(_) => [127, 0, 0, 1],
            },
            self.addr.port(),
            0,
        );

        let version_msg = VersionMessage::new(
            70015, // Protocol version
            0, // Services
            timestamp,
            addr_recv,
            remote_addr,
            rand::random::<u64>(),
            user_agent,
            start_height,
            true, // Relay
        );

        let msg = version_msg.to_message(self.network);
        self.send_message_internal(msg).await?;

        // Wait for version message reply
        let reply = timeout(self.default_timeout, self.receive_message_internal())
            .await
            .map_err(|_| PeerError::Timeout)??;

        if reply.command != "version" {
            return Err(PeerError::HandshakeFailed(format!(
                "Expected version message, got: {}",
                reply.command
            )));
        }

        // Parse version message
        let peer_version = VersionMessage::deserialize_payload(&reply.payload)
            .map_err(|e| PeerError::HandshakeFailed(format!("Failed to parse version: {}", e)))?;

        self.version = Some(peer_version.version);
        self.services = peer_version.services;

        // Send verack
        let verack = VerAckMessage.to_message(self.network);
        self.send_message_internal(verack).await?;

        // Wait for verack reply
        let verack_reply = timeout(self.default_timeout, self.receive_message_internal())
            .await
            .map_err(|_| PeerError::Timeout)??;

        if verack_reply.command != "verack" {
            return Err(PeerError::HandshakeFailed(format!(
                "Expected verack message, got: {}",
                verack_reply.command
            )));
        }

        self.state = PeerState::Connected;
        Ok(())
    }

    /// Send a message to the peer
    pub async fn send_message(&mut self, msg: Message) -> Result<()> {
        if self.state != PeerState::Connected {
            return Err(PeerError::InvalidState {
                expected: PeerState::Connected,
                actual: self.state,
            });
        }

        let start = Instant::now();
        self.send_message_internal(msg).await?;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.score.record_send(latency_ms);
        Ok(())
    }

    /// Internal message sending (without state/score checks)
    async fn send_message_internal(&mut self, msg: Message) -> Result<()> {
        let data = msg.serialize();
        self.stream
            .write_all(&data)
            .await
            .map_err(|e| {
                self.state = PeerState::Disconnected;
                PeerError::Io(format!("Write error: {}", e))
            })?;
        Ok(())
    }

    /// Receive a message from the peer
    pub async fn receive_message(&mut self) -> Result<Message> {
        if self.state != PeerState::Connected {
            return Err(PeerError::InvalidState {
                expected: PeerState::Connected,
                actual: self.state,
            });
        }

        let msg = timeout(self.default_timeout, self.receive_message_internal())
            .await
            .map_err(|_| {
                self.score.record_failure();
                PeerError::Timeout
            })??;

        self.score.record_receive();
        Ok(msg)
    }

    /// Internal message receiving (without state/score checks)
    async fn receive_message_internal(&mut self) -> Result<Message> {
        // Read message header (24 bytes)
        let mut header = [0u8; 24];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    self.state = PeerState::Disconnected;
                    PeerError::ConnectionClosed
                } else {
                    self.state = PeerState::Disconnected;
                    PeerError::Io(format!("Read error: {}", e))
                }
            })?;

        // Parse payload size from header
        let payload_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        
        // Validate payload size (max 32MB)
        if payload_size > 32 * 1024 * 1024 {
            return Err(PeerError::Message(MessageError::PayloadSizeExceeded {
                size: payload_size,
                limit: 32 * 1024 * 1024,
            }));
        }

        // Read payload
        let mut payload = vec![0u8; payload_size as usize];
        if payload_size > 0 {
            self.stream
                .read_exact(&mut payload)
                .await
                .map_err(|e| {
                    self.state = PeerState::Disconnected;
                    PeerError::Io(format!("Read payload error: {}", e))
                })?;
        }

        // Deserialize message (this validates magic, checksum, etc.)
        let full_message = [&header[..], &payload[..]].concat();
        let msg = Message::deserialize(&full_message, self.network)
            .map_err(|e| {
                self.score.record_failure();
                PeerError::Message(e)
            })?;

        Ok(msg)
    }

    /// Send ping message and wait for pong
    pub async fn ping(&mut self) -> Result<()> {
        if self.state != PeerState::Connected {
            return Err(PeerError::InvalidState {
                expected: PeerState::Connected,
                actual: self.state,
            });
        }

        let nonce = rand::random::<u64>();
        let ping_msg = PingMessage::new(nonce);
        let msg = ping_msg.to_message(self.network);

        let start = Instant::now();
        self.send_message(msg).await?;

        // Wait for pong reply
        let reply = self.receive_message().await?;

        if reply.command != "pong" {
            return Err(PeerError::HandshakeFailed(format!(
                "Expected pong message, got: {}",
                reply.command
            )));
        }

        let pong = PongMessage::deserialize_payload(&reply.payload)
            .map_err(|e| PeerError::HandshakeFailed(format!("Failed to parse pong: {}", e)))?;

        if pong.nonce != nonce {
            return Err(PeerError::HandshakeFailed("Pong nonce mismatch".to_string()));
        }

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.score.record_send(latency_ms);
        Ok(())
    }

    /// Disconnect from peer
    pub async fn disconnect(&mut self) {
        self.state = PeerState::Disconnected;
        let _ = self.stream.shutdown().await;
    }

    /// Get peer address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get peer version
    pub fn version(&self) -> Option<i32> {
        self.version
    }

    /// Get peer services
    pub fn services(&self) -> u64 {
        self.services
    }

    /// Get peer state
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Get peer score
    pub fn score(&self) -> &PeerScore {
        &self.score
    }

    /// Set default timeout for operations
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.default_timeout = timeout;
    }

    /// Check if peer is connected
    pub fn is_connected(&self) -> bool {
        self.state == PeerState::Connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use std::time::Duration;

    // Note: Integration tests would require a test Bitcoin node
    // These are unit tests for the struct and logic

    #[test]
    fn test_peer_score() {
        let mut score = PeerScore::default();
        assert_eq!(score.reliability(), 1.0);

        score.record_send(100.0);
        assert_eq!(score.messages_sent, 1);
        assert!((score.avg_latency_ms - 100.0).abs() < 0.1);

        score.record_receive();
        assert_eq!(score.messages_received, 1);
        assert_eq!(score.reliability(), 1.0);

        score.record_failure();
        assert_eq!(score.failures, 1);
        assert!((score.reliability() - 0.666).abs() < 0.1);
    }

    #[test]
    fn test_peer_state() {
        assert_ne!(PeerState::Connecting, PeerState::Connected);
        assert_ne!(PeerState::Connected, PeerState::Disconnected);
    }

    // Integration test would look like:
    // #[tokio::test]
    // async fn test_peer_connect() {
    //     // This would require a test Bitcoin node
    //     // or a mock server
    // }
}

