//! Bitcoin P2P peer connection and communication
//!
//! This module is the Rust IBD-only peer.  It performs the handshake,
//! reads block/header messages, and exposes a generic `Message` stream
//! to the caller.  Tx relay, BIP-152 compact blocks, and the matching
//! serving paths live in the Python layer (`src/ouroboros/p2p.py`,
//! `src/ouroboros/node.py`); see the cross-impl P2P parity audit
//! (PARITY-MATRIX.md, Category B).
//!
//! TODO(serve): if/when ferrous-utils is consumed by another front-end,
//! port the Python serving handlers (tx, getdata, getheaders,
//! sendcmpct, cmpctblock, getblocktxn, blocktxn) here.  Until then the
//! handshake correctly advertises NODE_NETWORK | NODE_WITNESS so peers
//! see consistent capabilities even when the Rust path is in use.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use bitcoin::Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use thiserror::Error;

use crate::network::messages::{
    get_magic, Message, MessageError, VersionMessage, VerAckMessage, PingMessage, PongMessage,
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

        // Bitcoin Core service flags (protocol.h):
        //   NODE_NETWORK = 1 << 0 — full block + tx relay
        //   NODE_WITNESS = 1 << 3 — serves segwit (witness) data
        // ferrous-utils validates witness data, so we must advertise
        // NODE_WITNESS too. Otherwise Core peers refuse to send us
        // post-segwit blocks via getdata MSG_WITNESS_BLOCK.
        const NODE_NETWORK: u64 = 1 << 0;
        const NODE_WITNESS: u64 = 1 << 3;
        let services = NODE_NETWORK | NODE_WITNESS;

        let version_msg = VersionMessage::new(
            70015, // Protocol version
            services,
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

    /// Internal message receiving (without state/score checks).
    ///
    /// Aligned with Bitcoin Core V1Transport behaviour:
    /// - Bad magic or oversized payload → disconnect.
    /// - Bad checksum or invalid command type → drop message, continue.
    async fn receive_message_internal(&mut self) -> Result<Message> {
        const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;
        const RESYNC_SCAN_LIMIT: usize = 1024 * 1024; // 1MB

        let try_resync = std::env::var("OUROBOROS_TRY_RESYNC").is_ok_and(|v| v == "1");
        let expected_magic = get_magic(self.network);

        loop {
            let mut header = [0u8; 24];
            self.stream
                .read_exact(&mut header)
                .await
                .map_err(|e| {
                    self.state = PeerState::Disconnected;
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        PeerError::ConnectionClosed
                    } else {
                        PeerError::Io(format!("Read error: {}", e))
                    }
                })?;

            let header_magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            if header_magic != expected_magic {
                if try_resync {
                    if let Some(msg) = self.try_magic_resync(expected_magic, RESYNC_SCAN_LIMIT).await? {
                        return Ok(msg);
                    }
                }
                self.state = PeerState::Disconnected;
                self.score.record_failure();
                return Err(PeerError::Message(MessageError::InvalidMagic {
                    expected: expected_magic,
                    actual: header_magic,
                }));
            }

            // Validate command type (Bitcoin Core IsMessageTypeValid):
            // chars before first null must be printable ASCII, after must be 0x00.
            let command_bytes = &header[4..16];
            let null_pos = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
            let cmd_slice = &command_bytes[..null_pos];
            let command_valid = cmd_slice.iter().all(|&b| b >= b' ' && b <= 0x7f)
                && command_bytes[null_pos..].iter().all(|&b| b == 0);

            let payload_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);

            if payload_size > MAX_PROTOCOL_MESSAGE_LENGTH {
                if try_resync {
                    if let Some(msg) = self.try_magic_resync(expected_magic, RESYNC_SCAN_LIMIT).await? {
                        return Ok(msg);
                    }
                }
                self.state = PeerState::Disconnected;
                return Err(PeerError::Message(MessageError::PayloadSizeExceeded {
                    size: payload_size,
                    limit: MAX_PROTOCOL_MESSAGE_LENGTH,
                }));
            }

            let checksum = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);

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

            // Bad checksum → drop message, don't disconnect (Bitcoin Core compat).
            let calculated_checksum = crate::network::messages::calculate_checksum(&payload);
            if checksum != calculated_checksum {
                log::warn!(
                    "Bad checksum (size={}): expected {:08x}, got {:08x} — dropping",
                    payload_size, calculated_checksum, checksum
                );
                continue;
            }

            // Invalid command → drop message, don't disconnect (Bitcoin Core compat).
            if !command_valid || cmd_slice.is_empty() {
                log::debug!(
                    "Invalid message type, dropping (size={}): cmd_bytes={}",
                    payload_size,
                    command_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                );
                continue;
            }

            let command = String::from_utf8(cmd_slice.to_vec())
                .map_err(|e| PeerError::Message(MessageError::InvalidCommand(format!("Invalid UTF-8: {}", e))))?;

            return Ok(Message {
                magic: expected_magic,
                command,
                payload_size,
                checksum,
                payload,
            });
        }
    }

    /// Scan the stream for network magic bytes and, if found, read the next message.
    /// Returns Ok(Some(msg)) on success, Ok(None) if magic not found within limit, Err on I/O.
    async fn try_magic_resync(
        &mut self,
        expected_magic: u32,
        scan_limit: usize,
    ) -> Result<Option<Message>> {
        let magic_bytes = expected_magic.to_le_bytes();
        let mut window = [0u8; 4];
        let mut wlen = 0;
        let mut bytes_scanned: usize = 0;

        while bytes_scanned < scan_limit {
            let mut byte = [0u8; 1];
            let n = self
                .stream
                .read(&mut byte)
                .await
                .map_err(|e| {
                    self.state = PeerState::Disconnected;
                    PeerError::Io(format!("Resync read error: {}", e))
                })?;
            if n == 0 {
                return Ok(None);
            }

            bytes_scanned += 1;

            if wlen < 4 {
                window[wlen] = byte[0];
                wlen += 1;
            } else {
                window[0] = window[1];
                window[1] = window[2];
                window[2] = window[3];
                window[3] = byte[0];
            }

            if wlen == 4 && window == magic_bytes {
                // Found magic. Read remaining 20 bytes of header.
                let mut header = [0u8; 24];
                header[0..4].copy_from_slice(&window);
                self.stream
                    .read_exact(&mut header[4..24])
                    .await
                    .map_err(|e| {
                        self.state = PeerState::Disconnected;
                        PeerError::Io(format!("Resync header read error: {}", e))
                    })?;

                let payload_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
                const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;
                if payload_size > MAX_PROTOCOL_MESSAGE_LENGTH {
                    // Garbage size; not a real header. Continue scanning.
                    wlen = 0;
                    bytes_scanned += 24; // Account for consumed header
                    continue;
                }

                let mut payload = vec![0u8; payload_size as usize];
                if payload_size > 0 {
                    self.stream
                        .read_exact(&mut payload)
                        .await
                        .map_err(|e| {
                            self.state = PeerState::Disconnected;
                            PeerError::Io(format!("Resync payload read error: {}", e))
                        })?;
                }

                let full = [&header[..], &payload[..]].concat();
                if let Ok(msg) = Message::deserialize(&full, self.network) {
                    return Ok(Some(msg));
                }
                // Checksum/format failed; 4 bytes matched by coincidence. Consumed 24+payload.
                bytes_scanned += 24 + payload_size as usize;
                wlen = 0;
            }
        }

        Ok(None)
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

    /// Consume this peer and return its TCP stream, address, and network.
    ///
    /// Used by block sync tasks that split the stream into read/write halves
    /// for concurrent, cancellation-safe I/O. Call `from_stream` to reconstruct.
    pub fn into_parts(self) -> (TcpStream, SocketAddr, Network) {
        (self.stream, self.addr, self.network)
    }

    /// Reconstruct a connected peer from a TCP stream.
    ///
    /// Used to reconstitute a Peer after splitting for block sync tasks.
    /// The peer is set to Connected state with a default score.
    pub fn from_stream(stream: TcpStream, addr: SocketAddr, network: Network) -> Self {
        Self {
            addr,
            stream,
            version: None,
            services: 0,
            state: PeerState::Connected,
            network,
            score: PeerScore::default(),
            default_timeout: Duration::from_secs(30),
        }
    }
}

/// Ring buffer that wraps an async reader and records the last N bytes read.
/// Used for post-mortem diagnostics when a stream desync (InvalidMagic /
/// PayloadSizeExceeded) is detected — the buffer contents reveal what data
/// preceded the corrupt header.
pub struct DiagnosticReader<R> {
    inner: R,
    ring: Vec<u8>,
    pos: usize,
    len: usize,
}

impl<R> DiagnosticReader<R> {
    const CAPACITY: usize = 256;

    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            ring: vec![0u8; Self::CAPACITY],
            pos: 0,
            len: 0,
        }
    }

    fn record(&mut self, data: &[u8]) {
        for &b in data {
            self.ring[self.pos] = b;
            self.pos = (self.pos + 1) % Self::CAPACITY;
            if self.len < Self::CAPACITY {
                self.len += 1;
            }
        }
    }

    /// Return the last N bytes in order (oldest first).
    pub fn dump_hex(&self) -> String {
        if self.len == 0 {
            return String::from("(empty)");
        }
        let start = if self.len < Self::CAPACITY {
            0
        } else {
            self.pos
        };
        let mut out = String::with_capacity(self.len * 3);
        for i in 0..self.len {
            let idx = (start + i) % Self::CAPACITY;
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&format!("{:02x}", self.ring[idx]));
        }
        out
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncReadExt + Unpin> DiagnosticReader<R> {
    async fn read_exact_recorded(&mut self, buf: &mut [u8]) -> std::result::Result<(), std::io::Error> {
        self.inner.read_exact(buf).await?;
        self.record(buf);
        Ok(())
    }
}

/// Read a single Bitcoin P2P message from an async reader wrapped in a
/// [`DiagnosticReader`].
///
/// Designed for long-lived block sync tasks where the TCP stream is split into
/// read/write halves. When called via a pinned future (`tokio::pin!` +
/// `&mut future`) inside `tokio::select!`, the read is never interrupted
/// mid-stream, preventing desyncs from async cancellation.
///
/// Behaviour aligned with Bitcoin Core's V1Transport (`net.cpp`):
/// - **Bad magic / oversized payload** → disconnect (return Err).
/// - **Bad checksum** → drop the message and read the next one (Bitcoin Core
///   sets `reject_message = true` but keeps the connection alive).
/// - **Invalid command type** (non-ASCII, non-zero padding after null) → drop
///   and continue, matching `IsMessageTypeValid()` in `protocol.cpp`.
///
/// On desync, logs the last 256 bytes from the ring buffer for post-mortem
/// analysis.
pub async fn read_network_message<R: AsyncReadExt + Unpin>(
    reader: &mut DiagnosticReader<R>,
    network: Network,
) -> Result<Message> {
    // Bitcoin Core uses 4 * 1000 * 1000 (MAX_PROTOCOL_MESSAGE_LENGTH in net.h).
    // We match that exactly for parity.
    const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;

    let expected_magic = get_magic(network);

    loop {
        // Read 24-byte message header
        let mut header = [0u8; 24];
        reader.read_exact_recorded(&mut header).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                PeerError::ConnectionClosed
            } else {
                PeerError::Io(format!("Read header error: {}", e))
            }
        })?;

        // Validate magic
        let header_magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if header_magic != expected_magic {
            log::warn!(
                "Stream desync: InvalidMagic expected={:08x} got={:08x} header={} ring_buffer=[{}]",
                expected_magic,
                header_magic,
                header.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                reader.dump_hex()
            );
            return Err(PeerError::Message(MessageError::InvalidMagic {
                expected: expected_magic,
                actual: header_magic,
            }));
        }

        // Parse command — match Bitcoin Core's IsMessageTypeValid():
        // bytes before first null must be printable ASCII (' '..=0x7f),
        // bytes after first null must all be 0x00.
        let command_bytes = &header[4..16];
        let null_pos = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
        let cmd_slice = &command_bytes[..null_pos];

        let command_valid = cmd_slice.iter().all(|&b| b >= b' ' && b <= 0x7f)
            && command_bytes[null_pos..].iter().all(|&b| b == 0);

        let command = if command_valid && !cmd_slice.is_empty() {
            // Safe: we verified printable ASCII above
            String::from_utf8(cmd_slice.to_vec()).ok()
        } else {
            None
        };

        // Parse payload size
        let payload_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);

        if payload_size > MAX_PROTOCOL_MESSAGE_LENGTH {
            log::warn!(
                "Stream desync: PayloadSizeExceeded size={} limit={} cmd={} header={} ring_buffer=[{}]",
                payload_size,
                MAX_PROTOCOL_MESSAGE_LENGTH,
                command.as_deref().unwrap_or("(invalid)"),
                header.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                reader.dump_hex()
            );
            return Err(PeerError::Message(MessageError::PayloadSizeExceeded {
                size: payload_size,
                limit: MAX_PROTOCOL_MESSAGE_LENGTH,
            }));
        }

        // Parse checksum from header
        let checksum = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);

        // Read payload
        let mut payload = vec![0u8; payload_size as usize];
        if payload_size > 0 {
            reader.read_exact_recorded(&mut payload).await.map_err(|e| {
                PeerError::Io(format!(
                    "Read payload error (cmd={}, size={}): {}",
                    command.as_deref().unwrap_or("?"), payload_size, e
                ))
            })?;
        }

        // Verify checksum — Bitcoin Core behaviour: bad checksum → reject message,
        // don't disconnect. The stream is still aligned (we consumed header + payload).
        let calculated_checksum = crate::network::messages::calculate_checksum(&payload);
        if checksum != calculated_checksum {
            log::warn!(
                "Bad checksum (cmd={}, size={}): expected {:08x}, got {:08x} — dropping message (Bitcoin Core compat)",
                command.as_deref().unwrap_or("?"),
                payload_size,
                calculated_checksum,
                checksum
            );
            continue;
        }

        // Invalid command type — Bitcoin Core rejects but keeps connection.
        // Stream is aligned since we read the full payload.
        let Some(command) = command else {
            log::debug!(
                "Invalid message type, dropping (size={}): cmd_bytes={}",
                payload_size,
                header[4..16].iter().map(|b| format!("{:02x}", b)).collect::<String>()
            );
            continue;
        };

        return Ok(Message {
            magic: expected_magic,
            command,
            payload_size,
            checksum,
            payload,
        });
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

