//! Bitcoin P2P protocol messages

use bitcoin::Network;
use common::crypto::double_sha256;
use thiserror::Error;

/// Bitcoin P2P magic bytes for different networks
pub const MAGIC_MAINNET: u32 = 0xD9B4BEF9;
pub const MAGIC_TESTNET: u32 = 0x0709110B;
pub const MAGIC_REGTEST: u32 = 0xDAB5BFFA;
pub const MAGIC_SIGNET: u32 = 0x40CF030A;

/// Get magic bytes for a network
pub fn get_magic(network: Network) -> u32 {
    match network {
        Network::Bitcoin => MAGIC_MAINNET,
        Network::Testnet => MAGIC_TESTNET,
        Network::Regtest => MAGIC_REGTEST,
        Network::Signet => MAGIC_SIGNET,
        Network::Testnet4 => MAGIC_TESTNET, // Testnet4 uses same magic as Testnet
    }
}

/// Message validation error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    #[error("Invalid magic bytes: expected {expected:08x}, got {actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("Invalid checksum: expected {expected:08x}, got {actual:08x}")]
    InvalidChecksum { expected: u32, actual: u32 },

    #[error("Payload size exceeds limit: {size} > {limit}")]
    PayloadSizeExceeded { size: u32, limit: u32 },

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid message format")]
    InvalidFormat,
}

/// Bitcoin P2P message envelope
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub magic: u32,
    pub command: String,
    pub payload_size: u32,
    pub checksum: u32,
    pub payload: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(command: &str, payload: Vec<u8>, network: Network) -> Self {
        let magic = get_magic(network);
        let checksum = calculate_checksum(&payload);
        let payload_size = payload.len() as u32;

        Self {
            magic,
            command: command.to_string(),
            payload_size,
            checksum,
            payload,
        }
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(24 + self.payload.len());

        // Magic (4 bytes, little-endian)
        data.extend_from_slice(&self.magic.to_le_bytes());

        // Command (12 bytes, null-padded)
        let command_bytes = command_to_bytes(&self.command);
        data.extend_from_slice(&command_bytes);

        // Payload size (4 bytes, little-endian)
        data.extend_from_slice(&self.payload_size.to_le_bytes());

        // Checksum (4 bytes, little-endian)
        data.extend_from_slice(&self.checksum.to_le_bytes());

        // Payload
        data.extend_from_slice(&self.payload);

        data
    }

    /// Deserialize message from bytes
    pub fn deserialize(data: &[u8], network: Network) -> Result<Self, MessageError> {
        if data.len() < 24 {
            return Err(MessageError::InvalidFormat);
        }

        // Read magic (4 bytes)
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let expected_magic = get_magic(network);
        if magic != expected_magic {
            return Err(MessageError::InvalidMagic {
                expected: expected_magic,
                actual: magic,
            });
        }

        // Read command (12 bytes, null-terminated)
        let mut command_bytes = [0u8; 12];
        command_bytes.copy_from_slice(&data[4..16]);
        let command = bytes_to_command(&command_bytes)?;

        // Read payload size (4 bytes)
        let payload_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        // Read checksum (4 bytes)
        let checksum = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // Validate payload size
        const MAX_PAYLOAD_SIZE: u32 = 32 * 1024 * 1024; // 32MB limit
        if payload_size > MAX_PAYLOAD_SIZE {
            return Err(MessageError::PayloadSizeExceeded {
                size: payload_size,
                limit: MAX_PAYLOAD_SIZE,
            });
        }

        // Read payload
        if data.len() < 24 + payload_size as usize {
            return Err(MessageError::InvalidFormat);
        }

        let payload = data[24..24 + payload_size as usize].to_vec();

        // Verify checksum
        let calculated_checksum = calculate_checksum(&payload);
        if checksum != calculated_checksum {
            return Err(MessageError::InvalidChecksum {
                expected: calculated_checksum,
                actual: checksum,
            });
        }

        Ok(Self {
            magic,
            command,
            payload_size,
            checksum,
            payload,
        })
    }

    /// Validate message
    pub fn validate(&self, network: Network) -> Result<(), MessageError> {
        // Check magic
        let expected_magic = get_magic(network);
        if self.magic != expected_magic {
            return Err(MessageError::InvalidMagic {
                expected: expected_magic,
                actual: self.magic,
            });
        }

        // Check payload size
        if self.payload.len() as u32 != self.payload_size {
            return Err(MessageError::InvalidFormat);
        }

        // Check checksum
        let calculated_checksum = calculate_checksum(&self.payload);
        if self.checksum != calculated_checksum {
            return Err(MessageError::InvalidChecksum {
                expected: calculated_checksum,
                actual: self.checksum,
            });
        }

        Ok(())
    }
}

/// Calculate message checksum (first 4 bytes of double SHA-256)
fn calculate_checksum(payload: &[u8]) -> u32 {
    let hash = double_sha256(payload);
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// Convert command string to 12-byte array (null-padded)
fn command_to_bytes(command: &str) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    let cmd_bytes = command.as_bytes();
    let len = cmd_bytes.len().min(12);
    bytes[..len].copy_from_slice(&cmd_bytes[..len]);
    bytes
}

/// Convert 12-byte command array to string
fn bytes_to_command(bytes: &[u8; 12]) -> Result<String, MessageError> {
    // Find null terminator
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(12);
    
    // Extract command string
    let cmd_bytes = &bytes[..null_pos];
    
    // Validate ASCII
    if !cmd_bytes.is_ascii() {
        return Err(MessageError::InvalidCommand("Non-ASCII characters".to_string()));
    }

    Ok(String::from_utf8(cmd_bytes.to_vec())
        .map_err(|e| MessageError::InvalidCommand(format!("Invalid UTF-8: {}", e)))?)
}

// ========== Message Types ==========

/// Version message for handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// Network address structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddress {
    pub services: u64,
    pub ip: [u8; 16], // IPv6 address (IPv4 mapped)
    pub port: u16,
}

impl NetworkAddress {
    /// Create IPv4 address
    pub fn from_ipv4(ip: [u8; 4], port: u16, services: u64) -> Self {
        let mut ipv6 = [0u8; 16];
        // IPv4-mapped IPv6 address (::ffff:ipv4)
        ipv6[10] = 0xff;
        ipv6[11] = 0xff;
        ipv6[12..16].copy_from_slice(&ip);
        
        Self {
            services,
            ip: ipv6,
            port,
        }
    }
}

impl VersionMessage {
    /// Create a new version message
    pub fn new(
        version: i32,
        services: u64,
        timestamp: i64,
        addr_recv: NetworkAddress,
        addr_from: NetworkAddress,
        nonce: u64,
        user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Self {
        Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        }
    }

    /// Serialize version message payload
    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        let mut encoder = Vec::new();

        // Version (4 bytes)
        self.version.consensus_encode(&mut encoder).unwrap();
        
        // Services (8 bytes)
        self.services.consensus_encode(&mut encoder).unwrap();
        
        // Timestamp (8 bytes)
        self.timestamp.consensus_encode(&mut encoder).unwrap();
        
        // Address receiving (26 bytes)
        serialize_network_address(&self.addr_recv, &mut encoder);
        
        // Address from (26 bytes)
        serialize_network_address(&self.addr_from, &mut encoder);
        
        // Nonce (8 bytes)
        self.nonce.consensus_encode(&mut encoder).unwrap();
        
        // User agent (varint length + bytes)
        let user_agent_bytes = self.user_agent.as_bytes();
        use common::serialize::encode_varint;
        encoder.extend_from_slice(&encode_varint(user_agent_bytes.len() as u64));
        encoder.extend_from_slice(user_agent_bytes);
        
        // Start height (4 bytes)
        self.start_height.consensus_encode(&mut encoder).unwrap();
        
        // Relay (1 byte, optional in newer versions)
        if self.version >= 70001 {
            encoder.push(if self.relay { 1 } else { 0 });
        }

        encoder
    }

    /// Deserialize version message payload
    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        use common::serialize::decode_varint;
        let mut decoder = &data[..];

        // Version (4 bytes)
        let version = i32::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Version: {}", e)))?;
        
        // Services (8 bytes)
        let services = u64::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Services: {}", e)))?;
        
        // Timestamp (8 bytes)
        let timestamp = i64::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Timestamp: {}", e)))?;
        
        // Address receiving (26 bytes)
        let addr_recv = deserialize_network_address(&mut decoder)?;
        
        // Address from (26 bytes)
        let addr_from = deserialize_network_address(&mut decoder)?;
        
        // Nonce (8 bytes)
        let nonce = u64::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Nonce: {}", e)))?;
        
        // User agent (varint length + bytes)
        let (ua_len, consumed) = decode_varint(decoder)
            .map_err(|e| MessageError::DeserializationError(format!("User agent length: {}", e)))?;
        decoder = &decoder[consumed..];
        let user_agent = String::from_utf8(decoder[..ua_len as usize].to_vec())
            .map_err(|e| MessageError::DeserializationError(format!("User agent: {}", e)))?;
        decoder = &decoder[ua_len as usize..];
        
        // Start height (4 bytes)
        let start_height = i32::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Start height: {}", e)))?;
        
        // Relay (1 byte, optional)
        let relay = if decoder.is_empty() {
            false // Default to false if not present
        } else {
            decoder[0] != 0
        };

        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }

    /// Convert to Message envelope
    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("version", payload, network)
    }
}

/// Serialize network address
fn serialize_network_address(addr: &NetworkAddress, encoder: &mut Vec<u8>) {
    use bitcoin::consensus::Encodable;
    
    // Services (8 bytes)
    addr.services.consensus_encode(encoder).unwrap();
    
    // IP address (16 bytes)
    encoder.extend_from_slice(&addr.ip);
    
    // Port (2 bytes, network byte order)
    encoder.extend_from_slice(&addr.port.to_be_bytes());
}

/// Deserialize network address
fn deserialize_network_address(decoder: &mut &[u8]) -> Result<NetworkAddress, MessageError> {
    use bitcoin::consensus::Decodable;
    
    if decoder.len() < 26 {
        return Err(MessageError::InvalidFormat);
    }
    
    // Services (8 bytes)
    let services = u64::consensus_decode(decoder)
        .map_err(|e| MessageError::DeserializationError(format!("Address services: {}", e)))?;
    
    // IP address (16 bytes)
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&decoder[..16]);
    *decoder = &decoder[16..];
    
    // Port (2 bytes, network byte order)
    let port = u16::from_be_bytes([decoder[0], decoder[1]]);
    *decoder = &decoder[2..];
    
    Ok(NetworkAddress { services, ip, port })
}

/// VerAck message (empty payload)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerAckMessage;

impl VerAckMessage {
    pub fn to_message(&self, network: Network) -> Message {
        Message::new("verack", vec![], network)
    }

    pub fn from_message(_msg: &Message) -> Result<Self, MessageError> {
        Ok(VerAckMessage)
    }
}

/// Ping message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingMessage {
    pub nonce: u64,
}

impl PingMessage {
    pub fn new(nonce: u64) -> Self {
        Self { nonce }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        let mut encoder = Vec::new();
        self.nonce.consensus_encode(&mut encoder).unwrap();
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        let mut decoder = data;
        let nonce = u64::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Ping nonce: {}", e)))?;
        Ok(Self { nonce })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("ping", payload, network)
    }
}

/// Pong message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongMessage {
    pub nonce: u64,
}

impl PongMessage {
    pub fn new(nonce: u64) -> Self {
        Self { nonce }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        let mut encoder = Vec::new();
        self.nonce.consensus_encode(&mut encoder).unwrap();
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        let mut decoder = data;
        let nonce = u64::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Pong nonce: {}", e)))?;
        Ok(Self { nonce })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("pong", payload, network)
    }
}

/// Inventory type constants
pub const INV_TYPE_ERROR: u32 = 0;
pub const INV_TYPE_TX: u32 = 1;
pub const INV_TYPE_BLOCK: u32 = 2;
pub const INV_TYPE_FILTERED_BLOCK: u32 = 3;
pub const INV_TYPE_COMPACT_BLOCK: u32 = 4;

/// Inventory item (type + hash)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvItem {
    pub inv_type: u32,
    pub hash: [u8; 32],
}

/// Inv message (announces inventory)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvMessage {
    pub inventory: Vec<InvItem>,
}

impl InvMessage {
    pub fn new(inventory: Vec<InvItem>) -> Self {
        Self { inventory }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        use common::serialize::encode_varint;
        
        let mut encoder = Vec::new();
        
        // Count (varint)
        encoder.extend_from_slice(&encode_varint(self.inventory.len() as u64));
        
        // Inventory items (4 bytes type + 32 bytes hash each)
        for item in &self.inventory {
            item.inv_type.consensus_encode(&mut encoder).unwrap();
            encoder.extend_from_slice(&item.hash);
        }
        
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        use common::serialize::decode_varint;
        
        let mut decoder = data;
        
        // Count (varint)
        let (count, consumed) = decode_varint(decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Inv count: {}", e)))?;
        decoder = &decoder[consumed..];
        
        let mut inventory = Vec::with_capacity(count.min(50000) as usize); // Limit to 50k items
        
        // Inventory items
        for _ in 0..count {
            if decoder.len() < 36 {
                return Err(MessageError::InvalidFormat);
            }
            
            let inv_type = u32::consensus_decode(&mut decoder)
                .map_err(|e| MessageError::DeserializationError(format!("Inv type: {}", e)))?;
            
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&decoder[..32]);
            decoder = &decoder[32..];
            
            inventory.push(InvItem { inv_type, hash });
        }
        
        Ok(Self { inventory })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("inv", payload, network)
    }
}

/// GetData message (requests blocks/transactions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDataMessage {
    pub inventory: Vec<InvItem>,
}

impl GetDataMessage {
    pub fn new(inventory: Vec<InvItem>) -> Self {
        Self { inventory }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        // Same format as InvMessage
        InvMessage::new(self.inventory.clone()).serialize_payload()
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        let inv_msg = InvMessage::deserialize_payload(data)?;
        Ok(Self {
            inventory: inv_msg.inventory,
        })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("getdata", payload, network)
    }
}

/// GetHeaders message (requests block headers)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMessage {
    pub version: i32,
    pub locator_hashes: Vec<[u8; 32]>,
    pub hash_stop: [u8; 32],
}

impl GetHeadersMessage {
    pub fn new(version: i32, locator_hashes: Vec<[u8; 32]>, hash_stop: [u8; 32]) -> Self {
        Self {
            version,
            locator_hashes,
            hash_stop,
        }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        use common::serialize::encode_varint;
        
        let mut encoder = Vec::new();
        
        // Version (4 bytes)
        self.version.consensus_encode(&mut encoder).unwrap();
        
        // Hash count (varint)
        encoder.extend_from_slice(&encode_varint(self.locator_hashes.len() as u64));
        
        // Locator hashes (32 bytes each)
        for hash in &self.locator_hashes {
            encoder.extend_from_slice(hash);
        }
        
        // Hash stop (32 bytes)
        encoder.extend_from_slice(&self.hash_stop);
        
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        use common::serialize::decode_varint;
        
        let mut decoder = data;
        
        // Version (4 bytes)
        let version = i32::consensus_decode(&mut decoder)
            .map_err(|e| MessageError::DeserializationError(format!("GetHeaders version: {}", e)))?;
        
        // Hash count (varint)
        let (count, consumed) = decode_varint(decoder)
            .map_err(|e| MessageError::DeserializationError(format!("GetHeaders count: {}", e)))?;
        decoder = &decoder[consumed..];
        
        if count > 2000 {
            return Err(MessageError::DeserializationError("Too many locator hashes".to_string()));
        }
        
        // Locator hashes
        let mut locator_hashes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if decoder.len() < 32 {
                return Err(MessageError::InvalidFormat);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&decoder[..32]);
            decoder = &decoder[32..];
            locator_hashes.push(hash);
        }
        
        // Hash stop (32 bytes)
        if decoder.len() < 32 {
            return Err(MessageError::InvalidFormat);
        }
        let mut hash_stop = [0u8; 32];
        hash_stop.copy_from_slice(&decoder[..32]);
        
        Ok(Self {
            version,
            locator_hashes,
            hash_stop,
        })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("getheaders", payload, network)
    }
}

/// Headers message (delivers block headers)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeaderWithTxCount>,
}

/// Block header with transaction count
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderWithTxCount {
    pub header: bitcoin::blockdata::block::Header,
    pub tx_count: u8, // Should be 0 for headers message
}

impl HeadersMessage {
    pub fn new(headers: Vec<BlockHeaderWithTxCount>) -> Self {
        Self { headers }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        use common::serialize::encode_varint;
        
        let mut encoder = Vec::new();
        
        // Header count (varint)
        encoder.extend_from_slice(&encode_varint(self.headers.len() as u64));
        
        // Headers (80 bytes header + 1 byte tx_count each)
        for header_with_count in &self.headers {
            header_with_count.header.consensus_encode(&mut encoder).unwrap();
            encoder.push(header_with_count.tx_count);
        }
        
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        use common::serialize::decode_varint;
        
        let mut decoder = data;
        
        // Header count (varint)
        let (count, consumed) = decode_varint(decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Headers count: {}", e)))?;
        decoder = &decoder[consumed..];
        
        if count > 2000 {
            return Err(MessageError::DeserializationError("Too many headers".to_string()));
        }
        
        // Headers
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if decoder.len() < 81 {
                return Err(MessageError::InvalidFormat);
            }
            
            let header = bitcoin::blockdata::block::Header::consensus_decode(&mut decoder)
                .map_err(|e| MessageError::DeserializationError(format!("Block header: {}", e)))?;
            
            let tx_count = decoder[0];
            decoder = &decoder[1..];
            
            headers.push(BlockHeaderWithTxCount { header, tx_count });
        }
        
        Ok(Self { headers })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("headers", payload, network)
    }
}

/// Block message (delivers a block)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMessage {
    pub block: bitcoin::Block,
}

impl BlockMessage {
    pub fn new(block: bitcoin::Block) -> Self {
        Self { block }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        let mut encoder = Vec::new();
        self.block.consensus_encode(&mut encoder).unwrap();
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        let block = bitcoin::Block::consensus_decode(&mut &data[..])
            .map_err(|e| MessageError::DeserializationError(format!("Block: {}", e)))?;
        Ok(Self { block })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("block", payload, network)
    }
}

/// Addr message (shares peer addresses)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMessage {
    pub addresses: Vec<AddressWithTimestamp>,
}

/// Network address with timestamp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressWithTimestamp {
    pub timestamp: i64,
    pub address: NetworkAddress,
}

impl AddrMessage {
    pub fn new(addresses: Vec<AddressWithTimestamp>) -> Self {
        Self { addresses }
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        use common::serialize::encode_varint;
        
        let mut encoder = Vec::new();
        
        // Address count (varint)
        encoder.extend_from_slice(&encode_varint(self.addresses.len() as u64));
        
        // Addresses (8 bytes timestamp + 26 bytes address each)
        for addr_with_ts in &self.addresses {
            addr_with_ts.timestamp.consensus_encode(&mut encoder).unwrap();
            serialize_network_address(&addr_with_ts.address, &mut encoder);
        }
        
        encoder
    }

    pub fn deserialize_payload(data: &[u8]) -> Result<Self, MessageError> {
        use bitcoin::consensus::Decodable;
        use common::serialize::decode_varint;
        
        let mut decoder = data;
        
        // Address count (varint)
        let (count, consumed) = decode_varint(decoder)
            .map_err(|e| MessageError::DeserializationError(format!("Addr count: {}", e)))?;
        decoder = &decoder[consumed..];
        
        if count > 1000 {
            return Err(MessageError::DeserializationError("Too many addresses".to_string()));
        }
        
        // Addresses
        let mut addresses = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // Timestamp (8 bytes)
            let timestamp = i64::consensus_decode(&mut decoder)
                .map_err(|e| MessageError::DeserializationError(format!("Addr timestamp: {}", e)))?;
            
            // Address (26 bytes)
            let address = deserialize_network_address(&mut decoder)?;
            
            addresses.push(AddressWithTimestamp { timestamp, address });
        }
        
        Ok(Self { addresses })
    }

    pub fn to_message(&self, network: Network) -> Message {
        let payload = self.serialize_payload();
        Message::new("addr", payload, network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_message_serialize_deserialize() {
        let payload = b"test payload".to_vec();
        let original = Message::new("ping", payload.clone(), Network::Bitcoin);
        
        let serialized = original.serialize();
        let deserialized = Message::deserialize(&serialized, Network::Bitcoin).unwrap();
        
        assert_eq!(original.command, deserialized.command);
        assert_eq!(original.payload, deserialized.payload);
        assert_eq!(original.checksum, deserialized.checksum);
    }

    #[test]
    fn test_message_validation() {
        let payload = b"test".to_vec();
        let msg = Message::new("ping", payload, Network::Bitcoin);
        
        // Should validate successfully
        assert!(msg.validate(Network::Bitcoin).is_ok());
        
        // Should fail with wrong network
        assert!(msg.validate(Network::Testnet).is_err());
    }

    #[test]
    fn test_ping_pong() {
        let ping = PingMessage::new(12345);
        let ping_msg = ping.to_message(Network::Bitcoin);
        
        let serialized = ping_msg.serialize();
        let deserialized = Message::deserialize(&serialized, Network::Bitcoin).unwrap();
        
        let pong_payload = PingMessage::deserialize_payload(&deserialized.payload).unwrap();
        assert_eq!(pong_payload.nonce, 12345);
    }

    #[test]
    fn test_verack() {
        let verack = VerAckMessage;
        let verack_msg = verack.to_message(Network::Bitcoin);
        
        assert_eq!(verack_msg.command, "verack");
        assert_eq!(verack_msg.payload.len(), 0);
        
        let serialized = verack_msg.serialize();
        let deserialized = Message::deserialize(&serialized, Network::Bitcoin).unwrap();
        assert!(VerAckMessage::from_message(&deserialized).is_ok());
    }

    #[test]
    fn test_version_message() {
        let addr_recv = NetworkAddress::from_ipv4([127, 0, 0, 1], 8333, 0);
        let addr_from = NetworkAddress::from_ipv4([127, 0, 0, 1], 8333, 0);
        
        let version = VersionMessage::new(
            70015,
            0,
            1234567890,
            addr_recv.clone(),
            addr_from.clone(),
            12345,
            "/bitcoin-hybrid:0.1.0/".to_string(),
            0,
            true,
        );
        
        let payload = version.serialize_payload();
        let deserialized = VersionMessage::deserialize_payload(&payload).unwrap();
        
        assert_eq!(version.version, deserialized.version);
        assert_eq!(version.addr_recv, deserialized.addr_recv);
        assert_eq!(version.addr_from, deserialized.addr_from);
    }

    #[test]
    fn test_inv_message() {
        let inventory = vec![
            InvItem {
                inv_type: INV_TYPE_BLOCK,
                hash: [1u8; 32],
            },
            InvItem {
                inv_type: INV_TYPE_TX,
                hash: [2u8; 32],
            },
        ];
        
        let inv = InvMessage::new(inventory.clone());
        let payload = inv.serialize_payload();
        let deserialized = InvMessage::deserialize_payload(&payload).unwrap();
        
        assert_eq!(inv.inventory, deserialized.inventory);
    }

    #[test]
    fn test_magic_bytes() {
        assert_eq!(get_magic(Network::Bitcoin), MAGIC_MAINNET);
        assert_eq!(get_magic(Network::Testnet), MAGIC_TESTNET);
        assert_eq!(get_magic(Network::Regtest), MAGIC_REGTEST);
    }

    #[test]
    fn test_checksum() {
        let payload1 = b"test".to_vec();
        let payload2 = b"test".to_vec();
        let payload3 = b"different".to_vec();
        
        let checksum1 = calculate_checksum(&payload1);
        let checksum2 = calculate_checksum(&payload2);
        let checksum3 = calculate_checksum(&payload3);
        
        // Same payload should have same checksum
        assert_eq!(checksum1, checksum2);
        
        // Different payload should have different checksum
        assert_ne!(checksum1, checksum3);
    }
}

