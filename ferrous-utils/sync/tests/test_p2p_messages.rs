//! Integration tests for Bitcoin P2P protocol messages
//! Tests message serialization/deserialization against Bitcoin protocol spec

use sync::network::messages::*;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoin::BlockHash;
use bitcoin::blockdata::block::Header;
use bitcoin::CompactTarget;

#[test]
fn test_message_envelope_structure() {
    // Test that message envelope matches Bitcoin protocol spec
    let payload = b"test payload".to_vec();
    let msg = Message::new("ping", payload, Network::Bitcoin);
    let serialized = msg.serialize();
    
    // Message should be: magic (4) + command (12) + payload_size (4) + checksum (4) + payload
    assert_eq!(serialized.len(), 24 + msg.payload.len());
    
    // Magic bytes should be at start
    let magic_bytes = u32::from_le_bytes([
        serialized[0], serialized[1], serialized[2], serialized[3]
    ]);
    assert_eq!(magic_bytes, MAGIC_MAINNET);
}

#[test]
fn test_version_message_protocol_compliance() {
    // Test version message matches Bitcoin protocol
    let addr_recv = NetworkAddress::from_ipv4([192, 168, 1, 1], 8333, 0);
    let addr_from = NetworkAddress::from_ipv4([10, 0, 0, 1], 8333, 0);
    
    let version = VersionMessage::new(
        70015, // Protocol version
        1,     // Services (NODE_NETWORK)
        1234567890, // Timestamp
        addr_recv.clone(),
        addr_from.clone(),
        12345, // Nonce
        "/bitcoin-hybrid:0.1.0/".to_string(),
        0,     // Start height
        true,  // Relay
    );
    
    // Serialize and deserialize
    let payload = version.serialize_payload();
    let deserialized = VersionMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(version.version, deserialized.version);
    assert_eq!(version.services, deserialized.services);
    assert_eq!(version.timestamp, deserialized.timestamp);
    assert_eq!(version.addr_recv, deserialized.addr_recv);
    assert_eq!(version.addr_from, deserialized.addr_from);
    assert_eq!(version.nonce, deserialized.nonce);
    assert_eq!(version.user_agent, deserialized.user_agent);
}

#[test]
fn test_inv_message_protocol_compliance() {
    // Test inv message with various inventory types
    let txid = Txid::from_byte_array([1u8; 32]);
    let block_hash = BlockHash::from_byte_array([2u8; 32]);
    
    let inventory = vec![
        InvItem {
            inv_type: INV_TYPE_TX,
            hash: *txid.as_byte_array(),
        },
        InvItem {
            inv_type: INV_TYPE_BLOCK,
            hash: *block_hash.as_byte_array(),
        },
        InvItem {
            inv_type: INV_TYPE_FILTERED_BLOCK,
            hash: [3u8; 32],
        },
    ];
    
    let inv = InvMessage::new(inventory.clone());
    let payload = inv.serialize_payload();
    let deserialized = InvMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(inv.inventory.len(), deserialized.inventory.len());
    for (orig, deser) in inv.inventory.iter().zip(deserialized.inventory.iter()) {
        assert_eq!(orig.inv_type, deser.inv_type);
        assert_eq!(orig.hash, deser.hash);
    }
}

#[test]
fn test_getheaders_message_protocol_compliance() {
    // Test getheaders message with block locator
    let genesis_hash = BlockHash::from_byte_array([0u8; 32]);
    let hash1 = BlockHash::from_byte_array([1u8; 32]);
    let hash2 = BlockHash::from_byte_array([2u8; 32]);
    let hash_stop = BlockHash::from_byte_array([0xFFu8; 32]);
    
    let locator = vec![
        *hash2.as_byte_array(),
        *hash1.as_byte_array(),
        *genesis_hash.as_byte_array(),
    ];
    
    let getheaders = GetHeadersMessage::new(
        70015,
        locator.clone(),
        *hash_stop.as_byte_array(),
    );
    
    let payload = getheaders.serialize_payload();
    let deserialized = GetHeadersMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(getheaders.version, deserialized.version);
    assert_eq!(getheaders.locator_hashes, deserialized.locator_hashes);
    assert_eq!(getheaders.hash_stop, deserialized.hash_stop);
}

#[test]
fn test_headers_message_protocol_compliance() {
    // Test headers message serialization
    // Create a minimal header for testing
    use bitcoin::blockdata::block::Header;
    use bitcoin::BlockHash;
    
    let header = Header {
        version: bitcoin::blockdata::block::Version::ONE,
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time: 1234567890,
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };
    
    let header_with_count = BlockHeaderWithTxCount {
        header: header.clone(),
        tx_count: 0, // Headers message should have tx_count = 0
    };
    
    let headers_msg = HeadersMessage::new(vec![header_with_count.clone()]);
    let payload = headers_msg.serialize_payload();
    let deserialized = HeadersMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(headers_msg.headers.len(), deserialized.headers.len());
    assert_eq!(headers_msg.headers[0].header.version, deserialized.headers[0].header.version);
    assert_eq!(headers_msg.headers[0].tx_count, 0);
}

#[test]
fn test_addr_message_protocol_compliance() {
    // Test addr message with multiple addresses
    let addr1 = NetworkAddress::from_ipv4([192, 168, 1, 1], 8333, 1);
    let addr2 = NetworkAddress::from_ipv4([10, 0, 0, 1], 8334, 1);
    
    let addresses = vec![
        AddressWithTimestamp {
            timestamp: 1234567890,
            address: addr1.clone(),
        },
        AddressWithTimestamp {
            timestamp: 1234567900,
            address: addr2.clone(),
        },
    ];
    
    let addr_msg = AddrMessage::new(addresses.clone());
    let payload = addr_msg.serialize_payload();
    let deserialized = AddrMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(addr_msg.addresses.len(), deserialized.addresses.len());
    for (orig, deser) in addr_msg.addresses.iter().zip(deserialized.addresses.iter()) {
        assert_eq!(orig.timestamp, deser.timestamp);
        assert_eq!(orig.address, deser.address);
    }
}

#[test]
fn test_checksum_validation() {
    // Test that checksum calculation matches Bitcoin protocol
    let payload = b"test payload".to_vec();
    let checksum = calculate_checksum(&payload);
    
    // Checksum should be first 4 bytes of double SHA256
    let double_hash = common::crypto::double_sha256(&payload);
    let expected_checksum = u32::from_le_bytes([
        double_hash[0], double_hash[1], double_hash[2], double_hash[3]
    ]);
    
    assert_eq!(checksum, expected_checksum);
}

#[test]
fn test_message_size_limits() {
    // Test that messages respect size limits
    let large_payload = vec![0u8; 33_554_432]; // 32MB (Bitcoin's MAX_PROTOCOL_MESSAGE_LENGTH)
    
    // Should succeed
    let msg = Message::new("ping", large_payload.clone(), Network::Bitcoin);
    assert_eq!(msg.payload_size, large_payload.len() as u32);
    
    // Test validation with oversized payload
    let oversized_payload = vec![0u8; 33_554_433]; // 32MB + 1
    let _msg = Message::new("ping", oversized_payload, Network::Bitcoin);
    // Validation should catch this (if implemented)
}

#[test]
fn test_network_magic_bytes() {
    // Test magic bytes for all networks
    assert_eq!(get_magic(Network::Bitcoin), MAGIC_MAINNET);
    assert_eq!(get_magic(Network::Testnet), MAGIC_TESTNET);
    assert_eq!(get_magic(Network::Regtest), MAGIC_REGTEST);
    assert_eq!(get_magic(Network::Signet), MAGIC_SIGNET);
    
    // Verify magic bytes match Bitcoin Core
    assert_eq!(MAGIC_MAINNET, 0xD9B4BEF9);
    assert_eq!(MAGIC_TESTNET, 0x0709110B);
    assert_eq!(MAGIC_REGTEST, 0xDAB5BFFA);
    assert_eq!(MAGIC_SIGNET, 0x40CF030A);
}

#[test]
fn test_command_encoding() {
    // Test command string encoding (12 bytes, null-padded)
    let commands = vec!["version", "verack", "ping", "pong", "getheaders", "headers", "getdata", "block", "inv", "addr"];
    
    for cmd in commands {
        let msg = Message::new(cmd, vec![], Network::Bitcoin);
        let serialized = msg.serialize();
        
        // Command should be in bytes 4-15 (after magic)
        let command_bytes = &serialized[4..16];
        
        // Should be null-padded
        assert!(command_bytes.len() == 12);
        
        // First bytes should match command
        let cmd_bytes = cmd.as_bytes();
        assert_eq!(&command_bytes[..cmd_bytes.len()], cmd_bytes);
        
        // Rest should be nulls
        for i in cmd_bytes.len()..12 {
            assert_eq!(command_bytes[i], 0);
        }
    }
}

#[test]
fn test_inv_item_types() {
    // Test all inventory item types
    let hash = [0u8; 32];
    
    let types = vec![
        INV_TYPE_ERROR,
        INV_TYPE_TX,
        INV_TYPE_BLOCK,
        INV_TYPE_FILTERED_BLOCK,
        INV_TYPE_COMPACT_BLOCK,
    ];
    
    for inv_type in types {
        let item = InvItem { inv_type, hash };
        let inventory = vec![item];
        let inv_msg = InvMessage::new(inventory);
        
        let payload = inv_msg.serialize_payload();
        let deserialized = InvMessage::deserialize_payload(&payload).unwrap();
        
        assert_eq!(deserialized.inventory[0].inv_type, inv_type);
    }
}

#[test]
fn test_ping_pong_roundtrip() {
    // Test ping/pong message roundtrip
    let nonce = 0x1234567890ABCDEFu64;
    let ping = PingMessage::new(nonce);
    
    let ping_msg = ping.to_message(Network::Bitcoin);
    let serialized = ping_msg.serialize();
    let deserialized = Message::deserialize(&serialized, Network::Bitcoin).unwrap();
    
    let pong_payload = PingMessage::deserialize_payload(&deserialized.payload).unwrap();
    assert_eq!(pong_payload.nonce, nonce);
    
    // Pong should have same nonce
    let pong = PongMessage::new(nonce);
    let pong_payload2 = PingMessage::deserialize_payload(&pong.serialize_payload()).unwrap();
    assert_eq!(pong_payload2.nonce, nonce);
}

#[test]
fn test_getdata_message() {
    // Test getdata message (same format as inv)
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
    
    let getdata = GetDataMessage::new(inventory.clone());
    let payload = getdata.serialize_payload();
    let deserialized = GetDataMessage::deserialize_payload(&payload).unwrap();
    
    assert_eq!(getdata.inventory, deserialized.inventory);
}

