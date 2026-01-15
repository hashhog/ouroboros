//! Tests for cryptographic operations

use common::crypto::*;

#[test]
fn test_double_sha256() {
    // Test with empty input
    let empty = b"";
    let result = double_sha256(empty);
    // Known value: double SHA256 of empty string
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // SHA256(e3b0c442...) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    let expected = [
        0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
        0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
        0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
        0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
    ];
    assert_eq!(result, expected);
}

#[test]
fn test_hash160() {
    // Test hash160 calculation
    let data = b"hello";
    let result = hash160(data);
    assert_eq!(result.len(), 20);
}

#[test]
fn test_merkle_root_single_tx() {
    // Merkle root of block with single transaction should equal the txid
    let txid = [0u8; 32];
    let txids = vec![txid];
    let root = compute_merkle_root(&txids);
    assert_eq!(root, txid);
}

#[test]
fn test_merkle_root_two_tx() {
    // Test merkle root with two transactions
    let txid1 = [1u8; 32];
    let txid2 = [2u8; 32];
    let txids = vec![txid1, txid2];
    let root = compute_merkle_root(&txids);
    
    // Should be double SHA256 of concatenated hashes
    let mut combined = Vec::new();
    combined.extend_from_slice(&txid1);
    combined.extend_from_slice(&txid2);
    let expected = double_sha256(&combined);
    assert_eq!(root, expected);
}

#[test]
fn test_bits_to_target() {
    // Test compact representation conversion
    // Example: difficulty 1 (mainnet genesis)
    let bits = 0x1d00ffff;
    let target = bits_to_target(bits);
    assert!(target > 0.into());
}

#[test]
fn test_target_to_bits() {
    // Test reverse conversion
    let bits = 0x1d00ffff;
    let target = bits_to_target(bits);
    let converted_bits = target_to_bits(target);
    assert_eq!(converted_bits, bits);
}

