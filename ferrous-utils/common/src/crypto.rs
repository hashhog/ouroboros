// Bitcoin cryptographic operations

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, Error as Secp256k1Error};
use bitcoin_hashes::{sha256d::Hash as Sha256dHash, hash160::Hash as Hash160Hash};
use primitive_types::U256;

/// Verify an ECDSA signature
///
/// # Arguments
/// * `sig` - The signature in compact format (64 bytes)
/// * `pubkey` - The public key in SEC1 format (33 or 65 bytes)
/// * `msg` - The message hash (32 bytes, SHA256 of the message)
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err` if there's an error parsing the signature or public key
pub fn verify_ecdsa_signature(
    sig: &[u8],
    pubkey: &[u8],
    msg: &[u8],
) -> Result<bool, Secp256k1Error> {
    let secp = Secp256k1::verification_only();
    
    // Parse public key
    let pubkey = PublicKey::from_slice(pubkey)?;
    
    // Parse signature (compact format: 64 bytes)
    let signature = Signature::from_compact(sig)?;
    
    // Create message from hash (msg must be 32 bytes)
    if msg.len() != 32 {
        return Err(Secp256k1Error::InvalidMessage);
    }
    let msg_array: [u8; 32] = msg.try_into().map_err(|_| Secp256k1Error::InvalidMessage)?;
    let message = Message::from_digest(msg_array);
    
    // Verify signature (pass message by value - API expects impl Into<Message>)
    match secp.verify_ecdsa(message, &signature, &pubkey) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute double SHA-256 hash
///
/// # Arguments
/// * `data` - Input data to hash
///
/// # Returns
/// 32-byte hash result
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256dHash::hash(data).to_byte_array()
}

/// Compute RIPEMD160(SHA256(data)) hash (Hash160)
///
/// # Arguments
/// * `data` - Input data to hash
///
/// # Returns
/// 20-byte hash result
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Hash160Hash::hash(data).to_byte_array()
}

/// Compute Merkle root from transaction IDs
///
/// Bitcoin's merkle tree algorithm:
/// 1. Start with transaction IDs
/// 2. If odd number of items, duplicate the last one
/// 3. Pair items and hash them together (double SHA256)
/// 4. Repeat until one hash remains
///
/// # Arguments
/// * `txids` - Vector of transaction IDs (32-byte arrays)
///
/// # Returns
/// Merkle root (32-byte array)
pub fn compute_merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    
    if txids.len() == 1 {
        return txids[0];
    }
    
    let mut level = txids.to_vec();
    
    while level.len() > 1 {
        let mut next_level = Vec::new();
        
        // Process pairs
        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                // Hash the pair
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                double_sha256(&combined)
            } else {
                // Odd number: duplicate the last element
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[0]);
                double_sha256(&combined)
            };
            next_level.push(hash);
        }
        
        level = next_level;
    }
    
    level[0]
}

/// Convert compact "bits" representation to target (U256)
///
/// Bitcoin's compact format:
/// - Bits 0-23: mantissa (0x007fffff mask)
/// - Bits 24-31: exponent
/// - Formula: target = mantissa * 256^(exponent - 3)
///
/// # Arguments
/// * `bits` - Compact representation (u32)
///
/// # Returns
/// Target as U256
pub fn bits_to_target(bits: u32) -> U256 {
    let exponent = (bits >> 24) as u8;
    let mantissa = bits & 0x007fffff;
    
    if exponent <= 3 {
        // For small exponents, shift mantissa right
        U256::from(mantissa) >> (8 * (3 - exponent))
    } else {
        // For larger exponents, shift mantissa left
        U256::from(mantissa) << (8 * (exponent - 3))
    }
}

/// Convert target (U256) to compact "bits" representation
///
/// # Arguments
/// * `target` - Target as U256
///
/// # Returns
/// Compact representation (u32)
pub fn target_to_bits(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    
    let mut exponent = 3u32;
    let mut mantissa = target;
    
    // Find the right exponent by shifting right
    while mantissa > U256::from(0x007fffff) {
        mantissa >>= 8;
        exponent += 1;
    }
    
    // Check if mantissa has the high bit set (would overflow)
    if mantissa & U256::from(0x00800000) != U256::zero() {
        mantissa >>= 8;
        exponent += 1;
    }
    
    // Extract the low 32 bits of mantissa
    let mantissa_u32 = (mantissa.low_u64() & 0x007fffff) as u32;
    
    (exponent << 24) | mantissa_u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    // Bitcoin Core test vectors

    #[test]
    fn test_double_sha256() {
        // Test vector: empty string
        let data = b"";
        let hash = double_sha256(data);
        let expected = [
            0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
            0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
            0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
            0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
        ];
        assert_eq!(hash, expected);
        
        // Test vector: "hello"
        let data = b"hello";
        let hash = double_sha256(data);
        let expected = [
            0x95, 0x95, 0xc9, 0xdf, 0x90, 0x07, 0x51, 0x48,
            0xeb, 0x06, 0x86, 0x03, 0x65, 0xdf, 0x33, 0x58,
            0x4b, 0x75, 0xbf, 0xf7, 0x82, 0xa5, 0x10, 0xc6,
            0xcd, 0x48, 0x83, 0xa4, 0x19, 0x83, 0x3d, 0x50,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash160() {
        // Test vector: empty string
        // Hash160("") = RIPEMD160(SHA256(""))
        let data = b"";
        let hash = hash160(data);
        let expected = [
            0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1,
            0x37, 0x06, 0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f,
            0x7c, 0x3b, 0x9f, 0xcb,
        ];
        assert_eq!(hash, expected);
        
        // Test vector: "hello"
        // Hash160("hello") = RIPEMD160(SHA256("hello"))
        let data = b"hello";
        let hash = hash160(data);
        let expected = [
            0xb6, 0xa9, 0xc8, 0xc2, 0x30, 0x72, 0x2b, 0x7c,
            0x74, 0x83, 0x31, 0xa8, 0xb4, 0x50, 0xf0, 0x55,
            0x66, 0xdc, 0x7d, 0x0f,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_merkle_root_empty() {
        let txids: Vec<[u8; 32]> = vec![];
        let root = compute_merkle_root(&txids);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let txid = [1u8; 32];
        let txids = vec![txid];
        let root = compute_merkle_root(&txids);
        assert_eq!(root, txid);
    }

    #[test]
    fn test_merkle_root_two_txids() {
        // Test vector: two transaction IDs
        let txid1 = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap()
            .try_into()
            .unwrap();
        let txid2 = hex::decode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap()
            .try_into()
            .unwrap();
        
        let txids = vec![txid1, txid2];
        let root = compute_merkle_root(&txids);
        
        // Expected: double SHA256 of concatenated txids
        let mut combined = Vec::new();
        combined.extend_from_slice(&txid1);
        combined.extend_from_slice(&txid2);
        let expected = double_sha256(&combined);
        
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three_txids() {
        // Test with 3 txids (should duplicate the last one)
        let txid1 = [1u8; 32];
        let txid2 = [2u8; 32];
        let txid3 = [3u8; 32];
        
        let txids = vec![txid1, txid2, txid3];
        let root = compute_merkle_root(&txids);
        
        // First level: hash(txid1, txid2) and hash(txid3, txid3)
        let mut combined1 = Vec::new();
        combined1.extend_from_slice(&txid1);
        combined1.extend_from_slice(&txid2);
        let hash1 = double_sha256(&combined1);
        
        let mut combined2 = Vec::new();
        combined2.extend_from_slice(&txid3);
        combined2.extend_from_slice(&txid3);
        let hash2 = double_sha256(&combined2);
        
        // Second level: hash(hash1, hash2)
        let mut combined_final = Vec::new();
        combined_final.extend_from_slice(&hash1);
        combined_final.extend_from_slice(&hash2);
        let expected = double_sha256(&combined_final);
        
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_genesis_block() {
        // Genesis block has only one transaction
        // For single txid, root should equal the txid
        
        // Genesis coinbase txid (in internal byte order)
        // The genesis block merkle root equals the single coinbase txid
        let genesis_txid_hex = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let mut genesis_txid = hex::decode(genesis_txid_hex).unwrap();
        genesis_txid.reverse(); // Convert from display format to internal format
        let genesis_txid: [u8; 32] = genesis_txid.try_into().unwrap();
        
        let txids = vec![genesis_txid];
        let root = compute_merkle_root(&txids);
        
        // For single txid, root should equal the txid
        assert_eq!(root, genesis_txid);
    }

    #[test]
    fn test_bits_to_target() {
        // Genesis block bits: 0x1d00ffff
        let bits = 0x1d00ffff;
        let target = bits_to_target(bits);
        
        // Expected target for 0x1d00ffff
        // exponent = 0x1d = 29
        // mantissa = 0x00ffff
        // target = 0x00ffff * 256^(29 - 3) = 0x00ffff * 256^26
        // Expected: 0x0000ffff00000000000000000000000000000000000000000000000000000000
        let expected = U256::from(0x00ffffu64) << (8 * 26);
        assert_eq!(target, expected);
    }

    #[test]
    fn test_target_to_bits() {
        // Test roundtrip: bits -> target -> bits
        let bits = 0x1d00ffff;
        let target = bits_to_target(bits);
        let result_bits = target_to_bits(target);
        assert_eq!(result_bits, bits);
        
        // Test another value
        let bits2 = 0x1b0404cb;
        let target2 = bits_to_target(bits2);
        let result_bits2 = target_to_bits(target2);
        assert_eq!(result_bits2, bits2);
    }

    #[test]
    fn test_bits_target_roundtrip() {
        // Test multiple roundtrips
        let test_cases = vec![
            0x1d00ffff, // Genesis block
            0x1b0404cb, // Block 1000
            0x1a05db8b, // Block 10000
            0x18009645, // Block 100000
            0x170b0c00, // Block 500000
        ];
        
        for bits in test_cases {
            let target = bits_to_target(bits);
            let result_bits = target_to_bits(target);
            assert_eq!(result_bits, bits, "Roundtrip failed for bits: 0x{:08x}", bits);
        }
    }

    #[test]
    fn test_verify_ecdsa_signature() {
        // Note: This test requires valid signature data
        // For a full implementation, you would use actual Bitcoin test vectors
        // Here we just test that the function handles errors correctly
        
        let invalid_sig = vec![0u8; 63]; // Wrong size
        let invalid_pubkey = vec![0u8; 32]; // Wrong size
        let msg = vec![0u8; 32];
        
        // Should return an error for invalid input
        let result = verify_ecdsa_signature(&invalid_sig, &invalid_pubkey, &msg);
        assert!(result.is_err());
    }
}

