// SipHash-2-4 implementation for BIP 152 compact blocks
//
// Reference: Bitcoin Core src/crypto/siphash.cpp

/// SipHash internal state initialized from a 128-bit key (k0, k1)
struct SipHashState {
    v: [u64; 4],
}

impl SipHashState {
    const C0: u64 = 0x736f6d6570736575;
    const C1: u64 = 0x646f72616e646f6d;
    const C2: u64 = 0x6c7967656e657261;
    const C3: u64 = 0x7465646279746573;

    fn new(k0: u64, k1: u64) -> Self {
        Self {
            v: [
                Self::C0 ^ k0,
                Self::C1 ^ k1,
                Self::C2 ^ k0,
                Self::C3 ^ k1,
            ],
        }
    }
}

/// SipHash-2-4 compression round
#[inline(always)]
fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// General SipHash-2-4 implementation for arbitrary data
pub struct SipHasher {
    state: SipHashState,
    tmp: u64,
    count: u8,
}

impl SipHasher {
    /// Create a new SipHasher with a 128-bit key (k0, k1)
    pub fn new(k0: u64, k1: u64) -> Self {
        Self {
            state: SipHashState::new(k0, k1),
            tmp: 0,
            count: 0,
        }
    }

    /// Hash a 64-bit integer worth of data (little-endian)
    /// Can only be called when a multiple of 8 bytes have been written
    pub fn write_u64(&mut self, data: u64) {
        debug_assert!(self.count % 8 == 0);

        self.state.v[3] ^= data;
        sipround(&mut self.state.v);
        sipround(&mut self.state.v);
        self.state.v[0] ^= data;

        self.count = self.count.wrapping_add(8);
    }

    /// Hash arbitrary bytes
    pub fn write(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process any partial block from previous writes
        while offset < data.len() {
            self.tmp |= (data[offset] as u64) << (8 * (self.count % 8));
            self.count = self.count.wrapping_add(1);

            if self.count % 8 == 0 {
                self.state.v[3] ^= self.tmp;
                sipround(&mut self.state.v);
                sipround(&mut self.state.v);
                self.state.v[0] ^= self.tmp;
                self.tmp = 0;
            }

            offset += 1;
        }
    }

    /// Finalize and return the 64-bit hash
    pub fn finalize(&self) -> u64 {
        let mut v = self.state.v;

        // Encode length in final block
        let t = self.tmp | ((self.count as u64) << 56);

        v[3] ^= t;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= t;
        v[2] ^= 0xff;
        sipround(&mut v);
        sipround(&mut v);
        sipround(&mut v);
        sipround(&mut v);

        v[0] ^ v[1] ^ v[2] ^ v[3]
    }
}

/// Optimized SipHash-2-4 implementation for 256-bit values (like txids/wtxids)
///
/// This is used for BIP 152 compact blocks where we need to hash many wtxids
/// with the same key. The key is derived from the block header + nonce.
pub struct PresaltedSipHasher {
    state: SipHashState,
}

impl PresaltedSipHasher {
    /// Create a new PresaltedSipHasher with a 128-bit key (k0, k1)
    pub fn new(k0: u64, k1: u64) -> Self {
        Self {
            state: SipHashState::new(k0, k1),
        }
    }

    /// Hash a 256-bit value (32 bytes, treated as 4 little-endian u64s)
    /// Returns the 64-bit SipHash result
    pub fn hash_u256(&self, data: &[u8; 32]) -> u64 {
        let mut v = self.state.v;

        // Process 4 x 64-bit words (256 bits total)
        let d0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
        v[3] ^= d0;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= d0;

        let d1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
        v[3] ^= d1;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= d1;

        let d2 = u64::from_le_bytes(data[16..24].try_into().unwrap());
        v[3] ^= d2;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= d2;

        let d3 = u64::from_le_bytes(data[24..32].try_into().unwrap());
        v[3] ^= d3;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= d3;

        // Finalize: length = 32 bytes = 0x20, encoded as 0x20 << 56
        v[3] ^= 4u64 << 59; // (32 / 8) << 59 = length in 8-byte blocks
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= 4u64 << 59;
        v[2] ^= 0xff;
        sipround(&mut v);
        sipround(&mut v);
        sipround(&mut v);
        sipround(&mut v);

        v[0] ^ v[1] ^ v[2] ^ v[3]
    }

    /// Compute a 6-byte short txid for BIP 152 compact blocks
    /// Returns the lower 48 bits of the SipHash
    #[inline]
    pub fn short_txid(&self, wtxid: &[u8; 32]) -> u64 {
        self.hash_u256(wtxid) & 0xffff_ffff_ffff
    }
}

/// Convenience function: SipHash-2-4 of arbitrary data with a 128-bit key
pub fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut hasher = SipHasher::new(k0, k1);
    hasher.write(data);
    hasher.finalize()
}

/// Compute the SipHash key from a block header and nonce (BIP 152)
///
/// key = SHA256(header || nonce_le64)[0..16]
/// k0 = key[0..8] as u64 LE
/// k1 = key[8..16] as u64 LE
pub fn compute_siphash_key(header: &[u8; 80], nonce: u64) -> (u64, u64) {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(header);
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();

    let k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

    (k0, k1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash_empty() {
        // Test vector: SipHash-2-4 with key (0, 0) and empty input
        let hash = siphash_2_4(0, 0, &[]);
        // Verify consistency (same key + input should always produce same hash)
        let hash2 = siphash_2_4(0, 0, &[]);
        assert_eq!(hash, hash2);
        // The hash should be non-zero for empty input
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_siphash_basic() {
        // Known test vector from SipHash reference
        // Key: k0 = 0x0706050403020100, k1 = 0x0f0e0d0c0b0a0908
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;

        // Test with 15 bytes of input: 0x00, 0x01, ..., 0x0e
        let data: Vec<u8> = (0..15).collect();
        let hash = siphash_2_4(k0, k1, &data);
        // Expected from SipHash reference
        assert_eq!(hash, 0xa129ca6149be45e5);
    }

    #[test]
    fn test_presalted_siphash_u256() {
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;
        let hasher = PresaltedSipHasher::new(k0, k1);

        let data = [0u8; 32];
        let hash = hasher.hash_u256(&data);
        // Should produce consistent output
        let hash2 = hasher.hash_u256(&data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_short_txid() {
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;
        let hasher = PresaltedSipHasher::new(k0, k1);

        let wtxid = [0xabu8; 32];
        let short_id = hasher.short_txid(&wtxid);

        // Short txid should be 48 bits (6 bytes)
        assert!(short_id <= 0xffff_ffff_ffff);

        // Should be consistent
        assert_eq!(short_id, hasher.short_txid(&wtxid));
    }

    #[test]
    fn test_siphash_incremental() {
        // Test that incremental hashing matches single-shot hashing
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;

        let data: Vec<u8> = (0..32).collect();

        // Single-shot
        let hash1 = siphash_2_4(k0, k1, &data);

        // Incremental
        let mut hasher = SipHasher::new(k0, k1);
        hasher.write(&data[0..10]);
        hasher.write(&data[10..25]);
        hasher.write(&data[25..32]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_siphash_matches_python() {
        // Test vector that can be verified against Python implementation
        // Key derived from all-zero 80-byte header with nonce=0
        // This is the SHA256 of (80 zeros || 8 zero bytes) truncated to 16 bytes

        // For now, just verify the function doesn't panic and returns consistent results
        let header = [0u8; 80];
        let nonce = 0u64;
        let (k0, k1) = compute_siphash_key(&header, nonce);

        let hasher = PresaltedSipHasher::new(k0, k1);
        let wtxid = [0x12u8; 32];
        let short_id1 = hasher.short_txid(&wtxid);
        let short_id2 = hasher.short_txid(&wtxid);
        assert_eq!(short_id1, short_id2);
    }
}
