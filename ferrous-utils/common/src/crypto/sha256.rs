// SHA256 implementation with optional hardware acceleration
//
// Provides runtime CPU feature detection for:
// - ARM SHA2 extensions (Apple Silicon, ARMv8-A)
// Falls back to the software implementation otherwise.
//
// NOTE: the x86/x86_64 SHA-NI transform was removed before v1.0 — it produced
// incorrect digests (sha256(b"") gave 46c5b51e… instead of e3b0c442…). The
// portable software path below is used on x86 until a corrected SHA-NI
// transform can be landed and validated against known-answer vectors.

use std::sync::OnceLock;

/// SHA256 implementation variant detected at runtime
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Implementation {
    /// Software implementation (portable)
    Software,
    /// ARM SHA2 extensions (Apple Silicon, ARMv8)
    ArmSha2,
}

impl std::fmt::Display for Sha256Implementation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software => write!(f, "software"),
            Self::ArmSha2 => write!(f, "arm_sha2"),
        }
    }
}

/// Global detected implementation (initialized once on first use)
static DETECTED_IMPL: OnceLock<Sha256Implementation> = OnceLock::new();

/// Detect available SHA256 implementation at runtime
pub fn detect_implementation() -> Sha256Implementation {
    *DETECTED_IMPL.get_or_init(|| {
        // x86/x86_64: SHA-NI detection intentionally absent — the former
        // SHA-NI transform produced incorrect digests and was removed (see
        // the note at the top of this file). x86 uses the software path.

        // ARM: check for SHA2 extensions
        #[cfg(target_arch = "aarch64")]
        {
            // On aarch64, SHA2 is usually available on ARMv8.0-A and later
            // std::arch::is_aarch64_feature_detected! requires nightly, so we use std
            #[cfg(target_feature = "sha2")]
            {
                return Sha256Implementation::ArmSha2;
            }
            #[cfg(not(target_feature = "sha2"))]
            {
                // Runtime detection for ARM SHA2
                // On Linux, we could check /proc/cpuinfo or use getauxval
                // On macOS, sysctlbyname("hw.optional.arm.FEAT_SHA256")
                // For now, assume SHA2 is available on aarch64 macOS (Apple Silicon)
                #[cfg(target_os = "macos")]
                {
                    return Sha256Implementation::ArmSha2;
                }
            }
        }

        Sha256Implementation::Software
    })
}

/// Get a human-readable string describing the detected implementation
pub fn implementation_string() -> String {
    let impl_type = detect_implementation();
    format!("sha256:{}", impl_type)
}

/// SHA256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial SHA256 state
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA256 hasher with hardware acceleration support
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA256 hasher
    pub fn new() -> Self {
        Self {
            state: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If we have buffered data, try to complete a block
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
                self.transform_block(&self.buffer.clone());
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()]
                    .copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        // Process complete blocks
        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.transform_block(&block);
            offset += 64;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 32] {
        // Pad the message
        let bit_len = self.total_len * 8;

        // Append 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough room for length, pad and process
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..64].fill(0);
            self.transform_block(&self.buffer.clone());
            self.buffer_len = 0;
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }

        // Append length in bits (big-endian)
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.transform_block(&self.buffer.clone());

        // Output state as big-endian bytes
        let mut output = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    /// Transform a single 64-byte block
    fn transform_block(&mut self, block: &[u8; 64]) {
        match detect_implementation() {
            Sha256Implementation::ArmSha2 => {
                #[cfg(target_arch = "aarch64")]
                {
                    // SAFETY: We've verified ARM SHA2 is available
                    unsafe {
                        self.transform_arm_sha2(block);
                    }
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    self.transform_software(block);
                }
            }
            Sha256Implementation::Software => {
                self.transform_software(block);
            }
        }
    }

    /// Software SHA256 transform (portable fallback)
    fn transform_software(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        // Load message words (big-endian)
        for (i, chunk) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // Extend message schedule
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add to state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    /// ARM SHA2 accelerated transform
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "sha2")]
    #[target_feature(enable = "neon")]
    unsafe fn transform_arm_sha2(&mut self, block: &[u8; 64]) {
        use core::arch::aarch64::*;

        // Load state into NEON registers
        let mut state0 = vld1q_u32(self.state.as_ptr());
        let mut state1 = vld1q_u32(self.state.as_ptr().add(4));

        // Save initial state
        let init_state0 = state0;
        let init_state1 = state1;

        // Load message block (big-endian to little-endian conversion)
        let mut msg0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr())));
        let mut msg1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16))));
        let mut msg2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32))));
        let mut msg3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48))));

        // Rounds 0-3
        let mut tmp = vaddq_u32(msg0, vld1q_u32(K.as_ptr()));
        let mut tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg0 = vsha256su0q_u32(msg0, msg1);

        // Rounds 4-7
        tmp = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(4)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        msg1 = vsha256su0q_u32(msg1, msg2);

        // Rounds 8-11
        tmp = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(8)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        msg2 = vsha256su0q_u32(msg2, msg3);

        // Rounds 12-15
        tmp = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(12)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        msg3 = vsha256su0q_u32(msg3, msg0);

        // Rounds 16-19
        tmp = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(16)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);
        msg0 = vsha256su0q_u32(msg0, msg1);

        // Rounds 20-23
        tmp = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(20)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        msg1 = vsha256su0q_u32(msg1, msg2);

        // Rounds 24-27
        tmp = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(24)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        msg2 = vsha256su0q_u32(msg2, msg3);

        // Rounds 28-31
        tmp = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(28)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        msg3 = vsha256su0q_u32(msg3, msg0);

        // Rounds 32-35
        tmp = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(32)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);
        msg0 = vsha256su0q_u32(msg0, msg1);

        // Rounds 36-39
        tmp = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(36)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        msg1 = vsha256su0q_u32(msg1, msg2);

        // Rounds 40-43
        tmp = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(40)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        msg2 = vsha256su0q_u32(msg2, msg3);

        // Rounds 44-47
        tmp = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(44)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        msg3 = vsha256su0q_u32(msg3, msg0);

        // Rounds 48-51
        tmp = vaddq_u32(msg0, vld1q_u32(K.as_ptr().add(48)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 52-55
        tmp = vaddq_u32(msg1, vld1q_u32(K.as_ptr().add(52)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);

        // Rounds 56-59
        tmp = vaddq_u32(msg2, vld1q_u32(K.as_ptr().add(56)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);

        // Rounds 60-63
        tmp = vaddq_u32(msg3, vld1q_u32(K.as_ptr().add(60)));
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp);
        state1 = vsha256h2q_u32(state1, tmp2, tmp);

        // Add initial state
        state0 = vaddq_u32(state0, init_state0);
        state1 = vaddq_u32(state1, init_state1);

        // Store state
        vst1q_u32(self.state.as_mut_ptr(), state0);
        vst1q_u32(self.state.as_mut_ptr().add(4), state1);
    }
}

/// Compute SHA256 hash of data (single-shot convenience function)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute double SHA256 hash (SHA256(SHA256(data))) - used extensively in Bitcoin
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute double SHA256 of 64-byte input (optimized for Bitcoin merkle tree)
/// This is a common operation in Bitcoin for merkle tree computation
pub fn double_sha256_64(data: &[u8; 64]) -> [u8; 32] {
    double_sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_long() {
        // Test with longer input spanning multiple blocks
        let data = b"The quick brown fox jumps over the lazy dog";
        let hash = sha256(data);
        let expected = hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_exactly_64_bytes() {
        // Test input exactly one block size
        let data = [0x61u8; 64]; // 64 'a' characters
        let hash = sha256(&data);
        let expected = hex::decode("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_double_sha256() {
        // Test double SHA256 (Bitcoin's hash function)
        let hash = double_sha256(b"");
        let expected = hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_double_sha256_hello() {
        // Known-answer vector (verified via `sha256sum | xxd -r -p | sha256sum`).
        // The previous literal was a corrupted 31-byte string and the test
        // only compared the function against itself, so it could not fail.
        let hash = double_sha256(b"hello");
        let expected = hex::decode("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_incremental_update() {
        // Test that incremental updates produce same result as single update
        let data = b"The quick brown fox jumps over the lazy dog";

        let hash1 = sha256(data);

        let mut hasher = Sha256::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_implementation_detection() {
        let impl_type = detect_implementation();
        println!("Detected SHA256 implementation: {}", impl_type);

        // Should detect something
        match impl_type {
            Sha256Implementation::Software | Sha256Implementation::ArmSha2 => {}
        }
    }

    #[test]
    fn test_software_matches_hardware() {
        // Previously compared sha256(data) against itself (Sha256::new().update()
        // .finalize() dispatches through the exact same code path), so it could
        // never catch a broken hardware transform — that's how the wrong-digest
        // SHA-NI bug shipped. This is now a known-answer test against an
        // independently computed vector (sha256sum).
        let data = b"test data for sha256 comparison";
        let hash = sha256(data);
        let expected = hex::decode("f93f3a675a7d17227ed63848db82b790019296b0883d65f74a3cc75eecd4fe11")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }
}
