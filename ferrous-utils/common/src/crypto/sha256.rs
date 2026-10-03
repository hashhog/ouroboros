//! SHA-256.
//!
//! The previous in-house compressor (portable software, x86 SHA-NI, ARM SHA2)
//! did not implement SHA-256. On this host's SHA-NI path even one-shot
//! `sha256(b"")` was `46c5b51e…` instead of `e3b0c442…`, and streaming
//! `update()` returned the same wrong digest. The SHA-NI routine added the
//! block's initial state in the unshuffled domain to a shuffled working
//! state (Bitcoin Core's `sha256_x86_shani.cpp` adds the state it saved
//! *after* `Shuffle`).
//!
//! Digests now come from the `sha2` crate. `detect_implementation` still
//! reports the CPU feature, but it does not select a compressor.

use sha2::Digest;
use std::sync::OnceLock;

/// CPU feature probe. Not used to hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256Implementation {
    /// Portable SHA-256 (`sha2`). This is what `Sha256` actually runs.
    Software,
    /// x86 SHA-NI is present. The broken intrinsic compressor was removed;
    /// hashing does not use it.
    X86Shani,
    /// ARM SHA2 is present. Hashing does not use it.
    ArmSha2,
}

impl std::fmt::Display for Sha256Implementation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software => write!(f, "software"),
            Self::X86Shani => write!(f, "x86_shani"),
            Self::ArmSha2 => write!(f, "arm_sha2"),
        }
    }
}

static DETECTED_IMPL: OnceLock<Sha256Implementation> = OnceLock::new();

/// Detect a SHA-256 CPU feature. The result is diagnostic only.
pub fn detect_implementation() -> Sha256Implementation {
    *DETECTED_IMPL.get_or_init(|| {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse4.1") {
                return Sha256Implementation::X86Shani;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(target_feature = "sha2")]
            {
                return Sha256Implementation::ArmSha2;
            }
            #[cfg(not(target_feature = "sha2"))]
            {
                #[cfg(target_os = "macos")]
                {
                    return Sha256Implementation::ArmSha2;
                }
            }
        }

        Sha256Implementation::Software
    })
}

/// What actually produces digests. Always `sha2`, regardless of
/// [`detect_implementation`].
pub fn implementation_string() -> String {
    "sha256:sha2".to_string()
}

/// Streaming SHA-256. `update` + `finalize` match one-shot [`sha256`].
#[derive(Clone)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            inner: sha2::Sha256::new(),
        }
    }

    /// Absorb `data`. Splitting a message across calls does not change the digest.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// SHA256(SHA256(data)), Bitcoin's hash for headers and txids.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Double SHA-256 of a 64-byte block (merkle-node input).
pub fn double_sha256_64(data: &[u8; 64]) -> [u8; 32] {
    double_sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect(hash: [u8; 32], hex_str: &str) {
        assert_eq!(hex::encode(hash), hex_str);
    }

    #[test]
    fn test_sha256_empty() {
        expect(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn test_sha256_hello() {
        expect(
            sha256(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
    }

    #[test]
    fn test_sha256_abc() {
        expect(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn test_sha256_long() {
        expect(
            sha256(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        );
    }

    #[test]
    fn test_sha256_exactly_64_bytes() {
        expect(
            sha256(&[0x61u8; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        );
    }

    #[test]
    fn test_double_sha256() {
        expect(
            double_sha256(b""),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
        // Same construction as `crypto::double_sha256` (bitcoin_hashes).
        assert_eq!(double_sha256(b""), crate::double_sha256(b""));
        assert_eq!(double_sha256(b"abc"), crate::double_sha256(b"abc"));
    }

    #[test]
    fn test_double_sha256_hello() {
        // SHA256(SHA256("hello")). The old expected hex dropped two nibbles
        // (`df`) and the test compared the hasher to itself.
        expect(
            double_sha256(b"hello"),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50",
        );
    }

    #[test]
    fn test_incremental_update() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Sha256::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..20]);
        hasher.update(&data[20..]);
        assert_eq!(hasher.finalize(), sha256(data));
    }

    #[test]
    fn test_implementation_detection() {
        match detect_implementation() {
            Sha256Implementation::Software
            | Sha256Implementation::X86Shani
            | Sha256Implementation::ArmSha2 => {}
        }
        assert_eq!(implementation_string(), "sha256:sha2");
    }

    #[test]
    fn test_software_matches_hardware() {
        // One-shot and a single update of the same bytes are one digest.
        let data = b"test data for sha256 comparison";
        let mut hasher = Sha256::new();
        hasher.update(data);
        assert_eq!(hasher.finalize(), sha256(data));
    }

    /// Streaming `update()` must match SHA-256, including the per-coin
    /// chunking the UTXO importer uses. One-shot agreeing with itself is
    /// not this check: both go through `sha2`, and so does a reference
    /// hasher fed the same chunks.
    #[test]
    fn streaming_update_matches_sha2() {
        let cpu = detect_implementation();
        let mut failures: Vec<String> = Vec::new();

        let check = |label: &str, chunks: &[&[u8]], failures: &mut Vec<String>| {
            let mut ours = Sha256::new();
            let mut reference = sha2::Sha256::new();
            for c in chunks {
                ours.update(c);
                reference.update(c);
            }
            let got = ours.finalize();
            let expect: [u8; 32] = reference.finalize().into();
            if got != expect {
                failures.push(format!(
                    "{label} cpu={cpu} got={} expect={}",
                    hex::encode(got),
                    hex::encode(expect),
                ));
            }
            let concat: Vec<u8> = chunks.iter().copied().flatten().copied().collect();
            let one = sha256(&concat);
            if one != expect {
                failures.push(format!(
                    "{label} ONE-SHOT cpu={cpu} got={} expect={}",
                    hex::encode(one),
                    hex::encode(expect),
                ));
            }
        };

        check("empty", &[b""], &mut failures);
        check("abc", &[b"abc"], &mut failures);
        let fox = b"The quick brown fox jumps over the lazy dog";
        check(
            "split-10-20",
            &[&fox[..10], &fox[10..20], &fox[20..]],
            &mut failures,
        );

        let long: Vec<u8> = (0u16..300).map(|i| (i * 17) as u8).collect();
        let bytes: Vec<&[u8]> = long.chunks(1).collect();
        check("byte-at-a-time-300", &bytes, &mut failures);
        let pieces: Vec<&[u8]> = long.chunks(47).collect();
        check("chunks-47", &pieces, &mut failures);
        let pieces64: Vec<&[u8]> = long.chunks(64).collect();
        check("chunks-64", &pieces64, &mut failures);
        check(
            "cross-boundary",
            &[&long[..70], &long[70..140], &long[140..]],
            &mut failures,
        );

        assert!(
            failures.is_empty(),
            "Sha256 streaming update disagrees with SHA-256 ({cpu}):\n{}",
            failures.join("\n"),
        );
    }
}
