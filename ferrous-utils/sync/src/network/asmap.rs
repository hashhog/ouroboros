//! ASMap interpreter — Autonomous System Number lookup from IP addresses.
//!
//! Port of bitcoin-core/src/util/asmap.cpp (Interpret, SanityCheckAsmap,
//! CheckStandardAsmap, DecodeAsmap, AsmapVersion).
//!
//! Format: bit-packed binary trie, LSB-first bytes for the asmap data,
//! MSB-first for IP address bits.  Four instruction types:
//!   RETURN   [0]      — return a constant ASN leaf
//!   JUMP     [1,0]    — branch on next IP bit (0=fall-through, 1=jump)
//!   MATCH    [1,1,0]  — compare several IP bits against a pattern
//!   DEFAULT  [1,1,1]  — set default ASN for subsequent MATCH failures

/// Maximum ASMap file size (8 MiB), matching Bitcoin Core's practical limit.
pub const MAX_ASMAP_FILE_SIZE: usize = 8 * 1024 * 1024;

/// Sentinel for decoding errors.
const INVALID: u32 = 0xFFFF_FFFF;

/// Instruction type encoding (same as asmap.cpp DecodeType).
const RETURN: u8 = 0;
const JUMP: u8 = 1;
const MATCH: u8 = 2;
const DEFAULT: u8 = 3;

/// Variable-length integer bit-size tables (from asmap.cpp).
/// TYPE: [0, 0, 1] — RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];
/// ASN: minval=1, 10 classes covering up to ~16.7 million
const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
/// MATCH argument: minval=2, 8 classes covering values [2, 511]
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
/// JUMP offset: minval=17, 26 classes
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30,
];

// IPv4-in-IPv6 mapped prefix: 10 zero bytes + 0xFF 0xFF
const IPV4_IN_IPV6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];

// NET_IPV6 prefix used by Core when encoding an ASN-based group.
const NET_IPV6: u8 = 2;

// ============================================================================
// Bit extraction helpers (ported from asmap.cpp ConsumeBitLE / ConsumeBitBE)
// ============================================================================

/// Extract one bit from `data` using LSB-first ordering (for asmap bytecode).
#[inline]
fn consume_bit_le(data: &[u8], bitpos: usize) -> u8 {
    (data[bitpos >> 3] >> (bitpos & 7)) & 1
}

/// Extract one bit from `data` using MSB-first ordering (for IP address bytes).
#[inline]
fn consume_bit_be(data: &[u8], bitpos: usize) -> u8 {
    (data[bitpos >> 3] >> (7 - (bitpos & 7))) & 1
}

// ============================================================================
// Variable-length integer decoder
// ============================================================================

/// Decode a variable-length integer from the asmap bitstream.
///
/// Returns `(value, new_bitpos)`.  Returns `(INVALID, bitpos)` on error.
///
/// Encoding: for each size class k:
///   - If k < last: read one continuation bit.
///     0 → decode `bit_sizes[k]` mantissa bits (big-endian within class).
///     1 → add `2^bit_sizes[k]` to val and move to class k+1.
///   - If k == last: no continuation bit; decode `bit_sizes[k]` bits.
fn decode_bits(data: &[u8], bitpos: usize, minval: u32, bit_sizes: &[u8]) -> (u32, usize) {
    let mut val: u32 = minval;
    let end_bit = data.len() * 8;
    let last = bit_sizes.len() - 1;
    let mut pos = bitpos;

    for (k, &bsize) in bit_sizes.iter().enumerate() {
        if k < last {
            if pos >= end_bit {
                return (INVALID, bitpos);
            }
            let cont = consume_bit_le(data, pos);
            pos += 1;
            if cont != 0 {
                val = val.saturating_add(1u32 << bsize);
                continue;
            }
        }
        // Decode `bsize` mantissa bits in big-endian order
        for b in (0..bsize).rev() {
            if pos >= end_bit {
                return (INVALID, bitpos);
            }
            let bit = consume_bit_le(data, pos);
            pos += 1;
            val = val.saturating_add((bit as u32) << b);
        }
        return (val, pos);
    }
    (INVALID, bitpos)
}

// ============================================================================
// Public API
// ============================================================================

/// Execute the ASMap trie bytecode to find the ASN for an IP address.
///
/// Direct port of bitcoin-core/src/util/asmap.cpp `Interpret()`.
///
/// # Arguments
/// * `asmap` — Raw asmap bytecode (LSB-first packed bits).
/// * `ip`    — IP address as bytes, MSB-first (16 bytes for IPv4-in-IPv6 or IPv6).
///
/// # Returns
/// ASN (> 0) on success, 0 if no mapping found.
pub fn interpret(asmap: &[u8], ip: &[u8]) -> u32 {
    let mut bitpos: usize = 0;
    let end_bit = asmap.len() * 8;
    let mut ip_bit: usize = 0;
    let ip_bits_end = ip.len() * 8;
    let mut default_asn: u32 = 0;

    while bitpos < end_bit {
        let (opcode, new_pos) = decode_bits(asmap, bitpos, 0, TYPE_BIT_SIZES);
        bitpos = new_pos;
        if opcode == INVALID as u32 {
            break;
        }
        let op = opcode as u8;

        if op == RETURN {
            let (asn, new_pos) = decode_bits(asmap, bitpos, 1, ASN_BIT_SIZES);
            bitpos = new_pos;
            if asn == INVALID {
                break;
            }
            return asn;
        } else if op == JUMP {
            let (jump, new_pos) = decode_bits(asmap, bitpos, 17, JUMP_BIT_SIZES);
            bitpos = new_pos;
            if jump == INVALID {
                break;
            }
            if ip_bit >= ip_bits_end {
                break;
            }
            if jump as usize >= end_bit - bitpos {
                break;
            }
            let ip_b = consume_bit_be(ip, ip_bit);
            ip_bit += 1;
            if ip_b != 0 {
                bitpos += jump as usize;
            }
        } else if op == MATCH {
            let (match_val, new_pos) = decode_bits(asmap, bitpos, 2, MATCH_BIT_SIZES);
            bitpos = new_pos;
            if match_val == INVALID {
                break;
            }
            // Highest set bit of match_val determines pattern length (n-1 bits below it).
            let matchlen = 31 - match_val.leading_zeros() as usize;
            if (ip_bits_end - ip_bit) < matchlen {
                break;
            }
            let mut mismatch = false;
            for bit_idx in 0..matchlen {
                let ip_b = consume_bit_be(ip, ip_bit);
                ip_bit += 1;
                let pattern_bit = ((match_val >> (matchlen - 1 - bit_idx)) & 1) as u8;
                if ip_b != pattern_bit {
                    mismatch = true;
                    break;
                }
            }
            if mismatch {
                return default_asn;
            }
        } else if op == DEFAULT {
            let (asn, new_pos) = decode_bits(asmap, bitpos, 1, ASN_BIT_SIZES);
            bitpos = new_pos;
            if asn == INVALID {
                break;
            }
            default_asn = asn;
        } else {
            break;
        }
    }

    default_asn
}

/// Validate ASMap structure by simulating all possible execution paths.
///
/// Direct port of bitcoin-core/src/util/asmap.cpp `SanityCheckAsmap()`.
///
/// # Returns
/// `true` if the asmap passes all structural checks.
pub fn sanity_check_asmap(asmap: &[u8], bits: usize) -> bool {
    let mut bitpos: usize = 0;
    let end_bit = asmap.len() * 8;
    // Stack of (jump_target_bitpos, remaining_ip_bits)
    let mut jumps: Vec<(usize, usize)> = Vec::new();
    let mut prev_opcode: u8 = JUMP; // Sentinel: start as if after a JUMP
    let mut had_incomplete_match = false;
    let mut remaining_bits = bits;

    while bitpos != end_bit {
        // If we have a pending jump target that we've already passed
        if let Some(&(target, _)) = jumps.last() {
            if bitpos >= target {
                return false;
            }
        }

        let (opcode, new_pos) = decode_bits(asmap, bitpos, 0, TYPE_BIT_SIZES);
        bitpos = new_pos;
        if opcode == INVALID as u32 {
            return false;
        }
        let op = opcode as u8;

        if op == RETURN {
            // RETURN immediately after DEFAULT is inefficient (fold into RETURN)
            if prev_opcode == DEFAULT {
                return false;
            }
            let (asn, new_pos) = decode_bits(asmap, bitpos, 1, ASN_BIT_SIZES);
            bitpos = new_pos;
            if asn == INVALID {
                return false;
            }
            if jumps.is_empty() {
                // Last RETURN — check zero-padding and EOF
                if (end_bit - bitpos) > 7 {
                    return false;
                }
                while bitpos < end_bit {
                    if consume_bit_le(asmap, bitpos) != 0 {
                        return false;
                    }
                    bitpos += 1;
                }
                return true;
            } else {
                // After RETURN, execution resumes at the saved jump target
                let (target, saved_bits) = jumps.last().copied().unwrap();
                if bitpos != target {
                    return false; // Unreachable code between RETURN and target
                }
                remaining_bits = saved_bits;
                jumps.pop();
                prev_opcode = JUMP;
            }
        } else if op == JUMP {
            let (jump, new_pos) = decode_bits(asmap, bitpos, 17, JUMP_BIT_SIZES);
            bitpos = new_pos;
            if jump == INVALID {
                return false;
            }
            if jump as usize > end_bit - bitpos {
                return false;
            }
            if remaining_bits == 0 {
                return false; // No IP bits left to branch on
            }
            remaining_bits -= 1;
            let jump_target = bitpos + jump as usize;
            if let Some(&(parent_target, _)) = jumps.last() {
                if jump_target >= parent_target {
                    return false; // Intersecting jumps
                }
            }
            jumps.push((jump_target, remaining_bits));
            prev_opcode = JUMP;
        } else if op == MATCH {
            let (match_val, new_pos) = decode_bits(asmap, bitpos, 2, MATCH_BIT_SIZES);
            bitpos = new_pos;
            if match_val == INVALID {
                return false;
            }
            let matchlen = 31 - match_val.leading_zeros() as usize;
            if prev_opcode != MATCH {
                had_incomplete_match = false;
            }
            // Within a consecutive MATCH sequence only one may be < 8 bits
            if matchlen < 8 && had_incomplete_match {
                return false;
            }
            had_incomplete_match = matchlen < 8;
            if remaining_bits < matchlen {
                return false;
            }
            remaining_bits -= matchlen;
            prev_opcode = MATCH;
        } else if op == DEFAULT {
            if prev_opcode == DEFAULT {
                return false; // Consecutive DEFAULTs should be folded
            }
            let (asn, new_pos) = decode_bits(asmap, bitpos, 1, ASN_BIT_SIZES);
            bitpos = new_pos;
            if asn == INVALID {
                return false;
            }
            prev_opcode = DEFAULT;
        } else {
            return false;
        }
    }

    false // Reached EOF without completing a RETURN path
}

/// Validate asmap data for standard 128-bit (IPv4/IPv6) use.
///
/// Port of bitcoin-core/src/util/asmap.cpp `CheckStandardAsmap()`.
pub fn check_standard_asmap(data: &[u8]) -> bool {
    if !sanity_check_asmap(data, 128) {
        log::warn!("Sanity check of asmap data failed");
        return false;
    }
    true
}

/// Load and validate an ASMap file from disk.
///
/// Port of bitcoin-core/src/util/asmap.cpp `DecodeAsmap()`.
///
/// Returns the raw asmap bytes on success, or an empty `Vec` on failure.
pub fn load_asmap(path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("Failed to open asmap file {}: {}", path, e);
            return Vec::new();
        }
    };

    // Read up to MAX + 1 bytes to detect oversized files
    let mut data = Vec::with_capacity(MAX_ASMAP_FILE_SIZE + 1);
    let mut buf = [0u8; 65536];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.len() > MAX_ASMAP_FILE_SIZE {
                    log::warn!(
                        "ASMap file {} exceeds maximum size of {} bytes",
                        path,
                        MAX_ASMAP_FILE_SIZE
                    );
                    return Vec::new();
                }
            }
            Err(e) => {
                log::warn!("Error reading asmap file {}: {}", path, e);
                return Vec::new();
            }
        }
    }

    log::info!(
        "Opened asmap file {} ({} bytes) from disk",
        path,
        data.len()
    );

    if !check_standard_asmap(&data) {
        log::warn!("Sanity check of asmap file {} failed", path);
        return Vec::new();
    }

    data
}

/// Compute double-SHA256 fingerprint of asmap data.
///
/// Port of bitcoin-core/src/util/asmap.cpp `AsmapVersion()`.
///
/// Used to detect asmap changes across restarts (addrman re-bucketing).
/// Returns 32 zero bytes when `data` is empty.
pub fn asmap_version(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return [0u8; 32];
    }
    // Double SHA256 (SHA256(SHA256(data))) via bitcoin_hashes (already a dep).
    use bitcoin::hashes::{sha256, Hash};
    let inner = sha256::Hash::hash(data);
    let outer = sha256::Hash::hash(inner.as_ref());
    outer.to_byte_array()
}

/// Encode an ASN as a 5-byte group vector for addrman bucket computation.
///
/// Mirrors bitcoin-core/src/netgroup.cpp `NetGroupManager::GetGroup()` when
/// an ASN is found.  Uses `NET_IPV6` (2) as the first byte so that IPv4 and
/// IPv6 addresses in the same AS compete for the same addrman buckets
/// (anti-eclipse property).
pub fn asn_group_bytes(asn: u32) -> [u8; 5] {
    [
        NET_IPV6,
        (asn & 0xFF) as u8,
        ((asn >> 8) & 0xFF) as u8,
        ((asn >> 16) & 0xFF) as u8,
        ((asn >> 24) & 0xFF) as u8,
    ]
}

/// Look up the ASN for an IP address using the loaded asmap.
///
/// Mirrors bitcoin-core/src/netgroup.cpp `NetGroupManager::GetMappedAS()`.
///
/// # Arguments
/// * `asmap`      — Raw asmap bytecode (from `load_asmap()`).
/// * `ip_bytes`   — 16-byte IPv4-in-IPv6 or IPv6 raw address (MSB-first).
///
/// # Returns
/// ASN as a positive integer, or 0 if no mapping.
pub fn get_mapped_as(asmap: &[u8], ip_bytes: &[u8; 16]) -> u32 {
    if asmap.is_empty() {
        return 0;
    }
    interpret(asmap, ip_bytes)
}

/// Build a 16-byte IPv4-in-IPv6 representation from a 4-byte IPv4 address.
///
/// Core: `src/netaddress.cpp` GetAddrBytes() for CNetAddr::NET_IPV4.
pub fn ipv4_to_ipv4_in_ipv6(ipv4: &[u8; 4]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..12].copy_from_slice(&IPV4_IN_IPV6_PREFIX);
    buf[12..].copy_from_slice(ipv4);
    buf
}

// ============================================================================
// Unit tests — verifying against hand-crafted RETURN-ASN vectors
// (matches the Python test suite _build_return_asmap / test_g1_* vectors)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RETURN-only asmap that always returns `asn`.
    ///
    /// Encoding (see asmap.cpp / test_w115_asmap.py _build_return_asmap):
    ///   RETURN opcode = bit [0]  (type=0)
    ///   ASN class-0   = bit [0] + 15-bit BE value of (asn-1), for asn in [1, 32768]
    ///   Total: 17 bits → padded to 3 bytes with zero bits.
    fn build_return_asmap(asn: u32) -> Vec<u8> {
        assert!(asn >= 1 && asn <= 32768, "only class-0 ASNs supported here");
        let val = asn - 1; // minval=1
        let mut bits: Vec<u8> = Vec::new();
        bits.push(0); // RETURN opcode bit
        bits.push(0); // class-0 continuation = 0 (no jump to next class)
        for b in (0..15u8).rev() {
            bits.push(((val >> b) & 1) as u8);
        }
        // Pack bits LSB-first into bytes
        let mut data: Vec<u8> = Vec::new();
        let mut byte_val: u8 = 0;
        for (i, &bit) in bits.iter().enumerate() {
            byte_val |= bit << (i % 8);
            if (i % 8) == 7 {
                data.push(byte_val);
                byte_val = 0;
            }
        }
        if bits.len() % 8 != 0 {
            data.push(byte_val);
        }
        data
    }

    fn ipv4_16(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        ipv4_to_ipv4_in_ipv6(&[a, b, c, d])
    }

    // --- interpret() tests ---

    #[test]
    fn test_return_asn_42_any_ip() {
        let asmap = build_return_asmap(42);
        for (a, b, c, d) in [(1, 2, 3, 4), (8, 8, 8, 8), (1, 1, 1, 1)] {
            let ip = ipv4_16(a, b, c, d);
            assert_eq!(interpret(&asmap, &ip), 42, "Expected ASN 42");
        }
    }

    #[test]
    fn test_return_asn_1_minimum() {
        let asmap = build_return_asmap(1);
        let ip = ipv4_16(192, 0, 2, 1);
        assert_eq!(interpret(&asmap, &ip), 1);
    }

    #[test]
    fn test_return_asn_32768_class0_boundary() {
        let asmap = build_return_asmap(32768);
        let ip = ipv4_16(10, 0, 0, 1);
        assert_eq!(interpret(&asmap, &ip), 32768);
    }

    #[test]
    fn test_return_asn_1337() {
        let asmap = build_return_asmap(1337);
        for (a, b, c, d) in [(8, 8, 8, 8), (1, 1, 1, 1), (203, 0, 113, 1)] {
            let ip = ipv4_16(a, b, c, d);
            assert_eq!(interpret(&asmap, &ip), 1337);
        }
    }

    #[test]
    fn test_interpret_ipv6_input() {
        // 2001:4860:4860::8888 — Google DNS IPv6
        let ip6: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ];
        let asmap = build_return_asmap(15169);
        assert_eq!(interpret(&asmap, &ip6), 15169);
    }

    #[test]
    fn test_interpret_empty_asmap_returns_0() {
        let ip = ipv4_16(8, 8, 8, 8);
        assert_eq!(interpret(&[], &ip), 0);
    }

    // --- bit extraction helpers ---

    #[test]
    fn test_consume_bit_le_lsb_first() {
        // 0xB1 = 0b10110001 → LSB-first bits: 1,0,0,0,1,1,0,1
        let data = [0b10110001u8];
        let expected = [1u8, 0, 0, 0, 1, 1, 0, 1];
        for (bp, &exp) in expected.iter().enumerate() {
            assert_eq!(consume_bit_le(&data, bp), exp, "bit {}", bp);
        }
    }

    #[test]
    fn test_consume_bit_be_msb_first() {
        // 0xB1 = 0b10110001 → MSB-first bits: 1,0,1,1,0,0,0,1
        let data = [0b10110001u8];
        let expected = [1u8, 0, 1, 1, 0, 0, 0, 1];
        for (bp, &exp) in expected.iter().enumerate() {
            assert_eq!(consume_bit_be(&data, bp), exp, "bit {}", bp);
        }
    }

    // --- sanity_check_asmap / check_standard_asmap ---

    #[test]
    fn test_sanity_check_valid_return_asmap() {
        let asmap = build_return_asmap(42);
        assert!(sanity_check_asmap(&asmap, 128));
        assert!(check_standard_asmap(&asmap));
    }

    #[test]
    fn test_sanity_check_rejects_all_ones() {
        assert!(!sanity_check_asmap(&[0xFF, 0xFF, 0xFF, 0xFF], 128));
        assert!(!check_standard_asmap(&[0xFF, 0xFF, 0xFF, 0xFF]));
    }

    #[test]
    fn test_sanity_check_rejects_empty() {
        assert!(!sanity_check_asmap(&[], 128));
    }

    #[test]
    fn test_sanity_check_rejects_nonzero_padding() {
        let mut asmap = build_return_asmap(1);
        *asmap.last_mut().unwrap() |= 0x80; // set a high padding bit
        assert!(!check_standard_asmap(&asmap));
    }

    // --- asmap_version ---

    #[test]
    fn test_asmap_version_empty_returns_zero_hash() {
        assert_eq!(asmap_version(&[]), [0u8; 32]);
    }

    #[test]
    fn test_asmap_version_returns_32_bytes() {
        let v = asmap_version(b"test asmap data");
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn test_asmap_version_deterministic() {
        let a = asmap_version(b"reproducible");
        let b = asmap_version(b"reproducible");
        assert_eq!(a, b);
    }

    #[test]
    fn test_asmap_version_double_sha256() {
        use bitcoin::hashes::{sha256, Hash};
        let data = b"\x00\x01\x02\x03";
        let inner = sha256::Hash::hash(data);
        let outer = sha256::Hash::hash(inner.as_ref());
        assert_eq!(asmap_version(data), outer.to_byte_array());
    }

    // --- asn_group_bytes ---

    #[test]
    fn test_asn_group_bytes_encoding() {
        let asn: u32 = 0x000F_4240; // 1,000,000
        let result = asn_group_bytes(asn);
        assert_eq!(result[0], NET_IPV6);
        assert_eq!(result[1], (asn & 0xFF) as u8);
        assert_eq!(result[2], ((asn >> 8) & 0xFF) as u8);
        assert_eq!(result[3], ((asn >> 16) & 0xFF) as u8);
        assert_eq!(result[4], ((asn >> 24) & 0xFF) as u8);
        assert_eq!(result, [2, 0x40, 0x42, 0x0F, 0x00]);
    }

    #[test]
    fn test_asn_group_bytes_always_5() {
        for asn in [1u32, 1000, 65536, 0xFF_FFFF] {
            assert_eq!(asn_group_bytes(asn).len(), 5);
        }
    }

    // --- ipv4_to_ipv4_in_ipv6 ---

    #[test]
    fn test_ipv4_in_ipv6_structure() {
        let buf = ipv4_to_ipv4_in_ipv6(&[8, 8, 8, 8]);
        assert_eq!(&buf[..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xFF, 0xFF]);
        assert_eq!(&buf[12..], &[8, 8, 8, 8]);
    }

    // --- get_mapped_as ---

    #[test]
    fn test_get_mapped_as_empty_asmap_returns_0() {
        let ip = ipv4_16(8, 8, 8, 8);
        assert_eq!(get_mapped_as(&[], &ip), 0);
    }

    #[test]
    fn test_get_mapped_as_ipv4_constant_asmap() {
        let asmap = build_return_asmap(15169);
        let ip = ipv4_16(8, 8, 8, 8);
        assert_eq!(get_mapped_as(&asmap, &ip), 15169);
    }

    // --- load_asmap (filesystem tests) ---

    #[test]
    fn test_load_asmap_missing_path_returns_empty() {
        let result = load_asmap("/nonexistent/path/to/asmap.dat");
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_asmap_valid_file() {
        let asmap_data = build_return_asmap(42);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &asmap_data).unwrap();
        let loaded = load_asmap(tmp.path().to_str().unwrap());
        assert_eq!(loaded, asmap_data);
    }

    #[test]
    fn test_load_asmap_oversized_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Write MAX + 1 bytes of zeros
        let oversized = vec![0u8; MAX_ASMAP_FILE_SIZE + 1];
        std::fs::write(tmp.path(), &oversized).unwrap();
        let result = load_asmap(tmp.path().to_str().unwrap());
        assert!(result.is_empty(), "Oversized file should be rejected");
    }
}
