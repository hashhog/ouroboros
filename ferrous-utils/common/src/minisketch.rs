//! Minisketch-based set reconciliation for BIP 330 (Erlay).
//!
//! This module implements a BCH-code-based sketch data structure that can
//! efficiently compute the symmetric difference between two sets. Each
//! element is mapped to a 32-bit finite-field element, and the sketch
//! stores odd power sums in GF(2^32).
//!
//! Reference: BIP 330, libminisketch (https://github.com/sipa/minisketch)

use std::collections::HashSet;

/// Field size: GF(2^32)
const FIELD_BITS: u32 = 32;
const FIELD_SIZE: u64 = 1 << FIELD_BITS;
const FIELD_MASK: u32 = 0xFFFFFFFF;

/// Irreducible polynomial for GF(2^32): x^32 + x^7 + x^3 + x^2 + 1
/// Represented as the low-order 32 bits (the x^32 term is implicit).
const GF32_MODULUS: u32 = (1 << 7) | (1 << 3) | (1 << 2) | 1; // 0x8D

/// Multiply two elements in GF(2^32) with modular reduction.
#[inline]
pub fn gf_mul(a: u32, b: u32) -> u32 {
    let mut result: u32 = 0;
    let mut a_shifted = a;
    let mut b_remaining = b;

    while b_remaining != 0 {
        if b_remaining & 1 != 0 {
            result ^= a_shifted;
        }
        // Check if MSB is set before shift (would overflow)
        let overflow = a_shifted & 0x80000000 != 0;
        a_shifted <<= 1;
        if overflow {
            a_shifted ^= GF32_MODULUS;
        }
        b_remaining >>= 1;
    }
    result
}

/// Square in GF(2^32).
#[inline]
pub fn gf_sq(a: u32) -> u32 {
    gf_mul(a, a)
}

/// Multiplicative inverse in GF(2^32) via Fermat's little theorem.
/// Returns 0 when a == 0.
#[inline]
pub fn gf_inv(a: u32) -> u32 {
    if a == 0 {
        return 0;
    }
    // a^(2^32 - 2) = a^(-1) in GF(2^32)
    // 2^32 - 2 = 0xFFFFFFFE
    let mut result = a;
    for _ in 0..30 {
        result = gf_sq(result);
        result = gf_mul(result, a);
    }
    gf_sq(result)
}

/// Exponentiation in GF(2^32) via repeated squaring.
#[inline]
pub fn gf_pow(base: u32, mut exp: u64) -> u32 {
    let mut result: u32 = 1;
    let mut base_pow = base;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base_pow);
        }
        base_pow = gf_sq(base_pow);
        exp >>= 1;
    }
    result
}

/// Berlekamp-Massey algorithm over GF(2^32).
/// Returns the error-locator polynomial coefficients, or None on failure.
fn berlekamp_massey(syndromes: &[u32]) -> Option<Vec<u32>> {
    let n = syndromes.len();
    if n == 0 {
        return Some(vec![1]);
    }

    let mut c = vec![0u32; n + 1]; // Current connection polynomial
    let mut b = vec![0u32; n + 1]; // Previous connection polynomial
    c[0] = 1;
    b[0] = 1;
    let mut l: usize = 0; // Current LFSR length
    let mut m: usize = 1; // Shift count since last length change
    let mut b_discrepancy: u32 = 1; // Previous discrepancy

    for nn in 0..n {
        // Compute discrepancy
        let mut d = syndromes[nn];
        for i in 1..=l {
            d ^= gf_mul(c[i], syndromes[nn - i]);
        }

        if d == 0 {
            m += 1;
            continue;
        }

        let t = c.clone(); // Save C
        let coeff = gf_mul(d, gf_inv(b_discrepancy));
        for i in m..=n {
            c[i] ^= gf_mul(coeff, b[i - m]);
        }

        if 2 * l <= nn {
            l = nn + 1 - l;
            b = t;
            b_discrepancy = d;
            m = 1;
        } else {
            m += 1;
        }
    }

    // Extract polynomial of degree L
    Some(c[..=l].to_vec())
}

// --- Polynomial arithmetic over GF(2^32) ---

fn poly_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut result = vec![0u32; a.len() + b.len() - 1];
    for (i, &ca) in a.iter().enumerate() {
        if ca == 0 {
            continue;
        }
        for (j, &cb) in b.iter().enumerate() {
            if cb != 0 {
                result[i + j] ^= gf_mul(ca, cb);
            }
        }
    }
    result
}

fn poly_mod(mut a: Vec<u32>, b: &[u32]) -> Vec<u32> {
    if b.is_empty() || (b.len() == 1 && b[0] == 0) {
        return a;
    }
    let db = b.len() - 1;
    let inv_lead = gf_inv(b[db]);

    while a.len() > db {
        if a[a.len() - 1] != 0 {
            let coeff = gf_mul(a[a.len() - 1], inv_lead);
            let offset = a.len() - b.len();
            for (i, &bi) in b.iter().enumerate() {
                a[offset + i] ^= gf_mul(coeff, bi);
            }
        }
        a.pop();
    }

    // Strip trailing zeros
    while a.len() > 1 && a[a.len() - 1] == 0 {
        a.pop();
    }
    a
}

fn poly_gcd(mut a: Vec<u32>, mut b: Vec<u32>) -> Vec<u32> {
    while !b.is_empty() && !(b.len() == 1 && b[0] == 0) {
        let rem = poly_mod(a, &b);
        a = b;
        b = rem;
    }
    // Normalize: make leading coefficient 1
    if !a.is_empty() && a[a.len() - 1] != 0 {
        let inv_lead = gf_inv(a[a.len() - 1]);
        for c in &mut a {
            *c = gf_mul(*c, inv_lead);
        }
    }
    a
}

fn poly_powmod(base: &[u32], mut exp: u64, modulus: &[u32]) -> Vec<u32> {
    let mut result = vec![1u32]; // polynomial 1
    let mut base_pow = poly_mod(base.to_vec(), modulus);

    while exp > 0 {
        if exp & 1 != 0 {
            result = poly_mod(poly_mul(&result, &base_pow), modulus);
        }
        base_pow = poly_mod(poly_mul(&base_pow, &base_pow), modulus);
        exp >>= 1;
    }
    result
}

/// Solve quadratic equation x^2 + x + d = 0 using trace-based method.
fn solve_quadratic_trace(d: u32) -> Option<u32> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for _ in 0..200 {
        let c: u32 = rng.gen::<u32>() | 1; // Ensure non-zero
        let mut z: u32 = 0;
        let mut w: u32 = c;

        for _ in 0..(FIELD_BITS - 1) {
            z = gf_sq(z) ^ gf_mul(gf_sq(w), d);
            w = gf_sq(w) ^ c;
        }

        if w != 0 {
            let t = gf_mul(z, gf_inv(w));
            // Verify: t^2 + t should equal d
            if (gf_sq(t) ^ t) == d {
                return Some(t);
            }
        }
    }
    None
}

/// Find roots of a linear polynomial a*x + b (degree 1).
fn find_roots_linear(poly: &[u32]) -> Option<Vec<u32>> {
    if poly.len() != 2 || poly[1] == 0 {
        return None;
    }
    let root = gf_mul(poly[0], gf_inv(poly[1]));
    if root == 0 {
        return None;
    }
    Some(vec![root])
}

/// Find roots of a quadratic polynomial a*x^2 + b*x + c.
fn find_roots_quadratic(poly: &[u32]) -> Option<Vec<u32>> {
    if poly.len() != 3 || poly[2] == 0 {
        return None;
    }

    let inv_a = gf_inv(poly[2]);
    let b = gf_mul(poly[1], inv_a);
    let c = gf_mul(poly[0], inv_a);

    // Now solve x^2 + bx + c = 0
    if b == 0 {
        // x^2 + c = 0 -> x = sqrt(c) = c^(2^(32-1))
        let root = gf_pow(c, 1u64 << (FIELD_BITS - 1));
        if root == 0 {
            return None;
        }
        return Some(vec![root]);
    }

    // Substitution x = b*t -> t^2 + t + c/b^2 = 0
    let d = gf_mul(c, gf_inv(gf_sq(b)));
    let t = solve_quadratic_trace(d)?;

    let x1 = gf_mul(b, t);
    let x2 = x1 ^ b;

    let mut roots = Vec::new();
    if x1 != 0 {
        roots.push(x1);
    }
    if x2 != 0 && x2 != x1 {
        roots.push(x2);
    }

    if roots.is_empty() {
        None
    } else {
        Some(roots)
    }
}

/// Find all roots of a polynomial using Cantor-Zassenhaus factorization.
fn factor_poly(poly: &[u32]) -> Option<Vec<u32>> {
    use rand::Rng;

    let degree = poly.len() - 1;
    if degree == 0 {
        return Some(vec![]);
    }
    if degree == 1 {
        return find_roots_linear(poly);
    }
    if degree == 2 {
        return find_roots_quadratic(poly);
    }

    // Normalize polynomial
    let inv_lead = gf_inv(poly[poly.len() - 1]);
    let poly: Vec<u32> = poly.iter().map(|&c| gf_mul(c, inv_lead)).collect();

    let mut roots: Vec<u32> = Vec::new();
    let mut stack: Vec<Vec<u32>> = vec![poly];
    let mut rng = rand::thread_rng();

    // Split exponents for multiplicative-order splitting
    let q_minus_1 = FIELD_SIZE - 1; // 2^32 - 1
    let split_divisors: [u64; 5] = [3, 5, 17, 257, 65537];
    let split_exponents: Vec<u64> = split_divisors.iter().map(|&d| q_minus_1 / d).collect();

    let mut max_iterations = 500;

    while !stack.is_empty() && roots.len() < degree && max_iterations > 0 {
        max_iterations -= 1;
        let f = stack.pop().unwrap();
        let d = f.len() - 1;

        if d == 0 {
            continue;
        }
        if d == 1 {
            if let Some(r) = find_roots_linear(&f) {
                roots.extend(r);
            }
            continue;
        }
        if d == 2 {
            if let Some(r) = find_roots_quadratic(&f) {
                roots.extend(r);
            }
            continue;
        }

        // Strategy 1: Trace-based splitting
        let delta: u32 = rng.gen();
        let h = vec![delta, 1]; // h(x) = x + delta

        // Compute trace: h + h^2 + h^(2^2) + ... + h^(2^(31)) mod f
        let mut t_poly = h.clone();
        let mut cur = h.clone();
        for _ in 0..(FIELD_BITS - 1) {
            cur = poly_mod(poly_mul(&cur, &cur), &f);
            let max_len = t_poly.len().max(cur.len());
            let mut new_t = vec![0u32; max_len];
            for (i, &v) in t_poly.iter().enumerate() {
                new_t[i] = v;
            }
            for (i, &v) in cur.iter().enumerate() {
                new_t[i] ^= v;
            }
            while new_t.len() > 1 && new_t[new_t.len() - 1] == 0 {
                new_t.pop();
            }
            t_poly = new_t;
        }

        let g = poly_gcd(f.clone(), t_poly.clone());
        let dg = g.len() - 1;

        if dg > 0 && dg < d {
            // Compute quotient via division
            if let Some(q) = poly_div(&f, &g) {
                stack.push(g);
                stack.push(q);
            }
            continue;
        }

        // Strategy 2: Multiplicative-order splitting
        let r_poly: Vec<u32> = (0..d).map(|_| rng.gen()).collect();
        let r_poly = if r_poly.iter().all(|&x| x == 0) {
            vec![1]
        } else {
            r_poly
        };

        let mut split_found = false;
        for &exp in &split_exponents {
            let re = poly_powmod(&r_poly, exp, &f);
            // Try gcd(f, r^e + 1)
            let mut re_xor_1 = re.clone();
            if !re_xor_1.is_empty() {
                re_xor_1[0] ^= 1;
            } else {
                re_xor_1.push(1);
            }
            while re_xor_1.len() > 1 && re_xor_1[re_xor_1.len() - 1] == 0 {
                re_xor_1.pop();
            }

            let g2 = poly_gcd(f.clone(), re_xor_1);
            let dg2 = g2.len() - 1;

            if dg2 > 0 && dg2 < d {
                if let Some(q) = poly_div(&f, &g2) {
                    stack.push(g2);
                    stack.push(q);
                    split_found = true;
                    break;
                }
            }
        }

        if !split_found {
            // Push back and try again
            stack.push(f);
        }
    }

    if roots.len() != degree {
        None
    } else {
        Some(roots)
    }
}

/// Polynomial division: a / b, returning quotient.
fn poly_div(a: &[u32], b: &[u32]) -> Option<Vec<u32>> {
    if b.is_empty() || (b.len() == 1 && b[0] == 0) {
        return None;
    }
    let db = b.len() - 1;
    if a.len() < b.len() {
        return Some(vec![0]);
    }

    let mut a = a.to_vec();
    let inv_lead = gf_inv(b[db]);
    let mut quot = Vec::new();

    while a.len() >= b.len() {
        let coeff = gf_mul(a[a.len() - 1], inv_lead);
        quot.push(coeff);
        let offset = a.len() - b.len();
        for (i, &bi) in b.iter().enumerate() {
            a[offset + i] ^= gf_mul(coeff, bi);
        }
        a.pop();
    }

    quot.reverse();
    Some(quot)
}

/// Find set elements from polynomial roots (inverses).
fn find_roots(poly: &[u32]) -> Option<Vec<u32>> {
    let degree = poly.len() - 1;
    if degree == 0 {
        return Some(vec![]);
    }

    let roots = factor_poly(poly)?;

    // Return inverses of roots (the actual set elements)
    let mut elements = Vec::new();
    for r in roots {
        if r == 0 {
            return None;
        }
        elements.push(gf_inv(r));
    }
    Some(elements)
}

/// BCH-based sketch for set reconciliation over GF(2^32).
///
/// A sketch of capacity `c` can recover the symmetric difference
/// of two sets as long as the difference contains at most `c` elements.
#[derive(Clone, Debug)]
pub struct Minisketch {
    /// Maximum number of differences that can be decoded.
    capacity: usize,
    /// Odd-power-sum syndromes: S_1, S_3, S_5, ..., S_{2c-1}.
    syndromes: Vec<u32>,
}

impl Minisketch {
    /// Create a new sketch with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            syndromes: vec![0; capacity],
        }
    }

    /// Create a sketch from existing syndromes.
    pub fn from_syndromes(syndromes: Vec<u32>) -> Self {
        let capacity = syndromes.len();
        Self { capacity, syndromes }
    }

    /// Get the capacity of this sketch.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the syndromes.
    pub fn syndromes(&self) -> &[u32] {
        &self.syndromes
    }

    /// Add (or remove, since XOR is self-inverse) a non-zero element.
    pub fn add(&mut self, element: u32) {
        assert!(element != 0, "Cannot add zero element to sketch");
        let e_sq = gf_sq(element); // element^2
        let mut val = element; // element^1 for S_1

        for i in 0..self.capacity {
            self.syndromes[i] ^= val;
            // Advance from element^(2i+1) to element^(2i+3)
            val = gf_mul(val, e_sq);
        }
    }

    /// Add all elements from a set.
    pub fn add_all(&mut self, elements: &HashSet<u32>) {
        for &e in elements {
            if e != 0 {
                self.add(e);
            }
        }
    }

    /// Merge another sketch into this one (XOR).
    pub fn merge(&mut self, other: &Minisketch) {
        assert_eq!(
            self.capacity, other.capacity,
            "Cannot merge sketches with different capacities"
        );
        for i in 0..self.capacity {
            self.syndromes[i] ^= other.syndromes[i];
        }
    }

    /// Merge two sketches, returning a new sketch encoding the symmetric difference.
    pub fn merge_new(&self, other: &Minisketch) -> Minisketch {
        let mut result = self.clone();
        result.merge(other);
        result
    }

    /// Expand odd syndromes to full 2*capacity syndromes for decoding.
    fn expand_syndromes(&self) -> Vec<u32> {
        let n = self.capacity;
        let mut full = vec![0u32; 2 * n];

        // Place odd syndromes: S_{2i+1} at index 2*i
        for i in 0..n {
            full[2 * i] = self.syndromes[i]; // S_{2i+1}
        }

        // Derive even syndromes: S_{2k} = S_k^2 (in characteristic 2)
        for k in 1..=n {
            // S_{2k} is at index 2k-1
            // S_k is at index k-1
            full[2 * k - 1] = gf_sq(full[k - 1]);
        }

        full
    }

    /// Decode the sketch into its elements.
    /// Returns None if the difference exceeds capacity.
    pub fn decode(&self) -> Option<HashSet<u32>> {
        // All-zero syndromes -> empty difference
        if self.syndromes.iter().all(|&s| s == 0) {
            return Some(HashSet::new());
        }

        // Expand to full 2*capacity syndromes
        let full_syndromes = self.expand_syndromes();

        // Run Berlekamp-Massey
        let poly = berlekamp_massey(&full_syndromes)?;

        let degree = poly.len() - 1;
        if degree == 0 {
            return Some(HashSet::new());
        }
        if degree > self.capacity {
            return None;
        }

        // Find roots and convert to elements
        let elements = find_roots(&poly)?;

        // Verify: recompute syndromes and check they match
        let mut check = Minisketch::new(self.capacity);
        for &e in &elements {
            check.add(e);
        }
        if check.syndromes != self.syndromes {
            return None;
        }

        Some(elements.into_iter().collect())
    }

    /// Serialize to bytes: each syndrome as 4-byte little-endian u32.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.capacity * 4);
        for &s in &self.syndromes {
            data.extend_from_slice(&s.to_le_bytes());
        }
        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8], capacity: usize) -> Result<Self, &'static str> {
        let expected = capacity * 4;
        if data.len() < expected {
            return Err("Sketch data too short");
        }

        let mut syndromes = Vec::with_capacity(capacity);
        for i in 0..capacity {
            let bytes: [u8; 4] = data[i * 4..(i + 1) * 4].try_into().unwrap();
            syndromes.push(u32::from_le_bytes(bytes));
        }

        Ok(Self { capacity, syndromes })
    }
}

/// Estimate sketch capacity based on set sizes per BIP 330.
/// Formula: |diff| + q*min(local, remote) + 1, clamped to [1, 2^15].
pub fn estimate_sketch_capacity(local_size: usize, remote_size: usize, q: f64) -> usize {
    let abs_diff = (local_size as isize - remote_size as isize).unsigned_abs();
    let min_size = local_size.min(remote_size);
    let capacity = abs_diff + (q * min_size as f64) as usize + 1;
    capacity.clamp(1, 1 << 15)
}

/// Compute a 32-bit short txid from a wtxid using SipHash.
/// Zero is remapped to 1 since GF(2^32) requires non-zero elements.
pub fn compute_short_txid(wtxid: &[u8; 32], k0: u64, k1: u64) -> u32 {
    use siphasher::sip::SipHasher24;
    use std::hash::Hasher;

    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(wtxid);
    let h = hasher.finish();

    let short_id = (h & 0xFFFFFFFF) as u32;
    if short_id == 0 {
        1
    } else {
        short_id
    }
}

/// Compute the reconciliation salt from two peer salts per BIP 330.
/// Salts are combined in ascending order.
pub fn compute_reconciliation_salt(salt1: u64, salt2: u64) -> (u64, u64) {
    use sha2::{Digest, Sha256};

    // BIP 330: Tag "Tx Relay Salting", combine salts in ascending order
    let tag = b"Tx Relay Salting";
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag); // Tagged hash: SHA256(tag || tag || data)

    let (s1, s2) = if salt1 < salt2 {
        (salt1, salt2)
    } else {
        (salt2, salt1)
    };

    hasher.update(s1.to_le_bytes());
    hasher.update(s2.to_le_bytes());
    let hash = hasher.finalize();

    // Extract k0 and k1 for SipHash
    let k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

    (k0, k1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_basic() {
        // Multiply by 1 should return the same element
        assert_eq!(gf_mul(0x12345678, 1), 0x12345678);
        assert_eq!(gf_mul(1, 0x87654321), 0x87654321);

        // Multiply by 0 should return 0
        assert_eq!(gf_mul(0x12345678, 0), 0);
        assert_eq!(gf_mul(0, 0x87654321), 0);

        // Commutativity
        let a = 0xABCD1234;
        let b = 0x56789ABC;
        assert_eq!(gf_mul(a, b), gf_mul(b, a));
    }

    #[test]
    fn test_gf_inv() {
        // Test some inverses
        for val in [1, 2, 255, 0x12345678, 0xFFFFFFFF] {
            let inv = gf_inv(val);
            assert_eq!(gf_mul(val, inv), 1, "Inverse test failed for {}", val);
        }

        // Inverse of 0 is 0
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn test_minisketch_empty() {
        let sketch = Minisketch::new(10);
        let decoded = sketch.decode().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_minisketch_single_element() {
        let mut sketch = Minisketch::new(10);
        sketch.add(0x12345678);

        let decoded = sketch.decode().unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded.contains(&0x12345678));
    }

    #[test]
    fn test_minisketch_multiple_elements() {
        let mut sketch = Minisketch::new(10);
        let elements = vec![0x11111111, 0x22222222, 0x33333333];

        for &e in &elements {
            sketch.add(e);
        }

        let decoded = sketch.decode().unwrap();
        assert_eq!(decoded.len(), 3);
        for e in elements {
            assert!(decoded.contains(&e));
        }
    }

    #[test]
    fn test_minisketch_merge() {
        let mut sketch1 = Minisketch::new(10);
        let mut sketch2 = Minisketch::new(10);

        // Set 1: {A, B, C}
        sketch1.add(0x11111111);
        sketch1.add(0x22222222);
        sketch1.add(0x33333333);

        // Set 2: {B, C, D}
        sketch2.add(0x22222222);
        sketch2.add(0x33333333);
        sketch2.add(0x44444444);

        // Merged should contain symmetric difference: {A, D}
        let merged = sketch1.merge_new(&sketch2);
        let decoded = merged.decode().unwrap();

        assert_eq!(decoded.len(), 2);
        assert!(decoded.contains(&0x11111111));
        assert!(decoded.contains(&0x44444444));
    }

    #[test]
    fn test_minisketch_serialize_deserialize() {
        let mut sketch = Minisketch::new(5);
        sketch.add(0x12345678);
        sketch.add(0xABCDEF01);

        let serialized = sketch.serialize();
        assert_eq!(serialized.len(), 20); // 5 * 4 bytes

        let deserialized = Minisketch::deserialize(&serialized, 5).unwrap();
        assert_eq!(sketch.syndromes, deserialized.syndromes);
    }

    #[test]
    fn test_estimate_capacity() {
        // Equal sets, small difference expected
        let cap = estimate_sketch_capacity(100, 100, 0.1);
        assert!(cap >= 10 && cap <= 20);

        // Different sizes
        let cap = estimate_sketch_capacity(100, 50, 0.1);
        assert!(cap >= 50);
    }

    #[test]
    fn test_compute_short_txid() {
        let wtxid = [0x42u8; 32];
        let short_id = compute_short_txid(&wtxid, 0x1234, 0x5678);
        assert_ne!(short_id, 0);
    }

    #[test]
    fn test_xor_cancellation() {
        // Adding and then adding again should cancel out (XOR property)
        let mut sketch = Minisketch::new(10);
        sketch.add(0x12345678);
        sketch.add(0x12345678);

        // Should be back to empty
        let decoded = sketch.decode().unwrap();
        assert!(decoded.is_empty());
    }
}
