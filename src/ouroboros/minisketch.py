"""
Minisketch-based set reconciliation for BIP 330 (Erlay).

This module implements a BCH-code-based sketch data structure that can
efficiently compute the symmetric difference between two sets.  Each
element is mapped to a ``field_bits``-bit finite-field element, and
the sketch is essentially the first *capacity* power sums of those
elements over GF(2^field_bits).

Overview
--------
1. A Minisketch holds *syndromes* S_1 … S_c where
       S_k = Σ a_i^k   for every element a_i in the set,
   with all arithmetic in GF(2^field_bits).

2. Two sketches computed over different sets can be XORed (merged).
   The result encodes the *symmetric difference* of the two sets.

3. The syndromes of the difference sketch can be decoded into up to
   *capacity* individual elements via the Berlekamp–Massey algorithm
   followed by a Chien search.

Implementation follows the libminisketch reference:
    https://github.com/sipa/minisketch

The default field size is 32 bits, which means each transaction is
mapped to a 32-bit short ID via SipHash.  A capacity-*c* sketch is
serialized as ``c * 4`` bytes.

Reference: BIP 330, libminisketch, Erlay paper (Naumenko et al. 2019)
"""

from __future__ import annotations

import logging
import struct
from collections import OrderedDict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Hard cap on a per-peer ``ReconciliationSet.announced_txids`` FIFO.
#
# ``announced_txids`` is the BIP-330 / Erlay per-peer dedup-of-already-
# announced set: ``mark_announced`` records every txid we have successfully
# announced to a peer so ``add_tx`` never re-queues it.  At tip the node
# announces transactions continuously, so a plain ``set[bytes]`` grew without
# bound, per peer — the exact at-tip RSS-leak shape that
# ``TrickleQueue.known_filter`` (p2p.py) already fixed by switching to a
# bounded ``OrderedDict`` FIFO.  We mirror that here: cap the FIFO and evict
# the oldest entry on insert.  Dropping an old entry only risks re-announcing a
# very-stale txid the peer has long since forgotten (harmless — the peer just
# replies notfound / ignores a dup), which is exactly the trade-off Core's
# rolling bloom filter makes.
#
# Sized to match KNOWN_FILTER_MAX_ENTRIES (50_000) in p2p.py so the two
# per-peer dedup structures stay on the same memory budget.
ANNOUNCED_TXIDS_MAX_ENTRIES = 50_000


# GF(2^32) arithmetic

# Irreducible polynomial for GF(2^32): x^32 + x^7 + x^3 + x^2 + 1
# Represented as the low-order 32 bits (the x^32 term is implicit).
GF32_MODULUS = (1 << 7) | (1 << 3) | (1 << 2) | (1 << 0)  # 0x8D
FIELD_BITS = 32
FIELD_SIZE = 1 << FIELD_BITS      # 2^32
FIELD_MASK = FIELD_SIZE - 1       # 0xFFFFFFFF


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^32) with modular reduction."""
    result = 0
    a &= FIELD_MASK
    b &= FIELD_MASK
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & FIELD_SIZE:  # overflowed 32 bits
            a ^= GF32_MODULUS
            a &= FIELD_MASK
        b >>= 1
    return result & FIELD_MASK


def gf_sq(a: int) -> int:
    """Square in GF(2^32) — slightly faster than gf_mul(a, a)."""
    return gf_mul(a, a)


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^32) via repeated squaring; returns 0 when *a* == 0."""
    if a == 0:
        return 0
    # Use exponentiation: a^(2^32 - 2) = a^(-1) in GF(2^32).
    # Computed via repeated squaring (addition chain for 2^32 - 2).
    # 2^32 - 2 = 0xFFFFFFFE
    result = a
    for _ in range(30):
        result = gf_sq(result)
        result = gf_mul(result, a)
    result = gf_sq(result)
    return result


def gf_pow(base: int, exp: int) -> int:
    """Exponentiation in GF(2^32) via repeated squaring."""
    result = 1
    base &= FIELD_MASK
    while exp > 0:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_sq(base)
        exp >>= 1
    return result


# Berlekamp-Massey algorithm

def berlekamp_massey(syndromes: list[int]) -> list[int] | None:
    """Berlekamp–Massey over GF(2^32): returns the error-locator polynomial Λ(x), or None on failure."""
    n = len(syndromes)
    # Current connection polynomial (LFSR taps)
    C = [0] * (n + 1)
    C[0] = 1
    # Previous connection polynomial
    B = [0] * (n + 1)
    B[0] = 1
    L = 0       # Current LFSR length
    m = 1       # Shift count since last length change
    b = 1       # Previous discrepancy

    for nn in range(n):
        # Compute discrepancy
        d = syndromes[nn]
        for i in range(1, L + 1):
            d ^= gf_mul(C[i], syndromes[nn - i])

        if d == 0:
            m += 1
            continue

        T = C[:]  # Save C
        coeff = gf_mul(d, gf_inv(b))
        for i in range(m, n + 1):
            C[i] ^= gf_mul(coeff, B[i - m])

        if 2 * L <= nn:
            L = nn + 1 - L
            B = T
            b = d
            m = 1
        else:
            m += 1

    # The error-locator polynomial has degree L
    poly = C[:L + 1]
    return poly


# --- Polynomial arithmetic over GF(2^32) ---

def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    if not a or not b:
        return []
    result = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if ca == 0:
            continue
        for j, cb in enumerate(b):
            if cb == 0:
                continue
            result[i + j] ^= gf_mul(ca, cb)
    return result


def _poly_mod(a: list[int], b: list[int]) -> list[int]:
    a = list(a)
    db = len(b) - 1
    inv_lead = gf_inv(b[db])
    while len(a) > db:
        if a[-1] != 0:
            coeff = gf_mul(a[-1], inv_lead)
            offset = len(a) - len(b)
            for i in range(len(b)):
                a[offset + i] ^= gf_mul(coeff, b[i])
        a.pop()
    # Strip trailing zeros
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _poly_divmod(a: list[int], b: list[int]) -> tuple[list[int], list[int]]:
    a = list(a)
    db = len(b) - 1
    if db < 0 or (len(b) == 1 and b[0] == 0):
        raise ValueError("Division by zero polynomial")
    inv_lead = gf_inv(b[db])
    quot: list[int] = []
    while len(a) >= len(b):
        coeff = gf_mul(a[-1], inv_lead)
        quot.append(coeff)
        for i in range(len(b)):
            a[len(a) - len(b) + i] ^= gf_mul(coeff, b[i])
        a.pop()
    # Strip trailing zeros from remainder
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    quot.reverse()
    return quot, a


def _poly_gcd(a: list[int], b: list[int]) -> list[int]:
    while b and not (len(b) == 1 and b[0] == 0):
        a, b = b, _poly_mod(a, b)
    # Normalize: make leading coefficient 1
    if a and a[-1] != 0:
        inv_lead = gf_inv(a[-1])
        a = [gf_mul(c, inv_lead) for c in a]
    return a


def _poly_powmod(base: list[int], exp: int, mod: list[int]) -> list[int]:
    result = [1]  # polynomial 1
    base = _poly_mod(base, mod)
    while exp > 0:
        if exp & 1:
            result = _poly_mod(_poly_mul(result, base), mod)
        base = _poly_mod(_poly_mul(base, base), mod)
        exp >>= 1
    return result


# Root finding via Cantor-Zassenhaus and square-free splitting

def _solve_quadratic_trace(d: int) -> int | None:
    import random as _rng
    rng = _rng.Random(0xBEEF)  # deterministic for reproducibility
    for _ in range(200):
        c = rng.randint(1, FIELD_MASK)
        z = 0
        w = c
        for _i in range(FIELD_BITS - 1):
            z = gf_sq(z) ^ gf_mul(gf_sq(w), d)
            w = gf_sq(w) ^ c
        if w != 0:
            t = gf_mul(z, gf_inv(w))
            if (gf_sq(t) ^ t) == d:
                return t
    return None


def _find_roots_linear(poly: list[int]) -> list[int] | None:
    if len(poly) != 2 or poly[1] == 0:
        return None
    root = gf_mul(poly[0], gf_inv(poly[1]))
    if root == 0:
        return None
    return [root]


def _find_roots_quadratic(poly: list[int]) -> list[int] | None:
    if len(poly) != 3 or poly[2] == 0:
        return None
    inv_a = gf_inv(poly[2])
    b = gf_mul(poly[1], inv_a)
    c = gf_mul(poly[0], inv_a)
    # Now solve x^2 + bx + c = 0
    if b == 0:
        # x^2 + c = 0 → x = sqrt(c) = c^(2^(32-1))
        root = gf_pow(c, 1 << (FIELD_BITS - 1))
        if root == 0:
            return None
        return [root]
    # Substitution x = b*t → t^2 + t + c/b^2 = 0
    d = gf_mul(c, gf_inv(gf_sq(b)))
    t = _solve_quadratic_trace(d)
    if t is None:
        return None
    x1 = gf_mul(b, t)
    x2 = x1 ^ b
    roots = []
    if x1 != 0:
        roots.append(x1)
    if x2 != 0:
        roots.append(x2)
    return roots if roots else None


def _factor_poly(poly: list[int]) -> list[int] | None:
    """Find all roots of a polynomial over GF(2^32) using randomized factorization."""
    import random as _random

    degree = len(poly) - 1
    if degree == 0:
        return []
    if degree == 1:
        return _find_roots_linear(poly)
    if degree == 2:
        return _find_roots_quadratic(poly)

    # Normalize polynomial (make leading coefficient 1)
    inv_lead = gf_inv(poly[-1])
    poly = [gf_mul(c, inv_lead) for c in poly]

    roots: list[int] = []
    stack = [poly]
    rng = _random.Random(0xBEEF)  # deterministic for reproducibility

    # Exponents for multiplicative splitting:
    # 2^32 - 1 = 3 × 5 × 17 × 257 × 65537
    q_minus_1 = FIELD_SIZE - 1  # 2^32 - 1
    split_divisors = [3, 5, 17, 257, 65537]
    split_exponents = [q_minus_1 // d for d in split_divisors]

    max_iterations = 500  # safety bound

    while stack and len(roots) < degree and max_iterations > 0:
        max_iterations -= 1
        f = stack.pop()
        d = len(f) - 1
        if d == 0:
            continue
        if d == 1:
            r = _find_roots_linear(f)
            if r:
                roots.extend(r)
            continue
        if d == 2:
            r = _find_roots_quadratic(f)
            if r:
                roots.extend(r)
            continue

        # Strategy 1: Trace-based splitting
        delta = rng.randint(1, FIELD_MASK)
        h = [delta, 1]  # h(x) = x + delta
        # Compute trace: h + h^2 + h^(2^2) + ... + h^(2^(31)) mod f
        t_poly = list(h)
        cur = list(h)
        for _ in range(FIELD_BITS - 1):
            cur = _poly_mod(_poly_mul(cur, cur), f)
            max_len = max(len(t_poly), len(cur))
            new_t = [0] * max_len
            for j in range(len(t_poly)):
                new_t[j] = t_poly[j]
            for j in range(len(cur)):
                new_t[j] ^= cur[j]
            while len(new_t) > 1 and new_t[-1] == 0:
                new_t.pop()
            t_poly = new_t

        g = _poly_gcd(f, t_poly)
        dg = len(g) - 1

        if 0 < dg < d:
            qr, _rem = _poly_divmod(f, g)
            stack.append(g)
            stack.append(qr)
            continue

        # Strategy 2: Multiplicative-order splitting
        # Pick random poly r(x), compute r^((q-1)/d) mod f
        # then gcd(f, r^e - 1) separates roots by d-th root of unity
        split_found = False
        r_poly = [rng.randint(0, FIELD_MASK) for _ in range(d)]
        while len(r_poly) > 1 and r_poly[-1] == 0:
            r_poly.pop()

        for exp in split_exponents:
            re = _poly_powmod(r_poly, exp, f)
            # Try gcd(f, r^e + 1) (in GF(2), -1 = +1, so r^e - 1 = r^e + 1 = r^e XOR 1)
            re_xor_1 = list(re)
            re_xor_1[0] ^= 1
            while len(re_xor_1) > 1 and re_xor_1[-1] == 0:
                re_xor_1.pop()

            g2 = _poly_gcd(f, re_xor_1)
            dg2 = len(g2) - 1

            if 0 < dg2 < d:
                qr, _rem = _poly_divmod(f, g2)
                stack.append(g2)
                stack.append(qr)
                split_found = True
                break

        if not split_found:
            # Push back and try again with different randomness
            stack.append(f)

    if len(roots) != degree:
        return None
    return roots


def find_roots(poly: list[int]) -> list[int] | None:
    """Return set-difference elements (inverse of roots) via Cantor–Zassenhaus; None on failure."""
    degree = len(poly) - 1
    if degree == 0:
        return []
    if degree == 1:
        root = gf_mul(poly[0], gf_inv(poly[1]))
        if root == 0:
            return None
        return [gf_inv(root)]

    # Find roots of the polynomial directly
    roots = _factor_poly(poly)
    if roots is None:
        return None
    # Return inverses of roots (the actual set elements)
    elements = []
    for r in roots:
        if r == 0:
            return None
        elements.append(gf_inv(r))
    return elements


# Minisketch data structure #

@dataclass
class Minisketch:
    """
    BCH-based sketch for set reconciliation over GF(2^32).

    A sketch of capacity *c* can recover the symmetric difference
    of two sets as long as the difference contains at most *c*
    elements.

    Internally the sketch stores *c* odd power sums:
        S_1, S_3, S_5, …, S_{2c-1}

    In characteristic 2, the even power sums satisfy S_{2k} = S_k²,
    so all 2c syndromes (S_1 through S_{2c}) are available for
    decoding via Berlekamp–Massey, which can then recover up to c
    error positions.

    Attributes:
        capacity: maximum number of differences that can be decoded
        syndromes: list of *capacity* odd-power-sum values in GF(2^32)
                   (indices 0..c-1 store S_1, S_3, …, S_{2c-1})
    """
    capacity: int
    syndromes: list[int] = field(default_factory=list)

    def __post_init__(self):
        if not self.syndromes:
            self.syndromes = [0] * self.capacity

    # Mutation

    def add(self, element: int) -> None:
        """Add (or remove) a non-zero GF(2^32) element; updates odd power sums S_1…S_{2c-1}."""
        if element == 0:
            raise ValueError("Cannot add zero element to sketch")
        element &= FIELD_MASK
        e_sq = gf_sq(element)  # element^2
        val = element           # element^1 for S_1
        for i in range(self.capacity):
            self.syndromes[i] ^= val
            # Advance from element^(2i+1) to element^(2i+3) = element^(2i+1) * element^2
            val = gf_mul(val, e_sq)

    def add_all(self, elements: set[int]) -> None:
        """Add every element from a set into the sketch."""
        for e in elements:
            if e != 0:
                self.add(e)

    # Merge (XOR)

    def merge(self, other: Minisketch) -> Minisketch:
        """XOR *other* into this sketch and return a new Minisketch encoding the symmetric difference."""
        if self.capacity != other.capacity:
            raise ValueError(
                f"Cannot merge sketches with different capacities "
                f"({self.capacity} vs {other.capacity})"
            )
        merged_syndromes = [
            self.syndromes[i] ^ other.syndromes[i]
            for i in range(self.capacity)
        ]
        return Minisketch(capacity=self.capacity, syndromes=merged_syndromes)

    def merge_inplace(self, other: Minisketch) -> None:
        """XOR another sketch into this one (in place)."""
        if self.capacity != other.capacity:
            raise ValueError(
                f"Cannot merge sketches with different capacities "
                f"({self.capacity} vs {other.capacity})"
            )
        for i in range(self.capacity):
            self.syndromes[i] ^= other.syndromes[i]

    def _expand_syndromes(self) -> list[int]:
        n = self.capacity
        full = [0] * (2 * n)
        # Place odd syndromes: S_{2i+1} at index 2*i
        for i in range(n):
            full[2 * i] = self.syndromes[i]  # S_{2i+1}
        # Derive even syndromes: S_{2k} = S_k^2 (index 2k-1 stores S_{2k})
        for k in range(1, n + 1):
            # S_{2k} is at index 2k-1
            # S_k is at index k-1
            full[2 * k - 1] = gf_sq(full[k - 1])
        return full

    # Decode

    def decode(self) -> set[int] | None:
        """Decode the sketch into its elements; returns None if the difference exceeds capacity."""
        # All-zero syndromes → empty difference
        if all(s == 0 for s in self.syndromes):
            return set()

        # Expand to full 2*capacity syndromes for Berlekamp–Massey
        full_syndromes = self._expand_syndromes()

        poly = berlekamp_massey(full_syndromes)
        if poly is None:
            return None

        degree = len(poly) - 1
        if degree == 0:
            return set()
        if degree > self.capacity:
            return None

        elements = find_roots(poly)
        if elements is None:
            return None

        # Verify: recompute syndromes and check they match
        check = Minisketch(capacity=self.capacity)
        for e in elements:
            check.add(e)
        if check.syndromes != self.syndromes:
            return None

        return set(elements)

    # Serialization

    def serialize(self) -> bytes:
        """Serialize to bytes: each syndrome as a 4-byte little-endian uint32 (capacity × 4 bytes total)."""
        data = bytearray()
        for s in self.syndromes:
            data.extend(struct.pack('<I', s & FIELD_MASK))
        return bytes(data)

    @classmethod
    def deserialize(cls, data: bytes, capacity: int) -> Minisketch:
        """Deserialize a sketch from *capacity × 4* bytes (each syndrome as a 4-byte little-endian uint32)."""
        expected = capacity * 4
        if len(data) < expected:
            raise ValueError(
                f"Sketch data too short: got {len(data)}, need {expected}"
            )
        syndromes = []
        for i in range(capacity):
            s = struct.unpack('<I', data[i * 4:(i + 1) * 4])[0]
            syndromes.append(s)
        return cls(capacity=capacity, syndromes=syndromes)


# Short transaction ID helpers

def compute_short_txid(txid: bytes, salt1: int, salt2: int) -> int:
    """Map a 32-byte txid to a 32-bit short ID via SipHash-2-4 (BIP 330 XOR-salt key); 0 → 1."""
    # Combine salts
    combined_salt = salt1 ^ salt2
    # Build 16-byte SipHash key from the combined salt
    key = struct.pack('<QQ', combined_salt, combined_salt)
    # Use SipHash from compact_blocks module
    from ouroboros.compact_blocks import _siphash_2_4
    h = _siphash_2_4(key, txid)
    short_id = h & FIELD_MASK  # Truncate to 32 bits
    # Zero is not a valid GF element; remap to 1
    return short_id if short_id != 0 else 1


# Reconciliation set manager

@dataclass
class ReconciliationSet:
    """
    Per-peer reconciliation set tracking.

    Tracks which transactions should be reconciled with a specific
    peer and builds sketches for reconciliation rounds.

    Attributes:
        local_salt: our 64-bit salt for this connection
        remote_salt: peer's 64-bit salt for this connection
        local_set: set of raw txids we want to reconcile with this peer
        announced_txids: txids already successfully announced to this peer
    """
    local_salt: int = 0
    remote_salt: int = 0
    local_set: set[bytes] = field(default_factory=set)
    # Bounded FIFO of already-announced txids (membership-test only).  Stored
    # as an ``OrderedDict[bytes, None]`` rather than a plain ``set`` so the
    # oldest entry can be evicted once ``ANNOUNCED_TXIDS_MAX_ENTRIES`` is
    # reached, keeping per-peer memory bounded at tip.  ``in`` / ``len`` work
    # the same as on a set, so existing readers (and the
    # ``txid in rs.announced_txids`` membership tests) are unaffected.  Mirrors
    # ``TrickleQueue.known_filter`` in p2p.py.
    announced_txids: OrderedDict[bytes, None] = field(default_factory=OrderedDict)
    # FIFO cap; overridable per-instance for tests.
    _announced_max: int = ANNOUNCED_TXIDS_MAX_ENTRIES

    def add_tx(self, txid: bytes) -> None:
        """Add a transaction to the reconciliation set."""
        if txid not in self.announced_txids:
            self.local_set.add(txid)

    def mark_announced(self, txid: bytes) -> None:
        """Mark a transaction as successfully announced.

        Records *txid* in the bounded ``announced_txids`` FIFO, evicting the
        oldest entry once the cap is reached.  Re-announcing an existing txid
        refreshes its position (LRU-on-touch) so the most-recently announced
        txids survive longest — matching ``TrickleQueue._known_filter_add``.
        """
        if txid in self.announced_txids:
            self.announced_txids.move_to_end(txid)
        else:
            if len(self.announced_txids) >= self._announced_max:
                # FIFO eviction: drop the oldest announced txid.
                self.announced_txids.popitem(last=False)
            self.announced_txids[txid] = None
        self.local_set.discard(txid)

    def get_short_ids(self) -> set[int]:
        """Map all txids in the local set to short IDs."""
        return {
            compute_short_txid(txid, self.local_salt, self.remote_salt)
            for txid in self.local_set
        }

    def txid_to_short_id(self, txid: bytes) -> int:
        """Map a single txid to its short ID."""
        return compute_short_txid(txid, self.local_salt, self.remote_salt)

    def build_sketch(self, capacity: int) -> Minisketch:
        """Build a sketch from the current reconciliation set."""
        sketch = Minisketch(capacity=capacity)
        for txid in self.local_set:
            short_id = compute_short_txid(
                txid, self.local_salt, self.remote_salt
            )
            sketch.add(short_id)
        return sketch

    def short_id_to_txid_map(self) -> dict:
        """Build a reverse map from short IDs to txids."""
        mapping = {}
        for txid in self.local_set:
            short_id = compute_short_txid(
                txid, self.local_salt, self.remote_salt
            )
            mapping[short_id] = txid
        return mapping

    def clear(self) -> None:
        """Clear the reconciliation set (after successful reconciliation)."""
        self.local_set.clear()

    @property
    def set_size(self) -> int:
        """Number of transactions pending reconciliation."""
        return len(self.local_set)


def estimate_sketch_capacity(
    local_size: int,
    remote_size: int,
    q: float = 0.1,
) -> int:
    """BIP 330 capacity estimate: ``|diff| + q*min(local, remote) + 1``, clamped to [1, 2^15]."""
    abs_diff = abs(local_size - remote_size)
    min_size = min(local_size, remote_size)
    capacity = int(abs_diff + q * min_size) + 1
    # Clamp to reasonable range
    return max(1, min(capacity, 1 << 15))
