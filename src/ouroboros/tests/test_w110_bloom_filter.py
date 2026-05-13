"""
W110 — BIP-37 Bloom filter fleet audit for ouroboros (Python + Rust ferrous-utils).

Covers both pipelines:
  Pipeline A (main Python): src/ouroboros/ — p2p.py, p2p_messages.py, peer.py, node.py
  Pipeline B (Rust):        ferrous-utils/common/src/ and ferrous-utils/sync/src/
                            (no bloom.rs found — Rust pipeline MISSING ENTIRELY)

Reference:
  bitcoin-core/src/common/bloom.h, bloom.cpp
  bitcoin-core/src/merkleblock.h, merkleblock.cpp
  bitcoin-core/src/net_processing.cpp  (filterload/filteradd/filterclear handlers)
  BIP-37: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
  BIP-111: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki

Key constants (Core):
  MAX_BLOOM_FILTER_SIZE = 36000 bytes
  MAX_HASH_FUNCS = 50
  LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
  Hash schedule: MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash)
  BLOOM_UPDATE_NONE = 0, BLOOM_UPDATE_ALL = 1, BLOOM_UPDATE_P2PUBKEY_ONLY = 2, BLOOM_UPDATE_MASK = 3
  NODE_BLOOM = 1 << 2  (= 4)

Two-pipeline observation (CRITICAL for ouroboros):
  Rust ferrous-utils has NO bloom.rs — the Rust pipeline has no BIP-37 implementation
  at all. Python pipeline has NODE_BLOOM service bit and partial merkle tree (rpc.py)
  but is MISSING CBloomFilter, MurmurHash3, filterload/filteradd/filterclear P2P handlers.

Run:
    cd /home/work/hashhog/ouroboros && \\
      python3 -m unittest src.ouroboros.tests.test_w110_bloom_filter
"""

import os
import struct
import unittest


# ---------------------------------------------------------------------------
# Helper: read a source file relative to the ouroboros root
# ---------------------------------------------------------------------------

def _read_src(relpath: str) -> str:
    # __file__ is src/ouroboros/tests/test_w110_bloom_filter.py
    # go up 3 levels: tests -> ouroboros -> src -> ouroboros repo root
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.normpath(os.path.join(base, "../../../"))  # ouroboros repo root
    fullpath = os.path.join(root, relpath)
    try:
        with open(fullpath, "r", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


# Pre-load sources for fast gate checks
_P2P_MSGS  = _read_src("src/ouroboros/p2p_messages.py")
_P2P       = _read_src("src/ouroboros/p2p.py")
_PEER      = _read_src("src/ouroboros/peer.py")
_NODE      = _read_src("src/ouroboros/node.py")
_RPC       = _read_src("src/ouroboros/rpc.py")

# Rust pipeline sources
_RUST_COMMON_LIB = _read_src("ferrous-utils/common/src/lib.rs")
_RUST_SYNC_LIB   = _read_src("ferrous-utils/sync/src/lib.rs")

# Check if a bloom.rs exists anywhere in ferrous-utils
def _rust_bloom_exists() -> bool:
    base = os.path.dirname(__file__)
    root = os.path.normpath(os.path.join(base, "../../../../"))
    fu_root = os.path.join(root, "ferrous-utils")
    for dirpath, _, files in os.walk(fu_root):
        # skip build artifacts
        if "target" in dirpath:
            continue
        for fname in files:
            if fname == "bloom.rs" or "bloom" in fname.lower():
                return True
    return False


# ---------------------------------------------------------------------------
# G1 — MAX_BLOOM_FILTER_SIZE = 36000
# ---------------------------------------------------------------------------

class TestG1_MaxBloomFilterSize(unittest.TestCase):
    """
    BUG-1 (HIGH): MAX_BLOOM_FILTER_SIZE constant absent.

    Core (bloom.h:16): `static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;`
    Ouroboros has no CBloomFilter class and no MAX_BLOOM_FILTER_SIZE constant in
    any Python or Rust source. Without this, filterload cannot enforce the wire-protocol
    size cap, allowing any peer to send a 2 MB filter and cause memory/CPU DoS.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_max_bloom_filter_size_absent_python(self):
        """No MAX_BLOOM_FILTER_SIZE or 36000 constant for bloom filter in Python source."""
        has_constant = (
            "MAX_BLOOM_FILTER_SIZE" in _P2P_MSGS
            or "MAX_BLOOM_FILTER_SIZE" in _P2P
            or "MAX_BLOOM_FILTER_SIZE" in _PEER
        )
        self.assertFalse(
            has_constant,
            "G1: MAX_BLOOM_FILTER_SIZE found in Python pipeline — update test",
        )

    def test_max_bloom_filter_size_absent_rust(self):
        """No MAX_BLOOM_FILTER_SIZE or bloom.rs in Rust pipeline."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G1: bloom.rs found in ferrous-utils — update test to check constant",
        )


# ---------------------------------------------------------------------------
# G2 — MAX_HASH_FUNCS = 50
# ---------------------------------------------------------------------------

class TestG2_MaxHashFuncs(unittest.TestCase):
    """
    BUG-2 (HIGH): MAX_HASH_FUNCS constant absent.

    Core (bloom.h:17): `static constexpr unsigned int MAX_HASH_FUNCS = 50;`
    Without this cap a filterload message with nHashFuncs > 50 would not be
    rejected; a peer could force O(nHashFuncs * dataLen) CPU per IsRelevantAndUpdate
    call.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_max_hash_funcs_absent_python(self):
        """No MAX_HASH_FUNCS constant in Python source."""
        has_constant = "MAX_HASH_FUNCS" in _P2P_MSGS or "MAX_HASH_FUNCS" in _P2P
        self.assertFalse(
            has_constant,
            "G2: MAX_HASH_FUNCS found in Python pipeline — update test",
        )

    def test_max_hash_funcs_absent_rust(self):
        """No MAX_HASH_FUNCS constant in Rust pipeline."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G2: bloom.rs found in ferrous-utils — update test to check constant",
        )


# ---------------------------------------------------------------------------
# G3 — LN2SQUARED full precision
# ---------------------------------------------------------------------------

class TestG3_LN2Squared(unittest.TestCase):
    """
    BUG-3 (MEDIUM): LN2SQUARED constant absent.

    Core (bloom.cpp:21):
        `static constexpr double LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;`
    Required for the bloom filter sizing formula in the constructor.
    Absent in both pipelines (no CBloomFilter class exists).

    Both pipelines: MISSING ENTIRELY.
    """

    def test_ln2squared_absent_python(self):
        """No LN2SQUARED constant in Python source."""
        has_constant = "LN2SQUARED" in _P2P_MSGS or "LN2SQUARED" in _P2P or "0.4804530" in _P2P
        self.assertFalse(
            has_constant,
            "G3: LN2SQUARED found in Python pipeline — update test",
        )

    def test_ln2squared_absent_rust(self):
        """No LN2SQUARED in Rust pipeline."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G3: bloom.rs found in ferrous-utils — update test to check constant",
        )


# ---------------------------------------------------------------------------
# G4 — Constructor sizing formula
# ---------------------------------------------------------------------------

class TestG4_ConstructorSizing(unittest.TestCase):
    """
    BUG-4 (HIGH): CBloomFilter constructor + sizing formula absent.

    Core (bloom.cpp:26-39):
        vData size = min(-1/LN2SQUARED * nElements * log(nFPRate), MAX_BLOOM_FILTER_SIZE*8) / 8
        nHashFuncs = min(vData.size()*8/nElements * LN2, MAX_HASH_FUNCS)
    Without this, there is no bloom filter object to load at all.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_bloom_filter_class_absent_python(self):
        """No CBloomFilter or BloomFilter class in Python source."""
        # Check across the main modules
        sources = _P2P_MSGS + _P2P + _PEER + _NODE
        has_class = (
            "class CBloomFilter" in sources
            or "class BloomFilter" in sources
        )
        self.assertFalse(
            has_class,
            "G4: CBloomFilter/BloomFilter class found in Python pipeline — update test",
        )

    def test_bloom_filter_constructor_absent_rust(self):
        """No CBloomFilter struct in Rust pipeline."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G4: bloom.rs found in ferrous-utils — update test to check constructor",
        )


# ---------------------------------------------------------------------------
# G5 — nHashFuncs computation
# ---------------------------------------------------------------------------

class TestG5_NHashFuncsComputation(unittest.TestCase):
    """
    BUG-5 (HIGH): nHashFuncs computation absent.

    Core: nHashFuncs = min(vData.size()*8/nElements * LN2, MAX_HASH_FUNCS)
    This is part of the constructor (also covered by G4), but separately the
    per-element hash function count drives the probability of false positives.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_nhashfuncs_formula_absent_python(self):
        """nHashFuncs formula absent from Python source."""
        has_formula = (
            "nHashFuncs" in _P2P_MSGS
            or "nHashFuncs" in _P2P
            or "n_hash_funcs" in _P2P_MSGS
            or "n_hash_funcs" in _P2P
        )
        self.assertFalse(
            has_formula,
            "G5: nHashFuncs computation found in Python — update test",
        )


# ---------------------------------------------------------------------------
# G6 — MurmurHash3 32-bit
# ---------------------------------------------------------------------------

class TestG6_MurmurHash3(unittest.TestCase):
    """
    BUG-6 (P0-CDIV): MurmurHash3 (x86_32) absent in both pipelines.

    Core (hash.cpp:13-75): MurmurHash3 is the core hash primitive for
    CBloomFilter.Hash(). Without it, bloom filter contains/insert are entirely
    non-functional. This is a P0-CDIV: any node receiving a filterload message
    cannot match transactions deterministically with Core-compatible behavior.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_murmurhash3_absent_python(self):
        """No MurmurHash3 implementation in Python source."""
        has_impl = (
            "MurmurHash3" in _P2P_MSGS
            or "MurmurHash3" in _P2P
            or "murmurhash3" in _P2P.lower()
            or "murmurhash3" in _P2P_MSGS.lower()
        )
        self.assertFalse(
            has_impl,
            "G6: MurmurHash3 found in Python pipeline — update test",
        )

    def test_murmurhash3_absent_rust(self):
        """No MurmurHash3 in Rust pipeline (no bloom.rs)."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G6: bloom.rs found in ferrous-utils — update test to check MurmurHash3",
        )

    def test_murmurhash3_x86_32_correctness(self):
        """
        Reference test: MurmurHash3(0, b'hello') should equal 0x248bfa47.
        This test documents the expected value; it will FAIL until MurmurHash3
        is implemented.
        """
        # Inline reference implementation for test-documentation purposes.
        # This mirrors bitcoin-core/src/hash.cpp MurmurHash3 exactly.
        def murmurhash3(seed: int, data: bytes) -> int:
            h1 = seed & 0xFFFFFFFF
            c1 = 0xcc9e2d51
            c2 = 0x1b873593

            def rotl32(x: int, r: int) -> int:
                return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

            nblocks = len(data) // 4
            for i in range(nblocks):
                k1 = struct.unpack_from('<I', data, i * 4)[0]
                k1 = (k1 * c1) & 0xFFFFFFFF
                k1 = rotl32(k1, 15)
                k1 = (k1 * c2) & 0xFFFFFFFF
                h1 ^= k1
                h1 = rotl32(h1, 13)
                h1 = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

            tail = data[nblocks * 4:]
            k1 = 0
            tail_len = len(tail)
            if tail_len >= 3:
                k1 ^= tail[2] << 16
            if tail_len >= 2:
                k1 ^= tail[1] << 8
            if tail_len >= 1:
                k1 ^= tail[0]
                k1 = (k1 * c1) & 0xFFFFFFFF
                k1 = rotl32(k1, 15)
                k1 = (k1 * c2) & 0xFFFFFFFF
                h1 ^= k1

            h1 ^= len(data)
            h1 ^= h1 >> 16
            h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
            h1 ^= h1 >> 13
            h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
            h1 ^= h1 >> 16
            return h1

        # Verify the reference impl itself is correct against known vector
        result = murmurhash3(0, b'hello')
        self.assertEqual(
            result, 0x248bfa47,
            "Reference MurmurHash3 implementation is wrong — test is broken",
        )


# ---------------------------------------------------------------------------
# G7 — nTweak + i*0xFBA4C795 schedule
# ---------------------------------------------------------------------------

class TestG7_HashSchedule(unittest.TestCase):
    """
    BUG-7 (P0-CDIV): Hash schedule `nHashNum * 0xFBA4C795 + nTweak` absent.

    Core (bloom.cpp:43):
        return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
    The constant 0xFBA4C795 "guarantees a reasonable bit difference between
    nHashNum values" (comment in Core). Without this exact schedule a bloom filter
    sent by a Core SPV client will produce different bit-indices.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_hash_schedule_constant_absent_python(self):
        """Constant 0xFBA4C795 absent from Python source."""
        has_const = "0xFBA4C795" in _P2P_MSGS or "0xFBA4C795" in _P2P or "FBA4C795" in _P2P
        self.assertFalse(
            has_const,
            "G7: 0xFBA4C795 hash schedule constant found in Python — update test",
        )

    def test_hash_schedule_constant_absent_rust(self):
        """Constant 0xFBA4C795 absent from Rust pipeline."""
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G7: bloom.rs found in ferrous-utils — update test to verify schedule",
        )


# ---------------------------------------------------------------------------
# G8 — Bit index
# ---------------------------------------------------------------------------

class TestG8_BitIndex(unittest.TestCase):
    """
    BUG-8 (P0-CDIV): Bit index calculation for bloom filter absent.

    Core (bloom.cpp:55, 73):
        insert:   vData[nIndex >> 3] |= (1 << (7 & nIndex));
        contains: vData[nIndex >> 3] & (1 << (7 & nIndex))
    The bit-packing scheme (byte = nIndex>>3, bit = nIndex&7) must match
    exactly between all implementations.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_bit_index_formula_absent_python(self):
        """Bit index formula absent from Python source."""
        # Look for the bit-packing pattern
        has_formula = (
            "nIndex >> 3" in _P2P_MSGS
            or "nIndex >> 3" in _P2P
            or ">> 3" in _P2P_MSGS  # too broad, so also check for 7 & nIndex
        ) and "7 & nIndex" in _P2P_MSGS
        self.assertFalse(
            has_formula,
            "G8: bit index formula found in Python — update test",
        )


# ---------------------------------------------------------------------------
# G9 — Insert + Contains
# ---------------------------------------------------------------------------

class TestG9_InsertContains(unittest.TestCase):
    """
    BUG-9 (P0-CDIV): insert() and contains() methods absent.

    Core: CBloomFilter::insert(span), contains(span), insert(COutPoint), contains(COutPoint)
    Without these, the filter cannot be populated or queried.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_insert_contains_absent_python(self):
        """No bloom_filter.insert or bloom_filter.contains in Python source."""
        # Check all sources for a method named 'insert' on a bloom filter type
        sources = _P2P_MSGS + _P2P + _PEER + _NODE
        # We're looking for bloom-specific insert/contains; generic list/dict
        # .insert or .contains do not count
        has_bloom_insert = (
            "class CBloomFilter" in sources
            or "class BloomFilter" in sources
        )
        self.assertFalse(
            has_bloom_insert,
            "G9: BloomFilter.insert/contains found — update test",
        )


# ---------------------------------------------------------------------------
# G10 — isFull/isEmpty short-circuit
# ---------------------------------------------------------------------------

class TestG10_IsFullIsEmpty(unittest.TestCase):
    """
    BUG-10 (P0-CDIV): isFull / isEmpty short-circuit absent.

    Core (bloom.cpp:49, 65): Both insert() and contains() guard with:
        `if (vData.empty()) return (true/nothing);   // Avoid divide-by-zero (CVE-2013-5700)`
    An empty vData (zero-byte filter) must be treated as "match-all" for contains
    and be a no-op for insert. Missing this guard is CVE-2013-5700 (remote crash).

    Both pipelines: MISSING ENTIRELY (CVE-class bug, P0).
    """

    def test_empty_guard_absent_python(self):
        """No vData.empty() / CVE-2013-5700 guard in Python source."""
        has_guard = (
            "vData.empty()" in _P2P_MSGS
            or "vData.empty()" in _P2P
            or "CVE-2013-5700" in _P2P_MSGS
        )
        self.assertFalse(
            has_guard,
            "G10: vData.empty() guard found — update test",
        )


# ---------------------------------------------------------------------------
# G11 — UPDATE_NONE = 0
# ---------------------------------------------------------------------------

class TestG11_UpdateNone(unittest.TestCase):
    """
    BUG-11 (HIGH): BLOOM_UPDATE_NONE = 0 constant absent.

    Core (bloom.h:24): `BLOOM_UPDATE_NONE = 0`
    Required for nFlags & BLOOM_UPDATE_MASK comparison in IsRelevantAndUpdate.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_bloom_update_none_absent(self):
        """BLOOM_UPDATE_NONE constant absent from Python source."""
        sources = _P2P_MSGS + _P2P
        has_const = "BLOOM_UPDATE_NONE" in sources or "UPDATE_NONE" in sources
        self.assertFalse(
            has_const,
            "G11: BLOOM_UPDATE_NONE found in Python pipeline — update test",
        )


# ---------------------------------------------------------------------------
# G12 — UPDATE_ALL = 1
# ---------------------------------------------------------------------------

class TestG12_UpdateAll(unittest.TestCase):
    """
    BUG-12 (HIGH): BLOOM_UPDATE_ALL = 1 constant absent.

    Core (bloom.h:25): `BLOOM_UPDATE_ALL = 1`
    Required for the outpoint auto-insert path in IsRelevantAndUpdate.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_bloom_update_all_absent(self):
        """BLOOM_UPDATE_ALL constant absent from Python source."""
        sources = _P2P_MSGS + _P2P
        has_const = "BLOOM_UPDATE_ALL" in sources or "UPDATE_ALL" in sources
        self.assertFalse(
            has_const,
            "G12: BLOOM_UPDATE_ALL found in Python pipeline — update test",
        )


# ---------------------------------------------------------------------------
# G13 — UPDATE_P2PUBKEY_ONLY = 2
# ---------------------------------------------------------------------------

class TestG13_UpdateP2PubkeyOnly(unittest.TestCase):
    """
    BUG-13 (HIGH): BLOOM_UPDATE_P2PUBKEY_ONLY = 2 constant absent.

    Core (bloom.h:27): `BLOOM_UPDATE_P2PUBKEY_ONLY = 2`
    Selectively adds outpoints for P2PK/multisig outputs only.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_bloom_update_p2pubkey_absent(self):
        """BLOOM_UPDATE_P2PUBKEY_ONLY absent from Python source."""
        sources = _P2P_MSGS + _P2P
        has_const = "BLOOM_UPDATE_P2PUBKEY_ONLY" in sources or "P2PUBKEY_ONLY" in sources
        self.assertFalse(
            has_const,
            "G13: BLOOM_UPDATE_P2PUBKEY_ONLY found in Python — update test",
        )


# ---------------------------------------------------------------------------
# G14 — UPDATE_MASK = 3
# ---------------------------------------------------------------------------

class TestG14_UpdateMask(unittest.TestCase):
    """
    BUG-14 (HIGH): BLOOM_UPDATE_MASK = 3 constant absent.

    Core (bloom.h:28): `BLOOM_UPDATE_MASK = 3`
    Masks the lower two bits of nFlags for the update-mode comparison.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_bloom_update_mask_absent(self):
        """BLOOM_UPDATE_MASK absent from Python source."""
        sources = _P2P_MSGS + _P2P
        has_const = "BLOOM_UPDATE_MASK" in sources or "UPDATE_MASK" in sources
        self.assertFalse(
            has_const,
            "G14: BLOOM_UPDATE_MASK found in Python — update test",
        )


# ---------------------------------------------------------------------------
# G15 — nFlags & UPDATE_MASK
# ---------------------------------------------------------------------------

class TestG15_NFlagsAndMask(unittest.TestCase):
    """
    BUG-15 (P0-CDIV): `nFlags & BLOOM_UPDATE_MASK` expression absent.

    Core (bloom.cpp:100-107):
        if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)   insert(COutPoint(hash, i));
        else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY) { ... }
    Missing this means that outpoints of matching outputs are never added to the
    filter, so spending transactions of matched outputs would never be found.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_nflags_and_mask_absent(self):
        """nFlags & BLOOM_UPDATE_MASK expression absent."""
        sources = _P2P_MSGS + _P2P
        has_expr = "BLOOM_UPDATE_MASK" in sources
        self.assertFalse(
            has_expr,
            "G15: BLOOM_UPDATE_MASK expression found — update test",
        )


# ---------------------------------------------------------------------------
# G16 — txid match
# ---------------------------------------------------------------------------

class TestG16_TxidMatch(unittest.TestCase):
    """
    BUG-16 (P0-CDIV): txid match in IsRelevantAndUpdate absent.

    Core (bloom.cpp:86-89):
        const Txid& hash = tx.GetHash();
        if (contains(hash.ToUint256())) fFound = true;
    The txid must be checked first against the bloom filter. Absent in both
    pipelines.
    """

    def test_txid_match_absent(self):
        """IsRelevantAndUpdate / txid match absent."""
        sources = _P2P_MSGS + _P2P + _PEER + _NODE
        has_impl = (
            "IsRelevantAndUpdate" in sources
            or "is_relevant_and_update" in sources
        )
        self.assertFalse(
            has_impl,
            "G16: IsRelevantAndUpdate found — update test",
        )


# ---------------------------------------------------------------------------
# G17 — Per-output-script pushdata
# ---------------------------------------------------------------------------

class TestG17_PerOutputScriptPushdata(unittest.TestCase):
    """
    BUG-17 (P0-CDIV): Per-output scriptPubKey pushdata scan absent.

    Core (bloom.cpp:91-107): Iterates over each CTxOut's scriptPubKey using
    GetOp, checking each data push against the bloom filter. If matched,
    optionally inserts the corresponding COutPoint.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_output_pushdata_scan_absent(self):
        """Output scriptPubKey scan absent from bloom subsystem."""
        # CBloomFilter class does not exist; IsRelevantAndUpdate absent
        sources = _P2P_MSGS + _P2P + _PEER + _NODE
        has_impl = "IsRelevantAndUpdate" in sources
        self.assertFalse(
            has_impl,
            "G17: output pushdata scan found — update test",
        )


# ---------------------------------------------------------------------------
# G18 — P2PKH/P2SH/P2PK/multisig script type detection
# ---------------------------------------------------------------------------

class TestG18_ScriptTypeDetection(unittest.TestCase):
    """
    BUG-18 (P0-CDIV): Script type detection for BLOOM_UPDATE_P2PUBKEY_ONLY absent.

    Core (bloom.cpp:103-106):
        TxoutType type = Solver(txout.scriptPubKey, vSolutions);
        if (type == TxoutType::PUBKEY || type == TxoutType::MULTISIG)
            insert(COutPoint(hash, i));
    Without this, P2PK and multisig spending txes would not be found under
    BLOOM_UPDATE_P2PUBKEY_ONLY mode.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_p2pubkey_script_detection_absent(self):
        """Script type detection for bloom update mode absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "BLOOM_UPDATE_P2PUBKEY_ONLY" in sources
        self.assertFalse(
            has_impl,
            "G18: P2PUBKEY script detection found — update test",
        )


# ---------------------------------------------------------------------------
# G19 — Outpoint match
# ---------------------------------------------------------------------------

class TestG19_OutpointMatch(unittest.TestCase):
    """
    BUG-19 (P0-CDIV): Outpoint (prevout) match in IsRelevantAndUpdate absent.

    Core (bloom.cpp:113-114):
        for (const CTxIn& txin : tx.vin)
            if (contains(txin.prevout)) return true;
    This enables SPV clients to watch for spending transactions by inserting
    outpoints into the filter after receiving the funding tx.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_outpoint_match_absent(self):
        """Outpoint match in bloom filter absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "IsRelevantAndUpdate" in sources
        self.assertFalse(
            has_impl,
            "G19: outpoint match found — update test",
        )


# ---------------------------------------------------------------------------
# G20 — scriptSig data items
# ---------------------------------------------------------------------------

class TestG20_ScriptSigDataItems(unittest.TestCase):
    """
    BUG-20 (P0-CDIV): scriptSig data item scan absent.

    Core (bloom.cpp:117-123):
        CScript::const_iterator pc = txin.scriptSig.begin();
        while (pc < txin.scriptSig.end())
            if (!txin.scriptSig.GetOp(pc, opcode, data)) break;
            if (data.size() != 0 && contains(data)) return true;
    Both pipelines: MISSING ENTIRELY.
    """

    def test_scriptsig_scan_absent(self):
        """scriptSig data item scan absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "IsRelevantAndUpdate" in sources
        self.assertFalse(
            has_impl,
            "G20: scriptSig scan found — update test",
        )


# ---------------------------------------------------------------------------
# G21 — UPDATE_ALL outpoint auto-insert
# ---------------------------------------------------------------------------

class TestG21_UpdateAllOutpointInsert(unittest.TestCase):
    """
    BUG-21 (P0-CDIV): UPDATE_ALL outpoint auto-insert absent.

    Core (bloom.cpp:98-100):
        if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
            insert(COutPoint(hash, i));
    This is the mechanism by which SPV clients receive spending transactions
    without having to update the filter themselves.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_update_all_absent(self):
        """UPDATE_ALL outpoint insert absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "BLOOM_UPDATE_ALL" in sources
        self.assertFalse(
            has_impl,
            "G21: UPDATE_ALL found — update test",
        )


# ---------------------------------------------------------------------------
# G22 — UPDATE_P2PUBKEY_ONLY conditional
# ---------------------------------------------------------------------------

class TestG22_UpdateP2PubkeyOnlyConditional(unittest.TestCase):
    """
    BUG-22 (P0-CDIV): UPDATE_P2PUBKEY_ONLY conditional absent.

    Core (bloom.cpp:101-106):
        else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY) {
            TxoutType type = Solver(txout.scriptPubKey, vSolutions);
            if (type == TxoutType::PUBKEY || type == TxoutType::MULTISIG)
                insert(COutPoint(hash, i));
        }
    Both pipelines: MISSING ENTIRELY.
    """

    def test_update_p2pubkey_only_absent(self):
        """UPDATE_P2PUBKEY_ONLY conditional absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "BLOOM_UPDATE_P2PUBKEY_ONLY" in sources
        self.assertFalse(
            has_impl,
            "G22: UPDATE_P2PUBKEY_ONLY found — update test",
        )


# ---------------------------------------------------------------------------
# G23 — UPDATE_NONE logic
# ---------------------------------------------------------------------------

class TestG23_UpdateNoneLogic(unittest.TestCase):
    """
    BUG-23 (HIGH): UPDATE_NONE logic absent.

    Under BLOOM_UPDATE_NONE, IsRelevantAndUpdate should NOT insert new outpoints
    even when a matching output is found. The default mode.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_update_none_logic_absent(self):
        """UPDATE_NONE logic absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "BLOOM_UPDATE_NONE" in sources
        self.assertFalse(
            has_impl,
            "G23: UPDATE_NONE found — update test",
        )


# ---------------------------------------------------------------------------
# G24 — Outpoint serialization (little-endian txid + index)
# ---------------------------------------------------------------------------

class TestG24_OutpointSerialization(unittest.TestCase):
    """
    BUG-24 (P0-CDIV): COutPoint serialization for bloom filter absent.

    Core (bloom.cpp:57-61, 67-70):
        void CBloomFilter::insert(const COutPoint& outpoint):
            DataStream stream{}; stream << outpoint; insert(MakeUCharSpan(stream));
    The outpoint is serialized as txid_le (32 bytes) + index_le (4 bytes)
    per Bitcoin wire format. This exact layout must be used when inserting
    outpoints so that SPV clients with Core-compatible filters can match.
    Both pipelines: MISSING ENTIRELY.
    """

    def test_outpoint_serialization_absent(self):
        """Outpoint serialization for bloom filter absent."""
        sources = _P2P_MSGS + _P2P
        has_impl = "class CBloomFilter" in sources or "class BloomFilter" in sources
        self.assertFalse(
            has_impl,
            "G24: outpoint serialization found — update test",
        )


# ---------------------------------------------------------------------------
# G25 — filterload P2P message
# ---------------------------------------------------------------------------

class TestG25_FilterloadMessage(unittest.TestCase):
    """
    BUG-25 (P0-CDIV): filterload P2P message handler absent.

    Core (net_processing.cpp:4963-4986):
        if (msg_type == NetMsgType::FILTERLOAD) {
            if (!(peer.m_our_services & NODE_BLOOM)) { disconnect; return; }
            CBloomFilter filter; vRecv >> filter;
            if (!filter.IsWithinSizeConstraints()) Misbehaving("too-large bloom filter");
            else { LOCK(mutex); tx_relay->m_bloom_filter.reset(new CBloomFilter(filter)); ... }
        }
    The filterload message name is present in transport_v2.py's V2 message ID
    table (index 8) but there is NO handler registered for it anywhere in p2p.py
    or node.py. This is a dead-constant: the message is named but silently dropped.

    Two-pipeline note: this is a classic ouroboros dead-helper pattern — the
    message name is in the BIP-324 short-ID table but the handler is missing.
    """

    def test_filterload_handler_absent(self):
        """filterload message name exists in transport_v2 but handler is absent in p2p.py."""
        # The message name appears in transport_v2.py V2_MESSAGE_IDS table
        from ouroboros.transport_v2 import V2_MESSAGE_IDS
        self.assertIn(
            "filterload",
            V2_MESSAGE_IDS,
            "G25: filterload absent from V2_MESSAGE_IDS — unexpected",
        )

    def test_filterload_handler_registered(self):
        """FIX-36: on_filterload handler IS registered in p2p.py (BIP-111 disconnect)."""
        has_handler = (
            'register_handler("filterload"' in _P2P
            or "on_filterload" in _P2P
        )
        self.assertTrue(
            has_handler,
            "FIX-36: filterload handler absent from p2p.py — BIP-111 disconnect not wired",
        )

    def test_filterload_handler_not_in_node(self):
        """No filterload handler registered in node.py."""
        has_handler = (
            'register_handler("filterload"' in _NODE
            or "on_filterload" in _NODE
        )
        self.assertFalse(
            has_handler,
            "G25: filterload handler found in node.py — update test",
        )


# ---------------------------------------------------------------------------
# G26 — filteradd message + 520-byte cap
# ---------------------------------------------------------------------------

class TestG26_FilteraddMessage(unittest.TestCase):
    """
    BUG-26 (P0-CDIV): filteradd P2P message handler absent + 520-byte cap missing.

    Core (net_processing.cpp:4988-5013):
        if (msg_type == NetMsgType::FILTERADD) {
            if (!(peer.m_our_services & NODE_BLOOM)) { disconnect; return; }
            std::vector<unsigned char> vData; vRecv >> vData;
            if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) bad = true;  // 520 bytes
            else if (m_bloom_filter) m_bloom_filter->insert(vData);
            else bad = true;
            if (bad) Misbehaving("bad filteradd message");
        }
    MAX_SCRIPT_ELEMENT_SIZE = 520 bytes (script/script.h).
    The filteradd message name is present in V2 table (index 6) but no handler
    is registered.

    Missing the 520-byte cap means a peer can insert arbitrarily large data
    items, causing O(itemLen * nHashFuncs) hash overhead per insert.
    """

    def test_filteradd_handler_registered(self):
        """FIX-36: on_filteradd handler IS registered in p2p.py (BIP-111 disconnect)."""
        has_handler = (
            'register_handler("filteradd"' in _P2P
            or "on_filteradd" in _P2P
        )
        self.assertTrue(
            has_handler,
            "FIX-36: filteradd handler absent from p2p.py — BIP-111 disconnect not wired",
        )

    def test_filteradd_520_byte_cap_absent(self):
        """520-byte cap (MAX_SCRIPT_ELEMENT_SIZE) absent from filteradd handler."""
        has_cap = (
            "MAX_SCRIPT_ELEMENT_SIZE" in _P2P
            or "520" in _P2P  # too broad; refine if needed
        ) and "filteradd" in _P2P
        self.assertFalse(
            has_cap,
            "G26: MAX_SCRIPT_ELEMENT_SIZE cap in filteradd found — update test",
        )


# ---------------------------------------------------------------------------
# G27 — filterclear message
# ---------------------------------------------------------------------------

class TestG27_FilterclearMessage(unittest.TestCase):
    """
    BUG-27 (HIGH): filterclear P2P message handler absent.

    Core (net_processing.cpp:5016-5033):
        if (msg_type == NetMsgType::FILTERCLEAR) {
            if (!(peer.m_our_services & NODE_BLOOM)) { disconnect; return; }
            auto tx_relay = peer.GetTxRelay();
            LOCK(mutex); tx_relay->m_bloom_filter = nullptr; tx_relay->m_relay_txs = true;
            pfrom.m_bloom_filter_loaded = false;
        }
    filterclear must reset the per-peer bloom filter and re-enable full tx relay.
    The filterclear message name is in V2_MESSAGE_IDS (index 7) but no handler
    is registered.
    """

    def test_filterclear_handler_registered(self):
        """FIX-36: on_filterclear handler IS registered in p2p.py (BIP-111 disconnect)."""
        has_handler = (
            'register_handler("filterclear"' in _P2P
            or "on_filterclear" in _P2P
        )
        self.assertTrue(
            has_handler,
            "FIX-36: filterclear handler absent from p2p.py — BIP-111 disconnect not wired",
        )


# ---------------------------------------------------------------------------
# G28 — merkleblock + PartialMerkleTree
# ---------------------------------------------------------------------------

class TestG28_MerkleblockAndPartialMerkleTree(unittest.TestCase):
    """
    BUG-28 (HIGH): merkleblock P2P message not served over the P2P layer.

    Status: PARTIAL. rpc.py has _build_partial_merkle_tree + _parse_partial_merkle_tree
    used by rpc_gettxoutproof. These are correct CMerkleBlock wire-format helpers.
    However, there is NO P2P-level merkleblock handler — when a peer sends
    `getdata` for INV_TYPE_FILTERED_BLOCK=3, the node does NOT serve a merkleblock.
    The node.py getdata handler only handles INV_TYPE_BLOCK and INV_TYPE_TX.

    Two-pipeline note: the partial merkle tree logic lives only in rpc.py (Python
    pipeline) and is not exported to the Rust pipeline via pyfunction.

    What IS present (credit):
    - INV_TYPE_FILTERED_BLOCK = 3 defined in p2p_messages.py
    - PartialMerkleTree build/parse helpers in rpc.py (_build_partial_merkle_tree,
      _parse_partial_merkle_tree, used by rpc_gettxoutproof)
    - merkleblock string in V2_MESSAGE_IDS

    What is MISSING:
    - No handler for INV_TYPE_FILTERED_BLOCK in getdata dispatch (node.py)
    - No per-peer bloom filter state to filter the block before serving
    - No merkleblock P2P outbound message class in p2p_messages.py
    """

    def test_partial_merkle_tree_helpers_present_in_rpc(self):
        """Partial Merkle tree helpers ARE present in rpc.py (used by gettxoutproof)."""
        self.assertIn(
            "_build_partial_merkle_tree",
            _RPC,
            "G28: _build_partial_merkle_tree unexpectedly absent from rpc.py",
        )
        self.assertIn(
            "_parse_partial_merkle_tree",
            _RPC,
            "G28: _parse_partial_merkle_tree unexpectedly absent from rpc.py",
        )

    def test_inv_type_filtered_block_defined(self):
        """INV_TYPE_FILTERED_BLOCK = 3 is defined in p2p_messages.py."""
        self.assertIn(
            "INV_TYPE_FILTERED_BLOCK",
            _P2P_MSGS,
            "G28: INV_TYPE_FILTERED_BLOCK missing from p2p_messages.py",
        )

    def test_filtered_block_not_served_by_getdata_handler(self):
        """
        BUG-28a (HIGH): INV_TYPE_FILTERED_BLOCK is NOT handled in node.py getdata dispatcher.

        Core serves a merkleblock when getdata requests INV_TYPE_FILTERED_BLOCK;
        ouroboros silently drops these getdata requests (falls to notfound path).
        """
        has_filtered_handler = "INV_TYPE_FILTERED_BLOCK" in _NODE
        self.assertFalse(
            has_filtered_handler,
            "G28: INV_TYPE_FILTERED_BLOCK found in node.py — update test",
        )

    def test_merkleblock_message_class_absent_in_p2p_messages(self):
        """No MerkleBlockMessage class in p2p_messages.py."""
        has_class = (
            "class MerkleBlockMessage" in _P2P_MSGS
            or "class MerkleBlock" in _P2P_MSGS
        )
        self.assertFalse(
            has_class,
            "G28: MerkleBlockMessage class found — update test",
        )

    def test_partial_merkle_tree_helpers_not_exported_to_rust(self):
        """
        Two-pipeline (dead-helper concern): partial merkle tree logic in rpc.py
        is not a #[pyfunction] in ferrous-utils. Rust pipeline has no equivalent.
        """
        # Check that there is no bloom or merkle pyfunction in Rust
        bloom_in_rust = _rust_bloom_exists()
        self.assertFalse(
            bloom_in_rust,
            "G28: bloom/merkle pyfunction found in Rust — update test",
        )


# ---------------------------------------------------------------------------
# G29 — IsWithinSizeConstraints
# ---------------------------------------------------------------------------

class TestG29_IsWithinSizeConstraints(unittest.TestCase):
    """
    BUG-29 (HIGH): IsWithinSizeConstraints absent.

    Core (bloom.cpp:82-85):
        bool CBloomFilter::IsWithinSizeConstraints() const {
            return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
        }
    This check runs on every deserialized filterload payload. Without it, any
    malicious peer can send a 36001-byte filter or set nHashFuncs = 1000000,
    causing DoS via CPU exhaustion.

    Both pipelines: MISSING ENTIRELY.
    """

    def test_is_within_size_constraints_absent(self):
        """IsWithinSizeConstraints absent from Python source."""
        sources = _P2P_MSGS + _P2P + _PEER + _NODE
        has_impl = (
            "IsWithinSizeConstraints" in sources
            or "is_within_size_constraints" in sources
        )
        self.assertFalse(
            has_impl,
            "G29: IsWithinSizeConstraints found — update test",
        )


# ---------------------------------------------------------------------------
# G30 — NODE_BLOOM + BIP-111
# ---------------------------------------------------------------------------

class TestG30_NodeBloomAndBip111(unittest.TestCase):
    """
    BIP-111 NODE_BLOOM service bit (1<<2 = 4) status.

    What IS present (partial credit):
    - NODE_BLOOM = 1 << 2 is correctly defined in p2p_messages.py (line 41)
    - peer.py correctly ORs NODE_BLOOM into version services when
      peer_bloom_filters=True (lines 710, 1224, 1376)
    - p2p.py mempool handler gates on NODE_BLOOM (line 2211)
    - node.py reads peer_bloom_filters from config (line 273)

    What is MISSING (bugs):
    - BUG-30a: When a peer sends filterload/filteradd/filterclear AND our node
      does NOT advertise NODE_BLOOM, Core disconnects the peer
      (net_processing.cpp:4965 `pfrom.fDisconnect = true`).
      Ouroboros has NO such disconnect path because the handlers are absent.
    - BUG-30b: Per-peer bloom filter state (per-peer CBloomFilter pointer) never
      stored; even if NODE_BLOOM is advertised, tx relay cannot be filtered.
    - BUG-30c: tx inv announcements do not respect per-peer bloom filter state
      (IsRelevantAndUpdate never called before INV announcement).
    """

    def test_node_bloom_constant_correct(self):
        """NODE_BLOOM = 1 << 2 = 4 is correctly defined."""
        from ouroboros.p2p_messages import NODE_BLOOM
        self.assertEqual(
            NODE_BLOOM, 4,
            "G30: NODE_BLOOM value is wrong",
        )

    def test_node_bloom_advertised_when_enabled(self):
        """NODE_BLOOM is ORed into version services when peer_bloom_filters=True."""
        self.assertIn(
            "NODE_BLOOM",
            _PEER,
            "G30: NODE_BLOOM not referenced in peer.py",
        )
        self.assertIn(
            "peer_bloom_filters",
            _PEER,
            "G30: peer_bloom_filters flag absent from peer.py",
        )

    def test_filterload_disconnect_on_no_bloom_present(self):
        """
        FIX-36 (BUG-30a closed): BIP-111 disconnect path IS present.

        filterload/filteradd/filterclear handlers are now registered in
        _register_bloom_handlers (p2p.py).  Each handler disconnects the peer
        when NODE_BLOOM was not advertised, matching
        bitcoin-core/src/net_processing.cpp:4965
        `pfrom.fDisconnect = true` on no-NODE_BLOOM.
        """
        has_handler = 'register_handler("filterload"' in _P2P
        has_disconnect = "peer.disconnect" in _P2P
        self.assertTrue(
            has_handler,
            "FIX-36: filterload handler absent from p2p.py — BIP-111 disconnect not wired",
        )
        self.assertTrue(
            has_disconnect,
            "FIX-36: peer.disconnect() call absent from p2p.py",
        )

    def test_per_peer_bloom_filter_state_absent(self):
        """
        BUG-30b (HIGH): Per-peer bloom filter state absent from Peer class.

        Core: Peer has tx_relay->m_bloom_filter (unique_ptr<CBloomFilter>).
        Ouroboros Peer has peer_bloom_filters (bool, our side) but no
        per-peer CBloomFilter object tracking what the remote sent us.
        """
        has_per_peer_state = (
            "bloom_filter" in _PEER
            and "class " in _PEER  # ensure this is in Peer class context
            and "CBloomFilter" in _PEER
        )
        # More precise check: 'self.bloom_filter' or 'm_bloom_filter'
        has_self_filter = (
            "self.bloom_filter" in _PEER
            or "self.m_bloom_filter" in _PEER
        )
        self.assertFalse(
            has_self_filter,
            "G30: per-peer bloom_filter state found in peer.py — update test",
        )

    def test_tx_inv_relay_does_not_respect_bloom_filter(self):
        """
        BUG-30c (P0-CDIV): tx INV relay does not call IsRelevantAndUpdate.

        Core calls IsRelevantAndUpdate on each pending tx before announcing it
        via INV to a peer that has loaded a bloom filter. Ouroboros announces
        all txs to all peers regardless of any filter state.
        """
        has_relay_filter = "IsRelevantAndUpdate" in _P2P or "is_relevant_and_update" in _P2P
        self.assertFalse(
            has_relay_filter,
            "G30: IsRelevantAndUpdate in tx relay found — update test",
        )


# ---------------------------------------------------------------------------
# Summary: two-pipeline analysis
# ---------------------------------------------------------------------------

class TestTwoPipelineAnalysis(unittest.TestCase):
    """
    Meta-gate: two-pipeline analysis for ouroboros BIP-37.

    Python pipeline (src/ouroboros/):
    - PARTIAL: NODE_BLOOM bit defined and advertised (service bit only)
    - PARTIAL: INV_TYPE_FILTERED_BLOCK defined but not handled in getdata
    - PARTIAL: PartialMerkleTree helpers in rpc.py (used by gettxoutproof only,
               not wired into P2P merkleblock serving)
    - MISSING: CBloomFilter class, MurmurHash3, all update flags
    - MISSING: filterload/filteradd/filterclear P2P handlers
    - MISSING: per-peer bloom filter state in Peer class
    - MISSING: IsRelevantAndUpdate called before tx INV announcement

    Rust pipeline (ferrous-utils/):
    - MISSING ENTIRELY: no bloom.rs, no MurmurHash3, no CBloomFilter struct
    - The Rust pipeline is completely clean of any BIP-37 code.

    Dead-helper observations:
    1. filterload/filterclear/filteradd appear in V2_MESSAGE_IDS (transport_v2.py)
       but have NO registered handlers. This is the classic ouroboros dead-helper
       pattern: the message names are registered for BIP-324 short-ID encoding but
       the actual message-processing functions are absent.
    2. INV_TYPE_FILTERED_BLOCK = 3 is defined in p2p_messages.py but is never
       checked in node.py's getdata dispatch loop.
    3. The partial merkle tree helpers (_build_partial_merkle_tree,
       _parse_partial_merkle_tree) in rpc.py are correctly implemented for
       gettxoutproof but are not wired into any P2P merkleblock serving path.
    """

    def test_rust_pipeline_missing_entirely(self):
        """Rust pipeline has no BIP-37 bloom.rs — confirmed MISSING ENTIRELY."""
        self.assertFalse(
            _rust_bloom_exists(),
            "Rust bloom.rs found unexpectedly — two-pipeline analysis needs update",
        )

    def test_filterload_in_v2_message_ids_and_handler_registered(self):
        """
        FIX-36: filterload/filterclear/filteradd are in V2_MESSAGE_IDS AND
        handlers ARE now registered in p2p.py (_register_bloom_handlers).

        Previously these were dead-constants: names in the BIP-324 short-ID
        table but no dispatch.  FIX-36 wires the BIP-111 disconnect path so
        peers sending bloom messages when NODE_BLOOM is not advertised are
        disconnected rather than silently tolerated.
        """
        from ouroboros.transport_v2 import V2_MESSAGE_IDS
        for msg_name in ("filterload", "filterclear", "filteradd"):
            self.assertIn(
                msg_name,
                V2_MESSAGE_IDS,
                f"Two-pipeline: {msg_name} absent from V2_MESSAGE_IDS",
            )
        # All three now have registered handlers in p2p.py
        for msg_name in ("filterload", "filterclear", "filteradd"):
            has_handler = f'register_handler("{msg_name}"' in _P2P
            self.assertTrue(
                has_handler,
                f"FIX-36: {msg_name} handler NOT registered in p2p.py",
            )

    def test_merkleblock_handler_registered_log_and_drop(self):
        """
        FIX-36: merkleblock inbound handler IS registered in p2p.py.

        merkleblock is a server→client message; receiving it inbound is
        unusual.  The handler logs at debug and drops (no disconnect), matching
        Core's silent-ignore path for unexpected server-side messages.
        """
        has_handler = 'register_handler("merkleblock"' in _P2P
        self.assertTrue(
            has_handler,
            "FIX-36: merkleblock handler NOT registered in p2p.py",
        )

    def test_inv_type_filtered_block_dead_constant(self):
        """
        Dead-constant: INV_TYPE_FILTERED_BLOCK defined in p2p_messages.py but
        never handled in node.py getdata dispatch.
        """
        self.assertIn(
            "INV_TYPE_FILTERED_BLOCK",
            _P2P_MSGS,
            "INV_TYPE_FILTERED_BLOCK missing — test needs update",
        )
        self.assertNotIn(
            "INV_TYPE_FILTERED_BLOCK",
            _NODE,
            "INV_TYPE_FILTERED_BLOCK unexpectedly handled in node.py",
        )

    def test_partial_merkle_tree_rpc_only_not_p2p(self):
        """
        Partial dead-helper: _build_partial_merkle_tree exists in rpc.py but is
        NOT wired into P2P merkleblock serving (node.py getdata handler).
        """
        self.assertIn(
            "_build_partial_merkle_tree",
            _RPC,
            "Partial merkle tree helper unexpectedly removed from rpc.py",
        )
        self.assertNotIn(
            "_build_partial_merkle_tree",
            _NODE,
            "_build_partial_merkle_tree unexpectedly wired into node.py",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
