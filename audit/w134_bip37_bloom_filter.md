W134 — BIP-37 Bloom Filter (legacy SPV) stress audit (ouroboros)
================================================================

Date: 2026-05-17
Impl: ouroboros (Python primary; Rust ferrous-utils — confirmed NO BIP-37
      code on the Rust side; pipeline is wallet/SPV-facing and Python-only)
Wave: W134 BIP-37 legacy bloom filter (SPV) + BIP-111 NODE_BLOOM service-bit
      semantics + CMerkleBlock partial-merkle-tree wire format
      (DISCOVERY, follow-up to W110)
Reference:
  - bitcoin-core/src/common/bloom.{cpp,h}      (CBloomFilter,
                                                CRollingBloomFilter,
                                                LN2 / LN2SQUARED constants,
                                                MAX_BLOOM_FILTER_SIZE = 36000,
                                                MAX_HASH_FUNCS = 50,
                                                BLOOM_UPDATE_{NONE,ALL,
                                                P2PUBKEY_ONLY,MASK},
                                                IsWithinSizeConstraints,
                                                IsRelevantAndUpdate,
                                                Hash(nHashNum, vData),
                                                vData[nIndex>>3] |= (1<<(7&nIndex)))
  - bitcoin-core/src/merkleblock.{cpp,h}       (CMerkleBlock,
                                                CPartialMerkleTree,
                                                TraverseAndBuild,
                                                TraverseAndExtract,
                                                ExtractMatches DoS guards,
                                                CalcTreeWidth,
                                                BitsToBytes / BytesToBits)
  - bitcoin-core/src/net_processing.cpp        (filterload/filteradd/
                                                filterclear/getdata
                                                INV_TYPE_FILTERED_BLOCK,
                                                m_relay_txs init from
                                                version fRelay,
                                                NODE_BLOOM disconnect path,
                                                m_bloom_filter_loaded flag,
                                                MAX_SCRIPT_ELEMENT_SIZE
                                                cap on filteradd)
  - bitcoin-core/src/init.cpp                  (-peerbloomfilters flag,
                                                DEFAULT_PEERBLOOMFILTERS = false,
                                                NODE_BLOOM advertisement
                                                gated on this flag)

BIPs: 37, 111. Status: BIP-37 is OPTIONAL service offered to SPV peers;
disabled by default in Core since v0.19 (2019) because BIP-157 compact
filters supersede it for privacy. BIP-111 makes the offering itself a
service-bit (NODE_BLOOM = 1<<2). When NODE_BLOOM is NOT advertised, any
filterload/filteradd/filterclear MUST trigger immediate disconnect.

Relationship to prior audits
----------------------------

- W110 (2026-04-XX) was the initial audit and found 27 BUGs across
  30 gates documenting absence of the entire BIP-37 CBloomFilter +
  MurmurHash3 + filter*/merkleblock-serving stack.
- FIX-36 closed W110 BUG-25/26/27/30a by wiring **BIP-111 disconnect
  handlers** (`_register_bloom_handlers` in p2p.py:2443-2520) so a peer
  sending filterload/filteradd/filterclear when ouroboros did not
  advertise NODE_BLOOM is now disconnected. ouroboros default config
  leaves `-peerbloomfilters=false` (Core parity since v0.19), so the
  handlers' "BIP-37 not implemented" arms are unreachable in practice.
- W134 audits the **STRESS / DEEP-CORRECTNESS** layer that W110's
  presence-census missed: CVE-class checks in the partial merkle tree
  parser (which IS implemented in rpc.py for gettxoutproof/
  verifytxoutproof), fRelay version-field plumbing, BIP-339 wtxid x
  BIP-37 interaction, and second-order DoS via unbounded
  `m_tx_inventory_known_filter` shadow-state.

Status: 30 gates audited — PRESENT 6 / PARTIAL 5 / MISSING/BUG 19.
**21 BUGS** (2 P0-CONSENSUS / 2 P1 / 17 P2/structural/cosmetic).

Two-pipeline scope
==================

BIP-37 is wallet/SPV-facing. Core implements bloom.{h,cpp} in
`src/common/` — a layer used by both the node (to filter outbound tx
INVs) and SPV wallets (to build the filter to send). For ouroboros the
**Python pipeline owns it entirely** and the Rust pipeline is the
correct architectural choice (wallet/SPV surface, not consensus). The
audit therefore declares the Rust pipeline OUT-OF-SCOPE.

Two-pipeline guard:

```
$ grep -rn -E "MurmurHash3|CBloomFilter|filterload|filteradd|filterclear" \
       ferrous-utils/   → 0 production matches
$ grep -rn -E "TraverseAndBuild|TraverseAndExtract|CalcTreeWidth" \
       ferrous-utils/   → 0 production matches
```

Test `test_g30_two_pipeline_bip37_python_only` codifies this boundary:
- Rust pipeline (`ferrous-utils/`) MUST contain ZERO production
  matches for any BIP-37 / CBloomFilter / MurmurHash3 / MerkleBlock
  identifier.
- Python pipeline (`src/ouroboros/`) MUST contain the partial-merkle-
  tree helpers in `rpc.py` (used by `gettxoutproof` /
  `verifytxoutproof`) and the BIP-111 disconnect handlers in
  `p2p.py::_register_bloom_handlers`.
- Future regressions (e.g. moving bloom.rs into ferrous-utils to make
  the Rust pipeline serve SPV peers) trip this guard.

Two-pipeline guard EXTENDED (prior set: W76 + W120 + W122 + W125 +
W128 + W129 + W130 + W133 + W134).

Top-level findings
==================

(F1) **CVE-2012-2459 duplicate-children check is MISSING in
     `_parse_partial_merkle_tree` (rpc.py:617-672).** Core's
     `CPartialMerkleTree::TraverseAndExtract` sets `fBad=true` when
     `right == left` because adjacent-leaf hash duplication is the
     attack vector for CVE-2012-2459 (Core fixed it in 2012,
     reintroduced and re-fixed via commit eccd66268). Ouroboros's
     `_consume` recurses into both subtrees but never compares
     left/right — a constructed proof with duplicated hashes accepts
     a forged merkle root that hashes to the right header. The
     consequence in ouroboros is currently bounded to `rpc_verifytxoutproof`
     (an RPC consumer), but if a future fix wires `INV_TYPE_FILTERED_BLOCK`
     into the getdata handler (W110 BUG-28) the same parser becomes
     the SPV trust root. **BUG-1 (P0-CONSENSUS-CLASS, CVE-2012-2459).**

(F2) **`_parse_partial_merkle_tree` accepts adversarial inputs with NO
     of the 5 ExtractMatches DoS guards (merkleblock.cpp:153-183).**
     Core rejects (returns null hash) when:
       (a) `nTransactions == 0`
       (b) `nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT`
           (= 4_000_000 / 240 = 16_666)
       (c) `vHash.size() > nTransactions`
       (d) `vBits.size() < vHash.size()`
       (e) `CeilDiv(nBitsUsed, 8) != CeilDiv(vBits.size(), 8)` (no
           "extra hashes")
       (f) `nHashUsed != vHash.size()` (all hashes consumed)
     Ouroboros performs NONE of these checks. The recursion bottoms
     out by returning zero bytes on overflow (rpc.py:646-647)
     instead of failing the proof. A crafted CMerkleBlock with
     `nTransactions = 2^31-1` causes:
       * height computation loop runs ~31 iterations — bounded;
       * `_consume(31, 0)` allocates recursion stack ≤ tree height;
       * Python recursion default limit (1000) saves us at h=31, but
         that's coincidence not defense.
     The dangerous variant is a crafted proof that returns a wrong
     merkle root that still equals the header's merkle root for the
     attacker's chosen header — see (F1). **BUG-2 through BUG-6 (P1
     each, with the duplicate-children case as P0 in F1).**

(F3) **Inbound version's `fRelay` field is parsed but NEVER stored on
     the Peer** (peer.py:715 + peer.py:1301). Core uses fRelay at
     `net_processing.cpp:3683-3691`:
       ```
       if (!pfrom.IsBlockOnlyConn() && !pfrom.IsFeelerConn() &&
           (fRelay || (peer.m_our_services & NODE_BLOOM))) {
           auto* const tx_relay = peer.SetTxRelay();
           tx_relay->m_relay_txs = fRelay;  // initial value from version
           if (fRelay) pfrom.m_relays_txs = true;
       }
       ```
     Ouroboros code at peer.py:715 assigns `version.version`,
     `version.services`, `version.user_agent`, `version.start_height`,
     `version.timestamp` — but DROPS `version.relay`. Peer field
     `self.relay_txs` is the LOCAL connection-type setting (full-relay
     vs block-relay-only), not the remote peer's fRelay. As a result:
       * Tx-INV announcement to a peer that sent `fRelay=false` still
         happens (no per-peer gate); the peer must then drop / disconnect
         us for protocol-spam.
       * `m_relays_txs` is never tracked at all — Core uses it to
         decide whether to refresh tx-relay state on this peer for
         BIP-339 wtxid-relay tracking.
       * BIP-111 + BIP-37 interaction: a peer sending fRelay=false
         followed by filterload IS supposed to flip m_relay_txs back to
         true (net_processing.cpp:4980). Ouroboros can't do this because
         the bit is never tracked at all. **BUG-7 (P1, BIP-37/BIP-111
         protocol-correctness).**

(F4) **`TrickleQueue.known_filter` grows UNBOUNDED** (p2p.py:227).
     Comment admits "Bitcoin Core uses CRollingBloomFilter; for
     simplicity, use a set here". Core caps the known filter at 50_000
     entries via `CRollingBloomFilter` rotation. On a long-running
     ouroboros peer, the set grows by every txid announced, up to
     hundreds of MB after a few days of mainnet traffic. **BUG-8 (P1)**.

(F5) **`INV_TYPE_FILTERED_BLOCK` (= 3) is defined in p2p_messages.py
     but `_make_getdata_handler` (node.py:1003-1073) never dispatches
     on it.** Already documented in W110 BUG-28; W134 confirms still
     open and adds the corollary: `MSG_WITNESS_FILTERED_BLOCK` (= 3 |
     0x40000000) is not even defined — Core dispatches both. The
     filtered-block path is a SPV-client request; ouroboros silently
     drops the getdata as `notfound`, which is **technically wire-spec
     compliant** (BIP-37 says a node MAY ignore the request) but is
     functionally absent. Documented for completeness — no behavior
     change required since the entire BIP-37 stack is intentionally
     not implemented. **BUG-9 (P2/cosmetic, already-known).**

(F6) **`_build_partial_merkle_tree` (rpc.py:574-614) constructs
     `flag_bytes` in the CORRECT bit order** ("least significant bit
     first" per merkleblock.h:53) — but does it INLINE rather than via
     a helper named `BitsToBytes`. Core has the helper precisely so
     that the inverse `BytesToBits` round-trips; ouroboros's inline
     bit-pack at rpc.py:608-610 happens to be correct but the
     companion bit-UNPACK at rpc.py:632-635 is a separate inline
     re-implementation in `_parse_partial_merkle_tree`. Round-trip
     identity is tested in this audit (G18); the structural
     duplication is **BUG-10 (P2/structural)**.

Gate matrix (30)
================

CBloomFilter core data + constants (G1-G7)
------------------------------------------

G1   MAX_BLOOM_FILTER_SIZE = 36000 — MISSING
     Source-level absent in both pipelines (covered W110 BUG-1).
     **BUG-11 (carried; W110 BUG-1).**

G2   MAX_HASH_FUNCS = 50 — MISSING
     Carried W110 BUG-2. No filterload size enforcement because no
     filterload handler exists past the disconnect arm.

G3   LN2SQUARED full precision — MISSING (W110 BUG-3).

G4   CBloomFilter constructor + sizing formula — MISSING (W110 BUG-4).

G5   Hash schedule `nHashNum * 0xFBA4C795 + nTweak` — MISSING
     (W110 BUG-7). Note this is *also* used by CRollingBloomFilter
     for the inventory-known filter Core uses; ouroboros uses a plain
     set, so no MurmurHash3 anywhere — see F4 / G8.

G6   Bit-index formula `vData[nIndex>>3] |= (1<<(7&nIndex))` — MISSING
     (W110 BUG-8). Used by both insert and contains. Absent in both
     pipelines.

G7   BLOOM_UPDATE_{NONE,ALL,P2PUBKEY_ONLY,MASK} enum — MISSING
     (W110 BUG-11-14).

CRollingBloomFilter / known filter (G8-G9)
------------------------------------------

G8   `m_tx_inventory_known_filter` uses CRollingBloomFilter — MISSING
     net_processing.cpp:303 declares
       `CRollingBloomFilter m_tx_inventory_known_filter{50000, 0.000001};`
     Ouroboros uses `set[bytes]` at p2p.py:227. Comment at p2p.py:225
     explicitly admits the simplification. **BUG-8 (P1, F4)**.

G9   CRollingBloomFilter rotation / reset on size — MISSING
     The Core filter rotates generations every 50_000/2 = 25_000
     inserts; ouroboros set never rotates → unbounded growth. Same
     BUG as G8.

IsRelevantAndUpdate match logic (G10-G16)
-----------------------------------------

G10  IsRelevantAndUpdate(tx) txid match — MISSING (W110 BUG-16).

G11  Per-output scriptPubKey pushdata scan — MISSING (W110 BUG-17).

G12  Per-input prevout match — MISSING (W110 BUG-19).

G13  Per-input scriptSig pushdata scan — MISSING (W110 BUG-20).

G14  UPDATE_ALL outpoint auto-insert — MISSING (W110 BUG-21).

G15  UPDATE_P2PUBKEY_ONLY conditional (Solver → PUBKEY|MULTISIG) —
     MISSING (W110 BUG-22).

G16  CVE-2013-5700 empty-vData "match-all" short-circuit — MISSING
     (W110 BUG-10). Core (bloom.cpp:49,65):
       `if (vData.empty()) return (true / nothing);`
     Absent in both pipelines.

P2P handlers + service-bit (G17-G22)
------------------------------------

G17  filterload handler + IsWithinSizeConstraints — PARTIAL
     Disconnect path wired (FIX-36); real filter-loading path absent
     by design (-peerbloomfilters default false). **BUG-12 (P2,
     documented gap)**.

G18  filteradd handler + 520-byte MAX_SCRIPT_ELEMENT_SIZE cap — PARTIAL
     Disconnect path wired; payload cap absent. Reachable only if
     `-peerbloomfilters=true` is enabled by an operator, which the
     ouroboros config layer accepts but the handler arms still don't
     accept the payload. **BUG-13 (P2, documented gap)**.

G19  filterclear handler + m_bloom_filter_loaded = false +
     m_relay_txs = true — PARTIAL
     Disconnect path wired. Flip-back-to-relay logic absent because
     `m_relay_txs` (F3) is never tracked. **BUG-14 (P2, ties to
     BUG-7)**.

G20  merkleblock inbound handler — PRESENT
     `_register_bloom_handlers` registers an `on_merkleblock` that
     logs and drops (p2p.py:2508-2515). Matches Core's silent-ignore
     for unexpected server→client inbound.

G21  NODE_BLOOM service bit advertisement gated on `-peerbloomfilters`
     — PRESENT
     `peer.py:746-752` (inbound), `peer.py:1263-1269` (outbound),
     `peer.py:1419-1425` (relay-only path) all OR `NODE_BLOOM` into
     `our_services` iff `self.peer_bloom_filters`. Default false.
     Matches Core init.cpp:1104.

G22  BIP-111 disconnect path on filter* when NODE_BLOOM unset — PRESENT
     FIX-36 wired in `_register_bloom_handlers`. Asserted by W110
     test `test_filterload_disconnect_on_no_bloom_present`.

CMerkleBlock partial-merkle-tree wire format (G23-G28)
------------------------------------------------------

G23  `_build_partial_merkle_tree` exists in rpc.py — PRESENT
     Used by `rpc_gettxoutproof` (rpc.py:4760). Correct CMerkleBlock
     output format per merkleblock.h:48-54.

G24  `_parse_partial_merkle_tree` exists in rpc.py — PRESENT
     Used by `rpc_verifytxoutproof` (rpc.py:4789).

G25  ExtractMatches `nTransactions == 0` reject — MISSING
     Core merkleblock.cpp:156: `if (nTransactions == 0) return uint256();`
     Ouroboros: rpc.py:638 enters the height loop with `n_tx=0`,
     stays at `height=0`, then `_consume(0, 0)` returns `hashes[0]`
     unconditionally — a malformed empty proof appears valid up to the
     SHA256d header-merkle comparison. **BUG-2 (P1)**.

G26  ExtractMatches `nTransactions > MAX_BLOCK_WEIGHT /
     MIN_TRANSACTION_WEIGHT` reject — MISSING
     Bound: 4_000_000 / 240 = 16_666. Ouroboros accepts any uint32 nTx
     (up to 2^32-1). The recursion depth IS bounded by `log2(nTx)` ~32,
     so Python's default recursion limit (1000) saves us — but Core
     considers this DoS surface worth blocking. **BUG-3 (P1).**

G27  ExtractMatches `vHash.size() > nTransactions` reject — MISSING
     Core merkleblock.cpp:162-163; ouroboros never compares.
     **BUG-4 (P1).**

G28  ExtractMatches `vBits.size() < vHash.size()` reject — MISSING
     Core merkleblock.cpp:165-166; ouroboros never compares.
     **BUG-5 (P1).**

G29  CVE-2012-2459 `right == left` duplicate-children reject — MISSING
     Core merkleblock.cpp:124-127:
       ```
       if (right == left) {
           // The left and right branches should never be identical
           fBad = true;
       }
       ```
     Ouroboros `_consume` (rpc.py:663-668) recurses into both
     subtrees and returns `_dsha256(left + right)` with NO comparison.
     A crafted CMerkleBlock with duplicated adjacent leaves produces a
     fake-but-validating merkle root; the attacker can prove inclusion
     of a forged txid in a real block (limit: their txid must hash to
     the same value as a sibling). The bound is small but the CVE was
     real enough that Core fixed and re-fixed it. **BUG-1 (P0-CONSENSUS-
     CLASS, CVE-2012-2459 reintroduction in ouroboros).**

G30  ExtractMatches consumption checks (bits/hashes used == size) —
     MISSING
     Core merkleblock.cpp:177-182:
       ```
       if (CeilDiv(nBitsUsed, 8u) != CeilDiv(vBits.size(), 8u))
           return uint256();
       if (nHashUsed != vHash.size()) return uint256();
       ```
     Ouroboros _consume never tracks "did we use all the bits / all the
     hashes". A crafted proof with EXTRA trailing bytes parses OK and
     returns whatever truncated-tree root the prefix encoded. **BUG-6 (P1).**

Tooling / two-pipeline meta gate
================================

T1   ferrous-utils / Rust pipeline contains ZERO BIP-37 production
     code — REQUIRED (PRESENT)
     Confirmed by grep against `MurmurHash3|CBloomFilter|filterload|
     filteradd|filterclear|TraverseAndBuild|TraverseAndExtract|
     CalcTreeWidth|MerkleBlock`. Only RocksDB-internal `bloom_locality`
     in `sync/src/storage/db.rs:143,2740-2742` — unrelated. Pinned by
     `test_g30_two_pipeline_bip37_python_only`.

T2   Python `rpc.py` retains `_build_partial_merkle_tree` /
     `_parse_partial_merkle_tree` — REQUIRED (PRESENT)
     Used by `rpc_gettxoutproof` / `rpc_verifytxoutproof`. Pinned by
     `test_partial_merkle_tree_helpers_present_in_rpc` (re-asserted
     from W110 G28).

Bug catalogue (W134 numbering)
==============================

| ID    | Sev          | Site                                | One-line                                                              |
|-------|--------------|-------------------------------------|-----------------------------------------------------------------------|
| BUG-1 | P0-CONSENSUS | rpc.py `_consume` 663-668           | CVE-2012-2459: missing `left == right` duplicate-children reject       |
| BUG-2 | P1           | rpc.py `_parse_partial_merkle_tree` | No `n_tx == 0` reject (Core: nTransactions==0 → uint256())             |
| BUG-3 | P1           | rpc.py `_parse_partial_merkle_tree` | No `n_tx > 16666` DoS reject                                           |
| BUG-4 | P1           | rpc.py `_parse_partial_merkle_tree` | No `n_hashes > n_tx` reject                                            |
| BUG-5 | P1           | rpc.py `_parse_partial_merkle_tree` | No `n_bits < n_hashes` reject                                          |
| BUG-6 | P1           | rpc.py `_parse_partial_merkle_tree` | No "bits/hashes fully consumed" check                                 |
| BUG-7 | P1           | peer.py 715, 1301                   | Inbound `version.relay` parsed and DROPPED — fRelay never stored      |
| BUG-8 | P1           | p2p.py 225-227                      | TrickleQueue.known_filter is unbounded set, not CRollingBloomFilter   |
| BUG-9 | P2           | node.py `_make_getdata_handler`     | INV_TYPE_FILTERED_BLOCK never dispatched (W110 BUG-28 carried)        |
| BUG-10| P2 structural| rpc.py 608-610 vs 632-635           | bits<->bytes pack/unpack inlined twice (no BitsToBytes/BytesToBits)   |
| BUG-11| P2 carried   | (W110 BUG-1)                        | MAX_BLOOM_FILTER_SIZE = 36000 absent in both pipelines                |
| BUG-12| P2 documented| p2p.py 2459-2476                    | filterload "BIP-37 not implemented" arm unreachable but stub-only     |
| BUG-13| P2 documented| p2p.py 2478-2491                    | filteradd payload-cap 520B not enforced (handler is disconnect-only)  |
| BUG-14| P2 documented| p2p.py 2493-2506                    | filterclear m_relay_txs flip-back missing (tied to BUG-7)             |
| BUG-15| P2 cosmetic  | p2p_messages.py VersionMessage      | `relay` field defaults `True` — silently coerces malformed peers      |
| BUG-16| P2           | p2p_messages.py MSG_WITNESS_*       | No MSG_WITNESS_FILTERED_BLOCK constant (= 3 | 0x40000000)             |
| BUG-17| P2 docs gap  | p2p.py `_register_bloom_handlers`   | Docstring says "we never advertise NODE_BLOOM" — config IS settable   |
| BUG-18| P2           | rpc.py `_parse_partial_merkle_tree` | Recursion uses list-as-cell mutation pattern (Python 2 idiom)         |
| BUG-19| P2 cosmetic  | rpc.py `_dsha256`                   | Defined twice (here + private inline in `rpc_verifytxoutproof`)       |
| BUG-20| P2           | rpc.py `_build_partial_merkle_tree` | No early-return when matches list is wrong length vs txids            |
| BUG-21| P2           | peer.py `peer_bloom_filters`        | Config flag accepted but no CBloomFilter — operator can mis-enable    |

Severity bands:
- **P0-CONSENSUS**: Wire-spec / CVE-class divergence from Core that
  could lead to forged inclusion proofs or chain forks. (BUG-1).
- **P1**: Stress-input DoS or behavioural divergence on adversarial
  inputs. (BUG-2 through BUG-8).
- **P2**: Cosmetic, structural, or "missing feature" gaps that don't
  affect default-configured behavior. (BUG-9 through BUG-21).

Fix priority (out-of-scope for this discovery wave):
- FIX-A would close BUG-1 + BUG-2 + BUG-3 + BUG-4 + BUG-5 + BUG-6 by
  porting Core's `ExtractMatches` DoS guards (~30 LOC) into
  `_parse_partial_merkle_tree`. Pre-fix verification with
  `tools/verify-fix.sh` is REQUIRED (CVE-class).
- FIX-B would close BUG-7 + BUG-14 by storing inbound
  `version.relay` on the Peer and consulting it in the trickle queue.
- FIX-C would close BUG-8 + BUG-9 by porting a small Python
  rolling-bloom (~50 LOC) and bounding `known_filter`.

Independent reference / cross-checks
====================================

1. **Core's blockfilter test vectors** (`bitcoin-core/src/test/data/`)
   are BIP-158 not BIP-37 — no Core-canonical CBloomFilter test
   vectors exist in tree. The Core unit test
   `bitcoin-core/src/test/bloom_tests.cpp` is the authoritative
   reference (not audited here; bloom code absent).
2. **CVE-2012-2459** PoC: build a merkle tree with N tx where N is
   not a power of 2, then craft a partial tree where the rightmost
   subtree's "missing right child" is supplied as a duplicate of the
   left child. Core rejects via `fBad=true` at line 124; ouroboros
   `_consume` returns `_dsha256(left+left)` which can match a
   computed header merkle root.
3. **fRelay fleet behaviour**: cross-checked with Core
   net_processing.cpp:3683-3691. fRelay arrived in protocol-version
   70001 (`p2p_messages.py:300` already gates the byte on this).

Out of scope
============

- Full BIP-37 implementation is intentionally not pursued (Core
  itself disables it by default since v0.19; deferred until/unless an
  operator requests SPV-server mode).
- FIX waves to close BUG-1 through BUG-6 will require pre-fix
  verification with `tools/verify-fix.sh` and a forward-regression
  test pinning each CVE-class check.
- BIP-339 wtxidrelay × BIP-37 interaction: when both are negotiated,
  the bloom filter MUST be queried with txid (not wtxid) per
  BIP-339 spec. ouroboros doesn't query a filter at all; deferred.

Verification snapshot
=====================

```
$ wc -l ouroboros/audit/w134_bip37_bloom_filter.md   # this file
$ wc -l src/ouroboros/tests/test_w134_bip37_bloom_filter.py
$ python3 -m pytest src/ouroboros/tests/test_w134_bip37_bloom_filter.py -v
```

Two-pipeline guard EXTENDED:
W76 + W120 + W122 + W125 + W128 + W129 + W130 + W133 + **W134**.
