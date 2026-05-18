# W148 — Headers-first sync + chain selection + reorg (ouroboros)

**Wave:** W148 — `ProcessNewBlockHeaders`, `AcceptBlockHeader`,
`ActivateBestChain`, `ActivateBestChainStep`, `ConnectTip`, `DisconnectTip`,
`FindMostWorkChain`, `MAX_REORG_DEPTH`/`MIN_BLOCKS_TO_KEEP`, `CBlockIndex`
validity bitfield (`BLOCK_VALID_TREE`/`TRANSACTIONS`/`CHAIN`/`SCRIPTS`),
`m_chain_tx_count`, `m_best_header`, `InvalidChainFound`,
`ResetBlockFailureFlags`.

**Scope:** discovery only — no production code changes. Ouroboros is a
Python orchestration layer on top of a Rust validation core
(`ferrous-utils/sync`); the audit specifically chases the **three-pipeline
drift** known fleet pattern (Python `BlockSync._handle_reorg` /
Rust `HeaderSync.save_headers` / Rust `BlockchainDB.invalidate_block` +
`reactivate_best_chain` — three coexisting consensus pipelines, well over
the two-pipeline guard).

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + context check + bad-prevblk + min_pow_checked gate +
  AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (loop body, `cs_main` once across batch, `CheckBlockIndex`,
  `NotifyHeaderTip`).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter over `setBlockIndexCandidates`, ancestor
  `BLOCK_FAILED_VALID` + `BLOCK_HAVE_DATA` filter, candidate erase
  on failure).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (DisconnectTip loop, vpindexToConnect 32-block chunks, ConnectTip
  loop, `MaybeUpdateMempoolForReorg`).
- `bitcoin-core/src/validation.cpp:3323-3450` — `ActivateBestChain`
  (do-while, releases `cs_main` between iterations).
- `bitcoin-core/src/validation.cpp:2900-3000` — `ConnectTip` (read,
  `ConnectBlock`, chainstate write, `UpdateTip`).
- `bitcoin-core/src/validation.cpp:3055-3107` — `DisconnectTip` (read
  `CBlockUndo`, `DisconnectBlock`, mempool refill).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filter `(block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(block_index.nHeight) == &block_index)`
  AND `BLOCK_FAILED_VALID`).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus`.
- `bitcoin-core/src/validation.cpp:1964-1984` — `InvalidChainFound`
  (`m_best_invalid`, `RecalculateBestHeader`).
- `bitcoin-core/src/validation.cpp:3765-3815` —
  `ReceivedBlockTransactions` (`nTx`, `m_chain_tx_count`).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum (5-level
  ordered ladder).
- `bitcoin-core/src/chain.h:120-129` — `CBlockIndex::nTx`,
  `m_chain_tx_count`.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.
- `bitcoin-core/src/headerssync.cpp:17-242` — `HeadersSyncState`.

**Files audited (ouroboros — hybrid Python + Rust)**

Rust (ferrous-utils/sync):
- `ferrous-utils/sync/src/network/header_sync.rs` — `HeaderSync`,
  `sync_headers`, `request_headers`, `save_headers`, `build_locator`,
  ChainReorg recovery path.
- `ferrous-utils/sync/src/network/block_sync.rs` — `BlockSync`,
  `sync_blocks`, in-flight tracking, peer task spawning.
- `ferrous-utils/sync/src/validate/header.rs` — `HeaderValidator`,
  `validate_header`, `validate_difficulty`, `validate_timestamp`,
  `validate_version`, `validate_checkpoint`, `validate_minimum_chain_work`.
- `ferrous-utils/sync/src/validate/headers_presync.rs` —
  `HeadersSyncState` PRESYNC/REDOWNLOAD machine.
- `ferrous-utils/sync/src/validate/block.rs` — `BlockValidator`,
  `apply_block`, `disconnect_block`.
- `ferrous-utils/sync/src/storage/db.rs` — `BlockchainDB`,
  `update_best_block`, `get_best_block`, `mark_block_invalid`,
  `mark_block_failed_child`, `clear_block_invalid`, `invalidate_block`,
  `reconsider_block`, `reactivate_best_chain`,
  `connect_block_at_height`, `block_descends_from`,
  `block_is_ancestor`, `update_block_status`.
- `ferrous-utils/sync/src/lib.rs` — PyO3 bindings (`PyBlockchainDB`,
  `connect_block_from_bytes`, `disconnect_blocks_atomic`,
  `invalidate_block`, `reconsider_block`, `is_synced`).
- `ferrous-utils/common/src/types.rs` — `BlockStatus` (lines 464-566),
  `BlockMetadata` (lines 568-642).

Python (src/ouroboros):
- `src/ouroboros/block_sync.py` — `BlockSync` (sync_loop,
  handle_headers, handle_block, `_handle_reorg`, `_drain_block_buffer`,
  `_process_orphans`, `_get_sync_peer`, `_build_locator`).
- `src/ouroboros/node.py` — `BitcoinNode` (`_check_synced`,
  `is_synced`, `_init_genesis_block`, `start`).
- `src/ouroboros/sync_manager.py` — `SyncManager.is_synced`,
  `get_progress`.
- `src/ouroboros/validation.py` — `BlockValidator._validate_header`,
  `_get_expected_bits`, `apply_block`.
- `src/ouroboros/rpc.py:6265-6395` — `rpc_invalidateblock`,
  `rpc_reconsiderblock`, `MAX_REORG_DEPTH` constant.

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ProcessNewBlockHeaders contract | G1: PoW + MTP + difficulty validated at header acceptance | **BUG-1 (P0-CONS)** Rust `validate_header` ships GUTTED difficulty + timestamp + version checks (header.rs:248-262 silently accepts any bits; timestamp MTP commented out lines 215-230) |
| 1 | … | G2: `m_best_header` advanced independently of full validation | **BUG-2 (P1)** No `m_best_header` field — only single `best_block` pointer (db.rs:843); no way to track "best valid header" separate from "best fully-validated block" |
| 1 | … | G3: header rejected if `pprev->nStatus & BLOCK_FAILED_VALID` ("bad-prevblk") | **BUG-3 (P0-CDIV)** Zero `parent.is_invalid()` checks anywhere in Rust validate_header or Python handle_headers (grep "bad-prevblk" returns ONE match — an unrelated rpc.py docstring) |
| 1 | … | G4: `min_pow_checked` boolean threaded to header acceptance | PARTIAL — Python `handle_headers` threads `min_pow_checked` (block_sync.py:1623) + cumulative work check (block_sync.py:1797); Rust `save_headers` does NOT |
| 1 | … | G5: empty headers message is no-op (no Misbehaving) | PASS — Python (block_sync.py:1648) returns early on empty; Rust (header_sync.rs:273) breaks loop |
| 2 | CChain m_chain tip pointer | G6: random-access `m_chain[height]` semantics | **BUG-4 (P1)** `get_block_hash_by_height` walks BLOCK_INDEX_CF per call (db.rs); no in-memory `m_chain` vector for O(1) height→hash. Every locator build = N RocksDB hits. |
| 2 | … | G7: `m_chain.Genesis()` / `Tip()` accessors | PASS — `get_best_block` returns tip; genesis is `get_block_hash_by_height(0)` |
| 2 | … | G8: `m_chain.FindFork(other_chain)` | **BUG-5 (P1)** No fork-finding helper at all. Python `_handle_reorg` walks 100 Parent pointers serially (block_sync.py:2852-2906); Rust `block_descends_from` (db.rs:2237) walks from descendant to ancestor block-by-block, O(height) per call |
| 3 | ActivateBestChain loop | G9: do-while loop iterates until `pindexMostWork == Tip()` | **BUG-6 (P0)** No equivalent. `connect_block_from_bytes` is one-shot tip extension; `reactivate_best_chain` (db.rs:2377) fires only inside `reconsider_block` RPC, NOT after every block accept |
| 3 | … | G10: releases lock between iterations for responsiveness | N/A — Python uses asyncio (no equivalent CS_MAIN); single-threaded reorg path holds the event loop across `_handle_reorg`'s 100-block walk |
| 3 | … | G11: `MaybeUpdateMempoolForReorg` after each ConnectTip | PARTIAL — `_handle_reorg` re-adds disconnected txs to mempool ONCE at end (block_sync.py:3146-3164); not invoked after each ConnectTip during normal forward sync; mempool not re-evaluated against new tip's UTXO view per-block |
| 3 | … | G12: vpindexToConnect chunked by 32 to bound stack frame | **BUG-7 (P2)** `_handle_reorg` builds full disconnect+connect lists in one shot (block_sync.py:2914-2921); no 32-block chunking, no asyncio yield-point between batches |
| 4 | MAX_REORG_DEPTH guard | G13: refuse `disconnect+connect > 100` | PARTIAL — RPC `submitblock` enforces `MAX_REORG_DEPTH=100` (rpc.py:5717); Python `_handle_reorg` walks `range(100)` as a HARDCODED loop limit (block_sync.py:2852, 2868) — silently truncates without erroring |
| 4 | … | G14: error message identifies the limit | PASS for submitblock; FAIL for `_handle_reorg` (which silently caps at 100 with no log warning) |
| 4 | … | G15: operator override to bypass cap | **BUG-8 (P1)** No operator knob; depth is literal `range(100)` (block_sync.py:2852) and a `MAX_REORG_DEPTH = 100` module constant (rpc.py:285) — both compile-time |
| 5 | ConnectTip semantics | G16: ConnectBlock + chainstate write + UpdateTip atomic | PASS — Rust `connect_block_from_bytes` (lib.rs:3402) uses single WriteBatch (lib.rs:3702-3711, HEAD_BLOCKS Phase 1/Phase 2 markers) |
| 5 | … | G17: on failure, block marked `BLOCK_FAILED_VALID` and chain disconnected | **BUG-9 (P0-CDIV)** `connect_block_from_bytes` returns PyValueError on every consensus failure path (high-hash, bad-merkle, bad-prev, bad-cb-length, etc.) but NEVER calls `mark_block_invalid` — failing block stays VALID-looking in metadata; the next attempt will re-validate from scratch and fail again, looping |
| 5 | … | G18: IBD-side accepts non-extending block as side-branch via `AcceptBlock` storage | **BUG-10 (P0-CDIV)** Rust `connect_block_from_bytes` HARD-REJECTS at lib.rs:3528-3536 if `prev_blockhash != tip_hash` ("Block prev_hash does not match chain tip"); the body is NOT stored, no header-only branch acceptance. Python `_handle_reorg` is the only side-branch path and is only triggered from `_process_orphans` (block_sync.py:2213) — IBD-side parallel forks during catch-up are silently dropped |
| 6 | DisconnectTip semantics | G19: rev*.dat undo applied in reverse | PASS — `disconnect_block_at_height` (db.rs:1061) reads SPENT_CF / UNDO_CF, restores Coin metadata (height + is_coinbase) |
| 6 | … | G20: DISCONNECT_UNCLEAN logged but not fatal | PARTIAL — `connect_block_at_height` warns on missing UTXO during reactivation (db.rs:2632-2636) but doesn't surface the inconsistency to operator/RPC |
| 6 | … | G21: failure halts (Core `FatalError`), not silent | **BUG-11 (P1)** `_handle_reorg` returns `False` on disconnect failure (block_sync.py:2960-2965); the caller (`sync_loop` at 660 or `_process_orphans` at 2214) just logs and continues — no `FatalError`, no halt, the chain manager is left in an inconsistent state (some peels done, some not) |
| 7 | CBlockIndex validity bitfield | G22: 5-level ordered validity ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS | **BUG-12 (P1)** `BlockStatus` (common/types.rs:464-566) is a FLAG bitmap, not Core's ordered ladder. Constants are mis-defined: BLOCK_VALID_TREE=1, BLOCK_VALID_TRANSACTIONS=2, BLOCK_VALID_CHAIN=3, BLOCK_VALID_SCRIPTS=4 — these are written as INTEGER CONSTANTS not BIT FLAGS, but stored OR-ed into a u32. Setting `BLOCK_VALID_TRANSACTIONS` (=2) without `BLOCK_VALID_TREE` (=1) is impossible to express; `BLOCK_VALID_CHAIN` (=3) collides with `1|2`. Comment at line 476 admits "Unused flag" for BLOCK_VALID_CHAIN. `is_valid()` only checks failed-mask, not validity-level. |
| 7 | … | G23: `BLOCK_HAVE_DATA` set after block body lands on disk | PASS — `apply_block` (validate/block.rs:901-904) calls `status.set_has_data()` before write |
| 7 | … | G24: `BLOCK_HAVE_UNDO` set after rev*.dat write | **BUG-13 (P1)** `set_has_undo()` defined (types.rs:563-565) but NO CALLERS in production: `apply_block` only sets `set_has_data()`; `disconnect_block` mutates SPENT_CF but doesn't set BLOCK_HAVE_UNDO on the disconnected block's metadata; reverse-engineering whether a block has rev data requires a separate SPENT_CF probe |
| 7 | … | G25: `BLOCK_FAILED_CHILD` propagated to descendants on InvalidateBlock | PASS — `invalidate_block` walks `(target_height+1)..=best_height+1000` calling `mark_block_failed_child` (db.rs:2217-2226); known fix (BUG-1 of the same code) extended horizon to cover orphan headers |
| 7 | … | G26: persisted to disk so flags survive restart | PASS — `update_block_status` writes both BLOCK_INDEX_CF (height key) and BLOCK_INDEX_BY_HASH_CF (hash key) — db.rs:2061-2101 explicitly persists |
| 8 | m_chain_tx_count + m_chain_work | G27: per-block cumulative tx counter set at header acceptance | **BUG-14 (P1)** `BlockMetadata` (common/types.rs:568-580) has NO `chain_tx_count` or `nTx` field. `chain_tx_count` only exists in `AssumeutxoData` (lib.rs:2161, snapshot.rs:92) — DEAD-FIELD outside snapshot context. RPC `getblockchaininfo` cannot return correct `nchaintx`; verificationprogress falls back to height-based estimate |
| 8 | … | G28: m_chain_work cumulative chainwork maintained | PASS — `BlockMetadata.chainwork` stored as 32-byte big-endian (types.rs:574); `compute_chainwork(prev, bits)` accumulated at every header save (header_sync.rs:758) and every apply_block (block.rs:888-897) |
| 8 | … | G29: ResetBlockFailureFlags clears only FAILED bits AND only on matching-ancestor chain | **BUG-15 (P0-CDIV)** `reconsider_block` (db.rs:2281-2342) walks `(0..target_height).rev()` clearing ALL invalid ancestors (filtered ONLY by `block_is_ancestor`), and `(target_height+1)..=best_height+1000` clearing ALL invalid descendants. Core's `ResetBlockFailureFlags` filters `(BLOCK_FAILED_VALID)` AND a strict-ancestor-or-descendant test; ouroboros's reconsider on a deep block can resurrect blocks that were independently invalidated via a separate `invalidateblock` RPC |
| 8 | … | G30: `IsInitialBlockDownload` exit gated on tip-recent + MinimumChainWork | **BUG-16 (P0-CDIV)** No `IsInitialBlockDownload` analog. `Node.is_synced` returns `self.synced` (node.py:1502); `_check_synced` delegates to `sync_manager.is_synced()` which delegates to Rust `FastSync::is_synced()` which is **HARDCODED `Ok(false)`** (lib.rs:5912-5916: "For now, return false (in practice would check against network tip)"). The only path that sets `self.synced=True` is the fallback `height > 0` at node.py:913 when there is no sync_manager — i.e. only in tests. IBD effectively NEVER exits in production; mempool acceptance, fee estimation gating, and assume-valid all run as if perpetually mid-IBD. |

---

## BUG-1 (P0-CONS) — Rust `validate_header` ships gutted; difficulty + MTP + version checks are no-ops

**Severity:** P0-CONSENSUS. Bitcoin Core's `ContextualCheckBlockHeader`
(validation.cpp:4080-4121) enforces five gates: `bad-diffbits`,
`time-too-old` (MTP), `time-timewarp-attack` (BIP94 testnet4),
`time-too-new`, and `bad-version` (BIP34/BIP65/BIP66 buried-deployment
versioning). The Rust `HeaderValidator.validate_header`
(`ferrous-utils/sync/src/validate/header.rs:81-110`) is the canonical
entry point used by `HeaderSync.save_headers` during P2P header sync,
and it ships with three of those five gates disabled:

```rust
// header.rs:202-233 — validate_timestamp
fn validate_timestamp(&self, header: &Header, prev_header: &Header) -> Result<()> {
    // Check not too far in the future (2 hours)
    if header.time > current_time + MAX_FUTURE_SECONDS {
        return Err(HeaderValidationError::TimestampTooFarFuture);
    }
    // ... 6 lines of comment "skip this check entirely" ...
    // Skip backward timestamp validation during header sync
    // if prev_header.time > header.time + MAX_BACKWARD_SECONDS {
    //     return Err(HeaderValidationError::TimestampBeforeMedian);
    // }
    Ok(())
}

// header.rs:248-263 — validate_difficulty
fn validate_difficulty(&self, header: &Header, prev_header: &Header) -> Result<()> {
    let expected_bits = prev_header.bits.to_consensus();
    let actual_bits = header.bits.to_consensus();
    // Allow some tolerance for difficulty adjustments
    // This is a simplified check - real validation is more complex
    if actual_bits != expected_bits {
        // For testing purposes, accept the difficulty
        // In production, this would be much stricter
    }
    Ok(())
}

// header.rs:236-245 — validate_version
fn validate_version(&self, header: &Header) -> Result<()> {
    if header.version.to_consensus() < 1 {
        return Err(HeaderValidationError::InvalidVersion);
    }
    Ok(())
}
```

**File:** `ferrous-utils/sync/src/validate/header.rs:81-263`

**Core ref:** `bitcoin-core/src/validation.cpp:4080-4121`

**Impact:**
- A peer can offer any `nBits` and it will pass — the consensus-critical
  difficulty retarget check is **disabled with an explicit
  "For testing purposes, accept the difficulty" comment**. Combined
  with the per-header PoW check in `handle_headers` (block_sync.py:1699
  — which validates `hash <= target` against the *header's claimed*
  bits, not the network's expected bits), a peer can advertise a low
  difficulty in the header, mine a low-PoW block satisfying that fake
  difficulty, and pass both gates.
- The Python `BlockValidator._validate_header` (validation.py:947-1048)
  DOES enforce all five Core gates correctly — but it runs only inside
  `validate_block`, which is invoked AFTER block-body arrival. Header
  sync (which is the choke point and the anti-DoS surface) uses the
  gutted Rust path.
- "Three-pipeline drift" first finding of this audit: Python
  `_validate_header` (validation.py:947, correct), Rust
  `validate_header` (header.rs:81, gutted), Rust inline header checks
  inside `connect_block_from_bytes` (lib.rs:3416-3572, partial MTP
  but no difficulty retarget).

**Comment-as-confession:** Both `validate_timestamp` and
`validate_difficulty` carry comments that literally document the bug —
"Skip backward timestamp validation during header sync" and "For
testing purposes, accept the difficulty". This is the fleet-wide
"comment-as-confession" pattern (now 6+ instances tracked across
W124-W148).

---

## BUG-2 (P1) — No `m_best_header` separate from `m_chain_tip`

**Severity:** P1. Bitcoin Core maintains TWO chain pointers:
`m_chain.Tip()` (active fully-validated tip) and `m_best_header`
(highest-work header known, regardless of body availability or
validation level). `m_best_header` advances during header sync long
before blocks land, so getheaders advertisements, RPC
`getblockchaininfo.headers`, and assume-valid sync targets all consult
it. Ouroboros stores ONE `best_block` (db.rs:843
`update_best_block` / db.rs:804 `get_best_block`) used for both
purposes.

**File:** `ferrous-utils/sync/src/storage/db.rs:804-870`

**Core ref:** `bitcoin-core/src/validation.h` `m_best_header`;
`validation.cpp:4234` (update at AcceptBlockHeader).

**Impact:**
- During header sync the `best_block` pointer advances to the highest
  header even though no block body has landed → RPC
  `getbestblockhash` returns a hash whose block we don't have →
  `getblock` immediately afterwards fails. Inconsistent RPC surface
  to wallet/explorer integrations.
- `RecalculateBestHeader` analog (called by `InvalidChainFound` in
  Core) has nothing to update; the single `best_block` pointer is the
  only state.

---

## BUG-3 (P0-CDIV) — No `bad-prevblk` check anywhere

**Severity:** P0-CDIV. Bitcoin Core's `AcceptBlockHeader`
(validation.cpp:4220-4223) explicitly rejects with
`BLOCK_INVALID_PREV` / "bad-prevblk" when
`pindexPrev->nStatus & BLOCK_FAILED_VALID`. A peer extending a known
invalid chain is immediately misbehaving-100.

Ouroboros: zero matches for "bad-prevblk" outside an unrelated
`rpc.py:6274` docstring. Neither Python `handle_headers`
(block_sync.py:1623-1946) nor Rust `validate_header`
(header.rs:81-110) nor Rust `save_headers`
(header_sync.rs:606-776) check the parent's `BlockStatus.is_invalid()`.

**File:** `src/ouroboros/block_sync.py:1623-1946`,
`ferrous-utils/sync/src/network/header_sync.rs:606-776`

**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`

**Impact:**
- After `invalidateblock` RPC marks block X as failed, a peer can
  send headers that extend X and the entire chain gets queued into
  `_validated_headers` (Python) or written to BLOCK_INDEX_CF (Rust)
  unmarked. The next reorg/reconsider iteration may resurrect them.
- Symmetric leak to BUG-9 (failed `connect_block_from_bytes` doesn't
  set `BLOCK_FAILED_VALID`). Header-layer + block-layer both omit
  fail-propagation at every entry point.

---

## BUG-4 (P1) — No in-memory `m_chain` vector; locator builds = N RocksDB lookups

**Severity:** P1 (performance). Core's `CChain.m_chain` is an
in-memory `std::vector<CBlockIndex*>` allowing O(1) height→hash
access. Locator construction (Core: `chain.cpp:26 LocatorEntries`)
walks the vector — no I/O.

Ouroboros's `_build_locator` (block_sync.py:2253-2327) calls
`self.db.get_block_hash_by_height(current_height)` in a `while`
loop with exponential spacing. Each call traverses BLOCK_INDEX_CF
via RocksDB. At tip height ~900k, every sync_loop iteration (1s
cadence during IBD) issues ~30 RocksDB GETs just to build the
locator.

**File:** `src/ouroboros/block_sync.py:2253-2327`,
`ferrous-utils/sync/src/storage/db.rs` (`get_block_hash_by_height`)

**Core ref:** `bitcoin-core/src/chain.h:50-72` `CChain`,
`chain.cpp:26-50` `LocatorEntries`.

**Impact:** RocksDB GET cost dominates the sync_loop hot path on
mainnet. Acceptable but well below Core's O(1) — measurable in
top-of-tip CPU profile.

---

## BUG-5 (P1) — No `FindFork` / `Skip` pointer; reorg walks linear ancestors

**Severity:** P1 (performance). Core's `CBlockIndex::pskip` builds a
skip-list (chain.h:174) so `GetAncestor(height)` is O(log N).
`CChain::FindFork(other)` uses pointer-set arithmetic — O(divergence
depth), not O(absolute height).

Ouroboros has neither helper:
- Python `_handle_reorg` (block_sync.py:2852-2906) builds both
  current-chain and new-chain back to depth 100 by walking
  `block.prev_blockhash` one block at a time, then compares hash
  membership with a nested `for` over both lists (O(100²) = 10000
  hash compares per reorg).
- Rust `block_descends_from` (db.rs:2237-2263) walks
  `current_height` to `ancestor_height` one block per loop
  iteration; called inside `(target_height+1)..=scan_ceiling` so
  invalidate at height N over a 1000-block scan horizon is O(N×1000).

**File:** `src/ouroboros/block_sync.py:2852-2906`,
`ferrous-utils/sync/src/storage/db.rs:2237-2263, 2681-2710`

**Core ref:** `bitcoin-core/src/chain.h:174` `pskip`;
`chain.cpp:79-100` `CChain::FindFork`.

**Impact:** Reconsider/invalidate RPCs and reorg paths get O(N×K)
slow; on mainnet a `reconsiderblock` of a 1000-deep ancestor scans
1M blocks worth of metadata.

---

## BUG-6 (P0) — No `ActivateBestChain` outer loop; tip selection only fires from RPC

**Severity:** P0 (semantic divergence). Bitcoin Core's
`ActivateBestChain` is a `do-while` loop that repeatedly calls
`FindMostWorkChain` + `ActivateBestChainStep` until the most-work
candidate equals the active tip. It's invoked from `ProcessNewBlock`,
`ProcessNewBlockHeaders`, `InvalidateBlock`, `ReconsiderBlock`,
periodic block-arrival paths, etc.

Ouroboros equivalents:
- `connect_block_from_bytes` (lib.rs:3402) advances the tip by exactly
  one block; if the block doesn't extend the current tip, hard-rejects.
- `reactivate_best_chain` (db.rs:2377-2538) is the ONLY analog to
  `FindMostWorkChain` + `ActivateBestChainStep`, and it is called
  ONLY from `reconsider_block` (db.rs:2334). It is NEVER invoked
  after a normal block accept or after a `_handle_reorg` completes.
- Python `_handle_reorg` (block_sync.py:2804) is a one-shot disconnect+
  connect; it doesn't re-evaluate whether a *different* higher-work
  candidate also emerged during the reorg.

**File:** `src/ouroboros/block_sync.py:2804-3172`,
`ferrous-utils/sync/src/storage/db.rs:2377-2538`,
`ferrous-utils/sync/src/lib.rs:3402-3960`

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3450`
(`ActivateBestChain`), `3191-3280` (`ActivateBestChainStep`).

**Impact:**
- Multi-tip ambiguity: if two chains A and B both arrive during sync
  and B becomes higher work mid-burst, ouroboros stays on A unless
  RPC `reconsiderblock` is invoked on B's tip. Header layer happily
  tracks B but block-body acceptance refuses non-extending blocks
  (see BUG-10).
- Pattern shape: known fleet finding "discovery: helper exists but
  call-site never wires it" (4× tracked already). `reactivate_best_chain`
  is the helper; the call-site gap is real.

---

## BUG-7 (P2) — `_handle_reorg` builds full disconnect/connect list with no chunking

**Severity:** P2. Core's `ActivateBestChainStep` splits the connect
side into 32-block chunks (validation.cpp:3224
`nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight)`)
to bound the time `cs_main` is held.

Python `_handle_reorg` (block_sync.py:2914-2921) builds both
`blocks_to_disconnect` and `blocks_to_connect` arrays in one shot,
then iterates each through `await asyncio.to_thread(self.db.disconnect_block, ...)`
and `await asyncio.to_thread(self.db.connect_block_from_bytes, ...)`.
Each call does yield (asyncio cooperates), but no explicit chunk
boundary, no halfway commit point, no progress logging granularity
suitable for forensics.

**File:** `src/ouroboros/block_sync.py:2914-3135`

**Core ref:** `bitcoin-core/src/validation.cpp:3217-3260`

**Impact:** Low — asyncio cooperative scheduling masks most of the
problem, but a 100-block reorg generates 200 PyO3 boundary crossings
serially with no chunked-batch consolidation.

---

## BUG-8 (P1) — `MAX_REORG_DEPTH=100` is hardcoded as a literal `range(100)` walk

**Severity:** P1. Two distinct sites enforce a "max reorg = 100"
cap:
1. `_handle_reorg` walks `for _ in range(100):` literally
   (block_sync.py:2852, 2868) — silently caps at 100 with no error
   if the actual fork depth exceeds the limit. A 101-block fork =
   "no common ancestor found within 100 blocks" → returns False,
   chain stays on the loser.
2. RPC `submitblock` returns `reorg-too-deep` error
   (rpc.py:5717-5726) — properly identifies the limit.

Core has NO MAX_REORG_DEPTH — only `MIN_BLOCKS_TO_KEEP=288`
governs prune-protection. Ouroboros's `MIN_BLOCKS_TO_KEEP=288` is
defined (config.py:26, blockstore.rs:747) but the reorg path uses
the unrelated hardcoded 100 walk depth instead.

**File:** `src/ouroboros/block_sync.py:2852, 2868`,
`src/ouroboros/rpc.py:285`

**Core ref:** `bitcoin-core/src/validation.h:75-76`
`MIN_BLOCKS_TO_KEEP = 288`; Core has no MAX_REORG_DEPTH.

**Impact:**
- On a > 100-block reorg (e.g. contentious fork at h=903,000 with
  a 150-block heavier alternate), ouroboros silently stays on the
  losing chain. Core would reorg. Cross-impl partition.
- The `_handle_reorg` walk hardcodes 100 with no constant
  reference; refactor-fragile.

---

## BUG-9 (P0-CDIV) — Failed `connect_block_from_bytes` never marks block invalid

**Severity:** P0-CDIV. Bitcoin Core's `ConnectTip` failure path
(validation.cpp:1988-1994) sets
`pindex->nStatus |= BLOCK_FAILED_VALID`, calls `InvalidChainFound`,
and erases from `setBlockIndexCandidates`. The block is ineligible
for re-selection.

Ouroboros's `connect_block_from_bytes` (lib.rs:3402-3960) returns
`PyValueError` on every consensus failure path:
- "high-hash: block hash exceeds PoW target" (line 3486)
- "Invalid merkle root" (line 3502)
- "Block prev_hash does not match chain tip" (line 3529)
- "Timestamp not greater than median time past" (line 3558)
- "bad-cb-length" (line 3578)
- "bad-witness-merkle-match" (line 3630, 3656)
- "bad-txns-nonfinal" (line 3689)

ZERO callsites mutate `BlockStatus`. The helper `mark_block_invalid`
exists (db.rs:2107-2113) but is invoked ONLY by `invalidate_block`
(RPC) — never by the validation failure path.

The Python `_handle_reorg` connect-side (block_sync.py:3087-3108)
catches the exception and returns False; no status mutation either.

**File:** `ferrous-utils/sync/src/lib.rs:3402-3960`
(all `Err(PyErr::new::<...>)` returns)

**Core ref:** `bitcoin-core/src/validation.cpp:1988-1994`
(`InvalidBlockFound` / `pindex->nStatus |= BLOCK_FAILED_VALID`)

**Impact:**
- A peer that submits a block that fails sanity will repeatedly
  succeed in re-buffering it (block_sync.py:925 `_ibd_block_buffer`
  has only a `_perm_rejected_blocks` set populated by Python-side
  failures — Rust-side failures don't feed it).
- No `m_best_invalid` warning surface; operator gets no signal
  that the network has produced a competing heavier-but-invalid
  chain (the canonical "consensus split detected" alert).

---

## BUG-10 (P0-CDIV) — IBD-side rejects all non-extending blocks; no AcceptBlock-style side-branch storage

**Severity:** P0-CDIV (Pattern Y closure GAP for ouroboros). Bitcoin
Core's `AcceptBlock` (validation.cpp:4297-4430) stores any
PoW-valid, contextually-valid block to disk regardless of whether it
extends the active tip — `ActivateBestChain` later decides what to
do with it.

Ouroboros's `connect_block_from_bytes` HARD-REJECTS non-extending
blocks unconditionally:

```rust
// lib.rs:3528-3536
if prev_blockhash != tip_hash {
    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
        format!(
            "Block prev_hash {} does not match chain tip {}",
            hex::encode(prev_blockhash),
            hex::encode(tip_hash),
        )
    ));
}
```

There is no parallel "store the body to BLOCKS_CF without changing
the active tip" path. The only side-branch acceptance is in Python's
`_handle_reorg`, which is invoked from `_process_orphans`
(block_sync.py:2213) when an orphan's parent is found post-hoc — but
the orphan must already be in `self.orphan_blocks` (block_sync.py:226,
capped at 200 entries).

**File:** `ferrous-utils/sync/src/lib.rs:3528-3536`

**Core ref:** `bitcoin-core/src/validation.cpp:4297-4430`

**Impact:**
- During IBD, an honest peer that announces a near-tip side branch
  (e.g. h=905,123 fork) gets blocks dropped — no body stored, no
  header-index update for the side-branch metadata. If that branch
  becomes heavier post-IBD, all bodies must be re-downloaded.
- Compounds with BUG-6 (no ABC outer loop) — even if blocks WERE
  stored, no tip-selection pass would fire automatically.

---

## BUG-11 (P1) — `_handle_reorg` disconnect-failure leaves chain in inconsistent state, no FatalError

**Severity:** P1. Core's `ActivateBestChainStep` treats DisconnectTip
failure as fatal:
```cpp
FatalError(m_chainman.GetNotifications(), state, _("Failed to disconnect block."));
return false;
```

Ouroboros's `_handle_reorg` (block_sync.py:2960-2965) returns False on
disconnect failure; the disconnect loop has already partially mutated
the chainstate (some heights peeled, some not). The caller
(`sync_loop` at 660 or `_process_orphans` at 2214) logs the False and
continues. Next ConnectBlock attempt will operate on a half-disconnected
chainstate.

**File:** `src/ouroboros/block_sync.py:2960-2965, 2804-3172`

**Core ref:** `bitcoin-core/src/validation.cpp:3208-3214`

**Impact:** A corrupted SPENT_CF row that causes
`disconnect_block_at_height` to fail mid-reorg leaves UTXO state in
limbo. The process continues with a broken chainstate and races
new block downloads against it. Core's `FatalError` halts the node;
ouroboros silently logs.

---

## BUG-12 (P1) — `BlockStatus` constants are mis-defined as integers, not flag bits

**Severity:** P1 (semantic and design defect, cross-cite W109).
Core's `BlockStatus` (chain.h:42-86) encodes a 5-level **ordered**
validity ladder in the low 3 bits (mask `BLOCK_VALID_MASK=7`), so
`pindex->IsValid(BLOCK_VALID_TRANSACTIONS)` means "validity level >= 3".
High bits (HAVE_DATA=8, HAVE_UNDO=16, FAILED_VALID=32, ...) are
independent flag bits.

Ouroboros's `BlockStatus` (`common/src/types.rs:464-566`):

```rust
pub const BLOCK_VALID_TREE: u32 = 1;
pub const BLOCK_VALID_TRANSACTIONS: u32 = 2;
pub const BLOCK_VALID_CHAIN: u32 = 3;        // ← collides with 1|2
pub const BLOCK_VALID_SCRIPTS: u32 = 4;
pub const BLOCK_VALID_MASK: u32 = 0x07;

pub const BLOCK_FAILED_VALID: u32 = 32;
pub const BLOCK_HAVE_DATA: u32 = 8;
pub const BLOCK_HAVE_UNDO: u32 = 16;
```

These are written as **integer level constants** but stored OR-ed
into a u32. Setting BLOCK_VALID_CHAIN (=3) is bitwise identical to
setting BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS (1|2=3). The
"Unused flag" comment on BLOCK_VALID_CHAIN (line 476) tacitly
admits the bug. `is_valid()` (types.rs:512-515) just tests
"no failed bits set" — never tests the validity LEVEL.

No code anywhere uses BLOCK_VALID_CHAIN or queries
`status.0 & BLOCK_VALID_MASK >= BLOCK_VALID_TRANSACTIONS`.

**File:** `ferrous-utils/common/src/types.rs:464-566`

**Core ref:** `bitcoin-core/src/chain.h:42-86`

**Impact:**
- `FindMostWorkChain` analog (`reactivate_best_chain`, db.rs:2377)
  cannot filter on "blocks with BLOCK_VALID_CHAIN" — Core uses
  this gate to select assume-valid IBD tips that have
  transactions+chain-valid but may still need script verification.
- assumeUTXO snapshot integration (W138) can't represent
  "TREE-valid, no TRANSACTIONS yet" — every snapshot base is
  stamped with default `BlockStatus::new()` (= BLOCK_VALID_TREE
  only).
- Migration cost: BLOCK_VALID_CHAIN is documented as "Unused" but
  any future use will require renumbering BLOCK_VALID_TRANSACTIONS
  and BLOCK_VALID_SCRIPTS, breaking on-disk format.

---

## BUG-13 (P1) — `BLOCK_HAVE_UNDO` setter exists, never called

**Severity:** P1. `set_has_undo()` (types.rs:563-565) is defined +
exported. Production callers: ZERO. `apply_block` (block.rs:901-904)
only sets `set_has_data()`; `disconnect_block` mutates SPENT_CF
but doesn't set `BLOCK_HAVE_UNDO` on the disconnected block's
metadata.

Determining "do we have undo data for block X" requires a separate
SPENT_CF range probe — exactly the cost the per-block flag is
supposed to avoid.

**File:** `ferrous-utils/common/src/types.rs:563-565`,
`ferrous-utils/sync/src/validate/block.rs:901` (only `set_has_data`),
no occurrences of `set_has_undo` in `ferrous-utils/sync/src/**/*.rs`

**Core ref:** `bitcoin-core/src/validation.cpp:3000-3015`
(set after `WriteUndoDataForBlock`).

**Impact:** Dead-helper-at-call-site. `FindFilesToPrune` analog
would have to do per-block SPENT_CF lookups instead of consulting
the flag. Fleet-pattern smell: third dead-helper instance in
ouroboros tracked since W138.

---

## BUG-14 (P1) — `BlockMetadata` has no `chain_tx_count` / `nTx` field

**Severity:** P1 (dead-data / structural omission). Core's
`CBlockIndex` carries `nTx` (per-block tx count) and `m_chain_tx_count`
(cumulative from genesis). Used by `getblockchaininfo` (returns
`nchaintx`), `EstimateBlockTime`, sync-progress, verificationprogress.

Ouroboros's `BlockMetadata` (`common/src/types.rs:568-580`):
```rust
pub struct BlockMetadata {
    pub height: u32,
    pub chainwork: [u8; 32],
    pub timestamp: u32,
    pub status: BlockStatus,
}
```

No `chain_tx_count`, no `nTx`. The string `chain_tx_count` ONLY
appears in `AssumeutxoData` (lib.rs:2161, snapshot.rs:92, three
hardcoded values for mainnet/testnet/regtest snapshots) — outside
snapshot context the field is unused dead data.

There IS a `nTx` field in HEADERS_CF format (db.rs:312-317 comment),
but it's stored alongside the 80-byte header and is not surfaced
in `BlockMetadata`; downstream RPCs never reach it.

**File:** `ferrous-utils/common/src/types.rs:568-580`,
`ferrous-utils/sync/src/lib.rs:2161`

**Core ref:** `bitcoin-core/src/chain.h:120-129`
`nTx` + `m_chain_tx_count`.

**Impact:**
- `verificationprogress` falls back to height-based linear
  interpolation; Core's tx-density-weighted progress is unavailable.
- `getblockchaininfo.nchaintx` returns 0 or a fabricated value.
- assumeUTXO snapshot validation can't cross-check
  `chain_tx_count` from the snapshot base against actual chain
  state.

---

## BUG-15 (P0-CDIV) — `reconsider_block` clears invalid flag from ALL ancestors / descendants

**Severity:** P0-CDIV (mirrors blockbrew W148 BUG-12). Core's
`ResetBlockFailureFlags` (validation.cpp:3711-3730) clears
`BLOCK_FAILED_VALID` ONLY from blocks that BOTH:
1. Are strict ancestors OR descendants of pindex (matched via
   `GetAncestor` symmetric check), AND
2. Have `BLOCK_FAILED_VALID` set.

Ouroboros's `reconsider_block` (db.rs:2281-2342):

```rust
// Clear failure flags on ancestors (lines 2300-2311)
for height in (0..target_height).rev() {
    if let Some(metadata) = self.get_block_metadata(height)? {
        if metadata.is_invalid() {
            if self.block_is_ancestor(height, target_height, block_hash)? {
                self.clear_block_invalid(height)?;
            }
        }
    }
}

// Clear failure flags on descendants (lines 2313-2329)
let max_scan_height = best_height + 1000;
for height in (target_height + 1)..=max_scan_height {
    if let Some(metadata) = self.get_block_metadata(height)? {
        if metadata.is_invalid() {
            if self.block_descends_from(height, target_height, block_hash)? {
                self.clear_block_invalid(height)?;
            }
        }
    }
}
```

The ancestor filter via `block_is_ancestor` is correct in shape —
but Core also requires the BLOCK_FAILED_VALID bit specifically
(types.rs:484), whereas ouroboros's `is_invalid` returns true on
ANY of `BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD`. If an ancestor
was `BLOCK_FAILED_CHILD` (e.g. inherited from a separate
invalidate-block call on a different branch), reconsidering this
target will silently resurrect it.

Additionally, the ancestor walk `(0..target_height).rev()` is
unbounded scope — it iterates from genesis to target. A reconsider
on a deep target traverses all of mainnet.

**File:** `ferrous-utils/sync/src/storage/db.rs:2300-2329`

**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730`

**Impact:**
- Operator invalidates blocks B1 (ancestor of pindex) and B2
  (separately, on a different branch). Reconsider pindex → B1 is
  cleared (correct; it's on pindex's ancestor chain) but if any
  descendant of B2 was incidentally on pindex's descendant scan,
  it'd be cleared too. The filter `block_descends_from` mostly
  catches this, but the FAILED_CHILD vs FAILED_VALID distinction
  is collapsed.

---

## BUG-16 (P0-CDIV) — `is_synced` is hardcoded `Ok(false)`; IBD effectively never exits

**Severity:** P0-CDIV. Bitcoin Core's `IsInitialBlockDownload`
(validation.cpp:1940-1942) checks tip-recent + MinimumChainWork
and latches `m_cached_is_ibd = false` once exit conditions are
met.

Ouroboros's chain:
- `Node.is_synced()` returns `self.synced` (node.py:1500-1502).
- `Node._check_synced()` (node.py:899-916) → if `sync_manager`
  exists, returns `sync_manager.is_synced()`.
- `SyncManager.is_synced()` (sync_manager.py:267-273) → returns
  `self.fast_sync.is_synced()`.
- `FastSync.is_synced` is the PyO3 method `PyFastSync::is_synced`
  (lib.rs:5911-5916):

```rust
/// Check if blockchain is synced
fn is_synced(&self) -> PyResult<bool> {
    // For now, return false (in practice would check against network tip)
    // This is a simplified version
    Ok(false)
}
```

So in production (where `sync_manager` is always set), `self.synced`
is fixed at False forever. The fallback path at node.py:913
(`height > 0`) only fires when `sync_manager` is None — a
test-only configuration.

The flag gates:
- `_compact_filters_advertised` (node.py:1523) — never advertises
  NODE_COMPACT_FILTERS.
- RPC `getblockchaininfo` `initialblockdownload` field
  (rpc.py:1454, 1652) — `is_ibd = not self._is_synced()` — always
  reports IBD=True even after caught up.
- Mempool acceptance gating (various) — runs as if perpetually
  mid-IBD, suppressing standardness checks that should fire post-IBD.

**Comment-as-confession:** lib.rs:5913 — "For now, return false
(in practice would check against network tip)". The "for now" has
been live in mainnet builds; node.py:910 says "In production, this
should check against network" — also a confession.

**File:** `ferrous-utils/sync/src/lib.rs:5911-5916`,
`src/ouroboros/node.py:899-916`, `src/ouroboros/sync_manager.py:267-273`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`

**Impact:**
- Long-running mainnet node ALWAYS reports IBD=True →
  getblockchaininfo lies to wallets / explorers / monitoring.
- Service-bit advertisements never flip — NODE_COMPACT_FILTERS
  permanently off even when filter index is fully synced.
- Mempool standardness path runs in IBD mode forever.
- The fleet pattern "comment-as-confession" hits its 7th
  recurrence; the "dead-helper / dead-data fall-through" pattern
  has its strongest single-instance example in this codebase.

---

## BUG-17 (P0-CDIV) — Rust `HeaderSync.save_headers` skips validation for first 1000 headers when database is empty

**Severity:** P0-CDIV. `HeaderSync.save_headers`
(`ferrous-utils/sync/src/network/header_sync.rs:725-739`) contains
a bootstrap shortcut:

```rust
// For empty database, skip validation for first 1000 headers to bootstrap
// This allows us to get a working chain started even if some early headers have issues
if was_empty && current_height < 1000 {
    // Skip validation for first 1000 headers when database was empty at start
    if current_height % 100 == 0 {
        log::debug!("Skipping validation for header at height {} (bootstrap mode, i={})", current_height, i);
    }
} else {
    self.validator.validate_header(header, prev_in_batch)
        .map_err(|e| { ... HeaderSyncError::Validation(e) })?;
}
```

So on a fresh datadir, a peer can send any bytes for the first 1000
headers — no PoW retarget, no MTP, no version checks (the Rust
gates wouldn't enforce them anyway per BUG-1, but here they're not
even called).

**File:** `ferrous-utils/sync/src/network/header_sync.rs:725-739`

**Core ref:** `bitcoin-core/src/validation.cpp:4183-4239`
(no "skip validation during bootstrap" provision in Core).

**Impact:**
- Trust-on-first-use vulnerability: every fresh-install ouroboros
  trusts the first peer for headers 1-999. Combined with BUG-1
  (validate_header doesn't actually check difficulty even on the
  path that "validates"), the entire pre-1000 header window is
  effectively peer-trusted.
- On mainnet this is mostly mitigated by checkpoints + assumed
  chainwork later — but headers 0-999 cover ~ a week of early
  Bitcoin history; a peer can offer a low-difficulty fork of that
  prefix and only get caught when later validation gates fire.

---

## BUG-18 (P0-CDIV) — Rust header_sync ChainReorg recovery rewinds best_block without disconnecting chainstate

**Severity:** P0-CDIV (severe consistency violation).
`HeaderSync.request_headers` (header_sync.rs:471-500) detects a
reorg when the first received header's `prev_blockhash` doesn't
match our best block, then "recovers":

```rust
if let Ok(Some(common_height)) =
    self.db.find_height_of_hash(&prev_hash_bytes, best_height)
{
    log::info!(
        "Chain reorg detected: rewinding from height {} to {} (common ancestor)",
        best_height, common_height
    );
    self.db
        .update_best_block(&prev_hash_bytes, common_height)
        .map_err(|e| HeaderSyncError::Database(e))?;
    // Headers now connect (first header's prev = our new best)
}
```

This calls `update_best_block` ALONE — rewinds the META_CF tip
pointer from `best_height` down to `common_height`, but DOES NOT:
- Call `disconnect_block_at_height` for the intervening blocks.
- Roll back UTXO mutations in CHAINSTATE_CF.
- Restore SPENT_CF undo records.
- Notify mempool of disconnected txs.
- Update the txindex.

The on-disk state now claims tip = X at height N, but
CHAINSTATE_CF contains UTXOs from blocks above N. Next
`connect_block_from_bytes` will write outputs whose spent-records
are already in SPENT_CF for the (now-undone) original chain.

**File:** `ferrous-utils/sync/src/network/header_sync.rs:475-500`

**Core ref:** `bitcoin-core/src/validation.cpp:3055-3107`
(`DisconnectTip` — atomic with undo).

**Impact:**
- Single-call inconsistency: any mainnet reorg detected via header
  sync corrupts the chainstate silently. Symptom: txindex
  inconsistency, missing UTXOs on next connect attempt, possible
  doublespend acceptance after the corrupted reorg.
- Comment "Headers now connect (first header's prev = our new
  best)" reveals the author's mental model — only header continuity
  was being fixed; UTXO consistency was overlooked.

---

## BUG-19 (P1) — `_get_sync_peer` uses `random.choice`; peer rotation bug stalls block downloads

**Severity:** P1 (live operational bug, documented in CLAUDE.md
"Known Issues" 2026-03-28). `BlockSync._get_sync_peer`
(block_sync.py:2329-2344) picks the sync peer:

```python
def _get_sync_peer(self, our_height: int) -> Peer | None:
    if hasattr(self.peer_manager, 'get_all_ready_peers'):
        peers = self.peer_manager.get_all_ready_peers()
    else:
        peers = getattr(self.peer_manager, 'peers', [])
        if isinstance(peers, dict):
            peers = list(peers.values())
    candidates = [
        p for p in peers
        if isinstance(p, Peer) and hasattr(p, 'start_height')
        and p.start_height > our_height and p.is_connected()
    ]
    if not candidates:
        return None
    return random.choice(candidates)
```

`random.choice` is uniform but stateless — the same peer can be
selected repeatedly even if it just stalled. The stall detection
at sync_loop (block_sync.py:671-680) catches a stalled peer after
`_header_sync_stall_timeout`, but on the next iteration
`random.choice` may immediately re-pick the same peer (1-in-N odds).

Core's `FindNextBlocksToDownload` (net_processing.cpp) maintains
per-peer in-flight + ban-score state and explicitly avoids stalled
peers.

**File:** `src/ouroboros/block_sync.py:2329-2344`

**Core ref:** `bitcoin-core/src/net_processing.cpp`
`FindNextBlocksToDownload`.

**Impact:** Production: block downloads stall when a peer goes
silent because re-selection oscillates. This is the documented
peer-rotation bug per CLAUDE.md.

---

## BUG-20 (P1) — Python `_handle_reorg` uses 100-block walk as both depth limit AND ancestor-search bound

**Severity:** P1 (correctness + carry-forward of BUG-8). The two
`for _ in range(100):` loops at block_sync.py:2852 and 2868 serve
double duty:
1. Limit reorg depth to 100 blocks (intentional).
2. Bound the common-ancestor search to 100 blocks (accidental).

If the actual common ancestor is at depth 50 but `db.get_block`
returns None at depth 30 (e.g. because the block was pruned via
`MIN_BLOCKS_TO_KEEP=288`), the loop `break`s early at line 2856-2857
and the chain-comparison nested loop misses the real ancestor. The
function then returns False with "no common ancestor found".

The two concerns should be decoupled: depth-limit is a policy,
ancestor-search is structural.

**File:** `src/ouroboros/block_sync.py:2844-2906`

**Core ref:** `bitcoin-core/src/validation.cpp:3093` (Core walks
arbitrary depth via `pindex->pprev`; the `MIN_BLOCKS_TO_KEEP`
prune-protection guarantees the body is available).

**Impact:** Pruned-node reorg detection has a higher failure rate
than unpruned. Operationally these failures manifest as silent
chain-divergence with no error log; the only signal is `False`
return from `_handle_reorg`.

---

## BUG-21 (P0) — Python `_handle_reorg` connect-side does NOT call validator on Rust path

**Severity:** P0 (consensus-relevant). Python `_handle_reorg`
connect loop (block_sync.py:3087-3108):

```python
try:
    if hasattr(self.db, "connect_block_from_bytes"):
        await asyncio.to_thread(
            self.db.connect_block_from_bytes, raw_bytes, connect_height
        )
    else:
        # Last-resort path used only when the Rust extension is not built
        valid, error = self.validator.validate_block(new_block_obj)
        if not valid:
            logger.error(f"Invalid block in reorg: ...")
            return False
        self.validator.apply_block(new_block_obj)
        self.db.update_best_block(new_hash, connect_height)
```

The Rust path runs `connect_block_from_bytes` which performs the
inline checks (PoW, merkle, prev, MTP, cb-length, witness commit,
IsFinalTx) — but does NOT run `BlockValidator.validate_block` from
validation.py (which has BIP-30, sigops, BIP-34 coinbase height,
fee-vs-subsidy, signet checks, etc).

So normal forward sync runs Python `validate_block` BEFORE
connect_block_from_bytes (via `_drain_block_buffer` →
`apply_block` pipeline), but the REORG path skips the full
validation and falls straight to the Rust connect.

**File:** `src/ouroboros/block_sync.py:3087-3108`

**Core ref:** `bitcoin-core/src/validation.cpp:2900-3000`
`ConnectTip` always runs `ConnectBlock` which runs ALL contextual
checks.

**Impact:**
- A side-branch block that would FAIL Python `validate_block` (e.g.
  BIP-30 duplicate-txid, illegal sigops, bad coinbase height) gets
  connected via the reorg path because Rust's `connect_block_from_bytes`
  doesn't replay those gates. The "three-pipeline drift" pattern's
  most consequential cost: REORG bypasses checks NORMAL accept runs.
- W143 BUG-7 noted this for ouroboros's `connect_block_from_bytes`
  shipping a HALF-FINISHED pipeline; BUG-21 here is the
  corresponding REORG-side surfacing.

---

## BUG-22 (P1) — `_handle_reorg` last-ditch fallback re-serializes via Python (witness-stripped) and "refuses to fall back"

**Severity:** P1 (defensive paranoia in wrong direction).
Block_sync.py:3074-3085:

```python
if raw_bytes is None:
    # Last-ditch fallback: re-serialize from the Python Block object.
    # This drops witness data, so consensus checks on segwit blocks
    # may misbehave under this branch. Keep the path so a missing-bytes
    # case fails loudly rather than silently committing wrong state.
    logger.error(
        f"Reorg connect: no raw bytes available for ..."
        f"refusing to fall back to witness-stripped serialize()"
    )
    return False
```

The author was aware that Python `Block.serialize()` drops witness
data and would corrupt SegWit consensus. The chosen fix: error out
hard instead of silently corrupting. Good. But:
- This branch fires whenever `get_block_bytes` returns None AND
  `new_block_obj.raw_payload` is empty — i.e. for any block that was
  received but whose raw payload was discarded post-deserialization.
- Result: certain reorg patterns simply CANNOT proceed; the node
  stops mid-reorg with `return False`, leaving the chain in the
  pre-reorg state (better than corruption, but still wedges sync).

**File:** `src/ouroboros/block_sync.py:3071-3085`

**Core ref:** `bitcoin-core/src/validation.cpp:3055-3107`
(`DisconnectTip` reads from disk via `ReadBlockFromDisk` — always
gets the on-disk witness data).

**Impact:** Reorg path is fragile. Combined with the "raw_payload
discarded post-deserialize" pattern in `Block` lifecycle, this
introduces non-deterministic reorg failure depending on which
blocks happen to retain `raw_payload` at the time of the reorg.

---

## BUG-23 (P1) — No `MaybeUpdateMempoolForReorg` post-connect equivalent during normal forward sync

**Severity:** P1 (mirrors blockbrew BUG-17). Core's
`ActivateBestChainStep` calls `MaybeUpdateMempoolForReorg` after
DisconnectTip (refill) AND after ConnectTip (evict mined txs +
re-validate against new UTXO view).

Ouroboros has:
- Disconnect-side: `_handle_reorg` re-adds disconnected non-coinbase
  txs to mempool at end of reorg (block_sync.py:3146-3164) — Pattern
  B, fires once at end (not per-block).
- Connect-side: `_handle_reorg` calls `mempool.remove_block_transactions`
  per-block (block_sync.py:3131) — removes-only, no
  re-validation pass.
- Normal forward sync (`_drain_block_buffer`): calls
  `mempool.remove_block_transactions` (somewhere in pipeline) but
  no post-connect re-validation that runs BIP-68/BIP-113/sequence
  locks against the new tip's UTXO view for txs still in mempool.

**File:** `src/ouroboros/block_sync.py:3146-3164` (re-add only),
`src/ouroboros/mempool.py` (no `RemoveForReorg` analog called
post-connect during normal sync).

**Core ref:** `bitcoin-core/src/validation.cpp:3206`
(`MaybeUpdateMempoolForReorg(disconnectpool, false)`).

**Impact:** Mempool may retain txs that violate new-chain sequence
locks. Next mining attempt or relay decision uses stale validity.

---

## BUG-24 (P1) — `min_pow_checked` threading is Python-only; Rust path lacks the gate entirely

**Severity:** P1. The `min_pow_checked` parameter is the Core
mechanism (validation.cpp:4186, 4242) that ensures headers from a
fresh peer are gated on nMinimumChainWork before being committed
to the index.

Python `handle_headers` threads it correctly (block_sync.py:1623
signature, 1797-1841 enforcement loop using
`get_minimum_chain_work` from Rust). Rust `HeaderSync.save_headers`
(header_sync.rs:606) has no `min_pow_checked` parameter and no
nMinimumChainWork check — it stores every header from any peer
unconditionally (subject to BUG-1's gutted per-header checks).

**File:** `ferrous-utils/sync/src/network/header_sync.rs:606`

**Core ref:** `bitcoin-core/src/validation.cpp:4186, 4229`

**Impact:** The CLI / `ouroboros sync` command path uses Rust
`HeaderSync` directly (without the Python `BlockSync.handle_headers`
gate). Operators running pure-Rust sync get headers from any peer
without the chainwork threshold check.

---

## BUG-25 (P2) — `compute_chainwork` for genesis uses `[0u8; 32]` as prev, ignoring chainparams

**Severity:** P2. Core computes genesis chainwork as
`GetBlockProof(genesis)` with no special prev — chainwork is
strictly additive from work-of-block-itself.

Rust `apply_block` (block.rs:888-897) and `save_headers`
(header_sync.rs:749-758) both compute:
```rust
let prev_chainwork = if current_height == 0 {
    [0u8; 32]
} else {
    self.db.get_block_metadata(current_height - 1)
        .ok().and_then(|opt| opt.map(|m| m.chainwork))
        .unwrap_or([0u8; 32])
};
```

The `unwrap_or([0u8; 32])` for non-genesis missing-prev is the
real bug — if the previous metadata is missing (e.g. corruption,
or assumeUTXO snapshot base not stamped), chainwork silently
resets. This silently desynchronizes work accounting and may cause
the BUG-15-class reactivate_best_chain comparator to pick the
wrong "highest" leaf.

**File:** `ferrous-utils/sync/src/validate/block.rs:888-897`,
`ferrous-utils/sync/src/network/header_sync.rs:749-758`

**Core ref:** `bitcoin-core/src/chain.h:166` (chainwork is
strictly additive, no fallback default).

**Impact:** Missing-metadata edge case (snapshot rollback, partial
restore) corrupts chainwork accounting silently.

---

## BUG-26 (P1) — `disconnect_blocks_atomic` documented as enforcing MAX_REORG_DEPTH "by Python caller" — but Python doesn't

**Severity:** P1 (documentation lies, enforcement gap). Rust
docstring (lib.rs:5124-5125):

```
/// Reorg depth is enforced by the Python caller via `MAX_REORG_DEPTH`.
```

Python actually only enforces it inside `rpc_submitblock`
(rpc.py:5717). The Python `_handle_reorg` (block_sync.py:2804) uses
the implicit `range(100)` walk-depth as the only cap — and that
cap is on the ANCESTOR SEARCH, not on the disconnect length.
`disconnect_blocks_atomic` itself accepts any (tip_height,
ancestor_height) and disconnects everything in between — there is
no internal cap.

A non-RPC caller (the orphan-driven reorg from
`_process_orphans` at block_sync.py:2214) inherits
`_handle_reorg`'s implicit cap, but the Rust contract says "enforced
by caller" — which only the submitblock path does correctly.

**File:** `ferrous-utils/sync/src/lib.rs:5124-5150`,
`src/ouroboros/block_sync.py:2804-3172`

**Core ref:** N/A (Core has no MAX_REORG_DEPTH).

**Impact:** A blob caller (future RPC, future bridge) that uses
`disconnect_blocks_atomic` without re-implementing the cap can
trigger arbitrarily deep disconnects. The doc-comment encodes a
non-existent invariant. Comment-as-confession (8th instance).

---

## BUG-27 (P2) — `reactivate_best_chain` defers real reorg "to the sync loop" — but sync loop has no such code path

**Severity:** P2 (dead-branch). Rust `reactivate_best_chain`
(db.rs:2485-2492):

```rust
if fork_height < best_height {
    log::warn!(
        "reactivate_best_chain: fork at height {} below current best {} — \
         reorg required, deferring to sync loop",
        fork_height, best_height
    );
    return Ok(best_height);
}
```

It bails out when the reactivated leaf forks BELOW the current
best — and "defers to the sync loop". But the Python sync_loop
(block_sync.py:636-715) has no code path that detects this state
or invokes a follow-up reorg. The warn log is the only output;
the reactivation is silently incomplete.

**File:** `ferrous-utils/sync/src/storage/db.rs:2485-2492`,
`src/ouroboros/block_sync.py:636-715`

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3450`
(`ActivateBestChain` outer loop handles this case directly).

**Impact:** After `reconsiderblock` on a deep block, if the
reactivated chain requires a real reorg (fork below current best),
the chain manager logs a warning and stays on the wrong chain
indefinitely. The promised "sync loop will pick it up" never
fires.

---

## BUG-28 (P1) — `node._init_genesis_block` calls `update_best_block(genesis_hash, 0)` as fallback, bypassing connect_block_from_bytes

**Severity:** P1 (consensus-pipeline bypass). Node startup
(node.py:790-897) tries `connect_block_from_bytes` first; if that
fails it falls back to:

```python
# node.py:895-897
self.db.update_best_block(genesis_hash, 0)
logger.info("Genesis block tip set (lightweight init)")
```

The fallback writes the META_CF best_block pointer without
writing the genesis block body to BLOCKS_CF, without populating
genesis block metadata, without setting BLOCK_HAVE_DATA. On the
next startup `get_block(genesis_hash)` returns None; on the next
header_sync request, `prev_blockhash` checks against the genesis
hash succeed (because META_CF says we're at genesis) but
RPC `getblock(genesis_hash)` fails.

**File:** `src/ouroboros/node.py:790-897`

**Core ref:** `bitcoin-core/src/validation.cpp:3756`
`LoadBlockIndexDB` / `init.cpp:LoadGenesisBlock`.

**Impact:** Partial init causes a phantom tip state. If
`connect_block_from_bytes` ever fails (e.g. genesis bytes
mis-encoded, or the Rust extension is the wrong version), the
node starts with broken state and continues silently.

---

## BUG-29 (P0-CDIV) — `connect_block_from_bytes` PoW check uses claimed bits, not GetNextWorkRequired

**Severity:** P0-CDIV. Rust `connect_block_from_bytes`
(lib.rs:3416-3490) decodes `nBits` from the header and computes
`target = mantissa * 2^(8*(exponent-3))`, then checks
`block_hash <= target`. PASS as a per-header sanity check.

What it does NOT do: verify the `nBits` is the CORRECT difficulty
(`GetNextWorkRequired(pprev)`) for this height. A peer can offer
a header with low difficulty bits, a hash satisfying that low
target, and the connect path accepts it. The retarget gate
(`bad-diffbits`) is supposed to catch this — but Python
`validate_block` (validation.py:947 `_validate_header`) DOES check
`_get_expected_bits`, while Rust `connect_block_from_bytes` does
NOT, and Rust `validate_header` (header.rs:248) explicitly
"accepts the difficulty" with a permissive comment.

So: if the consensus pipeline runs Python `validate_block` first
(as in normal forward sync via `_drain_block_buffer`), the
difficulty IS checked. If it runs `connect_block_from_bytes`
directly (as in reorg path BUG-21 OR `_init_genesis_block` path
OR Rust-only IBD via `FastSync.sync`), it is NOT.

**File:** `ferrous-utils/sync/src/lib.rs:3416-3490`

**Core ref:** `bitcoin-core/src/validation.cpp:4088`
`bad-diffbits` gate.

**Impact:**
- Consensus split risk on reorg path: a side-branch block with
  cooked low-difficulty header would be accepted via
  `_handle_reorg`'s connect side.
- "Three-pipeline drift" (CONFIRMED this audit, FIRST RECORDED
  INSTANCE in W148 ouroboros): three coexisting consensus
  pipelines (Python `validate_block`, Rust `validate_header`,
  Rust `connect_block_from_bytes`) with different gate sets.
  The previous W143 finding for ouroboros logged a related shape;
  this audit extends it with the difficulty-gate divergence
  specifically.

---

## BUG-30 (P2) — Python `handle_headers` queue cap = 50,000 silently drops batches; no peer ban for flood

**Severity:** P2 (anti-DoS gap). Python `handle_headers`
(block_sync.py:1657-1663):

```python
_MAX_HEADER_QUEUE = 50_000
if len(self._validated_headers) > _MAX_HEADER_QUEUE:
    logger.debug(
        f"Header queue at {len(self._validated_headers)}, "
        f"skipping batch until blocks catch up"
    )
    return
```

The batch is dropped silently. The peer is not penalized. A
malicious peer can keep firing 2000-header batches: each is dropped
at the queue cap with no score adjustment. Combined with BUG-19
(random peer selection), the bad peer remains in rotation.

Core's `ProcessHeadersMessage` (net_processing.cpp) has explicit
ban-score adjustments tied to header-batch behavior; ouroboros's
gate is queue-cap-only.

**File:** `src/ouroboros/block_sync.py:1657-1663`

**Core ref:** `bitcoin-core/src/net_processing.cpp`
`ProcessHeadersMessage`.

**Impact:** Defense-in-depth gap. Header-flood from a single peer
is rate-limited by the cap but not actively penalized; the peer
keeps trying.

---

## Fleet-pattern smells

- **Three-pipeline drift (NEW + confirmed 2nd instance for ouroboros
  in this quad)**: BUG-1, BUG-9, BUG-17, BUG-21, BUG-29. Python
  `validate_block` (full, correct, late), Rust `validate_header`
  (gutted, header-sync entry), Rust `connect_block_from_bytes`
  (inline-checks, partial, late) — three consensus pipelines with
  different gate sets diverging on difficulty, MTP, version,
  failed-block propagation. The W143 ouroboros audit identified
  this for block validation; W148 confirms it extends to header
  acceptance.
- **Comment-as-confession (7+ instances across this audit)**:
  - "For testing purposes, accept the difficulty" (header.rs:259)
  - "Skip backward timestamp validation during header sync"
    (header.rs:227)
  - "For now, return false (in practice would check against network
    tip)" (lib.rs:5913) — most egregious; gates all of
    `is_synced`.
  - "In production, this should check against network" (node.py:912)
  - "Bug-fix: was `block_mtp > 0` which incorrectly skips the
    check" (validation.py:989) — fixed in Python, but the
    underlying duplicate-implementation in Rust still has it.
  - "Headers now connect (first header's prev = our new best)"
    (header_sync.rs:489) — the comment reveals the author only
    saw header-continuity, not UTXO consistency (BUG-18).
  - "Reorg depth is enforced by the Python caller via
    MAX_REORG_DEPTH" (lib.rs:5125) — not actually enforced
    everywhere (BUG-26).
  - "refusing to fall back to witness-stripped serialize()"
    (block_sync.py:3083) — defensive paranoia masking real bug.
- **Two-pipeline guard 18th distinct extension**: BUG-1 (Python
  `_validate_header` vs Rust `validate_header` vs inline checks).
- **Dead-helper-at-call-site (4+ instances)**:
  - `set_has_undo` (types.rs:563, never called in production —
    BUG-13).
  - `validate_minimum_chain_work` (header.rs:361, only called
    from Python wrapper, not from Rust `save_headers` itself).
  - `reactivate_best_chain` (db.rs:2377, called only from
    `reconsider_block` RPC, never from sync loop after
    `_handle_reorg` — see BUG-27).
- **Dead-data plumbing**: `chain_tx_count` in `AssumeutxoData`
  (lib.rs:2161) — defined, set in 3 hardcoded snapshots, never
  surfaced anywhere downstream (BUG-14).
- **30-of-30 GATES**: not fired (this audit has 30 BUGs but
  spread across 8 behaviours; the pattern of "every single
  gate buggy" only applies to a specific sub-behaviour). The
  closest is `validate_header` in Rust where 3 of 5 Core gates
  are explicitly disabled.
- **"Shape-gated NOT flag-gated"** is absent (this audit's
  divergences are dispatch-style not flag-style).
- **Carry-forward re-anchor**: BUG-16 (`is_synced` hardcoded
  false) is a regression-test target that has been live since
  the FastSync module was introduced — multiple W-waves have
  not fixed it.
- **NEW pattern: "Recovery path is the bug path"** (BUG-18
  ChainReorg recovery via `update_best_block`-only rewinds
  best_block pointer without disconnecting chainstate) —
  defensive recovery code introduces the corruption it was
  meant to repair. Possible companion finding to W121 BUG-1
  filter-index rebase.

---

## Summary

**Severity totals (30 BUGs):**

- **P0-CONS** (consensus-criticial): 1 — BUG-1 (gutted
  Rust `validate_header`)
- **P0-CDIV** (consensus-divergent): 7 — BUG-3, BUG-9, BUG-10,
  BUG-15, BUG-16, BUG-17, BUG-18, BUG-29
- **P0** (semantic gap): 2 — BUG-6 (no ABC outer loop),
  BUG-21 (reorg bypasses Python validate_block)
- **P1**: 14 — BUG-2, BUG-4, BUG-5, BUG-8, BUG-11, BUG-12,
  BUG-13, BUG-14, BUG-19, BUG-20, BUG-22, BUG-23, BUG-24,
  BUG-26, BUG-28
- **P2**: 5 — BUG-7, BUG-25, BUG-27, BUG-30 (and BUG-4
  partially)

**Three highest-leverage fixes:**

1. **BUG-16** (1-line: change `Ok(false)` in
   `PyFastSync::is_synced` to compute `tip-recent +
   chainwork >= MinimumChainWork` — same shape as Core's
   `UpdateIBDStatus`; surfaces real IBD-exit signal across
   all RPCs, mempool gates, and service-bit advertisements).
2. **BUG-1** (~20 lines: implement `validate_difficulty`
   properly using existing `permitted_difficulty_transition`
   helper that's already imported into `headers_presync.rs`;
   uncomment the MTP backward check in `validate_timestamp`;
   add BIP34/BIP65/BIP66 version checks mirroring Python
   `_validate_header`).
3. **BUG-18** (~10 lines: in `HeaderSync::request_headers`
   reorg recovery path, call `disconnect_blocks_atomic(best_height,
   common_height)` BEFORE `update_best_block` so chainstate
   is consistent; mirrors Core's `DisconnectTip`).

**Three most-interesting structural findings:**

1. **`is_synced` is hardcoded `Ok(false)`** (BUG-16). The
   most-shipped Bitcoin-node RPC field (`initialblockdownload`)
   ships fixed at True forever in any production ouroboros
   deployment because the gate is literally
   `fn is_synced(&self) -> PyResult<bool> { Ok(false) }`.
2. **Rust `HeaderSync` rewinds best_block without disconnecting
   chainstate on a ChainReorg** (BUG-18). The "reorg recovery"
   path calls `update_best_block` ALONE — META_CF tip pointer
   moves but CHAINSTATE_CF and SPENT_CF are not rolled back.
   Single-call chainstate corruption on any header-sync-detected
   reorg.
3. **Three-pipeline drift WITH gutted header validator** (BUG-1
   + BUG-29). Rust `validate_header` explicitly "accepts the
   difficulty" with a "for testing purposes" comment, but it's
   the canonical header-sync entry. Python `_validate_header`
   does the right thing in `validate_block`. Reorg path
   (`_handle_reorg`) calls `connect_block_from_bytes` which
   does inline PoW but does NOT verify `nBits` is the expected
   retarget — meaning a side-branch with cooked low-difficulty
   header could pass the reorg connect.
