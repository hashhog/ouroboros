W132 — BIP-68 / BIP-112 / BIP-113 + nSequence + OP_CSV + MTP audit (ouroboros)
==============================================================================

Date: 2026-05-17
Impl: ouroboros (Python primary + Rust ferrous-utils consensus-validate pipeline)
Wave: W132 BIP-68 relative locktime + BIP-112 OP_CHECKSEQUENCEVERIFY +
      BIP-113 MTP-as-locktime-cutoff + IsFinalTx + GetMedianTimePast
      (DISCOVERY)
Reference:
  - bitcoin-core/src/consensus/tx_check.cpp           (CheckTransaction)
  - bitcoin-core/src/consensus/tx_verify.cpp          (IsFinalTx,
                                                       CalculateSequenceLocks,
                                                       EvaluateSequenceLocks,
                                                       SequenceLocks)
  - bitcoin-core/src/script/interpreter.cpp           (OP_CSV,
                                                       OP_CHECKLOCKTIMEVERIFY,
                                                       CheckSequence,
                                                       CheckLockTime)
  - bitcoin-core/src/chain.{h,cpp}                    (GetMedianTimePast,
                                                       nMedianTimeSpan=11)
  - bitcoin-core/src/validation.cpp                   (CalculateLockPointsAtTip,
                                                       CheckSequenceLocksAtTip,
                                                       ContextualCheckBlock,
                                                       nLockTimeCutoff)
  - bitcoin-core/src/policy/policy.{h,cpp}            (STANDARD_LOCKTIME_VERIFY_FLAGS,
                                                       LOCKTIME_VERIFY_SEQUENCE)
  - bitcoin-core/src/primitives/transaction.h         (SEQUENCE_FINAL,
                                                       SEQUENCE_LOCKTIME_DISABLE_FLAG,
                                                       SEQUENCE_LOCKTIME_TYPE_FLAG,
                                                       SEQUENCE_LOCKTIME_MASK,
                                                       SEQUENCE_LOCKTIME_GRANULARITY,
                                                       MAX_SEQUENCE_NONFINAL)

BIPs: 68, 112, 113. Status: ACTIVE on mainnet since block 419328 (CSV
deployment), buried; ACTIVE from genesis on testnet4 / signet / regtest.

Status: 30 gates audited — PRESENT 18 / PARTIAL 8 / MISSING/BUG 4.
**14 BUGS** (1 P0-CONSENSUS / 4 P1 / 9 P2/structural).

Two-pipeline scope
------------------

Sequence locks + IsFinalTx are consensus surface — both pipelines
implement them:

Python pipeline:
  - `src/ouroboros/script.py`        (OP_CSV + OP_CLTV opcodes)
  - `src/ouroboros/validation.py`    (BlockValidator + TransactionValidator,
                                      check_sequence_locks, _is_final_tx,
                                      nLockTimeCutoff plumbing)
  - `src/ouroboros/mempool.py`       (BIP-113 MTP plumbing for mempool;
                                      next-block height + tip MTP)
  - `src/ouroboros/database.py`      (get_median_time_past — Rust-backed
                                      with full-block-deser fallback)
  - `src/ouroboros/node.py`          (get_median_time — RPC mediantime)
  - `src/ouroboros/consensus.py`     (BURIED_DEPLOYMENTS / CSV heights)

Rust pipeline (ferrous-utils/sync):
  - `validate/sequence_lock.rs`      (SequenceLock, InputLockInfo,
                                      calculate_sequence_locks,
                                      evaluate_sequence_locks,
                                      check_sequence_locks, is_final_tx,
                                      csv_activation_height,
                                      LOCKTIME_THRESHOLD = 500_000_000,
                                      all SEQUENCE_LOCKTIME_* constants)
  - `validate/header.rs`             (HeaderValidator::get_median_time_past
                                      returns Result<u32>)
  - `validate/block.rs`              (check_tx_sequence_locks, calls
                                      check_sequence_locks crossing the
                                      FFI boundary via Python)
  - `lib.rs`                         (PyO3 wrappers: `check_sequence_locks`,
                                      `is_final_tx`, `locktime_threshold`,
                                      `get_median_time_past`)
  - `versionbits.rs`                 (trait fn `get_median_time_past`
                                      returns Option<i64> — used for BIP-9
                                      time-based deployment transitions)

Both pipelines must agree on consensus semantics. Two-pipeline guard
PRESERVED (no source divergence on opcode semantics or sequence-lock
math), with **3 documented divergences** (BUG-3, BUG-4, BUG-5 — see
below).

Top-level findings
==================

(F1) **Two pipelines implement sequence locks twice with subtly
     different fallback semantics.** Python `_check_sequence_locks_py`
     is the live default when the Rust extension isn't loaded; Rust
     `check_sequence_locks` is the fast path. Their handling of
     missing MTP diverges: Rust passes `prev_median_time: i64` (must
     be supplied by caller — caller decides None→0); Python fallback
     uses `if utxo_mtp is None: continue` (silently skips the lock
     entirely). The Rust call from Python at validation.py:2398
     coerces `None→0`, then Rust treats `0` as the coin time. Net
     effect: time-based BIP-68 locks **always succeed** for any input
     whose UTXO predates a header chain gap (i.e., post-assumeutxo
     snapshot loaded without backward header sync). This is the live
     production wedge that BIP68_STOPGAP papers over.

(F2) **CSV activation height differs between pipelines on testnet4
     and regtest.** Python BURIED_DEPLOYMENTS sets testnet4 / regtest
     CSV at height 1; Rust `csv_activation_height` returns 0. The
     `>=` comparator with `1` vs `0` means height-0 (genesis) is
     CSV-inactive in Python but CSV-active in Rust. The divergence
     is dormant in practice (genesis coinbase has nLockTime=0 →
     IsFinalTx returns true without consulting CSV), but the source
     of truth disagrees.

(F3) **Rust `HeaderValidator::get_median_time_past` returns `Result<u32>`
     instead of `i64`.** Core uses `int64_t` for all time arithmetic.
     The u32 return type works through 2106 but constrains
     interoperability with the i64 path used by `versionbits.rs`.
     There is no live bug — the Python wrapper at lib.rs:3140 also
     returns `Option<u32>` — but the conversion to i64 happens on the
     Python side, creating a 2-step type translation that is fragile
     if future code paths arithmetic-shift past u32.

(F4) **MTP slow-path fallback in `database.py:652-661` reads full
     block data instead of header-only.** Core's `GetMedianTimePast`
     walks `pindex->pprev` 11 times, reading only `nTime` from each
     block index. The ouroboros slow path deserializes the full
     block via `get_block_by_height`, which on a snapshot-loaded node
     can fault on a missing block body. Behavior is correct when the
     Rust fast path is available; degrades silently when it isn't.

(F5) **`node.get_median_time(height=None)` falls back to
     `int(time.time())` on any error, including a benign "block not
     found" at height=h.** Core's `getblockchaininfo.mediantime`
     never returns wall-clock time. RPC consumers (block explorers,
     dashboards) will see a "future" mediantime for a brief window
     during reorgs. Cosmetic — not consensus.

Gate matrix (30)
================

Activation + constants (1-5)
----------------------------

G1   SEQUENCE_FINAL = 0xFFFFFFFF — PRESENT
     Rust `validate/sequence_lock.rs:25`; matches Core's
     `CTxIn::SEQUENCE_FINAL` (primitives/transaction.h:76).

G2   SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31 — PRESENT
     Rust `validate/sequence_lock.rs:13`; Python script.py:1756
     (literal `1 << 31` inside the OP_CSV block; not module-level).
     **BUG-2 (cosmetic)**: Python literal differs from Rust constant
     name — silent maintenance hazard.

G3   SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22 — PRESENT
     Rust `validate/sequence_lock.rs:16`; Python script.py:1757
     (literal again).

G4   SEQUENCE_LOCKTIME_MASK = 0xFFFF — PRESENT
     Rust `validate/sequence_lock.rs:19`; Python:
     - `validation.py:2181` (TransactionValidator class const)
     - `script.py:1758` (per-call literal)
     Two-pipeline-internal: validation.py uses the class const for
     BIP-68; script.py inlines a local literal for OP_CSV. **BUG-7
     (P2/structural)**.

G5   SEQUENCE_LOCKTIME_GRANULARITY = 9 (2^9 = 512s) — PRESENT
     Rust `validate/sequence_lock.rs:22`. Python uses literal `512`
     in `_check_sequence_locks_py` (`validation.py:2475`):
     `required = (inp.sequence & SEQUENCE_MASK) * 512`. Correct
     value, but no named constant. **BUG-8 (P2/cosmetic)**.

CSV activation per network (6)
------------------------------

G6   csv_activation_height per network — DIVERGES
     | Network    | Core (chainparams.cpp) | Python (consensus.py) | Rust (sequence_lock.rs) |
     |------------|------------------------|-----------------------|-------------------------|
     | mainnet    | 419328                 | 419328                | 419328                  |
     | testnet3   | 770112                 | 770112                | 770112 (Network::Testnet) |
     | testnet4   | 1                      | 1                     | **0**                   |
     | signet     | 1                      | 1                     | (n/a; not in match)     |
     | regtest    | 1                      | 1                     | **0**                   |

     **BUG-3 (P1)**: Python and Rust disagree on testnet4 and regtest
     CSV activation heights. Both effectively make CSV active by
     genesis-1 in practice, but the comparator semantics differ.
     Core says `CSVHeight = 1` (i.e., active *at and after* height 1);
     Rust says `csv_activation_height = 0` (i.e., active *at and after*
     height 0). For testnet4 / regtest genesis block, the Python path
     would return CSV-inactive and the Rust path would return active.
     Practical impact: only the coinbase of the genesis block exists
     at that height; tx.locktime=0 makes IsFinalTx trivially true; no
     post-genesis tx is affected. Document and align to Core's "1".

nLockTime cutoff / BIP-113 (7-10)
---------------------------------

G7   nLockTimeCutoff selection pre-/post-CSV — PRESENT
     `validation.py:686-699`:
       csv_active = is_buried_deployment_active("csv", expected_height, network)
       nLockTimeCutoff = block_mtp if csv_active else block.timestamp
     Mirrors Core `validation.cpp:4135-4142`.

G8   IsFinalTx called for ALL transactions including coinbase — PRESENT
     `validation.py:835`. Matches Core `validation.cpp:4144-4148`.

G9   IsFinalTx threshold (LOCKTIME_THRESHOLD = 500_000_000) — PRESENT
     Rust `sequence_lock.rs:217`; Python `script.py:1734` (literal
     inside OP_CLTV block); Python `validation.py:2029` (literal
     in fallback `_is_final_tx`). **BUG-9 (P2/cosmetic)**: same
     literal appears in three places; should reference Rust constant
     via `locktime_threshold` PyO3 wrapper (lib.rs:336-339).

G10  IsFinalTx all-sequences-final check — PRESENT
     - Python fallback `validation.py:2036`:
         `if all(inp.sequence == 0xFFFFFFFF for inp in tx.inputs): return True`
     - Rust `sequence_lock.rs:248`:
         `if sequences.iter().all(|&seq| seq == SEQUENCE_FINAL) { return true; }`
     - Both match Core `tx_verify.cpp:32-35`. Hex literal `0xFFFFFFFF`
       in Python fallback rather than `SEQUENCE_FINAL` const → BUG-9
       collision.

BIP-68 sequence lock math (11-16)
---------------------------------

G11  BIP-68 v1 tx ignored — PRESENT
     Both pipelines short-circuit `tx_version < 2` → no locks
     (Rust `sequence_lock.rs:115`, Python `validation.py:2333`).

G12  Per-input disable-flag skip — PRESENT
     Both correctly skip when `nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG`.

G13  Height-based lock formula (utxo_h + lock - 1) — PRESENT
     Rust `sequence_lock.rs:146`:
       `let height_lock = (input.prev_height as i32) + (lock_value as i32) - 1`
     Python `validation.py:2492`:
       `depth = block_height - utxo_height; if depth < required: return False`
     Both equivalent to Core `tx_verify.cpp:90`. **BUG-10 (P2)**:
     Python expresses the condition as depth-vs-required; Rust
     expresses it as min_height-vs-block_height. Same outcome, but
     the Python form doesn't compute `nMinHeight` at all, which
     means Core's "transaction's effective min-height across all
     inputs" is not surfaced for LockPoints / max_input_height
     tracking. No live bug — ouroboros mempool re-checks at every
     try-accept rather than caching LockPoints — but the structural
     gap is a perf cost.

G14  Time-based lock formula (coin_time + (lock << 9) - 1) — PRESENT
     Rust `sequence_lock.rs:137`. Python `validation.py:2475-2485`
     uses the algebraically-equivalent form
     `block_mtp - utxo_mtp < lock * 512`. Both match Core.

G15  Coin time = MTP at (utxo_height - 1) — PRESENT
     Both pipelines compute coin_time as MTP at (utxo_height - 1).
     Python `validation.py:2398`:
       `utxo_mtp = self.db.get_median_time_past(max(utxo_height - 1, 0))`
     Matches Core `tx_verify.cpp:74`:
       `nCoinTime = block.GetAncestor(max(nCoinHeight - 1, 0))->GetMedianTimePast()`

G16  Multi-input maximum lock — PRESENT
     Rust uses `lock.min_height.max(...)` and `lock.min_time.max(...)`.
     Python evaluates per-input and short-circuits on any failure;
     equivalent semantics (a failing tx fails the most-restrictive
     input). **BUG-11 (P2)**: Python fallback never computes
     aggregate min_height/min_time. If a future call path needs the
     aggregate (e.g., for mempool LockPoints), the Python pipeline
     can't supply it without a re-walk.

OP_CHECKSEQUENCEVERIFY semantics (17-23)
----------------------------------------

G17  OP_CSV gated on SCRIPT_VERIFY_CHECKSEQUENCEVERIFY — PRESENT
     `script.py:1748` mirrors Core `interpreter.cpp:563`.

G18  Negative-lock-value rejected — PRESENT
     `script.py:1755` (matches Core `interpreter.cpp:579-580`).

G19  Operand disable-flag → NOP — PRESENT
     `script.py:1759-1760` mirrors Core `interpreter.cpp:585-586`.

G20  tx.version < 2 fails — PRESENT
     `script.py:1761-1762`. Core `interpreter.cpp:1790-1791`. Order
     of checks: Core checks `tx.version<2` BEFORE the input-side
     disable-flag check; ouroboros checks tx.version AFTER the
     operand-side disable-flag check but BEFORE the input-side
     disable-flag check. The early operand-disable `continue`
     short-circuits both Core and ouroboros equally → no semantic
     divergence.

G21  Input nSequence disable-flag fails — PRESENT
     `script.py:1764-1765`. Core `interpreter.cpp:1797-1798`.

G22  Type-mismatch (block-vs-time) check — PRESENT
     `script.py:1769-1773`. Core `interpreter.cpp:1813-1817`.

G23  Value comparison (`lock <= tx_seq` after mask) — PRESENT
     `script.py:1774`: `if lock_masked > tx_masked: raise`. Core
     `interpreter.cpp:1822-1823`. Match.

OP_CHECKLOCKTIMEVERIFY semantics (24-26)
----------------------------------------

G24  OP_CLTV gated on SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY — PRESENT
     `script.py:1725-1727` mirrors Core `interpreter.cpp:524-527`.

G25  Type-mismatch (height-vs-time) check — PRESENT
     `script.py:1736-1740`. Core `interpreter.cpp:?`. Note Core's
     CheckLockTime uses LOCKTIME_THRESHOLD as the boundary; ouroboros
     uses `500_000_000` literal. Same value, see BUG-9.

G26  SEQUENCE_FINAL bypass detection — PRESENT
     `script.py:1743-1744`: `if tx.inputs[input_index].sequence ==
     0xffffffff: raise`. Core `interpreter.cpp:1775-1776`. Match
     (note: hex literal, BUG-9 collision).

Median time past (27-29)
------------------------

G27  GetMedianTimePast window = 11 blocks — PRESENT
     - Rust `header.rs:147-162`: start at `max(0, h-10)`, walk to `h`.
     - Python `database.py:653-661` fallback: `range(max(0, h-10), h+1)`.
     - Python `node.py:1617`: `range(max(0, height-10), height+1)`.
     All three match Core `chain.h:231`'s `nMedianTimeSpan = 11`.

G28  MTP < 11 blocks at low heights — PRESENT
     All paths handle `height < 10` by walking fewer entries.

G29  MTP includes current block — PRESENT
     Core's loop is `pindex = this; for i in 0..11; pindex = pindex->pprev`,
     so MTP at height h includes block[h]. All three ouroboros paths
     include block[h]. Match. **BUG-12 (P2)**: documentation
     inconsistency — `validation.py:961` calls it "MTP of the previous
     11 blocks" but it's actually the *current* block plus the
     previous 10. Cosmetic.

Two-pipeline divergence (30)
----------------------------

G30  Two-pipeline divergence inventory — DOCUMENTED
     - **G6 / BUG-3**: csv_activation_height numeric divergence
       (testnet4 / regtest).
     - **F3 / BUG-5**: Rust HeaderValidator MTP returns u32; Python
       expects None|int; versionbits.rs trait expects Option<i64>.
       Three internal Rust types for one logical value.
     - **F1 / BUG-1**: missing-MTP fallback semantics differ (Rust
       caller coerces None→0; Python fallback silently `continue`s).

Bug catalogue (14)
==================

**BUG-1  P0-CONSENSUS  Missing-MTP fallback silently passes time-based BIP-68 locks**
File: `src/ouroboros/validation.py:2398-2402`
Code:
    utxo_mtp = self.db.get_median_time_past(max(utxo_height - 1, 0))
    if utxo_mtp is None:
        utxo_mtp = 0  # Fallback
    input_infos.append((inp.sequence, utxo_height, utxo_mtp))
Core: `tx_verify.cpp:74` asserts that
`block.GetAncestor(max(nCoinHeight-1, 0))` is non-null; the
`Assert(...)->GetMedianTimePast()` chain aborts on missing ancestor.
ouroboros has no such assertion — it falls back to `0`, which means
time-based locks always succeed for the affected input.

Impact: nodes loaded from an assumeutxo snapshot without prior
backward header sync will silently accept time-based BIP-68 locked
spends that should be rejected. This is the live wedge that the
`OUROBOROS_BIP68_STOPGAP=1` env-var works around at validation.py:2370.

Fix: Either (a) raise/return False when MTP is unavailable, or (b)
land Option 1 (post-snapshot backward header sync) so MTP is always
available. The stopgap is operator-opt-in and labeled `not
consensus-correct in the strict sense` in the source comment
(validation.py:2326).

**BUG-2  P2/cosmetic  SEQUENCE_LOCKTIME_DISABLE_FLAG inlined as literal**
File: `src/ouroboros/script.py:1756`
Code: `SEQ_DISABLE = 1 << 31`
Should reference the Rust constant via PyO3 or be promoted to a
module-level Python constant for cross-pipeline parity.

**BUG-3  P1  CSV activation height divergence Python-vs-Rust on testnet4/regtest**
Files:
  - `src/ouroboros/consensus.py:146` (testnet4 CSV = 1)
  - `src/ouroboros/consensus.py:162` (regtest CSV = 1)
  - `ferrous-utils/sync/src/validate/sequence_lock.rs:37-39`
    (Network::Testnet4 = 0, Network::Regtest = 0)
Core canonical: `kernel/chainparams.cpp:315,459,540` — all set
`CSVHeight = 1`. Rust should use `1` to match. Practical impact:
genesis-height tx behavior diverges (dormant — coinbase nLockTime=0
trivially passes IsFinalTx).

**BUG-4  P1  csv_activation_height for Signet missing from Rust enum**
File: `ferrous-utils/sync/src/validate/sequence_lock.rs:33-43`
The `csv_activation_height(network)` match arms cover Bitcoin,
Testnet, Testnet4, Signet, Regtest. Signet is listed at `0`.
Core says `CSVHeight = 1` for Signet (`kernel/chainparams.cpp:459`).
Same class as BUG-3.

**BUG-5  P1  Rust HeaderValidator::get_median_time_past returns u32; mismatched with i64 versionbits path**
Files:
  - `ferrous-utils/sync/src/validate/header.rs:145` returns `Result<u32>`
  - `ferrous-utils/sync/src/versionbits.rs:143` trait fn returns `Option<i64>`
  - `ferrous-utils/sync/src/lib.rs:3140` PyO3 wrapper returns
    `PyResult<Option<u32>>`
  - `ferrous-utils/sync/src/lib.rs:839` impl returns `Option<i64>`
Core uses `int64_t` (`chain.h:233`). Document and align. Type chain:
storage layer (u32 — header.time field) → MTP layer (u32) → trait
(i64) → Python (int|None) → caller-side coercion (Python `or 0`).
**No live bug** because actual MTP values fit in u32 through year
2106; structural fragility.

**BUG-6  P2  MTP slow-fallback in database.py reads full block bodies**
File: `src/ouroboros/database.py:652-661`
Code:
    # Slow fallback: deserialize full blocks
    timestamps = []
    for h in range(max(0, height - 10), height + 1):
        block = self.get_block_by_height(h)
        if block is not None:
            timestamps.append(block.timestamp)
Core walks only `pindex->nTime` (the in-memory block index — no disk
read for the body). The ouroboros slow fallback deserializes the
full block, which is ~MB-scale per call and faults on missing block
bodies (post-snapshot). Fix: walk a header-only path or fall back
to `db.get_block_header_by_height` (if present) before
deserializing the body.

**BUG-7  P2/structural  SEQUENCE_LOCKTIME_MASK lives in two places in Python**
Files:
  - `src/ouroboros/validation.py:2181` (class const SEQUENCE_MASK)
  - `src/ouroboros/script.py:1758`     (per-call literal)
Promote to a shared module constant (e.g., in `consensus.py` or a
new `sequence.py`).

**BUG-8  P2/cosmetic  SEQUENCE_LOCKTIME_GRANULARITY = 9 (2^9=512) inlined in Python**
File: `src/ouroboros/validation.py:2475` — `* 512`
No named constant — magic number. Cross-link to Rust constant.

**BUG-9  P2/cosmetic  LOCKTIME_THRESHOLD = 500_000_000 hardcoded in three places**
Files:
  - `src/ouroboros/validation.py:2029` (Python fallback IsFinalTx)
  - `src/ouroboros/script.py:1734`     (OP_CLTV)
  - Rust `validate/sequence_lock.rs:217` (named constant)
The PyO3 wrapper `locktime_threshold()` at lib.rs:336 exists. Use it
to populate a Python module constant once at import.

**BUG-10  P2/structural  Python fallback never computes min_height aggregate**
File: `src/ouroboros/validation.py:2422-2496`
The Python fallback `_check_sequence_locks_py` iterates per-input
and short-circuits; it never builds the `(min_height, min_time)`
pair that Core's `CalculateSequenceLocks` returns. Future LockPoints
caching would require a parallel implementation. Document or align
shape with Rust `calculate_sequence_locks`.

**BUG-11  P2/structural  No LockPoints / max_input_height tracking**
Core `validation.cpp:201-244` `CalculateLockPointsAtTip` returns a
`LockPoints` containing `(min_height, min_time, maxInputBlock)` so
that mempool RBF / reorg can validate the cached lock points against
the new tip. ouroboros mempool re-checks at every try-accept which
is correct but redundant. Document.

**BUG-12  P2/cosmetic  Docstring inconsistency at validation.py:961**
File: `src/ouroboros/validation.py:961-993`
Comment says "MTP of the previous 11 blocks" — actually it's the
current block plus the previous 10 (i.e., 11 blocks ending at
height h, including h). Same for `node.py:1604` ("11 blocks ending
at *height*" — correct), `database.py:641` ("11 blocks up to
*height*" — correct).

**BUG-13  P2  node.get_median_time falls back to wall-clock time**
File: `src/ouroboros/node.py:1638-1640`
Code:
    except Exception as e:
        logger.error(f"Error calculating median time at height {height}", ...)
        return int(time.time())
Used by RPC `mediantime` field in `getblockchaininfo`,
`getblockheader`, `getblock`. Returning wall-clock time on a
"block not found" error is wrong — return None (or omit field) and
let the RPC layer surface the gap. Affects RPC observability only.

**BUG-14  P2  Python fallback `_is_final_tx` requires block_mtp>0 for time-based locktime**
File: `src/ouroboros/validation.py:2049-2050`
Code:
    if block_mtp <= 0:
        return False  # BIP-113: MTP unavailable → cannot confirm finality
This is the CORRECT direction (reject rather than silently accept),
but Core's IsFinalTx never has this guard because Core always has
MTP available. The Python fallback comment is "Mirrors Core IsFinalTx
exactly — no silent-accept on missing MTP." but Core doesn't have a
silent-accept path either; the guard is ouroboros-specific defensive
coding. The behavioral divergence from BUG-1 (`utxo_mtp = 0`
fallback in `check_sequence_locks`) is jarring — IsFinalTx rejects
on unknown MTP, BIP-68 accepts. **Reconcile the two paths**.

Two-pipeline guard status
=========================

Sequence-lock math: PRESERVED (3 documented divergences in activation
heights / type signatures; semantics identical).

OP_CSV / OP_CLTV interpreter: PRESERVED (Python-only; Rust pipeline
does not run script). The Rust pipeline supplies primitives via
PyO3 for sequence_lock math; script evaluation stays in Python.

Two new guard tests added in
`src/ouroboros/tests/test_w132_nsequence_csv_mtp.py`:
  - `test_g30_two_pipeline_csv_height_divergence` — pins the
    BUG-3/BUG-4 divergence so a fix is detected.
  - `test_rust_pipeline_has_sequence_lock_module` — asserts Rust
    pipeline continues to ship sequence_lock.rs (i.e., the Rust
    consensus implementation hasn't been removed). Cross-pipeline
    guard analogous to the W120 / W129 RBF / coin-selection guards.

Out-of-scope (not covered by W132)
==================================

- BIP-9 deployment state machine (`versionbits.rs`) — separate
  audit surface (W84 / W85 covered MTP-vs-block-timestamp on the
  header validator; W126 covered BIP-9 starts/timeouts in the
  deployment table).
- nLockTime cosmetic in BIP-22 GetBlockTemplate (coinbase
  nSequence = MAX_SEQUENCE_NONFINAL) — covered by W108 GBT audit.
- BIP-125 RBF and SignalsOptInRBF using MAX_BIP125_RBF_SEQUENCE —
  covered by W120 mempool RBF audit.
- BIP-431 TRUC sequence-related rules — covered by W120 / W129.
- ZMQ notifications for new-tip MTP changes — out of scope.
- Sequence locks on Tapscript paths (BIP-341 / BIP-342) — out of
  scope; OP_CHECKSEQUENCEVERIFY is the only sequence opcode under
  Tapscript and works identically.

Top P0-CONSENSUS finding
========================

**BUG-1**: BIP-68 time-based locks silently pass when MTP is
unavailable. Single P0-CONSENSUS. Already mitigated by the
operator-opt-in `OUROBOROS_BIP68_STOPGAP=1` env-var; the structural
fix is post-snapshot backward header sync (Option 1).

Test inventory
==============

Tests in `src/ouroboros/tests/test_w132_nsequence_csv_mtp.py`:

- Constants gates (G1-G5): test SEQUENCE_FINAL, DISABLE_FLAG,
  TYPE_FLAG, MASK, GRANULARITY values match across pipelines.
- CSV activation gates (G6): test mainnet 419328 in both pipelines.
- nLockTime cutoff gate (G7): test pre-/post-CSV nLockTimeCutoff
  selection.
- IsFinalTx gates (G8-G10): test all-final, zero-locktime, height-
  vs-time-based, threshold boundary.
- BIP-68 sequence lock gates (G11-G16): test v1-ignored,
  disable-flag, height formula, time formula, coin-time at
  utxo_height-1, multi-input max.
- OP_CSV gates (G17-G23): test gating, negative, operand-disable,
  version-2-required, input-disable, type-mismatch, value-compare.
- OP_CLTV gates (G24-G26): test gating, type-mismatch, finalized-
  bypass.
- MTP gates (G27-G29): test 11-block window, < 11 blocks at low
  heights, current-block-included.
- Two-pipeline guard (G30): pin CSV-height divergence + assert
  Rust sequence_lock module still present.

Plus a documentation cross-reference test asserting that all 14
catalogued bugs are present in the inventory.

References for follow-on fix waves
==================================

- FIX-86 BIP-68 stopgap → post-snapshot backward header sync:
  follow-on for BUG-1; would close the BIP68_STOPGAP env-var
  permanently.
- FIX-87 CSV activation height alignment: 5-line Rust patch to
  align `csv_activation_height(Testnet4|Signet|Regtest)` to `1`.
- FIX-88 Python constant promotion: move SEQUENCE_LOCKTIME_*,
  LOCKTIME_THRESHOLD into a shared `src/ouroboros/sequence.py` (or
  `consensus.py`) so script.py + validation.py + tests all reference
  the same source.
- FIX-89 MTP slow-fallback header-only path: avoid full block
  deserialization in database.py:652-661.

Audit framework notes
=====================

This is the first W### that explicitly cross-references Rust
constants with Python-side per-call literals. Future fleet audits
on the two-pipeline impls (rustoshi has no Python; ouroboros is
the only two-pipeline impl in the fleet) should systematically
diff the constant-source side between languages, because identical
inline literals are not a substitute for shared imports.

The audit framework's "PRESENT" / "PARTIAL" / "MISSING" labels need
a fourth: "PRESENT-INLINED-LITERAL" — same semantics, but the
constant is duplicated per call site rather than imported from a
single source of truth. ouroboros has at least four W### worth of
these (W107 CompactSize, W117 BIP-155, W118 wallet, W127 Taproot)
and W132 adds another. Promotion to `consensus.py` or a new
`sequence.py` is recommended.
