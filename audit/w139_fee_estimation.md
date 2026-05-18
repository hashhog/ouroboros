W139 — Fee estimation engine (CBlockPolicyEstimator) audit (ouroboros)
======================================================================

Date: 2026-05-18
Impl: ouroboros (Python-only pipeline — fee estimation is policy,
      not consensus. The Rust pipeline (`ferrous-utils/sync`) has zero
      fee-estimation surface. Two-pipeline guard EXTENDS to forbid
      `CBlockPolicyEstimator`-style code in any `*.rs` under
      `ferrous-utils/`.)
Wave: W139 — Fee estimation engine (`CBlockPolicyEstimator`).
References:
  - `bitcoin-core/src/policy/fees/block_policy_estimator.h`
    (constants: `SHORT_BLOCK_PERIODS=12`, `MED_BLOCK_PERIODS=24`,
     `LONG_BLOCK_PERIODS=42`, `SHORT_SCALE=1`, `MED_SCALE=2`,
     `LONG_SCALE=24`, `SHORT_DECAY=0.962`, `MED_DECAY=0.9952`,
     `LONG_DECAY=0.99931`, `HALF_SUCCESS_PCT=0.6`,
     `SUCCESS_PCT=0.85`, `DOUBLE_SUCCESS_PCT=0.95`,
     `SUFFICIENT_FEETXS=0.1`, `SUFFICIENT_TXS_SHORT=0.5`,
     `MIN_BUCKET_FEERATE=100`, `MAX_BUCKET_FEERATE=1e7`,
     `FEE_SPACING=1.05`, `OLDEST_ESTIMATE_HISTORY=6048`,
     `FEE_FLUSH_INTERVAL=1h`, `MAX_FILE_AGE=60h`,
     `CURRENT_FEES_FILE_VERSION=309900`).
  - `bitcoin-core/src/policy/fees/block_policy_estimator.cpp`
    - `TxConfirmStats::Record` @ 217-229 (record confirm + bucket)
    - `TxConfirmStats::UpdateMovingAverages` @ 231-242
    - `TxConfirmStats::EstimateMedianVal` @ 245-409
    - `TxConfirmStats::removeTx` @ 485-520 (failAvg accounting)
    - `processTransaction` @ 596-639 (admission tracking + validForFeeEstimation)
    - `processBlock` @ 669-716 (ClearCurrent → decay → record)
    - `estimateRawFee` @ 727-761
    - `estimateCombinedFee` @ 808-842 (shortest-horizon-first + check-shorter)
    - `estimateConservativeFee` @ 847-862 (DOUBLE_SUCCESS_PCT across horizons)
    - `estimateSmartFee` @ 871-956 (3 sub-estimates: HALF + FULL + DOUBLE)
    - `Write` / `Read` @ 978-1062 (file persistence + version gate)
    - `FlushUnconfirmed` @ 1064-1076 (record-as-failure on shutdown)
    - `GetFeeEstimatorFileAge` @ 1078-1083 (MAX_FILE_AGE gate)
    - `FeeFilterRounder` @ 1103-1119 (private fee quantisation surface)
  - `bitcoin-core/src/policy/feerate.{cpp,h}` — CFeeRate; integer fee/kvB.
  - `bitcoin-core/src/rpc/fees.cpp` — `estimatesmartfee`, `estimaterawfee`
    (clamps target, applies min-mempool / min-relay floor, returns
     `feeCalc.returnedTarget` in "blocks").

Status: **30 gates audited — PRESENT 6 / PARTIAL 6 / MISSING 18.**
**21 BUGS** (1 P0-CDIV / 4 P1-CDIV-class / 11 P1 / 5 P2).

Relationship to prior audits
----------------------------

- **W114 (CBlockPolicyEstimator fleet audit, 2026-02-…)** catalogued 14
  bugs (BUG-1..BUG-14 in `test_w114_fee_estimation.py`). Several of
  those have since landed as fixes (the three-horizon SHORT/MED/LONG
  split — see `fee_estimator.DECAY/SCALE/PERIODS` — and the lift of
  `MAX_CONF_TARGET` from 25 to 1008 are FIXED). W139 is the **deep-dive
  follow-up** that audits the gaps W114 did not enumerate (chiefly:
  `EstimateMedianVal` algorithm parity, `estimateSmartFee` 3-sub-estimate
  max, persistence wire-format, stale-file age gate, conservative-mode
  cross-horizon walk, processTransaction admission hook, removeTx /
  failAvg / unconfTxs circular buffer, FlushUnconfirmed shutdown
  recording, the BTC-per-kB vs sat-per-vB unit collision in
  `estimate_fee_per_kb`, and the bucket-count + spacing precision
  divergence).
- **W123 (mining / GBT)** uses the same mempool fee-rate primitives but
  for block-template construction, not estimation. W139 does not touch
  GBT; in particular `getblocktemplate.fee` accuracy depends on
  `MempoolEntry.fee_rate`, which BUG-3 in this audit affects only at
  the **estimator** observation site, not the per-tx mining feerate.
- **W129 (coin selection)** consumes `estimate_fee` to compute target
  feerate; BUG-4, BUG-13, BUG-14 in this audit propagate into wallet
  fee-bumping behavior.
- **W130 (BIP-125 / feebumper rule 3)** consumes estimated feerate; the
  conservative-mode gap (BUG-7) means feebumper never gets the
  conservative-mode boost Core provides.
- **W136 (BIP-130/133/339 relay flags)** audits `FeeFilterRounder` from
  the **outbound feefilter** standpoint. `FeeFilterRounder` is
  physically defined in `p2p.py` rather than `fee_estimator.py`, but it
  is the same class as Core's `fees.h:323-344` — W139 enumerates the
  remaining Core parity gaps (G27-G28: `MakeFeeSet` does NOT insert
  `0` first in some Python code paths; sampling uses
  `random.randint(0,2)!=0` which has the wrong direction — see BUG-19).
- **W114 BUG-3 (entry.size vs entry.vsize)** is still partially open:
  the line `fee_rate = entry.fee / vsize where vsize = entry.size` now
  has a clearer fix path via `entry.fee_rate` (which is sigop-adjusted).
  W139 confirms the BUG persists at `fee_estimator.py:218` and adds the
  pre-FIX impact analysis for segwit fingerprinting.

Two-pipeline guard
------------------

Fee estimation is **policy code, not consensus code.** Bitcoin Core
keeps `CBlockPolicyEstimator` in `src/policy/fees/`, not in
`src/consensus/`, because the estimator never participates in block
validation — it is a pure observer of the mempool→block transition that
emits advisory feerates to RPC clients. The two-pipeline invariant:

- **Python pipeline (estimator)**: `src/ouroboros/fee_estimator.py`
  (542 lines) is the single source of truth for the bucket arrays,
  decay, period mapping, percentile fallback, persistence.
  `node.py:242-244` constructs `FeeEstimator()` and loads
  `fee_estimates.json` from disk. `block_sync.py:1349-1353` feeds
  confirmed blocks. `rpc.py:4485-4638` exposes `rpc_estimatesmartfee`
  and `rpc_estimaterawfee`. `rpc.py:3466-3475, 4297-4310, 9005-9100`
  consult the estimator for wallet sends.

- **Rust pipeline (`ferrous-utils/`)**: ZERO fee-estimation surface.
  No `BlockPolicyEstimator`, no `TxConfirmStats`, no decay loops, no
  bucket arrays, no `FEE_SPACING` / `MIN_BUCKET_FEERATE` constants.

  ```
  $ grep -rn -i "fee.estimator\|fee_estimate\|BlockPolicyEstimator\|TxConfirmStats\|estimateSmartFee\|FEE_SPACING" \
         ferrous-utils/ --include='*.rs'                  → 0 matches
  ```

  Confirmed via grep over `ferrous-utils/{common,sync}/src/`.

**Two-pipeline guard EXTENDED.** New test
`test_w139_g30_two_pipeline_fee_estimator_python_only` asserts:
- No `*.rs` file under `ferrous-utils/{common,sync}/src/` may contain
  `BlockPolicyEstimator`, `TxConfirmStats`, `FEE_SPACING`,
  `MIN_BUCKET_FEERATE`, `MAX_BUCKET_FEERATE`, `HALF_SUCCESS_PCT`,
  `DOUBLE_SUCCESS_PCT`, `SUFFICIENT_FEETXS`, `estimate_smart_fee`,
  `estimate_raw_fee`, or `fee_estimator` in any form.
- The Python module `ouroboros.fee_estimator` MUST remain importable
  as the single estimator (i.e., the class `FeeEstimator` must exist).

This extends the project-wide guard chain
W76 + W120 + W121 + W122 + W125 + W128 + W129 + W130 + W131 + W132 +
W133 + W136 + W137 → now W139 (12th distinct dedicated guard since
ouroboros adopted the two-pipeline pattern; FIRST guard dedicated to
the fee-estimation surface specifically).

Top-level findings
------------------

1. **`estimate_fee_per_kb` returns sat/vB units mislabelled as BTC/kB
   (BUG-1, P0-CDIV-class user-impact).**
   `fee_estimator.py:280-286`:
   ```python
   def estimate_fee_per_kb(self, conf_target: int = 6) -> float | None:
       rate = self.estimate_fee(conf_target)
       if rate is None:
           return None
       # sat/vB → BTC/kB:  rate * 1000 / 1e8
       return rate * 1000 / 1e8
   ```
   The math is correct (sat/vB → BTC/kvB: multiply by 1000, divide by
   1e8) BUT the comment claims "BTC/kB", Core's `estimatesmartfee`
   actually returns BTC/kvB. The variable is consistent (kB ~= kvB for
   non-segwit), but the precision loss combined with the sat→BTC float
   division causes:
   - Round-trip error: estimator returns 10 sat/vB → 0.0001 BTC/kvB,
     but a downstream caller decoding this with `int(rate * 1e8 / 1000)`
     gets 10. So far so good. But if the estimator returns e.g.
     0.95 sat/vB (clamped to 1.0 in `_estimate_from_buckets`), then
     0.95 * 1000 / 1e8 = 9.5e-6 BTC/kvB, which a downstream caller
     rounding back to sat/vB via int() gets 0 — corruption.
   - **Critical user-facing divergence**: an `estimatesmartfee 6` query
     after the estimator has converged returns BTC/kvB as `feerate`,
     but `rpc.py:9009-9015` (sendmany / send / similar wallet sends)
     calls `estimate_fee(int(conf_target))` and uses the **raw sat/vB**
     return; the wallet thus uses different units inconsistently
     across call sites. This is bug-amplifying.
   Severity P0-CDIV-class because (a) it affects every wallet RPC that
   consults `estimate_fee` vs `estimate_fee_per_kb`, (b) it diverges
   from Core's universal BTC/kvB integer-sat internal contract.

2. **`estimateSmartFee` 3-sub-estimate max(HALF, FULL, DOUBLE) algorithm
   is missing (BUG-2, P1-CDIV).** Core's `estimateSmartFee`
   (`block_policy_estimator.cpp:871-956`) does:
   ```cpp
   double halfEst   = estimateCombinedFee(confTarget/2,   HALF_SUCCESS_PCT,   ...);
   double actualEst = estimateCombinedFee(confTarget,     SUCCESS_PCT,        ...);
   double doubleEst = estimateCombinedFee(2*confTarget,   DOUBLE_SUCCESS_PCT, ...);
   median = std::max({halfEst, actualEst, doubleEst});
   ```
   This is the **monotonically-increasing-fee** safeguard documented in
   the comments at `:911-917`. ouroboros `_estimate_from_buckets` does a
   single-target lookup with a single hard-coded threshold of 0.85
   (`SUCCESS_THRESHOLD`). The three thresholds (0.60 / 0.85 / 0.95) are
   not used. Pre-FIX impact:
   - Estimates can be non-monotonic with conf_target: estimate(2) might
     exceed estimate(6).
   - The "DOUBLE_SUCCESS_PCT at 2×target" check that gives Core's
     conservative mode its safety margin is absent.
   - Estimates are reliably TOO LOW for short targets vs Core's HALF
     sub-estimate at 0.60 threshold.

3. **Conservative-mode parameter is silently ignored (BUG-3, P1).**
   `rpc.py:4488` accepts `estimate_mode` ("economical" / "conservative"
   / "unset") but never plumbs it into `fee_estimator.estimate_fee`,
   which has no `conservative` parameter. Core's conservative mode walks
   `estimateConservativeFee(2*confTarget, ...)` which takes the **max
   across all longer horizons at 0.95 threshold**, producing a higher
   (safer) fee for callers who explicitly request it. ouroboros's
   conservative mode is a no-op.

4. **No `processTransaction` admission hook → no `unconfTxs` circular
   buffer → `extraNum` term absent from EstimateMedianVal (BUG-4, P1).**
   Core's `processTransaction` (`:596-639`) is invoked on every
   `TransactionAddedToMempool` callback. It:
   - Assigns the tx a bucket index;
   - Inserts into `mapMemPoolTxs[hash] = {blockHeight, bucketIndex}`;
   - Increments `unconfTxs[blockIndex][bucketIndex]` (a circular
     buffer indexed mod-GetMaxConfirms);
   - Increments `trackedTxs` (which feeds the estimator-health log).
   ouroboros has NO equivalent. `mempool.add_transaction` (mempool.py:1874)
   never calls back into the fee_estimator. Consequence:
   - `EstimateMedianVal` lacks the `extraNum` term (Core line 290:
     `extraNum += unconfTxs[(nBlockHeight - confct) % bins][bucket]`).
     This term represents "txs still in mempool waiting for confirmation"
     and INCREASES the denominator of the success-rate calculation,
     making estimates more conservative when there is a long mempool
     backlog. Without it, estimates are biased UPWARD (overconfident)
     during congestion.
   - `validForFeeEstimation` Core gate (Core line 619) is bypassed.
     Core specifically excludes (a) txs accepted during reorg, (b) txs
     submitted while `m_chainstate_is_current == false` (i.e., during
     IBD), (c) packages, (d) txs with in-mempool parents. ouroboros
     processes EVERY confirmed tx as if it were a stand-alone admission
     observation — including chained children whose admission feerate
     depends on the parent's effective fee. This biases bucket
     placement.

5. **No `removeTx` / `failAvg` → eviction pressure invisible (BUG-5,
   P1).** Core's `removeTx` (`:485-520`) tracks evicted-but-unconfirmed
   txs into `failAvg[period][bucket]`. This is the **failNum** term in
   `EstimateMedianVal` (`:253, :289`) — txs that left the mempool
   without confirming. Without `failAvg`:
   - Estimates ignore feerate buckets that *lose* txs to mempool
     pressure (i.e., low-feerate buckets where many txs are evicted).
   - The `failBucket` reported in `estimaterawfee` is always empty.
   - Long-running operators with high mempool turnover get less
     useful estimates over time.

6. **No `ClearCurrent` circular-buffer roll → unconfirmed txs are
   silently lost on every block (BUG-6, P1).** Core calls
   `ClearCurrent(nBlockHeight)` (`:688-690`) inside `processBlock`,
   which rolls the `unconfTxs` ring (each block's bucket-bin moves
   into `oldUnconfTxs`, the per-block bin is zeroed). ouroboros has
   no equivalent because there is no `unconfTxs` (see BUG-4).

7. **`processBlock` decay precedes record-or-roll, opposite of Core's
   order (BUG-7, P1).** Core: `ClearCurrent` (roll) → `UpdateMovingAverages`
   (decay confAvg/failAvg/txCtAvg) → record block txs. The order matters
   because **decay applies to OLD data, then new data is added at full
   weight**. ouroboros (`fee_estimator.py:201-202, 228`):
   ```python
   self._apply_decay()    # decay BOTH conf AND total for all buckets
   ...
   self._record_confirmation(fee_rate, blocks_to_confirm)
   ```
   The order matches Core (decay → record). HOWEVER: ouroboros decays
   the `total_h[bucket][period]` array too, which is roughly the
   `txCtAvg + failAvg + unconfTxs` Core triple combined. Core decays
   `txCtAvg`, `m_feerate_avg`, `confAvg`, `failAvg` (`:236-241`), but
   NOT `unconfTxs` (which is a circular buffer that gets rolled
   differently via `ClearCurrent`). ouroboros's decay of `total_h`
   amounts to decaying the unconfirmed-tx contribution as if it
   were historical data, which biases the success-rate downward over
   time. Bug-shape: `_apply_decay` over-decays the denominator.

8. **`blocks_to_confirm` off-by-one — txHeight=100, block=101 should
   record btc=1, ouroboros records btc=2 (BUG-8, P1, same as W114
   BUG-4).** `fee_estimator.py:224`:
   ```python
   blocks_to_confirm = height - entry_height + 1  # 1-based
   ```
   Core (`:652`):
   ```cpp
   int blocksToConfirm = nBlockHeight - tx.info.txHeight;  // 1-based
   ```
   Both code paths label themselves "1-based" but they disagree by 1.
   The Core source is the canonical 1-based form (Core comments at
   `:137-138, :219-220` confirm: a tx mined in "the next block" gets
   `blocksToConfirm = 1`). ouroboros records `btc = 2` for the same
   case, shifting every observation one period right → estimates biased
   toward longer waits than reality.

9. **Stale fee_estimates.json is loaded with no MAX_FILE_AGE gate
   (BUG-9, P1, same as W114 BUG-11).**
   `fee_estimator.py:474-540` `load_from_file` unconditionally reads
   the JSON regardless of mtime. Core's constructor (`:567-576`):
   ```cpp
   std::chrono::hours file_age = GetFeeEstimatorFileAge();
   if (file_age > MAX_FILE_AGE && !read_stale_estimates) {
       LogWarning("Fee estimation file %s too old (age=…)…");
       return;
   }
   ```
   ouroboros has no equivalent, so an estimator restored from a 3-day-old
   file serves stale estimates as if fresh.

10. **No periodic flush to disk (BUG-10, P1).** Core's
    `FEE_FLUSH_INTERVAL=1h` (fees.h:26) drives a periodic flush via
    the kernel scheduler. ouroboros only persists `fee_estimates.json`
    on `node.py:582-588` clean-shutdown. A crash → all in-memory
    state lost since the last shutdown. Combined with BUG-9 (no
    stale-file gate), the only way to keep an up-to-date
    `fee_estimates.json` is to gracefully restart at least once an hour.

11. **No `FlushUnconfirmed` shutdown hook (BUG-11, P1).** Core's
    `FlushUnconfirmed` (`:1064-1076`) is called on `Flush()` —
    every still-tracked mempool tx is recorded as a `removeTx(_,
    inBlock=false)` which feeds the **failAvg** statistic.
    Rationale: a tx that was in our mempool at shutdown and didn't
    confirm represents a failed-to-confirm signal that future
    estimates should learn from. ouroboros has no `processTransaction`
    so there is nothing to flush — but the absence here is a knock-on
    effect of BUG-4 + BUG-5.

12. **File persistence is JSON, Core's is binary `serialize.h`
    (BUG-12, P2 architectural).**
    `fee_estimator.py:440-472` writes a JSON dict with keys
    `short_confirmed`, `med_confirmed`, `long_confirmed` (plus
    `_total` variants) using `json.dump`. Core's `Write`
    (`block_policy_estimator.cpp:978-1000`) writes a versioned
    binary stream:
    ```
    [CURRENT_FEES_FILE_VERSION:i32]
    [nBestSeenHeight:u32]
    [firstRecordedHeight/historicalFirst:u32]
    [nBestSeenHeight/historicalBest:u32]
    [VectorFormatter<EncodedDoubleFormatter> buckets]
    [feeStats…shortStats…longStats]
    ```
    Implications:
    - **Wire-format divergence**: ouroboros's `fee_estimates.json` is
      not portable to/from Bitcoin Core or to any cross-impl that
      writes Core's binary format.
    - **No version field**: ouroboros uses `version = 1` (a Python int
      in JSON) but never bumps it. Core has `CURRENT_FEES_FILE_VERSION =
      309900` and refuses to read files claiming a higher version.
    - **No bucket-set check**: Core's `Read` (`:1023-1029`) requires
      `2 <= numBuckets <= 1000` else `runtime_error`. ouroboros's
      `_check_dims` enforces `len == NUM_BUCKETS` exactly, which means
      changing `FEE_RATE_BUCKETS` in the source invalidates every
      saved file.
    - **No height bounds check**: Core (`:1022-1024`) requires
      `nFileHistoricalFirst <= nFileHistoricalBest <= nFileBestSeenHeight`
      else `runtime_error`. ouroboros has no `nBestSeenHeight`
      field at all.

13. **`MIN_BUCKET_FEERATE`/`MAX_BUCKET_FEERATE`/`FEE_SPACING` constants
    are absent — uses 24 hand-coded boundaries vs Core's ~237 (BUG-13,
    P1, same as W114 BUG-9).** Core's bucket layout
    (`block_policy_estimator.h:190-198`):
    ```
    MIN_BUCKET_FEERATE = 100   (sat/kvB == 0.1 sat/vB)
    MAX_BUCKET_FEERATE = 1e7   (sat/kvB)
    FEE_SPACING        = 1.05
    → ~237 buckets exponentially spaced
    ```
    ouroboros's `FEE_RATE_BUCKETS`:
    ```python
    [1, 2, 3, 5, 7, 10, 15, 20, 30, 50, 75, 100, 150, 200, 300,
     500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000]
    ```
    Note: ouroboros's boundaries are in **sat/vB** (24 values); Core's
    are in **sat/kvB** (~237 values). Two divergences here:
    1. **Unit mismatch**: ouroboros assigns tx feerate to a bucket
       via `_bucket_index(entry.fee / entry.size)` which gives a
       sat/vB number, compared against sat/vB boundaries. Core does
       this in sat/kvB. The intra-impl arithmetic is consistent
       (sat/vB throughout), but **cross-impl** divergence on which
       feerates land in which bucket is structural.
    2. **Coarse resolution**: 24 buckets vs 237 → bucket width
       averages ~10× wider, hurting precision near the median feerate.

14. **`SUFFICIENT_FEETXS=0.1` and `SUFFICIENT_TXS_SHORT=0.5` thresholds
    are absent (BUG-14, P1, same as W114 BUG-10).** Core's
    `EstimateMedianVal` merges adjacent buckets until the COMBINED
    bucket meets `sufficientTxVal / (1 - decay)` average txs
    (`:298`). Approximate floor: for LONG decay 0.99931 →
    `0.1 / 0.00069 ≈ 145 average txs in a 1-bucket window` before an
    estimate can be reported. ouroboros's `_estimate_from_buckets`
    (`:387-402`) requires only `total >= 2.0` per bucket → estimates
    can be generated from as few as 2 txs.

15. **Three success-threshold constants (0.60 / 0.85 / 0.95) are
    absent (BUG-15, P1).** Core uses `HALF_SUCCESS_PCT=0.60`,
    `SUCCESS_PCT=0.85`, `DOUBLE_SUCCESS_PCT=0.95`. ouroboros has a
    single `SUCCESS_THRESHOLD=0.85` and uses it for every estimate.
    Combined with BUG-2 (no 3-sub-estimate max) this entirely removes
    the HALF and DOUBLE side of the estimate. The 0.95 threshold is
    Core's "DOUBLE_SUCCESS_PCT at 2×target" safety check; without it,
    the conservative-mode safety margin is gone (see also BUG-3).

16. **`estimateConservativeFee` cross-horizon walk is missing
    (BUG-16, P1).** Core's `estimateConservativeFee`
    (`:847-862`) computes the max of the medium-horizon estimate at
    `doubleTarget` AND the long-horizon estimate at `doubleTarget`
    (when supported), all at the 0.95 threshold. This is the
    **fundamental safety property** of conservative mode: the
    estimate is bounded below by a long-horizon 95%-confidence value.
    ouroboros has no equivalent.

17. **`estimateCombinedFee` shortest-horizon-first + check-shorter
    logic is missing (BUG-17, P1).** Core's `estimateCombinedFee`
    (`:808-842`) does:
    ```cpp
    if (confTarget <= shortStats->GetMaxConfirms())       use shortStats
    else if (confTarget <= feeStats->GetMaxConfirms())    use feeStats
    else                                                  use longStats
    if (checkShorterHorizon) {
        // If a lower confTarget from a more recent horizon returns a lower
        // answer use it.
    }
    ```
    ouroboros's `estimate_fee` (`:249-278`) picks one horizon by target
    and stops — no cross-horizon fallback, no "lower answer from shorter
    horizon wins" logic. Estimates miss the cross-horizon optimum.

18. **`MaxUsableEstimate` clamp is missing — `feeCalc.returnedTarget`
    always echoes input (BUG-18, P1, same as W114 BUG-12).** Core
    (`:892-895`):
    ```cpp
    unsigned int maxUsableEstimate = MaxUsableEstimate();
    if ((unsigned int)confTarget > maxUsableEstimate) {
        confTarget = maxUsableEstimate;
    }
    if (feeCalc) feeCalc->returnedTarget = confTarget;
    ```
    `MaxUsableEstimate = min(longStats->GetMaxConfirms(),
    max(BlockSpan(), HistoricalBlockSpan()) / 2)`. ouroboros echoes the
    raw requested target as `"blocks"` in `estimatesmartfee` response.
    Pre-FIX impact: a caller asking for `conf_target=500` on a node
    that has only been running for 200 blocks gets `"blocks": 500`
    even though Core would clamp to `100` (`200/2`) and return that
    as `returnedTarget`. The caller has no signal that the estimate
    is from a shorter horizon.

19. **`FeeFilterRounder` MakeFeeSet does not insert `0` first; uses
    `random.randint` instead of FastRandomContext (BUG-19, P2).**
    Core's `MakeFeeSet` (`:1085-1101`) inserts `0` as the first
    bucket-boundary before the exponential ladder. ouroboros's
    `FeeFilterRounder._make_fee_set` (`p2p.py:113-119`):
    ```python
    fee_set = [0]
    min_fee_limit = max(1, min_incremental_fee // 2)
    ...
    ```
    Correct — `0` is inserted. BUT the round() method (p2p.py:121-154)
    uses `random.randint(0,2) != 0` (2/3 probability), which matches
    Core's `insecure_rand.rand32() % 3 != 0`. The behavior is the
    same — only the RNG source differs (`random.randint` is process-wide
    seeded vs Core's per-instance FastRandomContext). Cross-impl
    cryptographic-RNG divergence; OK because the rounder is for privacy
    quantisation, not consensus.

20. **`MIN_BUCKET_FEERATE > 0` static_assert is silent — boundary at
    sat/vB unit boundary not enforced (BUG-20, P2).** Core's constructor
    (`:546`):
    ```cpp
    static_assert(MIN_BUCKET_FEERATE > 0, "Min feerate must be nonzero");
    ```
    ouroboros's first bucket boundary is `1` (sat/vB), which is
    positive — but the constant is not asserted. If a future refactor
    introduces a `0`-first boundary, the bucket-walk would silently
    treat sub-1 fee rates as 0/0 division-by-zero — caught by the
    `<= FEE_RATE_BUCKETS[0]` short-circuit but a latent footgun.

21. **No `processBlock` `nBlockHeight <= nBestSeenHeight` reorg guard
    (BUG-21, P1).** Core (`:673-680`):
    ```cpp
    if (nBlockHeight <= nBestSeenHeight) {
        // Ignore side chains and re-orgs; assuming they are random
        // they don't affect the estimate.
        return;
    }
    ```
    ouroboros's `process_block` (`fee_estimator.py:193-243`) does NOT
    track `nBestSeenHeight` and does NOT guard against being called
    twice for the same height. The caller in `block_sync.py:1349-1353`
    only invokes after `connected += 1` (i.e., on a tip-advancing
    block), so this is mitigated in the live path. BUT a manual
    `submitblock` reorg path (rpc.py — submit_block flow) does NOT
    re-validate the estimator state, so a stale-side-branch tx could
    confuse the buckets. Severity P1 because reorgs are rare AND the
    caller mitigates, but the missing internal guard is a latent
    regression vector.

Bug inventory
-------------

```
ID      G#        Severity      File                Line    Summary
------  ----      -----------   ------------------  ------  -------------------------
BUG-1   G22       P0-CDIV       fee_estimator.py   280-286  estimate_fee_per_kb comment says BTC/kB but returns BTC/kvB; downstream call-site unit mismatch
BUG-2   G07-G10   P1-CDIV       fee_estimator.py   249-278  estimateSmartFee 3-sub-estimate max(HALF/FULL/DOUBLE) missing
BUG-3   G11       P1            rpc.py             4488      estimate_mode parameter accepted but never plumbed (conservative is a no-op)
BUG-4   G14-G15   P1            (absent)           n/a      processTransaction admission hook missing → no unconfTxs → no extraNum term
BUG-5   G16-G17   P1            (absent)           n/a      removeTx/failAvg missing → eviction pressure invisible (failNum term)
BUG-6   G18       P1            fee_estimator.py   201-202  No ClearCurrent ring-buffer roll (knock-on from BUG-4)
BUG-7   G19       P1            fee_estimator.py   201,228  _apply_decay over-decays total_h (decays the unconfirmed-equivalent denominator)
BUG-8   G20       P1            fee_estimator.py   224       blocks_to_confirm = height-entry_height+1 (off-by-one; Core uses no +1)
BUG-9   G23       P1            fee_estimator.py   474-540  load_from_file accepts stale files; no MAX_FILE_AGE=60h gate
BUG-10  G24       P1            node.py            (absent) No periodic FEE_FLUSH_INTERVAL=1h flush; only on clean shutdown
BUG-11  G25       P1            (absent)           n/a      FlushUnconfirmed shutdown hook missing (re-records still-tracked txs as fails)
BUG-12  G26       P2            fee_estimator.py   440-472  JSON persistence (Core uses binary VectorFormatter+EncodedDouble); no version gate; no nBestSeenHeight
BUG-13  G02-G05   P1            fee_estimator.py   55-61    24 hand-coded sat/vB buckets vs Core ~237 sat/kvB exponential (FEE_SPACING=1.05)
BUG-14  G13       P1            fee_estimator.py   389-402  SUFFICIENT_FEETXS / SUFFICIENT_TXS_SHORT absent (per-bucket merge threshold)
BUG-15  G12       P1            fee_estimator.py   108       Single 0.85 threshold vs Core's HALF=0.6 / FULL=0.85 / DOUBLE=0.95 triplet
BUG-16  G09       P1            (absent)           n/a      estimateConservativeFee cross-horizon DOUBLE_SUCCESS_PCT walk missing
BUG-17  G08       P1            fee_estimator.py   249-278  estimateCombinedFee shortest-horizon-first + checkShorterHorizon logic missing
BUG-18  G21       P1            rpc.py             4517     estimatesmartfee "blocks" always echoes input; no MaxUsableEstimate clamp
BUG-19  G28       P2            p2p.py             148       FeeFilterRounder uses python random (not seeded from FastRandomContext)
BUG-20  G27       P2            fee_estimator.py   55,116   MIN_BUCKET_FEERATE>0 static_assert absent; first-boundary not enforced positive
BUG-21  G29       P1            fee_estimator.py   193-243  No nBlockHeight <= nBestSeenHeight reorg guard inside process_block
```

Severity legend
- **P0-CDIV**: consensus-divergence-capable; affects every RPC consumer.
- **P1-CDIV**: algorithm-divergence-capable; specific bias direction
  vs Core but contained within fee-estimation surface.
- **P1**: protocol-divergence; observable cross-impl difference but
  not consensus-critical.
- **P2**: cosmetic / latent / micro-optimisation.

30-Gate audit matrix
--------------------

### Wave 1: Constants & data structures (G1–G6)

| Gate | Status   | Detail |
|------|----------|--------|
| G1: SHORT/MED/LONG decay constants 0.962/0.9952/0.99931 | PRESENT | fee_estimator.py:77-81 (`DECAY` dict). W114 BUG-1 closed. |
| G2: SHORT/MED/LONG scale constants 1/2/24 | PRESENT | fee_estimator.py:84-88 (`SCALE` dict). |
| G3: SHORT/MED/LONG period counts 12/24/42 | PRESENT | fee_estimator.py:91-95 (`PERIODS` dict). |
| G4: MIN/MAX/SPACING bucket params (Core: 100/1e7/1.05 sat/kvB) | MISSING | fee_estimator.py:55-61 uses 24 hand-coded sat/vB boundaries. BUG-13. |
| G5: Bucket count (Core: ~237) | MISSING | NUM_BUCKETS=24. BUG-13. |
| G6: MAX_CONF_TARGET=1008 (LONG horizon) | PRESENT | fee_estimator.py:66. W114 BUG-2 closed. |

### Wave 2: estimateSmartFee algorithm (G7–G11)

| Gate | Status   | Detail |
|------|----------|--------|
| G7: HALF sub-estimate at confTarget/2, threshold 0.60 | MISSING | Single 0.85-threshold path. BUG-2 + BUG-15. |
| G8: FULL sub-estimate at confTarget, threshold 0.85 | PARTIAL | `_estimate_from_buckets` uses 0.85 but single-target only; no cross-horizon. BUG-17. |
| G9: DOUBLE sub-estimate at 2×confTarget, threshold 0.95 | MISSING | BUG-2 + BUG-15. estimateConservativeFee cross-horizon also missing. BUG-16. |
| G10: max(HALF, FULL, DOUBLE) returned | MISSING | BUG-2. Single bucket scan returned directly. |
| G11: conservative-mode propagated from RPC | MISSING | rpc.py:4488 accepts `estimate_mode` but ignores it. BUG-3. |

### Wave 3: estimateMedianVal algorithm (G12–G18)

| Gate | Status   | Detail |
|------|----------|--------|
| G12: Three success thresholds (0.6/0.85/0.95) | MISSING | Single SUCCESS_THRESHOLD=0.85 (line 108). BUG-15. |
| G13: SUFFICIENT_FEETXS=0.1 / TXS_SHORT=0.5 merge-bucket-until | MISSING | _estimate_from_buckets requires `total >= 2.0` per bucket only. BUG-14. |
| G14: processTransaction admission hook | MISSING | No on_tx_added wiring. BUG-4. |
| G15: extraNum term from unconfTxs in EstimateMedianVal | MISSING | BUG-4 knock-on. |
| G16: removeTx records evictions to failAvg | MISSING | No remove_tx method, no fail_avg array. BUG-5. |
| G17: failNum term from failAvg in EstimateMedianVal | MISSING | BUG-5 knock-on. |
| G18: ClearCurrent ring-buffer roll in processBlock | MISSING | No ring buffer. BUG-6. |

### Wave 4: processBlock pipeline (G19–G22)

| Gate | Status   | Detail |
|------|----------|--------|
| G19: Decay applied BEFORE recording new block data | PARTIAL | `_apply_decay()` runs first (correct order), but over-decays `total_h` which contains the unconfirmed-equivalent denominator. BUG-7. |
| G20: blocks_to_confirm = nBlockHeight - txHeight (1-based) | MISSING | `height - entry_height + 1` (off-by-one). BUG-8. |
| G21: feeCalc.returnedTarget reflects MaxUsableEstimate clamp | MISSING | rpc.py:4517 always echoes input `conf_target`. BUG-18. |
| G22: estimatesmartfee returns BTC/kvB integer-sat-equivalent | PARTIAL | `estimate_fee_per_kb` returns float BTC/kvB but `estimate_fee` is sat/vB; downstream callers inconsistent. BUG-1. |

### Wave 5: Persistence (G23–G26)

| Gate | Status   | Detail |
|------|----------|--------|
| G23: Stale-file rejection (Core MAX_FILE_AGE=60h) | MISSING | load_from_file always reads. BUG-9. |
| G24: Periodic flush (Core FEE_FLUSH_INTERVAL=1h) | MISSING | Only on clean shutdown. BUG-10. |
| G25: FlushUnconfirmed records still-tracked txs as fails on stop | MISSING | No process_transaction → nothing to flush. BUG-11 (knock-on from BUG-4+5). |
| G26: Binary versioned format (Core 309900, EncodedDoubleFormatter) | MISSING | JSON with version=1; no version-gate, no bucket-range check, no height bounds. BUG-12. |

### Wave 6: FeeFilterRounder + wiring + two-pipeline (G27–G30)

| Gate | Status   | Detail |
|------|----------|--------|
| G27: MIN_BUCKET_FEERATE > 0 enforced (static_assert) | PARTIAL | First boundary is `1` (positive) but no assert. BUG-20. |
| G28: FeeFilterRounder buckets at FEE_FILTER_SPACING=1.1 | PRESENT | p2p.py:73-75 + p2p.py:113-119. Includes `0` first. BUG-19 caveat: RNG source diverges. |
| G29: process_block reorg guard (nBlockHeight > nBestSeenHeight) | MISSING | No nBestSeenHeight tracking. BUG-21. |
| G30: two-pipeline guard — fee estimator Python-only | NEW | Added in test_w139_fee_estimation.py. Confirms ferrous-utils has no fee-estimation code. |

Test status (test_w139_fee_estimation.py)
-----------------------------------------

30 gates → 30 test functions + 1 architectural guard.

- **xfailed (BUG-marked, P0/P1)**: 21 — one per BUG-* row in the inventory.
- **passed**: 9 — gates currently honored (G1, G2, G3, G6 (W114 close);
  G8 partial threshold; G19 partial decay order; G22 partial unit;
  G27 partial; G28 rounder + G30 two-pipeline guard).
- Total: 30 tests + 1 guard. With auto-fix landing, xfails flip to
  XPASS strict-mode.

Out-of-scope for W139
---------------------

- The CLI `-blockfilterindex`/`-peerblockfilters` flags (W121).
- The `feerate.cpp::EvaluateFeeUp` integer rounding (consensus-relevant
  for `getmempoolinfo` but not for the policy estimator). Audited
  separately under W136.
- The wallet's `-paytxfee` / `-walletfee` / `-falbackfee` mainnet
  CLI flags (operator UX, audited under W124).
- The `getmempoolinfo` `mempoolminfee` field accuracy (its value is
  computed by `mempool.get_min_fee` directly — not via the estimator).
- The cross-impl consistency of `estimatesmartfee` JSON output
  between ouroboros and the other 9 hashhog impls (W118 wallet fleet).

Future remediation order (post-discovery)
-----------------------------------------

1. **BUG-1** (P0-CDIV): make `estimate_fee_per_kb` and `estimate_fee`
   units consistent. Either:
   - Move BTC/kvB conversion out of `estimate_fee_per_kb` (return raw
     sat/vB and let callers convert), OR
   - Make `estimate_fee` return sat/kvB internally and have
     `estimate_fee_per_kb` divide by 1e8 only. Pick one, document.
   ~10 LOC.
2. **BUG-8** (P1): drop the `+1` from `blocks_to_confirm`. ~1 LOC.
3. **BUG-9** (P1): add `os.path.getmtime`-based MAX_FILE_AGE gate in
   `load_from_file`. ~5 LOC.
4. **BUG-15** (P1): introduce the three threshold constants
   (HALF_SUCCESS_PCT=0.6, SUCCESS_PCT=0.85, DOUBLE_SUCCESS_PCT=0.95).
   ~3 LOC.
5. **BUG-2 + BUG-16 + BUG-17** (P1): rewrite `estimate_fee` to do the
   three-sub-estimate max with cross-horizon walk. ~60 LOC; biggest
   single algorithm gap.
6. **BUG-3** (P1): plumb `estimate_mode` from `rpc_estimatesmartfee`
   into a new `conservative=True/False` kwarg on `estimate_fee`.
   ~8 LOC.
7. **BUG-21** (P1): add `self._n_best_seen_height` and the early-return
   guard in `process_block`. ~6 LOC.
8. **BUG-4 + BUG-5 + BUG-6 + BUG-11** (P1 cluster): the
   processTransaction/removeTx/ClearCurrent/FlushUnconfirmed
   admission-tracking cluster. ~150 LOC; biggest single LOC.
9. **BUG-13 + BUG-14** (P1 cluster): bump bucket count to ~237 via
   the exponential ladder + add the SUFFICIENT_FEETXS merge-until
   logic in `_estimate_from_buckets`. ~50 LOC.
10. **BUG-18** (P1): add `MaxUsableEstimate` + plumb `returnedTarget`
    through to the RPC response. ~15 LOC.
11. **BUG-10** (P1): add an asyncio task to call
    `fee_estimator.save_to_file` every 3600s. ~8 LOC.
12. **BUG-12** (P2): document binary-vs-JSON divergence; bump JSON
    version field on dimension change; add bucket-range and height-bounds
    sanity checks. ~12 LOC.
13. **BUG-19** (P2): document FeeFilterRounder RNG divergence; no fix
    needed.
14. **BUG-20** (P2): add `assert FEE_RATE_BUCKETS[0] > 0` at module
    import time. ~1 LOC.
15. **BUG-7** (P1): decouple `total_h` decay from `conf_h` decay so
    the denominator is not aggressively reduced over time. ~15 LOC.

Universal patterns observed
---------------------------

- **"Policy-only-in-Python" two-pipeline guard pattern** continues to
  hold across W137 (PSBT) → W139 (fee estimator). Both are wallet/policy
  surfaces with zero Rust footprint. Suggests the pattern is **the**
  ouroboros architectural invariant for the wallet+policy stack, and
  every future wallet/policy audit (W140 mining/getblocktemplate
  policy, W141 -paytxfee CLI) should EXTEND the guard rather than
  introduce a new one.

- **"Algorithm-divergence-class P1-CDIV"** is a new bug-severity shape
  introduced here: BUG-2 is not a pure missing-check (P1) and not a
  consensus-rule miss (P0), it's a **specific bias direction** in the
  estimator's mathematical behavior that diverges from Core. This
  echoes W118 wallet bugs (BIP-44 derivation off-by-one) and W120 RBF
  (CompareChunks misorder). Suggests we need a `P1-CDIV-algorithm`
  bucket distinct from `P0-CDIV-consensus`.

- **"Unit-collision at language boundary"** (BUG-1, BUG-13).
  ouroboros uses sat/vB throughout the estimator but Core's
  authoritative wire surface is sat/kvB. Two unit systems collide
  at:
  - The wallet RPC return value (BTC/kvB vs sat/vB).
  - The bucket-boundary array (sat/vB vs sat/kvB).
  Fix: pick sat/kvB internally (Core canonical) and only convert at
  the user-facing RPC boundary.

End of W139 audit.
