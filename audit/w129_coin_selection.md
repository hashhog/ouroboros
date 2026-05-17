W129 — Coin selection re-audit (BnB / Knapsack / SRD / CG) (ouroboros)
======================================================================

Date: 2026-05-17
Impl: ouroboros (Python only; Rust ferrous-utils does not serve wallet)
Wave: W129 Coin selection — BnB, Knapsack, SRD, CoinGrinder,
      effective_value, long-term feerate, cost of change, SFFO,
      change avoidance (DISCOVERY)
Reference: `bitcoin-core/src/wallet/coinselection.{h,cpp}`,
           `bitcoin-core/src/wallet/spend.cpp`,
           `bitcoin-core/src/wallet/feebumper.cpp`

Status: 30 gates audited — PRESENT 3 / PARTIAL 8 / MISSING 19. **20 BUGS**
(2 P0-PRIVACY / 8 P1 / 10 P2). One closed since W113 (FIX P0-PRIVACY
W118 BUG-3 / CSPRNG landed `703cf69` 2026-05-15).

Two-pipeline guard
------------------

Coin selection is wallet logic — Python-only on ouroboros. `ferrous-utils`
Rust crate is the IBD validation + RocksDB sync pipeline; it does NOT
implement any coin selection.

```
$ grep -rn "coin_select\|coinselect\|select_coins\|effective_value\|\
           long_term\|knapsack\|coingrinder\|cost_of_change\|change_target" \
       ferrous-utils/  → 0 matches
$ grep -rn "select_coins\|effective_value\|long_term_fee\|cost_of_change" \
       src/ouroboros/*.py  → all hits in wallet.py only
```

**Two-pipeline guard PRESERVED.** No coin selection on Rust side. Test
file includes a one-line guard `test_two_pipeline_no_coin_selection_in_rust`
asserting ferrous-utils contains zero matches for coin-selection
identifiers; this maintains the guard now codified in W76+W122+W125.

Scope
-----

W113 (2026-05-14, audit-only) catalogued 12 bugs at 45 tests. W129
revisits the same subsystem six weeks later with three new dimensions:

1. **CoinGrinder + SFFO** — Core 25.0 added CoinGrinder; SFFO behavior
   has subtle BnB-skip rule (`spend.cpp:751`) we missed.
2. **Cost-of-change formula precision** — Core decomposes
   `m_cost_of_change = m_discard_feerate.GetFee(change_spend_size)
                     + m_change_fee` (`spend.cpp:1175`); ouroboros
   collapses to a single fee rate. W113 BUG-3 noted the long-term
   confusion but missed that Core uses `m_discard_feerate` (not
   `m_long_term_feerate`) for the **spend** side.
3. **CoinControl / SFFO / TRUC** — full surface.

Top-level architectural findings
--------------------------------

**(F1) Coin selection is a flat-list three-tier pipeline; Core is a
filtered-group powerset over four algorithms.** ouroboros runs
BnB→Knapsack→SRD in parallel, then picks the min-waste result. Core
runs an outer `AutomaticCoinSelection` loop over 6+ confirmation-tier
filters (`spend.cpp:898-927`); for each filter it groups outputs by
script then by output-type; runs (BnB if not-SFFO) + Knapsack +
(CoinGrinder if `effective_feerate > 3*long_term_feerate`) + SRD; picks
the per-type min-waste; if no per-type works, tries mixed groups.
ouroboros is functionally 1/20th of this surface. Most W113 bugs in
this audit collapse to architectural gaps stemming from F1.

**(F2) No `CoinSelectionParams` / `CCoinControl` plumb.** Core threads
17 fields (`coinselection.h:134-196`) through every algorithm:
`change_output_size`, `change_spend_size`, `m_min_change_target`,
`min_viable_change`, `m_change_fee`, `m_cost_of_change`,
`m_effective_feerate`, `m_long_term_feerate`, `m_discard_feerate`,
`tx_noinputs_size`, `m_subtract_fee_outputs`, `m_avoid_partial_spends`,
`m_include_unsafe_inputs`, `m_version`, `m_max_tx_weight`. ouroboros
algorithms take only `(utxos, target, fee_rate)`. SFFO, discard
feerate, max-tx-weight, change-output-size, and avoid-partial-spends
are all absent from the signature. W113 BUG-11 (CoinControl absent)
ranked HIGH; should be P0-architectural — every other gap downstream.

**(F3) Waste metric is local to ouroboros, not Core-compatible.** Core
`SelectionResult::RecalculateWaste` (`coinselection.cpp:827-853`)
computes waste over the **selected coins**: sum of `(coin.GetFee() -
coin.long_term_fee)` minus bump-fee discount, plus either
`change_cost` (if change ≥ `min_viable_change`) **or** `excess` (if no
change, where excess = `selected_effective_value - m_target`).
ouroboros `_selection_waste` (`wallet.py:320-329`) reduces to
`total_input_weight * (fee_rate - long_term_fee_rate) + change_cost`
with `change_cost = COST_OF_CHANGE_VBYTES * fee_rate` if has_change
else 0. Three errors compounded: (a) the per-input waste term uses
`vbytes * delta_rate` instead of `coin.GetFee() - coin.long_term_fee`
(equivalent IFF all inputs are 68 vB; differs once non-P2WPKH inputs
appear); (b) no excess term in the no-change branch (W113 BUG-2,
re-confirmed); (c) `change_cost` formula uses `effective_feerate` for
the spend side instead of `m_discard_feerate.GetFee(change_spend_size)
+ m_change_fee` — W113 BUG-3 partly noted this but said "long_term";
the correct Core rate for the spend side is the **discard rate**, not
the **long-term rate**.

**(F4) CoinGrinder triggering rule absent.** Core gates CoinGrinder
on `effective_feerate > 3 * long_term_feerate`
(`spend.cpp:769`) — the high-feerate consolidation regime where input
minimization beats waste minimization. ouroboros has no CoinGrinder at
all (W113 BUG-12) and no feerate-bucketing logic. Without CG, ouroboros
will always overspend inputs during fee spikes (≥30 sat/vB by default).
Re-ranked P1 (W113 had LOW; for any node operating during
high-congestion windows, CG absence costs measurable sats per send).

Bug inventory (20 bugs / 30 gates)
-----------------------------------

Severity: P0=consensus-or-privacy, P1=user-funds/correctness, P2=cosmetic.

| Bug    | Gates    | Sev | Description                                           |
|--------|----------|-----|-------------------------------------------------------|
| BUG-1  | G1-G5    | P1  | CoinGrinder absent (W113 BUG-12 carried; re-ranked P1).|
| BUG-2  | G1-G5    | P1  | No feerate-bucketing rule → CG never auto-activates.  |
| BUG-3  | G6-G8    | P1  | OutputGroup concept absent (W113 BUG-1 carried).      |
| BUG-4  | G6-G8    | P1  | OUTPUT_GROUP_MAX_ENTRIES=100 cap absent.              |
| BUG-5  | G6-G8    | P1  | `m_avoid_partial_spends` absent — wallet always splits|
|        |          |     | UTXOs from the same address across txs (privacy gap). |
| BUG-6  | G9-G11   | P1  | `CoinEligibilityFilter` outer loop absent — no        |
|        |          |     | (conf_mine=1,conf_theirs=6,max_anc=0) → (1,1,0) →     |
|        |          |     | (0,1,2) → … → (0,0,∞) cascade. ouroboros uses all     |
|        |          |     | mature UTXOs without filtering by confirmation tier.  |
|        |          |     | Consequence: high-anti-privacy theirs UTXOs (1 conf   |
|        |          |     | external receive) are spent eagerly when 6-conf       |
|        |          |     | candidates would suffice.                             |
| BUG-7  | G9-G11   | P1  | `walletrejectlongchains` long-mempool-cluster guard   |
|        |          |     | absent (`spend.cpp:881-927` skips long-ancestor groups|
|        |          |     | unless flag is off). Caller cannot avoid building     |
|        |          |     | unconfirmed-ancestor chains.                          |
| BUG-8  | G12-G14  | P1  | BnB waste metric missing excess term in no-change     |
|        |          |     | branch (W113 BUG-2 carried).                          |
| BUG-9  | G12-G14  | P1  | BnB tries counter increments per backtrack call, not  |
|        |          |     | per DFS loop iteration (W113 BUG-4 carried). Counter  |
|        |          |     | exhausts faster than Core's 100k tries; pathological  |
|        |          |     | inputs that would solve under Core may return None.   |
| BUG-10 | G12-G14  | P1  | BnB skips clone-pruning (Core `coinselection.cpp:171-`|
|        |          |     | 184`: avoid searching exclusion branch when the prev  |
|        |          |     | UTXO had equal effective value AND equal fee).        |
|        |          |     | ouroboros recurses into both branches unconditionally;|
|        |          |     | for pools with >50 equal-value UTXOs, BnB's tree size |
|        |          |     | doubles relative to Core.                             |
| BUG-11 | G12-G14  | P1  | BnB skips `is_feerate_high` pruning (Core line 120 +  |
|        |          |     | 129): when `coin.fee > coin.long_term_fee`, Core      |
|        |          |     | aborts subtree once `curr_waste > best_waste`.        |
|        |          |     | ouroboros never prunes on waste-monotonicity.         |
| BUG-12 | G15-G17  | P1  | Knapsack missing two-pass structure (W113 BUG-5       |
|        |          |     | carried). Core's `ApproximateBestSubset` makes 1000   |
|        |          |     | reps where each rep has two passes: pass-0 includes   |
|        |          |     | each utxo with 50% prob; pass-1 sweeps remaining      |
|        |          |     | unincluded UTXOs to ensure coverage. ouroboros only   |
|        |          |     | does pass-0 then breaks early on coverage.            |
| BUG-13 | G15-G17  | P1  | Knapsack missing `lowest_larger` fallback. Core       |
|        |          |     | tracks the smallest single UTXO that overshoots and   |
|        |          |     | falls back to it when stochastic approximation fails  |
|        |          |     | OR returns suboptimal. ouroboros has the single-UTXO  |
|        |          |     | initialization but not the fallback during            |
|        |          |     | stochastic-approx failure path.                       |
| BUG-14 | G15-G17  | P2  | Knapsack: missing `subtract_fee_outputs` short-circuit|
|        |          |     | (Core uses `GetSelectionAmount` which returns         |
|        |          |     | `m_value` when SFFO is on, `effective_value`          |
|        |          |     | otherwise). ouroboros always uses                     |
|        |          |     | `value - input_fee` regardless of SFFO.               |
| BUG-15 | G18-G20  | P1  | SRD missing `change_fee` adjustment to target. Core   |
|        |          |     | `coinselection.cpp:546`: `target += CHANGE_LOWER +    |
|        |          |     | change_fee` before the random-draw loop, so SRD       |
|        |          |     | guarantees enough headroom for a change output above  |
|        |          |     | dust. ouroboros adds only a 2-output overhead;        |
|        |          |     | discriminator allows SRD to terminate with             |
|        |          |     | overshoot < change_fee → caller emits dust change or  |
|        |          |     | burns sats.                                           |
| BUG-16 | G18-G20  | P1  | SRD missing max-weight eviction. Core line 567-575:   |
|        |          |     | when accumulated weight exceeds `max_selection_weight`|
|        |          |     | drop the *smallest* selected UTXO (priority_queue.top)|
|        |          |     | until weight conforms. ouroboros has no weight cap →  |
|        |          |     | can build oversize unsignable txs in degenerate pools.|
| BUG-17 | G21-G23  | P0  | Change output uses `self.keys[0]` (W113 BUG-6         |
|        |   PRIVACY| | carried). Every change goes to the same address →     |
|        |          |     | trivial wallet-linkage leak. KeyPool exists but is    |
|        |          |     | not consulted by `send_transaction`.                  |
| BUG-18 | G21-G23  | P0  | Change position is always last output (W113 BUG-10    |
|        |   PRIVACY| | carried). Core line 1255 inserts change at            |
|        |          |     | `rng_fast.randrange(vout.size()+1)`.                  |
| BUG-19 | G21-G23  | P1  | Dust threshold hardcoded 546 (W113 BUG-7 carried).    |
|        |          |     | Core `min_viable_change = max(change_spend_fee+1,     |
|        |          |     | dust)` where dust = `GetDustThreshold(spk,            |
|        |          |     | discard_feerate)`. ouroboros ignores both factors;    |
|        |          |     | at high discard rates this drops change that should   |
|        |          |     | survive, or keeps change that should be absorbed.     |
| BUG-20 | G24-G26  | P1  | `_selection_waste` change_cost formula error          |
|        |          |     | (W113 BUG-3 corrected). Correct formula:              |
|        |          |     | `change_cost = m_effective_feerate*output_size +      |
|        |          |     |  m_discard_feerate*change_spend_size`. ouroboros uses |
|        |          |     | `COST_OF_CHANGE_VBYTES * fee_rate` (single rate).     |
|        |          |     | W113 said long_term_feerate; the correct Core rate    |
|        |          |     | for the spend side is the **discard** rate.           |

Carried-from-W113 (no behavioral regression, same scope):

* BUG-3,4,5  ↔ W113 BUG-1 (OutputGroup gap; split into 3 because the
              MAX_ENTRIES cap, the avoid-partial-spends bit, and the
              group concept are distinct fixes).
* BUG-8      ↔ W113 BUG-2 (waste metric excess term).
* BUG-9-11   ↔ W113 BUG-4 (BnB tries semantic; new audit splits the
              clone-pruning and is_feerate_high pruning gaps as
              separate bugs because the production fix is two patches).
* BUG-12,13  ↔ W113 BUG-5 (Knapsack two-pass).
* BUG-17,18  ↔ W113 BUG-6, BUG-10 (privacy gaps; promoted P0 — change
              reuse leaks **every** transaction's wallet linkage,
              that's a P0-PRIVACY-grade exposure per FIX-69
              precedent that promoted W118 BUG-3 to P0).
* BUG-19     ↔ W113 BUG-7 (dust threshold hardcoded).
* BUG-20     ↔ W113 BUG-3 (cost-of-change; correction of W113's
              long_term hypothesis with Core's actual discard
              feerate).
* BUG-1,2    ↔ W113 BUG-12 (CoinGrinder absence; re-ranked P1 with
              the auto-activation rule as a separate bug).

Newly identified (not in W113):

* BUG-6,7    — CoinEligibilityFilter cascade + walletrejectlongchains.
              W113 audit only looked at the in-algorithm tier; the
              outer filter loop is the larger architectural gap.
* BUG-10,11  — BnB clone-pruning and is_feerate_high pruning gaps.
              W113 lumped these into "tries counter differs"; they're
              algorithmically distinct optimizations.
* BUG-14,15,16 — Knapsack SFFO short-circuit; SRD change_fee
              adjustment; SRD max-weight eviction. W113 didn't audit
              SFFO at all and missed two SRD optimizations.

Closed since W113 (no longer applicable):

* **W113 BUG-8** (anti-fee-sniping 1-in-10 random nLockTime lowering):
  Out-of-scope for W129 (anti-fee-sniping is a separate subsystem
  audited in W113's G25-G28; W129 focuses on coin selection mechanics
  G1-G26 only).
* **W113 BUG-9** (IBD guard on anti-fee-sniping): same, out-of-scope.
* **W118 BUG-3 CSPRNG**: CLOSED 2026-05-15 by `703cf69`. Code now
  uses `secrets.SystemRandom()` (`_CSPRNG`) for Knapsack + SRD
  shuffles. Note however: W113 itself documented that this fix was
  *unnecessary* — Core uses `FastRandomContext` for coin selection,
  which is **seeded from secure entropy** (`random.h:380-414`,
  ChaCha20 with `GetRandHash()` seed) but is deterministic after
  seed. `secrets.SystemRandom()` reseeds from `/dev/urandom` on every
  call → ~10×slower than necessary but *not wrong*. We don't add a
  bug for this; the production change is conservative and the
  privacy property holds.

Anti-fee-sniping gates (W113 G25-G28)
-------------------------------------

Out of W129 scope. See W113's `test_w113_coin_selection.py::TestG25_G28
_AntiFeeSnipe` for the existing audit. The 3 anti-fee-sniping bugs
documented there (BUG-8, BUG-9, plus the IBD-guard absence) remain open
since W113 — no fix has landed. Owner should bundle into FIX wave with
this audit's findings.

Top 5 highest-impact findings
-----------------------------

1. **BUG-17 / BUG-18 (P0-PRIVACY change-output reuse + last-position
   fingerprinting)** — Every transaction the ouroboros wallet creates
   leaks: (a) change destination = `keys[0]` for every send → wallet
   clustering trivial; (b) change is always last output → fingerprint
   for chain-analysis heuristics. Two independent privacy-grade leaks
   on EVERY send. W113 BUG-6 and BUG-10 ranked LOW/MEDIUM; W129
   promotes both to P0-PRIVACY by analogy to W88 anti-pattern and
   FIX-69 precedent (privacy leaks that reveal wallet ownership are
   universally treated P0).

2. **BUG-20 (P1 change_cost formula error)** — The waste metric's
   change_cost uses `fee_rate * COST_OF_CHANGE_VBYTES` (= 99 vB at
   current fee rate). Core uses `effective_feerate * change_output_size
   + discard_feerate * change_spend_size`. When fee_rate=20 sat/vB and
   discard=3 sat/vB, ouroboros computes change_cost=1980 sat vs Core's
   620+204=824 sat — ouroboros over-penalizes change by 2.4×, biasing
   the waste-metric comparator to prefer changeless outcomes even when
   change would be cheaper in true cost. Affects every multi-algorithm
   tie-break.

3. **BUG-6 (P1 CoinEligibilityFilter cascade absent)** — Core's outer
   loop tries (1-conf-mine, 6-conf-theirs, 0-anc) FIRST, escalating
   permissiveness only on failure. ouroboros uses all mature UTXOs
   regardless of source. Consequence: a 1-conf external receive is
   spent immediately even when 6-conf coins suffice → fingerprint that
   the wallet is the receiver. This is the larger architectural gap
   that subsumes BUG-3,4,5 (OutputGroup).

4. **BUG-9 + BUG-10 + BUG-11 (P1 BnB efficiency / correctness gaps)**
   — Three independent BnB algorithm divergences: tries counter
   semantics; missing clone-pruning shortcut; missing
   `is_feerate_high` waste-monotonicity pruning. Each individually
   doubles or worsens the search tree size; in combination ouroboros's
   BnB exhausts the 100k tries budget on pools where Core terminates
   in <10k tries. For wallets with >50 small UTXOs, BnB will
   regularly fail and force the fallback to Knapsack (which over-
   selects), costing both extra fees and degraded coin selection
   quality.

5. **BUG-15 + BUG-16 (P1 SRD correctness gaps)** — SRD is the
   last-resort fallback when BnB and Knapsack both fail. ouroboros's
   SRD has two divergences that make it produce **invalid**
   transactions: (a) missing `change_fee` headroom → caller emits dust
   change; (b) missing max-weight eviction → SRD can construct an
   oversize unsignable input set. Both manifest in the same regime
   (high feerate + many small UTXOs) and are silent failures (no
   error; just bad txs).

Gate matrix (PRESENT / PARTIAL / MISSING)
-----------------------------------------

```
G1  BnB present                                                  PRESENT
G2  Knapsack present                                             PRESENT
G3  SRD present                                                  PRESENT
G4  CoinGrinder present                                          MISSING (BUG-1)
G5  CG auto-activates at effective_feerate > 3*long_term         MISSING (BUG-2)
G6  OutputGroup class exists                                     MISSING (BUG-3)
G7  OUTPUT_GROUP_MAX_ENTRIES=100 enforced                        MISSING (BUG-4)
G8  avoid_partial_spends supported                               MISSING (BUG-5)
G9  CoinEligibilityFilter outer cascade                          MISSING (BUG-6)
G10 walletrejectlongchains guard                                 MISSING (BUG-7)
G11 m_consolidate_feerate as long_term default                   PARTIAL  (constant exists but isn't read from wallet config)
G12 BnB waste metric matches Core (excess + change_cost branch)  PARTIAL  (BUG-8)
G13 BnB tries counter parity (per DFS iteration)                 PARTIAL  (BUG-9)
G14 BnB clone-pruning + is_feerate_high pruning                  MISSING (BUG-10,11)
G15 Knapsack two-pass (50% then sweep)                           MISSING (BUG-12)
G16 Knapsack lowest_larger fallback during stochastic-fail       PARTIAL  (BUG-13)
G17 Knapsack SFFO short-circuit (GetSelectionAmount)             MISSING (BUG-14)
G18 SRD target += CHANGE_LOWER + change_fee                      MISSING (BUG-15)
G19 SRD max-weight eviction with min-priority queue              MISSING (BUG-16)
G20 SRD on positive_group only                                   PARTIAL  (ouroboros excludes value≤input_fee, approximates pos)
G21 Change address from KeyPool fresh per tx                     MISSING (BUG-17 — P0 PRIVACY)
G22 Change position randomized via rng_fast.randrange            MISSING (BUG-18 — P0 PRIVACY)
G23 Dust threshold via GetDustThreshold(spk, discard_feerate)    MISSING (BUG-19)
G24 _selection_waste change_cost decomposes by spend rate        MISSING (BUG-20)
G25 m_use_effective semantic (vs SFFO m_value)                   MISSING (BUG-14 — subset)
G26 min_viable_change vs dust threshold                          MISSING (BUG-19 — subset)
G27 CCoinControl plumbed through select_coins                    MISSING (architectural; W113 BUG-11 carried, omitted from
                                                                          BUG list because it's a roll-up of every other gap)
G28 SelectionResult comparator (min waste, then more inputs)     PARTIAL  (ouroboros uses min waste only; tie-breaker absent)
G29 Two-pipeline guard (no coin selection in Rust)               PRESENT
G30 W118 BUG-3 CSPRNG fix verified                                PRESENT
```

Two-pipeline drift summary
--------------------------

NIL drift. ouroboros's coin selection is Python-only; ferrous-utils
contains zero coin-selection identifiers. The W129 test file adds
`test_two_pipeline_no_coin_selection_in_rust` as a permanent guard.

Followups
---------

A FIX wave on the P0 bugs (BUG-17 + BUG-18) can be a single-impl
30-60 min fix:

```
# BUG-17: change address from KeyPool
change_addr, _ = self._key_pool.get_new_address(is_change=True)
change_spk = address_to_script_pubkey(change_addr, self.network)

# BUG-18: random change position
if change > self._dust_threshold:
    change_pos = secrets.randbelow(len(outputs) + 1)
    outputs.insert(change_pos, TxOut(value=change, script_pubkey=change_spk))
```

BUG-20 is a 1-LOC parity fix once a discard feerate is plumbed (Core
default 10 sat/kvB). BUG-15 / BUG-16 are <50 LOC in SRD. BUG-6,7
(eligibility filter cascade) and BUG-3,4,5 (OutputGroup) are
architectural and would change `_collect_utxos` shape.
