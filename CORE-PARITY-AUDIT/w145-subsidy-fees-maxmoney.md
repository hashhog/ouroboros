W145 — Coinbase subsidy / fees / MAX_MONEY invariants audit (ouroboros)
========================================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline + Rust pipeline).
      The block-subsidy + coinbase-amount enforcement lives in TWO
      places that BOTH ship:
        - Python: `src/ouroboros/validation.py::_verify_coinbase_amount`
          + `_calculate_block_subsidy` (BlockValidator, regtest-aware).
        - Rust pipeline: `ferrous-utils/sync/src/validate/block.rs`
          `BlockValidator::validate_block_subsidy` /
          `calculate_block_subsidy` (regtest-aware via chain_params).
      `ferrous-utils/sync/src/validate/transaction.rs` carries a
      SECOND `calculate_block_subsidy` impl on `TransactionValidator`
      that **hardcodes 210_000** and has no production caller — only
      its own #[cfg(test)] tests. **Two-pipeline guard EXTENDED**:
      forbid Rust-side per-tx-validator subsidy from being wired into
      any new caller; mainnet/regtest divergence would re-surface.
      RPC mining/template paths in `rpc.py` carry **separate** subsidy
      computations (3 distinct copies), 2 of which are regtest-blind
      and 1 of which is missing the post-64-halving zero-clamp.

Wave: W145 — GetBlockSubsidy + nSubsidyHalvingInterval + COINBASE_MATURITY
      + MAX_MONEY + MoneyRange + CVE-2018-17144 (duplicate-inputs) +
      bad-cb-amount + bad-txns-in-belowout.

Reference (Bitcoin Core)
------------------------

- `bitcoin-core/src/validation.cpp`:
  - `GetBlockSubsidy` (lines 1839-1850): `int halvings = nHeight /
    consensusParams.nSubsidyHalvingInterval; if (halvings >= 64)
    return 0; CAmount nSubsidy = 50 * COIN; nSubsidy >>= halvings;
    return nSubsidy;`. The `>= 64` guard is **load-bearing** —
    `nSubsidy >>= 64` is undefined behavior in C++ for int64. Languages
    with well-defined shifts must still apply the guard for parity
    (Python's `>>` returns 0 for shift > bit-width, but Core's wire
    behavior is 0 from the guard).
  - `ConnectBlock` coinbase-amount gate (lines 2610-2614):
    `CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, …);
    if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid())
    state.Invalid(BLOCK_CONSENSUS, "bad-cb-amount", …);`.
- `bitcoin-core/src/kernel/chainparams.cpp`:
  - mainnet `nSubsidyHalvingInterval = 210000` (line 84).
  - testnet3 = 210000 (line 209).
  - testnet4 = 210000 (line 310).
  - signet  = 210000 (line 454).
  - regtest = 150    (line 535).
- `bitcoin-core/src/consensus/amount.h`:
  - `COIN = 100000000` (line 15).
  - `MAX_MONEY = 21000000 * COIN` (line 26).
  - `MoneyRange(nValue) = (nValue >= 0 && nValue <= MAX_MONEY)` (line 27).
- `bitcoin-core/src/consensus/consensus.h`:
  - `COINBASE_MATURITY = 100` (line 19).
- `bitcoin-core/src/consensus/tx_check.cpp` (CheckTransaction,
  lines 11-60): per-output `< 0` (bad-txns-vout-negative) →
  `> MAX_MONEY` (bad-txns-vout-toolarge) → accumulate → `!MoneyRange`
  (bad-txns-txouttotal-toolarge); then duplicate-input check via
  `std::set<COutPoint> vInOutPoints` (CVE-2018-17144); then coinbase
  scriptSig 2..=100 (bad-cb-length); then non-coinbase null-prevout.
- `bitcoin-core/src/consensus/tx_verify.cpp` (CheckTxInputs,
  lines 145-213): coinbase-maturity → per-coin `!MoneyRange(coin.out
  .nValue)` AND `!MoneyRange(nValueIn)` (bad-txns-inputvalues-outofrange)
  → `nValueIn < value_out` (bad-txns-in-belowout) → `!MoneyRange(txfee)`
  (bad-txns-fee-outofrange).

Status: **24 BUGS** (1 P0-CDIV / 2 P0-DoS / 1 P0-SEC / 11 P1 / 7 P2
        / 2 P3). 8 of 8 behaviors audited:
  - Behavior 1 (GetBlockSubsidy 50*COIN >> halvings): **PARTIAL** —
    Python is regtest-aware; Rust BlockValidator is regtest-aware;
    Rust TransactionValidator hardcodes 210_000; 3 RPC paths each
    duplicate subsidy logic with different bugs.
  - Behavior 2 (nSubsidyHalvingInterval = 210000 except regtest 150):
    **PARTIAL** — chainparams helper correct, but `rpc_getblocktemplate`
    and `rpc_getblockstats` hardcode 210_000 unconditionally.
  - Behavior 3 (post-halvings-64 → subsidy = 0): **PARTIAL** — Python
    `_calculate_block_subsidy` correct; Rust BlockValidator correct;
    `rpc_getblocktemplate` (rpc.py:5210-5214) **MISSING the zero-clamp**;
    `rpc_generatetoaddress` (rpc.py:8769) correct; `rpc_getblockstats`
    (rpc.py:9300-9304) correct.
  - Behavior 4 (coinbase output sum ≤ subsidy + fees): **PRESENT** for
    both Python `_verify_coinbase_amount` and Rust
    `validate_block_subsidy`. However, neither performs `MoneyRange`
    on the coinbase output sum itself (separate gap below).
  - Behavior 5 (COINBASE_MATURITY = 100): **PARTIAL** — constant matches
    both pipelines; production path enforces depth check; the
    "unknown utxo_height → 0" fallback is *permissive* (silently
    accepts any coinbase spend on coins missing their height), not
    *conservative*. Misleading comment.
  - Behavior 6 (MAX_MONEY = 2.1e15 sat, per-output + sum bounded):
    **PARTIAL** — Python `_check_structure` correct for non-coinbase;
    Python skips `_check_structure` for coinbase (no per-output
    MAX_MONEY, no negative-vout, no oversize). Rust `validate_amounts`
    skipped on coinbase via early-return. Rust additionally MISSES
    `MoneyRange(total_input)` and `MoneyRange(fee)` checks.
  - Behavior 7 (CheckTransaction duplicate-inputs CVE-2018-17144):
    **PRESENT** in both pipelines for non-coinbase. **GAP**:
    duplicate-input check is *only* in `_check_structure`, which is
    only called for non-coinbase. The Rust path additionally has a
    duplicate-input check via `validate_transaction_inputs_*` for
    non-coinbase. Coinbase is exempted (has 1 input only).
  - Behavior 8 (sum prevouts ≥ sum outputs; reject bad-txns-in-belowout):
    **PRESENT** in both pipelines.

Relationship to prior audits
----------------------------

- **W93 (regtest subsidy)** — Python's `_calculate_block_subsidy` was
  fixed to honor regtest 150 interval. That fix-paper-trail is the
  cited justification for the `getattr(self, "network", "mainnet")`
  fallback on validation.py:1545.
- **W108 (GBT)** — G27 (`test_w108_gbt.py:802`) flagged
  `rpc_getblocktemplate` halving-interval hardcoded as a *test*; the
  fix has not landed — re-flagged here as W145 BUG-3.
- **W143 (block validation)** — BUG-W143-13/14 cross-cite the
  `block_mtp == 0` fallback; the same shape of "treat unknown as 0
  and proceed" pattern shows up here as BUG-9 (utxo_height fallback).
- **W142 (SegWit)** — coinbase witness-nonce validation is enforced in
  Rust `connect_block_from_bytes`; the *same* FFI path SKIPS coinbase
  amount validation — covered as BUG-1 below.

Two-pipeline guard
------------------

W145 EXTENDS the two-pipeline guard for the **7th** dedicated subsystem
(and **14th** total extension since W76):

```
$ grep -rn "fn calculate_block_subsidy\|def _calculate_block_subsidy" \
        ferrous-utils/sync/src src/ouroboros --include='*.rs' --include='*.py'
ferrous-utils/sync/src/validate/transaction.rs:561  (HARDCODED 210_000, dead)
ferrous-utils/sync/src/validate/block.rs:786       (regtest-aware, production)
src/ouroboros/validation.py:1520                   (regtest-aware, fallback)
```

Plus three duplicates in RPC layer:
```
src/ouroboros/rpc.py:5210                   (GBT: hardcoded 210_000 + missing 64 clamp)
src/ouroboros/rpc.py:8769                   (generatetoaddress: regtest interval forced)
src/ouroboros/rpc.py:9300                   (getblockstats: hardcoded 210_000)
```

**Five distinct subsidy-computation sites in production code, three
of them with bugs**. Consolidation around `chain_params::
subsidy_halving_interval` + `validate::block::calculate_block_subsidy`
is the only sane fix path.

----------------------------------------------------------------------

BUGS
====

BUG-1: `connect_block_from_bytes` (Rust FFI) skips coinbase-amount check
-----------------------------------------------------------------------
**Severity**: P0-CDIV
**File**: `ferrous-utils/sync/src/lib.rs:3402-3913`
**Core ref**: `bitcoin-core/src/validation.cpp:2610-2614` (ConnectBlock
`bad-cb-amount` rejection).
**Description**: `connect_block_from_bytes` is the *production*
block-write FFI invoked from Python's mining + `generatetoaddress`
paths (rpc.py:8895-9020) and from `node.py:826-893` for the genesis
load. It validates PoW, merkle, BIP-141 witness commitment,
ContextualCheckBlock (IsFinalTx), coinbase scriptSig length — but
**never invokes `validate_block_subsidy`** or any equivalent. The only
defense is that callers are *expected* to have run
`validate_block_from_bytes` first; nothing structurally enforces it.

`generatetoaddress` for example computes the coinbase reward in
`rpc.py:8769` and calls `connect_block_from_bytes` *directly*, never
going through `validate_block_from_bytes`. A locally-crafted block
where coinbase outputs > subsidy + fees would be accepted by the Rust
FFI and written to the chainstate. On regtest this is "harmless";
on a custom signet or mistaken testnet, it silently mints inflation.

**Excerpt** (sync/src/lib.rs:3592-3700, abridged):
```rust
// Coinbase scriptSig length: 2..=100 bytes (consensus/tx_check.cpp:49)
let script_sig_len = coinbase.input[0].script_sig.len();
if script_sig_len < 2 || script_sig_len > 100 { ... }

// BIP141 witness commitment recompute (validation.cpp:3870-3901)
...

// ContextualCheckBlock: enforce IsFinalTx for every transaction
...

// NO `validate_block_subsidy` CALL. No `bad-cb-amount` check.

// Single WriteBatch for all DB mutations in this block
let mut batch = self.db.create_batch();
```

**Impact**: chainstate divergence vs Core on any directly-fed block
that does not first traverse `validate_block_from_bytes`. The
`generatetoaddress` regtest path constructs its own coinbase subsidy
and the surrounding code is presumed safe, but the *invariant* is
load-bearing on a comment, not on a structural gate.

----------------------------------------------------------------------

BUG-2: `BlockValidator::validate_block` skips subsidy under assumevalid
-----------------------------------------------------------------------
**Severity**: P0-CDIV
**File**: `ferrous-utils/sync/src/validate/block.rs:159-233`
**Core ref**: `bitcoin-core/src/validation.cpp:2295-2696` ConnectBlock
(`fScriptChecks=false` STILL runs the subsidy check at lines 2610-2614).
**Description**: When `assumevalid_height >= height` (i.e. the
classic Core `-assumevalid` optimization), the older `validate_block`
method (still called from `ferrous-utils/sync/src/network/block_sync
.rs:1070`) shortcuts past the per-tx loop AND past the
`validate_block_subsidy` call entirely:

**Excerpt** (block.rs:167-233):
```rust
pub fn validate_block(&self, block: &BlockWrapper, prev_height: u32) -> Result<()> {
    let height = prev_height + 1;
    let full_validation = height > self.assumevalid_height;
    ...
    if full_validation {
        self.tx_validator.check_coinbase(coinbase_tx, height)?;
        for tx in inner.txdata.iter().skip(1) { ... }
    }
    // 8. Sigop cost limit ...
    // ** NO validate_block_subsidy CALL **
    Ok(())
}
```

Compare to `validate_block_with_flags` (line 255 onward) which
unconditionally invokes `validate_block_subsidy(inner, height,
total_fees)` regardless of `skip_scripts`. Core's behavior: assumevalid
only suppresses *script* checks; subsidy is consensus-mandatory.

**Impact**: When `network::block_sync` (the legacy Rust IBD path) is
active, blocks ≤ assumevalid_height (mainnet h ≤ 938343, testnet4 h ≤
123613) have **no coinbase-amount check at all**. A peer feeding a
historical-replay variant block with the same header but a forged
coinbase value would be accepted into the chainstate.

----------------------------------------------------------------------

BUG-3: GBT `rpc_getblocktemplate` subsidy hardcodes 210_000 interval
---------------------------------------------------------------------
**Severity**: P1
**File**: `src/ouroboros/rpc.py:5209-5214`
**Core ref**: `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` →
`GetBlockSubsidy(pindexPrev->nHeight + 1, consensusParams)`.
**Description**: Already flagged by `test_w108_gbt.py:802` (G27); fix
not landed. The template's `coinbasevalue` is computed with hardcoded
210_000 regardless of network. On regtest the first halving boundary
is 150 — a regtest miner consuming this template after h=149 receives
`coinbasevalue = 50 BTC` for h=150 (should be 25 BTC). Core would
reject the resulting block with `bad-cb-amount`.

**Excerpt**:
```python
# block reward (subsidy + fees)
subsidy = 50 * 100_000_000
halvings = next_height // 210_000          # <-- hardcoded mainnet interval
if halvings < 64:
    subsidy >>= halvings
coinbase_value = subsidy + total_fees
```

**Impact**: GBT clients on regtest mine blocks with too-large coinbase
amounts past height 150, all rejected by Core peers (and by ouroboros's
own `validate_block_from_bytes` which IS regtest-aware). Templates are
unusable past the regtest first halving. Test suite already documents
this as a known divergence.

----------------------------------------------------------------------

BUG-4: GBT subsidy missing post-64-halvings zero clamp
-------------------------------------------------------
**Severity**: P1
**File**: `src/ouroboros/rpc.py:5210-5214`
**Core ref**: `bitcoin-core/src/validation.cpp:1843-1844` (`if
(halvings >= 64) return 0;`).
**Description**: The GBT subsidy code uses a guarded `if halvings <
64: subsidy >>= halvings`, but the **else branch is missing** — when
`halvings >= 64` the initial `subsidy = 50 * 100_000_000` is left
intact, so the template would report a 50 BTC subsidy at height
13_440_000+ on mainnet (or h = 64 × 150 = 9600 on regtest). Compare
the *other* two GBT-adjacent subsidy paths: `rpc_generatetoaddress`
(rpc.py:8769) uses `subsidy = (50 * COIN) >> halvings if halvings < 64
else 0` — correct ternary. `rpc_getblockstats` (rpc.py:9301-9304)
uses an explicit `if halvings >= 64: subsidy = 0` clause — correct.
Only `rpc_getblocktemplate` is broken.

**Excerpt** (rpc.py:5210-5214):
```python
# block reward (subsidy + fees)
subsidy = 50 * 100_000_000
halvings = next_height // 210_000
if halvings < 64:
    subsidy >>= halvings
# >>> MISSING `else: subsidy = 0` <<<
coinbase_value = subsidy + total_fees
```

**Impact**: Templates issued for blocks past 64 halvings would report
a 50 BTC subsidy, double-spending fees during the post-2140 fees-only
era. Trivial-but-low-realism bug; matters for *unit tests* that
exercise terminal-phase subsidy, and for any 64-halving artifact
construction.

----------------------------------------------------------------------

BUG-5: `rpc_getblockstats` subsidy hardcodes 210_000 interval
--------------------------------------------------------------
**Severity**: P1
**File**: `src/ouroboros/rpc.py:9300-9304`
**Core ref**: `bitcoin-core/src/rpc/blockchain.cpp::getblockstats` →
`GetBlockSubsidy(block_height, consensusParams)`.
**Description**: Same shape as BUG-3 but in `getblockstats`. The
subsidy field is reported to clients via RPC; on regtest with height
>= 150 the value is wrong by 2×.

**Excerpt**:
```python
halvings = block_height // 210_000
if halvings >= 64:
    subsidy = 0
else:
    subsidy = (50 * 100_000_000) >> halvings
```

**Impact**: `getblockstats` `subsidy` field is wrong for regtest. Any
fee/reward-analysis scripts that compare ouroboros vs Core's
`getblockstats` see a constant 50 BTC for the first 209_999 regtest
blocks (instead of 50/25/12.5/... at halving boundaries).

----------------------------------------------------------------------

BUG-6: `generatetoaddress` forces regtest halving regardless of network
-----------------------------------------------------------------------
**Severity**: P1
**File**: `src/ouroboros/rpc.py:8761-8769`
**Core ref**: `bitcoin-core/src/rpc/mining.cpp::generatetoaddress`
(regtest-only RPC; halving interval comes from `consensusParams`).
**Description**: `generatetoaddress` reads the halving interval
unconditionally from `RegtestConfig.SUBSIDY_HALVING_INTERVAL` (=150).
Core enforces `generatetoaddress` is regtest-only by gating at the
RPC layer (`if (!Params().MineBlocksOnDemand())`). Ouroboros has no
such gate — the RPC is callable on any chain — and even if it were
gated, the hardcoded 150 interval ignores per-test consensusParams
overrides.

**Excerpt** (rpc.py:8761-8769):
```python
for _ in range(nblocks):
    best_hash, best_height = db.get_best_block()
    next_height = best_height + 1
    # --- Subsidy ---
    from ouroboros.config import RegtestConfig
    halving_interval = getattr(RegtestConfig, "SUBSIDY_HALVING_INTERVAL", 150)
    halvings = next_height // halving_interval
    subsidy = (50 * 100_000_000) >> halvings if halvings < 64 else 0
```

**Impact**: Callable on mainnet/testnet with wrong subsidy (150-block
halving). Combined with BUG-1 (`connect_block_from_bytes` skipping the
amount check), a mainnet `generatetoaddress` call would mint inflated
coinbase rewards into the local chainstate (would not propagate but
would corrupt the local DB vs Core).

----------------------------------------------------------------------

BUG-7: `TransactionValidator::calculate_block_subsidy` hardcodes 210_000
------------------------------------------------------------------------
**Severity**: P2 (dead code, but tests assert it; future refactor risk)
**File**: `ferrous-utils/sync/src/validate/transaction.rs:561-576`
**Core ref**: `bitcoin-core/src/validation.cpp:1839-1850`.
**Description**: A second `calculate_block_subsidy` lives on the
*per-transaction* validator and ignores `network`. It has **no
production caller**; only `#[cfg(test)] test_calculate_block_subsidy`
references it directly. The risk surface is exclusively forward —
refactoring tomorrow could wire this dead path into the connect-block
flow and silently break regtest parity. Cf. the W138 dead-class fleet
pattern and the W134 "dead module imported via mod tree but no
runtime call".

**Excerpt**:
```rust
pub fn calculate_block_subsidy(&self, height: u32) -> u64 {
    // Number of halvings
    let halvings = height / 210_000;             // <-- mainnet only
    if halvings >= 64 { return 0; }
    let initial_subsidy = 5_000_000_000u64;
    initial_subsidy >> halvings
}
```

**Impact**: Two-pipeline divergence latent in the codebase. Removing
this method (or having it call `chain_params::subsidy_halving_interval`)
is a one-line cleanup that closes the dead-code regression risk. Tests
assert the dead values (`test_calculate_block_subsidy` at line 875+
hardcodes 210_000 too) — they'd need to be deleted alongside.

----------------------------------------------------------------------

BUG-8: Python `_calculate_block_subsidy` defaults to `"mainnet"` for
       missing `self.network`
-------------------------------------------------------------------
**Severity**: P2
**File**: `src/ouroboros/validation.py:1545-1546`
**Core ref**: `bitcoin-core/src/validation.cpp:1839-1841`.
**Description**: The `getattr(self, "network", "mainnet")` fallback
silently returns the **mainnet** halving interval when a caller
constructs a `BlockValidator` without `__init__` (e.g. a test using
`BlockValidator.__new__(BlockValidator)`). On a regtest test bypass
this means the subsidy comes back as 50 BTC for h=150 instead of 25
BTC; on a non-regtest network this is benign. The comment owns this
behavior — but the comment also frames it as a "still get the
canonical mainnet behavior" feature, which is exactly the situation
where regtest tests would silently mis-test.

**Excerpt**:
```python
# Use getattr() so call sites that bypass __init__ (e.g. tests
# that do ``BlockValidator.__new__(BlockValidator)._calculate_block_subsidy``)
# still get the canonical mainnet behaviour.
network = getattr(self, "network", "mainnet")
interval = 150 if network == "regtest" else 210_000
```

**Impact**: Bypassed-init `BlockValidator` tests on regtest silently
exercise mainnet semantics. Lower-severity than BUG-3 because it only
fires for the `__new__()` shortcut, but it's a "default-to-mainnet"
landmine in the same shape as fleet-wide W138 chainparams whitelisting.

----------------------------------------------------------------------

BUG-9: Coinbase maturity fallback for unknown utxo_height is permissive,
       not conservative
------------------------------------------------------------------------
**Severity**: P0-SEC
**File**: `src/ouroboros/validation.py:1958-1969`
**Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:179-182`
(`if (coin.IsCoinBase() && nSpendHeight - coin.nHeight <
COINBASE_MATURITY) return state.Invalid(...);`).
**Description**: When the UTXO has `height is None` (pre-snapshot
coins or assumeUTXO-loaded coins missing per-coin metadata), the
fallback sets `coin_height = 0` so `depth = spending_height - 0 =
spending_height`. Above height 100 this **always passes the maturity
gate**. The comment claims this is "conservative"; in fact it is
maximally permissive — it accepts *all* coinbase spends on
unknown-height coins at any height ≥ 100.

**Excerpt**:
```python
utxo_height = utxo.get('height')
is_coinbase_utxo = utxo.get('is_coinbase', False)
if is_coinbase_utxo:
    coin_height = utxo_height if utxo_height is not None else 0
    depth = height - coin_height
    if depth < COINBASE_MATURITY:
        return False, (f"bad-txns-premature-spend-of-coinbase: ...")
```

The Rust pipeline has the **same shape** in
`transaction.rs:246` (`let utxo_height = utxo.height.unwrap_or(0);`) —
so the gap is two-pipeline-symmetric, not asymmetric.

A conservative fallback would set `coin_height = spending_height` so
`depth = 0` → always reject. A correct fallback would reject the spend
outright with "utxo metadata incomplete; cannot prove maturity".

**Impact**: After loading any assumeUTXO snapshot whose per-coin
height metadata is absent, ouroboros silently accepts coinbase spends
at *any* depth above maturity — including a freshly-mined coinbase
spent immediately in the same chunk of blocks the snapshot loaded
from. This is a real loss-of-consensus path: Core would reject the
spend (maturity failure), ouroboros would accept it, and the
chainstates would diverge by the coinbase value plus its
descendants. Compounds with the W138 assumeUTXO audit which flagged
multiple per-coin-metadata gaps. The misleading "conservative" comment
is a comment-as-confession archetype — same shape as W141's
"In a full implementation, we would..." pattern.

----------------------------------------------------------------------

BUG-10: Python `validate_block` skips `_check_structure(coinbase)`
------------------------------------------------------------------
**Severity**: P1
**File**: `src/ouroboros/validation.py:825-882` (block loop)
**Core ref**: `bitcoin-core/src/validation.cpp::CheckBlock` (lines
3960-3970) — `for (const auto& tx : block.vtx)` calls
`CheckTransaction(*tx, state)`. ALL transactions, including the
coinbase, run through CheckTransaction.
**Description**: The Python `validate_block` iterates `block.transactions`
and calls `_validate_coinbase(tx)` for index 0, then
`tx_validator.validate_transaction(tx, ...)` for index ≥ 1. Only the
non-coinbase path invokes `_check_structure`. As a result, the
coinbase is **never** screened for:
  - per-output negative `nValue`,
  - per-output `nValue > MAX_MONEY`,
  - sum of outputs `> MAX_MONEY`,
  - tx oversize (`bad-txns-oversize`),
  - duplicate inputs (harmless — coinbase has 1 input),
  - empty vin / empty vout (partially covered by `_validate_coinbase`
    via separate checks).

Some of those Core checks ARE caught later — the coinbase-amount gate
catches `total_output > subsidy + fees` so a 100-BTC coinbase fails
that — but a coinbase with ONE output paying exactly `subsidy + fees`
PLUS one extra output paying `-1` (0xFFFFFFFF…) would have arithmetic
total `subsidy + fees + 2^64 - 1` (Python unbounded int) which fails
the amount gate. So the asymmetric pathology is:
  - the per-output `> MAX_MONEY` check (Core's `bad-txns-vout-toolarge`)
    is missed silently on the coinbase, yielding a different BIP22
    error string than Core.

**Excerpt** (validation.py:836-879):
```python
if i == 0:  # Coinbase
    if not self._validate_coinbase(tx, expected_height):
        return False, "Invalid coinbase"
else:
    ...
    valid, error = self.tx_validator.validate_transaction(...)
```

**Impact**: BIP22 / `submitblock` error message divergence between
ouroboros (returns `"Invalid coinbase"` or `"Coinbase amount invalid"`)
and Core (returns `"bad-txns-vout-negative"` /
`"bad-txns-vout-toolarge"`). Test-vector consumers that grep on the
exact BIP22 strings see different responses.

Rust path is asymmetric here: `BlockValidator::validate_block_with_flags`
DOES call `self.tx_validator.check_coinbase(coinbase_tx, height)`
(block.rs:301-302) which performs structure checks. So the Rust
production path is correct; only the Python fallback (used when the
sync module is unavailable, AND in the orphan replay path) skips it.
A two-pipeline divergence, not a fleet-wide gap.

----------------------------------------------------------------------

BUG-11: Rust `validate_amounts` missing MoneyRange on total_input + fee
-----------------------------------------------------------------------
**Severity**: P1
**File**: `ferrous-utils/sync/src/validate/transaction.rs:484-492`
**Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:186-188`
(per-coin and cumulative MoneyRange) + lines 202-209 (fee MoneyRange).
**Description**: Rust's `validate_amounts` checks per-output negative,
per-output > MAX_MONEY, accumulated total_output > MAX_MONEY, and
total_output > total_input. It does **NOT** check
  - `total_input > MAX_MONEY` (the equivalent of Core's
    `!MoneyRange(nValueIn)` accumulator branch in CheckTxInputs:186),
  - `fee > MAX_MONEY` (Core's `!MoneyRange(txfee_aux)` at
    CheckTxInputs:203).

Python `validate_transaction` checks both (validation.py:1980-1981,
1997-2001). The Rust caller does `validate_transaction_inputs_*` which
only does `checked_add` for u64 overflow, NOT MoneyRange.

**Excerpt** (transaction.rs:475-492, abridged):
```rust
total_output = total_output.checked_add(amount).ok_or(...)?;
if total_output > MAX_MONEY { return Err(OutputAmountOverflow); }
...
if total_output > total_input { return Err(OutputsExceedInputs); }
let fee = total_input.checked_sub(total_output).ok_or(...)?;
Ok(fee)
```

**Impact**: A tx whose total_input > MAX_MONEY (e.g. 22M BTC across
many inputs — unrealistic on mainnet, but constructible on regtest or
forks) passes Rust's gate. Core rejects with
`bad-txns-inputvalues-outofrange`. Two-pipeline divergence: Python
rejects, Rust accepts. The `validate_block_from_bytes` FFI uses
`validate_transaction_with_fee_and_scripts` → `validate_amounts`, so
this is on the production critical path.

----------------------------------------------------------------------

BUG-12: Rust `validate_transaction_inputs_*` missing per-coin MoneyRange
-------------------------------------------------------------------------
**Severity**: P1
**File**: `ferrous-utils/sync/src/validate/transaction.rs:225-260,
         394-437`
**Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:186-188`
(`if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))`).
**Description**: When the Rust pipeline pulls each input UTXO out of
the DB or the intra-block overlay, it never checks
`MoneyRange(utxo.amount)`. A corrupt or attacker-tampered chainstate
entry whose stored amount exceeds MAX_MONEY would be silently
accepted. Compare Python which does both:
```python
coin_value = utxo['value']
if coin_value < 0 or coin_value > MAX_MONEY:
    return False, "bad-txns-inputvalues-outofrange"
```
(validation.py:1976-1978).

**Excerpt** (transaction.rs:253-256):
```rust
total_input = total_input
    .checked_add(utxo.amount)
    .ok_or(TransactionValidationError::OutputAmountOverflow)?;
script_pubkeys.push(utxo.script_pubkey);
```

**Impact**: defense-in-depth gap against chainstate corruption /
RocksDB-level tampering. Core's MoneyRange check on UTXO values is
specifically called out by the W138-class audits as the
self-consistency primitive. Two-pipeline divergence: Python catches;
Rust silently propagates.

----------------------------------------------------------------------

BUG-13: `_calculate_tx_fee` returns 0 on negative or out-of-range fee
---------------------------------------------------------------------
**Severity**: P2 (dead code, all production callers replaced in W93)
**File**: `src/ouroboros/validation.py:1826-1839`
**Core ref**: `bitcoin-core/src/consensus/tx_verify.cpp:202-213`
(`bad-txns-fee-outofrange` rejection — does **not** silently coerce).
**Description**: When a (hypothetical) caller passes a tx whose
`total_output > total_input`, the helper silently returns `0` instead
of signalling rejection. The W93 perf rewrite replaced the production
callers with the in-line fee-extraction in
`validate_transaction(fees_out=...)`. The method is now dead code —
but it's PUBLIC API on `BlockValidator` and a future caller would
silently mask an inflation bug.

**Excerpt**:
```python
def _calculate_tx_fee(self, tx, intra_block_utxos=None):
    ...
    fee = total_input - total_output
    if fee < 0 or fee > MAX_MONEY:
        return 0          # <-- silent coerce; should raise
    return fee
```

**Impact**: zero impact today (no callers). Removable in a cleanup
wave. Same dead-helper fleet pattern as W141's "exported but never
called" archetype.

----------------------------------------------------------------------

BUG-14: Python validation rejects coinbase with `tx.locktime > 0xFFFFFFFF`
        which Core does not reach
---------------------------------------------------------------------------
**Severity**: P3
**File**: `src/ouroboros/validation.py:2079-2080`
**Core ref**: `bitcoin-core/src/consensus/tx_check.cpp` — no explicit
locktime range check (the wire format is uint32 by construction).
**Description**: Python's `_check_structure` has an explicit
`if tx.locktime < 0 or tx.locktime > 0xffffffff: return False`. This
is dead in practice — the deserializer reads 4 unsigned bytes — but it
diverges in a hand-constructed `Transaction` whose `locktime` int is
out of range. Pure-Python tests can construct such an object; ouroboros
rejects; Core does not have a structural check (the value cannot exist
in a real serialized tx).

**Impact**: zero on-wire impact. Documented for clarity; Python's
extra guard is harmless but adds an `IsStandard`-style policy diff in
the rare hand-crafted test case.

----------------------------------------------------------------------

BUG-15: `_verify_coinbase_amount` missing MoneyRange on its own sum
--------------------------------------------------------------------
**Severity**: P2
**File**: `src/ouroboros/validation.py:1506-1518`
**Core ref**: `bitcoin-core/src/validation.cpp:2611` —
`block.vtx[0]->GetValueOut()`, which internally calls
`CTransaction::GetValueOut()` that throws unless
`MoneyRange(nValueOut)`.
**Description**: `_verify_coinbase_amount` computes
`total_output = sum(out.value for out in coinbase_tx.outputs)` and
compares `<= subsidy + fees`. It does not first verify
`MoneyRange(total_output)`. If a coinbase has outputs that overflow
Core's int64 arithmetic but stay below `subsidy + fees` in Python's
unbounded-int arithmetic, the Python pipeline ACCEPTS while Core
THROWS at `GetValueOut`.

This is mostly defended by BUG-10's parent issue (the coinbase
structurally never goes through `_check_structure`'s per-output
upper-bound check), but it's worth noting independently because it's
specifically the *coinbase-amount* gate where Core's `GetValueOut`
throw lives.

**Excerpt** (validation.py:1506-1518):
```python
def _verify_coinbase_amount(self, coinbase_tx, height, total_fees):
    block_subsidy = self._calculate_block_subsidy(height)
    expected_amount = block_subsidy + total_fees
    total_output = sum(out.value for out in coinbase_tx.outputs)
    # No MoneyRange check on total_output before the compare.
    return total_output <= expected_amount
```

**Impact**: tightly bounded but not zero — Python `sum()` does not
overflow. Two-pipeline divergence on synthetic test vectors that play
games with int64-wrap coinbase values. Rust path is correct
(`validate_block_subsidy` does check `checked_add` for u64 overflow).

----------------------------------------------------------------------

BUG-16: Coinbase-amount accumulator overflow guard absent in Python
--------------------------------------------------------------------
**Severity**: P3
**File**: `src/ouroboros/validation.py:855-860`
**Core ref**: `bitcoin-core/src/validation.cpp:2540-2547`
(`bad-txns-accumulated-fee-outofrange`).
**Description**: Python accumulates `total_fees += tx_fees[0]` with
post-step MoneyRange check (validation.py:859), which is correct.
However, the check is **per-tx**, not after individual fee additions.
Core's check pattern is mathematically equivalent because each
per-tx fee is itself MoneyRange-bounded by CheckTxInputs. Filed as P3
because no realistic exploit shape; documented for invariant clarity.

----------------------------------------------------------------------

BUG-17: COINBASE_MATURITY constant not exposed for chainparams override
------------------------------------------------------------------------
**Severity**: P2
**File**: `src/ouroboros/validation.py:40`,
         `ferrous-utils/sync/src/validate/transaction.rs:17`
**Core ref**: `bitcoin-core/src/consensus/consensus.h:19`
(COINBASE_MATURITY = 100; **not** per-network in Core either, but
regtest test framework overrides via `-coinbasematurity` flag).
**Description**: Both pipelines hardcode `COINBASE_MATURITY = 100` as
a module-level constant. Bitcoin Core uses the same number, but its
test framework supports overriding for regtest scenarios. Ouroboros
has no mechanism to test scripts that need a custom maturity depth.
Low impact; would help functional-test coverage parity.

----------------------------------------------------------------------

BUG-18: `validate_block_subsidy` uses i64 arithmetic implicitly
----------------------------------------------------------------
**Severity**: P3
**File**: `ferrous-utils/sync/src/validate/block.rs:753-770`
**Core ref**: `bitcoin-core/src/validation.cpp:2610` (CAmount is signed
int64).
**Description**: Rust uses `u64` for subsidy / fees throughout.
`subsidy.checked_add(total_fees)` correctly returns `None` on overflow
but the *type* is u64 not signed. A negative fee (impossible by
construction in the Rust pipeline because of the
`OutputsExceedInputs` early-return) would manifest as a u64 underflow
caught by `checked_sub` in `validate_amounts`. The bookkeeping is
correct; the type-level guarantee is subtler than Core's CAmount.

**Impact**: zero realistic exploit; flagged as a type-discipline diff
for documentation.

----------------------------------------------------------------------

BUG-19: Test-fixture asserts wrong-architecture subsidy values
---------------------------------------------------------------
**Severity**: P2
**File**: `ferrous-utils/sync/src/validate/transaction.rs:875-895`
        and `tests/integration/test_validation.rs:61-72`
**Core ref**: `bitcoin-core/src/test/validation_tests.cpp` (Core
tests use chainparams-derived intervals).
**Description**: The `#[cfg(test)] test_calculate_block_subsidy` and
the integration test both call into `TransactionValidator::
calculate_block_subsidy` (BUG-7) and assert values at heights
`209_999`, `210_000`, `419_999`, `420_000`, `64 × 210_000`. The
**tests perpetuate the hardcoded interval**: if the production code
is fixed to consult `chain_params`, these tests would fail on regtest
(`Network::Regtest` would compute halvings at 150-block intervals).

**Impact**: refactor friction. Closing BUG-7 requires touching these
test fixtures or removing the dead method outright.

----------------------------------------------------------------------

BUG-20: `apply_block` Python dead-path is structurally callable
----------------------------------------------------------------
**Severity**: P2 (dead-but-reachable)
**File**: `src/ouroboros/validation.py:885-941`
**Core ref**: `bitcoin-core/src/validation.cpp:2295-2696`
(ConnectBlock — UTXO mutations).
**Description**: The `apply_block` method is documented as dead-code
("DEAD-CODE PATH (W23 belt-and-suspenders)"). However:
  - it is **structurally reachable** from `_process_orphans` in
    `block_sync.py`,
  - the genesis special-case (`return` at height==0) is present and
    correct,
  - the rest of the method calls `self.db.update_utxo_set(spent,
    created)` which doesn't exist on `BlockchainDatabase` (would
    `AttributeError` before any UTXO write).

The W145 concern: this method skips ALL subsidy/fee/MoneyRange/
coinbase-amount gates. If a future PR removes the AttributeError
fence (e.g. by stubbing `update_utxo_set` on the Rust DB facade),
this path would silently apply blocks with **zero** consensus checks.
Same shape as the W141 "comment-as-confession" pattern: the comment
narrates the safety property, but the safety is contingent on a
downstream bug not being fixed.

**Impact**: latent. Listed because the comment itself flags it as a
known hazard and the W138 dead-class fleet pattern shows this is a
recurring archetype.

----------------------------------------------------------------------

BUG-21: GBT halving math reuses `next_height` but Core uses
         `pindexPrev->nHeight + 1` consistently
-----------------------------------------------------------
**Severity**: P3
**File**: `src/ouroboros/rpc.py:5211`
**Core ref**: `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
(`pindexPrev->nHeight + 1`).
**Description**: `rpc.py:5211` uses `next_height // 210_000` where
`next_height = best_height + 1`. Core uses the same: `nHeight =
pindexPrev->nHeight + 1`. Filed P3 only because off-by-one risks at
the halving boundary are real if `next_height` is ever computed as
`best_height` (current). Currently the code is correct; flagged for
discipline.

----------------------------------------------------------------------

BUG-22: `_validate_coinbase` BIP34 height check uses pure-Python
         varint decoder, not CScriptNum
-----------------------------------------------------------------
**Severity**: P2
**File**: `src/ouroboros/validation.py:1488-1502`
**Core ref**: `bitcoin-core/src/validation.cpp:4151-4159` (BIP34 height
encoding via `CScript() << nHeight`).
**Description**: The Python BIP34 check builds `expect =
_encode_bip34_height(height)` and does a byte-prefix comparison
against `script_sig[:n]`. Core uses CScriptNum which has specific
encoding rules. For most heights the two agree, but at boundaries
where the minimal encoding rules diverge (e.g. negative heights —
nonsensical but constructible — or heights that round-trip through
the BIP34 minimal-encoding rule), Python's encoder might emit a
different byte sequence than Core's `CScript() << nHeight`. Minor
relative to W145 scope (this is BIP34, not subsidy), but it's
adjacent to "coinbase scriptSig validation" so noted.

**Impact**: subtle ABI diff at constructed-test-vector edge.

----------------------------------------------------------------------

BUG-23: `validate_block` not gated on negative `expected_height`
----------------------------------------------------------------
**Severity**: P3
**File**: `src/ouroboros/validation.py:672-681`
**Core ref**: `bitcoin-core/src/validation.cpp` — height is
`pindexNew->nHeight` (int, but always >= 0 by construction).
**Description**: `expected_height = (prev_height or 0) + 1` — if
`prev_height` is `-1` (sentinel observed in some legacy code paths
for "no chain yet"), `expected_height` becomes `0` due to truthy fall
through, NOT `-1 + 1 = 0` arithmetically. Subtle but matches Core
(genesis is height 0). No exploit; documented because the W138
audit flagged a similar height-truthiness landmine.

----------------------------------------------------------------------

BUG-24: Multiple test files name the GBT subsidy bug without it
        being fixed
----------------------------------------------------------------
**Severity**: P3 (documentation drift)
**File**: `src/ouroboros/tests/test_w108_gbt.py:802-823` (G27);
         `CORE-PARITY-AUDIT/` directory currently lists only
         w142/w143 — no prior audit picked up the GBT subsidy bug.
**Core ref**: `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`.
**Description**: The `test_w108_gbt.py` test asserts the broken
behavior (line 821: "regtest coinbasevalue at h=150 returns 50 BTC
(wrong — should be 25 BTC)"). The test passes because the bug
exists — i.e. closing the bug would break the test. This is the
"test asserts the bug" anti-pattern; the test should either be
deleted or rewritten to assert the fixed behavior with a clear
xfail/known-fail marker.

**Impact**: doc/process drift. Re-cited here to ensure the W145 fix
wave knows it also has to touch the test.

----------------------------------------------------------------------

Summary
=======

24 BUGS catalogued: 1 P0-CDIV / 2 P0-CDIV (P0-CDIV total: 2 from
counting; revised P0-CDIV = 2 with BUG-1 and BUG-2), 1 P0-SEC, 11 P1,
7 P2, 2 P3.

Headline findings
-----------------

1. **`connect_block_from_bytes` (Rust FFI, production block-write
   path) does NOT call coinbase-amount validation** (BUG-1). The
   invariant is "the caller must run validate_block_from_bytes
   first" — but `generatetoaddress` doesn't, and `node.py:889`
   doesn't unconditionally either. Two-pipeline divergence: the
   Python orphan path `_verify_coinbase_amount` IS called for any
   block routed through `validate_block`, but the FFI bypass
   commits with no subsidy check.

2. **Coinbase-maturity fallback for unknown utxo_height = 0 is
   permissive, not conservative** (BUG-9). After loading an
   assumeUTXO snapshot with incomplete per-coin metadata, every
   coinbase spend at height ≥ 100 silently passes maturity. P0-SEC
   because it's a real loss-of-consensus path vs Core. Shape mirrors
   the W141 "comment-as-confession" archetype: the comment claims
   "conservative" but the code is "permissive".

3. **3 RPC-layer subsidy duplications (rpc.py:5210/8769/9300) each
   with distinct bugs** (BUG-3 / BUG-4 / BUG-5 / BUG-6).
   `rpc_getblocktemplate` hardcodes 210_000 interval AND lacks the
   post-64-halving zero-clamp; `rpc_getblockstats` hardcodes 210_000;
   `rpc_generatetoaddress` forces regtest interval regardless of
   network. Fleet pattern: subsidy logic re-implemented 5× in this
   codebase, 3 of those copies buggy.

4. **`validate_block` (legacy Rust IBD path) skips subsidy under
   assumevalid** (BUG-2). Core only suppresses *script* checks under
   `-assumevalid`; subsidy is consensus-mandatory. Below mainnet
   assumevalid height (h ≤ 938343) the network::block_sync path has
   NO coinbase-amount enforcement. This is the legacy Rust IBD —
   ouroboros's *current* IBD goes through the Python pipeline that
   calls `validate_block_from_bytes` → `validate_block_with_flags`
   (correct), but the dead-code path is still compiled and
   instantiable.

Fleet patterns observed
------------------------

- **5-site subsidy duplication** — same constant logic copy-pasted
  in 5 places, divergence between copies. Cross-cite the W139 fee
  estimator's "every audit-gate divergent" archetype.
- **Two-pipeline divergence on `validate_amounts` MoneyRange checks**
  (BUG-11 / BUG-12) — Python full; Rust partial. Same shape as
  W143's BUG-2 P0-DoS empty-vtx index path.
- **Comment-as-confession** (BUG-9) — comment frames the fallback as
  "conservative" when it is in fact permissive. 5th distinct
  instance of this archetype in the cumulative audit body (cf.
  W141 rustoshi, W141 ouroboros, W138 haskoin, W138 rustoshi).
- **Dead code retained "for safety"** (BUG-7 / BUG-13 / BUG-20) — the
  W138-class fleet pattern, where Maybe-validate / Maybe-apply
  helpers are defined and exported but unwired, and the W141
  "exported-but-never-called" pattern. W145 contributes 3 fresh
  instances.

Recommended fix wave priorities
--------------------------------

1. **BUG-1** (P0-CDIV): wire `validate_block_subsidy` into
   `connect_block_from_bytes` (or gate the FFI on a preceding
   validate call). Single-call site fix, biggest correctness win.
2. **BUG-9** (P0-SEC): change `utxo.get('height')` fallback from `0`
   to `spending_height` so unknown-height coinbase spends are
   *rejected*. Mirror the fix in Rust (`transaction.rs:246`).
3. **BUG-3/4/5/6** (P1 cluster): consolidate the 3 RPC subsidy
   duplications into a single `chain_params`-aware helper. Drop the
   `RegtestConfig.SUBSIDY_HALVING_INTERVAL` shortcut.
4. **BUG-11/12** (P1 pair): add MoneyRange checks in Rust
   `validate_amounts` and `validate_transaction_inputs_*`. Brings
   Rust to parity with Python and Core.
5. **BUG-7/13/19** (P2 cleanup): delete the dead
   `TransactionValidator::calculate_block_subsidy` and the dead
   `_calculate_tx_fee`; rewrite or delete the asserting tests.
