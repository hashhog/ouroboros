W130 — BIP-125 wallet feebumper Rule 3 + RBF rules 1-5 enforcement (ouroboros)
==============================================================================

Date: 2026-05-17
Impl: ouroboros (Python pipeline only; ferrous-utils Rust crate does not
serve wallet/feebumper or mempool RBF)
Wave: W130 BIP-125 wallet feebumper Rule 3 — precise
`incrementalRelayFee.GetFee(maxTxSize)` invariant + Rule 1-5 surface in
the **wallet** path (DISCOVERY)
Reference:
  - `bitcoin-core/src/wallet/feebumper.cpp` (`PreconditionChecks`,
    `CheckFeeRate`, `EstimateFeeRate`, `CreateRateBumpTransaction`,
    `CommitTransaction`)
  - `bitcoin-core/src/wallet/feebumper.h` (`SignatureWeights` /
    `CalculateMaximumSignedTxSize` consumer)
  - `bitcoin-core/src/policy/rbf.cpp` (`IsRBFOptIn`, `PaysForRBF`,
    `GetEntriesForConflicts`, `EntriesAndTxidsDisjoint`,
    `ImprovesFeerateDiagram`)
  - `bitcoin-core/src/policy/rbf.h` (`MAX_REPLACEMENT_CANDIDATES`)
  - `bitcoin-core/src/policy/feerate.cpp` (`CFeeRate::GetFee` —
    `EvaluateFeeUp`, round-up semantics)
  - BIP 125 rules 1-5
  - Related prior wave: W120 (mempool RBF rules 1-5 from the
    `validation.cpp` side — covers `Mempool.try_replace`; W130 looks at
    the **wallet** side that proposes the replacement)

Status: **30 gates audited — PRESENT 4 / PARTIAL 6 / MISSING 20.
**22 BUGS** (3 P0-CDIV / 11 P1 / 8 P2).

Relationship to W120 / W129
---------------------------

- W120 audited the **mempool** side of RBF: `Mempool.try_replace()` in
  `mempool.py:3563` — five rules, plus the cluster-mempool diagram check.
- W129 audited **coin selection** consumed by `send_transaction` and
  (less directly) `bump_fee` for its replacement build.
- W130 audits the **wallet's bumpfee path**: `Wallet.bump_fee()` in
  `wallet.py:1467`, `Wallet._add_input_for_fee()` in `wallet.py:1676`,
  and the RPC entry points `Rpc.rpc_bumpfee` and `Rpc.rpc_psbtbumpfee`
  in `rpc.py:8974` / `rpc.py:9062`. The path that submits the
  replacement back into the mempool is covered by W120; W130 is
  specifically the pre-submit envelope (Core `feebumper.cpp`).

Two-pipeline guard
------------------

```
$ grep -rn "feebumper\|bumpfee\|bump_fee\|PaysForRBF\|signals_rbf\|\
            CheckFeeRate\|incrementalRelay\|MAX_BIP125_RBF_SEQUENCE" \
       ferrous-utils/  → 0 matches
$ grep -rn "bump_fee\|feebumper\|signals_rbf\|incremental_relay_fee" \
       src/ouroboros/*.py  → all hits in wallet.py / mempool.py / rpc.py
```

**Two-pipeline guard PRESERVED.** No feebumper / RBF code on Rust side.
Test `test_g30_two_pipeline_no_feebumper_in_rust` codifies a
forward-regression assertion on the Rust pipeline, **extending** the
guard set (W76 + W120 + W122 + W125 + W128 + W129 → now W130). If a
future wave adds wallet bumpfee or RBF mechanics to `ferrous-utils`,
this test fails and forces a re-audit.

Top-level architectural findings
--------------------------------

**(F1) Core's `PreconditionChecks` is entirely absent in ouroboros.**
Core `feebumper.cpp:23-57` does six pre-submit checks against the
original tx — bump is rejected before any work if any check fails:

```
1. wallet.HasWalletSpend(wtx.tx)            → INVALID_PARAMETER
2. wallet.chain().hasDescendantsInMempool() → INVALID_PARAMETER
3. wallet.GetTxDepthInMainChain(wtx) != 0   → WALLET_ERROR
4. wtx.mapValue.contains("replaced_by_txid")→ WALLET_ERROR
5. (require_mine) AllInputsMine(wallet, …)  → WALLET_ERROR
6. (later) MarkReplaced(orig, bumped_txid)  → WALLET_ERROR
```

`Wallet.bump_fee` (`wallet.py:1467-1671`) performs **none** of these.
It looks the original up in the mempool, checks the BIP-125 signal,
and builds a replacement. Direct consequences:

- A double-bump (bump A→A2, then bump A→A3) is **allowed by the wallet
  envelope** and only rejected later inside `Mempool.try_replace`
  (which itself only enforces BIP-125 Rule 1-5 — no `mapValue` /
  `replaced_by` bookkeeping). Core stops this at the wallet boundary;
  ouroboros has no equivalent guard.
- A tx already confirmed but still in the mempool view (race between
  block connect and mempool eviction) would be silently bumped.
- A tx with wallet descendants is bumpable; Core rejects to prevent
  orphaning the descendants.
- A bump can re-use inputs that don't belong to the wallet — Core
  refuses because the wallet cannot know the input value (and therefore
  the fee).

The whole `PreconditionChecks` surface is BUG-1 through BUG-5 in this
wave. None are consensus-breaking on their own (because the mempool
catches some downstream), but Rules 1+3 (HasWalletSpend +
GetTxDepthInMainChain) are P0-CDIV: they affect what gets broadcast and
charged to the user.

**(F2) `CheckFeeRate` invariant — the `incrementalRelayFee.GetFee(maxTxSize)`
precise check — is entirely absent.** Core
`feebumper.cpp:60-117` enforces FOUR fee invariants pre-build:

```
inv-A: newFeerate >= mempoolMinFee
inv-B: new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)
                                  ↑                ↑
                                  ↑       ROUND-UP fee for maxTxSize
                                  ↑
                              Rule 4 precise invariant
inv-C: new_total_fee >= GetRequiredFee(wallet, maxTxSize)
inv-D: new_total_fee <= wallet.m_default_max_tx_fee   (-maxtxfee)
```

ouroboros `bump_fee` computes `target_fee = max(int(new_fee_rate *
est_vsize), orig_fee + 1)` (`wallet.py:1559`). Three problems:

1. **No mempool-min-fee check (inv-A)**. `Wallet` does not consult the
   mempool's `dynamic_min_fee()` (which W114 wired). A bump at a feerate
   below the rolling-min is built and submitted — `Mempool.try_replace`
   may then reject for a different reason (Rule 4) or, if the rolling
   minimum is currently low, accept but immediately evict.
2. **`+1`-sat hack replaces `incrementalRelayFee.GetFee(maxTxSize)`
   (inv-B)**. Core's invariant is `old_fee + node_incremental_relay_fee
   * vsize` (vsize is `maxTxSize` — the **maximum** signed size).
   ouroboros uses `orig_fee + 1` — a single satoshi. For a 250-vB tx and
   the Core default incremental_relay_fee of 1000 sat/kvB, the correct
   floor is `orig_fee + 250 sat`. ouroboros is `orig_fee + 1` — 250×
   too lenient. This is the **precise invariant** the wave brief calls
   out and is **BUG-6 / P0-CDIV**: replacements that Core would reject
   under inv-B are accepted by the wallet, then handed to the mempool
   which (post-FIX-72) does correctly enforce Rule 4 on its own — so
   the bug is bounded in effect. **But it changes which feerate gets
   built first**: at orig_fee = 1 000 sat and new_fee_rate = 10 sat/vB,
   ouroboros's target is `max(10 * 250, 1 001) = 2 500 sat` (lucky).
   At orig_fee = 100 000 sat and new_fee_rate = 1 sat/vB, ouroboros's
   target is `max(1 * 250, 100 001) = 100 001 sat`; Core would require
   `100 000 + 1 000 * 250 / 1000 = 100 250 sat`. The 249-sat gap is the
   Rule 4 floor — ouroboros builds a tx that fails Rule 4 then submits
   it, hitting the mempool error path. UX bug; functionally CDIV
   because the wallet's "minimum bumpable fee rate" differs from Core.
3. **No `GetRequiredFee` / `m_default_max_tx_fee` checks (inv-C + inv-D)**.
   ouroboros has no `-maxtxfee` knob; a fat-fingered `fee_rate` arg
   (e.g. `1_000_000`) builds a tx whose fee exceeds the input value and
   would fail signing or burn the wallet. BUG-9 / BUG-10.

**(F3) Wallet rounds DOWN, Core rounds UP.** `CFeeRate::GetFee` uses
`EvaluateFeeUp` (`feerate.cpp:24`) — fractional sat-vB always round up.
ouroboros has two distinct fee rounding sites that round *down* via
integer truncation:

- `target_fee = int(new_fee_rate * est_vsize)` — float * int → int via
  truncation toward zero. At `new_fee_rate=1.5` and `vsize=250`, Core
  computes `375.0 → 375 sat`, ouroboros `int(1.5 * 250) = 375 sat`;
  same here, but at `new_fee_rate=1.1` and `vsize=251`,
  Core: `1.1 * 251 = 276.1` → EvaluateFeeUp → **277 sat**;
  ouroboros: `int(1.1 * 251) = int(276.099…) = 276 sat`.
  One-sat-under bug, BUG-11 / P1. Compounds with BUG-6: a wallet on the
  Rule 4 boundary now under-pays Rule 4 by 1 sat → mempool rejects.

- `bump_fee` always uses `int(new_fee_rate)` (`rpc.py:9013` casts the
  caller's `fee_rate` to int first). This means caller's `fee_rate=1.5`
  becomes `1`. Total-fee disagreement with both Core and the API
  contract (`bumpfee` accepts non-integer feerate). BUG-12 / P1.

**(F4) `EstimateFeeRate` (no-feerate-arg path) is entirely missing.**
Core `feebumper.cpp:119-144` defines: when caller omits `fee_rate`, the
wallet computes a target feerate by:
1. Original-tx feerate + 1 sat/vB (round-up via `feerate += CFeeRate(1)`).
2. Plus `max(node_incremental_relay_fee, WALLET_INCREMENTAL_RELAY_FEE)`
   — explicitly to satisfy Rule 4 against future incremental_relay_fee
   policy changes, and to ensure the replacement is large enough that
   "the total fee will be greater (Rule 3)" — quoted directly from the
   header comment.
3. `max` with `GetMinimumFeeRate` from the wallet's standard
   fee-estimation pipeline.

ouroboros `rpc.py:9007-9011` falls back to either fee_estimator or a
"conservative default bump rate" of **10 sat/vB**. This is unrelated to
the original tx's feerate. For a tx originally paying 50 sat/vB,
ouroboros's default bump is **5× lower** than the original — guaranteed
to fail Rule 3. BUG-7 / P0-CDIV: the *default* path produces tx that
fails BIP-125 Rule 3 absolute-fee check whenever orig_fee_rate > 10
sat/vB (which is the entire fee-spike regime where users *want* to
bump).

**(F5) `MarkReplaced` bookkeeping is absent.** Core
`feebumper.cpp:378-380` calls `wallet.MarkReplaced(orig, bumped_txid)`
after CommitTransaction. ouroboros writes nothing to wallet state about
which tx was bumped. Consequences: (a) double-bump protection
impossible (BUG-2 above); (b) JSON-RPC `gettransaction` returns no
`replaced_by_txid` field (Core does); (c) wallet UI / accounting layers
cannot link the original and replacement. BUG-15 / P1.

**(F6) Sequence selection on the replacement is hardcoded `0xFFFFFFFD`
regardless of original sequence.** `wallet.py:1548` and `wallet.py:1724`
unconditionally set the replacement's sequence to `0xFFFFFFFD` (RBF
signal). Core preserves the original sequence and only adjusts if
needed (and a replacement may itself want to *not* signal — e.g. the
caller wants the replacement to be final). This is a minor UX limit,
not a bug per se, but it also blocks BIP-68 relative-locktime semantics
on the replacement: BIP-68 only triggers when nSequence < 0x80000000
with bit 22 clear; `0xFFFFFFFD` clears bit 31 and bit 22 is set
(0xFFFFFFFD = 0b1111_1111_1111_1111_1111_1111_1111_1101 → bit 22 set
→ BIP-68 disabled). If the original had a relative-locktime input, the
bump silently drops the locktime. BUG-16 / P1.

Per-rule mapping table (Core → ouroboros)
-----------------------------------------

| BIP-125 rule | Core wallet site (`feebumper.cpp`) | Core policy site (`rbf.cpp`) | ouroboros wallet site (`wallet.py`) | ouroboros mempool site (`mempool.py`) | W130 status |
|---|---|---|---|---|---|
| Rule 1 (signal) | line 1493 RBF check pre-build | `IsRBFOptIn` 24-50 | `bump_fee` line 1493 | `signals_rbf` 3514, `is_rbf_opt_in` 3528 | PRESENT (W120 covers mempool side) |
| Rule 2 (no new unconf input) | not in feebumper (line 311 comment) | `validation.cpp::ReplacementChecks` | NOT ENFORCED IN WALLET | `_try_replace_inner` 3661-3684 | wallet-side MISSING (BUG-13) |
| Rule 3 (absolute fee ≥ orig) | line 95 `new_total_fee < minTotalFee` (with inv-B) | `PaysForRBF` 100-112 | `target_fee = max(…, orig_fee+1)` 1559 | `_try_replace_inner` 3731 | PARTIAL: `+1` instead of `incrementalRelayFee.GetFee(maxTxSize)` (BUG-6, P0-CDIV) |
| Rule 4 (incremental relay bandwidth) | line 93 `incrementalRelayFee.GetFee(maxTxSize)` | `PaysForRBF` 117-122 | NOT in wallet — only in mempool | `_try_replace_inner` 3743 | wallet-side MISSING (BUG-6 / BUG-18) |
| Rule 5 (≤ 100 cluster candidates) | not in feebumper | `GetEntriesForConflicts` 58-83 | NOT in wallet | `_try_replace_inner` 3655 | wallet-side MISSING — never previewed (BUG-14) |

Note: BIP-125 rules 2/4/5 in Core are enforced at the mempool side
(`ReplacementChecks`) and **previewed** at the wallet side only via
`CheckFeeRate`'s inv-B. ouroboros has no wallet-side preview at all —
the only signal a caller gets is the mempool-error log line from
`try_replace` after the bump tx has been built & signed. This makes
PSBT bumpfee (`rpc_psbtbumpfee`, line 9062) particularly bad: the
unsigned PSBT is returned even when it would be rejected later — the
external signer wastes effort.

Per-gate audit matrix (30 gates / 22 bugs)
-------------------------------------------

| Gate | Brief | Site | Status | Bug ref |
|------|-------|------|--------|---------|
| G1   | Wallet detects RBF signal pre-build | `wallet.py:1493` | PRESENT | — |
| G2   | Wallet returns specific error when not signaling | 1495-1500 | PRESENT (warning only) | — |
| G3   | Wallet rejects bump of confirmed tx | `bump_fee` | MISSING | BUG-3 (P0-CDIV) |
| G4   | Wallet rejects bump of tx with wallet descendants | `bump_fee` | MISSING | BUG-1 (P0-CDIV) |
| G5   | Wallet rejects bump of tx with mempool descendants | `bump_fee` | MISSING | BUG-2 (P1) |
| G6   | Wallet rejects bump of tx already bumped (`replaced_by_txid`) | `bump_fee` | MISSING | BUG-4 (P1) |
| G7   | Wallet enforces `require_mine` / `AllInputsMine` | `bump_fee` | MISSING | BUG-5 (P1) |
| G8   | `bump_fee` checks newFeerate ≥ mempoolMinFee (inv-A) | `bump_fee` | MISSING | BUG-8 (P1) |
| G9   | `bump_fee` checks new_total_fee ≥ old_fee + incrementalRelayFee.GetFee(maxTxSize) (inv-B, precise) | `wallet.py:1559` | PARTIAL: `+1` sat | BUG-6 (P0-CDIV) — wave hook |
| G10  | `bump_fee` checks new_total_fee ≥ GetRequiredFee (inv-C) | `bump_fee` | MISSING | BUG-9 (P1) |
| G11  | `bump_fee` checks new_total_fee ≤ -maxtxfee (inv-D) | `bump_fee` | MISSING | BUG-10 (P2) |
| G12  | `bump_fee` uses round-up fee (EvaluateFeeUp parity) | 1559 (int truncation) | MISSING | BUG-11 (P1) |
| G13  | `rpc_bumpfee` accepts non-integer fee_rate | `rpc.py:9013` | MISSING | BUG-12 (P1) |
| G14  | Wallet `EstimateFeeRate` (no-feerate-arg) ≥ orig_feerate + 1 sat/vB + incremental | `rpc.py:9007-9011` | MISSING — flat 10 sat/vB | BUG-7 (P0-CDIV) |
| G15  | Wallet checks Rule 2 (no new unconf input) pre-build | wallet | MISSING (delegated to mempool) | BUG-13 (P2) |
| G16  | Wallet checks Rule 5 (≤ 100 cluster) pre-build | wallet | MISSING | BUG-14 (P2) |
| G17  | Wallet calls `MarkReplaced(orig, bumped)` after submit | wallet | MISSING | BUG-15 (P1) |
| G18  | Replacement preserves original sequence semantics (BIP-68) | 1548, 1724 | MISSING — hardcoded 0xFFFFFFFD | BUG-16 (P1) |
| G19  | Wallet returns `errors[]` per BIP-125 contract | `rpc.py:9059` | PARTIAL (empty list) | BUG-17 (P2) |
| G20  | Wallet uses Core `CalculateMaximumSignedTxSize` for vsize | `wallet.py:1554` | MISSING — fixed 68/31/11 vB | BUG-18 (P1) |
| G21  | `bump_fee` plumbs `coin_control` (custom inputs, change index) | `bump_fee` | MISSING | BUG-19 (P1, see W129 BUG-11) |
| G22  | `bump_fee` plumbs `outputs` (custom new outputs) | `bump_fee` | MISSING | BUG-20 (P2) |
| G23  | `bump_fee` plumbs `original_change_index` | `bump_fee` | MISSING | BUG-21 (P2) |
| G24  | `psbtbumpfee` returns proper PSBT (not raw tx) | `rpc.py:9115` | PARTIAL — returns raw hex | BUG-22 (P2) |
| G25  | Wallet stores `replaces_txid` mapValue on bump tx | wallet | MISSING | BUG-15 cont. |
| G26  | RBF signal check uses `<= 0xFFFFFFFD` (Core `MAX_BIP125_RBF_SEQUENCE`) | `wallet.py:1493` | PRESENT (`< 0xFFFFFFFE` = equivalent) | — |
| G27  | Mempool side `signals_rbf` uses `<= 0xFFFFFFFD` | `mempool.py:3525` | PRESENT | — |
| G28  | Mempool side `is_rbf_opt_in` walks ancestors | `mempool.py:3528` | PRESENT | — |
| G29  | INCREMENTAL_RELAY_FEE matches Core default 1000 sat/kvB | `mempool.py:54` | **MISSING — 100 sat/kvB (10× too low)** | (W120 BUG-2 carried, P0-CDIV; not double-counted) |
| G30  | Two-pipeline guard — no feebumper / RBF in `ferrous-utils` | `ferrous-utils/` | PRESERVED | TP-1 |

Bug inventory (22 bugs / 30 gates)
-----------------------------------

Severity legend: P0-CDIV = behavior diverges from Core in a way an
operator could observe (replacement gets built when Core would refuse,
or vice-versa); P1 = user-funds / fee-accounting bug; P2 = UX / error
reporting / cosmetic.

| Bug    | Gate(s) | Sev | Summary |
|--------|---------|-----|---------|
| BUG-1  | G4     | P0-CDIV | `PreconditionChecks` #1 `HasWalletSpend` absent. A bump of a tx with wallet descendants succeeds — the descendants are silently orphaned by the eviction set inside `try_replace`. Core fails fast at the wallet boundary. |
| BUG-2  | G5     | P1 | `PreconditionChecks` #2 `hasDescendantsInMempool` absent. Same shape as BUG-1 for non-wallet descendants. The wallet has no way to detect that other parties have built on top of the tx in the mempool. |
| BUG-3  | G3     | P0-CDIV | `PreconditionChecks` #3 `GetTxDepthInMainChain != 0` absent. A tx that just confirmed (but is still in our mempool view due to a race) is bumpable, producing a tx that conflicts with the confirmed block. |
| BUG-4  | G6     | P1 | `PreconditionChecks` #4 `mapValue["replaced_by_txid"]` absent. Double-bumping the same original (bump A→A2, then bump A→A3 — both with different inputs, e.g. A2 changes the destination, A3 adds an input). A2 and A3 won't conflict. The user accidentally double-pays if both confirm. Core specifically calls this out in `feebumper.cpp:43-44`. |
| BUG-5  | G7     | P1 | `PreconditionChecks` #5 `AllInputsMine` (require_mine) absent. The wallet bumps a tx with foreign inputs and silently miscalculates the fee (uses 0 for unknown input values). The bump tx may pay vastly more or less than intended. |
| **BUG-6** | **G9** | **P0-CDIV** | **`CheckFeeRate` invariant inv-B absent — the wave's hook.** Core requires `new_total_fee ≥ old_fee + incrementalRelayFee.GetFee(maxTxSize)`, i.e. the wallet must enforce **at build time** that the replacement pays for at least one full incremental_relay_fee × max-vsize over the original. ouroboros enforces only `target_fee ≥ orig_fee + 1`. At default incremental_relay_fee=1000 sat/kvB and vsize=250, the Core floor is `orig_fee + 250`; ouroboros's is `orig_fee + 1` — 250× too low. Compounds with BUG-11 (round-down) and BUG-29 (10× incremental fee). |
| BUG-7  | G14    | P0-CDIV | `EstimateFeeRate` absent. When caller omits `fee_rate`, ouroboros's default is a flat 10 sat/vB regardless of original feerate. Core uses `orig_feerate + 1 sat/vB + max(node_incremental, WALLET_INCREMENTAL_RELAY_FEE)`. For any tx with orig_feerate > 10 sat/vB, the default bump path produces a tx that fails Rule 3 (absolute fee < orig). UX-breaking in fee-spike regimes (the only time anyone bumps). |
| BUG-8  | G8     | P1 | `CheckFeeRate` invariant inv-A absent — no `newFeerate ≥ mempoolMinFee` check. Wallet builds & signs a bump tx that's guaranteed to be rejected by the rolling-min-fee gate. |
| BUG-9  | G10    | P1 | `CheckFeeRate` invariant inv-C absent — no `GetRequiredFee` check. |
| BUG-10 | G11    | P2 | `CheckFeeRate` invariant inv-D absent — no `m_default_max_tx_fee` upper bound. A fat-fingered `fee_rate=1_000_000` produces a tx that signs with a fee greater than the input value (or burns the entire wallet). Core caps at `-maxtxfee`. |
| BUG-11 | G12    | P1 | Fee rounding direction wrong: `int(new_fee_rate * est_vsize)` truncates toward zero; Core's `CFeeRate::GetFee` uses `EvaluateFeeUp` (round up). At `fee_rate=1.1, vsize=251` Core charges 277 sat, ouroboros 276 sat. On the Rule 4 boundary this one-sat-under causes mempool rejection. |
| BUG-12 | G13    | P1 | `rpc.py:9013` casts caller's `fee_rate` via `int()` before use. RPC contract for `bumpfee` accepts floating-point feerates (sat/vB). Silent truncation: `fee_rate=2.7` becomes `2`. |
| BUG-13 | G15    | P2 | Wallet does not preview Rule 2 (no new unconfirmed input). Build & submit will fail later in `try_replace`. Not strictly required (Core delegates Rule 2 to the mempool too), but lack of preview means PSBT bumpfee returns unrejectable PSBTs. |
| BUG-14 | G16    | P2 | Wallet does not preview Rule 5 (≤ 100 cluster). Same shape as BUG-13. |
| BUG-15 | G17, G25| P1 | No `MarkReplaced` / `replaces_txid` / `replaced_by_txid` bookkeeping. `gettransaction` returns no `replaced_by_txid`; `listtransactions` cannot show "bumped" labels. Double-bump detection impossible — see BUG-4. Affects auditability of replacements. |
| BUG-16 | G18    | P1 | Replacement sequence is hardcoded `0xFFFFFFFD` regardless of original. Drops BIP-68 relative-locktime if the original had any. Also drops the BIP-125 "any sequence < 0xFFFFFFFE signals" — caller cannot bump a tx into a finalized form (sequence `0xFFFFFFFF`). |
| BUG-17 | G19    | P2 | `rpc_bumpfee` always returns `"errors": []` — Core's BIP-125 contract returns the list of errors / warnings (e.g. "fee bumped beyond mempool minimum"). Empty list is technically API-conformant; absence of error reporting is the bug. |
| BUG-18 | G20    | P1 | Vsize estimated as fixed `OVERHEAD_VBYTES + n_in*68 + n_out*31` (P2WPKH model). Core uses `CalculateMaximumSignedTxSize` which considers each input's actual script type (P2PKH 148 vB, P2SH-P2WPKH 91 vB, P2WPKH 68 vB, P2TR 57.5 vB, multisig variable). For any tx with non-P2WPKH inputs the wallet under-estimates vsize → over-estimates target_fee (or vice-versa) → Rule 4 boundary errors. |
| BUG-19 | G21    | P1 | `Wallet.bump_fee` signature is `(txid, new_fee_rate, *, sign=True)` — no `coin_control` / `outputs` / `original_change_index`. Caller cannot designate which inputs are eligible, which output is change, or alter outputs. (See also W129 BUG-11 / W113 BUG-11 — same root absent class.) |
| BUG-20 | G22    | P2 | No `outputs` parameter (Core: replace the original outputs with a new set during bump). |
| BUG-21 | G23    | P2 | No `original_change_index` parameter (Core: caller designates which output to deduct the fee from). |
| BUG-22 | G24    | P2 | `rpc_psbtbumpfee` returns raw transaction hex in `"psbt"` field, not a PSBT (no PSBT v0/v2 envelope, no input/output maps, no UTXO blobs). External signers expecting a real PSBT will fail to parse. (`rpc.py:9138-9140`: `"psbt": unsigned_hex`.) |

Cross-impl pattern notes
------------------------

- **F1 is universal-shape**: any wallet that doesn't enforce
  `PreconditionChecks` will exhibit BUG-1..5 — the brief asked me to
  watch for universal patterns. Expected fleet-wide presence: every
  implementation that built bumpfee against the RPC interface without
  consulting `feebumper.cpp`'s pre-check sequence.
- **F2 is the wave's named hook**: the precise
  `incrementalRelayFee.GetFee(maxTxSize)` invariant. The "+1 sat" hack
  is the canonical wallet-feebumper shape across non-Core impls; flag
  this as a universal pattern.
- **F3 fee rounding direction**: BUG-11 is a 1-sat-under bug. Cross-impl,
  this is the same shape as W120 BUG-4 (cluster diagram comparison uses
  `<` instead of strict-gt). Direction-of-comparison errors in integer
  fee accounting recur 3× now (W120 BUG-4, W129 BUG-8 excess-term, W130
  BUG-11). Suggests an audit pattern: every fee arithmetic site in an
  impl should be diff-tested against Core for round-up vs round-down.
- **F4 default-bump-fee policy**: the flat `10 sat/vB` default
  resembles the flat `10 sat/vB` fee_rate defaults seen in early
  ouroboros W57 and W113 tooling. Default-flat policies are the
  weakest spot in any non-Core wallet — the bumpfee default is the
  most user-visible because users hit it precisely during fee spikes.

Comment-as-confession sites
----------------------------

`wallet.py:1471-1474`:

```python
"""Create an RBF fee-bumped version of *txid* at *new_fee_rate* sat/vB.

Verifies the original signals RBF (sequence < 0xFFFFFFFE), then reduces
the change output (or adds a new input) to cover the higher fee.
Returns signed tx hex when *sign=True*, unsigned hex otherwise, or None on failure.
"""
```

Three statements:
1. "Verifies the original signals RBF" — partial; G3-G7 missing.
2. "reduces the change output (or adds a new input)" — does not match
   Core's "preserve a single change key if there is one" or Core's
   "Add change as recipient with SFFO flag" semantics
   (`feebumper.cpp:273-275`).
3. "Returns ... unsigned hex otherwise" — `rpc_psbtbumpfee` claims to
   return PSBT but returns raw hex. BUG-22.

Forward-regression hooks
------------------------

`test_w130_bip125_feebumper_rule3.py` includes guards that fail if
production drifts toward Core parity without an audit update:

- `test_g6_w130_hook_preserves_plus_one_workaround`: asserts the wallet
  still uses `orig_fee + 1` (BUG-6 marker). Failure means BUG-6 was
  closed (good!) — audit must be re-run to confirm matched invariant.
- `test_g7_default_bump_rate_still_flat_10_satvb`: asserts default-bump
  path still hardcodes 10 sat/vB (BUG-7 marker). Same shape.
- `test_g11_round_down_fee_arithmetic`: asserts `int(fee_rate * vsize)`
  truncation; failure means EvaluateFeeUp landed.
- `test_g30_two_pipeline_no_feebumper_in_rust`: forward-regression
  guard on the Rust pipeline. **EXTENDS** the cross-wave guard set.

Test plan
---------

22 BUGs (G1-G30 mapped) tested in `test_w130_bip125_feebumper_rule3.py`.
All assertions are static (source inspection + invariant arithmetic);
no live mempool / network / wallet I/O required. The W120 test file
covers the mempool side of Rules 1-5; W130 specifically does NOT
re-duplicate that.

Out of scope (deferred)
-----------------------

- Cluster mempool RBF diagram (W120 BUG-4 / BUG-5).
- BIP-431 TRUC v3 RBF special-cases (touched briefly in
  `mempool.py:3598-3635` but feebumper does not know about TRUC).
- External signer path (`WALLET_FLAG_EXTERNAL_SIGNER` in
  `feebumper.cpp:333-344`) — ouroboros does not yet implement
  hardware-wallet / external signers; entirely separate wave.
- `walletcreatefundedpsbt` / `fundrawtransaction` (different RPC
  surface; W118 / W129 territory).
- Mempool-side INCREMENTAL_RELAY_FEE constant (W120 BUG-2; not
  re-counted here as a separate W130 bug, but the test file pins it as
  G29 because the wallet's BUG-6 invariant is multiplicatively affected
  by it).
