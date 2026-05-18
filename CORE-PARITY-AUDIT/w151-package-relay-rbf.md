# W151 — Package relay + BIP-125 RBF rules 2-5 (ouroboros)

**Wave:** W151 — `AcceptPackage`, `AcceptMultipleTransactions`,
`AcceptSubPackage`, `IsTopoSortedPackage`, `IsWellFormedPackage`,
`IsChildWithParents`, `IsChildWithParentsTree`, `PackageRBFChecks`,
`ReplacementChecks`, `GetEntriesForConflicts`, `EntriesAndTxidsDisjoint`,
`PaysForRBF`, `ImprovesFeerateDiagram`, `IsRBFOptIn` / `SignalsOptInRBF`,
`MAX_REPLACEMENT_CANDIDATES`, `MAX_PACKAGE_COUNT`, `MAX_PACKAGE_WEIGHT`,
`submitpackage` RPC (`maxfeerate` + `maxburnamount`), BIP-331 wire
(`sendpackages` / `getpkgtxns` / `pkgtxns` / `ancpkginfo`), tx-rejection
→ misbehaving mapping.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/rbf.h:26` — `MAX_REPLACEMENT_CANDIDATES{100}`
  (number of **unique clusters** affected by an RBF — NOT total evictee
  count).
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`:
  uses `pool.GetUniqueClusterCount(iters_conflicting)` to enforce
  Rule #5, then `CalculateDescendants` per direct conflict.
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`:
  Rule #2 partial — replacement's mempool ancestors must not include any
  directly-conflicting txs. Called from `AcceptSingleTransactionInternal`
  at `validation.cpp:1356`.
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF`: Rules #3
  (`replacement_fees >= original_fees`) and #4 (`additional_fees >=
  relay_fee.GetFee(replacement_vsize)`). **vsize, NOT raw-serialised size**.
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`:
  cluster-mempool gate; replacement must strictly improve the chunk
  feerate diagram.
- `bitcoin-core/src/util/rbf.h:12` —
  `MAX_BIP125_RBF_SEQUENCE{0xfffffffd}`; `SignalsOptInRBF` returns
  `true` iff **any** input has `nSequence <= MAX_BIP125_RBF_SEQUENCE`.
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn`: 3-state
  return (`UNKNOWN` / `REPLACEABLE_BIP125` / `FINAL`); walks ancestors
  via `CalculateMemPoolAncestors` (NOT a per-tx parents set).
- `bitcoin-core/src/policy/packages.h:19/24/29/30` —
  `MAX_PACKAGE_COUNT{25}`, `MAX_PACKAGE_WEIGHT{404'000}` (weight units,
  not vbytes), `DEFAULT_CLUSTER_LIMIT{64}`,
  `DEFAULT_CLUSTER_SIZE_LIMIT_KVB{101}`.
- `bitcoin-core/src/policy/packages.cpp:19-50` — `IsTopoSortedPackage`:
  child cannot appear before its parent — checks parent in `later_txids`
  set.
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`:
  no two txs may share a prevout (rejects empty-vin txs too).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`:
  count + weight + duplicate-txid + topo + consistent. **No
  child-with-parents enforcement here**.
- `bitcoin-core/src/policy/packages.cpp:119-149` —
  `IsChildWithParents` / `IsChildWithParentsTree`: NOT enforced by
  `IsWellFormedPackage`; only enforced by `AcceptPackage` (line 1640) and
  the `submitpackage` RPC (rpc/mempool.cpp:1395).
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`:
  sorted-wtxid SHA-256 used as the BIP-331 `getpkgtxns` lookup key.
- `bitcoin-core/src/validation.cpp:984-1035` —
  `MemPoolAccept::ReplacementChecks`: order = Rule #5
  (`GetEntriesForConflicts`) → Rule #3+#4 (`PaysForRBF` with
  `GetModifiedFee`+`m_vsize`) → cluster limit
  (`m_changeset->CheckMemPoolPolicyLimits`) → `ImprovesFeerateDiagram`.
  Rule #2 (`EntriesAndTxidsDisjoint`) lives in
  `AcceptSingleTransactionInternal` AFTER `ReplacementChecks`.
- `bitcoin-core/src/validation.cpp:1037-1133` — `PackageRBFChecks`:
  **package size MUST be 2** (1-parent-1-child only); no in-mempool
  ancestors allowed for either tx; cluster limit; package feerate
  strictly > parent feerate (anti-DoS); ImprovesFeerateDiagram.
- `bitcoin-core/src/validation.cpp:1432-1620` —
  `AcceptMultipleTransactionsInternal`: per-tx PreChecks loop (with
  per-tx `client_maxfeerate` gate) → `PackageTRUCChecks` → package
  feerate (only when `m_package_feerates=true`) → `PackageRBFChecks`
  → cluster limit → `CheckEphemeralSpends` → per-tx `PolicyScriptChecks`
  → `SubmitPackage` (which re-runs `ConsensusScriptChecks`). **No
  child-with-parents check at this layer.**
- `bitcoin-core/src/validation.cpp:1622-1771` — `AcceptPackage`: tries
  SINGLE submission first per tx (line 1690-1696); falls back to package
  eval ONLY when single rejects on `TX_RECONSIDERABLE` or
  `TX_MISSING_INPUTS`. De-duplicates txs already in mempool (line
  1664-1675); produces `MempoolTx` results rather than rejecting.
- `bitcoin-core/src/rpc/mempool.cpp:1302-1514` — `submitpackage` RPC:
  array size ∈ [1, MAX_PACKAGE_COUNT]; `maxfeerate` (default 0.1 BTC/kvB,
  `DEFAULT_MAX_RAW_TX_FEE_RATE`); `maxburnamount` (default
  `DEFAULT_MAX_BURN_AMOUNT`, refuses txs with unspendable outputs above
  the threshold via `IsUnspendable()` / `!HasValidOps()`);
  `IsChildWithParentsTree` enforced (line 1395).
- `bitcoin-core/src/net_processing.cpp:3119-3144` —
  `ProcessInvalidTx`: **does NOT call `Misbehaving`** for any
  `TxValidationResult` value. Only `MempoolRejectedTx` is invoked; the
  download manager tracks fail counts but the inbound `tx` handler does
  not ban peers for invalid transactions. Compare to ouroboros W150
  BUG-23 / this audit BUG-6 echo.

**Files audited**
- `src/ouroboros/mempool.py` — `Mempool.try_replace` (3563-3813),
  `_try_replace_inner`, `_check_cluster_rbf` (3383-3482), `signals_rbf`
  (3514-3526), `is_rbf_opt_in` (3528-3561), `validate_package`
  (4476-4777), `_validate_package_inner` (4502+), `is_child_with_parents`
  (4416-4448), `is_child_with_parents_tree` (4450-4474),
  `_check_package_truc_policy` (2625+), `INCREMENTAL_RELAY_FEE`
  (3380), `MAX_REPLACEMENT_EVICTIONS` (3381), `MAX_PACKAGE_COUNT`
  (70), `MAX_PACKAGE_WEIGHT` (71), `DEFAULT_INCREMENTAL_RELAY_FEE`
  (54), `DEFAULT_MIN_RELAY_TX_FEE` (49), `_try_sibling_eviction`
  (2810-2883), accept-conflict dispatch (2157-2163), `full_rbf`
  knob (1573/1593), `wtxid_to_txid` (1603/2321),
  `get_transaction_by_wtxid` (4319+).
- `src/ouroboros/rpc.py` — `rpc_submitpackage` (7933-8019),
  `rpc_testmempoolaccept` (7905-7931), `rpc_sendrawtransaction`
  (2382-2538), `_map_mempool_error_to_reject_reason` (2540+).
- `src/ouroboros/p2p.py` — `_negotiate_package_relay` (2960-2985),
  `_register_package_relay_handlers` (2987-3158),
  `on_sendpackages` / `on_getpkgtxns` / `on_pkgtxns` / `on_ancpkginfo`
  (3024-3158), `package_relay_enabled` (545),
  `package_relay_version` (546), `_package_peers` set, `misbehaving`
  (3401-3422).
- `src/ouroboros/p2p_messages.py` — `SendPackagesMessage` (1721),
  `GetPkgTxnsMessage` (1755), `PkgTxnsMessage` (1781).
- `src/ouroboros/node.py` — `_make_tx_handler` (923-1001;
  `misbehaving(addr, 10, …)` at 993-995 fires on every rejection
  including RBF), `register_handler("tx", …)` (1460, 1470, 1488).
- `src/ouroboros/wallet.py` — `bump_fee` (1470+), `try_replace` call
  (1659) for wallet-side RBF.
- `src/ouroboros/peer.py` — `package_relay_version` (411),
  `_sendpackages_sent` / `_sendpackages_received` (414-415).

---

## Gate matrix (38 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RBF Rule #5 — MAX_REPLACEMENT_CANDIDATES | G1: bound by **unique cluster count** of `iters_conflicting`, not by total evictee count | **BUG-1 (P0-CDIV)** — `try_replace` counts total descendant evictees (`mempool.py:3645-3659`); Core counts unique CLUSTERS (`rbf.cpp:69-75`, `GetUniqueClusterCount`). Two long descendant chains rooted at the same cluster pass Core (1 cluster, hundreds of evictees) but fail ouroboros (>100 evictees). Conversely, two single-tx clusters with 60 descendants each pass ouroboros (120 evictees, fail) only when count > 100 — Core would also fail at "2 clusters" because the limit is on the **iters_conflicting set**, not all_conflicts. Worse: ouroboros's bound is per-100-evictees vs Core's per-100-clusters, which on cluster mempool is a tight intentional limit. |
| 1 | … | G2: order = Rule #5 → Rule #3+#4 → cluster-limit → ImprovesFeerateDiagram | **BUG-2 (P0-CDIV)** — `try_replace` runs Rule 1 (signal) → Rule 5 → Rule 2 → EntriesAndTxidsDisjoint → Rule 3 → Rule 4 → `_check_cluster_rbf` (mempool.py:3637-3760). Core runs signal-check inside `IsRBFOptInEmptyMempool` upstream, then Rule 5 → Rule 3+4 → cluster-limit → ImprovesFeerateDiagram. ouroboros's order means a tx that would fail cluster-limit gets through Rules 3+4 and the eviction set is staged unnecessarily. **EntriesAndTxidsDisjoint runs in the WRONG layer** in Core (lives in AcceptSingleTransactionInternal AFTER ReplacementChecks, not inside it); ouroboros conflates the layers. |
| 2 | RBF Rule #2 — HasNoNewUnconfirmed + EntriesAndTxidsDisjoint | G3: `HasNoNewUnconfirmed` enforced (replacement may not introduce new unconfirmed inputs) | PASS — `mempool.py:3661-3684` (BUG-23 noted: Core dropped HasNoNewUnconfirmed in 2024 cluster-mempool migration; only `EntriesAndTxidsDisjoint` remains. ouroboros enforces a **dropped** Core rule — see BUG-3). |
| 2 | … | G4: `EntriesAndTxidsDisjoint` enforced | PASS — `mempool.py:3686-3700` (literal port of the Core helper). |
| 3 | RBF Rule #3 — absolute fee gate | G5: `replacement_fees >= original_fees` using **modified** fees on both sides | PASS — `mempool.py:3712-3735` honours `get_modified_fee()` for both new tx and evicted set (FIX-72 noted). |
| 4 | RBF Rule #4 — incremental fee gate | G6: `additional_fees >= incremental_relay_fee × replacement_VSIZE / 1000` | **BUG-4 (P0-CDIV)** — `incremental_fee_needed = (new_size * INCREMENTAL_RELAY_FEE) // 1000` at `mempool.py:3743` uses **`new_size = len(new_tx.serialize())`** (raw witness-included byte count) — NOT vsize. Core uses `ws.m_vsize` (`rbf.cpp:118`: `relay_fee.GetFee(replacement_vsize)`). For a SegWit replacement at 200 raw bytes / 100 vbytes, ouroboros demands fee for 200 bytes ⇒ doubles the required additional fee ⇒ rejects legitimate replacements Core accepts. Same shape repeated in `_try_sibling_eviction` (`mempool.py:2857`). |
| 5 | RBF Rule #1 — signal detection | G7: `SignalsOptInRBF` checks **any** input nSequence ≤ MAX_BIP125_RBF_SEQUENCE | PASS — `mempool.py:3525-3526`. |
| 5 | … | G8: `IsRBFOptIn` honours TRUC always-replaceable AND ancestor inheritance AND own-signal | PASS — `mempool.py:3528-3561` walks `_get_ancestors`. |
| 5 | … | G9: `IsRBFOptInEmptyMempool` for txs not in mempool (e.g. RBF query before submit) | **BUG-5 (P1)** — no `IsRBFOptInEmptyMempool` equivalent. `is_rbf_opt_in(txid)` returns False for a txid not in `self.transactions` (mempool.py:3539-3541), conflating "not yet seen" with "explicitly opted out". A caller asking "is this incoming tx replaceable?" cannot distinguish UNKNOWN from FINAL. Core's 3-state return (UNKNOWN / REPLACEABLE_BIP125 / FINAL) is collapsed to True/False. Affects any external policy code or wallet querying RBF-status before submit. |
| 6 | P2P tx-rejection → misbehaving | G10: rejection on policy reasons does NOT trigger Misbehaving | **BUG-6 (P0-SEC)** **— ECHO of W150 BUG-23 — RBF-specific surface**: `_make_tx_handler` (`node.py:993-995`) calls `peer_manager.misbehaving(addr, 10, f"invalid tx: {error}")` on **every** `add_transaction` failure. Any RBF rejection — Rule 5 (too many evictions), Rule 1 (conflicting tx doesn't signal), Rule 3 (insufficient fee), Rule 4 (incremental fee gate), `_check_cluster_rbf` failures — flows through `add_transaction → try_replace → False` and lands at line 993. Core's `ProcessInvalidTx` (`net_processing.cpp:3119-3144`) does NOT call Misbehaving for any TxValidationResult — only logs and forwards to `MempoolRejectedTx`. With ouroboros's score-of-10 per rejection, 10 RBF-rejected attempts from one peer = ban; honest Core peers running pkg-pinning replacement attempts get banned within hours of heavy mempool churn. |
| 6 | … | G11: distinguish TX_RECONSIDERABLE / TX_MEMPOOL_POLICY / TX_CONSENSUS for misbehaving | **BUG-7 (P0-SEC)** — single boolean ok/!ok; no TxValidationResult class. The TX_RECONSIDERABLE classification (Core's signal that a tx may yet succeed in a package context — e.g. insufficient fee for own bandwidth, but may pass as part of a CPFP package) is conflated with TX_CONSENSUS (invalid sig / duplicate input / MoneyRange). Effect: a peer relaying a low-fee tx that should be reconsidered in a package context is banned for the SAME amount as a peer relaying a CVE-2018-17144 inflation tx. |
| 7 | RBF: vsize used for fees AND cluster | G12: `_check_cluster_rbf` uses vsize | **BUG-8 (P1)** — `_check_cluster_rbf` at `mempool.py:3424` uses `new_size = len(new_tx.serialize())` (raw bytes), then `new_tx_rate = new_fee / new_size` at line 3465. For witness-heavy txs this UNDERSTATES the rate, so the gate FALSELY rejects replacements that legitimately improve the chunk diagram. Compounds BUG-4. |
| 8 | Package-relay wire (BIP-331) | G13: `sendpackages` sent after `verack` only to relay-tx peers | PASS — `p2p.py:2960-2985` (block-relay-only skip). |
| 8 | … | G14: `pkgtxns` only accepted from peers we negotiated with | PASS — `p2p.py:3096-3101` (`_package_peers` set gate). |
| 8 | … | G15: `getpkgtxns` looks up child by **wtxid** | PASS — `p2p.py:3038-3046`. |
| 8 | … | G16: `ancpkginfo` parsed (forward-compat) | PASS — `p2p.py:3140-3153` (debug-logged, not acted on). |
| 8 | … | G17: `on_pkgtxns` runs same gate set as local package submission | **BUG-9 (P0-CDIV)** — `on_pkgtxns` (`p2p.py:3087-3138`) calls `validate_package(txs)` AND THEN ALSO `add_transaction(tx)` per-tx in the SAME handler (line 3129-3136). After a successful `validate_package` the txs are already in the mempool; the subsequent `add_transaction` then trips `txn-already-in-mempool`, **logged as failure**, which means EACH successful BIP-331 pkgtxns is logged as N spurious "failed to add tx" debug lines. If `validate_package` fails, the per-tx `add_transaction` loop tries to admit the same txs individually — without any RBF routing or topological-order awareness; if the package was a CPFP, individual admission will reject the low-fee parent. |
| 9 | submitpackage RPC | G18: array size validated [1, MAX_PACKAGE_COUNT] | **BUG-10 (P1)** — `rpc_submitpackage` (`rpc.py:7942`) accepts any non-empty list. The MAX_PACKAGE_COUNT gate is enforced downstream by `validate_package` (`mempool.py:4509-4512`), but the HTTP-400 error path treats a too-large-package as a successful POST returning `{"package_msg": "Package too large: …"}` instead of `RPC_INVALID_PARAMETER`. Core: `JSONRPCError(RPC_INVALID_PARAMETER, …)` thrown immediately. Client compatibility: scripts that check for HTTP 400 will miss the rejection. |
| 9 | … | G19: `maxfeerate` parameter | **BUG-11 (P0-CDIV)** — `rpc_submitpackage` signature has ONE parameter (`package: list[str]`); the `maxfeerate` argument is **completely absent** (`rpc.py:7933`). Core's submitpackage accepts `maxfeerate` (default 0.1 BTC/kvB) and short-circuits per-tx in `AcceptMultipleTransactionsInternal` at validation.cpp:1458. ouroboros has no equivalent gate ⇒ any feerate is accepted via submitpackage. Operator footgun: a malformed wallet that miscomputes fees can burn arbitrary amounts via submitpackage. |
| 9 | … | G20: `maxburnamount` parameter | **BUG-12 (P0-CDIV)** — `rpc_submitpackage` does not implement `maxburnamount` (Core: default 0). A package with a tx that has `IsUnspendable()` outputs above the burn threshold is accepted; Core throws `JSONRPCTransactionError(MAX_BURN_EXCEEDED)`. **Funds-loss footgun** when the operator's wallet accidentally produces an OP_RETURN output greater than expected. |
| 9 | … | G21: pre-eval `IsChildWithParentsTree` enforced at RPC level | PARTIAL — `validate_package` enforces it (`mempool.py:4558-4561`), but the RPC layer doesn't pre-check, so an `is_child_with_parents` failure returns `200 OK / package_msg="package-not-child-with-parents"` rather than the Core-style `RPC_INVALID_PARAMETER` exception. **BUG-13 (P1)** — diverges from RPC convention; clients that assume an HTTP-error path on bad input misbehave. |
| 10 | AcceptPackage flow | G22: single submission first, fall back to package only on TX_RECONSIDERABLE / TX_MISSING_INPUTS | **BUG-14 (P0-CDIV)** — `validate_package` (`mempool.py:4476-4777`) **never** tries single-tx submission first; it always runs the package flow. For a 25-tx package where 24 of the parents have already been admitted and only the child is new, Core's `AcceptPackage` (`validation.cpp:1664-1675`) **de-duplicates** the already-in-mempool ones and runs single-tx eval for the child — submitting the package as if all 25 are new. ouroboros REJECTS the package outright at line 4639-4640: `f"Transaction {txid.hex()[:16]}... already in mempool"`. **Censorship vector** as Core notes in the inline comment ("policy differences … pin or delay propagation"). |
| 10 | … | G23: de-duplicate already-in-mempool txs (results = MempoolTx, NOT failure) | **BUG-14 cross-cite** — see above. ouroboros returns `success=False`. |
| 10 | … | G24: same-txid-different-wtxid handling (`MempoolTxDifferentWitness`) | **BUG-15 (P1)** — ouroboros's package duplicate-detection uses `tx.get_txid()` (`mempool.py:4517-4519` — TXID, not wtxid). Two malleable witness variants of the same tx pass the in-package duplicate gate (because txids match) and the first wins; the second is silently dropped. Core's `IsWellFormedPackage` uses txids for duplicate detection too, but the result is `"package-contains-duplicates"`. The deeper issue: Core's `AcceptPackage` distinguishes wtxid-already-in-mempool from txid-already-in-mempool (line 1664-1686) and replaces the package member with `MempoolTxDifferentWitness`; ouroboros has no such path. |
| 11 | Package context-free policy | G25: `IsWellFormedPackage` count + weight + topo + consistent | PASS for the most part — count (`mempool.py:4509-4512`), weight (4523-4527), topo (4543-4551), in-package double-spend (4530-4539). |
| 11 | … | G26: total weight in **weight units**, not raw bytes | PASS — `sum(tx.get_weight())` at `mempool.py:4523`. |
| 11 | … | G27: package fee gate uses **vsize**, not raw size | **BUG-16 (P0-CDIV)** — `total_size = sum(len(tx.serialize()) for tx in txs)` at `mempool.py:4654`; `min_relay = (total_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000` (line 4658). Core uses sum of vsizes (`m_subpackage.m_total_vsize`, validation.cpp:1497-1498). For a witness-heavy package the raw-byte total OVERSTATES the fee requirement ⇒ ouroboros rejects packages Core accepts. Also `DEFAULT_MIN_RELAY_TX_FEE=1000` (sat/kvB) vs Core's 100 sat/kvB compounds 10×. **Cross-cite W150 BUG-15.** |
| 11 | … | G28: `IsChildWithParentsTree` enforced at correct layer (RPC only, not mempool) | **BUG-17 (P1)** — `validate_package` UNCONDITIONALLY enforces both `IsChildWithParents` and `IsChildWithParentsTree` for any `len(txs) > 1` at `mempool.py:4555-4561`. Core's `AcceptMultipleTransactionsInternal` (validation.cpp:1432-1620) does NOT enforce child-with-parents at the mempool layer — that lives in `AcceptPackage` (1640) for `IsChildWithParents` only and at the RPC for `IsChildWithParentsTree`. Result: programmatic callers of `validate_package` that want to submit an ancestor-set package (e.g. unbounded TRUC chain) are blocked even though Core would accept. |
| 12 | RBF: incremental + rolling-min interaction | G29: no rolling-min-fee gate inside `try_replace` | **BUG-18 (P1)** — `try_replace` does NOT consult `_get_min_fee_inner()`. The rolling minimum fee gate is in `_add_transaction_inner` (line 2284-2291) and is **skipped** when `has_conflict=True` short-circuits to `try_replace` (line 2162-2163). A replacement at exactly `original_fee + incremental_fee` may be below the rolling minimum (post-trim), but is accepted by ouroboros and rejected by Core (`txmempool.cpp::GetMinFee` gate runs upstream of replacement eval). |
| 12 | … | G30: `INCREMENTAL_RELAY_FEE` matches Core | PASS — `mempool.py:54, 3380` = 100 sat/kvB (Core default). |
| 12 | … | G31: `MAX_REPLACEMENT_EVICTIONS` matches Core constant name | **BUG-19 (P2)** — ouroboros names it `MAX_REPLACEMENT_EVICTIONS` (`mempool.py:3381`); Core's constant is `MAX_REPLACEMENT_CANDIDATES` (rbf.h:26). The semantic difference also matters: "evictions" (descendants) vs "candidates" (clusters). Name conflation hides BUG-1. |
| 13 | full_rbf knob | G32: default = True (post-v28 Core) | PASS — `mempool.py:1573, 1593` default True. |
| 13 | … | G33: `-mempoolfullrbf` CLI flag | **BUG-20 (P2)** — no CLI flag plumbed; only `Mempool.__init__(full_rbf=True)`. Operator cannot revert to opt-in-only RBF on the running node. Core REMOVED the knob (always full RBF since v28); ouroboros's situation is moot for parity but the constructor-only path is brittle if tests want to flip it. |
| 14 | TRUC sibling eviction | G34: incremental fee gate uses vsize | **BUG-21 (P0-CDIV)** — `_try_sibling_eviction` at `mempool.py:2857` mirrors BUG-4: `new_size = len(new_tx.serialize())`. Same witness-included raw-size bug; replacements of v3 child siblings demand 2× the fee Core demands. |
| 14 | … | G35: sibling eviction routed through ReplacementChecks (not as a separate path) | **BUG-22 (P1)** — `_try_sibling_eviction` (`mempool.py:2810-2883`) is its own pipeline parallel to `_try_replace_inner`. Core treats the sibling as part of `direct_conflicts` and routes through ReplacementChecks (truc_policy.cpp passes the sibling iter into `m_iters_conflicting`). The two pipelines diverge: sibling-eviction skips `_check_cluster_rbf`, MAX_REPLACEMENT_CANDIDATES, EntriesAndTxidsDisjoint, HasNoNewUnconfirmed. **N-pipeline drift carry-forward — 7th distinct entry in ouroboros, now extending W150's 6-pipeline record.** |
| 15 | Stale rules carry-forward | G36: ouroboros enforces a Core-DROPPED rule (HasNoNewUnconfirmed, Rule #2 part 1) | **BUG-23 (P1)** — `HasNoNewUnconfirmed` enforcement at `mempool.py:3661-3684` was dropped from Core's RBF rules in the 2024 cluster-mempool migration (rbf.cpp now only contains `EntriesAndTxidsDisjoint`; the BIP-125 Rule 2 "no new unconfirmed inputs" semantics are subsumed by cluster-mempool's diagram check). ouroboros still enforces it ⇒ rejects replacement-with-new-unconfirmed-input that Core accepts. Anti-Pin replacements (where a victim's child is replaced with a higher-fee child that itself spends a new unconfirmed parent) are killed in ouroboros even though they pass cluster-mempool's improvement check. |
| 16 | OUROBOROS_*_STOPGAP env vars | G37: any STOPGAP env-var in RBF/package code | NONE — `try_replace`, `validate_package`, package-relay handlers contain no `OUROBOROS_*_STOPGAP` reads. The W132 BIP-68 stopgap (`OUROBOROS_BIP68_STOPGAP`) still lives in `validation.py::check_sequence_locks` (cross-cite W150 BUG-27); the RBF/package path runs `validator.validate_transaction` which transitively traverses it. So STOPGAP technically reachable from the package pipeline via the sequence-lock check, but no NEW stopgap added in this surface. |
| 16 | … | G38: `_make_tx_handler` `if not self.synced` short-circuit (W138-class plumb-gate-then-flip) | PARTIAL — sync gate is in `_make_tx_handler` but NOT in the BIP-331 `on_pkgtxns` path (`p2p.py:3087-3138`). A peer can race the IBD gate by sending pkgtxns instead of tx. **BUG-24 (P1)** — pkgtxns bypasses the not-synced check that gates plain tx. |

---

## BUG-1 (P0-CDIV) — Rule #5 bounded by total evictees, not unique clusters

**Severity:** P0-CDIV. Bitcoin Core's `GetEntriesForConflicts`
(`policy/rbf.cpp:58-83`) uses `pool.GetUniqueClusterCount(iters_conflicting)`
to enforce Rule #5 — the bound is on the number of **unique mempool
clusters** the replacement would touch. The intent is to cap the
linearisation work the cluster-mempool would have to do, not to cap
the number of evicted transactions.

ouroboros's `try_replace` (`mempool.py:3645-3659`) instead bounds
`len(to_evict)` = direct conflicts + transitive descendants:

```python
to_evict: set[bytes] = set()
for c_txid in conflicts:
    to_evict |= self._collect_descendants(c_txid)

if len(to_evict) > self.MAX_REPLACEMENT_EVICTIONS:  # 100
    return False, (
        f"Replacement would evict {len(to_evict)} txs; "
        f"too many potential replacements (max {self.MAX_REPLACEMENT_EVICTIONS})"
    )
```

Two failure modes:

1. **False-reject** — a single mempool cluster of 150 txs where the
   replacement directly conflicts with one ancestor: Core counts
   1 cluster (PASS), ouroboros counts 150 evictees (REJECT).
2. **False-accept** — replacement that touches 99 distinct
   single-tx clusters (e.g. 99 fee-bumped UTXO consolidations from
   separate wallets): Core counts 99 clusters (PASS, just under the
   limit), ouroboros counts 99 evictees (PASS). Effect is the same
   here, but for any larger cluster mix, the bound differs.

The literal divergence is the bound axis (cluster count vs evictee
count); the practical effect is asymmetric rejection of legitimate
RBF batches AND admission of resource-intensive replacements that
Core would refuse.

**File:** `src/ouroboros/mempool.py:3381, 3645-3659`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:69-75`,
`bitcoin-core/src/txmempool.h::GetUniqueClusterCount`.

**Impact:** wire-level RBF divergence on heavy-mempool/CPFP situations;
operator-visible "too many potential replacements" rejection for
cases Core accepts; security implication: a malicious replacement
that touches many single-tx clusters bypasses the intended
linearisation-work cap.

---

## BUG-2 (P0-CDIV) — RBF gate order differs from Core; EntriesAndTxidsDisjoint at wrong layer

**Severity:** P0-CDIV.

Core's order (`validation.cpp:984-1035` `ReplacementChecks` +
`AcceptSingleTransactionInternal`):

1. `GetEntriesForConflicts` (Rule #5)
2. `PaysForRBF` (Rules #3 + #4)
3. `m_subpackage.m_changeset->CheckMemPoolPolicyLimits()` (cluster size)
4. `ImprovesFeerateDiagram`
5. `EntriesAndTxidsDisjoint` — **OUTSIDE** ReplacementChecks, run
   from `AcceptSingleTransactionInternal` at validation.cpp:1356
   AFTER `ReplacementChecks` returns true. It is **NOT** part of
   the RBF gate sequence; it lives in the per-tx ATMP path.

ouroboros's order (`mempool.py:3637-3760`):

1. Rule 1 SignalsOptInRBF (Core: handled upstream in
   `IsRBFOptInEmptyMempool` / `IsRBFOptIn`)
2. Rule 5 MAX_REPLACEMENT_EVICTIONS (wrong axis — see BUG-1)
3. Rule 2 `HasNoNewUnconfirmed` (Core-dropped; see BUG-23)
4. EntriesAndTxidsDisjoint (wrong layer — Core runs it outside ReplacementChecks)
5. Rule 3 PaysForRBF absolute
6. Rule 4 PaysForRBF incremental (wrong vsize — see BUG-4)
7. `_check_cluster_rbf` (wrong vsize — see BUG-8)

Three concrete divergences flow from the ordering:

- **EntriesAndTxidsDisjoint at the wrong layer**: in Core,
  `EntriesAndTxidsDisjoint` is a per-tx PRECHECK that runs on the
  replacement's ancestors regardless of whether RBF is being attempted
  — even for txs that just happen to have a mempool-ancestor that
  conflicts with a different tx. ouroboros only runs it when
  has_conflict=True triggers try_replace, which means a non-conflicting
  tx whose ancestor was being replaced concurrently is admitted.
- **Cluster-limit checked AFTER Rules 3+4** (ouroboros) vs **before**
  (Core's `CheckMemPoolPolicyLimits()` runs after `PaysForRBF` but
  before `ImprovesFeerateDiagram`). Doesn't affect correctness but
  wastes work when the cluster limit would have caught the failure.
- **No `ImprovesFeerateDiagram` integration**: ouroboros's
  `_check_cluster_rbf` is a ad-hoc "feerate must not worsen" check
  with `1% tolerance` (`mempool.py:3476`) that does not match Core's
  strict-improvement requirement.

**File:** `src/ouroboros/mempool.py:3637-3760`.

**Core ref:** `bitcoin-core/src/validation.cpp:984-1035` +
`bitcoin-core/src/validation.cpp:1356`.

**Impact:** behavioural divergence on edge cases of multi-conflict
replacements; the wrong-layer EntriesAndTxidsDisjoint is the most
serious — for a non-conflict tx whose ancestor was replaced by a
concurrent RBF, Core rejects (`<txid> spends conflicting transaction
<hashAncestor>`) and ouroboros accepts.

---

## BUG-3 (P1) — Rule #2 HasNoNewUnconfirmed enforces a Core-dropped rule (carry-forward)

Cross-cited at BUG-23 below.

---

## BUG-4 (P0-CDIV) — Rule #4 incremental fee gate uses raw witness-included bytes, not vsize

**Severity:** P0-CDIV. Bitcoin Core's `PaysForRBF`
(`policy/rbf.cpp:117-123`) computes the required incremental fee as:

```cpp
CAmount additional_fees = replacement_fees - original_fees;
if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
    return strprintf("rejecting replacement %s, not enough additional fees to relay; …");
}
```

`replacement_vsize = ws.m_vsize` — the sigop-adjusted **virtual size**,
not the raw serialised bytes.

ouroboros's `_try_replace_inner` (`mempool.py:3703-3749`):

```python
new_size = len(new_tx.serialize())          # raw bytes INCLUDING witness
...
incremental_fee_needed = (new_size * self.INCREMENTAL_RELAY_FEE) // 1000
additional_fee = new_fee_modified - old_fees
if additional_fee < incremental_fee_needed:
    return False, (
        f"Replacement does not cover incremental relay fee: "
        f"additional {additional_fee} sat < required {incremental_fee_needed} sat"
    )
```

For a SegWit replacement at 700 raw bytes / 200 vbytes (e.g. P2WPKH
spending a multisig parent), `INCREMENTAL_RELAY_FEE=100 sat/kvB`,
the required additional fee is:
- Core: `100 * 200 / 1000 = 20 sat`
- ouroboros: `100 * 700 / 1000 = 70 sat`

3.5× the demanded fee for witness-heavy spends. Replacements with
fees Core accepts are rejected by ouroboros — a wallet bumping a
TRUC v3 child finds the bump is "not enough additional fees to
relay" even though Core's network admits it.

**File:** `src/ouroboros/mempool.py:3703, 3743-3749`. Same shape at
`mempool.py:2826, 2857` (`_try_sibling_eviction`).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:117-123`;
`bitcoin-core/src/validation.cpp:1010-1015` (passes `ws.m_vsize`).

**Impact:** RBF fee-bumping silently fails for any witness-heavy
transaction. The wallet's perspective is "replaced fine on Core,
mysteriously stuck on this node". The error message claims "not
enough additional fees" without indicating that the requirement is
inflated by the witness bytes. Compounds with W150 BUG-15
(DEFAULT_MIN_RELAY_TX_FEE = 1000 = 10× Core) when the witness data is
large.

---

## BUG-5 (P1) — `IsRBFOptInEmptyMempool` semantics absent; UNKNOWN/FINAL collapsed

**Severity:** P1. Core's `IsRBFOptIn` returns `RBFTransactionState`
with **three** states: `UNKNOWN`, `REPLACEABLE_BIP125`, `FINAL`.
Callers (notably `MempoolToJSON` / `bumpfee` / fee estimation) branch
on the distinction: a tx in `UNKNOWN` state has no opinion on
replaceability, whereas `FINAL` is a definitive "no replacement
attempts allowed".

ouroboros's `is_rbf_opt_in(txid)` (`mempool.py:3528-3561`) returns a
plain `bool`:

```python
entry = self.transactions.get(txid)
if entry is None:
    return False   # ← conflates UNKNOWN with FINAL
```

There is also no `IsRBFOptInEmptyMempool` (Core: `rbf.cpp:52-56`)
which returns `REPLACEABLE_BIP125` for tx-not-in-mempool that signals,
`UNKNOWN` otherwise. ouroboros has no equivalent.

**File:** `src/ouroboros/mempool.py:3528-3561` (only single is_rbf_opt_in;
no empty-mempool variant).

**Core ref:** `bitcoin-core/src/policy/rbf.h:28-36` enum;
`bitcoin-core/src/policy/rbf.cpp:24-56`.

**Impact:** wallet code that queries pre-submission RBF status
(`bumpfee` cascade) cannot distinguish "this tx isn't in mempool"
from "this tx opted out of replacement". JSON-RPC consumers see
`bip125-replaceable=false` for both cases.

---

## BUG-6 (P0-SEC) — RBF rejection triggers Misbehaving(10) on inbound `tx` handler

**Severity:** P0-SEC. **Direct echo of W150 BUG-23**, RBF-specific
surface. Bitcoin Core's `ProcessInvalidTx` (`net_processing.cpp:3119-3144`)
does NOT call `Misbehaving` for any `TxValidationResult` — including
TX_MEMPOOL_POLICY (RBF rule-failures all fall here). Only logs the
rejection and forwards the result to `m_txdownloadman.MempoolRejectedTx`,
which manages per-peer fail counts for tx-download retry but does NOT
ban peers for policy-level rejections.

ouroboros's `_make_tx_handler` (`node.py:923-1001`):

```python
ok, error = self.mempool.add_transaction(tx, height)
...
elif success:
    ... relay INV ...
else:
    logger.debug(f"Rejected transaction: {error}")
    if hasattr(self, "peer_manager") and self.peer_manager:
        addr = f"{sender_peer.host}:{sender_peer.port}"
        self.peer_manager.misbehaving(
            addr, 10, f"invalid tx: {error}"
        )
```

`add_transaction` routes a conflict-bearing tx to `try_replace`
(`mempool.py:2157-2163`); ANY of the seven RBF gates rejecting →
`success=False` → misbehaving(addr, 10, ...). With a ban threshold
of 100, 10 RBF rejections from one peer = ban.

Concrete failure shapes:

- A Core peer running an aggressive fee-bumping wallet (legitimate
  RBF) routinely sends replacements that ouroboros rejects on:
  - BUG-4 (incremental fee inflation by witness) → 1 score event
  - BUG-8 (`_check_cluster_rbf` rate too low by witness) → 1 score
    event
  - BUG-1 (too many evictees on dense clusters) → 1 score event
- A peer relaying a TRUC fee-bump that ouroboros rejects on BUG-21
  → 1 score event
- A wallet relaying a low-fee tx that fails Rule 3 → 1 score event

**Within hours of a heavy mempool churn, the node's most active
honest peers are all banned.**

**File:** `src/ouroboros/node.py:923-1001`, specifically lines 988-995.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3119-3144`
(`ProcessInvalidTx`); contrast with `MempoolRejectedTx`'s
per-peer-counter design.

**Impact:**
- Eclipse-attack vector: an attacker creates many RBF-conflicting
  txs to ban all honest peers (cost: a few sat per ban).
- Functional break: legitimate Core peers running v28+ Full RBF
  wallets get banned for relaying valid fee-bumps.
- Topology fingerprinting: an attacker can determine
  ouroboros-vs-Core nodes by probing reactivity to RBF replacements.

**Fix shape:** the `misbehaving(addr, 10, …)` line should be gated
on `error` matching only `TX_CONSENSUS`-class reasons (invalid sig,
double-spend in same tx, MoneyRange, weight, sigops over consensus
limit, BIP-30). Policy reasons (RBF Rule N, non-standard, fee, dust,
ancestor limits) should NEVER trigger misbehaving.

---

## BUG-7 (P0-SEC) — TxValidationResult class not modeled; can't distinguish policy from consensus

**Severity:** P0-SEC. Same root as BUG-6 but the structural issue:
ouroboros's `Mempool.add_transaction` returns `tuple[bool, str]` —
no equivalent of `TxValidationResult` (`TX_RESULT_UNSET`,
`TX_CONSENSUS`, `TX_RECENT_CONSENSUS_CHANGE`, `TX_MISSING_INPUTS`,
`TX_PREMATURE_SPEND`, `TX_WITNESS_MUTATED`, `TX_WITNESS_STRIPPED`,
`TX_CONFLICT`, `TX_MEMPOOL_POLICY`, `TX_NO_MEMPOOL`,
`TX_RECONSIDERABLE`, `TX_UNKNOWN`, `TX_INVALID_INPUTS`,
`TX_NOT_STANDARD`).

Without this taxonomy:
- `_make_tx_handler` cannot apply Core's "consensus → punish,
  policy → don't" rule (BUG-6).
- `ProcessOrphanTx` can't tell which orphans are reconsiderable.
- `submitpackage` RPC can't return the per-tx error in Core's
  `error: "<reject_reason>"` format with the result-type prefix.
- BIP-331 `on_pkgtxns` can't decide whether to forward to
  `MempoolRejectedPackage` (Core's path) — it just logs and continues.

**File:** `src/ouroboros/mempool.py:1879-1955` (`accept_to_memory_pool`
returns `dict` with `reject_reason: str`); `add_transaction` returns
`tuple[bool, str]` everywhere.

**Core ref:** `bitcoin-core/src/consensus/validation.h::TxValidationResult`
(14-state enum); `bitcoin-core/src/validation.cpp` PreChecks /
ReplacementChecks / PolicyScriptChecks / ConsensusScriptChecks all
emit specific result codes.

**Impact:** fleet-wide reasoning gap; every consumer of mempool
errors squints at a free-form `str` to guess severity. **NEW
pattern**: "single-tuple-result-loses-error-class" — extends the
W150 N-pipeline drift by noting that even when the pipeline runs,
the result is stringly-typed.

---

## BUG-8 (P1) — `_check_cluster_rbf` uses raw serialised bytes, not vsize

**Severity:** P1. Companion to BUG-4. The cluster-mempool replacement
check at `mempool.py:3383-3482` computes:

```python
new_size = len(new_tx.serialize())          # raw bytes
...
new_tx_rate = new_fee / new_size if new_size > 0 else 0
for cid in affected_cluster_ids:
    cluster = self._cluster_manager._clusters.get(cid)
    if cluster:
        chunks = self._cluster_manager.get_chunks(cluster)
        if chunks:
            for chunk in chunks:
                if chunk.txids & to_evict:
                    if new_tx_rate < chunk.fee_rate * 0.99:  # 1% tolerance
                        return False, ...
```

For SegWit txs `new_size > new_vsize`, so `new_tx_rate` is
UNDERSTATED. Core's `ImprovesFeerateDiagram` (`policy/rbf.cpp:127-140`)
operates on the changeset's `m_chunks` which were computed with
sigop-adjusted vsize. Net effect: ouroboros rejects witness-heavy
replacements that legitimately improve the chunk diagram.

The `* 0.99` "1% tolerance" is also unsourced — Core requires strict
improvement (`std::is_gt(CompareChunks(...))`), no tolerance.

**File:** `src/ouroboros/mempool.py:3424, 3465-3480`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:127-140`;
`bitcoin-core/src/txmempool.h::ChangeSet::CalculateChunksForRBF`.

**Impact:** witness-heavy RBF replacements rejected; the 1% tolerance
silently admits some replacements Core would refuse.

---

## BUG-9 (P0-CDIV) — `on_pkgtxns` runs validate_package AND per-tx add_transaction; success ⇒ N spurious failures

**Severity:** P0-CDIV. `_register_package_relay_handlers.on_pkgtxns`
(`p2p.py:3087-3138`):

```python
try:
    height = self._start_height
    if hasattr(self._mempool, "validate_package"):
        self._mempool.validate_package(txs, height=height)
    for tx in txs:
        try:
            self._mempool.add_transaction(tx, height=height)
        except Exception as e:
            logger.debug(
                f"pkgtxns: failed to add tx from {addr}: {e}"
            )
except Exception as e:
    logger.debug(f"Error processing pkgtxns from {addr}: {e}")
```

Two distinct failure modes:

1. **Successful pkgtxns**: `validate_package` returns True and inserts
   all N txs into the mempool. The subsequent `for tx in txs` loop
   then calls `add_transaction(tx)` for each — every call fails with
   `txn-already-in-mempool` (`mempool.py:1997-1998`). Each failure
   is logged at debug and discarded. **Net effect: success ⇒ N
   spurious "failed to add tx" debug logs.**

2. **Failed pkgtxns** (e.g. CPFP package where the parent is below
   min-relay): `validate_package` returns False without admitting
   anything. The subsequent per-tx loop runs `add_transaction` for
   each tx individually — without RBF, without topo awareness,
   without TRUC package gates. If the package was a 2-tx CPFP, the
   child is offered to `add_transaction` BEFORE the parent (because
   the loop iterates `txs` in input order, which Core specifies as
   "parent first"); but the child can't admit because its parent
   isn't in the mempool — it becomes an orphan. The parent then
   admits successfully. The orphan resolution may later admit the
   child. Or it may not (if the parent was rejected on min-relay
   first). The behavior diverges from Core's `ProcessPackageResult`,
   which routes to `MempoolRejectedPackage` and does NOT retry
   individually.

`validate_package` AND `add_transaction` are BOTH ATMP entry points
in ouroboros's 6-pipeline drift (W150 BUG-1). Running them
back-to-back on the same txs is a structural bug masked by the
debug-log noise.

**File:** `src/ouroboros/p2p.py:3120-3138`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessPackageResult`
(only one pass; result aggregated).

**Impact:**
- Production logs are noisy (every successful pkgtxns ⇒ N spurious
  debug lines), masking real failures.
- For failed packages, the side-effect of per-tx individual
  admission produces inconsistent state: some txs land, others
  bounce into orphan, vs Core's atomic reject.
- BUG-6 amplifies this: the per-tx individual admission loop calls
  `add_transaction`, which on RBF/policy failure would call
  `misbehaving(10)` — except this loop runs inside `on_pkgtxns`,
  which has no `sender_peer` argument. Yet the
  `_make_tx_handler`-style misbehaving call is wired to
  `self.peer_manager` not to a specific peer; the score is applied
  to whichever address `on_pkgtxns` was registered for. Net: a
  pkgtxns-relaying peer can get banned for a failed CPFP via the
  retry loop even when Core would just reject the package once.

---

## BUG-10 (P1) — `rpc_submitpackage` doesn't pre-validate array size at RPC layer

**Severity:** P1. Core's submitpackage RPC handler (`rpc/mempool.cpp:1361-1364`):

```cpp
if (raw_transactions.empty() || raw_transactions.size() > MAX_PACKAGE_COUNT) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       "Array must contain between 1 and " + ToString(MAX_PACKAGE_COUNT) + " transactions.");
}
```

ouroboros's `rpc_submitpackage` (`rpc.py:7942-7946`) checks empty
only:

```python
if not isinstance(package, list) or len(package) == 0:
    raise HTTPException(
        status_code=400,
        detail="package must be a non-empty list of raw transaction hex strings",
    )
```

A 26-tx array passes the RPC gate, then `validate_package` rejects
at line 4509-4512 with `f"Package too large: {len(txs)} > {MAX_PACKAGE_COUNT}"`,
which is returned as `200 OK / {"package_msg": "Package too large…"}`
rather than the Core-style HTTP-level error. Client code branching
on HTTP status will silently mis-process.

**File:** `src/ouroboros/rpc.py:7942-7946`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1361-1364`.

---

## BUG-11 (P0-CDIV) — `submitpackage` `maxfeerate` parameter absent

**Severity:** P0-CDIV. Core's `submitpackage` RPC accepts a per-call
`maxfeerate` (default `DEFAULT_MAX_RAW_TX_FEE_RATE = COIN/10` = 0.1
BTC/kvB) and short-circuits per-tx inside
`AcceptMultipleTransactionsInternal`:

```cpp
if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize) > args.m_client_maxfeerate.value()) {
    ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max feerate exceeded", "");
    package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
    ...
}
```

ouroboros's `rpc_submitpackage(self, package: list[str])`
(`rpc.py:7933`) has **no `maxfeerate` parameter** and no
equivalent gate. A wallet that miscalculates fees and submits a
package at, say, 10 BTC/kvB is silently admitted (subject only to
the `DEFAULT_MIN_RELAY_TX_FEE` lower bound).

Note `rpc_sendrawtransaction` DOES have a maxfeerate parameter
(`rpc.py:2382-2511`) and applies a sanity gate. `submitpackage` is
the regression.

**File:** `src/ouroboros/rpc.py:7933-8019`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1367-1372` (parse);
`bitcoin-core/src/validation.cpp:1458` (gate).

**Impact:** operator footgun — a misbehaving wallet (mis-encoded
amounts in a CPFP) can drain funds via submitpackage. Same
class of bug as not-implementing `maxburnamount` (BUG-12).

---

## BUG-12 (P0-CDIV) — `submitpackage` `maxburnamount` parameter absent

**Severity:** P0-CDIV. Core's `submitpackage` enforces a per-call
`maxburnamount` (default 0) — refuses txs whose `IsUnspendable() ||
!HasValidOps()` outputs exceed the threshold:

```cpp
for (const auto& out : mtx.vout) {
    if((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps()) && out.nValue > max_burn_amount) {
        throw JSONRPCTransactionError(TransactionError::MAX_BURN_EXCEEDED);
    }
}
```

ouroboros's `rpc_submitpackage` has no `maxburnamount` parameter and
no `IsUnspendable` / `HasValidOps` gate. A package containing a tx
that accidentally produces an OP_RETURN with high value is admitted
silently; the funds are burned.

`rpc_sendrawtransaction` also lacks `maxburnamount` (W150 BUG-21);
submitpackage inherits the gap.

**File:** `src/ouroboros/rpc.py:7933-8019`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1375, 1387-1390`.

**Impact:** funds-loss footgun — a wallet bug or a malicious script
producing high-value OP_RETURNs in a package is silently admitted.
Cross-cite W150 BUG-21 for the sendrawtransaction surface.

---

## BUG-13 (P1) — Mempool-layer child-with-parents check ⇒ HTTP-200 on bad input

**Severity:** P1. Per BUG-17, `validate_package` enforces
child-with-parents-tree at the mempool layer. When `submitpackage`
RPC is called with a package that violates this topology, the
error path is:

```
RPC handler → validate_package → returns (False, "package-not-child-with-parents")
RPC handler → return {"package_msg": "package-not-child-with-parents", "tx-results": {}}
```

The HTTP response is 200 OK with the error in the JSON body. Core
throws `JSONRPCTransactionError(TransactionError::INVALID_PACKAGE,
"package topology disallowed. not child-with-parents or parents
depend on each other.")` — HTTP-level RPC error.

Clients porting Core scripts to ouroboros that branch on HTTP
status miss the rejection. The body-level error is also
inconsistently formatted (Core uses `"package topology disallowed
..."`).

**File:** `src/ouroboros/rpc.py:7942-7987`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1395-1397`.

---

## BUG-14 (P0-CDIV) — `validate_package` never tries single-tx submission first; rejects on `txn-already-in-mempool` instead of de-duplicating

**Severity:** P0-CDIV. Bitcoin Core's `AcceptPackage`
(`validation.cpp:1622-1771`) implements an intricate two-phase
algorithm:

1. For each tx in the package, check if it's already in the mempool
   (`m_pool.exists(wtxid)` or `m_pool.exists(txid)` for malleable
   variants). If so, record `results_final[wtxid] = MempoolTx(…)`
   (a SUCCESS result, not a failure) and exclude it from the
   package eval.
2. For each tx NOT in mempool, try SINGLE submission first
   (`AcceptSubPackage({tx}, args)`). If it succeeds — also a
   success. If it fails on `TX_RECONSIDERABLE` or
   `TX_MISSING_INPUTS`, include it in the package eval. Otherwise
   (any other failure), abort the package eval.
3. Run package eval ONLY on the remaining txs.

Quote from the Core comment (lines 1666-1675):
> Node operators are free to set their mempool policies however they
> please, nodes may receive transactions in different orders, and
> malicious counterparties may try to take advantage of policy
> differences to pin or delay propagation of transactions. As such,
> it's possible for some package transaction(s) to already be in the
> mempool, and we don't want to reject the entire package in that case
> (as that could be a censorship vector).

ouroboros's `validate_package` does NONE of this. At line 4636-4640:

```python
for tx in txs:
    txid = tx.get_txid()
    if txid in self.transactions:
        return False, f"Transaction {txid.hex()[:16]}... already in mempool"
```

The entire package is rejected if ANY tx is already known. This is
the exact censorship-vector pattern Core's comment warns about.

Additional implication: a "CPFP-with-1-known-parent" package that
Core gracefully de-duplicates (parent passes-through as `MempoolTx`,
child is package-eval'd) is rejected outright by ouroboros, even
though re-relaying CPFP packages from peers (`on_pkgtxns`) is the
PRIMARY use case for BIP-331.

**File:** `src/ouroboros/mempool.py:4636-4640, 4476-4777`.

**Core ref:** `bitcoin-core/src/validation.cpp:1622-1771`
(AcceptPackage) and `bitcoin-core/src/validation.cpp:1664-1716`
(per-tx de-dup + single-tx-first).

**Impact:**
- **Censorship vector**: an attacker who has a known parent tx in
  multiple mempools can cause ouroboros to reject the entire package
  every time it arrives via pkgtxns from any peer.
- BIP-331 relay effectively broken for CPFP-with-1-known-parent.
- **N-pipeline drift compounding**: in Core, `AcceptPackage` is the
  only valid entry; `AcceptMultipleTransactions` is internal. In
  ouroboros, `validate_package` and `add_transaction` are both
  public; the de-dup logic exists in NEITHER.

---

## BUG-15 (P1) — In-package duplicate detection uses txid, not wtxid

**Severity:** P1. ouroboros's package duplicate-detection
(`mempool.py:4515-4520`):

```python
seen_txids: set[bytes] = set()
for tx in txs:
    txid = tx.get_txid()
    if txid in seen_txids:
        return False, f"Duplicate transaction in package: {txid.hex()[:16]}..."
    seen_txids.add(txid)
```

Core's `IsWellFormedPackage` also uses txid for the duplicate set
(`packages.cpp:94-102`) — so the duplicate check itself matches.
The divergence is **what happens when a package contains
same-txid-different-wtxid (a malleable variant)**: Core's
`AcceptPackage` line 1676-1686 detects this in the per-tx check and
emits `MempoolAcceptResult::MempoolTxDifferentWitness(other_wtxid)`
— a success result that swaps the package member for the mempool
one. ouroboros has no such path; if both the package tx and a
malleable variant are in the mempool with the same txid, the txid
duplicate-check at line 4636-4640 (BUG-14) rejects the entire
package.

**File:** `src/ouroboros/mempool.py:4515-4520, 4636-4640`.

**Core ref:** `bitcoin-core/src/validation.cpp:1676-1686`.

---

## BUG-16 (P0-CDIV) — Package min-relay-fee gate uses raw bytes, not vsize, AND 10× higher constant

**Severity:** P0-CDIV. `validate_package` at `mempool.py:4653-4663`:

```python
total_fees = sum(tx_fees.values())
total_size = sum(len(tx.serialize()) for tx in txs)
package_fee_rate = total_fees / total_size if total_size > 0 else 0
min_relay = (total_size * DEFAULT_MIN_RELAY_TX_FEE) // 1000
if total_fees < min_relay:
    return False, (
        f"Package fee rate too low: {package_fee_rate:.2f} sat/vB "
        f"(need {DEFAULT_MIN_RELAY_TX_FEE / 1000:.2f} sat/vB)"
    )
```

Two compounding bugs:

1. `total_size = sum(len(tx.serialize()))` uses raw witness-included
   serialised bytes. Core's `m_subpackage.m_total_vsize` is the sum
   of sigop-adjusted vsizes (`validation.cpp:1497-1498`). For a
   witness-heavy package the raw-byte total INFLATES the required
   fee.
2. `DEFAULT_MIN_RELAY_TX_FEE = 1000` (sat/kvB) is 10× Core's 100
   sat/kvB (post-v28). Cross-cite W150 BUG-15.

Net: a package at vsize 10 kvB with 1000 sat fee passes Core
(1000 / 10 = 100 sat/kvB ≥ 100). ouroboros at raw-bytes 25 kvB
(witness-heavy) demands 25 * 1000 = 25000 sat ⇒ rejects.

Also the error message claims `"{:.2f} sat/vB"` while the rate is
computed as `total_fees / total_size` (where size is bytes, not
vbytes), so the reported rate is misleading.

**File:** `src/ouroboros/mempool.py:4653-4663`.

**Core ref:** `bitcoin-core/src/validation.cpp:1488-1512`
(`CheckFeeRate`, vsize-based); `bitcoin-core/src/policy/policy.h:70`
(`DEFAULT_MIN_RELAY_TX_FEE{100}`).

**Impact:** witness-heavy CPFP packages legitimate on Core are
rejected by ouroboros. Mirrors W150 BUG-15 on the per-tx surface.

---

## BUG-17 (P1) — `validate_package` unconditionally enforces child-with-parents at mempool layer

**Severity:** P1. Bitcoin Core enforces `IsChildWithParents` only in
`AcceptPackage` (`validation.cpp:1640-1645`) and `IsChildWithParentsTree`
only at the `submitpackage` RPC level (`rpc/mempool.cpp:1395`). The
internal `AcceptMultipleTransactionsInternal` does NOT enforce either
— it accepts any topologically-sorted, consistent, non-conflicting
package.

ouroboros's `validate_package` at `mempool.py:4555-4561`
**unconditionally** enforces BOTH for `len(txs) > 1`:

```python
if len(txs) > 1:
    if not self.is_child_with_parents(txs):
        return False, "package-not-child-with-parents"
    if not self.is_child_with_parents_tree(txs):
        return False, (
            "package topology disallowed: parents depend on each other"
        )
```

Effects:

- A programmatic caller (e.g. mining sub-system, internal test) who
  wants to validate an ancestor-set package (multiple parents, ONE
  of which has a parent in the package) is blocked, even though
  Core's internal `AcceptMultipleTransactions` accepts it.
- Future package types (PSBT v2 multi-child, multi-leaf CPFP) are
  pre-blocked at the wrong layer.
- BIP-331 `on_pkgtxns` (`p2p.py:3127-3129`) routes through the same
  function, so inbound non-tree topologies (legitimate per the BIP)
  are rejected. The BIP allows "any topology"; Core's `AcceptPackage`
  enforces only `IsChildWithParents` (NOT tree); ouroboros enforces
  both.

**File:** `src/ouroboros/mempool.py:4555-4561`.

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1620`
(AcceptMultipleTransactions, no topology gate);
`bitcoin-core/src/validation.cpp:1640-1645` (AcceptPackage, IsChildWithParents only);
`bitcoin-core/src/rpc/mempool.cpp:1395-1397` (submitpackage,
IsChildWithParentsTree).

---

## BUG-18 (P1) — Rolling-min-fee gate skipped during RBF; under-feerate replacements admitted

**Severity:** P1. `_add_transaction_inner` runs rolling-min-fee at
`mempool.py:2284-2291`:

```python
rolling_min_kvb = self._get_min_fee_inner()  # sat/kvB
if rolling_min_kvb > DEFAULT_MIN_RELAY_TX_FEE:
    rolling_min_fee = (tx_vsize * rolling_min_kvb) // 1000
    if fee < rolling_min_fee:
        return False, (...)
```

But this gate is **upstream** of the conflict-check / `try_replace`
short-circuit at line 2157-2163:

```python
has_conflict = any(
    (tx_in.prev_txid, tx_in.prev_vout) in self.spent_outputs
    for tx_in in tx.inputs
)
if has_conflict:
    return self.try_replace(tx, height)
```

…NO wait — re-reading. The conflict-check happens AFTER the
rolling-min-fee gate, at line 2157, post-`validate_transaction`.
Looking at the actual flow:

- Line 2139: `validator.validate_transaction(...)` — consensus check
- Line 2157-2163: conflict check → `try_replace`
- Line 2284-2291: rolling-min-fee gate — **runs after `try_replace`
  would have returned**.

So `try_replace` is invoked BEFORE the rolling-min-fee gate, and
`try_replace` itself does not consult `_get_min_fee_inner`. Result:
a replacement that satisfies Rule 3 + Rule 4 (modified-fee >
original-fee, additional-fee > incremental) but is below the rolling
minimum is **admitted**.

Core's `MemPoolAccept::PreChecks` (`validation.cpp:782-982`)
includes `CheckFeeRate` which gates on both `minRelayTxFee` and
rolling-min-fee BEFORE `ReplacementChecks`.

**File:** `src/ouroboros/mempool.py:2157-2163, 3563-3813`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckFeeRate` (called
from PreChecks before ReplacementChecks).

**Impact:** in a heavy-eviction window the rolling-min-fee bumps to
e.g. 50 sat/vB. A replacement at 2 sat/vB that doubles the original
fee passes ouroboros's RBF gates (BUG-4 inflated) but should be
caught by the rolling-min gate.

---

## BUG-19 (P2) — Constant named MAX_REPLACEMENT_EVICTIONS not MAX_REPLACEMENT_CANDIDATES; semantic divergence

**Severity:** P2 (naming + comment-as-confession). Core's constant
is `MAX_REPLACEMENT_CANDIDATES` (rbf.h:26) — the limit is on the
number of **unique mempool clusters** that may be affected by a
replacement (rbf.h:24-25 comment). ouroboros names the constant
`MAX_REPLACEMENT_EVICTIONS` (`mempool.py:3381`) — semantically
"max number of txs evicted".

The rename is not just cosmetic: it **encodes the BUG-1 divergence
in the name**. A future contributor wanting to ensure parity with
Core would change the value (e.g. raise from 100 to 200) thinking
they were matching Core's `MAX_REPLACEMENT_CANDIDATES` — but the
underlying check is on evictee count, not cluster count.

**Comment-as-confession** at line 3650-3654:

```python
# Gate 3 — Rule #5 MAX_REPLACEMENT_CANDIDATES: The eviction set
# (direct conflicts + all their descendants) must not exceed 100 entries.
# Core uses GetUniqueClusterCount(); without cluster mempool we count
# total evictees as a conservative bound (same limit, same intent).
# Reference: bitcoin/src/policy/rbf.cpp GetEntriesForConflicts() lines 68-75
```

— acknowledges "Core uses GetUniqueClusterCount(); … same limit, same
intent." But ouroboros DOES have cluster-mempool primitives
(`self._cluster_manager`, used elsewhere in this very function),
so the "without cluster mempool" justification is false.

**File:** `src/ouroboros/mempool.py:3381, 3650-3659`.

**Core ref:** `bitcoin-core/src/policy/rbf.h:24-26`.

---

## BUG-20 (P2) — `mempoolfullrbf` CLI flag absent

**Severity:** P2. Bitcoin Core REMOVED the `-mempoolfullrbf` flag
in v28 (always-full RBF), so the parity gap is purely defensive.
ouroboros's `Mempool.__init__(full_rbf=True)` default matches Core,
but the only way to flip it is via the constructor — no CLI argument,
no config-file setting. Tests that want to verify opt-in-only RBF
semantics must instantiate a separate `Mempool(full_rbf=False)`
instead of toggling via runtime config.

**File:** `src/ouroboros/mempool.py:1573, 1593`.

---

## BUG-21 (P0-CDIV) — Sibling-eviction incremental fee gate uses raw bytes, not vsize

**Severity:** P0-CDIV. Companion to BUG-4 on the TRUC sibling-eviction
surface. `_try_sibling_eviction` at `mempool.py:2810-2883`:

```python
new_size = len(new_tx.serialize())
...
incremental_fee_needed = (new_size * self.INCREMENTAL_RELAY_FEE) // 1000
additional_fee = new_fee - sibling_fee
if additional_fee < incremental_fee_needed:
    return False, (...)
```

Same shape: raw-bytes input to a per-kvB rate. Core's TRUC sibling
eviction (`policy/truc_policy.cpp` + the standard ReplacementChecks
path) uses vsize.

Additional bug: `sibling_fee = sibling_entry.fee` is the **unmodified**
fee, not `get_modified_fee(sibling_entry)`. A user-prioritised
sibling (`prioritisetransaction`) appears cheaper to the gate ⇒
easier to evict than it should be.

**File:** `src/ouroboros/mempool.py:2826, 2849, 2857`.

**Core ref:** `bitcoin-core/src/policy/truc_policy.cpp` sibling
eviction; `bitcoin-core/src/policy/rbf.cpp:117-123`.

---

## BUG-22 (P1) — Sibling-eviction is a separate pipeline; skips MAX_REPLACEMENT_CANDIDATES, EntriesAndTxidsDisjoint, HasNoNewUnconfirmed

**Severity:** P1. **N-pipeline drift carry-forward — 7th distinct
entry in ouroboros**, extending the W150 record of 6.

`_try_sibling_eviction` (`mempool.py:2810-2883`) is its own pipeline
parallel to `_try_replace_inner`:

```python
def _try_sibling_eviction(self, new_tx, sibling_txid, height):
    # Calculate fee
    # Sibling fee >, incremental fee
    # remove_transaction(sibling)
    # _add_transaction_inner(new_tx)
```

Gates that `_try_replace_inner` runs but `_try_sibling_eviction`
DOES NOT:
- MAX_REPLACEMENT_EVICTIONS (Rule 5)
- HasNoNewUnconfirmed (Rule 2 part — should be dropped anyway per BUG-23)
- EntriesAndTxidsDisjoint
- `_check_cluster_rbf` (the cluster-feerate-diagram check)
- Conflicts → descendant collection (only evicts the single named
  sibling, not its descendants)

Core's sibling eviction is **part of the standard ReplacementChecks
path** — the sibling is added to `direct_conflicts` and the same
ReplacementChecks run. There is no parallel pipeline. Quote from
Core inline comment (`validation.cpp:969`): "The sibling will be
treated as part of the to-be-replaced set in ReplacementChecks."

**File:** `src/ouroboros/mempool.py:2810-2883`.

**Core ref:** `bitcoin-core/src/policy/truc_policy.cpp:171-261`
SingleTRUCChecks, `bitcoin-core/src/validation.cpp:969`.

**Impact:** TRUC sibling eviction admits replacements that should
fail the standard RBF gates (e.g. a sibling-eviction that introduces
new unconfirmed inputs from a different mempool ancestor).

---

## BUG-23 (P1) — Enforces dropped Core rule (HasNoNewUnconfirmed)

**Severity:** P1. Bitcoin Core's BIP-125 Rule #2 historically had
two parts: (a) replacement spends no NEW unconfirmed inputs, and
(b) replacement's ancestors don't include any directly-conflicting
tx (EntriesAndTxidsDisjoint). The 2024 cluster-mempool migration
dropped (a) — `rbf.cpp` now only contains `EntriesAndTxidsDisjoint`;
the "no new unconfirmed inputs" semantics are subsumed by the
diagram-improvement check.

ouroboros's `try_replace` at `mempool.py:3661-3684`:

```python
# Rule #2 (HasNoNewUnconfirmed): The replacement must not introduce any
# new unconfirmed inputs that were not already spent by the to-be-evicted
# transactions.
...
old_unconfirmed: set[OutPoint] = set()
for evict_txid in to_evict:
    evict_entry = self.transactions[evict_txid]
    for inp in evict_entry.tx.inputs:
        op: OutPoint = (inp.prev_txid, inp.prev_vout)
        if inp.prev_txid in self.transactions:
            old_unconfirmed.add(op)
for inp in new_tx.inputs:
    op = (inp.prev_txid, inp.prev_vout)
    if inp.prev_txid in self.transactions and op not in old_unconfirmed:
        return False, (...)
```

— enforces a Core-dropped rule. Replacements that introduce new
unconfirmed inputs (a common pattern: bumping a fee by adding a
fresh UTXO from an unconfirmed parent) are REJECTED by ouroboros
even though Core accepts after the cluster-diagram check.

**File:** `src/ouroboros/mempool.py:3661-3684`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp` (current) has only
`EntriesAndTxidsDisjoint`; `HasNoNewUnconfirmed` was removed
2024-2025.

**Impact:** anti-pinning replacement workflows that legitimately
add new unconfirmed inputs are rejected; cross-impl divergence on
post-2024 Core RBF semantics.

---

## BUG-24 (P1) — `on_pkgtxns` bypasses the not-synced gate that protects plain `tx` handler

**Severity:** P1. `_make_tx_handler` (`node.py:923-1001`) — the
inbound `tx` message handler — implicitly relies on the node being
synced before relaying anything (the relay block at lines 960-986
skips peers whose feefilter exceeds, etc., but does not gate on
sync). Concretely: there is NO `if not self.synced: return` at the
top of the handler — the tx is admitted and relayed regardless of
IBD state. (This is itself a W138-class plumb-gate-then-flip issue
not in scope for W151.)

`on_pkgtxns` (`p2p.py:3087-3138`) ALSO has no sync gate. So during
IBD, an attacker can flood `pkgtxns` messages and have ouroboros's
mempool fill up before it's safe to evaluate. Compounding with
BUG-6 / BUG-7 — during IBD, the misbehaving counter for legitimate
peers ramps up because IBD-stale prevout checks fail and every
rejection scores +10.

**File:** `src/ouroboros/p2p.py:3087-3138` (no sync gate);
`src/ouroboros/node.py:923-1001` (also no sync gate, but at least
checks `self.mempool is not None`).

**Core ref:** `bitcoin-core/src/net_processing.cpp` — tx handlers
gate on `IsInitialBlockDownload()`.

---

## Cross-cite summary

| BUG | Severity | Pattern |
|-----|----------|---------|
| BUG-1 | P0-CDIV | RBF Rule 5: evictees vs unique-clusters axis |
| BUG-2 | P0-CDIV | RBF gate-order divergence; EntriesAndTxidsDisjoint at wrong layer |
| BUG-3 | (see BUG-23) | enforces Core-dropped Rule 2 part (HasNoNewUnconfirmed) |
| BUG-4 | P0-CDIV | Rule 4 incremental fee: raw bytes not vsize ⇒ 2-3× over-charge |
| BUG-5 | P1 | `IsRBFOptInEmptyMempool` absent; UNKNOWN/FINAL collapsed |
| BUG-6 | P0-SEC | RBF rejection → Misbehaving(10) (W150 BUG-23 ECHO; RBF-specific surface) |
| BUG-7 | P0-SEC | TxValidationResult class absent ⇒ policy vs consensus reasons indistinguishable |
| BUG-8 | P1 | `_check_cluster_rbf` raw bytes + 1% tolerance |
| BUG-9 | P0-CDIV | `on_pkgtxns` runs both pipelines; success ⇒ N spurious failures, failure ⇒ per-tx retry |
| BUG-10 | P1 | submitpackage no RPC-layer size pre-check |
| BUG-11 | P0-CDIV | submitpackage `maxfeerate` parameter absent (funds footgun) |
| BUG-12 | P0-CDIV | submitpackage `maxburnamount` parameter absent (funds-loss) |
| BUG-13 | P1 | child-with-parents rejection ⇒ HTTP-200 + body error (wrong RPC convention) |
| BUG-14 | P0-CDIV | `validate_package` never tries single-tx-first; rejects on `txn-already-in-mempool` (censorship vector) |
| BUG-15 | P1 | in-package duplicate by txid (no MempoolTxDifferentWitness path) |
| BUG-16 | P0-CDIV | package min-relay-fee: raw bytes + 1000 sat/kvB (W150 BUG-15 echo) |
| BUG-17 | P1 | child-with-parents enforced at wrong layer (mempool not RPC) |
| BUG-18 | P1 | rolling-min-fee gate skipped during RBF |
| BUG-19 | P2 | constant name + comment-as-confession (encodes BUG-1) |
| BUG-20 | P2 | `-mempoolfullrbf` CLI flag absent (mostly cosmetic post-v28) |
| BUG-21 | P0-CDIV | TRUC sibling eviction: raw bytes, unmodified-fee comparison |
| BUG-22 | P1 | TRUC sibling eviction is parallel pipeline (7th N-pipeline drift entry) |
| BUG-23 | P1 | enforces dropped Core rule HasNoNewUnconfirmed |
| BUG-24 | P1 | `on_pkgtxns` bypasses (already-absent) sync gate |

---

## Fleet-pattern carry-forwards

- **W150 BUG-23 `misbehaving-on-policy-reject` ECHO**: BUG-6 confirms
  the SAME pipeline that fires on standardness rejections ALSO fires
  on RBF rejections (Rules 1-5 + cluster + sibling eviction). The
  attack surface is now 7 distinct policy-class events: non-standard,
  low fee, dust, sigops, ancestor saturation, RBF Rules 1-5,
  sibling eviction. Same fix shape: gate `misbehaving(10)` on
  TX_CONSENSUS-class reasons only.
- **N-pipeline drift extension to 7**: BUG-22 confirms
  `_try_sibling_eviction` is a 7th distinct ATMP/RBF pipeline,
  extending W150 BUG-1's record of 6. ouroboros now holds N-pipeline
  drift at 7 in this surface alone.
- **W132 BIP-68 OUROBOROS_BIP68_STOPGAP** indirectly traversable from
  package pipeline via `validator.validate_transaction` call chain
  (G37); no NEW stopgap added in this surface.
- **`raw-bytes-vs-vsize` cluster**: BUG-4 + BUG-8 + BUG-16 + BUG-21
  all share the same root: ouroboros uses `len(tx.serialize())`
  (raw witness-included bytes) where Core uses vsize. **4 distinct
  call sites in this audit alone, all post-SegWit-era**. Pattern
  candidate: "raw-serialise-where-vsize-needed" — fleet-wide W122/W135
  echo (witness-discount missed). 4 fixes are all single-line each.
- **W125 reject-reason wire-parity slippage**: BUG-10 + BUG-13 (RPC
  body-only error vs HTTP exception); fleet pattern.
- **`comment-as-confession` 7th instance in ouroboros**: BUG-19 line
  3650-3654 literally documents "Core uses GetUniqueClusterCount();
  without cluster mempool we count total evictees as a conservative
  bound (same limit, same intent)" — but cluster-mempool IS present
  in the file. Pattern is a 5th distinct instance in ouroboros after
  W128/W132/W138/W141/W150.
- **W138-class `dead-data BIP9` analogue**: BUG-11 + BUG-12 — RPC
  parameters declared in Core's interface but **absent in ouroboros's
  RPC handler** (vs Core's "declared but never set" pattern). Same
  net effect: documented gate doesn't exist.

---

## Top findings (priority order for next fix wave)

1. **BUG-6 P0-SEC**: gate `misbehaving(addr, 10, …)` on TX_CONSENSUS-
   class errors only. Closes the eclipse-attack vector. ~10 LOC fix:
   add an error-class taxonomy or pattern-match on known
   consensus-class reject reasons. **Highest priority** — actively
   bans honest peers.
2. **BUG-14 P0-CDIV**: `validate_package` must try single-tx
   submission first AND de-duplicate already-in-mempool txs. Closes
   the censorship vector and is the core enabler for BIP-331 pkgtxns
   relay. ~50 LOC reorganisation of the `_validate_package_inner`
   prelude.
3. **BUG-4 + BUG-8 + BUG-16 + BUG-21 cluster (P0-CDIV ×3 + P1 ×1)**:
   change `new_size = len(new_tx.serialize())` to
   `new_size = new_tx.get_vsize()` in 4 sites. One-line each. Net:
   restores Core-parity on RBF fee gates AND package fee gate AND
   cluster diagram AND TRUC sibling eviction.
4. **BUG-11 + BUG-12 P0-CDIV cluster**: add `maxfeerate` and
   `maxburnamount` parameters to `rpc_submitpackage`. ~30 LOC. Closes
   the funds-loss/funds-burn footguns.
5. **BUG-1 P0-CDIV**: change Rule 5 gate to bound on
   `len({cluster_id(c) for c in conflicts})` not `len(to_evict)`.
   Requires plumbing `_cluster_manager.get_cluster_id` into
   `_try_replace_inner` (~5 LOC).
6. **BUG-23 P1**: remove HasNoNewUnconfirmed enforcement
   (mempool.py:3661-3684, ~20 LOC delete).
7. **BUG-9 P0-CDIV**: in `on_pkgtxns`, remove the per-tx
   `add_transaction` loop after `validate_package` (~10 LOC delete).
8. **BUG-22 P1**: fold `_try_sibling_eviction` into
   `_try_replace_inner` via the conflicts set. Requires plumbing the
   sibling-txid into `_find_conflicts` for TRUC paths.

---

## Operator-visible smoke tests

- Submit a 25-tx package where parent[0] is already in the mempool
  (e.g. previously sent via `sendrawtransaction`) and observe
  rejection on ouroboros vs success on Core (BUG-14).
- Submit a SegWit replacement that bumps fee by exactly
  `incremental_relay_fee × vsize / 1000` and observe rejection
  ouroboros vs admission Core (BUG-4).
- Run ouroboros as a relay peer of a Core node running a
  fee-bumping wallet; observe the peer-disconnect rate (BUG-6).
- Submit a package with a 1 BTC OP_RETURN output to
  `submitpackage` and observe silent acceptance ouroboros vs
  MAX_BURN_EXCEEDED error Core (BUG-12).
