# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (ouroboros)

**Wave:** W150 — `AcceptToMemoryPool`, `AcceptSingleTransaction`,
`MemPoolAccept::PreChecks`, `MemPoolAccept::PolicyScriptChecks`,
`MemPoolAccept::ConsensusScriptChecks`, `MemPoolAccept::Finalize`,
`IsStandardTx` (policy.cpp), `IsWitnessStandard`, `ValidateInputsStandardness`,
`GetDustThreshold`, `CheckFeeRate`, `bypass_limits`, `m_package_feerates`,
`CheckSigopsBIP54`, RBF, package validation, and orphan handling.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:782-982` — `MemPoolAccept::PreChecks`
  (CheckTransaction → coinbase → IsStandardTx → MIN_STANDARD_TX_NONWITNESS_SIZE
  → CheckFinalTxAtTip → wtxid+txid dupe → conflict scan → input existence →
  CheckSequenceLocksAtTip → Consensus::CheckTxInputs → ValidateInputsStandardness
  → IsWitnessStandard → GetTransactionSigOpCost(STANDARD) → m_changeset →
  PreCheckEphemeralTx → MAX_STANDARD_TX_SIGOPS_COST → CheckFeeRate → TRUC).
- `bitcoin-core/src/validation.cpp` (~1135-1156) — `PolicyScriptChecks`:
  CheckInputScripts with `STANDARD_SCRIPT_VERIFY_FLAGS`. Failures are
  `TX_NOT_STANDARD` (don't ban peer).
- `bitcoin-core/src/validation.cpp` (~1162-1200) — `ConsensusScriptChecks`:
  CheckInputScripts with consensus-only flags (per-height).
  Failures are `TX_CONSENSUS` (peer misbehavior).
- `bitcoin-core/src/policy/policy.cpp:100-165` — `IsStandardTx(tx,
  max_datacarrier_bytes, permit_bare_multisig, dust_relay_fee, reason)` —
  knobs operator can flip via `-datacarriersize`, `-permitbaremultisig`,
  `-dustrelayfee`.
- `bitcoin-core/src/policy/policy.cpp:27-64` — `GetDustThreshold(txout,
  dustRelayFeeIn)`: `GetSerializeSize(txout) + spend_cost` then
  `× DUST_RELAY_TX_FEE / 1000`. Segwit spend gets 75% witness-discount on the
  107-byte input script.
- `bitcoin-core/src/policy/policy.cpp:170-194` — `CheckSigopsBIP54`:
  per-input accurate sigop count ≤ `MAX_TX_LEGACY_SIGOPS=2500`. Mandatory in
  `ValidateInputsStandardness` (line 221-224).
- `bitcoin-core/src/policy/policy.cpp:214-263` — `ValidateInputsStandardness`:
  Solver result must not be NONSTANDARD / WITNESS_UNKNOWN; for P2SH the
  redeemScript must not exceed `MAX_P2SH_SIGOPS=15` accurately-counted.
- `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`:
  P2A reject on witness; P2WSH stack≤100, item≤80, script≤3600; P2TR
  annex reject; tapscript items ≤80.
- `bitcoin-core/src/policy/policy.h` —
  `DEFAULT_INCREMENTAL_RELAY_FEE{100}` sat/kvB,
  `DEFAULT_MIN_RELAY_TX_FEE{100}` sat/kvB (lowered from 1000 in v28),
  `MAX_STANDARD_TX_WEIGHT{400000}`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS{100}` / `STACK_ITEM_SIZE{80}`,
  `MAX_STANDARD_TX_SIGOPS_COST=MAX_BLOCK_SIGOPS_COST/5=16000`,
  `MIN_STANDARD_TX_NONWITNESS_SIZE{65}`,
  `DEFAULT_BYTES_PER_SIGOP{20}`,
  `DEFAULT_PERMIT_BAREMULTISIG{true}`,
  `MAX_TX_LEGACY_SIGOPS{2500}` (BIP-54),
  `MAX_REPLACEMENT_CANDIDATES{100}` (rbf.h:26).
- `bitcoin-core/src/script/interpreter.h` — `STANDARD_SCRIPT_VERIFY_FLAGS`,
  `MANDATORY_SCRIPT_VERIFY_FLAGS`.
- `bitcoin-core/src/policy/truc_policy.cpp:171-261` — `SingleTRUCChecks`,
  TRUC_MAX_VSIZE/CHILD_MAX_VSIZE/ANCESTOR/DESCENDANT, sibling eviction.
- `bitcoin-core/src/node/transaction.h:28` —
  `DEFAULT_MAX_RAW_TX_FEE_RATE{COIN/10}` (0.1 BTC/kvB).
- `bitcoin-core/src/rpc/mempool.cpp:1322` — `submitpackage` `maxburnamount`
  parameter; `node/transaction.h::DEFAULT_MAX_BURN_AMOUNT`.

**Files audited**
- `src/ouroboros/mempool.py` — `Mempool`, `accept_to_memory_pool`,
  `add_transaction`, `_add_transaction_inner`, `try_replace`,
  `_check_truc_policy`, `validate_package`, `_check_ephemeral_dust`,
  `_is_standard_tx`, `_is_standard_output_type`, `_get_dust_threshold`,
  `_has_ephemeral_dust`, `_validate_inputs_standardness`,
  `_is_witness_standard`, `_compute_tx_sigop_cost`, `OrphanPool`,
  rolling minimum fee (`_get_min_fee_inner`, `_track_package_removed`),
  `_insert_sorted_by_fee_rate`, `_evict_low_fee_txs`.
- `src/ouroboros/validation.py` — `TransactionValidator.validate_transaction`,
  `_check_structure`, `_verify_input_signature`, `_is_final_tx`,
  `check_sequence_locks` (BIP-68 stopgap incl. `OUROBOROS_BIP68_STOPGAP`),
  `MAX_MONEY`/`MAX_BLOCK_SIGOPS_COST`/`DEFAULT_BYTES_PER_SIGOP` constants.
- `src/ouroboros/script.py` — `get_flags_for_height`,
  `get_standard_script_flags`, `_SCRIPT_FLAG_EXCEPTIONS`.
- `src/ouroboros/rpc.py` — `rpc_sendrawtransaction` (incl. its own duplicate
  fee/vsize computation), `rpc_testmempoolaccept`, `rpc_submitpackage`,
  `rpc_getmempoolinfo`, `_map_mempool_error_to_reject_reason`,
  `submitblock` reorg path that re-adds via `add_transaction` (no
  bypass_limits).
- `src/ouroboros/p2p.py` — `on_pkgtxns` handler (BIP-331 package relay).
- `src/ouroboros/node.py` — `_make_tx_handler` (P2P tx handler), `synced`
  flag wiring, `_check_synced`, sync gate.
- `src/ouroboros/sync_manager.py` — `SyncManager.is_synced` (delegates to
  Rust `fast_sync.is_synced`).
- `src/ouroboros/cli.py` — `Mempool()` (no-arg, type-error) at line 686.

---

## Gate matrix (40 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ATMP entry points | G1: single canonical entry vs N-pipeline drift | **BUG-1 (P0-CDIV)** — FIVE parallel entries: `accept_to_memory_pool` (mempool.py:1879), `add_transaction` (mempool.py:1874→`_add_transaction_inner`), `rpc_sendrawtransaction` (rpc.py:2382, does pre-fee + pre-maxfee check), `rpc_submitpackage` (calls `validate_package`), `validate_package` (mempool.py:4476), `on_pkgtxns` (p2p.py:3087, calls validate_package + add_transaction), `_make_tx_handler` (node.py:923 calls add_transaction), reorg refill (rpc.py:6048 calls add_transaction). |
| 2 | PreChecks: coinbase reject | G2: reject coinbase loose tx | PASS (`mempool.py:1976-1981, 1904-1908`) |
| 2 | … | G3: same in test_accept path | PASS (`mempool.py:1904-1912`) |
| 3 | IsStandardTx | G4: version range [1, TX_MAX_STANDARD_VERSION] | PASS (`mempool.py:1125-1126`) |
| 3 | … | G5: weight ≤ MAX_STANDARD_TX_WEIGHT | PASS (`mempool.py:1133-1135`) |
| 3 | … | G6: nonwitness size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE=65 (CVE-2017-12842) | PASS (`mempool.py:1140-1142`) |
| 3 | … | G7: per-input scriptSig size + push-only | PASS (`mempool.py:1148-1152`) |
| 3 | … | G8: bare-multisig pattern match (Solver MULTISIG with n≤3) | **BUG-2 (P1)** `_is_standard_output_type` matches **any** ≥3-byte script ending in `0xae` (OP_CHECKMULTISIG) as standard (`mempool.py:867`). Core's Solver enforces strict `OP_m PUSH-pk... OP_n OP_CHECKMULTISIG` shape AND `1 ≤ m ≤ n ≤ 3`. Arbitrary garbage ending in 0xae passes the gate. |
| 3 | … | G9: `-permitbaremultisig=false` (DEFAULT_PERMIT_BAREMULTISIG=true) operator knob | **BUG-3 (P1)** — no `-permitbaremultisig` flag at all; can never be disabled. Bare-multisig outputs always considered standard. |
| 3 | … | G10: `-datacarrier=false` operator knob | **BUG-4 (P1)** — no `-datacarrier` flag; OP_RETURN outputs always treated as standard via `_is_standard_output_type` (`mempool.py:835-836`). Operator cannot disable datacarrier relay. |
| 3 | … | G11: `-datacarriersize` operator knob (Core: `max_datacarrier_bytes`) | **BUG-5 (P1)** — hardcoded `MAX_OP_RETURN_RELAY=100_000` (`mempool.py:43, 1166`); no per-policy override. |
| 3 | … | G12: dust ≤ MAX_DUST_OUTPUTS_PER_TX (=1) | PASS (`mempool.py:1182-1188`) |
| 4 | GetDustThreshold semantics | G13: include serialized-txout bytes (`GetSerializeSize(txout)`) | **BUG-6 (P0-CDIV)** — uses hardcoded `n_size` (99 / 110 / 182 / 182) without `GetSerializeSize(txout)`. Core's formula is `(GetSerializeSize(txout) + spend_cost) × dust_relay_fee / 1000`. ouroboros's value for P2WPKH is 99 instead of 31+67=98; for P2SH 182 instead of 32+148=180. Drifts the threshold for non-default `-dustrelayfee` values. |
| 4 | … | G14: witness-program detection via IsWitnessProgram, not length heuristic | **BUG-7 (P1)** — length-based heuristic (`len==22 and [0]==0x00 → P2WPKH`, `len==34 and [0]∈(0x00,0x51) → P2WSH/P2TR`) at `mempool.py:887-895`. Any 22-byte non-witness scriptPubKey starting 0x00 is misclassified as P2WPKH and gets the 99-byte threshold; a 34-byte non-witness scriptPubKey starting OP_1 (0x51) gets the witness threshold. Core uses `IsWitnessProgram` which inspects opcode + length. |
| 4 | … | G15: IsUnspendable → 0 dust threshold | **BUG-8 (P2)** — only OP_RETURN (`[0]==0x6a`) is short-circuited (`mempool.py:910`); other unspendable shapes (OP_RETURN+empty, scripts that hash-encode to `OP_RETURN OP_PUSHBYTES_N` truncated) follow the normal threshold path. |
| 5 | wtxid + txid duplicate detection (BIP-339) | G16: wtxid-first then txid (`txn-already-in-mempool` / `txn-same-nonwitness-data-in-mempool`) | PASS (`mempool.py:1995-1998, 1919-1923`) |
| 5 | … | G17: `txn-already-known` (tx already mined, UTXO consumed) | **BUG-9 (P1)** — no equivalent. Tx whose outputs already in UTXO set is treated as missing inputs → orphan. Eats orphan slots until ORPHAN_EXPIRY_SECONDS=1200. Core: `txn-already-known` reject + no orphan storage. |
| 5 | … | G18: in-package duplicate by wtxid (validate_package) | **BUG-10 (P1)** — `seen_txids` (line 4515-4520) uses txid not wtxid. Two malleable variants of the same tx pass duplicate check; only the first lands. |
| 6 | CheckFinalTxAtTip / BIP-68 | G19: locktime checked at tip+1 | PASS (`mempool.py:2107`, validation.py `_is_final_tx`) |
| 6 | … | G20: BIP-68 SequenceLocks at tip+1 | PASS via `check_sequence_locks` with stopgap env-var (validation.py:2307+, **carries OUROBOROS_BIP68_STOPGAP** see W132 BUG-4) |
| 7 | Input-side standardness | G21: Solver result not NONSTANDARD/WITNESS_UNKNOWN | PASS (`mempool.py:1064-1080`) |
| 7 | … | G22: P2SH redeemScript sigop ≤ MAX_P2SH_SIGOPS=15 | PASS (`mempool.py:1084-1107`) |
| 7 | … | G23: BIP-54 per-input sigops ≤ MAX_TX_LEGACY_SIGOPS=2500 | **BUG-11 (P0-CDIV)** — `CheckSigopsBIP54` entirely absent. `ValidateInputsStandardness` in Core (policy.cpp:221-224) calls it mandatorily; failure = `bad-txns-nonstandard-inputs`. ouroboros's `_validate_inputs_standardness` skips this check. Gates 5+ impls fleet-wide (cross-cite W135 fleet pattern). |
| 8 | IsWitnessStandard | G24: P2A reject on witness | PASS (`mempool.py:1332-1333`) |
| 8 | … | G25: P2WSH script ≤ 3600, items ≤ 100, item ≤ 80 | PASS (`mempool.py:1354-1367`) |
| 8 | … | G26: P2TR annex reject, tapscript items ≤ 80 | PASS (`mempool.py:1368-1391`) |
| 9 | PolicyScriptChecks vs ConsensusScriptChecks | G27: TWO distinct passes (STANDARD then MANDATORY-only) | **BUG-12 (P0-CDIV)** — single combined `validate_transaction` with `extra_script_flags = standard & ~consensus` OR'd into the consensus flag set (`mempool.py:2123-2142`). Core's two-phase design means a STANDARD-only fail (e.g. NULLFAIL, LOW_S) is `TX_NOT_STANDARD` and the peer is NOT banned; a CONSENSUS-only fail is `TX_CONSENSUS` and the peer IS banned. Combined gate cannot distinguish — and the P2P tx handler (`node.py:993-995`) calls `misbehaving(addr, 10)` on EVERY non-success error, conflating policy with consensus. |
| 9 | … | G28: STANDARD flag derivation gracefully degrades | **BUG-13 (P0-SEC)** — broad `except Exception: extra_flags = 0` (`mempool.py:2134-2137`). Any import failure or runtime exception in `ouroboros.script` silently drops STANDARD flags AND there is no log line — non-standard transactions pass policy gates. Carry-forward of the "silent degradation" pattern. |
| 9 | … | G29: `script_flag_exceptions` block-hash-aware in mempool | **BUG-14 (P2)** — `next_height` flag derivation passes `block_hash=None` (`mempool.py:2130-2131`). For NEXT-block mempool acceptance the block hash is unknown so this is technically correct, but the comment doesn't note the implicit invariant — operators reading the code may assume per-block-hash exceptions are honored in mempool. |
| 10 | CheckFeeRate (min-relay) | G30: enforce DEFAULT_MIN_RELAY_TX_FEE=100 sat/kvB | **BUG-15 (P0-CDIV)** — `DEFAULT_MIN_RELAY_TX_FEE = 1000` sat/kvB (`mempool.py:49`) — 10× higher than Core's 100 (lowered in v28+). ouroboros rejects txs at 0.1-0.9 sat/vB that Core accepts. Also `getmempoolinfo` hardcodes `minrelaytxfee = 0.00001 BTC/kvB = 1 sat/vB = 1000 sat/kvB` (`rpc.py:2311, 2360` and `rest.py:1258`) — operator monitoring is misleading even apart from the gate value. |
| 10 | … | G31: `-minrelaytxfee` CLI flag | **BUG-16 (P1)** — absent. Hardcoded. |
| 10 | … | G32: rolling minimum fee respects `incremental_relay_feerate` halving threshold | PASS (`mempool.py:1711` clamps to `< INCREMENTAL_RELAY_FEE/2`) |
| 10 | … | G33: `bypass_limits` skips min-relay + ancestor limits (reorg readd) | **BUG-17 (P0-CDIV)** — no `bypass_limits` parameter. Reorg refill (`rpc.py:6048`) calls `add_transaction(tx, final_height)` without bypass. Txs that were mined into the disconnected block and are below the rolling-min or have ancestor saturated chains are silently dropped — Core would re-admit via `bypass_limits=true`. Same for `disconnectBlock` paths. |
| 10 | … | G34: `m_package_feerates` flag for per-tx fee gate skip during package validation | **BUG-18 (P1)** — `validate_package` does its own package-level fee check (`mempool.py:4658-4663`) but never sets a per-tx skip flag; it just never calls `_add_transaction_inner` for per-tx fee gates. |
| 11 | sigop cost limit | G35: ≤ MAX_STANDARD_TX_SIGOPS_COST=16000 | PASS (`mempool.py:2087-2091`) |
| 11 | … | G36: `-bytespersigop` operator knob | **BUG-19 (P1)** — no knob; `DEFAULT_BYTES_PER_SIGOP=20` hardcoded. |
| 12 | RPC parity | G37: `testmempoolaccept` runs full mempool acceptance pipeline | **BUG-20 (P0-CDIV)** — `rpc_testmempoolaccept` (`rpc.py:7905-7931`) calls `validator.validate_transaction` directly — bypasses `_is_standard_tx`, `_validate_inputs_standardness`, `_is_witness_standard`, sigop cost, fee gates, TRUC checks, RBF gates, ancestor/descendant limits. Returns `allowed=true` for txs that the real mempool would reject. Core's `testmempoolaccept` calls `ProcessNewPackage(/*test_accept=*/true)` — full policy + consensus. Major divergence. |
| 12 | … | G38: `submitpackage` returns wtxid-keyed `tx-results` matching Core | PASS (`rpc.py:7996-8014`) |
| 12 | … | G39: `sendrawtransaction` `maxburnamount` parameter | **BUG-21 (P1)** — not implemented (`rpc.py:2382-2538`). Core's `sendrawtransaction` and `submitpackage` accept `maxburnamount` to refuse txs with unspendable outputs above the threshold. |
| 12 | … | G40: reject-string mapping for wire parity | **BUG-22 (P1)** — `_map_mempool_error_to_reject_reason` (`rpc.py:2540-2596`) uses fuzzy substring matching (`if "script" in error.lower(): return "script-failed"`). Maps `Output 0 has non-standard script type (scriptpubkey)` → `"script-failed"` (should be `"scriptpubkey"`); `Transaction weight … exceeds 400000` → `"tx-size"` matches Core but is reached via `"size" in error.lower()` so any error string containing "size" hits it; `bad-txns-too-many-sigops` substring "size" → returns `"tx-size"` (WRONG, should pass through). Reject-reason wire-parity slippage, fleet pattern (cross-cite W125/W145). |

---

## BUG-1 (P0-CDIV) — Six-pipeline drift for ATMP / mempool acceptance

**Severity:** P0-CDIV (**"N-pipeline drift" 6th distinct ouroboros instance**;
extends the W149 6-pipeline-for-validate/connect record. ouroboros now holds
both records).

Bitcoin Core has ONE canonical entry point for mempool acceptance:
`MemPoolAccept::AcceptSingleTransaction` (validation.cpp). Every caller —
`sendrawtransaction`, `submitpackage`, `testmempoolaccept`, P2P `tx`
handler, BIP-331 `on_pkgtxns`, reorg refill via
`MaybeUpdateMempoolForReorg` — routes through `ProcessNewPackage` →
`MemPoolAccept::AcceptSingleTransaction` or `AcceptPackage`. The same gates
fire in the same order; the same reject reasons emerge.

ouroboros has SIX coexisting entry points each running a different subset
of the gates:

1. **`Mempool.accept_to_memory_pool`** (`mempool.py:1879-1955`) — the
   "official" public entry. Has a `test_accept` shortcut that runs
   `_is_standard_tx` AND wtxid/txid dupe detection BUT skips `_is_final_tx`,
   `_validate_inputs_standardness`, `_is_witness_standard`, sigop-cost,
   fee gates, TRUC, RBF, ancestor/descendant. Then for non-test calls
   delegates to `add_transaction` → `_add_transaction_inner`.

2. **`Mempool.add_transaction`** (`mempool.py:1874-1877`) → `_add_transaction_inner`
   (mempool.py:1957-2364) — the actual heavy-lift gate runner.

3. **`rpc_sendrawtransaction`** (`rpc.py:2382-2538`) — does its own coinbase
   reject, has-transaction shortcut, tx-index shortcut, fee+vsize calculation,
   `maxfeerate` gate, THEN calls `add_transaction`. The fee/vsize calculation
   here uses `tx.get_vsize()` (no sigop adjustment); `_add_transaction_inner`
   later recomputes with sigop-adjusted vsize. The `maxfeerate` gate runs
   against the NON-sigop-adjusted vsize, which means sigop-heavy txs get a
   different rate at the gate vs the real fee-rate at admission.

4. **`rpc_testmempoolaccept`** (`rpc.py:7905-7931`) — calls
   `validator.validate_transaction` directly, bypassing ALL mempool policy.
   Returns `allowed=true` for txs the real mempool would reject as non-standard,
   below min-fee, exceeding ancestor limits, etc. See BUG-20.

5. **`rpc_submitpackage`** (`rpc.py:7933-8019`) → `validate_package` (#6).

6. **`Mempool.validate_package`** (`mempool.py:4476-4777`) — used by
   submitpackage AND `on_pkgtxns` (p2p.py:3127-3129). Runs:
   - duplicate-by-**txid** (not wtxid — see BUG-10),
   - total weight,
   - in-package double-spend,
   - topological order,
   - child-with-parents topology,
   - per-tx fee accounting,
   - **package** min-relay-fee gate,
   - per-tx ephemeral-dust check,
   - TRUC package check,
   - `validator.validate_transaction` (consensus-only).

   Skips: `_is_standard_tx` (no version/weight/scriptsig/scriptpubkey-type),
   `_validate_inputs_standardness` (no P2SH-sigops, no Solver type check, no
   BIP-54 sigops), `_is_witness_standard` (no P2WSH/P2TR limits), per-tx
   sigop cost (`_compute_tx_sigop_cost`), per-tx rolling-min-fee, RBF gates,
   ancestor/descendant count + size limits, cluster limits. **Major bypass.**

7. **`on_pkgtxns`** (`p2p.py:3087-3138`) — handles BIP-331 inbound packages.
   Calls `validate_package(txs)` THEN ALSO calls `add_transaction(tx)` per-tx
   in the same handler (line 3129-3136). If `validate_package` succeeds it
   has already added the txs; the subsequent `add_transaction` then catches
   `txn-already-in-mempool` and treats it as failure ("debug" log), masking
   the success of the package. If `validate_package` fails it returns early
   without adding anything; the subsequent `add_transaction` loop then tries
   to admit each tx individually, but without RBF (no per-tx routing) — this
   could let through a tx that fails package gates but passes individual gates
   (or vice versa).

8. **`_make_tx_handler`** (`node.py:923-1001`) — inbound P2P `tx` message.
   Calls `add_transaction(tx, height)`. On ANY non-success-non-orphan
   reason, calls `peer_manager.misbehaving(addr, 10, ...)` (`node.py:993-995`).
   Does not distinguish policy reasons (non-standard, low fee, dust, sigops,
   ancestor saturation) from consensus reasons (invalid signature, duplicate
   inputs, MoneyRange). A peer relaying a non-standard transaction (legitimate
   policy-relay difference between Core and ouroboros) gets banned at the
   10th transaction. **Companion to BUG-12.**

9. **Reorg refill** (`rpc.py:6039-6063`) — after a submitblock-driven
   disconnect, calls `mempool.add_transaction(tx, final_height)` per
   disconnected non-coinbase tx. **No `bypass_limits=True` plumbing**, so
   txs that were mined into a block and are now below the rolling-min-fee
   or have saturated ancestor chains are dropped. See BUG-17.

The gate semantics differ across entries:
- `_is_standard_tx` runs in entries 1, 2; bypassed in entries 4, 6.
- `_validate_inputs_standardness` runs in entry 2; bypassed in entries 1
  test_accept, 4, 6.
- `_is_witness_standard` runs in entry 2; bypassed in entries 1 test_accept,
  4, 6.
- Sigop-cost gate runs in entry 2; bypassed in entries 1 test_accept, 4, 6.
- Min-relay fee runs in entry 2; bypassed in entries 4 (only package rate
  in 6 — which lets sub-min-fee individual txs through if package average is OK).
- RBF runs in entries 2; bypassed in entries 4, 6 (package rejects any
  conflict).
- TRUC runs in entries 2, 6; bypassed in entries 1 test_accept, 4.

**File:** `src/ouroboros/mempool.py:1874-1955, 4476-4777`;
`src/ouroboros/rpc.py:2382-2538, 7905-7931, 7933-8019, 6039-6063`;
`src/ouroboros/p2p.py:3087-3138`; `src/ouroboros/node.py:923-1001`.

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::AcceptSingleTransaction`
+ `AcceptPackage` + `ProcessNewPackage` (single dispatch).

**Impact:**
- Inbound `tx` and reorg-refill use the FULL gate set;
  `sendrawtransaction` uses the full gate set PLUS a duplicate
  maxfee check on a non-sigop-adjusted vsize.
- `testmempoolaccept` returns "allowed" for txs that the same node will
  immediately reject if actually sent (operator-confusing dry-run).
- `submitpackage` accepts packages whose individual txs would be rejected
  by `add_transaction` (skips standardness, witness-standardness,
  per-tx sigop cap, ancestor/descendant limits, cluster limits).
- `on_pkgtxns` double-runs (package + per-tx) yielding inconsistent
  success/fail/already-in-mempool sequences.

---

## BUG-2 (P1) — Bare-multisig "standard" pattern matches any 3+ byte script ending 0xae

**Severity:** P1 (mempool-policy correctness, no consensus impact).

Bitcoin Core's `Solver` (script/solver.cpp) decodes bare-multisig by
matching the strict pattern `OP_m  PUSH-PK_1 ... PUSH-PK_n  OP_n  OP_CHECKMULTISIG`
where `1 ≤ m ≤ n ≤ 3` (the n≤3 cap is enforced in `IsStandard`,
policy.cpp:87-95). Any deviation makes the script `NONSTANDARD` and the
output cannot be mined into a relayed transaction.

ouroboros's `_is_standard_output_type` falls back at line 867:

```python
# Bare multisig: OP_m ... OP_n OP_CHECKMULTISIG
# This is rare but standard. Check for OP_CHECKMULTISIG at end.
if len(script_pubkey) >= 3 and script_pubkey[-1] == 0xae:
    return True
```

This matches:
- `0x02 0x03 0xae` — `OP_2 OP_3 OP_CHECKMULTISIG` (no pubkeys at all,
  unspendable but matched).
- `0xff 0xff 0xae` — `OP_INVALIDOPCODE OP_INVALIDOPCODE OP_CHECKMULTISIG`.
- Any 1024-byte garbage where `[-1]==0xae`.
- 4-of-4 multisig (which Core rejects as n>3 NONSTANDARD).
- 17-of-17 multisig.

The output is treated as standard for mempool acceptance; the tx then
gets relayed but is unspendable. Wastes mempool slots and UTXO entries.

**File:** `src/ouroboros/mempool.py:865-868`.

**Core ref:** `bitcoin-core/src/script/solver.cpp::Solver()` (MULTISIG
branch) + `bitcoin-core/src/policy/policy.cpp:87-95` (IsStandard
n<=3 cap).

**Impact:** spam vector — arbitrary garbage scripts ending in 0xae get
into the mempool and relayed by ouroboros nodes. Cross-impl divergence
(Core rejects with `scriptpubkey` reason). Also enables relay of n>3
multisig that Core nodes won't relay or mine.

---

## BUG-3 (P1) — `-permitbaremultisig` operator knob absent

**Severity:** P1. Core defaults `DEFAULT_PERMIT_BAREMULTISIG{true}` and
exposes the `-permitbaremultisig=false` flag for operators that want to
refuse bare-multisig (Lightning-watchtower / OP-RETURN-only relay
configurations). Per `IsStandardTx`:

```cpp
} else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
    reason = "bare-multisig";
    return false;
}
```

ouroboros has no `-permitbaremultisig` flag (grep across `cli.py`,
`config.py`, `daemon.py`, `node.py` returns nothing). The
`require_standard` flag exists on `Mempool` but no CLI/config path sets it.
A node operator cannot disable bare-multisig relay.

**File:** `src/ouroboros/mempool.py:1108-1190` (no permit_bare_multisig
parameter); `cli.py`/`config.py` (no flag).

**Core ref:** `bitcoin-core/src/policy/policy.h:52` and
`bitcoin-core/src/init.cpp` `-permitbaremultisig`.

**Impact:** missing operator knob; cross-fleet parity gap. Combined
with BUG-2 the lack of a knob means even operators who want to refuse
non-standard multisig cannot.

---

## BUG-4 (P1) — `-datacarrier`/`-datacarriersize` operator knobs absent

**Severity:** P1. Core's `IsStandardTx` accepts an
`std::optional<unsigned> max_datacarrier_bytes` parameter. When
`-datacarrier=false`, this is `nullopt`, and any non-zero OP_RETURN output
fails with `reason="datacarrier"`. Default is `MAX_OP_RETURN_RELAY = 100_000`
bytes (configurable via `-datacarriersize`).

ouroboros hardcodes the cumulative limit at `MAX_OP_RETURN_RELAY = 100_000`
(`mempool.py:43`) and unconditionally accepts OP_RETURN outputs as
"standard" via `_is_standard_output_type` (`mempool.py:835-836`). There is no
operator knob to either disable datacarrier (`-datacarrier=false`) or to
shrink the cap (`-datacarriersize`).

**File:** `src/ouroboros/mempool.py:43, 835-836, 1163-1170`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp::IsStandardTx` lines
137-156 (datacarrier_bytes_left = max_datacarrier_bytes.value_or(0)).

**Impact:** operators cannot refuse datacarrier; cannot tighten the cap
below 100kB. Routinely requested operator-knob (controversial in the
broader debate over OP_RETURN limits).

---

## BUG-5 (P1) — `-datacarriersize` hardcoded (companion to BUG-4)

**Severity:** P1. The 100_000-byte cumulative cap is hardcoded.

**File:** `src/ouroboros/mempool.py:43, 1166`.

**Impact:** operator-knob parity gap.

---

## BUG-6 (P0-CDIV) — `GetDustThreshold` formula omits `GetSerializeSize(txout)` term

**Severity:** P0-CDIV. Bitcoin Core's `GetDustThreshold` formula
(`policy.cpp:27-64`) computes:

```cpp
uint64_t nSize{GetSerializeSize(txout)};  // 8 (value) + 1+ (script length varint) + scriptLen
if (witness_program) {
    nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);  // ~67
} else {
    nSize += (32 + 4 + 1 + 107 + 4);  // 148
}
return dustRelayFeeIn.GetFee(nSize);
```

i.e. it adds the **txout serialised size** to the **spend-side input cost**.
For a 22-byte P2WPKH (size 22), Core computes `(8+1+22)+67 = 98` bytes →
98×3 = 294 sat at default 3000 sat/kvB.

ouroboros (`mempool.py:873-895`) uses a **hardcoded** `n_size` table
(99/110/182/182) that bakes in approximate values for a fixed
`dustRelayFeeIn` schedule. The values don't include the txout's
serialised size, just the spend cost:

```python
if len(script_pubkey) == 22 and script_pubkey[0] == 0x00:
    n_size = 99  # P2WPKH
elif len(script_pubkey) == 34 and script_pubkey[0] in (0x00, 0x51):
    n_size = 110  # P2WSH or P2TR
elif len(script_pubkey) == 23 and script_pubkey[0] == 0xa9:
    n_size = 182  # P2SH
else:
    n_size = 182  # P2PKH and others
return (n_size * DUST_RELAY_TX_FEE) // 1000
```

Mismatches per output type:
- P2WPKH: ouroboros 99 vs Core 31+67=98 (off by 1, 297 vs 294 sat).
- P2WSH (34-byte): ouroboros 110 vs Core 43+67=110 (matches).
- P2TR (34-byte): same.
- P2SH (23-byte): ouroboros 182 vs Core 32+148=180 (off by 2, 546 vs 540 sat).
- P2PKH (25-byte): ouroboros 182 vs Core 34+148=182 (matches).
- Custom 36-byte scriptPubKey: ouroboros 182 (falls to else branch) vs
  Core 45+148=193 (off by 11, 546 vs 579 sat).

For default `DUST_RELAY_TX_FEE=3000` the divergence is 0-11% and most outputs
agree at the round-sat level. For operator-overridden `dustrelayfee` values
the divergence amplifies linearly. **Also** there is no `-dustrelayfee`
operator knob (DUST_RELAY_TX_FEE hardcoded at `mempool.py:48`), so the
divergence is bounded in practice — but cross-impl behavior diverges
silently for any tx within a few sat of either threshold.

**File:** `src/ouroboros/mempool.py:873-895`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:27-64`.

**Impact:** borderline outputs near the dust threshold are accepted
by ouroboros and rejected by Core (or vice versa). Specific to P2SH
(ouroboros says ≥546 sat OK, Core says ≥540 sat OK — divergence in
the 540-545 range) and to custom non-standard-length outputs.

---

## BUG-7 (P1) — `GetDustThreshold` witness-program detection is shape-gated, not opcode-gated

**Severity:** P1. ouroboros's dust threshold detects witness programs by
length+first-byte heuristic (`len==22 and [0]==0x00` for P2WPKH).
A non-witness 22-byte scriptPubKey that happens to start with 0x00 (e.g.
a malformed script with `OP_0` followed by 20 garbage bytes — totally legal
on the wire) is misclassified as P2WPKH and gets the 99-byte threshold
instead of the 182-byte non-witness threshold. The output is "more easily"
considered non-dust.

Core uses `txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)`
which decodes the opcode properly: leading byte must be `OP_0` or
`OP_1..OP_16` (not just byte value 0x00 or 0x51), followed by a single push
opcode (`OP_PUSHBYTES_N` with N=script.size()-2), and 2 ≤ program ≤ 40.

**File:** `src/ouroboros/mempool.py:887-895`.

**Core ref:** `bitcoin-core/src/script/script.cpp::CScript::IsWitnessProgram`.

**Impact:** rare in practice (most 22-byte 0x00-prefixed scripts are
genuine P2WPKH); but a crafted non-standard output that flips the wrong
side of dust threshold cross-impl is feasible.

---

## BUG-8 (P2) — `_get_dust_threshold` only short-circuits OP_RETURN, not all unspendable shapes

**Severity:** P2 (cosmetic, low-frequency).

Bitcoin Core's `GetDustThreshold` short-circuits any
`IsUnspendable()` script to threshold = 0:

```cpp
if (txout.scriptPubKey.IsUnspendable())
    return 0;
```

`IsUnspendable()` returns true for: empty script, scripts beginning with
`OP_RETURN`, AND any script > MAX_SCRIPT_SIZE (10kB) — guaranteed to fail
at execution.

ouroboros's `_has_ephemeral_dust` short-circuits only OP_RETURN
(`mempool.py:910`) and P2A (line 915) before calling `_get_dust_threshold`,
which then returns a non-zero threshold for other unspendable shapes
(scripts > 10kB; `OP_DUP OP_HASH160` only — incomplete; `OP_RETURN` with
non-push-only tail).

Most of these are also rejected by `_is_standard_output_type` so they
never get to the dust check anyway. The fallback path matters only for
`require_standard=False` nodes.

**File:** `src/ouroboros/mempool.py:898-920, 873-895`.

**Impact:** cosmetic only on `require_standard=True` nodes.

---

## BUG-9 (P1) — No `txn-already-known` reject; already-confirmed tx goes to orphan pool

**Severity:** P1 ("already-known semantics break" — companion to BUG-1).

Bitcoin Core's `PreChecks` at validation.cpp:858-866:

```cpp
// Are inputs missing because we already have the tx?
for (size_t out = 0; out < tx.vout.size(); out++) {
    if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
    }
}
// Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
```

The "tx already mined" case is distinguished from the orphan case by
checking whether ANY of the candidate tx's OUTPUTS are present in the
chainstate (i.e., this tx is already on-chain and its outputs are
spendable). The reject reason is `txn-already-known`; the tx is NOT
stored as an orphan.

ouroboros's `_add_transaction_inner` (`mempool.py:2021-2031`):

```python
missing_parents: set[bytes] = set()
for tx_in in tx.inputs:
    parent_txid = tx_in.prev_txid
    utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
    if utxo is None and parent_txid not in self.transactions:
        missing_parents.add(parent_txid)
if missing_parents:
    self.orphan_pool.add(tx, missing_parents)
    return False, "orphan"
```

No check of the tx's own outputs. A tx that was already mined (its
inputs have been spent, so `get_utxo` returns None) is misclassified
as an orphan and stored. The orphan pool fills with already-mined
transactions until ORPHAN_EXPIRY_SECONDS (1200s) flushes them.

**File:** `src/ouroboros/mempool.py:2021-2031`.

**Core ref:** `bitcoin-core/src/validation.cpp:858-866`.

**Impact:** orphan-pool exhaustion vector. A peer that re-relays
recently-mined transactions fills the 100-slot orphan pool quickly,
evicting legitimate orphans. Cross-impl reject-string divergence
(`orphan` vs `txn-already-known`).

---

## BUG-10 (P1) — `validate_package` duplicate detection uses txid not wtxid

**Severity:** P1 (BIP-339 conformance, fleet pattern — cross-cite W134
BIP-339 / W142 wtxid parity).

ouroboros's `_validate_package_inner` at `mempool.py:4515-4520`:

```python
seen_txids: set[bytes] = set()
for tx in txs:
    txid = tx.get_txid()
    if txid in seen_txids:
        return False, f"Duplicate transaction in package: {txid.hex()[:16]}..."
    seen_txids.add(txid)
```

Detects duplicates by **txid**, not wtxid. A package containing two
malleable variants of the same tx (same non-witness data, different
witness) trips the duplicate check on the second one — but Core's
duplicate detection is wtxid-keyed (mirrors `txn-already-in-mempool`
gate). A package legitimately containing two witness-different variants
(e.g. a CPFP child paying for one specific witness variant) gets rejected
spuriously.

Conversely, since txid is non-unique for malleable tx pairs, two
genuinely-different transactions that share a txid (rare but legal pre-
BIP-141) would not be flagged.

**File:** `src/ouroboros/mempool.py:4515-4520`.

**Core ref:** `bitcoin-core/src/validation.cpp::PackageMempoolChecks` +
`AcceptMultipleTransactions` uses wtxid-keyed dedup.

**Impact:** BIP-339 wire-format parity gap; package relay edge cases
diverge from Core.

---

## BUG-11 (P0-CDIV) — `CheckSigopsBIP54` per-input sigops limit absent

**Severity:** P0-CDIV (consensus-class — BIP-54 is a soft fork that
hashhog fleet has been adding; cross-cite W135 fleet pattern: 5 impls
lack BIP-54 sigops).

Bitcoin Core's `ValidateInputsStandardness` (`policy.cpp:214-263`) calls
`CheckSigopsBIP54` mandatorily:

```cpp
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) { return state; }
    if (!CheckSigopsBIP54(tx, mapInputs)) {
        state.Invalid(TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs",
                      "non-witness sigops exceed bip54 limit");
        return state;
    }
    ...
}
```

`CheckSigopsBIP54` (policy.cpp:170-194) sums per-input scriptSig sigops +
prev scriptPubKey sigops (accurate counting, includes P2SH sigops), gated
on `MAX_TX_LEGACY_SIGOPS=2500`.

ouroboros's `_validate_inputs_standardness` (`mempool.py:1016-1107`)
checks (1) prev-output type is standard, (2) WITNESS_UNKNOWN, (3) P2SH
redeem-script sigops ≤ MAX_P2SH_SIGOPS=15. **BIP-54 per-input
MAX_TX_LEGACY_SIGOPS=2500 check is entirely absent.** Grep confirms no
`MAX_TX_LEGACY_SIGOPS` / `CheckSigopsBIP54` / "bip54" references in the
ouroboros source tree.

`_compute_tx_sigop_cost` (mempool.py:968-1013) computes BIP-141-weighted
sigop COST (for the `MAX_STANDARD_TX_SIGOPS_COST=16000` gate), which is
a DIFFERENT limit — it's WITNESS_SCALE_FACTOR-weighted and ranges across
all input/output sigops, but does not enforce BIP-54's per-tx legacy
sigops cap.

Pre-BIP-54-activation this is purely policy. **Post-activation it is
consensus.** Currently BIP-54 is unactivated, so this is a P0-class
finding for the post-activation chain split risk, not an active bug.

**File:** `src/ouroboros/mempool.py:1016-1107`; absent elsewhere.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:170-194` (`CheckSigopsBIP54`),
`bitcoin-core/src/policy/policy.h:46` (`MAX_TX_LEGACY_SIGOPS{2500}`).

**Impact:** post-BIP-54 chain-split candidate. Fleet pattern (5+ impls
share this gap per W135). Even pre-activation, the policy gate would
reject some non-standard txs that Core rejects.

---

## BUG-12 (P0-CDIV) — No two-phase PolicyScriptChecks / ConsensusScriptChecks split

**Severity:** P0-CDIV (peer-banning behavior incorrect).

Bitcoin Core's `MemPoolAccept` runs scripts in **two separate phases**:

1. **`PolicyScriptChecks`** (validation.cpp ~1135-1156) — calls
   `CheckInputScripts` with `STANDARD_SCRIPT_VERIFY_FLAGS`. On failure,
   the result is `TX_NOT_STANDARD` or `TX_INPUTS_NOT_STANDARD` — the
   peer is **NOT** banned. This is what catches NULLFAIL, LOW_S,
   CLEANSTACK, MINIMALDATA, MINIMALIF, WITNESS_PUBKEYTYPE,
   CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE
   _TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS.

2. **`ConsensusScriptChecks`** (validation.cpp ~1162-1200) — calls
   `CheckInputScripts` with consensus-only flags (per-height
   MANDATORY_SCRIPT_VERIFY_FLAGS — P2SH/DERSIG/CLTV/CSV/WITNESS/NULLDUMMY/TAPROOT
   as buried). On failure, the result is `TX_CONSENSUS` — the peer IS
   misbehaving (sent us an invalid signature or violated a deployed
   soft-fork rule), and the peer IS banned.

ouroboros combines both into a single `validate_transaction` call
(`mempool.py:2123-2142`):

```python
extra_flags = 0
if self.require_standard:
    try:
        consensus = _consensus_flags(next_height, None, network)
        standard = _standard_flags(next_height, None, network)
        extra_flags = (standard & ~consensus)
    except Exception:
        extra_flags = 0
valid, error = self.validator.validate_transaction(
    tx, next_height, mempool_mtp, extra_script_flags=extra_flags,
)
```

The combined `flags = consensus | extra_flags` is passed to
`_verify_input_signature`. A failure can be:
- POLICY-only (NULLFAIL etc.) — peer is honest;
- CONSENSUS (signature invalid) — peer is dishonest.

ouroboros cannot distinguish. The error string returned is just "Invalid
signature for input N" with no further classification (validation.py:1988).

The P2P `tx` handler (`node.py:993-995`) sees the boolean failure and
calls:

```python
self.peer_manager.misbehaving(addr, 10, f"invalid tx: {error}")
```

So a peer relaying a transaction whose CLEANSTACK fails (policy reject,
Core would not ban) gets misbehaving=10 from ouroboros. After 10 such
relays = ban. Honest peers running on a Core-like relay policy get
banned.

**File:** `src/ouroboros/mempool.py:2113-2142`;
`src/ouroboros/validation.py:1874-1898`;
`src/ouroboros/node.py:987-995`.

**Core ref:** `bitcoin-core/src/validation.cpp::PolicyScriptChecks` +
`ConsensusScriptChecks`; `bitcoin-core/src/net_processing.cpp`
`TX_NOT_STANDARD` vs `TX_CONSENSUS` peer-state handling.

**Impact:**
- Honest peers running standard Core relay policy get banned at 10
  policy-divergent transactions. On a fresh ouroboros datadir
  reachable from public Core peers, this can blow up the addrman in
  hours.
- Cross-cite W128 fleet pattern (banman conflates ban+discouragement
  in 8/10 impls); BUG-12 is the per-tx analogue: PreChecks conflates
  policy+consensus reject classes.

---

## BUG-13 (P0-SEC) — STANDARD-flag derivation silently degrades on any exception

**Severity:** P0-SEC ("silent degradation" pattern).

`mempool.py:2123-2137`:

```python
extra_flags = 0
if self.require_standard:
    try:
        from ouroboros.script import (
            get_flags_for_height as _consensus_flags,
            get_standard_script_flags as _standard_flags,
        )
        consensus = _consensus_flags(next_height, None, self.validator.network if hasattr(...) else "mainnet")
        standard = _standard_flags(next_height, None, ...)
        extra_flags = (standard & ~consensus)
    except Exception:
        # Test doubles may not implement the script module; fall back
        # to consensus-only verification (current behavior).
        extra_flags = 0
```

The `except Exception:` catches:
- `ImportError` (missing module),
- `AttributeError` (validator without `network` field),
- `KeyError` / `IndexError` in `_SCRIPT_FLAG_EXCEPTIONS`,
- ANY exception from `get_flags_for_height` /
  `get_standard_script_flags` (database lookup failures, deployment
  state errors, etc.).

On any of these, `extra_flags = 0` and the tx is validated
**consensus-only**. Mempool admission gate becomes: "the tx must pass
consensus rules". NULLFAIL, LOW_S, CLEANSTACK, MINIMALDATA, MINIMALIF,
WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_NOPS, CONST_SCRIPTCODE,
DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS are all
silently disabled. **No log line.** The operator has no signal that
the policy gate degraded.

The triggering condition matters: in production, importing `ouroboros.script`
is normally safe. But a soak hit where the consensus module has a
bug in `is_deployment_active` (e.g. raises on an unknown deployment
name during a deployment flag-day) would silently widen ouroboros's
mempool acceptance to relay non-standard transactions for the duration
of the bug.

**File:** `src/ouroboros/mempool.py:2123-2137`.

**Core ref:** `bitcoin-core/src/validation.cpp::PolicyScriptChecks` —
no equivalent silent-degradation path; `STANDARD_SCRIPT_VERIFY_FLAGS`
is a hardcoded bitmask, not a runtime lookup.

**Impact:** silent loss of policy enforcement on lookup failure.
Cross-impl divergence under fault. Defense-in-depth gap. (Cross-cite
W144 "STANDARD flags incomplete" 5+ impls pattern.)

---

## BUG-14 (P2) — `next_height` script flag derivation uses `block_hash=None`

**Severity:** P2 (technically correct, doc gap).

`mempool.py:2130-2131`:

```python
consensus = _consensus_flags(next_height, None, network)
standard = _standard_flags(next_height, None, network)
```

`block_hash=None` skips the per-block-hash exception table in
`get_flags_for_height` (`script.py:159-160`). For NEXT-block mempool
acceptance this is correct — the next block's hash isn't known. However
the code has no comment marking this implicit invariant. A future
refactor that accidentally passes a stale tip-hash here would break BIP-16
exception handling (h~174,062 mainnet) and Taproot exception handling
(h=692,263).

**File:** `src/ouroboros/mempool.py:2130-2131`.

**Impact:** doc gap; defensive-coding flag.

---

## BUG-15 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE` is 1000 sat/kvB, Core is 100

**Severity:** P0-CDIV (relay-policy divergence; user-facing).

Bitcoin Core's `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
(`policy/policy.h:70`, lowered from 1000 in v28+ — see commits
`66559d1a4a` v28.3rc1 and `9dd7efc8c3` v29.1rc2 "lower default
minrelaytxfee and incrementalrelayfee to 100sat/kvB"). 100 sat/kvB =
0.1 sat/vB = 0.000001 BTC/kvB.

ouroboros's `DEFAULT_MIN_RELAY_TX_FEE = 1000` sat/kvB (`mempool.py:49`).
**10× higher than Core.** ouroboros rejects transactions at 0.1-0.9
sat/vB that current Core nodes accept and relay.

Compounding: `getmempoolinfo` (`rpc.py:2311, 2360, 2373`) and `rest.py`
(line 1258, 1259) hardcode the JSON values to `0.00001 BTC/kvB`
(= 1 sat/vB = 1000 sat/kvB) — operator monitoring scripts read these as
authoritative even though they're hardcoded duplicates of the same wrong
constant.

`DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB (`mempool.py:54`) IS
correct (matches Core), so the comment block at lines 50-54 even calls
out that Core uses 100 — but the adjacent `DEFAULT_MIN_RELAY_TX_FEE`
was not updated.

**File:** `src/ouroboros/mempool.py:49`;
`src/ouroboros/rpc.py:2311, 2360, 2373`;
`src/ouroboros/rest.py:1258, 1259`.

**Core ref:** `bitcoin-core/src/policy/policy.h:70`
(`DEFAULT_MIN_RELAY_TX_FEE{100}`).

**Impact:**
- 0.1-0.9 sat/vB transactions accepted on the Core network get
  rejected by ouroboros mempool. Wallet UX divergence — `bitcoin-cli
  estimatesmartfee 1000` on ouroboros vs Core returns different
  feerates after a long period of low-fee mempool.
- `getmempoolinfo.minrelaytxfee` reported as 0.00001 BTC/kvB
  regardless of actual gate.
- Carry-forward from v28 release (Q4 2024) — unfixed for ~6 months.

---

## BUG-16 (P1) — `-minrelaytxfee` CLI flag absent

**Severity:** P1. Core supports `-minrelaytxfee=<sat/kvB>`. ouroboros
hardcodes the value (see BUG-15).

**File:** absent across `cli.py`, `config.py`, `daemon.py`,
`node.py`.

**Core ref:** `bitcoin-core/src/init.cpp` `-minrelaytxfee`.

**Impact:** missing operator knob.

---

## BUG-17 (P0-CDIV) — Reorg refill calls `add_transaction` without `bypass_limits=True`

**Severity:** P0-CDIV (reorg correctness; mempool loss).

Bitcoin Core's reorg path (`Chainstate::DisconnectTip` →
`MaybeUpdateMempoolForReorg`) re-adds disconnected txs into the mempool
with `bypass_limits=true`. This skips:
- the min-relay-fee gate (`CheckFeeRate`),
- the rolling-min-fee gate,
- the ancestor count + size limits,
- the descendant limits,
- (does NOT skip standardness / signature / consensus).

The rationale: a tx that was previously mined into a block has already
been "approved" by the network; on disconnect it should re-enter the
mempool even if its fee is now below the post-disconnect rolling
minimum or its ancestor chain is over-saturated.

ouroboros's reorg refill (`rpc.py:6039-6063`):

```python
mempool = getattr(self.node, "mempool", None)
if mempool is not None and disconnected_txs:
    try:
        _, final_height = db.get_best_block()
    except Exception:
        final_height = -1
    refilled = 0
    for tx in disconnected_txs:
        try:
            success, reason = mempool.add_transaction(tx, final_height)
            if success:
                refilled += 1
            else:
                logger.debug(
                    "submitblock reorg: tx %s not re-added: %s",
                    tx.get_txid().hex()[:16], reason,
                )
```

No bypass. `add_transaction(tx, final_height)` runs the full gate
set including min-relay (BUG-15: 10× too high), ancestor count
(MAX_ANCESTOR_COUNT=25 — disconnected txs in long chains drop), the
ephemeral-dust check (a tx that paid a fee post-block-disconnect now
has dust outputs and a non-zero fee → reject), and TRUC inheritance
checks.

`add_transaction` is also wrapped under `Mempool._lock`, but it's a
reentrant lock so the loop pattern is OK.

The same gap applies to `block_sync.py::_handle_reorg` (referenced at
`rpc.py:6022` but not shown here) which also re-adds via the same gate
pattern.

**File:** `src/ouroboros/rpc.py:6039-6063` (submitblock reorg path);
`src/ouroboros/mempool.py:1874-1955` (no bypass parameter).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
calls `AcceptToMemoryPool(... /*bypass_limits=*/true)`.

**Impact:**
- After a reorg, transactions that were mined into the disconnected
  block(s) silently vanish from the mempool if their fee is below the
  current 1000 sat/kvB gate, or if they're in long chains, or have
  dust outputs.
- Operator can't tell why a chain reorg "lost" their fee-paying tx.
- Cross-impl divergence — Core re-admits, ouroboros drops.

---

## BUG-18 (P1) — `validate_package` bypasses per-tx policy via `_inner` path; no `m_package_feerates` flag plumbed

**Severity:** P1 (package-relay correctness).

`validate_package` (`mempool.py:4476-4777`) implements its own gate set
that overlaps with `_add_transaction_inner` but skips many checks:

| Gate | _add_transaction_inner | validate_package |
|------|------------------------|------------------|
| coinbase reject | YES | YES (via topology check) |
| BIP-339 wtxid dupe | YES (line 1995) | NO (txid dupe only — BUG-10) |
| txid dupe (already-in-mempool) | YES (line 1997) | YES (line 4516-4520) |
| orphan check | YES | NO (returns error if utxo missing) |
| IsStandardTx | YES (line 2007) | **NO** |
| ValidateInputsStandardness | YES (line 2054) | **NO** |
| IsWitnessStandard | YES (line 2062) | **NO** |
| MAX_STANDARD_TX_SIGOPS_COST | YES (line 2087) | **NO** |
| validate_transaction (consensus) | YES (line 2140) | YES (line 4681) |
| RBF (try_replace) | YES (line 2163) | NO (rejects any conflict) |
| TRUC single-tx | YES (line 2175) | NO |
| TRUC package | NO | YES (line 4632) |
| ancestor count + size limits | YES (line 2200) | **NO** |
| descendant count + size limits | YES (line 2212) | **NO** |
| cluster size limit | YES (line 2227) | **NO** |
| ephemeral-dust per-tx (with fee≠0 gate) | YES (line 2257) | YES (line 4617) |
| per-tx min-relay fee | YES (line 2273) | NO (package-rate only) |
| rolling-min-fee | YES (line 2284) | **NO** |
| prioritisetransaction (map_deltas) | YES via get_modified_fee | NO |

A package whose individual txs would each fail `IsStandardTx`,
`ValidateInputsStandardness`, sigop-cap, or ancestor limits — but
collectively pass package fee gate — is admitted via `validate_package`.
This is **not** Core's behavior: Core's `AcceptPackage` runs full
PreChecks per tx (just relaxes the per-tx fee gate via `m_package_feerates=true`).

**File:** `src/ouroboros/mempool.py:4476-4777`.

**Core ref:** `bitcoin-core/src/validation.cpp::AcceptPackage`
+ `AcceptMultipleTransactions` — each tx runs full PreChecks with
`m_package_feerates=true`.

**Impact:** package-relay can introduce non-standard / oversized /
ancestor-saturated txs into ouroboros's mempool that Core would reject.
Operators using `submitpackage` from a Core wallet may see different
acceptance results. Cross-impl mempool divergence.

---

## BUG-19 (P1) — `-bytespersigop` operator knob absent

**Severity:** P1. `DEFAULT_BYTES_PER_SIGOP=20` hardcoded in
`validation.py:506`. Core supports `-bytespersigop=<N>` to scale the
sigop-adjusted vsize gate used for relay fee.

**File:** `src/ouroboros/validation.py:506`.

**Core ref:** `bitcoin-core/src/policy/policy.h:50`
(`DEFAULT_BYTES_PER_SIGOP{20}`).

**Impact:** missing operator knob; fleet-pattern consistent.

---

## BUG-20 (P0-CDIV) — `testmempoolaccept` bypasses ALL mempool policy gates

**Severity:** P0-CDIV (RPC-shape divergence; deceptive dry-run).

ouroboros's `rpc_testmempoolaccept` (`rpc.py:7905-7931`):

```python
async def rpc_testmempoolaccept(
    self, rawtxs: list[str], maxfeerate: float = 0.10
) -> list[dict[str, Any]]:
    results = []
    for raw in rawtxs:
        try:
            from ouroboros.p2p_messages import TxMessage
            tx_msg = TxMessage.from_payload(bytes.fromhex(raw))
            tx = tx_msg.transaction
            _, best_height = self.node.db.get_best_block()
            valid, error = self.node.validator.validate_transaction(
                tx, best_height + 1)
            results.append({
                "txid": tx.get_txid()[::-1].hex(),
                "allowed": valid,
                "reject-reason": error if not valid else None,
            })
        except Exception as e:
            results.append({
                "txid": "",
                "allowed": False,
                "reject-reason": str(e),
            })
    return results
```

This calls `validator.validate_transaction` — the **consensus-only**
validator (with `extra_script_flags=0`, no STANDARD policy flags).
**It bypasses:**
- `_is_standard_tx` (version, weight, size, scriptsig, scriptpubkey, dust),
- coinbase reject (would crash on `validate_transaction` since coinbase
  txs have no UTXO),
- wtxid/txid duplicate detection,
- `_validate_inputs_standardness` (P2SH redeem-script sigops),
- `_is_witness_standard`,
- `_compute_tx_sigop_cost` + MAX_STANDARD_TX_SIGOPS_COST gate,
- per-tx min-relay fee,
- rolling-min-fee,
- TRUC checks,
- RBF gates,
- ancestor / descendant limits,
- cluster limits,
- ephemeral-dust check.

The `maxfeerate` parameter is **ignored** (declared but not consulted).

`allowed: true` is returned for transactions that would be REJECTED if
sent to `sendrawtransaction` (which routes through `add_transaction` /
`_add_transaction_inner`). The dry-run result systematically over-reports
acceptance.

Core's `testmempoolaccept` (`rpc/mempool.cpp::testmempoolaccept`) calls
`ProcessNewPackage(... /*test_accept=*/true)` which dispatches to
`AcceptSingleTransaction` / `AcceptPackage` with the test_accept flag —
i.e., **full PreChecks + PolicyScriptChecks + ConsensusScriptChecks
without actual admission**. The result fields `vsize` and `fees` are
populated.

**File:** `src/ouroboros/rpc.py:7905-7931`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::testmempoolaccept`.

**Impact:**
- Operator-facing JSON-RPC shape divergence: missing `vsize`, `fees`,
  `package-error`, `fees.effective-feerate`, `fees.effective-includes`,
  `effective-feerate` fields.
- Dry-run unreliable: ouroboros says "allowed: true" for a tx that
  `sendrawtransaction` would then reject. Wallet RPC consumers
  (e.g. Sparrow, BlueWallet) that use `testmempoolaccept` as a
  pre-flight check before broadcasting are misled.
- The `accept_to_memory_pool` path has a `test_accept=True` parameter
  (`mempool.py:1879`) that runs a partial gate set — `_is_standard_tx`
  + wtxid/txid dupe — but `testmempoolaccept` doesn't use it. Even
  using `accept_to_memory_pool(tx, height, test_accept=True)` would
  miss `_validate_inputs_standardness`, `_is_witness_standard`,
  sigop-cost, fee gates, etc.

---

## BUG-21 (P1) — `maxburnamount` parameter absent

**Severity:** P1 (RPC shape).

Bitcoin Core's `sendrawtransaction` and `submitpackage` accept
`maxburnamount` (default `DEFAULT_MAX_BURN_AMOUNT`) to reject
transactions whose UNSPENDABLE outputs exceed the threshold (protects
against accidental fund-burn via crafted scriptPubKeys).

ouroboros's `rpc_sendrawtransaction` signature:

```python
async def rpc_sendrawtransaction(
    self,
    hexstring: str,
    maxfeerate: float | None = None,
) -> str:
```

No `maxburnamount`. The same gap in `rpc_submitpackage`.

**File:** `src/ouroboros/rpc.py:2382-2538, 7933-8019`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:72, 1322`;
`bitcoin-core/src/common/messages.cpp:141`.

**Impact:** RPC shape parity; operator UX divergence.

---

## BUG-22 (P1) — `_map_mempool_error_to_reject_reason` uses fuzzy substring matching

**Severity:** P1 ("reject-string wire-parity slippage", fleet pattern —
cross-cite W125 fleet finding, W145 lunarblock 9-token sweep).

`rpc.py:2540-2596`:

```python
def _map_mempool_error_to_reject_reason(self, error: str) -> str:
    error_lower = error.lower()
    if "already in mempool" in error_lower:
        return "txn-already-in-mempool"
    if "orphan" in error_lower:
        return "missing-inputs"
    if "utxo not found" in error_lower:
        return "missing-inputs"
    if "conflict" in error_lower or "double" in error_lower:
        return "txn-mempool-conflict"
    if "fee" in error_lower and ("low" in error_lower or "minimum" in error_lower or "below" in error_lower):
        return "insufficient-fee"
    if "non-standard" in error_lower or "standardness" in error_lower:
        return "non-standard"
    if "script" in error_lower:
        return "script-failed"
    if "ancestor" in error_lower or "descendant" in error_lower:
        return "too-long-mempool-chain"
    if "size" in error_lower or "weight" in error_lower:
        return "tx-size"
    if "truc" in error_lower or "v3" in error_lower:
        return "truc-policy"
    if "dust" in error_lower:
        return "dust"
    if "negative" in error_lower:
        return "bad-txns-in-belowout"
    return error
```

Problems:
- `error = "bad-txns-too-many-sigops: sigop cost 17000 exceeds MAX_STANDARD_TX_SIGOPS_COST (16000)"`
  contains "size" (in "size") → maps to `"tx-size"`. WRONG (should
  be `"bad-txns-too-many-sigops"`).
- `error = "Output 0 has non-standard script type (scriptpubkey)"`
  contains "non-standard" → maps to `"non-standard"`. Actually
  matches Core's TX_NOT_STANDARD generic class — but the specific
  reason "scriptpubkey" is lost (Core emits the specific reason
  separately).
- `error = "Input 0 scriptSig size 1700 exceeds 1650 (scriptsig-size)"`
  contains "script" → maps to `"script-failed"`. WRONG (should be
  `"scriptsig-size"`). The "size" branch is checked LATER so the
  "script" branch wins.
- `error = "Transaction weight 401000 exceeds 400000"` contains "size"
  via "weight" → maps to `"tx-size"`. Matches Core but only by
  accident.
- `error = "ephemeral dust policy: tx with dust output must be 0-fee"`
  contains "dust" → maps to `"dust"`. Loses the "ephemeral" subtype.
- `error = "Below minimum relay fee: 50 < 1000"` contains "fee" +
  "below" + "minimum" → maps to `"insufficient-fee"`. OK.
- `error = "txn-already-in-mempool"` (already a Core string) goes
  through unmapped because there's no exact-match branch for it —
  the substring `"already in mempool"` matches (without the
  hyphens) → returns `"txn-already-in-mempool"`. OK accidentally.

The substring-matching pattern is fragile. Core's reject reasons are
**exact** wire strings (`bad-txns-vout-negative`, `bad-txns-fee-outofrange`,
`mempool min fee not met`, etc.). ouroboros's mapping reduces ~30
distinct Core reasons to ~12 substring buckets, with several wrong
assignments.

**File:** `src/ouroboros/rpc.py:2540-2596`.

**Core ref:** `bitcoin-core/src/common/messages.cpp::TransactionErrorString`.

**Impact:** RPC error wire-string parity slippage. Wallet error-handling
that string-matches the reject reason breaks differently on ouroboros vs
Core. Same fleet pattern as W125 / W145 lunarblock.

---

## BUG-23 (P0-SEC) — P2P `tx` handler bans peers for any add_transaction failure (10 points)

**Severity:** P0-SEC ("conflated punishment scoring" — pairs with BUG-12).

`src/ouroboros/node.py:987-995`:

```python
else:
    logger.debug(f"Rejected transaction: {error}")
    # Record misbehavior for invalid transactions
    # Invalid tx = 10 points (requires 10 violations to ban)
    if hasattr(self, "peer_manager") and self.peer_manager:
        addr = f"{sender_peer.host}:{sender_peer.port}"
        self.peer_manager.misbehaving(
            addr, 10, f"invalid tx: {error}"
        )
```

Failure cases this scores 10 points for:
- `"coinbase"` — peer relayed a coinbase loose-tx (suspicious — Core
  bans this with `TX_CONSENSUS`).
- `"orphan"` — **not malicious** (Core treats as missing parents, no
  ban).
- `"txn-already-in-mempool"` — racey re-relay, **not malicious**.
- `"txn-same-nonwitness-data-in-mempool"` — re-relay of malleated
  variant, mild — Core does NOT ban.
- `"Already in orphan pool"` — re-relay of known orphan, **not
  malicious**.
- `"Non-standard transaction: ..."` — peer relayed a tx that's
  non-standard by ouroboros policy but may be standard by Core
  policy (cross-cite BUG-15 min-relay 10× too high).
- `"bad-txns-too-many-sigops: ..."` — policy reject.
- `"BIP 68 sequence lock not satisfied"` — consensus, but only
  applies at NEXT-block height; tx may become valid in a future
  block.
- `"Below minimum relay fee: ..."` — policy.
- `"Insufficient fee: ... < rolling minimum ..."` — policy.
- `"Too many ancestors: 26 > 25"` — policy.
- `"Cluster limit ..."` — policy.
- `"TRUC ..."` — policy.
- `"version=3 ... cannot spend from non-version=3"` — TRUC policy.

A peer relaying any of these gets +10 each, banned at 100 (default
threshold). A typical Core peer running standard relay policy will
hit policy divergences regularly:

- BUG-15: 100 sat/kvB < 1000 sat/kvB cutoff → "Below minimum relay
  fee" for any tx in 0.1-0.9 sat/vB range.
- BUG-13: any txs relayed during the brief window when STANDARD
  flags degrade (silent).
- BUG-2: bare-multisig txs that look standard to ouroboros but
  Core wouldn't even forward.

Honest Core peers get banned in hours of normal traffic.

**File:** `src/ouroboros/node.py:987-995`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
"tx" branch differentiates `TX_NOT_STANDARD` (no ban),
`TX_MEMPOOL_POLICY` (no ban), `TX_CONFLICT` (no ban),
`TX_MISSING_INPUTS` (no ban — orphan), vs `TX_CONSENSUS` /
`TX_INPUTS_NOT_STANDARD` (ban via Misbehaving).

**Impact:**
- ouroboros bans honest Core peers within hours of normal mainnet
  traffic.
- Compounds with BUG-12 (no policy/consensus split) — even if
  ouroboros's reject classification were correct, the per-failure
  scoring would still over-punish.

---

## BUG-24 (P1) — OrphanPool has no per-tx size limit and no total-weight cap

**Severity:** P1 (DoS vector, partial mitigation via count limit).

ouroboros's `OrphanPool` has `MAX_ORPHAN_TRANSACTIONS = 100`
(`mempool.py:1450`) and `ORPHAN_EXPIRY_SECONDS = 20 * 60` (line 1451).

Bitcoin Core has additionally:
- `MAX_ORPHAN_TX_SIZE = 100KB` per-tx weight cap (
  `txorphanage.h` / `txorphanage.cpp`).
- `DEFAULT_MAX_ORPHAN_TOTAL_SIZE = 10MB` cumulative weight cap.
- Per-peer storage quotas (one peer cannot saturate the orphan pool
  alone).

ouroboros's `OrphanPool.add` (line 1474-1496) caps only by count.
A peer that relays 100 orphans of ~400KB each fills 40MB of RAM
pinned for 20 minutes per peer. The `_evict_random` policy doesn't
favor evicting bloat-from-one-peer.

Also: no DROP on `BLOCK_CONNECTED` (orphan promotion only on tx
arrival). Orphans whose parents arrive as part of a block do NOT
get re-processed.

**File:** `src/ouroboros/mempool.py:1450-1562`.

**Core ref:** `bitcoin-core/src/txorphanage.{h,cpp}` —
`MAX_ORPHAN_TX_SIZE`, `MAX_ORPHAN_TOTAL_SIZE`, per-peer accounting.

**Impact:** orphan-pool memory exhaustion vector (40MB per peer × N
peers); orphan re-evaluation gap on block connect.

---

## BUG-25 (P1) — `add_transaction` runs full gate set even during IBD

**Severity:** P1 (resource waste; fault tolerance).

Bitcoin Core does not normally accept transactions during IBD —
mempool is meaningless when the chainstate isn't synced. Specifically,
P2P `tx` messages during IBD are dropped early.

ouroboros's mempool exposes no IBD gate. `add_transaction` runs the
full pipeline (UTXO lookups, fee accounting, sigop counts, RBF logic)
regardless of sync state. The P2P `tx` handler (`node.py:923-1001`)
unconditionally calls `add_transaction(tx, height)` where `height` is
`db.get_best_block()` — the **current** db tip, which during IBD is
far behind network tip.

A tx whose inputs were spent in an unsync'd block will be misclassified
as orphan; a tx whose `nLockTime` is in the future relative to db tip
but valid for the network tip will be rejected as non-final.

The fallout is benign on a properly-syncing node — txs eventually
expire from orphan pool, peers resend, etc. — but it's wasted CPU and
storage, and the mempool can end up populated with stale orphans
during IBD that then need to be flushed.

**File:** `src/ouroboros/mempool.py:1874-1955`;
`src/ouroboros/node.py:923-1001` (no `if self.synced` gate before
`add_transaction`).

**Core ref:** `bitcoin-core/src/net_processing.cpp` — IBD short-circuit
on `tx` message ProcessMessage.

**Impact:** wasted IBD-time CPU + RAM; cross-cite W141 BUG-16
("is_synced hardcoded false since W113") — same architecture gap.

---

## BUG-26 (P1) — `cli.py:686` calls `Mempool()` with no `validator` arg → TypeError

**Severity:** P1 (CLI crash; tooling break).

`src/ouroboros/cli.py:686`:

```python
mempool = Mempool()
tx_count = len(mempool.get_all_transactions())
table.add_row("Mempool transactions", f"{tx_count}")
except Exception as e:
    ...
```

`Mempool.__init__` (`mempool.py:1568`) has `validator: TransactionValidator`
as the required first positional argument. `Mempool()` raises
`TypeError: __init__() missing 1 required positional argument: 'validator'`.

The surrounding `try: ... except Exception as e:` (the except at line
~689) catches it silently and adds an error row to the status table.
So `ouroboros status` shows "[red]Error: ...[/red]" for the Mempool
field every time.

This is wrong both ways: (1) the constructor SHOULD work without a
validator for a status-display use-case OR (2) the CLI should pass a
validator from the running daemon. Currently neither.

**File:** `src/ouroboros/cli.py:686`.

**Core ref:** N/A (operator UX).

**Impact:** `ouroboros status` cmd silently broken for mempool field
since this constructor signature was tightened. Cross-impl tooling
parity gap.

---

## BUG-27 (P0-SEC) — `OUROBOROS_BIP68_STOPGAP` env-var bypass live in PreChecks path

**Severity:** P0-SEC (intentional design but documented as "stopgap";
this is a re-anchor reminder per the W144 fleet-wide carry-forward
methodology).

`validation.py:2189` defines `_BIP68_STOPGAP_ENV = "OUROBOROS_BIP68_STOPGAP"`
and `_bip68_stopgap_enabled` (lines 2191-2201) reads on every call.
When set to truthy, `check_sequence_locks` skips BIP-68 enforcement for
inputs whose prevout was confirmed at or below the snapshot height
(`_is_pre_snapshot_prevout`).

This flag is consulted by `validate_transaction`'s BIP-68 gate (line
2004) — the same gate that PreChecks calls. So `add_transaction` /
`accept_to_memory_pool` will admit transactions that should be
BIP-68-rejected when the operator has set the env-var.

The acknowledged risk per the W132 fleet finding (cross-cite "ouroboros
live wedge papered over by OUROBOROS_BIP68_STOPGAP env-var") is that this
relaxation is consensus-divergent: an ouroboros node with this env-var
set will accept (into mempool AND into blocks) txs that Core rejects with
`non-BIP68-final`. Mining nodes producing such txs would mint blocks
that Core nodes reject. **The stopgap is intentional but unfixed since
W132**. Per the prior-quad pattern: "ouroboros 3 P0-CDIV consensus
splits" (W126 W127).

**File:** `src/ouroboros/validation.py:2183-2201, 2307-2370`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckSequenceLocksAtTip`
— no equivalent stopgap.

**Impact:** consensus relaxation under operator opt-in. Documented
as TODO replace with backwards-header-sync (Option 1) per W132 audit.
Re-anchored here because PreChecks calls this codepath.

---

## BUG-28 (P1) — `Mempool` constructor knobs not wired to CLI/config

**Severity:** P1 (operator-knob gap, fleet pattern).

`Mempool.__init__` accepts:
- `max_size: int = 300_000_000` — `-maxmempool` analogue.
- `require_standard: bool = True` — `-acceptnonstdtxn=false` analogue
  (Core's flag inverts: `-acceptnonstdtxn=true` makes ouroboros's
  `require_standard=false`).
- `full_rbf: bool = True` — `-mempoolfullrbf` analogue.

`node.py:228` constructs `self.mempool = Mempool(self.tx_validator)` —
all three defaults used. No CLI/config path threads through to override
any of these.

Operator cannot:
- shrink the mempool below 300MB (or grow it),
- disable standardness for testing (Core has `-acceptnonstdtxn=true`),
- disable full RBF (Core has `-mempoolfullrbf=false` since v28).

**File:** `src/ouroboros/node.py:228`; `src/ouroboros/mempool.py:1568-1648`.

**Core ref:** `bitcoin-core/src/init.cpp` `-maxmempool`,
`-acceptnonstdtxn`, `-mempoolfullrbf`.

**Impact:** parity gap for operator knobs; cross-fleet finding.

---

## Summary

**Bug count:** 28 (BUG-1 through BUG-28).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-1, BUG-6, BUG-11, BUG-12, BUG-15, BUG-17, BUG-20)
  — wait, BUG-23 is P0-SEC. Recount: P0-CDIV = BUG-1, BUG-6, BUG-11,
  BUG-12, BUG-15, BUG-17, BUG-20 = 7.
- **P0-SEC:** 3 (BUG-13, BUG-23, BUG-27)
- **P1:** 16 (BUG-2, BUG-3, BUG-4, BUG-5, BUG-7, BUG-9, BUG-10, BUG-16,
  BUG-18, BUG-19, BUG-21, BUG-22, BUG-24, BUG-25, BUG-26, BUG-28)
- **P2:** 2 (BUG-8, BUG-14)

Total: 7+3+16+2 = 28. ✓

**Fleet patterns confirmed:**
- **"N-pipeline drift" 6th distinct ouroboros instance** (BUG-1) —
  SIX coexisting ATMP entry points each running a different subset of
  the gates. ouroboros now holds both the W149 6-pipeline-validate
  record AND a 6-pipeline ATMP record.
- **"Carry-forward re-anchor"** (BUG-15 v28 minrelaytxfee unchanged for
  6 months; BUG-27 OUROBOROS_BIP68_STOPGAP unfixed since W132).
- **"Silent degradation"** (BUG-13) — broad `except Exception:` silently
  drops STANDARD flags; no log line.
- **"Substring-matching wire-string parity slippage"** (BUG-22) — same
  shape as W125 / W145 lunarblock.
- **"Operator-knob absent"** (BUG-3 permitbaremultisig, BUG-4
  datacarrier, BUG-5 datacarriersize, BUG-16 minrelaytxfee, BUG-19
  bytespersigop, BUG-21 maxburnamount, BUG-28 mempool knobs) — 7 instances
  in one wave, fleet-pattern density record.
- **"Two-pipeline-guard 17th distinct extension"** (BUG-15) — the
  static gate value and the dynamic JSON output BOTH need updating;
  they're at different sites and drifted independently.
- **"Wiring-look-but-no-wire"** (BUG-1, BUG-28) — `Mempool` constructor
  exposes knobs that no CLI/config path sets.
- **"Conflated punishment scoring"** (BUG-23) — same shape as W128
  banman conflation fleet pattern (8/10 impls).
- **"Test-double-driven gate degradation"** (BUG-13 comment-as-confession
  "Test doubles may not implement the script module; fall back to
  consensus-only verification" — 6th comment-as-confession instance in
  ouroboros audit history).
- **"BIP-54 sigops absent"** (BUG-11) — 5+ impls fleet pattern (cross-cite
  W135).
- **"hot-RPC bypass-all-policy"** (BUG-20) — `testmempoolaccept` skips
  every policy gate; new shape.

**P0-CONS-class candidates** (consensus-class, not just policy):
- BUG-11 (CheckSigopsBIP54 absent → post-activation chain split).
- BUG-12 (PolicyScriptChecks/ConsensusScriptChecks split absent → peer-banning policy).
- BUG-15 (DEFAULT_MIN_RELAY_TX_FEE 10× too high → relay-policy fragmentation).
- BUG-17 (no bypass_limits in reorg refill → mempool tx-loss on reorg).
- BUG-20 (testmempoolaccept bypass-all-policy → operator UX + DoS for sendrawtransaction).
- BUG-27 (OUROBOROS_BIP68_STOPGAP — already documented P0-CONS in W132).

**Top three findings:**

1. **BUG-1 (P0-CDIV, six-pipeline ATMP drift)** —
   `accept_to_memory_pool` / `add_transaction` /
   `rpc_sendrawtransaction` / `rpc_testmempoolaccept` /
   `rpc_submitpackage` → `validate_package` / `on_pkgtxns` /
   `_make_tx_handler` / reorg refill are SIX distinct entries each
   running a different subset of mempool gates. The same transaction
   gets different acceptance verdicts depending on entry point. The
   "N-pipeline drift" record holder extends from W149's six-pipeline
   validate/connect into mempool acceptance — ouroboros holds both
   records.

2. **BUG-12 + BUG-13 + BUG-23 cluster (P0-CDIV / P0-SEC, peer-banning
   misbehavior + silent policy degradation)** — there's no two-phase
   PolicyScriptChecks vs ConsensusScriptChecks split (single combined
   `validate_transaction` call), the STANDARD-flag derivation silently
   degrades on any exception with no log line, AND the P2P `tx`
   handler unconditionally bans peers at 10 points per failure. The
   combination: an ouroboros node bans honest Core peers within hours
   of normal mainnet traffic — any tx that's standard-by-Core but
   non-standard-by-ouroboros (e.g. 0.5 sat/vB due to BUG-15) hits +10
   misbehavior. After 10 such relays = ban. The addrman erodes within
   a day of normal operation.

3. **BUG-15 + BUG-16 + BUG-17 (P0-CDIV cluster, fee policy drift +
   reorg loss)** — `DEFAULT_MIN_RELAY_TX_FEE = 1000` sat/kvB (10× higher
   than Core's v28+ value of 100), with no `-minrelaytxfee` operator
   knob, AND reorg refill calls `add_transaction` without
   `bypass_limits=True`. After a chain reorg the disconnected
   transactions (which were mined into a block, so the network accepted
   them at their fee rate) are re-evaluated against the 1000 sat/kvB
   gate and silently dropped. Operators see mempool tx-loss on reorgs
   with no diagnostic.

**Cross-cite priorities** (where this audit re-confirms prior fleet
findings):
- W128 banman fleet pattern (8/10 impls) — BUG-23 is the per-tx
  analogue.
- W132 OUROBOROS_BIP68_STOPGAP — re-anchored BUG-27.
- W135 BIP-54 sigops absent (5+ impls) — BUG-11.
- W125 / W145 reject-string wire-parity slippage — BUG-22.
- W141 BUG-16 (is_synced hardcoded false since W113) — BUG-25 same
  architecture gap.
- W144 STANDARD flags incomplete (5+ impls) — BUG-13 silent degradation.
- W149 6-pipeline validate/connect drift — BUG-1 6-pipeline ATMP
  drift (sibling record).
