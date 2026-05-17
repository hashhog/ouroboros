W123 — Mining / getblocktemplate parity audit (ouroboros)
=========================================================

Date: 2026-05-17
Impl: ouroboros (Python pipeline; Rust pipeline mining-free)
Target:
  - `src/ouroboros/rpc.py::rpc_getblocktemplate` (4841-5332)
  - `src/ouroboros/rpc.py::rpc_submitblock` (6067-6171)
  - `src/ouroboros/rpc.py::rpc_submitblockbatch` (6173-6232)
  - `src/ouroboros/rpc.py::rpc_getmininginfo` (4798-4839)
  - `src/ouroboros/rpc.py::rpc_prioritisetransaction` (8654-8703)
  - `src/ouroboros/rpc.py::rpc_getprioritisedtransactions` (8705-8726)
  - `src/ouroboros/rpc.py::rpc_generatetoaddress` (8728-8949)
  - `src/ouroboros/rpc.py::rpc_getnetworkhashps` (8600-8652)
  - `src/ouroboros/rpc.py::accept_block` (288-414)
Reference:
  - `bitcoin-core/src/node/miner.cpp`
  - `bitcoin-core/src/rpc/mining.cpp`
  - `bitcoin-core/src/node/miner.h`
  - `bitcoin-core/src/policy/policy.h`
  - BIP-22 / BIP-23 / BIP-141 / BIP-152 / BIP-325 / BIP-94
Tests: `src/ouroboros/tests/test_w123_mining_gbt.py` (31 cases / 30 gates)

Status: **27 BUGS / 30 gates**
  - PRESENT (Core parity, no work needed): **3**  — G26 two-pipeline guard,
    plus G7 and G14 partial overlap with prior FIX-72 / dead-helper deferrals
  - PARTIAL (some plumbing, missing edge cases): **0**
  - MISSING (full gap vs Core): **27**

  - **P0-CDIV** (consensus / interop critical): **5**
  - **P1-RPC** (RPC surface gaps that break standard mining setups): **12**
  - **P2-POLICY** (policy knobs / telemetry / DX): **10**

Trigger: FIX-72 wired prioritisetransaction → modified-fee throughout
mempool + GBT ancestor sort. Confirmed COMPLETE — `map_deltas` is consulted
in `rpc.py:5004` and `rpc.py:9173`, `_check_cluster_rbf` honours modified
fees, and FIX-76 persists deltas across restart. Gate G11 of W108 is now
PRESENT. This wave hunts the *remaining* mining/GBT gaps W108 did not
exercise — specifically argument-driven knobs, BIP-23/152/325 plumbing,
template caching, ZMQ hooks, and missing RPCs (generateblock,
generatetodescriptor, submitheader).

W123 deliberately uses gate names G1..G30 that are DISJOINT from W108's
gate scheme; the two audits target different concerns. Where the new
gate touches a W108-adjacent concern (e.g. G4 narrows in on
TestBlockValidity inside mode=proposal, G10 narrows on signet wiring,
G24 narrows on coinbasetxn data field), the linkage is called out in
the test comments and below.

Top findings
------------

| Sev | ID | Title | Evidence |
|-----|----|-------|----------|
| **P0-CDIV** | G4  | mode='proposal' never runs TestBlockValidity — accepted-by-default | `rpc_getblocktemplate` ignores `template_request` entirely; `mode='proposal'` falls through to the full template return path; no `validator.validate_block` call observed in test. |
| **P0-CDIV** | G16 | submitblock cannot emit `duplicate-invalid` — known-bad blocks reported as duplicate-inconclusive (or rejected via prev-blk-not-found if pruned) | `rpc_submitblock` source has no `"duplicate-invalid"` string; no invalid-block index lookup. |
| **P0-CDIV** | G17 | submitblock/accept_block does NOT call `zmq_publisher.notify_block` — RPC-submitted blocks skip ZMQ; P2P-arrived blocks notify | `accept_block` (rpc.py:288-414) has no `zmq` reference; only `block_sync.py:1381` calls `notify_block`. |
| **P0-CDIV** | G18 | Side-branch buffer is in-memory only — fork accumulation lost on restart | `RPCServer._side_branch_blocks` is a plain dict; no load/save method. |
| **P0-CDIV** | G19 | Cluster-mempool block-builder chunk API absent — block builder uses greedy ancestor-fee-rate sort, NOT Core's `GetBlockBuilderChunk` / `IncludeBuilderChunk` / `SkipBuilderChunk` cluster cuts | `Mempool` has none of those methods (verified `dir(Mempool)`). |
| **P1-RPC** | G1  | `coinbase_output_script` not a configurable BlockAssembler option | GBT response has no coinbase scriptPubKey field; no Options struct exists. |
| **P1-RPC** | G3  | No template caching / pindexPrev pin — every GBT call rebuilds | `RPCServer` has no `_gbt_template_cache` / `_gbt_pindex_prev`. |
| **P1-RPC** | G5  | Mempool has no `GetTransactionsUpdated` counter — blocks long-poll wiring | No `transactions_updated` attribute on `Mempool`. |
| **P1-RPC** | G6  | `-blockmaxweight` arg not consulted — `WEIGHT_BUDGET` hardcoded | `rpc_getblocktemplate` source has no `blockmaxweight`. |
| **P1-RPC** | G7  | `-blockmintxfee` chunk-fee-floor gate absent in addChunks loop (W108 G14 noted the value being hardcoded; W123 narrows to the FLOOR-GATE) | No `blockMinFeeRate` / `min_fee_rate` floor check in GBT loop. |
| **P1-RPC** | G8  | `-blockreservedweight` arg not consulted — `BLOCK_RESERVED_WEIGHT = 8000` hardcoded | No `blockreservedweight` in source. |
| **P1-RPC** | G13 | `CooldownIfHeadersAhead` not implemented — GBT proceeds with stale tip when headers are ahead | No `CooldownIfHeadersAhead` / `BlocksAheadOfTip` references. |
| **P1-RPC** | G14 | `waitTipChanged` primitive missing on `BitcoinNode` — long-poll cannot be built | Confirmed via `dir(BitcoinNode)`. |
| **P1-RPC** | G15 | `submitblock` signature is `(self, hexdata)` — does not accept the BIP-22 dummy 2nd arg | Some pool stacks pass `workid` in dummy and rely on it being silently ignored. |
| **P1-RPC** | G21 | `generateblock` RPC not implemented | No `rpc_generateblock` method on `RPCServer`. |
| **P1-RPC** | G22 | `generatetodescriptor` RPC not implemented | No `rpc_generatetodescriptor` method. |
| **P1-RPC** | G23 | `submitheader` RPC not implemented | No `rpc_submitheader` method. |
| **P1-RPC** | G24 | GBT `coinbasetxn` lacks `data` field (serialized coinbase hex) — Core BIP-22 includes it | Per W108 G7 / re-asserted here. |
| **P2-POLICY** | G2  | No `include_dummy_extranonce` policy — coinbase scriptSig at small heights only ≥ 2 bytes by accident, no `OP_0` extranonce pad | `rpc_generatetoaddress` does not append `OP_0`. |
| **P2-POLICY** | G9  | `-printpriority` debug logging knob missing | No `print_modified_fee` / `printpriority` strings anywhere. |
| **P2-POLICY** | G10 | Signet (BIP-325) block-signing not wired into mining helpers | `rpc_generatetoaddress` source is signet-unaware; no `SignetSolution`. |
| **P2-POLICY** | G11 | BIP-94 `MAX_TIMEWARP` mintime arm at retarget boundary not implemented | No `MAX_TIMEWARP` reference in GBT. |
| **P2-POLICY** | G12 | `UpdateTime` does not recompute `nBits` on `fPowAllowMinDifficultyBlocks` | GBT computes bits once and never recomputes. |
| **P2-POLICY** | G20 | After GBT call, no `last_block_weight` / `last_block_num_txs` cached for later `getmininginfo` (W108 G15 noted the field absence; W123 narrows in on the STORAGE-after-GBT path) | No `_last_block_*` attribute appears on `RPCServer` after a GBT call. |
| **P2-POLICY** | G25 | GBT `total_sigops` starts at 0 — no coinbase sigops reserve (`coinbase_output_max_additional_sigops`) | Verified: `total_sigops = 0` in source. |
| **P2-POLICY** | G27 | GBT `mutable[]` carries only `["time", "transactions", "prevblock"]` — no BIP-23 `version/force` or `submit/coinbase` capability advertised | Verified set equality. |
| **P2-POLICY** | G28 | `default_witness_commitment` emitted unconditionally — pre-SegWit miners see an unusable hex | No `fPreSegWit` branch around the emit. |
| **P2-POLICY** | G29 | `BitcoinNode` has no `signet_challenge` attribute; `rpc.py` never reads it (W108 G13 noted the field absence; W123 narrows to the WIRING) | Confirmed via `dir(BitcoinNode)` and source grep. |
| **P2-POLICY** | G30 | No `longpollid` format code — even the `tip+counter` string is not constructible | `nTransactionsUpdated` not referenced. |
| **PRESERVE** | G26 | Two-pipeline guard: `ferrous-utils/` Rust crate has no mining surface | Verified — no `getblocktemplate` / `BlockAssembler` / `BlockTemplate` / `addChunks` / `GetBlockBuilderChunk` / `prioritise_transaction` strings in any `*.rs` file outside `target/`. INVARIANT to preserve. |

FIX-72 completeness check (positive finding)
--------------------------------------------

W108 G11 flagged that `prioritisetransaction` was a stub.  FIX-72
(commit `c46158b`) wired:

1. `Mempool.map_deltas: dict[bytes, int]` (mempool.py:1647)
2. `Mempool.prioritise_transaction(txid, delta)` (mempool.py:1770)
3. `Mempool.get_modified_fee(...)` / `get_modified_fee_rate(...)` (mempool.py:1805+)
4. `Mempool.clear_prioritisation(txid)` (mempool.py:1840)
5. `Mempool.get_prioritised_transactions()` (mempool.py:1851)
6. RPC `prioritisetransaction` (rpc.py:8654)
7. RPC `getprioritisedtransactions` (rpc.py:8705)
8. GBT ancestor-fee-rate sort uses `_mod_fee(t, e) = entry.fee +
   map_deltas[t]` for both the entry and every ancestor (rpc.py:5004-5028)
9. Mempool RBF Rule 3/4 admission honours deltas (verified in
   `test_w120_fix72_priority.py` 33 tests).
10. FIX-76 persists `map_deltas` across `dump_to_file` / `load_from_file`
    (mempool.py:4031-4267).

All 33 FIX-72 tests pass; W108 G11 is now PRESENT.  W123 finds no
follow-up gap in the priority pipeline itself.

P0-CDIV bug detail
------------------

### G4 — mode='proposal' bypasses TestBlockValidity

```python
async def rpc_getblocktemplate(self, template_request: dict = None):
    # template_request is never read; no `mode` dispatch.
    ...
```

Core (mining.cpp:730-751):

```cpp
if (strMode == "proposal") {
    const UniValue& dataval = oparam.find_value("data");
    // ... decode block ...
    return BIP22ValidationResult(
        TestBlockValidity(chainman.ActiveChainstate(), block,
                          /*check_pow=*/false, /*check_merkle_root=*/true));
}
```

Impact: an external mining proxy that proposes a block via GBT
mode=proposal expects a result string (`""` for valid, error reason
for invalid). Ouroboros returns a brand-new template, which the
proxy will interpret as silent acceptance — a CDIV vector if a
poorly-formed block is treated as accepted upstream.

### G16 — submitblock has no `duplicate-invalid` path

```python
if hasattr(db, "has_block_hash") and db.has_block_hash(block_hash):
    return "duplicate"
if block_hash in self._side_branch_blocks:
    return "duplicate-inconclusive"
```

Core (mining.cpp:742-748):

```cpp
const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
if (pindex) {
    if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
        return "duplicate";
    if (pindex->nStatus & BLOCK_FAILED_VALID)
        return "duplicate-invalid";
    return "duplicate-inconclusive";
}
```

Impact: known-invalid blocks resubmitted via RPC look identical to
`duplicate-inconclusive` in ouroboros responses. A mining proxy
cannot distinguish "this block is known-bad, give up" from "still
inconclusive, keep retrying."

### G17 — accept_block path skips ZMQ notify

`rpc.py::accept_block` (the unified ProcessNewBlock helper used by
`rpc_submitblock` + `rpc_submitblockbatch` + `rpc_generatetoaddress`)
does not call `zmq_publisher.notify_block`.

Only `block_sync.py:1381` (P2P arrival) notifies ZMQ.  So:

- A miner submitting via RPC → block accepted → ZMQ subscribers see
  nothing.
- The same block arriving over P2P from another peer → ZMQ
  subscribers see it.

This is the canonical "P2P arrival fires hashblock, RPC arrival
doesn't" disparity that breaks every fee-watcher / fork-monitor /
indexer downstream subscribing via ZMQ.

### G18 — Side-branch buffer is in-memory only

`RPCServer._side_branch_blocks: dict[bytes, tuple]` is initialised in
`__init__`. There is no `_load_side_branch_buffer` / `_save_side_branch_buffer`
method. A node restart discards every accumulated fork; if a competing
chain becomes heavier *across* a restart, ouroboros must re-receive
those blocks via P2P to reorg. Comment in `rpc.py:5496` explicitly notes
"BLOCK_INDEX_CF is height-keyed (a relic of the IBD-only single-best-chain
era)" — a known limitation that W123 promotes to a P0-CDIV gate.

### G19 — Cluster-mempool block-builder chunk API absent

Bitcoin Core's post-cluster-mempool block builder uses
`GetBlockBuilderChunk` / `IncludeBuilderChunk` / `SkipBuilderChunk`
which return DAG-aware chunks rather than individual entries.
Ouroboros uses `snapshot()` + greedy ancestor-fee-rate sort, which
is correct for simple non-DAG mempools but does NOT replicate Core's
chunked admission semantics on dense CPFP topologies.

For practical mining this is rarely catastrophic but it IS a
divergence from the Core API and complicates IPC-level
template-equivalence comparisons.

Patterns observed (cross-wave)
------------------------------

1. **Configurable-options pattern absent.** W123 G1/G6/G7/G8/G9 all
   trace to the same root: ouroboros has no `BlockAssembler::Options`
   struct.  Every knob is a module-level constant.  This is the
   "hardcoded constants where Core has CLI knobs" pattern observed in
   prior waves (W108 G14 blockmintxfee, W107 reject-thresholds).

2. **Dead-helper persists at GBT site.** `rpc.py:5223` uses
   `getattr(self.node, "get_next_bits", None)` and
   `rpc.py:5246` uses `getattr(self.node, "get_next_block_version", None)`,
   but neither method exists on `BitcoinNode`. Verified — W108 G10
   confirmed the same. The dead-helper-at-call-site pattern from W117
   recurs at the mining surface.

3. **ZMQ / notification dispersion.** ouroboros emits ZMQ notifications
   only from the P2P arrival path. The unified `accept_block` helper
   added precisely so every entry point would share validation also
   needed to share notify, but didn't. Cross-wave pattern: "unified
   helper added for one concern (validation) misses an adjacent concern
   (notification)".

4. **Side-branch buffer hack.** The in-memory fork buffer in `rpc.py`
   was introduced to close Pattern X/Y but is structurally a shim
   around the deeper "height-keyed BLOCK_INDEX_CF" data-model gap.
   Restart-persistence is the obvious next gate that closes the
   shim into a real fix.

5. **Mining surface gap pattern continues.** generateblock,
   generatetodescriptor, submitheader — three Core mining RPCs that
   were added in 2020-2023, none of which ouroboros implements.
   Mirrors the "BIP-N feature added in Core 2-3 years ago, fleet
   impls trailing" pattern visible at W117, W118, W119.

Recommended fix order
---------------------

If a follow-up FIX wave lands W123 gates, propose this priority:

1. **G17 ZMQ notify in accept_block** — single function edit; instantly
   unbreaks every RPC-submission downstream.
2. **G24 coinbasetxn data field** — straightforward, miner-visible.
3. **G15 submitblock dummy arg** — trivial signature change.
4. **G29 + G10 signet wiring** — combine; requires Node config
   plumbing but unblocks signet mining.
5. **G21 / G22 / G23 missing RPCs** — additive, no risk to existing
   paths.
6. **G16 duplicate-invalid path** — requires invalid-block tracking
   (currently only via reject-cache in validator).
7. **G19 cluster-mempool chunk API** — large refactor; punt unless
   downstream IPC interop is demanded.
8. **G18 side-branch persistence** — requires schema change to
   BLOCK_INDEX_CF; biggest blast radius.
9. **G3 template cache + G5 GetTransactionsUpdated + G14 wait_tip_changed
   + G30 longpollid format** — bundle into one "long-poll wiring" wave;
   useful but not pressing.
10. **G2 + G4 + G6 + G7 + G8 + G9 + G11 + G12 + G13 + G20 + G25 + G27 +
    G28** — single "Options struct + arg plumbing" wave.

Two-pipeline guard (PRESERVE)
-----------------------------

```bash
$ grep -rn "getblocktemplate\|BlockAssembler\|BlockTemplate\|addChunks\|GetBlockBuilderChunk\|prioritise_transaction" ferrous-utils/
(no matches outside target/)
```

Rust pipeline remains mining-free. Gate G26 asserts this and MUST
remain green across any future W123 fix wave — mining lives in Python
only.
