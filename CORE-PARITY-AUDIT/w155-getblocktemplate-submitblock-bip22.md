# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (ouroboros)

**Wave:** W155 — `getblocktemplate` RPC (BIP-22 / BIP-23 / BIP-9 / BIP-145
mode dispatch, template_request parsing, capabilities, rules, vbavailable,
vbrequired, longpollid, mintime, sigoplimit, sizelimit, weightlimit,
target, coinbaseaux, coinbasevalue, coinbasetxn, default_witness_commitment,
per-tx data/txid/hash/depends/fee/sigops/weight), `submitblock` RPC
(BIP-22 hexdata+dummy, UpdateUncommittedBlockStructures, ProcessNewBlock
with StateCatcher, BIP22ValidationResult string mapping, duplicate /
duplicate-invalid / duplicate-inconclusive triage), `submitheader` RPC,
`getmininginfo`, `prioritisetransaction`, `getprioritisedtransactions`,
`generateblock`, `generatetodescriptor`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1034` — `getblocktemplate`:
  template/proposal mode dispatch, longpoll using
  `tip + nTransactionsUpdatedLast`, peer-count + IBD guards, segwit/signet
  client-rule enforcement, `pindexPrev`/`block_template`/`time_start`
  static cache, `UpdateTime` recompute, fPreSegWit sigoplimit/sizelimit
  division by WITNESS_SCALE_FACTOR, `default_witness_commitment` ONLY
  when `coinbase.required_outputs.size() > 0`, `signet_challenge` ONLY
  when `consensusParams.signet_blocks`.
- `bitcoin-core/src/rpc/mining.cpp:587-602` — `BIP22ValidationResult(state)`
  returning `UniValue::VNULL` for accept, `state.GetRejectReason()`
  (which is the Core consensus reject token, NOT a free-form English
  message) for invalid, throwing `RPC_VERIFY_ERROR` for error.
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`: 2-argument
  signature (hexdata + dummy/ignored), pre-Process
  `UpdateUncommittedBlockStructures`, `submitblock_StateCatcher` via
  `RegisterSharedValidationInterface`, single-call `ProcessNewBlock`
  (no side-branch buffer; chain selection is internal to ActivateBestChain),
  `if (!new_block && accepted) return "duplicate"`, `if (!sc->found)
  return "inconclusive"`, otherwise `BIP22ValidationResult(sc->state)`.
- `bitcoin-core/src/rpc/mining.cpp:730-752` — `mode=="proposal"`:
  `DecodeHexBlk`, lookup block-index for `duplicate`/`duplicate-invalid`/
  `duplicate-inconclusive`, otherwise `BIP22ValidationResult(TestBlockValidity(...))`.
- `bitcoin-core/src/rpc/mining.cpp:850-852, 854-857` —
  `getblocktemplate must be called with the segwit rule set` /
  `... signet rule set` invariants (RPC_INVALID_PARAMETER).
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`: header-only
  fast path, requires parent already known.
- `bitcoin-core/src/node/miner.cpp:36-79, 140, 196, 220, 267, 284-316` —
  CreateNewBlock: `GetMinimumTime` (BIP-94 timewarp arm), `UpdateTime`
  (with `fPowAllowMinDifficultyBlocks` bits recompute), `ComputeBlockVersion`,
  `GetNextWorkRequired`, coinbase nLockTime = nHeight-1,
  `MAX_CONSECUTIVE_FAILURES`, `BLOCK_FULL_ENOUGH_WEIGHT_DELTA`.
- `bitcoin-core/src/policy/policy.h:27` — `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`.
- `bitcoin-core/src/consensus/consensus.h:13,15,17` —
  `MAX_BLOCK_SERIALIZED_SIZE = MAX_BLOCK_WEIGHT = 4_000_000`,
  `MAX_BLOCK_SIGOPS_COST = 80_000`, `WITNESS_SCALE_FACTOR = 4`.

**Files audited**
- `src/ouroboros/rpc.py:125-267` — `bip22_result_string()` translator
  (the rough-edged English-to-canonical-token mapper).
- `src/ouroboros/rpc.py:288-409` — `accept_block()` unified helper.
- `src/ouroboros/rpc.py:4798-4839` — `rpc_getmininginfo`.
- `src/ouroboros/rpc.py:4841-5332` — `rpc_getblocktemplate` (the main
  audit target; ~492 lines).
- `src/ouroboros/rpc.py:5334-5452` — `_get_block_height`,
  `_resolve_parent_height`.
- `src/ouroboros/rpc.py:5454-5469` — `_evict_side_branch_if_full`.
- `src/ouroboros/rpc.py:5471-5624` — `_attach_side_branch_block`.
- `src/ouroboros/rpc.py:5626-6065` — `_reorg_to_side_branch_tip`
  (the in-Python submitblock-driven reorg shim).
- `src/ouroboros/rpc.py:6067-6171` — `rpc_submitblock`.
- `src/ouroboros/rpc.py:6173-6232` — `rpc_submitblockbatch` (ouroboros
  bespoke; not in Core).
- `src/ouroboros/rpc.py:8654-8726` — `rpc_prioritisetransaction` /
  `rpc_getprioritisedtransactions`.
- `src/ouroboros/rpc.py:8728-9000` — `rpc_generatetoaddress`.
- `src/ouroboros/rpc.py:1011-1077` — `_execute_single_rpc` (dispatch via
  `getattr(self, f"rpc_{method}")`).
- `src/ouroboros/consensus.py:645-720` — `get_all_deployments_info`
  (BIP-9 deployment state, the wire that GBT does NOT use).
- `src/ouroboros/config.py:71` — `RegtestConfig.SUBSIDY_HALVING_INTERVAL = 150`.
- `src/ouroboros/tests/test_w108_gbt.py` — 30 W108 GBT gates (mostly
  document current incorrect state as regression contracts).
- `src/ouroboros/tests/test_w123_mining_gbt.py` — 30 W123 GBT gates
  (ditto).
- `ferrous-utils/sync/src/lib.rs` — confirmed mining-free per the W123 G26
  invariant.

---

## Gate matrix (54 sub-gates / 16 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | template_request parse | G1: `mode` dispatch (template / proposal) | **BUG-1 (P0-CDIV)** — parameter declared but never read; `mode=="proposal"` silently returns full template |
| 1 | … | G2: invalid mode → RPC_INVALID_PARAMETER | **BUG-1 cross-cite** |
| 1 | … | G3: client `rules` must include `segwit` | **BUG-2 (P0-CDIV)** — no `setClientRules` enforcement |
| 1 | … | G4: client `rules` must include `signet` on signet chain | **BUG-2 cross-cite** |
| 1 | … | G5: `capabilities` (client-supported features) read | **BUG-1 cross-cite** |
| 1 | … | G6: `longpollid` parsed → wait on tip-change OR mempool-change | **BUG-3 (P0-CDIV)** — no longpoll loop at all |
| 2 | non-test-chain guards | G7: refuse if `isInitialBlockDownload()` | **BUG-4 (P1)** — `_is_synced()` exists but GBT does not consult it |
| 2 | … | G8: refuse if `connman.GetNodeCount(Both) == 0` | **BUG-5 (P1)** — no peer-count gate |
| 3 | template caching | G9: re-build only when (tip changed) OR (mempool delta AND >5s elapsed) | **BUG-6 (P1)** — every call rebuilds; no `pindexPrev` pin / 5s window |
| 4 | nVersion / nBits | G10: `version = ComputeBlockVersion(pindexPrev, params)` | **BUG-7 (P0-CDIV)** dead-helper `get_next_block_version`; carry-forward W154 BUG-3 — fallback `best_block.version \| 0x20000000` always runs (consensus.py:763 `compute_block_version` defined but uncalled) |
| 4 | … | G11: `bits = GetNextWorkRequired(pindexPrev, params)` | **BUG-7 cross-cite** dead-helper `get_next_bits`; rpc.py:5223 always falls back to `best_block.bits` → every 2016-block adjustment boundary template emits previous-epoch's bits |
| 4 | … | G12: `UpdateTime` recompute bits on `fPowAllowMinDifficultyBlocks` chains | **BUG-7 cross-cite** — testnet/signet 20-min-mindiff rule never fires |
| 5 | BIP-9 fields | G13: `rules` includes active+locked-in deployment names | **BUG-8 (P1)** — `gbt_rules` is hardcoded `["csv", "!segwit", "taproot"]` (+ `!signet`); does not consult `get_all_deployments_info` |
| 5 | … | G14: `vbavailable` enumerates STARTED + LOCKED_IN deployments | **BUG-9 (P0-CDIV)** — hardcoded empty `{}` (rpc.py:5287); future soft-fork signalling structurally broken |
| 5 | … | G15: `vbrequired` bitmask reflects mandatory bits | **BUG-9 cross-cite** — hardcoded `0`; mandatory bits cannot be advertised |
| 6 | BIP-22 mutables | G16: `mutable[]` contains `time` / `transactions` / `prevblock` | PASS (rpc.py:5326) |
| 6 | … | G17: `mutable[]` may include `version/force` / `submit/coinbase` / `coinbase/append` | **BUG-10 (P1)** — only the 3-tuple basics emitted |
| 7 | coinbasetxn / coinbasevalue | G18: `coinbasevalue` is JSON NUMBER (satoshis int) | PASS — `coinbase_value = subsidy + total_fees` emitted as Python int, `_BTCEncoder` renders ints as bare digits (rpc.py:502-503) |
| 7 | … | G19: `coinbasetxn` includes `data` (raw hex of coinbase) | **BUG-11 (P1)** — `coinbasetxn` is `{"locktime", "sequence"}` only; no `data` hex. Miners cannot reconstruct txid without rebuilding the coinbase themselves (W123 G24 carry-forward) |
| 7 | … | G20: `coinbasetxn` includes `fee` / `sigops` / `weight` | **BUG-11 cross-cite** — none of these are emitted |
| 7 | … | G21: `coinbasetxn.locktime = nHeight-1` | PASS (W87 B3 fix; rpc.py:5313) |
| 7 | … | G22: `coinbasetxn.sequence = 0xFFFFFFFE` (MAX_SEQUENCE_NONFINAL) | PASS (W87 B2 fix; rpc.py:5317) |
| 8 | per-tx entries | G23: each tx has `data` (hex) | PASS (rpc.py:5152) |
| 8 | … | G24: each tx has `txid` (display-order BE) | PASS (rpc.py:5153) |
| 8 | … | G25: each tx has `hash` = wtxid (display-order BE) | PASS (W87 B11 fix; rpc.py:5154) |
| 8 | … | G26: each tx has `depends[]` (1-based template indices of in-template parents) | PASS (W87 B12 fix; rpc.py:5155) |
| 8 | … | G27: each tx has `fee` (satoshis int) | PASS (rpc.py:5156) |
| 8 | … | G28: each tx has `sigops` (cost int) | PASS (rpc.py:5157) |
| 8 | … | G29: each tx has `weight` (BIP-141 weight units) | PASS (W87 B6 fix; rpc.py:5158) |
| 9 | template constants | G30: `noncerange = "00000000ffffffff"` | PASS (rpc.py:5327) |
| 9 | … | G31: `sigoplimit = 80_000` post-segwit, `20_000` pre-segwit | **BUG-12 (P1)** — always `MAX_BLOCK_SIGOPS_COST` regardless of fPreSegWit (W108 G12 carry-forward) |
| 9 | … | G32: `sizelimit = 4_000_000` post-segwit, `1_000_000` pre-segwit | **BUG-12 cross-cite** — always `4_000_000` |
| 9 | … | G33: `weightlimit` ONLY present post-segwit | **BUG-13 (P2)** — unconditionally emitted |
| 9 | … | G34: `default_witness_commitment` ONLY present when coinbase has a witness commitment | **BUG-14 (P1)** — emitted unconditionally; pre-segwit miners see an unusable hex (rpc.py:5331) |
| 10 | curtime / mintime | G35: `curtime = max(MTP+1, NodeClock::now())` (UpdateTime) | PASS (W87 B9 fix; rpc.py:5258-5259) |
| 10 | … | G36: `mintime = GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval)` including BIP-94 timewarp arm | **BUG-15 (P1)** — `mintime = MTP+1`; no `MAX_TIMEWARP` adjustment at retarget boundary (W123 G11 carry-forward) |
| 11 | longpollid | G37: `longpollid = tip.GetHex() + ToString(nTransactionsUpdatedLast)` | **BUG-16 (P0-CDIV)** — field **entirely absent** from response (rpc.py:5294-5332 enumerates fields; no `longpollid`); plus no `GetTransactionsUpdated` counter on Mempool. Strictly violates BIP-22 minimum response shape |
| 12 | signet | G38: `signet_challenge` field on signet | **BUG-17 (P1)** — never emitted; Node has no `signet_challenge` attribute |
| 12 | … | G39: signet block-signing (BIP-325) on submitblock path | **BUG-17 cross-cite** — generatetoaddress unaware of signet |
| 13 | coinbaseaux | G40: `coinbaseaux = {}` (empty object per Core) | **BUG-18 (P2)** — emits `{"flags": ""}`; Core emits empty object |
| 14 | submitblock | G41: signature accepts `(hexdata, dummy=ignored)` per BIP-22 | **BUG-19 (P1)** — signature is `(hexdata: str)` only; calling clients that pass `["blockhex", "workid"]` per BIP-22 fail dispatch (params list-length mismatch raises TypeError) |
| 14 | … | G42: `UpdateUncommittedBlockStructures(block, pindex)` called pre-Process | **BUG-20 (P1)** — never called; pools that mine atop a stale tip do not get witness commitment fixed up |
| 14 | … | G43: `submitblock_StateCatcher` via `RegisterSharedValidationInterface` | **BUG-21 (P0-CDIV)** — no StateCatcher; the result string is derived from `bip22_result_string(str(e))`, an English-to-token translator with **catch-all `return "rejected"` for any unknown error** (rpc.py:267). Block reject reasons that Core surfaces as canonical tokens leak through ouroboros as `"rejected"` — wire-protocol divergence on the spec's most important field |
| 14 | … | G44: `if (!new_block && accepted) return "duplicate"` | PARTIAL — duplicates short-circuit BEFORE accept_block via `db.has_block_hash` (rpc.py:6125), but only when block was previously on the active chain |
| 14 | … | G45: `if (!sc->found) return "inconclusive"` | **BUG-22 (P1)** — `"inconclusive"` is in the canonical-token pass-through list (rpc.py:143) but NO code path returns it; the only way it surfaces is if `bip22_result_string` matches `"previous block not found"` (rpc.py:264-265) |
| 14 | … | G46: `duplicate-invalid` for previously-rejected blocks (BLOCK_FAILED_VALID) | **BUG-23 (P1)** — string defined in pass-through list but no invalid-block index to consult; W108 G19 + W123 G16 cross-cite |
| 14 | … | G47: BIP22ValidationResult string is Core's CONSENSUS REJECT TOKEN (not free-form English) | **BUG-21 cross-cite** — explicit mapping table compensates but is incomplete & lossy |
| 14 | … | G48: submitblock notifies ZMQ subscribers (CMainSignals::BlockChecked) | **BUG-24 (P1)** — `accept_block` does NOT call `zmq_publisher.notify_block`; only P2P arrivals notify ZMQ. Asymmetric, monitoring-divergent |
| 14 | … | G49: ZeroMQ NotifyBlockChecked is fired for ACCEPTED blocks via submitblock path | **BUG-24 cross-cite** |
| 15 | submitheader | G50: `submitheader` RPC exists | **BUG-25 (P1)** — no `rpc_submitheader`; light-clients / SPV bridges can't push a header-only update |
| 16 | mining RPC surface | G51: `generateblock` RPC exists (deterministic regtest mining) | **BUG-26 (P1)** — no `rpc_generateblock` |
| 16 | … | G52: `generatetodescriptor` RPC exists | **BUG-27 (P1)** — no `rpc_generatetodescriptor` |
| 16 | … | G53: `prioritisetransaction` rejects dust-output tx (`mempool.m_opts.require_standard && !GetDust(tx).empty()`) | **BUG-28 (P1)** — no dust-check (Core mining.cpp:537-539); ouroboros accepts dust-output prioritisation silently |
| 16 | … | G54: GBT `subsidy` is params-aware (`nSubsidyHalvingInterval` per network) | **BUG-29 (P0-CDIV)** — `halvings = next_height // 210_000` hardcoded (rpc.py:5211); regtest (`SUBSIDY_HALVING_INTERVAL=150`, config.py:71) ignored; W145 carry-forward. **N-pipeline drift extended to 4+ subsidy pipelines** (cross-cite W154 BUG-11) — `generatetoaddress` CORRECTLY consults `RegtestConfig.SUBSIDY_HALVING_INTERVAL` (rpc.py:8767) but GBT does NOT |

---

## BUG-1 (P0-CDIV) — `template_request.mode` dispatch entirely absent

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate` accepts a
`template_request` object whose `mode` key drives the whole dispatch:

- `mode == "template"` (default) — return a template
- `mode == "proposal"` — VALIDATE the supplied `data` block hex via
  `TestBlockValidity` and return `BIP22ValidationResult(state)` (or
  `"duplicate"` / `"duplicate-invalid"` / `"duplicate-inconclusive"` if
  the block is already in the block index)
- any other string — `throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode")`

ouroboros's `rpc_getblocktemplate(self, template_request: dict = None)`
declares the parameter but the function body **reads it zero times after
the signature line**. Every call returns a fresh template; proposal mode
is silently treated as template mode; invalid modes are silently treated
as template mode.

**File:** `src/ouroboros/rpc.py:4841` (signature declares
`template_request: dict = None`); 4884-5332 (body never references
`template_request`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:715-764`.

**Impact:**
- BIP-23 `proposal` flow is structurally absent. A pool that tries to
  submit-then-validate a candidate using GBT's proposal mode gets a
  template back instead of a validation verdict. The pool then has no
  way to know if its candidate is valid before broadcasting.
- Spec violation: `mode == "invalid_xxx"` does not error.
- Carry-forward W108 G3 + W123 G4; this audit re-emphasizes severity
  because **this is the BIP-23 contract**, not optional gold-plating.

---

## BUG-2 (P0-CDIV) — `rules` client-rule enforcement absent (segwit / signet mandatory)

**Severity:** P0-CDIV. Bitcoin Core enforces two `rules`-array
invariants (`mining.cpp:850-857`):

```cpp
if (consensusParams.signet_blocks && !setClientRules.contains("signet")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the signet rule set ...");
}
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set ...");
}
```

These are HARD GATES on the response — a client that does not declare
`segwit` (or `signet` on signet chains) must not be served a template,
because the server cannot guarantee the client will produce a valid
block.

ouroboros's GBT body never reads `template_request["rules"]`. A
non-segwit-aware client (any pre-BIP-141 miner) receives a post-segwit
template and produces a block that fails wire-validity at the next
node it submits to.

**File:** `src/ouroboros/rpc.py:4841` (signature) — body does not parse
`rules` or maintain `setClientRules`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:850-857`.

**Impact:** spec-mandatory gate absent; a legacy miner can be silently
fed a template it cannot honour. Fleet pattern continuity with BUG-1.

---

## BUG-3 (P0-CDIV) — `longpollid` parse + waitTipChanged loop absent

**Severity:** P0-CDIV. BIP-22's long-poll model is the canonical way
for a pool to wait for either a tip change or a meaningful mempool
delta without spinning. Core's loop (`mining.cpp:783-845`) does:

1. Parse client-supplied `longpollid` = `tip(64 hex) + counter(decimal)`.
2. Release `cs_main` and call `miner.waitTipChanged(hashWatchedChain,
   checktxtime)` with 1-min initial / 10-sec subsequent timeout.
3. Wake on tip change OR `mempool.GetTransactionsUpdated() !=
   nTransactionsUpdatedLastLP`.

ouroboros's `rpc_getblocktemplate`:
- Does not parse `longpollid` from `template_request` (BUG-1
  cross-cite).
- Does not have a `waitTipChanged` primitive on `BitcoinNode`
  (test_w123 G14 explicitly asserts the absence).
- Mempool has no `GetTransactionsUpdated` counter (test_w123 G5
  explicitly asserts the absence).
- Response does not emit `longpollid` (BUG-16 below).

Pool software (e.g. Stratum bridges, Eligius-style infra) that uses
long-poll on Core fails to long-poll on ouroboros; the pool falls back
to polling at whatever rate it has internally, wasting bandwidth /
CPU and increasing block-template staleness.

**File:** `src/ouroboros/rpc.py:4841-5332` (no longpoll machinery).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:777-845`.

**Impact:** BIP-22 spec-mandatory mechanic missing. Pool software has
to fall back to polling. Affects every pool integration.

---

## BUG-4 (P1) — IBD guard absent on non-test chains

**Severity:** P1. Core's GBT (`mining.cpp:766-775`) refuses to serve
a template on a non-test chain if either `connman.GetNodeCount(Both)
== 0` or `miner.isInitialBlockDownload()`. The rationale is that a
miner who builds a block on top of a stale tip risks orphaning their
work.

ouroboros has the `_is_synced()` helper at `rpc.py:9587-9592` that
returns `not self.node.sync_manager.is_synced()` when present, but
`rpc_getblocktemplate` does not consult it. A node still in IBD that
gets a GBT call returns a template anchored to whatever stale tip the
node has reached, which is almost certainly already orphaned by the
real network.

**File:** `src/ouroboros/rpc.py:4841-5332` (no `self._is_synced()`
call); `_is_synced` exists at line 9587 and is used by
`handleGetBlockchainInfo` and similar, but not by GBT.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:772-774`.

**Impact:** miners served a doomed template during IBD; pool burns
hashrate on stale work.

---

## BUG-5 (P1) — Peer-count guard absent on non-test chains

**Severity:** P1. Companion to BUG-4. Core refuses GBT when
`connman.GetNodeCount(Both) == 0` (the rationale: a node with no peers
cannot push a found block out to the network, so the work would be
wasted). ouroboros emits a template even with zero peers.

The `Node` exposes peer count via `len(node.peer_manager.peers)` (per
the `handleGetSyncState` / `getconnectioncount` paths) but GBT does
not consult it.

**File:** `src/ouroboros/rpc.py:4841-5332` (no peer-count gate).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:767-771`.

**Impact:** same shape as BUG-4 for the "isolated node" case.

---

## BUG-6 (P1) — No template caching; rebuild on every call

**Severity:** P1. Core caches the assembled `CBlockTemplate` and only
rebuilds when:
- the tip has changed since the cached template was built, OR
- `mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast` AND
  more than 5 seconds have elapsed.

This bounds template-assembly cost when a pool issues GBT calls at
sub-second frequency.

ouroboros's `rpc_getblocktemplate` rebuilds from scratch on every
call: mempool snapshot, ancestor-fee-rate sort, witness merkle
computation, etc. For a busy mainnet mempool (~150k tx) this is
~100-200 ms of wall time per call. A pool issuing 10 GBT/sec saturates
the asyncio loop on GBT alone.

**File:** `src/ouroboros/rpc.py:4841` (no cache attributes on
`RPCServer`; W123 G3 explicitly asserts absence of
`_gbt_template_cache` / `_gbt_pindex_prev`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:860-884`.

**Impact:** O(mempool size) work per GBT call vs Core's O(1) cache
hit. Performance regression scaled by pool poll rate; not a
correctness gap, but a meaningful operational divergence.

---

## BUG-7 (P0-CDIV) — Dead-helper `get_next_bits` / `get_next_block_version` (carry-forward from W154 BUG-3)

**Severity:** P0-CDIV. Cross-cite W154 BUG-3 — restating because the
RPC-side observable consequence is what this audit catalogues, and the
bug is unfixed. ouroboros's GBT body (`rpc.py:5219-5251`) does:

```python
_next_bits = getattr(self.node, "get_next_bits", None)
if callable(_next_bits):
    _bits_val = _next_bits(best_height)
    bits = _bits_val if isinstance(_bits_val, int) else best_block.bits
else:
    bits = best_block.bits

_next_version_fn = getattr(self.node, "get_next_block_version", None)
if callable(_next_version_fn):
    _ver_val = _next_version_fn(best_height)
    block_version = _ver_val if isinstance(_ver_val, int) else (best_block.version | 0x20000000)
else:
    block_version = (best_block.version | 0x20000000)
```

Neither `def get_next_bits` nor `def get_next_block_version` exists
anywhere in `src/ouroboros/`. The fallback ALWAYS runs.

Tests at `test_w108_gbt.py:318-339` (TestG10DeadHelperBitsVersion) and
`test_w123_mining_gbt.py:85-86` (`del mock_node.get_next_bits` /
`del mock_node.get_next_block_version`) **explicitly delete these
attributes from the mock node to confirm the dead-helper path is
exercised**, and assert the resulting incorrect behaviour as a
regression contract — i.e. the test suite documents the bug as the
intended state.

Observable consequences at the BIP-22 wire layer:

1. Every 2016-block adjustment boundary emits the previous epoch's
   bits → mined block has wrong `nBits` → `bad-diffbits` reject. Permanent
   failure mode every ~2 weeks on mainnet.
2. BIP-9 signalling broken: if a STARTED deployment activates between
   GBT calls, miners never signal the new bit. Future soft-fork
   activations would be effectively undeployable through ouroboros
   miners. (`consensus.compute_block_version` exists with full BIP-9
   logic but no caller.)
3. testnet/signet `fPowAllowMinDifficultyBlocks` 20-minute mindiff
   rule cannot fire (no bits recompute on `curtime` advance).

**File:** `src/ouroboros/rpc.py:5219-5251`;
`src/ouroboros/consensus.py:763-816` (compute_block_version
defined-but-uncalled); `ferrous-utils/sync/src/lib.rs:401-447`
(`get_next_work_required` Rust function defined-but-uncalled).

**Core ref:** `bitcoin-core/src/node/miner.cpp:140, 220` —
`ComputeBlockVersion` + `GetNextWorkRequired` are unconditionally
called inside `CreateNewBlock`.

**Impact:** identical to W154 BUG-3; cross-tabulated here because this
audit's primary deliverable is the BIP-22 wire surface and the
incorrect `bits` / `version` are the most visible wire-layer
consequences. "Plumb-but-don't-wire" / "comment-as-confession" 12th
ouroboros instance.

---

## BUG-8 (P1) — `rules` array hardcoded; does not reflect actual deployment state

**Severity:** P1. Core's GBT builds the `rules` array dynamically from
`gbtstatus.active` (`mining.cpp:985-991`), pushing each active
deployment's name (prefixed with `!` if mandatory). New soft forks
flow into this list as they reach ACTIVE state, with zero code
changes.

ouroboros hardcodes:
```python
gbt_rules = ["csv", "!segwit", "taproot"]
if network == "signet":
    gbt_rules.append("!signet")
```

Consequences:
- Pre-activation chain (regtest below taproot height): emits
  `"taproot"` regardless. Miners trying to build a non-segwit pre-segwit
  block on a regtest fork see an inconsistent rules array.
- Post-taproot future-soft-fork ACTIVE deployments (anything not
  in the hardcoded list): never advertised; pools cannot know to
  signal.
- Compounds BUG-9 (vbavailable always empty): the rules array is the
  ONLY communication channel for active soft forks in ouroboros, and
  it's frozen.

**File:** `src/ouroboros/rpc.py:5269-5280`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:954-991`.

**Impact:** rules array doesn't reflect actual chain state; pools
miss new soft forks; pre-segwit context is misreported.

---

## BUG-9 (P0-CDIV) — `vbavailable` + `vbrequired` hardcoded; BIP-9 signalling pipeline absent

**Severity:** P0-CDIV. Core's `vbavailable` is the central BIP-9
soft-fork SIGNAL channel:

```cpp
const auto gbtstatus = chainman.m_versionbitscache.GBTStatus(*pindexPrev, consensusParams);
for (const auto& [name, info] : gbtstatus.signalling) {
    vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
    if (!info.gbt_optional_rule && !setClientRules.contains(name)) {
        block.nVersion &= ~info.mask;   // mask the bit out if client can't honour
    }
}
for (const auto& [name, info] : gbtstatus.locked_in) {
    block.nVersion |= info.mask;        // FORCE the bit on for LOCKED_IN
    vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
    ...
}
```

Two things happen here: (a) the response advertises which bits a
miner may/must signal, AND (b) the `block.nVersion` field is modified
based on client capability declarations + LOCKED_IN bits being forced
on.

ouroboros emits a hardcoded empty `vbavailable = {}` (rpc.py:5287)
with a code comment that calls itself out:

> "In ouroboros's simplified model there are no actively-signalling
> version-bit deployments beyond what is already in the rules list,
> so this is an empty dict. A full implementation would query the
> versionbits cache here."

This is a **comment-as-confession** (12th distinct ouroboros instance)
that the implementation is structurally incomplete.

And: `vbrequired = 0` (rpc.py:5292) is also hardcoded.

The supporting Rust infrastructure exists: `consensus.py:645-720`
defines `get_all_deployments_info(height, network, block_versions,
block_mtps)` which proxies to a Rust pyfunction
`get_all_deployments_info` exposed by `ferrous-utils/sync/src/lib.rs`,
returning the per-deployment STARTED/LOCKED_IN/ACTIVE state. **The
helper is called by getblockchaininfo but not by GBT.**

Consequences:
- Soft-fork signalling broken: any future BIP-9 deployment (e.g. the
  proposed great-consensus-cleanup) cannot be signalled by an
  ouroboros miner.
- LOCKED_IN bits not forced into `block.nVersion`: BUG-7 cross-cite
  means version is already wrong, and this widens the divergence: a
  hypothetical post-taproot LOCKED_IN deployment would not have its
  bit forced into the version field, so the miner's block would
  fail the mandatory-bit consensus check at the next height.

**File:** `src/ouroboros/rpc.py:5281-5292`;
`src/ouroboros/consensus.py:645` (helper defined but uncalled from GBT).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:965-996`.

**Impact:** BIP-9 signalling structurally broken; soft-fork activation
pipeline absent. P0-CDIV because future soft-fork activations are
effectively undeployable through ouroboros miners.

---

## BUG-10 (P1) — `mutable[]` array minimal; missing BIP-23 capability tokens

**Severity:** P1. Core's BIP-23 `mutable` list communicates which
parts of the template the miner is permitted to alter. The minimum
3-element list `["time", "transactions", "prevblock"]` is what
ouroboros emits. Core's full set may include
`"version/force"` (miner may set version bits), `"submit/coinbase"`
(miner may modify coinbase outputs), `"coinbase/append"`, etc.

ouroboros emits only the 3 basics, which is correct as a minimum but
silently strips the miner of the freedom to do useful things like
include extra coinbase outputs (mev tipping, MEV burns, etc.).

**File:** `src/ouroboros/rpc.py:5326`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:942-945` (basics) plus
the comment block at lines 942-945 describing the optional capability
tokens; W123 G27 cross-cite.

**Impact:** miner permission set silently restricted; capability gap.

---

## BUG-11 (P1) — `coinbasetxn` missing `data` / `fee` / `sigops` / `weight` fields

**Severity:** P1. BIP-22's `coinbasetxn` alternative payload (Core
`mining.cpp:911-933` for the per-tx shape applied to the coinbase
template) requires:
- `data` — raw hex of the coinbase transaction (CRITICAL: this is how
  miners reconstruct the txid without rebuilding the cb tx from
  scratch).
- `fee` — coinbase fee (NEGATIVE total block fees, since the coinbase
  is paid the fees plus subsidy).
- `sigops` — coinbase sigops cost.
- `weight` — coinbase weight.

ouroboros's `coinbasetxn` is:
```python
"coinbasetxn": {
    "locktime": next_height - 1,
    "sequence": 0xFFFFFFFE,
},
```

Two fields only. Miners can't:
- compute the coinbase txid without re-building the coinbase tx from
  scratch using the `coinbasevalue` field (which itself is partial
  information — `coinbasevalue = subsidy + total_fees` doesn't tell
  the miner what to put in the OP_RETURN, what extranonce padding
  to use, etc.),
- know the coinbase weight contribution to the budget calculation,
- know the coinbase sigops contribution.

In Core, `coinbasetxn` is emitted ONLY when the alternative-mode
flow is in use; the default flow uses `coinbasevalue` + the
`default_witness_commitment` + miner self-builds the coinbase. But if
`coinbasetxn` IS emitted, it MUST be a fully-formed entry with `data`
+ `fee` + `sigops` + `weight` (the same shape as per-tx entries).
ouroboros's hybrid is neither: it emits both `coinbasevalue` AND
`coinbasetxn`, but the latter only has 2 fields.

**File:** `src/ouroboros/rpc.py:5311-5318`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:911-933`; W123 G24
cross-cite.

**Impact:** BIP-22 contract leakage; miners following the spec for
`coinbasetxn` see a half-formed entry. Pools that test
`coinbasetxn.data` for the alternative flow break.

---

## BUG-12 (P1) — `sigoplimit` / `sizelimit` not divided by WITNESS_SCALE_FACTOR for pre-segwit blocks

**Severity:** P1. Core's GBT response (`mining.cpp:1007-1014`):

```cpp
int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;        // 80000
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;     // 4000000
if (fPreSegWit) {
    CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
    nSigOpLimit /= WITNESS_SCALE_FACTOR;            // 20000 pre-segwit
    CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
    nSizeLimit /= WITNESS_SCALE_FACTOR;             // 1000000 pre-segwit
}
```

ouroboros (rpc.py:5328-5329):
```python
"sigoplimit": MAX_BLOCK_SIGOPS_COST,      # always 80000
"sizelimit": 4_000_000,                   # always 4000000
```

A miner targeting a regtest fork below segwit activation (or a
testnet4 fork below segwit activation) gets `sigoplimit = 80_000` and
fills the block accordingly; the resulting block then exceeds the
pre-segwit consensus limit and is rejected `bad-blk-sigops` /
`bad-blk-length` at the next node.

In practice mainnet has been post-segwit since 2017, so this only
bites regtest and exotic test scenarios. But it IS a wire-spec
divergence that the W108 G12 test pinned as known-bad.

**File:** `src/ouroboros/rpc.py:5328-5329`; W108 G12 cross-cite.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1014`.

**Impact:** regtest pre-segwit mining diverges; spec contract gap.

---

## BUG-13 (P2) — `weightlimit` always emitted; Core emits only post-segwit

**Severity:** P2. Cosmetic / spec-contract. Core (`mining.cpp:1017-1019`):

```cpp
if (!fPreSegWit) {
    result.pushKV("weightlimit", MAX_BLOCK_WEIGHT);
}
```

ouroboros emits `"weightlimit": MAX_BLOCK_WEIGHT` unconditionally
(rpc.py:5330). Pre-segwit miners see a weightlimit they cannot
honour (because weight is segwit-defined).

**File:** `src/ouroboros/rpc.py:5330`; W108 G28 cross-cite.

**Impact:** spec-contract leakage; harmless on modern chains.

---

## BUG-14 (P1) — `default_witness_commitment` emitted unconditionally

**Severity:** P1. Core (`mining.cpp:1028-1031`):

```cpp
if (auto coinbase{block_template->getCoinbaseTx()}; coinbase.required_outputs.size() > 0) {
    CHECK_NONFATAL(coinbase.required_outputs.size() == 1);
    result.pushKV("default_witness_commitment", HexStr(coinbase.required_outputs[0].scriptPubKey));
}
```

The witness commitment is emitted ONLY when the coinbase has a
witness-commitment required output (i.e. segwit is active for the
parent block).

ouroboros emits `default_witness_commitment` unconditionally
(rpc.py:5331), computed from the witness merkle root of the selected
txs. On a pre-segwit chain (or pre-segwit regtest fork), the miner
sees a hex they cannot include without breaking pre-segwit consensus.

The witness merkle computation itself is also unconditional — adding
~O(ntx) extra work to every GBT call regardless of segwit state.

**File:** `src/ouroboros/rpc.py:5171-5207, 5331`; W123 G28 cross-cite.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1028-1031`.

**Impact:** pre-segwit miners get an unusable witness commitment hex;
spec-contract gap; minor perf regression on the witness-merkle
compute.

---

## BUG-15 (P1) — `mintime` ignores BIP-94 MAX_TIMEWARP arm

**Severity:** P1. Core's `GetMinimumTime(pindexPrev,
DifficultyAdjustmentInterval)` (miner.cpp:36-46) implements:

```cpp
int64_t min_time = pindexPrev->GetMedianTimePast() + 1;
if (height % difficulty_adjustment_interval == 0) {
    // BIP-94 timewarp: the new block's time cannot precede
    // (tip.GetBlockTime() - MAX_TIMEWARP) at the boundary.
    min_time = std::max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```

ouroboros (`rpc.py:5258-5259, 5325`):
```python
mtp_plus_one = block_mtp + 1
curtime = max(mtp_plus_one, int(_time.time()))
...
"mintime": mtp_plus_one,
```

No retarget-boundary clamp. A miner at a DAI boundary who consults
`mintime` and produces a block with timestamp >= mintime but <
(prev_block_time - MAX_TIMEWARP) ends up with a header that Core
rejects as `time-too-old-mediantime` (and the BIP-94 cleanup fork would
reject as a timewarp).

**File:** `src/ouroboros/rpc.py:5258-5259, 5325`; W108 G9 + W123 G11
cross-cite.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-46`.

**Impact:** rare — only retarget-boundary blocks with manually-controlled
miner timestamps trip this — but BIP-94 enforcement post-cleanup makes
this a hard reject. Spec-contract gap.

---

## BUG-16 (P0-CDIV) — `longpollid` field entirely absent from response

**Severity:** P0-CDIV (BIP-22 minimum response shape violation). BIP-22
specifies `longpollid` as a mandatory field of the GBT response (Core
`mining.cpp:1002`):

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

A pool that issues a follow-up GBT with this exact string in
`template_request.longpollid` is supposed to get the same template back
until either tip changes or mempool delta accumulates.

ouroboros's GBT response (rpc.py:5294-5332) enumerates every field
emitted: `capabilities`, `version`, `rules`, `vbavailable`,
`vbrequired`, `previousblockhash`, `transactions`, `coinbaseaux`,
`coinbasevalue`, `coinbasetxn`, `target`, `bits`, `curtime`,
`height`, `mintime`, `mutable`, `noncerange`, `sigoplimit`,
`sizelimit`, `weightlimit`, `default_witness_commitment`.

**No `longpollid` key.** A BIP-22-conformant pool's
`template_request.longpollid = response.longpollid` cycle is broken at
the first call.

Cross-cite W123 G30 (`TestG30LongpollidFormatMissing`) which asserts
this as the regression contract.

**File:** `src/ouroboros/rpc.py:5294-5332` (response dict literal —
no `longpollid` key).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1002`; BIP-22 spec.

**Impact:** BIP-22 minimum-response-shape violation. Pool software
that expects `response.longpollid` per spec encounters a KeyError on
the first call.

---

## BUG-17 (P1) — `signet_challenge` field absent + signet block-signing missing

**Severity:** P1. Core's GBT (`mining.cpp:1024-1026`):
```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

Signet miners need this challenge script to compute the BIP-325
signature that the next block requires in its coinbase. ouroboros's
GBT body has zero references to `signet_challenge`.

In addition, the signet block-signing primitive (BIP-325 mining flow —
sign the candidate, embed the signature in coinbase scriptSig, then
broadcast) is absent from `rpc_generatetoaddress`. A miner mining on
the default signet via ouroboros produces unsigned candidate blocks
that the signet challenge script will always reject.

`BURIED_DEPLOYMENTS` exists per-network, but signet challenge data
plumbing through to Node config / RPC layer is missing.

**File:** `src/ouroboros/rpc.py:5294-5332` (GBT response, no
`signet_challenge`); `rpc.py:8728-9000` (`generatetoaddress`, no
signet signing); cross-cite W108 G13 + W123 G10/G29.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026`;
`bitcoin-core/src/signet.cpp`.

**Impact:** signet mining via ouroboros structurally broken (both GBT
template field AND signing flow absent). Affects any signet pool /
test fixture.

---

## BUG-18 (P2) — `coinbaseaux` emits `{"flags": ""}` instead of empty `{}`

**Severity:** P2. Core's GBT (`mining.cpp:1000`):

```cpp
UniValue aux(UniValue::VOBJ);
result.pushKV("coinbaseaux", std::move(aux));
```

`aux` is constructed empty and never appended to. Core emits `{}`.

ouroboros (rpc.py:5261-5263, 5309):
```python
coinbase_aux = {
    "flags": "",  # extra nonce space in coinbase scriptSig
}
...
"coinbaseaux": coinbase_aux,
```

Comment refers to "extra nonce space" — which is from the
ancient/deprecated BIP-22 alternative where `coinbaseaux.flags`
indicated bytes a miner should APPEND to the coinbase scriptSig.
Modern Core stopped emitting this; ouroboros still does. Pools that
parse `coinbaseaux` strictly per shape see an unexpected key.

**File:** `src/ouroboros/rpc.py:5261-5263, 5309`; W108 G16 cross-cite.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1000`.

**Impact:** cosmetic / contract-leakage; harmless in practice but the
contract is wrong.

---

## BUG-19 (P1) — `rpc_submitblock` signature accepts only 1 arg; BIP-22 mandates 2 (with dummy)

**Severity:** P1. BIP-22 specifies `submitblock` as a 2-argument RPC
(`hexdata`, `dummy`) with `dummy` ignored. Core's signature
(`mining.cpp:1063-1065`) matches:

```cpp
{
    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ...},
    {"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, ...},
},
```

A pool stack that sends a workid or other tracking string as the
second positional argument is the BIP-22 default. ouroboros's
`async def rpc_submitblock(self, hexdata: str) -> str | None`
(rpc.py:6067) accepts only one parameter. The dispatch at
`_execute_single_rpc` (rpc.py:1052-1053):

```python
if isinstance(params, list):
    result = await handler(*params)
```

Unpacking a 2-element `params` list into a 1-arg handler raises
`TypeError: rpc_submitblock() takes 2 positional arguments but 3 were
given`, caught at the catch-all (rpc.py:1067) and returned as a
generic `-32603` JSON-RPC error rather than a successful submission.

W123 G15 cross-cite (TestG15SubmitBlockDummyArg explicitly asserts
this 1-arg shape as the regression contract).

**File:** `src/ouroboros/rpc.py:6067`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1063-1065`.

**Impact:** any BIP-22-conformant pool that includes the 2nd arg as
documented breaks on submit. Catastrophic UX gap because of the
spec-compliant call shape.

---

## BUG-20 (P1) — `UpdateUncommittedBlockStructures` pre-Process step missing

**Severity:** P1. Core's `submitblock` (`mining.cpp:1083-1090`):

```cpp
ChainstateManager& chainman = EnsureAnyChainman(request.context);
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```

`UpdateUncommittedBlockStructures` updates the witness commitment in
the coinbase if the SegWit deployment is active for this block's
parent but the candidate (built by an old miner that doesn't know
SegWit) lacks the commitment. This step is what allowed pools to
transition mid-flight as SegWit activated.

ouroboros's `rpc_submitblock` goes straight from header parse →
`accept_block`; the witness-commitment fix-up never runs. A miner
software built before SegWit activation that submits a candidate that
just-passed-the-activation-height block would have the candidate
rejected for missing commitment, where Core would silently fix it up.

**File:** `src/ouroboros/rpc.py:6067-6171`; W108 G18 cross-cite.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1083-1090`.

**Impact:** edge-case at SegWit activation; in practice harmless on
mainnet (activated 2017) but spec-contract gap and would matter on
fresh testnet/regtest fork activations.

---

## BUG-21 (P0-CDIV) — BIP22ValidationResult mapping is an English-to-token translator with catch-all `"rejected"`

**Severity:** P0-CDIV (wire-protocol divergence on BIP-22 spec's most
important field). Core's `BIP22ValidationResult` (`mining.cpp:587-602`):

```cpp
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid()) return UniValue::VNULL;
    if (state.IsError()) throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid()) {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty()) return "rejected";
        return strRejectReason;       // ← Core's CONSENSUS reject token
    }
    return "valid?";
}
```

Core's `state.GetRejectReason()` is the EXACT consensus reject token
(`bad-cb-amount`, `bad-txnmrklroot`, `bad-witness-merkle-match`,
`bad-blk-sigops`, `bad-txns-inputs-missingorspent`, etc.). Core sets
these tokens at the exact `state.Invalid(...)` call sites in
`validation.cpp` / `consensus/`. The token is the spec contract.

ouroboros has no `BlockValidationState`-like object that propagates the
canonical token from the original `state.Invalid` call site. Instead
it has `bip22_result_string(error_str)` (rpc.py:125-267) that walks
through ~30 if-arms doing substring matching on the English error
message that bubbled up from validation:

```python
if "premature" in s or "coinbase maturity" in s or "not yet mature" in s or "not mature" in s:
    return "bad-txns-premature-spend-of-coinbase"
...
if "outputs exceed inputs" in s or "bad-txns-in-belowout" in s:
    return "bad-txns-in-belowout"
...
return "rejected"   # ← catch-all for any unmatched message
```

The catch-all `return "rejected"` is the heart of the wire divergence.
Any validation error whose English message doesn't match any of the
~30 substring arms is reported as `"rejected"` — a token that Core
uses only when `state.GetRejectReason()` is empty (which Core's
consensus code never does — every `state.Invalid` call passes a
non-empty token). So a miner who submits a block that ouroboros
rejects with `"rejected"` and another impl rejects with the real
token sees a divergence on what should be the same consensus
behaviour.

Examples that escape to `"rejected"`:
- Any new validation error introduced in Rust `BlockValidationError`
  whose `__str__` does not contain any of the substring keywords.
- Any error from the Rust `validate_block_from_bytes` whose wrapping
  layer prefixed `"Block validation error: "` before the rest, since
  several arms (e.g. `"premature"` arm) check for substrings present
  in the inner error but the outer Rust wrapping may insert words that
  short-circuit a different arm.
- Any Python `validation.BlockValidator.validate_block` reject path
  whose error message format changes — and these messages change
  routinely as we land fix waves.

Compound failure: BUG-22 (`"inconclusive"` token never emitted) + BUG-23
(`"duplicate-invalid"` never emitted) means the canonical-pass-through
list of 17 strings (rpc.py:143-149) has multiple entries that
NO production code path can ever surface — they're plumbed as
recognised tokens but no upstream code returns them.

**File:** `src/ouroboros/rpc.py:125-267`; cross-cite every fix wave
that touches a validation error message.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:587-602`;
`bitcoin-core/src/consensus/validation.h::BlockValidationState`.

**Impact:** wire-protocol divergence on the most-significant field of
BIP-22's reject contract. Cross-impl test harnesses that fingerprint
the reject token to verify consensus parity see ouroboros as a noise
source: every unfamiliar error becomes `"rejected"` while other impls
return the canonical token. The right fix is to plumb the token from
the original Rust/Python `state.Invalid` call site through to the
RPC return, the same way Core's `BlockValidationState` does.

This is **the** structural BIP-22 bug.

---

## BUG-22 (P1) — `"inconclusive"` canonical token never emitted

**Severity:** P1. Core (`mining.cpp:1100-1102`):

```cpp
if (!sc->found) {
    return "inconclusive";
}
```

`"inconclusive"` is emitted when ProcessNewBlock returned but the
StateCatcher's BlockChecked signal never fired for this hash — i.e.
the block was probably accepted as a side branch or was about to be
processed but the function returned before the validation completed
(rare; can happen on shutdown).

ouroboros lists `"inconclusive"` in the canonical-token pass-through
set (rpc.py:144), but no code path ever returns it. The only mention
in `bip22_result_string` is the substring arm at rpc.py:263-265:

```python
if "previous block not found" in s or "block not found" in s:
    return "inconclusive"
```

— which is the WRONG semantic. Core uses `"inconclusive"` to mean
"validation didn't complete in time"; ouroboros uses it for
"prev-blk-not-found" (which Core would emit as
`"bad-prevblk"` or similar via the consensus token path). Two
different protocol meanings; ouroboros routes the wrong one to the
canonical token.

W108 G19 + W123 G16 cross-cite the related `"duplicate-invalid"` gap.

**File:** `src/ouroboros/rpc.py:143-149, 263-265`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1100-1102`.

**Impact:** token-meaning divergence on the `"inconclusive"` token;
fleet-pattern continuity with BUG-21 (the BIP-22 string contract is
structurally not honoured).

---

## BUG-23 (P1) — `"duplicate-invalid"` canonical token never emitted

**Severity:** P1. Core (`mining.cpp:746-748` in the proposal-mode
branch):

```cpp
if (pindex->nStatus & BLOCK_FAILED_VALID)
    return "duplicate-invalid";
return "duplicate-inconclusive";
```

— and Core's standard submitblock returns `"duplicate"` (line 1097)
for previously-accepted blocks. The three-way distinction
(`duplicate` / `duplicate-invalid` / `duplicate-inconclusive`) is the
miner's signal about whether to retry, give up, or try a different
template.

ouroboros's `rpc_submitblock` (rpc.py:6125, 6129):
```python
if hasattr(db, "has_block_hash") and db.has_block_hash(block_hash):
    return "duplicate"
...
if block_hash in self._side_branch_blocks:
    return "duplicate-inconclusive"
```

`"duplicate-invalid"` never emitted because there is no invalid-block
index to consult: ouroboros doesn't persist `BLOCK_FAILED_VALID` for
known-bad blocks. A miner who submits a previously-rejected block
gets the SAME validation path run again (full reject), rather than
the short-circuit `"duplicate-invalid"`. Wasted CPU per resubmit.

**File:** `src/ouroboros/rpc.py:6120-6130` (no invalid-block index
consultation); cross-cite W108 G19 + W123 G16.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:746-747`.

**Impact:** lack of short-circuit for known-bad block resubmits;
spec-contract gap on the three-way duplicate triage.

---

## BUG-24 (P1) — submitblock path does not fire ZMQ `BlockChecked` / `notify_block`

**Severity:** P1. Core's `submitblock` registers a
`submitblock_StateCatcher` via `RegisterSharedValidationInterface`
which is a CMainSignals subscriber. Any ZMQ publisher subscribed to
`CMainSignals::BlockChecked` also receives the same signal on the same
block. The result is that submitblock-accepted blocks notify ZMQ
subscribers (`hashblock`, `rawblock`) exactly like P2P-arrived blocks.

ouroboros's `accept_block` (rpc.py:288-409) does not call
`zmq_publisher.notify_block`. Only `src/ouroboros/block_sync.py:1381`
notifies ZMQ on P2P arrival. Asymmetric:
- P2P-arrived block → ZMQ subscribers see it.
- RPC-submitted block (via `submitblock` or `submitblockbatch`) → ZMQ
  subscribers DO NOT see it.

W123 G17 (TestG17SubmitBlockZmqNotifyMissing) explicitly asserts
this as the regression contract.

A pool stack that uses ZMQ `hashblock` to coordinate block-template
refresh after their own submitblock sees no notification and emits a
stale template until the next P2P arrival.

**File:** `src/ouroboros/rpc.py:288-409` (accept_block, no ZMQ);
`src/ouroboros/block_sync.py:1381` (P2P-side ZMQ wire-up).

**Core ref:** `bitcoin-core/src/validation.cpp::CMainSignals` /
`BlockChecked`; `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`.

**Impact:** asymmetric ZMQ notification; pool/monitoring tooling using
ZMQ on the submit-and-confirm path misses self-submitted blocks.

---

## BUG-25 (P1) — `submitheader` RPC missing entirely

**Severity:** P1. Core's `submitheader` (`mining.cpp:1108-1146`)
allows a caller to push an 80-byte header without supplying the full
block body — used by light-client / SPV bridges that want to advance
the node's header chain without paying the block-body bandwidth /
processing cost.

ouroboros has no `rpc_submitheader`. A grep over rpc.py confirms.
W123 G23 explicitly asserts this absence.

**File:** `src/ouroboros/rpc.py` (no `rpc_submitheader` method).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146`.

**Impact:** SPV bridge / light-client tooling that issues
`submitheader` to drive header-only updates hits Method not found.

---

## BUG-26 (P1) — `generateblock` RPC missing

**Severity:** P1. Core's `generateblock` (`mining.cpp:305`) is the
deterministic test-harness mining RPC: takes a list of pre-supplied
transactions, builds a block containing exactly those (no mempool
selection), mines it. Used heavily in functional tests.

ouroboros has no `rpc_generateblock`. W123 G21 explicitly asserts.

**File:** `src/ouroboros/rpc.py`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:305-413`.

**Impact:** Core functional-test compat gap; cross-impl test suites
that expect `generateblock` (e.g. for testing reorg with specific tx
sets) fail.

---

## BUG-27 (P1) — `generatetodescriptor` RPC missing

**Severity:** P1. Core's `generatetodescriptor` (`mining.cpp:219`)
is `generatetoaddress` but takes a descriptor instead of an address.
Used by wallet-aware test setups.

ouroboros has no `rpc_generatetodescriptor`. W123 G22 asserts.

**File:** `src/ouroboros/rpc.py`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:219-303`.

**Impact:** Core functional-test compat gap.

---

## BUG-28 (P1) — `prioritisetransaction` does NOT reject dust-output txs

**Severity:** P1. Core's `prioritisetransaction` (`mining.cpp:535-539`):

```cpp
// Non-0 fee dust transactions are not allowed for entry, and modification not allowed afterwards
const auto& tx = mempool.get(txid);
if (mempool.m_opts.require_standard && tx && !GetDust(*tx, mempool.m_opts.dust_relay_feerate).empty()) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is not supported for transactions with dust outputs.");
}
```

The rationale: prioritising a tx with dust outputs creates an
exception to the standard-policy dust-relay rule that the mempool
otherwise enforces. Core blocks this to keep the policy contract
intact.

ouroboros's `rpc_prioritisetransaction` (rpc.py:8654-8703) does only
the `dummy != 0` check + `int(fee_delta)` parse, then forwards to
`self.node.mempool.prioritise_transaction(txid, delta)`. No dust
check; an operator can prioritise a dust-bearing tx and silently
escape the policy rule.

**File:** `src/ouroboros/rpc.py:8654-8703`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:535-539`.

**Impact:** policy-contract leak; operator can promote dust-output
txs into mining selection that wouldn't otherwise be admitted via the
ATMP path.

---

## BUG-29 (P0-CDIV) — GBT subsidy hardcodes mainnet halving 210_000 (W145 carry-forward; N-pipeline drift extended to 4+ subsidy pipelines)

**Severity:** P0-CDIV. Cross-cite W145 (subsidy) and W154 BUG-11
(N-pipeline drift). The GBT body (rpc.py:5210-5213):

```python
subsidy = 50 * 100_000_000
halvings = next_height // 210_000     # ← hardcoded
if halvings < 64:
    subsidy >>= halvings
coinbase_value = subsidy + total_fees
```

Hardcodes mainnet's `nSubsidyHalvingInterval = 210_000`. Regtest's
`SUBSIDY_HALVING_INTERVAL = 150` (defined at config.py:71) is
ignored, so at regtest height 150 the GBT returns 50 BTC subsidy
instead of the correct 25 BTC (first halving). A miner who solves
the template emits a block with `coinbasevalue = 5_000_000_000`
which Core rejects as `bad-cb-amount`.

Meanwhile, `rpc_generatetoaddress` at rpc.py:8767 correctly consults
`RegtestConfig.SUBSIDY_HALVING_INTERVAL`:

```python
halving_interval = getattr(RegtestConfig, "SUBSIDY_HALVING_INTERVAL", 150)
halvings = next_height // halving_interval
```

**This is a fourth N-pipeline drift instance for ouroboros subsidy.**
Cross-cite W154 BUG-11 (which counted 3+ subsidy pipelines: GBT
hardcode, generatetoaddress with config, validation.py); W155 adds:
- GBT hardcoded 210_000 (rpc.py:5211) — wrong for regtest
- generatetoaddress params-aware (rpc.py:8767) — correct
- validation.py subsidy compute (W145 finding) — partially correct
- ferrous-utils Rust block_subsidy (lib.rs) — separate yet again

**Same node, same `RPCServer`, two adjacent mining helpers, two
different halving constants.**

W108 G27 (`TestG27SubsidyHalvingInterval`) and W145 already flagged
the GBT side; W155 narrows in on the **divergence between GBT and
`generatetoaddress` in the same module**.

**File:** `src/ouroboros/rpc.py:5210-5213` (GBT, wrong); rpc.py:8767
(generatetoaddress, right); `src/ouroboros/config.py:71` (regtest
constant).

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy` /
`consensusParams.nSubsidyHalvingInterval`; W145 cross-cite.

**Impact:** regtest GBT-driven mining emits `bad-cb-amount` past
h=150. Carry-forward W145; intra-node N-pipeline drift extended.

---

## Summary

**Bug count:** 29 (BUG-1 through BUG-29).

**Severity distribution:**
- **P0-CDIV:** 8 — BUG-1, BUG-2, BUG-3, BUG-7, BUG-9, BUG-16,
  BUG-21, BUG-29
- **P1:** 19 — BUG-4, BUG-5, BUG-6, BUG-8, BUG-10, BUG-11, BUG-12,
  BUG-14, BUG-15, BUG-17, BUG-19, BUG-20, BUG-22, BUG-23, BUG-24,
  BUG-25, BUG-26, BUG-27, BUG-28
- **P2:** 2 — BUG-13, BUG-18

Total: 8 + 19 + 2 = 29.

**Fleet patterns confirmed:**
- **"dead-helper plumb-but-don't-wire" 12th+ ouroboros instance**
  (BUG-7 — `get_next_bits` / `get_next_block_version` carry-forward
  W154 BUG-3; ALSO BUG-9 — `get_all_deployments_info` defined but
  uncalled from GBT).
- **"N-pipeline drift" 7+ ouroboros instances** — BUG-29 extends the
  subsidy pipeline count to 4+ (GBT-hardcoded vs generatetoaddress-
  params-aware vs validation.py vs Rust ferrous-utils, all coexisting
  with different values). Same `RPCServer` class, two adjacent
  methods, two different halving constants.
- **"comment-as-confession" 12th+ ouroboros instance** (BUG-9 inline
  comment "A full implementation would query the versionbits cache
  here"; BUG-8 hardcoded rules list with comment explaining "for
  post-segwit blocks always include csv, !segwit, and taproot" but no
  dynamic deployment query; BUG-14 unconditional witness commitment
  emission).
- **"wire-protocol English-to-token translator with catch-all
  'rejected'" NEW** (BUG-21). Distinct from the Core pattern where
  `BlockValidationState::GetRejectReason()` carries the consensus
  token verbatim. This is the structural BIP-22 bug.
- **"plumb-the-token-but-no-emitter" NEW** (BUG-22 + BUG-23). The
  canonical pass-through list at rpc.py:143-149 includes
  `"inconclusive"`, `"duplicate-invalid"`, `"duplicate-inconclusive"`
  as recognised tokens, but no production code path emits them with
  the right semantics (or at all).
- **"BIP-22-spec-mandatory-field-absent"** (BUG-16 `longpollid`;
  BUG-19 2nd `dummy` arg; BUG-2 client `rules` enforcement;
  BUG-3 longpoll loop). Four distinct spec-mandatory mechanisms
  absent in one GBT/submitblock surface.
- **"asymmetric notification"** (BUG-24 — submitblock path does not
  fire ZMQ; P2P arrival does). Companion to W141 ZMQ asymmetry
  patterns.
- **"intra-module subsidy divergence"** (BUG-29 — `rpc_getblocktemplate`
  and `rpc_generatetoaddress` in the same `RPCServer` class disagree
  on halving interval). NEW: previous N-pipeline findings were
  cross-module (Python vs Rust); this is the first intra-method
  pair in the same Python module.
- **"feature-RPC absent" cluster** (BUG-25 submitheader, BUG-26
  generateblock, BUG-27 generatetodescriptor) — three Core mining RPCs
  with zero ouroboros analogue. Functional-test compat gap.

**Top three findings:**

1. **BUG-21 (P0-CDIV) — BIP22ValidationResult is an English-to-token
   translator with catch-all `"rejected"`.** The most-important field
   of the BIP-22 submitblock contract is structurally wrong. Core's
   `BlockValidationState::GetRejectReason()` propagates the consensus
   token verbatim from the original `state.Invalid` call site;
   ouroboros's `bip22_result_string` does substring matching on the
   English error text bubbled up from validation, with a final
   `return "rejected"` for any unmatched message. Every fix-wave that
   changes a Rust/Python validation error message risks reclassifying
   a previously-canonical reject as `"rejected"`. Cross-impl test
   harnesses that fingerprint the reject token see ouroboros as a
   noise source.

2. **BUG-7 (P0-CDIV carry-forward from W154 BUG-3) — `get_next_bits`
   / `get_next_block_version` dead-helpers; tests explicitly delete the
   methods from the mock node to assert wrong behaviour as a regression
   contract.** Every 2016-block adjustment boundary on mainnet, the
   template emits the previous epoch's bits → the assembled block has
   the wrong `nBits` → permanent `bad-diffbits` reject. The Rust
   `get_next_work_required` pyfunction AND the Python
   `compute_block_version` exist and work correctly; the wiring layer
   between `RPCServer.node` and them is the gap.

3. **BUG-1 + BUG-2 + BUG-3 + BUG-16 + BUG-19 cluster — five separate
   BIP-22-spec-mandatory mechanisms absent in one wave.** `mode`
   dispatch (BUG-1), client `rules` enforcement (BUG-2), longpoll loop
   + `longpollid` field (BUG-3 + BUG-16), and 2-argument submitblock
   signature (BUG-19) are all spec-required and all absent. Together
   they make ouroboros a non-conformant BIP-22 implementation at the
   protocol-surface level.

**Cross-wave priority queue input (for next fix wave selection):**
- **BUG-21 (3-4 LOC root cause; ~50 LOC fix)** — propagate the
  Rust `BlockValidationError` enum variant name as a Python string
  attribute on the exception, then read THAT in `bip22_result_string`
  instead of `str(e)`. Closes the English-translator pattern at the
  point of error origin; downstream callers stop being lossy.
- **BUG-7 (~10 LOC fix)** — add `def get_next_bits(self, height)` and
  `def get_next_block_version(self, height)` to `BitcoinNode`, each
  calling the existing Rust pyfunction / `consensus.compute_block_version`
  helper. Wires the test-asserted dead-helper.
- **BUG-29 (1-line fix)** — `halving_interval =
  getattr(self.node.network_config, "SUBSIDY_HALVING_INTERVAL", 210_000)`
  in GBT, mirroring the `generatetoaddress` line. Removes one prong
  of the N-pipeline drift.
- **BUG-16 (~30 LOC fix)** — add a `nTransactionsUpdated` counter on
  `Mempool`, emit `longpollid = best_hash.hex() + str(counter)` in
  GBT. The waitTipChanged loop (BUG-3) can land later; the field is
  the contract.
- **BUG-19 (1-line fix)** — change signature to
  `rpc_submitblock(self, hexdata: str, dummy: str | None = None)`.
