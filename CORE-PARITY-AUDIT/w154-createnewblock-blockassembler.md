# W154 — CreateNewBlock + BlockAssembler + block template construction (ouroboros)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addPackageTxs`
(→ `addChunks` post-cluster mempool), `AddToBlock`, `TestChunkBlockLimits`,
`TestChunkTransactions`, `GetMinimumTime` (BIP-94 timewarp),
`UpdateTime`, `GenerateCoinbaseCommitment` (BIP-141), `BlockMerkleRoot`,
`BlockWitnessMerkleRoot`, `RegenerateCommitments`, `CoinbaseTx`,
`include_dummy_extranonce`, `IncrementExtraNonce`,
`coinbase_output_max_additional_sigops`, the GBT (`getblocktemplate`) +
`generateblock` + `generatetoaddress` + `generatetodescriptor` +
`submitblock` + `getmininginfo` + `prioritisetransaction` RPC family,
`MAX_BLOCK_WEIGHT=4_000_000`, `WITNESS_SCALE_FACTOR=4`,
`DEFAULT_BLOCK_MAX_WEIGHT`, `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`,
`MINIMUM_BLOCK_RESERVED_WEIGHT=2000`,
`MAX_CONSECUTIVE_FAILURES=1000`, `BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.h:60-123` — `class BlockAssembler` /
  `Options{nBlockMaxWeight, block_reserved_weight, …}` /
  `CreateNewBlock` / `AddToBlock` / `addChunks` /
  `TestChunkBlockLimits` / `TestChunkTransactions`.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime(pindexPrev,
  difficulty_adjustment_interval)` — at adjustment-interval boundary,
  clamps `min_time = max(MTP+1, prev_block_time - MAX_TIMEWARP)`
  (BIP-94 timewarp rule, applies on all networks for future-activation
  safety).
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime(pblock, params,
  pindexPrev)` — sets `nTime = max(GetMinimumTime, now)`, recomputes
  `nBits` via `GetNextWorkRequired` on `fPowAllowMinDifficultyBlocks`
  chains.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`:
  erase old witness-commitment output, regenerate via
  `GenerateCoinbaseCommitment`, recompute `hashMerkleRoot`. Called from
  `generateblock` after the caller pre-pends extra txs.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`: applies
  `DEFAULT_BLOCK_RESERVED_WEIGHT` default and clamps reserved weight
  between `MINIMUM_BLOCK_RESERVED_WEIGHT=2000` and `MAX_BLOCK_WEIGHT`.
- `bitcoin-core/src/node/miner.cpp:98-109` — `ApplyArgsManOptions` —
  `-blockmaxweight`, `-blockmintxfee`, `-printpriority`,
  `-blockreservedweight`.
- `bitcoin-core/src/node/miner.cpp:111-237` — `BlockAssembler::CreateNewBlock`:
  resetBlock → reserve coinbase as vtx[0] placeholder → `nVersion =
  ComputeBlockVersion(pindexPrev)` → `m_lock_time_cutoff =
  pindexPrev->GetMedianTimePast()` → `addChunks` (selects mempool
  packages by ancestor feerate) → build coinbase
  (`nSequence=MAX_SEQUENCE_NONFINAL=0xFFFFFFFE`, `nLockTime=nHeight-1`,
  `scriptSig = CScript() << nHeight`, optionally `<< OP_0` extranonce)
  → `GenerateCoinbaseCommitment` → `UpdateTime` →
  `nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams)` →
  `TestBlockValidity(check_pow=false, check_merkle_root=false)`.
- `bitcoin-core/src/node/miner.cpp:239-247` — `TestChunkBlockLimits`:
  `nBlockWeight + chunk.size >= nBlockMaxWeight` OR
  `nBlockSigOpsCost + chunk_sigops >= MAX_BLOCK_SIGOPS_COST` → false.
- `bitcoin-core/src/node/miner.cpp:262-277` — `AddToBlock` increments
  `nBlockWeight += entry.GetTxWeight()`, `nFees += entry.GetFee()`.
- `bitcoin-core/src/node/miner.cpp:279-330` — `addChunks` consumes
  cluster-mempool chunks via `GetBlockBuilderChunk`/`SkipBuilderChunk`
  /`IncludeBuilderChunk`; respects `blockMinFeeRate` and the
  `MAX_CONSECUTIVE_FAILURES=1000` + `BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000`
  early-exit.
- `bitcoin-core/src/validation.cpp:3997-4019` — `ChainstateManager::GenerateCoinbaseCommitment`:
  if `GetWitnessCommitmentIndex` returns `NO_WITNESS_COMMITMENT`, append
  the OP_RETURN 0x24 0xaa21a9ed + 32-byte SHA256d(witness_root||nonce)
  output. Then `UpdateUncommittedBlockStructures` sets the coinbase
  witness stack to one 32-zero-byte element.
- `bitcoin-core/src/rpc/mining.cpp:164-182` — `generateBlocks` mines via
  `createNewBlock({.coinbase_output_script, .include_dummy_extranonce =
  true})` — INCLUDES mempool txs.
- `bitcoin-core/src/rpc/mining.cpp:305-414` — `generateblock` RPC:
  builds template with `use_mempool=false`, splices in caller-supplied
  txs, calls `RegenerateCommitments`, validates via `TestBlockValidity`.
- `bitcoin-core/src/rpc/mining.cpp:416-497` — `getmininginfo`:
  `currentblockweight` / `currentblocktx` from
  `BlockAssembler::m_last_block_*`, `blockmintxfee` from
  `Options.blockMinFeeRate`, `next.{bits,target,difficulty}` from
  `NextEmptyBlockIndex` (not tip!), `signet_challenge` when on signet.
- `bitcoin-core/src/rpc/mining.cpp:712-1033` — `getblocktemplate`: IBD
  guard (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`), peer-count guard
  (`RPC_CLIENT_NOT_CONNECTED`), `mode` dispatch ("proposal" runs
  `getblocktemplate_proposal`, "template" is the default), `longpollid`
  (`hashBestChain + nTransactionsUpdatedLast`), `setClientRules` MUST
  contain "segwit" on post-segwit chains and "signet" on signet,
  `vbavailable` populated from `GBTStatus.signalling`/`locked_in`,
  `coinbasetxn` carries the full coinbase template (`data` field with
  serialized hex), `signet_challenge` for signet, `sigoplimit` /
  `sizelimit` divided by `WITNESS_SCALE_FACTOR` for pre-segwit.
- `bitcoin-core/src/rpc/mining.cpp:1056-1116` — `submitblock`: calls
  `chainman.UpdateUncommittedBlockStructures(block, pindex)` BEFORE
  `ProcessNewBlock`; returns `"duplicate-invalid"` for previously-failed
  blocks (`pindex->nStatus & BLOCK_FAILED_VALID`); error reasons via
  `submitblock_StateCatcher`.
- `bitcoin-core/src/policy/policy.h:25-34` —
  `DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT}`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT{8000}`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT{2000}`.
- `bitcoin-core/src/consensus/consensus.h:13-26` —
  `MAX_BLOCK_SERIALIZED_SIZE=4_000_000`, `MAX_BLOCK_WEIGHT=4_000_000`,
  `WITNESS_SCALE_FACTOR=4`, `MAX_BLOCK_SIGOPS_COST=80_000`,
  `COINBASE_MATURITY=100`.

**Files audited**
- `src/ouroboros/rpc.py:4798-4839` — `rpc_getmininginfo`.
- `src/ouroboros/rpc.py:4841-5332` — `rpc_getblocktemplate` (THE
  template assembler; ~500 LOC monolith of selection + sigops + merkle).
- `src/ouroboros/rpc.py:6067-6171` — `rpc_submitblock` (best-chain
  fast path + side-branch Pattern X/Y reorg shim).
- `src/ouroboros/rpc.py:6173-6232` — `rpc_submitblockbatch`.
- `src/ouroboros/rpc.py:8654-8703` — `rpc_prioritisetransaction`.
- `src/ouroboros/rpc.py:8705-8726` — `rpc_getprioritisedtransactions`.
- `src/ouroboros/rpc.py:8728-8949` — `rpc_generatetoaddress` (mines
  empty regtest blocks; bespoke hand-rolled coinbase).
- `src/ouroboros/rpc.py:288-414` — `accept_block` unified pipeline
  (Step 1 = BIP-34 byte-prefix; Step 2 = Rust validate; Step 3 = Python
  validator; Step 4 = connect).
- `src/ouroboros/mempool.py:1627`, `1728-1737` — `snapshot()` for GBT
  isolation.
- `src/ouroboros/mempool.py:1839-1849` — `clear_prioritisation`
  (`removeForBlock` clears delta, but comment also names
  `removeConflicts` — see W153 BUG-8 cross-cite).
- `src/ouroboros/mempool.py:3163-3211` — `remove_block_transactions`.
- `src/ouroboros/validation.py:97-118` — `_encode_bip34_height`
  (canonical CScript<<nHeight). Disagrees with `generatetoaddress` —
  BUG-12.
- `src/ouroboros/validation.py:271-313` — `_count_legacy_sigops`.
- `src/ouroboros/validation.py:457-481` — `_count_witness_sigops`.
- `src/ouroboros/validation.py:483-510` — `_get_p2sh_sigops`.
- `src/ouroboros/consensus.py:85-86, 235-450` —
  `VERSIONBITS_TOP_BITS = 0x20000000`, `BIP9_DEPLOYMENTS` per-network.
- `src/ouroboros/consensus.py:763-816` — `compute_block_version()`
  EXISTS but never wired (BUG-3 below).
- `ferrous-utils/sync/src/lib.rs:401-447` — Rust
  `get_next_work_required` Python-binding EXISTS but never wired
  (BUG-3 below).
- `src/ouroboros/tests/test_w108_gbt.py` — 30 catalogued G-bugs (60
  tests), several of which assert the WRONG behaviour as a regression
  contract. The audit cross-references those numerically.
- `src/ouroboros/tests/test_w123_mining_gbt.py` — wave-123 mining
  test file (re-confirms get_next_bits / get_next_block_version
  deliberately absent from mock — line 85-86).

---

## Gate matrix (40 sub-gates / 16 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GBT IBD guard | G1: refuse with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` on non-test chain in IBD | **BUG-1 (P0-CDIV)** — no IBD check; cross-cite W148 BUG-16 `is_synced` hardcoded `false` since W113; GBT always serves a template even with no chain |
| 2 | GBT peer-count guard | G2: refuse with `RPC_CLIENT_NOT_CONNECTED` when `connman.GetNodeCount(Both)==0` on non-test chain | **BUG-2 (P0-CDIV)** — never checks peer count; mainnet operator with zero peers gets a phantom template |
| 3 | GBT proposal mode | G3: `mode=="proposal"` validates supplied hex and returns reject string, not a fresh template | **BUG-4 (P0-CDIV)** — `template_request` parameter is never read; the entire argument is dead |
| 3 | … | G4: `mode` of unknown value rejected with `RPC_INVALID_PARAMETER` | BUG-4 cross-cite |
| 3 | … | G5: `setClientRules` MUST contain "segwit" on post-segwit chain | **BUG-5 (P1)** — never enforced |
| 3 | … | G6: `setClientRules` MUST contain "signet" on signet | BUG-5 cross-cite |
| 4 | Long-polling | G7: GBT response includes `longpollid` | **BUG-6 (P1)** — `longpollid` field absent from response |
| 4 | … | G8: `longpollid` param blocks until tip change or mempool update | BUG-6 cross-cite — no waitTipChanged equivalent |
| 5 | Mintime / BIP-94 timewarp | G9: `mintime = max(MTP+1, prev_block_time - MAX_TIMEWARP)` at difficulty-adjustment-interval boundaries | **BUG-7 (P0-CDIV)** — ouroboros always emits `mintime = MTP + 1`; MAX_TIMEWARP clamp absent; tests/test_w108_gbt.py G9 explicitly documents the bug |
| 6 | `nBits` derivation | G10: `bits = GetNextWorkRequired(pindexPrev, pblock, params)` for the NEXT block | **BUG-3 (P0-CDIV)** — `node.get_next_bits` is never defined; `rpc_getblocktemplate` line 5223 calls `getattr(self.node, "get_next_bits", None)` which is **always None**, so the fallback `bits = best_block.bits` runs. At every difficulty-adjustment boundary (every 2016 blocks on mainnet, every 2016 on signet/testnet4) the template emits the WRONG nBits and the assembled block has the wrong target → permanent doom |
| 7 | Block version (BIP-9 / ComputeBlockVersion) | G11: `version = ComputeBlockVersion(pindexPrev, params)` honouring STARTED+LOCKED_IN deployments | **BUG-3 cross-cite** — `node.get_next_block_version` similarly absent; fallback `block_version = best_block.version \| 0x20000000` ignores per-network BIP9_DEPLOYMENTS. `consensus.compute_block_version` EXISTS in consensus.py:763-816 with full BIP-9 logic but no caller |
| 8 | Coinbase scriptSig | G12: `scriptSig = CScript() << nHeight` (canonical BIP-34 byte-encoding) | **BUG-12 (P0-CDIV)** — `rpc_generatetoaddress` hand-rolls a NON-canonical encoder (`_st.pack("<q", h)` + trim trailing zeros + length-prefix) that disagrees with `_encode_bip34_height` for heights 1..16. Validator uses `_encode_bip34_height`. Outcome: generatetoaddress on regtest at heights 1..16 produces blocks the validator immediately rejects with `bad-cb-height` — TWO-PIPELINE GUARD |
| 8 | … | G13: scriptSig length 2..100 (consensus rule) | PASS in `rpc_generatetoaddress` for h>=17 (length-prefix 0x01 + 1 byte = 2). For h=1..16 the bogus encoder still passes the 2..100 length gate but fails BIP-34 (see G12) |
| 8 | … | G14: coinbase `nSequence = 0xFFFFFFFE` (`MAX_SEQUENCE_NONFINAL`) | **BUG-13 (P0-CDIV)** — `rpc_generatetoaddress` line 8783 uses `0xFFFFFFFF` (SEQUENCE_FINAL), which disables nLockTime enforcement; tests/test_w108_gbt.py G25 documents this; GBT response coinbasetxn.sequence is 0xFFFFFFFE (correct) — divergence between generator and template |
| 8 | … | G15: coinbase `nLockTime = nHeight - 1` (miner.cpp:196) | **BUG-13 cross-cite** — `rpc_generatetoaddress` line 8822 packs locktime=0 unconditionally; GBT coinbasetxn.locktime is correct (next_height-1). Same two-pipeline divergence |
| 9 | Witness commitment | G16: `OP_RETURN 0x24 0xaa21a9ed` + `SHA256d(witness_root\|\|32-zero-nonce)` | PASS (rpc.py:5199-5207; generatetoaddress same) |
| 9 | … | G17: commitment placed in LAST output of coinbase | PARTIAL — generatetoaddress places it at the 2nd of 2 outputs (last). GBT template emits `default_witness_commitment` as a hex script for the miner to insert; ouroboros does not specify where to insert it (Core's miner is expected to append). Acceptable |
| 9 | … | G18: coinbase witness stack = single 32-byte zero element | PASS (witness=[bytes(32)] in generatetoaddress) |
| 9 | … | G19: `UpdateUncommittedBlockStructures` called on `submitblock` to fix witness when prev≥segwit and block has no witness | **BUG-14 (P1)** — `rpc_submitblock` does NOT call any equivalent of `UpdateUncommittedBlockStructures`; tests/test_w108_gbt.py G18 documents this; Core mining.cpp:1086-1090 patches the witness commitment IF the block is missing it on segwit-active prev |
| 10 | Block weight / size limits | G20: `MAX_BLOCK_WEIGHT = 4_000_000` | PASS (rpc.py:4889) |
| 10 | … | G21: `WITNESS_SCALE_FACTOR = 4` | PASS (used at rpc.py:5102, 5118) |
| 10 | … | G22: `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000` carved out of weight budget | PASS (rpc.py:4891) |
| 10 | … | G23: `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000` floor for `-blockreservedweight` | **BUG-15 (P1)** — no clamp constant; no `-blockreservedweight` operator knob; the 8000 default is hardcoded |
| 10 | … | G24: `-blockmaxweight` operator knob | **BUG-16 (P1)** — no `-blockmaxweight` CLI flag; MAX_BLOCK_WEIGHT used directly. Operators cannot tune block size for stratum-pool ergonomics |
| 11 | Package / ancestor selection | G25: select by ancestor / chunk feerate (cluster mempool) | PASS (greedy ancestor-feerate at rpc.py:5009-5028; pre-cluster-mempool approximation) |
| 11 | … | G26: `MAX_CONSECUTIVE_FAILURES=1000` + `BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000` early-exit | PASS (rpc.py:4892-4895, 5039) — but BUG-9 below shows the counter doesn't update for sigops-skip path |
| 11 | … | G27: `TestChunkBlockLimits` rejects per-CHUNK not per-tx (an atomic chunk that exceeds either weight or sigops is skipped wholesale) | **BUG-8 (P0-CDIV)** — ouroboros's batch loop at rpc.py:5085 processes batch members INDIVIDUALLY; if any member's sigops would overflow, that member is `continue`'d but the rest of the batch is still appended → batch with broken parent-child dependency graph |
| 11 | … | G28: missing prev_utxo on an input causes the tx to be SKIPPED (Core would reject ATMP and never enter the mempool) | **BUG-9 (P0-CDIV)** — rpc.py:5113 `continue`s the INPUT loop on missing prev_utxo, then proceeds to compare `tx_sigops_cost` (now UNDER-COUNTED) against the gate and emits the tx into the template. Witness sigops for unresolvable parents are silently omitted |
| 11 | … | G29: `removeConflicts` evicts mempool txs that conflict with a new block-included tx | **BUG-10 (P0-CDIV) — cross-cite W153 BUG-8** — `remove_block_transactions` only removes txs by their own txid; it does NOT walk the new block's tx outputs to evict mempool txs that spent the SAME prev_outpoint as a block-included tx. Comment at mempool.py:1844 names `removeConflicts (txmempool.cpp:398)` but the function is absent. Next GBT call would include those stale conflicting txs → assembled template is DOOMED |
| 12 | Coinbase value | G30: `coinbase_value = nFees + GetBlockSubsidy(nHeight, params)` with per-network `nSubsidyHalvingInterval` | **BUG-11 (P0-CDIV) — cross-cite W145 BUG-1 fleet pattern** — rpc.py:5211 hardcodes `next_height // 210_000` for GBT (mainnet halving interval). On regtest (150) GBT emits 50 BTC at height=150 where Core would emit 25 BTC; the operator-mined block then has wrong `coinbasevalue` and gets rejected with `bad-cb-amount` (or worse — accepted by an unaware regtest peer fleet). tests/test_w108_gbt.py G27 explicitly documents the bug and asserts the wrong value as the regression contract |
| 12 | … | G31: regtest generatetoaddress uses RegtestConfig.SUBSIDY_HALVING_INTERVAL (150) | PASS for generatetoaddress (rpc.py:8767). Asymmetry vs GBT (G30) — see BUG-11 |
| 13 | curtime / UpdateTime | G32: `curtime = max(GetMinimumTime(pindexPrev, …), now)` (UpdateTime semantics) | PARTIAL — rpc.py:5259 uses `max(MTP+1, now)`; missing BIP-94 clamp at adjustment boundary (BUG-7) |
| 13 | … | G33: testnet/signet `fPowAllowMinDifficultyBlocks` reruns `GetNextWorkRequired` after `nTime` updates | **BUG-3 cross-cite** — nBits never recomputed; the testnet/signet "0x207FFFFF when last block >20min ago" rule cannot fire |
| 14 | `getmininginfo` shape | G34: `bits` / `target` / `difficulty` for tip | PASS (rpc.py:4811-4820) |
| 14 | … | G35: `currentblockweight` / `currentblocktx` emitted when a block was ever assembled (BlockAssembler::m_last_block_weight statics) | **BUG-17 (P1)** — fields ABSENT from getmininginfo response (no static accumulator); tests/test_w108_gbt.py G15 documents the absence |
| 14 | … | G36: `next.bits` / `next.target` / `next.difficulty` computed via `NextEmptyBlockIndex` (not tip!) | **BUG-3 cross-cite** — `next.bits = bits_hex` (same as tip; rpc.py:4834). Wrong at adjustment boundary |
| 14 | … | G37: `blockmintxfee` from `BlockAssembler::Options.blockMinFeeRate` (configurable via `-blockmintxfee`) | **BUG-18 (P1)** — rpc.py:4828 hardcodes `0.00001000`; no `-blockmintxfee` operator knob; tests/test_w108_gbt.py G14 documents this |
| 14 | … | G38: `networkhashps` from getnetworkhashps default window | **BUG-19 (P2)** — rpc.py:4829 hardcodes `networkhashps: 0` despite `rpc_getnetworkhashps` existing at rpc.py:8600 and being correct |
| 14 | … | G39: `signet_challenge` emitted for signet network | **BUG-20 (P1)** — never emitted in either getmininginfo or GBT; tests/test_w108_gbt.py G13 documents this for GBT |
| 14 | … | G40: `warnings` aggregates warning sources (`GetWarningsForRpc(deprecated=...)`) | **BUG-19 cross-cite** — hardcoded `""` |

---

## BUG-1 (P0-CDIV) — `getblocktemplate` ignores IBD state; emits a template at any tip

**Severity:** P0-CDIV. Core's `getblocktemplate`
(`bitcoin-core/src/rpc/mining.cpp:712`) checks
`chainman.IsInitialBlockDownload()` (after the rules/signet validation
block) and throws `RPC_CLIENT_IN_INITIAL_DOWNLOAD` to refuse template
generation. The rationale: a miner mining on top of an unsynced or
partially-known tip would burn hashrate on a block that joins a stale
chain.

ouroboros's `rpc_getblocktemplate` (`src/ouroboros/rpc.py:4841-5332`)
runs the entire selection + commitment pipeline regardless of IBD
state. The body never references `node.is_synced`, `is_initial_block_download`,
`sync_manager`, `ibd_active`, or any equivalent gate. Cross-cite W148
BUG-16 — `is_synced` was reported there as hardcoded `false` since
W113 (~6 weeks ago); even if a working IBD flag existed, this RPC
wouldn't consult it.

**File:** `src/ouroboros/rpc.py:4841-5332` (entire body, no IBD check).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:712-770`
(`getblocktemplate` IBD check + signet rule check).

**Impact:**
- Mining pool / stratum proxy that connects during IBD gets a template
  rooted at the partial-sync tip — the assembled block joins a stale
  chain or wastes hashrate.
- Cross-cite with W148 BUG-16 → the very flag that would catch this is
  itself wrongly latched.
- Cross-cite with W148 BUG-17 → `NODE_NETWORK_LIMITED` plumb-gate-then-flip
  → the same "plumb but don't wire" pattern is fleet-wide on ouroboros.

tests/test_w108_gbt.py:112 documents this exact bug ("BUG: GBT does not
refuse while node is in IBD") and asserts that the wrong (passthrough)
behaviour is preserved as a regression contract.

---

## BUG-2 (P0-CDIV) — `getblocktemplate` ignores peer count; emits template with 0 peers

**Severity:** P0-CDIV. Core (`bitcoin-core/src/rpc/mining.cpp:725-740`)
throws `RPC_CLIENT_NOT_CONNECTED` when
`connman.GetNodeCount(ConnectionDirection::Both) == 0` on a non-test
chain. Rationale: a node with no peers cannot reliably know the tip
and any mined block extends a possibly-stale chain.

ouroboros never queries `node.peer_count`, `peer_manager.peer_count`,
or any equivalent (a grep on `peer_count`/`get_peer_count` over
rpc.py:4841-5332 returns zero hits inside the GBT body). Mining on a
disconnected mainnet node silently produces templates against the
local tip.

**File:** `src/ouroboros/rpc.py:4841-5332`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:725-740`.

**Impact:** same shape as BUG-1; companion gate that Core uses as
belt-and-suspenders. tests/test_w108_gbt.py:131 documents.

---

## BUG-3 (P0-CDIV) — `get_next_bits` / `get_next_block_version` dead-helper; ComputeBlockVersion + GetNextWorkRequired never wired

**Severity:** P0-CDIV. The GBT template embeds two consensus-critical
header fields:

- `nBits` — `GetNextWorkRequired(pindexPrev, pblock, params)` — wraps
  difficulty adjustment every 2016 blocks (mainnet) /
  `fPowAllowMinDifficultyBlocks` on testnet/signet.
- `nVersion` — `ComputeBlockVersion(pindexPrev, params)` honouring
  BIP-9 deployments in STARTED + LOCKED_IN states.

ouroboros's GBT body at `rpc.py:5223` does:
```python
_next_bits = getattr(self.node, "get_next_bits", None)
if callable(_next_bits):
    _bits_val = _next_bits(best_height)
    bits = _bits_val if isinstance(_bits_val, int) else best_block.bits
else:
    bits = best_block.bits
```
and at `rpc.py:5246`:
```python
_next_version_fn = getattr(self.node, "get_next_block_version", None)
if callable(_next_version_fn):
    _ver_val = _next_version_fn(best_height)
    block_version = _ver_val if isinstance(_ver_val, int) else (best_block.version | 0x20000000)
else:
    block_version = (best_block.version | 0x20000000)
```

A grep of the whole codebase shows `def get_next_bits` and `def
get_next_block_version` are **never defined** on `Node`, on any class
in `node.py`, or anywhere else. The fallback path ALWAYS runs.

Yet the supporting infrastructure is in place:
- `consensus.py:763-816` defines `compute_block_version(height,
  network, block_versions, block_mtps)` with full BIP-9 deployment
  logic (taproot, testdummy per-network).
- `ferrous-utils/sync/src/lib.rs:401-447` exposes
  `get_next_work_required(last_height, last_bits, last_timestamp,
  new_block_time, network, ancestors)` as a pyfunction.
- Two pipelines exist for difficulty calc
  (`ferrous-utils/sync/src/validate/header.rs:168` + `difficulty.rs:53`
  + the lib.rs pyfunction wrapper at line 401), all unwired to GBT.

The wiring is missing in the bridge layer between
`RPCServer.node` and the consensus/Rust modules. **Pure "plumb-but-don't-wire"
dead-helper, fleet pattern, 6th+ distinct ouroboros instance.**

Observable consequences:
1. **Every difficulty-adjustment boundary** (every 2016 blocks on
   mainnet, every 2016 on signet/testnet4) the template emits the
   PREVIOUS epoch's bits. A miner who solves that template produces a
   block with the wrong `nBits` → `bad-diffbits` reject on `submitblock`
   and on the P2P network. Permanent failure mode every 2016 blocks
   (~2 weeks on mainnet).
2. **Testnet3/signet `fPowAllowMinDifficultyBlocks`** — Core reruns
   `GetNextWorkRequired` after `nTime` is bumped via `UpdateTime`
   (miner.cpp:60-62). ouroboros never recomputes, so on testnet3 the
   "0x207FFFFF when 20+ minutes since last block" rule cannot trigger
   in a template.
3. **BIP-9 signalling broken** — if a STARTED deployment activates
   between GBT calls, miners never signal the new bit. Future soft-fork
   activations would be effectively undeployable through ouroboros
   miners.
4. **getmininginfo.next.bits** (rpc.py:4834) similarly uses tip bits,
   so monitoring tools see the wrong "next" target at boundaries.

tests/test_w108_gbt.py:318 EXPLICITLY documents the bug pattern with
the class name `TestG10DeadHelperBitsVersion` and asserts the WRONG
behaviour as a regression contract.

**File:** `src/ouroboros/rpc.py:5219-5251` (GBT fallback path);
`src/ouroboros/consensus.py:763-816`
(`compute_block_version` defined-but-uncalled);
`ferrous-utils/sync/src/lib.rs:401-447` (`get_next_work_required` Rust
function defined-but-uncalled).

**Core ref:** `bitcoin-core/src/node/miner.cpp:140, 220`
(`ComputeBlockVersion` + `GetNextWorkRequired` called inside
`CreateNewBlock`).

**Impact:** P0-CDIV — every adjustment boundary the template is
DOOMED. Probably the single highest-severity bug in this wave.

---

## BUG-4 (P0-CDIV) — `template_request` argument entirely ignored (proposal mode, mode validation, longpollid, client rules)

**Severity:** P0-CDIV. ouroboros's
`async def rpc_getblocktemplate(self, template_request: dict = None)`
declares the parameter and ignores it from the first line onward. A
grep of the body shows `template_request` is read zero times after
the function signature. Consequences:

1. **`mode == "proposal"`** — BIP-23 specifies that a client may
   submit a candidate block hex for validation; the server replies
   with a reject reason string or null. Core implements this via
   `getblocktemplate_proposal`. ouroboros treats every call as the
   default `mode == "template"` and emits a fresh template — silently
   discarding the candidate.
2. **Unknown `mode`** — Core throws `RPC_INVALID_PARAMETER "Invalid
   mode"`. ouroboros emits a template.
3. **`rules`** — Core enforces that the client declared `"segwit"` (and
   `"signet"` on signet) — refuses with `RPC_INVALID_PARAMETER` if
   absent. ouroboros never reads.
4. **`longpollid`** — Core's wait-tip-changed loop blocks until tip
   change or mempool churn; ouroboros returns instantly.
5. **`capabilities`** — Core respects `coinbasetxn` capability (returns
   coinbase as `coinbasetxn`) vs default `coinbasevalue`; ouroboros
   returns BOTH unconditionally (BUG-23 below).

This is the same "dead-argument" pattern as W138 ChainstateManager
methods (fleet-wide). The capability list advertises `["proposal"]` at
rpc.py:5267 — **false advertising** since proposal mode is not actually
implemented.

**File:** `src/ouroboros/rpc.py:4841` (function signature),
4841-5332 (body, never reads `template_request`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:712-770` (mode dispatch,
longpoll loop, rules enforcement).

**Impact:**
- BIP-23 proposal-mode mining pools (rare but exist) silently get
  wrong responses.
- Stratum daemons relying on longpoll backpressure poll-spam ouroboros.
- The advertised `["proposal"]` capability is a lie — tests catch
  failures here as "no error raised" not as "expected error".

tests/test_w108_gbt.py:149 documents proposal-mode bug;
test_w108_gbt.py:223 documents longpollid absent;
test_w108_gbt.py:607 documents segwit-rule unenforced.

---

## BUG-5 (P1) — Client rules not enforced (segwit / signet)

**Severity:** P1 (sub-component of BUG-4 but with distinct visibility).
Bitcoin Core unconditionally throws when `setClientRules` lacks
`"segwit"` on a post-segwit chain (mining.cpp:855-857) and when
`setClientRules` lacks `"signet"` on signet (mining.cpp:849-852).

ouroboros's reply DOES advertise `["csv", "!segwit", "taproot"]` in
the response's `rules` field — that's the SERVER side declaring what
the assembled block requires. But it never validates the CLIENT's
declared rules. A pre-segwit client (modern stratum proxies all
declare segwit, but a regression that silently dropped the rule from a
config would not be caught) would get a post-segwit template and
produce blocks the client cannot reason about.

**File:** `src/ouroboros/rpc.py:4841-5332`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-857`.

**Impact:** silent acceptance of stale/broken miners; no signet rule
enforcement on signet templates (different chain-of-trust).

---

## BUG-6 (P1) — `longpollid` absent from GBT response

**Severity:** P1. BIP-22 specifies `longpollid` as a token (usually
`hashBestChain + nTransactionsUpdated`) that the client passes back to
block until tip change or mempool update. ouroboros never emits the
field (the returned dict at rpc.py:5294-5332 has no `longpollid` key).
Consequence: clients fall back to polling.

**File:** `src/ouroboros/rpc.py:5294-5332` (response dict).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1002`.

**Impact:** miners poll at fixed intervals (typically every 1-5s)
instead of being notified on tip change; wasted RPC round-trips;
slightly elevated stale-block rate during tip churn.

---

## BUG-7 (P0-CDIV) — `mintime` ignores BIP-94 timewarp clamp at difficulty-adjustment boundaries

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`bitcoin-core/src/node/miner.cpp:36-47`) computes:
```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
const int height{pindexPrev->nHeight + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```
BIP-94 (testnet4 + future-activation safety) requires that at the
difficulty-adjustment boundary, the new block's timestamp cannot
precede the previous block's timestamp by more than `MAX_TIMEWARP`
(600 seconds).

ouroboros at `rpc.py:5258-5259`:
```python
mtp_plus_one = block_mtp + 1
curtime = max(mtp_plus_one, int(_time.time()))
```
and at `rpc.py:5325`: `"mintime": mtp_plus_one`.

The clamp `prev_block_time - MAX_TIMEWARP` is NOT applied. The
validator at `validation.py:1002` correctly enforces BIP-94 on inbound
blocks, so:
- On testnet4: a block whose `mintime` falls below the timewarp clamp
  is emitted; a miner who uses `mintime` as `nTime` produces a block
  rejected by the same node (`time-timewarp-attack` from
  validation.py:996-1002). **TWO-PIPELINE GUARD** — assembly and
  validation disagree on the floor.
- On mainnet: BIP-94 is not yet a consensus rule but the future-safety
  rationale (Core applies it on all networks) means ouroboros will
  also break on mainnet when BIP-94 activates.

tests/test_w108_gbt.py:299 documents the bug explicitly and pins the
broken behaviour as a regression contract:
> "mintime is MTP+1 only — BIP-94 timewarp boundary not applied"

**File:** `src/ouroboros/rpc.py:5258, 5325`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Impact:** testnet4 mining produces invalid blocks at every
adjustment boundary if the prev_block_time was much earlier than now.
Mainnet at BIP-94 activation will see the same.

---

## BUG-8 (P0-CDIV) — Sigops-skip mid-batch breaks parent-child dependency contract

**Severity:** P0-CDIV. Core's `addChunks` is **package-atomic** — a
chunk (cluster) either fits wholesale or is rejected wholesale via
`TestChunkBlockLimits` + `m_mempool->SkipBuilderChunk`. Ouroboros's
GBT body decomposes each ancestor batch and applies the sigops gate
PER MEMBER:

```python
# rpc.py:5085  for t in batch:
#   ... compute tx_sigops_cost ...
if total_sigops + tx_sigops_cost >= MAX_BLOCK_SIGOPS_COST:
    continue  # tx would push block over sigops limit — skip
```

When this `continue` fires on a parent that's a member of a
multi-element batch, the children — which depend on the parent in the
mempool — proceed to `txs.append(...)` and `txid_to_template_index[t]
= len(txs)`. But the child's `depends` array at rpc.py:5143-5147 walks
its own inputs and ONLY adds an index if `inp.prev_txid` is already in
`txid_to_template_index`. Since the parent was skipped, the parent's
in-template index is missing, so the child's `depends` is incomplete
or empty.

Outcome: a miner who concatenates the template txs in order produces a
block that references an UNINCLUDED parent → the assembled block is
INVALID (the child's input has no provider) → `submitblock` returns
`bad-txns-inputs-missingorspent`. The selection algorithm has
silently produced a doomed template.

**File:** `src/ouroboros/rpc.py:5085-5167`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:309-326`
(`TestChunkBlockLimits` evaluates the WHOLE chunk; chunk is skipped
atomically on failure).

**Impact:** any block-template construction with a multi-tx cluster
near the sigops budget can emit a broken template. Pattern: "atomic
chunk decomposed to per-tx loop", first ouroboros instance.

Compounding: the `continue` at rpc.py:5133 does NOT increment
`n_consecutive_failed`, so the MAX_CONSECUTIVE_FAILURES early-exit
gate is desynced from the actual selection failures (the counter only
sees locktime-failure and weight-failure, not sigops-failure).

---

## BUG-9 (P0-CDIV) — Missing prev_utxo silently under-counts sigops; tx still included

**Severity:** P0-CDIV. When the GBT selector iterates a candidate
tx's inputs at rpc.py:5105-5128 to count P2SH + witness sigops, the
flow is:

```python
for inp in e.tx.inputs:
    prev_utxo = await asyncio.to_thread(db.get_utxo, inp.prev_txid, inp.prev_vout)
    if prev_utxo is None:
        parent_entry = snap_txs.get(inp.prev_txid)
        if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
            prev_spk = bytes(parent_entry.tx.outputs[inp.prev_vout].script_pubkey)
        else:
            continue   # <-- skips THIS INPUT, not THIS TX
    ...
    tx_sigops_cost += p2sh_sigops * WITNESS_SCALE_FACTOR
    tx_sigops_cost += _count_witness_sigops(witness_spk, inp.witness)
```

The `continue` jumps to the next input. The tx then falls through to
the sigops gate at rpc.py:5132 with an UNDER-COUNTED sigops total
(P2SH + witness sigops for the unresolvable input are omitted). If
the gate passes (which it will if the rest of the inputs don't push
the budget over 80,000), the tx is appended to the template.

Core's path: a tx whose input prev_utxo cannot be resolved would have
been rejected at ATMP (AcceptToMemoryPool checks `inputs.HaveInputs`),
so the case "tx in mempool with unresolved prev_outpoint" cannot arise
in Core. ouroboros's mempool can drift to that state (cross-cite W153
BUG-7/BUG-8 — entire ZMQ tx-event pipeline dead at source, plus
removeConflicts absent), making this code path actually reachable.

**File:** `src/ouroboros/rpc.py:5105-5128`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:126-141`
(`GetP2SHSigOpCount` asserts `!coin.IsSpent()` — Core's invariant).

**Impact:** under-counted sigops can let blocks slip past Core's
`bad-blk-sigops` cap. Combined with the W128 fleet-wide
banman/discouragement bug (8 of 10 impls) the chain-split risk
compounds.

---

## BUG-10 (P0-CDIV) — `removeConflicts` absent → mining a doomed block (cross-cite W153 BUG-8)

**Severity:** P0-CDIV. Bitcoin Core's `CTxMemPool::removeForBlock`
(`bitcoin-core/src/txmempool.cpp:418-430`) calls `removeConflicts`
(`txmempool.cpp:398-417`) — for each tx in the new block, walks each
input prevout, looks up any OTHER mempool tx spending the same prevout,
and evicts that conflicting tx with reason `CONFLICT`.

ouroboros's `remove_block_transactions`
(`src/ouroboros/mempool.py:3163-3211`) only removes mempool txs by
their own txid (`if txid in self.transactions: self.remove_transaction(...)`).
There is no inner loop over each block-tx's inputs to find and evict
conflicting mempool entries. The comment at mempool.py:1844 NAMES
`removeConflicts (txmempool.cpp:398)` but the function body is
missing.

**Consequences for mining:**
1. Block N is connected; tx X (in block N) spends UTXO U.
2. Tx Y (also spending U; conflict with X) was in the mempool.
3. ouroboros's `remove_block_transactions` does NOT see Y (different
   txid), so Y stays in the mempool.
4. Next GBT call selects Y by ancestor feerate; emits Y in the
   template.
5. Y's input is now SPENT in the UTXO set, so `submitblock` rejects
   the assembled block with `bad-txns-inputs-missingorspent`.

The very next mined block is **DOOMED by construction**. This is
explicitly called out by the W153 BUG-8 cross-cite in the parent
memory and is the SAME failure mode here at the mining-template
construction layer.

**File:** `src/ouroboros/mempool.py:1839-1849` (comment names
removeConflicts but function absent); `src/ouroboros/mempool.py:3163-3211`
(`remove_block_transactions` is removeForBlock without removeConflicts).

**Core ref:** `bitcoin-core/src/txmempool.cpp:398-430`
(`removeConflicts` + `removeForBlock`).

**Impact:** **immediate post-block-connect template construction
emits a doomed block whenever there were any RBF/conflict candidates
in the mempool.** Detection delay: 1 mined block. Cross-cite W153
BUG-8 (mempool layer), this BUG-10 (mining layer).

---

## BUG-11 (P0-CDIV) — GBT subsidy hardcodes mainnet halving interval (210_000), ignores regtest=150 + asymmetric vs generatetoaddress

**Severity:** P0-CDIV — cross-cite W145 BUG-1 fleet-wide subsidy
hardcoding pattern (5+ impls). ouroboros's GBT body hardcodes:
```python
# rpc.py:5210-5214
subsidy = 50 * 100_000_000
halvings = next_height // 210_000   # <-- mainnet hardcoded
if halvings < 64:
    subsidy >>= halvings
```

The very next mining RPC, `rpc_generatetoaddress`, is properly
params-aware:
```python
# rpc.py:8766-8769
from ouroboros.config import RegtestConfig
halving_interval = getattr(RegtestConfig, "SUBSIDY_HALVING_INTERVAL", 150)
halvings = next_height // halving_interval
subsidy = (50 * 100_000_000) >> halvings if halvings < 64 else 0
```

So on regtest at height 150 (one halving):
- `generatetoaddress`: subsidy = 25 BTC (correct).
- `getblocktemplate`: subsidy = 50 BTC (wrong by 1 halving), embedded
  into `coinbasevalue`.

Outcome on regtest mining: a miner who reads `coinbasevalue` from GBT
and pays it into the coinbase produces a block with `coinbasevalue =
50 BTC` at h>=150. Validator (which uses the correct interval) rejects
with `bad-cb-amount`. Two-pipeline guard between assembly and
generatetoaddress.

Worse: this is a **THIRD pipeline** (cross-cite W145 BUG-3 rustoshi
"two parallel block_subsidy") — ouroboros has THREE subsidy
calculation sites:
1. `rpc.py:5210-5214` (GBT, hardcoded 210k)
2. `rpc.py:8767-8769` (generatetoaddress, regtest-aware)
3. `rpc.py:9300-9304` (a third one, hardcoded 210k)

The connect-block / validate-block path through the Rust validator
goes through yet another site. **Three-to-five pipeline drift on a
single chainparams field.** Note the W145 audit already flagged this
class as "5 distinct pipelines" for ouroboros.

tests/test_w108_gbt.py:802-822 documents the bug AND asserts the
wrong behaviour as a regression contract:
```python
# Ouroboros: halvings = 150 // 210_000 = 0 → subsidy = 50 BTC (wrong for regtest)
# Correct for regtest: halvings = 150 // 150 = 1 → subsidy = 25 BTC
self.assertEqual(result.get("coinbasevalue"), 50 * 100_000_000,
                 "regtest coinbasevalue at h=150 returns 50 BTC (wrong — should be 25 BTC)")
```

**File:** `src/ouroboros/rpc.py:5210-5214` (GBT subsidy);
`src/ouroboros/rpc.py:8767-8769` (generatetoaddress subsidy);
`src/ouroboros/rpc.py:9300-9304` (third subsidy site).

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy`
(per-network `nSubsidyHalvingInterval`).

**Impact:** regtest miners on a fresh chain past h=150 produce
invalid blocks via GBT but valid blocks via generatetoaddress.
Test-suite divergence; cross-impl divergence vs other hashhog impls
that correctly use 150 on regtest.

---

## BUG-12 (P0-CDIV) — `generatetoaddress` BIP-34 encoder disagrees with validator for heights 1..16

**Severity:** P0-CDIV. The validator (`validation.py:97-118`
`_encode_bip34_height`) implements Core's `CScript() << nHeight`
exactly:
```python
if 1 <= height <= 16:
    return bytes([0x50 + height])  # OP_1..OP_16, single byte
```

`generatetoaddress` (`rpc.py:8773-8777`) hand-rolls a different
encoder:
```python
height_bytes = _st.pack("<q", next_height)
while len(height_bytes) > 1 and height_bytes[-1] == 0:
    height_bytes = height_bytes[:-1]
coinbase_script = bytes([len(height_bytes)]) + height_bytes
```

For height=1:
- Validator expects: `\x51` (1 byte, OP_1).
- generatetoaddress produces: `\x01\x01` (length-prefix + single byte).

The validator at `validation.py:1490-1494` then runs:
```python
expect = _encode_bip34_height(height)   # \x51
n = len(expect)                          # 1
if len(script) < n or script[:n] != expect:
    # raises bad-cb-height
```
`script[:1]` = `\x01`, `expect` = `\x51` → mismatch → reject.

Regtest activates BIP-34 from genesis (`consensus.py:159`
`"bip34": BuriedDeployment("bip34", 1)`), so for ANY regtest height
in `{1..16}` the generatetoaddress-produced block is rejected by the
node that just produced it.

For h≥17 the two encoders converge (length-prefix + raw bytes) and
the test passes.

This is a TWO-PIPELINE GUARD failure (encoder #1 in
`_encode_bip34_height` for validation, encoder #2 hand-rolled in
generatetoaddress) — same shape as the W145 multi-pipeline subsidy
finding within ouroboros.

**File:** `src/ouroboros/rpc.py:8773-8777` (broken encoder);
`src/ouroboros/validation.py:97-118` (correct encoder).

**Core ref:** `bitcoin-core/src/script/script.h` (`CScript::operator<<(int64_t)`).

**Impact:** test suites using `generatetoaddress` to bootstrap from
genesis on regtest see immediate rejection at heights 1..16. Fix is a
1-line call to `_encode_bip34_height(next_height)` instead of the
hand-rolled packer.

---

## BUG-13 (P0-CDIV) — `generatetoaddress` coinbase: sequence is SEQUENCE_FINAL and locktime is 0

**Severity:** P0-CDIV. Bitcoin Core's `BlockAssembler::CreateNewBlock`
(`bitcoin-core/src/node/miner.cpp:171, 196`) sets:
```cpp
coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;  // 0xFFFFFFFE
coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
```

This pairing is what allows the coinbase to BE a non-final tx (since
all sequences are 0xFFFFFFFE, IsFinalTx looks at nLockTime). The
`nLockTime = nHeight - 1` is the value that satisfies the nLockTime
gate for the new block at `nHeight`. The rationale is documented in
the miner.cpp comments: "Make sure timelock is enforced".

ouroboros's `generatetoaddress` (rpc.py:8779-8784):
```python
coinbase_in = _TxIn(
    prev_txid=bytes(32),
    prev_vout=0xFFFFFFFF,
    script_sig=coinbase_script,
    sequence=0xFFFFFFFF,      # <-- SEQUENCE_FINAL
    witness=[bytes(32)],
)
```
and rpc.py:8822:
```python
cb_raw.extend(_st.pack("<I", 0))   # <-- locktime = 0
```

Both diverge from Core. The GBT response coinbasetxn at rpc.py:5313-5317
DOES use the correct `0xFFFFFFFE` + `next_height - 1` (B2/B3 in the
inline comment). So the SAME impl emits two contradictory coinbase
contracts:
- GBT (for external miners): correct.
- generatetoaddress (for internal mining): wrong.

This is identical in shape to BUG-12 — a second internal/external
pipeline disagreement on coinbase construction. Listed in
tests/test_w108_gbt.py:754 (G25 sequence) and 782 (G26 locktime); both
tests assert the WRONG values as regression contracts:
```python
self.assertIn("0xFFFFFFFF", src,
              "generatetoaddress uses sequence=0xFFFFFFFF — should be 0xFFFFFFFE")
```

**File:** `src/ouroboros/rpc.py:8783, 8822`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:171, 196`.

**Impact:** the generatetoaddress-produced coinbases are technically
final regardless of nLockTime (sequence=0xFFFFFFFF). nLockTime
enforcement disabled. While the coinbase doesn't have meaningful
inputs, the contract divergence is real — a future BIP that read
coinbase locktime for any purpose would see different values from
ouroboros's two coinbase-builders.

---

## BUG-14 (P1) — `submitblock` skips `UpdateUncommittedBlockStructures` pre-step

**Severity:** P1. Bitcoin Core's `submitblock`
(`bitcoin-core/src/rpc/mining.cpp:1083-1090`) does:
```cpp
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
```
BEFORE calling `ProcessNewBlock`. This step is what fixes up the
coinbase witness stack (the 32-zero-byte nonce) if a miner submitted
a block without it on a segwit-active chain. The reason it lives in
submitblock and not in ProcessNewBlock is that the block-as-submitted
may have a valid witness commitment but a missing nonce — the
`UpdateUncommittedBlockStructures` repair lets such blocks be
accepted.

ouroboros's `rpc_submitblock` (`src/ouroboros/rpc.py:6067-6171`) goes
directly to `accept_block` → `validate_block_from_bytes` →
`connect_block_from_bytes`. No equivalent of
`UpdateUncommittedBlockStructures` is called.

**File:** `src/ouroboros/rpc.py:6067-6171`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1083-1090`;
`bitcoin-core/src/validation.cpp:3975-3995`
(`UpdateUncommittedBlockStructures`).

**Impact:** legacy miners (or pools using historical mining
templates) that submit blocks without the coinbase witness nonce on a
segwit-active chain are rejected by ouroboros where Core would
repair-then-accept. tests/test_w108_gbt.py:531 documents.

---

## BUG-15 (P1) — No `-blockreservedweight` operator knob; MINIMUM_BLOCK_RESERVED_WEIGHT floor absent

**Severity:** P1. Core's `ClampOptions`
(`bitcoin-core/src/node/miner.cpp:79-88`) reads
`-blockreservedweight` via `ApplyArgsManOptions` and clamps to
`[MINIMUM_BLOCK_RESERVED_WEIGHT=2000, MAX_BLOCK_WEIGHT]`.

ouroboros hardcodes `BLOCK_RESERVED_WEIGHT = 8_000` at rpc.py:4891
and provides no CLI knob. Stratum pools that want to reserve a
larger coinbase scriptSig (extranonce space) cannot tune it.

**File:** `src/ouroboros/rpc.py:4891`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:79-88`.

**Impact:** operator can't reserve coinbase space for extranonce
expansion; mid-tier mining pools may need >8000 wu for branded
coinbase output sets.

---

## BUG-16 (P1) — No `-blockmaxweight` operator knob

**Severity:** P1. Core's `-blockmaxweight` lets operators cap the
block weight below MAX_BLOCK_WEIGHT (some pools have business
rationale: stratum mempool DOS protection, regional bandwidth caps).
ouroboros has no equivalent flag; the constant is used directly at
rpc.py:4889.

**File:** `src/ouroboros/rpc.py:4889`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:101`.

**Impact:** operator tuning gap, no consensus risk.

---

## BUG-17 (P1) — `getmininginfo` missing `currentblockweight` / `currentblocktx`

**Severity:** P1. Core's `getmininginfo`
(`bitcoin-core/src/rpc/mining.cpp:467-468`) emits these fields when a
template was ever assembled, sourced from the static accumulators
`BlockAssembler::m_last_block_weight` / `m_last_block_num_txs`.

ouroboros's `rpc_getmininginfo`
(`src/ouroboros/rpc.py:4823-4839`) emits neither. There is no static
counter or instance field accumulated by `rpc_getblocktemplate` for
"the last template's weight/tx count". tests/test_w108_gbt.py:467
documents (G15).

**File:** `src/ouroboros/rpc.py:4823-4839`;
`src/ouroboros/rpc.py:5167` (where Core would store the last
template's weight after assembly).

**Core ref:** `bitcoin-core/src/node/miner.h:96-98`
(`m_last_block_num_txs`, `m_last_block_weight`).

**Impact:** monitoring tools that scrape getmininginfo see different
shape across impls.

---

## BUG-18 (P1) — `getmininginfo.blockmintxfee` hardcoded 0.00001000

**Severity:** P1. Core reads `Options.blockMinFeeRate` (from
`-blockmintxfee` arg) and emits `ValueFromAmount(GetFeePerK())`.
ouroboros hardcodes `0.00001000` at rpc.py:4828 (= 1 sat/B = 1000 sat/kvB).
Operators cannot tune. tests/test_w108_gbt.py G14 documents.

**File:** `src/ouroboros/rpc.py:4828`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:474-476`.

**Impact:** operator tuning gap; if mempool minfee rises above this
hardcoded value the template's `blockmintxfee` claim is wrong (the
selector uses `mempool.snapshot` which has its own ordering).

---

## BUG-19 (P2) — `getmininginfo.networkhashps` and `warnings` hardcoded

**Severity:** P2. ouroboros at rpc.py:4829 emits `"networkhashps": 0`
despite a correct `rpc_getnetworkhashps` existing at rpc.py:8600-8652.
The body never delegates to it. At rpc.py:4838 `"warnings": ""` is
hardcoded — Core uses `GetWarningsForRpc(*node.warnings,
IsDeprecatedRPCEnabled("warnings"))`.

**File:** `src/ouroboros/rpc.py:4829, 4838`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472, 494`.

**Impact:** cosmetic; monitoring divergence.

---

## BUG-20 (P1) — `signet_challenge` never emitted on signet (GBT + getmininginfo)

**Severity:** P1. Core emits `signet_challenge` (the hex challenge
script) in both `getmininginfo` and `getblocktemplate` when on signet.
ouroboros never emits the field in either RPC (no
`getattr(self.node, "signet_challenge", None)` or
`chainparams.signet_challenge` reference in rpc.py). Signet pools
cannot derive the challenge from the template; they must hard-code
it. tests/test_w108_gbt.py G13 documents the GBT side.

**File:** `src/ouroboros/rpc.py:4823-4839` (getmininginfo);
`src/ouroboros/rpc.py:5294-5332` (GBT response).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:489-493, 1024-1026`.

**Impact:** signet miners get no challenge from the template; must
side-channel the value.

---

## BUG-21 (P0-CDIV) — `generatetoaddress` produces empty blocks; ignores mempool entirely

**Severity:** P0-CDIV. Bitcoin Core's `generateBlocks`
(`bitcoin-core/src/rpc/mining.cpp:164-182`) calls
`miner.createNewBlock({.coinbase_output_script = ...})` — the default
`use_mempool=true` path INCLUDES the mempool, producing blocks with
fee revenue.

ouroboros's `rpc_generatetoaddress` (rpc.py:8728-8949) builds a hand-
rolled coinbase + a single-tx block:
```python
# rpc.py:8845
merkle_root = cb_txid  # only coinbase
```
The mempool is never consulted, no fees are collected, and the
coinbase value is `subsidy` only.

Outcome:
- Regtest CI that mines via `generatetoaddress` to confirm mempool
  txs will see those txs NEVER confirm — they sit forever in mempool
  because the mined blocks are always empty.
- Cross-impl divergence — other hashhog impls (and Core) include
  mempool. A consensus-diff harness that uses generatetoaddress to
  mature blocks on a shared mempool will see different state on
  ouroboros vs the others.

This is the most visible "feature parity gap" — the function NAME
implies mempool inclusion but the body doesn't.

**File:** `src/ouroboros/rpc.py:8728-8949`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:164-182`
(`generateBlocks`).

**Impact:** regtest test harness divergence; mempool eviction never
happens via mining; cross-impl consensus tests that mine through
ouroboros leave mempool state diverged.

---

## BUG-22 (P0-CDIV) — `generateblock` and `generatetodescriptor` RPCs entirely missing

**Severity:** P0-CDIV (missing feature). Bitcoin Core exposes three
related RPCs:
- `generatetoaddress(num_blocks, address, maxtries)` — empty blocks +
  mempool to address.
- `generatetodescriptor(num_blocks, descriptor, maxtries)` — same but
  descriptor.
- `generateblock(output, transactions, submit)` — single block from a
  caller-supplied tx list (test harness primitive; runs
  `RegenerateCommitments` to fix witness commitment).

ouroboros only exposes `generatetoaddress` (rpc.py:8728), and that
one ignores the mempool (BUG-21). A grep for `generateblock` /
`generatetodescriptor` against the dispatch convention
(`rpc_<method>`) returns ZERO hits.

**File:** `src/ouroboros/rpc.py` (entire file; `rpc_generateblock` /
`rpc_generatetodescriptor` absent).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:219-303` (g2desc),
`bitcoin-core/src/rpc/mining.cpp:305-414` (generateblock).

**Impact:**
- The `generateblock(output, [rawtx,...], submit=false)` primitive is
  used by Core's functional test harness for property tests
  (specifically: build a custom tx, mine it into a block, snapshot
  the result without persisting). hashhog cross-impl tests that
  depend on this primitive (test-suite/test_vectors.py etc.) cannot
  exercise ouroboros.
- Descriptor-based mining is the Core convention for modern wallets;
  ouroboros forces operators to derive addresses out-of-band.

---

## BUG-23 (P1) — GBT response: both `coinbasetxn` and `coinbasevalue` emitted (BIP-22 violation)

**Severity:** P1. BIP-22 specifies: the server returns EITHER
`coinbasetxn` (full coinbase template, when client declares capability)
OR `coinbasevalue` (subsidy + fees scalar). Not both. Core respects
the capability dispatch.

ouroboros emits BOTH unconditionally
(`src/ouroboros/rpc.py:5310-5318`). Plus `coinbasetxn` only carries
`{locktime, sequence}` — no `data` field with the serialized coinbase
hex — so consumers expecting the BIP-22 contract get a half-filled
sub-object. tests/test_w108_gbt.py G7 (line 260 — missing data field)
and G8 (line 278 — both present) and G17 (line 504 — missing fee /
sigops / weight on coinbasetxn) all document this.

**File:** `src/ouroboros/rpc.py:5310-5318`.

**Core ref:** BIP-22 § Specification/Template; Core mining.cpp
emits `coinbasevalue` always and `coinbasetxn` only when the client
declared `coinbasetxn` capability (default off).

**Impact:** BIP-22-compliant clients that interpret `coinbasetxn`
preferentially see a malformed sub-object (no `data` / `fee` /
`sigops` / `weight`). Workaround: read `coinbasevalue` instead.

---

## BUG-24 (P1) — `coinbaseaux` has spurious `flags` key

**Severity:** P1. Core's default GBT response has `coinbaseaux = {}`
(empty dict). ouroboros emits `{"flags": ""}` (rpc.py:5261-5263).
Cosmetic shape divergence — BIP-22 says `coinbaseaux` is for the
server to push key/value pairs of bytes for the miner to splice into
the coinbase scriptSig; an empty `flags` key is meaningless. tests/test_w108_gbt.py G16 documents.

**File:** `src/ouroboros/rpc.py:5261-5263`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:938-1000`.

**Impact:** shape divergence; miners that splice all coinbaseaux
entries blindly might add a 0-byte payload.

---

## BUG-25 (P1) — `sigoplimit` / `sizelimit` not adjusted for pre-segwit clients

**Severity:** P1. Core at mining.cpp:1009-1016 divides both limits by
`WITNESS_SCALE_FACTOR=4` when `fPreSegWit` is true (no segwit
support advertised by client):
```cpp
if (fPreSegWit) {
    nSigOpLimit /= WITNESS_SCALE_FACTOR;
    nSizeLimit /= WITNESS_SCALE_FACTOR;
}
```
and omits `weightlimit` entirely.

ouroboros always emits `sigoplimit=80000`, `sizelimit=4_000_000`,
`weightlimit=4_000_000` regardless. tests/test_w108_gbt.py G12 and G28
document.

**File:** `src/ouroboros/rpc.py:5328-5330`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1009-1019`.

**Impact:** pre-segwit miners (legacy hardware, ASICBoost firmware
that doesn't speak segwit-style nonce) get over-budget templates and
their assembled blocks would exceed the legacy size limit.

---

## BUG-26 (P1) — `vbavailable` always empty; BIP-9 deployments not surfaced

**Severity:** P1. Core's `vbavailable`
(`bitcoin-core/src/rpc/mining.cpp:965-983`) populates from
`GBTStatus.signalling` and `GBTStatus.locked_in` — for each STARTED
or LOCKED_IN deployment the field maps `name → bit`.

ouroboros at rpc.py:5287 hardcodes `gbt_vbavailable: dict = {}`. The
`BIP9_DEPLOYMENTS` table in consensus.py:235-450 has per-network
data but no aggregator. tests/test_w108_gbt.py G4 (FIXED part) only
checks the field is present and is a dict — not that any deployment
is signalled.

**File:** `src/ouroboros/rpc.py:5285-5287`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:965-983`.

**Impact:** miners cannot opt in to ad-hoc soft-fork signalling
through ouroboros templates. Any future deployment that goes through
STARTED on mainnet will not be signallable.

---

## BUG-27 (P1) — `getmininginfo.next.bits` uses tip bits, not next-block bits

**Severity:** P1. Core's `getmininginfo` populates `next.{bits,target,
difficulty}` via `NextEmptyBlockIndex(tip, params, next_index)`
(mining.cpp:480-486) — which calls `GetNextWorkRequired` for the
next block.

ouroboros at `rpc.py:4832-4837`:
```python
"next": {
    "height": next_height,
    "bits": bits_hex,           # <-- tip bits
    "difficulty": difficulty,    # <-- tip difficulty
    "target": target_hex,        # <-- tip target
},
```
Same bug as BUG-3 surfaced through getmininginfo. Cross-cite.

**File:** `src/ouroboros/rpc.py:4832-4837`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:480-487`.

**Impact:** monitoring tooling sees the wrong "next" target at every
adjustment-interval boundary.

---

## BUG-28 (P0-CDIV) — `generatetoaddress` hardcodes mainnet-invalid version + bits; no network check

**Severity:** P0-CDIV. `rpc_generatetoaddress` hardcodes:
- `bits = 0x207FFFFF` at rpc.py:8849 (regtest min-difficulty).
- `version = 0x20000000` at rpc.py:8865.

There is no `if network != "regtest": raise HTTPException(...)` guard;
the network getattr at rpc.py:8751 defaults to `"regtest"` but a
mainnet caller would just produce wrong-target blocks. Core's
`generatetoaddress` is not regtest-gated but it correctly calls
`GetNextWorkRequired` (because it goes through BlockAssembler), so
the same RPC works on regtest/testnet/signet/mainnet there.

**File:** `src/ouroboros/rpc.py:8849, 8865`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:164-182`
(`generateBlocks` uses CreateNewBlock → GetNextWorkRequired).

**Impact:** mainnet/testnet `generatetoaddress` calls silently
produce invalid-target blocks. Test harnesses that share helpers
between regtest and other networks see opaque rejections.

---

## BUG-29 (P0-CDIV) — Template never validates via `TestBlockValidity`

**Severity:** P0-CDIV. Core's `BlockAssembler::CreateNewBlock`
(`bitcoin-core/src/node/miner.cpp:223-228`):
```cpp
if (m_options.test_block_validity) {
    if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock,
                                                     /*check_pow=*/false,
                                                     /*check_merkle_root=*/false)}; !state.IsValid()) {
        throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
    }
}
```
The template is run through the full block validator (less PoW + less
merkle root, which the assembler hasn't computed yet). If validation
fails — e.g., a mempool tx with a stale UTXO ref slipped in — the
template is rejected before being returned to the miner.

ouroboros's `rpc_getblocktemplate` (rpc.py:4841-5332) emits the
selection results directly, with no validity gate. Cross-cite W153
BUG-8 + this audit's BUG-10 (removeConflicts absent) — the very
failure mode TestBlockValidity catches in Core (stale-input mempool
tx) is the exact failure mode ouroboros mempool gets into.

**File:** `src/ouroboros/rpc.py:4841-5332`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** combined with BUG-10, the very next mined block after a
RBF/conflict block-connect is built on a stale mempool snapshot and
the GBT response is silently doomed. No defense-in-depth catches it.

---

## BUG-30 (P1) — `prioritisetransaction` does not surface entries in BIP-22 fee map

**Severity:** P1. Core uses `entry.GetModifiedFee()` (=
nFee + nFeeDelta) throughout BlockAssembler selection and emits the
modified fee back through the GBT `fee` field (mining.cpp:926
`tx_fees.at(...)`).

ouroboros at rpc.py:5156 emits `"fee": e.fee` — the RAW fee, NOT the
modified fee. The selector at rpc.py:5006-5028 DOES use modified fee
via `_mod_fee` for the ancestor-fee-rate sort, but the template's
per-tx `fee` field reports the raw value. Miners that re-tally
ancestor packages and want to see Core's modified-fee picture get the
wrong number.

**File:** `src/ouroboros/rpc.py:5156` (raw fee in template);
`src/ouroboros/rpc.py:5006-5028` (modified fee used for sort).

**Core ref:** `bitcoin-core/src/node/miner.cpp:265-275`
(`AddToBlock` pushes `entry.GetFee()` — not `GetModifiedFee`). Wait —
Core DOES use raw fee here. Let me re-check… Yes, Core's
`pblocktemplate->vTxFees.push_back(entry.GetFee())` uses raw fee, not
modified fee. So this gate is actually correct in ouroboros. **PROMOTE
TO PASS / DEMOTE from bug list — keeping the BUG number for stability
of the audit but lowering severity to P2.** Note this is the only
two-pipeline ELEMENT in ouroboros where the fee field is consistent.

Reclassify: P2 — note for fleet pattern study: even Core emits
template fees as raw, not modified, despite using modified for
selection. The pattern of "select-modified, emit-raw" is intentional
and matches Core. ouroboros gets this right.

---

## BUG-31 (P0-CDIV) — `addPackageTxs` ancestor-feerate is GREEDY-PER-TX not CHUNK-PER-PACKAGE (mempool cluster mismatch)

**Severity:** P0-CDIV. Bitcoin Core (cluster mempool era,
post-v29.0) selects PACKAGES from
`m_mempool->GetBlockBuilderChunk` — atomic chunks pre-computed by
the mempool's cluster solver. Each chunk has a known `FeePerWeight`
and atomic include/skip decisions.

ouroboros's GBT body recomputes ancestor fee rates greedily per-tx
(rpc.py:5009-5028) and serves them in a flat sorted order
(rpc.py:5031-5035), then expands each candidate to its ancestor set
batch at rpc.py:5053. This greedy approach diverges from cluster
mempool in three ways:
1. **No chunking** — Core's chunks are pre-clustered (a parent + its
   high-feerate child are a single unit). ouroboros may pick a
   high-feerate child whose low-feerate parent does not satisfy the
   batch's effective feerate against `blockMinFeeRate`.
2. **No deferred chunk skip** — Core's `SkipBuilderChunk` advances
   the cursor; ouroboros's `continue` may try the same effective
   batch on a subsequent iteration via a different `entry_txid`.
3. **`blockMinFeeRate` gate missing** — Core compares `chunk_feerate_vsize
   << blockMinFeeRate.GetFeePerVSize()` (mining.cpp:298-300) and
   stops selection when the next chunk falls below the minimum.
   ouroboros has no equivalent gate; templates can include
   below-minimum-fee txs as long as the weight budget has room.

The current Python implementation matches pre-cluster-mempool Core
(circa v0.21..v0.23) which used `selectByDescendantScore +
selectByAncestorFeeRate` greedy paths. It does NOT match the cluster
mempool semantics shipped in Core v29.0+. As Core converges on
cluster-mempool everywhere (a Core change in late 2025 made cluster
mempool the only path), ouroboros's GBT will diverge in selection
choice — different block templates with different fee revenue
characteristics.

**File:** `src/ouroboros/rpc.py:4945-5167` (entire selection loop).

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-330` (`addChunks`);
`bitcoin-core/src/kernel/mempool_persist.cpp` (chunk solver).

**Impact:** systematically different block templates vs Core; fleet
divergence in mining-revenue-optimal selection; not consensus-fatal
on its own but compounding the doomed-block patterns above.

---

## BUG-32 (P1) — Witness commitment merkle tree uses naive doubling; no CVE-2012-2459 detection (template side)

**Severity:** P1. The witness merkle root computation at rpc.py:5186-5197
uses Bitcoin's standard "duplicate-last-on-odd" doubling:
```python
while len(level) > 1:
    next_level = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            combined = level[i] + level[i + 1]
        else:
            combined = level[i] + level[i]
        ...
```
This matches Core's `ComputeMerkleRoot` so the commitment value is
correct. **However:** Core's `BlockWitnessMerkleRoot` runs the same
sha256-32-pad logic that has the CVE-2012-2459 (duplicated-leaf
malleability) property. The template assembler doesn't need to detect
the mutation (mutation only matters for block-arrival), so this is
acceptable. But the comment-as-confession cross-cite to W142 BUG-13
fleet finding (6 of 10 impls missing mutated-merkle detection)
remains a fleet pattern.

This entry is informational — the bug doesn't manifest at
template-construction time, only at block-validation time (cross-cite
W142 / W143).

**File:** `src/ouroboros/rpc.py:5186-5197`.

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp::ComputeMerkleRoot`.

**Impact:** N/A at GBT layer; fleet pattern persists at validation
layer (W142 BUG cross-cite).

---

## Summary

**Bug count:** 32 (BUG-1 through BUG-32; BUG-30 demoted to P2 on
re-verification against Core).

**Severity distribution:**
- **P0-CDIV:** 13 — BUG-1, BUG-2, BUG-3, BUG-4, BUG-7, BUG-8, BUG-9,
  BUG-10, BUG-11, BUG-12, BUG-21, BUG-22, BUG-28, BUG-29, BUG-31
  (re-count: 15 — see below).

  Actually counting: BUG-1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 21, 22,
  28, 29, 31 = 16 P0-CDIVs. The very HIGH P0-CDIV concentration
  reflects the dead-helper / multi-pipeline / missing-gate density
  of this subsystem.

- **P1:** 14 — BUG-5, BUG-6, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18,
  BUG-20, BUG-23, BUG-24, BUG-25, BUG-26, BUG-27, BUG-32.

- **P2:** 2 — BUG-19, BUG-30.

Total: 16 + 14 + 2 = 32. ✓

**Top three findings (most severe):**

1. **BUG-3 (P0-CDIV) — `get_next_bits` + `get_next_block_version`
   dead-helper.** Two getattr fallbacks at rpc.py:5223 and rpc.py:5246
   ALWAYS run because the underlying methods are never defined on
   Node. Yet `consensus.compute_block_version` and Rust
   `get_next_work_required` both exist (defined + tested) — pure
   plumb-but-don't-wire dead-helper, fleet pattern 6th+ ouroboros
   instance. Outcome: every 2016-block adjustment boundary the GBT
   template emits the PREVIOUS epoch's bits → mined blocks fail
   `bad-diffbits`. BIP-9 deployments are never signalled. **Single
   highest-severity bug this wave.**

2. **BUG-10 (P0-CDIV) — `removeConflicts` absent → next mined block
   is DOOMED-BY-CONSTRUCTION after every RBF/conflict block-connect.**
   `remove_block_transactions` only removes block txs by their own
   txid; the inner loop that walks each block-tx's inputs to evict
   conflicting mempool entries is missing. Combined with BUG-29
   (`TestBlockValidity` not called at template construction), the
   GBT response after a block connect with any RBF candidate in
   mempool emits a stale-input template that `submitblock` rejects
   immediately. Cross-cite W153 BUG-8 (the same gap reported at the
   mempool layer; this audit reports the consequent at the mining
   layer).

3. **BUG-4 (P0-CDIV) — `template_request` ignored entirely
   (proposal mode, longpoll, client-rules, mode dispatch).** The
   second function parameter is dead from the first line of the body
   onward. The capability list advertises `["proposal"]` at
   rpc.py:5267 — **false advertising**. Stratum daemons relying on
   longpoll backpressure poll-spam ouroboros; BIP-22 proposal mode is
   silently a no-op; unknown modes don't error.

**Fleet patterns confirmed in this wave:**

- **"Plumb-but-don't-wire" dead-helper, 6th+ ouroboros instance**
  (BUG-3) — `get_next_bits` / `get_next_block_version` fallback
  branches are deliberate plumbing for non-existent methods. Cross-
  fleet companion to W148 BUG-16 (`is_synced` returns hardcoded false)
  and W153 BUG-7 (entire ZMQ pipeline dead at source).
- **N-pipeline drift, 5+ ouroboros instances** — BUG-11 (3+ subsidy
  sites; cross-cite W145 "5 distinct pipelines"); BUG-12 (BIP-34
  encoder generatetoaddress vs validator); BUG-13 (coinbase
  sequence/locktime generatetoaddress vs GBT); BUG-7 (mintime vs
  validator's timewarp). With W149 + W150 ATMP + W151 + W152 + W153,
  ouroboros holds the cross-impl record for distinct-pipeline drift
  (now extended to **7+** with this wave).
- **"comment-as-confession", 11th+ instance** — BUG-10 comment at
  mempool.py:1844 NAMES `removeConflicts (txmempool.cpp:398)` but
  the function body is absent. The author KNEW it was needed.
- **"Recovery-path-is-the-bug-path"** — BUG-29 (no TestBlockValidity)
  + BUG-10 (no removeConflicts) co-occurring; the very gates Core
  uses as defense-in-depth against the gap that creates the bug are
  themselves missing. (This is W148 / W153 fleet pattern continuation.)
- **"misbehaving-on-policy-reject"** — N/A this wave; the analogous
  pattern here is BUG-9 (`continue` on missing prev_utxo silently
  under-counts and emits the tx anyway).
- **"Two-pipeline guard, 18th+ extension"** — first time the
  COINBASE itself is doubled across subsystems within one impl
  (BUG-12, BUG-13). The generatetoaddress coinbase-builder and the
  GBT coinbase-template diverge on encoding (BIP-34), sequence
  (SEQUENCE_FINAL vs MAX_SEQUENCE_NONFINAL), and locktime (0 vs
  next_height-1).
- **"Operator knob absent"** — BUG-15, BUG-16, BUG-18 — no
  `-blockreservedweight`, `-blockmaxweight`, `-blockmintxfee` CLI
  flags. Pattern continues from W148 BUG-6 (`-assumevalid` absent
  fleet) at the mining layer.
- **"OUROBOROS_*_STOPGAP env-var for mining"** — checked, **none
  found** (only `OUROBOROS_BIP68_STOPGAP=1` exists, scoped to
  sequence-locks). No env-var escape hatch for mining bugs — they
  are silently active in every production deployment.
- **"raw-bytes-vs-vsize" (W151 NEW)** — BUG-31 ancestor fee rate
  uses `entry.size` (which in `mempool.py` represents stripped bytes
  for legacy txs, not strict vsize). tests/test_w108_gbt.py G21
  documents but does not fix.
- **"Cross-cite W153 BUG-13 ~30% capacity OOM"** — BUG-31 has
  similar shape: greedy-per-tx evaluation visits the same package
  multiple times via different children, O(N²) worst-case on a
  package-dense mempool. Not OOM yet, but compute-cost analogue.

**Cross-cites this wave:**
- **W153 BUG-7** (ZMQ tx-event pipeline dead at source) → BUG-1 IBD
  guard absent: even if ouroboros had a working IBD flag, no consumer.
- **W153 BUG-8** (removeConflicts absent in mempool) → BUG-10 (same
  gap surfaces at mining-template construction; the very next mined
  block after RBF block-connect is doomed).
- **W148 BUG-16** (`is_synced` hardcoded false since W113) → BUG-1
  IBD guard absent: the flag exists but it's wrong, and the GBT
  doesn't even consult it.
- **W148 BUG-17** (NODE_NETWORK_LIMITED plumb-gate-then-flip) →
  BUG-3 (plumb-but-don't-wire pattern; same shape).
- **W145 BUG-1** (subsidy halving interval not params-aware, fleet
  pattern 5+ impls) → BUG-11 (third+ subsidy pipeline in
  ouroboros; GBT hardcodes 210k, generatetoaddress uses 150 on regtest).
- **W145 BUG-3** (rustoroshi two parallel block_subsidy) → BUG-11
  extended: ouroboros has THREE+ subsidy pipelines, exceeding the
  W145-reported "5 distinct pipelines" already.
- **W144 BUG-2** (taproot dead-data BIP9) → BUG-26 (`vbavailable`
  always empty; no deployment surfaced).
- **W142 BUG-13** (CVE-2012-2459 mutated-merkle missing fleet
  pattern, 6 of 10) → BUG-32 (informational only at GBT layer;
  bug manifests at validation layer per W142).

**PRIORITY FIX RANKING (for FIX-W154+):**

1. **BUG-3 + BUG-27** — wire `get_next_bits` to the existing Rust
   `get_next_work_required` (lib.rs:401); wire `get_next_block_version`
   to the existing `consensus.compute_block_version` (consensus.py:763).
   ~30 LOC across Node + RPC bridge. Closes 2 P0-CDIVs that fire on
   every difficulty-adjustment boundary forever.
2. **BUG-10** — add removeConflicts to `_remove_block_transactions_inner`:
   walk each block-tx's inputs, evict mempool entries spending the
   same prevout. ~10 LOC. Closes the doomed-next-block primitive.
3. **BUG-11** — replace `next_height // 210_000` at rpc.py:5211 with
   network-aware `halving_interval` lookup (same shape as the
   generatetoaddress fix at rpc.py:8767). ~3 LOC. Closes regtest GBT
   subsidy divergence; cross-fleet companion to other W145 fixes.
4. **BUG-12** — replace generatetoaddress's hand-rolled BIP-34
   encoder with `_encode_bip34_height(next_height)`. ~3 LOC. Closes
   regtest h=1..16 doom.
5. **BUG-13** — change generatetoaddress coinbase
   `sequence=0xFFFFFFFE`, `locktime=next_height-1` (pack at line
   8822). ~2 LOC. Closes generatetoaddress coinbase-contract
   divergence vs GBT.
6. **BUG-21** — make generatetoaddress include the mempool (mirror
   the GBT selection logic OR factor out a shared helper). ~30 LOC.
   Closes regtest-CI mempool-eviction-never-happens.
7. **BUG-1 + BUG-2** — add IBD + peer-count guards to GBT.
   Requires fixing W148 BUG-16 first (is_synced wired correctly).
   ~5 LOC after that.
8. **BUG-4 + BUG-5 + BUG-6** — parse `template_request`: enforce
   client-rules, dispatch on mode (proposal/template), emit
   longpollid. ~50 LOC.
9. **BUG-29 + BUG-8 + BUG-9** — add TestBlockValidity equivalent at
   end of `rpc_getblocktemplate` (call `accept_block` with
   `dry_run=True` or equivalent); make sigops-skip atomic per batch;
   reject txs with unresolvable prev_utxo. ~40 LOC.
10. **BUG-22 + BUG-28** — add `rpc_generateblock` and
    `rpc_generatetodescriptor`; gate generatetoaddress mainnet/testnet
    calls behind `GetNextWorkRequired`. ~80 LOC.
