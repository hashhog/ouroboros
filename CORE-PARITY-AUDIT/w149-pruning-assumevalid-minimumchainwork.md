# W149 — Pruning + AssumeValid + MinimumChainWork (ouroboros)

**Wave:** W149 — `FindFilesToPrune`, `FindFilesToPruneManual`,
`PruneOneBlockFile`, `UnlinkPrunedFiles`, `-prune=N` arg semantics,
`PRUNE_TARGET_MANUAL` sentinel, `MIN_BLOCKS_TO_KEEP`, `MIN_DISK_SPACE_FOR_BLOCK_FILES`,
`AssumedValidBlock()` 5-precondition gate, `defaultAssumeValid`, `fScriptChecks`,
`BLOCK_ASSUMED_VALID`, `BLOCK_HAVE_DATA`/`HAVE_UNDO`, `nMinimumChainWork`,
`UpdateIBDStatus`, `MinimumConnectedChainWork`, `pruneblockchain` RPC dual-mode
(height/timestamp), BIP-159 `NODE_NETWORK_LIMITED`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp:294-310` — `FindFilesToPruneManual`
  (asserts `IsPruneMode() && nManualPruneHeight > 0`, calls
  `chain.GetPruneRange(nManualPruneHeight)`, deletes by file number).
- `bitcoin-core/src/node/blockstorage.cpp:321-401` — `FindFilesToPrune`
  (target derived from `GetPruneTarget()/num_chainstates`,
  `target_sync_height = m_best_header->nHeight`,
  `if (chain.m_chain.Height() <= chainparams.PruneAfterHeight()) return`,
  IBD-aware buffer `average_block_size * remaining_blocks`,
  per-file `BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE` allocation buffer).
- `bitcoin-core/src/node/blockstorage.h:407-408` —
  `PRUNE_TARGET_MANUAL = std::numeric_limits<uint64_t>::max()` sentinel,
  `GetPruneTarget()` accessor.
- `bitcoin-core/src/init.cpp:524` — `-prune=N` arg unit is **MiB** (1024 × 1024).
- `bitcoin-core/src/node/blockstorage.cpp:1225` —
  `m_prune_mode{opts.prune_target > 0}` (any non-zero target = prune mode).
- `bitcoin-core/src/rpc/blockchain.cpp:908-965` — `pruneblockchain` RPC:
  rejects negative, treats `> 10^9` as Unix timestamp (subtract 2-hr window,
  `FindEarliestAtLeast`), rejects `chainHeight > height`, clamps to
  `chainHeight - MIN_BLOCKS_TO_KEEP`, refuses below `PruneAfterHeight()`.
- `bitcoin-core/src/rpc/blockchain.cpp:1397, 1452-1456` — `getblockchaininfo`
  surfaces `prune_target_size` only when `GetPruneTarget() != PRUNE_TARGET_MANUAL`
  (automatic pruning only).
- `bitcoin-core/src/validation.cpp:2344-2382` — `BLOCK_ASSUMED_VALID` /
  `fScriptChecks` gate: **5 preconditions** —
  (1) `AssumedValidBlock()` not null;
  (2) hash present in `m_block_index`;
  (3) `pindex` is an ancestor of assumevalid block;
  (4) `m_best_header->GetAncestor(pindex->nHeight) == pindex`;
  (5) `m_best_header->nChainWork >= MinimumChainWork()`;
  (6) `GetBlockProofEquivalentTime(*m_best_header, *pindex, *m_best_header) > TWO_WEEKS_IN_SECONDS`.
- `bitcoin-core/src/kernel/chainparams.cpp:312, 456, 537` —
  `defaultAssumeValidBlockHash` per network (mainnet/testnet3/testnet4/signet/regtest).
- `bitcoin-core/src/validation.cpp:3283-3291` — `UpdateIBDStatus` exits IBD
  when `IsTipRecent(MinimumChainWork(), max_tip_age)`; one-way latch
  (`m_cached_is_ibd.store(false)`).
- `bitcoin-core/src/validation.cpp:4280, 4345` — `m_best_header->nChainWork`
  checked against `MinimumChainWork()` for "low-work-headers" gate.
- `bitcoin-core/src/net_processing.cpp:2643` — `MinimumConnectedChainWork`
  = `max(near_chaintip_work, MinimumChainWork())` (for peer-served-blocks).
- `bitcoin-core/src/net_processing.cpp:4328` — `MinimumChainWork` gate on
  `getheaders`/`headers` to non-Download-permission peers.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`,
  `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB`.
- `bitcoin-core/src/chain.h:42-86` — `BLOCK_HAVE_DATA` (8),
  `BLOCK_HAVE_UNDO` (16), `BLOCK_ASSUMED_VALID` (128).
- `bitcoin-core/src/init.cpp:1109-1114` — `nLocalServices |= NODE_NETWORK_LIMITED`
  when `IsPruneMode()`.

**Files audited**
- `src/ouroboros/pruning.py` — `BlockPruner`, `PruneStats`, `FilePruner`,
  `MIN_KEEP_BLOCKS`, `MIN_TARGET_MB`, `manual` sentinel.
- `src/ouroboros/config.py:22-26, 460-470` — `MIN_BLOCKS_TO_KEEP = 288`
  module constant, `NodeConfig.get_minimum_chain_work`.
- `src/ouroboros/cli.py:99-490` — CLI argument surface (no `--prune`,
  no `--assumevalid`, no `--minimumchainwork`; `--reindex` is a no-op marker).
- `src/ouroboros/node.py:270-283, 643-697, 1003-1073` — pruner construction,
  periodic prune trigger, BIP-159 peer-served-blocks `getdata` short-circuit.
- `src/ouroboros/node.py:368-376` — `PeerManager` construction (does NOT
  thread `node_network_limited` from pruner state).
- `src/ouroboros/peer.py:298-332, 750-763, 1265-1281, 1422-1430` —
  `NODE_NETWORK_LIMITED` service-bit emission gated on
  `self.node_network_limited`.
- `src/ouroboros/rpc.py:1395-1533, 6234-6263, 11015-11038` —
  `getblockchaininfo` prune fields, `pruneblockchain` RPC,
  `dumptxoutset` pre-check.
- `src/ouroboros/validation.py:807-823, 1874-1989` — Python `skip_scripts`
  gate (checkpoint-based, NOT `defaultAssumeValid` hash).
- `src/ouroboros/block_sync.py:1086-1334, 1778-1840` — `_drain_block_buffer`
  three-pipeline gate (Rust route, Python fallback, cross-check), G8
  `nMinimumChainWork` post-PoW header-batch gate.
- `src/ouroboros/sync_manager.py:267-273` — `SyncManager.is_synced` proxy.
- `ferrous-utils/sync/src/chain_params.rs:280-313, 454-461` —
  `minimum_chain_work` per network, `subsidy_halving_interval`.
- `ferrous-utils/sync/src/validate/block.rs:82-156, 235-397` —
  `BlockValidator::new` (assumevalid_height + `OUROBOROS_ASSUMEVALID` env-var
  stopgap), `validate_block` vs `validate_block_with_flags` (TWO pipelines).
- `ferrous-utils/sync/src/storage/blockstore.rs:743-1040` —
  `MIN_BLOCKS_TO_KEEP = 288`, `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB`,
  `find_files_to_prune`, `prune_to_target`, `prune_to_height`,
  `get_prune_height`, `has_block_data_at_height`.
- `ferrous-utils/sync/src/lib.rs:895-918, 1110-1145, 1590-1640, 3270-3402,
  3946-4055, 4502-4636, 5912-5916` — `get_minimum_chain_work` FFI,
  `can_skip_scripts_for_block` (checkpoint-based), `validate_block_from_bytes`,
  `connect_block_from_bytes` (inline consensus checks pipeline),
  `connect_blocks_atomic` (third pipeline), `import_blocks_from_file`
  (fourth pipeline), `FastSync.is_synced` (always returns false).
- `ferrous-utils/common/src/types.rs:471-565` — `BlockStatus` flag layout:
  `BLOCK_HAVE_DATA`, `BLOCK_HAVE_UNDO` present; **`BLOCK_ASSUMED_VALID` absent**.

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` arg semantics | G1: `-prune=0` disables; `-prune=1` is manual sentinel (RPC-only); `-prune>=550` auto-target | **BUG-1 (P0-CDIV)** no `--prune` / `--prune-keep-blocks` CLI flag; only `prune=` config-file key. `-prune=0` doesn't disable anything because there is no CLI gate. |
| 1 | … | G2: `-prune=N` unit is **MiB** (binary 1024×1024) | **BUG-2 (P0-CDIV)** Python `pruning.py:109` multiplies `MB × 1_000_000` (decimal). User-supplied `-prune=550` becomes 550 MB = 524 MiB, then Rust clamps up to 576 MiB (550 MiB). Operator's target is silently misrepresented. Carry-forward W146 BUG-15. |
| 1 | … | G3: `-prune=1` sentinel preserves `IsPruneMode()=true` (NODE_NETWORK_LIMITED, `pruned=true`) but disables auto-prune | PARTIAL — `self.manual = target_size_mb == 1` (pruning.py:108); auto-prune correctly disabled; **but `pruned=pruner.prune_height > 0` (rpc.py:1416)** reports `false` until something has actually been pruned — Core reports `true` for any non-zero prune target. **BUG-3 (P0-CDIV)** |
| 1 | … | G4: Refuse to start if `0 < N < 550` (Core clamps; doesn't silently promote) | PARTIAL — `pruning.py:109` silently promotes anything < 550 to 550 with no warning. Core: `if (nPruneTarget && nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) throw InitError(...)` (init.cpp:528). **BUG-4 (P1)** |
| 2 | `pruneblockchain` RPC dual-mode | G5: integer ≤ 10^9 = height; integer > 10^9 = Unix timestamp (subtract 2-hr window, walk to earliest block ≥ that time) | **BUG-5 (P0)** `rpc.py:6234-6263` treats input always as height. A caller passing `pruneblockchain(1700000000)` (Nov 2023 epoch) is interpreted as height 1.7B — Python pruner clamps to `current_height - 288` silently. Core would walk to ~block 815k. |
| 2 | … | G6: Reject negative; reject `height > chainHeight`; reject below `PruneAfterHeight()` | **BUG-6 (P0-CDIV)** No input validation in `rpc_pruneblockchain`. Negative height crashes inside Rust (`u32::try_from(-1)` panic), oversize silently clamps. No `PruneAfterHeight()` gate. Core throws `RPC_INVALID_PARAMETER`. |
| 2 | … | G7: Clamp to `chainHeight - MIN_BLOCKS_TO_KEEP` with `LogDebug` warning | PASS — `pruning.py:184` `min(target_height, current_height - keep_blocks)` matches semantics, but no log emitted at clamp (Core emits "Retaining the minimum number of blocks"). |
| 3 | `MIN_BLOCKS_TO_KEEP` enforcement | G8: hard floor of 288 on `-prune-keep-blocks` | PASS — `pruning.py:110` `max(keep_blocks, 288)`. |
| 3 | … | G9: any block within 288 of tip is unprunable, **per chain (not per-file)** | PARTIAL — Rust `prune_to_target` uses `current_height - 288` as `last_block_can_prune` (blockstore.rs:937), but only entire FILES are pruned (file's `height_last > last_block_can_prune` → skip). When a file spans the tip-288 boundary, the whole file stays. This matches Core's file-granular behavior. PASS. |
| 3 | … | G10: Reorg-safety: during IBD prune uses `target_sync_height = m_best_header->nHeight`, NOT `m_chain.Tip()->nHeight` | **BUG-7 (P0)** `node.py:684` passes `best_height` (active tip) to `prune_to_target`. During mid-IBD with active=100k and best_header=900k, prune horizon is 100k-288 — but blocks 50k-99k may legitimately need to stay (deep reorg of the partial sync), AND Core would NOT auto-prune mid-IBD at this height because `target_sync_height >> chain_tip_height`. |
| 4 | `AssumedValidBlock()` 5-precondition gate | G11: assumevalid is keyed by **block hash** (defaultAssumeValid), not height | **BUG-8 (P0-CDIV)** Both Python (`validation.py:815`, `can_skip_scripts_for_block`) and Rust (`block.rs:142`, `assumevalid_height`) gate on **HEIGHT** (last checkpoint or env var). Core gates on the hash of a specific block AND validates 5 preconditions (chain ancestry, best-header ancestry, MinimumChainWork, 2-week equivalence). |
| 4 | … | G12: `pindex` is an ancestor of the assumevalid block | **BUG-8 cross-cite** — no ancestor check; a side-branch block at height H ≤ assumevalid skips scripts even though it descends from a different fork. |
| 4 | … | G13: `m_best_header->nChainWork >= MinimumChainWork()` | **BUG-9 (P0-CDIV)** the assumevalid skip gate has no MinimumChainWork sanity. An eclipse-attacker can feed a low-work header chain and ouroboros will gladly skip scripts on all blocks below the last checkpoint anyway. |
| 4 | … | G14: 2-week `GetBlockProofEquivalentTime` gate (block not too recent relative to best header) | **BUG-10 (P0-CDIV)** absent. Core deliberately discourages a hash-power attack that buries a fake assumevalid hash within 2 weeks of best_header. |
| 4 | … | G15: `defaultAssumeValid` per-network value shipped + updated per release | **BUG-11 (P0-CDIV)** Rust uses `Network::Bitcoin => 938_343` (block 938k, a height), not the corresponding `0x000000000000000000022b1ce6c08c2c4b8a8e3...` hash. There is NO `defaultAssumeValidBlockHash` table in `chain_params.rs`. The Python side has no concept of assumevalid hash at all. |
| 5 | `nMinimumChainWork` integration | G16: per-network value present and matches Core v28+ | PASS — `chain_params.rs:280-313` (mainnet `0001128750f82f4c366153a3a030`, testnet4 `09a0fe15d0177d086304`, etc., match Core v28 chainparams.cpp values). |
| 5 | … | G17: `IsInitialBlockDownload` exits when `IsTipRecent(MinimumChainWork(), max_tip_age)` | **BUG-12 (P0-CDIV)** `FastSync.is_synced` returns `false` UNCONDITIONALLY (`lib.rs:5912-5916` `// For now, return false (in practice would check against network tip)`). Comment-as-confession 7th instance. `sync_manager.is_synced()` always False → `node._check_synced()` always False → `rpc._is_synced()` always False → `getblockchaininfo.initialblockdownload = true` FOREVER, even mid-2026 with a fully-synced mainnet node at tip. Mempool acceptance, fee estimation, sendheaders gating, RPC `verificationprogress` all see `is_ibd=true` perpetually. |
| 5 | … | G18: `MinimumConnectedChainWork` = `max(near_chaintip_work, MinimumChainWork)` for getheaders gate | **BUG-13 (P0)** no `MinimumConnectedChainWork` analog. `block_sync.py:1797-1840` checks min-chain-work on the batch only when `min_pow_checked=False`, after-the-fact rollback rather than Core's pre-acceptance pindex-level gate. |
| 5 | … | G19: low-work peers (active tip chainwork < min_chain_work) get getheaders refused unless they have Download permission | **BUG-14 (P0)** absent. `net_processing.cpp:4328` blocks getheaders responses to non-Download peers when the active chain is below MinimumChainWork. Ouroboros has no such gate, so a fresh-IBD ouroboros (which IS below MinimumChainWork on its first hour) cheerfully serves getheaders responses to anyone — amplifying the headers-spam attack surface that Core's gate exists to dampen. |
| 6 | `BLOCK_HAVE_DATA`/`HAVE_UNDO` bitfield + `BLOCK_ASSUMED_VALID` | G20: `BLOCK_HAVE_DATA` set after block body lands on disk | PASS — `types.rs:558-560`; `block.rs:898-902` `status.set_has_data()`. |
| 6 | … | G21: `BLOCK_HAVE_UNDO` set after rev*.dat write | **BUG-15 (P1)** `types.rs:563-565` defines `set_has_undo` but it's **never called** from production code paths. The SPENT_CF undo data is written via `spend_utxo_batch` but `BlockStatus::set_has_undo` is dead. A future `FindFilesToPrune` that wants per-block undo presence has no flag to consult. |
| 6 | … | G22: `BLOCK_ASSUMED_VALID` bit (Core chain.h:67) distinguishes "assumeUTXO-snapshot base" from "fully-validated" | **BUG-16 (P1)** entire bit absent from `BlockStatus`. The 5-bit BLOCK_HAVE/FAILED layout is otherwise Core-compatible (W138 BUG-9 also found this). assumeUTXO snapshot machinery in `snapshot.py` cannot stamp this bit on the snapshot base, so a restart of a node mid-background-validation cannot distinguish snapshot-base blocks from fully-validated ones. |
| 7 | BIP-159 NODE_NETWORK_LIMITED wiring | G23: `nLocalServices |= NODE_NETWORK_LIMITED` when `IsPruneMode()` | **BUG-17 (P0)** `node.py:368-376` constructs `PeerManager` WITHOUT passing `node_network_limited`. The default is `False` (peer.py:298 default). Even with `-prune=550`, peers never see the bit advertised. The full plumbing exists end-to-end (config → node.pruner → peer.our_services), but the ONE WIRE between node and PeerManager is missing — "plumb-gate-then-flip" pattern, 5th instance fleet-wide. |
| 7 | … | G24: BIP-159 peer-served-blocks `getdata` short-circuit on pre-prune-horizon | PARTIAL — `node.py:1029-1054` does the short-circuit, but uses `block.height` attribute that may not be present on cached blocks (older block objects lack `height`); `bh is None` path silently serves the block instead of declining. **BUG-18 (P1)** |
| 7 | … | G25: BIP-159 peer-served-blocks horizon = `tip - 288 - ALLOWED_DRIFT(48)` (Core uses 288 + 48 grace) | **BUG-19 (P1)** `node.py:1027,1033` uses bare 288. Core's `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS` = 288 but `NODE_NETWORK_LIMITED_MIN_BLOCKS` = 288; specifically `setblock_relay_pruning_horizon = tip - 288 + safety` differs by 48. A pruning ouroboros peer disconnect-bans Core peers requesting blocks at `tip - 288 + 5` (within grace). |
| 8 | Two/three-pipeline drift (W143/W144 family) | G26: a single block traverses exactly one validation pipeline | **BUG-20 (P0-CONS)** SIX distinct validate/connect entry points coexist:<br>(a) Python `validation.py::Validator.validate_block` (checkpoint skip_scripts);<br>(b) Rust `BlockValidator::validate_block` (env-var assumevalid_height);<br>(c) Rust `BlockValidator::validate_block_with_flags` (skip_scripts arg, currently unused per `let _ = skip_scripts`);<br>(d) Rust `connect_block_from_bytes` inline consensus (PoW + merkle + MTP + cb-len + witness-commit — `lib.rs:3402-3592`);<br>(e) Rust `connect_blocks_atomic` inline consensus duplicating (d) `lib.rs:3965-4500`;<br>(f) Rust `import_blocks_from_file` calls `validate_block_with_flags(skip=true)` then `connect_block_from_bytes` `lib.rs:4502-4636`. Extends W143's three-pipeline drift to **six pipelines**. |
| 8 | … | G27: skip_scripts argument ACTUALLY skips script verification | **BUG-21 (P0)** `block.rs:261` `let _ = skip_scripts; // reserved for future script-verify gating`. The `validate_block_with_flags` path discards the flag. Production callers pass `skip_scripts=true` expecting cheap structural-only checks; Rust currently runs the same per-tx structural+UTXO+sigop work either way (script verification is unimplemented across the board). Comment-as-confession 8th instance. |
| 8 | … | G28: `OUROBOROS_ASSUMEVALID` env-var stopgap is documented | PARTIAL — `block.rs:82-92` reads env var, but it ONLY affects Rust pipeline (b/c above). Python pipeline (a) never consults it. A user setting `OUROBOROS_ASSUMEVALID=999999` to bypass scripts gets surprise Python script verification on blocks that fall to pipeline (a) because `validate_block_from_bytes` is not always selected (gated on `route_only and rust_available and skip_scripts` at `block_sync.py:1258`). **BUG-22 (P1)** |
| 8 | … | G29: prune-and-reindex round-trip resumes correctly | **BUG-23 (P0)** `--reindex` is a no-op marker (`cli.py:477-490` literally logs "acknowledged but not implemented"). Combining `--prune=550 --reindex` is the standard recovery path for a corrupted chainstate; ouroboros operators have no analog. Core treats this as the primary recovery surface for storage bugs. |
| 8 | … | G30: prune+reindex race: prune doesn't fire while reindex is reading old block files | **BUG-23 cross-cite** — no race possible because reindex is absent. But the same class of bug would apply if reindex landed: `_periodic_tasks` at `node.py:643` fires `prune_to_target` every tick with no lock against any other consumer of blk*.dat files (the assumeUTXO snapshot reader, `dumptxoutset`, etc.). |

---

## BUG-1 (P0-CDIV) — No `--prune` / `--prune-keep-blocks` CLI flag

**Severity:** P0-CDIV. Bitcoin Core exposes `-prune=N`, `-prune=0` (off),
`-prune=1` (manual sentinel) on the command line. Ouroboros's `cli.py`
(audited 1-490, full grep) defines `--reindex`, `--rpc-tls-cert`,
`--rpc-tls-key`, `--peerbloomfilters`, `--blockfilterindex`, `--cfilter`,
`--daemon`, `--pid`, etc. — but no `--prune`, no `--prune-keep-blocks`,
no `--assumevalid`, no `--minimumchainwork`. The only way to enable
pruning is via the `prune=N` key in `ouroboros.conf` (config-file only).

**File:** `src/ouroboros/cli.py` (no `--prune` option anywhere
in the 969-line file).

**Core ref:** `bitcoin-core/src/init.cpp:524`,
`bitcoin-core/src/node/blockstorage.cpp:1225`.

**Impact:** Operators relying on Core-style CLI invocation
(`ouroboros start --prune=550 --network=mainnet`) get a Click "no such
option" error. Ops scripts ported from Core need rewriting to push the
value through a config file. **Cross-impl partition risk**: a deployment
where Core was reconfigured by passing `-prune=10000` would not silently
fail; ouroboros would.

---

## BUG-2 (P0-CDIV) — `-prune=N` unit divergence: MB (10^6) vs MiB (2^20)

**Severity:** P0-CDIV (units-divergence). Bitcoin Core's `-prune=N` is
in **MiB** (binary mebibytes, 1024 × 1024 = 1_048_576 bytes). Ouroboros's
`BlockPruner.__init__` (`pruning.py:109`):

```python
self.target_size = max(target_size_mb, self.MIN_TARGET_MB) * 1_000_000
```

multiplies by **decimal megabytes** (10^6). For `-prune=1000`:
- Core: 1000 × 1_048_576 = 1_048_576_000 bytes (~1000 MiB)
- ouroboros: 1000 × 1_000_000 = 1_000_000_000 bytes (~954 MiB)

Then Rust's `prune_to_target` (`blockstore.rs:930`) clamps:
```rust
let target = target_bytes.max(Self::MIN_DISK_SPACE_FOR_BLOCK_FILES);  // 550 MiB
```
For `-prune=550`: Python computes 550_000_000, Rust silently up-clamps
to 576_716_800 (550 MiB). The Python-supplied target was 524 MiB but
the actual on-disk target is 550 MiB.

**File:** `src/ouroboros/pruning.py:55, 109, 164, 197`;
`ferrous-utils/sync/src/storage/blockstore.rs:750, 930`.

**Core ref:** `bitcoin-core/src/init.cpp:524`,
`bitcoin-core/src/node/blockstorage.cpp:1225`.

**Impact:** A user setting `-prune=10000` on Core (10 GiB on-disk) and
`-prune=10000` on ouroboros gets 9.54 GiB on the same hardware — a 5%
divergence that an ops dashboard tracking "disk used by prune target"
would flag as a misconfiguration but is actually a per-impl unit
divergence. Carry-forward W146 BUG-15 (open ~2 weeks; same path).

---

## BUG-3 (P0-CDIV) — `pruned=true` in `getblockchaininfo` requires actual pruning, not prune mode

**Severity:** P0-CDIV. Core's `getblockchaininfo` reports
`pruned: true` for any node with `IsPruneMode() == true` —
i.e., any non-zero `-prune` value at startup, INCLUDING the manual
sentinel `-prune=1` and `-prune=550` even on a freshly-started node
with 0 bytes pruned. Ouroboros (`rpc.py:1416`):

```python
pruner = getattr(self.node, "pruner", None)
pruned = pruner is not None and pruner.prune_height > 0
```

requires `prune_height > 0`, which is the height of the LOWEST
available block. On a fresh prune-mode node before the first prune
event, `prune_height` is the lowest stored height (typically 0 if
synced from genesis) → `pruned=False`.

**File:** `src/ouroboros/rpc.py:1416`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:1452-1456`
(`automatic_pruning = (GetPruneTarget() != PRUNE_TARGET_MANUAL)`;
`prune_target_size` is set whenever automatic_pruning is true).

**Impact:** Wallets, monitoring, and BIP-159 client logic that consult
`getblockchaininfo.pruned` to decide whether to ask this node for
historical blocks will mistakenly believe a prune-mode ouroboros can
serve any block — until the first prune fires. Then the field flips,
behavior changes mid-session. Operators who run `bitcoin-cli
getblockchaininfo` to verify their `-prune=550` config landed see
`pruned=false` and re-do their config thinking it didn't take.

Companion miss: Core's `prune_target_size` field (bytes) is also absent
from the response. Ouroboros emits `target_size`, `keep_blocks` via
`pruner.get_prune_info()` (`pruning.py:217-230`) — different field
names, different units (target_size is in BYTES via the off-by-MiB
Python target).

---

## BUG-4 (P1) — `-prune=N` between 1 and 549 silently promoted, not rejected

**Severity:** P1. Core's init refuses to start with a prune target
below `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB` (init.cpp:528 throws
`InitError`). Ouroboros (`pruning.py:109`):

```python
self.target_size = max(target_size_mb, self.MIN_TARGET_MB) * 1_000_000
```

silently promotes any value ≥ 2 to 550 (the sentinel `1` is caught at
`pruning.py:108` for manual mode). No log, no warning, no startup
refusal. An operator who passes `-prune=100` (intending 100 MiB)
unknowingly enables 524 MB auto-pruning.

**File:** `src/ouroboros/pruning.py:108-109`.

**Core ref:** `bitcoin-core/src/init.cpp:528`.

**Impact:** Silent operator misconfiguration; symptom is "I asked for
100 MB and disk is at 550 MB and growing".

---

## BUG-5 (P0) — `pruneblockchain` RPC missing height/timestamp dual-mode

**Severity:** P0 (RPC contract). Core's `pruneblockchain(N)`:
- N ≤ 10^9 → height (block N is the highest to prune).
- N > 10^9 → Unix timestamp; walks `FindEarliestAtLeast(N - 7200, 0)`
  and converts to a height (`bitcoin-core/src/rpc/blockchain.cpp:941-948`).

Ouroboros (`rpc.py:6234-6263`):

```python
async def rpc_pruneblockchain(self, height: int) -> int:
    ...
    actual_height = pruner.prune_to_height(height, best_height)
```

always treats the input as a height. A wallet that issues
`pruneblockchain(<unix_timestamp>)` (a common pattern — "prune
everything older than X") interprets the timestamp as a height ≫ chain
height; Python's `prune_to_height` clamps to `current_height -
keep_blocks` and silently does the wrong thing.

**File:** `src/ouroboros/rpc.py:6234-6263`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:939-948`.

**Impact:** Wallet-server integrations that follow the Core protocol
break or silently misbehave on ouroboros. Cross-impl RPC parity gap.

---

## BUG-6 (P0-CDIV) — `pruneblockchain` accepts negative + oversized heights without rejection

**Severity:** P0-CDIV. Core throws:
- `RPC_INVALID_PARAMETER` on `heightParam < 0`.
- `RPC_INVALID_PARAMETER` on `height > chainHeight`.
- `RPC_MISC_ERROR` on `chainHeight < PruneAfterHeight()` ("Blockchain is too short for pruning").

Ouroboros (`rpc.py:6234-6263`) does **no input validation at all**.
A negative height (`int`) gets passed to Rust's
`pruner.prune_to_height(height, best_height)`. Inside Rust
(`blockstore.rs:972-1008`), `target_height: u32` — Python's `pyo3`
overflow check will RuntimeError, but the JSON-RPC client sees a
generic 500 instead of `RPC_INVALID_PARAMETER`. Over-sized integers
silently clamp.

**File:** `src/ouroboros/rpc.py:6258-6263`;
`ferrous-utils/sync/src/storage/blockstore.rs:972-1008`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:934-958`.

**Impact:** RPC clients written against Core's error codes get
different error responses. Negative-height fuzz crashes the FFI layer
rather than returning a structured JSON error.

---

## BUG-7 (P0) — Prune fires against active tip not `m_best_header->nHeight` during IBD

**Severity:** P0 (semantic divergence). Core's `FindFilesToPrune`
(blockstorage.cpp:338):

```cpp
const uint64_t target_sync_height = chainman.m_best_header->nHeight;
...
if (chainman.IsInitialBlockDownload() && target_sync_height > (uint64_t)chain_tip_height) {
    // Since this is only relevant during IBD, we assume blocks are at least 1 MB on average
    static constexpr uint64_t average_block_size = 1000000;
    const uint64_t remaining_blocks = target_sync_height - chain_tip_height;
    nBuffer += average_block_size * remaining_blocks;
}
```

uses `m_best_header->nHeight` (the target tip we're syncing toward)
to compute the IBD buffer, so blocks near the active tip are NOT
pruned while there's still chain to download.

Ouroboros (`node.py:684`):

```python
removed_files, bytes_freed = self.pruner.prune_to_target(best_height)
```

passes the active tip height — there is no `target_sync_height`
equivalent. During mid-IBD with active=100k and best_header=900k,
prune horizon is computed as 100k − 288 = 99,712. Files containing
blocks 0..99,712 become eligible for prune even though we still need
them in case of a deep IBD-time reorg (admittedly rare, but Core's
buffer accounts for it). More critically, the prune fires at all
during IBD — Core's IBD-buffer scaling
(`average_block_size * remaining_blocks`) essentially disables
auto-pruning until close to tip, deliberately reserving the prune
disk-IO budget for post-IBD steady state.

**File:** `src/ouroboros/node.py:643-693`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:336-394`.

**Impact:** Mid-IBD ouroboros prune-mode nodes do significantly more
disk-IO (constant prune events) than Core, slowing IBD. A mid-IBD
deep reorg becomes unrecoverable because the rev*.dat files have been
deleted.

---

## BUG-8 (P0-CDIV) — assumevalid gate uses HEIGHT not block hash

**Severity:** P0-CDIV. Core's assumevalid (`validation.cpp:2346-2382`)
gate is keyed by the **HASH** of `m_chainman.AssumedValidBlock()`
(default-supplied per release in chainparams.cpp). The 5 preconditions
ensure the assumevalid hash is on the active chain AND on the best
header chain AND not too recent vs best header AND chainwork above
`MinimumChainWork`.

Ouroboros uses **height-only** gates in **both** pipelines:
- Python (`validation.py:815`, calling `can_skip_scripts_for_block`)
  → `chain_params.rs:257` `is_below_last_checkpoint(network, height)`
  → checkpoint height comparison.
- Rust (`block.rs:142, 170`) → `assumevalid_height` from env-var or
  per-network default (`938_343` for mainnet — that's a HEIGHT, not
  the hash of block 938343).

There is no `AssumedValidBlockHash` table anywhere. The Rust default
height 938_343 was chosen to roughly match Core v28's
`defaultAssumeValid` block (which IS block 938343 on mainnet), but
ANY block at that height passes the skip gate — including a fork
block whose hash differs from the canonical one.

**File:** `src/ouroboros/validation.py:807-823`;
`ferrous-utils/sync/src/validate/block.rs:82-156`;
`ferrous-utils/sync/src/chain_params.rs:138-141, 257-261`.

**Core ref:** `bitcoin-core/src/validation.cpp:2344-2382`;
`bitcoin-core/src/kernel/chainparams.cpp:312` (`defaultAssumeValid` hash).

**Impact:** During a contentious chain split at or below assumevalid
height, an ouroboros node connecting to a peer serving the losing
fork will skip script verification on the losing fork's blocks. Core
would NOT skip because the losing-fork blocks are not ancestors of
`AssumedValidBlock()`. The losing-fork attacker can include
unverifiable scriptSigs that pass the skipped-script path — pure
funds-loss / counterfeit-coin primitive on ouroboros, no-op on Core.

---

## BUG-9 (P0-CDIV) — assumevalid skip gate has no MinimumChainWork sanity

**Severity:** P0-CDIV. Core's precondition 5
(`validation.cpp:2362-2363`):

```cpp
} else if (m_chainman.m_best_header->nChainWork < m_chainman.MinimumChainWork()) {
    script_check_reason = "best header chainwork below minimumchainwork";
}
```

ensures we never skip scripts while the best-header chain has below
`MinimumChainWork()` work — a tip-eclipse attacker can NOT bootstrap
a fork with `< nMinimumChainWork` and force skip-script.

Ouroboros's gates (Python via checkpoint, Rust via env+height) make
NO such sanity check. A freshly-started ouroboros node fed a low-work
header chain by an eclipse-attacker will happily skip scripts on the
attacker's blocks if their heights fall below the checkpoint or
`assumevalid_height`.

**File:** `src/ouroboros/validation.py:807-823`;
`ferrous-utils/sync/src/validate/block.rs:167-212`.

**Core ref:** `bitcoin-core/src/validation.cpp:2362-2363`.

**Impact:** Eclipse-attack amplification: combined with BUG-8 (no
ancestor check) and BUG-14 (no MinimumConnectedChainWork getheaders
gate), an attacker can serve a fake low-work chain that ouroboros
skip-validates entirely.

---

## BUG-10 (P0-CDIV) — assumevalid skip gate has no 2-week equivalent-time sanity

**Severity:** P0-CDIV. Core's precondition 6
(`validation.cpp:2364-2365`):

```cpp
} else if (GetBlockProofEquivalentTime(*m_chainman.m_best_header, *pindex,
                                       *m_chainman.m_best_header, params.GetConsensus()) <= TWO_WEEKS_IN_SECONDS) {
    script_check_reason = "block too recent relative to best header";
}
```

discourages a hash-power-extortion attack: an attacker who manages to
get ouroboros to advance `defaultAssumeValid` (via release-pressure
or version-bumping) within 2 weeks of any block they've mined would
otherwise have a window to slip an invalid-script block through.
Core forces a 2-week burial.

Ouroboros has no such gate. The Rust env-var `OUROBOROS_ASSUMEVALID=N`
takes effect immediately; an operator under attacker influence can
set it to a recent height and start skipping scripts on blocks mined
days ago.

**File:** `src/ouroboros/validation.py:807-823`;
`ferrous-utils/sync/src/validate/block.rs:82-92`.

**Core ref:** `bitcoin-core/src/validation.cpp:2364-2365`.

**Impact:** Removes a defense that exists explicitly to make
hash-power-coercion of assumevalid harder.

---

## BUG-11 (P0-CDIV) — `defaultAssumeValidBlockHash` table absent fleet-side

**Severity:** P0-CDIV (architectural). Bitcoin Core ships per-network
hex hashes (`bitcoin-core/src/kernel/chainparams.cpp:312` mainnet,
:456 testnet3, :537 regtest), updated in each release. Ouroboros
substitutes per-network **heights** (`block.rs:138-141`):

```rust
Network::Bitcoin => 938_343,   // Bitcoin Core v28 default assumevalid
Network::Testnet4 => 123_613,  // Testnet4 assumevalid
_ => 0,                        // Validate everything on other networks
```

with a comment claiming Core-parity but actually shipping just a
height. The block at height 938_343 on mainnet IS what Core uses, but
ouroboros never verifies the block AT that height matches the hash
Core ships.

**File:** `ferrous-utils/sync/src/validate/block.rs:131-156`;
`ferrous-utils/sync/src/chain_params.rs` (no `default_assume_valid`
function defined).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:312, 456, 537`.

**Impact:** Pre-condition for all of BUG-8/9/10. Fixing the gate
without first fixing the data table is impossible.

---

## BUG-12 (P0-CDIV) — `FastSync.is_synced()` is hardcoded to return `false`

**Severity:** P0-CDIV (operational catastrophe). At
`ferrous-utils/sync/src/lib.rs:5912-5916`:

```rust
fn is_synced(&self) -> PyResult<bool> {
    // For now, return false (in practice would check against network tip)
    // This is a simplified version
    Ok(false)
}
```

Comment-as-confession (8th instance fleet-wide). This is the only
back-end for `SyncManager.is_synced` → `BitcoinNode._check_synced` →
`BitcoinNode.synced` → `RPC._is_synced` → `getblockchaininfo.initialblockdownload`.

Every consumer sees `initialblockdownload=true` PERMANENTLY, even on
a node sitting at tip for weeks. Downstream effects:
- `verificationprogress` always estimates IBD progress (rpc.py:1463).
- The mempool acceptance gates that consult is_ibd take the IBD path.
- Fee estimator (W139) thinks every block is mid-IBD.
- BIP-159 advertisement gating, sendheaders gating (W136) — all
  driven off the wrong is_ibd value.
- Pruning auto-trigger fires constantly because the IBD-buffer
  scaling (which Core uses to disable auto-prune mid-IBD) is missing
  (BUG-7).

**File:** `ferrous-utils/sync/src/lib.rs:5912-5916`.

**Core ref:** `bitcoin-core/src/validation.cpp:3283-3291`
(`UpdateIBDStatus` — `IsTipRecent(MinimumChainWork(), max_tip_age)`).

**Impact:** Architectural — the IBD state machine doesn't exist.
Two-week-old mainnet tip with all checkpoints crossed and chainwork
≥ MinimumChainWork still reports `initialblockdownload=true`. Live
production bug since W113 (when the comment was first added per
`lib.rs:5913`).

---

## BUG-13 (P0) — No `MinimumConnectedChainWork` analog for peer-level chain selection

**Severity:** P0. Core's `MinimumConnectedChainWork`
(`net_processing.cpp:2643`):

```cpp
return std::max(near_chaintip_work, m_chainman.MinimumChainWork());
```

is used by `FindNextBlocksToDownload` (net_processing.cpp:1406) to
gate which peer's best-known-block is worth downloading from. A peer
whose `pindexBestKnownBlock->nChainWork < MinimumConnectedChainWork()`
is skipped entirely.

Ouroboros's header-batch gate (`block_sync.py:1797-1840`) checks
post-acceptance and rolls back; there's no pre-acceptance peer-level
gate. A peer announcing a low-work chain gets full headers download
attention before ouroboros rolls back.

**File:** `src/ouroboros/block_sync.py:1797-1840`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1406, 2643, 2928`.

**Impact:** Increased bandwidth/CPU during eclipse-attack scenarios;
ouroboros downloads then rejects, Core never downloads.

---

## BUG-14 (P0) — Low-work-tip ouroboros serves getheaders responses to anyone

**Severity:** P0. Core (`net_processing.cpp:4328`) refuses to
serve `getheaders` to a non-Download-permission peer when the active
tip is below `MinimumChainWork`:

```cpp
if ((m_chainman.ActiveTip()->nChainWork < m_chainman.MinimumChainWork() &&
     !pfrom.HasPermission(NetPermissionFlags::Download))) {
    LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d because active chain has too little work; sending empty response\n", pfrom.GetId());
    return;
}
```

A fresh ouroboros node syncing from genesis IS below MinimumChainWork
for hours; Core deliberately avoids amplifying header-spam by not
responding. Ouroboros has no equivalent gate in
`HandleGetHeaders`.

**File:** grep `HandleGetHeaders` in `src/ouroboros/p2p.py`,
`src/ouroboros/block_sync.py` — no MinimumChainWork-vs-active-tip
gate found.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4317-4329`.

**Impact:** Fresh ouroboros nodes consume more bandwidth processing
getheaders queries that Core would short-circuit. Headers-spam
amplification vector during initial sync window.

---

## BUG-15 (P1) — `BlockStatus::set_has_undo()` defined but never called

**Severity:** P1. `ferrous-utils/common/src/types.rs:563-565`:

```rust
pub fn set_has_undo(&mut self) {
    self.0 |= Self::BLOCK_HAVE_UNDO;
}
```

The flag bit (16) is defined; the setter is defined; the read accessor
`has_undo()` is defined. But the WRITE path is never invoked from
production code. `BlockValidator::apply_block` (block.rs:898-902) calls
only `status.set_has_data()`. SPENT_CF undo data IS written (via
`spend_utxo_batch`), but the per-block status bit isn't updated.

**File:** `ferrous-utils/common/src/types.rs:562-565`;
`ferrous-utils/sync/src/validate/block.rs:898-902`.

**Core ref:** `bitcoin-core/src/chain.h:84` (`BLOCK_HAVE_UNDO`);
`bitcoin-core/src/validation.cpp:2738` (set after `WriteUndoDataForBlock`).

**Impact:** Dead-field; future `FindFilesToPrune` enhancement that
wants to consult per-block undo presence (Core's
`pindex->nStatus & BLOCK_HAVE_UNDO`) has nothing to consult. Same
shape as W101 BUG-X / W148 BUG-10 (block-index field absent).

---

## BUG-16 (P1) — `BLOCK_ASSUMED_VALID` bit absent from `BlockStatus`

**Severity:** P1 (W138 cross-cite, also called out at W138 BUG-9).
Core's `chain.h:67` defines `BLOCK_ASSUMED_VALID = 128` — set on
blocks marked valid by virtue of the assumeUTXO snapshot, without
actually being script-verified. Distinguishes
"trust-from-snapshot" from "verified-from-genesis".

Ouroboros's `BlockStatus` (`types.rs:471-565`) defines only:
- `BLOCK_VALID_{TREE,TRANSACTIONS,CHAIN,SCRIPTS}` (1..4 + mask 7)
- `BLOCK_HAVE_{DATA,UNDO}` (8, 16)
- `BLOCK_FAILED_{VALID,CHILD}` (32, 64)

Missing the 128 bit — assumeUTXO snapshot machinery in `snapshot.py`
cannot stamp snapshot-base blocks. Restart of a mid-validation node
cannot distinguish.

**File:** `ferrous-utils/common/src/types.rs:471-565`.

**Core ref:** `bitcoin-core/src/chain.h:67`.

**Impact:** assumeUTXO restart correctness on partial background
validation; W138-tracked gap not yet closed.

---

## BUG-17 (P0) — `NODE_NETWORK_LIMITED` advertisement bit never set even in prune mode

**Severity:** P0 (BIP-159 wire-protocol bug). The full advertisement
plumbing exists end-to-end: `PeerManager(node_network_limited=...)`
→ `self.node_network_limited` → forwarded to every Peer constructor
(`peer.py:332`) → `our_services |= NODE_NETWORK_LIMITED`
(peer.py:759, 1276, 1428). All three handshake paths (inbound,
outbound v1, outbound v2) check the flag.

The ONE missing wire: `BitcoinNode._initialize_subsystems`
(`node.py:368-376`) constructs `PeerManager` without passing
`node_network_limited`. Default at the `PeerManager` signature
(`p2p.py:438`) is `False`. So even when `-prune=550` is set and
`self.pruner is not None`, peers see `services=NODE_NETWORK |
NODE_WITNESS` — no BIP-159 limited bit.

**File:** `src/ouroboros/node.py:368-376` (the missing `node_network_limited`
keyword); should be something like:
```python
self.peer_manager = PeerManager(
    ...,
    node_network_limited=(self.pruner is not None),
)
```

**Core ref:** `bitcoin-core/src/init.cpp:1109-1114`
(`nLocalServices |= NODE_NETWORK_LIMITED` when `IsPruneMode()`).

**Impact:** Wire-protocol divergence: ouroboros prune-mode nodes
LIE on the wire about what blocks they can serve. A Core peer that
checks `services & NODE_NETWORK_LIMITED` to decide whether to issue
`getdata` for old blocks will issue the request — ouroboros's
BIP-159 `getdata` short-circuit (BUG-18, `node.py:1029-1053`) then
emits `notfound`, and the Core peer score-decrements the connection.
Eventually disconnect-and-ban from honest Core peers for serving
NotFound on inv'd blocks. **Pattern: "plumb-gate-then-flip" 5th
fleet instance** (W141 nimrod's `mempoolminfee` divisor; W141
ouroboros's `zmq_publisher` AttributeError; W122 hotbuns wire-up).

---

## BUG-18 (P1) — BIP-159 getdata short-circuit silently serves blocks when `height` attr missing

**Severity:** P1. `node.py:1049-1054`:

```python
if block is not None and prune_horizon >= 0:
    # Decline pre-prune-horizon blocks per BIP-159.
    bh = getattr(block, 'height', None)
    if bh is not None and bh < prune_horizon:
        not_found.append((inv_type, inv_hash))
        continue
```

When `block.height` is `None` (legacy cached `Block` objects without
`height`, blocks reconstructed from raw bytes without metadata
fetch), the short-circuit silently SKIPS the prune-horizon check and
serves the block. If the block bytes are still on disk (pre-prune)
this works; if the block file was just pruned and we're serving from
stale cache, we serve corrupt data.

**File:** `src/ouroboros/node.py:1049-1054`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2300-2320` (Core
strictly enforces, never falls through to "serve anyway").

**Impact:** Tiny window: block in cache, height stripped, post-prune
serves stale; small per-impl divergence.

---

## BUG-19 (P1) — BIP-159 horizon uses `tip - 288` not `tip - 288 - GRACE`

**Severity:** P1. Core's `NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 288`
governs the advertised window, but the actual peer-serving gate uses
a small additional grace to avoid disconnect-races during chain
extension. Ouroboros (`node.py:1027, 1033`):

```python
MIN_BLOCKS_TO_KEEP = 288
...
if best_h is not None and best_h > MIN_BLOCKS_TO_KEEP:
    prune_horizon = best_h - MIN_BLOCKS_TO_KEEP
```

uses bare 288. A Core peer requesting block `tip - 287` 5 seconds
after we advanced tip (so we technically still have it) — Core's
`NODE_NETWORK_LIMITED_MIN_BLOCKS` is 288 but the peer-served-blocks
gate is `min(tip-288, last_blk_we_have)` with implicit grace from
the fact that the file containing tip-288 also contains tip-287..tip.
Ouroboros's strict `bh < 288` cuts the block exactly at the boundary.

**File:** `src/ouroboros/node.py:1023-1054`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2300-2320`.

**Impact:** Minor — peer-server churn at the boundary; not a chain
correctness issue.

---

## BUG-20 (P0-CONS) — SIX-pipeline validate/connect drift; extends W143's three-pipeline to six

**Severity:** P0-CONS. W143/W144 found ouroboros's "three-pipeline
drift" (Python validate, Rust validate, Rust mining). W149 expands
the count to **SIX** distinct entry points for "validate this block
and connect it":

1. **Python** `Validator.validate_block` + `validator.apply_block`
   (`validation.py`); skip_scripts gated on `can_skip_scripts_for_block`.
2. **Rust** `BlockValidator::validate_block` (`block.rs:167-233`);
   skip_scripts gated on `assumevalid_height` (env-var override).
3. **Rust** `BlockValidator::validate_block_with_flags`
   (`block.rs:255-397`); explicit `skip_scripts` arg — currently
   IGNORED via `let _ = skip_scripts`.
4. **Rust** `connect_block_from_bytes` inline consensus checks
   (`lib.rs:3402-3592`) — PoW + merkle + MTP + cb-len + witness
   commitment; does NOT call `BlockValidator`.
5. **Rust** `connect_blocks_atomic` inline consensus checks
   (`lib.rs:3965-4500`) — duplicates (4); 600+ lines of consensus
   logic byte-for-byte.
6. **Rust** `import_blocks_from_file` (`lib.rs:4502-4636`); calls
   `validate_block_with_flags(skip_scripts=true)` then
   `connect_block_from_bytes` — combines (3) and (4) but the
   `skip_scripts=true` is hard-coded regardless of assumevalid state.

The Python pipeline (`block_sync.py:1086-1334`) selects ONE of (1),
(2), or (3) per block via env vars `OUROBOROS_VALIDATE_CROSS_CHECK`
and `OUROBOROS_DISABLE_RUST_VALIDATE`, then ALWAYS calls (4) to
connect. So a single block touches at minimum two different
consensus pipelines.

**File:** see Files audited above.

**Core ref:** Bitcoin Core has ONE pipeline — `ProcessNewBlock` →
`AcceptBlock` → `ConnectBlock` → `ConnectTip`. All other entry
points funnel through.

**Impact:** Class-defect — any consensus bug fixed in pipeline (1)
must be ported to (2), (3), (4), (5), (6) independently. Concrete
divergences already exist:
- Coinbase-amount check is in (2), (3) but not (4), (5).
- BIP-30 check is in (2), (3) but not (4), (5).
- BIP-68 sequence locks are in (3), partially in (1), absent from
  (4), (5).
- Sigop budget is in (2), (3), absent from (4), (5).

A miner submitting a block via `submitblock` (which routes through
(4) `connect_block_from_bytes`) bypasses BIP-30, BIP-68, sigop, and
coinbase-amount checks. Same shape as W143 BUG-7 ouroboros
`connect_block_from_bytes` HALF-FINISHED pipeline — confirmed STILL
PRESENT and now also tracked in `connect_blocks_atomic` (which
duplicates the half-finished checks).

---

## BUG-21 (P0) — `validate_block_with_flags(skip_scripts=…)` IGNORES the flag

**Severity:** P0 (semantic divergence). `block.rs:255-262`:

```rust
pub fn validate_block_with_flags(
    &self,
    block: &BlockWrapper,
    prev_height: u32,
    skip_scripts: bool,
) -> Result<()> {
    let _ = skip_scripts; // reserved for future script-verify gating
```

The docstring promises script-skip semantics; the body discards the
flag. Callers that pay extra latency to compute `skip_scripts`
correctly (e.g., `block_sync.py:1112-1120`'s `_run_rust` lambda
hard-coding `True`) get neither performance nor semantic benefit.
Above-checkpoint blocks that should have scripts verified — DON'T,
because (a) Rust never verifies scripts in this pipeline regardless
of the flag, and (b) the Python `block_sync.py:1258` gate
`route_only and rust_available and skip_scripts` only routes through
Rust when skip_scripts is True, so above-checkpoint blocks go to
Python pipeline (1) instead — but that's a different concern.

Net effect: Rust validate is structurally a no-op on the
script-verification axis. Skip-scripts=True or False, output is
identical. Comment-as-confession (9th instance: "reserved for
future") encodes a behavioral lie.

**File:** `ferrous-utils/sync/src/validate/block.rs:260-262`.

**Core ref:** `bitcoin-core/src/validation.cpp:2494-2515` — `fScriptChecks`
is consulted to decide whether per-tx CheckInputs calls into the
script interpreter (validation.cpp:2574) and whether the parallel
queue is even instantiated (validation.cpp:2515).

**Impact:** Rust validate pipeline (3) is the path most production
blocks traverse (below-checkpoint blocks). All such blocks get
structural-only validation; an attacker who slips a fake-script block
into the below-checkpoint range is undetected by this pipeline. The
checkpoint gate is the only defense — fragile.

---

## BUG-22 (P1) — `OUROBOROS_ASSUMEVALID` env-var stopgap is Rust-only; Python pipeline ignores it

**Severity:** P1. `block.rs:82-92` reads `OUROBOROS_ASSUMEVALID` and
overrides the per-network default — but this is read at
`BlockValidator::new` time and only affects Rust pipelines (2), (3),
(6) — not the Python `Validator.validate_block` pipeline (1) which
gates only on the checkpoint-based `can_skip_scripts_for_block`.

An operator setting `OUROBOROS_ASSUMEVALID=999999` to bypass scripts
for IBD acceleration discovers that:
- Below the last checkpoint (mainnet height ~850k as of W149),
  the env-var lifts the Rust gate to 999k → Rust pipeline runs
  full structural-only on blocks 850k..999k. (But scripts are
  unverified anyway per BUG-21.)
- Above the last checkpoint, `can_skip_scripts_for_block` returns
  `false` regardless of env-var → block routes to Python pipeline
  (1) → full script verification → no speedup.

Configuration that LOOKS like it's enabling assumevalid-bypass
silently has no effect for the blocks that actually matter
(post-checkpoint IBD).

**File:** `ferrous-utils/sync/src/validate/block.rs:82-92`;
`src/ouroboros/validation.py:807-823`;
`src/ouroboros/block_sync.py:1086-1110`.

**Impact:** Operator confusion + IBD performance footgun. Same shape
as W132 OUROBOROS_BIP68_STOPGAP family (env-var papers over a
behavior gap without full plumbing).

---

## BUG-23 (P0) — `--reindex` is a no-op marker; no prune+reindex recovery path

**Severity:** P0 (operational catastrophe). `cli.py:477-490`:

```python
if reindex:
    # Honest-progress marker.  See --reindex help text and CLAUDE.md
    # ops-parity audit: full reindex is deferred — operators wanting
    # to clear and rebuild can use ``ouroboros sync --reset``.
    console.print(
        "[yellow]⚠ --reindex acknowledged but not implemented; full block "
        "reindex is deferred. Use 'ouroboros sync --reset' to clear "
        "chainstate and re-IBD.[/yellow]"
    )
```

The standard Core recovery from chainstate corruption is
`bitcoind -prune=550 -reindex`. Ouroboros parses the flag, prints a
warning, ignores it, and continues startup. The suggested workaround
`ouroboros sync --reset` clears the chainstate but ALSO would re-download
all blocks from peers — which a prune-mode node literally cannot do
because most peers don't serve historical data.

**File:** `src/ouroboros/cli.py:428-490`.

**Core ref:** `bitcoin-core/src/init.cpp:1075-1100` (`-reindex`
triggers `BlockManager::ImportBlocks` over local blk*.dat files).

**Impact:** Pruned-mode ouroboros nodes that suffer ANY chainstate
corruption have NO in-band recovery path. They must be re-IBDed from
scratch (impossible without a full archival peer connection) or
restored from off-host backup. Core's `-reindex` walks the existing
local blk*.dat files to rebuild chainstate, which works even on
pruned nodes (within the prune horizon).

Cross-cite: same recovery-gap shape as the smaller-scope W138 dead-class
patterns. Companion bug to BUG-17 (BIP-159 wire-bit absent), W109
(block-index serialization absent — chainstate corruption fix would
land via reindex but no reindex exists).

---

## Fleet-pattern smells

- **Comment-as-confession** (3× this audit): (i) `lib.rs:5913`
  `// For now, return false (in practice would check against network tip)`
  → BUG-12 IBD never exits; (ii) `block.rs:261`
  `let _ = skip_scripts; // reserved for future script-verify gating`
  → BUG-21 flag silently discarded; (iii) `block.rs:147` log claims
  "assumevalid enabled — skipping script/input validation for blocks
  ≤ height N" — but Rust does not verify scripts in either branch
  (`script::verify_*` never called from validate path).
- **Plumb-gate-then-flip** (BUG-17, 5th fleet instance): full BIP-159
  wire chain exists, single wire missing at `node.py:368-376`. One
  keyword arg fix would land the bit.
- **Two/three/SIX-pipeline drift** (BUG-20, **first six-pipeline
  finding fleet-wide**): extends W143 three-pipeline to six;
  ouroboros now holds the fleet record for "number of consensus
  pipelines coexisting in one impl".
- **Env-var stopgap papering over a structural gap** (BUG-22, 2nd
  instance after W132 `OUROBOROS_BIP68_STOPGAP`): `OUROBOROS_ASSUMEVALID`
  only affects Rust-side default; operators expecting cross-pipeline
  effect get silent surprise.
- **Hardcoded constants that should be per-network** (BUG-2 carry-forward;
  W123 BlockSubsidy halving fleet-wide pattern; W149 instance:
  `MIN_BLOCKS_TO_KEEP=288` defined in three places: `config.py:26`
  Python; `pruning.py:76` Python; `blockstore.rs:747` Rust — drifting
  is one rename away).
- **Dead-data / dead-helper** (BUG-15 `set_has_undo`; BUG-16
  `BLOCK_ASSUMED_VALID` absent; BUG-23 `--reindex` is a no-op marker):
  ouroboros has 3 dead-or-missing fields in this single wave; cumulative
  per-impl record in the W76+ tracking.
- **`pruneblockchain` lacks Core's dual-mode** (BUG-5) and **input
  validation** (BUG-6): RPC-shape divergence fleet-pattern; 6th impl
  to confirm `pruneblockchain` RPC parity gap (W146 blockbrew, W123
  hotbuns prior).
- **Carry-forward W146** (BUG-2 MiB vs MB units): ~2 weeks open, prior
  audit flagged, no fix; same fix surface ~1 line.
- **Comment-as-confession 8th instance fleet-wide** (BUG-12): the
  `is_synced` function literally describes the bug it perpetuates.
- **30-of-30 GATES** — not fired (this audit has 23 BUGs across 8
  behaviours; BUG-12 IBD-never-exits is bad enough to single-handedly
  warrant a separate "subsystem rewrite" finding under the
  W138/W139/W141 "30-of-30" archetype).

---

## Summary

23 P0/P1-class divergences across 8 behaviours:

- **P0-CONS** (consensus-divergent in production): 1 — BUG-20 (six-pipeline)
- **P0-CDIV** (consensus-divergent / wire-divergent / units-divergent): 7 —
  BUG-1, BUG-2, BUG-3, BUG-6, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12
- **P0** (semantic gap with operational impact): 7 — BUG-5, BUG-7,
  BUG-13, BUG-14, BUG-17, BUG-21, BUG-23
- **P1** (correctness / wire-protocol / dead-data): 6 — BUG-4, BUG-15,
  BUG-16, BUG-18, BUG-19, BUG-22

Highest-leverage fixes (by effort × severity):
1. **BUG-12** — wire `FastSync.is_synced` to consult
   `m_chainman.IsTipRecent(MinimumChainWork, max_tip_age)`-equivalent
   (chainwork compare + tip age check). ~15 LOC in `lib.rs:5912`.
   Single-handedly fixes is_ibd everywhere downstream.
2. **BUG-17** — one keyword arg at `node.py:368-376`:
   `node_network_limited=(self.pruner is not None)`. Fixes BIP-159
   wire-protocol divergence. 1 line.
3. **BUG-2** — change `* 1_000_000` to `* 1024 * 1024` in
   `pruning.py:109`. Closes W146 carry-forward. 1 line.
4. **BUG-3** — change `pruned = pruner is not None and pruner.prune_height > 0`
   to `pruned = pruner is not None` (`rpc.py:1416`). 1 line.
5. **BUG-11** — add `default_assume_valid_hash(network) -> [u8; 32]`
   table in `chain_params.rs`, switch `block.rs` to consult it.
   Pre-req for BUG-8/9/10. ~30 LOC.
6. **BUG-21** — actually consult `skip_scripts` in `block.rs:260` (or
   delete the parameter and rename to be honest). ~10 LOC.
7. **BUG-20** — architectural: consolidate the six pipelines behind
   ONE `BlockValidator::validate_and_connect` entry point.
   ~200 LOC, but closes 4 of the W143 BUG-7 carry-forwards.

P0-CONS density: 1 — high-value `BlockValidator::validate_block_with_flags`
ignored-flag plus six-pipeline drift makes this the most-architecturally-broken
ouroboros audit since W143.
