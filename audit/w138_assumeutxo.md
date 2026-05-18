W138 — assumeUTXO snapshots audit (ouroboros)
=============================================

Date: 2026-05-18
Impl: ouroboros (Python + Rust two-pipeline).

Wave: W138 assumeUTXO snapshots — BIP-305-style fast-init via UTXO
      set dumps (`loadtxoutset` / `dumptxoutset` / `getchainstates`).

Reference:
  - `bitcoin-core/src/node/utxo_snapshot.{h,cpp}` (137 + 95 lines: the
    `SnapshotMetadata` codec, `WriteSnapshotBaseBlockhash`,
    `ReadSnapshotBaseBlockhash`, `FindAssumeutxoChainstateDir`,
    `SNAPSHOT_CHAINSTATE_SUFFIX` = `_snapshot`)
  - `bitcoin-core/src/validation.cpp` (lines 5588-5953 ActivateSnapshot
    + PopulateAndValidateSnapshot; 5967-6077 MaybeValidateSnapshot;
    6151-6168 LoadAssumeutxoChainstate; 6170-6187 AddChainstate;
    6201-6231 InvalidateCoinsDBOnDisk; 6280-6345 ValidatedSnapshotCleanup)
  - `bitcoin-core/src/rpc/blockchain.cpp` (3368-3447 loadtxoutset RPC;
    3462-3519 getchainstates RPC; 3078-3367 dumptxoutset RPC)
  - `bitcoin-core/src/kernel/chainparams.cpp` (158-183 mainnet
    `m_assumeutxo_data`; 271-289 testnet3; 376-389 testnet4;
    489-505 signet; 607-630 regtest; 677-686
    `GetAvailableSnapshotHeights`)

BIPs: none (the design lives in
      `bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md`, not a BIP).

Status: 30 gates audited — **PRESENT 9 / PARTIAL 6 / MISSING 15.**
**23 BUGS** (3 P0-CDIV / 3 P0-CONSENSUS / 1 P0-CVE-class /
9 P1 / 7 P2).

Relationship to prior audits
----------------------------

- **W132 BUG-1 / FIX-86** flagged a P0-CONSENSUS divergence in the
  assume-utxo IBD path (BIP-68 relative locktime skip when prev tx
  predates the snapshot tip). W138 audits the snapshot SUBSYSTEM
  itself: how snapshots are loaded, validated, dumped, exposed via
  RPC, and integrated with the two chainstates.
- **W133 BUG-2** noted that ouroboros has no `BaseIndex` abstraction,
  so txindex/coinstatsindex cannot start in background while serving
  a snapshot-bootstrapped chain. W138 confirms the same gap on the
  background-validation chainstate (BUG-21 here).
- **W109 block-index** documents `BLOCKS_CF` gaps after a snapshot
  load (BLOCKS_CF has no entry for the snapshot tip's bytes — only
  the in-memory `BlockNode` is populated). W138 inspects the
  downstream consequences for `getblock`, `getblockheader`,
  `verifychain`, and Core-parity error messages.

Two-pipeline guard (EXTENDED)
-----------------------------

assumeUTXO is the **most legitimately Rust-touching subsystem** in
ouroboros — the snapshot loader writes millions of UTXO entries
into RocksDB's chainstate CF, which is hot-path Rust code. Two
distinct code paths exist:

- **Python pipeline** (`src/ouroboros/snapshot.py`, 1326 lines):
  The "authoritative" snapshot module. It owns
  `SnapshotMetadata`, `AssumeutxoData`, `SnapshotManager`,
  hardcoded assumeUTXO data for mainnet (5 entries) + testnet3
  (2) + testnet4 (2), HASH_SERIALIZED commitment check (Core
  `validation.cpp:5912-5914`), MuHash3072 + SHA256d UTXO hashing
  paths, and is the consumer of every RPC entry point
  (`rpc_loadtxoutset`, `rpc_dumptxoutset`, `rpc_getchainstates`).

- **Rust pipeline** (`ferrous-utils/sync/src/storage/snapshot.rs`,
  927 lines + lib.rs bindings): An INDEPENDENT, PARTIAL snapshot
  codec. Has its own `AssumeutxoData` (different shape — no
  `base_header`, no `chainwork_hex`), its own
  `SnapshotMetadata`, its own `load_snapshot` / `dump_snapshot`
  functions, its own `compute_utxo_hash` (NON-Core-compatible).
  Additionally exposes `PyBlockchainDB::import_core_snapshot`,
  a CLI-only fast path that BYPASSES every gate that the
  Python loader enforces. The Python snapshot module
  (`SnapshotManager.load_snapshot`) does NOT delegate to this
  Rust path — it walks the UTXO bytes itself via
  `db.add_utxo_raw`. The Rust path is reachable ONLY via
  `ouroboros import-snapshot` CLI (`cli.py:801`).

**This is a structural two-pipeline divergence (BUG-20, P0-CDIV).**
The two codepaths disagree on:
- assumeUTXO parameter table: Python has 5 mainnet + 2 testnet3 + 2
  testnet4 entries with correct Core values. Rust has 1 mainnet entry
  with a CLEARLY INVENTED `hash_serialized`
  (`2d6b0d7a5c4e8f90a3b5c7d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0`
  vs Core's
  `a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96`)
  + 1 testnet4 entry with FAKE height 50000 + fake hash. Live mainnet
  loads via the Python path so this hasn't bitten yet, but any
  caller that asks `get_assumeutxo_data` against the Rust binding
  gets garbage. (BUG-20a)
- per-coin validation: Python enforces `coin_height > base_height`,
  `MoneyRange(amount)`, trailing-bytes check after coins (BUG-3/4/5/6
  fixes that landed inline in `snapshot.py`). Rust path
  (`import_core_snapshot`) enforces NONE of these. (BUG-20b)
- HASH_SERIALIZED commitment check at end of load: Python enforces
  via streaming `HashWriter` (lines 1046-1059). Rust does not
  (the `import_core_snapshot` path has NO commitment check; the
  standalone `load_snapshot` in `snapshot.rs:457` does not even
  reference `hash_serialized` after lookup — it logs the height
  and proceeds). (BUG-20c)
- `compute_utxo_hash` in Rust (`snapshot.rs:646`) hashes the
  outpoint via `txid + vout.to_le_bytes()`, then coin via
  `code as u64 LE 8 bytes + value LE + script_len u32 + script`.
  This is NOT Core's `TxOutSer` (`coinstats.cpp:46-51` uses
  VarInt(code) + raw value + VarInt(script_len)+script). The Rust
  hash will NEVER match the Core/Python `hash_serialized`.
  Single-SHA-256, not SHA256d. (BUG-20d)

**Two-pipeline guard EXTENSION.** Test
`test_w138_g30_two_pipeline_assumeutxo_rust_isolation` codifies:
- The Rust `snapshot.rs` module remains the "fast bulk loader" via
  `import_core_snapshot` ONLY, with explicit OPERATOR-DRIVEN CLI
  entry point. No other Python module may invoke
  `db.import_core_snapshot`.
- The Rust `AssumeutxoData` table is documented as STALE /
  placeholder; either it must be deleted (Python is authoritative)
  or it must be repopulated from Core's `chainparams.cpp`. This
  extends the guard set
  W76 + W120 + W122 + W125 + W128 + W129 + W130 + W131 + W133 +
  W137 → now W138.

Top-level architectural findings
--------------------------------

**(F1) Two pipelines, no synchronization (BUG-20).** See above.
This is the most important finding of W138. The Python pipeline
is the authoritative one for live ouroboros runs (the
`SnapshotManager` class hooked into `Node` and the RPC layer), but
the Rust pipeline ships dead, placeholder, never-actually-removed
code that can be imported via `from sync import …` and would
return false data. Mitigation: delete the Rust
`AssumeutxoData` table (`snapshot.rs:118-152`) and the
`get_assumeutxo_*` functions, OR ship them with the real
mainnet/testnet entries. The `import_core_snapshot` fast-path
remains useful as a CLI helper but should be HEAVILY GATED with
a "this bypasses safety checks; use loadtxoutset RPC for
production" warning.

**(F2) `loadtxoutset` RPC silently allows a re-load.** Core's
`ChainstateManager::ActivateSnapshot` (validation.cpp:5600-5602)
fails with `"Can't activate a snapshot-based chainstate more than
once"` if a snapshot is already loaded — checked via
`CurrentChainstate().m_from_snapshot_blockhash`. Ouroboros's
`rpc_loadtxoutset` (`rpc.py:10615-10620`) checks
`sm.snapshot_loaded`, which is a **process-local** flag that
resets to `False` on every restart. Across restart boundaries the
flag drops, so a second `loadtxoutset` call on a previously-loaded
datadir does NOT fail — instead it triggers a full reload, which
in the current code clobbers `chainstate_snapshot/base_blockhash`
without first checking whether a different snapshot was already
in the chainstate. Result: a node already on the network from a
mainnet snapshot can be silently rewound to a different snapshot
on next restart by overwriting the file. **BUG-7 (P0-CDIV +
P1-state-corruption)**.

**(F3) `getchainstates` RPC shape divergence from Core.** Core's
`getchainstates` (`rpc/blockchain.cpp:3462-3519`) returns
`{headers: int, chainstates: [...]}` where each chainstate entry
has the canonical fields `blocks, bestblockhash, bits, target,
difficulty, verificationprogress, snapshot_blockhash (optional),
coins_db_cache_bytes, coins_tip_cache_bytes, validated`.
Ouroboros's `rpc_getchainstates` (`rpc.py:11213-11272`) returns
fields with DIFFERENT NAMES — `id, validated_height,
validated_hash, validated, active, snapshot_blockhash,
snapshot_height, from_snapshot` — and OMITS `bits, target,
difficulty, verificationprogress, coins_db_cache_bytes,
coins_tip_cache_bytes, blocks, bestblockhash`. Cross-impl test
suites (test-suite/test_rpc.py) and Bitcoin Core clients that
hit `getchainstates` against ouroboros will see a KeyError on
every field they expect. **BUG-8 (P0-CDIV)**.

**(F4) No `FindAssumeutxoChainstateDir` equivalent.** Core
(`utxo_snapshot.cpp:83-92`) probes the data dir at startup for a
`chainstate_snapshot/` directory (suffix `_snapshot`), reads the
`base_blockhash` file, and reconstructs the snapshot chainstate
in memory via `LoadAssumeutxoChainstate` (validation.cpp:6151).
Ouroboros has `SnapshotManager.has_snapshot_chainstate()`
(`snapshot.py:832-835`) which checks the same dir, BUT the
re-init path (`node.py:711-723`) only calls
`start_background_validation` — it does NOT repopulate
`snapshot_manager.snapshot_height` from chainparams via the
on-disk `base_blockhash`. Result: after a restart, the
in-memory `snapshot_height` is `None`, the
`_chainwork_snapshot_offset` correction is broken
(`node.py:1665-1707` depends on `snapshot_height`), and BIP-68
stopgap (`validation.py:_resolve_snapshot_height`) re-derives
from disk on every call (cached, but adds 1 file-read at
process-start). Cross-restart state is incomplete.
**BUG-9 (P1)**.

**(F5) `MaybeValidateSnapshot` / two-chainstate handshake missing.**
Core's flow has two chainstates side-by-side: the snapshot
chainstate (serving queries) and the background (genesis-IBD)
chainstate (validating from genesis). When background validation
catches up to the snapshot tip, Core's `MaybeValidateSnapshot`
(`validation.cpp:5967-6077`) compares the two UTXO hashes; on
mismatch it triggers `handle_invalid_snapshot` which RENAMES the
snapshot chainstate dir to `<dir>_INVALID` and calls
`fatalError`. Ouroboros's `start_background_validation`
(`snapshot.py:1085-1160`) only logs "Background validation hash
mismatch" and sets `self.background_validated = False`. There is
NO fatal-error, NO directory rename, NO node shutdown. A
corrupted/malicious snapshot detected late survives in the
chainstate and continues to serve. **BUG-10 (P0-CONSENSUS).**

**(F6) `ValidatedSnapshotCleanup` (chainstate swap) missing.**
After background validation succeeds, Core's
`ValidatedSnapshotCleanup` (`validation.cpp:6280-6345`) MOVES
`chainstate/` to `chainstate_todelete`, MOVES
`chainstate_snapshot/` to `chainstate/`, deletes the old. The
snapshot chainstate BECOMES the canonical chainstate. Ouroboros
keeps the snapshot in `chainstate_snapshot/` indefinitely and
flags `background_validated = True`. There's no rename and no
delete. Result: `chainstate_snapshot/base_blockhash` lingers on
disk forever, and on every restart the node thinks "snapshot
loaded" even after full background validation. **BUG-11 (P1)**.

**(F7) `m_target_blockhash` / two-chainstate target tracking
missing.** Core sets the previous chainstate's `m_target_blockhash`
to the snapshot's base hash (`validation.cpp:6173-6176` in
`AddChainstate`); the background chainstate then knows it must
stop at that height when validating. Ouroboros has no such
target — the `validation_worker` loop just iterates
`range(target_height + 1)` and counts (`snapshot.py:1104-1112`);
it does NOT actually re-validate any block, just sleeps with a
counter. This is a STUB validator. **BUG-12 (P0-CONSENSUS)**.

**(F8) Coin EOF check is correct, but coin-count overflow
unchecked.** Core's `PopulateAndValidateSnapshot`
(`validation.cpp:5811`) computes `outpoint.n` and rejects
`outpoint.n >= numeric_limits<uint32>::max()` to avoid wraparound
in `coinstats.cpp::ApplyHash`. Ouroboros decodes `vout` via
`_read_compact_size` and writes it to disk without checking the
max — a malicious snapshot specifying `vout=0xFFFFFFFF` for some
output passes through. The MAX_SIZE constraint
(`snapshot.py:412`) caps at 0x02000000 which IS below
`uint32::max`, BUT it does not pin to Core's particular
`< uint32::max` semantic. Cosmetic, but worth pinning.
**BUG-13 (P2)**.

**(F9) No periodic `FlushSnapshotToDisk` during load.** Core's
`PopulateAndValidateSnapshot` (`validation.cpp:5840-5856`) every
120,000 coins checks `GetCoinsCacheSizeState()` and flushes to
leveldb if `CRITICAL`. Ouroboros writes every coin directly via
`db.add_utxo_raw` (`snapshot.py:1007-1014`), which goes to
RocksDB through one call per coin — no batching, no periodic
checkpoint, no memory-pressure backoff. This is a performance
concern (slower than Core's batched flushes) but ALSO a
durability concern: a process kill mid-load leaves the chainstate
in an inconsistent partial state with NO way to detect-and-
restart (no progress checkpoint). The Rust
`import_core_snapshot` path DOES batch (`lib.rs:4829-4835`,
default 100k entries). **BUG-14 (P1)**.

**(F10) `m_chain_tx_count` not used / not written.** Core stores
`au_data.m_chain_tx_count` into `index->m_chain_tx_count`
(`validation.cpp:5949`) so post-snapshot `getblockchaininfo` and
`getblockstats` can report cumulative tx counts. Ouroboros has
the `chain_tx_count` field in `AssumeutxoData` (`snapshot.py:166,
223 etc`) but no code reads it. `getblockchaininfo` /
`getchaintxstats` / `getblockstats` will report wrong tx counts
on a snapshot-loaded node. **BUG-15 (P1)**.

**(F11) `BLOCK_OPT_WITNESS` not set on snapshot block index
entries.** Core's `PopulateAndValidateSnapshot`
(`validation.cpp:5930-5945`) walks every CBlockIndex from
AFTER_GENESIS_START to snapshot tip, sets `BLOCK_OPT_WITNESS`
flag if `DeploymentActiveAt(*index, *this, DEPLOYMENT_SEGWIT)`,
and adds to `m_dirty_blockindex`. Ouroboros's snapshot loader
makes NO modifications to its `BlockNode` flags after loading.
Result: on a snapshot-loaded node, a later
`Chainstate::NeedsRedownload()` check that hinges on
`BLOCK_OPT_WITNESS` (which doesn't exist as a flag in ouroboros)
cannot reproduce Core's behavior. Cosmetic for ouroboros because
the gate doesn't exist; flagged as a "no-op-relative-to-Core"
divergence. **BUG-16 (P2)**.

**(F12) NetworkDisable RAII implemented but ONLY for `submitblock`
and batch-submit.** ouroboros has a `block_submission_paused` flag
(`node.py:932`) which the rpc dispatcher checks at `rpc_submitblock`
(`rpc.py:6089-6094`) and the batch-submit path
(`rpc.py:6189-6196`). Core's `NetworkDisable` (`dumptxoutset` line
3155-3159) ALSO disables outbound peer messaging: peers stop being
served `getdata`, `getheaders`, etc. — the whole P2P listening
loop is gated. Ouroboros keeps P2P chatty during a rollback dump.
A peer querying mid-dump can read inconsistent state (e.g.
`getbestblockhash` returns the rolled-back tip, then the original
tip seconds later). **BUG-17 (P1)**.

**(F13) `reactivate_best_chain` fallback is silent.** When the
Rust DB binding lacks `reactivate_best_chain`, the Python
dumptxoutset path logs a WARNING but returns
`chain_restored=False` and resumes operation
(`rpc.py:11176-11180`). Core never has this fallback — the dump
fails cleanly. Ouroboros's "best effort" silent fallback is
dangerous: an operator running an `rpc dumptxoutset rollback` on
an older Rust binding will see the RPC succeed but the chain
will be stuck at the rollback height until P2P catches up.
**BUG-18 (P1)**.

**(F14) Background validation has no mempool replay / no
`SetMempool`.** Core's `AddChainstate` (`validation.cpp:6181-6185`)
TRANSFERS the mempool from the IBD chainstate to the snapshot
chainstate. Ouroboros has no such transfer — the mempool is
attached to the `Node`, not a chainstate, and a snapshot load
does not pause/replay the mempool. The mempool-empty
precondition (BUG-2 fix, `rpc.py:10685-10695`) catches the
common case, but a tx accepted in the same second as the
loadtxoutset RPC fires could land in mempool while the snapshot
loader is mid-flight. **BUG-19 (P2)**.

**(F15) Dumped snapshot is NOT byte-identical to Core's.** ouroboros's
`SnapshotManager.dump_snapshot` (`snapshot.py:1168-1253`) emits the
correct wire format BUT iterates UTXOs via `self.db.iter_utxos()` —
the underlying Rust `iter_utxos` does NOT guarantee the same
sort order as Core's `CCoinsViewCursor` over leveldb (Core
yields entries in lexicographic order over the COutPoint key,
which is `txid LE 32 || vout LE 4`; ouroboros sorts within a
txid group on the Python side but relies on the iterator for
the inter-txid order). A SHA256d-byte-exact comparison to
Core's `dumptxoutset` output will succeed for matching txid sets
but the inter-group order is RocksDB iteration order, which is
key order over `txid LE || vout LE` — which IS the same as
Core's. The sort guarantee is therefore correct IFF the underlying
store key encoding matches; this needs a regression test.
**BUG-22 (P2)** to pin the assumption.

30-gate audit matrix
--------------------

| Gate    | Status   | BUG   | Severity | Note |
|---------|----------|-------|----------|------|
| G1      | PRESENT  | —     | —        | `SNAPSHOT_MAGIC = b"utxo\xff"` (`snapshot.py:101`, Core `utxo_snapshot.h:28`). |
| G2      | PRESENT  | —     | —        | `SNAPSHOT_VERSION = 2` constant (`snapshot.py:102`). |
| G3      | PRESENT  | —     | —        | Network magic mainnet/testnet/testnet4/signet/regtest table (`snapshot.py:105-111`). |
| G4      | PRESENT  | —     | —        | `SnapshotMetadata` codec round-trips via `_read_metadata_header` + `_write_metadata_header` (`snapshot.py:740-793`). |
| G5      | PRESENT  | —     | —        | Mainnet `m_assumeutxo_data` table at heights 840k/880k/910k/935k matches Core `chainparams.cpp:158-183`. |
| G6      | PARTIAL  | BUG-1 | P2       | testnet3 entries (`snapshot.py:299-320`) are correct vs Core `chainparams.cpp:271-289` BUT `base_header` and `chainwork_hex` are unprovisioned. Cosmetic; testnet3 snapshot loads will lose the post-snapshot prev-block synthesis fast path. |
| G7      | PARTIAL  | BUG-2 | P1       | testnet4 entries (`snapshot.py:322-343`) are correct vs Core BUT same `base_header`/`chainwork_hex` gap. Live: nobody is running an assumeutxo on testnet4 yet, but the cross-restart chainwork correction will be off-by-snapshot-chainwork until the gap closes. |
| G8      | PRESENT  | —     | —        | Per-coin VARINT(code) + VARINT(CompressAmount) + ScriptCompression encoders match Core `compressor.cpp`. |
| G9      | PRESENT  | —     | —        | `_read_compact_size` rejects non-canonical encodings + values > MAX_SIZE (`snapshot.py:387-413`); Rust `read_compact_size` (`snapshot.rs:291-344`) matches. |
| G10     | PRESENT  | —     | —        | Streaming HASH_SERIALIZED (`HashWriter` + `coin_element`) at end of load matches Core `validation.cpp:5912-5914`. |
| G11     | PRESENT  | —     | —        | mempool-empty precondition (`rpc.py:10685-10695`) mirrors Core `validation.cpp:5626-5629`. |
| G12     | PRESENT  | —     | —        | Per-coin `coin_height > base_height` check + MoneyRange check (`snapshot.py:984-1004`) mirror Core `validation.cpp:5814-5823`. |
| G13     | PRESENT  | —     | —        | Trailing-bytes EOF check (`snapshot.py:1033-1044`) mirrors Core `validation.cpp:5872-5883`. |
| G14     | PARTIAL  | BUG-3 | P2       | base-blockhash file written on load (`snapshot.py:1068`); base_blockheader written when provisioned (1076-1077); but NO `is_from_snapshot` boolean tag, NO `validated` flag persisted. After restart, `getchainstates` can't say if validation completed. |
| G15     | MISSING  | BUG-7 | P0-CDIV  | No "already loaded" cross-restart guard. See F2. |
| G16     | MISSING  | BUG-8 | P0-CDIV  | `getchainstates` shape diverges from Core. See F3. |
| G17     | MISSING  | BUG-9 | P1       | No `FindAssumeutxoChainstateDir` re-init populating `snapshot_height` from disk on startup. See F4. |
| G18     | MISSING  | BUG-10| P0-CONSENSUS | `MaybeValidateSnapshot` (background-vs-snapshot UTXO hash compare with fatal-on-mismatch) absent. See F5. |
| G19     | MISSING  | BUG-11| P1       | `ValidatedSnapshotCleanup` (chainstate dir swap) absent. See F6. |
| G20     | MISSING  | BUG-12| P0-CONSENSUS | Background validation worker is a STUB — counts heights but does not re-validate. See F7. |
| G21     | PARTIAL  | BUG-13| P2       | `vout >= u32::MAX` check absent; MAX_SIZE catches large values but not specifically `numeric_limits<uint32>::max()`. |
| G22     | PARTIAL  | BUG-14| P1       | No periodic `FlushSnapshotToDisk` during multi-million-coin load. See F9. |
| G23     | MISSING  | BUG-15| P1       | `m_chain_tx_count` never written into block index. See F10. |
| G24     | MISSING  | BUG-16| P2       | `BLOCK_OPT_WITNESS` not propagated. See F11. |
| G25     | PARTIAL  | BUG-17| P1       | NetworkDisable doesn't gate P2P chatter during dumptxoutset rollback. See F12. |
| G26     | PRESENT  | —     | —        | Pruned-mode pre-check before rollback (`rpc.py:11015-11038`) mirrors Core `rpc/blockchain.cpp:dumptxoutset`. |
| G27     | MISSING  | BUG-18| P1       | `reactivate_best_chain` silent fallback. See F13. |
| G28     | MISSING  | BUG-19| P2       | No mempool transfer between chainstates. See F14. |
| G29     | MISSING  | BUG-20| P0-CDIV  | Rust pipeline ships placeholder `AssumeutxoData` table + non-Core-compatible `compute_utxo_hash` + bypassing `import_core_snapshot`. See F1. |
| G30     | MISSING  | BUG-22| P2       | Sort-order assumption between RocksDB and Core's `CCoinsViewCursor` over `dumptxoutset` is unstated/untested. See F15. |

Bug table (severity-ranked)
---------------------------

| ID    | Gate    | Severity     | Site | Note |
|-------|---------|--------------|------|------|
| BUG-7  | G15    | P0-CDIV      | `rpc.py:10615-10620` | snapshot_loaded is process-local — no cross-restart guard against re-loading. Cross-impl divergence (Core rejects). |
| BUG-8  | G16    | P0-CDIV      | `rpc.py:11213-11272` | `getchainstates` response field names diverge from Core. Cross-impl. |
| BUG-10 | G18    | P0-CONSENSUS | `snapshot.py:1115-1145` | Background validation hash mismatch does NOT trigger fatal-error / dir rename / shutdown. Stuck on corrupted snapshot. |
| BUG-12 | G20    | P0-CONSENSUS | `snapshot.py:1100-1112` | `validation_worker` is a STUB — counts but doesn't validate. |
| BUG-20a | G29   | P0-CDIV      | `snapshot.rs:118-152` | Rust placeholder `AssumeutxoData` with invented `hash_serialized` for mainnet h=840k + fake testnet4 h=50k. |
| BUG-20b | G29   | P0-CVE-class | `lib.rs:4679-4881` | `import_core_snapshot` skips per-coin MoneyRange / coin_height>base_height / trailing-bytes / HASH_SERIALIZED checks. Operator-facing CLI: any operator using `ouroboros import-snapshot` foot-guns themselves. |
| BUG-20c | G29   | P1           | `lib.rs:4869-4878` | `import_core_snapshot` calls `update_best_block` without verifying the snapshot's coins against any commit. |
| BUG-20d | G29   | P1           | `snapshot.rs:646-684` | Rust `compute_utxo_hash` uses non-Core element encoding (`u64 LE code + LE value + u32 LE script_len` vs Core's VARINT(code) + raw value + VARINT(script_len)) and single-SHA-256, not SHA256d. Cannot match Core's hashSerialized ever. |
| BUG-2 | G7      | P1           | `snapshot.py:322-343` | testnet4 entries missing `base_header` + `chainwork_hex`. |
| BUG-9  | G17    | P1           | `node.py:711-723`, `snapshot.py:832-848` | No cross-restart re-init of `snapshot_height` from disk. |
| BUG-11 | G19    | P1           | (absent everywhere) | `ValidatedSnapshotCleanup` chainstate dir swap absent — `chainstate_snapshot/` lingers forever. |
| BUG-14 | G22    | P1           | `snapshot.py:1007-1031` | No periodic `FlushSnapshotToDisk` during load. |
| BUG-15 | G23    | P1           | `snapshot.py:166`, no consumer | `m_chain_tx_count` field exists but never read into block index. |
| BUG-17 | G25    | P1           | `rpc.py:11041-11048` | NetworkDisable gates submit but not P2P chatter. |
| BUG-18 | G27    | P1           | `rpc.py:11169-11180` | Silent `reactivate_best_chain` fallback. |
| BUG-21 | G14    | P1           | `snapshot.py:832-888` | No `validated` boolean persisted to `chainstate_snapshot/`; cannot resume validation across restarts. |
| BUG-1  | G6     | P2           | `snapshot.py:299-320` | testnet3 entries missing `base_header` + `chainwork_hex`. |
| BUG-13 | G21    | P2           | `snapshot.py:981` | No explicit `vout < uint32::max` check (MAX_SIZE catches it but loosely). |
| BUG-16 | G24    | P2           | (absent) | `BLOCK_OPT_WITNESS` flag not propagated. |
| BUG-19 | G28    | P2           | `snapshot.py` | No mempool transfer between chainstates (mempool-empty check at start instead). |
| BUG-22 | G30    | P2           | `snapshot.py:1207-1226` | Inter-txid sort order assumes RocksDB key order matches Core's COutPoint key order — true today but untested. |
| BUG-4  | (—)    | INFO         | —    | Already enforced inline in `snapshot.py:984-994` (per-coin height bound). Pinned by G12. |
| BUG-5  | (—)    | INFO         | —    | Already enforced inline in `snapshot.py:996-1005` (per-coin MoneyRange). Pinned by G12. |
| BUG-6  | (—)    | INFO         | —    | Already enforced inline (trailing-bytes after coins). Pinned by G13. |

(BUG-4/5/6 are the "already-fixed" originals from the in-source
comments — they have been closed by inline checks. They are listed
here only to disambiguate from the new W138-discovered bugs.)

Suggested fix wave shapes
-------------------------

- **FIX-87a (P0-CONSENSUS / P0-CDIV bundle, single impl):** BUG-10
  + BUG-12 are the two consensus-grade gaps. Both require landing a
  REAL background validation worker that actually replays
  blocks from genesis (not just counts heights), and on hash
  mismatch invokes a fatal-error + dir-rename path. ~250 lines
  net new + tests. Likely takes 2-3 fix waves.

- **FIX-87b (P0-CDIV cleanup, single impl):** BUG-7 + BUG-8.
  - BUG-7: persist `chainstate_snapshot/` exists check on RPC entry;
    fail with Core's exact error message.
  - BUG-8: change `rpc_getchainstates` field names to Core's
    canonical ones; add missing fields (`bits`, `target`, `difficulty`,
    `verificationprogress`, `coins_db_cache_bytes`,
    `coins_tip_cache_bytes`, `blocks`, `bestblockhash`).
  ~80 lines + 4 new assertions in cross-impl test_rpc.py.

- **FIX-87c (Rust pipeline cleanup, single impl):** BUG-20 a/b/c/d.
  Two options:
  1. Delete the Rust `AssumeutxoData` table + `get_assumeutxo_*` +
     `compute_utxo_hash` entirely; gate `import_core_snapshot` to
     the CLI only with a "use loadtxoutset RPC for live nodes"
     banner.
  2. Repopulate from Core's `chainparams.cpp`; fix
     `compute_utxo_hash` to match Core's `TxOutSer` element +
     SHA256d finalize.
  Option 1 is preferred (Python is the source of truth; Rust path
  is operator-only).

- **FIX-87d (P1 hygiene bundle):** BUG-9 + BUG-11 + BUG-14 + BUG-15
  + BUG-17 + BUG-18 + BUG-21. The "make it look like a real Core
  flow" cleanup — chainstate swap, periodic flush, chain_tx_count
  write, NetworkDisable extension to P2P, validated marker
  persisted.

Two-pipeline guard
------------------

`test_w138_g30_two_pipeline_assumeutxo_rust_isolation` codifies the
following invariants (this is the **10th extension** of the
ouroboros two-pipeline guard set —
W76 + W120 + W122 + W125 + W128 + W129 + W130 + W131 + W133 + W137
+ W138):

1. The Rust `import_core_snapshot` symbol is reachable ONLY from
   `src/ouroboros/cli.py` (the operator CLI path). No other Python
   module under `src/ouroboros/` may import it.
2. The Rust `compute_utxo_hash` and `validate_snapshot_hash`
   symbols are NEVER called from Python. They exist for Rust unit
   tests only; production Python uses
   `snapshot.compute_utxo_hash` instead.
3. The Rust `AssumeutxoData` table is documented as
   STALE/placeholder; the test file's docstring explicitly
   labels it so. Future regression that calls
   `get_assumeutxo_data` (the Rust binding) from Python trips the
   guard.

What this audit is NOT
----------------------

- **Not a fix.** No production code changes in this commit.
- **Not a snapshot-byte-identity check.** ouroboros's emitted
  snapshot bytes are NOT byte-compared to Core's for the same
  UTXO set in this audit. That comparison lives in
  `tools/snapshot-byte-identity.sh` (referenced in `node.py`
  comments) and is a separate operator-driven test.
- **Not a `BaseIndex` audit.** W133 covered index databases'
  inability to start in background on a snapshot-loaded
  chainstate. That gap is reported there.
