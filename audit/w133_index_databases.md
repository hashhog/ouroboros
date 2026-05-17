W133 — Index databases (txindex + coinstatsindex) audit (ouroboros)
====================================================================

Date: 2026-05-17
Impl: ouroboros (TWO pipelines — Rust ferrous-utils writes the live
      `tx_index` column family on `connect_block_from_bytes`; Python
      RPC layer reads + dispatches. Coinstatsindex is **absent** in
      both pipelines.)
Wave: W133 Index databases — BaseIndex, TxIndex, CoinStatsIndex.
      Excludes BlockFilterIndex (audited under W121).
Reference:
  - `bitcoin-core/src/index/base.{h,cpp}` (BaseIndex CValidationInterface
    subclass, sync thread, locator persistence, rewind/reorg, BlockConnected
    + ChainStateFlushed semantics, prune lock)
  - `bitcoin-core/src/index/txindex.{h,cpp}` (TxIndex final class,
    CustomAppend writes file-position-based CDiskTxPos, FindTx reads
    block header + seeks to tx_offset)
  - `bitcoin-core/src/index/coinstatsindex.{h,cpp}` (CoinStatsIndex
    final class — MuHash3072 cumulative state, per-height DBVal, hash
    index for fork retention, RevertBlock)
  - `bitcoin-core/src/index/disktxpos.h` (CDiskTxPos = FlatFilePos +
    VARINT tx-byte-offset; serialized with FlatFilePos::SERIALIZE)
  - `bitcoin-core/src/index/db_key.h` (DBHeightKey BIG-endian for
    sequential read; DBHashKey for fork retention via
    CopyHeightIndexToHashIndex during reorg)

Status: 30 gates audited — **PRESENT 5 / PARTIAL 5 / MISSING 20.**
**24 BUGS** (2 P0-CDIV / 13 P1 / 9 P2).

Relationship to prior audits
----------------------------

- W109 (block index, 2026-05-13) audited the block-metadata storage
  (BLOCK_INDEX_CF, BLOCK_INDEX_BY_HASH_CF); W133 audits the **derived
  indexes** that ride on top.
- W121 (BIP-157 + blockfilterindex) audited the **third** index type
  (CFilters). The base-class plumbing audited here (sync thread,
  locator, rewind) is the same surface for all three indexes — the
  W121 gaps documented in BlockFilterIndex Python pipeline (in
  `blockfilter.py`) are mirrored here in the Rust pipeline because
  `tx_index` writes happen inline with `connect_block_from_bytes`
  rather than from a separate index thread.
- W122 verified ouroboros's BIP-158 codec is CLEAN; W133 has NO codec
  parity work — the txindex is structured-key, not GCS-encoded.

Two-pipeline guard
------------------

txindex storage is **split** between pipelines:

- **Rust pipeline (live)**: `ferrous-utils/sync/src/storage/db.rs`
  defines `TX_INDEX_CF` (`schema.rs:124`), `store_tx_index{,_batch}`
  (`db.rs:457,1960`), `get_tx_index` (`db.rs:479`), `delete_tx_index`
  (`db.rs:501`). Called from three call sites:
  - `lib.rs:3856` connect-single-block path
  - `lib.rs:4429` connect-batch path
  - `validate/block.rs:874` validator path
  Disconnect calls in `db.rs:1656` and `db.rs:1870` (single + atomic).

- **Rust pipeline (dead-code)**: `ferrous-utils/sync/src/storage/txindex.rs`
  defines a SEPARATE `TxIndex` struct with proper Core-shape
  `DiskTxPos` (file_number + block_offset + tx_offset) wrapped as
  `PyTxIndex`/`PyDiskTxPos` (`lib.rs:1786-2050`). **Wired into the
  Python module** but **never instantiated** — production never opens
  this CF or calls these APIs. `database.py` does not reference
  `PyTxIndex` or `PyDiskTxPos` anywhere. **BUG-1 (P1) DEAD-CODE.**

- **Python pipeline**: `database.py::get_tx_index` (`database.py:615`)
  is a thin wrapper over the Rust live path. `rpc.py:2118,2460`
  + `rest.py:930` consume it for `getrawtransaction` /
  `sendrawtransaction` already-confirmed check / REST `/tx/<txid>`.

No coinstatsindex implementation exists in either pipeline.
`rpc_gettxoutsetinfo` (`rpc.py:7022`) walks the chainstate live every
call — see BUG-9, BUG-10, BUG-11.

```
$ grep -rn "CoinStatsIndex\|coinstatsindex\|g_coin_stats_index" \
       ferrous-utils/ src/ouroboros/  → 0 production matches
$ grep -rn "BaseIndex\|m_synced\|m_thread_sync\|StartBackgroundSync" \
       ferrous-utils/ src/ouroboros/  → 0 matches
$ grep -rn "txindex_enabled\|enable_txindex\|-txindex" \
       src/ouroboros/  → only comment + RPC help strings; no flag
```

**Two-pipeline guard EXTENDED.** Test
`test_g30_two_pipeline_txindex_only_in_rust_storage_db` codifies:
- `ferrous-utils/sync/src/storage/db.rs` contains `TX_INDEX_CF`
  (live path) — REQUIRED;
- `ferrous-utils/sync/src/storage/txindex.rs` contains an unused
  alternate definition — DOCUMENTED (until BUG-1 is closed by deletion);
- No Python file under `src/ouroboros/` defines its own txindex
  storage (the boundary remains: Rust writes, Python reads).
This extends the guard set W76 + W120 + W122 + W125 + W128 + W129 +
W130 → now W133. Future regressions (e.g. moving txindex to
Python-side SQLite or LMDB) trip this guard.

Top-level architectural findings
--------------------------------

**(F1) No BaseIndex abstraction.** Core's `index/base.cpp` is the
shared sync engine for txindex, coinstatsindex, and blockfilterindex:
shared sync thread, `m_synced` flag, locator persistence
(DB_BEST_BLOCK), rewind on reorg, prune lock plumbing. ouroboros has
no equivalent abstraction. `tx_index` writes happen inline with
`connect_block_from_bytes` (Rust). This means:
- The index is **always in sync with chainstate by construction**
  (good: BUG class avoided).
- The index **cannot be reindexed separately** from chainstate.
- The index **cannot start in background** while the node serves
  requests from a snapshot-bootstrapped chainstate (assumeutxo gap;
  see BUG-2).
- No `BlockUntilSyncedToCurrentChain()` API — RPC callers cannot
  block on index catch-up.
- No `IndexSummary` returned from `getindexinfo`: BUG-3 below.

**(F2) DiskTxPos divergence.** Core stores
`(file_number, block_offset, tx_byte_offset_within_block)` allowing
direct seek to a single transaction without parsing the whole block.
ouroboros stores `(block_hash, height, tx_position_index)` where
`tx_position` is an **array index** (0..n_tx), not a byte offset.
Every `getrawtransaction` therefore reads the full block from
BLOCKS_CF + traverses txdata to find the target (`rpc.py:2126-2131`
`for block_tx in block.transactions: ... if found_txid == tx_hash`).
For an early block with one tx this is fine; for a 4 MB block this
costs O(n_tx) per lookup. Stored value is 40 bytes/key
(`db.rs:467-470`); Core stores 12 bytes/key (`disktxpos.h`).

The unused `storage/txindex.rs` HAS the Core-shape `DiskTxPos` but
isn't wired into the connect path — see BUG-1 (P1 DEAD-CODE).

**(F3) No coinstatsindex.** `gettxoutsetinfo` always walks the live
chainstate (`rpc.py:7022-7198`). For a 100 GB UTXO set this is a
multi-minute call. Core's coinstatsindex maintains running MuHash +
DBVal per height, making the call O(1). The MuHash3072 implementation
exists (`muhash.py`, `coin_element`); the **incremental cumulative
state** + per-height/per-hash DB persistence does not.

Consequence: ouroboros cannot serve `gettxoutsetinfo` at historical
heights — `hash_or_height` parameter is silently ignored
(`rpc.py:7095-7097`). The RPC signature accepts the parameter for
"parity with Core's RPC help"; behavior is "always the current tip".
This is a **P0-CDIV** behavior gap because operators relying on
audit/reproducible-UTXO-hash workflows get a wrong answer (no
indication that the height parameter was ignored).

**(F4) Genesis-tx indexing divergence.** Core's `TxIndex::CustomAppend`
returns early for `block.height == 0` ("Exclude genesis block
transaction because outputs are not spendable", `txindex.cpp:77`).
ouroboros indexes the genesis coinbase
(`validate/block.rs:840-880` — `store_utxos = height > 0` skips the
UTXO write but still writes tx_index). Detectable cross-impl
divergence on `getrawtransaction <mainnet-genesis-coinbase-txid>`:
Core returns `transaction not found`, ouroboros returns the tx.

**(F5) No locator persistence for the index.** Core's BaseIndex
writes `DB_BEST_BLOCK` (a `CBlockLocator`, not a single hash) so
that on restart the index can find the last in-sync point even if
the chainstate has advanced or rewound (`base.cpp:78-93,270-288`).
ouroboros has no per-index locator — the index implicitly tracks
the chain tip via META_CF::BEST_BLOCK_HASH because all writes happen
inside the same atomic batch as the chainstate update
(`lib.rs:3903-3911`). This is **structurally consistent** (one
batch, never out-of-sync) but loses the ability to:
- start a fresh index (e.g. wipe `tx_index` CF for reindex without
  wiping chainstate);
- detect partial index reads (Core's `LookupBlockIndex` cross-check
  in `base.cpp:128-133`).
See BUG-4.

**(F6) No hash-keyed retention for reorgs.** Core's BaseIndex uses
`db_key.h::CopyHeightIndexToHashIndex` during reorg disconnect: the
height-keyed entry for the disconnected block is copied to a hash-
keyed entry so the data remains accessible even though the height
slot is now owned by the new chain's block. ouroboros's `tx_index`
disconnect (`db.rs:1656,1870`) DELETES the txid entries
unconditionally; on a small reorg this is consistent (the new chain's
blocks rewrite them); but for the coinstatsindex shape (per-height
DBVal) this would be silent data loss. Since coinstatsindex is
absent, the bug is latent — but the **CopyHeightIndexToHashIndex
pattern is missing fleet-wide** and would need to be added before
coinstatsindex (or any future per-height index) is wired. See BUG-5.

Gate matrix
-----------

| Gate | Category                    | Status   | Bug    | Sev |
|------|-----------------------------|----------|--------|-----|
| G1   | BaseIndex abstraction       | MISSING  | BUG-2  | P1  |
| G2   | Sync thread / m_synced flag | MISSING  | BUG-6  | P1  |
| G3   | BlockUntilSyncedToCurrentChain RPC | MISSING | BUG-7 | P1  |
| G4   | IndexSummary / getindexinfo | MISSING  | BUG-3  | P1  |
| G5   | DB_BEST_BLOCK locator       | MISSING  | BUG-4  | P1  |
| G6   | Per-index DB obfuscation    | MISSING  | BUG-8  | P2  |
| G7   | TX_INDEX_CF present (live)  | PRESENT  | —      | —   |
| G8   | TxIndex genesis-exclusion   | MISSING  | BUG-14 | P1  |
| G9   | DiskTxPos byte-offset       | PARTIAL  | BUG-15 | P1  |
| G10  | DiskTxPos VARINT serialize  | MISSING  | BUG-16 | P2  |
| G11  | FindTx file-seek path       | MISSING  | BUG-17 | P1  |
| G12  | Dead-code storage/txindex.rs| PRESENT  | BUG-1  | P1  |
| G13  | -txindex opt-in flag        | MISSING  | BUG-13 | P2  |
| G14  | tx_index reorg rewind       | PRESENT  | —      | —   |
| G15  | tx_index atomic w/ chain    | PRESENT  | —      | —   |
| G16  | Hash-keyed reorg fork retention | MISSING | BUG-5 | P1  |
| G17  | Prune+txindex incompat warn | MISSING  | BUG-12 | P2  |
| G18  | Prune lock for tx_index     | MISSING  | BUG-18 | P2  |
| G19  | CoinStatsIndex class        | MISSING  | BUG-9  | P0-CDIV|
| G20  | gettxoutsetinfo at height   | MISSING  | BUG-10 | P0-CDIV|
| G21  | gettxoutsetinfo use_index   | MISSING  | BUG-11 | P1  |
| G22  | MuHash3072 incremental state | MISSING | BUG-19 | P1  |
| G23  | BIP30 unspendable in coinstats | MISSING | BUG-20 | P2 |
| G24  | "indexes/coinstats" old-dir warn | MISSING | BUG-21 | P2 |
| G25  | DBHeightKey BIG-endian ordering | MISSING | BUG-22 | P2  |
| G26  | DBHashKey reorg-fork pattern | MISSING | BUG-23 | P1  |
| G27  | scanblocks / scantxoutset RPC | MISSING | BUG-24 | P2 |
| G28  | tx_position byte-offset semantic | PARTIAL | BUG-15 | P1 (same as G9) |
| G29  | TxIndex CustomOptions notify  | MISSING | — (subsumed by G2) | — |
| G30  | Two-pipeline guard extension | PRESENT | —      | —   |

Bug inventory (24 bugs / 30 gates)
-----------------------------------

Severity legend: P0-CDIV=consensus-or-cross-impl-divergence;
P1=correctness or operator-functional; P2=cosmetic.

| Bug    | Gate    | Sev      | Description |
|--------|---------|----------|-------------|
| BUG-1  | G12     | P1 DEAD  | `ferrous-utils/sync/src/storage/txindex.rs` defines a parallel `TxIndex` struct + `DiskTxPos` (file-position based, mirroring Core exactly) wrapped as `PyTxIndex`/`PyDiskTxPos` in `lib.rs:1786-2050`. **Never instantiated.** No Python or Rust call site opens this CF or these APIs. Should either be wired (replacing the live `db.rs::store_tx_index_batch` shape) OR deleted. Dead-code wave 33b candidate. |
| BUG-2  | G1      | P1       | No `BaseIndex` abstraction. txindex writes are inline in `connect_block_from_bytes`; cannot reindex independently of chainstate, cannot start in background while serving snapshot-bootstrapped chain. |
| BUG-3  | G4      | P1       | `rpc_getindexinfo` returns empty dict `{}` (`rpc.py:8968-8970`). Core returns per-index `{ "synced": bool, "best_block_height": int }`. Operators cannot verify the txindex is caught up. |
| BUG-4  | G5      | P1       | No per-index `DB_BEST_BLOCK` `CBlockLocator` persistence. Index relies on META_CF::BEST_BLOCK_HASH atomic-batch coupling. Loses ability to reindex / detect partial reads / start with a different chainstate. |
| BUG-5  | G16,G26 | P1       | No `CopyHeightIndexToHashIndex` (`db_key.h:72-93`) reorg pattern. txindex is keyed by txid so the loss is theoretical (the new chain rewrites the same txids); but missing pattern blocks adding per-height indexes like coinstatsindex. |
| BUG-6  | G2      | P1       | No `m_synced` flag, no sync thread, no `BlockConnected`/`ChainStateFlushed` validation-interface dispatch. The index is "synced by construction"; this looks like a feature until a future index (e.g. a P2WSH-script index) needs out-of-band rebuild. |
| BUG-7  | G3      | P1       | No `BlockUntilSyncedToCurrentChain` API. RPC callers (e.g. `getrawtransaction`) cannot block on index catch-up. In production this only matters during initial sync (the inline write closes the gap), but it's a stable Core API consumers expect. |
| BUG-8  | G6      | P2       | No per-index DB obfuscation key. Core wraps DB writes in `CDBWrapper { ..., .obfuscate=true }` (`base.cpp:68-76`) so bytes-at-rest aren't trivially identifiable in disk forensics. RocksDB's per-CF compression/encryption is not configured. |
| BUG-9  | G19     | P0-CDIV  | `CoinStatsIndex` class entirely absent. `gettxoutsetinfo` walks live chainstate every call (`rpc.py:7022-7198`). For mainnet UTXO set this means multi-minute call latency vs Core's O(1) hash lookup. |
| BUG-10 | G20     | P0-CDIV  | `gettxoutsetinfo` `hash_or_height` parameter silently ignored (`rpc.py:7095-7097`). Caller cannot query historical UTXO state at any height other than tip. Cross-impl audit divergence: operators expecting Core's historical-snapshot answer get current tip without warning. |
| BUG-11 | G21     | P1       | `gettxoutsetinfo` `use_index` parameter accepted then ignored. Core distinguishes `use_index=true` (lookup via coinstatsindex, fast) from `false` (recompute). ouroboros silently always recomputes. |
| BUG-12 | G17     | P2       | No `-txindex` + `-prune` incompatibility check at startup. Core (`init.cpp`) refuses to start with both set because pruning would orphan tx_index rows pointing to pruned blocks. ouroboros pruning + tx_index lookup would yield `get_block(block_hash) == None` for pruned blocks (silent get-tx failure). |
| BUG-13 | G13     | P2       | No `-txindex` / `-coinstatsindex` opt-in flag. The Rust CF is always created; index is always populated. Cannot disable to save disk space (24+ GB tx_index on mainnet). RPC help text mentions "if -txindex is enabled" but there is no toggle. |
| BUG-14 | G8      | P1       | tx_index writes the genesis coinbase txid (`validate/block.rs:874-880`, `lib.rs:3856`). Core's `TxIndex::CustomAppend` returns early on `height == 0` (`txindex.cpp:76-77`). Cross-impl divergence: `getrawtransaction <mainnet-genesis-coinbase-txid>` returns the tx in ouroboros, returns `tx not found` in Core. Doc comment in `validate/block.rs:838-839` acknowledges the deviation: "We still maintain the tx index so RPCs that look up the genesis coinbase by txid keep working." This is a **deliberate** Core-divergence — should be tagged + tracked. |
| BUG-15 | G9,G28  | P1       | `tx_position` stored as txdata **index** (0..n_tx-1), not byte offset. Every `getrawtransaction` reads the full block + traverses txdata to find the target (`rpc.py:2126-2131`). For a 4 MB block this is O(n_tx) per lookup vs Core's O(1) seek. The unused `storage/txindex.rs` HAS the Core-shape `DiskTxPos` (file_number + block_offset + tx_offset) but isn't wired. |
| BUG-16 | G10     | P2       | tx_index value is 40 bytes fixed (32 hash + 4 LE height + 4 LE tx_pos). Core's CDiskTxPos uses VARINT for `nTxOffset` (`disktxpos.h:17`) → typically 1-3 bytes per row, 12 bytes total. ouroboros pays 28-byte overhead per row. For ~1B mainnet txs this is ~28 GB wasted disk vs Core. |
| BUG-17 | G11     | P1       | `FindTx` (Core: `txindex.cpp:93-120`) reads the block header + seeks `nTxOffset` bytes + deserializes one tx + verifies `tx->GetHash() == tx_hash`. ouroboros's lookup deserializes the entire block and traverses the txdata array. No file-seek path exists. |
| BUG-18 | G18     | P2       | No `PruneLockInfo` plumbing. Core's `BaseIndex::SetBestBlockIndex` (`base.cpp:487-503`) writes a prune lock keyed by index name so the pruner refuses to drop block files needed by the index. ouroboros pruner doesn't consult any index state. |
| BUG-19 | G22     | P1       | MuHash3072 implementation exists (`muhash.py::MuHash3072`) but is only used in snapshot creation/load (`snapshot.py`) and in the live walk of `gettxoutsetinfo` (`rpc.py:7109`). No **cumulative MuHash state** maintained per block. Adding `CoinStatsIndex` would require an `ApplyCoinHash` / `RemoveCoinHash` call site in `connect_block_from_bytes` to update the running hash, then commit to per-height DB. |
| BUG-20 | G23     | P2       | No `m_total_unspendables_*` family of counters (genesis-block subsidy, BIP30 dupes, IsUnspendable scripts, unclaimed rewards). ouroboros's chainstate walk treats unspendable outputs uniformly. Mostly cosmetic until coinstatsindex is added. |
| BUG-21 | G24     | P2       | No "old indexes/coinstats" directory warning. Core (`coinstatsindex.cpp:95-101`) emits a startup `LogWarning` if `indexes/coinstats/` exists (pre-fix legacy path) — since ouroboros never had the legacy path, the warning is moot but the path-name compatibility (`indexes/coinstatsindex/` vs `indexes/coinstats/`) doesn't exist either, which would matter for an operator who migrates an old datadir. |
| BUG-22 | G25     | P2       | No big-endian height-key encoding for sequential reads. Core's `DBHeightKey::Serialize` uses `ser_writedata32be` (`db_key.h:41`) so that sequential RocksDB iteration yields blocks in chain order. ouroboros uses LE everywhere (`schema.rs:353` `encode_height` is LE) — fine for point lookups, breaks ordered range scans (which coinstatsindex.cpp:218-225 uses in `CopyHeightIndexToHashIndex`). |
| BUG-23 | G26     | P1       | No `DBHashKey` / `DBHeightKey` typed-prefix discriminator in tx_index CF. Core's two-prefix scheme (`'s'` for hash, `'t'` for height) coexists in one CF (`db_key.h:29-30`); ouroboros uses one CF per key type (TX_INDEX_CF only has the txid mapping). When coinstatsindex is added, the same prefix discrimination would be needed for the height + hash dual-index pattern. |
| BUG-24 | G27     | P2       | No `scanblocks` or `scantxoutset` RPC. Both depend on indexes (`scanblocks` on blockfilterindex per W121 BUG-26; `scantxoutset` on either coinstatsindex or live chainstate). Out of scope for W133 strictly — flagged here for the cross-wave tracker. |

P0-CDIV summary
----------------

Two of the 24 bugs are P0-CDIV. Both stem from F3 (no coinstatsindex):

- **BUG-9** (G19): no coinstatsindex class → `gettxoutsetinfo` is
  multi-minute every call;
- **BUG-10** (G20): `hash_or_height` parameter silently ignored →
  operators querying historical UTXO digests get wrong answer.

Both should be visible in any cross-impl consensus-diff run that
asks for `gettxoutsetinfo` at a non-tip height. Suggested fix
sequence: add `CoinStatsIndex` (single-impl wave, Python-side
incremental MuHash with per-height DBVal in a new CF
`coin_stats_index`), then wire `gettxoutsetinfo`'s
`hash_or_height` to look up the cached entry.

Lower priorities (P1 = 13 bugs)
-------------------------------

The biggest functional cluster is around the `BaseIndex` abstraction
gap (BUG-2/3/4/6/7). These would block adding any future index type
(e.g. spent-output index, address index) because the shared sync
plumbing doesn't exist. Recommend "BaseIndex sweep" as a separate
wave once W133 closure starts.

The Core-shape `DiskTxPos` is present-but-unused (BUG-1) — the
cheapest P1 fix is to delete `storage/txindex.rs` + `PyTxIndex` +
`PyDiskTxPos`, removing the architectural confusion. Replacing
`store_tx_index_batch`'s shape with the file-position shape is a
larger fix that touches both `connect_block_from_bytes` paths +
`getrawtransaction` lookup.

The genesis-tx-indexing divergence (BUG-14) is **deliberate** per
the production comment, but it does cause an asymmetric reply
between ouroboros and Core. Should be either flipped to Core parity
(skip genesis) or documented as a permanent friendly deviation
(operators relying on `getrawtransaction <mainnet-genesis-coinbase>`
returning OK).

Stable Core API gaps (BUG-3/7/11/13/17) are operator-functional
losses: `getindexinfo`, `BlockUntilSyncedToCurrentChain`,
`gettxoutsetinfo use_index`, `-txindex` flag, `FindTx` file-seek —
none consensus-affecting, but every tool that talks to Bitcoin Core
expects these.

P2 cluster (9 bugs)
-------------------

Mostly cosmetic encoding choices (LE vs BE for heights, fixed-width
vs VARINT, missing obfuscation, missing prune-lock plumbing, missing
"old folder" startup warning, missing `scanblocks`/`scantxoutset`).
These won't affect a consensus-diff but they affect operator-tool
parity.

Closure plan (recommended sequence)
-----------------------------------

Two ordered closure recommendations:

**Phase A — single-impl scope** (closes BUG-1/3/14):
1. Delete `ferrous-utils/sync/src/storage/txindex.rs` +
   `PyTxIndex`/`PyDiskTxPos` from `lib.rs` (dead-code; closes BUG-1).
2. Implement `rpc_getindexinfo` to return per-index status from
   META_CF::BEST_BLOCK_HASH + `db.get_best_block().height` (closes
   BUG-3; gives operators basic visibility).
3. Decide on BUG-14 (genesis-tx indexing): either gate the write on
   `height > 0` to match Core, or formalize the deviation in
   `docs/CONSENSUS_DIVERGENCES.md`.

**Phase B — multi-pipeline scope** (closes BUG-9/10/11/19):
4. Add a `CoinStatsIndex` Python class wrapping `MuHash3072` with
   `apply_block` / `revert_block` hooks. Wire into
   `connect_block_from_bytes` via a new RocksDB CF
   `coin_stats_index`. Implement DBVal-per-height + DBHashKey
   reorg-retention pattern from `db_key.h`. Honor
   `gettxoutsetinfo hash_or_height + use_index` parameters.

**Phase C — base-class consolidation** (closes BUG-2/4/5/6/7):
5. Extract a shared `BaseIndex` abstraction (Python-side, since
   coinstatsindex is Python; tx_index stays where it is). Move
   sync-thread + locator persistence + sync-flag pattern there.
   Probably worth a separate wave (W134?) once BUG-9/19 land.

Cumulative streak status
-------------------------

W133 is a DISCOVERY wave (no production changes). Streak: 71 fix +
60 discovery preserved. If W133 closes via Phase A in a single fix
wave, that would be FIX-83+ (TBD numbering).

Out-of-scope (not audited here)
-------------------------------

- `blockfilterindex` storage + retrieval — see W121.
- `txospenderindex` — newer Core 28 index; not yet in the fleet.
- Whether the inline-batched approach is preferable to Core's
  separate-thread approach. (W133 documents the divergence; doesn't
  argue for/against.)
- RocksDB tuning for tx_index CF (compression, write-buffer size).
- Cross-impl divergence beyond what `consensus-diff.py` already
  catches.

References
----------

- `bitcoin-core/src/index/base.{h,cpp}` — BaseIndex, sync thread,
  ChainStateFlushed, locator, prune lock
- `bitcoin-core/src/index/txindex.{h,cpp}` — TxIndex, CustomAppend,
  FindTx
- `bitcoin-core/src/index/coinstatsindex.{h,cpp}` — CoinStatsIndex,
  RevertBlock, CustomInit, DBVal
- `bitcoin-core/src/index/disktxpos.h` — CDiskTxPos, FlatFilePos
- `bitcoin-core/src/index/db_key.h` — DBHeightKey BE, DBHashKey,
  CopyHeightIndexToHashIndex, LookUpOne
- `ferrous-utils/sync/src/storage/schema.rs:124` — TX_INDEX_CF
- `ferrous-utils/sync/src/storage/db.rs:457,479,501,1656,1870,1960`
  — store/get/delete tx_index live paths
- `ferrous-utils/sync/src/storage/txindex.rs` — DEAD-CODE alternate
- `ferrous-utils/sync/src/lib.rs:1786-2050` — PyTxIndex/PyDiskTxPos
  wrappers (dead-code)
- `ferrous-utils/sync/src/lib.rs:3856,4429` — Rust connect-side
  call sites
- `ferrous-utils/sync/src/validate/block.rs:874,983` — validator
  pipeline call sites
- `src/ouroboros/database.py:615-623` — Python wrapper
- `src/ouroboros/rpc.py:2066,2118,2460,7022,8968` — txindex /
  gettxoutsetinfo / getindexinfo
- `src/ouroboros/rest.py:887-942` — REST tx lookup
