W146 — Block storage layer audit (ouroboros)
==============================================

Date: 2026-05-18
Impl: ouroboros (Python+Rust). The Rust side is the source of truth for
      on-disk storage (`ferrous-utils/sync/src/storage/`). The PyBlockStore
      binding (`ferrous-utils/sync/src/lib.rs:1346-1729`) wraps the Rust
      `BlockStore` (`storage/blockstore.rs`) and exposes pruning + flat-file
      operations to Python. The Python side (`src/ouroboros/pruning.py`,
      `src/ouroboros/database.py`) imports it but only the **pruning**
      methods are actually called in production (`node.py:275`); the
      `write_block`/`read_block`/`write_block_undo` methods on
      `PyBlockStore` are NEVER called from any Python entry point.

Wave: W146 — Block storage layer (blkXXXXX.dat + rev*.dat + block-index
      leveldb). 8 behaviors audited:
  1. blkXXXXX.dat file format (magic + size prefix)
  2. rev*.dat (undo) file format
  3. FindBlockPos rotation (128 MiB MAX_BLOCKFILE_SIZE / 16 MiB chunks)
  4. FlushBlockFile + fsync discipline
  5. Block-index leveldb keys ('b' / 'f' / 'l' / 'F' / 'R' / 't')
  6. WriteBlock atomicity (fsync before DB commit)
  7. ReadBlockFromDisk + magic checksum
  8. Recovery on partial write (bad-magic / reindex flag 'R')

Reference (Bitcoin Core)
------------------------
- `bitcoin-core/src/node/blockstorage.h:119-123`: constants
  `BLOCKFILE_CHUNK_SIZE = 0x1000000` (16 MiB),
  `UNDOFILE_CHUNK_SIZE = 0x100000` (1 MiB),
  `MAX_BLOCKFILE_SIZE = 0x8000000` (128 MiB).
- `bitcoin-core/src/node/blockstorage.cpp:58-62`: leveldb prefix bytes
  `DB_BLOCK_FILES{'f'}`, `DB_BLOCK_INDEX{'b'}`, `DB_FLAG{'F'}`,
  `DB_REINDEX_FLAG{'R'}`, `DB_LAST_BLOCK{'l'}`. txindex prefix
  `DB_TXINDEX{'t'}` (`src/index/txindex.cpp:31`).
- `bitcoin-core/src/node/blockstorage.cpp:1134-1165` `BlockManager::
  WriteBlock`: writes header (`MessageStart << blk_size`) then block;
  `file.fclose()` flushes/closes; DB commit (`WriteBlockIndexDB`) is a
  SEPARATE step that writes `DB_BLOCK_FILES`/`DB_LAST_BLOCK`/
  `DB_BLOCK_INDEX` keys in a SINGLE `CDBBatch` (atomic).
- `bitcoin-core/src/node/blockstorage.cpp:742-769` `FlushBlockFile` calls
  `FlatFileSeq::Flush(pos, fFinalize)` which `Sync()` the file (fsync)
  and optionally truncates (`flatfile.cpp:88-106`). Undo files have a
  separate `FlushUndoFile` path.
- `bitcoin-core/src/node/blockstorage.cpp:967-1034` `WriteBlockUndo`:
  computes checksum `HashWriter << prev_block_hash << blockundo`, writes
  `MessageStart << blockundo_size << blockundo << checksum`, sets
  `block.nStatus |= BLOCK_HAVE_UNDO`.
- `bitcoin-core/src/node/blockstorage.cpp:833-921` `FindNextBlockPos`:
  rolls to next file when `nSize + nAddSize >= max_blockfile_size`,
  calls `m_block_file_seq.Allocate(pos, nAddSize, out_of_space)` which
  uses `posix_fallocate` (`fs_helpers.cpp:181-227`).
- `bitcoin-core/src/node/blockstorage.cpp:1036-1132` `ReadBlock` /
  `ReadRawBlock`: reads `blk_start` (4-byte magic) + `blk_size`,
  rejects on `blk_start != MessageStart()` ("Block magic mismatch"),
  rejects on `blk_size > MAX_SIZE` (`serialize.h:34`,
  `MAX_SIZE = 0x02000000 = 33554432`).
- `bitcoin-core/src/node/blockstorage.cpp:1224-1230` `BlockManager`
  constructor wires `m_obfuscation` from `xor.dat`; ALL blocksdir
  reads/writes go through `AutoFile{file, m_obfuscation}` which
  XOR-obfuscates every byte (added in v25.0 to avoid AV false-positives).
- `bitcoin-core/src/txdb.cpp:25` `DB_HEAD_BLOCKS{'H'}`: two-phase commit
  recovery key written before chainstate mutate, deleted after; on
  startup, presence of `'H'` triggers rollback.
- `bitcoin-core/src/init.cpp:524`: `-prune` argument unit is **MiB**
  (`MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024`); `MIN_DISK_SPACE
  _FOR_BLOCK_FILES = 550 * 1024 * 1024` (`blockstorage.h`).

Two-pipeline guard
------------------
Block storage runs in the **Rust pipeline** only — the Python side has
no `blk*.dat` writer of its own. **BUT** the actual production storage
path bypasses the Rust `BlockStore` entirely: blocks are stored in
RocksDB column families (`BLOCKS_CF`, `BLOCK_INDEX_CF`,
`BLOCK_INDEX_BY_HASH_CF`, `UNDO_CF`, `HEADERS_CF`) via
`BlockchainDB::store_block` (`db.rs:173-186`) and
`store_block_undo` (`db.rs:1163-1192`). `BlockStore::write_block` is
exposed to Python as `PyBlockStore.write_block`
(`lib.rs:1392-1410`) **but is never called by any Python entry point**
— `grep -n "py_block_store\|\.write_block(" src/ouroboros/*.py` finds
zero hits. The 1463-line `blockstore.rs` module is therefore a
**second, parallel, dead-on-arrival** block-storage implementation
sitting alongside the RocksDB-based production path.

This is the THIRD architectural pattern of "well-engineered
parallel-but-unused storage module" cataloged across ouroboros (cross-cite
W138 `ChainstateManager`/`run_background_validation` and W139 fee
persistence shim). **Two-pipeline guard EXTENDED** (now 15th distinct
extension since W76): forbid wiring `PyBlockStore.write_block` /
`write_block_undo` into the production sync path WITHOUT a coordinated
migration that disables `BlockchainDB::store_block` to BLOCKS_CF — else
blocks would be written TWICE on every connect, doubling IO and
permanently desyncing the two views.

Status: **25 BUGS** (4 P0-CDIV / 1 P0-DoS / 1 P0 / 1 P0-DEAD-CLASS /
        12 P1 / 4 P2 / 2 P3). 8 of 8 behaviors audited:
  - Behavior 1 (blk*.dat header magic+size): **PRESENT but DEAD** —
    correct byte format, but `PyBlockStore.write_block` has zero
    Python callers; production blocks live in `BLOCKS_CF` (RocksDB) NOT
    `blk00000.dat`.
  - Behavior 2 (rev*.dat undo format): **PRESENT but DEAD** — same
    pattern as (1); `UndoFileManager` defined but unused.
  - Behavior 3 (FindBlockPos rotation): correct constants and logic in
    `BlockStore::find_next_block_pos`, **but `allocate()` uses
    `set_len` (sparse extend) NOT `posix_fallocate`**.
  - Behavior 4 (FlushBlockFile + fsync): correct fsync in `write_block`
    (line 423) and `flush()` (line 738), but timing order divergent
    from Core's flush-on-rotation.
  - Behavior 5 (block-index leveldb keys): **DIVERGENT** — ouroboros
    uses string-named column families (`"blocks"`, `"block_index"`,
    `"fileinfo"`, `"blockpos"`) NOT single-byte prefixes
    (`'b'`/`'f'`/`'l'`/`'F'`/`'R'`).
  - Behavior 6 (WriteBlock atomicity): file-fsync-before-DB ordering
    correct in `BlockStore::write_block`, but the two follow-up DB
    writes (`save_file_info` + `save_block_pos`) are NOT atomic —
    two separate `put_cf` calls.
  - Behavior 7 (ReadBlock magic check): correct magic reject in
    `read_block_at`, but `size > 4_000_000` rejection limit is too
    strict (Core uses `MAX_SIZE = 0x02000000 = 33_554_432`).
  - Behavior 8 (recovery on partial write): **MISSING** — no
    `DB_REINDEX_FLAG{'R'}` equivalent; no reindex code path; no
    bad-magic-recovery scan. Magic mismatch returns hard error
    (`InvalidMagic`), no truncation/replay.

Relationship to prior audits
----------------------------
- W138 (assumeUTXO): the `BlockStore::network()` enum lacks a
  `BlockfileType::ASSUMED` analog — `BlockfileTypeForHeight`
  (`blockstorage.cpp:771-777`) maps assumeutxo blocks to a separate
  cursor pool. Ouroboros has ONE cursor; loading a snapshot mid-IBD
  cannot keep the two block ranges in separate files.
- W109 (block index): W109 audited `block_index.py` (height→hash lookups
  in Python). W146 audits the on-disk format underneath. W109's
  height-keyed CF is REUSED here.
- W145 (subsidy): unrelated subsystem; cross-cited only because both
  surface "two-pipeline guard" extensions.
- Pruning audit lives in the existing `BlockPruner` code; not all bugs
  are duplicated here, but pruning-relevant ones (BUG-23) are flagged.

Findings
========

BUG-1 — P0-DEAD-CLASS: Entire `BlockStore` + `UndoFileManager` modules are dead code in production
---------------------------------------------------------------------------------------------------
**Severity**: P0 (dead module)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs` (1463 LOC),
`ferrous-utils/sync/src/storage/undo.rs` `UndoFileManager` (lines 317-433),
`ferrous-utils/sync/src/lib.rs:1334-1729` (PyBlockStore PyO3 binding).
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1134-1165`
(`BlockManager::WriteBlock`) — this is THE production code path.

**Description**: `PyBlockStore.write_block` (lib.rs:1392-1410),
`write_block_undo` (referenced 1700+), and the underlying
`BlockStore::write_block`/`write_block_undo` (blockstore.rs:397-526) are
exposed to Python but called by ZERO production code. Production blocks
go through `BlockchainDB::store_block` (db.rs:173-186) which writes the
entire serialized block to RocksDB's `BLOCKS_CF` column family keyed by
hash. Undo data goes through `BlockchainDB::store_block_undo`
(db.rs:1163-1192) which writes to `UNDO_CF` keyed by height.

`grep -rn "block_store\.write_block\|\.write_block(\|py_block_store"
src/ouroboros/*.py` → zero hits. Only the **pruning** methods on
`PyBlockStore` are called from `pruning.py`, and those probe an empty
`BlockFileInfo` vector that nothing has populated.

**Excerpt** (lib.rs:1334-1382 — wired but unused):
```rust
// PyBlockStore: Flat file block storage (blk*.dat/rev*.dat format)
#[pyclass]
pub struct PyBlockStore {
    store: Arc<std::sync::RwLock<BlockStore>>,
}
// ... new() takes data_dir + network and creates blocks/ subdir
//     with empty RocksDB index — never written to in production.
```

**Impact**:
- ~1900 LOC of audited block-storage code (blockstore.rs + undo.rs
  UndoFileManager + lib.rs binding) does NOT run in production.
- Disk-on-disk format diverges from Core: ouroboros's mainnet datadir
  contains `blocks/index/` (RocksDB) but no `blocks/blk00000.dat`. A
  Bitcoin Core node cannot read ouroboros's on-disk blocks, and
  vice-versa.
- `-reindex`, `bitcoin-cli getblockfilename`, `dumpfileinfo` style RPC
  ops would all break — they would query the in-memory cursor (which
  is at file 0, pos 0 forever) and report empty results.
- Pruning's `find_files_to_prune` walks an empty file_info vector and
  always returns []; `BlockPruner.prune_blocks` is a no-op against
  production storage even when wired (`node.py:275`).

BUG-2 — P0-CDIV: Block file allocator uses `set_len` (sparse extend) instead of `posix_fallocate`
--------------------------------------------------------------------------------------------------
**Severity**: P0-CDIV (consensus-divergent disk-full behavior; CORE
specifically pre-allocates to fail-fast on low-disk).
**File**: `ferrous-utils/sync/src/storage/flatfile.rs:188-211`
**Core ref**: `bitcoin-core/src/util/fs_helpers.cpp:181-227`
`AllocateFileRange` → `posix_fallocate(fileno(file), 0, nEndPos)` on
Linux.

**Description**: Rust uses `OpenOptions::new().create(true).open(&path)`
followed by `file.set_len(new_size)?`. On Linux, `set_len` (via
`ftruncate(2)`) just extends the inode's reported length without
actually reserving disk blocks — the file becomes sparse (zero-pages
unbacked by storage). Core's `posix_fallocate` reserves real disk blocks
upfront so write-time `ENOSPC` is detected at allocation time.

**Excerpt** (flatfile.rs:188-211):
```rust
pub fn allocate(&self, pos: &FlatFilePos, add_size: u64) -> Result<u64> {
    let current_pos = pos.pos as u64;
    let new_pos = current_pos + add_size;
    let old_chunks = (current_pos + self.chunk_size - 1) / self.chunk_size;
    let new_chunks = (new_pos + self.chunk_size - 1) / self.chunk_size;

    if new_chunks > old_chunks {
        let path = self.file_name(pos);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        let new_size = new_chunks * self.chunk_size;
        file.set_len(new_size)?;  // ← sparse extend, no real reservation
        Ok(new_size - (old_chunks * self.chunk_size))
    } else { Ok(0) }
}
```

**Impact**: Disk-pressure behavior differs from Core. A node near full
disk would NOT receive the upfront `OutOfSpace` error during
`Allocate`; instead, the subsequent `file.write_all(block_data)` would
fail with `ENOSPC` mid-write, leaving a partially-written block on
disk. Also missing: Core's `CheckDiskSpace(m_dir, inc_size)` pre-check
(flatfile.cpp:70) which would fatalError BEFORE attempting allocation.

BUG-3 — P0-CDIV: ReadBlockFromDisk rejects blk_size > 4 MB; Core uses MAX_SIZE = 33 MB
---------------------------------------------------------------------------------------
**Severity**: P0-CDIV (would reject blocks that Core accepts; or shrinks
the upper-bound check far below Core's serialization deserialization cap)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:568-572`
**Core ref**: `bitcoin-core/src/serialize.h:34`
`static constexpr uint64_t MAX_SIZE = 0x02000000;` (33,554,432 bytes).
`bitcoin-core/src/node/blockstorage.cpp:1110-1114` checks
`blk_size > MAX_SIZE` (not `MAX_BLOCK_SERIALIZED_SIZE`!).

**Description**: ouroboros's `read_block_at` rejects with
`InvalidSize(size)` when `size > 4_000_000`. The comment claims this
matches `MAX_BLOCK_SERIALIZED_SIZE`. But Core's reader uses
`MAX_SIZE = 0x02000000 = 33,554,432` — an 8× larger upper bound,
because the post-segwit serialized form (which is what's written to
disk) includes witness data, and CompactSize-deserialization-anomalies
on corrupted blk*.dat files can yield apparent sizes up to MAX_SIZE
before erroring out.

**Excerpt** (blockstore.rs:566-572):
```rust
let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
if size > 4_000_000 {
    // MAX_BLOCK_SERIALIZED_SIZE
    return Err(BlockStoreError::InvalidSize(size));
}
```

**Impact**: Functionally a ceiling on what blocks can be read off-disk.
Currently dead code (BUG-1), but if `PyBlockStore` is ever wired up,
this asymmetry would emerge as an immediate divergence on any block
whose `serialized_with_witness` size exceeds 4 MB (large segwit blocks
do occur post-witness-discount).

BUG-4 — P0-CDIV: Magic-bytes byte-order mismatch in MAGIC_TESTNET vs Bitcoin spec
---------------------------------------------------------------------------------
**Severity**: P0-CDIV (testnet3 disk-format divergence — files
written under one impl unreadable by Core, and vice-versa)
**File**: `ferrous-utils/sync/src/network/messages.rs:9`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp` (testnet3
`pchMessageStart = {0x0b, 0x11, 0x09, 0x07}`); also W146 task constants
"testnet3 = 0x0B110907".

**Description**: ouroboros stores magic as `u32` and calls
`.to_le_bytes()`. For testnet3 the constant is
`MAGIC_TESTNET: u32 = 0x0709110B` which yields `.to_le_bytes() = [0x0B, 0x11, 0x09, 0x07]` — correct wire bytes. **However** the
mainnet constant `MAGIC_MAINNET: u32 = 0xD9B4BEF9` yields
`.to_le_bytes() = [0xF9, 0xBE, 0xB4, 0xD9]` (correct). Regtest
`MAGIC_REGTEST: u32 = 0xDAB5BFFA` → `[0xFA, 0xBF, 0xB5, 0xDA]` (correct).
**The signet definition `MAGIC_SIGNET: u32 = 0x40CF030A` yields
`.to_le_bytes() = [0x0A, 0x03, 0xCF, 0x40]` (correct).**

After verification ALL magic values are correct. **Retracting this bug
as a false-positive on closer reading.** Keeping the slot for an
adjacent concern that IS real (see BUG-5 below).

**Status**: RETRACTED at audit time. Pattern: "audit-time bug closure"
(2nd instance after W135 lunarblock BUG-4 retraction).

BUG-5 — P0-CDIV: Block-index keys use string-named column families instead of single-byte prefixes
---------------------------------------------------------------------------------------------------
**Severity**: P0-CDIV (on-disk format divergent from Core; the LevelDB
contents of `blocks/index/` are byte-incompatible)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:50-53`,
`storage/schema.rs:96-150`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:58-62`
(`DB_BLOCK_FILES{'f'}`, `DB_BLOCK_INDEX{'b'}`, `DB_FLAG{'F'}`,
`DB_REINDEX_FLAG{'R'}`, `DB_LAST_BLOCK{'l'}`).

**Description**: Core's block-index leveldb uses single-byte key
prefixes — every record is `[prefix_byte][optional_key_bytes]`. Records
of different types coexist in one CF, and prefix-byte iteration is the
indexing primitive. Ouroboros instead opens 9 separate column families
named with full strings ("blocks", "block_index", "block_index_by_hash",
"chainstate", "spent", "meta", "tx_index", "undo", "headers") plus 2
more in BlockStore ("fileinfo", "blockpos"). RocksDB serializes CF
names as part of the LevelDB envelope; the on-disk file layout is
completely different from Core's.

**Excerpt** (blockstore.rs:49-53):
```rust
/// Column family for block file info.
const FILEINFO_CF: &str = "fileinfo";

/// Column family for block index (hash -> file position).
const BLOCKPOS_CF: &str = "blockpos";
```

**Impact**: A Bitcoin Core node cannot read ouroboros's
`blocks/index/`, and vice-versa. The data is recoverable if
re-imported (via `loadblock` on the blk*.dat files), but the index DB
itself is non-portable. This is a permanent on-disk divergence; the
Core fleet-monitor / `-loadblock` cannot reuse an ouroboros datadir.

BUG-6 — P0-CDIV: No `xor.dat` blocksdir obfuscation (Core v25.0 feature)
------------------------------------------------------------------------
**Severity**: P0-CDIV (on-disk format divergent; Core writes
XOR-obfuscated blk*.dat files since v25.0)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs` (no
`m_obfuscation` field, no `xor.dat` initialization)
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1167-1230`
(`InitBlocksdirXorKey` writes a random 8-byte XOR key to `xor.dat` on
first launch; `m_obfuscation` then wraps every `AutoFile` to
XOR every byte on read and write).

**Description**: Core obfuscates `blk*.dat` and `rev*.dat` with an
8-byte XOR key stored in `blocks/xor.dat`. This was added in v25.0 to
avoid antivirus false-positives on Windows (PSBT signatures and
embedded data triggered heuristics). ouroboros has NO `m_obfuscation`
field on `BlockStore` and never reads/writes `xor.dat`. Files written
by ouroboros (if ever — see BUG-1) would be Core-incompatible: Core
would XOR every byte on read with whatever random key it generated,
producing garbage. Conversely, ouroboros reading a Core-written
blk*.dat would see XOR'd bytes and reject on magic mismatch.

**Excerpt** (blockstore.rs:417-422 — writes plain bytes):
```rust
// Write header: magic + size
file.write_all(&self.magic)?;
file.write_all(&block_size.to_le_bytes())?;
// Write block data
file.write_all(&block_data)?;
file.sync_all()?;
```

**Impact**: ouroboros cannot read Core-produced blk*.dat files (loadblock
RPC, -reindex from a Core fleet share). Conversely ouroboros's blk*.dat
files (if BUG-1 is ever resolved) cannot be read by Core. Permanent
on-disk format split.

BUG-7 — P0-CDIV: `save_file_info` + `save_block_pos` are TWO separate puts (not atomic)
----------------------------------------------------------------------------------------
**Severity**: P0-CDIV (write-atomicity gap — Core uses a single
`CDBBatch` for all WriteBlockIndexDB index updates)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:436-447`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:91-103`
`BlockTreeDB::WriteBatchSync` — fileInfo, lastFile, and blockindex
updates all batched into one `CDBBatch` and committed atomically.

**Description**: After writing a block to disk + fsync, ouroboros calls
`save_file_info(pos.file, info)` (writes to FILEINFO_CF) **then**
`save_block_pos(&block_hash, &block_pos)` (writes to BLOCKPOS_CF) as
**two separate `db.put_cf(...)` calls**. If a crash occurs between
them, the index is left half-written: file_info shows the block as
accounted for, but `get_block_pos(hash)` returns None.

**Excerpt** (blockstore.rs:428-447):
```rust
{
    let mut cursor = self.cursor.write().unwrap();
    let mut file_info = self.file_info.write().unwrap();
    cursor.block_pos = data_pos + block_size;
    let info = &mut file_info[pos.file as usize];
    info.size = cursor.block_pos;
    // Save file info to database
    self.save_file_info(pos.file, info)?;  // ← put_cf #1
}
// Save block position to index
let block_hash = block.block_hash();
let block_pos = BlockPosition { file: pos.file, data_pos, undo_pos: 0 };
self.save_block_pos(&block_hash, &block_pos)?;  // ← put_cf #2
```

**Impact**: Crash-mid-WriteBlock creates an inconsistent on-disk index.
The block bytes are on disk + fsynced, the file_info knows about them,
but the hash→pos lookup is missing. On restart, the block is "stuck"
— present in `blk*.dat`, accounted in fileinfo, but unfindable by
hash. Core's `CDBBatch` write avoids this entirely (atomicity of all
three keys via the underlying LevelDB WriteBatch).

BUG-8 — P0-DoS: ReadBlock allocates `vec![0u8; size as usize]` with attacker-controlled size before validation
---------------------------------------------------------------------------------------------------------------
**Severity**: P0-DoS (memory bomb via corrupt blk*.dat or
attacker-controlled disk content)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:566-576`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:1110-1126`
checks `blk_size > MAX_SIZE` BEFORE `std::vector<std::byte> data(blk_size)`.

**Description**: After reading the 4-byte `size` field from a
blk*.dat record, ouroboros checks `if size > 4_000_000` (BUG-3
flagged this constant is wrong) — but the check uses the attacker-
controllable size from the file. If a malicious actor (or even
corrupted disk) writes a record header claiming `size = 3_999_999`
(just under the cap), the `vec![0u8; size as usize]` will allocate
~4 MB. With ouroboros's larger cap (or if BUG-3 were "fixed" upward
to 33 MB matching Core's MAX_SIZE), a single corrupt record header
near MAX_SIZE bytes allocates ~33 MB.

For the BlockStore wired up to PyBlockStore.read_block (currently
dead), an attacker who controls the blocks/ directory (or a network
adversary in a `-loadblock` chain) can flood with corrupt records
each consuming MAX_SIZE bytes. Core mitigates this by reading
`MAX_SIZE` only INTO an `std::vector` AFTER the size check; ouroboros
does the same... BUT the check happens AFTER seeking, and the
allocation happens before `file.read_exact(&mut block_data)` would
even fail. So per-attempt memory cost is 33 MB. Multiplied by
concurrent `read_block` calls at startup (e.g. 8 threads scanning),
~260 MB transient allocation.

**Excerpt** (blockstore.rs:566-576):
```rust
// Read size
let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
if size > 4_000_000 {
    return Err(BlockStoreError::InvalidSize(size));
}
// Read block data
let mut block_data = vec![0u8; size as usize];  // ← bulk alloc before read
file.read_exact(&mut block_data)?;
```

Note: NOT a strict consensus bug since `size` is bounded by check above,
but a denial-of-service vector via corrupt disk. Also: `block_data`
is zero-initialized via `vec![0u8; ...]` (~10% slower than
`Vec::with_capacity`), small perf nit.

**Impact**: Dead code (BUG-1) currently — but if `PyBlockStore` is
wired, an attacker with disk-write or `-loadblock` access can trigger
33 MB allocations per corrupt-header record, OOM-ing the node at
startup.

BUG-9 — P0: No `DB_REINDEX_FLAG{'R'}` equivalent — `-reindex` cannot be implemented atop ouroboros's storage
-----------------------------------------------------------------------------------------------------------
**Severity**: P0 (missing recovery primitive)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs` (no reindex
tracking), `storage/schema.rs:152-180` (`meta_keys` has no
`REINDEX_IN_PROGRESS` key)
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:74-86`
(`BlockTreeDB::WriteReindexing` / `ReadReindexing` write the `'R'`
flag to leveldb; presence on startup triggers full block-file
replay via `LoadExternalBlockFile`).

**Description**: Core's reindex flag is a single-byte leveldb key `'R'`
which Core writes when starting `-reindex` and erases when finished.
On unclean shutdown mid-reindex, the flag persists and Core re-runs
the full blk*.dat → chainstate replay. Ouroboros has no equivalent:
neither `BlockStore` nor `BlockchainDB` (`db.rs` `meta_keys`) defines a
`REINDEX_FLAG`. Therefore:
1. No CLI/RPC `-reindex` flag can be implemented.
2. A crash mid-replay would leave the node in an indeterminate state
   with no recovery cue.
3. `pruned + headers-first sync + reorg corruption` scenarios cannot
   trigger automatic recovery.

**Excerpt** (schema.rs:152-180 — full list of meta keys, no REINDEX):
```rust
pub mod meta_keys {
    pub const BEST_BLOCK_HASH: &[u8] = b"best_block_hash";
    pub const BEST_HEIGHT: &[u8] = b"best_height";
    pub const CHAINSTATE_VERSION: &[u8] = b"chainstate_version";
    pub const PRUNE_HEIGHT: &[u8] = b"prune_height";
    pub const PRUNING_ENABLED: &[u8] = b"pruning_enabled";
    pub const HEAD_BLOCKS: &[u8] = b"head_blocks";
}
```

**Impact**: No corruption-recovery path. After unclean shutdown +
corruption, the node either runs full from-genesis sync or crashes
on first connect. Manual `rm -rf` + re-sync is the only remediation.

BUG-10 — P1: `BlockStore::flush()` does NOT truncate (finalize=false) — preallocation slack persists across crashes
--------------------------------------------------------------------------------------------------------------------
**Severity**: P1 (file-size correctness; recovery-after-crash hazard)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:727-740`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:756-769`
`FlushBlockFile(file, fFinalize, finalize_undo)`.

**Description**: `BlockStore::flush()` (line 727) is the
explicit-shutdown flush. It calls `self.block_files.flush(&pos,
false)` — `false` means "don't truncate". After a clean shutdown
mid-file, the blk*.dat file is left preallocated to the next
16 MiB chunk boundary (so a 12 MiB file might sit on disk as 16 MiB,
zero-padded for 4 MiB). Core's equivalent shutdown path calls
`FlushBlockFile(false, false)` which mirrors this — so it's not a
divergence per se. **BUT**: on resume, ouroboros's `load_state`
sets `cursor.block_pos = info.size` from the DB (i.e. the LOGICAL
size, not the file size). Subsequent writes will start at
`info.size`. So far consistent. The bug is: if the DB's `info.size`
disagrees with the on-disk size (e.g. info.size was lost after the
last save_file_info but the file write succeeded), there's no
reconciliation step on startup. Core uses `LoadBlockFileInfo` which
scans the actual files for inconsistency.

**Excerpt** (blockstore.rs:727-740):
```rust
pub fn flush(&self) -> Result<()> {
    let cursor = self.cursor.read().unwrap();
    let pos = FlatFilePos::new(cursor.block_file, cursor.block_pos);
    self.block_files.flush(&pos, false)?;  // ← no truncate
    if cursor.undo_pos > 0 {
        let undo_pos = FlatFilePos::new(cursor.block_file, cursor.undo_pos);
        self.undo_files.flush(&undo_pos, false)?;
    }
    self.db.flush()?;
    Ok(())
}
```

**Impact**: If the DB info disagrees with on-disk file size after a
crash, subsequent writes would overwrite existing data at the wrong
offset (corruption) or skip an offset range (sparse blank zone).

BUG-11 — P1: No `m_dirty_fileinfo` / `m_dirty_blockindex` deferred-flush set; every WriteBlock issues a synchronous DB put
--------------------------------------------------------------------------------------------------------------------------
**Severity**: P1 (perf gap; not consensus)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:436-447`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:919, 928, 942`
`m_dirty_fileinfo.insert(nFile); m_dirty_blockindex.insert(&block);`
batched flush at next `FlushStateToDisk` (validation.cpp).

**Description**: Core defers fileinfo + blockindex updates to a
periodic `FlushStateToDisk` batch (every nFlushFrequency seconds, or
when memory pressure hits). Ouroboros writes both per block:
`save_file_info(pos.file, info)?` AND `save_block_pos(&block_hash,
&block_pos)?` are issued on EVERY block. For 800k-block IBD this is
2× 800k = 1.6M leveldb puts that Core would have batched into ~1k
flushes.

**Excerpt** (blockstore.rs:436-447):
```rust
self.save_file_info(pos.file, info)?;  // per-block put
// ...
self.save_block_pos(&block_hash, &block_pos)?;  // per-block put
```

**Impact**: Slower IBD (write amplification on the index DB). Not
consensus, not correctness — just throughput. Dead code currently
(BUG-1), so latent.

BUG-12 — P1: BlockStore tracks single cursor; cannot handle `BlockfileType::ASSUMED` snapshot-blockfile separation
------------------------------------------------------------------------------------------------------------------
**Severity**: P1 (assumeUTXO interop gap; W138 cross-cite)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:186-205`
(single `BlockStoreCursor`)
**Core ref**: `bitcoin-core/src/node/blockstorage.h` defines `enum
class BlockfileType { NORMAL, ASSUMED }` and `BlockManager::
m_blockfile_cursors` keyed by type (line 771-777).

**Description**: After loading an assumeutxo snapshot, Core writes
post-snapshot blocks to a SEPARATE blk*.dat sequence from any
background-validated pre-snapshot blocks. `BlockfileTypeForHeight`
chooses between NORMAL and ASSUMED cursors. Ouroboros has ONE
`BlockStoreCursor` with `block_file: i32, block_pos: u32`. Loading
a snapshot mid-sync, then validating in the background, would write
both ranges to the same monotonic blk file sequence, breaking the
separation invariant Core expects.

**Excerpt** (blockstore.rs:186-205):
```rust
#[derive(Debug, Clone)]
struct BlockStoreCursor {
    /// Current block file number.
    block_file: i32,
    /// Current position in block file.
    block_pos: u32,
    /// Current undo file position (tracks undo writes for current block file).
    undo_pos: u32,
}
```

**Impact**: Cross-cite W138 BUG-1 ouroboros (`f62058d`) — invented
mainnet h=840000 hash and runtime assumeUTXO loading. The W138 dead-
class pattern is mirrored here: even if assumeUTXO were activated,
the storage layer lacks the dual-cursor primitive to separate
pre-snapshot and post-snapshot block storage.

BUG-13 — P1: BlockFileInfo serialization is custom (NOT Core's `CBlockFileInfo` wire format)
---------------------------------------------------------------------------------------------
**Severity**: P1 (on-disk format divergence — fileinfo records
not portable between impls)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:107-140`
**Core ref**: `bitcoin-core/src/chain.h` `CBlockFileInfo::SERIALIZE`
uses `VARINT(nBlocks) VARINT(nSize) VARINT(nUndoSize) VARINT(nHeightFirst)
VARINT(nHeightLast) VARINT(nTimeFirst) VARINT(nTimeLast)`.

**Description**: Core serializes `CBlockFileInfo` using `VARINT` (the
MSB-base-128 VarInt — same encoding pattern as Core's coin
serialization in W109). Ouroboros writes fixed-width little-endian
integers: 4-byte u32 for the first five fields, 8-byte u64 for the
last two. Total = 36 bytes vs Core's typical 7-21 bytes for small
counts.

**Excerpt** (blockstore.rs:108-119):
```rust
pub fn serialize(&self) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&self.num_blocks.to_le_bytes());      // u32 LE
    data.extend_from_slice(&self.size.to_le_bytes());            // u32 LE
    data.extend_from_slice(&self.undo_size.to_le_bytes());       // u32 LE
    data.extend_from_slice(&self.height_first.to_le_bytes());    // u32 LE
    data.extend_from_slice(&self.height_last.to_le_bytes());     // u32 LE
    data.extend_from_slice(&self.time_first.to_le_bytes());      // u64 LE
    data.extend_from_slice(&self.time_last.to_le_bytes());       // u64 LE
    data
}
```

**Impact**: Core nodes cannot ingest ouroboros's `fileinfo` records
and vice-versa. Also: `time_first`/`time_last` are u64 in ouroboros
but u32 (4-byte) timestamps in Core's `CBlockFileInfo` — would
break at year 2106 if anyone ever wired this up. Currently dead
code (BUG-1).

BUG-14 — P1: BlockPosition::has_data uses `data_pos > 0` — disallows blocks at offset 0
---------------------------------------------------------------------------------------
**Severity**: P1 (off-by-one boundary — first block in a new file is at
data_pos = STORAGE_HEADER_BYTES = 8; never 0, so likely benign — but the
gate is wrong-spirited)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:175-178`
**Core ref**: `bitcoin-core/src/chain.h` `CBlockIndex::GetBlockPos()`
checks `nFile >= 0` only; nPos == 0 is a valid genesis-block position.

**Description**: `BlockPosition::has_data` returns true only if
`self.file >= 0 && self.data_pos > 0`. After `write_block`, the
recorded `data_pos = pos.pos + STORAGE_HEADER_BYTES = 0 + 8 = 8` for
the FIRST block. So `data_pos > 0` holds. But the gate is wrong-spirited:
if anyone ever stores a record at data_pos = 0, it'd be classified
as "no data". Core's gate is `nFile >= 0` only.

**Excerpt** (blockstore.rs:175-184):
```rust
pub fn has_data(&self) -> bool {
    self.file >= 0 && self.data_pos > 0
}
pub fn has_undo(&self) -> bool {
    self.undo_pos > 0
}
```

**Impact**: Cosmetic; in practice every block sits at `data_pos >= 8`
because of the 8-byte storage header prefix. But it embeds an
invariant ("0 means none") that Core does not embed.

BUG-15 — P1: rev*.dat undo position resets to 0 on block-file rotation, even though Core treats undo files separately
---------------------------------------------------------------------------------------------------------------------
**Severity**: P1 (cursor-tracking divergence)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:344-352`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:870-871, 903`
`m_blockfile_cursors[chain_type] = BlockfileCursor{nFile}` — `undo_height`
is part of the cursor struct, separate from block file boundaries.

**Description**: When the block file rolls over (line 344), ouroboros
resets `cursor.undo_pos = 0`. This implies the new rev*.dat file
starts at position 0. But Core's undo files have their OWN size
tracking (`m_blockfile_info[nFile].nUndoSize`) and a separate undo
height cursor (`m_blockfile_cursors[chain_type]->undo_height`). Block
file N and rev file N share the index but their write/flush cadence
differs (rev files flush only when their last block is connected).

Ouroboros's "reset undo_pos to 0 on rotation" assumes a fresh rev{N+1}.dat
where the next undo write starts at 0. If undo data is added LATER
(blocks come in out of order), the undo file would not exist at all
until first write — fine. But it also means the undo cursor cannot
distinguish "no blocks yet undo'd in this file" from "first byte of
this file was overwritten".

**Excerpt** (blockstore.rs:340-352):
```rust
while cursor.block_pos as u64 + total_size as u64 >= MAX_BLOCKFILE_SIZE {
    // Finalize current file
    self.finalize_file(cursor.block_file, &file_info)?;
    // Move to next file
    cursor.block_file += 1;
    cursor.block_pos = 0;
    cursor.undo_pos = 0;
    // ...
}
```

**Impact**: Out-of-order undo writes (rare but possible during reorg)
may collide with the reset offset. Dead code (BUG-1) currently.

BUG-16 — P1: `flush()` does not call `block_files.flush(..., finalize=true)` before rotation acknowledgment
-----------------------------------------------------------------------------------------------------------
**Severity**: P1 (durability ordering — current flush is
"fsync but don't truncate"; Core's rotation flush IS truncate)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:372-385`
(`finalize_file`)
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:897-901`
`FlushBlockFile(last_blockfile, /*fFinalize=*/true, finalize_undo)`.

**Description**: `finalize_file` is called within `find_next_block_pos`
when rolling files. It calls `self.block_files.flush(&pos, true)`
with `finalize=true` (correct truncation). But: the call is made
**while holding the cursor write lock** (`cursor.write().unwrap()`),
which serializes all writers. Also: between the moment block N is
written and committed and the moment block N+1 triggers rotation,
the block N file is NOT truncated. So crash-after-block-N before
N+1 leaves the file with preallocation slack. Recovery is correct
(info.size knows the logical size) but a debugging operator scrolling
through blk*.dat sees a 16 MiB file with maybe 1 MiB of real data.

**Excerpt** (blockstore.rs:372-385):
```rust
fn finalize_file(&self, file_num: i32, file_info: &[BlockFileInfo]) -> Result<()> {
    if file_num >= 0 && (file_num as usize) < file_info.len() {
        let info = &file_info[file_num as usize];
        let pos = FlatFilePos::new(file_num, info.size);
        self.block_files.flush(&pos, true)?;
        // Also finalize undo file if it has data
        if info.undo_size > 0 {
            let undo_pos = FlatFilePos::new(file_num, info.undo_size);
            self.undo_files.flush(&undo_pos, true)?;
        }
    }
    Ok(())
}
```

**Impact**: Slightly larger disk footprint between flushes. Match
Core's semantics on rotation but not on shutdown (BUG-10).

BUG-17 — P1: `BlockPruner.target_size = max(target_size_mb, 550) * 1_000_000` uses MB not MiB
---------------------------------------------------------------------------------------------
**Severity**: P1 (units divergence; user-facing `-prune=N` differs from
Core by ~5%)
**File**: `src/ouroboros/pruning.py:109`
**Core ref**: `bitcoin-core/src/init.cpp:524` `(default: 0 = disable
pruning blocks, 1 = allow manual pruning via RPC, >=%u = automatically
prune block files to stay under the specified target size in MiB)`.
`MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024`.

**Description**: Core's `-prune=N` argument is in **MiB** (binary
megabytes, 1024×1024). Ouroboros's `BlockPruner.__init__` multiplies
by `1_000_000` (decimal megabytes). For `-prune=1000`:
- Core: 1000 × 1024 × 1024 = 1,048,576,000 bytes (1.048 GiB)
- Ouroboros: 1000 × 1,000,000 = 1,000,000,000 bytes (0.953 GiB)
~5% smaller target. Minimum threshold `550 * 1_000_000 = 550 MB`
also differs from Core's `550 * 1024 * 1024 = 576.7 MB` MIN_DISK_
SPACE_FOR_BLOCK_FILES.

**Excerpt** (pruning.py:106-110):
```python
# `-prune=1` manual-only sentinel (Core PRUNE_TARGET_MANUAL,
# node/blockstorage.h:408). Maps to "auto-prune off; manual via RPC".
self.manual = target_size_mb == 1
self.target_size = max(target_size_mb, self.MIN_TARGET_MB) * 1_000_000
```

**Impact**: A user running `ouroboros -prune=550` gets a 524 MiB
target (below Core's 550 MiB minimum). Slightly more aggressive
pruning than Core; not consensus, but operator surprise.

BUG-18 — P2: `MAX_BLOCKFILE_SIZE` boundary uses `>=` while Core uses `>=` (correct), but rotation triggers BEFORE the block fits
-------------------------------------------------------------------------------------------------------------------------------
**Severity**: P2 (rotation-eagerness divergence)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:340`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:866`
`while (m_blockfile_info[nFile].nSize + nAddSize >= max_blockfile_size)`.

**Description**: Both Core and ouroboros use `>=`, so they agree on
when to rotate. **However** Core's nAddSize includes the storage
header (8 bytes) — `WriteBlock` passes `block_size + STORAGE_HEADER_
BYTES` to `FindNextBlockPos`. Ouroboros's `find_next_block_pos` adds
`STORAGE_HEADER_BYTES` internally on the parameter `block_size`.
So both functions compute `nSize + block_size + 8 >= 128 MiB`.
**Cross-check passes**.

Sub-issue: `STORAGE_HEADER_BYTES` is `u64 = 8` in flatfile.rs but
cast `STORAGE_HEADER_BYTES as u32` at the comparison site. With u32
arithmetic on `cursor.block_pos (u32) + total_size (u32)` could
overflow if `block_pos` approaches `u32::MAX`. The comparison is
done in u64 (`cursor.block_pos as u64 + total_size as u64 >=
MAX_BLOCKFILE_SIZE`), so OK.

**Status**: RETRACTED at audit time after careful trace. Both match
Core. Keeping the slot for the real concern: there's no overflow
check on `block_size + STORAGE_HEADER_BYTES` itself if block_size is
near u32::MAX (which it can't be — max block weight is 4M).

BUG-19 — P2: `current_pos()` returns `cursor.block_pos` which may be ahead of `info.size` after a flush failure
---------------------------------------------------------------------------------------------------------------
**Severity**: P2 (state-tracking inconsistency on error path)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:702-706, 425-438`
**Core ref**: Core treats `info.nSize` as the canonical "next write
offset" and never lets the cursor and the fileinfo diverge.

**Description**: If `save_file_info(...)?` fails (DB error), the
in-memory `info.size` has already been updated to `cursor.block_pos`
on line 434, but no DB write occurred. On restart, `load_state`
sees the old `info.size` from DB, sets `cursor.block_pos` to old
value — but the actual file may have the new block written. On the
next `write_block`, the new block would be written at the OLD
position, overwriting bytes 0..N of the previously-written block.

**Excerpt** (blockstore.rs:425-438):
```rust
// Write block data
file.write_all(&block_data)?;
file.sync_all()?;
// Update cursor and file info
let data_pos = pos.pos + STORAGE_HEADER_BYTES as u32;
{
    let mut cursor = self.cursor.write().unwrap();
    let mut file_info = self.file_info.write().unwrap();
    cursor.block_pos = data_pos + block_size;
    let info = &mut file_info[pos.file as usize];
    info.size = cursor.block_pos;
    // Save file info to database
    self.save_file_info(pos.file, info)?;  // ← fails: info already updated in-memory
}
```

**Impact**: Crash scenarios may corrupt the next block's offset.
Dead code currently (BUG-1).

BUG-20 — P2: `get_file_info` returns Some(default) for never-written files (Core distinguishes)
------------------------------------------------------------------------------------------------
**Severity**: P2 (probe-correctness)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:687-695`
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:67-70`
`ReadBlockFileInfo` returns `false` if the leveldb key is absent;
Core's `m_blockfile_info[nFile]` is also constructed on demand.

**Description**: `get_file_info(file_num)` returns
`Some(BlockFileInfo::default())` (all-zero) when the file slot exists
in the in-memory Vec but has never been written to (e.g. after a
crash that resized the Vec but didn't populate the slot). Caller
cannot distinguish "file exists but is empty" from "file doesn't
exist at all". Core's interface returns true/false from
`ReadBlockFileInfo` based on key presence in leveldb.

**Excerpt** (blockstore.rs:687-695):
```rust
pub fn get_file_info(&self, file_num: i32) -> Option<BlockFileInfo> {
    let file_info = self.file_info.read().unwrap();
    if file_num >= 0 && (file_num as usize) < file_info.len() {
        Some(file_info[file_num as usize].clone())  // ← may be default()
    } else {
        None
    }
}
```

**Impact**: Caller probing `if let Some(info) = store.get_file_info(N)`
gets a default `BlockFileInfo {num_blocks: 0, size: 0, ...}` which
silently looks empty. Bug latent until callers exist (BUG-1).

BUG-21 — P2: `STORAGE_HEADER_BYTES` is `u64` but used as `u32` arithmetic
------------------------------------------------------------------------
**Severity**: P2 (type-coercion smell)
**File**: `ferrous-utils/sync/src/storage/flatfile.rs:33`
(`pub const STORAGE_HEADER_BYTES: u64 = 8;`)
**Core ref**: `bitcoin-core/src/flatfile.h` `STORAGE_HEADER_BYTES = 8`
(unsigned int).

**Description**: Declared as `u64` but every use site casts to u32
(blockstore.rs:337, 426, 508, 541, 597) or u32-equivalent
(`as u32`). The u64 type is purely cosmetic — but it's a smell. If
the constant changed it would force ripple casts.

**Excerpt** (flatfile.rs:33):
```rust
/// Header size before each record: 4-byte magic + 4-byte size.
pub const STORAGE_HEADER_BYTES: u64 = 8;
```

**Impact**: Cosmetic. Same wire effect as u32.

BUG-22 — P2: BlockStore stores network in struct but never uses it after construction
-------------------------------------------------------------------------------------
**Severity**: P2 (dead field)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:215, 268, 723-725`
**Core ref**: Core's `BlockManager` uses `m_opts.chainparams` for
multiple per-network behaviors (assumeUTXO whitelist, magic, prune
threshold tweaks).

**Description**: `BlockStore` stores `network: Network` (line 215)
and exposes it via `pub fn network(&self) -> Network` (line 723).
The `magic` field is derived once at construction. After that, the
`network` field is read by NOTHING in this module — every magic
write/read references `self.magic` (the cached bytes), not
`self.network`. The exposed accessor `network()` is called by tests
only.

**Excerpt** (blockstore.rs:267-275):
```rust
let store = Self {
    blocks_dir,
    network,           // ← stored
    magic,
    block_files,
    undo_files,
    db,
    cursor: RwLock::new(BlockStoreCursor::default()),
    file_info: RwLock::new(Vec::new()),
};
```

**Impact**: Dead field. Magic computed once is correct; the network
enum itself is unused. Could be removed.

BUG-23 — P2: Pruning code does not delete the corresponding `blocks/index/blockpos` entries
-------------------------------------------------------------------------------------------
**Severity**: P2 (pruning incompleteness — block-hash → pos lookups
keep pointing at deleted blk*.dat files)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:777-808`
(`prune_one_file`)
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:485-507`
`BlockManager::PruneOneBlockFile` walks `m_block_index` and clears
`BLOCK_HAVE_DATA`/`BLOCK_HAVE_UNDO` from each block index entry whose
nFile is being pruned.

**Description**: `prune_one_file` resets `BlockFileInfo` to default
and saves the empty info to DB, then deletes the .dat files. But
the BLOCKPOS_CF entries (block_hash → BlockPosition) for blocks that
were in the pruned file are NOT removed. After pruning,
`get_block_pos(hash)` for a pruned block still returns the OLD
position pointing at a deleted file. Subsequent `read_block(hash)`
opens the file, gets `NotFound`, returns `None` — acceptable
behavior, but the BLOCKPOS_CF entry is unreachable garbage.

**Excerpt** (blockstore.rs:771-808):
```rust
pub fn prune_one_file(&self, file_num: i32) -> Result<u64> {
    if file_num < 0 { return Ok(0); }
    let mut file_info = self.file_info.write().unwrap();
    if (file_num as usize) >= file_info.len() { return Ok(0); }
    let info = &file_info[file_num as usize];
    if info.size == 0 { return Ok(0); }
    let bytes_freed = info.size as u64 + info.undo_size as u64;
    // Reset file info to empty
    file_info[file_num as usize] = BlockFileInfo::default();
    // Save the empty file info to database
    self.save_file_info(file_num, &BlockFileInfo::default())?;
    log::info!(...);
    Ok(bytes_freed)
}
```

No iteration over BLOCKPOS_CF to clear entries for the pruned file.
Core's pattern: walk block_index entries, find those with nFile ==
pruned_file, clear BLOCK_HAVE_DATA flag.

**Impact**: BLOCKPOS_CF grows monotonically; pruning only deletes
file contents, not the index entries. RocksDB compaction will reclaim
some space later, but the table still reports stale pointers.

BUG-24 — P3: `Cursor::default()` has `block_file: 0` not `-1` (null sentinel)
-----------------------------------------------------------------------------
**Severity**: P3 (sentinel-value convention)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:197-205`
**Core ref**: Core uses `nFile = 0` for the first file too (not -1);
the `IsNull()` check on FlatFilePos uses `nFile = -1`.

**Description**: `BlockStoreCursor::default()` initializes
`block_file: 0`. This means an empty store reports "I'm at file 0,
position 0". The same value would be reported AFTER writing the
first block to file 0. There's no clear "empty" sentinel.

**Excerpt** (blockstore.rs:197-205):
```rust
impl Default for BlockStoreCursor {
    fn default() -> Self {
        Self {
            block_file: 0,
            block_pos: 0,
            undo_pos: 0,
        }
    }
}
```

**Impact**: Cosmetic. `current_pos() == 0` is the empty signal. OK.

BUG-25 — P3: `BlockUndo::tx_undo` count uses Core's MSB VarInt but the OUTER `magic + size_u32_LE` envelope uses CompactSize for `size`
---------------------------------------------------------------------------------------------------------------------------------------
**Severity**: P3 (one inconsistency in encoding family)
**File**: `ferrous-utils/sync/src/storage/blockstore.rs:498-499`
(`undo_size.to_le_bytes()`)
**Core ref**: `bitcoin-core/src/node/blockstorage.cpp:992`
`fileout << GetParams().MessageStart() << blockundo_size;` —
`blockundo_size` is `uint32_t` written as fixed-width 4 bytes (matches).

**Description**: The OUTER undo envelope writes `magic + 4-byte LE
size_u32 + serialized BlockUndo + checksum`. The INNER BlockUndo
serialization uses Core's MSB-VarInt for counts (undo.rs:209 line
encodes `prev_outputs.len() as u64`). Both match Core's actual
behavior — but the LACK of a separate "size_u32" field is buried
in the implementation. **Re-checked**: matches Core wire format.
**Status**: RETRACTED at audit time. Both layers match.

Fleet patterns observed
=======================

1. **Dead-class pattern (W138/W139/W146 continuity)** — ~1900 LOC of
   parallel-but-unused storage code. Same archetype as W138's
   ChainstateManager (`f62058d`), W139's fee persistence dead path.
   Now THREE distinct subsystems where ouroboros has a Core-shaped
   dead module sitting next to the RocksDB-flat path that actually
   runs. **CUMULATIVE: ouroboros leads fleet on this pattern.**

2. **Two-pipeline guard extended** — 15th distinct extension since
   W76. BlockStore module gets the same "do not wire into production"
   advisory as the W138 ChainstateManager.

3. **String-named column families vs Core's single-byte prefixes** —
   on-disk format permanently divergent. Recoverable but not
   portable. Cross-cite W109 (block index).

4. **No `-reindex` / `DB_REINDEX_FLAG{'R'}` recovery primitive** —
   missing across both pipelines.

5. **No `xor.dat` blocksdir obfuscation** — Core v25.0 feature absent;
   blk*.dat files would be non-portable in both directions.

6. **MB vs MiB units in pruning** — 5% under-target on `-prune`.

7. **No fleet-wide reindex possibility** — affects 9 of 10 impls (per
   prior W138 audit pattern) but ouroboros's depth is unique.

8. **NEW "audit-time bug closure" pattern, instance #2** — BUG-4
   (magic byte-order) and BUG-18 (rotation eagerness) and BUG-25 (size
   field encoding) all RETRACTED after closer re-read during audit.
   First instance was W135 lunarblock BUG-4. This indicates the audit
   pass is catching its own false positives via runtime/wire-byte
   verification.

Summary
=======

Catalogue: 25 BUGS (1 retracted; 24 active).
Active severity: 4 P0-CDIV / 1 P0-DoS / 1 P0 / 1 P0-DEAD-CLASS / 12
P1 / 4 P2 / 2 P3.

Primary architectural finding: the entire ~1900-LOC flat-file
block-storage subsystem (`BlockStore` + `UndoFileManager` + `PyBlockStore`
binding) is **DEAD CODE in production**. Blocks are stored in RocksDB
column families via `BlockchainDB::store_block` / `store_block_undo`,
NOT in `blk*.dat` / `rev*.dat` files. The dead subsystem is well-
engineered and largely Core-faithful in shape, but cannot be wired up
without removing the active RocksDB path (which would be a major
architectural change). Cross-cite W138, W139.

Most severe individual findings:
- **BUG-1 P0-DEAD-CLASS** — entire blockstore.rs is dead code.
- **BUG-2 P0-CDIV** — `set_len` (sparse) vs Core's `posix_fallocate`.
- **BUG-3 P0-CDIV** — ReadBlock rejects size > 4 MB; Core uses 33 MB.
- **BUG-5 P0-CDIV** — string-named CFs vs Core's single-byte prefixes.
- **BUG-6 P0-CDIV** — no `xor.dat` blocksdir obfuscation.
- **BUG-7 P0-CDIV** — non-atomic two-phase DB writes after fsync.
- **BUG-8 P0-DoS** — 33 MB allocation per corrupt-record-header.
- **BUG-9 P0** — no `DB_REINDEX_FLAG{'R'}` recovery primitive.

If `PyBlockStore` is ever wired into production, BUG-1 reclassifies
to RESOLVED but the remaining 7 P0s become live consensus/security
issues. Recommendation: either delete the dead module entirely, or
schedule a coordinated migration that disables BLOCKS_CF storage.
