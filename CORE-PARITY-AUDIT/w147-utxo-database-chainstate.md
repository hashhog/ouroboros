W147 — UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB) audit (ouroboros)
==================================================================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline + Rust pipeline).

The UTXO-set / chainstate surface lives in THREE distinct code paths
that all ship and disagree on critical encoding/semantics:

  * **Rust live path A** — `PyBlockchainDB::connect_block_from_bytes`
    (`ferrous-utils/sync/src/lib.rs:3402`). Single WriteBatch per
    block; MultiGet prefetch + intra-block overlay HashMap. **Used by
    Python `BlockchainDatabase.connect_block_from_bytes` (the IBD
    write path).**
  * **Rust live path B** — `BlockchainDB::connect_block_at_height`
    (`ferrous-utils/sync/src/storage/db.rs:2559`). Per-input `get_cf`,
    NO intra-block overlay. **Used by the reactivation/reorg path.**
  * **Rust "CCoinsViewCache" lookalike** — `storage::coins::CoinsCache`
    (`ferrous-utils/sync/src/storage/coins.rs`, 894 LOC including
    DIRTY/FRESH flags, `connect_block_utxos`, `flush`, `sync`,
    `set_dbcache_bytes`). **Zero production callers — only invoked by
    its own `#[cfg(test)] mod tests`.** This is exactly the
    "dead-module" fleet pattern.

The chainstate value serializer (`UTXO::bitcoin_serialize`,
`common/src/serialize.rs:366`) and the undo-data Coin serializer
(`storage::undo::Coin::serialize`, `undo.rs:105`) use **DIFFERENT
encodings** for the same logical data — the live chainstate stores
raw, uncompressed UTXOs with an Option<u32>+1-byte-flag height; the
undo file uses Core-compatible `VARINT((height<<1)|fCoinBase) +
VARINT(CompressAmount(value))`.

Wave: W147 — CCoinsView / CCoinsViewCache / CCoinsViewDB / Coin
      compression / obfuscate_key / FlushStateToDisk / DIRTY+FRESH /
      AccessCoin+SpendCoin / batch atomicity / `'C'`-prefix DB key.

Reference (Bitcoin Core)
------------------------

- `bitcoin-core/src/coins.h:92-209` — `CCoinsCacheEntry`, DIRTY/FRESH
  flags, sentinel-linked-list of flagged entries (lines 100-107
  document the four legal states).
- `bitcoin-core/src/coins.h:307-343` — `CCoinsView` virtual interface:
  `GetCoin`, `PeekCoin` (non-caching!), `HaveCoin`, `GetBestBlock`,
  `GetHeadBlocks`, `BatchWrite(cursor, hashBlock)`, `Cursor()`,
  `EstimateSize()`.
- `bitcoin-core/src/coins.h:367-509` — `CCoinsViewCache` API:
  `AddCoin`, `EmplaceCoinInternalDANGER` (snapshot bulk-load — bypass
  validation), `SpendCoin`, `AccessCoin`, `Flush`, `Sync`, `Uncache`,
  `HaveCoinInCache`, `HaveInputs`, `ReallocateCache`,
  `DynamicMemoryUsage`, `GetCacheSize`, `GetDirtyCount`.
- `bitcoin-core/src/txdb.cpp:23-27` — DB-key prefix bytes: `DB_COIN =
  'C'` (current), `DB_BEST_BLOCK = 'B'`, `DB_HEAD_BLOCKS = 'H'`,
  `DB_COINS = 'c'` (deprecated v0.15).
- `bitcoin-core/src/txdb.cpp:43-49` — `CoinEntry` serializer:
  `READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n))`.
  **Key = 1-byte 'C' + 32-byte txid + VARINT(vout)** — NOT a
  fixed-width 4-byte little-endian vout.
- `bitcoin-core/src/txdb.cpp:100-164` — `CCoinsViewDB::BatchWrite`:
  three-phase pattern (`Erase(DB_BEST_BLOCK)` → `Write(DB_HEAD_BLOCKS,
  Vector(new_hash, old_hash))` → per-coin Write/Erase → final
  `Erase(DB_HEAD_BLOCKS)` + `Write(DB_BEST_BLOCK, hashBlock)`). The
  `HEAD_BLOCKS` payload is **a vector of two `uint256`** (= 64 bytes
  CompactSize-prefixed serialized), **NOT a single (hash,height,
  hash,height) tuple**.
- `bitcoin-core/src/dbwrapper.h:192` — `OBFUSCATION_KEY =
  "\000obfuscate_key"` (14-byte explicit-length string with leading
  NUL, stored under that key in the DB; **value is the 8-byte XOR
  obfuscation key that masks every other value on read/write**).
- `bitcoin-core/src/compressor.cpp:149-191` — `CompressAmount` /
  `DecompressAmount` mantissa+exponent packing (sat-values become
  ~3-byte VARINTs on average).
- `bitcoin-core/src/compressor.cpp:55-138` — `CompressScript` /
  `DecompressScript`: 6 special tags (P2PKH/P2SH/2× P2PK
  compressed/2× P2PK uncompressed) → 21 / 21 / 33 / 33 bytes on disk
  vs 25 / 23 / 35 / 67 in the script body. Saves ~50% of script bytes
  for the standard set.
- `bitcoin-core/src/compressor.h:97-110` —
  `TxOutCompression`: stored value =
  `VARINT(CompressAmount(val)) + script_with_compression`.
- `bitcoin-core/src/coins.h:50-72` — `Coin::Serialize`:
  `VARINT((height << 1) | fCoinBase)` then `TxOutCompression(out)`.
- `bitcoin-core/src/kernel/cs_main.h` / `bitcoin-core/src/validation.h`
  — `FlushStateToDisk` modes: `FLUSH_STATE_IF_NEEDED`,
  `FLUSH_STATE_PERIODIC`, `FLUSH_STATE_ALWAYS`. Triggers documented in
  `validation.cpp::FlushStateToDisk` (cache size > dbcache, shutdown,
  reorg threshold, snapshot load).

Status: **26 BUGS** (3 P0-CDIV / 2 P0-CONSENSUS-class /
        7 P1 / 9 P2 / 5 P3). 8 of 8 behaviors audited.

  - Behavior 1 (CCoinsView interface contract): **DIVERGENT** — no
    abstract base; the live path is hardcoded to `BlockchainDB` (a
    RocksDB wrapper). `Cursor()` exists in two unrelated flavours,
    neither cached. No `PeekCoin` (non-caching).
  - Behavior 2 (CCoinsViewCache + DIRTY/FRESH): **DEAD CODE** —
    `CoinsCache` exists with full flag semantics but has zero
    production callers; the live IBD pipeline writes per-block via
    WriteBatch directly and skips the cache entirely.
  - Behavior 3 (CCoinsViewDB leveldb key encoding): **DIVERGENT** —
    key = `txid(32) + vout(u32 LE)(4)` = 36 bytes flat with no 'C'
    prefix and no VARINT(vout). Core's key = `'C' + txid +
    VARINT(vout)` (33+ bytes, average 34).
  - Behavior 4 (Coin compression): **PARTIAL** — undo & snapshot use
    CompressAmount + VARINT; chainstate uses raw `value: u64` LE +
    raw script_pubkey. No CompressScript anywhere on the live
    chainstate write path.
  - Behavior 5 (obfuscate_key XOR): **MISSING ENTIRELY** — no
    OBFUSCATION_KEY storage, no XOR on reads/writes, no
    \\x0eobfuscate_key meta entry.
  - Behavior 6 (FlushStateToDisk triggers): **MISSING** — every block
    is an atomic WriteBatch (so the disk state is always tip-consistent),
    but there is no dbcache, no shutdown flush, no reorg threshold,
    no `flushchainstate` RPC. `coins.rs` has `needs_flush`/`flush`/
    `dbcache_bytes` plumbed through — but it's the dead module.
  - Behavior 7 (Coin height|coinbase packed VARINT): **PARTIAL** —
    undo data uses `VARINT((height<<1)|fCoinBase)` (correct); live
    chainstate uses `Option<u32>` height + separate `bool is_coinbase`
    + redundant outpoint inside the value.
  - Behavior 8 (AccessCoin/SpendCoin DIRTY plumbing): **DEAD** —
    `CoinsCache::spend_coin` does the FRESH/DIRTY dance correctly,
    but it is not wired; the production path queues batch.delete_cf
    directly and never tracks DIRTY/FRESH.

BUGS
----

### BUG-1 — CCoinsViewCache (`coins.rs`, 894 LOC) is dead code: zero production callers [P1]

- **File**: `ferrous-utils/sync/src/storage/coins.rs:175-651`
  (`CoinsCache` struct + impl); `mod.rs:35` re-exports.
- **Core ref**: `bitcoin-core/src/coins.h:367-509` (`CCoinsViewCache`
  is the *only* path coins enter the leveldb chainstate). Live IBD
  path: `validation.cpp::ConnectBlock` → `UpdateCoins` → `CoinsTip()`
  (which is a `CCoinsViewCache`).
- **Description**: `CoinsCache` exposes `add_coin`, `spend_coin`,
  `get_coin`, `have_coin`, `uncache`, `flush(clear_after)`, `sync()`,
  `connect_block_utxos`, `disconnect_block_utxos`, `stats()`,
  `needs_flush()`, `set_dbcache_bytes`, `best_block_hash`, DIRTY/FRESH
  flag tracking, FRESH+spent drop-without-DB-touch optimization, and
  20+ unit tests — **and is never instantiated outside its own
  `mod tests`**. The IBD pipeline
  (`PyBlockchainDB::connect_block_from_bytes`) writes directly via
  `WriteBatch::put_cf`/`delete_cf` against `CHAINSTATE_CF` + `SPENT_CF`
  with NO cache layer.
- **Excerpt** (`coins.rs:194-212`):
  ```rust
  impl CoinsCache {
      pub fn new() -> Self {
          Self::with_dbcache(DEFAULT_DBCACHE_BYTES)
      }
      pub fn with_dbcache(dbcache_bytes: usize) -> Self { ... }
  }
  ```
  And the only callers (`grep -rn CoinsCache /home/work/hashhog/ouroboros/`):
  every hit is inside `coins.rs` itself or `mod.rs`'s re-export — no
  production crate constructs a `CoinsCache`.
- **Impact**: Two effects. (a) Misleading architecture — readers
  assume DIRTY/FRESH bookkeeping protects against UTXO resurrection;
  in reality the live path has no such bookkeeping and depends
  entirely on per-block WriteBatch atomicity. (b) Maintenance debt —
  894 LOC of cache code that drifts from the live path (different
  serialization, different ordering semantics, different
  unspendable-script handling). **This is the classic
  fleet "dead module" / "subsystem rewrite candidate" pattern**.

### BUG-2 — Chainstate DB key has no 'C' prefix and uses fixed-width vout [P0-CDIV]

- **File**: `ferrous-utils/sync/src/storage/schema.rs:299-304`
  (`encode_outpoint`), used by `db.rs:511, 612, 623, 641, 1781, 1820,
  3732, 3850, 4384`.
- **Core ref**: `bitcoin-core/src/txdb.cpp:43-49` — `CoinEntry`
  serializer reads/writes `key (1 byte = 'C') + outpoint.hash (32
  bytes) + VARINT(outpoint.n)`. Stored key length = 1 + 32 + VARINT(n)
  bytes; the VARINT is **Bitcoin's MSB-base-128 varint, not
  CompactSize**. For typical `n ∈ [0, 127]` that's 34 bytes.
- **Description**: ouroboros stores chainstate under a 36-byte key
  `txid(32) || vout.to_le_bytes()(4)`. Compared to Core: (1) no `'C'`
  prefix, (2) wrong vout encoding (fixed 4-byte LE vs Core's MSB
  VARINT), (3) wrong byte order (LE vs Core's big-endian VARINT byte
  layout). Two consequences: a Core leveldb chainstate cannot be
  mounted by ouroboros, and vice versa; iterator-prefix scans built
  against Core's `'C'` prefix won't bound the key range (would have
  to scan the entire RocksDB to find chainstate keys if multiplexed
  in a single CF — ouroboros currently uses a dedicated
  `CHAINSTATE_CF` so this is masked, but the key-shape divergence
  remains for any future single-CF migration / cross-impl tooling).
- **Excerpt** (`schema.rs:299-304`):
  ```rust
  pub fn encode_outpoint(txid: &[u8; 32], vout: u32) -> [u8; 36] {
      let mut key = [0u8; 36];
      key[0..32].copy_from_slice(txid);
      key[32..36].copy_from_slice(&vout.to_le_bytes());
      key
  }
  ```
- **Impact**: Wire-incompatible chainstate on disk. `bitcoin-cli` /
  `coinstats` / external indexers built against Core's leveldb layout
  see opaque garbage. Cross-impl chainstate compat
  (`gettxoutsetinfo hash_serialized_3`) only happens because we
  compute the digest from already-decoded coins — the *bytes* on disk
  differ. Also breaks the future "drop CHAINSTATE_CF and use a single
  CF with prefix dispatch" optimization that Core uses.

### BUG-3 — No obfuscate_key XOR layer (anti-virus false-positive risk) [P1]

- **File**: searched all of `ferrous-utils/sync/src/storage/`,
  `ferrous-utils/common/src/`, `src/ouroboros/database.py` — no
  `obfuscate_key`, no `OBFUSCATION_KEY`, no XOR-on-read/write helper,
  no `dbwrapper.h`-style obfuscation namespace.
- **Core ref**: `bitcoin-core/src/dbwrapper.h:188-192`:
  ```cpp
  Obfuscation m_obfuscation;
  inline static const std::string OBFUSCATION_KEY{"\000obfuscate_key", 14};
  ```
  Plus `dbwrapper.cpp` constructor reads/initializes the key and
  every `Read`/`Write` XORs the value bytes through `m_obfuscation`.
- **Description**: Core obfuscates the leveldb chainstate values with
  an 8-byte XOR key (per-database, randomly generated on first open,
  stored under the leading-NUL `\\x00obfuscate_key`) so that
  bitscript byte patterns (especially OP_RETURN, P2PKH templates)
  don't trigger anti-virus / IDS pattern matches on the leveldb SST
  files. Ouroboros stores every Coin value in plaintext.
- **Excerpt**: full-text grep:
  ```
  $ grep -rn "obfuscate" /home/work/hashhog/ouroboros/src/ \
      /home/work/hashhog/ouroboros/ferrous-utils/
  (no hits)
  ```
- **Impact**: (a) Real-world: anti-virus false positives on the
  chainstate SSTs flag known-bad script patterns; users have lost
  datadirs to Symantec/Defender quarantine. (b) Strict-parity gap —
  `dumptxoutset` output is unaffected (snapshot format uses its own
  encoding) but on-disk SST round-tripping with Core is impossible.

### BUG-4 — Live chainstate UTXO encoding redundantly stores outpoint inside the value [P1]

- **File**: `ferrous-utils/common/src/types.rs:414-434` (`UTXO::to_bytes`),
  used as the chainstate value via `UTXO::bitcoin_serialize`
  (`serialize.rs:367-371`).
- **Core ref**: `bitcoin-core/src/coins.h:42-77` (`Coin`) — the leveldb
  value is **just** `VARINT(height<<1 | fCoinBase) + TxOutCompression`.
  The outpoint lives in the *key*; storing it in the value is pure
  waste.
- **Description**: ouroboros writes the **outpoint a second time inside
  the value**. `OutPoint::consensus_encode` is 36 bytes
  (txid + vout u32 LE). Plus the value carries amount (raw u64 LE = 8
  bytes), full script_pubkey (length CompactSize + raw bytes),
  Option<u32> height (1 + 0/4 bytes), and is_coinbase (1 byte). Total
  on-disk overhead per coin vs Core's compressed-encoding is roughly
  **36 + ~5 (uncompressed value vs ~3-byte VARINT(CompressAmount)) +
  ~5 (uncompressed script) + 1 (Option flag) + 1 (bool) ≈ 48 bytes
  per coin** of avoidable storage.
- **Excerpt** (`types.rs:415-433`):
  ```rust
  pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
      let mut encoder = Vec::new();
      // Custom serialization: outpoint + amount + script_pubkey + height + is_coinbase
      // Encode outpoint directly, not its bytes
      self.outpoint.inner().consensus_encode(&mut encoder)?;
      self.amount.consensus_encode(&mut encoder)?;
      self.script_pubkey.consensus_encode(&mut encoder)?;
      // Encode Option<u32> as: 1 byte flag (0 = None, 1 = Some) + optional u32
      match self.height {
          None => { 0u8.consensus_encode(&mut encoder)?; }
          Some(h) => { 1u8.consensus_encode(&mut encoder)?; h.consensus_encode(&mut encoder)?; }
      }
      self.is_coinbase.consensus_encode(&mut encoder)?;
      Ok(encoder)
  }
  ```
- **Impact**: Mainnet UTXO set ≈ 190 M coins × ~48 extra bytes ≈
  **~9 GiB** of avoidable chainstate disk usage. Slower bloom-filter
  lookups (larger value pages → more SST blocks per coin). Compaction
  pressure scales linearly with the bloat.

### BUG-5 — No CompressAmount/CompressScript on the live chainstate write path [P2]

- **File**: `ferrous-utils/common/src/types.rs:418` writes
  `self.amount.consensus_encode(...)` (raw `u64` LE, 8 bytes); script
  is `self.script_pubkey.consensus_encode(...)` (CompactSize length +
  raw bytes — NOT `TxOutCompression`).
- **Core ref**: `bitcoin-core/src/compressor.cpp:149-191`
  (CompressAmount averages 3 bytes for typical sat-values like
  100_000_000 → packed via mantissa/exponent); `compressor.cpp:55-138`
  (CompressScript matches 6 standard templates and stores 21–33 bytes
  in place of 23–67-byte serialized scripts).
- **Description**: `common::compress_amount` and
  `decompress_amount` exist (`ferrous-utils/common/src/serialize.rs:188`)
  and are correctly Core-byte-compatible, but they are ONLY called by
  the undo path (`storage::undo::Coin::serialize`,
  `storage::snapshot.rs:408`) and the snapshot import path
  (`lib.rs:2720`). The live chainstate writer
  (`UTXO::bitcoin_serialize`) calls neither. Similarly `read_compressed_script`
  and the matching DecompressScript exist for snapshot import
  (`lib.rs:2743-2820`), but no CompressScript helper exists on the
  write side at all — the chainstate stores raw scripts.
- **Impact**: (a) Bloated chainstate (compounds BUG-4). (b)
  Compression mismatch with Core's on-disk format — even if BUG-2/3/4
  were closed, the value bytes would still differ.

### BUG-6 — Coin height/is_coinbase split into two fields, not packed into VARINT [P2]

- **File**: `ferrous-utils/common/src/types.rs:417-433`,
  `serialize.rs:374-411` (deserialize); same path as BUG-4.
- **Core ref**: `bitcoin-core/src/coins.h:73-79`:
  ```cpp
  template<typename Stream>
  void Serialize(Stream &s) const {
      assert(!IsSpent());
      uint32_t code = nHeight * uint32_t{2} + fCoinBase;
      ::Serialize(s, VARINT(code));
      ::Serialize(s, Using<TxOutCompression>(out));
  }
  ```
- **Description**: ouroboros stores `Option<u32>` height + 1-byte
  `Some/None` flag + 1-byte `bool is_coinbase`. Core packs both into
  a single `VARINT(height<<1 | fCoinBase)` which is 1–5 bytes total.
  For typical mid-chain heights (24-bit) Core uses **3 bytes** of
  VARINT vs ouroboros's **6 bytes (1 flag + 4 LE u32 + 1 bool)**.
- **Impact**: 3 bytes × 190 M coins ≈ 570 MB of avoidable storage;
  plus parity-break with Core's on-disk format (compounds BUG-5).
  Also: the `Option<u32>` representation allows storing a coin with
  `height=None` (1-byte flag = 0), which has no Core equivalent — a
  corrupted SST or buggy import path can produce `height=None` UTXOs
  that pass deserialization and then crash downstream consumers that
  assume `height` is always present (e.g. `gettxoutsetinfo` computes
  `(height<<1)|coinbase` as `int(utxo.height) if utxo.height is not
  None else 0`, silently treating missing-height coins as genesis
  — see `database.py:486-487`).

### BUG-7 — HEAD_BLOCKS marker is single-tuple, not Core's vector-of-uint256 [P2]

- **File**: `ferrous-utils/sync/src/storage/db.rs:1044-1101`
  (`write_head_blocks`, `get_head_blocks`).
- **Core ref**: `bitcoin-core/src/txdb.cpp:128-130`:
  ```cpp
  batch.Erase(DB_BEST_BLOCK);
  batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));
  ```
  The value is `std::vector<uint256>` — CompactSize prefix `0x02` +
  64 bytes of hash data = 65 bytes total. Reader is
  `txdb.cpp:92-98` (`GetHeadBlocks`). The vector form is explicit
  future-extensibility: "as we may want to support interrupting
  after partial writes from multiple independent reorgs"
  (`txdb.cpp:126-127`).
- **Description**: ouroboros stores a fixed 72-byte tuple
  `[old_tip_hash(32) || old_tip_height(4) || new_block_hash(32) ||
  new_height(4)]`. Different shape, different size, different
  semantics:
  - Cannot represent multi-block partial-reorg state.
  - Stores `*_height` redundantly with block-index lookups (Core
    derives height from `m_block_index[hash]->nHeight`).
  - Stores `(old_tip, new_tip)` ordering reversed from Core's
    `Vector(new_tip, old_tip)`.
  - Wire-incompatible — a Core node mounting an ouroboros chainstate
    that crashed mid-apply will fail to deserialize HEAD_BLOCKS (it
    expects a CompactSize length prefix on a `std::vector<uint256>`).
- **Excerpt** (`db.rs:1054-1061`):
  ```rust
  let mut value = Vec::with_capacity(72);
  value.extend_from_slice(old_tip_hash);
  value.extend_from_slice(&old_tip_height.to_le_bytes());
  value.extend_from_slice(new_block_hash);
  value.extend_from_slice(&new_height.to_le_bytes());
  self.db.put_cf(cf, meta_keys::HEAD_BLOCKS, &value)?;
  ```
- **Impact**: Marker is non-interoperable with Core, AND the
  single-tuple shape forecloses Core's planned multi-reorg-resume
  feature.

### BUG-8 — connect_block_at_height misses intra-block undo records (same class as W93 BUG-C — second pipeline) [P0-CDIV]

- **File**: `ferrous-utils/sync/src/storage/db.rs:2604-2638`
  (`connect_block_at_height`, the reactivation / reorg-reconnect
  pipeline).
- **Core ref**: `bitcoin-core/src/validation.cpp::Chainstate::ConnectBlock`
  per-tx loop (lines 2524-2601). UpdateCoins is applied
  tx-by-tx so that a later tx in the same block can spend an earlier
  tx's output via the cache overlay, and the SPENT_CF undo record
  is recorded against the pre-block coin state.
- **Description**: This is the same class of bug as W93 BUG-C in
  pipeline A — but in pipeline B. `connect_block_at_height` walks
  txs in order, but for each non-coinbase input it does
  `self.db.get_cf(chainstate_cf, &key)?` directly. **The
  WriteBatch is not yet committed**, so a tx that spends the output
  of an earlier tx in the same reconnected block sees `None` (the
  earlier tx's `add_utxo_batch` put_cf is queued but not visible to
  `get_cf`). The code then logs `"missing UTXO"` and continues —
  no SPENT_CF undo record is written for that intra-block spend. If
  the reconnected block is later disconnected again (chain whips
  back), the missing undo record means we cannot restore the
  intra-block-spent coin; the chainstate silently desyncs from
  Core.
- **Excerpt** (`db.rs:2610-2637`):
  ```rust
  if !tx.is_coinbase() {
      for input in &tx.input {
          let outpoint = input.previous_output;
          let prev_txid = *outpoint.txid.as_byte_array();
          let key = encode_outpoint(&prev_txid, outpoint.vout);

          // Read UTXO from CHAINSTATE_CF — these were restored
          // during disconnect_block, so they should be present.
          if let Some(utxo_bytes) = self.db.get_cf(chainstate_cf, &key)? {
              ...
              batch.put_cf(&spent_cf, &key, &undo_value);
              batch.delete_cf(&chainstate_cf, &key);
          } else {
              log::warn!(
                  "connect_block_at_height: missing UTXO {:?}:{} at height {}",
                  outpoint.txid, outpoint.vout, height
              );
          }
      }
  }
  ```
  Notice no `in_block_added` overlay HashMap (pipeline A has one at
  `lib.rs:3770-3771`). The reactivation path also doesn't MultiGet
  prefetch — it does per-input synchronous `get_cf` calls inside the
  batch construction loop, which is also a perf bug.
- **Impact**: Reactivation of a previously-disconnected block that
  contains intra-block dependencies (one tx spending an earlier tx
  from the same block) **silently loses the undo record for the
  intra-block input**. If chain whips back across that block again,
  the disconnect cannot fully reverse the apply. The chainstate then
  no longer matches Core. **Same severity class as the original W93
  fix — but the fix only landed in pipeline A**. Fleet pattern:
  **two-pipeline guard 5th distinct extension in ouroboros, this
  time on the connect-side**.

### BUG-9 — No BIP-30 duplicate-coinbase enforcement on connect (chainstate silently overwrites) [P0-CONSENSUS]

- **File**: `ferrous-utils/sync/src/lib.rs:3402-3858`
  (`connect_block_from_bytes`); also `db.rs:2540-2678`
  (`connect_block_at_height`). Neither path enforces fEnforceBIP30
  on the *connect* side.
- **Core ref**: `bitcoin-core/src/validation.cpp:2235-2298` — Core
  rejects a block whose coinbase txid duplicates an existing unspent
  txid in the UTXO set, unless the duplicate-coinbase block is one of
  the two grandfathered heights (91842, 91880). The check is
  performed against `CoinsTip()` *before* writing the new coinbase
  outputs.
- **Description**: ouroboros's `connect_block_from_bytes` happily
  writes new coinbase outputs at the same `encode_outpoint(txid, n)`
  key as an existing UTXO — RocksDB silently overwrites, and the
  spent UTXO is lost without any SPENT_CF undo record (only spends
  produce SPENT_CF entries; the coinbase isn't a spend). The disconnect
  side handles the BIP-30 exception heights correctly
  (`DISCONNECT_BIP30_EXCEPTION_HEIGHTS` constant), but the connect
  side has no symmetric check.
- **Excerpt** (`lib.rs:3823-3852`):
  ```rust
  // (c) — add this tx's outputs (when not genesis) and tx index.
  if store_utxos {
      for (vout, output) in tx.output.iter().enumerate() {
          // No HaveCoin / HaveCoinInCache check against the existing
          // chainstate — just put_cf and overwrite whatever was there.
          ...
          batch.put_cf(&chainstate_cf, &key, &utxo_serialized);
          in_block_added.insert(key, utxo_serialized);
      }
  }
  ```
- **Impact**: On mainnet, every block at heights 91842 and 91880
  would silently overwrite the prior coinbase's UTXOs. Currently
  irrelevant for sync past those heights (UTXOs are spent or expired),
  but a forked / hostile test scenario at any height can exploit
  this: an attacker who controls coinbase txid space (BIP-34
  height-prefix predates many of these tests; pre-BIP-34 anything
  goes) can replace an existing UTXO via a duplicate coinbase. The
  **only reason this isn't a live mainnet bug today** is BIP-34
  height-uniqueness on coinbase txids post-227835 — but consensus
  parity requires the explicit check.

### BUG-10 — No CCoinsView::Cursor() — gettxoutsetinfo materializes entire UTXO set into Python memory [P0-CDIV]

- **File**: `src/ouroboros/rpc.py:7101-7146` (`rpc_gettxoutsetinfo`
  `_walk_utxos` thread); `database.py:461-489` (`iter_utxos`);
  `lib.rs:5295` (`PyBlockchainDB::iter_utxos`).
- **Core ref**: `bitcoin-core/src/coins.h:229-246` (`CCoinsViewCursor`
  abstract interface); `bitcoin-core/src/txdb.cpp:171-247`
  (`CCoinsViewDBCursor` — wraps a leveldb iterator with bounded
  buffer, walks key range `'C'..='C'+1` lazily).
- **Description**: `gettxoutsetinfo` is supposed to be a streaming
  cursor walk with bounded memory (Core uses a leveldb iterator that
  reads ~64 KB at a time). Ouroboros's implementation:
  ```python
  utxos = list(self.node.db.iter_utxos())
  utxos.sort(key=lambda u: (u.txid, u.vout))
  ```
  `iter_utxos` on the Rust side returns a `Vec<(OutPoint, UTXO)>`
  built by walking the entire chainstate eagerly
  (`db.rs:657-681`). Mainnet UTXO set ≈ 190 M entries × roughly 200
  bytes per `_SnapshotUTXOView` (txid + script_pubkey + dict
  overhead) ≈ **38 GB of resident Python memory** to compute one
  `gettxoutsetinfo` call.
- **Excerpt** (`rpc.py:7119-7120`):
  ```python
  # Sort by (txid, vout) so the digest is deterministic and
  # matches Core's CCoinsViewCursor leveldb-key ordering.
  utxos = list(self.node.db.iter_utxos())
  utxos.sort(key=lambda u: (u.txid, u.vout))
  ```
  Cross-reference `lib.rs:5295` — `iter_utxos` returns
  `Vec<PyUTXO>` (not a generator) so there is no way to avoid the
  materialization on the Python side.
- **Impact**: `gettxoutsetinfo` on mainnet either OOMs the daemon
  outright (32 GB box) or stalls the asyncio loop and starves all
  other RPCs for tens of minutes. Core handles 190 M entries in ~3
  GiB of cache + bounded iterator scratch and ~3 minutes wall-clock.
  **In addition**, the RocksDB iterator path doesn't honour Core's
  leveldb prefix-key ordering — ouroboros's key has no `'C'` prefix
  (BUG-2), so the natural iteration order is the same as Core's, but
  a future BUG-2 fix that adds the prefix would shift the iteration
  range and require updating the cursor seek logic that doesn't yet
  exist.

### BUG-11 — add_utxo_raw (loadtxoutset bulk import) does per-call put_cf instead of WriteBatch [P1]

- **File**: `ferrous-utils/sync/src/lib.rs:5332-5365` (`add_utxo_raw`);
  caller: `database.py:491-524` (`add_utxo_raw`), invoked from
  `loadtxoutset` snapshot loader.
- **Core ref**: `bitcoin-core/src/coins.h:441-448`
  (`EmplaceCoinInternalDANGER` — bypass-validation bulk-add into
  CCoinsViewCache); `validation.cpp::PopulateAndValidateSnapshot`
  batches into the cache, then flushes to leveldb.
- **Description**: For each coin in a snapshot, ouroboros's
  `add_utxo_raw` calls `self.db.add_utxo(&outpoint, &utxo)` —
  which itself calls `self.db.put_cf(cf, key, value)?` for that
  single coin. Snapshot loaders walk ~190 M coins. Each put_cf is
  a (likely cached) individual RocksDB write with WAL append and
  internal counter bumps. Compared to a batched
  `WriteBatch::put_cf` per ~10 k coins followed by `apply_batch`,
  this is ~10–100× slower and ~10× more WAL bytes written.
- **Excerpt** (`lib.rs:5340-5364`):
  ```rust
  fn add_utxo_raw(
      &self,
      txid: &[u8], vout: u32, amount: u64,
      script_pubkey: Vec<u8>, height: u32, is_coinbase: bool,
  ) -> PyResult<()> {
      ...
      self.db.add_utxo(&outpoint, &utxo).map_err(|e| { ... })
  }
  ```
- **Impact**: Snapshot import on mainnet takes hours instead of
  minutes; WAL grows to multi-GB and stalls the daemon. Operator
  bypasses `loadtxoutset` for fast-sync entirely because it's
  unusable.

### BUG-12 — Chainstate has no flush mode (FLUSH_STATE_ALWAYS / IF_NEEDED / PERIODIC) — `flushchainstate` RPC absent [P1]

- **File**: searched all of `src/ouroboros/rpc.py`,
  `ferrous-utils/sync/src/lib.rs`,
  `ferrous-utils/sync/src/storage/db.rs` — no `rpc_flushchainstate`
  handler, no `FlushStateToDisk`/`flush_state`/`flush_chainstate`
  function. `CoinsCache::flush` exists in dead code.
- **Core ref**: `bitcoin-core/src/validation.cpp::FlushStateToDisk`
  triggers: cache size > `m_coinstip_cache_size_bytes` ⇒
  `FLUSH_STATE_IF_NEEDED`; on shutdown ⇒ `FLUSH_STATE_ALWAYS`; on
  reorg with cache > 200 MB ⇒ `FLUSH_STATE_PERIODIC`; on snapshot
  load ⇒ forced via `FlushStateToDisk(state, FLUSH_STATE_ALWAYS)`.
  RPC: `rpc/blockchain.cpp::flushchainstate`.
- **Description**: Without an in-memory cache, "flush" is a no-op
  for ouroboros's chainstate (every block is already a WriteBatch
  to disk). But: (a) operators cannot manually trigger a flush via
  `bitcoin-cli flushchainstate` — every other fleet impl ships this
  RPC, and consensus-diff harnesses pre-W110 expected it. (b) The
  test `test_w124_g10_flushchainstate_rpc_present` claims
  `"rpc_flushchainstate" in src` — this assertion is currently
  failing or the test is stale (`grep rpc_flushchainstate
  src/ouroboros/rpc.py` returns empty). Stale test.
- **Excerpt** (`tests/test_w124_operator.py:235-238`):
  ```python
  def test_w124_g10_flushchainstate_rpc_present() -> None:
      """G10: Core's `flushchainstate` RPC has a parity stub."""
      ...
      assert "rpc_flushchainstate" in src, "G10: no rpc_flushchainstate handler"
  ```
  `grep -n rpc_flushchainstate src/ouroboros/rpc.py` → no output.
- **Impact**: (a) Parity gap with Core RPC surface. (b) Operator
  cannot force a disk sync before snapshot / backup — must SIGTERM
  the daemon (which the launcher does, but is heavier). (c) Stale
  test assertion will eventually fail under CI when it's actually
  exercised.

### BUG-13 — No `dbcache` CLI/config option — chainstate memory unconfigurable [P2]

- **File**: searched `src/ouroboros/config.py`,
  `src/ouroboros/cli.py`, `src/ouroboros/daemon.py`,
  `config.example.toml` — no `dbcache`/`db_cache`/`-dbcache` knob.
  `coins.rs:181 dbcache_bytes` field exists but only on the dead
  `CoinsCache` struct.
- **Core ref**: Core's `-dbcache` CLI defaults to 450 MiB; documented
  in `bitcoin-core/src/init.cpp::SetupServerArgs`
  (`DEFAULT_DB_CACHE = 450 << 20`).
- **Description**: Operator has no way to size the chainstate
  memory. RocksDB has `optimize_for_point_lookup(1024)` and
  `set_write_buffer_size(128 MB)` hardcoded
  (`db.rs:144-156`), making the daemon use roughly 1 GiB of
  chainstate block cache regardless of workload. On a 4 GiB cloud
  VPS this is too much; on a 128 GiB maxbox this is too little for
  fast IBD.
- **Impact**: Cannot tune for low-memory VPS deployments; cannot
  exploit high-memory hardware for IBD acceleration. Compounded by
  BUG-1 — the only place a `dbcache_bytes` value would matter is in
  the dead `CoinsCache`.

### BUG-14 — Chainstate disk_size always 0 in gettxoutsetinfo — operators can't see UTXO bytes on disk [P3]

- **File**: `src/ouroboros/rpc.py:7184-7186`:
  ```python
  # disk_size: ouroboros stores the chainstate in RocksDB and
  # does not expose a per-CF size estimate here; emit 0 so the
  # field is present (Core also emits 0 when no view is open).
  "disk_size": 0,
  ```
- **Core ref**: `bitcoin-core/src/kernel/coinstats.cpp` →
  `CCoinsViewDB::EstimateSize` (`txdb.cpp:166-169`): returns
  `m_db->EstimateSize(DB_COIN, DB_COIN+1)` — leveldb's
  `GetApproximateSize` over the `'C'` key range.
- **Description**: RocksDB exposes
  `db.GetApproximateSize(ranges)` / `live_files_metadata()` for
  per-CF size estimates. Ouroboros has them available but doesn't
  call them. The hardcoded 0 silently lies to operators. Note the
  comment is **wrong** about Core — Core does not "emit 0 when no
  view is open"; Core always emits the EstimateSize result. This is
  a comment-as-confession case.
- **Excerpt**: see file: line.
- **Impact**: Operators cannot monitor chainstate growth. `du -sh`
  on the RocksDB datadir is the only signal — but that includes
  block bodies / undo / tx-index. **Comment-as-confession pattern
  4th distinct extension this campaign**.

### BUG-15 — UTXO::bitcoin_serialize/deserialize Option<u32> height accepts `height=None` from disk [P2]

- **File**: `ferrous-utils/common/src/serialize.rs:390-400`:
  ```rust
  let height = match u8::consensus_decode(&mut decoder)... {
      0 => None,
      1 => Some(u32::consensus_decode(&mut decoder)?),
      _ => return Err(SerializeError::InvalidVarInt),
  };
  ```
- **Core ref**: `bitcoin-core/src/coins.h:50-79` — no Option type;
  `nHeight` is always a `uint32_t` (max value 4294967295). If a
  coin is in the UTXO set it has a definite height; "no height"
  is meaningless.
- **Description**: Accepting `height=None` from the on-disk
  chainstate creates downstream invariants violations:
  - `gettxoutsetinfo` coerces `None → 0` (rpc.py:7137,
    `int(utxo.height) if utxo.height is not None else 0`), so a
    no-height coin gets digest-included as if it were a genesis
    coin. **A buggy import or pre-fix legacy SST could poison the
    `hash_serialized_3` digest silently.**
  - `coinbase_maturity` checks (`tx_verify.cpp` equivalent) that
    use `height` against `current_height - 100` will treat
    `height=None` as zero — making mature any "no-height" coin
    even at height 5.
  - `loadtxoutset` `add_utxo_raw` defaults to `Some(height)` so
    new snapshots don't produce this, but legacy SST scans (or
    schema-version migrations from earlier ouroboros builds) can
    leave `height=None` rows.
- **Impact**: Latent UTXO poisoning + maturity-bypass class bug
  if a `None`-height coin lands in the chainstate.

### BUG-16 — Genesis coinbase outputs are written into chainstate by `connect_block_at_height` [P2]

- **File**: `db.rs:2559-2563`:
  ```rust
  pub fn connect_block_at_height(&self, height: u32) -> Result<()> {
      if height == 0 {
          return Err(DbError::InvalidData(
              "Cannot reconnect genesis block via connect_block_at_height".to_string()
          ));
      }
      ...
  }
  ```
  contrast with `lib.rs:3769` (`connect_block_from_bytes`):
  ```rust
  let store_utxos = height > 0;
  ```
- **Core ref**: `bitcoin-core/src/validation.cpp:2337-2343` —
  genesis coinbase outputs are unspendable; the genesis coinbase is
  excluded from chainstate.
- **Description**: Pipeline A correctly skips outputs at height
  0; pipeline B refuses to reconnect genesis at all. The semantics
  differ: pipeline A handles the case `connect_block_from_bytes(genesis_bytes, 0)`
  but pipeline B doesn't even try. **The asymmetry is benign today
  (genesis is always written via path A), but a future code path
  that uses path B for chain rebuild would silently skip the
  genesis step.**
- **Impact**: Two-pipeline divergence; potential
  rebuild/reactivation hazard if path B is wired into a chain-restore
  workflow.

### BUG-17 — recover_from_crash always calls disconnect_block_at_height — falls back to "reset tip directly" without disconnect on missing block body [P1]

- **File**: `db.rs:1111-1150` (`recover_from_crash`).
- **Core ref**: `bitcoin-core/src/init.cpp::AppInitMain` →
  `ReplayBlocks` (validation.cpp:5650-5717): replays the
  HEAD_BLOCKS vector forward from `old_tip` to `new_tip` using
  the on-disk undo data. Crash recovery does NOT
  unconditionally disconnect — it replays.
- **Description**: ouroboros's recovery: if the HEAD_BLOCKS
  marker is present, blindly call
  `disconnect_block_at_height(new_height)`; on failure, call
  `update_best_block(&old_tip_hash, old_tip_height)` directly
  WITHOUT touching the chainstate. The "reset tip directly"
  fallback can produce a chainstate that contains coins from a
  partially-applied block while the BEST_BLOCK_HASH points to
  the old tip → **chainstate is now inconsistent with the
  declared tip**, and subsequent reads will see "ghost" UTXOs
  that don't exist on the active chain.
- **Excerpt** (`db.rs:1134-1142`):
  ```rust
  Err(e) => {
      // If the block wasn't even stored (crash very early), just
      // reset the tip directly.
      log::warn!(
          "Could not disconnect block at height {} ({}) — resetting tip directly",
          new_height, e,
      );
      self.update_best_block(&old_tip_hash, old_tip_height)?;
  }
  ```
- **Impact**: Crash mid-apply where the block body is missing
  (e.g. WriteBatch wrote chainstate mutations but block-store
  flush failed) → tip rolls back but chainstate retains
  half-applied UTXOs. On subsequent block validation, those
  ghost UTXOs become "spendable" by an attacker who can predict
  them. **Note**: ouroboros's apply_batch is a single
  `self.db.write(batch)?` which is atomic in RocksDB, so this
  is hard to trigger today — but the recovery path has no
  defence against the case where the block body and chainstate
  state diverged via a different mechanism (e.g. snapshot import
  partial failure).

### BUG-18 — No HaveCoin / HaveCoinInCache distinction — every existence check round-trips RocksDB [P2]

- **File**: `db.rs:641-651` (`utxo_exists`):
  ```rust
  pub fn utxo_exists(&self, outpoint: &OutPoint) -> bool {
      let txid_bytes = *outpoint.txid.as_byte_array();
      let key = encode_outpoint(&txid_bytes, outpoint.vout);
      let cf = match self.db.cf_handle(CHAINSTATE_CF) { ... };
      self.db.get_cf(cf, &key).map(|opt| opt.is_some()).unwrap_or(false)
  }
  ```
- **Core ref**: `bitcoin-core/src/coins.h:419-421` —
  `HaveCoinInCache` checks only the in-memory cache; `HaveCoin`
  walks the cache, falling back to the parent view only on miss.
- **Description**: `utxo_exists` does a full `get_cf` (which
  fetches the value) rather than `db.key_may_exist_cf` (RocksDB's
  bloom-filtered key existence check). Plus there's no
  in-memory layer to short-circuit hot lookups. During mempool
  validation, the same prevouts may be queried thousands of
  times.
- **Impact**: Hot-path performance loss. Mempool validation
  of a 250-input tx fetches each coin from RocksDB (and
  deserializes the full UTXO value, which includes redundant
  outpoint bytes — see BUG-4) instead of doing a bloom-filtered
  key-existence check.

### BUG-19 — UTXO deserialization tolerates trailing bytes (no bytes_consumed == len check) [P2]

- **File**: `serialize.rs:374-410` — returns
  `(UTXO::new(...), bytes_consumed)` and lets the caller decide
  what to do with leftover bytes.
- **Core ref**: `bitcoin-core/src/coins.h::Unserialize` — Core's
  pattern is to fail-closed if trailing bytes remain after
  deserialization of a leveldb value.
- **Description**: `db.rs:631-634`:
  ```rust
  match self.db.get_cf(cf, &key)? {
      Some(data) => {
          let (utxo, _) = UTXO::bitcoin_deserialize(&data)
              .map_err(...)?;
          Ok(Some(utxo))
      }
  ```
  The `_` discards `bytes_consumed`. If the on-disk value has
  trailing bytes (e.g. from a buggy migration / future schema
  version with appended fields), they're silently ignored.
- **Impact**: Schema-versioning hazard — future writers can
  append fields and current readers will accept the prefix,
  potentially mis-interpreting state.

### BUG-20 — No PeekCoin (non-caching read) variant — all reads always hit RocksDB [P3]

- **File**: there is no `peek_coin` / `peek_utxo` in
  `db.rs`/`lib.rs`.
- **Core ref**: `bitcoin-core/src/coins.h:314-316`:
  ```cpp
  //! Does not populate the cache. Use GetCoin() to cache the result.
  virtual std::optional<Coin> PeekCoin(const COutPoint& outpoint) const;
  ```
- **Description**: PeekCoin is a hot-path API for views that
  shouldn't pollute the cache (e.g. mempool checks for already-
  known-spent coins). Ouroboros's `get_utxo` is always a
  RocksDB get; there is no concept of "cache" to bypass, so the
  primitive doesn't exist. With BUG-1 closed and a real cache
  added, PeekCoin must be wired or the cache will thrash on
  one-shot mempool queries.
- **Impact**: Latent — won't materialize until BUG-1 is closed.

### BUG-21 — clear_chainstate uses `[0u8; 36]..[0xFFu8; 36]` range with no `'C'` prefix bound [P3]

- **File**: `db.rs:706-719` (`clear_chainstate`).
- **Core ref**: N/A — Core handles wipe via leveldb destroy.
- **Description**:
  ```rust
  let start = [0u8; 36];
  let end = [0xFFu8; 36];
  self.db.delete_range_cf(cf, &start, &end)?;
  ```
  Works because CHAINSTATE_CF is a dedicated column family with
  no other keys. If BUG-2 ever lands (`'C'` prefix added), this
  range will silently miss keys that don't fall inside the
  37-byte (`'C'` + 36-byte body) range. Latent regression risk.
- **Impact**: Forward-compatibility hazard with BUG-2 fix.

### BUG-22 — No GetHeadBlocks read API exposed on PyBlockchainDB (Python cannot inspect recovery state) [P3]

- **File**: `db.rs:1076-1101` defines `get_head_blocks` but
  `PyBlockchainDB` does not expose it via pyo3. Search:
  `grep -n head_blocks lib.rs` returns matches only inside
  apply_block batch construction.
- **Core ref**: Core exposes this via `gettxoutsetinfo` JSON
  output (`hash_serialized_3` is computed on the *finalized*
  view — if HEAD_BLOCKS exists, RPC operations refuse to start
  until ReplayBlocks completes). Ouroboros has no such gate.
- **Description**: A Python operator wanting to diagnose
  "why is recovery taking so long?" has no programmatic access
  to the HEAD_BLOCKS state. Could be useful to expose for
  `getchainstates` parity.
- **Impact**: Operability gap.

### BUG-23 — connect_block_at_height does serial per-input get_cf (no MultiGet) — slow reorgs [P2]

- **File**: `db.rs:2611-2618`.
- **Core ref**: N/A — Core uses cache lookups which are
  in-memory.
- **Description**: Pipeline A
  (`connect_block_from_bytes`) batches all inputs into a single
  `multi_get_cf` call (`lib.rs:3739-3746`). Pipeline B
  (`connect_block_at_height`) reads inputs one at a time inside
  the per-tx loop. A reorg that reconnects multiple blocks does
  N × M individual `get_cf` calls (N blocks × M inputs/block) →
  potentially 100s of ms per block during a deep reorg.
- **Impact**: Reorg latency / starvation under load.

### BUG-24 — UTXO Serialize/Deserialize use `serde::{Serialize, Deserialize}` derive — schema is bincode-tied not Core-tied [P3]

- **File**: `types.rs:355-368`:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
  pub struct UTXO { ... }
  ```
- **Description**: The struct derives `serde::{Serialize,
  Deserialize}` which is **not** what `bitcoin_serialize` /
  `bitcoin_deserialize` use (those go through `to_bytes` /
  `from_bytes` — `consensus_encode`). The serde-derived impls
  exist anyway and are accessible to any future caller — risk
  of two different on-disk encodings being produced if someone
  swaps `bitcoin_serialize` for `bincode::serialize`. Plus
  drops a maintenance hazard: bincode-encoded UTXOs would be
  silently unrecognizable to bitcoin_deserialize.
- **Impact**: Latent — only fires if a developer uses
  `bincode::serialize(utxo)` instead of `utxo.bitcoin_serialize()`.
  Defensive: drop the serde derives.

### BUG-25 — iter_utxos in lib.rs sorts by Txid::to_string (display hex) NOT internal byte order [P2]

- **File**: `database.py:477-481`:
  ```python
  raw_txid = py_utxo.txid
  if isinstance(raw_txid, str):
      raw_txid = bytes.fromhex(raw_txid)[::-1]
  ```
- **Core ref**: `bitcoin-core/src/kernel/coinstats.cpp` iterates
  via `CCoinsViewCursor` which yields coins in leveldb-key order
  — i.e. internal little-endian byte order of (txid, vout).
- **Description**: Rust's `PyUTXO.txid` is serialized via
  `Txid::to_string` (display order, reversed). Python reverses
  with `[::-1]` to recover internal order. **Then** `rpc.py:7120`
  sorts by `(u.txid, u.vout)` — which sorts on the reversed
  bytes. So the iteration order matches Core's iteration order
  only if Core also iterates in the reversed byte-order — which
  it does NOT (leveldb keys are byte-compared lexicographically).
  Currently the sort is in **internal byte order** (since
  `database.py` reverses back to internal order before yielding),
  so this happens to be parity-correct. But: any future change
  to skip the reverse step in `database.py` (or to call
  `iter_utxos` directly without the wrapper) silently shifts the
  iteration order and breaks `hash_serialized_3` parity.
- **Impact**: Latent — depends on a specific manual reversal
  step in `database.py:479` that has no test enforcing it.
  Comment-as-confession candidate (the wrapper code IS the only
  thing keeping parity).

### BUG-26 — `dumptxoutset` snapshot dumping path also materializes via list(iter_utxos) in Python [P1]

- **File**: `src/ouroboros/snapshot.py` (referenced via
  `iter_utxos` consumers); `database.py:461-489`.
- **Description**: Same OOM class as BUG-10. The snapshot
  dumper iterates `for py_utxo in self._db.iter_utxos()` — which
  is a `Vec<PyUTXO>` returned across the FFI boundary, so the
  Python side does see a list-materialization moment even though
  the `for ... in ...` syntax suggests a generator.
- **Impact**: `dumptxoutset` on mainnet OOMs the daemon. Maxbox
  has 128 GiB so it barely fits, but VPS deployments cannot run
  dumptxoutset at all.

Fleet-pattern smells
--------------------

- **Dead module (W138/W139-style)** — `CoinsCache` (894 LOC + 13
  tests + flag bitfield + DIRTY/FRESH state machine + flush
  semantics) has zero production callers. Closest fleet analogue:
  the rustoshi `zmq.rs` 1079-LOC dead module from W141.
- **Two-pipeline guard 5th extension** — connect-side pipeline
  divergence (A=`connect_block_from_bytes` with intra-block
  overlay + MultiGet; B=`connect_block_at_height` without
  overlay, serial get_cf) re-introduces W93 BUG-C in path B.
  Twin to the W124 RPC two-pipeline and the W140 HTTP two-pipeline.
- **Comment-as-confession 4th distinct extension this campaign**
  — `rpc.py:7184-7186` ("Core also emits 0 when no view is open"
  — incorrect; rationalizes the gap rather than fixing it).
  Mirrors haskoin W138 ("In a full implementation, we would
  compute MuHash3072 here. For now, mark as validated") and
  rustoshi W141 zmq.rs:271-275.
- **Carry-forward re-anchor** — `iter_utxos` materialization
  (BUG-10/BUG-26) is the same shape as W124/W125 RPC eager-list
  problems — Python list materialization across the Rust→Python
  FFI boundary in a place that should be a streaming generator.
  Same root cause: pyo3 doesn't easily allow streaming returns,
  so every "iter" actually copies.
- **Genesis edge-case fork** (BUG-16) — pipeline A handles
  height==0 (`store_utxos = height > 0`), pipeline B refuses
  (`return Err(...)`). Different behaviour, same input.

Cross-cut to other waves
------------------------

- **W138 (assumeUTXO)**: BUG-11 (per-call put_cf in
  `add_utxo_raw`) compounds with W138 BUG-7 (ouroboros invented
  mainnet h=840000 hash). A bulk-import path that's both slow
  AND validates against a fabricated commitment is the worst-case
  combination.
- **W110 (block storage)**: BUG-7 (HEAD_BLOCKS shape) overlaps
  with the block-storage crash-recovery story — Core's
  ReplayBlocks reads HEAD_BLOCKS and replays forward from undo
  data; ouroboros's recovery rolls BACKWARDS via
  disconnect_block_at_height. Different reconciliation
  semantics.
- **W141 (REST)**: BUG-10 (`gettxoutsetinfo` eager
  materialization) also poisons `/rest/chaininfo.json` and
  `/rest/getutxos` (which call `iter_utxos`-equivalent paths). A
  REST consumer on a public endpoint can DoS the daemon by
  hitting `getutxos` with a script-template scan.

Priority fix order (operator-visible)
-------------------------------------

1. **BUG-10** (gettxoutsetinfo materialization → daemon OOM) —
   refactor `iter_utxos` to yield a Python generator via pyo3's
   `__iter__` protocol; refactor RPC handler to use a running
   digest accumulator. Closes BUG-10/BUG-26. 1 day of work.
2. **BUG-8** (intra-block undo loss on reconnect) — copy the
   `in_block_added` overlay from pipeline A into pipeline B.
   ~30-LOC fix. Closes a P0-CDIV.
3. **BUG-9** (no BIP-30 enforcement on connect) — gate `put_cf`
   with a HaveCoin check before adding coinbase outputs (with
   exception-height carve-outs symmetric to
   `DISCONNECT_BIP30_EXCEPTION_HEIGHTS`). ~20-LOC fix.
4. **BUG-1** (dead CoinsCache) — wire `CoinsCache` into the live
   path in pipeline A, replacing the in_block_added overlay. Closes
   BUG-1 AND BUG-12 AND BUG-13. Large refactor (~500 LOC),
   benefits IBD perf + flush triggers + dbcache tunability.
5. **BUG-2 / BUG-4 / BUG-5 / BUG-6** as a single
   "Core-byte-compat chainstate" wave — adds `'C'` prefix, drops
   redundant outpoint, adds CompressAmount, packs height|coinbase.
   Major schema migration; gate behind `CHAINSTATE_VERSION` bump.
   Combined ~9 GB chainstate shrink on mainnet.
6. **BUG-3** (obfuscate_key) — bundle with the schema-version
   migration (same migration window).
7. **BUG-7** (HEAD_BLOCKS vector shape) — bundle with the same
   migration.

End of W147 audit.
