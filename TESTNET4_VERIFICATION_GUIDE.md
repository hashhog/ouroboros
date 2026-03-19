# Testnet4 Verification Guide

Compare Ouroboros with Bitcoin Core on testnet4 for **correctness** and **speed**.

**Goals:**
1. Verify Ouroboros stores the same block hashes as Bitcoin Core (correctness)
2. Get Ouroboros sync speed within a reasonable range of Bitcoin Core

---

## Prerequisites

| Component | Path / Command |
|-----------|----------------|
| Ouroboros | `ouroboros --network testnet4 --data-dir <dir> sync` |
| Bitcoin Core | `bitcoin/build/bin/bitcoind` and `bitcoin/build/bin/bitcoin-cli` |
| Bitcoin data dir | `bitcoin/testnet4_sync_data` (or custom) |

Ensure both are built. Bitcoin Core: see `bitcoin/sync_testnet4_timed.sh`.

---

## Phase 1: Correctness Verification

Run both to completion, then compare block hashes at sampled heights.

### Step 1.1: Sync Bitcoin Core

```bash
cd bitcoin
./sync_testnet4_timed.sh
```

Wait until "SYNC COMPLETE" in `sync_testnet4_timing.log`. Or run manually:

```bash
bitcoin/build/bin/bitcoind -testnet4 -datadir=bitcoin/testnet4_sync_data -daemon
# Monitor until verificationprogress >= 0.9999
bitcoin/build/bin/bitcoin-cli -testnet4 -datadir=bitcoin/testnet4_sync_data getblockchaininfo
```

### Step 1.2: Sync Ouroboros

Use a **separate** data dir. Run with resync enabled (recommended):

```bash
OUROBOROS_TRY_RESYNC=1 RUST_LOG=sync=info ouroboros --network testnet4 --data-dir .ouroboros-testnet4-compare sync 2>&1 | tee ouroboros-sync-compare.log
```

Wait until header and block sync complete (progress reaches 100%).

### Step 1.3: Compare Block Hashes

**Note:** Bitcoin Core must be running (bitcoind) for bitcoin-cli to work. Start it if needed:
`bitcoin/build/bin/bitcoind -testnet4 -datadir=bitcoin/testnet4_sync_data -daemon`

Use the comparison script:

```bash
python scripts/compare_block_hashes.py \
  --ouroboros-dir .ouroboros-testnet4-compare \
  --bitcoin-cli bitcoin/build/bin/bitcoin-cli \
  --bitcoin-datadir bitcoin/testnet4_sync_data \
  --testnet4
```

Run from project root. Requires `bitcoind` running.

**Expected:** All sampled block hashes match. Exit 0 = success.

---

## Phase 2: Speed Comparison

Run **sequentially** (not at the same time) to avoid resource contention.

### Step 2.1: Time Bitcoin Core Sync

```bash
cd bitcoin
rm -rf testnet4_sync_data   # fresh sync
./sync_testnet4_timed.sh
```

Record the **Total sync time** from `sync_testnet4_timing.log`.

### Step 2.2: Time Ouroboros Sync

```bash
rm -rf .ouroboros-testnet4-speedtest
time env OUROBOROS_TRY_RESYNC=1 RUST_LOG=sync=info \
  ouroboros --network testnet4 --data-dir .ouroboros-testnet4-speedtest sync 2>&1 | tee ouroboros-speed.log
```

Record the `real` time from the `time` output.

### Step 2.3: Compare

| Metric | Bitcoin Core | Ouroboros |
|--------|--------------|-----------|
| Blocks | ~122,300 | ~122,300 |
| Time | ___ min | ___ min |
| Blocks/sec | ___ | ___ |

**Target:** Ouroboros within ~2–5× of Bitcoin Core. Bitcoin Core does full UTXO validation; Ouroboros may do less, so raw block throughput can be higher, but network/peer behavior affects both.

---

## Cursor Prompts

### Prompt #1: Create Block Hash Comparison Script

```
Create scripts/compare_block_hashes.py that:

1. Takes CLI args:
   --ouroboros-dir (Ouroboros data directory, e.g. .ouroboros-testnet4-compare)
   --bitcoin-cli (path to bitcoin-cli, e.g. bitcoin/build/bin/bitcoin-cli)
   --bitcoin-datadir (path to Bitcoin Core data dir, e.g. bitcoin/testnet4_sync_data)
   --testnet4 (flag: add -testnet4 to bitcoin-cli)
   --heights (optional: comma-separated heights to check, default: 0,1000,10000,50000,100000,tip)

2. For each height:
   - Ouroboros: Use BlockchainDatabase(ouroboros_dir).get_block_hash_by_height(h) and get_best_block() for tip. Convert hash to hex (same byte order as stored - typically display/reversed order for Bitcoin).
   - Bitcoin: Run bitcoin-cli with -testnet4 -datadir and getblockhash <height>. For tip, use getblockcount() then getblockhash.

3. Compare hashes (string comparison). Bitcoin Core returns hex in display order. Ensure Ouroboros hash is normalized the same way - if rust-bitcoin uses internal order, reverse bytes before hex.

4. Output: Print "height H: Ouroboros=XXX Bitcoin=YYY [MATCH|MISMATCH]" for each. If any mismatch, exit 1. If all match, exit 0.

5. Handle missing blocks (None from Ouroboros, or RPC error from Bitcoin) - report and exit 1.
```

### Prompt #2: Add Ouroboros Timed Sync Script

```
Create scripts/sync_testnet4_timed.sh in the project root that:

1. Runs Ouroboros sync with timing:
   - { time env OUROBOROS_TRY_RESYNC=1 RUST_LOG=sync=info ouroboros --network testnet4 --data-dir .ouroboros-testnet4-timed sync 2>&1; } | tee ouroboros_sync_timing.log
   - Or use bash SECONDS/date before and after for cleaner timing output

2. Logs start time, end time, and total duration to ouroboros_sync_timing.log
3. Uses lock file (.ouroboros_sync.lock) to prevent multiple instances
4. Accepts -f/--fresh to clear data dir before sync (like Bitcoin script)
5. On success, prints "SYNC COMPLETE" and total time
```

### Prompt #3 (Optional): Reduce Ouroboros Log Verbosity for Benchmarks

```
In ferrous-utils/sync/src/network/block_sync.rs: Change the per-block "Requested block X from Y" logging from debug! to trace!, so it only appears with RUST_LOG=sync=trace. This reduces log size during speed runs while keeping summary logs at info/debug.
```

---

## Summary Workflow

**Quick: use the unified script (from project root):**

```bash
cd /home/max/hashhog/ouroboros
./scripts/run_testnet4_comparison.sh --fresh
```

This will:
1. Sync Bitcoin Core from `bitcoin/` (uses `bitcoin/build/bin/bitcoind`)
2. Sync Ouroboros (uses your installed `ouroboros` CLI)
3. Compare block hashes at heights 0, 1000, 10000, 50000, 100000, tip
4. Print sync times and correctness result

**Manual workflow:**
```
1. Sync Bitcoin Core (fresh)     → record time
2. Sync Ouroboros (fresh)       → record time  
3. Run compare_block_hashes.py  → verify correctness
4. Compare times                 → assess speed gap
5. If slow: apply SYNC_RECOMMENDATIONS_20260212.md (TRY_RESYNC, etc.)
6. Re-run until correctness ✓ and speed acceptable
```

**If both are already synced** – run correctness check only:
```bash
./scripts/run_testnet4_comparison.sh --compare-only
```

---

## Troubleshooting

| Issue | Action |
|-------|--------|
| Hash mismatch at height 0 | Check genesis hash for testnet4; Ouroboros and Bitcoin must use same chain params |
| Hash mismatch at tip | One may not have finished syncing; ensure both at same height |
| Ouroboros much slower | Enable OUROBOROS_TRY_RESYNC=1; check for "No peers" stalls in log |
| Bitcoin-cli fails | Ensure bitcoind is running or use a synced datadir from a completed run |
| Ouroboros DB error | Ensure sync completed; data dir must contain RocksDB from Rust sync |
