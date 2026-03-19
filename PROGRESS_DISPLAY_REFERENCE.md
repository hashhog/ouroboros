# Progress Bar Display Reference

This document describes what each phase of the sync progress bar displays, where the values come from, and how they appear in the CLI. Use this to understand current behavior before modifying it.

---

## Overview

Sync runs in two phases: **header sync** (download block headers) and **block sync** (download full blocks). The CLI polls `get_sync_progress()` about once per second and updates a progress bar.

**Data flow:** `SyncProgressReporter.get_progress()` (Rust) → `sync_manager.get_progress()` → `cli.progress_callback()` → Rich `Progress` bar

---

## Phase: Header Sync

**When:** Before block sync starts. `progress_cache.total_to_download == 0`.

### Values Displayed

| Field | Source | Meaning |
|-------|--------|---------|
| `current_height` | `db_height + 1` | Blocks in our chain (headers we have) |
| `total_height` | `header_sync_tip + 1` if set, else `max(estimated_tip, db_height + 1)` | Total headers for the chain |
| `progress_percent` | `(blocks_in_chain / total) × 100` | Percent of headers synced |
| `blocks_per_second` | `0.0` | Not shown meaningfully |
| `eta_seconds` | `0` | No ETA during header sync |
| `phase` | `"header"` | Used to switch display format |
| `total_known` | `header_sync_tip.is_some()` | When false, CLI shows "Requesting current block height..." instead of % |

### Estimated Tip (total_height)

Hardcoded per network in `ferrous-utils/sync/src/lib.rs`:

| Network | Estimated Tip |
|---------|---------------|
| Testnet | 18,000,000 |
| Testnet4 | 150,000 |
| Mainnet (Bitcoin) | 900,000 |
| Other | 1,000,000 |

Actual formula: `total = max(estimated_tip, db_height + 1)` so the bar never goes backwards.

### Edge Cases (addressed)

- **Empty DB:** `db_height = 0` → `blocks_in_chain = 1` (genesis), `progress_percent` reflects 1/total
- **Chain shorter than estimate:** When header sync receives a short batch (< 2000 headers), it sets `header_sync_tip` in the progress cache. `get_progress` then uses `total = header_sync_tip + 1`, so progress reaches 100% at completion
- **Chain longer than estimate:** `total = max(estimated_tip, db_height + 1)` grows as we sync; when `db_height + 1 >= estimated_tip`, we use `db_height + 1` and percent correctly reaches 100%

### CLI Display (Header Phase)

- **When `total_known` is false:** Description shows "Requesting current block height..."; bar shows 0% (avoids misleading percentage).
- **When `total_known` is true:** Normal display.
- **Bar:** Filled according to `progress_percent` (out of 100)
- **Percentage:** `progress_percent` (e.g. `45%`)
- **Blocks field:** `"{current_height:,} headers"` (e.g. `67,501 headers` when at height 67,500)
- **Speed:** Not shown during header sync
- **ETA:** `ETA: 0s` (from `eta_seconds`)

---

## Phase: Block Sync

**When:** After header sync, when downloading full blocks. `progress_cache.total_to_download > 0`.

### Values Displayed

| Field | Source | Meaning |
|-------|--------|---------|
| `current_height` | `blocks_we_have` = (total_chain − total_to_download) + blocks_downloaded | Full blocks we have (from start + downloaded) |
| `total_height` | `progress_cache.total_chain_blocks` | Chain length / block height we're syncing to |
| `progress_percent` | `(blocks_we_have / total_chain_blocks) × 100` | Percent of chain downloaded |
| `blocks_per_second` | From `BlockProgressCache` (rolling 10s window) | Recent download speed |
| `eta_seconds` | `remaining_blocks / speed` | Est. seconds to finish |
| `phase` | `"block"` | Used to switch display format |

### How total_chain_blocks Is Set

When block sync starts (`block_sync.rs`):

```text
total_chain_blocks = (end_height - start_height) + 1
```

With `start_height = 0` and `end_height` = best header height from header sync, this is the full chain length (e.g. 122,198 for a chain whose tip is at height 122,197).

### Speed and ETA Computation

- **Speed:** Rolling 10-second window of `blocks_downloaded` (falls back to average if not enough data)
- **ETA:** `remaining = queue_len + in_flight_count`; `eta = remaining / speed` (or `MAX` if speed is 0)

### CLI Display (Block Phase)

- **Bar:** Filled according to `progress_percent` (out of 100)
- **Percentage:** `progress_percent` (e.g. `45%`)
- **Blocks field:** `"{current_height:,} blocks / {total_height:,}"` (e.g. `55,288 blocks / 122,201`)
- **Speed:** `"{blocks_per_second:.1f} blocks/s"`
- **ETA:** Formatted from `eta_seconds` (e.g. `5m 30s`, `2h 15m`)

---

## Progress Bar Layout (cli.py)

```text
[spinner] Syncing blockchain... ETA: Xm Ys  [=========>    ] 45% • 55,288 / 122,198 blocks • 12.3 blocks/s • 1:30:00
```

- **Description:** `Syncing blockchain... ETA: {eta_str}` (updated every callback)
- **Bar:** `completed = progress_percent`, `total = 100.0`
- **Percentage:** From `progress_percent`
- **Blocks:** `blocks_str` (headers or blocks, depending on phase)
- **Speed:** Shown only during block phase; hidden during header sync
- **TimeRemainingColumn:** Rich’s built-in ETA; may use progress rate when we don’t supply duration

---

## Phase Transition

When switching from header to block phase:

1. `progress_cache.total_to_download` becomes > 0 when block sync starts
2. CLI resets the bar (`completed = 0`) on the first block-phase update
3. Display format changes from `"X headers"` to `"X / Y blocks"`

---

## Relevant Code Locations

| What | File |
|------|------|
| Progress computation | `ferrous-utils/sync/src/lib.rs` — `SyncProgressReporter::get_progress()` |
| Block progress cache | `ferrous-utils/sync/src/network/block_sync.rs` — `BlockProgressCache`, `init_progress_cache`, `update_progress`, `compute_progress` |
| Progress bar / display | `src/ouroboros/cli.py` — `progress_callback`, Rich `Progress` |
| Polling loop | `src/ouroboros/sync_manager.py` — `perform_initial_sync` (polls every `progress_interval`, default 1.0s) |
