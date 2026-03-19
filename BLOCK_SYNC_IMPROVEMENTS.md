# Block Sync Performance Improvements

This document outlines issues found during testnet4 sync testing and provides steps and Cursor prompts to fix them. Block sync was measured at ~11 blocks/minute, which would take ~7-8 days to sync 122k blocks—far too slow.

## Issues Overview

| Issue | Impact | File(s) |
|-------|--------|---------|
| Low parallelism | Only ~15-16 in-flight requests across 8 peers | `block_sync.rs` |
| Frequent timeouts | 15s timeout may be too aggressive; peers often timeout | `block_sync.rs` |
| Peer disconnects | Peers drop connection; need reconnection handling | `block_sync.rs`, `peer_manager.rs` |
| Progress bar stuck at 0 | Block sync progress not reported to UI | `block_sync.rs`, `lib.rs`, `sync_manager.py` |
| Genesis block skipped | "No hash found for height 0" - early blocks may not download | `block_sync.rs` |

---

## Issue 1: Low Parallelism ✅ IMPLEMENTED

**Problem:** Only ~15-16 block requests in flight at a time across 8 peers. Bitcoin Core typically uses far more parallelism during IBD (e.g., 16+ requests per peer).

**Location:** `ferrous-utils/sync/src/network/block_sync.rs`

**Implementation (done):**
- Added `DEFAULT_MAX_IN_FLIGHT = 128` (16 per peer × 8 peers, matching Bitcoin Core style)
- Default `max_concurrent` increased from 16 to 128
- Removed `batch_size.min(16)` cap—batch size now uses full `max_concurrent`
- Raised `set_max_concurrent` cap from 32 to 256 for configurability

**Steps:**
1. Find where the max in-flight or batch size is defined.
2. Increase the number of simultaneous block requests (e.g., 16-32 per peer, or 128-256 total).
3. Ensure requests are distributed across peers rather than waiting for one peer to finish.

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, find where we limit the number of 
in-flight block requests. Increase parallelism so we request more blocks simultaneously 
from peers—aim for at least 16 requests per peer or 128+ total in-flight. Bitcoin Core 
uses high parallelism during IBD. Show me the current limits and suggest new values.
```

---

## Issue 2: Frequent Timeouts ✅ IMPLEMENTED

**Problem:** `Timeout waiting for block from X (in-flight: N)` appears often. The 15-second receive timeout may be too short—peers sometimes take longer to respond, especially under load.

**Location:** `ferrous-utils/sync/src/network/block_sync.rs`

**Implementation (done):**
- Added `RECEIVE_TIMEOUT_SECS` (60s) and `IN_FLIGHT_TIMEOUT_SECS` (60s) constants
- Increased receive timeout from 15s to 60s when waiting for block messages
- On receive timeout: re-queue that peer's in-flight blocks so another peer can try immediately (no longer wait for in-flight timeout)
- Increased in-flight timeout from 30s to 60s for consistency
- Both main sync loop and `download_block_parallel` use the shared constants

**Steps:**
1. Find the timeout duration used when waiting for block messages.
2. Increase it (e.g., from 15s to 30s or 60s).
3. Consider making the timeout configurable or using exponential backoff for retries.
4. When a timeout occurs, don't treat it as a fatal error—re-request from another peer.

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, find the timeout used when waiting 
for block messages. The current 15 second timeout causes frequent "Timeout waiting 
for block" messages. Increase it to 30-60 seconds. Also ensure that when we timeout, 
we re-request the block from a different peer rather than failing. Show me the timeout 
logic and the retry handling.
```

---

## Issue 3: Peer Disconnects ✅ IMPLEMENTED

**Problem:** `Error receiving from X: Connection closed` and `Invalid peer state: expected Connected, got Disconnected`. When a peer disconnects, we should remove it from the active set and retry requests from other peers.

**Location:** `ferrous-utils/sync/src/network/block_sync.rs`, `peer_manager.rs`

**Implementation (done):**
- Added `is_disconnect_error()` helper for `ConnectionClosed`, `Disconnected`, `InvalidState { actual: Disconnected }`
- **Receive loop:** On disconnect error, do not add peer back; re-queue its in-flight blocks so other peers can fetch them
- **Send loop:** On `send_message` failure with disconnect error, do not add peer back; do not insert into `in_flight` for that request
- Only insert into `in_flight` when send succeeds
- Disconnected peers are no longer in the peer map, so `connected_peers()` excludes them automatically

**Steps:**
1. When a peer disconnects during block sync, mark it as unavailable and don't retry requests to it.
2. Re-request any in-flight blocks that were requested from the disconnected peer from other peers.
3. Consider reconnecting to peers after a cooldown period if we need more peers.

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, when we get "Connection closed" or 
"Invalid peer state: expected Connected, got Disconnected", we should:
1. Remove the peer from the active sync pool
2. Re-request any blocks that were in-flight for that peer from other peers
3. Avoid trying to use that peer for new requests until it reconnects

Find where peer errors are handled and add this logic. Also check peer_manager.rs 
for how we mark peers as disconnected.
```

---

## Issue 4: Progress Bar Stuck at 0 ✅ IMPLEMENTED

**Problem:** The progress bar shows "0 blocks/s" throughout block sync. The block sync progress is not being reported to the Python progress callback.

**Location:** `ferrous-utils/sync/src/network/block_sync.rs`, `ferrous-utils/sync/src/lib.rs`, `src/ouroboros/cli.py`

**Implementation (done):**
- Added `BlockProgressCache` and `progress_cache` to BlockSync - updated when blocks are received
- `update_progress()` now writes to cache; `get_progress_stats()` reads it (sync, no await)
- `FastSync::get_sync_progress` uses block_sync stats when available for blocks_per_second and eta_seconds
- Call `update_progress()` after each block stored for responsive UI updates
- CLI label changed from "headers" to "blocks"
- **Additional fix:** `get_sync_progress` handles empty DB (BlockNotFound) - returns current_height=0 instead of error, so progress bar updates from the very start
- **Additional fix:** Initial progress callback fired immediately at sync start so user sees progress state right away

**Steps:**
1. Find where the block sync progress callback is invoked (if at all).
2. Ensure `sync_blockchain()` reports both header progress and block progress.
3. The progress callback should receive: blocks downloaded, blocks per second, total blocks.
4. Update the Python sync_manager to pass the callback and display block progress.

**Cursor prompt:**
```
The block sync progress bar shows "0 blocks/s" because block download progress is never 
reported. In ferrous-utils/sync:

1. In block_sync.rs: Find where blocks are received and stored. Add a call to the 
   progress callback (ProgressCallback) each time a block is successfully received, 
   passing the current block count and height.

2. In lib.rs: Ensure sync_blockchain() passes the progress callback to both header 
   sync and block sync, and that block sync invokes it when blocks are downloaded.

3. The callback should report: blocks downloaded so far, estimated total, and 
   blocks-per-second for the progress bar.

Search for ProgressCallback and sync_blockchain to understand the flow.
```

---

## Issue 5: Genesis Block / Early Blocks ✅ IMPLEMENTED

**Problem:** `No hash found for height 0, skipping`. Blocks 0-144 may not be requested correctly because we don't have block hashes for the early chain.

**Location:** `ferrous-utils/sync/src/network/block_sync.rs`, `header_sync.rs`, `chain_params.rs`

**Implementation (done):**
- Added `chain_params.rs` with `genesis_block_hash()` and `genesis_block_timestamp()` for Bitcoin, Testnet, Testnet4
- In `header_sync.rs`: When saving first batch (was_empty && start_height==1), store genesis metadata at height 0
- In `block_sync.rs`: Fallback to genesis hash when `get_block_hash_by_height(0)` returns None (schedule_downloads, request_block, handle_timeout)

**Steps:**
1. We store block metadata (including hash) in the header sync phase. Height 0 should have the genesis block hash.
2. Ensure we store genesis block metadata during header sync—even when we request "from block 1", we need the genesis hash for the chain.
3. For block sync, when we need a hash for height N, we should get it from `get_block_hash_by_height(N)`. If we don't have it, we may need to request headers from genesis first.
4. Verify that header sync stores genesis/block 0 metadata when the first batch starts from block 1.

**Cursor prompt:**
```
In ferrous-utils/sync, block sync logs "No hash found for height 0, skipping". 
This suggests we're missing genesis block metadata.

1. In header_sync.rs: When we receive the first batch (block 1, 2, 3...) from genesis 
   locator, we never store genesis (block 0) metadata. We need to either:
   - Request genesis header explicitly, or
   - Store a placeholder/genesis hash when we know we're starting from block 1

2. In block_sync.rs: Find where "No hash found for height 0" is logged. We need 
   get_block_hash_by_height(0) to return the genesis hash. Check if we can get 
   genesis from the network config when the DB doesn't have it.

3. Ensure blocks 0 through N are all requested—don't skip genesis.
```

---

## Recommended Order of Implementation

1. **Fix Issue 5 (Genesis)** first—otherwise we may never sync blocks 0-144. ✅
2. **Fix Issue 4 (Progress)**—helps with debugging and user feedback. ✅
3. **Fix Issue 1 (Parallelism)**—biggest impact on speed. ✅
4. **Fix Issue 2 (Timeouts)**—reduces false timeouts and retries. ✅
5. **Fix Issue 3 (Disconnects)**—improves robustness. ✅

---

## Verification

After applying fixes, run:

```bash
cd /home/max/hashhog/ouroboros
source .venv/bin/activate
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset
```

**Target metrics:**
- Block rate: **100+ blocks/minute** (1.5+ blocks/s)
- Full testnet4 sync (122k blocks): **~2-4 hours** on a good connection
- Progress bar: Should show accurate blocks/s and percentage

---

## Receive Timeout Tuning (Step 2 from BLOCK_SYNC_NEXT_STEPS)

**Implementation (done):**
- Added configurable receive timeout via:
  - `BlockSync::set_receive_timeout_secs(u64)` for programmatic control
  - Environment variable `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS` (default: 30)
- Timeout logged at block sync start: `Block sync: N blocks to download (receive timeout: Xs)`

**Usage:**
```bash
# Try 15s timeout
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=15 ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset

# Try 20s timeout
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=20 ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset
```

**Tuning results:** (fill in after testing)
| Timeout | Blocks/min | Notes |
|---------|------------|-------|
| 30s (default) | | |
| 20s | | |
| 15s | | |

---

## Reduced Debug Logging (Step 4 from BLOCK_SYNC_NEXT_STEPS)

**Implementation (done):**
- `OUROBOROS_VERBOSE=1` enables per-message debug logs (per-block requests, received messages)
- Default: batch log every 50 blocks: `[block-sync] Received N blocks`
- Error logs always kept: "Failed to store/deserialize", "Re-queued N blocks from disconnected peer", etc.

**Usage:**
```bash
# Normal (reduced logging)
ouroboros --network testnet4 sync

# Verbose (full debug)
OUROBOROS_VERBOSE=1 ouroboros --network testnet4 sync
```

---

## Progress Bar Verification (Step 5 from BLOCK_SYNC_NEXT_STEPS)

**Implementation (done):**
- Rolling-window speed: blocks_per_second computed from last 10 seconds of block timestamps (more responsive than average-from-start)
- progress_cache updated after each block; Python sync_manager polls every 1 second
- Flow: update_progress() → compute_progress() → progress_cache → get_progress_stats() → get_sync_progress()

**Verification:** Run sync and observe progress bar shows non-zero blocks/s after first blocks arrive:
```bash
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset
```

---

## Additional References

- Bitcoin Core IBD: Uses `-maxblocksinflight` (default 16) and `-maxoutboundconnections` (default 8)
- Block sync typically requests blocks in parallel by height, with priorities for recent blocks
- Peers may rate-limit; spreading requests across many peers helps
