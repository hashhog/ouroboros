# Sync Run Improvements and Changes

This document outlines improvements and changes to implement based on observing:

```bash
source .venv/bin/activate
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset
```

Each section includes implementation steps and Cursor prompts.

---

## Observed Issues Summary

| Issue | Severity | Impact |
|-------|----------|--------|
| `ouroboros: command not found` without venv | Medium | Users must remember to `source .venv/bin/activate` first |
| Progress bar stuck at 0% • 0 • 0.0 blocks/s | High | No visible feedback during sync; blocks are downloading (9700+ received) |
| Payload size exceeds limit / Invalid magic bytes | High | Peers disconnect rapidly; massive error spam; sync stalls |
| Excessive logging | Medium | Header sync, DNS, block timeouts, errors flood console |
| No peers available (stall) | High | After all peers disconnect, sync waits indefinitely |
| Block request timeouts | Medium | Many blocks re-queued; cascading failures |

---

## Step 1: Fix `ouroboros` Command Not Found

**Goal:** Allow running `ouroboros` without manually activating the venv.

**Current:** User must run `source .venv/bin/activate` before `ouroboros`.

**Solution options:**
- Add a wrapper script or ensure `ouroboros` is on PATH after `pip install -e .` or `maturin develop`
- Update INSTALLATION.md with clear instructions for making the command available
- Add a shell alias or `pipx` installation option

**Files to modify:**
- `pyproject.toml` – verify scripts/entry points
- `INSTALLATION.md` – document activation requirement or alternatives

**Cursor prompt:**
```
After "pip install -e ." or "maturin develop", the user gets "ouroboros: command not found" unless they run "source .venv/bin/activate". 

1. Update pyproject.toml and/or INSTALLATION.md so users can run `ouroboros` reliably.
2. Options: ensure the venv bin is on PATH, add a wrapper script, or document "python -m ouroboros" as an alternative.
3. Add a troubleshooting section for "command not found".
```

---

## Step 2: Fix Progress Bar Stuck at 0% ✅ IMPLEMENTED

**Goal:** Progress bar must show actual blocks downloaded, percentage, and blocks/s during block sync.

**Current:** Progress shows `0% • 0 • 0.0 blocks/s • -:--:--` even when blocks are being received (e.g. `[block-sync] Received 9700 blocks`).

**Root cause:** `get_sync_progress()` uses `db.get_best_block()` for `current_height` and `progress_percent`. During block sync, either:
- `get_best_block()` returns 0 or BlockNotFound (e.g. chainstate cleared, best_block not updated correctly)
- Or the progress bar uses `current_height` from DB while blocks are stored but best_block is not updated until blocks are validated/committed in order

**Solution:** Use `blocks_downloaded` from the block sync progress cache when available, instead of (or in addition to) `get_best_block()`. The cache is updated on each stored block. For the progress bar during block sync:
- `blocks` = max(db.get_best_block().1, block_sync.blocks_downloaded)
- `total_height` = actual sync target (e.g. 122155 for testnet4) not estimated_tip
- `progress_percent` = blocks / total_height * 100
- `blocks_per_second` = from block_sync cache (already implemented)

**Files to modify:**
- `ferrous-utils/sync/src/lib.rs` – `get_sync_progress()` should prefer block_sync stats when block sync is active
- Possibly pass `total_to_download` from block sync into progress so percentage is accurate

**Implementation (done):**
- Added `total_to_download` to `BlockProgressCache`; set in `init_progress_cache(queue_size)` when block sync starts
- Extended `get_progress_stats()` to return `(blocks_downloaded, total_to_download, blocks_per_second, eta_seconds)`
- In `get_sync_progress()`: when block sync is active and `total_to_download > 0`, use `blocks_downloaded` (or max with DB height) for current and `total_to_download` for total; percentage = blocks / total × 100
- Falls back to DB height + estimated_tip when block sync is not active

**Cursor prompt:**
```
The progress bar shows 0% • 0 • 0.0 blocks/s during block sync even though blocks are being received ([block-sync] Received 9700 blocks).

In ferrous-utils/sync/src/lib.rs get_sync_progress():
1. When block_sync is active, use block_sync.get_progress_stats() for blocks_downloaded.
2. Use blocks_downloaded (or max of that and db.get_best_block()) for the "blocks" count in the progress bar.
3. For total_height during block sync, use the actual sync target (e.g. from header sync tip) instead of estimated_tip, so percentage is accurate.
4. Ensure progress_percent = blocks_downloaded / total_to_download * 100 when block sync is running.

Trace the flow: block_sync stores blocks → update_progress() → progress_cache. get_sync_progress reads progress_cache. The Python progress bar displays current_height (from DB) and progress_percent. Fix so the bar reflects real progress.
```

---

## Step 3: Fix Payload Size Exceeds Limit / Invalid Magic Bytes ✅ IMPLEMENTED

**Goal:** Stop the flood of "Payload size exceeds limit" and "Invalid magic bytes" errors that disconnect peers.

**Current:** Errors like:
- `Payload size exceeds limit: 3683234585 > 33554432`
- `Invalid magic bytes: expected 283f161c, got 99399e48`

**Root cause:** Stream desynchronization. When reading a message:
1. We read 24-byte header, parse payload_size, then read payload_size bytes.
2. If the connection is reset, truncated, or we read from the wrong offset, we interpret garbage as payload size or magic.
3. The huge "payload size" values (e.g. 3.6e9) are clearly garbage—valid blocks are < 4MB.

**Possible causes:**
- Peer sends a block, we read header then start reading payload; connection resets mid-payload; next read gets block bytes as "header"
- Protocol confusion: reading from wrong offset after partial read
- Need to disconnect cleanly on first parse error and not retry reads on same stream

**Solution:**
- On `PayloadSizeExceeded` or `InvalidMagic`, immediately close the connection and do not attempt further reads—the stream is desync'd.
- Consider adding a max payload sanity check: if payload_size > 4MB (or similar), treat as protocol error and disconnect.
- Ensure we don't log the same error repeatedly for the same peer (rate-limit or single log per disconnect).

**Implementation (done):**
- In `peer.rs`: Added 8MB sanity check before 32MB; if payload_size > 8MB, treat as desync and disconnect immediately
- Set `state = Disconnected` on PayloadSizeExceeded and when Message::deserialize returns any MessageError (InvalidMagic, etc.)
- In `block_sync.rs`: Added `is_protocol_desync_error()` for PayloadSizeExceeded and InvalidMagic; suppress "Error receiving from X" for these unless `OUROBOROS_VERBOSE=1`

**Files to modify:**
- `ferrous-utils/sync/src/network/peer.rs` – receive logic; on MessageError, mark stream as invalid
- `ferrous-utils/sync/src/network/messages.rs` – possibly relax or document MAX_PAYLOAD_SIZE (32MB is correct for Bitcoin)
- Error handling in block_sync peer tasks

**Cursor prompt:**
```
We're seeing massive "Payload size exceeds limit: X > 33554432" and "Invalid magic bytes" errors during block sync. These suggest stream desynchronization—we're reading from the wrong offset (e.g. mid-block).

In ferrous-utils/sync/src/network/peer.rs and/or block_sync.rs:
1. On MessageError::PayloadSizeExceeded or InvalidMagic, immediately close the connection—do not retry reads. The stream is corrupted.
2. Add a sanity check: if payload_size > 4_000_000 (4MB), treat as invalid and disconnect. Bitcoin blocks are rarely > 2MB.
3. Rate-limit or deduplicate "Error receiving from X" logs per peer to avoid spam.
4. Ensure the peer task sends PeerDone(Error) and exits; don't keep reading from the same stream after a parse error.
```

---

## Step 4: Reduce Logging Noise

**Goal:** Clean up console output so users see meaningful progress, not hundreds of debug lines.

**Current noisy logs:**
- `Skipping validation for header at height X (bootstrap mode, i=Y)` – every 100 headers
- `Requesting headers from peer X (starting from height Y)`
- `Received headers message from peer X` / `Deserialized 2000 headers from peer X`
- `Would connect to peer: X:48333` – repeatedly for same IPv6 addresses
- `Retrying DNS seed resolution (attempt N)...` / `Resolved 56 new peer address(es)`
- `Block request timed out for height X, re-queuing` – many per batch
- `Error receiving from X: Message error: ...` – hundreds of times
- `[block-sync] Received N blocks` – every 50 blocks (already reduced from Step 4 of BLOCK_SYNC_NEXT_STEPS)

**Solution:**
- Gate header-sync logs behind `OUROBOROS_VERBOSE=1` (like block-sync)
- "Would connect to peer" – log once per address or batch; or remove if not useful
- DNS retries – log every Nth attempt (e.g. 5, 10, 20) or only on failure
- Block timeout – batch: "Block request timed out for N blocks (heights X-Y), re-queuing"
- Error receiving – keep first occurrence per peer; avoid repeating same error for same peer (or batch)

**Files to modify:**
- `ferrous-utils/sync/src/network/header_sync.rs`
- `ferrous-utils/sync/src/network/peer_manager.rs`
- `ferrous-utils/sync/src/network/block_sync.rs`

**Cursor prompt:**
```
Reduce logging noise during sync. Apply the same pattern as block_sync (OUROBOROS_VERBOSE=1 for debug).

1. header_sync.rs: Gate "Skipping validation", "Requesting headers", "Received headers", "Deserialized N headers" behind is_verbose(). Keep errors and important state changes.
2. peer_manager.rs: Reduce "Would connect to peer" - log once per batch or remove. Reduce "Retrying DNS seed resolution" / "Resolved N addresses" - log every 5th attempt or only on final failure.
3. block_sync.rs: Batch "Block request timed out" - instead of one line per block, log "Block request timed out for N blocks (heights X-Y), re-queuing" every 10-20 timeouts.
4. Ensure errors (disconnect, payload size, etc.) are still logged but optionally rate-limited per peer.
```

---

## Step 5: Improve Peer Recovery When All Peers Disconnect

**Goal:** When all block-sync peers disconnect (e.g. due to payload/magic errors), sync should recover by waiting for new peers instead of stalling indefinitely.

**Current:** After all peers disconnect, we see "No peers available, waiting..." repeatedly. DNS keeps resolving addresses ("Would connect to peer") but no new connections succeed. Eventually the user Ctrl+C.

**Possible causes:**
- PeerManager's connect logic may not be actively connecting to new addresses while block sync is waiting
- Block sync drains peers; when all fail, we wait for PeerManager to have peers again—but PeerManager might not be connecting in the background
- IPv6 addresses ("Would connect to peer: [2001:df6:7280::92:209]:48333") may never connect (IPv4-only connectivity?)

**Solution:**
- Ensure PeerManager has a background task that keeps trying to connect when peer count is low
- When block sync has no peers, wait with exponential backoff (e.g. 1s, 2s, 5s, 10s) to avoid "No peers available, waiting..." spam
- Consider preferring IPv4 addresses if IPv6 connections consistently fail
- Add a max wait time or retry limit before failing sync with a clear error

**Files to modify:**
- `ferrous-utils/sync/src/network/peer_manager.rs`
- `ferrous-utils/sync/src/network/block_sync.rs`

**Cursor prompt:**
```
When all block-sync peers disconnect (e.g. due to payload/magic errors), sync prints "No peers available, waiting..." repeatedly and never recovers.

1. In block_sync.rs: When peer_tasks is empty and we're waiting for peers, add exponential backoff (1s, 2s, 5s, 10s) before each "No peers available" log to reduce spam.
2. In peer_manager.rs: Verify there's an active background task that tries to connect when we have fewer than N peers. Ensure it keeps running during block sync.
3. Consider: if we've been waiting for peers for >5 minutes, log a warning and suggest user check network/firewall.
4. Optionally: prefer IPv4 seed addresses if IPv6 connections consistently fail (testnet4).
```

---

## Step 6: Use Actual Sync Target for Progress

**Goal:** Progress percentage and total should reflect the real sync target (e.g. 122155 for testnet4), not an estimated tip.

**Current:** `estimated_tip` for testnet4 is 100,000, but header sync completed at 122,154. So total_height can be wrong.

**Solution:** When header sync completes, we know the actual tip. Pass that to block sync and to get_sync_progress so:
- `total_height` = header sync tip (e.g. 122155)
- `progress_percent` = blocks_downloaded / total_height * 100

**Files to modify:**
- `ferrous-utils/sync/src/lib.rs` – get_sync_progress
- `ferrous-utils/sync/src/network/block_sync.rs` – store total_to_download
- Possibly header_sync → block_sync handoff

**Cursor prompt:**
```
get_sync_progress uses estimated_tip (100k for testnet4) for total_height, but header sync can reach 122k+ blocks. So progress percentage is wrong.

1. When block sync starts, it knows total_to_download (e.g. 122155). Store that in BlockSync/progress_cache.
2. In get_sync_progress, when block sync is active, use block_sync's total_to_download for total_height instead of estimated_tip.
3. Fall back to estimated_tip when block sync is not active (e.g. header-only phase).
```

---

## Step 7: Batch "Block Request Timed Out" Logging

**Goal:** Reduce noise from hundreds of "Block request timed out for height X, re-queuing" lines.

**Solution:** Collect timeouts and log in batches, e.g.:
- "Block request timed out for 35 blocks (heights 4276–4318), re-queuing"

**Files to modify:**
- `ferrous-utils/sync/src/network/block_sync.rs`

**Cursor prompt:**
```
In block_sync.rs, when we log "Block request timed out for height X, re-queuing", we do it once per block. When many timeouts happen at once, this floods the console.

Instead, collect timeouts in a Vec and log a batch: "Block request timed out for N blocks (heights X-Y), re-queuing". Trigger batch log when we have 10+ timeouts, or every 5 seconds, or when we finish processing a receive round.
```

---

## Verification Checklist

After implementing:

- [ ] `ouroboros` runs without manual venv activation (or doc is clear)
- [ ] Progress bar shows non-zero blocks and blocks/s during block sync
- [ ] Progress percentage increases as blocks are downloaded
- [ ] Payload/magic errors don't flood the console; failed peers disconnect cleanly
- [ ] Logging is minimal without OUROBOROS_VERBOSE
- [ ] When peers disconnect, "No peers available" is throttled; sync recovers when new peers connect
- [ ] Sync completes on testnet4 without manual interrupt

---

## Reference: Key Paths

- Progress: `lib.rs` get_sync_progress → `block_sync.get_progress_stats()` + `db.get_best_block()`
- CLI progress: `cli.py` progress_callback → `sync_manager.get_progress()` → `fast_sync.get_sync_progress()`
- Message parsing: `peer.rs` receive_message_internal → `messages.rs` Message::deserialize
- Payload limit: `messages.rs` MAX_PAYLOAD_SIZE = 32MB
- Noisy logs: `header_sync.rs`, `peer_manager.rs`, `block_sync.rs`
