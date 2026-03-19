# Sync Fixes and Debugging Guide

This document explains the issues seen during `ouroboros sync` on testnet4, their root causes, and step-by-step fixes (including Cursor prompts).

## Issue Summary from Your Log

| Symptom | Root Cause |
|---------|------------|
| `Payload size exceeds limit: 3585571606 > 4194304` | Stream desync: reading from wrong byte offset |
| `Invalid magic bytes: expected 283f161c, got 4e2e4fbb` | Stream desync: treating payload bytes as header |
| `[block-sync] Re-queued N blocks from disconnected peer` | Peers drop after desync; blocks re-queued |
| `No peers available, waiting 1s/2s/5s/10s...` | Most peers blacklisted after desync; slow recovery |
| `81 / 122,198 blocks` | `blocks_downloaded` is per *run*; DB may have more blocks |

---

## 1. Stream Desynchronization (Primary Bug)

### What’s happening

Peers send valid Bitcoin P2P messages (24-byte header + payload). After receiving a block:

1. The next `receive_message()` call sometimes starts from the middle of the previous block’s payload instead of the next message header.
2. Those bytes are interpreted as a message header → garbage `payload_size` (e.g. billions) and wrong magic bytes.
3. We blacklist the peer, disconnect, and re-queue blocks.

### Root cause: timeout during large payload read

Flow:

1. We read 24-byte header → `payload_size` = ~2MB.
2. We call `read_exact(&mut payload)` for 2MB.
3. The read is wrapped in `timeout(30s, receive_message_internal())`.
4. If the block takes >30s (slow link, large block), the timeout fires.
5. The `read_exact` future is cancelled mid-read → only part of the payload is read.
6. The stream is now at the wrong offset; the next read sees payload bytes as header → garbage.

Evidence: garbage values like `3585571606` or `4e2e4fbb` (hex) look like arbitrary block data, not real headers.

### Fix 1a: Apply block-sync receive timeout to peers

Block sync has `receive_timeout_secs` (env `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS`, default 30), but this is never applied to the `Peer`. Each `Peer` is created with a hardcoded 30s timeout and keeps it after being drained for block sync.

**Fix:** When draining peers for block sync, set each peer’s timeout to `self.receive_timeout_secs` before spawning the receive task.

**File:** `ferrous-utils/sync/src/network/block_sync.rs`

**Cursor prompt:**
```
In block_sync.rs, when we drain peers and spawn peer receive tasks, the Peer uses 
default_timeout=30s from Peer::connect. Block sync has receive_timeout_secs (env 
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS, default 30) but we never apply it.

Before spawning each peer task (in the "for (addr, peer) in peer_map" loop around line 315), 
call peer.set_timeout(Duration::from_secs(self.receive_timeout_secs)) so block sync 
timeouts are respected. This allows increasing the timeout via env var for slow connections.
```

### Fix 1b: Treat Timeout as stream corruption (don’t re-add peer)

If we time out during a payload read, the stream is left in an inconsistent state. We currently do `PeerDoneReason::Timeout => true` and re-add the peer. The next use of that peer will immediately produce garbage (InvalidMagic / PayloadSizeExceeded).

**Fix:** Do not re-add the peer on Timeout. Treat it like desync: re-queue in-flight blocks and do not return the peer to the pool.

**File:** `ferrous-utils/sync/src/network/block_sync.rs`

**Cursor prompt:**
```
In block_sync.rs, when we get RecvEvent::PeerDone(addr, peer, reason), we currently 
set should_add_peer_back = true for PeerDoneReason::Timeout. But if we timed out during 
a large payload read (e.g. receiving a 2MB block), the stream is corrupted - we read only 
part of the payload. The next read would start from the wrong offset.

Change PeerDoneReason::Timeout => false (or handle it like Error with desync: re-queue 
in-flight blocks, don't add peer back). Do NOT add the peer back to the pool on Timeout, 
since the connection is unusable.
```

### Fix 1c: Increase default receive timeout for block sync

30s may be too short for large blocks on slow links. Increase the default and document the env var.

**File:** `ferrous-utils/sync/src/network/block_sync.rs` (look for `DEFAULT_RECEIVE_TIMEOUT_SECS`)

**Cursor prompt:**
```
In block_sync.rs, find DEFAULT_RECEIVE_TIMEOUT_SECS and increase it from 30 to 120 
(2 minutes). Large blocks (up to 4MB) on slow connections can take a long time. 
Document in a comment that OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS can be set for tuning.
```

### Temporary workaround (no code change)

```bash
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

Note: This only helps after Fix 1a is applied. Until then, the env var is ignored.

---

## 2. Block Count and Progress Clarification

### “81 / 122,198 blocks” vs. “almost half downloaded”

- `blocks_downloaded` in the progress bar is for the current run only.
- If you restarted sync after downloading ~53k blocks, the new run starts at 0.
- `fill_download_queue` correctly skips already stored blocks by calling `get_block_by_height`.

So:

1. Your DB likely has many blocks from earlier runs.
2. The progress bar’s numerator is how many blocks this run has stored.
3. Total blocks to download (`67321` in the log) = `end_height - start_height + 1` minus blocks already in DB.

### Verifying DB state

```bash
# Check if blocks exist (example - adjust for your setup)
sqlite3 ~/.ouroboros-testnet4/blocks.db "SELECT COUNT(*) FROM block_metadata;" 2>/dev/null || echo "DB path may differ"
```

Or add a small debug command that prints `get_best_block()` and total block count.

### Cursor prompt for diagnostics

```
Add a debug log at the start of block sync (in block_sync.rs sync_blocks, right after 
fill_download_queue): log::info!("Block sync: db has best_height={}, queue_size={}", 
best_height, queue_size). Use get_best_block for best_height and the queue length for 
queue_size. This helps confirm whether we're re-downloading or starting fresh.
```

---

## 3. “No peers available” for long periods

### Why it happens

After many desyncs (PayloadSizeExceeded, InvalidMagic, or Timeout), most peers are blacklisted. The log shows "Resolved 56 new peer address(es) from DNS seeds" but "No peers available" continues—connections to those addresses may be failing or timing out.

### Fixes

1. **Desync blacklist cooldown**  
   Ensure blacklisted peers expire so we can retry them. Check `peer_manager.rs` for `desync_blacklist` and cooldown logic.

2. **Connection retries**  
   When `maintain_connections` runs and we have few/no peers, it should aggressively try new addresses from DNS seeds.

3. **Avoid over-blacklisting**  
   After Fix 1a/1b/1c, desyncs should drop, so fewer peers will be blacklisted.

### Cursor prompt

```
In peer_manager.rs, review the desync blacklist logic. Ensure blacklisted peers 
are removed after a cooldown (e.g. 5–10 minutes) so we can retry them. Log when 
a peer is removed from the blacklist. Also ensure maintain_connections is called 
when block_sync has no peers - it should trigger connection attempts to known addresses.
```

---

## 4. “Is it trying to redownload blocks?”

### Behavior

No. `fill_download_queue` calls `get_block_by_height(height)` for each height. If the block exists, it skips. Only missing blocks are queued. The “67321 blocks to download” in your log is the number of missing blocks in the range `[start_height, end_height]`, not a full re-sync.

If you see a large queue after a previous partial sync:

- The DB may have been reset, or
- You are using a different data dir, or
- `get_block_by_height` / `get_best_block` are wrong.

Adding the debug log from Section 2 will clarify this.

---

## 5. Implementation order

1. **Fix 1a** – Apply receive timeout to peers (required for env var to work).
2. **Fix 1b** – Don’t re-add peers on Timeout.
3. **Fix 1c** – Increase default timeout.
4. Add the Section 2 debug log.
5. Review desync blacklist and connection logic (Section 3).

---

## 6. Quick reference: env vars and commands

```bash
# Longer receive timeout for large blocks (after Fix 1a)
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120

# Debug logging
RUST_LOG=sync=debug

# Full sync command
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync 2>&1 | tee sync_debug.log
```

---

## 7. Related files

| File | Role |
|------|------|
| `ferrous-utils/sync/src/network/peer.rs` | `receive_message`, `receive_message_internal`, `set_timeout` |
| `ferrous-utils/sync/src/network/block_sync.rs` | Peer task spawn, `PeerDone` handling, `fill_download_queue` |
| `ferrous-utils/sync/src/network/peer_manager.rs` | `drain_peers`, `add_peer`, desync blacklist |
| `ferrous-utils/sync/src/network/messages.rs` | `Message::deserialize`, payload size check |
