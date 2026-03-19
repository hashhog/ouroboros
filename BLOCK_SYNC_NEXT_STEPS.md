# Block Sync: Suggested Next Steps

This document outlines follow-up improvements for block sync performance, based on testing and the previous BLOCK_SYNC_IMPROVEMENTS work. Each section includes Cursor prompts to guide implementation.

---

## Context

**Current state (after BLOCK_SYNC_IMPROVEMENTS):**
- 128 in-flight block requests (was 16)
- 60s → 30s receive timeout
- Peer disconnect handling (re-queue blocks, don't add back)
- Timeout re-queue (blocks go to other peers)
- Genesis block support

**Observed throughput:** ~64 blocks in ~3 minutes (~21 blocks/min) on testnet4. Target: 100+ blocks/min.

**Root cause of slowness:** Block receive loop polls peers *sequentially*. We wait up to 30s per peer before moving to the next, so we only read from one peer at a time while others have blocks buffered.

---

## Step 1: Implement Concurrent Receive (Per-Peer Tasks)

**Goal:** Receive from all peers concurrently by spawning a receive task per peer and processing blocks as they arrive.

**Approach:** Instead of iterating over peers and calling `receive_message()` one at a time, spawn one async task per peer. Each task receives messages and sends blocks (or other results) over a channel. A central loop processes incoming blocks from the channel.

**Files to modify:**
- `ferrous-utils/sync/src/network/block_sync.rs` – receive loop architecture
- Possibly `ferrous-utils/sync/src/network/peer.rs` – if Peer needs `Clone` or `Send` for task spawning

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, the block receive loop polls peers one at a time, which is slow. Refactor to receive from all peers concurrently:

1. After sending GetData requests, spawn one tokio::spawn task per connected peer.
2. Each task runs a loop: call peer.receive_message(), then send the result (Ok(msg) or Err) over a tokio::sync::mpsc channel.
3. The main sync loop receives from the channel and processes blocks (store, update in_flight, etc.).
4. On disconnect or timeout, the task sends the error and exits; the main loop re-queues that peer's blocks.
5. Ensure Peer and Message are Send so they can cross task boundaries. Add tokio::sync::mpsc::Sender to the channel type.

The channel message type could be: enum RecvResult { Message(SocketAddr, Message), Error(SocketAddr, PeerError), Timeout(SocketAddr) }

Show me the channel setup and how the main loop processes messages. Handle the case where we need to put the peer back after temporarily removing it—we may need to pass the peer in the channel when the task exits.
```

**Alternative prompt (simpler):**
```
The block sync receive loop in block_sync.rs polls 8 peers sequentially with a 30s timeout each. To speed this up, use tokio::select! to receive from all peers at once. The challenge: we need to hold 8 Peer objects and call receive_message() on each concurrently. 

Add a drain_peers() method to PeerManager that returns HashMap<SocketAddr, Peer>. Then create 8 futures (one per peer), each doing timeout(10s, peer.receive_message()). Use tokio::select! with 8 branches—when any completes, process that message and recreate the future for that peer. Loop until all peers have produced a result (message, error, or timeout). Debug why the previous futures::select_all implementation hung—maybe use tokio::select! instead since we're in a tokio runtime.
```

---

## Step 2: Tune Receive Timeout

**Goal:** Find a receive timeout that balances throughput and robustness.

**Current:** 30 seconds.

**Trade-off:** Shorter timeout = faster cycling through peers = higher throughput, but more timeouts and re-queues. Longer timeout = fewer false timeouts but slower when a peer is unresponsive.

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, RECEIVE_TIMEOUT_SECS is currently 30. Add a configurable timeout so we can tune it without recompiling. Options:

1. Add a BlockSync::set_receive_timeout_secs(u64) method.
2. Or read from an environment variable like OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS (default 30).
3. Log the timeout value at block sync start for debugging.

Then run testnet4 sync with 15s and 20s timeouts and compare blocks/minute. Document the results in BLOCK_SYNC_IMPROVEMENTS.md.
```

---

## Step 3: Per-Peer Receive Tasks with Channel (Architecture) ✅ IMPLEMENTED

**Goal:** Redesign so each peer has a dedicated receive task that streams messages to a central processor.

**Implementation:** See `BLOCK_SYNC_ARCHITECTURE.md` for the design. Long-lived tasks run for the entire block sync; main sends GetData via command channel.

**Approach:**
- One long-lived task per peer connection
- Each task: loop { msg = peer.receive_message(); sender.send((addr, msg)).await; }
- Main loop: receives from channel, processes blocks, handles errors
- When a peer disconnects, its task exits; re-queue in-flight blocks for that peer

**Files to modify:**
- `ferrous-utils/sync/src/network/block_sync.rs`
- Possibly `ferrous-utils/sync/src/network/peer_manager.rs` – peer lifecycle

**Cursor prompt:**
```
Design a per-peer receive architecture for block sync:

1. When block sync starts, for each connected peer, spawn a tokio task that:
   - Takes ownership of the Peer (removed from PeerManager)
   - Loops: receives messages, sends (peer_addr, Result<Message>) over an mpsc channel
   - On receive error or disconnect, sends the error and exits (drops the peer)

2. The main sync loop receives from the channel. For each (addr, Ok(msg)): process block/ping/inv. For each (addr, Err(e)): re-queue that peer's in-flight blocks.

3. We need to handle "putting the peer back" when we're done with it for a round—but with long-lived tasks, the peer stays in the task. So we don't remove peers during block sync; we spawn receive tasks for the peers we have at the start of each "receive round" and let them run until timeout or error. Clarify: do we run one "round" (drain peers, spawn tasks, collect until all timeout) or keep tasks running for the whole block sync?

4. Consider: PeerManager maintains N connections. Block sync could request "give me all peers" at the start of a round, spawn N receive tasks, process until we've received from all (or a global timeout), then add peers back. Document the design before implementing.
```

---

## Step 4: Reduce Debug Logging ✅ IMPLEMENTED

**Goal:** Cut down noisy logs that can slow sync and obscure progress.

**Implementation:**
- Per-message debug logs moved behind `OUROBOROS_VERBOSE=1` env var
- Batch logging: every 50 blocks logs `[block-sync] Received N blocks` (when not verbose)
- Error logs and important state changes kept (Re-queued, timeout, etc.)

**Cursor prompt:**
```
In ferrous-utils/sync/src/network/block_sync.rs, there are many eprintln! calls for every block and message received. This can slow sync and flood the terminal. 

1. Remove or reduce the per-message debug logs (e.g. "[block-sync] Received 'block' from X").
2. Keep error logs and important state changes (e.g. "Re-queued N blocks from disconnected peer").
3. Consider adding a log level or --verbose flag so debug logging can be enabled when needed.
4. Keep "Received block at height X from Y" only when verbose, or batch-log every N blocks (e.g. "Received 50 blocks (heights 0-49)").
```

---

## Step 5: Verify Progress Bar During Block Sync ✅ IMPLEMENTED

**Goal:** Ensure the progress bar shows blocks/s and percentage during block download.

**Implementation:**
- Rolling-window speed: uses last 10 seconds of block timestamps for responsive blocks_per_second (was: average from sync start)
- progress_cache updated after each block via update_progress(); Python sync_manager polls every 1s
- Flow documented in update_progress() and compute_progress()

**Cursor prompt:**
```
Verify block sync progress reporting in ferrous-utils/sync:

1. In block_sync.rs, when update_progress() is called after each block is stored, does compute_progress() correctly calculate blocks_per_second? Trace the flow: stats.blocks_downloaded, stats.last_update, elapsed time.

2. In lib.rs get_sync_progress(), we use block_sync.get_progress_stats() for blocks_per_second. Is the progress_cache updated frequently enough? The Python sync_manager polls every 1 second—does it get stale data?

3. Add a test: during sync, print get_progress_stats() every 2 seconds from a separate task and verify blocks_per_second is non-zero when blocks are being received.
```

---

## Verification

After implementing any step, run:

```bash
cd /home/max/hashhog/ouroboros
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync --reset
```

**Target metrics:**
- Block rate: **100+ blocks/minute** (1.5+ blocks/s)
- Full testnet4 sync (~122k blocks): **~2–4 hours** on a good connection

---

## References

- `BLOCK_SYNC_IMPROVEMENTS.md` – Issues 1–5 and their implementations
- `ferrous-utils/sync/src/network/block_sync.rs` – Main sync logic
- Bitcoin Core: `-maxblocksinflight` (default 16 per peer), concurrent block fetch
