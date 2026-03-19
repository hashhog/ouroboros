# Ouroboros Sync Analysis (2026-02-13)

Analysis from running sync with `OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug` and identifying bottlenecks and improvements.

---

## Executive Summary

| Phase | Time | Bottleneck | Potential Improvement |
|-------|------|------------|----------------------|
| Header sync | ~2 min | Sequential GetHeaders (1 at a time) | Limited - chain dependency requires ordering |
| Block sync (0-50k) | ~15-20 min | Network + peer capacity | Tuned via env vars |
| Block sync (50k+) | Often slows | Peer exhaustion, timeouts | OUROBOROS_MAX_IN_FLIGHT=64 helps |

---

## 1. Header Sync

**Observed:** 122,395 headers in ~1 min 43 sec (~1,200 headers/sec). Sequential request-response pattern.

**Flow:**
- Request 2000 headers from peer A → wait 2-8s (RTT + peer processing)
- Validate, save to DB
- Request next 2000 from peer B (or same)
- Repeat

**Why not parallel:** Each batch's locator depends on the previous batch being saved. We build the locator from `get_block_hash_by_height(current_height)`. So we cannot request batch N+1 until batch N is validated and stored.

**Quick win:** Already at 2000/request (Bitcoin max). No simple parallelization without significant redesign.

---

## 2. Block Sync

**Observed (fresh sync):** ~50-70 blocks/s initially. Good throughput with 64 in-flight, 12 peers.

**Flow:**
- Fill queue with heights 0..122394
- Assign 64 blocks to peers (round-robin)
- Spawn per-peer receive tasks that send blocks to event channel
- Main loop: process events (store block, update stats), reassign, check timeouts

**Findings:**

1. **Blocks stored without validation** in main receive path (`sync_blocks` RecvEvent::Message). Validation (`validate_block`) exists but is only used in `process_received_block` / `download_block_parallel` code paths. The main sync loop stores directly for speed. *Security note: Rust tx validator has placeholder signature check.*

2. **Event processing:** 500ms timeout on `event_rx.recv()` - when no event for 500ms, we break and do assignments/timeouts. Fine for responsiveness.

3. **Peer disconnects:** One peer ("Connection closed") immediately when block sync started. Background task reconnects peers. Normal.

4. **Progress display:** Uses `blocks_downloaded` from stats, updated after each block stored. May show momentary lag during rapid receive.

---

## 3. Slowness Around Block 50k

**Observed in user runs:** Throughput drops from 70-80 blocks/s to 1-2 blocks/s around height 50,000-52,000.

**Root causes (from prior analysis):**
1. **Peer exhaustion** - Desyncs/timeouts remove peers; testnet4 has limited pool
2. **Overload** - 128 in-flight across few peers → each peer handles many requests → slow delivery → timeouts
3. **Re-queue churn** - Timed-out blocks re-queued, reassigned to same overloaded peers

**Mitigations (implemented):**
- `OUROBOROS_IN_FLIGHT_TIMEOUT_SECS=120` (was 60) - fewer re-queues
- `OUROBOROS_MAX_IN_FLIGHT=64` (was 128) - less pressure per peer
- `OUROBOROS_DESYNC_BLACKLIST_SECS=30` (was 120) - faster peer recovery
- `OUROBOROS_TRY_RESYNC=1` - recover from some desyncs without disconnect
- `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=180` - longer for large blocks

---

## 4. Recommendations

### Immediate (env vars)

```bash
OUROBOROS_MAX_IN_FLIGHT=64 \
OUROBOROS_IN_FLIGHT_TIMEOUT_SECS=120 \
OUROBOROS_DESYNC_BLACKLIST_SECS=30 \
OUROBOROS_TRY_RESYNC=1 \
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=180 \
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

### When Still Slow

Try `OUROBOROS_MAX_IN_FLIGHT=32` to reduce peer load further.

### Implemented (2026-02-13)

5. **Per-peer request cap** - Max 16 blocks in-flight per peer. When we have few peers (e.g. 3), each gets at most 16 requests instead of 64/3=21. Reduces overload on slow peers.

6. **Avoid re-assigning to same peer** - When a block times out, the failed peer is recorded. On re-queue, that block is assigned to a *different* peer, breaking the cycle of repeatedly hitting the same slow/unresponsive peer.

7. **Diagnostic mode** - `OUROBOROS_SYNC_DIAG=1` logs every 60s: peer count, in-flight total, per-peer breakdown, queue size, blocks/s, desync count. Use to identify peer exhaustion or one peer being overloaded.

### Future Improvements (not yet implemented)

1. **Parallel header sync** - Complex; would require prefetching and out-of-order validation
2. **Block validation** - Main sync path stores without full validation; add optional `--validate` flag for security vs speed tradeoff

---

## 5. Files Reference

| File | Purpose |
|------|---------|
| `ferrous-utils/sync/src/network/header_sync.rs` | Sequential GetHeaders loop |
| `ferrous-utils/sync/src/network/block_sync.rs` | Block download, event loop, timeouts |
| `ferrous-utils/sync/src/network/peer_manager.rs` | Peer connections, desync blacklist |
| `BLOCK_SYNC_DEBUGGING_GUIDE.md` | Env var reference, debugging steps |
