# Block Sync Fix Guide: Testnet4 Issues and Optimizations

This document provides step-by-step guidance and Cursor prompts to fix the issues identified during the full testnet4 sync run (122k blocks in ~14.5 hours, ~2.3 blocks/sec vs Bitcoin Core's ~21 blocks/sec for mainnet).

---

## Reference: Bitcoin Core Source (in `bitcoin/`)

| Topic | Bitcoin Core Path | Key Concepts |
|-------|------------------|--------------|
| Message header | `bitcoin/src/protocol.h` | CMessageHeader: 4 magic + 12 command + 4 size + 4 checksum = 24 bytes |
| V1 transport | `bitcoin/src/net.h` (lines 374–453), `bitcoin/src/net.cpp` (715–833) | Buffered incremental header reading, hdrbuf, readHeader/readData |
| Size limits | `bitcoin/src/net.h` line 65, `bitcoin/src/net.cpp` 756–759 | MAX_PROTOCOL_MESSAGE_LENGTH = 4MB; reject if hdr.nMessageSize exceeds |
| Header split test | `bitcoin/test/functional/p2p_invalid_messages.py` test_buffer() | Message with header split across two buffers is received correctly |
| Peer connection params | `bitcoin/src/net.h` | MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8, DEFAULT_MAX_PEER_CONNECTIONS=125 |

---

## Issue 1: Stream Desync (PayloadSizeExceeded / InvalidMagic)

**Observed:** 11,914 PayloadSizeExceeded + 1,899 InvalidMagic in one full sync.

**Root cause:** Bytes in the TCP stream are read as a message header when we're not aligned with the protocol (e.g. in the middle of block payload). That yields bogus payload sizes or invalid magic.

**Bitcoin Core approach:** `V1Transport` in `net.cpp` uses incremental buffered reading:
- `hdrbuf` (24 bytes) + `nHdrPos` to accumulate header bytes across multiple `ReceivedBytes()` calls
- Only deserializes when the full header is received
- Handles TCP fragmentation; see `bitcoin/src/net.cpp` lines 727–767

**Our approach:** `peer.rs` uses `read_exact()` – a single blocking read for 24 bytes. That is fine when the stream is aligned. Desync can occur when:
- A previous read consumed only part of the payload (e.g. connection closed mid-block)
- Peer sends malformed or overlapping messages

### Step 1.1: Audit the receive path for partial consumption ✓ IMPLEMENTED

Before changing behavior, confirm that header and payload are always fully consumed or the connection is closed on error.

**Implemented:** Inline audit comments in `receive_message_internal()` document bytes consumed in each error path (header read, PayloadSizeExceeded, payload read failure, deserialize failure, success).

### Step 1.2: Add optional magic-byte resync on desync ✓ IMPLEMENTED

When we detect desync (e.g. PayloadSizeExceeded with obviously invalid size), try to resync by scanning for the network magic bytes in the stream instead of discarding the connection immediately.

**Implemented:** `try_magic_resync()` in peer.rs scans for 4-byte magic (little-endian) byte-by-byte, capped at 1MB. Invoked on PayloadSizeExceeded or InvalidMagic when `OUROBOROS_TRY_RESYNC=1`. Enable with `OUROBOROS_TRY_RESYNC=1`.

### Step 1.3: Validate magic before reading payload ✓ IMPLEMENTED

Bitcoin Core validates the checksum after the full payload has been read. Our `Message::deserialize` performs validation too. Ensure we never treat payload as consumed before validation – we already read the full payload before deserialize, so this is about confirming we don’t advance on partial/corrupt reads.

Early magic check in `receive_message_internal()` right after `read_exact(header)`; rejects invalid magic before payload allocation/read.

---

## Issue 2: No-Peers Wait Logic

**Observed:** 1,787 "No peers available" waits; peers can become available during the 1s→2s→5s→10s backoff, but we sleep for the full duration before re-checking.

### Step 2.1: Re-check for peers before sleeping the full backoff ✓ IMPLEMENTED

**Implemented:** After `maintain_connections()`, we now call `drain_peers()` again before sleeping. If peers are available, we skip the sleep and spawn them immediately. Only sleep when re-checked and still no peers.

---

## Issue 3: Desync Blacklist Duration

**Observed:** Peers that hit PayloadSizeExceeded are blacklisted for 5 minutes (DESYNC_BLACKLIST_SECS). When many peers desync at once, recovery is delayed until blacklist entries expire.

### Step 3.1: Reduce desync blacklist or make it configurable ✓ IMPLEMENTED

**Implemented:** Default reduced to 120s (2 min). Configurable via `OUROBOROS_DESYNC_BLACKLIST_SECS`. Added comment that Bitcoin Core disconnects without blacklisting; ours is a conservative measure.

---

## Issue 4: Peer Count and Connection Targets

**Observed:** Often down to 1–2 peers; when they disconnect, sync stalls until `maintain_connections` refills.

**Bitcoin Core:** MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8, up to 125 total.

### Step 4.1: Increase target/min peers for block sync ✓ IMPLEMENTED

**Implemented:** Defaults increased to min_peers=10, target_peers=12. max_peers raised from 50 to 125 (matches Bitcoin Core DEFAULT_MAX_PEER_CONNECTIONS). Configurable via `OUROBOROS_MIN_PEERS`, `OUROBOROS_TARGET_PEERS`, and `OUROBOROS_MAX_PEERS`.

---

## Issue 5: Add Hardcoded Testnet4 Peers

**Observed:** Testnet4 has fewer DNS seeds; adding fallback addresses improves robustness.

### Step 5.1: Add testnet4 seed addresses from Bitcoin Core ✓ IMPLEMENTED

**Implemented:** Added 8 IPv4 hardcoded peers from `bitcoin/contrib/seeds/nodes_testnet4.txt`: 5.182.4.106, 18.189.156.102, 51.158.61.33, 103.165.192.207, 104.237.131.138, 35.201.167.154, 38.102.86.40, 89.166.29.73 (port 48333).

---

## Issue 6: Logging and Observability

**Observed:** Many desync events at DEBUG level; could add simple metrics for debugging.

### Step 6.1: Add desync rate counter (optional) ✓ IMPLEMENTED

**Implemented:** Atomic `desync_count` in BlockSync, incremented on PayloadSizeExceeded/InvalidMagic. Logged in the "No peers available for >5 minutes" warning: `(N desyncs since start)`.

---

## Implementation Order

| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| 1 | No-peers re-check before sleep (2.1) | Low | Reduces idle time when peers appear |
| 2 | Desync blacklist reduction (3.1) | Low | Faster recovery after mass desync |
| 3 | Increase target peers (4.1) | Low | More redundancy |
| 4 | Add hardcoded testnet4 peers (5.1) | Low | Better fallback connectivity |
| 5 | Audit receive path (1.1) | Medium | Ensures correct consumption model |
| 6 | Magic-byte resync (1.2) | High | Potential large reduction in desync impact |
| 7 | Logging/metrics (6.1) | Low | Better observability |

---

## Verification

After changes:

1. Run sync with verbose logging:
   ```bash
   OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-verify sync
   ```

2. Compare:
   - Count of PayloadSizeExceeded + InvalidMagic (should decrease, especially if resync is enabled)
   - Count of "No peers available" and total stall time
   - Time to sync 122k blocks (target: under ~4 hours with fixes)

3. Run a short test (e.g. 10–15 min) and check that sync progress and peer churn look reasonable.

---

## Summary of Bitcoin Core Differences

| Aspect | Bitcoin Core | Ouroboros (current) |
|--------|--------------|---------------------|
| Header reading | Buffered, incremental (hdrbuf) | Single read_exact(24) |
| Desync on error | Disconnect, discard buffer | Disconnect, no resync |
| Max message size | 4MB (MAX_PROTOCOL_MESSAGE_LENGTH) | 4MB sanity, 32MB protocol |
| Peer targets | 8 outbound full relay, 125 max | 10 min, 12 target, 125 max ✓ |
| Size check | Before reading payload | Before reading payload ✓ |
