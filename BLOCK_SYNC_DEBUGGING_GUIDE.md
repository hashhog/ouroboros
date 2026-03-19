# Block Sync Debugging Guide

This document helps debug slow block sync, peer connection issues, and related problems. The project is based on [Bitcoin Core](https://github.com/bitcoin/bitcoin); many concepts and fixes are derived from there.

---

## Common Issues and Quick Checks

### 1. ETA Shows Absurd Value (e.g. "5124095576030431h")

**Cause:** When download speed is very low (e.g. 0.0001 blocks/s), `remaining / speed` produces a huge ETA. The value may also overflow when cast to `u64`.

**Fix (applied):** ETA is capped at 999 hours in `lib.rs`; CLI shows "ETA: —" when capped. If speed is 0, `block_sync` uses `f64::MAX` which gets capped to 999h.

**Code location:** `ferrous-utils/sync/src/lib.rs` — `eta_seconds` capping; `cli.py` — "ETA: —" when ≥999h.

---

### 2. Sync Stuck / No Progress for Minutes

**Symptoms:**
- "No peers available for >5 minutes"
- Blocks count not increasing
- "Connection closed", "early eof", "Invalid peer state"

**Possible causes:**
- All peers disconnected and not reconnecting
- DNS seeds not resolving (Testnet4 has fewer seeds)
- Firewall blocking outbound 48333 (testnet4) or 8333 (mainnet)
- Peers banning our node (misbehavior, wrong protocol)

---

### 3. Peer Connection Errors

| Error | Meaning |
|-------|---------|
| `Connection closed` | Peer closed the connection |
| `early eof` | Connection closed mid-message |
| `Invalid peer state: expected Connected, got Disconnected` | Using peer after it disconnected |
| `Read payload error` | Incomplete/corrupt message |

**Bitcoin Core reference:** See `src/net_processing.cpp` for peer disconnect handling and `src/net.cpp` for connection logic.

---

## Debugging Steps

### Step 1: Enable Verbose Logging

```bash
OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

This shows:
- Peer connect/disconnect
- Block request/response
- DNS resolution
- Timeout and retry behavior

### Step 2: Check Network Connectivity

```bash
# Test DNS resolution for testnet4 seeds
nslookup seed.testnet4.bitcoin.sprovoost.nl
nslookup seed.testnet4.wiz.biz

# Test outbound port (testnet4 uses 48333)
nc -zv seed.testnet4.bitcoin.sprovoost.nl 48333
```

### Step 3: Add Hardcoded Peers (Testnet4)

Testnet4 has limited DNS seeds. Add known-good peers in `peer_manager.rs`:

```rust
// In connect_to_seeds(), hardcoded_peers for Testnet4:
Network::Testnet4 => vec![
    "seed.testnet4.bitcoin.sprovoost.nl:48333",
    "seed.testnet4.wiz.biz:48333",
    // Add more from: https://github.com/bitcoin/bitcoin/blob/master/contrib/seeds/README.md
],
```

### Step 4: Increase Peer Count and Parallelism

**Relevant files:**
- `ferrous-utils/sync/src/lib.rs` — PeerManager `max_peers` (default 50)
- `ferrous-utils/sync/src/network/block_sync.rs` — `DEFAULT_MAX_IN_FLIGHT` (128), `max_concurrent`

Bitcoin Core typically uses 8–16 outbound connections and fetches from multiple peers in parallel. More peers = more redundancy when some disconnect.

### Step 5: Inspect Block Sync Flow

When peers disconnect, block sync should:
1. Re-queue in-flight requests
2. Drain new peers from PeerManager
3. Reassign blocks to new peers

**Check:** Does `drain_peers()` return peers when all previous peers have disconnected? The background DNS/connection task may need time to resolve and connect.

### Step 6: Tune Sync Parameters via Environment Variables

When sync slows or stalls (e.g. around block 50k on testnet4), try these env vars:

```bash
# Block receive timeout (default 120s) - increase for large blocks on slow links
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=180

# In-flight request timeout before re-queueing (default 60s) - increase to reduce re-queue churn
OUROBOROS_IN_FLIGHT_TIMEOUT_SECS=120

# Max blocks requested in parallel (default 128) - reduce to 64 when peers are slow
OUROBOROS_MAX_IN_FLIGHT=64

# Desync blacklist duration (default 120s) - shorter = faster peer recovery
OUROBOROS_DESYNC_BLACKLIST_SECS=30

# Try to resync stream on InvalidMagic/PayloadSizeExceeded instead of disconnecting
OUROBOROS_TRY_RESYNC=1
```

**Example for slow/stalled sync:**
```bash
OUROBOROS_MAX_IN_FLIGHT=64 OUROBOROS_IN_FLIGHT_TIMEOUT_SECS=120 \
OUROBOROS_DESYNC_BLACKLIST_SECS=30 OUROBOROS_TRY_RESYNC=1 \
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=180 \
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

**With diagnostic logging (identify peer exhaustion):**
```bash
OUROBOROS_SYNC_DIAG=1 RUST_LOG=sync=info \
OUROBOROS_MAX_IN_FLIGHT=32 OUROBOROS_IN_FLIGHT_TIMEOUT_SECS=120 \
OUROBOROS_DESYNC_BLACKLIST_SECS=30 OUROBOROS_TRY_RESYNC=1 \
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=180 \
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

Every 60 seconds, `[sync-diag]` logs: `peers=N in_flight=M queue=Q blocks/s=X desyncs=D per_peer=[addr:count ...]`. Use this to see if you're down to 1–2 peers or one peer is overloaded.

**Avoid-failed-peer behavior:** When a block request times out, the peer that failed is recorded. On re-queue, that block is assigned to a *different* peer to avoid repeatedly hitting the same slow/unresponsive peer.

---

## Cursor Prompts for Debugging

Use these prompts in Cursor to explore and fix issues:

### Prompt 1: ETA Overflow
> "Cap the ETA display when eta_seconds exceeds 24 hours - show 'Unknown' or max 999h. The ETA comes from block_sync compute_progress and is displayed in cli.py."

### Prompt 2: Peer Reconnection
> "When block sync has no peers, it logs 'No peers available for >5 minutes'. How does it retry getting peers? Trace the flow from block_sync main loop when peer_tasks is empty to when new peers are drained. Does it proactively call maintain_connections or wait for background task?"

### Prompt 3: Add Testnet4 Peers
> "Bitcoin Core's testnet4 DNS seeds and peer discovery - search for testnet4 in contrib/seeds. Add more testnet4 peer addresses or DNS seeds to peer_manager.rs if the current seeds are unreliable."

### Prompt 4: Connection Reliability
> "When we get 'Error receiving from X: Connection closed' or 'early eof', does block sync immediately re-queue the in-flight block and try another peer? Trace the error handling in block_sync when a PeerDone with Error is received."

### Prompt 5: Parallel Downloads
> "Bitcoin Core downloads blocks from multiple peers in parallel. How many blocks do we request in parallel per peer and total? Compare our DEFAULT_MAX_IN_FLIGHT and peer assignment to Bitcoin Core's block fetch logic."

### Prompt 6: Speed Calculation
> "When sync is stuck, blocks_per_second shows 0.0 or very low. The speed uses a rolling window. If no blocks have been received recently, should we show 'paused' or different messaging? Check compute_progress in block_sync."

---

## Relevant Bitcoin Core Files

For reference when implementing fixes:

| Topic | Bitcoin Core Path |
|-------|-------------------|
| Peer connection | `src/net.cpp`, `src/net_processing.cpp` |
| Block fetch | `src/net_processing.cpp` (BlockRequest, SendBlocks) |
| DNS seeds | `contrib/seeds/`, `src/chainparams.cpp` |
| Peer eviction | `src/net.cpp` (SelectOutboundPeers) |
| Connection limits | `src/net.cpp` (MAX_OUTBOUND_FULL_RELAY) |

---

## Environment Variables Summary

| Variable | Default | Purpose |
|----------|---------|---------|
| `OUROBOROS_VERBOSE` | 0 | Set to 1 for debug logging |
| `RUST_LOG` | sync=warn | Override: sync=debug, sync=info |
| `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS` | 120 | Timeout per block receive |
| `OUROBOROS_PREFER_IPV4` | 0 | Set to 1 for IPv4-only (helps some networks) |
| `OUROBOROS_SYNC_DIAG` | 0 | Set to 1 or true: log peer count, in-flight, queue, blocks/s every 60s |
| `OUROBOROS_IN_FLIGHT_TIMEOUT_SECS` | 60 | Seconds before re-queueing timed-out block requests |
| `OUROBOROS_MAX_IN_FLIGHT` | 128 | Max concurrent block requests (cap 256) |
| `OUROBOROS_DESYNC_BLACKLIST_SECS` | 120 | How long to blacklist peers after PayloadSizeExceeded/InvalidMagic |
| `OUROBOROS_TRY_RESYNC` | 0 | Set to 1: try to resync stream on desync instead of immediate disconnect |

---

## Checklist for "Sync Stuck" Bug

- [x] Run with `OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug` and capture logs
- [x] Verify DNS seeds resolve for testnet4
- [x] Check firewall allows outbound 48333
- [ ] Add hardcoded testnet4 peers if DNS fails
- [x] Cap ETA to avoid overflow/absurd display
- [x] Trace peer reconnection when all peers disconnect
- [ ] Consider increasing `max_peers` or connection retry frequency
- [ ] Compare block request parallelism to Bitcoin Core

---

## Debugging Run Results (2026-02-11)

### Step 1: Verbose Logging

Ran: `OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-test sync`

**Findings:**
- Header sync progresses normally (~60k headers in ~60s)
- One peer disconnect observed: `136.243.173.99:48333` — "Connection closed"
- Header sync handled it: "Peer disconnected, retrying with different peer in 2 seconds..." — continued with `65.108.143.22:48333`
- New peers connect during sync (e.g. `103.99.171.207`)

### Step 2: Network Connectivity

- **DNS**: Both `seed.testnet4.bitcoin.sprovoost.nl` and `seed.testnet4.wiz.biz` resolve with many IPv4/IPv6 addresses
- **Port 48333**: `nc -zv 103.99.169.150 48333` — connected successfully

### Step 3: Peer Reconnection Flow (code trace)

When block sync peers disconnect:

1. **PeerDone(Error)** in `block_sync.rs` (line ~576):
   - `Connection closed`, `Disconnected`, `InvalidState::Disconnected` → **do not add peer back** (peer discarded)
   - `PayloadSizeExceeded`, `InvalidMagic` → blacklist + do not add back
   - Other errors (transient) → add peer back to PeerManager

2. **When peer_tasks is empty** (all peers gone):
   - `drain_peers()` returns empty
   - `maintain_connections()` is called — connects to `known_addrs` (from DNS seeds)
   - Sleep 1s→2s→5s→10s (exponential backoff), then retry
   - Background task also runs `maintain_connections` every 30s (10s when &lt; min_peers)

3. **known_addrs** is populated at startup from DNS; the background task re-resolves DNS when low on peers.

**Possible stuck scenario:** If all `known_addrs` fail to connect (banned/backoff), or DNS returns no new addresses, block sync waits with increasing backoff. Consider adding hardcoded testnet4 peers as fallback.

---

## 15+ Minute Sync Run Results (2026-02-11)

**Command:** `OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-test sync`  
**Duration:** ~16 minutes (14:06–14:22 UTC)  
**Log file:** `sync_long_run.log` (51k lines)

### Summary

| Phase     | Progress                           |
|----------|-------------------------------------|
| Header   | 72k → 122,204 (chain tip)           |
| Block    | 0 → ~49,100 blocks (~40% of chain)  |
| Throughput | ~51 blocks/sec during block sync |

### Issues Observed

1. **Frequent peer disconnects**  
   - 52+ "Re-queued X blocks from disconnected peer" events  
   - Peers frequently close connections during block sync  
   - Re-queuing works: blocks are reassigned to other peers

2. **Problematic peer: `136.243.173.99`**  
   - "Connection closed" reported 4 times  
   - Reconnects then disconnects again; consider temporary blacklisting or backoff

3. **Peer pool churn**  
   - "Spawned N long-lived peer receive tasks" logged 8 times  
   - Indicates full peer drain and reconnect cycles  
   - Recovery works: `maintain_connections` refills peers

4. **No "No peers for >5 min"**  
   - Peer recovery and `maintain_connections` keep sync progressing  
   - DNS and connection logic are functioning

### Recommendations

- Add short-term blacklist/backoff for peers that disconnect repeatedly (e.g. `136.243.173.99`)
- Consider increasing `maintain_connections` frequency when `peer_tasks` is low
- Optionally add hardcoded testnet4 peers for fallback when DNS peers are unstable

---

## Second 15+ Minute Run (2026-02-11)

**Command:** `OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-run2 sync`  
**Duration:** ~16 minutes (15:00–15:16 UTC)  
**Log file:** `sync_run2.log` (55.7k lines)

### Summary

| Phase       | Progress                                    |
|------------|----------------------------------------------|
| Header     | 0 → 122,210 (chain tip)                      |
| Block      | 0 → 51,800 blocks (~42% of chain)            |
| Throughput | ~61 blocks/sec during block sync             |

### Issues Identified

1. **Stream desync – PayloadSizeExceeded (49 events)**  
   - Reported sizes: 923MB–4.2GB, far above 4MB sanity limit  
   - Root cause: byte stream desync – header bytes read from middle of block payload  
   - Sanity check in `peer.rs` is correct; peers are blacklisted for 5 min on desync  
   - Same value (e.g. 2756587087) seen on multiple peers → likely misaligned read in block payload  

2. **Stream desync – InvalidMagic (8 events)**  
   - Same root cause: header parsed from wrong offset in stream  
   - Example: expected `283f161c`, got `4fa44e2e` (block/transaction data)  

3. **Dense disconnect cascade**  
   - 15:15:15–15:15:37: many peers disconnecting together (40+ in ~20 seconds)  
   - Probably network or shared block issue; recovery works via respawned peers  

4. **Re-spawn cycles**  
   - 10 peer spawn events; full drain and refill several times  
   - Sync kept progressing despite churn  

### Optimization Opportunities

| Area                | Current behavior                          | Suggestion                                                                 |
|---------------------|-------------------------------------------|-----------------------------------------------------------------------------|
| Desync recovery     | Disconnect + 5 min blacklist             | Optional: try to resync by scanning for magic bytes instead of immediate disconnect |
| Payload size check  | 4MB sanity limit (correct)               | No change; values like 2GB are clearly garbage                              |
| Logging             | DEBUG for PayloadSizeExceeded            | Keep DEBUG; add optional metric/counter for desync rate per peer           |
| Request batching    | 128 blocks in flight                     | Compare with Bitcoin Core’s parallel fetch; consider tuning if needed       |
| Peer respawn delay  | 1s→2s→5s→10s backoff when no peers       | Lower initial delay (e.g. 500 ms) when recovering from mass disconnects    |

### Root Cause Note

The large “payload size” values (e.g. 2.7GB) show we read block payload data as message header. That happens when the stream is misaligned, e.g. after:

- Partial reads or buffering issues  
- Peer sending malformed data  
- TCP reordering or corruption  

The 4MB limit is appropriate. Peers that trigger it are blacklisted; recovery by respawning new peers is functioning.
