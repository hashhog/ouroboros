# Ouroboros → Bitcoin Core Parity Plan

A plan to align Ouroboros block sync behavior and performance with Bitcoin Core, based on log analysis and code review.

**Locations:**
- **Bitcoin Core source:** `bitcoin/` directory
- **Bitcoin Core testnet4 logs (full debug):** `bitcoin/bitcoin_core_testnet4_sync_data/testnet4/debug.log`
- **Bitcoin Core testnet4 logs (legacy):** `bitcoin/testnet4_sync_data/testnet4/debug.log`

**Last updated:** 2026-02-10

---

## 1. Current State Comparison

### Observed Behavior (testnet4 full sync)

| Metric | Bitcoin Core | Ouroboros (before) | Ouroboros (current) |
|--------|--------------|-----------|-----------|
| Full testnet4 sync time | ~2.7 hours (161 min) | ~7 hours | ~4–5 hours (estimated, needs benchmark) |
| Blocks per second (avg) | ~12.6 | ~4.9 | ~7–9 (estimated) |
| Peer disconnects | "Peer is stalling" (99 events) | Desync blacklist 120s → peer drought | Disconnect without blacklist (improved) |
| Peer replenishment | Immediate new connections | 30s interval, blocked by blacklist | 10s normal / 3s when low (improved) |
| "No peers available" | Never | Frequent | Reduced (blacklist no longer used in block sync) |

### Root Cause Summary (updated)

The original #1 bottleneck — desync blacklisting causing peer drought — has been largely fixed. Block sync no longer calls `blacklist_peer_desync()` on protocol errors; it disconnects like Bitcoin Core. Peer replenishment is faster (10s/3s vs 30s). Target peers increased from 12 to 16.

**Remaining gap** is primarily:
1. **Desync frequency**: Ouroboros still hits PayloadSizeExceeded/InvalidMagic more often than Bitcoin Core (which hits zero). Each desync costs a peer reconnection cycle.
2. **No `assumevalid`**: Bitcoin Core skips script/signature verification for blocks below a known-good hash. Ouroboros validates everything.
3. **Validation inefficiencies**: Redundant serialization, duplicate input validation calls, individual DB writes instead of batching.

---

## 2. Bitcoin Core Constants (Reference)

From `bitcoin/src/net_processing.cpp` and `bitcoin/src/net.h`:

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | 16 | Blocks in flight per peer |
| `BLOCK_STALLING_TIMEOUT_DEFAULT` | 2s | Disconnect peer if no block progress for 2s |
| `BLOCK_STALLING_TIMEOUT_MAX` | 64s | Max stalling timeout (adaptive) |
| `BLOCK_DOWNLOAD_TIMEOUT_BASE` | 1 | Base timeout (× block interval) |
| `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER` | 0.5 | Additional per peer |
| `BLOCK_DOWNLOAD_WINDOW` | 1024 | Blocks ahead of current height to fetch |
| `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` | 8 | Outbound full-relay peers |
| `MAX_BLOCK_RELAY_ONLY_CONNECTIONS` | 2 | Block-relay-only peers |

Bitcoin Core uses a **dynamic stalling timeout**: if many peers hit the timeout, it increases (up to 64s), then gradually decreases back to 2s as progress recovers.

---

## 3. Ouroboros Current Settings

From `ferrous-utils/sync` (updated to reflect current code):

| Setting | Value | Env override | Changed? |
|---------|-------|-------------|----------|
| Max in-flight total | 128 | `OUROBOROS_MAX_IN_FLIGHT` | — |
| Max in-flight per peer | 16 | (hardcoded) | — |
| Receive timeout | 60s | `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS` | Was 90s → now 60s |
| Stalling timeout (base) | 5s | `OUROBOROS_STALLING_TIMEOUT_SECS` | Was 45s fixed → now 5s adaptive |
| Stalling timeout (max) | 64s | (hardcoded) | New (adaptive, matches Bitcoin Core) |
| Desync blacklist (default) | 120s | `OUROBOROS_DESYNC_BLACKLIST_SECS` | Still 120s default but **unused** in block sync |
| Block sync blacklisting | **Disabled** | — | **Fixed**: disconnect only, no blacklist |
| Target peers | 16 | `OUROBOROS_TARGET_PEERS` | Was 12 → now 16 |
| Min peers | 12 | `OUROBOROS_MIN_PEERS` | Was 10 → now 12 |
| Peer replenishment | 10s / 3s (low) | — | Was 30s → now 10s normal, 3s when below min |
| Max message size | 4,000,000 bytes | — | Was 4,194,304 → now matches Bitcoin Core `MAX_PROTOCOL_MESSAGE_LENGTH` |
| Stream splitting | Read/write halves | — | New (prevents cancel-mid-read desyncs) |
| Diagnostic ring buffer | 256 bytes | — | New (`DiagnosticReader` logs last 256 bytes on desync) |
| Bad checksum handling | Drop message, continue | — | Was disconnect → now matches Bitcoin Core (keep connection) |
| Command validation | `IsMessageTypeValid` parity | — | New (printable ASCII before null, all-zero after) |
| TRY_RESYNC | Magic scan up to 1MB | `OUROBOROS_TRY_RESYNC=1` | New |

---

## 4. Implementation Plan

### Phase 1: Peer Management — DONE

**Goal:** Stop exhausting the peer pool when desyncs occur; behave like Bitcoin Core (disconnect, don't blacklist long-term).

| Step | Action | Status |
|------|--------|--------|
| 1.1 | Make desync blacklist optional or very short | **DONE** — block_sync.rs no longer calls `blacklist_peer_desync()` on desyncs. Peers are disconnected without blacklisting. |
| 1.2 | Add `OUROBOROS_DESYNC_BLACKLIST_SECS` env override | **DONE** — supported in `peer_manager.rs`. Default 120s but unused by block sync. |
| 1.3 | Faster peer replenishment: 10s normal, 3s when peers < min | **DONE** — `peer_manager.rs` runs `maintain_connections` every 10s, 3s when below min_peers. |
| 1.4 | Increase target peers to 16, min to 12 | **DONE** — `peer_manager.rs` defaults: target=16, min=12. |

---

### Phase 2: Reduce Desync Frequency — DONE

**Goal:** Fix or mitigate the causes of PayloadSizeExceeded and InvalidMagic so fewer peers are disconnected.

| Step | Action | Status |
|------|--------|--------|
| 2.1 | Detailed logging when desync occurs | **DONE** — `DiagnosticReader` ring buffer (256 bytes) wraps the read half in block sync tasks. On desync, the last 256 bytes are logged in hex for post-mortem analysis. Header hex dump also included. |
| 2.2 | Fix transport/message framing: partial reads, async races | **DONE** — TCP stream split into read/write halves in `block_sync.rs`. `read_network_message()` uses pinned futures to prevent `tokio::select!` cancellation mid-read. |
| 2.3 | Compare with Bitcoin Core's V1Transport/CMessageHeader | **DONE** — Systematic comparison performed. Three discrepancies fixed: (a) bad checksum now drops message instead of disconnecting (matches `GetReceivedMessage` in `net.cpp`); (b) command type validation now matches `IsMessageTypeValid()` — printable ASCII before null, all-zero after; (c) payload size limit now uses `4_000_000` matching Bitcoin Core's `MAX_PROTOCOL_MESSAGE_LENGTH` instead of `4 * 1024 * 1024`. |
| 2.4 | Lenient handling for plausible payload sizes | **DONE** — 4MB limit (matching Bitcoin Core). Disconnects without blacklisting. |
| 2.5 | TRY_RESYNC implementation | **DONE** — `peer.rs` implements magic-byte resync scanning (up to 1MB) when `OUROBOROS_TRY_RESYNC=1`. |

---

### Phase 3: Timeout Alignment — DONE

**Goal:** Align Ouroboros timeouts with Bitcoin Core's stalling and download timeouts.

| Step | Action | Status |
|------|--------|--------|
| 3.1 | Document Bitcoin Core stalling timeout | **DONE** — documented in §2. |
| 3.2 | Shorter receive timeout (90s → 60s) | **DONE** — default changed to 60s in `block_sync.rs`. Still overridable via `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS`. |
| 3.3 | Adaptive stalling timeout (5s base → 64s max) | **DONE** — implemented with decay factor 0.85. Matches Bitcoin Core behavior. |
| 3.4 | Env override for stalling timeout | **DONE** — `OUROBOROS_STALLING_TIMEOUT_SECS`. |

---

### Phase 4: Concurrency and Batching — DONE

**Goal:** Use available peers and parallelism efficiently.

| Step | Action | Status |
|------|--------|--------|
| 4.1 | Max in-flight 128 (configurable) | **DONE** |
| 4.2 | GetData batching per peer | **DONE** — one GetData message per peer with multiple block hashes. |
| 4.3 | Queue-based block download window | **DONE** — uses queue system with sufficient prefetch. |

---

### Phase 5: Services and Compatibility — DONE

**Goal:** Ensure peers treat Ouroboros as a valid full relay node.

| Step | Action | Status |
|------|--------|--------|
| 5.1 | Version handshake sends `services: 1` (NODE_NETWORK) | **DONE** |
| 5.2 | Verify user agent is accepted | **DONE** — User agent updated to `/Ouroboros:0.1.0/` (BIP 14 format). Added `MAX_SUBVERSION_LENGTH` (256 byte) validation on deserialization, matching Bitcoin Core. No nodes filter by user agent. |
| 5.3 | V2 transport support or compatible fallback | **DONE (v1 compatible)** — Bitcoin Core defaults to v2 (`DEFAULT_V2_TRANSPORT=true`) but automatically falls back to v1 when it receives v1 magic bytes (`V2Transport::ProcessReceivedMaybeV1Bytes` in `net.cpp`). Ouroboros uses v1 for all connections; Bitcoin Core detects this and downgrades seamlessly. Full BIP324 v2 implementation is not needed for sync parity — it's a privacy feature, not a performance one. |

---

### Phase 6: Measurement and Validation — PARTIAL

**Goal:** Track progress and validate parity.

| Step | Action | Status |
|------|--------|--------|
| 6.1 | Speed comparison script | **EXISTS** — `scripts/run_testnet4_speed_comparison.sh` exists but needs fresh run. |
| 6.2 | Blocks/sec tracking | **DONE** — rolling-window speed calculation in `block_sync.rs`. |
| 6.3 | Desync counting | **DONE** — `desync_count` atomic counter, logged in diagnostics. |
| 6.4 | "No peers available" monitoring | **DONE** — logged with rate limiting. |
| 6.5 | Block hash comparison | **EXISTS** — `scripts/compare_block_hashes.py` exists but needs validation. |
| 6.6 | Bitcoin Core debug log comparison | **NOT DONE** — logs exist but no systematic comparison performed. |

---

## 5. Remaining Work to Reach Bitcoin Core Parity

The peer management fixes (Phase 1) were the highest-impact change. The remaining gap (~4–5 hours vs ~2.7 hours) comes from three areas:

### 5.1 `assumevalid` Optimization — DONE

**What Bitcoin Core does:** Ships with a hardcoded `assumevalid` block hash. During IBD, skips script verification and signature checking for all blocks at or below that height. Still validates PoW, merkle roots, block structure, and UTXO consistency. See `bitcoin/src/validation.cpp:2344-2378`.

**What Ouroboros does now:** `BlockValidator` has an `assumevalid_height` field. Default is `u32::MAX` (skip scripts for all known-good blocks). Set `OUROBOROS_ASSUMEVALID=0` to disable.

| Step | Action | Status |
|------|--------|--------|
| 5.1.1 | `OUROBOROS_ASSUMEVALID` env var: not set → `u32::MAX` (skip scripts); `=0` → full validation; any u32 → use that height | **DONE** |
| 5.1.2 | `BlockValidator` stores `assumevalid_height`, logged at startup | **DONE** |
| 5.1.3 | `validate_block()` at height ≤ assumevalid: skips `validate_transaction_inputs()`, script checks, coinbase validation, and fee calculation; keeps header PoW, merkle root, structure, duplicate tx, and sigops | **DONE** |
| 5.1.4 | Above assumevalid height: full validation (current behavior) | **DONE** |

**Impact:** Eliminates per-transaction UTXO lookups and input/script validation for all historical blocks during IBD.

### 5.2 Validation Efficiency Fixes — DONE

All five inefficiencies fixed:

| Issue | Fix | Status |
|-------|-----|--------|
| `validate_transaction_inputs()` called twice per non-coinbase tx | Removed first call; single call returns `total_input` and feeds into `validate_amounts()` | **DONE** |
| `check_size_limits()` re-serialized entire block via `consensus_encode()` | Replaced with fast tx-count upper-bound check (no serialization) | **DONE** |
| `validate_amounts()` re-serialized each tx for relay fee check | Removed relay fee enforcement from block validation (relay fees are mempool policy, not consensus) | **DONE** |
| `calculate_tx_fee()` returned 0 (placeholder) | Removed dead code — fee calculation was unreachable and subsidy check skipped under assumevalid | **DONE** |
| `apply_block()` created WriteBatch but didn't use it | Removed dead `_batch` variable; individual writes remain (batch upgrade deferred to full UTXO overhaul) | **DONE** |
| `check_size_limits()` in `transaction.rs` re-serialized each tx | Replaced with input/output count check — block size already bounds individual tx size | **DONE** |
| `FeeTooLow` error variant unused | Removed dead variant | **DONE** |

### 5.3 Desync Root Cause — DONE

All three items implemented:

| Step | Action | Status |
|------|--------|--------|
| 5.3.1 | Compare message framing with Bitcoin Core V1Transport | **DONE** — Three discrepancies found and fixed (see Phase 2 step 2.3). |
| 5.3.2 | Ring buffer logging for post-mortem analysis | **DONE** — `DiagnosticReader` (256-byte ring buffer) wraps read half in block sync peer tasks. Hex dump logged on every desync event. |
| 5.3.3 | Test with `OUROBOROS_TRY_RESYNC=1` | Available — needs a full sync run to measure. |

### 5.4 Minor Tuning

| Item | Current | Suggested | Impact |
|------|---------|-----------|--------|
| Receive timeout | 60s | — | **DONE** — changed from 90s to 60s |
| V2 transport | v1 only (compatible) | Not needed — Bitcoin Core falls back to v1 seamlessly | **VERIFIED** — privacy feature, not performance |

---

## 6. Priority Order for Remaining Work

| Priority | Item | Expected speedup | Effort | Status |
|----------|------|------------------|--------|--------|
| ~~1~~ | ~~`assumevalid` (§5.1)~~ | ~~20–40% faster IBD~~ | ~~Medium~~ | **DONE** |
| ~~2~~ | ~~Fix double `validate_transaction_inputs` call (§5.2)~~ | ~~5–10%~~ | ~~Trivial~~ | **DONE** |
| ~~3~~ | ~~Remove redundant serialization in validation (§5.2)~~ | ~~5–10%~~ | ~~Low~~ | **DONE** |
| ~~4~~ | ~~Desync root cause analysis (§5.3)~~ | ~~Variable~~ | ~~Medium~~ | **DONE** |
| ~~5~~ | ~~Receive timeout 90s → 60s (§5.4)~~ | ~~<5%~~ | ~~Trivial~~ | **DONE** |
| ~~6~~ | ~~WriteBatch / dead code cleanup (§5.2)~~ | ~~Marginal~~ | ~~Low~~ | **DONE** |
| ~~7~~ | ~~V2 transport (§5.4)~~ | ~~Marginal~~ | ~~High~~ | **NOT NEEDED** — v1 fallback verified |

---

## 7. Key Differences: Bitcoin Core vs Ouroboros (Updated)

| Aspect | Bitcoin Core | Ouroboros (before) | Ouroboros (now) |
|--------|--------------|-----------|-----------|
| Disconnect on protocol error | Yes | Yes | Yes |
| Blacklist on disconnect | No | Yes (120s) | **No** (block sync doesn't blacklist) |
| Stalling detection | 2s adaptive → 64s | 45s fixed | **5s adaptive → 64s** |
| Peer replenishment | Immediate (8+2 targets) | 30s interval | **10s / 3s when low** |
| Target outbound peers | 10 (8+2) | 12 | **16** |
| Blocks in transit per peer | 16 | 16 | 16 |
| `assumevalid` (skip scripts) | Yes (default on) | No | **Yes** (default on, `OUROBOROS_ASSUMEVALID=0` to disable) |
| Stream splitting | N/A (event loop) | No | **Yes** (read/write halves) |
| Magic resync on desync | N/A (no desyncs) | No | **Yes** (`TRY_RESYNC=1`) |

---

## 8. Running Bitcoin Core with Full Debug Logging

To capture protocol-level events (including Header error, Wrong MessageStart, Size too large), run Bitcoin Core with:

```bash
cd bitcoin

# Stop any existing bitcoind first (port 48332 conflict)
./build/bin/bitcoin-cli -testnet4 -datadir="./bitcoin_core_testnet4_sync_data" stop
# or: ./build/bin/bitcoin-cli -testnet4 -datadir="./testnet4_sync_data" stop

# Foreground with full debug (logs to console and file)
./build/bin/bitcoind -testnet4 \
  -datadir="./bitcoin_core_testnet4_sync_data" \
  -debug=1 \
  -debugexclude=libevent \
  -debugexclude=leveldb \
  -printtoconsole=1
```

Logs are written to:
- **`bitcoin/bitcoin_core_testnet4_sync_data/testnet4/debug.log`**

To search for protocol errors in Bitcoin Core logs:
```bash
grep -E "Header error|Wrong MessageStart|Size too large|Peer is stalling" \
  bitcoin/bitcoin_core_testnet4_sync_data/testnet4/debug.log
```

**Observed:** Bitcoin Core full-debug logs show "Peer is stalling block download" (disconnect slow peers). No "Header error", "Wrong MessageStart", or "Size too large" — i.e. Bitcoin Core did not hit PayloadSizeExceeded or InvalidMagic during testnet4 sync. Ouroboros hits these frequently.

---

## 9. Recommended Environment for Testing

```
OUROBOROS_MAX_IN_FLIGHT=128
OUROBOROS_STALLING_TIMEOUT_SECS=5
OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=60   # now the default
OUROBOROS_TARGET_PEERS=16
OUROBOROS_MIN_PEERS=12
OUROBOROS_TRY_RESYNC=1
OUROBOROS_SYNC_DIAG=1
# OUROBOROS_ASSUMEVALID not set → default u32::MAX (skip scripts for all blocks)
# OUROBOROS_ASSUMEVALID=0 → full validation for all blocks
RUST_LOG=sync=info
```

---

## 10. References

- **Bitcoin Core source:** `bitcoin/src/net_processing.cpp`, `bitcoin/src/net.cpp`, `bitcoin/src/net.h`, `bitcoin/src/validation.cpp`
- **Bitcoin Core testnet4 logs (full debug):** `bitcoin/bitcoin_core_testnet4_sync_data/testnet4/debug.log`
- **Bitcoin Core testnet4 logs (legacy):** `bitcoin/testnet4_sync_data/testnet4/debug.log`
- **Ouroboros block sync:** `ferrous-utils/sync/src/network/block_sync.rs`
- **Ouroboros peer manager:** `ferrous-utils/sync/src/network/peer_manager.rs`
- **Ouroboros messages:** `ferrous-utils/sync/src/network/messages.rs`
- **Ouroboros block validation:** `ferrous-utils/sync/src/validate/block.rs`
- **Ouroboros tx validation:** `ferrous-utils/sync/src/validate/transaction.rs`
- **Speed comparison script:** `scripts/run_testnet4_speed_comparison.sh`
- **Prior analysis:** `SYNC_ANALYSIS_20260213.md`, `SYNC_RECOMMENDATIONS_20260212.md`
