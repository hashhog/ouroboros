# Ouroboros: Bugs, Improvements, and Recommendations

This document addresses issues observed from sync runs, including terminal output showing:

- `Block request timed out for height X, re-queuing` (flooding)
- `Payload size exceeds limit: 3683234585 > 33554432`
- `Invalid magic bytes: expected 283f161c, got 99399e48`
- `Headers don't connect: first header prev_blockhash X != best block hash Y`
- Progress bar stuck at `0% • 0 • 0.0 blocks/s • -:--:--`
- `No peers available, waiting...` (sync stalling)
- `Error receiving from X: Message error: ...` (repeated)

Each section includes implementation steps and Cursor prompts.

---

## Issue Summary

| Issue | Severity | Root Cause Hypothesis |
|-------|----------|----------------------|
| Payload size / Invalid magic bytes | **Critical** | Stream desync: reading from wrong byte offset after partial read or peer corruption |
| Progress bar stuck at 0% | **High** | Blocks received but not validated/stored; or best_block not updated |
| Block timeout flooding | Medium | Batched logging may not be in active code path; or old build |
| Headers don't connect | High | Corrupted chainstate or wrong network; needs --reset |
| Sync stall (no peers) | High | All peers disconnect; recovery logic may not connect to good peers in time |
| Excessive error logging | Medium | Desync errors still printed despite suppression (or verbose on) |

---

## Step 1: Diagnose and Fix Stream Desynchronization (Payload/Magic Errors)

**Goal:** Eliminate or drastically reduce "Payload size exceeds limit" and "Invalid magic bytes" errors that cause peer disconnects and sync failure.

**Current behavior:** Peers send valid Bitcoin P2P messages; after reading a block (large payload), the next read may interpret block payload bytes as a message header. This yields garbage `payload_size` values (e.g., 3.6e9) and wrong magic bytes.

**Root cause:** After reading a 24-byte header + payload_size bytes, if:
- The stream was truncated
- We read fewer bytes than expected
- The peer sent additional data before we finished reading

…then the next `receive_message` call starts reading from the middle of a payload instead of a new header.

**Solution approach:**
1. **Strict framing:** On any parse error (invalid magic, payload_size > max), close the connection immediately and do not retry reads on that stream.
2. **Early sanity check:** If `payload_size > 4_000_000` (4MB), treat as invalid before the 32MB check—Bitcoin blocks are rarely > 2MB.
3. **Blacklist bad peers:** Don't reconnect to peers that sent desync-inducing data for a cooldown period.
4. **Verify disconnect propagation:** Ensure `state = Disconnected` and the peer task exits; no further reads.

**Files to modify:**
- `ferrous-utils/sync/src/network/peer.rs` – receive logic, disconnect on parse error
- `ferrous-utils/sync/src/network/messages.rs` – payload size sanity
- `ferrous-utils/sync/src/network/peer_manager.rs` – optional peer blacklist

**Cursor prompt:**
```
We see massive "Payload size exceeds limit: 3683234585 > 33554432" and "Invalid magic bytes" 
during block sync. These indicate stream desync—we're reading from the wrong offset.

1. In peer.rs receive_message/receive_message_internal: On MessageError::PayloadSizeExceeded 
   or InvalidMagic, immediately set state=Disconnected and return Err. Do not attempt further 
   reads—the stream is corrupted.

2. In messages.rs Message::deserialize: Add early check: if payload_size > 4_000_000 before 
   reading payload, return PayloadSizeExceeded. Bitcoin blocks are rarely > 2MB; values in 
   the billions are garbage.

3. Verify that when we return Err from receive_message, the peer task in block_sync exits and 
   sends PeerDone(Error). The peer must not be reused for further reads.

4. Optionally in peer_manager: Add a simple peer blacklist (SocketAddr + timestamp) for peers 
   that caused PayloadSizeExceeded or InvalidMagic; don't reconnect for 60 seconds.
```

---

## Step 2: Fix Progress Bar Stuck at 0%

**Goal:** Progress bar shows real blocks downloaded, percentage, and blocks/s during block sync.

**Current:** Progress shows `0% • 0 • 0.0 blocks/s` even when `[block-sync] Received N blocks` appears. This suggests either:
- Blocks are received but not stored (validation/storage fails)
- `best_block` / metadata not updated when blocks are stored
- `get_sync_progress` uses `db.get_best_block()` which returns 0 if blocks aren't committed in order
- `blocks_downloaded` in progress cache not updated

**Solution:**
1. Ensure `update_progress()` is called after each successfully stored block.
2. In `get_sync_progress`, when block sync is active, use `blocks_downloaded` from progress cache as primary source for current_height, not just `db.get_best_block()`.
3. Trace: block received → validated → stored → `update_best_block` → `update_progress`. Fix any gap.
4. If blocks fail validation (e.g., "headers don't connect" or bad prev_blockhash), log why and ensure we don't silently skip updates.

**Files to modify:**
- `ferrous-utils/sync/src/network/block_sync.rs` – where blocks are stored, call `update_progress`
- `ferrous-utils/sync/src/lib.rs` – `get_sync_progress` to prefer block_sync stats

**Cursor prompt:**
```
Progress bar shows 0% • 0 blocks • 0.0 blocks/s during block sync, but we see 
"[block-sync] Received N blocks" in logs. So blocks are received but progress doesn't update.

1. In block_sync.rs: Find where we store a block to the database. Ensure update_progress() 
   is called after each successful store. Verify blocks_downloaded in progress_cache is 
   incremented.

2. In lib.rs get_sync_progress: When block_sync is active and has progress_cache, use 
   blocks_downloaded (from get_progress_stats) for current_height. Use max(blocks_downloaded, 
   db.get_best_block().1) to handle both phases. Use total_to_download for total_height.

3. Trace the flow: process_incoming_block → validate → store_block → update_best_block. 
   Confirm we update best_block when we store blocks, and that blocks are actually being 
   stored (not failing validation silently).
```

---

## Step 3: Verify Batched "Block Request Timed Out" Logging

**Goal:** Ensure timeout messages are batched, not one line per block.

**Current:** Code in `block_sync.rs` (main sync loop) batches timeouts:
`"Block request timed out for N block(s) (heights X-Y), re-queuing"`. If user still sees per-block messages, either:
- They're running an old build
- There's another code path (e.g., `download_block_parallel` + `handle_timeout`) that logs per-block
- A different component logs timeouts

**Solution:**
1. Search for all `"Block request timed out"` or `"re-queuing"` strings.
2. Ensure only the batched message is emitted.
3. Add `maturin develop` / rebuild step to docs so users get latest Rust changes.

**Cursor prompt:**
```
User still sees individual "Block request timed out for height X, re-queuing" lines. 
The main sync loop in block_sync.rs has batched logging. Find all places that log 
timeout or re-queue messages.

1. Grep for "Block request timed out", "re-queuing", "timed out" in block_sync.
2. Ensure the only timeout log is the batched one: "Block request timed out for N block(s) 
   (heights X-Y), re-queuing". Remove or consolidate any per-block logs.
3. download_block_parallel calls handle_timeout(height) per block—does handle_timeout log? 
   If so, remove or batch. The main sync loop doesn't use download_block_parallel, but 
   verify no other caller does.
```

---

## Step 4: Suppress Desync Error Log Spam

**Goal:** "Error receiving from X: Message error: Payload size exceeds limit" should not flood the console.

**Current:** `is_protocol_desync_error()` suppresses these unless `OUROBOROS_VERBOSE=1`. If they still appear, either verbose is on, or the suppression isn't applied in the right place.

**Solution:**
1. Confirm the `if is_verbose() || !is_protocol_desync_error(&e)` guard is in the peer receive loop where we log "Error receiving from".
2. Document that `OUROBOROS_VERBOSE=1` enables these logs for debugging.
3. Optionally: log the first occurrence per peer, then suppress for 60 seconds (rate-limit).

**Cursor prompt:**
```
"Error receiving from X: Message error: Payload size exceeds limit" floods the console. 
We have is_protocol_desync_error() to suppress these unless OUROBOROS_VERBOSE=1.

1. In block_sync.rs peer task loop: Verify we use 
   if is_verbose() || !is_protocol_desync_error(&e) before eprintln!("Error receiving from...").
2. If suppression is correct and user still sees logs, they may have OUROBOROS_VERBOSE=1. 
   Add a note in TROUBLESHOOTING or INSTALLATION: unset OUROBOROS_VERBOSE for quiet sync.
3. Optionally: add per-peer rate limit—log first error per peer, suppress same error for 
   that peer for 60 seconds.
```

---

## Step 5: Improve Header Sync "Headers Don't Connect" Handling

**Goal:** When headers don't connect to chain, guide user to fix instead of failing repeatedly.

**Current:** Error: `Headers don't connect: first header prev_blockhash X != best block hash Y`. Common when:
- Chainstate was corrupted or partially synced
- User switched networks without reset
- Database has wrong network data

**Solution:**
1. In the error message, explicitly suggest: "Run with --reset to clear chainstate, or verify you're using the correct network."
2. Add `--reset` flag handling to clear DB before sync if specified.
3. Document in TROUBLESHOOTING.md and INSTALLATION.md.

**Cursor prompt:**
```
When header sync fails with "Headers don't connect to chain", users don't know how to fix.

1. In header_sync.rs: When returning HeaderSyncError::HeadersDontConnect, include a hint 
   in the error string: "Try: ouroboros --network <net> sync --reset"
2. Ensure the CLI has --reset and that it clears the chainstate (or data dir) before sync.
3. Add a TROUBLESHOOTING section: "Headers don't connect" → run with --reset, confirm network.
```

---

## Step 6: Prefer IPv4 for Peer Connections (Testnet4)

**Goal:** Testnet4 has limited peers; IPv6 addresses often fail to connect. Prefer IPv4.

**Current:** DNS seeds return both IPv4 and IPv6. "Would connect to peer: [2001:...]:48333" suggests we try IPv6; many networks block or don't route IPv6.

**Solution:**
1. When sorting or selecting peer candidates, prefer IPv4 over IPv6.
2. Add env var `OUROBOROS_PREFER_IPV4=1` to force IPv4-first.
3. Optionally: filter out IPv6 from DNS results if IPv4-only mode.

**Cursor prompt:**
```
Testnet4 sync fails to connect to many peers. DNS returns IPv6 addresses that often don't 
work. Prefer IPv4.

1. In peer_manager.rs: When building the list of peer addresses to connect to, sort or 
   filter to prefer IPv4. IPv4 addresses (SocketAddr with IpAddr::V4) first, then IPv6.
2. Add OUROBOROS_PREFER_IPV4=1 to force IPv4-only (skip IPv6).
3. Log "Using IPv4-only mode" when the env var is set.
```

---

## Step 7: Add Peer Blacklisting After Desync Errors

**Goal:** Don't immediately reconnect to peers that sent garbage data.

**Current:** When a peer disconnects due to PayloadSizeExceeded or InvalidMagic, we may try to reconnect to the same peer. That peer may still be bad.

**Solution:**
1. Maintain a blacklist: `HashMap<SocketAddr, Instant>` for peers that caused desync.
2. When we disconnect due to `is_protocol_desync_error`, add peer to blacklist with expiry (e.g., 5 minutes).
3. When selecting peers to connect, skip blacklisted addresses until expiry.

**Cursor prompt:**
```
Peers that send "Payload size exceeds limit" or "Invalid magic" get disconnected but we 
may reconnect to them and get the same errors. Blacklist them temporarily.

1. In peer_manager.rs: Add a blacklist: Arc<Mutex<HashMap<SocketAddr, Instant>>>. When 
   adding a peer to drain_peers or when we learn a peer caused desync, add to blacklist 
   with Instant::now(). Expiry: 300 seconds.
2. In block_sync or peer_manager: When we get PeerDone(Error) with is_protocol_desync_error, 
   notify peer_manager to blacklist that peer.
3. When resolving/selecting peers to connect, filter out blacklisted addresses (check 
   elapsed and remove expired entries).
```

---

## Step 8: Improve "Block Not Found" / Empty Database Handling

**Goal:** First-time sync or empty DB should initialize genesis and proceed.

**Current:** "Header sync failed: Database error: Block not found" when DB is empty. Previous fixes added genesis handling in header_sync when `get_best_block()` fails.

**Solution:**
1. Ensure genesis block is initialized before header sync if DB is empty.
2. In `build_locator`, when DB is empty, use genesis hash from chain params.
3. Verify `sync_blockchain` in lib.rs initializes genesis if needed (or that header_sync does).

**Cursor prompt:**
```
First sync fails with "Block not found" when database is empty. Genesis must be 
initialized before header sync.

1. In lib.rs sync_blockchain: Before starting peer_manager and header_sync, check 
   db.get_best_block(). If Err (empty DB), store genesis block and metadata, set as 
   best block. Use chain_params::genesis_block_hash and create minimal genesis block 
   for the network.
2. In header_sync build_locator: When get_best_block fails (empty DB), return locator 
   with only genesis hash from chain_params.
3. Ensure no code path assumes get_best_block succeeds when DB can be empty.
```

---

## Step 9: Testing and Verification Recommendations

**Goal:** Provide reliable way to verify sync works.

**Recommendations:**
1. **Regtest:** Use `--network regtest` for fast local testing; no real peers needed if run with a local node.
2. **Mainnet with limit:** Add `--limit N` to sync only first N blocks for quick validation.
3. **Rebuild:** Always run `maturin develop` or `pip install -e .` after Rust changes so Python uses updated extension.
4. **Reset between runs:** When switching networks or debugging, use `--reset` to avoid stale chainstate.

**Cursor prompt:**
```
Add testing and verification guidance to the project.

1. In README or TEST_EXECUTION_GUIDE: Document that after Rust changes, run 
   `maturin develop` (or equivalent) to rebuild. Otherwise Python may use old 
   extension and fixes won't appear.
2. Add --limit N flag to sync command to sync only first N blocks (useful for 
   quick validation on mainnet).
3. Document: For reliable testing, use regtest or testnet with --reset. Testnet4 
   has fewer peers and may be flakier.
```

---

## Step 10: Structured Logging Instead of eprintln!

**Goal:** Replace `eprintln!` with proper logging (e.g., `log` crate) for levels and filtering.

**Solution:**
1. Add `log` and `env_logger` (or `tracing`) as dependencies.
2. Replace `eprintln!` with `log::warn!`, `log::info!`, `log::debug!` etc.
3. Use `RUST_LOG=warn` or `RUST_LOG=ouroboros=info` for control.
4. Map `OUROBOROS_VERBOSE=1` to `RUST_LOG=debug`.

**Cursor prompt:**
```
Replace eprintln! with structured logging for better control.

1. Add log and env_logger to Cargo.toml. Initialize env_logger in lib.rs or main.
2. Replace eprintln! in sync code: errors → log::error!, important state → log::info!, 
   debug → log::debug!. Use log::warn! for recoverable issues.
3. In Python binding init: if OUROBOROS_VERBOSE=1, set RUST_LOG=debug. Otherwise default 
   to RUST_LOG=warn for sync crate.
4. Document RUST_LOG usage in TROUBLESHOOTING.
```

---

## Implementation Priority

| Order | Step | Impact | Effort |
|-------|------|--------|--------|
| 1 | Step 1: Stream desync (payload/magic) | Critical – root cause of most failures | Medium |
| 2 | Step 2: Progress bar 0% | High – user feedback | Low |
| 3 | Step 5: Headers don't connect handling | High – clear path to fix | Low |
| 4 | Step 3: Verify batched timeouts | Medium – reduce noise | Low |
| 5 | Step 4: Suppress desync spam | Medium | Low |
| 6 | Step 6: Prefer IPv4 | Medium – Testnet4 reliability | Low |
| 7 | Step 7: Peer blacklisting | Medium – avoid bad peers | Medium |
| 8 | Step 8: Block not found / genesis | High if still occurring | Low |
| 9 | Step 9: Testing recommendations | Documentation | Low |
| 10 | Step 10: Structured logging | Long-term maintainability | Medium |

---

## Verification Checklist

After implementing:

- [ ] Run `maturin develop` to rebuild after Rust changes
- [ ] Sync with `--network testnet4 --reset` or `--network regtest`
- [ ] Progress bar shows non-zero blocks and blocks/s
- [ ] Payload/magic errors are rare or suppressed (unless verbose)
- [ ] "Block request timed out" appears batched
- [ ] "Headers don't connect" suggests --reset in error message
- [ ] Sync completes or makes measurable progress without flooding logs
