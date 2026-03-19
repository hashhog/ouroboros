# Sync Recommendations – 2026-02-12

Based on `sync-20260212-0505.log` and `SYNC_LOG_ANALYSIS_20260212.md`.

---

## Corrected Log Summary

| Metric | SYNC_LOG_ANALYSIS | Actual (from log) |
|--------|-------------------|-------------------|
| Run duration | ~28 min | **~65 min** (10:05–11:10) |
| Blocks received | ~64k | **102,750** (~84% of 122,279) |
| Desyncs since start | ~32 | **1,123+** (final warning) |
| "No peers >5 min" warnings | 1 stall | **30 warnings** (recurring stalls) |
| Log lines | ~82k | **154,349** |
| "Requested block" DEBUG lines | — | **146,337** (95% of log) |

---

## Recommendations

### 1. Enable Magic Resync (No Code Change)

**Problem:** 1,123+ desync events (InvalidMagic / PayloadSizeExceeded) caused peer disconnects and 30 "No peers" stalls. Each desync drops the peer; with `OUROBOROS_TRY_RESYNC=1`, the code can resync on the stream instead of disconnecting.

**Action:** Run sync with resync enabled:

```bash
OUROBOROS_TRY_RESYNC=1 OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-verify sync 2>&1 | tee sync-resync.log
```

**Expected:** Fewer disconnects, fewer "No peers" stalls, faster recovery.

---

### 2. Reduce Block-Request DEBUG Verbosity (Code Change)

**Problem:** 146,337 "Requested block X from Y" lines dominate the log (95%). Makes analysis slow and logs huge.

**Recommendation:** Log block requests at batch/summary level only, or gate behind a separate trace level.

**Cursor prompt:**

```
In ferrous-utils/sync/src/network/block_sync.rs, the "Requested block X from Y" DEBUG log is emitted for every individual block request. This creates ~150k lines for a full testnet4 sync. Change it so that:
- Either: Log only when a batch of N requests is sent (e.g. "Requested blocks A-B from peer" at batch boundaries)
- Or: Use trace!() instead of debug!() for individual requests so they only appear with RUST_LOG=sync=trace
- Keep the "Sent N block requests" (or equivalent) summary log at DEBUG
```

---

### 3. No Other Fixes Required

Per `BLOCK_SYNC_FIX_GUIDE.md` and `SYNC_LOG_ANALYSIS_20260212.md`:

- ✓ Re-check peers before sleep (Issue 2)
- ✓ Desync blacklist 120s (Issue 3)
- ✓ Peer targets 10/12/125 (Issue 4)
- ✓ Hardcoded testnet4 peers (Issue 5)
- ✓ Desync counter in "No peers" warning (Issue 6)

These are implemented and helping. The main actionable change is **#1 (use TRY_RESYNC)** and optionally **#2 (reduce log noise)**.

---

## Verification Steps

1. **With TRY_RESYNC:**
   - Run full sync with `OUROBOROS_TRY_RESYNC=1`
   - Compare: desync count at end, number of "No peers >5 min" warnings, total sync time
   - Expect: lower desync impact, fewer stalls

2. **Log verbosity (if #2 applied):**
   - Run 10–15 min, confirm DEBUG log is readable without per-request spam
   - Confirm batch/summary logs still show progress

---

## Summary

| Priority | Action | Effort | Impact |
|----------|--------|--------|--------|
| 1 | Run with `OUROBOROS_TRY_RESYNC=1` | None (env var) | High – reduce desync disconnects |
| 2 | Reduce "Requested block" log verbosity | Low (code) | Medium – smaller logs, easier analysis |
| 3 | — | — | No other changes needed |
