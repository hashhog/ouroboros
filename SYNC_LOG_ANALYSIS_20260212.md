# Sync Log Analysis – 2026-02-12

Analysis of `sync-20260212-0505.log` (testnet4, ~82k lines, ~28 min run).

---

## Summary

| Metric | Value |
|--------|-------|
| Header sync | Completed (best_height=122,279) |
| Block sync | Started, reached ~64k blocks stored |
| InvalidMagic events | ~32 |
| Peer disconnections (total) | ~1,230 |
| Mass desync | ~50 peers at 10:16:06 |
| "No peers" stall | ~2 min (10:16:39–10:18:17) |

---

## 1. "Blocks Being Redownloaded" – Expected Behavior

**Observation:** Sync starts at block 0 with `queue_size=122,280` despite `best_height=122,279`.

**Explanation:** This is correct. Header sync stores only headers (metadata), not full blocks. Block sync must download all block payloads once. The queue of 122,280 blocks is the full chain. You are not re-downloading blocks that were already stored; you are filling in block data for heights that previously had headers only.

**Flow:**
- Header sync: stores height→hash in BLOCK_INDEX_CF, updates best_block
- Block sync: for each height, `get_block_by_height` returns None (no block data yet)
- All heights 0..122279 are queued for download
- As blocks are received and validated, they are stored and stay stored

---

## 2. "Go Back to 50,000" – Clarification

**"Received X blocks" is a count, not a height.** Log messages like:

```
[block-sync] Received 50000 blocks
[block-sync] Received 50500 blocks
```

mean “50,000 blocks stored so far” and “50,500 blocks stored so far”, i.e. forward progress.

The log interval is every 50 blocks (`BATCH_LOG_INTERVAL=50`), so you see 50, 100, 150, … 50000, 50500, etc.

There is no observed “restart” or rollback to height 50,000 in this run.

---

## 3. Mass Desync and Peer Drought

**Timeline around 10:16:06:**
- Many peers hit InvalidMagic at nearly the same time
- ~50 peer disconnections in a short window
- Desync causes blacklisting (120s with current config)
- All peers were effectively blacklisted
- **"No peers available for >5 minutes (50 desyncs since start)"**
- Sync stalled ~2 minutes until blacklist entries expired and new connections were made
- Sync resumed around 10:18:17

**Cause:** InvalidMagic means the parser read bytes that were not a valid message header (e.g. from the middle of a block). That is consistent with stream desync, often under load or with fragmented TCP.

---

## 4. Desync Count vs Baseline

| Run | InvalidMagic + PayloadSizeExceeded |
|-----|-----------------------------------|
| Prior full sync | ~13,813 (11,914 + 1,899) |
| This run | ~32 |

The current run has far fewer desync events, which suggests earlier fixes (early magic check, fewer peers hitting bad paths) are helping.

---

## 5. Recommendations

### Enable magic-byte resync

```bash
OUROBOROS_TRY_RESYNC=1 OUROBOROS_VERBOSE=1 RUST_LOG=sync=debug ouroboros --network testnet4 --data-dir .ouroboros-testnet4-verify sync 2>&1 | tee sync-resync.log
```

`OUROBOROS_TRY_RESYNC=1` enables scanning for magic bytes instead of disconnecting on InvalidMagic. That can recover from desync without dropping peers.

### Keep existing behavior for now

- Re-check peers before sleep (Issue 2): already implemented
- Shorter blacklist (Issue 3): 120s
- More peers (Issue 4): 10–12 target, 125 max
- Hardcoded testnet4 peers (Issue 5): 8 fallbacks

All are active and appear to be helping.

### Monitor for mass desync

During the stall, the new metric was logged:

```
No peers available for >5 minutes (50 desyncs since start)
```

Use this to correlate peer droughts with desync events. If you see high desync counts during stalls, enabling `OUROBOROS_TRY_RESYNC=1` is especially useful.

---

## 6. Peer Disconnections

~1,230 disconnect events in the log. These include:

- **InvalidMagic** (~32): stream desync
- **Connection closed**: remote peer closed
- **Re-queued blocks**: in-flight requests for disconnected peers are re-queued for other peers

Re-queuing is intended: when a peer disconnects, its pending requests are retried on other peers. Blocks already stored are not requested again.

---

## 7. Optimization Ideas

1. **Use `OUROBOROS_TRY_RESYNC=1`** to reduce disconnects from desync.
2. **Avoid logging every block request** at DEBUG to shrink log size; keep summaries (e.g. “requested N blocks”) or log only on batch boundaries.
3. **Throttle or stagger GetData** if you suspect overload when many peers send large blocks at once.
4. **Consider longer receive timeout** for slow links if timeouts appear in logs; current default is 120s.

---

## 8. Next Steps

1. Run again with `OUROBOROS_TRY_RESYNC=1` and compare desync/stall counts.
2. Let a full sync run complete (up to ~122k blocks) to confirm end-to-end behavior.
3. Compare total sync time and number of stalls with and without resync enabled.
