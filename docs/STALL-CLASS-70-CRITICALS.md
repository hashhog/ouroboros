# Stall class: 70 CRITICALs in 30 days

Diagnosed 2026-09-10T03:10Z from `fleet-monitor-history.jsonl`
(window 2026-08-11 → 2026-09-10) and the live unit
`journalctl --user -u hashhog-ouroboros-mainnet` (pid 3910893, up
since 2026-09-07 15:26Z). No genesis rig. **No fix in this commit** —
there is not yet an in-repo control that fails when the class is
reverted.

## What "70 CRITICALs" counts

`tools/fleet-monitor.sh` writes every tick into the JSONL unthrottled
(`all_alerts`) and pages on a 1 h `{node, kind, level}` throttle
(`ALERT_THROTTLE_S=3600`). PLAN.md's "ouroboros 70" is the throttled
count:

| 30-day ouroboros alerts | raw JSONL | 1 h throttle |
|---|---:|---:|
| CRITICAL `no_progress` | 504 | 45 |
| CRITICAL `tip_age` | 273 | 25 |
| CRITICAL `rpc_fail` | 2 | 1 |
| **CRITICAL total** | **779** | **71** |
| WARN `no_progress` / `lag` | 160 | 20 |

Zero CRITICAL `lag` (that gate is 500 blocks / 2 h). The node is not
falling hundreds of blocks behind; it **freezes a few blocks off tip
for tens of minutes to a day**.

## The 30-day timeline is two long freezes plus the class that remains

Same-tip, lag>0 episodes ≥20 min (43 of them, 79 h stuck):

| start (UTC) | end | frozen tip | max lag | duration | notes |
|---|---|---:|---:|---:|---|
| 2026-08-24 07:17 | 08-25 02:08 | 963825 | 113 | **18.85 h** | 18 throttled `no_progress` CRITICALs |
| 2026-08-26 01:39 | 08-27 01:21 | 964076 | 150 | **23.69 h** | 23 `no_progress` + 23 `tip_age`; cleared only by restart (`rpc_fail` NO_COOKIE 01:36–01:41) |
| 2026-08-28 01:12–09:02 | several | 964367–964399 | 9 | 0.3–1.7 h | the 6760 s / 22-watchdog outage named in `ce28aef` |
| 2026-08-11 … 08-22 | ~30 shorts | near tip | 4–28 | 0.3–4.3 h | most die before the 1 h CRITICAL gate |
| 2026-08-29 … 09-09 | — | — | — | — | no throttled CRITICAL (W75-RECOVER, `ce28aef` 2026-08-28, caps most stalls at ~15–50 min) |
| 2026-09-10 01:39– | 966291 then 966293 | 5 | ≥1 h | **this class, live** |

## Live signature (this boot, still wedged at diagnosis)

`getblockchaininfo`: `blocks == headers == 966293`,
`00000000000000000000c9bb7eaf869aeab4dac9949e83c42258debfa880ec20`.
Core `:8332` at 966298. `getchaintips` is a single active branch.
`getpeerinfo`: 8 outbound, 0 inbound (`--nolisten --p2p-port 0`);
every `synced_headers`/`synced_blocks` is `-1`; `inflight` is `[]`.

This process, 2026-09-07 15:26Z → 2026-09-10 03:10Z:

- **18× `[W75-RECOVER]`**, almost always `queue=1 buffer=1 in-flight=1`
  at 900–3800 s of no tip advance. Recovery #18 at 2026-09-09 22:03:36
  EDT: `tip=966291`, `queue=3 buffer=1 in-flight=4`, stale **3030 s**.
- **70× `[W75-WATCHDOG]`** (the warn that gates recover).
- **67× `[slot-misalign]`** queue drops.
- **H1 frontier getdata** this boot, by peer: **1690** to
  `116.202.56.177` (`/Satoshi:0.15.99/`, connected since boot,
  services `0xd` = NETWORK|BLOOM|WITNESS), 681 / 539 / 242 to the
  next three. A 2017-era `0.15.99` cannot serve block 966292; it
  advertises `NODE_WITNESS` so it passes `_can_serve_witness_blocks`.
- Around recovery #18 the drain loop logged
  `Drain waiting on network for 9e817abdf41f6379... (height 966292;
  queue=2–3 buffer=0 requested=2–3; no disk bytes)` while H1
  re-requested that same hash every 5 s, alternating
  `116.202.56.177` and `212.132.112.45`. `PyHeadersSyncState rejected
  batch … Header at height 966292 doesn't connect: prev_hash mismatch`
  (76 rejects this boot). Header-sync peer "stalled, switching" every
  30 s; `_catch_up` sends `getheaders` on **every** sync-loop tick
  (~1 Hz) with no empty-reply backoff.

After the 22:03 recover, 966292 connected at 22:08:36; immediately
`[slot-misalign] _prune_validated_headers dropping stale queue (4
entries)` — the remaining headers for 966293+ were thrown away and
had to be re-fetched. Tip then sat at 966293 while Core moved to
966298.

## Root cause

Near-tip **headers-first download is scheduled onto peers that will
never deliver the connect-frontier block**, and the stall-clock
treats "peer has nothing new" as "peer is dead":

1. **Header-sync stall timer only resets on an *accepted* header
   batch** (`handle_headers` ~4774–4776). An empty `headers` (normal
   at tip), an unconnecting batch, or a `PyHeadersSyncState` reject
   does not touch `_header_sync_time`. After 30 s the designated
   sync peer is dropped and `adjust_score(-2)` (`block_sync.py`
   1309–1357). At tip every honest peer trips this. Commit `80a21c8`
   stopped the *ban*; the demotion remains.

2. **H1 frontier scheduling sorts by that score**
   (`_request_next_blocks`, `FRONTIER_REQUEST_INTERVAL = 5 s`).
   Long-lived zombies that are never picked as header-sync (low
   `start_height`, so `_get_sync_peer` skips them) keep the default
   score 100 and win the sort. This boot that winner is
   `/Satoshi:0.15.99/`. `_can_serve_witness_blocks` only tests
   `NODE_WITNESS` (`e9e78a7`); it does not test `NODE_NETWORK` vs
   `NODE_NETWORK_LIMITED`, nor "does this peer actually have height
   H". Core's `CanServeBlocks` / `CanServeWitnesses` pair is the
   missing half.

3. **H1 re-issue writes `requested_blocks[hash] = now`**, so the
   size-aware `HEAD_TIMEOUT` (~34 s at 1.36 MB) never fires on the
   frontier. The 5 s rotation *is* the timeout path. Getdata to a
   peer that does not have the block is a silent no-op; the drain
   waits on `buffer=0` for 15–50 min.

4. **W75-RECOVER (`ce28aef`) is a band-aid, not a fix.** It only
   runs when *both* `_validated_headers` and `_ibd_block_buffer` are
   non-empty (watchdog preconditions). A pure download stall
   (`buffer=0`) is silent until a far-ahead body happens to land;
   that is why recovery #18 waited 3030 s, not 900 s. The reset
   drops the in-memory queue/buffer/in-flight maps; one block often
   connects; `[slot-misalign]` then discards the rest of the header
   queue and the cycle repeats. Before `ce28aef` the same freeze
   lasted 19–24 h (the 70 CRITICALs). After it, the class still
   fires ~7 times/day and still pages when a stall overruns 1 h.

Contributing, not sufficient: outbound-only (`--nolisten`); banman
86400 s bans of those outbound peers for mempool `Input not found`
and `non-final`; locator always appending genesis, which some peers
answer with a 2000-header unconnecting batch (97 such this 2 h
window) and then get `too many unconnecting headers` banned.

## What a fix control has to fail on

Not another watchdog. A test that:

- builds a tip, queues `tip+1`, and offers two ready `NODE_WITNESS`
  peers — one high-score with `start_height`/`best_known_height`
  far below the frontier (the 0.15.99 stand-in), one lower-score
  peer that can serve that height — and asserts H1/`getdata`
  **never** targets the unservable peer (`CanServeBlocks`);
- asserts that an empty or unconnecting `headers` reply at tip does
  **not** `adjust_score(-2)` and does not rotate the download
  peer-set onto zombies;
- keeps the frontier in-flight timestamp from being reset every 5 s
  so a single in-flight getdata can actually finish, *or* equivalent
  Core `BLOCK_STALLING_TIMEOUT` disconnect-and-refetch of the
  current holder only.

Control: `pytest tests/test_stall_class_control.py`. Landed with the
header-path `target > powLimit` CheckProofOfWork gate. W75 stays as the
production backstop.

## Instruments

- `/home/work/hashhog/fleet-monitor-history.jsonl`
- `journalctl --user -u hashhog-ouroboros-mainnet`
- RPC `:8359` `getblockchaininfo` / `getpeerinfo` / `getchaintips`
- Core `:8332` `getblockchaininfo`
- `src/ouroboros/block_sync.py` (`_request_next_blocks`,
  `_handle_timeouts`, `_catch_up`, `_check_wedge_watchdog`,
  `_maybe_recover_from_wedge`, `_can_serve_witness_blocks`)
- `ce28aef` (W75-RECOVER, 2026-08-28), `80a21c8` (stop banning
  header-sync stallers, 2026-07-09), `e9e78a7` (NODE_WITNESS
  getdata filter, 2026-07-10)
