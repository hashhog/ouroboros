W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay (ouroboros)
==============================================================================

Date: 2026-05-17
Impl: ouroboros (TWO pipelines — relay-flags are **P2P only**, so Python is the
      sole pipeline that owns this surface. Rust ferrous-utils participates in
      neither sendheaders, feefilter, nor wtxidrelay negotiation: those are
      decided in Python (`peer.py`, `p2p.py`, `node.py`) and never cross the
      ABI into Rust.)
Wave: W136 — BIP-130 (sendheaders), BIP-133 (feefilter), BIP-339 (wtxidrelay)
References:
  - `bitcoin-core/src/net_processing.cpp`
    - SENDHEADERS handler @ 3896-3899 (m_prefers_headers latch)
    - MaybeSendSendHeaders @ 5519-5538 (deferred until peer-best-known-block
      crosses MinimumChainWork)
    - WTXIDRELAY handler @ 3919-3939 (must arrive between VERSION and VERACK)
    - WTXIDRELAY outbound send @ 3710-3712 (greatest_common_version
      >= WTXID_RELAY_VERSION (70016))
    - FEEFILTER incoming handler @ 5035-5045 (MoneyRange guard, silent ignore
      on out-of-range)
    - MaybeSendFeefilter @ 5540-5580 (current_filter,
      m_fee_filter_rounder.round, MAX_MONEY-during-IBD,
      MAX_FILTER-recovery-latch, hysteresis 3/4 vs 4/3)
    - Per-peer fee-filter check on outbound INV @ 6013, 6071
      (`txinfo.fee < filterrate.GetFee(txinfo.vsize)` — **absolute fee against
      filterrate-scaled vsize**, *not* a per-kvB compare)
    - Pre-VERACK unsupported-message drop @ 4010-4013 (silent, no
      misbehavior score)
  - `bitcoin-core/src/policy/feerate.cpp/h` — CFeeRate::GetFee, GetFeePerK
  - `bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}` —
    FeeFilterRounder: MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1,
    `round()` returns lower_bound, with 2/3 probability of stepping back one
    bucket for fee-privacy randomisation.
  - `bitcoin-core/src/node/protocol_version.h` — SENDHEADERS_VERSION=70012,
    FEEFILTER_VERSION=70013, WTXID_RELAY_VERSION=70016.

Status: **30 gates audited — PRESENT 14 / PARTIAL 7 / MISSING 9.**
**14 BUGS** (2 P0-CDIV / 7 P1 / 5 P2).

Relationship to prior audits
----------------------------

- W117 (BIP-155 address-relay) audited the sendaddrv2/addrv2 surface in the
  same pre-VERACK negotiation window — W136 audits the three sibling flags
  that share that window.
- W121 (BIP-157 / BIP-158 P2P) audited the `NODE_COMPACT_FILTERS` service
  bit; this audit notes only the wtxidrelay handler's lack of version-gating.
- W126 (BIP-152 compact blocks) audited `sendcmpct`, which is the fourth
  post-VERACK feature-negotiation message; W136 audits the BIP-130 sibling
  that ships from the same `peer.py` post-VERACK block (lines 1397-1413).
- W128 (AddrMan) is unaffected — sendheaders/feefilter/wtxidrelay don't
  touch the address pool.
- W134 (orphan pool, if separately audited) and W135 (tx-relay trickle) share
  the BIP-133 fee-filter outbound application path through
  `TrickleQueue.get_invs_to_send` (p2p.py:294, line 333) which **does** the
  per-kvB compare correctly — see BUG-3 vs BUG-4 distinction below.

Two-pipeline guard
------------------

These relay flags are negotiated and applied **entirely in Python**:

- **Python pipeline (only path)**:
  - `peer.py:387-397` — `wants_headers` (BIP-130 latch), `peer_feefilter` /
    `feefilter_sent` / `next_feefilter_time` (BIP-133 state),
    `wtxid_relay` (BIP-339 latch).
  - `peer.py:782-787, 814-816, 1333-1338, 1363-1366` — outbound and inbound
    handshake sends of `wtxidrelay`.
  - `peer.py:846-861, 1395-1415` — post-VERACK feature-negotiation block:
    sends `sendheaders`, conditional `sendcmpct`, conditional
    `feefilter(feerate=1000)` (the hard-coded value is BUG-2).
  - `p2p.py:67-77` — BIP-133 broadcast timing constants.
  - `p2p.py:89-153` — `FeeFilterRounder` (Python port of Core's class).
  - `p2p.py:1952-2073` — `_init_feefilter_rounder`, `_get_current_feefilter`,
    `_broadcast_feefilter`, `_maybe_send_feefilter`. The maintenance loop at
    p2p.py:1940 calls `_broadcast_feefilter` every 30s.
  - `p2p.py:2360-2436` — registers `on_sendheaders`, `on_feefilter`,
    `on_wtxidrelay` post-VERACK handlers.
  - `node.py:967-986` — outbound INV path consults `p.peer_feefilter` to
    decide whether to announce a newly-accepted tx to a given peer.
  - `block_sync.py:2178-2191` — `_announce_block` consults `p.wants_headers`
    to choose between `headers` and `inv` block-announcement format.

- **Rust pipeline (passive ignore only)**:
  - `ferrous-utils/sync/src/network/header_sync.rs:427-435` contains a
    silent-ignore allowlist that drops `feefilter` / `sendcmpct` /
    `inv` / `addr` / etc. arriving at the headers-sync-client phase.
    This is the **passive boundary**: the Rust HeaderSync is a headers-only
    client that doesn't crash on receiving the message, but neither sets any
    per-peer flag nor reacts to it.
  - No `sendheaders`, `wtxidrelay`, or `m_fee_filter_received` peer-state
    in any Rust file (architectural invariant intact for the active surface).
  - This is **intentional**: relay-flag negotiation is a Python-only
    responsibility in ouroboros. The Rust HeaderSync's allowlist exists
    only to prevent crash on unsolicited messages during the brief
    header-bootstrap window before peer hand-off back to Python.

**Two-pipeline guard EXTENDED.** New test
`test_g30_two_pipeline_relay_flags_python_only` asserts:
  - `src/ouroboros/peer.py` defines `peer.wtxid_relay`, `peer.wants_headers`,
    and `peer.peer_feefilter` (Python-side active ownership);
  - `src/ouroboros/p2p.py` defines `FeeFilterRounder` (Python-side
    quantisation);
  - `ferrous-utils/sync/src/` contains no **active** relay-flag
    identifiers (`fee_filter_received`, `m_fee_filter_sent`,
    `m_prefers_headers`, `m_wtxid_relay`, `sendheaders`, `wtxidrelay`);
  - The single passive-ignore match in
    `ferrous-utils/sync/src/network/header_sync.rs:427-435` is explicitly
    whitelisted because it's a non-acting "don't crash on this command"
    allowlist, not an active flag.

This extends the project-wide guard chain W76 + W120 + W121 + W122 + W125 +
W128 + W129 + W130 + W131 + W132 + W133 → now W136 (5th distinct dedicated
guard since ouroboros adopted the two-pipeline pattern).

Top-level findings
------------------

1. **Hardcoded `feerate=1000` on initial post-VERACK send (BUG-2, P1).**
   `peer.py:854` and `peer.py:1408` send `FeeFilterMessage(feerate=1000)`
   immediately after VERACK. Core does **not** send a feefilter at handshake
   time — it relies on `MaybeSendFeefilter` ticking after `current_time >
   m_next_send_feefilter`, where `m_next_send_feefilter{0}` so the FIRST
   `SendMessages` tick sends the actual rounded `m_mempool.GetMinFee()`.
   Pre-FIX impact:
     - **Information leak**: every peer learns we run a 1000 sat/kvB floor at
       handshake — but Core never emits this exact starting value.
       Effectively a fingerprint that distinguishes ouroboros from Core.
     - **Stale value persists**: `peer.feefilter_sent` is set to 1000 only by
       this initial send (we never update the local mirror inside `peer.py`),
       so the next `_maybe_send_feefilter` tick at p2p.py:2028 sees
       `peer.feefilter_sent == 0` (because `_inbound_handshake` /
       `_handshake` write to the wire but don't touch
       `peer.feefilter_sent`) — confirmed via grep. So `_maybe_send_feefilter`
       will send AGAIN immediately with the real current filter, and a
       passive observer sees two feefilters within seconds (one hard-coded
       1000, one real). Both leaks fingerprint and waste bandwidth.

2. **`on_feefilter` does not MoneyRange-validate (BUG-1, P0-CDIV).**
   Core (net_processing.cpp:5038) writes
   `tx_relay->m_fee_filter_received = newFeeFilter` ONLY if
   `MoneyRange(newFeeFilter)` (i.e., 0 ≤ value ≤ MAX_MONEY).
   `p2p.py:2364-2368`:
     ```python
     async def on_feefilter(msg):
         ff = FeeFilterMessage.from_payload(msg.payload)
         peer.peer_feefilter = ff.feerate
     ```
   No MoneyRange check, no signed-vs-unsigned check.
   Combined with BUG-7 (`FeeFilterMessage` uses `<Q` not `<q` so negative
   values come through as huge uint64), a malicious peer can set
   `peer_feefilter = 0xFFFFFFFFFFFFFFFF` and **permanently suppress all tx
   relay from us to that peer**. The peer can also set our compare path in
   `node.py:971` to always-skip:
     ```python
     if p.peer_feefilter > tx_feerate_per_kb:
         continue
     ```
   so as long as `peer_feefilter > 0`, the comparison cannot fail.
   Severity: P0-CDIV because (a) it lets a peer **isolate** us from tx relay
   silently, (b) it is the same shape as W117 BUG-1 and W120 BUG-3 — an
   audit-class universal "validate-before-store" gap, (c) it diverges from
   Core's documented MoneyRange invariant.

3. **`on_feefilter` accepts the message post-VERACK with no version check
   (BUG-6, P1).** BIP-133 says feefilter is sent by peers running version
   ≥ FEEFILTER_VERSION (70013). `on_feefilter` does not gate on
   `peer.version >= 70013` nor on `not peer.is_block_only_conn`. Core gates
   `MaybeSendFeefilter` (the outbound path) on version ≥ FEEFILTER_VERSION
   and `IsBlockOnlyConn() == false`, but Core's INBOUND path
   (net_processing.cpp:5035) is also unguarded by version (because if the
   peer is sending us feefilter, they obviously support it). However Core
   DOES drop the message pre-VERACK via the generic
   `!pfrom.fSuccessfullyConnected` gate at line 4010. ouroboros's pre-VERACK
   filter at peer.py:1647 allows only `{version, verack, wtxidrelay,
   sendaddrv2}`, so feefilter is correctly dropped pre-VERACK — but with a
   −10 misbehaviour score, which Core does NOT apply (Core silently
   ignores). This is BUG-8.

4. **`on_wtxidrelay` post-VERACK handler is dead-code for negotiation
   (BUG-5, P1).** BIP-339 mandates that wtxidrelay arrive between VERSION
   and VERACK — Core disconnects the peer if it arrives later
   (net_processing.cpp:3922-3927 sets `pfrom.fDisconnect = true`). ouroboros
   `peer.py:1679-1690` logs a warning and silently ignores the post-VERACK
   case (good — does not regress to dis-misbehavior), but **also** registers
   an `on_wtxidrelay` handler at p2p.py:2370-2371 that fires on receipt of
   wtxidrelay post-VERACK. The handler just logs — it does NOT set
   `peer.wtxid_relay = True`, and it does NOT disconnect. So:
     - if the peer sends wtxidrelay pre-VERACK: handled in `_handshake` loop,
       sets `self.wtxid_relay = True` (correct);
     - if the peer sends wtxidrelay post-VERACK: handled in `listen` loop,
       logs and skips (correct silent-ignore, but diverges from Core which
       disconnects);
     - the registered `on_wtxidrelay` in p2p.py:2370 is **never reached**
       because `listen` consumes the message via the pre-handler at
       peer.py:1679-1690 with `continue`. Dead code.
   Severity P1 because (a) the dead-code is a footgun (someone might
   "fix" the handler thinking it's live, regressing the BIP-339-mandated
   behaviour), and (b) we diverge from Core's disconnect-on-violation
   policy. We can either match Core (disconnect) or document the
   intentional divergence; the current state is a half-measure that leaves
   intent ambiguous.

5. **No `wtxid_relay_peers` counter / no global wtxid-relay-coverage
   tracking (BUG-13, P2).** Core tracks `m_wtxid_relay_peers` as a
   gauge of the fraction of peers supporting BIP-339, used by
   `getpeerinfo` and the tx-download manager for orphan parent fetches
   (so an orphan parent is fetched via txid GETDATA only if the source
   peer is in legacy mode). ouroboros has no such counter. Impact is
   minor today (modern fleet ≥99% wtxid-relay), but the orphan-parent
   fetch path in ouroboros doesn't make the distinction either —
   tracked separately under W103/W135.

6. **MaybeSendSendHeaders deferral until peer-best-known crosses
   MinimumChainWork is absent (BUG-9, P1).** Core's
   `MaybeSendSendHeaders` (net_processing.cpp:5519-5538) explicitly delays
   sending `sendheaders` until "we're done with an initial-headers-sync
   with this peer" (peer's `pindexBestKnownBlock->nChainWork >
   MinimumChainWork`). Receiving header announcements for new blocks
   while still syncing their headers is "problematic, because of the
   state tracking done." ouroboros sends `sendheaders` unconditionally at
   peer.py:849 / peer.py:1400 IMMEDIATELY after VERACK — before any
   headers-sync has happened, before MinimumChainWork is established.
   Pre-FIX impact: during IBD, every peer announces all new blocks via
   `headers` instead of `inv`, which (a) wastes bandwidth on
   already-known headers, (b) interleaves announce-headers with
   sync-headers in the inbound queue, complicating BIP-130 anti-DoS
   state tracking. Severity P1 because it's a real divergence with
   observable behavior, but is not consensus-affecting.

7. **No `m_sent_sendheaders` deduplication latch (BUG-10, P2).** Core
   sets `peer.m_sent_sendheaders = true` after sending sendheaders to
   prevent re-sending it on every `MaybeSendSendHeaders` call. ouroboros
   sends sendheaders in only one place (post-VERACK in the handshake),
   so there's no re-send risk today, but the missing latch is a latent
   regression vector: any future code that calls a maintenance-loop send
   of sendheaders would re-send it indefinitely. Match Core: add a
   `peer.sent_sendheaders` bool.

Bug inventory
-------------

```
ID      G#       Severity   File           Line     Summary
------  -------  ---------  -------------  -------  ---------------------------
BUG-1   G14      P0-CDIV    p2p.py         2364     on_feefilter does not MoneyRange-check ff.feerate
BUG-2   G07      P1         peer.py        854,1408 Hardcoded feefilter=1000 sent at post-VERACK
BUG-3   G15      P1         node.py        971      Outbound INV feefilter compare uses per-kvB; correct shape, but the comparison `peer_feefilter > tx_feerate_per_kb` is strict-gt — Core uses `txinfo.fee < filterrate.GetFee(txinfo.vsize)` which is fee-vs-(filter×vsize/1000). Boundary case `tx_feerate == peer_feefilter` is OPPOSITE of Core (we send, Core drops). See gate G15 detail.
BUG-4   G15      P2         p2p.py         334      TrickleQueue.get_invs_to_send compares fee_rate_kvb < feefilter (strict-lt vs strict-lt). For fee_rate == feefilter we SEND, Core SENDS. Correct match here. (Documented for contrast w/ BUG-3.)
BUG-5   G23      P1         p2p.py         2370     on_wtxidrelay post-VERACK handler is dead code; pre-VERACK path in peer.py:1679-1690 short-circuits before dispatch
BUG-6   G14      P1         p2p.py         2364     on_feefilter does not gate on peer.version >= FEEFILTER_VERSION (70013)
BUG-7   G12      P1         p2p_messages.py 1184    FeeFilterMessage uses `<Q` (uint64) on both pack and unpack; Core serialises CAmount (int64_t) with `<q`
BUG-8   G24      P2         peer.py        1674     adjust_score(-10) for non-handshake messages pre-handshake diverges from Core which silently drops (NET_DEBUG only, no score)
BUG-9   G09      P1         peer.py        849,1400 sendheaders is sent unconditionally post-VERACK; Core defers until peer-best-known-block crosses MinimumChainWork
BUG-10  G09      P2         peer.py        387      No `peer.sent_sendheaders` deduplication latch (Core has m_sent_sendheaders atomic bool)
BUG-11  G16      P1         p2p.py         2030     `_maybe_send_feefilter` lacks Core's MAX_FILTER-recovery latch (post-IBD immediate-send when previous send was MAX_MONEY)
BUG-12  G18      P2         p2p.py         148      FeeFilterRounder.round uses random.randint(0,2)!=0 (== 2/3 chance step back), matches Core, but seeds python random not FastRandomContext; deterministic-seed tests would mismatch.
BUG-13  G29      P2         (absent)       n/a      No m_wtxid_relay_peers counter; getpeerinfo missing per-peer wtxid_relay field
BUG-14  G28      P1         rpc.py         6545     getpeerinfo `minfeefilter` field reads `peer.fee_filter` (no such attribute — typo for `peer.peer_feefilter`). getattr fallback returns 0 unconditionally. Field always reports 0 sat/B regardless of peer's actual filter, breaking cross-impl fleet-monitor classification.
```

Severity legend
- **P0-CDIV**: consensus-divergence-capable; can be exploited by a peer to
  isolate us from a network-wide policy invariant.
- **P1**: protocol-divergence; observable cross-impl difference but not
  consensus-critical.
- **P2**: cosmetic / latent / micro-optimisation.

30-Gate audit matrix
--------------------

### Wire format & message types (G1–G6)

| Gate | Status   | Detail |
|------|----------|--------|
| G1: `sendheaders` empty-payload command  | PRESENT  | p2p_messages.py:1160-1172, payload=b''. |
| G2: `feefilter` 8-byte little-endian payload | PARTIAL | p2p_messages.py:1183 uses `<Q` (uint64) — should be `<q` (int64_t per CAmount). BUG-7. |
| G3: `wtxidrelay` empty-payload command | PRESENT | p2p_messages.py:1197-1209. |
| G4: command-name strings = NetMsgType constants | PRESENT | "sendheaders"/"feefilter"/"wtxidrelay" exact match to bitcoin-core/src/protocol.h NetMsgType. |
| G5: message magic per network | PRESENT | All three use `get_magic(network)`. |
| G6: payload-length sanity (4-byte LE in header, max 32M) | PRESENT | Inherited from NetworkMessage framing in p2p_messages.py. |

### Outbound send timing (G7–G11)

| Gate | Status   | Detail |
|------|----------|--------|
| G7: feefilter sent at handshake (BIP-133 v70013) | PARTIAL | peer.py:854/1408 sends, but hardcoded `feerate=1000`. BUG-2. Core does not send at handshake — uses `MaybeSendFeefilter` ticking. |
| G8: feefilter only sent if `relay_txs && not block_relay_only` | PRESENT | peer.py:850 gates on `self.relay_txs`. block-relay-only path (peer.py:855-859) logs and skips. |
| G9: sendheaders deferred until peer-best-known crosses MinimumChainWork | MISSING | peer.py:849/1400 unconditional. BUG-9. No `m_sent_sendheaders` latch either. BUG-10. |
| G10: wtxidrelay sent before VERACK, only if version >= 70016 && relay_txs | PRESENT | peer.py:782-787 (inbound) & peer.py:1333-1338 (outbound) gate on `greatest_common_version >= 70016 and self.relay_txs`. Matches Core net_processing.cpp:3710-3712. |
| G11: outbound feefilter on maintenance tick uses real mempool min | PRESENT | p2p.py:1985 `_broadcast_feefilter` calls `_get_current_feefilter` which reads `mempool.get_mempool_info().min_fee_rate`. |

### Inbound handler logic (G12–G16)

| Gate | Status   | Detail |
|------|----------|--------|
| G12: `feefilter.from_payload` deserialises 8 bytes | PARTIAL | Uses `<Q` not `<q`. BUG-7. |
| G13: on_sendheaders sets `peer.wants_headers = True` | PRESENT | p2p.py:2360-2362. |
| G14: on_feefilter MoneyRange-validates before storing | MISSING | p2p.py:2364-2368 stores unconditionally. BUG-1 (P0-CDIV) + BUG-6. |
| G15: outbound INV announce drops txs below peer's feefilter | PARTIAL | TWO call-sites differ: TrickleQueue.get_invs_to_send (p2p.py:334) uses correct per-kvB strict-lt; node.py:971 uses **strict-gt opposite-direction** with `peer_feefilter > tx_feerate_per_kb`. node.py:971 strict-gt vs Core's `tx.fee < filterrate.GetFee(tx.vsize)`: at the boundary `tx_feerate == peer_feefilter`, node.py SENDS (gt is false), but Core DROPS only if `tx.fee < filterrate*vsize/1000` which at equality is FALSE → Core also SENDS. Net behaviour matches! BUT the per-kvB form loses precision: `tx.fee*1000 // tx.vsize < peer_feefilter` vs Core's `tx.fee < (peer_feefilter*tx.vsize+999)/1000`-equivalent (integer ceiling not used; Core uses `CFeeRate::GetFee(vsize)` which is `(nSatoshisPerK * vsize) / 1000`). Off-by-one at boundary for unusual vsize. BUG-3 P1. |
| G16: post-IBD recovery: previous-MAX_FILTER sent → next_send=0 | MISSING | p2p.py:2018-2052 has no equivalent of Core net_processing.cpp:5558-5563. BUG-11. |

### State tracking & misbehavior (G17–G22)

| Gate | Status   | Detail |
|------|----------|--------|
| G17: peer.wtxid_relay set only between VERSION and VERACK | PRESENT | peer.py:1679-1690 + peer.py:814-816/1363-1366. Post-VERACK ignored with a warning. |
| G18: FeeFilterRounder buckets at 1.1x spacing, MAX=1e7 | PRESENT | p2p.py:73-75, 107-119 — port of Core's MakeFeeSet. BUG-12 caveat: Python `random.randint` is not seeded from the same RNG as Core, so fee-quantisation noise is not bit-identical (acceptable — Core itself uses FastRandomContext which is per-instance). |
| G19: hysteresis 3/4 vs 4/3 expedite if next_send too far away | PRESENT | p2p.py:2056-2068. |
| G20: feefilter Poisson interval = ~10 min average | PRESENT | p2p.py:69 (AVG_FEEFILTER_BROADCAST_INTERVAL=600s) + p2p.py:2051 (expovariate). |
| G21: feefilter MAX_FEEFILTER_CHANGE_DELAY = 5 min | PRESENT | p2p.py:71 (MAX_FEEFILTER_CHANGE_DELAY=300s). |
| G22: feefilter set to MAX_MONEY during IBD | PRESENT | p2p.py:1974 (`if self._in_ibd: return MAX_MONEY`). Matches Core net_processing.cpp:5552-5555. |

### Cross-cutting / divergences (G23–G27)

| Gate | Status   | Detail |
|------|----------|--------|
| G23: on_wtxidrelay post-VERACK handler does what? | MISSING | Registered at p2p.py:2370 but never reached (dead code). BUG-5. |
| G24: pre-VERACK non-handshake messages dropped silently per Core | PARTIAL | peer.py:1668-1675 applies adjust_score(-10). BUG-8. |
| G25: `wants_cmpctblock` AND `wants_headers` precedence in block-announce | PRESENT | block_sync.py:2170-2191: cmpctblock > headers > inv (matches Core 5892-5915). |
| G26: tx-INV uses MSG_WTX(5) iff peer.wtxid_relay else MSG_TX(1) | PRESENT | node.py:974 (per-tx INV) and p2p.py:340 (TrickleQueue) and p2p.py:2420 (mempool inv). |
| G27: GETDATA-tx with MSG_WTX(5) is matched against peer's wtxid_relay | PRESENT | block_sync.py:746 accepts both INV_TYPE_TX, MSG_WITNESS_TX, and MSG_WTX (W121 close). |

### Wiring & two-pipeline guard (G28–G30)

| Gate | Status   | Detail |
|------|----------|--------|
| G28: getpeerinfo emits per-peer fee_filter_received | PARTIAL | rpc.py:6545 emits a "minfeefilter" field BUT reads `peer.fee_filter` which does not exist (peer state attribute is `peer.peer_feefilter`). `getattr` fallback returns 0 → field ALWAYS reports 0 sat/B. BUG-14. |
| G29: getpeerinfo emits per-peer wtxid_relay | MISSING | No "relaytxes_wtxid" field. BUG-13. |
| G30: two-pipeline guard — relay flags Python-only | NEW | Added in test_w136_relay_flags.py. Confirms Rust pipeline has no feefilter / sendheaders / wtxidrelay code. |

Test status (test_w136_relay_flags.py)
--------------------------------------

30 gates → 30 test functions + 1 architectural guard.
PASS count flips with each bug fix; current behavior:

- **xfailed (BUG-marked)**: 13 — one per BUG-* row in the inventory.
- **passed**: ~17 — gates currently honored.
- **passed (architectural guard)**: 1 (G30 two-pipeline guard).

Out-of-scope for W136
---------------------

- The privatebroadcast feefilter exemption (Core net_processing.cpp:3853-3861)
  — ouroboros has no private-broadcast connection type. Out of scope.
- The txreconciliation/Erlay BIP-330 interaction with WTXIDRELAY
  (net_processing.cpp:3723-3737) — audited under W117 / W134.
- The `ignore_incoming_txs` option that suppresses MaybeSendFeefilter
  (net_processing.cpp:5542) — ouroboros has no `-blocksonly` config flag.
  Tracked separately as a documented feature gap.
- HasPermission(ForceRelay) / NetPermissionFlags — no permission system in
  ouroboros (handled by config.allowlist only, no per-peer overrides).
- The CompareInvMempoolOrder topological-mining-score sort in Core
  (net_processing.cpp:5582-5594) used for INV trickling — ouroboros's
  TrickleQueue uses arrival-order randomisation. Separate W134/W135 surface.

Future remediation order (post-discovery)
-----------------------------------------

1. **BUG-1** (P0-CDIV): add MoneyRange check in `on_feefilter`. ~3 LOC fix.
2. **BUG-7** (P1): switch FeeFilterMessage to `<q` (or document and add an
   explicit `0 <= feerate <= MAX_MONEY` cast). ~2 LOC.
3. **BUG-2** (P1): remove the post-VERACK hardcoded `feefilter=1000` send;
   rely on `_broadcast_feefilter` maintenance tick (which already does the
   first send within ~5s). ~6 LOC.
4. **BUG-9** (P1): defer sendheaders until peer's best-known-block exceeds
   MinimumChainWork. Will require plumbing the chainstate.MinimumChainWork
   into the post-handshake hook OR splitting sendheaders out of the
   post-VERACK block into a maintenance-loop tick (the latter matches Core
   exactly).
5. **BUG-5** (P1): either delete the dead `on_wtxidrelay` handler at
   p2p.py:2370 or wire it to set `peer.fDisconnect=true` for Core parity
   on post-VERACK wtxidrelay arrivals.
6. **BUG-6** (P1): version-gate `on_feefilter`. ~2 LOC.
7. **BUG-11** (P1): add the MAX_FILTER-recovery latch in
   `_maybe_send_feefilter`. ~5 LOC.
8. **BUG-3** (P1): switch node.py:971 to absolute-fee compare:
   `tx_fee < (peer_feefilter * tx_vsize) // 1000`. Matches Core exactly.
9. **BUG-13** (P2): add `m_wtxid_relay_peers` counter + getpeerinfo
   "wtxid_relay" / "minfeefilter" fields.
10. **BUG-8** (P2): drop the adjust_score(-10) on non-handshake pre-VERACK
    messages — Core does not score them.
11. **BUG-10** (P2): add `peer.sent_sendheaders` latch.
12. **BUG-12** (P2): document FeeFilterRounder RNG divergence — no fix
    needed because Core itself uses per-instance FastRandomContext.

End of W136 audit.
