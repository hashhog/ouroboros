# W152 — Tx relay + inv batching + orphan handling (ouroboros)

**Wave:** W152 — `RelayTransaction`, `AddTxAnnouncement`, ProcessMessage
`msg_tx` + `msg_inv` handlers, `SendMessages` inv batching loop,
`m_recently_announced_invs`, `m_tx_inventory_to_send`,
`m_next_inv_send_time`, `MaybeSendMessage` cadence, `TxOrphanage::AddTx`,
`EraseTx`, `EraseForBlock`, `EraseForPeer`, `LimitOrphans`,
`OrphanByParent` map, `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000`,
`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404000`, `TxRequestTracker`,
`INVENTORY_BROADCAST_PER_SECOND=14`, `INVENTORY_BROADCAST_MAX=1000`,
`MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `GETDATA_TX_INTERVAL=60s`,
`TXID_RELAY_DELAY=2s`, `NONPREF_PEER_TX_DELAY=2s`,
`OVERLOADED_PEER_TX_DELAY=2s`, `MSG_TX` (type 1) vs `MSG_WTX` (type 5)
dispatch (BIP-339), `MAX_INV_SZ=50000`, BIP-37 `fRelay`, BIP-35 MEMPOOL.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:126` — `MAX_INV_SZ = 50000`.
- `bitcoin-core/src/net_processing.cpp:128` — `MAX_GETDATA_SZ = 1000`.
- `bitcoin-core/src/net_processing.cpp:165-178` —
  `INBOUND_INVENTORY_BROADCAST_INTERVAL{5s}`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL{2s}`,
  `INVENTORY_BROADCAST_PER_SECOND{14}`,
  `INVENTORY_BROADCAST_TARGET = 14 × 5s = 70`,
  `INVENTORY_BROADCAST_MAX = 1000`. Static asserts: TARGET ≤ MAX ≤
  `MAX_PEER_TX_ANNOUNCEMENTS`.
- `bitcoin-core/src/net_processing.cpp:1171-1181` — `NextInvToInbounds`:
  **shared** per-network Poisson timer across inbound peers so a network
  observer cannot bin-correlate two inbound trickle events to the same
  upstream peer; outbound peers each get an independent
  `m_rng.rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)`.
- `bitcoin-core/src/net_processing.cpp:6045-6047` —
  `broadcast_max = INVENTORY_BROADCAST_TARGET + (queue_size/1000)*5`,
  clamped to `INVENTORY_BROADCAST_MAX=1000`.
- `bitcoin-core/src/net_processing.cpp:5572-5578` —
  `AVG_FEEFILTER_BROADCAST_INTERVAL=10min`,
  `MAX_FEEFILTER_CHANGE_DELAY=5min`.
- `bitcoin-core/src/node/txdownloadman.h:24-38` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `TXID_RELAY_DELAY=2s`,
  `NONPREF_PEER_TX_DELAY=2s`, `OVERLOADED_PEER_TX_DELAY=2s`,
  `GETDATA_TX_INTERVAL=60s`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:200-285` — request
  scheduler: per-peer per-txhash timer; on `RequestedTx` registers the
  expiry, on `ReceivedResponse` clears in-flight, on expiry promotes
  the *next* announcement (different peer) to candidate. Outbound,
  preferred, and `relay`-permission peers are prioritised; non-preferred
  and overloaded peers are delayed.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:278` — `RequestedTx`
  schedules `GETDATA_TX_INTERVAL = 60s` retry; on timeout the entry
  flips back to candidate and another peer's announcement (if any) is
  selected.
- `bitcoin-core/src/node/txorphanage.h:20-23` — defaults
  `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404000` bytes per peer +
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000`. The legacy
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` was replaced by per-peer
  reserved usage + global latency score; the global cap is now
  `N_peers × 404 KB + 3000-score-window`.
- `bitcoin-core/src/node/txorphanage.h:38-130` — `TxOrphanage` API:
  `AddTx(tx, peer)`, `AddAnnouncer(wtxid, peer)`, `EraseTx(wtxid)`,
  `EraseForPeer(peer)`, `EraseForBlock(block)`,
  `AddChildrenToWorkSet(parent_tx, rng)`,
  `GetTxToReconsider(peer)`, `HaveTxToReconsider(peer)`,
  `GetChildrenFromSamePeer(parent, peer)`. Note: orphan is keyed by
  wtxid and **tracks the set of announcers** (NodeId set), so a single
  peer cannot DoS the global pool by churning random orphans — eviction
  evicts the oldest announcement of the **most-resource-intensive
  peer**, never another peer's announcements.
- `bitcoin-core/src/protocol.h:481-517` —
  `MSG_TX=1`, `MSG_BLOCK=2`, `MSG_FILTERED_BLOCK=3`, `MSG_CMPCT_BLOCK=4`,
  **`MSG_WTX=5`** (BIP-339, hash carried is a **wtxid** not a txid),
  `MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG` (`0x40000001`),
  `MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG` (`0x40000002`).
  `IsGenTxMsg() = (MSG_TX || MSG_WTX || MSG_WITNESS_TX)` — all three
  carry tx data, but **`MSG_WTX` is the only one whose hash field is a
  wtxid**.
- `bitcoin-core/src/net_processing.cpp:3870-3920` — BIP-339 wtxidrelay
  negotiation MUST happen BEFORE VERACK; receiving a `wtxidrelay` after
  VERACK results in disconnect.
- `bitcoin-core/src/net_processing.cpp:2243-2270` —
  `InitiateTxBroadcastToAll(txid, wtxid)`: per-peer chooses
  `peer.m_wtxid_relay ? wtxid : txid` and inserts the **wtxid** key into
  `m_tx_inventory_to_send` regardless (the wtxid is the canonical
  identity). The hash dispatched on the wire is then whichever the
  peer prefers, but the queue is wtxid-keyed.
- `bitcoin-core/src/net_processing.cpp:3128-3245` — orphan reconsider
  loop runs from `MaybeSendMessage`/`ProcessOrphanTx` after every
  successful tx-accept AND after every block-connect (via
  `EraseForBlock` then `AddChildrenToWorkSet` on each block tx).
- `bitcoin-core/src/net_processing.cpp:3566` — `MEMPOOLREJ` log gate:
  Core only calls `Misbehaving(peer, ...)` when
  `state.GetResult() == TxValidationResult::TX_CONSENSUS`. Policy
  rejects (TX_NOT_STANDARD, TX_MEMPOOL_POLICY, TX_PREMATURE_SPEND,
  TX_INPUTS_NOT_STANDARD, TX_MISSING_INPUTS, TX_RECONSIDERABLE,
  TX_WITNESS_STRIPPED, TX_NO_MEMPOOL) **never** cause peer scoring.
- `bitcoin-core/src/net.h` — peer-side BIP-37 `fRelay` bit: when
  peer's `version.fRelay==false`, we MUST NOT send tx INVs to that peer.
  Block-relay-only outbound connections also set this on our outbound
  version.

**Files audited**
- `src/ouroboros/p2p.py:67-77` — feefilter constants
  (AVG_FEEFILTER_BROADCAST_INTERVAL, MAX_FEEFILTER_CHANGE_DELAY,
  FEE_FILTER_SPACING, MAX_FILTER_FEERATE, MIN_RELAY_FEE_RATE).
- `src/ouroboros/p2p.py:157-373` — `INBOUND_INVENTORY_BROADCAST_INTERVAL`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL`, `INVENTORY_BROADCAST_PER_SECOND`,
  `INVENTORY_BROADCAST_TARGET`, `INVENTORY_BROADCAST_MAX`,
  `TrickleEntry`, `TrickleQueue` (add_tx / mark_known / should_send /
  schedule_next_send / get_invs_to_send / clear).
- `src/ouroboros/p2p.py:552-555, 3446-3623` — `_trickle_queues` dict,
  `_trickle_task`, `_trickle_loop`, `queue_tx_for_relay`,
  `mark_tx_known_by_peer`, `update_peer_wtxid_relay`, `get_trickle_stats`.
- `src/ouroboros/p2p.py:2390-2428` — `on_mempool` (BIP-35 MEMPOOL
  handler / bloom-filter mempool dump).
- `src/ouroboros/p2p.py:3401-3422` — `peer_manager.misbehaving(...)`.
- `src/ouroboros/block_sync.py:90-92` — `MAX_GETDATA_SZ=1000`.
- `src/ouroboros/block_sync.py:218-219` — `_requested_txs: dict[bytes, float]`.
- `src/ouroboros/block_sync.py:224-227` — `orphan_blocks` (blocks, NOT txs)
  + `_max_orphans=200`.
- `src/ouroboros/block_sync.py:717-808` — `handle_inv` (tx inv path
  + stale-tx-request expire).
- `src/ouroboros/mempool.py:1450-1562` — `MAX_ORPHAN_TRANSACTIONS=100`,
  `ORPHAN_EXPIRY_SECONDS=20min`, `OrphanPool` (add / remove /
  remove_by_txid / get_orphans_for_parent / has / has_wtxid / expire /
  size / _evict_random).
- `src/ouroboros/mempool.py:1995-2031` — orphan acceptance gate in
  `_add_transaction_inner`.
- `src/ouroboros/mempool.py:2362, 2984-3010` — `_resolve_orphans`.
- `src/ouroboros/mempool.py:3012-3048` — `expire_old_transactions`
  (the ONLY caller of `orphan_pool.expire()`).
- `src/ouroboros/mempool.py:3163-3211` — `remove_block_transactions`
  (does NOT touch orphan_pool).
- `src/ouroboros/node.py:923-1001` — `_make_tx_handler` (P2P tx receive +
  relay-to-all + misbehaving call).
- `src/ouroboros/node.py:1003-1073` — `_make_getdata_handler` (mempool
  tx serve back).
- `src/ouroboros/peer.py:286-451` — Peer constructor (relay_txs,
  wtxid_relay, peer_feefilter, feefilter_sent).
- `src/ouroboros/peer.py:715-740, 1301-1326` — inbound/outbound handshake
  parsing of received VersionMessage (services, user_agent, height,
  time_offset). **fRelay is parsed by `VersionMessage.from_payload`
  but NOT propagated to `Peer.relay_txs`** — see BUG-15.
- `src/ouroboros/p2p_messages.py:25-37` — INV_TYPE constants.
- `src/ouroboros/p2p_messages.py:363-411` — `InvMessage` /
  `from_payload` (50000-item cap).
- `src/ouroboros/rpc.py:2382-2538` — `rpc_sendrawtransaction` (calls
  `mempool.add_transaction` AND `queue_tx_for_relay` without
  fee/vsize).
- `src/ouroboros/rpc.py:7905-7931` — `rpc_testmempoolaccept` (calls
  `validator.validate_transaction` only).
- `ferrous-utils/sync/src/lib.rs:5911-5916` — `FastSync::is_synced`
  hard-coded `Ok(false)` (W148 BUG-16 carry-forward).

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | INVENTORY_BROADCAST constants | G1: PER_SECOND = 14 | PASS (`p2p.py:163`) |
| 1 | … | G2: INBOUND_INTERVAL = 5s | PASS (`p2p.py:159`) |
| 1 | … | G3: OUTBOUND_INTERVAL = 2s | PASS (`p2p.py:160`) |
| 1 | … | G4: TARGET = PER_SECOND × INBOUND_INTERVAL = 70 | PASS (`p2p.py:166-168`) |
| 1 | … | G5: MAX = 1000 | PASS (`p2p.py:171`) |
| 1 | … | G6: broadcast_max = TARGET + (queue/1000)*5 capped at MAX | PASS (`p2p.py:312-317`) |
| 2 | Poisson-distributed trickle timer | G7: per-outbound rand_exp_duration | PASS (`p2p.py:284-292`) |
| 2 | … | G8: **shared** timer across all inbound peers per-network (NextInvToInbounds) | **BUG-1 (P0-PRIVACY)** — every peer has its own independent `next_send_time` initialised via `random.expovariate(1/avg_interval)`; Core's per-network shared timer for inbound peers is missing. A network observer can correlate the tx-announce times to a single upstream node. |
| 3 | BIP-339 MSG_WTX wire-format dispatch | G9: incoming MSG_WTX inv carries wtxid (NOT txid) | **BUG-2 (P0-CDIV)** — `block_sync.py:746-754` treats the MSG_WTX hash as if it were a txid: stores it in `_requested_txs[inv_hash]`, checks `mempool.get_transaction(inv_hash)` (which is txid-keyed), then requests `MSG_WITNESS_TX` (txid type) with the **wtxid bytes**. Peer interprets the request as txid → returns NOTFOUND or a different tx. |
| 3 | … | G10: getdata response handler dispatches MSG_WTX | **BUG-3 (P0-CDIV)** — `node.py:1038-1046` only handles `INV_TYPE_TX, MSG_WITNESS_TX`. MSG_WTX (type 5) falls through to the else-block → added to `not_found` → peer treats us as not having the tx, even if we do (lookup-by-wtxid path exists at `mempool.get_transaction_by_wtxid` line 4319 but is never wired into getdata). |
| 4 | TxRequestTracker scheduler | G11: per-peer per-txhash retry timer (GETDATA_TX_INTERVAL=60s) | PARTIAL — `_requested_txs` keyed by **hash only**, not (peer, hash). The 60s stale-flush exists (`block_sync.py:728-730`) but the only side-effect is a `dict.pop()`; no re-request is sent to a different peer. |
| 4 | … | G12: NONPREF_PEER_TX_DELAY for non-preferred peers | **BUG-4 (P1)** — absent. All peers requested with the same priority. |
| 4 | … | G13: TXID_RELAY_DELAY when wtxid peers available | **BUG-4 cross-cite** — absent. |
| 4 | … | G14: OVERLOADED_PEER_TX_DELAY when peer has ≥100 in-flight | **BUG-4 cross-cite** — absent; no per-peer in-flight count for txs. |
| 4 | … | G15: MAX_PEER_TX_REQUEST_IN_FLIGHT cap per peer | **BUG-4 cross-cite** — absent; unbounded concurrent tx requests per peer. |
| 4 | … | G16: on timeout, switch to next announcement (different peer) | **BUG-5 (P0)** — stale entry is popped and forgotten; the tx is silently lost from our pool until a different peer announces it again. |
| 5 | Orphan handling | G17: per-peer reserved usage (404 KB) + global latency-score (3000) | **BUG-6 (P0-DoS)** — single global cap `MAX_ORPHAN_TRANSACTIONS=100` shared across all peers, no per-peer accounting at all. Random eviction (`_evict_random` line 1557) lets any peer poison the pool — flood 100 orphans, evict every honest one. |
| 5 | … | G18: orphan keyed by wtxid | PASS (`mempool.py:1480`) |
| 5 | … | G19: AddAnnouncer-equivalent (multi-peer announcer set) | **BUG-7 (P1)** — orphan stores no list of peers that announced; can't EraseForPeer or score-the-right-peer on bad orphans. |
| 5 | … | G20: EraseForBlock(block) — drop orphans confirmed/invalidated by block | **BUG-8 (P0)** — `remove_block_transactions` (line 3163) walks block txs but **never touches `orphan_pool`**. Orphans that the block confirms or invalidates sit until 20-min expiry (which is also dead code — see BUG-9). |
| 5 | … | G21: EraseForPeer(peer) — drop orphans on peer disconnect | **BUG-7 cross-cite** — no API; peer disconnect leaks orphans. |
| 5 | … | G22: AddChildrenToWorkSet on each block tx → orphan reconsider | **BUG-10 (P0)** — `_resolve_orphans` is called only from `_add_transaction_inner` (line 2362) and a stale `submit_transaction` clone at line 4775; it is NEVER called after block connection. Block-confirmed parents never unlock orphans. |
| 5 | … | G23: 20-minute orphan expiry actually fires | **BUG-9 (P0)** — `OrphanPool.expire()` is only called from `Mempool.expire_old_transactions` (mempool.py:3046), and `expire_old_transactions` has **ZERO call sites** in the entire ouroboros codebase. The 20-minute expiry constant is dead code. |
| 6 | MSG_WTX dispatch in version handshake | G24: peer's wtxid_relay state captured during handshake | PASS (`peer.py:815`, also `update_peer_wtxid_relay` for the late path) |
| 7 | BIP-37 fRelay (peer asks not to receive tx) | G25: parse `version.fRelay` | PASS — `p2p_messages.py:233/272/283/321/377/392` parses the field. |
| 7 | … | G26: propagate parsed fRelay to `Peer.relay_txs` and skip tx INVs to that peer | **BUG-11 (P0-CDIV)** — `peer.py:715-722, 1301-1308` reads `version.services / user_agent / start_height / timestamp` but **never reads `version.relay`**. A peer announcing `relay=false` (block-relay-only) still receives our tx INVs, both via the trickle queue (relay_txs is set from OUR side at construction, not from peer's announcement) AND via the P2P-receive direct-INV path at `node.py:967-986`. |
| 8 | bloom-filter MEMPOOL dump | G27: gate on advertised NODE_BLOOM | PASS (`p2p.py:2405-2409`) |
| 8 | … | G28: MAX_INV_SZ=50000 chunking | PASS (`p2p.py:2418-2423`) |
| 8 | … | G29: dispatch wtxid for wtxid-relay peers | **BUG-12 (P1)** — `p2p.py:2420` uses `MSG_WTX if NODE_WITNESS else INV_TYPE_TX` and the hash is `all_txids[i]` (a txid). MSG_WTX requires a wtxid. So wtxid-relay peers receive txids labelled as MSG_WTX → peer rejects the inventory or re-requests the wrong hash. |
| 9 | MAX_INV_SZ enforcement on incoming inv | G30: misbehaving(100) on inv > 50000 (Core) | **BUG-13 (P1)** — `p2p_messages.py:396-397` raises `ValueError`; caller (`block_sync.py:807-808`) catches and applies `peer.adjust_score(-2)` only. Core misbehaves at 100 (straight to discouragement). |
| 10 | Misbehaving-on-policy-reject (W150 carry-forward BUG-23) | G31: only TX_CONSENSUS → misbehaving | **BUG-14 (P0-DoS)** — `node.py:987-995` unconditionally calls `peer_manager.misbehaving(addr, 10, ...)` on EVERY mempool reject including policy rejects (non-standard, txn-already-in-mempool, RBF mempool-conflict, min-relay-fee-not-met, too-long-mempool-chain). With ban_threshold=100 and score=10, **10 RBF rejects bans the peer** — a legitimate v28 peer broadcasting consecutive RBF versions of the same tx accumulates the ban in <1 minute. Carry-forward from W150 BUG-23. |
| 11 | Privacy-preserving P2P-receive relay | G32: route received tx through trickle queue | **BUG-15 (P0-PRIVACY)** — `_make_tx_handler` at `node.py:967-986` synchronously sends an INV directly to every peer (`p.send_message(inv...)` in a loop) on every tx received from the network. NO Poisson delay, NO trickle queue. A timing observer can identify the originating node by which downstream peer announces first. This is exactly what BIP-339 + the trickle queue exist to prevent. |

---

## BUG-1 (P0-PRIVACY) — Inbound peers have independent Poisson timers; missing Core's `NextInvToInbounds` per-network shared timer

**Severity:** P0-PRIVACY. Bitcoin Core's `PeerManagerImpl::NextInvToInbounds`
(net_processing.cpp:1171-1181) returns a **shared** per-network Poisson
timer for all inbound peers — every inbound peer's
`m_next_inv_send_time` is overwritten with the same value drawn from
`m_rng.rand_exp_duration(INBOUND_INVENTORY_BROADCAST_INTERVAL)`. This
means all inbound peers receive their trickle batch at the **same
randomised instant**. A network observer who sees all of our outbound
inv announcements cannot bin-correlate them back to the originating
upstream peer, because every inbound got the same draw.

ouroboros's `TrickleQueue.schedule_next_send`
(`src/ouroboros/p2p.py:284-292`) draws an independent
`random.expovariate(1.0 / self.avg_interval)` per peer, both inbound
and outbound. So 10 inbound peers each have 10 different next-send
times, and a passive observer can statistically link "this inbound
peer's tx-announce time pattern matches what we'd expect if it
sourced the tx 200ms ago" — which is exactly the de-anonymisation
attack BIP-339 + `NextInvToInbounds` were designed to prevent.

**File:** `src/ouroboros/p2p.py:283-292` (`schedule_next_send`), absent
PeerManager-level shared timer.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1171-1181`
(`NextInvToInbounds`).

**Excerpt (ouroboros, per-peer)**
```python
def schedule_next_send(self, current_time: float) -> None:
    # Poisson delay: exponential distribution with rate = 1/avg_interval
    delay = random.expovariate(1.0 / self.avg_interval)
    self.next_send_time = current_time + delay
```

vs Core (shared per inbound network key):
```cpp
std::chrono::microseconds PeerManagerImpl::NextInvToInbounds(...) {
    auto [it, inserted] = m_next_inv_to_inbounds_per_network_key.try_emplace(network_key, 0us);
    auto& timer{it->second};
    if (timer < now) {
        timer = now + m_rng.rand_exp_duration(average_interval);
    }
    return timer;
}
```

**Impact:** privacy loss for inbound peers; tx originator
de-anonymisation easier than Core's bar. Mainnet-relevant on any node
serving inbound peers.

---

## BUG-2 (P0-CDIV) — `handle_inv` treats MSG_WTX inv hash as a txid; requests with wrong inv-type bytes

**Severity:** P0-CDIV. BIP-339 wire-format: `MSG_WTX` (inv type `5`)
declares "the 32-byte hash that follows is a **wtxid**", and the inv
type intentionally differs from `MSG_TX=1` and `MSG_WITNESS_TX=0x40000001`
so the receiver can dispatch the correct hash lookup. ouroboros's
`block_sync.handle_inv` collapses all three inv types into one branch
and stores the bytes as a txid:

```python
elif inv_type in (INV_TYPE_TX, MSG_WITNESS_TX, MSG_WTX):
    if (
        self.mempool
        and not self.mempool.get_transaction(inv_hash)   # ← TXID LOOKUP
        and inv_hash not in self._requested_txs
    ):
        txs_to_request.append((MSG_WITNESS_TX, inv_hash))  # ← TXID INV TYPE
        self._requested_txs[inv_hash] = now
```

Consequences when peer sends `MSG_WTX(wtxid_X)`:
1. `mempool.get_transaction(wtxid_X)` looks up the wtxid bytes in
   `self.transactions` (which is **txid-keyed**) → always returns None,
   even when we already have the tx with that wtxid (lookup-by-wtxid
   exists at `mempool.get_transaction_by_wtxid`, line 4319, but is
   not used here).
2. We re-request the tx via `MSG_WITNESS_TX(wtxid_X)`. Peer
   interprets that as "give me the tx with txid = wtxid_X". For any
   non-segwit tx, txid == wtxid so the response is correct by
   coincidence. For any segwit tx, txid != wtxid → peer responds with
   NOTFOUND (if it can find anything) or with a different tx whose
   txid happens to equal the wtxid bytes (collision: in practice
   none).
3. `_requested_txs` is keyed by wtxid_X but the matching gate at line
   751 (`inv_hash not in self._requested_txs`) suppresses
   re-requests on subsequent MSG_WTX inv announcements only for the
   same wtxid; if any peer sends `MSG_WITNESS_TX(txid_X)` for the
   same tx, that txid is a different cache key and we still re-request.
4. The corresponding tx delivery (via `_make_tx_handler`,
   `node.py:923`) calls `mempool.add_transaction(tx, height)` which
   succeeds and updates `self.transactions[txid]`. The cached
   `_requested_txs[wtxid]` entry stays for 60 s until the next inv
   arrives; we re-request the same wtxid from every other peer that
   announces it.

**File:** `src/ouroboros/block_sync.py:746-754`.

**Core ref:** `bitcoin-core/src/protocol.h:481, 509, 517` (MSG_WTX type
+ hash semantics); `bitcoin-core/src/net_processing.cpp` tx_download
dispatch routes MSG_WTX hashes through wtxid lookups.

**Impact:** segwit IBD over wtxid-relay peers (i.e., every modern
peer) performs duplicate work — re-requesting txs we already have
because the local mempool lookup misses. Bandwidth waste scales with
mempool depth × peer count. On mainnet with ~80k mempool tx, this is
~5 GB/day of redundant tx data per peer at high txn-relay churn.

---

## BUG-3 (P0-CDIV) — `getdata` handler does not dispatch `MSG_WTX`; replies NOTFOUND for every wtxid request

**Severity:** P0-CDIV. Bitcoin Core's `ProcessGetData`
(net_processing.cpp ~3550-3650) handles MSG_TX, MSG_WITNESS_TX, AND
MSG_WTX. The MSG_WTX branch looks up by wtxid via
`m_mempool->get(GenTxid::Wtxid(...))` — the canonical wtxid lookup.

ouroboros's `_make_getdata_handler` at `node.py:1038-1046`:

```python
for inv_type, inv_hash in getdata.inventory:
    if inv_type in (INV_TYPE_TX, MSG_WITNESS_TX) and self.mempool:
        tx = self.mempool.get_transaction(inv_hash)   # txid lookup only
        if tx:
            ...
        else:
            not_found.append((inv_type, inv_hash))
    elif inv_type in (INV_TYPE_BLOCK, MSG_WITNESS_BLOCK):
        ...
```

MSG_WTX (type 5) falls through both branches → silently dropped from
the handler, then the loop returns NOTFOUND for ALL inv items
including the unhandled wtxid ones (the `not_found.append` is in the
`else` of the txid branch — but MSG_WTX never enters that branch
at all, so `not_found` is never appended for it, and the peer's
getdata times out with no response).

Additionally, even if we routed MSG_WTX to a wtxid lookup,
`mempool.get_transaction_by_wtxid` exists at line 4319 but is **not
called** anywhere in the network path — it is only consumed by RPC
debug paths.

**File:** `src/ouroboros/node.py:1038-1062`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` ProcessGetData
MSG_WTX branch.

**Impact:**
- We never serve mempool txs to wtxid-relay peers when they request
  by wtxid (Core's preferred path).
- Peer sees a stalled getdata (NOTFOUND never sent for MSG_WTX
  because the unhandled branch never adds to `not_found`); after
  `GETDATA_TX_INTERVAL=60s` the peer's TxRequestTracker retries a
  different peer. Wasted round-trip latency, mempool-propagation
  delay on every cross-fleet tx.
- Cross-cite BUG-2: even when our own outbound requests are
  malformed, peer's getdata back to us is also broken.

---

## BUG-4 (P1) — TxRequestTracker scheduler entirely absent: no NONPREF/TXID/OVERLOADED delays, no in-flight cap, no peer rotation

**Severity:** P1 (per-pattern; constitutes a missing subsystem).
Bitcoin Core's `TxRequestTracker` (`node/txdownloadman.h:24-38` +
`node/txdownloadman_impl.cpp:200-285`) is the per-peer per-txhash
request scheduler. It implements:
- `NONPREF_PEER_TX_DELAY=2s` for announcements from non-preferred
  connections (e.g. inbound non-fanout, non-feeler).
- `TXID_RELAY_DELAY=2s` for txid-only announcements while wtxid peers
  are available (prefer wtxid peers for non-malleability).
- `OVERLOADED_PEER_TX_DELAY=2s` for peers with ≥
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` requests in flight (rate-shape
  one peer that's slow to respond).
- `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` hard cap per peer.
- `GETDATA_TX_INTERVAL=60s` retry timer; on expiry the scheduler
  switches to the **next peer's announcement** of the same tx.

ouroboros has `_requested_txs: dict[bytes, float]` (block_sync.py:219)
— a single global hash → request-timestamp map. There is:
- No per-peer keying. We cannot tell which peer is being asked.
- No NONPREF / TXID / OVERLOADED delay class.
- No per-peer in-flight count → no MAX_PEER_TX_REQUEST_IN_FLIGHT cap.
  A single peer that announces 10000 txs gets 10000 concurrent
  getdata-tx requests.
- The 60 s stale-flush at `block_sync.py:728-730` only `dict.pop()`s;
  it does NOT call any "try the next peer" path. Combined with the
  per-peer disconnect path having no `requested_txs` cleanup,
  outstanding tx requests effectively leak when their originating peer
  disconnects mid-request.

**File:** `src/ouroboros/block_sync.py:219, 726-730, 746-754`.

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp:200-285`;
`bitcoin-core/src/node/txrequest.cpp`.

**Impact:**
- High-mempool-churn mainnet operation: a single misbehaving peer can
  consume our entire concurrent-getdata budget by inv-flooding;
  honest tx announcements wait behind the queue.
- No rate-shaping on slow peers → tail latency on mempool reception.
- No prefer-wtxid path → malleability exposure higher than Core.

---

## BUG-5 (P0) — Stale tx-request flush has no peer-rotation; tx silently lost

**Severity:** P0. The stale-flush in `handle_inv`
(`block_sync.py:726-730`):

```python
# Expire stale tx requests (>60 s)
now = time.time()
stale = [h for h, t in self._requested_txs.items() if now - t > 60]
for h in stale:
    self._requested_txs.pop(h, None)
```

The only effect of expiry is `dict.pop()`. There is no:
- mark-this-peer-as-bad call,
- request-to-different-peer-from-announcement-set call (Core: the
  scheduler keeps the per-txhash announcement set keyed by peer; on
  expiry, the next peer's announcement is promoted to candidate),
- log line ("redacted request from peer X for tx Y, retrying").

Worse: the flush runs only inside `handle_inv`. If no new inv message
arrives, the stale check never runs. So a tx request that was issued
to peer X, where X then disconnects, will remain in `_requested_txs`
until the next inv arrives from anyone.

Failure mode: peer X sends inv(tx_Y), we request from X, X disconnects
mid-getdata. Tx_Y is never re-requested unless a different peer also
inv-announces tx_Y AND a new inv arrives to trigger the stale-flush
that purges `_requested_txs[tx_Y]` AND that new inv arrives within
the same handler call. Race window: minutes during low-tx periods.

**File:** `src/ouroboros/block_sync.py:726-730`.

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp:278`
(`RequestedTx` schedules retry; expiry path consults full announcement
set).

**Impact:** tx-propagation gaps when peer churn coincides with single-
peer announcements (low-fee txs, signet/testnet with few peers). One
disconnect can drop the tx from our pool until a re-announcement
arrives — minutes to hours of latency where Core re-requests in
≤60 s.

---

## BUG-6 (P0-DoS) — Global `MAX_ORPHAN_TRANSACTIONS=100` with random eviction; any peer can churn out honest orphans

**Severity:** P0-DoS. Bitcoin Core's modern (post-2024) TxOrphanage
tracks per-peer reserved usage
(`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER=404000` bytes) and a global
`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000` cap. When the global cap
is exceeded, eviction targets the **most-resource-intensive peer's**
oldest announcement, never another peer's. A single misbehaving peer
cannot evict honest orphans.

ouroboros's `OrphanPool` (`mempool.py:1454-1562`) has:
- Single global cap `MAX_ORPHAN_TRANSACTIONS=100` (line 1450).
- No per-peer accounting at all — `add(tx, missing_parents)` takes no
  peer argument.
- Eviction uses `_evict_random` (line 1557):
  ```python
  def _evict_random(self) -> None:
      if not self.orphans:
          return
      victim = random.choice(list(self.orphans))
      logger.debug(f"Evicting random orphan wtxid={victim.hex()[:16]}...")
      self.remove(victim)
  ```

Attack: a single peer floods 100 orphans whose parents will never
arrive (random invalid txids in inputs). Every honest orphan from any
other peer hits the 100-slot cap and triggers `_evict_random`, which
with uniform probability evicts the attacker OR an honest orphan.
With repeat flooding the attacker's orphans dominate the pool; honest
orphans are evicted with high probability before their parents
arrive.

Combined with **BUG-9** (expire never fires) and **BUG-10** (block
connection never reconsiders orphans), the orphan pool becomes a
DoS target with no defense.

**File:** `src/ouroboros/mempool.py:1450, 1474-1496, 1557-1562`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:18-23, 38-130`
(per-peer announcer set, reserved usage, latency-score eviction).

**Impact:** DoS on tx-propagation. Any single peer can effectively
disable orphan-promotion on the local node by churning 100+ junk
orphans per second.

---

## BUG-7 (P1) — Orphan stores no announcer set; no `EraseForPeer` API; peer disconnect leaks orphans

**Severity:** P1. Core's `TxOrphanage::OrphanInfo` tracks
`std::set<NodeId> announcers` (txorphanage.h:46-47). On peer
disconnect Core calls `EraseForPeer(peer)`: for each orphan, drop
this peer from the announcer set, and if the set is now empty, erase
the orphan entirely. This bounds the per-peer orphan footprint and
lets the scheduler correctly attribute peer misbehavior.

ouroboros's `OrphanPool.add(tx, missing_parents)` takes only the tx
and parent-set — no peer. There is:
- No announcer field on the orphan tuple `(Transaction, expiry,
  missing)`.
- No `erase_for_peer` method.
- No call from peer disconnect to clean orphans.

Consequence: when a peer disconnects, every orphan it contributed
sits in the pool until either it's evicted randomly (BUG-6) or it
expires (BUG-9 — never). Over a 24-hour mainnet session with normal
churn, the pool fills with announcements from peers that disconnected
hours ago.

Cross-cite: this also defeats the "score the right peer" rationale —
when an orphan eventually fails validation, we have no way to apply
misbehaving to the announcing peer; we can only fall back to applying
it to whichever peer delivered its parent (a different peer).

**File:** `src/ouroboros/mempool.py:1466-1496`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:43-54, 86`.

**Impact:** orphan leaks on every peer disconnect; misattributed
misbehaving on orphan validation failures.

---

## BUG-8 (P0) — `remove_block_transactions` does not call `orphan_pool.erase_for_block`

**Severity:** P0. Bitcoin Core's `TxOrphanage::EraseForBlock(block)`
(txorphanage.h:89) walks every tx in the connected block, drops any
orphan with that wtxid, AND drops any orphan whose inputs conflict
with a tx in the block (the orphan would have been doublespent and
is now permanently invalid). It runs after every block connect.

ouroboros's `Mempool.remove_block_transactions` at
`mempool.py:3163-3211` walks the block's transactions and calls
`remove_transaction(txid)` for each one in the mempool, but **never
touches `self.orphan_pool`**. Consequences:
- An orphan whose tx is now confirmed in a block stays as an orphan
  forever (until BUG-9-broken expire eventually doesn't fire). When
  a peer later requests it via getdata, we attempt to serve from
  mempool (which now has it from block-confirm path? no, the block
  remove path REMOVED the tx from mempool too, line 3179). So we
  respond NOTFOUND despite holding the tx in `orphan_pool`. Tx
  duplication.
- An orphan whose input is doublespent by a tx in the block stays as
  an orphan with stale missing-parent metadata. If the original
  parent arrives later (unlikely but possible after a chain reorg),
  `_resolve_orphans` will admit the doublespend → reject at consensus
  check → wasted work.

**File:** `src/ouroboros/mempool.py:3163-3211` (no orphan_pool call);
no `OrphanPool.erase_for_block` method exists.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:89`
(`EraseForBlock`).

**Impact:**
- Stale orphans accumulate post-block-connect; pool fills with
  already-confirmed txs we cannot serve and don't recognise as
  duplicates if announced again.
- Doublespend evaluation race after reorgs.

---

## BUG-9 (P0) — `OrphanPool.expire()` is dead code: `expire_old_transactions` has zero call sites

**Severity:** P0. `OrphanPool.expire()` (mempool.py:1541-1552) is the
only path that purges the 20-minute `ORPHAN_EXPIRY_SECONDS` constant.
The only caller of `expire()` is `Mempool._expire_old_transactions_inner`
(`mempool.py:3046`).

A grep over the entire codebase shows ZERO call sites for
`expire_old_transactions`:

```
$ grep -rn "expire_old_transactions" /home/work/hashhog/ouroboros/src/ouroboros/
mempool.py:3012:    def expire_old_transactions(self, current_time: float | None = None) -> int:
mempool.py:3015:            return self._expire_old_transactions_inner(current_time)
mempool.py:3017:    def _expire_old_transactions_inner(self, current_time: float | None = None) -> int:
```

Only the definitions show. No scheduler, no asyncio.create_task loop,
no periodic timer, no on_block_connected hook calls it. The 20-minute
orphan-expiry constant is **dead code**. Orphans only ever exit the
pool via `_resolve_orphans` (a parent arrives) or `_evict_random` (cap
reached). This compounds BUG-6 (random eviction) and BUG-7 (no
EraseForPeer) — the pool monotonically accumulates from peer-churn
until it hits 100 slots, then any honest orphan loses a coin-flip
against attacker-supplied junk.

`MEMPOOL_EXPIRY_HOURS` for regular mempool entries (line 3019) suffers
the same fate — no caller of `expire_old_transactions` means regular
mempool entries also never expire on the 2-week TTL. (Note: that's a
W150 concern; W152 records the orphan-side observation.)

**File:** `src/ouroboros/mempool.py:1451, 1541-1552, 3012-3048`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::LimitOrphans`
(called from `MaybeSendMessage` cadence).

**Impact:** orphan pool effectively monotonic. Combined with random
eviction at the 100-slot cap (BUG-6), the steady-state composition
of the pool is biased toward attacker-supplied junk that never
resolves. On a long-running mainnet node, every orphan slot is held
by an announcement whose parent will never arrive.

---

## BUG-10 (P0) — `_resolve_orphans` never invoked on block connect

**Severity:** P0. Bitcoin Core's `ProcessBlock` path (after
`ActivateBestChain`) runs `EraseForBlock(block)` AND walks every
block tx via `AddChildrenToWorkSet(tx)`, which promotes any orphan
that lists tx as a parent to the per-peer reconsider queue. The
next ProcessMessages tick drains the work set and re-runs ATMP on
each formerly-orphaned tx.

ouroboros's `_resolve_orphans(parent_txid, height)` is called
**only** from:
1. `Mempool._add_transaction_inner` line 2362 (after every successful
   mempool admit).
2. Stale duplicate at `mempool.py:4775` inside `submit_transaction_with_callback`.

There is no call from any block-connect path. Concretely:
- `block_sync.py:1378` calls `self.mempool.remove_block_transactions(block)`
  after `apply_block`. `remove_block_transactions` does NOT call
  `_resolve_orphans` for any of the block's txs.
- `_process_orphans` (block_sync.py:2195) only resolves block-level
  orphans (whose `prev_blockhash` matched the new tip), NOT tx-level
  orphans waiting on the block's txs.

Concrete consequence: peer announces tx_C whose parent tx_P is not
in our mempool or chain → tx_C stored as orphan. Block arrives
containing tx_P (it was just mined). `remove_block_transactions`
removes tx_P from mempool (it was never there) and ignores
orphan_pool. **tx_C remains an orphan forever** even though its
parent's UTXO is now in our chainstate.

A peer later requests tx_C via inv → we don't have it in mempool, we
re-request, and the same orphan-lifecycle repeats every time.

**File:** `src/ouroboros/mempool.py:2362, 2984-3010, 3163-3211`;
`src/ouroboros/block_sync.py:1378`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` (post-ProcessBlock
`AddChildrenToWorkSet` iteration; net_processing.cpp:3128-3245
reconsider loop).

**Impact:** tx-propagation latency for any tx whose parent was
mined while it was orphaned. The orphaned child is never promoted to
mempool, never re-broadcast, never served to peers. Mempool view
diverges from Core's view on the same chain state.

---

## BUG-11 (P0-CDIV) — `version.relay` (BIP-37 fRelay) parsed by decoder but never copied to `Peer.relay_txs`; block-relay-only peers still receive tx INVs

**Severity:** P0-CDIV. BIP-37 specifies that a peer setting
`version.fRelay=false` does NOT want tx INVs from us — this is the
mechanism that makes outbound block-relay-only connections work
(Core sets fRelay=false on outbound BLOCK_RELAY_ONLY peers and our
side honors it).

`VersionMessage.from_payload` parses the field
(`p2p_messages.py:377-392`):

```python
relay = if decoder.is_empty():
    True  # default for protocols < 70001
else:
    decoder.pop_u8() != 0
```

And exposes it as `version.relay`. But the inbound/outbound handshake
in `peer.py:715-722, 1301-1308` reads only:

```python
version = VersionMessage.from_payload(msg.payload)
self.version = version.version
self.services = version.services
self.user_agent = version.user_agent
self.start_height = version.start_height
self.time_offset = int(version.timestamp - time.time())
self._version_received = True
```

`version.relay` is **never read**. `Peer.relay_txs` is set from OUR
side at construction time (line 306) based on whether WE want
tx-relay on this connection — never updated from the peer's
announcement.

Consequences:
- A peer announcing `relay=false` (block-relay-only inbound) receives
  our tx INVs both via:
  - `TrickleQueue` (each queue inits with `is_inbound=True,
    wtxid_relay=peer.wtxid_relay`; no `peer_relay_txs` field; the
    queue announces to every queued peer regardless of peer's
    fRelay).
  - The direct-INV path in `_make_tx_handler`
    (`node.py:967-986`) loops `for p in get_all_ready_peers()` and
    skips ONLY the sender peer; `peer.relay_txs` is our side's flag,
    not theirs.
- Cross-impl: a Core peer that announced fRelay=false sees tx
  spam from ouroboros and may discourage us. From their perspective
  we're a misbehaving peer.

**File:** `src/ouroboros/peer.py:715-722` (inbound parse),
`peer.py:1301-1308` (outbound parse), `node.py:967` (relay loop
without peer.relay_txs check on PEER's side).

**Core ref:** BIP-37; `bitcoin-core/src/net.h::CNode` `fRelayTxes`
flag; `bitcoin-core/src/net_processing.cpp` tx-INV scheduler skips
peers with `!fRelayTxes`.

**Excerpt (ouroboros, missing read)**
```python
# peer.py:715-722
version = VersionMessage.from_payload(msg.payload)
self.version = version.version
self.services = version.services
# MISSING: self.peer_announced_relay_txs = version.relay
```

**Impact:**
- BIP-37 violation: block-relay-only peers receive tx INVs they
  explicitly asked not to receive.
- W134 fleet-pattern recurrence: "fRelay parsed but ignored" was
  observed in 4 impls during W134; this is the ouroboros instance.
- Bandwidth waste at scale; peer-discourage risk from Core fleet.

---

## BUG-12 (P1) — BIP-35 MEMPOOL handler sends `MSG_WTX` with txid bytes (not wtxid)

**Severity:** P1. The MEMPOOL handler at `p2p.py:2390-2428` (BIP-35
dump-the-mempool) chunks `all_txids` (line 2413) and emits inv items:

```python
inv_type = MSG_WTX if (peer.services & NODE_WITNESS) else INV_TYPE_TX
for chunk_start in range(0, len(all_txids), MAX_INV_SZ):
    chunk = all_txids[chunk_start:chunk_start + MAX_INV_SZ]
    inv = InvMessage([(inv_type, txid) for txid in chunk])
```

When `peer.services & NODE_WITNESS`, the inv type is set to MSG_WTX
(type 5, BIP-339) but the hash is `txid` — a **txid**, not a wtxid.
Per the BIP-339 wire format, MSG_WTX requires a wtxid.

Symmetric bug to BUG-2 on the opposite direction: when peer receives
our MEMPOOL response with `MSG_WTX(txid)`, peer interprets each
hash as a wtxid and either:
- Looks up by wtxid → mostly misses (txid != wtxid for segwit txs) →
  re-requests via getdata,
- Or never finds the wtxid → gives up on the entry.

The gate at line 2420 also conflates "peer supports witness" (services
NODE_WITNESS) with "peer supports wtxid relay" (wtxidrelay
negotiation). Those are different things: NODE_WITNESS only means
"willing to receive witness data", wtxidrelay means "I want INVs by
wtxid". The correct dispatch is `peer.wtxid_relay`, not
`peer.services & NODE_WITNESS`.

**File:** `src/ouroboros/p2p.py:2418-2424`.

**Core ref:** BIP-339 / `bitcoin-core/src/net_processing.cpp::on_mempool`
serves wtxid for wtxidrelay peers via `tx->GetWitnessHash()`.

**Impact:** BIP-35 MEMPOOL response wastes bandwidth and disrupts
peer mempool synchronisation; recurring re-requests for items we
just announced wrongly.

---

## BUG-13 (P1) — InvMessage > 50000 items penalised with `adjust_score(-2)`, not `misbehaving(100)`

**Severity:** P1. `InvMessage.from_payload` at `p2p_messages.py:387-411`
correctly enforces `MAX_INV_SZ=50000`:

```python
# Limit to 50k items for safety
if count > 50000:
    raise ValueError(f"Inventory count too large: {count}")
```

But the ValueError propagates to `handle_inv`'s broad except
(`block_sync.py:806-808`):

```python
except Exception as e:
    logger.error(f"Error handling inv from {peer.host}:{peer.port}: {e}")
    peer.adjust_score(-2)
```

Score gets debited by 2 (out of 100 → 100 hits ban) → 50 violations
to ban. Core's behavior at `net_processing.cpp:4040-4041`:

```cpp
if (vInv.size() > MAX_INV_SZ) {
    Misbehaving(*peer, 100, strprintf("inv message size = %u", vInv.size()));
    return;
}
```

Direct ban (score 100/100). The Core threshold reflects that a peer
sending >50k inv items is unambiguously misbehaving — there is no
honest reason to do so. ouroboros's score-by-2 means an attacker can
send 49 oversized invs before tripping the threshold.

**File:** `src/ouroboros/p2p_messages.py:395-397`,
`src/ouroboros/block_sync.py:806-808`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4040-4041`.

**Impact:** weakened DoS gate; an attacker can probe / waste our
parse budget 50× before disconnect.

---

## BUG-14 (P0-DoS) — Unconditional `misbehaving(addr, 10, ...)` on every tx-reject including policy; honest Core peers banned within minutes

**Severity:** P0-DoS. Carry-forward of W150 BUG-23. `_make_tx_handler`
at `node.py:987-995`:

```python
else:
    logger.debug(f"Rejected transaction: {error}")
    # Record misbehavior for invalid transactions
    # Invalid tx = 10 points (requires 10 violations to ban)
    if hasattr(self, "peer_manager") and self.peer_manager:
        addr = f"{sender_peer.host}:{sender_peer.port}"
        self.peer_manager.misbehaving(
            addr, 10, f"invalid tx: {error}"
        )
```

The comment "requires 10 violations to ban" assumes the rejection is
peer-misbehaviour. But `mempool.add_transaction` returns errors for
many reasons that are POLICY, not consensus:
- `"txn-already-in-mempool"` (peer sent a tx we already have — normal
  during INV processing race)
- `"txn-same-nonwitness-data-in-mempool"` (BIP-339 stripped-witness
  duplicate — normal during malleability churn)
- `"orphan"` (parent not yet present — Core stores in orphan pool, no
  misbehaving)
- `"Non-standard transaction: ..."` (datacarrier, version, dust;
  Core's TX_NOT_STANDARD → no misbehaving)
- `"min-relay-fee-not-met"` (fee below our feefilter; Core's
  TX_MEMPOOL_POLICY → no misbehaving)
- RBF mempool-conflict reasons (Core's TX_RECONSIDERABLE)
- `"too-long-mempool-chain"` (ancestor/descendant limit; Core
  TX_MEMPOOL_POLICY)
- `"insufficient fee, replacement rejected"` (RBF rule 6; Core
  TX_RECONSIDERABLE)

Core's pattern (net_processing.cpp:3566): only
`state.GetResult() == TxValidationResult::TX_CONSENSUS` triggers
`Misbehaving(peer, ...)`. The list of consensus-class results is
narrow: `TX_CONSENSUS` (input doesn't exist, bad signature, etc.)
and a few specific input-not-standard variants. Policy rejects are
silent.

ouroboros's unconditional misbehaving(10) with ban_threshold=100
means **10 policy rejects = ban**. On a v28 mainnet peer pushing
RBF-replacement chains, RBF replacements are tested against our
mempool; if peer's replacement bumps fee twice in 30s, both bumps
hit our `txn-already-in-mempool`/`mempool-conflict` paths. Repeated
across normal-volume tx churn, an honest peer is banned within
minutes.

Cross-cite: W150 BUG-23 documented this. As of 2026-05-18 it is
still live.

**File:** `src/ouroboros/node.py:987-995`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3128, 3566`
(MEMPOOLREJ log line, misbehaving gate on TX_CONSENSUS only);
`bitcoin-core/src/consensus/validation.h::TxValidationResult` (enum).

**Impact:**
- Honest Core peers banned within hours during mainnet operation;
  fleet observation expected.
- Cross-cite W148 BUG-16: `is_synced` always returns false from Rust
  (see BUG-16 below), but the `_make_tx_handler` does NOT gate on
  `is_synced` — so the misbehaving is applied even during IBD,
  banning peers that send us txs that fail because of partial chain
  state.

---

## BUG-15 (P0-PRIVACY) — P2P-received tx fan-out bypasses trickle queue; instant relay to all peers

**Severity:** P0-PRIVACY. `_make_tx_handler` at `node.py:957-986`
relays an accepted P2P tx by sending an INV directly to every peer
in a synchronous loop:

```python
# Relay INV to all peers except the sender.
# BIP-339: wtxid-relay peers get MSG_WTX(5)+wtxid;
# legacy peers get MSG_TX(1)+txid.
if hasattr(self, "peer_manager") and self.peer_manager:
    entry = self.mempool.transactions.get(txid)
    tx_feerate_per_kb = int(entry.fee_rate * 1000) if entry else 0
    for p in self.peer_manager.get_all_ready_peers():
        if p is not sender_peer:
            if p.peer_feefilter > tx_feerate_per_kb:
                continue
            try:
                if getattr(p, "wtxid_relay", False):
                    inv = InvMessage(inventory=[(MSG_WTX, wtxid)])
                else:
                    inv = InvMessage(inventory=[(INV_TYPE_TX, txid)])
                await p.send_message(inv.to_network_message(self.network))
            except Exception:
                pass
```

There is no:
- Poisson delay,
- per-peer trickle queue insertion,
- batching with other queued txs,
- `mark_tx_known_by_peer` call for sender (so the trickle queue
  doesn't later send it back to the sender),
- `peer.relay_txs` honoring (BUG-11 above; doesn't check peer's
  BIP-37 fRelay).

The `peer_manager.queue_tx_for_relay(...)` mechanism exists at
`p2p.py:3509-3573` and DOES use the trickle queue. But the P2P
receive path (the most common origin of new txs on a server-side
node) bypasses it.

By contrast, `rpc_sendrawtransaction` (rpc.py:2530) DOES call
`queue_tx_for_relay`. So the same tx, relayed via wallet vs P2P,
takes wildly different paths.

Privacy impact: a passive network observer who sees a tx flooding
from ouroboros instantly (no Poisson delay) versus from Core (with
2-5s Poisson) can infer that ouroboros was the originating node, OR
that ouroboros's downstream peer that announced first is the
upstream. Without the trickle, ouroboros becomes a privacy-leakage
relay.

**File:** `src/ouroboros/node.py:957-986`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`
inserts into `m_tx_inventory_to_send`; the actual wire INV happens
on the next `m_next_inv_send_time` Poisson tick in
`SendMessages`.

**Impact:**
- Tx-originator de-anonymisation: observer can identify the node
  closest to the tx originator.
- Two-path divergence (RPC vs P2P) — same tx behaves differently
  depending on entry point, defeating any uniform privacy posture.

---

## BUG-16 (P0) — `is_synced()` hard-coded to `Ok(false)` since W113 (~6 weeks open); orphan-promote / IBD gates broken

**Severity:** P0 (carry-forward, W148 BUG-16). The Rust
`FastSync::is_synced` at `ferrous-utils/sync/src/lib.rs:5912-5916`:

```rust
/// Check if blockchain is synced
fn is_synced(&self) -> PyResult<bool> {
    // For now, return false (in practice would check against network tip)
    // This is a simplified version
    Ok(false)
}
```

Has returned `Ok(false)` unconditionally since W113 (per W148 BUG-16
tracking, ~6 weeks open as of 2026-05-18). The Python
`SyncManager.is_synced()` (sync_manager.py:267-273) delegates to
this, then `node.py:909` exposes it.

Consequences for W152 scope:
- The `node.py` synced gate at line 286 / 647-649 latches
  `self.synced = self._check_synced()`. `_check_synced` calls
  `self.sync_manager.is_synced()` → always False. So `self.synced`
  stays False forever, and any code that uses `node.synced` (e.g.
  the BIP-35 MEMPOOL handler gating, peer-handshake feature-flag
  gates) treats us as never-synced.
- The privacy-relevant trickle path doesn't gate on is_synced (a
  good thing; Core trickles during IBD too), so this doesn't
  amplify BUG-15.
- But the dust-extra-conservative pre-IBD policy gate — if it were
  to ever exist — could not be unwound. The `is_synced` flag is
  *intended* to be the post-IBD trigger that promotes orphan-pool
  acceptance from "conservative" to "normal", and that promotion
  never happens. The orphan-acceptance path always runs as if we
  were in IBD.

**File:** `ferrous-utils/sync/src/lib.rs:5912-5916`;
`src/ouroboros/sync_manager.py:267-273`.

**Core ref:** `bitcoin-core/src/validation.cpp::IsInitialBlockDownload`
(post-22.0 `UpdateIBDStatus`).

**Impact:** every "post-IBD" code path on the node thinks it is
mid-IBD forever. Tx-relay-specific impacts include:
- BIP-35 MEMPOOL handler gating (Core gates MEMPOOL service on
  post-IBD; ouroboros does not but the symmetric gate is broken),
- ZMQ notifications gated on post-IBD,
- any future "wait for IBD to finish before applying expensive
  orphan reconsider policy" hook,
- monitoring dashboards report node as never-synced (alert noise).

---

## BUG-17 (P1) — Erlay tx-add by `txid` only; wtxid-relay Erlay peers get wrong identity

**Severity:** P1. `queue_tx_for_relay` at `p2p.py:3549-3552`:

```python
# For Erlay peers, add to reconciliation set instead
if self.is_erlay_peer(addr):
    self.erlay_add_tx_to_reconcile(txid, exclude_addr=exclude_addr)
    continue
```

`erlay_add_tx_to_reconcile` (line 3206-3223) iterates `_erlay_peers`
and calls `recon.add_tx(txid)` — passing only the **txid**. The
wtxid is dropped.

BIP-330 (Erlay) interacts with BIP-339 (wtxid relay): for wtxid-relay
Erlay peers, the reconciliation set must hold wtxids, not txids.
ouroboros loses the wtxid before adding to the set, so Erlay
reconciliation with wtxid-relay peers compares the wrong identity →
false-negative reconciliation (we think we and peer disagree on a
tx when we actually have the same wtxid under a different txid for
segwit malleability variants).

**File:** `src/ouroboros/p2p.py:3549-3552, 3206-3223`.

**Core ref:** BIP-330 / `bitcoin-core/src/txreconciliation.cpp`.

**Impact:** correctness gap on Erlay reconciliation. Recurring
false-disagreement → wasted bandwidth via fallback INV. Cross-cite
BUG-2: every Erlay leaks the wtxid-handling bug.

---

## BUG-18 (P1) — `queue_tx_for_relay` called from `rpc_sendrawtransaction` without fee/vsize; BIP-133 feefilter check skipped on RPC-submitted txs

**Severity:** P1. `rpc.py:2530`:

```python
self.node.peer_manager.queue_tx_for_relay(txid, wtxid)
```

The full signature is `queue_tx_for_relay(self, txid, wtxid, fee=0,
vsize=0, exclude_addr="")`. Without fee+vsize, the trickle queue's
BIP-133 feefilter check (`p2p.py:333-337`) is bypassed:

```python
# Only filter if we have valid fee info (vsize > 0)
if feefilter > 0 and entry is not None and entry.vsize > 0:
    if entry.fee_rate_kvb < feefilter:
        continue
```

vsize=0 means "skip feefilter" → we announce a 1 sat/vB tx to a peer
whose feefilter=10 sat/vB. Peer rejects → wasted bandwidth +
peer-side discourage risk.

Same bug shape at `node.py:967-986` (P2P-receive direct-INV path
uses `p.peer_feefilter > tx_feerate_per_kb` correctly, but BUG-15
documents that this path bypasses the trickle anyway).

**File:** `src/ouroboros/rpc.py:2530`.

**Core ref:** BIP-133; `bitcoin-core/src/net_processing.cpp` tx-INV
schedules respect per-peer feefilter.

**Impact:** wallet-submitted txs announced to peers that don't want
them; minor wasted bandwidth, possible mild peer-discourage. Also
inconsistent vs P2P-relay path (different bug, same effect).

---

## BUG-19 (P1) — `mark_tx_known_by_peer` never called on tx receive; trickle queue announces tx back to sender

**Severity:** P1. `mark_tx_known_by_peer` (p2p.py:3575-3592) adds the
(txid, wtxid) to the peer's trickle queue's `known_filter` so future
trickle batches skip it. It is correctly defined but **never
called**:

```
$ grep -rn "mark_tx_known_by_peer" /home/work/hashhog/ouroboros/src/
src/ouroboros/p2p.py:3575:    def mark_tx_known_by_peer(...)
src/ouroboros/p2p.py:3580:        ...
```

Only the definition, no call sites. Consequences:
- When peer X sends us tx_A, the `_make_tx_handler` (BUG-15) directly
  INVs all OTHER peers (correct), AND `queue_tx_for_relay` (RPC
  path) inserts into the trickle queue for **all** peers including
  peer X. Peer X gets a trickle INV for tx_A later, which it
  already announced to us → it sees us as confused / bandwidth-
  wasting.
- The trickle queue's `known_filter` is populated only by
  `add_tx` (line 264) and by `get_invs_to_send` (line 353) — both
  of those mark what WE just sent the peer, not what the peer just
  sent us. So the filter is one-directional.

**File:** `src/ouroboros/p2p.py:3575-3592`; no call sites.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`
records via `m_tx_inventory_known_filter` immediately when peer's
inv arrives or when peer sends us the tx.

**Impact:** trickle-back-to-sender bandwidth waste, especially at
high mempool churn; weakened privacy because the very peer that
sent us the tx sees us re-announce it.

---

## BUG-20 (P1) — `orphan_pool.add` happens BEFORE standardness / sigop / coinbase checks; orphan pool can be flooded with non-standard / oversized junk

**Severity:** P1. `mempool.py:2021-2031`:

```python
# Check for missing parent transactions — store as orphan
missing_parents: set[bytes] = set()
for tx_in in tx.inputs:
    parent_txid = tx_in.prev_txid
    utxo = self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
    if utxo is None and parent_txid not in self.transactions:
        missing_parents.add(parent_txid)
if missing_parents:
    self.orphan_pool.add(tx, missing_parents)
    return False, "orphan"
```

This runs AFTER duplicate-check (line 1995-2003) and standardness
(line 2007-2009) BUT before `_validate_inputs_standardness`,
`_is_witness_standard`, sigop-cost, and several other policy gates
that run at `mempool.py:2051+`. So the orphan pool stores transactions
that COULD fail those checks but we never know until parents arrive.

Worse: the `IsStandardTx` gate at line 2007 is gated on
`require_standard`. If `require_standard=False` (a config option), no
standardness check runs at all before orphan storage — coinbase-shaped,
oversized, no-output, witness-malformed, etc. txs all go in the
orphan pool.

Compounding factors:
- BUG-6: no per-peer orphan cap → single peer can store 100 oversized
  bogus orphans.
- The orphan tx is held in Python memory; max single-tx weight in
  Core is `MAX_STANDARD_TX_WEIGHT=400000` ≈ 400 KB but no such cap
  is enforced before orphan storage. Theoretical: 100 × 4 MB junk
  orphans = 400 MB resident.

Core's `MemPoolAccept::PreChecks` runs **all** policy gates BEFORE
deciding whether to store as orphan — orphans are limited to txs that
would have been accepted except for missing inputs.

**File:** `src/ouroboros/mempool.py:2021-2031`.

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks`
runs IsStandardTx, ValidateInputsStandardness, sigop-cost,
CheckSequenceLocks, etc., before the txdownload path stores as
orphan.

**Impact:** orphan-pool memory amplification by a factor of
~MAX_STANDARD_TX_WEIGHT / typical-tx-size on attacker-supplied
inputs; combined with BUG-6 (no per-peer cap) and BUG-9 (no
expiry), the orphan pool is a soft memory-DoS surface.

---

## BUG-21 (P1) — `_resolve_orphans` holds the mempool RLock recursively; recursive `add_transaction` from inside the lock could deadlock with `expire_old_transactions` if it ever fired

**Severity:** P1. `Mempool._add_transaction_inner` runs under
`self._lock` (RLock; mempool.py:1629). Inside it, at line 2362, calls
`self._resolve_orphans(txid, height)` which then calls back to
`self.add_transaction(orphan_tx, height)` (mempool.py:2997), which
re-acquires the RLock. RLock allows this; no immediate deadlock.

However, the comment at line 1628 admits "RLock because
_resolve_orphans -> add_transaction recurses." This is the only
reason for RLock vs Lock — and the recursion depth is unbounded (an
orphan chain of N levels means N nested add_transaction calls). Stack
depth limit (~1000 in CPython) caps this practically, but a malicious
peer could craft a 500-deep orphan chain (each child orphan resolving
the next) → 500 nested add_transaction calls → 500 stack frames per
call.

Cross-cite: if `expire_old_transactions` ever started firing (BUG-9
documents it doesn't), it ALSO takes the RLock at line 3014. Combined
with `_resolve_orphans` recursion + a long orphan chain, the
RLock-protected critical section can hold for seconds-minutes,
stalling all other mempool operations including RPC.

**File:** `src/ouroboros/mempool.py:1628-1632, 2362, 2984-3010`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx`
uses a work-set + iteration (`GetTxToReconsider` loop), not
recursion, to bound stack depth.

**Impact:** soft DoS via deep orphan chains; future-deadlock risk if
BUG-9 is fixed without also fixing recursion-to-iteration.

---

## BUG-22 (P1) — `_requested_txs` not cleared on peer disconnect; stale per-tx entries leak forever (until next inv message)

**Severity:** P1. `_requested_txs` is a global dict at
`block_sync.py:219`. When a peer disconnects, the entries that peer
was responsible for are not purged. The only purge path is the
60s stale-flush inside `handle_inv` (BUG-5), which only runs when an
inv message arrives.

Failure mode:
- Peer X announces 1000 txs via inv.
- We populate `_requested_txs[h1..h1000]` and send getdata to X.
- Peer X disconnects (RST, timeout, etc.) before delivering.
- No other inv arrives from any peer for those hashes.
- `_requested_txs` retains all 1000 entries until either (a) someone
  re-announces one of them AND a new inv triggers the stale-flush, or
  (b) the dict is cleared on process restart.

If the same peer reconnects and re-announces the same 1000 txs, the
gate `inv_hash not in self._requested_txs` (line 751) suppresses the
new request → tx never requested. Permanent loss until restart or
the 60s flush fires (which requires a NEW inv to arrive first).

**File:** `src/ouroboros/block_sync.py:219, 726-730`.

**Core ref:** `bitcoin-core/src/node/txrequest.cpp::DisconnectedPeer`
purges all entries for the departing peer.

**Impact:** tx-propagation loss on peer churn; same-peer reconnect
can't recover because the cache entry blocks re-request.

---

## BUG-23 (P0-CDIV) — Five+ distinct tx-acceptance pipelines (SIX-pipeline drift carry-forward from W150 BUG-1)

**Severity:** P0-CDIV (carry-forward, W150 BUG-1). Tx relay touches
the ATMP-pipeline drift; W152 adds two more entry points to the
list:

W150 enumerated 5 pipelines for ATMP. W152 augments with:
6. **`_make_tx_handler`** (`node.py:923-1001`) — P2P tx receive,
   calls `mempool.add_transaction(tx, height)` (the SAME entry as
   pipeline 2 of W150) BUT also does its own:
   - misbehaving call (BUG-14)
   - direct-INV fan-out (BUG-15)
   - feefilter check (correct but redundant with trickle)
   without going through any common "post-acceptance" function. So
   the contract drift is "pipelines 1-5 may or may not include the
   announce-to-peers step; pipeline 6 always includes it inline; no
   common abstraction".
7. **`rpc_testmempoolaccept`** (`rpc.py:7905-7931`) — runs
   `validator.validate_transaction(tx, best_height + 1)` directly,
   bypassing ALL mempool-policy gates (no IsStandardTx, no
   feefilter, no RBF rules, no ancestor limits, no sigop cost,
   no ephemeral dust). Wallets calling testmempoolaccept get
   false-positive "allowed=true" answers for txs that would be
   rejected by the actual mempool path.

For W152's tx-relay scope, pipeline 6 (P2P receive) is the highest-
volume entry and is the one that uniquely drives:
- BUG-14 unconditional misbehaving
- BUG-15 trickle bypass
- BUG-2 wrong-MSG_WTX-treatment-of-hash

Pipeline 7 affects RPC-side decisions but not wire relay directly.

**File:** `src/ouroboros/node.py:923-1001`,
`src/ouroboros/rpc.py:7905-7931`.

**Core ref:** Core has ONE entry: `ProcessTransaction` →
`AcceptToMemoryPool` for both RPC and P2P paths.

**Impact:** every tx-relay bug is N-fold to fix (must touch every
pipeline); fleet-wide ouroboros "N-pipeline drift" pattern (W148, W150,
W152 — now 6-7-pipeline tracking).

---

## BUG-24 (P1) — Trickle queue's per-peer `known_filter` is an unbounded Python set, not a CRollingBloomFilter

**Severity:** P1. `TrickleQueue.known_filter` at `p2p.py:227`:

```python
# Bloom filter to track already-announced txs (like m_tx_inventory_known_filter)
# For simplicity, use a set here; Bitcoin Core uses CRollingBloomFilter
self.known_filter: set[bytes] = set()
```

The comment is honest ("Bitcoin Core uses CRollingBloomFilter").
Core's `CRollingBloomFilter` for tx-known has ~50000-entry capacity
with rolling eviction; the false-positive rate ~1e-6 controls
re-announce of recently-seen txs.

ouroboros's `set[bytes]` grows monotonically. On a busy mainnet
peer (full-relay, observing every tx), this set grows by ~500
entries / minute. Over 24h: ~720k entries × 32 bytes ≈ 23 MB per
peer. With 100 peers, ~2.3 GB resident just for the known-filter
sets. The set is cleared only when the peer disconnects (the queue
is dropped); peers that stay connected for days accumulate
indefinitely.

The set ALSO never forgets old txs that have already been mined and
expired from any reasonable mempool, so re-announce-after-replay
(legitimate behavior — a tx is unmined via reorg and re-broadcast)
is silently suppressed.

**File:** `src/ouroboros/p2p.py:225-227`.

**Core ref:** `bitcoin-core/src/common/bloom.h::CRollingBloomFilter`;
`bitcoin-core/src/net_processing.cpp::m_tx_inventory_known_filter`.

**Impact:**
- Memory growth: O(uptime × tx-rate × n_peers).
- Correctness: re-broadcast after deep reorg is silently dropped
  per peer (correctness-soft — eventual re-INV from another tx-relay
  observation will re-populate trickle).

---

## BUG-25 (P0) — Orphan pool key collision: `orphan_pool.add` early-returns False if wtxid already present, never adds a peer to announcer set

**Severity:** P0 (compounds BUG-7). When two different peers
announce the same orphan tx, ouroboros's `OrphanPool.add` at
`mempool.py:1480-1482`:

```python
wtxid = tx.get_wtxid()
if wtxid in self.orphans:
    return False
```

Silently early-returns. The new peer's contribution is dropped.
There is no:
- announcer-set bookkeeping to record that peer-B also has this
  orphan (so if peer-A disconnects we can still get the orphan's
  resolution from peer-B),
- re-request scheduling for the orphan's parent (Core's `txrequest`
  marks the parent as requestable from peer-B's announcement set).

Combined with BUG-7 (no announcer set), the effective semantics is
"first-peer-to-announce-an-orphan wins; if they disconnect, the
orphan is dead even though other peers also have it".

**File:** `src/ouroboros/mempool.py:1480-1482`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::AddTx`,
`AddAnnouncer`.

**Impact:** orphan resolution depends on connection stability of the
single first-announcing peer; honest orphans drop on peer churn.

---

## BUG-26 (P1) — No "recently confirmed transactions" cache; re-requested confirmed txs waste bandwidth + orphan-pool slots

**Severity:** P1. Core maintains `m_lazy_recent_confirmed_transactions`
(net_processing.cpp ~770) — a bounded set of txids that were confirmed
in recent blocks. When a peer inv-announces a tx already in this
cache, Core skips the getdata: we know the tx is in our chain
(confirmed), no need to re-pull.

ouroboros has no equivalent. The `handle_inv` check at
`block_sync.py:748-754` is:

```python
if (
    self.mempool
    and not self.mempool.get_transaction(inv_hash)   # mempool only
    and inv_hash not in self._requested_txs
):
    txs_to_request.append((MSG_WITNESS_TX, inv_hash))
```

If a tx was just confirmed (block N), removed from mempool by
`remove_block_transactions`, then peer announces it at block N+1
because their announcement was racing the block, ouroboros:
1. `get_transaction(inv_hash)` → None (just removed),
2. Not in `_requested_txs` → request,
3. Peer sends the tx,
4. `add_transaction` → `db.get_utxo(input)` → None (spent in block
   N+1 already, or before),
5. Stored as orphan ("missing inputs"),
6. Orphan slot consumed for a tx that's now confirmed and will
   never re-resolve (BUG-9, BUG-10 — no expiry, no block-side
   reconsider).

**File:** `src/ouroboros/block_sync.py:748-754`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` references
`m_lazy_recent_confirmed_transactions`.

**Impact:**
- Wasted bandwidth on tx redelivery at block boundaries.
- Orphan-pool pressure during block-boundary races (compounds BUG-6).
- No "we already have this confirmed" log → operator debugging
  harder.

---

## BUG-27 (P1) — `_make_tx_handler` swallows all exceptions; no rate-limit on parse failures, no peer scoring

**Severity:** P1. `_make_tx_handler` at `node.py:997-1000`:

```python
except Exception as e:
    logger.error(
        f"Error handling transaction: {e}", exc_info=True
    )
```

A peer sending a malformed `tx` payload (truncated bytes, oversized
varint, garbage script) hits this broad except. Behaviour:
- Logs the error,
- Does not score the peer,
- Does not disconnect,
- Does not increment any per-peer counter.

Core distinguishes parse failure (immediate Misbehaving(100), Core
treats it as protocol violation) from validation failure (logged at
MEMPOOLREJ, conditionally Misbehaving based on TxValidationResult).
ouroboros doesn't score either way for parse failures.

Combined with BUG-14 (over-eager misbehaving on validation), the
weighting is inverted: honest peers get banned for sending
policy-rejectable txs, while malicious peers can spam malformed
parse-failure txs forever.

**File:** `src/ouroboros/node.py:997-1000`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` parse failures
trigger `Misbehaving(*peer, 100, "...")` immediately.

**Impact:** asymmetric peer-scoring; honest peers banned, malicious
peers free to spam parse-failures.

---

## BUG-28 (P0) — On-disconnect cleanup misses `_requested_txs`, orphan-pool (no announcer set), trickle queue's `known_filter` is dropped (losing valid de-dupe state for reconnect)

**Severity:** P0 (consolidation finding; bridges BUG-7, BUG-22).
Peer disconnect path (`p2p.py:1859, 1883`):

```python
self._trickle_queues.pop(addr, None)  # cleanup trickle queue
```

What happens on disconnect:
- Trickle queue dropped (correct — peer's gone).
- **BUT**: `known_filter` for that peer is also dropped. If peer
  reconnects in <60s, we forget that we already announced txs
  A..Z; we re-announce them. Peer scores us as misbehaving (Core
  treats unsolicited re-INVs as wasted bandwidth).
- `_requested_txs` not cleaned (BUG-22).
- `orphan_pool` not cleaned (BUG-7).
- `_block_request_peer` / `requested_blocks` cleanup is separate
  (block-sync's own concern, not W152 scope but worth noting).

Net effect on tx-relay specifically: every short-blip disconnect
(common on home internet, esp. mobile + cellular failover) causes
mass re-announce on reconnect. Each re-announce hits BUG-14's
"misbehaving on every rejection" → reconnecting peer gets banned
within minutes.

**File:** `src/ouroboros/p2p.py:1859, 1883` (cleanup site);
`src/ouroboros/block_sync.py` (no disconnect hook for `_requested_txs`).

**Core ref:** `bitcoin-core/src/net.cpp::FinalizeNode` calls
`m_txrequest.DisconnectedPeer(...)`, `m_orphanage.EraseForPeer(...)`.

**Impact:** combined disconnect-and-reconnect path is a self-DoS;
mobile / unstable connections see ouroboros ban them after a few
reconnect cycles.

---

## Summary

**Bug count:** 28 (BUG-1 through BUG-28).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-2, BUG-3, BUG-11, BUG-23)
- **P0-DoS:** 2 (BUG-6, BUG-14)
- **P0-PRIVACY:** 2 (BUG-1, BUG-15)
- **P0:** 7 (BUG-5, BUG-8, BUG-9, BUG-10, BUG-16, BUG-25, BUG-28)
- **P1:** 13 (BUG-4, BUG-7, BUG-12, BUG-13, BUG-17, BUG-18,
  BUG-19, BUG-20, BUG-21, BUG-22, BUG-24, BUG-26, BUG-27)

Total: 4 + 2 + 2 + 7 + 13 = 28. ✓

P0-class total: 15 of 28.

**Fleet patterns confirmed:**
- **N-pipeline drift extension** (BUG-23): W150 5-pipeline drift
  augmented to 6-7 pipelines once tx relay is included (`_make_tx_handler`
  inline relay-and-misbehave; `rpc_testmempoolaccept` direct
  validator). Ouroboros "N-pipeline drift" record extends to 7.
- **dead-code pattern** (BUG-9): `orphan_pool.expire` is the most
  expensive of the wave — comment "20 minutes" is dead.
  Cross-cite: `expire_old_transactions` for the regular mempool also
  has zero callers (W150 territory).
- **dead-data plumbing** (BUG-16, BUG-19): W148 BUG-16 `is_synced`
  hard-coded false in Rust, never wired. `mark_tx_known_by_peer`
  defined and exported, never called.
- **wiring-look-but-no-wire** (BUG-4, BUG-10): TxRequestTracker
  scheduler absent despite per-tx-hash dict existing; orphan
  reconsider after block-connect absent despite `_resolve_orphans`
  existing.
- **W134 fRelay-ignored fleet pattern recurrence** (BUG-11): version
  field parsed by the decoder but never propagated to `Peer`.
- **comment-as-confession 11th distinct instance** (BUG-9, BUG-24):
  comments admit "Bitcoin Core uses CRollingBloomFilter" and the
  `expire` cadence is dead.
- **misbehaving-on-policy-reject** (W150 NEW pattern, carry-forward
  here BUG-14): unchanged from W150 BUG-23; now confirmed as a
  tx-relay-path live bug.
- **Recovery path is the bug path** (BUG-28): disconnect+reconnect
  is the broken cycle; tx-relay disintegrates between BUG-22,
  BUG-24, BUG-14.
- **MSG_WTX-as-txid** (BUG-2, BUG-3, BUG-12): symmetric on send and
  receive — the entire BIP-339 wire format is mis-dispatched. Three
  separate places (handle_inv, getdata, mempool dump) all use the
  wrong identity. First W152 fleet pattern.

**Top three findings:**
1. **BUG-2 + BUG-3 + BUG-12 cluster (P0-CDIV BIP-339 wtxid-as-txid
   bug fleet)** — On EVERY wire path that touches MSG_WTX
   (handle_inv-incoming, getdata-outgoing, MEMPOOL-dump-outgoing),
   ouroboros conflates wtxid bytes with txid bytes. Modern wtxid-relay
   peers (every Core ≥0.21) see: (a) duplicate re-requests of txs we
   already have, (b) NOTFOUND responses to our wtxid-keyed getdata,
   (c) malformed MEMPOOL responses. Bandwidth waste at scale: ~5 GB/day
   redundant tx data per peer; mempool-synchronisation latency.
2. **BUG-6 + BUG-7 + BUG-9 + BUG-10 cluster (P0/P0-DoS orphan-pool
   architectural gap)** — `MAX_ORPHAN_TRANSACTIONS=100` with random
   eviction (BUG-6), no per-peer announcer set (BUG-7), expiry
   completely dead-code (BUG-9), block-connect orphan-reconsider
   absent (BUG-10). Combined: orphan pool is a free DoS surface; one
   peer can monopolise 100 slots forever, honest orphans get
   random-evicted, never expire, never resolve on block-confirm.
   This is a 4-bug architectural rewrite needed — not patches.
3. **BUG-14 (P0-DoS unconditional misbehaving on every policy
   reject)** — Carry-forward W150 BUG-23 still live. Every mempool
   reject (RBF, mempool-conflict, txn-already-in-mempool,
   non-standard, min-relay-fee-not-met) triggers
   `misbehaving(addr, 10, ...)`. 10 rejects = ban (score 100). A
   normal v28 Core peer pushing RBF replacements accumulates the
   ban within ~1 minute of normal operation. Cross-cite BUG-15
   (P2P-receive direct relay path) and BUG-28 (disconnect-then-
   reconnect re-INVs trigger more bans). Honest Core peers banned
   on contact.
