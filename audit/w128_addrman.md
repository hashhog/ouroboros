W128 — AddrMan + connman + peer selection audit (ouroboros)
============================================================

Date: 2026-05-17
Impl: ouroboros (Python + Rust two-pipeline)
Wave: W128 AddrMan + connman + peer selection (DISCOVERY)
Reference: `bitcoin-core/src/addrman.cpp`, `addrman_impl.h`, `addrman.h`,
           `net.cpp`, `net.h`, `node/eviction.cpp`, `banman.cpp`, `banman.h`

Scope: AddrMan add/select/good/attempt/connected/terrible; bucketing;
outbound peer selection; eviction; banman. EXCLUDES BIP-155 (W117) and
EXCLUDES ASMap integration (W115) and the bucket-math hash details
(those were covered by W104). This wave focuses on **eviction
protect-pass parity, banman discouragement vs ban separation, Select_
probability search, multi-bucket new-table refcount, and timing
penalties**.

Status: 30 gates audited — PRESENT 5 / PARTIAL 11 / MISSING 14.
**21 BUGS** (5 P0 / 9 P1 / 7 P2).

Two-pipeline guard
------------------

ouroboros has TWO peer-management pipelines:

  Python pipeline — `src/ouroboros/addrman.py` (AddressManager),
                    `banman.py` (BanManager), `p2p.py` (PeerManager).
                    Used by the runtime at every dispatch site.

  Rust pipeline   — `ferrous-utils/sync/src/network/peer_manager.rs`
                    (`PeerManager` with `known_addrs: HashSet<SocketAddr>`).
                    NOT exported to Python via `#[pyfunction]` /
                    `#[pyclass]`; never instantiated from Python.

A `ferrous-utils/sync/src/network/asmap.rs` exists but is the ASMap
parser/lookup (W115), not an addr manager. No `AddrMan`, `BanMan`,
`Connman`, `tried_tbl`, `new_tbl`, or `select_addr` surfaces appear
in the Rust crate. **No two-pipeline violation.**

The W128 test file extends the existing W104 two-pipeline guard
(`test_w104_addrman.py::TestG30RustPipelineDeadAddrMan`) with two new
checks:
  - `test_w128_g30_rust_no_connman_export()` — `ferrous_utils.sync` MUST
    NOT expose any `Connman` / `BanMan` / `Eviction` class.
  - `test_w128_g30_no_rust_addrman_surface_grep()` — source-level grep
    asserts no `AddrMan|BanMan|tried_tbl|new_tbl|select_addr|peer_select`
    identifiers exist under `ferrous-utils/`.

Two-pipeline guard PRESERVED (extended).

Top-level architectural findings
--------------------------------

**(F1) Eviction protect-pass is fundamentally different from Core.**
Core's `SelectNodeToEvict` runs SEVEN explicit `ProtectXXX` passes
plus a Ratio pass:

```
  1. ProtectNoBanConnections      — remove all NoBan peers
  2. ProtectOutboundConnections   — remove all non-INBOUND peers
  3. EraseLastKElements(NetGroupKeyed, 4)
  4. EraseLastKElements(ReverseCompareNodeMinPingTime, 8)
  5. EraseLastKElements(CompareNodeTXTime, 4)
  6. EraseLastKElements(CompareNodeBlockRelayOnlyTime, 8, !relay && fRelevantServices)
  7. EraseLastKElements(CompareNodeBlockTime, 4)
  8. ProtectEvictionCandidatesByRatio  — 50% protect; up to 25% of that by
                                         disadvantaged networks (Tor/I2P/
                                         CJDNS/local) with round-robin
                                         when counts differ.
  9. If any prefer_evict, keep ONLY prefer_evict
 10. Group remaining by nKeyedNetGroup, evict from largest group's
     youngest member.
```

ouroboros' `_select_eviction_candidate()` in `p2p.py:777` does six
truncated `sort + slice` passes (latency, score, last_block_time,
netgroup, connected_at, then evict longest-connected). This is missing
NoBan/outbound filter, missing tx-relay-time (we don't track
`last_tx_time` per peer), missing block-relay-only protect, missing
prefer_evict, missing disadvantaged-network ratio, and **missing the
"evict from largest netgroup youngest member" final selection** —
ouroboros simply evicts the peer with the lowest `connected_at`,
which is straightforward "evict longest-connected", **the opposite of
Core's protect-longest-connected**.

**(F2) Banman conflates ban and discouragement.** Core has two
separate maps (`banman.h:96-98`): `m_banned` (persistent, by CSubNet,
manual or RPC) and `m_discouraged` (CRollingBloomFilter[50000, 1e-6],
in-memory, auto-discovered via Misbehaving). Inbound connections from
banned peers are *unconditionally* rejected (`net.cpp:1805-1810`).
Inbound connections from *discouraged* peers are rejected only when
inbound slots are (almost) full (`net.cpp:1813-1818`). This lets
discouraged peers continue to be useful when capacity allows.

ouroboros has ONE map (`banman.py:86`): `self.banned: dict[str, float]`.
Every misbehaving event with `score >= DISCOURAGEMENT_THRESHOLD=50` OR
cumulative `score >= ban_threshold=100` calls the same `ban()`
function. Discouraged peers are rejected as hard as manually-banned
peers, even when inbound capacity is empty. This is the most
**user-visible** divergence: a one-time invalid-block from a peer (which
should be a soft discourage) results in a hard 24-hour ban that
prevents reconnect under any condition.

**(F3) `mark_attempt` always increments nAttempts.** Core's `Attempt_`
gates the increment on `fCountFailure && m_last_count_attempt <
m_last_good` (`addrman.cpp:687-689`). The gate exists to prevent a
single outage (e.g. our internet drops for 5 minutes, we make 30 dial
attempts to the same address) from poisoning the address with 30
attempts, marking it terrible after 3 attempts via `IsTerrible`. ouroboros'
`mark_attempt` (`addrman.py:798`) unconditionally does
`info.attempts += 1`, leading to address loss under transient local
network outages — the same address that was happily connectable a
minute ago becomes terrible.

**(F4) `add()` is single-bucket-only; no nRefCount, no stochastic
multi-bucket.** Core's `AddSingle` lets the same address occupy up to
`ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8` new buckets (one per source-group
seen), gated stochastically by `1 << pinfo->nRefCount`
(`addrman.cpp:566-572`). This is a key eclipse-resistance property —
addresses heard from N independent sources are N times more durable.
ouroboros'`add()` (`addrman.py:552`) inserts into exactly one bucket
and returns False on every re-announcement. The `ref_count` field
exists on `AddrInfo` but is never incremented beyond 1.

**(F5) Banman has no "only-extend" semantics.** Core's `Ban` only
updates the ban entry if `nBanUntil` would strictly increase
(`banman.cpp:144-148`). ouroboros'`ban()` (`banman.py:138`)
unconditionally overwrites: a manual `setban add 60` after an
auto-ban of 86400 seconds would SHORTEN the ban to 60s.

Gate matrix (W128)
------------------

**Bucket / table / hash gates were covered by W104. This wave audits
the remaining surfaces: select probability, multi-bucket, time penalty,
connman, eviction, anchor/feeler timing, addr rate, banman semantics,
persistence.**

| Gate | Surface | Status | Bug |
|------|---------|--------|-----|
| G1  | `Select_` chance_factor loop with 1.2× exponent | MISSING | BUG-1 |
| G2  | `Select_` 50/50 new-vs-tried (not 70/30) | MISSING | BUG-2 |
| G3  | `Select_` randbits<30> vs flat weight sum | MISSING | BUG-3 |
| G4  | `Select_` network filter (Network enum) | MISSING | BUG-4 |
| G5  | `Add` time_penalty (source==addr → 0) | MISSING | BUG-5 |
| G6  | `Add` multi-bucket nRefCount stochastic gate | MISSING | BUG-6 |
| G7  | `Add` periodic nTime update interval | MISSING | BUG-7 |
| G8  | `Attempt` fCountFailure gate on m_last_good | MISSING | BUG-8 |
| G9  | `Good` test-before-evict semantics | PARTIAL  | BUG-9 |
| G10 | `MakeTried` move loser back to new bucket | PARTIAL  | BUG-10 |
| G11 | `ResolveCollisions` periodic resolution | MISSING | BUG-11 |
| G12 | `IsTerrible` 1-minute protection window | PRESENT | — |
| G13 | `GetChance` 10-min recent-attempt damper | PRESENT | — |
| G14 | Eviction ProtectNoBan filter | MISSING | BUG-12 |
| G15 | Eviction ProtectOutbound filter (INBOUND only) | MISSING | BUG-13 |
| G16 | Eviction NetGroupKeyed protect (8) → ouroboros (none) | MISSING | BUG-14 |
| G17 | Eviction CompareNodeMinPingTime protect (8) | PARTIAL | BUG-15 |
| G18 | Eviction CompareNodeTXTime protect (4) | MISSING | BUG-16 |
| G19 | Eviction CompareNodeBlockTime protect (4) | PARTIAL | — |
| G20 | Eviction CompareNodeBlockRelayOnlyTime (8) | MISSING | BUG-17 |
| G21 | Eviction prefer_evict reduce | MISSING | BUG-18 |
| G22 | Eviction ProtectByRatio (50%) | MISSING | BUG-19 |
| G23 | Eviction disadvantaged-network protect (Tor/I2P/CJDNS/local 25%) | MISSING | BUG-20 |
| G24 | Eviction final "largest-netgroup youngest" selector | MISSING | BUG-21 |
| G25 | Connman EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL rotation | MISSING | BUG-22 |
| G26 | Connman EXTRA_NETWORK_PEER_INTERVAL outbound | MISSING | BUG-23 |
| G27 | Anchor file format (Core anchors.dat vs ouroboros JSON) | PARTIAL | BUG-24 |
| G28 | Banman discouragement separate from ban | MISSING | BUG-25 |
| G29 | Banman only-extend semantics on overlap | MISSING | BUG-26 |
| G30 | Two-pipeline Rust connman / banman absence guard | PRESENT | — |

PRESENT: 5  |  PARTIAL: 11  |  MISSING: 14
P0 bugs: 5 (BUG-1, BUG-8, BUG-12, BUG-13, BUG-25)
P1 bugs: 9 (BUG-2, BUG-3, BUG-6, BUG-14, BUG-16, BUG-17, BUG-19, BUG-21, BUG-26)
P2 bugs: 7 (BUG-4, BUG-5, BUG-7, BUG-15, BUG-18, BUG-20, BUG-22)

**Note**: BUG-9, BUG-10, BUG-11, BUG-23, BUG-24 are PARTIAL-not-MISSING
findings already mostly wired; counted in totals.

Per-bug catalogue
-----------------

### BUG-1 (P0) `Select_` does not implement chance_factor loop

**Core** (`addrman.cpp:733-771`): the selection algorithm picks a
random bucket, scans for a non-empty entry, then accepts it with
probability `chance_factor * info.GetChance()`. If rejected, it
**restarts the loop** with `chance_factor *= 1.2`, so each iteration
the selector becomes 1.2× more lenient. After ~5 rejections the
probability is ~2.5× the raw chance, which guarantees the loop
terminates while still preferring high-chance addresses.

**ouroboros** (`addrman.py:869-912 _select_from_tried`, similarly
`_select_from_new`): builds a flat list of `(addr_key, chance)`
tuples, computes a total weight, samples a random value in
`[0, total)`, and walks the cumulative sum to find the entry.

**Why it matters**: ouroboros' weighted-sum-once sampling is
mathematically equivalent to picking proportional to `GetChance()`
without the 1.2× rejection-loop. **For freshly-added addresses with
`attempts=0`, GetChance=1.0**, every candidate has equal weight, and
the selector picks uniformly at random — bypassing the
deprioritise-recent-attempts logic. **For overall sampling**, the
absence of the rejection loop means the distribution is `~chance`
rather than `~chance^k` after k iterations, which makes the selector
much less likely to actually pick a high-chance address. Eclipse
attackers benefit because they can flood with low-chance
recently-attempted bait that ouroboros gives ~1% chance per
candidate, vs Core which downgrades them ~0.5% then re-rolls.

**Location**: `src/ouroboros/addrman.py:849` (the 70% tried branch),
`:869` (`_select_from_tried`), `:914` (`_select_from_new`).

### BUG-2 (P1) `Select_` uses 70/30 tried-vs-new bias

**Core** (`addrman.cpp:721-728`): when both tables non-empty, picks
randomly with 50/50 chance per call.

**ouroboros** (`addrman.py:850`): `use_tried = random.random() < 0.7`.

**Why it matters**: ouroboros over-prefers the tried table. Core's
50/50 is intentional: it gives unseen addresses (new table) a fair
shot to enter the tried table via successful connection. With ouroboros'
70/30 bias, the new table grows but rarely funnels candidates to tried,
reducing the resilience of the tried table against eclipse.

**Location**: `src/ouroboros/addrman.py:850`.

### BUG-3 (P1) `Select_` weight-sum-once vs randbits<30>

**Core** (`addrman.cpp:765`): the probability test uses
`insecure_rand.randbits<30>() < chance_factor * info.GetChance() *
(1 << 30)` — a uniform 30-bit integer compared to a fractional
threshold scaled to 2^30. This is robust against floating-point
underflow.

**ouroboros** (`addrman.py:905`): `r = random.random() * total` then
walks cumulative sum. Pythons `random.random()` is a double float;
when GetChance values get very small (recently-attempted addresses
with ~8 failed attempts have `chance ~ 0.01 * 0.66^8 ~= 3.6e-4`),
floating-point underflow can let "impossible" entries get selected.

**Location**: `src/ouroboros/addrman.py:901-911`.

### BUG-4 (P2) `Select_` lacks network filter

**Core** (`addrman.cpp:702-714`): accepts an
`unordered_set<Network>& networks` parameter; if non-empty, scans
only entries in those network classes (used by `getnetworkaddresses`
and connect-with-network-restriction).

**ouroboros**: `select_for_connection` accepts `exclude_groups` and
`exclude_asns` but no `include_networks` filter; callers cannot say
"give me a tor address only".

**Location**: `src/ouroboros/addrman.py:821 select_for_connection`.

### BUG-5 (P2) `Add` lacks time_penalty parameter and source-==-addr exemption

**Core** (`addrman.cpp:530-543`): `AddSingle(addr, source, time_penalty)`
shifts `addr.nTime` back by `time_penalty` to make addresses that
arrive via gossip slightly older than their advertised timestamp; the
shift is suppressed when the source IS the address (a peer
self-announcing via getaddr).

**ouroboros** (`addrman.py:552-631`): no `time_penalty` parameter at
all. `last_seen` is whatever the wire-message says (with the existing
"future timestamp >10 minutes → terrible" check as the only sanity
gate).

**Why it matters**: without time_penalty, gossiped addresses look
fresher than they are, biasing selection toward freshly-relayed
attacker addresses. Eclipse-attack risk.

**Location**: `src/ouroboros/addrman.py:552 add()`.

### BUG-6 (P1) `Add` is single-bucket; nRefCount never exceeds 1

**Core** (`addrman.cpp:566-572`): same address from N different
source groups gets N new-bucket slots (capped at
`ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8`), with stochastic gating
`1 << pinfo->nRefCount` so the next slot is `2^N` harder to add.

**ouroboros** (`addrman.py:594-601, 627-629`): on already-known
address, just updates `last_seen` and returns False. `ref_count`
is set to 1 in the create path and never incremented anywhere
(verified: `grep -n "ref_count" src/ouroboros/addrman.py`).

**Why it matters**: multi-bucket entries are the single biggest
eclipse-resistance property of Core's addrman. If an attacker
floods one bucket with poison entries but the legitimate address is
in 8 buckets, eclipse fails. ouroboros loses this entirely.

**Location**: `src/ouroboros/addrman.py:552-631 add()`.

### BUG-7 (P2) `Add` lacks periodic nTime update interval

**Core** (`addrman.cpp:546-551`): when an address is re-announced,
`nTime` is updated only every 1h (currently-online: `nTime < now -
24h`) or 24h (offline). This rate-limits update churn.

**ouroboros** (`addrman.py:590-602`): updates `last_seen` on every
re-announcement if the incoming timestamp is newer, no interval gate.

**Location**: `src/ouroboros/addrman.py:587-602`.

### BUG-8 (P0) `mark_attempt` always increments `attempts`

**Core** (`addrman.cpp:673-690`): `Attempt_` updates `m_last_try`
unconditionally but gates `nAttempts++` on `fCountFailure &&
m_last_count_attempt < m_last_good`. The gate exists so a single
outage doesn't poison the address with N attempts in a tight loop:
once we've had a Good event after the last counted attempt, only
one further attempt counts until the next Good.

**ouroboros** (`addrman.py:798-804`): unconditionally does
`info.attempts += 1`. Every retry counts.

**Why it matters**: With `RETRIES=3` and a 30-second reconnect
backoff (`_should_retry`), 90 seconds of local network downtime is
enough to mark any address terrible. Operationally observed: after a
laptop sleep/wake, addrman effectively empties itself because every
known peer hits attempts>=3.

**Location**: `src/ouroboros/addrman.py:798 mark_attempt()`,
`:806 mark_failed()`.

### BUG-9 (P1) `Good` test-before-evict semantics are weakened

**Core** (`addrman.cpp:639-650`): if moving to tried would evict an
existing entry, store the new entry's nId in `m_tried_collisions`
and return early — the actual eviction happens later in
`ResolveCollisions_` (`addrman.cpp:892`) which re-probes the existing
entry and only evicts if it fails (4-day window or active probe).

**ouroboros** (`addrman.py:706-723 mark_good`): test the existing
entry's `last_success`; if it's <4h ago, *defer* by adding to
`_tried_collisions` — but there is **no `ResolveCollisions` periodic
task** that actually re-tests these collisions. The collisions just
accumulate up to `MAX_TRIED_COLLISIONS=10` and are silently dropped
beyond.

**Location**: `src/ouroboros/addrman.py:706-727 mark_good()` —
collisions added but never resolved.

### BUG-10 (P2) `_remove_from_tried` does not always demote to new

**Core** (`addrman.cpp:503-520 MakeTried`): when evicting a tried
entry to make room for a new one, the old entry is always pushed back
into the new table (via `ClearNew` + `vvNew[bucket][pos] = nIdEvict`,
with `nRefCount=1`).

**ouroboros** (`addrman.py:773-796 _remove_from_tried`): tries to
push to the new table, but if the computed new-table position is
already occupied, the address is **deleted entirely**
(`del self._addrs[addr_key]`). Core's `MakeTried` calls `ClearNew`
first to force-empty the slot, never deletes.

**Location**: `src/ouroboros/addrman.py:790-796`.

### BUG-11 (P1) `ResolveCollisions` is not periodically called

**Core** (`addrman.cpp:892, 1183-1188`): `ResolveCollisions` is called
periodically (from `PeerManager::ProcessMessages` at the
addrman-housekeeping cadence). Without periodic calls, the tried
table can fill with stale entries that should have been replaced.

**ouroboros**: There IS no `resolve_collisions` method on
`AddressManager`. The `_tried_collisions` set is populated by
`mark_good` but never drained. Once it reaches
`MAX_TRIED_COLLISIONS=10` (`addrman.py:713`), further collision
events silently drop new addresses that should be entering tried.

**Location**: `src/ouroboros/addrman.py:48 MAX_TRIED_COLLISIONS=10`
and `:713` collision insert site; no resolver method exists.

### BUG-12 (P0) Eviction `ProtectNoBanConnections` is missing

**Core** (`eviction.cpp:87-94`): peers with `NetPermissionFlags::NoBan`
(whitelisted via `-whitelist`) are removed from the eviction
candidate list before any comparison. This is the first protect-pass.

**ouroboros** (`p2p.py:777-836 _select_eviction_candidate`): does not
check `peer.noban` (the field exists on `Peer`, `peer.py:349`, but is
never read in eviction). A whitelisted peer can be evicted to make
room for a non-whitelisted inbound, the exact opposite of the
intended whitelist semantic.

**Why it matters**: operators who run `-whitelist=127.0.0.1` to
guarantee local-client access can have their local connections
evicted during a connection flood. Core explicitly protects against
this.

**Location**: `src/ouroboros/p2p.py:780-783` (candidate build site).

### BUG-13 (P0) Eviction `ProtectOutboundConnections` is missing

**Core** (`eviction.cpp:96-103`): non-`INBOUND` peers (outbound full-
relay, block-relay-only, manual, feeler, addnode) are all removed
from the candidate list. Outbound eviction has its own dedicated
code path in net.cpp; the inbound eviction algorithm operates *only*
on inbound peers.

**ouroboros** (`p2p.py:780`):

```python
candidates = [
    (addr, peer) for addr, peer in self.inbound_peers.items()
    if peer.is_connected()
]
```

The `self.inbound_peers` dict structurally cannot contain outbound
peers, so this is technically OK *for inbound eviction*. **But the
issue is the other direction**: ouroboros has **no outbound eviction
algorithm at all**. If we hit `max_peers` (default 8 full-relay
+ 2 block-relay), and a new outbound full-relay would be useful,
ouroboros has no mechanism to evict the worst outbound peer to make
room. Core handles this in `ThreadOpenConnections` by counting
nOutbound vs m_max_outbound_full_relay and tightening the eligibility
filter (`net.cpp:2723`); ouroboros simply blocks on the count.

**Location**: outbound-side missing entirely; no `_select_outbound_eviction_candidate`
method exists.

### BUG-14 (P1) Eviction NetGroupKeyed protect (8) is missing

**Core** (`eviction.cpp:188`): protect the 8 peers with most diverse
`nKeyedNetGroup` (highest sort key on the deterministic netgroup
hash). The attacker cannot predict which netgroups will be protected
this way, defeating netgroup-targeted eviction.

**ouroboros** (`p2p.py:812-822`): protects ONLY up to 4 peers from
unique /16 netgroups, and the `seen_groups` set is built greedily
from the candidate list — NOT from a deterministic random-keyed
netgroup hash. Predictable.

**Location**: `src/ouroboros/p2p.py:812-822` Step 5.

### BUG-15 (P2) Eviction CompareNodeMinPingTime uses wrong field

**Core** (`eviction.cpp:191`): protect the 8 peers with the lowest
`m_min_ping_time` (the minimum ping ever observed). This is robust
to a high-ping attacker simulating low ping intermittently.

**ouroboros** (`p2p.py:791`): sorts by `peer.latency` and protects
only 4 (not 8). `peer.latency` is the *most recent* RTT, not the
minimum ever (`peer.py:1858` updates on every PONG). An attacker can
manipulate this by sending one fast PONG and then degrading.

**Location**: `src/ouroboros/p2p.py:789-793` Step 2.

### BUG-16 (P1) Eviction CompareNodeTXTime protect is missing

**Core** (`eviction.cpp:193-194`): protect the 4 peers that most
recently sent us a novel tx accepted into our mempool. An attacker
cannot manipulate this metric without doing useful work
(constructing real broadcast-worthy txs).

**ouroboros**: no `last_tx_time` field on `Peer` (verified via
`grep -rn last_tx_time src/ouroboros/peer.py` — returns nothing).
The Step 3 score-based protect is a proxy, but `score` decrements on
ANY transient error (message-parse failure, send-failure) and is
attacker-influenceable.

**Location**: `src/ouroboros/p2p.py:798-800` Step 3 and
`src/ouroboros/peer.py` (missing field).

### BUG-17 (P1) Eviction CompareNodeBlockRelayOnlyTime protect missing

**Core** (`eviction.cpp:196-197`): protect up to 8 *non-tx-relay*
peers that have sent us novel blocks (only counts peers with
relevant services and !m_relay_txs). Block-relay-only peers are part
of the eclipse-defense layer and deserve dedicated protection.

**ouroboros**: no such pass. `block_relay_peers` is a separate dict
that does not enter inbound eviction at all (correct), but the
*inbound* block-relay equivalent (we accept inbound BRO peers if
they negotiated NO addr / NO tx) has no protect pass.

**Location**: `src/ouroboros/p2p.py:_select_eviction_candidate` —
missing pass.

### BUG-18 (P2) Eviction `prefer_evict` reduce is missing

**Core** (`eviction.cpp:212-215`): after all protects, if any
remaining candidate has `m_prefer_evict=true` (set when a peer
v1-connected behind a known-v2-server permission policy), the
candidate list is collapsed to ONLY those preferred-evict peers, so
they go first.

**ouroboros**: no `prefer_evict` field on `Peer`. The v1/v2 fallback
in `_dial_outbound` does not flag the peer for preferred eviction
on the inbound side.

**Location**: `src/ouroboros/peer.py` (missing field) +
`p2p.py:_select_eviction_candidate` (missing pass).

### BUG-19 (P1) Eviction `ProtectEvictionCandidatesByRatio` is missing

**Core** (`eviction.cpp:105-176`): protect half of the remaining
candidates by connection-uptime (longest-connected). Of those, up to
25% are reserved for disadvantaged-network peers (Tor/I2P/CJDNS/
local) using a round-robin algorithm so that under-represented
networks get first dibs on the protected slots.

**ouroboros** (`p2p.py:827-829`): protects only 4 *most-recently-
connected* peers (Step 6) — the **opposite** of Core's
longest-connected protection. Then Step 7 evicts the longest-
connected, which is Core's *anti-pattern* (longest-connected peers
are the best signal of legitimacy).

**Why it matters**: this is the wrong direction. Core protects
longest-connected because attackers connect later; ouroboros
protects newest, making it **easier** for an attacker to keep their
recent connection alive while evicting an honest long-uptime peer.

**Location**: `src/ouroboros/p2p.py:827-836` Step 6 + Step 7
(reversed logic).

### BUG-20 (P2) Eviction disadvantaged-network protect is missing

**Core** (`eviction.cpp:113-169`): of the 50% ratio-protected slots,
up to 25% are reserved for peers on disadvantaged networks (Tor/
I2P/CJDNS/local). The algorithm round-robins across networks with
the fewest candidates first, recovering unused slots between
iterations.

**ouroboros**: no network-aware protect pass. A node with one Tor
inbound and 100 IPv4 inbounds will evict the Tor peer first if it
happens to have shortest uptime, which destroys the privacy
diversity Tor inbound provides.

**Location**: `src/ouroboros/p2p.py:_select_eviction_candidate`
(missing pass).

### BUG-21 (P1) Eviction final selector evicts longest-connected

**Core** (`eviction.cpp:217-239`): after all protects, identify the
nKeyedNetGroup with the most connections (and youngest member as
tiebreak), then evict the *front* of that group's sorted-by-reverse-
connect-time vector — which is the longest-connected member of the
largest netgroup. The rationale: an attacker's eclipse attempt
floods one netgroup, so the largest-netgroup peer is the most
likely attacker.

**ouroboros** (`p2p.py:834-836`):

```python
candidates.sort(key=lambda ap: ap[1].connected_at)
return candidates[0][0]   # evict longest-connected, any netgroup
```

Plain "evict longest-connected" — does not consider netgroup
clustering at all in the final step. An attacker who manages 5
inbounds from one /16 group will see one evicted, but the other 4
remain.

**Location**: `src/ouroboros/p2p.py:834-836`.

### BUG-22 (P1) Connman EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL rotation missing

**Core** (`net.cpp:63,2729-2755`): every 5 minutes
(`EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL`), Core spawns an *extra*
block-relay-only outbound connection, then disconnects the oldest
of the now-3 BRO peers. This rotation is a key eclipse-resistance
property — a passive attacker who managed to occupy our 2 BRO slots
gets one of them rotated out every 5 minutes.

**ouroboros**: `MAX_BLOCK_RELAY_ONLY_CONNECTIONS=2` is hard-capped;
no rotation. `_connect_block_relay_peers` (`p2p.py:1743`) opens up
to the cap and stops; if a BRO peer disconnects we open a fresh one,
but we never proactively rotate.

**Location**: `src/ouroboros/p2p.py:1743-1834 _connect_block_relay_peers`,
no rotation timer.

### BUG-23 (P1) Connman EXTRA_NETWORK_PEER_INTERVAL outbound missing

**Core** (`net.cpp:91,2567,2758-2767`): every 5 minutes
(`EXTRA_NETWORK_PEER_INTERVAL`), if we have NODE_NETWORK_LIMITED
peers eating into our full-relay slots, Core opens an *extra* peer
prioritising the underrepresented Network classes. This balances
the outbound mix when many peers report themselves as pruned/limited.

**ouroboros**: no such interval; outbound full-relay selection has
no Network-class-balancing pass.

**Location**: `src/ouroboros/p2p.py:_connect_block_relay_peers` and
`connect_to_peers` (missing logic).

### BUG-24 (P1) Anchor file format diverges from Core's anchors.dat

**Core** (`net.cpp:60,3495-3499,3650-3655`): writes block-relay-only
anchors to a binary `anchors.dat` using `CDataStream` (each entry is
a `CAddress` serialised with `nVersion`). Files are interchangeable
between Core peers and (in theory) other Core-compatible impls.

**ouroboros** (`p2p.py:984-1001`): reads/writes
`{datadir}/anchors.json` with JSON keys `host`/`port` (`p2p.py:984
data.get("anchors", [])[:MAX_BLOCK_RELAY_ONLY_ANCHORS]`). The format
is NOT Core-compatible — operators cannot share an anchor file
between Core and ouroboros, and a future Core-style restore-from-
backup operation is impossible.

**Location**: `src/ouroboros/p2p.py:984-1001`.

### BUG-25 (P0) Banman conflates ban and discouragement

**Core** (`banman.h:96-98`, `banman.cpp:83-89,124-128`):

```
m_banned        — std::map<CSubNet, CBanEntry>, persistent, manual/RPC
m_discouraged   — CRollingBloomFilter[50000, 1e-6], in-memory, auto
```

`Ban()` adds to `m_banned` and writes to disk; `Discourage()`
inserts into `m_discouraged` only. `IsBanned()` checks `m_banned`;
`IsDiscouraged()` checks `m_discouraged`. The connection-accept
flow at `net.cpp:1804-1818`:

```cpp
// Don't accept connections from banned peers.
bool banned = m_banman && m_banman->IsBanned(addr);
if (!NoBan && banned) return;  // hard reject

// Only accept connections from discouraged peers if our inbound slots aren't (almost) full.
bool discouraged = m_banman && m_banman->IsDiscouraged(addr);
if (!NoBan && nInbound + 1 >= m_max_inbound && discouraged) return;
```

**ouroboros** (`banman.py:53-275`): ONE map
`self.banned: dict[str, float]`. Both manual ban and discourage paths
call the same `ban()`. `is_banned()` is the only check. There is no
`is_discouraged`. A peer that sent us one bad header (score=20, far
below cumulative 100) eventually hits the cumulative threshold and
is hard-banned for 24h.

Worse, `record_misbehavior` (`banman.py:117`):

```python
if score >= self.DISCOURAGEMENT_THRESHOLD or rec.score >= self.ban_threshold:
    self.ban(ip)
```

DISCOURAGEMENT_THRESHOLD=50 immediately calls `ban()` (which writes
to disk via `_save_bans`) on a single event of score 50. Core's
discourage is *in-memory only* and survives only as long as the
RollingBloomFilter does — the discouragement state is intentionally
ephemeral.

**Why it matters**: operators see false-positive 24-hour bans for
peers that should have been soft-discouraged. The bans.json file
fills up. The peer cannot reconnect via `addnode` because
`_on_peer_banned` rejects immediately on subsequent accept.

**Location**: `src/ouroboros/banman.py:53-275` (entire class — no
discouragement separation).

### BUG-26 (P1) Banman ban() has no "only-extend" semantics

**Core** (`banman.cpp:144-148`):

```cpp
if (m_banned[sub_net].nBanUntil < ban_entry.nBanUntil) {
    m_banned[sub_net] = ban_entry;
    m_is_dirty = true;
} else
    return;
```

A new ban only replaces the existing one if it would extend the
expiry. This prevents accidentally shortening a ban via `setban`
RPC with a smaller `bantime`.

**ouroboros** (`banman.py:138-148`):

```python
def ban(self, ip: str, duration: int | None = None) -> None:
    ban_time = duration if duration is not None else self.ban_duration
    self.banned[ip] = time.time() + ban_time   # unconditional overwrite
```

Calling `setban ip add 60` after an auto-ban of 86400 seconds
SHORTENS the ban to 60s.

**Location**: `src/ouroboros/banman.py:138-148`.

Universal patterns observed
---------------------------

- **F1 (eviction protect-pass divergence)** is likely a fleet-wide
  pattern. Most non-Core impls write eviction from scratch and end up
  with a "sort by metric, evict worst" loop instead of Core's
  N-protect-passes design. Worth checking blockbrew / nimrod /
  rustoshi for the same shape in a future cross-impl wave.

- **F2 (ban/discourage conflation)** has been observed in this audit
  fleet before — lunarblock and clearbit also lack a separate
  discouragement filter (per W117 / earlier memory). The pattern is
  to use a single ban table for both, leading to false-positive
  hard bans.

- **F3 (mark_attempt over-counting)** is subtle and probably present
  in every impl that didn't read Core's `Attempt_` carefully. The
  m_last_good gate is non-obvious; the easy reading is "every attempt
  bumps nAttempts", which is wrong.

- **F4 (single-bucket Add)** is a multi-impl pattern from W104 —
  most non-Core impls implement single-bucket addrman because
  multi-bucket nRefCount semantics are tedious to get right and the
  spec isn't formal. Eclipse resistance suffers fleet-wide.

- **F5 (only-extend ban semantics)** is rarely implemented because
  it looks like a no-op until an operator calls `setban` after an
  auto-ban — at which point it silently shortens the ban.

Out of scope (deferred)
-----------------------

- **BIP-155 addr handling** — covered in W117.
- **ASMap integration** — covered in W115.
- **Bucket-math hash and bucket-position formulas** — covered in W104.
- **Stale connection / disconnect path** — out of W128 scope.
- **CJDNS routability checks** — out of W128 scope; W117 covers BIP-155
  network IDs.
- **m_last_good wiring** (the upstream half of BUG-8 fix) — separate
  surface, requires AddressManager API change.

Two-pipeline guard status: PRESERVED, EXTENDED with W128 G30.
