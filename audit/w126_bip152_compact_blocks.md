W126 — BIP-152 Compact Block Relay audit (ouroboros)
=====================================================

Date: 2026-05-17
Impl: ouroboros (Python + Rust ferrous-utils pipeline)
Wave: W126 BIP-152 Compact Blocks (DISCOVERY ONLY — no production code changes)
Reference: `bitcoin-core/src/blockencodings.{h,cpp}`,
           `bitcoin-core/src/net_processing.cpp` (SENDCMPCT / CMPCTBLOCK /
           GETBLOCKTXN / BLOCKTXN), BIP-152.

Status: 30 gates audited — PRESENT 12 / PARTIAL 4 / MISSING 14. **17 BUGS**
(1 P0-CDIV / 6 P1 / 9 P2 / 1 P3) + G29 re-audit of W112 BUG-8 (P3 dead-state).

Streak: 71 fix + 56 discovery preserved (W126 is discovery; no break).
W126 is a deeper re-audit of W112 (FIX-41 closed BUG-1/BUG-2). It catalogues
the remaining FillBlock-mutation gap, the duplicate `sendcmpct` send, the
missing fast-announce / most-recent-block cache, and several
peer-management invariants that W112 did not score (HB rotation, inflight
cap, lazy serialization, NODE_BLOOM/-blocksonly gate, etc.).

Two-pipeline guard
------------------

`ferrous-utils` Rust crate is the IBD validation pipeline; it does NOT
serve the BIP-152 wire surface. Pre-W126:

```
$ grep -rEn "CompactBlock|cmpctblock|getblocktxn|blocktxn" ferrous-utils/
    common/src/lib.rs:20:        # Re-export siphash for compact blocks
    common/src/crypto/siphash.rs:182  short_txid() helper
    common/src/crypto/siphash.rs:199  compute_siphash_key()
    common/src/minisketch.rs:637      compute_short_txid() (BIP-330 reconciliation)
    sync/src/network/peer.rs:12       # comment: TODO note (no code)
```

SipHash + minisketch live in Rust because they are reused for **BIP-330
transaction reconciliation** (Erlay), *not* BIP-152 P2P. The BIP-152
message handlers, `CompactBlock` type, `PartiallyDownloadedBlock`-equivalent
in-flight state, and `_register_compact_handlers()` all live in Python
(`src/ouroboros/compact_blocks.py` + `src/ouroboros/p2p.py`). Two-pipeline
guard PRESERVED. The W126 test file adds a `test_rust_pipeline_has_no_bip152_handlers`
gate (G30) extending the guard set per FIX-76/FIX-79 ouroboros pattern.

Top-level architectural findings
--------------------------------

**(F1) Duplicate `sendcmpct` on every inbound handshake.** `peer.py:852`
emits `SendCmpctMessage(announce=False, version=2)` inside
`accept_inbound` immediately after the verack flow. `p2p.py:917` schedules
`negotiate_compact_blocks(peer)` which fires a *second*
`SendCmpctMessage(announce=False, version=2)` from `p2p.py:2114`. Same for
outbound at `peer.py:1406` + `p2p.py:1320`. Wire-level peers see two
identical sendcmpct messages. Core sends one. (BUG-1 P1)

**(F2) `m_provides_cmpctblocks` peer-state field never recorded.**
Core's `on_sendcmpct` sets `nodestate->m_provides_cmpctblocks = true`,
guarding all later compact-block sends. ouroboros's `on_sendcmpct`
(`p2p.py:2124`) sets `peer.wants_cmpctblock` *only* when `sc.announce`
is true; the case where the peer sends `sendcmpct(false, 2)` does NOT
record support, so the BIP-152 spec's "peer supports cmpct but doesn't
want HB" case is lost — we treat them as if they never sendcmpct'd.
(BUG-2 P1)

**(F3) No HB-peer cap / selection (BIP-152 §"announcement").** Core picks
at most 3 peers as HB announce-to-us via `MaybeSetPeerAsAnnouncingHeaderAndIDs`,
sends them `sendcmpct(announce=True)` on first valid block, and rotates the
oldest out when adding a 4th. ouroboros never sends `sendcmpct(True)` (we
hard-code `announce=False` in every send site) and never tracks the
3-peer list. This is documented in W112 as BUG-3 (P1) + BUG-4 (P1); the
re-audit confirms the absence and adds the missing rotation/inbound-priority
edge-case logic (BUG-3 P1, see G9/G10/G11).

**(F4) No `PartiallyDownloadedBlock`-equivalent mutation check on
`FillBlock`.** Core's `blockencodings.cpp:218-222` runs
`IsBlockMutated(block, segwit_active)` **inside** `FillBlock`, BEFORE
returning `READ_STATUS_OK`. A short-ID collision that survives the dedup
gate can produce a mutated block (witness root mismatch). ouroboros's
`reconstruct_partial` (`compact_blocks.py:292`) returns the assembled
list with no mutation check; the block goes to `_on_compact_block` and
is fed into the chain pipeline. If `validate_block` later rejects the
mutation, no peer punishment occurs — Core punishes on the FillBlock-side
collision. (BUG-4 P0-CDIV)

**(F5) `cmpctblock` path delivers reconstructed block without
`UpdateBlockAvailability` or `mapBlockSource` accounting.** Core's CMPCTBLOCK
handler runs `UpdateBlockAvailability(pfrom.GetId(), pindex->GetBlockHash())`
+ `mapBlockSource.emplace(...)` so later `BlockChecked` can call
`MaybeSetPeerAsAnnouncingHeaderAndIDs` on the peer that delivered a
*valid* block. ouroboros does neither. Consequence: even if BUG-3 were
fixed, we'd have no signal of "this peer delivered a valid block, mark
them HB". (BUG-5 P1)

**(F6) No `m_most_recent_compact_block` cache.** Core caches the most
recent compact block + tx-genid lookup map (`net_processing.h:863-865`)
and the `lazy_ser` future at fast-announce time (`net_processing.cpp:2117`).
A `getdata MSG_CMPCT_BLOCK` for the cached hash is served directly from
the cache. ouroboros has NO `MSG_CMPCT_BLOCK` getdata-side serving path,
and no recent-block cache. Inbound `getdata` for type 4 (`MSG_CMPCT_BLOCK`)
falls through to the unhandled-inv branch. (BUG-6 P2)

**(F7) No `vExtraTxnForCompact` pool.** Core maintains a rolling 100-tx
ring of recently-orphan-resolved / recently-block-evicted transactions
that did not make it back into the mempool, and feeds them to
`PartiallyDownloadedBlock::InitData` as `extra_txn`. They cover the
mempool-eviction edge case (a tx in the block that was evicted from the
mempool right before the block arrived). ouroboros only matches against
the current mempool. Re-audit confirms W112 BUG-6; no change. (BUG-7 P2)

**(F8) -blocksonly / `relay_txs` HB-decline gate missing.** Core's
`MaybeSetPeerAsAnnouncingHeaderAndIDs` short-circuits when
`m_opts.ignore_incoming_txs` (the `-blocksonly` flag) is set, because a
blocks-only node has an empty mempool and CANNOT reconstruct compact
blocks. ouroboros has no equivalent. If `--blocksonly` were honoured in
the HB-peer-selection path (currently missing entirely, see BUG-3) we'd
also have no guard against requesting HB to-us when we cannot use it.
(BUG-8 P2, latent until BUG-3 closes)

**(F9) `sendcmpct` permitted after VERACK.** Core's `on_sendcmpct`
(`net_processing.cpp:3901-3917`) accepts the message at any time,
matching BIP-152's "MAY be sent more than once" — ouroboros also accepts
it at any time, but does NOT reject it *before* VERACK (Core wraps it in
the standard post-verack message loop; ouroboros registers the handler
before handshake completion in some paths). Inspection of `accept_inbound`
shows `_register_compact_handlers` runs *after* the handshake (p2p.py:914),
so this is actually safe — verified by reading. NOT a bug. (G7 PRESENT,
no BUG)

**(F10) Optimistic reconstruction missing.** When a cmpctblock arrives
for a block already in-flight from another peer, Core (4640-4654) does an
"optimistic" `tempBlock.InitData` + `FillBlock` to try to reconstruct
without a round-trip. ouroboros has no such path — we always either
fully match from mempool or send a `getblocktxn`. Bandwidth penalty under
high-parallelism IBD. (BUG-9 P2)

Constants & wire codec
----------------------

PRESENT and correct: `CMPCTBLOCKS_VERSION=2`, `MAX_CMPCTBLOCK_DEPTH=5`,
`MAX_BLOCKTXN_DEPTH=10`, `MAX_CMPCTBLOCK_TX_COUNT=100000` (4M/40),
`MAX_SHORT_ID_BUCKET_SIZE=12`, `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3`
(latter not used — see BUG-10).
SipHash-2-4, key derivation, 48-bit short_txid, BIP-152 wtxid-keyed
hashing all match Core byte-for-byte (`compact_blocks.py:56-146`).
Reference vector `0xa129ca6149be45e5` produced by both the Python
`_siphash_2_4` and Rust `siphash_2_4` — cross-validated in
`tests/test_w112_compact_blocks.py:G5` (already pass).

Wire layout `serialize/deserialize` covers the 88-byte header+nonce
prefix, the differential-encoded varint indexes, the prefilled tx body,
and the uint16 overflow check (`compact_blocks.py:397`).

Gate matrix
-----------

| Gate | Description                                              | Status   | Notes |
|------|----------------------------------------------------------|----------|-------|
| G1   | CMPCTBLOCKS_VERSION = 2                                  | PRESENT  | exact match to Core (`compact_blocks.py:28`) |
| G2   | MAX_CMPCTBLOCK_DEPTH = 5                                 | PRESENT  | `compact_blocks.py:32` |
| G3   | MAX_BLOCKTXN_DEPTH = 10                                  | PRESENT  | `compact_blocks.py:36` |
| G4   | Short ID length = 6 bytes (48 bits)                      | PRESENT  | `compact_blocks.py:146` |
| G5   | SipHash key = SHA256(header‖nonce_le64)[0:16]            | PRESENT  | `compact_blocks.py:138-141` |
| G6   | InitData validates header-not-null + tx count ≤ 100 000  | PRESENT  | `compact_blocks.py:204-211` |
| G7   | InitData rejects prefilled.index gap overflow            | PRESENT  | `compact_blocks.py:216-225` |
| G8   | InitData duplicate short-id + bucket-DoS gate (>12)      | PRESENT  | `compact_blocks.py:233-243` |
| G9   | sendcmpct sent EXACTLY once per peer                     | MISSING  | **BUG-1 P1**: sent twice (peer.py + p2p.py) |
| G10  | on_sendcmpct records m_provides_cmpctblocks=true for ANY | MISSING  | **BUG-2 P1**: only records on announce=True |
| G11  | HB-peer rotation cap = 3 (BIP-152 announce flow)         | MISSING  | **BUG-3 P1**: re-audit of W112 BUG-3/4 |
| G12  | MaybeSetPeerAsAnnouncingHeaderAndIDs() on valid block    | MISSING  | **BUG-5 P1**: no signal "peer delivered valid block" |
| G13  | -blocksonly disables HB-to-us selection                  | PARTIAL  | **BUG-8 P2**: latent — no HB selection at all |
| G14  | FillBlock invokes IsBlockMutated(segwit_active)          | MISSING  | **BUG-4 P0-CDIV**: no witness-root mutation gate |
| G15  | UpdateBlockAvailability on cmpctblock receive            | MISSING  | covered by BUG-5 |
| G16  | mapBlockSource emplace on reconstructed block            | MISSING  | covered by BUG-5 |
| G17  | optimistic tempBlock reconstruction when in-flight       | MISSING  | **BUG-9 P2** |
| G18  | MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 + enforced        | PARTIAL  | **BUG-10 P2**: constant absent; no parallel cmpctblock tracking |
| G19  | high_bandwidth_to / high_bandwidth_from per-peer state   | MISSING  | **BUG-11 P1**: only `wants_cmpctblock` flag (no HB-from) |
| G20  | getblocktxn → blocktxn round-trip (depth gate, OOB)      | PRESENT  | `p2p.py:2286-2358` |
| G21  | getblocktxn fallback: deep block sends full block        | MISSING  | **BUG-12 P2**: re-audit of W112 BUG-7 |
| G22  | vExtraTxnForCompact pool of recently-evicted txs         | MISSING  | **BUG-7 P2**: re-audit of W112 BUG-6 |
| G23  | cmpctblock receive: depth gate uses TIP-depth direction  | PARTIAL  | **BUG-13 P2**: re-audit of W112 BUG-5 — direction is right but path is wrong |
| G24  | cmpctblock receive: low-work header drop                 | MISSING  | **BUG-14 P1**: no GetAntiDoSWorkThreshold equivalent |
| G25  | cmpctblock receive: revert to header processing on far-future | MISSING | **BUG-15 P2**: no fRevertToHeaderProcessing branch |
| G26  | most-recent compact block cache + lazy serialization     | MISSING  | **BUG-6 P2**: no `m_most_recent_compact_block` |
| G27  | MSG_CMPCT_BLOCK getdata response path                    | MISSING  | **BUG-16 P2**: type-4 inv falls through unhandled |
| G28  | m_highest_fast_announce de-dup at announce time          | MISSING  | **BUG-17 P3**: re-announce on reorg can spam HB peers |
| G29  | cmpct_peers set populated but never read (dead state)    | PARTIAL  | re-audit of W112 BUG-8 (P3, dead-helper-at-call-site) |
| G30  | Rust pipeline has NO BIP-152 handlers (two-pipeline guard) | PRESENT | preserved + extended via new test |

PRESENT 12 / PARTIAL 4 / MISSING 14.

BUGs (17)
---------

**BUG-1 (P1) — Duplicate `sendcmpct` to every peer.**
`peer.py:852` sends `SendCmpctMessage(announce=False, version=2)` from
`accept_inbound`. `p2p.py:917` schedules
`negotiate_compact_blocks(peer)` which sends the SAME message from
`p2p.py:2114`. Outbound path is symmetric (`peer.py:1406` +
`p2p.py:1320`). All peers receive two consecutive identical `sendcmpct`
frames. Per BIP-152 a peer MAY ignore duplicates, but this is wire-level
sloppy and signals to honest peers we may be confused. Fix: drop one of
the two sites. Recommendation: keep `peer.py` (handshake-local) and
delete the `negotiate_compact_blocks` calls at p2p.py:917 / 1320 / 1659 /
1723. (No code changes in this audit.)

**BUG-2 (P1) — `wants_cmpctblock` only set when peer signals announce=True.**
`p2p.py:2137-2138`:
```python
if sc.announce:
    peer.wants_cmpctblock = True
```
But Core records `m_provides_cmpctblocks = true` regardless of the
announce bit. The semantics differ:
  - `m_provides_cmpctblocks`: peer SUPPORTS cmpctblock (we may try to
    relay cmpctblock back if other gates pass)
  - `m_requested_hb_cmpctblocks`: peer wants HB-style unsolicited send
ouroboros conflates both into `wants_cmpctblock`. Consequence: a peer
that sent `sendcmpct(announce=False, version=2)` (e.g. all Core nodes
that haven't picked us as an HB target) is treated as a NON-cmpct peer
and gets a plain `headers` / `inv` announcement, defeating the entire
BIP-152 negotiation. Fix: separate `peer.provides_cmpctblocks` and
`peer.wants_hb_cmpctblock`.

**BUG-3 (P1) — No HB-peer cap or rotation (re-audit of W112 BUG-3/4).**
Confirms W112 finding: ouroboros never sends `sendcmpct(announce=True)`
and never maintains the 3-peer LRU `lNodesAnnouncingHeaderAndIDs` list
or its rotation rules (Core net_processing.cpp:1272-1329 incl. inbound
swap-to-front trick at line 1306). Re-audit adds the inbound-edge
specific test (BIP-152 §"Selection of Peers" requires that
adding an inbound HB-to-us peer cannot remove our LAST outbound HB-to-us
peer).

**BUG-4 (P0-CDIV) — `FillBlock` missing `IsBlockMutated` check.**
`blockencodings.cpp:218-222`:
```cpp
IsBlockMutatedFn check_mutated{...};
if (check_mutated(block, segwit_active)) {
    return READ_STATUS_FAILED; // Possible Short ID collision
}
```
The witness-root mutation check is what catches the rare case where two
distinct transactions hash to the same 6-byte short ID AND happen to
slot into the same position in the reconstructed block. ouroboros's
`reconstruct_partial` (`compact_blocks.py:292-338`) does NOT call any
mutation check before returning. The reconstructed block is then passed
to `_on_compact_block` which feeds it into the chain pipeline. If
`validate_block` rejects on merkle / witness mismatch, the peer that
caused the collision is NOT punished — Core does
`Misbehaving(peer, "invalid compact block/non-matching block
transactions")` on the FillBlock path. Without this, we miss the
peer-attribution signal entirely. P0-CDIV because under adversarial
short-ID collision, we silently fail-open instead of returning
READ_STATUS_FAILED + falling back to `getdata MSG_BLOCK` (Core ::3489).

**BUG-5 (P1) — No `UpdateBlockAvailability` / `mapBlockSource` on receive.**
`net_processing.cpp:4529`:
`UpdateBlockAvailability(pfrom.GetId(), pindex->GetBlockHash());` and
`:4690`: `mapBlockSource.emplace(pblock->GetHash(), {pfrom.GetId(),
false})`. These two calls thread the per-peer "best known block" used
for HB-peer scoring (`MaybeSetPeerAsAnnouncingHeaderAndIDs` only
upgrades a peer if it delivered the **most recent** valid block).
ouroboros's `on_cmpctblock` does neither — we just call
`_on_compact_block` and forget. Even if BUG-3 were fixed, we'd have no
signal of "which peer delivered the valid block first" to promote them
to HB.

**BUG-6 (P2) — No most-recent compact block cache (`m_most_recent_compact_block`).**
Core caches the most recently constructed `CBlockHeaderAndShortTxIDs`
alongside the block, gated by `m_most_recent_block_mutex`
(`net_processing.h:863`). When an inbound `getdata MSG_CMPCT_BLOCK`
asks for the tip's hash, the cache is served directly. ouroboros has no
such cache. Compounds with BUG-16 (MSG_CMPCT_BLOCK type-4 inv has no
serving path at all).

**BUG-7 (P2) — No `vExtraTxnForCompact` pool (W112 BUG-6 re-audit).**
Core ring-buffer of 100 recently-orphan-resolved / recently-block-evicted
txs (`m_opts.max_extra_txs`). Fed into `PartiallyDownloadedBlock::InitData`
as `extra_txn` second source for short-ID matching. ouroboros only
matches the current mempool. Edge case: a tx that was evicted from the
mempool *between* the prev-block's accept and the new-block's arrival
will appear as "missing" in the cmpct reconstruction and trigger an
unnecessary `getblocktxn` round-trip.

**BUG-8 (P2, latent) — No `-blocksonly` HB-decline gate.**
`net_processing.cpp:1279`: `if (m_opts.ignore_incoming_txs) return;`
short-circuits HB-peer selection. ouroboros lacks the entire HB-selection
flow (BUG-3) so this is latent — but when BUG-3 is fixed, BUG-8 MUST
land in the same patch.

**BUG-9 (P2) — No optimistic temp-block reconstruction.**
`net_processing.cpp:4640-4654`: when a cmpctblock arrives for an
already-in-flight block, Core makes a stack-allocated
`PartiallyDownloadedBlock tempBlock` and tries to reconstruct
opportunistically. If it succeeds, the block is processed without a
round-trip. ouroboros short-circuits this — we drop the second
cmpctblock entirely. Bandwidth penalty in high-parallelism IBD.

**BUG-10 (P2) — `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` constant absent.**
ouroboros has no constant for the per-block parallel cmpctblock cap.
Core's net_processing.h:47 sets it to 3 and enforces it at multiple
sites (1208, 1243, 4577, 4624). ouroboros has no parallel cmpctblock
tracking at all — each block is single-source. Compounds with BUG-9.

**BUG-11 (P1) — `m_bip152_highbandwidth_to` / `m_bip152_highbandwidth_from`
state fields missing.**
Core tracks TWO bandwidth bits per peer:
- `m_bip152_highbandwidth_to`: WE selected this peer as HB-to-us (we sent
  them sendcmpct(true))
- `m_bip152_highbandwidth_from`: This peer selected US as HB-from-them
  (they sent us sendcmpct(true))
The `from` bit gates the optimistic-reconstruction path
(`net_processing.cpp:4621`). ouroboros has only `wants_cmpctblock` (and
even that conflates announce-True with provides-cmpctblock per BUG-2);
we cannot distinguish the two directions.

**BUG-12 (P2) — getblocktxn fallback to full block missing (W112 BUG-7
re-audit).**
For `getblocktxn` requests targeting blocks > MAX_BLOCKTXN_DEPTH=10 deep,
Core falls back to sending the full block via `MSG_WITNESS_BLOCK`
(`net_processing.cpp:4299-4302`). ouroboros silently drops the response
(`p2p.py:2321-2328` returns without sending anything). Confirms W112
finding; no change.

**BUG-13 (P2) — cmpctblock depth gate uses wrong direction (W112 BUG-5
re-audit).**
W112 found the depth gate at the receive-side has the wrong direction.
Re-reading `p2p.py:2169`:
```python
if announced_height < our_height - MAX_CMPCTBLOCK_DEPTH:
```
This rejects compact blocks ABOVE our tip with a height delta > 5
(announced_height < our_height - 5 means announced_height is at least 6
BELOW our tip — i.e. only "too old" cmpct blocks are dropped). Core's
gate at `net_processing.cpp:4576` is
`pindex->nHeight <= m_chainman.ActiveChain().Height() + 2` (drop if
announce is more than 2 ABOVE tip — handle as plain header revert
otherwise). The direction is opposite in semantics:
- ouroboros drops cmpctblock that's too FAR BELOW tip
- Core caps cmpctblock processing at +2 above tip; far-above goes to
  header-revert
The W112 BUG-5 framing was "wrong direction" — the actual bug is
"missing far-above (+2) cap + missing fRevertToHeaderProcessing" rather
than a direction inversion. Documentation correction.

**BUG-14 (P1) — No low-work cmpctblock drop (`GetAntiDoSWorkThreshold`).**
`net_processing.cpp:4490-4494`: a cmpctblock whose
`prev_block->nChainWork + GetBlockProof(header) <
GetAntiDoSWorkThreshold()` is dropped to prevent low-difficulty DoS.
ouroboros has no equivalent check. Cheap to send a torrent of
low-difficulty cmpctblocks at us and trigger
ProcessNewBlockHeaders / mempool match overhead.

**BUG-15 (P2) — No `fRevertToHeaderProcessing` branch.**
`net_processing.cpp:4664-4666`: if a cmpctblock arrives for a block too
far in the future (> tip+2) and we didn't request it from this peer,
Core treats the embedded header as if it had arrived in a plain
`headers` message, calling `ProcessHeadersMessage(...,
via_compact_block=true)`. ouroboros has no such revert path —
the cmpctblock is just dropped. Headers-first sync misses a hint.

**BUG-16 (P2) — `MSG_CMPCT_BLOCK` getdata serving path missing.**
Core's `ProcessGetBlockData` (`:2461-2476`) handles `inv.IsMsgCmpctBlk()`:
if the block is within `MAX_CMPCTBLOCK_DEPTH` of tip and we have the
cached `m_most_recent_compact_block` for the same hash, push the cached
cmpctblock; otherwise construct on-the-fly with a fresh nonce; for older
blocks (> 5 deep), push the full block instead. ouroboros has no
`MSG_CMPCT_BLOCK` (type 4) handler in its getdata loop — the inv type
falls through to "unknown" and we silently drop. Means: no peer can
pull a compact block from us via getdata.

**BUG-17 (P3) — No `m_highest_fast_announce` dedup at announce time.**
Core (`net_processing.cpp:2109-2111`):
```cpp
if (pindex->nHeight <= m_highest_fast_announce)
    return;
m_highest_fast_announce = pindex->nHeight;
```
Prevents re-announcing the same block (or a same-height alt-chain block)
twice to all peers. ouroboros's `_announce_block` (`block_sync.py:2158`)
fires on every connectTip + every reorg without a height-based dedup
guard. On flap-reorgs at tip we'd announce the same compact block
multiple times — minor bandwidth waste, not a CDIV.

PARTIAL gate: BUG-8 (latent until BUG-3 fixes), BUG-13 (W112 BUG-5
documentation correction), G29 (dead-state — re-audit of W112 BUG-8),
G18 (constant absent rather than enforcement absent).

P0-CDIV count: **1** — BUG-4 (FillBlock IsBlockMutated)
P1 count:      **6** — BUG-1, BUG-2, BUG-3, BUG-5, BUG-11, BUG-14
P2 count:      **9** — BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-12, BUG-13, BUG-15, BUG-16
              (BUG-12 + BUG-13 are documentation-corrections; BUG-8 latent until BUG-3 fixes)
P3 count:      **1** — BUG-17 highest_fast_announce dedup
G29:           re-audit of W112 BUG-8 (P3) — cmpct_peers dead-state — scored
              as a PARTIAL gate, not a fresh BUG, to avoid double-counting
              with W112.

Final tally: **17 BUGS (1 P0-CDIV / 6 P1 / 9 P2 / 1 P3) — distinct from G29 re-audit.**

Audit framework patterns observed
---------------------------------

- **dead-helper-at-call-site (34-wave streak continues):** `cmpct_peers`
  set (`p2p.py:520`) is populated by `on_sendcmpct` (`:2136`) but never
  queried anywhere. The actual HB state lives on `peer.wants_cmpctblock`.
  Same shape as W120 dead-helper finds. Listed as G29 (re-audit of W112
  BUG-8 P3).

- **comment-as-confession:** `compact_blocks.py:354-359` build_short_txid_map
  docstring admits "On collision, we could null out the entry like
  Bitcoin Core, but for simplicity we just overwrite". This is the EXACT
  pattern Core handles via `txn_available[idit->second].reset()` +
  `mempool_count--` (blockencodings.cpp:130-136). The "simplicity"
  shortcut means we lose collision detection — a colliding mempool tx
  silently wins the slot instead of being marked unavailable. Caught by
  test G15 with explicit collision vector.

- **well-engineered helper never wired:**
  `mempool.match_compact_block` (`mempool.py:4363`) IS wired and used by
  both `compact_blocks.py:274` and `:322`. Not a dead-helper. Good.

- **two-pipeline guard extension:** new test
  `test_rust_pipeline_has_no_bip152_handlers` asserts that
  `ferrous-utils/sync/src/network/peer.rs` (and the broader Rust crate)
  contain NO references to `CompactBlock` / `cmpctblock` / `getblocktxn`
  / `blocktxn` outside comments + SipHash helpers (which serve BIP-330
  reconciliation, not BIP-152 P2P). Extends the guard set per FIX-76 /
  FIX-79 ouroboros pattern.

Out-of-scope (future waves)
---------------------------

- Mempool-side collision handling in `build_short_txid_map`
  (comment-as-confession finding) — owned by W106 mempool.
- BIP-330 Erlay sketches that share the SipHash helpers — owned by
  ouroboros-Erlay audit (not yet scheduled).
- `MAX_BLOCKS_TO_ANNOUNCE = 8` reorg-cap interaction with `_announce_block`
  — owned by W103 tx-relay / block-relay scope.
- `m_continuation_block` getblocks INV chaining — irrelevant to BIP-152.

Conclusion
----------

ouroboros has a working BIP-152 receive-and-reconstruct happy path
(SipHash, key derivation, deserialize, partial-state in-flight cache,
getblocktxn round-trip) but is missing the bulk of the HB-peer
management, mutation safety, and getdata-side serving that BIP-152
requires for production interop. The 17 bugs catalogued here are
discovery-only; no production code changed.

Two-pipeline guard PRESERVED + EXTENDED (G30 new test).
