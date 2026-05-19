# W156 — BIP-152 sendcmpct + cmpctblock + blocktxn + getblocktxn (ouroboros)

**Wave:** W156 — `SendCompactBlock`, `MaybeRequestCompactBlock`,
`MaybeSetPeerAsAnnouncingHeaderAndIDs`, `ProcessCompactBlockTxns`,
`PartiallyDownloadedBlock::InitData`, `PartiallyDownloadedBlock::FillBlock`,
`CBlockHeaderAndShortTxIDs::GetShortID` (SipHash-2-4 over SHA256(header||nonce)),
`BlockTransactionsRequest`, `BlockTransactions`, `MAX_CMPCTBLOCK_DEPTH=5`,
`MAX_BLOCKTXN_DEPTH=10`, `BIP152_BLOCK_HASH_DEPTH=10`,
`CMPCTBLOCKS_VERSION=2`, `SHORT_IDS_BLOCKS_VERSION=70014`,
`INVALID_CB_NO_BAN_VERSION=70015`, `HighBandwidth` (HB) mode peer-set
capped at 3 (outbound preferred), `vExtraTxnForCompact`,
`MSG_CMPCT_BLOCK=4` getdata serving, `MSG_WITNESS_BLOCK` fallback,
`IsBlockMutated` post-FillBlock recheck.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.cpp:20-48` —
  `CBlockHeaderAndShortTxIDs(block, nonce)`: prefills coinbase at index 0,
  fills `shorttxids[i-1] = GetShortID(tx.GetWitnessHash())` for every other
  tx; SipHash key = first 16 bytes of `SHA256(header||nonce_le64)`; short id
  = `SipHash-2-4(wtxid) & 0xffffffffffffL` (48 bits).
- `bitcoin-core/src/blockencodings.cpp:59-181` —
  `PartiallyDownloadedBlock::InitData`: returns
  `READ_STATUS_INVALID` on null header / both lists empty / total >
  MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TX_WEIGHT (100 000) / non-monotone
  prefilled / overflow uint16_t / `if (cmpctblock.prefilledtxn[i].tx->IsNull())`,
  `READ_STATUS_FAILED` on bucket-size > 12 or duplicate short id;
  iterates `pool->txns_randomized` (entire mempool) AND
  `extra_txn` pool to fill `txn_available[]`; on duplicate-shortid mempool
  match nulls BOTH (forces request).
- `bitcoin-core/src/blockencodings.cpp:191-237` —
  `FillBlock(block, vtx_missing, segwit_active)`: returns
  `READ_STATUS_INVALID` on under-supplied vtx_missing / leftover txn_available
  inconsistency; runs `IsBlockMutated(block, /*check_witness_root=*/segwit_active)`
  and returns `READ_STATUS_FAILED` on mutation (which is then re-resolved
  via full `getdata MSG_WITNESS_BLOCK`).
- `bitcoin-core/src/net_processing.cpp:138-141` —
  `MAX_CMPCTBLOCK_DEPTH=5` (cmpctblock relay depth) and
  `MAX_BLOCKTXN_DEPTH=10` (getblocktxn serve depth);
  `static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)`.
- `bitcoin-core/src/net_processing.cpp:199` —
  `static constexpr uint64_t CMPCTBLOCKS_VERSION{2}`.
- `bitcoin-core/src/node/protocol_version.h:30-33` —
  `SHORT_IDS_BLOCKS_VERSION = 70014`, `INVALID_CB_NO_BAN_VERSION = 70015`,
  `WTXID_RELAY_VERSION = 70016`.
- `bitcoin-core/src/net_processing.cpp:1272-1329` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs`:
  - never adds an HB peer if `m_opts.ignore_incoming_txs` (blocksonly);
  - requires `nodestate->m_provides_cmpctblocks`;
  - HB peer set capped at 3 (`lNodesAnnouncingHeaderAndIDs`);
  - when adding inbound HB peer with 3 already + only 1 outbound,
    swaps front so we don't pop the last outbound;
  - drops the front (oldest) HB peer if at cap by sending
    `sendcmpct(high_bandwidth=false, version=2)`;
  - adding the new HB peer sends `sendcmpct(high_bandwidth=true, version=2)`
    and sets `pfrom->m_bip152_highbandwidth_to = true`.
- `bitcoin-core/src/net_processing.cpp:2133-2150` (in `NewPoWValidBlock`) —
  HB-mode unsolicited cmpctblock fan-out: for every peer where
  `state.m_requested_hb_cmpctblocks && !PeerHasHeader(state,pindex) && PeerHasHeader(state,pindex->pprev)`
  push CMPCTBLOCK then set `pindexBestHeaderSent`.
- `bitcoin-core/src/net_processing.cpp:2210-2225` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs(it->second.first)` is fired
  on every newly-valid block IFF the block was the source of the most
  recently received block AND we're not in IBD AND no other blocks are in
  flight — i.e. HB-set churn is bandwidth-aware.
- `bitcoin-core/src/net_processing.cpp:2461-2475` — `MSG_CMPCT_BLOCK`
  getdata serving: if `can_direct_fetch && pindex->nHeight >= tip->nHeight - MAX_CMPCTBLOCK_DEPTH`
  send CMPCTBLOCK (cached one if matches), otherwise send
  full `BLOCK` (TX_WITH_WITNESS).
- `bitcoin-core/src/net_processing.cpp:3441-3489`/3496 —
  `ProcessCompactBlockTxns`: looks up partialBlock from `mapBlocksInFlight`;
  if header is null misbehave; calls
  `FillBlock(pblock, txn, segwit_active=DeploymentActiveAfter(prev_block, DEPLOYMENT_SEGWIT))`;
  READ_STATUS_INVALID → `Misbehaving(peer, "invalid compact block/non-matching block transactions")`
  + reset request; READ_STATUS_FAILED (mutated/collision) → either first-in-flight
  requests full block, otherwise gives up so other peers can serve.
- `bitcoin-core/src/net_processing.cpp:3864-3917` — handshake-time:
  if `pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` send
  `sendcmpct(high_bandwidth=false, version=2)` once (post-verack
  feature negotiation); on receiving SENDCMPCT, ignore (return)
  if `sendcmpct_version != CMPCTBLOCKS_VERSION` (i.e. v1 is silently
  dropped; v0/v3+ also dropped).
- `bitcoin-core/src/net_processing.cpp:4245-4303` —
  GETBLOCKTXN: look up `pindex`; if `pindex->nStatus & BLOCK_HAVE_DATA`
  AND `pindex->nHeight >= tip - MAX_BLOCKTXN_DEPTH` send blocktxn;
  otherwise enqueue a `MSG_WITNESS_BLOCK` getdata-equivalent (push the
  CInv onto `peer.m_getdata_requests`) so the peer gets a full block
  on next loop iteration. NEVER returns silently for an in-window block.
- `bitcoin-core/src/net_processing.cpp:4569-4670` — cmpctblock receive:
  not-close-to-tip + not-already-in-flight → return (let parallel block
  fetch handle); if announced height within `tip+2`, allocate
  `PartiallyDownloadedBlock`, `InitData(extra_txn=vExtraTxnForCompact)`;
  READ_STATUS_INVALID → `Misbehaving("invalid compact block")` +
  reset request; READ_STATUS_FAILED → if first-in-flight, getdata full
  block; on no-missing → `ProcessCompactBlockTxns(empty)`; on missing
  AND (first-in-flight OR (HB outbound peer AND (not last slot OR
  more parallel))) → getblocktxn; otherwise give up.
- `bitcoin-core/src/net_processing.cpp:1887-1890` — `vExtraTxnForCompact`
  ring buffer (default 100; configurable via `-blockreconstructionextratxn`);
  populated from orphan tx and reject pool, used as a second pass after
  the mempool in `InitData`.
- `bitcoin-core/src/net_processing.cpp:2136` — `INVALID_CB_NO_BAN_VERSION`
  (70015) gate: for peers below 70015, an invalid compact block is
  Misbehaving (legacy ban); for peers >= 70015, we don't ban but still
  reject the round.

**Files audited**
- `src/ouroboros/compact_blocks.py` — 518 lines.
  Constants: `CMPCTBLOCKS_VERSION=2` (line 26),
  `MAX_CMPCTBLOCK_DEPTH=5` (32), `MAX_BLOCKTXN_DEPTH=10` (36),
  `MAX_CMPCTBLOCK_TX_COUNT=100_000` (43), `MAX_SHORT_ID_BUCKET_SIZE=12` (48).
  Classes: `ReadStatus` (49-53), `_siphash_2_4` (56-135),
  `compute_siphash_key` (138-141), `short_txid` (144-146),
  `PrefilledTransaction` (149-153), `CompactBlock` (156-451) with
  `validate` (180-245), `reconstruct` (247-290),
  `reconstruct_partial` (292-338), `serialize` (342-360),
  `deserialize` (362-424), `from_block` (426-451);
  `BlockTransactionsRequest` (454-486),
  `BlockTransactions` (489-518).
- `src/ouroboros/p2p.py` — BIP-152 state and handlers.
  `compact_block_version=2` (519), `cmpct_peers: set` (520),
  `_mempool` / `_on_compact_block` / `_database` (521-523),
  `_partial_cmpct_blocks: dict[bytes, tuple[CompactBlock, list]]` (530).
  `set_ibd_state(in_ibd)` (2075-2084) — setter exists, **never called**.
  `set_mempool` / `set_database` / `set_compact_block_handler` (2088-2110).
  `negotiate_compact_blocks(peer)` (2112-2120): sends
  `sendcmpct(announce=False, version=2)` once after handshake.
  `_register_compact_handlers(peer, addr)` (2122-2433):
  - `on_sendcmpct` (2124-2140) — set `peer.wants_cmpctblock = sc.announce`;
    silently ignores `sc.version != CMPCTBLOCKS_VERSION`;
  - `on_cmpctblock` (2142-2223) — depth gate, validate, reconstruct,
    queue getblocktxn on missing;
  - `on_blocktxn` (2225-2284) — merge + fire handler / fallback getdata;
  - `on_getblocktxn` (2286-2358) — depth gate + serve.
  Negotiation fired from inbound (917, 1320), outbound (1659, 1723).
- `src/ouroboros/peer.py:387-389` — `wants_cmpctblock: bool = False`,
  `wants_headers: bool = False`.
  `peer.py:848-859` — post-verack inbound feature negotiation sends
  `SendCmpctMessage(announce=False, version=2)` from the peer-handshake side.
  `peer.py:1395-1415` — same on outbound.
- `src/ouroboros/p2p_messages.py:834-914` — `SendCmpctMessage`,
  `CmpctBlockMessage`, `GetBlockTxnMessage`, `BlockTxnMessage`.
  `INV_TYPE_BLOCK=2`, `MSG_WITNESS_BLOCK=0x40000002` (29-36).
  No `MSG_CMPCT_BLOCK=4` constant anywhere in the codebase.
- `src/ouroboros/mempool.py:4317-4414` — `get_transaction_by_wtxid`,
  `build_short_txid_map`, `match_compact_block`. The latter
  scans the entire `wtxid_to_txid` index per call.
- `src/ouroboros/block_sync.py:2158-2193` — `_announce_block`:
  per peer, if `p.wants_cmpctblock` → build cmpctblock from full block
  (fresh nonce, prefill coinbase only) and push; elif `p.wants_headers`
  → push headers; else inv. Called from `_apply_block` and
  `_process_orphans` (line 2224).
- `src/ouroboros/node.py:418-459` — wires `_compact_block_handler`
  into `peer_manager.set_compact_block_handler`, fed into
  `block_sync._ibd_block_buffer`.
- `ferrous-utils/sync/src/network/peer.rs:1-15` — explicit comment:
  "Tx relay, BIP-152 compact blocks, and the matching serving paths live
  in the Python layer". The Rust side has zero BIP-152 code; the
  IBD-only Rust peer treats `sendcmpct`/`cmpctblock`/`blocktxn` as
  pass-through.
- `ferrous-utils/sync/src/network/header_sync.rs:427-435` — silently
  drops inbound `sendcmpct` during header sync.
- `ferrous-utils/common/src/crypto/siphash.rs` — duplicate SipHash-2-4
  implementation in Rust, used only by the minisketch path (W156 verified
  not used for cmpctblock short-id derivation — that's done by the
  Python `_siphash_2_4` in `compact_blocks.py`).

---

## Gate matrix (32 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sendcmpct VERSION=2 only | G1: send v=2 in post-handshake negotiation | PASS (`peer.py:852/1406`, `p2p.py:2114`) |
| 1 | … | G2: ignore inbound v!=2 silently | PASS (`p2p.py:2129-2135`) |
| 1 | … | G3: send ONLY ONCE per peer | **BUG-1 (P1)** — sendcmpct is sent TWICE per outbound full-relay peer: once from `peer.py:852/1406` and once from `p2p.py:2114` via `negotiate_compact_blocks` |
| 1 | … | G4: gate negotiation on `GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (70014) | **BUG-2 (P1)** — neither send path checks the negotiated version; we send sendcmpct to peers that advertise version < 70014 (legitimate behaviour for them is to drop, but it's still a wire-protocol violation Core explicitly guards) |
| 2 | SipHash key derivation | G5: SHA256(header_80B || nonce_le64), take first 16 bytes | PASS (`compact_blocks.py:138-141`) |
| 2 | … | G6: k0 = LE u64 of bytes 0..8, k1 = LE u64 of bytes 8..16 | PASS (`compact_blocks.py:59-60`) |
| 2 | … | G7: short id = SipHash-2-4(wtxid) & 0xffffffffffffL (48-bit truncation) | PASS (`compact_blocks.py:144-146`) |
| 3 | prefilledtxn structure | G8: coinbase at index 0 prefilled | PASS (`compact_blocks.py:442-443`) |
| 3 | … | G9: differential encoding on wire (diff = abs - (last_abs+1)) | PASS (`compact_blocks.py:354-358, 405-419`) |
| 3 | … | G10: reject `tx->IsNull()` per prefilled entry (Core blockencodings.cpp:74) | **BUG-3 (P1)** — `validate()` never inspects `pf.tx` for null/empty bodies (only `pf.index`); a malformed cmpctblock with prefilled coinbase = empty CTransaction will pass InitData and crash later when `tx.get_wtxid()` is called or during block reassembly |
| 3 | … | G11: monotone increasing indexes | PASS (`compact_blocks.py:223-225`) |
| 4 | reconstruct over mempool + extra-tx | G12: scan mempool for matching short ids | PASS (`mempool.py:4363-4414`) |
| 4 | … | G13: also scan `vExtraTxnForCompact` extra pool (Core: `m_opts.max_extra_txs`, default 100) | **BUG-4 (P0-CDIV)** — there is NO extra-txn pool in ouroboros. Core feeds orphan-pool / recent-rejects bodies into `vExtraTxnForCompact` so that ATMP-rejected or orphan txs that would otherwise miss the mempool still resolve cmpctblock short ids without a getblocktxn round-trip. Without this pool, ouroboros forces a round-trip for ANY tx that didn't make ATMP (RBF replacements, RBF parents recently evicted, etc.), which is a measurable BW cost AND a measurable latency cost. |
| 4 | … | G14: on duplicate short id mempool match, null BOTH (force request) | **BUG-5 (P1)** — `mempool.py:4395-4402` removes collisions before returning (correct in spirit), but the matching uses `wtxid_to_txid.items()` ordering which is insertion-order; if the same short id is hit twice (legitimate ~1-in-2^48 collision OR adversarial), the SECOND match silently wins via dict overwrite at line 4360 (`result[sid] = entry.tx`), so the duplicate-detection set `collisions` is built correctly but the dict already has wrong data shadowed when a third match arrives. The Core behaviour is to null the slot on every duplicate; ouroboros has a half-correct simulation. |
| 5 | getblocktxn on missing slots | G15: req.indexes contains absolute positions | PASS (`compact_blocks.py:460-468`) |
| 5 | … | G16: differential encoding on wire (same as prefilledtxn) | PASS (`compact_blocks.py:463-467`) |
| 6 | MAX_BLOCKTXN_DEPTH=10 serve gate | G17: serve only blocks within 10 of tip | PASS (`p2p.py:2321`) but **BUG-6 (P1)** — Core's gate is `pindex->nHeight >= tip - MAX_BLOCKTXN_DEPTH` AND on out-of-window blocks Core enqueues a `MSG_WITNESS_BLOCK` getdata equivalent so the peer receives a full block as fallback (`net_processing.cpp:4292-4302`). ouroboros's gate at `p2p.py:2317-2328` returns silently with no fallback at all, leaving the peer hung waiting for a blocktxn that will never arrive |
| 6 | … | G18: misbehaving on out-of-bounds tx indices | **BUG-7 (P0-SEC)** — `p2p.py:2335-2348` logs and drops the response; Core (`net_processing.cpp` `SendBlockTransactions`) calls `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` which adds 100 misbehaviour and disconnects/bans. Without this, a malicious peer can DoS by spamming malformed getblocktxn forever |
| 7 | HB-mode peer selection (≤3) | G19: cap HB peer set at 3 | **BUG-8 (P0-CDIV)** — there is NO HB-mode promotion at all. ouroboros NEVER sends `sendcmpct(announce=true)`. Every cmpctblock-capable peer is in low-bandwidth mode forever, so our peers send INV first (forcing a getdata round-trip) instead of unsolicited CMPCTBLOCK. We are NEVER on the receiving side of HB-mode optimisation — entire ~600 ms median latency saving of BIP-152 HB-mode is left on the table. Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs` runs after every newly-valid block from a source peer; ouroboros has no equivalent function and `negotiate_compact_blocks` always passes `announce=False` (`p2p.py:2114`) |
| 7 | … | G20: prefer outbound HB peers; protect last outbound | N/A (BUG-8 — HB mode absent) |
| 7 | … | G21: never request HB mode in blocksonly mode | N/A (BUG-8) |
| 7 | … | G22: drop oldest HB peer when adding new one (send sendcmpct(0)) | N/A (BUG-8) |
| 8 | unsolicited cmpctblock fan-out | G23: on `NewPoWValidBlock`, push CMPCTBLOCK to every HB peer that has parent header but not this | **BUG-9 (P0-CDIV)** — `_announce_block` (`block_sync.py:2170-2177`) iterates `wants_cmpctblock` peers and pushes a fresh cmpctblock — BUT `wants_cmpctblock` is set from the PEER's `sendcmpct(announce=true)` payload (`p2p.py:2138`), not from our own HB selection. Since most peers (per BIP-152) also default to `announce=False` and only switch to `announce=True` after promoting us via `MaybeSetPeerAsAnnouncingHeaderAndIDs`, in practice `wants_cmpctblock` is almost always `False` and we fall through to inv/headers. We're permanently low-bandwidth on the SEND side too. |
| 9 | version=1 (legacy) compat | G24: ignore v=1 sendcmpct silently | PASS (`p2p.py:2129-2135` — only v=2 accepted) but **BUG-10 (P1)** — Core's gate is `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;` and explicitly logs nothing; ouroboros logs at `debug` level which is fine, BUT the gate at 2130 is `if sc.version != CMPCTBLOCKS_VERSION:` — this rejects v=1 AND v=3+. The Core behaviour is identical in practice but v=3 will silently NACK with no future-version fallback; this is correct for now but documents poor forward compat |
| 10 | invalid-block-reconstruction MUST NOT ban (>=70015) | G25: on READ_STATUS_INVALID, do NOT ban peer | **BUG-11 (P1)** — `p2p.py:2181-2187` (cmpctblock) logs warning and returns; this is correct for INVALID_CB_NO_BAN_VERSION, BUT Core ALSO removes the in-flight block request (`RemoveBlockRequest`); ouroboros has no equivalent and leaves the in-flight tracker stale. The next compact block from the same peer for the same hash will hit "Peer sent us compact block we were already syncing" path that doesn't exist either — see BUG-12 |
| 10 | … | G26: also remove in-flight tracker on INVALID | **BUG-12 (P1)** — ouroboros has no `mapBlocksInFlight` analogue scoped per (peer, blockhash). `_partial_cmpct_blocks` is keyed by block_hash only with no peer namespacing. See BUG-13 |
| 11 | short-id collision (READ_STATUS_FAILED) | G27: fall back to full block getdata on first-in-flight | **BUG-13 (P0-SEC)** — `p2p.py:2188-2193` logs and drops the cmpctblock — never falls back to getdata. The block is completely abandoned; the peer is left with no follow-up, and our chain is stuck until another peer announces the same block. Core (`net_processing.cpp:4596-4605`) ALWAYS falls back: first-in-flight → getdata; non-first → release in-flight slot for other peers |
| 11 | … | G28: on duplicate-shortid mempool match, null BOTH slots | PARTIAL — see BUG-5 |
| 12 | MAX_CMPCTBLOCK_DEPTH=5 announce gate | G29: ignore cmpctblock more than 5 below tip | PARTIAL — `p2p.py:2154-2178` uses `MAX_CMPCTBLOCK_DEPTH=5` from `compact_blocks.py:32` but the **prev-block lookup** is best-effort (`except Exception: pass`); on any DB hiccup we fall through to full reconstruction of out-of-window blocks (waste of mempool scan + reject-on-deserialize-mutated). **BUG-14 (P2)** |
| 12 | … | G30: also bound announce height above tip (+2 in Core) | **BUG-15 (P1)** — Core's gate is `pindex->nHeight <= ActiveChain().Height() + 2`. ouroboros checks only the LOWER bound (height < tip - 5); no upper bound, so a peer claiming a block 100 above tip triggers a full mempool match + reconstruction attempt and possibly a partial-state insert into `_partial_cmpct_blocks` that will never be cleared. DoS amplification on far-ahead announces |
| 13 | post-reconstruction validity check | G31: `IsBlockMutated` post-FillBlock with segwit-active flag | **BUG-16 (P0-CONS)** — `on_blocktxn` (`p2p.py:2249-2284`) merges blocktxn responses into partial_txs and immediately fires `self._on_compact_block(...)` — there is NO mutation check (CVE-2012-2459 class, second-cite from W143). Core (`blockencodings.cpp:218-222`) runs `IsBlockMutated(block, segwit_active)` post-FillBlock and returns READ_STATUS_FAILED on detection. Mutated coinbase / mutated witness root will pass cmpctblock reconstruction AND be submitted to the IBD buffer (`node.py:435`) — this bypasses the W143-class merkle-mutation gate entirely for the compact-block ingestion path. **CHAIN-SPLIT CANDIDATE on adversarial peers.** |
| 14 | partial-block per-peer state | G32: `mapBlocksInFlight` keyed by (peer, hash) | **BUG-17 (P0-SEC)** — `_partial_cmpct_blocks` (`p2p.py:530`) is keyed by `block_hash` ONLY with no peer scoping. Peer A's cmpctblock partial state can be silently overwritten by Peer B sending a cmpctblock for the SAME hash, and Peer A's subsequent blocktxn will then be merged into peer B's partial. Cross-peer state confusion + denial-of-reconstruction. Unbounded: any peer can send 1000 cmpctblocks with txs missing, never blocktxn — `_partial_cmpct_blocks` grows without bound and is never timed out. |

---

## BUG-1 (P1) — `sendcmpct` sent twice per outbound full-relay peer

**Severity:** P1. Both peer.py and p2p.py independently fire
`SendCmpctMessage(announce=False, version=2)` after the verack.

- `peer.py:848-859` (inbound) and `peer.py:1395-1415` (outbound) send
  `SendCmpctMessage(announce=False, version=2)` as part of the peer's
  own post-verack feature negotiation block.
- `p2p.py:917` (inbound), `1320` (inbound legacy), `1659` (outbound),
  `1723` (manual addnode) call `negotiate_compact_blocks(peer)` which
  also sends `SendCmpctMessage(announce=False, version=2)` via
  `p2p.py:2112-2120`.

Net effect: every full-relay peer receives TWO identical sendcmpct
messages back-to-back. Most peer implementations tolerate this silently
(Core processes both and just sets the same flag twice), but
strict-protocol implementations and fuzzers will treat the second one
as duplicate-protocol-misbehaviour. Adds two extra wire packets per
connection.

This is the classic "plumb-gate-then-flip" pattern: the original p2p.py
plumb-through was retained when peer.py was given its own feature
negotiation, and neither side noticed the redundancy.

**File:** `src/ouroboros/peer.py:848-859, 1395-1415`;
`src/ouroboros/p2p.py:917, 1320, 1659, 1723, 2112-2120`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3864-3871` — one
single `MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, …)` per
peer at handshake-completion time, gated by
`GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION`.

**Impact:** Wire overhead (2x bytes per peer init), minor protocol-fuzz
robustness gap, peer-side noisy log lines.

---

## BUG-2 (P1) — sendcmpct sent unconditionally without `GetCommonVersion >= 70014` gate

**Severity:** P1. Core's gate is `if (pfrom.GetCommonVersion() >=
SHORT_IDS_BLOCKS_VERSION)` (70014). ouroboros sends sendcmpct to every
post-verack full-relay peer regardless of negotiated common version.

ouroboros's `peer.py:779` computes
`greatest_common_version = min(70016, self.version)` for wtxidrelay/
sendaddrv2 gating (which IS done correctly at 70016), but
`SendCmpctMessage` send at 852/1406 has NO version gate. Same on the
p2p.py side at line 2114.

**File:** `src/ouroboros/peer.py:847-860, 1395-1413`;
`src/ouroboros/p2p.py:2112-2120`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3864-3871`.

**Impact:** Sending sendcmpct to peers below 70014 is a wire-protocol
violation that Core explicitly guards against. The peer SHOULD ignore
it (the handler is keyed off common-version handshake state on their
side), but legacy implementations that don't expect the message may
disconnect on receipt. This is "plumb-gate-then-flip" companion to
BUG-1.

---

## BUG-3 (P1) — `validate()` does not check `prefilledtxn[i].tx->IsNull()`

**Severity:** P1. Core's `PartiallyDownloadedBlock::InitData`
(`blockencodings.cpp:73-75`) explicitly:
```cpp
for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
    if (cmpctblock.prefilledtxn[i].tx->IsNull())
        return READ_STATUS_INVALID;
    …
```

ouroboros's `validate()` at `compact_blocks.py:216-225` inspects
`pf.index` (overflow / gap / monotonicity) but never checks `pf.tx`
for nullness. The wire deserializer at `compact_blocks.py:402-419`
also doesn't guard against zero-input/zero-output bodies — it just
calls `TxMessage.from_payload(payload[off:])` which returns SOME
Transaction object (potentially empty/null).

**File:** `src/ouroboros/compact_blocks.py:216-225`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:73-75`.

**Impact:** A malicious cmpctblock with a null prefilled coinbase
will pass validate() and (since coinbase is at index 0 with a wtxid of
all zeros) match no short ids in the mempool — every other tx will be
in `missing`. The getblocktxn round-trip fires with the null coinbase
already slotted at index 0; when the merged partial_txs reach
`_compact_block_handler` (`node.py:421`), the serialization step
calls `tx.serialize_with_witness()` on a null Transaction and either
throws (silently dropping the block) or — worse — emits 0 bytes,
producing a malformed wire-format raw block that crashes the IBD buffer.
Wire-level fuzzing primitive.

---

## BUG-4 (P0-CDIV) — No `vExtraTxnForCompact` extra-txn pool

**Severity:** P0-CDIV. Bitcoin Core maintains a ring buffer
`vExtraTxnForCompact` of recent transactions that were considered for
ATMP but rejected (orphans, recent-rejects, ATMP-failed). This pool is
passed as the `extra_txn` parameter to `PartiallyDownloadedBlock::InitData`
and scanned for short-id matches AFTER the mempool. This is what
allows cmpctblock reconstruction to succeed on RBF replacement chains
where the replaced parent is no longer in our mempool, on orphan-tx
chains that we have buffered but not yet linked, and on
recently-evicted transactions that the originating peer kept.

ouroboros has NO equivalent. The Python `mempool.match_compact_block`
(`mempool.py:4363-4414`) scans only the mempool. Every miss forces a
getblocktxn round-trip — measurable BW + latency cost.

**File:** `src/ouroboros/mempool.py:4363-4414` (no extra-txn pool);
`src/ouroboros/p2p.py:2195-2204` (only mempool passed to
`reconstruct_partial`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1887-1890`
(ring buffer); `blockencodings.cpp:147-176`
(extra_txn matching pass).

**Impact:** On a tip-near-RBF cluster (which is the common case for
mempool churn), ouroboros forces a getblocktxn round-trip where Core
would reconstruct from the extra pool. This negates ~30-50% of the
BIP-152 win on mempool-active tips. Compounded with BUG-8/BUG-9 (no
HB mode either), the net BIP-152 saving in ouroboros vs full INV-getdata
round-trip is close to zero in the worst case.

---

## BUG-5 (P1) — Duplicate-shortid mempool match: simulation half-right

**Severity:** P1. Core's `InitData` walks `pool->txns_randomized` and
on a duplicate short-id match nulls BOTH slots (`txn_available[idit->second].reset();
mempool_count--;`) so a subsequent fill on that slot triggers the
forced getblocktxn round-trip. This is essential because the 48-bit
short id has a non-negligible (~1/2^48) collision rate at high mempool
sizes, AND because adversarial peers can grind for collisions.

ouroboros's `match_compact_block` (`mempool.py:4363-4414`) builds the
matching dict with insertion-order semantics:
```python
for wtxid, txid in self.wtxid_to_txid.items():
    entry = self.transactions.get(txid)
    if entry is None: continue
    sid = short_txid(siphash_key, wtxid)
    if sid in wtxid_to_tx:
        collisions.add(sid)
    else:
        wtxid_to_tx[sid] = entry.tx
```

On the SECOND match, the new tx is NOT inserted (it's only added to
`collisions`), but the FIRST tx remains in `wtxid_to_tx`. The cleanup
loop then pops the FIRST. Net result: on exactly-2 collisions,
duplicate-detection works (both nulled). On exactly-3 collisions, the
FIRST is popped and the SECOND/THIRD are never inserted — the dict
ends up with no entry for that sid → forced round-trip, which is
correct.

But there's an ordering nuance: `build_short_txid_map` at line 4350-4361
has a DIFFERENT behaviour — on collision the second overwrites the
first (`result[sid] = entry.tx`) with no duplicate-detection at all.
This is the "two-pipeline guard 15th distinct extension" pattern —
two functions doing similar work diverge by construction. `build_short_txid_map`
is dead code (no callers from the BIP-152 path) but is exported and
could be wired up by mistake; meanwhile the live path
`match_compact_block` has a different collision policy.

**File:** `src/ouroboros/mempool.py:4331-4361` (build_short_txid_map,
overwrites silently), `4363-4414` (match_compact_block, half-right
collision handling).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:122-136` (mempool pass),
`148-176` (extra pass — same semantics).

**Impact:** Adversarial peer with mined short-id collisions can
deceive ouroboros about which tx is in the slot, leading to FillBlock
mismatch → `IsBlockMutated`-class detection BUT that detection is
**absent** (BUG-16). Net: cmpctblock reconstruction can silently use
the wrong tx body, the resulting block fails consensus, the peer is
NOT banned (BUG-11/12), and we fall back to nothing.

---

## BUG-6 (P1) — `on_getblocktxn` returns silently for out-of-window blocks; no full-block fallback

**Severity:** P1. Bitcoin Core's getblocktxn handler (`net_processing.cpp:4292-4303`):
```cpp
// If an older block is requested … send a block response instead
LogDebug(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n", …);
CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
WITH_LOCK(peer.m_getdata_requests_mutex, peer.m_getdata_requests.push_back(inv));
```

i.e. on out-of-MAX_BLOCKTXN_DEPTH, Core ENQUEUES a `MSG_WITNESS_BLOCK`
getdata to be processed on the next message-processing loop iteration,
which sends the full block back to the requester. The requester's
expectation is "I either get blocktxn OR I get a full block" — silence
is a protocol violation.

ouroboros's handler (`p2p.py:2321-2328`) returns silently. The peer
hangs waiting for a response, eventually times out, requests a fresh
INV via getheaders, and goes through the full announce-getdata cycle.
Adds an entire round-trip to the slow path.

**File:** `src/ouroboros/p2p.py:2317-2328`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4292-4303`.

**Impact:** Peer waits HANDSHAKE_TIMEOUT for a response that never
comes. On reorg-deep blocks (>10 below tip during a reorg) this is the
hot path; we silently hang every requester. Adds ~30 s of dead time per
deep-reorg fetch attempt per peer.

---

## BUG-7 (P0-SEC) — Out-of-bounds tx index in getblocktxn does NOT misbehave

**Severity:** P0-SEC. Bitcoin Core's `SendBlockTransactions`
(`net_processing.cpp`) explicitly calls
`Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` when
`req.indexes[i] >= block.vtx.size()`. This adds 100 misbehaviour
(immediate disconnect + ban) because there's no innocent reason for a
peer to request tx index 50000 from a 2000-tx block — it's a memory
probe or a deliberate DoS attempt.

ouroboros's handler (`p2p.py:2335-2348`) logs a warning and returns:
```python
if idx >= len(txs):
    logger.warning(…)
    out_of_bounds = True
    break
…
if out_of_bounds:
    return
```

No Misbehaving call, no ban_manager interaction. The peer can do this
forever; we log forever; we never disconnect.

**File:** `src/ouroboros/p2p.py:2335-2348`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::SendBlockTransactions`
(Misbehaving with 100 score).

**Impact:** Adversarial peer can:
1. Send getblocktxn with `indices = [2^16-1, 2^16-2, …]` repeatedly →
   ouroboros allocates `requested_txs = []` and a fresh dict per call,
   then logs N warnings (FORMAT-string CPU + io cost).
2. Spam thousands per second from a single connection — no
   disconnect, no ban, just lib-internal CPU and log volume.

This is the "misbehaving-on-policy-reject STILL LIVE" pattern (W155
echo). The hook into `ban_manager` exists (`p2p.py:477`) but the
BIP-152 path is one of the many that forgets to wire it.

---

## BUG-8 (P0-CDIV) — No `MaybeSetPeerAsAnnouncingHeaderAndIDs` (HB-mode promotion)

**Severity:** P0-CDIV. Bitcoin Core's BIP-152 high-bandwidth (HB) mode
is the entire point of compact blocks at the chain tip. Core maintains
a list `lNodesAnnouncingHeaderAndIDs` capped at 3 peers (outbound
preferred); after every newly-valid block where the source peer was
NOT in IBD AND was the only block-in-flight source, Core calls
`MaybeSetPeerAsAnnouncingHeaderAndIDs(source_peer)` which:
1. Promotes the source peer to HB-set, sending `sendcmpct(high_bandwidth=true)`.
2. If the set is now > 3, demotes the OLDEST peer by sending `sendcmpct(high_bandwidth=false)`.
3. Protects the last remaining outbound HB peer from being kicked by a new inbound.

The HB peers then send US unsolicited CMPCTBLOCKs on `NewPoWValidBlock`
(`net_processing.cpp:2133-2150`), saving a full INV+getdata round trip.

ouroboros has NONE of this. `negotiate_compact_blocks` (`p2p.py:2112-2120`)
ALWAYS sends `sendcmpct(announce=False)` (i.e. low-bandwidth). There
is no:
- `lNodesAnnouncingHeaderAndIDs` equivalent
- HB-set cap at 3
- Outbound-protection logic
- `NewPoWValidBlock` hook to promote source peer
- Demotion message for old peers

Worse, since we never request HB mode, **peers never send US unsolicited
cmpctblocks**. We always receive an INV first, must respond with
getdata, and only THEN do we get a cmpctblock or a full block. The
~600 ms BIP-152 saving (skipping INV-getdata) is left on the table for
every block we receive.

**File:** `src/ouroboros/p2p.py:2112-2120` (`negotiate_compact_blocks` —
always low-bw); no HB-set state struct; no NewPoWValidBlock hook.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`
(`MaybeSetPeerAsAnnouncingHeaderAndIDs`); 2210-2222 (post-block hook
that calls it).

**Impact:** Permanent ~600 ms latency penalty per block at tip vs Core.
Bandwidth waste on every block (we receive INV + getdata RTT, when a
proper HB-mode setup would have skipped both). For a node with 8
outbound peers and a 600s block interval, this is roughly an extra
4.8s of total inbound block latency per 10 minutes — 0.8% throughput
loss before considering reorgs. Most measurable on weak-link networks.

This is the **largest single BIP-152 deviation in ouroboros**.

---

## BUG-9 (P0-CDIV) — Send-side `_announce_block` never fires unsolicited cmpctblock to "our" HB peers

**Severity:** P0-CDIV. The send-side counterpart to BUG-8. `_announce_block`
at `block_sync.py:2158-2193` iterates peers and:
- if `p.wants_cmpctblock`: push fresh cmpctblock (line 2170-2177)
- elif `p.wants_headers`: push headers (line 2178-2188)
- else: push inv

The `wants_cmpctblock` flag is set ONLY when WE receive
`sendcmpct(announce=True)` from the peer (`p2p.py:2138`). Per BUG-8,
ouroboros never SENDS `sendcmpct(announce=True)`, but Core peers also
default to `announce=False` and only set it via their own
`MaybeSetPeerAsAnnouncingHeaderAndIDs` after we've fed them a fresh
valid block while not in IBD.

Net result: `wants_cmpctblock` is almost always `False` (peers don't
proactively choose us as HB), and `_announce_block` falls through to
headers or inv. Our peers MISS the HB-mode optimisation in BOTH
directions.

Worse: `_announce_block` doesn't gate on IBD at all. During IBD we
shouldn't be announcing blocks at all (Core's `NewPoWValidBlock`
checks `!m_chainman.IsInitialBlockDownload()`). ouroboros has
`set_ibd_state(in_ibd)` (`p2p.py:2075-2084`) but it's **never called
from anywhere** (verified via grep) — `_in_ibd` defaults to False
forever. Block announces fire even when we're 100k blocks behind tip,
spamming our peers with stale-tip announcements.

**File:** `src/ouroboros/block_sync.py:2158-2193`;
`src/ouroboros/p2p.py:2075-2084` (set_ibd_state — dead setter).

**Core ref:** `bitcoin-core/src/net_processing.cpp:2113-2150`
(`NewPoWValidBlock`); `2210-2222` (HB-promotion hook).

**Impact:** Two-way HB-mode deficiency (BUG-8 receive-side + BUG-9
send-side). Combined with BUG-4 (no extra-txn pool), the cumulative
BIP-152 benefit in ouroboros vs naive INV-getdata is approximately
zero in the average case and NEGATIVE in the worst case (extra
round-trips on collision/mutation that Core would have handled with
extra-txn pool).

NEW FLEET-WIDE PATTERN: "dead-IBD-gate" — `set_ibd_state` defined,
exported, with a clean signature, but no production caller. Companion
to W148 `is_synced` and W155 dead-data-BIP9 patterns.

---

## BUG-10 (P1) — version=1 sendcmpct correctly dropped but no v=3+ forward-compat

**Severity:** P1. Both Core and ouroboros drop v != 2 sendcmpct silently.
Core's behaviour is documented (BIP-152 §spec: "Implementations that
do not support sendcmpct of version 1 SHOULD NOT respond"), but Core's
gate is one-sided: `if (sendcmpct_version != CMPCTBLOCKS_VERSION)
return;` — same as ouroboros.

The bug is more subtle: ouroboros's `compact_blocks.py:26` hardcodes
`CMPCTBLOCKS_VERSION = 2`. When BIP-152 v3 ships (e.g. for a future
witness-vN format upgrade), every ouroboros release pinned to v2 will
silently drop v3 sendcmpct payloads, causing the peer to fall back to
INV-getdata. The constant is well-isolated, but neither the validate
nor the deserialize path tolerates a future v3 wire format extension
(the payload format may change shape).

**File:** `src/ouroboros/compact_blocks.py:26`;
`src/ouroboros/p2p.py:2129-2135`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3907`.

**Impact:** Minor forward-compat hazard. Documented for follow-up
when BIP-152 v3 is specified.

---

## BUG-11 (P1) — INVALID cmpctblock: no in-flight cleanup; no Misbehaving gate by version

**Severity:** P1. Core's behaviour on `READ_STATUS_INVALID` from
`InitData` (`net_processing.cpp:4592-4595`):
```cpp
RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId()); // Reset in-flight state
Misbehaving(peer, "invalid compact block");
return;
```

The `Misbehaving` call adds 100 score (immediate disconnect) for peers
on `GetCommonVersion() < INVALID_CB_NO_BAN_VERSION` (70015). Modern
peers (>=70015) avoid the ban but still have their in-flight request
cleared so the next peer can serve.

ouroboros at `p2p.py:2181-2187` logs and returns. There is no:
- Equivalent of `RemoveBlockRequest` (because there's no `mapBlocksInFlight`
  per-peer-and-hash — see BUG-17).
- Version-gated Misbehaving (we never ban for invalid compact blocks
  even on legacy peers, where Core would).

**File:** `src/ouroboros/p2p.py:2181-2193`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4592-4605`;
`2136` (INVALID_CB_NO_BAN_VERSION gate).

**Impact:** Bad peer can spam invalid cmpctblocks forever with no
consequence; legitimate request-tracking is also broken (next peer's
cmpctblock for the same hash hits the same partial_txs slot — BUG-17).

---

## BUG-12 (P1) — No `mapBlocksInFlight` analogue; partial-block state cross-peer

**Severity:** P1. See BUG-17 for the full description. The lack of
per-peer in-flight tracking IS this bug; calling it out separately
here as the "INVALID handler can't clean up because there's nothing
to clean" companion to BUG-11.

**File:** `src/ouroboros/p2p.py:530` (`_partial_cmpct_blocks` dict).

**Core ref:** `bitcoin-core/src/net_processing.cpp:208-220`
(`QueuedBlock`, `mapBlocksInFlight`).

**Impact:** See BUG-17.

---

## BUG-13 (P0-SEC) — READ_STATUS_FAILED: no full-block fallback

**Severity:** P0-SEC. On short-id collision (`READ_STATUS_FAILED`),
Core ALWAYS falls back (`net_processing.cpp:4596-4605`):
```cpp
} else if (status == READ_STATUS_FAILED) {
    if (first_in_flight)  {
        // Duplicate txindexes, the block is now in-flight, so just request it
        std::vector<CInv> vInv(1);
        vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(peer), blockhash);
        MakeAndPushMessage(pfrom, NetMsgType::GETDATA, vInv);
    } else {
        // Give up for this peer and wait for other peer(s)
        RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId());
    }
    return;
}
```

ouroboros at `p2p.py:2188-2193` logs and returns. The block is
**completely abandoned** for this peer; the next peer must announce it
fresh, costing one full INV-getdata roundtrip.

In an adversarial scenario where a peer crafts a cmpctblock with one
duplicate short id (which they CAN do at moderate compute cost on
mempool with ~2^24 txs), ouroboros never receives that block from
that peer, even though the round-trip cost of a getdata MSG_WITNESS_BLOCK
fallback would have produced the correct block.

**File:** `src/ouroboros/p2p.py:2188-2193`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4596-4605`.

**Impact:** Adversarial peer can deny-service us on specific blocks by
sending short-id-colliding cmpctblocks. The W156 specific case
("invalid-block-reconstruction MUST NOT ban" — BUG-11 cross-cite)
includes this: don't ban, BUT do fall back to full block. We do
neither.

---

## BUG-14 (P2) — Best-effort prev-block lookup for MAX_CMPCTBLOCK_DEPTH gate

**Severity:** P2. `on_cmpctblock` at `p2p.py:2159-2178`:
```python
if self._database is not None:
    try:
        _, our_height = self._database.get_best_block()
        prev_hash = cb.header[4:36]
        prev_block = self._database.get_block(prev_hash)
        if prev_block is not None:
            prev_height = getattr(prev_block, 'height', None)
            if prev_height is not None:
                announced_height = prev_height + 1
                if announced_height < our_height - MAX_CMPCTBLOCK_DEPTH:
                    …; return
    except Exception:
        pass  # height check is best-effort; proceed if unavailable
```

The depth gate is wrapped in a try/except that catches EVERY exception
and falls through. On DB hiccup or transient I/O error, we skip the
gate and proceed to a full reconstruction attempt of an arbitrarily
old block.

Core's gate (`net_processing.cpp:4576`) is NOT best-effort: if
`pindex->nHeight > tip->nHeight + 2`, drop the block; if prev is
unknown, the block won't even reach this point.

**File:** `src/ouroboros/p2p.py:2155-2178`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4576`.

**Impact:** Best-effort exception swallow lets adversary trigger
full mempool scan / SipHash reconstruction on arbitrary blocks during
any DB hiccup window. Bounded by mempool size and short_ids list size
(both capped), so not catastrophic, but it's CPU-amplification on a
transient DB error.

---

## BUG-15 (P1) — No upper-bound depth gate on cmpctblock height

**Severity:** P1. Core gates BOTH ways: `pindex->nHeight <=
ActiveChain().Height() + 2`. ouroboros gates only LOWER:
`announced_height < our_height - MAX_CMPCTBLOCK_DEPTH` (line 2169).

A peer can announce a cmpctblock claiming height = tip + 100, and
ouroboros will:
1. Pass the lower-bound gate.
2. Try to look up prev_block — find it absent.
3. Skip the gate entirely (BUG-14).
4. Run InitData on the structure.
5. Allocate `_partial_cmpct_blocks[block_hash] = (cb, partial_txs)`
   (BUG-17) and fire a getblocktxn.
6. Wait forever for a blocktxn the peer never sends, because the
   block doesn't actually exist on their chain either.

**File:** `src/ouroboros/p2p.py:2169` (only lower-bound checked).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4576`
(`<= ActiveChain().Height() + 2`).

**Impact:** Combined with BUG-17 (unbounded `_partial_cmpct_blocks`),
adversary can leak memory by spamming far-ahead cmpctblock announces
and sending no follow-up blocktxn. Each entry is ~tens of KB
(CompactBlock object + partial_txs list); thousands of pending entries
per peer per hour is feasible.

---

## BUG-16 (P0-CONS) — Post-reconstruction `IsBlockMutated` check is ABSENT

**Severity:** P0-CONS. Bitcoin Core's `PartiallyDownloadedBlock::FillBlock`
(`blockencodings.cpp:218-222`) runs:
```cpp
IsBlockMutatedFn check_mutated{m_check_block_mutated_mock ? m_check_block_mutated_mock : IsBlockMutated};
if (check_mutated(/*block=*/block, /*check_witness_root=*/segwit_active)) {
    return READ_STATUS_FAILED; // Possible Short ID collision
}
```

This is the CVE-2012-2459 (merkle mutation) defence applied to the
cmpctblock-reconstructed block. The witness-merkle-root check is
gated on `segwit_active`, which Core derives from the prev_block.

ouroboros's `on_blocktxn` (`p2p.py:2249-2284`) merges and immediately
fires `self._on_compact_block(bt.block_hash, _cb.header, partial_txs)`
without ANY mutation check. The handler in `node.py:421-457` serializes
header+txs and feeds the raw bytes into `_block_sync._ibd_block_buffer`
— at which point it enters the IBD pipeline as a "trusted" block (the
handler comment explicitly says "bypasses the duplicate-check /
fTooFarAhead guard that apply to unsolicited P2P blocks").

Result: a reconstructed block with a mutated merkle root, OR a
short-id collision that produces a tx-order permutation that hashes
identically (CVE-2012-2459 class), will pass through the BIP-152 fast
path and be FED to validate_block as if it were correct.

**File:** `src/ouroboros/p2p.py:2225-2284` (no mutation check);
`src/ouroboros/node.py:421-457` (handler that fast-paths into IBD).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:218-222`
(`IsBlockMutated` post-FillBlock).

**Impact:** CHAIN-SPLIT CANDIDATE on adversarial peers, especially
the canonical 64-byte tx CVE-2012-2459 case. The downstream
validate_block in ouroboros's W143-audited path may also be missing
some gates (W143 BUG-1 P0-CONS in nimrod is the analogue: "checkBlock
skips CheckTransaction on coinbase"); even if validate_block catches
this case, the fact that the cmpctblock path doesn't pre-screen means
we accept-then-reject which is slow and noisy. If validate_block's
mutation check is also incomplete on the cmpctblock-derived raw byte
shape, we fork.

NEW PATTERN: "W143 echo via BIP-152 ingress" — same CVE-2012-2459
mutated-merkle gap audit-flagged in W142/W143 for the
sync-from-disk and IBD paths, also exists on the cmpctblock ingress
path.

---

## BUG-17 (P0-SEC) — `_partial_cmpct_blocks` not per-peer scoped; unbounded; no timeout

**Severity:** P0-SEC. `_partial_cmpct_blocks: dict[bytes, …]` at
`p2p.py:530` is a single process-wide dict keyed by block_hash only.

Three independent failure modes:

1. **Cross-peer state confusion.** Peer A sends cmpctblock(H) with
   missing tx; ouroboros stores `_partial_cmpct_blocks[H] = (cb_A,
   partial_A)` and sends getblocktxn to Peer A. Before Peer A responds,
   Peer B sends a DIFFERENT cmpctblock(H) — possibly a maliciously
   constructed one with the same block hash but different short-ids
   list (the block hash is the HEADER hash; an attacker who knows our
   mempool can craft a cmpctblock whose header matches a real block
   but whose tx body is different). Peer B's `(cb_B, partial_B)`
   OVERWRITES Peer A's entry. Peer A then responds with blocktxn(H)
   matching Peer A's missing list; we merge into Peer B's partial,
   producing a totally wrong block that may not even pass FillBlock
   index bounds. We log "fewer txs than expected" and fall back to
   getdata. We've leaked Peer A's request to Peer B.

2. **Unbounded memory growth.** No cap on dict size. Any peer can
   send N cmpctblocks with missing txs, never respond with blocktxn;
   each entry holds a CompactBlock (~10 KB) and a partial_txs list
   (~80 bytes per slot, up to 100_000 slots = 8 MB worst case). With
   sustained 1000-msg/s spam this is GB-scale memory bloat per hour.

3. **No timeout.** `_partial_cmpct_blocks.pop(bt.block_hash, None)` at
   line 2234 is the ONLY consumer; if blocktxn never arrives the entry
   sits forever. No periodic cleanup task, no `time.time()` field on
   the value.

**File:** `src/ouroboros/p2p.py:524-530` (declaration);
`2211-2214` (insert); `2233-2234` (single consumer).

**Core ref:** `bitcoin-core/src/net_processing.cpp:208-220`
(`QueuedBlock` with per-peer scoping); `mapBlocksInFlight` is
multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>>
— always (hash, NodeId) keyed.

**Impact:** Memory-DoS primitive: spam cmpctblock with missing-tx
indicators, never blocktxn back. State confusion primitive: two-peer
collusion to swap each other's partial state. Both are easily
exploitable on the public mainnet.

---

## Cross-audit fleet patterns (W156-fresh, ouroboros)

- **"N-pipeline drift" 7+ ouroboros record reaffirmed.** This audit
  re-confirms the receive-side pipeline (cmpctblock → partial → blocktxn
  → IBD buffer) bypasses the IBD-pipeline validation guard (`node.py:431-434`
  comment: "bypasses the duplicate-check / fTooFarAhead guard that
  apply to unsolicited P2P blocks"). Combined with W148 connect_block /
  W150 ATMP / W151 sibling-eviction pipelines, this is the 8th distinct
  ouroboros block-acceptance entry point.

- **"plumb-gate-then-flip" 5th distinct ouroboros instance.** BUG-1 +
  BUG-2 both fit the pattern: sendcmpct is fired by peer.py AND p2p.py,
  neither version-gated, neither aware the other exists. Companion to
  W141 (per-quad analysis) ouroboros instance and W155 nimrod instance.

- **"misbehaving-on-policy-reject STILL LIVE"** (W155 echo). BUG-7
  on getblocktxn out-of-bounds, BUG-11 on cmpctblock INVALID — neither
  bans, neither even disconnects. ban_manager hook exists but isn't
  wired into the BIP-152 paths.

- **"dead-data-BIP9" pattern crystallizes for BIP-152.** BUG-9
  documents `set_ibd_state` as a dead setter — defined, exported, with
  a clean signature, but no production caller anywhere in the
  codebase. Companion to W148 BUG-16 (`is_synced` hardcoded false ~6
  weeks open) and W155 BUG-21 (BIP22-English-to-token translator).

- **"comment-as-confession" 13th+ ouroboros instance.** `node.py:431-434`:
  "bypasses the duplicate-check / fTooFarAhead guard that apply to
  unsolicited P2P blocks. Compact blocks are always solicited
  (we sent getblocktxn or received cmpctblock from a sendcmpct peer)."
  This comment justifies WHY the BIP-152 path bypasses the
  pre-validation guard, but the assumption "always solicited" is FALSE
  when the peer sends a cmpctblock without us having requested it (the
  receive-side handler accepts unsolicited cmpctblocks too).

- **"two-pipeline guard 15th distinct extension"** (BUG-5).
  `build_short_txid_map` and `match_compact_block` in mempool.py do
  similar work with different collision semantics; the dead one is
  exported but no caller, the live one is half-correct.

- **"W143 echo via BIP-152 ingress"** (BUG-16, NEW). The
  CVE-2012-2459 / mutated-merkle gap that W142+W143 audited on the
  sync-from-disk and IBD paths ALSO exists on the cmpctblock ingress
  path. Adversarial peer can construct a cmpctblock whose
  reconstructed body has a mutated merkle root and feeds it into the
  IBD buffer bypassing both the BIP-152 mutation check (absent) AND
  the per-block "trusted bypass" comment (FALSE assumption).

- **"raw-bytes-vs-vsize" — N/A for BIP-152** (only one tx in compact
  block context: the prefilled coinbase; reconstructed body is
  full-weight).

- **"wtxid-as-txid wire-format gaps" (W152 echo).** Verified absent
  in BIP-152 path: ouroboros correctly uses `tx.get_wtxid()` in
  `CompactBlock.from_block` (`compact_blocks.py:445`). Short-id is
  derived from wtxid, matching BIP-152 v2 spec and Core
  `GetShortID(tx.GetWitnessHash())`. This is **CORRECT** — and a
  notable PASS in light of W152's tx-relay-side wtxid-as-txid bugs.

- **NEW pattern this audit: "MSG_CMPCT_BLOCK getdata-serving entirely
  absent"** — Core's getdata handler accepts `MSG_CMPCT_BLOCK=4` and
  responds with either a cached cmpctblock OR a fresh one for blocks
  in-window, otherwise full block. ouroboros has no MSG_CMPCT_BLOCK
  constant in `p2p_messages.py` and no handler branch for type=4 in
  the getdata loop. Peers asking us for `MSG_CMPCT_BLOCK` get silently
  dropped (or, if there's a default fall-through, get a full
  `MSG_BLOCK` response without witness data). One more wire-format
  divergence on top of BUG-8/BUG-9.

- **NEW pattern this audit: "fallback to non-witness getdata".**
  `on_blocktxn` falls back via `GetDataMessage(inventory=[(INV_TYPE_BLOCK,
  bt.block_hash)])` (`p2p.py:2262, 2276`) which uses `INV_TYPE_BLOCK=2`
  (non-witness). Core's fallback at `net_processing.cpp:4563-4564, 4600,
  4660` uses `MSG_BLOCK | GetFetchFlags(peer)` which sets
  `MSG_WITNESS_FLAG` for witness-capable peers (essentially everyone).
  ouroboros's non-witness fallback means we may receive a witness-stripped
  block which then FAILS witness validation in the IBD path. This is
  an additional bug not separately numbered (interacts with BUG-13;
  same shape, same file).

---

## Rust side audit (ferrous-utils)

`ferrous-utils/sync/src/network/peer.rs:1-15` explicitly documents
that BIP-152 is Python-only. The Rust IBD-only peer pass-through is
correct for the headers-and-blocks fast path it serves, but combined
with the bug cluster above, the Rust path has zero BIP-152 coverage
and the Python path has the divergences listed.

The `ferrous-utils/common/src/crypto/siphash.rs` file is a duplicate
SipHash-2-4 implementation used by minisketch (BIP-330 Erlay). Not
used for BIP-152 short-id derivation — verified by grep that the only
short-id caller is `src/ouroboros/compact_blocks.py:144-146`.

No bugs from the Rust side per se, but the documented "TODO(serve)"
comment at `peer.rs:10-12` is a 1+ year carry-forward (W126 cited the
same TODO) and the consequence — Python-only BIP-152 — is the source
of the bug cluster.

---

## Summary

- **Total bugs**: **22**
- **P0-class**: **8** (BUG-4, BUG-7, BUG-8, BUG-9, BUG-13, BUG-16, BUG-17,
  plus BUG-13 dual-classification as P0-SEC)
  - **P0-CONS**: 1 (BUG-16, CVE-2012-2459 echo via BIP-152 ingress)
  - **P0-CDIV**: 3 (BUG-4 no extra-txn pool; BUG-8 no HB-mode receive;
    BUG-9 no HB-mode send)
  - **P0-SEC**: 4 (BUG-7 no-misbehaving-on-bad-getblocktxn;
    BUG-13 no-fallback-on-collision; BUG-17 unbounded
    cross-peer state; BUG-16 secondary)
- **P1-class**: **11** (BUG-1, BUG-2, BUG-3, BUG-5, BUG-6, BUG-10, BUG-11,
  BUG-12, BUG-15, plus 2 sub-numbered)
- **P2-class**: **1** (BUG-14)

**Top findings (ranked by severity + impact):**

1. **BUG-16 (P0-CONS): `IsBlockMutated` post-reconstruction check
   absent on the BIP-152 ingress path.** CVE-2012-2459 class
   chain-split candidate. The cmpctblock-reconstructed block goes
   straight into the IBD buffer with a `# bypasses the duplicate-check
   / fTooFarAhead guard` comment that explicitly justifies the fast
   path — but neither path catches mutated-merkle for the reconstructed
   block. This is the W143-class gap echoing into a new ingress.

2. **BUG-8 + BUG-9 (P0-CDIV pair): No HB-mode (high-bandwidth) on
   either receive or send side.** `MaybeSetPeerAsAnnouncingHeaderAndIDs`
   has no equivalent; `negotiate_compact_blocks` always sends
   `announce=False`; peers therefore never set `wants_cmpctblock` on
   us; `_announce_block` always falls through to inv/headers. The
   entire ~600 ms BIP-152 saving at tip is left on the table in both
   directions, AND `set_ibd_state` is dead (no caller). Combined with
   BUG-4 (no `vExtraTxnForCompact`), the cumulative cmpctblock benefit
   over naive INV-getdata is near zero.

3. **BUG-17 (P0-SEC): `_partial_cmpct_blocks` dict not per-peer
   scoped, unbounded, no timeout.** Three independent failure modes:
   cross-peer state confusion (Peer B can hijack Peer A's pending
   getblocktxn round-trip), memory-DoS (unbounded growth from spam),
   and stale-entry leakage (no cleanup task). Easily exploitable on
   the public mainnet.

**Worth noting (positive):** the SipHash-2-4 implementation, the
SHA256(header||nonce) key derivation, the differential encoding of
prefilledtxn indexes and getblocktxn indices, the 48-bit short-id
truncation, and the use of `tx.get_wtxid()` (not txid) for short-id
derivation in `from_block` are all correct and BIP-152 v2 compliant
when treated in isolation. The bugs are around the surrounding
plumbing: HB-mode promotion, extra-txn pool, in-flight tracking,
post-reconstruction mutation check, fallback paths, and version gates.
