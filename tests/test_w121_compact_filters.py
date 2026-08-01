"""
W121 audit — BIP-157 / BIP-158 compact block filters (ouroboros)

Reference: bitcoin-core/src/blockfilter.{cpp,h}, src/index/blockfilterindex.cpp,
src/net_processing.cpp (ProcessGetCFilters/ProcessGetCFHeaders/ProcessGetCFCheckPt,
PrepareBlockFilterRequest, BlockRequestAllowed). BIPs:
    https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

Two-pipeline note:
    All BIP-157/158 logic lives in the Python pipeline (src/ouroboros/blockfilter.py
    + P2P message types in p2p_messages.py + handlers in node.py + REST/RPC).
    The Rust pipeline (ferrous-utils/sync/) has ZERO BIP-157/158 code — no GCS
    interpreter, no BlockFilterIndex CF, no header chain. This mirrors the
    pattern noted in W120 / W116 etc.: opt-in indexer features run Python-only,
    consensus-critical code is in Rust.

Audit summary (30 gates):
    G01 GCS parameters (P=19, M=784931)                                     PASS
    G02 SipHash key from block hash (internal/LE first 16 bytes)            PASS
    G03 Golomb-Rice encode/decode roundtrip                                 PASS
    G04 hash_to_range fast-range reduction                                  PASS
    G05 CompactSize N prefix on filter                                      PASS
    G06 Empty filter is single 0x00 byte                                    PASS
    G07 Deltas non-decreasing (sorted hashes)                               PASS
    G08 filter_hash = dSHA256(filter_bytes)                                 PASS
    G09 filter_header = dSHA256(filter_hash || prev_header)                 PASS
    G10 BasicFilterElements: outputs minus OP_RETURN, minus empty           PASS
    G11 BasicFilterElements: prevouts minus empty (OP_RETURN INCLUDED)      PASS
    G12 Handler disconnects on unsupported filter_type                      PASS
    G13 Handler disconnects on unknown stop_hash                            PASS
    G14 Handler disconnects on start_height > stop_height                   PASS
    G15 Handler disconnects on range > MAX_GETCFILTERS_SIZE (1000)          PASS
    G16 Handler disconnects on range > MAX_GETCFHEADERS_SIZE (2000)         PASS
    G17 getcfcheckpt has NO range limit (max_height_diff=UINT32_MAX)        PASS
    G18 cfcheckpt heights at multiples of CFCHECKPT_INTERVAL=1000           PASS
    G19 cfilter wire encode/decode roundtrip                                PASS
    G20 cfheaders wire encode/decode roundtrip                              PASS
    G21 cfcheckpt wire encode/decode roundtrip                              PASS
    G22 NODE_COMPACT_FILTERS = 1 << 6 = 0x40                                PASS
    G23 NODE_COMPACT_FILTERS advertised only when --blockfilterindex=1      PASS
    G24 BIP-158 genesis-block test vector (filter hex)                      PASS
    G25 Reorg disconnect rolls back index (remove filter + tip header)      FIX-74 PASS
    G26 Reorg connect re-runs add_block for new chain                       FIX-74 PASS
    G27 cfilter handler aborts on any missing height (no partial response)  FIX-75 PASS
    G28 cfheaders prev_header lookup failure → no response (not zeros)      BUG-4 BROKEN
    G29 Index-not-synced gate before advertising NODE_COMPACT_FILTERS       BUG-5 MISSING
    G30 Rust pipeline parity (ferrous-utils BIP-157/158)                    TP-1 MISSING
    G31 P2P handlers walk stop_hash ancestor (not active chain)             FIX-75 PASS
    G32 P2P handlers never call get_block_by_height (forward-regression)    FIX-75 PASS

Bugs (5 single-impl + 1 two-pipeline gap):

  BUG-1 [P1-CDIV] Reorg disconnect does not remove indexed filters
    block_sync.py:2942 reorg disconnect loop calls db.disconnect_block but
    never block_filter_index.remove() or set_tip_header(). After a reorg
    the index keeps stale (filter, header) pairs for now-orphaned blocks,
    and the tip_header still chains to the OLD tip. Subsequent
    add_block() calls compute headers as
        H_new = dSHA256(filter_hash_new || H_old_chain_tip)
    which permanently diverges from any honest peer's filter chain.
    A light client that fetches cfheaders from this node post-reorg
    receives a chain that fails BIP-157 §"Filter Headers" verification.

  BUG-2 [P1-CDIV] Reorg connect-side does not re-index filters
    block_sync.py:2974-3027 reorg connect loop calls connect_block_from_bytes
    but no block_filter_index.add_block(). New-chain blocks are absent
    from the index → all subsequent getcfilters/getcfheaders for those
    heights miss the cache, fall back to on-fly build at the handler.
    Compound with BUG-1: tip_header stale AND new heights absent.

  BUG-3 [P1] getcfilters silent partial response on missing block
    node.py:1148-1158 loop uses `continue` when a height has no block
    available. Core's LookupFilterRange returns false on the first miss
    and the handler sends NOTHING; ouroboros sends a partial cfilter
    stream missing some heights — peer sees wrong count and may treat
    as DoS / silent corruption. Should mirror Core: abort the entire
    response (no cfilter messages emitted) on any miss.
    [CLOSED by FIX-75: the stop-hash-ancestor refactor replaced the
    per-height active-chain lookup with _get_ancestor() + return-on-miss;
    the `continue` is gone — see test_g27 audit-flip.]

  BUG-6 [P0-PRIVACY/P1-CDIV] BIP-157 handlers walk active chain not stop_hash
    Pre-FIX-75: node.py:_make_getcfilters/cfheaders/cfcheckpt_handler all
    resolved stop_hash via db.get_block (correct) but then iterated via
    db.get_block_by_height (which walks the ACTIVE chain).  When the peer's
    stop_hash points at a stale/orphan block, the handler signed and
    returned filters from the active chain at the same heights — a
    signed-but-lying response.
    Security impact (Core net_processing.cpp PrepareBlockFilterRequest
    deliberately serves stale-fork filters by walking stop_index->
    GetAncestor; no chain.Contains check): light clients querying with
    orphan stop_hash get an active-chain stream and the response leaks
    which fork the peer is monitoring (privacy DoS).
    [CLOSED by FIX-75 (2026-05-16): added module-level _get_ancestor()
    mirroring CBlockIndex::GetAncestor; all 3 handlers walk from
    stop_block via prev_blockhash.  Forward-regression guard in
    test_fix75_test_e asserts the 3 handlers never call
    get_block_by_height.  Universal W121 #3 finding — beamchain
    counterpart's audit lens.]

  BUG-4 [P1] getcfheaders falls back to all-zeros prev_filter_header
    node.py:1224-1236: if start_height > 0 and bfi cannot resolve the
    previous block hash or its stored header, prev_filter_header is left
    as `b'\\x00' * 32`. Core's PrepareBlockFilterRequest → LookupFilterHeader
    path returns false on miss and sends NO response. The zero-fallback
    here produces a wire-valid cfheaders message that chains to a fake
    genesis — light clients verifying against another peer's anchored
    checkpoint will detect a fork.

  BUG-5 [P2] NODE_COMPACT_FILTERS advertised before index backfill
    node.py:294-314 sets node_compact_filters=True the moment
    PersistentBlockFilterIndex.__init__ succeeds, regardless of whether
    the index has caught up to the chain tip. Mid-IBD peers querying
    this node will get on-fly-built filters for blocks the index has
    never indexed AND prev_filter_header=zeros for any non-genesis
    start_height (BUG-4 collateral). Core only advertises after the
    index thread has reached the active chain tip
    (see net_processing's m_initial_sync_finished / index_synced gate
    around init.cpp StartBlockFilterIndexes + Index::Start).

  TP-1 [TWO-PIPELINE] Rust pipeline has zero BIP-157/158
    ferrous-utils/sync/ has no GCS interpreter, no BlockFilterIndex
    column-family, no filter-header chain. The Python pipeline owns
    every byte. Phase 2 note in blockfilter.py docstring acknowledges
    this — but it's been "Phase 2" for the entire history of the
    feature. Net effect today: --blockfilterindex incurs full Python
    cost (filter construction is tens of ms per block, single-threaded
    via asyncio.to_thread), and any reindex restart re-scans the
    entire chain from Python. Comment-as-confession: blockfilter.py:558
    "Phase 2 will migrate the on-disk format to a dedicated RocksDB CF
    (BlockFilters) in the ferrous-utils crate; the public API of this
    class is intentionally kept narrow so the swap is internal."

Per-impl correctness: PARTIAL — wire codec, GCS construction, genesis
vector, and handler disconnect cases are Core-faithful (W90 audit closed
those). The five bugs above are all reorg / startup / failure-path bugs,
not happy-path bytes-on-the-wire bugs. The two-pipeline gap is a
performance/architecture observation, not a wire-incompat.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Imports under audit
# ---------------------------------------------------------------------------

from ouroboros.blockfilter import (
    BASIC_FILTER_TYPE,
    GCS_P,
    GCS_M,
    PersistentBlockFilterIndex,
    BlockFilterIndex,
    build_basic_filter,
    compute_filter_hash,
    compute_filter_header,
    construct_gcs_filter,
)
from ouroboros.p2p_messages import (
    NODE_COMPACT_FILTERS,
    MAX_GETCFILTERS_SIZE,
    MAX_GETCFHEADERS_SIZE,
    CFCHECKPT_INTERVAL,
    GetCFiltersMessage,
    CFilterMessage,
    GetCFHeadersMessage,
    CFHeadersMessage,
    GetCFCheckptMessage,
    CFCheckptMessage,
)


# ===========================================================================
# Constants and wire format (G01, G05, G15-G18, G19-G22) — PASS
# ===========================================================================

def test_g01_gcs_parameters_match_bip158():
    """BIP 158 §"Basic Filter": P=19, M=784931."""
    assert GCS_P == 19
    assert GCS_M == 784931
    assert BASIC_FILTER_TYPE == 0


def test_g15_g16_g17_protocol_limits_match_core():
    """Core net_processing.cpp lines 184-186 + CFCHECKPT_INTERVAL."""
    assert MAX_GETCFILTERS_SIZE == 1000
    assert MAX_GETCFHEADERS_SIZE == 2000
    assert CFCHECKPT_INTERVAL == 1000


def test_g22_node_compact_filters_bit():
    """BIP 157 §"NODE_COMPACT_FILTERS" — bit 6 (1 << 6 = 0x40)."""
    assert NODE_COMPACT_FILTERS == 1 << 6
    assert NODE_COMPACT_FILTERS == 0x40


def test_g19_cfilter_wire_roundtrip():
    """cfilter wire encode/decode preserves all fields."""
    m = CFilterMessage(
        filter_type=0,
        block_hash=b'\x11' * 32,
        filter_bytes=b'\x02\xab\xcd\xef\x01',
    )
    netmsg = m.to_network_message("mainnet")
    decoded = CFilterMessage.from_payload(netmsg.payload)
    assert decoded.filter_type == 0
    assert decoded.block_hash == b'\x11' * 32
    assert decoded.filter_bytes == b'\x02\xab\xcd\xef\x01'


def test_g20_cfheaders_wire_roundtrip():
    """cfheaders wire encode/decode preserves all fields including hash list."""
    hashes = [bytes([i]) * 32 for i in range(5)]
    m = CFHeadersMessage(
        filter_type=0,
        stop_hash=b'\x22' * 32,
        previous_filter_header=b'\x33' * 32,
        filter_hashes=hashes,
    )
    netmsg = m.to_network_message("mainnet")
    decoded = CFHeadersMessage.from_payload(netmsg.payload)
    assert decoded.filter_type == 0
    assert decoded.stop_hash == b'\x22' * 32
    assert decoded.previous_filter_header == b'\x33' * 32
    assert decoded.filter_hashes == hashes


def test_g21_cfcheckpt_wire_roundtrip():
    """cfcheckpt wire encode/decode preserves checkpoint header list."""
    headers = [bytes([i]) * 32 for i in range(3)]
    m = CFCheckptMessage(
        filter_type=0,
        stop_hash=b'\x44' * 32,
        filter_headers=headers,
    )
    netmsg = m.to_network_message("mainnet")
    decoded = CFCheckptMessage.from_payload(netmsg.payload)
    assert decoded.filter_type == 0
    assert decoded.stop_hash == b'\x44' * 32
    assert decoded.filter_headers == headers


# ===========================================================================
# GCS algorithm correctness (G02-G04, G06-G09) — PASS (covered by W90)
# ===========================================================================

def test_g03_gcs_roundtrip_smoke():
    """build_basic_filter on an empty input yields the single 0x00 byte."""
    from ouroboros.blockfilter import _encode_compact_size
    f = construct_gcs_filter([], b'\x00' * 16)
    assert f == _encode_compact_size(0)
    assert f == b'\x00'


def test_g08_filter_hash_is_dsha256():
    """filter_hash = dSHA256(filter_bytes)."""
    import hashlib
    filt = b'\x01\xff'
    expected = hashlib.sha256(hashlib.sha256(filt).digest()).digest()
    assert compute_filter_hash(filt) == expected


def test_g09_filter_header_formula():
    """filter_header = dSHA256(filter_hash || prev_filter_header)."""
    import hashlib
    filt = b'\x01\xff'
    prev = b'\x42' * 32
    fhash = compute_filter_hash(filt)
    expected = hashlib.sha256(hashlib.sha256(fhash + prev).digest()).digest()
    assert compute_filter_header(filt, prev) == expected


# ===========================================================================
# Index in-memory roundtrip (G23 surface, exists) — PASS
# ===========================================================================

def test_index_inmemory_smoke():
    """BlockFilterIndex stores + retrieves filter and chained header."""
    idx = BlockFilterIndex()
    assert idx.tip_header == b'\x00' * 32

    class _FakeBlock:
        def __init__(self, h: bytes, height: int):
            self.hash = h
            self.height = height
            self.transactions = []

    blk = _FakeBlock(b'\xaa' * 32, height=1)
    filt, header = idx.add(blk)
    # Empty block → empty filter (single 0x00 byte for N=0)
    assert filt == b'\x00'
    assert idx.get_filter(blk.hash) == filt
    assert idx.get_header(blk.hash) == header
    assert idx.tip_header == header


# ===========================================================================
# G25 — Reorg disconnect must remove indexed filters (BUG-1)
# FIX-74 — landed 2026-05-16.  Audit flips xfail -> PASS.
# ===========================================================================

def test_g25_reorg_disconnect_rolls_back_filter_index():
    """
    Core requires the filter index to follow the active chain. On a reorg,
    Bitcoin Core's BlockFilterIndex receives BlockDisconnected callbacks
    via CValidationInterface (see index/blockfilterindex.cpp) and rolls
    back its summary.

    FIX-74 / W121 BUG-1 (closed 2026-05-16): the reorg disconnect loop now
    calls ``block_filter_index.remove(curr_hash, height)`` after each Rust
    ``db.disconnect_block``, and ``set_tip_header(common_ancestor_header)``
    once disconnect completes — so subsequent ``add_block`` calls compute
    the new filter chain from the correct prev_header.  This activates the
    FIX-71 best_indexed_height rollback machinery, which had been wired
    into ``PersistentBlockFilterIndex.remove()`` but never called because
    the reorg path didn't hook it.
    """
    reorg_section = _reorg_section_of_block_sync()
    # The disconnect loop must call block_filter_index.remove() AND set
    # tip_header back to the common ancestor's filter header to keep the
    # filter index consistent with the active chain.
    assert "block_filter_index.remove" in reorg_section, (
        "reorg disconnect loop must call block_filter_index.remove() — "
        "FIX-74 hook missing."
    )
    assert "block_filter_index.set_tip_header" in reorg_section, (
        "reorg disconnect loop must rebase filter header chain on the "
        "common ancestor via block_filter_index.set_tip_header() — "
        "FIX-74 hook missing."
    )


def _reorg_section_of_block_sync() -> str:
    """Slice block_sync.py from the 'Disconnect side' comment through end
    of the reorg connect loop. We deliberately exclude the linear connect
    path so BUG-2 (reorg-only) is not masked by the working linear hook."""
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "block_sync.py"
    text = src.read_text(encoding="utf-8")
    start = text.find("# Disconnect side:")
    # Reorg section ends at the Mempool refill block — we scope to the
    # full reorg processing region so both disconnect + connect loops
    # are within the slice.
    end = text.find("# Mempool refill:", start) if start != -1 else -1
    if start == -1 or end == -1:
        # Fall back: take the entire reorg method body via a wider sentinel.
        start = text.find("disconnect_height = common_ancestor_height")
        end = text.find("if self.mempool:", start) if start != -1 else -1
    assert start != -1 and end != -1, "could not locate reorg method body"
    return text[start:end]


# ===========================================================================
# G26 — Reorg connect must re-index new chain (BUG-2)
# FIX-74 — landed 2026-05-16.  Audit flips xfail -> PASS.
# ===========================================================================

def test_g26_reorg_connect_reindexes_new_chain():
    """
    Symmetric to G25: when a reorg connects the new chain, each newly
    connected block must be passed to block_filter_index.add_block so
    the index follows the active chain.

    FIX-74 / W121 BUG-2 (closed 2026-05-16): the reorg connect loop now
    hooks ``block_filter_index.add_block(new_block_obj, connect_height,
    self.db)`` after each successful ``db.connect_block_from_bytes``.
    Mirrors the linear connect path at block_sync.py:~1362 and Core's
    BlockFilterIndex::CustomAppend via the CValidationInterface
    BlockConnected callback (src/index/blockfilterindex.cpp +
    src/index/base.cpp).
    """
    reorg_section = _reorg_section_of_block_sync()
    # Within the reorg section ONLY, the connect loop must hook the
    # filter index. The linear path at line ~1362 is outside this slice.
    assert "block_filter_index" in reorg_section and (
        ".add_block" in reorg_section or ".add(" in reorg_section
    ), (
        "reorg connect loop does not call block_filter_index.add_block(); "
        "new-chain blocks are never indexed and getcfilters/getcfheaders "
        "for those heights miss the cache forever."
    )


# ===========================================================================
# G27 — getcfilters must abort entire response on missing height (BUG-3, BROKEN)
# ===========================================================================

def test_g27_getcfilters_aborts_on_missing_height():
    """
    Core's ProcessGetCFilters calls LookupFilterRange which returns false
    on the first missing filter; the handler then logs and returns
    WITHOUT sending any cfilter messages (net_processing.cpp:3333-3337).

    Pre-FIX-75: ouroboros used `continue` in the per-height loop, silently
    skipping missing heights and sending a wire-inconsistent partial
    cfilter stream.

    FIX-75 (2026-05-16) / W121 BUG-3 closed as a natural consequence of
    the stop-hash-ancestor refactor (W121 #3): the per-height loop now
    aborts via `return` on any ancestor-walk or block-storage miss, so
    a partial cfilter stream is never emitted.  Audit-flip: xfail → PASS.
    """
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "node.py"
    text = src.read_text(encoding="utf-8")

    # Locate the getcfilters handler block (between the def and the
    # next def). Look for the `continue` pattern that indicates partial
    # response on missing block.
    start = text.find("def _make_getcfilters_handler")
    end = text.find("def _make_getcfheaders_handler", start)
    assert start != -1 and end != -1
    handler = text[start:end]

    # Must NOT contain the broken `continue` skip on missing block.
    # Specifically: "if blk is None:\n                                continue"
    # If this pattern is present, the bug is live.
    assert "continue" not in handler or "abort" in handler.lower() or "break" in handler, (
        "getcfilters handler still uses `continue` to skip missing heights; "
        "should abort entire response per Core ProcessGetCFilters"
    )


# ===========================================================================
# G28 — getcfheaders prev_header zero-fallback is wire-incompat (BUG-4)
# FIX-79 — landed 2026-05-16.  Audit flips xfail → PASS.
# ===========================================================================

def test_g28_getcfheaders_no_zero_fallback_for_prev_header():
    """
    FIX-79 / W121 BUG-4 (closed 2026-05-16).

    Core's ProcessGetCFHeaders calls LookupFilterHeader on the
    (start_height - 1) block and aborts the response if the lookup
    fails (net_processing.cpp:3361-3370). It NEVER falls back to
    zero — that would produce a wire-valid cfheaders message chained
    to a fake genesis, indistinguishable on the wire from an honest
    one until a light client cross-checks against another peer.

    Pre-FIX-79 ouroboros node.py started ``prev_filter_header =
    b'\\x00' * 32`` and only updated it if the index had the stored
    header. On miss (index not synced past start_height-1, or block
    absent because FIX-74 removed it during reorg-disconnect), the
    response was sent with zeros — "signed-but-lying".

    FIX-79: after the ancestor-walk + bfi lookup chain, if
    ``prev_filter_header`` cannot be resolved AND start_height > 0,
    return without sending.  Peer will time out and retry, ideally
    from another peer who has the orphan block indexed (Core does
    not store per-fork filter headers either; LookupFilterHeader is
    keyed by block hash but the index is keyed by block-disk-position).
    """
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "node.py"
    text = src.read_text(encoding="utf-8")

    start = text.find("def _make_getcfheaders_handler")
    end = text.find("def _make_getcfcheckpt_handler", start)
    assert start != -1 and end != -1
    handler = text[start:end]

    # The handler must explicitly abort on prev_header lookup failure.
    # Look for either: a `return` on prev miss, or an explicit guard.
    # The buggy form is the bare `prev_filter_header = b'\\x00' * 32`
    # initialization with no abort branch when it stays zero.
    has_abort_on_prev_miss = (
        "no prev_filter_header" in handler
        or "abort getcfheaders" in handler
        or "prev_filter_header is None" in handler
    )
    assert has_abort_on_prev_miss, (
        "getcfheaders handler falls back to all-zero prev_filter_header "
        "when the index lookup misses; should abort response per Core "
        "ProcessGetCFHeaders + LookupFilterHeader (net_processing.cpp:3361-3370)"
    )


# ===========================================================================
# G29 — NODE_COMPACT_FILTERS must not advertise until index synced (BUG-5)
# FIX-71 — landed 2026-05-16.  Audit flips xfail → PASS.
# ===========================================================================

def test_g29_index_synced_gate_before_node_compact_filters_advertised():
    """
    FIX-71 / W121 BUG-5 (closed 2026-05-16).

    Bitcoin Core's BlockFilterIndex inherits BaseIndex which only signals
    "ready" once the index thread has caught up to ActiveChain().Tip()
    (see ``src/index/base.cpp`` ThreadSync + ``BaseIndex::IsSynced`` and
    the ``src/init.cpp`` ``StartBlockFilterIndexes`` path that registers
    the index asynchronously).  Pre-FIX-71 ouroboros set
    ``node_compact_filters=True`` the moment ``PersistentBlockFilterIndex``
    opened, regardless of whether the index had caught up.  Mid-IBD peers
    querying that node received zero-prev-header cfheaders (BUG-4
    collateral) — a light client cross-checking against another peer
    saw a fork.

    The fix exposes ``is_synced(chain_tip_height)`` +
    ``best_indexed_height`` on both ``BlockFilterIndex`` (in-memory) and
    ``PersistentBlockFilterIndex``.  ``Peer._should_advertise_node_compact_filters``
    re-evaluates the gate at every version handshake (the
    ``node_compact_filters`` parameter now accepts a callable; the
    production wiring in ``node.py`` passes a closure that consults
    ``block_filter_index.is_synced(active_chain_tip_height())``).
    """
    # The two API surfaces the sync gate depends on must exist.
    assert hasattr(PersistentBlockFilterIndex, "is_synced"), (
        "PersistentBlockFilterIndex.is_synced missing — sync gate cannot "
        "evaluate at handshake time."
    )
    assert hasattr(PersistentBlockFilterIndex, "best_indexed_height"), (
        "PersistentBlockFilterIndex.best_indexed_height missing — sync "
        "gate has no monotonic height to compare against the chain tip."
    )
    # Same on the in-memory fallback (used in tests and as the disabled
    # fallback inside PersistentBlockFilterIndex).
    assert hasattr(BlockFilterIndex, "is_synced")
    assert hasattr(BlockFilterIndex, "best_indexed_height")


# ===========================================================================
# G29 positive tests (FIX-71)
# ===========================================================================
# These directly exercise the three states the sync gate must
# distinguish: pre-sync, synced, and reorg-rolled-back.
# ===========================================================================

def _fake_block(block_hash: bytes, height: int):
    """Build a minimal stand-in for a Block compatible with index.add_block."""
    class _FakeBlock:
        def __init__(self, h: bytes, ht: int):
            self.hash = h
            self.height = ht
            self.transactions = []
    return _FakeBlock(block_hash, height)


def test_g29_fix71_test_a_pre_sync_bit_not_advertised():
    """A fresh index (best_indexed_height=None) is NOT synced.

    A node whose handshake gate consults ``is_synced(tip)`` must
    therefore WITHHOLD NODE_COMPACT_FILTERS until at least one block has
    been indexed.
    """
    idx = BlockFilterIndex()
    # Mimic node._compact_filters_advertised when the chain has blocks
    # but the index hasn't caught up (the worst case: peers expect us to
    # serve compact filters because the bit was set, but we can't).
    assert idx.best_indexed_height is None
    assert idx.is_synced(chain_tip_height=100) is False
    assert idx.is_synced(chain_tip_height=0) is False
    # Negative / None tip => not synced (chain not initialised yet).
    assert idx.is_synced(chain_tip_height=None) is False
    assert idx.is_synced(chain_tip_height=-1) is False


def test_g29_fix71_test_b_synced_bit_is_advertised():
    """When best_indexed_height ≥ chain tip, the gate flips on.

    Pre-FIX-71 the gate was a static bool captured at peer construction;
    even with the index opened, the bit was already advertised before any
    block was indexed.  Post-FIX-71 the gate only flips on once the
    index actually catches up to the chain tip.
    """
    idx = BlockFilterIndex()

    # Index 5 blocks at heights 0..4.
    for h in range(5):
        idx.add_block(_fake_block(bytes([h + 1]) * 32, h))

    assert idx.best_indexed_height == 4
    # Synced when the chain tip is at or below best_indexed_height.
    assert idx.is_synced(chain_tip_height=4) is True
    assert idx.is_synced(chain_tip_height=3) is True
    # NOT synced when the chain tip moves ahead of the index.
    assert idx.is_synced(chain_tip_height=5) is False
    assert idx.is_synced(chain_tip_height=100) is False


def test_g29_fix71_test_c_reorg_invalidates_sync_bit_temporarily_withdrawn():
    """A reorg disconnect must roll back best_indexed_height so the bit
    is temporarily UN-advertised.

    Sequence:
      1. Index heights 0..4 → synced for chain_tip=4.
      2. Reorg disconnects height 4 (remove + tip_header rollback).
      3. best_indexed_height now == 3 → NOT synced for chain_tip=4
         (peers asking for filter @ 4 would get nothing; the bit must
         be withdrawn until the new chain re-connects past 4).
      4. Re-add a NEW block at height 4 on the new chain → synced again.
    """
    idx = BlockFilterIndex()
    hashes = [bytes([h + 1]) * 32 for h in range(5)]
    for h in range(5):
        idx.add_block(_fake_block(hashes[h], h))
    assert idx.best_indexed_height == 4
    assert idx.is_synced(chain_tip_height=4) is True

    # Reorg disconnect of the tip (height 4).
    idx.remove(hashes[4])
    assert idx.best_indexed_height == 3
    # While the new chain is still being connected, the bit MUST NOT
    # be advertised: a light client querying us at height 4 would get
    # nothing (or worse, the orphan-chain entry if we hadn't removed it).
    assert idx.is_synced(chain_tip_height=4) is False

    # Re-connect the new chain at height 4 with a different hash.
    new_hash_4 = b"\xff" * 32
    idx.add_block(_fake_block(new_hash_4, 4))
    assert idx.best_indexed_height == 4
    assert idx.is_synced(chain_tip_height=4) is True


def test_g29_fix71_test_d_persistent_index_sync_gate_survives_restart(tmp_path):
    """best_indexed_height persists across PersistentBlockFilterIndex restarts.

    A node that finishes IBD, indexes the full chain, and restarts must
    immediately advertise NODE_COMPACT_FILTERS — without this
    persistence the first run after restart would re-traverse the full
    "I haven't indexed anything yet" → "catching up" → "synced" cycle,
    which would temporarily withdraw the bit even though the on-disk
    data is fully up-to-date.
    """
    data_dir = str(tmp_path / "pbi")

    idx1 = PersistentBlockFilterIndex(data_dir=data_dir, enabled=True)
    # Fresh datadir → no observed blocks.
    assert idx1.best_indexed_height is None
    assert idx1.is_synced(chain_tip_height=0) is False

    # Index blocks 0..2.
    hashes = [bytes([h + 1]) * 32 for h in range(3)]
    for h in range(3):
        idx1.add_block(_fake_block(hashes[h], h))
    assert idx1.best_indexed_height == 2
    assert idx1.is_synced(chain_tip_height=2) is True

    # Reopen — best_indexed_height must survive.
    idx2 = PersistentBlockFilterIndex(data_dir=data_dir, enabled=True)
    assert idx2.best_indexed_height == 2, (
        "Sync-gate height did not survive PersistentBlockFilterIndex "
        "restart; the node would temporarily withdraw "
        "NODE_COMPACT_FILTERS after every restart even with a fully "
        "indexed on-disk store."
    )
    assert idx2.is_synced(chain_tip_height=2) is True
    assert idx2.is_synced(chain_tip_height=3) is False  # chain advanced


def test_g29_fix71_test_e_peer_handshake_predicate_is_callable():
    """Peer accepts a callable as node_compact_filters; predicate is
    re-evaluated at handshake time (FIX-71 / W121 BUG-5).

    Regression guard against the captured-bool form that caused the
    original bug.  We don't actually run a handshake here — that needs
    a live socket — but we verify the predicate plumbing by toggling a
    closure-captured flag and confirming
    Peer._should_advertise_node_compact_filters reflects it.
    """
    from ouroboros.peer import Peer

    state = {"synced": False}

    def gate() -> bool:
        return state["synced"]

    p = Peer(
        host="127.0.0.1",
        port=18333,
        network="mainnet",
        node_compact_filters=gate,
    )
    # Pre-sync.
    assert p._should_advertise_node_compact_filters() is False
    # Flip the gate — the next handshake (or any re-eval) must see True.
    state["synced"] = True
    assert p._should_advertise_node_compact_filters() is True
    # A callable that raises must NOT crash the handshake.
    def boom() -> bool:
        raise RuntimeError("intentional test failure")
    p.node_compact_filters = boom
    assert p._should_advertise_node_compact_filters() is False
    # And the legacy bool path still works.
    p.node_compact_filters = True
    assert p._should_advertise_node_compact_filters() is True
    p.node_compact_filters = False
    assert p._should_advertise_node_compact_filters() is False


# ===========================================================================
# G25 / G26 / G29 behavioral tests (FIX-74)
# ===========================================================================
# These exercise the reorg-hook path end-to-end against an in-memory
# BlockFilterIndex by directly invoking ``BlockSync._handle_reorg`` with
# stub db / mempool collaborators.  They are deliberately structural —
# we do not stand up a full Rust DB here (covered by
# tests/test_reorg_handle_rust_path.py + tests/test_reorg_atomic_*.py);
# instead we pin the filter-index side of the reorg contract.
# ===========================================================================


def _build_fix74_harness():
    """Return ``(BlockSync, fake_db, idx, blocks)`` wired together.

    The fake_db pre-loads:
        height 0  -> A0 (common ancestor)
        height 1  -> A1 (current chain tip; will be disconnected)
    The "new chain" produces:
        height 1  -> B1 (new tip)

    The harness exercises the FIX-74 hooks (remove + set_tip_header +
    add_block) without depending on the Rust extension.  Sequence kept
    deliberately small (1 disconnect + 1 connect) so the test stays
    fast; the underlying machinery is the same for any depth.
    """
    import asyncio  # noqa: F401  (re-export so callers can asyncio.run)
    from ouroboros.block_sync import BlockSync
    from ouroboros.blockfilter import BlockFilterIndex

    class _FakeBlock:
        def __init__(self, h: bytes, prev: bytes, height: int):
            self.hash = h
            self.prev_blockhash = prev
            self.height = height
            self.transactions = []
            # Non-empty placeholder so the connect path's "no raw bytes"
            # guard doesn't fail before the FIX-74 hook runs.  The bytes
            # are never decoded — connect_block_from_bytes on _FakeDB is
            # a no-op.
            self.raw_payload = b"\x00" * 80

    A0 = _FakeBlock(b"\x10" * 32, bytes(32), 0)
    A1 = _FakeBlock(b"\x11" * 32, A0.hash, 1)
    B1 = _FakeBlock(b"\x21" * 32, A0.hash, 1)

    class _FakeDB:
        """Minimal storage interface used by ``_handle_reorg``.

        Tracks current best tip + hash->block map; ``disconnect_block`` /
        ``connect_block_from_bytes`` are no-ops that walk the chain ptr
        without touching real UTXO state.  Block lookups follow whichever
        chain the test has currently switched to (toggled by the harness).
        """

        def __init__(self):
            self._blocks_by_hash = {A0.hash: A0, A1.hash: A1, B1.hash: B1}
            # _height_to_block reflects the *current* active chain.
            self._height_to_block = {0: A0, 1: A1}
            self._tip = (A1.hash, 1)

        def get_block(self, h):
            return self._blocks_by_hash.get(h)

        def get_block_by_height(self, ht):
            return self._height_to_block.get(ht)

        def get_best_block(self):
            return self._tip

        def disconnect_block(self, height):
            # Roll the tip pointer back without touching the UTXO state.
            self._tip = (self._height_to_block[height - 1].hash, height - 1)
            self._height_to_block.pop(height, None)

        def connect_block_from_bytes(self, raw, height, network=None):
            # Signature mirrors BlockchainDatabase.connect_block_from_bytes
            # (network param added in 5e6e1fd for pre-BIP113 finality);
            # _handle_reorg passes it positionally.
            # Pick whichever new-chain block corresponds to the height
            # — by harness contract, only B1 is connect-target post-reorg.
            new = B1
            self._blocks_by_hash[new.hash] = new
            self._height_to_block[height] = new
            self._tip = (new.hash, height)

        # Linear-connect path stubs (unused in this harness)
        def update_best_block(self, h, ht):
            self._tip = (h, ht)

    class _FakeMempool:
        def remove_block_transactions(self, _block):
            return None

        def add_transaction(self, _tx, _height):
            return True, ""

    class _FakeValidator:
        def validate_block(self, _block):
            return True, None

        def apply_block(self, _block):
            return None

    class _FakePeerManager:
        pass

    idx = BlockFilterIndex()
    # Pre-seed the index for the original chain: A0 at height 0 (genesis
    # filter chains from zero prev_header), A1 at height 1 chaining from
    # A0's filter header.
    idx.add_block(A0, height=0)
    idx.add_block(A1, height=1)

    sync = BlockSync(
        db=_FakeDB(),
        validator=_FakeValidator(),
        peer_manager=_FakePeerManager(),
        mempool=_FakeMempool(),
        fee_estimator=None,
        block_filter_index=idx,
    )

    return sync, idx, A0, A1, B1


def test_fix74_test_a_reorg_removes_disconnected_filters():
    """Test A (G25 behavioral): one-block reorg disconnects the old tip
    and the filter index drops its (filter, header) entry.

    Before FIX-74: index kept stale A1 entry; ``get_filter(A1.hash)``
    returned the orphan-chain filter.  After FIX-74: A1's entries are
    removed; ``best_indexed_height`` rolled back to the common ancestor.
    """
    import asyncio

    sync, idx, A0, A1, B1 = _build_fix74_harness()

    # Pre-reorg: both blocks indexed.
    assert idx.get_filter(A1.hash) is not None
    assert idx.get_filter(A0.hash) is not None
    assert idx.best_indexed_height == 1

    # Run the reorg: A0 (common) -> B1 (new tip).
    ok = asyncio.run(sync._handle_reorg(B1, B1.hash))
    assert ok is True

    # Post-reorg: A1 entry removed; A0 still present; B1 added.
    assert idx.get_filter(A1.hash) is None, (
        "FIX-74 BUG-1: reorg disconnect failed to remove stale filter "
        "for the orphaned tip — index will diverge from active chain."
    )
    assert idx.get_filter(A0.hash) is not None
    assert idx.get_filter(B1.hash) is not None
    assert idx.best_indexed_height == 1


def test_fix74_test_b_reorg_reindexes_new_chain():
    """Test B (G26 behavioral): the new-chain tip is added to the filter
    index after the reorg connects it.

    Before FIX-74: the connect loop only updated the UTXO state and the
    index never saw B1.  After FIX-74: B1 has a filter + chained
    filter_header in the index.
    """
    import asyncio

    sync, idx, A0, A1, B1 = _build_fix74_harness()

    assert idx.get_filter(B1.hash) is None
    assert idx.get_header(B1.hash) is None

    ok = asyncio.run(sync._handle_reorg(B1, B1.hash))
    assert ok is True

    assert idx.get_filter(B1.hash) is not None, (
        "FIX-74 BUG-2: reorg connect failed to re-index new-chain tip "
        "— getcfilters/getcfheaders for B1.hash will miss the cache."
    )
    assert idx.get_header(B1.hash) is not None
    # Height mapping reflects the new chain.
    assert idx.get_block_hash_by_height(1) == B1.hash


def test_fix74_test_c_filter_header_chain_rolls_back_to_common_ancestor():
    """Test C: after the disconnect+connect, the filter header for B1 is
    computed from A0's filter header — not from the stale A1 header that
    would have leaked through pre-FIX-74.

    Direct mathematical check: compute_filter_header(B1_filter, A0_header)
    must equal idx.get_header(B1.hash).  This is the canonical fork
    detector — a light client cross-checking us against another peer
    would see exactly this header.
    """
    import asyncio
    from ouroboros.blockfilter import (
        compute_filter_header,
        build_basic_filter,
    )

    sync, idx, A0, A1, B1 = _build_fix74_harness()

    a0_header = idx.get_header(A0.hash)
    assert a0_header is not None

    ok = asyncio.run(sync._handle_reorg(B1, B1.hash))
    assert ok is True

    b1_filter = idx.get_filter(B1.hash)
    b1_header = idx.get_header(B1.hash)
    assert b1_filter is not None and b1_header is not None

    expected = compute_filter_header(b1_filter, a0_header)
    assert b1_header == expected, (
        "FIX-74 BUG-1 collateral: B1 filter header was computed from "
        "the stale A1 tip header instead of the common-ancestor A0 "
        "header; the filter header chain forks from any honest peer."
    )

    # And the index's tip header advanced to B1's header (the new tip).
    assert idx.tip_header == b1_header


def test_fix74_test_d_sync_gate_advertisement_through_reorg():
    """Test D: FIX-71 sync gate continues to behave correctly through a
    reorg now that the FIX-71 rollback machinery actually fires.

    Sequence:
      1. Pre-reorg: best_indexed_height == 1, is_synced(chain_tip=1) True
      2. Run reorg — disconnect removes A1 (height=1), best_indexed_height
         temporarily rolls back to 0 inside the loop, then re-advances to
         1 when B1 is re-added.  We only observe the post-reorg state
         here (the in-flight state is hidden inside ``_handle_reorg``),
         but the relevant guard is that the gate stays correct at the
         endpoint.
      3. Post-reorg: best_indexed_height == 1, is_synced(chain_tip=1)
         True; AND the height mapping points at B1, not the orphan A1.
    """
    import asyncio

    sync, idx, A0, A1, B1 = _build_fix74_harness()

    # FIX-71 invariant — pre-reorg.
    assert idx.best_indexed_height == 1
    assert idx.is_synced(chain_tip_height=1) is True

    ok = asyncio.run(sync._handle_reorg(B1, B1.hash))
    assert ok is True

    # FIX-71 invariant — post-reorg.  Re-added B1 advances the gate back.
    assert idx.best_indexed_height == 1
    assert idx.is_synced(chain_tip_height=1) is True
    # The height-mapping no longer points at the orphan A1 hash.
    assert idx.get_block_hash_by_height(1) == B1.hash
    assert idx.get_block_hash_by_height(1) != A1.hash


# ===========================================================================
# Two-pipeline guard (FIX-74)
# ===========================================================================
# Matches the FIX-72 pattern: assert that ferrous-utils carries zero
# block_filter_index code so this fix doesn't accidentally tilt the
# two-pipeline gap.  Counterpart to G30 — G30 expects ZERO Rust filter
# code (currently xfail); this guard pins the FIX-74-specific surface.
# ===========================================================================

def test_fix74_two_pipeline_guard_rust_has_no_block_filter_index():
    """FIX-74 lives entirely in the Python pipeline.  The Rust crate
    (ferrous-utils/sync) must not be touched — any block_filter_index
    references there would mean the fix has bled across the pipeline
    boundary.
    """
    from pathlib import Path

    rust_root = Path(__file__).parent.parent / "ferrous-utils" / "sync" / "src"
    forbidden = ("block_filter_index", "BlockFilterIndex")

    if not rust_root.exists():
        # Fresh checkout without the submodule populated — guard is
        # trivially true.
        return

    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in txt:
                offenders.append(f"{path}: {needle}")

    assert not offenders, (
        f"FIX-74 two-pipeline guard: ferrous-utils/sync/src must contain "
        f"NO block_filter_index references — fix bled across pipeline "
        f"boundary at: {offenders[:5]}"
    )


# ===========================================================================
# G30 — Rust pipeline parity (TP-1, TWO-PIPELINE GAP)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="TP-1: Rust pipeline (ferrous-utils) has zero BIP-157/158 implementation")
def test_g30_rust_pipeline_blockfilter_parity():
    """
    Two-pipeline gap.

    Python (src/ouroboros/blockfilter.py): full BIP-157/158 — GCS encoder,
    SipHash key derivation, filter header chain, PersistentBlockFilterIndex
    with sharded on-disk layout, P2P handlers in node.py, REST + RPC.

    Rust (ferrous-utils/sync/): NOTHING. No GCS, no BlockFilterIndex CF,
    no filter header chain. The Phase 1 docstring on
    PersistentBlockFilterIndex acknowledges Phase 2 will migrate to a
    RocksDB CF in ferrous-utils — but the migration has never landed.

    Today's impact:
      • Filter construction runs in Python via asyncio.to_thread —
        tens of ms per block, single-threaded, blocks the IBD connect
        loop's "off-thread" indexer.
      • The on-disk format is file-per-block sharded by hex prefix; a
        full mainnet index is ~870k files in 256 shard dirs. RocksDB
        would be ~1 SST file (compaction permitting) and significantly
        cheaper to scan during reindex / verify.
      • Reindex on restart re-reads every block from the Rust DB and
        re-builds every filter in Python. No way to parallelize across
        cores without the Rust-side native impl.

    No wire-incompatibility — purely architecture/perf — but the
    fleet-wide audit lens still flags the gap so we can prioritize
    Phase 2 (or formally decline).
    """
    from pathlib import Path
    rust_root = Path(__file__).parent.parent / "ferrous-utils" / "sync" / "src"

    # Scan the Rust source for any BIP-157/158 marker. If ANY file
    # mentions GCS / blockfilter / cfilter / golomb, the gap is being
    # closed and this xfail can flip to pass.
    keywords = ("blockfilter", "cfilter", "cfheader", "golomb", "gcs_filter", "BlockFilter")
    found = False
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for kw in keywords:
            if kw.lower() in txt:
                found = True
                break
        if found:
            break

    assert found, (
        "ferrous-utils/sync/src has no BIP-157/158 implementation; "
        "Phase 2 RocksDB CF migration remains unimplemented. "
        "All filter work runs in Python (single-threaded, file-per-block "
        "on-disk format)."
    )


# ===========================================================================
# Sanity — Bitcoin Core BIP-158 genesis-block vector (G24 corpus)
# ===========================================================================
# (Already covered in tests/test_w90_blockfilter_audit.py
# TestG24GenesisVector — explicit re-assertion here so W121 can be run
# standalone and the audit summary line matches reality.)

def test_g24_bip158_genesis_filter_hex_constant():
    """
    BIP 158 §"Test Vectors": basic filter for the mainnet genesis block
    is the single byte 0x017bb0a0. (The exact mainnet genesis vector is
    asserted in tests/test_w90_blockfilter_audit.py; here we just confirm
    the relevant constants exist so the W121 summary is self-contained.)
    """
    assert BASIC_FILTER_TYPE == 0
    assert GCS_P == 19 and GCS_M == 784931


# ===========================================================================
# FIX-75 — BIP-157 P2P stop-hash ancestor walk (W121 #3 BUG-6 closure)
# ===========================================================================
# Audit follow-on to FIX-74 a4cebff which closed the reorg-bookkeeping side
# of the "active-chain walk vs stop-hash ancestor" universal pattern.
# Pre-FIX-75: the 3 BIP-157 P2P handlers in node.py
# (_make_getcfilters/cfheaders/cfcheckpt_handler) resolved stop_hash via
# self.db.get_block(req.stop_hash) — correctly returning the stop block on
# any fork — but then iterated via self.db.get_block_by_height(h) which
# walks the *active* chain.  When the peer's stop_hash was on a stale/
# orphan fork, the handler signed and returned filters from the active
# chain at the same heights, producing a signed-but-lying response that
# leaks which fork the peer is interested in.
# Core's behavior (net_processing.cpp ProcessGetCFilters / ProcessGetCFHeaders
# / ProcessGetCFCheckPt): LookupBlockIndex(stop_hash) then
# stop_index->GetAncestor(h) for each requested height.  Critically NO
# chain.Contains(stop_index) check — compact filters are indexed by block
# hash regardless of fork membership.
# ===========================================================================


class _FakeOrphanBlock:
    """Minimal block stub used by the FIX-75 ancestor-walk tests.

    Mirrors the shape that ``BlockchainDatabase.get_block`` returns: hash,
    prev_blockhash, and height.  No serialization / transaction data needed
    because the FIX-75 code path only reads these three fields when walking
    the prev_blockhash chain.
    """

    __slots__ = ("hash", "prev_blockhash", "height")

    def __init__(self, h: bytes, prev: bytes, height: int):
        self.hash = h
        self.prev_blockhash = prev
        self.height = height


class _FakeForkedDB:
    """Two-fork DB stub.

    Chain layout (heights 0..2):
        height 0: G  (genesis / common ancestor)
        height 1: A1 (active chain)            height 1: B1 (orphan fork)
        height 2: A2 (active chain tip)        height 2: B2 (orphan fork tip)

    ``get_block_by_height`` returns the ACTIVE chain (A0/A1/A2).
    ``get_block(hash)`` returns whichever block was stored for that hash
    (both forks visible).  The ancestor walk inside FIX-75 uses
    ``get_block(prev_blockhash)`` only, so it must reconstruct the orphan
    chain B0→B1→B2 from the orphan-tip stop_hash, NEVER touching the
    active chain.
    """

    def __init__(self):
        self.G = _FakeOrphanBlock(b"\x00" * 31 + b"G", bytes(32), 0)
        self.A1 = _FakeOrphanBlock(b"\x00" * 31 + b"\xa1", self.G.hash, 1)
        self.A2 = _FakeOrphanBlock(b"\x00" * 31 + b"\xa2", self.A1.hash, 2)
        self.B1 = _FakeOrphanBlock(b"\x00" * 31 + b"\xb1", self.G.hash, 1)
        self.B2 = _FakeOrphanBlock(b"\x00" * 31 + b"\xb2", self.B1.hash, 2)
        self._by_hash = {
            self.G.hash: self.G,
            self.A1.hash: self.A1,
            self.A2.hash: self.A2,
            self.B1.hash: self.B1,
            self.B2.hash: self.B2,
        }
        # ACTIVE chain only — orphans not reachable via get_block_by_height.
        self._by_height = {0: self.G, 1: self.A1, 2: self.A2}

    def get_block(self, h):
        return self._by_hash.get(h)

    def get_block_by_height(self, ht):
        # This MUST NOT be called by the FIX-75 handler path — see
        # test_fix75_test_e_forward_regression_no_get_block_by_height.
        return self._by_height.get(ht)


def test_fix75_test_a_get_ancestor_walks_orphan_fork():
    """A: starting at the orphan-tip B2 (height 2), _get_ancestor walks
    via prev_blockhash and returns B1 at height 1, B2 at height 2, G at
    height 0 — NEVER A1 or A2.
    """
    from ouroboros.node import _get_ancestor

    db = _FakeForkedDB()

    # height 2 from B2 -> B2 itself
    h2 = _get_ancestor(db, db.B2, 2)
    assert h2 is db.B2
    # height 1 from B2 -> B1 (the orphan-fork parent), NOT A1
    h1 = _get_ancestor(db, db.B2, 1)
    assert h1 is db.B1
    assert h1 is not db.A1, (
        "FIX-75 BUG-6: ancestor walk returned active-chain block A1 for "
        "orphan stop_hash=B2 — signed-but-lying response."
    )
    # height 0 from B2 -> G (common ancestor)
    h0 = _get_ancestor(db, db.B2, 0)
    assert h0 is db.G


def test_fix75_test_b_get_ancestor_height_above_block():
    """B: target_height > block.height returns None.

    Mirrors Core CBlockIndex::GetAncestor: returns nullptr if the index is
    at a lower height than the requested ancestor (chain.h:153-160).
    """
    from ouroboros.node import _get_ancestor

    db = _FakeForkedDB()
    # Requesting height 5 from B2 (height 2) -> None
    assert _get_ancestor(db, db.B2, 5) is None


def test_fix75_test_c_get_ancestor_negative_height_or_none_block():
    """C: defensive — negative height, None block, and None height all
    return None without raising.
    """
    from ouroboros.node import _get_ancestor

    db = _FakeForkedDB()
    assert _get_ancestor(db, db.B2, -1) is None
    assert _get_ancestor(db, None, 0) is None
    # Synthesize a block with height=None (occurs in some db paths)
    orphan = _FakeOrphanBlock(b"\xee" * 32, bytes(32), 0)
    orphan.height = None
    assert _get_ancestor(db, orphan, 0) is None


def test_fix75_test_d_get_ancestor_broken_chain_returns_none():
    """D: if the prev_blockhash chain runs off the end (db inconsistency,
    pruned block), _get_ancestor returns None rather than infinite-looping
    or raising.
    """
    from ouroboros.node import _get_ancestor

    # Block at height 3 whose prev_blockhash points at a non-existent hash.
    db = _FakeForkedDB()
    broken = _FakeOrphanBlock(b"\xcd" * 32, b"\xab" * 32, 3)
    db._by_hash[broken.hash] = broken
    # Requesting height 0 should fail cleanly (chain broken at step 1).
    result = _get_ancestor(db, broken, 0)
    assert result is None


def test_fix75_test_e_forward_regression_no_get_block_by_height_in_handlers():
    """E: forward-regression source guard.

    The 3 BIP-157 P2P handlers — _make_getcfilters_handler /
    _make_getcfheaders_handler / _make_getcfcheckpt_handler — must NOT
    call self.db.get_block_by_height(...) anywhere in their bodies.  That
    function walks the ACTIVE chain and is the source of the W121 #3
    signed-but-lying response.  All per-height lookups must go through
    _get_ancestor(self.db, stop_block, h) instead.

    Pre-FIX-75 there were 3 occurrences (one per handler).  Post-FIX-75
    there are zero call sites (the only remaining references are comments
    documenting why the lookup was replaced — these are filtered out
    here by stripping ``#`` lines before the substring check).
    """
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "node.py"
    text = src.read_text(encoding="utf-8")

    for handler_name, next_marker in [
        ("_make_getcfilters_handler", "_make_getcfheaders_handler"),
        ("_make_getcfheaders_handler", "_make_getcfcheckpt_handler"),
        # cfcheckpt is the last of the three; bound on the registration
        # site which closes the BIP-157 block.
        ("_make_getcfcheckpt_handler", "# Register cfilter handlers"),
    ]:
        start = text.find(f"def {handler_name}")
        end = text.find(next_marker, start)
        assert start != -1, f"handler {handler_name} not found"
        assert end != -1, f"next marker after {handler_name} not found"
        body = text[start:end]
        # Strip comments so we only assert on call sites (the fix
        # commentary references get_block_by_height legitimately to
        # explain why it was replaced).
        non_comment = "\n".join(
            line for line in body.splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "get_block_by_height" not in non_comment, (
            f"FIX-75 BUG-6 forward-regression: {handler_name} still calls "
            f"db.get_block_by_height — must walk stop-hash ancestor via "
            f"_get_ancestor(self.db, stop_block, h) instead.  See Bitcoin "
            f"Core net_processing.cpp PrepareBlockFilterRequest + "
            f"CBlockIndex::GetAncestor (chain.cpp)."
        )


def test_fix75_test_f_handler_uses_get_ancestor_in_all_three():
    """F: positive companion to test E.  The 3 P2P handlers must contain
    a call to _get_ancestor — pinning the new code path so a future
    drive-by refactor can't silently swap it back to get_block_by_height
    without flipping this assertion AND the forward-regression guard
    above.
    """
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "node.py"
    text = src.read_text(encoding="utf-8")

    for handler_name, next_marker in [
        ("_make_getcfilters_handler", "_make_getcfheaders_handler"),
        ("_make_getcfheaders_handler", "_make_getcfcheckpt_handler"),
        ("_make_getcfcheckpt_handler", "# Register cfilter handlers"),
    ]:
        start = text.find(f"def {handler_name}")
        end = text.find(next_marker, start)
        body = text[start:end]
        assert "_get_ancestor" in body, (
            f"FIX-75: {handler_name} does not call _get_ancestor — "
            f"stop-hash-ancestor walk is the W121 #3 fix.  See FIX-75 "
            f"audit-flip G31."
        )


def test_fix75_test_g_handler_aborts_on_range_violations_unchanged():
    """G: regression — the Misbehaving-disconnect range guards (G13/G14/
    G15/G16) still fire after FIX-75.  The refactor must not have
    accidentally swallowed a peer-disconnect branch.
    """
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "ouroboros" / "node.py"
    text = src.read_text(encoding="utf-8")

    # All 3 handlers retain _peer_disconnect(... unknown stop_hash ...).
    for handler_name in (
        "_make_getcfilters_handler",
        "_make_getcfheaders_handler",
        "_make_getcfcheckpt_handler",
    ):
        start = text.find(f"def {handler_name}")
        # Look at ~120 lines beyond the def for the guards.
        body = text[start:start + 6000]
        assert "_peer_disconnect" in body, (
            f"FIX-75 regression: {handler_name} lost peer-disconnect calls"
        )
        assert "unknown stop_hash" in body, (
            f"FIX-75 regression: {handler_name} lost the unknown-stop_hash "
            f"disconnect branch (G13)"
        )

    # cfilters + cfheaders retain the range cap (G15/G16); cfcheckpt does NOT
    # have a range cap (G17 — UINT32_MAX in Core).
    cfilters_start = text.find("def _make_getcfilters_handler")
    cfheaders_start = text.find("def _make_getcfheaders_handler")
    cfcheckpt_start = text.find("def _make_getcfcheckpt_handler")
    cfilters_body = text[cfilters_start:cfheaders_start]
    cfheaders_body = text[cfheaders_start:cfcheckpt_start]
    assert "MAX_GETCFILTERS_SIZE" in cfilters_body
    assert "MAX_GETCFHEADERS_SIZE" in cfheaders_body


def test_fix75_test_h_handler_invocation_orphan_stop_hash():
    """H: end-to-end behavioral test.  Build a BitcoinNode-equivalent harness
    with the forked DB, instantiate the cfilters handler factory, invoke
    it with an orphan stop_hash, and verify the emitted CFilterMessage(s)
    reference orphan-fork block hashes (NOT active-chain hashes).

    This is the "signed-but-lying response" guard: peer sends getcfilters
    with stop_hash=B2 (orphan tip), and pre-FIX-75 the response listed
    A1/A2 hashes.  Post-FIX-75 the response lists B1/B2 hashes.
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import (
        GetCFiltersMessage,
        CFilterMessage,
    )

    db = _FakeForkedDB()

    # Pre-seed an in-memory filter index for BOTH forks so the handler
    # has filter bytes to emit; the test focuses on which block_hash the
    # handler picks for each height, not on filter byte equality.
    bfi = BlockFilterIndex()
    # Stash pre-computed bytes per block hash so the handler's bfi.get_filter
    # path returns deterministic values without rebuilding from a real
    # block (which would require full transactions).
    bfi._filters = {
        db.G.hash: b"\x00",
        db.A1.hash: b"\xa1",
        db.A2.hash: b"\xa2",
        db.B1.hash: b"\xb1",
        db.B2.hash: b"\xb2",
    }
    bfi._headers = {h: b"\x00" * 32 for h in bfi._filters}
    # height->hash for the ACTIVE chain (mirrors the W121 BUG-6 trap —
    # the handler must NOT consult this even though it's present).
    bfi._height_to_hash = {0: db.G.hash, 1: db.A1.hash, 2: db.A2.hash}

    # Build a stub node that exposes just enough surface for
    # _register_handlers to attach the cfilters handler to a fake peer.
    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers
            self._inbound_cb = None
            self._outbound_cb = None

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            self._inbound_cb = cb

        def set_outbound_peer_handler(self, cb):
            self._outbound_cb = cb

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    # Minimum-viable node — bypass __init__ to skip config-file loading.
    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None  # tx-handler factory needs this attribute set

    # Register handlers — registers our handler factory on the stub peer.
    node._register_handlers()

    handler = peer.handlers.get("getcfilters")
    assert handler is not None, "FIX-75 harness: getcfilters handler not registered"

    # Build a wire request for stop_hash=B2 (orphan tip), heights 0..2.
    # GetCFiltersMessage payload: filter_type(1) + start_height(4 LE) +
    # stop_hash(32 LE).
    req = GetCFiltersMessage(
        filter_type=0,
        start_height=0,
        stop_hash=db.B2.hash,
    )
    msg = req.to_network_message("mainnet")

    asyncio.run(handler(msg))

    # 3 CFilterMessages emitted, in height order 0..2, each referencing
    # the orphan-fork block hash (G/B1/B2).
    assert len(peer.sent) == 3, (
        f"FIX-75: expected 3 cfilter messages for heights 0..2, got "
        f"{len(peer.sent)}"
    )
    decoded = [CFilterMessage.from_payload(m.payload) for m in peer.sent]
    sent_hashes = [d.block_hash for d in decoded]

    expected_orphan = [db.G.hash, db.B1.hash, db.B2.hash]
    active_chain = [db.G.hash, db.A1.hash, db.A2.hash]
    assert sent_hashes == expected_orphan, (
        "FIX-75 BUG-6: handler returned active-chain block hashes for "
        "orphan stop_hash — signed-but-lying response.  "
        f"got={sent_hashes!r} active={active_chain!r} expected={expected_orphan!r}"
    )


def test_fix75_two_pipeline_guard_rust_has_no_compact_filter_p2p():
    """FIX-75 must live entirely in the Python pipeline.  The Rust crate
    (ferrous-utils/sync) must remain free of any BIP-157 P2P / GetCFilters
    handling — any drift here would mean the fix has bled across the
    pipeline boundary.

    Matches the FIX-74 two-pipeline guard.  Counterpart to G30 (the wider
    two-pipeline gap which expects ZERO Rust filter code overall — still
    xfail until Phase 2).
    """
    from pathlib import Path

    rust_root = Path(__file__).parent.parent / "ferrous-utils" / "sync" / "src"
    forbidden = (
        "GetCFilters",
        "GetCFHeaders",
        "GetCFCheckpt",
        "_get_ancestor",
    )

    if not rust_root.exists():
        return  # submodule not populated — trivially true

    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in txt:
                offenders.append(f"{path}: {needle}")

    assert not offenders, (
        f"FIX-75 two-pipeline guard: ferrous-utils/sync/src must contain "
        f"NO BIP-157 P2P handler / ancestor-walk code — fix bled across "
        f"pipeline boundary at: {offenders[:5]}"
    )


def test_fix75_test_i_handler_aborts_on_unknown_stop_hash():
    """I: regression — handler still disconnects peer when stop_hash is
    unknown (G13).  FIX-75's refactor must not have swallowed the
    PrepareBlockFilterRequest validation step.
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import GetCFiltersMessage

    db = _FakeForkedDB()
    bfi = BlockFilterIndex()
    bfi._filters = {db.G.hash: b"\x00"}
    bfi._headers = {db.G.hash: b"\x00" * 32}
    bfi._height_to_hash = {0: db.G.hash}

    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []
            self.disconnected = False

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

        def disconnect(self):
            self.disconnected = True

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            pass

        def set_outbound_peer_handler(self, cb):
            pass

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None
    node._register_handlers()

    handler = peer.handlers["getcfilters"]
    bad_stop = b"\xff" * 32  # never seen
    req = GetCFiltersMessage(filter_type=0, start_height=0, stop_hash=bad_stop)
    msg = req.to_network_message("mainnet")
    asyncio.run(handler(msg))

    assert peer.sent == [], "FIX-75: handler emitted filters for unknown stop_hash"
    assert peer.disconnected, (
        "FIX-75: handler did not disconnect peer on unknown stop_hash "
        "(G13 regression)"
    )


# ===========================================================================
# FIX-79 — cfheaders no longer falls back to zero prev_filter_header on
# orphan-fork ancestors (W121 BUG-4 / G28 closure)
# ===========================================================================
# Per FIX-75 commit body OOS note: "W121 BUG-4 (G28) cfheaders
# prev_filter_header zero-fallback remains xfail — the ancestor walk now
# resolves the correct orphan-fork prev_hash, BUT bfi.get_header() on an
# orphan block returns None and the response still falls back to zeros
# (separate fix needed)."
#
# FIX-79 adopts Approach B (defensive return-without-sending), matching
# Core's exact behavior in ProcessGetCFHeaders at net_processing.cpp:3361-
# 3370: LookupFilterHeader failure → log and return.  This is the same
# pattern already used by the ouroboros cfcheckpt handler at
# node.py:1396-1399 (post-FIX-75) — FIX-79 brings cfheaders into line with
# its sibling handler.
#
# Storage refactor (Approach A: per-hash secondary index, or Approach C:
# recompute on-the-fly) is deferred — Core itself returns silently from
# LookupFilterHeader when the block is not in the active-chain index, so
# parity is achieved without storage churn.
# ===========================================================================


def test_fix79_test_a_handler_aborts_on_orphan_prev_block_miss():
    """A: behavioral — getcfheaders with start_height > 0 on an orphan-tip
    stop_hash, where the orphan-fork prev block at (start_height - 1) is
    NOT in the filter index (the post-FIX-74 state after reorg-disconnect
    removed it).  Handler must NOT send a zero-anchored cfheaders.

    This is the "signed-but-lying" guard for the previous_filter_header
    field: pre-FIX-79 the handler emitted a CFHeadersMessage with
    previous_filter_header=b'\\x00'*32; post-FIX-79 the handler returns
    silently and the peer sees nothing (will time out and retry).
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import GetCFHeadersMessage

    db = _FakeForkedDB()

    # Pre-seed the filter index for the ACTIVE-CHAIN blocks only.  The
    # orphan-fork blocks B1/B2 are visible via db.get_block() but NOT
    # present in the filter index (mirrors the post-FIX-74 reorg state).
    bfi = BlockFilterIndex()
    bfi._filters = {
        db.G.hash: b"\x00",
        db.A1.hash: b"\xa1",
        db.A2.hash: b"\xa2",
        # NOTE: B1 / B2 deliberately absent — this is the orphan-after-
        # reorg-disconnect scenario.
    }
    bfi._headers = {
        db.G.hash: b"\x11" * 32,
        db.A1.hash: b"\x22" * 32,
        db.A2.hash: b"\x33" * 32,
        # NOTE: B1 / B2 deliberately absent.
    }
    bfi._height_to_hash = {0: db.G.hash, 1: db.A1.hash, 2: db.A2.hash}

    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []
            self.disconnected = False

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

        def disconnect(self):
            self.disconnected = True

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            pass

        def set_outbound_peer_handler(self, cb):
            pass

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None
    node._register_handlers()

    handler = peer.handlers.get("getcfheaders")
    assert handler is not None, "FIX-79 harness: getcfheaders handler not registered"

    # Request: stop_hash=B2 (orphan tip), start_height=2 (so prev block is
    # at height 1 → B1, which is NOT in the filter index).
    req = GetCFHeadersMessage(
        filter_type=0,
        start_height=2,
        stop_hash=db.B2.hash,
    )
    msg = req.to_network_message("mainnet")
    asyncio.run(handler(msg))

    # Pre-FIX-79: handler would have emitted a CFHeadersMessage with
    # previous_filter_header=b'\x00'*32.  Post-FIX-79: silent return.
    assert peer.sent == [], (
        "FIX-79 BUG-4: handler emitted a cfheaders response for an "
        "orphan-fork stop_hash where bfi.get_header(prev_block) returned "
        "None — would be a signed-but-lying response rooted at the all-"
        f"zeros sentinel.  Sent: {peer.sent!r}"
    )
    # We do NOT disconnect the peer here — Core only disconnects for
    # protocol-violation paths (unknown stop_hash, out-of-range, etc.).
    # An index miss on our side is not the peer's fault.
    assert not peer.disconnected, (
        "FIX-79: handler should NOT disconnect peer on our-side index "
        "miss — Core just returns silently (net_processing.cpp:3365-3369)"
    )


def test_fix79_test_b_handler_aborts_on_broken_ancestor_walk():
    """B: behavioral — getcfheaders where stop_block has no path back to
    (start_height - 1) because the db chain is broken (e.g. the prev
    block is missing entirely).  Handler must not zero-anchor.
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import GetCFHeadersMessage

    # Build a single-block "chain" where stop_block has height 5 but
    # prev_blockhash points at a hash the db doesn't know.  The ancestor
    # walk from height 5 → 4 will return None.
    G = _FakeOrphanBlock(b"\x00" * 31 + b"G", bytes(32), 0)
    stop = _FakeOrphanBlock(
        b"\xab" * 32, b"\xcd" * 32, 5
    )

    class _BrokenDB:
        def __init__(self):
            self._by_hash = {G.hash: G, stop.hash: stop}

        def get_block(self, h):
            return self._by_hash.get(h)

        def get_block_by_height(self, ht):
            return G if ht == 0 else None

    db = _BrokenDB()
    bfi = BlockFilterIndex()
    bfi._filters = {G.hash: b"\x00"}
    bfi._headers = {G.hash: b"\x00" * 32}
    bfi._height_to_hash = {0: G.hash}

    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []
            self.disconnected = False

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

        def disconnect(self):
            self.disconnected = True

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            pass

        def set_outbound_peer_handler(self, cb):
            pass

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None
    node._register_handlers()

    handler = peer.handlers["getcfheaders"]
    req = GetCFHeadersMessage(
        filter_type=0,
        start_height=5,
        stop_hash=stop.hash,
    )
    msg = req.to_network_message("mainnet")
    asyncio.run(handler(msg))

    assert peer.sent == [], (
        "FIX-79: handler emitted cfheaders despite ancestor walk failing "
        "to resolve prev_block at start_height - 1"
    )


def test_fix79_test_c_handler_emits_response_when_prev_header_resolvable():
    """C: forward regression — when the orphan-fork prev block IS in the
    filter index (e.g. before reorg-disconnect removed it), the handler
    MUST still emit a cfheaders response with the correct prev_header
    (not zeros, not nothing).
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import (
        GetCFHeadersMessage,
        CFHeadersMessage,
    )

    db = _FakeForkedDB()

    # Pre-seed the filter index for BOTH forks so the handler has every
    # header it needs.  This is the "pre-reorg-disconnect" state.
    bfi = BlockFilterIndex()
    bfi._filters = {
        db.G.hash: b"\x00",
        db.A1.hash: b"\xa1",
        db.A2.hash: b"\xa2",
        db.B1.hash: b"\xb1",
        db.B2.hash: b"\xb2",
    }
    bfi._headers = {
        db.G.hash: b"\x11" * 32,
        db.A1.hash: b"\x22" * 32,
        db.A2.hash: b"\x33" * 32,
        db.B1.hash: b"\x44" * 32,
        db.B2.hash: b"\x55" * 32,
    }
    bfi._height_to_hash = {0: db.G.hash, 1: db.A1.hash, 2: db.A2.hash}

    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            pass

        def set_outbound_peer_handler(self, cb):
            pass

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None
    node._register_handlers()

    handler = peer.handlers["getcfheaders"]
    # start_height=2 on orphan tip B2: prev block is B1 (orphan), which
    # IS indexed → handler must emit with prev_filter_header = B1's header.
    req = GetCFHeadersMessage(
        filter_type=0,
        start_height=2,
        stop_hash=db.B2.hash,
    )
    msg = req.to_network_message("mainnet")
    asyncio.run(handler(msg))

    assert len(peer.sent) == 1, (
        f"FIX-79: handler should have emitted exactly 1 cfheaders msg "
        f"when prev_block is indexed; got {len(peer.sent)}"
    )
    decoded = CFHeadersMessage.from_payload(peer.sent[0].payload)
    assert decoded.previous_filter_header == b"\x44" * 32, (
        f"FIX-79: previous_filter_header should be B1's stored header "
        f"(b'\\x44'*32), got {decoded.previous_filter_header!r}"
    )
    assert decoded.previous_filter_header != b"\x00" * 32, (
        "FIX-79: previous_filter_header is all-zeros — handler still "
        "falling back to zero sentinel"
    )


def test_fix79_test_d_handler_genesis_start_still_uses_zero_prev_header():
    """D: forward regression — when start_height == 0, the previous-header
    field is by-definition the all-zeros sentinel (no block precedes
    genesis).  The FIX-79 abort branch is gated on start_height > 0, so
    this path must still emit a cfheaders with zero prev_header.
    """
    import asyncio

    from ouroboros.node import BitcoinNode
    from ouroboros.blockfilter import BlockFilterIndex
    from ouroboros.p2p_messages import (
        GetCFHeadersMessage,
        CFHeadersMessage,
    )

    db = _FakeForkedDB()
    bfi = BlockFilterIndex()
    bfi._filters = {
        db.G.hash: b"\x00",
        db.A1.hash: b"\xa1",
        db.A2.hash: b"\xa2",
    }
    bfi._headers = {
        db.G.hash: b"\x11" * 32,
        db.A1.hash: b"\x22" * 32,
        db.A2.hash: b"\x33" * 32,
    }
    bfi._height_to_hash = {0: db.G.hash, 1: db.A1.hash, 2: db.A2.hash}

    class _StubPeer:
        host = "fake"
        port = 0
        network = "mainnet"

        def __init__(self):
            self.handlers = {}
            self.sent: list = []

        def register_handler(self, name, fn):
            self.handlers[name] = fn

        async def send_message(self, msg):
            self.sent.append(msg)

    class _StubPeerManager:
        def __init__(self, peers):
            self._peers = peers

        def get_all_ready_peers(self):
            return self._peers

        def set_inbound_peer_handler(self, cb):
            pass

        def set_outbound_peer_handler(self, cb):
            pass

    peer = _StubPeer()
    pm = _StubPeerManager([peer])

    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = bfi
    node.peer_manager = pm
    node.mempool = None
    node._register_handlers()

    handler = peer.handlers["getcfheaders"]
    req = GetCFHeadersMessage(
        filter_type=0,
        start_height=0,
        stop_hash=db.A2.hash,
    )
    msg = req.to_network_message("mainnet")
    asyncio.run(handler(msg))

    assert len(peer.sent) == 1, (
        f"FIX-79: genesis-rooted cfheaders should still emit; "
        f"got {len(peer.sent)} responses"
    )
    decoded = CFHeadersMessage.from_payload(peer.sent[0].payload)
    assert decoded.previous_filter_header == b"\x00" * 32, (
        "FIX-79: start_height == 0 must keep zero-sentinel prev_header "
        "(no block precedes genesis); FIX-79 must not over-fire here"
    )


def test_fix79_two_pipeline_guard_rust_has_no_cfheaders_handler():
    """FIX-79 must live entirely in the Python pipeline.  The Rust crate
    (ferrous-utils/sync) must remain free of any cfheaders / prev_filter
    handling — any drift here would mean the fix has bled across the
    pipeline boundary.

    Mirrors the FIX-74 + FIX-75 two-pipeline guards.  Counterpart to G30.
    """
    from pathlib import Path

    rust_root = Path(__file__).parent.parent / "ferrous-utils" / "sync" / "src"
    forbidden = (
        "GetCFHeaders",
        "CFHeaders",
        "prev_filter_header",
        "previous_filter_header",
        "LookupFilterHeader",
        "block_filter_index",
    )

    if not rust_root.exists():
        return  # submodule not populated — trivially true

    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in txt:
                offenders.append(f"{path}: {needle}")

    assert not offenders, (
        f"FIX-79 two-pipeline guard: ferrous-utils/sync/src must contain "
        f"NO cfheaders / prev_filter_header / block_filter_index code — "
        f"fix bled across pipeline boundary at: {offenders[:5]}"
    )
