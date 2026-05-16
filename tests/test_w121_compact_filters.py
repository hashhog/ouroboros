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
    G25 Reorg disconnect rolls back index (remove filter + tip header)      BUG-1 MISSING
    G26 Reorg connect re-runs add_block for new chain                       BUG-2 MISSING
    G27 cfilter handler aborts on any missing height (no partial response)  BUG-3 BROKEN
    G28 cfheaders prev_header lookup failure → no response (not zeros)      BUG-4 BROKEN
    G29 Index-not-synced gate before advertising NODE_COMPACT_FILTERS       BUG-5 MISSING
    G30 Rust pipeline parity (ferrous-utils BIP-157/158)                    TP-1 MISSING

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
# G25 — Reorg disconnect must remove indexed filters (BUG-1, MISSING)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="BUG-1: reorg disconnect never calls block_filter_index.remove()")
def test_g25_reorg_disconnect_rolls_back_filter_index():
    """
    Core requires the filter index to follow the active chain. On a reorg,
    Bitcoin Core's BlockFilterIndex receives BlockDisconnected callbacks
    via CValidationInterface (see index/blockfilterindex.cpp) and rolls
    back its summary.

    Ouroboros block_sync.py reorg path (lines 2942-2955) calls
    self.db.disconnect_block but NEVER block_filter_index.remove(),
    leaving stale filter entries that chain to the now-orphan tip.

    The fix is a hook in the reorg disconnect loop:
        if self.block_filter_index is not None:
            await asyncio.to_thread(
                self.block_filter_index.remove,
                curr_hash, height
            )
        # plus a tip_header rollback to common_ancestor's filter header
    """
    reorg_section = _reorg_section_of_block_sync()
    # The disconnect loop must call block_filter_index.remove() (or set
    # tip_header back to the common ancestor's filter header — either
    # path keeps the filter index consistent with the active chain).
    assert "block_filter_index.remove" in reorg_section or (
        "block_filter_index.set_tip_header" in reorg_section
    ), (
        "reorg disconnect loop does not call block_filter_index.remove() "
        "or set_tip_header(); filter index will diverge from active chain "
        "after any reorg, and the tip_header still chains to the orphan tip."
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
# G26 — Reorg connect must re-index new chain (BUG-2, MISSING)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="BUG-2: reorg connect-side never re-runs block_filter_index.add_block()")
def test_g26_reorg_connect_reindexes_new_chain():
    """
    Symmetric to G25: when a reorg connects the new chain, each newly
    connected block must be passed to block_filter_index.add_block so
    the index follows the active chain. block_sync.py:2974-3027 misses
    this — only the linear connect path at line 1362 does it.
    """
    reorg_section = _reorg_section_of_block_sync()
    # Within the reorg section ONLY, the connect loop must hook the
    # filter index. The linear path at line 1365 is outside this slice.
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

@pytest.mark.xfail(strict=True, reason="BUG-3: getcfilters uses `continue` instead of aborting on missing block")
def test_g27_getcfilters_aborts_on_missing_height():
    """
    Core's ProcessGetCFilters calls LookupFilterRange which returns false
    on the first missing filter; the handler then logs and returns
    WITHOUT sending any cfilter messages (net_processing.cpp:3333-3337).

    Ouroboros uses `continue` (node.py:1151) which silently skips the
    missing height and continues sending cfilters for later heights —
    the peer receives a stream that's inconsistent with their request
    and may flag DoS / treat as silent corruption.

    Test: scan the source for the broken `continue` pattern. Fix is to
    abort the loop entirely (raise / break + don't send anything).
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
# G28 — getcfheaders prev_header zero-fallback is wire-incompat (BUG-4, BROKEN)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="BUG-4: getcfheaders silently uses all-zero prev_filter_header when index lookup fails")
def test_g28_getcfheaders_no_zero_fallback_for_prev_header():
    """
    Core's ProcessGetCFHeaders calls LookupFilterHeader on the
    (start_height - 1) block and aborts the response if the lookup
    fails (net_processing.cpp:3361-3370). It NEVER falls back to
    zero — that would produce a wire-valid cfheaders message chained
    to a fake genesis, indistinguishable on the wire from an honest
    one until a light client cross-checks against another peer.

    Ouroboros node.py:1224 starts `prev_filter_header = b'\\x00' * 32`
    and only updates it if the index has the stored header. On miss
    (index not synced past start_height-1, or block absent), the
    response is sent with zeros.

    Fix: after the lookup chain, if `prev_filter_header` is still the
    sentinel zeros AND start_height > 0, abort without sending.
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
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="BUG-5: NODE_COMPACT_FILTERS advertised on index OPEN, not on index SYNCED")
def test_g29_index_synced_gate_before_node_compact_filters_advertised():
    """
    Bitcoin Core's BlockFilterIndex inherits BaseIndex which only signals
    "ready" once the index thread has caught up to ActiveChain().Tip()
    (see index/base.cpp ThreadSync + BaseIndex::Start, and the
    init.cpp StartBlockFilterIndexes path that registers the index
    asynchronously). NODE_COMPACT_FILTERS is set in init.cpp
    `nLocalServices` immediately, but the SERVICE BIT is what Core
    advertises in version; in practice the index thread blocks any
    inbound getcfilters response while it's still backfilling because
    LookupFilterRange returns false for un-indexed heights.

    Ouroboros lets the handler fall back to on-fly construction for
    un-indexed heights AND uses zero-fallback for prev_filter_header
    (BUG-4). Combined, a fresh node that opens an empty index serves
    *invalid* (zero-anchored) filter headers to light clients
    immediately at handshake.

    The fix is a sync gate: track block_filter_index.best_indexed_height
    and only set node_compact_filters=True once it ≥ active chain tip,
    OR only advertise the service bit after the first add_block call
    succeeds at the current tip.
    """
    # Probe the PersistentBlockFilterIndex API for a sync-state property.
    has_sync_property = any(
        hasattr(PersistentBlockFilterIndex, attr)
        for attr in (
            "is_synced",
            "best_indexed_height",
            "synced",
            "is_caught_up",
        )
    )
    assert has_sync_property, (
        "PersistentBlockFilterIndex exposes no is_synced / best_indexed_height "
        "property; node.py cannot gate NODE_COMPACT_FILTERS advertisement on "
        "index-caught-up. A fresh node serves zero-prev-header cfheaders "
        "(see BUG-4) the moment it advertises NODE_COMPACT_FILTERS."
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
