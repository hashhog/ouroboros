"""W97 — AcceptBlock/AcceptBlockHeader/ProcessNewBlockHeaders gate audit
(ouroboros).

Audits ouroboros's block-acceptance pipeline against Bitcoin Core's
``AcceptBlockHeader`` (validation.cpp:4186-4239),
``ProcessNewBlockHeaders`` (4242-4270), and
``AcceptBlock`` (4298-4396).

ouroboros's pipeline is split across three modules:

* ``src/ouroboros/block_sync.py::BlockSync.handle_headers`` is the
  ProcessNewBlockHeaders + AcceptBlockHeader analog for the P2P headers
  message: per-header PoW gate, chain-continuity gate, dedup against the
  in-session validated-header queue, hand-off to the Rust
  ``PyHeadersSyncState`` for commitment / cumulative-work tracking.
* ``src/ouroboros/block_sync.py::BlockSync._drain_block_buffer_locked``
  is the P2P AcceptBlock analog: CheckBlock + ConnectBlock per buffered
  block in chain order.
* ``src/ouroboros/rpc.py::accept_block`` is the unified RPC AcceptBlock
  pipeline (Step 1 BIP-34, Step 2 Rust validate_block_from_bytes, Step
  3 Python BlockValidator.validate_block, Step 4 connect_block_from_bytes,
  Step 5 mempool eviction).

Reference: bitcoin-core/src/validation.cpp (4186-4396); ouroboros's own
W93 audit memo for the connect-side gates already closed.

The tests below are scoped to *audit findings*: each one is marked
``xfail(strict=False, reason="W97 audit")`` to record the spec without
breaking the suite while fixes are pending.  Cosmetic-only gates that
ouroboros has correctly closed are added as plain passes for regression
protection.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# Install the sync mock before any ouroboros import.
import tests.conftest  # noqa: F401

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import BlockHeader, HeadersMessage, NetworkMessage


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

GENESIS_TIME = 1_231_006_505
MAINNET_BITS = 0x1D00FFFF
REGTEST_BITS = 0x207FFFFF


def _make_block_sync(
    tip_hash: bytes = b"\x00" * 32,
    tip_height: int = 0,
    network: str = "mainnet",
) -> BlockSync:
    """Build a ``BlockSync`` with stubbed db / validator / peer manager."""
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.has_block_hash.return_value = False
    db.get_median_time_past.return_value = 1_700_000_000

    peer_manager = MagicMock()
    peer_manager.network = network
    peer_manager.misbehaving = MagicMock()

    return BlockSync(db=db, validator=MagicMock(), peer_manager=peer_manager)


def _make_peer(host: str = "127.0.0.1", port: int = 8333):
    peer = MagicMock()
    peer.host = host
    peer.port = port
    peer.adjust_score = MagicMock()
    peer.is_connected = MagicMock(return_value=True)

    async def _send_message(*_a, **_kw):
        return None

    peer.send_message = MagicMock(side_effect=_send_message)
    return peer


def _valid_header_extending(prev: bytes, *, bits: int = REGTEST_BITS) -> BlockHeader:
    """A header that extends *prev*; uses regtest bits=0x207fffff so any nonce
    that yields a hash <= the (huge) regtest target passes the PoW gate.
    For regtest the smallest-bytes hash is almost always within target, so we
    iterate a tiny nonce search to find one that passes.
    """
    # Iterate until the header hashes under target; for regtest bits this
    # converges essentially immediately (target is 2^255-1 class).
    for nonce in range(0, 200):
        h = BlockHeader(
            version=1,
            prev_blockhash=prev,
            merkle_root=b"\x00" * 32,
            timestamp=GENESIS_TIME,
            bits=bits,
            nonce=nonce,
        )
        if BlockSync._header_meets_pow(h):
            return h
    raise RuntimeError("could not find a PoW-passing header at given bits")


# ---------------------------------------------------------------------------
# AcceptBlockHeader gates (G1 — G10)
# ---------------------------------------------------------------------------


class TestG1DuplicateHashShortCircuit:
    """G1 — Duplicate-hash short-circuit before any validation."""

    @pytest.mark.asyncio
    async def test_duplicate_header_in_queue_is_skipped(self):
        """A header whose hash is already in ``_validated_headers`` is
        skipped without re-running PoW/chain-prev validation.

        This is the in-session dedup path; the per-batch ``known_hashes``
        set short-circuits the header before the per-header PoW gate.
        """
        tip = b"\x11" * 32
        bs = _make_block_sync(tip_hash=tip, tip_height=100)
        peer = _make_peer()

        h1 = _valid_header_extending(tip)
        # Pre-seed the queue so the dedup branch fires.
        h1_hash = bs._header_to_block_hash(h1)
        bs._validated_headers.append((h1_hash, h1))

        msg = NetworkMessage(
            command="headers",
            payload=HeadersMessage(headers=[h1]).serialize_payload(),
            magic=0,
        )
        await bs.handle_headers(msg, peer)
        # The duplicate must NOT have caused a misbehavior call.
        peer.adjust_score.assert_not_called()

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G1: handle_headers does not consult the persistent "
        "block-index dedup. After a restart, BLOCK_FAILED_VALID / "
        "BLOCK_HAVE_DATA short-circuits aren't run; the per-header PoW gate "
        "re-runs every received header. Core's AcceptBlockHeader returns "
        "'duplicate' / 'duplicate-invalid' at validation.cpp:4191-4198.",
    )
    def test_handle_headers_consults_persistent_block_index(self):
        """Persistent dedup against the block index isn't wired into
        ``handle_headers``.  Documented as a deliberate trade-off in the
        938231-wedge comments (block_sync.py:1612-1626), but it means a peer
        that re-sends a known-bad header forces another PoW recheck."""
        assert False, "G1: persistent dedup is intentionally skipped"


class TestG2GenesisBypass:
    """G2 — Genesis-block bypass of CheckBlockHeader + prev lookup."""

    def test_validator_genesis_height_branch_exists(self):
        """``BlockValidator._validate_header`` guards every contextual
        check on ``height > 0`` so the function does NOT call
        ``prev_block.timestamp`` etc. when height==0.

        Reference: ouroboros/validation.py:960 ``# Guard on height > 0:
        genesis (height 0) has no pindexPrev in Core, so the check is
        never reached for genesis``.
        """
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator._validate_header)
        # The genesis-aware guards must mention height > 0 at least once.
        assert "height > 0" in src, (
            "_validate_header must guard contextual checks on height > 0 "
            "(genesis-bypass; Core validation.cpp:4080 sequence)"
        )


class TestG3CachedInvalidShortCircuit:
    """G3 — BLOCK_FAILED_VALID existing → 'duplicate-invalid' / BLOCK_CACHED_INVALID."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G3: handle_headers has no BLOCK_FAILED_VALID dedup. "
        "_perm_rejected_blocks (block_sync.py:366) is checked only in "
        "handle_block, not in handle_headers — a peer can re-send the "
        "header for a permanently-rejected block and we'll re-walk the "
        "queue, re-feed presync, and re-misbehave on the chain-prev path "
        "instead of returning early with 'duplicate-invalid'.",
    )
    def test_perm_rejected_block_hash_short_circuits_handle_headers(self):
        """Pre-fix: ``_perm_rejected_blocks`` is only consulted in
        ``handle_block``, after the full deserialize+validate work.
        ``handle_headers`` does NOT check it, so a peer can keep
        re-announcing the header for a known-bad block."""
        assert False, "G3: BLOCK_FAILED_VALID dedup absent in handle_headers"


class TestG4CheckBlockHeaderPoW:
    """G4 — CheckBlockHeader call (PoW + nBits sanity)."""

    @pytest.mark.asyncio
    async def test_header_failing_pow_is_dropped_with_misbehavior(self):
        """The per-header PoW gate is the CheckBlockHeader analog (post
        2026-05-06 fix; ``_header_meets_pow``).  This is the closed
        version of W97's G4 — included as regression protection."""
        tip = b"\x11" * 32
        bs = _make_block_sync(tip_hash=tip, tip_height=100)
        peer = _make_peer()

        bad = BlockHeader(
            version=1,
            prev_blockhash=tip,
            merkle_root=b"\xcc" * 32,
            timestamp=1_700_000_000,
            bits=MAINNET_BITS,  # claimed difficulty
            nonce=0,            # nonce=0 will almost never satisfy
        )
        msg = NetworkMessage(
            command="headers",
            payload=HeadersMessage(headers=[bad]).serialize_payload(),
            magic=0,
        )
        await bs.handle_headers(msg, peer)
        peer.adjust_score.assert_called()  # G4 misbehavior path fires
        assert len(bs._validated_headers) == 0


class TestG5PrevBlockNotFound:
    """G5 — Prev block lookup → 'prev-blk-not-found' / BLOCK_MISSING_PREV."""

    @pytest.mark.asyncio
    async def test_unconnecting_header_does_not_append_and_misbehaves(self):
        """A header whose ``prev_blockhash`` does not extend the current
        expected-prev is the analog of Core's BLOCK_MISSING_PREV.  After
        ``MAX_NUM_UNCONNECTING_HEADERS_MSGS`` consecutive such batches,
        the peer is misbehavior-scored.  (block_sync.py:1647-1663.)
        """
        tip = b"\x11" * 32
        bs = _make_block_sync(tip_hash=tip, tip_height=100)
        peer = _make_peer()

        unrelated = _valid_header_extending(b"\x99" * 32)
        msg = NetworkMessage(
            command="headers",
            payload=HeadersMessage(headers=[unrelated]).serialize_payload(),
            magic=0,
        )
        await bs.handle_headers(msg, peer)
        # First miss: counter incremented but no immediate ban.  The
        # queue must still be empty — we did NOT append the bad header.
        assert len(bs._validated_headers) == 0

    def test_rpc_submitblock_returns_prev_blk_not_found(self):
        """The RPC AcceptBlock analog (rpc.py:5699-5702) returns the
        Core-canonical ``prev-blk-not-found`` string when the parent is
        neither on the active chain nor in the side-branch buffer."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_submitblock)
        assert "prev-blk-not-found" in src, (
            "rpc_submitblock must surface BIP-22 'prev-blk-not-found' for "
            "orphan side-branch submissions (Core validation.cpp:4321-4323)"
        )


class TestG6BadPrevBlk:
    """G6 — Prev BLOCK_FAILED_VALID → 'bad-prevblk' / BLOCK_INVALID_PREV."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G6: ouroboros does not propagate BLOCK_FAILED_VALID "
        "to children. If a header's parent was previously rejected, the "
        "header is treated as a normal chain-prev miss and contributes "
        "to the unconnecting-headers counter rather than being rejected "
        "with 'bad-prevblk' and the BLOCK_FAILED_CHILD flag (Core "
        "validation.cpp:4219). _perm_rejected_blocks is a flat set with "
        "no descendant taint propagation.",
    )
    def test_bad_prevblk_propagation_missing(self):
        assert False, "G6: BLOCK_FAILED_CHILD propagation absent"


class TestG7ContextualCheckBlockHeader:
    """G7 — ContextualCheckBlockHeader with pindexPrev."""

    def test_validate_header_runs_contextual_gates(self):
        """``_validate_header`` covers the 5 contextual gates Core's
        ContextualCheckBlockHeader runs: bad-diffbits, time-too-old,
        BIP-94 time-warp, time-too-new, bad-version."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator._validate_header)
        for marker in ("bad-diffbits", "time-too-old", "time-timewarp-attack",
                       "time-too-new", "bad-version"):
            assert marker in src, f"_validate_header missing {marker} gate"

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G7: in the IBD drain path, ContextualCheckBlockHeader "
        "is NOT separately invoked on the header before CheckBlock. The "
        "header's contextual checks happen inside the validator's "
        "validate_block call, which runs AFTER the cheap structural gates. "
        "Core's AcceptBlockHeader runs ContextualCheckBlockHeader as the "
        "second gate (validation.cpp:4221), allowing earlier rejection "
        "of bad-diffbits / bad-version headers before the block body is "
        "even deserialized. ouroboros's order is reversed: PoW gate (cheap), "
        "chain-prev (cheap), then full block validate (expensive) — no "
        "per-header contextual rejection.",
    )
    def test_handle_headers_runs_contextual_check_before_block_body(self):
        assert False, "G7: ContextualCheckBlockHeader not separately run on header path"


class TestG8MinimumChainWork:
    """G8 — min_pow_checked → 'too-little-chainwork' / BLOCK_HEADER_LOW_WORK."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G8 (CRITICAL DOS): Python handle_headers does NOT "
        "enforce nMinimumChainWork. validate_minimum_chain_work exists in "
        "Rust (ferrous-utils/sync/src/validate/header.rs:361) and is "
        "advertised in config.py:444, but is NEVER called from Python. "
        "PyHeadersSyncState (block_sync.py:1701) tracks cumulative work "
        "but its result.success boolean drops the presync state rather than "
        "rejecting individual headers below threshold. A peer can therefore "
        "feed up to 50,000 well-formed-PoW low-work headers (mainnet "
        "starting bits) and have all of them appended to _validated_headers "
        "and forwarded to other peers via header-announce. Core's "
        "AcceptBlockHeader returns BLOCK_HEADER_LOW_WORK and 'too-little-"
        "chainwork' at validation.cpp:4223-4225.",
    )
    def test_minimum_chain_work_enforced_in_handle_headers(self):
        assert False, "G8: nMinimumChainWork not wired into Python header path"

    def test_rust_minimum_chain_work_helper_exists(self):
        """The Rust helper is defined; the bug is that it's not wired from
        Python.  Test pins down the API surface so it isn't accidentally
        removed before the wiring lands."""
        import inspect
        from ouroboros.config import ChainParams
        src = inspect.getsource(ChainParams.get_minimum_chain_work)
        assert "minimum_chain_work" in src


class TestG9AddToBlockIndex:
    """G9 — AddToBlockIndex updates best_header + nChainWork."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G9: ouroboros has no in-memory block-index that "
        "tracks best_header / nChainWork independently of the active "
        "chain. _validated_headers is a FIFO queue (block_sync.py:340), "
        "not a Core-style mapBlockIndex with per-entry nChainWork. "
        "Headers above the active tip are never reflected in "
        "getblockchaininfo's 'headers' field (which derives from the "
        "active chain only) — this is the observable manifestation of "
        "the gap. Core's AddToBlockIndex updates m_best_header at "
        "validation.cpp:4146.",
    )
    def test_best_header_tracks_above_active_tip(self):
        assert False, "G9: best_header / nChainWork tracking absent"


class TestG10PpindexWriteBack:
    """G10 — ppindex write-back including genesis-bypass."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G10: handle_headers returns no per-header "
        "CBlockIndex* analog to callers; the return is implicit via the "
        "_validated_headers queue. There is no genesis-bypass branch "
        "because ouroboros's handle_headers loop only ever receives "
        "non-genesis headers (genesis is bootstrapped at db init). "
        "Verifying that genesis can never be silently added to the queue "
        "requires a separate invariant test the audit calls out.",
    )
    def test_genesis_never_appended_to_validated_headers(self):
        assert False, "G10: genesis-bypass invariant not testable today"


# ---------------------------------------------------------------------------
# ProcessNewBlockHeaders gates (G11 — G16)
# ---------------------------------------------------------------------------


class TestG11CsMainHeldThroughout:
    """G11 — cs_main held throughout loop."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G11 (CONCURRENCY): handle_headers takes NO lock for "
        "the per-batch loop. _drain_lock (block_sync.py:340) is acquired "
        "ONLY in _drain_block_buffer, not in handle_headers. Two "
        "concurrent headers messages from two peers can interleave the "
        "_validated_headers append / known_hashes update / presync feed "
        "without serialization. Core's ProcessNewBlockHeaders holds "
        "cs_main for the entire loop (validation.cpp:4247).",
    )
    def test_handle_headers_acquires_chain_lock(self):
        assert False, "G11: no cs_main analog around the header-accept loop"


class TestG12CheckBlockIndexInvariant:
    """G12 — CheckBlockIndex invariant after EACH AcceptBlockHeader."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G12: ouroboros has no CheckBlockIndex post-condition "
        "after each accepted header. In debug builds Core runs an "
        "expensive invariant check (validation.cpp:4256). ouroboros has "
        "a slot-alignment check (_queue_anchored_to_tip / "
        "_coinbase_height_mismatch) but they fire in the connect path, "
        "not the header path, so a corrupted _validated_headers queue is "
        "only detected at block-connect time — the 938231 wedge memory.",
    )
    def test_check_block_index_post_each_header(self):
        assert False, "G12: post-accept invariant absent in header path"


class TestG13EarlyReturnOnFirstFail:
    """G13 — Early return on first failed header."""

    @pytest.mark.asyncio
    async def test_handle_headers_breaks_on_first_chain_prev_failure(self):
        """When a header in the middle of a batch fails chain-prev, the
        remaining headers in the batch are dropped (block_sync.py:1663
        ``break``).  This is the early-return analog."""
        tip = b"\x11" * 32
        bs = _make_block_sync(tip_hash=tip, tip_height=100)
        peer = _make_peer()

        h1 = _valid_header_extending(tip)
        h1_hash = bs._header_to_block_hash(h1)
        # h2 connects to h1 (good); h3 dangles (bad).
        h2 = _valid_header_extending(h1_hash)
        h2_hash = bs._header_to_block_hash(h2)
        h3 = _valid_header_extending(b"\x99" * 32)  # wrong prev

        msg = NetworkMessage(
            command="headers",
            payload=HeadersMessage(headers=[h1, h2, h3]).serialize_payload(),
            magic=0,
        )
        await bs.handle_headers(msg, peer)
        # h1, h2 accepted; h3 (and any subsequent) rejected at break.
        accepted = {h for h, _ in bs._validated_headers}
        assert h1_hash in accepted
        assert h2_hash in accepted
        h3_hash = bs._header_to_block_hash(h3)
        assert h3_hash not in accepted


class TestG14PpindexUpdatedOnAccept:
    """G14 — ppindex updated on each successful accept."""

    @pytest.mark.asyncio
    async def test_validated_headers_appended_in_chain_order(self):
        """Each successful accept appends to ``_validated_headers`` so
        slot ordering is preserved.  This is the ppindex analog
        (per-header observable handle)."""
        tip = b"\x11" * 32
        bs = _make_block_sync(tip_hash=tip, tip_height=100)
        peer = _make_peer()

        h1 = _valid_header_extending(tip)
        h1_hash = bs._header_to_block_hash(h1)
        h2 = _valid_header_extending(h1_hash)
        h2_hash = bs._header_to_block_hash(h2)

        msg = NetworkMessage(
            command="headers",
            payload=HeadersMessage(headers=[h1, h2]).serialize_payload(),
            magic=0,
        )
        await bs.handle_headers(msg, peer)
        assert bs._validated_headers[0][0] == h1_hash
        assert bs._validated_headers[1][0] == h2_hash


class TestG15NotifyHeaderTipOutsideCsMain:
    """G15 — NotifyHeaderTip OUTSIDE cs_main."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G15: ouroboros has no NotifyHeaderTip / "
        "header-tip ZMQ notification. ZMQPublisher.notify_block fires "
        "AFTER the block body connects (block_sync.py:1309) and "
        "rawheader / -zmqpubrawblock are wired separately. The 'header "
        "tip is advancing while blocks are still downloading' UI signal "
        "Core surfaces via UI_NOTIFY_HEADER_TIP does not exist here.",
    )
    def test_notify_header_tip_emitted(self):
        assert False, "G15: NotifyHeaderTip analog absent"


class TestG16IBDProgressLogPowTargetSpacing:
    """G16 — IBD progress log uses PowTargetSpacing()."""

    def test_pow_target_spacing_constant_is_not_network_aware(self):
        """``POW_TARGET_SPACING`` is hardcoded at 10*60 in validation.py:56
        and is used to compute the min-difficulty exception in
        ``_get_expected_bits`` (validation.py:1059).  Core's
        ``PowTargetSpacing()`` returns a network-specific value but for
        all four standard networks it IS 600s — this constant is correct
        by accident.  A custom network would diverge.  Pinning the
        constant here forces future test failures if it's changed without
        updating the IBD progress log."""
        from ouroboros import validation
        assert validation.POW_TARGET_SPACING == 600

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G16: no IBD-progress log in handle_headers uses "
        "PowTargetSpacing for estimated-completion-time math. Core logs "
        "'Synchronizing blockheaders, progress=...' with rate keyed off "
        "PowTargetSpacing (net_processing.cpp). ouroboros logs raw "
        "'Received N headers' (block_sync.py:1544) with no completion "
        "estimate — purely observability.",
    )
    def test_ibd_progress_log_emits_estimated_completion(self):
        assert False, "G16: IBD progress log uses no spacing-based ETA"


# ---------------------------------------------------------------------------
# AcceptBlock gates (G17 — G30)
# ---------------------------------------------------------------------------


class TestG17AcceptBlockHeaderInnerCall:
    """G17 — AcceptBlockHeader inner call + CheckBlockIndex invariant."""

    def test_accept_block_runs_bip34_height_check_first(self):
        """``accept_block`` (rpc.py:220) runs the BIP-34 coinbase-height
        check BEFORE Rust validate_block_from_bytes.  This is the Core
        AcceptBlock prelude — header gates fire first.

        Test compares the runtime invocation, not the docstring text:
        anchored on the "Step 1" and "Step 2" comment markers so the
        ordering check survives docstring rewrites.
        """
        import inspect
        from ouroboros.rpc import accept_block
        src = inspect.getsource(accept_block)
        idx_step1 = src.index("Step 1")
        idx_step2 = src.index("Step 2")
        idx_rust_call = src.index("db.validate_block_from_bytes")
        assert idx_step1 < idx_step2 < idx_rust_call, (
            "accept_block must run BIP-34 height check (Step 1, header-level) "
            "before block-body validation (Step 2; Core AcceptBlockHeader order)"
        )


class TestG18FAlreadyHaveBlockHaveData:
    """G18 — fAlreadyHave = BLOCK_HAVE_DATA → return true."""

    def test_rpc_submitblock_returns_duplicate_for_known_block(self):
        """rpc_submitblock returns the Core-canonical 'duplicate' string
        when has_block_hash already returns True (rpc.py:5664-5666)."""
        import inspect
        from ouroboros.rpc import RPCServer
        src = inspect.getsource(RPCServer.rpc_submitblock)
        assert "duplicate" in src and "has_block_hash" in src

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G18: in the P2P drain path "
        "(_drain_block_buffer_locked), the fAlreadyHave check only "
        "fires in handle_block at the BUFFER level (block_sync.py:854). "
        "The drain itself does not re-check 'do we already have this "
        "block on the active chain' before validating + connecting. In "
        "the rare case where two paths buffer the same block, both run "
        "the full validate path. Not a consensus bug — just wasted CPU.",
    )
    def test_drain_rechecks_have_data_before_validate(self):
        assert False, "G18: redundant have-data check in drain"


class TestG19EarlyReturnGates:
    """G19a/b/c/d — Early-return gates before CheckBlock."""

    def test_g19a_nTx_zero_early_return_for_pruned_blocks(self):
        """G19a: ouroboros has no explicit nTx==0 early-return (pruned
        blocks are detected later in the validator via empty
        transactions list — 'Block has no transactions',
        validation.py:773). This is a logic-equivalent guard but at a
        different stage of the pipeline."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator.validate_block)
        assert "no transactions" in src

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G19b: no fHasMoreOrSameWork gate. handle_block "
        "buffers every received block whose hash is in requested_blocks "
        "or whose hash isn't already-known; it never checks whether the "
        "new tip would have *more chain work* than the current active "
        "tip before validating. Core: validation.cpp:4336-4342.",
    )
    def test_g19b_fHasMoreOrSameWork_unrequested_gate(self):
        assert False, "G19b: fHasMoreOrSameWork gate absent"

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G19c (CRITICAL DOS): no fTooFarAhead = "
        "nHeight > ActiveHeight + 288 gate. A peer can deliver a block "
        "whose claimed height is millions above the active tip; "
        "handle_block buffers it (block_sync.py:874-883) until "
        "_max_ibd_buffer is reached. Core: validation.cpp:4348-4350 "
        "rejects with no further validation. This is a real memory-DoS "
        "vector — _max_ibd_buffer defaults to a multi-MB cap.",
    )
    def test_g19c_fTooFarAhead_gate(self):
        assert False, "G19c: fTooFarAhead gate absent — DoS"

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G19d: nChainWork < MinimumChainWork early-return "
        "absent in handle_block. Same root cause as G8 — Rust helper "
        "exists, Python doesn't call it. Core: validation.cpp:4352-4356.",
    )
    def test_g19d_minimum_chain_work_early_return(self):
        assert False, "G19d: nChainWork < MinChainWork early-return absent"


class TestG20CheckBlockCall:
    """G20 — CheckBlock call."""

    def test_accept_block_runs_check_block_structural(self):
        """``accept_block`` (rpc.py:303) calls Rust
        ``validate_block_from_bytes`` which is the Core CheckBlock +
        ContextualCheckBlock analog (PoW, merkle root, weight, sigops,
        witness, BIP-30, BIP-68, duplicate txid)."""
        import inspect
        from ouroboros.rpc import accept_block
        src = inspect.getsource(accept_block)
        assert "validate_block_from_bytes" in src


class TestG21ContextualCheckBlock:
    """G21 — ContextualCheckBlock(block, state, *this, pindex->pprev)."""

    def test_validator_uses_prev_block_mtp_for_block_113(self):
        """``BlockValidator.validate_block`` computes ``block_mtp`` from
        the previous block (validation.py:657) and uses MTP-vs-blocktime
        for BIP-113 / nLockTimeCutoff (validation.py:671-672).  This is
        the ContextualCheckBlock analog."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator.validate_block)
        assert "get_median_time_past" in src
        assert "nLockTimeCutoff" in src


class TestG22InvalidBlockFound:
    """G22 — InvalidBlockFound on either fail."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G22: InvalidBlockFound's job is to mark the "
        "CBlockIndex with BLOCK_FAILED_VALID AND propagate "
        "BLOCK_FAILED_CHILD to descendants. ouroboros's "
        "_mark_perm_rejected (block_sync.py:394) marks the single "
        "block_hash but never walks descendants. A re-announce of a "
        "child of a perm-rejected block has no fast-rejection path; the "
        "child goes through full validate (which rejects on prev-not-"
        "found) and is again perm-rejected — N round trips for an N-deep "
        "bad chain. Same root as G6.",
    )
    def test_invalid_block_found_taints_descendants(self):
        assert False, "G22: BLOCK_FAILED_CHILD propagation absent"


class TestG23NewPoWValidBlock:
    """G23 — NewPoWValidBlock ONLY when (!IBD && ActiveTip == pprev)."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G23: ouroboros has no NewPoWValidBlock-class "
        "callback. Core uses it to seed BIP-152 compact-block relay "
        "BEFORE ConnectBlock finishes (net_processing.cpp). ouroboros's "
        "compact-block path (compact_blocks.py) waits for the full "
        "connect — added latency for connected peers. Performance / "
        "observability only; no consensus impact.",
    )
    def test_new_pow_valid_block_pre_connect_relay(self):
        assert False, "G23: NewPoWValidBlock callback absent"


class TestG24WriteBlockVsUpdateBlockInfo:
    """G24 — WriteBlock vs UpdateBlockInfo (dbp path)."""

    def test_connect_block_from_bytes_persists_atomically(self):
        """The Rust ``connect_block_from_bytes`` path is a single-batch
        atomic write covering block bytes + UTXO mutations + undo
        records + BEST_BLOCK pointer (W92 Pattern D — confirmed in
        accept_block source).  This is the WriteBlock analog."""
        import inspect
        from ouroboros.rpc import accept_block
        src = inspect.getsource(accept_block)
        assert "connect_block_from_bytes" in src


class TestG25ReceivedBlockTransactions:
    """G25 — ReceivedBlockTransactions sets BLOCK_HAVE_DATA."""

    def test_block_status_flag_helpers_exist_in_rust(self):
        """The BLOCK_HAVE_DATA flag transitions are in ferrous-utils
        (types.rs:491+).  The Python-side observable is
        ``has_block_hash`` returning True after a successful connect;
        that's what handle_block uses for the dedup check
        (block_sync.py:854).
        """
        # Pure documentation test: pin the constant location.
        import pathlib
        types_rs = pathlib.Path(
            "/home/work/hashhog/ouroboros/ferrous-utils/common/src/types.rs"
        )
        if types_rs.exists():
            txt = types_rs.read_text()
            assert "BLOCK_HAVE_DATA" in txt


class TestG26FlushStateToDisk:
    """G26 — FlushStateToDisk(FlushStateMode::NONE)."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G26: no FlushStateToDisk-mode equivalent. RocksDB "
        "Write writes are flushed on the WriteBatch boundary (per "
        "block) — there is no periodic/forced FlushStateMode::PERIODIC "
        "/ FlushStateMode::IF_NEEDED / FlushStateMode::ALWAYS layer "
        "that Core's validation.cpp:4385 uses to control flush "
        "granularity. flushchainstate RPC is wired (rpc.py rpc_flushchainstate) "
        "but only on operator demand, not after every accepted block.",
    )
    def test_flush_state_to_disk_modes_distinct(self):
        assert False, "G26: FlushStateToDisk modes not modeled"


class TestG27CheckBlockIndexFinal:
    """G27 — CheckBlockIndex final invariant."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G27: no post-accept CheckBlockIndex invariant. "
        "Same root as G12 — ouroboros has no block-index data structure "
        "to invariant-check. validation.cpp:4388 calls CheckBlockIndex "
        "(no-op in release builds; structural assertions in debug).",
    )
    def test_check_block_index_final_invariant(self):
        assert False, "G27: post-accept invariant absent"


class TestG28FNewBlockOutput:
    """G28 — fNewBlock output (only true on new-block path)."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G28: accept_block returns the block_hash on "
        "success; there is no fNewBlock-equivalent out-parameter to "
        "distinguish 'newly connected' from 'already had it'. Callers "
        "must infer from has_block_hash before calling, which is "
        "racy across concurrent submitblock calls. Core: "
        "validation.cpp:4308 (the new_block out-pointer parameter).",
    )
    def test_accept_block_returns_new_block_flag(self):
        assert False, "G28: fNewBlock out-parameter absent"


class TestG29SystemErrorCatchOnDiskWrite:
    """G29 — System-error catch on disk write."""

    def test_drain_handles_connect_failure_by_rebuffer(self):
        """If ``connect_block_from_bytes`` raises, the drain rebuffers
        the block and continues (block_sync.py:1249-1255).  This is the
        connect-side analog of Core's AcceptBlock disk-error handler —
        though Core's response is more severe (AbortNode).  ouroboros's
        treats it as transient.  Documented; the harness pins down the
        behavior."""
        import inspect
        from ouroboros.block_sync import BlockSync
        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # The rebuffer pattern is present.
        assert "self._ibd_block_buffer[next_hash] = (block, raw_payload)" in src


class TestG30BlockHaveDataBeforeNextReceivedBlockTransactions:
    """G30 — BLOCK_HAVE_DATA set BEFORE next ReceivedBlockTransactions."""

    @pytest.mark.xfail(
        strict=False,
        reason="W97 audit G30: ordering invariant cannot be tested at this "
        "layer without the compiled Rust extension. The Rust "
        "connect_block_from_bytes path is a single WriteBatch so the "
        "ordering is structural, but the Python harness can't observe "
        "the intermediate state. Documented for the Rust unit-test "
        "suite (ferrous-utils/sync/src/storage/db_tests.rs).",
    )
    def test_block_have_data_set_before_next_block_transactions(self):
        assert False, "G30: ordering invariant only testable in Rust"


# ---------------------------------------------------------------------------
# Endianness / network-conditional gate spot-checks (memory-cited hot zones)
# ---------------------------------------------------------------------------


class TestEndiannessAndNetworkConditional:
    """Memory cites: W93 check_bip30 network-gating, W87 previousblockhash
    LE/BE swap, W81 pre-CSV BIP-113 misuse, W69 txid byte-order LE→BE.
    Spot-check the AcceptBlock path for the same class of regression.
    """

    def test_block_hash_computed_internal_byte_order(self):
        """``handle_block`` computes the block hash as
        ``dsha256(payload[:80])`` directly (block_sync.py:829-831),
        keeping it in internal byte order — matches DB / accept_block.
        W87 cited a previousblockhash LE/BE swap; this guard pins the
        ordering."""
        import inspect
        from ouroboros.block_sync import BlockSync
        src = inspect.getsource(BlockSync.handle_block)
        # Collapse whitespace + newlines so the cross-line dsha256 form
        # is matched: ``hashlib.sha256(hashlib.sha256(payload[:80]).digest())``.
        flat = " ".join(src.split())
        assert "hashlib.sha256( hashlib.sha256(payload[:80]).digest() )".replace(" ", "") \
            in flat.replace(" ", ""), (
                "handle_block must compute block_hash via dsha256(payload[:80]) "
                "without byte-order reversal — W87 endianness regression guard"
            )
        # The block_hash assignment line itself must not reverse bytes.
        assign_line = src.split("block_hash = ")[1].split("\n")[0]
        assert "[::-1]" not in assign_line

    def test_bip30_per_network_enforcement_present(self):
        """W93 found check_bip30 early-returned on testnet4/signet/regtest.
        The Python validator (validation.py:733-758) enforces BIP-30
        per-network, checking BIP34Hash all-zeros to keep enforcement on
        non-mainnet."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator.validate_block)
        assert "BIP34Hash" in src or "bip34_canon_hash" in src
        assert "bytes(32)" in src  # all-zeros sentinel for non-mainnet

    def test_pre_csv_block_113_uses_block_time_not_mtp(self):
        """W81 cited pre-CSV BIP-113 misuse (MTP applied before
        activation).  validation.py:671-672 picks ``block_mtp`` if CSV
        active, else ``block.timestamp`` — correct."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator.validate_block)
        assert "csv_active = is_buried_deployment_active" in src
        assert "nLockTimeCutoff: int = block_mtp if csv_active else block.timestamp" in src

    def test_signet_solution_gated_on_network(self):
        """Signet block-signature verification fires only on signet
        (validation.py:1531-1532).  Spot-check the network gate is
        present so a regression won't run signet code on mainnet."""
        import inspect
        from ouroboros.validation import BlockValidator
        src = inspect.getsource(BlockValidator._validate_signet_solution)
        assert 'self.network != "signet"' in src
