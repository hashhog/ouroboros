"""Per-header PoW gate + Rust HeadersSyncState wiring in ``handle_headers``.

Background: ``ouroboros/src/ouroboros/block_sync.py:handle_headers`` previously
only checked chain continuity (``header.prev_blockhash == expected_prev``) and
appended every connecting header to ``self._validated_headers`` (capped at
50,000).  A peer could craft headers with valid ``bits`` + correct
``prev_blockhash`` chaining but garbage ``nonce`` (so the resulting hash
trivially exceeded the target) and flood our queue cheaply.

Fix (2026-05-06): a per-header PoW gate now requires
``double-SHA256(header) <= target(bits)`` before append, and the freshly-
accepted headers are also fed into the Rust ``PyHeadersSyncState`` for
commitment-tracking / cumulative-work accounting.

Reference: CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part2.md
RED finding #1; Bitcoin Core ``src/pow.cpp`` ``CheckProofOfWork``,
``src/headerssync.cpp`` ``HeadersSyncState``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import BlockHeader, HeadersMessage


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_block_sync(tip_hash: bytes = b"\x00" * 32, tip_height: int = 0) -> BlockSync:
    """Build a ``BlockSync`` with a stubbed db / validator / peer manager.

    The peer manager exposes the ``misbehaving`` hook so the test can
    assert that bad-PoW peers are escalated.
    """
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.has_block_hash.return_value = False
    db.get_median_time_past.return_value = 1_700_000_000

    peer_manager = MagicMock()
    peer_manager.network = "mainnet"
    peer_manager.misbehaving = MagicMock()

    return BlockSync(db=db, validator=MagicMock(), peer_manager=peer_manager)


def _make_peer(host: str = "127.0.0.1", port: int = 8333):
    peer = MagicMock()
    peer.host = host
    peer.port = port
    peer.adjust_score = MagicMock()
    peer.is_connected = MagicMock(return_value=True)

    async def _send_message(*_args, **_kwargs):
        return None

    peer.send_message = MagicMock(side_effect=_send_message)
    return peer


# ---------------------------------------------------------------------------
# _bits_to_target / _header_meets_pow unit tests
# ---------------------------------------------------------------------------


def test_bits_to_target_known_values():
    """Compact 'bits' decoding must match Bitcoin Core arith_uint256::SetCompact."""
    # Mainnet starting difficulty (bits=0x1d00ffff)
    assert BlockSync._bits_to_target(0x1D00FFFF) == 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    # Regtest min-difficulty (bits=0x207fffff) — the largest legal target.
    assert BlockSync._bits_to_target(0x207FFFFF) == 0x7FFFFF0000000000000000000000000000000000000000000000000000000000
    # Mantissa zero ⇒ target zero.
    assert BlockSync._bits_to_target(0x20000000) == 0


def test_header_meets_pow_accepts_known_valid_block_one():
    """Bitcoin mainnet block #1 has a valid PoW relative to bits=0x1d00ffff.

    Values from public chain data (https://blockstream.info/block/<height>/1)::

        version       = 1
        prev_blockhash= genesis (display: 000000000019d6689c085ae...)
        merkle_root   = 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f...
        timestamp     = 1231469665
        bits          = 0x1d00ffff
        nonce         = 2573394689

    Both prev_blockhash and merkle_root are stored in the header as
    little-endian (Bitcoin internal byte order).
    """
    prev_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    h = BlockHeader(
        version=1,
        prev_blockhash=prev_be[::-1],
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )
    assert BlockSync._header_meets_pow(h) is True


def test_header_meets_pow_rejects_bogus_nonce():
    """A header with valid bits=0x1d00ffff but nonce=0 (and otherwise
    plausible fields) almost certainly hashes ABOVE the target.
    """
    h = BlockHeader(
        version=1,
        prev_blockhash=b"\xaa" * 32,
        merkle_root=b"\xbb" * 32,
        timestamp=1_700_000_000,
        bits=0x1D00FFFF,
        nonce=0,
    )
    assert BlockSync._header_meets_pow(h) is False


def test_header_meets_pow_rejects_zero_target():
    """bits with zero mantissa decode to target=0 (no hash can meet it)."""
    h = BlockHeader(
        version=1,
        prev_blockhash=b"\x00" * 32,
        merkle_root=b"\x00" * 32,
        timestamp=0,
        bits=0x20000000,  # mantissa = 0 ⇒ target = 0
        nonce=0,
    )
    assert BlockSync._header_meets_pow(h) is False


# ---------------------------------------------------------------------------
# handle_headers integration: bad-PoW headers are rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_headers_rejects_bad_pow_header(monkeypatch):
    """A connecting header whose hash exceeds the claimed target is rejected
    BEFORE being appended to ``_validated_headers``.

    Pre-fix (2026-05-06): the loop ran chain-prev validation only; this
    header would be appended.  Post-fix: the per-header PoW gate fires,
    the batch is dropped, the peer's score is decremented, and
    ``misbehaving`` is escalated.
    """
    tip_hash = b"\x11" * 32
    bs = _make_block_sync(tip_hash=tip_hash, tip_height=100)

    # Connecting header with mainnet bits but nonce=0 — virtually
    # guaranteed to hash above 0x1d00ffff's target.
    bad = BlockHeader(
        version=1,
        prev_blockhash=tip_hash,
        merkle_root=b"\xcc" * 32,
        timestamp=1_700_000_000,
        bits=0x1D00FFFF,
        nonce=0,
    )
    # Sanity: the helper agrees.
    assert BlockSync._header_meets_pow(bad) is False

    headers_msg = HeadersMessage(headers=[bad])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # The bad header MUST NOT have been appended.
    assert bs._validated_headers == []
    # The PoW-rejection counter is incremented.
    assert bs._headers_pow_rejected == 1
    # The peer is misbehaving-flagged with score=100 (Bitcoin Core's
    # ``Misbehaving`` cap).
    peer.adjust_score.assert_called_with(-20)
    bs.peer_manager.misbehaving.assert_called_once()
    args, _kw = bs.peer_manager.misbehaving.call_args
    assert args[0] == "127.0.0.1:8333"
    assert args[1] == 100
    assert "PoW" in args[2]


@pytest.mark.asyncio
async def test_handle_headers_does_not_request_more_after_pow_failure(monkeypatch):
    """After a PoW failure mid-batch, ``handle_headers`` must NOT trigger
    block-download requests (no headers were actually validated).
    """
    tip_hash = b"\x22" * 32
    bs = _make_block_sync(tip_hash=tip_hash, tip_height=200)

    bad = BlockHeader(
        version=1,
        prev_blockhash=tip_hash,
        merkle_root=b"\xdd" * 32,
        timestamp=1_700_000_000,
        bits=0x1D00FFFF,
        nonce=0,
    )

    headers_msg = HeadersMessage(headers=[bad])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    request_calls = {"n": 0}

    async def _spy():
        request_calls["n"] += 1

    monkeypatch.setattr(bs, "_request_next_blocks", _spy)

    await bs.handle_headers(msg, peer)

    assert request_calls["n"] == 0, "block download must not be triggered after PoW failure"


# ---------------------------------------------------------------------------
# handle_headers integration: valid-PoW path still works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_headers_accepts_valid_pow_header(monkeypatch):
    """A header with a hash that genuinely meets its target (Bitcoin block #1)
    is appended to ``_validated_headers`` and triggers block download.
    """
    # Set the tip to genesis (block #1's prev) so chain-prev passes.
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    block1 = BlockHeader(
        version=1,
        prev_blockhash=genesis_le,
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )
    # Sanity: the helper agrees.
    assert BlockSync._header_meets_pow(block1) is True

    headers_msg = HeadersMessage(headers=[block1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # The valid header was appended.  ``HeadersMessage.from_payload``
    # round-trips through serialize/deserialize so we compare by value
    # (equal dataclass) rather than identity.
    assert len(bs._validated_headers) == 1
    appended_hash, appended_header = bs._validated_headers[0]
    assert appended_header == block1
    assert appended_hash == bs._header_to_block_hash(block1)
    # PoW counter unchanged (no rejections).
    assert bs._headers_pow_rejected == 0
    # No misbehaving escalation for a good peer.
    bs.peer_manager.misbehaving.assert_not_called()


@pytest.mark.asyncio
async def test_handle_headers_rejects_bad_pow_in_middle_of_batch(monkeypatch):
    """A batch containing a valid header followed by a bad-PoW header
    must reject the whole batch as soon as the bad header is hit.

    Pre-fix this would have appended both (continuity-only).  Post-fix
    we early-return on the PoW failure and the queue is left in a
    consistent state.
    """
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    good = BlockHeader(
        version=1,
        prev_blockhash=genesis_le,
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )
    good_hash = bs._header_to_block_hash(good)

    # Second header chain-connects to the first but has bad PoW.
    bad = BlockHeader(
        version=1,
        prev_blockhash=good_hash,
        merkle_root=b"\xee" * 32,
        timestamp=1_231_469_700,
        bits=0x1D00FFFF,
        nonce=0,
    )
    assert BlockSync._header_meets_pow(bad) is False

    headers_msg = HeadersMessage(headers=[good, bad])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # Only the good header was appended; the bad one triggered an
    # early return.  Compare by value (HeadersMessage round-trips).
    assert len(bs._validated_headers) == 1
    assert bs._validated_headers[0][1] == good
    assert bs._headers_pow_rejected == 1


# ---------------------------------------------------------------------------
# Core-parity unconnecting-headers counter (Pattern B closure)
# ---------------------------------------------------------------------------
#
# Per CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
# (Pattern B), the per-peer unconnecting-headers counter must tolerate up
# to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10 successive unlinked batches
# before misbehavior-scoring the peer.  Mirrors Bitcoin Core's
# nUnconnectingHeaders accounting in
# net_processing.cpp::ProcessHeadersMessage.  Pre-fix, ouroboros silently
# `break`ed the per-header loop on the first orphan with no penalty —
# a malicious peer could keep us in an infinite getheaders loop.


def test_unconnecting_headers_counter_under_threshold():
    """10 successive .note_unconnecting_headers() calls must NOT exceed."""
    bs = _make_block_sync()
    peer = _make_peer()
    for i in range(1, 11):
        exceeded = bs._note_unconnecting_headers(peer)
        assert not exceeded, f"call #{i} should not yet exceed threshold"
        assert bs._unconnecting_headers_count_for(peer) == i


def test_unconnecting_headers_counter_exceeds_threshold():
    """11th call must signal exceeded (caller bans the peer)."""
    bs = _make_block_sync()
    peer = _make_peer()
    for _ in range(10):
        assert not bs._note_unconnecting_headers(peer)
    assert bs._note_unconnecting_headers(peer)


def test_unconnecting_headers_reset_clears_count():
    """_reset_unconnecting_headers wipes the per-peer entry."""
    bs = _make_block_sync()
    peer = _make_peer()
    for _ in range(5):
        bs._note_unconnecting_headers(peer)
    assert bs._unconnecting_headers_count_for(peer) == 5
    bs._reset_unconnecting_headers(peer)
    assert bs._unconnecting_headers_count_for(peer) == 0
    # Subsequent unconnecting starts fresh.
    bs._note_unconnecting_headers(peer)
    assert bs._unconnecting_headers_count_for(peer) == 1


def test_unconnecting_headers_per_peer_independent():
    """Each (host, port) tuple gets its own counter."""
    bs = _make_block_sync()
    peer_a = _make_peer(host="1.2.3.4", port=8333)
    peer_b = _make_peer(host="5.6.7.8", port=8333)
    for _ in range(10):
        bs._note_unconnecting_headers(peer_a)
    assert bs._unconnecting_headers_count_for(peer_a) == 10
    assert bs._unconnecting_headers_count_for(peer_b) == 0
    # Peer B's first note does NOT trip the threshold.
    assert not bs._note_unconnecting_headers(peer_b)
    # Peer A's 11th note trips.
    assert bs._note_unconnecting_headers(peer_a)


# ---------------------------------------------------------------------------
# G8 — nMinimumChainWork gate (total-chain-work, not header-window-only)
# ---------------------------------------------------------------------------
#
# Regression for the mainnet stall at h=948464 (2026-05-19).  The G8 gate
# in handle_headers (min_pow_checked=False path) compared
# nMinimumChainWork against the cumulative work of ONLY the in-flight
# `_validated_headers` queue — a few thousand recent headers.  Past
# genesis that sum is always far below nMinimumChainWork, so EVERY raw
# P2P headers batch was rejected `too-little-chainwork`, the serving peer
# was banned, and the node could never advance its tip.
#
# Bitcoin Core (net_processing.cpp::TryLowWorkHeadersSync) computes
#     total_work = chain_start_header.nChainWork
#                  + CalculateClaimedHeadersWork(headers)
# i.e. the work of the block the headers fork FROM plus the new headers.
# The fix adds that base term: the cumulative chain work already stored
# at our DB tip (the block the `_validated_headers` queue connects to).

import sync as _sync_for_test  # noqa: E402  module-level import is fine here

_MIN_CHAIN_WORK_MAINNET = int(
    _sync_for_test.get_minimum_chain_work("mainnet"), 16
)


def _real_block_one():
    """Bitcoin mainnet block #1 header — has genuinely valid PoW.

    Reused from the PoW tests above.  Its single-block work is ~2**32
    (bits=0x1d00ffff), which is *vastly* below nMinimumChainWork — so a
    one-header batch only passes the G8 gate when the DB-tip base term is
    counted.
    """
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    return BlockHeader(
        version=1,
        prev_blockhash=genesis_be[::-1],
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )


@pytest.mark.asyncio
async def test_g8_accepts_batch_when_db_tip_chainwork_above_minimum(monkeypatch):
    """A short, low-work header batch extending a deep chain is ACCEPTED.

    This is the exact mainnet-stall scenario: the node is past genesis
    with a DB-tip chain work already well above nMinimumChainWork, and a
    peer sends a small batch of fresh headers.  The G8 gate must count
    the DB-tip work as the base and let the batch through.

    Pre-fix: rejected (`too-little-chainwork`) — the base term was
    omitted, so only the ~2**32 work of block #1 was measured.
    """
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    # DB tip already carries MORE work than nMinimumChainWork — mirrors a
    # node deep into the chain (live node at h=948464 had chainwork
    # 0x125fa2f56... vs nMinimumChainWork 0x1128750f8...).
    #
    # get_chainwork_by_height is also probed by the snapshot-offset
    # detector at snap_h+1 (944184 on mainnet).  Returning a very large
    # value there (>= the snapshot's own chainwork) models a CORRECTLY
    # built datadir whose snapshot base was applied, so the detector
    # returns a zero offset and this test isolates the plain DB-tip base
    # term.  The DB tip itself is at height 0 (genesis) in this fixture.
    db_tip_chainwork = _MIN_CHAIN_WORK_MAINNET + (1 << 80)

    def _chainwork_by_height(height: int) -> int:
        # snap_h+1 probe: report ample work → snapshot base already applied.
        if height >= 944_184:
            return 1 << 120
        return db_tip_chainwork

    bs.db.get_chainwork_by_height = MagicMock(side_effect=_chainwork_by_height)

    block1 = _real_block_one()
    assert BlockSync._header_meets_pow(block1) is True

    headers_msg = HeadersMessage(headers=[block1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    # Isolate the G8 gate from the presync defense-in-depth layer.
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)

    # min_pow_checked=False → the raw-P2P G8 gate runs.
    await bs.handle_headers(msg, peer, min_pow_checked=False)

    # The header passed the gate and was appended.
    assert len(bs._validated_headers) == 1
    assert bs._validated_headers[0][1] == block1
    # No too-little-chainwork rejection.
    assert bs._headers_pow_rejected == 0
    bs.peer_manager.misbehaving.assert_not_called()
    # The DB-tip chainwork was actually consulted (the fix's base term).
    # assert_any_call (not assert_called_with): the snapshot-offset
    # detector also probes get_chainwork_by_height at snap_h+1, so the
    # height-0 base read is not necessarily the final call.
    bs.db.get_chainwork_by_height.assert_any_call(0)


@pytest.mark.asyncio
async def test_g8_rejects_batch_when_total_work_below_minimum(monkeypatch):
    """A low-work batch forking a zero-work base is REJECTED.

    When the base chain work is 0 (e.g. genuinely syncing from genesis)
    and the header batch alone does not reach nMinimumChainWork, the G8
    gate must still reject — proving the gate is real, not disabled by
    the fix.
    """
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    # Base chain work 0 — the batch must stand on its own work (~2**32),
    # which is far below nMinimumChainWork.
    bs.db.get_chainwork_by_height = MagicMock(return_value=0)

    block1 = _real_block_one()
    headers_msg = HeadersMessage(headers=[block1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)

    await bs.handle_headers(msg, peer, min_pow_checked=False)

    # The batch was rolled back — too-little-chainwork.
    assert bs._validated_headers == []
    assert bs._headers_pow_rejected == 1
    bs.peer_manager.misbehaving.assert_called_once()
    args, _kw = bs.peer_manager.misbehaving.call_args
    assert args[2] == "too-little-chainwork"


@pytest.mark.asyncio
async def test_g8_skipped_when_min_pow_checked_true(monkeypatch):
    """The G8 gate is bypassed for trusted / presync-cleared batches.

    With min_pow_checked=True the cumulative-work check must not run, so
    even a tiny batch off a zero-work base is accepted.  This guards the
    Core-parity contract: G8 is the anti-DoS gate for *raw* P2P headers
    only (validation.cpp:4229).
    """
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)
    bs.db.get_chainwork_by_height = MagicMock(return_value=0)

    block1 = _real_block_one()
    headers_msg = HeadersMessage(headers=[block1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)

    # Default min_pow_checked=True → G8 skipped.
    await bs.handle_headers(msg, peer)

    assert len(bs._validated_headers) == 1
    assert bs._headers_pow_rejected == 0
    bs.peer_manager.misbehaving.assert_not_called()


@pytest.mark.asyncio
async def test_g8_applies_snapshot_offset_for_corrupt_datadir(monkeypatch):
    """G8 un-bricks an assumeUTXO datadir whose snapshot base was dropped.

    Incident (2026-05-19): a mainnet node bootstrapped from the h=944183
    assumeUTXO snapshot never persisted the snapshot block's chainwork, so
    every post-snapshot block accumulated work from 0.  ``get_chainwork_by_
    height`` then returned a DB-tip base ~32x too small, and the G8 gate
    rejected EVERY honest headers batch with ``too-little-chainwork``.

    The G8 gate now adds ``detect_snapshot_chainwork_offset``'s correction:
    the snapshot height's canonical chainwork.  With it, the corrected
    base + headers clears nMinimumChainWork and the batch is accepted.
    """
    from ouroboros.snapshot import get_assumeutxo_data

    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    genesis_le = genesis_be[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    au = get_assumeutxo_data("mainnet", 944_183)
    assert au is not None and au.chainwork_hex is not None
    snapshot_chainwork = int(au.chainwork_hex, 16)

    # Model the corrupt datadir: the stored DB-tip base is far below
    # nMinimumChainWork (post-snapshot blocks accumulated from 0).  The
    # snapshot-offset detector probes snap_h+1 and also sees a tiny value,
    # so it returns the snapshot's canonical chainwork as the offset.
    # Derive `tiny_base` relative to nMinimumChainWork so the test holds
    # whether the real Rust constant or a conftest stub value is in play;
    # the snapshot chainwork (h=944183) always far exceeds nMinimumChainWork.
    tiny_base = _MIN_CHAIN_WORK_MAINNET // 32  # ~the incident's ~32x deficit

    def _chainwork_by_height(height: int) -> int:
        return tiny_base

    bs.db.get_chainwork_by_height = MagicMock(side_effect=_chainwork_by_height)
    # Pre-fix sanity: the raw base alone could never clear the gate.
    assert tiny_base < _MIN_CHAIN_WORK_MAINNET
    # Post-fix: base + snapshot offset comfortably exceeds the minimum.
    assert snapshot_chainwork > _MIN_CHAIN_WORK_MAINNET
    assert tiny_base + snapshot_chainwork > _MIN_CHAIN_WORK_MAINNET

    block1 = _real_block_one()
    headers_msg = HeadersMessage(headers=[block1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)

    await bs.handle_headers(msg, peer, min_pow_checked=False)

    # The batch passed G8 — the snapshot offset rescued the corrupt base.
    assert len(bs._validated_headers) == 1
    assert bs._headers_pow_rejected == 0
    bs.peer_manager.misbehaving.assert_not_called()
    # The snapshot-offset detector probed snap_h+1 (944184).
    bs.db.get_chainwork_by_height.assert_any_call(944_184)
