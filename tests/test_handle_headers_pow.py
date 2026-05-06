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
