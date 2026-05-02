"""Unit tests for the BIP34 slot-alignment guard added in block_sync.

Background: a `dumptxoutset` rollback at mainnet height 935001 disconnected
938231..938348 from the active chain but left their block records (and
BLOCK_INDEX_CF entries) in place.  After restart, ``handle_headers`` saw the
orphaned block hashes via ``db.has_block_hash`` and "skipped" them while
advancing ``expected_prev`` along the OLD chain.  The next freshly-validated
header at height 938349 was then appended to slot 0 of
``_validated_headers``, even though slot 0 logically corresponds to the next
block after our actual chain tip (938231).  Block download dutifully fetched
hash_938349 for slot 0, but the validator (running with ``known_height=tip+1
= 938231``) found the BIP34 height encoded in the coinbase scriptSig was
938349, rejected the block as "Invalid coinbase", and wedged forever on the
same slot.

The fix has two parts, both exercised here:

1. ``handle_headers`` no longer skips on ``db.has_block_hash`` — that probe
   does not distinguish active-chain hashes from disconnected-but-stored
   hashes, so it cannot be used to advance the slot pointer.  Headers must
   chain-connect through ``prev_blockhash`` instead.
2. ``_drain_block_buffer_locked`` runs a BIP34 height-vs-slot sanity check
   AFTER deserialisation but BEFORE validation.  On mismatch, the validated
   header queue and IBD buffer are dropped (queue is corrupt) and a fresh
   header sync is triggered.  The block hash is NOT marked permanently
   rejected — its bytes are canonical mainnet data, just at the wrong slot.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def _coinbase_scriptsig(height: int) -> bytes:
    """Produce a CScriptNum-encoded BIP34 coinbase scriptSig for *height*."""
    if height == 0:
        return bytes([0x00, 0x00])  # OP_0, then pad byte (sig_len >= 2)
    # Determine smallest LE byte length.
    encoded = height.to_bytes(4, "little").rstrip(b"\x00")
    if not encoded:
        encoded = b"\x00"
    # If the high bit of the most-significant byte is set, prepend 0x00 to
    # avoid sign-bit ambiguity in CScriptNum.  Real coinbases do this; we
    # do it here too so the test scripts mirror live mainnet bytes.
    if encoded[-1] & 0x80:
        encoded = encoded + b"\x00"
    return bytes([len(encoded)]) + encoded + b"\x00"  # trailing pad to sig_len>=2


def _make_block_with_bip34_height(height: int):
    """Synthesize a minimal block-shaped object whose coinbase encodes
    BIP34 height *height*.  Only the attributes the slot-alignment guard
    reads are populated."""
    coinbase_input = MagicMock()
    coinbase_input.script_sig = _coinbase_scriptsig(height)
    coinbase = MagicMock()
    coinbase.inputs = [coinbase_input]
    block = MagicMock()
    block.transactions = [coinbase]
    return block


# ---------------------------------------------------------------------------
# _decode_bip34_height
# ---------------------------------------------------------------------------


def test_decode_bip34_height_short_height():
    """A typical post-BIP34, pre-height-65536 coinbase: push_size=2."""
    sig = bytes([0x02, 0x05, 0x57])  # height = 0x5705 = 22277
    assert BlockSync._decode_bip34_height(sig) == 22277


def test_decode_bip34_height_three_byte_push():
    """Mainnet block 938349 uses push_size=3 — replicate that exactly."""
    sig = bytes.fromhex("036d510e")  # 0x0e516d == 938349
    assert BlockSync._decode_bip34_height(sig) == 938349


def test_decode_bip34_height_rejects_invalid_push_size():
    assert BlockSync._decode_bip34_height(bytes([0x00, 0xff])) is None
    assert BlockSync._decode_bip34_height(bytes([0x05, 1, 2, 3, 4, 5])) is None


def test_decode_bip34_height_rejects_truncated():
    """push_size says 4 bytes follow but only 2 actually do."""
    assert BlockSync._decode_bip34_height(bytes([0x04, 0x01, 0x02])) is None


def test_decode_bip34_height_too_short_scriptsig():
    """BIP34 push needs at least one push-size byte and one data byte."""
    assert BlockSync._decode_bip34_height(b"") is None
    assert BlockSync._decode_bip34_height(b"\x01") is None


# ---------------------------------------------------------------------------
# _coinbase_height_mismatch
# ---------------------------------------------------------------------------


def test_coinbase_height_mismatch_below_bip34_returns_false():
    """Below BIP34 activation, no encoded height to check — never a mismatch."""
    bs = _make_block_sync()
    block = _make_block_with_bip34_height(123_456)  # encoded value irrelevant
    assert bs._coinbase_height_mismatch(block, expected_height=200_000) is False


def test_coinbase_height_mismatch_matching_height():
    bs = _make_block_sync()
    block = _make_block_with_bip34_height(800_000)
    assert bs._coinbase_height_mismatch(block, expected_height=800_000) is False


def test_coinbase_height_mismatch_938231_vs_938349():
    """Reproduce the exact wedge: block 938349 delivered for slot 938231."""
    bs = _make_block_sync()
    block = _make_block_with_bip34_height(938_349)
    assert bs._coinbase_height_mismatch(block, expected_height=938_231) is True


def test_coinbase_height_mismatch_undecodable_sig_returns_false():
    """If the scriptSig isn't BIP34-decodable (push_size=0 or out of range),
    the validator handles it — the slot-alignment guard stays out of the way."""
    bs = _make_block_sync()
    block = MagicMock()
    coinbase_input = MagicMock()
    coinbase_input.script_sig = bytes([0x00, 0xff])  # push_size=0
    coinbase = MagicMock()
    coinbase.inputs = [coinbase_input]
    block.transactions = [coinbase]
    assert bs._coinbase_height_mismatch(block, expected_height=800_000) is False


def test_coinbase_height_mismatch_handles_missing_attributes():
    """A malformed block-like object must not raise — return False."""
    bs = _make_block_sync()
    block = MagicMock()
    block.transactions = []  # no coinbase
    assert bs._coinbase_height_mismatch(block, expected_height=800_000) is False


# ---------------------------------------------------------------------------
# _handle_misaligned_block — the recovery path
# ---------------------------------------------------------------------------


def test_handle_misaligned_block_clears_queue_and_buffer():
    bs = _make_block_sync()
    bs._validated_headers = [(b"\xab" * 32, MagicMock()), (b"\xcd" * 32, MagicMock())]
    bs._ibd_block_buffer = {b"\xab" * 32: (None, b"x"), b"\xcd" * 32: (None, b"y")}
    bs.requested_blocks = {b"\xab" * 32: 1.0, b"\xee" * 32: 2.0}
    bs._block_request_peer = {b"\xab" * 32: MagicMock()}
    bs._header_sync_peer = MagicMock()
    bs._header_sync_time = 12345.0

    block = _make_block_with_bip34_height(938_349)
    bs._handle_misaligned_block(b"\xab" * 32, expected_height=938_231, block=block)

    assert bs._validated_headers == []
    assert bs._ibd_block_buffer == {}
    assert bs.requested_blocks == {}
    assert bs._block_request_peer == {}
    assert bs._header_sync_peer is None
    assert bs._header_sync_time == 0.0


def test_handle_misaligned_block_does_not_perm_reject():
    """The block is canonical mainnet data delivered at the wrong slot;
    perm-rejecting it would discard valid future redeliveries once the
    queue is rebuilt correctly."""
    bs = _make_block_sync()
    block_hash = b"\x42" * 32
    block = _make_block_with_bip34_height(938_349)
    bs._handle_misaligned_block(block_hash, expected_height=938_231, block=block)
    assert block_hash not in bs._perm_rejected_blocks
    assert bs._blk_perm_rejected_dropped == 0


# ---------------------------------------------------------------------------
# handle_headers — has_block_hash skip is gone
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_headers_does_not_skip_orphaned_db_hashes(monkeypatch):
    """Reproduces the live wedge: after a rollback, 938231..938348 are still
    in BLOCKS_CF (so ``has_block_hash`` returns True) but disconnected from
    the active chain.  An incoming headers batch starting at 938231 with
    OLD-chain prev links must NOT auto-accept those headers via the skip:
    the chain-prev check must enforce that the first header connects to
    our actual tip (best_hash).  In the wedge scenario, the OLD chain's
    938231 has prev = best_hash (the fork point), so it WOULD chain-connect
    — but the post-fix code accepts it as a one-element extension at slot 0
    instead of skipping 118 orphaned hashes and slotting 938349 there."""
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage

    bs = _make_block_sync()
    # Tip = block 938230; old chain hashes 938231..938348 are still in
    # BLOCKS_CF after the rollback, so has_block_hash returns True for
    # ALL of them.  Active chain has tip at 938230.
    tip_hash = bytes.fromhex("01" * 32)
    bs.db.get_best_block.return_value = (tip_hash, 938_230)
    bs.db.has_block_hash.return_value = True  # the orphaned-but-stored case

    # Build a single header that connects to our tip (so chain-prev check
    # passes) but encodes a different block.
    h0 = BlockHeader(
        version=1,
        prev_blockhash=tip_hash,
        merkle_root=b"\xaa" * 32,
        timestamp=1_700_000_000,
        bits=0x1d00ffff,
        nonce=0,
    )
    headers_msg = HeadersMessage(headers=[h0])

    # peer + msg shells
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333
    bs.peer_manager.network = "mainnet"
    bs._header_sync_peer = peer

    # Stub _request_next_blocks so we don't try to drive peer state.
    async def _noop():
        return None
    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # Critical: exactly ONE header was appended.  Prior to the fix,
    # has_block_hash=True would have caused the FIRST header to be
    # "skipped" as already-known and expected_prev to be advanced to its
    # hash, even though the header should have been queued at slot 0.
    # With the fix, has_block_hash is ignored and the chain-prev gate
    # accepts h0 normally.
    assert len(bs._validated_headers) == 1
    assert bs._validated_headers[0][0] == bs._header_to_block_hash(h0)


# ---------------------------------------------------------------------------
# _queue_anchored_to_tip + handle_block accepting requested redeliveries
# ---------------------------------------------------------------------------


def test_queue_anchored_to_tip_empty_queue():
    """An empty queue is vacuously anchored — the drain has nothing to do."""
    bs = _make_block_sync()
    assert bs._queue_anchored_to_tip() is True


def test_queue_anchored_to_tip_matching_prev():
    """Slot 0's prev_blockhash matches the active tip — anchored."""
    bs = _make_block_sync()
    tip_hash = bytes.fromhex("aa" * 32)
    bs.db.get_best_block.return_value = (tip_hash, 938_230)

    hdr = MagicMock()
    hdr.prev_blockhash = tip_hash
    bs._validated_headers = [(b"\xbb" * 32, hdr)]
    assert bs._queue_anchored_to_tip() is True


def test_queue_anchored_to_tip_stale_after_rollback():
    """After a rollback the queue's slot 0 still extends the OLD tip; the
    anchor probe must report False so the caller drops the queue."""
    bs = _make_block_sync()
    new_tip = bytes.fromhex("11" * 32)  # post-rollback tip
    old_tip = bytes.fromhex("22" * 32)  # pre-rollback tip the queue extends
    bs.db.get_best_block.return_value = (new_tip, 938_230)

    hdr = MagicMock()
    hdr.prev_blockhash = old_tip
    bs._validated_headers = [(b"\xcc" * 32, hdr)]
    assert bs._queue_anchored_to_tip() is False


@pytest.mark.asyncio
async def test_handle_block_accepts_requested_redelivery_post_rollback():
    """After a chainstate rollback, BLOCKS_CF still contains the bytes for
    blocks above the new tip.  A peer redelivering block N (which IS the
    block we just requested at slot 0) must NOT be dropped on the
    `has_block_hash=True` duplicate path — its bytes need to land in the
    IBD buffer so the drain can re-validate and re-connect them.

    Pre-fix, every redelivery for an orphan-tagged block was discarded as
    a duplicate; the drain then waited forever for a buffer entry that
    never arrived.
    """
    import hashlib

    bs = _make_block_sync()
    # The block hash is in BLOCKS_CF (post-rollback orphan) but it IS
    # something we asked for via requested_blocks.
    header = b"\xee" * 80
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    bs.db.has_block_hash = MagicMock(return_value=True)
    bs.requested_blocks[block_hash] = 1.0

    msg = MagicMock()
    msg.payload = header
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333

    await bs.handle_block(msg, peer)

    # Solicited delivery: bytes ended up in the IBD buffer despite
    # has_block_hash=True.
    assert block_hash in bs._ibd_block_buffer
    # in-flight cleared.
    assert block_hash not in bs.requested_blocks


@pytest.mark.asyncio
async def test_handle_block_drops_unsolicited_duplicate():
    """If a peer spontaneously delivers a block we already have AND did
    not request, drop it (no in-flight tracking, no buffer churn)."""
    import hashlib

    bs = _make_block_sync()
    header = b"\xff" * 80
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    bs.db.has_block_hash = MagicMock(return_value=True)
    # NOT in requested_blocks — unsolicited.

    msg = MagicMock()
    msg.payload = header
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333

    await bs.handle_block(msg, peer)

    assert block_hash not in bs._ibd_block_buffer
    assert bs._blk_duplicate >= 1


@pytest.mark.asyncio
async def test_handle_headers_breaks_on_chain_disconnect(monkeypatch):
    """If the very first header's prev does not match our tip, drop the
    whole batch.  This is the safety net that the deleted has_block_hash
    skip was inadvertently bypassing — with that skip, an orphaned hash
    chain could "advance" expected_prev without a single chain-prev check."""
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage

    bs = _make_block_sync()
    tip_hash = bytes.fromhex("01" * 32)
    other_hash = bytes.fromhex("02" * 32)
    bs.db.get_best_block.return_value = (tip_hash, 938_230)
    bs.db.has_block_hash.return_value = True  # would have masked the bug pre-fix

    # First header's prev is OTHER_HASH, not our tip.  The pre-fix code's
    # has_block_hash skip would have advanced expected_prev to the orphaned
    # block's hash and accepted the next header silently.  Post-fix, the
    # chain-connect check fires and the batch is rejected.
    h0 = BlockHeader(
        version=1,
        prev_blockhash=other_hash,
        merkle_root=b"\xaa" * 32,
        timestamp=1_700_000_000,
        bits=0x1d00ffff,
        nonce=0,
    )
    headers_msg = HeadersMessage(headers=[h0])

    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333
    bs.peer_manager.network = "mainnet"

    async def _noop():
        return None
    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)
    assert bs._validated_headers == []
