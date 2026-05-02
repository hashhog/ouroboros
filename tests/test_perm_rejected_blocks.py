"""Unit tests for the _perm_rejected_blocks set.

Background: the recurring "Invalid coinbase" rejection at mainnet block
938231 produced no perm-reject memory, so peer redeliveries forced a fresh
deserialize / validate cycle on every reception.  The set added in this
wave breaks that loop: hashes of blocks whose validation deterministically
failed (anything except "Previous block not found", which is transient
ordering) are tracked, and ``handle_block`` drops redeliveries before they
ever hit the buffer or the validator.

These tests exercise the bookkeeping helper and the dedup behaviour in
isolation, without spinning up the real validator + DB stack.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def test_init_state_is_empty():
    bs = _make_block_sync()
    assert bs._perm_rejected_blocks == set()
    assert bs._perm_rejected_order == []
    assert bs._perm_rejected_max == 10000
    assert bs._blk_perm_rejected_dropped == 0


def test_mark_perm_rejected_adds_hash():
    bs = _make_block_sync()
    h = b"\x01" * 32
    bs._mark_perm_rejected(h)
    assert h in bs._perm_rejected_blocks
    assert bs._perm_rejected_order == [h]


def test_mark_perm_rejected_is_idempotent():
    """Re-adding an already-tracked hash does not append it twice."""
    bs = _make_block_sync()
    h = b"\x01" * 32
    bs._mark_perm_rejected(h)
    bs._mark_perm_rejected(h)
    bs._mark_perm_rejected(h)
    assert bs._perm_rejected_blocks == {h}
    assert bs._perm_rejected_order == [h]


def test_perm_rejected_set_evicts_oldest_at_capacity():
    """When the set is full, adding a new hash drops the FIFO-oldest one."""
    bs = _make_block_sync()
    bs._perm_rejected_max = 3  # tight cap for the test

    h1 = b"\x01" * 32
    h2 = b"\x02" * 32
    h3 = b"\x03" * 32
    h4 = b"\x04" * 32

    bs._mark_perm_rejected(h1)
    bs._mark_perm_rejected(h2)
    bs._mark_perm_rejected(h3)
    assert bs._perm_rejected_order == [h1, h2, h3]
    assert bs._perm_rejected_blocks == {h1, h2, h3}

    bs._mark_perm_rejected(h4)
    # h1 was the FIFO-oldest, so it gets evicted.
    assert bs._perm_rejected_order == [h2, h3, h4]
    assert bs._perm_rejected_blocks == {h2, h3, h4}


@pytest.mark.asyncio
async def test_handle_block_drops_perm_rejected_redelivery():
    """A peer redelivering a perm-rejected block hash should not re-buffer.

    The buffer must remain empty and the drop counter must increment.
    """
    bs = _make_block_sync()
    bs.db.has_block_hash = MagicMock(return_value=False)

    # Fabricate an 80-byte header whose double-sha256 we can pre-compute.
    import hashlib

    header = b"\xab" * 80
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    # Mark the hash as permanently rejected.
    bs._mark_perm_rejected(block_hash)
    assert block_hash in bs._perm_rejected_blocks

    # Synthesize a NetworkMessage-like object + a Peer-like object with
    # the attributes handle_block reaches for.  We don't need a real
    # network stack — the perm-reject branch returns early, well before
    # any drain or peer lookup.
    msg = MagicMock()
    msg.payload = header  # exactly 80 bytes; size guard passes
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333

    await bs.handle_block(msg, peer)

    # Block was NOT buffered.
    assert block_hash not in bs._ibd_block_buffer
    # Counter incremented.
    assert bs._blk_perm_rejected_dropped == 1
    # Peer score was docked.
    peer.adjust_score.assert_called_once_with(-5)


def test_perm_rejected_dedup_counter_persists_across_repeated_calls():
    """Repeated drops increment _blk_perm_rejected_dropped, not the set size."""
    bs = _make_block_sync()
    bs.db.has_block_hash = MagicMock(return_value=False)

    import hashlib

    header = b"\xcd" * 80
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    bs._mark_perm_rejected(block_hash)

    msg = MagicMock()
    msg.payload = header
    peer = MagicMock()
    peer.host = "127.0.0.1"
    peer.port = 8333

    async def _drive():
        for _ in range(5):
            await bs.handle_block(msg, peer)

    asyncio.run(_drive())

    assert bs._blk_perm_rejected_dropped == 5
    assert len(bs._perm_rejected_blocks) == 1
    assert bs._ibd_block_buffer == {}
