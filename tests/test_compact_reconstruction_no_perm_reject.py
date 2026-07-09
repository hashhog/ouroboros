"""At-tip block-download wedge: a failed BIP152 compact-block reconstruction
must NOT permanently reject the block hash.

Background (live mainnet, 2026-07-09): ouroboros repeatedly froze at the tip,
stuck re-requesting the next block from peer after peer for ~30+ min until a
restart.  Root cause: at the tip blocks arrive mostly as BIP152 compact
blocks.  A reconstruction that produced validate-failing bytes — a 6-byte
short-id collision substituting the wrong mempool tx, or (the smoking gun) a
fallback getdata that fetched the block WITHOUT the witness flag
(INV_TYPE_BLOCK instead of MSG_WITNESS_BLOCK) so it failed the
witness-commitment check — routed through the drain's validation-failure
branch and called ``_mark_perm_rejected(real_hash)``.  Once the real hash was
poisoned, every later *honest* full-block delivery of that block was dropped
at ``handle_block``'s ``_perm_rejected_blocks`` gate, and the head-of-window
request loop (which never abandons head blocks) re-fetched it forever.  The
in-memory perm-reject set only cleared on restart.

Bitcoin Core treats a ``PartiallyDownloadedBlock`` / ``FillBlock`` failure as
"reconstruction failed -> request the full block" (net_processing.cpp), never
as permanent block invalidity.  The fix mirrors that: bytes tagged as
compact-reconstruction origin (``_compact_origin_hashes``) that fail
validation are dropped + re-requested as a full witness block, and the hash is
NOT added to ``_perm_rejected_blocks``.  A genuinely solicited *full* block
that fails validation is still perm-rejected as before.

These tests drive the real ``_drain_block_buffer_locked`` with the Rust
validator disabled (``OUROBOROS_DISABLE_RUST_VALIDATE=1``) so validation is the
mockable Python path, and assert the origin-dependent routing.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync


def _make_block_sync() -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def _stage_next_block(bs: BlockSync, block_hash: bytes) -> None:
    """Place *block_hash* as tip+1: anchored queue slot 0 + a buffered,
    already-deserialized block object.  new_height == 1 is below BIP34, so the
    coinbase height-vs-slot guard is a no-op and the drain proceeds straight to
    validation."""
    tip_hash, _ = bs.db.get_best_block.return_value
    hdr = MagicMock()
    hdr.prev_blockhash = tip_hash  # anchors slot 0 to the active tip
    bs._validated_headers = [(block_hash, hdr)]

    # A block-shaped object whose coinbase encodes no checkable BIP34 height
    # (height 1 < BIP34 activation) so _coinbase_height_mismatch returns False.
    coinbase_input = MagicMock()
    coinbase_input.script_sig = bytes([0x00, 0x00])
    coinbase = MagicMock()
    coinbase.inputs = [coinbase_input]
    block = MagicMock()
    block.transactions = [coinbase]

    bs._ibd_block_buffer[block_hash] = (block, b"\x00" * 80)
    bs.requested_blocks[block_hash] = 1.0


@pytest.mark.asyncio
async def test_compact_origin_validation_failure_is_not_perm_rejected(monkeypatch):
    """The wedge fix: a compact-reconstructed block that fails validation is
    dropped + re-requestable, NOT poisoned.  Pre-fix this hash was
    perm-rejected and the tip froze until restart."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _make_block_sync()
    block_hash = b"\x11" * 32
    _stage_next_block(bs, block_hash)
    # Reconstruction failure surfaces as a non-transient validation error.
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Invalid merkle root")
    )
    # Tagged as compact-block reconstruction origin (node.py handler does this).
    bs._compact_origin_hashes.add(block_hash)

    await bs._drain_block_buffer_locked()

    # NOT poisoned — the honest full-block redelivery will be accepted.
    assert block_hash not in bs._perm_rejected_blocks
    assert bs._blk_perm_rejected_dropped == 0
    # Request tracking cleared so the head-of-window loop re-requests the FULL
    # witness block immediately.
    assert block_hash not in bs.requested_blocks
    # Origin tag consumed (no leak).
    assert block_hash not in bs._compact_origin_hashes


@pytest.mark.asyncio
async def test_full_block_validation_failure_is_still_perm_rejected(monkeypatch):
    """Control: a solicited *full* block (not compact origin) that fails
    validation is still perm-rejected — the fix narrows the perm-reject to
    genuine full-block failures, it does not disable it."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _make_block_sync()
    block_hash = b"\x22" * 32
    _stage_next_block(bs, block_hash)
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Invalid merkle root")
    )
    # NOT in _compact_origin_hashes — this came from a full-block getdata.

    await bs._drain_block_buffer_locked()

    assert block_hash in bs._perm_rejected_blocks


@pytest.mark.asyncio
async def test_transient_error_rebuffers_regardless_of_origin(monkeypatch):
    """The pre-existing "Previous block not found" transient-ordering path is
    unchanged: the block is re-buffered, never perm-rejected, for both
    origins."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _make_block_sync()
    block_hash = b"\x33" * 32
    _stage_next_block(bs, block_hash)
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Previous block not found")
    )
    bs._compact_origin_hashes.add(block_hash)

    await bs._drain_block_buffer_locked()

    assert block_hash not in bs._perm_rejected_blocks
    # Re-buffered for the next drain attempt.
    assert block_hash in bs._ibd_block_buffer
