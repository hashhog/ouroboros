"""sm-sweep-ouroboros, path (a) sync / IBD modes.

A1  ``BlockSync._handle_timeouts`` counts an attempt for every timed-out
    request and, for any hash outside the first HEAD_OF_WINDOW (8)
    unconnected headers, calls ``_mark_perm_rejected`` once attempts exceed
    BLOCK_REQUEST_MAX_ATTEMPTS (10) (block_sync.py, "PERMANENTLY ABANDON").
    The comment assumes non-head timeouts are only off-chain inv announces,
    but during IBD / catch-up every queued header from slot 9 up to the
    1024-block window is "general".  A valid block of the header chain we
    are downloading is then perm-rejected: ``handle_block`` drops it on
    redelivery and docks the sender -5, and the drain waits on that slot
    forever; the watchdog recovery does not clear ``_perm_rejected_blocks``.
    Core never marks a block failed for a download timeout: a stall only
    disconnects the peer (net_processing.cpp ``SendMessages``
    BLOCK_STALLING_TIMEOUT / BLOCK_DOWNLOAD_TIMEOUT_BASE) and the block is
    re-requested from another peer via ``FindNextBlocksToDownload``.

xfail(strict=True) until sm-fix-ouroboros-timeout-perm-reject lands.
"""

from __future__ import annotations

import pytest

from ouroboros.block_sync import BLOCK_REQUEST_MAX_ATTEMPTS
from tests.test_campaign_hol_cap_wedge import _assign, _fresh, _peer, _queue


async def _timed_out_queue_slot(slot: int):
    peer = _peer()
    bs = _fresh([peer])
    hashes = _queue(bs, 40)  # the validated header chain being downloaded
    target = hashes[slot]
    _assign(bs, peer, [target], age_s=10_000)  # far past any timeout
    bs._block_request_attempts[target] = BLOCK_REQUEST_MAX_ATTEMPTS
    await bs._handle_timeouts()
    return bs, target


@pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros A1: download timeouts perm-reject a queued "
    "header-chain block outside the 8-slot head window",
)
@pytest.mark.asyncio
async def test_sm_sweep_timed_out_queued_chain_block_is_not_perm_rejected():
    bs, target = await _timed_out_queue_slot(20)
    assert target not in bs._perm_rejected_blocks, (
        "a block on the validated header chain was permanently rejected "
        "for timing out; its redelivery will be dropped and the drain wedges"
    )


@pytest.mark.asyncio
async def test_sm_sweep_control_head_window_block_is_not_perm_rejected():
    """Control: the same timeout on a head-of-window slot is exempt."""
    bs, target = await _timed_out_queue_slot(2)
    assert target not in bs._perm_rejected_blocks
    assert bs._block_request_attempts[target] == BLOCK_REQUEST_MAX_ATTEMPTS + 1
