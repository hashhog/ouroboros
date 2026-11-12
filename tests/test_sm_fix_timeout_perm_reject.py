"""sm-fix-ouroboros-timeout-perm-reject.

``BlockSync._handle_timeouts`` used to call ``_mark_perm_rejected`` on any
general-timeout hash (outside the 8-slot head window) once it exceeded
BLOCK_REQUEST_MAX_ATTEMPTS.  During IBD / catch-up that includes valid
blocks of the validated header chain being downloaded (slots 9..window):
``handle_block`` then dropped their redelivery, docked the peer -5, and
the drain waited on that slot forever.

Core never marks a block failed for a download timeout
(net_processing.cpp ``SendMessages`` stall / download timeouts only
disconnect the peer; ``FindNextBlocksToDownload`` re-requests the block).

The fix: a queued header-chain block keeps being re-requested; only a hash
that is NOT in ``_validated_headers`` (an off-chain inv announce) is
abandoned, and abandoning drops it from the in-flight maps (the at-tip
leak fix) without perm-rejecting it.
"""

from __future__ import annotations

import pytest

from ouroboros.block_sync import BLOCK_REQUEST_MAX_ATTEMPTS
from tests.test_campaign_hol_cap_wedge import _assign, _fresh, _h, _peer, _queue


def _over_limit(bs, peer, target):
    _assign(bs, peer, [target], age_s=10_000)  # far past any timeout
    bs._block_request_attempts[target] = BLOCK_REQUEST_MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_timed_out_queued_chain_block_keeps_being_requested():
    """A header-chain block past the attempt limit stays wanted: it is
    neither perm-rejected nor dropped from the in-flight bookkeeping, so
    a later delivery still counts as requested and reaches the drain."""
    peer = _peer()
    bs = _fresh([peer])
    hashes = _queue(bs, 40)
    target = hashes[20]
    _over_limit(bs, peer, target)

    await bs._handle_timeouts()

    assert target not in bs._perm_rejected_blocks
    assert target not in bs._failed_blocks
    assert target in bs.requested_blocks, (
        "the header-chain block was dropped from the in-flight maps"
    )
    assert bs._block_request_attempts.get(target) == BLOCK_REQUEST_MAX_ATTEMPTS + 1


@pytest.mark.asyncio
async def test_timed_out_queued_chain_block_survives_repeated_timeouts():
    """Many more timeout passes do not turn the queued block into a give-up."""
    peer = _peer()
    bs = _fresh([peer])
    hashes = _queue(bs, 40)
    target = hashes[30]
    for _ in range(BLOCK_REQUEST_MAX_ATTEMPTS + 5):
        _assign(bs, peer, [target], age_s=10_000)
        await bs._handle_timeouts()
    assert target not in bs._perm_rejected_blocks
    assert target in bs.requested_blocks


@pytest.mark.asyncio
async def test_off_chain_announce_is_still_dropped_from_inflight_maps():
    """At-tip leak fix kept: an announced hash with no queued header that
    no peer delivers is dropped from every in-flight map after the limit.
    It is a give-up, not a verdict, so it is not perm-rejected either."""
    peer = _peer()
    bs = _fresh([peer])
    _queue(bs, 40)
    off_chain = _h(10_000)  # not in the validated-header queue
    _over_limit(bs, peer, off_chain)

    await bs._handle_timeouts()

    assert off_chain not in bs.requested_blocks
    assert off_chain not in bs._block_request_peer
    assert off_chain not in bs._w77_first_request_time
    assert off_chain not in bs._block_request_attempts
    assert off_chain not in bs._perm_rejected_blocks
    assert off_chain not in bs._failed_blocks


@pytest.mark.asyncio
async def test_off_chain_announce_under_limit_is_not_abandoned():
    """Control: below the limit the off-chain hash is still retried."""
    peer = _peer()
    bs = _fresh([peer])
    _queue(bs, 40)
    off_chain = _h(10_001)
    _assign(bs, peer, [off_chain], age_s=10_000)
    bs._block_request_attempts[off_chain] = BLOCK_REQUEST_MAX_ATTEMPTS - 1

    await bs._handle_timeouts()

    assert off_chain in bs.requested_blocks
    assert bs._block_request_attempts[off_chain] == BLOCK_REQUEST_MAX_ATTEMPTS
