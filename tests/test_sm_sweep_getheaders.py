"""sm-sweep-ouroboros D1: getheaders ignores the locator's height.

``_make_getheaders_handler`` (node.py) computes
``start_height = (block.height if block.height else 0) + 1`` from
``db.get_block_header``, which always carries ``height=None``
(database.py ``get_block_header``).  So every matched locator serves from
height 1: a peer at our tip gets 2000 headers it already has instead of an
empty reply, and nobody can header-sync past height 2000 from us.

Core: net_processing.cpp ProcessMessage(GETHEADERS) ->
``FindForkInGlobalIndex(m_chainman.ActiveChain(), locator)`` then
``ActiveChain().Next(pindex)``.

Fixed by sm-fix-ouroboros-getheaders-locator: the handler resolves the
locator's height from the hash index and accepts it only when the active
chain holds that hash at that height.
"""

from __future__ import annotations

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests._f0_chain import BASE_TIME, build_block, coinbase_tx  # noqa: E402

from tests.test_getheaders_header_only import (  # noqa: E402
    TIP,
    _headers_payload,
    _request,
    _stored_headers,
    served,  # noqa: F401  (fixture)
)

@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def test_sm_sweep_getheaders_tip_locator_serves_nothing(served):  # noqa: F811
    """A peer whose locator is our tip already has every header."""
    _, real, handler, peer = served
    payload = _request(handler, peer, [real.get_block_hash_by_height(TIP)])
    assert payload == _headers_payload([]), "tip locator must get an empty headers reply"


def test_sm_sweep_getheaders_mid_locator_serves_after_fork(served):  # noqa: F811
    """Locator at height 5 -> headers 6..TIP, not 1..TIP."""
    _, real, handler, peer = served
    payload = _request(handler, peer, [real.get_block_hash_by_height(5)])
    assert payload == _headers_payload(_stored_headers(real, range(6, TIP + 1)))


def _fork_last_two(real) -> tuple[bytes, bytes]:
    """Reorg TIP-1..TIP onto a sibling branch; return the displaced (old)
    TIP-1 and TIP hashes, which stay in the hash index off the active chain."""
    old = (real.get_block_hash_by_height(TIP - 1), real.get_block_hash_by_height(TIP))
    real._db.disconnect_block(TIP)
    real._db.disconnect_block(TIP - 1)
    prev = real.get_block_hash_by_height(TIP - 2)
    for height in (TIP - 1, TIP):
        cb = coinbase_tx(height, tag=b"\x03K" + height.to_bytes(2, "little"))
        raw, bh = build_block(prev, BASE_TIME + height * 600 + 7, [cb])
        real._db.connect_block_from_bytes(raw, height, "regtest")
        prev = bh
    assert real.get_best_block() == (prev, TIP)
    for h, displaced in zip((TIP - 1, TIP), old):
        assert real.get_block_hash_by_height(h) != displaced
        assert real.get_block_height_by_hash(displaced) == h, "fixture: displaced block left the hash index"
    return old


def test_sm_sweep_getheaders_fork_locator_is_skipped(served):  # noqa: F811
    """Core FindForkInGlobalIndex only accepts a locator entry the active
    chain contains: a displaced TIP block is skipped and the next entry
    (height 5) is the fork point."""
    _, real, handler, peer = served
    _, old_tip = _fork_last_two(real)
    payload = _request(handler, peer, [old_tip, real.get_block_hash_by_height(5)])
    assert payload == _headers_payload(_stored_headers(real, range(6, TIP + 1)))


def test_sm_sweep_getheaders_fork_only_locator_serves_from_one(served):  # noqa: F811
    """A locator holding only off-chain blocks matches nothing, so Core
    falls back to genesis and serves from height 1 on the ACTIVE chain."""
    _, real, handler, peer = served
    old = _fork_last_two(real)
    payload = _request(handler, peer, list(reversed(old)))
    assert payload == _headers_payload(_stored_headers(real, range(1, TIP + 1)))
