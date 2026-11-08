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

xfail(strict=True) until the fix item (sm-fix-ouroboros-getheaders-locator)
lands; the fix removes the marker.
"""

from __future__ import annotations

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests.test_getheaders_header_only import (  # noqa: E402
    TIP,
    _headers_payload,
    _request,
    _stored_headers,
    served,  # noqa: F401  (fixture)
)

pytestmark = pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros D1: getheaders serves from height 1 for any "
    "matched locator (node.py _make_getheaders_handler)",
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
