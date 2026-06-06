"""
Regression tests for header-sync peer selection on the LIVE best-known height.

Finding: ``_get_sync_peer`` / ``_get_peer_with_highest_block`` filtered/ranked
peers on ``Peer.start_height`` — a ONE-TIME snapshot captured from the peer's
``version`` handshake (peer.py _inbound_handshake / _handshake) and never
refreshed.  This is the lunarblock stale-start_height pattern: a peer that was
level with us at connect, then advanced its chain past us, keeps a frozen
``start_height`` so ``start_height > our_height`` stays False — the peer is
never picked and header sync can starve even though that peer has new blocks.

Fix (Core CNodeState::pindexBestKnownBlock, net_processing.cpp:441 +
UpdateBlockAvailability/ProcessBlockAvailability): track a live, monotonic
``Peer.best_known_height`` advanced whenever the peer reveals a higher tip
(headers / inv / block), and select on that.

The first two tests prove the starvation case the frozen snapshot caused; they
also assert the underlying ``_peer_known_height`` helper prefers the live
value, which is what the pre-fix code (selecting on ``p.start_height``) did
NOT do.
"""

from __future__ import annotations

import types

from ouroboros.block_sync import BlockSync
from ouroboros.peer import Peer, PeerState


def _make_peer(start_height: int) -> Peer:
    p = Peer("127.0.0.1", 8333, "regtest")
    p.start_height = start_height
    # note_block_height seeds best_known_height at handshake; replicate that so
    # the test peer starts in the same state a real handshake leaves it in.
    p.note_block_height(start_height)
    p.state = PeerState.READY
    return p


class _FakePeerManager:
    def __init__(self, peers):
        self._peers = list(peers)

    def get_all_ready_peers(self):
        return list(self._peers)


def _make_block_sync(peers) -> BlockSync:
    # BlockSync.__init__ only stores db/validator/peer_manager; the selector
    # methods touch only peer_manager.  Pass lightweight stand-ins.
    return BlockSync(
        db=types.SimpleNamespace(),
        validator=types.SimpleNamespace(),
        peer_manager=_FakePeerManager(peers),
    )


def test_note_block_height_is_monotonic():
    p = Peer("127.0.0.1", 8333, "regtest")
    assert p.best_known_height == 0
    p.note_block_height(100)
    assert p.best_known_height == 100
    p.note_block_height(50)  # lower — ignored
    assert p.best_known_height == 100
    p.note_block_height(150)  # higher — advances
    assert p.best_known_height == 150
    p.note_block_height(None)  # garbage — ignored
    assert p.best_known_height == 150


def test_peer_known_height_prefers_live_value_over_frozen_snapshot():
    p = _make_peer(start_height=500)
    # Peer advanced its chain to 900 at runtime (revealed via headers/inv).
    p.note_block_height(900)
    # The live value wins; start_height stays frozen at the handshake snapshot.
    assert p.start_height == 500
    assert p.best_known_height == 900
    assert BlockSync._peer_known_height(p) == 900


def test_stale_start_height_no_longer_starves_sync_peer_selection():
    """The core starvation case.

    Peer handshook at height 800 when we were also at ~800 (start_height=800).
    Both then advanced: the peer is now at 1000, we are at 850.  The frozen
    snapshot (800) is BELOW our height (850), so the pre-fix selector
    (``p.start_height > our_height``) would reject this peer and return None —
    starving sync.  With the live best-known height (1000 > 850) it is picked.
    """
    peer = _make_peer(start_height=800)
    peer.note_block_height(1000)  # peer revealed a height-1000 tip at runtime

    bs = _make_block_sync([peer])
    our_height = 850

    # Guard: the pre-fix predicate would have starved here.
    assert peer.start_height <= our_height, "guard: frozen snapshot is stale"

    chosen = bs._get_sync_peer(our_height)
    assert chosen is peer, "live best-known height must keep the peer eligible"


def test_get_sync_peer_still_excludes_genuinely_behind_peer():
    """A peer truly behind us (live height included) must NOT be selected."""
    behind = _make_peer(start_height=400)
    behind.note_block_height(820)  # still below our height
    ahead = _make_peer(start_height=900)
    ahead.note_block_height(1000)

    bs = _make_block_sync([behind, ahead])
    chosen = bs._get_sync_peer(our_height=850)
    assert chosen is ahead


def test_highest_block_peer_ranks_on_live_height():
    """``_get_peer_with_highest_block`` ranks on best-known, not start_height."""
    # p_low handshook high (start 950) but never advanced.
    p_low = _make_peer(start_height=950)
    # p_high handshook lower (start 600) but advanced past everyone at runtime.
    p_high = _make_peer(start_height=600)
    p_high.note_block_height(1200)

    bs = _make_block_sync([p_low, p_high])
    chosen = bs._get_peer_with_highest_block()
    # Pre-fix (rank by start_height) would have picked p_low (950 > 600).
    assert chosen is p_high
    assert BlockSync._peer_known_height(p_high) == 1200
    assert BlockSync._peer_known_height(p_low) == 950
