"""Regression tests for the at-tip block-request RSS leak.

Root cause (2026-06-02/03 mainnet OOMs at chain tip, mempool=0): peers at tip
announce stale / fork / competing block hashes via ``inv``.  BlockSync.handle_inv
requested each one and recorded it in ``requested_blocks`` + ``_block_request_peer``
+ ``_w77_first_request_time``, but those announces never become part of our active
chain, so they never reach the ``handle_block`` -> connect path that pops them.
``_handle_timeouts`` re-requested them forever (only the no-peers branch dropped
entries) and ``_w77_first_request_time`` was never touched by the timeout path at
all, so every unique never-connecting requested hash leaked one entry in each of
the three maps without bound.  ``_block_request_peer`` holds live Peer references,
so a leaked entry also pinned a zombie Peer (transport buffers, BIP-324 state).

The fix bounds all of these:
  * handle_inv honours the global in-flight cap + skips perm-rejected hashes
  * _w77_first_request_time is FIFO-capped (W77_FIRST_REQUEST_MAX_ENTRIES)
  * _handle_timeouts counts attempts and permanently abandons (perm-rejects +
    drops from every in-flight map) off-active-chain blocks past
    BLOCK_REQUEST_MAX_ATTEMPTS
  * _mark_perm_rejected drops the hash from every in-flight map
"""

import asyncio
import hashlib
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import (  # noqa: E402
    BlockSync,
    BLOCK_REQUEST_MAX_ATTEMPTS,
    W77_FIRST_REQUEST_MAX_ENTRIES,
)
import ouroboros.block_sync as bsmod  # noqa: E402
from ouroboros.p2p_messages import InvMessage, INV_TYPE_BLOCK, NODE_WITNESS  # noqa: E402
from ouroboros.peer import Peer, PeerState  # noqa: E402


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class _StubDB:
    """A DB pinned at a stable tip (models a node sitting at chain tip)."""

    def __init__(self, tip: bytes, height: int):
        self._tip = tip
        self._h = height
        self._have = {tip}

    def get_best_block(self):
        return self._tip, self._h

    def has_block_hash(self, h):
        return h in self._have

    def get_block_hash_by_height(self, height):
        return self._tip if height == self._h else None


class _StubPeerManager:
    network = "regtest"

    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return self._peers

    def misbehaving(self, *a, **k):
        return False


def _make_peer(i: int) -> Peer:
    p = Peer("10.0.0.%d" % i, 18444, network="regtest")
    p.state = PeerState.READY  # is_connected() -> True
    # Block-download peers must advertise NODE_WITNESS (ouroboros requests
    # MSG_WITNESS_BLOCK; block_sync now filters candidates to witness-capable
    # peers, Core CanServeWitnesses parity).
    p.services = NODE_WITNESS
    p.adjust_score = lambda d: None  # keep peers in the ready set (no ban churn)

    async def _send(_msg):
        return None

    p.send_message = _send
    return p


def _fresh_block_sync(n_peers=5):
    tip = _dsha(b"tip")
    db = _StubDB(tip, 952_076)
    peers = [_make_peer(i) for i in range(1, n_peers + 1)]
    pm = _StubPeerManager(peers)
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=db, validator=None, peer_manager=pm, mempool=None)
    return bs, peers


class TestBlockRequestLeak(unittest.IsolatedAsyncioTestCase):
    async def test_handle_inv_request_maps_capped_by_in_flight(self):
        """A flood of distinct unknown-block INVs cannot push the in-flight
        request maps past the in-flight cap."""
        bs, peers = _fresh_block_sync()
        cap = bs._max_blocks_in_flight
        for i in range(cap * 20):  # 20x the cap
            h = _dsha(b"blk" + i.to_bytes(8, "little"))
            inv = InvMessage([(INV_TYPE_BLOCK, h)]).to_network_message("regtest")
            await bs.handle_inv(inv, peers[i % len(peers)])

        self.assertLessEqual(len(bs.requested_blocks), cap)
        self.assertLessEqual(len(bs._block_request_peer), cap)
        self.assertLessEqual(len(bs._w77_first_request_time), cap)

    async def test_timeouts_abandon_never_connecting_blocks(self):
        """Off-active-chain blocks re-requested past BLOCK_REQUEST_MAX_ATTEMPTS
        are permanently abandoned: dropped from every in-flight map and
        perm-rejected (so they cannot re-open the slot)."""
        bs, peers = _fresh_block_sync()
        for i in range(5):
            h = _dsha(b"stuck" + i.to_bytes(8, "little"))
            inv = InvMessage([(INV_TYPE_BLOCK, h)]).to_network_message("regtest")
            await bs.handle_inv(inv, peers[i])
        self.assertEqual(len(bs.requested_blocks), 5)

        real_time = bsmod.time.time
        base = real_time()
        tick = [0]
        bsmod.time.time = lambda: base + tick[0] * 100_000.0
        try:
            for _ in range(BLOCK_REQUEST_MAX_ATTEMPTS + 2):
                tick[0] += 1
                await bs._handle_timeouts()
        finally:
            bsmod.time.time = real_time

        self.assertEqual(len(bs.requested_blocks), 0)
        self.assertEqual(len(bs._block_request_peer), 0)
        self.assertEqual(len(bs._w77_first_request_time), 0)
        self.assertEqual(len(bs._block_request_attempts), 0)
        self.assertEqual(len(bs._perm_rejected_blocks), 5)

    async def test_perm_reject_drops_in_flight_request_state(self):
        """_mark_perm_rejected clears the per-hash in-flight bookkeeping that
        the connect path would otherwise have popped."""
        bs, peers = _fresh_block_sync()
        h = _dsha(b"bad")
        inv = InvMessage([(INV_TYPE_BLOCK, h)]).to_network_message("regtest")
        await bs.handle_inv(inv, peers[0])
        self.assertIn(h, bs.requested_blocks)
        self.assertIn(h, bs._w77_first_request_time)

        bs._mark_perm_rejected(h)

        self.assertNotIn(h, bs.requested_blocks)
        self.assertNotIn(h, bs._block_request_peer)
        self.assertNotIn(h, bs._w77_first_request_time)
        self.assertNotIn(h, bs._block_request_attempts)
        self.assertIn(h, bs._perm_rejected_blocks)

    async def test_w77_first_request_time_hard_capped(self):
        """The telemetry latency map can never exceed its FIFO cap even if a
        huge number of distinct blocks are recorded directly."""
        bs, _ = _fresh_block_sync()
        now = 1_700_000_000.0
        for i in range(W77_FIRST_REQUEST_MAX_ENTRIES + 5_000):
            bs._record_first_request_time(
                _dsha(b"h" + i.to_bytes(8, "little")), now + i
            )
        self.assertLessEqual(
            len(bs._w77_first_request_time), W77_FIRST_REQUEST_MAX_ENTRIES
        )
        self.assertEqual(
            len(bs._w77_first_request_order), len(bs._w77_first_request_time)
        )


if __name__ == "__main__":
    asyncio.set_event_loop_policy(None)
    unittest.main()


class TestLocatorWalkBounded(unittest.IsolatedAsyncioTestCase):
    """`_build_locator` must stay O(log height) even with a SPARSE index.

    Core doubles the locator step on vHave.size() (chain.cpp:34), and that is
    equivalent to counting steps there because Core's block index is complete —
    every probe appends. Ouroboros's index is not always complete: right after a
    `loadtxoutset` the BLOCK_INDEX_CF has no rows for snapshot-loaded heights,
    so every probe returns None, the locator never reaches 10 entries, and
    gating the doubling on len(locator) left `step` at 1 forever — a walk over
    EVERY height from the tip to genesis, rebuilt once a second during IBD.

    Measured before the fix on a 952,076-height stub: ~950k probes per locator,
    98.35 ms per handle_inv. After: 0.011 ms.
    """

    async def test_sparse_index_does_not_walk_the_whole_chain(self):
        bs, peers = _fresh_block_sync()
        probes = []
        real = bs.db.get_block_hash_by_height

        def counting(height):
            probes.append(height)
            return real(height)

        bs.db.get_block_hash_by_height = counting
        locator = bs._build_locator(bs.db._h)

        # The stub answers only at the tip, so this is the fully-sparse case.
        self.assertLessEqual(
            len(probes), 250,
            f"locator walked {len(probes)} heights on a sparse index — the "
            f"step doubling is not engaging",
        )
        # Still produces a usable tip-anchored locator.
        self.assertGreaterEqual(len(locator), 1)
        self.assertEqual(locator[0], bs.db._tip)

    async def test_dense_index_still_spaces_exponentially(self):
        """With a complete index the walk is short AND well spaced."""
        bs, peers = _fresh_block_sync()
        tip_h = bs.db._h
        dense = {h: _dsha(b"h%d" % h) for h in range(tip_h - 3000, tip_h + 1)}
        bs.db.get_block_hash_by_height = lambda h: dense.get(h)
        locator = bs._build_locator(tip_h)
        # ~10 single steps then doubling => far fewer than 3000 entries.
        self.assertLess(len(locator), 60)
        self.assertGreater(len(locator), 5)
