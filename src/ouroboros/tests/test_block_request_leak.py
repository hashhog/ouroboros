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


class TestHeaderBackfillWiring(unittest.IsolatedAsyncioTestCase):
    """block_sync must arm the #52 backfill and route below-floor headers to it.

    Without the routing these headers are ~950k below the active tip, so the
    normal connect path classifies them as unconnecting and drops them — the
    backfill would never receive a single header.
    """

    def _sync_with_floor(self, floor: int, tip_height: int):
        from ouroboros.header_backfill import GENESIS_HASHES

        bs, peers = _fresh_block_sync()
        anchor = _dsha(b"anchor-at-floor")
        tip = _dsha(b"tip")

        class FloorDB(_StubDB):
            def get_best_block(self_inner):
                return tip, tip_height

            def get_block_hash_by_height(self_inner, height):
                if height < floor:
                    return None          # snapshot-loaded: no rows below base
                if height == floor:
                    return anchor
                return _dsha(b"h%d" % height)

        bs.db = FloorDB(tip, tip_height)
        bs.db.written = []
        bs.db.store_block_metadata_persistent = (
            lambda h, bh, cw, ts: bs.db.written.append((h, bh, cw, ts))
        )
        return bs, peers, anchor, GENESIS_HASHES["mainnet"]

    async def test_arms_when_the_index_has_a_gap(self):
        bs, peers, anchor, _ = self._sync_with_floor(floor=4, tip_height=20)
        await bs._maybe_start_header_backfill()
        self.assertIsNotNone(bs._header_backfill)
        self.assertEqual(bs._header_backfill.start_height, 0)
        self.assertEqual(bs._header_backfill.end_height, 4)
        self.assertEqual(bs._header_backfill.anchor_hash, anchor)

    async def test_arms_on_a_MID_CHAIN_gap_the_live_shape(self):
        """0..107 present, 108..944183 absent, 944184..tip present.

        This is the shape the live mainnet node actually has, and the shape the
        original find_index_floor could not see: it probes height 0, finds
        genesis, returns 0, and reports nothing to backfill.
        """
        bs, peers = _fresh_block_sync()
        low = {h: _dsha(b"lo%d" % h) for h in range(0, 108)}
        high = {h: _dsha(b"hi%d" % h) for h in range(944184, 964055)}

        class GappyDB(_StubDB):
            def get_best_block(self_inner):
                return high[964054], 964054

            def get_block_hash_by_height(self_inner, height):
                return low.get(height) or high.get(height)

        bs.db = GappyDB(high[964054], 964054)
        await bs._maybe_start_header_backfill()
        self.assertIsNotNone(bs._header_backfill, "must arm on a mid-chain gap")
        self.assertEqual(bs._header_backfill.start_height, 108)
        self.assertEqual(bs._header_backfill.end_height, 944184)
        # Lower pin is the block at 107; upper pin is the block at 944184.
        self.assertEqual(bs._header_backfill.prev_anchor, low[107])
        self.assertEqual(bs._header_backfill.anchor_hash, high[944184])
        # And the walk resumes from the block below the gap, not from genesis.
        self.assertEqual(bs._header_backfill.start_locator(), [low[107]])

    async def test_does_not_arm_when_the_index_reaches_genesis(self):
        bs, peers, _, _ = self._sync_with_floor(floor=0, tip_height=20)
        await bs._maybe_start_header_backfill()
        self.assertIsNone(bs._header_backfill)
        self.assertTrue(bs._backfill_done)  # latched: no repeated probing

    async def test_routes_below_floor_headers_and_commits_at_the_anchor(self):
        from ouroboros.header_backfill import block_hash as bh
        import ouroboros.tests.test_header_backfill as thb

        # A real genesis + 3 synthetic headers; the 4th links to the anchor.
        tail, anchor = thb.make_chain(bh(thb.MAINNET_GENESIS_HEADER), 3)
        headers = [thb.MAINNET_GENESIS_HEADER] + tail

        bs, peers, _, _ = self._sync_with_floor(floor=4, tip_height=20)
        # The driver takes its genesis anchor from peer_manager.network; this
        # fixture serves the real MAINNET genesis, so the manager must agree.
        # (The stub defaults to regtest, which correctly made wants() decline.)
        bs.peer_manager.network = "mainnet"
        bs.db.get_block_hash_by_height = (
            lambda height: None if height < 4 else (anchor if height == 4 else _dsha(b"x"))
        )
        await bs._maybe_start_header_backfill()
        self.assertIsNotNone(bs._header_backfill)
        bs._header_backfill.anchor_hash = anchor

        # Disable PoW for synthetic headers; the anchor check still applies.
        orig_commit = bs._header_backfill.commit
        bs._header_backfill.commit = lambda db, **kw: orig_commit(db, check_pow=False)

        consumed = await bs._consume_backfill_headers(headers, peers[0])
        self.assertTrue(consumed, "below-floor batch must be routed to the backfill")
        self.assertEqual([row[0] for row in bs.db.written], [0, 1, 2, 3])
        self.assertTrue(bs._backfill_done)
        self.assertIsNone(bs._header_backfill)

    async def test_ordinary_sync_batch_is_not_swallowed(self):
        """An unrelated batch arriving mid-backfill must fall through."""
        bs, peers, _, _ = self._sync_with_floor(floor=4, tip_height=20)
        await bs._maybe_start_header_backfill()
        self.assertIsNotNone(bs._header_backfill)
        unrelated = [
            b"\x01\x00\x00\x00" + b"\x99" * 32 + bytes(32)
            + (1234).to_bytes(4, "little") + (0x207FFFFF).to_bytes(4, "little")
            + bytes(4)
        ]
        consumed = await bs._consume_backfill_headers(unrelated, peers[0])
        self.assertFalse(consumed, "ordinary sync headers must not be consumed")
        self.assertEqual(bs.db.written, [])
