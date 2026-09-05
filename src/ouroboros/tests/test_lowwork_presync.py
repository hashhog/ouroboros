"""Regression tests for the low-work headers PRESYNC continuation.

THE WEDGE
---------
``handle_headers``' G8 gate refuses to commit a header batch whose total chain
work is below ``nMinimumChainWork``.  That is correct — it is Bitcoin Core's
anti-DoS bar — but the pre-fix code then *stopped*: it rolled the batch back
and returned.  A node whose chain is legitimately below the bar (a from-genesis
IBD, or a datadir bootstrapped from an assumeUTXO snapshot whose base is far
below the tip) therefore re-requested the SAME 2000 headers every sync tick
forever and never advanced a single block.

Core does not stop.  ``TryLowWorkHeadersSync`` (net_processing.cpp:2765) opens a
``HeadersSyncState``, stores nothing, and keeps asking the same peer for the
next batch until cumulative claimed work crosses the threshold; only then are
the headers re-requested and committed.  These tests pin that continuation.
"""

import hashlib
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import BlockHeader  # noqa: E402
from ouroboros.peer import Peer, PeerState  # noqa: E402

REGTEST_BITS = 0x207FFFFF


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _bits_to_target(bits: int) -> int:
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF
    if mantissa == 0:
        return 0
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


_REGTEST_TARGET = _bits_to_target(REGTEST_BITS)


def _mine(prev_hash: bytes, tag: int, bits: int = REGTEST_BITS) -> BlockHeader:
    """A header whose double-SHA256 actually meets *bits* (regtest powLimit
    rejects ~half of random hashes, so this is a real, tiny search)."""
    for bump in range(1 << 20):
        h = BlockHeader(
            version=1,
            prev_blockhash=prev_hash,
            merkle_root=_dsha(b"mr" + tag.to_bytes(8, "little")
                              + bump.to_bytes(8, "little")),
            timestamp=1_700_000_000 + (tag & 0xFFFF),
            bits=bits,
            nonce=tag & 0xFFFFFFFF,
        )
        if int.from_bytes(_dsha(h.serialize()), "little") <= _bits_to_target(bits):
            return h
    raise AssertionError("could not mine a passing header")


def _chain_from(prev_hash: bytes, count: int, first_tag: int = 0):
    headers, prev = [], prev_hash
    for i in range(count):
        h = _mine(prev, first_tag + i)
        headers.append(h)
        prev = _dsha(h.serialize())
    return headers, prev


class _StubDB:
    def __init__(self, tip_hash: bytes, height: int):
        self._tip, self._height = tip_hash, height

    def get_best_block(self):
        return self._tip, self._height

    def get_block_hash_by_height(self, height):
        return self._tip if height == self._height else None


class _StubPeerManager:
    network = "regtest"

    def __init__(self, peers):
        self._peers = peers
        self.misbehaved = []

    def get_all_ready_peers(self):
        return self._peers

    def misbehaving(self, addr, score, reason):
        self.misbehaved.append((addr, score, reason))
        return False


def _make_peer() -> Peer:
    p = Peer("10.0.0.7", 18444, network="regtest")
    p.state = PeerState.READY
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    return p


def _fresh(tip_height: int = 500):
    tip = _dsha(b"tip")
    db = _StubDB(tip, tip_height)
    peer = _make_peer()
    pm = _StubPeerManager([peer])
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=db, validator=None, peer_manager=pm, mempool=None)
    return bs, db, peer, tip


def _getheaders_locators(peer) -> list[list[bytes]]:
    """Locator hash lists of every getheaders the peer was sent."""
    from ouroboros.p2p_messages import GetHeadersMessage
    out = []
    for msg in peer.sent:
        if getattr(msg, "command", None) == "getheaders":
            out.append(GetHeadersMessage.from_payload(msg.payload).locator_hashes)
    return out


class TestLowWorkPresync(unittest.IsolatedAsyncioTestCase):
    async def test_opening_a_walk_asks_the_peer_for_more(self):
        """Core TryLowWorkHeadersSync: the batch is dropped, but a continuation
        getheaders anchored on its last header goes straight back out."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=10, min_work=10 ** 40,
        )
        key = bs._peer_key(peer)
        self.assertIn(key, bs._lowwork_presync)
        self.assertEqual(_getheaders_locators(peer), [[tip]])

    async def test_a_short_batch_is_ignored_rather_than_walked(self):
        """net_processing.cpp:2799 — a non-full message means the peer has no
        more headers, so its chain really does end below the bar."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            17, tip, 500, REGTEST_BITS, peer, total_work=10, min_work=10 ** 40,
        )
        self.assertEqual(bs._lowwork_presync, {})
        self.assertEqual(peer.sent, [])

    async def test_a_full_batch_advances_the_walk_and_asks_for_the_next(self):
        """The continuation, batch after batch: work accumulates, the resume
        point moves to the batch's last header, the tip-anchored queue is never
        touched, and one more getheaders goes out."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=10 ** 40,
        )
        peer.sent.clear()
        headers, last = _chain_from(tip, 2000)
        await bs._advance_lowwork_presync(headers, peer)

        state = bs._lowwork_presync[bs._peer_key(peer)]
        self.assertEqual(state["last_hash"], last)
        self.assertEqual(state["height"], 2500)
        self.assertEqual(state["headers"], 4000)   # opening batch + this one
        self.assertGreater(state["work"], 0)
        self.assertEqual(bs._validated_headers, [], "presync must store nothing")
        self.assertEqual(_getheaders_locators(peer), [[last]])

    async def test_a_batch_that_is_not_the_continuation_is_ignored(self):
        """A late reply to an older getheaders must not tear down a walk that
        may already be hundreds of thousands of headers in."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=10 ** 40,
        )
        peer.sent.clear()
        elsewhere, _ = _chain_from(_dsha(b"somewhere else"), 3)
        await bs._advance_lowwork_presync(elsewhere, peer)

        state = bs._lowwork_presync[bs._peer_key(peer)]
        self.assertEqual(state["last_hash"], tip)   # unchanged
        self.assertEqual(state["headers"], 2000)
        # The re-ask is rate-limited, so a peer replying with the wrong thing
        # cannot make us spin: nothing goes out until the interval elapses.
        self.assertEqual(peer.sent, [])
        state["asked_at"] -= 10.0
        await bs._advance_lowwork_presync(elsewhere, peer)
        self.assertEqual(_getheaders_locators(peer), [[tip]])  # re-asked once

    async def test_crossing_the_threshold_flips_to_redownload(self):
        """PRESYNC -> REDOWNLOAD: the peer is marked already_validated_work and
        asked again from OUR tip so the ordinary path can commit the headers."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=1,
        )
        peer.sent.clear()
        headers, _ = _chain_from(tip, 3)
        await bs._advance_lowwork_presync(headers, peer)

        key = bs._peer_key(peer)
        self.assertNotIn(key, bs._lowwork_presync)
        self.assertIn(key, bs._lowwork_validated)
        self.assertEqual(bs._validated_headers, [])
        # The redownload getheaders is anchored on our own tip, not on the
        # presynced head.
        self.assertEqual(_getheaders_locators(peer), [[tip]])

    async def test_a_header_failing_its_own_pow_drops_the_walk(self):
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=10 ** 40,
        )
        bad = BlockHeader(
            version=1, prev_blockhash=tip, merkle_root=b"\x11" * 32,
            timestamp=1_700_000_000, bits=0x1D00FFFF, nonce=1,
        )
        await bs._advance_lowwork_presync([bad], peer)
        self.assertEqual(bs._lowwork_presync, {})
        self.assertTrue(
            any(r[2] == "header with invalid proof of work"
                for r in bs.peer_manager.misbehaved)
        )

    async def test_an_impermissible_difficulty_transition_drops_the_walk(self):
        """Core headerssync.cpp:189 — PermittedDifficultyTransition is checked
        on every presynced header, which is what stops a peer from holding
        difficulty at the minimum for a cheap million-header flood."""
        bs, db, peer, tip = _fresh()
        bs.peer_manager.network = "mainnet"   # regtest permits any transition
        await bs._begin_lowwork_presync(
            2000, tip, 500, 0x1B04864C, peer, total_work=0, min_work=10 ** 40,
        )
        # Height 501 is not a retarget boundary, so nBits must not change.
        cheat = BlockHeader(
            version=1, prev_blockhash=tip, merkle_root=b"\x22" * 32,
            timestamp=1_700_000_000, bits=REGTEST_BITS, nonce=1,
        )
        await bs._advance_lowwork_presync([cheat], peer)
        self.assertEqual(bs._lowwork_presync, {})
        self.assertTrue(
            any(r[2] == "invalid header received"
                for r in bs.peer_manager.misbehaved)
        )

    async def test_catch_up_does_not_restart_a_walk_in_flight(self):
        """The sync loop's tip-anchored getheaders must stay out of the way, or
        the walk restarts from our tip on every tick and never advances."""
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=10 ** 40,
        )
        peer.sent.clear()
        await bs._catch_up(peer, 500)
        self.assertEqual(peer.sent, [])
        self.assertIn(bs._peer_key(peer), bs._lowwork_presync)

    async def test_cleanup_peer_forgets_the_walk(self):
        bs, db, peer, tip = _fresh()
        await bs._begin_lowwork_presync(
            2000, tip, 500, REGTEST_BITS, peer, total_work=0, min_work=10 ** 40,
        )
        key = bs._peer_key(peer)
        bs._lowwork_validated.add(key)
        bs.cleanup_peer(key)
        self.assertNotIn(key, bs._lowwork_presync)
        self.assertNotIn(key, bs._lowwork_validated)


if __name__ == "__main__":
    unittest.main()
