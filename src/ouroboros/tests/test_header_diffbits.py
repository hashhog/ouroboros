"""bad-diffbits at header-admission time — regression suite.

The bug: ouroboros never evaluated Bitcoin Core's FIRST
``ContextualCheckBlockHeader`` rule::

    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.Invalid(BLOCK_INVALID_HEADER, "bad-diffbits",
                             "incorrect proof of work");
    -- bitcoin-core/src/validation.cpp:4088-4089

``BlockSync.handle_headers`` ran ``_header_meets_pow`` — which is
hash-vs-DECLARED-target, i.e. Core's ``CheckBlockHeader`` / "high-hash"
(validation.cpp:3832) — plus chain continuity, and nothing else.  A peer could
therefore fill the 50 000-slot validated-header queue with headers claiming
difficulty 1, each of whose hashes legitimately met its own claimed target.

MAINNET-SHAPED, NOT REGTEST.  Every test here runs on ``network="mainnet"``,
so ``fPowAllowMinDifficultyBlocks`` is false and retargeting is ON — the real
mainnet code path.  Regtest sets ``pow_no_retargeting``, which makes every
height answer powLimit; a regtest-only test is a NO-OP for this rule because
an implementation that ignores it entirely still passes.  That is exactly why
``test_p2p_fork_discovery.py``'s ``REGTEST_BITS`` fixture is deliberately NOT
reused here.

The nBits VALUES are chosen easy enough to mine in-process; what matters for
this rule is that ``nBits == GetNextWorkRequired``, not the absolute
difficulty.  The network SHAPE is mainnet.
"""

import hashlib
import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import BlockHeader, HeadersMessage  # noqa: E402
from ouroboros.peer import Peer, PeerState  # noqa: E402
from ouroboros.validation import (  # noqa: E402
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    POW_LIMIT_REGTEST,
    POW_TARGET_TIMESPAN,
    _bits_to_target,
    _target_to_bits,
)

# Honest chain difficulty for these fixtures. 0x1f7fffff decodes to
# 0x7fffff << (8 * 28); ~1 in 512 random hashes meets it, so headers are
# mineable in-process while still being a REAL target that the easy value
# below is measurably easier than.
HONEST_BITS = 0x1F7FFFFF
# The attacker's claim: ~256x easier. Its hashes DO meet this target, so
# _header_meets_pow ("high-hash") passes and only bad-diffbits can reject it.
EASY_BITS = 0x207FFFFF
# A REAL mainnet difficulty (block ~32256).  Not mineable in-process, so it is
# used only where the rule is driven directly rather than through a mined
# header — the retarget clamp and the boundary lookup are only meaningful for
# values at or below the mainnet powLimit.
MAINNET_REAL_BITS = 0x1B0404CB

_HONEST_TARGET = _bits_to_target(HONEST_BITS)
_EASY_TARGET = _bits_to_target(EASY_BITS)
assert _EASY_TARGET > _HONEST_TARGET


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _mine(prev_hash: bytes, bits: int, timestamp: int, tag: bytes) -> BlockHeader:
    """Build a header whose double-SHA256 actually meets ``bits``.

    Mining is required: the whole point is that these headers PASS the
    hash<=declared-target gate, so that a rejection can only come from
    bad-diffbits.
    """
    target = _bits_to_target(bits)
    for bump in range(1 << 24):
        h = BlockHeader(
            version=4,
            prev_blockhash=prev_hash,
            merkle_root=_dsha(tag + bump.to_bytes(8, "little")),
            timestamp=timestamp,
            bits=bits,
            nonce=bump & 0xFFFFFFFF,
        )
        if int.from_bytes(_dsha(h.serialize()), "little") <= target:
            return h
    raise AssertionError("could not mine a passing header")


def _hh(h: BlockHeader) -> bytes:
    return _dsha(h.serialize())


class _Blk:
    """Block-like record: only bits/timestamp/prev_blockhash are read."""

    def __init__(self, bits, timestamp, prev_blockhash=b"\x00" * 32):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = prev_blockhash


class _StubDB:
    """Active chain addressed by height, with an independently settable
    height->hash / height->block index so a test can POISON it."""

    def __init__(self, tip_hash: bytes, tip_height: int):
        self._tip = (tip_hash, tip_height)
        self.by_height: dict[int, _Blk] = {}
        self.hash_by_height: dict[int, bytes] = {tip_height: tip_hash}
        self.blocks: dict[bytes, _Blk] = {}

    def get_best_block(self):
        return self._tip

    def get_block_by_height(self, height):
        return self.by_height.get(height)

    def get_block_hash_by_height(self, height):
        return self.hash_by_height.get(height)

    def get_block(self, h):
        return self.blocks.get(h)

    def has_block_hash(self, h):
        return h in self.blocks or h == self._tip[0]

    def get_chainwork_by_height(self, height):
        return 0


class _StubPeerManager:
    network = "mainnet"

    def __init__(self, peers):
        self._peers = peers
        self.misbehaving_calls: list[tuple] = []

    def get_all_ready_peers(self):
        return self._peers

    def misbehaving(self, addr, score, reason):
        self.misbehaving_calls.append((addr, score, reason))
        return False


def _make_peer(i: int = 1) -> Peer:
    p = Peer("10.0.0.%d" % i, 8333, network="mainnet")
    p.state = PeerState.READY
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    return p


def _fresh(tip_height: int, tip_bits: int = HONEST_BITS, tip_ts: int = 1_700_000_000):
    tip_hash = _dsha(b"tip" + tip_height.to_bytes(8, "little"))
    db = _StubDB(tip_hash, tip_height)
    tip_blk = _Blk(tip_bits, tip_ts)
    db.by_height[tip_height] = tip_blk
    db.blocks[tip_hash] = tip_blk
    peer = _make_peer()
    pm = _StubPeerManager([peer])
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=db, validator=None, peer_manager=pm, mempool=None)
    # These fixtures mine at 0x1f7fffff so they can run in-process; that
    # target is above mainnet powLimit, so Core CheckBlockHeader would
    # reject them as high-hash. Raise the CheckProofOfWork ceiling so this
    # suite isolates ContextualCheckBlockHeader (bad-diffbits).
    bs._header_pow_limit_override = POW_LIMIT_REGTEST
    return bs, db, peer, pm, tip_hash, tip_blk


async def _feed(bs, peer, headers):
    msg = HeadersMessage(list(headers)).to_network_message("mainnet")
    await bs.handle_headers(msg, peer, min_pow_checked=True)


def _direct(bs, db, header, height, parent_hash, parent_height):
    """Drive the rule the way handle_headers does, without PoW mining.

    Builds the same pointer-based ancestor provider and calls the same
    ``_check_header_diffbits``; only the (unrelated) hash<=target gate is
    skipped, which lets these cases use REAL mainnet nBits.
    """
    tip_hash, tip_height = db.get_best_block()
    queue_index = {h: i for i, (h, _) in enumerate(bs._validated_headers)}
    provider = bs._header_ancestor_provider(
        parent_hash, parent_height, tip_hash, tip_height, queue_index, {}
    )
    parent = provider(parent_height)
    return bs._check_header_diffbits(header, height, parent, provider)


# ===========================================================================


class TestHandleHeadersDiffbits(unittest.IsolatedAsyncioTestCase):
    """handle_headers integration on MAINNET-shaped params."""

    async def test_honest_batch_accepted(self):
        """Regression guard against wedging sync: an honest mainnet-shaped
        batch is accepted in full."""
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        hdrs, prev, ts = [], tip_hash, tip.timestamp
        for i in range(20):
            ts += 600
            h = _mine(prev, HONEST_BITS, ts, b"honest%d" % i)
            hdrs.append(h)
            prev = _hh(h)
        await _feed(bs, peer, hdrs)

        self.assertEqual(len(bs._validated_headers), 20)
        self.assertEqual(bs._headers_diffbits_rejected, 0)
        self.assertEqual(pm.misbehaving_calls, [])

    async def test_wrong_nbits_batch_rejected(self):
        """20 headers whose hashes all meet their DECLARED easy targets but
        whose nBits != GetNextWorkRequired.  Pre-fix all 20 were queued."""
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        hdrs, prev, ts = [], tip_hash, tip.timestamp
        for i in range(20):
            ts += 600
            h = _mine(prev, EASY_BITS, ts, b"attack%d" % i)
            hdrs.append(h)
            prev = _hh(h)

        # Sanity: every one of these DOES pass the high-hash gate.
        for h in hdrs:
            self.assertTrue(BlockSync._header_meets_pow(h))

        await _feed(bs, peer, hdrs)

        self.assertEqual(
            len(bs._validated_headers),
            0,
            "not one difficulty-1 header may be admitted",
        )
        self.assertEqual(bs._headers_diffbits_rejected, 1)
        self.assertEqual(len(pm.misbehaving_calls), 1)
        self.assertEqual(pm.misbehaving_calls[0][2], "bad-diffbits")

    async def test_first_bad_header_drops_remainder_of_batch(self):
        """Core exits ProcessNewBlockHeaders on the first invalid header."""
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        hdrs, prev, ts = [], tip_hash, tip.timestamp
        for i in range(5):
            ts += 600
            bits = EASY_BITS if i == 2 else HONEST_BITS
            h = _mine(prev, bits, ts, b"mixed%d" % i)
            hdrs.append(h)
            prev = _hh(h)
        await _feed(bs, peer, hdrs)

        self.assertEqual(len(bs._validated_headers), 2, "only the first two")
        self.assertEqual(bs._headers_diffbits_rejected, 1)

    async def test_boundary_lookup_actually_runs(self):
        """A retarget BOUNDARY reached through handle_headers.

        DB tip 2014; headers at 2015 (non-boundary, expected == prev.bits) and
        2016 (BOUNDARY, expected == the retarget from the period-first block at
        height 0, capped at the mainnet powLimit — Core pow.cpp:81-82).

        These fixtures use easy-but-real nBits so the headers can be mined
        in-process; on mainnet that means the retarget result caps to
        ``0x1d00ffff``, which cannot be mined here.  So this test proves the
        boundary branch RAN and produced the capped answer by asserting the
        rejection of a boundary header carrying prev.bits.  The boundary
        arithmetic itself is pinned exactly, against real Core vectors, in
        ``tests/test_pow_w83.py::TestMainnetRetargetVectors``, and the
        boundary ancestor RESOLUTION is covered by
        ``TestBoundaryAncestorResolution`` below.
        """
        t0 = 1_600_000_000
        bs, db, peer, pm, tip_hash, tip = _fresh(2014, tip_ts=t0 + 2014 * 600)
        db.by_height[0] = _Blk(HONEST_BITS, t0)

        h2015 = _mine(tip_hash, HONEST_BITS, tip.timestamp + 600, b"c2015")
        bad2016 = _mine(_hh(h2015), HONEST_BITS, h2015.timestamp + 600, b"c2016")

        with self.assertLogs("ouroboros.block_sync", level="WARNING") as cm:
            await _feed(bs, peer, [h2015, bad2016])

        self.assertEqual(len(bs._validated_headers), 1, "2015 in, 2016 out")
        self.assertEqual(bs._headers_diffbits_rejected, 1)
        self.assertTrue(
            any("at height 2016 REJECTED" in m and "expected=0x1d00ffff" in m for m in cm.output),
            f"boundary branch did not run: {cm.output}",
        )


class TestPoisonImmunity(unittest.IsolatedAsyncioTestCase):
    """The test that separates this fix from the WRONG one.

    An implementation that resolves retarget ancestors through the
    height->hash index INVERTS: it rejects the honest header and accepts the
    attacker's.  Both assertions must hold.
    """

    def _poisoned(self):
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        # Queue three honest headers above the tip.
        hdrs, prev, ts = [], tip_hash, tip.timestamp
        for i in range(3):
            ts += 600
            h = _mine(prev, HONEST_BITS, ts, b"q%d" % i)
            hdrs.append(h)
            bs._validated_headers.append((_hh(h), h))
            prev = _hh(h)
        # POISON: the height index claims heights 900001..900003 are
        # attacker-chosen easy-difficulty blocks.  They are NOT ancestors of
        # the queued chain; the index does not even cover headers above the
        # validated tip on a real node.
        for i, height in enumerate((900_001, 900_002, 900_003)):
            poison = _Blk(EASY_BITS, ts + 1)
            db.by_height[height] = poison
            db.hash_by_height[height] = _dsha(b"poison%d" % i)
        return bs, db, peer, pm, prev, ts

    async def test_honest_header_accepted_despite_poisoned_index(self):
        bs, db, peer, pm, prev, ts = self._poisoned()
        honest = _mine(prev, HONEST_BITS, ts + 600, b"honest-tip")
        await _feed(bs, peer, [honest])
        self.assertEqual(
            len(bs._validated_headers),
            4,
            "an index-resolving implementation rejects this honest header",
        )
        self.assertEqual(bs._headers_diffbits_rejected, 0)

    async def test_attack_header_rejected_despite_poisoned_index(self):
        bs, db, peer, pm, prev, ts = self._poisoned()
        attack = _mine(prev, EASY_BITS, ts + 600, b"attack-tip")
        self.assertTrue(BlockSync._header_meets_pow(attack))
        await _feed(bs, peer, [attack])
        self.assertEqual(
            len(bs._validated_headers),
            3,
            "an index-resolving implementation ACCEPTS this difficulty-1 header",
        )
        self.assertEqual(bs._headers_diffbits_rejected, 1)

    async def test_fork_store_prev_comes_from_pointers_not_the_index(self):
        """A fork header's parent must be read from ``_fork_headers``, not
        from ``get_block_by_height`` — the active chain at that height is a
        DIFFERENT block."""
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        # Fork anchor: an active-chain block at height 899_999.
        anchor_hash = _dsha(b"anchor")
        db.hash_by_height[899_999] = anchor_hash
        db.by_height[899_999] = _Blk(HONEST_BITS, tip.timestamp - 600)
        db.blocks[anchor_hash] = db.by_height[899_999]
        # The ACTIVE chain block at 900_000 carries EASY_BITS (the poison):
        # if the fork path resolves its parent by height it will demand
        # EASY_BITS for the fork's child.
        db.by_height[900_000].bits = EASY_BITS

        # Fork header at height 900_000 built on the anchor, honest bits.
        f1 = _mine(anchor_hash, HONEST_BITS, tip.timestamp, b"fork1")
        await _feed(bs, peer, [f1])
        self.assertIn(_hh(f1), bs._fork_headers)

        # Fork child at 900_001: correct value is the FORK parent's bits.
        good = _mine(_hh(f1), HONEST_BITS, tip.timestamp + 600, b"fork2")
        await _feed(bs, peer, [good])
        self.assertIn(_hh(good), bs._fork_headers)
        self.assertEqual(bs._headers_diffbits_rejected, 0)

        # A fork child carrying the POISONED (active-chain) value is rejected.
        bad = _mine(_hh(f1), EASY_BITS, tip.timestamp + 600, b"fork3")
        await _feed(bs, peer, [bad])
        self.assertNotIn(_hh(bad), bs._fork_headers)
        self.assertEqual(bs._headers_diffbits_rejected, 1)
        self.assertTrue(any(c[2] == "bad-diffbits" for c in pm.misbehaving_calls))


class TestFailClosed(unittest.IsolatedAsyncioTestCase):
    async def test_unresolvable_boundary_ancestor_is_rejected_not_skipped(self):
        """Boundary at height 2016 with the period-first block ABSENT and no
        assumeUTXO snapshot.  FAIL-OPEN IS THE BUG: the header must be
        REJECTED, and nothing appended."""
        t0 = 1_600_000_000
        bs, db, peer, pm, tip_hash, tip = _fresh(2015, tip_ts=t0 + 2015 * 600)
        # db.by_height[0] deliberately absent.
        self.assertIsNone(db.get_block_by_height(0))
        self.assertEqual(bs._snapshot_base_height(), -1)

        h = _mine(tip_hash, HONEST_BITS, tip.timestamp + 600, b"unres")
        await _feed(bs, peer, [h])

        self.assertEqual(len(bs._validated_headers), 0)
        self.assertEqual(bs._headers_diffbits_rejected, 1)
        self.assertEqual(bs._headers_diffbits_unresolved, 0)

    def test_snapshot_bounded_fallback_still_clamps(self):
        """With a snapshot base at/above the missing height, the NARROW
        fallback engages — but Core's 4x clamp
        (PermittedDifficultyTransition, pow.cpp:89-136) still binds, so a
        difficulty-1 header is still rejected.

        Driven through ``_check_header_diffbits`` with REAL mainnet nBits: the
        clamp is only meaningful for values at or below the mainnet powLimit,
        which are not mineable in-process.
        """
        t0 = 1_600_000_000
        bs, db, peer, pm, tip_hash, tip = _fresh(
            2015, tip_bits=MAINNET_REAL_BITS, tip_ts=t0 + 2015 * 600
        )
        # Period-first (height 0) deliberately absent -> unresolvable.
        bs._snapshot_base_height_cache = 100  # first_height (0) <= 100

        # Unchanged nBits at a boundary is inside the clamp -> accepted, but
        # LOUDLY and counted.
        with self.assertLogs("ouroboros.block_sync", level="WARNING") as cm:
            ok, reason, _ = _direct(
                bs,
                db,
                _Blk(MAINNET_REAL_BITS, tip.timestamp + 600),
                2016,
                tip_hash,
                2015,
            )
        self.assertTrue(ok)
        self.assertEqual(reason, "unresolved-fallback")
        self.assertEqual(bs._headers_diffbits_unresolved, 1)
        self.assertTrue(any("unresolvable" in m for m in cm.output))

        # A difficulty-1 claim is far outside the 4x clamp -> still rejected.
        ok2, reason2, _ = _direct(
            bs,
            db,
            _Blk(0x1D00FFFF, tip.timestamp + 600),
            2016,
            tip_hash,
            2015,
        )
        self.assertFalse(ok2)
        self.assertIn("fallback", reason2)

    def test_snapshot_fallback_rejects_a_third_value_on_testnet4(self):
        """On min-difficulty networks PermittedDifficultyTransition returns
        True unconditionally (Core pow.cpp:91), so the fallback is the
        explicit two-value rule instead."""
        from ouroboros.validation import diffbits_unresolved_fallback_ok as fb

        self.assertTrue(fb("testnet4", 1000, 0x1D00FFFF, 0x1D00FFFF))
        self.assertTrue(fb("testnet4", 1000, MAINNET_REAL_BITS, MAINNET_REAL_BITS))
        self.assertFalse(fb("testnet4", 1000, MAINNET_REAL_BITS, 0x1C00FFFF))


class TestBoundaryAncestorResolution(unittest.TestCase):
    """The retarget-boundary ancestor must be resolved by POINTER, even when
    the height it lives at is ABOVE the DB tip (inside the validated-header
    queue) and the height index at that height is poisoned.

    Uses REAL mainnet nBits (0x1b0404cb) and drives ``_check_header_diffbits``
    directly — no PoW mining, because the rule under test is nBits-vs-required,
    not hash-vs-target.
    """

    def _chain_to_boundary(self):
        t0 = 1_600_000_000
        # DB tip at 2015; queue holds 2016..4031 so the boundary at 4032 has
        # its period-first block (height 4032-2016 = 2016) at QUEUE SLOT 0.
        bs, db, peer, pm, tip_hash, tip = _fresh(
            2015, tip_bits=MAINNET_REAL_BITS, tip_ts=t0 + 2015 * 600
        )
        prev = tip_hash
        for h in range(2016, 4032):
            hdr = BlockHeader(
                version=4,
                prev_blockhash=prev,
                merkle_root=_dsha(b"h" + h.to_bytes(4, "little")),
                timestamp=t0 + h * 600,
                bits=MAINNET_REAL_BITS,
                nonce=h,
            )
            bs._validated_headers.append((_hh(hdr), hdr))
            prev = _hh(hdr)
        self.assertEqual(len(bs._validated_headers), 2016)
        # POISON the height index at 2016 with a different block: an
        # index-resolving implementation reads its timestamp and inverts.
        db.by_height[2016] = _Blk(MAINNET_REAL_BITS, t0)
        db.hash_by_height[2016] = _dsha(b"poison-2016")
        # Core pow.cpp:41-47: nHeightFirst = 4031 - 2015 = 2016.
        timespan = (t0 + 4031 * 600) - (t0 + 2016 * 600)
        expected = _target_to_bits(
            _bits_to_target(MAINNET_REAL_BITS) * timespan // POW_TARGET_TIMESPAN
        )
        poisoned_timespan = (t0 + 4031 * 600) - t0
        poisoned = _target_to_bits(
            _bits_to_target(MAINNET_REAL_BITS) * poisoned_timespan // POW_TARGET_TIMESPAN
        )
        self.assertNotEqual(expected, poisoned, "fixture must distinguish")
        return bs, db, prev, t0, expected, poisoned

    def test_honest_boundary_header_accepted(self):
        bs, db, prev, t0, expected, poisoned = self._chain_to_boundary()
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(expected, t0 + 4032 * 600),
            4032,
            prev,
            4031,
        )
        self.assertTrue(ok, f"{reason} exp={exp}")
        self.assertEqual(exp, expected)

    def test_poisoned_index_answer_rejected(self):
        bs, db, prev, t0, expected, poisoned = self._chain_to_boundary()
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(poisoned, t0 + 4032 * 600),
            4032,
            prev,
            4031,
        )
        self.assertFalse(
            ok,
            "the value derived from the POISONED index must be rejected",
        )
        self.assertEqual(reason, "bad-diffbits")

    def test_difficulty_one_boundary_header_rejected(self):
        bs, db, prev, t0, expected, poisoned = self._chain_to_boundary()
        ok, reason, _ = _direct(
            bs,
            db,
            _Blk(0x1D00FFFF, t0 + 4032 * 600),
            4032,
            prev,
            4031,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "bad-diffbits")


class TestPeriodFirstIsItselfARetarget(unittest.TestCase):
    """missing-period-first at a retarget whose period-first is itself a retarget.

    Production (receipts/ouroboros-missing-period-first-284256-2026-09-11.md):
    range 265000→290000 connected through 284,255, then header 284,256 was
    REJECTED ``bad-diffbits-unresolved(missing-period-first)`` and the feeder
    banned.  284,256 = 141×2016; its period-first 282,240 is itself a
    2016-boundary, is above the snapshot base, and was connected 13 minutes
    earlier.  Earlier retargets in the same run (268128…282240) passed
    because their period-first was still sitting in ``_validated_headers``.

    Two invariants collide once the queue is gone (slot-misalign dropped
    3973 entries at 284,255) and the feeder re-sends a 2000-header window
    that includes the now-connected tip:

      * P2P ``headers`` messages are at most 2000 long, so a batch ending
        at the retarget parent can never contain the period-first (always
        2016 back — 16 blocks before the start of that window).
      * Those re-sent headers land in ``_batch_headers`` / ``_fork_headers``.
        ``_header_ancestor_provider`` walked them instead of treating the
        parent (the active tip) as an active-chain anchor, then asked
        ``_resolve_active_height`` — which only scans ``MAX_REORG_DEPTH``
        (288) — to place a cursor ~2000 back.  That miss is reported as
        ``missing-period-first`` even though ``get_block_by_height(282240)``
        would have answered.

    Core's ``pindexLast->GetAncestor(nHeightFirst)`` (pow.cpp:42-47) never
    does this: when pindexLast is on the active chain, the ancestor is
    height-addressed in that chain.  A 2000-header re-send of the tip must
    not hide a connected period-first.

    The nBits values are real mainnet compact targets; the rule under test
    is nBits-vs-required, so we drive ``_check_header_diffbits`` directly
    (same helper as ``TestBoundaryAncestorResolution``).
    """

    # A 2000-header walk matches Bitcoin P2P MAX_HEADERS.  Period-first at
    # 4032 − 2016 = 2016 sits 16 blocks before the start of that window
    # (2032), so the walk cannot record it.
    _FORK_WINDOW = 2000
    _TIP_HEIGHT = 4031
    _NEW_HEIGHT = 4032
    _PERIOD_FIRST = 2016

    def _setup(self):
        t0 = 1_600_000_000
        bs, db, _peer, _pm, tip_hash, _tip = _fresh(
            self._TIP_HEIGHT,
            tip_bits=MAINNET_REAL_BITS,
            tip_ts=t0 + self._TIP_HEIGHT * 600,
        )
        self.assertEqual(len(bs._validated_headers), 0)

        # Period-first is itself a retarget (2016 % 2016 == 0) and is
        # CONNECTED — in the height index, with a body.  Production had
        # this at 282,240.
        first_ts = t0 + self._PERIOD_FIRST * 600
        first_hash = _dsha(b"period-first-2016")
        db.by_height[self._PERIOD_FIRST] = _Blk(MAINNET_REAL_BITS, first_ts)
        db.hash_by_height[self._PERIOD_FIRST] = first_hash
        db.blocks[first_hash] = db.by_height[self._PERIOD_FIRST]

        # Re-sent 2000-header window ending at the tip, stored in the fork
        # store the way handle_headers does when the queue has been
        # dropped and the batch does not start at expected_prev == tip.
        # Heights covered: (4031-2000+1)=2032 .. 4031.  2016 is not among
        # them.
        window_start = self._TIP_HEIGHT - self._FORK_WINDOW + 1
        self.assertGreater(window_start, self._PERIOD_FIRST)
        prev = _dsha(b"below-window")
        for h in range(window_start, self._TIP_HEIGHT):
            hdr = BlockHeader(
                version=4,
                prev_blockhash=prev,
                merkle_root=_dsha(b"f" + h.to_bytes(4, "little")),
                timestamp=t0 + h * 600,
                bits=MAINNET_REAL_BITS,
                nonce=h,
            )
            hh = _hh(hdr)
            bs._fork_headers[hh] = hdr
            bs._fork_header_prev[hh] = prev
            prev = hh
        # The active tip itself is in the fork store (the production log
        # line: "Fork header f07dc15a7082b3ff... stored").  Its hash MUST
        # be the DB tip hash so the provider starts there.
        tip_hdr = SimpleNamespace(
            bits=MAINNET_REAL_BITS,
            timestamp=t0 + self._TIP_HEIGHT * 600,
            prev_blockhash=prev,
        )
        bs._fork_headers[tip_hash] = tip_hdr
        bs._fork_header_prev[tip_hash] = prev
        self.assertEqual(len(bs._fork_headers), self._FORK_WINDOW)

        timespan = (t0 + self._TIP_HEIGHT * 600) - first_ts
        expected = _target_to_bits(
            _bits_to_target(MAINNET_REAL_BITS) * timespan // POW_TARGET_TIMESPAN
        )
        return bs, db, tip_hash, t0, expected

    def test_connected_period_first_is_found_even_when_tip_is_in_fork_store(self):
        """The production stall: parent is the active tip, the tip hash is
        also in ``_fork_headers`` as part of a 2000-header re-send, and
        the period-first (itself a retarget) is connected below the window.
        Pre-fix this returned ``bad-diffbits-unresolved(missing-period-first)``.
        """
        bs, db, tip_hash, t0, expected = self._setup()
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(expected, t0 + self._NEW_HEIGHT * 600),
            self._NEW_HEIGHT,
            tip_hash,
            self._TIP_HEIGHT,
        )
        self.assertTrue(
            ok,
            f"connected period-first {self._PERIOD_FIRST} must resolve; "
            f"got ok={ok} reason={reason} exp={exp}",
        )
        self.assertEqual(reason, "ok")
        self.assertEqual(exp, expected)

    def test_wrong_bits_at_that_boundary_is_bad_diffbits_not_unresolved(self):
        """Negative: once the period-first is found, a wrong-nBits header
        is still REJECTED, and the reason is the resolved rule
        (``bad-diffbits``), not ``missing-period-first``.  An implementation
        that fail-opens on the miss would accept this; one that fail-closes
        without resolving would reject with ``unresolved``.
        """
        bs, db, tip_hash, t0, expected = self._setup()
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(0x1D00FFFF, t0 + self._NEW_HEIGHT * 600),
            self._NEW_HEIGHT,
            tip_hash,
            self._TIP_HEIGHT,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "bad-diffbits")
        self.assertEqual(exp, expected)
        self.assertNotIn("unresolved", reason)
        self.assertNotIn("missing-period-first", reason)

    def test_fork_retarget_anchors_deeper_than_reorg_depth(self):
        """A competing-fork retarget whose join to the active chain is
        deeper than ``MAX_REORG_DEPTH`` (288) must still resolve a
        connected period-first via the O(1) height-index agreement check.

        ``_resolve_active_height`` only scans 288 blocks (the fork-anchor
        bound).  Pre-fix a 301-header fork walk then asked that helper to
        place a cursor 301 back and reported ``missing-period-first``.
        ``get_block_hash_by_height(h) == cursor`` is Core's proof at any
        depth and cannot invert.
        """
        t0 = 1_600_000_000
        bs, db, _peer, _pm, tip_hash, _tip = _fresh(
            self._TIP_HEIGHT,
            tip_bits=MAINNET_REAL_BITS,
            tip_ts=t0 + self._TIP_HEIGHT * 600,
        )
        first_ts = t0 + self._PERIOD_FIRST * 600
        db.by_height[self._PERIOD_FIRST] = _Blk(MAINNET_REAL_BITS, first_ts)
        db.hash_by_height[self._PERIOD_FIRST] = _dsha(b"period-first-2016")

        walk = 301  # one past MAX_REORG_DEPTH
        join_height = self._TIP_HEIGHT - walk
        self.assertGreater(join_height, self._PERIOD_FIRST)
        join_hash = _dsha(b"join")
        db.hash_by_height[join_height] = join_hash
        db.by_height[join_height] = _Blk(MAINNET_REAL_BITS, t0 + join_height * 600)
        db.blocks[join_hash] = db.by_height[join_height]

        prev = join_hash
        parent_hash = None
        for h in range(join_height + 1, self._TIP_HEIGHT + 1):
            hdr = BlockHeader(
                version=4,
                prev_blockhash=prev,
                merkle_root=_dsha(b"k" + h.to_bytes(4, "little")),
                timestamp=t0 + h * 600,
                bits=MAINNET_REAL_BITS,
                nonce=h,
            )
            hh = _hh(hdr)
            bs._fork_headers[hh] = hdr
            bs._fork_header_prev[hh] = prev
            prev = hh
            parent_hash = hh
        self.assertIsNotNone(parent_hash)
        self.assertNotEqual(parent_hash, tip_hash)

        timespan = (t0 + self._TIP_HEIGHT * 600) - first_ts
        expected = _target_to_bits(
            _bits_to_target(MAINNET_REAL_BITS) * timespan // POW_TARGET_TIMESPAN
        )
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(expected, t0 + self._NEW_HEIGHT * 600),
            self._NEW_HEIGHT,
            parent_hash,
            self._TIP_HEIGHT,
        )
        self.assertTrue(
            ok,
            f"fork join at {join_height} (>288 back) must still resolve "
            f"period-first; got ok={ok} reason={reason} exp={exp}",
        )
        self.assertEqual(exp, expected)

    def test_empty_queue_connected_period_first_without_fork_store(self):
        """Baseline: queue empty, period-first in the height index, parent
        is the tip and is NOT in the fork store.  This is GetAncestor on
        the active chain and must not depend on the fork-store walk.
        """
        t0 = 1_600_000_000
        bs, db, _peer, _pm, tip_hash, _tip = _fresh(
            self._TIP_HEIGHT,
            tip_bits=MAINNET_REAL_BITS,
            tip_ts=t0 + self._TIP_HEIGHT * 600,
        )
        first_ts = t0 + self._PERIOD_FIRST * 600
        db.by_height[self._PERIOD_FIRST] = _Blk(MAINNET_REAL_BITS, first_ts)
        db.hash_by_height[self._PERIOD_FIRST] = _dsha(b"period-first-2016")
        timespan = (t0 + self._TIP_HEIGHT * 600) - first_ts
        expected = _target_to_bits(
            _bits_to_target(MAINNET_REAL_BITS) * timespan // POW_TARGET_TIMESPAN
        )
        ok, reason, exp = _direct(
            bs,
            db,
            _Blk(expected, t0 + self._NEW_HEIGHT * 600),
            self._NEW_HEIGHT,
            tip_hash,
            self._TIP_HEIGHT,
        )
        self.assertTrue(ok, f"{reason} exp={exp}")
        self.assertEqual(exp, expected)


class TestQueueAnchorStaleness(unittest.IsolatedAsyncioTestCase):
    async def test_stale_queue_cleared_before_any_height_is_derived(self):
        """Every header height is derived positionally from the queue.  If
        slot 0 no longer extends the DB tip the derivation is wrong and the
        check inverts — drop the queue loudly instead."""
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        stale = _mine(_dsha(b"some-other-parent"), HONEST_BITS, tip.timestamp, b"stale")
        bs._validated_headers.append((_hh(stale), stale))
        self.assertFalse(bs._queue_anchored_to_tip())

        honest = _mine(tip_hash, HONEST_BITS, tip.timestamp + 600, b"fresh")
        with self.assertLogs("ouroboros.block_sync", level="ERROR") as cm:
            await _feed(bs, peer, [honest])

        self.assertTrue(any("slot-misalign" in m for m in cm.output))
        # Queue rebuilt from the real tip: exactly the one honest header.
        self.assertEqual(len(bs._validated_headers), 1)
        self.assertEqual(bs._validated_headers[0][0], _hh(honest))


class TestSubmitHeaderLabels(unittest.IsolatedAsyncioTestCase):
    """Core's submitheader surfaces state.GetRejectReason()
    (rpc/mining.cpp:1108-1144).  A hash>target failure is "high-hash"
    (validation.cpp:3832), NOT "bad-diffbits"."""

    def _server(self, bs, db):
        from ouroboros.rpc import RPCServer
        from ouroboros.validation import BlockValidator

        validator = BlockValidator.__new__(BlockValidator)
        validator.network = "mainnet"
        validator.db = db
        srv = RPCServer.__new__(RPCServer)
        srv.node = SimpleNamespace(db=db, block_sync=bs, validator=validator)
        return srv

    async def test_high_hash_is_labelled_high_hash(self):
        from ouroboros.rpc import RpcError

        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        srv = self._server(bs, db)
        # Declared HONEST_BITS but hash does not meet it (mined against the
        # easy target instead) — and its nBits is ALSO wrong for its height,
        # so this doubles as the ordering assertion.
        h = _mine(tip_hash, EASY_BITS, tip.timestamp + 600, b"hh")
        forged = BlockHeader(
            version=h.version,
            prev_blockhash=h.prev_blockhash,
            merkle_root=h.merkle_root,
            timestamp=h.timestamp,
            bits=0x1D00FFFF,
            nonce=h.nonce,
        )
        self.assertFalse(BlockSync._header_meets_pow(forged))
        with self.assertRaises(RpcError) as ctx:
            await srv.rpc_submitheader(forged.serialize().hex())
        self.assertEqual(ctx.exception.message, "high-hash")
        self.assertNotEqual(ctx.exception.message, "bad-diffbits")

    async def test_valid_pow_but_wrong_nbits_is_bad_diffbits(self):
        from ouroboros.rpc import RpcError

        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        srv = self._server(bs, db)
        h = _mine(tip_hash, EASY_BITS, tip.timestamp + 600, b"bd")
        self.assertTrue(BlockSync._header_meets_pow(h))
        with self.assertRaises(RpcError) as ctx:
            await srv.rpc_submitheader(h.serialize().hex())
        self.assertEqual(ctx.exception.message, "bad-diffbits")

    async def test_honest_header_returns_none(self):
        bs, db, peer, pm, tip_hash, tip = _fresh(900_000)
        srv = self._server(bs, db)
        h = _mine(tip_hash, HONEST_BITS, tip.timestamp + 600, b"okhdr")
        self.assertIsNone(await srv.rpc_submitheader(h.serialize().hex()))
        self.assertIn(_hh(h), {x for x, _ in bs._validated_headers})


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
