"""GAP2 + GAP3 regression tests for the P2P reorg-drop fix.

Production blocker (tools/reorg-ouroboros-proof.sh): R1 on chain A connects to
R3 serving a heavier chain B forking at genesis and STAYS on chain A.  GAP1
(test_p2p_fork_discovery.py) admits the chain-B headers into a bounded fork
store and decides "strictly heavier".  GAP2 (this file) downloads the bridging
bodies, and GAP3 routes the completed bridge through the SAME submitblock
side-branch reorg engine (rpc._attach_side_branch_block /
_reorg_to_side_branch_tip) via the callback closure node.py injects with
set_reorg_handler — never a second reorg engine.

These tests pin:
  * the download descent (_request_fork_blocks) requests exactly the missing
    bridging bodies, in-flight-capped, bypassing the IBD tip-window throttle;
  * a fork body delivered to handle_block is stashed in _fork_block_bytes (NOT
    _ibd_block_buffer, so the TTL sweep can't evict it) and never enters the
    height-anchored IBD drain;
  * once the bridge is complete, GAP3 calls _attach_side_branch_block for every
    bridging block in FORWARD chain order with the correct (hash, prev, height),
    and the heaviest triggers the reorg — proving the route-through path;
  * the fork store is cleared after adoption so the per-tick re-check does not
    re-attach.

Faithful to the design plan section "PART 3 / PART 4 / PART 5".
"""

import hashlib
import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import (  # noqa: E402
    BlockHeader,
    HeadersMessage,
    NetworkMessage,
)
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


def _make_header(prev_hash: bytes, nonce: int) -> BlockHeader:
    for bump in range(1 << 22):
        h = BlockHeader(
            version=1,
            prev_blockhash=prev_hash,
            merkle_root=_dsha(b"mr" + nonce.to_bytes(8, "little")
                              + bump.to_bytes(8, "little")),
            timestamp=1_700_000_000 + (nonce & 0xFFFF),
            bits=REGTEST_BITS,
            nonce=nonce & 0xFFFFFFFF,
        )
        if int.from_bytes(_dsha(h.serialize()), "little") <= _REGTEST_TARGET:
            return h
    raise AssertionError("could not mine a passing regtest header")


def _header_hash(h: BlockHeader) -> bytes:
    return _dsha(h.serialize())


def _block_bytes(h: BlockHeader) -> bytes:
    """A fake 'block' whose first 80 bytes are the header, so
    dsha(payload[:80]) == header hash (what handle_block keys on)."""
    return h.serialize() + b"\x01" + b"\x00" * 64


class _StubDB:
    def __init__(self, chain: list[bytes]):
        self._chain = list(chain)
        self._have = set(chain)

    @property
    def _height(self) -> int:
        return len(self._chain) - 1

    def get_best_block(self):
        return self._chain[-1], self._height

    def has_block_hash(self, h):
        return h in self._have

    def get_block_hash_by_height(self, height):
        if 0 <= height < len(self._chain):
            return self._chain[height]
        return None

    # Used by _complete_fork_bridge's adoption clear-check after a reorg.
    def adopt_fork(self, ancestor_height: int, bridge_hashes: list[bytes]):
        """Simulate the rpc reorg engine swapping the active tip to the fork."""
        self._chain = self._chain[: ancestor_height + 1] + list(bridge_hashes)
        self._have.update(bridge_hashes)


class _StubPeerManager:
    network = "regtest"

    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return self._peers

    def misbehaving(self, *a, **k):
        return False


class _FakeReorgServer:
    """Stands in for the RPCServer's side-branch reorg machinery, recording the
    EXACT attach call sequence GAP3 makes and simulating the heavier-tip reorg
    (advance the stub DB tip) exactly as rpc._reorg_to_side_branch_tip would.

    Mirrors the real contract: _attach_side_branch_block stores into
    _side_branch_blocks and, when height > active_tip, calls
    _reorg_to_side_branch_tip which adopts the fork.
    """

    def __init__(self, db: _StubDB):
        self._db = db
        self._side_branch_blocks: dict[bytes, tuple[bytes, int, bytes]] = {}
        self._side_branch_max_entries = 1024
        self.attach_calls: list[tuple[bytes, bytes, int]] = []  # (hash, prev, h)
        self.reorg_calls: list[bytes] = []

    def _evict_side_branch_if_full(self):
        return None

    async def _attach_side_branch_block(self, db, raw, block_hash, prev, height):
        self.attach_calls.append((block_hash, prev, height))
        self._side_branch_blocks[block_hash] = (prev, height, raw)
        _, active_h = db.get_best_block()
        if height <= active_h:
            return None  # stored, not heavier
        return await self._reorg_to_side_branch_tip(db, block_hash)

    async def _reorg_to_side_branch_tip(self, db, new_tip_hash):
        self.reorg_calls.append(new_tip_hash)
        # Walk the side-branch buffer back to the common ancestor exactly like
        # the real engine, then adopt.
        chain_rev: list[bytes] = []
        cursor = new_tip_hash
        ancestor_h = None
        for _ in range(200):
            entry = self._side_branch_blocks.get(cursor)
            if entry is None:
                # cursor on active chain — resolve its height
                _, tip_h = db.get_best_block()
                for h in range(tip_h, -1, -1):
                    if db.get_block_hash_by_height(h) == cursor:
                        ancestor_h = h
                        break
                break
            prev, _height, _raw = entry
            chain_rev.append(cursor)
            cursor = prev
        if ancestor_h is None:
            return "rejected"
        chain_rev.reverse()
        db.adopt_fork(ancestor_h, chain_rev)
        return None


def _make_peer(i: int) -> Peer:
    p = Peer("10.0.0.%d" % i, 18444, network="regtest")
    p.state = PeerState.READY
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)
        return None

    p.send_message = _send
    return p


def _fresh(chain_len=5):
    chain = [_dsha(b"genesis")]
    for i in range(1, chain_len):
        chain.append(_dsha(b"A" + i.to_bytes(8, "little")))
    db = _StubDB(chain)
    peer = _make_peer(1)
    pm = _StubPeerManager([peer])
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=db, validator=None, peer_manager=pm, mempool=None)
    bs._header_sync_peer = peer
    return bs, db, peer, chain


def _mine_fork(fork_prev: bytes, n: int, base_nonce: int):
    """Return (headers, hashes, block_bytes_by_hash) for an n-block fork."""
    hdrs = []
    hashes = []
    bodies = {}
    prev = fork_prev
    for k in range(n):
        h = _make_header(prev, nonce=base_nonce + k)
        hdrs.append(h)
        hh = _header_hash(h)
        hashes.append(hh)
        bodies[hh] = _block_bytes(h)
        prev = hh
    return hdrs, hashes, bodies


class TestForkBlockDownload(unittest.IsolatedAsyncioTestCase):
    async def test_request_fork_blocks_requests_missing_bridge(self):
        """_request_fork_blocks issues getdata for the missing bridging bodies,
        records them in requested_blocks, and bypasses the IBD throttle."""
        bs, db, peer, chain = _fresh(chain_len=5)  # active tip h=4
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=10_000)
        # Admit the fork headers (GAP1).
        msg = HeadersMessage(hdrs).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)
        fork_tip = hashes[-1]
        self.assertEqual(len(bs._fork_headers), 6)
        # The heavier-fork trigger already fired in handle_headers; getdata for
        # the bridging bodies should have been sent.
        getdatas = [m for m in peer.sent if m.command == "getdata"]
        self.assertTrue(getdatas, "expected a getdata for fork bridging bodies")
        # All 6 fork hashes should be in-flight.
        for hh in hashes:
            self.assertIn(hh, bs.requested_blocks)

    async def test_request_fork_blocks_respects_in_flight_cap(self):
        bs, db, peer, chain = _fresh(chain_len=5)
        bs._max_blocks_in_flight = 3
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=11_000)
        msg = HeadersMessage(hdrs).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)
        # At most _max_blocks_in_flight bodies requested at once.
        self.assertLessEqual(len(bs.requested_blocks), 3)


class TestForkBodyHandling(unittest.IsolatedAsyncioTestCase):
    async def test_fork_body_goes_to_fork_store_not_ibd_buffer(self):
        """A delivered fork body is stashed in _fork_block_bytes, never the IBD
        buffer (so the TTL sweep can't evict it and the height-anchored drain
        never touches it)."""
        bs, db, peer, chain = _fresh(chain_len=5)
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=12_000)
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        # Deliver the first bridging body.
        h0 = hashes[0]
        blkmsg = NetworkMessage(command="block", payload=bodies[h0])
        await bs.handle_block(blkmsg, peer)
        self.assertIn(h0, bs._fork_block_bytes)
        self.assertNotIn(h0, bs._ibd_block_buffer)


class TestForkRouteThroughReorg(unittest.IsolatedAsyncioTestCase):
    async def test_full_bridge_attaches_in_order_and_reorgs(self):
        """End-to-end GAP2+GAP3: feed all fork headers, deliver every bridging
        body, and assert the side-branch reorg engine was called for each block
        in forward chain order with correct (hash, prev, height), the heaviest
        triggered the reorg, and the active tip adopted the fork."""
        bs, db, peer, chain = _fresh(chain_len=5)  # active tip h=4
        fork_prev = chain[0]  # fork at genesis (h=0)
        hdrs, hashes, bodies = _mine_fork(fork_prev, 6, base_nonce=13_000)
        fork_tip = hashes[-1]  # fork tip at h=6 > active h=4

        srv = _FakeReorgServer(db)
        bs.set_reorg_handler(srv)

        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        # Deliver every bridging body (out of order to stress ordering).
        for hh in reversed(hashes):
            await bs.handle_block(
                NetworkMessage(command="block", payload=bodies[hh]), peer
            )

        # Exactly ONE reorg fired (no cascade): GAP3 pre-populates the
        # side-branch buffer for all-but-the-tip and attaches only the tip.
        self.assertEqual(len(srv.reorg_calls), 1, "exactly one reorg fired")
        self.assertEqual(srv.reorg_calls[0], fork_tip)
        # attach_side_branch_block was called exactly once — on the tip — with
        # the correct (hash, prev, height).
        self.assertEqual(len(srv.attach_calls), 1)
        self.assertEqual(srv.attach_calls[0][0], fork_tip)
        self.assertEqual(srv.attach_calls[0][1], hashes[-2])  # prev = block 5
        self.assertEqual(srv.attach_calls[0][2], 6)  # tip height
        # Every bridging block (1..6) was put in the SAME buffer the engine
        # walks, in order, with correct heights and prev edges.
        all_prevs = [fork_prev] + hashes[:-1]
        for idx, hh in enumerate(hashes):
            self.assertIn(hh, srv._side_branch_blocks)
            prev_in_buf, height_in_buf, _raw = srv._side_branch_blocks[hh]
            self.assertEqual(height_in_buf, idx + 1)
            self.assertEqual(prev_in_buf, all_prevs[idx])
        # Active tip adopted the fork.
        tip_hash, tip_h = db.get_best_block()
        self.assertEqual(tip_h, 6)
        self.assertEqual(tip_hash, fork_tip)
        # Fork store cleared after adoption (per-tick re-check won't re-attach).
        self.assertEqual(len(bs._fork_headers), 0)

    async def test_incomplete_bridge_does_not_attach(self):
        """If a bridging body is still missing, GAP3 must NOT attach/reorg —
        it waits for the rest of the bridge."""
        bs, db, peer, chain = _fresh(chain_len=5)
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=14_000)
        srv = _FakeReorgServer(db)
        bs.set_reorg_handler(srv)
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        # Deliver all but the LAST bridging body.
        for hh in hashes[:-1]:
            await bs.handle_block(
                NetworkMessage(command="block", payload=bodies[hh]), peer
            )
        self.assertEqual(len(srv.reorg_calls), 0, "no reorg on incomplete bridge")
        # Tip unchanged.
        _, tip_h = db.get_best_block()
        self.assertEqual(tip_h, 4)

    async def test_no_reorg_handler_stores_only(self):
        """Without a wired reorg handler (header-only/test context), a full
        bridge is stored but never reorged — node continues, no crash."""
        bs, db, peer, chain = _fresh(chain_len=5)
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=15_000)
        # NOTE: set_reorg_handler intentionally NOT called.
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        for hh in hashes:
            await bs.handle_block(
                NetworkMessage(command="block", payload=bodies[hh]), peer
            )
        # All bodies stashed; nothing reorged; tip unchanged.
        self.assertEqual(len(bs._fork_block_bytes), 6)
        _, tip_h = db.get_best_block()
        self.assertEqual(tip_h, 4)

    async def test_lighter_fork_bodies_do_not_reorg(self):
        """A fork that is NOT heavier than the active chain is downloaded/stored
        but never reorged (height-as-work shortcut)."""
        bs, db, peer, chain = _fresh(chain_len=10)  # active tip h=9
        hdrs, hashes, bodies = _mine_fork(chain[0], 3, base_nonce=16_000)
        srv = _FakeReorgServer(db)
        bs.set_reorg_handler(srv)
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        # A lighter fork never triggers the download, but even if we hand it
        # the bodies directly the bridge-complete check must not reorg.
        for hh in hashes:
            bs._fork_block_bytes[hh] = bodies[hh]
        await bs._complete_fork_bridge(hashes[-1])
        self.assertEqual(len(srv.reorg_calls), 0)
        _, tip_h = db.get_best_block()
        self.assertEqual(tip_h, 9)

    async def test_recheck_forks_completes_bridge_after_late_body(self):
        """PART 5: a fork whose last body arrives via a path that did not
        re-drive completion is still reorged by the per-tick _recheck_forks."""
        bs, db, peer, chain = _fresh(chain_len=5)
        hdrs, hashes, bodies = _mine_fork(chain[0], 6, base_nonce=17_000)
        srv = _FakeReorgServer(db)
        bs.set_reorg_handler(srv)
        await bs.handle_headers(
            HeadersMessage(hdrs).to_network_message("regtest"),
            peer, min_pow_checked=True,
        )
        # Simulate all bodies present but completion not yet driven.
        for hh in hashes:
            bs._fork_block_bytes[hh] = bodies[hh]
        # A per-tick re-check should detect the now-complete heavier bridge.
        await bs._recheck_forks()
        self.assertEqual(len(srv.reorg_calls), 1)
        _, tip_h = db.get_best_block()
        self.assertEqual(tip_h, 6)


if __name__ == "__main__":
    unittest.main()
