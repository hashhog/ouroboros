"""Per-peer tx-announcement limits and O(expired) expiry (audit 2026-10-30 H3).

Before the fix ``BlockSync.handle_inv`` put every unknown txid from any peer
into one global ``_requested_txs`` dict with a 60 s TTL, sent a getdata for
all of them at once, and rebuilt the whole dict on every inv to expire old
entries.  One peer sending 60 invs of 50,000 txids grew it to 3,000,000
entries, and each later inv paid a full scan of it on the event loop.

Core (txdownloadman.h) tracks announcements per peer:
MAX_PEER_TX_ANNOUNCEMENTS = 5000, MAX_PEER_TX_REQUEST_IN_FLIGHT = 100,
and TxRequestTracker expiry costs O(expired).
"""

import struct
import sys
import time
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import (  # noqa: E402
    GetDataMessage,
    InvMessage,
    MSG_WTX,
    NetworkMessage,
    get_magic,
)
from ouroboros.peer import Peer, PeerState  # noqa: E402

MAX_INV_SZ = 50_000


def _h(n: int) -> bytes:
    return n.to_bytes(32, "little")


class _StubDB:
    def get_best_block(self):
        return _h(0), 0

    def has_block_hash(self, h):
        return False


class _StubMempool:
    def __len__(self):
        return 0

    def get_transaction(self, txid):
        return None

    def get_transaction_by_wtxid(self, wtxid):
        return None


class _StubPeerManager:
    network = "regtest"

    def get_all_ready_peers(self):
        return []


def _peer(i: int = 1) -> Peer:
    p = Peer(f"10.0.{i // 256}.{i % 256}", 18444, network="regtest")
    p.state = PeerState.READY
    p.services = 0x1 | 0x8
    p.version = 70016
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    return p


def _bs() -> BlockSync:
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(
        bs, db=_StubDB(), validator=None, peer_manager=_StubPeerManager(),
        mempool=_StubMempool(),
    )
    return bs


def _inv(start: int, n: int) -> NetworkMessage:
    # Built by hand: InvMessage.serialize_payload is quadratic and takes
    # seconds for a 50,000-item inv.
    assert n < 0x10000
    count = bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)
    item = struct.pack("<I", MSG_WTX)
    payload = count + b"".join(item + _h(start + i) for i in range(n))
    return NetworkMessage(command="inv", payload=payload, magic=get_magic("regtest"))


def _requested(peer) -> list:
    out = []
    for m in peer.sent:
        if m.command == "getdata":
            out.extend(h for _, h in GetDataMessage.from_payload(m.payload).inventory)
    return out


def _addr(peer) -> str:
    return f"{peer.host}:{peer.port}"


class TestTxRequestPerPeer(unittest.IsolatedAsyncioTestCase):
    async def test_one_peer_flood_tracks_at_most_5000(self):
        """60 invs x 50,000 txids from one peer leave at most
        MAX_PEER_TX_ANNOUNCEMENTS (5000) tracked, after every inv."""
        bs, peer = _bs(), _peer()
        for k in range(60):
            await bs.handle_inv(_inv(1 + k * MAX_INV_SZ, MAX_INV_SZ), peer)
            self.assertLessEqual(
                len(bs._requested_txs), 5000,
                f"after inv {k + 1}: {len(bs._requested_txs)} tracked",
            )
        from ouroboros.tx_request import MAX_PEER_TX_ANNOUNCEMENTS
        self.assertEqual(MAX_PEER_TX_ANNOUNCEMENTS, 5000)
        self.assertEqual(bs._requested_txs.peer_count(_addr(peer)), 5000)

    async def test_in_flight_capped_at_100_per_peer(self):
        """A 50,000-txid inv yields getdata for only
        MAX_PEER_TX_REQUEST_IN_FLIGHT (100) txs, the first announced."""
        bs, peer = _bs(), _peer()
        await bs.handle_inv(_inv(1, MAX_INV_SZ), peer)
        got = _requested(peer)
        self.assertEqual(len(got), 100)
        self.assertEqual(got, [_h(1 + i) for i in range(100)])
        # A further inv from the same peer requests nothing new: still 100
        # in flight.
        await bs.handle_inv(_inv(10**6, 10), peer)
        self.assertEqual(len(_requested(peer)), 100)

    async def test_answer_frees_slot_and_requests_next(self):
        """A tx (or notfound) answer frees an in-flight slot and the peer's
        next queued announcement is requested."""
        bs, peer = _bs(), _peer()
        await bs.handle_inv(_inv(1, 300), peer)
        peer.sent.clear()
        await bs.on_tx_answered(peer, [_h(1), _h(2)])
        self.assertEqual(_requested(peer), [_h(101), _h(102)])
        self.assertEqual(bs._requested_txs.in_flight_count(_addr(peer)), 100)
        self.assertEqual(bs._requested_txs.peer_count(_addr(peer)), 298)

    async def test_flooding_peer_does_not_block_other_peers(self):
        bs, a, b = _bs(), _peer(1), _peer(2)
        for k in range(3):
            await bs.handle_inv(_inv(1 + k * MAX_INV_SZ, MAX_INV_SZ), a)
        await bs.handle_inv(_inv(10**7, 3), b)
        self.assertEqual(_requested(b), [_h(10**7 + i) for i in range(3)])

    async def test_same_txid_from_two_peers_requested_once(self):
        bs, a, b = _bs(), _peer(1), _peer(2)
        await bs.handle_inv(_inv(1, 1), a)
        await bs.handle_inv(_inv(1, 1), b)
        self.assertEqual(_requested(a), [_h(1)])
        self.assertEqual(_requested(b), [])

    async def test_disconnect_drops_peer_announcements(self):
        bs, peer = _bs(), _peer()
        await bs.handle_inv(_inv(1, MAX_INV_SZ), peer)
        bs.cleanup_peer(_addr(peer))
        self.assertEqual(len(bs._requested_txs), 0)
        self.assertEqual(bs._requested_txs.peer_count(_addr(peer)), 0)

    async def test_expired_requests_free_the_peer(self):
        """After GETDATA_TX_INTERVAL (60 s) unanswered requests and queued
        announcements expire, so a silent peer's slots come back."""
        from unittest import mock
        bs, peer = _bs(), _peer()
        clock = [1000.0]
        with mock.patch("ouroboros.block_sync.time.monotonic", lambda: clock[0]):
            await bs.handle_inv(_inv(1, 150), peer)
            clock[0] += 30
            await bs.handle_inv(_inv(10**6, 1), peer)
            self.assertEqual(len(_requested(peer)), 100)
            clock[0] += 31  # the first 150 were announced 61 s ago
            await bs.handle_inv(_inv(2 * 10**6, 1), peer)
        got = _requested(peer)
        self.assertEqual(got[100:], [_h(10**6), _h(2 * 10**6)])
        self.assertEqual(len(bs._requested_txs), 2)

    async def test_per_inv_expiry_cost_does_not_grow_with_tracked(self):
        """The per-inv expiry must not scan every tracked entry: handling a
        1-txid inv costs the same with 400,000 entries tracked as with ~0."""
        async def one_inv_cost(bs, peer, base):
            best = float("inf")
            for r in range(5):
                t0 = time.perf_counter()
                await bs.handle_inv(_inv(base + r, 1), peer)
                best = min(best, time.perf_counter() - t0)
            return best

        small = _bs()
        t_small = await one_inv_cost(small, _peer(999), 9 * 10**8)

        big = _bs()
        for i in range(80):
            await big.handle_inv(_inv(1 + i * MAX_INV_SZ, 5000), _peer(i))
        self.assertGreaterEqual(len(big._requested_txs), 400_000)
        t_big = await one_inv_cost(big, _peer(999), 9 * 10**8)

        self.assertLess(
            t_big, t_small * 10 + 0.002,
            f"1-txid inv: {t_big * 1e3:.2f} ms with 400k tracked vs "
            f"{t_small * 1e3:.2f} ms empty — expiry scans the whole dict",
        )


class TestTxRequestTrackerExpiry(unittest.TestCase):
    def test_expire_pops_only_expired(self):
        from ouroboros.tx_request import TxRequestTracker
        tr = TxRequestTracker()
        for i in range(10):
            tr.announce("old", _h(i), i, now=0.0)
        tr.pop_requests("old", now=0.0)
        for i in range(10, 1010):
            tr.announce("new", _h(i), i, now=50.0)
        self.assertEqual(tr.expire(now=61.0), 10)
        self.assertEqual(len(tr), 1000)
        self.assertEqual(tr.peer_count("old"), 0)
        self.assertEqual(tr.peer_count("new"), 1000)

    def test_requested_entry_expires_from_request_time(self):
        from ouroboros.tx_request import TxRequestTracker
        tr = TxRequestTracker()
        tr.announce("p", _h(1), 1, now=0.0)
        tr.announce("p", _h(2), 2, now=0.0)
        tr.max_in_flight = 1
        tr.pop_requests("p", now=0.0)       # h1 in flight at t=0
        tr.pop_requests("p", now=55.0)      # still full: h2 stays queued
        tr.received(_h(1))
        self.assertEqual(tr.pop_requests("p", now=55.0), [2])
        self.assertEqual(tr.expire(now=100.0), 0)   # h2 requested at 55
        self.assertEqual(tr.expire(now=116.0), 1)


if __name__ == "__main__":
    unittest.main()
