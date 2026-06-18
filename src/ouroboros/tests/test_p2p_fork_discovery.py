"""GAP1 regression tests for the P2P reorg-drop fix (fork-header discovery).

Production blocker (tools/reorg-ouroboros-proof.sh): R1 on chain A connects to
R3 serving a heavier chain B forking at genesis.  R3 already serves chain B
headers and R1 already sends getheaders every tick, but R1's handle_headers
DROPPED every chain-B batch at the tip-anchored continuity check — a header
whose prev is a KNOWN hash but which does NOT extend the active tip was treated
as "unconnecting" and discarded, so the heavier fork was never discovered and
R1 stayed on chain A forever.

GAP1 (this phase) admits such headers into a SEPARATE bounded fork store
(``_fork_headers``) instead of dropping them, keeping ``_validated_headers``
linear + tip-anchored (the normal tip-extension path stays byte-identical), and
fires the heavier-fork download trigger when the stored fork is strictly
heavier than the active best chain.

These tests exercise handle_headers / handle_inv against an in-memory stub DB,
mirroring the fixture style of test_block_request_leak.py.
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
    InvMessage,
    INV_TYPE_BLOCK,
)
from ouroboros.peer import Peer, PeerState  # noqa: E402

# regtest powLimit: any double-SHA256 hash is <= this target, so every header
# we build trivially passes the per-header PoW gate (_header_meets_pow).
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
    """Build a header whose double-SHA256 actually meets REGTEST_BITS.

    The regtest powLimit (0x207fffff) leaves ~half of random hashes ABOVE
    target (byte-31, the LE most-significant, must be <= 0x7f), so we mine the
    nonce until the hash passes — exactly what _header_meets_pow checks.
    """
    # Vary the merkle_root (a 32-byte field, no uint32 limit) to search for a
    # passing hash; keep nonce in valid uint32 range.
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
        digest = _dsha(h.serialize())
        if int.from_bytes(digest, "little") <= _REGTEST_TARGET:
            return h
    raise AssertionError("could not mine a passing regtest header")


def _header_hash(h: BlockHeader) -> bytes:
    return _dsha(h.serialize())


class _StubDB:
    """In-memory active chain: a list of block hashes by height (0 = genesis)."""

    def __init__(self, chain: list[bytes]):
        # chain[i] == hash at height i; chain[-1] is the tip.
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
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)
        return None

    p.send_message = _send
    return p


def _fresh(chain_len=10):
    # Build an active chain of length chain_len (genesis + chain_len-1 blocks).
    chain = [_dsha(b"genesis")]
    for i in range(1, chain_len):
        chain.append(_dsha(b"A" + i.to_bytes(8, "little")))
    db = _StubDB(chain)
    peer = _make_peer(1)
    pm = _StubPeerManager([peer])
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=db, validator=None, peer_manager=pm, mempool=None)
    return bs, db, peer, chain


class TestP2PForkDiscovery(unittest.IsolatedAsyncioTestCase):
    async def test_below_tip_fork_header_stored_not_validated(self):
        """A header whose prev is a KNOWN active-chain block but which does NOT
        extend the active tip goes into _fork_headers, never _validated_headers."""
        bs, db, peer, chain = _fresh(chain_len=10)
        # Fork off height 0 (genesis), competing with chain A.
        fork_prev = chain[0]
        fork_hdr = _make_header(fork_prev, nonce=1)
        fork_hash = _header_hash(fork_hdr)

        msg = HeadersMessage([fork_hdr]).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)

        self.assertIn(fork_hash, bs._fork_headers)
        self.assertEqual(bs._fork_header_prev[fork_hash], fork_prev)
        self.assertNotIn(
            fork_hash, {h for h, _ in bs._validated_headers},
            "fork header must not pollute the tip-anchored validated queue",
        )

    async def test_tip_extension_path_unchanged(self):
        """A header that extends the active tip still lands in _validated_headers
        and does NOT touch the fork store (normal IBD path byte-identical)."""
        bs, db, peer, chain = _fresh(chain_len=10)
        tip = chain[-1]
        next_hdr = _make_header(tip, nonce=99)
        next_hash = _header_hash(next_hdr)

        msg = HeadersMessage([next_hdr]).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)

        self.assertIn(next_hash, {h for h, _ in bs._validated_headers})
        self.assertEqual(len(bs._fork_headers), 0)

    async def test_multi_header_fork_chains_on_itself(self):
        """A multi-header fork batch (h1 forks off a known block, h2 builds on
        h1, ...) is admitted in full — later members chain on earlier fork
        members, not on the active tip."""
        bs, db, peer, chain = _fresh(chain_len=5)
        # Fork at genesis, build 8 fork blocks => fork height 8 > active tip 4.
        fork_prev = chain[0]
        hdrs = []
        prev = fork_prev
        for n in range(1, 9):
            h = _make_header(prev, nonce=1000 + n)
            hdrs.append(h)
            prev = _header_hash(h)
        msg = HeadersMessage(hdrs).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)

        self.assertEqual(len(bs._fork_headers), 8)
        self.assertEqual(len(bs._validated_headers), 0)
        # The fork tip should be the last header, at height 8.
        fork_tip = _header_hash(hdrs[-1])
        self.assertEqual(bs._fork_tip_height(fork_tip), 8)

    async def test_heavier_fork_triggers_download(self):
        """A stored fork strictly heavier than the active chain fires the
        heavier-fork trigger (returns True / bumps _fork_reorg_triggered)."""
        bs, db, peer, chain = _fresh(chain_len=5)  # active tip height = 4
        fork_prev = chain[0]
        hdrs = []
        prev = fork_prev
        for n in range(1, 7):  # 6 fork blocks => fork tip height 6 > 4
            h = _make_header(prev, nonce=2000 + n)
            hdrs.append(h)
            prev = _header_hash(h)
        msg = HeadersMessage(hdrs).to_network_message("regtest")
        before = bs._fork_reorg_triggered
        await bs.handle_headers(msg, peer, min_pow_checked=True)
        self.assertEqual(bs._fork_reorg_triggered, before + 1)

    async def test_lighter_fork_does_not_trigger(self):
        """A stored fork NOT heavier than the active chain is kept but does not
        trigger a reorg download."""
        bs, db, peer, chain = _fresh(chain_len=10)  # active tip height = 9
        fork_prev = chain[0]
        hdrs = []
        prev = fork_prev
        for n in range(1, 4):  # 3 fork blocks => fork tip height 3 < 9
            h = _make_header(prev, nonce=3000 + n)
            hdrs.append(h)
            prev = _header_hash(h)
        msg = HeadersMessage(hdrs).to_network_message("regtest")
        before = bs._fork_reorg_triggered
        await bs.handle_headers(msg, peer, min_pow_checked=True)
        self.assertEqual(len(bs._fork_headers), 3)
        self.assertEqual(bs._fork_reorg_triggered, before)

    async def test_unknown_prev_header_not_stored_and_banned_path(self):
        """A header whose prev is genuinely unknown (not active chain, not in
        fork store) is NOT admitted to the fork store and is treated as
        unconnecting (a fork getheaders is sent, DoS counter advances)."""
        bs, db, peer, chain = _fresh(chain_len=10)
        unknown_prev = _dsha(b"nowhere")
        hdr = _make_header(unknown_prev, nonce=4242)
        hdr_hash = _header_hash(hdr)
        msg = HeadersMessage([hdr]).to_network_message("regtest")
        await bs.handle_headers(msg, peer, min_pow_checked=True)
        self.assertNotIn(hdr_hash, bs._fork_headers)
        # An unconnecting-headers getheaders should have been sent.
        self.assertTrue(any(m.command == "getheaders" for m in peer.sent))

    async def test_handle_inv_unknown_block_sends_getheaders(self):
        """An unknown-block inv triggers a (rate-limited) getheaders with a
        full locator so a competing fork announced only via inv is chased."""
        bs, db, peer, chain = _fresh(chain_len=10)
        unknown = _dsha(b"competing-tip")
        inv = InvMessage([(INV_TYPE_BLOCK, unknown)]).to_network_message("regtest")
        await bs.handle_inv(inv, peer)
        self.assertTrue(any(m.command == "getheaders" for m in peer.sent))

    async def test_fork_getheaders_rate_limited(self):
        """Repeated unknown-block invs for the same hash do not flood the peer
        with getheaders (rate-limited per hash)."""
        bs, db, peer, chain = _fresh(chain_len=10)
        unknown = _dsha(b"spam-tip")
        inv = InvMessage([(INV_TYPE_BLOCK, unknown)]).to_network_message("regtest")
        for _ in range(5):
            await bs.handle_inv(inv, peer)
        gh = [m for m in peer.sent if m.command == "getheaders"]
        self.assertEqual(len(gh), 1, "fork getheaders must be rate-limited")

    async def test_fork_store_bounded(self):
        """The fork store evicts oldest entries past its cap."""
        bs, db, peer, chain = _fresh(chain_len=10)
        bs._fork_headers_max = 4
        fork_prev = chain[0]
        # Store more distinct forks (each forking off genesis) than the cap.
        for n in range(10):
            h = _make_header(fork_prev, nonce=5000 + n)
            bs._store_fork_header(_header_hash(h), h, fork_prev)
        self.assertLessEqual(len(bs._fork_headers), 4)
        self.assertLessEqual(len(bs._fork_header_prev), 4)


if __name__ == "__main__":
    unittest.main()
