"""getheaders is served from headers, never from full blocks (audit H4).

``_make_getheaders_handler`` used to call ``db.get_block_by_height`` for each
of up to 2000 heights: a full RocksDB block read, a PyO3 ``PyBlock`` with one
Python object per tx / input / output, then ``_py_block_to_block`` — all to
copy six header fields.  ~11.7 ms per 3000-tx block, so one 82-byte request
cost >= 23 s of GIL-held CPU and could be pipelined without penalty.  Core
copies the headers out of ``CBlockIndex`` (``ProcessGetHeaders``) and never
reads a block body.

These tests run the real handler over the real compiled ``sync`` extension
(``tests/_f0_chain.Chain``) with the database wrapped in a spy:

* the handler never calls ``get_block`` / ``get_block_by_height``;
* the served ``headers`` payload is byte-identical to the 80-byte headers in
  the stored blocks AND to the headers the old full-block path built, for
  every locator / hash_stop shape the handler distinguishes.

The reply STARTS where Core's does (sm-fix-ouroboros-getheaders-locator):
after the first locator entry on the active chain, or at height 1 when none
matches (FindForkInGlobalIndex falls back to genesis, then
ActiveChain().Next).  The old full-block path started at height 1 for every
matched locator and at height 0 for an unmatched one, because it read
``height`` off a block object that never carries it; the reference below
keeps that path's header construction and takes Core's start height.
"""

from __future__ import annotations

import asyncio

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests._f0_chain import Chain  # noqa: E402

TIP = 8
FULL_BLOCK_READS = ("get_block", "get_block_by_height")


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


class _SpyDB:
    """Delegates to a real ``BlockchainDatabase``; records every method call."""

    def __init__(self, real):
        self._real = real
        self.calls: list[str] = []

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if not callable(attr):
            return attr

        def wrapped(*args, **kwargs):
            self.calls.append(name)
            return attr(*args, **kwargs)

        return wrapped


class _StubPeer:
    host = "127.0.0.1"
    port = 0
    network = "regtest"

    def __init__(self):
        self.handlers: dict = {}
        self.sent: list = []

    def register_handler(self, name, fn):
        self.handlers[name] = fn

    async def send_message(self, msg):
        self.sent.append(msg)


class _StubPeerManager:
    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return self._peers

    def set_inbound_peer_handler(self, cb):
        pass

    def set_outbound_peer_handler(self, cb):
        pass


@pytest.fixture
def served(tmp_path):
    """(spy db, real db, getheaders handler, peer) over a TIP-block regtest chain."""
    from ouroboros.database import BlockchainDatabase
    from ouroboros.node import BitcoinNode

    real = BlockchainDatabase(str(tmp_path / "db"))
    Chain(real._db, tip=TIP)
    spy = _SpyDB(real)

    peer = _StubPeer()
    node = BitcoinNode.__new__(BitcoinNode)
    node.db = spy
    node.block_filter_index = None
    node.peer_manager = _StubPeerManager([peer])
    node.mempool = None
    node._register_handlers()
    handler = peer.handlers["getheaders"]
    return spy, real, handler, peer


def _request(handler, peer, locator, hash_stop=b"\x00" * 32) -> bytes:
    from ouroboros.p2p_messages import GetHeadersMessage

    peer.sent.clear()
    msg = GetHeadersMessage(
        version=70016, locator_hashes=list(locator), hash_stop=hash_stop,
    ).to_network_message("regtest")
    asyncio.run(handler(msg))
    assert len(peer.sent) == 1, f"expected one reply, got {len(peer.sent)}"
    assert peer.sent[0].command == "headers"
    return peer.sent[0].payload


def _stored_headers(real, heights) -> list[bytes]:
    """The 80 header bytes of each stored block, straight from BLOCKS_CF."""
    return [
        bytes(real.get_block_bytes(real.get_block_hash_by_height(h))[:80])
        for h in heights
    ]


def _headers_payload(headers80: list[bytes]) -> bytes:
    """Wire ``headers`` payload: count, then each header + a 0 tx count."""
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage

    return HeadersMessage(
        headers=[BlockHeader.from_payload(h)[0] for h in headers80]
    ).serialize_payload()


def _full_block_reply_from_core_fork(real, locator, hash_stop=b"\x00" * 32) -> bytes:
    """Reference reply: headers built from full blocks (get_block_by_height),
    the way the pre-H4 handler built them, starting at Core's fork point —
    the block after the first locator entry the active chain contains
    (found by a linear scan of the active chain, independent of the hash
    index the handler uses), else height 1."""
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage

    _, best = real.get_best_block()
    active = {real.get_block_hash_by_height(h): h for h in range(best + 1)}
    start = 1
    for loc in locator:
        if loc in active:
            start = active[loc] + 1
            break
    headers = []
    for h in range(start, min(start + 2000, best + 1)):
        blk = real.get_block_by_height(h)
        if blk is None:
            break
        headers.append(BlockHeader(
            version=blk.version, prev_blockhash=blk.prev_blockhash,
            merkle_root=blk.merkle_root, timestamp=blk.timestamp,
            bits=blk.bits, nonce=blk.nonce,
        ))
        if hash_stop != b"\x00" * 32 and blk.hash == hash_stop:
            break
    return HeadersMessage(headers=headers).serialize_payload()


def _cases(real):
    h = real.get_block_hash_by_height
    unknown = b"\x11" * 32
    return {
        "unknown_locator": ([unknown], b"\x00" * 32),
        "empty_locator": ([], b"\x00" * 32),
        "genesis_locator": ([h(0)], b"\x00" * 32),
        "mid_chain_locator": ([unknown, h(5), h(2)], b"\x00" * 32),
        "tip_locator": ([h(TIP)], b"\x00" * 32),
        "hash_stop_mid_chain": ([unknown], h(4)),
        "hash_stop_unknown": ([unknown], b"\x22" * 32),
    }


def test_getheaders_never_reads_full_blocks(served):
    """No get_block / get_block_by_height for any locator / hash_stop shape."""
    spy, real, handler, peer = served
    for name, (locator, stop) in _cases(real).items():
        spy.calls.clear()
        _request(handler, peer, locator, stop)
        hits = [c for c in spy.calls if c in FULL_BLOCK_READS]
        assert not hits, (
            f"{name}: getheaders read full blocks ({len(hits)} x "
            f"{sorted(set(hits))}) to copy 80-byte headers — audit H4"
        )


def test_getheaders_unknown_locator_serves_stored_header_bytes(served):
    """A missed locator serves 1..tip (Core: genesis is the fork point, the
    reply starts at its successor), byte-identical to BLOCKS_CF."""
    _, real, handler, peer = served
    payload = _request(handler, peer, [b"\x11" * 32])
    assert payload == _headers_payload(_stored_headers(real, range(1, TIP + 1)))


def test_getheaders_hash_stop_serves_stored_header_bytes(served):
    """hash_stop at height 4 ends the reply at (and including) height 4."""
    _, real, handler, peer = served
    payload = _request(
        handler, peer, [b"\x11" * 32], real.get_block_hash_by_height(4),
    )
    assert payload == _headers_payload(_stored_headers(real, range(1, 5)))


def test_getheaders_reply_matches_full_block_headers_from_core_fork(served):
    """Every case answers byte-for-byte the full-block path's headers, from
    Core's fork point.  This test used to be
    ``test_getheaders_reply_unchanged_from_full_block_path`` and compared
    against the old path's start height too, which pinned the bug: height 1
    for every matched locator, so a tip locator got the whole chain back."""
    _, real, handler, peer = served
    for name, (locator, stop) in _cases(real).items():
        got = _request(handler, peer, locator, stop)
        assert got == _full_block_reply_from_core_fork(real, locator, stop), name
