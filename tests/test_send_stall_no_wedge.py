"""One peer that stops reading must not wedge block connection.

Live, mainnet 2026-10-05 (ouroboros d94041f): block 969990 connected at
05:34:52 (its mempool removal logged) but its "✓ Block 969990 connected" line
never appeared; the drain loop's 30 s heartbeat stopped at the same instant;
no block connected for 45 min although 969991 was delivered and buffered; the
W75-RECOVER map reset at 06:20:25 changed nothing; a process restart fixed it.

Root cause: after the connect commit, ``_drain_block_buffer_locked`` awaited
``_announce_block``, which awaited ``Peer.send_message`` → ``writer.drain()``
on each ready peer in turn.  ``drain()`` parks until the peer reads; a peer
that stopped reading parks it forever.  The coroutine held ``_drain_lock``, and
``_drain_block_buffer`` returns 0 whenever the lock is held — so every later
drain was a no-op.  W75's reset clears the queue/buffer/in-flight maps but not
the coroutine holding the lock; a restart kills the coroutine.

Core: SocketSendData is non-blocking; a full send buffer pauses only THAT
peer (fPauseSend) and InactivityCheck disconnects a peer whose sends make no
progress.  Announcements come from SendMessages, decoupled from
ActivateBestChain.

No TCP ports are used: the stalled peer is one end of a ``socketpair`` whose
other end is never read.
"""
from __future__ import annotations

import asyncio
import socket
import time
from types import SimpleNamespace

import pytest

import tests.conftest  # noqa: F401  (installs the sync stub first)
from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import NetworkMessage
from ouroboros.peer import Peer, PeerState


def _big_msg(n: int = 200_000) -> NetworkMessage:
    return NetworkMessage(command="cmpctblock", payload=b"\x00" * n)


async def _peer_on_socketpair(drain_other_end: bool):
    """A READY Peer whose remote end either never reads or reads everything."""
    ours, theirs = socket.socketpair()
    ours.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    theirs.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    reader, writer = await asyncio.open_connection(sock=ours)
    peer = Peer("203.0.113.9", 8333, network="mainnet")
    peer.reader, peer.writer = reader, writer
    peer.state = PeerState.READY
    peer._send_stall_timeout = 0.5
    sink = None
    if drain_other_end:
        r2, w2 = await asyncio.open_connection(sock=theirs)

        async def _sink():
            while await r2.read(1 << 16):
                pass
        sink = asyncio.ensure_future(_sink())
        return peer, (sink, w2)
    return peer, theirs


def test_send_to_peer_that_stopped_reading_is_bounded():
    async def run():
        peer, theirs = await _peer_on_socketpair(drain_other_end=False)
        try:
            async def flood():
                for _ in range(50):          # 10 MB: far past every buffer
                    await peer.send_message(_big_msg())
            try:
                await asyncio.wait_for(flood(), 5.0)
            except TimeoutError:
                pytest.fail("send_message parked >5 s on a peer that is not "
                            "reading (unbounded writer.drain())")
            except ConnectionError:
                pass  # the bounded path: aborted + raised
            else:
                pytest.fail("10 MB was 'sent' to a peer that reads nothing")
            assert peer.state == PeerState.DISCONNECTED
            assert not peer.is_connected()
        finally:
            theirs.close()
    asyncio.run(run())


def test_healthy_reader_is_not_cut_off():
    """Negative control: the bound must not disconnect a peer that drains."""
    async def run():
        peer, (sink, w2) = await _peer_on_socketpair(drain_other_end=True)
        try:
            for _ in range(50):
                await asyncio.wait_for(peer.send_message(_big_msg()), 5.0)
            assert peer.state == PeerState.READY
        finally:
            peer.writer.close()
            w2.close()
            sink.cancel()
    asyncio.run(run())


def test_repeat_disconnect_leaves_ready():
    """A second disconnect() of a peer still READY must take it out of READY
    (live: the sweep 'disconnected' one peer 208 times in 3 h, no effect)."""
    async def run():
        peer, theirs = await _peer_on_socketpair(drain_other_end=False)
        try:
            peer._disconnect_started = True     # first teardown never finished
            peer.state = PeerState.READY
            await asyncio.wait_for(peer.disconnect(), 2.0)
            assert not peer.is_connected()
        finally:
            theirs.close()
    asyncio.run(run())


# ---------------------------------------------------------------------------
# The real drain loop: a stuck announce must not hold _drain_lock
# ---------------------------------------------------------------------------


def _coinbase_scriptsig(height: int) -> bytes:
    enc = height.to_bytes(4, "little").rstrip(b"\x00")
    if enc[-1] & 0x80:
        enc += b"\x00"
    return bytes([len(enc)]) + enc + b"\x00"


def _block(height: int, prev: bytes):
    cb = SimpleNamespace(inputs=[SimpleNamespace(script_sig=_coinbase_scriptsig(height))])
    return SimpleNamespace(
        transactions=[cb], prev_blockhash=prev, timestamp=int(time.time()),
        version=0x20000000, merkle_root=b"\x00" * 32, bits=0x17021EF0, nonce=0,
    )


class _ChainDB:
    def __init__(self, tip_hash, tip_height):
        self.tip = (tip_hash, tip_height)

    def get_best_block(self):
        return self.tip

    def get_block_bytes(self, h):
        return None


class _Validator:
    def __init__(self, db, hashes):
        self.db, self.hashes = db, hashes

    def validate_block(self, block, **kw):
        return True, ""

    def apply_block(self, block):
        h = self.hashes[id(block)]
        self.db.tip = (h, self.db.tip[1] + 1)


class _StuckPeer:
    """A ready peer whose socket never drains (send parks forever)."""
    host, port = "198.51.100.66", 8333
    wants_cmpctblock = False
    wants_headers = True

    def __init__(self):
        self.parked = 0

    async def send_message(self, msg):
        self.parked += 1
        await asyncio.Event().wait()


def test_stuck_announce_does_not_hold_drain_lock():
    async def run():
        h0, h1, h2 = b"\x10" * 32, b"\x11" * 32, b"\x12" * 32
        db = _ChainDB(h0, 969989)
        b1, b2 = _block(969990, h0), _block(969991, h1)
        validator = _Validator(db, {id(b1): h1, id(b2): h2})
        stuck = _StuckPeer()
        pm = SimpleNamespace(network="mainnet",
                             get_all_ready_peers=lambda: [stuck])
        bs = BlockSync(db=db, validator=validator, peer_manager=pm)
        bs._prebase_headers_complete = True

        bs._validated_headers = [(h1, SimpleNamespace(prev_blockhash=h0))]
        bs._buffer_put(h1, (b1, b"raw1"))
        n = await asyncio.wait_for(bs._drain_block_buffer(), 5.0)
        assert n == 1 and db.tip == (h1, 969990)
        await asyncio.sleep(0.05)
        assert stuck.parked == 1, "the tip was never announced"
        assert not bs._drain_lock.locked(), "announce is holding _drain_lock"

        # The next block must connect while the first announce is still parked.
        bs._validated_headers = [(h2, SimpleNamespace(prev_blockhash=h1))]
        bs._buffer_put(h2, (b2, b"raw2"))
        n = await asyncio.wait_for(bs._drain_block_buffer(), 5.0)
        assert n == 1 and db.tip == (h2, 969991)
        for t in list(bs._announce_tasks):
            t.cancel()
    try:
        asyncio.run(asyncio.wait_for(run(), 10.0))
    except TimeoutError:
        pytest.fail("drain parked on a peer that never drains its socket "
                    "(announce awaited under _drain_lock)")


def test_slow_but_progressing_reader_is_not_cut_off():
    """Core drops only a peer whose sends make NO progress: a reader slower
    than the stall window, but steadily draining, must keep its connection."""
    async def run():
        ours, theirs = socket.socketpair()
        ours.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        theirs.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        reader, writer = await asyncio.open_connection(sock=ours)
        peer = Peer("203.0.113.10", 8333, network="mainnet")
        peer.reader, peer.writer = reader, writer
        peer.state = PeerState.READY
        peer._send_stall_timeout = 1.0
        # The reading StreamReader pulls in 64 KB bursts (its buffer limit),
        # so progress is visible about every 0.4 s at this rate; the whole
        # 200 KB message still takes ~1.25 s — longer than the stall window.
        r2, w2 = await asyncio.open_connection(sock=theirs, limit=16384)

        async def trickle():              # ~160 KB/s
            while await r2.read(8192):
                await asyncio.sleep(0.05)
        sink = asyncio.ensure_future(trickle())
        try:
            await asyncio.wait_for(peer.send_message(_big_msg()), 10.0)
            await asyncio.wait_for(peer.send_message(_big_msg()), 10.0)
            assert peer.state == PeerState.READY
        finally:
            peer.writer.close()
            w2.close()
            sink.cancel()
    asyncio.run(run())
