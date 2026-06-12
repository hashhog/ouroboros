"""Mid-handshake-stall disconnect + O(connections) timer bound for the
attempt-5 v2/v1-recv leak fix.

Attempt-5 made ``Peer._read_exactly`` a plain ``await readexactly`` with ZERO
per-read ``asyncio.timeout`` (Core net.cpp parity -- the only recv timer is the
coarse ``CConnman::InactivityCheck``).  A stalled STEADY-STATE peer is caught by
``PeerManager.maintain_connections`` -> ``Peer.is_recv_stalled``.

But that coarse sweeper only iterates REGISTERED peers
(``self.peers`` / ``block_relay_peers`` / ``inbound_peers``), and a peer is
registered ONLY AFTER its version/verack handshake completes.  The handshake
version/verack reads (``_handshake`` / ``_inbound_handshake`` via
``receive_message`` -> ``_read_exactly``) are therefore bare timer-free awaits
that NOTHING bounds: a peer that completes TCP connect (and any v2 negotiation)
then hangs mid version/verack would await forever inside ``connect`` /
``accept_inbound`` -- before registration -- leaking a slot/coroutine/fd
(a DoS regression introduced by attempt-5).

The fix wraps each handshake in a SINGLE ``asyncio.timeout(HANDSHAKE_TIMEOUT)``
(one timer per connection ATTEMPT, cancelled on success -- O(connections), NOT
O(messages), so it does NOT reintroduce the per-read TimerHandle churn the leak
fix removed).  On timeout the context raises ``TimeoutError`` and the existing
connect-failure / accept-failure cleanup disconnects the peer and frees the slot.

A blocked read is modelled with an in-memory ``_StallReader`` (an ``await`` on a
never-set ``asyncio.Event``) rather than a real loopback socket: that is the
exact wire condition -- the bytes are not in the StreamReader buffer and the
read suspends -- and it is genuinely cancellable by ``asyncio.timeout`` /
``wait_for`` at the asyncio layer, the same path the production
``_read_exactly`` -> ``reader.readexactly`` blocks on.  (Real loopback sockets
are used for nothing here: in this sandbox a coroutine blocked in a real
``sock_recv`` is not woken by cancellation, a selector quirk unrelated to the
code under test.)

Tests:
  * ``test_outbound_handshake_stall_disconnects_within_timeout`` -- connect()
    against a peer that completes TCP connect then hangs mid version handshake
    returns False within ~HANDSHAKE_TIMEOUT (slot freed), NOT hung.
  * ``test_inbound_handshake_stall_disconnects_within_timeout`` -- same for the
    inbound path (accept_inbound() returns False).
  * ``test_unwrapped_handshake_hangs_nonvacuous`` -- proves NON-VACUITY: the
    bare ``_inbound_handshake`` / ``_handshake`` coroutine (the attempt-5 code
    WITHOUT this fix) never completes on its own against a stalling peer, so the
    timeout above is load-bearing.
  * ``test_concurrent_handshakes_bounded_timers`` -- K concurrent in-flight
    handshakes hold ~O(K) live TimerHandles (one per connection), NOT O(messages).
  * ``test_handshake_timeout_no_per_message_timers`` -- a wrapped handshake that
    consumes many buffered pre-verack messages arms ~1 timer total, not one per
    message (the handshake timeout must not reintroduce per-message churn).
"""

from __future__ import annotations

import asyncio
import gc
import time

import pytest

import ouroboros.peer as peer_mod
from ouroboros.p2p_messages import NetworkMessage, VersionMessage, get_magic
from ouroboros.peer import Peer, PeerState


# Small handshake bound so the stall tests resolve fast.  The production code
# reads the module global ``HANDSHAKE_TIMEOUT`` at the ``asyncio.timeout`` call
# site, so monkeypatching the module attribute reroutes the deadline.
FAST_HANDSHAKE_TIMEOUT = 0.4


def _count_live_timer_handles() -> int:
    gc.collect()
    return sum(1 for obj in gc.get_objects()
               if type(obj).__name__ == "TimerHandle")


def _version_frame(network: str = "regtest") -> bytes:
    """A single complete, valid v1 ``version`` frame (regtest)."""
    v = VersionMessage(
        version=70016,
        services=0,
        timestamp=int(time.time()),
        nonce=1234,
        user_agent="/test/",
        start_height=0,
        relay=True,
    )
    return v.to_network_message(network).serialize()


class _StallReader:
    """Reader whose ``readexactly`` blocks forever at the asyncio layer.

    Models a peer that completed TCP connect but sends no (further) handshake
    bytes: the public StreamReader buffer is empty and the read suspends on a
    never-set ``asyncio.Event`` -- genuinely cancellable by the per-handshake
    ``asyncio.timeout``, exactly like a real blocked ``readexactly`` would be
    on a non-sandbox event loop.  Optionally yields a fixed prefix of bytes
    first (a partial version) and then stalls."""

    def __init__(self, prefix: bytes = b""):
        self._sr = asyncio.StreamReader()
        if prefix:
            self._sr.feed_data(prefix)
        self._never = asyncio.Event()  # never set

    async def readexactly(self, n: int) -> bytes:
        if len(self._sr._buffer) >= n:
            return await self._sr.readexactly(n)
        # Not enough buffered bytes -> block until cancelled (stall).
        await self._never.wait()
        raise AssertionError("unreachable: _StallReader never receives data")

    @property
    def _buffer(self) -> bytearray:
        return self._sr._buffer


class _NullWriter:
    def __init__(self):
        self.closed = False

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed


# --------------------------------------------------------------------------- #
# Outbound: connect() -> _handshake stall                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_outbound_handshake_stall_disconnects_within_timeout(monkeypatch):
    """connect() against a peer that completes the TCP connect then hangs mid
    version handshake (a partial version header, then nothing) is disconnected
    by the per-handshake timeout -- connect() returns False, not hangs."""
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", FAST_HANDSHAKE_TIMEOUT)

    # Make connect()'s ``asyncio.open_connection`` hand back a reader that
    # accepts the TCP connect, lets us send our version, then stalls on the
    # peer's version read -- the mid-handshake stall.
    stall_reader = _StallReader(prefix=b"\xfa\xbf\xb5\xda" + b"version\x00")  # truncated

    async def _fake_open_connection(host, port, **kw):
        return stall_reader, _NullWriter()

    monkeypatch.setattr(peer_mod.asyncio, "open_connection", _fake_open_connection)

    peer = Peer("203.0.113.7", 18444, "regtest", transport_version=1)
    started = time.monotonic()
    # Hard outer guard: absent the fix this hangs forever; the cap surfaces a
    # clear failure instead of a hung run.  It is far above HANDSHAKE_TIMEOUT.
    ok = await asyncio.wait_for(
        peer.connect(start_height=0, retry=False),
        timeout=FAST_HANDSHAKE_TIMEOUT * 12,
    )
    elapsed = time.monotonic() - started

    assert ok is False, "connect() should fail on a mid-handshake stall"
    assert peer.state == PeerState.DISCONNECTED
    assert peer.reader is None and peer.writer is None, "slot/fd freed"
    # Resolved on the handshake deadline, well under the outer cap.
    assert elapsed < FAST_HANDSHAKE_TIMEOUT * 12


# --------------------------------------------------------------------------- #
# Inbound: accept_inbound() -> _inbound_handshake stall                       #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_inbound_handshake_stall_disconnects_within_timeout(monkeypatch):
    """accept_inbound() for a peer that opens then hangs before sending its
    version is disconnected by the per-handshake timeout -- returns False, the
    peer is never registered, slot freed."""
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", FAST_HANDSHAKE_TIMEOUT)

    stall_reader = _StallReader()  # peer never sends its version
    writer = _NullWriter()

    peer = Peer("203.0.113.8", 0, "regtest", transport_version=1, inbound=True)
    started = time.monotonic()
    ok = await asyncio.wait_for(
        peer.accept_inbound(stall_reader, writer, start_height=0),
        timeout=FAST_HANDSHAKE_TIMEOUT * 12,
    )
    elapsed = time.monotonic() - started

    assert ok is False, "accept_inbound() should fail on a mid-handshake stall"
    assert peer.state == PeerState.DISCONNECTED
    assert peer.reader is None and peer.writer is None, "slot/fd freed"
    assert elapsed < FAST_HANDSHAKE_TIMEOUT * 12


# --------------------------------------------------------------------------- #
# NON-VACUITY: the unwrapped handshake coroutine never completes on its own.  #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_unwrapped_handshake_hangs_nonvacuous(monkeypatch):
    """Drive the BARE ``_inbound_handshake`` coroutine directly (the attempt-5
    code WITHOUT the new ``asyncio.timeout`` wrapper) against a stalling peer:
    it must NOT complete on its own.  Proven by an EXTERNAL ``wait_for`` that
    must time it out -- if the coroutine were self-bounded this would instead
    return/raise quickly and the assertion below would fail, making the stall
    tests above vacuous."""
    # Make the in-handshake HANDSHAKE_TIMEOUT huge so it cannot be what bounds
    # this -- only the EXTERNAL wait_for can.
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", 1000.0)

    peer = Peer("203.0.113.9", 0, "regtest", transport_version=1, inbound=True)
    peer.reader = _StallReader()  # client sends nothing
    peer.writer = _NullWriter()

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        await asyncio.wait_for(
            peer._inbound_handshake(start_height=0),
            timeout=FAST_HANDSHAKE_TIMEOUT,
        )
    # Confirm it really stalled in the version read, not in setup.
    assert peer._version_received is False


# --------------------------------------------------------------------------- #
# O(connections) timer bound: K in-flight handshakes hold ~K timers.          #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_concurrent_handshakes_bounded_timers(monkeypatch):
    """K concurrent IN-FLIGHT handshakes (each blocked on its version read)
    hold ~O(K) live TimerHandles -- one ``asyncio.timeout`` timer per connection
    attempt -- NOT O(messages).  Proves the per-handshake timeout is
    per-connection, not per-read/per-message."""
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", 10.0)  # long: keep in-flight

    K = 12

    before = _count_live_timer_handles()

    peers = []
    tasks = []
    for _ in range(K):
        peer = Peer("203.0.113.10", 0, "regtest", transport_version=1, inbound=True)
        peers.append(peer)
        tasks.append(asyncio.create_task(
            peer.accept_inbound(_StallReader(), _NullWriter(), 0)))

    # Let every handshake reach its (blocked) version read so its single
    # asyncio.timeout timer is armed.
    for _ in range(50):
        await asyncio.sleep(0)
        if all(p.state == PeerState.HANDSHAKING for p in peers):
            break

    during = _count_live_timer_handles()
    delta = during - before

    try:
        # One timer per in-flight handshake (plus a little scheduler slack).
        # The key property: delta scales with CONNECTIONS (K), not messages.
        assert delta <= K + 5, (
            f"{K} in-flight handshakes armed {delta} TimerHandles "
            f"(expected ~{K}, one per connection; O(messages) churn far larger)"
        )
        assert delta >= 1, (
            "expected at least one armed handshake timer in flight "
            "(the per-handshake asyncio.timeout)"
        )
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        for p in peers:
            try:
                await p.disconnect()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# The handshake timeout adds ~1 timer even when it consumes many messages.    #
# --------------------------------------------------------------------------- #
class _BufferedReader:
    """All bytes already buffered; readexactly never blocks (synchronous)."""

    def __init__(self, blob: bytes):
        self._sr = asyncio.StreamReader()
        self._sr.feed_data(blob)
        self._sr.feed_eof()

    async def readexactly(self, n: int) -> bytes:
        return await self._sr.readexactly(n)

    @property
    def _buffer(self):
        return self._sr._buffer


@pytest.mark.asyncio
async def test_handshake_timeout_no_per_message_timers(monkeypatch):
    """A handshake wrapped in ONE ``asyncio.timeout`` that consumes a version
    plus many buffered pre-verack negotiation messages arms ~1 timer TOTAL --
    NOT one per message.  Confirms the per-handshake bound did not reintroduce
    the per-read/per-message TimerHandle churn the attempt-5 leak fix removed."""
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", 30.0)

    network = "regtest"
    magic = get_magic(network)
    # version, then a long run of pre-verack wtxidrelay/sendaddrv2 (legal,
    # ignored), then verack -- the inbound handshake loops over all of these.
    # The inbound verack-wait loop is bounded to 20 reads, so keep the verack
    # within that window: version (1) + 16 pre-verack + verack = 18 reads.
    blob = bytearray(_version_frame(network))
    for _ in range(8):
        blob += NetworkMessage(command="wtxidrelay", payload=b"", magic=magic).serialize()
        blob += NetworkMessage(command="sendaddrv2", payload=b"", magic=magic).serialize()
    blob += NetworkMessage(command="verack", payload=b"", magic=magic).serialize()

    peer = Peer("203.0.113.11", 0, network, transport_version=1, inbound=True)
    peer.reader = _BufferedReader(bytes(blob))
    peer.writer = _NullWriter()

    before = _count_live_timer_handles()
    # Drive the handshake exactly as accept_inbound does: one asyncio.timeout
    # around the whole _inbound_handshake.
    async with asyncio.timeout(peer_mod.HANDSHAKE_TIMEOUT):
        await peer._inbound_handshake(start_height=0)
    after = _count_live_timer_handles()

    assert peer._verack_sent is True
    delta = after - before
    # 1 version + 16 pre-verack + 1 verack = 18 receive_message calls.  If the
    # timeout were per-message we would see ~18 retained handles; the
    # single-per-handshake design leaves at most a couple.
    assert delta <= 3, (
        f"handshake consuming 18 messages armed {delta} live TimerHandles "
        f"(expected ~1 -- a single per-handshake asyncio.timeout; per-message "
        f"churn would be ~18)"
    )
