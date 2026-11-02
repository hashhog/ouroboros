"""Inbound BIP324 handshake deadline + inbound-slot reservation (audit H1).

Security audit of ouroboros (audits/security/ouroboros-2026-10-30.md, H1):

* ``Peer.accept_inbound`` ran the 16-byte v1/v2 classify read and the whole
  ``_negotiate_v2_inbound`` responder handshake BEFORE entering the
  ``asyncio.timeout(HANDSHAKE_TIMEOUT)`` that bounds the version/verack
  exchange.  Each v2 read had only its own 10 s ``wait_for``, and the garbage
  terminator scan reads one byte at a time for up to MAX_GARBAGE_LEN+16 bytes,
  so a peer that drips one byte every few seconds held the socket for ~11 h.
* ``PeerManager._handle_inbound_connection`` compared ``len(inbound_peers)``
  to ``max_inbound`` but only added the peer AFTER the handshake, so
  in-flight handshakes were counted nowhere.  Proven live on regtest: 400
  sockets from one IP held past 152 s with ``getconnectioncount=0``.

Core: an accepted socket counts against ``nMaxInbound`` at once
(``CConnman::CreateNodeFromAcceptedSocket``), and a peer that has not
finished its version handshake within ``-peertimeout`` (60 s) is dropped
(``CConnman::InactivityCheck``) -- whatever transport it is on.

Tests:
  * ``test_v2_garbage_drip_aborted_within_handshake_timeout`` -- a fake
    stream sends a 64-byte ellswift key, then drips one garbage byte faster
    than the 10 s per-read timeout.  ``accept_inbound`` must return False
    within ~HANDSHAKE_TIMEOUT.
  * ``test_v2_garbage_drip_5s_aborted_within_handshake_timeout`` -- the same
    with a literal 5 s drip (the audit's attack interval).
  * ``test_pending_handshakes_count_toward_max_inbound`` -- with max_inbound
    connections still in their handshake, the next connection is refused
    before any read.
  * ``test_pending_slot_released_on_handshake_failure`` -- a failed handshake
    gives its slot back.
  * ``test_pending_slot_released_on_cancellation`` -- so does a cancelled one
    (node shutdown mid-handshake).
  * ``test_pending_slot_moves_to_inbound_peers_on_success`` -- a completed
    handshake trades its reservation for an ``inbound_peers`` entry, so the
    total held never exceeds max_inbound.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

import ouroboros.peer as peer_mod
from ouroboros.p2p import PeerManager
from ouroboros.peer import Peer, PeerState


class _Writer:
    """Accepts and discards whatever the responder sends (its ellswift key,
    garbage, terminator)."""

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

    def get_extra_info(self, name, default=None):
        return default


async def _drip(reader: asyncio.StreamReader, interval: float,
                stop: asyncio.Event) -> None:
    """The audit's attacker: a 64-byte ellswift key plus a 16-byte garbage
    window, then one random byte every ``interval`` seconds.  Random bytes
    never match the 16-byte garbage terminator, so the responder keeps
    scanning; each byte arrives inside its 10 s per-read timeout."""
    reader.feed_data(os.urandom(64 + 16))
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except (asyncio.TimeoutError, TimeoutError):
            reader.feed_data(os.urandom(1))


async def _run_drip(monkeypatch, handshake_timeout: float, drip: float,
                    guard: float) -> None:
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", handshake_timeout)
    reader = asyncio.StreamReader()
    stop = asyncio.Event()
    dripper = asyncio.create_task(_drip(reader, drip, stop))
    peer = Peer("203.0.113.20", 0, "regtest", transport_version=2,
                inbound=True)
    started = time.monotonic()
    try:
        # Without the fix this only ends when ``guard`` fires (the drip keeps
        # every 10 s per-read timer satisfied for ~4,100 reads).
        ok = await asyncio.wait_for(
            peer.accept_inbound(reader, _Writer(), start_height=0),
            timeout=guard,
        )
    finally:
        stop.set()
        await dripper
    elapsed = time.monotonic() - started

    assert ok is False, "a dripping v2 handshake must be refused"
    assert peer.state == PeerState.DISCONNECTED
    assert peer.reader is None and peer.writer is None, "socket released"
    # Ended on HANDSHAKE_TIMEOUT, not on some later per-read bound.
    assert elapsed < handshake_timeout + 2.0, elapsed


@pytest.mark.asyncio
async def test_v2_garbage_drip_aborted_within_handshake_timeout(monkeypatch):
    # Scaled: drip every 50 ms against a 0.5 s deadline (ratio as in the
    # audit's 8 s drip against 60 s).
    await _run_drip(monkeypatch, handshake_timeout=0.5, drip=0.05, guard=8.0)


@pytest.mark.asyncio
async def test_v2_garbage_drip_5s_aborted_within_handshake_timeout(monkeypatch):
    # The literal attack interval: one byte every 5 s keeps every 10 s
    # per-read timer alive; only the overall deadline (12 s here) ends it.
    await _run_drip(monkeypatch, handshake_timeout=12.0, drip=5.0, guard=40.0)


# --------------------------------------------------------------------------- #
# Inbound-slot reservation                                                    #
# --------------------------------------------------------------------------- #

class _ConnWriter(_Writer):
    """A writer for ``_handle_inbound_connection``: reports a peername."""

    def __init__(self, host: str, port: int):
        super().__init__()
        self._peername = (host, port)

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self._peername
        return default


class _GatedAccept:
    """Stands in for ``Peer.accept_inbound``: each call blocks until the test
    releases it with an outcome (True, False, or an exception)."""

    def __init__(self):
        self.calls: list[str] = []
        self._gates: dict[str, asyncio.Future] = {}

    def install(self, monkeypatch):
        gated = self

        async def _accept(peer, reader, writer, start_height=0):
            key = f"{peer.host}:{peer.port}"
            gated.calls.append(key)
            fut = asyncio.get_running_loop().create_future()
            gated._gates[key] = fut
            outcome = await fut
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome:
                peer.state = PeerState.READY
            return outcome

        monkeypatch.setattr(Peer, "accept_inbound", _accept)

    def release(self, key: str, outcome) -> None:
        self._gates[key].set_result(outcome)


def _manager(max_inbound: int) -> PeerManager:
    return PeerManager(network="regtest", listen=False, dns_seed=False,
                       max_inbound=max_inbound)


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0)


def _connect(pm: PeerManager, host: str, port: int = 40000):
    writer = _ConnWriter(host, port)
    task = asyncio.create_task(
        pm._handle_inbound_connection(asyncio.StreamReader(), writer))
    return task, writer


@pytest.mark.asyncio
async def test_pending_handshakes_count_toward_max_inbound(monkeypatch):
    gate = _GatedAccept()
    gate.install(monkeypatch)
    pm = _manager(max_inbound=3)

    # Three handshakes in flight, from distinct /16s (so the new-netgroup
    # reserve does not lower the limit).
    pending = [_connect(pm, f"10.{i}.0.1") for i in range(3)]
    await _settle()
    assert len(gate.calls) == 3
    assert pm.inbound_peers == {}

    # The fourth is refused before any read: the slots are all reserved.
    task, writer = _connect(pm, "10.9.0.1")
    await asyncio.wait_for(task, timeout=2.0)
    assert writer.closed, "fourth inbound must be refused while 3 are pending"
    assert len(gate.calls) == 3, "refused connection must not start a handshake"

    for i, (t, _) in enumerate(pending):
        gate.release(f"10.{i}.0.1:40000", False)
    await asyncio.gather(*(t for t, _ in pending))


@pytest.mark.asyncio
async def test_pending_slot_released_on_handshake_failure(monkeypatch):
    gate = _GatedAccept()
    gate.install(monkeypatch)
    pm = _manager(max_inbound=1)

    first, _ = _connect(pm, "10.1.0.1")
    await _settle()
    blocked, bw = _connect(pm, "10.2.0.1")
    await asyncio.wait_for(blocked, timeout=2.0)
    assert bw.closed

    gate.release("10.1.0.1:40000", False)
    await asyncio.wait_for(first, timeout=2.0)
    assert pm.inbound_peers == {}

    # Slot free again: the next connection gets a handshake.
    again, aw = _connect(pm, "10.3.0.1")
    await _settle()
    assert gate.calls[-1] == "10.3.0.1:40000"
    assert not aw.closed
    gate.release("10.3.0.1:40000", False)
    await asyncio.wait_for(again, timeout=2.0)


@pytest.mark.asyncio
async def test_pending_slot_released_on_cancellation(monkeypatch):
    gate = _GatedAccept()
    gate.install(monkeypatch)
    pm = _manager(max_inbound=1)

    first, _ = _connect(pm, "10.1.0.1")
    await _settle()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    again, aw = _connect(pm, "10.3.0.1")
    await _settle()
    assert gate.calls[-1] == "10.3.0.1:40000", "cancelled handshake leaked its slot"
    assert not aw.closed
    gate.release("10.3.0.1:40000", False)
    await asyncio.wait_for(again, timeout=2.0)


@pytest.mark.asyncio
async def test_pending_slot_moves_to_inbound_peers_on_success(monkeypatch):
    gate = _GatedAccept()
    gate.install(monkeypatch)
    pm = _manager(max_inbound=2)
    # Keep the post-handshake bookkeeping out of the way.
    monkeypatch.setattr(pm, "negotiate_compact_blocks",
                        lambda peer: asyncio.sleep(0))
    monkeypatch.setattr(pm, "_maybe_send_local_addr",
                        lambda peer: asyncio.sleep(0))

    a, _ = _connect(pm, "10.1.0.1")
    b, _ = _connect(pm, "10.2.0.1")
    await _settle()
    gate.release("10.1.0.1:40000", True)
    await asyncio.wait_for(a, timeout=2.0)
    assert list(pm.inbound_peers) == ["10.1.0.1:40000"]

    # One established + one pending = 2 = max_inbound.  Eviction cannot free
    # a slot (one candidate, and it is protected), so the third is refused.
    c, cw = _connect(pm, "10.3.0.1")
    await asyncio.wait_for(c, timeout=2.0)
    assert cw.closed
    assert "10.3.0.1:40000" not in gate.calls

    gate.release("10.2.0.1:40000", False)
    await asyncio.wait_for(b, timeout=2.0)
    for p in pm.inbound_peers.values():
        p.state = PeerState.DISCONNECTED
