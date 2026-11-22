"""Outbound BIP324 handshake deadline (cffix-ouroboros-outbound-v2-deadline).

``Peer.connect`` awaited ``_negotiate_v2()`` BEFORE entering the
``asyncio.timeout(HANDSHAKE_TIMEOUT)`` that bounds the version/verack
exchange.  Each v2 read had only its own 5-10 s ``wait_for``, and the
garbage-terminator scan reads one byte at a time for up to
MAX_GARBAGE_LEN+16 (4111) bytes, then up to 1024 decoy packets.  A remote
that answers with a 64-byte ellswift key and then drips one garbage byte
every few seconds kept the dial pending for ~11 h.  Dials are awaited inline
in ``PeerManager.maintain_connections``, so one such peer stalled outbound
maintenance for the whole node.  The inbound sibling was bounded in
``accept_inbound`` already (test_v2_inbound_handshake_deadline.py).

Core: ``CConnman::InactivityCheck`` (net.cpp) disconnects any peer that is
not fully connected within ``-peertimeout`` -- "V2 handshake timeout" while
the transport is still detecting/negotiating, "version handshake timeout"
after -- regardless of direction.  A peer that sent us bytes is not retried
over v1 (``V2Transport::ShouldReconnectV1`` needs an empty receive buffer).

The fixture is a real loopback TCP server: it sends a 64-byte key plus a
16-byte garbage window, then drips one random byte every ``drip`` seconds,
which never matches the garbage terminator and always arrives inside the
10 s per-read wait.  With ``HANDSHAKE_TIMEOUT`` scaled down, ``connect``
must give up on the overall deadline.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

import ouroboros.peer as peer_mod
from ouroboros.peer import Peer, PeerState


async def _start_drip_server(drip: float):
    stop = asyncio.Event()
    writers: list[asyncio.StreamWriter] = []

    async def _handle(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        writers.append(writer)
        try:
            # Wait for the initiator's 64-byte ellswift key, then answer with
            # a (random, hence valid ellswift-encoded) key + garbage window.
            await reader.readexactly(64)
            writer.write(os.urandom(64 + 16))
            await writer.drain()
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=drip)
                except (asyncio.TimeoutError, TimeoutError):
                    writer.write(os.urandom(1))
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, stop, writers


async def _dial_drip(monkeypatch, handshake_timeout: float, drip: float,
                     guard: float):
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", handshake_timeout)
    server, port, stop, writers = await _start_drip_server(drip)
    peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
    started = time.monotonic()
    try:
        # Without the fix this only ends when ``guard`` fires: the drip keeps
        # every per-read timer satisfied for ~4,100 one-byte reads.
        ok = await asyncio.wait_for(
            peer.connect(start_height=0, retry=False), timeout=guard)
    finally:
        stop.set()
        for w in writers:
            w.close()
        server.close()
        await server.wait_closed()
    return peer, ok, time.monotonic() - started


@pytest.mark.asyncio
async def test_outbound_v2_garbage_drip_aborted_within_handshake_timeout(
        monkeypatch):
    # Scaled: 1 s deadline, one byte every 50 ms.  Dripping faster than the
    # real 10 s per-read waits is equivalent to scaling those waits down: no
    # per-read wait ever expires.  Must end on the deadline, ~1 s, not on
    # the guard.
    peer, ok, elapsed = await _dial_drip(
        monkeypatch, handshake_timeout=1.0, drip=0.05, guard=8.0)

    assert ok is False, "a dripping outbound v2 handshake must fail"
    assert peer.state == PeerState.DISCONNECTED
    assert peer.reader is None and peer.writer is None, "socket released"
    assert elapsed < 1.5, elapsed
    # The peer answered with v2 bytes, so it is not a v1-only peer: Core's
    # ShouldReconnectV1 is false once anything was received.
    assert peer.v2_negotiation_failed is False


@pytest.mark.asyncio
async def test_outbound_v2_deadline_covers_negotiation_and_version(
        monkeypatch):
    # A coarser drip (0.5 s, the audit's few-seconds interval scaled to a
    # 2 s deadline): still ends on the overall deadline, not on a later
    # per-read bound (the 5-10 s wait_for timers never expire).
    peer, ok, elapsed = await _dial_drip(
        monkeypatch, handshake_timeout=2.0, drip=0.5, guard=15.0)

    assert ok is False
    assert peer.state == PeerState.DISCONNECTED
    assert elapsed < 2.0 + 1.0, elapsed
