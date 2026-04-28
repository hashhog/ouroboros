"""Tests for BIP 324 v2 transport wiring + per-address v1 fall-back.

These tests cover the *wiring* layer added on top of the existing
``transport_v2`` cipher (handshake, FSChaCha20Poly1305 simulation, etc).
The cipher itself is exercised by ``TestV2Transport`` in
``tests/test_integration.py`` — those vectors are self-consistent
round-trips, not Bitcoin Core spec vectors.

Coverage:

  - ``Peer._negotiate_v2`` happy path against a v2 echo server.
  - ``Peer._negotiate_v2`` v1 fall-back: peer responds with v1 magic ->
    ``V2NegotiationFailed`` raised, ``v2_negotiation_failed`` latched.
  - ``Peer._negotiate_v2`` peer disconnects mid-handshake -> graceful
    fall-back signal, no v1 retry on the same socket.
  - ``PeerManager._is_v1_only_addr`` + ``_mark_v1_only`` TTL semantics.
  - ``PeerManager._transport_for`` returns 1 for flagged addresses even
    when the manager is configured for v2.
  - End-to-end self-consistency: two peers exchanging full
    handshake-and-message round-trip via the wired ``send_message`` /
    ``receive_message`` paths (validates that the wiring does not
    corrupt the cipher's framing).

NOTE: Bitcoin Core's BIP 324 packet test vectors at
``src/test/bip324_tests.cpp`` require *real* secp256k1 ECDH +
ElligatorSwift decoding.  Ouroboros's current cipher uses simulated
ECDH (hash of both pubkeys) for self-consistency only and cannot
match those vectors — the cross-impl negotiation gap is documented as
NEEDS-INFRA in the task report; this test suite validates that the
wiring layer is correct given the existing cipher.
"""

from __future__ import annotations

import asyncio
import struct
import time
import unittest

import pytest

from ouroboros.p2p import V2_FALLBACK_TTL, PeerManager
from ouroboros.p2p_messages import get_magic
from ouroboros.peer import (
    Peer,
    V2NegotiationFailed,
)
from ouroboros.transport_v2 import V2Handshake, V2Transport


def _free_port() -> int:
    """Return an unused TCP port on localhost."""
    import socket as _socket
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── _negotiate_v2 happy path ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_negotiate_v2_happy_path():
    """Two ouroboros peers exchanging the full BIP 324 handshake
    (ellswift pubkey + garbage + terminator + version packet) on both
    sides successfully derive matching session keys."""
    import os as _os
    from ouroboros.transport_v2 import (
        CHACHA20POLY1305_EXPANSION,
        GARBAGE_TERMINATOR_LEN,
        HEADER_LEN,
        LENGTH_FIELD_LEN,
    )

    port = _free_port()
    server_handshake_done = asyncio.Event()
    server_session: dict = {}

    async def server_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # 1. Read the initiator's 64-byte ellswift pubkey first.
        peer_pub = await reader.readexactly(64)
        responder = V2Handshake(initiator=False, network="regtest")
        # 2. Send our 64-byte ellswift response + (zero-length) garbage.
        server_garbage = b""
        writer.write(responder.local_pubkey_bytes + server_garbage)
        await writer.drain()
        # 3. Now we know the shared secret; build the cipher.
        responder.receive_remote_pubkey(peer_pub)
        server_t = V2Transport.from_handshake(responder)
        server_session["transport"] = server_t
        # 4. Send our garbage terminator + version packet (AAD = our garbage).
        version_packet = server_t.encrypt_message(b"", aad=server_garbage)
        writer.write(server_t.send_garbage_terminator + version_packet)
        await writer.drain()
        # 5. Scan incoming bytes for the initiator's recv_garbage_terminator
        # (== our send_garbage_terminator from the server's view? no — from
        # the responder's perspective, recv == initiator_terminator).  We
        # mirror the initiator's drain logic in miniature here.
        recv_term = server_t.recv_garbage_terminator
        window = await reader.readexactly(GARBAGE_TERMINATOR_LEN)
        for _ in range(4096):
            if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                break
            window += await reader.readexactly(1)
        recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
        # 6. Read and decrypt one packet (the initiator's version packet).
        enc_len = await reader.readexactly(LENGTH_FIELD_LEN)
        contents_len = server_t.decrypt_length(enc_len)
        body = await reader.readexactly(
            HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        )
        server_t.decrypt_contents(body, contents_len, aad=recv_garbage)
        server_handshake_done.set()
        # Hold the connection open briefly so the client can finish.
        await asyncio.sleep(0.2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        await peer._negotiate_v2()
        await asyncio.wait_for(server_handshake_done.wait(), timeout=5.0)
        assert peer._v2_transport is not None, "client transport not set"
        assert server_session["transport"] is not None, "server transport not set"
        assert not peer.v2_negotiation_failed
        # Verify session-key symmetry: client send_key == server recv_key.
        client = peer._v2_transport
        server_t = server_session["transport"]
        assert client.send_cipher.key == server_t.recv_cipher.key
        assert client.recv_cipher.key == server_t.send_cipher.key
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()
    _ = _os  # silence unused-import warning


# ── _negotiate_v2: peer replies with v1 magic ───────────────────────────


@pytest.mark.asyncio
async def test_negotiate_v2_detects_v1_magic_response():
    """A peer that responds with a v1-framed message (network magic in
    first 4 bytes) is detected and the handshake fails fast with
    ``V2NegotiationFailed``."""
    port = _free_port()

    async def v1_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Discard the 64 bytes of v2 garbage the client sends.
        try:
            await reader.read(64)
        except Exception:
            pass
        # Reply with a v1 message header (mainnet magic is 0xD9B4BEF9
        # little-endian).  Use regtest to match the client.
        magic = get_magic("regtest")
        header = struct.pack(
            "<I12sI4s",
            magic,
            b"reject\x00\x00\x00\x00\x00\x00",
            0,
            b"\x5d\xf6\xe0\xe2",  # double-SHA256 of empty
        )
        writer.write(header)
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(v1_server, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        with pytest.raises(V2NegotiationFailed) as exc_info:
            await peer._negotiate_v2()
        assert "v1 network magic" in str(exc_info.value)
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


# ── _negotiate_v2: peer disconnects mid-handshake ───────────────────────


@pytest.mark.asyncio
async def test_negotiate_v2_handles_premature_disconnect():
    """A peer that closes the connection right after seeing the v2
    garbage triggers ``V2NegotiationFailed`` rather than a generic
    exception, so the caller can treat it as a v1 fall-back signal."""
    port = _free_port()

    async def hangup_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await reader.read(8)  # read something then close
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(hangup_server, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        with pytest.raises(V2NegotiationFailed):
            await peer._negotiate_v2()
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


# ── connect() flags v2_negotiation_failed and disconnects ───────────────


@pytest.mark.asyncio
async def test_connect_latches_v2_failure_flag():
    """``connect()`` against a v1-only peer sets
    ``v2_negotiation_failed=True`` and returns False without trying to
    reuse the corrupt socket for a v1 handshake."""
    port = _free_port()

    async def v1_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await reader.read(64)
        except Exception:
            pass
        # Hard-close after seeing the v2 garbage — most v1 nodes do
        # not emit a reject, they just drop the conn.
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(v1_server, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        ok = await peer.connect(start_height=0, retry=False)
        assert ok is False
        assert peer.v2_negotiation_failed is True
        assert peer._v2_transport is None
    finally:
        server.close()
        await server.wait_closed()


# ── PeerManager v1-only TTL cache ──────────────────────────────────────


def test_peer_manager_v1_only_ttl():
    """``_mark_v1_only`` records timestamp; ``_is_v1_only_addr`` honours
    the TTL and lazily evicts stale entries."""
    pm = PeerManager(network="regtest", listen=False, transport_version=2)
    addr = "192.0.2.1:8333"
    assert not pm._is_v1_only_addr(addr)
    pm._mark_v1_only(addr)
    assert pm._is_v1_only_addr(addr)
    assert pm._transport_for(addr) == 1
    # A different address remains v2.
    assert pm._transport_for("192.0.2.2:8333") == 2

    # Force-expire by rewriting the recorded timestamp into the past.
    pm._v1_only_addrs[addr] = time.time() - V2_FALLBACK_TTL - 1
    assert not pm._is_v1_only_addr(addr)
    # Lazy eviction — entry should be gone after the check.
    assert addr not in pm._v1_only_addrs
    assert pm._transport_for(addr) == 2


def test_peer_manager_transport_for_respects_global_setting():
    """When the manager is configured for v1 globally, fall-back state is
    a no-op (we never probe v2 in the first place)."""
    pm = PeerManager(network="regtest", listen=False, transport_version=1)
    assert pm._transport_for("192.0.2.3:8333") == 1
    pm._mark_v1_only("192.0.2.3:8333")
    assert pm._transport_for("192.0.2.3:8333") == 1


# ── _dial_outbound: v2-first → v1 fall-back on a fresh socket ────────────


@pytest.mark.asyncio
async def test_dial_outbound_falls_back_to_v1_on_fresh_socket():
    """``PeerManager._dial_outbound`` first tries v2; on failure it
    marks the address v1-only and immediately re-dials with v1 on a
    fresh socket — matching Bitcoin Core's m_reconnections flow.
    """
    from ouroboros.p2p_messages import (
        NODE_NETWORK,
        NODE_WITNESS,
        NetworkAddress,
        VersionMessage,
        get_magic,
    )

    port = _free_port()
    state = {
        "v1_attempts": 0,
        "v2_attempts": 0,
    }

    async def server_handler(reader, writer):
        # Distinguish v1 from v2 by peeking at the first 4 bytes:
        # v1 starts with our network magic, v2 starts with random
        # ElligatorSwift bytes (random values almost-surely won't
        # match the regtest magic).
        try:
            head = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
        except Exception:
            writer.close()
            return
        magic = get_magic("regtest").to_bytes(4, "little")
        if head == magic:
            # v1 path: drain the rest of the version header + payload
            # and reply with our own version + verack so the client's
            # ``_handshake`` can complete.
            state["v1_attempts"] += 1
            try:
                rest_header = await reader.readexactly(20)
                _, length, _ = struct.unpack(
                    "<12sI4s", rest_header
                )
                if length:
                    await reader.readexactly(length)

                # Send version
                addr = NetworkAddress(
                    services=NODE_NETWORK | NODE_WITNESS,
                    ip=b"\x00" * 16,
                    port=port,
                )
                ver = VersionMessage(
                    version=70016,
                    services=NODE_NETWORK | NODE_WITNESS,
                    timestamp=int(time.time()),
                    addr_recv=addr,
                    addr_from=addr,
                    nonce=1,
                    user_agent="/test:0.0/",
                    start_height=0,
                    relay=True,
                )
                writer.write(ver.to_network_message("regtest").serialize())
                # Send verack
                from ouroboros.p2p_messages import VerAckMessage
                writer.write(
                    VerAckMessage().to_network_message("regtest").serialize()
                )
                await writer.drain()
                # Drain the client's verack
                try:
                    await asyncio.wait_for(reader.read(1024), timeout=1.0)
                except Exception:
                    pass
            except Exception:
                pass
        else:
            # v2 path: read the rest of the 64 bytes then hard-close
            # (simulates a v1-only peer that received garbage).
            state["v2_attempts"] += 1
            try:
                await asyncio.wait_for(reader.readexactly(60), timeout=2.0)
            except Exception:
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        pm = PeerManager(network="regtest", listen=False, transport_version=2)
        peer = await pm._dial_outbound(
            "127.0.0.1", port,
            relay_txs=False,
            start_height=0,
            retry=False,
        )
        # The v2 attempt should have failed and a v1 retry should have
        # been issued on a fresh socket.
        assert state["v2_attempts"] == 1, (
            f"expected exactly 1 v2 attempt, got {state['v2_attempts']}"
        )
        assert state["v1_attempts"] >= 1, (
            f"expected at least 1 v1 retry, got {state['v1_attempts']}"
        )
        # The address should now be marked v1-only in PeerManager.
        addr = f"127.0.0.1:{port}"
        assert pm._is_v1_only_addr(addr)
        if peer is not None:
            await peer.disconnect()
    finally:
        server.close()
        await server.wait_closed()


# ── Self-consistency end-to-end via send_message/receive_message ────────


@pytest.mark.asyncio
async def test_v2_self_consistent_message_roundtrip():
    """Drive the existing cipher through the wired ``send_message`` /
    ``_receive_v2_message`` paths.  Validates that the wiring does not
    corrupt framing relative to the cipher's own packet format.
    """
    from ouroboros.p2p_messages import NetworkMessage, PingMessage

    # Both sides do a synchronous in-memory handshake.
    initiator = V2Handshake(initiator=True, network="regtest")
    responder = V2Handshake(initiator=False, network="regtest")
    initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
    responder.receive_remote_pubkey(initiator.local_pubkey_bytes)
    i_transport = V2Transport.from_handshake(initiator)
    r_transport = V2Transport.from_handshake(responder)

    # Wire two Peer objects to a localhost socket pair so we can use
    # the production send_message / receive_message paths.
    port = _free_port()
    server_done = asyncio.Event()
    received_msgs: list[NetworkMessage] = []

    async def server_handler(reader, writer):
        # Bypass the negotiate step: install the pre-derived transport.
        server_peer = Peer("127.0.0.1", 0, "regtest", transport_version=2,
                           inbound=True)
        server_peer.reader = reader
        server_peer.writer = writer
        server_peer._v2_transport = r_transport
        server_peer.state = server_peer.state.__class__.READY
        try:
            msg = await server_peer.receive_message(timeout=5.0)
            received_msgs.append(msg)
        finally:
            server_done.set()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        client = Peer("127.0.0.1", port, "regtest", transport_version=2)
        client.reader, client.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        client._v2_transport = i_transport
        client.state = client.state.__class__.READY
        ping = PingMessage(nonce=0xDEADBEEF1234)
        await client.send_message(ping.to_network_message("regtest"))
        await asyncio.wait_for(server_done.wait(), timeout=5.0)
        client.writer.close()
    finally:
        server.close()
        await server.wait_closed()

    assert len(received_msgs) == 1
    assert received_msgs[0].command == "ping"


# ── Vector validation: existing cipher self-consistency ─────────────────


def test_cipher_handshake_session_key_symmetry():
    """The simulated ElligatorSwift / ECDH path produces matching
    initiator / responder session keys.  This is the closest analog of
    a "test vector" that the simulated cipher can satisfy: both sides
    must agree on send/recv keys.

    This is the property the WIRING layer relies on to exchange v2
    packets at all.  If the cipher were upgraded to real secp256k1
    ECDH (so it could pass Bitcoin Core's bip324_tests.cpp packet
    vectors) this test would still hold.
    """
    initiator = V2Handshake(initiator=True, network="regtest")
    responder = V2Handshake(initiator=False, network="regtest")
    initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
    responder.receive_remote_pubkey(initiator.local_pubkey_bytes)
    i_send, i_recv = initiator.derive_session_keys()
    r_send, r_recv = responder.derive_session_keys()
    assert i_send == r_recv, "initiator send-key must match responder recv-key"
    assert i_recv == r_send, "initiator recv-key must match responder send-key"
    assert len(i_send) == 32
    assert len(i_recv) == 32


# ── BIP 324 garbage-exchange wire layer ─────────────────────────────────


@pytest.mark.asyncio
async def test_negotiate_v2_handles_nonempty_recv_garbage():
    """Server sends a non-empty garbage chunk (47 bytes) before its
    terminator + version packet.  The initiator must scan past the
    garbage, locate the terminator, and decrypt the version packet
    using the received garbage as AAD."""
    import os as _os
    from ouroboros.transport_v2 import (
        CHACHA20POLY1305_EXPANSION,
        GARBAGE_TERMINATOR_LEN,
        HEADER_LEN,
        LENGTH_FIELD_LEN,
    )

    port = _free_port()
    server_done = asyncio.Event()
    server_session: dict = {}

    async def server_handler(reader, writer):
        peer_pub = await reader.readexactly(64)
        responder = V2Handshake(initiator=False, network="regtest")
        # 47-byte non-empty garbage stresses the byte-by-byte scan loop.
        server_garbage = _os.urandom(47)
        writer.write(responder.local_pubkey_bytes + server_garbage)
        await writer.drain()
        responder.receive_remote_pubkey(peer_pub)
        server_t = V2Transport.from_handshake(responder)
        server_session["transport"] = server_t
        version_packet = server_t.encrypt_message(b"", aad=server_garbage)
        writer.write(server_t.send_garbage_terminator + version_packet)
        await writer.drain()

        # Read initiator's terminator + version packet on the server side.
        recv_term = server_t.recv_garbage_terminator
        window = await reader.readexactly(GARBAGE_TERMINATOR_LEN)
        for _ in range(4096):
            if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                break
            window += await reader.readexactly(1)
        recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
        enc_len = await reader.readexactly(LENGTH_FIELD_LEN)
        contents_len = server_t.decrypt_length(enc_len)
        body = await reader.readexactly(
            HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        )
        server_t.decrypt_contents(body, contents_len, aad=recv_garbage)
        server_done.set()
        await asyncio.sleep(0.1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        await peer._negotiate_v2()
        await asyncio.wait_for(server_done.wait(), timeout=5.0)
        assert peer._v2_transport is not None
        # Ciphers stayed in lock-step despite the 47-byte garbage chunk
        # and the version-packet AAD binding.
        client = peer._v2_transport
        server_t = server_session["transport"]
        assert client.send_cipher.key == server_t.recv_cipher.key
        assert client.recv_cipher.key == server_t.send_cipher.key
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_negotiate_v2_drops_decoy_packets_before_version():
    """Server inserts 3 decoy packets between its garbage terminator
    and its (real) version packet.  The initiator must drop the decoys
    and decrypt the version packet, with AAD = received garbage on the
    very first decryption only.  Mirrors Bitcoin Core net.cpp:1243
    (m_recv_aad cleared after first successful decrypt, regardless of
    whether the decrypted packet was a decoy)."""
    from ouroboros.transport_v2 import (
        CHACHA20POLY1305_EXPANSION,
        GARBAGE_TERMINATOR_LEN,
        HEADER_LEN,
        LENGTH_FIELD_LEN,
    )

    port = _free_port()
    server_done = asyncio.Event()

    async def server_handler(reader, writer):
        peer_pub = await reader.readexactly(64)
        responder = V2Handshake(initiator=False, network="regtest")
        server_garbage = b"hello-garbage"
        writer.write(responder.local_pubkey_bytes + server_garbage)
        await writer.drain()
        responder.receive_remote_pubkey(peer_pub)
        server_t = V2Transport.from_handshake(responder)
        # Send terminator, then 3 decoys (first decoy uses AAD = garbage,
        # next two use empty AAD), then the real version packet (also
        # empty AAD).
        out = server_t.send_garbage_terminator
        out += server_t.encrypt_message(b"\x00" * 7, aad=server_garbage, decoy=True)
        out += server_t.encrypt_message(b"\x00" * 3, aad=b"", decoy=True)
        out += server_t.encrypt_message(b"\x00" * 11, aad=b"", decoy=True)
        out += server_t.encrypt_message(b"", aad=b"")  # the version packet
        writer.write(out)
        await writer.drain()

        # Mirror initiator-side drain.
        recv_term = server_t.recv_garbage_terminator
        window = await reader.readexactly(GARBAGE_TERMINATOR_LEN)
        for _ in range(4096):
            if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                break
            window += await reader.readexactly(1)
        recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
        enc_len = await reader.readexactly(LENGTH_FIELD_LEN)
        contents_len = server_t.decrypt_length(enc_len)
        body = await reader.readexactly(
            HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
        )
        server_t.decrypt_contents(body, contents_len, aad=recv_garbage)
        server_done.set()
        await asyncio.sleep(0.1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        await peer._negotiate_v2()
        await asyncio.wait_for(server_done.wait(), timeout=5.0)
        assert peer._v2_transport is not None
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_negotiate_v2_aborts_on_missing_garbage_terminator():
    """A peer that never sends a recv_garbage_terminator within
    MAX_GARBAGE_LEN bytes triggers ``V2NegotiationFailed``.  Matches
    Bitcoin Core's GARB_GARBTERM abort (net.cpp:1192)."""
    port = _free_port()

    async def server_handler(reader, writer):
        await reader.readexactly(64)
        responder = V2Handshake(initiator=False, network="regtest")
        # Send pubkey, then 4096 bytes of /dev/urandom-style noise that
        # is exceedingly unlikely to contain the (random, derived)
        # 16-byte send_garbage_terminator.  Receiver should give up
        # after MAX_GARBAGE_LEN (4095) bytes.
        writer.write(responder.local_pubkey_bytes)
        # 4112 = 4096 garbage + 16 fake-terminator suffix that won't match.
        writer.write(b"\xaa" * 4112)
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        peer = Peer("127.0.0.1", port, "regtest", transport_version=2)
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        with pytest.raises(V2NegotiationFailed) as exc:
            await peer._negotiate_v2()
        assert "garbage" in str(exc.value).lower()
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
