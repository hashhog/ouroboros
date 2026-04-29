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


# ── _negotiate_v2_inbound (responder) ───────────────────────────────────


@pytest.mark.asyncio
async def test_negotiate_v2_inbound_happy_path():
    """An ouroboros peer accepting an inbound v2 dialer drives the
    responder handshake to completion: both sides end up with the
    same session keys and the encrypted transport is wired up."""
    from ouroboros.transport_v2 import (
        CHACHA20POLY1305_EXPANSION,
        GARBAGE_TERMINATOR_LEN,
        HEADER_LEN,
        LENGTH_FIELD_LEN,
    )

    port = _free_port()
    server_session: dict = {}
    server_done = asyncio.Event()

    async def server_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # The "server" here is the ouroboros peer that just accepted
        # an inbound TCP connection — i.e. the v2 responder.  The
        # "client" is a v2 initiator simulated below.
        peer = Peer("127.0.0.1", 0, "regtest",
                    transport_version=2, inbound=True)
        peer.reader = reader
        peer.writer = writer
        # Pre-read 4 bytes (the classifier in accept_inbound does this)
        # and call _negotiate_v2_inbound directly so we exercise just
        # the handshake without the full version/verack phase.
        prefix = await reader.readexactly(4)
        await peer._negotiate_v2_inbound(initial_prefix=prefix)
        server_session["peer"] = peer
        server_done.set()
        await asyncio.sleep(0.2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        # Drive a manual initiator (mirrors the body of _negotiate_v2).
        initiator = V2Handshake(initiator=True, network="regtest")
        client_garbage = b""  # zero-length garbage exercises the AAD path
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(initiator.local_pubkey_bytes + client_garbage)
            await writer.drain()
            # Read the responder's pubkey + (random 0..32-byte) garbage —
            # we don't know the garbage length yet, so read pubkey first
            # and then scan for the terminator.
            peer_pub = await reader.readexactly(64)
            initiator.receive_remote_pubkey(peer_pub)
            client_t = V2Transport.from_handshake(initiator)
            # Now read the responder's garbage + send_garbage_terminator,
            # which from the *initiator's* perspective is recv_term.
            recv_term = client_t.recv_garbage_terminator
            window = await reader.readexactly(GARBAGE_TERMINATOR_LEN)
            for _ in range(4096):
                if window[-GARBAGE_TERMINATOR_LEN:] == recv_term:
                    break
                window += await reader.readexactly(1)
            recv_garbage = window[:-GARBAGE_TERMINATOR_LEN]
            # Read and decrypt the responder's version packet.
            enc_len = await reader.readexactly(LENGTH_FIELD_LEN)
            contents_len = client_t.decrypt_length(enc_len)
            body = await reader.readexactly(
                HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
            )
            client_t.decrypt_contents(body, contents_len, aad=recv_garbage)
            # Send our garbage terminator + version packet (AAD = client_garbage).
            send_term = client_t.send_garbage_terminator
            version_packet = client_t.encrypt_message(b"", aad=client_garbage)
            writer.write(send_term + version_packet)
            await writer.drain()
            await asyncio.wait_for(server_done.wait(), timeout=5.0)

            assert "peer" in server_session, "responder never finished"
            responder_peer = server_session["peer"]
            assert responder_peer._v2_transport is not None
            # Session-key symmetry: client.send == responder.recv etc.
            r_t = responder_peer._v2_transport
            assert client_t.send_cipher.key == r_t.recv_cipher.key
            assert client_t.recv_cipher.key == r_t.send_cipher.key
            # Garbage-terminator symmetry across roles.
            assert client_t.send_garbage_terminator == r_t.recv_garbage_terminator
            assert client_t.recv_garbage_terminator == r_t.send_garbage_terminator
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_negotiate_v2_inbound_rejects_short_prefix():
    """Defensive: the responder must refuse to run with a non-4-byte
    classifier prefix (programmer-error guard)."""
    peer = Peer("127.0.0.1", 0, "regtest",
                transport_version=2, inbound=True)

    # Need a reader/writer pair so the Not-connected branch isn't hit.
    rsock, wsock = await asyncio.open_connection(
        *await _make_local_pair_addr()
    ) if False else (None, None)  # placeholder — see below
    # Build minimal in-memory streams via a loopback server.
    port = _free_port()

    async def noop_handler(reader, writer):
        await asyncio.sleep(0.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(noop_handler, "127.0.0.1", port)
    try:
        peer.reader, peer.writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        with pytest.raises(V2NegotiationFailed):
            await peer._negotiate_v2_inbound(initial_prefix=b"\x00\x00")
        peer.writer.close()
    finally:
        server.close()
        await server.wait_closed()


async def _make_local_pair_addr():  # pragma: no cover (helper for typing)
    return ("127.0.0.1", _free_port())


@pytest.mark.asyncio
async def test_accept_inbound_classifies_v1_magic_and_passes_prefix():
    """When ``transport_version=2`` is set on an inbound peer but the
    dialer sends a v1 VERSION header, the classifier must consume the
    4-byte network magic, recognise it, and re-feed those bytes back
    to the v1 path so the wrapped reader yields the full 24-byte
    header to ``_inbound_handshake``.  We assert the prefix-injection
    contract directly via ``_PrefixedStreamReader``."""
    from ouroboros.peer import _PrefixedStreamReader

    port = _free_port()

    async def server_handler(reader, writer):
        # Send a v1 VERSION header + minimum-viable payload so the
        # peek+inject works end-to-end.  We don't assert handshake
        # success here — only that the classifier doesn't lose the
        # 4-byte magic prefix.
        magic = get_magic("regtest").to_bytes(4, "little")
        writer.write(magic + b"version\x00\x00\x00\x00\x00")
        writer.write(struct.pack("<I", 0))  # length
        writer.write(b"\x5d\xf6\xe0\xe2")   # checksum
        await writer.drain()
        # Stay open briefly so the reader can drain.
        await asyncio.sleep(0.3)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(server_handler, "127.0.0.1", port)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Manually run the classifier read step.
        prefix = await reader.readexactly(4)
        wrapped = _PrefixedStreamReader(reader, prefix)
        # First 4 bytes from the wrapper must be the magic prefix.
        roundtrip = await wrapped.readexactly(4)
        assert roundtrip == prefix
        # Next read draws from the underlying socket.
        cmd = await wrapped.readexactly(12)
        assert cmd == b"version\x00\x00\x00\x00\x00"
        writer.close()
    finally:
        server.close()
        await server.wait_closed()


# ── getpeerinfo RPC: v2 transport visibility ─────────────────────────────


@pytest.mark.asyncio
async def test_getpeerinfo_reports_v2_transport_for_inbound_peers():
    """``getpeerinfo`` must list inbound peers AND mark them with
    ``transport_protocol_type="v2"`` when ``Peer._v2_transport`` is set.

    Cross-impl interop tooling (``tools/bip324-interop-matrix.sh``)
    and ``fleet-snapshot.sh`` match on these fields, so omitting them
    silently misclassified ouroboros-inbound v2 connections as v1 in
    the 2026-04-28 matrix run.

    The PeerManager exposes three peer buckets (``peers`` outbound
    full-relay, ``block_relay_peers`` outbound block-relay-only,
    ``inbound_peers``); all three must be enumerated.
    """
    from types import SimpleNamespace

    from ouroboros.rpc import RPCServer

    # Build a fake peer with a real V2Transport stapled on (via a
    # local self-handshake) so the session_id field is exercised.
    init = V2Handshake(initiator=True, network="regtest")
    resp = V2Handshake(initiator=False, network="regtest")
    init.receive_remote_pubkey(resp.local_pubkey_bytes)
    resp.receive_remote_pubkey(init.local_pubkey_bytes)
    v2 = V2Transport.from_handshake(init)

    inbound_peer = Peer("203.0.113.7", 8333, "regtest",
                        transport_version=2, inbound=True)
    inbound_peer._v2_transport = v2
    inbound_peer.user_agent = "/dialer:1/"
    inbound_peer.version = 70016

    outbound_peer = Peer("198.51.100.5", 8333, "regtest",
                         transport_version=1, inbound=False)
    outbound_peer.user_agent = "/v1-peer:1/"
    outbound_peer.version = 70016

    fake_pm = SimpleNamespace(
        peers={"198.51.100.5:8333": outbound_peer},
        block_relay_peers={},
        inbound_peers={"203.0.113.7:8333": inbound_peer},
    )
    fake_node = SimpleNamespace(peer_manager=fake_pm, p2p=None)
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = fake_node

    info = await rpc.rpc_getpeerinfo()
    addrs = {p["addr"]: p for p in info}
    assert "203.0.113.7:8333" in addrs, "inbound peer missing from getpeerinfo"
    assert "198.51.100.5:8333" in addrs, "outbound peer missing from getpeerinfo"
    assert addrs["203.0.113.7:8333"]["transport_protocol_type"] == "v2"
    assert addrs["203.0.113.7:8333"]["session_id"] != ""
    assert len(addrs["203.0.113.7:8333"]["session_id"]) == 64  # 32 bytes hex
    assert addrs["198.51.100.5:8333"]["transport_protocol_type"] == "v1"
    assert addrs["198.51.100.5:8333"]["session_id"] == ""


@pytest.mark.asyncio
async def test_getconnectioncount_includes_all_peer_buckets():
    """``getconnectioncount`` must count every direction, mirroring
    Bitcoin Core rpc/net.cpp getconnectioncount."""
    from types import SimpleNamespace

    from ouroboros.rpc import RPCServer

    p_out = Peer("198.51.100.1", 8333, "regtest", inbound=False)
    p_blk = Peer("198.51.100.2", 8333, "regtest", inbound=False, relay_txs=False)
    p_in = Peer("203.0.113.4", 8333, "regtest", inbound=True)

    fake_pm = SimpleNamespace(
        peers={"198.51.100.1:8333": p_out},
        block_relay_peers={"198.51.100.2:8333": p_blk},
        inbound_peers={"203.0.113.4:8333": p_in},
    )
    fake_node = SimpleNamespace(peer_manager=fake_pm, p2p=None)
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = fake_node

    n = await rpc.rpc_getconnectioncount()
    assert n == 3


if __name__ == "__main__":
    unittest.main()
