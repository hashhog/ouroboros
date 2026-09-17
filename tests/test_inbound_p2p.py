"""Inbound P2P listener control (CHARTER: full P2P, outbound AND inbound).

Requirements (QUEUES.md ouroboros item 0), each with a regtest control that
does not need mainnet:

  (1) The P2P listener binds a CONFIGURABLE address, defaulting to all
      interfaces (0.0.0.0 and [::]) rather than loopback, with --bind to
      restrict it.
  (2) An inbound connection is accepted, completes version/verack, and
      appears in getpeerinfo with inbound: true.
  (3) Inbound peers are counted against their own limit, separate from
      outbound, so a flood of inbound cannot starve outbound sync.
  (4) An inbound peer that never completes the handshake is disconnected
      on a timeout and does not hold a slot.
  (5) The node serves getheaders/getdata to an inbound peer the same as
      to an outbound one.

Default bind address (report in the commit body): 0.0.0.0 and :: .
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from types import SimpleNamespace

import pytest

import ouroboros.p2p as p2p_mod
import ouroboros.peer as peer_mod
from ouroboros.database import Block
from ouroboros.header_backfill import GENESIS_HASHES, GENESIS_HEADERS
from ouroboros.node import BitcoinNode
from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import (
    INV_TYPE_BLOCK,
    NODE_NETWORK,
    NODE_WITNESS,
    GetDataMessage,
    GetHeadersMessage,
    NetworkMessage,
    VersionMessage,
    get_magic,
)
from ouroboros.rpc import RPCServer

NETWORK = "regtest"
FAST_HANDSHAKE_TIMEOUT = 0.4


def _ipv6_supported() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind(("::", 0))
        s.close()
        return True
    except OSError:
        return False


def _sock_host(sock: socket.socket) -> str:
    host = sock.getsockname()[0]
    if host in ("::0", "0000:0000:0000:0000:0000:0000:0000:0000"):
        return "::"
    return host


def _verack_frame(network: str = NETWORK) -> bytes:
    return NetworkMessage(command="verack", payload=b"", magic=get_magic(network)).serialize()


def _version_frame(network: str = NETWORK, start_height: int = 0) -> bytes:
    v = VersionMessage(
        version=70016,
        services=NODE_NETWORK | NODE_WITNESS,
        timestamp=int(time.time()),
        nonce=1234,
        user_agent="/inbound-control:0.1.0/",
        start_height=start_height,
        relay=True,
    )
    return v.to_network_message(network).serialize()


async def _read_msg(reader: asyncio.StreamReader, timeout: float = 5.0) -> NetworkMessage:
    header = await asyncio.wait_for(reader.readexactly(24), timeout=timeout)
    payload_len = struct.unpack_from("<I", header, 16)[0]
    payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=timeout)
    return NetworkMessage.deserialize(header + payload, NETWORK)


async def _drain_until(
    reader: asyncio.StreamReader,
    command: str,
    timeout: float = 5.0,
) -> NetworkMessage:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {command!r}")
        msg = await _read_msg(reader, timeout=remaining)
        if msg.command == command:
            return msg


async def _handshake_as_dialer(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Dial *host:port*, complete version/verack as the inbound initiator."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(_version_frame())
    await writer.drain()
    await _drain_until(reader, "version")
    writer.write(_verack_frame())
    await writer.drain()
    await _drain_until(reader, "verack")
    return reader, writer


def _regtest_genesis() -> Block:
    hdr = GENESIS_HEADERS["regtest"]
    return Block(
        version=struct.unpack_from("<i", hdr, 0)[0],
        prev_blockhash=hdr[4:36],
        merkle_root=hdr[36:68],
        timestamp=struct.unpack_from("<I", hdr, 68)[0],
        bits=struct.unpack_from("<I", hdr, 72)[0],
        nonce=struct.unpack_from("<I", hdr, 76)[0],
        transactions=[],
        hash=GENESIS_HASHES["regtest"],
        height=0,
    )


class _FakeDB:
    """Minimal chain for getheaders/getdata serving (genesis only)."""

    def __init__(self, genesis: Block):
        self._genesis = genesis
        self._raw = genesis.serialize()

    def get_block(self, block_hash: bytes):
        if block_hash == self._genesis.hash:
            return self._genesis
        return None

    def get_block_by_height(self, height: int):
        if height == 0:
            return self._genesis
        return None

    def get_best_block(self):
        return self._genesis.hash, 0

    def get_block_bytes(self, block_hash: bytes):
        if block_hash == self._genesis.hash:
            return self._raw
        return None


async def _start_listening_pm(tmp_path, **kwargs) -> PeerManager:
    kwargs.setdefault("network", NETWORK)
    kwargs.setdefault("max_peers", 0)
    kwargs.setdefault("data_dir", str(tmp_path))
    kwargs.setdefault("transport_version", 1)
    kwargs.setdefault("listen", True)
    kwargs.setdefault("dns_seed", False)
    kwargs.setdefault("connect_addrs", [])
    p2p_port = kwargs.pop("p2p_port", 0)
    pm = PeerManager(**kwargs)
    await pm.start(start_height=0, p2p_port=p2p_port)
    return pm


def _listen_port(pm: PeerManager) -> int:
    socks = pm.listening_sockets()
    assert socks, "P2P listener is not bound"
    return socks[0].getsockname()[1]


# --------------------------------------------------------------------------- #
# (1) configurable bind, default all interfaces
# --------------------------------------------------------------------------- #


def test_default_bind_hosts_are_all_interfaces():
    """DEFAULT_BIND_HOSTS is 0.0.0.0 and ::, not loopback."""
    hosts = getattr(p2p_mod, "DEFAULT_BIND_HOSTS", ())
    assert "0.0.0.0" in hosts, f"default bind must include 0.0.0.0 (all IPv4), got {hosts!r}"
    assert "::" in hosts, f"default bind must include :: (all IPv6), got {hosts!r}"
    assert "127.0.0.1" not in hosts
    assert "::1" not in hosts


def test_cli_exposes_bind_flag():
    """--bind is the operator flag that restricts the default all-interfaces bind."""
    from ouroboros.cli import start

    names = {p.name for p in start.params}
    assert "bind" in names, "CLI is missing --bind (Bitcoin Core -bind)"


def test_config_default_bind_is_all_interfaces(tmp_path):
    """Empty conf bind means 'all interfaces'; NodeConfig surfaces it."""
    from ouroboros.config import NodeConfig

    cfg = NodeConfig(config_path=str(tmp_path / "missing.conf"), data_dir=str(tmp_path))
    d = cfg.to_dict()
    assert "bind" in d, "NodeConfig.to_dict() must expose bind"
    # Empty / missing bind = default all-interfaces (not loopback).
    bind = d["bind"]
    if bind in ("", None, []):
        return
    if isinstance(bind, str):
        parts = [p.strip() for p in bind.split(",") if p.strip()]
    else:
        parts = list(bind)
    assert "0.0.0.0" in parts and "::" in parts


@pytest.mark.asyncio
async def test_default_listener_binds_all_interfaces(tmp_path):
    """With listen=True and no --bind, sockets are 0.0.0.0 and :: (not 127.0.0.1)."""
    pm = await _start_listening_pm(tmp_path)
    try:
        socks = pm.listening_sockets()
        assert socks, "listener must bind when listen=True (port 0 = ephemeral)"
        hosts = {_sock_host(s) for s in socks}
        assert "0.0.0.0" in hosts, f"default bind missing 0.0.0.0; bound {hosts}"
        assert "127.0.0.1" not in hosts
        if _ipv6_supported():
            assert "::" in hosts, f"default bind missing [::]; bound {hosts}"
    finally:
        await pm.stop()


@pytest.mark.asyncio
async def test_bind_flag_restricts_to_loopback(tmp_path):
    """--bind 127.0.0.1 must bind ONLY loopback, not 0.0.0.0."""
    pm = await _start_listening_pm(tmp_path, bind=["127.0.0.1"])
    try:
        socks = pm.listening_sockets()
        assert socks, "restricted listener must still bind"
        hosts = {_sock_host(s) for s in socks}
        assert hosts == {"127.0.0.1"}, f"expected only 127.0.0.1, bound {hosts}"
        # Connecting to the loopback port must succeed.
        port = _listen_port(pm)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
    finally:
        await pm.stop()


# --------------------------------------------------------------------------- #
# (2) inbound handshake appears in getpeerinfo with inbound: true
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_inbound_handshake_getpeerinfo_inbound_true(tmp_path):
    pm = await _start_listening_pm(tmp_path)
    try:
        port = _listen_port(pm)
        reader, writer = await _handshake_as_dialer("127.0.0.1", port)
        # Yield so the accept callback can register the peer.
        for _ in range(50):
            if pm.inbound_peers:
                break
            await asyncio.sleep(0.05)
        assert pm.inbound_peers, "inbound peer was not registered after handshake"

        rpc = RPCServer(SimpleNamespace(peer_manager=pm), port=0, rate_limit=False)
        info = await rpc.rpc_getpeerinfo()
        inbound = [p for p in info if p.get("inbound") is True]
        assert inbound, f"getpeerinfo missing inbound:true; got {info!r}"
        writer.close()
        await writer.wait_closed()
    finally:
        await pm.stop()


# --------------------------------------------------------------------------- #
# (3) inbound limit is separate from outbound
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_inbound_flood_does_not_starve_outbound(tmp_path, monkeypatch):
    """Fill the inbound cap; an outbound dial must still succeed."""
    # Same-source-IP dials share a /16 group; disable the new-group reserve
    # so two loopback inbounds can actually fill a cap of 2.
    monkeypatch.setattr(p2p_mod, "RESERVED_INBOUND_SLOTS_FOR_NEW_GROUPS", 0)
    dummy_conns: list[asyncio.StreamWriter] = []
    dummy_stop = asyncio.Event()

    async def dummy_handshake(reader, writer):
        dummy_conns.append(writer)
        try:
            await _drain_until(reader, "version")
            writer.write(_version_frame())
            writer.write(_verack_frame())
            await writer.drain()
            await dummy_stop.wait()
        except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    dummy = await asyncio.start_server(dummy_handshake, "127.0.0.1", 0)
    dummy_port = dummy.sockets[0].getsockname()[1]

    pm = await _start_listening_pm(
        tmp_path,
        max_peers=1,
        max_inbound=2,
    )
    inbound_writers = []
    try:
        port = _listen_port(pm)
        for _ in range(2):
            r, w = await _handshake_as_dialer("127.0.0.1", port)
            inbound_writers.append(w)
        for _ in range(50):
            if len(pm.inbound_peers) >= 2:
                break
            await asyncio.sleep(0.05)
        assert len(pm.inbound_peers) == 2, f"expected 2 inbound peers, got {len(pm.inbound_peers)}"

        # A third inbound must be refused (at cap, no eviction of 2 peers:
        # Core protects ≤4 by latency so eviction of 2 is a no-op).
        r3, w3 = await asyncio.open_connection("127.0.0.1", port)
        w3.write(_version_frame())
        await w3.drain()
        await asyncio.sleep(0.5)
        assert len(pm.inbound_peers) == 2, "inbound cap must not grow past max_inbound"
        w3.close()
        try:
            await w3.wait_closed()
        except (ConnectionResetError, ConnectionError, BrokenPipeError):
            pass

        ok = await pm.connect_to_node("127.0.0.1", dummy_port)
        assert ok, "outbound dial must succeed while inbound is at cap"
        assert len(pm.peers) >= 1, "outbound peer missing; inbound flood starved outbound"
    finally:
        for w in inbound_writers:
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
        dummy_stop.set()
        dummy.close()
        await dummy.wait_closed()
        await pm.stop()


# --------------------------------------------------------------------------- #
# (4) half-open inbound is reaped and does not hold a slot
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_half_open_inbound_is_reaped(tmp_path, monkeypatch):
    monkeypatch.setattr(peer_mod, "HANDSHAKE_TIMEOUT", FAST_HANDSHAKE_TIMEOUT)
    pm = await _start_listening_pm(tmp_path, max_inbound=2)
    try:
        port = _listen_port(pm)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Send nothing — TCP is open, handshake never starts.
        await asyncio.sleep(FAST_HANDSHAKE_TIMEOUT * 4)
        assert pm.inbound_peers == {}, (
            f"half-open connection held an inbound slot: {list(pm.inbound_peers)}"
        )
        # The listener must have closed the socket (EOF on our read).
        leftover = await asyncio.wait_for(reader.read(1), timeout=2.0)
        assert leftover == b"", "half-open socket was not closed by the listener"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    finally:
        await pm.stop()


# --------------------------------------------------------------------------- #
# (5) inbound peer is served getheaders / getdata
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_inbound_serves_getheaders_and_getdata(tmp_path):
    genesis = _regtest_genesis()
    pm = await _start_listening_pm(tmp_path)

    node = BitcoinNode(
        data_dir=str(tmp_path / "node"),
        network=NETWORK,
        config={
            "network": NETWORK,
            "listen": True,
            "v2transport": False,
            "dnsseed": False,
        },
    )
    node.db = _FakeDB(genesis)
    node.mempool = None
    node.pruner = None
    node.block_filter_index = None
    node.peer_manager = pm
    node._register_handlers()

    try:
        port = _listen_port(pm)
        reader, writer = await _handshake_as_dialer("127.0.0.1", port)
        for _ in range(50):
            peers = list(pm.inbound_peers.values())
            if peers and "getdata" in getattr(peers[0], "message_handlers", {}):
                break
            await asyncio.sleep(0.05)
        peers = list(pm.inbound_peers.values())
        assert peers, "inbound peer missing after handshake"
        assert "getdata" in peers[0].message_handlers
        assert "getheaders" in peers[0].message_handlers

        # Locator of an unknown hash keeps start_height=0 so genesis is served.
        gh = GetHeadersMessage(
            version=70016,
            locator_hashes=[b"\x00" * 32],
            hash_stop=b"\x00" * 32,
        )
        writer.write(gh.to_network_message(NETWORK).serialize())
        await writer.drain()
        headers_msg = await _drain_until(reader, "headers", timeout=5.0)
        assert headers_msg.command == "headers"
        assert len(headers_msg.payload) > 1, "expected a served header, got empty headers"

        gd = GetDataMessage(inventory=[(INV_TYPE_BLOCK, genesis.hash)])
        writer.write(gd.to_network_message(NETWORK).serialize())
        await writer.drain()
        block_msg = await _drain_until(reader, "block", timeout=5.0)
        assert block_msg.command == "block"
        assert len(block_msg.payload) >= 80, "served block too short to contain a header"

        writer.close()
        await writer.wait_closed()
    finally:
        await pm.stop()
