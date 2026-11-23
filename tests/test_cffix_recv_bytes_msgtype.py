"""Received bytes per message type are keyed only by known types + ``*other*``.

Finding (cffix-ouroboros-recv-bytes-msgtype-cap, 2026-11-09 security audit):
``Peer.receive_message`` keyed ``bytes_recv_per_msg`` by the peer-chosen
command on both the v1 and the BIP 324 v2 path.  Unknown commands are logged
and ignored by the dispatcher, but the counter dict kept a permanent entry per
distinct command, so a peer could add one dict key per 24 wire bytes (v1) for
the lifetime of the connection.

Core (``src/net.cpp`` ``CNode::CNode``) fills ``mapRecvBytesPerMsgType`` with
``ALL_NET_MESSAGE_TYPES`` plus ``NET_MESSAGE_TYPE_OTHER`` ("*other*") and
``CNode::ReceiveMsgBytes`` charges a type that is not in the map to
``*other*`` ("To prevent a memory DOS, only allow known message types").
``getpeerinfo`` then lists only non-zero entries, so the RPC shape is
``{known_type: n, ..., "*other*": n}``.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from ouroboros.p2p_messages import NetworkMessage, get_magic
from ouroboros.peer import Peer, PeerState
from ouroboros.transport_v2 import V2Handshake, V2Transport, encode_v2_contents

# Core v31.1 src/protocol.h ALL_NET_MESSAGE_TYPES (35 entries), spelled out
# here so the test does not depend on the constant the fix adds.
CORE_KNOWN_TYPES = frozenset({
    "version", "verack", "addr", "addrv2", "sendaddrv2", "inv", "getdata",
    "merkleblock", "getblocks", "getheaders", "tx", "headers", "block",
    "getaddr", "mempool", "ping", "pong", "notfound", "filterload",
    "filteradd", "filterclear", "sendheaders", "feefilter", "sendcmpct",
    "cmpctblock", "getblocktxn", "blocktxn", "getcfilters", "cfilter",
    "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "wtxidrelay",
    "sendtxrcncl",
})
OTHER = "*other*"
N_UNKNOWN = 10_000


def _unknown_command(i: int) -> str:
    # 12 printable ASCII chars, none of them a known type.
    return f"zz{i:010d}"


def _v1_peer(blob: bytes) -> Peer:
    peer = Peer("203.0.113.7", 8333, "regtest", transport_version=1,
                inbound=True)
    reader = asyncio.StreamReader()
    reader.feed_data(blob)
    reader.feed_eof()
    peer.reader = reader
    peer.state = PeerState.READY
    return peer


def _v2_pair() -> tuple[V2Transport, V2Transport]:
    init = V2Handshake(initiator=True, network="regtest")
    resp = V2Handshake(initiator=False, network="regtest")
    init.receive_remote_pubkey(resp.local_pubkey_bytes)
    resp.receive_remote_pubkey(init.local_pubkey_bytes)
    return V2Transport.from_handshake(init), V2Transport.from_handshake(resp)


async def _drain(peer: Peer, n: int) -> list[str]:
    return [(await peer.receive_message(timeout=5.0)).command
            for _ in range(n)]


@pytest.mark.asyncio
async def test_v1_unknown_commands_do_not_grow_recv_map():
    magic = get_magic("regtest")
    blob = b"".join(
        NetworkMessage(command=_unknown_command(i), payload=b"",
                       magic=magic).serialize()
        for i in range(N_UNKNOWN))
    peer = _v1_peer(blob)
    await _drain(peer, N_UNKNOWN)

    assert len(peer.bytes_recv_per_msg) <= len(CORE_KNOWN_TYPES) + 1
    # Every byte is still accounted for, under *other* (24 B per empty frame).
    assert peer.bytes_recv_per_msg == {OTHER: 24 * N_UNKNOWN}
    assert peer.bytes_recv == 24 * N_UNKNOWN


@pytest.mark.asyncio
async def test_v2_unknown_long_form_commands_do_not_grow_recv_map():
    send, recv = _v2_pair()
    blob = b"".join(
        send.encrypt_message(encode_v2_contents(_unknown_command(i), b""))
        for i in range(N_UNKNOWN))
    peer = _v1_peer(blob)
    peer._v2_transport = recv
    await _drain(peer, N_UNKNOWN)

    assert len(peer.bytes_recv_per_msg) <= len(CORE_KNOWN_TYPES) + 1
    assert set(peer.bytes_recv_per_msg) == {OTHER}
    # 3 B length + 1 B header + 13 B long-form type + 16 B tag per packet.
    assert peer.bytes_recv_per_msg[OTHER] == len(blob)


@pytest.mark.asyncio
async def test_known_types_keep_their_own_key():
    """The fix must not lump known types into *other* (Core keys them)."""
    magic = get_magic("regtest")
    frames = [
        NetworkMessage(command="ping", payload=b"\x00" * 8, magic=magic),
        NetworkMessage(command="sendtxrcncl", payload=b"\x00" * 12,
                       magic=magic),
        NetworkMessage(command="alert", payload=b"", magic=magic),
    ]
    peer = _v1_peer(b"".join(f.serialize() for f in frames))
    assert await _drain(peer, 3) == ["ping", "sendtxrcncl", "alert"]
    assert peer.bytes_recv_per_msg == {"ping": 32, "sendtxrcncl": 36,
                                       OTHER: 24}


@pytest.mark.asyncio
async def test_getpeerinfo_reports_other_bucket():
    from ouroboros.rpc import RPCServer

    magic = get_magic("regtest")
    blob = (NetworkMessage(command="pong", payload=b"\x00" * 8,
                           magic=magic).serialize()
            + NetworkMessage(command="bogus", payload=b"\x01",
                             magic=magic).serialize())
    peer = _v1_peer(blob)
    peer.version = 70016
    await _drain(peer, 2)

    pm = SimpleNamespace(peers={}, block_relay_peers={},
                         inbound_peers={"203.0.113.7:8333": peer})
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = SimpleNamespace(peer_manager=pm, p2p=None)
    info = (await rpc.rpc_getpeerinfo())[0]
    assert info["bytesrecv_per_msg"] == {"pong": 32, OTHER: 25}
