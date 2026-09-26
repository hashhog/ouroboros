"""Handshake Core-parity tests (bitcoin-core net_processing.cpp).

Core rules exercised here:

* ``MIN_PEER_PROTO_VERSION = 31800`` (node/protocol_version.h:18) is the ONLY
  version floor, applied to every peer (net_processing.cpp:3619).  An inbound
  VERSION(70002) with no NODE_WITNESS completes the handshake.
* The desirable-services check (NODE_WITNESS) applies only to connections that
  ``ExpectServicesFromConn`` -- automatic outbound (net_processing.cpp:3609).
* Between VERSION and VERACK Core PROCESSES sendheaders (:3896) and sendcmpct
  (:3901) -- the state is recorded -- and LOGS-AND-IGNORES everything else
  ("Unsupported message prior to verack", :4010).  No disconnect, no
  misbehaviour, no message-count cap.
* Feature messages we send are gated on the common version: sendheaders
  >= 70012, feefilter >= 70013, sendcmpct >= 70014, wtxidrelay/sendaddrv2
  >= 70016; ping carries a nonce only above BIP0031 (60000).
"""

from __future__ import annotations

import asyncio
import struct
import time

import pytest

from ouroboros.p2p_messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    NetworkMessage,
    SendCmpctMessage,
    get_magic,
)
from ouroboros.peer import MIN_PEER_VERSION, Peer


NET = "regtest"


def _version_payload(version: int, services: int) -> bytes:
    na = struct.pack("<Q", 0) + b"\x00" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", 0)
    ua = b"/test:0.1/"
    return (
        struct.pack("<iQq", version, services, int(time.time()))
        + na + na + struct.pack("<Q", 424242)
        + bytes([len(ua)]) + ua + struct.pack("<i", 0) + b"\x00"
    )


def _msg(cmd: str, payload: bytes = b"") -> NetworkMessage:
    return NetworkMessage(command=cmd, payload=payload, magic=get_magic(NET))


class _Scripted:
    """Feed a fixed list of inbound messages; capture everything we send."""

    def __init__(self, peer: Peer, incoming: list[NetworkMessage]):
        self.incoming = list(incoming)
        self.sent: list[str] = []
        peer.receive_message = self._recv  # type: ignore[assignment]
        peer.send_message = self._send  # type: ignore[assignment]

    async def _recv(self, timeout: float = 30.0) -> NetworkMessage:
        if not self.incoming:
            raise ConnectionError("script exhausted (peer would hang)")
        return self.incoming.pop(0)

    async def _send(self, msg: NetworkMessage) -> None:
        self.sent.append(msg.command)


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Minimum version / services
# --------------------------------------------------------------------------

def test_min_peer_version_is_core_31800():
    assert MIN_PEER_VERSION == 31800


def test_inbound_version_70002_completes_handshake():
    peer = Peer("127.0.0.1", 50001, NET, inbound=True)
    io = _Scripted(peer, [
        _msg("version", _version_payload(70002, NODE_NETWORK)),
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert peer.version == 70002
    # Never send a 70002 peer messages from protocol versions it predates.
    for cmd in ("sendheaders", "sendcmpct", "feefilter", "wtxidrelay", "sendaddrv2"):
        assert cmd not in io.sent, f"sent {cmd} to a 70002 peer: {io.sent}"
    assert io.sent == ["version", "verack"]


def test_inbound_version_below_31800_rejected():
    peer = Peer("127.0.0.1", 50002, NET, inbound=True)
    _Scripted(peer, [_msg("version", _version_payload(31799, NODE_NETWORK)), _msg("verack")])
    with pytest.raises(Exception):
        _run(peer._inbound_handshake(0))
    assert not peer.handshake_complete


def test_outbound_automatic_requires_witness():
    peer = Peer("127.0.0.1", 50003, NET, inbound=False)
    peer.expect_services = True
    _Scripted(peer, [_msg("version", _version_payload(70002, NODE_NETWORK)), _msg("verack")])
    with pytest.raises(Exception):
        _run(peer._handshake(0))
    assert not peer.handshake_complete


def test_outbound_manual_accepts_old_non_witness_peer():
    peer = Peer("127.0.0.1", 50004, NET, inbound=False)
    peer.expect_services = False
    io = _Scripted(peer, [_msg("version", _version_payload(70002, NODE_NETWORK)), _msg("verack")])
    _run(peer._handshake(0))
    assert peer.handshake_complete
    assert "sendheaders" not in io.sent and "sendcmpct" not in io.sent


def test_version_gated_feature_messages_70012():
    peer = Peer("127.0.0.1", 50005, NET, inbound=True)
    io = _Scripted(peer, [_msg("version", _version_payload(70012, NODE_NETWORK)), _msg("verack")])
    _run(peer._inbound_handshake(0))
    assert "sendheaders" in io.sent
    assert "feefilter" not in io.sent  # FEEFILTER_VERSION 70013
    assert "sendcmpct" not in io.sent  # SHORT_IDS_BLOCKS_VERSION 70014


# --------------------------------------------------------------------------
# Pre-verack message handling
# --------------------------------------------------------------------------

def test_pre_verack_sendheaders_recorded_inbound():
    peer = Peer("127.0.0.1", 50006, NET, inbound=True)
    _Scripted(peer, [
        _msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS)),
        _msg("sendheaders"),
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert peer.wants_headers is True


def test_pre_verack_sendheaders_recorded_outbound():
    peer = Peer("127.0.0.1", 50007, NET, inbound=False)
    _Scripted(peer, [
        _msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS)),
        _msg("sendheaders"),
        _msg("verack"),
    ])
    _run(peer._handshake(0))
    assert peer.handshake_complete
    assert peer.wants_headers is True


def test_pre_verack_sendcmpct_recorded():
    peer = Peer("127.0.0.1", 50008, NET, inbound=True)
    sc = SendCmpctMessage(announce=True, version=2).to_network_message(NET)
    _Scripted(peer, [
        _msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS)),
        sc,
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert peer.wants_cmpctblock is True
    # stashed for PeerManager's on_sendcmpct replay (cmpct_peers bookkeeping)
    assert peer._pending_sendcmpct_payload == sc.payload


def test_pre_verack_sendcmpct_v1_ignored():
    peer = Peer("127.0.0.1", 50009, NET, inbound=True)
    _Scripted(peer, [
        _msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS)),
        SendCmpctMessage(announce=True, version=1).to_network_message(NET),
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert peer.wants_cmpctblock is False
    assert peer._pending_sendcmpct_payload is None


def test_pre_verack_ping_inv_ignored_no_disconnect():
    peer = Peer("127.0.0.1", 50010, NET, inbound=True)
    io = _Scripted(peer, [
        _msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS)),
        _msg("ping", struct.pack("<Q", 7)),
        _msg("inv", b"\x01" + struct.pack("<I", 1) + b"\x11" * 32),
        _msg("feefilter", struct.pack("<q", 5000)),
        _msg("getheaders", b"\x00" * 37),
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert "pong" not in io.sent            # ignored, not answered
    assert peer.peer_feefilter == 0          # ignored, not applied


def test_pre_verack_no_message_count_cap():
    """Core has no count cap -- only the connect timeout bounds the window."""
    peer = Peer("127.0.0.1", 50011, NET, inbound=False)
    msgs = [_msg("version", _version_payload(70016, NODE_NETWORK | NODE_WITNESS))]
    msgs += [_msg("ping", struct.pack("<Q", i)) for i in range(50)]
    msgs.append(_msg("verack"))
    _Scripted(peer, msgs)
    _run(peer._handshake(0))
    assert peer.handshake_complete


def test_wtxidrelay_ignored_below_70016():
    peer = Peer("127.0.0.1", 50012, NET, inbound=True)
    _Scripted(peer, [
        _msg("version", _version_payload(70015, NODE_NETWORK | NODE_WITNESS)),
        _msg("wtxidrelay"),
        _msg("verack"),
    ])
    _run(peer._inbound_handshake(0))
    assert peer.handshake_complete
    assert peer.wtxid_relay is False


# --------------------------------------------------------------------------
# Block requests only go to NODE_WITNESS peers (Core CanServeWitnesses)
# --------------------------------------------------------------------------

class _InvDB:
    def has_block_hash(self, h):
        return False

    def get_best_block(self):
        return (b"\x00" * 32, 10)

    def __getattr__(self, name):  # anything else the fork-getheaders path touches
        def _none(*a, **k):
            return None
        return _none


class _PM:
    network = NET

    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return list(self._peers)


def _ready_peer(i: int, services: int, version: int) -> Peer:
    from ouroboros.peer import PeerState
    p = Peer("10.9.0.%d" % i, 18444, NET, inbound=True)
    p.state = PeerState.READY
    p.services = services
    p.version = version
    p.handshake_complete = True
    p.sent = []

    async def _send(m):
        p.sent.append(m)

    p.send_message = _send
    return p


def _block_sync(peers):
    from ouroboros.block_sync import BlockSync
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(bs, db=_InvDB(), validator=None, peer_manager=_PM(peers), mempool=None)
    return bs


def _getdata_block_items(peer):
    from ouroboros.p2p_messages import MSG_WITNESS_BLOCK, GetDataMessage
    out = []
    for m in peer.sent:
        if m.command == "getdata":
            out += [h for t, h in GetDataMessage.from_payload(m.payload).inventory
                    if t & 0xFFFF == 2 or t == MSG_WITNESS_BLOCK]
    return out


def _inv_block(h: bytes) -> NetworkMessage:
    return _msg("inv", b"\x01" + struct.pack("<I", 2) + h)


def test_block_inv_from_non_witness_peer_not_fetched():
    old = _ready_peer(1, NODE_NETWORK, 70002)
    bs = _block_sync([old])
    _run(bs.handle_inv(_inv_block(b"\x42" * 32), old))
    assert _getdata_block_items(old) == []
    assert b"\x42" * 32 not in bs.requested_blocks


def test_block_inv_from_witness_peer_fetched():
    new = _ready_peer(2, NODE_NETWORK | NODE_WITNESS, 70016)
    bs = _block_sync([new])
    _run(bs.handle_inv(_inv_block(b"\x43" * 32), new))
    assert _getdata_block_items(new) == [b"\x43" * 32]


def test_fallback_download_peer_requires_witness():
    old = _ready_peer(3, NODE_NETWORK, 70002)
    new = _ready_peer(4, NODE_NETWORK | NODE_WITNESS, 70016)
    bs = _block_sync([old])
    bs._header_sync_peer = old
    assert bs._block_download_fallback_peer() is None
    bs = _block_sync([old, new])
    bs._header_sync_peer = old
    assert bs._block_download_fallback_peer() is new


def test_force_block_download_skips_non_witness_peer():
    old = _ready_peer(5, NODE_NETWORK, 70002)
    bs = _block_sync([old])
    bs._validated_headers = [(b"\x44" * 32, None)]
    _run(bs._force_block_download_from(old))
    assert _getdata_block_items(old) == []
