"""getpeerinfo fields Core always/conditionally emits (rpc/net.cpp):
addrbind, addrlocal, bytessent_per_msg, bytesrecv_per_msg."""
import asyncio
from types import SimpleNamespace

from ouroboros.peer import Peer
from ouroboros.rpc import RPCServer


def _rpc(peer):
    pm = SimpleNamespace(peers={}, block_relay_peers={},
                         inbound_peers={"203.0.113.7:8333": peer})
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = SimpleNamespace(peer_manager=pm, p2p=None)
    return rpc


def _peer():
    p = Peer("203.0.113.7", 8333, "regtest", transport_version=1, inbound=True)
    p.version = 70016
    return p


def test_per_msg_maps_always_present_empty():
    info = asyncio.run(_rpc(_peer()).rpc_getpeerinfo())[0]
    assert info["bytessent_per_msg"] == {}
    assert info["bytesrecv_per_msg"] == {}


def test_per_msg_maps_reflect_tracked_bytes():
    p = _peer()
    p.bytes_sent_per_msg = {"ping": 32}
    p.bytes_recv_per_msg = {"pong": 32, "version": 126}
    info = asyncio.run(_rpc(p).rpc_getpeerinfo())[0]
    assert info["bytessent_per_msg"] == {"ping": 32}
    assert info["bytesrecv_per_msg"] == {"pong": 32, "version": 126}


def test_addrbind_and_addrlocal_when_known():
    p = _peer()
    p.writer = SimpleNamespace(
        get_extra_info=lambda k: ("127.0.0.1", 18444) if k == "sockname" else None)
    p.addr_local = ("127.0.0.1", 18444)
    info = asyncio.run(_rpc(p).rpc_getpeerinfo())[0]
    assert info["addrbind"] == "127.0.0.1:18444"
    assert info["addrlocal"] == "127.0.0.1:18444"


def test_addrlocal_omitted_when_unknown():
    info = asyncio.run(_rpc(_peer()).rpc_getpeerinfo())[0]
    assert "addrlocal" not in info and "addrbind" not in info


def test_send_receive_counters_keyed_by_command():
    p = _peer()
    assert p.bytes_sent_per_msg == {} and p.bytes_recv_per_msg == {}
