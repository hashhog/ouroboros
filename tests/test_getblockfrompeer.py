"""In-process unit tests for the ``getblockfrompeer`` RPC (ouroboros).

Mirrors Bitcoin Core rpc/blockchain.cpp getblockfrompeer +
net_processing.cpp PeerManagerImpl::FetchBlock:

  (a) unknown header                 -> RPC_MISC_ERROR(-1) "Block header missing"
  (b) bad / out-of-range peer_id     -> RPC_MISC_ERROR(-1) "Peer does not exist"
  (c) success                        -> sends a witness-block GETDATA for the
                                        requested hash to the resolved peer and
                                        returns {} (UniValue::VOBJ).

The test runs entirely in-process against a lightweight fake node — no
multi-node regtest, no real RocksDB, no real sockets — so it is OOM-free and
fast.  The peer_id is resolved against the SAME aggregated index that
``getpeerinfo`` emits, which is also asserted here.
"""

import asyncio
import types

import pytest

from ouroboros.rpc import RPCServer, RpcError, RPC_MISC_ERROR
from ouroboros.p2p_messages import (
    GetDataMessage,
    INV_TYPE_BLOCK,
    MSG_WITNESS_BLOCK,
    MSG_WITNESS_FLAG,
)


# A real, known block hash (mainnet block 1), display-order (big-endian) hex.
KNOWN_BLOCKHASH_BE = (
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
)
KNOWN_BLOCKHASH_INTERNAL_LE = bytes.fromhex(KNOWN_BLOCKHASH_BE)[::-1]


class FakePeer:
    """Minimal stand-in for ouroboros.peer.Peer capturing outbound messages."""

    def __init__(self, host="127.0.0.1", port=8333):
        self.host = host
        self.port = port
        self.sent = []  # list of NetworkMessage objects

    async def send_message(self, msg):
        self.sent.append(msg)


class FakeNativeDB:
    """Stands in for node.db._db (the Rust layer)."""

    def __init__(self, header_known: bool):
        self._header_known = header_known

    def get_raw_header_with_chainwork(self, block_hash):
        if self._header_known:
            # (raw_header_bytes, n_tx, chainwork, height, mediantime, nexthash)
            return (b"\x00" * 80, 1, b"\x00" * 32, 1, 0, b"\x00" * 32)
        return None


class FakeDB:
    """Stands in for node.db (the Python wrapper)."""

    def __init__(self, body_present: bool, header_known: bool):
        self._body_present = body_present
        # If the body is present the header is implicitly known.
        self._db = FakeNativeDB(header_known or body_present)

    def get_block(self, block_hash):
        if self._body_present:
            return object()  # truthy "block" sentinel
        return None


class FakePeerManager:
    """Three-bucket PeerManager like ouroboros uses."""

    def __init__(self, peers=None, block_relay_peers=None, inbound_peers=None):
        self.peers = peers if peers is not None else []
        self.block_relay_peers = (
            block_relay_peers if block_relay_peers is not None else []
        )
        self.inbound_peers = (
            inbound_peers if inbound_peers is not None else []
        )


def make_rpc(*, body_present=False, header_known=True, pm=None):
    node = types.SimpleNamespace(
        db=FakeDB(body_present=body_present, header_known=header_known),
        peer_manager=pm,
        network="mainnet",
    )
    return RPCServer(node, port=18450)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# (a) unknown header -> "Block header missing"
# ---------------------------------------------------------------------------
def test_unknown_header_raises_block_header_missing():
    peer = FakePeer()
    pm = FakePeerManager(peers=[peer])
    rpc = make_rpc(body_present=False, header_known=False, pm=pm)

    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 0))

    assert ei.value.code == RPC_MISC_ERROR == -1
    assert ei.value.message == "Block header missing"
    # No message must have been sent.
    assert peer.sent == []


# ---------------------------------------------------------------------------
# (b) bad / out-of-range peer_id -> "Peer does not exist"
# ---------------------------------------------------------------------------
def test_out_of_range_peer_id_raises_peer_does_not_exist():
    peer = FakePeer()
    pm = FakePeerManager(peers=[peer])  # only id 0 exists
    rpc = make_rpc(body_present=False, header_known=True, pm=pm)

    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 5))

    assert ei.value.code == -1
    assert ei.value.message == "Peer does not exist"
    assert peer.sent == []


def test_no_peer_manager_raises_peer_does_not_exist():
    rpc = make_rpc(body_present=False, header_known=True, pm=None)
    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 0))
    assert ei.value.code == -1
    assert ei.value.message == "Peer does not exist"


# ---------------------------------------------------------------------------
# (c) success -> getdata sent to the resolved peer + returns {}
# ---------------------------------------------------------------------------
def test_success_sends_witness_block_getdata_and_returns_empty():
    peer = FakePeer()
    pm = FakePeerManager(peers=[peer])
    rpc = make_rpc(body_present=False, header_known=True, pm=pm)

    result = run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 0))

    # Returns {} (Core UniValue::VOBJ).
    assert result == {}

    # Exactly one message sent to the resolved peer.
    assert len(peer.sent) == 1
    netmsg = peer.sent[0]
    assert netmsg.command == "getdata"

    # Decode the getdata payload and verify the inventory.
    decoded = GetDataMessage.from_payload(netmsg.payload)
    assert len(decoded.inventory) == 1
    inv_type, inv_hash = decoded.inventory[0]

    # Witness-block inventory type (MSG_BLOCK | MSG_WITNESS_FLAG).
    assert inv_type == MSG_WITNESS_BLOCK
    assert inv_type & MSG_WITNESS_FLAG == MSG_WITNESS_FLAG
    assert inv_type & ~MSG_WITNESS_FLAG == INV_TYPE_BLOCK

    # Hash on the wire is the internal little-endian byte order of the BE hash.
    assert inv_hash == KNOWN_BLOCKHASH_INTERNAL_LE


# ---------------------------------------------------------------------------
# Extra parity: peer_id resolves against the SAME aggregated index that
# getpeerinfo emits (peers, then block_relay_peers, then inbound_peers).
# ---------------------------------------------------------------------------
def test_peer_id_matches_getpeerinfo_aggregated_index():
    p0 = FakePeer(port=8001)  # peers[0]      -> id 0
    p1 = FakePeer(port=8002)  # block_relay[0]-> id 1
    p2 = FakePeer(port=8003)  # inbound[0]    -> id 2
    pm = FakePeerManager(
        peers=[p0],
        block_relay_peers=[p1],
        inbound_peers=[p2],
    )
    rpc = make_rpc(body_present=False, header_known=True, pm=pm)

    # getpeerinfo's aggregated order is exactly [p0, p1, p2] with ids 0,1,2.
    aggregated = rpc._aggregate_peerinfo_peers(pm)
    assert aggregated == [p0, p1, p2]

    # Fetch from id 2 -> must reach the inbound peer p2, nobody else.
    result = run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 2))
    assert result == {}
    assert len(p2.sent) == 1
    assert p0.sent == [] and p1.sent == []

    # And id 1 -> p1 only.
    run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 1))
    assert len(p1.sent) == 1
    assert len(p2.sent) == 1  # unchanged from before


# ---------------------------------------------------------------------------
# Optional parity: body already present -> "Block already downloaded".
# ---------------------------------------------------------------------------
def test_body_present_raises_block_already_downloaded():
    peer = FakePeer()
    pm = FakePeerManager(peers=[peer])
    rpc = make_rpc(body_present=True, header_known=True, pm=pm)

    with pytest.raises(RpcError) as ei:
        run(rpc.rpc_getblockfrompeer(KNOWN_BLOCKHASH_BE, 0))

    assert ei.value.code == -1
    assert ei.value.message == "Block already downloaded"
    assert peer.sent == []
