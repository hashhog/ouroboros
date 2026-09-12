"""Control for QUEUES.md ouroboros item 3: per-peer sync fields.

Bitcoin Core rpc/net.cpp:270-277 emits, per peer:

  presynced_headers  HeadersSyncState::GetPresyncHeight, or -1
  synced_headers     pindexBestKnownBlock->nHeight (nSyncHeight)
  synced_blocks      pindexLastCommonBlock->nHeight (nCommonHeight)
  inflight           heights of CNodeState.vBlocksInFlight

Those are live measurements from CNodeState, not VERSION startHeight and
not the -1 stub. A peer that has announced a header we also have, delivered
a block body, or has a getdata in flight must surface those heights;
a peer that has done none of that stays at -1 / [].

Control: ``pytest tests/test_per_peer_sync_fields.py``
"""

from __future__ import annotations

import asyncio
import hashlib
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import BlockHeader, HeadersMessage
from ouroboros.peer import Peer, PeerState
from ouroboros.rpc import RPCServer


# ---------------------------------------------------------------------------
# Peer-level: unset sentinel, monotonic, genesis zero, body implies header
# ---------------------------------------------------------------------------


def test_peer_synced_heights_start_unset_and_monotonic() -> None:
    """VERSION startHeight must not leak into nSyncHeight / nCommonHeight.

    Core GetNodeStateStats: nSyncHeight / nCommonHeight are -1 until
    pindexBestKnownBlock / pindexLastCommonBlock are set. Height 0 (genesis)
    is a real measurement and must not collapse to the unset sentinel.
    """
    p = Peer("1.2.3.4", 8333, "regtest")
    p.start_height = 800000
    p.note_block_height(800000)
    p.state = PeerState.READY

    assert p.synced_headers == -1
    assert p.synced_blocks == -1
    assert p.best_known_height == 800000

    p.update_synced_headers(0)
    assert p.synced_headers == 0
    assert p.synced_blocks == -1

    p.update_synced_headers(50)
    p.update_synced_headers(20)  # must not rewind
    assert p.synced_headers == 50
    assert p.best_known_height == 800000  # 50 < 800000; best-known stays

    p.update_synced_headers(850010)
    assert p.synced_headers == 850010
    assert p.best_known_height == 850010

    p.update_synced_blocks(40)
    assert p.synced_blocks == 40
    assert p.synced_headers == 850010  # headers stay ahead

    p.update_synced_blocks(850020)
    assert p.synced_blocks == 850020
    assert p.synced_headers == 850020  # body implies header


def test_update_synced_ignores_garbage() -> None:
    p = Peer("1.2.3.4", 8333, "regtest")
    p.update_synced_headers(None)
    p.update_synced_headers("nope")
    p.update_synced_headers(-3)
    p.update_synced_blocks(None)
    assert p.synced_headers == -1
    assert p.synced_blocks == -1


# ---------------------------------------------------------------------------
# getpeerinfo: live measurements, not -1 stubs
# ---------------------------------------------------------------------------


def test_getpeerinfo_per_peer_sync_fields() -> None:
    """getpeerinfo must emit the live nSyncHeight / nCommonHeight, not -1.

    Mirrors blockbrew TestGetPeerInfoPerPeerSyncFields / hotbuns
    "per-peer sync fields are live measurements, not -1 stubs".
    """

    class LivePeer:
        id = 1
        address = "192.168.1.3:8333"
        host = "192.168.1.3"
        port = 8333
        services = 1
        synced_headers = 850010
        synced_blocks = 849900

    class UnsetPeer:
        id = 2
        address = "192.168.1.4:8333"
        host = "192.168.1.4"
        port = 8333
        services = 1
        start_height = 800000

    class _PM:
        peers = [LivePeer(), UnsetPeer()]
        block_relay_peers: list = []
        inbound_peers: list = []

    class _BS:
        def inflight_heights_for_peer(self, peer):
            if getattr(peer, "id", None) == 1:
                return [100]
            return []

        def presync_height_for_peer(self, peer):
            return -1

    class _Node:
        peer_manager = _PM()
        block_sync = _BS()

    result = asyncio.run(RPCServer(_Node()).rpc_getpeerinfo())
    assert len(result) == 2
    by_addr = {row["addr"]: row for row in result}

    live = by_addr["192.168.1.3:8333"]
    assert live["synced_headers"] == 850010
    assert live["synced_blocks"] == 849900
    assert live["inflight"] == [100]
    assert live["presynced_headers"] == -1

    unset = by_addr["192.168.1.4:8333"]
    assert unset["synced_headers"] == -1
    assert unset["synced_blocks"] == -1
    assert unset["inflight"] == []
    assert unset["presynced_headers"] == -1
    assert "startingheight" not in unset


# ---------------------------------------------------------------------------
# handle_headers / handle_block: the sync path actually writes the fields
# ---------------------------------------------------------------------------


class _StubBlk:
    def __init__(self, bits: int, timestamp: int):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = b"\x00" * 32


def _make_block_sync(tip_hash: bytes, tip_height: int) -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.has_block_hash.return_value = False
    db.get_median_time_past.return_value = 1_700_000_000
    db.get_block_by_height.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    db.get_block.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)

    peer_manager = MagicMock()
    peer_manager.network = "mainnet"
    peer_manager.misbehaving = MagicMock()
    return BlockSync(db=db, validator=MagicMock(), peer_manager=peer_manager)


def _real_block_one() -> BlockHeader:
    genesis_be = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    merkle_be = bytes.fromhex(
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    )
    return BlockHeader(
        version=1,
        prev_blockhash=genesis_be[::-1],
        merkle_root=merkle_be[::-1],
        timestamp=1_231_469_665,
        bits=0x1D00FFFF,
        nonce=2_573_394_689,
    )


def _g8_ready_sync(monkeypatch) -> tuple[BlockSync, bytes]:
    """BlockSync that will accept mainnet block 1 as a connecting header."""
    import sync as _sync_for_test

    min_work = int(_sync_for_test.get_minimum_chain_work("mainnet"), 16)
    genesis_le = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )[::-1]
    bs = _make_block_sync(tip_hash=genesis_le, tip_height=0)

    db_tip_chainwork = min_work + (1 << 80)

    def _chainwork_by_height(height: int) -> int:
        if height >= 944_184:
            return 1 << 120
        return db_tip_chainwork

    bs.db.get_chainwork_by_height = MagicMock(side_effect=_chainwork_by_height)

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: None)
    return bs, genesis_le


def _real_peer() -> Peer:
    p = Peer("192.0.2.7", 8333, "mainnet")
    p.state = PeerState.READY
    p.start_height = 0
    return p


def _headers_msg(headers: list[BlockHeader]):
    msg = MagicMock()
    msg.payload = HeadersMessage(headers=headers).serialize_payload()
    return msg


@pytest.mark.asyncio
async def test_handle_headers_advances_synced_headers(monkeypatch) -> None:
    """Core UpdateBlockAvailability: a header this peer announced that we
    also have becomes nSyncHeight. Not VERSION startHeight, not -1.
    """
    bs, _genesis = _g8_ready_sync(monkeypatch)
    peer = _real_peer()
    assert peer.synced_headers == -1

    await bs.handle_headers(_headers_msg([_real_block_one()]), peer, min_pow_checked=False)

    assert len(bs._validated_headers) == 1
    assert peer.synced_headers == 1
    assert peer.synced_blocks == -1  # header-only; no body yet


@pytest.mark.asyncio
async def test_handle_headers_already_known_advances_synced_headers(monkeypatch) -> None:
    """A re-delivered (already-queued) batch still updates pindexBestKnownBlock.

    Core UpdateBlockAvailability runs on every announced hash that is in our
    index, including ones we already have.
    """
    bs, _genesis = _g8_ready_sync(monkeypatch)
    peer = _real_peer()
    msg = _headers_msg([_real_block_one()])
    await bs.handle_headers(msg, peer, min_pow_checked=False)
    assert peer.synced_headers == 1

    peer.synced_headers = -1
    peer.best_known_height = 0
    await bs.handle_headers(msg, peer, min_pow_checked=False)

    assert len(bs._validated_headers) == 1  # not duplicated
    assert peer.synced_headers == 1


@pytest.mark.asyncio
async def test_handle_block_advances_synced_blocks(monkeypatch) -> None:
    """A body from this peer advances nCommonHeight and implies the header."""
    db = MagicMock()
    db.get_best_block.return_value = (b"\x11" * 32, 849899)
    db.has_block_hash.return_value = False
    pm = MagicMock()
    pm.network = "regtest"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)

    payload = b"\xab" * 80 + b"\x00"
    block_hash = hashlib.sha256(hashlib.sha256(payload[:80]).digest()).digest()
    bs._validated_headers = [(block_hash, object())]

    async def _noop_drain():
        return 0

    async def _noop_req():
        return None

    monkeypatch.setattr(bs, "_drain_block_buffer", _noop_drain)
    monkeypatch.setattr(bs, "_request_next_blocks", _noop_req)

    peer = _real_peer()
    assert peer.synced_blocks == -1

    msg = MagicMock()
    msg.payload = payload
    await bs.handle_block(msg, peer)

    assert peer.synced_blocks == 849900
    assert peer.synced_headers == 849900


def test_inflight_heights_for_peer() -> None:
    """getpeerinfo.inflight is heights of blocks requested from this peer."""
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 99)
    pm = MagicMock()
    pm.network = "regtest"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)

    peer = _real_peer()
    other = Peer("192.0.2.8", 8333, "regtest")
    h_ours = b"\x22" * 32
    h_theirs = b"\x33" * 32
    h_unknown = b"\x44" * 32
    bs._validated_headers = [
        (h_ours, object()),
        (h_theirs, object()),
    ]
    bs.requested_blocks[h_ours] = 1.0
    bs.requested_blocks[h_theirs] = 1.0
    bs.requested_blocks[h_unknown] = 1.0
    bs._block_request_peer[h_ours] = peer
    bs._block_request_peer[h_theirs] = other
    bs._block_request_peer[h_unknown] = peer  # no header → omitted (Core null pindex)

    assert bs.inflight_heights_for_peer(peer) == [100]
    assert bs.inflight_heights_for_peer(other) == [101]
    assert bs.inflight_heights_for_peer(Peer("9.9.9.9", 1, "regtest")) == []


def test_presync_height_for_peer() -> None:
    """getpeerinfo.presynced_headers is the low-work PRESYNC height, or -1."""
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    pm = MagicMock()
    pm.network = "regtest"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    peer = _real_peer()
    other = Peer("192.0.2.8", 8333, "regtest")

    assert bs.presync_height_for_peer(peer) == -1
    bs._lowwork_presync[bs._peer_key(peer)] = {"height": 12345}
    assert bs.presync_height_for_peer(peer) == 12345
    assert bs.presync_height_for_peer(other) == -1
