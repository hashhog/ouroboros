"""Failing control for the at-tip stall class (QUEUES.md item 2).

Diagnosis: ``docs/STALL-CLASS-70-CRITICALS.md``. Near-tip headers-first
download is scheduled onto peers that will never deliver the connect-frontier
block, and the stall-clock treats "peer has nothing new" as "peer is dead".

This file is the in-repo control that has to go red on current master and
green after the fix. Not another watchdog.

Ref: Bitcoin Core ``CanServeBlocks`` / ``CanServeWitnesses``
(net_processing.cpp:1152-1168), ``CheckProofOfWork`` / ``DeriveTarget``
(pow.cpp:146-157), ``BLOCK_STALLING_TIMEOUT`` (net_processing.cpp:133-135).
"""

from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.block_sync import (
    FRONTIER_REQUEST_INTERVAL,
    BlockSync,
)
from ouroboros.p2p_messages import (
    NODE_BLOOM,
    NODE_NETWORK,
    NODE_WITNESS,
    BlockHeader,
    GetDataMessage,
    HeadersMessage,
)
from ouroboros.peer import Peer
from ouroboros.validation import POW_LIMIT_MAINNET

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _StubBlk:
    def __init__(self, bits: int, timestamp: int):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = b"\x00" * 32


def _h(tag: int) -> bytes:
    return hashlib.sha256(f"slot-{tag}".encode()).digest()


def _make_block_sync(
    tip_hash: bytes = b"\x11" * 32,
    tip_height: int = 900_000,
    network: str = "mainnet",
) -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.has_block_hash.return_value = False
    db.get_median_time_past.return_value = 1_700_000_000
    db.get_block_by_height.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    db.get_block.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    db.get_block_hash_by_height.return_value = None
    db.find_height_of_hash.return_value = None

    peer_manager = MagicMock()
    peer_manager.network = network
    peer_manager.misbehaving = MagicMock()
    return BlockSync(db=db, validator=MagicMock(), peer_manager=peer_manager)


def _make_ready_peer(
    host: str,
    score: int = 100,
    services: int = NODE_NETWORK | NODE_WITNESS,
    start_height: int = 900_002,
) -> MagicMock:
    peer = MagicMock(spec=Peer)
    peer.host = host
    peer.port = 8333
    peer.score = score
    peer.services = services
    peer.start_height = start_height
    peer.best_known_height = start_height
    peer.is_connected.return_value = True
    peer.send_message = AsyncMock()
    peer.adjust_score = MagicMock()
    peer.is_manual = False
    peer.noban = False
    return peer


def _frontier_sends(peer: MagicMock, frontier_hash: bytes) -> int:
    n = 0
    for call in peer.send_message.await_args_list:
        netmsg = call.args[0]
        gd = GetDataMessage.from_payload(netmsg.payload)
        inv = list(gd.inventory)
        if inv and inv[0][1] == frontier_hash:
            n += 1
    return n


def _mine_easy(prev: bytes, bits: int = 0x207FFFFF, tag: bytes = b"easy") -> BlockHeader:
    """Mine a header whose hash meets ``bits``. 0x207fffff is in-process cheap."""
    target = BlockSync._bits_to_target(bits)
    for bump in range(1 << 20):
        h = BlockHeader(
            version=4,
            prev_blockhash=prev,
            merkle_root=hashlib.sha256(tag + bump.to_bytes(8, "little")).digest(),
            timestamp=1_700_000_000,
            bits=bits,
            nonce=bump & 0xFFFFFFFF,
        )
        digest = hashlib.sha256(hashlib.sha256(h.serialize()).digest()).digest()
        if int.from_bytes(digest, "little") <= target:
            return h
    raise AssertionError("could not mine a header meeting the inflated target")


# ---------------------------------------------------------------------------
# 1. target > powLimit  (CheckProofOfWork / DeriveTarget, deferred from 1.0.1)
# ---------------------------------------------------------------------------


def test_header_meets_pow_hash_only_accepts_inflated_target():
    """Sanity: hash<=claimed-target still holds for bits=0x207fffff.

    That is Core's hash comparison, NOT the range check. The range check is
    the next test — this one proves the header is a real positive control
    (it would be accepted if we only compared hash to the claimed target).
    """
    h = _mine_easy(b"\x11" * 32)
    assert BlockSync._header_meets_pow(h) is True


def test_target_above_powlimit_rejected_as_high_hash_not_bad_diffbits():
    """Core CheckBlockHeader: DeriveTarget returns nullopt when
    ``bnTarget > powLimit`` → "high-hash", BEFORE ContextualCheckBlockHeader
    even looks at nBits==GetNextWorkRequired ("bad-diffbits").

    Pre-fix, ``_header_meets_pow`` only compared hash<=claimed-target, so a
    mainnet header claiming 0x207fffff (regtest powLimit, target >> mainnet
    powLimit) was a PoW *pass* and only later a bad-diffbits reject.
    """
    h = _mine_easy(b"\x11" * 32, bits=0x207FFFFF)
    assert BlockSync._header_meets_pow(h) is True
    # Production header-sync must apply the network powLimit.
    assert (
        BlockSync._header_meets_pow(h, pow_limit=POW_LIMIT_MAINNET) is False
    ), (
        "nBits whose target exceeds mainnet powLimit must fail CheckProofOfWork "
        "(pow.cpp:155), not sail through as hash<=inflated-target"
    )


@pytest.mark.asyncio
async def test_handle_headers_rejects_target_above_powlimit_as_pow(monkeypatch):
    """handle_headers on mainnet must increment the PoW-reject counter, not
    admit the header and not wait for bad-diffbits. Core order:
    CheckBlockHeader (high-hash) then ContextualCheckBlockHeader.
    """
    tip_hash = b"\x11" * 32
    bs = _make_block_sync(tip_hash=tip_hash, tip_height=100)
    easy = _mine_easy(tip_hash, bits=0x207FFFFF, tag=b"hdr-powlimit")
    assert BlockSync._header_meets_pow(easy) is True

    headers_msg = HeadersMessage(headers=[easy])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()
    peer = _make_ready_peer("127.0.0.1")
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    await bs.handle_headers(msg, peer)

    assert bs._validated_headers == []
    assert bs._headers_pow_rejected == 1, (
        "target > powLimit is CheckBlockHeader / high-hash, not bad-diffbits; "
        f"pow_rejected={bs._headers_pow_rejected} "
        f"diffbits_rejected={getattr(bs, '_headers_diffbits_rejected', 0)}"
    )


# ---------------------------------------------------------------------------
# 2. H1 / getdata must never target an unservable peer (CanServeBlocks)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h1_never_sends_getdata_to_unservable_low_height_peer():
    """Diagnosis control #1.

    Tip queued, two ready NODE_WITNESS peers: a high-score zombie whose
    start_height/best_known_height is far below the frontier (the 0.15.99
    stand-in, services 0xd = NETWORK|BLOOM|WITNESS), and a lower-score peer
    that can serve that height. H1/getdata must NEVER target the zombie.
    """
    tip_hash = _h(0xDEAD)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 8)]
    bs._ibd_block_buffer = {}
    bs.requested_blocks = {}

    # 0.15.99 stand-in: high score, NODE_WITNESS so the old filter lets it
    # through, but its advertised height is a 2017-era chain.
    zombie = _make_ready_peer(
        "116.202.56.177",
        score=100,
        services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,  # 0xd
        start_height=500_000,
    )
    servable = _make_ready_peer(
        "1.2.3.4",
        score=40,
        services=NODE_NETWORK | NODE_WITNESS,
        start_height=900_010,
    )
    bs.peer_manager.get_all_ready_peers.return_value = [zombie, servable]

    await bs._request_next_blocks()

    assert _frontier_sends(zombie, frontier) == 0, (
        "H1 sent getdata for the connect-frontier to a peer whose "
        "best_known_height is far below that height (CanServeBlocks / "
        "pindexBestKnownBlock)"
    )
    assert _frontier_sends(servable, frontier) == 1
    assert bs._block_request_peer.get(frontier) is servable


@pytest.mark.asyncio
async def test_h1_never_sends_getdata_to_witness_only_non_network_peer():
    """CanServeBlocks requires NODE_NETWORK | NODE_NETWORK_LIMITED.

    NODE_WITNESS alone is CanServeWitnesses, not CanServeBlocks. Pre-fix
    ``_can_serve_witness_blocks`` was the only filter, so a witness-only
    high-score peer won H1 and silently dropped MSG_WITNESS_BLOCK.
    """
    tip_hash = _h(0xBEEF)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 8)]
    bs._ibd_block_buffer = {}
    bs.requested_blocks = {}

    witness_only = _make_ready_peer(
        "10.0.0.9",
        score=100,
        services=NODE_WITNESS,
        start_height=900_010,
    )
    full = _make_ready_peer(
        "10.0.0.8",
        score=10,
        services=NODE_NETWORK | NODE_WITNESS,
        start_height=900_010,
    )
    bs.peer_manager.get_all_ready_peers.return_value = [witness_only, full]

    await bs._request_next_blocks()

    assert _frontier_sends(witness_only, frontier) == 0
    assert _frontier_sends(full, frontier) == 1


# ---------------------------------------------------------------------------
# 3. Stall-clock: empty / unconnecting headers at tip are not a stall
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_headers_at_tip_reset_stall_clock():
    """Diagnosis control #2a.

    An empty ``headers`` message is the honest at-tip reply. Pre-fix the
    stall-clock only reset on an *accepted* batch, so every honest tip-peer
    tripped the 30s rotate + ``adjust_score(-2)``.
    """
    tip_hash = b"\x22" * 32
    bs = _make_block_sync(tip_hash=tip_hash, tip_height=900_000)
    peer = _make_ready_peer("212.132.126.162", start_height=900_000)
    bs._header_sync_peer = peer
    bs._header_sync_time = time.time() - 25.0
    stale = bs._header_sync_time

    headers_msg = HeadersMessage(headers=[])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()
    await bs.handle_headers(msg, peer)

    assert bs._header_sync_time > stale, (
        "empty headers at tip must reset the stall-clock; otherwise the "
        "30s rotate demotes every honest tip-peer (adjust_score(-2))"
    )
    peer.adjust_score.assert_not_called()
    assert bs._header_sync_peer is peer


@pytest.mark.asyncio
async def test_unconnecting_headers_at_tip_reset_stall_clock(monkeypatch):
    """Diagnosis control #2b.

    An unconnecting batch (prev_hash mismatch) is also a reply. Pre-fix it
    did not touch ``_header_sync_time``, so the designated sync peer was
    dropped after 30s and download scoring rotated onto zombies.
    """
    tip_hash = b"\x33" * 32
    bs = _make_block_sync(tip_hash=tip_hash, tip_height=900_000)
    peer = _make_ready_peer("9.9.9.9", start_height=900_000)
    bs._header_sync_peer = peer
    bs._header_sync_time = time.time() - 25.0
    stale = bs._header_sync_time

    # Does not connect to our tip — unconnecting, not a PoW fail.
    orphan = _mine_easy(prev=b"\xab" * 32, tag=b"unconn")
    headers_msg = HeadersMessage(headers=[orphan])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)
    await bs.handle_headers(msg, peer)

    assert bs._header_sync_time > stale, (
        "unconnecting headers at tip must reset the stall-clock"
    )
    # Stall demotion is -2; unconnecting may score -20 only after 10 misses.
    for call in peer.adjust_score.call_args_list:
        assert call.args[0] != -2, (
            "unconnecting at tip must not be the header-sync stall demotion"
        )


# ---------------------------------------------------------------------------
# 4. Frontier in-flight timestamp is not reset every H1 re-issue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h1_reissue_does_not_reset_inflight_timestamp():
    """Diagnosis control #3.

    H1 re-issued the frontier every 5s AND wrote ``requested_blocks[hash]=now``,
    so the size-aware HEAD_TIMEOUT (~34s at 1.36 MB) never fired on the
    frontier. Keep the original in-flight timestamp so one getdata can
    actually finish (Core BLOCK_STALLING_TIMEOUT).
    """
    tip_hash = _h(0xCAFE)
    bs = _make_block_sync(tip_hash, 900_000)
    frontier = _h(0)
    bs._validated_headers = [(_h(i), MagicMock()) for i in range(0, 8)]
    bs._ibd_block_buffer = {}

    holder = _make_ready_peer("10.0.0.1", score=50, start_height=900_010)
    other = _make_ready_peer("10.0.0.2", score=40, start_height=900_010)
    bs.peer_manager.get_all_ready_peers.return_value = [holder, other]

    original = time.time() - (FRONTIER_REQUEST_INTERVAL + 1.0)
    bs.requested_blocks[frontier] = original
    bs._block_request_peer[frontier] = holder

    await bs._request_next_blocks()

    assert bs.requested_blocks[frontier] == original, (
        "H1 re-issue must not reset the in-flight timestamp "
        f"(was {original}, now {bs.requested_blocks[frontier]}); "
        "HEAD_TIMEOUT has to be able to fire on the frontier"
    )
