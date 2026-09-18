"""Failing control: cannot resume after a long offline period.

QUEUES.md ouroboros item 0 (observed 2026-09-18T01:30-01:55Z): after 8 days
paused the node connected peers, received the whole header gap (1171 ==
Core tip − stored tip), and then looped

    Requested headers from <peer> (locator: 30 hashes)
    Received 1171 headers from <peer>

~1/second for 20+ minutes. Tip did not move. A restart cleared it.

The locator is rebuilt every sync_loop tick from the *block* tip
(``get_best_block``), so a complete (non-full, <2000) header batch is
re-requested forever instead of transitioning to block download.  W75
does not recover: it requires a non-empty IBD buffer, and no bodies were
ever requested.

This file is the in-repo control.  It must go red on current master and
green after the fix.  The operator-visible case is a gap of >1000 blocks
(8 days ≈ 1150); we use 1001.

Ref: Bitcoin Core ``LocatorEntries`` from ``pindexBestHeader`` (chain.cpp),
``ProcessHeadersMessage`` / ``FindNextBlocksToDownload`` (net_processing.cpp).
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import (
    HEADER_STALL_BATCHES,
    NODE_NETWORK_LIMITED_MIN_BLOCKS,
    BlockSync,
)
from ouroboros.p2p_messages import (
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_WITNESS,
    BlockHeader,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
)
from ouroboros.peer import Peer, PeerState

REGTEST_BITS = 0x207FFFFF
LONG_GAP = 1001  # >1000; the operator-visible 8-day resume was 1171


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _mine(prev: bytes, tag: int, bits: int = REGTEST_BITS) -> BlockHeader:
    target = BlockSync._bits_to_target(bits)
    for bump in range(1 << 20):
        h = BlockHeader(
            version=1,
            prev_blockhash=prev,
            merkle_root=_dsha(b"gap" + tag.to_bytes(8, "little") + bump.to_bytes(8, "little")),
            timestamp=1_700_000_000 + tag,
            bits=bits,
            nonce=bump & 0xFFFFFFFF,
        )
        if int.from_bytes(_dsha(h.serialize()), "little") <= target:
            return h
    raise AssertionError("could not mine a passing header")


def _chain(prev: bytes, n: int) -> list[BlockHeader]:
    out = []
    for i in range(n):
        h = _mine(prev, i)
        out.append(h)
        prev = _dsha(h.serialize())
    return out


class _Blk:
    def __init__(self, bits=REGTEST_BITS, timestamp=1_700_000_000, prev=b"\x00" * 32):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = prev


class _StubDB:
    def __init__(self, tip_hash: bytes, tip_height: int):
        self._tip = (tip_hash, tip_height)
        self.hash_by_height = {tip_height: tip_hash, 0: b"\x00" * 32}
        self.by_height = {tip_height: _Blk()}
        self.blocks = {tip_hash: _Blk()}

    def get_best_block(self):
        return self._tip

    def get_block_hash_by_height(self, height):
        return self.hash_by_height.get(height)

    def get_block_by_height(self, height):
        return self.by_height.get(height)

    def get_block(self, h):
        return self.blocks.get(h)

    def has_block_hash(self, h):
        return h in self.blocks or h == self._tip[0]

    def get_chainwork_by_height(self, height):
        return 1 << 80

    def get_median_time_past(self, height=None):
        return 1_700_000_000

    def find_height_of_hash(self, h):
        if h == self._tip[0]:
            return self._tip[1]
        return None


class _StubPM:
    network = "regtest"

    def __init__(self, peers):
        self._peers = list(peers)
        self.misbehaving_calls = []

    def get_all_ready_peers(self):
        return list(self._peers)

    def misbehaving(self, addr, score, reason):
        self.misbehaving_calls.append((addr, score, reason))
        return False


def _peer(
    host: str = "10.0.0.7",
    services: int = NODE_NETWORK | NODE_WITNESS,
    start_height: int = 0,
) -> Peer:
    p = Peer(host, 18444, network="regtest")
    p.state = PeerState.READY
    p.services = services
    p.start_height = start_height
    p.best_known_height = start_height
    p.score = 100
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)

    p.send_message = _send
    p.adjust_score = lambda d: None
    return p


def _fresh(
    *,
    tip_height: int = 10_000,
    gap: int = LONG_GAP,
    services: int = NODE_NETWORK | NODE_WITNESS,
):
    tip = _dsha(b"stored-tip" + tip_height.to_bytes(8, "little"))
    db = _StubDB(tip, tip_height)
    peer = _peer(start_height=tip_height + gap, services=services)
    pm = _StubPM([peer])
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    bs._header_sync_peer = peer
    return bs, db, peer, tip, tip_height


def _commands(peer) -> list[str]:
    return [getattr(m, "command", None) for m in peer.sent]


def _getdata_hashes(peer) -> list[bytes]:
    out = []
    for m in peer.sent:
        if getattr(m, "command", None) != "getdata":
            continue
        gd = GetDataMessage.from_payload(m.payload)
        out.extend(h for _t, h in gd.inventory)
    return out


def _getheaders_count(peer) -> int:
    return sum(1 for c in _commands(peer) if c == "getheaders")


def _locator_heads(peer) -> list[bytes]:
    heads = []
    for m in peer.sent:
        if getattr(m, "command", None) != "getheaders":
            continue
        gh = GetHeadersMessage.from_payload(m.payload)
        if gh.locator_hashes:
            heads.append(gh.locator_hashes[0])
    return heads


async def _feed(bs, peer, headers, network: str = "regtest"):
    msg = HeadersMessage(list(headers)).to_network_message(network)
    await bs.handle_headers(msg, peer, min_pow_checked=True)


# ---------------------------------------------------------------------------
# 1. Locator must start at the HEADER tip once a gap is queued
# ---------------------------------------------------------------------------


def test_locator_starts_at_queued_header_tip_not_block_tip():
    """Core LocatorEntries walks pindexBestHeader, not the block tip.

    After a long gap the block tip is 1000+ headers behind.  A locator
    whose first hash is the stored block tip makes the peer re-send the
    same gap forever — the live 1171-header loop.
    """
    bs, db, peer, tip, tip_height = _fresh()
    queued_tip = _dsha(b"header-tip")
    hdr = MagicMock()
    hdr.prev_blockhash = tip
    bs._validated_headers = [(queued_tip, hdr)]

    locator = bs._build_locator(tip_height)
    assert locator, "locator must not be empty"
    assert locator[0] == queued_tip, (
        f"locator[0] must be the queued header tip, not the block tip "
        f"(got {locator[0][:8].hex()} vs block tip {tip[:8].hex()})"
    )


# ---------------------------------------------------------------------------
# 2. _catch_up must not re-request headers we already have
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_catch_up_does_not_rerequest_once_header_gap_is_queued():
    """After the complete gap is in ``_validated_headers``, another
    sync_loop tick must NOT send getheaders for the same locator.

    Pre-fix ``_catch_up`` fires every 1 s IBD tick from the block tip,
    which is the ~1/second log loop.
    """
    bs, db, peer, tip, tip_height = _fresh()
    # Simulate "we already received the whole 1001-header gap".
    queued = []
    prev = tip
    for i in range(LONG_GAP):
        h = _dsha(b"q" + i.to_bytes(4, "little"))
        hdr = MagicMock()
        hdr.prev_blockhash = prev
        queued.append((h, hdr))
        prev = h
    bs._validated_headers = queued
    peer.best_known_height = tip_height + LONG_GAP
    peer.start_height = tip_height + LONG_GAP
    peer.sent.clear()

    await bs._catch_up(peer, tip_height)

    assert _getheaders_count(peer) == 0, (
        f"_catch_up re-requested headers after the {LONG_GAP}-header gap "
        f"was already queued ({_getheaders_count(peer)} getheaders) — "
        f"this is the live resume loop"
    )


# ---------------------------------------------------------------------------
# 3. Limited (pruned) peer 1000+ behind: still request bodies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_limited_peer_outside_288_window_still_gets_getdata():
    """After 8 days a NODE_NETWORK_LIMITED peer can serve the headers
    (it has them) but ``_can_serve_block_at`` refuses bodies 1000+ back.
    The transition to getdata must still fire — otherwise we loop
    headers forever on the only peers we have.

    BIP-159 window is 288; LONG_GAP (1001) is well outside it.
    """
    assert LONG_GAP >= (NODE_NETWORK_LIMITED_MIN_BLOCKS - 2)

    bs, db, peer, tip, tip_height = _fresh(
        services=NODE_NETWORK_LIMITED | NODE_WITNESS,
    )
    headers = _chain(tip, 8)
    frontier = _dsha(headers[0].serialize())

    await _feed(bs, peer, headers)

    assert len(bs._validated_headers) >= 1, (
        f"connecting headers must be queued, got {len(bs._validated_headers)}"
    )
    assert frontier in _getdata_hashes(peer), (
        "tip+1 getdata must fire even when the only peer is NODE_NETWORK_LIMITED "
        f"and {LONG_GAP} blocks behind (BIP-159 window "
        f"{NODE_NETWORK_LIMITED_MIN_BLOCKS}). sent={_commands(peer)}"
    )


# ---------------------------------------------------------------------------
# 4. Stall guard: duplicate batches + zero getdata → force transition
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stall_guard_forces_getdata_after_duplicate_header_batches(
    monkeypatch,
):
    """ASK (2): N consecutive header batches with zero new headers accepted
    AND zero blocks requested must log and force the header→block
    transition rather than looping forever.

    ``_request_next_blocks`` is stubbed to no-op so the only way getdata
    fires is the stall guard's last-resort send.
    """
    bs, db, peer, tip, tip_height = _fresh()
    headers = _chain(tip, 4)
    frontier = _dsha(headers[0].serialize())

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    # First batch is accepted into the queue; no getdata (stubbed).
    await _feed(bs, peer, headers)
    assert len(bs._validated_headers) == 4
    assert _getdata_hashes(peer) == []
    peer.sent.clear()

    # Re-send the same batch HEADER_STALL_BATCHES times (the live loop).
    for _ in range(HEADER_STALL_BATCHES):
        await _feed(bs, peer, headers)

    assert frontier in _getdata_hashes(peer), (
        "stall guard must force a tip+1 getdata after consecutive duplicate "
        f"header batches with an empty request map. sent={_commands(peer)}"
    )


# ---------------------------------------------------------------------------
# 5. The 1001-block resume itself: headers → getdata, no re-request loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_after_1001_block_gap_requests_bodies_not_headers():
    """The operator-visible control: stored tip, peer 1001 ahead, one
    complete (non-full) header batch covering the whole gap.

    After that batch:
      * tip+1 must be in a getdata (transition to bodies fired)
      * a subsequent ``_catch_up`` must not send another getheaders
    """
    bs, db, peer, tip, tip_height = _fresh()
    headers = _chain(tip, LONG_GAP)
    assert len(headers) == LONG_GAP
    assert len(headers) < 2000, "must be a complete (non-full) batch"
    frontier = _dsha(headers[0].serialize())
    header_tip = _dsha(headers[-1].serialize())

    await _feed(bs, peer, headers)

    assert len(bs._validated_headers) == LONG_GAP, (
        f"expected the whole {LONG_GAP}-header gap queued, got {len(bs._validated_headers)}"
    )
    assert frontier in _getdata_hashes(peer), (
        f"tip+1 was never requested after the {LONG_GAP}-header batch "
        f"(commands={_commands(peer)}) — the header→body transition never fired"
    )

    peer.sent.clear()
    await bs._catch_up(peer, tip_height)
    assert _getheaders_count(peer) == 0, (
        f"_catch_up sent {_getheaders_count(peer)} getheaders after the "
        f"complete gap was queued; locator heads="
        f"{[h[:8].hex() for h in _locator_heads(peer)]}"
    )
    # And if it *did* send (pre-fix), the first locator hash would be the
    # block tip, not the header tip — pin that too so a partial fix fails.
    if _locator_heads(peer):
        assert _locator_heads(peer)[0] != tip
        assert _locator_heads(peer)[0] == header_tip
