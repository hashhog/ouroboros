"""W88: headerssync.cpp PRESYNC/REDOWNLOAD pipeline audit — ouroboros Python layer.

Tests for bugs fixed by W88:

  Bug 6 — ``handle_headers`` ignored ``result.request_more`` from
           ``PyHeadersSyncState.process_headers``.  When PRESYNC transitions
           to REDOWNLOAD on a sub-2000-header batch the Rust state machine
           sets ``request_more=True``; the Python caller must propagate that
           and fire a GETHEADERS continuation.
           Core reference: ``headerssync.cpp:85-89`` —
               if (full_headers_message || m_download_state == State::REDOWNLOAD)
                   ret.request_more = true;

Tests for _get_presync_state height/bits forwarding (Bugs 1-5 are exercised
via the Rust unit-test suite; these Python tests verify the Python binding
plumbing correctly forwards chain_start_height and chain_start_bits to the
Rust constructor, and that ``handle_headers`` propagates ``request_more``).

Reference: Bitcoin Core ``src/headerssync.cpp``,
CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part2.md.
"""

from __future__ import annotations

from unittest.mock import MagicMock, AsyncMock, call

import pytest

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import BlockHeader, HeadersMessage


# ---------------------------------------------------------------------------
# Shared helpers (duplicated from test_handle_headers_pow for isolation)
# ---------------------------------------------------------------------------


class _StubBlk:
    """Minimal block-like parent record (bits / timestamp / prev_blockhash)."""

    def __init__(self, bits: int, timestamp: int):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = b"\x00" * 32


def _make_block_sync(
    tip_hash: bytes = b"\x00" * 32,
    tip_height: int = 0,
    tip_bits: int = 0,
) -> BlockSync:
    db = MagicMock()
    db.get_best_block.return_value = (tip_hash, tip_height)
    db.has_block_hash.return_value = False
    db.get_median_time_past.return_value = 1_700_000_000
    # Provide optional bits-retrieval so _get_presync_state can populate
    # chain_start_bits.
    db.get_block_bits = MagicMock(return_value=tip_bits)
    # Parent block for the header-time bad-diffbits gate (Core
    # validation.cpp:4088-4089).  A bare MagicMock would answer bits=1
    # (int(MagicMock()) == 1) for every height; these fixtures mine at
    # 0x1d00ffff on mainnet-shaped params at non-boundary heights, where the
    # rule is expected == prev.nBits.
    db.get_block_by_height.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)
    db.get_block.return_value = _StubBlk(0x1D00FFFF, 1_700_000_000)

    peer_manager = MagicMock()
    peer_manager.network = "mainnet"
    peer_manager.misbehaving = MagicMock()

    return BlockSync(db=db, validator=MagicMock(), peer_manager=peer_manager)


def _make_peer(host: str = "127.0.0.1", port: int = 8333):
    peer = MagicMock()
    peer.host = host
    peer.port = port
    peer.adjust_score = MagicMock()
    peer.is_connected = MagicMock(return_value=True)

    async def _send_message(*_args, **_kwargs):
        return None

    peer.send_message = MagicMock(side_effect=_send_message)
    return peer


# Bitcoin mainnet block #1 (genuinely valid PoW)
_GENESIS_BE = bytes.fromhex(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
_GENESIS_LE = _GENESIS_BE[::-1]
_BLOCK1_MERKLE_BE = bytes.fromhex(
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
)
_BLOCK1 = BlockHeader(
    version=1,
    prev_blockhash=_GENESIS_LE,
    merkle_root=_BLOCK1_MERKLE_BE[::-1],
    timestamp=1_231_469_665,
    bits=0x1D00FFFF,
    nonce=2_573_394_689,
)


# ---------------------------------------------------------------------------
# Bug 6: presync ``request_more`` must trigger GETHEADERS on sub-2000 batch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_headers_fires_getheaders_on_presync_request_more(monkeypatch):
    """When the Rust presync state machine sets request_more=True (e.g. on
    PRESYNC→REDOWNLOAD transition), the Python handle_headers must send a
    GETHEADERS continuation even if fewer than 2000 headers were in the batch.

    Pre-fix: continuation was gated on ``len(headers_msg.headers) >= 2000``
    only; a sub-2000 batch that transitioned PRESYNC→REDOWNLOAD would silently
    stall because no follow-up request was issued.

    Post-fix: ``_presync_request_more = result.request_more`` is OR-ed into
    the continuation condition.
    """
    bs = _make_block_sync(tip_hash=_GENESIS_LE, tip_height=0)

    # Inject a fake presync state that reports request_more=True but success.
    fake_presync = MagicMock()
    fake_result = MagicMock()
    fake_result.success = True
    fake_result.request_more = True  # <-- PRESYNC→REDOWNLOAD signal
    fake_presync.process_headers.return_value = fake_result
    # Patch _get_presync_state to return our fake.
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: fake_presync)

    headers_msg = HeadersMessage(headers=[_BLOCK1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    getheaders_sent = {"count": 0}

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # A sub-2000-header batch arrived.  The presync result has request_more=True.
    # The peer.send_message must have been called (GETHEADERS continuation).
    peer.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_handle_headers_no_spurious_getheaders_when_presync_request_more_false(
    monkeypatch,
):
    """When the presync state machine sets request_more=False and the batch
    is sub-2000 headers, no GETHEADERS continuation should be sent.
    """
    bs = _make_block_sync(tip_hash=_GENESIS_LE, tip_height=0)

    fake_presync = MagicMock()
    fake_result = MagicMock()
    fake_result.success = True
    fake_result.request_more = False  # presync says: do NOT request more
    fake_presync.process_headers.return_value = fake_result
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: fake_presync)

    headers_msg = HeadersMessage(headers=[_BLOCK1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # Sub-2000 batch + presync says no more → no GETHEADERS.
    peer.send_message.assert_not_called()


# ---------------------------------------------------------------------------
# _get_presync_state: height + bits forwarding to PyHeadersSyncState
# ---------------------------------------------------------------------------


def test_get_presync_state_passes_height_and_bits_to_constructor(monkeypatch):
    """_get_presync_state must forward chain_start_height and chain_start_bits
    to PyHeadersSyncState so the Rust constructor initialises commitment slots
    and difficulty checks correctly (Bugs 1–5 fix plumbing check).

    We mock ``PyHeadersSyncState`` so we can inspect the constructor call.
    """
    TIP_HASH = b"\xab" * 32
    TIP_HEIGHT = 850_000
    TIP_BITS = 0x1702B7B4

    bs = _make_block_sync(
        tip_hash=TIP_HASH,
        tip_height=TIP_HEIGHT,
        tip_bits=TIP_BITS,
    )

    captured: dict = {}

    class FakePresyncState:
        def __init__(self, network, chain_hash, mtp, chain_start_height=0, chain_start_bits=0):
            captured["network"] = network
            captured["chain_hash"] = chain_hash
            captured["chain_start_height"] = chain_start_height
            captured["chain_start_bits"] = chain_start_bits

    # Patch the sync module reference so _get_presync_state finds our fake.
    import ouroboros.block_sync as bs_module

    real_has_sync = bs_module._has_sync_module
    real_sync = bs_module._sync_module

    fake_sync = MagicMock()
    fake_sync.PyHeadersSyncState = FakePresyncState
    monkeypatch.setattr(bs_module, "_has_sync_module", True)
    monkeypatch.setattr(bs_module, "_sync_module", fake_sync)

    peer = _make_peer()
    bs._get_presync_state(peer)

    assert captured.get("chain_start_height") == TIP_HEIGHT, (
        f"chain_start_height not forwarded: got {captured.get('chain_start_height')}"
    )
    assert captured.get("chain_start_bits") == TIP_BITS, (
        f"chain_start_bits not forwarded: got {captured.get('chain_start_bits')}"
    )

    monkeypatch.setattr(bs_module, "_has_sync_module", real_has_sync)
    monkeypatch.setattr(bs_module, "_sync_module", real_sync)


@pytest.mark.parametrize("tip_block_present", [True, False])
def test_get_presync_state_falls_back_zero_bits_when_db_bits_returns_none(
    monkeypatch, tip_block_present
):
    """When the DB's get_block_bits returns None, _get_presync_state seeds
    chain_start_bits from the tip block header (get_block_bytes / tip
    Block.bits, then the assumeUTXO base header) and only falls back to 0
    when none of those sources has the block either.
    """
    TIP_HASH = b"\xcd" * 32
    TIP_HEIGHT = 0

    bs = _make_block_sync(tip_hash=TIP_HASH, tip_height=TIP_HEIGHT, tip_bits=0)
    # Return None from get_block_bits to exercise the recovery chain.
    bs.db.get_block_bits = MagicMock(return_value=None)
    bs.db.get_block_bytes = MagicMock(return_value=None)
    if not tip_block_present:
        bs.db.get_block = MagicMock(return_value=None)
    expected_bits = 0x1D00FFFF if tip_block_present else 0

    captured: dict = {}

    class FakePresyncState:
        def __init__(self, network, chain_hash, mtp, chain_start_height=0, chain_start_bits=0):
            captured["chain_start_bits"] = chain_start_bits

    import ouroboros.block_sync as bs_module

    fake_sync = MagicMock()
    fake_sync.PyHeadersSyncState = FakePresyncState
    monkeypatch.setattr(bs_module, "_has_sync_module", True)
    monkeypatch.setattr(bs_module, "_sync_module", fake_sync)

    peer = _make_peer()
    bs._get_presync_state(peer)

    assert captured.get("chain_start_bits") == expected_bits, (
        f"Expected {expected_bits:#x} (tip Block.bits recovery, else 0) when "
        f"get_block_bits returns None, got {captured.get('chain_start_bits')}"
    )


# ---------------------------------------------------------------------------
# Interaction: presync failure still allows block sync to continue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_presync_failure_does_not_break_header_acceptance(monkeypatch):
    """A presync state machine rejection must NOT roll back headers that
    already passed the per-header PoW gate + continuity check.

    The presync is defense-in-depth; the consensus-relevant gate is the
    per-header PoW check.  A presync failure only drops the presync state.
    """
    bs = _make_block_sync(tip_hash=_GENESIS_LE, tip_height=0)

    fake_presync = MagicMock()
    fake_result = MagicMock()
    fake_result.success = False
    fake_result.request_more = False
    fake_result.error = "simulated presync mismatch"
    fake_presync.process_headers.return_value = fake_result
    monkeypatch.setattr(bs, "_get_presync_state", lambda _peer: fake_presync)

    headers_msg = HeadersMessage(headers=[_BLOCK1])
    msg = MagicMock()
    msg.payload = headers_msg.serialize_payload()

    peer = _make_peer()
    bs._header_sync_peer = peer

    async def _noop():
        return None

    monkeypatch.setattr(bs, "_request_next_blocks", _noop)

    await bs.handle_headers(msg, peer)

    # The valid block-1 header must still have been appended despite the
    # presync failure.
    assert len(bs._validated_headers) == 1, (
        "Valid header must be accepted even if presync rejects the batch"
    )
    # Presync failure counter incremented.
    assert bs._headers_presync_failures == 1
