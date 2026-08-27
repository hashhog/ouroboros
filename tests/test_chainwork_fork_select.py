"""
Regression tests: fork/reorg selection must use cumulative 256-bit chainwork,
not block height.

Bitcoin Core's CBlockIndexWorkComparator (node/blockstorage.cpp:174) ranks
candidates by nChainWork (arith_uint256) descending, with first-seen as the
tie-break.  Before this fix, ouroboros used HEIGHT as a proxy for chainwork
in two places:

  A. SyncManager._maybe_trigger_fork_download (block_sync.py)
  B. RPCServer._attach_side_branch_block (rpc.py)

Both gated the reorg on ``fork_height > active_height``.  On a
difficulty-adjustment boundary a shorter but harder fork has MORE cumulative
chainwork and must win; using height would keep the lighter (but taller) tip.
Equal-work forks must NOT trigger a reorg (first-seen tie-break).

These tests exercise:
  1. _fork_tip_chainwork — the new helper that sums work from fork headers
     above the common ancestor.
  2. _maybe_trigger_fork_download decision:
     a. fork MORE work than active → reorg triggered (True)
     b. fork EQUAL work → no reorg (False, first-seen wins)
     c. fork LESS work → no reorg (False)
     d. chainwork unavailable → falls back to height comparison
  3. _side_branch_chainwork (already existed) feeds the rpc path:
     a. side-branch MORE work → reorg driven
     b. side-branch EQUAL work → no reorg
"""

from __future__ import annotations

import asyncio
import struct
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

# Mock sync FFI before any ouroboros import
if "sync" not in sys.modules:
    _sync = types.ModuleType("sync")
    _sync.PyUTXO = type("PyUTXO", (), {})
    _sync.SyncEngine = type("SyncEngine", (), {})
    _sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    _sync.__file__ = "<test-mock>"
    sys.modules["sync"] = _sync

import pytest

from ouroboros.block_sync import BlockSync as SyncManager
from ouroboros.p2p_messages import BlockHeader


# ---------------------------------------------------------------------------
# Minimal _bits_to_work reference (same formula as SyncManager._bits_to_work)
# ---------------------------------------------------------------------------

def _bits_to_work(bits: int) -> int:
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF
    if mantissa == 0:
        return 0
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target <= 0:
        return 0
    return (2 ** 256) // (target + 1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regtest difficulty bits (min-difficulty block: all ones)
_BITS_MIN = 0x207fffff  # regtest minimum difficulty
_WORK_MIN = _bits_to_work(_BITS_MIN)

# Harder bits (simulated difficulty-adjustment block)
_BITS_HARD = 0x1d00ffff  # ~mainnet genesis difficulty (~4× harder than regtest)
_WORK_HARD = _bits_to_work(_BITS_HARD)


def _make_header(bits: int, prev: bytes = b"\x00" * 32) -> BlockHeader:
    return BlockHeader(
        version=2,
        prev_blockhash=prev,
        merkle_root=b"\x00" * 32,
        timestamp=0,
        bits=bits,
        nonce=0,
    )


def _hash(n: int) -> bytes:
    return n.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# StubDB for block_sync tests
# ---------------------------------------------------------------------------

class _StubDB:
    """Minimal DB stub for SyncManager."""

    def __init__(self, tip_hash: bytes, tip_height: int, chainwork_by_height: dict | None = None):
        self._tip = (tip_hash, tip_height)
        self._cw: dict[int, int] = chainwork_by_height or {}
        # Support get_block_hash_by_height for _resolve_active_height
        self._hash_by_height: dict[int, bytes] = {}

    def get_best_block(self):
        return self._tip

    def get_chainwork_by_height(self, height: int) -> int:
        return self._cw.get(height, 0)

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        return self._hash_by_height.get(height)


# ---------------------------------------------------------------------------
# Build a minimal SyncManager with a loaded fork store
# ---------------------------------------------------------------------------

def _make_sync_manager(
    active_tip_hash: bytes,
    active_tip_height: int,
    chainwork_by_height: dict | None = None,
) -> SyncManager:
    db = _StubDB(active_tip_hash, active_tip_height, chainwork_by_height)
    # Also expose the active tip in hash-by-height so _resolve_active_height works
    db._hash_by_height[active_tip_height] = active_tip_hash

    validator = MagicMock()
    peer_manager = MagicMock()

    sm = SyncManager(db=db, validator=validator, peer_manager=peer_manager)
    return sm


# ---------------------------------------------------------------------------
# Tests for _fork_tip_chainwork
# ---------------------------------------------------------------------------

class TestForkTipChainwork:
    """Unit tests for the new _fork_tip_chainwork helper."""

    def test_single_fork_block_above_active_ancestor(self):
        """One fork block above the active tip: chainwork = ancestor_cw + block_work."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)

        ancestor_cw = 1_000_000
        sm = _make_sync_manager(ancestor_hash, 10, {10: ancestor_cw})

        # Add the fork header to the fork store
        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        cw = sm._fork_tip_chainwork(fork_tip_hash)
        expected = ancestor_cw + _WORK_MIN
        assert cw == expected

    def test_two_fork_blocks_above_ancestor(self):
        """Two fork blocks: chainwork = ancestor_cw + work(block1) + work(block2)."""
        ancestor_hash = _hash(1)
        fork_h1_hash = _hash(2)
        fork_h2_hash = _hash(3)

        ancestor_cw = 500
        sm = _make_sync_manager(ancestor_hash, 5, {5: ancestor_cw})

        sm._fork_headers[fork_h1_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_h1_hash] = ancestor_hash
        sm._fork_headers[fork_h2_hash] = _make_header(_BITS_HARD, prev=fork_h1_hash)
        sm._fork_header_prev[fork_h2_hash] = fork_h1_hash

        cw = sm._fork_tip_chainwork(fork_h2_hash)
        expected = ancestor_cw + _WORK_MIN + _WORK_HARD
        assert cw == expected

    def test_returns_none_when_anchor_not_found(self):
        """Returns None when the fork doesn't anchor to any active-chain block."""
        orphan_hash = _hash(99)
        sm = _make_sync_manager(_hash(1), 5, {})

        # Put in fork store but don't anchor to active chain
        unknown_prev = _hash(50)
        sm._fork_headers[orphan_hash] = _make_header(_BITS_MIN, prev=unknown_prev)
        sm._fork_header_prev[orphan_hash] = unknown_prev

        assert sm._fork_tip_chainwork(orphan_hash) is None

    def test_unknown_fork_hash(self):
        """Returns None when the hash isn't in the fork store or active chain."""
        sm = _make_sync_manager(_hash(1), 5, {})
        assert sm._fork_tip_chainwork(_hash(42)) is None

    def test_zero_ancestor_chainwork_still_works(self):
        """When DB has no stored chainwork (returns 0), accumulated work is returned."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)

        # DB has no chainwork persisted
        sm = _make_sync_manager(ancestor_hash, 10, {})

        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        cw = sm._fork_tip_chainwork(fork_tip_hash)
        # ancestor_cw = 0, so we get just the one block's work
        assert cw == _WORK_MIN


# ---------------------------------------------------------------------------
# Tests for _maybe_trigger_fork_download chainwork gate
# ---------------------------------------------------------------------------

class TestMaybeTriggerForkDownload:
    """_maybe_trigger_fork_download uses chainwork, not height."""

    def _make_peer(self) -> MagicMock:
        peer = MagicMock()
        peer.host = "127.0.0.1"
        peer.port = 8333
        return peer

    def test_fork_with_more_work_triggers_download(self):
        """Fork with strictly greater chainwork → reorg triggered (True)."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)
        active_tip_hash = _hash(3)

        # Active tip at height 10, fork at height 10 (same height) but more work
        active_cw = 1000
        # Fork: one block above ancestor (h=9) with VERY hard bits
        ancestor_cw = 500
        sm = _make_sync_manager(active_tip_hash, 10, {
            9: ancestor_cw,   # ancestor at height 9
            10: active_cw,    # active tip at height 10
        })
        # Register ancestor as known active-chain block
        sm.db._hash_by_height[9] = ancestor_hash

        # Fork header above the ancestor
        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_HARD, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        fork_cw = ancestor_cw + _WORK_HARD
        assert fork_cw > active_cw, "test precondition: fork must have more work"

        # _request_fork_blocks is async — stub it
        async def _noop_request(*a, **kw):
            pass

        sm._request_fork_blocks = _noop_request

        peer = self._make_peer()
        result = asyncio.run(sm._maybe_trigger_fork_download(fork_tip_hash, peer))
        assert result is True

    def test_fork_with_equal_work_keeps_current_tip(self):
        """Fork with equal chainwork → no reorg (first-seen tie-break)."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)
        active_tip_hash = _hash(3)

        # Both ancestor_cw + WORK_MIN == active_cw → exactly equal
        ancestor_cw = 1000
        active_cw = ancestor_cw + _WORK_MIN

        sm = _make_sync_manager(active_tip_hash, 10, {
            9: ancestor_cw,
            10: active_cw,
        })
        sm.db._hash_by_height[9] = ancestor_hash

        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        peer = self._make_peer()
        result = asyncio.run(sm._maybe_trigger_fork_download(fork_tip_hash, peer))
        assert result is False, "equal-work fork must NOT trigger reorg"

    def test_fork_with_less_work_keeps_current_tip(self):
        """Fork with less chainwork → no reorg."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)
        active_tip_hash = _hash(3)

        # Active has more work than fork will add
        ancestor_cw = 1000
        active_cw = ancestor_cw + _WORK_HARD + _WORK_MIN  # two blocks' worth

        sm = _make_sync_manager(active_tip_hash, 10, {
            9: ancestor_cw,
            10: active_cw,
        })
        sm.db._hash_by_height[9] = ancestor_hash

        # Fork: only one min-work block above ancestor — less than active tip
        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        peer = self._make_peer()
        result = asyncio.run(sm._maybe_trigger_fork_download(fork_tip_hash, peer))
        assert result is False, "lighter fork must NOT trigger reorg"

    def test_chainwork_unavailable_refuses_reorg_equal_height(self):
        """No chainwork basis -> refuse reorg regardless of heights (#49)."""
        ancestor_hash = _hash(1)
        fork_tip_hash = _hash(2)
        active_tip_hash = _hash(3)

        # No chainwork in DB (all return 0)
        sm = _make_sync_manager(active_tip_hash, 10, {})
        sm.db._hash_by_height[9] = ancestor_hash

        # Fork one block above ancestor (h=9) → fork height = 10 = active → no reorg
        sm._fork_headers[fork_tip_hash] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash] = ancestor_hash

        peer = self._make_peer()
        result = asyncio.run(sm._maybe_trigger_fork_download(fork_tip_hash, peer))
        # No work basis: refusal is unconditional (heights irrelevant).
        assert result is False

    def test_taller_fork_no_chainwork_refuses_reorg(self):
        """FLIPPED (#49, 2026-08-27): this test used to ASSERT the defect —
        that a TALLER fork with no chainwork basis triggers a reorg by
        HEIGHT (the #45 length-beats-work class; Core selects on work
        alone, validation.cpp:3114). A taller min-difficulty fork carrying
        LESS work would have evicted the heavier active chain. The fix
        refuses to reorganise without a comparable work basis; this test
        now pins the refusal and FAILS at the parent commit (which
        returned True here)."""
        ancestor_hash = _hash(1)
        fork_tip_hash_1 = _hash(2)
        fork_tip_hash_2 = _hash(3)
        active_tip_hash = _hash(4)

        # No chainwork in DB
        sm = _make_sync_manager(active_tip_hash, 10, {})
        sm.db._hash_by_height[9] = ancestor_hash

        # Two fork blocks above ancestor → fork height = 11 > active 10
        sm._fork_headers[fork_tip_hash_1] = _make_header(_BITS_MIN, prev=ancestor_hash)
        sm._fork_header_prev[fork_tip_hash_1] = ancestor_hash
        sm._fork_headers[fork_tip_hash_2] = _make_header(_BITS_MIN, prev=fork_tip_hash_1)
        sm._fork_header_prev[fork_tip_hash_2] = fork_tip_hash_1

        async def _noop_request(*a, **kw):
            pass

        sm._request_fork_blocks = _noop_request

        peer = self._make_peer()
        result = asyncio.run(sm._maybe_trigger_fork_download(fork_tip_hash_2, peer))
        # fork h=11 > active h=10 but NO WORK BASIS: the refusal must hold —
        # height never drives a disconnect (pre-fix this asserted True).
        assert result is False, (
            "taller fork with no chainwork basis must NOT trigger a reorg "
            "(height-based selection is the #45 length-beats-work defect)"
        )
