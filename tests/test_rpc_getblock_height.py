"""Tests for ``getblock`` / ``getblockheader`` height resolution.

Pattern D regression (post-reorg-consistency corpus entry, 2026-05-05).

Ouroboros previously read the response ``height`` field via
``getattr(block, 'height', None)`` then falsy-coerced ``None`` to ``0``.
The deserialised Rust ``PyBlock`` has no ``height`` field — height is a
chainstate-level concept, not a serialised-block field — so every
``getblock`` / ``getblockheader`` response carried ``height: 0``.

That tripped two corpus invariants:

  D1 (stale-rpc)    — ``getbestblockhash → getblock(hash, 1).height``
                      disagrees with ``getblockcount``.
  D3 (roundtrip)    — ``getblockheader(getblockhash(50)).height`` was
                      ``0`` instead of ``50``.

Fix: resolve height from the chainstate index by hash, mirroring
Bitcoin Core ``rpc/blockchain.cpp``'s ``blockToJSON`` /
``getblockheader`` which read ``pblockindex->nHeight`` off the block
index, never off the deserialised block body.

These tests exercise both an active-chain block and a disconnected
(side-branch buffer) block so the second-tier resolution path is also
covered.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from ouroboros.rpc import RPCServer


# ---------------------------------------------------------------------------
# Minimal block / db stubs.  Mirrors the surface getblock / getblockheader
# reach for: ``get_block``, ``get_best_block``, ``get_block_hash_by_height``.
# ---------------------------------------------------------------------------


@dataclass
class _StubBlock:
    """Mimics ``ouroboros.database.Block`` minus methods getblock doesn't
    use here (serialize, transactions for verbosity >= 1 are kept simple).
    """

    version: int = 1
    prev_blockhash: bytes = b"\x00" * 32
    merkle_root: bytes = b"\x11" * 32
    timestamp: int = 1_700_000_000
    bits: int = 0x1D00FFFF
    nonce: int = 0
    transactions: list = field(default_factory=list)
    # CRITICAL: no ``height`` attribute.  This mirrors Rust PyBlock which
    # never carries one — the bug being fixed is that the RPC layer used
    # to *read* this missing attribute and falsy-coerce to 0.

    def serialize(self) -> bytes:
        # 80-byte header + varint(0) for tx count, good enough for size
        # / strippedsize math in rpc_getblock.
        return b"\x00" * 80 + b"\x00"


class _StubDB:
    """In-memory chainstate index stub.  Built around a height-keyed dict
    with explicit hash→height resolution via ``get_block_hash_by_height``
    walks (mirroring the production Rust BlockchainDB API)."""

    def __init__(self) -> None:
        # height -> (hash, block)
        self._chain: dict[int, tuple[bytes, _StubBlock]] = {}
        # hash -> block (covers active-chain + side-branch lookups)
        self._by_hash: dict[bytes, _StubBlock] = {}
        self._tip_hash: bytes = b"\x00" * 32
        self._tip_height: int = 0

    # -- chain construction helpers (test-only) ----------------------

    def add_active_block(self, height: int, block: _StubBlock) -> bytes:
        # Synthesize a deterministic 32-byte hash so equality checks work.
        h = (b"A" + height.to_bytes(4, "big")).ljust(32, b"\x00")
        self._chain[height] = (h, block)
        self._by_hash[h] = block
        if height > self._tip_height:
            self._tip_hash = h
            self._tip_height = height
        return h

    def add_side_branch_block(self, block: _StubBlock) -> bytes:
        # Side-branch blocks live in BLOCKS_CF (by hash) but NOT in the
        # height-keyed BLOCK_INDEX_CF — i.e. ``get_block_hash_by_height``
        # never returns this hash.
        h = (b"S" + len(self._by_hash).to_bytes(4, "big")).ljust(32, b"\x00")
        self._by_hash[h] = block
        return h

    # -- production surface ------------------------------------------

    def get_block(self, block_hash: bytes):
        return self._by_hash.get(bytes(block_hash))

    def get_best_block(self) -> tuple[bytes, int]:
        return (self._tip_hash, self._tip_height)

    def get_block_hash_by_height(self, height: int):
        entry = self._chain.get(int(height))
        return entry[0] if entry else None


# ---------------------------------------------------------------------------
# Test fixture
# ---------------------------------------------------------------------------


def _make_rpc(db: _StubDB) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    # Median-time / chainwork / difficulty helpers used by getblock /
    # getblockheader — return cheap deterministic stand-ins.
    node.get_median_time = lambda h: 1_700_000_000
    node.get_chainwork_at_height = lambda h: "0" * 64
    node.get_difficulty = lambda bits: 1.0
    rpc.node = node
    rpc._current_wallet_name = None
    rpc._side_branch_blocks = {}
    rpc._side_branch_max_entries = 1024
    return rpc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_getblock_height_for_active_chain_block_below_tip() -> None:
    """Pattern D D3-roundtrip: ``getblockhash(50) → getblock(hash, 1).height``
    must round-trip to ``50``.  Previously returned ``height: 0`` because
    the falsy-coerced ``getattr(block, 'height', None)`` always evaluated
    to ``None``.
    """
    db = _StubDB()
    # Build a 113-block active chain (matches the post-reorg-consistency
    # corpus expected_height after B3 reorg).
    last_hash = b""
    for h in range(113 + 1):
        last_hash = db.add_active_block(h, _StubBlock(timestamp=1_700_000_000 + h))

    rpc = _make_rpc(db)

    probe_height = 50
    probe_hash = db.get_block_hash_by_height(probe_height)
    assert probe_hash is not None

    # display-order hex (big-endian) — getblock reverses internally.
    display_hash = probe_hash[::-1].hex()
    result = asyncio.run(rpc.rpc_getblock(display_hash, verbosity=1))

    assert isinstance(result, dict)
    assert result["height"] == probe_height, (
        f"Pattern D D3-roundtrip regression: "
        f"getblock({display_hash[:16]}…).height = {result['height']}, "
        f"expected {probe_height}"
    )
    # gbbh_h sanity: the hash this round-trips to must match.
    assert result["hash"] == display_hash


def test_getblockheader_height_for_active_chain_block_below_tip() -> None:
    """Same Pattern D D3-roundtrip invariant for ``getblockheader``.
    The corpus consistency probe is ``getblockhash(50)`` →
    ``getblockheader(hash).height`` and asserts ``== 50``.
    """
    db = _StubDB()
    last_hash = b""
    for h in range(113 + 1):
        last_hash = db.add_active_block(h, _StubBlock(timestamp=1_700_000_000 + h))

    rpc = _make_rpc(db)

    probe_height = 50
    probe_hash = db.get_block_hash_by_height(probe_height)
    assert probe_hash is not None

    display_hash = probe_hash[::-1].hex()
    result = asyncio.run(rpc.rpc_getblockheader(display_hash, verbose=True))

    assert isinstance(result, dict)
    assert result["height"] == probe_height, (
        f"Pattern D D3-roundtrip regression in getblockheader: "
        f"got height={result['height']}, expected {probe_height}"
    )


def test_getblock_height_at_tip_uses_fast_path() -> None:
    """Tip-equality fast path: getblock on the current best block must
    report the tip height (gbbh_h == gbc invariant for D1)."""
    db = _StubDB()
    for h in range(113 + 1):
        db.add_active_block(h, _StubBlock(timestamp=1_700_000_000 + h))

    rpc = _make_rpc(db)
    tip_hash, tip_height = db.get_best_block()
    display_hash = tip_hash[::-1].hex()

    result = asyncio.run(rpc.rpc_getblock(display_hash, verbosity=1))

    assert result["height"] == tip_height
    # On-chain block at tip → confirmations should be 1.
    assert result["confirmations"] == 1


def test_getblock_height_for_disconnected_side_branch_block() -> None:
    """Disconnected blocks (e.g. a side-branch block stored via
    ``submitblock`` but not on the active chain) MUST also resolve to a
    real height when present in the side-branch buffer.

    confirmations stays -1 because the active-chain hash at that height
    is a different hash.
    """
    db = _StubDB()
    for h in range(113 + 1):
        db.add_active_block(h, _StubBlock(timestamp=1_700_000_000 + h))

    # Stash a competing block at height 110 (below the post-reorg tip).
    side_block = _StubBlock(timestamp=1_700_000_111)
    side_hash = db.add_side_branch_block(side_block)

    rpc = _make_rpc(db)
    rpc._side_branch_blocks[side_hash] = (b"\x00" * 32, 110, b"")

    display_hash = side_hash[::-1].hex()
    result = asyncio.run(rpc.rpc_getblock(display_hash, verbosity=1))

    assert result["height"] == 110, (
        "Side-branch buffer resolution must surface the recorded height, "
        "not the legacy falsy-coerced 0."
    )
    # Not on the active chain → confirmations -1 (Bitcoin Core parity).
    assert result["confirmations"] == -1
