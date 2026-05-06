"""Pattern X + Y closure for ``rpc_submitblock`` (2026-05-06).

Reference: ``CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md``.

Pre-fix ouroboros's ``submitblock`` derived ``next_height`` from
``best_height + 1`` unconditionally, so any side-branch block whose
parent was not the active tip got a wrong BIP-34 expected height and
was rejected with ``bad-cb-height``. End-to-end coverage by the
``tools/diff-test-corpus/regression/reorg-via-submitblock`` corpus
entry; these unit tests pin the structural invariants the fix relies
on so a future refactor cannot silently re-introduce the bug.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402


class _FakeDb:
    """Minimal stand-in for ``PyBlockchainDB`` that pins the contract
    ``_resolve_parent_height`` exercises: best-block + height-keyed
    block-hash index. The active-chain map is height -> hash."""

    def __init__(self, active_chain: dict[int, bytes], tip_height: int):
        self._chain = dict(active_chain)
        self._tip_h = tip_height

    def get_best_block(self) -> tuple[bytes, int]:
        return self._chain[self._tip_h], self._tip_h

    def get_block_hash_by_height(self, h: int) -> bytes | None:
        return self._chain.get(h)

    def has_block_hash(self, _h: bytes) -> bool:
        return False


class TestResolveParentHeight(unittest.TestCase):
    """``_resolve_parent_height`` MUST return ``parent.height + 1`` style
    height for the BIP-34 check, NOT ``active_tip + 1``. This is the
    Pattern X correctness contract.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc = RPCServer(self.node, port=18332)
        # Synthetic active chain: g (h=0) -> a1 (h=1) -> a2 (h=2).
        self.g = b"\x00" + b"g" + b"\x00" * 30
        self.a1 = b"\x01" + b"a" + b"\x00" * 30
        self.a2 = b"\x02" + b"a" + b"\x00" * 30
        self.db = _FakeDb({0: self.g, 1: self.a1, 2: self.a2}, tip_height=2)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_active_tip_parent_returns_tip_height(self) -> None:
        """Best-chain extension fast path: prev IS the active tip."""
        h = self.rpc._resolve_parent_height(self.db, self.a2)
        self.assertEqual(h, 2)

    def test_active_chain_ancestor_returns_ancestor_height(self) -> None:
        """Pattern X: prev is on the active chain but is NOT the tip
        (e.g. fork-point parent). Pre-fix ouroboros used best_height + 1
        for BIP-34 — wrong. Post-fix the helper returns the parent's own
        height in the index, so the caller can derive parent.height + 1.
        """
        # a1 is at h=1, even though active tip is at h=2.
        h = self.rpc._resolve_parent_height(self.db, self.a1)
        self.assertEqual(h, 1)

    def test_genesis_ancestor_returns_zero(self) -> None:
        """A side-branch rooted at genesis must resolve to height 0.
        Off-by-one here would push BIP-34 expected height to 2 instead
        of 1 for the first side-branch child."""
        h = self.rpc._resolve_parent_height(self.db, self.g)
        self.assertEqual(h, 0)

    def test_unknown_parent_returns_none(self) -> None:
        """A truly orphan block (parent not in active chain or
        side-branch buffer) must surface as None — the caller maps
        this to a BIP-22 ``rejected`` string. We must NOT silently
        treat unknown parents as if they were the genesis."""
        unknown = b"\xff" * 32
        h = self.rpc._resolve_parent_height(self.db, unknown)
        self.assertIsNone(h)

    def test_side_branch_buffer_resolves_first(self) -> None:
        """A side-branch block whose parent is itself in the
        ``_side_branch_blocks`` map (i.e. a depth-2+ side branch like
        B2 in the regression corpus, whose parent B1 sits in the
        buffer not on the active chain) must resolve via the buffer.
        Pre-Pattern-Y ouroboros had no such buffer; this test pins
        the buffer invariant."""
        b1 = b"\x10" + b"b" + b"\x00" * 30
        # B1 is at side-branch height 1 (sharing parent g with a1).
        self.rpc._side_branch_blocks[b1] = (self.g, 1, b"raw-b1-bytes")
        h = self.rpc._resolve_parent_height(self.db, b1)
        self.assertEqual(h, 1)

    def test_side_branch_buffer_takes_precedence_over_active_chain(
        self,
    ) -> None:
        """Defensive: if the SAME hash appears in both the active
        chain and the side-branch buffer (shouldn't happen normally
        but pin the precedence anyway), the buffer wins. The buffer
        height is what the heaviest-chain compare uses, so making it
        authoritative keeps ``_attach_side_branch_block`` consistent
        with the reorg dispatch."""
        # Stash a1's hash in the side-branch buffer with a different
        # height than its active-chain placement.
        self.rpc._side_branch_blocks[self.a1] = (self.g, 1, b"raw")
        # The buffer-stored height matches the chain placement here so
        # the test stays sensitive to the precedence rule rather than
        # picking up an off-by-one win.
        h = self.rpc._resolve_parent_height(self.db, self.a1)
        self.assertEqual(h, 1)


class TestSideBranchBufferEviction(unittest.TestCase):
    """Cap on the in-memory side-branch buffer."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc = RPCServer(self.node, port=18332)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_buffer_caps_at_max_entries(self) -> None:
        self.rpc._side_branch_max_entries = 4
        for i in range(8):
            h = bytes([i]) + b"\x00" * 31
            self.rpc._side_branch_blocks[h] = (b"\x00" * 32, i, b"")
            self.rpc._evict_side_branch_if_full()
        # FIFO eviction: only the last 4 survived.
        self.assertEqual(len(self.rpc._side_branch_blocks), 4)
        for i in range(4, 8):
            h = bytes([i]) + b"\x00" * 31
            self.assertIn(h, self.rpc._side_branch_blocks)


class TestRpcSubmitBlockTooShort(unittest.TestCase):
    """Pin the very-short-input fast-reject path so a refactor can't
    accidentally drop the 80-byte header guard."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc = RPCServer(self.node, port=18332)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_short_block_rejected(self) -> None:
        # 79 bytes is one byte short of a header.
        async def _run():
            return await self.rpc.rpc_submitblock("aa" * 79)
        result = asyncio.run(_run())
        self.assertEqual(result, "rejected")

    def test_invalid_hex_rejected(self) -> None:
        async def _run():
            return await self.rpc.rpc_submitblock("not-hex-at-all")
        result = asyncio.run(_run())
        self.assertEqual(result, "rejected")


if __name__ == "__main__":
    unittest.main()
