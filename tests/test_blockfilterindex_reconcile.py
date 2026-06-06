"""
Regression tests for BIP-157 block-filter-index <-> chainstate reconcile.

The chainstate is crash-safe (one atomic WriteBatch + HEAD_BLOCKS marker),
but the block-filter index is written from a SEPARATE thread AFTER the
chainstate commit (block_sync ``add_block`` hook).  On an unclean restart, or
after a rollback / reorg, the persisted index can therefore be AHEAD of, or
FORKED from, the chainstate.  If we advertise NODE_COMPACT_FILTERS in that
state we serve cfilters / cfheaders for blocks that are NOT on our active
chain.

``PersistentBlockFilterIndex.reconcile_to_chainstate(db)`` mirrors Bitcoin
Core ``BaseIndex::Init`` + the rewind-to-fork-point in ``BaseIndex::Sync``
(src/index/base.cpp:124-145, 219-242): on startup it walks the index tip down
until it agrees with the chainstate in both height and identity.

These tests prove the gap is closed and (critically) that the assertion they
make would FAIL against the pre-fix code (no reconcile, so the index stays
ahead and ``is_synced`` returns True).
"""

from __future__ import annotations

import tempfile
import unittest

from ouroboros.blockfilter import PersistentBlockFilterIndex
from ouroboros.database import Block, Transaction, TxIn, TxOut


def _make_block(height: int, block_hash: bytes, prev_hash: bytes) -> Block:
    normal_spk = bytes([0x76, 0xA9, 0x14] + [height & 0xFF] * 20 + [0x88, 0xAC])
    coinbase_input = TxIn(
        prev_txid=bytes(32),
        prev_vout=0xFFFFFFFF,
        script_sig=b"\x01" + bytes([height & 0xFF]),
        sequence=0xFFFFFFFF,
    )
    tx = Transaction(
        txid=bytes(32),
        version=1,
        locktime=0,
        inputs=[coinbase_input],
        outputs=[TxOut(value=50_0000_0000, script_pubkey=normal_spk)],
    )
    return Block(
        version=1,
        prev_blockhash=prev_hash,
        merkle_root=bytes(32),
        timestamp=1231006505 + height * 600,
        bits=0x1D00FFFF,
        nonce=height,
        transactions=[tx],
        hash=block_hash,
        height=height,
    )


class _FakeChainstate:
    """Minimal stand-in exposing the two reconcile reads the index needs.

    ``height_to_hash`` maps active-chain height -> 32-byte hash; the tip is the
    maximum key.  This models the crash-safe chainstate independently of the
    Rust-backed real DB.
    """

    def __init__(self, height_to_hash: dict[int, bytes]):
        self.height_to_hash = dict(height_to_hash)

    def get_best_block(self) -> tuple[bytes, int]:
        tip = max(self.height_to_hash)
        return self.height_to_hash[tip], tip

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        return self.height_to_hash.get(height)


def _hash_for(height: int, tag: int = 0) -> bytes:
    # Distinct, height-derived 32-byte hash; ``tag`` distinguishes forks.
    return bytes([height & 0xFF, tag & 0xFF]) + bytes(30)


def _index_chain(idx: PersistentBlockFilterIndex, heights, tag: int = 0):
    """Index a contiguous chain [0..max] into the persistent index."""
    prev = bytes(32)
    for h in heights:
        bh = _hash_for(h, tag)
        idx.add_block(_make_block(h, bh, prev), height=h)
        prev = bh


class TestReconcileIndexAheadOfChainstate(unittest.TestCase):
    """Index persisted PAST the chainstate (the unclean-restart gap)."""

    def test_rewinds_index_ahead_and_clears_sync_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Index committed heights 0..5 ...
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            _index_chain(idx, range(0, 6))
            self.assertEqual(idx.best_indexed_height, 5)

            # ... but the chainstate's atomic commit only reached height 3
            # (heights 4,5 lost on an unclean crash).  Same hashes for the
            # heights both sides DO share.
            chainstate = _FakeChainstate(
                {h: _hash_for(h, 0) for h in range(0, 4)}
            )

            # PRE-FIX behaviour (no reconcile): the index is still at 5, so it
            # reports SYNCED for the chainstate tip 3 and would advertise
            # NODE_COMPACT_FILTERS while serving filters for orphaned 4,5.
            self.assertTrue(
                idx.is_synced(3),
                "guard: pre-fix the ahead-index falsely reports synced",
            )

            rewound = idx.reconcile_to_chainstate(chainstate)

            # Post-fix: rewound heights 5 and 4 back to the chainstate tip.
            self.assertEqual(rewound, 2)
            self.assertEqual(idx.best_indexed_height, 3)
            # Orphaned heights are gone from the index.
            self.assertIsNone(idx.get_block_hash_by_height(4))
            self.assertIsNone(idx.get_block_hash_by_height(5))
            # The shared chain (0..3) is intact and still synced to tip 3.
            self.assertEqual(idx.get_block_hash_by_height(3), _hash_for(3, 0))
            self.assertTrue(idx.is_synced(3))
            # The filter-header tip rolled back to height 3's stored header.
            self.assertEqual(idx.tip_header, idx.get_header(_hash_for(3, 0)))

    def test_reconcile_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            _index_chain(idx, range(0, 6))
            chainstate = _FakeChainstate(
                {h: _hash_for(h, 0) for h in range(0, 4)}
            )
            idx.reconcile_to_chainstate(chainstate)

            # Re-open: the rewind was persisted, so the fresh instance loads
            # best_indexed_height = 3 and is consistent without a second
            # reconcile.
            idx2 = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            self.assertEqual(idx2.best_indexed_height, 3)
            self.assertEqual(idx2.reconcile_to_chainstate(chainstate), 0)


class TestReconcileForkAtSameHeight(unittest.TestCase):
    """Reorg: chainstate replaced a block at a height the index still holds."""

    def test_rewinds_to_fork_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            # Index has the OLD fork at heights 0..4 (tag 0).
            _index_chain(idx, range(0, 5), tag=0)
            self.assertEqual(idx.best_indexed_height, 4)

            # Chainstate reorged: heights 0..2 are shared (tag 0), but 3,4 are
            # a different fork (tag 9) at the SAME heights.
            chainstate = _FakeChainstate(
                {
                    0: _hash_for(0, 0),
                    1: _hash_for(1, 0),
                    2: _hash_for(2, 0),
                    3: _hash_for(3, 9),
                    4: _hash_for(4, 9),
                }
            )

            # PRE-FIX: same height (4 == tip 4) so is_synced is True even
            # though the index points at the wrong (orphaned) fork tip.
            self.assertTrue(idx.is_synced(4))

            rewound = idx.reconcile_to_chainstate(chainstate)

            # Rewound the two forked heights (4, 3) down to the common
            # ancestor at height 2.
            self.assertEqual(rewound, 2)
            self.assertEqual(idx.best_indexed_height, 2)
            self.assertEqual(idx.get_block_hash_by_height(2), _hash_for(2, 0))
            # Index is now BEHIND the chainstate tip (4) -> not synced; the
            # connect path must re-index the new fork's 3,4 before
            # NODE_COMPACT_FILTERS is advertised again.
            self.assertFalse(idx.is_synced(4))


class TestReconcileNoOpWhenConsistent(unittest.TestCase):
    """Index already equal to / behind the chainstate: never touches it."""

    def test_index_equal_to_chainstate_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            _index_chain(idx, range(0, 5))
            chainstate = _FakeChainstate(
                {h: _hash_for(h, 0) for h in range(0, 5)}
            )
            self.assertEqual(idx.reconcile_to_chainstate(chainstate), 0)
            self.assertEqual(idx.best_indexed_height, 4)
            self.assertTrue(idx.is_synced(4))

    def test_index_behind_chainstate_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            idx = PersistentBlockFilterIndex(data_dir=tmp, enabled=True)
            _index_chain(idx, range(0, 3))  # index at height 2
            chainstate = _FakeChainstate(
                {h: _hash_for(h, 0) for h in range(0, 6)}  # chainstate at 5
            )
            # Behind is the IBD-catch-up case, NOT an inconsistency: leave it
            # to the connect path; reconcile must not rewind.
            self.assertEqual(idx.reconcile_to_chainstate(chainstate), 0)
            self.assertEqual(idx.best_indexed_height, 2)
            self.assertFalse(idx.is_synced(5))


if __name__ == "__main__":
    unittest.main()
