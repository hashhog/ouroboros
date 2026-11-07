"""RBF rule 5 counts distinct conflicting clusters, not evicted transactions.

Core v31 policy/rbf.cpp GetEntriesForConflicts: the limit
MAX_REPLACEMENT_CANDIDATES (100) applies to pool.GetUniqueClusterCount() of the
direct conflicts. Five clusters of 21 transactions (105 evictees) are accepted;
the Core regtest `rbf/clusters` scenario found ouroboros rejecting that with
"too many potential replacements".
"""

import unittest

from ouroboros.tests.test_w120_mempool_rbf import (
    _bytes32, _make_mempool, _make_tx, _add_tx_with_input, TxIn, TxOut,
)
from ouroboros.mempool import Mempool


def _chain(mp, db, seed: int, length: int):
    """A chain of `length` txs (one cluster); returns (root parent txid, txids)."""
    root_parent = _bytes32(10_000 + seed)
    parent, vout, txids = root_parent, 0, []
    for i in range(length):
        txid = _bytes32(100_000 * (seed + 1) + i)
        value = 1_000_000 - 1_000 * i
        tx = _add_tx_with_input(mp, db, parent_txid=parent, parent_vout=vout,
                                parent_value=value, tx_id=txid)
        parent, vout = txid, 0
        txids.append(txid)
    return root_parent, txids


def _replace(mp, roots):
    inputs = [TxIn(prev_txid=r, prev_vout=0, sequence=0xFFFFFFFD) for r in roots]
    new_tx = _make_tx(txid=_bytes32(9_999_999), inputs=inputs,
                      outputs=[TxOut(value=100_000)])
    return mp.add_transaction(new_tx, height=101), new_tx


class TestRule5CountsClusters(unittest.TestCase):
    def test_two_clusters_of_sixty_are_replaceable(self):
        mp, db = _make_mempool()
        roots = []
        for s in range(2):
            r, txids = _chain(mp, db, s, 60)
            roots.append(r)
        self.assertEqual(len(mp.transactions), 120)
        (ok, err), new_tx = _replace(mp, roots)
        self.assertTrue(ok, err)
        self.assertEqual(len(mp.transactions), 1)

    def test_over_limit_clusters_rejected_with_core_message(self):
        mp, db = _make_mempool()
        roots = []
        for s in range(Mempool.MAX_REPLACEMENT_EVICTIONS + 1):
            r, _ = _chain(mp, db, s, 1)
            roots.append(r)
        (ok, err), _ = _replace(mp, roots)
        self.assertFalse(ok)
        self.assertIn("too many conflicting clusters (101 > 100)", err)
        self.assertEqual(len(mp.transactions), 101)


if __name__ == "__main__":
    unittest.main()
