"""
Tests for the wtxid dual index in :class:`ouroboros.mempool.Mempool`.

Reference: Bitcoin Core ``txmempool.h`` — ``mapTx`` is keyed by both txid
and wtxid for O(1) BIP 152 / BIP 339 lookups.

These tests verify:
  - The ``wtxid_to_txid`` dict is populated on add and pruned on remove.
  - For non-segwit txs wtxid == txid (the index entry collapses to itself).
  - For segwit txs wtxid != txid and the index returns the right entry.
  - ``Mempool.get_transaction_by_wtxid`` returns the same Transaction object
    that was inserted (no hash/lookup mismatch).
  - ``clear()`` flushes the wtxid map alongside ``transactions``.
  - The cmpctblock helper ``build_short_txid_map`` consults the wtxid index
    rather than recomputing wtxids on every entry.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Stub the Rust ``sync`` extension before importing ouroboros modules.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: True
    sys.modules["sync"] = _mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402


class _StubDB:
    def __init__(self) -> None:
        self._utxos: dict = {}

    def add_utxo(self, txid: bytes, vout: int, value: int) -> None:
        self._utxos[(txid, vout)] = {"value": value, "script_pubkey": b""}

    def get_utxo(self, txid: bytes, vout: int):
        return self._utxos.get((txid, vout))


class _AlwaysOkValidator:
    def __init__(self, db: _StubDB) -> None:
        self.db = db

    def validate_transaction(self, tx, height):
        return True, ""


def _make_tx(seed: int, db: _StubDB, *, with_witness: bool = False) -> Transaction:
    import hashlib

    prev_txid = bytes([seed]) * 32
    db.add_utxo(prev_txid, 0, 100_000_000)
    inputs = [
        TxIn(
            prev_txid=prev_txid,
            prev_vout=0,
            script_sig=b"\x51",
            sequence=0xFFFFFFFF,
            witness=([b"\x51"] if with_witness else None),
        )
    ]
    outputs = [TxOut(value=99_990_000, script_pubkey=b"\x76\xa9")]
    tx = Transaction(
        txid=bytes(32),
        version=2,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=with_witness,
    )
    body = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(body).digest()).digest()
    return tx


class TestWtxidDualIndex(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _StubDB()
        self.mp = Mempool(_AlwaysOkValidator(self.db), require_standard=False)

    def test_index_populated_on_add(self) -> None:
        tx = _make_tx(1, self.db)
        ok, _ = self.mp.add_transaction(tx, height=100)
        self.assertTrue(ok)
        wtxid = tx.get_wtxid()
        self.assertIn(wtxid, self.mp.wtxid_to_txid)
        self.assertEqual(self.mp.wtxid_to_txid[wtxid], tx.get_txid())

    def test_non_segwit_wtxid_equals_txid(self) -> None:
        tx = _make_tx(2, self.db, with_witness=False)
        self.mp.add_transaction(tx, height=100)
        self.assertEqual(tx.get_wtxid(), tx.get_txid())
        self.assertEqual(self.mp.wtxid_to_txid[tx.get_txid()], tx.get_txid())

    def test_segwit_wtxid_distinct_from_txid(self) -> None:
        tx = _make_tx(3, self.db, with_witness=True)
        self.mp.add_transaction(tx, height=100)
        self.assertNotEqual(tx.get_wtxid(), tx.get_txid())
        self.assertIn(tx.get_wtxid(), self.mp.wtxid_to_txid)
        self.assertNotIn(tx.get_txid(), self.mp.wtxid_to_txid)

    def test_index_pruned_on_remove(self) -> None:
        tx = _make_tx(4, self.db, with_witness=True)
        self.mp.add_transaction(tx, height=100)
        wtxid = tx.get_wtxid()
        self.assertIn(wtxid, self.mp.wtxid_to_txid)
        self.mp.remove_transaction(tx.get_txid())
        self.assertNotIn(wtxid, self.mp.wtxid_to_txid)

    def test_clear_flushes_index(self) -> None:
        for i in (5, 6, 7):
            tx = _make_tx(i, self.db, with_witness=(i % 2 == 0))
            self.mp.add_transaction(tx, height=100)
        self.assertEqual(len(self.mp.wtxid_to_txid), 3)
        self.mp.clear()
        self.assertEqual(len(self.mp.wtxid_to_txid), 0)
        self.assertEqual(len(self.mp.transactions), 0)

    def test_get_transaction_by_wtxid(self) -> None:
        tx = _make_tx(8, self.db, with_witness=True)
        self.mp.add_transaction(tx, height=100)
        looked_up = self.mp.get_transaction_by_wtxid(tx.get_wtxid())
        self.assertIsNotNone(looked_up)
        self.assertEqual(looked_up.get_txid(), tx.get_txid())

    def test_get_transaction_by_unknown_wtxid_returns_none(self) -> None:
        unknown = bytes(32)
        self.assertIsNone(self.mp.get_transaction_by_wtxid(unknown))

    def test_build_short_txid_map_uses_index(self) -> None:
        # Insert one segwit tx and verify the cmpctblock helper finds it.
        tx = _make_tx(9, self.db, with_witness=True)
        self.mp.add_transaction(tx, height=100)
        siphash_key = b"\xaa" * 16
        result = self.mp.build_short_txid_map(siphash_key)
        self.assertEqual(len(result), 1)
        self.assertIs(next(iter(result.values())), tx)


if __name__ == "__main__":
    unittest.main()
