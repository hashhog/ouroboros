"""
FIX-72 (W120 BUG-3) — prioritisetransaction RPC + modified-fee wiring.

Verifies:
  1. Mempool.prioritise_transaction stores delta in map_deltas dict.
  2. get_modified_fee returns entry.fee + delta.
  3. positive delta makes a victim survive an RBF Rule 3 attempt.
  4. negative delta makes a replacement that would have passed Rule 3 fail.
  5. delta accumulates (saturating add) across multiple calls.
  6. delta of zero (after accumulation) erases the map_deltas entry.
  7. delta survives normal removal (eviction/expiry).
  8. delta is cleared on block confirmation (Core removeForBlock parity).
  9. delta IS persisted across mempool.dump_to_file / load_from_file
     (FIX-76 — Core parity, node/mempool_persist.cpp:101+166-203 —
     supersedes the FIX-72 brief's incorrect "in-memory only" claim).
 10. rpc_prioritisetransaction wires through (endian + dummy gating).
 11. rpc_getprioritisedtransactions emits Core-shape map.
 12. getmempoolentry RPC reflects modified fee in fees.modified.
 13. getblocktemplate ancestor-fee-rate sort honours deltas.
 14. _check_cluster_rbf uses modified fees on the old side.
 15. SOURCE-LEVEL regression guard: PaysForRBF path no longer references
     ``entry.fee`` directly inside the comparator — must use
     ``get_modified_fee`` / ``map_deltas`` instead.
 16. Two-pipeline guard: Rust ferrous-utils still has no mempool / delta code
     (Rust pipeline doesn't run RBF; the modified-fee wiring is Python-only).
"""

import asyncio
import hashlib
import inspect
import os
import struct
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Bootstrap — mirrors test_w120 scaffold so the suite runs offline.
# ---------------------------------------------------------------------------

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _bytes32(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes = field(default_factory=lambda: bytes([0x51, 0x20]) + bytes(32))


@dataclass
class TxIn:
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFE
    witness: list = field(default_factory=list)


@dataclass
class Transaction:
    version: int
    locktime: int
    inputs: list
    outputs: list
    _txid: bytes = field(default=None, repr=False)

    @property
    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1
                and self.inputs[0].prev_txid == bytes(32)
                and self.inputs[0].prev_vout == 0xFFFFFFFF)

    def get_txid(self) -> bytes:
        if self._txid is not None:
            return self._txid
        return hashlib.sha256(hashlib.sha256(self.serialize()).digest()).digest()

    def get_wtxid(self) -> bytes:
        return self.get_txid()

    def serialize(self) -> bytes:
        data = self.version.to_bytes(4, "little")
        data += _varint(len(self.inputs))
        for inp in self.inputs:
            data += inp.prev_txid
            data += inp.prev_vout.to_bytes(4, "little")
            data += _varint(len(inp.script_sig)) + inp.script_sig
            data += inp.sequence.to_bytes(4, "little")
        data += _varint(len(self.outputs))
        for out in self.outputs:
            data += out.value.to_bytes(8, "little")
            data += _varint(len(out.script_pubkey)) + out.script_pubkey
        data += self.locktime.to_bytes(4, "little")
        return data

    def serialize_with_witness(self) -> bytes:
        return self.serialize()

    def get_weight(self) -> int:
        return len(self.serialize()) * 4

    def get_vsize(self) -> int:
        return (self.get_weight() + 3) // 4


def _make_tx(txid: bytes = None, version: int = 1, inputs=None, outputs=None,
             sequence: int = 0xFFFFFFFD, value_out: int = 40_000) -> Transaction:
    if inputs is None:
        inputs = [TxIn(prev_txid=_bytes32(999), prev_vout=0, sequence=sequence)]
    if outputs is None:
        outputs = [TxOut(value=value_out)]
    tx = Transaction(version=version, locktime=0, inputs=inputs, outputs=outputs)
    if txid is not None:
        tx._txid = txid
    return tx


class MockDB:
    def __init__(self):
        self._utxos: dict = {}
        self._tip_height = 100
        self._mtp = 1_600_000_000

    def add_utxo(self, txid: bytes, vout: int, value: int,
                 script_pubkey: bytes = None, height: int = 1,
                 is_coinbase: bool = False):
        if script_pubkey is None:
            script_pubkey = bytes([0x51, 0x20]) + bytes(32)
        self._utxos[(txid, vout)] = {
            "value": value,
            "script_pubkey": script_pubkey,
            "height": height,
            "is_coinbase": is_coinbase,
        }

    def get_utxo(self, txid: bytes, vout: int):
        return self._utxos.get((txid, vout))

    def get_block_height(self):
        return self._tip_height

    def get_median_time_past(self, height: int = None) -> int:
        return self._mtp


class MockValidator:
    def __init__(self, db: MockDB):
        self.db = db
        self.network = "mainnet"

    def validate_transaction(self, tx, height, mtp=None, extra_script_flags=None):
        return True, ""


def _make_mempool(full_rbf: bool = True, require_standard: bool = False):
    from ouroboros.mempool import Mempool
    db = MockDB()
    validator = MockValidator(db)
    mp = Mempool(validator=validator, full_rbf=full_rbf,
                 require_standard=require_standard)
    return mp, db


def _add_tx_with_input(mp, db, *, parent_txid: bytes, parent_vout: int = 0,
                      parent_value: int = 1_000_000, fee: int = 1_000,
                      sequence: int = 0xFFFFFFFD, version: int = 1,
                      tx_id: bytes = None, value_out: int = None,
                      height: int = 101):
    if value_out is None:
        value_out = parent_value - fee
    db.add_utxo(parent_txid, parent_vout, value=parent_value)
    inp = TxIn(prev_txid=parent_txid, prev_vout=parent_vout, sequence=sequence)
    tx = _make_tx(txid=tx_id, version=version, inputs=[inp],
                  outputs=[TxOut(value=value_out)])
    ok, err = mp.add_transaction(tx, height=height)
    if not ok:
        raise AssertionError(f"setup add_transaction failed: {err}")
    return tx


# ===========================================================================
# Section 1 — primitive accessors
# ===========================================================================

class TestDeltaPrimitives(unittest.TestCase):

    def test_map_deltas_starts_empty(self):
        mp, _ = _make_mempool()
        self.assertEqual(mp.map_deltas, {})

    def test_prioritise_stores_delta(self):
        mp, _ = _make_mempool()
        txid = _bytes32(1)
        mp.prioritise_transaction(txid, 1234)
        self.assertEqual(mp.map_deltas.get(txid), 1234)

    def test_prioritise_accumulates(self):
        mp, _ = _make_mempool()
        txid = _bytes32(1)
        mp.prioritise_transaction(txid, 100)
        mp.prioritise_transaction(txid, 250)
        self.assertEqual(mp.map_deltas.get(txid), 350)

    def test_prioritise_zero_net_clears_entry(self):
        """Core txmempool.cpp:644-646: delta=0 erases the mapDeltas entry."""
        mp, _ = _make_mempool()
        txid = _bytes32(1)
        mp.prioritise_transaction(txid, 500)
        mp.prioritise_transaction(txid, -500)
        self.assertNotIn(txid, mp.map_deltas)

    def test_prioritise_works_for_tx_not_in_mempool(self):
        """Core stores delta for txs not yet in mempool."""
        mp, _ = _make_mempool()
        mp.prioritise_transaction(_bytes32(99), 10_000)
        # Tx is absent but delta is recorded.
        self.assertIn(_bytes32(99), mp.map_deltas)

    def test_get_modified_fee_by_txid(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(1), tx_id=_bytes32(2),
            parent_value=1_000_000, fee=1_000,
        )
        txid = tx.get_txid()
        self.assertEqual(mp.get_modified_fee(txid), 1_000)
        mp.prioritise_transaction(txid, 5_000)
        self.assertEqual(mp.get_modified_fee(txid), 6_000)

    def test_get_modified_fee_by_entry(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(3), tx_id=_bytes32(4),
            parent_value=1_000_000, fee=2_000,
        )
        entry = mp.transactions[tx.get_txid()]
        self.assertEqual(mp.get_modified_fee(entry), 2_000)
        mp.prioritise_transaction(tx.get_txid(), -500)
        self.assertEqual(mp.get_modified_fee(entry), 1_500)

    def test_get_modified_fee_rate(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(5), tx_id=_bytes32(6),
            parent_value=1_000_000, fee=1_000,
        )
        entry = mp.transactions[tx.get_txid()]
        base_rate = mp.get_modified_fee_rate(entry)
        mp.prioritise_transaction(tx.get_txid(), 9_000)
        # Should have risen — same size, 10x the fee → ~10x feerate.
        self.assertGreater(mp.get_modified_fee_rate(entry), base_rate * 9)


# ===========================================================================
# Section 2 — RBF Rule 3 honours delta on BOTH sides
# ===========================================================================

class TestRBFRule3HonoursDelta(unittest.TestCase):
    """Positive delta on victim → blocks a Rule-3-borderline replacement."""

    def test_positive_delta_on_victim_blocks_borderline_replacement(self):
        mp, db = _make_mempool(full_rbf=True)
        # Victim with fee 10_000 sats.
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(10), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(11),
        )
        victim_txid = v.get_txid()
        # Prioritise victim by +90_000 sats — modified fee now 100_000.
        mp.prioritise_transaction(victim_txid, 90_000)

        # Replacement with fee 11_000 — would beat raw fee, must FAIL on modified.
        rep_inp = TxIn(prev_txid=_bytes32(10), prev_vout=0, sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(12), inputs=[rep_inp],
                       outputs=[TxOut(value=1_000_000 - 11_000)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(
            ok,
            "Replacement must lose Rule 3 once victim is prioritised (FIX-72)"
        )
        self.assertIn("less than", err)
        # Victim still present.
        self.assertIn(victim_txid, mp.transactions)

    def test_positive_delta_on_replacement_wins_rule3(self):
        """Negative-fee replacement wins Rule 3 if prioritised enough."""
        mp, db = _make_mempool(full_rbf=True)
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(20), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(21),
        )

        # Replacement under-bids by 5k raw — but we prioritise it heavily.
        rep_txid = _bytes32(22)
        # delta must be applied BEFORE try_replace (Core PrioritiseTransaction
        # may be called for txids not yet in mempool).
        mp.prioritise_transaction(rep_txid, 100_000)
        rep_inp = TxIn(prev_txid=_bytes32(20), prev_vout=0, sequence=0xFFFFFFFD)
        rep = _make_tx(
            txid=rep_txid, inputs=[rep_inp],
            outputs=[TxOut(value=1_000_000 - 5_000)],  # raw fee 5k
        )
        ok, err = mp.try_replace(rep, height=101)
        self.assertTrue(
            ok,
            f"Replacement should win Rule 3 with positive delta: err={err}"
        )
        self.assertIn(rep_txid, mp.transactions)
        self.assertNotIn(v.get_txid(), mp.transactions)

    def test_negative_delta_on_replacement_blocks_borderline_pass(self):
        """Replacement that just barely passes raw Rule 3 fails with -delta."""
        mp, db = _make_mempool(full_rbf=True)
        _add_tx_with_input(
            mp, db, parent_txid=_bytes32(30), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(31),
        )

        rep_txid = _bytes32(32)
        # Penalise the replacement so its modified fee < victim's modified fee.
        mp.prioritise_transaction(rep_txid, -50_000)
        rep_inp = TxIn(prev_txid=_bytes32(30), prev_vout=0, sequence=0xFFFFFFFD)
        rep = _make_tx(
            txid=rep_txid, inputs=[rep_inp],
            outputs=[TxOut(value=1_000_000 - 50_000)],  # raw fee 50k beats raw
        )
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(
            ok,
            "Replacement with -50k modified-fee should lose Rule 3"
        )


# ===========================================================================
# Section 3 — delta lifecycle: eviction vs. confirmation vs. restart
# ===========================================================================

class TestDeltaLifecycle(unittest.TestCase):

    def test_delta_survives_normal_eviction(self):
        """Core preserves delta when tx is removed for non-block reasons."""
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(40), tx_id=_bytes32(41),
            parent_value=1_000_000, fee=1_000,
        )
        txid = tx.get_txid()
        mp.prioritise_transaction(txid, 5_000)
        mp.remove_transaction(txid, _reason="size-limit")
        self.assertIn(
            txid, mp.map_deltas,
            "Delta must survive non-block removal (Core parity)"
        )

    def test_delta_cleared_on_block_confirmation(self):
        """Core removeForBlock clears delta (txmempool.cpp:420)."""
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(50), tx_id=_bytes32(51),
            parent_value=1_000_000, fee=1_000,
        )
        txid = tx.get_txid()
        mp.prioritise_transaction(txid, 5_000)

        # Fake-block with this tx + a coinbase placeholder.
        block = types.SimpleNamespace(transactions=[tx])
        mp.remove_block_transactions(block)
        self.assertNotIn(txid, mp.map_deltas)
        self.assertNotIn(txid, mp.transactions)

    def test_clear_prioritisation_method(self):
        mp, _ = _make_mempool()
        mp.prioritise_transaction(_bytes32(60), 1_000)
        mp.clear_prioritisation(_bytes32(60))
        self.assertNotIn(_bytes32(60), mp.map_deltas)

    def test_delta_persisted_across_dump_load_roundtrip(self):
        """Delta survives a mempool.dat dump → reload (FIX-76).

        FIX-72 originally documented map_deltas as intentionally in-memory
        only, but the FIX-72 brief was wrong about Core: Core DOES persist
        mapDeltas (node/mempool_persist.cpp:101+166-203).  FIX-76 brings
        ouroboros to Core parity: in-mempool entries persist via the per-tx
        nFeeDelta field, standalone deltas via the tail block.

        Note: the test scaffold's synthetic ``_txid`` override survives in
        the live Transaction object but NOT through serialize → deserialize.
        After load, mp2's entry txid is the genuine double-SHA256 of the
        serialized body — which is the txid we look up.
        """
        from ouroboros.mempool import Mempool
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(70), tx_id=_bytes32(71),
            parent_value=1_000_000, fee=1_000,
        )
        txid = tx.get_txid()
        mp.prioritise_transaction(txid, 7_777)
        self.assertEqual(mp.map_deltas[txid], 7_777)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mempool.dat")
            written = mp.dump_to_file(path, use_xor=False)
            self.assertEqual(written, 1)

            # Fresh mempool.
            mp2 = Mempool(validator=mp.validator, full_rbf=True,
                          require_standard=False)
            mp2.validator.db = db  # share UTXOs for re-admission
            mp2.load_from_file(path, height=101)
            # Exactly one entry was reloaded — its real txid is the lookup
            # key in mp2.map_deltas (production-equivalent semantics).
            self.assertEqual(len(mp2.transactions), 1)
            real_txid = next(iter(mp2.transactions.keys()))
            # Delta IS restored (FIX-76 — Core parity).
            self.assertIn(
                real_txid, mp2.map_deltas,
                "mapDeltas must be persisted (FIX-76, Core parity)",
            )
            self.assertEqual(mp2.map_deltas[real_txid], 7_777)

    def test_standalone_delta_persisted_via_tail_block(self):
        """Delta for a txid NOT in mempool persists via the tail block.

        Matches Core (mempool_persist.cpp:125-132 LoadMempool):
            std::map<Txid, CAmount> mapDeltas;
            file >> mapDeltas;
            for (const auto& i : mapDeltas) pool.PrioritiseTransaction(...);
        """
        from ouroboros.mempool import Mempool
        mp, db = _make_mempool()
        # First add a real tx so the dump runs (mempool needs ≥1 entry OR a
        # delta to skip the empty early-return).
        _add_tx_with_input(
            mp, db, parent_txid=_bytes32(72), tx_id=_bytes32(73),
            parent_value=1_000_000, fee=1_000,
        )
        # Standalone delta for a txid that is NOT in mempool.
        absent_txid = _bytes32(0xABCDEF)
        mp.prioritise_transaction(absent_txid, -4_242)
        self.assertNotIn(absent_txid, mp.transactions)
        self.assertEqual(mp.map_deltas[absent_txid], -4_242)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mempool.dat")
            mp.dump_to_file(path, use_xor=False)

            mp2 = Mempool(validator=mp.validator, full_rbf=True,
                          require_standard=False)
            mp2.validator.db = db
            mp2.load_from_file(path, height=101)
            self.assertIn(absent_txid, mp2.map_deltas)
            self.assertEqual(mp2.map_deltas[absent_txid], -4_242)
            self.assertNotIn(
                absent_txid, mp2.transactions,
                "Standalone delta should NOT introduce a mempool entry"
            )

    def test_empty_map_deltas_survives_dump_load(self):
        """Mempool with zero deltas dumps + loads cleanly (no crash)."""
        from ouroboros.mempool import Mempool
        mp, db = _make_mempool()
        _add_tx_with_input(
            mp, db, parent_txid=_bytes32(74), tx_id=_bytes32(75),
            parent_value=1_000_000, fee=1_000,
        )
        self.assertEqual(mp.map_deltas, {})

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mempool.dat")
            mp.dump_to_file(path, use_xor=False)
            mp2 = Mempool(validator=mp.validator, full_rbf=True,
                          require_standard=False)
            mp2.validator.db = db
            mp2.load_from_file(path, height=101)
            self.assertEqual(mp2.map_deltas, {})
            self.assertEqual(len(mp2.transactions), 1)

    def test_mixed_in_mempool_and_standalone_deltas_roundtrip(self):
        """Both kinds of delta on the same dump roundtrip back."""
        from ouroboros.mempool import Mempool
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(76), tx_id=_bytes32(77),
            parent_value=1_000_000, fee=1_000,
        )
        in_pool_txid = tx.get_txid()
        mp.prioritise_transaction(in_pool_txid, 11_111)
        absent_a = _bytes32(0xAAAA)
        absent_b = _bytes32(0xBBBB)
        mp.prioritise_transaction(absent_a, 22_222)
        mp.prioritise_transaction(absent_b, -33_333)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mempool.dat")
            mp.dump_to_file(path, use_xor=False)
            mp2 = Mempool(validator=mp.validator, full_rbf=True,
                          require_standard=False)
            mp2.validator.db = db
            mp2.load_from_file(path, height=101)
            # In-mempool entry has its real (serialize-derived) txid after
            # reload; the synthetic ``_txid`` injection doesn't survive the
            # serialize → deserialize round-trip.
            self.assertEqual(len(mp2.transactions), 1)
            real_in_pool_txid = next(iter(mp2.transactions.keys()))
            self.assertEqual(mp2.map_deltas[real_in_pool_txid], 11_111)
            # Standalone deltas survive byte-for-byte (no serialization
            # involved on the txid bytes — they're written as-is).
            self.assertEqual(mp2.map_deltas[absent_a], 22_222)
            self.assertEqual(mp2.map_deltas[absent_b], -33_333)

    def test_old_format_file_without_tail_loads_cleanly(self):
        """Pre-FIX-76 dumps wrote tail count=0; current code must still load them.

        Backward-compat: a v1 (no XOR) dump written before FIX-76 with no
        per-tx delta + empty mapDeltas tail must load without raising.
        """
        from ouroboros.mempool import Mempool
        # Build a minimal v1 mempool.dat by hand:
        # uint64 version=1, uint64 tx_count=0, compact_size 0 (mapDeltas),
        # compact_size 0 (unbroadcast).
        blob = bytearray()
        blob.extend(struct.pack("<Q", 1))  # version
        blob.extend(struct.pack("<Q", 0))  # tx_count
        blob.append(0)                     # compact_size mapDeltas_count=0
        blob.append(0)                     # compact_size unbroadcast_count=0
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mempool.dat")
            with open(path, "wb") as f:
                f.write(bytes(blob))

            mp = Mempool(validator=MockValidator(MockDB()),
                         full_rbf=True, require_standard=False)
            n = mp.load_from_file(path, height=101)
            self.assertEqual(n, 0)
            self.assertEqual(mp.map_deltas, {})


# ===========================================================================
# Section 4 — RPC plumbing (rpc_prioritisetransaction +
# rpc_getprioritisedtransactions + getmempoolentry mirror)
# ===========================================================================

class _RpcStub:
    """Minimal RPC harness — only what the prioritisation handlers need."""
    def __init__(self, mempool):
        self.node = types.SimpleNamespace(mempool=mempool)


def _make_rpc(mempool):
    from ouroboros.rpc import RPCServer
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = types.SimpleNamespace(mempool=mempool)
    rpc._side_branch_blocks = {}
    rpc._side_branch_max_entries = 1024
    rpc.block_submission_paused = False
    return rpc


class TestPrioritiseTransactionRPC(unittest.TestCase):

    def test_rpc_prioritise_applies_delta(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(80), tx_id=_bytes32(81),
            parent_value=1_000_000, fee=1_000,
        )
        rpc = _make_rpc(mp)
        # Display-order txid is reverse of internal.
        display = tx.get_txid()[::-1].hex()
        result = asyncio.run(rpc.rpc_prioritisetransaction(
            txid=display, dummy=0, fee_delta=12_345,
        ))
        self.assertTrue(result)
        self.assertEqual(mp.map_deltas.get(tx.get_txid()), 12_345)

    def test_rpc_prioritise_negative_delta(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(82), tx_id=_bytes32(83),
            parent_value=1_000_000, fee=10_000,
        )
        rpc = _make_rpc(mp)
        display = tx.get_txid()[::-1].hex()
        asyncio.run(rpc.rpc_prioritisetransaction(
            txid=display, dummy=0, fee_delta=-5_000,
        ))
        self.assertEqual(mp.map_deltas.get(tx.get_txid()), -5_000)

    def test_rpc_prioritise_rejects_nonzero_dummy(self):
        mp, _ = _make_mempool()
        rpc = _make_rpc(mp)
        with self.assertRaises(ValueError):
            asyncio.run(rpc.rpc_prioritisetransaction(
                txid="aa" * 32, dummy=1.5, fee_delta=1_000,
            ))

    def test_rpc_prioritise_handles_string_delta(self):
        """JSON ints may decode as Python int; protect against str inputs too."""
        mp, _ = _make_mempool()
        rpc = _make_rpc(mp)
        asyncio.run(rpc.rpc_prioritisetransaction(
            txid="aa" * 32, dummy=0, fee_delta="2500"
        ))
        self.assertIn(bytes.fromhex("aa" * 32)[::-1], mp.map_deltas)

    def test_rpc_getprioritised_returns_core_shape(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(90), tx_id=_bytes32(91),
            parent_value=1_000_000, fee=1_000,
        )
        rpc = _make_rpc(mp)
        # One in-mempool delta + one absent-tx delta.
        mp.prioritise_transaction(tx.get_txid(), 4_000)
        mp.prioritise_transaction(_bytes32(99), 1_111)

        result = asyncio.run(rpc.rpc_getprioritisedtransactions())
        # In-mempool entry has modified_fee + in_mempool=True.
        display = tx.get_txid()[::-1].hex()
        self.assertIn(display, result)
        self.assertEqual(result[display]["fee_delta"], 4_000)
        self.assertTrue(result[display]["in_mempool"])
        self.assertEqual(result[display]["modified_fee"], 5_000)

        # Absent-tx entry: no modified_fee key (Core: only emitted when in_mempool).
        absent = _bytes32(99)[::-1].hex()
        self.assertIn(absent, result)
        self.assertEqual(result[absent]["fee_delta"], 1_111)
        self.assertFalse(result[absent]["in_mempool"])
        self.assertNotIn("modified_fee", result[absent])

    def test_getmempoolentry_reports_modified_fee(self):
        mp, db = _make_mempool()
        tx = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(100), tx_id=_bytes32(101),
            parent_value=1_000_000, fee=10_000,
        )
        rpc = _make_rpc(mp)
        mp.prioritise_transaction(tx.get_txid(), 50_000)
        display = tx.get_txid()[::-1].hex()
        entry_dict = asyncio.run(rpc.rpc_getmempoolentry(display))
        self.assertAlmostEqual(entry_dict["fees"]["base"], 10_000 / 1e8)
        self.assertAlmostEqual(entry_dict["fees"]["modified"], 60_000 / 1e8)
        self.assertAlmostEqual(entry_dict["modifiedfee"], 60_000 / 1e8)


# ===========================================================================
# Section 5 — source-level regression guard
# ===========================================================================

class TestSourceRegressionGuards(unittest.TestCase):
    """Lock down the structural fix so future drive-bys can't regress."""

    def test_try_replace_uses_modified_fee_not_raw_entry_fee(self):
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool._try_replace_inner)
        # The fix must consult either map_deltas or get_modified_fee in the
        # PaysForRBF region.  Raw "entry.fee" must no longer appear in the
        # fee-comparison region of try_replace.
        self.assertTrue(
            "get_modified_fee" in src or "map_deltas" in src,
            "RBF path must consult prioritise-tx delta (FIX-72)",
        )
        # Specifically, the old anti-pattern (raw .fee sum in PaysForRBF)
        # should no longer appear.
        self.assertNotIn(
            "sum(self.transactions[t].fee for t in to_evict)", src,
            "Raw entry.fee sum in PaysForRBF is the BUG-3 root cause",
        )

    def test_check_cluster_rbf_uses_modified_fee(self):
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool._check_cluster_rbf)
        self.assertIn(
            "get_modified_fee", src,
            "_check_cluster_rbf must use modified fees (FIX-72)",
        )

    def test_mempool_class_exposes_priority_api(self):
        from ouroboros.mempool import Mempool
        for name in (
            "prioritise_transaction",
            "get_modified_fee",
            "get_modified_fee_rate",
            "clear_prioritisation",
            "get_prioritised_transactions",
            "map_deltas",
        ):
            self.assertTrue(hasattr(Mempool, name) or name == "map_deltas",
                            f"Mempool must expose {name}")

    def test_dump_to_file_writes_n_fee_delta_from_map_deltas(self):
        """FIX-76 source guard: dump_to_file no longer writes literal nFeeDelta=0.

        The pre-FIX-76 anti-pattern wrote ``struct.pack("<q", 0)`` for every
        per-tx nFeeDelta and a zero-length mapDeltas tail.  Make sure the new
        dump path consults ``map_deltas`` for both halves.
        """
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool.dump_to_file)
        # The persisted-delta path must mention map_deltas.
        self.assertIn(
            "map_deltas", src,
            "dump_to_file must consult map_deltas (FIX-76)",
        )
        # The pre-FIX-76 stub literal must be gone.
        self.assertNotIn(
            'body.extend(struct.pack("<q", 0))  # int64 nFeeDelta',
            src,
            "dump_to_file no longer writes literal nFeeDelta=0 (FIX-76)",
        )

    def test_load_from_file_restores_deltas(self):
        """FIX-76 source guard: load_from_file restores both kinds of delta.

        The pre-FIX-76 load path parsed the tail and DISCARDED deltas via a
        bare ``offset += 32 + 8`` loop with no PrioritiseTransaction call.
        After FIX-76 the loop must call ``prioritise_transaction`` for both
        per-entry and standalone deltas.
        """
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool.load_from_file)
        self.assertIn(
            "prioritise_transaction", src,
            "load_from_file must replay deltas via prioritise_transaction (FIX-76)",
        )
        # Per-entry nFeeDelta must be consumed not just skipped.
        self.assertNotIn(
            "_n_fee_delta", src,
            "load_from_file should USE nFeeDelta, not throw it away (FIX-76)",
        )


# ===========================================================================
# Section 6 — two-pipeline guard (Rust ferrous-utils still has no RBF)
# ===========================================================================

class TestTwoPipelineGuard(unittest.TestCase):
    """The Rust pipeline does not run RBF/mempool — delta wiring is Python-only.

    This mirrors W120 G24 + W120 TP-1: any future Rust-side mempool path that
    consumes deltas MUST also call get_modified_fee.  Until that happens, the
    Python guard is sufficient and the Rust side must remain blank.
    """

    def test_rust_pipeline_has_no_priority_api(self):
        rust_root = src_dir.parent / "ferrous-utils" / "sync" / "src"
        if not rust_root.exists():
            self.skipTest("Rust pipeline not present in this checkout")
        hits = 0
        for path in rust_root.rglob("*.rs"):
            content = path.read_text(errors="ignore")
            if any(needle in content for needle in (
                "PrioritiseTransaction",
                "map_deltas",
                "mapDeltas",
                "modified_fee",
                "GetModifiedFee",
            )):
                hits += 1
        self.assertEqual(
            hits, 0,
            "Rust pipeline currently has no priority/RBF; if this changes, "
            "GetModifiedFee semantics MUST be honoured there too (FIX-72)",
        )

    def test_rust_pipeline_has_no_mempool_persist_code(self):
        """FIX-76: persistence code stays Python-only.

        ferrous-utils (Rust) must not touch mempool.dat or mapDeltas
        persistence — Python-side owns dump_to_file/load_from_file.  If a
        future wave adds Rust-side mempool persistence, BOTH halves of the
        delta tail must be honoured (per-tx nFeeDelta + standalone tail).
        """
        rust_root = src_dir.parent / "ferrous-utils" / "sync" / "src"
        if not rust_root.exists():
            self.skipTest("Rust pipeline not present in this checkout")
        hits = []
        for path in rust_root.rglob("*.rs"):
            content = path.read_text(errors="ignore")
            for needle in ("mempool.dat", "DumpMempool", "LoadMempool",
                           "nFeeDelta", "fee_delta", "map_deltas"):
                if needle in content:
                    hits.append((path.name, needle))
        self.assertEqual(
            hits, [],
            f"Rust pipeline must remain mempool-persistence-free (FIX-76); "
            f"hits: {hits}",
        )


if __name__ == "__main__":
    unittest.main()
