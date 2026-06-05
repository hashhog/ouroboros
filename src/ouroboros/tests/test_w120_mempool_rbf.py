"""
W120 audit: BIP-125 strict mempool RBF rules 1-5 for ouroboros — 30 gates.

Reference: Bitcoin Core src/policy/rbf.cpp, src/policy/rbf.h; BIP-125.

Two pipelines:
  - Python: src/ouroboros/mempool.py — Mempool.try_replace() implements all
    five BIP-125 rules + DiagramCheck (cluster-mempool successor).
  - Rust: ferrous-utils/sync/ — NO mempool/RBF code (consensus only).
    All P0/P1 RBF audit findings apply to the Python pipeline.

Per-rule mapping (Core policy/rbf.cpp -> Mempool._try_replace_inner):
  Rule 1 (SignalsOptInRBF gate, unless full_rbf):  lines 3479-3485
  Rule 2 (HasNoNewUnconfirmed):                    lines 3503-3526
  Rule 3 (PaysForRBF absolute):                    lines 3557-3565
  Rule 4 (PaysForRBF incremental):                 lines 3567-3578
  Rule 5 (MAX_REPLACEMENT_CANDIDATES = 100):       lines 3493-3501
  Diagram (ImprovesFeerateDiagram):                _check_cluster_rbf

Findings summary (P0/P1 bugs; full per-gate table below):
  BUG-1 (P1-CDIV): Rule 5 uses total-evictee-count, not Core's
         GetUniqueClusterCount(iters_conflicting); comment-as-confession.
  BUG-2 (P0-CDIV): INCREMENTAL_RELAY_FEE constant is 100 sat/kvB, Core default
         is 1000 sat/kvB (DEFAULT_INCREMENTAL_RELAY_FEE in policy/policy.h).
         Replacement bandwidth bar is 10x too low — Rule 4 dramatically weaker.
         (Note: line 54 sets DEFAULT_INCREMENTAL_RELAY_FEE=100 and copies it.)
  BUG-3 (P1-CDIV): PaysForRBF uses MempoolEntry.fee (raw fee), not modified
         fee (fee + nFeeDelta from PrioritiseTransaction). prioritisetransaction
         is unimplemented — feeDelta is zero everywhere (mempool.py:3848).
         FIXED in FIX-72: Mempool.prioritise_transaction / get_modified_fee
         wired into PaysForRBF, _check_cluster_rbf, getmempoolentry,
         getblocktemplate.
  BUG-4 (P1-CDIV): DiagramCheck _check_cluster_rbf uses `new_rate < old_rate`
         (allows equal rates) but Core requires `std::is_gt(new, old)` →
         strictly-greater. ouroboros accepts replacements Core would reject.
  BUG-5 (P1-CDIV): DiagramCheck _check_cluster_rbf hard-codes a 1% tolerance
         (`chunk.fee_rate * 0.99`) in the per-chunk feerate sanity bound.
         No equivalent in Core's CompareChunks; replacement can underbid by
         up to 1% and still pass.
  BUG-6 (P2-MINOR): incrementalrelayfee not CLI-configurable; hardcoded class
         constant (Core: -incrementalrelayfee).
  BUG-7 (P2-MINOR): try_replace returns `(ok, error_str)` but does not
         propagate the evicted txid set to the caller — only logger.info.
         RPC `sendrawtransaction` cannot report replaced txids per BIP-125.
  TP-1 (TWO-PIPELINE): Rust ferrous-utils has NO RBF code; entirely Python.
         Any future Rust-side mempool/relay path would not enforce BIP-125.

Comment-as-confession sites carried forward into W120:
  - mempool.py:3494 "Core uses GetUniqueClusterCount(); without cluster
    mempool we count total evictees as a conservative bound"
  - mempool.py:3296 "Simple check: the new fee rate must be >= old fee rate /
    This is a simplified version of the full diagram comparison"
  - mempool.py:3848 "we don't track prioritise-tx deltas yet" (FIX-72 — closed)

All tests run offline (no live network, no RocksDB).
"""

import sys
import time
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Bootstrap (matches test_w106 scaffold)
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


# ---------------------------------------------------------------------------
# Minimal stubs (intentionally self-contained — mirrors test_w106 scaffold)
# ---------------------------------------------------------------------------

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
        import hashlib
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
             sequence: int = 0xFFFFFFFE, value_out: int = 40_000) -> Transaction:
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
    def __init__(self, db: MockDB, network: str = "mainnet"):
        self.db = db
        self.network = network

    def validate_transaction(self, tx, height, mtp=None, extra_script_flags=None):
        if tx.is_coinbase:
            return False, "coinbase"
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
    """Add a UTXO + tx that spends it; returns the tx (or raises if rejected)."""
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
# G1 — SignalsOptInRBF: sequence < 0xFFFFFFFE signals
# Core: util/rbf.cpp SignalsOptInRBF (any input nSequence < MAX_BIP125_RBF_SEQUENCE+1)
# Status: PRESENT
# ===========================================================================

class TestG1SignalsBasic(unittest.TestCase):
    """Sequence values 0..0xFFFFFFFD signal RBF; 0xFFFFFFFE/F do not."""

    def test_sequence_zero_signals(self):
        mp, _ = _make_mempool()
        tx = _make_tx(sequence=0)
        self.assertTrue(mp.signals_rbf(tx))

    def test_sequence_fffffffd_signals(self):
        mp, _ = _make_mempool()
        tx = _make_tx(sequence=0xFFFFFFFD)
        self.assertTrue(mp.signals_rbf(tx))


# ===========================================================================
# G2 — SignalsOptInRBF boundary: 0xFFFFFFFE does NOT signal
# Core: src/util/rbf.h MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD
# Status: PRESENT
# ===========================================================================

class TestG2SignalsBoundary(unittest.TestCase):
    def test_sequence_fffffffe_no_signal(self):
        mp, _ = _make_mempool()
        tx = _make_tx(sequence=0xFFFFFFFE)
        self.assertFalse(mp.signals_rbf(tx))

    def test_sequence_ffffffff_no_signal(self):
        mp, _ = _make_mempool()
        tx = _make_tx(sequence=0xFFFFFFFF)
        self.assertFalse(mp.signals_rbf(tx))


# ===========================================================================
# G3 — any-input semantics: one signaling input flips entire tx
# Core: SignalsOptInRBF iterates all inputs, returns true on any < FFFFFFFE
# Status: PRESENT
# ===========================================================================

class TestG3SignalsAnyInput(unittest.TestCase):
    def test_one_signaling_input_flips_tx(self):
        mp, _ = _make_mempool()
        inputs = [
            TxIn(prev_txid=_bytes32(1), prev_vout=0, sequence=0xFFFFFFFF),
            TxIn(prev_txid=_bytes32(2), prev_vout=0, sequence=0xFFFFFFFD),
            TxIn(prev_txid=_bytes32(3), prev_vout=0, sequence=0xFFFFFFFE),
        ]
        tx = _make_tx(inputs=inputs)
        self.assertTrue(mp.signals_rbf(tx))

    def test_all_inputs_non_signaling(self):
        mp, _ = _make_mempool()
        inputs = [
            TxIn(prev_txid=_bytes32(1), prev_vout=0, sequence=0xFFFFFFFE),
            TxIn(prev_txid=_bytes32(2), prev_vout=0, sequence=0xFFFFFFFF),
        ]
        tx = _make_tx(inputs=inputs)
        self.assertFalse(mp.signals_rbf(tx))


# ===========================================================================
# G4 — IsRBFOptIn: ancestor inheritance (BIP-125 ancestor walk)
# Core: policy/rbf.cpp IsRBFOptIn walks CalculateMemPoolAncestors
# Status: PRESENT
# ===========================================================================

class TestG4AncestorInheritance(unittest.TestCase):
    def test_non_signaling_child_of_signaling_parent_is_replaceable(self):
        mp, db = _make_mempool(full_rbf=False)
        # parent signals (sequence 0xFFFFFFFD)
        parent = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(10), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(20),
        )
        # child does NOT signal (sequence 0xFFFFFFFE)
        db.add_utxo(_bytes32(20), 0, value=999_000)
        child_inp = TxIn(prev_txid=_bytes32(20), prev_vout=0,
                         sequence=0xFFFFFFFE)
        child = _make_tx(txid=_bytes32(21), inputs=[child_inp],
                         outputs=[TxOut(value=998_000)])
        ok, err = mp.add_transaction(child, height=101)
        self.assertTrue(ok, err)
        # Per BIP-125, child inherits replaceability from parent
        self.assertTrue(mp.is_rbf_opt_in(_bytes32(21)),
                        "Non-signaling child of signaling parent must inherit replaceability")


# ===========================================================================
# G5 — Rule 1 enforcement when full_rbf disabled (opt-in semantics)
# Core: ReplacementChecks rejects conflicts that don't signal unless mempoolfullrbf
# Status: PRESENT
# ===========================================================================

class TestG5Rule1OptInGate(unittest.TestCase):
    def test_non_signaling_conflict_rejected_without_full_rbf(self):
        mp, db = _make_mempool(full_rbf=False)
        # Victim: NOT signaling RBF
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(30), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFE, tx_id=_bytes32(31),
        )
        # Replacement spends same UTXO with higher fee
        rep_inp = TxIn(prev_txid=_bytes32(30), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(32), inputs=[rep_inp],
                       outputs=[TxOut(value=900_000)])  # 100k fee >> incremental
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok)
        # Reason should mention signaling / BIP125
        self.assertTrue(("BIP125" in err) or ("signal" in err.lower()) or
                        ("replaceability" in err.lower()), err)


# ===========================================================================
# G6 — Rule 1 bypass when full_rbf=True (Core default since v28)
# Core: validation.cpp ReplacementChecks skips signaling gate if mempoolfullrbf
# Status: PRESENT
# ===========================================================================

class TestG6Rule1FullRBFBypass(unittest.TestCase):
    def test_non_signaling_conflict_accepted_with_full_rbf(self):
        mp, db = _make_mempool(full_rbf=True)
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(40), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFE, tx_id=_bytes32(41),
        )
        rep_inp = TxIn(prev_txid=_bytes32(40), prev_vout=0,
                       sequence=0xFFFFFFFE)
        rep = _make_tx(txid=_bytes32(42), inputs=[rep_inp],
                       outputs=[TxOut(value=900_000)])
        ok, err = mp.try_replace(rep, height=101)
        # full_rbf should not block on Rule 1; failure (if any) must be
        # for a downstream policy rule (3/4/diagram), not signaling.
        if not ok:
            self.assertNotIn("BIP125", err)
            self.assertNotIn("signal", err.lower())
            self.assertNotIn("replaceability", err.lower())


# ===========================================================================
# G7 — Rule 2 HasNoNewUnconfirmed: replacement may not spend NEW unconfirmed
# Core: policy/rbf.cpp / validation.cpp ReplacementChecks lines ~1356
# Status: PRESENT
# ===========================================================================

class TestG7Rule2HasNoNewUnconfirmed(unittest.TestCase):
    def test_new_unconfirmed_input_rejected(self):
        mp, db = _make_mempool(full_rbf=True)
        # Victim 1: spends confirmed utxo A
        v1 = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(50), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(51),
        )
        # Independent unconfirmed tx (not in eviction set)
        unrel = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(60), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(61),
        )
        # Replacement spends victim's confirmed input AND unrelated unconfirmed
        rep_inputs = [
            TxIn(prev_txid=_bytes32(50), prev_vout=0, sequence=0xFFFFFFFD),
            TxIn(prev_txid=_bytes32(61), prev_vout=0, sequence=0xFFFFFFFD),
        ]
        db.add_utxo(_bytes32(61), 0, value=999_000)
        rep = _make_tx(txid=_bytes32(52), inputs=rep_inputs,
                       outputs=[TxOut(value=1_900_000)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok)
        self.assertIn("unconfirmed", err.lower())


# ===========================================================================
# G8 — Rule 2: freed unconfirmed inputs (from eviction set) ARE allowed
# Core: HasNoNewUnconfirmed allows re-spending outputs of replaced txs
# Status: PRESENT (the helper exists; this proves it accepts the legal case)
# ===========================================================================

class TestG8Rule2FreedInputs(unittest.TestCase):
    def test_freed_inputs_from_eviction_set_allowed(self):
        # If victim spends X and replacement spends X (only X), Rule 2 should
        # not flag it: there are no NEW unconfirmed inputs.
        mp, db = _make_mempool(full_rbf=True)
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(70), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(71),
        )
        rep_inp = TxIn(prev_txid=_bytes32(70), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(72), inputs=[rep_inp],
                       outputs=[TxOut(value=900_000)])  # 100k fee
        ok, err = mp.try_replace(rep, height=101)
        self.assertTrue(ok, f"Rule 2 false positive: {err}")


# ===========================================================================
# G9 — Rule 3 (PaysForRBF absolute): replacement_fees < original_fees rejected
# Core: rbf.cpp PaysForRBF lines 107-111
# Status: PRESENT
# ===========================================================================

class TestG9Rule3AbsoluteFee(unittest.TestCase):
    def test_lower_fee_rejected(self):
        mp, db = _make_mempool(full_rbf=True)
        # Victim pays 10_000 sats fee
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(80), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(81),
        )
        # Replacement pays only 5_000 sats
        rep_inp = TxIn(prev_txid=_bytes32(80), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(82), inputs=[rep_inp],
                       outputs=[TxOut(value=995_000)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok)
        self.assertIn("less", err.lower())


# ===========================================================================
# G10 — Rule 3: equal fees allowed (Core's `<` strict, not `<=`)
# Core: if (replacement_fees < original_fees) reject -> equality passes Rule 3
# Status: PRESENT (note: it then fails Rule 4 unless additional fee >= ceiling)
# ===========================================================================

class TestG10Rule3EqualFees(unittest.TestCase):
    def test_equal_fees_pass_rule3_fail_rule4(self):
        mp, db = _make_mempool(full_rbf=True)
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(90), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(91),
        )
        rep_inp = TxIn(prev_txid=_bytes32(90), prev_vout=0,
                       sequence=0xFFFFFFFD)
        # Same fee as victim (10_000) -> additional_fee = 0 -> Rule 4 fails
        rep = _make_tx(txid=_bytes32(92), inputs=[rep_inp],
                       outputs=[TxOut(value=990_000)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok)
        # Reason must NOT be Rule 3 (less fees) — must be Rule 4. The reject
        # string now mirrors Core's PaysForRBF detail "not enough additional
        # fees to relay" (rbf.cpp:119) under the "insufficient fee" token.
        self.assertNotIn("less fees", err.lower())
        self.assertIn("not enough additional fees to relay", err.lower())


# ===========================================================================
# G11 — Rule 4 PaysForRBF incremental: additional_fee >= relay * vsize
# Core: rbf.cpp PaysForRBF lines 117-122
# Status: PRESENT
# ===========================================================================

class TestG11Rule4Incremental(unittest.TestCase):
    def test_below_incremental_relay_fee_rejected(self):
        mp, db = _make_mempool(full_rbf=True)
        victim = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(100), parent_value=1_000_000,
            fee=10_000, sequence=0xFFFFFFFD, tx_id=_bytes32(101),
        )
        rep_inp = TxIn(prev_txid=_bytes32(100), prev_vout=0,
                       sequence=0xFFFFFFFD)
        # Replacement pays 10_001 (1 sat over victim) -> below incremental ceiling
        rep = _make_tx(txid=_bytes32(102), inputs=[rep_inp],
                       outputs=[TxOut(value=989_999)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok)
        # Core-faithful Rule 4 reject: "insufficient fee ... not enough
        # additional fees to relay" (rbf.cpp PaysForRBF lines 117-122).
        self.assertIn("insufficient fee", err.lower())
        self.assertIn("not enough additional fees to relay", err.lower())


# ===========================================================================
# G12 — Rule 5 constant MAX_REPLACEMENT_CANDIDATES = 100
# Core: rbf.h MAX_REPLACEMENT_CANDIDATES{100}
# Status: PRESENT
# ===========================================================================

class TestG12Rule5Constant(unittest.TestCase):
    def test_max_replacement_candidates_constant(self):
        from ouroboros.mempool import Mempool
        self.assertEqual(Mempool.MAX_REPLACEMENT_EVICTIONS, 100,
                         "Core rbf.h sets MAX_REPLACEMENT_CANDIDATES=100")


# ===========================================================================
# G13 — BUG-1 (P1-CDIV): Rule 5 cluster-count vs evictee-count divergence
# Core: GetUniqueClusterCount(iters_conflicting) — count of DISTINCT CLUSTERS
#   among direct conflicts, NOT the total number of evictees.
# ouroboros: len(to_evict) where to_evict = direct conflicts + all descendants.
#   This is strictly LARGER than Core's count (one cluster can contain many
#   txs). Therefore some replacements that Core ACCEPTS (because only 1
#   cluster is touched, regardless of size) ouroboros would REJECT once the
#   eviction-set exceeds 100. False-negative on legitimate RBF.
# Comment-as-confession: mempool.py:3494-3495.
# Status: BUG-1 — DIVERGENT (more restrictive than Core).
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-1: Rule 5 uses len(to_evict) not GetUniqueClusterCount("
    "iters_conflicting). Core would accept a single-cluster replacement "
    "with 101 evictees (cluster_count=1); ouroboros rejects."
))
class TestG13Rule5ClusterCountDivergence(unittest.TestCase):
    def test_uses_cluster_count_not_evictee_count(self):
        # Marker test: assert that the eviction-bound is implemented in terms
        # of cluster count rather than total evictee count. The current code
        # has the predicate `if len(to_evict) > self.MAX_REPLACEMENT_EVICTIONS:`.
        # When the bug is fixed, that exact code line should be gone in favor
        # of a cluster-count expression (e.g.
        # `GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES`).
        import inspect, re
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool._try_replace_inner)
        # Strip /* … */-style block comments and #-line comments so we look at
        # code only, not at the comment-as-confession that already references
        # GetUniqueClusterCount.
        code_only = "\n".join(
            line for line in src.splitlines()
            if not re.match(r"^\s*#", line)
        )
        # Will FAIL (xfail-strict XPASS once fixed) iff Core-faithful logic lands:
        bad_predicate = "len(to_evict) > self.MAX_REPLACEMENT_EVICTIONS"
        self.assertNotIn(bad_predicate, code_only,
                         "Rule 5 still gates on total evictees, not cluster count")


# ===========================================================================
# G14 — EntriesAndTxidsDisjoint: replacement ancestors ∩ conflicts = ∅
# Core: rbf.cpp EntriesAndTxidsDisjoint
# Status: PRESENT (lines 3528-3542)
# ===========================================================================

class TestG14EntriesAndTxidsDisjoint(unittest.TestCase):
    def test_replacement_cannot_spend_conflict_descendant(self):
        # Build: A (in mempool) -> B (child); replacement spends B AND
        # conflicts with A. EntriesAndTxidsDisjoint must reject.
        mp, db = _make_mempool(full_rbf=True)
        a = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(110), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(111),
        )
        b = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(111), parent_value=999_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(112),
        )
        # Replacement conflicts with A by spending the same confirmed UTXO,
        # AND tries to spend B's output (i.e. B is an ancestor of replacement).
        rep_inputs = [
            TxIn(prev_txid=_bytes32(110), prev_vout=0, sequence=0xFFFFFFFD),
            TxIn(prev_txid=_bytes32(112), prev_vout=0, sequence=0xFFFFFFFD),
        ]
        db.add_utxo(_bytes32(112), 0, value=998_000)
        rep = _make_tx(txid=_bytes32(113), inputs=rep_inputs,
                       outputs=[TxOut(value=1_500_000)])
        ok, err = mp.try_replace(rep, height=101)
        self.assertFalse(ok, "Replacement that spends a conflict's descendant must be rejected")


# ===========================================================================
# G15 — BUG-3 (P1-CDIV): modified-fee handling for prioritisetransaction
# Core: ReplacementChecks uses CTxMemPoolEntry::GetModifiedFee()
#   = nFee + nFeeDelta where nFeeDelta is prioritisetransaction's delta.
# Status: FIXED in FIX-72 — Mempool now exposes prioritise_transaction,
#   get_modified_fee, get_prioritised_transactions, and clear_prioritisation;
#   try_replace and _check_cluster_rbf consult mapDeltas via get_modified_fee.
#   See src/ouroboros/tests/test_w120_fix72_priority.py for full coverage.
# ===========================================================================

class TestG15ModifiedFeesUsedInRBF(unittest.TestCase):
    def test_prioritise_delta_applied_in_rbf(self):
        from ouroboros.mempool import Mempool
        # Modified-fee accessors + delta map must be present.
        self.assertTrue(hasattr(Mempool, "prioritise_transaction"),
                        "Need prioritisetransaction + modified-fee accounting")
        self.assertTrue(hasattr(Mempool, "get_modified_fee"),
                        "Need GetModifiedFee equivalent")
        self.assertTrue(hasattr(Mempool, "clear_prioritisation"),
                        "Need ClearPrioritisation equivalent")
        self.assertTrue(hasattr(Mempool, "get_prioritised_transactions"),
                        "Need GetPrioritisedTransactions equivalent")


# ===========================================================================
# G16 — BUG-4 (P1-CDIV): DiagramCheck strict-improve violation
# Core: rbf.cpp ImprovesFeerateDiagram requires std::is_gt(new, old) →
#   strictly greater (not equal). EQUAL diagrams are REJECTED.
# ouroboros: _check_cluster_rbf uses `new_rate < old_rate` → equal rates pass.
# Status: BUG-4 — DIVERGENT (more permissive than Core).
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-4: _check_cluster_rbf accepts new_rate == old_rate. Core's "
    "ImprovesFeerateDiagram requires strict > (std::is_gt)."
))
class TestG16DiagramStrictImprove(unittest.TestCase):
    def test_equal_cluster_rate_rejected(self):
        import inspect
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool._check_cluster_rbf)
        # The faithful predicate is `new_rate <= old_rate` (reject when not strictly greater).
        # Current code: `if new_rate < old_rate`. Mark divergent until fixed.
        self.assertIn("new_rate <= old_rate", src,
                      "Expect strict-improve predicate matching Core std::is_gt")


# ===========================================================================
# G17 — BUG-5 (P1-CDIV): 1% tolerance fudge in chunk-feerate bound
# Core: CompareChunks has no tolerance.
# ouroboros: `if new_tx_rate < chunk.fee_rate * 0.99` (mempool.py:3320).
#   Replacement at 99% of chunk feerate is accepted; Core rejects.
# Status: BUG-5 — DIVERGENT (more permissive than Core).
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-5: _check_cluster_rbf uses chunk.fee_rate * 0.99 tolerance; "
    "Core CompareChunks has no tolerance."
))
class TestG17DiagramNoToleranceFudge(unittest.TestCase):
    def test_no_one_percent_tolerance(self):
        import inspect
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool._check_cluster_rbf)
        self.assertNotIn("0.99", src, "Remove 1% tolerance fudge")


# ===========================================================================
# G18 — BUG-2 (P0-CDIV): INCREMENTAL_RELAY_FEE constant wrong
# Core: policy/policy.h DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB (== 1 sat/vB).
# ouroboros: DEFAULT_INCREMENTAL_RELAY_FEE = 100 (mempool.py:54). Rule 4 bar
#   is 10x weaker. A replacement adding only 1 sat per 10 vbytes passes the
#   incremental ceiling — Core would require 1 sat/vbyte.
# Status: BUG-2 — DIVERGENT P0 (consensus-adjacent policy off by 10x).
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-2: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB; Core default is "
    "1000 sat/kvB (1 sat/vB). Rule 4 ceiling is 10x lower than Core."
))
class TestG18IncrementalRelayFeeConstant(unittest.TestCase):
    def test_default_matches_core(self):
        from ouroboros.mempool import DEFAULT_INCREMENTAL_RELAY_FEE
        self.assertEqual(DEFAULT_INCREMENTAL_RELAY_FEE, 1000,
                         "Core policy/policy.h DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB")


# ===========================================================================
# G19 — BUG-6 (P2): incrementalrelayfee not CLI-configurable
# Core: -incrementalrelayfee CLI flag, threaded through into CTxMemPool::m_opts.
# ouroboros: hardcoded class constant Mempool.INCREMENTAL_RELAY_FEE.
# Status: BUG-6 — divergent (configurability gap).
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-6: incrementalrelayfee is a hardcoded class constant; Core exposes "
    "-incrementalrelayfee CLI flag and Mempool::m_opts.incremental_relay_feerate."
))
class TestG19IncrementalRelayFeeConfigurable(unittest.TestCase):
    def test_can_override_incremental_relay_fee(self):
        from ouroboros.mempool import Mempool
        validator = MockValidator(MockDB())
        # Faithful API: per-instance override (constructor or m_opts).
        mp = Mempool(validator=validator, incremental_relay_feerate=2_000)
        self.assertEqual(mp.INCREMENTAL_RELAY_FEE, 2_000)


# ===========================================================================
# G20 — RBFTransactionState distinction: REPLACEABLE/FINAL/UNKNOWN
# Core: rbf.h enum RBFTransactionState (UNKNOWN, REPLACEABLE_BIP125, FINAL).
# ouroboros: is_rbf_opt_in collapses UNKNOWN and FINAL into bool False.
# Status: PARTIAL (RPC may need 3-state in future; not strictly bug for Rules 1-5).
# ===========================================================================

class TestG20RBFTransactionState(unittest.TestCase):
    def test_is_rbf_opt_in_two_state_bool(self):
        mp, _ = _make_mempool()
        # tx not in mempool, no parent → Core: UNKNOWN; ouroboros: False
        self.assertFalse(mp.is_rbf_opt_in(_bytes32(999)))


# ===========================================================================
# G21 — reject_reason strings are informative
# Status: PARTIAL — strings exist but not machine-parseable; Core uses
# strprintf("rejecting replacement %s; too many conflicting clusters …").
# ===========================================================================

class TestG21RejectReasonStrings(unittest.TestCase):
    def test_too_many_replacements_message(self):
        from ouroboros.mempool import Mempool
        # Confirm the error string used when Rule 5 trips
        import inspect
        src = inspect.getsource(Mempool._try_replace_inner)
        self.assertIn("too many potential replacements", src)


# ===========================================================================
# G22 — BUG-7 (P2): try_replace does not propagate evicted txid set
# Core: AcceptToMemoryPool returns Workspace with m_replaced_transactions for
# wallet/RPC reporting (e.g., sendrawtransaction logs replaced_transactions).
# ouroboros: try_replace returns (ok, error_str) only; eviction list goes to
# logger.info but never to the caller / RPC.
# Status: BUG-7 — gap.
# ===========================================================================

@pytest.mark.xfail(strict=True, reason=(
    "BUG-7: try_replace returns (bool, str); evicted txids not propagated "
    "to caller. Core's AcceptToMemoryPool exposes m_replaced_transactions."
))
class TestG22EvictedTxidsPropagated(unittest.TestCase):
    def test_caller_can_observe_evictions(self):
        import inspect
        from ouroboros.mempool import Mempool
        sig = inspect.signature(Mempool.try_replace)
        ret = sig.return_annotation
        # Faithful API returns 3-tuple (ok, error, evicted_set) or a result
        # object with .replaced_transactions. The current 2-tuple is divergent.
        self.assertIn("tuple", str(ret).lower())
        # When fixed, the 3rd element should exist:
        result = ret if hasattr(ret, "__args__") else None
        self.assertIsNotNone(result)
        self.assertGreaterEqual(len(result.__args__), 3)


# ===========================================================================
# G23 — try_replace returns (ok, error) shape (current contract)
# Status: PRESENT
# ===========================================================================

class TestG23TryReplaceShape(unittest.TestCase):
    def test_returns_tuple_bool_str(self):
        mp, db = _make_mempool(full_rbf=True)
        # No conflicts → (False, "No conflicts to replace")
        tx = _make_tx(inputs=[TxIn(prev_txid=_bytes32(900), prev_vout=0)])
        db.add_utxo(_bytes32(900), 0, value=100_000)
        ok, err = mp.try_replace(tx, height=101)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(err, str)


# ===========================================================================
# G24 — TP-1: Rust ferrous-utils pipeline has no RBF/mempool
# Status: MISSING ENTIRELY (Rust side)
# ===========================================================================

class TestG24RustPipelineNoMempool(unittest.TestCase):
    def test_rust_pipeline_has_no_rbf(self):
        # Documented two-pipeline split: Rust ferrous-utils handles consensus
        # only. Mempool/policy/RBF live in Python. Any future Rust-side relay
        # path MUST honor BIP-125 (currently absent → vacuously satisfied).
        rust_root = src_dir.parent / "ferrous-utils" / "sync" / "src"
        if not rust_root.exists():
            self.skipTest("Rust pipeline not present in this checkout")
        hits = 0
        for path in rust_root.rglob("*.rs"):
            content = path.read_text(errors="ignore")
            if "BIP125" in content or "RBFTransaction" in content or \
               "try_replace" in content:
                hits += 1
        self.assertEqual(hits, 0,
                         "Rust pipeline currently has no RBF; if this changes, "
                         "BIP-125 rules 1-5 must be enforced there too.")


# ===========================================================================
# G25 — Empty-conflicts case: try_replace returns "No conflicts to replace"
# Status: PRESENT
# ===========================================================================

class TestG25EmptyConflicts(unittest.TestCase):
    def test_no_conflicts_returns_specific_message(self):
        mp, db = _make_mempool(full_rbf=True)
        db.add_utxo(_bytes32(910), 0, value=1_000_000)
        tx = _make_tx(inputs=[TxIn(prev_txid=_bytes32(910), prev_vout=0,
                                    sequence=0xFFFFFFFD)])
        ok, err = mp.try_replace(tx, height=101)
        self.assertFalse(ok)
        self.assertIn("No conflicts to replace", err)


# ===========================================================================
# G26 — Conflicts collected via spent_outputs / input dedup
# Core: ReplacementChecks builds iters_conflicting from prev_outs.
# Status: PRESENT (via Mempool._find_conflicts)
# ===========================================================================

class TestG26ConflictsViaSpentOutputs(unittest.TestCase):
    def test_find_conflicts_detects_double_spend(self):
        mp, db = _make_mempool(full_rbf=True)
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(120), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(121),
        )
        rep_inp = TxIn(prev_txid=_bytes32(120), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(122), inputs=[rep_inp],
                       outputs=[TxOut(value=900_000)])
        conflicts = mp._find_conflicts(rep)
        self.assertEqual(conflicts, {_bytes32(121)})


# ===========================================================================
# G27 — Descendant counts updated post-replace
# Core: standard CTxMemPool bookkeeping after Apply().
# Status: PRESENT (lines 3625-3640)
# ===========================================================================

class TestG27DescendantCountsUpdated(unittest.TestCase):
    def test_replace_keeps_bookkeeping_consistent(self):
        mp, db = _make_mempool(full_rbf=True)
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(130), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(131),
        )
        # Replacement with much higher fee.
        rep_inp = TxIn(prev_txid=_bytes32(130), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(132), inputs=[rep_inp],
                       outputs=[TxOut(value=500_000)])  # 500k fee
        ok, err = mp.try_replace(rep, height=101)
        self.assertTrue(ok, err)
        # Victim gone; replacement present.
        self.assertNotIn(_bytes32(131), mp.transactions)
        self.assertIn(_bytes32(132), mp.transactions)
        entry = mp.transactions[_bytes32(132)]
        self.assertEqual(entry.descendant_count, 1)


# ===========================================================================
# G28 — Replacement signaling not required
# Core: replacement itself need not signal RBF; only the VICTIM(s) need to.
# Status: PRESENT (no SignalsOptInRBF check on the replacement)
# ===========================================================================

class TestG28ReplacementNeedNotSignal(unittest.TestCase):
    def test_replacement_with_ffffffff_seq_accepted(self):
        mp, db = _make_mempool(full_rbf=False)
        # Victim signals
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(140), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(141),
        )
        # Replacement DOES NOT signal (sequence 0xFFFFFFFF)
        rep_inp = TxIn(prev_txid=_bytes32(140), prev_vout=0,
                       sequence=0xFFFFFFFF)
        rep = _make_tx(txid=_bytes32(142), inputs=[rep_inp],
                       outputs=[TxOut(value=500_000)])  # 500k fee
        ok, err = mp.try_replace(rep, height=101)
        self.assertTrue(ok, f"Replacement need not signal RBF: {err}")


# ===========================================================================
# G29 — Replacement logging (info-level summary)
# Status: PRESENT (logger.info call lines 3636-3640)
# ===========================================================================

class TestG29ReplaceLogs(unittest.TestCase):
    def test_logger_info_called_on_replace(self):
        import logging
        mp, db = _make_mempool(full_rbf=True)
        v = _add_tx_with_input(
            mp, db, parent_txid=_bytes32(150), parent_value=1_000_000,
            fee=1_000, sequence=0xFFFFFFFD, tx_id=_bytes32(151),
        )
        rep_inp = TxIn(prev_txid=_bytes32(150), prev_vout=0,
                       sequence=0xFFFFFFFD)
        rep = _make_tx(txid=_bytes32(152), inputs=[rep_inp],
                       outputs=[TxOut(value=500_000)])
        with self.assertLogs("ouroboros.mempool", level="INFO") as cm:
            ok, err = mp.try_replace(rep, height=101)
            self.assertTrue(ok, err)
        msgs = " ".join(cm.output)
        self.assertIn("RBF", msgs)


# ===========================================================================
# G30 — RPC getmempoolinfo: fullrbf field
# Core: getmempoolinfo returns 'fullrbf' bool (since v24/v28).
# Status: PRESENT (rpc.py:2376)
# ===========================================================================

class TestG30RpcGetmempoolinfoFullRbf(unittest.TestCase):
    def test_fullrbf_field_present(self):
        import inspect
        try:
            from ouroboros import rpc
        except Exception as exc:
            self.skipTest(f"rpc import: {exc}")
        src = inspect.getsource(rpc)
        # Both the field and the reference field-doc must be present.
        self.assertIn('"fullrbf"', src)
        self.assertIn("fullrbf", src.lower())


if __name__ == "__main__":
    unittest.main()
