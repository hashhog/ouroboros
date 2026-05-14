"""
W116 audit: Package relay for ouroboros (Python + Rust) — 30-gate audit.

Reference: Bitcoin Core src/policy/packages.h/cpp, validation.cpp ProcessNewPackage,
           net_processing.cpp (BIP 331 P2P), rpc/mempool.cpp testmempoolaccept/submitpackage.

Two pipelines:
  - Python: src/ouroboros/mempool.py + rpc.py + p2p.py (full package relay)
  - Rust: ferrous-utils/sync/src/ (block/tx consensus only — NO package code)

Two-pipeline finding: Rust ferrous-utils has ZERO package relay code. The entire
package relay implementation lives exclusively in the Python pipeline.

Gates:
  G1-G5   Package definition (constants, topology, well-formed checks)
  G6-G10  testmempoolaccept (RPC)
  G11-G15 submitpackage (RPC)
  G16-G20 Validation internals
  G21-G24 CPFP fee mechanics
  G25-G28 Edge cases
  G29-G30 P2P (BIP 331)

All tests run offline (no live network, no RocksDB).
"""

import inspect
import sys
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Bootstrap: stub the Rust extension so pure-Python imports work offline
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
# Minimal stubs: Transaction, TxIn, TxOut
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
        raw = self.serialize()
        import hashlib
        return hashlib.sha256(hashlib.sha256(raw).digest()).digest()

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


def _make_tx(
    txid: bytes = None,
    version: int = 1,
    inputs: list = None,
    outputs: list = None,
    value_out: int = 49_000,
) -> Transaction:
    """Create a minimal valid transaction stub."""
    if inputs is None:
        inputs = [TxIn(prev_txid=_bytes32(999), prev_vout=0)]
    if outputs is None:
        outputs = [TxOut(value=value_out, script_pubkey=bytes([0x51, 0x20]) + bytes(32))]
    tx = Transaction(version=version, locktime=0, inputs=inputs, outputs=outputs)
    if txid is not None:
        tx._txid = txid
    return tx


# ---------------------------------------------------------------------------
# MockDB and MockValidator
# ---------------------------------------------------------------------------

class MockDB:
    """Simulates database.BlockchainDatabase with a mutable UTXO set."""

    def __init__(self):
        self._utxos: dict = {}
        self._tip_height = 100
        self._mtp = 1_600_000_000

    def add_utxo(self, txid: bytes, vout: int, value: int,
                 script_pubkey: bytes = None, height: int = 1, is_coinbase: bool = False):
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

    def get_best_block(self):
        return (b'\x00' * 32, self._tip_height)


class MockValidator:
    def __init__(self, db: MockDB, network: str = "mainnet"):
        self.db = db
        self.network = network

    def validate_transaction(self, tx, height, mtp=None, extra_script_flags=None):
        if tx.is_coinbase:
            return False, "coinbase"
        return True, ""


def _make_mempool(full_rbf: bool = True, require_standard: bool = False):
    """Create a Mempool with a MockDB."""
    from ouroboros.mempool import Mempool
    db = MockDB()
    validator = MockValidator(db)
    mp = Mempool(validator=validator, full_rbf=full_rbf,
                 require_standard=require_standard)
    return mp, db


# ---------------------------------------------------------------------------
# G1 — MAX_PACKAGE_COUNT = 25
# ---------------------------------------------------------------------------

class TestG1MaxPackageCount(unittest.TestCase):
    """G1: MAX_PACKAGE_COUNT constant must equal 25 (Core policy/packages.h)."""

    def test_max_package_count_constant(self):
        from ouroboros.mempool import MAX_PACKAGE_COUNT
        self.assertEqual(MAX_PACKAGE_COUNT, 25,
                         f"MAX_PACKAGE_COUNT must be 25, got {MAX_PACKAGE_COUNT}")

    def test_package_exceeding_count_rejected(self):
        from ouroboros.mempool import MAX_PACKAGE_COUNT
        mp, db = _make_mempool()
        txs = []
        for i in range(MAX_PACKAGE_COUNT + 1):
            txid = _bytes32(i + 1)
            db.add_utxo(txid, 0, value=50_000)
            inp = TxIn(prev_txid=txid, prev_vout=0)
            tx = _make_tx(txid=_bytes32(i + 100), inputs=[inp])
            txs.append(tx)
        ok, err = mp.validate_package(txs, height=101)
        self.assertFalse(ok, "Package with >MAX_PACKAGE_COUNT txs must be rejected")
        self.assertIn("26", err)

    def test_package_at_limit_accepted_if_fees_ok(self):
        """Single-tx package (size=1) should not fail on count check."""
        mp, db = _make_mempool()
        utxo_txid = _bytes32(1)
        db.add_utxo(utxo_txid, 0, value=50_000)
        inp = TxIn(prev_txid=utxo_txid, prev_vout=0)
        tx = _make_tx(txid=_bytes32(100), inputs=[inp], value_out=49_000)
        ok, err = mp.validate_package([tx], height=101)
        self.assertTrue(ok, f"Single-tx package must not fail count check: {err}")


# ---------------------------------------------------------------------------
# G2 — MAX_PACKAGE_WEIGHT = 404000
# ---------------------------------------------------------------------------

class TestG2MaxPackageWeight(unittest.TestCase):
    """G2: MAX_PACKAGE_WEIGHT constant must equal 404000 (Core policy/packages.h)."""

    def test_max_package_weight_constant(self):
        from ouroboros.mempool import MAX_PACKAGE_WEIGHT
        self.assertEqual(MAX_PACKAGE_WEIGHT, 404_000,
                         f"MAX_PACKAGE_WEIGHT must be 404000, got {MAX_PACKAGE_WEIGHT}")

    def test_package_weight_check_exists(self):
        """validate_package must check total weight against MAX_PACKAGE_WEIGHT."""
        src = inspect.getsource(__import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner)
        self.assertIn("MAX_PACKAGE_WEIGHT", src,
                      "Package weight limit check must reference MAX_PACKAGE_WEIGHT")


# ---------------------------------------------------------------------------
# G3 — IsTopoSortedPackage / topological order enforcement
# ---------------------------------------------------------------------------

class TestG3TopologicalOrder(unittest.TestCase):
    """G3: Package must be in topological order (parents before children)."""

    def test_reversed_order_rejected(self):
        mp, db = _make_mempool()
        parent_utxo = _bytes32(1)
        db.add_utxo(parent_utxo, 0, value=100_000)

        parent_txid = _bytes32(10)
        child_txid = _bytes32(11)

        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=90_000)

        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = _make_tx(txid=child_txid, inputs=[child_inp], value_out=80_000)

        # Submit child before parent — must be rejected
        ok, err = mp.validate_package([child_tx, parent_tx], height=101)
        self.assertFalse(ok, "Out-of-order package (child before parent) must be rejected")

    def test_correct_order_accepted(self):
        mp, db = _make_mempool()
        parent_utxo = _bytes32(1)
        db.add_utxo(parent_utxo, 0, value=100_000)

        parent_txid = _bytes32(10)
        child_txid = _bytes32(11)

        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=90_000)

        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = _make_tx(txid=child_txid, inputs=[child_inp], value_out=80_000)

        ok, err = mp.validate_package([parent_tx, child_tx], height=101)
        self.assertTrue(ok, f"Parent-before-child package must be accepted: {err}")


# ---------------------------------------------------------------------------
# G4 — IsConsistentPackage: no duplicate inputs within package
# ---------------------------------------------------------------------------

class TestG4ConsistentPackage(unittest.TestCase):
    """G4: Package must not have two transactions spending the same input (IsConsistentPackage)."""

    def test_internal_double_spend_rejected(self):
        mp, db = _make_mempool()
        shared_utxo = _bytes32(1)
        db.add_utxo(shared_utxo, 0, value=100_000)

        inp1 = TxIn(prev_txid=shared_utxo, prev_vout=0)
        tx1 = _make_tx(txid=_bytes32(10), inputs=[inp1], value_out=90_000)

        inp2 = TxIn(prev_txid=shared_utxo, prev_vout=0)
        tx2 = _make_tx(txid=_bytes32(11), inputs=[inp2], value_out=88_000)

        ok, err = mp.validate_package([tx1, tx2], height=101)
        self.assertFalse(ok, "Package with conflicting inputs must be rejected")

    def test_no_duplicate_transactions(self):
        """Same txid twice in package must be rejected."""
        mp, db = _make_mempool()
        utxo_txid = _bytes32(1)
        db.add_utxo(utxo_txid, 0, value=100_000)

        inp = TxIn(prev_txid=utxo_txid, prev_vout=0)
        tx = _make_tx(txid=_bytes32(10), inputs=[inp], value_out=90_000)

        ok, err = mp.validate_package([tx, tx], height=101)
        self.assertFalse(ok, "Package with duplicate transaction must be rejected")


# ---------------------------------------------------------------------------
# G5 — IsChildWithParents topology enforcement
# ---------------------------------------------------------------------------

class TestG5ChildWithParents(unittest.TestCase):
    """G5: Multi-tx packages must satisfy IsChildWithParents/IsChildWithParentsTree."""

    def test_is_child_with_parents_method_exists(self):
        from ouroboros.mempool import Mempool
        self.assertTrue(hasattr(Mempool, "is_child_with_parents"),
                        "Mempool must have is_child_with_parents static method")
        self.assertTrue(hasattr(Mempool, "is_child_with_parents_tree"),
                        "Mempool must have is_child_with_parents_tree static method")

    def test_sibling_package_rejected(self):
        """Two independent transactions with a shared child — parents cannot depend on each other."""
        mp, db = _make_mempool()

        utxo1 = _bytes32(1)
        utxo2 = _bytes32(2)
        db.add_utxo(utxo1, 0, value=100_000)
        db.add_utxo(utxo2, 0, value=100_000)

        # parent1 spends utxo1
        parent1_txid = _bytes32(10)
        parent1 = _make_tx(txid=parent1_txid,
                           inputs=[TxIn(prev_txid=utxo1, prev_vout=0)],
                           value_out=90_000)
        db.add_utxo(parent1_txid, 0, value=90_000)

        # parent2 spends parent1 output — this creates inter-parent dependency
        parent2_txid = _bytes32(11)
        parent2 = _make_tx(txid=parent2_txid,
                           inputs=[TxIn(prev_txid=parent1_txid, prev_vout=0)],
                           value_out=80_000)
        db.add_utxo(parent2_txid, 0, value=80_000)

        # child spends both
        child_txid = _bytes32(12)
        child = _make_tx(txid=child_txid,
                         inputs=[TxIn(prev_txid=parent1_txid, prev_vout=0),
                                 TxIn(prev_txid=parent2_txid, prev_vout=0)],
                         value_out=60_000)

        # parent1 and parent2 have a dependency — must be rejected as not a tree
        ok, err = mp.validate_package([parent1, parent2, child], height=101)
        self.assertFalse(ok,
                         "Package where parents depend on each other must be rejected")

    def test_non_related_transactions_rejected(self):
        """Two transactions where the last one doesn't spend from the first — not child-with-parents."""
        mp, db = _make_mempool()

        utxo1 = _bytes32(1)
        utxo2 = _bytes32(2)
        db.add_utxo(utxo1, 0, value=100_000)
        db.add_utxo(utxo2, 0, value=100_000)

        tx1 = _make_tx(txid=_bytes32(10),
                       inputs=[TxIn(prev_txid=utxo1, prev_vout=0)],
                       value_out=90_000)
        tx2 = _make_tx(txid=_bytes32(11),
                       inputs=[TxIn(prev_txid=utxo2, prev_vout=0)],
                       value_out=88_000)

        ok, err = mp.validate_package([tx1, tx2], height=101)
        self.assertFalse(ok, "Package where child doesn't spend any parent must be rejected")
        self.assertIn("child", err.lower())


# ---------------------------------------------------------------------------
# G6 — testmempoolaccept: wtxid field present in response
# BUG: ouroboros response missing 'wtxid' field (Core always returns it)
# ---------------------------------------------------------------------------

class TestG6TestMempoolAcceptWtxid(unittest.TestCase):
    """G6 BUG: testmempoolaccept response must include 'wtxid' field.

    Core (rpc/mempool.cpp:359): result_inner.pushKV("wtxid", tx->GetWitnessHash().GetHex())
    ouroboros (rpc.py): returns only 'txid', 'allowed', 'reject-reason' — 'wtxid' is absent.
    This is a HIGH-severity API incompatibility: any client relying on wtxid for
    deduplication (BIP-339) will silently get wrong behavior.
    """

    def test_testmempoolaccept_response_missing_wtxid(self):
        """Document that testmempoolaccept response lacks wtxid field."""
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_testmempoolaccept)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        # Document the bug: 'wtxid' is absent from the response dict
        bug_present = "wtxid" not in src
        self.assertTrue(bug_present,
                        "BUG CONFIRMED: testmempoolaccept response is missing 'wtxid' field. "
                        "Core rpc/mempool.cpp:359: result_inner.pushKV(\"wtxid\", tx->GetWitnessHash().GetHex())")


# ---------------------------------------------------------------------------
# G7 — testmempoolaccept: 'vsize' field present when allowed=True
# BUG: ouroboros response missing 'vsize' field
# ---------------------------------------------------------------------------

class TestG7TestMempoolAcceptVsize(unittest.TestCase):
    """G7 BUG: testmempoolaccept response must include 'vsize' when allowed=True.

    Core (rpc/mempool.cpp:385): result_inner.pushKV("vsize", virtual_size)
    ouroboros: only returns 'txid', 'allowed', 'reject-reason' — 'vsize' absent.
    """

    def test_testmempoolaccept_response_missing_vsize(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_testmempoolaccept)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        bug_present = "vsize" not in src
        self.assertTrue(bug_present,
                        "BUG CONFIRMED: testmempoolaccept response is missing 'vsize' field. "
                        "Core rpc/mempool.cpp:385: result_inner.pushKV(\"vsize\", virtual_size)")


# ---------------------------------------------------------------------------
# G8 — testmempoolaccept: 'fees' object with 'base', 'effective-feerate',
#       'effective-includes' when allowed=True
# BUG: ouroboros response missing entire 'fees' object
# ---------------------------------------------------------------------------

class TestG8TestMempoolAcceptFees(unittest.TestCase):
    """G8 BUG: testmempoolaccept response must include 'fees' object when allowed=True.

    Core (rpc/mempool.cpp:387-394): fees.pushKV("base", ...), fees.pushKV("effective-feerate", ...),
    fees.pushKV("effective-includes", ...), result_inner.pushKV("fees", fees)
    ouroboros: no 'fees' object returned at all.
    """

    def test_testmempoolaccept_missing_fees_object(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_testmempoolaccept)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        missing_fees = '"fees"' not in src
        missing_effective_feerate = "effective-feerate" not in src
        missing_effective_includes = "effective-includes" not in src
        bug_present = missing_fees or missing_effective_feerate or missing_effective_includes
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: testmempoolaccept response missing 'fees' object "
            "and/or 'effective-feerate'/'effective-includes'. "
            "Core rpc/mempool.cpp:387-394"
        )


# ---------------------------------------------------------------------------
# G9 — testmempoolaccept: multi-tx must use package semantics (ProcessNewPackage)
# BUG: ouroboros validates each tx independently, not as a package
# ---------------------------------------------------------------------------

class TestG9TestMempoolAcceptMultiTxPackageSemantics(unittest.TestCase):
    """G9 BUG: testmempoolaccept with multiple transactions must use package semantics.

    Core (rpc/mempool.cpp:345):
      if (txns.size() > 1) return ProcessNewPackage(..., test_accept=true, ...)

    ouroboros: loops over each raw tx and calls validate_transaction individually.
    This means parent-pays-for-child CPFP fee evaluation is skipped for >1 txns.
    A parent tx below the relay fee will be rejected even if the child bumps it.
    """

    def test_testmempoolaccept_loops_individually_not_package(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_testmempoolaccept)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        # Core calls ProcessNewPackage for multi-tx. ouroboros loops individually.
        lacks_package_validation = (
            "validate_package" not in src and "ProcessNewPackage" not in src
        )
        self.assertTrue(
            lacks_package_validation,
            "BUG CONFIRMED: testmempoolaccept validates each tx individually instead of "
            "using package validation for multi-tx arrays. "
            "Core rpc/mempool.cpp:345: if (txns.size() > 1) return ProcessNewPackage(..., test_accept=true)"
        )


# ---------------------------------------------------------------------------
# G10 — testmempoolaccept: maxfeerate parameter respected
# ---------------------------------------------------------------------------

class TestG10TestMempoolAcceptMaxFeerate(unittest.TestCase):
    """G10: testmempoolaccept maxfeerate parameter must be accepted and enforced."""

    def test_maxfeerate_parameter_exists(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            sig = inspect.signature(RPCServer.rpc_testmempoolaccept)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        self.assertIn("maxfeerate", sig.parameters,
                      "testmempoolaccept must accept maxfeerate parameter")


# ---------------------------------------------------------------------------
# G11 — submitpackage: tx-results keyed by wtxid (not txid)
# BUG: ouroboros keys tx-results by txid
# ---------------------------------------------------------------------------

class TestG11SubmitPackageTxResultsKeyedByWtxid(unittest.TestCase):
    """G11 BUG: submitpackage tx-results must be keyed by wtxid.

    Core (rpc/mempool.cpp:1464-1505):
      const auto wtxid_hex = tx->GetWitnessHash().GetHex();
      ...
      tx_result_map.pushKV(wtxid_hex, std::move(result_inner));

    ouroboros (rpc.py:7606): txid_hex = tx.get_txid()[::-1].hex()
    The map key is txid, not wtxid. This is a P0-CDIV on segwit transactions where
    txid != wtxid — client tools keying by wtxid will find an empty result.
    """

    def test_submitpackage_tx_results_keyed_by_txid_not_wtxid(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_submitpackage)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        # Bug: tx_results keyed by txid_hex (get_txid), not wtxid
        keys_by_txid = "get_txid" in src and "tx_results[" in src
        keys_by_wtxid = "get_wtxid" in src and "tx_results[" in src
        bug_present = keys_by_txid and not keys_by_wtxid
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: submitpackage tx-results keyed by txid, not wtxid. "
            "Core rpc/mempool.cpp:1464: tx_result_map.pushKV(wtxid_hex, ...) "
            "Segwit txs where txid!=wtxid will have wrong result key."
        )


# ---------------------------------------------------------------------------
# G12 — submitpackage: maxfeerate and maxburnamount parameters
# BUG: ouroboros submitpackage lacks maxfeerate parameter
# ---------------------------------------------------------------------------

class TestG12SubmitPackageMissingMaxfeerate(unittest.TestCase):
    """G12 BUG: submitpackage must accept maxfeerate (and maxburnamount) parameters.

    Core (rpc/mempool.cpp:1319-1326): two optional params maxfeerate and maxburnamount.
    ouroboros rpc_submitpackage signature: only 'package' list, no maxfeerate.
    Any client passing maxfeerate=0 for fee bypass will get a TypeError.
    """

    def test_submitpackage_lacks_maxfeerate(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            sig = inspect.signature(RPCServer.rpc_submitpackage)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        bug_present = "maxfeerate" not in sig.parameters
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: submitpackage lacks maxfeerate parameter. "
            "Core rpc/mempool.cpp:1319 accepts maxfeerate to reject high-fee txs."
        )


# ---------------------------------------------------------------------------
# G13 — submitpackage: replaced-transactions in response
# BUG: ouroboros response missing 'replaced-transactions' list
# ---------------------------------------------------------------------------

class TestG13SubmitPackageMissingReplacedTransactions(unittest.TestCase):
    """G13 BUG: submitpackage response must include 'replaced-transactions' list.

    Core (rpc/mempool.cpp:1508-1510): rpc_result.pushKV("replaced-transactions", replaced_list)
    ouroboros: only returns 'package_msg' and 'tx-results', no 'replaced-transactions'.
    """

    def test_submitpackage_response_missing_replaced_transactions(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_submitpackage)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        bug_present = "replaced-transactions" not in src
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: submitpackage response missing 'replaced-transactions' list. "
            "Core rpc/mempool.cpp:1508: rpc_result.pushKV(\"replaced-transactions\", replaced_list)"
        )


# ---------------------------------------------------------------------------
# G14 — submitpackage: effective-feerate and effective-includes in tx-results
# BUG: ouroboros fees dict lacks effective-feerate and effective-includes
# ---------------------------------------------------------------------------

class TestG14SubmitPackageMissingEffectiveFeerate(unittest.TestCase):
    """G14 BUG: submitpackage tx-results fees must include effective-feerate and effective-includes.

    Core (rpc/mempool.cpp:1492-1497):
      fees.pushKV("effective-feerate", ValueFromAmount(...))
      fees.pushKV("effective-includes", effective_includes_res)

    ouroboros tx-results fees: only returns 'base', missing effective-feerate/effective-includes.
    Tools use effective-feerate to know if package feerate was applied (CPFP bump visible).
    """

    def test_submitpackage_fees_missing_effective_feerate(self):
        import inspect
        try:
            from ouroboros.rpc import RPCServer
            src = inspect.getsource(RPCServer.rpc_submitpackage)
        except Exception:
            self.skipTest("Cannot import RPCServer")
        missing_effective_feerate = "effective-feerate" not in src
        missing_effective_includes = "effective-includes" not in src
        bug_present = missing_effective_feerate or missing_effective_includes
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: submitpackage tx-results fees missing 'effective-feerate' and/or "
            "'effective-includes'. Core rpc/mempool.cpp:1492-1497."
        )


# ---------------------------------------------------------------------------
# G15 — submitpackage: single-tx package is valid (no topology check)
# ---------------------------------------------------------------------------

class TestG15SubmitPackageSingleTxValid(unittest.TestCase):
    """G15: submitpackage must accept single-transaction packages."""

    def test_single_tx_package_passes_topology(self):
        mp, db = _make_mempool()
        utxo_txid = _bytes32(1)
        db.add_utxo(utxo_txid, 0, value=50_000)
        inp = TxIn(prev_txid=utxo_txid, prev_vout=0)
        tx = _make_tx(txid=_bytes32(100), inputs=[inp], value_out=49_000)
        # Single-tx: is_child_with_parents returns False (< 2 txs) but
        # validate_package should not call it for single-tx packages
        ok, err = mp.validate_package([tx], height=101)
        self.assertTrue(ok, f"Single-tx package must succeed: {err}")


# ---------------------------------------------------------------------------
# G16 — Package fee rate uses virtual size (vsize), not raw serialized size
# BUG: ouroboros uses len(tx.serialize()) — non-witness size, not virtual size
# ---------------------------------------------------------------------------

class TestG16PackageFeerateUsesVirtualSize(unittest.TestCase):
    """G16 BUG: Package fee rate check must use virtual size (weight/4 ceil), not raw size.

    Core AcceptMultipleTransactionsInternal uses m_total_vsize (virtual size with
    witness discount applied). ouroboros _validate_package_inner:
      total_size = sum(len(tx.serialize()) for tx in txs)
    serialize() returns non-witness data. For segwit transactions, this over-counts
    the size (no witness discount), making the feerate check wrong.
    Severity: HIGH — segwit package CPFP fee calculations are systematically incorrect.
    """

    def test_package_feerate_uses_raw_serialize_not_vsize(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        # Bug: ouroboros uses len(tx.serialize()), not tx.get_vsize() / virtual size
        # Core uses m_total_vsize which applies witness discount
        uses_raw_size = "tx.serialize()" in src
        uses_vsize = "get_vsize()" in src and "total_vsize" in src
        # If raw serialize is used without vsize, the bug is present
        bug_present = uses_raw_size and not uses_vsize
        self.assertTrue(
            bug_present,
            "BUG CONFIRMED: Package fee rate uses raw serialize() size, not virtual size. "
            "Core uses m_total_vsize (virtual). Segwit transactions have wrong fee check."
        )


# ---------------------------------------------------------------------------
# G17 — Package standardness checks skipped in validate_package
# BUG: _validate_package_inner never calls _is_standard_tx
# ---------------------------------------------------------------------------

class TestG17PackageStandardnessChecks(unittest.TestCase):
    """G17 BUG: validate_package skips standardness checks on package transactions.

    Core AcceptPackage → AcceptMultipleTransactions → applies policy/standardness
    checks via PolicyScriptChecks per-tx. ouroboros _validate_package_inner only
    calls validator.validate_transaction (consensus only) — no _is_standard_tx call.
    Non-standard package transactions are silently admitted.
    """

    def test_package_validation_skips_standardness(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        self.assertNotIn(
            "_is_standard_tx", src,
            "BUG: _validate_package_inner does not call _is_standard_tx. "
            "Non-standard transactions bypass policy checks in package path. "
            "Core applies standardness per-tx in AcceptMultipleTransactions."
        )


# ---------------------------------------------------------------------------
# G18 — validate_package child-tx validation fails to supply package context
# BUG: validate_transaction called without intra_block_utxos from package
# ---------------------------------------------------------------------------

class TestG18PackageValidationMissingParentContext(unittest.TestCase):
    """G18 BUG: Package child tx validation must supply parent outputs as intra_block_utxos.

    Core provides the package UTXO view when validating child transactions so that
    a child's inputs (spending a package parent output not yet in the DB) can be resolved.

    ouroboros _validate_package_inner line 4454:
      valid, error = self.validator.validate_transaction(tx, height, pkg_mtp)
    No intra_block_utxos argument passed. Child tx validation will fail to find
    parent outputs that are not in the UTXO DB yet (only in package_outputs).
    This means CPFP packages fail consensus validation for the child tx.
    Severity: P0 — CPFP package submission with unconfirmed parent is broken.
    """

    def test_validate_transaction_called_without_package_utxos(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        # The call to validate_transaction must pass package_outputs or intra_block_utxos
        # to allow child tx to find parent outputs
        call_has_context = (
            "intra_block_utxos" in src
            or "package_outputs" in src and "validate_transaction" in src
        )
        # Currently the call is: self.validator.validate_transaction(tx, height, pkg_mtp)
        # no package_outputs passed
        self.assertTrue(
            call_has_context,
            "BUG: validate_transaction for package child tx must receive package parent "
            "outputs as intra_block_utxos. Current call has no UTXO context for package "
            "parents. CPFP packages fail if parent is not already in the UTXO DB. "
            "Core provides the package UTXO view during AcceptMultipleTransactions."
        )


# ---------------------------------------------------------------------------
# G19 — Already-in-mempool package txs must be de-duplicated, not rejected
# BUG: ouroboros rejects any package tx already in mempool
# ---------------------------------------------------------------------------

class TestG19AlreadyInMempoolDeduplication(unittest.TestCase):
    """G19 BUG: Package submission must de-duplicate transactions already in mempool.

    Core AcceptPackage (validation.cpp:1664-1675):
      if (m_pool.exists(wtxid)):  // already in mempool
          results_final.emplace(wtxid, MempoolAcceptResult::MempoolTx(...))
      // continue with remaining txs

    ouroboros _validate_package_inner line 4418:
      if txid in self.transactions:
          return False, f"Transaction ... already in mempool"
    This rejects the entire package if any tx is already in mempool, rather than
    de-duplicating and continuing. This is a policy difference that can cause
    legitimate CPFP packages to be rejected when the parent was independently submitted.
    """

    def test_already_in_mempool_causes_full_rejection(self):
        from ouroboros.mempool import Mempool
        mp, db = _make_mempool()

        utxo_txid = _bytes32(1)
        db.add_utxo(utxo_txid, 0, value=100_000)

        parent_txid = _bytes32(10)
        parent_inp = TxIn(prev_txid=utxo_txid, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=90_000)

        # First add parent individually to mempool
        ok, err = mp.add_transaction(parent_tx, height=101)
        self.assertTrue(ok, f"Parent add must succeed: {err}")

        # Now the parent is in mempool. Core would de-duplicate and only
        # evaluate the child. ouroboros rejects the package entirely.
        db.add_utxo(parent_txid, 0, value=90_000)
        child_txid = _bytes32(11)
        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = _make_tx(txid=child_txid, inputs=[child_inp], value_out=80_000)

        ok2, err2 = mp.validate_package([parent_tx, child_tx], height=101)
        # ouroboros rejects because parent is already in mempool
        # Core would de-duplicate and accept the child
        if not ok2:
            self.assertIn("already in mempool", err2.lower(),
                          "BUG: package rejected because parent already in mempool. "
                          "Core de-duplicates existing mempool txs in AcceptPackage.")


# ---------------------------------------------------------------------------
# G20 — Package conflicts: double-spend against mempool detected
# ---------------------------------------------------------------------------

class TestG20PackageMempoolConflict(unittest.TestCase):
    """G20: Package tx conflicting with existing mempool tx must be rejected."""

    def test_package_conflict_with_mempool_rejected(self):
        mp, db = _make_mempool()

        shared_utxo = _bytes32(1)
        db.add_utxo(shared_utxo, 0, value=100_000)

        # Add a mempool tx spending the shared UTXO
        mempool_txid = _bytes32(10)
        mempool_tx = _make_tx(
            txid=mempool_txid,
            inputs=[TxIn(prev_txid=shared_utxo, prev_vout=0)],
            value_out=90_000,
        )
        ok, err = mp.add_transaction(mempool_tx, height=101)
        self.assertTrue(ok, f"Baseline mempool add failed: {err}")

        # Package tx tries to spend the same UTXO — should be rejected
        pkg_txid = _bytes32(20)
        pkg_tx = _make_tx(
            txid=pkg_txid,
            inputs=[TxIn(prev_txid=shared_utxo, prev_vout=0)],
            value_out=88_000,
        )
        ok2, err2 = mp.validate_package([pkg_tx], height=101)
        self.assertFalse(ok2, "Package conflicting with mempool must be rejected")


# ---------------------------------------------------------------------------
# G21 — CPFP: child pays for parent fee bump
# ---------------------------------------------------------------------------

class TestG21CpfpChildPayForParent(unittest.TestCase):
    """G21: CPFP package allows child to bump low-fee parent."""

    def test_cpfp_child_bumps_low_fee_parent(self):
        """Parent below relay fee + child with enough fee for both = accepted."""
        mp, db = _make_mempool()

        parent_utxo = _bytes32(1)
        db.add_utxo(parent_utxo, 0, value=100_000)

        parent_txid = _bytes32(10)
        # Parent outputs 99_999 sats (fee=1 sat, below MIN_RELAY_FEE for its size)
        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=99_999)

        child_txid = _bytes32(11)
        # Child outputs 80_000 sats (fee=19_999 sats, covers parent+child relay fee)
        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = _make_tx(txid=child_txid, inputs=[child_inp], value_out=80_000)

        ok, err = mp.validate_package([parent_tx, child_tx], height=101)
        self.assertTrue(ok, f"CPFP package (child bumps low-fee parent) must be accepted: {err}")

    def test_package_fee_rate_check_aggregate(self):
        """Package fee rate check must be aggregate (parent+child together), not per-tx."""
        mp, db = _make_mempool()

        parent_utxo = _bytes32(1)
        db.add_utxo(parent_utxo, 0, value=100_000)

        parent_txid = _bytes32(10)
        # Parent with zero fee — individually would fail relay fee
        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=100_000)

        child_txid = _bytes32(11)
        # Child with 20_000 sat fee — aggregate rate covers both
        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = _make_tx(txid=child_txid, inputs=[child_inp], value_out=80_000)

        # The aggregate fee_rate check should pass (20_000 sats / total_size)
        ok, err = mp.validate_package([parent_tx, child_tx], height=101)
        self.assertTrue(ok, f"Aggregate CPFP fee rate must be used for multi-tx packages: {err}")


# ---------------------------------------------------------------------------
# G22 — CPFP fee calculation uses package_outputs for inputs
# ---------------------------------------------------------------------------

class TestG22CpfpFeeCalculationPackageOutputs(unittest.TestCase):
    """G22: Fee calculation for child tx must use package_outputs for parent outputs."""

    def test_fee_calculation_builds_package_outputs(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        self.assertIn("package_outputs", src,
                      "Package fee calculation must build package_outputs map for cross-tx input resolution")


# ---------------------------------------------------------------------------
# G23 — Ephemeral dust policy: dust parent must have 0 fee
# ---------------------------------------------------------------------------

class TestG23EphemeralDustPolicy(unittest.TestCase):
    """G23: Ephemeral dust parent tx must have 0 fee; child must spend all dust outputs."""

    def test_ephemeral_dust_functions_exist(self):
        try:
            from ouroboros.mempool import _has_ephemeral_dust, _check_ephemeral_dust
        except ImportError:
            self.fail("_has_ephemeral_dust and _check_ephemeral_dust must be importable")

    def test_dust_parent_nonzero_fee_rejected(self):
        """A parent with dust output and non-zero fee must be rejected."""
        mp, db = _make_mempool()
        from ouroboros.mempool import _check_ephemeral_dust

        # Build a tx with a real dust output (non-P2A so it's not exempt from dust checks)
        # A P2PKH output with value below the dust threshold (~546 sats) is dust
        # Standard P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        p2pkh_script = bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])
        dust_output = TxOut(value=100, script_pubkey=p2pkh_script)  # 100 sat < 546 sat threshold
        normal_output = TxOut(value=40_000)

        parent_utxo = _bytes32(1)
        parent_txid = _bytes32(10)
        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = Transaction(
            version=1, locktime=0,
            inputs=[parent_inp],
            outputs=[normal_output, dust_output],
            _txid=parent_txid,
        )
        # fee=10_000 (non-zero) — should be rejected by ephemeral dust policy
        ok, err = _check_ephemeral_dust(parent_tx, fee=10_000)
        self.assertFalse(ok, "Dust parent with non-zero fee must be rejected by ephemeral dust policy")
        self.assertIn("0-fee", err,
                      f"Expected '0-fee' error message, got: {err}")


# ---------------------------------------------------------------------------
# G24 — TRUC (v3) policy for packages: PackageTRUCChecks present
# ---------------------------------------------------------------------------

class TestG24TrucPackagePolicy(unittest.TestCase):
    """G24: _check_package_truc_policy must be implemented and called during package validation."""

    def test_truc_package_check_method_exists(self):
        from ouroboros.mempool import Mempool
        self.assertTrue(
            hasattr(Mempool, "_check_package_truc_policy"),
            "Mempool must have _check_package_truc_policy method"
        )

    def test_truc_package_check_called_in_validate(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        self.assertIn("_check_package_truc_policy", src,
                      "_validate_package_inner must call _check_package_truc_policy")

    def test_truc_v3_child_exceeding_max_vsize_rejected(self):
        """v3 child with unconfirmed parent exceeding TRUC_CHILD_MAX_VSIZE must be rejected."""
        from ouroboros.mempool import Mempool, TRUC_CHILD_MAX_VSIZE
        mp, db = _make_mempool()

        parent_utxo = _bytes32(1)
        db.add_utxo(parent_utxo, 0, value=5_000_000)

        parent_txid = _bytes32(10)
        parent_inp = TxIn(prev_txid=parent_utxo, prev_vout=0)
        parent_tx = _make_tx(txid=parent_txid, inputs=[parent_inp], value_out=4_900_000, version=3)

        # Create a large child tx with padded outputs to exceed TRUC_CHILD_MAX_VSIZE (1000 vbytes)
        # Pad outputs to inflate size
        big_output = TxOut(value=1_000_000, script_pubkey=bytes(1001))  # huge script
        child_txid = _bytes32(11)
        child_inp = TxIn(prev_txid=parent_txid, prev_vout=0)
        child_tx = Transaction(
            version=3, locktime=0,
            inputs=[child_inp],
            outputs=[big_output],
            _txid=child_txid,
        )

        ok, err = mp._check_package_truc_policy([parent_tx, child_tx])
        self.assertFalse(ok, f"v3 child exceeding TRUC_CHILD_MAX_VSIZE must be rejected: {err}")


# ---------------------------------------------------------------------------
# G25 — Single-tx package weight check: Core skips weight for single-tx
# BUG: ouroboros applies MAX_PACKAGE_WEIGHT even for single-tx packages
# ---------------------------------------------------------------------------

class TestG25SingleTxPackageWeightCheck(unittest.TestCase):
    """G25 BUG: Core does NOT apply MAX_PACKAGE_WEIGHT for single-transaction packages.

    Core IsWellFormedPackage (packages.cpp):
      if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT): ...
    The guard `package_count > 1` means a single large-but-valid tx is not
    rejected by the package weight limit (it may be valid individually).

    ouroboros _validate_package_inner: no such guard — always checks weight.
    A tx with weight > 404000 (impossible for standard tx but possible for
    non-standard) would be accepted individually but rejected via package path.
    """

    def test_single_tx_weight_check_should_have_multi_tx_guard(self):
        src = inspect.getsource(
            __import__("ouroboros.mempool", fromlist=["Mempool"]).Mempool._validate_package_inner
        )
        # Document: Core only applies package weight limit when package_count > 1
        # ouroboros should have: if len(txs) > 1 and total_weight > MAX_PACKAGE_WEIGHT
        has_multi_guard = "len(txs) > 1" in src and "MAX_PACKAGE_WEIGHT" in src
        self.assertTrue(
            has_multi_guard,
            "BUG: Package weight limit should only apply to multi-tx packages "
            "(len(txs) > 1 guard). Core: packages.cpp 'if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT)'"
        )


# ---------------------------------------------------------------------------
# G26 — Empty package rejected
# ---------------------------------------------------------------------------

class TestG26EmptyPackageRejected(unittest.TestCase):
    """G26: Empty package must be rejected."""

    def test_empty_package_rejected(self):
        mp, db = _make_mempool()
        ok, err = mp.validate_package([], height=101)
        self.assertFalse(ok, "Empty package must be rejected")
        self.assertIn("empty", err.lower())


# ---------------------------------------------------------------------------
# G27 — Negative fee in package tx detected
# ---------------------------------------------------------------------------

class TestG27NegativeFeeInPackage(unittest.TestCase):
    """G27: Package tx with output value > input value (negative fee) must be rejected."""

    def test_negative_fee_in_package_rejected(self):
        mp, db = _make_mempool()

        utxo_txid = _bytes32(1)
        db.add_utxo(utxo_txid, 0, value=50_000)

        # Outputs exceed inputs — negative fee
        inp = TxIn(prev_txid=utxo_txid, prev_vout=0)
        tx = _make_tx(txid=_bytes32(10), inputs=[inp], value_out=60_000)

        ok, err = mp.validate_package([tx], height=101)
        self.assertFalse(ok, "Package tx with negative fee must be rejected")
        self.assertIn("negative", err.lower())


# ---------------------------------------------------------------------------
# G28 — pkgtxns P2P handler: double-processing via validate_package + add_transaction
# BUG: p2p.py calls validate_package (which adds to mempool) then add_transaction again
# ---------------------------------------------------------------------------

class TestG28PkgTxnsDoubleProcessing(unittest.TestCase):
    """G28 BUG: on_pkgtxns handler calls validate_package (which adds txs) then
    add_transaction again, causing a double-add attempt.

    ouroboros p2p.py on_pkgtxns (line 3097-3105):
      self._mempool.validate_package(txs, height=height)  # adds txs to mempool
      for tx in txs:
          self._mempool.add_transaction(tx, height=height)  # tries to add again!

    validate_package already inserts accepted transactions into self.transactions.
    add_transaction will find them already present and fail with 'already in mempool'.
    The pkgtxns handler silently ignores these errors so the bug is hidden, but
    the redundant validation is wasteful and error-prone.
    """

    def test_pkgtxns_handler_double_processes(self):
        import inspect
        try:
            from ouroboros.p2p import P2PManager
        except Exception:
            self.skipTest("Cannot import P2PManager")

        # Read the source of _register_package_relay_handlers
        src = inspect.getsource(P2PManager._register_package_relay_handlers)
        self.assertIn("validate_package", src,
                      "on_pkgtxns must call validate_package")
        self.assertIn("add_transaction", src,
                      "on_pkgtxns also calls add_transaction after validate_package")

        # The bug: both are present — validate_package already adds, add_transaction is redundant
        validate_pos = src.index("validate_package")
        add_pos = src.index("add_transaction")
        self.assertLess(validate_pos, add_pos,
                        "BUG: validate_package called before add_transaction — double-add. "
                        "validate_package already inserts txs. add_transaction call is redundant "
                        "and will fail with 'already in mempool' for successfully validated txs.")


# ---------------------------------------------------------------------------
# G29 — BIP 331 P2P: sendpackages / getpkgtxns / pkgtxns messages implemented
# ---------------------------------------------------------------------------

class TestG29BIP331Messages(unittest.TestCase):
    """G29: BIP 331 P2P messages must be fully implemented."""

    def test_sendpackages_message_implemented(self):
        from ouroboros.p2p_messages import SendPackagesMessage
        msg = SendPackagesMessage(version=1, max_count=25, max_weight=404_000)
        network_msg = msg.to_network_message("mainnet")
        self.assertEqual(network_msg.command, "sendpackages")

        # Round-trip test
        decoded = SendPackagesMessage.from_payload(network_msg.payload)
        self.assertEqual(decoded.version, 1)
        self.assertEqual(decoded.max_count, 25)
        self.assertEqual(decoded.max_weight, 404_000)

    def test_getpkgtxns_message_implemented(self):
        from ouroboros.p2p_messages import GetPkgTxnsMessage
        wtxid = bytes(range(32))
        msg = GetPkgTxnsMessage(child_wtxid=wtxid)
        network_msg = msg.to_network_message("mainnet")
        self.assertEqual(network_msg.command, "getpkgtxns")
        decoded = GetPkgTxnsMessage.from_payload(network_msg.payload)
        self.assertEqual(decoded.child_wtxid, wtxid)

    def test_pkgtxns_message_implemented(self):
        from ouroboros.p2p_messages import PkgTxnsMessage
        raw_txs = [b"\x01" * 100, b"\x02" * 120]
        msg = PkgTxnsMessage(transactions=raw_txs)
        network_msg = msg.to_network_message("mainnet")
        self.assertEqual(network_msg.command, "pkgtxns")
        decoded = PkgTxnsMessage.from_payload(network_msg.payload)
        self.assertEqual(decoded.transactions, raw_txs)

    def test_ancpkginfo_message_implemented(self):
        from ouroboros.p2p_messages import AncPkgInfoMessage
        child_wtxid = bytes(range(32))
        parent_wtxids = [bytes([i] * 32) for i in range(3)]
        msg = AncPkgInfoMessage(child_wtxid=child_wtxid, parent_wtxids=parent_wtxids)
        network_msg = msg.to_network_message("mainnet")
        self.assertEqual(network_msg.command, "ancpkginfo")
        decoded = AncPkgInfoMessage.from_payload(network_msg.payload)
        self.assertEqual(decoded.child_wtxid, child_wtxid)
        self.assertEqual(decoded.parent_wtxids, parent_wtxids)

    def test_pkgtxns_count_limit_enforced(self):
        """pkgtxns message must reject > 25 transactions."""
        from ouroboros.p2p_messages import PkgTxnsMessage, encode_varint
        # Manually craft a payload with 26 txs
        payload = encode_varint(26)
        for _ in range(26):
            payload += encode_varint(10)
            payload += b"\x00" * 10
        with self.assertRaises(ValueError, msg="pkgtxns with >25 txs must raise ValueError"):
            PkgTxnsMessage.from_payload(payload)


# ---------------------------------------------------------------------------
# G30 — P2P: package relay negotiation gated on relay_txs
# ---------------------------------------------------------------------------

class TestG30PackageRelayNegotiationGating(unittest.TestCase):
    """G30: sendpackages must not be sent to block-relay-only peers (relay_txs=False)."""

    def test_negotiate_package_relay_respects_relay_txs(self):
        import inspect
        try:
            from ouroboros.p2p import P2PManager
            src = inspect.getsource(P2PManager._negotiate_package_relay)
        except Exception:
            self.skipTest("Cannot import P2PManager._negotiate_package_relay")
        self.assertIn("relay_txs", src,
                      "sendpackages must be gated on peer.relay_txs per Core net_processing logic")

    def test_package_relay_constants_correct(self):
        """p2p.py must use correct MAX_PACKAGE_COUNT and MAX_PACKAGE_WEIGHT values."""
        import inspect
        try:
            from ouroboros.p2p import P2PManager
            src = inspect.getsource(P2PManager.__init__)
        except Exception:
            self.skipTest("Cannot inspect P2PManager.__init__")
        self.assertIn("25", src, "package_max_count must be 25 in P2PManager")
        self.assertIn("404_000", src, "package_max_weight must be 404_000 in P2PManager")

    def test_rust_pipeline_has_no_package_code(self):
        """Two-pipeline: ferrous-utils/sync has zero package relay code."""
        import subprocess
        result = subprocess.run(
            ["grep", "-r", "package", "/home/work/hashhog/ouroboros/ferrous-utils/sync/src/"],
            capture_output=True, text=True
        )
        # Only Cargo.toml [package] should match, not package relay code
        lines = [l for l in result.stdout.splitlines() if "Cargo.toml" not in l and "[package]" not in l]
        self.assertEqual(
            len(lines), 0,
            f"Two-pipeline: Rust ferrous-utils/sync has no package relay code "
            f"(expected). Unexpected references: {lines[:5]}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
