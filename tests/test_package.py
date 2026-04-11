"""
Tests for package relay and CPFP package acceptance.

Reference: Bitcoin Core policy/packages.cpp, validation.cpp AcceptPackage()
"""

import sys
import types
from pathlib import Path

import pytest

# Mock the sync module before importing ouroboros modules
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"

    class _StubDB:
        def __init__(self, *a, **kw):
            self._utxos = {}
            self._best_block = (b"\x00" * 32, 100)

        def get_block(self, *a, **kw):
            return None

        def get_block_by_height(self, *a, **kw):
            return None

        def get_best_block(self, *a, **kw):
            return self._best_block

        def get_utxo(self, txid, vout):
            return self._utxos.get((txid, vout))

        def add_utxo(self, txid, vout, value, script_pubkey=b""):
            self._utxos[(txid, vout)] = {
                "value": value,
                "script_pubkey": script_pubkey,
            }

    _mock.PyBlockchainDB = _StubDB
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: True
    sys.modules["sync"] = _mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import MAX_PACKAGE_COUNT, Mempool
from ouroboros.p2p_messages import (
    MSG_PKGTXNS,
    AncPkgInfoMessage,
    GetPkgTxnsMessage,
    PkgTxnsMessage,
    SendPackagesMessage,
)


class MockValidator:
    """Mock transaction validator for testing."""

    def __init__(self, db):
        self.db = db

    def validate_transaction(self, tx, height):
        # Always valid for testing
        return True, ""


def make_tx(
    inputs: list,  # [(prev_txid, prev_vout), ...]
    outputs: list,  # [(value, script_pubkey), ...]
    version: int = 2,
) -> Transaction:
    """Create a test transaction."""
    tx_inputs = [
        TxIn(
            prev_txid=prev_txid,
            prev_vout=prev_vout,
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=None,
        )
        for prev_txid, prev_vout in inputs
    ]
    tx_outputs = [
        TxOut(value=value, script_pubkey=script_pubkey)
        for value, script_pubkey in outputs
    ]
    tx = Transaction(
        txid=b"\x00" * 32,
        version=version,
        locktime=0,
        inputs=tx_inputs,
        outputs=tx_outputs,
        has_witness=False,
    )
    # Recompute the txid
    import hashlib
    tx_bytes = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()
    return tx


class TestChildWithParentsTopology:
    """Test the is_child_with_parents and is_child_with_parents_tree helpers."""

    def test_single_tx_not_child_with_parents(self):
        """A single transaction is not a child-with-parents package."""
        tx = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(1000, b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac")],
        )
        assert not Mempool.is_child_with_parents([tx])

    def test_valid_1p1c_package(self):
        """A 1-parent-1-child package is valid."""
        parent = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        child = make_tx(
            inputs=[(parent.get_txid(), 0)],
            outputs=[(9000, b"\x00")],
        )
        assert Mempool.is_child_with_parents([parent, child])
        assert Mempool.is_child_with_parents_tree([parent, child])

    def test_valid_2p1c_package(self):
        """A 2-parent-1-child package is valid."""
        parent1 = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        parent2 = make_tx(
            inputs=[(b"\x02" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        child = make_tx(
            inputs=[
                (parent1.get_txid(), 0),
                (parent2.get_txid(), 0),
            ],
            outputs=[(18000, b"\x00")],
        )
        assert Mempool.is_child_with_parents([parent1, parent2, child])
        assert Mempool.is_child_with_parents_tree([parent1, parent2, child])

    def test_invalid_unrelated_tx(self):
        """A package with unrelated transactions is invalid."""
        parent = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        unrelated = make_tx(
            inputs=[(b"\x02" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        child = make_tx(
            inputs=[(parent.get_txid(), 0)],
            outputs=[(9000, b"\x00")],
        )
        # unrelated is not a parent of child
        assert not Mempool.is_child_with_parents([parent, unrelated, child])

    def test_parents_depend_on_each_other(self):
        """Parents that depend on each other make an invalid tree."""
        grandparent = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        parent1 = make_tx(
            inputs=[(grandparent.get_txid(), 0)],
            outputs=[(9000, b"\x00")],
        )
        child = make_tx(
            inputs=[
                (grandparent.get_txid(), 0),  # also spends from grandparent
                (parent1.get_txid(), 0),
            ],
            outputs=[(8000, b"\x00")],
        )
        # This is child-with-parents, but not a tree because parent1 depends on grandparent
        assert Mempool.is_child_with_parents([grandparent, parent1, child])
        assert not Mempool.is_child_with_parents_tree([grandparent, parent1, child])


class TestPackageValidation:
    """Test mempool package validation."""

    def test_empty_package_rejected(self):
        """Empty packages are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        success, error = mempool.validate_package([], height=100)
        assert not success
        assert "Empty" in error

    def test_package_too_many_txs(self):
        """Packages with too many transactions are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        # Create MAX_PACKAGE_COUNT + 1 transactions
        txs = []
        for i in range(MAX_PACKAGE_COUNT + 1):
            tx = make_tx(
                inputs=[(bytes([i]) + b"\x00" * 31, 0)],
                outputs=[(1000, b"\x00")],
            )
            txs.append(tx)

        success, error = mempool.validate_package(txs, height=100)
        assert not success
        assert "too large" in error.lower() or str(MAX_PACKAGE_COUNT) in error

    def test_duplicate_tx_rejected(self):
        """Packages with duplicate transactions are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        tx = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(1000, b"\x00")],
        )

        success, error = mempool.validate_package([tx, tx], height=100)
        assert not success
        assert "Duplicate" in error

    def test_double_spend_in_package_rejected(self):
        """Packages with double-spends are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        tx1 = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(1000, b"\x00")],
        )
        tx2 = make_tx(
            inputs=[(b"\x01" * 32, 0)],  # same input as tx1
            outputs=[(2000, b"\x00")],   # different output to get different txid
        )
        # Create a child that spends from both
        child = make_tx(
            inputs=[
                (tx1.get_txid(), 0),
                (tx2.get_txid(), 0),
            ],
            outputs=[(1500, b"\x00")],
        )

        success, error = mempool.validate_package([tx1, tx2, child], height=100)
        assert not success
        assert "Double-spend" in error

    def test_not_topological_order_rejected(self):
        """Packages not in topological order are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        parent = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        child = make_tx(
            inputs=[(parent.get_txid(), 0)],
            outputs=[(9000, b"\x00")],
        )

        # Submit in wrong order: child before parent
        success, error = mempool.validate_package([child, parent], height=100)
        assert not success
        assert "topological" in error.lower()

    def test_not_child_with_parents_rejected(self):
        """Packages that aren't child-with-parents are rejected."""
        db = sys.modules["sync"].PyBlockchainDB()
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        # Two unrelated transactions — not a valid package topology
        tx1 = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )
        tx2 = make_tx(
            inputs=[(b"\x02" * 32, 0)],
            outputs=[(10000, b"\x00")],
        )

        success, error = mempool.validate_package([tx1, tx2], height=100)
        assert not success
        assert "not-child-with-parents" in error

    def test_cpfp_package_accepted(self):
        """A child can pay for a low-fee parent via CPFP."""
        # Create a custom db with UTXO support
        class TestDB:
            def __init__(self):
                self._utxos = {}
            def get_utxo(self, txid, vout):
                return self._utxos.get((txid, vout))
            def get_best_block(self):
                return (b"\x00" * 32, 100)

        db = TestDB()
        # Add UTXO for the parent to spend
        db._utxos[(b"\x01" * 32, 0)] = {"value": 100000, "script_pubkey": b"\x00"}
        validator = MockValidator(db)
        mempool = Mempool(validator, require_standard=False)

        # Parent with very low fee (below min relay)
        parent = make_tx(
            inputs=[(b"\x01" * 32, 0)],
            outputs=[(99999, b"\x00")],  # 1 sat fee = very low
        )
        # Child with high fee to cover both
        child = make_tx(
            inputs=[(parent.get_txid(), 0)],
            outputs=[(90000, b"\x00")],  # ~10000 sat fee
        )

        success, error = mempool.validate_package([parent, child], height=100)
        assert success, f"Package should be accepted: {error}"

        # Both transactions should be in mempool
        assert mempool.has_transaction(parent.get_txid())
        assert mempool.has_transaction(child.get_txid())


class TestP2PPackageMessages:
    """Test BIP 331 package relay P2P messages."""

    def test_sendpackages_serialize_deserialize(self):
        """Test SendPackagesMessage serialization."""
        msg = SendPackagesMessage(version=1, max_count=25, max_weight=404000)
        network_msg = msg.to_network_message("mainnet")
        assert network_msg.command == "sendpackages"

        restored = SendPackagesMessage.from_payload(network_msg.payload)
        assert restored.version == 1
        assert restored.max_count == 25
        assert restored.max_weight == 404000

    def test_getpkgtxns_serialize_deserialize(self):
        """Test GetPkgTxnsMessage serialization."""
        wtxid = b"\xab" * 32
        msg = GetPkgTxnsMessage(child_wtxid=wtxid)
        network_msg = msg.to_network_message("mainnet")
        assert network_msg.command == "getpkgtxns"

        restored = GetPkgTxnsMessage.from_payload(network_msg.payload)
        assert restored.child_wtxid == wtxid

    def test_pkgtxns_serialize_deserialize(self):
        """Test PkgTxnsMessage serialization."""
        tx1_bytes = b"\x01" * 100
        tx2_bytes = b"\x02" * 150
        msg = PkgTxnsMessage(transactions=[tx1_bytes, tx2_bytes])
        network_msg = msg.to_network_message("mainnet")
        assert network_msg.command == "pkgtxns"

        restored = PkgTxnsMessage.from_payload(network_msg.payload)
        assert len(restored.transactions) == 2
        assert restored.transactions[0] == tx1_bytes
        assert restored.transactions[1] == tx2_bytes

    def test_ancpkginfo_serialize_deserialize(self):
        """Test AncPkgInfoMessage serialization."""
        child_wtxid = b"\xcc" * 32
        parent_wtxids = [b"\xaa" * 32, b"\xbb" * 32]
        msg = AncPkgInfoMessage(
            child_wtxid=child_wtxid,
            parent_wtxids=parent_wtxids,
        )
        network_msg = msg.to_network_message("mainnet")
        assert network_msg.command == "ancpkginfo"

        restored = AncPkgInfoMessage.from_payload(network_msg.payload)
        assert restored.child_wtxid == child_wtxid
        assert len(restored.parent_wtxids) == 2
        assert restored.parent_wtxids[0] == parent_wtxids[0]
        assert restored.parent_wtxids[1] == parent_wtxids[1]

    def test_msg_pkgtxns_constant(self):
        """Test MSG_PKGTXNS inventory type constant."""
        assert MSG_PKGTXNS == 6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
