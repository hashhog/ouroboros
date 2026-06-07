"""
Proven-teeth test for the getorphantxs JSON-RPC method (ouroboros).

getorphantxs was added in Bitcoin Core v28 (commit 34a9c10e8c "rpc: add
getorphantxs"); it was MISSING on every hashhog node — an RPC-completeness
gap. This test inserts orphans directly into the node's OrphanPool, calls
rpc_getorphantxs at every supported verbosity, and asserts the EXACT Core
field shape (txid, wtxid, bytes, vsize, weight, from [+hex at v2]) plus the
out-of-range-verbosity error and the bool-arg rejection (allow_bool=false).

Reference: bitcoin-core/src/rpc/mempool.cpp OrphanDescription/OrphanToJSON.

Runs offline (no live network, no RocksDB) — the Rust `sync` extension is
stubbed exactly as test_w106_mempool.py does.
"""

import asyncio
import hashlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

# Stub the Rust extension so pure-Python imports work offline (mempool.py and
# rpc.py both import it transitively).
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import OrphanPool  # noqa: E402
from ouroboros.rpc import (  # noqa: E402
    RPC_INVALID_PARAMETER,
    RPC_TYPE_ERROR,
    RpcError,
    RPCServer,
)


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _bytes32(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _make_tx(missing_parent: bytes, witness: bool = False) -> Transaction:
    """Build a real database.Transaction spending one (missing) parent output."""
    wit = [b"\x01" * 72, b"\x02" * 33] if witness else None
    txin = TxIn(
        prev_txid=missing_parent,
        prev_vout=0,
        script_sig=b"" if witness else b"\x47" + b"\x01" * 71,
        sequence=0xFFFFFFFE,
        witness=wit,
    )
    txout = TxOut(value=50_000, script_pubkey=bytes([0x51, 0x20]) + bytes(32))
    tx = Transaction(
        txid=b"\x00" * 32,  # placeholder; replaced below with the real txid
        version=2,
        locktime=0,
        inputs=[txin],
        outputs=[txout],
        has_witness=witness,
    )
    # txid = sha256d of the non-witness serialization (Core CTransaction::GetHash).
    tx.txid = _sha256d(tx.serialize())
    return tx


class _FakeNode:
    """Minimal node exposing only what rpc_getorphantxs reads."""

    def __init__(self, mempool):
        self.mempool = mempool
        self.network = "regtest"
        self.data_dir = "/tmp/ouroboros-getorphantxs-test"


class _FakeMempool:
    def __init__(self):
        self.orphan_pool = OrphanPool()


class TestGetOrphanTxs(unittest.TestCase):
    def setUp(self):
        self.mempool = _FakeMempool()
        self.node = _FakeNode(self.mempool)
        self.rpc = RPCServer(self.node, port=18332)

        # Orphan A: non-witness, announced by a peer addr.
        self.tx_a = _make_tx(_bytes32(900), witness=False)
        # Orphan B: witness tx (so bytes > vsize), NO announcing peer.
        self.tx_b = _make_tx(_bytes32(901), witness=True)

        self.mempool.orphan_pool.add(
            self.tx_a, missing_parents={_bytes32(900)}, peer="1.2.3.4:8333"
        )
        self.mempool.orphan_pool.add(
            self.tx_b, missing_parents={_bytes32(901)}, peer=None
        )

    def _call(self, *args, **kwargs):
        return asyncio.run(self.rpc.rpc_getorphantxs(*args, **kwargs))

    def test_method_exists(self):
        self.assertTrue(callable(getattr(self.rpc, "rpc_getorphantxs", None)))

    def test_verbosity_0_returns_txid_list(self):
        result = self._call(0)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        # Display order is big-endian (reverse of internal LE), matching Core.
        expected = {
            self.tx_a.get_txid()[::-1].hex(),
            self.tx_b.get_txid()[::-1].hex(),
        }
        self.assertEqual(set(result), expected)

    def test_verbosity_0_is_default(self):
        # No arg → default verbosity 0 (Core RPCArg::Default{0}).
        self.assertEqual(self._call(), self._call(0))

    def test_verbose_alias(self):
        # Core arg name is "verbosity|verbose"; the alias must work as kwarg.
        self.assertEqual(self._call(verbose=1), self._call(1))

    def test_verbosity_1_shape_and_fields(self):
        result = self._call(1)
        self.assertEqual(len(result), 2)
        by_wtxid = {o["wtxid"]: o for o in result}

        # --- Orphan A (non-witness, has announcer) ---
        oa = by_wtxid[self.tx_a.get_wtxid()[::-1].hex()]
        # EXACT Core OrphanToJSON field set — NO ``expiration`` field.
        self.assertEqual(
            set(oa.keys()),
            {"txid", "wtxid", "bytes", "vsize", "weight", "from"},
        )
        # Core has no expiration field — assert it is absent.
        self.assertNotIn("expiration", oa)
        self.assertEqual(oa["txid"], self.tx_a.get_txid()[::-1].hex())
        # Non-witness: txid == wtxid.
        self.assertEqual(oa["txid"], oa["wtxid"])
        self.assertEqual(oa["bytes"], len(self.tx_a.serialize_with_witness()))
        self.assertEqual(oa["vsize"], self.tx_a.get_vsize())
        self.assertEqual(oa["weight"], self.tx_a.get_weight())
        # Non-witness: bytes == vsize and weight == bytes * 4.
        self.assertEqual(oa["bytes"], oa["vsize"])
        self.assertEqual(oa["weight"], oa["bytes"] * 4)
        # from = single announcing peer (this node tracks one announcer addr).
        self.assertEqual(oa["from"], ["1.2.3.4:8333"])

        # --- Orphan B (witness, no announcer) ---
        ob = by_wtxid[self.tx_b.get_wtxid()[::-1].hex()]
        # Witness tx: txid != wtxid, bytes > vsize.
        self.assertNotEqual(ob["txid"], ob["wtxid"])
        self.assertGreater(ob["bytes"], ob["vsize"])
        # No announcer tracked → empty from array (best-effort).
        self.assertEqual(ob["from"], [])

    def test_verbosity_2_adds_hex(self):
        result = self._call(2)
        self.assertEqual(len(result), 2)
        for o in result:
            self.assertIn("hex", o)
            # v2 = all v1 fields + hex (NO ``expiration`` field).
            self.assertEqual(
                set(o.keys()),
                {"txid", "wtxid", "bytes", "vsize", "weight", "from", "hex"},
            )
        by_wtxid = {o["wtxid"]: o for o in result}
        ob = by_wtxid[self.tx_b.get_wtxid()[::-1].hex()]
        # hex is the serialized (with-witness) transaction, round-trippable.
        self.assertEqual(ob["hex"], self.tx_b.serialize_with_witness().hex())

    def test_invalid_verbosity_raises_minus_8(self):
        for bad in (3, -1, 99):
            with self.assertRaises(RpcError) as cm:
                self._call(bad)
            self.assertEqual(cm.exception.code, RPC_INVALID_PARAMETER)
            self.assertEqual(
                cm.exception.message, f"Invalid verbosity value {bad}"
            )

    def test_bool_verbosity_rejected(self):
        # Core: ParseVerbosity(..., allow_bool=false) → a boolean arg is
        # REJECTED with RPC_TYPE_ERROR, NOT silently mapped to 0/1.
        for bad in (True, False):
            with self.assertRaises(RpcError) as cm:
                self._call(bad)
            self.assertEqual(cm.exception.code, RPC_TYPE_ERROR)
            self.assertEqual(
                cm.exception.message,
                "Verbosity was boolean but only integer allowed",
            )

    def test_empty_orphanage_returns_empty_list(self):
        self.mempool.orphan_pool = OrphanPool()
        self.assertEqual(self._call(0), [])
        self.assertEqual(self._call(1), [])
        self.assertEqual(self._call(2), [])

    def test_no_mempool_returns_empty_list(self):
        # Node not fully started (mempool is None) → empty array, not a crash.
        self.node.mempool = None
        self.assertEqual(self._call(0), [])
        self.assertEqual(self._call(1), [])


if __name__ == "__main__":
    unittest.main()
