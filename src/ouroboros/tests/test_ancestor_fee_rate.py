"""
Test ancestor fee rate scoring for block template transaction ordering.

Verifies that rpc_getblocktemplate() selects transactions using ancestor
fee rate (package fee rate) rather than individual fee rate.  A low-fee
parent paired with a high-fee child (CPFP) should be selected before a
standalone transaction whose individual fee rate is higher than the
parent's but whose package fee rate is lower than the child's package.
"""

import asyncio
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Mock the Rust extension module before any ouroboros imports
sys.modules.setdefault("sync", MagicMock())

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import MempoolEntry  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402


def _make_txid(label: str) -> bytes:
    """Produce a deterministic 32-byte txid from a human label."""
    return hashlib.sha256(label.encode()).digest()


def _make_tx(txid: bytes, inputs: list, outputs: list) -> Transaction:
    """Build a minimal Transaction object sufficient for template selection."""
    tx = Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=False,
    )
    return tx


class TestAncestorFeeRateOrdering(unittest.TestCase):
    """
    Scenario
    --------
    Three mempool transactions:

    1. **parent** – 200 bytes, fee 100 sat
       individual fee rate = 100/200 = 0.50 sat/byte

    2. **child** – 200 bytes, fee 1900 sat, spends parent
       individual fee rate = 1900/200 = 9.50 sat/byte
       ancestor (package) fee rate = (100+1900)/(200+200) = 5.00 sat/byte

    3. **standalone** – 200 bytes, fee 600 sat (no mempool parents)
       individual fee rate = 600/200 = 3.00 sat/byte
       ancestor fee rate = same (no ancestors) = 3.00 sat/byte

    With **individual** fee rate ordering the template would pick:
        child (9.50) → standalone (3.00) → parent (0.50)
    But the child cannot be included without its parent, so the parent
    would be pulled in anyway – meaning the effective ordering used to
    *consider* candidates matters.

    With **ancestor** fee rate ordering the child's package (5.00) is
    considered before the standalone (3.00), so the resulting template
    is: parent, child, standalone – which maximises total fees.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # Helper: run the template builder with a mocked node / mempool
    # ------------------------------------------------------------------ #
    def _run_template(self, snap_txs, snap_fee_rate):
        """
        Build a mock node, inject the given mempool snapshot, call
        rpc_getblocktemplate and return the resulting template dict.
        """
        # -- mock DB ---------------------------------------------------
        mock_db = MagicMock()
        best_hash = b"\x00" * 32
        mock_db.get_best_block.return_value = (best_hash, 100)
        mock_block = MagicMock()
        mock_block.bits = 0x1d00ffff
        mock_block.version = 0x20000000
        mock_block.serialize.return_value = b"\x00" * 80
        mock_db.get_block.return_value = mock_block
        mock_db.get_utxo.return_value = None  # no UTXOs needed

        # -- mock mempool ----------------------------------------------
        mock_mempool = MagicMock()
        mock_mempool.snapshot.return_value = (snap_fee_rate, snap_txs)

        # -- mock node -------------------------------------------------
        mock_node = MagicMock()
        mock_node.db = mock_db
        mock_node.mempool = mock_mempool
        mock_node.get_median_time.return_value = 0

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        return asyncio.run(rpc.rpc_getblocktemplate({}))

    # ------------------------------------------------------------------ #
    # Build the three transactions described above
    # ------------------------------------------------------------------ #
    def _build_scenario(self):
        parent_txid = _make_txid("parent")
        child_txid = _make_txid("child")
        standalone_txid = _make_txid("standalone")

        # --- parent: no mempool parents, 1 output --------------------
        parent_tx = _make_tx(
            parent_txid,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9900, script_pubkey=b"\x00\x14" + b"\xbb" * 20)],
        )

        # --- child: spends parent output 0 ----------------------------
        child_tx = _make_tx(
            child_txid,
            inputs=[TxIn(prev_txid=parent_txid, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=8000, script_pubkey=b"\x00\x14" + b"\xcc" * 20)],
        )

        # --- standalone: unrelated, no mempool parents ----------------
        standalone_tx = _make_tx(
            standalone_txid,
            inputs=[TxIn(prev_txid=b"\xdd" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9400, script_pubkey=b"\x00\x14" + b"\xee" * 20)],
        )

        tx_size = 200  # use a uniform, round size for clarity

        snap_txs = {
            parent_txid: MempoolEntry(
                tx=parent_tx, fee=100, fee_rate=100 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
            child_txid: MempoolEntry(
                tx=child_tx, fee=1900, fee_rate=1900 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
            standalone_txid: MempoolEntry(
                tx=standalone_tx, fee=600, fee_rate=600 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
        }

        # Old individual-fee-rate sorted list (lowest → highest)
        snap_fee_rate = [standalone_txid, parent_txid, child_txid]

        return snap_txs, snap_fee_rate, parent_txid, child_txid, standalone_txid

    # ================================================================== #
    # Tests
    # ================================================================== #
    def test_parent_child_package_selected_before_standalone(self):
        """
        The parent+child package (ancestor fee rate 5.0) must appear in
        the template before the standalone tx (ancestor fee rate 3.0).
        """
        snap_txs, snap_fee_rate, parent_txid, child_txid, standalone_txid = (
            self._build_scenario()
        )
        result = self._run_template(snap_txs, snap_fee_rate)
        # t["txid"] is display-order (BE) hex; internal txids are LE — reverse. W69.
        tx_order = [bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]]

        # All three transactions should be present
        self.assertIn(parent_txid, tx_order,
                      "parent must be included in template")
        self.assertIn(child_txid, tx_order,
                      "child must be included in template")
        self.assertIn(standalone_txid, tx_order,
                      "standalone must be included in template")

        parent_idx = tx_order.index(parent_txid)
        child_idx = tx_order.index(child_txid)
        standalone_idx = tx_order.index(standalone_txid)

        # Parent must come before child (topological ordering)
        self.assertLess(parent_idx, child_idx,
                        "parent must precede child (topological order)")

        # The package (parent+child) must be selected before standalone
        # i.e. standalone comes after both parent and child
        self.assertLess(child_idx, standalone_idx,
                        "child (package fee rate 5.0) must come before "
                        "standalone (fee rate 3.0)")

    def test_all_fees_collected(self):
        """Total fees in the template should equal sum of all entry fees."""
        snap_txs, snap_fee_rate, *_ = self._build_scenario()
        result = self._run_template(snap_txs, snap_fee_rate)
        total = sum(t["fee"] for t in result["transactions"])
        expected = sum(e.fee for e in snap_txs.values())
        self.assertEqual(total, expected,
                         "all transaction fees must be accounted for")

    def test_standalone_only_no_ancestors(self):
        """
        A single standalone transaction with no mempool parents should
        have an ancestor fee rate equal to its own individual fee rate.
        """
        txid = _make_txid("solo")
        tx = _make_tx(
            txid,
            inputs=[TxIn(prev_txid=b"\xff" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9000, script_pubkey=b"\x00\x14" + b"\xab" * 20)],
        )
        snap_txs = {
            txid: MempoolEntry(
                tx=tx, fee=500, fee_rate=500 / 100,
                size=100, time_added=0.0, height_added=100,
            ),
        }
        result = self._run_template(snap_txs, [txid])
        self.assertEqual(len(result["transactions"]), 1)
        self.assertEqual(result["transactions"][0]["fee"], 500)

    def test_grandparent_chain_ancestor_fee_rate(self):
        """
        A three-level chain (grandparent→parent→child) should compute
        ancestor fee rate across the entire chain.

        grandparent: 200 bytes, fee 50   → individual rate 0.25
        parent:      200 bytes, fee 50   → individual rate 0.25
        child:       200 bytes, fee 1700 → individual rate 8.50
        Package fee rate = (50+50+1700)/(200+200+200) = 3.00

        standalone:  200 bytes, fee 400  → individual rate 2.00

        The child package (3.00) should be selected before standalone (2.00).
        """
        gp_txid = _make_txid("grandparent")
        parent_txid = _make_txid("parent2")
        child_txid = _make_txid("child2")
        standalone_txid = _make_txid("standalone2")

        tx_size = 200

        gp_tx = _make_tx(
            gp_txid,
            inputs=[TxIn(prev_txid=b"\x01" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9950, script_pubkey=b"\x00\x14" + b"\x11" * 20)],
        )
        parent_tx = _make_tx(
            parent_txid,
            inputs=[TxIn(prev_txid=gp_txid, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9900, script_pubkey=b"\x00\x14" + b"\x22" * 20)],
        )
        child_tx = _make_tx(
            child_txid,
            inputs=[TxIn(prev_txid=parent_txid, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=8200, script_pubkey=b"\x00\x14" + b"\x33" * 20)],
        )
        standalone_tx = _make_tx(
            standalone_txid,
            inputs=[TxIn(prev_txid=b"\x02" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9600, script_pubkey=b"\x00\x14" + b"\x44" * 20)],
        )

        snap_txs = {
            gp_txid: MempoolEntry(
                tx=gp_tx, fee=50, fee_rate=50 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
            parent_txid: MempoolEntry(
                tx=parent_tx, fee=50, fee_rate=50 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
            child_txid: MempoolEntry(
                tx=child_tx, fee=1700, fee_rate=1700 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
            standalone_txid: MempoolEntry(
                tx=standalone_tx, fee=400, fee_rate=400 / tx_size,
                size=tx_size, time_added=0.0, height_added=100,
            ),
        }

        snap_fee_rate = [gp_txid, parent_txid, standalone_txid, child_txid]

        result = self._run_template(snap_txs, snap_fee_rate)
        # t["txid"] is display-order (BE) hex; internal txids are LE — reverse. W69.
        tx_order = [bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]]

        gp_idx = tx_order.index(gp_txid)
        parent_idx = tx_order.index(parent_txid)
        child_idx = tx_order.index(child_txid)
        standalone_idx = tx_order.index(standalone_txid)

        # Topological: grandparent < parent < child
        self.assertLess(gp_idx, parent_idx)
        self.assertLess(parent_idx, child_idx)

        # Package (3.00) before standalone (2.00)
        self.assertLess(child_idx, standalone_idx,
                        "3-deep package should be selected before standalone")


if __name__ == "__main__":
    unittest.main()
