"""
Test getblocktemplate sigops budget enforcement.

Verifies that rpc_getblocktemplate() enforces the MAX_BLOCK_SIGOPS_COST = 80,000
running-total cap during block assembly (Core BlockAssembler parity).

Reference: bitcoin-core/src/node/miner.cpp TestChunkBlockLimits
"""

import asyncio
import hashlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

# Mock the Rust extension module before any ouroboros imports
sys.modules.setdefault("sync", MagicMock())

from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import MempoolEntry  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402
from ouroboros.validation import WITNESS_SCALE_FACTOR, _count_legacy_sigops  # noqa: E402


MAX_BLOCK_SIGOPS_COST = 80_000


def _make_txid(label: str) -> bytes:
    """Produce a deterministic 32-byte txid from a human label."""
    return hashlib.sha256(label.encode()).digest()


def _checksig_script(n: int) -> bytes:
    """
    Build a scriptPubKey containing exactly n OP_CHECKSIG opcodes.

    Each OP_CHECKSIG = 0xac.  We use OP_TRUE (0x51) as a push before
    each CHECKSIG so the script is syntactically valid push-data.
    This gives n legacy sigops per output (fAccurate=False).
    """
    script = b""
    for _ in range(n):
        script += b"\x51\xac"  # OP_TRUE OP_CHECKSIG
    return script


def _make_tx_with_sigops(txid: bytes, n_checksig: int) -> Transaction:
    """
    Build a Transaction whose single output contains n_checksig OP_CHECKSIG
    opcodes.  Legacy sigop cost = n_checksig * WITNESS_SCALE_FACTOR.
    """
    return Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=b"\xaa" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            TxOut(
                value=9000,
                script_pubkey=_checksig_script(n_checksig),
            )
        ],
        has_witness=False,
    )


def _run_template(snap_txs, snap_fee_rate):
    """
    Build a mock node, inject the given mempool snapshot, call
    rpc_getblocktemplate and return the resulting template dict.
    """
    mock_db = MagicMock()
    best_hash = b"\x00" * 32
    mock_db.get_best_block.return_value = (best_hash, 100)
    mock_block = MagicMock()
    mock_block.bits = 0x1D00FFFF
    mock_block.version = 0x20000000
    mock_block.serialize.return_value = b"\x00" * 80
    mock_db.get_block.return_value = mock_block
    mock_db.get_utxo.return_value = None  # no UTXOs needed for legacy sigops

    mock_mempool = MagicMock()
    mock_mempool.snapshot.return_value = (snap_fee_rate, snap_txs)

    mock_node = MagicMock()
    mock_node.db = mock_db
    mock_node.mempool = mock_mempool
    mock_node.get_median_time.return_value = 0

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = mock_node

    return asyncio.run(rpc.rpc_getblocktemplate({}))


class TestGBTSigopsBudget(unittest.TestCase):
    """
    Verify that getblocktemplate enforces the 80,000-sigop budget.

    Scenario:
      Four transactions, each with 25 OP_CHECKSIG opcodes in one output.
      Legacy sigop cost per tx = 25 * WITNESS_SCALE_FACTOR = 25 * 4 = 100.
      Cumulative after 3 txs = 300 (well under 80,000).
      A fifth tx has 20,001 legacy-sigop outputs so it alone costs 80,004
      and must be dropped regardless of order.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_per_tx_sigops_nonzero(self):
        """
        Each transaction in the template must report a non-zero sigops cost
        when it has OP_CHECKSIG in an output.
        """
        txid = _make_txid("single_checksig")
        # 1 OP_CHECKSIG → legacy cost = 1 * WITNESS_SCALE_FACTOR = 4
        tx = _make_tx_with_sigops(txid, 1)
        snap_txs = {
            txid: MempoolEntry(
                tx=tx,
                fee=1000,
                fee_rate=10.0,
                size=100,
                time_added=0.0,
                height_added=100,
            )
        }
        result = _run_template(snap_txs, [txid])
        self.assertEqual(len(result["transactions"]), 1)
        reported = result["transactions"][0]["sigops"]
        self.assertGreater(reported, 0,
                           "per-tx sigops must be > 0 for a tx with OP_CHECKSIG")

    def test_running_total_does_not_exceed_limit(self):
        """
        When 3 txs with 25 checksigs each are in the template (cumulative 300
        sigop cost), and a 4th tx would push total to 80,304, the 4th must be
        dropped.

        n_checksig=20_001 → legacy cost = 20_001 * 4 = 80_004 (exceeds budget).
        """
        txid_a = _make_txid("sig_a")
        txid_b = _make_txid("sig_b")
        txid_c = _make_txid("sig_c")
        txid_big = _make_txid("sig_big")

        # 25 checksigs → cost = 100 each; 3 × 100 = 300 cumulative
        tx_a = _make_tx_with_sigops(txid_a, 25)
        tx_b = _make_tx_with_sigops(txid_b, 25)
        tx_c = _make_tx_with_sigops(txid_c, 25)
        # 20,001 checksigs → cost = 80,004 (exceeds 80,000 budget alone)
        tx_big = _make_tx_with_sigops(txid_big, 20_001)

        snap_txs = {
            txid_a: MempoolEntry(tx=tx_a, fee=5000, fee_rate=50.0,
                                 size=100, time_added=0.0, height_added=100),
            txid_b: MempoolEntry(tx=tx_b, fee=4000, fee_rate=40.0,
                                 size=100, time_added=0.0, height_added=100),
            txid_c: MempoolEntry(tx=tx_c, fee=3000, fee_rate=30.0,
                                 size=100, time_added=0.0, height_added=100),
            txid_big: MempoolEntry(tx=tx_big, fee=100, fee_rate=1.0,
                                   size=100, time_added=0.0, height_added=100),
        }
        # Fee-rate order (highest first): a, b, c, big
        snap_fee_rate = [txid_a, txid_b, txid_c, txid_big]

        result = _run_template(snap_txs, snap_fee_rate)
        # t["txid"] is display-order (BE) hex; internal txids are LE — reverse. W69.
        included_ids = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}

        self.assertIn(txid_a, included_ids, "tx_a (25 checksigs) should be included")
        self.assertIn(txid_b, included_ids, "tx_b (25 checksigs) should be included")
        self.assertIn(txid_c, included_ids, "tx_c (25 checksigs) should be included")
        self.assertNotIn(
            txid_big, included_ids,
            "tx_big (20001 checksigs, cost 80004) must be dropped — exceeds budget"
        )

    def test_budget_boundary_exact_fit(self):
        """
        A tx whose sigop cost exactly fills the remaining budget must be included;
        a subsequent tx that would push past the limit must be dropped.

        Budget = 80,000. Use txs with 19,999 checksigs each:
          19,999 * 4 = 79,996 sigop cost.
        First tx: cumulative = 79,996 (fits).
        Second tx: cumulative = 159,992 (exceeds) → dropped.
        """
        txid_fits = _make_txid("fits_exactly")
        txid_over = _make_txid("over_budget")

        tx_fits = _make_tx_with_sigops(txid_fits, 19_999)
        tx_over = _make_tx_with_sigops(txid_over, 19_999)

        snap_txs = {
            txid_fits: MempoolEntry(tx=tx_fits, fee=2000, fee_rate=20.0,
                                    size=100, time_added=0.0, height_added=100),
            txid_over: MempoolEntry(tx=tx_over, fee=1000, fee_rate=10.0,
                                    size=100, time_added=0.0, height_added=100),
        }
        snap_fee_rate = [txid_fits, txid_over]

        result = _run_template(snap_txs, snap_fee_rate)
        # t["txid"] is display-order (BE) hex; internal txids are LE — reverse. W69.
        included_ids = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}

        self.assertIn(txid_fits, included_ids,
                      "first tx (79,996 sigop cost) should fit")
        self.assertNotIn(txid_over, included_ids,
                         "second tx would push total to 159,992 — must be dropped")

    def test_sigoplimit_in_response(self):
        """Template response must advertise sigoplimit = 80000."""
        snap_txs = {}
        result = _run_template(snap_txs, [])
        self.assertEqual(result.get("sigoplimit"), MAX_BLOCK_SIGOPS_COST,
                         "sigoplimit field must equal MAX_BLOCK_SIGOPS_COST")


if __name__ == "__main__":
    unittest.main()
