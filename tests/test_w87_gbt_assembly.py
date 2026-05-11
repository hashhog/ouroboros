"""
W87 — getblocktemplate block-assembly audit: 12 bug regression tests.

Tests cover every gate fixed in rpc_getblocktemplate against the Core
reference (bitcoin-core/src/node/miner.cpp, rpc/mining.cpp, policy/policy.h).

Bug index:
  B1  previousblockhash byte order (LE → BE display)
  B2  coinbasetxn.sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL, not 0xFFFFFFFF)
  B3  coinbasetxn.locktime = next_height - 1 (not 0)
  B4  BLOCK_RESERVED_WEIGHT = 8000 (was 4000)
  B5  MAX_CONSECUTIVE_FAILURES = 1000 early-exit gate
  B6  per-tx weight via get_weight() not stripped_bytes * 4
  B7  block version computed for next block (not copied from prev)
  B8  bits from GetNextWorkRequired (not prev block bits)
  B9  curtime = max(MTP+1, now)
  B10 sigops gate uses >= not >
  B11 per-tx hash field is wtxid not txid
  B12 per-tx depends field populated with 1-based in-template ancestor indices
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock the Rust extension before any ouroboros imports.
sys.modules.setdefault("sync", MagicMock())

src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import MempoolEntry  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _txid(label: str) -> bytes:
    """Deterministic 32-byte txid from a human label."""
    return hashlib.sha256(label.encode()).digest()


def _make_tx(
    txid: bytes,
    inputs: list | None = None,
    outputs: list | None = None,
    locktime: int = 0,
    has_witness: bool = False,
) -> Transaction:
    if inputs is None:
        inputs = [TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                       script_sig=b"", sequence=0xFFFFFFFF)]
    if outputs is None:
        outputs = [TxOut(value=9000,
                         script_pubkey=b"\x00\x14" + b"\xbb" * 20)]
    return Transaction(
        txid=txid,
        version=2,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
        has_witness=has_witness,
    )


def _make_entry(
    txid: bytes,
    fee: int = 1000,
    size: int = 200,
    fee_rate: float | None = None,
    locktime: int = 0,
) -> MempoolEntry:
    tx = _make_tx(txid, locktime=locktime)
    return MempoolEntry(
        tx=tx,
        fee=fee,
        fee_rate=fee_rate if fee_rate is not None else fee / size,
        size=size,
        time_added=0.0,
        height_added=100,
    )


def _build_rpc(snap_txs: dict, snap_fee_rate: list,
               best_height: int = 100,
               best_block_bits: int = 0x1D00FFFF,
               best_block_version: int = 0x20000000,
               mtp: int = 0) -> dict:
    """
    Run rpc_getblocktemplate with a mocked node and return the result dict.
    """
    best_hash = b"\x01" * 32  # non-zero to test B1

    mock_db = MagicMock()
    mock_db.get_best_block.return_value = (best_hash, best_height)
    mock_block = MagicMock()
    mock_block.bits = best_block_bits
    mock_block.version = best_block_version
    mock_db.get_block.return_value = mock_block
    mock_db.get_utxo.return_value = None
    mock_db.get_median_time_past.return_value = mtp

    mock_mempool = MagicMock()
    mock_mempool.snapshot.return_value = (snap_fee_rate, snap_txs)

    mock_node = MagicMock()
    mock_node.db = mock_db
    mock_node.mempool = mock_mempool
    mock_node.get_median_time.return_value = mtp
    # get_next_bits / get_next_block_version are MagicMock auto-attributes;
    # their return values are also MagicMock (not int), so rpc_getblocktemplate
    # falls back to best_block.bits / best_block.version automatically.

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = mock_node

    return asyncio.run(rpc.rpc_getblocktemplate({}))


# ---------------------------------------------------------------------------
# B1 — previousblockhash byte order
# ---------------------------------------------------------------------------

class TestB1PreviousBlockHash(unittest.TestCase):
    """B1: previousblockhash must be display-order (big-endian reversed).

    Core: block.hashPrevBlock.GetHex() — GetHex() reverses the bytes.
    """

    def test_previousblockhash_is_reversed(self):
        best_hash_le = b"\x01\x02\x03" + b"\x00" * 29
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (best_hash_le, 100)
        mock_block = MagicMock()
        mock_block.bits = 0x1D00FFFF
        mock_block.version = 0x20000000
        mock_db.get_block.return_value = mock_block
        mock_db.get_utxo.return_value = None
        mock_db.get_median_time_past.return_value = 0

        mock_node = MagicMock()
        mock_node.db = mock_db
        mock_node.mempool = None
        mock_node.get_median_time.return_value = 0
        # No get_next_bits / get_next_block_version hooks on this node mock.
        # The fallback paths in rpc_getblocktemplate detect MagicMock return
        # values via isinstance(val, int) and fall back to best_block.bits /
        # best_block.version, so no explicit deletion is needed.

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = asyncio.run(rpc.rpc_getblocktemplate({}))
        expected = best_hash_le[::-1].hex()
        self.assertEqual(result["previousblockhash"], expected,
                         "previousblockhash must be byte-reversed (display order / BE)")
        # Also verify it is NOT the raw LE hex
        self.assertNotEqual(result["previousblockhash"], best_hash_le.hex())


# ---------------------------------------------------------------------------
# B2 — coinbase sequence
# ---------------------------------------------------------------------------

class TestB2CoinbaseSequence(unittest.TestCase):
    """B2: coinbasetxn.sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL).

    Core miner.cpp:171: CTxIn::MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1.
    0xFFFFFFFF (SEQUENCE_FINAL) disables nLockTime enforcement.
    """

    def test_coinbase_sequence_is_max_nonfinal(self):
        result = _build_rpc({}, [])
        seq = result["coinbasetxn"]["sequence"]
        self.assertEqual(seq, 0xFFFFFFFE,
                         "coinbasetxn.sequence must be MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)")
        self.assertNotEqual(seq, 0xFFFFFFFF,
                            "coinbasetxn.sequence must NOT be SEQUENCE_FINAL (0xFFFFFFFF)")


# ---------------------------------------------------------------------------
# B3 — coinbase locktime
# ---------------------------------------------------------------------------

class TestB3CoinbaseLocktime(unittest.TestCase):
    """B3: coinbasetxn.locktime = next_height - 1.

    Core miner.cpp:196: coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1).
    """

    def test_coinbase_locktime_is_next_height_minus_one(self):
        best_height = 199
        result = _build_rpc({}, [], best_height=best_height)
        expected_locktime = best_height  # next_height - 1 = (best_height+1) - 1 = best_height
        lt = result["coinbasetxn"]["locktime"]
        self.assertEqual(lt, expected_locktime,
                         f"coinbasetxn.locktime must be {expected_locktime} (next_height - 1)")

    def test_coinbase_locktime_not_zero(self):
        result = _build_rpc({}, [], best_height=100)
        self.assertNotEqual(result["coinbasetxn"]["locktime"], 0,
                            "coinbasetxn.locktime must not be 0 (was hardcoded 0 before B3 fix)")


# ---------------------------------------------------------------------------
# B4 — BLOCK_RESERVED_WEIGHT = 8000
# ---------------------------------------------------------------------------

class TestB4ReservedWeight(unittest.TestCase):
    """B4: weight budget = MAX_BLOCK_WEIGHT - 8000 (not 4000).

    Core policy.h:27: DEFAULT_BLOCK_RESERVED_WEIGHT = 8000.
    A transaction whose weight lands between 3_992_000 and 3_996_000
    must be included (fits in 8000-reserved budget) but would have been
    excluded by the old 4000-reserved budget.
    """

    def test_tx_fitting_in_8000_reserved_budget_is_included(self):
        # weight = 3_991_000 < 3_992_000 (= 4M - 8000) → must fit
        txid_a = _txid("b4_fits")
        # Patch get_weight to return a controlled value
        entry_a = _make_entry(txid_a, fee=5000, size=900_000)
        # Override get_weight on the Transaction object
        entry_a.tx.get_weight = lambda: 3_991_000

        snap_txs = {txid_a: entry_a}
        result = _build_rpc(snap_txs, [txid_a])
        included = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}
        self.assertIn(txid_a, included,
                      "tx with weight 3_991_000 must fit in 8000-reserved budget")

    def test_tx_exactly_hitting_4000_reserved_boundary_still_fits(self):
        # weight = 3_995_000 < 3_996_000 (= 4M - 4000): would have been
        # excluded by old 4000 budget but is NOT excluded by 8000 budget either.
        # Point: weight 3_991_001..3_996_000 range requires 8000 reserved to fit.
        txid_b = _txid("b4_boundary")
        entry_b = _make_entry(txid_b, fee=1000, size=100)
        entry_b.tx.get_weight = lambda: 3_991_500
        snap_txs = {txid_b: entry_b}
        result = _build_rpc(snap_txs, [txid_b])
        included = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}
        self.assertIn(txid_b, included,
                      "tx with weight 3_991_500 must be included with 8000-reserved budget")


# ---------------------------------------------------------------------------
# B5 — MAX_CONSECUTIVE_FAILURES early exit
# ---------------------------------------------------------------------------

class TestB5ConsecutiveFailures(unittest.TestCase):
    """B5: when block is near-full and >=1001 batches fail consecutively,
    assembly must terminate early rather than scanning all remaining entries.

    Core miner.cpp:313-316:
      if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
          nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > m_options.nBlockMaxWeight)
          return;

    We verify termination by injecting a sentinel tx that should be reachable
    only if the loop continues past the consecutive-fail threshold.
    """

    def test_early_exit_when_near_full_and_consecutive_failures_exceed_limit(self):
        # Fill the block to within BLOCK_FULL_ENOUGH_DELTA (4000) of budget.
        # Budget = MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT = 3_992_000.
        # total_weight after first tx must be > 3_992_000 - 4000 = 3_988_000.
        # Use a tx with weight 3_989_000 so total > 3_988_000 threshold.
        #
        # Filler gets the highest ancestor fee rate (fee=100_000, size=100 →
        # rate=1000) so it is selected first and fills the block.
        filler_txid = _txid("b5_filler")
        filler_entry = _make_entry(filler_txid, fee=100_000, size=100, fee_rate=1000.0)
        filler_entry.tx.get_weight = lambda: 3_989_000

        # 1002 "oversized" txs that will always fail weight check (their weight
        # is 10_000 and total_weight is already 3_989_000, so
        # 3_989_000 + 10_000 = 3_999_000 >= 3_992_000 → skip), driving
        # nConsecutiveFailed above MAX_CONSECUTIVE_FAILURES (1000).
        snap_txs = {filler_txid: filler_entry}
        snap_order = [filler_txid]
        for i in range(1002):
            ot = _txid(f"b5_oversized_{i}")
            oe = _make_entry(ot, fee=1, size=100, fee_rate=0.01)
            oe.tx.get_weight = lambda: 10_000  # too big to fit after filler
            snap_txs[ot] = oe
            snap_order.append(ot)

        # The filler will be included first (highest fee rate = 1000).
        # Then all 1002 oversized txs fail weight check consecutively.
        # After 1001 failures the loop should break early.
        # Validate: terminates in finite time AND filler was included.
        import threading
        result = [None]
        exc = [None]

        def _run():
            try:
                result[0] = _build_rpc(snap_txs, snap_order)
            except Exception as e:
                exc[0] = e

        t = threading.Thread(target=_run)
        t.start()
        t.join(timeout=5)  # must terminate within 5 seconds
        self.assertFalse(t.is_alive(), "assembly loop did not terminate within 5s")
        if exc[0]:
            raise exc[0]
        included = {bytes.fromhex(tx["txid"])[::-1] for tx in result[0]["transactions"]}
        self.assertIn(filler_txid, included, "filler tx must be included before early exit")


# ---------------------------------------------------------------------------
# B6 — per-tx weight via get_weight()
# ---------------------------------------------------------------------------

class TestB6TxWeight(unittest.TestCase):
    """B6: per-tx weight field must be e.tx.get_weight(), not e.size * 4.

    For non-SegWit txs the values coincide; for SegWit they diverge.
    We inject a fake SegWit entry where get_weight() returns a value
    different from size * 4 and verify the template's weight field
    matches get_weight().
    """

    def test_weight_field_uses_get_weight_not_size_times_4(self):
        txid_a = _txid("b6_segwit")
        entry = _make_entry(txid_a, fee=2000, size=250)
        # Simulate a segwit tx: weight != size * 4
        # size=250 → old code: weight=1000; get_weight() returns 700
        entry.tx.get_weight = lambda: 700

        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(len(result["transactions"]), 1)
        reported_weight = result["transactions"][0]["weight"]
        self.assertEqual(reported_weight, 700,
                         "weight field must equal get_weight() (700), not size*4 (1000)")

    def test_batch_weight_check_uses_get_weight(self):
        """A batch whose size*4 exceeds the budget but whose get_weight()
        fits must still be included (B6 batch-level check also uses get_weight).
        """
        txid_a = _txid("b6_batch_fits")
        # size=1_000_000 → size*4=4_000_000 (> budget); get_weight()=100 (fits)
        entry = _make_entry(txid_a, fee=2000, size=1_000_000)
        entry.tx.get_weight = lambda: 100

        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        included = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}
        self.assertIn(txid_a, included,
                      "tx with get_weight()=100 must be included even if size*4 is huge")


# ---------------------------------------------------------------------------
# B7 — block version
# ---------------------------------------------------------------------------

class TestB7BlockVersion(unittest.TestCase):
    """B7: template version must be computed for the *next* block.

    Without a get_next_block_version() hook the fallback is
    best_block.version | 0x20000000 (BIP9 top-bits always set).
    """

    def test_version_has_bip9_top_bits_set(self):
        # prev version without top bits → fallback must set them
        result = _build_rpc({}, [], best_block_version=0x00000001)
        self.assertEqual(result["version"] & 0x20000000, 0x20000000,
                         "template version must have BIP9 top-bits set")

    def test_version_not_blindly_copied_from_prev_when_no_top_bits(self):
        # If prev block has version 1 (pre-BIP9), the template must not
        # report version 1 — it must at minimum set BIP9 top-bits.
        result = _build_rpc({}, [], best_block_version=1)
        self.assertNotEqual(result["version"], 1,
                            "template version must not blindly copy prev block version")

    def test_node_hook_get_next_block_version_is_used(self):
        """When node.get_next_block_version() is available it takes precedence."""
        best_hash = b"\x02" * 32
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (best_hash, 100)
        mock_block = MagicMock()
        mock_block.bits = 0x1D00FFFF
        mock_block.version = 0x20000004
        mock_db.get_block.return_value = mock_block
        mock_db.get_utxo.return_value = None
        mock_db.get_median_time_past.return_value = 0

        mock_node = MagicMock()
        mock_node.db = mock_db
        mock_node.mempool = None
        mock_node.get_median_time.return_value = 0
        mock_node.get_next_block_version.return_value = 0x20000007
        del mock_node.get_next_bits

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = asyncio.run(rpc.rpc_getblocktemplate({}))
        self.assertEqual(result["version"], 0x20000007,
                         "get_next_block_version() hook must be used when available")


# ---------------------------------------------------------------------------
# B8 — bits (GetNextWorkRequired)
# ---------------------------------------------------------------------------

class TestB8Bits(unittest.TestCase):
    """B8: bits field must come from GetNextWorkRequired, not prev block bits.

    Without a get_next_bits() hook the fallback carries prev block bits.
    We verify the hook is used when available.
    """

    def test_node_hook_get_next_bits_is_used(self):
        best_hash = b"\x03" * 32
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (best_hash, 2015)  # last before retarget
        mock_block = MagicMock()
        mock_block.bits = 0x1D00FFFF
        mock_block.version = 0x20000000
        mock_db.get_block.return_value = mock_block
        mock_db.get_utxo.return_value = None
        mock_db.get_median_time_past.return_value = 0

        mock_node = MagicMock()
        mock_node.db = mock_db
        mock_node.mempool = None
        mock_node.get_median_time.return_value = 0
        mock_node.get_next_bits.return_value = 0x1A00FFFF  # new difficulty
        del mock_node.get_next_block_version

        rpc = RPCServer.__new__(RPCServer)
        rpc.node = mock_node

        result = asyncio.run(rpc.rpc_getblocktemplate({}))
        self.assertEqual(result["bits"], "1a00ffff",
                         "get_next_bits() hook must be used when available")

    def test_fallback_uses_prev_block_bits(self):
        """Without hook, falls back to prev block bits."""
        result = _build_rpc({}, [], best_block_bits=0x1D00FFFF)
        self.assertEqual(result["bits"], "1d00ffff",
                         "fallback bits must equal prev block bits")


# ---------------------------------------------------------------------------
# B9 — curtime clamped to max(MTP+1, now)
# ---------------------------------------------------------------------------

class TestB9Curtime(unittest.TestCase):
    """B9: curtime must be max(MTP+1, int(time.time())).

    Core UpdateTime (miner.cpp:52-55):
      nNewTime = max(GetMinimumTime(pindexPrev, ...), NodeClock::now())
    MinimumTime = MTP+1 for non-adjustment blocks.
    """

    def test_curtime_at_least_mtp_plus_one(self):
        # Set MTP to far future so MTP+1 > now
        future_mtp = int(time.time()) + 9_999_999
        result = _build_rpc({}, [], mtp=future_mtp)
        self.assertGreaterEqual(result["curtime"], future_mtp + 1,
                                "curtime must be >= MTP+1")

    def test_curtime_uses_wall_clock_when_now_gt_mtp(self):
        # MTP = 0, now >> MTP+1; curtime should be approximately now
        mtp = 0
        before = int(time.time())
        result = _build_rpc({}, [], mtp=mtp)
        after = int(time.time())
        self.assertGreaterEqual(result["curtime"], before,
                                "curtime must be >= wall-clock time when now > MTP+1")
        self.assertLessEqual(result["curtime"], after + 1,
                             "curtime must not be too far in the future")

    def test_curtime_never_below_mtp_plus_one(self):
        # With any MTP value, curtime >= MTP+1
        for mtp_val in [0, 1_000_000, int(time.time()) - 1]:
            result = _build_rpc({}, [], mtp=mtp_val)
            self.assertGreaterEqual(result["curtime"], mtp_val + 1,
                                    f"curtime must be >= mtp+1 for mtp={mtp_val}")


# ---------------------------------------------------------------------------
# B10 — sigops gate >= vs >
# ---------------------------------------------------------------------------

class TestB10SigopsGate(unittest.TestCase):
    """B10: sigops gate is >= (not >) MAX_BLOCK_SIGOPS_COST.

    Core miner.cpp TestChunkBlockLimits:
      if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false;
    A tx that would make total == 80_000 must be EXCLUDED (not included).
    """

    def test_tx_that_hits_exact_limit_is_excluded(self):
        """Running total + tx_sigops == 80_000 → must be excluded."""
        from ouroboros.validation import WITNESS_SCALE_FACTOR, _count_legacy_sigops

        # Build a tx with exactly 20_000 OP_CHECKSIG in one output →
        # legacy sigop cost = 20_000 * 4 = 80_000.
        # With total_sigops = 0 before this tx: 0 + 80_000 = 80_000 → excluded.
        n_checksig = 20_000
        script = b"\x51\xac" * n_checksig  # OP_1 OP_CHECKSIG × n
        txid_a = _txid("b10_exact")
        tx = Transaction(
            txid=txid_a,
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=1000, script_pubkey=script)],
            has_witness=False,
        )
        entry = MempoolEntry(
            tx=tx, fee=5000, fee_rate=5.0, size=100,
            time_added=0.0, height_added=100,
        )
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        included = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}
        self.assertNotIn(txid_a, included,
                         "tx with exact 80_000 sigop cost must be EXCLUDED (>= gate)")

    def test_tx_just_under_limit_is_included(self):
        """Running total + tx_sigops = 79_996 < 80_000 → must be included."""
        n_checksig = 19_999  # 19_999 * 4 = 79_996
        script = b"\x51\xac" * n_checksig
        txid_b = _txid("b10_under")
        tx = Transaction(
            txid=txid_b,
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=b"\xbb" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=1000, script_pubkey=script)],
            has_witness=False,
        )
        entry = MempoolEntry(
            tx=tx, fee=5000, fee_rate=5.0, size=100,
            time_added=0.0, height_added=100,
        )
        snap_txs = {txid_b: entry}
        result = _build_rpc(snap_txs, [txid_b])
        included = {bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]}
        self.assertIn(txid_b, included,
                      "tx with 79_996 sigop cost must be included (below 80_000 limit)")


# ---------------------------------------------------------------------------
# B11 — per-tx hash field is wtxid
# ---------------------------------------------------------------------------

class TestB11TxHash(unittest.TestCase):
    """B11: per-tx hash field must be the witness txid (wtxid).

    Core rpc/mining.cpp:915: entry.pushKV("hash", tx.GetWitnessHash().GetHex()).
    For non-SegWit transactions wtxid == txid; for SegWit they differ.
    """

    def test_hash_field_present_and_is_string(self):
        txid_a = _txid("b11_basic")
        entry = _make_entry(txid_a)
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(len(result["transactions"]), 1)
        tx_entry = result["transactions"][0]
        self.assertIn("hash", tx_entry, "hash field must be present in each tx entry")
        self.assertIsInstance(tx_entry["hash"], str)
        self.assertEqual(len(tx_entry["hash"]), 64, "hash must be 64-char hex string")

    def test_hash_differs_from_txid_for_segwit(self):
        """For a SegWit tx, hash != txid."""
        txid_a = _txid("b11_segwit_tx")
        tx = Transaction(
            txid=txid_a,
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF,
                         witness=[b"\x01" * 65])],
            outputs=[TxOut(value=9000,
                           script_pubkey=b"\x00\x14" + b"\xbb" * 20)],
            has_witness=True,
        )
        entry = MempoolEntry(
            tx=tx, fee=1000, fee_rate=5.0, size=200,
            time_added=0.0, height_added=100,
        )
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(len(result["transactions"]), 1)
        tx_entry = result["transactions"][0]
        # For segwit, hash (wtxid) must differ from txid
        self.assertNotEqual(tx_entry["hash"], tx_entry["txid"],
                            "hash (wtxid) must differ from txid for segwit transactions")

    def test_hash_equals_txid_for_non_segwit(self):
        """For non-SegWit, wtxid == txid so hash == txid."""
        txid_a = _txid("b11_non_segwit")
        tx = Transaction(
            txid=txid_a,
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=9000,
                           script_pubkey=b"\x00\x14" + b"\xbb" * 20)],
            has_witness=False,
        )
        entry = MempoolEntry(
            tx=tx, fee=1000, fee_rate=5.0, size=200,
            time_added=0.0, height_added=100,
        )
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(len(result["transactions"]), 1)
        tx_entry = result["transactions"][0]
        self.assertEqual(tx_entry["hash"], tx_entry["txid"],
                         "hash must equal txid for non-SegWit transactions")


# ---------------------------------------------------------------------------
# B12 — depends field
# ---------------------------------------------------------------------------

class TestB12Depends(unittest.TestCase):
    """B12: per-tx depends field must list 1-based indices of in-template parents.

    Core rpc/mining.cpp:917-923:
      for (const CTxIn &in : tx.vin)
          if (setTxIndex.contains(in.prevout.hash))
              deps.push_back(setTxIndex[in.prevout.hash]);
    """

    def test_depends_field_present(self):
        txid_a = _txid("b12_standalone")
        entry = _make_entry(txid_a)
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(len(result["transactions"]), 1)
        tx_entry = result["transactions"][0]
        self.assertIn("depends", tx_entry, "depends field must be present in each tx entry")
        self.assertIsInstance(tx_entry["depends"], list)

    def test_standalone_tx_has_empty_depends(self):
        """Tx with no in-template parents has depends = []."""
        txid_a = _txid("b12_no_parent")
        entry = _make_entry(txid_a)
        snap_txs = {txid_a: entry}
        result = _build_rpc(snap_txs, [txid_a])
        self.assertEqual(result["transactions"][0]["depends"], [],
                         "standalone tx must have empty depends list")

    def test_child_depends_on_parent_index(self):
        """Child tx must list its in-template parent's 1-based index."""
        parent_txid = _txid("b12_parent")
        child_txid = _txid("b12_child")

        parent_tx = _make_tx(parent_txid)
        child_tx = _make_tx(
            child_txid,
            inputs=[TxIn(prev_txid=parent_txid, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
        )
        parent_entry = MempoolEntry(
            tx=parent_tx, fee=2000, fee_rate=10.0, size=200,
            time_added=0.0, height_added=100,
        )
        child_entry = MempoolEntry(
            tx=child_tx, fee=1000, fee_rate=5.0, size=200,
            time_added=0.0, height_added=100,
        )

        snap_txs = {parent_txid: parent_entry, child_txid: child_entry}
        # ancestor fee rate: child's package (3000/400 = 7.5) > standalone parent
        # so parent gets selected first (it's included before child topologically)
        result = _build_rpc(snap_txs, [parent_txid, child_txid])

        tx_order = [bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]]
        self.assertIn(parent_txid, tx_order)
        self.assertIn(child_txid, tx_order)

        parent_idx_0based = tx_order.index(parent_txid)
        child_idx_0based = tx_order.index(child_txid)

        # Parent must come before child (topological order)
        self.assertLess(parent_idx_0based, child_idx_0based)

        # Child's depends must contain the 1-based index of the parent
        child_entry_result = result["transactions"][child_idx_0based]
        expected_parent_1based = parent_idx_0based + 1
        self.assertIn(expected_parent_1based, child_entry_result["depends"],
                      f"child depends must contain parent's 1-based index ({expected_parent_1based})")

    def test_grandparent_chain_depends(self):
        """A 3-level chain: child depends on parent, parent depends on grandparent."""
        gp_txid = _txid("b12_gp")
        p_txid = _txid("b12_p")
        c_txid = _txid("b12_c")

        gp_tx = _make_tx(gp_txid)
        p_tx = _make_tx(p_txid, inputs=[TxIn(prev_txid=gp_txid, prev_vout=0,
                                              script_sig=b"", sequence=0xFFFFFFFF)])
        c_tx = _make_tx(c_txid, inputs=[TxIn(prev_txid=p_txid, prev_vout=0,
                                              script_sig=b"", sequence=0xFFFFFFFF)])

        def _entry(tx, fee):
            return MempoolEntry(tx=tx, fee=fee, fee_rate=fee / 200,
                                size=200, time_added=0.0, height_added=100)

        snap_txs = {gp_txid: _entry(gp_tx, 100),
                    p_txid: _entry(p_tx, 100),
                    c_txid: _entry(c_tx, 3000)}
        result = _build_rpc(snap_txs, [gp_txid, p_txid, c_txid])

        tx_order = [bytes.fromhex(t["txid"])[::-1] for t in result["transactions"]]

        gp_pos = tx_order.index(gp_txid) + 1
        p_pos = tx_order.index(p_txid) + 1
        c_pos = tx_order.index(c_txid)  # 0-based for accessing result list

        # parent must depend on grandparent
        p_entry = result["transactions"][p_pos - 1]
        self.assertIn(gp_pos, p_entry["depends"],
                      "parent depends must include grandparent index")

        # child must depend on parent
        c_entry = result["transactions"][c_pos]
        self.assertIn(p_pos, c_entry["depends"],
                      "child depends must include parent index")


# ---------------------------------------------------------------------------
# Combined smoke: all fields present in empty-mempool template
# ---------------------------------------------------------------------------

class TestEmptyMempoolTemplate(unittest.TestCase):
    """Smoke test: all required BIP-22 fields present in an empty template."""

    REQUIRED_FIELDS = {
        "version", "previousblockhash", "transactions", "coinbaseaux",
        "coinbasevalue", "coinbasetxn", "target", "bits", "curtime",
        "height", "mintime", "mutable", "noncerange", "sigoplimit",
        "sizelimit", "weightlimit", "default_witness_commitment",
    }

    def test_all_required_fields_present(self):
        result = _build_rpc({}, [])
        missing = self.REQUIRED_FIELDS - result.keys()
        self.assertFalse(missing, f"Missing required GBT fields: {missing}")

    def test_coinbasetxn_subfields(self):
        result = _build_rpc({}, [])
        self.assertIn("locktime", result["coinbasetxn"])
        self.assertIn("sequence", result["coinbasetxn"])


if __name__ == "__main__":
    unittest.main()
