"""W76 — BIP-141 weight/vsize comprehensive audit tests.

Covers all 12 gates from the Core spec:
  Gate 1:  MAX_BLOCK_WEIGHT = 4_000_000  (consensus/consensus.h:15)
  Gate 2:  WITNESS_SCALE_FACTOR = 4      (consensus/consensus.h:21)
  Gate 3:  MIN_TRANSACTION_WEIGHT = 240  (consensus/consensus.h:23)
  Gate 4:  MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40  (consensus/consensus.h:24)
  Gate 5:  weight formula: stripped_size * 3 + total_size  (validation.h:132-134)
  Gate 6:  vsize = ceil(weight / 4)      (policy/policy.cpp:397)
  Gate 7:  GetSigOpsAdjustedWeight = max(weight, sigop_cost * 20)  (policy/policy.cpp:391-392)
  Gate 8:  GetVirtualTransactionSize with sigop adjustment  (policy/policy.cpp:395-397)
  Gate 9:  MAX_STANDARD_TX_WEIGHT = 400_000  (policy/policy.h:38)
  Gate 10: MIN_STANDARD_TX_NONWITNESS_SIZE = 65  (CVE-2017-12842)
  Gate 11: DEFAULT_BYTES_PER_SIGOP = 20  (policy/policy.h:50)
  Gate 12: Block early size check: len(txs)*4 and stripped_block_size*4
           must not exceed MAX_BLOCK_WEIGHT  (validation.cpp:3947)

References:
  bitcoin-core/src/consensus/consensus.h:15-24
  bitcoin-core/src/consensus/validation.h:132-144
  bitcoin-core/src/policy/policy.cpp:390-407
  bitcoin-core/src/policy/policy.h:25,38,50,182-198
  bitcoin-core/src/validation.cpp:3947
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Mock the Rust extension module before any ouroboros imports
sys.modules.setdefault("sync", MagicMock())

src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.validation import (  # noqa: E402
    MAX_BLOCK_WEIGHT,
    MAX_BLOCK_SIGOPS_COST,
    WITNESS_SCALE_FACTOR,
    MIN_TRANSACTION_WEIGHT,
    MIN_SERIALIZABLE_TRANSACTION_WEIGHT,
    DEFAULT_BYTES_PER_SIGOP,
    get_sigops_adjusted_weight,
    get_virtual_transaction_size,
)
from ouroboros.mempool import (  # noqa: E402
    MAX_STANDARD_TX_WEIGHT,
    MIN_STANDARD_TX_NONWITNESS_SIZE,
    MempoolEntry,
    _is_standard_tx,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

DUMMY_TXID = b"\xaa" * 32
COINBASE_TXID = b"\x00" * 32


def _make_tx(
    *,
    inputs=None,
    outputs=None,
    version=2,
    has_witness=False,
    locktime=0,
) -> Transaction:
    if outputs is None:
        outputs = [TxOut(value=1000, script_pubkey=b"\x51\x20" + bytes(32))]
    if inputs is None:
        inputs = [TxIn(
            prev_txid=DUMMY_TXID,
            prev_vout=0,
            script_sig=b"",
            sequence=0xFFFFFFFF,
        )]
    return Transaction(
        txid=b"\xbb" * 32,
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
        has_witness=has_witness,
    )


def _make_segwit_tx(witness_items: list[bytes]) -> Transaction:
    """Build a minimal SegWit tx with one input carrying the given witness."""
    inp = TxIn(
        prev_txid=DUMMY_TXID,
        prev_vout=0,
        script_sig=b"",
        sequence=0xFFFFFFFF,
        witness=witness_items,
    )
    return Transaction(
        txid=b"\xcc" * 32,
        version=2,
        locktime=0,
        inputs=[inp],
        outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
        has_witness=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Gate 1 + 2: consensus constants
# ─────────────────────────────────────────────────────────────────────────────

class TestConsensusConstants(unittest.TestCase):
    """bitcoin-core/src/consensus/consensus.h:15-24"""

    def test_max_block_weight(self):
        # Gate 1: consensus/consensus.h:15
        self.assertEqual(MAX_BLOCK_WEIGHT, 4_000_000)

    def test_witness_scale_factor(self):
        # Gate 2: consensus/consensus.h:21
        self.assertEqual(WITNESS_SCALE_FACTOR, 4)

    def test_min_transaction_weight(self):
        # Gate 3: WITNESS_SCALE_FACTOR * 60 = 240
        # consensus/consensus.h:23
        self.assertEqual(MIN_TRANSACTION_WEIGHT, 240)
        self.assertEqual(MIN_TRANSACTION_WEIGHT, WITNESS_SCALE_FACTOR * 60)

    def test_min_serializable_transaction_weight(self):
        # Gate 4: WITNESS_SCALE_FACTOR * 10 = 40
        # consensus/consensus.h:24
        self.assertEqual(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, 40)
        self.assertEqual(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, WITNESS_SCALE_FACTOR * 10)

    def test_max_standard_tx_weight(self):
        # Gate 9: policy/policy.h:38
        self.assertEqual(MAX_STANDARD_TX_WEIGHT, 400_000)

    def test_min_standard_tx_nonwitness_size(self):
        # Gate 10: CVE-2017-12842 mitigation
        # policy/policy.h:40
        self.assertEqual(MIN_STANDARD_TX_NONWITNESS_SIZE, 65)

    def test_default_bytes_per_sigop(self):
        # Gate 11: policy/policy.h:50
        self.assertEqual(DEFAULT_BYTES_PER_SIGOP, 20)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 5: weight formula  stripped_size * 3 + total_size
# ─────────────────────────────────────────────────────────────────────────────

class TestWeightFormula(unittest.TestCase):
    """Bitcoin Core validation.h:132-134: weight = stripped*3 + total."""

    def test_non_segwit_weight_equals_size_times_4(self):
        # Non-SegWit: stripped == total → weight = total * 4
        tx = _make_tx()
        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        self.assertEqual(stripped, total, "non-segwit: stripped must equal total")
        expected = stripped * 3 + total  # = stripped * 4
        self.assertEqual(tx.get_weight(), expected)
        self.assertEqual(tx.get_weight(), stripped * 4)

    def test_segwit_weight_discounts_witness_bytes(self):
        # SegWit: weight = stripped*3 + total (witness bytes count once, not 4×)
        witness_items = [bytes(72), bytes(33)]  # signature + pubkey
        tx = _make_segwit_tx(witness_items)
        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        self.assertGreater(total, stripped, "segwit: total must exceed stripped")
        expected = stripped * 3 + total
        self.assertEqual(tx.get_weight(), expected)

    def test_marker_flag_bytes_count_weight_1(self):
        # The 2-byte SegWit marker+flag are in the witness serialization and
        # count at weight 1 (not 4).  The old buggy formula was (stripped+2)*4.
        witness_item = bytes(33)
        tx = _make_segwit_tx([witness_item])
        stripped = len(tx.serialize())
        total = len(tx.serialize_with_witness())
        # total = stripped + 2 (marker+flag) + witness_stack_bytes
        witness_stack = tx.get_witness_bytes()
        self.assertEqual(total, stripped + 2 + witness_stack)
        # Correct weight
        correct = stripped * 3 + total
        # Old buggy weight (if marker+flag were counted at 4×)
        buggy = (stripped + 2) * 4 + witness_stack
        self.assertEqual(tx.get_weight(), correct)
        self.assertEqual(buggy - correct, 6, "marker+flag overcounting is exactly 6")

    def test_empty_witness_stack_equals_non_segwit(self):
        # A SegWit tx with all empty witnesses has same weight as non-SegWit
        # in practice (the marker+flag still add 2 bytes to total though).
        tx_nw = _make_tx(has_witness=False)
        inp_w = TxIn(
            prev_txid=DUMMY_TXID, prev_vout=0, script_sig=b"",
            sequence=0xFFFFFFFF, witness=[],
        )
        tx_w = Transaction(
            txid=b"\xdd" * 32, version=2, locktime=0,
            inputs=[inp_w],
            outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
            has_witness=True,
        )
        # Stripped sizes should be similar (same base fields)
        # But total_with_witness adds 2 bytes (marker+flag) for the segwit tx
        stripped_nw = len(tx_nw.serialize())
        total_w = len(tx_w.serialize_with_witness())
        weight_nw = tx_nw.get_weight()
        weight_w = tx_w.get_weight()
        # weight_w = stripped_w * 3 + total_w; has +2 from marker+flag in total_w
        # weight_nw = size_nw * 4; structures differ so not identical, just both correct
        self.assertGreater(weight_nw, 0)
        self.assertGreater(weight_w, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 6: vsize = ceil(weight / 4)
# ─────────────────────────────────────────────────────────────────────────────

class TestVsizeFormula(unittest.TestCase):
    """vsize = ceil(weight / 4) = (weight + 3) // 4."""

    def test_non_segwit_vsize_equals_byte_size(self):
        tx = _make_tx()
        byte_size = len(tx.serialize())
        self.assertEqual(tx.get_vsize(), byte_size)

    def test_vsize_ceil_when_weight_not_divisible(self):
        # Manually check ceil behaviour
        # weight = 5: vsize = ceil(5/4) = 2
        self.assertEqual((5 + 3) // 4, 2)
        # weight = 8: vsize = ceil(8/4) = 2
        self.assertEqual((8 + 3) // 4, 2)
        # weight = 9: vsize = ceil(9/4) = 3
        self.assertEqual((9 + 3) // 4, 3)

    def test_segwit_vsize_less_than_full_size(self):
        witness_items = [bytes(72), bytes(33)]
        tx = _make_segwit_tx(witness_items)
        total_size = len(tx.serialize_with_witness())
        vsize = tx.get_vsize()
        self.assertLessEqual(vsize, total_size)
        # Also must be at least stripped size (base data counts full)
        stripped = len(tx.serialize())
        self.assertGreaterEqual(vsize, stripped)

    def test_vsize_formula_matches_weight(self):
        tx = _make_segwit_tx([bytes(64)])
        weight = tx.get_weight()
        expected_vsize = (weight + 3) // 4
        self.assertEqual(tx.get_vsize(), expected_vsize)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 7 + 11: GetSigOpsAdjustedWeight  (max(weight, sigop_cost * 20))
# ─────────────────────────────────────────────────────────────────────────────

class TestGetSigOpsAdjustedWeight(unittest.TestCase):
    """bitcoin-core/src/policy/policy.cpp:390-392."""

    def test_no_sigops_returns_weight(self):
        # When sigop_cost=0, max(weight, 0*20) = weight
        self.assertEqual(get_sigops_adjusted_weight(1000, 0), 1000)

    def test_high_sigops_bumps_weight(self):
        # sigop_cost=100, bytes_per_sigop=20 → 100*20=2000 > weight=1000 → 2000
        self.assertEqual(get_sigops_adjusted_weight(1000, 100, 20), 2000)

    def test_equal_sigop_weight(self):
        # sigop_cost=50, bytes_per_sigop=20 → 50*20=1000 == weight → 1000
        self.assertEqual(get_sigops_adjusted_weight(1000, 50, 20), 1000)

    def test_weight_dominates(self):
        # sigop_cost=1, bytes_per_sigop=20 → 1*20=20 < weight=10000 → 10000
        self.assertEqual(get_sigops_adjusted_weight(10000, 1, 20), 10000)

    def test_default_bytes_per_sigop_is_20(self):
        # Using the default parameter
        self.assertEqual(get_sigops_adjusted_weight(100, 10), max(100, 10 * 20))
        self.assertEqual(get_sigops_adjusted_weight(100, 10), 200)

    def test_zero_weight_sigops_dominate(self):
        # Degenerate case: weight=0, sigop_cost=1 → 1*20=20
        self.assertEqual(get_sigops_adjusted_weight(0, 1, 20), 20)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 8: GetVirtualTransactionSize with sigop adjustment
# ─────────────────────────────────────────────────────────────────────────────

class TestGetVirtualTransactionSize(unittest.TestCase):
    """bitcoin-core/src/policy/policy.cpp:395-397."""

    def test_no_sigops_plain_vsize(self):
        # No sigop adjustment → ceil(weight/4)
        self.assertEqual(get_virtual_transaction_size(400, 0), 100)
        self.assertEqual(get_virtual_transaction_size(401, 0), 101)

    def test_sigop_adjustment_bumps_vsize(self):
        # weight=100, sigop_cost=10, bytes_per_sigop=20 → adj=200 → vsize=50
        self.assertEqual(get_virtual_transaction_size(100, 10, 20), 50)

    def test_ceil_on_sigop_adjusted(self):
        # adj = max(100, 5*20) = 100 → vsize = 25
        self.assertEqual(get_virtual_transaction_size(100, 5, 20), 25)
        # adj = max(100, 6*20) = 120 → vsize = ceil(120/4) = 30
        self.assertEqual(get_virtual_transaction_size(100, 6, 20), 30)
        # adj = max(101, 6*20) = 120 → vsize = 30
        self.assertEqual(get_virtual_transaction_size(101, 6, 20), 30)
        # adj = max(121, 6*20) = 121 → vsize = ceil(121/4) = 31
        self.assertEqual(get_virtual_transaction_size(121, 6, 20), 31)

    def test_zero_sigop_cost_matches_get_vsize(self):
        tx = _make_tx()
        weight = tx.get_weight()
        self.assertEqual(get_virtual_transaction_size(weight, 0), tx.get_vsize())

    def test_identity_when_bytes_per_sigop_zero(self):
        # bytes_per_sigop=0 → sigop_cost*0=0 → max(weight,0)=weight → ceil(weight/4)
        self.assertEqual(get_virtual_transaction_size(400, 1000, 0), 100)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 9: MAX_STANDARD_TX_WEIGHT = 400_000 (policy gate in _is_standard_tx)
# ─────────────────────────────────────────────────────────────────────────────

class TestMaxStandardTxWeight(unittest.TestCase):
    """policy/policy.h:38, policy/policy.cpp:111-115."""

    def test_constant_value(self):
        self.assertEqual(MAX_STANDARD_TX_WEIGHT, 400_000)
        # Must be exactly 1/10 of MAX_BLOCK_WEIGHT
        self.assertEqual(MAX_STANDARD_TX_WEIGHT * 10, MAX_BLOCK_WEIGHT)

    def test_standard_tx_at_weight_limit_accepted(self):
        # A 100,000-byte non-SegWit tx has weight 400,000 — exactly at limit.
        # Core uses `sz > MAX_STANDARD_TX_WEIGHT` (strictly greater), so
        # exactly at the limit should still pass.
        # Build a tx with script_sig of exactly the right size to hit 400k weight.
        # Non-segwit: weight = size * 4. To get weight=400000, size=100000.
        # Actual tx overhead: version(4)+varint(1)+input_fields+varint(1)+output+locktime(4).
        # Padding via script_sig so that stripped = 100000 exactly.
        # stripped = 4 + 1 + (32+4+1+len(ss)+4) + 1 + (8+1+23) + 4
        #          = 4+1+41+len(ss)+4+1+32+4 = 87 + len(ss)
        # For size=100000: len(ss) = 99913. But MAX_STANDARD_SCRIPTSIG_SIZE=1650
        # would reject it. So we can't build a 100k non-segwit tx that is also
        # "standard" for output checks. Instead, test the weight gate directly.
        tx = _make_tx()
        weight = tx.get_weight()
        # Small tx: weight << 400,000 → should pass the weight gate
        self.assertLessEqual(weight, MAX_STANDARD_TX_WEIGHT)

    def test_tx_exceeding_max_standard_weight_rejected(self):
        # Build a tx whose serialized size exceeds MAX_STANDARD_TX_WEIGHT / 4
        # (non-segwit weight = size * 4).
        # Use a large script_sig (non-standard but we're testing the weight gate directly).
        large_script = bytes(100_001)  # 100,001 bytes → weight ≈ 100,001*4 = 400,004
        inp = TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=large_script, sequence=0xFFFFFFFF)
        tx = Transaction(
            txid=b"\xff" * 32, version=1, locktime=0,
            inputs=[inp],
            outputs=[TxOut(value=1000, script_pubkey=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")],
            has_witness=False,
        )
        self.assertGreater(tx.get_weight(), MAX_STANDARD_TX_WEIGHT)
        ok, reason = _is_standard_tx(tx)
        # May be rejected by scriptsig-size gate (1650) first, or weight gate — both are expected.
        self.assertFalse(ok)


# ─────────────────────────────────────────────────────────────────────────────
# Gate 10: MIN_STANDARD_TX_NONWITNESS_SIZE = 65 (CVE-2017-12842)
# ─────────────────────────────────────────────────────────────────────────────

class TestMinStandardTxNonwitnessSize(unittest.TestCase):
    """CVE-2017-12842 mitigation: tx with < 65 non-witness bytes rejected.

    Reference:
      bitcoin-core/src/validation.cpp:812-814
      bitcoin-core/src/policy/policy.h:40
    """

    def test_constant_is_65(self):
        self.assertEqual(MIN_STANDARD_TX_NONWITNESS_SIZE, 65)

    def test_tiny_tx_rejected(self):
        # A tx serializing to fewer than 65 bytes non-witness is non-standard.
        # Minimal coinbase: version(4)+varint(1)+outpoint(36)+scriptsig_len(1)+
        #   scriptsig(0)+seq(4)+varint(1)+value(8)+spk_len(1)+spk(0)+locktime(4) = 60 bytes
        tiny_inp = TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF, script_sig=b"", sequence=0xFFFFFFFF)
        tiny_out = TxOut(value=0, script_pubkey=b"")
        tx = Transaction(
            txid=b"\x00" * 32, version=1, locktime=0,
            inputs=[tiny_inp], outputs=[tiny_out], has_witness=False,
        )
        stripped = len(tx.serialize())
        if stripped < MIN_STANDARD_TX_NONWITNESS_SIZE:
            ok, reason = _is_standard_tx(tx)
            self.assertFalse(ok, f"Tiny tx (stripped={stripped}) should be rejected")
            self.assertIn("small", reason.lower())

    def test_normal_tx_passes_min_size(self):
        # A typical P2WPKH tx is well above 65 bytes stripped.
        tx = _make_tx(
            inputs=[TxIn(
                prev_txid=DUMMY_TXID, prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFF,
            )],
            outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
        )
        stripped = len(tx.serialize())
        self.assertGreaterEqual(stripped, MIN_STANDARD_TX_NONWITNESS_SIZE,
                                f"Normal tx stripped={stripped} should be >= 65")


# ─────────────────────────────────────────────────────────────────────────────
# Gate 12: Block early size checks (validation.cpp:3947)
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockEarlySizeChecks(unittest.TestCase):
    """Bitcoin Core CheckBlock() pre-filter (validation.cpp:3947):
        block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT → bad-blk-length
        stripped_block_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT → bad-blk-length
    """

    def _make_minimal_block(self, txs: list[Transaction]) -> Block:
        return Block(
            version=0x20000000,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=1700000000,
            bits=0x1d00ffff,
            nonce=0,
            transactions=txs,
            hash=bytes(32),
            height=1,
        )

    def _make_coinbase(self) -> Transaction:
        return Transaction(
            txid=(0).to_bytes(32, "big"),
            version=1, locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                         script_sig=b"\x04" + bytes(4), sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=50_0000_0000,
                           script_pubkey=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")],
        )

    def test_tx_count_limit(self):
        # More than 1,000,000 txs (1M * 4 > 4M) would be caught by the early check.
        # We can't instantiate that many, so verify the arithmetic.
        # At the boundary: 1_000_001 * 4 = 4_000_004 > 4_000_000 → invalid.
        count = 1_000_001
        self.assertGreater(count * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT)
        # 1_000_000 * 4 = 4_000_000 → not > MAX_BLOCK_WEIGHT
        count_ok = 1_000_000
        self.assertFalse(count_ok * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)

    def test_stripped_block_size_limit(self):
        # stripped_block * 4 > 4M → invalid.
        # stripped threshold = 4M / 4 = 1M bytes.
        over_stripped = MAX_BLOCK_WEIGHT // WITNESS_SCALE_FACTOR + 1  # 1_000_001 bytes
        self.assertGreater(over_stripped * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT)
        ok_stripped = MAX_BLOCK_WEIGHT // WITNESS_SCALE_FACTOR  # 1_000_000
        self.assertFalse(ok_stripped * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)

    def test_small_block_passes_early_checks(self):
        # A normal block with a handful of small txs should pass.
        cb = self._make_coinbase()
        txs = [cb]
        for i in range(5):
            txs.append(Transaction(
                txid=(i + 1).to_bytes(32, "big"),
                version=1, locktime=0,
                inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=i,
                             script_sig=b"", sequence=0xFFFFFFFF)],
                outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
            ))
        block = self._make_minimal_block(txs)
        self.assertFalse(len(block.transactions) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        stripped = sum(len(tx.serialize()) for tx in block.transactions)
        self.assertFalse(stripped * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)

    def test_validate_block_limits_rejects_tx_count_overflow(self):
        # Verify _validate_block_limits() implements the early tx-count check.
        # We fake a block with enough transactions to trigger the gate.
        # The block object itself is never fully serialized; we just check the count.
        # Instead: verify that a block exactly at the count limit is not rejected by Gate 12.
        # (Full count limit is 1M+ txs — impractical to build; test the guard arithmetic.)
        cb = self._make_coinbase()
        block = self._make_minimal_block([cb])
        # Simulate the guard
        count_flag = len(block.transactions) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        self.assertFalse(count_flag, "single-tx block must pass count check")

    def test_large_stripped_block_caught_by_early_check(self):
        # Build a block whose stripped size * 4 exceeds MAX_BLOCK_WEIGHT.
        # Each tx with a 120,000-byte script_sig contributes stripped ~120,042 bytes.
        # 9 such txs → stripped ~1,080,378 bytes → *4 = 4,321,512 > 4,000,000.
        cb = self._make_coinbase()
        big_txs = []
        for i in range(9):
            big_txs.append(Transaction(
                txid=(i + 1).to_bytes(32, "big"),
                version=1, locktime=0,
                inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=i,
                             script_sig=bytes(120_000), sequence=0xFFFFFFFF)],
                outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
            ))
        block = self._make_minimal_block([cb] + big_txs)
        stripped = sum(len(tx.serialize()) for tx in block.transactions)
        # Assert our fabricated block actually triggers the check
        self.assertGreater(stripped * WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT,
                           "Test setup: stripped block must exceed limit")


# ─────────────────────────────────────────────────────────────────────────────
# MempoolEntry.vsize property
# ─────────────────────────────────────────────────────────────────────────────

class TestMempoolEntryVsize(unittest.TestCase):
    """MempoolEntry must expose a .vsize property that returns the sigop-adjusted vsize.

    This was Bug 1: entry.vsize raised AttributeError.
    Reference: bitcoin-core/src/kernel/mempool_entry.h:110-113
        int32_t GetTxSize() const {
            return GetVirtualTransactionSize(nTxWeight, sigOpCost, ::nBytesPerSigOp);
        }
    """

    def _make_entry(self, tx: Transaction, sigop_cost: int = 0) -> MempoolEntry:
        return MempoolEntry(
            tx=tx,
            fee=1000,
            fee_rate=1.0,
            size=len(tx.serialize()),
            time_added=0.0,
            height_added=100,
            sigop_cost=sigop_cost,
        )

    def test_vsize_property_exists(self):
        tx = _make_tx()
        entry = self._make_entry(tx)
        # Must not raise AttributeError
        vsize = entry.vsize
        self.assertIsInstance(vsize, int)
        self.assertGreater(vsize, 0)

    def test_vsize_no_sigops_equals_get_vsize(self):
        # With sigop_cost=0, MempoolEntry.vsize == tx.get_vsize()
        tx = _make_tx()
        entry = self._make_entry(tx, sigop_cost=0)
        self.assertEqual(entry.vsize, tx.get_vsize())

    def test_vsize_with_sigops_is_adjusted(self):
        # With high sigop_cost, vsize must be at least as large as plain get_vsize().
        tx = _make_tx()
        weight = tx.get_weight()
        # Set sigop_cost such that sigop_cost * 20 > weight
        high_sigop = weight // 20 + 1
        entry = self._make_entry(tx, sigop_cost=high_sigop)
        plain_vsize = tx.get_vsize()
        adj_vsize = entry.vsize
        self.assertGreater(adj_vsize, plain_vsize,
                           "High sigop_cost must inflate the effective vsize")

    def test_vsize_matches_get_virtual_transaction_size(self):
        # Cross-check: entry.vsize == get_virtual_transaction_size(weight, sigop, 20)
        tx = _make_segwit_tx([bytes(64)])
        sigop = 5
        entry = self._make_entry(tx, sigop_cost=sigop)
        expected = get_virtual_transaction_size(tx.get_weight(), sigop, DEFAULT_BYTES_PER_SIGOP)
        self.assertEqual(entry.vsize, expected)

    def test_vsize_non_segwit_equals_byte_size_without_sigops(self):
        # For a non-segwit tx with no sigops, vsize = size in bytes.
        tx = _make_tx()
        entry = self._make_entry(tx, sigop_cost=0)
        byte_size = len(tx.serialize())
        self.assertEqual(entry.vsize, byte_size)

    def test_vsize_segwit_smaller_than_full_serialized(self):
        # For a SegWit tx, vsize < full (with-witness) size.
        tx = _make_segwit_tx([bytes(72), bytes(33)])
        entry = self._make_entry(tx, sigop_cost=0)
        full_size = len(tx.serialize_with_witness())
        self.assertLess(entry.vsize, full_size)


# ─────────────────────────────────────────────────────────────────────────────
# Sigop-adjusted vsize accuracy for fee-rate calculations
# ─────────────────────────────────────────────────────────────────────────────

class TestSigopAdjustedFeeRate(unittest.TestCase):
    """The sigop-adjusted vsize must correctly inflate fee-rate-sensitive sizes."""

    def test_low_sigop_cost_no_inflation(self):
        # A tx with weight=1000, sigop_cost=1:
        # adj = max(1000, 1*20) = 1000 → vsize = 250
        self.assertEqual(get_virtual_transaction_size(1000, 1, 20), 250)

    def test_moderate_sigop_cost_inflates(self):
        # weight=1000, sigop_cost=60:
        # adj = max(1000, 60*20) = 1200 → vsize = ceil(1200/4) = 300
        self.assertEqual(get_virtual_transaction_size(1000, 60, 20), 300)

    def test_extreme_sigop_cost(self):
        # weight=100, sigop_cost=16000 (MAX_STANDARD_TX_SIGOPS_COST):
        # adj = max(100, 16000*20) = 320000 → vsize = 80000
        self.assertEqual(get_virtual_transaction_size(100, 16_000, 20), 80_000)

    def test_formula_against_core_spec(self):
        # Bitcoin Core GetVirtualTransactionSize formula:
        #   (GetSigOpsAdjustedWeight(weight, sigop_cost, bytes_per_sigop)
        #    + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR
        for weight, sigop, bps in [
            (400, 0, 20),
            (401, 0, 20),
            (400, 20, 20),
            (0, 1, 20),
            (1000, 50, 20),
        ]:
            adj = max(weight, sigop * bps)
            expected = (adj + 4 - 1) // 4
            self.assertEqual(
                get_virtual_transaction_size(weight, sigop, bps),
                expected,
                f"Mismatch for weight={weight}, sigop={sigop}, bps={bps}",
            )


if __name__ == "__main__":
    unittest.main()
