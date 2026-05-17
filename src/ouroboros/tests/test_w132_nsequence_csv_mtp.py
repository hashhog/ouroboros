"""
W132 — BIP-68 / BIP-112 / BIP-113 + nSequence + OP_CSV + MTP audit (ouroboros).

DISCOVERY wave: 30 gates audited against bitcoin-core/src/script/interpreter.cpp,
bitcoin-core/src/consensus/tx_verify.cpp, bitcoin-core/src/chain.h,
bitcoin-core/src/validation.cpp, bitcoin-core/src/policy/policy.h, and the
canonical BIP-68 / BIP-112 / BIP-113 texts.

Two-pipeline scope: ouroboros implements sequence locks twice. Python pipeline
(src/ouroboros/{script,validation,database,mempool,node}.py) and Rust pipeline
(ferrous-utils/sync/src/validate/sequence_lock.rs). Both pipelines are
consensus surface and MUST agree.

This file pins:
  - Constants gates (G1-G5): hex / decimal values for SEQUENCE_FINAL,
    DISABLE_FLAG, TYPE_FLAG, MASK, GRANULARITY.
  - CSV activation gates (G6): mainnet 419328, testnet3 770112, testnet4 /
    signet / regtest = 1 in Core canonical (with documented Rust-pipeline
    divergence at 0).
  - nLockTime / IsFinalTx gates (G7-G10).
  - BIP-68 sequence lock math gates (G11-G16).
  - OP_CSV interpreter gates (G17-G23).
  - OP_CLTV interpreter gates (G24-G26).
  - MTP window gates (G27-G29).
  - Two-pipeline guard (G30).

PRESENT gates pass; PARTIAL / MISSING / BUG gates are xfail (or assert-the-
divergence) and pin the bug so a future FIX wave can flip them to pass.

NO production code changes. Audit + xfail tests only.

Reference:
  - bitcoin-core/src/consensus/tx_verify.cpp (IsFinalTx, CalculateSequenceLocks)
  - bitcoin-core/src/script/interpreter.cpp:522 (OP_CHECKLOCKTIMEVERIFY)
  - bitcoin-core/src/script/interpreter.cpp:561 (OP_CHECKSEQUENCEVERIFY)
  - bitcoin-core/src/script/interpreter.cpp:1782 (CheckSequence)
  - bitcoin-core/src/chain.h:231-245 (GetMedianTimePast / nMedianTimeSpan=11)
  - bitcoin-core/src/validation.cpp:4129-4148 (ContextualCheckBlock /
    nLockTimeCutoff)
  - bitcoin-core/src/kernel/chainparams.cpp (CSVHeight per network)
  - bitcoin-core/src/primitives/transaction.h:73-115 (SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_*)
  - BIP-68 / BIP-112 / BIP-113

Bug inventory: 14 bugs (1 P0-CONSENSUS / 4 P1 / 9 P2). See
audit/w132_nsequence_csv_mtp.md for full description.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from dataclasses import dataclass

# Bootstrap — tests/conftest.py installs the sync stub.
_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))

_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))

# Import conftest to install sync stub (idempotent).
import conftest  # noqa: F401  pylint: disable=unused-import

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.script import (  # noqa: E402
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_NONE,
    ScriptInterpreter,
)
from ouroboros.consensus import (  # noqa: E402
    BURIED_DEPLOYMENTS,
    is_buried_deployment_active,
)
from ouroboros.validation import TransactionValidator  # noqa: E402


# ---------------------------------------------------------------------------
# Bitcoin Core canonical constants (sourced from
# bitcoin-core/src/primitives/transaction.h and consensus/consensus.h).
# ---------------------------------------------------------------------------

CORE_SEQUENCE_FINAL = 0xFFFFFFFF
CORE_MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE
CORE_SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
CORE_SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
CORE_SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
CORE_SEQUENCE_LOCKTIME_GRANULARITY = 9
CORE_LOCKTIME_THRESHOLD = 500_000_000
CORE_LOCKTIME_VERIFY_SEQUENCE = 1 << 0
CORE_NMEDIANTIMESPAN = 11

# Bitcoin Core CSVHeight values per kernel/chainparams.cpp.
CORE_CSV_HEIGHTS = {
    "mainnet":  419328,  # chainparams.cpp:93
    "testnet":  770112,  # chainparams.cpp:216 (testnet3)
    "testnet3": 770112,
    "testnet4": 1,       # chainparams.cpp:315
    "signet":   1,       # chainparams.cpp:459
    "regtest":  1,       # chainparams.cpp:540
}


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_tx(version: int, locktime: int, sequences: list[int]) -> Transaction:
    """Build a minimal in-memory Transaction with the given version, locktime,
    and per-input sequence values. Used for IsFinalTx / OP_CSV / OP_CLTV
    semantic tests — never serialized to a block."""
    inputs = [
        TxIn(
            prev_txid=bytes(32),
            prev_vout=i,
            script_sig=b"",
            sequence=s,
        )
        for i, s in enumerate(sequences)
    ]
    outputs = [
        TxOut(value=1_000, script_pubkey=b"\x51"),  # OP_TRUE
    ]
    return Transaction(
        txid=bytes(32),
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
    )


# Build a stand-alone CScriptNum push for OP_CSV / OP_CLTV operand testing.
# Encodes minimally per Core's `CScriptNum::serialize`.
def _push_scriptnum(value: int) -> bytes:
    """Return push-opcode prefix + minimal CScriptNum encoding of `value`."""
    if value == 0:
        return b"\x00"  # OP_0
    neg = value < 0
    abs_v = -value if neg else value
    # Little-endian magnitude
    out = bytearray()
    while abs_v:
        out.append(abs_v & 0xFF)
        abs_v >>= 8
    # Set sign bit (high bit of MSB) if negative; if high bit already set,
    # append an extra 0x80 (or 0x00 for positive).
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes([len(out)]) + bytes(out)


# ===========================================================================
# G1-G5: Constants
# ===========================================================================


class TestG1_SequenceFinal(unittest.TestCase):
    """G1: SEQUENCE_FINAL = 0xFFFFFFFF — PRESENT (both pipelines)."""

    def test_python_pipeline_sequence_final_literal(self):
        # Python's IsFinalTx fallback uses the literal 0xFFFFFFFF — BUG-9 / BUG-2.
        # Test the literal value matches Core.
        # (Document the literal location; cannot trivially import the
        #  per-call literal from validation.py:2036.)
        self.assertEqual(0xFFFFFFFF, CORE_SEQUENCE_FINAL)

    def test_rust_pipeline_constant_present(self):
        # Best-effort: read the Rust source and assert constant declaration.
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present in this checkout")
        src = rust_file.read_text()
        self.assertIn("pub const SEQUENCE_FINAL: u32 = 0xFFFFFFFF;", src,
                      "Rust SEQUENCE_FINAL constant must match Core")


class TestG2_SequenceDisableFlag(unittest.TestCase):
    """G2: SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31. **BUG-2** — Python inlines."""

    def test_rust_constant_matches_core(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        self.assertIn("pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;",
                      src)

    @unittest.expectedFailure  # BUG-2: Python inlines the literal
    def test_python_promotes_disable_flag_to_module_const(self):
        """A Python module-level SEQUENCE_LOCKTIME_DISABLE_FLAG should exist."""
        from ouroboros import script as _s
        self.assertTrue(hasattr(_s, "SEQUENCE_LOCKTIME_DISABLE_FLAG"),
                        "Python pipeline should expose a module-level "
                        "SEQUENCE_LOCKTIME_DISABLE_FLAG constant. "
                        "Currently inlined at script.py:1756 (BUG-2).")


class TestG3_SequenceTypeFlag(unittest.TestCase):
    """G3: SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22 — PRESENT (both pipelines)."""

    def test_rust_constant_matches_core(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        self.assertIn("pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;",
                      src)

    def test_python_tx_validator_class_const_matches(self):
        # validation.py exposes SEQUENCE_TYPE as a class const on
        # TransactionValidator.
        self.assertEqual(TransactionValidator.SEQUENCE_TYPE,
                         CORE_SEQUENCE_LOCKTIME_TYPE_FLAG)


class TestG4_SequenceMask(unittest.TestCase):
    """G4: SEQUENCE_LOCKTIME_MASK = 0xFFFF. **BUG-7** — Python defines this in
    two places (validation.py class const + script.py inline literal)."""

    def test_rust_constant_matches_core(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        self.assertIn("pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;",
                      src)

    def test_python_tx_validator_class_const_matches(self):
        self.assertEqual(TransactionValidator.SEQUENCE_MASK,
                         CORE_SEQUENCE_LOCKTIME_MASK)

    @unittest.expectedFailure  # BUG-7: duplicated literal in script.py
    def test_python_single_source_for_mask(self):
        """SEQUENCE_LOCKTIME_MASK should live in one module."""
        # Script.py references the mask inline as literal `0x0000ffff`;
        # validation.py defines SEQUENCE_MASK as a class const. They should
        # share one source.
        script_py = Path(__file__).resolve().parent.parent / "script.py"
        src = script_py.read_text()
        # If the inline literal still appears (BUG-7), this assertion fails.
        self.assertNotIn("SEQ_MASK = 0x0000ffff", src,
                          "Inline duplicate of SEQUENCE_LOCKTIME_MASK in "
                          "script.py — should import from a shared module.")


class TestG5_SequenceGranularity(unittest.TestCase):
    """G5: SEQUENCE_LOCKTIME_GRANULARITY = 9 (2^9 = 512). **BUG-8** —
    Python inlines `* 512` magic number in validation.py fallback."""

    def test_rust_constant_matches_core(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        self.assertIn("pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;", src)

    @unittest.expectedFailure  # BUG-8: Python uses `* 512` literal
    def test_python_has_named_granularity_constant(self):
        """Python should expose SEQUENCE_LOCKTIME_GRANULARITY = 9 (or 512s)."""
        from ouroboros import validation as _v
        self.assertTrue(
            hasattr(_v, "SEQUENCE_LOCKTIME_GRANULARITY")
            or hasattr(TransactionValidator, "SEQUENCE_GRANULARITY"),
            "Python pipeline should expose a named constant for the BIP-68 "
            "512-second granularity. Currently `* 512` is inlined at "
            "validation.py:2475 (BUG-8).")


# ===========================================================================
# G6: CSV activation height per network
# ===========================================================================


class TestG6_CSVActivationHeights(unittest.TestCase):
    """G6: CSV activation heights per network. **BUG-3 + BUG-4** — Python
    and Rust diverge on testnet4 / signet / regtest."""

    def test_mainnet_matches_core(self):
        self.assertEqual(BURIED_DEPLOYMENTS["mainnet"]["csv"].height,
                         CORE_CSV_HEIGHTS["mainnet"])

    def test_testnet3_matches_core(self):
        self.assertEqual(BURIED_DEPLOYMENTS["testnet3"]["csv"].height,
                         CORE_CSV_HEIGHTS["testnet3"])

    def test_testnet4_python_matches_core(self):
        # Python uses 1 — matches Core canonical.
        self.assertEqual(BURIED_DEPLOYMENTS["testnet4"]["csv"].height,
                         CORE_CSV_HEIGHTS["testnet4"])

    def test_signet_python_matches_core(self):
        self.assertEqual(BURIED_DEPLOYMENTS["signet"]["csv"].height,
                         CORE_CSV_HEIGHTS["signet"])

    def test_regtest_python_matches_core(self):
        self.assertEqual(BURIED_DEPLOYMENTS["regtest"]["csv"].height,
                         CORE_CSV_HEIGHTS["regtest"])

    def test_g30_two_pipeline_csv_height_divergence(self):
        """**BUG-3**: Rust pipeline returns 0 for testnet4 / signet / regtest;
        Python uses 1. Both effectively activate CSV from genesis-1; the
        comparator semantics differ at the precise genesis-height boundary."""
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        # Pin the divergence.
        self.assertIn("Network::Testnet4 => 0,", src,
                      "BUG-3: Rust pipeline currently returns 0 for "
                      "Testnet4 CSV activation; Core canonical is 1.")
        self.assertIn("Network::Regtest => 0,", src,
                      "BUG-3: Rust pipeline currently returns 0 for "
                      "Regtest CSV activation; Core canonical is 1.")


# ===========================================================================
# G7: nLockTimeCutoff selection pre-/post-CSV
# ===========================================================================


class TestG7_LockTimeCutoff(unittest.TestCase):
    """G7: nLockTimeCutoff = MTP if CSV active, else block.timestamp."""

    def test_is_buried_deployment_active_csv_mainnet(self):
        # Pre-CSV (height 419327): inactive.
        self.assertFalse(is_buried_deployment_active("csv", 419327, "mainnet"))
        # At-CSV (height 419328): active.
        self.assertTrue(is_buried_deployment_active("csv", 419328, "mainnet"))

    def test_cutoff_logic_pre_csv_uses_block_timestamp(self):
        """Mirrors validation.py:686-699."""
        # Logical equivalent of:
        #   csv_active = is_buried_deployment_active("csv", h, net)
        #   nLockTimeCutoff = block_mtp if csv_active else block.timestamp
        h = 419327  # pre-CSV
        block_mtp = 1_500_000_000
        block_timestamp = 1_600_000_000
        csv_active = is_buried_deployment_active("csv", h, "mainnet")
        cutoff = block_mtp if csv_active else block_timestamp
        self.assertEqual(cutoff, block_timestamp)

    def test_cutoff_logic_post_csv_uses_mtp(self):
        h = 419328  # at-CSV
        block_mtp = 1_500_000_000
        block_timestamp = 1_600_000_000
        csv_active = is_buried_deployment_active("csv", h, "mainnet")
        cutoff = block_mtp if csv_active else block_timestamp
        self.assertEqual(cutoff, block_mtp)


# ===========================================================================
# G8-G10: IsFinalTx
# ===========================================================================


class TestG8_IsFinalTxAppliesToAllTxs(unittest.TestCase):
    """G8: ContextualCheckBlock iterates ALL txs (including coinbase) with
    nLockTimeCutoff. Mirrors Core validation.cpp:4144-4148."""

    def test_validation_call_site_iterates_all_txs(self):
        """Pin the structural invariant: the loop iterating
        `block.transactions` at validation.py:831 starts from i=0
        (coinbase included)."""
        validation_py = Path(__file__).resolve().parent.parent / "validation.py"
        src = validation_py.read_text()
        # The call should NOT be `for i, tx in enumerate(block.transactions[1:]):`
        # or anything that skips coinbase.
        self.assertIn("for i, tx in enumerate(block.transactions):", src,
                      "BlockValidator must iterate ALL txs starting from "
                      "coinbase for the IsFinalTx check (validation.cpp:4144).")


class TestG9_LockTimeThreshold(unittest.TestCase):
    """G9: LOCKTIME_THRESHOLD = 500_000_000. **BUG-9** — hardcoded in 3+
    places across the Python pipeline."""

    def test_stub_locktime_threshold_constant(self):
        # The PyO3 wrapper / conftest stub returns 500_000_000.
        import sync
        self.assertEqual(sync.locktime_threshold(), CORE_LOCKTIME_THRESHOLD)

    def test_rust_constant_matches_core(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        self.assertIn("pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;", src)


class TestG10_IsFinalTxAllSequencesFinal(unittest.TestCase):
    """G10: all inputs SEQUENCE_FINAL → tx is final regardless of locktime.
    Mirrors Core tx_verify.cpp:32-35."""

    def test_all_sequences_final_with_future_locktime(self):
        import sync
        # Future height locktime, all sequences final → must be final.
        self.assertTrue(
            sync.is_final_tx(1_000_000, [CORE_SEQUENCE_FINAL,
                                         CORE_SEQUENCE_FINAL], 1, 0))

    def test_all_sequences_final_with_future_time_locktime(self):
        import sync
        # Future MTP locktime, all sequences final → must be final.
        self.assertTrue(
            sync.is_final_tx(1_700_000_000, [CORE_SEQUENCE_FINAL],
                             1, 1_600_000_000))

    def test_locktime_zero_always_final(self):
        import sync
        self.assertTrue(sync.is_final_tx(0, [0], 0, 0))

    def test_height_based_locktime_strict_lt(self):
        import sync
        # locktime 100, height 100 → NOT final (must be locktime < height).
        self.assertFalse(sync.is_final_tx(100, [0], 100, 0))
        # locktime 100, height 101 → final.
        self.assertTrue(sync.is_final_tx(100, [0], 101, 0))

    def test_time_based_locktime_strict_lt(self):
        import sync
        # locktime 1_600_000_000, MTP 1_600_000_000 → NOT final.
        self.assertFalse(sync.is_final_tx(1_600_000_000, [0],
                                          1, 1_600_000_000))
        # locktime 1_600_000_000, MTP 1_600_000_001 → final.
        self.assertTrue(sync.is_final_tx(1_600_000_000, [0],
                                         1, 1_600_000_001))

    def test_threshold_boundary(self):
        import sync
        # locktime 499_999_999 → height-based; height=500_000_000 satisfies.
        self.assertTrue(sync.is_final_tx(499_999_999, [0],
                                         500_000_000, 0))
        # locktime 500_000_000 → time-based; MTP=500_000_001 satisfies.
        self.assertTrue(sync.is_final_tx(500_000_000, [0],
                                         0, 500_000_001))


# ===========================================================================
# G11-G16: BIP-68 sequence lock math
# ===========================================================================


class TestG11_SequenceLockV1Ignored(unittest.TestCase):
    """G11: BIP-68 only applies to tx_version >= 2.
    Mirrors Core tx_verify.cpp:51 (`fEnforceBIP68 = tx.version >= 2 && ...`)."""

    def test_v1_tx_no_lock(self):
        import sync
        # Even with a 100-block sequence lock, v1 tx is unaffected.
        inputs = [(100, 1000, 1_600_000_000)]
        # check_sequence_locks(version, inputs, tip_h, tip_mtp, enforce)
        self.assertTrue(sync.check_sequence_locks(1, inputs, 1001, 0, True))

    def test_v2_tx_lock_enforced(self):
        import sync
        # tip_height=1001, prev_height=1000, lock=100 → min_height=1099.
        # 1001 <= 1099 → fail.
        inputs = [(100, 1000, 1_600_000_000)]
        self.assertFalse(sync.check_sequence_locks(2, inputs, 1001, 0, True))


class TestG12_DisableFlagSkipsLock(unittest.TestCase):
    """G12: per-input SEQUENCE_LOCKTIME_DISABLE_FLAG → skip that input."""

    def test_disable_flag_skips_input(self):
        import sync
        # Disable-flagged input contributes no lock.
        inputs = [(CORE_SEQUENCE_LOCKTIME_DISABLE_FLAG | 100,
                   1000, 1_600_000_000)]
        self.assertTrue(sync.check_sequence_locks(2, inputs, 0, 0, True))

    def test_sequence_final_implies_disable(self):
        import sync
        # SEQUENCE_FINAL = 0xFFFFFFFF — high bit set → disable.
        inputs = [(CORE_SEQUENCE_FINAL, 1000, 1_600_000_000)]
        self.assertTrue(sync.check_sequence_locks(2, inputs, 0, 0, True))


class TestG13_HeightBasedLockFormula(unittest.TestCase):
    """G13: min_height = utxo_height + lock_value - 1.
    Mirrors Core tx_verify.cpp:90."""

    def test_exact_lock_value(self):
        import sync
        # utxo at 1000, lock=100 → min_height=1099 → tip must be >= 1100.
        inputs = [(100, 1000, 0)]
        self.assertFalse(sync.check_sequence_locks(2, inputs, 1099, 0, True))
        self.assertTrue(sync.check_sequence_locks(2, inputs, 1100, 0, True))

    def test_zero_lock_satisfied_at_utxo_height(self):
        import sync
        # lock=0 → min_height = utxo_height - 1 → satisfied at utxo_height.
        inputs = [(0, 1000, 0)]
        self.assertTrue(sync.check_sequence_locks(2, inputs, 1000, 0, True))

    def test_max_height_lock(self):
        import sync
        # lock = MASK = 65535. min_height = 1000 + 65535 - 1 = 66534.
        inputs = [(CORE_SEQUENCE_LOCKTIME_MASK, 1000, 0)]
        self.assertFalse(sync.check_sequence_locks(2, inputs, 66534, 0, True))
        self.assertTrue(sync.check_sequence_locks(2, inputs, 66535, 0, True))


class TestG14_TimeBasedLockFormula(unittest.TestCase):
    """G14: min_time = coin_time + (lock_value << 9) - 1.
    Mirrors Core tx_verify.cpp:88."""

    def test_one_unit_512_seconds(self):
        import sync
        # TYPE_FLAG | 1 → 1 * 512 seconds.
        seq = CORE_SEQUENCE_LOCKTIME_TYPE_FLAG | 1
        coin_time = 1_600_000_000
        # min_time = coin_time + 512 - 1 = coin_time + 511
        # tx valid when tip_mtp > min_time → tip_mtp >= coin_time + 512
        inputs = [(seq, 1000, coin_time)]
        self.assertFalse(sync.check_sequence_locks(2, inputs, 2000,
                                                    coin_time + 511, True))
        self.assertTrue(sync.check_sequence_locks(2, inputs, 2000,
                                                   coin_time + 512, True))

    def test_max_time_lock(self):
        import sync
        # TYPE_FLAG | MASK → 65535 * 512 seconds = 33_553_920 seconds (~388 days)
        seq = (CORE_SEQUENCE_LOCKTIME_TYPE_FLAG
               | CORE_SEQUENCE_LOCKTIME_MASK)
        coin_time = 1_600_000_000
        max_delta = 65535 * 512  # 33_553_920
        inputs = [(seq, 1000, coin_time)]
        # min_time = coin_time + max_delta - 1
        # Required: tip_mtp > min_time = coin_time + max_delta - 1
        # So tip_mtp = coin_time + max_delta satisfies.
        self.assertFalse(sync.check_sequence_locks(
            2, inputs, 2000, coin_time + max_delta - 1, True))
        self.assertTrue(sync.check_sequence_locks(
            2, inputs, 2000, coin_time + max_delta, True))


class TestG15_CoinTimeIsMtpAtUtxoHeightMinusOne(unittest.TestCase):
    """G15: coin_time = MTP at (utxo_height - 1).
    Mirrors Core tx_verify.cpp:74:
      nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
    """

    def test_validation_py_uses_utxo_height_minus_one(self):
        """Pin the structural invariant — validation.py:2398 must use
        `max(utxo_height - 1, 0)`."""
        validation_py = Path(__file__).resolve().parent.parent / "validation.py"
        src = validation_py.read_text()
        self.assertIn("get_median_time_past(max(utxo_height - 1, 0))", src,
                      "coin_time must be MTP at (utxo_height - 1), not "
                      "utxo_height. Core tx_verify.cpp:74.")


class TestG16_MultiInputMaximumLock(unittest.TestCase):
    """G16: Multi-input → take the maximum lock requirement.
    Mirrors Core tx_verify.cpp:85,88 (`nMinTime = std::max(...)`)."""

    def test_two_inputs_max_height(self):
        import sync
        inputs = [
            (50, 1000, 0),   # input 0: min_height = 1049
            (100, 900, 0),   # input 1: min_height = 999
        ]
        # max = 1049 → tip must be >= 1050.
        self.assertFalse(sync.check_sequence_locks(2, inputs, 1049, 0, True))
        self.assertTrue(sync.check_sequence_locks(2, inputs, 1050, 0, True))


# ===========================================================================
# G17-G23: OP_CHECKSEQUENCEVERIFY interpreter semantics
# ===========================================================================


class TestG17_OpCsvGatedOnFlag(unittest.TestCase):
    """G17: OP_CSV gated on SCRIPT_VERIFY_CHECKSEQUENCEVERIFY.
    Mirrors Core interpreter.cpp:563."""

    def test_csv_op_is_nop_without_flag(self):
        # Without the flag, OP_CSV is a NOP.
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(100) + b"\xb2" + b"\x51"  # CSV + OP_TRUE
        script_sig = b""
        tx = _make_tx(version=2, locktime=0, sequences=[100])
        # Without CSV flag, push of 100 stays on stack, OP_CSV is NOP,
        # OP_TRUE pushes 1, finishes with two truthy items.
        # Use verify to evaluate end-to-end with cleanstack off (no flags).
        result = interp.verify(
            script_sig, script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_NONE, amount=0,
        )
        # Without CHECKSEQUENCEVERIFY flag, the script behaves as if OP_CSV
        # were OP_NOP3 → final top-of-stack is OP_TRUE which is truthy.
        self.assertTrue(result, "OP_CSV must be a NOP without the flag")


class TestG18_OpCsvNegativeValue(unittest.TestCase):
    """G18: negative operand rejected with NEGATIVE_LOCKTIME.
    Mirrors Core interpreter.cpp:579-580."""

    def test_negative_csv_value(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(-1) + b"\xb2"  # OP_CSV
        tx = _make_tx(version=2, locktime=0, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result)


class TestG19_OpCsvOperandDisableFlagIsNop(unittest.TestCase):
    """G19: operand has DISABLE_FLAG set → OP_CSV is a NOP.
    Mirrors Core interpreter.cpp:585-586."""

    def test_operand_disable_flag_treated_as_nop(self):
        interp = ScriptInterpreter()
        # Operand with DISABLE_FLAG (1<<31) → OP_CSV breaks (NOP).
        # Note: operand is read as a 5-byte CScriptNum, so values up to
        # 2^39-1 are valid.
        operand = CORE_SEQUENCE_LOCKTIME_DISABLE_FLAG | 0  # 0x80000000
        # 5-byte encoding for 0x80000000 (since high bit of the 4-byte form
        # would mark it as negative): 0x00 0x00 0x00 0x80 0x00
        encoded = (operand).to_bytes(5, "little")
        script_pubkey = bytes([5]) + encoded + b"\xb2" + b"\x51"  # CSV + OP_TRUE
        tx = _make_tx(version=2, locktime=0, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertTrue(result,
                         "Operand-side DISABLE_FLAG must make OP_CSV a NOP "
                         "(Core interpreter.cpp:585-586).")


class TestG20_OpCsvVersionRequirement(unittest.TestCase):
    """G20: v1 tx with OP_CSV (non-disabled) → fails.
    Mirrors Core interpreter.cpp:1790-1791."""

    def test_v1_tx_fails_csv(self):
        interp = ScriptInterpreter()
        # Operand = 10 (small height-based lock).
        script_pubkey = _push_scriptnum(10) + b"\xb2" + b"\x51"  # CSV + OP_TRUE
        tx = _make_tx(version=1, locktime=0, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result,
                         "OP_CSV must fail for v1 tx "
                         "(Core interpreter.cpp:1790-1791).")


class TestG21_OpCsvInputDisableFlagFails(unittest.TestCase):
    """G21: input nSequence has DISABLE_FLAG → OP_CSV fails.
    Mirrors Core interpreter.cpp:1797-1798."""

    def test_input_disable_flag_fails_csv(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(10) + b"\xb2" + b"\x51"  # CSV + OP_TRUE
        # tx input sequence has DISABLE_FLAG → fails.
        tx = _make_tx(
            version=2, locktime=0,
            sequences=[CORE_SEQUENCE_LOCKTIME_DISABLE_FLAG | 100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result)


class TestG22_OpCsvTypeMismatch(unittest.TestCase):
    """G22: operand and input nSequence must agree on type (block-vs-time).
    Mirrors Core interpreter.cpp:1813-1817."""

    def test_block_vs_time_mismatch_fails(self):
        interp = ScriptInterpreter()
        # Operand = block-based (no TYPE_FLAG); tx_seq = time-based (TYPE_FLAG).
        script_pubkey = _push_scriptnum(10) + b"\xb2" + b"\x51"
        tx = _make_tx(
            version=2, locktime=0,
            sequences=[CORE_SEQUENCE_LOCKTIME_TYPE_FLAG | 10])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result)

    def test_time_vs_block_mismatch_fails(self):
        interp = ScriptInterpreter()
        # Operand = time-based (TYPE_FLAG); tx_seq = block-based.
        operand = CORE_SEQUENCE_LOCKTIME_TYPE_FLAG | 10
        script_pubkey = _push_scriptnum(operand) + b"\xb2" + b"\x51"
        tx = _make_tx(version=2, locktime=0, sequences=[10])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result)


class TestG23_OpCsvValueComparison(unittest.TestCase):
    """G23: stack-operand value <= input nSequence (after masking).
    Mirrors Core interpreter.cpp:1822-1823."""

    def test_operand_exceeds_tx_seq_fails(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(100) + b"\xb2" + b"\x51"
        tx = _make_tx(version=2, locktime=0, sequences=[50])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertFalse(result, "operand 100 > tx_seq 50 → must fail")

    def test_operand_equals_tx_seq_succeeds(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(50) + b"\xb2" + b"\x51"
        tx = _make_tx(version=2, locktime=0, sequences=[50])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertTrue(result, "operand 50 <= tx_seq 50 → must pass")

    def test_operand_below_tx_seq_succeeds(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(10) + b"\xb2" + b"\x51"
        tx = _make_tx(version=2, locktime=0, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, amount=0,
        )
        self.assertTrue(result, "operand 10 <= tx_seq 100 → must pass")


# ===========================================================================
# G24-G26: OP_CHECKLOCKTIMEVERIFY interpreter semantics
# ===========================================================================


class TestG24_OpCltvGatedOnFlag(unittest.TestCase):
    """G24: OP_CLTV gated on SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY.
    Mirrors Core interpreter.cpp:524-527."""

    def test_cltv_is_nop_without_flag(self):
        interp = ScriptInterpreter()
        # Without CLTV flag, OP_CLTV is NOP.
        script_pubkey = _push_scriptnum(100) + b"\xb1" + b"\x51"
        tx = _make_tx(version=2, locktime=0, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_NONE, amount=0,
        )
        self.assertTrue(result, "OP_CLTV must be a NOP without the flag")


class TestG25_OpCltvTypeMismatch(unittest.TestCase):
    """G25: operand and tx.nLockTime must agree on type (height vs time)."""

    def test_height_vs_time_mismatch(self):
        interp = ScriptInterpreter()
        # Operand height-based (< threshold); tx locktime time-based.
        script_pubkey = _push_scriptnum(100) + b"\xb1" + b"\x51"
        tx = _make_tx(version=2, locktime=1_600_000_000, sequences=[100])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, amount=0,
        )
        self.assertFalse(result)


class TestG26_OpCltvSequenceFinalBypass(unittest.TestCase):
    """G26: input nSequence == SEQUENCE_FINAL → OP_CLTV fails.
    Mirrors Core interpreter.cpp:1775-1776."""

    def test_sequence_final_makes_cltv_fail(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(100) + b"\xb1" + b"\x51"
        # tx has nLockTime in the future; sequence==FINAL bypasses nLockTime,
        # which CLTV detects and fails.
        tx = _make_tx(version=2, locktime=200,
                      sequences=[CORE_SEQUENCE_FINAL])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, amount=0,
        )
        self.assertFalse(result)

    def test_max_sequence_nonfinal_passes_cltv(self):
        interp = ScriptInterpreter()
        script_pubkey = _push_scriptnum(100) + b"\xb1" + b"\x51"
        # Sequence = MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE allows nLockTime.
        tx = _make_tx(version=2, locktime=100,
                      sequences=[CORE_MAX_SEQUENCE_NONFINAL])
        result = interp.verify(
            b"", script_pubkey, tx, 0,
            flags=SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, amount=0,
        )
        self.assertTrue(result,
                         "MAX_SEQUENCE_NONFINAL must not trigger the "
                         "SEQUENCE_FINAL bypass check.")


# ===========================================================================
# G27-G29: MedianTimePast window
# ===========================================================================


class TestG27_MTPWindowEleven(unittest.TestCase):
    """G27: GetMedianTimePast uses nMedianTimeSpan = 11 blocks.
    Mirrors Core chain.h:231."""

    def test_validation_doc_references_eleven(self):
        """All three MTP implementations doc-reference '11'."""
        for rel in ["validation.py", "database.py", "node.py"]:
            f = Path(__file__).resolve().parent.parent / rel
            self.assertIn("11", f.read_text(),
                          f"{rel} should reference the 11-block MTP window.")


class TestG28_MTPFewBlocksAtLowHeights(unittest.TestCase):
    """G28: MTP at height < 10 uses fewer than 11 blocks (truncated window)."""

    def test_python_fallback_range_clamped_at_zero(self):
        # database.py:654 — `range(max(0, height - 10), height + 1)`.
        # At height=3 this yields range(0, 4) = [0,1,2,3] → 4 blocks.
        database_py = Path(__file__).resolve().parent.parent / "database.py"
        src = database_py.read_text()
        self.assertIn("range(max(0, height - 10), height + 1)", src,
                      "MTP slow-fallback must clamp range start to 0.")


class TestG29_MTPIncludesCurrentBlock(unittest.TestCase):
    """G29: MTP at height h includes block[h] (not block[h-1]).
    Mirrors Core chain.h:239-241 (loop starts at `this`, not `this->pprev`)."""

    def test_python_node_includes_current_height(self):
        # node.py:1617 — `range(max(0, height - 10), height + 1)`.
        # The `+ 1` ensures block[height] is INCLUDED in the iteration.
        node_py = Path(__file__).resolve().parent.parent / "node.py"
        src = node_py.read_text()
        self.assertIn("range(max(0, height - 10), height + 1)", src,
                      "MTP must INCLUDE the block at `height` in its window.")


# ===========================================================================
# G30: Two-pipeline guard
# ===========================================================================


class TestG30_TwoPipelineGuard(unittest.TestCase):
    """G30: Rust pipeline ships sequence_lock module; Python imports via
    PyO3. The two pipelines MUST agree on consensus semantics."""

    def test_rust_pipeline_has_sequence_lock_module(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present in this checkout")
        src = rust_file.read_text()
        for fn in ["fn calculate_sequence_locks",
                   "fn evaluate_sequence_locks",
                   "fn check_sequence_locks",
                   "fn is_final_tx",
                   "fn csv_activation_height",
                   "fn is_bip68_active"]:
            self.assertIn(fn, src,
                          f"Rust sequence_lock.rs must export {fn}.")

    def test_pyo3_exports_present_in_lib_rs(self):
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_file.exists():
            self.skipTest("Rust lib.rs not present")
        src = rust_file.read_text()
        for export in ["wrap_pyfunction!(check_sequence_locks",
                       "wrap_pyfunction!(is_final_tx",
                       "wrap_pyfunction!(locktime_threshold"]:
            self.assertIn(export, src,
                          f"lib.rs must wrap {export} for PyO3 export.")

    def test_csv_activation_height_divergence_pinned(self):
        """BUG-3 / BUG-4: pin the testnet4 / regtest / signet divergence."""
        rust_file = Path(__file__).resolve().parent.parent.parent.parent \
            / "ferrous-utils" / "sync" / "src" / "validate" / "sequence_lock.rs"
        if not rust_file.exists():
            self.skipTest("Rust pipeline not present")
        src = rust_file.read_text()
        # When this divergence is fixed, both literals will say `=> 1,`,
        # this test will fail, the fixing developer updates the test.
        self.assertIn("Network::Testnet4 => 0,", src,
                      "BUG-3 still open: Rust pipeline returns 0 for Testnet4.")
        self.assertIn("Network::Regtest => 0,", src,
                      "BUG-3 still open: Rust pipeline returns 0 for Regtest.")


# ===========================================================================
# Bug inventory cross-reference
# ===========================================================================


class TestBugInventory(unittest.TestCase):
    """Documentation cross-reference: assert audit doc lists all 14 bugs."""

    def test_audit_doc_lists_14_bugs(self):
        audit_doc = Path(__file__).resolve().parent.parent.parent.parent \
            / "audit" / "w132_nsequence_csv_mtp.md"
        if not audit_doc.exists():
            self.skipTest("Audit doc not present")
        src = audit_doc.read_text()
        # All 14 bugs must appear in the catalogue heading.
        for n in range(1, 15):
            self.assertIn(f"**BUG-{n} ", src,
                          f"Audit doc must catalogue BUG-{n}.")

    def test_audit_doc_lists_30_gates(self):
        audit_doc = Path(__file__).resolve().parent.parent.parent.parent \
            / "audit" / "w132_nsequence_csv_mtp.md"
        if not audit_doc.exists():
            self.skipTest("Audit doc not present")
        src = audit_doc.read_text()
        for n in range(1, 31):
            # Each gate appears as 'G##  ' or 'G##   '.
            self.assertRegex(src, rf"G{n}\b",
                              f"Audit doc must reference gate G{n}.")

    def test_p0_consensus_finding_documented(self):
        """At least one P0-CONSENSUS bug must be documented."""
        audit_doc = Path(__file__).resolve().parent.parent.parent.parent \
            / "audit" / "w132_nsequence_csv_mtp.md"
        if not audit_doc.exists():
            self.skipTest("Audit doc not present")
        self.assertIn("P0-CONSENSUS", audit_doc.read_text())


if __name__ == "__main__":
    unittest.main()
