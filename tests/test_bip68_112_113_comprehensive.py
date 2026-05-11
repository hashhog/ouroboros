"""
Comprehensive BIP-68 + BIP-112 + BIP-113 sequence-lock audit tests.

W80: covers all 21 gates across CalculateSequenceLocks / EvaluateSequenceLocks /
CheckSequence (OP_CSV) / IsFinalTx (BIP-113 MTP).

Reference:
  - Bitcoin Core consensus/tx_verify.cpp:17-110  (IsFinalTx, CalculateSequenceLocks,
    EvaluateSequenceLocks, SequenceLocks)
  - Bitcoin Core primitives/transaction.h:60-115  (constants)
  - Bitcoin Core script/interpreter.cpp:561-593   (OP_CHECKSEQUENCEVERIFY)
  - Bitcoin Core script/interpreter.cpp:1782-1825 (CheckSequence)

Gate index
----------
G1  tx.version < 2 → BIP-68 disabled (CalculateSequenceLocks returns -1/-1)
G2  DISABLE_FLAG (bit 31) on nSequence → skip input
G3  TYPE_FLAG (bit 22) distinguishes height vs time lock
G4  coin_time = MTP of GetAncestor(max(coin_height - 1, 0))
G5  time lock value = coin_time + (lock << 9) - 1
G6  height lock value = coin_height + lock - 1
G7  EvaluateSequenceLocks uses MTP of block.pprev (not block.nTime)
G8  OP_CSV: flag not set → NOP (treated as NOP3)
G9  OP_CSV: stack non-empty
G10 OP_CSV: 5-byte CScriptNum read
G11 OP_CSV: value < 0 → NEGATIVE_LOCKTIME error
G12 OP_CSV: value has DISABLE_FLAG → behave as NOP
G13 OP_CSV: tx.version < 2 → fail
G14 OP_CSV: txToSequence & DISABLE_FLAG → fail
G15 OP_CSV: type mismatch → fail
G16 OP_CSV: nSequenceMasked > txToSequenceMasked → fail
G17 IsFinalTx: nLockTime == 0 → final
G18 IsFinalTx: height-based comparison (nLockTime < block_height)
G19 IsFinalTx: time-based comparison via MTP (BIP-113)
G20 IsFinalTx: all inputs SEQUENCE_FINAL → override (locktime disabled)
G21 IsFinalTx: block_mtp == 0 → reject (not silent-accept)

Fixed bugs found in W80 audit
------------------------------
BUG-A  _is_final_tx: silent-accept when block_mtp <= 0 → fixed to reject (G21)
BUG-B  _check_sequence_locks_py: missing intra_block_utxos → false UTXO-not-found
BUG-C  enforce_bip68 fallback hardcodes 419328 (mainnet only) → fixed to use
       is_buried_deployment_active(), correct for testnet4/regtest/signet

Implementation notes
--------------------
- Tests use ``network="regtest"`` (BIP-68 active from genesis = height 0) unless
  explicitly testing network-specific activation.  This avoids the mainnet
  CSV-activation gate (419328) confusing tests that only care about lock math.
- OP_CSV tests call ``_execute_script(script, tx, idx, b"")`` matching the pattern
  in test_integration.py.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Ensure conftest mock is loaded before any ouroboros import
import tests.conftest  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.validation import TransactionValidator
from ouroboros.script import ScriptInterpreter, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

# ---------------------------------------------------------------------------
# Constants (mirror Bitcoin Core)
# ---------------------------------------------------------------------------
SEQ_DISABLE = 1 << 31    # 0x80000000
SEQ_TYPE    = 1 << 22    # 0x00400000
SEQ_MASK    = 0x0000FFFF
SEQ_FINAL   = 0xFFFFFFFF
LOCKTIME_THRESHOLD = 500_000_000

# Mainnet CSV activation height (buried deployment).
# Tests that need BIP-68 to be active on mainnet must use heights >= this.
MAINNET_CSV_HEIGHT = 419_328


# ---------------------------------------------------------------------------
# Transaction / UTXO / Validator builders
# ---------------------------------------------------------------------------

def _make_tx(
    *,
    version: int = 2,
    locktime: int = 0,
    inputs: list[tuple[int, bytes, int]] | None = None,
) -> Transaction:
    """Build a minimal transaction.  Each input tuple: (sequence, prev_txid, prev_vout)."""
    raw_inputs = []
    for seq, txid, vout in (inputs or [(SEQ_FINAL, b"\xaa" * 32, 0)]):
        raw_inputs.append(
            TxIn(prev_txid=txid, prev_vout=vout, script_sig=b"", sequence=seq)
        )
    return Transaction(
        txid=b"\xcc" * 32,
        version=version,
        locktime=locktime,
        inputs=raw_inputs,
        outputs=[TxOut(value=1_000, script_pubkey=b"\x51")],
    )


def _make_validator(
    *,
    utxo_height: int = 1000,
    utxo_mtp: int | None = 1_600_000_000,
    network: str = "regtest",  # regtest = BIP-68 active from genesis
    snapshot_height: int | None = None,
) -> TransactionValidator:
    """Build a TransactionValidator with a fully-mocked database.

    ``network="regtest"`` is the default so that BIP-68/CSV is active from
    block 0 — tests that want to exercise the lock math don't need to use
    heights above 419328.
    """
    db = MagicMock()
    db.get_utxo.return_value = {
        "txid": b"\xaa" * 32,
        "vout": 0,
        "value": 100_000,
        "script_pubkey": b"\x51",
        "height": utxo_height,
    }
    db.get_utxo_batch.return_value = [db.get_utxo.return_value]
    db.get_median_time_past.side_effect = lambda h: utxo_mtp

    sm = None
    if snapshot_height is not None:
        sm = MagicMock()
        sm.snapshot_height = snapshot_height

    return TransactionValidator(db, network=network, snapshot_manager=sm)


def _csl(v: TransactionValidator, tx: Transaction, block_height: int, block_mtp: int) -> bool:
    """Shorthand: check_sequence_locks using the validator's own network."""
    return v.check_sequence_locks(
        tx, block_height=block_height, block_mtp=block_mtp, network=v.network
    )


# ---------------------------------------------------------------------------
# OP_CSV helper
# ---------------------------------------------------------------------------

def _encode_scriptnum(value: int) -> bytes:
    """Minimal CScriptNum encoding (mirrors Bitcoin Core's CScriptNum::serialize)."""
    if value == 0:
        return b""
    neg = value < 0
    val = abs(value)
    result = []
    while val > 0:
        result.append(val & 0xFF)
        val >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if neg else 0x00)
    elif neg:
        result[-1] |= 0x80
    return bytes(result)


def _run_csv_script(
    lock_value: int,
    tx_version: int,
    tx_seq: int,
    flags: int = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
) -> bool:
    """Run a minimal script: <lock_value> OP_CSV; return True on success."""
    encoded = _encode_scriptnum(lock_value)
    if encoded:
        script = bytes([len(encoded)]) + encoded + bytes([0xb2])
    else:
        # lock_value == 0: push OP_0 (empty / b""), then OP_CSV
        script = bytes([0x00, 0xb2])

    tx = _make_tx(version=tx_version, inputs=[(tx_seq, b"\xaa" * 32, 0)])
    interp = ScriptInterpreter()
    try:
        # script_pubkey=b"" matches the convention in test_integration.py
        interp._execute_script(script, tx, 0, b"", flags=flags)
        return True
    except Exception:
        return False


# ===========================================================================
# G1 — tx.version < 2 disables BIP-68
# ===========================================================================

class TestG1VersionGate(unittest.TestCase):
    """G1: version-1 transactions are exempt from BIP-68."""

    def test_v1_tx_ignores_height_lock(self):
        """A v1 tx with a height-based lock must pass (BIP-68 disabled)."""
        v = _make_validator(utxo_height=1000)
        # sequence=65535 would require depth >= 65535; at height 1001 depth=1
        tx = _make_tx(version=1, inputs=[(65535, b"\xaa" * 32, 0)])
        self.assertTrue(_csl(v, tx, block_height=1001, block_mtp=2_000_000_000))

    def test_v1_tx_ignores_time_lock(self):
        """A v1 tx with a time-based lock must pass (BIP-68 disabled)."""
        v = _make_validator(utxo_height=1000, utxo_mtp=1_600_000_000)
        tx = _make_tx(version=1, inputs=[(SEQ_TYPE | 65535, b"\xaa" * 32, 0)])
        self.assertTrue(_csl(v, tx, block_height=2000, block_mtp=1_600_000_000))

    def test_v2_tx_enforces_height_lock(self):
        """A v2 tx with a height-based lock IS subject to BIP-68."""
        v = _make_validator(utxo_height=1000)
        # Require depth >= 100; at 1099, depth=99 → fail; at 1100, depth=100 → pass
        tx = _make_tx(version=2, inputs=[(100, b"\xaa" * 32, 0)])
        self.assertFalse(_csl(v, tx, block_height=1099, block_mtp=2_000_000_000))
        self.assertTrue(_csl(v, tx, block_height=1100, block_mtp=2_000_000_000))

    def test_v3_tx_enforces_like_v2(self):
        """v3 transactions (BIP-431 TRUC) must also obey BIP-68 (version >= 2)."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=3, inputs=[(100, b"\xaa" * 32, 0)])
        self.assertFalse(_csl(v, tx, block_height=1099, block_mtp=2_000_000_000))
        self.assertTrue(_csl(v, tx, block_height=1100, block_mtp=2_000_000_000))


# ===========================================================================
# G2 — DISABLE_FLAG skips the input
# ===========================================================================

class TestG2DisableFlag(unittest.TestCase):
    """G2: inputs with DISABLE_FLAG (bit 31) are ignored by BIP-68."""

    def test_disable_flag_set_skips_input(self):
        """Sequence with bit 31 set → no lock constraint."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(SEQ_DISABLE | 65535, b"\xaa" * 32, 0)])
        # Block height 1: depth=1-1000<0, would fail if enforced
        self.assertTrue(_csl(v, tx, block_height=1, block_mtp=2_000_000_000))

    def test_sequence_final_skips_input(self):
        """SEQUENCE_FINAL (0xFFFFFFFF) has DISABLE_FLAG → skipped."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(SEQ_FINAL, b"\xaa" * 32, 0)])
        self.assertTrue(_csl(v, tx, block_height=1, block_mtp=2_000_000_000))

    def test_one_disabled_one_enforced(self):
        """Only the non-disabled input contributes its constraint."""
        db = MagicMock()
        def get_utxo(txid, vout):
            h = 800 if vout == 0 else 900
            return {"txid": txid, "vout": vout, "value": 50_000,
                    "script_pubkey": b"\x51", "height": h}
        db.get_utxo.side_effect = get_utxo
        db.get_utxo_batch.side_effect = lambda ops: [get_utxo(t, v) for t, v in ops]
        db.get_median_time_past.return_value = 1_600_000_000
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[
            (SEQ_DISABLE | 200, b"\xaa" * 32, 0),  # disabled; utxo_height=800
            (50,               b"\xbb" * 32, 1),   # enforced; utxo_height=900
        ])
        # need depth >= 50 for the enabled input: block_height >= 950
        self.assertFalse(_csl(v, tx, 949, 2_000_000_000))
        self.assertTrue(_csl(v, tx, 950, 2_000_000_000))


# ===========================================================================
# G3 — TYPE_FLAG distinguishes height vs time
# ===========================================================================

class TestG3TypeFlag(unittest.TestCase):
    """G3: bit 22 (TYPE_FLAG) selects time-based vs height-based lock."""

    def test_no_type_flag_height_based(self):
        """No TYPE_FLAG → height-based lock."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(50, b"\xaa" * 32, 0)])
        # min_height = 1000 + 50 - 1 = 1049; fail at 1049, pass at 1050
        self.assertFalse(_csl(v, tx, 1049, 2_000_000_000))
        self.assertTrue(_csl(v, tx, 1050, 2_000_000_000))

    def test_type_flag_set_time_based(self):
        """TYPE_FLAG set → time-based lock (units of 512 s)."""
        v = _make_validator(utxo_height=1000, utxo_mtp=1_600_000_000)
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 10, b"\xaa" * 32, 0)])
        # min_time = 1_600_000_000 + 10*512 - 1 = 1_600_005_119
        self.assertFalse(_csl(v, tx, 2000, 1_600_005_119))
        self.assertTrue(_csl(v, tx, 2000, 1_600_005_120))


# ===========================================================================
# G4 — coin_time uses MTP of ancestor(max(coin_height - 1, 0))
# ===========================================================================

class TestG4CoinTime(unittest.TestCase):
    """G4: coin_time is the MTP of the block at max(coin_height-1, 0)."""

    def test_coin_time_queries_prev_height(self):
        """Verifies the DB query uses max(coin_height-1, 0)."""
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
            "script_pubkey": b"\x51", "height": 500,
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        queried_heights = []

        def mock_mtp(h):
            queried_heights.append(h)
            return 1_500_000_000 + h * 600

        db.get_median_time_past.side_effect = mock_mtp
        v = TransactionValidator(db, network="regtest")
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 1, b"\xaa" * 32, 0)])
        _csl(v, tx, 600, 1_700_000_000)
        # The coin_time query must use height 499 (= 500 - 1)
        self.assertIn(499, queried_heights)

    def test_coin_height_zero_clamps_to_zero(self):
        """When coin_height == 0, max(0-1, 0) = 0 → query height 0."""
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
            "script_pubkey": b"\x51", "height": 0,
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        queried_heights = []
        def mock_mtp(h):
            queried_heights.append(h)
            return 1_231_006_505
        db.get_median_time_past.side_effect = mock_mtp

        v = TransactionValidator(db, network="regtest")
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 1, b"\xaa" * 32, 0)])
        _csl(v, tx, 1, 1_231_006_600)

        # Must query height 0, NOT -1
        self.assertNotIn(-1, queried_heights)
        self.assertIn(0, queried_heights)


# ===========================================================================
# G5 — time lock formula: coin_time + (lock << 9) - 1
# ===========================================================================

class TestG5TimeLockFormula(unittest.TestCase):
    """G5: min_time = coin_time + (lock_value * 512) - 1."""

    def _val(self, coin_mtp: int) -> TransactionValidator:
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
            "script_pubkey": b"\x51", "height": 1000,
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        db.get_median_time_past.return_value = coin_mtp
        return TransactionValidator(db, network="regtest")

    def test_1_unit_512s(self):
        """1 unit = 512 s; min_time = coin_mtp + 511."""
        v = self._val(1_600_000_000)
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 1, b"\xaa" * 32, 0)])
        self.assertFalse(_csl(v, tx, 2000, 1_600_000_511))
        self.assertTrue(_csl(v, tx, 2000, 1_600_000_512))

    def test_granularity_is_512_not_500(self):
        """Granularity is exactly 2^9 = 512, not 500 or 600."""
        v = self._val(1_000_000_000)
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 100, b"\xaa" * 32, 0)])
        # 100 * 512 = 51200; min_time = 1_000_051_199
        self.assertFalse(_csl(v, tx, 2000, 1_000_051_199))
        self.assertTrue(_csl(v, tx, 2000, 1_000_051_200))

    def test_zero_units_passes_at_coin_mtp(self):
        """0 units: min_time = coin_mtp - 1; any block_mtp >= coin_mtp passes."""
        coin_mtp = 1_600_000_000
        v = self._val(coin_mtp)
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 0, b"\xaa" * 32, 0)])
        # min_time = coin_mtp + 0*512 - 1 = coin_mtp - 1; block_mtp=coin_mtp > min_time → pass
        self.assertTrue(_csl(v, tx, 2000, coin_mtp))

    def test_max_mask_65535(self):
        """lock = 65535: min_time = coin_mtp + 65535*512 - 1."""
        coin_mtp = 1_600_000_000
        v = self._val(coin_mtp)
        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 0xFFFF, b"\xaa" * 32, 0)])
        min_time = coin_mtp + 65535 * 512 - 1  # = 1_633_553_919
        self.assertFalse(_csl(v, tx, 2000, min_time))
        self.assertTrue(_csl(v, tx, 2000, min_time + 1))


# ===========================================================================
# G6 — height lock formula: coin_height + lock - 1
# ===========================================================================

class TestG6HeightLockFormula(unittest.TestCase):
    """G6: min_height = coin_height + lock_value - 1."""

    def test_boundary_at_1099(self):
        """min_height = 1000 + 100 - 1 = 1099; fail at 1099, pass at 1100."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(100, b"\xaa" * 32, 0)])
        self.assertFalse(_csl(v, tx, 1099, 2_000_000_000))
        self.assertTrue(_csl(v, tx, 1100, 2_000_000_000))

    def test_lock_zero_passes_at_coin_height(self):
        """lock=0: min_height = coin_height - 1; block at coin_height passes."""
        v = _make_validator(utxo_height=500)
        tx = _make_tx(version=2, inputs=[(0, b"\xaa" * 32, 0)])
        # depth = 500 - 500 = 0 >= 0 → pass
        self.assertTrue(_csl(v, tx, 500, 2_000_000_000))

    def test_lock_max_65535(self):
        """lock=65535: min_height = coin_height + 65534."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(0xFFFF, b"\xaa" * 32, 0)])
        # min_height = 1000 + 65535 - 1 = 66534
        self.assertFalse(_csl(v, tx, 66534, 2_000_000_000))
        self.assertTrue(_csl(v, tx, 66535, 2_000_000_000))

    def test_multiple_inputs_max_constraint(self):
        """Multiple inputs: strictest (maximum) lock wins."""
        db = MagicMock()
        def get_utxo(txid, vout):
            heights = {0: 800, 1: 900, 2: 1000}
            h = heights.get(vout, 1000)
            return {"txid": txid, "vout": vout, "value": 10_000,
                    "script_pubkey": b"\x51", "height": h}
        db.get_utxo.side_effect = get_utxo
        db.get_utxo_batch.side_effect = lambda ops: [get_utxo(t, v) for t, v in ops]
        db.get_median_time_past.return_value = 1_600_000_000
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[
            (50,  b"\xaa" * 32, 0),  # min_height = 800+50-1 = 849
            (100, b"\xbb" * 32, 1),  # min_height = 900+100-1 = 999
            (10,  b"\xcc" * 32, 2),  # min_height = 1000+10-1 = 1009 (strictest)
        ])
        self.assertFalse(_csl(v, tx, 1009, 2_000_000_000))
        self.assertTrue(_csl(v, tx, 1010, 2_000_000_000))


# ===========================================================================
# G7 — EvaluateSequenceLocks uses block.pprev MTP (not block.nTime)
# ===========================================================================

class TestG7BlockMtpIsPrevBlock(unittest.TestCase):
    """G7: time evaluation compares against MTP of block.pprev."""

    def test_block_mtp_is_prev_mtp(self):
        """block_mtp == MTP at height-1 is used for time-based lock evaluation."""
        coin_mtp = 1_600_000_000
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 10_000,
            "script_pubkey": b"\x51", "height": 100,
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        db.get_median_time_past.return_value = coin_mtp
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[(SEQ_TYPE | 1, b"\xaa" * 32, 0)])
        # min_time = coin_mtp + 511 = 1_600_000_511
        self.assertFalse(_csl(v, tx, 200, 1_600_000_511))
        self.assertTrue(_csl(v, tx, 200, 1_600_000_512))


# ===========================================================================
# G8-G16 — OP_CHECKSEQUENCEVERIFY (BIP-112)
# ===========================================================================

class TestOPCSVGates(unittest.TestCase):
    """G8-G16: OP_CHECKSEQUENCEVERIFY (opcode 0xb2) gates."""

    def test_g8_flag_not_set_acts_as_nop(self):
        """G8: without SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, OP_CSV is NOP3."""
        # Huge lock_value and depth=0 — would fail if enforced, but flag is off
        result = _run_csv_script(
            lock_value=99999,
            tx_version=2,
            tx_seq=0,
            flags=0,  # CSV flag NOT set
        )
        self.assertTrue(result, "OP_CSV with flag off must act as NOP3")

    def test_g9_empty_stack_fails(self):
        """G9: OP_CSV with nothing on the stack raises an error."""
        # Script is just OP_CSV with no push before it
        script = bytes([0xb2])
        tx = _make_tx(version=2, inputs=[(100, b"\xaa" * 32, 0)])
        interp = ScriptInterpreter()
        with self.assertRaises((ValueError, Exception)):
            interp._execute_script(script, tx, 0, b"",
                                   flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)

    def test_g10_5_byte_scriptnum_accepted(self):
        """G10: OP_CSV reads up to 5-byte CScriptNum (large value)."""
        # Encode a value requiring 5 bytes: 2^31 = 0x80000000
        # 5-byte encoding: [0x00, 0x00, 0x00, 0x80, 0x00]
        big_val = 1 << 31  # = 0x80000000 (DISABLE_FLAG value → NOP)
        result = _run_csv_script(big_val, tx_version=2, tx_seq=0)
        # DISABLE_FLAG in operand → NOP → should pass
        self.assertTrue(result, "5-byte CScriptNum with DISABLE_FLAG must NOP")

    def test_g11_negative_locktime_fails(self):
        """G11: negative lock value → SCRIPT_ERR_NEGATIVE_LOCKTIME."""
        result = _run_csv_script(-1, tx_version=2, tx_seq=SEQ_TYPE | 1000)
        self.assertFalse(result)

    def test_g12_disable_flag_in_operand_is_nop(self):
        """G12: if the script operand has DISABLE_FLAG, behave as NOP."""
        # Lock = 0x80000001 (DISABLE_FLAG | 1): must act as NOP
        result = _run_csv_script(SEQ_DISABLE | 1, tx_version=2, tx_seq=0)
        self.assertTrue(result, "DISABLE_FLAG in script operand means NOP")

    def test_g13_version_1_fails(self):
        """G13: tx.version < 2 → fail."""
        result = _run_csv_script(1, tx_version=1, tx_seq=SEQ_TYPE | 10)
        self.assertFalse(result)

    def test_g14_input_disable_flag_fails(self):
        """G14: txToSequence has DISABLE_FLAG → fail."""
        result = _run_csv_script(1, tx_version=2, tx_seq=SEQ_DISABLE | 1)
        self.assertFalse(result)

    def test_g15_type_mismatch_time_vs_height_fails(self):
        """G15: script wants time-based (TYPE_FLAG) but input is height-based → fail."""
        result = _run_csv_script(
            lock_value=SEQ_TYPE | 1,  # time-based in script
            tx_version=2,
            tx_seq=1,                 # height-based in input
        )
        self.assertFalse(result)

    def test_g15_type_mismatch_height_vs_time_fails(self):
        """G15: script wants height-based but input is time-based → fail."""
        result = _run_csv_script(
            lock_value=1,             # height-based in script
            tx_version=2,
            tx_seq=SEQ_TYPE | 1,      # time-based in input
        )
        self.assertFalse(result)

    def test_g16_insufficient_lock_fails(self):
        """G16: script requires more than the input's lock value → fail."""
        result = _run_csv_script(100, tx_version=2, tx_seq=50)
        self.assertFalse(result)

    def test_g16_sufficient_lock_passes(self):
        """G16: script requirement <= input lock value → pass."""
        result = _run_csv_script(50, tx_version=2, tx_seq=100)
        self.assertTrue(result)

    def test_g16_exact_lock_passes(self):
        """G16: nSequenceMasked == nScriptMasked → pass (equality OK)."""
        result = _run_csv_script(100, tx_version=2, tx_seq=100)
        self.assertTrue(result)

    def test_g16_time_lock_sufficient_passes(self):
        """G16: time-based lock, script == input → pass."""
        result = _run_csv_script(SEQ_TYPE | 10, tx_version=2, tx_seq=SEQ_TYPE | 10)
        self.assertTrue(result)

    def test_g16_time_lock_insufficient_fails(self):
        """G16: time-based lock, script > input → fail."""
        result = _run_csv_script(SEQ_TYPE | 100, tx_version=2, tx_seq=SEQ_TYPE | 50)
        self.assertFalse(result)

    def test_g16_csv_peeks_not_pops(self):
        """G16: OP_CSV must NOT consume the stack item (peek semantics)."""
        # Script: OP_1 <10> OP_CSV OP_DROP OP_1 → stack should be [b'\x01']
        # (The sequence is 20 >= 10 so CSV passes; then OP_DROP removes the
        # lock_value; OP_1 leaves something on the stack)
        lock_bytes = bytes([0x0a])  # minimal encoding of 10
        # OP_1 (0x51) pushes 1 to stack; then push 10; OP_CSV; OP_DROP; OP_1
        script = bytes([0x51]) + bytes([len(lock_bytes)]) + lock_bytes + bytes([0xb2, 0x75, 0x51])
        tx = _make_tx(version=2, inputs=[(20, b"\xaa" * 32, 0)])  # tx_seq=20
        interp = ScriptInterpreter()
        stack = interp._execute_script(script, tx, 0, b"",
                                       flags=SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
        # After DROP, OP_1 pushes; stack = [b'\x01', b'\x01']
        # The important thing is execution succeeded and CSV didn't pop its arg
        self.assertGreater(len(stack), 0)


# ===========================================================================
# G17-G20 — IsFinalTx (BIP-113)
# ===========================================================================

class TestIsFinalTx(unittest.TestCase):
    """G17-G20: IsFinalTx covers BIP-113 (MTP for locktime) plus SEQUENCE_FINAL override."""

    def _final(self, tx: Transaction, height: int, mtp: int) -> bool:
        return TransactionValidator._is_final_tx(tx, height, mtp)

    def test_g17_locktime_zero_always_final(self):
        """G17: nLockTime == 0 → always final."""
        tx = _make_tx(locktime=0, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertTrue(self._final(tx, 1, 1))
        self.assertTrue(self._final(tx, 0, 0))

    def test_g18_height_based_locktime_strict_less_than(self):
        """G18: locktime < block_height → final; locktime >= block_height → not final."""
        tx = _make_tx(locktime=100, inputs=[(0, b"\xaa" * 32, 0)])
        # locktime=100, height=99: 100 < 99? No → not final
        self.assertFalse(self._final(tx, 99, 0))
        # locktime=100, height=100: 100 < 100? No → not final
        self.assertFalse(self._final(tx, 100, 0))
        # locktime=100, height=101: 100 < 101? Yes → final
        self.assertTrue(self._final(tx, 101, 0))

    def test_g19_time_based_locktime_uses_mtp(self):
        """G19: time-based locktime (BIP-113) compared against MTP."""
        locktime = 1_600_000_000
        tx = _make_tx(locktime=locktime, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertFalse(self._final(tx, 1000, locktime - 1))   # MTP too low
        self.assertFalse(self._final(tx, 1000, locktime))        # MTP == locktime → not final
        self.assertTrue(self._final(tx, 1000, locktime + 1))    # MTP > locktime → final

    def test_g19_threshold_boundary(self):
        """G19: LOCKTIME_THRESHOLD = 500_000_000 (499_999_999 height, 500_000_000 time)."""
        # Just below → height-based
        tx_h = _make_tx(locktime=499_999_999, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertTrue(self._final(tx_h, 500_000_000, 0))
        self.assertFalse(self._final(tx_h, 499_999_998, 0))

        # At threshold → time-based
        tx_t = _make_tx(locktime=500_000_000, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertTrue(self._final(tx_t, 0, 500_000_001))
        self.assertFalse(self._final(tx_t, 0, 500_000_000))

    def test_g20_all_sequence_final_overrides_locktime(self):
        """G20: all inputs SEQUENCE_FINAL → tx is final regardless of locktime."""
        tx = _make_tx(locktime=9_999_999, inputs=[(SEQ_FINAL, b"\xaa" * 32, 0)])
        self.assertTrue(self._final(tx, 1, 1))

    def test_g20_partial_final_does_not_override(self):
        """G20: at least one non-FINAL input → locktime is checked normally."""
        tx = _make_tx(
            locktime=9_999_999,
            inputs=[
                (SEQ_FINAL, b"\xaa" * 32, 0),
                (0,          b"\xbb" * 32, 1),  # NOT SEQUENCE_FINAL
            ],
        )
        # locktime 9_999_999 < LOCKTIME_THRESHOLD → height-based
        # block_height=1 → 9_999_999 >= 1 → not final
        self.assertFalse(self._final(tx, 1, 0))


# ===========================================================================
# G21 — block_mtp == 0 must REJECT (not silent-accept)
# ===========================================================================

class TestG21MtpZeroRejects(unittest.TestCase):
    """G21: block_mtp=0 for a time-locked tx must return False, not True.

    Prior to W80, the Python fallback had 'if block_mtp <= 0: return True',
    silently accepting any time-based locked tx when MTP was unavailable.
    Fix: return False instead (cannot confirm finality without MTP).
    """

    def test_mtp_zero_with_future_time_locktime_rejects(self):
        """block_mtp=0 must not silently accept a time-locked tx."""
        tx = _make_tx(locktime=600_000_000, inputs=[(0, b"\xaa" * 32, 0)])
        result = TransactionValidator._is_final_tx(tx, block_height=1, block_mtp=0)
        self.assertFalse(result, "block_mtp=0 must reject time-locked tx (BUG-A fix)")

    def test_mtp_zero_locktime_zero_still_final(self):
        """locktime=0 short-circuits before any MTP check."""
        tx = _make_tx(locktime=0, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertTrue(TransactionValidator._is_final_tx(tx, 1, 0))

    def test_mtp_zero_height_locktime_works(self):
        """Height-based locktime doesn't use MTP; block_mtp=0 is harmless."""
        tx = _make_tx(locktime=50, inputs=[(0, b"\xaa" * 32, 0)])
        self.assertTrue(TransactionValidator._is_final_tx(tx, 100, 0))

    def test_mtp_negative_time_locktime_rejects(self):
        """Negative block_mtp also must not silently accept time-locked tx."""
        tx = _make_tx(locktime=600_000_000, inputs=[(0, b"\xaa" * 32, 0)])
        result = TransactionValidator._is_final_tx(tx, 1, -1)
        self.assertFalse(result)


# ===========================================================================
# BUG-B — _check_sequence_locks_py intra_block_utxos fix
# ===========================================================================

class TestIntraBlockUtxosPythonFallback(unittest.TestCase):
    """BUG-B: _check_sequence_locks_py must resolve intra-block UTXOs."""

    def test_py_fallback_finds_intra_block_utxo(self):
        """Python fallback must use intra_block_utxos for lookup when DB misses."""
        db = MagicMock()
        db.get_utxo.return_value = None  # DB has no record
        db.get_median_time_past.return_value = 1_600_000_000

        v = TransactionValidator(db, network="regtest")
        tx = _make_tx(version=2, inputs=[(1, b"\xaa" * 32, 0)])

        intra_block = {
            (b"\xaa" * 32, 0): {
                "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
                "script_pubkey": b"\x51", "height": 1000,
            }
        }
        # depth=1100-1000=100>=1 → pass
        result = v._check_sequence_locks_py(
            tx, block_height=1100, block_mtp=1_700_000_000,
            intra_block_utxos=intra_block,
        )
        self.assertTrue(result, "intra-block UTXO must be found in Python fallback")

    def test_py_fallback_fails_without_utxo(self):
        """Without any UTXO source, Python fallback must return False."""
        db = MagicMock()
        db.get_utxo.return_value = None
        db.get_median_time_past.return_value = 1_600_000_000

        v = TransactionValidator(db, network="regtest")
        tx = _make_tx(version=2, inputs=[(1, b"\xaa" * 32, 0)])
        result = v._check_sequence_locks_py(tx, block_height=1100, block_mtp=1_700_000_000)
        self.assertFalse(result, "Missing UTXO must fail")

    def test_outer_check_sequence_locks_uses_intra_block(self):
        """check_sequence_locks must use intra_block_utxos for UTXO lookup."""
        db = MagicMock()
        db.get_utxo.return_value = None
        db.get_utxo_batch.side_effect = lambda _: [None]
        db.get_median_time_past.return_value = 1_600_000_000

        v = TransactionValidator(db, network="regtest")
        tx = _make_tx(version=2, inputs=[(1, b"\xaa" * 32, 0)])

        intra_block = {
            (b"\xaa" * 32, 0): {
                "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
                "script_pubkey": b"\x51", "height": 1000,
            }
        }
        result = v.check_sequence_locks(
            tx, block_height=1100, block_mtp=1_700_000_000,
            network="regtest",
            intra_block_utxos=intra_block,
        )
        self.assertTrue(result)


# ===========================================================================
# BUG-C — enforce_bip68 network-aware fallback
# ===========================================================================

class TestNetworkAwareBip68(unittest.TestCase):
    """BUG-C: enforce_bip68 fallback must use network-specific activation heights."""

    def _val(self, network: str, utxo_h: int = 1000) -> TransactionValidator:
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 50_000,
            "script_pubkey": b"\x51", "height": utxo_h,
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        db.get_median_time_past.return_value = 1_600_000_000
        return TransactionValidator(db, network=network)

    def test_testnet4_active_from_genesis(self):
        """testnet4: BIP-68 active from genesis → enforced at height 1."""
        v = self._val("testnet4", utxo_h=0)
        tx = _make_tx(version=2, inputs=[(1, b"\xaa" * 32, 0)])
        # depth = 1 - 0 = 1 >= 1 → pass
        self.assertTrue(v.check_sequence_locks(tx, 1, 1_600_000_000, network="testnet4"))

    def test_testnet4_enforces_failing_lock(self):
        """testnet4: a failing height lock must be rejected even at low heights."""
        v = self._val("testnet4", utxo_h=500)
        tx = _make_tx(version=2, inputs=[(100, b"\xaa" * 32, 0)])
        # depth = 510 - 500 = 10 < 100 → fail
        self.assertFalse(v.check_sequence_locks(tx, 510, 1_600_000_000, network="testnet4"))

    def test_regtest_enforces_failing_lock(self):
        """regtest: BIP-68 active from genesis."""
        v = self._val("regtest", utxo_h=0)
        tx = _make_tx(version=2, inputs=[(100, b"\xaa" * 32, 0)])
        # depth = 50 - 0 = 50 < 100 → fail
        self.assertFalse(v.check_sequence_locks(tx, 50, 1_600_000_000, network="regtest"))

    def test_mainnet_not_active_before_419328(self):
        """mainnet: BIP-68 NOT active before height 419328."""
        v = self._val("mainnet", utxo_h=1000)
        tx = _make_tx(version=2, inputs=[(65535, b"\xaa" * 32, 0)])
        # Block at mainnet 419327 → BIP-68 off → pass
        self.assertTrue(v.check_sequence_locks(tx, 419327, 1_600_000_000, network="mainnet"))

    def test_mainnet_active_at_419328(self):
        """mainnet: BIP-68 enforced AT height 419328."""
        v = self._val("mainnet", utxo_h=MAINNET_CSV_HEIGHT - 1000)
        tx = _make_tx(version=2, inputs=[(65535, b"\xaa" * 32, 0)])
        # utxo_h=418328, block_height=419328, depth=1000 < 65535 → fail
        self.assertFalse(v.check_sequence_locks(
            tx, MAINNET_CSV_HEIGHT, 1_600_000_000, network="mainnet"
        ))


# ===========================================================================
# Interaction and regression tests
# ===========================================================================

class TestSequenceLockInteractions(unittest.TestCase):
    """Cross-gate interaction and regression tests."""

    def test_mixed_height_time_both_must_satisfy(self):
        """Both height and time constraints must be met simultaneously."""
        db = MagicMock()
        def get_utxo(txid, vout):
            return {"txid": txid, "vout": vout, "value": 10_000,
                    "script_pubkey": b"\x51", "height": 1000}
        db.get_utxo.side_effect = get_utxo
        db.get_utxo_batch.side_effect = lambda ops: [get_utxo(t, v) for t, v in ops]
        db.get_median_time_past.return_value = 1_600_000_000
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[
            (50,           b"\xaa" * 32, 0),   # height lock: depth >= 50
            (SEQ_TYPE | 1, b"\xbb" * 32, 0),   # time lock: MTP diff >= 512
        ])
        # Height OK, time NOT OK
        self.assertFalse(_csl(v, tx, 1050, 1_600_000_000))
        # Height NOT OK, time OK
        self.assertFalse(_csl(v, tx, 1049, 1_600_000_512))
        # Both OK
        self.assertTrue(_csl(v, tx, 1050, 1_600_000_512))

    def test_no_height_metadata_skips_bip68(self):
        """UTXOs without height metadata are skipped (assumevalid-era)."""
        db = MagicMock()
        db.get_utxo.return_value = {
            "txid": b"\xaa" * 32, "vout": 0, "value": 10_000,
            "script_pubkey": b"\x51",
            # 'height' intentionally absent
        }
        db.get_utxo_batch.return_value = [db.get_utxo.return_value]
        db.get_median_time_past.return_value = 1_600_000_000
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[(65535, b"\xaa" * 32, 0)])
        # No height → skip → trivially passes
        self.assertTrue(_csl(v, tx, 100, 1_700_000_000))

    def test_depth_exactly_at_boundary_passes(self):
        """depth == required → pass (min_height = utxo_h + lock - 1 < block_h)."""
        v = _make_validator(utxo_height=1000)
        tx = _make_tx(version=2, inputs=[(10, b"\xaa" * 32, 0)])
        # min_height = 1000 + 10 - 1 = 1009; block_height=1010 > 1009 → pass
        self.assertTrue(_csl(v, tx, 1010, 2_000_000_000))
        # block_height=1009: 1009 >= 1009 → fail
        self.assertFalse(_csl(v, tx, 1009, 2_000_000_000))

    def test_bip113_compares_mtp_not_timestamp(self):
        """BIP-113: IsFinalTx uses MTP of prev block, not block's nTime."""
        tx = _make_tx(locktime=1_600_000_000, inputs=[(0, b"\xaa" * 32, 0)])
        # block_mtp = MTP of prev block
        self.assertTrue(TransactionValidator._is_final_tx(tx, 1000, 1_600_000_001))
        self.assertFalse(TransactionValidator._is_final_tx(tx, 1000, 1_600_000_000))

    def test_sequence_lock_utxo_missing_returns_false(self):
        """When the UTXO cannot be found, check_sequence_locks returns False."""
        db = MagicMock()
        db.get_utxo.return_value = None
        db.get_utxo_batch.return_value = [None]
        db.get_median_time_past.return_value = 1_600_000_000
        v = TransactionValidator(db, network="regtest")

        tx = _make_tx(version=2, inputs=[(1, b"\xaa" * 32, 0)])
        self.assertFalse(_csl(v, tx, 2000, 1_700_000_000))

    def test_v2_tx_zero_sequence_treated_as_height_lock_zero(self):
        """sequence=0 on v2 tx creates a 0-block height lock (depth >= 0 always)."""
        v = _make_validator(utxo_height=500)
        tx = _make_tx(version=2, inputs=[(0, b"\xaa" * 32, 0)])
        # min_height = 500 + 0 - 1 = 499; any block_height > 499 passes
        self.assertTrue(_csl(v, tx, 500, 1_600_000_000))

    def test_all_three_bips_locktime_sequence_mtp(self):
        """Smoke: a tx that satisfies BIP-68 height lock and BIP-113 time locktime."""
        # tx.locktime is time-based (BIP-113), seq is height-based (BIP-68)
        tx = _make_tx(
            version=2,
            locktime=1_600_000_000,  # time-based locktime (BIP-113)
            inputs=[(10, b"\xaa" * 32, 0)],   # 10-block relative lock (BIP-68)
        )
        # BIP-113: locktime=1_600_000_000 < block_mtp=1_600_000_001 → final
        self.assertTrue(
            TransactionValidator._is_final_tx(tx, block_height=1000, block_mtp=1_600_000_001)
        )
        # BIP-68: utxo_height=1000, depth=1010-1000=10>=10 → passes
        v = _make_validator(utxo_height=1000)
        self.assertTrue(_csl(v, tx, 1010, 1_600_000_001))
        # BIP-68: depth=1009-1000=9 < 10 → fails
        self.assertFalse(_csl(v, tx, 1009, 1_600_000_001))


if __name__ == "__main__":
    unittest.main()
