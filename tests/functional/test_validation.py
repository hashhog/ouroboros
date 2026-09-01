"""
Tests for block and transaction validation rules.

Covers coinbase maturity, block subsidy, BIP 113 MTP locktime,
BIP 68 sequence locks, and basic structural checks.
"""

from unittest.mock import MagicMock, patch

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.validation import (
    BlockValidator,
    TransactionValidator,
    _bits_to_target,
)


def _make_tx(
    *,
    version=2,
    locktime=0,
    inputs=None,
    outputs=None,
    is_coinbase=False,
):
    tx = MagicMock(spec=Transaction)
    tx.version = version
    tx.locktime = locktime
    tx.inputs = inputs or []
    tx.outputs = outputs or []
    tx.is_coinbase = is_coinbase
    tx.serialize.return_value = b'\x00' * 200
    # validation.py _verify_input_signature keys the sigcache envelope on
    # serialize_with_witness(); a spec'd MagicMock method returns a Mock.
    tx.serialize_with_witness.return_value = b'\x00' * 200
    tx.get_txid.return_value = b'\xaa' * 32
    return tx


def _make_txin(prev_txid=None, prev_vout=0, script_sig=b'', sequence=0xffffffff):
    inp = MagicMock(spec=TxIn)
    inp.prev_txid = prev_txid or b'\x01' * 32
    inp.prev_vout = prev_vout
    inp.script_sig = script_sig
    inp.sequence = sequence
    return inp


def _make_txout(value=50000, script_pubkey=b'\x76\xa9' + b'\x14' + b'\x00' * 20 + b'\x88\xac'):
    out = MagicMock(spec=TxOut)
    out.value = value
    out.script_pubkey = script_pubkey
    return out


def _mock_db(utxo_value=100000, utxo_height=1, is_coinbase=False):
    db = MagicMock()
    utxo = {
        'value': utxo_value,
        'script_pubkey': b'\x76\xa9' + b'\x14' + b'\x00' * 20 + b'\x88\xac',
        'height': utxo_height,
        'is_coinbase': is_coinbase,
    }
    db.get_utxo.return_value = utxo
    # validation.py validate_transaction prefers db.get_utxo_batch(outpoints)
    # (one result per outpoint) when the db has it; a bare MagicMock "has" it
    # and would yield an empty iterable, so give it real semantics.
    db.get_utxo_batch.side_effect = lambda outpoints: [dict(utxo) for _ in outpoints]
    db.get_median_time_past.return_value = 1700000000
    return db


class TestBitsToTarget:
    def test_zero_mantissa(self):
        assert _bits_to_target(0x00000000) == 0

    def test_exponent_3(self):
        assert _bits_to_target(0x03010000) == 0x010000

    def test_exponent_less_than_3(self):
        result = _bits_to_target(0x02010000)
        assert result == 0x0100

    def test_standard_bits(self):
        target = _bits_to_target(0x1d00ffff)
        assert target > 0


class TestBlockSubsidy:
    def setup_method(self):
        self.db = MagicMock()
        self.validator = BlockValidator(self.db)

    def test_first_era(self):
        assert self.validator._calculate_block_subsidy(0) == 50 * 100_000_000

    def test_first_halving(self):
        assert self.validator._calculate_block_subsidy(210000) == 25 * 100_000_000

    def test_second_halving(self):
        assert self.validator._calculate_block_subsidy(420000) == 1250000000

    def test_64_halvings(self):
        assert self.validator._calculate_block_subsidy(210000 * 64) == 0


class TestCoinbaseMaturity:
    """Coinbase outputs need 100 confirmations before spending."""

    def setup_method(self):
        self.db = _mock_db(utxo_value=100000, utxo_height=100, is_coinbase=True)
        self.validator = TransactionValidator(self.db)

    def test_immature_coinbase_rejected(self):
        inp = _make_txin()
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        valid, msg = self.validator.validate_transaction(tx, height=150)
        assert not valid
        # Core consensus/tx_verify.cpp:180 "bad-txns-premature-spend-of-coinbase"
        assert "bad-txns-premature-spend-of-coinbase" in msg

    def test_mature_coinbase_accepted_at_exact_depth(self):
        inp = _make_txin()
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=200)
        assert valid

    def test_non_coinbase_utxo_no_maturity_check(self):
        self.db = _mock_db(utxo_value=100000, utxo_height=100, is_coinbase=False)
        self.validator = TransactionValidator(self.db)

        inp = _make_txin()
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=101)
        assert valid


class TestBIP113MTPLocktime:
    """BIP 113: locktime (when >= 500_000_000) checked against MTP."""

    def setup_method(self):
        self.db = _mock_db(utxo_value=100000, utxo_height=1)
        self.validator = TransactionValidator(self.db)

    def test_future_locktime_rejected_nonfinal_sequence(self):
        inp = _make_txin(sequence=0x00000001)
        out = _make_txout(value=50000)
        tx = _make_tx(locktime=1700000001, inputs=[inp], outputs=[out])

        valid, msg = self.validator.validate_transaction(tx, height=800000, block_mtp=1700000000)
        assert not valid
        # Core validation.cpp ContextualCheckTransaction / MemPoolAccept:
        # the reject token for an unsatisfied nLockTime is "non-final".
        assert "non-final" in msg

    def test_past_locktime_accepted(self):
        inp = _make_txin(sequence=0x00000001)
        out = _make_txout(value=50000)
        tx = _make_tx(locktime=1699999999, inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=800000, block_mtp=1700000000)
        assert valid

    def test_final_sequence_bypasses_locktime(self):
        inp = _make_txin(sequence=0xffffffff)
        out = _make_txout(value=50000)
        tx = _make_tx(locktime=1700000001, inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=800000, block_mtp=1700000000)
        assert valid


class TestBIP68SequenceLocks:
    """BIP 68 relative lock-time via nSequence for version-2 transactions."""

    def setup_method(self):
        self.db = _mock_db(utxo_value=100000, utxo_height=100)
        # Use regtest so BIP68 is active at height 0 (no mainnet activation wait)
        self.validator = TransactionValidator(self.db, network="regtest")

    def test_height_lock_not_satisfied(self):
        inp = _make_txin(sequence=10)
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, msg = self.validator.validate_transaction(tx, height=105)
        assert not valid
        assert "sequence" in msg.lower() or "BIP 68" in msg

    def test_height_lock_satisfied(self):
        inp = _make_txin(sequence=10)
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=110)
        assert valid

    def test_disable_flag_skips_check(self):
        inp = _make_txin(sequence=0x80000001)
        out = _make_txout(value=50000)
        tx = _make_tx(inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=101)
        assert valid

    def test_v1_tx_skips_bip68(self):
        inp = _make_txin(sequence=10)
        out = _make_txout(value=50000)
        tx = _make_tx(version=1, inputs=[inp], outputs=[out])

        with patch.object(self.validator.script_interpreter, 'verify', return_value=True):
            valid, _msg = self.validator.validate_transaction(tx, height=101)
        assert valid


class TestTransactionStructure:
    def setup_method(self):
        self.db = _mock_db()
        self.validator = TransactionValidator(self.db)

    def test_empty_inputs_rejected(self):
        tx = _make_tx(inputs=[], outputs=[_make_txout()])
        valid, msg = self.validator.validate_transaction(tx, height=1)
        assert not valid

    def test_empty_outputs_rejected(self):
        tx = _make_tx(inputs=[_make_txin()], outputs=[])
        valid, msg = self.validator.validate_transaction(tx, height=1)
        assert not valid

    def test_v3_tx_passes_structure_check(self):
        # BIP-431 TRUC: tx version 3 is mempool/relay policy, NOT consensus.
        # Bitcoin Core's consensus/tx_check.cpp::CheckTransaction has no
        # nVersion check — block consensus accepts any nVersion. Pre-fix
        # ouroboros rejected version=3 in _check_structure, which wedged
        # mainnet IBD past the snapshot tip on block 944,184 tx 217 (txid
        # 7372defce8713521da62fe0284b4fd23c3f33c8a7a23275788b50762db8fc0a3).
        tx = _make_tx(version=3, inputs=[_make_txin()], outputs=[_make_txout()])
        assert self.validator._check_structure(tx) is None  # None == valid (else Core reject token)

    def test_v0_tx_passes_structure_check(self):
        # Per Core, even version=0 is consensus-valid (mempool would
        # reject via IsStandardTx, but block validation does not).
        tx = _make_tx(version=0, inputs=[_make_txin()], outputs=[_make_txout()])
        assert self.validator._check_structure(tx) is None  # None == valid (else Core reject token)

    def test_high_version_tx_passes_structure_check(self):
        # Future soft-fork tx versions must be consensus-accepted
        # (forward compatibility).
        tx = _make_tx(version=99, inputs=[_make_txin()], outputs=[_make_txout()])
        assert self.validator._check_structure(tx) is None  # None == valid (else Core reject token)

    def test_negative_output_value_rejected(self):
        tx = _make_tx(inputs=[_make_txin()], outputs=[_make_txout(value=-1)])
        valid, msg = self.validator.validate_transaction(tx, height=1)
        assert not valid

    def test_overflow_output_value_rejected(self):
        tx = _make_tx(inputs=[_make_txin()], outputs=[_make_txout(value=21000001 * 100000000)])
        valid, msg = self.validator.validate_transaction(tx, height=1)
        assert not valid
