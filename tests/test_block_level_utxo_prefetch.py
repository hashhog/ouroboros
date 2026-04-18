"""Unit tests for the block-level UTXO prefetch (B2-lite, W60).

Background: W60 B0 drain-timing instrumentation showed ``validate_block``
spending ~1.14 s/block at mainnet height 768k — 82 % of drain time —
almost entirely in per-tx Python→Rust FFI to ``get_utxo_batch``
(one call per non-coinbase tx, ~2000 calls per block).  B2-lite hoists
the batch one level: ``validate_block`` calls ``get_utxo_batch`` ONCE
with every non-coinbase outpoint in the block and passes the resulting
dict into ``validate_transaction`` / ``_calculate_tx_fee``.  Those
functions now look up inputs in the prefetched dict and fall back to
``intra_block_utxos`` for outputs created earlier in the same block.

These tests verify:
* prefetched lookups do not issue any further FFI calls,
* the intra-block fallback still works when prefetched holds None,
* the legacy per-tx path is untouched for non-block callers (mempool).
"""

from __future__ import annotations

from dataclasses import dataclass

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.validation import BlockValidator, TransactionValidator


@dataclass
class _UTXO:
    value: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool = False


class RecordingDB:
    """Minimal DB stub that records every UTXO lookup.

    B2-lite's contract is "no per-tx FFI when a block-level prefetch is
    provided".  A recording stub is the easiest way to assert that.
    """

    def __init__(self, utxos: dict[tuple[bytes, int], dict] | None = None):
        self._utxos = utxos or {}
        self.get_utxo_calls: list[tuple[bytes, int]] = []
        self.get_utxo_batch_calls: list[list[tuple[bytes, int]]] = []

    def get_utxo(self, txid: bytes, vout: int):
        self.get_utxo_calls.append((txid, vout))
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        self.get_utxo_batch_calls.append(list(outpoints))
        return [self._utxos.get(o) for o in outpoints]


def _make_tx(inputs: list[tuple[bytes, int]], version: int = 1) -> Transaction:
    """Build a non-coinbase Transaction with *inputs* and one trivial output.

    Version 1 skips BIP68 entirely (``check_sequence_locks`` short-circuits
    on version<2), keeping these tests focused on UTXO-lookup wiring.
    """
    tx_ins = [
        TxIn(prev_txid=txid, prev_vout=vout, script_sig=b"", sequence=0xFFFFFFFF)
        for (txid, vout) in inputs
    ]
    tx_outs = [TxOut(value=1, script_pubkey=b"\x51")]  # 1 sat, OP_TRUE
    return Transaction(
        txid=b"\x11" * 32,
        version=version,
        locktime=0,
        inputs=tx_ins,
        outputs=tx_outs,
    )


def _utxo(value: int = 1000, height: int = 100) -> dict:
    """Build a dict-shaped UTXO matching what validation.py expects."""
    return {
        'value': value,
        'script_pubkey': b"\x51",
        'height': height,
        'is_coinbase': False,
    }


# ---------------------------------------------------------------------------
# validate_transaction — prefetched path
# ---------------------------------------------------------------------------

def test_prefetched_skips_db_lookups_entirely():
    """With a block-level prefetch, no per-tx FFI should be issued."""
    outpoint = (b"\xaa" * 32, 0)
    db = RecordingDB()
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx([outpoint])
    prefetched = {outpoint: _utxo(value=5000)}

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        skip_scripts=True,
        prefetched_utxos=prefetched,
    )

    assert valid, error
    assert db.get_utxo_calls == []
    assert db.get_utxo_batch_calls == []


def test_prefetched_none_falls_back_to_intra_block_utxos():
    """Outpoint missing from committed UTXO set → intra_block_utxos rescues it."""
    outpoint = (b"\xbb" * 32, 1)
    db = RecordingDB()
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx([outpoint])

    # Prefetched has an explicit None — outpoint not in committed DB yet
    # because it was created by an earlier tx in this same block.
    prefetched = {outpoint: None}
    intra = {outpoint: _utxo(value=7000)}

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        intra_block_utxos=intra,
        skip_scripts=True,
        prefetched_utxos=prefetched,
    )

    assert valid, error
    assert db.get_utxo_calls == []
    assert db.get_utxo_batch_calls == []


def test_prefetched_none_and_no_intra_fails():
    """Outpoint not in prefetch, not in intra_block → Input not found."""
    outpoint = (b"\xcc" * 32, 0)
    db = RecordingDB()
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx([outpoint])
    prefetched = {outpoint: None}

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        skip_scripts=True,
        prefetched_utxos=prefetched,
    )

    assert not valid
    assert "Input not found" in error
    # Still no DB hit — we must not fall back to per-tx FFI when a prefetch
    # was supplied, because doing so would mask correctness bugs and defeat
    # the whole point of the block-level batch.
    assert db.get_utxo_calls == []
    assert db.get_utxo_batch_calls == []


def test_prefetched_with_multiple_inputs_no_ffi():
    """N-input tx with full prefetch → still zero FFI."""
    outpoints = [(bytes([i]) * 32, 0) for i in range(5)]
    db = RecordingDB()
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx(outpoints)
    prefetched = {op: _utxo(value=1000 * (i + 1)) for i, op in enumerate(outpoints)}

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        skip_scripts=True,
        prefetched_utxos=prefetched,
    )

    assert valid, error
    assert db.get_utxo_calls == []
    assert db.get_utxo_batch_calls == []


# ---------------------------------------------------------------------------
# validate_transaction — legacy path must still work for mempool callers
# ---------------------------------------------------------------------------

def test_legacy_path_uses_get_utxo_batch_when_no_prefetch():
    """With prefetched_utxos=None and >1 inputs, the per-tx batch path runs."""
    outpoints = [(bytes([i]) * 32, 0) for i in range(3)]
    utxos = {op: _utxo(value=1000) for op in outpoints}
    db = RecordingDB(utxos=utxos)
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx(outpoints)

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        skip_scripts=True,
    )

    assert valid, error
    # Exactly one per-tx batch call, zero single-item calls.
    assert len(db.get_utxo_batch_calls) == 1
    assert db.get_utxo_batch_calls[0] == outpoints
    assert db.get_utxo_calls == []


def test_legacy_single_input_uses_get_utxo():
    """With prefetched=None and a single input, the slow path issues get_utxo."""
    outpoint = (b"\xdd" * 32, 0)
    db = RecordingDB(utxos={outpoint: _utxo(value=1000)})
    validator = TransactionValidator(db, network="mainnet")
    tx = _make_tx([outpoint])

    valid, error = validator.validate_transaction(
        tx, height=800_000, block_mtp=0,
        skip_scripts=True,
    )

    assert valid, error
    # len(tx.inputs) == 1 skips the batch path in the legacy code.
    assert db.get_utxo_calls == [outpoint]
    assert db.get_utxo_batch_calls == []


# ---------------------------------------------------------------------------
# _calculate_tx_fee — prefetched path
# ---------------------------------------------------------------------------

def test_calculate_fee_uses_prefetched_without_ffi():
    """Fee calc reads the prefetched dict; no per-input get_utxo calls."""
    outpoints = [(bytes([i]) * 32, 0) for i in range(3)]
    db = RecordingDB()
    validator = BlockValidator(db, network="mainnet")
    tx = _make_tx(outpoints)
    prefetched = {op: _utxo(value=1000) for op in outpoints}

    # Input total = 3000, output total = 1 → fee = 2999
    fee = validator._calculate_tx_fee(tx, intra_block_utxos=None, prefetched_utxos=prefetched)

    assert fee == 2999
    assert db.get_utxo_calls == []


def test_calculate_fee_falls_back_to_intra_block_utxos():
    """Prefetch has None for an intra-block dep → fee reads from intra dict."""
    op_db = (b"\xee" * 32, 0)
    op_intra = (b"\xff" * 32, 0)
    db = RecordingDB()
    validator = BlockValidator(db, network="mainnet")
    tx = _make_tx([op_db, op_intra])
    prefetched = {op_db: _utxo(value=2000), op_intra: None}
    intra = {op_intra: _utxo(value=3000)}

    fee = validator._calculate_tx_fee(tx, intra_block_utxos=intra, prefetched_utxos=prefetched)

    # Input total = 5000, output = 1 → fee = 4999.
    assert fee == 4999
    assert db.get_utxo_calls == []


def test_calculate_fee_legacy_path_still_hits_db():
    """With prefetched=None, fee calc uses the existing per-input get_utxo path."""
    outpoints = [(bytes([i]) * 32, 0) for i in range(2)]
    db = RecordingDB(utxos={op: _utxo(value=1000) for op in outpoints})
    validator = BlockValidator(db, network="mainnet")
    tx = _make_tx(outpoints)

    fee = validator._calculate_tx_fee(tx, intra_block_utxos=None)

    assert fee == 1999
    assert db.get_utxo_calls == outpoints


# ---------------------------------------------------------------------------
# Realistic-shape FFI-reduction assertion
# ---------------------------------------------------------------------------

def test_mainnet_shape_2000tx_block_one_ffi_not_two_thousand():
    """Sanity: for a 2000-tx block with 2 inputs each, the helper makes
    exactly ONE get_utxo_batch call with 4000 outpoints — the whole point
    of B2-lite vs the old per-tx path (2000 calls × 2 outpoints each)."""
    # Build the outpoint list the same way validate_block does.
    txs_outpoints = [
        [(bytes([i & 0xFF, (i >> 8) & 0xFF]).ljust(32, b"\x00"), 0),
         (bytes([i & 0xFF, (i >> 8) & 0xFF]).ljust(32, b"\x00"), 1)]
        for i in range(2000)
    ]
    all_outpoints = [op for tx_ops in txs_outpoints for op in tx_ops]

    db = RecordingDB(utxos={op: _utxo(value=1) for op in all_outpoints})
    # Simulate what validate_block does: one batch call covering the whole
    # block, then O(1) dict lookups per tx.
    batch = db.get_utxo_batch(all_outpoints)
    prefetched = dict(zip(all_outpoints, batch))

    validator = TransactionValidator(db, network="mainnet")
    for tx_ops in txs_outpoints:
        tx = _make_tx(tx_ops)
        valid, error = validator.validate_transaction(
            tx, height=800_000, block_mtp=0,
            skip_scripts=True,
            prefetched_utxos=prefetched,
        )
        assert valid, error

    # Exactly ONE FFI call for the whole 2000-tx block.
    assert len(db.get_utxo_batch_calls) == 1
    assert len(db.get_utxo_batch_calls[0]) == 4000
    assert db.get_utxo_calls == []
