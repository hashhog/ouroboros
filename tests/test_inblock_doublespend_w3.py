"""
Wave-3 — In-block double-spend detection (Python validate_block path).

Reference:
  Bitcoin Core validation.cpp:2535  (Chainstate::ConnectBlock)
  Bitcoin Core coins.cpp:153-175    (CCoinsViewCache::SpendCoin)
  Bitcoin Core coins.cpp:329-339    (CCoinsViewCache::HaveInputs)
  Bitcoin Core consensus/tx_verify.cpp:167-170  (Consensus::CheckTxInputs)

Bug (pre-fix):
  ouroboros's ``BlockValidator.validate_block`` built ``intra_block_utxos`` as
  an add-only map (outputs only, never removed when spent).  A non-coinbase tx
  that spent an on-disk UTXO never marked it spent, and a second non-coinbase
  tx in the same block that tried to spend the same outpoint would
  (a) not find it in ``intra_block_utxos`` and
  (b) call ``get_utxo`` / ``get_utxo_batch`` against the unflushed DB, which
      still returns the coin — yielding a silent false-accept.

Fix (post-fix):
  A ``spent_in_block: set[tuple[bytes, int]]`` is populated after each
  non-coinbase tx is validated.  Before calling ``validate_transaction`` for
  the next tx, every input's (prev_txid, prev_vout) is checked against this
  set; a hit returns immediately with "bad-txns-inputs-missingorspent".
  Spent intra-block outputs are also evicted from ``intra_block_utxos``.

EFFECTIVE criterion (wave-3):
  Pre-fix: ``validate_block`` returned ``(True, "")`` for a block where two
           non-coinbase transactions both spend the same outpoint (DB returns
           the coin for both, no cross-tx tracking).
  Post-fix: returns ``(False, "bad-txns-inputs-missingorspent")``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

# Install the sync mock before any ouroboros import.
import tests.conftest  # noqa: F401


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tx_in(prev_txid: bytes, prev_vout: int) -> MagicMock:
    """Return a mock TxIn with the given prev-outpoint."""
    tx_in = MagicMock()
    tx_in.prev_txid = prev_txid
    tx_in.prev_vout = prev_vout
    tx_in.script_sig = b""
    tx_in.sequence = 0xFFFFFFFF
    return tx_in


def _make_non_coinbase_tx(
    txid: bytes,
    inputs: list,
    output_value: int = 900_000,
    script_pubkey: bytes = b"\x51",
) -> MagicMock:
    tx = MagicMock()
    tx.is_coinbase = False
    tx.get_txid.return_value = txid
    tx.inputs = inputs
    out = MagicMock()
    out.value = output_value
    out.script_pubkey = script_pubkey
    tx.outputs = [out]
    tx.version = 2
    tx.locktime = 0
    return tx


def _make_coinbase_tx(
    txid: bytes = b"\xcc" * 32,
    output_value: int = 5_000_000_000,
) -> MagicMock:
    cb = MagicMock()
    cb.is_coinbase = True
    cb.get_txid.return_value = txid
    cb.inputs = [_make_tx_in(bytes(32), 0xFFFFFFFF)]
    out = MagicMock()
    out.value = output_value
    out.script_pubkey = b"\x51"
    cb.outputs = [out]
    cb.version = 1
    cb.locktime = 0
    return cb


def _make_prev_block() -> MagicMock:
    """Minimal mock for the block at height prev_height (height - 1)."""
    prev = MagicMock()
    prev.hash = bytes(32)
    prev.timestamp = 1_600_000_000
    prev.bits = 0x207FFFFF
    prev.height = 199
    prev.version = 4
    return prev


def _utxo_dict(
    txid: bytes,
    vout: int,
    value: int = 1_000_000,
    is_coinbase: bool = False,
    height: int = 100,
) -> dict:
    return {
        "txid": txid,
        "vout": vout,
        "value": value,
        "script_pubkey": b"\x51",
        "height": height,
        "is_coinbase": is_coinbase,
    }


# ---------------------------------------------------------------------------
# Core test: on-disk UTXO double-spend detection
# ---------------------------------------------------------------------------

class TestInBlockDoubleSpendDetection:
    """Two non-coinbase txs spending the same on-disk UTXO must be rejected.

    This is the wave-3 consensus-parity fix.  Bitcoin Core's
    ``CCoinsViewCache::SpendCoin`` removes each coin from the cache as
    ``ConnectBlock`` processes each tx; a second tx that tries to re-spend
    the same coin fails ``HaveInputs`` (coins.cpp:329-339) with
    "bad-txns-inputs-missingorspent".

    ouroboros previously lacked any cross-transaction spent tracking in
    ``BlockValidator.validate_block``, so the same coin would be found in
    the (unflushed) DB on both spends — a silent false-accept.
    """

    def _make_validator(self, network: str = "regtest"):
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        return BlockValidator(db, network=network), db

    def _run_validate_block(self, v, block, db, *, known_height: int = 200):
        """Call validate_block with all structural checks mocked away.

        • db.get_block → prev block (needed for the prev-block lookup).
        • db.get_utxo → None (ensures BIP30 check passes; the block's own
          txids must not exist in the UTXO set to avoid BIP30 rejection).
        • All heavy per-block validators (header, merkle, limits, witness,
          signet, coinbase) are stubbed out so the test can focus purely on
          the in-block double-spend detection logic in the tx-loop.
        """
        with \
                patch.object(db, "get_block", return_value=_make_prev_block()), \
                patch.object(db, "get_utxo", return_value=None), \
                patch.object(v, "_validate_header", return_value=True), \
                patch.object(v, "_verify_merkle_root", return_value=True), \
                patch.object(v, "_validate_block_limits", return_value=(True, "")), \
                patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
                patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
                patch.object(v, "_validate_coinbase", return_value=True), \
                patch.object(v, "_verify_coinbase_amount", return_value=True), \
                patch.object(v.tx_validator, "_is_final_tx", return_value=True):
            return v.validate_block(block, known_height=known_height)

    # ------------------------------------------------------------------
    # EFFECTIVE test: on-disk double-spend is now rejected
    # ------------------------------------------------------------------

    def test_ondisk_double_spend_within_block_rejected(self):
        """Wave-3 EFFECTIVE test: second spend of an on-disk UTXO is rejected.

        Pre-fix: both tx_A and tx_B called validate_transaction successfully
        because the DB still had the coin (batch uncommitted) — (True, "").

        Post-fix: after tx_A is validated, outpoint_X is added to
        ``spent_in_block``; when tx_B is processed, the check fires before
        ``validate_transaction`` is ever called, returning
        (False, "bad-txns-inputs-missingorspent").
        """
        v, db = self._make_validator("regtest")

        # Shared on-disk UTXO that both tx_A and tx_B try to spend.
        shared_txid = b"\xAA" * 32
        shared_vout = 0
        utxo_x = _utxo_dict(shared_txid, shared_vout, value=1_000_000)

        # tx_A: spends utxo_X, produces some output
        tx_in_a = _make_tx_in(shared_txid, shared_vout)
        tx_a = _make_non_coinbase_tx(b"\xBB" * 32, [tx_in_a], output_value=900_000)

        # tx_B: ALSO spends utxo_X (double-spend)
        tx_in_b = _make_tx_in(shared_txid, shared_vout)
        tx_b = _make_non_coinbase_tx(b"\xCC" * 32, [tx_in_b], output_value=900_000)

        coinbase = _make_coinbase_tx()
        block = MagicMock()
        block.hash = b"\xFF" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [coinbase, tx_a, tx_b]
        block.timestamp = 1_600_001_000
        block.bits = 0x207FFFFF
        block.version = 4

        # Simulate that validate_transaction succeeds for any input
        # (the DB still has the coin on both calls — exactly the pre-fix bug).
        def fake_validate_tx(tx, *args, fees_out=None, **kwargs):
            if fees_out is not None:
                fees_out.append(100_000)
            return (True, "")

        with patch.object(
            v.tx_validator, "validate_transaction", side_effect=fake_validate_tx
        ) as mock_vt:
            ok, err = self._run_validate_block(v, block, db)

        # Post-fix: MUST reject with the canonical Core error string.
        assert not ok, "double-spend block must be rejected"
        assert "missingorspent" in err, f"expected 'missingorspent' in error, got: {err!r}"

        # validate_transaction was called for tx_A but NOT for tx_B
        # (the double-spend gate fires before it).
        assert mock_vt.call_count == 1, (
            f"expected validate_transaction called once (tx_A only), "
            f"but was called {mock_vt.call_count} time(s)"
        )

    def test_intrablock_output_double_spend_rejected(self):
        """An intra-block output (created by tx_A) cannot be spent twice.

        tx_A creates output Y.  tx_B spends Y (legitimate intra-block spend).
        tx_C ALSO spends Y (double-spend of an intra-block output).

        Pre-fix: tx_C would find Y in ``intra_block_utxos`` (it was never
        removed) and validate_transaction would succeed.

        Post-fix: after tx_B is validated, Y is added to ``spent_in_block``
        AND removed from ``intra_block_utxos``.  When tx_C is processed the
        double-spend check fires before validate_transaction is called.
        """
        v, db = self._make_validator("regtest")

        # tx_A creates intra-block output Y.
        txid_a = b"\xAA" * 32
        coinbase_in = _make_tx_in(bytes(32), 0xFFFFFFFF)
        # tx_A is the coinbase in this simplified test — it creates output Y.
        # In a real block the coinbase is tx[0]; here we test the intra-block
        # eviction through a coinbase output that a later tx tries to spend twice.
        coinbase = _make_coinbase_tx(txid=txid_a, output_value=5_000_000_000)

        # tx_B: spends the coinbase output Y (intra-block spend, allowed if mature).
        # For simplicity we use a different txid and a non-coinbase flag so
        # the coinbase-maturity check isn't triggered (height < coinbase_height + 100).
        # We focus only on the double-spend detection path.
        txid_b = b"\xBB" * 32
        intra_txid = b"\xDD" * 32  # a non-coinbase intra-block output
        intra_vout = 0

        # Add an intra-block producer: a tx that creates an output the later txs fight over.
        txid_producer = b"\xDD" * 32
        out_producer = MagicMock()
        out_producer.value = 500_000
        out_producer.script_pubkey = b"\x51"
        tx_producer = MagicMock()
        tx_producer.is_coinbase = False
        tx_producer.get_txid.return_value = txid_producer
        tx_in_producer = _make_tx_in(b"\x01" * 32, 0)  # spends some on-disk coin
        tx_producer.inputs = [tx_in_producer]
        tx_producer.outputs = [out_producer]
        tx_producer.version = 2
        tx_producer.locktime = 0

        # tx_B: spends the intra-block output (txid_producer, 0)
        tx_in_b = _make_tx_in(txid_producer, 0)
        tx_b = _make_non_coinbase_tx(txid_b, [tx_in_b], output_value=400_000)

        # tx_C: ALSO spends the intra-block output (txid_producer, 0) — double-spend
        txid_c = b"\xCC" * 32
        tx_in_c = _make_tx_in(txid_producer, 0)
        tx_c = _make_non_coinbase_tx(txid_c, [tx_in_c], output_value=400_000)

        block = MagicMock()
        block.hash = b"\xFF" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [coinbase, tx_producer, tx_b, tx_c]
        block.timestamp = 1_600_001_000
        block.bits = 0x207FFFFF
        block.version = 4

        # DB has a coin for the producer tx's on-disk input (so tx_producer validates).
        producer_input_utxo = _utxo_dict(b"\x01" * 32, 0, value=500_000)
        db.get_utxo_batch.side_effect = lambda outpoints: [
            producer_input_utxo if op == (b"\x01" * 32, 0) else None
            for op in outpoints
        ]

        call_count = 0

        def fake_validate_tx(tx, *args, fees_out=None, intra_block_utxos=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if fees_out is not None:
                fees_out.append(50_000)
            return (True, "")

        with patch.object(
            v.tx_validator, "validate_transaction", side_effect=fake_validate_tx
        ):
            ok, err = self._run_validate_block(v, block, db)

        # tx_producer and tx_b should succeed; tx_c should be blocked.
        assert not ok, "block with double-spent intra-block output must be rejected"
        assert "missingorspent" in err, (
            f"expected 'missingorspent' in error, got: {err!r}"
        )
        # validate_transaction was called for tx_producer and tx_b (2 times),
        # but NOT for tx_c (the double-spend check fires first).
        assert call_count == 2, (
            f"expected 2 validate_transaction calls (tx_producer + tx_b), "
            f"got {call_count}"
        )

    def test_distinct_inputs_same_block_accepted(self):
        """Sanity check: two txs spending DIFFERENT outpoints in the same block is fine."""
        v, db = self._make_validator("regtest")

        # tx_A spends outpoint X
        txid_x = b"\xAA" * 32
        tx_in_a = _make_tx_in(txid_x, 0)
        tx_a = _make_non_coinbase_tx(b"\xBB" * 32, [tx_in_a], output_value=900_000)

        # tx_B spends outpoint Y (DIFFERENT from X)
        txid_y = b"\xDD" * 32
        tx_in_b = _make_tx_in(txid_y, 0)
        tx_b = _make_non_coinbase_tx(b"\xCC" * 32, [tx_in_b], output_value=900_000)

        coinbase = _make_coinbase_tx()
        block = MagicMock()
        block.hash = b"\xFF" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [coinbase, tx_a, tx_b]
        block.timestamp = 1_600_001_000
        block.bits = 0x207FFFFF
        block.version = 4

        call_count = 0

        def fake_validate_tx(tx, *args, fees_out=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if fees_out is not None:
                fees_out.append(50_000)
            return (True, "")

        with patch.object(
            v.tx_validator, "validate_transaction", side_effect=fake_validate_tx
        ):
            ok, err = self._run_validate_block(v, block, db)

        assert ok, f"distinct inputs in same block must be accepted; err={err!r}"
        assert call_count == 2, (
            f"both txs must be validated; got {call_count} validate_transaction calls"
        )

    def test_coinbase_output_in_intra_block_utxos_when_child_validates(self):
        """The coinbase output is visible in intra_block_utxos when the child tx validates.

        This tests the basic intra-block overlay invariant: when tx_A (a non-coinbase tx)
        is validated, the coinbase's output is already in intra_block_utxos because
        the coinbase was processed first (i=0).
        """
        v, db = self._make_validator("regtest")

        # Coinbase creates output at (cb_txid, 0)
        cb_txid = b"\xAA" * 32
        coinbase = _make_coinbase_tx(txid=cb_txid, output_value=5_000_000_000)

        # tx_A: spends the coinbase output (intra-block).
        tx_in_a = _make_tx_in(cb_txid, 0)
        tx_a = _make_non_coinbase_tx(b"\xBB" * 32, [tx_in_a], output_value=4_900_000_000)

        block = MagicMock()
        block.hash = b"\xFF" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [coinbase, tx_a]
        block.timestamp = 1_600_001_000
        block.bits = 0x207FFFFF
        block.version = 4

        captured_intra: list[dict] = []

        def capture_validate(tx, *args, intra_block_utxos=None, fees_out=None, **kwargs):
            # Capture a COPY of the intra_block_utxos at call time so later
            # mutations to the live dict don't affect our assertions.
            captured_intra.append(dict(intra_block_utxos or {}))
            if fees_out is not None:
                fees_out.append(100_000_000)
            return (True, "")

        with patch.object(
            v.tx_validator, "validate_transaction", side_effect=capture_validate
        ):
            self._run_validate_block(v, block, db)

        # The coinbase output (cb_txid, 0) must be in intra_block_utxos when
        # tx_A is validated — that's what allows intra-block spending.
        assert len(captured_intra) == 1, "validate_transaction called exactly once"
        assert (cb_txid, 0) in captured_intra[0], (
            "coinbase output must be in intra_block_utxos when tx_A is validated"
        )
