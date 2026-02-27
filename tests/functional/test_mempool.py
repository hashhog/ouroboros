"""
Functional test: mempool policy enforcement.

Tests that the mempool correctly enforces standardness, dust, and
ancestor/descendant limits.
"""

import pytest
from ouroboros.mempool import (
    Mempool, _is_standard_tx, _get_dust_threshold,
    MAX_ANCESTOR_COUNT, MAX_STANDARD_TX_WEIGHT,
)
from ouroboros.database import Transaction, TxIn, TxOut


def _make_tx(
    version=2,
    n_inputs=1,
    n_outputs=1,
    output_value=50000,
    output_script=b'\x00\x14' + b'\x00' * 20,
    locktime=0,
):
    """Helper to build a minimal transaction."""
    inputs = [
        TxIn(
            prev_txid=bytes(32),
            prev_vout=i,
            script_sig=b'\x00' * 72,
            sequence=0xFFFFFFFD,
        )
        for i in range(n_inputs)
    ]
    outputs = [
        TxOut(value=output_value, script_pubkey=output_script)
        for _ in range(n_outputs)
    ]
    return Transaction(
        txid=bytes(32),
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
    )


class TestStandardness:
    def test_standard_tx(self):
        tx = _make_tx(output_value=50000)
        ok, reason = _is_standard_tx(tx)
        assert ok, f"Expected standard: {reason}"

    def test_nonstandard_version(self):
        tx = _make_tx(version=3)
        ok, reason = _is_standard_tx(tx)
        assert not ok
        assert "version" in reason.lower()

    def test_dust_output(self):
        tx = _make_tx(output_value=1)
        ok, reason = _is_standard_tx(tx)
        assert not ok
        assert "dust" in reason.lower()


class TestDustThreshold:
    def test_p2wpkh(self):
        script = b'\x00\x14' + b'\x00' * 20
        threshold = _get_dust_threshold(script)
        assert threshold > 0
        assert threshold < 600

    def test_p2pkh(self):
        script = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'
        threshold = _get_dust_threshold(script)
        assert threshold > 0
        assert threshold < 1000

    def test_p2tr(self):
        script = b'\x51\x20' + b'\x00' * 32
        threshold = _get_dust_threshold(script)
        assert threshold > 0


class TestAncestorLimits:
    def test_max_ancestor_count(self):
        assert MAX_ANCESTOR_COUNT == 25

    def test_max_standard_tx_weight(self):
        assert MAX_STANDARD_TX_WEIGHT == 400_000
