"""
Functional test: mempool policy enforcement.

Tests that the mempool correctly enforces standardness, dust, and
ancestor/descendant limits, as well as TRUC (v3 transaction) policy.
"""

import pytest
from ouroboros.mempool import (
    Mempool, _is_standard_tx, _get_dust_threshold, _has_ephemeral_dust,
    MAX_ANCESTOR_COUNT, MAX_STANDARD_TX_WEIGHT,
    TX_V3_MAX_VSIZE, TX_V3_ANCESTOR_LIMIT, TX_V3_DESCENDANT_LIMIT,
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
        tx = _make_tx(version=4)
        ok, reason = _is_standard_tx(tx)
        assert not ok
        assert "version" in reason.lower()

    def test_v3_is_standard(self):
        tx = _make_tx(version=3)
        ok, reason = _is_standard_tx(tx)
        assert ok, f"v3 should be standard: {reason}"

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


# ── TRUC (v3 Transaction) Policy Tests ──────────────────────────────


class _StubUTXODB:
    """Maps (prev_txid, prev_vout) -> {'value': int}."""

    def __init__(self, mapping: dict):
        self._m = dict(mapping)

    def get_utxo(self, txid, vout):
        return self._m.get((txid, vout))

    def add(self, txid, vout, value):
        self._m[(txid, vout)] = {"value": value}


class _StubValidator:
    """Minimal validator stub that always accepts transactions."""

    def __init__(self, utxo_values: dict):
        self.db = _StubUTXODB(utxo_values)

    def validate_transaction(self, tx, height, block_mtp=0):
        return True, ""


def _truc_tx(
    txid_byte,
    inputs,
    outputs_values,
    version=3,
    sequence=0xFFFFFFFD,
    script_sig_size=72,
):
    """Build a Transaction for TRUC tests.

    *txid_byte*: single byte to fill the 32-byte txid (for easy identification).
    *inputs*: list of (prev_txid_bytes, prev_vout).
    *outputs_values*: list of output satoshi values.
    """
    txid = bytes([txid_byte]) * 32
    return Transaction(
        txid=txid,
        version=version,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=pt,
                prev_vout=pv,
                script_sig=b"\x00" * script_sig_size,
                sequence=sequence,
            )
            for pt, pv in inputs
        ],
        outputs=[
            TxOut(value=v, script_pubkey=b"\x51")
            for v in outputs_values
        ],
    )


def _truc_pool(utxo_values):
    """Create a Mempool with standardness disabled (we test TRUC rules only)."""
    return Mempool(validator=_StubValidator(utxo_values), require_standard=False)


class TestTRUCPolicy:
    """TRUC (Topologically Restricted Until Confirmation) v3 transaction policy."""

    def test_v3_max_vsize_constant(self):
        assert TX_V3_MAX_VSIZE == 10_000

    # ── Test 1: v3 tx with 2 unconfirmed ancestors → reject ──────

    def test_v3_reject_two_unconfirmed_ancestors(self):
        """A v3 transaction with 2 unconfirmed ancestors must be rejected.

        Chain: grandparent (v3, unconfirmed) → parent (v3, unconfirmed) → child (v3)
        The child has 2 unconfirmed ancestors which exceeds the TRUC limit of 1.
        """
        # Confirmed UTXO that funds the grandparent
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        # Grandparent: v3, spends confirmed UTXO
        grandparent = _truc_tx(
            0xAA,
            inputs=[(b"\x00" * 32, 0)],
            outputs_values=[90_000],
            version=3,
        )
        ok, err = pool.add_transaction(grandparent, height=100)
        assert ok, f"Grandparent should be accepted: {err}"

        # Register grandparent's output as available UTXO for parent
        pool.validator.db.add(b"\xAA" * 32, 0, 90_000)

        # Parent: v3, spends grandparent output (1 unconfirmed ancestor = OK)
        parent = _truc_tx(
            0xBB,
            inputs=[(b"\xAA" * 32, 0)],
            outputs_values=[80_000],
            version=3,
        )
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, f"Parent should be accepted: {err}"

        # Register parent's output as available UTXO for child
        pool.validator.db.add(b"\xBB" * 32, 0, 80_000)

        # Child: v3, spends parent output (2 unconfirmed ancestors = REJECT)
        child = _truc_tx(
            0xCC,
            inputs=[(b"\xBB" * 32, 0)],
            outputs_values=[70_000],
            version=3,
        )
        ok, err = pool.add_transaction(child, height=100)
        assert not ok, "Child with 2 unconfirmed ancestors should be rejected"
        assert "ancestor" in err.lower() or "truc" in err.lower()

    # ── Test 2: v3 child > 10,000 vB of v3 parent → reject ──────

    def test_v3_reject_oversized_child(self):
        """A v3 child of an unconfirmed v3 parent that exceeds 10,000 vB
        must be rejected.
        """
        utxos = {(b"\x00" * 32, 0): {"value": 200_000}}
        pool = _truc_pool(utxos)

        # Parent: v3, confirmed funding
        parent = _truc_tx(
            0xAA,
            inputs=[(b"\x00" * 32, 0)],
            outputs_values=[190_000],
            version=3,
        )
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, f"Parent should be accepted: {err}"

        # Register parent's output
        pool.validator.db.add(b"\xAA" * 32, 0, 190_000)

        # Child: v3, very large script_sig to push vsize > 10,000 vB
        # We use a large script_sig to make the serialized size big enough.
        oversized_child = Transaction(
            txid=b"\xBB" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\xAA" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 12_000,  # large enough to exceed 10k vB
                    sequence=0xFFFFFFFD,
                )
            ],
            outputs=[TxOut(value=180_000, script_pubkey=b"\x51")],
        )
        # Sanity: confirm the tx is indeed > 10k bytes
        assert len(oversized_child.serialize()) > TX_V3_MAX_VSIZE

        ok, err = pool.add_transaction(oversized_child, height=100)
        assert not ok, "Oversized v3 child should be rejected"
        assert "vsize" in err.lower() or "truc" in err.lower()

    # ── Test 3: second child of v3 parent → reject ───────────────

    def test_v3_reject_second_child(self):
        """A v3 parent may have at most one unconfirmed child.
        A second child must be rejected (or redirected to RBF).
        """
        utxos = {
            (b"\x00" * 32, 0): {"value": 100_000},
            (b"\x00" * 32, 1): {"value": 100_000},
        }
        pool = _truc_pool(utxos)

        # Parent v3 with two outputs
        parent = Transaction(
            txid=b"\xAA" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\x00" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=40_000, script_pubkey=b"\x51"),
                TxOut(value=40_000, script_pubkey=b"\x51"),
            ],
        )
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, f"Parent should be accepted: {err}"

        # Register parent's outputs
        pool.validator.db.add(b"\xAA" * 32, 0, 40_000)
        pool.validator.db.add(b"\xAA" * 32, 1, 40_000)

        # First child: spends parent output 0
        child1 = _truc_tx(
            0xBB,
            inputs=[(b"\xAA" * 32, 0)],
            outputs_values=[30_000],
            version=3,
        )
        ok, err = pool.add_transaction(child1, height=100)
        assert ok, f"First child should be accepted: {err}"

        # Second child: spends parent output 1 — should be rejected
        # (It will be redirected to try_replace, but there's no actual
        # conflict so the replacement will fail too.)
        child2 = _truc_tx(
            0xCC,
            inputs=[(b"\xAA" * 32, 1)],
            outputs_values=[30_000],
            version=3,
        )
        ok, err = pool.add_transaction(child2, height=100)
        assert not ok, "Second child of v3 parent should be rejected"

    # ── Additional: v3 with 1 unconfirmed ancestor succeeds ──────

    def test_v3_single_ancestor_accepted(self):
        """A v3 tx with exactly 1 unconfirmed ancestor should be accepted."""
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        parent = _truc_tx(
            0xAA,
            inputs=[(b"\x00" * 32, 0)],
            outputs_values=[90_000],
            version=3,
        )
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, f"Parent should be accepted: {err}"

        pool.validator.db.add(b"\xAA" * 32, 0, 90_000)

        child = _truc_tx(
            0xBB,
            inputs=[(b"\xAA" * 32, 0)],
            outputs_values=[80_000],
            version=3,
        )
        ok, err = pool.add_transaction(child, height=100)
        assert ok, f"Single-ancestor v3 child should be accepted: {err}"

    # ── Additional: v3 child within vsize limit is accepted ──────

    def test_v3_child_within_vsize_accepted(self):
        """A v3 child of a v3 parent with vsize ≤ 10,000 should be accepted."""
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        parent = _truc_tx(
            0xAA,
            inputs=[(b"\x00" * 32, 0)],
            outputs_values=[90_000],
            version=3,
        )
        ok, _ = pool.add_transaction(parent, height=100)
        assert ok

        pool.validator.db.add(b"\xAA" * 32, 0, 90_000)

        # Small child, well within 10k vsize
        child = _truc_tx(
            0xBB,
            inputs=[(b"\xAA" * 32, 0)],
            outputs_values=[80_000],
            version=3,
        )
        assert len(child.serialize()) < TX_V3_MAX_VSIZE
        ok, err = pool.add_transaction(child, height=100)
        assert ok, f"Small v3 child should be accepted: {err}"


# ── Ephemeral Dust Policy Tests ─────────────────────────────────────


class TestEphemeralDust:
    """Ephemeral dust policy for v3 transactions (policy/ephemeral_policy.cpp)."""

    # ── Test 1: v3 tx with zero-value output in package where child
    #            spends it → accept ──────────────────────────────────

    def test_v3_ephemeral_dust_in_package_accepted(self):
        """A v3 parent with a zero-value (dust) output should be accepted in
        a package when a child transaction spends that dust output.
        """
        # Confirmed UTXO that funds the parent
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        # Parent: v3 with two outputs — one normal, one zero-value (dust)
        parent = Transaction(
            txid=b"\xAA" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\x00" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=90_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
                TxOut(value=0, script_pubkey=b"\x00\x14" + b"\x00" * 20),  # dust
            ],
        )
        # Confirm it has ephemeral dust
        assert _has_ephemeral_dust(parent) == [1]

        # Child: v3, spends BOTH parent outputs (including dust at index 1)
        child = Transaction(
            txid=b"\xBB" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\xAA" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
                TxIn(
                    prev_txid=b"\xAA" * 32,
                    prev_vout=1,  # spends the dust output
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=80_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
            ],
        )

        ok, err = pool.validate_package([parent, child], height=100)
        assert ok, f"Package with spent ephemeral dust should be accepted: {err}"

    # ── Test 2: v3 tx with zero-value output submitted alone → reject

    def test_v3_ephemeral_dust_individual_rejected(self):
        """A v3 transaction with a zero-value (dust) output must be rejected
        when submitted individually (not in a package).
        """
        # Confirmed UTXO that funds the tx
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        # v3 tx with a zero-value output
        tx = Transaction(
            txid=b"\xAA" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\x00" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=90_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
                TxOut(value=0, script_pubkey=b"\x00\x14" + b"\x00" * 20),  # dust
            ],
        )

        ok, err = pool.add_transaction(tx, height=100)
        assert not ok, "v3 tx with ephemeral dust should be rejected individually"
        assert "ephemeral dust" in err.lower()

    # ── Test 3: v3 package with unspent dust output → reject ────────

    def test_v3_ephemeral_dust_unspent_in_package_rejected(self):
        """A v3 parent with dust output that is NOT spent by any child in the
        package must be rejected.
        """
        utxos = {(b"\x00" * 32, 0): {"value": 100_000}}
        pool = _truc_pool(utxos)

        # Parent: v3, with a zero-value output at index 1
        parent = Transaction(
            txid=b"\xAA" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\x00" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=90_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
                TxOut(value=0, script_pubkey=b"\x00\x14" + b"\x00" * 20),  # dust
            ],
        )

        # Child: only spends output 0 (NOT the dust output at index 1)
        child = Transaction(
            txid=b"\xBB" * 32,
            version=3,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\xAA" * 32,
                    prev_vout=0,  # only spends the normal output
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                ),
            ],
            outputs=[
                TxOut(value=80_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
            ],
        )

        ok, err = pool.validate_package([parent, child], height=100)
        assert not ok, "Package with unspent ephemeral dust should be rejected"
        assert "ephemeral dust" in err.lower()

    # ── Test 4: non-v3 tx with dust is still rejected normally ──────

    def test_non_v3_dust_still_rejected(self):
        """Non-v3 transactions with dust outputs should still be rejected
        by the normal standardness check (no ephemeral dust exemption).
        """
        tx = _make_tx(version=2, output_value=0)
        ok, reason = _is_standard_tx(tx)
        assert not ok
        assert "dust" in reason.lower()

    # ── Test 5: v3 tx without dust passes standardness ──────────────

    def test_v3_no_dust_passes_standardness(self):
        """A v3 transaction without any dust outputs should pass standardness."""
        tx = _make_tx(version=3, output_value=50_000)
        ok, reason = _is_standard_tx(tx)
        assert ok, f"v3 without dust should be standard: {reason}"
