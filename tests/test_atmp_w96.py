"""W96 — AcceptToMemoryPool end-to-end audit (ouroboros).

Audits ouroboros's mempool acceptance pipeline against Bitcoin Core's
``MemPoolAccept::PreChecks`` / ``ReplacementChecks`` /
``PolicyScriptChecks`` / ``ConsensusScriptChecks`` /
``AcceptSingleTransactionInternal`` (validation.cpp:782-1431).

Gates tested:

G1   Coinbase rejection — a coinbase tx is rejected before any other gate
     (Core validation.cpp:802-804: ``if (tx.IsCoinBase()) return Invalid("coinbase")``).
G2   Coinbase rejection in test_accept (testmempoolaccept) path.
G3   Dust output cap — Core allows up to MAX_DUST_OUTPUTS_PER_TX=1 dust output;
     ouroboros previously rejected ANY dust output (policy.cpp:158-162).
G4   Dust output cap — > MAX_DUST_OUTPUTS_PER_TX dust outputs rejected.
G5   PreCheckEphemeralTx — non-zero-fee tx with dust is rejected
     (ephemeral_policy.cpp:23-31).
G6   PreCheckEphemeralTx — zero-fee tx with one dust output is accepted
     (subject to other policy gates).
G7   ValidateInputsStandardness — input spending a non-standard prevScript
     is rejected ("bad-txns-nonstandard-inputs"; policy.cpp:226-233).
G8   ValidateInputsStandardness — input spending WITNESS_UNKNOWN (witness
     version 2+) is rejected ("witness program is undefined";
     policy.cpp:234-240).
G9   ValidateInputsStandardness — P2SH redeem-script sigops > MAX_P2SH_SIGOPS
     rejected ("p2sh redeemscript sigops exceed limit"; policy.cpp:255-258).
G10  ValidateInputsStandardness — P2SH redeem-script with <= MAX_P2SH_SIGOPS
     sigops is allowed.
G11  ValidateInputsStandardness — coinbase exempt (no input-side gates run).
G12  STANDARD vs CONSENSUS script flag delta — mempool acceptance uses the
     STANDARD flag set (NULLFAIL, LOW_S, CLEANSTACK, etc.) on top of the
     consensus per-height flags.  Mirrors PolicyScriptChecks
     (validation.cpp:1135-1156).
G13  ``add_transaction(tx, height)`` evaluates locktime / BIP-68 at height+1
     ("next block"), matching Core's CheckFinalTxAtTip (validation.cpp:147-167).

Reference: bitcoin-core/src/validation.cpp:782-1431
           bitcoin-core/src/policy/policy.cpp:100-263
           bitcoin-core/src/policy/ephemeral_policy.cpp:23-31

Notes:
- These tests use stub validators / DBs and exercise the ATMP pipeline
  directly via ``Mempool._add_transaction_inner`` (and friends).  Sufficient
  to gate the policy decisions without spinning up a full chain.
"""

from __future__ import annotations

import time

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    DEFAULT_MIN_RELAY_TX_FEE,
    DUST_RELAY_TX_FEE,
    MAX_DUST_OUTPUTS_PER_TX,
    MAX_P2SH_SIGOPS,
    Mempool,
    _is_standard_tx,
    _validate_inputs_standardness,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NULL_TXID = bytes(32)


def _txid(tag: int) -> bytes:
    """Make a deterministic 32-byte txid from a small integer."""
    return tag.to_bytes(4, "little") + b"\x00" * 28


# Standard P2PKH scriptPubKey for a deterministic 20-byte hash.
def _p2pkh(seed: int = 1) -> bytes:
    h = bytes([seed]) * 20
    return b"\x76\xa9\x14" + h + b"\x88\xac"


# P2SH scriptPubKey for a deterministic 20-byte hash.
def _p2sh(seed: int = 2) -> bytes:
    h = bytes([seed]) * 20
    return b"\xa9\x14" + h + b"\x87"


# Build a scriptSig that pushes the given redeem script as its last push.
# For redeem scripts up to 75 bytes use a single-byte length push.
def _p2sh_scriptsig(redeem: bytes) -> bytes:
    # leading sig push (token bytes) so the redeem script is the LAST push
    leading = b"\x01\x00"  # OP_PUSHBYTES_1 0x00  (a placeholder sig)
    n = len(redeem)
    if n <= 75:
        return leading + bytes([n]) + redeem
    elif n <= 255:
        return leading + b"\x4c" + bytes([n]) + redeem  # OP_PUSHDATA1
    else:
        return leading + b"\x4d" + n.to_bytes(2, "little") + redeem  # OP_PUSHDATA2


def _make_tx(
    txid: bytes,
    inputs: list,
    outputs: list,  # list of (value, script_pubkey)
    version: int = 2,
    locktime: int = 0,
    coinbase: bool = False,
) -> Transaction:
    """Build a Transaction with explicit prevouts and outputs."""
    if coinbase:
        tx_inputs = [
            TxIn(prev_txid=NULL_TXID, prev_vout=0xFFFFFFFF, script_sig=b"\x00", sequence=0xFFFFFFFF)
        ]
    else:
        tx_inputs = [
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=ss, sequence=seq)
            for pt, pv, ss, seq in inputs
        ]
    tx_outputs = [TxOut(value=v, script_pubkey=spk) for v, spk in outputs]
    return Transaction(
        txid=txid,
        version=version,
        locktime=locktime,
        inputs=tx_inputs,
        outputs=tx_outputs,
    )


class _StubDB:
    def __init__(self, utxos: dict | None = None, mtp: int = 0):
        self._utxos = utxos or {}
        self._mtp = mtp

    def get_utxo(self, txid: bytes, vout: int):
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self._utxos.get(op) for op in outpoints]

    def get_median_time_past(self, height: int) -> int:
        return self._mtp


class _StubValidator:
    def __init__(self, utxos: dict | None = None, mtp: int = 0):
        self.db = _StubDB(utxos, mtp)
        self.network = "mainnet"
        self._last_call: dict | None = None

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        # Record the call args so tests can assert on next_height + flags.
        self._last_call = {
            "tx": tx,
            "height": height,
            "block_mtp": block_mtp,
            "kwargs": kwargs,
        }
        return True, ""


def _pool(
    utxos: dict | None = None,
    mtp: int = 0,
    max_size: int = 300_000_000,
    require_standard: bool = True,
) -> Mempool:
    return Mempool(
        validator=_StubValidator(utxos or {}, mtp),
        max_size=max_size,
        require_standard=require_standard,
        full_rbf=True,
    )


# ---------------------------------------------------------------------------
# G1, G2 — Coinbase rejection
# ---------------------------------------------------------------------------


class TestCoinbaseRejection:
    """Core validation.cpp:802-804.

    > if (tx.IsCoinBase())
    >     return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");
    """

    def test_coinbase_rejected_in_add(self) -> None:
        pool = _pool(require_standard=False)
        cb = _make_tx(_txid(1), [], [(50_00000000, _p2pkh())], coinbase=True)
        assert cb.is_coinbase
        ok, reason = pool.add_transaction(cb, height=100)
        assert not ok
        assert reason == "coinbase"

    def test_coinbase_rejected_in_test_accept(self) -> None:
        pool = _pool(require_standard=False)
        cb = _make_tx(_txid(2), [], [(50_00000000, _p2pkh())], coinbase=True)
        result = pool.accept_to_memory_pool(cb, height=100, test_accept=True)
        assert result["accepted"] is False
        assert result["reject_reason"] == "coinbase"

    def test_coinbase_rejection_precedes_orphan_check(self) -> None:
        """A coinbase tx must NOT enter the orphan pool."""
        pool = _pool(require_standard=False)
        cb = _make_tx(_txid(3), [], [(50_00000000, _p2pkh())], coinbase=True)
        pool.add_transaction(cb, height=100)
        assert not pool.orphan_pool.has(_txid(3))


# ---------------------------------------------------------------------------
# G3, G4 — Dust output cap (IsStandardTx)
# ---------------------------------------------------------------------------


class TestDustOutputCap:
    """Core policy.cpp:158-162.

    > if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
    >     reason = "dust";
    >     return false;
    > }
    """

    def test_one_dust_output_allowed(self) -> None:
        """Exactly MAX_DUST_OUTPUTS_PER_TX (=1) dust outputs must pass _is_standard_tx."""
        # P2PKH dust threshold: 182 * 3000 / 1000 = 546 sat
        tx = _make_tx(
            _txid(10),
            inputs=[(_txid(99), 0, b"\x00" * 1, 0xFFFFFFFD)],  # min push
            outputs=[
                (100_000, _p2pkh()),       # non-dust
                (100, _p2pkh(seed=2)),     # 1 dust output (< 546)
            ],
        )
        # Pad scriptSig to >= MIN_STANDARD_TX_NONWITNESS_SIZE so we don't trip CVE-2017-12842.
        tx.inputs[0] = TxIn(
            prev_txid=_txid(99), prev_vout=0,
            script_sig=b"\x00" * 64,
            sequence=0xFFFFFFFD,
        )
        ok, reason = _is_standard_tx(tx)
        assert ok, f"unexpected reject: {reason}"

    def test_two_dust_outputs_rejected(self) -> None:
        tx = _make_tx(
            _txid(11),
            inputs=[(_txid(99), 0, b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[
                (100_000, _p2pkh()),
                (100, _p2pkh(seed=2)),
                (100, _p2pkh(seed=3)),
            ],
        )
        ok, reason = _is_standard_tx(tx)
        assert not ok
        assert "dust" in reason.lower()

    def test_max_dust_outputs_constant(self) -> None:
        assert MAX_DUST_OUTPUTS_PER_TX == 1


# ---------------------------------------------------------------------------
# G5, G6 — PreCheckEphemeralTx (fee == 0 if has dust)
# ---------------------------------------------------------------------------


class TestEphemeralDustFee:
    """Core ephemeral_policy.cpp:23-31.

    > if ((base_fee != 0 || mod_fee != 0) && !GetDust(tx, dust_relay_rate).empty()) {
    >     return state.Invalid(... "dust", "tx with dust output must be 0-fee");
    > }
    """

    def test_dust_with_nonzero_fee_rejected(self) -> None:
        # Build a tx with 1 dust output and a non-zero fee (input >> sum(outputs)).
        utxo_in = (_txid(100), 0)
        utxos = {utxo_in: {"value": 100_000, "script_pubkey": _p2pkh(), "height": 50, "is_coinbase": False}}
        pool = _pool(utxos=utxos, mtp=1_700_000_000, require_standard=True)

        tx = _make_tx(
            _txid(20),
            inputs=[(utxo_in[0], utxo_in[1], b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[
                (1_000, _p2pkh(seed=4)),   # non-dust
                (100, _p2pkh(seed=5)),     # dust (1 allowed by IsStandardTx)
            ],
        )
        # Input is 100_000, outputs total 1_100, fee = 98_900 (non-zero). Should reject.
        ok, reason = pool.add_transaction(tx, height=200)
        assert not ok
        assert "dust" in reason.lower()
        assert "0-fee" in reason or "must be 0-fee" in reason

    def test_dust_with_zero_fee_passes_pretest_ephemeral_gate(self) -> None:
        # When fee == 0 (input == sum(outputs)), the PreCheckEphemeralTx gate
        # must NOT fire even though there's a dust output.  Other gates (min
        # relay fee) will still reject — we just verify the *specific* gate
        # didn't bypass.
        utxo_in = (_txid(101), 0)
        utxos = {utxo_in: {"value": 1_100, "script_pubkey": _p2pkh(), "height": 50, "is_coinbase": False}}
        pool = _pool(utxos=utxos, mtp=1_700_000_000, require_standard=True)

        tx = _make_tx(
            _txid(21),
            inputs=[(utxo_in[0], utxo_in[1], b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[
                (1_000, _p2pkh(seed=6)),
                (100, _p2pkh(seed=7)),     # dust
            ],
        )
        # Fee = 1_100 - 1_100 = 0.  Will fail min-relay-fee instead.
        ok, reason = pool.add_transaction(tx, height=200)
        # We assert it failed but NOT on the ephemeral-dust gate.
        assert not ok
        # The PreCheckEphemeralTx 0-fee error has both "dust" and "must be 0-fee".
        assert not ("dust" in reason.lower() and "0-fee" in reason)


# ---------------------------------------------------------------------------
# G7, G8, G9, G10, G11 — ValidateInputsStandardness
# ---------------------------------------------------------------------------


class TestValidateInputsStandardness:
    """Core policy.cpp:214-263 (ValidateInputsStandardness).

    Called from PreChecks (validation.cpp:897) when require_standard is on.
    Rejects:
      - NONSTANDARD prevScript types
      - WITNESS_UNKNOWN (witness v2..16, or v0 with wrong program length)
      - P2SH redeem scripts whose accurate sigop count > MAX_P2SH_SIGOPS=15
    """

    def test_nonstandard_input_rejected(self) -> None:
        # Spending a totally-bogus prev script.
        tx = _make_tx(
            _txid(30),
            inputs=[(_txid(99), 0, b"\x00", 0xFFFFFFFD)],
            outputs=[(1000, _p2pkh())],
        )
        prev_scripts = {0: b"\xde\xad\xbe\xef"}  # not a standard type
        ok, reason = _validate_inputs_standardness(tx, prev_scripts)
        assert not ok
        assert "nonstandard-inputs" in reason
        assert "script unknown" in reason

    def test_witness_unknown_v2_rejected(self) -> None:
        # OP_2 (witness v2) + 32-byte program — IsStandard returns WITNESS_UNKNOWN
        # so ValidateInputsStandardness rejects.  ouroboros's
        # _is_standard_output_type returns False for v2; the resulting error
        # message must mention "witness program is undefined".
        spk_v2 = bytes([0x52, 0x20]) + bytes([0x01]) * 32  # OP_2 OP_PUSHBYTES_32 ...
        tx = _make_tx(
            _txid(31),
            inputs=[(_txid(99), 0, b"\x00", 0xFFFFFFFD)],
            outputs=[(1000, _p2pkh())],
        )
        ok, reason = _validate_inputs_standardness(tx, {0: spk_v2})
        assert not ok
        # ouroboros's branch emits "witness program is undefined" when the prev
        # script parses as a witness program but is not P2WPKH/P2WSH/P2TR.
        assert "witness program is undefined" in reason

    def test_p2sh_redeem_excess_sigops_rejected(self) -> None:
        # Build a redeem script with 16 OP_CHECKSIG opcodes (> MAX_P2SH_SIGOPS=15)
        # in accurate-counting mode.  OP_CHECKSIG = 0xac, each counts as 1 sigop.
        redeem = bytes([0xac]) * (MAX_P2SH_SIGOPS + 1)
        scriptsig = _p2sh_scriptsig(redeem)
        tx = _make_tx(
            _txid(32),
            inputs=[(_txid(99), 0, scriptsig, 0xFFFFFFFD)],
            outputs=[(1000, _p2pkh())],
        )
        ok, reason = _validate_inputs_standardness(tx, {0: _p2sh()})
        assert not ok
        assert "p2sh" in reason.lower() and "sigops" in reason.lower()

    def test_p2sh_redeem_within_sigop_limit_passes(self) -> None:
        # 15 OP_CHECKSIG opcodes — exactly at the limit, must pass.
        redeem = bytes([0xac]) * MAX_P2SH_SIGOPS
        scriptsig = _p2sh_scriptsig(redeem)
        tx = _make_tx(
            _txid(33),
            inputs=[(_txid(99), 0, scriptsig, 0xFFFFFFFD)],
            outputs=[(1000, _p2pkh())],
        )
        ok, reason = _validate_inputs_standardness(tx, {0: _p2sh()})
        assert ok, f"unexpected reject: {reason}"

    def test_coinbase_exempt(self) -> None:
        """Coinbase txs skip ValidateInputsStandardness entirely
        (Core policy.cpp:217-219)."""
        cb = _make_tx(_txid(34), [], [(50_00000000, _p2pkh())], coinbase=True)
        ok, reason = _validate_inputs_standardness(cb, {})
        assert ok

    def test_max_p2sh_sigops_constant(self) -> None:
        assert MAX_P2SH_SIGOPS == 15


# ---------------------------------------------------------------------------
# G12 — STANDARD vs CONSENSUS script flag delta
# ---------------------------------------------------------------------------


class TestStandardScriptFlags:
    """Core validation.cpp:1135-1156 (PolicyScriptChecks).

    > constexpr script_verify_flags scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
    > if (!CheckInputScripts(tx, ..., scriptVerifyFlags, ...))

    Mempool acceptance uses STANDARD_SCRIPT_VERIFY_FLAGS (consensus + policy);
    block validation uses only per-height MANDATORY_SCRIPT_VERIFY_FLAGS.
    """

    def test_standard_flags_passed_to_validator(self) -> None:
        # Build a minimal accepted tx and assert that
        # validate_transaction received extra_script_flags > 0 (the policy
        # delta).
        utxo_in = (_txid(102), 0)
        # script_pubkey that resolves to standard P2PKH so input-standardness
        # passes; coin big enough to cover min-relay fee.
        utxos = {utxo_in: {"value": 1_000_000, "script_pubkey": _p2pkh(), "height": 50, "is_coinbase": False}}
        pool = _pool(utxos=utxos, mtp=1_700_000_000, require_standard=True)

        tx = _make_tx(
            _txid(40),
            inputs=[(utxo_in[0], utxo_in[1], b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[(900_000, _p2pkh(seed=8))],
        )
        # Use a recent-mainnet height so all deployments are active and the
        # standard-vs-consensus flag delta is non-empty (NULLFAIL, LOW_S,
        # CLEANSTACK, MINIMALDATA, MINIMALIF, etc.).  At h=800_001 the
        # delta is 0x1e1ea = LOW_S | NULLDUMMY-policy | STRICTENC |
        # MINIMALDATA | NULLFAIL | DISCOURAGE_UPGRADABLE_NOPS |
        # CLEANSTACK | MINIMALIF | DISCOURAGE_UPGRADABLE_PUBKEYTYPE |
        # CONST_SCRIPTCODE | WITNESS_PUBKEYTYPE | DISCOURAGE_UPGRADABLE_WITNESS
        # | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION | DISCOURAGE_OP_SUCCESS
        # | SIGPUSHONLY.
        pool.add_transaction(tx, height=800_000)
        call = pool.validator._last_call
        assert call is not None, "validate_transaction was not invoked"
        flags = call["kwargs"].get("extra_script_flags", 0)
        # Expect at least one non-zero policy flag bit set on mainnet at h>=800_000.
        assert flags > 0, f"expected non-zero policy delta, got {flags}"


# ---------------------------------------------------------------------------
# G13 — Mempool uses tip+1 for next-block evaluation
# ---------------------------------------------------------------------------


class TestNextBlockHeight:
    """Core validation.cpp:147-167 (CheckFinalTxAtTip) and :892:

    > const int nBlockHeight = active_chain_tip.nHeight + 1;
    > if (!Consensus::CheckTxInputs(tx, state, m_view,
    >         m_active_chainstate.m_chain.Height() + 1, ws.m_base_fees)) {

    Mempool holds txs for the *next* block, so locktime, BIP-68 sequence-locks,
    coinbase maturity, etc. must all be evaluated at tip_height + 1.
    """

    def test_validate_transaction_receives_tip_plus_one(self) -> None:
        utxo_in = (_txid(103), 0)
        utxos = {utxo_in: {"value": 1_000_000, "script_pubkey": _p2pkh(), "height": 50, "is_coinbase": False}}
        pool = _pool(utxos=utxos, mtp=1_700_000_000, require_standard=True)

        tx = _make_tx(
            _txid(50),
            inputs=[(utxo_in[0], utxo_in[1], b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[(900_000, _p2pkh(seed=9))],
        )
        pool.add_transaction(tx, height=200)
        call = pool.validator._last_call
        assert call is not None, "validate_transaction was not invoked"
        assert call["height"] == 201, (
            f"expected validate_transaction(..., height=201) (tip+1); got {call['height']}"
        )


# ---------------------------------------------------------------------------
# Regression: orphan still respected, ie ATMP doesn't short-circuit on
# coinbase before standardness check.
# ---------------------------------------------------------------------------


class TestOrderingRegression:
    def test_orphan_for_missing_parent_still_returned(self) -> None:
        pool = _pool(utxos={}, mtp=1_700_000_000, require_standard=False)
        tx = _make_tx(
            _txid(60),
            inputs=[(_txid(999), 0, b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[(1_000, _p2pkh(seed=10))],
        )
        ok, reason = pool.add_transaction(tx, height=200)
        assert not ok
        assert reason == "orphan"

    def test_standard_tx_with_zero_dust_outputs_passes_dust_gate(self) -> None:
        """Regression: ensure the loosened dust gate didn't drop the case
        where there are *zero* dust outputs.  Should still accept."""
        tx = _make_tx(
            _txid(61),
            inputs=[(_txid(99), 0, b"\x00" * 64, 0xFFFFFFFD)],
            outputs=[(100_000, _p2pkh())],   # well above dust threshold
        )
        ok, reason = _is_standard_tx(tx)
        assert ok, f"unexpected reject: {reason}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
