"""
W74 — Comprehensive sigops counting audit tests.

Covers all 12 gates from Bitcoin Core:
  1.  GetLegacySigOpCount: scriptSig sigops (inaccurate) for ALL txs incl coinbase
  2.  GetLegacySigOpCount: scriptPubKey sigops (inaccurate)
  3.  P2SH: redeem-script sigops (accurate), × WITNESS_SCALE_FACTOR
  4.  P2WSH: witness-script sigops (accurate), × 1
  5.  P2WPKH: always 1 sigop, × 1
  6.  Taproot (v1 witness): 0 at block sigops level (budget enforced at exec)
  7.  P2SH-wrapped P2WPKH: 1 witness sigop
  8.  P2SH-wrapped P2WSH: accurate witness-script sigops
  9.  Block limit MAX_BLOCK_SIGOPS_COST = 80 000 (consensus)
  10. Mempool policy MAX_STANDARD_TX_SIGOPS_COST = 16 000
  11. Coinbase: legacy counted (inputs + outputs); P2SH + witness skipped
  12. MAX_PUBKEYS_PER_MULTISIG = 20 fallback for bare CHECKMULTISIG

References:
  bitcoin-core/src/script/script.cpp:158-204 (GetSigOpCount)
  bitcoin-core/src/consensus/tx_verify.cpp:112-162 (GetTransactionSigOpCost)
  bitcoin-core/src/script/interpreter.cpp:2123-2166 (WitnessSigOps, CountWitnessSigOps)
  bitcoin-core/src/consensus/consensus.h:17,21
  bitcoin-core/src/policy/policy.h:44
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Mock the Rust extension module before any ouroboros imports
sys.modules.setdefault("sync", MagicMock())

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import (  # noqa: E402
    MAX_STANDARD_TX_SIGOPS_COST,
    Mempool,
    _compute_tx_sigop_cost,
)
from ouroboros.validation import (  # noqa: E402
    MAX_BLOCK_SIGOPS_COST,
    WITNESS_SCALE_FACTOR,
    _count_legacy_sigops,
    _count_witness_sigops,
    _get_p2sh_sigops,
)


# =========================================================================
# Script-building helpers
# =========================================================================

OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_16 = 0x60
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_DUP = 0x76
OP_1NEGATE = 0x4F

DUMMY_TXID = b"\xaa" * 32
COINBASE_TXID = b"\x00" * 32  # prev_txid=all-zeros marks coinbase input


def _make_script(*opcodes_or_bytes) -> bytes:
    """Concatenate opcodes/byte-literals into a raw script."""
    out = b""
    for item in opcodes_or_bytes:
        if isinstance(item, int):
            out += bytes([item])
        else:
            out += item
    return out


def _push(data: bytes) -> bytes:
    """Minimal push of data bytes (direct push for len ≤ 75)."""
    n = len(data)
    assert n <= 75, "use PUSHDATA1 for longer"
    return bytes([n]) + data


def _p2sh_script(hash20: bytes) -> bytes:
    """OP_HASH160 <20 bytes> OP_EQUAL."""
    assert len(hash20) == 20
    return bytes([OP_HASH160, 0x14]) + hash20 + bytes([OP_EQUAL])


def _p2wpkh_script(hash20: bytes) -> bytes:
    """OP_0 <20 bytes> — P2WPKH."""
    assert len(hash20) == 20
    return bytes([0x00, 0x14]) + hash20


def _p2wsh_script(hash32: bytes) -> bytes:
    """OP_0 <32 bytes> — P2WSH."""
    assert len(hash32) == 32
    return bytes([0x00, 0x20]) + hash32


def _p2tr_script(key32: bytes) -> bytes:
    """OP_1 <32 bytes> — P2TR (Taproot)."""
    assert len(key32) == 32
    return bytes([0x51, 0x20]) + key32


def _make_tx(
    inputs=None,
    outputs=None,
    version=2,
    coinbase=False,
) -> Transaction:
    """Build a minimal Transaction for testing."""
    if outputs is None:
        outputs = [TxOut(value=1000, script_pubkey=b"")]
    if coinbase:
        inputs = [TxIn(
            prev_txid=COINBASE_TXID,
            prev_vout=0xFFFFFFFF,
            script_sig=b"",
            sequence=0xFFFFFFFF,
        )]
    if inputs is None:
        inputs = [TxIn(
            prev_txid=DUMMY_TXID,
            prev_vout=0,
            script_sig=b"",
            sequence=0xFFFFFFFF,
        )]
    txid = b"\xbb" * 32
    return Transaction(
        txid=txid,
        version=version,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=False,
    )


# =========================================================================
# Gate 1+2: _count_legacy_sigops
# =========================================================================

class TestCountLegacySigops(unittest.TestCase):
    """Bitcoin Core script/script.cpp CScript::GetSigOpCount(bool fAccurate)."""

    def test_empty_script_zero(self):
        self.assertEqual(_count_legacy_sigops(b""), 0)

    def test_single_checksig(self):
        script = _make_script(OP_CHECKSIG)
        self.assertEqual(_count_legacy_sigops(script), 1)

    def test_single_checksigverify(self):
        script = _make_script(OP_CHECKSIGVERIFY)
        self.assertEqual(_count_legacy_sigops(script), 1)

    def test_three_checksig(self):
        script = _make_script(OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG)
        self.assertEqual(_count_legacy_sigops(script), 3)

    def test_checkmultisig_inaccurate_always_20(self):
        # Without preceding OP_N, inaccurate counts 20.
        script = _make_script(OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=False), 20)

    def test_checkmultisig_accurate_no_opn_still_20(self):
        # OP_N not immediately before CHECKMULTISIG → fall back to 20.
        script = _make_script(OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_checkmultisig_accurate_op1(self):
        # OP_1 OP_CHECKMULTISIG → 1 sigop (accurate).
        script = _make_script(OP_1, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 1)

    def test_checkmultisig_accurate_op3(self):
        # OP_3 OP_CHECKMULTISIG → 3 sigops (accurate).
        script = _make_script(OP_3, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 3)

    def test_checkmultisig_accurate_op16(self):
        # OP_16 OP_CHECKMULTISIG → 16 sigops (accurate).
        script = _make_script(OP_16, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 16)

    def test_checkmultisig_inaccurate_op3(self):
        # Even with OP_3 prefix, inaccurate mode still counts 20.
        script = _make_script(OP_3, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=False), 20)

    def test_checkmultisigverify_accurate(self):
        script = _make_script(OP_2, OP_CHECKMULTISIGVERIFY)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 2)

    def test_data_push_skipped_correctly(self):
        # A 33-byte push (0x21 <33 bytes>) should not count as sigops and
        # last_opcode should be updated to 0x21 (not OP_1..OP_16), so the
        # following CHECKMULTISIG falls back to 20.
        pk = b"\x02" * 33
        script = bytes([len(pk)]) + pk + bytes([OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_op_n_after_data_push_is_accurate(self):
        # <pk_push> OP_1 OP_CHECKMULTISIG → last_opcode=OP_1 → 1 sigop accurate.
        pk = b"\x02" * 33
        script = bytes([len(pk)]) + pk + bytes([OP_1, OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 1)

    def test_p2pkh_script_one_sigop(self):
        # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG → 1 sigop
        script = bytes([OP_DUP, 0xA9, 0x14]) + b"\x00" * 20 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=False), 1)

    def test_max_pubkeys_fallback(self):
        # Gate 12: bare CHECKMULTISIG (no OP_N) → MAX_PUBKEYS_PER_MULTISIG = 20
        self.assertEqual(_count_legacy_sigops(bytes([OP_CHECKMULTISIG]), accurate=True), 20)

    def test_pushdata1_skipped(self):
        # PUSHDATA1 <len> <data> OP_CHECKSIG should count 1 sigop
        data = b"\xaa" * 40
        script = bytes([0x4C, len(data)]) + data + bytes([OP_CHECKSIG])
        self.assertEqual(_count_legacy_sigops(script), 1)

    def test_pushdata2_skipped(self):
        data = b"\xbb" * 100
        script = bytes([0x4D]) + len(data).to_bytes(2, "little") + data + bytes([OP_CHECKSIG])
        self.assertEqual(_count_legacy_sigops(script), 1)

    def test_op0_does_not_confuse_accurate_count(self):
        # OP_0 OP_CHECKMULTISIG: OP_0 is not in OP_1..OP_16 → 20 fallback
        script = _make_script(OP_0, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_op1negate_does_not_confuse_accurate_count(self):
        # OP_1NEGATE (0x4F) OP_CHECKMULTISIG → not in OP_1..OP_16 → 20 fallback
        script = _make_script(OP_1NEGATE, OP_CHECKMULTISIG)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_constants(self):
        self.assertEqual(MAX_BLOCK_SIGOPS_COST, 80_000)
        self.assertEqual(WITNESS_SCALE_FACTOR, 4)
        self.assertEqual(MAX_STANDARD_TX_SIGOPS_COST, 16_000)


# =========================================================================
# Gate 3: P2SH sigop counting (_get_p2sh_sigops)
# =========================================================================

class TestGetP2SHSigops(unittest.TestCase):
    """Bitcoin Core script/script.cpp CScript::GetSigOpCount(const CScript& scriptSig)."""

    def test_not_p2sh_returns_zero(self):
        # A plain P2PKH scriptPubKey → _get_p2sh_sigops returns 0
        non_p2sh = bytes([OP_DUP, 0xA9, 0x14]) + b"\x00" * 20 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
        self.assertEqual(_get_p2sh_sigops(b"", non_p2sh), 0)

    def test_p2sh_with_checksig_redeem(self):
        # Redeem script = OP_CHECKSIG → 1 sigop
        redeem = bytes([OP_CHECKSIG])
        script_sig = bytes([len(redeem)]) + redeem
        p2sh_spk = _p2sh_script(b"\x00" * 20)
        self.assertEqual(_get_p2sh_sigops(script_sig, p2sh_spk), 1)

    def test_p2sh_1of2_multisig_accurate(self):
        # Redeem: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG → 2 sigops (accurate)
        pk1 = b"\x02" * 33
        pk2 = b"\x02" * 33
        redeem = (
            bytes([OP_1])
            + bytes([len(pk1)]) + pk1
            + bytes([len(pk2)]) + pk2
            + bytes([OP_2, OP_CHECKMULTISIG])
        )
        script_sig = bytes([len(redeem)]) + redeem
        p2sh_spk = _p2sh_script(b"\x00" * 20)
        # Accurate mode: OP_2 before CHECKMULTISIG → 2 sigops
        self.assertEqual(_get_p2sh_sigops(script_sig, p2sh_spk), 2)

    def test_p2sh_non_push_only_scriptsig_returns_zero(self):
        # A non-push-only scriptSig (e.g. contains OP_DUP=0x76) → 0
        bad_sig = bytes([0x76])  # OP_DUP
        p2sh_spk = _p2sh_script(b"\x00" * 20)
        self.assertEqual(_get_p2sh_sigops(bad_sig, p2sh_spk), 0)

    def test_p2sh_empty_scriptsig_returns_zero(self):
        p2sh_spk = _p2sh_script(b"\x00" * 20)
        self.assertEqual(_get_p2sh_sigops(b"", p2sh_spk), 0)


# =========================================================================
# Gates 4-8: Witness sigop counting (_count_witness_sigops)
# =========================================================================

class TestCountWitnessSigops(unittest.TestCase):
    """Bitcoin Core script/interpreter.cpp WitnessSigOps / CountWitnessSigOps."""

    def test_p2wpkh_native_one_sigop(self):
        # Gate 5: P2WPKH (v0, 20-byte program) → 1 sigop
        spk = _p2wpkh_script(b"\x00" * 20)
        self.assertEqual(_count_witness_sigops(spk, [[b"\x00" * 71, b"\x02" * 33]]), 1)

    def test_p2wpkh_no_witness_still_one(self):
        # P2WPKH: program size alone determines the count — witness items don't matter
        spk = _p2wpkh_script(b"\x00" * 20)
        self.assertEqual(_count_witness_sigops(spk, []), 1)

    def test_p2wsh_checksig_one_sigop(self):
        # Gate 4: P2WSH (v0, 32-byte program), witness script = OP_CHECKSIG → 1
        witness_script = bytes([OP_CHECKSIG])
        spk = _p2wsh_script(b"\x00" * 32)
        witness = [b"\x00" * 71, witness_script]
        self.assertEqual(_count_witness_sigops(spk, witness), 1)

    def test_p2wsh_2of3_multisig_accurate(self):
        # Gate 4: P2WSH, witness script = OP_3 CHECKMULTISIG → 3 sigops (accurate)
        pk = b"\x02" * 33
        witness_script = bytes([OP_2, len(pk)]) + pk + bytes([len(pk)]) + pk + bytes([len(pk)]) + pk + bytes([OP_3, OP_CHECKMULTISIG])
        spk = _p2wsh_script(b"\x00" * 32)
        witness = [b"", b"\x00" * 71, b"\x00" * 71, witness_script]
        self.assertEqual(_count_witness_sigops(spk, witness), 3)

    def test_p2wsh_no_witness_zero(self):
        # P2WSH with empty witness stack → 0 (Core: `witness.stack.size() > 0` required)
        spk = _p2wsh_script(b"\x00" * 32)
        self.assertEqual(_count_witness_sigops(spk, []), 0)
        self.assertEqual(_count_witness_sigops(spk, None), 0)

    def test_taproot_v1_zero_at_block_level(self):
        # Gate 6: Taproot (v1 witness) → 0 at block sigops level.
        # Taproot sigops budget enforced at execution time, not here.
        # Reference: Bitcoin Core interpreter.cpp WitnessSigOps() → returns 0 for v1+
        spk = _p2tr_script(b"\x02" * 32)
        witness = [b"\x00" * 64]  # schnorr sig
        self.assertEqual(_count_witness_sigops(spk, witness), 0)

    def test_non_witness_script_zero(self):
        # P2PKH (not a witness program) → 0
        p2pkh = bytes([OP_DUP, 0xA9, 0x14]) + b"\x00" * 20 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
        self.assertEqual(_count_witness_sigops(p2pkh, [b"\x00" * 71, b"\x02" * 33]), 0)

    def test_p2sh_not_handled_directly_zero(self):
        # P2SH scriptPubKey passed to _count_witness_sigops directly → 0
        # (P2SH-wrapped witness is handled at a higher level by substituting redeem)
        p2sh = _p2sh_script(b"\x00" * 20)
        self.assertEqual(_count_witness_sigops(p2sh, []), 0)


# =========================================================================
# Gate 7+8: P2SH-wrapped witness sigops (combined in _validate_block_limits)
# =========================================================================

class TestP2SHWrappedWitness(unittest.TestCase):
    """P2SH-P2WPKH and P2SH-P2WSH: redeem script IS the witness program."""

    def test_p2sh_p2wpkh_witness_sigop(self):
        # Gate 7: P2SH-P2WPKH
        # scriptPubKey = P2SH, redeem = P2WPKH → 1 witness sigop (unscaled)
        redeem = _p2wpkh_script(b"\x00" * 20)
        witness_spk = redeem  # after substitution in _validate_block_limits
        self.assertEqual(_count_witness_sigops(witness_spk, [b"\x00" * 71, b"\x02" * 33]), 1)

    def test_p2sh_p2wsh_witness_sigop_checksig(self):
        # Gate 8: P2SH-P2WSH, witness script = OP_CHECKSIG → 1 sigop
        witness_script = bytes([OP_CHECKSIG])
        redeem = _p2wsh_script(b"\x00" * 32)
        witness_spk = redeem
        witness = [b"\x00" * 71, witness_script]
        self.assertEqual(_count_witness_sigops(witness_spk, witness), 1)


# =========================================================================
# Gate 9: Block-level MAX_BLOCK_SIGOPS_COST
# =========================================================================

class TestBlockSigopsLimit(unittest.TestCase):
    """Block sigop cost must not exceed 80,000."""

    def test_max_block_sigops_constant(self):
        self.assertEqual(MAX_BLOCK_SIGOPS_COST, 80_000)

    def test_legacy_sigops_scale_factor(self):
        # 1 OP_CHECKSIG in an output costs WITNESS_SCALE_FACTOR = 4
        script = bytes([OP_CHECKSIG])
        count = _count_legacy_sigops(script)
        self.assertEqual(count * WITNESS_SCALE_FACTOR, 4)

    def test_max_legacy_sigops_per_block(self):
        # Max legacy sigops without hitting limit: 80000 / 4 = 20000 raw sigops
        max_legacy = MAX_BLOCK_SIGOPS_COST // WITNESS_SCALE_FACTOR
        self.assertEqual(max_legacy, 20_000)

    def test_checkmultisig_20_fallback_cost(self):
        # Bare CHECKMULTISIG → 20 sigops × 4 = 80 cost units
        script = bytes([OP_CHECKMULTISIG])
        count = _count_legacy_sigops(script, accurate=False)
        self.assertEqual(count, 20)
        self.assertEqual(count * WITNESS_SCALE_FACTOR, 80)


# =========================================================================
# Gate 10: Mempool policy MAX_STANDARD_TX_SIGOPS_COST = 16 000
# =========================================================================

class TestMempoolSigopsPolicy(unittest.TestCase):
    """Bitcoin Core validation.cpp AcceptToMemoryPoolWorker:908-943."""

    def _make_utxo(self, script_pubkey: bytes) -> dict:
        return {"script_pubkey": script_pubkey, "value": 50_000_000}

    def test_constant_value(self):
        # MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5
        self.assertEqual(MAX_STANDARD_TX_SIGOPS_COST, 80_000 // 5)
        self.assertEqual(MAX_STANDARD_TX_SIGOPS_COST, 16_000)

    def test_compute_tx_sigop_cost_legacy_only(self):
        # A tx with 1 OP_CHECKSIG output → cost = 1 * 4 = 4
        tx = _make_tx(outputs=[TxOut(value=1000, script_pubkey=bytes([OP_CHECKSIG]))])
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: None)
        self.assertEqual(cost, 4)

    def test_compute_tx_sigop_cost_multiple_checksig(self):
        # 3 OP_CHECKSIG in outputs → cost = 3 * 4 = 12
        tx = _make_tx(outputs=[TxOut(value=1000, script_pubkey=bytes([OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG]))])
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: None)
        self.assertEqual(cost, 12)

    def test_compute_tx_sigop_cost_coinbase_skips_p2sh_witness(self):
        # Coinbase: legacy only (outputs); P2SH and witness are skipped even if
        # prev_script_pubkey would look like P2SH. Core: GetTransactionSigOpCost
        # early-returns for coinbase after GetLegacySigOpCount.
        coinbase_out = TxOut(value=50_0000_0000, script_pubkey=bytes([OP_CHECKSIG]))
        tx = _make_tx(outputs=[coinbase_out], coinbase=True)
        # Resolver would return a P2SH UTXO — but coinbase inputs have no prevout
        # so it should not be called; cost = 1 * 4 = 4
        called = []
        def resolver(txid, vout):
            called.append((txid, vout))
            return self._make_utxo(_p2sh_script(b"\x00" * 20))
        cost = _compute_tx_sigop_cost(tx, resolver)
        self.assertEqual(cost, 4)  # 1 output CHECKSIG × 4
        # The resolver must NOT be called for coinbase (no prevouts to resolve)
        self.assertEqual(len(called), 0)

    def test_compute_tx_sigop_cost_p2sh_redeem(self):
        # Input spending a P2SH output, redeem = OP_CHECKSIG OP_CHECKSIG → 2 accurate
        # P2SH cost = 2 * WITNESS_SCALE_FACTOR = 8; no legacy script_sig sigops; no output sigops.
        redeem = bytes([OP_CHECKSIG, OP_CHECKSIG])
        script_sig = bytes([len(redeem)]) + redeem
        p2sh_spk = _p2sh_script(b"\x00" * 20)

        tx = _make_tx(
            inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=script_sig, sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=1000, script_pubkey=b"")],
        )

        def resolver(txid, vout):
            return self._make_utxo(p2sh_spk)

        cost = _compute_tx_sigop_cost(tx, resolver)
        # Legacy: 0 from outputs, script_sig contains no checksig opcodes (just data pushes)
        # P2SH: 2 sigops × 4 = 8
        self.assertEqual(cost, 8)

    def test_compute_tx_sigop_cost_p2wpkh(self):
        # Input spending P2WPKH (native) → 1 witness sigop × 1 = 1
        p2wpkh_spk = _p2wpkh_script(b"\x00" * 20)
        tx = _make_tx(
            inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=b"",
                         sequence=0xFFFFFFFF, witness=[b"\x00" * 71, b"\x02" * 33])],
            outputs=[TxOut(value=1000, script_pubkey=b"")],
        )

        def resolver(txid, vout):
            return self._make_utxo(p2wpkh_spk)

        cost = _compute_tx_sigop_cost(tx, resolver)
        # Legacy: 0; P2SH: 0; Witness: 1
        self.assertEqual(cost, 1)

    def test_tx_over_16000_rejected_by_mempool_policy(self):
        # A tx with 4001 OP_CHECKSIG outputs → cost = 4001 * 4 = 16004 > 16000
        # _compute_tx_sigop_cost should return > MAX_STANDARD_TX_SIGOPS_COST
        checksig_script = bytes([OP_CHECKSIG]) * 4001
        tx = _make_tx(
            outputs=[TxOut(value=1, script_pubkey=checksig_script)],
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: None)
        self.assertGreater(cost, MAX_STANDARD_TX_SIGOPS_COST)

    def test_tx_at_16000_not_rejected(self):
        # 4000 OP_CHECKSIG → cost = 4000 * 4 = 16000, exactly at limit (not over)
        checksig_script = bytes([OP_CHECKSIG]) * 4000
        tx = _make_tx(
            outputs=[TxOut(value=1, script_pubkey=checksig_script)],
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: None)
        self.assertEqual(cost, 16_000)
        self.assertLessEqual(cost, MAX_STANDARD_TX_SIGOPS_COST)


# =========================================================================
# Gate 11: Coinbase scriptSig legacy sigops counted (Bug #2 fix)
# =========================================================================

class TestCoinbaseScriptSigSigops(unittest.TestCase):
    """Core GetLegacySigOpCount() counts coinbase scriptSig sigops.

    Reference: bitcoin-core/src/consensus/tx_verify.cpp:112-124
      for (const auto& txin : tx.vin) { nSigOps += txin.scriptSig.GetSigOpCount(false); }
    This loop runs for ALL transactions including coinbase.
    """

    def test_coinbase_scriptsig_checksig_counted(self):
        # A coinbase with OP_CHECKSIG in scriptSig → _count_legacy_sigops counts it.
        # (Pathological but spec-mandated.)
        checksig_in_scriptsig = bytes([OP_CHECKSIG])
        count = _count_legacy_sigops(checksig_in_scriptsig, accurate=False)
        self.assertEqual(count, 1)

    def test_compute_tx_sigop_cost_counts_coinbase_input_legacy(self):
        # _compute_tx_sigop_cost should count OP_CHECKSIG in coinbase scriptSig.
        # Cost = 1 (input) * 4 + 0 (no output sigops) = 4
        tx = Transaction(
            txid=b"\xcc" * 32,
            version=1,
            locktime=0,
            inputs=[TxIn(
                prev_txid=COINBASE_TXID,
                prev_vout=0xFFFFFFFF,
                script_sig=bytes([OP_CHECKSIG]),  # unusual but valid spec
                sequence=0xFFFFFFFF,
            )],
            outputs=[TxOut(value=50_0000_0000, script_pubkey=b"")],
            has_witness=False,
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: None)
        # 1 legacy sigop (from coinbase scriptSig) × 4 = 4
        self.assertEqual(cost, 4)

    def test_normal_coinbase_scriptsig_zero_sigops(self):
        # Standard coinbase scriptSig (height push + arbitrary data): no sigops
        bip34_height = bytes([0x03, 0xD6, 0x35, 0x0E])  # height 939478
        count = _count_legacy_sigops(bip34_height, accurate=False)
        self.assertEqual(count, 0)


# =========================================================================
# Gate 12: MAX_PUBKEYS_PER_MULTISIG = 20 fallback
# =========================================================================

class TestMaxPubkeysPerMultisig(unittest.TestCase):
    """Bitcoin Core script/script.cpp: MAX_PUBKEYS_PER_MULTISIG = 20."""

    def test_bare_checkmultisig_fallback_20(self):
        # OP_CHECKMULTISIG with no preceding OP_N → 20 (inaccurate)
        script = bytes([OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=False), 20)
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_op0_before_checkmultisig_accurate_20(self):
        # OP_0 is not in OP_1..OP_16 → falls back to 20
        script = bytes([OP_0, OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 20)

    def test_op1_before_checkmultisig_accurate_1(self):
        script = bytes([OP_1, OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 1)

    def test_op16_before_checkmultisig_accurate_16(self):
        script = bytes([OP_16, OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 16)

    def test_mixed_checksig_and_checkmultisig(self):
        # OP_CHECKSIG + OP_3 OP_CHECKMULTISIG (accurate) → 1 + 3 = 4
        script = bytes([OP_CHECKSIG, OP_3, OP_CHECKMULTISIG])
        self.assertEqual(_count_legacy_sigops(script, accurate=True), 4)
        # inaccurate: 1 + 20 = 21
        self.assertEqual(_count_legacy_sigops(script, accurate=False), 21)


# =========================================================================
# Integration: GetTransactionSigOpCost equivalence
# =========================================================================

class TestGetTransactionSigOpCost(unittest.TestCase):
    """End-to-end _compute_tx_sigop_cost: matches Core GetTransactionSigOpCost."""

    def _make_utxo(self, spk: bytes) -> dict:
        return {"script_pubkey": spk, "value": 1_000_000}

    def test_legacy_only_non_coinbase(self):
        # Tx: 1 CHECKSIG output, no P2SH, no witness
        # Legacy: 1 * 4 = 4
        tx = _make_tx(outputs=[TxOut(value=1000, script_pubkey=bytes([OP_CHECKSIG]))])
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: self._make_utxo(b""))
        self.assertEqual(cost, 4)

    def test_p2sh_redeem_counted_once_accurately(self):
        # 1-of-1 P2SH multisig: redeem = OP_1 OP_CHECKSIG → wait, no
        # Redeem: OP_CHECKSIG → 1 accurate sigop → P2SH cost = 1 * 4 = 4
        redeem = bytes([OP_CHECKSIG])
        script_sig = bytes([len(redeem)]) + redeem
        p2sh_spk = _p2sh_script(b"\x00" * 20)

        tx = _make_tx(
            inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=script_sig, sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=1000, script_pubkey=b"")],
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: self._make_utxo(p2sh_spk))
        # Legacy: 0 output sigops; 0 input script_sig sigops (just a data push)
        # P2SH: 1 * 4 = 4; Witness: 0
        self.assertEqual(cost, 4)

    def test_witness_p2wpkh_cost_1(self):
        # P2WPKH → 1 witness sigop (×1, BIP141 discount)
        p2wpkh_spk = _p2wpkh_script(b"\x00" * 20)
        tx = _make_tx(
            inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=b"",
                         sequence=0xFFFFFFFF, witness=[b"\x00" * 71, b"\x02" * 33])],
            outputs=[TxOut(value=1000, script_pubkey=b"")],
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: self._make_utxo(p2wpkh_spk))
        self.assertEqual(cost, 1)

    def test_taproot_v1_zero(self):
        # Taproot output/input → 0 witness sigops at block level
        p2tr_spk = _p2tr_script(b"\x02" * 32)
        tx = _make_tx(
            inputs=[TxIn(prev_txid=DUMMY_TXID, prev_vout=0, script_sig=b"",
                         sequence=0xFFFFFFFF, witness=[b"\x00" * 64])],
            outputs=[TxOut(value=1000, script_pubkey=b"")],
        )
        cost = _compute_tx_sigop_cost(tx, lambda txid, vout: self._make_utxo(p2tr_spk))
        self.assertEqual(cost, 0)

    def test_coinbase_p2sh_skipped(self):
        # Coinbase: P2SH/witness counting is skipped even for P2SH prevscripts.
        # GetTransactionSigOpCost early-returns after legacy for coinbase.
        coinbase_out = TxOut(value=50_0000_0000, script_pubkey=b"")
        tx = _make_tx(outputs=[coinbase_out], coinbase=True)
        called = []
        def resolver(txid, vout):
            called.append(1)
            return self._make_utxo(_p2sh_script(b"\x00" * 20))
        cost = _compute_tx_sigop_cost(tx, resolver)
        self.assertEqual(cost, 0)  # no sigops in output or coinbase input
        self.assertEqual(len(called), 0, "resolver must not be called for coinbase")


if __name__ == "__main__":
    unittest.main()
