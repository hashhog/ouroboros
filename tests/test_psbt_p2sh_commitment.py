"""
W31: PSBT P2SH commitment-check tests.

These tests pin the BIP-16 commitment behavior of the PSBT finalizer
that landed in W31. Pre-fix the P2SH-P2WPKH finalizer matched only the
*shape* of ``redeem_script`` (OP_0 <20 bytes>) and never compared
``HASH160(redeem_script)`` against the witness_utxo scriptPubKey hash —
a malicious cosigner could swap in any P2WPKH-shaped redeemScript and
the finalizer would happily emit a transaction whose scriptSig fails
script verification at broadcast.

Coverage:
  * test_p2sh_p2wpkh_correct_commitment_finalizes  — happy path: PSBT
    where ``HASH160(redeem_script) == spk[2:22]`` finalizes with the
    expected scriptSig and witness stack.
  * test_p2sh_p2wpkh_forged_redeem_script_raises   — negative path:
    swap in a redeem_script whose hash160 does not match the P2SH
    scriptPubKey commitment; finalize() must raise loudly rather than
    silently emit an unbroadcastable transaction.
  * test_p2sh_p2wsh_correct_commitment_finalizes   — new path:
    P2SH-P2WSH 2-of-2 multisig finalizes with both BIP-16 (outer P2SH)
    and BIP-141 (inner P2WSH) commitments verified.

Reference:
  BIP-16: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
  BIP-141: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
"""

from __future__ import annotations

import hashlib

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import PSBT
from ouroboros.segwit_v0 import (
    verify_p2sh_commitment,
    verify_p2wsh_commitment,
)
from ouroboros.wallet import _hash160


def _mk_tx() -> Transaction:
    """Single-input/single-output spending tx shell."""
    return Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=b"\xaa" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFE,
                witness=None,
            )
        ],
        outputs=[
            TxOut(value=99_000_000, script_pubkey=b"\x00\x14" + b"\xbb" * 20)
        ],
        has_witness=False,
    )


def _p2sh_spk(redeem_script: bytes) -> bytes:
    """Build a P2SH scriptPubKey: OP_HASH160 <h160(rs)> OP_EQUAL."""
    return b"\xa9\x14" + _hash160(redeem_script) + b"\x87"


# ---------------------------------------------------------------------------
# verify_p2sh_commitment / verify_p2wsh_commitment unit tests (defensive —
# the helpers themselves are short and the PSBT tests already exercise them
# end-to-end, but a direct test makes regressions trivial to localize).
# ---------------------------------------------------------------------------


class TestCommitmentHelpers:
    def test_p2sh_commitment_valid(self):
        rs = b"\x00\x14" + b"\x11" * 20
        spk = _p2sh_spk(rs)
        # Returns None on success.
        assert verify_p2sh_commitment(rs, spk) is None

    def test_p2sh_commitment_forged_raises(self):
        rs_real = b"\x00\x14" + b"\x11" * 20
        rs_forged = b"\x00\x14" + b"\x22" * 20
        spk = _p2sh_spk(rs_real)
        with pytest.raises(ValueError, match="does not commit"):
            verify_p2sh_commitment(rs_forged, spk)

    def test_p2sh_commitment_wrong_spk_shape_raises(self):
        rs = b"\x00\x14" + b"\x11" * 20
        # P2WPKH scriptPubKey, not P2SH — must reject.
        not_p2sh = b"\x00\x14" + b"\x11" * 20
        with pytest.raises(ValueError, match="not P2SH"):
            verify_p2sh_commitment(rs, not_p2sh)

    def test_p2wsh_commitment_valid(self):
        ws = b"\x51"  # OP_TRUE — meaningless content, just exercising the hash.
        program = hashlib.sha256(ws).digest()
        assert verify_p2wsh_commitment(ws, program) is None

    def test_p2wsh_commitment_forged_raises(self):
        ws_real = b"\x51"
        ws_forged = b"\x52"
        program = hashlib.sha256(ws_real).digest()
        with pytest.raises(ValueError, match="does not commit"):
            verify_p2wsh_commitment(ws_forged, program)


# ---------------------------------------------------------------------------
# PSBT finalizer tests
# ---------------------------------------------------------------------------


class TestPSBTP2SHCommitment:
    def test_p2sh_p2wpkh_correct_commitment_finalizes(self):
        """Happy path: well-formed P2SH-P2WPKH PSBT finalizes."""
        # Real pubkey hash — content doesn't matter, only that it's the
        # one the redeemScript wraps.
        pubkey_hash = b"\x33" * 20
        redeem_script = b"\x00\x14" + pubkey_hash
        spk = _p2sh_spk(redeem_script)

        tx = _mk_tx()
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].witness_utxo = (100_000_000, spk)
        psbt.inputs[0].redeem_script = redeem_script

        # Single 33-byte pubkey + 71-byte DER-shaped sig (content opaque
        # to the finalizer — finalize() does not verify sigs).
        pubkey = b"\x02" + b"\xaa" * 32
        sig = b"\x30" + b"\x44" * 70
        psbt.inputs[0].partial_sigs[pubkey] = sig

        psbt.finalize()

        inp = psbt.inputs[0]
        assert inp.is_finalized()
        # scriptSig = single-push of redeemScript.
        assert inp.final_script_sig == bytes([len(redeem_script)]) + redeem_script
        # Witness stack = [sig, pubkey].
        assert inp.final_script_witness == [sig, pubkey]

    def test_p2sh_p2wpkh_forged_redeem_script_raises(self):
        """Forged redeemScript (hash160 mismatch) must raise — not silently finalize."""
        real_redeem = b"\x00\x14" + b"\x11" * 20
        spk = _p2sh_spk(real_redeem)

        # Attacker swaps in a different P2WPKH redeemScript (matches the
        # shape gate but its HASH160 does not match the spk commitment).
        forged_redeem = b"\x00\x14" + b"\x22" * 20

        tx = _mk_tx()
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].witness_utxo = (100_000_000, spk)
        psbt.inputs[0].redeem_script = forged_redeem

        pubkey = b"\x02" + b"\xaa" * 32
        sig = b"\x30" + b"\x44" * 70
        psbt.inputs[0].partial_sigs[pubkey] = sig

        with pytest.raises(ValueError, match="does not commit"):
            psbt.finalize()

        # And the input is NOT marked finalized (no final fields written).
        assert not psbt.inputs[0].is_finalized()

    def test_p2sh_p2wsh_correct_commitment_finalizes(self):
        """P2SH-P2WSH 2-of-2 multisig finalizes with both commitments verified."""
        # Two opaque 33-byte pubkeys — the finalizer matches partial_sigs
        # by pubkey-equality with the witnessScript-embedded pubkeys, no
        # ECDSA verification.
        pk1 = b"\x02" + b"\x11" * 32
        pk2 = b"\x02" + b"\x22" * 32

        # OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG.
        witness_script = (
            b"\x52"
            + bytes([len(pk1)]) + pk1
            + bytes([len(pk2)]) + pk2
            + b"\x52\xae"
        )
        # P2WSH redeemScript: OP_0 <SHA256(witnessScript)>.
        redeem_script = b"\x00\x20" + hashlib.sha256(witness_script).digest()
        spk = _p2sh_spk(redeem_script)

        tx = _mk_tx()
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].witness_utxo = (100_000_000, spk)
        psbt.inputs[0].redeem_script = redeem_script
        psbt.inputs[0].witness_script = witness_script

        sig1 = b"\x30" + b"\x44" * 70 + b"\x01"
        sig2 = b"\x30" + b"\x44" * 70 + b"\x01"
        psbt.inputs[0].partial_sigs[pk1] = sig1
        psbt.inputs[0].partial_sigs[pk2] = sig2

        psbt.finalize()

        inp = psbt.inputs[0]
        assert inp.is_finalized()
        # scriptSig = single-push of the 34-byte redeemScript.
        assert inp.final_script_sig == bytes([len(redeem_script)]) + redeem_script
        # Witness stack = [<empty>, sig1, sig2, witnessScript].
        assert inp.final_script_witness is not None
        assert inp.final_script_witness[0] == b""  # CHECKMULTISIG dummy
        assert inp.final_script_witness[1] == sig1
        assert inp.final_script_witness[2] == sig2
        assert inp.final_script_witness[3] == witness_script
