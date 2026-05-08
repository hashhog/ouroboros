"""
Phase-2 segwit-v0 signing tests for ouroboros (W28).

Covers:
  * BIP-143 P2WSH 2-of-3 multisig signing → ECDSA-verifies against the
    witnessScript pubkeys.
  * P2SH-P2WPKH wrap helper → produces the same scriptSig/witness as
    the existing in-rpc P2SH-P2WPKH path.
  * P2SH-P2WSH 2-of-2 multisig wrap → script_sig is push of
    OP_0 <SHA256(witnessScript)>; witness stack mirrors bare P2WSH.
  * Round-trip parity — the helper and the inline ``rpc.py``
    ``_bip143_sighash`` agree on the produced 32-byte sighash for the
    P2WPKH path. This is the parallel-impl-drift sentinel: if either
    copy diverges in a future fix, this test breaks.

These tests are deliberately self-contained — no FastAPI / running node
required — and work against the new ``ouroboros.segwit_v0`` module.

Reference: BIP-143 https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.segwit_v0 import (
    bip143_sighash,
    parse_multisig_script,
    parse_p2pk_checksig_script,
    sign_p2sh_p2wpkh_input,
    sign_p2sh_p2wsh_input,
    sign_p2wsh_input,
)
from ouroboros.wallet import WalletKey, _hash160


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mk_key(secret_int: int) -> WalletKey:
    secret = secret_int.to_bytes(32, "big")
    return WalletKey(secret, network="regtest")


def _mk_simple_tx(
    prev_txid: bytes = b"\xaa" * 32,
    prev_vout: int = 0,
    sequence: int = 0xFFFFFFFE,
    output_value: int = 99_000_000,
    output_spk: bytes | None = None,
) -> Transaction:
    """Build a 1-input/1-output spending transaction shell."""
    if output_spk is None:
        # P2WPKH burn output — content is irrelevant for the sighash test.
        output_spk = b"\x00\x14" + b"\xbb" * 20
    tx = Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=prev_txid,
                prev_vout=prev_vout,
                script_sig=b"",
                sequence=sequence,
                witness=None,
            )
        ],
        outputs=[TxOut(value=output_value, script_pubkey=output_spk)],
        has_witness=False,
    )
    return tx


def _build_multisig_script(m: int, pubkeys: list[bytes]) -> bytes:
    """Build OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG."""
    op_m = 0x50 + m  # OP_1..OP_16
    op_n = 0x50 + len(pubkeys)
    parts = bytearray([op_m])
    for pk in pubkeys:
        parts.append(len(pk))
        parts.extend(pk)
    parts.append(op_n)
    parts.append(0xAE)  # OP_CHECKMULTISIG
    return bytes(parts)


# ---------------------------------------------------------------------------
# Script parser tests
# ---------------------------------------------------------------------------


class TestScriptParsers:
    def test_parse_multisig_2of3(self):
        keys = [_mk_key(i + 1) for i in range(3)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        parsed = parse_multisig_script(ws)
        assert parsed is not None
        m, pks = parsed
        assert m == 2
        assert pks == [k.pubkey for k in keys]

    def test_parse_multisig_rejects_non_multisig(self):
        # P2WPKH script-code should not parse as multisig.
        spk = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        assert parse_multisig_script(spk) is None

    def test_parse_p2pk_checksig(self):
        key = _mk_key(7)
        ws = bytes([len(key.pubkey)]) + key.pubkey + b"\xac"
        assert parse_p2pk_checksig_script(ws) == key.pubkey

    def test_parse_p2pk_rejects_wrong_shape(self):
        # CHECKMULTISIG terminator should not match CHECKSIG.
        keys = [_mk_key(i + 1) for i in range(2)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        assert parse_p2pk_checksig_script(ws) is None


# ---------------------------------------------------------------------------
# Sighash drift sentinel — segwit_v0.bip143_sighash MUST match the inline
# rpc.py copy at line 6407 byte-for-byte. We re-implement the inline one
# here as the reference and compare.
# ---------------------------------------------------------------------------


def _reference_bip143(tx, idx, script_code, value, sh_type):
    """Reference implementation — direct transcription of rpc.py:6407."""
    base = sh_type & 0x1F
    acp = (sh_type & 0x80) != 0

    def _enc_varint(n):
        if n < 0xFD:
            return bytes([n])
        if n <= 0xFFFF:
            return b"\xfd" + struct.pack("<H", n)
        if n <= 0xFFFFFFFF:
            return b"\xfe" + struct.pack("<I", n)
        return b"\xff" + struct.pack("<Q", n)

    def _ds(data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    if not acp:
        prevouts = b"".join(
            i.prev_txid + struct.pack("<I", i.prev_vout) for i in tx.inputs
        )
        hp = _ds(prevouts)
    else:
        hp = b"\x00" * 32
    if not acp and base not in (2, 3):
        seqs = b"".join(struct.pack("<I", i.sequence) for i in tx.inputs)
        hs = _ds(seqs)
    else:
        hs = b"\x00" * 32
    if base not in (2, 3):
        outs = b""
        for o in tx.outputs:
            outs += struct.pack("<q", o.value)
            outs += _enc_varint(len(o.script_pubkey))
            outs += o.script_pubkey
        ho = _ds(outs)
    elif base == 3 and idx < len(tx.outputs):
        o = tx.outputs[idx]
        single = struct.pack("<q", o.value)
        single += _enc_varint(len(o.script_pubkey))
        single += o.script_pubkey
        ho = _ds(single)
    else:
        ho = b"\x00" * 32
    inp = tx.inputs[idx]
    pre = struct.pack("<i", tx.version)
    pre += hp + hs
    pre += inp.prev_txid + struct.pack("<I", inp.prev_vout)
    pre += _enc_varint(len(script_code)) + script_code
    pre += struct.pack("<q", value)
    pre += struct.pack("<I", inp.sequence)
    pre += ho
    pre += struct.pack("<I", tx.locktime)
    pre += struct.pack("<I", sh_type)
    return _ds(pre)


class TestSighashDriftSentinel:
    def test_p2wpkh_path_matches_inline(self):
        key = _mk_key(0xC0FFEE)
        tx = _mk_simple_tx()
        h160 = _hash160(key.pubkey)
        script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        for sh in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            assert bip143_sighash(
                tx, 0, script_code, 100_000_000, sh
            ) == _reference_bip143(tx, 0, script_code, 100_000_000, sh)

    def test_p2wsh_multisig_scriptcode(self):
        keys = [_mk_key(i + 1) for i in range(3)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        tx = _mk_simple_tx()
        # witnessScript is used verbatim as scriptCode for P2WSH.
        assert bip143_sighash(
            tx, 0, ws, 100_000_000, 0x01
        ) == _reference_bip143(tx, 0, ws, 100_000_000, 0x01)


# ---------------------------------------------------------------------------
# P2WSH 2-of-3 multisig signing
# ---------------------------------------------------------------------------


class TestP2WSHMultisigSigning:
    def test_2of3_signs_and_verifies(self):
        keys = [_mk_key(i + 1) for i in range(3)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        spk = b"\x00\x20" + hashlib.sha256(ws).digest()
        assert len(spk) == 34

        tx = _mk_simple_tx()
        # Provide only 2 of the 3 keys to signing_keys.
        witness, sigs = sign_p2wsh_input(
            tx, 0, ws, 100_000_000, [keys[0], keys[2]], 0x01
        )

        # Witness shape: [b"", sig_a, sig_c, witnessScript]
        assert witness[0] == b""
        assert witness[-1] == ws
        assert len(witness) == 4
        assert len(sigs) == 2

        sighash = bip143_sighash(tx, 0, ws, 100_000_000, 0x01)
        # Verify each signature with the matching pubkey.
        from coincurve import PublicKey

        sig_pks_remaining = list(witness[1:-1])
        # sigs ordered same as pubkeys appear in ws → match keys[0], keys[2]
        ordered_pks = [keys[0].pubkey, keys[2].pubkey]
        for sig_with_sh, pk in zip(sig_pks_remaining, ordered_pks):
            assert sig_with_sh[-1] == 0x01  # SIGHASH_ALL
            sig_der = sig_with_sh[:-1]
            ok = PublicKey(pk).verify(sig_der, sighash, hasher=None)
            assert ok, f"sig fails verify for pk {pk.hex()[:16]}"

    def test_2of3_partial_sign_with_one_key(self):
        keys = [_mk_key(i + 1) for i in range(3)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        tx = _mk_simple_tx()
        # Only one key supplied — should produce 1 signature, partial.
        witness, sigs = sign_p2wsh_input(
            tx, 0, ws, 50_000_000, [keys[1]], 0x01
        )
        assert len(sigs) == 1
        # Stack still ends with witnessScript and starts with b"".
        assert witness[0] == b""
        assert witness[-1] == ws

    def test_unsupported_witnessscript_raises(self):
        # Random bytes — neither CHECKSIG nor CHECKMULTISIG terminator.
        tx = _mk_simple_tx()
        with pytest.raises(ValueError, match="Unsupported P2WSH"):
            sign_p2wsh_input(
                tx, 0, b"\x51\x52\x53", 100_000_000, [_mk_key(1)], 0x01
            )


# ---------------------------------------------------------------------------
# P2SH-P2WPKH parity (helper output == in-rpc output, byte-for-byte)
# ---------------------------------------------------------------------------


class TestP2SHP2WPKH:
    def test_helper_matches_inline_path(self):
        key = _mk_key(42)
        tx = _mk_simple_tx()
        h160 = _hash160(key.pubkey)

        # Reference: what the existing rpc.py P2SH-P2WPKH branch builds.
        ref_redeem = b"\x00\x14" + h160
        ref_script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        ref_sh = bip143_sighash(tx, 0, ref_script_code, 200_000_000, 0x01)
        ref_sig = key.sign(ref_sh) + bytes([0x01])
        ref_script_sig = bytes([len(ref_redeem)]) + ref_redeem
        ref_witness = [ref_sig, key.pubkey]

        # Helper.
        ss, witness = sign_p2sh_p2wpkh_input(tx, 0, key, 200_000_000, 0x01)

        assert ss == ref_script_sig
        # Note: ECDSA sigs are deterministic w/ RFC6979 (coincurve default),
        # so the byte equality below holds.
        assert witness == ref_witness


# ---------------------------------------------------------------------------
# P2SH-P2WSH 2-of-2 wrap
# ---------------------------------------------------------------------------


class TestP2SHP2WSH:
    def test_2of2_wrap_signs_and_redeem_hashes_correctly(self):
        keys = [_mk_key(101), _mk_key(202)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])

        # Build a P2SH scriptPubKey for the wrapper.
        ws_redeem = b"\x00\x20" + hashlib.sha256(ws).digest()
        p2sh_h160 = _hash160(ws_redeem)
        p2sh_spk = b"\xa9\x14" + p2sh_h160 + b"\x87"
        assert len(p2sh_spk) == 23

        tx = _mk_simple_tx()
        ss, witness, sigs = sign_p2sh_p2wsh_input(
            tx, 0, ws, 300_000_000, keys, 0x01
        )
        # scriptSig must push the redeemScript whose hash matches p2sh_spk.
        # Single push of <0x22><redeemScript> for a 34-byte redeem.
        assert ss == bytes([len(ws_redeem)]) + ws_redeem
        # Decode the push and re-hash to confirm.
        pushed = ss[1:]
        assert _hash160(pushed) == p2sh_h160
        assert pushed == ws_redeem
        # Witness stack: [b"", sig1, sig2, witnessScript]
        assert witness[0] == b""
        assert witness[-1] == ws
        assert len(witness) == 4
        assert len(sigs) == 2

        # Verify each sig against the BIP-143 sighash (witnessScript as
        # scriptCode — same as bare P2WSH, that's the whole point of
        # the wrap).
        sighash = bip143_sighash(tx, 0, ws, 300_000_000, 0x01)
        from coincurve import PublicKey

        for sig_with_sh, k in zip(witness[1:-1], keys):
            assert sig_with_sh[-1] == 0x01
            ok = PublicKey(k.pubkey).verify(
                sig_with_sh[:-1], sighash, hasher=None
            )
            assert ok

    def test_p2sh_p2wsh_partial_sign_only_one_key(self):
        keys = [_mk_key(11), _mk_key(22)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        tx = _mk_simple_tx()
        ss, witness, sigs = sign_p2sh_p2wsh_input(
            tx, 0, ws, 100_000_000, [keys[0]], 0x01
        )
        # Still emits a redeemScript scriptSig + witness shape, but
        # sigs len == 1.
        assert len(sigs) == 1
        assert witness[0] == b""
        assert witness[-1] == ws
