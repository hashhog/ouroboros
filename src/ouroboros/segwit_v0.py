"""
BIP-143 segwit v0 raw-transaction signing helpers (P2WSH and P2SH-wraps).

These functions are pulled out of ``rpc.py`` so that:

  1. The BIP-143 sighash computation is computed in one place — both the
     ``signrawtransactionwithkey`` handler and the
     ``signrawtransactionwithwallet`` handler dispatch through the same
     code. Two divergent local copies existed at ``rpc.py:6407`` and
     ``rpc.py:8559`` (W19 audit, "drift risk on future fixes").

  2. The new P2WSH and P2SH-P2WSH branches added in W28 can be unit
     tested without spinning up the FastAPI app.

References
----------
* BIP-143: Transaction Signature Verification for Version 0 Witness
  Programs — https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
* Bitcoin Core ``src/script/interpreter.cpp::SignatureHash`` (BIP-143
  branch when ``sigversion == SigVersion::WITNESS_V0``).
* Bitcoin Core ``src/script/sign.cpp::ProduceSignature`` for the
  dispatcher template.

Scope of this module
--------------------
* P2WPKH bare and P2SH-P2WPKH wrap signing (single-key, helper exposed
  for parity with new P2WSH paths).
* P2WSH bare signing for both single-key (``<pk> OP_CHECKSIG``) and
  ``OP_M ... OP_N OP_CHECKMULTISIG`` witnessScripts (M-of-N).
* P2SH-P2WSH wrap signing — same witness stack as bare P2WSH plus a
  ``scriptSig = push(redeemScript)`` where ``redeemScript`` is the
  P2WSH scriptPubKey ``OP_0 <SHA256(witnessScript)>``.

Out of scope (deliberate)
-------------------------
* Tapscript signing (BIP-342) — Phase 4.
* Multi-party PSBT partial-sign + combiner state machine — Phase 2.5.
* Arbitrary witnessScripts that are neither single-key CHECKSIG nor
  OP_CHECKMULTISIG (e.g. Miniscript-emitted scripts) — those return an
  error rather than producing a malformed witness.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ouroboros.database import Transaction
    from ouroboros.wallet import WalletKey


# ---------------------------------------------------------------------------
# Shared helpers (mirror ouroboros.wallet._encode_varint / _dsha256, kept
# local to avoid cyclic-import risk during wallet/rpc loading order).
# ---------------------------------------------------------------------------


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# BIP-143 sighash (segwit v0) — single source of truth.
# ---------------------------------------------------------------------------


def bip143_sighash(
    tx: "Transaction",
    input_index: int,
    script_code: bytes,
    value: int,
    sighash_type: int,
) -> bytes:
    """Compute the BIP-143 sighash for ``input_index``.

    ``script_code`` is the canonical "P2WPKH script code" for P2WPKH
    inputs (``OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG``) and
    the *witnessScript verbatim* for P2WSH inputs.

    ``value`` is the previous output's amount in satoshis.

    ``sighash_type`` is the 1-byte BIP-143 sighash flag (``0x01`` =
    SIGHASH_ALL, ``0x81`` = SIGHASH_ALL|ANYONECANPAY, etc.).
    """
    base = sighash_type & 0x1F
    acp = (sighash_type & 0x80) != 0

    if not acp:
        prevouts = b"".join(
            i.prev_txid + struct.pack("<I", i.prev_vout) for i in tx.inputs
        )
        hash_prevouts = _dsha256(prevouts)
    else:
        hash_prevouts = b"\x00" * 32

    if not acp and base not in (2, 3):
        seqs = b"".join(struct.pack("<I", i.sequence) for i in tx.inputs)
        hash_sequence = _dsha256(seqs)
    else:
        hash_sequence = b"\x00" * 32

    if base not in (2, 3):
        outs = bytearray()
        for o in tx.outputs:
            outs += struct.pack("<q", o.value)
            outs += _encode_varint(len(o.script_pubkey))
            outs += o.script_pubkey
        hash_outputs = _dsha256(bytes(outs))
    elif base == 3 and input_index < len(tx.outputs):
        o = tx.outputs[input_index]
        single = struct.pack("<q", o.value)
        single += _encode_varint(len(o.script_pubkey))
        single += o.script_pubkey
        hash_outputs = _dsha256(single)
    else:
        hash_outputs = b"\x00" * 32

    inp = tx.inputs[input_index]
    pre = bytearray()
    pre += struct.pack("<i", tx.version)
    pre += hash_prevouts
    pre += hash_sequence
    pre += inp.prev_txid + struct.pack("<I", inp.prev_vout)
    pre += _encode_varint(len(script_code))
    pre += script_code
    pre += struct.pack("<q", value)
    pre += struct.pack("<I", inp.sequence)
    pre += hash_outputs
    pre += struct.pack("<I", tx.locktime)
    pre += struct.pack("<I", sighash_type)
    return _dsha256(bytes(pre))


# ---------------------------------------------------------------------------
# witnessScript inspection: detect single-key CHECKSIG and bare M-of-N
# OP_CHECKMULTISIG patterns and pull the pubkeys out.
# ---------------------------------------------------------------------------


# Bitcoin script opcodes used here.
OP_0 = 0x00
OP_1 = 0x51  # 81
OP_16 = 0x60  # 96
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF


def _decode_smallint(b: int) -> int | None:
    """Return the integer ``OP_N`` (1..16) decodes to, or None."""
    if b == OP_0:
        return 0
    if OP_1 <= b <= OP_16:
        return b - OP_1 + 1
    return None


def _iter_script_pushes(script: bytes):
    """Yield ``(opcode, payload, end_offset)`` for each push op.

    Non-push opcodes yield ``(op, b"", end)``. Used for crude pattern
    matching; not a full script parser.
    """
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if 1 <= op <= 0x4B:
            payload = script[i : i + op]
            i += op
            yield op, payload, i
        elif op == OP_PUSHDATA1:
            ln = script[i]
            i += 1
            payload = script[i : i + ln]
            i += ln
            yield op, payload, i
        elif op == OP_PUSHDATA2:
            ln = int.from_bytes(script[i : i + 2], "little")
            i += 2
            payload = script[i : i + ln]
            i += ln
            yield op, payload, i
        elif op == OP_PUSHDATA4:
            ln = int.from_bytes(script[i : i + 4], "little")
            i += 4
            payload = script[i : i + ln]
            i += ln
            yield op, payload, i
        else:
            yield op, b"", i


def parse_multisig_script(script: bytes) -> tuple[int, list[bytes]] | None:
    """Match ``OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG`` and return ``(M, [pks])``.

    Returns None if the script does not match a bare M-of-N multisig.
    Pubkeys may be 33 (compressed) or 65 (uncompressed) bytes.
    """
    if not script or script[-1] not in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
        return None
    if len(script) < 4:
        return None
    m = _decode_smallint(script[0])
    if m is None or m < 1:
        return None

    ops = list(_iter_script_pushes(script))
    # First op must be OP_M (already consumed above by reading script[0]).
    if not ops or ops[0][0] != script[0]:
        return None

    # Walk pubkey pushes between OP_M and OP_N.
    pubkeys: list[bytes] = []
    j = 1
    while j < len(ops):
        op, payload, _ = ops[j]
        if 1 <= op <= 0x4B and len(payload) in (33, 65):
            pubkeys.append(bytes(payload))
            j += 1
            continue
        break

    if j >= len(ops):
        return None

    n_op, _, _ = ops[j]
    n = _decode_smallint(n_op)
    if n is None or n != len(pubkeys):
        return None
    if m > n:
        return None

    # Next must be OP_CHECKMULTISIG (already gated on script[-1] above);
    # this also ensures we hit the end of the script with no trailing ops.
    if j + 1 >= len(ops):
        return None
    final_op, _, end_off = ops[j + 1]
    if final_op not in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
        return None
    if end_off != len(script):
        return None

    return m, pubkeys


def parse_p2pk_checksig_script(script: bytes) -> bytes | None:
    """Match ``<pubkey> OP_CHECKSIG`` and return the pubkey, or None."""
    if not script or script[-1] not in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
        return None
    ops = list(_iter_script_pushes(script))
    if len(ops) != 2:
        return None
    op, payload, end_off = ops[0]
    if not (1 <= op <= 0x4B):
        return None
    if len(payload) not in (33, 65):
        return None
    final_op, _, end_off2 = ops[1]
    if final_op not in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
        return None
    if end_off2 != len(script):
        return None
    return bytes(payload)


# ---------------------------------------------------------------------------
# Signers
# ---------------------------------------------------------------------------


def _push_data(data: bytes) -> bytes:
    """Encode a single push of ``data`` for use inside scriptSig.

    Mirrors Core's ``CScript << data`` operator overload: small lengths
    use the bare push opcode; longer ones use OP_PUSHDATA1/2/4. The
    witness stack does NOT use this — witness items are length-prefixed
    by ``compactSize`` directly (handled by ``serialize_with_witness``).
    """
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def sign_p2wsh_input(
    tx: "Transaction",
    input_index: int,
    witness_script: bytes,
    value: int,
    signing_keys: list["WalletKey"],
    sighash_type: int = 0x01,
) -> tuple[list[bytes], list[bytes]]:
    """Sign a bare P2WSH input.

    Returns ``(witness_stack, signatures_used)``.

    ``witness_stack`` is the witness items list ready to assign to
    ``tx.inputs[input_index].witness``. The caller must also set
    ``tx.has_witness = True``.

    Supported witnessScript shapes:
      * ``<pubkey> OP_CHECKSIG``  — single-key. Stack: ``[sig, witnessScript]``.
      * ``OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG`` — multisig.
        Stack: ``[OP_0, sig1, ..., sigM, witnessScript]`` (the leading
        ``b""`` empty bytes item is the off-by-one OP_CHECKMULTISIG dummy).

    For multisig, signatures are inserted in the order the pubkeys appear
    in ``witnessScript`` (Core's ``CHECKMULTISIG`` requires that). Keys
    in ``signing_keys`` that are not in the witnessScript are ignored;
    keys in the witnessScript that are missing from ``signing_keys``
    are simply skipped (partial sign — caller decides whether
    ``len(sigs) >= M`` is "complete").
    """
    sigs_used: list[bytes] = []

    # Try multisig pattern first (the more common P2WSH shape).
    multisig = parse_multisig_script(witness_script)
    if multisig is not None:
        m, script_pubkeys = multisig
        sigs_in_order: list[bytes] = []
        keys_by_pubkey = {k.pubkey: k for k in signing_keys}
        # Index uncompressed too if any key happens to be uncompressed.
        for k in signing_keys:
            if len(k.pubkey) == 33:
                # 65-byte uncompressed form not derivable from compressed
                # without a libsecp call — skip; multisig vectors in
                # practice use compressed pubkeys.
                pass
        for pk in script_pubkeys:
            if len(sigs_in_order) >= m:
                break
            key = keys_by_pubkey.get(pk)
            if key is None:
                continue
            sh = bip143_sighash(
                tx, input_index, witness_script, value, sighash_type
            )
            sig = key.sign(sh) + bytes([sighash_type])
            sigs_in_order.append(sig)
            sigs_used.append(sig)
        # Stack: <empty> sig1 ... sigK witnessScript. The empty item is
        # CHECKMULTISIG's off-by-one dummy. Even partial signs include
        # it — Core's PSBT finalizer follows the same shape.
        witness = [b""] + sigs_in_order + [witness_script]
        return witness, sigs_used

    # Single-key CHECKSIG.
    pk = parse_p2pk_checksig_script(witness_script)
    if pk is not None:
        keys_by_pubkey = {k.pubkey: k for k in signing_keys}
        key = keys_by_pubkey.get(pk)
        if key is None:
            # No signing key — return unsigned witness shape for the
            # caller's "complete=False" path.
            return [b"", witness_script], []
        sh = bip143_sighash(
            tx, input_index, witness_script, value, sighash_type
        )
        sig = key.sign(sh) + bytes([sighash_type])
        sigs_used.append(sig)
        return [sig, witness_script], sigs_used

    # Unknown witnessScript shape — refuse rather than emit garbage.
    raise ValueError(
        "Unsupported P2WSH witnessScript shape: "
        "expected <pk> OP_CHECKSIG or OP_M ... OP_N OP_CHECKMULTISIG"
    )


def sign_p2sh_p2wpkh_input(
    tx: "Transaction",
    input_index: int,
    key: "WalletKey",
    value: int,
    sighash_type: int = 0x01,
) -> tuple[bytes, list[bytes]]:
    """Sign a P2SH-wrapped P2WPKH input.

    Returns ``(script_sig, witness_stack)``.

    The caller assigns ``script_sig`` to ``tx.inputs[idx].script_sig``,
    sets ``tx.inputs[idx].witness = witness_stack``, and flips
    ``tx.has_witness = True``.

    ``redeemScript`` is ``OP_0 <HASH160(pubkey)>`` (P2WPKH scriptPubKey
    pattern); ``scriptSig`` is a single push of the redeemScript.
    """
    from ouroboros.wallet import _hash160

    h160 = _hash160(key.pubkey)
    redeem_script = b"\x00\x14" + h160
    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
    sh = bip143_sighash(tx, input_index, script_code, value, sighash_type)
    sig = key.sign(sh) + bytes([sighash_type])
    return _push_data(redeem_script), [sig, key.pubkey]


# ---------------------------------------------------------------------------
# P2SH / P2WSH commitment-check helpers
# ---------------------------------------------------------------------------
#
# BIP-16 (P2SH) commits the redeemScript to the scriptPubKey via
# HASH160(redeemScript). BIP-141 (P2WSH) commits the witnessScript via
# SHA256(witnessScript). Validators MUST check both before accepting any
# script-side data — but PSBT *finalizers* operate on data that arrived
# from a multi-party workflow and can be forged independently of the
# UTXO. The pre-W31 PSBT finalizer here checked the redeemScript *shape*
# (OP_0 <20 bytes>) but never compared HASH160(redeemScript) against
# witness_utxo.scriptPubKey[2:22]; a malicious cosigner could swap in a
# different P2WPKH redeemScript and produce a structurally valid PSBT
# that, when extracted, broadcasts a transaction whose scriptSig fails
# script verification. The hotbuns W29-D wave fixed the same class of
# bug in TS; this is the Python parity fix.


def verify_p2sh_commitment(redeem_script: bytes, script_pubkey: bytes) -> None:
    """Raise ``ValueError`` if ``HASH160(redeem_script)`` does not match the P2SH
    scriptPubKey commitment.

    A P2SH scriptPubKey is the 23-byte sequence
    ``OP_HASH160 <20-byte push> OP_EQUAL`` (``0xa9 0x14 <h160> 0x87``).
    This helper enforces:

      1. ``script_pubkey`` is exactly 23 bytes with the canonical prefix
         and trailing ``OP_EQUAL``.
      2. ``HASH160(redeem_script) == script_pubkey[2:22]``.

    Used by the PSBT finalizer (P2SH-P2WPKH and P2SH-P2WSH paths) and is
    safe to call from any other validator that needs to assert the
    BIP-16 commitment before relying on a redeem-script.
    """
    from ouroboros.wallet import _hash160

    if (
        len(script_pubkey) != 23
        or script_pubkey[0] != 0xA9
        or script_pubkey[1] != 0x14
        or script_pubkey[22] != 0x87
    ):
        raise ValueError("scriptPubKey is not P2SH")
    expected = script_pubkey[2:22]
    actual = _hash160(redeem_script)
    if expected != actual:
        raise ValueError(
            "redeem_script does not commit to scriptPubKey "
            f"(expected hash160={expected.hex()}, got {actual.hex()})"
        )


def verify_p2wsh_commitment(witness_script: bytes, program: bytes) -> None:
    """Raise ``ValueError`` if ``SHA256(witness_script)`` does not match the
    P2WSH 32-byte witness program.

    ``program`` is the *bare* 32-byte witness program (i.e. what follows
    the ``OP_0 0x20`` prefix in a P2WSH scriptPubKey or redeemScript) —
    *not* the full 34-byte scriptPubKey. Callers who have the full
    scriptPubKey should slice ``[2:34]`` themselves; that asymmetry with
    ``verify_p2sh_commitment`` is deliberate (a P2WSH program can appear
    bare inside a P2SH-P2WSH redeemScript).
    """
    if len(program) != 32:
        raise ValueError(f"P2WSH program must be 32 bytes, got {len(program)}")
    actual = hashlib.sha256(witness_script).digest()
    if program != actual:
        raise ValueError(
            "witness_script does not commit to P2WSH program "
            f"(expected sha256={program.hex()}, got {actual.hex()})"
        )


def sign_p2sh_p2wsh_input(
    tx: "Transaction",
    input_index: int,
    witness_script: bytes,
    value: int,
    signing_keys: list["WalletKey"],
    sighash_type: int = 0x01,
) -> tuple[bytes, list[bytes], list[bytes]]:
    """Sign a P2SH-wrapped P2WSH input.

    Returns ``(script_sig, witness_stack, signatures_used)``.

    Witness stack is identical to bare P2WSH; ``script_sig`` is a single
    push of the redeem-script ``OP_0 <SHA256(witnessScript)>`` (the
    P2WSH scriptPubKey).
    """
    redeem_script = b"\x00\x20" + hashlib.sha256(witness_script).digest()
    witness, sigs_used = sign_p2wsh_input(
        tx, input_index, witness_script, value, signing_keys, sighash_type
    )
    return _push_data(redeem_script), witness, sigs_used
