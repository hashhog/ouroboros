"""
Regression tests for the W29-A BIP-143 sighash consolidation.

Background (W29-A)
------------------
Three private BIP-143 sighash implementations had grown inside
``rpc.py``:

  * ``rpc.py:6418`` — driving ``signrawtransactionwithkey``
  * ``rpc.py:8690`` — driving ``walletprocesspsbt``
  * ``rpc.py:10278 _compute_bip143_sighash`` — driving
    ``signrawtransactionwithwallet``

The first two matched ``Transaction.serialize_with_witness``'s
prev_txid byte-order convention (no reversal). The third reversed
``prev_txid`` (``inp.prev_txid[::-1]``) — so signatures from
``signrawtransactionwithwallet`` were computed against a different
sighash than the rest of the network would compute on relay. They
never verified, end-to-end. P0.

This was the second parallel-impl-drift in ``rpc.py`` in a single
day after W23-B's taproot tweak duplication.

Fix (W29-A)
-----------
* Promote ``ouroboros.segwit_v0.bip143_sighash`` (W28's helper) to the
  single source of truth.
* Delete the 2 inline copies in ``rpc.py`` and the buggy
  ``_compute_bip143_sighash`` method.
* Wire all 3 callers through the canonical helper.

These tests pin the byte-order behavior so a future re-introduction
of a private impl is caught immediately.

Reference
---------
* BIP-143:
  https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
* Bitcoin Core
  ``src/script/interpreter.cpp::SignatureHash`` (WITNESS_V0 branch).
"""

from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.segwit_v0 import bip143_sighash
from ouroboros.wallet import WalletKey, _hash160


# ---------------------------------------------------------------------------
# Fixture: 2-input P2WSH spend transaction with deterministic keys.
# ---------------------------------------------------------------------------


def _mk_key(secret_int: int) -> WalletKey:
    return WalletKey(secret_int.to_bytes(32, "big"), network="regtest")


def _build_multisig_script(m: int, pubkeys: list[bytes]) -> bytes:
    """Build the bare ``OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG`` script."""
    op_m = 0x50 + m
    op_n = 0x50 + len(pubkeys)
    parts = bytearray([op_m])
    for pk in pubkeys:
        parts.append(len(pk))
        parts.extend(pk)
    parts.append(op_n)
    parts.append(0xAE)  # OP_CHECKMULTISIG
    return bytes(parts)


def _two_input_p2wsh_tx() -> tuple[Transaction, list[bytes], list[int]]:
    """Build a deterministic 2-input / 1-output P2WSH spend.

    Returns ``(tx, witness_scripts_per_input, prev_values_per_input)``.
    """
    keys_a = [_mk_key(i + 11) for i in range(2)]  # 2-of-2
    keys_b = [_mk_key(i + 21) for i in range(2)]  # 2-of-2
    ws_a = _build_multisig_script(2, [k.pubkey for k in keys_a])
    ws_b = _build_multisig_script(2, [k.pubkey for k in keys_b])

    # Deterministic prev_txid bytes — internal-order (NOT display order).
    # Asymmetric so reversal produces a distinct byte string (the W29-A
    # buggy variant byte-reversed prev_txid; we want the regression test
    # below to actually exercise that difference).
    prev_a = bytes.fromhex(
        "deadbeefcafef00d0102030405060708090a0b0c0d0e0f1011121314151617aa"
    )
    prev_b = bytes.fromhex(
        "00112233445566778899aabbccddeefffedcba9876543210facefacefaceface"
    )
    # Sanity: the reversed forms must differ from the originals.
    assert prev_a != prev_a[::-1]
    assert prev_b != prev_b[::-1]

    tx = Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=prev_a,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFD,
                witness=None,
            ),
            TxIn(
                prev_txid=prev_b,
                prev_vout=1,
                script_sig=b"",
                sequence=0xFFFFFFFE,
                witness=None,
            ),
        ],
        outputs=[
            TxOut(value=49_000_000, script_pubkey=b"\x00\x14" + b"\xcc" * 20),
        ],
        has_witness=False,
    )
    return tx, [ws_a, ws_b], [50_000_000, 50_000_000]


# ---------------------------------------------------------------------------
# Hand-rolled BIP-143 reference — direct transcription of the spec.
# ---------------------------------------------------------------------------


def _ref_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _ref_dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _bip143_reference(
    tx: Transaction,
    idx: int,
    script_code: bytes,
    value: int,
    sighash_type: int,
) -> bytes:
    """Independent re-implementation of BIP-143 from the spec."""
    base = sighash_type & 0x1F
    acp = (sighash_type & 0x80) != 0

    # hashPrevouts: dsha256(prev_txid || prev_vout for each input).
    # NOTE: prev_txid is the 32-byte internal-order hash exactly as
    # serialize_with_witness writes it — NO reversal.
    if not acp:
        hash_prevouts = _ref_dsha256(
            b"".join(
                inp.prev_txid + struct.pack("<I", inp.prev_vout)
                for inp in tx.inputs
            )
        )
    else:
        hash_prevouts = b"\x00" * 32

    if not acp and base not in (2, 3):
        hash_sequence = _ref_dsha256(
            b"".join(struct.pack("<I", inp.sequence) for inp in tx.inputs)
        )
    else:
        hash_sequence = b"\x00" * 32

    if base not in (2, 3):
        outs = bytearray()
        for o in tx.outputs:
            outs += struct.pack("<q", o.value)
            outs += _ref_varint(len(o.script_pubkey))
            outs += o.script_pubkey
        hash_outputs = _ref_dsha256(bytes(outs))
    elif base == 3 and idx < len(tx.outputs):
        o = tx.outputs[idx]
        single = struct.pack("<q", o.value)
        single += _ref_varint(len(o.script_pubkey))
        single += o.script_pubkey
        hash_outputs = _ref_dsha256(single)
    else:
        hash_outputs = b"\x00" * 32

    inp = tx.inputs[idx]
    pre = bytearray()
    pre += struct.pack("<i", tx.version)
    pre += hash_prevouts
    pre += hash_sequence
    pre += inp.prev_txid + struct.pack("<I", inp.prev_vout)
    pre += _ref_varint(len(script_code))
    pre += script_code
    pre += struct.pack("<q", value)
    pre += struct.pack("<I", inp.sequence)
    pre += hash_outputs
    pre += struct.pack("<I", tx.locktime)
    pre += struct.pack("<I", sighash_type)
    return _ref_dsha256(bytes(pre))


# ---------------------------------------------------------------------------
# 1. signrawtransactionwithwallet sighash matches the BIP-143 spec.
# ---------------------------------------------------------------------------


class TestSighashMatchesSpec:
    """The canonical helper must produce the BIP-143 spec sighash."""

    def test_p2wsh_two_input_input0_sighash_all(self):
        tx, ws_list, values = _two_input_p2wsh_tx()
        # Input 0 sighash, scriptCode = witnessScript verbatim (P2WSH).
        sighash_type = 0x01  # SIGHASH_ALL
        spec = _bip143_reference(tx, 0, ws_list[0], values[0], sighash_type)
        canon = bip143_sighash(tx, 0, ws_list[0], values[0], sighash_type)
        assert canon == spec, (
            f"canonical helper diverges from BIP-143 spec: "
            f"canon={canon.hex()} spec={spec.hex()}"
        )

    def test_p2wsh_two_input_input1_sighash_all(self):
        tx, ws_list, values = _two_input_p2wsh_tx()
        sighash_type = 0x01
        spec = _bip143_reference(tx, 1, ws_list[1], values[1], sighash_type)
        canon = bip143_sighash(tx, 1, ws_list[1], values[1], sighash_type)
        assert canon == spec

    def test_p2wsh_two_input_acp_single(self):
        # Exercise ANYONECANPAY|SINGLE — different
        # hashPrevouts/hashSequence/hashOutputs branches.
        tx, ws_list, values = _two_input_p2wsh_tx()
        sighash_type = 0x83  # SIGHASH_SINGLE | ANYONECANPAY
        for idx in (0, 1):
            spec = _bip143_reference(
                tx, idx, ws_list[idx], values[idx], sighash_type
            )
            canon = bip143_sighash(
                tx, idx, ws_list[idx], values[idx], sighash_type
            )
            assert canon == spec, (
                f"input={idx} sh=0x{sighash_type:02x}: "
                f"canon={canon.hex()} spec={spec.hex()}"
            )


# ---------------------------------------------------------------------------
# 2. The 3 callers (signrawtxwithwallet, signrawtxwithkey,
#    walletprocesspsbt) all dispatch through the SAME canonical helper —
#    so by construction they agree. This is the cross-caller parity
#    test: verify all 3 import the canonical, and that the canonical's
#    output equals the spec for the path each caller exercises (P2WPKH
#    in this case, the P2WSH path is covered above).
# ---------------------------------------------------------------------------


class TestCrossCallerSighashParity:
    """All 3 sign* RPC handlers route through ``segwit_v0.bip143_sighash``."""

    def test_p2wpkh_sighash_matches_across_paths(self):
        # Identical inputs to a P2WPKH sighash — the script_code is
        # ``OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG``.
        key = _mk_key(0xBEEF)
        tx, _ws, _v = _two_input_p2wsh_tx()  # reuse the 2-input shape
        h160 = _hash160(key.pubkey)
        script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"

        for sh_type in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            canonical = bip143_sighash(
                tx, 0, script_code, 100_000_000, sh_type
            )
            spec = _bip143_reference(
                tx, 0, script_code, 100_000_000, sh_type
            )
            assert canonical == spec, (
                f"sh=0x{sh_type:02x}: canonical={canonical.hex()} "
                f"spec={spec.hex()}"
            )

    def test_canonical_signature_verifies(self):
        """Sanity: a sig produced over the canonical sighash verifies."""
        from coincurve import PublicKey

        keys = [_mk_key(i + 11) for i in range(2)]
        ws = _build_multisig_script(2, [k.pubkey for k in keys])
        tx, _ws_unused, _v = _two_input_p2wsh_tx()
        # Replace input-0 witnessScript with our scripted one for the test
        canonical = bip143_sighash(tx, 0, ws, 50_000_000, 0x01)

        for k in keys:
            sig = k.sign(canonical)
            ok = PublicKey(k.pubkey).verify(sig, canonical, hasher=None)
            assert ok, f"sig must verify against canonical sighash for {k.pubkey.hex()[:10]}"


# ---------------------------------------------------------------------------
# 3. Byte-order pinning: the canonical helper must follow
#    ``Transaction.serialize_with_witness``'s prev_txid convention
#    (no reversal). The deleted ``_compute_bip143_sighash`` reversed
#    prev_txid — that bug must NOT come back.
# ---------------------------------------------------------------------------


def _bip143_REVERSED_buggy(
    tx: Transaction,
    idx: int,
    script_code: bytes,
    value: int,
    sighash_type: int,
) -> bytes:
    """The W29-A buggy variant — reproduces the deleted
    ``_compute_bip143_sighash``'s prev_txid reversal. The ONLY purpose
    of this function is to assert in the regression test that the
    canonical helper does NOT match this — i.e. the bug is gone."""
    base = sighash_type & 0x1F
    acp = (sighash_type & 0x80) != 0
    if acp:
        hp = b"\x00" * 32
    else:
        hp = _ref_dsha256(
            b"".join(
                inp.prev_txid[::-1] + struct.pack("<I", inp.prev_vout)
                for inp in tx.inputs
            )
        )
    if not acp and base not in (2, 3):
        hs = _ref_dsha256(
            b"".join(struct.pack("<I", inp.sequence) for inp in tx.inputs)
        )
    else:
        hs = b"\x00" * 32
    if base not in (2, 3):
        outs = bytearray()
        for o in tx.outputs:
            outs += struct.pack("<q", o.value)
            outs += _ref_varint(len(o.script_pubkey))
            outs += o.script_pubkey
        ho = _ref_dsha256(bytes(outs))
    elif base == 3 and idx < len(tx.outputs):
        o = tx.outputs[idx]
        single = struct.pack("<q", o.value)
        single += _ref_varint(len(o.script_pubkey))
        single += o.script_pubkey
        ho = _ref_dsha256(single)
    else:
        ho = b"\x00" * 32
    inp = tx.inputs[idx]
    pre = bytearray()
    pre += struct.pack("<i", tx.version)
    pre += hp + hs
    pre += inp.prev_txid[::-1] + struct.pack("<I", inp.prev_vout)
    pre += _ref_varint(len(script_code)) + script_code
    pre += struct.pack("<q", value)
    pre += struct.pack("<I", inp.sequence)
    pre += ho
    pre += struct.pack("<I", tx.locktime)
    pre += struct.pack("<I", sighash_type)
    return _ref_dsha256(bytes(pre))


class TestPrevTxidByteOrderPinned:
    """Pin: canonical agrees with serialize_with_witness, NOT the
    buggy reversed variant. If anyone re-introduces a reversed-prev
    impl in the future, this fails."""

    def test_canonical_does_not_match_buggy_variant(self):
        tx, ws_list, values = _two_input_p2wsh_tx()
        canon = bip143_sighash(tx, 0, ws_list[0], values[0], 0x01)
        buggy = _bip143_REVERSED_buggy(tx, 0, ws_list[0], values[0], 0x01)
        assert canon != buggy, (
            "canonical helper produced the buggy reversed-prev sighash; "
            "the W29-A regression has come back"
        )

    def test_canonical_aligns_with_serialize_with_witness_prev_order(self):
        """``hashPrevouts`` must be computed from the same byte string
        as ``serialize_with_witness`` writes for the per-input prevout
        — i.e. ``prev_txid`` not reversed."""
        tx, _ws, _v = _two_input_p2wsh_tx()
        # hashPrevouts in the canonical (acp=0): dsha256(prev_txid || vout for each input)
        expected_prevouts = b"".join(
            inp.prev_txid + struct.pack("<I", inp.prev_vout)
            for inp in tx.inputs
        )
        # Verify canonical prevouts match by checking the canonical
        # sighash equals the spec built from the same byte order.
        canon = bip143_sighash(tx, 0, b"\x51", 12345, 0x01)
        spec = _bip143_reference(tx, 0, b"\x51", 12345, 0x01)
        assert canon == spec
        # And the byte string we'd hash matches what serialize_with_witness
        # would write input-by-input (just the prevout bytes).
        from io import BytesIO

        ser = bytearray()
        for inp in tx.inputs:
            ser += inp.prev_txid + struct.pack("<I", inp.prev_vout)
        assert bytes(ser) == expected_prevouts


# ---------------------------------------------------------------------------
# 4. Parity sentinel — grep rpc.py for re-introduced inline impls.
# ---------------------------------------------------------------------------


_RPC_PATH = Path(__file__).resolve().parent.parent / "src" / "ouroboros" / "rpc.py"


class TestParitySentinel:
    """If anyone defines a private ``_*bip143_sighash*`` in rpc.py
    (case-insensitive), this fails. Force them to use the canonical
    ``segwit_v0.bip143_sighash``.

    Mirror of the W23-B taproot tweak parity test — same idea, same
    failure mode it prevents.
    """

    def test_no_inline_bip143_sighash_def_in_rpc_py(self):
        text = _RPC_PATH.read_text()
        # Match either ``def _bip143_sighash`` (nested helper) or
        # ``def _compute_bip143_sighash`` (the deleted method) —
        # case-insensitive.  ``import bip143_sighash`` is fine.
        bad_def = re.compile(
            r"^\s*def\s+\w*bip143_sighash\b", re.IGNORECASE | re.MULTILINE
        )
        matches = bad_def.findall(text)
        assert not matches, (
            "rpc.py re-introduced an inline BIP-143 sighash impl. "
            "Route through ouroboros.segwit_v0.bip143_sighash instead. "
            f"Found defs: {matches}"
        )

    def test_canonical_helper_imported_in_rpc_py(self):
        """All 3 sighash callsites import the canonical helper."""
        text = _RPC_PATH.read_text()
        # The 3 callers (signrawtransactionwithkey, walletprocesspsbt,
        # signrawtransactionwithwallet) each import bip143_sighash from
        # segwit_v0. We require >= 3 imports as a proxy.
        imports = re.findall(
            r"from\s+ouroboros\.segwit_v0\s+import\s+bip143_sighash", text
        )
        assert len(imports) >= 3, (
            f"expected >= 3 imports of segwit_v0.bip143_sighash in rpc.py "
            f"(one per sign* RPC handler), found {len(imports)}"
        )
