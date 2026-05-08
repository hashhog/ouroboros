"""Regression tests for W41 — PSBT NON_WITNESS_UTXO consistency + decodepsbt
txid endianness.

Three bug classes covered:

* A1 (W40-A): ``rpc_walletprocesspsbt`` indexed
  ``non_witness_utxo``→``outputs[prev_vout]`` without checking that
  ``sha256d(non_witness_utxo) == prev_txid``. A coordinator could swap in
  a forged prev-tx blob and the signer would commit to its outputs. Fix:
  reject when the hash mismatches before the index step.

* A2 (CVE-2020-14199 class): when both ``witness_utxo`` and
  ``non_witness_utxo`` are present, the signer used the
  ``witness_utxo`` amount unconditionally — an amount-oracle attack.
  Fix: require both to agree on (amount, scriptPubKey); reject on
  mismatch and prefer the tx-derived value when both pass.

* W40-C harness (``tools/psbt-multi-input-test.sh``):
  ``decodepsbt(...).tx.txid`` was emitted in internal LE form
  (``7b61d191...``) instead of canonical display BE
  (``82efd652...``). Plus the cross-handler audit found
  ``_tx_to_dict`` (used by getrawtransaction / decoderawtransaction /
  gettransaction / getblock verbosity 1+2+3) and
  ``rpc_sendrawtransaction`` carrying the same shape bug.

References:
- bitcoin-core/src/psbt.cpp ``PSBTInput::IsSane`` (A1 + A2 contract)
- bitcoin-core/src/rpc/rawtransaction.cpp ``TxToUniv`` (display-order
  txid serialization)
- ``CLAUDE.md`` known issue: txid display convention.
"""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import PSBT


# ---------------------------------------------------------------------------
# Fixture: 2-input/2-output asymmetric PSBT lifted from
# tools/psbt-multi-input-fixture.json (extracted from
# bitcoin-core/test/functional/data/rpc_psbt.json by the W40-C harness).
# Including the bytes inline so the ouroboros submodule's tests are
# self-contained (do not depend on meta-repo paths).
# ---------------------------------------------------------------------------
W40C_PSBT_SIGNED = (
    "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9Ds"
    "ZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuB"
    "XlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+E"
    "rkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2r"
    "ZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0"
    "IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785"
    "rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282b"
    "Va1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxL"
    "GDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pn"
    "Wm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhV"
    "nWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCX"
    "R60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8"
    "SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHb"
    "NTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0Ws"
    "SrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI6"
    "3ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90"
    "UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3"
    "Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50b"
    "mQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUp"
    "t/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcj"
    "N50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWH"
    "cRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8A"
    "AACAAAAAgAUAAIAA"
)
W40C_FIXTURE_TXID_BE = (
    "82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b"
)


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _serialize_simple_tx(
    *, version: int = 2, outputs: list[tuple[int, bytes]],
) -> bytes:
    """Serialize a 1-input dummy tx with the supplied outputs (no witness)."""
    data = bytearray()
    data += struct.pack("<i", version)
    # 1 dummy input
    data += _encode_varint(1)
    data += b"\x00" * 32
    data += struct.pack("<I", 0xFFFFFFFF)
    data += _encode_varint(0)  # empty scriptSig
    data += struct.pack("<I", 0xFFFFFFFF)
    # outputs
    data += _encode_varint(len(outputs))
    for value, spk in outputs:
        data += struct.pack("<q", value)
        data += _encode_varint(len(spk))
        data += spk
    # locktime
    data += struct.pack("<I", 0)
    return bytes(data)


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------------------
# Fix 3 — txid endianness in decodepsbt (W40-C harness reproducer)
# ---------------------------------------------------------------------------
class TestDecodepsbtTxidEndianness:
    def test_decodepsbt_emits_display_order_txid(self):
        """The W40-C harness fixture's ``decodepsbt(...).tx.txid`` MUST equal
        Core's canonical BE-display txid, NOT the byte-reversed LE form.
        Pre-W41 this returned ``7b61d191...`` (the reversal of the
        expected hash) because ``self.tx.txid.hex()`` skipped the
        display-order reversal that the vin loop already did.
        """
        psbt = PSBT.deserialize(base64.b64decode(W40C_PSBT_SIGNED))
        decoded = psbt.decode()
        assert decoded["tx"]["txid"] == W40C_FIXTURE_TXID_BE, (
            "decodepsbt must emit txid in display order (Bitcoin Core "
            "convention). Got: " + decoded["tx"]["txid"]
        )
        # And the byte-reversed pre-fix value MUST NOT appear.
        reversed_form = bytes.fromhex(W40C_FIXTURE_TXID_BE)[::-1].hex()
        assert decoded["tx"]["txid"] != reversed_form

    def test_decodepsbt_vin_txid_unchanged(self):
        """vin[*].txid was already correctly reversed; the W41 fix must
        not regress that path."""
        psbt = PSBT.deserialize(base64.b64decode(W40C_PSBT_SIGNED))
        decoded = psbt.decode()
        # Both vin entries are 32 bytes of hex; just sanity-check shape.
        assert len(decoded["tx"]["vin"]) == 2
        for vin in decoded["tx"]["vin"]:
            assert isinstance(vin["txid"], str)
            assert len(vin["txid"]) == 64


# ---------------------------------------------------------------------------
# Fix 1 — Bug A1: NON_WITNESS_UTXO sha256d-vs-prev_txid sanity
# ---------------------------------------------------------------------------
class TestNonWitnessUtxoTxidSanity:
    def _make_psbt_with_non_witness_utxo(
        self, *, real_prev: bytes, claimed_prev_txid: bytes,
    ) -> PSBT:
        """Build a 1-input PSBT whose ``prev_txid`` is ``claimed_prev_txid``
        and whose ``non_witness_utxo`` field carries ``real_prev`` raw.
        When claimed != sha256d(real_prev) the signer must reject."""
        spend_tx = Transaction(
            txid=bytes(32),  # placeholder — recomputed by callers
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=claimed_prev_txid, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=10_000, script_pubkey=b"\x00\x14" + b"\xab" * 20)],
        )
        psbt = PSBT.from_transaction(spend_tx)
        psbt.inputs[0].non_witness_utxo = real_prev
        return psbt

    @pytest.mark.asyncio
    async def test_a1_rejects_mismatched_non_witness_utxo(self):
        """A1: forged non_witness_utxo whose sha256d != prev_txid is
        rejected before the outputs[prev_vout] index. Pre-W41 the
        signer accepted the forged blob and pinned the BIP-143
        ``hashAmount`` to it.
        """
        from fastapi import HTTPException

        from ouroboros.rpc import RPCServer

        # The "honest" prev tx has a 1 BTC P2WPKH output.
        honest_prev = _serialize_simple_tx(
            outputs=[(100_000_000, b"\x00\x14" + b"\x11" * 20)]
        )
        honest_txid_le = _sha256d(honest_prev)

        # Attacker hands us a different blob that sha256d's to a
        # different txid. We claim the honest txid as prev_txid.
        attacker_prev = _serialize_simple_tx(
            outputs=[(999_999_999_99, b"\x00\x14" + b"\x22" * 20)]
        )
        assert _sha256d(attacker_prev) != honest_txid_le

        psbt = self._make_psbt_with_non_witness_utxo(
            real_prev=attacker_prev,
            claimed_prev_txid=honest_txid_le,
        )

        # Stub RPC server with a no-op wallet that has no keys —
        # the consistency check fires before any signing.
        rpc = RPCServer.__new__(RPCServer)
        node = type("N", (), {})()
        node.network = "mainnet"
        node.wallet = type("W", (), {"keys": [], "is_locked": False})()
        rpc.node = node

        with pytest.raises(HTTPException) as excinfo:
            await rpc.rpc_walletprocesspsbt(
                base64.b64encode(psbt.serialize()).decode("ascii"),
                sign=False,
            )
        assert "non_witness_utxo hash mismatch" in str(excinfo.value.detail)

    @pytest.mark.asyncio
    async def test_a1_accepts_consistent_non_witness_utxo(self):
        """Counterpart: when sha256d(non_witness_utxo) == prev_txid the
        signer proceeds (no signing happens because the wallet is empty,
        but no consistency error is raised)."""
        from ouroboros.rpc import RPCServer

        honest_prev = _serialize_simple_tx(
            outputs=[(100_000_000, b"\x00\x14" + b"\x11" * 20)]
        )
        honest_txid_le = _sha256d(honest_prev)

        psbt = self._make_psbt_with_non_witness_utxo(
            real_prev=honest_prev,
            claimed_prev_txid=honest_txid_le,
        )

        rpc = RPCServer.__new__(RPCServer)
        node = type("N", (), {})()
        node.network = "mainnet"
        node.wallet = type("W", (), {"keys": [], "is_locked": False})()
        rpc.node = node

        result = await rpc.rpc_walletprocesspsbt(
            base64.b64encode(psbt.serialize()).decode("ascii"),
            sign=False,
        )
        assert "psbt" in result
        assert result.get("complete") in (True, False)


# ---------------------------------------------------------------------------
# Fix 2 — Bug A2: witness_utxo vs non_witness_utxo (CVE-2020-14199)
# ---------------------------------------------------------------------------
class TestWitnessUtxoAmountOracle:
    @pytest.mark.asyncio
    async def test_a2_rejects_amount_disagreement(self):
        """A2 / CVE-2020-14199 class: when both fields are present and
        the witness_utxo amount lies relative to the tx-derived
        non_witness_utxo amount, reject. Pre-W41 the signer trusted the
        witness_utxo blindly and committed BIP-143 ``hashAmount`` to
        the wrong value, which is the classic amount-oracle attack.
        """
        from fastapi import HTTPException

        from ouroboros.rpc import RPCServer

        spk = b"\x00\x14" + b"\x33" * 20
        honest_amount = 50_000_000  # 0.5 BTC, the truth
        forged_amount = 25_000_000  # what the witness_utxo lies about

        prev_tx_raw = _serialize_simple_tx(
            outputs=[(honest_amount, spk)]
        )
        honest_txid_le = _sha256d(prev_tx_raw)

        spend_tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=honest_txid_le, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=10_000, script_pubkey=b"\x00\x14" + b"\xab" * 20)],
        )
        psbt = PSBT.from_transaction(spend_tx)
        psbt.inputs[0].non_witness_utxo = prev_tx_raw
        psbt.inputs[0].witness_utxo = (forged_amount, spk)  # the lie

        rpc = RPCServer.__new__(RPCServer)
        node = type("N", (), {})()
        node.network = "mainnet"
        node.wallet = type("W", (), {"keys": [], "is_locked": False})()
        rpc.node = node

        with pytest.raises(HTTPException) as excinfo:
            await rpc.rpc_walletprocesspsbt(
                base64.b64encode(psbt.serialize()).decode("ascii"),
                sign=False,
            )
        assert "CVE-2020-14199" in str(excinfo.value.detail) or \
               "disagrees" in str(excinfo.value.detail)

    @pytest.mark.asyncio
    async def test_a2_accepts_matching_amounts(self):
        """When witness_utxo and non_witness_utxo agree on
        (amount, scriptPubKey), the signer continues."""
        from ouroboros.rpc import RPCServer

        spk = b"\x00\x14" + b"\x44" * 20
        amount = 75_000_000

        prev_tx_raw = _serialize_simple_tx(outputs=[(amount, spk)])
        prev_txid_le = _sha256d(prev_tx_raw)

        spend_tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=prev_txid_le, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=10_000, script_pubkey=b"\x00\x14" + b"\xab" * 20)],
        )
        psbt = PSBT.from_transaction(spend_tx)
        psbt.inputs[0].non_witness_utxo = prev_tx_raw
        psbt.inputs[0].witness_utxo = (amount, spk)  # consistent

        rpc = RPCServer.__new__(RPCServer)
        node = type("N", (), {})()
        node.network = "mainnet"
        node.wallet = type("W", (), {"keys": [], "is_locked": False})()
        rpc.node = node

        result = await rpc.rpc_walletprocesspsbt(
            base64.b64encode(psbt.serialize()).decode("ascii"),
            sign=False,
        )
        assert "psbt" in result


# ---------------------------------------------------------------------------
# Cross-handler audit (W41 finding): _tx_to_dict / _vin_to_dict / etc.
# ---------------------------------------------------------------------------
class TestTxToDictTxidEndianness:
    def test_tx_to_dict_emits_display_order_txid(self):
        """Direct unit test of ``RPCServer._tx_to_dict``: the helper
        used by getrawtransaction / decoderawtransaction / gettransaction
        must emit BE-display txids. Pre-W41 it emitted internal LE."""
        from ouroboros.database import Transaction as DbTx
        from ouroboros.rpc import RPCServer

        # The raw 32-byte LE form. Distinct from its reverse so we can
        # tell the byte-orderings apart.
        le_bytes = bytes.fromhex(
            "1122334455667788990011223344556677889900112233445566778899001122"
        )
        be_hex = le_bytes[::-1].hex()
        assert le_bytes.hex() != be_hex  # asymmetric

        class _FakeTx:
            def __init__(self):
                self.version = 2
                self.locktime = 0
                self.inputs = []
                self.outputs = []
                self.has_witness = False

            def get_txid(self):
                return le_bytes

            def get_wtxid(self):
                return le_bytes

            def get_weight(self):
                return 0

            def get_vsize(self):
                return 0

            def serialize(self):
                return b""

        rpc = RPCServer.__new__(RPCServer)
        result = rpc._tx_to_dict(_FakeTx())  # type: ignore[arg-type]
        assert result["txid"] == be_hex, (
            "_tx_to_dict must emit txid in display order (W41 audit)."
        )
        assert result["hash"] == be_hex
