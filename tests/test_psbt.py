"""
Tests for PSBT (BIP174/BIP370) implementation.

Tests cover:
- PSBT serialization/deserialization (v0 and v2)
- Magic bytes and key-value encoding
- createpsbt, combinepsbt, finalizepsbt RPC functions
- decodepsbt and analyzepsbt
- PSBT input/output types
- Taproot fields
- Round-trip serialization
"""

import base64
import io

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import (
    PSBT,
    PSBT_MAGIC,
    PSBT_VERSION_0,
    PSBT_VERSION_2,
    KeyOriginInfo,
    PSBTInput,
    PSBTOutput,
    _read_compact_size,
    _write_compact_size,
    analyzepsbt,
    combinepsbt,
    createpsbt,
    decodepsbt,
    finalizepsbt,
    joinpsbts,
)


class TestCompactSize:
    """Test compact size encoding/decoding."""

    def test_single_byte(self):
        """Values < 0xFD encode as single byte."""
        for n in [0, 1, 127, 252]:
            encoded = _write_compact_size(n)
            assert len(encoded) == 1
            assert _read_compact_size(io.BytesIO(encoded)) == n

    def test_two_bytes(self):
        """Values 0xFD-0xFFFF encode with 0xFD prefix."""
        for n in [0xFD, 0xFF, 0x1000, 0xFFFF]:
            encoded = _write_compact_size(n)
            assert len(encoded) == 3
            assert encoded[0] == 0xFD
            assert _read_compact_size(io.BytesIO(encoded)) == n

    def test_four_bytes(self):
        """Values 0x10000-0xFFFFFFFF encode with 0xFE prefix."""
        # Round-trip only in-range values: _read_compact_size enforces Core's
        # serialize.h MAX_SIZE (0x02000000) range check on read.
        for n in [0x10000, 0x02000000]:
            encoded = _write_compact_size(n)
            assert len(encoded) == 5
            assert encoded[0] == 0xFE
            assert _read_compact_size(io.BytesIO(encoded)) == n

        # 0xFFFFFFFF exceeds MAX_SIZE and must be rejected on read
        # (Core serialize.h ReadCompactSize).
        with pytest.raises(ValueError, match="exceeds MAX_SIZE"):
            _read_compact_size(io.BytesIO(_write_compact_size(0xFFFFFFFF)))


class TestKeyOriginInfo:
    """Test BIP32 derivation path serialization."""

    def test_serialize_deserialize(self):
        """Round-trip serialization of key origin info."""
        origin = KeyOriginInfo(
            fingerprint=bytes.fromhex("d34db33f"),
            path=[44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 5],
        )
        serialized = origin.serialize()
        restored = KeyOriginInfo.deserialize(serialized)
        assert restored.fingerprint == origin.fingerprint
        assert restored.path == origin.path

    def test_to_string(self):
        """Human-readable path string (Core WriteHDKeypath format)."""
        origin = KeyOriginInfo(
            fingerprint=bytes.fromhex("deadbeef"),
            path=[84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 1],
        )
        path_str = origin.to_string()
        # Core util/bip32.cpp WriteHDKeypath (apostrophe=false): "m/..."
        # with 'h' hardened suffix; the fingerprint is NOT part of the path
        # string — decodepsbt emits it separately as master_fingerprint.
        assert path_str == "m/84h/0h/0h/0/1"
        assert "deadbeef" not in path_str


class TestPSBTInput:
    """Test PSBTInput serialization."""

    def test_empty_input(self):
        """Empty input serializes to empty map."""
        inp = PSBTInput()
        kv = inp.to_kv()
        assert kv == {}

    def test_witness_utxo(self):
        """Witness UTXO serialization."""
        inp = PSBTInput()
        inp.witness_utxo = (100000, bytes.fromhex("0014" + "00" * 20))
        kv = inp.to_kv()
        assert b"\x01" in kv  # WITNESS_UTXO key

        # Round-trip
        restored = PSBTInput.from_kv(kv)
        assert restored.witness_utxo is not None
        assert restored.witness_utxo[0] == 100000
        assert len(restored.witness_utxo[1]) == 22

    def test_partial_sig(self):
        """Partial signature serialization."""
        inp = PSBTInput()
        pubkey = bytes(33)
        sig = bytes(72)
        inp.partial_sigs[pubkey] = sig
        kv = inp.to_kv()

        restored = PSBTInput.from_kv(kv)
        assert pubkey in restored.partial_sigs
        assert restored.partial_sigs[pubkey] == sig

    def test_is_finalized(self):
        """Finalization detection."""
        inp = PSBTInput()
        assert not inp.is_finalized()

        inp.final_script_sig = b"\x00"
        assert inp.is_finalized()

        inp2 = PSBTInput()
        inp2.final_script_witness = [b"\x00"]
        assert inp2.is_finalized()

    def test_taproot_fields(self):
        """Taproot-specific fields."""
        inp = PSBTInput()
        inp.tap_key_sig = bytes(64)
        inp.tap_internal_key = bytes(32)
        kv = inp.to_kv()

        restored = PSBTInput.from_kv(kv)
        assert restored.tap_key_sig == inp.tap_key_sig
        assert restored.tap_internal_key == inp.tap_internal_key


class TestPSBTOutput:
    """Test PSBTOutput serialization."""

    def test_empty_output(self):
        """Empty output serializes to empty map."""
        out = PSBTOutput()
        kv = out.to_kv()
        assert kv == {}

    def test_redeem_script(self):
        """Redeem script serialization."""
        out = PSBTOutput()
        out.redeem_script = bytes.fromhex("0014" + "00" * 20)
        kv = out.to_kv()

        restored = PSBTOutput.from_kv(kv)
        assert restored.redeem_script == out.redeem_script

    def test_psbt_v2_fields(self):
        """PSBT v2 amount and script fields."""
        out = PSBTOutput()
        out.amount = 50000
        out.script = bytes.fromhex("76a914" + "00" * 20 + "88ac")
        kv = out.to_kv()

        restored = PSBTOutput.from_kv(kv)
        assert restored.amount == 50000
        assert restored.script == out.script


class TestPSBTSerialization:
    """Test full PSBT serialization."""

    def _make_simple_tx(self):
        """Create a simple transaction for testing."""
        return Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes.fromhex(
                        "0000000000000000000000000000000000000000000000000000000000000001"
                    ),
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFD,
                )
            ],
            outputs=[
                TxOut(
                    value=50000,
                    script_pubkey=bytes.fromhex("0014" + "00" * 20),
                )
            ],
        )

    def test_magic_bytes(self):
        """PSBT starts with magic bytes."""
        tx = self._make_simple_tx()
        psbt = PSBT.from_transaction(tx)
        serialized = psbt.serialize()
        assert serialized[:5] == PSBT_MAGIC

    def test_round_trip_v0(self):
        """Round-trip serialization for PSBT v0."""
        tx = self._make_simple_tx()
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_0)
        serialized = psbt.serialize()

        restored = PSBT.deserialize(serialized)
        assert restored.version == PSBT_VERSION_0
        assert restored.tx is not None
        assert len(restored.inputs) == 1
        assert len(restored.outputs) == 1

    def test_round_trip_v2(self):
        """Round-trip serialization for PSBT v2."""
        tx = self._make_simple_tx()
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_2)
        serialized = psbt.serialize()

        restored = PSBT.deserialize(serialized)
        assert restored.version == PSBT_VERSION_2
        assert restored.tx is not None
        assert len(restored.inputs) == 1
        assert len(restored.outputs) == 1

    def test_base64_encoding(self):
        """Base64 encoding/decoding."""
        tx = self._make_simple_tx()
        psbt = PSBT.from_transaction(tx)
        b64 = psbt.to_base64()

        # Valid base64
        decoded = base64.b64decode(b64)
        assert decoded[:5] == PSBT_MAGIC

        # Round-trip
        restored = PSBT.from_base64(b64)
        assert len(restored.inputs) == len(psbt.inputs)

    def test_invalid_magic(self):
        """Invalid magic bytes raise error."""
        with pytest.raises(ValueError, match="Invalid PSBT magic"):
            PSBT.deserialize(b"invalid")


class TestPSBTOperations:
    """Test PSBT combine, finalize, and extract operations."""

    def _make_psbt_with_sig(self):
        """Create a PSBT with a partial signature."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[TxOut(value=50000, script_pubkey=bytes.fromhex("0014" + "00" * 20))],
        )
        psbt = PSBT.from_transaction(tx)
        # Add witness UTXO (P2WPKH)
        psbt.inputs[0].witness_utxo = (100000, bytes.fromhex("0014" + "00" * 20))
        return psbt

    def test_combine_signatures(self):
        """Combine two PSBTs with different signatures."""
        psbt1 = self._make_psbt_with_sig()
        psbt2 = self._make_psbt_with_sig()

        pubkey1 = bytes.fromhex("02" + "11" * 32)
        pubkey2 = bytes.fromhex("02" + "22" * 32)
        sig1 = bytes(72)
        sig2 = bytes(71)

        psbt1.inputs[0].partial_sigs[pubkey1] = sig1
        psbt2.inputs[0].partial_sigs[pubkey2] = sig2

        # Combine
        psbt1.combine(psbt2)

        # Both signatures present
        assert pubkey1 in psbt1.inputs[0].partial_sigs
        assert pubkey2 in psbt1.inputs[0].partial_sigs

    def test_combine_different_tx_fails(self):
        """Combining PSBTs for different transactions fails."""
        tx1 = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        tx2 = Transaction(
            txid=bytes(32),
            version=2,
            locktime=1,  # Different locktime
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )

        psbt1 = PSBT.from_transaction(tx1)
        psbt2 = PSBT.from_transaction(tx2)

        with pytest.raises(ValueError, match="different transactions"):
            psbt1.combine(psbt2)

    def test_finalize_p2wpkh(self):
        """Finalize P2WPKH input."""
        psbt = self._make_psbt_with_sig()

        # Add signature
        pubkey = bytes.fromhex("02" + "aa" * 32)
        sig = bytes(72)
        psbt.inputs[0].partial_sigs[pubkey] = sig

        # Finalize
        psbt.finalize()

        assert psbt.inputs[0].is_finalized()
        assert psbt.inputs[0].final_script_witness is not None
        assert len(psbt.inputs[0].final_script_witness) == 2  # sig, pubkey

    def test_extract_not_finalized_fails(self):
        """Extract from non-finalized PSBT fails."""
        psbt = self._make_psbt_with_sig()

        with pytest.raises(ValueError, match="not finalized"):
            psbt.extract_transaction()


class TestRPCFunctions:
    """Test PSBT RPC helper functions."""

    def test_createpsbt(self):
        """createpsbt creates valid PSBT."""
        inputs = [{"txid": "00" * 32, "vout": 0}]
        outputs = [{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 50000}]

        # Should not raise
        try:
            psbt_b64 = createpsbt(inputs, outputs)
            # Verify it's valid base64 PSBT
            psbt = PSBT.from_base64(psbt_b64)
            assert len(psbt.inputs) == 1
            assert len(psbt.outputs) == 1
        except ImportError:
            # address module might not be available in test environment
            pytest.skip("address module not available")

    def test_combinepsbt(self):
        """combinepsbt merges PSBTs."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )

        psbt1 = PSBT.from_transaction(tx)
        psbt2 = PSBT.from_transaction(tx)

        psbt1.inputs[0].partial_sigs[b"key1"] = b"sig1"
        psbt2.inputs[0].partial_sigs[b"key2"] = b"sig2"

        combined_b64 = combinepsbt([psbt1.to_base64(), psbt2.to_base64()])
        combined = PSBT.from_base64(combined_b64)

        assert b"key1" in combined.inputs[0].partial_sigs
        assert b"key2" in combined.inputs[0].partial_sigs

    def test_combinepsbt_empty_fails(self):
        """combinepsbt with empty list fails."""
        with pytest.raises(ValueError, match="No PSBTs"):
            combinepsbt([])

    def test_finalizepsbt(self):
        """finalizepsbt returns correct structure."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)
        # Pre-finalize (add final scriptSig)
        psbt.inputs[0].final_script_sig = b"\x00"

        result = finalizepsbt(psbt.to_base64())

        assert "psbt" in result
        assert "complete" in result
        assert result["complete"] is True

    def test_decodepsbt(self):
        """decodepsbt returns human-readable dict."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=bytes(22))],
        )
        psbt = PSBT.from_transaction(tx)

        decoded = decodepsbt(psbt.to_base64())

        # Core decodepsbt top level has "psbt_version" (there is no
        # "version" key; the tx version lives under decoded["tx"]).
        assert "psbt_version" in decoded
        assert "tx" in decoded
        assert "inputs" in decoded
        assert "outputs" in decoded

    def test_analyzepsbt(self):
        """analyzepsbt returns analysis."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)

        analysis = analyzepsbt(psbt.to_base64())

        assert "inputs" in analysis
        assert "next" in analysis
        assert analysis["next"] == "updater"  # No UTXO info yet

    def test_joinpsbts(self):
        """joinpsbts combines multiple PSBTs."""
        tx1 = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        tx2 = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=30000, script_pubkey=b"")],
        )

        psbt1 = PSBT.from_transaction(tx1)
        psbt2 = PSBT.from_transaction(tx2)

        joined_b64 = joinpsbts([psbt1.to_base64(), psbt2.to_base64()])
        joined = PSBT.from_base64(joined_b64)

        assert len(joined.inputs) == 2
        assert len(joined.outputs) == 2


class TestPSBTDecoding:
    """Test decoding of various PSBT structures."""

    def test_decode_with_witness_utxo(self):
        """Decode PSBT with witness UTXO info."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=bytes.fromhex("0014" + "00" * 20))],
        )
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].witness_utxo = (100000, bytes.fromhex("0014" + "00" * 20))

        decoded = psbt.decode()
        assert "witness_utxo" in decoded["inputs"][0]
        # Amount is a BTCAmount sentinel that serializes as Core's fixed
        # %d.%08d decimal (core_io.cpp ValueFromAmount), not a float.
        amount = decoded["inputs"][0]["witness_utxo"]["amount"]
        assert amount.text == "0.00100000"  # 100000 sat

    def test_decode_with_bip32_derivs(self):
        """Decode PSBT with BIP32 derivation paths."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)
        pubkey = bytes.fromhex("02" + "aa" * 32)
        origin = KeyOriginInfo(
            fingerprint=bytes.fromhex("deadbeef"),
            path=[84 | 0x80000000, 0, 0],
        )
        psbt.inputs[0].bip32_derivations[pubkey] = origin

        decoded = psbt.decode()
        assert "bip32_derivs" in decoded["inputs"][0]
        assert len(decoded["inputs"][0]["bip32_derivs"]) == 1


class TestPSBTV2:
    """Test PSBT v2 (BIP370) specific functionality."""

    def test_v2_global_fields(self):
        """PSBT v2 has separate global fields."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=500000,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_2)

        assert psbt.tx_version == 2
        assert psbt.fallback_locktime == 500000
        assert psbt.input_count == 1
        assert psbt.output_count == 1

    def test_v2_per_input_fields(self):
        """PSBT v2 stores txid/vout per-input."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes.fromhex("01" * 32),
                    prev_vout=5,
                    script_sig=b"",
                    sequence=0xFFFFFFFD,
                )
            ],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_2)

        assert psbt.inputs[0].previous_txid == bytes.fromhex("01" * 32)
        assert psbt.inputs[0].output_index == 5
        assert psbt.inputs[0].sequence == 0xFFFFFFFD

    def test_v2_per_output_fields(self):
        """PSBT v2 stores amount/script per-output."""
        script = bytes.fromhex("76a914" + "00" * 20 + "88ac")
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=12345, script_pubkey=script)],
        )
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_2)

        assert psbt.outputs[0].amount == 12345
        assert psbt.outputs[0].script == script

    def test_v2_reconstruct_tx(self):
        """PSBT v2 can reconstruct transaction from per-input/output fields."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=100,
            inputs=[
                TxIn(
                    prev_txid=bytes.fromhex("aa" * 32),
                    prev_vout=3,
                    script_sig=b"",
                    sequence=0xFFFFFFFE,
                )
            ],
            outputs=[TxOut(value=99999, script_pubkey=bytes.fromhex("0014" + "bb" * 20))],
        )
        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_2)

        # Serialize and deserialize
        restored = PSBT.deserialize(psbt.serialize())

        # Transaction should be reconstructed
        assert restored.tx is not None
        assert restored.tx.version == 2
        assert restored.tx.locktime == 100
        assert restored.tx.inputs[0].prev_txid == bytes.fromhex("aa" * 32)
        assert restored.tx.inputs[0].prev_vout == 3
        assert restored.tx.outputs[0].value == 99999


class TestPSBTUtilityMethods:
    """Test PSBT utility methods."""

    def test_add_input(self):
        """add_input adds a new input."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)

        idx = psbt.add_input("ff" * 32, 2)
        assert idx == 0
        assert len(psbt.inputs) == 1
        assert psbt.tx.inputs[0].prev_vout == 2

    def test_add_output(self):
        """add_output adds a new output."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[],
        )
        psbt = PSBT.from_transaction(tx)

        script = bytes.fromhex("0014" + "00" * 20)
        idx = psbt.add_output(script, 25000)
        assert idx == 0
        assert len(psbt.outputs) == 1
        assert psbt.tx.outputs[0].value == 25000

    def test_set_witness_utxo(self):
        """set_witness_utxo updates input."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)

        script = bytes.fromhex("0014" + "aa" * 20)
        psbt.set_witness_utxo(0, 100000, script)

        assert psbt.inputs[0].witness_utxo == (100000, script)

    def test_count_unsigned_inputs(self):
        """count_unsigned_inputs returns correct count."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0),
                TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0),
            ],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)

        assert psbt.count_unsigned_inputs() == 2

        # Finalize one input
        psbt.inputs[0].final_script_sig = b"\x00"
        assert psbt.count_unsigned_inputs() == 1


class TestTaprootPSBT:
    """Test Taproot-specific PSBT functionality."""

    def test_tap_key_sig(self):
        """Taproot key path signature."""
        inp = PSBTInput()
        inp.tap_key_sig = bytes(64)

        kv = inp.to_kv()
        restored = PSBTInput.from_kv(kv)

        assert restored.tap_key_sig == inp.tap_key_sig

    def test_tap_internal_key(self):
        """Taproot internal key."""
        inp = PSBTInput()
        inp.tap_internal_key = bytes(32)

        kv = inp.to_kv()
        restored = PSBTInput.from_kv(kv)

        assert restored.tap_internal_key == inp.tap_internal_key

    def test_finalize_taproot_key_path(self):
        """Finalize Taproot key path spend."""
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50000, script_pubkey=b"")],
        )
        psbt = PSBT.from_transaction(tx)

        # Set up as Taproot (P2TR script)
        psbt.inputs[0].witness_utxo = (100000, bytes.fromhex("5120" + "aa" * 32))
        psbt.inputs[0].tap_key_sig = bytes(64)

        psbt.finalize()

        assert psbt.inputs[0].is_finalized()
        assert psbt.inputs[0].final_script_witness == [bytes(64)]


class TestPreimageFields:
    """Test PSBT preimage fields (RIPEMD160, SHA256, HASH160, HASH256)."""

    def test_sha256_preimage(self):
        """SHA256 preimage storage and retrieval."""
        inp = PSBTInput()
        preimage = b"secret preimage data"
        import hashlib
        hash_val = hashlib.sha256(preimage).digest()

        inp.sha256_preimages[hash_val] = preimage

        kv = inp.to_kv()
        restored = PSBTInput.from_kv(kv)

        assert hash_val in restored.sha256_preimages
        assert restored.sha256_preimages[hash_val] == preimage

    def test_hash160_preimage(self):
        """HASH160 preimage storage and retrieval."""
        inp = PSBTInput()
        preimage = b"another secret"
        import hashlib
        hash_val = hashlib.new(
            "ripemd160", hashlib.sha256(preimage).digest()
        ).digest()

        inp.hash160_preimages[hash_val] = preimage

        kv = inp.to_kv()
        restored = PSBTInput.from_kv(kv)

        assert hash_val in restored.hash160_preimages
        assert restored.hash160_preimages[hash_val] == preimage


class TestBIP174Strictness:
    """W34-D: BIP-174 conformance — EOF strictness, key ordering, segwit marker."""

    def _make_minimal_psbt(self) -> PSBT:
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0)],
            outputs=[TxOut(value=50_000, script_pubkey=b"\x00\x14" + bytes(20))],
        )
        return PSBT.from_transaction(tx)

    def test_eof_without_separator_raises(self):
        """A PSBT truncated before its trailing 0x00 separator must be rejected.

        BIP-174 mandates the separator at the end of every map (global,
        per-input, per-output). Bitcoin Core throws ios_base::failure
        ("Separator is missing at the end of an input map"). We surface
        a ValueError with a clear message.
        """
        psbt = self._make_minimal_psbt()
        # Add an unknown key so the global map is non-empty and we can drop
        # the trailing separator without making the stream syntactically
        # ambiguous in some other way.
        psbt.unknown_global[b"\xfc\x09unknownkey"] = b"unknownval"

        raw = psbt.serialize()
        # Last byte of any well-formed PSBT is the final 0x00 separator
        # (the tail map's terminator). Drop it.
        assert raw[-1:] == b"\x00"
        truncated = raw[:-1]

        with pytest.raises(ValueError, match="missing trailing 0x00 separator"):
            PSBT.deserialize(truncated)

    def test_lexicographic_key_ordering(self):
        """Serializer must sort map keys ascending by raw bytes.

        Build a PSBT with multiple unknown-global keys inserted in
        non-sorted order, serialize, and assert the on-the-wire key
        order is ascending. Then round-trip and assert byte-identity.
        """
        psbt = self._make_minimal_psbt()
        # Insertion order: zz, aa, mm — must come out aa, mm, zz.
        psbt.unknown_global[b"\xfc\x02zz"] = b"v_zz"
        psbt.unknown_global[b"\xfc\x02aa"] = b"v_aa"
        psbt.unknown_global[b"\xfc\x02mm"] = b"v_mm"

        raw = psbt.serialize()

        # Assert the three unknown-global keys appear in ascending byte order
        # by checking offsets. (Each key is 4 bytes incl. proprietary prefix
        # \xfc + len + name — but we just check substring positions of the
        # 2-byte name fragments.)
        i_aa = raw.find(b"\xfc\x02aa")
        i_mm = raw.find(b"\xfc\x02mm")
        i_zz = raw.find(b"\xfc\x02zz")
        assert i_aa != -1 and i_mm != -1 and i_zz != -1
        assert i_aa < i_mm < i_zz, (
            f"keys not in ascending order: aa={i_aa}, mm={i_mm}, zz={i_zz}"
        )

        # Round-trip + re-serialize: deserialize-then-serialize must be
        # byte-identical, because both passes apply the same canonical
        # ordering. This is the property third-party PSBTs depend on.
        restored = PSBT.deserialize(raw)
        assert restored.serialize() == raw

    def test_unsigned_tx_no_segwit_marker(self):
        """Global UNSIGNED_TX MUST NOT carry the segwit \\x00\\x01 marker/flag.

        BIP-174: "The transaction must be in the old serialization format
        (without witnesses)." Even if the wallet has witness data on the
        inputs, the global UNSIGNED_TX bytes must serialize without the
        marker (0x00) + flag (0x01) bytes that follow the version field
        in BIP-141 segwit serialization.
        """
        # Build a witness input on an actual P2WPKH-spending tx
        witness_inp = TxIn(
            prev_txid=bytes(32), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFF
        )
        # Tag witness data on the input (mirrors how the wallet primes it)
        witness_inp.witness = [b"\x30" * 71, b"\x02" + b"\x33" * 32]

        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[witness_inp],
            outputs=[TxOut(value=10_000, script_pubkey=b"\x00\x14" + bytes(20))],
        )
        psbt = PSBT.from_transaction(tx)

        raw = psbt.serialize()

        # Decode the global map and inspect the UNSIGNED_TX value
        # directly — this is the authoritative bytes that go on the wire.
        f = io.BytesIO(raw)
        magic = f.read(5)
        assert magic == PSBT_MAGIC
        from ouroboros.psbt import _read_kv_pairs, PSBTGlobalType
        global_kv = _read_kv_pairs(f)
        unsigned_tx_bytes = global_kv[bytes([PSBTGlobalType.UNSIGNED_TX])]

        # Layout: <version: 4 LE> then either compactsize(num_inputs) for
        # legacy, or 0x00 0x01 (marker || flag) for BIP-141 segwit. The
        # legal PSBT shape is the legacy one — bytes 4..6 must NOT be
        # \x00\x01.
        assert len(unsigned_tx_bytes) >= 6
        marker_flag = unsigned_tx_bytes[4:6]
        assert marker_flag != b"\x00\x01", (
            f"PSBT UNSIGNED_TX leaked segwit marker/flag: {marker_flag.hex()}"
        )
        # Positive-shape sanity: byte 4 should be the compactsize for
        # num_inputs (== 1), so 0x01.
        assert unsigned_tx_bytes[4] == 0x01


class TestW43MultisigFinalize:
    """W43 regression tests: legacy P2SH-multisig finalize and
    bare-P2WSH multisig sig ordering by witnessScript pubkey order
    (NOT pubkey-byte sort).

    The bug class this guards: CHECKMULTISIG is order-sensitive — sigs
    must appear in the witness/scriptSig in the same order as the
    matching pubkeys appear in the redeemScript / witnessScript.
    Bitcoin Core's ProduceSignature emits this order (sign.cpp,
    GetMultisigSigner). Ouroboros previously emitted by
    ``sorted(partial_sigs.keys())``, which is correct ONLY by
    coincidence and silently produced rejected scripts otherwise.
    """

    def _build_multisig_script(self, m: int, pubkeys: list[bytes]) -> bytes:
        """Build a bare ``OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG``."""
        assert 1 <= m <= 16 and 1 <= len(pubkeys) <= 16
        out = bytearray()
        out.append(0x50 + m)  # OP_M
        for pk in pubkeys:
            assert len(pk) in (33, 65)
            out.append(len(pk))
            out.extend(pk)
        out.append(0x50 + len(pubkeys))  # OP_N
        out.append(0xAE)  # OP_CHECKMULTISIG
        return bytes(out)

    def _make_unsigned_psbt(self) -> PSBT:
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[TxOut(value=50000, script_pubkey=bytes.fromhex("0014" + "00" * 20))],
        )
        return PSBT.from_transaction(tx)

    # Two distinct compressed pubkey shapes whose lex ordering does NOT
    # match the script-pubkey order we hand to the redeemScript. We
    # deliberately put pkB (lex-larger) first in the script so that
    # ``sorted(partial_sigs.keys())`` would emit (pkA, pkB) — the wrong
    # order — and the W43 fix walks (pkB, pkA) instead.
    PK_A = bytes.fromhex("02" + "11" * 32)  # lex-smaller
    PK_B = bytes.fromhex("03" + "ee" * 32)  # lex-larger
    SIG_A = b"\xa1" * 71 + b"\x01"  # mock DER + sighash
    SIG_B = b"\xb2" * 72 + b"\x01"

    def test_legacy_p2sh_multisig_finalize_script_order(self):
        """W43 fix #1: legacy P2SH 2-of-2 finalize emits OP_0 + sig(pkB) +
        sig(pkA) + push(redeemScript), where redeemScript declares pkB
        before pkA. partial_sigs are inserted in REVERSE script order
        (pkA first then pkB) to ensure the finalizer cannot accidentally
        pass via insertion order.
        """
        from ouroboros.wallet import _hash160

        # redeemScript declares pkB BEFORE pkA — so script order is [pkB, pkA].
        redeem_script = self._build_multisig_script(2, [self.PK_B, self.PK_A])
        h160 = _hash160(redeem_script)
        spk_p2sh = b"\xa9\x14" + h160 + b"\x87"  # OP_HASH160 <h160> OP_EQUAL

        psbt = self._make_unsigned_psbt()
        psbt.inputs[0].redeem_script = redeem_script
        psbt.inputs[0].witness_utxo = (100000, spk_p2sh)
        # Insert in reverse pubkey-script order to defeat insertion-order
        # finalizers. Insert pkA first, then pkB.
        psbt.inputs[0].partial_sigs[self.PK_A] = self.SIG_A
        psbt.inputs[0].partial_sigs[self.PK_B] = self.SIG_B

        psbt.finalize()
        inp = psbt.inputs[0]
        assert inp.is_finalized(), "legacy P2SH-multisig must finalize"
        assert inp.final_script_sig is not None and len(inp.final_script_sig) > 0
        # Witness must be empty/None for non-segwit P2SH.
        assert inp.final_script_witness is None or inp.final_script_witness == []

        # Walk the scriptSig: OP_0 then push(SIG_B) then push(SIG_A) then
        # push(redeemScript). Sigs must appear in script-pubkey order.
        ss = inp.final_script_sig
        assert ss[0] == 0x00, f"first byte must be OP_0, got 0x{ss[0]:02x}"
        # Expected layout: 0x00 || len(SIG_B) || SIG_B || len(SIG_A) || SIG_A
        # || push(redeem_script). All sigs are 72/73 bytes => single-byte
        # length prefix (< 0x4c).
        i = 1
        assert ss[i] == len(self.SIG_B)
        i += 1
        assert ss[i : i + len(self.SIG_B)] == self.SIG_B, (
            "sig for pkB must come FIRST (script-pubkey order)"
        )
        i += len(self.SIG_B)
        assert ss[i] == len(self.SIG_A)
        i += 1
        assert ss[i : i + len(self.SIG_A)] == self.SIG_A
        i += len(self.SIG_A)
        # Followed by push of redeemScript. redeem_script is 71 bytes
        # (1 OP_M + 2*(1+33) + 1 OP_N + 1 OP_CHECKMULTISIG = 71), so
        # single-byte push prefix.
        assert ss[i] == len(redeem_script)
        i += 1
        assert ss[i : i + len(redeem_script)] == redeem_script
        assert i + len(redeem_script) == len(ss), "no trailing junk"

        # And non-final fields must be cleared (W41 cleanup shape).
        assert inp.partial_sigs == {}
        assert inp.redeem_script is None

    def test_bare_p2wsh_multisig_finalize_script_order(self):
        """W43 fix #2: bare P2WSH 2-of-2 finalize emits witness stack
        [OP_0, sig(pkB), sig(pkA), witnessScript] where the witnessScript
        declares pkB before pkA. Previously ouroboros walked
        ``sorted(partial_sigs.keys())`` which would emit (pkA, pkB) — the
        wrong order — and Core would reject the broadcast.
        """
        import hashlib

        witness_script = self._build_multisig_script(2, [self.PK_B, self.PK_A])
        ws_hash = hashlib.sha256(witness_script).digest()
        spk_p2wsh = b"\x00\x20" + ws_hash  # OP_0 <32 bytes>

        psbt = self._make_unsigned_psbt()
        psbt.inputs[0].witness_script = witness_script
        psbt.inputs[0].witness_utxo = (100000, spk_p2wsh)
        # Reverse insertion order again.
        psbt.inputs[0].partial_sigs[self.PK_A] = self.SIG_A
        psbt.inputs[0].partial_sigs[self.PK_B] = self.SIG_B

        psbt.finalize()
        inp = psbt.inputs[0]
        assert inp.is_finalized(), "bare P2WSH multisig must finalize"
        assert inp.final_script_sig == b""
        assert inp.final_script_witness is not None
        wit = inp.final_script_witness
        # Stack: [OP_0_dummy, sig_pkB, sig_pkA, witnessScript]
        assert len(wit) == 4, f"expected 4-element witness stack, got {len(wit)}: {wit}"
        assert wit[0] == b"", "first witness item must be empty (CHECKMULTISIG dummy)"
        assert wit[1] == self.SIG_B, (
            "sig for pkB must come FIRST (witnessScript pubkey order, NOT byte sort)"
        )
        assert wit[2] == self.SIG_A
        assert wit[3] == witness_script

        # Non-final fields cleared.
        assert inp.partial_sigs == {}
        assert inp.witness_script is None

    def test_legacy_p2sh_multisig_insufficient_sigs_does_not_finalize(self):
        """W43: with M=2 and only 1 partial sig, finalize must NOT
        emit a final_script_sig — guards against the new branch
        accidentally producing an under-signed scriptSig.
        """
        from ouroboros.wallet import _hash160

        redeem_script = self._build_multisig_script(2, [self.PK_B, self.PK_A])
        h160 = _hash160(redeem_script)
        spk_p2sh = b"\xa9\x14" + h160 + b"\x87"

        psbt = self._make_unsigned_psbt()
        psbt.inputs[0].redeem_script = redeem_script
        psbt.inputs[0].witness_utxo = (100000, spk_p2sh)
        psbt.inputs[0].partial_sigs[self.PK_A] = self.SIG_A  # only one

        psbt.finalize()
        inp = psbt.inputs[0]
        assert not inp.is_finalized()
        assert inp.final_script_sig is None or inp.final_script_sig == b""


class TestW46PartialSigsCanonicalOrder:
    """W46 regression tests: combinepsbt must produce byte-identical
    output regardless of insertion order of ``partial_sigs``.

    Bitcoin Core stores ``partial_sigs`` in
    ``std::map<CKeyID, SigPair>`` (psbt.h:270); the per-input serializer
    walks that map in key order, i.e. sorted by ``HASH160(pubkey)``.
    Ouroboros previously sorted on emit by raw wire-key (= pubkey
    bytes), which produced a stable but Core-incompatible order for
    multi-sig partial-sig sets whose pubkey lex-order differs from
    their HASH160 lex-order. That is the W43-3 follow-up "T2 DIVERGE"
    on ``tools/psbt-multi-input-test.sh`` (W42-A diagnostic).
    """

    # Two compressed pubkeys whose HASH160 ordering is the OPPOSITE of
    # their raw-bytes ordering. We pre-computed these by brute-forcing
    # the second-byte ramp until the order flipped — required so the
    # test is meaningful: a fixture where raw-sort happens to agree
    # with HASH160-sort would silently pass under both the old AND new
    # serializer.
    #
    # PK_LEX_LO is lex-smaller than PK_LEX_HI as raw bytes, but
    # HASH160(PK_LEX_LO) > HASH160(PK_LEX_HI). The W46 fix MUST emit
    # PK_LEX_HI's PARTIAL_SIG entry first.
    # Constants chosen by brute-force search over (0x02 || i, 0x03 || j)
    # to guarantee raw_lex_order(PK_LO, PK_HI) is INVERTED relative to
    # h160_order(PK_LO, PK_HI). With these:
    #   h160(PK_LEX_LO) = e01b06b9dce4b03b169c1e9c9d59d7907b2b6e5b
    #   h160(PK_LEX_HI) = 429d7e0ec4135a738ae573c85de9c9b4385688e8
    # PK_LEX_LO < PK_LEX_HI raw, but h160(PK_LEX_LO) > h160(PK_LEX_HI).
    PK_LEX_LO = bytes.fromhex(
        "020000000000000000000000000000000000000000000000000000000000000001"
    )
    PK_LEX_HI = bytes.fromhex(
        "030000000000000000000000000000000000000000000000000000000000000003"
    )
    SIG_LO = b"\x30" + b"\xaa" * 70 + b"\x01"  # mock DER + sighash
    SIG_HI = b"\x30" + b"\xbb" * 70 + b"\x01"

    def _make_unsigned_psbt(self) -> PSBT:
        tx = Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=bytes(32),
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[TxOut(value=50000, script_pubkey=bytes.fromhex("0014" + "00" * 20))],
        )
        return PSBT.from_transaction(tx)

    def test_pubkeys_have_inverted_hash160_order(self):
        """Sanity check: the chosen pubkeys actually exercise the bug.

        If raw-sort and HASH160-sort happen to agree, the regression
        test below is vacuous. Force the assumption to fail loudly if
        the constants ever drift.
        """
        import hashlib

        def h160(pk: bytes) -> bytes:
            return hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()

        assert self.PK_LEX_LO < self.PK_LEX_HI, "raw-byte order assumption"
        assert h160(self.PK_LEX_LO) > h160(self.PK_LEX_HI), (
            "HASH160 order must invert raw-byte order for this test to "
            "exercise the W46 fix; chosen constants do not. Pick new keys."
        )

    def test_combinepsbt_byte_identity_regardless_of_insertion_order(self):
        """W46 fix: two PSBTs that differ only in ``partial_sigs``
        insertion order, then combined, MUST serialize to identical
        bytes. This is the property Bitcoin Core gets for free from
        ``std::map<CKeyID, SigPair>``.
        """
        # PSBT_A: insert LO first, then HI.
        psbt_a1 = self._make_unsigned_psbt()
        psbt_a1.inputs[0].partial_sigs[self.PK_LEX_LO] = self.SIG_LO
        psbt_a2 = self._make_unsigned_psbt()
        psbt_a2.inputs[0].partial_sigs[self.PK_LEX_HI] = self.SIG_HI
        combined_a_b64 = combinepsbt([psbt_a1.to_base64(), psbt_a2.to_base64()])

        # PSBT_B: insert HI first, then LO. Same two sigs, opposite
        # combine order.
        psbt_b1 = self._make_unsigned_psbt()
        psbt_b1.inputs[0].partial_sigs[self.PK_LEX_HI] = self.SIG_HI
        psbt_b2 = self._make_unsigned_psbt()
        psbt_b2.inputs[0].partial_sigs[self.PK_LEX_LO] = self.SIG_LO
        combined_b_b64 = combinepsbt([psbt_b1.to_base64(), psbt_b2.to_base64()])

        assert combined_a_b64 == combined_b_b64, (
            "combinepsbt is non-deterministic under partial_sigs "
            "insertion-order permutation — W46 fix did not land."
        )

    def test_partial_sigs_emitted_in_hash160_order_not_raw_order(self):
        """Stronger property than byte-identity: the ON-WIRE order of
        PARTIAL_SIG entries MUST be HASH160(pubkey) ascending, NOT raw
        pubkey ascending. Decodes the serialized bytes and checks the
        physical layout.
        """
        import hashlib
        from ouroboros.psbt import (
            PSBT_MAGIC,
            PSBTInputType,
            _read_compact_size,
            _read_kv_pairs,
        )

        def h160(pk: bytes) -> bytes:
            return hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()

        psbt = self._make_unsigned_psbt()
        # Insert LO first to defeat insertion-order emission.
        psbt.inputs[0].partial_sigs[self.PK_LEX_LO] = self.SIG_LO
        psbt.inputs[0].partial_sigs[self.PK_LEX_HI] = self.SIG_HI

        raw = psbt.serialize()

        # Skip magic + global map.
        f = io.BytesIO(raw)
        assert f.read(5) == PSBT_MAGIC
        _ = _read_kv_pairs(f)  # global

        # Read the per-input map manually so we observe byte order, not
        # dict iteration order.
        partial_sig_keys_in_wire_order: list[bytes] = []
        while True:
            kl_byte = f.read(1)
            assert kl_byte, "truncated PSBT"
            if kl_byte == b"\x00":
                break
            f.seek(f.tell() - 1)
            kl = _read_compact_size(f)
            key = f.read(kl)
            vl = _read_compact_size(f)
            _ = f.read(vl)
            if key and key[0] == PSBTInputType.PARTIAL_SIG:
                partial_sig_keys_in_wire_order.append(key[1:])

        assert len(partial_sig_keys_in_wire_order) == 2, (
            f"expected 2 partial_sigs on the wire, got "
            f"{len(partial_sig_keys_in_wire_order)}"
        )
        # HI's HASH160 < LO's HASH160 (verified above), so HI must
        # appear FIRST on the wire under the W46 fix. Under the old
        # raw-sort behavior, LO came first.
        assert partial_sig_keys_in_wire_order[0] == self.PK_LEX_HI, (
            "first PARTIAL_SIG on the wire must be the pubkey with the "
            "smaller HASH160 (Core's std::map<CKeyID, SigPair> order)"
        )
        assert partial_sig_keys_in_wire_order[1] == self.PK_LEX_LO

        # Belt-and-braces: the wire order matches sort-by-HASH160.
        sorted_by_hash160 = sorted(
            partial_sig_keys_in_wire_order, key=h160
        )
        assert partial_sig_keys_in_wire_order == sorted_by_hash160

    def test_combinepsbt_round_trips_through_decode(self):
        """The combined PSBT must still parse cleanly. Guards against
        the fix accidentally corrupting the wire format (e.g. wrong
        compactsize length, mis-emitted separator).
        """
        psbt1 = self._make_unsigned_psbt()
        psbt1.inputs[0].partial_sigs[self.PK_LEX_LO] = self.SIG_LO
        psbt2 = self._make_unsigned_psbt()
        psbt2.inputs[0].partial_sigs[self.PK_LEX_HI] = self.SIG_HI

        combined_b64 = combinepsbt([psbt1.to_base64(), psbt2.to_base64()])
        combined = PSBT.from_base64(combined_b64)

        assert self.PK_LEX_LO in combined.inputs[0].partial_sigs
        assert self.PK_LEX_HI in combined.inputs[0].partial_sigs
        assert combined.inputs[0].partial_sigs[self.PK_LEX_LO] == self.SIG_LO
        assert combined.inputs[0].partial_sigs[self.PK_LEX_HI] == self.SIG_HI
