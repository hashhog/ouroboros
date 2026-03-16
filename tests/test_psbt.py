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
import pytest

from ouroboros.psbt import (
    PSBT,
    PSBTInput,
    PSBTOutput,
    KeyOriginInfo,
    PSBT_MAGIC,
    PSBT_VERSION_0,
    PSBT_VERSION_2,
    createpsbt,
    combinepsbt,
    finalizepsbt,
    decodepsbt,
    analyzepsbt,
    joinpsbts,
    _write_compact_size,
    _read_compact_size,
    _serialize_unsigned_tx,
)
from ouroboros.database import Transaction, TxIn, TxOut
import io


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
        for n in [0x10000, 0xFFFFFFFF]:
            encoded = _write_compact_size(n)
            assert len(encoded) == 5
            assert encoded[0] == 0xFE
            assert _read_compact_size(io.BytesIO(encoded)) == n


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
        """Human-readable path string."""
        origin = KeyOriginInfo(
            fingerprint=bytes.fromhex("deadbeef"),
            path=[84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 1],
        )
        path_str = origin.to_string()
        assert path_str.startswith("deadbeef")
        assert "84'" in path_str
        assert "0'" in path_str
        assert "/0/1" in path_str


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

        assert "version" in decoded
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
        assert decoded["inputs"][0]["witness_utxo"]["amount"] == 0.001  # 100000 sat

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
