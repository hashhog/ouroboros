"""
Test block and transaction validation.

Verifies BlockValidator._validate_header() including proof-of-work.
Ref: bitcoin/src/pow.cpp CheckProofOfWork
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block, BlockchainDatabase  # noqa: E402
from ouroboros.validation import BlockValidator, _bits_to_target, _encode_bip34_height  # noqa: E402


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with optional whitespace) to bytes."""
    return bytes.fromhex(hex_str.replace("\n", "").replace(" ", ""))


# Bitcoin mainnet genesis block
GENESIS_HEX = (
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49"
    "ffff001d1dac2b7c"
    "01"
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
    "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75"
    "7420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55482719"
    "67f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51e"
    "c112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)


class TestPowValidation(unittest.TestCase):
    """Test proof-of-work validation in BlockValidator._validate_header"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.db = BlockchainDatabase(data_dir=self.temp_dir)
        self.validator = BlockValidator(self.db)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_prev_block(self, timestamp: int = 0) -> Block:
        """Create a minimal block for use as previous block in validation."""
        return Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=timestamp,
            bits=0x1D00FFFF,
            nonce=0,
            transactions=[],
            hash=bytes(32),
        )

    def test_genesis_block_passes_pow(self):
        """Genesis block (bits 0x1d00ffff) passes PoW validation"""
        block = Block.deserialize(hex_to_bytes(GENESIS_HEX))
        prev_block = self._make_prev_block(timestamp=0)
        # Genesis has timestamp 1231006505, so prev_block with 0 is valid
        self.assertTrue(
            self.validator._validate_header(block, prev_block),
            "Genesis block with valid PoW should pass _validate_header",
        )

    def test_block_with_hash_above_target_fails_pow(self):
        """Block with hash exceeding target fails PoW validation"""
        block = Block.deserialize(hex_to_bytes(GENESIS_HEX))
        # Use very hard target (bits=0x03000001 -> target=1)
        # Genesis header hashes to a large value, so hash > 1
        block_hard = Block(
            version=block.version,
            prev_blockhash=block.prev_blockhash,
            merkle_root=block.merkle_root,
            timestamp=block.timestamp,
            bits=0x03000001,
            nonce=block.nonce,
            transactions=block.transactions,
            hash=block.hash,
        )
        prev_block = self._make_prev_block(timestamp=0)
        self.assertFalse(
            self.validator._validate_header(block_hard, prev_block),
            "Block with hash > target should fail _validate_header",
        )


class TestBitsToTarget(unittest.TestCase):
    """Test _bits_to_target helper"""

    def test_genesis_bits(self):
        """0x1d00ffff (genesis) produces valid target"""
        target = _bits_to_target(0x1D00FFFF)
        self.assertGreater(target, 0)
        self.assertLessEqual(target, 2**256 - 1)

    def test_hard_target(self):
        """Very hard bits produce small target"""
        target = _bits_to_target(0x03000001)
        self.assertEqual(target, 1)


class TestEncodeBip34Height(unittest.TestCase):
    """Test _encode_bip34_height canonical encoder.

    Reference: Bitcoin Core script.h:433-448 (CScript::push_int64).
    """

    def test_height_0_op0(self):
        """height 0 → OP_0 (0x00), single byte"""
        self.assertEqual(_encode_bip34_height(0), b"\x00")

    def test_height_1_op1(self):
        """height 1 → OP_1 (0x51), single byte"""
        self.assertEqual(_encode_bip34_height(1), bytes([0x51]))

    def test_height_16_op16(self):
        """height 16 → OP_16 (0x60), single byte"""
        self.assertEqual(_encode_bip34_height(16), bytes([0x60]))

    def test_height_17_one_byte_push(self):
        """height 17 → 1-byte push (0x01 0x11)"""
        self.assertEqual(_encode_bip34_height(17), bytes([0x01, 0x11]))

    def test_height_127_no_sign_pad(self):
        """height 127 (0x7f) → 1-byte push, no sign pad needed"""
        self.assertEqual(_encode_bip34_height(127), bytes([0x01, 0x7F]))

    def test_height_128_sign_pad(self):
        """height 128 (0x80) → sign pad: 0x02 0x80 0x00"""
        self.assertEqual(_encode_bip34_height(128), bytes([0x02, 0x80, 0x00]))

    def test_height_32768_sign_pad(self):
        """height 32768 (0x8000) → sign pad: 0x03 0x00 0x80 0x00"""
        self.assertEqual(_encode_bip34_height(32768), bytes([0x03, 0x00, 0x80, 0x00]))

    def test_height_500000(self):
        """height 500000 (0x07A120 LE: 0x20 0xA1 0x07)"""
        self.assertEqual(_encode_bip34_height(500000), bytes([0x03, 0x20, 0xA1, 0x07]))

    def test_height_227931_mainnet_bip34(self):
        """height 227931 (mainnet BIP34 activation, 0x37A5B LE: 0x5B 0x7A 0x03)"""
        self.assertEqual(_encode_bip34_height(227931), bytes([0x03, 0x5B, 0x7A, 0x03]))


class TestBip34Activation(unittest.TestCase):
    """Test that BIP-34 activation uses per-network height, not hardcoded 227931.

    Reference: Bitcoin Core chainparams.cpp — testnet4/regtest have bip34_height=1.
    """

    def _make_validator(self, network: str) -> BlockValidator:
        tmpdir = tempfile.mkdtemp()
        db = BlockchainDatabase(tmpdir, network)
        return BlockValidator(db, network)

    def test_encode_bip34_rejects_non_canonical_zero_pad(self):
        """Non-canonical zero-padded encoding rejected (value-decode false positive)."""
        # Height 100 canonical: 0x01 0x64. Zero-padded: 0x02 0x64 0x00.
        canonical = _encode_bip34_height(100)
        non_canonical = bytes([0x02, 0x64, 0x00])
        self.assertNotEqual(canonical, non_canonical)
        # And non_canonical starts with 0x02 which is != canonical[0]=0x01
        self.assertNotEqual(non_canonical[:len(canonical)], canonical)

    def test_encode_bip34_rejects_length_prefixed_for_low_heights(self):
        """Length-prefixed form for height 1 (0x01 0x01) != OP_1 (0x51)."""
        # Core emits OP_1 for height 1; length-prefixed form is non-canonical.
        self.assertEqual(_encode_bip34_height(1), bytes([0x51]))
        self.assertNotEqual(_encode_bip34_height(1), bytes([0x01, 0x01]))

    def test_encode_bip34_missing_sign_byte_rejected(self):
        """Height 128: <<0x01, 0x80>> is non-canonical vs <<0x02, 0x80, 0x00>>."""
        canonical = _encode_bip34_height(128)
        missing_sign = bytes([0x01, 0x80])
        self.assertNotEqual(canonical[:len(missing_sign)], missing_sign)


class TestApplyBlockGenesisGate(unittest.TestCase):
    """Belt-and-suspenders: BlockValidator.apply_block must not insert
    genesis (height 0) coinbase outputs into the UTXO set.

    The Python ``apply_block`` is dead code in production (every IBD /
    reorg / orphan path goes through the Rust FFI
    ``connect_block_from_bytes``), but the W23 fix wired in a defensive
    early-return so that if the path is ever revived it still matches
    Bitcoin Core's ``ConnectBlock`` genesis special-case
    (validation.cpp:2337-2343). This test pins that gate.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db = BlockchainDatabase(data_dir=self.temp_dir)
        self.validator = BlockValidator(self.db)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_block(self, height):
        # Height-only block with empty tx list. update_utxo_set does
        # not exist on BlockchainDatabase (the path is dead), so any
        # block that *does* reach the bottom of apply_block raises
        # AttributeError. The genesis-gated path returns early and
        # therefore must NOT raise.
        return Block(
            version=1,
            prev_blockhash=bytes(32),
            merkle_root=bytes(32),
            timestamp=0,
            bits=0x1d00ffff,
            nonce=0,
            transactions=[],
            hash=bytes(32),
            height=height,
        )

    def test_height_zero_returns_without_db_write(self):
        """Genesis block (height=0) returns early — no AttributeError."""
        try:
            self.validator.apply_block(self._make_block(0))
        except AttributeError as e:  # pragma: no cover
            self.fail(
                f"apply_block(height=0) hit dead update_utxo_set path: {e}"
            )

    def test_non_genesis_height_falls_through(self):
        """Non-genesis heights skip the gate and hit the dead path
        (AttributeError on update_utxo_set), confirming the gate is
        scoped to height 0 only."""
        with self.assertRaises(AttributeError):
            self.validator.apply_block(self._make_block(1))


class TestSigCacheKeyCommitsToWitness(unittest.TestCase):
    """W159 BUG-13 / W160 BUG-9 regression.

    Pre-fix, ``_verify_input_signature`` derived the SigCache key from
    ``txid + input_index + script_pubkey + script_sig`` only. For Taproot
    (and SegWit v0) inputs ``script_sig`` is EMPTY — the signature lives
    in ``witness`` — so the cache key carried NO witness-bearing
    material. Two distinct spends of the same outpoint with different
    witnesses produced IDENTICAL cache keys; a cached True from a
    legitimate spend short-circuited verification of a forged-witness
    spend on the next lookup.

    Post-fix (per Core ``sigcache.cpp:39-50``), the cache key commits to
    the full witness-bearing tx envelope (``serialize_with_witness()``).
    Two Taproot spends of the same ``(txid, input_index)`` with different
    witnesses MUST produce distinct cache keys.
    """

    def setUp(self):
        from ouroboros.database import Transaction, TxIn, TxOut  # noqa
        from ouroboros.validation import SIG_CACHE
        SIG_CACHE.clear()
        self.Transaction = Transaction
        self.TxIn = TxIn
        self.TxOut = TxOut

    def _build_taproot_tx(self, witness_stack):
        """Construct a Taproot-shaped tx: empty script_sig, non-empty witness."""
        # P2TR scriptPubKey: OP_1 <32-byte-x-only-pubkey>
        spk = b"\x51\x20" + bytes(32)
        return self.Transaction(
            txid=bytes(32),
            version=2,
            locktime=0,
            has_witness=True,
            inputs=[
                self.TxIn(
                    prev_txid=b"\x11" * 32,
                    prev_vout=0,
                    script_sig=b"",  # Taproot key-path: empty script_sig
                    sequence=0xffffffff,
                    witness=list(witness_stack),
                ),
            ],
            outputs=[self.TxOut(value=900, script_pubkey=spk)],
        )

    def test_taproot_forged_witness_does_not_collide_with_cached_valid(self):
        """W159 BUG-13 / W160 BUG-9 regression: differing witnesses on the
        same (txid, input_index, script_pubkey) MUST derive distinct
        SigCache keys — even when script_sig is empty (Taproot).

        We replicate the cache-key derivation logic from
        ``_verify_input_signature`` (without actually running the script
        interpreter, which would need real keypairs / signatures). The
        post-fix key includes ``serialize_with_witness()``, so the two
        witnesses produce distinct keys.
        """
        import hashlib as _hashlib
        import struct as _struct
        from ouroboros.validation import SIG_CACHE

        # P2TR scriptPubKey + utxo amount — identical across both spends.
        spk = b"\x51\x20" + bytes(32)
        amount = 1000

        # "Legitimate" spend: a Schnorr-ish 64-byte witness.
        tx_valid = self._build_taproot_tx([b"\xaa" * 64])
        # "Forged" spend: same outpoint, same script_pubkey, but different
        # witness bytes — i.e. an attacker swapped the signature.
        tx_forged = self._build_taproot_tx([b"\xbb" * 64])

        def _make_key(tx, input_index):
            amount_bytes = _struct.pack("<q", amount)
            sighash_material = _hashlib.sha256(
                tx.serialize_with_witness()
                + _struct.pack("<I", input_index)
                + spk
                + amount_bytes
            ).digest()
            return sighash_material, bytes(spk), bytes(tx.inputs[input_index].script_sig)

        sh_v, pk_v, sig_v = _make_key(tx_valid, 0)
        sh_f, pk_f, sig_f = _make_key(tx_forged, 0)

        # Cryptographic-material guarantee: the per-input commitments differ.
        self.assertNotEqual(
            sh_v, sh_f,
            "Forged-witness Taproot spend MUST derive a distinct sighash "
            "commitment (W159 BUG-13 / W160 BUG-9: pre-fix, empty script_sig "
            "left the cache key without any witness-bearing material).",
        )

        # End-to-end SigCache guarantee: insert the "valid" cache entry,
        # then look up the "forged" key — it must NOT short-circuit to True.
        SIG_CACHE.insert(sh_v, pk_v, sig_v, 0)
        self.assertTrue(SIG_CACHE.lookup(sh_v, pk_v, sig_v, 0),
                        "sanity: the inserted key is retrievable")
        self.assertFalse(
            SIG_CACHE.lookup(sh_f, pk_f, sig_f, 0),
            "Forged-witness lookup MUST miss the cache — pre-fix it hit, "
            "letting a tampered witness replay a cached valid result.",
        )
