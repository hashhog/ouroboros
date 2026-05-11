"""
W77 — BIP-141 witness commitment comprehensive audit tests.

Reference: Bitcoin Core CheckWitnessMalleation() validation.cpp:3870-3916
           GetWitnessCommitmentIndex()  consensus/validation.h:147-165

Gates under test (12, matching Core spec):
  G1  SegWit not yet active → block with witness data → "unexpected-witness"
  G2  SegWit active, no commitment output, no witness → accepted
  G3  SegWit active, no commitment output, tx has witness → "unexpected-witness"
  G4  SegWit active, commitment present, nonce stack empty → "bad-witness-nonce-size"
  G5  SegWit active, commitment present, nonce stack has 2 items → "bad-witness-nonce-size"
  G6  SegWit active, commitment present, nonce item ≠ 32 bytes → "bad-witness-nonce-size"
  G7  SegWit active, commitment present, correct nonce → accepted
  G8  SegWit active, commitment present, wrong commitment hash → "bad-witness-merkle-match"
  G9  SegWit active, commitment present, block has NO non-cb witness → still validates
      nonce + commitment (Core does not condition on has_witness)
  G10 _find_witness_commitment uses LAST matching output (Core: keeps overwriting)
  G11 _find_witness_commitment ignores outputs shorter than 38 bytes
  G12 _find_witness_commitment ignores outputs with wrong magic bytes

BUG1 (fixed): Pre-SegWit block with witness data was silently accepted.
BUG2 (fixed): Commitment present + no witness → nonce/hash checks were skipped.
"""

from __future__ import annotations

import hashlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Inject a minimal mock for the Rust `sync` extension so we can import
# ouroboros.database / ouroboros.validation without a compiled binary.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.validation import BlockValidator  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _make_validator(network: str = "regtest") -> BlockValidator:
    """Return a BlockValidator with a stub DB (no Rust calls needed)."""
    db = MagicMock()
    v = BlockValidator.__new__(BlockValidator)
    v.db = db
    v.network = network
    v.tx_validator = MagicMock()
    v.snapshot_manager = None
    return v


def _make_coinbase(
    outputs: list[TxOut],
    witness: list[bytes] | None = None,
    has_witness: bool = False,
) -> Transaction:
    """Build a minimal coinbase transaction."""
    inp = TxIn(
        prev_txid=bytes(32),
        prev_vout=0xFFFFFFFF,
        script_sig=b"\x03\x01\x00\x00",  # BIP-34 height=1
        sequence=0xFFFFFFFF,
        witness=witness,
    )
    return Transaction(
        txid=bytes(32),
        version=1,
        locktime=0,
        inputs=[inp],
        outputs=outputs,
        has_witness=has_witness,
    )


def _make_regular_tx(has_witness: bool = False, witness: list[bytes] | None = None) -> Transaction:
    """Build a non-coinbase transaction."""
    inp = TxIn(
        prev_txid=b"\x01" * 32,
        prev_vout=0,
        script_sig=b"",
        sequence=0xFFFFFFFF,
        witness=witness,
    )
    return Transaction(
        txid=b"\x02" * 32,
        version=2,
        locktime=0,
        inputs=[inp],
        outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + bytes(20))],
        has_witness=has_witness,
    )


def _commitment_output(commitment_hash: bytes) -> TxOut:
    """Build a coinbase output containing the witness commitment."""
    # OP_RETURN 0x24 0xaa21a9ed <32-byte-hash>
    spk = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + commitment_hash
    return TxOut(value=0, script_pubkey=spk)


def _compute_commitment(
    block: Block,
    validator: BlockValidator,
    nonce: bytes,
) -> bytes:
    """Compute the expected witness commitment for a block + nonce."""
    witness_root = validator._calculate_witness_merkle_root(block)
    return _sha256d(witness_root + nonce)


def _make_block_with_commitment(
    nonce: bytes | None = None,
    extra_txs: list[Transaction] | None = None,
    has_witness_txs: bool = False,
    wrong_commitment: bool = False,
    height: int = 1,
) -> tuple[Block, BlockValidator]:
    """Build a SegWit-active block with a valid (or wrong) witness commitment."""
    v = _make_validator("regtest")  # activation height = 0

    if nonce is None:
        nonce = bytes(32)  # standard all-zero nonce

    txs = extra_txs or []
    # Build a temporary block without coinbase to compute the root
    placeholder_cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")],
                                    witness=None)
    temp_block = Block(
        version=0x20000000,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1700000000,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[placeholder_cb] + txs,
        hash=bytes(32),
        height=height,
    )

    commitment = _compute_commitment(temp_block, v, nonce)
    if wrong_commitment:
        commitment = bytes(b ^ 0xFF for b in commitment)

    cb_out_payment = TxOut(value=50_0000_0000, script_pubkey=b"\x51")
    cb_out_commitment = _commitment_output(commitment)
    cb = _make_coinbase(
        outputs=[cb_out_payment, cb_out_commitment],
        witness=[nonce],
        has_witness=True,
    )

    block = Block(
        version=0x20000000,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1700000000,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[cb] + txs,
        hash=bytes(32),
        height=height,
    )
    return block, v


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestFindWitnessCommitment(unittest.TestCase):
    """_find_witness_commitment — matches Core GetWitnessCommitmentIndex logic."""

    def _v(self) -> BlockValidator:
        return _make_validator()

    def test_g10_last_matching_output_used(self):
        """G10: if multiple outputs match, the LAST one is used (Core keeps overwriting commitpos)."""
        v = self._v()
        commitment_a = b"\xaa" * 32
        commitment_b = b"\xbb" * 32
        cb = _make_coinbase([
            _commitment_output(commitment_a),
            _commitment_output(commitment_b),
            TxOut(value=0, script_pubkey=b"\x51"),  # non-matching at end
        ])
        # _find_witness_commitment iterates reversed → returns first in reverse
        # which is the last in forward order.
        result = v._find_witness_commitment(cb)
        self.assertEqual(result, commitment_b,
                         "should return commitment from the LAST matching output")

    def test_g10_last_matching_when_trailing_nonmatch(self):
        """G10: trailing non-matching output doesn't affect last-match."""
        v = self._v()
        commitment_a = b"\xaa" * 32
        commitment_b = b"\xbb" * 32
        cb = _make_coinbase([
            TxOut(value=0, script_pubkey=b"\x51"),  # non-match
            _commitment_output(commitment_a),
            _commitment_output(commitment_b),
        ])
        result = v._find_witness_commitment(cb)
        self.assertEqual(result, commitment_b)

    def test_g11_output_too_short_ignored(self):
        """G11: output shorter than 38 bytes is not a commitment (MINIMUM_WITNESS_COMMITMENT=38)."""
        v = self._v()
        # 37-byte script: OP_RETURN 0x24 0xaa21a9ed + 31 bytes (one short)
        short_spk = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + b"\x00" * 31
        self.assertEqual(len(short_spk), 37)
        cb = _make_coinbase([TxOut(value=0, script_pubkey=short_spk)])
        result = v._find_witness_commitment(cb)
        self.assertIsNone(result, "output < 38 bytes must not be recognized as a commitment")

    def test_g11_output_exactly_38_bytes_accepted(self):
        """G11: exactly 38-byte output IS a valid commitment output."""
        v = self._v()
        commitment = b"\xcc" * 32
        spk = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + commitment
        self.assertEqual(len(spk), 38)
        cb = _make_coinbase([TxOut(value=0, script_pubkey=spk)])
        result = v._find_witness_commitment(cb)
        self.assertEqual(result, commitment)

    def test_g12_wrong_opcode_not_opreturn(self):
        """G12: first byte ≠ 0x6A (OP_RETURN) → not a commitment."""
        v = self._v()
        spk = bytes([0x00, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + b"\x00" * 32
        cb = _make_coinbase([TxOut(value=0, script_pubkey=spk)])
        self.assertIsNone(v._find_witness_commitment(cb))

    def test_g12_wrong_push_byte(self):
        """G12: second byte ≠ 0x24 → not a commitment."""
        v = self._v()
        spk = bytes([0x6A, 0x23, 0xAA, 0x21, 0xA9, 0xED]) + b"\x00" * 32
        cb = _make_coinbase([TxOut(value=0, script_pubkey=spk)])
        self.assertIsNone(v._find_witness_commitment(cb))

    def test_g12_wrong_magic_bytes(self):
        """G12: bytes 2-5 ≠ 0xaa21a9ed → not a commitment."""
        v = self._v()
        spk = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xEE]) + b"\x00" * 32  # last magic byte off
        cb = _make_coinbase([TxOut(value=0, script_pubkey=spk)])
        self.assertIsNone(v._find_witness_commitment(cb))

    def test_no_outputs_returns_none(self):
        """Empty coinbase outputs → None."""
        v = self._v()
        cb = _make_coinbase([])
        self.assertIsNone(v._find_witness_commitment(cb))

    def test_longer_than_38_bytes_still_valid(self):
        """Output longer than 38 bytes is fine; we read bytes [6:38]."""
        v = self._v()
        commitment = b"\xdd" * 32
        spk = bytes([0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED]) + commitment + b"\xFF" * 10
        cb = _make_coinbase([TxOut(value=0, script_pubkey=spk)])
        result = v._find_witness_commitment(cb)
        self.assertEqual(result, commitment)


class TestValidateWitnessCommitmentPreSegwit(unittest.TestCase):
    """G1: pre-SegWit blocks. BUG1: was silently accepting witness data."""

    def test_g1_pre_segwit_no_witness_accepted(self):
        """G1: pre-SegWit block with no witness data is accepted."""
        v = _make_validator("mainnet")  # activation=481_824
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        tx = _make_regular_tx(has_witness=False)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=100)
        ok, err = v._validate_witness_commitment(block, height=100)
        self.assertTrue(ok, f"pre-SegWit no-witness block should be accepted: {err}")

    def test_g1_pre_segwit_with_witness_rejected(self):
        """G1 (BUG1 fix): pre-SegWit block with witness data → 'unexpected-witness'."""
        v = _make_validator("mainnet")  # activation=481_824
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        tx = _make_regular_tx(has_witness=True, witness=[bytes(32)])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=100)
        ok, err = v._validate_witness_commitment(block, height=100)
        self.assertFalse(ok)
        self.assertEqual(err, "unexpected-witness",
                         "pre-SegWit block with witness data must be rejected "
                         "with 'unexpected-witness' (was silently accepted before fix)")

    def test_g1_at_activation_height_no_commitment_no_witness_ok(self):
        """Boundary: exactly at activation height, no witness, no commitment → accepted."""
        v = _make_validator("mainnet")
        activation = BlockValidator._SEGWIT_ACTIVATION["mainnet"]
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=activation)
        ok, err = v._validate_witness_commitment(block, height=activation)
        self.assertTrue(ok, f"at activation, no witness, no commitment: {err}")

    def test_g1_coinbase_witness_pre_segwit_rejected(self):
        """G1: coinbase itself carrying witness pre-SegWit → 'unexpected-witness'."""
        v = _make_validator("mainnet")
        cb = _make_coinbase(
            [TxOut(value=50_0000_0000, script_pubkey=b"\x51")],
            witness=[bytes(32)],
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=100)
        ok, err = v._validate_witness_commitment(block, height=100)
        self.assertFalse(ok)
        self.assertEqual(err, "unexpected-witness")


class TestValidateWitnessCommitmentNoCommitment(unittest.TestCase):
    """G2 & G3: SegWit active, no commitment output."""

    def test_g2_segwit_active_no_commitment_no_witness_ok(self):
        """G2: SegWit active, no commitment, no witness → accepted."""
        v = _make_validator("regtest")  # activation=0
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertTrue(ok, f"no commitment, no witness → should pass: {err}")

    def test_g3_segwit_active_no_commitment_tx_has_witness_rejected(self):
        """G3: SegWit active, no commitment, tx has witness → 'unexpected-witness'."""
        v = _make_validator("regtest")
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        tx = _make_regular_tx(has_witness=True, witness=[bytes(32)])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "unexpected-witness")


class TestValidateWitnessCommitmentNonceSize(unittest.TestCase):
    """G4-G6: nonce size validation (bad-witness-nonce-size)."""

    def test_g4_empty_witness_stack_rejected(self):
        """G4: commitment present, nonce stack empty → 'bad-witness-nonce-size'."""
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [TxOut(value=0, script_pubkey=b"\x51"), _commitment_output(bytes(32))],
            witness=[],   # empty stack
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-nonce-size")

    def test_g5_two_item_witness_stack_rejected(self):
        """G5: commitment present, nonce stack has 2 items → 'bad-witness-nonce-size'."""
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [_commitment_output(bytes(32))],
            witness=[bytes(32), bytes(32)],  # 2 items
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-nonce-size")

    def test_g6_nonce_not_32_bytes_rejected(self):
        """G6: nonce item ≠ 32 bytes → 'bad-witness-nonce-size'."""
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [_commitment_output(bytes(32))],
            witness=[bytes(31)],  # 31 bytes, not 32
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-nonce-size")

    def test_g6_nonce_33_bytes_rejected(self):
        """G6 edge: nonce 33 bytes → 'bad-witness-nonce-size'."""
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [_commitment_output(bytes(32))],
            witness=[bytes(33)],
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-nonce-size")

    def test_g6_nonce_none_treated_as_empty_rejected(self):
        """G6: witness=None treated as empty stack → 'bad-witness-nonce-size'."""
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [_commitment_output(bytes(32))],
            witness=None,  # None → treated as []
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-nonce-size")


class TestValidateWitnessCommitmentHashMatch(unittest.TestCase):
    """G7-G8: commitment hash verification."""

    def test_g7_valid_commitment_accepted(self):
        """G7: correct nonce and commitment → accepted."""
        block, v = _make_block_with_commitment()
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertTrue(ok, f"valid commitment should be accepted: {err}")

    def test_g7_valid_commitment_coinbase_only_block(self):
        """G7: coinbase-only block (single tx), valid commitment → accepted."""
        block, v = _make_block_with_commitment(extra_txs=[])
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertTrue(ok, f"coinbase-only valid commitment: {err}")

    def test_g7_valid_commitment_with_extra_txs(self):
        """G7: multiple non-witness txs, valid commitment → accepted."""
        tx1 = _make_regular_tx(has_witness=False)
        tx2 = _make_regular_tx(has_witness=False)
        # give them distinct txids
        tx1 = Transaction(txid=b"\x01" * 32, version=tx1.version, locktime=tx1.locktime,
                          inputs=tx1.inputs, outputs=tx1.outputs, has_witness=False)
        tx2 = Transaction(txid=b"\x02" * 32, version=tx2.version, locktime=tx2.locktime,
                          inputs=tx2.inputs, outputs=tx2.outputs, has_witness=False)
        block, v = _make_block_with_commitment(extra_txs=[tx1, tx2])
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertTrue(ok, f"multi-tx valid commitment: {err}")

    def test_g8_wrong_commitment_hash_rejected(self):
        """G8: commitment bytes don't match → 'bad-witness-merkle-match'."""
        block, v = _make_block_with_commitment(wrong_commitment=True)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-merkle-match")

    def test_g8_off_by_one_byte_in_commitment_rejected(self):
        """G8: single bit flip in commitment → 'bad-witness-merkle-match'."""
        block, v = _make_block_with_commitment()
        # Flip a byte in the commitment output script
        cb = block.transactions[0]
        spk = bytearray(cb.outputs[1].script_pubkey)
        spk[6] ^= 0x01  # flip one bit in the hash
        cb.outputs[1] = TxOut(value=0, script_pubkey=bytes(spk))
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-merkle-match")

    def test_g8_all_zeros_commitment_wrong(self):
        """G8: all-zero commitment with non-zero witness root → rejected."""
        v = _make_validator("regtest")
        nonce = bytes(32)
        # Create a block with a witness tx so the root ≠ 0x00*32
        tx = _make_regular_tx(has_witness=True, witness=[b"\xAB" * 32])
        tx = Transaction(txid=b"\x03" * 32, version=2, locktime=0,
                         inputs=tx.inputs, outputs=tx.outputs, has_witness=True)
        wrong_commitment = bytes(32)  # all-zero — almost certainly wrong
        cb = _make_coinbase(
            [_commitment_output(wrong_commitment)],
            witness=[nonce],
            has_witness=True,
        )
        block = Block(version=0x20000000, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok)
        self.assertEqual(err, "bad-witness-merkle-match")


class TestG9CommitmentWithNoWitnessTxs(unittest.TestCase):
    """G9 (BUG2 fix): commitment present but no non-cb witness → still validates.

    Before the fix, `if commitment is not None and has_witness:` skipped the
    nonce + hash checks when has_witness was False. Core does NOT condition
    these checks on has_witness — it checks whenever commitpos != -1.
    """

    def test_g9_commitment_no_witness_txs_valid_nonce_accepted(self):
        """G9: commitment output present, non-cb txs are non-witness, valid nonce → accepted."""
        v = _make_validator("regtest")
        nonce = bytes(32)

        # Non-witness regular tx (has_witness=False → wtxid = txid)
        reg_tx = Transaction(txid=b"\x04" * 32, version=1, locktime=0,
                             inputs=[TxIn(prev_txid=b"\x05" * 32, prev_vout=0,
                                          script_sig=b"", sequence=0xFFFFFFFF)],
                             outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
                             has_witness=False)

        # Build a placeholder block to compute the correct commitment
        # (it must include reg_tx so the witness root is correct)
        cb_placeholder = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        temp_block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                           timestamp=0, bits=0x1D00FFFF, nonce=0,
                           transactions=[cb_placeholder, reg_tx], hash=bytes(32), height=1)
        commitment = _compute_commitment(temp_block, v, nonce)

        cb = _make_coinbase(
            [_commitment_output(commitment)],
            witness=[nonce],
            has_witness=True,  # coinbase has witness (the nonce)
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, reg_tx], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertTrue(ok, f"commitment present, no witness txs, valid nonce: {err}")

    def test_g9_commitment_no_witness_txs_bad_nonce_rejected(self):
        """G9 (BUG2 fix): commitment present, non-cb txs non-witness, BAD nonce → 'bad-witness-nonce-size'.

        Before the fix this silently passed because `has_witness=False` short-circuited
        the validation entirely.
        """
        v = _make_validator("regtest")
        cb = _make_coinbase(
            [_commitment_output(bytes(32))],
            witness=[bytes(31)],  # wrong nonce size: 31 bytes
            has_witness=True,
        )
        reg_tx = Transaction(txid=b"\x06" * 32, version=1, locktime=0,
                             inputs=[TxIn(prev_txid=b"\x07" * 32, prev_vout=0,
                                          script_sig=b"", sequence=0xFFFFFFFF)],
                             outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
                             has_witness=False)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, reg_tx], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok, "bad nonce size should be rejected even when no witness txs")
        self.assertEqual(err, "bad-witness-nonce-size",
                         "BUG2 fix: commitment checks must not be guarded by has_witness")

    def test_g9_commitment_no_witness_txs_wrong_hash_rejected(self):
        """G9 (BUG2 fix): commitment present, non-cb txs non-witness, WRONG hash → 'bad-witness-merkle-match'.

        Before the fix this silently passed.
        """
        v = _make_validator("regtest")
        nonce = bytes(32)
        wrong_commitment = b"\xDE\xAD" + bytes(30)  # definitely wrong
        cb = _make_coinbase(
            [_commitment_output(wrong_commitment)],
            witness=[nonce],
            has_witness=True,
        )
        reg_tx = Transaction(txid=b"\x08" * 32, version=1, locktime=0,
                             inputs=[TxIn(prev_txid=b"\x09" * 32, prev_vout=0,
                                          script_sig=b"", sequence=0xFFFFFFFF)],
                             outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
                             has_witness=False)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, reg_tx], hash=bytes(32), height=1)
        ok, err = v._validate_witness_commitment(block, height=1)
        self.assertFalse(ok, "wrong commitment hash should be rejected even when no witness txs")
        self.assertEqual(err, "bad-witness-merkle-match",
                         "BUG2 fix: commitment hash check must not be guarded by has_witness")


class TestCalculateWitnessMerkleRoot(unittest.TestCase):
    """Witness merkle root computation matches Core BlockWitnessMerkleRoot."""

    def test_coinbase_only_root_is_zero_hash(self):
        """Coinbase-only block: witness root = SHA256d(0x00*32) = the coinbase wtxid."""
        v = _make_validator()
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        root = v._calculate_witness_merkle_root(block)
        # Single leaf = coinbase wtxid = 0x00*32
        # ComputeMerkleRoot with one leaf = that leaf
        self.assertEqual(root, bytes(32),
                         "coinbase-only: root must equal the null coinbase wtxid")

    def test_coinbase_wtxid_is_always_null(self):
        """Core: coinbase wtxid is always 0x00*32 in witness merkle tree."""
        v = _make_validator()
        # Even if coinbase has witness data, its wtxid in the tree is null
        cb = _make_coinbase(
            [TxOut(value=50_0000_0000, script_pubkey=b"\x51")],
            witness=[b"\xAB" * 32],
            has_witness=True,
        )
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=1)
        root = v._calculate_witness_merkle_root(block)
        self.assertEqual(root, bytes(32),
                         "coinbase wtxid in witness tree must always be null (0x00*32)")

    def test_two_tx_block_root_computed_correctly(self):
        """Two-tx block: root = SHA256d(cb_wtxid || tx_wtxid)."""
        v = _make_validator()
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        # Non-witness tx: wtxid = txid
        tx = Transaction(txid=b"\xAA" * 32, version=1, locktime=0,
                         inputs=[TxIn(prev_txid=b"\x01" * 32, prev_vout=0,
                                      script_sig=b"", sequence=0xFFFFFFFF)],
                         outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
                         has_witness=False)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=1)
        root = v._calculate_witness_merkle_root(block)
        # Expected: SHA256d(0x00*32 || 0xAA*32)
        expected = _sha256d(bytes(32) + b"\xAA" * 32)
        self.assertEqual(root, expected)


class TestSegwitNetworkActivation(unittest.TestCase):
    """Activation height is per-network, not hardcoded."""

    def test_regtest_activates_at_0(self):
        """regtest: SegWit active from height 0."""
        v = _make_validator("regtest")
        # Block at height 0 with commitment → must validate (not skip due to height)
        nonce = bytes(32)
        cb_placeholder = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        temp_block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                           timestamp=0, bits=0x1D00FFFF, nonce=0,
                           transactions=[cb_placeholder], hash=bytes(32), height=0)
        commitment = _compute_commitment(temp_block, v, nonce)
        cb = _make_coinbase([_commitment_output(commitment)], witness=[nonce], has_witness=True)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=0)
        ok, err = v._validate_witness_commitment(block, height=0)
        self.assertTrue(ok, f"regtest h=0 with valid commitment: {err}")

    def test_mainnet_below_activation_no_witness_ok(self):
        """mainnet: h=481_823 (one below activation) → no witness OK."""
        v = _make_validator("mainnet")
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb], hash=bytes(32), height=481_823)
        ok, err = v._validate_witness_commitment(block, height=481_823)
        self.assertTrue(ok)

    def test_testnet4_activates_at_0(self):
        """testnet4: SegWit active from height 0."""
        v = _make_validator("testnet4")
        # Witness data without commitment → unexpected-witness
        cb = _make_coinbase([TxOut(value=50_0000_0000, script_pubkey=b"\x51")])
        tx = _make_regular_tx(has_witness=True, witness=[bytes(32)])
        tx = Transaction(txid=b"\x0A" * 32, version=tx.version, locktime=tx.locktime,
                         inputs=tx.inputs, outputs=tx.outputs, has_witness=True)
        block = Block(version=1, prev_blockhash=bytes(32), merkle_root=bytes(32),
                      timestamp=0, bits=0x1D00FFFF, nonce=0,
                      transactions=[cb, tx], hash=bytes(32), height=0)
        ok, err = v._validate_witness_commitment(block, height=0)
        self.assertFalse(ok)
        self.assertEqual(err, "unexpected-witness")


class TestRpcBip22ResultStrings(unittest.TestCase):
    """bip22_result_string() must pass through the new canonical error strings."""

    def test_bad_witness_nonce_size_is_canonical(self):
        """'bad-witness-nonce-size' must pass through bip22_result_string unchanged."""
        from ouroboros.rpc import bip22_result_string
        result = bip22_result_string("bad-witness-nonce-size")
        self.assertEqual(result, "bad-witness-nonce-size")

    def test_unexpected_witness_is_canonical(self):
        """'unexpected-witness' must pass through bip22_result_string unchanged."""
        from ouroboros.rpc import bip22_result_string
        result = bip22_result_string("unexpected-witness")
        self.assertEqual(result, "unexpected-witness")

    def test_bad_witness_merkle_match_still_canonical(self):
        """'bad-witness-merkle-match' must still pass through unchanged."""
        from ouroboros.rpc import bip22_result_string
        result = bip22_result_string("bad-witness-merkle-match")
        self.assertEqual(result, "bad-witness-merkle-match")


if __name__ == "__main__":
    unittest.main()
