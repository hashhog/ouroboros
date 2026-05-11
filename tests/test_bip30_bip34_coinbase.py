"""
W79 — BIP-30 + BIP-34 coinbase comprehensive audit tests.

Reference:
  Bitcoin Core validation.cpp:2392-2476 (ConnectBlock, BIP30)
  Bitcoin Core validation.cpp:4129-4159 (ContextualCheckBlock, BIP34)
  Bitcoin Core validation.cpp:6189-6199 (IsBIP30Repeat, IsBIP30Unspendable)
  Bitcoin Core kernel/chainparams.cpp:89-90 (mainnet BIP34Hash)

Tests cover all 10 gates:

Gate 1  — IsBIP30Repeat exception is height+hash, not height-only.
Gate 2  — BIP34 suppresses BIP30 only on the canonical chain (hash-verified).
Gate 3  — Per-network BIP34 height used, not hardcoded 227,931.
Gate 4  — BIP34_IMPLIES_BIP30_LIMIT (1,983,702) re-enables BIP30.
Gate 5  — BIP30 checks ALL transactions (not only coinbase).
Gate 6  — BIP30 checks ALL vouts of each transaction.
Gate 7  — BIP34 coinbase height encoding: OP_n for 1..16, CScriptNum otherwise.
Gate 8  — BIP34 check is a prefix match (starts-with), not exact equality.
Gate 9  — BIP34 activation uses per-network height (testnet4/regtest = 1).
Gate 10 — Error code is "bad-txns-BIP30" (Core parity).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure conftest mock is active before importing ouroboros modules.
import tests.conftest  # noqa: F401  -- install the sync mock

from ouroboros.consensus import BIP30_REPEAT_EXCEPTIONS, BIP34_HASHES, BURIED_DEPLOYMENTS
from ouroboros.validation import _encode_bip34_height

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAINNET_BIP34_HASH = bytes.fromhex(
    "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
)
_MAINNET_BIP34_HEIGHT = 227_931
_BIP30_RECHECK_HEIGHT = 1_983_702

# Hash of block 91842 (IsBIP30Repeat) — internal byte order (LE as stored).
_REPEAT_HASH_91842 = bytes.fromhex(
    "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
)
_REPEAT_HASH_91880 = bytes.fromhex(
    "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
)

# A fake block hash for non-canonical forks.
_FORK_HASH = bytes(b"\xde\xad" * 16)


def _make_tx(txid: bytes, n_outputs: int = 1, is_coinbase: bool = False):
    """Construct a minimal mock Transaction."""
    tx = MagicMock()
    tx.get_txid.return_value = txid
    tx.outputs = [MagicMock() for _ in range(n_outputs)]
    tx.is_coinbase = is_coinbase
    tx.inputs = [MagicMock()]
    tx.inputs[0].prev_txid = bytes(32) if is_coinbase else b"\xaa" * 32
    tx.inputs[0].prev_vout = 0xFFFFFFFF if is_coinbase else 0
    tx.inputs[0].script_sig = b"\x03\x01\x00\x00"
    return tx


def _make_block(
    block_hash: bytes,
    transactions: list,
    prev_hash: bytes = bytes(32),
    height: int | None = None,
):
    """Construct a minimal mock Block."""
    blk = MagicMock()
    blk.hash = block_hash
    blk.transactions = transactions
    blk.prev_blockhash = prev_hash
    blk.height = height
    blk.version = 4
    blk.bits = 0x1D00FFFF
    blk.nonce = 0
    blk.timestamp = 1_600_000_000
    blk.merkle_root = bytes(32)
    return blk


def _make_validator(
    network: str = "mainnet",
    utxo_exists: bool = False,
    bip34_ancestor_hash: bytes | None = None,
):
    """
    Build a BlockValidator with a mocked database.

    utxo_exists  — if True, get_utxo() returns a non-None value (UTXO exists).
    bip34_ancestor_hash — what get_block_hash_at_height() returns for the
                          BIP34 activation height lookup.  None means the DB
                          does not support that method.
    """
    from ouroboros.validation import BlockValidator

    db = MagicMock()
    db.get_utxo.return_value = {"value": 5000} if utxo_exists else None
    db.get_best_block.return_value = (bytes(32), 0)
    db.get_median_time_past.return_value = 0

    if bip34_ancestor_hash is not None:
        db.get_block_hash_at_height.return_value = bip34_ancestor_hash
    else:
        # Simulate a DB that doesn't have the method.
        del db.get_block_hash_at_height

    validator = BlockValidator(db, network=network)
    return validator


# ===========================================================================
# Gate 1 — IsBIP30Repeat: exception is height+hash, not height-only
# ===========================================================================

class TestBip30RepeatExceptions:
    """BIP30_REPEAT_EXCEPTIONS must be keyed by (height, hash) per Core."""

    def test_repeat_exceptions_exist_in_consensus(self):
        """Both repeat heights must be present in BIP30_REPEAT_EXCEPTIONS."""
        assert 91842 in BIP30_REPEAT_EXCEPTIONS
        assert 91880 in BIP30_REPEAT_EXCEPTIONS

    def test_repeat_hash_91842_correct(self):
        """Block 91842 exception hash matches Core IsBIP30Repeat."""
        assert BIP30_REPEAT_EXCEPTIONS[91842] == _REPEAT_HASH_91842

    def test_repeat_hash_91880_correct(self):
        """Block 91880 exception hash matches Core IsBIP30Repeat."""
        assert BIP30_REPEAT_EXCEPTIONS[91880] == _REPEAT_HASH_91880

    def test_canonical_repeat_block_skips_bip30(self):
        """A block at height 91842 with the correct hash must skip BIP30."""
        validator = _make_validator(utxo_exists=True)
        # If BIP30 were enforced the test block would fail (UTXO exists).
        # With the correct hash the exception fires and the block passes.
        cb_txid = b"\xcc" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\xaa\x65\x00" + b"\x00" * 6  # valid len

        block = _make_block(
            block_hash=_REPEAT_HASH_91842,
            transactions=[cb],
        )

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator, "_verify_coinbase_amount", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=91842)

        assert ok, f"Block with canonical 91842 hash should skip BIP30, got: {err}"

    def test_fork_block_at_repeat_height_enforces_bip30(self):
        """A fork block at height 91842 with a different hash must fail BIP30."""
        validator = _make_validator(utxo_exists=True)
        cb_txid = b"\xcc" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\xaa\x65\x00" + b"\x00" * 6

        # Different hash — not the canonical IsBIP30Repeat exception.
        block = _make_block(
            block_hash=_FORK_HASH,
            transactions=[cb],
        )

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=91842)

        assert not ok, "Fork block at height 91842 must be rejected by BIP30"
        assert "bad-txns-BIP30" in err  # Gate 10


# ===========================================================================
# Gate 2 — BIP34 suppresses BIP30 only via canonical-hash verification
# ===========================================================================

class TestBip34SuppressesBip30CanonicalChainOnly:
    """BIP30 must only be suppressed when the BIP34 anchor hash matches."""

    def test_bip34_hashes_in_consensus(self):
        """BIP34_HASHES must contain the correct mainnet canonical hash."""
        assert "mainnet" in BIP34_HASHES
        assert BIP34_HASHES["mainnet"] == _MAINNET_BIP34_HASH

    def test_mainnet_canonical_chain_skips_bip30(self):
        """When the ancestor hash matches BIP34Hash, BIP30 is suppressed (height 250000)."""
        # Provide the canonical BIP34 ancestor hash → BIP30 suppressed.
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=_MAINNET_BIP34_HASH,
        )
        cb_txid = b"\xdd" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\xd0\xd4\x03" + b"\x00" * 6  # h=250000

        block = _make_block(block_hash=b"\xab" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator, "_verify_coinbase_amount", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=250_000)

        assert ok, f"Mainnet canonical chain at h=250000 should skip BIP30, got: {err}"

    def test_mainnet_fork_does_not_skip_bip30(self):
        """When the ancestor hash does NOT match BIP34Hash, BIP30 is still enforced."""
        wrong_hash = b"\xff" * 32
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=wrong_hash,
        )
        cb_txid = b"\xdd" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\xd0\xd4\x03" + b"\x00" * 6  # h=250000

        block = _make_block(block_hash=b"\xab" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=250_000)

        assert not ok, "Fork at h=250000 should fail BIP30 (wrong BIP34 anchor hash)"
        assert "bad-txns-BIP30" in err

    def test_bip30_enforced_when_db_has_no_hash_lookup(self):
        """If DB lacks get_block_hash_at_height, BIP30 is conservatively enforced."""
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=None,  # No method → conservative
        )
        cb_txid = b"\xee" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\xd0\xd4\x03" + b"\x00" * 6

        block = _make_block(block_hash=b"\xba" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=250_000)

        assert not ok, "Without ancestry DB, BIP30 must be conservatively enforced"
        assert "bad-txns-BIP30" in err


# ===========================================================================
# Gate 3 — Per-network BIP34 height
# ===========================================================================

class TestBip34PerNetworkHeight:
    """BIP34 activation uses per-network height, not hardcoded 227,931."""

    def test_testnet4_bip34_height_is_1(self):
        assert BURIED_DEPLOYMENTS["testnet4"]["bip34"].height == 1

    def test_regtest_bip34_height_is_1(self):
        assert BURIED_DEPLOYMENTS["regtest"]["bip34"].height == 1

    def test_signet_bip34_height_is_1(self):
        assert BURIED_DEPLOYMENTS["signet"]["bip34"].height == 1

    def test_mainnet_bip34_height_is_227931(self):
        assert BURIED_DEPLOYMENTS["mainnet"]["bip34"].height == 227_931

    def test_testnet4_bip34_hash_is_zero(self):
        """testnet4 BIP34Hash is all-zeros → BIP30 always enforced."""
        assert BIP34_HASHES["testnet4"] == bytes(32)

    def test_regtest_bip34_hash_is_zero(self):
        """regtest BIP34Hash is all-zeros → BIP30 always enforced."""
        assert BIP34_HASHES["regtest"] == bytes(32)

    def test_testnet4_bip30_always_enforced_at_low_height(self):
        """testnet4 at height 10 must enforce BIP30 (BIP34 is at 1, hash is zero)."""
        validator = _make_validator(network="testnet4", utxo_exists=True)
        cb_txid = b"\x01" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        # BIP34 active from height 1: scriptSig must encode height.
        # Height 10 → OP_10 = 0x5a
        cb.inputs[0].script_sig = bytes([0x5A]) + b"\x00" * 4

        block = _make_block(block_hash=b"\x11" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=10)

        # Zero BIP34Hash → BIP30 always enforced → UTXO collision detected.
        assert not ok, "testnet4 BIP30 must be enforced (zero BIP34Hash)"
        assert "bad-txns-BIP30" in err

    def test_mainnet_below_bip34_enforces_bip30(self):
        """mainnet at height 200,000 (below BIP34 227,931) must enforce BIP30."""
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=bytes(32),  # ancestor before BIP34 height = irrelevant
        )
        cb_txid = b"\x02" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\x40\x0d\x03" + b"\x00" * 6

        block = _make_block(block_hash=b"\x22" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=200_000)

        assert not ok
        assert "bad-txns-BIP30" in err


# ===========================================================================
# Gate 4 — BIP34_IMPLIES_BIP30_LIMIT re-enables BIP30 at height 1,983,702
# ===========================================================================

class TestBip34ImpliesBip30Limit:
    """BIP30 is re-enabled at height >= 1,983,702 regardless of BIP34 status."""

    def test_bip30_reenabled_at_limit(self):
        """At height 1,983,702 BIP30 must be enforced even on canonical chain."""
        # Even with the canonical BIP34 ancestor hash, re-check is forced.
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=_MAINNET_BIP34_HASH,
        )
        cb_txid = b"\x03" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x04\xd6\x47\x1e\x00" + b"\x00" * 6

        block = _make_block(block_hash=b"\x33" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator, "_verify_coinbase_amount", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=_BIP30_RECHECK_HEIGHT)

        assert not ok, "BIP30 must be re-enforced at height 1,983,702"
        assert "bad-txns-BIP30" in err

    def test_bip30_reenabled_above_limit(self):
        """At height 2,000,000 (above limit) BIP30 is still enforced."""
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=_MAINNET_BIP34_HASH,
        )
        cb_txid = b"\x04" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x04\x80\x84\x1e\x00" + b"\x00" * 6

        block = _make_block(block_hash=b"\x44" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=2_000_000)

        assert not ok, "BIP30 must be enforced above 1,983,702"
        assert "bad-txns-BIP30" in err

    def test_bip30_suppressed_just_below_limit(self):
        """At height 1,983,701 (just below limit), BIP30 is suppressed on canonical chain."""
        validator = _make_validator(
            network="mainnet",
            utxo_exists=True,
            bip34_ancestor_hash=_MAINNET_BIP34_HASH,
        )
        cb_txid = b"\x05" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x04\xd5\x47\x1e\x00" + b"\x00" * 6

        block = _make_block(block_hash=b"\x55" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator, "_verify_coinbase_amount", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=_BIP30_RECHECK_HEIGHT - 1)

        assert ok, (
            f"BIP30 should be suppressed at h=1,983,701 on canonical chain, got: {err}"
        )


# ===========================================================================
# Gate 5 — BIP30 checks ALL transactions (not only coinbase)
# ===========================================================================

class TestBip30ChecksAllTransactions:
    """BIP30 must check every transaction in the block, not just the coinbase."""

    def test_non_coinbase_duplicate_rejected(self):
        """A non-coinbase tx whose UTXO exists must be rejected by BIP30."""
        validator = _make_validator(network="mainnet", utxo_exists=True)

        cb_txid = b"\x06" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\x40\x0d\x03" + b"\x00" * 6

        non_cb_txid = b"\x07" * 32
        non_cb = _make_tx(non_cb_txid, n_outputs=2, is_coinbase=False)

        # Only non-coinbase UTXO exists.
        def _utxo_exists(txid, vout):
            if txid == non_cb_txid:
                return {"value": 5000}
            return None

        validator.db.get_utxo.side_effect = _utxo_exists

        block = _make_block(block_hash=b"\x66" * 32, transactions=[cb, non_cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=200_000)

        assert not ok, "Non-coinbase duplicate must be caught by BIP30"
        assert "bad-txns-BIP30" in err


# ===========================================================================
# Gate 6 — BIP30 checks ALL vouts of each transaction
# ===========================================================================

class TestBip30ChecksAllVouts:
    """BIP30 must check every output index of every transaction."""

    def test_second_vout_duplicate_rejected(self):
        """A collision on vout=1 (not vout=0) must still be caught."""
        validator = _make_validator(network="mainnet", utxo_exists=False)

        cb_txid = b"\x08" * 32
        cb = _make_tx(cb_txid, n_outputs=3, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\x40\x0d\x03" + b"\x00" * 6

        # Only vout=1 collides.
        def _utxo(txid, vout):
            if txid == cb_txid and vout == 1:
                return {"value": 5000}
            return None

        validator.db.get_utxo.side_effect = _utxo

        block = _make_block(block_hash=b"\x77" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=200_000)

        assert not ok, "Collision on vout=1 must be caught by BIP30"
        assert "bad-txns-BIP30" in err


# ===========================================================================
# Gate 7 — BIP34 height encoding: OP_n for 1..16, CScriptNum otherwise
# ===========================================================================

class TestEncodeBip34Height:
    """_encode_bip34_height must produce canonical CScript() << nHeight output."""

    def test_height_0_is_op0(self):
        """Height 0 → OP_0 (0x00)."""
        assert _encode_bip34_height(0) == b"\x00"

    def test_height_1_is_op1(self):
        """Height 1 → OP_1 (0x51)."""
        assert _encode_bip34_height(1) == bytes([0x51])

    def test_height_16_is_op16(self):
        """Height 16 → OP_16 (0x60)."""
        assert _encode_bip34_height(16) == bytes([0x60])

    def test_height_17_is_cscriptnum(self):
        """Height 17 → 1-byte push [0x01, 0x11]."""
        assert _encode_bip34_height(17) == bytes([0x01, 0x11])

    def test_height_127_no_sign_pad(self):
        """Height 127 (0x7f) → [0x01, 0x7f] (no sign pad needed)."""
        assert _encode_bip34_height(127) == bytes([0x01, 0x7F])

    def test_height_128_sign_pad(self):
        """Height 128 (0x80) → [0x02, 0x80, 0x00] (sign pad required)."""
        assert _encode_bip34_height(128) == bytes([0x02, 0x80, 0x00])

    def test_height_227931_mainnet_bip34(self):
        """Height 227,931 (mainnet BIP34 activation) encodes as 3-byte CScriptNum."""
        # 227931 = 0x037A5B → LE = [0x5B, 0x7A, 0x03] → push: [0x03, 0x5B, 0x7A, 0x03]
        assert _encode_bip34_height(227_931) == bytes([0x03, 0x5B, 0x7A, 0x03])

    def test_height_1983702_recheck_boundary(self):
        """Height 1,983,702 (BIP34_IMPLIES_BIP30_LIMIT) encodes correctly."""
        # 1983702 = 0x1E44D6 → LE = [0xD6, 0x44, 0x1E] → [0x03, 0xD6, 0x44, 0x1E]
        assert _encode_bip34_height(1_983_702) == bytes([0x03, 0xD6, 0x44, 0x1E])

    def test_op1_through_op16_single_byte(self):
        """All heights 1..16 must be single-byte OP_n opcodes."""
        for h in range(1, 17):
            enc = _encode_bip34_height(h)
            assert len(enc) == 1, f"height {h} should be single byte, got {enc.hex()}"
            assert enc[0] == 0x50 + h, f"height {h} should be OP_{h}=0x{0x50+h:02x}"

    def test_no_op1_for_height_17(self):
        """Height 17 must NOT use OP_1 (0x51) — that would be wrong."""
        enc = _encode_bip34_height(17)
        assert enc != bytes([0x51])


# ===========================================================================
# Gate 8 — BIP34 check is a prefix match (starts-with)
# ===========================================================================

def _make_bv(network: str = "mainnet"):
    """Build a BlockValidator backed by a mock DB (no filesystem needed)."""
    from ouroboros.validation import BlockValidator
    db = MagicMock()
    db.get_utxo.return_value = None
    db.get_best_block.return_value = (bytes(32), 0)
    db.get_median_time_past.return_value = 0
    return BlockValidator(db, network=network)


def _make_coinbase_tx(script_sig: bytes):
    """Build a minimal coinbase Transaction with the given scriptSig.

    Transaction.is_coinbase is a computed property: prev_txid == bytes(32).
    We set prev_txid=bytes(32) which makes it a coinbase automatically.
    """
    from ouroboros.database import Transaction, TxIn, TxOut
    inp = TxIn(
        prev_txid=bytes(32),
        prev_vout=0xFFFFFFFF,
        script_sig=script_sig,
        sequence=0xFFFFFFFF,
    )
    tx = Transaction(
        txid=b"\x99" * 32,
        version=1,
        locktime=0,
        inputs=[inp],
        outputs=[TxOut(value=5_000_000_000, script_pubkey=b"\x51")],
    )
    return tx


class TestBip34PrefixMatch:
    """BIP34 validation is a prefix check, not exact equality."""

    def test_bip34_accepts_extra_data_after_height(self):
        """A coinbase scriptSig that starts with the correct height prefix but has
        extra bytes after it must be accepted (Core: starts-with check)."""
        v = _make_bv("mainnet")
        height = 300_000  # Above BIP34 activation (227,931)
        prefix = _encode_bip34_height(height)
        # scriptSig = height prefix + extra bytes (valid by Core's prefix rule)
        script_sig = prefix + b"\x01\x02\x03\x04\x05"
        assert 2 <= len(script_sig) <= 100
        tx = _make_coinbase_tx(script_sig)
        assert v._validate_coinbase(tx, height), (
            "Coinbase with extra bytes after height prefix must pass"
        )

    def test_bip34_rejects_wrong_prefix(self):
        """A coinbase whose scriptSig does not start with the correct height
        prefix must be rejected."""
        v = _make_bv("mainnet")
        height = 300_000
        wrong_prefix = _encode_bip34_height(height + 1)  # Off-by-one
        script_sig = wrong_prefix + b"\x00" * 4
        assert len(script_sig) >= 2
        tx = _make_coinbase_tx(script_sig)
        assert not v._validate_coinbase(tx, height), (
            "Coinbase with wrong height prefix must fail BIP34"
        )


# ===========================================================================
# Gate 9 — BIP34 activation uses per-network height
# ===========================================================================

class TestBip34PerNetworkActivation:
    """BIP34 is enforced from each network's deployment height, not always 227,931."""

    def _validate_cb(self, network: str, height: int, script_sig: bytes) -> bool:
        """Helper: create a mock-DB BlockValidator and call _validate_coinbase."""
        v = _make_bv(network)
        tx = _make_coinbase_tx(script_sig)
        return v._validate_coinbase(tx, height)

    def test_testnet4_bip34_active_at_height_1(self):
        """testnet4: BIP34 is active from height 1 — correct prefix required."""
        # Height 1 → OP_1 = 0x51
        prefix = _encode_bip34_height(1)
        script_sig = prefix + b"\x00" * 4
        assert self._validate_cb("testnet4", 1, script_sig)

    def test_testnet4_bip34_wrong_prefix_rejected_at_height_1(self):
        """testnet4: wrong prefix at height 1 must fail."""
        # Height 2 → OP_2 = 0x52, but block height is 1
        wrong = bytes([0x52]) + b"\x00" * 4
        assert not self._validate_cb("testnet4", 1, wrong)

    def test_regtest_bip34_active_at_height_1(self):
        """regtest: BIP34 active from height 1."""
        prefix = _encode_bip34_height(1)
        script_sig = prefix + b"\x00" * 4
        assert self._validate_cb("regtest", 1, script_sig)

    def test_mainnet_bip34_inactive_at_height_100000(self):
        """mainnet: BIP34 is NOT active at height 100,000 (below 227,931)."""
        # Arbitrary 2-byte scriptSig should pass since BIP34 not active yet.
        script_sig = b"\xff\xff"  # 2 bytes, passes length check
        assert self._validate_cb("mainnet", 100_000, script_sig)

    def test_mainnet_bip34_active_at_height_227931(self):
        """mainnet: BIP34 active at height 227,931 — correct prefix required."""
        prefix = _encode_bip34_height(227_931)
        script_sig = prefix + b"\x00" * 4
        assert self._validate_cb("mainnet", 227_931, script_sig)

    def test_mainnet_bip34_wrong_prefix_at_activation_height(self):
        """mainnet: wrong prefix at height 227,931 must fail."""
        wrong = _encode_bip34_height(227_930) + b"\x00" * 4
        assert not self._validate_cb("mainnet", 227_931, wrong)


# ===========================================================================
# Gate 10 — Error code is "bad-txns-BIP30" (Core parity)
# ===========================================================================

class TestBip30ErrorCode:
    """The rejection string must contain 'bad-txns-BIP30' matching Core."""

    def test_bip30_error_code_in_rejection(self):
        """When BIP30 triggers, error message must contain 'bad-txns-BIP30'."""
        validator = _make_validator(network="mainnet", utxo_exists=True)
        cb_txid = b"\xf0" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\x40\x0d\x03" + b"\x00" * 6

        block = _make_block(block_hash=b"\xf1" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=200_000)

        assert not ok
        assert err == "bad-txns-BIP30", (
            f"Error code must be exactly 'bad-txns-BIP30', got: {repr(err)}"
        )

    def test_no_bip30_error_when_no_collision(self):
        """When there is no UTXO collision, no BIP30 error is emitted."""
        validator = _make_validator(network="mainnet", utxo_exists=False)
        cb_txid = b"\xf2" * 32
        cb = _make_tx(cb_txid, n_outputs=1, is_coinbase=True)
        cb.inputs[0].script_sig = b"\x03\x40\x0d\x03" + b"\x00" * 6

        block = _make_block(block_hash=b"\xf3" * 32, transactions=[cb])

        with patch.object(validator, "_validate_header", return_value=True), \
             patch.object(validator, "_verify_merkle_root", return_value=True), \
             patch.object(validator, "_validate_block_limits", return_value=(True, "")), \
             patch.object(validator, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(validator, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(validator, "_validate_coinbase", return_value=True), \
             patch.object(validator, "_verify_coinbase_amount", return_value=True), \
             patch.object(validator.db, "get_block", return_value=_make_block(bytes(32), [])):
            ok, err = validator.validate_block(block, known_height=200_000)

        assert ok, f"No UTXO collision should produce no BIP30 error, got: {err}"
        assert err == ""


# ===========================================================================
# BIP34_HASHES / BIP30_REPEAT_EXCEPTIONS correctness
# ===========================================================================

class TestConsensusConstantsCorrectness:
    """Spot-check critical constants against Bitcoin Core source."""

    def test_mainnet_bip34_hash_length(self):
        """BIP34Hash must be 32 bytes."""
        assert len(BIP34_HASHES["mainnet"]) == 32

    def test_mainnet_bip34_hash_starts_with_zeros(self):
        """Mainnet BIP34Hash starts with many zeros (real block hash)."""
        h = BIP34_HASHES["mainnet"].hex()
        # 000000000000024b...
        assert h.startswith("00000000000002"), f"Unexpected hash: {h}"

    def test_testnet3_bip34_hash(self):
        """testnet3 BIP34Hash matches Core kernel/chainparams.cpp:213."""
        expected = bytes.fromhex(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
        )
        assert BIP34_HASHES.get("testnet3") == expected

    def test_repeat_block_91842_hash_prefix(self):
        """Block 91842 exception hash starts with 00000000000a4d0a (Core:6191)."""
        h = BIP30_REPEAT_EXCEPTIONS[91842].hex()
        assert h.startswith("00000000000a4d0a"), f"Unexpected: {h}"

    def test_repeat_block_91880_hash_prefix(self):
        """Block 91880 exception hash starts with 00000000000743f1 (Core:6192)."""
        h = BIP30_REPEAT_EXCEPTIONS[91880].hex()
        assert h.startswith("00000000000743f1"), f"Unexpected: {h}"

    def test_zero_hashes_are_exactly_32_zero_bytes(self):
        """testnet4/signet/regtest BIP34Hash must be exactly 32 zero bytes."""
        for net in ("testnet4", "signet", "regtest"):
            assert BIP34_HASHES[net] == bytes(32), f"{net} BIP34Hash not zero"
