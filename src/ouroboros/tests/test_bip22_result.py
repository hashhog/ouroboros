"""
BIP-22 submitblock result string mapping tests.

Verifies that bip22_result_string() maps internal Rust/Python validation
error strings to the canonical BIP-22 result strings:
  https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki

Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp
"""

import pytest
from ouroboros.rpc import bip22_result_string


class TestBip22ResultString:
    """Unit tests for bip22_result_string() in rpc.py."""

    def test_already_canonical_high_hash(self):
        assert bip22_result_string("high-hash") == "high-hash"

    def test_already_canonical_duplicate(self):
        assert bip22_result_string("duplicate") == "duplicate"

    def test_already_canonical_rejected(self):
        assert bip22_result_string("rejected") == "rejected"

    def test_already_canonical_inconclusive(self):
        assert bip22_result_string("inconclusive") == "inconclusive"

    def test_already_canonical_bad_txnmrklroot(self):
        assert bip22_result_string("bad-txnmrklroot") == "bad-txnmrklroot"

    def test_already_canonical_bad_witness_merkle_match(self):
        assert bip22_result_string("bad-witness-merkle-match") == "bad-witness-merkle-match"

    def test_already_canonical_bad_cb_amount(self):
        assert bip22_result_string("bad-cb-amount") == "bad-cb-amount"

    def test_already_canonical_bad_blk_sigops(self):
        assert bip22_result_string("bad-blk-sigops") == "bad-blk-sigops"

    def test_already_canonical_bad_cb_height(self):
        assert bip22_result_string("bad-cb-height") == "bad-cb-height"

    def test_already_canonical_bad_txns_nonfinal(self):
        assert bip22_result_string("bad-txns-nonfinal") == "bad-txns-nonfinal"

    def test_pow_validation_failed(self):
        # HeaderValidationError::InvalidPow #[error("Proof of work validation failed")]
        assert bip22_result_string("Proof of work validation failed") == "high-hash"

    def test_invalid_difficulty(self):
        # HeaderValidationError::InvalidDifficulty #[error("Difficulty does not match expected value")]
        assert bip22_result_string("Difficulty does not match expected value") == "high-hash"

    def test_invalid_merkle_root(self):
        # BlockValidationError::InvalidMerkleRoot #[error("Invalid merkle root")]
        assert bip22_result_string("Invalid merkle root") == "bad-txnmrklroot"

    def test_witness_commitment_mismatch(self):
        # BlockValidationError::WitnessCommitmentMismatch #[error("BIP141: witness commitment mismatch")]
        assert bip22_result_string("BIP141: witness commitment mismatch") == "bad-witness-merkle-match"

    def test_missing_witness_commitment(self):
        # BlockValidationError::MissingWitnessCommitment
        assert bip22_result_string("BIP141: block has witness data but no witness commitment") == "bad-witness-merkle-match"

    def test_invalid_coinbase_witness_nonce(self):
        # BlockValidationError::InvalidCoinbaseWitnessNonce
        assert bip22_result_string("BIP141: coinbase witness must be exactly one 32-byte item") == "bad-witness-merkle-match"

    def test_coinbase_amount_exceeded(self):
        # BlockValidationError::CoinbaseAmountExceeded #[error("Coinbase amount exceeds subsidy + fees")]
        assert bip22_result_string("Coinbase amount exceeds subsidy + fees") == "bad-cb-amount"

    def test_too_many_sigops(self):
        # BlockValidationError::TooManySigops #[error("Total sigops exceeds limit")]
        assert bip22_result_string("Total sigops exceeds limit") == "bad-blk-sigops"

    def test_sequence_lock_not_satisfied(self):
        # BlockValidationError::InvalidSequenceLock
        assert bip22_result_string("BIP68: sequence lock not satisfied") == "bad-txns-nonfinal"

    def test_bip30_duplicate_txid(self):
        # BlockValidationError::Bip30DuplicateTxid
        assert bip22_result_string("BIP30: duplicate unspent txid") == "bad-txns-duplicate"

    def test_duplicate_transaction(self):
        # BlockValidationError::DuplicateTransaction
        assert bip22_result_string("Duplicate transaction detected") == "bad-txns-duplicate"

    def test_missing_utxo_for_input(self):
        # BlockValidationError::Bip68MissingUtxo
        assert bip22_result_string("BIP68: missing UTXO for input 0") == "bad-txns-inputs-missingorspent"

    def test_transaction_validation_error(self):
        # BlockValidationError::TransactionValidation wraps script errors
        assert bip22_result_string("Transaction validation error: script verify failed") == "mandatory-script-verify-flag-failed"

    def test_previous_block_not_found(self):
        # BlockValidationError::PreviousBlockNotFound → inconclusive (orphan)
        assert bip22_result_string("Previous block not found") == "inconclusive"

    def test_timestamp_too_far_future(self):
        # HeaderValidationError::TimestampTooFarFuture
        assert bip22_result_string("Timestamp too far in the future") == "time-too-new"

    def test_timestamp_before_median(self):
        # HeaderValidationError::TimestampBeforeMedian
        assert bip22_result_string("Timestamp not greater than median time past") == "time-too-old"

    def test_unknown_error_returns_rejected(self):
        assert bip22_result_string("some totally unexpected error") == "rejected"
        assert bip22_result_string("ENOENT") == "rejected"
        assert bip22_result_string("") == "rejected"

    def test_case_insensitive_matching(self):
        # Error strings from Rust are title-case; function should handle any case
        assert bip22_result_string("PROOF OF WORK VALIDATION FAILED") == "high-hash"
        assert bip22_result_string("invalid merkle root") == "bad-txnmrklroot"
