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
        #   #[error("BIP141: block has witness data but no witness commitment")]
        # This is Core's CheckWitnessMalleation NO_WITNESS_COMMITMENT case:
        # a witness-bearing block with no coinbase commitment output is
        # rejected as "unexpected-witness" (validation.cpp:3905-3913), NOT
        # bad-witness-merkle-match (which is the commitment-*present*-but-
        # mismatched case). Regression guard for the substring mis-map.
        assert bip22_result_string("BIP141: block has witness data but no witness commitment") == "unexpected-witness"
        # The Rust CheckBlock also prefixes this variant with a "bad-witness-
        # merkle-match:" label in one path; the mapper must still yield the
        # Core-exact token.
        assert bip22_result_string("bad-witness-merkle-match: block has witness data but no witness commitment") == "unexpected-witness"

    def test_invalid_coinbase_witness_nonce(self):
        # BlockValidationError::InvalidCoinbaseWitnessNonce
        # Core's CheckWitnessMalleation rejects a coinbase witness stack that
        # is not exactly one 32-byte item as "bad-witness-nonce-size"
        # (validation.cpp:3878-3886) BEFORE the commitment-hash compare.
        # The old expectation (bad-witness-merkle-match) encoded the mis-map
        # the bwmc corpus flagged (C7-reserved-nonce-31-bytes, 2026-08-10).
        assert bip22_result_string("BIP141: coinbase witness must be exactly one 32-byte item") == "bad-witness-nonce-size"
        # Bare Core token round-trips unchanged.
        assert bip22_result_string("bad-witness-nonce-size") == "bad-witness-nonce-size"

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
        # BlockValidationError::Bip30DuplicateTxid. Core's ConnectBlock BIP30
        # gate reports "bad-txns-BIP30" (validation.cpp:2471), NOT
        # "bad-txns-duplicate" (which is the CheckTransaction in-block dup-vin
        # token). Corpus: version-dup/bip30-duplicate-txid-reject.
        assert bip22_result_string("BIP30: duplicate unspent txid") == "bad-txns-BIP30"
        # The Python validator emits the token directly; it must round-trip too.
        assert bip22_result_string("bad-txns-BIP30") == "bad-txns-BIP30"

    def test_duplicate_transaction(self):
        # BlockValidationError::DuplicateTransaction — Core parity (bad-txns-inputs-missingorspent)
        # Core reaches ConnectBlock prevout-already-spent for the same block.
        assert bip22_result_string("Duplicate transaction detected") == "bad-txns-inputs-missingorspent"

    def test_missing_utxo_for_input(self):
        # BlockValidationError::Bip68MissingUtxo
        assert bip22_result_string("BIP68: missing UTXO for input 0") == "bad-txns-inputs-missingorspent"

    def test_input_not_found_maps_to_missingorspent(self):
        # Issue #119: a missing/absent prevout surfaces from ouroboros as
        # "Input not found: <txid>:<vout>" (validation.py CheckTxInputs) and as
        # the Rust TransactionValidationError::InputNotFound ("InputNotFound").
        # Both are the Core CheckTxInputs "bad-txns-inputs-missingorspent" class
        # (consensus/tx_verify.cpp) and MUST NOT fall through to the generic
        # "transaction validation" script-verify catch-all (which would wrongly
        # yield block-script-verify-flag-failed).
        assert bip22_result_string("Input not found: abcd:0") == "bad-txns-inputs-missingorspent"
        assert bip22_result_string("InputNotFound") == "bad-txns-inputs-missingorspent"
        assert bip22_result_string("input not found") == "bad-txns-inputs-missingorspent"
        assert bip22_result_string("Transaction validation error: InputNotFound") == "bad-txns-inputs-missingorspent"
        assert bip22_result_string("prevout not found in utxo set") == "bad-txns-inputs-missingorspent"

    def test_transaction_validation_error(self):
        # BlockValidationError::TransactionValidation wraps script errors
        assert bip22_result_string("Transaction validation error: script verify failed") == "mandatory-script-verify-flag-failed"

    def test_checktransaction_bare_tokens_round_trip(self):
        # CheckTransaction (consensus/tx_check.cpp) tokens are already Core-exact
        # when emitted by the Python validator / accept_block refinement pass and
        # must survive the normaliser verbatim. In particular
        # "bad-txns-inputs-duplicate" contains the "tx"+"duplicate" substrings
        # that the CVE-2012-2459 in-block-dup rule keys on, so without an explicit
        # pass-through it would be mis-mapped to bad-txns-inputs-missingorspent.
        for tok in (
            "bad-txns-vout-empty", "bad-txns-vin-empty",
            "bad-txns-inputs-duplicate", "bad-txns-oversize",
            "bad-txns-vout-negative", "bad-txns-vout-toolarge",
            "bad-txns-txouttotal-toolarge", "bad-txns-prevout-null",
            "bad-cb-length",
        ):
            assert bip22_result_string(tok) == tok

    def test_bad_version_tokens_round_trip(self):
        # ContextualCheckBlockHeader bad-version, strprintf("bad-version(0x%08x)").
        # The signed/unsigned discriminators (high-bit, -1) must render unsigned.
        assert bip22_result_string("bad-version(0x00000001)") == "bad-version(0x00000001)"
        assert bip22_result_string("bad-version(0x80000000)") == "bad-version(0x80000000)"
        assert bip22_result_string("bad-version(0xffffffff)") == "bad-version(0xffffffff)"

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
