//! The Rust proof-of-work check must be Core's, flags included.
//!
//! Item psweep-ouroboros-rust-bits-to-target-flags.  Bitcoin Core v31.1:
//!
//! * `arith_uint256::SetCompact` (src/arith_uint256.cpp) decodes nBits and
//!   reports `fNegative` (sign bit set on a non-zero mantissa) and
//!   `fOverflow` (the target does not fit in 256 bits).
//! * `DeriveTarget` / `CheckProofOfWorkImpl` (src/pow.cpp) reject a
//!   negative, zero, overflowing or above-powLimit target before the hash is
//!   compared at all.
//! * `GetBitsProof` (src/chain.cpp) gives such bits zero work.
//!
//! ouroboros' Rust decoder (`common::crypto::bits_to_target`) masked the sign
//! bit away and had no overflow flag, and the header validator compared the
//! hash against that value with no range check, so nBits 0x2080ffff (a
//! negative target) with a low hash passed the Rust PoW gate, and the header
//! presync and chainwork code counted real work for it.
//!
//! Vectors: Core's `bignum_SetCompact` (src/test/arith_uint256_tests.cpp) and
//! the `CheckProofOfWork_test_*` cases (src/test/pow_tests.cpp), plus the
//! regtest inputs the item names.

use std::sync::Arc;

use bitcoin::blockdata::block::{Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Network, TxMerkleNode};
use common::crypto::{double_sha256, set_compact};
use common::BlockHeaderWrapper;
use primitive_types::U256;
use sync::chain_params::pow_limit;
use sync::chainwork::{bytes_to_chainwork, compute_chainwork};
use sync::storage::db::BlockchainDB;
use sync::validate::headers_presync::HeadersSyncState;
use sync::validate::pow::{check_proof_of_work, get_bits_proof};
use sync::validate::{HeaderValidationError, HeaderValidator};
use tempdir::TempDir;

const REGTEST_BITS: u32 = 0x207f_ffff;

/// `uint256{n}` in internal byte order (what double-SHA256 returns).
fn hash_of(n: U256) -> [u8; 32] {
    n.to_little_endian()
}

fn hex(n: U256) -> String {
    format!("{:064x}", n)
}

/// The bits every check below must refuse, with the reason Core refuses them.
const BAD_BITS_REGTEST: &[(u32, &str)] = &[
    (0x2080_ffff, "negative (item input)"),
    (0x1d80_ffff, "negative (Core CheckProofOfWork_test_negative_target)"),
    (0x0480_0001, "negative, small"),
    (0x2201_0000, "overflow: mantissa > 0xffff at size 34 (item input)"),
    (0x2300_0001, "overflow: size 35 (item input)"),
    (0xff7f_ffff, "overflow (Core CheckProofOfWork_test_overflow_target)"),
    (0x0400_0000, "zero mantissa"),
    (0x0000_0000, "zero (Core CheckProofOfWork_test_zero_target)"),
    (0x0300_0000, "zero mantissa, size 3"),
    (0x0100_3456, "mantissa shifted to zero"),
];

// ---------------------------------------------------------------------------
// SetCompact
// ---------------------------------------------------------------------------

#[test]
fn set_compact_matches_core_bignum_setcompact_vectors() {
    // (nCompact, GetHex() or None where Core does not check the value,
    //  fNegative, fOverflow) -- src/test/arith_uint256_tests.cpp.
    let zero = "0".repeat(64);
    let cases: &[(u32, Option<&str>, bool, bool)] = &[
        (0x0000_0000, Some(&zero), false, false),
        (0x0012_3456, Some(&zero), false, false),
        (0x0100_3456, Some(&zero), false, false),
        (0x0200_0056, Some(&zero), false, false),
        (0x0300_0000, Some(&zero), false, false),
        (0x0400_0000, Some(&zero), false, false),
        (0x0092_3456, Some(&zero), false, false),
        (0x0180_3456, Some(&zero), false, false),
        (0x0280_0056, Some(&zero), false, false),
        (0x0380_0000, Some(&zero), false, false),
        (0x0480_0000, Some(&zero), false, false),
        (0x0112_3456, Some("0000000000000000000000000000000000000000000000000000000000000012"), false, false),
        (0x01fe_dcba, Some("000000000000000000000000000000000000000000000000000000000000007e"), true, false),
        (0x0212_3456, Some("0000000000000000000000000000000000000000000000000000000000001234"), false, false),
        (0x0312_3456, Some("0000000000000000000000000000000000000000000000000000000000123456"), false, false),
        (0x0412_3456, Some("0000000000000000000000000000000000000000000000000000000012345600"), false, false),
        (0x0492_3456, Some("0000000000000000000000000000000000000000000000000000000012345600"), true, false),
        (0x0500_9234, Some("0000000000000000000000000000000000000000000000000000000092340000"), false, false),
        (0x2012_3456, Some("1234560000000000000000000000000000000000000000000000000000000000"), false, false),
        (0xff12_3456, None, false, true),
    ];
    for &(bits, want_hex, want_neg, want_ovf) in cases {
        let (target, negative, overflow) = set_compact(bits);
        if let Some(h) = want_hex {
            assert_eq!(hex(target), h, "SetCompact({bits:#010x}) value");
        }
        assert_eq!(negative, want_neg, "SetCompact({bits:#010x}) fNegative");
        assert_eq!(overflow, want_ovf, "SetCompact({bits:#010x}) fOverflow");
    }
}

#[test]
fn set_compact_flags_the_item_inputs() {
    let (_, neg, ovf) = set_compact(0x2080_ffff);
    assert!(neg && !ovf, "0x2080ffff: negative, not overflow");
    let (_, neg, ovf) = set_compact(0x2201_0000);
    assert!(!neg && ovf, "0x22010000: overflow");
    let (_, neg, ovf) = set_compact(0x2300_0001);
    assert!(!neg && ovf, "0x23000001: overflow");
    // Boundaries of Core's overflow rule: these still fit.
    for bits in [0x2200_00ffu32, 0x2100_ffff, 0x2200_0001, REGTEST_BITS, 0x1d00_ffff] {
        let (_, neg, ovf) = set_compact(bits);
        assert!(!neg && !ovf, "{bits:#010x} is neither negative nor overflow");
    }
}

#[test]
fn set_compact_value_for_wide_exponents_is_cores() {
    // Core shifts a 256-bit integer: everything shifted past bit 255 is gone.
    // (The old decoder computed `8 * (exponent - 3)` in u8, which wrapped
    // for exponent >= 35: 0x23000001 became 1 instead of 0.)
    assert_eq!(set_compact(0x2300_0001).0, U256::zero());
    assert_eq!(set_compact(0xff12_3456).0, U256::zero());
    assert_eq!(set_compact(0x2200_0001).0, U256::one() << 248);
    assert_eq!(set_compact(0x2201_0000).0, U256::zero());
}

// ---------------------------------------------------------------------------
// CheckProofOfWork
// ---------------------------------------------------------------------------

#[test]
fn check_pow_rejects_negative_overflow_and_zero_bits() {
    for network in [Network::Regtest, Network::Bitcoin] {
        let limit = pow_limit(network);
        for &(bits, why) in BAD_BITS_REGTEST {
            for h in [U256::zero(), U256::one()] {
                assert!(
                    !check_proof_of_work(&hash_of(h), bits, limit),
                    "{network:?}: bits {bits:#010x} ({why}) with hash {h} must fail CheckProofOfWork"
                );
            }
        }
    }
}

#[test]
fn check_pow_rejects_negative_regtest_bits_with_a_low_hash() {
    // The item's input: nBits 0x2080ffff and a hash below 0xffff << 232
    // (about 1 in 128 hashes).  The masked target is 0xffff << 232, so the
    // old check passed it.
    let hash = (U256::from(0xffffu32) << 232) - U256::one();
    assert!(!check_proof_of_work(&hash_of(hash), 0x2080_ffff, pow_limit(Network::Regtest)));
}

#[test]
fn check_pow_rejects_a_target_above_pow_limit() {
    // Core CheckProofOfWork_test_too_easy_target: powLimit * 2, compacted.
    assert!(!check_proof_of_work(&hash_of(U256::one()), 0x1d01_ffff, pow_limit(Network::Bitcoin)));
    // Regtest powLimit + 1 = 2^255, compact 0x21008000.
    assert!(!check_proof_of_work(&hash_of(U256::one()), 0x2100_8000, pow_limit(Network::Regtest)));
    // Signet's limit is exact: one mantissa step above it fails.
    assert!(!check_proof_of_work(&hash_of(U256::one()), 0x1e03_77af, pow_limit(Network::Signet)));
}

#[test]
fn check_pow_accepts_valid_targets() {
    // A valid block must stay valid: the powLimit itself, harder targets,
    // and a hash equal to the target all pass, as in Core.
    let cases = [
        (Network::Regtest, REGTEST_BITS),
        (Network::Bitcoin, 0x1d00_ffff),
        (Network::Bitcoin, 0x1702_8c61), // a mainnet-range nBits
        (Network::Testnet4, 0x1d00_ffff),
        (Network::Signet, 0x1e03_77ae),
    ];
    for (network, bits) in cases {
        let limit = pow_limit(network);
        let (target, _, _) = set_compact(bits);
        assert!(check_proof_of_work(&hash_of(U256::one()), bits, limit), "{network:?} {bits:#010x} low hash");
        assert!(check_proof_of_work(&hash_of(target), bits, limit), "{network:?} {bits:#010x} hash == target");
        // Core CheckProofOfWork_test_biger_hash_than_target.
        assert!(!check_proof_of_work(&hash_of(target + U256::one()), bits, limit), "{network:?} {bits:#010x} hash > target");
    }
}

#[test]
fn pow_limit_is_cores_full_uint256() {
    assert_eq!(hex(pow_limit(Network::Bitcoin)), "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert_eq!(hex(pow_limit(Network::Testnet4)), "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert_eq!(hex(pow_limit(Network::Regtest)), "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert_eq!(hex(pow_limit(Network::Signet)), "00000377ae000000000000000000000000000000000000000000000000000000");
}

// ---------------------------------------------------------------------------
// GetBlockProof (work)
// ---------------------------------------------------------------------------

#[test]
fn bits_proof_is_zero_for_negative_overflow_and_zero_bits() {
    for &(bits, why) in BAD_BITS_REGTEST {
        assert_eq!(get_bits_proof(bits), U256::zero(), "GetBitsProof({bits:#010x}) ({why}) must be 0");
    }
}

#[test]
fn bits_proof_matches_core_for_valid_bits() {
    // Regtest blocks carry 2 work each; mainnet difficulty 1 is 0x100010001.
    assert_eq!(get_bits_proof(REGTEST_BITS), U256::from(2u32));
    assert_eq!(get_bits_proof(0x1d00_ffff), U256::from(0x1_0001_0001u64));
    // Core's GetBitsProof has no powLimit test: above-limit bits still count.
    assert_ne!(get_bits_proof(0x2100_8000), U256::zero());
}

#[test]
fn chainwork_adds_no_work_for_negative_bits() {
    let prev = compute_chainwork(&[0u8; 32], REGTEST_BITS);
    for &(bits, why) in BAD_BITS_REGTEST {
        let next = compute_chainwork(&prev, bits);
        assert_eq!(
            bytes_to_chainwork(&next),
            bytes_to_chainwork(&prev),
            "chainwork must not grow for bits {bits:#010x} ({why})"
        );
    }
}

#[test]
fn presync_counts_no_work_for_negative_bits() {
    // Regtest allows min-difficulty, so PermittedDifficultyTransition passes
    // any nBits; only the work function decides what the header adds.
    let mut state = HeadersSyncState::new(Network::Regtest, [0u8; 32], 0, REGTEST_BITS, 0);
    let header = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1000,
        bits: CompactTarget::from_consensus(0x2080_ffff),
        nonce: 0,
    };
    let result = state.process_headers(&[header], false);
    assert!(result.success, "{:?}", result.error);
    assert_eq!(state.presync_height(), 1);
    assert_eq!(state.presync_work(), U256::zero(), "a negative-target header adds no work");
}

// ---------------------------------------------------------------------------
// The real call site: HeaderValidator::validate_header on regtest
// ---------------------------------------------------------------------------

/// Mine a regtest child of `prev` whose hash meets `target` (or, with
/// `meet = false`, misses it).
fn mine(prev: &Header, bits: u32, target: U256, meet: bool) -> Header {
    let mut h = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: prev.block_hash(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: prev.time + 1,
        bits: CompactTarget::from_consensus(bits),
        nonce: 0,
    };
    loop {
        let hash = U256::from_little_endian(&double_sha256(&BlockHeaderWrapper::new(h).to_bytes()));
        if (hash <= target) == meet {
            return h;
        }
        h.nonce += 1;
    }
}

#[test]
fn validate_header_accepts_a_valid_regtest_header_and_rejects_a_high_hash() {
    let dir = TempDir::new("psweep_bits").unwrap();
    let db = Arc::new(BlockchainDB::open(dir.path().to_str().unwrap()).unwrap());
    let validator = HeaderValidator::new(db, Network::Regtest);
    let genesis = genesis_block(Network::Regtest).header;
    let (target, _, _) = set_compact(REGTEST_BITS);

    let good = mine(&genesis, REGTEST_BITS, target, true);
    validator
        .validate_header(&BlockHeaderWrapper::new(good), &BlockHeaderWrapper::new(genesis), 0)
        .expect("a regtest header meeting powLimit is valid");

    let bad = mine(&genesis, REGTEST_BITS, target, false);
    let err = validator
        .validate_header(&BlockHeaderWrapper::new(bad), &BlockHeaderWrapper::new(genesis), 0)
        .unwrap_err();
    assert!(matches!(err, HeaderValidationError::InvalidPow), "{err:?}");
}

#[test]
fn validate_header_rejects_negative_bits_on_regtest() {
    // Today bad-diffbits (step 4) catches this first; the verdict must stay a
    // rejection whichever gate fires.
    let dir = TempDir::new("psweep_bits_neg").unwrap();
    let db = Arc::new(BlockchainDB::open(dir.path().to_str().unwrap()).unwrap());
    let validator = HeaderValidator::new(db, Network::Regtest);
    let genesis = genesis_block(Network::Regtest).header;
    let (masked, _, _) = set_compact(0x2080_ffff);
    let neg = mine(&genesis, 0x2080_ffff, masked, true);
    assert!(validator
        .validate_header(&BlockHeaderWrapper::new(neg), &BlockHeaderWrapper::new(genesis), 0)
        .is_err());
}
