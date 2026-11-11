//! A mutated block must fail as MUTATED, never as a size-limit verdict.
//!
//! Item cffix-ouroboros-witness-malleation-before-limits.  Bitcoin Core
//! (src/validation.cpp): `CheckBlock` runs `CheckMerkleRoot` before the size
//! limits, and `ContextualCheckBlock` runs `CheckWitnessMalleation` before the
//! `bad-blk-weight` check.  Both failures are `BLOCK_MUTATED`: the bytes do not
//! match the header, so they say nothing about the block the header names, and
//! Core never caches that hash as invalid.
//!
//! `BlockValidator::validate_block_with_flags` (the Python FFI route,
//! `validate_block_from_bytes`) ran `check_size_limits` -- block weight
//! INCLUDING witness bytes -- before the merkle root and the witness
//! commitment, so a relaying peer that padded an honest block's witness got
//! it rejected as `SizeExceeded`, which ouroboros records as a verdict on the
//! header hash.
//!
//! Every case runs the real validator end to end on regtest (genesis stored in
//! a real RocksDB, PoW solved) so the header gate passes and the order of the
//! body checks is what is measured.

use std::sync::Arc;

use bitcoin::blockdata::block::{Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{
    absolute, transaction, Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use common::{BlockMetadata, BlockWrapper};
use sync::storage::db::BlockchainDB;
use sync::validate::{BlockValidationError, BlockValidator};
use tempdir::TempDir;

const REGTEST_BITS: u32 = 0x207f_ffff;

fn setup() -> (TempDir, Arc<BlockchainDB>, BlockValidator, Block) {
    let dir = TempDir::new("cffix_wmal").unwrap();
    let db = Arc::new(BlockchainDB::open(dir.path().to_str().unwrap()).unwrap());
    let genesis = genesis_block(Network::Regtest);
    let gw = BlockWrapper::new(genesis.clone());
    db.store_block(&gw).unwrap();
    db.store_block_metadata(
        0,
        &genesis.block_hash().to_byte_array(),
        &BlockMetadata::new(0, [0u8; 32], genesis.header.time),
    )
    .unwrap();
    let validator = BlockValidator::new(Arc::clone(&db), Network::Regtest);
    (dir, db, validator, genesis)
}

fn merkle(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                sha256d::Hash::hash(&buf).to_byte_array()
            })
            .collect();
    }
    level[0]
}

fn spend(witness: &[Vec<u8>]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x5a; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from(vec![0x51]) }],
    }
}

/// Coinbase at height 1 committing to the wtxids of `committed` (BIP141),
/// plus an optional extra output script (used to make the block oversized).
fn coinbase(committed: &[Transaction], extra_spk: Option<Vec<u8>>) -> Transaction {
    let mut wtxids = vec![[0u8; 32]];
    wtxids.extend(committed.iter().map(|t| t.compute_wtxid().to_byte_array()));
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&merkle(wtxids));
    let commitment = sha256d::Hash::hash(&buf).to_byte_array(); // nonce = 32 zero bytes
    let mut cspk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    cspk.extend_from_slice(&commitment);
    let mut output = vec![
        TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from(vec![0x51]) },
        TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from(cspk) },
    ];
    if let Some(spk) = extra_spk {
        output.insert(0, TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from(spk) });
    }
    Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // BIP34: CScript() << 1 == OP_1, padded to the 2-byte minimum.
            script_sig: ScriptBuf::from(vec![0x51, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0u8; 32]]),
        }],
        output,
    }
}

/// Assemble + solve a block on `genesis`.  `merkle_override` lets a case put
/// a header merkle root that does not match the transactions.
fn block(genesis: &Block, txdata: Vec<Transaction>, merkle_override: Option<[u8; 32]>) -> Block {
    let root = merkle_override.unwrap_or_else(|| {
        merkle(txdata.iter().map(|t| t.compute_txid().to_byte_array()).collect())
    });
    let mut b = Block {
        header: Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array(root),
            time: genesis.header.time + 600,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txdata,
    };
    let target = b.header.target();
    while !target.is_met_by(b.header.block_hash()) {
        b.header.nonce += 1;
    }
    b
}

fn validate(v: &BlockValidator, b: &Block) -> Result<(), BlockValidationError> {
    v.validate_block_with_flags(&BlockWrapper::new(b.clone()), 0, true)
}

fn honest_witness() -> Vec<Vec<u8>> {
    vec![vec![0x51]]
}

fn padded_witness() -> Vec<Vec<u8>> {
    vec![vec![0u8; 4_000_001], vec![0x51]]
}

#[test]
fn control_honest_coinbase_only_block_is_valid() {
    // The header gate and the coinbase/commitment checks really pass, so the
    // errors below come from the body-check order and not from the harness.
    let (_d, _db, v, g) = setup();
    let b = block(&g, vec![coinbase(&[], None)], None);
    assert!(validate(&v, &b).is_ok(), "{:?}", validate(&v, &b));
}

#[test]
fn oversized_block_with_mismatched_merkle_is_invalid_merkle_root() {
    let (_d, _db, v, g) = setup();
    let cb = coinbase(&[], Some(vec![0x6a; 4_000_001]));
    let b = block(&g, vec![cb], Some([0x42; 32]));
    assert!(b.weight().to_wu() > 4_000_000);
    assert!(matches!(validate(&v, &b), Err(BlockValidationError::InvalidMerkleRoot)),
        "got {:?}", validate(&v, &b));
    // The assumevalid route (`validate_block`) orders the same way.
    assert!(matches!(
        v.validate_block(&BlockWrapper::new(b.clone()), 0),
        Err(BlockValidationError::InvalidMerkleRoot)
    ));
}

#[test]
fn witness_padded_copy_is_witness_commitment_mismatch() {
    let (_d, _db, v, g) = setup();
    let honest_spend = spend(&honest_witness());
    let cb = coinbase(&[honest_spend.clone()], None);
    let honest = block(&g, vec![cb.clone(), honest_spend], None);
    let padded = block(&g, vec![cb, spend(&padded_witness())], None);
    // Same txids, same header: the padded copy names the honest block.
    assert_eq!(padded.header.merkle_root, honest.header.merkle_root);
    assert!(padded.weight().to_wu() > 4_000_000);
    assert!(
        matches!(validate(&v, &padded), Err(BlockValidationError::WitnessCommitmentMismatch)),
        "got {:?}",
        validate(&v, &padded)
    );
}

#[test]
fn control_committed_overweight_block_is_still_size_exceeded() {
    // NEGATIVE CONTROL for the reorder: a block whose coinbase COMMITS to the
    // overweight witness is not mutated -- it is genuinely too heavy and must
    // still be rejected on weight.
    let (_d, _db, v, g) = setup();
    let fat = spend(&padded_witness());
    let b = block(&g, vec![coinbase(&[fat.clone()], None), fat], None);
    assert!(b.weight().to_wu() > 4_000_000);
    assert!(matches!(validate(&v, &b), Err(BlockValidationError::SizeExceeded)),
        "got {:?}", validate(&v, &b));
}
