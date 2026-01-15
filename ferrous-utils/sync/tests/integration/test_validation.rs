//! Integration tests for validation modules

use sync::validate::*;
use sync::storage::db::BlockchainDB;
use common::{BlockWrapper, TransactionWrapper, BlockHeaderWrapper};
use bitcoin::{Block, Network, BlockHash};
use bitcoin::hashes::Hash;
use std::sync::Arc;
use tempdir::TempDir;

/// Helper function to create a test database
fn create_test_db() -> (TempDir, Arc<BlockchainDB>) {
    let temp_dir = TempDir::new("test_db").unwrap();
    let db_path = temp_dir.path().to_str().unwrap();
    let db = Arc::new(BlockchainDB::open(db_path).unwrap());
    (temp_dir, db)
}

#[test]
fn test_genesis_block_validation() {
    let (_temp_dir, db) = create_test_db();
    let validator = BlockValidator::new(Arc::clone(&db), Network::Bitcoin);
    
    // Get Bitcoin mainnet genesis block
    let genesis_hash = BlockHash::from_byte_array([
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
        0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
        0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
        0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    
    // TODO: Load actual genesis block and validate
    // This is a placeholder test structure
}

#[test]
fn test_header_chain_validation() {
    let (_temp_dir, db) = create_test_db();
    let validator = HeaderValidator::new(Arc::clone(&db), Network::Bitcoin);
    
    // TODO: Load chain of headers and validate
    // Test with first 100 headers
}

#[test]
fn test_p2pkh_script() {
    // TODO: Test P2PKH script execution
    // Use Bitcoin Core script test vectors
}

#[test]
fn test_transaction_validation() {
    let (_temp_dir, db) = create_test_db();
    let validator = TransactionValidator::new(Arc::clone(&db));
    
    // TODO: Test transaction validation
    // Test with real Bitcoin transactions
}

#[test]
fn test_block_subsidy_calculation() {
    let (_temp_dir, db) = create_test_db();
    let validator = BlockValidator::new(Arc::clone(&db), Network::Bitcoin);
    
    // Test block subsidy at various heights
    assert_eq!(validator.calculate_block_subsidy(0), 50_000_000_000); // 50 BTC
    assert_eq!(validator.calculate_block_subsidy(209999), 50_000_000_000); // Still 50 BTC
    assert_eq!(validator.calculate_block_subsidy(210000), 25_000_000_000); // First halving
    assert_eq!(validator.calculate_block_subsidy(419999), 25_000_000_000); // Still 25 BTC
    assert_eq!(validator.calculate_block_subsidy(420000), 12_500_000_000); // Second halving
}

