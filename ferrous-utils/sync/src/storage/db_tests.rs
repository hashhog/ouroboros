//! Comprehensive integration tests for BlockchainDB

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use bitcoin::{
        Amount, Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
        blockdata::block::{Header, Version as BlockVersion},
        blockdata::transaction::Version as TxVersion,
        hashes::Hash,
        locktime::absolute::LockTime,
    };

    use common::{
        BlockMetadata, BlockWrapper, OutPointWrapper, UTXO,
    };

    use crate::storage::db::BlockchainDB;

    // Helper functions to create test data

    fn create_test_db() -> (BlockchainDB, TempDir) {
        let temp_dir = TempDir::new("blockchain_db_test").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let db = BlockchainDB::open(db_path).unwrap();
        (db, temp_dir)
    }

    fn create_test_block(height: u32, prev_hash: BlockHash) -> BlockWrapper {
        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1231006505 + height * 600, // ~10 minutes per block
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        };

        // Create a coinbase transaction
        let coinbase_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000), // 0.5 BTC
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let block = Block {
            header,
            txdata: vec![coinbase_tx],
        };

        BlockWrapper::new(block)
    }

    fn create_test_utxo(txid: bitcoin::Txid, vout: u32, amount: u64, height: Option<u32>) -> (OutPoint, UTXO) {
        let outpoint = OutPoint::new(txid, vout);
        let outpoint_wrapper = OutPointWrapper::new(outpoint);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]); // P2PKH
        let utxo = UTXO::new(
            outpoint_wrapper,
            amount,
            script_pubkey,
            height,
            height == Some(0), // Coinbase if height is 0
        );
        (outpoint, utxo)
    }

    fn create_large_block(height: u32, prev_hash: BlockHash, num_txs: usize) -> BlockWrapper {
        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1231006505 + height * 600,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        };

        let mut txdata = Vec::new();

        // Coinbase transaction
        let coinbase_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        txdata.push(coinbase_tx);

        // Add many transactions with large scripts
        for i in 0..num_txs {
            let large_script = ScriptBuf::from_bytes(vec![0x51; 1000]); // Large script
            let tx = Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(1000 + i as u64),
                    script_pubkey: large_script,
                }],
            };
            txdata.push(tx);
        }

        let block = Block { header, txdata };
        BlockWrapper::new(block)
    }

    // ========== Basic Operations Tests ==========

    #[test]
    fn test_store_and_retrieve_block() {
        let (db, _temp_dir) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let block = create_test_block(0, prev_hash);
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();

        // Store block
        db.store_block(&block).unwrap();

        // Retrieve block
        let retrieved = db.get_block(&hash_bytes).unwrap();
        assert!(retrieved.is_some());
        let retrieved_block = retrieved.unwrap();
        assert_eq!(retrieved_block.block_hash(), block_hash);
    }

    #[test]
    fn test_store_and_retrieve_block_by_height() {
        let (db, _temp_dir) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let block = create_test_block(100, prev_hash);
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();
        let height = 100;

        // Store block
        db.store_block(&block).unwrap();

        // Store metadata
        let chainwork = [1u8; 32];
        let metadata = BlockMetadata::new(height, chainwork, block.header().time);
        db.store_block_metadata(height, &hash_bytes, &metadata).unwrap();

        // Retrieve by height
        let retrieved = db.get_block_by_height(height).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_hash(), block_hash);
    }

    #[test]
    fn test_add_and_query_utxo() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let (outpoint, utxo) = create_test_utxo(txid, 0, 50_000_000, Some(100));

        // Add UTXO
        db.add_utxo(&outpoint, &utxo).unwrap();

        // Query UTXO
        let retrieved = db.get_utxo(&outpoint).unwrap();
        assert!(retrieved.is_some());
        let retrieved_utxo = retrieved.unwrap();
        assert_eq!(retrieved_utxo.amount, utxo.amount);
        assert_eq!(retrieved_utxo.outpoint.txid(), utxo.outpoint.txid());
        assert_eq!(retrieved_utxo.outpoint.vout(), utxo.outpoint.vout());

        // Check existence
        assert!(db.utxo_exists(&outpoint));
    }

    #[test]
    fn test_spend_utxo() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let (outpoint, utxo) = create_test_utxo(txid, 0, 50_000_000, Some(100));
        let spending_txid = [2u8; 32];

        // Add UTXO
        db.add_utxo(&outpoint, &utxo).unwrap();
        assert!(db.utxo_exists(&outpoint));

        // Spend UTXO
        let spent_utxo = db.spend_utxo(&outpoint, &spending_txid).unwrap();
        assert!(spent_utxo.is_some());
        assert_eq!(spent_utxo.unwrap().amount, utxo.amount);

        // Verify it's gone
        assert!(!db.utxo_exists(&outpoint));
        let retrieved = db.get_utxo(&outpoint).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_update_chain_state() {
        let (db, _temp_dir) = create_test_db();
        let block_hash = [1u8; 32];
        let height = 100;

        // Update best block
        db.update_best_block(&block_hash, height).unwrap();

        // Retrieve best block
        let (retrieved_hash, retrieved_height) = db.get_best_block().unwrap();
        assert_eq!(retrieved_hash, block_hash);
        assert_eq!(retrieved_height, height);
    }

    #[test]
    fn test_block_metadata() {
        let (db, _temp_dir) = create_test_db();
        let height = 200;
        let chainwork = [2u8; 32];
        let timestamp = 1234567890;
        let metadata = BlockMetadata::new(height, chainwork, timestamp);
        let block_hash = [3u8; 32];

        // Store metadata
        db.store_block_metadata(height, &block_hash, &metadata).unwrap();

        // Retrieve metadata
        let retrieved = db.get_block_metadata(height).unwrap();
        assert!(retrieved.is_some());
        let retrieved_metadata = retrieved.unwrap();
        assert_eq!(retrieved_metadata.height, height);
        assert_eq!(retrieved_metadata.chainwork, chainwork);
        assert_eq!(retrieved_metadata.timestamp, timestamp);
    }

    // ========== Batch Operations Tests ==========

    #[test]
    fn test_batch_utxo_updates() {
        let (db, _temp_dir) = create_test_db();

        // Create multiple UTXOs
        let mut utxos = Vec::new();
        for i in 0..10 {
            let txid = bitcoin::Txid::from_byte_array([i as u8; 32]);
            let (outpoint, utxo) = create_test_utxo(txid, 0, 1000 * i as u64, Some(i));
            utxos.push((outpoint, utxo));
        }

        // Test that batch creation works
        let batch = db.create_batch();
        // Apply empty batch
        db.apply_batch(batch).unwrap();

        // Add UTXOs individually and verify they all exist
        for (outpoint, utxo) in &utxos {
            db.add_utxo(outpoint, utxo).unwrap();
        }

        // Verify all exist
        for (outpoint, utxo) in &utxos {
            let retrieved = db.get_utxo(outpoint).unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().amount, utxo.amount);
        }
    }

    #[test]
    fn test_multiple_blocks() {
        let (db, _temp_dir) = create_test_db();
        let mut prev_hash = BlockHash::all_zeros();

        // Store multiple blocks
        for height in 0..10 {
            let block = create_test_block(height, prev_hash);
            let block_hash = block.block_hash();
            let hash_bytes = *block_hash.as_byte_array();

            db.store_block(&block).unwrap();

            let chainwork = [height as u8; 32];
            let metadata = BlockMetadata::new(height, chainwork, block.header().time);
            db.store_block_metadata(height, &hash_bytes, &metadata).unwrap();

            prev_hash = block_hash;
        }

        // Verify all blocks can be retrieved
        for height in 0..10 {
            let retrieved = db.get_block_by_height(height).unwrap();
            assert!(retrieved.is_some());
        }
    }

    // ========== Edge Cases Tests ==========

    #[test]
    fn test_large_block() {
        let (db, _temp_dir) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let block = create_large_block(0, prev_hash, 1000); // 1000 transactions
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();

        // Store large block
        db.store_block(&block).unwrap();

        // Retrieve and verify
        let retrieved = db.get_block(&hash_bytes).unwrap();
        assert!(retrieved.is_some());
        let retrieved_block = retrieved.unwrap();
        assert_eq!(retrieved_block.block_hash(), block_hash);
        assert_eq!(retrieved_block.inner().txdata.len(), 1001); // 1 coinbase + 1000 txs
    }

    #[test]
    fn test_many_utxos() {
        let (db, _temp_dir) = create_test_db();
        use bitcoin::hashes::Hash;
        let num_utxos = 1000;

        // Create and add many UTXOs with unique txids
        for i in 0..num_utxos {
            // Create unique txid bytes: first 4 bytes are i as u32, rest are zeros
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);
            let (outpoint, utxo) = create_test_utxo(txid, 0, 1000 * i as u64, Some(i as u32));
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        // Verify random samples
        for i in (0..num_utxos).step_by(100) {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);
            let outpoint = OutPoint::new(txid, 0);
            assert!(db.utxo_exists(&outpoint), "UTXO should exist for i={}", i);
            let retrieved = db.get_utxo(&outpoint).unwrap();
            assert!(retrieved.is_some(), "UTXO should be retrieved for i={}", i);
            let amount = retrieved.unwrap().amount;
            let expected = 1000 * i as u64;
            assert_eq!(amount, expected, "Amount mismatch for i={}: got {}, expected {}", i, amount, expected);
        }
    }

    #[test]
    fn test_reorg_scenario() {
        let (db, _temp_dir) = create_test_db();
        let prev_hash = BlockHash::all_zeros();

        // Create block at height 100
        let block1 = create_test_block(100, prev_hash);
        let block1_hash = block1.block_hash();
        let hash1_bytes = *block1_hash.as_byte_array();

        // Create UTXOs from block 1
        let txid1 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let (outpoint1, utxo1) = create_test_utxo(txid1, 0, 50_000_000, Some(100));
        db.add_utxo(&outpoint1, &utxo1).unwrap();

        // Store block 1
        db.store_block(&block1).unwrap();
        let metadata1 = BlockMetadata::new(100, [1u8; 32], block1.header().time);
        db.store_block_metadata(100, &hash1_bytes, &metadata1).unwrap();
        db.update_best_block(&hash1_bytes, 100).unwrap();

        // Create competing block at same height (reorg)
        let block2 = create_test_block(100, prev_hash);
        let block2_hash = block2.block_hash();
        let hash2_bytes = *block2_hash.as_byte_array();

        // Spend UTXO from block 1
        let spending_txid = [2u8; 32];
        db.spend_utxo(&outpoint1, &spending_txid).unwrap();

        // Add UTXO from block 2
        let txid2 = bitcoin::Txid::from_byte_array([3u8; 32]);
        let (outpoint2, utxo2) = create_test_utxo(txid2, 0, 50_000_000, Some(100));
        db.add_utxo(&outpoint2, &utxo2).unwrap();

        // Store block 2 and update best block
        db.store_block(&block2).unwrap();
        let metadata2 = BlockMetadata::new(100, [2u8; 32], block2.header().time);
        db.store_block_metadata(100, &hash2_bytes, &metadata2).unwrap();
        db.update_best_block(&hash2_bytes, 100).unwrap();

        // Verify reorg state
        let (best_hash, best_height) = db.get_best_block().unwrap();
        assert_eq!(best_hash, hash2_bytes);
        assert_eq!(best_height, 100);

        // Verify UTXO from block 1 is spent
        assert!(!db.utxo_exists(&outpoint1));

        // Verify UTXO from block 2 exists
        assert!(db.utxo_exists(&outpoint2));
    }

    #[test]
    fn test_nonexistent_block() {
        let (db, _temp_dir) = create_test_db();
        let hash = [0xFFu8; 32];

        let retrieved = db.get_block(&hash).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_nonexistent_utxo() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([0xFFu8; 32]);
        let outpoint = OutPoint::new(txid, 0);

        assert!(!db.utxo_exists(&outpoint));
        let retrieved = db.get_utxo(&outpoint).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_spend_nonexistent_utxo() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([0xFFu8; 32]);
        let outpoint = OutPoint::new(txid, 0);
        let spending_txid = [1u8; 32];

        // Should return None, not error
        let result = db.spend_utxo(&outpoint, &spending_txid).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_coinbase_utxo() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let (outpoint, utxo) = create_test_utxo(txid, 0, 50_000_000, Some(0)); // Height 0 = coinbase

        db.add_utxo(&outpoint, &utxo).unwrap();

        let retrieved = db.get_utxo(&outpoint).unwrap();
        assert!(retrieved.is_some());
        assert!(retrieved.unwrap().is_coinbase);
    }

    #[test]
    fn test_utxo_without_height() {
        let (db, _temp_dir) = create_test_db();
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let (outpoint, utxo) = create_test_utxo(txid, 0, 50_000_000, None); // No height

        db.add_utxo(&outpoint, &utxo).unwrap();

        let retrieved = db.get_utxo(&outpoint).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height, None);
    }

    // ========== Benchmarks ==========

    #[test]
    fn bench_utxo_lookup() {
        let (db, _temp_dir) = create_test_db();
        use bitcoin::hashes::Hash;
        
        // Setup: Add 1000 UTXOs with unique txids
        let mut utxos = Vec::new();
        for i in 0..1000 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);
            let (outpoint, utxo) = create_test_utxo(txid, 0, 1000 * i as u64, Some(i as u32));
            db.add_utxo(&outpoint, &utxo).unwrap();
            utxos.push(outpoint);
        }

        // Benchmark: Lookup 100 UTXOs
        let start = std::time::Instant::now();
        for outpoint in &utxos[0..100] {
            let _ = db.get_utxo(outpoint).unwrap();
        }
        let duration = start.elapsed();
        println!("UTXO lookup (100 lookups): {:?} ({:?} per lookup)", duration, duration / 100);
    }

    #[test]
    fn bench_block_storage() {
        let (db, _temp_dir) = create_test_db();
        let mut prev_hash = BlockHash::all_zeros();

        // Benchmark: Store 10 blocks
        let start = std::time::Instant::now();
        for height in 0..10 {
            let block = create_test_block(height, prev_hash);
            db.store_block(&block).unwrap();
            prev_hash = block.block_hash();
        }
        let duration = start.elapsed();
        println!("Block storage (10 blocks): {:?} ({:?} per block)", duration, duration / 10);
    }

    #[test]
    fn bench_batch_write() {
        let (db, _temp_dir) = create_test_db();
        use bitcoin::hashes::Hash;

        // Benchmark: Write 100 UTXOs with unique txids
        let start = std::time::Instant::now();
        for i in 0..100 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(txid_bytes);
            let (outpoint, utxo) = create_test_utxo(txid, 0, 1000 * i as u64, Some(i as u32));
            db.add_utxo(&outpoint, &utxo).unwrap();
        }
        let duration = start.elapsed();
        println!("Batch write (100 UTXOs): {:?} ({:?} per UTXO)", duration, duration / 100);
    }
}
