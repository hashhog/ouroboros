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
    fn test_has_block_hash() {
        let (db, _temp_dir) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let block = create_test_block(0, prev_hash);
        let hash_bytes = *block.block_hash().as_byte_array();

        // Not present before insert.
        assert!(!db.has_block_hash(&hash_bytes).unwrap());

        // Random 32-byte hash is also absent.
        let random_hash = [0x42u8; 32];
        assert!(!db.has_block_hash(&random_hash).unwrap());

        // Present after insert.
        db.store_block(&block).unwrap();
        assert!(db.has_block_hash(&hash_bytes).unwrap());

        // An unrelated random hash is still absent.
        assert!(!db.has_block_hash(&random_hash).unwrap());
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

    /// Regression: the bare `update_best_block` API must persist
    /// BEST_BLOCK_HASH and BEST_HEIGHT atomically as a single WriteBatch.
    ///
    /// Pre-fix the two `put_cf` calls were issued separately — a SIGKILL
    /// between them could persist the hash while losing the height (or
    /// vice versa), leaving the META_CF in a torn state. Post-fix the two
    /// writes are wrapped in an internal WriteBatch + apply_batch, so a
    /// successful return guarantees BOTH keys are durably committed and
    /// a crash leaves NEITHER. This test asserts the success-side
    /// invariant — a sequence of updates always reads back the matching
    /// (hash, height) pair, never a torn intermediate.
    ///
    /// See CORE-PARITY-AUDIT/_chainstate-atomicity-family-2026-05-26.md.
    #[test]
    fn test_update_best_block_is_atomic_pair() {
        let (db, _temp_dir) = create_test_db();

        // Walk through a sequence of (hash, height) updates. Every read
        // after a successful update must match BOTH the hash and the
        // height we just wrote. If the two puts were ever applied
        // independently, an interleaved read could see a stale half.
        for i in 1..=20u8 {
            let hash = [i; 32];
            let height = (i as u32) * 17;
            db.update_best_block(&hash, height).unwrap();

            let (read_hash, read_height) = db.get_best_block().unwrap();
            assert_eq!(read_hash, hash, "BEST_BLOCK_HASH drift at i={}", i);
            assert_eq!(read_height, height, "BEST_HEIGHT drift at i={}", i);
        }

        // Final cross-check after a downward update (reorg-style rewind).
        let rewind_hash = [99u8; 32];
        let rewind_height = 7u32;
        db.update_best_block(&rewind_hash, rewind_height).unwrap();
        let (read_hash, read_height) = db.get_best_block().unwrap();
        assert_eq!(read_hash, rewind_hash);
        assert_eq!(read_height, rewind_height);
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

    // ========== scrub_unspendable_coins ==========

    /// Seed the chainstate with a mix of spendable and provably-unspendable
    /// outputs (OP_RETURN witness-commitment shape and oversize script),
    /// scrub, and check counts.  Then re-scrub and verify idempotency.
    #[test]
    fn test_scrub_unspendable_coins_removes_op_return_and_oversize() {
        use bitcoin::hashes::Hash;

        let (db, _temp_dir) = create_test_db();

        // 5 spendable P2PKH-shaped outputs.
        for i in 0..5u32 {
            let mut tx = [0u8; 32];
            tx[0..4].copy_from_slice(&i.to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(tx);
            let outpoint = OutPoint::new(txid, 0);
            let mut p2pkh = vec![0x76u8, 0xa9, 0x14];
            p2pkh.extend(std::iter::repeat(0u8).take(20));
            p2pkh.extend_from_slice(&[0x88, 0xac]);
            let utxo = UTXO::new(
                OutPointWrapper::new(outpoint),
                10_000 + i as u64,
                ScriptBuf::from_bytes(p2pkh),
                Some(100 + i),
                false,
            );
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        // 3 OP_RETURN outputs (witness-commitment style: 0x6a 0x24 [magic] [32]).
        for i in 100..103u32 {
            let mut tx = [0u8; 32];
            tx[0..4].copy_from_slice(&i.to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(tx);
            let outpoint = OutPoint::new(txid, 0);
            let mut spk = vec![0x6au8, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            spk.extend(std::iter::repeat(0u8).take(32));
            let utxo = UTXO::new(
                OutPointWrapper::new(outpoint),
                0,
                ScriptBuf::from_bytes(spk),
                Some(500_000 + i),
                false,
            );
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        // 1 oversize script (> MAX_SCRIPT_SIZE).
        {
            let txid = bitcoin::Txid::from_byte_array([0xAA; 32]);
            let outpoint = OutPoint::new(txid, 7);
            let oversize = vec![0x51u8; crate::validate::block::MAX_SCRIPT_SIZE + 1];
            let utxo = UTXO::new(
                OutPointWrapper::new(outpoint),
                1234,
                ScriptBuf::from_bytes(oversize),
                Some(700_000),
                false,
            );
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        // 1 bare OP_RETURN.
        {
            let txid = bitcoin::Txid::from_byte_array([0xBB; 32]);
            let outpoint = OutPoint::new(txid, 1);
            let utxo = UTXO::new(
                OutPointWrapper::new(outpoint),
                0,
                ScriptBuf::from_bytes(vec![0x6a]),
                Some(1),
                true,
            );
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        // Pre-scrub: 5 + 3 + 1 + 1 = 10 entries.
        assert_eq!(db.utxo_count().unwrap(), 10);

        let (removed, bytes_freed) = db.scrub_unspendable_coins().unwrap();
        assert_eq!(removed, 5, "expected 5 unspendable entries removed");
        assert!(bytes_freed > 0, "bytes_freed should be non-zero");

        // Post-scrub: only 5 spendable entries remain.
        assert_eq!(db.utxo_count().unwrap(), 5);

        // Sanity: the spendable entries are still queryable.
        for i in 0..5u32 {
            let mut tx = [0u8; 32];
            tx[0..4].copy_from_slice(&i.to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(tx);
            let outpoint = OutPoint::new(txid, 0);
            assert!(db.get_utxo(&outpoint).unwrap().is_some(),
                "spendable utxo {} should survive scrub", i);
        }
    }

    /// Idempotency: scrub a clean chainstate, then re-scrub.  Both calls
    /// must return (0, 0) and leave the chainstate untouched.
    #[test]
    fn test_scrub_unspendable_coins_is_idempotent() {
        use bitcoin::hashes::Hash;

        let (db, _temp_dir) = create_test_db();

        // Seed with only spendable outputs.
        for i in 0..3u32 {
            let mut tx = [0u8; 32];
            tx[0..4].copy_from_slice(&i.to_le_bytes());
            let txid = bitcoin::Txid::from_byte_array(tx);
            let outpoint = OutPoint::new(txid, i);
            let utxo = UTXO::new(
                OutPointWrapper::new(outpoint),
                42 + i as u64,
                ScriptBuf::from_bytes(vec![0x51u8]), // OP_1: spendable
                Some(i),
                false,
            );
            db.add_utxo(&outpoint, &utxo).unwrap();
        }

        let pre_count = db.utxo_count().unwrap();
        assert_eq!(pre_count, 3);

        let (r1, b1) = db.scrub_unspendable_coins().unwrap();
        assert_eq!(r1, 0);
        assert_eq!(b1, 0);
        assert_eq!(db.utxo_count().unwrap(), pre_count);

        // Second pass must be a no-op too.
        let (r2, b2) = db.scrub_unspendable_coins().unwrap();
        assert_eq!(r2, 0);
        assert_eq!(b2, 0);
        assert_eq!(db.utxo_count().unwrap(), pre_count);

        // Now mix in one OP_RETURN, scrub, re-scrub.
        let txid = bitcoin::Txid::from_byte_array([0xCC; 32]);
        let outpoint = OutPoint::new(txid, 0);
        let utxo = UTXO::new(
            OutPointWrapper::new(outpoint),
            0,
            ScriptBuf::from_bytes(vec![0x6a, 0x10]),
            Some(123),
            false,
        );
        db.add_utxo(&outpoint, &utxo).unwrap();

        let (r3, b3) = db.scrub_unspendable_coins().unwrap();
        assert_eq!(r3, 1);
        assert!(b3 > 0);
        assert_eq!(db.utxo_count().unwrap(), 3);

        // Re-scrub: clean again.
        let (r4, b4) = db.scrub_unspendable_coins().unwrap();
        assert_eq!(r4, 0);
        assert_eq!(b4, 0);
        assert_eq!(db.utxo_count().unwrap(), 3);
    }

    // ========== W92: DisconnectBlock + ApplyTxInUndo + Reorg gates ==========
    //
    // These exercise the gate structure in
    // `BlockchainDB::disconnect_block_at_height_checked` against the
    // canonical reference (`validation.cpp:2149-2248`). Each test pins one
    // gate so a regression bisects to a single Core code path.

    use crate::storage::db::{
        is_bip30_disconnect_exception, DisconnectStatus,
    };
    use crate::storage::undo::{BlockUndo, Coin, TxUndo};

    /// Build a block at `height` whose coinbase pays `value` sats to the
    /// supplied `script_pubkey`, and (optionally) one extra non-coinbase tx
    /// that spends `prev_outpoint` (with `prev_coin` describing what it spent).
    /// Returns `(block, second_tx_txid_if_any)`.
    fn build_block_with_optional_spend(
        height: u32,
        prev_block: BlockHash,
        coinbase_value: u64,
        coinbase_script: ScriptBuf,
        spend: Option<(OutPoint, ScriptBuf, u64)>,
    ) -> (BlockWrapper, Option<bitcoin::Txid>) {
        let coinbase_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![height as u8, 0x00]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: coinbase_script,
            }],
        };

        let mut txdata = vec![coinbase_tx];
        let mut second_txid = None;

        if let Some((prev_outpoint, out_script, out_value)) = spend {
            let tx = Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: prev_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(out_value),
                    script_pubkey: out_script,
                }],
            };
            second_txid = Some(tx.compute_txid());
            txdata.push(tx);
        }

        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev_block,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_231_006_505 + height * 600,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        };
        (BlockWrapper::new(Block { header, txdata }), second_txid)
    }

    /// G9: BIP-30 disconnect-exception lookup is height + hash specific.
    #[test]
    fn test_w92_g9_bip30_disconnect_exception_lookup() {
        // Height 91722 with its canonical hash → exception.
        let hash_91722 = [
            0x8e, 0xd0, 0x4d, 0x57, 0xf2, 0xd3, 0xcd, 0xc6,
            0xa6, 0xe5, 0x55, 0x69, 0xdc, 0x16, 0x54, 0x2e,
            0x9f, 0x41, 0x84, 0xf8, 0x67, 0x76, 0x26, 0xdc,
            0xa2, 0x71, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_bip30_disconnect_exception(91_722, &hash_91722));

        // Height 91812 with its canonical hash → exception.
        let hash_91812 = [
            0x2f, 0x6f, 0x30, 0xf9, 0xd6, 0x83, 0xde, 0xb8,
            0x5d, 0x93, 0x14, 0xef, 0x5d, 0xcf, 0x36, 0xaf,
            0x66, 0xd9, 0xe3, 0xce, 0x1a, 0x2b, 0x79, 0xd4,
            0xae, 0xf0, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_bip30_disconnect_exception(91_812, &hash_91812));

        // Wrong height with the right hash → NOT exception.
        assert!(!is_bip30_disconnect_exception(91_711, &hash_91722));
        // Right height with the wrong hash → NOT exception.
        let bogus = [0u8; 32];
        assert!(!is_bip30_disconnect_exception(91_722, &bogus));
        // Connect-side BIP-30 exceptions (91842 / 91880) are NOT
        // disconnect-side exceptions.
        assert!(!is_bip30_disconnect_exception(91_842, &bogus));
        assert!(!is_bip30_disconnect_exception(91_880, &bogus));
    }

    /// Disconnect a coinbase-only block → OK + chain rolls back.
    #[test]
    fn test_w92_disconnect_coinbase_only_block_ok() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_hash_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_hash_bytes, 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]), // OP_1 — spendable
            None,
        );
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Seed the coinbase output into the chainstate exactly as
        // apply_block would.
        let coinbase_tx = &block.inner().txdata[0];
        let coinbase_txid = coinbase_tx.compute_txid();
        let cb_outpoint = OutPoint::new(coinbase_txid, 0);
        let cb_utxo = UTXO::new(
            OutPointWrapper::new(cb_outpoint),
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            Some(1),
            true,
        );
        db.add_utxo(&cb_outpoint, &cb_utxo).unwrap();

        // Disconnect.
        let (returned_hash, status) = db.disconnect_block_at_height_checked(1).unwrap();
        assert_eq!(returned_hash, hash_bytes);
        assert_eq!(status, DisconnectStatus::Ok);

        // Chain tip rolled back to genesis.
        let (best, h) = db.get_best_block().unwrap();
        assert_eq!(best, prev_hash_bytes);
        assert_eq!(h, 0);

        // Coinbase output is gone from the chainstate.
        assert!(!db.utxo_exists(&cb_outpoint));
    }

    /// G12: An unspendable (OP_RETURN) output in a block being disconnected
    /// must NOT contribute to UNCLEAN — Core's `IsUnspendable` filter skips
    /// the per-output mismatch check entirely.
    #[test]
    fn test_w92_g12_unspendable_output_skipped() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        db.update_best_block(prev_hash.as_byte_array(), 0).unwrap();

        // Build a block whose coinbase has an OP_RETURN output (unspendable).
        let coinbase_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x42]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    // OP_RETURN output — unspendable
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]),
                },
            ],
        };
        let block = BlockWrapper::new(Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: prev_hash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_231_006_505,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 1,
            },
            txdata: vec![coinbase_tx.clone()],
        });
        let block_hash = block.block_hash();
        let hash_bytes = *block_hash.as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Only the spendable output goes into chainstate (mirrors apply_block).
        let cb_txid = coinbase_tx.compute_txid();
        let cb_out0 = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out0,
            &UTXO::new(
                OutPointWrapper::new(cb_out0),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();

        // Disconnect must be CLEAN — the absent OP_RETURN output must not
        // trigger an output-mismatch warning.
        let (_, status) = db.disconnect_block_at_height_checked(1).unwrap();
        assert_eq!(
            status,
            DisconnectStatus::Ok,
            "OP_RETURN absence must not trigger UNCLEAN (G12)",
        );
    }

    /// G13: a spendable coinbase output that is *missing* from the
    /// chainstate when we try to disconnect must signal UNCLEAN (not OK).
    #[test]
    fn test_w92_g13_missing_spendable_output_unclean() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        db.update_best_block(prev_hash.as_byte_array(), 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Deliberately DO NOT add the coinbase UTXO to chainstate — simulate
        // an inconsistency.

        let (_, status) = db.disconnect_block_at_height_checked(1).unwrap();
        assert_eq!(
            status,
            DisconnectStatus::Unclean,
            "missing spendable output must surface DISCONNECT_UNCLEAN (G13)",
        );
    }

    /// G13: a coinbase output whose stored height disagrees with the block's
    /// height also fires UNCLEAN.
    #[test]
    fn test_w92_g13_height_mismatch_unclean() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        db.update_best_block(prev_hash.as_byte_array(), 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            2,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(2, [1u8; 32], block.header().time);
        db.store_block_metadata(2, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 2).unwrap();

        // Seed coinbase output with the WRONG height.
        let cb_txid = block.inner().txdata[0].compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(99), // wrong — should be 2
                true,
            ),
        )
        .unwrap();

        let (_, status) = db.disconnect_block_at_height_checked(2).unwrap();
        assert_eq!(status, DisconnectStatus::Unclean);
    }

    /// G8: A BlockUndo whose tx_undo.len() + 1 does not match block.vtx.len()
    /// must fail the disconnect with an InvalidData error.
    #[test]
    fn test_w92_g8_undo_arity_mismatch_fails() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        // Block with 1 coinbase + 1 spending tx = vtx.len() == 2.
        // We seed a UTXO that the spending tx consumes.
        let seed_txid = bitcoin::Txid::from_byte_array([7u8; 32]);
        let seed_outpoint = OutPoint::new(seed_txid, 0);
        db.add_utxo(
            &seed_outpoint,
            &UTXO::new(
                OutPointWrapper::new(seed_outpoint),
                10_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(0),
                false,
            ),
        )
        .unwrap();

        let (block, _spend_txid) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            Some((seed_outpoint, ScriptBuf::from_bytes(vec![0x51]), 9_000)),
        );
        assert_eq!(block.inner().txdata.len(), 2);
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Seed the block's coinbase output (so the per-output check passes).
        let cb_txid = block.inner().txdata[0].compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();

        // Store an INTENTIONALLY MALFORMED BlockUndo: zero tx_undo entries
        // for a block whose vtx.len() == 2 (should be 1 — one for the
        // non-coinbase tx).
        let bad_undo = BlockUndo::with_tx_undo(Vec::new());
        db.store_block_undo(1, &bad_undo, &prev_bytes).unwrap();

        let result = db.disconnect_block_at_height_checked(1);
        assert!(result.is_err(), "G8 mismatch must surface as Err");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("tx_undo+1"),
            "error message must reference tx_undo arity check, got: {}",
            msg,
        );
    }

    /// G15: a per-tx vprevout.len() != tx.vin.len() must also fail.
    #[test]
    fn test_w92_g15_per_tx_undo_arity_mismatch_fails() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        let seed_txid = bitcoin::Txid::from_byte_array([9u8; 32]);
        let seed_outpoint = OutPoint::new(seed_txid, 0);
        db.add_utxo(
            &seed_outpoint,
            &UTXO::new(
                OutPointWrapper::new(seed_outpoint),
                10_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(0),
                false,
            ),
        )
        .unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            Some((seed_outpoint, ScriptBuf::from_bytes(vec![0x51]), 9_000)),
        );
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Seed coinbase UTXO so per-output check passes.
        let cb_txid = block.inner().txdata[0].compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();

        // Store a BlockUndo with the right top-level arity (1 tx_undo for the
        // one non-coinbase tx), but where the inner prev_outputs.len() == 0
        // even though the spending tx has 1 input.
        let bad_inner = TxUndo::with_outputs(Vec::new());
        let bad_undo = BlockUndo::with_tx_undo(vec![bad_inner]);
        db.store_block_undo(1, &bad_undo, &prev_bytes).unwrap();

        let result = db.disconnect_block_at_height_checked(1);
        assert!(result.is_err(), "G15 mismatch must surface as Err");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("vprevout"),
            "error message must reference per-tx vprevout check, got: {}",
            msg,
        );
    }

    /// Public wrapper (`disconnect_block_at_height`) returns Ok(hash) and
    /// hides UNCLEAN behind a log line — but a hard FAILED still propagates
    /// as Err.
    #[test]
    fn test_w92_public_wrapper_swallows_unclean_propagates_failed() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Don't seed the coinbase output — UNCLEAN.
        // Public wrapper still returns Ok.
        let res = db.disconnect_block_at_height(1);
        assert!(res.is_ok(), "public wrapper must hide UNCLEAN");
        assert_eq!(res.unwrap(), hash_bytes);
    }

    /// G16: input restore order is REVERSE of `tx.vin`. We verify this
    /// indirectly by constructing a tx with two inputs and undo data that
    /// pins each input to a distinct coin (different value), then check
    /// that both restores landed correctly — order-independence proves we
    /// matched the undo records to inputs by index, not by walk order.
    #[test]
    fn test_w92_g16_reverse_vin_restore_keeps_undo_index_alignment() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        // Two distinct seed outpoints with different values.
        let seed_a = OutPoint::new(bitcoin::Txid::from_byte_array([0xA1; 32]), 0);
        let seed_b = OutPoint::new(bitcoin::Txid::from_byte_array([0xB2; 32]), 0);
        let coin_a = Coin::new(1_111, ScriptBuf::from_bytes(vec![0x51]), 0, false);
        let coin_b = Coin::new(2_222, ScriptBuf::from_bytes(vec![0x51]), 0, false);

        // Spending tx with input[0] = seed_a, input[1] = seed_b.
        let spending_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: seed_a,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                TxIn {
                    previous_output: seed_b,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        let coinbase_tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        let block = BlockWrapper::new(Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: prev_hash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_231_006_505,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 1,
            },
            txdata: vec![coinbase_tx.clone(), spending_tx.clone()],
        });
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Seed coinbase UTXO so per-output check is clean.
        let cb_txid = coinbase_tx.compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();
        // Seed spending tx output to keep per-output check clean.
        let spend_txid = spending_tx.compute_txid();
        let spend_out = OutPoint::new(spend_txid, 0);
        db.add_utxo(
            &spend_out,
            &UTXO::new(
                OutPointWrapper::new(spend_out),
                3_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                false,
            ),
        )
        .unwrap();

        // Store BlockUndo: 1 tx_undo with 2 coins, matched by INDEX
        // (prev_outputs[0] = coin_a, prev_outputs[1] = coin_b).
        let tx_undo = TxUndo::with_outputs(vec![coin_a.clone(), coin_b.clone()]);
        let block_undo = BlockUndo::with_tx_undo(vec![tx_undo]);
        db.store_block_undo(1, &block_undo, &prev_bytes).unwrap();

        let (_, status) = db.disconnect_block_at_height_checked(1).unwrap();
        assert_eq!(status, DisconnectStatus::Ok);

        // After disconnect, seed_a / seed_b are back as UTXOs with the
        // values from coin_a / coin_b (proving G16 + per-index alignment).
        let restored_a = db.get_utxo(&seed_a).unwrap().expect("seed_a restored");
        let restored_b = db.get_utxo(&seed_b).unwrap().expect("seed_b restored");
        assert_eq!(restored_a.amount, 1_111, "input 0 must restore coin_a");
        assert_eq!(restored_b.amount, 2_222, "input 1 must restore coin_b");
    }

    /// G18 + chain tip rollback: after a clean disconnect, BEST_BLOCK_HASH
    /// must equal the disconnected block's prev_blockhash and BEST_HEIGHT
    /// must drop by one.
    #[test]
    fn test_w92_g18_best_block_rollback() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let hash_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        let meta = BlockMetadata::new(1, [1u8; 32], block.header().time);
        db.store_block_metadata(1, &hash_bytes, &meta).unwrap();
        db.update_best_block(&hash_bytes, 1).unwrap();

        // Seed cb so disconnect is clean.
        let cb_txid = block.inner().txdata[0].compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();

        db.disconnect_block_at_height(1).unwrap();
        let (best, h) = db.get_best_block().unwrap();
        assert_eq!(best, prev_bytes);
        assert_eq!(h, 0);
    }

    /// G7 + G8 atomic-batch path: a malformed undo at any depth in a
    /// multi-block disconnect refuses the entire batch.
    #[test]
    fn test_w92_atomic_batch_refuses_malformed_undo_anywhere() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        // Two clean blocks at heights 1 and 2.
        let (block1, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let h1 = block1.block_hash();
        let h1_bytes = *h1.as_byte_array();
        db.store_block(&block1).unwrap();
        db.store_block_metadata(
            1,
            &h1_bytes,
            &BlockMetadata::new(1, [1u8; 32], block1.header().time),
        )
        .unwrap();

        let (block2, _) = build_block_with_optional_spend(
            2,
            h1,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let h2_bytes = *block2.block_hash().as_byte_array();
        db.store_block(&block2).unwrap();
        db.store_block_metadata(
            2,
            &h2_bytes,
            &BlockMetadata::new(2, [2u8; 32], block2.header().time),
        )
        .unwrap();
        db.update_best_block(&h2_bytes, 2).unwrap();

        // Seed coinbases.
        for (b, height) in [(&block1, 1u32), (&block2, 2u32)].iter() {
            let cb = &b.inner().txdata[0];
            let cb_out = OutPoint::new(cb.compute_txid(), 0);
            db.add_utxo(
                &cb_out,
                &UTXO::new(
                    OutPointWrapper::new(cb_out),
                    50_000_000,
                    ScriptBuf::from_bytes(vec![0x51]),
                    Some(*height),
                    true,
                ),
            )
            .unwrap();
        }

        // Block 1 has good (empty) undo, block 2 has malformed undo.
        db.store_block_undo(1, &BlockUndo::with_tx_undo(Vec::new()), &prev_bytes)
            .unwrap();
        // Block 2: 5 tx_undo entries for a coinbase-only block (vtx.len()==1)
        let bogus = BlockUndo::with_tx_undo(vec![
            TxUndo::with_outputs(Vec::new()),
            TxUndo::with_outputs(Vec::new()),
            TxUndo::with_outputs(Vec::new()),
            TxUndo::with_outputs(Vec::new()),
            TxUndo::with_outputs(Vec::new()),
        ]);
        db.store_block_undo(2, &bogus, &h1_bytes).unwrap();

        let res = db.disconnect_blocks_atomic(2, 0);
        assert!(res.is_err(), "malformed undo must refuse atomic batch");

        // After refusal, tip must STILL be at block 2 — nothing applied.
        let (still, h) = db.get_best_block().unwrap();
        assert_eq!(still, h2_bytes);
        assert_eq!(h, 2);
    }

    /// Reverse-walk sanity: confirm we don't accidentally walk forward by
    /// constructing a block whose later tx (txdata[2]) consumes outputs of
    /// an earlier tx (txdata[1]), then disconnecting. Forward iteration
    /// would delete txdata[1]'s outputs before txdata[2]'s sanity check
    /// (because the check would try to find them in chainstate) — reverse
    /// iteration handles them in the correct order.
    ///
    /// This test only goes as far as proving the rollback completes cleanly
    /// when the in-block dependency is present. Pre-fix the function did
    /// walk in reverse for tx (.rev()) but in forward order for vin —
    /// G16 now makes vin reverse too.
    #[test]
    fn test_w92_g10_g16_full_reverse_walk_succeeds() {
        let (db, _tmp) = create_test_db();
        let prev_hash = BlockHash::all_zeros();
        let prev_bytes = *prev_hash.as_byte_array();
        db.update_best_block(&prev_bytes, 0).unwrap();

        let (block, _) = build_block_with_optional_spend(
            1,
            prev_hash,
            50_000_000,
            ScriptBuf::from_bytes(vec![0x51]),
            None,
        );
        let h_bytes = *block.block_hash().as_byte_array();
        db.store_block(&block).unwrap();
        db.store_block_metadata(
            1,
            &h_bytes,
            &BlockMetadata::new(1, [1u8; 32], block.header().time),
        )
        .unwrap();
        db.update_best_block(&h_bytes, 1).unwrap();

        // Seed coinbase output.
        let cb_txid = block.inner().txdata[0].compute_txid();
        let cb_out = OutPoint::new(cb_txid, 0);
        db.add_utxo(
            &cb_out,
            &UTXO::new(
                OutPointWrapper::new(cb_out),
                50_000_000,
                ScriptBuf::from_bytes(vec![0x51]),
                Some(1),
                true,
            ),
        )
        .unwrap();

        let (returned, status) = db.disconnect_block_at_height_checked(1).unwrap();
        assert_eq!(returned, h_bytes);
        assert_eq!(status, DisconnectStatus::Ok);
        assert!(!db.utxo_exists(&cb_out));
    }
}
