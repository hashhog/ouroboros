//! Hash-keyed block index v2 (header + nTx tail) and its in-place migration.
//!
//! The v2 value is `[BlockMetadata 44][header 80][nTx 4]`; see
//! `schema::BLOCK_INDEX_BY_HASH_CF`.  These tests write legacy (44-byte)
//! values through a raw RocksDB handle, the way a datadir written by the
//! previous binary looks, and check what `BlockchainDB::open` makes of them.

#[cfg(test)]
mod tests {
    use bitcoin::{
        blockdata::block::{Header, Version as BlockVersion},
        blockdata::transaction::Version as TxVersion,
        hashes::Hash,
        locktime::absolute::LockTime,
        Amount, Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
    };
    use tempdir::TempDir;

    use common::{BlockMetadata, BlockStatus, BlockWrapper};

    use crate::storage::db::{BlockIndexEntry, BlockchainDB};
    use crate::storage::schema::{
        get_column_families, meta_keys, BLOCK_INDEX_BY_HASH_CF, BLOCK_INDEX_ENTRY_V2_LEN,
        BLOCK_METADATA_LEN, HEADERS_CF, META_CF,
    };

    fn block(n: u32, prev: BlockHash, n_tx: usize) -> BlockWrapper {
        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_296_688_602 + n * 600,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };
        let tx = |i: usize| Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![i as u8, n as u8]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
        };
        BlockWrapper::new(Block { header, txdata: (0..n_tx).map(tx).collect() })
    }

    fn h(b: &BlockWrapper) -> [u8; 32] {
        *b.block_hash().as_byte_array()
    }

    fn header80(b: &BlockWrapper) -> [u8; 80] {
        let v = bitcoin::consensus::encode::serialize(b.header());
        v.as_slice().try_into().unwrap()
    }

    fn raw(path: &str) -> rocksdb::DB {
        rocksdb::DB::open_cf(&rocksdb::Options::default(), path, get_column_families()).unwrap()
    }

    /// Make `path` look like a datadir written by the previous binary: every
    /// hash-index value cut back to its 44-byte `BlockMetadata`, no marker.
    fn make_legacy(path: &str) {
        let db = raw(path);
        let cf = db.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap();
        let all: Vec<(Box<[u8]>, Box<[u8]>)> =
            db.iterator_cf(cf, rocksdb::IteratorMode::Start).map(|r| r.unwrap()).collect();
        for (k, v) in all {
            db.put_cf(cf, &k, &v[..BLOCK_METADATA_LEN.min(v.len())]).unwrap();
        }
        let meta = db.cf_handle(META_CF).unwrap();
        db.delete_cf(meta, meta_keys::BLOCK_INDEX_V2_MIGRATED).unwrap();
    }

    fn raw_value(path: &str, hash: &[u8; 32]) -> Vec<u8> {
        let db = raw(path);
        let cf = db.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap();
        db.get_cf(cf, hash).unwrap().unwrap()
    }

    fn marker(path: &str) -> Option<Vec<u8>> {
        let db = raw(path);
        let meta = db.cf_handle(META_CF).unwrap();
        db.get_cf(meta, meta_keys::BLOCK_INDEX_V2_MIGRATED).unwrap()
    }

    #[test]
    fn test_block_index_v2_migration_upgrades_legacy_entries_in_place() {
        let tmp = TempDir::new("bi_v2_migrate").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let g = block(0, BlockHash::all_zeros(), 1);
        let a = block(1, g.block_hash(), 3); // header in HEADERS_CF (nTx 3)
        let b = block(2, a.block_hash(), 2); // body only (BLOCKS_CF)
        let c = block(1002, a.block_hash(), 1); // fork at height 2 (own nonce/time), entry only
        let d = block(3, b.block_hash(), 1); // HEADERS_CF holds a WRONG header for d
        assert_ne!(h(&b), h(&c), "setup: b and c are distinct blocks");

        let md = |height: u32, t: u32, st: BlockStatus| {
            BlockMetadata::with_status(height, [height as u8; 32], t, st)
        };
        let mut failed = BlockStatus::new();
        failed.set_has_data();
        failed.set_failed_valid();
        {
            let db = BlockchainDB::open(&path).unwrap();
            db.store_block_metadata(0, &h(&g), &md(0, g.header().time, BlockStatus::new())).unwrap();
            db.store_raw_header(&h(&g), &header80(&g), 1).unwrap();
            db.store_block_metadata(1, &h(&a), &md(1, a.header().time, BlockStatus::new())).unwrap();
            db.store_raw_header(&h(&a), &header80(&a), 3).unwrap();
            db.store_block_metadata(2, &h(&b), &md(2, b.header().time, BlockStatus::new())).unwrap();
            db.store_block(&b).unwrap();
            db.store_block_metadata(2, &h(&c), &md(2, c.header().time, failed)).unwrap();
            db.store_block_metadata(3, &h(&d), &md(3, d.header().time, BlockStatus::new())).unwrap();
            db.store_raw_header(&h(&d), &header80(&a), 9).unwrap();
        }
        make_legacy(&path);
        for x in [&g, &a, &b, &c, &d] {
            assert_eq!(raw_value(&path, &h(x)).len(), BLOCK_METADATA_LEN, "setup: legacy");
        }

        let db = BlockchainDB::open(&path).unwrap();
        let e = |x: &BlockWrapper| db.get_block_index_entry(&h(x)).unwrap().unwrap();

        let ea = e(&a);
        assert_eq!(ea.header, Some(header80(&a)), "header taken from HEADERS_CF");
        assert_eq!(ea.n_tx, 3, "nTx taken from HEADERS_CF");
        assert_eq!(ea.prev_hash(), Some(h(&g)), "prev link is the header's prev hash");
        assert_eq!(ea.metadata, md(1, a.header().time, BlockStatus::new()), "metadata unchanged");

        let eb = e(&b);
        assert_eq!(eb.header, Some(header80(&b)), "header taken from the body");
        assert_eq!(eb.n_tx, 2, "nTx counted from the body");
        assert_eq!(eb.prev_hash(), Some(h(&a)));

        let ec = e(&c);
        assert_eq!(ec.header, None, "no header anywhere: stays legacy");
        assert_eq!(ec.metadata.status, failed, "status kept for a legacy fork entry");
        let rdb = db.raw_db();
        let v = rdb.get_cf(rdb.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap(), h(&c)).unwrap().unwrap();
        assert_eq!(v.len(), BLOCK_METADATA_LEN, "legacy entry left byte-for-byte");

        let ed = e(&d);
        assert_eq!(ed.header, None, "a header that does not hash to the key is never used");

        assert_eq!(e(&g).prev_hash(), Some([0u8; 32]));
        assert_eq!(db.block_index_summary().unwrap(), (5, 3, 2));
        // Marker present -> a second pass is a no-op.
        assert_eq!(db.migrate_block_index_v2().unwrap(), None);
        drop(db);
        assert_eq!(marker(&path), Some(vec![2u8]));
    }

    #[test]
    fn test_block_index_v2_migration_counts_and_resumes_across_batches() {
        // 25,000 entries spans three 10,000-entry write batches.  Seven are
        // already v2 (an interrupted earlier pass), five have no header.
        let tmp = TempDir::new("bi_v2_stats").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let db = BlockchainDB::open(&path).unwrap();
        let rdb = db.raw_db().clone();
        let cf = rdb.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap();
        let mut prev = BlockHash::all_zeros();
        let mut blocks = Vec::new();
        for n in 0..25_000u32 {
            let b = block(n, prev, 1);
            prev = b.block_hash();
            let md = BlockMetadata::new(n, [0u8; 32], n).to_bytes().unwrap();
            let mut v = md.clone();
            if n < 7 {
                v.extend_from_slice(&header80(&b));
                v.extend_from_slice(&1u32.to_le_bytes());
            }
            rdb.put_cf(cf, h(&b), v).unwrap();
            if n < 24_995 {
                db.store_raw_header(&h(&b), &header80(&b), 1).unwrap();
            }
            blocks.push(b);
        }
        rdb.delete_cf(rdb.cf_handle(META_CF).unwrap(), meta_keys::BLOCK_INDEX_V2_MIGRATED)
            .unwrap();

        let s = db.migrate_block_index_v2().unwrap().expect("marker was removed");
        assert_eq!(s.scanned, 25_000);
        assert_eq!(s.already_v2, 7);
        assert_eq!(s.from_headers, 24_988);
        assert_eq!(s.from_body, 0);
        assert_eq!(s.no_header, 5);
        assert_eq!(s.hash_mismatch, 0);
        assert_eq!(s.malformed, 0);
        assert_eq!(db.block_index_summary().unwrap(), (25_000, 24_995, 5));
        for (n, b) in blocks.iter().enumerate().step_by(997) {
            let e = db.get_block_index_entry(&h(b)).unwrap().unwrap();
            assert_eq!(e.header, Some(header80(b)));
            assert_eq!(e.metadata.height, n as u32, "metadata unchanged");
        }
        assert_eq!(db.migrate_block_index_v2().unwrap(), None, "one-time");

        // Forced re-run (marker deleted): idempotent, nothing rewritten.
        rdb.delete_cf(rdb.cf_handle(META_CF).unwrap(), meta_keys::BLOCK_INDEX_V2_MIGRATED)
            .unwrap();
        let s = db.migrate_block_index_v2().unwrap().unwrap();
        assert_eq!((s.already_v2, s.from_headers, s.no_header), (24_995, 0, 5));
    }

    #[test]
    fn test_block_index_v2_status_rewrite_keeps_header_tail() {
        // update_block_status (invalidate/reconsider, HAVE_UNDO) rewrites the
        // 44 metadata bytes; it must not truncate the v2 tail.
        let tmp = TempDir::new("bi_v2_status").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let g = block(0, BlockHash::all_zeros(), 1);
        let db = BlockchainDB::open(&path).unwrap();
        db.store_raw_header(&h(&g), &header80(&g), 1).unwrap();
        db.store_block_metadata(0, &h(&g), &BlockMetadata::new(0, [1u8; 32], 5)).unwrap();
        assert_eq!(raw_len(&db, &h(&g)), BLOCK_INDEX_ENTRY_V2_LEN, "write picks up HEADERS_CF");
        db.mark_block_invalid(0).unwrap();
        let e = db.get_block_index_entry(&h(&g)).unwrap().unwrap();
        assert!(e.metadata.status.is_failed_valid());
        assert_eq!(e.header, Some(header80(&g)), "status rewrite kept the header");
        assert_eq!(e.n_tx, 1);
        db.clear_block_invalid(0).unwrap();
        let e = db.get_block_index_entry(&h(&g)).unwrap().unwrap();
        assert!(e.metadata.status.is_valid());
        assert_eq!(e.header, Some(header80(&g)));
    }

    #[test]
    fn test_block_index_v2_batch_write_refuses_foreign_header() {
        let tmp = TempDir::new("bi_v2_foreign").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let g = block(0, BlockHash::all_zeros(), 1);
        let x = block(9, BlockHash::all_zeros(), 1);
        let db = BlockchainDB::open(&path).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        let md = BlockMetadata::new(0, [0u8; 32], 0);
        assert!(db
            .store_block_metadata_batch_with_header(&mut batch, 0, &h(&g), &md, Some((&header80(&x), 1)))
            .is_err());
        db.store_block_metadata_batch_with_header(&mut batch, 0, &h(&g), &md, Some((&header80(&g), 1)))
            .unwrap();
    }

    #[test]
    fn test_block_index_v2_value_decodes_with_legacy_reader() {
        // Downgrade safety: the previous binary decodes values with
        // BlockMetadata::from_bytes, which must read a v2 value's first 44
        // bytes and ignore the tail.
        let g = block(0, BlockHash::all_zeros(), 1);
        let mut st = BlockStatus::new();
        st.set_has_data();
        let md = BlockMetadata::with_status(7, [3u8; 32], 99, st);
        let mut v = md.to_bytes().unwrap();
        v.extend_from_slice(&header80(&g));
        v.extend_from_slice(&5u32.to_le_bytes());
        assert_eq!(v.len(), BLOCK_INDEX_ENTRY_V2_LEN);
        assert_eq!(BlockMetadata::from_bytes(&v).unwrap(), md);
        let e = BlockIndexEntry::from_value(&v).unwrap();
        assert_eq!((e.metadata, e.header, e.n_tx), (md, Some(header80(&g)), 5));
        // A 40-byte pre-status value still decodes (status defaults).
        let e40 = BlockIndexEntry::from_value(&v[..40]).unwrap();
        assert_eq!(e40.header, None);
        let _ = HEADERS_CF;
    }

    fn raw_len(db: &BlockchainDB, hash: &[u8; 32]) -> usize {
        let e = db.get_block_index_entry(hash).unwrap().unwrap();
        if e.header.is_some() { BLOCK_INDEX_ENTRY_V2_LEN } else { BLOCK_METADATA_LEN }
    }
}
