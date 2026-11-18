//! Online header fill of header-less hash-index entries
//! (`fill_index_headers_by_height` / `fill_index_headers_by_hash` /
//! `attach_index_headers`).
//!
//! Every entry here is written through the raw RocksDB handle as a legacy
//! 44-byte value, the way the assumeUTXO header backfill (#52) left the
//! pre-snapshot rows on mainnet.

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

    use common::{BitcoinSerialize, BlockMetadata, BlockStatus, BlockWrapper};

    use crate::storage::db::BlockchainDB;
    use crate::storage::schema::{
        encode_height, meta_keys, BLOCKS_CF, BLOCK_INDEX_BY_HASH_CF, BLOCK_INDEX_CF,
        BLOCK_METADATA_LEN, META_CF,
    };

    /// A block at `n` on `prev` with `n_tx` transactions and a CORRECT merkle root.
    fn block(n: u32, prev: BlockHash, n_tx: usize, salt: u8) -> BlockWrapper {
        let tx = |i: usize| Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![i as u8, n as u8, (n >> 8) as u8, salt]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
        };
        let txdata: Vec<Transaction> = (0..n_tx).map(tx).collect();
        let mut b = Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_296_688_602 + n * 600,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: n + (salt as u32) * 1_000_000,
            },
            txdata,
        };
        b.header.merkle_root = b.compute_merkle_root().unwrap();
        BlockWrapper::new(b)
    }

    fn h(b: &BlockWrapper) -> [u8; 32] {
        *b.block_hash().as_byte_array()
    }

    fn header80(b: &BlockWrapper) -> [u8; 80] {
        let v = bitcoin::consensus::encode::serialize(b.header());
        v.as_slice().try_into().unwrap()
    }

    fn md(height: u32, t: u32) -> Vec<u8> {
        let mut st = BlockStatus::new();
        st.set_has_data();
        BlockMetadata::with_status(height, [height as u8; 32], t, st).to_bytes().unwrap()
    }

    /// Legacy hash-index entry (+ the active-chain height row when `active`).
    fn put_legacy(db: &BlockchainDB, height: u32, b: &BlockWrapper, active: bool) {
        let r = db.raw_db();
        let m = md(height, b.header().time);
        assert_eq!(m.len(), BLOCK_METADATA_LEN);
        r.put_cf(r.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap(), h(b), &m).unwrap();
        if active {
            let mut v = h(b).to_vec();
            v.extend_from_slice(&m);
            r.put_cf(r.cf_handle(BLOCK_INDEX_CF).unwrap(), encode_height(height), v).unwrap();
        }
    }

    fn put_body(db: &BlockchainDB, key: &[u8; 32], bytes: &[u8]) {
        let r = db.raw_db();
        r.put_cf(r.cf_handle(BLOCKS_CF).unwrap(), key, bytes).unwrap();
    }

    fn raw_entry(db: &BlockchainDB, key: &[u8; 32]) -> Vec<u8> {
        let r = db.raw_db();
        r.get_cf(r.cf_handle(BLOCK_INDEX_BY_HASH_CF).unwrap(), key).unwrap().unwrap()
    }

    /// A 12-block active chain, all legacy, tip set; bodies for heights
    /// 3..=6 stored in BLOCKS_CF.
    fn chain(path: &str) -> (BlockchainDB, Vec<BlockWrapper>) {
        let db = BlockchainDB::open(path).unwrap();
        let mut blocks = Vec::new();
        let mut prev = BlockHash::all_zeros();
        for n in 0..12u32 {
            let b = block(n, prev, 1 + (n as usize % 3), 0);
            prev = b.block_hash();
            put_legacy(&db, n, &b, true);
            blocks.push(b);
        }
        for n in 3..=6 {
            put_body(&db, &h(&blocks[n]), &blocks[n].bitcoin_serialize().unwrap());
        }
        db.update_best_block(&h(&blocks[11]), 11).unwrap();
        (db, blocks)
    }

    #[test]
    fn by_height_fills_bodies_and_returns_the_peer_run() {
        let tmp = TempDir::new("ihf_height").unwrap();
        let (db, blocks) = chain(tmp.path().to_str().unwrap());
        // Step 1 starts at genesis: heights 0..=2 have no local header.
        let s = db.fill_index_headers_by_height(0, 100, 0, 2000, true).unwrap();
        assert_eq!(s.peer_run.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(s.from_body, 4, "bodies 3..=6 fill in the same step");
        assert_eq!(s.next_height, 7, "the walk stops where the run would break");
        for n in 3..=6 {
            let e = db.get_block_index_entry(&h(&blocks[n])).unwrap().unwrap();
            assert_eq!(e.header, Some(header80(&blocks[n])));
            assert_eq!(e.n_tx as usize, blocks[n].inner().txdata.len(), "nTx counted from the body");
            assert_eq!(&raw_entry(&db, &h(&blocks[n]))[..BLOCK_METADATA_LEN],
                       &md(n as u32, blocks[n].header().time)[..], "metadata unchanged");
        }
        assert_eq!(db.index_header_fill_cursor().unwrap().0, Some(0), "resume at the run");
        // Peer serves 0..=2.
        let hs: Vec<[u8; 80]> = blocks[0..3].iter().map(header80).collect();
        let a = db.attach_index_headers(&hs, Some(7), true).unwrap();
        assert_eq!(a.attached, 3);
        assert_eq!(db.index_header_fill_cursor().unwrap().0, Some(7));
        let s2 = db.fill_index_headers_by_height(7, 100, 0, 2000, true).unwrap();
        assert_eq!(s2.peer_run.first().map(|r| r.0), Some(7));
        assert_eq!(s2.need_peer, 5);
        assert!(s2.done);
        let hs: Vec<[u8; 80]> = blocks[7..].iter().map(header80).collect();
        assert_eq!(db.attach_index_headers(&hs, Some(12), true).unwrap().attached, 5);
        for (n, b) in blocks.iter().enumerate() {
            let e = db.get_block_index_entry(&h(b)).unwrap().unwrap();
            assert_eq!(e.header, Some(header80(b)), "height {n}");
            assert_eq!(e.metadata.height, n as u32);
        }
    }

    #[test]
    fn corrupted_or_foreign_bodies_are_counted_and_never_written() {
        let tmp = TempDir::new("ihf_corrupt").unwrap();
        let (db, blocks) = chain(tmp.path().to_str().unwrap());
        // Height 4: one byte of a transaction flipped (header intact, so the
        // header still hashes to the key, but the merkle root no longer matches).
        let mut bad = blocks[4].bitcoin_serialize().unwrap();
        let last = bad.len() - 6;
        bad[last] ^= 0x01;
        put_body(&db, &h(&blocks[4]), &bad);
        // Height 5: truncated body (does not parse).
        let mut short = blocks[5].bitcoin_serialize().unwrap();
        short.truncate(90);
        put_body(&db, &h(&blocks[5]), &short);
        // Height 6: the body of ANOTHER block stored under this key.
        put_body(&db, &h(&blocks[6]), &blocks[2].bitcoin_serialize().unwrap());
        let before: Vec<Vec<u8>> = (4..=6).map(|n| raw_entry(&db, &h(&blocks[n]))).collect();

        let s = db.fill_index_headers_by_height(3, 4, 0, 0, true).unwrap();
        assert_eq!(s.from_body, 1, "only height 3's body verifies");
        assert_eq!(s.corrupt_body, 2, "flipped tx byte + truncated body");
        assert_eq!(s.hash_mismatch, 1, "foreign body");
        assert_eq!(s.need_peer, 0, "a refused entry is not handed to a peer either");
        // With peer runs on, the walk must not stop at, recount, or queue them.
        let s2 = db.fill_index_headers_by_height(4, 3, 0, 2000, true).unwrap();
        assert_eq!((s2.corrupt_body, s2.hash_mismatch, s2.need_peer), (2, 1, 0));
        assert!(s2.peer_run.is_empty() && s2.next_height == 7);
        for (i, n) in (4..=6).enumerate() {
            assert_eq!(raw_entry(&db, &h(&blocks[n])), before[i], "height {n} must stay unchanged");
        }
    }

    #[test]
    fn a_header_whose_parent_is_not_one_height_below_is_not_written() {
        let tmp = TempDir::new("ihf_unlinked").unwrap();
        let (db, blocks) = chain(tmp.path().to_str().unwrap());
        // An entry at height 9 whose header's parent is height 2's block.
        let liar = block(9, blocks[2].block_hash(), 1, 7);
        put_legacy(&db, 9, &liar, false);
        let a = db.attach_index_headers(&[header80(&liar)], None, true).unwrap();
        assert_eq!((a.attached, a.unlinked), (0, 1));
        assert_eq!(raw_entry(&db, &h(&liar)).len(), BLOCK_METADATA_LEN);
        // A header for no entry at all, and a repeated one.
        let stranger = block(3, blocks[2].block_hash(), 1, 9);
        let hs = [header80(&stranger), header80(&blocks[1]), header80(&blocks[1])];
        let a = db.attach_index_headers(&hs, None, true).unwrap();
        assert_eq!((a.unknown, a.attached, a.already_v2), (1, 1, 1));
    }

    #[test]
    fn by_key_pass_fills_off_chain_bodies_and_leaves_the_active_chain_alone() {
        let tmp = TempDir::new("ihf_key").unwrap();
        let (db, blocks) = chain(tmp.path().to_str().unwrap());
        let fork_with_body = block(5, blocks[4].block_hash(), 2, 3);
        let fork_no_body = block(6, fork_with_body.block_hash(), 1, 3);
        put_legacy(&db, 5, &fork_with_body, false);
        put_legacy(&db, 6, &fork_no_body, false);
        put_body(&db, &h(&fork_with_body), &fork_with_body.bitcoin_serialize().unwrap());

        let mut key = None;
        let mut total = (0u64, 0u64, 0u64);
        loop {
            let s = db.fill_index_headers_by_hash(key, 3, 0, true).unwrap();
            total.0 += s.from_body;
            total.1 += s.no_source;
            total.2 += s.need_peer;
            key = s.next_key;
            if s.done {
                break;
            }
        }
        assert_eq!(total, (1, 1, 12), "1 fork filled, 1 fork unfillable, 12 active left");
        let e = db.get_block_index_entry(&h(&fork_with_body)).unwrap().unwrap();
        assert_eq!(e.header, Some(header80(&fork_with_body)));
        assert_eq!(e.n_tx, 2);
        for n in 3..=6 {
            assert_eq!(raw_entry(&db, &h(&blocks[n])).len(), BLOCK_METADATA_LEN,
                       "the by-key pass does not touch active-chain entries");
        }
        let (_, k, done) = db.index_header_fill_cursor().unwrap();
        assert!(done && k.is_some());
    }

    #[test]
    fn dry_run_writes_nothing_and_counts_like_the_real_step() {
        let tmp = TempDir::new("ihf_dry").unwrap();
        let (db, blocks) = chain(tmp.path().to_str().unwrap());
        let dry = db.fill_index_headers_by_height(0, 100, 0, 0, false).unwrap();
        assert_eq!((dry.from_body, dry.need_peer, dry.scanned), (4, 8, 12));
        assert!(dry.peer_run.is_empty() && dry.done, "max_peer_run 0 never stops");
        for b in &blocks {
            assert_eq!(raw_entry(&db, &h(b)).len(), BLOCK_METADATA_LEN, "dry run wrote nothing");
        }
        let r = db.raw_db();
        assert!(r.get_cf(r.cf_handle(META_CF).unwrap(), meta_keys::INDEX_HEADER_FILL_HEIGHT)
            .unwrap().is_none(), "no cursor written by a dry run");
        let a = db.attach_index_headers(&[header80(&blocks[0])], Some(1), false).unwrap();
        assert_eq!(a.attached, 1);
        assert_eq!(raw_entry(&db, &h(&blocks[0])).len(), BLOCK_METADATA_LEN);
    }

    #[test]
    fn step_is_bounded_by_max_scan_and_resumes() {
        let tmp = TempDir::new("ihf_bound").unwrap();
        let (db, _blocks) = chain(tmp.path().to_str().unwrap());
        let s = db.fill_index_headers_by_height(3, 2, 0, 2000, true).unwrap();
        assert_eq!((s.scanned, s.from_body, s.next_height, s.done), (2, 2, 5, false));
        assert_eq!(db.index_header_fill_cursor().unwrap().0, Some(5));
    }

    #[test]
    fn step_is_bounded_by_its_time_budget() {
        // 80 bodies of 400 transactions: parsing + merkle-checking all of
        // them takes far longer than 1 ms, so a 1 ms budget must stop early.
        let tmp = TempDir::new("ihf_budget").unwrap();
        let db = BlockchainDB::open(tmp.path().to_str().unwrap()).unwrap();
        let mut prev = BlockHash::all_zeros();
        let mut last = [0u8; 32];
        for n in 0..80u32 {
            let b = block(n, prev, 400, 0);
            prev = b.block_hash();
            put_legacy(&db, n, &b, true);
            put_body(&db, &h(&b), &b.bitcoin_serialize().unwrap());
            last = h(&b);
        }
        db.update_best_block(&last, 79).unwrap();
        let s = db.fill_index_headers_by_height(0, 10_000, 1, 2000, true).unwrap();
        assert!(s.scanned >= 1 && s.scanned < 80, "1 ms budget must stop the walk early (scanned {})", s.scanned);
        assert!(!s.done);
        assert_eq!(db.index_header_fill_cursor().unwrap().0, Some(s.next_height));
        let rest = db.fill_index_headers_by_height(s.next_height, 10_000, 0, 2000, true).unwrap();
        assert_eq!(s.from_body + rest.from_body, 80, "the next step picks up where the budget stopped");
    }

    /// Generator for `tests/fixtures/index_header_fill/local-bodies.tar.xz`
    /// (run: `INDEX_FILL_FIXTURE_OUT=<empty dir> cargo test --lib
    /// make_index_fill_fixture -- --ignored`).  The mainnet shape after the
    /// v2 deploy (v2 and nTx-reconcile markers present, so open runs neither
    /// pass) with 20 legacy entries; heights 5..=9 also have a body in
    /// BLOCKS_CF, 7's with one transaction byte flipped (header intact) and
    /// 8's truncated.  Writes `db/` and `headers.json` (height, internal hash
    /// hex, header hex, nTx).
    #[test]
    #[ignore]
    fn make_index_fill_fixture() {
        let out = std::path::PathBuf::from(std::env::var("INDEX_FILL_FIXTURE_OUT").unwrap());
        let path = out.join("db");
        let db = BlockchainDB::open(path.to_str().unwrap()).unwrap();
        let mut prev = BlockHash::all_zeros();
        let mut rows = Vec::new();
        let mut blocks = Vec::new();
        for n in 0..20u32 {
            let b = block(n, prev, 1 + (n as usize % 3), 5);
            prev = b.block_hash();
            put_legacy(&db, n, &b, true);
            rows.push(format!(
                "{{\"height\": {}, \"hash\": \"{}\", \"header\": \"{}\", \"n_tx\": {}}}",
                n,
                h(&b).iter().map(|x| format!("{:02x}", x)).collect::<String>(),
                header80(&b).iter().map(|x| format!("{:02x}", x)).collect::<String>(),
                b.inner().txdata.len()
            ));
            blocks.push(b);
        }
        for n in [5usize, 6, 9] {
            put_body(&db, &h(&blocks[n]), &blocks[n].bitcoin_serialize().unwrap());
        }
        let mut bad = blocks[7].bitcoin_serialize().unwrap();
        let at = bad.len() - 6;
        bad[at] ^= 0x01;
        put_body(&db, &h(&blocks[7]), &bad);
        let mut short = blocks[8].bitcoin_serialize().unwrap();
        short.truncate(90);
        put_body(&db, &h(&blocks[8]), &short);
        db.update_best_block(&h(&blocks[19]), 19).unwrap();
        let r = db.raw_db();
        let meta = r.cf_handle(META_CF).unwrap();
        r.put_cf(meta, meta_keys::BLOCK_INDEX_V2_MIGRATED, [2u8]).unwrap();
        r.put_cf(meta, meta_keys::HEADERS_NTX_RECONCILED_V1, [1u8]).unwrap();
        r.flush_wal(true).unwrap();
        for cf in [BLOCK_INDEX_BY_HASH_CF, BLOCK_INDEX_CF, BLOCKS_CF, META_CF] {
            r.flush_cf(r.cf_handle(cf).unwrap()).unwrap();
        }
        drop(db);
        std::fs::write(out.join("headers.json"), format!("[\n{}\n]\n", rows.join(",\n"))).unwrap();
    }
}
