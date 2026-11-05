//! Boot-open behaviour after a crash inside `loadtxoutset` / `import-utxo`
//! (security audit 2026-10-30, findings H8 and L12).
//!
//! H8: snapshot-load recovery used to leave an all-zero tip at height 0,
//! which boot took for a real tip, so block 1 could never connect.
//! L12: a recovery that failed was logged and ignored ("continuing anyway"),
//! so the node booted half-recovered with its markers still set.
//!
//! The tests open through `PyBlockchainDB::new`, the constructor the node's
//! boot uses (`database.py` -> `sync.PyBlockchainDB(data_dir)`), and
//! `FastSync::new` (`ouroboros sync`), so they check the real opens.

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use crate::storage::db::{BlockchainDB, DbError};
    use crate::storage::schema::{get_column_families, meta_keys, META_CF};
    use crate::{FastSync, PyBlockchainDB};

    fn write_raw_meta(path: &str, key: &[u8], value: &[u8]) {
        let raw = rocksdb::DB::open_cf(&rocksdb::Options::default(), path, get_column_families())
            .unwrap();
        let meta = raw.cf_handle(META_CF).unwrap();
        raw.put_cf(meta, key, value).unwrap();
    }

    /// A datadir that crashed mid-load boots with NO tip record, the same
    /// state as a fresh datadir, so boot connects the real genesis.
    #[test]
    fn test_boot_open_after_snapshot_crash_leaves_no_tip() {
        let temp_dir = TempDir::new("snap_recovery_genesis").unwrap();
        let path = temp_dir.path().to_str().unwrap();
        {
            let db = BlockchainDB::open(path).unwrap();
            db.update_best_block(&[0x42u8; 32], 5).unwrap();
            db.write_snapshot_load_marker(&[0xCDu8; 32], 10).unwrap();
        }

        let py_db = PyBlockchainDB::new(path.to_string()).expect("boot open");
        let db = &py_db.db;
        assert!(db.get_snapshot_load_marker().unwrap().is_none());
        assert_eq!(db.utxo_count().unwrap(), 0);
        match db.get_best_block() {
            Err(DbError::BlockNotFound) => {}
            Ok((hash, height)) => panic!(
                "recovery left a tip ({}, height {}); boot would skip genesis init",
                hex::encode(hash),
                height,
            ),
            Err(e) => panic!("unexpected error reading tip: {e}"),
        }
    }

    /// L12: a recovery error must fail the boot open, not boot anyway.
    /// A malformed SNAPSHOT_LOAD_IN_PROGRESS value makes `recover_from_crash`
    /// return an error before it touches anything.
    #[test]
    fn test_boot_open_fails_when_recovery_fails() {
        let temp_dir = TempDir::new("snap_recovery_error").unwrap();
        let path = temp_dir.path().to_str().unwrap();
        {
            let db = BlockchainDB::open(path).unwrap();
            db.update_best_block(&[0x42u8; 32], 5).unwrap();
        }
        write_raw_meta(path, meta_keys::SNAPSHOT_LOAD_IN_PROGRESS, b"short");

        assert!(
            PyBlockchainDB::new(path.to_string()).is_err(),
            "a failed crash recovery must fail the boot open",
        );

        // Nothing was changed: the marker and the old tip are still there
        // for the operator to inspect.
        let db = BlockchainDB::open(path).unwrap();
        assert!(db.get_snapshot_load_marker().is_err());
        assert_eq!(db.get_best_block().unwrap(), ([0x42u8; 32], 5));
    }

    /// L12, same rule for the `ouroboros sync` CLI, which opens through
    /// `FastSync::new`.
    #[test]
    fn test_fastsync_open_fails_when_recovery_fails() {
        let temp_dir = TempDir::new("snap_recovery_error_fastsync").unwrap();
        let path = temp_dir.path().to_str().unwrap();
        {
            let db = BlockchainDB::open(path).unwrap();
            db.update_best_block(&[0x42u8; 32], 5).unwrap();
        }
        write_raw_meta(path, meta_keys::SNAPSHOT_LOAD_IN_PROGRESS, b"short");

        assert!(
            FastSync::new(path.to_string(), "regtest".to_string()).is_err(),
            "a failed crash recovery must fail the FastSync open",
        );
    }

    /// Control: a clean datadir boots fine and keeps its tip.
    #[test]
    fn test_boot_open_clean_datadir_keeps_tip() {
        let temp_dir = TempDir::new("snap_recovery_clean").unwrap();
        let path = temp_dir.path().to_str().unwrap();
        {
            let db = BlockchainDB::open(path).unwrap();
            db.update_best_block(&[0x42u8; 32], 5).unwrap();
        }
        let py_db = PyBlockchainDB::new(path.to_string()).expect("boot open");
        assert_eq!(py_db.db.get_best_block().unwrap(), ([0x42u8; 32], 5));
    }
}
