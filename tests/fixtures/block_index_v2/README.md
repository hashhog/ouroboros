# block_index_v2 fixture

`regtest-datadirs-dcf7338.tar.xz` holds two ouroboros regtest datadirs written
by ouroboros at `dcf7338` (master before the block index v2 change), so every
BLOCK_INDEX_BY_HASH_CF value in them is the legacy 44-byte encoding.
`tests/test_block_index_v2.py` unpacks a fresh copy into `tmp_path` and opens
it with the current build, which migrates it in place.

| datadir | how it was made | tip | hash-index entries |
|---|---|---|---|
| `failed_reorg/` | core-regtest group `failed_reorg`: side branches, a block failing `bad-cb-amount`, invalidate / reconsider, two node restarts | 22 | 33 |
| `reorg/` | core-regtest group `reorg`: 111 blocks, invalidateblock / reconsiderblock of the tip | 111 | 112 |

Both were produced by the hashhog `tools/core-regtest` harness (meta-repo
`51dc5305d`) against Bitcoin Core v31.1 (sha256-pinned), which submits each
block to Core and to ouroboros and stops ouroboros with SIGTERM:

```sh
BITCOIND=<bitcoin-31.1>/bin/bitcoind OUROBOROS_PYTHON=<venv>/bin/python \
OUROBOROS_SRC=<ouroboros@dcf7338>/src:<site dir with the dcf7338 sync wheel> \
python3 tools/core-regtest/core_regtest.py --adapter tools/core-regtest/adapters/ouroboros.json \
  --groups failed_reorg --keep --workdir <dir> --node-commit dcf7338
```

(and the same with `--groups reorg`).  Only the RocksDB files (`CURRENT`,
`IDENTITY`, `MANIFEST-*`, `OPTIONS-*`, `*.sst`, the `*.log` WAL) and the three
side-state JSON files were kept; node logs, wallets, cookies and peers were
dropped.

`expected.json` was read from a fresh copy after migration and checked
against the master build: every active-chain and side-state block's
`(height, chainwork, timestamp, status)` read by the master build on an
unmigrated copy is identical to what the new build reads after migrating, and
the master build reads a migrated copy identically too (downgrade).  The two
hashes under `absent` were never in the hash index on master (blocks the
harness submitted that master did not store; that is the gap later
block-index steps close for new blocks).  The test checks they stay absent:
the migration upgrades entries, it never invents one.

`SHA256` pins the tarball; the suite checks it.
