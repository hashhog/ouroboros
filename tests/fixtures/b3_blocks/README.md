# B3 Stage 1 block fixtures

Raw Bitcoin mainnet blocks used by `tests/test_b3_cross_validate.py` for
the Rust ↔ Python validator equivalence harness.

## Contents

- `block_<H>.hash` — canonical block hash (hex, 32 bytes) for height `H`.
  All five heights ship with a hash file.
- `block_<H>.bin` — raw wire bytes (SegWit-including). Only
  `block_770000.bin` is checked into the repo (~485 KB). The other four
  fixtures are not committed to keep the repo small.
- `index.json` — mapping `{height → {hash, bytes}}` for all five.
- `fetch.py` — downloader script that pulls the missing `.bin` files
  from blockstream.info and verifies integrity via header dSHA256.

## Fetching the full set locally

```bash
python3 tests/fixtures/b3_blocks/fetch.py
```

Run once. Network is only needed to top up missing files; the script
skips any `.bin` that already exists and passes integrity check.

## Adding a new fixture

1. Decide height and run the RPC against any node with block bodies
   (or use blockstream as in `fetch.py`).
2. Save the raw bytes as `block_<H>.bin` and the canonical hash as
   `block_<H>.hash`.
3. Update `index.json`.
4. Whether to commit the `.bin` depends on size — see note above.
