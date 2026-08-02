# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release: a Bitcoin full node written in Python with Rust
extensions (`ferrous-utils/sync`, PyO3), featuring full block and transaction
validation, header-first sync, and a JSON-RPC surface tracked against Bitcoin
Core behavior.

### Highlights

- Full block and transaction validation: SegWit (P2WPKH/P2WSH), Taproot,
  BIP65/66/68 timelocks, sigop counting, and a complete script interpreter
  (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, NULLFAIL, MINIMALIF,
  WITNESS_PUBKEYTYPE, witness cleanstack, FindAndDelete, OP_CODESEPARATOR).
- Rust hot paths (`ferrous-utils/sync`): RocksDB-backed UTXO set and block
  index, secp256k1 ECDSA/Schnorr with batch verification, batch UTXO lookup.
- Header-first sync with full PoW validation and a windowed download
  scheduler; assumeutxo snapshot load (`loadtxoutset`) with Core chainparams
  heights plus a Track-B 481823 windowed-replay boundary entry.
- Mempool: ancestor/descendant limits, full RBF (BIP-125) with
  mempoolfullrbf, TRUC (v3) policy, ephemeral dust, package relay and CPFP
  (BIP-331), Core v31 cluster limits.
- P2P: BIP-324 v2 encrypted transport, BIP-155 ADDRv2, BIP-339 WTXIDRELAY,
  compact blocks (BIP-152), Minisketch-based Erlay reconciliation, eclipse
  mitigations (bucketed addrman, /16 diversity, anchors, feelers), stale-tip
  eviction, transaction trickling, Tor SOCKS5.
- Wallet: HD (BIP-39/44/49/84/86) with per-purpose keypools, taproot key-path
  signing, PSBT (BIP-174/370), output descriptors (BIP380-386), Miniscript
  (BIP-379).
- RPC: Core-compatible surface including getblockchaininfo/getdeploymentinfo
  (Core v27+ shape), getblock verbosity 0-2, getrawtransaction, PSBT methods,
  getblocktemplate, dumptxoutset/loadtxoutset, gettxoutsetinfo
  (hash_serialized/muhash), estimaterawfee (3-horizon), coinstatsindex,
  pruning, invalidateblock/reconsiderblock, regtest mining.
- REST interface for block explorers, ZMQ notifications, Prometheus metrics.

### Fixed for 1.0.0 (release-readiness sweep)

- Removed the x86 SHA-NI SHA-256 transform: it produced incorrect digests
  (`sha256(b"")` gave `46c5b51e…` instead of `e3b0c442…`). The portable
  software path is used on x86 until a corrected transform lands; the dormant
  code path had no consensus callers (live consensus uses `bitcoin_hashes`),
  and the self-comparing cross-check test that masked the bug is now a real
  known-answer test.
- `common::serialize`: `BitcoinDeserialize for BlockMetadata` now reads the
  optional trailing `status` word (round-trips the 44-byte format written by
  `to_bytes`/`bitcoin_serialize` instead of dropping status flags after 40
  bytes), mirroring `BlockMetadata::from_bytes`.
- `mempool`: spending a `WITNESS_UNKNOWN` v2+ output is non-standard again —
  `_validate_inputs_standardness` regained Core's `ValidateInputsStandardness`
  rejection (`policy/policy.cpp`), which had become dead code when
  WITNESS_UNKNOWN outputs were (correctly) made standard to create.
- Test suite: ~75 stale tests re-pinned to intentional, Core-cited behavior
  (addrman routability gate, Core v27+ deployments surface, 8-sub-pool
  keypool, BIP-22 submitblock strings, 3-horizon fee estimator, NODE_WITNESS
  block-download routing, inactivity-timeout reaping, CompactSize 32 MiB
  `MAX_SIZE` cap, 6th mainnet assumeutxo height 481823); order-dependent
  `asyncio.get_event_loop()` uses in tests replaced with `asyncio.run()`.
- `gettxoutsetinfo`: tests now pin the Core-exact `%d.%08d` `total_amount`
  wire form (`ValueFromAmount` parity via the `BTCAmount` JSON sentinel)
  instead of asserting a pre-serialization float.

### Packaging / CI

- Version bumped to 1.0.0 across `pyproject.toml`, the Cargo workspace
  (`common`, `sync`), `__version__`, P2P user agents, and metrics labels.
- Enabled the GitHub Actions workflows (`ci.yml`, `build-wheels.yml`);
  replaced the archived `actions-rs/toolchain` with
  `dtolnay/rust-toolchain`, aligned the wheel matrix with
  `requires-python` (3.11–3.12), and scoped the CI test job to the unit
  suite (`--ignore=tests/functional`).

### Known issues

- Chronic mainnet OOM during long IBD runs (memory growth under
  investigation).
- Assume-valid lineage coverage ~60% (AV=0 paths still exercised in some
  configurations).
