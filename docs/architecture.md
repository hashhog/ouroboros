# Architecture

ouroboros is a Python application on an asyncio event loop. Storage, cryptography, block-level checks and a second script interpreter live in a Rust extension module, `sync`, that Python imports through PyO3. The Python side holds the node logic: P2P, chain selection, mempool, RPC and wallet.

```
            ouroboros CLI (click)            src/ouroboros/cli.py
                     |
              BitcoinNode                    src/ouroboros/node.py
   +-------+--------+--------+--------+---------+
   |       |        |        |        |         |
  P2P   BlockSync  Mempool  Wallet   RPC    indexes, ZMQ, metrics
   |       |                          (FastAPI + uvicorn)
   +---- validation (Python) ----+
                |                 \
      Rust extension `sync`        script interpreter
      (RocksDB, block checks,      (Python by default,
       header sync, crypto)         Rust with OUROBOROS_NATIVE_SCRIPT=1)
```

## Startup

`ouroboros start` builds a config dictionary from its flags, and `BitcoinNode` (`node.py`) merges it over the config file (`config.py`). `BitcoinNode.start` then opens the database, writes the RPC cookie, creates the validators, mempool, fee estimator and wallets, starts the peer manager and block sync, and finally the RPC server, the optional indexes and the metrics exporter.

## Storage

| Part | Where |
|---|---|
| RocksDB database: blocks, block index, UTXO set, undo data | `ferrous-utils/sync/src/storage/` (`db.rs`, `coins.rs`, `undo.rs`, `blockstore.rs`, `schema.rs`) |
| Python wrapper and the `Block` / `Transaction` types | `src/ouroboros/database.py` |
| UTXO set hash (`hash_serialized_3`) and coin statistics | `ferrous-utils/sync/src/storage/coinstats.rs`, `src/ouroboros/coinstatsindex.py`, `src/ouroboros/muhash.py` |
| assumeUTXO snapshots (`dumptxoutset`, `loadtxoutset`, `import-utxo`) | `ferrous-utils/sync/src/storage/snapshot.rs`, `src/ouroboros/snapshot.py` |
| Block filter and spender indexes | `src/ouroboros/blockfilter.py`, `src/ouroboros/txospenderindex.py` |
| Pruning | `src/ouroboros/pruning.py` |

The Rust layer batches lookups: `get_utxo_batch()` fetches every input of a transaction in one call, so validation crosses the Python/Rust boundary once per transaction rather than once per input.

## Validation

| Part | Where |
|---|---|
| Block and transaction rules, contextual checks, script-check queue | `src/ouroboros/validation.py`, `src/ouroboros/consensus.py` |
| Rust block checks (on by default; `OUROBOROS_DISABLE_RUST_VALIDATE=1` turns them off) | `ferrous-utils/sync/src/validate/block.rs`, `transaction.rs`, `sigop.rs`, `sequence_lock.rs` |
| Proof of work, difficulty, header checks, low-work header presync | `ferrous-utils/sync/src/validate/pow.rs`, `difficulty.rs`, `header.rs`, `headers_presync.rs` |
| Chain parameters, checkpoints, BIP-9 deployments | `ferrous-utils/sync/src/chain_params.rs`, `versionbits.rs` |
| Script interpreter, Python | `src/ouroboros/script.py`, `segwit_v0.py`, `taproot.py`, `sig_cache.py` |
| Script interpreter, Rust | `ferrous-utils/sync/src/validate/interpreter.rs`, `sighash.rs`, `checkqueue.rs` |

The Python interpreter is the default and the reference. `tests/native_script_differential.py` runs both interpreters on the same inputs and reports any difference. Only the Rust interpreter runs in parallel threads (`--par`), because the Python one holds the GIL.

Below the last checkpoint (mainnet height 850,000) script checks are skipped during sync unless `--noassumevalid` is given. The same switch applies to blocks arriving over P2P and through `submitblock`.

## P2P and sync

| Part | Where |
|---|---|
| Peer manager, message handling, inbound/outbound slots, eviction | `src/ouroboros/p2p.py`, `src/ouroboros/peer.py` |
| Message encoding | `src/ouroboros/p2p_messages.py`, `ferrous-utils/sync/src/network/messages.rs` |
| BIP-324 v2 transport | `src/ouroboros/transport_v2.py` |
| Address manager, ban list, ASMap, local addresses | `src/ouroboros/addrman.py`, `banman.py`, `asmap.py`, `localaddr.py` |
| Headers-first sync, block download, reorgs found over P2P | `src/ouroboros/block_sync.py`, `header_backfill.py`, `sync_manager.py` |
| Compact blocks (BIP-152), Erlay sketches | `src/ouroboros/compact_blocks.py`, `minisketch.py` |
| Rust sync engine used by `ouroboros sync` | `ferrous-utils/sync/src/network/` |

Block validation runs in a worker thread (`asyncio.to_thread`), and the loop yields after each connected block, so RPC requests are answered while the node syncs.

## Mempool and fees

`src/ouroboros/mempool.py` holds the mempool: ancestor and descendant limits, replace-by-fee, TRUC (v3) transactions, packages and orphans. Reject reasons and peer penalties are in `tx_reject.py`. Fee estimation is `fee_estimator.py`. The mempool is written to `mempool.dat` at shutdown and loaded again at startup.

## RPC

`src/ouroboros/rpc.py` is a FastAPI application served by uvicorn on `127.0.0.1`. A request for method `foo` is dispatched to the `rpc_foo` method of `RPCServer`; `help` lists every such method. The same file handles batch requests, `/wallet/<name>` routing, cookie and basic auth, and rate limiting. REST handlers are in `rest.py`, ZMQ publishing in `zmq_notifier.py` and `zmq_publisher.py`, and the waitfor* notifications in `tip_notifier.py`.

## Wallet

| Part | Where |
|---|---|
| Wallets, keys, coin selection, signing, encryption | `src/ouroboros/wallet.py` |
| Output descriptors and miniscript | `src/ouroboros/descriptors.py`, `miniscript.py` |
| PSBT (BIP-174, and BIP-370 behind `OUROBOROS_PSBT_V2=1`) | `src/ouroboros/psbt.py` |
| Addresses, BIP-21, BIP-39 | `src/ouroboros/address.py`, `bip21.py`, `bip39.py` |
| Payjoin (not in Core) | `src/ouroboros/payjoin.py` |

Each wallet is a file at `<datadir>/wallets/<name>/wallet.dat`.

## Operations

Logging setup and Core-style debug categories are in `logging_config.py`; `--daemon`, PID files and systemd notifications in `daemon.py`; the Prometheus exporter in `metrics.py`; fatal-error shutdown in `fatal.py`.

## Tests

`tests/` is the pytest suite (about 4,100 tests). `tests/conftest.py` installs a stand-in for the Rust `sync` module, so most tests run the Python code without the extension; tests that need the real extension import it themselves and skip when it is missing. `tests/functional/` holds regtest tests built on a small framework modelled on Core's `test/functional/`. Rust unit tests sit next to the code in `ferrous-utils/` and in `ferrous-utils/sync/tests/`.
