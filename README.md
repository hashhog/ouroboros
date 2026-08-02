# ouroboros

A Bitcoin full node written in Python and Rust.

## Quick Start

### Docker

```bash
docker build -t ouroboros .
docker run -v ouroboros-data:/data -p 48350:48350 -p 48340:48340 ouroboros
```

### From Source

```bash
./setup.sh
source .venv/bin/activate

# Sync the blockchain
ouroboros --network testnet4 sync

# Start the node
ouroboros --network testnet4 start --rpc-port=48350 --p2p-port=48340

# Check status
ouroboros status
```

## Features

- Full block and transaction validation (SegWit P2WPKH/P2WSH, Taproot, BIP65/66/68 time locks, sigop counting)
- Script interpreter (all standard opcodes, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, NULLFAIL, MINIMALIF, WITNESS_PUBKEYTYPE, witness cleanstack, FindAndDelete, OP_CODESEPARATOR)
- Header-first sync with full PoW validation
- Block download with Rust-accelerated sync engine (PyO3 bindings)
- Mempool with ancestor/descendant limits (25 txs, 101KB)
- Full RBF (BIP-125) with mempoolfullrbf support
- TRUC (v3 transaction) policy and ephemeral dust
- Package relay and CPFP (BIP-331 P2P messages: sendpackages, getpkgtxns, pkgtxns, ancpkginfo)
- BIP-339 WTXIDRELAY and BIP-155 SENDADDRV2 negotiation
- BIP-155 ADDRv2 (Tor v3, I2P, CJDNS addresses)
- BIP-324 v2 encrypted transport
- Eclipse attack mitigations (bucketed addrman, /16 diversity, anchors, feelers)
- Stale tip detection and peer eviction (ConsiderEviction, extra outbound connection)
- Transaction trickling (Poisson-timed relay for privacy)
- Pre-handshake peer filtering (protocol version check, timeout)
- Compact blocks (BIP-152)
- Minisketch-based Erlay reconciliation
- PSBT (BIP-174/370, creation, signing, combining, finalization, taproot fields)
- Output descriptors (BIP380-386: pk, pkh, wpkh, tr, sh, wsh, multi, sortedmulti, combo, addr, raw)
- Miniscript (BIP-379: parsing, type checking, compilation to Script, witness size analysis)
- Signature verification cache (LRU, cleared on reorg)
- Fee estimation (confirmation targets, bucketed tracking)
- Block template construction (getblocktemplate with segwit rules)
- REST interface for block explorers (block, tx, headers, utxos, mempool, chaininfo)
- ZMQ notifications (hashblock, hashtx, rawblock, rawtx, sequence)
- Tor SOCKS5 proxy support
- Block pruning (pruneblockchain RPC)
- Chain management (invalidateblock, reconsiderblock RPCs)
- Regtest mode (generatetoaddress, generateblock RPCs)
- Multi-wallet support (createwallet, loadwallet, unloadwallet)
- Wallet encryption (encryptwallet, walletpassphrase, walletlock, walletpassphrasechange)

## Configuration

### CLI Flags

Global options (before command):

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir DIR` | `~/.ouroboros` | Data directory (env: `OUROBOROS_DATADIR`) |
| `--config FILE` | `$datadir/ouroboros.conf` | Path to config file |
| `--network NET` | `mainnet` | Network: mainnet, testnet, testnet3, testnet4, regtest, signet |
| `--debug` | off | Enable debug logging (also sets `OUROBOROS_VERBOSE=1`) |
| `--log-json` | off | Emit structured JSON log lines |

`start` command options:

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc-port PORT` | `8332` | RPC server port |
| `--p2p-port PORT` | `8333` | P2P network port |
| `--listen/--nolisten` | listen | Accept inbound P2P connections |
| `--connect ADDR` | none | Connect to specific peer (repeatable) |
| `--force` | off | Skip sync check prompt |

`sync` command options:

| Flag | Default | Description |
|------|---------|-------------|
| `--reset` | off | Clear chainstate before syncing |
| `--limit N` | none | Sync only the first N blocks |

### Commands

| Command | Description |
|---------|-------------|
| `sync` | Synchronize blockchain (initial block download) |
| `start` | Start the Bitcoin node |
| `status` | Show node status |
| `getbalance` | Get balance for an address |
| `import-utxo` | Import UTXO snapshot in Bitcoin Core dumptxoutset v2 format |
| `import-blocks` | Import blocks from framed binary file or stdin |

### Config File

`ouroboros.conf` in the data directory (key=value format with optional `[section]` headers):

```ini
network=testnet4
rpcport=48350
rpcuser=myuser
rpcpassword=mypass
p2pport=48340
maxconnections=125
listen=1
rest=1
proxy=127.0.0.1:9050
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333
i2psam=127.0.0.1:7656
torcontrol=127.0.0.1:9051

[testnet4]
rpcport=48350
```

Environment variables `OUROBOROS_<KEY>` override config file values.

## RPC API

Bitcoin Core-compatible JSON-RPC via FastAPI with batch request support and rate limiting.

| Category | Methods |
|----------|---------|
| Blockchain | `getblockchaininfo`, `getblock`, `getblockhash`, `getblockheader`, `getblockcount`, `getbestblockhash`, `getchaintips`, `getchaintxstats`, `getdifficulty`, `gettxout`, `gettxoutsetinfo`, `getblockfilter`, `verifychain` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction`, `decodescript`, `createrawtransaction`, `signrawtransactionwithkey`, `testmempoolaccept`, `submitpackage`, `gettxoutproof`, `verifytxoutproof` |
| Mempool | `getmempoolinfo`, `getrawmempool`, `getmempoolancestors`, `getmempooldescendants`, `prioritisetransaction` |
| Mining | `getblocktemplate`, `submitblock`, `submitblockbatch`, `getmininginfo`, `getnetworkhashps`, `generatetoaddress`, `generateblock` |
| Network | `getpeerinfo`, `getnetworkinfo`, `getconnectioncount`, `addnode`, `disconnectnode`, `setban`, `listbanned`, `clearbanned`, `getnettotals` |
| Wallet | `createwallet`, `loadwallet`, `unloadwallet`, `listwallets`, `listwalletdir`, `getnewaddress`, `getrawchangeaddress`, `getbalance`, `sendtoaddress`, `listunspent`, `listtransactions`, `gettransaction`, `getwalletinfo`, `getaddressinfo`, `keypoolrefill`, `sethdseed`, `importprivkey`, `dumpprivkey`, `backupwallet`, `bumpfee` |
| Wallet Security | `encryptwallet`, `walletpassphrase`, `walletlock`, `walletpassphrasechange` |
| Descriptors | `getdescriptorinfo`, `deriveaddresses`, `importdescriptors`, `listdescriptors` |
| PSBT | `createpsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt` |
| Util | `validateaddress`, `estimatesmartfee` |
| Chain Mgmt | `invalidateblock`, `reconsiderblock`, `pruneblockchain` |
| Control | `help`, `stop`, `uptime`, `getrpcinfo`, `getindexinfo` |

REST interface available when `rest=1` is set in config, with endpoints for blocks, transactions, headers, UTXOs, mempool, and chain info.

## Monitoring

Built-in Prometheus metrics exporter (requires `prometheus_client` package). Starts an HTTP server on port 9332 by default.

Exported metrics include:
- `ouroboros_block_height` -- current chain tip height
- `ouroboros_chain_difficulty` -- current chain difficulty
- `ouroboros_peers_connected` -- number of connected peers
- `ouroboros_mempool_size` / `ouroboros_mempool_tx_count` -- mempool statistics
- `ouroboros_utxo_cache_size` / `ouroboros_utxo_cache_hit_rate` -- UTXO cache performance
- `ouroboros_blocks_received` / `ouroboros_tx_received` -- cumulative counters
- `ouroboros_rpc_requests` / `ouroboros_rpc_duration` -- RPC server metrics
- `ouroboros_stale_tip_detected` / `ouroboros_peer_evictions` -- health indicators

## Architecture

ouroboros uses a hybrid Python/Rust architecture. The performance-critical block sync engine, chain validation, and UTXO set management are implemented in Rust and exposed to Python via PyO3 bindings (built with maturin). This allows the Rust layer to handle the computationally intensive initial block download at native speed while Python provides the application logic, RPC server, mempool, and P2P networking through an asyncio event loop.

The Python layer uses FastAPI to serve the JSON-RPC interface, providing automatic request validation and async request handling. The Click library structures the CLI with subcommands (sync, start, status) and Rich provides formatted terminal output with progress bars and status tables. Configuration follows Bitcoin Core conventions with a `ouroboros.conf` file supporting `[section]` headers for per-network settings, with environment variable overrides.

The P2P networking layer runs on Python asyncio, managing peer connections, protocol handshakes, and message dispatch. Eclipse attack mitigations include bucketed address management with /16 netgroup diversity, anchor connections for restart resilience, and feeler connections to probe new addresses. Stale tip detection follows Bitcoin Core's ConsiderEviction logic, opening extra outbound connections when the chain tip falls behind.

The mempool enforces ancestor and descendant limits (25 transactions, 101KB aggregate virtual size), with full RBF support and TRUC (v3) policy for topologically restricted transactions. Package relay implements BIP-331 with child-pays-for-parent fee evaluation across package boundaries. The Prometheus metrics module provides optional observability with gauges for chain height, peer count, and UTXO cache performance, plus histograms for RPC latency.

## Performance Architecture

ouroboros separates work into two layers to minimise Python overhead during
Initial Block Download (IBD):

**Rust hot paths (ferrous-utils/sync)**

- Block and transaction storage — RocksDB-backed UTXO set and block index via
  `PyBlockchainDB`
- Cryptographic primitives — double-SHA256 (ARM SHA2-accelerated where
  available, portable software elsewhere), secp256k1
  ECDSA/Schnorr via libsecp256k1 with batch Schnorr verification
- Batch UTXO lookup — `get_utxo_batch()` fetches all inputs for a transaction
  in a single FFI call, replacing N individual calls and halving GIL
  re-acquisition overhead in the validation inner loop
- Script flags, difficulty retarget, checkpoint and assume-valid logic

**Python coordination layer**

- asyncio event loop driving FastAPI (RPC), P2P peer sockets, and mempool
- `block_sync._drain_block_buffer` runs `validate_block` and
  `connect_block_from_bytes` via `asyncio.to_thread` so the event loop stays
  free to service incoming RPC requests between block connections
- An `await asyncio.sleep(0)` yield after each connected block lets the
  scheduler dispatch any pending coroutines before the next validation begins
- `RPCServer._get_deployment_state_cached` caches BIP9 deployment state by
  chain height so `getblockchaininfo` never calls Rust FFI on the hot path,
  eliminating GIL contention with the validation thread pool workers
- `size_on_disk` is recomputed at most once per 30 seconds to avoid
  repeated filesystem walks

**Profiling recipe**

```bash
# Attach py-spy to a running node (non-invasive, no code changes required)
sudo py-spy record -o /tmp/ouroboros-prof.svg -d 60 -p $(pgrep -f 'ouroboros.cli')

# 50-call RPC latency probe
python3 tests/rpc_latency_probe.py --port 8359 --cookie ~/.ouroboros/.cookie --calls 50

# Profile with yappi inside the process (add to cli.py startup)
import yappi; yappi.start(builtins=True)
# ... run workload ...
yappi.stop(); yappi.get_func_stats().print_all()
```

**Measured IBD latency** (getblockchaininfo, 50 calls, mainnet IBD ~495k):

| Date       | Fix                         | p50   | p95     | max     |
|------------|-----------------------------|-------|---------|---------|
| 2026-04-10 | baseline (async.to_thread)  | 4998ms | 10010ms | 10010ms |
| 2026-04-10 | +sleep(0) yield + tip cache | 1ms   | 1635ms  | 1635ms  |
| 2026-04-11 | +deployment cache + batch UTXO | 1ms | <100ms | <400ms |

## License

MIT
