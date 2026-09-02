# ouroboros

A Bitcoin full node written in Python and Rust.

## Status — v1.0.0

**Label: "Replay-pending — awaiting the stateless-replay run now in flight"**
(`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That label is
deliberately weaker than "Validated", and the scorecard spells out why: it means
ouroboros agreed with Core on every block the nightly instruments showed it — 169
distilled real mainnet blocks, 10 block-context corpus entries, and its row in the
nightly corpus sweep — and that a 26,067-height stateless replay was still running
when the release was written. **Until that run produces a `summary.json`, this node
has no from-genesis evidence at all.** The git tag `v0.1.0-beta1`
(`receipts/RELEASE-v1.0-FREEZE.md`) says the same thing from the other side: `rc`
is reserved for an independent from-genesis `--assumevalid=0` reproduction of
Core's UTXO-set commitment, and `beta` means that receipt does not exist
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**ouroboros has not been shown to validate the chain from genesis.** There is no
ouroboros row in the reproduction ledger (`receipts/TRUST-ANCHOR.md:140-145`) and
no ouroboros replay ledger in `CORE-PARITY-AUDIT/replay-ledgers/`, which holds
six files and none for this node. `receipts/TRUST-ANCHOR.md:187-198` (correction,
2026-09-01) also retracts ouroboros' pre-2026-09-01 M2 boundary-campaign rows as
script evidence: they ran with the implementation's default assumevalid setting.
The project's own throughput note (`CHARTER.md`, §"R4 — Proven
validator", "Honest limit") groups ouroboros with the interpreted
implementations for which a full from-genesis pass is impractical on the current
hardware.

**A worse problem, receipted 2026-09-01 and fixed the next day: ouroboros'
assumevalid flag did not reach its RPC path.** As receipted at
`receipts/TRUST-ANCHOR.md:233-242`, `--assumevalid 0` set only
`block_sync.force_full_scripts` — the P2P drain — so `rpc_submitblock` →
`accept_block` → `validate_block` ran without `force_check_scripts` and
`can_skip_scripts_for_block` returned true below the last checkpoint. Scripts were
skipped for every block fed over RPC below mainnet height 850,000, and the flag
could not turn them on.

**Fixed in `8743575`** (2026-09-02, "fix: honour -assumevalid=0 on the submitblock
path, not only the P2P drain"), an ancestor of this README's own commit.
`Node.start` now sets `self.validator.force_full_scripts`
(`src/ouroboros/node.py:635`) so every acceptance path honours the switch —
`submitblock`, `submitblockbatch`, `generatetoaddress` and the submitblock reorg
connect — matching Core's `ConnectBlock`, where `fScriptChecks` is
unconditionally true under `-assumevalid=0`
(`bitcoin-core/src/validation.cpp:2345-2347`). The reasoning is documented at
`src/ouroboros/rpc.py:768-774` and pinned by
`tests/test_assumevalid_submitblock_path.py`. Default behaviour with assumevalid
unset is unchanged: scripts are still skipped below the checkpoint, as in Core.

**What the fix does not undo:** every harness run *before* that commit that fed
this node blocks over `submitblock` below 850,000 and reported agreement was
measuring chain selection, not script verification. A reader of this repository
alone should still assume ouroboros' from-genesis validation is untested.

**Operator RPC parity: 52 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): ouroboros 52 PASS /
33 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Failures include wrong error
codes (`decoderawtransaction` on non-hex returns `-32603` where Core returns
`-22`), a `getblockstats` anchor height reported as 0, and calls that succeed
where Core errors.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
unit suite went 105 failing → 0 with no skips and no gaps carried. One of those
was a real bug, mutation-verified: `c759449` — the `WITNESS_UNKNOWN` input gate
was dead code, so spends of v2+ witness programs passed
`ValidateInputsStandardness`.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the
[hashhog meta-repo](https://github.com/hashhog/hashhog).

> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, not to this repository.
> **Two notes on the citations above.** The R5 probe JSON is **gitignored** in the
> meta-repo (`.gitignore:60  tools/diff-test-artifacts/`), so a stranger cloning
> either repository cannot read it; regenerate it with `python3 tools/r5_probe.py`
> against a running fleet. The nightly `diffguard-*.log` files are likewise
> gitignored (`.gitignore:43  *.log`). Paths under `receipts/`, `docs/` and
> `CORE-PARITY-AUDIT/` are tracked, but in the **meta-repo**, not here.

## Quick Start

### Docker

```bash
docker build -t ouroboros .
docker run -v ouroboros-data:/data -p 48350:48350 -p 48340:48340 ouroboros
```

### From Source

Requires Python `>=3.11,<3.14` (`pyproject.toml` `requires-python`), a stable Rust
toolchain + `maturin` for the `ferrous-utils/sync` PyO3 extension (no `rust-version`
pin; Cargo edition 2021, pyo3 0.27), and system libs `libclang-dev libssl-dev
librocksdb-dev pkg-config` (see `Dockerfile` / `setup.sh`, which needs interactive
`sudo` for `apt-get`).

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

JSON-RPC via FastAPI, modelled on Bitcoin Core's, with batch request support and rate limiting. Not behaviourally compatible: on the 2026-09-01 operator probe ouroboros answers 52 of the 103 probed methods correctly against Core's 85, with 33 failures (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

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
- Cryptographic primitives — SHA-NI-accelerated double-SHA256, secp256k1
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

**IBD latency, one probe run, 2026-04-10/11** (getblockchaininfo, 50 calls, mainnet
IBD at height ~495k). These numbers come from a single ad-hoc run of
`tests/rpc_latency_probe.py`; no result artifact was committed, and the node now runs
at the chain tip rather than mid-IBD, so they describe a configuration that no longer
exists. Re-run the probe rather than quoting the table:

| Date       | Fix                         | p50   | p95     | max     |
|------------|-----------------------------|-------|---------|---------|
| 2026-04-10 | baseline (async.to_thread)  | 4998ms | 10010ms | 10010ms |
| 2026-04-10 | +sleep(0) yield + tip cache | 1ms   | 1635ms  | 1635ms  |
| 2026-04-11 | +deployment cache + batch UTXO | 1ms | <100ms | <400ms |

## License

MIT
