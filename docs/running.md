# Running ouroboros

Everything here comes from `src/ouroboros/cli.py`, `src/ouroboros/config.py` and `src/ouroboros/node.py`. `ouroboros --help` and `ouroboros <command> --help` print the same options.

The command line has two levels:

```
ouroboros [GLOBAL OPTIONS] <command> [COMMAND OPTIONS]
```

`ouroboros` is the console script installed by `pip install -e .`; `python3 -m ouroboros.cli` is the same program.

## Global options

These go before the command.

| Option | Default | Meaning |
|---|---|---|
| `--data-dir DIR` | `~/.ouroboros` | Data directory. Created if missing. The `OUROBOROS_DATADIR` environment variable overrides it. |
| `--config FILE` | `<datadir>/ouroboros.conf` | Config file (see below). |
| `--network NET` | `mainnet` | `mainnet`, `testnet4`, `testnet3`, `testnet` (same as `testnet3`), `regtest` or `signet`. Signet is accepted but not tested. |
| `--debug[=CATS]` | off | Debug logging. Without a value, or with `1` or `all`, every category; or a comma-separated list such as `--debug=net,mempool,validation`. `0` turns it off. |
| `--log-json` | off | Write log lines as JSON. |
| `--printtoconsole` / `--noprinttoconsole` | on (off with `--daemon`) | Also send log output to stderr. |

## Commands

| Command | What it does |
|---|---|
| `start` | Run the node: P2P, block sync, mempool, wallet and the RPC server. This is the normal way to run ouroboros. |
| `sync [--reset] [--limit N]` | A separate initial block download in the Rust sync engine, with a progress bar and no RPC server. `--reset` deletes everything in the datadir except `ouroboros.conf` first. `--limit N` stops after N blocks. Not covered by these docs' tests. |
| `status` | Meant to print the network, datadir and best block of a stopped node. In this version it prints the network and datadir, then errors on the best block (it opens the database a second time while its own first handle still holds the lock) and on the mempool. Use the `getblockchaininfo` RPC instead. |
| `import-utxo FILE [--batch-size N]` | Replace the chainstate with a UTXO snapshot written by Bitcoin Core's `dumptxoutset` (format version 2). The snapshot's block must be one of the network's built-in assumeUTXO heights, except on regtest. The file is hashed and checked against the built-in commitment before anything is written. |
| `import-blocks [FILE]` | Connect raw blocks from a file, or from stdin with `-` (the default). Each frame is a 4-byte little-endian height, a 4-byte little-endian size, then the serialized block. Blocks at or below the current tip are skipped. |
| `getbalance ADDRESS` | Look up an address balance in the datadir. |

On mainnet, `start` asks for confirmation if `sync` has not finished, unless `--force` is passed or stdin is not a terminal. On other networks it never asks.

## `start` options

| Option | Default | Meaning |
|---|---|---|
| `--rpc-port PORT` | `8332` | RPC port. The default is the same on every network, so pass it outside mainnet. |
| `--p2p-port PORT` | `8333` | P2P port. Same caveat. |
| `--listen` / `--nolisten` | listen | Accept inbound P2P connections. |
| `--bind ADDR[:PORT]` | all interfaces | P2P listen address; repeatable. `--bind 127.0.0.1` limits it to loopback. |
| `--externalip IP[:PORT]` | none | Address to advertise to peers; repeatable or comma-separated. Turns `--discover` off unless that is given too. |
| `--discover` / `--nodiscover` | on | Learn our own public address from outbound peers. |
| `--connect HOST:PORT` | none | Connect only to these peers; repeatable. Turns off DNS seeds and automatic outbound connections, as in Core. |
| `--dnsseed` / `--nodnsseed` | on | Query DNS seeds for peers. Regtest has none. |
| `--force` | off | Skip the "not synced" confirmation on mainnet. |
| `--v2transport` / `--nov2transport` | on | BIP-324 encrypted transport, with automatic fallback to v1 per peer. |
| `--peerbloomfilters` / `--nopeerbloomfilters` | off | Advertise `NODE_BLOOM` (BIP-111) and answer BIP-35 `mempool` requests. |
| `--blockfilterindex` / `--noblockfilterindex` | off | Build the BIP-157/158 basic filter index and serve compact filters to peers. |
| `--cfilter N` | none | `1` is the same as `--blockfilterindex`, `0` turns it off. |
| `--coinstatsindex` / `--nocoinstatsindex` | off | Keep per-height UTXO statistics, so `gettxoutsetinfo` can answer for past heights. |
| `--txospenderindex` / `--notxospenderindex` | off | Index which transaction spent each output, for `gettxspendingprevout` on confirmed spends. |
| `--assumevalid 0` | not set | Check every script, including blocks at or below the last checkpoint (mainnet 850,000). Any other value keeps the default; a block hash is not accepted as an assumevalid point. |
| `--noassumevalid` | off | Same as `--assumevalid 0`. |
| `--par N` | `0` | Script-check threads: `0` is one per core (up to 15 extra), `1` is serial, a negative number leaves that many cores free. Core's `-par=N` spelling also works. Only has an effect with `OUROBOROS_NATIVE_SCRIPT=1`. |
| `--daemon` | off | Detach from the terminal after startup. Console logging goes off unless `--printtoconsole` is given. |
| `--pid FILE` | `<datadir>/ouroboros.pid` | PID file, removed on clean shutdown. |
| `--rpc-tls-cert FILE`, `--rpc-tls-key FILE` | none | Serve RPC over HTTPS. Give both or neither. |
| `--reindex` | off | Accepted, prints a warning, and does nothing else. To rebuild, use `ouroboros sync --reset` on a stopped node. |

The RPC server always listens on `127.0.0.1`. There is no option to bind it elsewhere.

## Config file

The config file is read with Python's `configparser`, so it must have at least one `[section]` header; a file of bare `key=value` lines is ignored with a warning in the log. Keys are looked up in these sections only: `[rpc]`, `[p2p]`, `[network]`, `[logging]` and `[mainnet]`. Keys in `[regtest]`, `[testnet4]` or any other section are not read, whatever `--network` says. Keys in `[DEFAULT]` are read only when the file also has one of the five sections above, because `configparser` copies `[DEFAULT]` values into every section; in a file whose only section is `[DEFAULT]` they are ignored. The section name does not need to match the key; `[rpc]` is a safe place for all of them.

These keys take effect:

| Key | Same as |
|---|---|
| `rpcuser`, `rpcpassword` | Basic-auth credentials. When both are set, no cookie is written. |
| `maxconnections` | Peer limit (default 125). |
| `bind`, `externalip` | `--bind`, `--externalip` (comma-separated). |
| `discover`, `v2transport`, `peerbloomfilters`, `blockfilterindex`, `coinstatsindex`, `txospenderindex` | The flags of the same name; `1`/`0`. A flag on the command line wins. |
| `par` | `--par`. |

`network`, `datadir`, `rpcport`, `p2pport` and `listen` are parsed, but the command-line values (or their defaults) always replace them. `rpcallowip`, `rpcbind`, `proxy`, `onion`, `i2psam`, `torcontrol`, `torpassword`, `asmap`, `debug` and `logtimestamps` are parsed and then not used. `rest`, `prune` and the `zmqpub*` keys are not read from the file at all, so the REST interface, pruning and ZMQ notifications cannot be turned on from the command line or the config file.

Any of the keys in the first table can also be set as an environment variable `OUROBOROS_<KEY>` (for example `OUROBOROS_RPCUSER`), which wins over the file and does not need a section.

Example:

```ini
[rpc]
rpcuser=alice
rpcpassword=change-me
maxconnections=40
v2transport=1
```

## Environment variables

| Variable | Effect |
|---|---|
| `OUROBOROS_DATADIR` | Overrides `--data-dir`. |
| `OUROBOROS_<KEY>` | Overrides a config-file key (see above). |
| `OUROBOROS_NATIVE_SCRIPT=1` | Verify scripts with the Rust interpreter instead of the Python one. The node refuses to start if the installed extension has no native interpreter. Off by default; the Python interpreter is the reference. |
| `OUROBOROS_PAR`, `OUROBOROS_SCRIPT_THREADS` | Script-check threads, ahead of `--par`. Native interpreter only. |
| `OUROBOROS_DISABLE_RUST_VALIDATE=1` | Run block-level checks in Python instead of Rust. |
| `OUROBOROS_UTXO_PREFETCH_THREADS` | Threads that prefetch a block's inputs from RocksDB (default 16; `0` turns it off). |
| `OUROBOROS_PSBT_V2=1` | Accept version 2 PSBTs (BIP-370) at the RPC layer. Off by default, as in Core. |
| `OUROBOROS_ERLAY=1`, `OUROBOROS_PACKAGE_RELAY=1` | Turn on Erlay transaction reconciliation and BIP-331 package relay messages. Both off by default. |
| `OUROBOROS_LOOP_WATCHDOG=0` | Turn off the event-loop stall watchdog (on by default; it logs when the asyncio loop is blocked). |
| `OUROBOROS_TRACEMALLOC=N` | Every N seconds, append the top Python allocations to `<datadir>/tracemalloc.log`. |
| `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=H` | Let `import-utxo` load a snapshot whose block is not a built-in assumeUTXO height, taking H as its height. For testing block ranges only: the snapshot is not checked against anything. |

## Networks and ports

| Network | Bitcoin Core's P2P port | Bitcoin Core's RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 | 48333 | 48332 |
| testnet3 | 18333 | 18332 |
| regtest | 18444 | 18443 |
| signet | 38333 | 38332 |

ouroboros does not pick these by network; pass `--p2p-port` and `--rpc-port`. A Prometheus exporter also starts on port 9332 on all interfaces. Its port cannot be changed; if 9332 is taken, the node logs a warning and runs without metrics.

## Datadir layout

Everything is flat in the datadir, with no per-network subdirectory:

| Path | Contents |
|---|---|
| `*.sst`, `CURRENT`, `MANIFEST-*`, `OPTIONS-*`, `LOG*`, `LOCK`, `IDENTITY` | The RocksDB database: blocks, block index, UTXO set, undo data and indexes. |
| `.cookie` | RPC cookie (`__cookie__:<password>`), written at startup and deleted at shutdown. |
| `ouroboros.log` | Node log. Rotates at 10 MB, keeping 5 old files. `SIGHUP` reopens it. |
| `ouroboros.pid` | PID file while running. |
| `wallets/<name>/wallet.dat` | One directory per wallet. |
| `peers.json`, `anchors.dat`, `bans.json` | Address manager, anchor connections, bans. |
| `fee_estimates.json`, `mempool.dat` | Fee estimator state; mempool saved at shutdown and reloaded at startup. |

## Resources

On mainnet, plan for at least the disk space of an unpruned Bitcoin Core node, plus headroom for RocksDB compaction, and a few GB of RAM. Initial block download is much slower than Core's because most validation runs in Python; `OUROBOROS_NATIVE_SCRIPT=1` speeds up script checks.

## Logging and monitoring

Logs go to `<datadir>/ouroboros.log` and, unless turned off, to stderr. `--debug=<categories>` uses Core's category names (`net`, `mempool`, `validation`, and so on); the `logging` RPC changes them at run time.

The Prometheus exporter on port 9332 reports, among others, `ouroboros_block_height`, `ouroboros_peers_connected`, `ouroboros_mempool_size`, `ouroboros_utxo_cache_hit_rate` and `ouroboros_rpc_duration_seconds`. The RPC port also answers `GET /health` with `{"status":"healthy",...}`.

## Stopping

Call the `stop` RPC, or send SIGINT or SIGTERM. Both shut down cleanly and remove the cookie and PID file. Under systemd the node sends readiness notifications when `NOTIFY_SOCKET` is set.
