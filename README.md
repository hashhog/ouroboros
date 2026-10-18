# ouroboros

A Bitcoin full node written from scratch in Python, with its storage and hot paths in Rust. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Blocks 0 to 958,794 were validated with script checks on, as 48 consecutive block ranges. Each range began from the UTXO set the previous one ended with, and the set at 958,794 matched Bitcoin Core's `hash_serialized_3` (`29692050…6e7af0`, 166,180,925 coins). The ranges ran on several commits of this repo, not on one build. See [docs/status.md](docs/status.md) for how to check this yourself. |
| Script interpreter | Passes all 1,222 vectors in Bitcoin Core v31.1's `script_tests.json` and all 500 in `sighash.json` ([docs/status.md](docs/status.md#script-interpreter)). |
| UTXO set vs Core on regtest | After syncing a chain from Bitcoin Core v31.1 over P2P, `gettxoutsetinfo` returns the same `hash_serialized_3` as Core ([docs/status.md](docs/status.md#utxo-set-against-core-on-regtest)). |
| RPC | 142 JSON-RPC methods; 130 have Core's names. Some error codes and messages differ. See [docs/rpc.md](docs/rpc.md). |
| Test suite | `python -m pytest`: 3,953 passed, 4 failed, 83 skipped, 58 expected failures ([docs/status.md](docs/status.md#test-suite)). |
| Wallet | Descriptor HD wallets, PSBT and coin selection work on regtest. Not reviewed for custody: see [SECURITY.md](SECURITY.md). |

Last updated: 2026-10-17.

## Quick start

Tested on Debian 13 with Python 3.13 and Rust 1.99. Python 3.11 to 3.13 is supported. The Rust build compiles RocksDB from source: about 27 CPU-minutes, two minutes of wall time on a 16-core machine.

```bash
sudo apt-get install -y build-essential clang libclang-dev pkg-config python3-dev python3-venv git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"
git clone https://github.com/hashhog/ouroboros.git && cd ouroboros
python3 -m venv .venv && . .venv/bin/activate && pip install maturin
maturin build --release --manifest-path ferrous-utils/sync/Cargo.toml && pip install target/wheels/*.whl && pip install -e '.[dev]'
DATADIR=$(mktemp -d)
ouroboros --network regtest --data-dir "$DATADIR" start --rpc-port 18443 --p2p-port 18444 &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The first `curl` prints the regtest genesis state (`"chain":"regtest","blocks":0`). Always pass `--rpc-port` and `--p2p-port`: the defaults are 8332 and 8333 on every network, so without them a regtest node would try to take mainnet's ports.

## Running

`--network` selects `mainnet` (the default), `testnet4`, `testnet3` (or `testnet`), `regtest` or `signet`. Global options such as `--network` and `--data-dir` go before the subcommand; node options go after `start`.

| Network | Flag | Suggested `--p2p-port` | Suggested `--rpc-port` |
|---|---|---|---|
| mainnet | (none) | 8333 | 8332 |
| testnet4 | `--network testnet4` | 48333 | 48332 |
| testnet3 | `--network testnet3` | 18333 | 18332 |
| regtest | `--network regtest` | 18444 | 18443 |
| signet | `--network signet` (not tested) | 38333 | 38332 |

The suggested ports are Bitcoin Core's. Data goes directly into `--data-dir` (default `~/.ouroboros`), with no per-network subdirectory, so give each network its own datadir. Blocks, the block index and the UTXO set live in one RocksDB database there. For mainnet, plan for at least the disk of an unpruned Bitcoin Core node and a few GB of RAM. By default scripts are not checked for blocks at or below the last checkpoint (mainnet height 850,000); `--noassumevalid` checks every script. A from-genesis mainnet sync is slow, because most validation runs in Python.

`start` syncs the chain and serves RPC. Every flag, the config file, environment variables and the datadir layout are in [docs/running.md](docs/running.md).

## RPC

ouroboros serves a JSON-RPC interface modelled on Bitcoin Core's, on `127.0.0.1` at `--rpc-port`. On startup it writes a cookie to `<datadir>/.cookie`. With the quick-start node running (before the final `stop`):

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo
```

As in Core, wallet calls go to a named wallet through the `/wallet/<name>` URL path. Responses always carry `"jsonrpc":"2.0"` and leave out `error` on success, even for JSON-RPC 1.0 requests. The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git bitcoin   # Core's test vectors, used by some tests
python -m pytest                 # about 4,100 tests; under two minutes
```

```
src/ouroboros/             the Python node: CLI, node startup, P2P, sync, validation, mempool, RPC, wallet
src/ouroboros/cli.py       command line (click)
src/ouroboros/node.py      wires the components together and starts them
src/ouroboros/rpc.py       JSON-RPC server (FastAPI) and every RPC method
ferrous-utils/sync/        Rust extension (PyO3): RocksDB storage, block and script validation, header sync
ferrous-utils/common/      shared Rust helpers
tests/                     pytest suite; tests/functional/ holds regtest functional tests
```

[docs/architecture.md](docs/architecture.md) describes how the parts fit together, [docs/building.md](docs/building.md) covers the toolchain and build options, and [CONTRIBUTING.md](CONTRIBUTING.md) explains how to send changes.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
