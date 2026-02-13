# Ouroboros

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

**A Bitcoin full node CLI that syncs the blockchain in hours, not days, using Rust for fast I/O and Python for operations.**

Ouroboros is a hybrid Bitcoin node: Rust handles the heavy lifting (header sync, block download, chain validation) while Python provides the CLI, RPC server, mempool, and script execution. Run it as a standalone node, query balances by address, or use it as a development tool for Bitcoin applications.

### Demo

![Ouroboros sync demo](docs/demo.gif)

---

## Usage

```bash
ouroboros [OPTIONS] COMMAND [ARGS]
```

### Global options

Applied to all commands (unless overridden per-command).

| Flag | Description | Default |
|------|-------------|---------|
| `--data-dir PATH` | Data directory (chainstate, blocks). Overridden by `OUROBOROS_DATADIR` env var | `~/.ouroboros` |
| `--config PATH` | Path to config file | `{data_dir}/ouroboros.conf` |
| `--network NETWORK` | Bitcoin network | `mainnet` |
| `--help` | Show help and exit | — |

**Networks:** `mainnet`, `testnet`, `testnet3`, `testnet4`, `regtest`, `signet`

### Commands

| Command | Description | Command-specific flags |
|---------|-------------|-------------------------|
| `sync` | Synchronize blockchain (initial download) | `--reset`, `--limit N` |
| `start` | Start the Bitcoin node (RPC + P2P) | `--rpc-port`, `--p2p-port` |
| `status` | Show node status (sync, best block, mempool) | — |
| `getbalance ADDRESS` | Get balance for a Bitcoin address | `--network` |

### Command flags

| Command | Flag | Description | Default |
|---------|------|-------------|---------|
| `sync` | `--reset` | Clear chainstate before syncing (use after switching networks) | `false` |
| `sync` | `--limit N` | Sync only first N blocks (for quick validation) | None |
| `start` | `--rpc-port PORT` | RPC server port | `8332` (mainnet), `18332` (testnet), `18443` (regtest) |
| `start` | `--p2p-port PORT` | P2P network port | `8333` (mainnet), `18333` (testnet), `18444` (regtest) |
| `getbalance` | `--network NETWORK` | Network for address decoding | `mainnet` |

---

## Examples

```bash
# Sync mainnet (full blockchain)
ouroboros sync

# Sync testnet4 with fresh chainstate
ouroboros --network testnet4 sync --reset

# Start node after sync (RPC on 8332, P2P on 8333)
ouroboros start

# Query balance for a P2PKH address
ouroboros getbalance 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

# Custom data dir and config
ouroboros --data-dir /data/bitcoin --config /data/bitcoin/ouroboros.conf start
```

---

## Installation

### Prerequisites

- **Python 3.10–3.12** (3.13 has limited dependency support)
- **Rust** (for building the sync extension)
- **System deps:** gcc, clang, openssl, pkg-config, python3-dev, snappy, zlib, bzip2, lz4, zstd

### Quick setup (development)

```bash
git clone <repo-url>
cd ouroboros
./setup.sh
source .venv/bin/activate
ouroboros --help
```

The setup script installs Rust (if needed), system dependencies, creates a venv, installs Python packages, and builds the Rust extension with maturin.

### Manual installation

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install system deps (Fedora/RHEL)
sudo dnf install gcc gcc-c++ clang glibc-devel openssl-devel pkg-config \
  python3-devel snappy-devel zlib-devel bzip2-devel lz4-devel libzstd-devel

# 3. Create venv and install Python deps
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install maturin

# 4. Build Rust extension
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
```

### Install as CLI (optional)

```bash
pip install -e .
# or, from project root: pip install .
ouroboros --help
```

---

## Configuration

### Config file

Place `ouroboros.conf` in your data directory, or pass `--config /path/to/ouroboros.conf`. Format: `key=value`, one per line. Chain-specific options use sections like `[testnet4]`, `[regtest]`.

| Option | Description | Example |
|--------|-------------|---------|
| `network` | mainnet, testnet, testnet3, testnet4, regtest, signet | `network=testnet4` |
| `datadir` | Data directory path | `datadir=~/.ouroboros` |
| `rpcport` | RPC server port | `rpcport=8332` |
| `rpcuser` | RPC auth (basic) | `rpcuser=myuser` |
| `rpcpassword` | RPC auth (basic) | `rpcpassword=secret` |
| `rpcallowip` | Allowed RPC client IPs | `rpcallowip=127.0.0.1` |
| `maxconnections` | Max P2P peer connections | `maxconnections=125` |
| `debug` | Debug logging (0/1) | `debug=0` |
| `logtimestamps` | Timestamps in logs (0/1) | `logtimestamps=1` |

Example config: `share/ouroboros.conf.example`

### Environment variables

Environment variables override config file. Prefix: `OUROBOROS_` + uppercase key.

| Variable | Description | Example |
|----------|-------------|---------|
| `OUROBOROS_DATADIR` | Data directory | `OUROBOROS_DATADIR=/data/bitcoin` |
| `OUROBOROS_NETWORK` | Network | `OUROBOROS_NETWORK=testnet4` |
| `OUROBOROS_VERBOSE` | Debug logging (1 = verbose) | `OUROBOROS_VERBOSE=1` |
| `OUROBOROS_TRY_RESYNC` | Resync on stream desync instead of disconnect | `OUROBOROS_TRY_RESYNC=1` |
| `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS` | Block receive timeout | `OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120` |
| `OUROBOROS_PREFER_IPV4` | Prefer IPv4 for P2P | `OUROBOROS_PREFER_IPV4=1` |
| `RUST_LOG` | Rust sync logging | `RUST_LOG=sync=info` (info/debug/warn/error) |

---

## Development

```bash
# Run tests
pytest
cargo test --workspace

# Rebuild Rust extension after changes
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
```

### Project structure

```
ouroboros/
├── ferrous-utils/          # Rust crates
│   ├── common/             # Shared types, crypto
│   └── sync/               # Fast sync, PyO3 bindings
├── src/ouroboros/          # Python package
│   ├── cli.py              # CLI (click)
│   ├── node.py             # Node orchestrator
│   ├── rpc.py              # FastAPI RPC server
│   ├── block_sync.py       # Block sync, reorg
│   ├── mempool.py          # Transaction mempool
│   ├── validation.py       # Block/tx validation
│   ├── script.py           # Script interpreter (ECDSA)
│   ├── config.py           # Config + env
│   └── ...
├── share/
│   └── ouroboros.conf.example
└── pyproject.toml
```

---

## License

MIT
