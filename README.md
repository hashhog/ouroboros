# Ouroboros

A Bitcoin node implementation in Python with Rust extensions.

## Features

- Fast blockchain synchronization using Rust extensions
- P2P networking
- Mempool management
- Transaction and block validation
- RPC server (FastAPI)
- Wallet functionality
- LevelDB database backend

## Requirements

- Python 3.10+ (including 3.13)
- Rust toolchain (for building extensions)
- System dependencies for LevelDB (see setup instructions)

## Installation

### Development Setup

Run the setup script:

```bash
./setup.sh
```

This will:
- Install Rust toolchain
- Install system dependencies
- Create a virtual environment
- Install Python dependencies
- Build Rust extension modules

### Manual Installation

1. Install Rust: https://rustup.rs/
2. Install system dependencies (Fedora/RHEL):
   ```bash
   sudo dnf install gcc gcc-c++ clang glibc-devel openssl-devel pkg-config python3-devel leveldb-devel snappy-devel
   ```
3. Install Python dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
4. Build Rust extension:
   ```bash
   maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
   ```

## Usage

Start the Bitcoin node:

```bash
ouroboros start
```

See available commands:

```bash
ouroboros --help
```

## Development

Run tests:

```bash
# Rust tests
cargo test --workspace

# Python tests
pytest
```

## Project Structure

```
ouroboros/
├── ferrous-utils/          # Rust crates
│   ├── common/             # Shared Bitcoin types
│   └── sync/               # Fast sync module with PyO3 bindings
├── src/ouroboros/          # Python package
│   ├── node.py             # Main node implementation
│   ├── p2p.py              # P2P networking
│   ├── mempool.py          # Mempool management
│   ├── validation.py       # Block/transaction validation
│   ├── rpc.py              # RPC server
│   ├── database.py         # Database layer
│   ├── wallet.py           # Wallet functionality
│   └── cli.py              # Command-line interface
└── pyproject.toml          # Python package configuration
```

## License

MIT

