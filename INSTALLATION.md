# Installation Guide

This guide will help you install and set up the Ouroboros Bitcoin full node.

## Prerequisites

### Required
- **Python 3.10-3.12** (Python 3.13 has limited support for some dependencies)
- **Rust toolchain** (for building extensions)
- **System build tools** (gcc, g++, clang, pkg-config)
- **System libraries** (OpenSSL, compression libraries)

### System Requirements
- **Linux** (Fedora/RHEL, Ubuntu/Debian, or similar)
- **macOS** (with Homebrew)
- **Windows** (WSL2 recommended)

## Quick Installation (Recommended)

The easiest way to install is using the automated setup script:

```bash
# Make the script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

This script will:
1. ✅ Install/update Rust toolchain
2. ✅ Install system dependencies
3. ✅ Create Python virtual environment
4. ✅ Install Python dependencies
5. ✅ Build Rust extension modules
6. ✅ Verify installation

**After running setup.sh:**
```bash
# Activate the virtual environment
source .venv/bin/activate

# Verify installation
ouroboros --help
```

## Manual Installation

If you prefer to install manually or the script doesn't work for your system:

### Step 1: Install Rust

```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Rust to your PATH
source "$HOME/.cargo/env"

# Verify installation
rustc --version
```

### Step 2: Install System Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    clang \
    glibc-devel \
    openssl-devel \
    pkg-config \
    python3-devel \
    python3-pip \
    snappy-devel \
    zlib-devel \
    bzip2-devel \
    lz4-devel \
    libzstd-devel
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    clang \
    libclang-dev \
    libssl-dev \
    pkg-config \
    python3-dev \
    python3-pip \
    python3-venv \
    libsnappy-dev \
    zlib1g-dev \
    libbz2-dev \
    liblz4-dev \
    libzstd-dev
```

**macOS (Homebrew):**
```bash
brew install snappy zstd lz4 openssl pkg-config
```

### Step 3: Set Up Python Environment

```bash
# Create virtual environment (recommended)
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### Step 4: Install Python Dependencies

```bash
# Install the package in development mode (includes dev dependencies)
pip install -e ".[dev]"

# Or install without dev dependencies
pip install -e .
```

### Step 5: Install Maturin (Rust-Python Bridge)

```bash
pip install maturin
```

### Step 6: Build Rust Extension

```bash
# Verify Rust workspace compiles
cargo check --workspace

# Build the Rust extension module
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
```

**After any Rust code changes**, rebuild the extension so Python uses the updated code:
```bash
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
# or, from project root: pip install -e .
```

## Verification

After installation, verify everything works:

```bash
# 1. Check Python package imports
python3 -c "import ouroboros; print('✓ Python package OK')"

# 2. Check Rust module (if built)
python3 -c "from sync import SyncEngine; print('✓ Rust module OK')" 2>/dev/null || echo "⚠ Rust module not yet built (this is OK)"

# 3. Check CLI command
ouroboros --help

# 4. Run Rust tests
cargo test --workspace

# 5. Run Python tests
pytest
```

## Post-Installation Setup

### 1. Create Configuration File (Optional)

```bash
# Copy example config
cp ouroboros.conf.example ~/.ouroboros/ouroboros.conf

# Edit as needed
nano ~/.ouroboros/ouroboros.conf
```

### 2. Choose Your Network

**Mainnet (default):**
```bash
ouroboros sync
ouroboros start
```

**Testnet:**
```bash
ouroboros --network testnet sync
ouroboros --network testnet start
```

**Testnet4:** If you have trouble connecting to peers (IPv6 may fail on some networks):
```bash
OUROBOROS_PREFER_IPV4=1 ouroboros --network testnet4 sync
```

If you see "Headers don't connect to chain", run with `--reset` to clear chainstate first:
```bash
ouroboros --network testnet sync --reset
```

**Regtest (local testing):**
```bash
ouroboros --network regtest sync
ouroboros --network regtest start
```

## Troubleshooting

### "Rust not found" or "cargo: command not found"

**Solution:**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### "Python 3.10+ required"

**Solution:** Install Python 3.10, 3.11, or 3.12. Python 3.13 may have compatibility issues.

### "rocksdb module not found" or compilation errors

**Solution:** Install system dependencies for RocksDB:
- **Fedora:** `sudo dnf install snappy-devel zlib-devel bzip2-devel lz4-devel libzstd-devel`
- **Ubuntu:** `sudo apt-get install libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev`
- **macOS:** `brew install snappy zstd lz4`

### "maturin: command not found"

**Solution:**
```bash
pip install maturin
```

### "Permission denied" when running setup.sh

**Solution:**
```bash
chmod +x setup.sh
./setup.sh
```

### Rust compilation errors

**Solution:**
```bash
# Update Rust
rustup update stable

# Clean and rebuild
cargo clean
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
```

### Sync fixes not appearing (e.g. still see per-block timeout messages)

**Cause:** Python is using a cached/old version of the Rust extension.

**Solution:** Rebuild after Rust changes:
```bash
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
# Or: pip install -e .
```
Then run sync again. The Rust extension is compiled separately from the Python package.

### "Error receiving" / "Payload size exceeds limit" flooding the console

**Cause:** `OUROBOROS_VERBOSE=1` is set, which enables debug logs including protocol errors from peers.

**Solution:** For quiet sync, unset the variable:
```bash
unset OUROBOROS_VERBOSE
ouroboros sync
```
Or run without the variable in your environment. Use `OUROBOROS_VERBOSE=1` only when debugging.

### Python import errors

**Solution:**
```bash
# Make sure you're in the virtual environment
source .venv/bin/activate

# Reinstall package
pip install -e ".[dev]"
```

### "Module 'sync' not found"

**Solution:** The Rust module needs to be built:
```bash
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
```

Note: The node can run without the Rust module, but sync performance will be slower.

### "Headers don't connect to chain"

**Cause:** Your local chainstate is inconsistent with the network. Common causes:
- Corrupted or partially synced database
- Switched networks without clearing data (e.g. synced testnet, then ran mainnet)
- Wrong network for the data directory

**Solution:** Clear chainstate and resync with the `--reset` flag. **Use the same network as your data:**
```bash
# For testnet4:
ouroboros --network testnet4 sync --reset

# For testnet:
ouroboros --network testnet sync --reset

# For mainnet:
ouroboros --network mainnet sync --reset
```

The `--reset` flag removes blockchain data from your data directory (preserving `ouroboros.conf`) and starts a fresh sync. Verify you're using the correct `--network` for your use case.

## Development Installation

For development work, install with dev dependencies:

```bash
pip install -e ".[dev]"
```

This includes:
- `pytest` - Testing framework
- `black` - Code formatter
- `ruff` - Linter
- `mypy` - Type checker

## Production Installation

For production use:

```bash
# Install without dev dependencies
pip install -e .

# Build Rust extension in release mode
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
```

## Docker Installation (Future)

Docker support is planned but not yet available. For now, use the manual installation steps above.

## Next Steps

After installation:

1. **Sync the blockchain:**
   ```bash
   ouroboros sync
   ```

2. **Start the node:**
   ```bash
   ouroboros start
   ```

3. **Test RPC:**
   ```bash
   curl -X POST http://localhost:8332/ \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
   ```

4. **Read the documentation:**
   - `README.md` - Overview
   - `TESTNET_GUIDE.md` - Running on testnet
   - `FULL_NODE_IMPLEMENTATION_ROADMAP.md` - Implementation details

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review error messages carefully
3. Ensure all prerequisites are installed
4. Try the manual installation steps
5. Check that you're using Python 3.10-3.12

## Uninstallation

To remove the installation:

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf .venv

# Remove installed package
pip uninstall ouroboros

# Remove Rust extension (if installed globally)
# Check with: pip list | grep sync
```

Note: Your blockchain data in `~/.ouroboros/` will remain unless you delete it manually.
