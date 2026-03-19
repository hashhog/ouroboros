# Troubleshooting Guide

## Sync Issues (Headers Don't Connect)

If you see "Headers don't connect to chain" during sync:

**Cause:** Local chainstate is inconsistent (corrupted DB, switched network, or partial sync).

**Solution:** Run with `--reset` using the correct network:
```bash
ouroboros --network testnet4 sync --reset   # for testnet4
ouroboros --network testnet sync --reset    # for testnet
```

See [INSTALLATION.md](INSTALLATION.md#headers-dont-connect-to-chain) for details.

### Verbose sync logs (Error receiving, Payload size exceeds)

If you see many "Error receiving from X: Payload size exceeds limit" or "Invalid magic bytes" lines:

**Cause:** These are debug-level logs. They appear when `RUST_LOG=sync=debug` or `OUROBOROS_VERBOSE=1` is set.

**Solution:** For quiet sync, ensure neither is set. The default is `sync=warn`.

### RUST_LOG environment variable

The Rust sync code uses structured logging. Control verbosity with `RUST_LOG`:

- **Default:** `sync=warn` (set automatically when Python loads the extension, unless `RUST_LOG` is already set)
- **Verbose:** `OUROBOROS_VERBOSE=1` — sets `RUST_LOG=sync=debug` for detailed peer/block logs
- **Manual override:** `RUST_LOG=sync=info` for normal progress, `RUST_LOG=sync=debug` for all debug logs, `RUST_LOG=warn` for all crates

Examples:
```bash
ouroboros sync                          # Default: warn level
RUST_LOG=sync=info ouroboros sync       # Show info-level progress
OUROBOROS_VERBOSE=1 ouroboros sync      # Full debug (peer I/O, desync errors, etc.)
RUST_LOG=sync=error ouroboros sync      # Only errors
```

---

## Rust Installation Issues

### Rust Update Conflicts

If you encounter errors like:
```
error: failed to install component: 'rust-std-x86_64-unknown-linux-gnu', detected conflict
```

This is a known rustup issue. Here are solutions:

### Solution 1: Continue Anyway (Recommended)

Your existing Rust version (1.92.0) is perfectly fine for this project. You can skip the update and continue:

```bash
# The setup script will now continue even if update fails
./setup.sh
```

### Solution 2: Fix Rust Installation

If you want to fix the rustup issue:

```bash
# Option A: Clean and reinstall rustup
rustup self uninstall
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Option B: Remove conflicting toolchain and reinstall
rustup toolchain uninstall stable
rustup toolchain install stable
rustup default stable

# Option C: Just clean the toolchain directory (if permissions allow)
rm -rf ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu
rustup toolchain install stable
```

### Solution 3: Skip Update in Setup Script

The setup script has been updated to continue even if the Rust update fails. Your existing Rust 1.92.0 will work fine.

## Verify Rust Works

After any fix, verify Rust is working:

```bash
rustc --version
cargo --version
rustup show
```

## Minimum Rust Version

This project requires Rust 1.70+ (Edition 2021). Your version 1.92.0 is more than sufficient.

## Continue Installation

Even if Rust update fails, you can continue with the setup:

```bash
# Manually continue from where setup.sh left off
source .venv/bin/activate  # if virtual env was created
pip install -e ".[dev]"
pip install maturin
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml --release
```
