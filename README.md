# ouroboros

A Bitcoin full node written in Python and Rust.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
ouroboros is a from-scratch Bitcoin full node that does exactly that. The heavy lifting
(block sync, chain validation) is handled in Rust for performance, while Python handles
the node logic, RPC server, and mempool.

## Current status

- [x] Block header sync and validation
- [x] Full block download and storage
- [x] Proof of work validation
- [x] BIP66 (DERSIG) strict signature encoding
- [x] BIP65/112 (CLTV/CSV) time locks
- [x] BIP141 SegWit support (P2WPKH, P2WSH)
- [x] BIP146 NULLFAIL enforcement
- [x] BIP141 WITNESS_PUBKEYTYPE (compressed keys in witness v0)
- [x] BIP141 witness cleanstack (exactly one true element after execution)
- [x] Script interpreter with stack operations
- [ ] Full signature verification (secp256k1)
- [ ] Mempool transaction relay
- [ ] Wallet functionality

## Quick start

```bash
# Install dependencies and build
./setup.sh
source .venv/bin/activate

# Sync testnet4 (faster for testing)
ouroboros --network testnet4 sync

# Check status
ouroboros status
```

## Project structure

```
ouroboros/
├── ferrous-utils/sync/     # Rust: block sync, validation, PyO3 bindings
├── src/ouroboros/          # Python: CLI, RPC, mempool, node logic
└── pyproject.toml
```

## Running tests

```bash
# Python tests
pytest

# Rust tests
cargo test --workspace

# Rebuild Rust extension after changes
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
```
