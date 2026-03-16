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
- [x] BIP16 P2SH push-only scriptSig enforcement
- [x] BIP141 SegWit support (P2WPKH, P2WSH)
- [x] BIP146 NULLFAIL enforcement
- [x] BIP141 WITNESS_PUBKEYTYPE (compressed keys in witness v0)
- [x] BIP141 witness cleanstack (exactly one true element after execution)
- [x] BIP141 MINIMALIF (OP_IF/OP_NOTIF must use minimal boolean encoding)
- [x] Legacy sighash (FindAndDelete, OP_CODESEPARATOR, all sighash types)
- [x] Script interpreter with stack operations and control flow (IF/ELSE/ENDIF)
- [x] Mempool with ancestor/descendant limits (25 txs, 101KB)
- [x] TRUC (v3 transaction) policy and ephemeral dust
- [x] BIP125 Replace-By-Fee (RBF)
- [x] Pre-handshake peer filtering (reject old protocol versions, timeout)
- [x] BIP339 WTXIDRELAY and BIP155 SENDADDRV2 negotiation
- [x] Transaction trickling (privacy-preserving relay with Poisson delays)
- [x] Eclipse attack mitigations (bucketed addrman, /16 diversity, anchors, feelers)
- [x] Stale tip detection and peer eviction (ConsiderEviction, extra outbound connection)
- [x] sendrawtransaction RPC with maxfeerate, confirmed/mempool checks, detailed errors
- [x] getrawtransaction RPC with txindex support, verbose output, and in_active_chain
- [ ] Full signature verification (secp256k1)
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
