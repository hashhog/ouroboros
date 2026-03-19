---
name: ouroboros-bitcoin-node
description: Provides domain knowledge for the Ouroboros Bitcoin full node project. Use when working on Ouroboros code, Bitcoin protocol implementation, consensus rules, P2P sync, or blockchain validation in this repository.
---

# Ouroboros Bitcoin Node

## Architecture

Ouroboros is a hybrid **Python + Rust** Bitcoin node:

| Layer | Language | Location | Responsibilities |
|-------|----------|----------|------------------|
| Sync | Rust | `ferrous-utils/sync/` | Header sync, block download, RocksDB storage, assumevalid |
| Script/Validation | Python | `src/ouroboros/script.py`, `validation.py` | Full script interpreter (P2SH, SegWit, Taproot), tx/block validation |
| Node ops | Python | `src/ouroboros/` | CLI, RPC (FastAPI), mempool, block_sync, P2P peer |

**Two script interpreters exist**: Python (`script.py`) is the canonical full implementation. Rust (`ferrous-utils/sync/src/validate/script.rs`) handles assumevalid blocks and has partial/placeholder logic—SegWit witness verification returns false; disabled opcodes (OP_MUL, OP_DIV, etc.) must not be enabled.

## Key Files

| Concern | Path |
|---------|------|
| Entry point | `src/ouroboros/cli.py` |
| Node orchestration | `src/ouroboros/node.py` |
| Script verification | `src/ouroboros/script.py` |
| Block/tx validation | `src/ouroboros/validation.py` |
| Mempool | `src/ouroboros/mempool.py` |
| RPC | `src/ouroboros/rpc.py` |
| Rust sync | `ferrous-utils/sync/src/` |
| Orphaned features | `ORPHANED_FEATURE_INTEGRATION.md` |

## Build and Test

```bash
# Rebuild Rust extension after changes
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml

# Tests
pytest
cargo test --workspace
```

Python 3.10–3.12 preferred; 3.13 has limited dependency support.

## Networks and Config

Networks: `mainnet`, `testnet`, `testnet3`, `testnet4`, `regtest`, `signet`.

Data dir: `~/.ouroboros` (override with `--data-dir` or `OUROBOROS_DATADIR`).

Use `--network testnet4` or `testnet` for faster sync during development.

## Bitcoin Protocol Context

- **Consensus vs policy**: Consensus rules (script flags, BIPs) are mandatory. Policy (standardness, mempool limits) is relay-specific.
- **Script verification flags**: Bitcoin Core uses `SCRIPT_VERIFY_*` (P2SH, DERSIG, NULLDUMMY, WITNESS, TAPROOT, etc.) gated by block height. Reference `bitcoin/src/script/interpreter.h` when implementing checks.
- **Key BIPs**: 66 (DER), 112/113 (locktime), 125 (RBF), 143 (SegWit sighash), 147 (NULLDUMMY), 340/341/342 (Taproot).
- **P2P**: Peers may send `verack`, `ping`, `feefilter`, `sendcmpct` before `headers`. Header sync must filter non-headers messages.

## Common Gotchas

1. **Empty database**: Header sync must handle empty DB (start from genesis). `build_locator()` must return empty locator when no blocks exist.
2. **Tests and standardness**: Unit tests with minimal tx (e.g. OP_TRUE) fail `IsStandardTx`. Use `Mempool(require_standard=False)` or pass `check_standard=False` in test helpers.
3. **Rust disabled opcodes**: `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT` must fail scripts; never implement them.
4. **Rust rebuild**: After editing `ferrous-utils/sync`, run `maturin develop`; Python imports `sync` from the extension.
5. **RUST_LOG**: Set `RUST_LOG=sync=debug` or `OUROBOROS_VERBOSE=1` for sync debugging.

## Quick Reference

| Task | Command / Location |
|------|--------------------|
| Sync chain | `ouroboros --network testnet4 sync` |
| Fresh chainstate | `ouroboros --network testnet4 sync --reset` |
| Start node | `ouroboros start` |
| Config example | `share/ouroboros.conf.example` |
