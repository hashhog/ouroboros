---
name: ouroboros-bitcoin-node
description: Provides domain knowledge for the Ouroboros umbrella project. Use when working on the Python/Rust Bitcoin node code, Rust sync engine, or umbrella project structure.
---

# Ouroboros Bitcoin Node (Umbrella Project)

## Architecture

Ouroboros is an umbrella project containing multiple Bitcoin node implementations:

| Component | Language | Location | Status |
|-----------|----------|----------|--------|
| Ouroboros (original) | Python + Rust | `src/ouroboros/`, `ferrous-utils/sync/` | Legacy — hybrid Python/Rust node |
| Beamchain | Erlang/OTP | `/home/max/hashhog/beamchain/` | Active — full Erlang rewrite |
| Pequod | Erlang | `pequod/` | Sub-project |

## Original Python + Rust Node

### Key Files

| Concern | Path |
|---------|------|
| Entry point | `src/ouroboros/cli.py` |
| Node orchestration | `src/ouroboros/node.py` |
| Script verification | `src/ouroboros/script.py` |
| Block/tx validation | `src/ouroboros/validation.py` |
| Mempool | `src/ouroboros/mempool.py` |
| RPC | `src/ouroboros/rpc.py` |
| Rust sync engine | `ferrous-utils/sync/src/` |

### Build and Test

```bash
# Rebuild Rust extension after changes
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml

# Tests
pytest
cargo test --workspace
```

Python 3.10-3.12 preferred; 3.13 has limited dependency support.

### Networks and Config

Networks: `mainnet`, `testnet`, `testnet3`, `testnet4`, `regtest`, `signet`.
Data dir: `~/.ouroboros` (override with `--data-dir` or `OUROBOROS_DATADIR`).
Use `--network testnet4` or `testnet` for faster sync during development.

## Beamchain (Erlang Rewrite)

The active development is in the Beamchain project at `/home/max/hashhog/beamchain/`. When working on Beamchain code, use Claude from that directory — it has its own skill with detailed script interpreter debugging knowledge, consensus rules, and bug fix history.

## Common Gotchas

1. **Two codebases**: The Python/Rust code in this repo is the legacy implementation. Active development is in Beamchain (Erlang).
2. **Rust rebuild**: After editing `ferrous-utils/sync`, run `maturin develop`; Python imports `sync` from the extension.
3. **RUST_LOG**: Set `RUST_LOG=sync=debug` or `OUROBOROS_VERBOSE=1` for sync debugging.
4. **Tests and standardness**: Unit tests with minimal tx (e.g. OP_TRUE) fail `IsStandardTx`. Use `Mempool(require_standard=False)`.
5. **Rust disabled opcodes**: `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT` must fail scripts; never implement them.
