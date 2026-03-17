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
- [x] BIP125 Replace-By-Fee (RBF) with full RBF support (mempoolfullrbf)
- [x] Pre-handshake peer filtering (reject old protocol versions, timeout)
- [x] BIP339 WTXIDRELAY and BIP155 SENDADDRV2 negotiation
- [x] BIP155 addrv2 message format (Tor v3, I2P, CJDNS addresses)
- [x] Transaction trickling (privacy-preserving relay with Poisson delays)
- [x] Eclipse attack mitigations (bucketed addrman, /16 diversity, anchors, feelers)
- [x] Stale tip detection and peer eviction (ConsiderEviction, extra outbound connection)
- [x] sendrawtransaction RPC with maxfeerate, confirmed/mempool checks, detailed errors
- [x] getrawtransaction RPC with txindex support, verbose output, and in_active_chain
- [x] Bitcoin Core-compatible RPCs (getblockchaininfo, getmempoolinfo, getpeerinfo, etc.)
- [x] JSON-RPC batch request support (array of calls in single HTTP request)
- [x] Package relay and CPFP (child-pays-for-parent) package acceptance
- [x] submitpackage RPC for package submission (child-with-parents topology)
- [x] BIP331 P2P messages (sendpackages, getpkgtxns, pkgtxns, ancpkginfo)
- [x] PSBT (BIP174/BIP370) creation, signing, combining, and finalization
- [x] Taproot PSBT fields (key path sigs, script path, internal key)
- [x] Output descriptors (BIP380-386): pk, pkh, wpkh, tr, sh, wsh, multi, sortedmulti, combo, addr, raw
- [x] Descriptor RPCs: getdescriptorinfo, deriveaddresses, importdescriptors, listdescriptors
- [x] Miniscript (BIP379): parsing, type checking, compilation to Script, witness size analysis
- [x] Miniscript fragments: pk, pkh, older, after, sha256, hash256, ripemd160, hash160
- [x] Miniscript combinators: and_v, and_b, or_b, or_c, or_d, or_i, andor, thresh, multi, multi_a
- [x] Miniscript wrappers: a:, s:, c:, d:, v:, j:, n:, t:, l:, u:
- [x] Miniscript in descriptors: wsh(miniscript), tr(KEY, TREE)
- [x] REST interface for block explorers (block, tx, headers, utxos, mempool, chaininfo)
- [x] decoderawtransaction and decodescript RPCs
- [x] getbalance and signrawtransactionwithwallet RPCs
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
│   ├── rpc.py              # JSON-RPC server (FastAPI)
│   ├── rest.py             # REST interface for block explorers
│   ├── mempool.py          # Transaction mempool
│   ├── node.py             # Node orchestration
│   ├── psbt.py             # PSBT (BIP174/BIP370) support
│   ├── descriptors.py      # Output descriptors (BIP380-386)
│   ├── miniscript.py       # Miniscript (BIP379) support
│   └── validation.py       # Transaction/block validation
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
