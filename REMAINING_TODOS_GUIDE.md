# Remaining TODOs: Recommendations and Implementation Guide

This document covers the remaining TODOs in the Ouroboros codebase after the fixes from `GAPS_AND_FIXES_GUIDE.md` and the "Do now / Do soon" RPC/block_sync improvements.

**Status:** F.1, F.2, G.1, G.2, H.1 completed. RPC wtxid, coinbase, bestblock, and block_sync header→block requests completed.

---

## Part 1: Remaining TODO Inventory

| Location | TODO | Category |
|----------|------|----------|
| `rpc.py` | Calculate mempool priority (startingpriority, currentpriority) | Mempool |
| `rpc.py` | Track mempool dependencies (depends) | Mempool |
| `cli.py` | Peer count and desync warnings | Sync UI |
| `wallet.py` | Initialize key storage | Wallet |
| `wallet.py` | Implement address generation | Wallet |
| `wallet.py` | Implement balance retrieval | Wallet |
| `wallet.py` | Implement address listing | Wallet |
| `wallet.py` | Implement transaction sending | Wallet |
| `wallet.py` | Implement transaction history | Wallet |

---

## Part 2: Recommendations by Category

### Category A: Mempool Priority and Dependencies

**Location:** `src/ouroboros/rpc.py` lines 490–492, `src/ouroboros/mempool.py`

**Recommendation: Defer (Medium effort, low urgency)**

**Rationale:**
- Mempool priority/dependencies require ancestor/descendant tracking in the mempool.
- Bitcoin Core uses a rich mempool model (CTxMemPoolEntry, ancestor score, etc.).
- Current mempool is simpler: fee-rate sorted, no ancestor sets.
- Most full-node use cases work without these fields.
- Implementation touches mempool design, RPC, and tests.

**If implemented, high-level steps:**
1. Add ancestor/descendant tracking to `Mempool` (sets of txids per entry).
2. Compute `modified_fee` = fee + sum of ancestor fees (for priority).
3. Compute `modified_size` = size + sum of ancestor sizes.
4. `currentpriority` = modified_fee / modified_size (sat/vB).
5. `depends` = list of unconfirmed ancestor txids.
6. Extend `MempoolEntry` and `get_transaction_entry` to expose these.
7. Update `rpc_getrawmempool` verbose output.

**Complexity:** Medium–high. Ancestor/descendant updates on add/remove must stay consistent.

---

### Category B: CLI Peer Count and Desync Warnings

**Location:** `src/ouroboros/cli.py` line 185, Rust `BlockProgressCache`, `SyncProgress`

**Recommendation: Implement when Rust layer supports it**

**Rationale:**
- Peer count and desync info live in the Rust sync layer.
- `BlockProgressCache` has no `peer_count` today.
- `desync_count` exists in block_sync but is not exposed to Python.
- Adding these to the sync progress will require Rust + Python changes.

**High-level steps:**
1. In `ferrous-utils/sync`: add `peer_count: u32` and `desync_warnings: u64` (or similar) to `BlockProgressCache`.
2. Update `BlockSync` / `HeaderSync` to write these when peers or desync state changes.
3. Expose them from `SyncProgressReporter::get_progress()` into `SyncProgress`.
4. Extend Python `SyncProgress` with `peer_count` and `desync_warnings`.
5. In `cli.py` progress callback: show peer count and desync warnings in the progress description.
6. Run `ouroboros sync` and verify display.

**Alternative:** If a Python `SyncManager` has access to a peer manager (e.g. after sync), peer count could be shown from Python instead. Current design uses Rust-only sync, so Rust is the main integration point.

---

### Category C: Wallet Implementation

**Location:** `src/ouroboros/wallet.py`

**Recommendation: Treat as a separate project; implement only if wallet is a goal**

**Rationale:**
- A full Bitcoin wallet is a large feature set.
- Needs key storage, HD derivation, signing, broadcast, privacy considerations.
- Ouroboros is currently a full-node/sync project; wallet is optional.
- Implementing all stubs is weeks of work.

**If you want a minimal usable wallet:**

| Step | Task | Effort |
|------|------|--------|
| 1 | Key storage | Medium – file-based encrypted storage or `libsecp256k1` key management |
| 2 | Address generation | Medium – BIP32/39/44 HD derivation, Bech32/Bech32m encoding |
| 3 | Balance retrieval | Low – use `db.list_unspent_by_address()` (already exists) |
| 4 | Address listing | Low – list from key storage |
| 5 | Transaction sending | High – build tx, sign inputs, broadcast via RPC or P2P |
| 6 | Transaction history | Medium – tx index or block scan for address |

**Priority order if doing a subset:** Balance → Address listing → Key storage → Address generation → Sending → History.

---

## Part 3: Cursor Prompts for Remaining TODOs

### Prompt M.1: Mempool Priority and Dependencies (Deferred)

```
In src/ouroboros/mempool.py and src/ouroboros/rpc.py:

1. Extend MempoolEntry to track:
   - ancestors: Set[bytes]  # txids of unconfirmed parents
   - descendants: Set[bytes]  # txids of unconfirmed children
2. When add_transaction runs:
   - For each input, if prev_tx is in mempool, add to ancestors
   - Update descendants of ancestor entries to include this tx
3. Add _compute_priority(entry) -> float:
   - modified_fee = entry.fee + sum(ancestor.fee for ancestor in mempool)
   - modified_size = entry.size + sum(ancestor.size for ancestor in mempool)
   - return modified_fee / modified_size if modified_size > 0 else 0
4. Add get_dependencies(txid) -> List[bytes]: return ancestor txids still in mempool
5. In rpc.py rpc_getrawmempool verbose:
   - "startingpriority": priority when first entered (use height_added to estimate, or store in entry)
   - "currentpriority": _compute_priority(entry)
   - "depends": [txid.hex() for txid in get_dependencies(txid)]
6. Add unit tests in test_mempool.py or test_rpc_methods.py
7. Ref: bitcoin/src/txmempool.cpp, CTxMemPoolEntry
```

---

### Prompt M.2: CLI Peer Count and Desync Warnings

```
In ferrous-utils/sync:

1. Add to BlockProgressCache (block_sync.rs):
   - peer_count: u32 (number of connected peers)
   - desync_warnings: u64 (count of desync events; already have desync_count)
2. Update BlockSync/HeaderSync to set peer_count when peer manager state changes
3. In SyncProgressReporter::get_progress (lib.rs):
   - Add peer_count and desync_warnings to SyncProgress
4. In Python sync_manager.py SyncProgress dataclass:
   - Add peer_count: int = 0, desync_warnings: int = 0
5. In cli.py progress_callback:
   - Append " | N peers" to the task description when phase is "block" and peer_count > 0
   - If desync_warnings > 0, show "[yellow]Desync: N[/yellow]" or similar
6. Ensure Rust SyncProgress pyclass exposes the new fields
7. Ref: bitcoin/src/net_processing.cpp, PROGRESS_DISPLAY_REFERENCE.md
```

---

### Prompt W.1: Wallet – Balance and Address Listing (Minimal)

```
In src/ouroboros/wallet.py:

1. get_balance(address):
   - Use BlockchainDatabase.list_unspent_by_address(address) 
   - Sum utxo["value"] for returned UTXOs
   - Requires db reference: add __init__(self, db: BlockchainDatabase, ...)
   - Return total satoshis
2. get_addresses():
   - Return self.addresses (populated when addresses are generated or loaded)
   - For now, return [] if no key storage; placeholder for future
3. Add a simple test in test_wallet.py that mocks db and tests get_balance with empty result
4. Note: Full implementation needs key storage and address generation first
```

---

### Prompt W.2: Wallet – Key Storage and Address Generation (Full)

```
In src/ouroboros/wallet.py:

1. Add key storage:
   - Use a JSON/encrypted file in data_dir/wallets/<name>/
   - Store: encrypted seed or xpriv (BIP32), derivation path (BIP44: m/84'/0'/0')
   - Use python-bitcoinlib or a minimal implementation for key derivation
2. generate_new_address():
   - Derive next external address from HD path (m/84'/0'/0'/0/<index>)
   - Use Bech32 (bc1...) for native SegWit
   - Append to self.addresses, persist to key storage
   - Return the new address string
3. Implement BIP32/BIP39 if not using a library:
   - BIP39: mnemonic -> seed
   - BIP32: seed -> xpriv -> child keys
4. Add create_wallet(mnemonic?, passphrase?) for initial setup
5. Ref: BIP32, BIP39, BIP44, bitcoin/src/wallet
```

---

## Part 4: Quick Reference

| TODO | Recommendation | Prompt |
|------|----------------|--------|
| Mempool priority/depends | Defer | M.1 |
| CLI peer count / desync | Implement when Rust ready | M.2 |
| Wallet (all) | Separate project; do balance/addresses if minimal | W.1, W.2 |

---

## Part 5: Verification After Each Fix

1. **M.1 (Mempool):** `getrawmempool true` returns non-zero priority and depends when applicable.
2. **M.2 (CLI):** `ouroboros sync` shows "N peers" and desync warnings when relevant.
3. **W.1 (Wallet balance):** `wallet.get_balance(addr)` returns correct sum for known addresses.
4. **W.2 (Wallet keys):** `generate_new_address()` produces valid Bech32 address; can sign and broadcast (if W.1+send implemented).
