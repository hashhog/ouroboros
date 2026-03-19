# Ouroboros — Remaining Gaps vs Bitcoin Core

## What's Already Implemented

The following consensus fixes are complete (from previous sessions):

- Difficulty retargeting (2016-block, testnet min-difficulty)
- Block weight (4MW) and sigops limits (legacy + P2SH + witness)
- Witness commitment validation (SegWit coinbase)
- Coinbase amount `<=` (miners may underpay)
- Timestamp MTP rule + future time limit
- No minimum fee in consensus
- Duplicate input check (CVE-2018-17144)
- Tapscript unification (SigVersion enum, OP_CHECKSIGADD, sigops budget)
- Block template dependency ordering
- TX relay (INV/GETDATA/TX)
- BIP30 duplicate txid check
- Complete sigops counting (P2SH + witness)
- BIP34 coinbase height enforcement
- FindAndDelete for legacy sighash
- Unknown taproot leaf versions → succeed (BIP 341 forward compat)
- Merkle malleation detection (CVE-2012-2459)
- Coinbase position/uniqueness enforcement
- IsFinalTx locktime completion (height + time + sequence)
- Coinbase scriptSig minimum 2 bytes

---

## Tier 1 — Consensus / Validation (High Priority)

### 1.1 Script Flag Enforcement Gaps

**Files**: `src/ouroboros/script.py`
**Status**: Flags are defined and set in `get_flags_for_height()` but never checked during opcode execution.

#### 1.1a DISCOURAGE_UPGRADABLE_NOPS
Reserved NOPs (OP_NOP1, OP_NOP4–OP_NOP10 / 0xb0, 0xb3–0xb9) are silently skipped. When `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` is set, Bitcoin Core rejects them.

#### 1.1b STRICTENC pubkey validation
Bitcoin Core's `CheckPubKeyEncoding()` validates that pubkeys are exactly 33 bytes (compressed, prefix 0x02/0x03) or 65 bytes (uncompressed, prefix 0x04). Ouroboros accepts any length.

#### 1.1c MINIMALDATA push validation
Only enforced for CScriptNum interpretation. Not enforced during push operations (e.g., using OP_PUSHDATA1 for data that fits in a direct push).

#### 1.1d WITNESS_PUBKEYTYPE
Flag is set at SegWit activation but never checked. Should validate pubkey format in witness scripts.

#### 1.1e CONST_SCRIPTCODE
Flag defined but never checked. Should reject OP_CODESEPARATOR in non-segwit scripts when set.

#### 1.1f DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
Not defined. Should reject unknown taproot leaf versions when this flag is set (policy, not consensus — but Bitcoin Core enforces it for relay).

#### 1.1g DISCOURAGE_OP_SUCCESS
Not defined. Should reject OP_SUCCESS opcodes when set (policy for relay).

```
Prompt:

Read src/ouroboros/script.py and implement the following script flag enforcement gaps. For each, add the actual runtime check in the opcode handler or verification flow:

1. DISCOURAGE_UPGRADABLE_NOPS (line 45): In the NOP handler (around line 1266), when `flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` is set, raise ValueError for OP_NOP1 (0xb0) and OP_NOP4-OP_NOP10 (0xb3-0xb9). Note: OP_NOP2 (0xb1) = OP_CHECKLOCKTIMEVERIFY and OP_NOP3 (0xb2) = OP_CHECKSEQUENCEVERIFY are already handled.

2. STRICTENC pubkey validation: Add a _check_pubkey_encoding() method. For legacy/witness_v0, when SCRIPT_VERIFY_STRICTENC is set, validate pubkeys are 33 bytes (prefix 0x02/0x03) or 65 bytes (prefix 0x04). Call it from OP_CHECKSIG, OP_CHECKSIGVERIFY, and OP_CHECKMULTISIG handlers in the legacy/v0 path.

3. MINIMALDATA push validation: In the data push handler (around line 600-630), when SCRIPT_VERIFY_MINIMALDATA is set, reject pushes that use a longer encoding than necessary (e.g., OP_PUSHDATA1 for data <= 75 bytes, OP_PUSHDATA2 for data <= 255 bytes).

4. WITNESS_PUBKEYTYPE: In the SegWit v0 verification paths (P2WPKH, P2WSH), when SCRIPT_VERIFY_WITNESS_PUBKEYTYPE is set, validate that pubkeys are compressed (33 bytes, prefix 0x02/0x03).

5. CONST_SCRIPTCODE: In the OP_CODESEPARATOR handler (around line 966), when SCRIPT_VERIFY_CONST_SCRIPTCODE is set and sig_version is BASE (not witness), raise ValueError.

6. Add SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1 << 18) and SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = (1 << 19) flag constants. In _verify_taproot_scriptpath(), when DISCOURAGE_UPGRADABLE_TAPROOT_VERSION is set and leaf_version != 0xc0, raise ValueError. In the OP_SUCCESS pre-check, when DISCOURAGE_OP_SUCCESS is set, raise ValueError.

Also update get_flags_for_height() to include DISCOURAGE_UPGRADABLE_NOPS at SegWit activation and DISCOURAGE_UPGRADABLE_TAPROOT_VERSION + DISCOURAGE_OP_SUCCESS at Taproot activation.

Run `python -m pytest tests/ -v` after all changes.
```

---

### 1.2 GetBlockScriptFlags Equivalent

**File**: `src/ouroboros/script.py`
**Status**: `get_flags_for_height()` exists but is incomplete — doesn't handle all deployment-based flags.

```
Prompt:

Read src/ouroboros/script.py function get_flags_for_height() (line 79-97) and Bitcoin Core's GetBlockScriptFlags() in bitcoin/src/validation.cpp (around line 2249-2288).

Update get_flags_for_height() to match Bitcoin Core's flag activation:
- BIP16 (P2SH): height >= 173805 → SCRIPT_VERIFY_P2SH (already done)
- BIP66 (DERSIG): height >= 363725 → SCRIPT_VERIFY_DERSIG (already done)
- BIP65 (CLTV): height >= 388381 → SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (already done)
- BIP68/112/113: height >= 419328 → SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (already done)
- SegWit (BIP141): height >= 481824 → add SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, SCRIPT_VERIFY_CONST_SCRIPTCODE
- Taproot (BIP341): height >= 709632 → add SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS

Run tests after.
```

---

### 1.3 BIP94 Testnet4 Difficulty + Timewarp Protection

**File**: `src/ouroboros/validation.py`
**Status**: Testnet4 min-difficulty exception exists but BIP94's special `CalculateNextWorkRequired` (using first block of period) and timewarp protection are missing.

```
Prompt:

Read src/ouroboros/validation.py method _get_expected_bits() (around line 272-332) and Bitcoin Core's pow.cpp (lines 50-85, especially 66-76 for BIP94).

Implement:
1. In the retarget boundary section (height % 2016 == 0), when self.network == "testnet4": use the nBits from the FIRST block of the difficulty period (height - 2015) instead of the last block, matching Bitcoin Core pow.cpp:66-76.

2. Add timewarp attack protection (Bitcoin Core validation.cpp:4144-4154): when self.network in ("testnet4", "regtest") and height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0, check that block.timestamp is not more than MAX_TIMEWARP (600) seconds before prev_block.timestamp. If violated, return False from _validate_header().

Run tests after.
```

---

### 1.4 MoneyRange Overflow Checking

**File**: `src/ouroboros/validation.py`
**Status**: Basic checks exist but no comprehensive overflow protection matching Bitcoin Core's `MoneyRange()`.

```
Prompt:

Read src/ouroboros/validation.py and add MoneyRange overflow checking:

1. Add a constant: MAX_MONEY = 21_000_000 * 100_000_000 (2,100,000,000,000,000 satoshis)

2. In _check_structure() (around line 710): after checking individual output values, add a total outputs overflow check:
   - Sum all output values and verify the total <= MAX_MONEY

3. In validate_transaction() (around line 634): after summing input values, verify total_input <= MAX_MONEY (guards against overflow from corrupted UTXO data).

4. In _calculate_tx_fee(): verify fee (total_input - total_output) is non-negative and <= MAX_MONEY.

Run tests after.
```

---

## Tier 2 — P2P Networking (Important)

### 2.1 Inbound Connections

**Files**: `src/ouroboros/node.py`, `src/ouroboros/peer.py`
**Status**: Ouroboros only makes outbound connections. No listening socket.

```
Prompt:

Read src/ouroboros/node.py and src/ouroboros/peer.py to understand the current peer architecture.

Implement inbound connection support:

1. In node.py, add a listening socket (asyncio.start_server) that accepts TCP connections on the configured port (default 8333 for mainnet, 18333 for testnet).

2. For each inbound connection, create a Peer object with an `inbound=True` flag.

3. The inbound handshake is reversed from outbound: the inbound peer sends version first, we receive it, send our version, then verack exchange.

4. Update peer.py:
   - Add `inbound: bool = False` parameter to __init__
   - Add `_inbound_handshake()` method that receives version first, validates it, then sends our version + verack
   - The existing connect() and _handshake() remain for outbound

5. Add inbound peers to PeerManager so they participate in block/tx relay.

6. Limit inbound connections (MAX_INBOUND = 117, matching Bitcoin Core's default).

7. Add a `--listen` / `--nolisten` CLI flag to control whether the node accepts inbound connections.

Run tests after.
```

---

### 2.2 Service Flags

**Files**: `src/ouroboros/peer.py`, `src/ouroboros/p2p_messages.py`
**Status**: `services=1` is hardcoded.

```
Prompt:

Read src/ouroboros/peer.py (line 212 where services=1 is hardcoded) and src/ouroboros/p2p_messages.py.

1. Add service flag constants to p2p_messages.py:
   NODE_NETWORK = (1 << 0)         # 0x01
   NODE_BLOOM = (1 << 2)           # 0x04
   NODE_WITNESS = (1 << 3)         # 0x08
   NODE_NETWORK_LIMITED = (1 << 10) # 0x400
   NODE_P2P_V2 = (1 << 11)        # 0x800

2. In peer.py _handshake(), replace `services=1` with `services=NODE_NETWORK | NODE_WITNESS` (since ouroboros supports SegWit). If v2 transport is available, also set NODE_P2P_V2.

3. After receiving the peer's version, validate their service flags:
   - If we need witness data (SegWit-era), prefer peers with NODE_WITNESS
   - Log a warning if peer lacks NODE_NETWORK (they may not serve full blocks)

Run tests after.
```

---

### 2.3 Address Gossip (AddrMan)

**Files**: `src/ouroboros/node.py`, `src/ouroboros/p2p.py`, new file `src/ouroboros/addrman.py`
**Status**: addr/addrv2 messages are parsed but never relayed. No address database.

```
Prompt:

Read src/ouroboros/p2p.py (handler registration for addr messages) and src/ouroboros/p2p_messages.py (AddrMessage, AddrV2Message, GetAddrMessage classes).

Implement address gossip:

1. Create src/ouroboros/addrman.py with an AddressManager class:
   - Stores known peer addresses with metadata (services, last_seen, source, attempts, last_success)
   - Two tables: "new" (unverified) and "tried" (successfully connected)
   - Methods: add(addr), get_addresses(count), select_for_connection(), mark_good(addr), mark_attempt(addr)
   - Persistence: save/load to a JSON file in the data directory
   - Limit: 65536 addresses max

2. In node.py, initialize AddressManager during startup. On each successful outbound connection, call mark_good().

3. In p2p.py, implement the addr message handlers:
   - on_addr / on_addrv2: parse addresses, add to AddrMan, relay to 1-2 random peers (rate-limited to max 1000/day per peer)
   - on_getaddr: respond with up to 1000 random addresses from AddrMan

4. Periodically (every 30s), if connection count < target, try connecting to an address from AddrMan.

5. After initial handshake, send getaddr to new outbound peers.

Run tests after.
```

---

### 2.4 sendheaders / Compact Block Announcements

**Files**: `src/ouroboros/block_sync.py`, `src/ouroboros/node.py`
**Status**: sendheaders and sendcmpct are negotiated but new blocks aren't announced via headers or compact blocks.

```
Prompt:

Read src/ouroboros/block_sync.py and src/ouroboros/node.py.

When a new block is received and validated:
1. Track which peers have sent sendheaders (add a `wants_headers: bool` field to Peer).
2. Track which peers have sent sendcmpct with announce=True (add a `wants_cmpctblock: bool` field).
3. After applying a new block to the chain:
   - To peers with wants_cmpctblock=True: send a CmpctBlockMessage (use compact_blocks.py)
   - To peers with wants_headers=True: send a HeadersMessage with just the new block header
   - To other peers: send an InvMessage with the block hash

4. In p2p.py on_sendheaders handler, set peer.wants_headers = True.
5. In p2p.py on_sendcmpct handler, if announce=True, set peer.wants_cmpctblock = True.

Run tests after.
```

---

### 2.5 Fee Filter Enforcement

**Files**: `src/ouroboros/peer.py`, `src/ouroboros/node.py`
**Status**: Hardcoded 1000 sat/kB feefilter sent. Peer feefilter not respected for outgoing TX relay.

```
Prompt:

Read src/ouroboros/peer.py and src/ouroboros/node.py (the tx relay handler).

1. In peer.py, add `peer_feefilter: int = 0` to track the peer's minimum fee rate.
2. In the feefilter handler (p2p.py on_feefilter), store the peer's fee rate: `peer.peer_feefilter = ff.feerate`.
3. When relaying transactions to peers (node.py _make_tx_handler), skip peers whose peer_feefilter > tx's fee rate (in sat/kB).
4. Periodically update our feefilter based on mempool minimum fee rate (not hardcoded 1000).

Run tests after.
```

---

## Tier 3 — Mempool (Important)

### 3.1 Orphan Transaction Pool

**File**: `src/ouroboros/mempool.py`
**Status**: Transactions with missing parents are rejected immediately.

```
Prompt:

Read src/ouroboros/mempool.py.

Add orphan transaction handling:

1. Add an OrphanPool class (or integrate into Mempool):
   - Dictionary: orphan_txid → (Transaction, expiry_time)
   - Index: missing_parent_txid → set of orphan txids
   - Limit: MAX_ORPHAN_TRANSACTIONS = 100
   - Expiry: 20 minutes

2. In add_transaction(), when a UTXO is not found:
   - Instead of immediately returning False, store the tx as an orphan
   - Track which parent txids are missing
   - Return a special status like (False, "orphan")

3. When a new transaction IS successfully added to the mempool:
   - Check the orphan index for any orphans waiting on this txid
   - Try to re-validate and accept those orphans
   - Recursively process (an accepted orphan may be a parent of another orphan)

4. Periodic cleanup: every 60 seconds, remove orphans older than 20 minutes.

5. Random eviction: if orphan pool is full, evict a random orphan before adding a new one.

Run tests after.
```

---

### 3.2 Mempool Persistence

**File**: `src/ouroboros/mempool.py`
**Status**: Mempool is purely in-memory, lost on restart.

```
Prompt:

Read src/ouroboros/mempool.py and understand the MempoolEntry structure.

Add mempool persistence:

1. Add dump_to_file(filepath) method:
   - Serialize each MempoolEntry as: raw_tx_bytes (varint-prefixed), fee (8 bytes LE), time_added (8 bytes LE)
   - Write a version byte (0x01) header
   - Write count (varint), then all entries

2. Add load_from_file(filepath) class method:
   - Read and validate version byte
   - Deserialize each entry
   - Re-validate each transaction before adding to mempool (UTXOs may have changed)
   - Skip transactions that fail validation (stale)

3. In node.py, call mempool.dump_to_file() during graceful shutdown.
4. In node.py, call Mempool.load_from_file() during startup (if file exists).
5. Default path: {datadir}/mempool.dat

Run tests after.
```

---

### 3.3 Witness Commitment in Block Templates

**File**: `src/ouroboros/rpc.py`
**Status**: getblocktemplate doesn't include the witness commitment OP_RETURN output.

```
Prompt:

Read src/ouroboros/rpc.py function rpc_getblocktemplate() and src/ouroboros/validation.py method _calculate_witness_merkle_root().

Add witness commitment generation to block templates:

1. After selecting transactions for the template, compute the witness merkle root:
   - wtxids = [bytes(32)] + [tx.get_wtxid() for tx in selected_txs]
   - Use the merkle root algorithm on wtxids

2. Use a default 32-byte zero nonce for the coinbase witness.

3. Compute the commitment: SHA256(SHA256(witness_root || nonce))

4. Add to the template response:
   - "default_witness_commitment": hex of the full scriptPubKey (6a24aa21a9ed + commitment_hash)

5. This tells miners to include this output in their coinbase transaction.

Run tests after.
```

---

### 3.4 Ancestor Count Staleness Fix

**File**: `src/ouroboros/mempool.py`
**Status**: ancestor_count/ancestor_size are set once at add-time and never updated on removal or RBF.

```
Prompt:

Read src/ouroboros/mempool.py and find where ancestor_count and ancestor_size are tracked in MempoolEntry.

Fix the staleness bug:

1. When a transaction is removed from the mempool (remove_transaction, or via RBF replacement):
   - Find all descendants of the removed transaction
   - Recalculate ancestor_count and ancestor_size for each descendant

2. Add a _recalculate_ancestors(txid) method that walks up the parent chain and recomputes the counts.

3. Call _recalculate_ancestors() for all affected descendants after any removal.

4. In try_replace() (RBF), after removing the conflicting transaction and its descendants, recalculate ancestors for any remaining transactions that referenced the removed ones.

Run tests after.
```

---

## Tier 4 — Database / Storage (Important for Robustness)

### 4.1 Complete Undo Data for Reorgs

**Files**: `src/ouroboros/database.py`, Rust code in `ferrous-utils/sync/src/storage/db.rs`
**Status**: SPENT_CF tracks spending txid but not the original UTXO value. disconnect_block() is a stub.

```
Prompt:

Read src/ouroboros/database.py (methods restore_utxo, remove_utxo around lines 466-520) and ferrous-utils/sync/src/storage/db.rs (spend_utxo method, disconnect_block method).

The goal is to make chain reorgs work:

1. In the Rust spend_utxo() function: before deleting the UTXO from CHAINSTATE_CF, serialize the full UTXO data (value, script_pubkey, height, is_coinbase) and store it in SPENT_CF alongside the spending txid. This creates an "undo record".

2. Implement disconnect_block() in Rust:
   - For each transaction in the block (reverse order):
     - For each output: remove from CHAINSTATE_CF (these UTXOs were created by this block)
     - For each input (non-coinbase): look up the undo record in SPENT_CF, restore the UTXO to CHAINSTATE_CF, delete the SPENT_CF entry
   - Remove the block from BLOCKS_CF
   - Update BEST_BLOCK_HASH and BEST_HEIGHT to the previous block
   - All operations in a single WriteBatch for atomicity

3. Expose disconnect_block(height) via PyO3 to Python.

4. In database.py, update restore_utxo() to use the new Rust API instead of the current incomplete implementation.

Run tests after. Test with: apply a block, then disconnect it, verify UTXOs are restored.
```

---

### 4.2 Two-Phase Commit for Crash Safety

**File**: Rust code in `ferrous-utils/sync/src/storage/db.rs`
**Status**: Single atomic WriteBatch. No crash-safe two-phase commit.

```
Prompt:

Read ferrous-utils/sync/src/storage/db.rs (apply_block method, update_best_block method) and Bitcoin Core's txdb.cpp (DB_HEAD_BLOCKS pattern).

Implement a two-phase commit for apply_block:

1. Before applying changes, write a HEAD_BLOCKS entry to META_CF containing [old_tip_hash, new_tip_hash]. This is Phase 1.

2. Apply all UTXO changes (spend inputs, create outputs) in a WriteBatch. Flush.

3. Update BEST_BLOCK_HASH and BEST_HEIGHT. Delete HEAD_BLOCKS entry. This is Phase 2.

4. On startup, check for HEAD_BLOCKS in META_CF:
   - If found, a crash occurred mid-apply
   - Use the old_tip_hash to determine the safe state
   - Rollback the partial apply by disconnecting the block (using undo data from 4.1)

This ensures the database is always in a consistent state even after crashes.

Run tests after.
```

---

## Tier 5 — RPC (Lower Priority)

### 5.1 getrawtransaction for Confirmed Transactions

**File**: `src/ouroboros/rpc.py`
**Status**: Only searches mempool, can't fetch historical transactions.

```
Prompt:

Read src/ouroboros/rpc.py function rpc_getrawtransaction() and src/ouroboros/database.py.

Currently getrawtransaction only checks the mempool. Add blockchain lookup:

1. If the tx is not in the mempool and blockhash is provided:
   - Get the block by hash from the database
   - Search the block's transactions for the matching txid
   - Return the transaction data

2. If no blockhash is provided and tx is not in mempool:
   - This requires a txindex (transaction index mapping txid → block_hash)
   - For now, return an error: "Transaction not in mempool. Use -txindex or provide blockhash."

3. (Optional) Add a transaction index:
   - New column family TX_INDEX_CF: txid → (block_hash, tx_position)
   - Populated during apply_block()
   - Enable via config flag txindex=1
   - When enabled, getrawtransaction can look up any confirmed tx

Run tests after.
```

---

### 5.2 getnetworkhashps Implementation

**File**: `src/ouroboros/rpc.py`
**Status**: Stub returning 0.0.

```
Prompt:

Read src/ouroboros/rpc.py function rpc_getnetworkhashps().

Implement network hash rate estimation:

1. Accept parameters: nblocks (default 120), height (default -1 = tip)
2. Get the block at `height` and the block at `height - nblocks`
3. Calculate: hashrate = (difficulty_at_tip * 2^32) / ((time_tip - time_start) / nblocks)
4. Where difficulty = target_max / current_target
5. Return the estimated hashes per second as a float

Reference: Bitcoin Core's GetNetworkHashPS() in rpc/mining.cpp.

Run tests after.
```

---

### 5.3 signrawtransactionwithkey Completion

**File**: `src/ouroboros/rpc.py`
**Status**: Stub implementation.

```
Prompt:

Read src/ouroboros/rpc.py function rpc_signrawtransactionwithkey() and src/ouroboros/wallet.py for existing signing logic.

Complete the implementation:

1. Accept parameters: hexstring (raw tx), privkeys (array of WIF keys), prevtxs (optional array of {txid, vout, scriptPubKey, amount})
2. Deserialize the raw transaction
3. For each input:
   - Find the previous output (from prevtxs or UTXO set)
   - Determine script type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
   - Find the matching private key from the provided keys
   - Sign with appropriate sighash (SIGHASH_ALL by default)
   - Populate scriptSig and/or witness as appropriate
4. Return: {hex: signed_tx_hex, complete: bool}

Run tests after.
```

---

### 5.4 verifychain Implementation

**File**: `src/ouroboros/rpc.py`
**Status**: Always returns True.

```
Prompt:

Read src/ouroboros/rpc.py function rpc_verifychain().

Implement basic chain verification:

1. Accept parameters: checklevel (0-4, default 3), nblocks (default 6)
2. Level 0: Read block data, verify it deserializes correctly
3. Level 1: Verify block hashes match stored hashes
4. Level 2: Verify merkle roots
5. Level 3: Verify proof-of-work meets difficulty target
6. Level 4: Verify all transactions (full validation — expensive)
7. Check the last `nblocks` blocks from the tip
8. Return true if all checks pass, false otherwise

Run tests after.
```

---

## Tier 6 — Nice-to-Have / Optimization

### 6.1 Package Validation / CPFP

**File**: `src/ouroboros/mempool.py`

```
Prompt:

Read src/ouroboros/mempool.py.

Implement basic package validation for CPFP (Child Pays For Parent):

1. Add a validate_package(txs: List[Transaction]) method:
   - txs must be topologically sorted (parents before children)
   - Maximum 25 transactions per package
   - Maximum 404,000 weight units per package
   - No duplicate transactions in the package
   - No double-spends within the package

2. For fee evaluation, compute the package fee rate:
   - Sum fees of all transactions in the package
   - Sum weights of all transactions
   - Package fee rate = total_fees / total_weight

3. Accept the package if the package fee rate meets the mempool minimum, even if individual transactions don't meet it (this is CPFP).

4. Add transactions to mempool in topological order.

Run tests after.
```

---

### 6.2 Block Template Snapshot Isolation

**File**: `src/ouroboros/rpc.py`

```
Prompt:

Read src/ouroboros/rpc.py function rpc_getblocktemplate().

The current implementation reads from the mempool without any locking, so the mempool can change during template construction (race condition).

Fix:
1. At the start of template construction, take a snapshot of the mempool state:
   - Copy the by_fee_rate list
   - Copy references to the transaction entries
2. Build the template from the snapshot only
3. This prevents inconsistencies from concurrent mempool modifications

If the mempool has a threading lock, acquire it during the snapshot. If not, add one (threading.Lock) and acquire/release around mempool mutations.

Run tests after.
```

---

### 6.3 Signet Block Solution Validation

**File**: `src/ouroboros/validation.py`
**Status**: Only relevant for Signet network.

```
Prompt:

Read Bitcoin Core's CheckBlockSolution() in signet.cpp.

Implement Signet block validation in validation.py:

1. Only applies when self.network == "signet"
2. Signet blocks must contain a valid signature in the coinbase's last OP_RETURN output
3. The signature is verified against the Signet challenge script (a network parameter)
4. Parse the Signet commitment from the coinbase
5. Verify the signature against the block header hash

This is a low-priority feature since Signet is a testing network.

Run tests after.
```

---

## Summary Table

| # | Fix | Priority | File(s) | Complexity |
|---|-----|----------|---------|------------|
| 1.1 | Script flag enforcement (7 flags) | High | script.py | Medium |
| 1.2 | GetBlockScriptFlags | High | script.py | Low |
| 1.3 | BIP94 Testnet4 difficulty | High | validation.py | Low |
| 1.4 | MoneyRange overflow | High | validation.py | Low |
| 2.1 | Inbound connections | High | node.py, peer.py | High |
| 2.2 | Service flags | Medium | peer.py, p2p_messages.py | Low |
| 2.3 | Address gossip (AddrMan) | Medium | new addrman.py | High |
| 2.4 | Block announcements | Medium | block_sync.py, node.py | Medium |
| 2.5 | Fee filter enforcement | Low | peer.py, node.py | Low |
| 3.1 | Orphan transaction pool | Medium | mempool.py | Medium |
| 3.2 | Mempool persistence | Low | mempool.py | Medium |
| 3.3 | Witness commitment in templates | Medium | rpc.py | Low |
| 3.4 | Ancestor count staleness | Medium | mempool.py | Medium |
| 4.1 | Undo data for reorgs | High | database.py, db.rs | High |
| 4.2 | Two-phase commit | Medium | db.rs | High |
| 5.1 | getrawtransaction blockchain | Medium | rpc.py | Medium |
| 5.2 | getnetworkhashps | Low | rpc.py | Low |
| 5.3 | signrawtransactionwithkey | Low | rpc.py | Medium |
| 5.4 | verifychain | Low | rpc.py | Low |
| 6.1 | Package validation / CPFP | Low | mempool.py | High |
| 6.2 | Template snapshot isolation | Low | rpc.py | Low |
| 6.3 | Signet validation | Low | validation.py | Medium |
