# Ouroboros Full Node Implementation Guide

Steps and Cursor prompts to complete Ouroboros as a Bitcoin full node, with clear logging and terminal output.

**References:**
- `FULL_NODE_CHECKLIST.md` – Missing features
- `GAPS_AND_FIXES_GUIDE.md` – Gaps from code review (PoW, SegWit, orphans)
- `SYNC_RECOMMENDATIONS_20260212.md` – Sync tuning
- `PROGRESS_DISPLAY_REFERENCE.md` – Progress bar behavior
- `../bitcoin/src/` – Bitcoin Core implementation

---

## Part 1: Logging and Terminal Output

### Goal

Show what is happening in real time: sync phases, peer state, block progress, errors, and node status.

### Current State

- **Sync:** Rich progress bar, RUST_LOG for Rust (sync=debug very noisy)
- **Node start:** Basic info logs; little feedback during operation
- **Issues:** ~150k "Requested block X" lines at debug; no phase labels; desync/stall events not surfaced to user

---

## Part 2: Implementation Phases

### Phase A: Logging and User-Facing Output (Do First)

Makes the node understandable without changing correctness.

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| A.1 | Reduce block-request log verbosity | See Prompt A.1 |
| A.2 | Add sync phase labels and key metrics to progress | See Prompt A.2 |
| A.3 | Add node startup status output | See Prompt A.3 |

### Phase B: Core Calculations (Must Have)

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| B.1 | Fix difficulty calculation to match Bitcoin Core | See Prompt B.1 |
| B.2 | Persist and expose chainwork correctly | See Prompt B.2 |
| B.3 | Fix median time (remove dead code, verify logic) | See Prompt B.3 |
| B.4 | Implement nextblockhash in RPC | See Prompt B.4 |

### Phase C: Transaction and Block Handling

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| C.1 | Implement transaction deserialization | ✅ See Prompt C.1 |
| C.2 | Implement Block.serialize | ✅ See Prompt C.2 |
| C.3 | Implement rpc_sendrawtransaction (basic) | ✅ See Prompt C.3 |

### Phase D: UTXO and Script Execution

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| D.1 | UTXO querying by address | ✅ See Prompt D.1 |
| D.2 | ECDSA signature verification in script | ✅ See Prompt D.2 |

### Phase E: Advanced (Reorg, Production)

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| E.1 | Reorg handling | ✅ See Prompt E.1 |
| E.2 | Config file (ouroboros.conf) | ✅ See Prompt E.2 |

---

## Cursor Prompts

### Prompt A.1: Reduce Block-Request Log Verbosity

```
In ferrous-utils/sync/src/network/block_sync.rs:

1. Find the debug! log that prints "Requested block X from Y" for each block request
2. Change it to trace! so it only appears with RUST_LOG=sync=trace
3. Add or keep a summary log at batch boundaries, e.g. debug!("Sent {} block requests to {} peer(s)", count, num_peers)
4. Ensure "Received N blocks" or similar progress logs remain at info level

Reference: SYNC_RECOMMENDATIONS_20260212.md
```

### Prompt A.2: Improve Sync Progress and Terminal Output

```
In src/ouroboros/cli.py, improve the sync progress display:

1. When phase is "header": show "Phase: Header sync" and "headers" count
2. When phase is "block": show "Phase: Block sync" and "blocks" count with speed and ETA
3. Add a status line below the progress bar (or in the description) that shows:
   - Peer count (if available from sync_manager or Rust)
   - Any "No peers" or desync warnings - surface these from RUST_LOG to the user
4. On sync complete: print a clear "✓ Blockchain synchronization completed" with final height and duration
5. Use Rich's live display or console status for transient messages
6. Reference: PROGRESS_DISPLAY_REFERENCE.md for data flow

If peer count isn't available from SyncManager, add a note/TODO; at minimum improve the phase labels and completion message.
```

### Prompt A.3: Node Startup Status Output

```
In src/ouroboros/node.py start() and src/ouroboros/cli.py start command:

1. When node starts, print a clear status block to the terminal (using Rich Panel or Table):
   - Network, data dir
   - Best block height, hash (truncated)
   - RPC port, P2P port
   - "Node is running. Press Ctrl+C to stop."
2. If not synced: show a prominent warning "Blockchain not fully synced - run 'ouroboros sync' first"
3. Log key events: "Database initialized", "Peer manager started (N peers)", "RPC server listening on :PORT"
4. Use logger.info for file logging, and also console.print for user-visible status
5. Ensure the start command doesn't exit immediately - it should block until shutdown
```

### Prompt B.1: Fix Difficulty Calculation

```
In src/ouroboros/node.py, _bits_to_difficulty():

1. Bitcoin Core uses: GetDifficulty() in bitcoin/src/rpc/blockchain.cpp lines 96-115
   - nShift = (nBits >> 24) & 0xff
   - dDiff = 0x0000ffff / (nBits & 0x00ffffff)
   - while nShift < 29: dDiff *= 256; nShift++
   - while nShift > 29: dDiff /= 256; nShift--
2. Verify our formula matches. The checklist says we return placeholder - ensure we actually compute.
3. Add a unit test: known bits (e.g. 0x1d00ffff for difficulty 1) -> expected difficulty
4. Ref: bitcoin/src/rpc/blockchain.cpp GetDifficulty
```

### Prompt B.2: Persist Chainwork

```
Chainwork is computed in node.py _calculate_chainwork_at_height but stored in in-memory _chainwork_cache (database.py). It's lost on restart.

1. In ferrous-utils/sync: BlockMetadata already has chainwork field. Ensure we compute and store real chainwork when saving block metadata during sync.
   - See ferrous-utils/sync/src/validate/header.rs and block.rs - they use [0u8;32] placeholder
   - Add proper chainwork calculation: work = (2^256) / (target + 1), accumulate from genesis
   - Store in BlockMetadata when we persist block to DB

2. In src/ouroboros/database.py: add persistent chainwork storage.
   - Option A: Add a chainwork column/key in the database schema (Rust side), expose via PyBlockchainDB
   - Option B: Store chainwork in a separate Python-managed table/file keyed by block_hash, persist to disk
   - get_block_chainwork and store_block_chainwork should persist across restarts

3. Ref: bitcoin/src/rpc/blockchain.cpp nChainWork, arith_uint256
```

### Prompt B.3: Fix Median Time

```
In src/ouroboros/node.py get_median_time():

1. There is duplicate/dead code: two for-loops, the second overwrites the first. Remove the dead block (lines 443-454 roughly - the second loop that uses get_block_by_height)
2. The first loop uses get_block_hash_by_height then get_block - verify this path works with our DB
3. Median = middle of sorted timestamps of last 11 blocks (indices max(0, h-10) to h inclusive)
4. Add a simple test: 11 blocks with known timestamps -> median is the 6th sorted value
5. Ref: Bitcoin Core GetMedianTimePast()
```

### Prompt B.4: Implement nextblockhash in RPC

```
In src/ouroboros/rpc.py rpc_getblock():

1. The response includes "nextblockhash" which is currently None
2. If we have the block at height H, nextblockhash = block at height H+1
3. Use self.node.db.get_block_hash_by_height(block_height + 1) - convert to hex display format
4. Return None only if height+1 doesn't exist (we're at tip)
5. Ref: bitcoin/src/rpc/blockchain.cpp blockToJSON
```

### Prompt C.1: Transaction Deserialization ✅ DONE

```
In src/ouroboros/p2p_messages.py, TxMessage.from_payload():

1. ~~Currently raises NotImplementedError.~~ IMPLEMENTED. Full deserialization for non-SegWit and SegWit.
2. Format (Bitcoin wire): version(4) + marker+flag(2) if segwit + inputs(varint count, then each) + outputs(varint count, then each) + witness if segwit + locktime(4)
3. For non-SegWit: version(4) + input_count(varint) + [prev_txid(32), prev_vout(4), script_len(varint), script, sequence(4)] + output_count(varint) + [value(8), script_len(varint), script] + locktime(4)
4. Uses decode_varint for lengths, returns TxMessage with Transaction (version, inputs, outputs, locktime, txid)
5. Handle SegWit: if marker=0, flag=1, parse witness data per input before locktime (skipped for storage; txid excludes witness)
6. Tests: src/ouroboros/tests/test_transaction_deserialize.py (coinbase, P2PKH, SegWit)
7. Ref: bitcoin/src/primitives/transaction.cpp, ouroboros/ferrous-utils sync (tx already parsed in Rust)
```

### Prompt C.2: Block Serialization ✅ DONE

```
In src/ouroboros/database.py, Block.serialize():

1. ~~Currently raises NotImplementedError.~~ IMPLEMENTED. Full serialization to Bitcoin wire format.
2. Format: header(80) + tx_count(varint) + [serialized tx for each]
3. Header: version(4) + prev_blockhash(32) + merkle_root(32) + timestamp(4) + bits(4) + nonce(4)
4. All little-endian. Hashes reversed from display format to wire format.
5. Each tx: Transaction.serialize() (non-SegWit; SegWit blocks serialize without witness)
6. BlockMessage.to_network_message() now uses Block.serialize() (was NotImplementedError)
7. Tests: src/ouroboros/tests/test_block_deserialize.py (genesis round-trip, BlockMessage)
8. Ref: bitcoin/src/primitives/block.cpp
```

### Prompt C.3: rpc_sendrawtransaction (Basic) ✅ DONE

```
In src/ouroboros/rpc.py rpc_sendrawtransaction():

1. Accept hex-encoded raw transaction
2. Deserialize using TxMessage.from_payload()
3. Reject coinbase transactions
4. Add to mempool via self.node.mempool.add_transaction()
5. Broadcast inv (INV_TYPE_TX) to peers via peer_manager.broadcast()
6. getdata handler (node._register_handlers): respond with tx/block when peers request
7. Return txid (hex) on success; "Already in mempool" returns txid
8. Tests: src/ouroboros/tests/test_rpc_methods.py (invalid hex, coinbase, mempool unavailable)
9. Ref: bitcoin/src/rpc/rawtransaction.cpp
```

### Prompt D.1: UTXO Querying by Address ✅ DONE

```
Implement balance/UTXO lookup by address:

1. Address types: P2PKH (1...), P2SH (3...), P2WPKH (bc1.../tb1...)
2. address.py: address_to_script_pubkey() - base58 for legacy, bech32 for SegWit
3. Rust db.iter_utxos() - iterate chainstate; PyBlockchainDB.get_utxos()
4. database.py: get_balance(), list_unspent_by_address(), _iter_matching_utxos()
5. cli.py getbalance: uses db.get_balance(address)
6. rpc.py rpc_listunspent: filter by addresses via list_unspent_by_address
7. Tests: src/ouroboros/tests/test_address_utxo.py
8. Ref: bitcoin/src/rpc/blockchain.cpp gettxout, scantxoutset
```

### Prompt D.2: ECDSA in ScriptInterpreter

```
In src/ouroboros/script.py, ScriptInterpreter:

1. OP_CHECKSIG: pop sig, pop pubkey, verify ECDSA
2. Use secp256k1 (we have it in ferrous-utils/common crypto::verify_ecdsa_signature)
3. Message to verify: double-SHA256 of serialized tx (or appropriate part per SIGHASH type)
4. For v1: support SIGHASH_ALL; extend later for SIGHASH_SINGLE, etc.
5. OP_CHECKMULTISIG: verify k-of-n signatures
6. Ref: bitcoin/src/script/interpreter.cpp
```

### Prompt E.1: Reorg Handling

```
In src/ouroboros/block_sync.py _handle_reorg():

1. When we receive a block whose prev_blockhash doesn't match our tip, we have a reorg
2. Walk back our chain and the new chain to find common ancestor
3. Disconnect blocks from our tip down to ancestor: remove UTXOs created by those blocks, restore UTXOs spent
4. Connect new chain from ancestor to new tip: apply blocks, update UTXO set
5. Use db.restore_utxo and db.remove_utxo (see database.py)
6. Re-validate and re-add orphaned transactions to mempool if still valid
7. Ref: bitcoin/src/validation.cpp ConnectTip, DisconnectTip
```

### Prompt E.2: Config File Support

```
In src/ouroboros/config.py and node.py:

1. Parse ouroboros.conf from data_dir (or path from --config)
2. Support: datadir, network, rpcport, rpcuser, rpcpassword, rpcallowip, maxconnections, debug
3. Format: key=value, one per line; [section] for testnet4 etc. (Bitcoin-style)
4. Environment variables override config (OUROBOROS_DATADIR, etc.)
5. Create share/ouroboros.conf.example with documented options
6. Ref: bitcoin/src/util/settings.cpp
```

---

## Part 3: Recommended Order

```
1. A.1  - Log verbosity (quick win)
2. A.2  - Sync progress (user visibility)
3. A.3  - Node startup output (user visibility)
4. B.1  - Difficulty (RPC correctness)
5. B.3  - Median time (fix bug)
6. B.4  - nextblockhash (RPC completeness)
7. B.2  - Chainwork (larger, persistence)
8. C.1  - Tx deserialization (enables sendrawtransaction)
9. C.2  - Block serialize (enables getblock verbosity=0)
10. C.3  - sendrawtransaction (basic relay)
11. D.1  - UTXO by address (getbalance, listunspent)
12. D.2  - ECDSA (full validation)
13. E.1  - Reorg (chain safety)
14. E.2  - Config file (operations)
```

---

## Part 4: Verification

After each phase:

1. **Sync:** `ouroboros --network testnet4 sync` – Progress bar and logs should be clear
2. **Node:** `ouroboros --network testnet4 start` – Status block, RPC responds
3. **RPC:** `curl -X POST http://localhost:8332/ -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'` – difficulty, chainwork, mediantime non-placeholder
4. **Comparison:** Use TESTNET4_VERIFICATION_GUIDE.md to compare with Bitcoin Core

---

## Part 5: Logging Best Practices

| Context | Level | Example |
|---------|-------|--------|
| Sync phase transitions | INFO | "Header sync complete, starting block sync" |
| Block progress (batch) | INFO | "Received 50000 blocks" |
| Per-block requests | TRACE | (only with RUST_LOG=sync=trace) |
| Peer connect/disconnect | INFO | "Connected to peer X", "Peer X disconnected: reason" |
| Desync recovery | WARN | "Stream desync, trying magic resync" |
| No peers stall | WARN | "No peers for >5 min (N desyncs)" |
| RPC requests | DEBUG | Method and params (avoid logging sensitive) |
| Validation errors | WARN | "Block X failed validation: reason" |

**Environment:**
- Default: `RUST_LOG=sync=info` (or sync=warn)
- Verbose: `OUROBOROS_VERBOSE=1` → `RUST_LOG=sync=debug`
- Trace (debugging): `RUST_LOG=sync=trace`
