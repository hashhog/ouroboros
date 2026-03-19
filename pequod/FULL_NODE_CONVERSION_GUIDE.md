# Pequod: Converting to a Fully Validating Bitcoin Full Node

This document outlines how to convert Pequod from an **archival block storage node** into a **fully validating Bitcoin full node**, matching Bitcoin Core's consensus validation.

**Prerequisites:** Pequod has completed Phases 1–8 from `BITCOIN_ERLANG_IMPLEMENTATION_GUIDE.md` (protocol, peers, header sync, block sync, storage, peer manager, desync handling).

---

## 1. Current State vs Full Node

### What Pequod Has Today

| Component | Status |
|-----------|--------|
| P2P protocol (version, getheaders, headers, getdata, block) | ✅ |
| Header sync (PoW, chain link, timestamp) | ✅ |
| Block download (per-peer cap, timeout, avoid failed peer) | ✅ |
| Block storage (hash→block, height→hash) | ✅ |
| Peer management, seeds, blacklist | ✅ |
| Desync recovery (4MB sanity, TRY_RESYNC) | ✅ |

### What Bitcoin Core Validates (and Pequod Does Not)

| Validation | Bitcoin Core | Pequod |
|------------|--------------|--------|
| Block hash, prev_blockhash | ✅ | ✅ |
| **Merkle root** | ✅ CheckMerkleRoot | ❌ |
| **Transaction structure** | ✅ CheckTransaction | ❌ |
| **Script/signature verification** | ✅ VerifyScript | ❌ |
| **UTXO set (inputs exist, amounts)** | ✅ CheckTxInputs | ❌ |
| **Difficulty adjustment (2016 blocks)** | ✅ GetNextWorkRequired | ❌ |
| Coinbase rules (subsidy, BIP34) | ✅ | ❌ |
| Block size/weight limits | ✅ | ❌ |

---

## 2. Implementation Phases

### Phase A: Main Sync and CLI (Unblock Usage)

Enables running Pequod end-to-end without full validation. Blocks are stored; validation can be added later.

### Phase B: Block Structure Validation

Merkle root, transaction count, basic block rules. No script execution yet.

### Phase C: Transaction Parsing

Parse transactions from block binaries. Required before UTXO or script work.

### Phase D: UTXO Set

Maintain unspent outputs. Required for `CheckTxInputs`.

### Phase E: Script and Signature Verification

ECDSA verification, Bitcoin script execution. Most complex; may use NIF/port to existing code.

### Phase F: Difficulty Adjustment

Validate `bits` every 2016 blocks per `GetNextWorkRequired`.

### Phase G: Full Block Validation Pipeline

Wire all checks into block_sync; reject invalid blocks.

### Phase H: Optional (RPC, Mempool, Relay)

RPC server, mempool, block relay to peers.

---

## 3. Cursor Prompts (Copy-Paste Ready)

### Prompt A.1: Main Sync and CLI

```
Create src/pequod_sync.erl and a CLI entry point:

1. pequod_sync.erl gen_server:
   - sync(Network) -> start application, wait for header_sync + block_sync to run
   - Loop: poll get_best_block(), when height matches header tip and queue empty → done
   - Progress logging: blocks received, rate (blocks/s), ETA (cap at 999h when speed near 0)
2. CLI: add escript or script that runs `pequod sync testnet4`
   - Support --data-dir (optional; ETS is in-memory, persist later)
   - PEQUOD_SYNC_DIAG=1: log peer count, in-flight, queue every 60s
3. Start order: pequod_db, pequod_peer_sup, pequod_peer_manager, pequod_header_sync, pequod_block_sync
4. Ref: ../BITCOIN_ERLANG_IMPLEMENTATION_GUIDE.md Prompt 5.10, ../ferrous-utils/sync/src/lib.rs
```

### Prompt B.1: Merkle Root Verification

```
Add Merkle root verification to pequod:

1. src/pequod_merkle.erl:
   - compute_merkle_root([TxHashBin]) -> RootHash
   - Double-SHA256 each tx (as raw binary for leaf), build tree bottom-up
   - Formula: hash(concat(left, right)) per level; odd count: duplicate last
   - Ref: ../bitcoin/src/consensus/merkle.cpp, ../ferrous-utils/common compute_merkle_root
2. In pequod_block.erl: add verify_merkle_root(Header80, [TxBin]) -> boolean()
   - Extract merkle_root from header (bytes 36-67)
   - Parse txs to get list of tx hashes (double-SHA256 of each serialized tx)
   - compute_merkle_root([TxHashes]) == header_merkle_root
3. Block validation must fail if merkle root mismatch
4. Ref: ../bitcoin/src/consensus/merkle.h BlockMerkleRoot
```

### Prompt B.2: Block Structure Checks

```
Add block structure validation to pequod_block.erl:

1. check_block_structure(BlockBinary) -> ok | {error, Reason}
   - Block size <= 1MB (pre-SegWit) or 4MB weight limit for SegWit
   - Tx count >= 1 (coinbase required)
   - First tx is coinbase (input count 1, prevout 32 zeros + 0xffffffff)
   - No duplicate txids within block
2. Integrate into pequod_block_sync handle_block before store
3. Ref: ../bitcoin/src/validation.cpp CheckBlock, ../ferrous-utils/sync/src/validate/block.rs
```

### Prompt C.1: Transaction Parsing

```
Add src/pequod_tx.erl for transaction parsing:

1. parse(Binary) -> {ok, TxMap} | {error, Reason}
   - TxMap: #{version, inputs => [{prevout, script_sig, sequence}], outputs => [{value, script_pubkey}], locktime}
   - prevout: 32-byte hash + 4-byte index
   - script_sig, script_pubkey: varint length + raw bytes
   - Ref: ../bitcoin/src/primitives/transaction.h, bitcoin serialization format
2. txid(TxBinary) -> Hash (double-SHA256 of serialized tx for signing)
3. parse_list(Binary, Count) -> {ok, [TxMap], Rest} - parse Count txs from block payload
4. Ref: ../ferrous-utils/sync (TransactionWrapper), ../src/ouroboros/p2p_messages.py TxMessage
```

### Prompt D.1: UTXO Set

```
Add src/pequod_utxo.erl for UTXO management:

1. ETS table: {OutPoint, #{value, script_pubkey, height}}
   - OutPoint = {TxHash, Index}
2. API: put_utxo/4, get_utxo/2, spend/2 (remove), get_balance/1 (optional)
3. connect_block(Block, Height) -> ok | {error, Reason}
   - Spend all inputs (remove from UTXO)
   - Add all outputs (except coinbase until 100 conf - optional for sync)
   - Ref: ../bitcoin/src/validation.cpp ConnectBlock coins view
4. disconnect_block(Block, Height) -> ok (reverse for reorg)
5. Ref: ../ferrous-utils/sync storage, ../src/ouroboros/database.py chainstate
```

### Prompt D.2: CheckTxInputs (UTXO Validation)

```
Add input validation to pequod:

1. pequod_tx: check_inputs(TxMap, UTXOView) -> ok | {error, Reason}
   - For each input (skip coinbase): outpoint must exist in UTXO
   - Sum inputs >= sum outputs (fee >= 0)
   - No double spend within block (track used outpoints)
2. UTXOView can be from pequod_utxo or a cache built during ConnectBlock
3. Ref: ../bitcoin/src/consensus/tx_verify.cpp CheckTxInputs
```

### Prompt E.1: Script Verification (ECDSA)

```
Add script/signature verification - Phase 1 (ECDSA only):

1. src/pequod_script.erl:
   - verify_signature(MessageHash32, Signature, PubKey) -> boolean()
   - Use crypto:verify/4 with ecdsa, sha256
   - PubKey: 33-byte compressed or 65-byte uncompressed
   - Signature: 64-byte compact (r,s) or DER - Bitcoin uses DER in tx, need to extract r,s
2. For P2PKH: hash160(pubkey) == scriptPubKey, verify sig of sighash
3. Reference: ../bitcoin/src/script/interpreter.cpp, ../ferrous-utils/common verify_ecdsa_signature
4. Note: Full script engine (OP_CHECKSIG, OP_CHECKMULTISIG, etc.) is large; start with P2PKH only
```

### Prompt E.2: Script Engine (Minimal)

```
Extend pequod_script.erl for minimal script execution:

1. execute_script(ScriptSig, ScriptPubKey, Tx, InputIndex, PrevOut) -> ok | {error, Reason}
   - Stack machine: push/pop, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
   - SignatureHash: double-SHA256 of serialized tx with appropriate SIGHASH masking
   - Ref: ../bitcoin/src/script/interpreter.cpp EvalScript
2. Support: P2PKH, P2PK (minimal set for testnet4)
3. Consider NIF to Rust/bitcoin consensus lib if Erlang impl is too large
4. Ref: ../src/ouroboros/script.py ScriptInterpreter
```

### Prompt F.1: Difficulty Adjustment

```
Add difficulty adjustment validation to pequod:

1. src/pequod_difficulty.erl:
   - get_next_work_required(PrevBits, FirstBlockTime, LastBlockTime) -> NewBits
   - Every 2016 blocks: actual_timespan = last_time - first_time
   - Clamp timespan to [target/4, target*4] where target = 2 weeks
   - NewTarget = PrevTarget * (actual_timespan / target_timespan)
   - Convert target back to bits (pequod_pow:target_to_bits if added)
2. In pequod_header_sync: when (Height+1) rem 2016 =:= 0, validate bits of first header in batch
3. Genesis block (height 0): no adjustment
4. Ref: ../bitcoin/src/pow.cpp GetNextWorkRequired, ../ferrous-utils/sync validate/header.rs
```

### Prompt G.1: Full Block Validation Pipeline

```
Integrate full validation into pequod_block_sync:

1. On block receive: parse block -> validate -> connect
2. Validation order (match Bitcoin Core):
   a. Header (hash, prev, already done)
   b. Merkle root (pequod_merkle)
   c. Block structure (coinbase, no dups, size)
   d. For each tx: CheckTransaction (basic), CheckTxInputs (UTXO)
   e. For each tx: script verification (pequod_script)
   f. ConnectBlock: update UTXO (pequod_utxo:connect_block)
3. On failure: reject block, re-queue, optionally blacklist peer
4. Ref: ../bitcoin/src/validation.cpp ConnectBlock, ../ferrous-utils/sync validate/block.rs
```

### Prompt H.1: RPC Server (Optional)

```
Add minimal RPC server to pequod:

1. src/pequod_rpc.erl: gen_server listening on 8332 (configurable)
2. JSON-RPC 2.0 over HTTP: getblockhash, getblock, getblockcount
3. getblockhash(height) -> hex hash (reverse bytes for display)
4. getblock(hash, verbosity) -> block json
5. Ref: ../bitcoin/src/rpc/blockchain.cpp, ../src/ouroboros/rpc.py
```

---

## 4. Implementation Order

| Order | Phase | Prompt | Dependencies |
|-------|-------|--------|--------------|
| 1 | A | A.1 Main Sync + CLI | None |
| 2 | B | B.1 Merkle root | pequod_block parse |
| 3 | B | B.2 Block structure | pequod_tx (partial) |
| 4 | C | C.1 Transaction parsing | None |
| 5 | D | D.1 UTXO set | C.1 |
| 6 | D | D.2 CheckTxInputs | D.1, C.1 |
| 7 | E | E.1 ECDSA verify | crypto |
| 8 | E | E.2 Script engine | E.1 |
| 9 | F | F.1 Difficulty | pequod_pow |
| 10 | G | G.1 Full pipeline | B, C, D, E, F |

---

## 5. Bitcoin Core Reference Map

| Pequod Module | Bitcoin Core Path | Ouroboros / Ferrous |
|---------------|-------------------|---------------------|
| pequod_merkle | consensus/merkle.cpp | common/crypto compute_merkle_root |
| pequod_tx | primitives/transaction.cpp | TransactionWrapper |
| pequod_utxo | validation.cpp CCoinsViewCache | storage chainstate |
| pequod_script | script/interpreter.cpp | script.py, sync verify |
| pequod_difficulty | pow.cpp GetNextWorkRequired | validate/header.rs |

---

## 6. Testing Strategy

1. **Unit tests:** Merkle root (known blocks), tx parse, bits_to_target
2. **Integration:** Sync testnet4, compare block hashes to Bitcoin Core
3. **Invalid blocks:** Reject blocks with bad merkle, invalid sigs
4. **Script fuzz:** Use Bitcoin Core script_tests.json for script validation

---

## 7. Notes

- **Script complexity:** Full Bitcoin script has 100+ opcodes. Start with P2PKH/P2PK; defer P2SH, SegWit.
- **NIF option:** Consider `erlang-nif` or `rustler` to call ferrous-utils validation from Erlang.
- **Persistence:** ETS is in-memory. Add `dets` or RocksDB for block/UTXO persistence.
- **Reorg:** Implement disconnect_block for chain reorganizations.
