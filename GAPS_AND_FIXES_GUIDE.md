# Ouroboros Gaps and Fixes Guide

Gaps identified from code review (vs Bitcoin Core). Steps and Cursor prompts to address them.

**References:**
- `OUROBOROS_FULL_NODE_GUIDE.md` – Implementation phases
- `FULL_NODE_CHECKLIST.md` – Feature status
- `bitcoin/src/` – Bitcoin Core implementation

---

## Part 1: Priority Overview

| Priority | Gap | Location | Impact |
|----------|-----|----------|--------|
| **Critical** | Proof-of-work validation disabled | Rust header validator | Invalid blocks could be accepted |
| **Critical** | Python block validator has no PoW check | validation.py | Same for Python path |
| **Medium** | SegWit vsize/weight ignores witness | database.py Transaction | Fee/vsize wrong for SegWit txs |
| **Low** | Chainwork formula slight mismatch | ferrous-utils chainwork.rs | Minor; rarely matters |
| **Low** | Orphan block handling | block_sync.py | Blocks with missing parents not queued |
| **Optional** | Wallet stubs | wallet.py | N/A for full node only |

---

## Part 2: Implementation Phases

### Phase F: Proof-of-Work (Critical)

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| F.1 | Re-enable PoW validation in Rust | See Prompt F.1 |
| F.2 | Add PoW check to Python block validator | See Prompt F.2 |

### Phase G: SegWit and Orphans

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| G.1 | Fix SegWit weight/vsize calculation | See Prompt G.1 |
| G.2 | Orphan block management (optional) | See Prompt G.2 |

### Phase H: Chainwork (Low Priority)

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| H.1 | Align chainwork formula with Bitcoin Core | See Prompt H.1 |

---

## Part 3: Cursor Prompts

### Prompt F.1: Re-enable PoW Validation in Rust

```
In ferrous-utils/sync/src/validate/header.rs:

1. Uncomment and re-enable the proof-of-work validation block (lines 89-94)
2. The validate_pow function already exists in pow.rs and is correct:
   - Serializes header, computes double SHA-256
   - Compares hash (as U256) <= target
3. Ensure bits_to_target(inner.bits.to_consensus()) is used to get target
4. Remove the TODO comment about "temporarily disabled"
5. Run: cargo test -p sync (in ferrous-utils/sync) to verify no regressions
6. Ref: bitcoin/src/validation.cpp CheckBlock, pow.cpp
```

### Prompt F.2: Add PoW Check to Python Block Validator

```
In src/ouroboros/validation.py, BlockValidator._validate_header():

1. Add proof-of-work validation: block hash must meet difficulty target
2. Reuse logic from node.py _calculate_block_work / bits_to_target:
   - Decode target from block.bits (mantissa, exponent; target = mantissa * 256^(exponent-3))
   - Compute double SHA-256 of block header (80 bytes: version, prev_blockhash, merkle_root, timestamp, bits, nonce)
   - Compare: hash_as_int <= target
3. Block header for hashing: use block.serialize() first 80 bytes, or construct manually
   - Note: hashes in Bitcoin block header are in wire format (little-endian) for hashing
4. If hash > target: return False (invalid block)
5. Add unit test in test_validation.py or test_pow.py: genesis block (0x1d00ffff) passes, all-zeros hash fails
6. Ref: bitcoin/src/pow.cpp CheckProofOfWork
```

### Prompt G.1: Fix SegWit Weight/Vsize

```
In src/ouroboros/database.py, Transaction class:

1. Transaction needs to store witness data when deserializing SegWit txs
   - p2p_messages.py TxMessage.from_payload already parses SegWit (marker 0, flag 1)
   - Ensure witness data is preserved on Transaction or TxIn
2. Add witness_bytes attribute or method to Transaction/TxIn
3. In get_weight():
   - non_witness_bytes = size of tx without witness (version, inputs, outputs, locktime; exclude marker+flag and witness)
   - witness_bytes = sum of witness stack item lengths for all inputs
   - weight = (non_witness_bytes * 4) + witness_bytes
4. For non-SegWit: witness_bytes = 0 (current behavior)
5. get_vsize() stays: (weight + 3) // 4
6. Ref: bitcoin/src/primitives/transaction.cpp GetTransactionWeight
   - BIP 141: weight = (base size * 4) + total size (incl. witness)
```

### Prompt G.2: Orphan Block Management (Optional)

```
In src/ouroboros/block_sync.py:

1. When a block arrives whose prev_blockhash is not in our chain, it's an orphan
2. Add orphan_blocks: Dict[bytes, Block] to store blocks with missing parents
3. In handle_block: if db.get_block(block.prev_blockhash) is None:
   - Store in orphan_blocks[block.hash] = block (don't validate yet)
   - Optionally request prev block via getdata
4. When a new block is applied, check if any orphan has prev_blockhash == new_block.hash
   - If so, move orphan to main processing (validate and apply)
   - Recursively process orphans that now have parents
5. Limit orphan pool size (e.g. 100) to prevent memory exhaustion
6. Ref: bitcoin/src/net_processing.cpp orphan_work_set, ProcessOrphanTx
```

### Prompt H.1: Align Chainwork with Bitcoin Core (Low Priority)

```
In ferrous-utils/sync/src/validate/pow.rs, calculate_work():

Bitcoin Core uses: work = (~target / (target + 1)) + 1
  (See bitcoin/src/chain.cpp GetBitsProof, arith_uint256)

Current Ouroboros: work = max_target / target  (max_target = 2^256 - 1)

1. Change calculate_work to match Bitcoin Core:
   - work = (!target / (target + 1)) + 1 in U256 terms
   - In Rust: let target_plus_one = target + U256::one();
   - work = ((U256::max_value() - target) / target_plus_one) + U256::one();
   - Or: work = target.not() / target_plus_one + 1 (check U256 API)
2. Update chainwork.rs compute_chainwork to use the new calculate_work
3. Add test: genesis block chainwork should match Bitcoin Core for same bits
4. Ref: bitcoin/src/chain.cpp GetBitsProof
```

---

## Part 4: Verification

After each phase:

1. **F.1 (Rust PoW):** Sync a few blocks; invalid block (e.g. modified nonce) should be rejected
2. **F.2 (Python PoW):** `python -m pytest src/ouroboros/tests/test_validation.py -v -k pow`
3. **G.1 (SegWit):** RPC `getrawtransaction` for a SegWit tx; vsize should be < size
4. **G.2 (Orphans):** Receive block before parent; it should be queued, then applied when parent arrives

---

## Part 5: Quick Reference

| File | Change |
|------|--------|
| `ferrous-utils/sync/src/validate/header.rs` | Uncomment PoW check |
| `src/ouroboros/validation.py` | Add _validate_pow, call from _validate_header |
| `src/ouroboros/database.py` | Store witness, fix get_weight for SegWit |
| `src/ouroboros/p2p_messages.py` | Preserve witness on TxIn when parsing |
| `src/ouroboros/block_sync.py` | Orphan block dict, process when parent arrives |
| `ferrous-utils/sync/src/validate/pow.rs` | calculate_work formula (optional) |
