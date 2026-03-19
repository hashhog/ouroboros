# Remaining Tasks for Full Bitcoin Node

Based on the implementation status, here's what's still needed to run as a complete Bitcoin full node.

## ✅ Already Completed (From Roadmap)

1. **Phase 1: Critical Bitcoin Calculations** ✅
   - ✅ Difficulty calculation (`get_difficulty`, `get_current_difficulty`)
   - ✅ Chainwork calculation (`get_chainwork`, `get_chainwork_at_height`)
   - ✅ Next block hash (`_get_next_block_hash` in RPC)
   - ⚠️ Median time (implemented but user reverted - placeholder remains)

2. **Phase 2: Transaction Handling** ✅
   - ✅ Transaction deserialization (`TxMessage.from_payload`)
   - ✅ Block serialization/deserialization (`Block.serialize`, `Block.deserialize`)

3. **Phase 3: Script Execution & ECDSA** ✅
   - ✅ ECDSA signature verification (`ScriptInterpreter._verify_ecdsa_signature`)
   - ✅ Signature hash calculation (basic implementation)

4. **Phase 4: Reorg Handling** ⚠️
   - ✅ Reorg detection and structure (`_handle_reorg`)
   - ⚠️ UTXO restoration (structure in place, needs database support)

5. **Phase 5: Configuration & Testing** ✅
   - ✅ Configuration file support (`NodeConfig`)
   - ✅ Test suite framework

## ❌ Critical Missing Features

### 1. **UTXO Restoration in Reorg Handling** (High Priority)

**Location:** `src/ouroboros/block_sync.py:535-564`

**Issue:** The `_handle_reorg()` method has the structure for disconnecting blocks and restoring UTXOs, but the actual UTXO restoration is a placeholder.

**What's needed:**
```python
# In _handle_reorg(), when disconnecting blocks:
# Need to properly restore spent UTXOs to the database
# Currently: logger.debug(f"Would restore {len(spent_to_restore)} UTXOs...")
# Needed: Actual database call to restore UTXOs
```

**Impact:** Reorgs won't properly restore the UTXO set, leading to incorrect chain state.

**Fix:** Implement or expose database methods for UTXO restoration:
- `db.restore_utxo(txid, vout, utxo_data)` - Restore a single UTXO
- Or use batch operations: `db.batch_restore_utxos(utxo_list)`

---

### 2. **Median Time Calculation** (Medium Priority)

**Location:** `src/ouroboros/node.py:390-410`

**Issue:** User reverted the median time implementation. Currently returns placeholder.

**What's needed:**
```python
def get_median_time(self, height: Optional[int] = None) -> int:
    # Get last 11 blocks' timestamps
    # Return median of those timestamps
```

**Impact:** RPC `getblockchaininfo` and `getblock` return incorrect median time.

**Fix:** Re-implement median time calculation (was done in Phase 1, Task 1.3).

---

### 3. **Transaction ID Calculation** (Medium Priority)

**Location:** `src/ouroboros/p2p_messages.py:574-590`

**Issue:** Transaction ID is calculated from serialized transaction, but this might not match Bitcoin's exact format (especially for SegWit).

**What's needed:**
- Ensure `transaction.serialize()` produces exact Bitcoin wire format
- For SegWit transactions, txid should exclude witness data
- Verify txid calculation matches Bitcoin Core

**Impact:** Transaction IDs might not match Bitcoin Core, causing compatibility issues.

---

### 4. **Block Storage in Database** (Medium Priority)

**Location:** `src/ouroboros/validation.py:103`

**Issue:** Comment says `store_block is not implemented in Python wrapper yet`.

**What's needed:**
- Ensure blocks are properly stored in database after validation
- Verify block storage includes all necessary metadata

**Impact:** Blocks might not be persisted correctly.

---

### 5. **RPC Method Completeness** (Low-Medium Priority)

**Missing RPC Methods:**
- `getrawmempool` - List all mempool transaction IDs
- `getblockheader` - Get block header without full block
- `gettxout` - Get UTXO information by outpoint
- `gettxoutproof` - Generate merkle proof
- `verifytxoutproof` - Verify merkle proof
- `estimatesmartfee` - Fee estimation
- `listunspent` - List UTXOs for addresses

**Location:** `src/ouroboros/rpc.py`

**Impact:** Limited RPC API compatibility with Bitcoin Core.

---

### 6. **Script Disassembly** (Low Priority)

**Location:** `src/ouroboros/rpc.py:451, 465`

**Issue:** RPC responses return empty `asm` field for scripts.

**What's needed:**
- Implement script disassembly to human-readable format
- Convert opcodes to names (OP_DUP, OP_HASH160, etc.)
- Handle data pushes

**Impact:** RPC responses less useful for debugging.

---

### 7. **SegWit Transaction Support** (Medium Priority)

**Location:** Multiple files

**Issues:**
- `rpc.py:435` - vsize/weight calculation is placeholder
- Witness data handling in transactions might be incomplete

**What's needed:**
- Proper vsize calculation: `vsize = (weight + 3) / 4`
- Proper weight calculation: `weight = (non-witness bytes * 4) + witness bytes`
- Ensure SegWit transactions are handled correctly throughout

**Impact:** SegWit transactions might not be properly validated or reported.

---

### 8. **Best Block Update in Reorg** (Medium Priority)

**Location:** `src/ouroboros/block_sync.py:590`

**Issue:** Comment says `set_best_block may not be implemented - this is a placeholder`.

**What's needed:**
- Verify `db.set_best_block()` exists and works correctly
- Or implement it if missing

**Impact:** After reorg, best block might not be updated correctly.

---

## 🔧 Quick Fixes Needed

### Immediate (To Run as Basic Full Node):

1. **Fix UTXO Restoration in Reorg** (1-2 hours)
   - Implement database method to restore UTXOs
   - Update `_handle_reorg()` to call it

2. **Re-implement Median Time** (30 minutes)
   - Restore the implementation from Phase 1, Task 1.3

3. **Verify Block Storage** (30 minutes)
   - Ensure blocks are stored after validation
   - Test block retrieval

### Short-term (For Feature Completeness):

4. **Add Missing RPC Methods** (4-6 hours)
   - Implement `getrawmempool`, `getblockheader`, `gettxout`
   - These are commonly used by Bitcoin tools

5. **Fix SegWit Support** (2-3 hours)
   - Proper vsize/weight calculation
   - Verify witness handling

6. **Script Disassembly** (2-3 hours)
   - Implement opcode-to-string conversion
   - Handle all standard opcodes

## 📊 Current Status Summary

**Can Run As:**
- ✅ Basic full node (syncs blocks, validates, serves RPC)
- ✅ P2P node (connects to peers, syncs blocks)
- ⚠️ Limited RPC compatibility (some methods missing)
- ⚠️ Reorg handling incomplete (UTXO restoration needed)

**Cannot Do Yet:**
- ❌ Properly handle deep reorgs (UTXO restoration)
- ❌ Some RPC methods (getrawmempool, gettxout, etc.)
- ❌ Accurate SegWit transaction reporting
- ❌ Script disassembly in RPC

## 🎯 Recommended Next Steps

1. **Priority 1:** Fix UTXO restoration in reorg handling
2. **Priority 2:** Re-implement median time calculation
3. **Priority 3:** Add critical missing RPC methods (`getrawmempool`, `gettxout`)
4. **Priority 4:** Fix SegWit vsize/weight calculation
5. **Priority 5:** Implement script disassembly

## ⏱️ Estimated Time

- **Critical fixes (1-3):** 2-3 hours
- **Feature completeness (4-6):** 8-12 hours
- **Total:** ~10-15 hours for production-ready full node

## 🚀 Can It Run Now?

**Yes, with limitations:**
- ✅ Can sync blockchain
- ✅ Can validate blocks and transactions
- ✅ Can serve basic RPC requests
- ✅ Can connect to Bitcoin network
- ⚠️ Reorgs won't properly restore UTXO set
- ⚠️ Some RPC methods missing
- ⚠️ Median time is placeholder

**Recommendation:** Fix UTXO restoration and median time before running on mainnet for extended periods.
