# Remaining Tasks Implementation Plan

This document provides step-by-step instructions and Cursor prompts for completing the remaining tasks to make Ouroboros a production-ready Bitcoin full node.

## Priority Order

1. **Task 1: Fix UTXO Restoration in Reorg Handling** (High Priority - Critical)
2. **Task 2: Re-implement Median Time Calculation** (Medium Priority - Important)
3. **Task 3: Add Missing RPC Methods** (Medium Priority - Compatibility)
4. **Task 4: Fix SegWit Transaction Support** (Medium Priority - Accuracy)
5. **Task 5: Implement Script Disassembly** (Low Priority - Nice to Have)
6. **Task 6: Verify Block Storage** (Medium Priority - Data Integrity)

---

## Task 1: Fix UTXO Restoration in Reorg Handling

**Priority:** High (Critical)  
**Estimated Time:** 1-2 hours  
**Files to Modify:** `src/ouroboros/block_sync.py`, `src/ouroboros/database.py`

### Problem

When a chain reorganization occurs, blocks need to be disconnected and their UTXOs restored. Currently, the `_handle_reorg()` method in `block_sync.py` has the structure but doesn't actually restore UTXOs - it just logs a placeholder message.

### Implementation Steps

**Step 1:** Understand the current UTXO restoration flow

**Prompt:**
```
In src/ouroboros/block_sync.py, the _handle_reorg() method at lines 535-564 collects UTXOs to restore but doesn't actually restore them. The method collects:
- spent_to_restore: List of (txid, vout) tuples for UTXOs that were spent
- created_to_remove: List of (txid, vout) tuples for UTXOs that were created

Currently it just logs: "Would restore {len(spent_to_restore)} UTXOs, remove {len(created_to_remove)} UTXOs"

To restore a UTXO, we need to:
1. Look up the transaction that created the UTXO (the transaction that was spent)
2. Get the output data (value, script_pubkey) from that transaction
3. Restore it to the database

The challenge is that when we disconnect a block, we need to reconstruct the UTXO from the transaction that created it. We need to look up the previous transaction that created each input.
```

**Step 2:** Implement UTXO restoration helper method

**Prompt:**
```
In src/ouroboros/block_sync.py, add a helper method to restore UTXOs during reorg:

```python
async def _restore_utxos_from_block(self, block: Block) -> List[Tuple[bytes, int, int, bytes]]:
    """
    Restore UTXOs that were spent in this block.
    
    For each non-coinbase transaction input, we need to:
    1. Find the transaction that created the UTXO (prev_txid)
    2. Get the output data from that transaction
    3. Return UTXO data: (txid, vout, value, script_pubkey)
    
    Returns:
        List of (txid, vout, value, script_pubkey) tuples for UTXOs to restore
    """
    utxos_to_restore = []
    
    for tx in block.transactions:
        if tx.is_coinbase:
            continue
        
        for tx_in in tx.inputs:
            # Get the transaction that created this UTXO
            prev_tx = self.db.get_transaction(tx_in.prev_txid)
            if not prev_tx:
                logger.warning(f"Previous transaction {tx_in.prev_txid.hex()[:16]}... not found, cannot restore UTXO")
                continue
            
            # Get the output that was spent
            if tx_in.prev_vout >= len(prev_tx.outputs):
                logger.warning(f"Invalid vout {tx_in.prev_vout} for transaction {tx_in.prev_txid.hex()[:16]}...")
                continue
            
            output = prev_tx.outputs[tx_in.prev_vout]
            
            # Add to restore list
            utxos_to_restore.append((
                tx_in.prev_txid,  # txid
                tx_in.prev_vout,  # vout
                output.value,     # value
                output.script_pubkey  # script_pubkey
            ))
    
    return utxos_to_restore
```

Note: This assumes `db.get_transaction()` exists. If not, we may need to get it from the block that contained it.
```

**Step 3:** Implement database method to restore UTXOs

**Prompt:**
```
In src/ouroboros/database.py, add a method to restore UTXOs. The current `update_utxo_set()` raises NotImplementedError. We need to either:

Option A: Use the Rust API directly if available
Option B: Implement a Python wrapper that calls the Rust layer

Add this method to BlockchainDatabase class:

```python
def restore_utxo(self, txid: bytes, vout: int, value: int, script_pubkey: bytes) -> None:
    """
    Restore a single UTXO to the database.
    
    This is used during chain reorganization to restore UTXOs that were spent.
    
    Args:
        txid: Transaction ID that created the UTXO
        vout: Output index
        value: Output value in satoshis
        script_pubkey: Script pubkey (locking script)
    """
    # Try to use Rust API if available
    try:
        # Check if Rust API has a method to restore UTXOs
        # This would need to be exposed from the Rust layer
        # For now, we can use a workaround by calling the Rust database directly
        pass
    except Exception as e:
        logger.error(f"Error restoring UTXO: {e}")
        raise

def batch_restore_utxos(self, utxos: List[Tuple[bytes, int, int, bytes]]) -> None:
    """
    Restore multiple UTXOs in a batch operation.
    
    Args:
        utxos: List of (txid, vout, value, script_pubkey) tuples
    """
    for txid, vout, value, script_pubkey in utxos:
        self.restore_utxo(txid, vout, value, script_pubkey)
```

If the Rust API doesn't expose this directly, we may need to:
1. Check ferrous-utils/sync/src/storage/db.rs for UTXO management methods
2. Expose a restore_utxo method from Rust to Python via PyO3
3. Or use the existing batch_update_utxos with appropriate parameters
```

**Step 4:** Update `_handle_reorg()` to actually restore UTXOs

**Prompt:**
```
In src/ouroboros/block_sync.py, update the _handle_reorg() method at lines 535-564 to actually restore UTXOs instead of just logging.

Replace the placeholder code:

```python
# Current placeholder code (lines 556-562):
# Update UTXO set (restore spent, remove created)
# Note: update_utxo_set is not fully implemented in Python wrapper
# This would need to be done via Rust API or implemented properly
try:
    # Reverse the update: restore spent UTXOs, remove created ones
    # This is a placeholder - full implementation needs proper UTXO management
    logger.debug(f"Would restore {len(spent_to_restore)} UTXOs, remove {len(created_to_remove)} UTXOs")
except Exception as e:
    logger.error(f"Error updating UTXO set during disconnect: {e}")
```

With actual implementation:

```python
# Restore UTXOs that were spent in this block
utxos_to_restore = await self._restore_utxos_from_block(curr_block)
if utxos_to_restore:
    try:
        # Convert to format expected by database
        restore_data = [
            {'txid': txid, 'vout': vout, 'value': value, 'script_pubkey': script_pubkey}
            for txid, vout, value, script_pubkey in utxos_to_restore
        ]
        # Use database method to restore (may need to implement)
        # For now, try using existing methods or Rust API
        logger.info(f"Restoring {len(restore_data)} UTXOs from disconnected block")
        # TODO: Call database restore method
    except Exception as e:
        logger.error(f"Error restoring UTXOs during disconnect: {e}")
        raise

# Remove UTXOs that were created in this block
for txid, vout in created_to_remove:
    try:
        # Remove UTXO from database
        # This may require a remove_utxo method or using Rust API
        logger.debug(f"Removing UTXO {txid.hex()[:16]}...:{vout}")
        # TODO: Call database remove method
    except Exception as e:
        logger.error(f"Error removing UTXO {txid.hex()[:16]}...:{vout}: {e}")
```

Note: This implementation depends on having database methods to restore and remove UTXOs. We may need to check the Rust API first.
```

**Step 5:** Check Rust database API for UTXO operations

**Prompt:**
```
Check ferrous-utils/sync/src/storage/db.rs for methods that can restore or remove UTXOs. Look for:
- Methods that modify the UTXO set
- Batch operations for UTXO updates
- Methods that can add/remove individual UTXOs

If such methods exist, we need to expose them via PyO3 in ferrous-utils/sync/src/lib.rs so they can be called from Python.

If they don't exist, we may need to implement them in Rust first, or use a workaround by reconstructing the UTXO set from blocks.
```

**Step 6:** Test UTXO restoration

**Prompt:**
```
Create a test to verify UTXO restoration works correctly:

1. Create a test blockchain with some blocks
2. Add some transactions that spend UTXOs
3. Simulate a reorg by disconnecting a block
4. Verify that UTXOs are properly restored
5. Verify that UTXOs created in the disconnected block are removed

Test file: src/ouroboros/tests/test_reorg_utxo_restoration.py
```

---

## Task 2: Re-implement Median Time Calculation

**Priority:** Medium (Important)  
**Estimated Time:** 30 minutes  
**Files to Modify:** `src/ouroboros/node.py`, `src/ouroboros/rpc.py`

### Problem

The median time calculation was implemented in Phase 1, Task 1.3 but was reverted by the user. Currently, `get_median_time()` returns a placeholder (current time).

### Implementation Steps

**Step 1:** Re-implement median time calculation

**Prompt:**
```
In src/ouroboros/node.py, re-implement the get_median_time() method at lines 390-410.

The median time is the median timestamp of the last 11 blocks (or fewer if not enough blocks exist).

Implementation:
1. If height is None, get the best block height
2. Get blocks from max(0, height-10) to height (11 blocks total)
3. Extract timestamps from each block
4. Sort timestamps
5. Return the median (middle value, index 5 for 11 blocks)

```python
def get_median_time(self, height: Optional[int] = None) -> int:
    """
    Get median time of last 11 blocks.
    
    Args:
        height: Block height (None for best block)
        
    Returns:
        Median timestamp of last 11 blocks
    """
    if not self.db:
        return int(time.time())
    
    try:
        # Get height if not provided
        if height is None:
            _, height = self.db.get_best_block()
        
        # Get timestamps of last 11 blocks (or fewer if not enough)
        timestamps = []
        for h in range(max(0, height - 10), height + 1):
            block_hash = self.db.get_block_hash_by_height(h)
            if not block_hash:
                continue
            block = self.db.get_block(block_hash)
            if block:
                timestamps.append(block.timestamp)
        
        if not timestamps:
            # No blocks, return current time
            return int(time.time())
        
        # Sort and get median
        timestamps.sort()
        median_index = len(timestamps) // 2
        return timestamps[median_index]
    
    except Exception as e:
        logger.error(f"Error calculating median time: {e}", exc_info=True)
        return int(time.time())
```

Note: This assumes `db.get_block_hash_by_height()` exists. If not, we may need to walk the chain.
```

**Step 2:** Verify median time is used in RPC

**Prompt:**
```
In src/ouroboros/rpc.py, verify that get_median_time() is being called correctly in:
- rpc_getblockchaininfo() - should use self.node.get_median_time()
- rpc_getblock() - should use self.node.get_median_time(block_height)

Check that these methods are using the median time calculation and not placeholders.
```

**Step 3:** Test median time calculation

**Prompt:**
```
Create a test to verify median time calculation:

1. Create a test with blocks at different timestamps
2. Calculate median time for various heights
3. Verify it returns the correct median value
4. Test edge cases (less than 11 blocks, no blocks, etc.)

Test file: src/ouroboros/tests/test_median_time.py
```

---

## Task 3: Add Missing RPC Methods

**Priority:** Medium (Compatibility)  
**Estimated Time:** 4-6 hours  
**Files to Modify:** `src/ouroboros/rpc.py`

### Problem

Several commonly-used RPC methods are missing, limiting compatibility with Bitcoin Core and Bitcoin tools.

### Implementation Steps

**Step 1:** Implement `getrawmempool`

**Prompt:**
```
In src/ouroboros/rpc.py, add the getrawmempool RPC method:

```python
async def rpc_getrawmempool(self, verbose: bool = False) -> Union[List[str], Dict[str, Dict[str, Any]]]:
    """
    Get all transaction IDs in mempool.
    
    Args:
        verbose: If True, return detailed information for each transaction
        
    Returns:
        If verbose=False: List of transaction IDs (hex strings)
        If verbose=True: Dictionary mapping txid to transaction info
    """
    if not self.node.mempool:
        return [] if not verbose else {}
    
    txids = list(self.node.mempool.transactions.keys())
    
    if not verbose:
        return [txid.hex() for txid in txids]
    
    # Return detailed information
    result = {}
    for txid in txids:
        entry = self.node.mempool.get_transaction_entry(txid)
        if entry:
            result[txid.hex()] = {
                "size": entry.size,
                "fee": entry.fee,
                "time": entry.time,
                "height": entry.height,
                "startingpriority": 0.0,  # TODO: Calculate priority
                "currentpriority": 0.0,    # TODO: Calculate priority
                "depends": []  # TODO: Track dependencies
            }
    
    return result
```

Register this method in _register_methods().
```

**Step 2:** Implement `getblockheader`

**Prompt:**
```
In src/ouroboros/rpc.py, add the getblockheader RPC method:

```python
async def rpc_getblockheader(self, blockhash: str, verbose: bool = True) -> Union[str, Dict[str, Any]]:
    """
    Get block header information.
    
    Args:
        blockhash: Block hash (hex string)
        verbose: If True, return JSON object; if False, return hex-encoded header
        
    Returns:
        If verbose=True: Dictionary with header fields
        If verbose=False: Hex-encoded block header (80 bytes)
    """
    try:
        block_hash = bytes.fromhex(blockhash)
        block = self.node.db.get_block(block_hash)
        
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")
        
        if not verbose:
            # Return hex-encoded header (80 bytes)
            # Serialize block header
            header_data = bytearray()
            header_data.extend(block.version.to_bytes(4, 'little', signed=True))
            header_data.extend(block.prev_blockhash[::-1])  # Reverse for wire format
            header_data.extend(block.merkle_root[::-1])
            header_data.extend(block.timestamp.to_bytes(4, 'little'))
            header_data.extend(block.bits.to_bytes(4, 'little'))
            header_data.extend(block.nonce.to_bytes(4, 'little'))
            return header_data.hex()
        
        # Return verbose JSON
        block_height = block.height if hasattr(block, 'height') and block.height else 0
        
        return {
            "hash": blockhash,
            "confirmations": 0,  # TODO: Calculate confirmations
            "height": block_height,
            "version": block.version,
            "versionHex": f"{block.version:08x}",
            "merkleroot": block.merkle_root.hex(),
            "time": block.timestamp,
            "mediantime": self.node.get_median_time(block_height),
            "nonce": block.nonce,
            "bits": f"{block.bits:08x}",
            "difficulty": self.node.get_difficulty(block.bits),
            "chainwork": self.node.get_chainwork_at_height(block_height),
            "previousblockhash": block.prev_blockhash.hex() if block.prev_blockhash != bytes(32) else None,
            "nextblockhash": self._get_next_block_hash(block_height)
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid block hash: {e}")
    except Exception as e:
        logger.error(f"Error getting block header: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
```

Register this method in _register_methods().
```

**Step 3:** Implement `gettxout`

**Prompt:**
```
In src/ouroboros/rpc.py, add the gettxout RPC method:

```python
async def rpc_gettxout(self, txid: str, n: int, includemempool: bool = True) -> Optional[Dict[str, Any]]:
    """
    Get UTXO information by outpoint.
    
    Args:
        txid: Transaction ID (hex string)
        n: Output index (vout)
        includemempool: If True, also check mempool
        
    Returns:
        Dictionary with UTXO information, or None if spent/not found
    """
    try:
        txid_bytes = bytes.fromhex(txid)
        
        # First check mempool if enabled
        if includemempool and self.node.mempool:
            # Check if transaction is in mempool
            if self.node.mempool.has_transaction(txid_bytes):
                tx = self.node.mempool.get_transaction(txid_bytes)
                if tx and n < len(tx.outputs):
                    output = tx.outputs[n]
                    return {
                        "bestblock": None,  # TODO: Get best block hash
                        "confirmations": 0,
                        "value": output.value / 100000000.0,  # Convert to BTC
                        "scriptPubKey": {
                            "asm": "",  # TODO: Disassemble script
                            "hex": output.script_pubkey.hex(),
                            "type": self._get_script_type(output.script_pubkey)
                        },
                        "coinbase": False
                    }
        
        # Check database (confirmed UTXOs)
        utxo = self.node.db.get_utxo(txid_bytes, n)
        if not utxo:
            return None
        
        # Get block height for confirmations
        # TODO: Find which block contains this transaction
        block_height = 0  # Placeholder
        best_hash, best_height = self.node.db.get_best_block()
        confirmations = max(0, best_height - block_height + 1) if block_height else 0
        
        return {
            "bestblock": best_hash.hex(),
            "confirmations": confirmations,
            "value": utxo['value'] / 100000000.0,  # Convert to BTC
            "scriptPubKey": {
                "asm": "",  # TODO: Disassemble script
                "hex": utxo['script_pubkey'].hex(),
                "type": self._get_script_type(utxo['script_pubkey'])
            },
            "coinbase": False  # TODO: Check if coinbase
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid transaction ID: {e}")
    except Exception as e:
        logger.error(f"Error getting txout: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
```

Register this method in _register_methods().
```

**Step 4:** Test new RPC methods

**Prompt:**
```
Create tests for the new RPC methods:

1. Test getrawmempool with verbose=False and verbose=True
2. Test getblockheader with verbose=False and verbose=True
3. Test gettxout with various UTXOs
4. Test error cases (invalid hashes, not found, etc.)

Test file: src/ouroboros/tests/test_rpc_methods.py
```

---

## Task 4: Fix SegWit Transaction Support

**Priority:** Medium (Accuracy)  
**Estimated Time:** 2-3 hours  
**Files to Modify:** `src/ouroboros/rpc.py`, `src/ouroboros/database.py`

### Problem

SegWit transaction size calculations (vsize and weight) are placeholders in RPC responses.

### Implementation Steps

**Step 1:** Implement proper transaction weight calculation

**Prompt:**
```
In src/ouroboros/database.py, add a method to calculate transaction weight:

```python
def calculate_transaction_weight(tx: Transaction) -> int:
    """
    Calculate transaction weight for SegWit transactions.
    
    Weight = (non-witness bytes * 4) + witness bytes
    
    For non-SegWit transactions, weight = size * 4
    
    Args:
        tx: Transaction object
        
    Returns:
        Transaction weight
    """
    # Serialize transaction without witness (for non-witness bytes)
    # This is the "traditional" serialization
    non_witness_bytes = len(tx.serialize())  # This should exclude witness if present
    
    # For SegWit transactions, we need to count witness bytes separately
    # Check if transaction has witness data
    has_witness = any(
        hasattr(tx_in, 'witness') and tx_in.witness 
        for tx_in in tx.inputs
    )
    
    if not has_witness:
        # Non-SegWit transaction: weight = size * 4
        return non_witness_bytes * 4
    
    # SegWit transaction: need to count witness bytes
    # Serialize with witness to get total size
    # Then: weight = (non_witness_bytes * 4) + witness_bytes
    # For now, approximate: if we have witness, assume it adds to size
    # Full implementation needs proper witness serialization
    total_bytes = len(tx.serialize())  # This might include witness
    witness_bytes = total_bytes - non_witness_bytes
    
    return (non_witness_bytes * 4) + witness_bytes
```

Note: This is a simplified implementation. Full implementation needs proper witness serialization.
```

**Step 2:** Implement vsize calculation

**Prompt:**
```
In src/ouroboros/rpc.py, update the _tx_to_dict() method to calculate proper vsize and weight:

```python
def _tx_to_dict(self, tx: Transaction, block_hash: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Convert transaction to dictionary for RPC response.
    
    Update the vsize and weight calculations to use proper SegWit formulas.
    """
    txid = tx.get_txid()
    txid_hex = txid.hex()
    
    # Calculate weight and vsize
    from ouroboros.database import calculate_transaction_weight
    
    weight = calculate_transaction_weight(tx)
    vsize = (weight + 3) // 4  # Round up
    
    return {
        "txid": txid_hex,
        "hash": txid_hex,  # TODO: Add wtxid for segwit
        "version": tx.version,
        "size": len(tx.serialize()),
        "vsize": vsize,  # Virtual size for SegWit
        "weight": weight,  # Transaction weight
        "locktime": tx.locktime,
        "vin": [self._vin_to_dict(vin, i, tx) for i, vin in enumerate(tx.inputs)],
        "vout": [self._vout_to_dict(vout, i) for i, vout in enumerate(tx.outputs)],
        "hex": tx.serialize().hex()  # TODO: Include witness if SegWit
    }
```

Update the method at lines 430-450 in rpc.py.
```

**Step 3:** Verify SegWit transaction handling

**Prompt:**
```
Verify that SegWit transactions are handled correctly throughout:

1. Check that TxMessage.from_payload() properly parses witness data
2. Verify that transaction serialization includes/excludes witness correctly
3. Test with actual SegWit transactions from Bitcoin testnet
4. Verify vsize and weight match Bitcoin Core for known transactions

Create test: src/ouroboros/tests/test_segwit.py
```

---

## Task 5: Implement Script Disassembly

**Priority:** Low (Nice to Have)  
**Estimated Time:** 2-3 hours  
**Files to Modify:** `src/ouroboros/rpc.py`, `src/ouroboros/script.py` (new module or add to existing)

### Problem

RPC responses return empty `asm` fields for scripts, making debugging difficult.

### Implementation Steps

**Step 1:** Create script disassembly function

**Prompt:**
```
Create a new function in src/ouroboros/script.py (or create src/ouroboros/script_disasm.py) to disassemble Bitcoin scripts:

```python
def disassemble_script(script: bytes) -> str:
    """
    Disassemble Bitcoin script to human-readable ASM format.
    
    Args:
        script: Script bytes
        
    Returns:
        Human-readable script assembly (e.g., "OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG")
    """
    if not script:
        return ""
    
    asm_parts = []
    i = 0
    
    while i < len(script):
        opcode = script[i]
        i += 1
        
        # Data push opcodes
        if opcode == 0x00:
            asm_parts.append("OP_0")
        elif 0x01 <= opcode <= 0x4b:
            # OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, or direct push
            if opcode <= 0x4b:
                # Direct push
                data_len = opcode
            elif opcode == 0x4c:  # OP_PUSHDATA1
                if i >= len(script):
                    break
                data_len = script[i]
                i += 1
            elif opcode == 0x4d:  # OP_PUSHDATA2
                if i + 1 >= len(script):
                    break
                data_len = int.from_bytes(script[i:i+2], 'little')
                i += 2
            elif opcode == 0x4e:  # OP_PUSHDATA4
                if i + 3 >= len(script):
                    break
                data_len = int.from_bytes(script[i:i+4], 'little')
                i += 4
            else:
                data_len = 0
            
            if data_len > 0 and i + data_len <= len(script):
                data = script[i:i+data_len]
                # Format as hex string
                asm_parts.append(data.hex())
                i += data_len
        else:
            # Opcode name
            opcode_name = _get_opcode_name(opcode)
            asm_parts.append(opcode_name)
    
    return " ".join(asm_parts)

def _get_opcode_name(opcode: int) -> str:
    """Get opcode name from opcode value"""
    opcode_names = {
        0x76: "OP_DUP",
        0xa9: "OP_HASH160",
        0x88: "OP_EQUALVERIFY",
        0xac: "OP_CHECKSIG",
        0x87: "OP_EQUAL",
        0x6a: "OP_RETURN",
        0x51: "OP_1",
        0x52: "OP_2",
        0x53: "OP_3",
        0x54: "OP_4",
        0x55: "OP_5",
        0x56: "OP_6",
        0x57: "OP_7",
        0x58: "OP_8",
        0x59: "OP_9",
        0x5a: "OP_10",
        0x5b: "OP_11",
        0x5c: "OP_12",
        0x5d: "OP_13",
        0x5e: "OP_14",
        0x5f: "OP_15",
        0x60: "OP_16",
        # Add more opcodes as needed
    }
    return opcode_names.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
```

Add comprehensive opcode name mapping.
```

**Step 2:** Use disassembly in RPC responses

**Prompt:**
```
In src/ouroboros/rpc.py, update _vin_to_dict() and _vout_to_dict() to use script disassembly:

```python
from ouroboros.script import disassemble_script

def _vin_to_dict(self, tx_in: TxIn, index: int, tx: Transaction) -> Dict[str, Any]:
    """Update to include script disassembly"""
    result = {
        "txid": tx_in.prev_txid.hex(),
        "vout": tx_in.prev_vout,
        "scriptSig": {
            "asm": disassemble_script(tx_in.script_sig),  # Add disassembly
            "hex": tx_in.script_sig.hex()
        },
        "sequence": tx_in.sequence
    }
    # ... rest of method

def _vout_to_dict(self, tx_out: TxOut, index: int) -> Dict[str, Any]:
    """Update to include script disassembly"""
    return {
        "value": tx_out.value / 100000000.0,
        "n": index,
        "scriptPubKey": {
            "asm": disassemble_script(tx_out.script_pubkey),  # Add disassembly
            "hex": tx_out.script_pubkey.hex(),
            "type": self._get_script_type(tx_out.script_pubkey)
        }
    }
```

Update lines 451 and 465 in rpc.py.
```

**Step 3:** Test script disassembly

**Prompt:**
```
Create tests for script disassembly:

1. Test P2PKH script disassembly
2. Test P2SH script disassembly
3. Test P2WPKH script disassembly
4. Test various opcodes
5. Verify output matches Bitcoin Core format

Test file: src/ouroboros/tests/test_script_disassembly.py
```

---

## Task 6: Verify Block Storage

**Priority:** Medium (Data Integrity)  
**Estimated Time:** 30 minutes  
**Files to Modify:** `src/ouroboros/validation.py`, `src/ouroboros/database.py`

### Problem

Comment in `validation.py:103` says `store_block is not implemented in Python wrapper yet`. Need to verify blocks are stored correctly.

### Implementation Steps

**Step 1:** Check block storage implementation

**Prompt:**
```
In src/ouroboros/validation.py, check the apply_block() method at line 75-104.

Verify that blocks are being stored after validation. The comment says:
```python
# Note: store_block is not implemented in Python wrapper yet
# self.db.store_block(block)
```

Check:
1. Are blocks stored via the Rust API during sync?
2. Do we need to explicitly store blocks in apply_block()?
3. Is block storage handled elsewhere (e.g., in block_sync.py)?

If blocks are not being stored, we need to either:
- Implement store_block() in the Python wrapper
- Use the Rust API directly
- Or verify that blocks are stored during sync and don't need explicit storage here
```

**Step 2:** Verify block retrieval works

**Prompt:**
```
Test that blocks can be retrieved after being stored:

1. Store a test block
2. Retrieve it by hash
3. Verify all fields are correct
4. Test edge cases (genesis block, etc.)

Create test: src/ouroboros/tests/test_block_storage.py
```

---

## Testing Checklist

After completing each task, run these tests:

### Task 1 (UTXO Restoration)
```bash
# Test reorg handling
python3 -m pytest src/ouroboros/tests/test_reorg_utxo_restoration.py -v
```

### Task 2 (Median Time)
```bash
# Test median time calculation
python3 -m pytest src/ouroboros/tests/test_median_time.py -v
# Test RPC
curl -X POST http://localhost:8332/ -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

### Task 3 (RPC Methods)
```bash
# Test new RPC methods
python3 -m pytest src/ouroboros/tests/test_rpc_methods.py -v
# Test manually
curl -X POST http://localhost:8332/ -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getrawmempool","params":[false],"id":1}'
```

### Task 4 (SegWit)
```bash
# Test SegWit support
python3 -m pytest src/ouroboros/tests/test_segwit.py -v
```

### Task 5 (Script Disassembly)
```bash
# Test script disassembly
python3 -m pytest src/ouroboros/tests/test_script_disassembly.py -v
```

### Task 6 (Block Storage)
```bash
# Test block storage
python3 -m pytest src/ouroboros/tests/test_block_storage.py -v
```

---

## Summary

**Total Estimated Time:** 10-15 hours

**Priority Order:**
1. Task 1: UTXO Restoration (Critical) - 1-2 hours
2. Task 2: Median Time (Important) - 30 minutes
3. Task 3: RPC Methods (Compatibility) - 4-6 hours
4. Task 4: SegWit Support (Accuracy) - 2-3 hours
5. Task 6: Block Storage (Data Integrity) - 30 minutes
6. Task 5: Script Disassembly (Nice to Have) - 2-3 hours

**After completing these tasks, the node will be production-ready!**
