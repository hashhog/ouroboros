# Task 1: Rust API Improvements for UTXO Restoration

## Current Status

The Python implementation for UTXO restoration is complete, but it relies on `update_utxo_set()` which is not fully implemented in the Rust PyO3 bindings.

## Rust Database Methods Available

The Rust `BlockchainDB` has these UTXO methods:
- `add_utxo(&self, outpoint: &OutPoint, utxo: &UTXO) -> Result<()>` - Add/restore a UTXO
- `spend_utxo(&self, outpoint: &OutPoint, spending_txid: &[u8; 32]) -> Result<Option<UTXO>>` - Remove/spend a UTXO
- `get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UTXO>>` - Get a UTXO (already exposed)
- `utxo_exists(&self, outpoint: &OutPoint) -> bool` - Check if UTXO exists

## Recommended Improvements

### Option 1: Expose `add_utxo` and `spend_utxo` via PyO3

**File:** `ferrous-utils/sync/src/lib.rs`

Add these methods to `PyBlockchainDB`:

```rust
#[pymethods]
impl PyBlockchainDB {
    // ... existing methods ...
    
    /// Add/restore a UTXO to the database
    fn add_utxo(&self, txid: Vec<u8>, vout: u32, value: u64, script_pubkey: Vec<u8>) -> PyResult<()> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid);
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid_array),
            vout,
        };
        
        // Reconstruct UTXO from components
        let script = bitcoin::ScriptBuf::from_bytes(script_pubkey.into());
        let utxo = UTXO::new(outpoint, value, script);
        
        self.db.add_utxo(&outpoint, &utxo)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to add UTXO: {}", e)
            ))?;
        
        Ok(())
    }
    
    /// Remove/spend a UTXO from the database
    fn spend_utxo(&self, txid: Vec<u8>, vout: u32) -> PyResult<Option<PyUTXO>> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid);
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid_array),
            vout,
        };
        
        // Use a dummy spending txid (not critical for removal)
        let spending_txid = [0u8; 32];
        
        match self.db.spend_utxo(&outpoint, &spending_txid) {
            Ok(Some(utxo)) => Ok(Some(PyUTXO::from(utxo))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to spend UTXO: {}", e)
            )),
        }
    }
}
```

### Option 2: Complete `update_utxo_set` Implementation

**File:** `ferrous-utils/sync/src/lib.rs`

Complete the `update_utxo_set` method to properly handle UTXO creation:

```rust
fn update_utxo_set(
    &self,
    spent: Vec<(Vec<u8>, u32)>,
    created: Vec<PyUTXO>,
) -> PyResult<()> {
    // Convert spent outpoints
    let mut spent_outpoints = Vec::new();
    for (txid_bytes, vout) in spent {
        if txid_bytes.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        spent_outpoints.push(bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid),
            vout,
        });
    }
    
    // Convert created UTXOs
    let mut created_utxos = Vec::new();
    for py_utxo in created {
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(
            &hex::decode(&py_utxo.txid)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid txid hex: {}", e)
                ))?
        );
        
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid_array),
            vout: py_utxo.vout,
        };
        
        let script = bitcoin::ScriptBuf::from_bytes(py_utxo.script_pubkey.into());
        let utxo = UTXO::new(outpoint, py_utxo.value, script);
        created_utxos.push(utxo);
    }
    
    // Use batch operations if available, or individual operations
    for outpoint in &spent_outpoints {
        let _ = self.db.spend_utxo(outpoint, &[0u8; 32]);
    }
    
    for utxo in &created_utxos {
        let _ = self.db.add_utxo(&utxo.outpoint(), utxo);
    }
    
    Ok(())
}
```

## Benefits

1. **Direct API Access**: Python can directly call `add_utxo` and `spend_utxo` without workarounds
2. **Better Performance**: No need to go through `update_utxo_set` wrapper
3. **Clearer Code**: More explicit about what operations are being performed
4. **Better Error Handling**: Direct error propagation from Rust

## Implementation Priority

**Medium** - The current Python implementation works with warnings. These improvements would:
- Remove warning messages
- Improve performance
- Make the code cleaner
- Enable proper UTXO restoration

## Testing

After implementing, update `src/ouroboros/database.py` to use the new methods:

```python
def restore_utxo(self, txid: bytes, vout: int, value: int, script_pubkey: bytes) -> None:
    """Use direct Rust API if available"""
    try:
        self._db.add_utxo(txid, vout, value, list(script_pubkey))
    except AttributeError:
        # Fallback to update_utxo_set
        # ... existing code ...
```
