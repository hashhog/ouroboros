# Examples

This directory contains example scripts demonstrating how to use Ouroboros.

## Rust Extension Example

`rust_extension_example.py` demonstrates how to use the Rust extension module from Python.

### Running the Example

1. Make sure the Rust extension is built:
   ```bash
   maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
   ```

2. Run the example:
   ```bash
   python examples/rust_extension_example.py
   ```

### What It Demonstrates

- Importing `SyncEngine` and `PyUTXO` from the Rust extension
- Creating and using a `SyncEngine` instance
- Syncing blocks with the Rust extension
- Accessing UTXO data through `PyUTXO` objects
- Integrating Rust extension functionality with Python code
- Accessing PyUTXO attributes (txid, vout, value, script_pubkey)

### Example Output

```
Rust Extension Usage Examples
============================================================
✓ Successfully imported Rust extension module

============================================================
Example 1: Using SyncEngine
============================================================
✓ Created SyncEngine instance
✓ Synced 3 blocks
✓ Retrieved 0 UTXOs

============================================================
Example 2: Working with PyUTXO
============================================================
Processing 0 UTXOs...
  (No UTXOs available - this is expected as the implementation is a stub)
...
```

