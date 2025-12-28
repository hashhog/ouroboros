#!/usr/bin/env python3
"""Example demonstrating the usage of Rust extension module in Python.

This example shows how to:
- Import and use SyncEngine from the Rust extension
- Use PyUTXO to work with UTXO data
- Integrate Rust extension functionality with Python code
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from sync import SyncEngine, PyUTXO
    print("✓ Successfully imported Rust extension module")
except ImportError as e:
    print(f"✗ Failed to import Rust extension: {e}")
    print("\nMake sure the Rust extension is built:")
    print("  maturin develop --manifest-path ferrous-utils/sync/Cargo.toml")
    sys.exit(1)


def example_sync_engine():
    """Demonstrate SyncEngine usage."""
    print("\n" + "=" * 60)
    print("Example 1: Using SyncEngine")
    print("=" * 60)
    
    # Create a new sync engine
    engine = SyncEngine()
    print("✓ Created SyncEngine instance")
    
    # Example: Sync some blocks (as raw bytes)
    # In a real scenario, these would be actual Bitcoin block data
    example_blocks = [
        b"block_data_1" * 100,  # Simulated block 1
        b"block_data_2" * 100,  # Simulated block 2
        b"block_data_3" * 100,  # Simulated block 3
    ]
    
    # Convert to Vec<Vec<u8>> format (list of byte lists)
    blocks_data = [list(block) for block in example_blocks]
    
    # Sync blocks
    try:
        synced_count = engine.sync_blocks(blocks_data)
        print(f"✓ Synced {synced_count} blocks")
    except Exception as e:
        print(f"✗ Error syncing blocks: {e}")
    
    # Get UTXOs (currently returns empty list as it's not implemented)
    try:
        utxos = engine.get_utxos()
        print(f"✓ Retrieved {len(utxos)} UTXOs")
    except Exception as e:
        print(f"✗ Error getting UTXOs: {e}")


def example_pyutxo():
    """Demonstrate PyUTXO usage."""
    print("\n" + "=" * 60)
    print("Example 2: Working with PyUTXO")
    print("=" * 60)
    
    # Create a sync engine and get example UTXOs
    engine = SyncEngine()
    
    # Get example UTXOs (for demonstration)
    try:
        utxos = engine.get_example_utxos()
        print(f"✓ Retrieved {len(utxos)} example UTXOs")
    except Exception as e:
        print(f"✗ Error getting example UTXOs: {e}")
        return
    
    # Process UTXOs
    print(f"\nProcessing {len(utxos)} UTXOs...")
    
    total_value = 0
    for i, utxo in enumerate(utxos, 1):
        print(f"\nUTXO #{i}:")
        print(f"  TXID: {utxo.txid}")
        print(f"  Vout: {utxo.vout}")
        btc_value = utxo.value / 100_000_000
        print(f"  Value: {utxo.value:,} satoshis ({btc_value:.8f} BTC)")
        print(f"  Script PubKey (hex): {utxo.script_pubkey.hex()}")
        print(f"  Script PubKey Length: {len(utxo.script_pubkey)} bytes")
        total_value += utxo.value
    
    print(f"\n✓ Total value across all UTXOs: {total_value:,} satoshis ({total_value / 100_000_000:.8f} BTC)")


def example_integration():
    """Demonstrate integration with Python code."""
    print("\n" + "=" * 60)
    print("Example 3: Integration with Python Code")
    print("=" * 60)
    
    # Create sync engine
    engine = SyncEngine()
    
    # Example: Process blocks from a hypothetical source
    def process_blocks_with_rust(block_list):
        """Process blocks using the Rust extension."""
        # Convert Python bytes objects to the format expected by Rust
        blocks_data = [list(bytes(block)) for block in block_list]
        
        # Use Rust extension for fast processing
        synced = engine.sync_blocks(blocks_data)
        
        # Get results back from Rust (using example UTXOs for demo)
        utxos = engine.get_example_utxos()
        
        # Continue processing in Python
        total_value = sum(utxo.value for utxo in utxos)
        
        return {
            "blocks_synced": synced,
            "utxo_count": len(utxos),
            "total_value": total_value,
        }
    
    # Simulate processing some blocks
    test_blocks = [b"block1", b"block2", b"block3"]
    result = process_blocks_with_rust(test_blocks)
    
    print(f"✓ Processed blocks using Rust extension:")
    print(f"  Blocks synced: {result['blocks_synced']}")
    print(f"  UTXOs found: {result['utxo_count']}")
    print(f"  Total value: {result['total_value']} satoshis")


def example_utxo_attributes():
    """Demonstrate accessing PyUTXO attributes."""
    print("\n" + "=" * 60)
    print("Example 4: PyUTXO Attributes")
    print("=" * 60)
    
    # Create engine and get example UTXOs
    engine = SyncEngine()
    try:
        utxos = engine.get_example_utxos()
    except Exception as e:
        print(f"✗ Error getting example UTXOs: {e}")
        return
    
    if utxos:
        utxo = utxos[0]
        
        # All attributes are readable (defined with #[pyo3(get)])
        print("Accessing PyUTXO attributes:")
        print(f"  utxo.txid (str): {utxo.txid}")
        print(f"  utxo.vout (int): {utxo.vout}")
        print(f"  utxo.value (int): {utxo.value}")
        print(f"  utxo.script_pubkey (bytes): {utxo.script_pubkey}")
        
        # Convert script_pubkey bytes to hex for display
        print(f"  utxo.script_pubkey.hex(): {utxo.script_pubkey.hex()}")
        
        # Demonstrate that PyUTXO is a Python object
        print(f"\n✓ PyUTXO type: {type(utxo)}")
        print(f"✓ PyUTXO is iterable: {hasattr(utxo, '__iter__')}")
        
        # Show that we can work with multiple UTXOs
        print(f"\nWorking with {len(utxos)} UTXO objects:")
        for i, u in enumerate(utxos, 1):
            print(f"  UTXO {i}: {u.txid[:16]}... (vout={u.vout}, value={u.value:,} sats)")
    else:
        print("(No UTXOs available to demonstrate)")


def main():
    """Run all examples."""
    print("Rust Extension Usage Examples")
    print("=" * 60)
    print("This example demonstrates how to use the Rust extension module")
    print("from Python code.\n")
    
    try:
        example_sync_engine()
        example_pyutxo()
        example_integration()
        example_utxo_attributes()
        
        print("\n" + "=" * 60)
        print("✓ All examples completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

