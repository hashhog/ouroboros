# Rust Implementation Testing Plan
## Bitcoin Hybrid Node - Pre-Python Validation

---

## Overview

This document outlines comprehensive testing procedures to validate the Rust implementation before proceeding with Python integration. The goal is to ensure all Rust components work correctly, conform to Bitcoin standards, and are ready for Python bindings.

---

## Testing Strategy

### Phase 1: Unit Tests (Week 1)
- Test individual components in isolation
- Verify Bitcoin standard compliance
- Use Bitcoin Core test vectors

### Phase 2: Integration Tests (Week 2)
- Test component interactions
- Validate end-to-end workflows
- Test error handling and edge cases

### Phase 3: Bitcoin Core Compatibility (Week 3)
- Compare outputs with Bitcoin Core
- Validate against Bitcoin testnet/mainnet data
- Performance benchmarking

### Phase 4: Python Binding Tests (Week 4)
- Test PyO3 bindings
- Verify data serialization
- Test async runtime integration

---

## Module 1: Core Types Testing

### File: `tests/unit/test_types.rs`

**Test Cases:**

1. **BlockHeader Tests**
   ```rust
   #[test]
   fn test_block_header_serialization() {
       // Test with genesis block header
       // Verify serialization matches Bitcoin Core
   }

   #[test]
   fn test_block_header_hash() {
       // Test block hash calculation
       // Compare with known Bitcoin block hashes
   }

   #[test]
   fn test_block_header_deserialization() {
       // Test deserialization from raw bytes
       // Use real Bitcoin block headers
   }
   ```

2. **Transaction Tests**
   ```rust
   #[test]
   fn test_transaction_serialization() {
       // Test transaction serialization
       // Compare with Bitcoin Core format
   }

   #[test]
   fn test_transaction_txid() {
       // Test TXID calculation
       // Verify against known transaction IDs
   }

   #[test]
   fn test_coinbase_transaction() {
       // Test coinbase transaction structure
       // Verify height encoding
   }
   ```

3. **UTXO Tests**
   ```rust
   #[test]
   fn test_utxo_creation() {
       // Test UTXO struct creation
   }

   #[test]
   fn test_utxo_serialization() {
       // Test UTXO serialization/deserialization
   }
   ```

**Test Vectors:**
- Genesis block header (mainnet)
- First 10 block headers (mainnet)
- Sample transactions from block 1, 100, 1000
- Coinbase transactions from various blocks

---

## Module 2: Cryptographic Operations Testing

### File: `tests/unit/test_crypto.rs`

**Test Cases:**

1. **Hash Functions**
   ```rust
   #[test]
   fn test_double_sha256() {
       // Test with known inputs/outputs
       // Use Bitcoin Core test vectors
   }

   #[test]
   fn test_hash160() {
       // Test RIPEMD160(SHA256(data))
       // Compare with Bitcoin Core
   }
   ```

2. **Merkle Root**
   ```rust
   #[test]
   fn test_merkle_root_single_tx() {
       // Merkle root of block with 1 transaction
   }

   #[test]
   fn test_merkle_root_multiple_tx() {
       // Merkle root of block with multiple transactions
       // Compare with actual Bitcoin blocks
   }

   #[test]
   fn test_merkle_root_odd_tx() {
       // Test duplicate last element for odd count
   }
   ```

3. **Target/Difficulty**
   ```rust
   #[test]
   fn test_bits_to_target() {
       // Test compact representation conversion
       // Use difficulty adjustments from Bitcoin history
   }

   #[test]
   fn test_target_to_bits() {
       // Test reverse conversion
   }

   #[test]
   fn test_difficulty_adjustment() {
       // Test 2016-block difficulty adjustment
       // Use historical difficulty changes
   }
   ```

4. **Signature Verification**
   ```rust
   #[test]
   fn test_ecdsa_signature_verification() {
       // Test with known valid signatures
       // Test with invalid signatures
   }
   ```

**Test Vectors:**
- Bitcoin Core test vectors for hashing
- Real block merkle roots (blocks 1, 100, 1000, 10000)
- Historical difficulty adjustments
- Sample transaction signatures

---

## Module 3: Storage Layer Testing

### File: `tests/integration/test_storage.rs`

**Test Cases:**

1. **Database Operations**
   ```rust
   #[test]
   fn test_block_storage() {
       // Store and retrieve blocks
       // Test with various block sizes
   }

   #[test]
   fn test_utxo_operations() {
       // Add, query, and spend UTXOs
       // Test batch operations
   }

   #[test]
   fn test_chain_state() {
       // Test best block tracking
       // Test metadata storage
   }
   ```

2. **Batch Operations**
   ```rust
   #[test]
   fn test_batch_utxo_updates() {
       // Test atomic batch updates
       // Test rollback on error
   }
   ```

3. **Reorg Handling**
   ```rust
   #[test]
   fn test_block_reorg() {
       // Test disconnecting blocks
       // Test UTXO reversal
   }
   ```

**Test Data:**
- First 100 blocks (mainnet)
- Blocks with various transaction counts
- Large blocks (near size limit)

---

## Module 4: Validation Testing

### File: `tests/integration/test_validation.rs`

**Test Cases:**

1. **Proof of Work**
   ```rust
   #[test]
   fn test_pow_validation() {
       // Test with valid blocks
       // Test with invalid blocks (wrong nonce)
   }

   #[test]
   fn test_difficulty_adjustment_validation() {
       // Test difficulty adjustment at block 2016, 4032, etc.
       // Use historical blocks
   }
   ```

2. **Header Validation**
   ```rust
   #[test]
   fn test_header_chain_validation() {
       // Validate chain of 1000 headers
       // Test with invalid headers
   }

   #[test]
   fn test_median_time_past() {
       // Test median time calculation
       // Compare with Bitcoin Core
   }
   ```

3. **Script Validation**
   ```rust
   #[test]
   fn test_p2pkh_script() {
       // Test P2PKH script execution
       // Use Bitcoin Core script test vectors
   }

   #[test]
   fn test_p2sh_script() {
       // Test P2SH script execution
   }

   #[test]
   fn test_p2wpkh_script() {
       // Test SegWit P2WPKH
   }

   #[test]
   fn test_multisig_script() {
       // Test multisig scripts
   }

   #[test]
   fn test_all_opcodes() {
       // Test all Bitcoin opcodes
       // Use Bitcoin Core opcode test vectors
   }
   ```

4. **Transaction Validation**
   ```rust
   #[test]
   fn test_transaction_validation() {
       // Test valid transactions
       // Test invalid transactions (double spend, invalid sig, etc.)
   }

   #[test]
   fn test_coinbase_validation() {
       // Test coinbase transaction validation
       // Test subsidy calculation
   }
   ```

5. **Block Validation**
   ```rust
   #[test]
   fn test_block_validation() {
       // Test full block validation
       // Use real Bitcoin blocks
   }

   #[test]
   fn test_genesis_block() {
       // Validate genesis block
       // Compare with Bitcoin Core genesis
   }

   #[test]
   fn test_block_subsidy() {
       // Test block subsidy calculation
       // Test halving at block 210000, 420000, etc.
   }
   ```

**Test Vectors:**
- Bitcoin Core script test vectors
- Real Bitcoin blocks (genesis, early blocks, recent blocks)
- Blocks with various transaction types
- Invalid blocks for negative testing

---

## Module 5: Network Protocol Testing

### File: `tests/integration/test_network.rs`

**Test Cases:**

1. **Message Serialization**
   ```rust
   #[test]
   fn test_version_message() {
       // Test version message serialization
       // Compare with Bitcoin Core format
   }

   #[test]
   fn test_headers_message() {
       // Test headers message serialization
   }

   #[test]
   fn test_block_message() {
       // Test block message serialization
   }
   ```

2. **Message Validation**
   ```rust
   #[test]
   fn test_message_checksum() {
       // Test checksum calculation
       // Test checksum validation
   }

   #[test]
   fn test_magic_bytes() {
       // Test network magic bytes
   }
   ```

3. **Peer Communication** (Mock)
   ```rust
   #[test]
   fn test_peer_handshake() {
       // Mock peer handshake
       // Test version/verack exchange
   }
   ```

**Test Data:**
- Real Bitcoin P2P message captures
- Wireshark pcap files (if available)
- Bitcoin Core message format examples

---

## Module 6: Sync Testing

### File: `tests/integration/test_sync.rs`

**Test Cases:**

1. **Header Sync**
   ```rust
   #[tokio::test]
   async fn test_header_sync() {
       // Mock peer manager
       // Test header synchronization
       // Verify header chain validation
   }
   ```

2. **Block Sync**
   ```rust
   #[tokio::test]
   async fn test_block_sync() {
       // Mock peer manager
       // Test parallel block download
       // Test block validation pipeline
   }
   ```

3. **Sync Orchestration**
   ```rust
   #[tokio::test]
   async fn test_full_sync() {
       // Test complete sync process
       // Use testnet data
   }
   ```

---

## Module 7: Bitcoin Core Compatibility Tests

### File: `tests/compatibility/test_bitcoin_core.rs`

**Test Cases:**

1. **Block Compatibility**
   ```rust
   #[test]
   fn test_genesis_block_compatibility() {
       // Load Bitcoin Core genesis block
       // Verify our implementation matches
   }

   #[test]
   fn test_block_serialization_compatibility() {
       // Serialize blocks
       // Compare with Bitcoin Core serialization
   }
   ```

2. **Transaction Compatibility**
   ```rust
   #[test]
   fn test_transaction_serialization_compatibility() {
       // Compare transaction serialization
   }
   ```

3. **UTXO Set Compatibility**
   ```rust
   #[test]
   fn test_utxo_set_compatibility() {
       // Compare UTXO set after processing blocks
       // Use Bitcoin Core's UTXO set as reference
   }
   ```

**Test Data:**
- Bitcoin Core blockchain data (testnet)
- Bitcoin Core UTXO set dumps
- Bitcoin Core serialized blocks

---

## Module 8: Performance Benchmarks

### File: `benches/performance.rs`

**Benchmarks:**

1. **Hash Operations**
   ```rust
   #[bench]
   fn bench_double_sha256(b: &mut Bencher) {
       // Benchmark hash operations
   }
   ```

2. **Block Validation**
   ```rust
   #[bench]
   fn bench_block_validation(b: &mut Bencher) {
       // Benchmark block validation speed
   }
   ```

3. **Database Operations**
   ```rust
   #[bench]
   fn bench_utxo_lookup(b: &mut Bencher) {
       // Benchmark UTXO lookups
   }

   #[bench]
   fn bench_block_storage(b: &mut Bencher) {
       // Benchmark block storage
   }
   ```

4. **Script Execution**
   ```rust
   #[bench]
   fn bench_script_execution(b: &mut Bencher) {
       // Benchmark script interpreter
   }
   ```

**Targets:**
- Block validation: > 100 blocks/sec
- UTXO lookup: < 1ms per lookup
- Script execution: < 10ms per script
- Block storage: > 50 blocks/sec

---

## Module 9: Test Data Setup

### Directory: `tests/data/`

**Required Test Data:**

1. **Blocks**
   - `genesis_block.hex` - Genesis block (mainnet)
   - `block_1.hex` - First block after genesis
   - `block_100.hex` - Block 100
   - `block_1000.hex` - Block 1000
   - `block_210000.hex` - First halving block
   - `large_block.hex` - Large block (near size limit)

2. **Transactions**
   - `coinbase_tx.hex` - Sample coinbase transaction
   - `p2pkh_tx.hex` - P2PKH transaction
   - `p2sh_tx.hex` - P2SH transaction
   - `segwit_tx.hex` - SegWit transaction
   - `multisig_tx.hex` - Multisig transaction

3. **Headers**
   - `headers_1_to_100.bin` - First 100 headers
   - `headers_2016.bin` - Difficulty adjustment headers

4. **Script Test Vectors**
   - `script_tests.json` - Bitcoin Core script test vectors

**Script to Download Test Data:**
```bash
#!/bin/bash
# scripts/download_test_data.sh

# Download Bitcoin Core test vectors
curl -o tests/data/script_tests.json https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/script_tests.json

# Download sample blocks (using Bitcoin Core RPC or block explorers)
# This would require Bitcoin Core running or API access
```

---

## Module 10: Test Execution

### Running Tests

**Unit Tests:**
```bash
# Run all unit tests
cargo test --lib

# Run specific module tests
cargo test --lib validate::script::tests

# Run with output
cargo test --lib -- --nocapture
```

**Integration Tests:**
```bash
# Run integration tests
cargo test --test test_validation

# Run with test data
TEST_DATA_DIR=tests/data cargo test --test test_validation
```

**Benchmarks:**
```bash
# Run benchmarks
cargo bench
```

**Coverage:**
```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

---

## Module 11: Validation Checklist

### Before Proceeding to Python

**Core Types:**
- [ ] All types serialize/deserialize correctly
- [ ] Hash calculations match Bitcoin Core
- [ ] Test vectors pass

**Cryptography:**
- [ ] All hash functions produce correct outputs
- [ ] Merkle root calculation matches Bitcoin Core
- [ ] Difficulty adjustment calculations correct
- [ ] Signature verification works

**Storage:**
- [ ] Blocks store and retrieve correctly
- [ ] UTXO operations are atomic
- [ ] Batch operations work
- [ ] Reorg handling works

**Validation:**
- [ ] PoW validation correct
- [ ] Header validation chain works
- [ ] All script types execute correctly
- [ ] Transaction validation works
- [ ] Block validation works
- [ ] Genesis block validates correctly

**Network:**
- [ ] Messages serialize correctly
- [ ] Checksums validate
- [ ] Magic bytes correct

**Sync:**
- [ ] Header sync works (with mocks)
- [ ] Block sync works (with mocks)
- [ ] Progress tracking works

**Performance:**
- [ ] Meets performance targets
- [ ] No memory leaks
- [ ] Efficient database usage

**Bitcoin Core Compatibility:**
- [ ] Block serialization matches
- [ ] Transaction serialization matches
- [ ] UTXO set matches (after same blocks)

---

## Module 12: Test Utilities

### File: `tests/utils/mod.rs`

**Helper Functions:**

```rust
pub mod test_utils {
    use bitcoin::Block;
    use std::fs;

    /// Load block from hex file
    pub fn load_block_from_hex(path: &str) -> Block {
        let hex = fs::read_to_string(path).unwrap();
        let bytes = hex::decode(hex.trim()).unwrap();
        // Deserialize block
    }

    /// Create test database
    pub fn create_test_db() -> BlockchainDB {
        // Create temporary database
    }

    /// Load test transaction
    pub fn load_test_tx(name: &str) -> Transaction {
        // Load from test data
    }

    /// Compare with Bitcoin Core output
    pub fn assert_bitcoin_core_compatible<T: PartialEq + Debug>(
        ours: T,
        expected: T,
        field: &str
    ) {
        assert_eq!(ours, expected, "{} mismatch with Bitcoin Core", field);
    }
}
```

---

## Module 13: Continuous Integration

### File: `.github/workflows/test.yml`

```yaml
name: Rust Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests
        run: cargo test --all
      - name: Run benchmarks
        run: cargo bench --no-run
      - name: Check formatting
        run: cargo fmt -- --check
      - name: Clippy
        run: cargo clippy -- -D warnings
```

---

## Module 14: Test Report Template

### File: `TEST_REPORT.md`

```markdown
# Test Report - Rust Implementation

## Date: [DATE]

## Summary
- Total Tests: [N]
- Passed: [N]
- Failed: [N]
- Coverage: [X]%

## Module Results

### Core Types
- [ ] All tests pass
- Issues: [LIST]

### Cryptography
- [ ] All tests pass
- Issues: [LIST]

### Storage
- [ ] All tests pass
- Issues: [LIST]

### Validation
- [ ] All tests pass
- Issues: [LIST]

### Network
- [ ] All tests pass
- Issues: [LIST]

### Sync
- [ ] All tests pass
- Issues: [LIST]

## Bitcoin Core Compatibility
- [ ] Blocks match
- [ ] Transactions match
- [ ] UTXO set matches

## Performance
- Block validation: [X] blocks/sec
- UTXO lookup: [X] ms
- Script execution: [X] ms

## Recommendations
- [LIST ISSUES TO FIX]

## Sign-off
- [ ] Ready for Python integration
```

---

## Module 15: Known Issues Tracking

### File: `KNOWN_ISSUES.md`

Track any issues found during testing:

```markdown
# Known Issues

## Critical
- [ ] [ISSUE DESCRIPTION]

## High Priority
- [ ] [ISSUE DESCRIPTION]

## Medium Priority
- [ ] [ISSUE DESCRIPTION]

## Low Priority
- [ ] [ISSUE DESCRIPTION]
```

---

## Next Steps After Testing

1. **Fix All Critical Issues** - Must be resolved before Python work
2. **Document Test Results** - Create test report
3. **Performance Optimization** - If benchmarks are below targets
4. **Code Review** - Review test coverage
5. **Python Integration** - Proceed only after all tests pass

---

## Resources

- **Bitcoin Core Test Vectors**: https://github.com/bitcoin/bitcoin/tree/master/src/test/data
- **Bitcoin Script Tests**: https://github.com/bitcoin/bitcoin/blob/master/src/test/data/script_tests.json
- **Bitcoin Improvement Proposals**: https://github.com/bitcoin/bips
- **Bitcoin Testnet**: Use for live testing
- **Block Explorers**: For verifying block/transaction data

---

## Conclusion

This testing plan ensures the Rust implementation is:
- ✅ Functionally correct
- ✅ Bitcoin standard compliant
- ✅ Performance optimized
- ✅ Ready for Python integration

**Estimated Testing Time:** 3-4 weeks

**Success Criteria:** All tests pass, 90%+ code coverage, Bitcoin Core compatibility verified, performance targets met.

