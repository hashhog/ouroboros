# Test Execution Guide
## Quick Start for Testing Rust Implementation

---

## Rebuild After Rust Changes

**Important:** After modifying any Rust code in `ferrous-utils/`, rebuild the Python extension or Python will use the old extension and fixes won't appear:

```bash
maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
```

Or, from project root with pip install:

```bash
pip install -e .
```

---

## Sync Verification Testing

For reliable sync testing:

- **Regtest:** Use `--network regtest` for fast local testing; no real peers needed if run with a local node.
- **Testnet with --reset:** When switching networks or debugging, use `sync --reset` to avoid stale chainstate and "Headers don't connect" errors.
- **Mainnet with --limit N:** Use `sync --limit 1000` to sync only the first N blocks for quick validation.
- **Testnet4:** Has fewer peers and may be flakier; prefer IPv4 with `OUROBOROS_PREFER_IPV4=1` if needed.

---

## Prerequisites

1. **Rust Toolchain**
   ```bash
   rustup update stable
   rustup component add clippy rustfmt
   ```

2. **Test Data**
   ```bash
   ./scripts/download_test_data.sh
   ```

3. **Coverage Tool** (Optional)
   ```bash
   cargo install cargo-tarpaulin
   ```

---

## Running Tests

### 1. Run All Tests
```bash
cd ferrous-utils
cargo test --workspace
```

### 2. Run Specific Module Tests
```bash
# Core types
cargo test --package common --lib

# Validation
cargo test --package sync --lib validate

# Storage
cargo test --package sync --lib storage

# Network
cargo test --package sync --lib network
```

### 3. Run Integration Tests
```bash
cargo test --test test_validation
```

### 4. Run with Output
```bash
cargo test --lib -- --nocapture
```

### 5. Run Single Test
```bash
cargo test test_genesis_block_validation
```

---

## Test Coverage

### Generate Coverage Report
```bash
cargo tarpaulin --workspace --out Html --output-dir coverage
```

Open `coverage/tarpaulin-report.html` in a browser.

**Target:** 90%+ code coverage

---

## Benchmarking

### Run Benchmarks
```bash
cargo bench
```

### Compare Performance
```bash
# Run multiple times and compare
cargo bench -- --sample-size 100
```

---

## Validation Checklist

### Quick Validation Script
```bash
#!/bin/bash
# scripts/validate_rust_impl.sh

echo "Running Rust implementation validation..."

# 1. Format check
echo "Checking code format..."
cargo fmt -- --check || exit 1

# 2. Clippy
echo "Running clippy..."
cargo clippy --workspace -- -D warnings || exit 1

# 3. Tests
echo "Running tests..."
cargo test --workspace || exit 1

# 4. Benchmarks (no-run)
echo "Checking benchmarks..."
cargo bench --no-run || exit 1

echo "✅ All checks passed!"
```

---

## Bitcoin Core Compatibility Testing

### 1. Compare Block Serialization
```bash
# Export block from Bitcoin Core
bitcoin-cli getblock <blockhash> 0 > block.hex

# Compare with our serialization
# (Create test that loads and compares)
```

### 2. Compare Transaction Serialization
```bash
# Export transaction from Bitcoin Core
bitcoin-cli getrawtransaction <txid> > tx.hex

# Compare with our serialization
```

### 3. Compare UTXO Set
```bash
# After processing same blocks, compare UTXO sets
# Use Bitcoin Core's gettxoutsetinfo
```

---

## Test Data Sources

### 1. Bitcoin Core Test Vectors
- Script tests: `tests/data/script_tests.json`
- Base58 tests: `tests/data/base58_keys_valid.json`

### 2. Real Blockchain Data
- **Testnet**: Use for live testing
- **Mainnet**: Use for compatibility testing (be careful with size)

### 3. Block Explorers
- Testnet: https://blockstream.info/testnet/
- Mainnet: https://blockstream.info/

---

## Common Test Issues

### Issue: Test Database Locked
**Solution:** Ensure tests clean up temporary directories
```rust
let temp_dir = TempDir::new("test").unwrap();
// ... use temp_dir ...
// Automatically cleaned up when dropped
```

### Issue: Async Test Timeouts
**Solution:** Increase timeout or use `tokio::test` with timeout
```rust
#[tokio::test]
async fn test_with_timeout() {
    tokio::time::timeout(Duration::from_secs(30), async {
        // test code
    }).await.unwrap();
}
```

### Issue: Missing Test Data
**Solution:** Download test data first
```bash
./scripts/download_test_data.sh
```

---

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Block Validation | > 100 blocks/sec | TBD |
| UTXO Lookup | < 1ms | TBD |
| Script Execution | < 10ms | TBD |
| Block Storage | > 50 blocks/sec | TBD |

---

## Next Steps

1. **Run All Tests** - Ensure everything passes
2. **Check Coverage** - Aim for 90%+
3. **Run Benchmarks** - Verify performance
4. **Bitcoin Core Comparison** - Verify compatibility
5. **Fix Issues** - Address any failures
6. **Document Results** - Create test report

---

## Test Report Template

After running tests, fill out `TEST_REPORT.md`:

```markdown
# Test Report

## Date: [DATE]

## Summary
- Total Tests: [N]
- Passed: [N]
- Failed: [N]
- Coverage: [X]%

## Module Results
[Fill in results for each module]

## Bitcoin Core Compatibility
[Document compatibility results]

## Performance
[Document benchmark results]

## Issues Found
[List any issues]

## Sign-off
- [ ] Ready for Python integration
```

---

## Getting Help

If tests fail:
1. Check error messages carefully
2. Verify test data is present
3. Check Bitcoin Core compatibility
4. Review test vectors
5. Check for known issues in `KNOWN_ISSUES.md`

