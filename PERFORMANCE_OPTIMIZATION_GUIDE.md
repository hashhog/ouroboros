# Ouroboros Performance Optimization Guide

Steps and Cursor prompts to make Ouroboros verify blocks faster, with full validation. This guide addresses the analysis in the prior performance discussion: incomplete Rust signature verification, sequential transaction validation, database tuning, and benchmarking.

**Prerequisites:** Working sync (header + block), PoW validation enabled, testnet4 or mainnet verified.

**References:**
- `GAPS_AND_FIXES_GUIDE.md` – Security/correctness fixes
- `REMAINING_TODOS_GUIDE.md` – Other TODOs
- Bitcoin Core: `bitcoin/src/script/interpreter.cpp`, `bitcoin/src/validation.cpp`, `bitcoin/src/script/sigcache.cpp`

---

## Part 1: Current State and Goals

| Aspect | Current | Target |
|--------|---------|--------|
| Signature verification | Placeholder (script_sig non-empty only) | Full ECDSA in Rust |
| Tx validation parallelism | Sequential per block | Parallel inputs (rayon) |
| Script execution | Python ScriptInterpreter | Rust (or keep Python for non-hot path) |
| RocksDB | Default opts | Tuned for sync workload |
| In-flight blocks | 128 (configurable) | Tuned based on benchmarks |

---

## Part 2: Implementation Phases

### Phase P.1: Full ECDSA Signature Verification in Rust (Critical)

The Rust `TransactionValidator` currently only checks `script_sig.is_empty()`. Full validation is required for correct sync and enables fair performance comparison.

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| P.1.1 | Add sighash computation and ECDSA verify in Rust | See Prompt P.1.1 |
| P.1.2 | Support P2PKH, P2WPKH, P2SH-P2WPKH | See Prompt P.1.2 |
| P.1.3 | Wire into BlockValidator and run tests | See Prompt P.1.3 |

### Phase P.2: Parallel Transaction Validation

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| P.2.1 | Add rayon, parallelize input validation | See Prompt P.2.1 |
| P.2.2 | Benchmark before/after | See Prompt P.2.2 |

### Phase P.3: RocksDB Tuning

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| P.3.1 | Add tunable RocksDB options | See Prompt P.3.1 |

### Phase P.4: Parallelism and Timeout Tuning

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| P.4.1 | Expose max_concurrent and receive timeout | See Prompt P.4.1 |

### Phase P.5: Benchmarking

| Step | Description | Cursor Prompt |
|------|-------------|---------------|
| P.5.1 | Add sync benchmark script | See Prompt P.5.1 |
| P.5.2 | Document how to compare with Bitcoin Core IBD | See Prompt P.5.2 |

---

## Part 3: Cursor Prompts

### Prompt P.1.1: Add Sighash and ECDSA Verify in Rust

```
In ferrous-utils/sync/src/validate/transaction.rs, replace the placeholder signature check with real ECDSA verification:

1. For each non-coinbase input:
   - Look up the UTXO (script_pubkey, amount) from db.get_utxo() (already done)
   - Compute the sighash for this input:
     - Use SIGHASH_ALL (0x01) unless the signature has a different flag
     - Formula: double_sha256(version || prevouts_hash || sequences_hash || outpoint || scriptCode || amount || sequence || outputs_hash || locktime || hash_type)
     - Ref: BIP143 (SegWit) and legacy sighash for non-SegWit
   - Parse script_sig: extract DER signature + pubkey (for P2PKH: <sig> <pubkey>)
   - Verify: secp256k1::Message::from_digest_slice(sighash) and secp256k1::ecdsa::Signature::from_der(sig)
   - Use bitcoin crate's sighash utilities if available, or common::crypto functions

2. The common crate already has verify_ecdsa_signature_der(der_sig, pubkey, msg_hash) - use it for the crypto part.

3. Handle SegWit vs legacy:
   - If tx has witness (SegWit): use BIP143 sighash (witness_v0_scripthash style)
   - If no witness: use legacy sighash
   - Ref: bitcoin/src/script/sign.cpp SignatureHash, bitcoin/src/script/interpreter.cpp

4. For now, support only P2PKH and P2WPKH (most common). P2SH-P2WPKH can follow.
   - P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
   - P2WPKH: scriptPubKey is OP_0 <20 bytes>; scriptSig empty; witness has <sig> <pubkey>

5. If any signature fails, return SignatureVerificationFailed with input index.

6. Remove the "script_sig.is_empty()" placeholder - replace with the full flow.

7. Add unit test: create a known-valid P2PKH tx, call validate_transaction_inputs, assert Ok.
   Ref: bitcoin/src/test/script_tests.cpp, or use a test vector from BIP143.
```

### Prompt P.1.2: Support P2PKH, P2WPKH, P2SH-P2WPKH

```
In ferrous-utils/sync/src/validate/transaction.rs (and any new module you split out):

1. P2PKH: scriptPubKey is 25 bytes starting 0x76 0xa9 0x14 ... 0x88 0xac
   - scriptSig = <sig> <pubkey>
   - Sighash: legacy (double_sha256 of serialized tx with scriptCode = scriptPubKey)

2. P2WPKH: scriptPubKey is 22 bytes OP_0 (0x00) 0x14 <20-byte hash>
   - scriptSig: empty
   - Witness: 2 items [signature, pubkey]
   - Sighash: BIP143 (witness version 0, 32-byte prevouts, sequences, etc.)

3. P2SH-P2WPKH: scriptPubKey is OP_HASH160 0x14 <20 bytes> OP_EQUAL
   - Redeem script in witness: OP_0 <20-byte push>
   - scriptSig: single push of redeem script (witness program)
   - Sighash: BIP143 with scriptCode = P2WPKH output script (OP_0 <20>)

4. Add a helper: fn script_type(script_pubkey: &[u8]) -> Option<ScriptType> { P2PKH | P2WPKH | P2SH }

5. For unsupported script types, return a clear error (e.g. UnsupportedScriptType) rather than failing silently.
   This allows adding P2SH, P2WSH later.

6. Ref: bitcoin/src/script/interpreter.cpp EvalScript, VerifyWitnessProgram
```

### Prompt P.1.3: Wire Full Validation and Tests

```
In ferrous-utils/sync:

1. Ensure BlockValidator.validate_block() calls tx_validator.validate_transaction() with check_inputs=true for non-coinbase txs (it already does).

2. Run full sync test: cargo test -p sync --test '*' (or integration test if you have one)
3. Run: ouroboros --network testnet4 --data-dir /tmp/ouroboros-perf-test sync --reset (or a small limit)
4. If any block fails validation, debug with a known-good block from Bitcoin Core (bitcoin-cli getblock <hash> 0) and compare sighash/script.

5. Add integration test in ferrous-utils/sync/tests/ or sync/tests:
   - Load a real block (e.g. testnet4 block 1000) from a fixture
   - Call BlockValidator.validate_block()
   - Assert it succeeds
   - Optionally: create an invalid tx (wrong sig), assert validation fails
```

---

### Prompt P.2.1: Add Rayon and Parallelize Input Validation

```
In ferrous-utils/sync:

1. Add rayon to Cargo.toml: rayon = "1.10"

2. In ferrous-utils/sync/src/validate/transaction.rs, function validate_transaction_inputs:
   - The current loop iterates over tx.input sequentially
   - Split work: prepare a Vec of (input_idx, outpoint, input) that need verification
   - Use rayon::par_iter() over these items to verify signatures in parallel
   - Each parallel task: get UTXO, compute sighash, verify ECDSA
   - Collect results: if any Err, return first error
   - Sum total_input in a final step (or use fold with Result)

3. Caveat: sighash for input i depends on all outputs (BIP143) - so the sighash computation can be parallelized per input, but each input's sighash is independent.
   - Sighash computation is pure given (tx, input_index, script_code, amount, prev_outs, prev_sequences)
   - So we can compute all sighashes in parallel, then verify all sigs in parallel

4. Alternative: parallelize at block level - validate multiple transactions in parallel. That may require more refactoring (e.g. BlockValidator takes a list of txs).
   - Simpler first step: parallelize within validate_transaction_inputs (inputs of one tx)

5. Re-run tests to ensure no regression.
```

### Prompt P.2.2: Benchmark Before/After Parallel Validation

```
Create a benchmark for block validation:

1. In ferrous-utils/sync, add a criterion benchmark (dev-dependency already has criterion):
   - benches/block_validation.rs or add to existing bench
   - Load a real block (e.g. 2000 txs) from a test fixture or generate
   - Time BlockValidator.validate_block() 100 times
   - Report: mean, std dev (before rayon, after rayon)

2. Or add a simple timing in the sync loop:
   - In block_sync.rs, around where validate_block is called, add:
     let start = Instant::now();
     self.validator.validate_block(...)?;
     log::debug!("validate_block took {:?}", start.elapsed());
   - Run sync with OUROBOROS_VERBOSE=1 and grep for validate_block timing
   - Compare with/without rayon
```

---

### Prompt P.3.1: Add Tunable RocksDB Options

```
In ferrous-utils/sync/src/storage/db.rs:

1. Read from environment or config:
   - OUROBOROS_ROCKSDB_WRITE_BUFFER_MB (default 64)
   - OUROBOROS_ROCKSDB_MAX_WRITE_BUFFER_NUMBER (default 4)
   - OUROBOROS_ROCKSDB_PARALLELISM (default: num_cpus)

2. Apply to Options:
   - opts.set_write_buffer_size(write_buffer_mb * 1024 * 1024)
   - opts.set_max_write_buffer_number(max_num)
   - opts.increase_parallelism(parallelism)
   - Consider: opts.set_optimize_filters_for_hits(true) if reads >> writes after sync

3. Document in INSTALLATION.md or a new PERFORMANCE.md section:
   - "For faster IBD, try OUROBOROS_ROCKSDB_WRITE_BUFFER_MB=128"
   - "For low-memory systems, reduce OUROBOROS_ROCKSDB_WRITE_BUFFER_MB to 32"

4. Ref: RocksDB tuning guide, Bitcoin Core LevelDB options (different DB but similar concepts)
```

---

### Prompt P.4.1: Expose max_concurrent and Receive Timeout

```
Make block sync parallelism and timeouts configurable from Python/CLI:

1. Rust: FastSync or SyncEngine should accept (or read from env):
   - max_concurrent_blocks: u32 (default 128)
   - block_receive_timeout_secs: u64 (default 120)
   - These are already in block_sync.rs (DEFAULT_MAX_IN_FLIGHT, receive_timeout_secs)

2. Expose via FastSync.__init__ or a config method:
   - In lib.rs, FastSync::new() or similar - add optional params
   - Pass through to BlockSync::set_max_concurrent and set_receive_timeout_secs

3. Python: In sync_manager.py or ouroboros.conf:
   - Add config keys: max_concurrent_blocks, block_receive_timeout_secs
   - Pass to sync.FastSync when creating

4. CLI: ouroboros sync --max-concurrent 256 (optional)
   - Or via config file

5. Document recommended values:
   - "256 in-flight can speed up on fast networks; 60s timeout may help on slow connections"
```

---

### Prompt P.5.1: Add Sync Benchmark Script

```
Create scripts/bench_sync.sh (or docs/benchmarking.md):

1. Reset data dir: rm -rf ~/.ouroboros-bench && mkdir -p ~/.ouroboros-bench
2. Run: time ouroboros --network testnet4 --data-dir ~/.ouroboros-bench sync --reset
   - Or use --limit 10000 to sync only 10k blocks
3. Record: real time, blocks synced, blocks/sec
4. Optionally: run with /usr/bin/time -v to get max RSS (memory)
5. Repeat with different OUROBOROS_* env vars (e.g. ROCKSDB_WRITE_BUFFER_MB, max_concurrent)
6. Output a simple table: config | blocks | time | blocks/sec | RSS
```

### Prompt P.5.2: Document How to Compare with Bitcoin Core IBD

```
Add a section to PERFORMANCE_OPTIMIZATION_GUIDE.md (or docs/benchmarking.md):

1. Prerequisites:
   - Same machine, same network (testnet4 or mainnet)
   - Bitcoin Core in ./bitcoin, Ouroboros built

2. Ouroboros:
   - rm -rf ~/.ouroboros-bench
   - time ouroboros --network testnet4 --data-dir ~/.ouroboros-bench sync --reset
   - Record blocks/sec

3. Bitcoin Core:
   - rm -rf ~/.bitcoin-bench/blocks ~/.bitcoin-bench/chainstate  (or testnet4 equivalent)
   - bitcoind -testnet4 -datadir=~/.bitcoin-bench
   - Wait for IBD; check debug.log for "Block downloaded" or use getblockcount
   - time from start to tip
   - Or use -reindex to revalidate existing blocks (measures validation speed more than download)

4. Caveats:
   - Download speed dominates; use same network
   - Testnet4 has different block distribution than mainnet
   - Bitcoin Core may throttle; Ouroboros may not - compare apples to apples
```

---

## Part 4: Suggested Order

| Order | Phase | Notes |
|-------|-------|-------|
| 1 | P.1 | Must-do for correctness; enables honest speed comparison |
| 2 | P.2 | Clear win; low risk |
| 3 | P.5.1, P.5.2 | Establish baseline before further tuning |
| 4 | P.3 | Tune if I/O bound |
| 5 | P.4 | Optional; only if network is bottleneck |

---

## Part 5: Quick Reference

| File | Purpose |
|------|---------|
| `ferrous-utils/sync/src/validate/transaction.rs` | ECDSA verification, parallel validation |
| `ferrous-utils/sync/src/validate/block.rs` | BlockValidator, calls tx validator |
| `ferrous-utils/sync/src/storage/db.rs` | RocksDB options |
| `ferrous-utils/sync/src/network/block_sync.rs` | max_concurrent, receive_timeout |
| `ferrous-utils/common/src/crypto.rs` | verify_ecdsa_signature_der |
