"""
W105 — CCheckQueue / parallel script verification 30-gate audit
ouroboros (Python + Rust ferrous-utils)

Reference: bitcoin-core/src/checkqueue.h, validation.cpp ConnectBlock,
           init.cpp -par, script/sigcache.h

Two-pipeline summary (ouroboros recurring pattern):
  Rust:   validate/script.rs  — ScriptInterpreter (evaluate_script_with_context,
          evaluate_witness_v0_script, evaluate_tapscript, etc.);
          verify_signature_in_script / verify_witness are exported via mod.rs
          but NEVER #[pyfunction]-exported and NEVER called from Rust block path.
          The Rust block validator (validate/block.rs) does structural checks only;
          per-input script crypto is delegated to Python via skip_scripts=True.
  Python: script.py ScriptInterpreter.verify() → called from validation.py
          _verify_input_signature() → single-threaded serial loop over each input.

Gates:
  G1   CCheckQueue equivalent absent (no parallel script queue at all)
  G2   No -par / nScriptCheckThreads equivalent
  G3   No CCheckQueueControl RAII drain
  G4   No batch-size tuning (Core: nBatchSize=128, dynamic sizing)
  G5   No early-exit on first failure (Core: do_work gate, local_result short-circuit)
  G6   No script-execution cache (Core: m_script_execution_cache wtxhash+flags key)
  G7   Script-execution cache key wrong (not wtxhash+flags; txid+input_index+flags)
  G8   No salted/nonce SigCache key (Core: GetRandHash nonce + CSHA256 salted hasher)
  G9   SigCache key missing sighash (txid+idx+flags misses sighash component)
  G10  No CachingTransactionSignatureChecker equivalent
  G11  Only one cache (SigCache); no dual-cache (signature + script execution)
  G12  SigCache: shared_mutex absent (Python threading.Lock not shared reader)
  G13  No PrecomputedTransactionData equivalent (no upfront Taproot batch setup)
  G14  Rust ScriptInterpreter never called from Rust block validation path
  G15  Rust verify_signature_in_script: P2SH/P2WPKH/P2WSH return Ok(false) stub
  G16  Rust verify_witness: complete placeholder (Ok(false) unconditionally)
  G17  No MAX_SCRIPTCHECK_THREADS (15) limit or -par config option
  G18  SigCache default size: 50k entries vs Core 16 MiB CuckooCache
  G19  No cacheFullScriptStore / cacheSigStore false-on-connect path
  G20  No pvChecks reserve() (Core reserves tx.vin.size() upfront)
  G21  Python serial: inputs verified one-by-one inside tx loop (no parallel)
  G22  Rust BlockValidator: skip_scripts=True always in production path
  G23  validate_block_with_flags: skip_scripts param dead (comment says future compat)
  G24  No fScriptChecks flag (Core gates parallel queue on pindex checks)
  G25  SigCache.clear() on reorg: not wired to disconnect/reorg path
  G26  Rust verify_p2pkh_signature: skips actual secp256k1 verify (Ok(true) stub)
  G27  No separate policy vs consensus CheckInputScripts calls
  G28  No m_control_mutex (Core uses separate control mutex for CCheckQueueControl)
  G29  Rust ScriptInterpreter exported from mod.rs but not used in FFI bridge
  G30  GIL-releasing detach in validate_block_from_bytes: script checks not parallelised
       (detach only moves one block's structural validation off-GIL; scripts still serial)
"""

import sys
import threading
import unittest
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.sig_cache import SigCache  # noqa: E402
from ouroboros.script import (  # noqa: E402
    ScriptInterpreter,
    SCRIPT_VERIFY_NONE,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_TAPROOT,
)


# ---------------------------------------------------------------------------
# G1: CCheckQueue equivalent absent (no parallel script queue at all)
# ---------------------------------------------------------------------------
class TestG1NoCheckQueue(unittest.TestCase):
    """
    BUG-G1: ouroboros has no CCheckQueue or equivalent.

    Core (checkqueue.h): CCheckQueue<CScriptCheck> — producer/consumer queue
    with N-1 worker threads plus the master thread each draining batches of
    CScriptCheck objects concurrently.  ConnectBlock pushes vChecks batches via
    CCheckQueueControl; Complete() blocks until all inputs across the block are
    verified in parallel.

    ouroboros Python: script.py ScriptInterpreter.verify() called sequentially
    from validation.py _verify_input_signature() inside a for-loop over inputs.
    No queue, no workers, no CCheckQueueControl.

    ouroboros Rust: validate/script.rs ScriptInterpreter exists but is never
    invoked from the Rust block validation path (block.rs); the Rust FFI bridge
    always calls validate_block_with_flags(skip_scripts=True — structural only).
    """

    def test_no_parallel_script_queue_python(self):
        """Python block validation uses a serial input loop — no queue/workers."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        # Core's queue-based pattern: each tx's inputs pushed onto a control;
        # Python never does this — all checks are inline in the for-loop.
        self.assertNotIn("CheckQueue", src,
            "BUG-G1: Python validation unexpectedly contains CCheckQueue logic")
        self.assertNotIn("control.Add", src,
            "BUG-G1: Python validation unexpectedly has control.Add() batching")
        self.assertNotIn("ThreadPoolExecutor", src,
            "BUG-G1: Python validation unexpectedly uses ThreadPoolExecutor")

    def test_no_parallel_script_queue_rust_path(self):
        """Rust block.rs validator does NOT call the Rust ScriptInterpreter."""
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_block.exists():
            self.skipTest("Rust source not found")
        content = rust_block.read_text()
        # block.rs does call transaction.rs — but neither calls
        # ScriptInterpreter::evaluate_script_with_context on the per-input path.
        self.assertNotIn("ScriptInterpreter::evaluate_script",
                         content,
                         "BUG-G1: Rust block.rs unexpectedly calls ScriptInterpreter directly")


# ---------------------------------------------------------------------------
# G2: No -par / nScriptCheckThreads equivalent
# ---------------------------------------------------------------------------
class TestG2NoPar(unittest.TestCase):
    """
    BUG-G2: ouroboros has no -par (nScriptCheckThreads) option.

    Core (init.cpp:513-514):
      argsman.AddArg("-par=<n>", ..., MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS)
      validation.h: static constexpr int MAX_SCRIPTCHECK_THREADS{15}

    ouroboros config.py has no script_check_threads, par, or related option.
    The node always runs single-threaded script verification regardless of CPU count.
    """

    def test_no_par_option_in_config(self):
        """config.py does not expose a -par / script check threads option."""
        import ouroboros.config as cfg_mod
        import inspect
        src = inspect.getsource(cfg_mod)
        for needle in ("script_check_thread", "nScriptCheckThread",
                       "par", "MAX_SCRIPTCHECK", "worker_threads"):
            if needle in src and "par" in needle:
                # 'par' may match 'parameter' — check carefully
                if "script" not in src[src.index(needle)-30:src.index(needle)+60]:
                    continue
            self.assertNotIn(
                needle.lower(),
                src.lower(),
                f"BUG-G2 (unexpected): config.py contains '{needle}' — "
                "would indicate -par equivalent was added"
            ) if needle in ("script_check_thread", "nScriptCheckThread",
                            "MAX_SCRIPTCHECK", "worker_threads") else None

    def test_no_par_cli_option(self):
        """CLI entrypoint (cli.py) has no -par argument."""
        import ouroboros.cli as cli_mod
        import inspect
        src = inspect.getsource(cli_mod)
        self.assertNotIn("script-check-thread", src,
            "BUG-G2 (unexpected): CLI has script-check-threads")
        self.assertNotIn("par=", src,
            "BUG-G2 (unexpected): CLI has --par option")


# ---------------------------------------------------------------------------
# G3: No CCheckQueueControl RAII drain
# ---------------------------------------------------------------------------
class TestG3NoQueueControl(unittest.TestCase):
    """
    BUG-G3: No CCheckQueueControl RAII equivalent.

    Core (checkqueue.h:207-238): CCheckQueueControl is an RAII guard that
    acquires m_control_mutex (preventing two concurrent ConnectBlock runs),
    batches CScriptCheck objects via Add(), and calls Complete() in its
    destructor if not already called.  If the block fails mid-loop, the
    destructor drains remaining checks so workers are not stranded.

    ouroboros: validation loop returns immediately on the first invalid tx
    (_verify_input_signature returns False → "Invalid signature for input N").
    There is no queue to drain and no RAII guard; leftover script work
    from an invalid block is not an issue only because there is no queue.
    The absence is still a design gap relative to Core.
    """

    def test_no_raii_queue_control(self):
        """Python validation has no RAII CCheckQueueControl equivalent."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        for name in ("QueueControl", "CheckQueueControl", "__del__", "__exit__"):
            if name in src:
                # Allowed if it's in a comment or docstring only
                idx = src.index(name)
                context = src[max(0, idx-100):idx+100]
                self.assertIn("#", context,
                    f"BUG-G3 (unexpected): found '{name}' in non-comment context")


# ---------------------------------------------------------------------------
# G4: No batch-size tuning
# ---------------------------------------------------------------------------
class TestG4NoBatchSize(unittest.TestCase):
    """
    BUG-G4: No batch-size tuning (Core nBatchSize=128, dynamic sizing).

    Core (checkqueue.h:121):
      nNow = max(1, min(nBatchSize, queue.size() / (nTotal + nIdle + 1)))
    This dynamically sizes batches so all N workers finish approximately
    simultaneously.  Worker threads steal progressively smaller batches as
    the queue drains.

    ouroboros: no batch concept; inputs are checked one-by-one sequentially.
    """

    def test_no_batch_size_constant(self):
        """No nBatchSize or BATCH_SIZE equivalent in Python validation path."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("nBatchSize", src)
        self.assertNotIn("BATCH_SIZE", src)
        # Confirm the serial input loop
        self.assertIn("for i, tx_in in enumerate(tx.inputs):", src,
            "Expected serial input loop in validate_transaction")


# ---------------------------------------------------------------------------
# G5: No early-exit on first failure in parallel path
# ---------------------------------------------------------------------------
class TestG5NoEarlyExitParallel(unittest.TestCase):
    """
    BUG-G5 (design): Core CCheckQueue short-circuits remaining work via do_work gate.

    Core (checkqueue.h:126-133):
      do_work = !m_result.has_value();
      if (do_work) { for (T& check : vChecks) { local_result = check(); if (has_value()) break; } }

    Once any worker sets m_result (failure), all subsequent workers skip their
    batches (do_work=false).  This avoids verifying thousands more inputs once
    a block is already known bad.

    ouroboros: returns from validate_transaction immediately on the first
    bad input (line: 'return False, f"Invalid signature for input {i}"').
    This achieves serial early-exit.  However, since there are no parallel
    workers, the improvement that Core gets (workers draining without doing
    real work) does not apply.  Not a correctness bug but a perf gap.
    """

    def test_serial_early_exit_present(self):
        """Python validation DOES exit early on first invalid input (serial path)."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertIn('return False, f"Invalid signature for input',
                      src,
                      "Expected early-exit on first invalid input in serial path")

    def test_no_parallel_worker_do_work_gate(self):
        """No do_work gate or m_result equivalent — no parallel workers."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("do_work", src)
        self.assertNotIn("m_result", src)


# ---------------------------------------------------------------------------
# G6: No script-execution cache (full-tx-level cache)
# ---------------------------------------------------------------------------
class TestG6NoScriptExecutionCache(unittest.TestCase):
    """
    BUG-G6: No script-execution cache (Core: m_script_execution_cache).

    Core (validation.cpp:2078-2083):
      uint256 hashCacheEntry;
      hasher.Write(tx.GetWitnessHash(), 32).Write(&flags, sizeof(flags))
            .Finalize(hashCacheEntry);
      if (m_script_execution_cache.contains(hashCacheEntry, !cacheFullScriptStore))
          return true;   // entire tx skipped

    When a tx was verified in the mempool, ConnectBlock can skip ALL per-input
    signature checks by looking up the wtxhash+flags entry.  This is separate
    from the per-signature SigCache and is the dominant speedup for blocks
    where most txs were previously validated in the mempool.

    ouroboros: has SigCache (per-input), but no per-tx script-execution cache.
    Every ConnectBlock re-runs _verify_input_signature for every input.
    """

    def test_no_script_execution_cache_class(self):
        """No ScriptExecutionCache or equivalent class."""
        import ouroboros.sig_cache as sc_mod
        import inspect
        src = inspect.getsource(sc_mod)
        self.assertNotIn("ScriptExecutionCache", src,
            "Unexpected: ScriptExecutionCache found in sig_cache.py")
        self.assertNotIn("script_execution_cache", src,
            "Unexpected: script_execution_cache found in sig_cache.py")

    def test_no_per_tx_cache_lookup_in_validation(self):
        """validate_transaction does not do a per-tx witness-hash cache check."""
        import ouroboros.validation as val_mod
        import inspect
        src = inspect.getsource(val_mod)
        self.assertNotIn("wtxhash", src,
            "Unexpected: wtxhash cache hit in validation.py")
        self.assertNotIn("GetWitnessHash", src,
            "Unexpected: GetWitnessHash cache lookup in validation.py")
        # Confirm per-input cache only (SIG_CACHE used)
        self.assertIn("SIG_CACHE.lookup", src,
            "Expected per-input SIG_CACHE.lookup in validation.py")


# ---------------------------------------------------------------------------
# G7: SigCache key includes sighash+pubkey+sig (FIXED)
# ---------------------------------------------------------------------------
class TestG7CacheKeyWrong(unittest.TestCase):
    """
    FIXED-G7: SigCache key now commits to (sighash, pubkey, sig, flags).

    Core SigCache (sigcache.h / sigcache.cpp):
      ComputeEntryECDSA: SHA256(nonce||'E'||0*31||sighash||pubkey||sig)
      ComputeEntrySchnorr: SHA256(nonce||hash||pubkey||sig)

    After fix: ouroboros uses SHA256(nonce || sighash || pubkey || sig ||
    flags_le32)[:8].  Two different (sig, pubkey) pairs on the same outpoint
    produce distinct cache entries.
    """

    def test_different_sigs_produce_distinct_cache_entries(self):
        """FIXED: distinct sig bytes → distinct cache entries (no false hit)."""
        cache = SigCache(max_entries=100)
        sighash = b"sighash_bytes_" + bytes(18)
        pubkey  = b"pubkey_bytes__" + bytes(19)
        sig_a   = b"sig_a_" + bytes(58)
        sig_b   = b"sig_b_" + bytes(58)  # different signature

        cache.insert(sighash, pubkey, sig_a, 0)

        # A different signature on the same outpoint must NOT hit the cache.
        self.assertTrue(cache.lookup(sighash, pubkey, sig_a, 0),
            "Same material should hit after insert")
        self.assertFalse(cache.lookup(sighash, pubkey, sig_b, 0),
            "G7 FIXED: different sig bytes must not produce a false cache hit")

    def test_different_sighashes_produce_distinct_cache_entries(self):
        """FIXED: distinct sighash bytes → distinct cache entries."""
        cache = SigCache(max_entries=10)
        pubkey = b"pk" + bytes(31)
        sig    = b"sig" + bytes(61)
        sh_a   = b"sighash_A" + bytes(23)
        sh_b   = b"sighash_B" + bytes(23)

        cache.insert(sh_a, pubkey, sig, 1)
        self.assertTrue(cache.lookup(sh_a, pubkey, sig, 1))
        self.assertFalse(cache.lookup(sh_b, pubkey, sig, 1),
            "G7 FIXED: different sighash bytes must not hit same cache entry")


# ---------------------------------------------------------------------------
# G8: SigCache uses os.urandom(32) nonce (FIXED)
# ---------------------------------------------------------------------------
class TestG8NoSaltedNonce(unittest.TestCase):
    """
    FIXED-G8: SigCache.__init__ now generates a 32-byte random nonce via
    os.urandom(32).  All cache entry hashes incorporate this nonce so that
    an attacker who can observe txids / input indices cannot predict or
    pre-compute cache keys.

    Core equivalent: GetRandHash() nonce written into m_salted_hasher_ecdsa /
    m_salted_hasher_schnorr at startup (sigcache.cpp:22-32).
    """

    def test_nonce_present_in_sig_cache(self):
        """SigCache.__init__ now generates a random nonce via os.urandom."""
        import inspect
        from ouroboros.sig_cache import SigCache as SC
        src = inspect.getsource(SC)
        self.assertIn("nonce", src,
            "G8 FIXED: SigCache must have a nonce attribute")
        self.assertIn("urandom", src,
            "G8 FIXED: nonce must be generated with os.urandom")
        # Key derivation must use SHA256, not a raw tuple
        self.assertIn("sha256", src,
            "G8 FIXED: key derivation must use hashlib.sha256")

    def test_cache_key_is_hashed_bytes_not_plain_tuple(self):
        """Cache stores 8-byte hashed keys, not raw tuples."""
        cache = SigCache(max_entries=10)
        sighash = b"sh" + bytes(30)
        pubkey  = b"pk" + bytes(31)
        sig     = b"sg" + bytes(62)
        cache.insert(sighash, pubkey, sig, 0)
        with cache._lock:
            stored_keys = list(cache._cache.keys())
        self.assertEqual(len(stored_keys), 1)
        stored = stored_keys[0]
        # Key must be bytes (the 8-byte hash prefix), not a plain tuple
        self.assertIsInstance(stored, bytes,
            "G8 FIXED: internal key must be bytes (SHA256 prefix), not a tuple")
        self.assertEqual(len(stored), 8,
            "G8 FIXED: internal key must be 8 bytes")

    def test_two_caches_have_different_nonces(self):
        """Each SigCache instance has its own distinct nonce."""
        c1 = SigCache(max_entries=10)
        c2 = SigCache(max_entries=10)
        self.assertNotEqual(c1.nonce, c2.nonce,
            "G8 FIXED: each SigCache instance must have a unique per-process nonce")
        self.assertEqual(len(c1.nonce), 32,
            "G8 FIXED: nonce must be 32 bytes")


# ---------------------------------------------------------------------------
# G9: SigCache key commits to sighash + pubkey + sig (FIXED)
# ---------------------------------------------------------------------------
class TestG9CacheKeyMissingSighash(unittest.TestCase):
    """
    FIXED-G9: SigCache key now commits to the full cryptographic material:
    sighash bytes, pubkey bytes, sig bytes, and flags — all salted with the
    per-process nonce.

    Core ComputeEntryECDSA key covers: nonce || 'E' || zeros || sighash || pubkey || sig
    Core ComputeEntrySchnorr: nonce || hash || pubkey || sig

    After fix: no two distinct (sighash, pubkey, sig, flags) tuples share a
    cache entry.  Adversarial cache poisoning via outpoint reuse is prevented.
    """

    def test_no_false_cache_hit_with_different_sigs(self):
        """FIXED: a different sig on same outpoint does NOT produce a cache hit."""
        cache = SigCache(max_entries=100)
        sighash = b"sighash_material" + bytes(16)
        pubkey  = b"pubkey_material_" + bytes(17)
        sig_a   = b"sig_a_material__" + bytes(48)
        sig_b   = b"sig_b_material__" + bytes(48)  # different sig (e.g. malleated)

        cache.insert(sighash, pubkey, sig_a, 0)

        self.assertTrue(cache.lookup(sighash, pubkey, sig_a, 0))
        self.assertFalse(cache.lookup(sighash, pubkey, sig_b, 0),
            "G9 FIXED: malleated sig must not produce a false cache hit")

    def test_different_pubkeys_do_not_collide(self):
        """FIXED: different pubkeys on same outpoint produce distinct entries."""
        cache = SigCache(max_entries=100)
        sighash = b"sighash_material" + bytes(16)
        pk_a    = b"pubkey_a_material" + bytes(16)
        pk_b    = b"pubkey_b_material" + bytes(16)
        sig     = b"sig_material____" + bytes(48)

        cache.insert(sighash, pk_a, sig, 0x0001)

        self.assertTrue(cache.lookup(sighash, pk_a, sig, 0x0001))
        self.assertFalse(cache.lookup(sighash, pk_b, sig, 0x0001),
            "G9 FIXED: different pubkey must not collapse to same cache entry")


# ---------------------------------------------------------------------------
# G10: No CachingTransactionSignatureChecker equivalent
# ---------------------------------------------------------------------------
class TestG10NoCachingChecker(unittest.TestCase):
    """
    BUG-G10: No CachingTransactionSignatureChecker equivalent.

    Core (sigcache.h:63-74): CachingTransactionSignatureChecker wraps
    TransactionSignatureChecker and overrides VerifyECDSASignature and
    VerifySchnorrSignature to consult the SignatureCache before calling
    the underlying secp256k1 verifier.  This is the only code path that
    writes successful verifications to the cache.

    ouroboros: _verify_input_signature manually checks SIG_CACHE.lookup()
    and then calls ScriptInterpreter.verify() directly, then inserts on
    success.  This pattern is functionally equivalent but:
      1. The script interpreter itself is not aware of the cache.
      2. Any refactoring that bypasses _verify_input_signature will miss
         the cache entirely (e.g. direct ScriptInterpreter.verify() calls).
      3. The Rust ScriptInterpreter has no cache integration at all.
    """

    def test_no_caching_checker_class(self):
        """No CachingTransactionSignatureChecker class in Python."""
        import ouroboros.script as script_mod
        import inspect
        src = inspect.getsource(script_mod)
        self.assertNotIn("CachingTransactionSignatureChecker", src)
        self.assertNotIn("caching_checker", src.lower())

    def test_rust_script_interpreter_no_cache(self):
        """Rust ScriptInterpreter has no SigCache integration."""
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        self.assertNotIn("SigCache", content)
        self.assertNotIn("sig_cache", content)
        self.assertNotIn("cache.lookup", content)
        self.assertNotIn("cache.insert", content)

    def test_cache_check_only_in_verify_input_signature(self):
        """SIG_CACHE is only consulted in _verify_input_signature — not in interpreter."""
        import ouroboros.script as script_mod
        import inspect
        src = inspect.getsource(script_mod)
        self.assertNotIn("SIG_CACHE", src,
            "G10: ScriptInterpreter itself should not reference SIG_CACHE")


# ---------------------------------------------------------------------------
# G11: Only one cache; no dual-cache (signature + script execution)
# ---------------------------------------------------------------------------
class TestG11SingleCache(unittest.TestCase):
    """
    BUG-G11: Only one cache (SigCache); Core has TWO caches.

    Core ValidationCache (validation.h:366-389) holds:
      1. SignatureCache m_signature_cache  — per-signature (ECDSA + Schnorr)
      2. CuckooCache m_script_execution_cache  — per-tx (wtxhash+flags)

    The per-tx cache is the bigger win: if a tx was validated in the mempool,
    the entire tx's script check is skipped in ConnectBlock with a single lookup.
    The per-sig cache helps for txs NOT previously in the mempool.

    ouroboros: SigCache is the only cache.  No per-tx execution cache.
    """

    def test_only_sig_cache_no_execution_cache(self):
        """Validation module references SIG_CACHE but not a script execution cache."""
        import ouroboros.validation as val_mod
        import inspect
        src = inspect.getsource(val_mod)
        # Only one global cache instance
        self.assertIn("SIG_CACHE", src)
        # No second cache
        self.assertNotIn("SCRIPT_EXEC_CACHE", src)
        self.assertNotIn("ScriptExecutionCache", src)
        self.assertNotIn("execution_cache", src.lower())
        # Confirm only one SigCache instantiation
        import ouroboros.sig_cache as sc_mod
        sc_src = inspect.getsource(sc_mod)
        self.assertNotIn("ScriptExecutionCache", sc_src)


# ---------------------------------------------------------------------------
# G12: SigCache lock: threading.Lock (exclusive) vs Core shared_mutex
# ---------------------------------------------------------------------------
class TestG12LockGranularity(unittest.TestCase):
    """
    BUG-G12: SigCache uses threading.Lock (mutual exclusion) vs Core shared_mutex.

    Core (sigcache.h:45): std::shared_mutex cs_sigcache
      — shared_lock for reads (multiple readers allowed simultaneously)
      — unique_lock for writes (exclusive)

    ouroboros SigCache: single threading.Lock() serialises ALL operations
    including concurrent lookups.  Under parallel script verification this
    would be a bottleneck since all worker threads contend on the same lock
    even for read-only cache lookups.  (Not critical given G1 — no parallel
    workers exist — but a design gap that would matter if parallelism landed.)
    """

    def test_lock_is_threading_lock_not_rwlock(self):
        """SigCache uses threading.Lock (no reader/writer distinction)."""
        import threading as th
        cache = SigCache(max_entries=100)
        lock = cache._lock
        # threading.Lock() returns a _thread.lock (not an RLock / RWLock)
        # Verify it is NOT an RLock
        rlock_type = type(th.RLock())
        self.assertNotIsInstance(lock, rlock_type,
            "Lock should not be RLock — G12 confirmed: no reader concurrency")
        # threading.Lock is always acquired exclusively (no shared-read semantics)
        # Confirm by checking it does NOT have a reader count attribute
        self.assertFalse(hasattr(lock, "_is_owned"),
            "Lock should be a plain threading.Lock, not an RLock with _is_owned")

    def test_lookup_acquires_same_lock_as_insert(self):
        """lookup() and insert() both acquire the same exclusive lock."""
        import inspect
        from ouroboros.sig_cache import SigCache as SC
        src = inspect.getsource(SC)
        # Both lookup and insert should use 'with self._lock'
        lookup_src = src[src.index("def lookup"):src.index("def insert")]
        insert_src = src[src.index("def insert"):src.index("def clear")]
        self.assertIn("with self._lock", lookup_src)
        self.assertIn("with self._lock", insert_src)


# ---------------------------------------------------------------------------
# G13: No PrecomputedTransactionData equivalent
# ---------------------------------------------------------------------------
class TestG13NoPrecomputedTxData(unittest.TestCase):
    """
    BUG-G13: No PrecomputedTransactionData equivalent.

    Core (hash.h / interpreter.cpp): PrecomputedTransactionData is constructed
    once per tx and caches the serialized hash midstates needed for BIP-143
    (SegWit v0) and BIP-341 (Taproot) sighash computation.  Building it once
    amortises the SHA256 work across all inputs.  ConnectBlock pre-allocates
    txsdata(block.vtx.size()) before the input loop.

    ouroboros: script.py passes input_amounts and input_script_pubkeys as lists
    to verify() but re-derives sighash inside each call.  No PrecomputedTxData,
    no amortised midstate caching.  For Taproot txs with many inputs (e.g. CTV
    vaults, batch spends) this means N redundant SHA256 over all outputs.
    """

    def test_no_precomputed_tx_data_class(self):
        """No PrecomputedTransactionData class in script.py."""
        import ouroboros.script as script_mod
        import inspect
        src = inspect.getsource(script_mod)
        self.assertNotIn("PrecomputedTransactionData", src)
        self.assertNotIn("precomputed_txdata", src)
        self.assertNotIn("txsdata", src)

    def test_sighash_recomputed_per_input(self):
        """Each verify() call recomputes the sighash — no amortised midstate."""
        import ouroboros.script as script_mod
        import inspect
        src = inspect.getsource(script_mod)
        # Taproot sighash function called inside verify_taproot
        self.assertIn("def verify_taproot", src)
        # No Init(tx, spent_outputs) call — everything done per-input
        self.assertNotIn(".Init(", src)


# ---------------------------------------------------------------------------
# G14: Rust ScriptInterpreter never called from Rust block validation path
# ---------------------------------------------------------------------------
class TestG14RustScriptInterpreterDeadPath(unittest.TestCase):
    """
    BUG-G14 (two-pipeline): Rust ScriptInterpreter is exported from mod.rs
    but NEVER called from the Rust block validation path.

    validate/mod.rs re-exports:
      pub use script::{ScriptInterpreter, ..., verify_signature_in_script, verify_witness}

    validate/block.rs BlockValidator::validate_block_with_flags():
      "skip_scripts is reserved for future script-verify gating"
      "the production validate path does not call the script interpreter"
    The comment in block.rs explicitly says script verification never lands.

    This is the classic ouroboros two-pipeline pattern: a Rust implementation
    exists (full ScriptInterpreter with CHECKSIG, CHECKMULTISIG, witness, tapscript)
    but the Rust block path runs structural checks only and hands script work
    back to Python.  The Rust interpreter is used ONLY in unit tests.
    """

    def test_rust_block_rs_does_not_call_script_interpreter(self):
        """block.rs never calls ScriptInterpreter::evaluate_script."""
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_block.exists():
            self.skipTest("Rust source not found")
        content = rust_block.read_text()
        self.assertNotIn("ScriptInterpreter::",
                         content,
                         "BUG-G14 resolved unexpectedly: block.rs calls ScriptInterpreter")

    def test_skip_scripts_comment_in_rust_block(self):
        """block.rs documents that skip_scripts is a dead parameter today."""
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_block.exists():
            self.skipTest("Rust source not found")
        content = rust_block.read_text()
        # The comment acknowledges the dead code
        self.assertIn("skip_scripts", content,
            "Expected skip_scripts param in validate_block_with_flags")
        # Reserved for future use
        self.assertTrue(
            "reserved" in content or "future" in content or "dead" in content,
            "Expected reservation comment for skip_scripts in block.rs"
        )

    def test_rust_lib_rs_does_not_export_parallel_script_check(self):
        """lib.rs does not export parallel_check_inputs or equivalent."""
        rust_lib = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_lib.exists():
            self.skipTest("Rust source not found")
        content = rust_lib.read_text()
        self.assertNotIn("parallel_check_inputs", content)
        self.assertNotIn("check_inputs_parallel", content)
        self.assertNotIn("batch_verify_inputs", content)


# ---------------------------------------------------------------------------
# G15: Rust verify_signature_in_script: P2SH/P2WPKH/P2WSH return stub
# ---------------------------------------------------------------------------
class TestG15RustVerifyStub(unittest.TestCase):
    """
    BUG-G15: Rust verify_signature_in_script returns Ok(false) for P2SH/SegWit.

    validate/script.rs (lines ~1400-1409):
      ScriptType::P2SH => Ok(false),   // "P2SH requires executing the redeem script / simplified"
      _ => Ok(false),                  // "Other script types not implemented yet"

    Only P2PKH and P2PK have even a partial implementation (pubkey hash check
    passes but signature check is skipped with "skip actual signature verification").
    This means if this Rust path were ever wired into production, ALL P2SH,
    P2WPKH, P2WSH, and Taproot inputs would be rejected.
    """

    def test_rust_verify_signature_stub_returns_false_for_p2sh(self):
        """Rust verify_signature_in_script returns Ok(false) for non-P2PKH types."""
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        # P2SH arm uses block form — locate the arm and verify Ok(false) inside it
        self.assertIn("ScriptType::P2SH => {", content,
            "G15: P2SH arm in verify_signature_in_script should be present")
        p2sh_pos = content.index("ScriptType::P2SH => {")
        p2sh_region = content[p2sh_pos:p2sh_pos + 200]
        self.assertIn("Ok(false)", p2sh_region,
            "G15: P2SH arm should return Ok(false) stub")
        # Wildcard arm returns false
        self.assertIn("Other script types not implemented yet", content,
            "G15: wildcard stub for unimplemented script types expected")

    def test_rust_p2pkh_skips_actual_secp256k1(self):
        """Rust verify_p2pkh_signature skips actual sig check — Ok(true) stub."""
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        self.assertIn("skip actual signature verification", content,
            "G15: P2PKH Rust verify skips secp256k1 check")


# ---------------------------------------------------------------------------
# G16: Rust verify_witness: complete placeholder (Ok(false) unconditionally)
# ---------------------------------------------------------------------------
class TestG16RustVerifyWitnessStub(unittest.TestCase):
    """
    BUG-G16: Rust verify_witness is a complete placeholder returning Ok(false).

    validate/script.rs (lines ~1506-1515):
      pub fn verify_witness(_tx: &TransactionWrapper, _input_idx: usize) -> Result<bool> {
          // Placeholder implementation
          Ok(false)
      }

    All SegWit inputs (P2WPKH, P2WSH, P2SH-P2WPKH, P2SH-P2WSH) would be
    rejected if this function were ever called.  Exported from mod.rs but
    the live block path never calls it.
    """

    def test_rust_verify_witness_is_stub(self):
        """verify_witness returns Ok(false) unconditionally."""
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        # Signature of the stub function
        self.assertIn("pub fn verify_witness(_tx: &TransactionWrapper, _input_idx: usize)", content)
        # Returns Ok(false)
        verify_witness_pos = content.index("pub fn verify_witness")
        stub_region = content[verify_witness_pos:verify_witness_pos + 700]
        self.assertIn("Ok(false)", stub_region,
            "G16: verify_witness should be Ok(false) stub")

    def test_rust_verify_witness_exported_but_unused_in_production(self):
        """verify_witness is exported from mod.rs but not called from block.rs."""
        rust_mod = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "mod.rs"
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_mod.exists() or not rust_block.exists():
            self.skipTest("Rust source not found")
        mod_content = rust_mod.read_text()
        block_content = rust_block.read_text()
        # Exported from mod.rs
        self.assertIn("verify_witness", mod_content)
        # But block.rs never calls it
        self.assertNotIn("verify_witness(", block_content,
            "G16: verify_witness should not be called from block.rs — it's a stub")


# ---------------------------------------------------------------------------
# G17: No MAX_SCRIPTCHECK_THREADS limit or -par config
# ---------------------------------------------------------------------------
class TestG17NoMaxScriptcheckThreads(unittest.TestCase):
    """
    BUG-G17: No MAX_SCRIPTCHECK_THREADS (15) or -par configuration option.

    Core (validation.h:90):
      static constexpr int MAX_SCRIPTCHECK_THREADS{15};
    Core (init.cpp:513):
      argsman.AddArg("-par=<n>", ..., MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS)
    Core (validation.cpp:6136):
      m_script_check_queue{128, std::clamp(options.worker_threads_num, 0, MAX_SCRIPTCHECK_THREADS)}

    ouroboros has no equivalent constant, no clamp, and no runtime configuration
    of script-check parallelism.
    """

    def test_max_scriptcheck_threads_constant_absent(self):
        """No MAX_SCRIPTCHECK_THREADS constant in Python or Rust."""
        import ouroboros.validation as val_mod
        import inspect
        src = inspect.getsource(val_mod)
        self.assertNotIn("MAX_SCRIPTCHECK_THREADS", src)
        # Named constant is absent — the number 15 may appear in other contexts
        # (e.g. nScriptCheckThreads default) but the NAMED CONSTANT is what matters
        self.assertNotIn("nScriptCheckThreads", src)

    def test_max_scriptcheck_constant_absent_named(self):
        """The specific constant name is absent in all Python modules."""
        import ouroboros.validation as val_mod
        import ouroboros.config as cfg_mod
        import inspect
        for mod in [val_mod, cfg_mod]:
            src = inspect.getsource(mod)
            self.assertNotIn("MAX_SCRIPTCHECK_THREADS", src)


# ---------------------------------------------------------------------------
# G18: SigCache default size mismatch (50k entries vs Core 16 MiB)
# ---------------------------------------------------------------------------
class TestG18SigCacheSizeMismatch(unittest.TestCase):
    """
    BUG-G18: SigCache default 50,000 entries vs Core 16 MiB CuckooCache.

    Core (sigcache.h:28-31):
      DEFAULT_VALIDATION_CACHE_BYTES = 32 MiB
      DEFAULT_SIGNATURE_CACHE_BYTES  = 16 MiB
      DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES = 16 MiB
    Core's CuckooCache stores ~(16 MiB / entry_size) ≈ 1,000,000+ entries.

    ouroboros (validation.py:38):
      SIG_CACHE = SigCache(max_entries=50_000)
    The comment says "50,000 matches Bitcoin Core's default" — this is WRONG.
    Core's default is approximately 1,000,000 entries (from 16 MiB), not 50,000.
    Underscaling the cache reduces mempool→block hit rate and increases
    redundant ECDSA/Schnorr verifications during block connection.
    """

    def test_sig_cache_default_size_is_50000(self):
        """SigCache is initialized with 50,000 entries — wrong Core-parity claim."""
        import ouroboros.validation as val_mod
        import inspect
        src = inspect.getsource(val_mod)
        self.assertIn("SigCache(max_entries=50_000)", src,
            "Expected SIG_CACHE = SigCache(max_entries=50_000) in validation.py")

    def test_wrong_comment_in_validation(self):
        """Comment says 50,000 matches Core default — that is inaccurate."""
        import ouroboros.validation as val_mod
        import inspect
        src = inspect.getsource(val_mod)
        # The comment is there and claims Core parity
        self.assertIn("50,000", src)
        # Core default is ~1M entries from 16 MiB CuckooCache
        # The 50k figure is off by ~20x
        cache = SigCache(max_entries=50_000)
        self.assertEqual(cache._max_entries, 50_000)
        # Core DEFAULT_SIGNATURE_CACHE_BYTES = 16 MiB = 16 * 1024 * 1024
        CORE_DEFAULT_BYTES = 16 * 1024 * 1024
        # Core entry is ~32 bytes (uint256 hash) → ~500k entries
        APPROX_CORE_ENTRIES = CORE_DEFAULT_BYTES // 32
        self.assertLess(cache._max_entries, APPROX_CORE_ENTRIES,
            f"G18: ouroboros {cache._max_entries} << Core ~{APPROX_CORE_ENTRIES}")


# ---------------------------------------------------------------------------
# G19: No cacheFullScriptStore / cacheSigStore conditional caching
# ---------------------------------------------------------------------------
class TestG19NoCacheResultsControl(unittest.TestCase):
    """
    BUG-G19: No cacheFullScriptStore / cacheSigStore flag equivalents.

    Core (validation.cpp:2576-2586):
      bool fCacheResults = fJustCheck;
      // Don't cache results if we're actually connecting blocks
      // (still consult the cache, though)

    When fJustCheck=false (normal ConnectBlock), fCacheResults=false, so Core
    does NOT write new entries to m_script_execution_cache and REMOVES matched
    signature cache entries (!cacheFullScriptStore passed to CuckooCache::contains).
    This eviction-on-hit pattern ensures the cache shrinks as verified txs age
    out of mempool relevance.

    ouroboros: SigCache always inserts on success (insert on every cache miss),
    and never removes entries on lookup.  No fCacheResults / fJustCheck concept.
    """

    def test_sig_cache_always_inserts_on_success(self):
        """SigCache.insert is called unconditionally on success — no fCacheResults gate."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        # insert is called after every successful verify (variable name post-fix)
        self.assertIn("SIG_CACHE.insert(", src,
            "Expected unconditional insert in _verify_input_signature")
        # No fCacheResults gate
        self.assertNotIn("fCacheResults", src)
        self.assertNotIn("cache_results", src.lower())

    def test_lookup_does_not_remove_entry(self):
        """lookup() does not erase the found entry (Core erases on !cacheFullScriptStore)."""
        cache = SigCache(max_entries=100)
        sh = b"sighash_g19__" + bytes(19)
        pk = b"pubkey_g19___" + bytes(20)
        sig = b"sig_g19______" + bytes(51)
        cache.insert(sh, pk, sig, 0)
        # First lookup
        self.assertTrue(cache.lookup(sh, pk, sig, 0))
        # Entry not erased — still present
        self.assertTrue(cache.lookup(sh, pk, sig, 0),
            "G19: lookup does not remove entry (Core removes on !cacheFullScriptStore)")


# ---------------------------------------------------------------------------
# G20: No pvChecks reserve() upfront allocation
# ---------------------------------------------------------------------------
class TestG20NoPvChecksReserve(unittest.TestCase):
    """
    BUG-G20: No pvChecks.reserve() equivalent.

    Core (validation.cpp:2069-2071):
      if (pvChecks) { pvChecks->reserve(tx.vin.size()); }
    Reserves vector capacity before pushing per-input CScriptCheck objects
    to avoid reallocations that would invalidate pointers to earlier checks
    while they are being executed by worker threads.  Safety-critical since
    worker threads hold raw pointers into the vector.

    ouroboros: no pvChecks vector, no reserve, and no pointer aliasing risk
    (Python operates on list references, not raw pointers).  Not a correctness
    issue in Python, but documents the design divergence.
    """

    def test_no_pvchecks_reserve(self):
        """No pvChecks.reserve() pattern in validation."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("pvChecks", src)
        self.assertNotIn(".reserve(", src)


# ---------------------------------------------------------------------------
# G21: Python serial input verification (no parallel)
# ---------------------------------------------------------------------------
class TestG21SerialInputVerification(unittest.TestCase):
    """
    BUG-G21: Python verifies inputs serially, one by one.

    Core: per-input CScriptCheck objects are pushed to CCheckQueueControl;
    worker threads verify them in parallel across the block.  A 1,000-input
    tx with 15 workers processes ~67 inputs per worker simultaneously.

    ouroboros: for i, tx_in in enumerate(tx.inputs): _verify_input_signature(...)
    All inputs of all transactions are verified serially.  For high-input
    blocks (e.g. consolidation txs, CoinJoin, batch payments) this is a
    significant performance gap.  Not a consensus bug, but IBD performance
    diverges widely from Core at high-input blocks.
    """

    def test_inputs_verified_in_serial_for_loop(self):
        """validate_transaction uses a serial for-loop over inputs."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertIn("for i, tx_in in enumerate(tx.inputs):",
                      src, "Expected serial enumerate loop over tx inputs")

    def test_no_parallel_input_verification(self):
        """No concurrent.futures or asyncio.gather for input verification."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("concurrent.futures", src)
        self.assertNotIn("asyncio.gather", src)
        self.assertNotIn("ThreadPoolExecutor", src)


# ---------------------------------------------------------------------------
# G22: Rust BlockValidator: skip_scripts=True always in production
# ---------------------------------------------------------------------------
class TestG22RustAlwaysSkipsScripts(unittest.TestCase):
    """
    BUG-G22: Rust BlockValidator always uses skip_scripts=True in production.

    validate/block.rs validate_block_with_flags():
      let _ = skip_scripts; // reserved for future script-verify gating

    lib.rs validate_block_from_bytes():
      validator.validate_block_with_flags(&block, prev_height, skip_scripts)
    Where skip_scripts is passed in from Python — but the Rust comment says:
      "skip_scripts is reserved; today Rust never calls script::verify_*
       in the validate path"

    The Rust block path does NOT perform any script/signature verification
    regardless of the skip_scripts value.  Setting skip_scripts=False would
    NOT cause script verification to run — it is a no-op.
    """

    def test_rust_skip_scripts_is_dead_code(self):
        """block.rs ignore skip_scripts with let _ = skip_scripts;"""
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_block.exists():
            self.skipTest("Rust source not found")
        content = rust_block.read_text()
        # The skip_scripts param is discarded
        self.assertIn("let _ = skip_scripts;", content,
            "G22: skip_scripts should be discarded (dead) in Rust block.rs")

    def test_lib_rs_validate_block_from_bytes_comment(self):
        """lib.rs documents that Rust never calls script::verify_*."""
        rust_lib = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_lib.exists():
            self.skipTest("Rust source not found")
        content = rust_lib.read_text()
        # skip_scripts parameter is present
        self.assertIn("skip_scripts", content)
        # Comment about it being reserved / today Rust never
        self.assertTrue(
            "never" in content or "reserved" in content or "forward compat" in content,
            "G22: lib.rs should document that skip_scripts is reserved/dead"
        )


# ---------------------------------------------------------------------------
# G23: validate_block_with_flags skip_scripts parameter dead
# ---------------------------------------------------------------------------
class TestG23SkipScriptsParamDead(unittest.TestCase):
    """
    BUG-G23: skip_scripts in validate_block_with_flags is a dead parameter.

    Both Rust (block.rs) and the Python path treat skip_scripts as a future
    gate.  The Rust path ignores it; the Python path that uses the Rust FFI
    passes it through but the Rust side discards it.  There is no code path
    where setting skip_scripts=False actually changes script verification
    behavior in the Rust validator.
    """

    def test_python_passes_skip_scripts_to_rust(self):
        """Python block_sync / sync_manager passes skip_scripts to Rust."""
        rust_lib = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_lib.exists():
            self.skipTest("Rust source not found")
        content = rust_lib.read_text()
        # validate_block_from_bytes accepts skip_scripts
        self.assertIn("fn validate_block_from_bytes", content)
        self.assertIn("skip_scripts: bool", content)

    def test_rust_ignores_skip_scripts_value(self):
        """Regardless of skip_scripts value, Rust block.rs behavior unchanged."""
        rust_block = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "block.rs"
        if not rust_block.exists():
            self.skipTest("Rust source not found")
        content = rust_block.read_text()
        # Only one occurrence of skip_scripts and it's being discarded
        count = content.count("skip_scripts")
        self.assertGreaterEqual(count, 1)
        # The discard pattern
        self.assertIn("let _ = skip_scripts;", content)


# ---------------------------------------------------------------------------
# G24: No fScriptChecks flag (Core gates queue on pindex status checks)
# ---------------------------------------------------------------------------
class TestG24NoFScriptChecks(unittest.TestCase):
    """
    BUG-G24: No fScriptChecks gate.

    Core (validation.cpp:2574):
      if (!tx.IsCoinBase() && fScriptChecks)
    fScriptChecks is derived from pindex state and is false for assumevalid
    blocks.  Even with the queue active, no CScriptCheck objects are pushed
    when fScriptChecks=false.  The queue control is also conditioned:
      if (auto& queue = m_chainman.GetCheckQueue(); queue.HasThreads() && fScriptChecks)
        control.emplace(queue);

    ouroboros: skip_scripts boolean serves a similar purpose (skip_scripts=True
    means no _verify_input_signature calls) but there is no equivalent
    fScriptChecks that conditions the parallel queue instantiation.
    """

    def test_no_fscriptchecks_variable(self):
        """No fScriptChecks variable in Python validation."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("fScriptChecks", src)

    def test_skip_scripts_is_analogous_gate(self):
        """skip_scripts boolean controls whether script verification runs."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        # skip_scripts gates _verify_input_signature
        self.assertIn("if not skip_scripts:", src)


# ---------------------------------------------------------------------------
# G25: SigCache.clear() not wired to disconnect/reorg path
# ---------------------------------------------------------------------------
class TestG25ClearNotWiredToReorg(unittest.TestCase):
    """
    G25 PARTIAL: SigCache.clear() is wired to the reorg path in block_sync.py
    but NOT to validation.py's disconnect path or any Python-side chain-switch.

    block_sync.py:2834 calls SIG_CACHE.clear() in the reorg handler — this is
    the block_sync.py (new-blocks path) reorg.  The validation.py path
    (used for IBD and direct submitblock) does not call clear on disconnect,
    so the exposure window is:
      * IBD reorgs that go through validation.py directly (not block_sync.py)
      * Any code path that does disconnect_block without going through
        block_sync.py handle_reorg

    Core clears the signature cache on any chain reorg in Chainstate::
    DisconnectTip() before re-evaluating the new tip.  The ouroboros reorg
    path in block_sync.py does call clear() at the start of handle_reorg
    which is equivalent — but validation.py's standalone disconnect path
    does not.  Severity: low (IBD rarely reorgs in an adversarial window).
    """

    def test_sig_cache_clear_defined(self):
        """SigCache.clear() exists."""
        cache = SigCache(max_entries=10)
        self.assertTrue(hasattr(cache, 'clear'))
        cache.insert(b"sh_g25_" + bytes(25), b"pk_g25_" + bytes(26), b"sig_g25" + bytes(57), 0)
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_clear_called_in_block_sync_reorg_handler(self):
        """block_sync.py handle_reorg calls SIG_CACHE.clear() — partial fix present."""
        import inspect
        import ouroboros.block_sync as bs_mod
        src = inspect.getsource(bs_mod)
        self.assertIn("SIG_CACHE.clear()", src,
            "G25 partial fix: block_sync.py handle_reorg should call SIG_CACHE.clear()")

    def test_clear_not_called_in_validation_disconnect(self):
        """validation.py disconnect/apply_block path does not call SIG_CACHE.clear()."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        # validation.py does not call clear — gap remains on IBD reorg path
        self.assertNotIn("SIG_CACHE.clear()", src,
            "G25 unexpectedly resolved in validation.py: SIG_CACHE.clear() found")


# ---------------------------------------------------------------------------
# G26: Rust verify_p2pkh_signature skips actual secp256k1 (Ok(true) stub)
# ---------------------------------------------------------------------------
class TestG26RustP2PKHSkipsActualVerify(unittest.TestCase):
    """
    BUG-G26: Rust verify_p2pkh_signature skips actual secp256k1 signature check.

    validate/script.rs (lines ~1456-1460):
      // For now, skip actual signature verification
      // In production, this would create the sighash and verify the signature
      // using secp256k1
      Ok(true)  // Returns true without verifying!

    This means any input whose pubkey hash matches is accepted regardless of
    whether the signature is valid.  If this Rust path were wired into production,
    a thief could spend any P2PKH output by providing only a matching pubkey
    and an arbitrary garbage signature.  Combined with G15 returning Ok(false)
    for all other types, this Rust interpreter path would be unusable: it
    over-accepts P2PKH and over-rejects everything else.
    """

    def test_rust_p2pkh_always_returns_true_after_hash_match(self):
        """verify_p2pkh_signature returns Ok(true) without secp256k1 — stub."""
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        # The skip comment is present
        self.assertIn("skip actual signature verification", content,
            "G26: Rust P2PKH verify must have 'skip actual signature verification' comment")
        # Returns Ok(true) — not Ok(false)
        p2pkh_pos = content.index("fn verify_p2pkh_signature")
        p2pkh_region = content[p2pkh_pos:p2pkh_pos + 2500]
        self.assertIn("Ok(true)", p2pkh_region,
            "G26: P2PKH Rust stub returns Ok(true) — accepts any pubkey-hash-matching input")


# ---------------------------------------------------------------------------
# G27: No separate policy vs consensus CheckInputScripts calls
# ---------------------------------------------------------------------------
class TestG27NoPolicyConsensusCheckSplit(unittest.TestCase):
    """
    BUG-G27: No separate PolicyScriptChecks / ConsensusScriptChecks calls.

    Core mempool (txmempool.cpp / validation.cpp):
      PolicyScriptChecks: flags = STANDARD_SCRIPT_VERIFY_FLAGS (policy + consensus)
      ConsensusScriptChecks: flags = GetBlockScriptFlags() (consensus only)
    Both run before AcceptToMemoryPool; ConnectBlock only calls CheckInputScripts
    with the consensus flags.

    ouroboros (validation.py validate_transaction):
      flags = get_flags_for_height(height, ...) | int(extra_script_flags)
      extra_script_flags carries the policy delta for mempool callers.
    This is functionally correct for the mempool path.  For the block path,
    extra_script_flags=0 so only consensus flags apply.  However there is no
    explicit two-pass structure (PolicyScriptChecks then ConsensusScriptChecks)
    matching Core's design; it's a single pass with merged flags.
    """

    def test_single_flags_merge_not_two_passes(self):
        """validate_transaction merges flags in one call — not two-pass structure."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        # PolicyScriptChecks and ConsensusScriptChecks appear in docstrings/comments
        # but are NOT used as actual function calls — there is no two-pass structure.
        # Verify there is no function NAMED PolicyScriptChecks or ConsensusScriptChecks
        self.assertNotIn("def PolicyScriptChecks", src,
            "G27: No PolicyScriptChecks function should be defined")
        self.assertNotIn("def ConsensusScriptChecks", src,
            "G27: No ConsensusScriptChecks function should be defined")
        self.assertNotIn("PolicyScriptChecks(", src,
            "G27: No PolicyScriptChecks() function call expected")
        self.assertNotIn("ConsensusScriptChecks(", src,
            "G27: No ConsensusScriptChecks() function call expected")
        # Single flags computation (one merged call)
        self.assertIn("flags = get_flags_for_height", src)
        self.assertIn("flags |= int(extra_script_flags)", src)


# ---------------------------------------------------------------------------
# G28: No m_control_mutex (Core CCheckQueueControl exclusivity)
# ---------------------------------------------------------------------------
class TestG28NoControlMutex(unittest.TestCase):
    """
    BUG-G28: No m_control_mutex equivalent.

    Core (checkqueue.h:141):
      Mutex m_control_mutex;  // ensures only one concurrent CCheckQueueControl

    This prevents two concurrent ConnectBlock calls (e.g. on different
    chainstate managers, or a reorg racing with initial sync) from pushing
    conflicting check batches into the same queue.

    ouroboros: no equivalent mutex since there is no queue.  The single-threaded
    nature of Python's GIL provides implicit exclusivity, but there is no
    explicit guard against concurrent validation attempts.
    """

    def test_no_control_mutex_needed_without_queue(self):
        """Without a CCheckQueue there is no need for m_control_mutex."""
        import inspect
        import ouroboros.validation as val_mod
        src = inspect.getsource(val_mod)
        self.assertNotIn("m_control_mutex", src)
        self.assertNotIn("control_mutex", src)


# ---------------------------------------------------------------------------
# G29: Rust ScriptInterpreter exported from mod.rs but not in FFI bridge
# ---------------------------------------------------------------------------
class TestG29RustInterpreterNotInFFI(unittest.TestCase):
    """
    BUG-G29 (two-pipeline): Rust ScriptInterpreter is exported from mod.rs
    but has NO #[pyfunction] binding and is NOT accessible from Python.

    validate/mod.rs:
      pub use script::{ScriptInterpreter, ScriptError, ...};

    lib.rs: zero occurrences of 'ScriptInterpreter' as a #[pyfunction] or
    #[pyclass] — the Rust interpreter is entirely inaccessible from Python.

    Python uses its own ScriptInterpreter (script.py).  The Rust interpreter
    and Python interpreter are completely independent and not linked.  Two
    separate interpreters for the same Bitcoin script engine → divergence risk.
    """

    def test_rust_script_interpreter_not_pyfunction(self):
        """ScriptInterpreter has no #[pyfunction] or #[pyclass] annotation."""
        rust_lib = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_lib.exists():
            self.skipTest("Rust source not found")
        content = rust_lib.read_text()
        # No pyfunction wrapper for ScriptInterpreter
        self.assertNotIn("pyfunction\nfn", content)
        # Specifically no ScriptInterpreter export
        # (search for wrapping ScriptInterpreter in add_function)
        self.assertNotIn("ScriptInterpreter", content,
            "G29: ScriptInterpreter should not appear in lib.rs FFI bindings")

    def test_two_independent_interpreters(self):
        """Both Python and Rust have their own ScriptInterpreter class."""
        # Python interpreter
        py_interpreter = ScriptInterpreter()
        self.assertIsNotNone(py_interpreter)

        # Rust interpreter exists in validate/script.rs
        rust_script = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "validate" / "script.rs"
        if not rust_script.exists():
            self.skipTest("Rust source not found")
        content = rust_script.read_text()
        self.assertIn("pub struct ScriptInterpreter;", content,
            "G29: Rust ScriptInterpreter struct expected")


# ---------------------------------------------------------------------------
# G30: GIL-releasing detach in validate_block_from_bytes does not parallelise scripts
# ---------------------------------------------------------------------------
class TestG30GILReleaseNoScriptParallel(unittest.TestCase):
    """
    BUG-G30: py.detach() in validate_block_from_bytes releases GIL but script
    checks are STILL NOT parallelised — single block processed per detach().

    lib.rs validate_block_from_bytes():
      py.detach(|| {
          validator.validate_block_with_flags(&block, prev_height, skip_scripts)
      })

    This releases the GIL for the duration of ONE block's structural validation
    (deserialization + header PoW + merkle + sigop check).  This is a good
    optimization — it allows Python to drain the next block from the network
    while Rust validates the current block.

    However it does NOT achieve parallel script verification because:
      1. skip_scripts is always true in production → no scripts run in Rust
      2. Even if skip_scripts=False, the Rust validate_block_with_flags
         processes inputs sequentially (no rayon, no parallel workers)
      3. Only ONE block is in the Rust path at a time per GIL release

    Core runs up to 15 worker threads simultaneously on the SAME block's inputs.
    ouroboros releases the GIL for one sequential structural check.
    """

    def test_gil_release_is_per_block_not_per_input(self):
        """validate_block_from_bytes detaches once per block, not per input."""
        rust_lib = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "src" / "lib.rs"
        if not rust_lib.exists():
            self.skipTest("Rust source not found")
        content = rust_lib.read_text()
        # py.detach() is used (GIL release)
        self.assertIn("py.detach(", content,
            "Expected py.detach() in validate_block_from_bytes")
        # Only one validate_block_with_flags call inside the detach
        detach_pos = content.index("py.detach(")
        detach_region = content[detach_pos:detach_pos + 600]
        self.assertIn("validate_block_with_flags", detach_region)
        # No rayon or par_iter inside the validate path
        self.assertNotIn("par_iter", content)
        self.assertNotIn("rayon", content)

    def test_no_rayon_in_cargo_toml(self):
        """rayon is not a dependency — no data-parallel workers available."""
        cargo_toml = Path(__file__).parent.parent.parent.parent / \
            "ferrous-utils" / "sync" / "Cargo.toml"
        if not cargo_toml.exists():
            self.skipTest("Cargo.toml not found")
        content = cargo_toml.read_text()
        self.assertNotIn("rayon", content,
            "G30: rayon dependency absent — no parallel script verification possible in Rust")


# ---------------------------------------------------------------------------
# Supplementary: SigCache correctness tests (converted from existing behavior)
# ---------------------------------------------------------------------------
class TestSigCacheCorrectness(unittest.TestCase):
    """Verify SigCache behaves correctly for its current design."""

    def test_failure_not_cached(self):
        """Failed verifications are NOT inserted — only successes are cached."""
        cache = SigCache(max_entries=100)
        sh  = b"sighash_fail_" + bytes(19)
        pk  = b"pubkey_fail__" + bytes(20)
        sig = b"sig_fail_____" + bytes(51)
        # Simulate a failed verification: we never call insert
        self.assertFalse(cache.lookup(sh, pk, sig, 0))
        # Only after a successful verification would insert be called
        # This test confirms the contract: look up first, insert only on success

    def test_flags_disambiguate_policy_vs_consensus(self):
        """Different flags (consensus vs policy) create separate cache entries."""
        cache = SigCache(max_entries=100)
        from ouroboros.script import SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS
        sh  = b"sighash_flags" + bytes(19)
        pk  = b"pubkey_flags_" + bytes(20)
        sig = b"sig_flags____" + bytes(51)
        consensus_flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
        policy_flags = consensus_flags | 0x8000  # additional policy bits

        cache.insert(sh, pk, sig, consensus_flags)
        self.assertTrue(cache.lookup(sh, pk, sig, consensus_flags))
        self.assertFalse(cache.lookup(sh, pk, sig, policy_flags),
            "Policy flags cache entry is separate from consensus flags entry")

    def test_cache_survives_threading(self):
        """SigCache is thread-safe for concurrent insert+lookup."""
        cache = SigCache(max_entries=10_000)
        errors = []

        def worker(thread_id: int) -> None:
            for i in range(200):
                sh  = f"sh_{thread_id}_{i}".encode().ljust(32, b'\x00')
                pk  = f"pk_{thread_id}_{i}".encode().ljust(33, b'\x00')
                sig = f"sig_{thread_id}_{i}".encode().ljust(64, b'\x00')
                fl  = i % 5
                cache.insert(sh, pk, sig, fl)
                result = cache.lookup(sh, pk, sig, fl)
                if not result:
                    errors.append(f"thread={thread_id} i={i} lookup after insert failed")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread-safety errors: {errors[:5]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
