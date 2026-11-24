# The native script interpreter is the default

`--par` only parallelises the native Rust interpreter
(`sync.script_verify_parallel`). The Python interpreter holds the GIL; a
thread pool around `verify_python` would be a fake, so `--par` is a
deliberate no-op on that path. Until the native interpreter was the default,
nothing accelerated unless an operator set `OUROBOROS_NATIVE_SCRIPT=1`.

That is now the default. `OUROBOROS_NATIVE_SCRIPT=0` (or `false`, `no`,
`off`) forces the Python interpreter.

## What was done

1. `ouroboros.script._NATIVE_SCRIPT_REQUESTED` is
   `_native_script_requested(os.environ.get(...))`: unset or empty means
   native, `0` / `false` / `no` / `off` mean Python, and any other value keeps
   native, so a typo cannot drop the node to the slow path.
2. Fail-closed is kept: native is in effect by default, so a compiled `sync`
   extension without `script_native_abi == 1` (stale wheel, ABI drift) makes
   the import fail with a message naming the rebuild and the
   `OUROBOROS_NATIVE_SCRIPT=0` opt-out. A green run that silently measured
   Python is worse than no run.
3. `tests/native_script_differential.py` sets the opt-out itself when the
   variable is unset, and refuses to run when it asks for native, so the
   pure-Python interpreter stays the oracle.
4. `tests/conftest.py` sets the opt-out before importing ouroboros: the test
   stub has no native ABI, and fail-closed would make the suite refuse to
   import. The default itself is pinned in a clean interpreter with the real
   extension by `tests/test_perf_fix_native_script_default.py`, including
   that `--par` reaches the Rust pool.

## What is still operator-gated

1. **Production restart is operator-gated.** The source default takes
   effect on the next restart of a node running this tree, including an
   on-failure OOM relaunch. This repo does not bounce mainnet
   (`stop_mainnet.sh ouroboros` is the operator's step). A deployment that
   must keep the Python interpreter sets `OUROBOROS_NATIVE_SCRIPT=0` in its
   unit or launcher.
2. **Genesis IBD provenance.** A from-genesis R4 rig started on Python-era
   code would mix interpreters in one lineage log if restarted on this
   tree. Do not restart such a rig on this change without setting
   `OUROBOROS_NATIVE_SCRIPT=0`, or record the switch height in its ledger.
3. **The wheel is mandatory.** A Python-only install (no `maturin` wheel)
   already could not run the node (`ouroboros/__init__.py` imports `sync`);
   the native interpreter adds only the ABI check above.

## Evidence the interpreters agree

- Python-vs-native differential: 0 mismatches on Core's `script_tests.json`,
  `tx_valid.json` / `tx_invalid.json`, `sighash.json` and real mainnet
  inputs (`tests/native_script_differential.py`, with a negative control).
- Pool plumbing: `tests/test_parallel_corpus_identity.py` runs 1-vs-N
  over the diff-test corpus and asserts the exact
  `(ok, fail-index, reason)` triple is identical at 1/2/4/8 workers,
  reasons included.
