# Making the native script interpreter the default

`--par` only parallelises the native Rust interpreter
(`sync.script_verify_parallel`). The Python interpreter holds the GIL; a
thread pool around `verify_python` would be a fake, so `--par` is a
deliberate no-op on that path. Nothing accelerates until
`OUROBOROS_NATIVE_SCRIPT=1` is the path in use.

This file is the explicit answer to that gap. It is not a flip.

## What it would take

1. Invert `ouroboros.script._NATIVE_SCRIPT_REQUESTED` so unset means ON
   and `OUROBOROS_NATIVE_SCRIPT=0` is the opt-out. Today the default is
   Python unless the env is truthy (`1` / `true` / `yes` / `on`).
2. Keep fail-closed: if native is requested (the new default) and the
   compiled `sync` extension lacks `script_native_abi == 1`, refuse to
   start. A green run that silently measured Python is worse than no run.
3. Point `tests/native_script_differential.py` at the opt-out so the
   pure-Python interpreter stays the oracle.
4. `tests/conftest.py` must set the opt-out before importing ouroboros —
   the test stub has no native ABI, and fail-closed would make the suite
   refuse to import.
5. An operator restart of production. This repo does not bounce mainnet
   (`stop_mainnet.sh ouroboros` is operator-gated). `start_mainnet.sh`
   does not set the env today; a source default-on would take effect on
   the next restart, including an on-failure OOM relaunch.

## What still blocks it

1. **Genesis IBD provenance.** The from-genesis R4 rig started
   2026-09-19T03:09:02Z on `7e55946`-era code with the Python interpreter
   and is hundreds of thousands of blocks into a capture. A restart after
   a default flip would mix interpreters in one lineage log. Do not restart
   that rig from this change.
2. **Production restart is operator-gated.** The live unit is at tip;
   flipping the default in source without a restart accelerates nothing,
   and this run does not restart.
3. **Fail-closed makes the wheel mandatory.** A Python-only install (no
   `maturin` wheel) would refuse to start. That is acceptable once
   `setup.sh` is the only supported install path; it is not the
   documented default today (`README.md` still allows Python).

## Not a blocker

- Interpreter identity: Python-vs-native differential is 0 mismatches on
  Core vectors and millions of real mainnet inputs. R1 is closed. The
  interpreter itself is not the new risk surface.
- Pool plumbing: `tests/test_parallel_corpus_identity.py` runs 1-vs-N
  over the diff-test corpus and asserts the exact
  `(ok, fail-index, reason)` triple is identical at 1/2/4/8 workers,
  reasons included.
