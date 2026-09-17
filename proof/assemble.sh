#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + runnable-tree + MANIFEST.
# Frozen evidence (R1/R2/R4/R5 artifacts) is already in proof/ and is not
# regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"

list_runnable() {
  {
    find src/ouroboros -type f \( -name '*.py' -o -name '*.txt' -o -name '*.json' \) \
      ! -path '*/__pycache__/*' \
      ! -path '*/tests/*'
    find ferrous-utils -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' -o -name 'pyproject.toml' \) \
      ! -path '*/target/*' \
      ! -path '*/tests/*' \
      ! -path '*/benches/*'
    printf '%s\n' pyproject.toml setup.sh Cargo.toml Cargo.lock
  } | LC_ALL=C sort -u
}

# Hash the production source this node would run. Interpreted analogue of
# nimrod's bin/nimrod sha256: promote_mainnet.sh refuses this node; the
# launcher is python3 -m ouroboros.cli from this tree plus a maturin-built
# sync extension rebuilt by tools/reinstall_ouroboros.sh on every start.
list_runnable | xargs -d '\n' sha256sum > "$PROOF/runnable-tree.sha256"

SYNC_SO=""
SYNC_SO_SHA=""
if python3 -c 'import sync' >/dev/null 2>&1; then
  SYNC_SO="$(python3 -c 'import pathlib, sync; print(next(pathlib.Path(sync.__file__).parent.glob("*.so")))')"
  SYNC_SO_SHA="$(sha256sum "$SYNC_SO" | awk '{print $1}')"
fi

{
  echo "# Provenance — ouroboros proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/ouroboros"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  echo "interpreted: yes"
  echo "promote_does_not_apply: yes (start_mainnet.sh runs python3 -m ouroboros.cli from this tree)"
  echo "launch: python3 -m ouroboros.cli"
  echo "runnable_tree: proof/runnable-tree.sha256"
  echo "runnable_files: $(wc -l < "$PROOF/runnable-tree.sha256")"
  echo "runtime: $(python3 --version 2>&1 | head -1)"
  echo "runtime_path: $(command -v python3)"
  echo "rustc: $(rustc --version 2>/dev/null || echo 'rustc not on PATH')"
  echo "maturin: $(maturin --version 2>/dev/null || echo 'maturin not on PATH')"
  echo "target: Linux amd64"
  echo "native_extension: ferrous-utils/sync (PyO3 module sync)"
  if [ -n "$SYNC_SO_SHA" ]; then
    echo "installed_sync_so: $SYNC_SO"
    echo "installed_sync_so_sha256: $SYNC_SO_SHA"
  else
    echo "installed_sync_so: (sync extension not importable)"
    echo "installed_sync_so_sha256: (rebuild with maturin build --release --manifest-path ferrous-utils/sync/Cargo.toml)"
  fi
  echo "deploy_pin: deploy/ouroboros/MANIFEST (wheel sha256 52039f392abc8a1555d52c94041aef71c9233e276d47152e56980df2b73c302c)"
  echo "deploy_pin_stale: yes (reinstall_ouroboros.sh rebuilds the wheel from this tree on every start; the pin is unused)"
  echo "unit: hashhog-ouroboros-mainnet (maintenance-paused since 2026-09-10; no live PID)"
  echo
  echo "# Honest caveats"
  echo "ouroboros is interpreted Python plus a native Rust extension. There is no"
  echo "relocatable deploy pin that start_mainnet.sh uses: promote_mainnet.sh refuses"
  echo "this node, and tools/reinstall_ouroboros.sh rebuilds sync from source on every"
  echo "launch. The attested artifact is the production source tree hashed in"
  echo "runnable-tree.sha256 plus the currently installed sync .so (informational;"
  echo "maturin rebuilds are not bit-stable). The mainnet unit is maintenance-paused,"
  echo "so this bundle does not claim a live PID matches these bytes today."
  echo "The deploy/ouroboros wheel sha256 is recorded as STALE, not as the running"
  echo "binary. Do not treat it as nimrod-style pin closure."
  echo "This script refreshes provenance + runnable-tree + MANIFEST only. Frozen"
  echo "evidence in r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
} > "$PROOF/provenance.txt"

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
echo "  runnable: $(wc -l < "$PROOF/runnable-tree.sha256") source files"
