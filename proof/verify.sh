#!/usr/bin/env bash
# proof/verify.sh — re-check every claim in this bundle against a file here.
# Exit 0 only if the files match claims.json AND the in-repo T2 + assumevalid
# controls are green. Run from the ouroboros repo root: `bash proof/verify.sh`
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

need() {
  local f="$1"
  [ -f "$PROOF/$f" ] || die "missing $f"
}

say "== ouroboros proof bundle verify =="

# 1. every claims.json file exists
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if not (proof / f).is_file():
            missing.append(f)
if missing:
    print("FAIL: missing files:", ", ".join(missing))
    sys.exit(1)
print("files: every claims.json path exists")
PY

# 2. R4 — UNPROVEN, and the included files say why
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r4"]
st = json.loads((proof / "r4/status.json").read_text())
rows = json.loads((proof / "r4/range-rows.json").read_text())
none = (proof / "r4/no-c958794.txt").read_text()
cov = (proof / "r4/range-coverage.txt").read_text()
unit = (proof / "r4/genesis-unit.service").read_text()
excerpt = (proof / "r4/lineage-excerpt.txt").read_text()
errs = []
if c["status"] != "UNPROVEN" or st["status"] != "UNPROVEN":
    errs.append("R4 status must be UNPROVEN (no C(H) capture in this bundle)")
if (proof / "r4/C958794.json").exists():
    errs.append("r4/C958794.json exists — a C() file would need a matching completed lineage; this node does not have one")
if c.get("snapshot_booted_does_not_count") is not True or st.get("snapshot_booted_does_not_count") is not True:
    errs.append("claims must refuse snapshot-booted lineages")
if c.get("range_counts_as_r4") is not False or rows.get("counts_as_r4") is not False:
    errs.append("range-runner rows must not count as R4 (TRUST-ANCHOR)")
if rows.get("snapshot_booted") is not True:
    errs.append("range-rows.json must declare snapshot_booted=true")
closed = [r for r in rows["rows"] if r["verdict"] == "CLOSED"]
if len(closed) != c["range_closed"]:
    errs.append(f"range closed count {len(closed)} != claims {c['range_closed']}")
blocks = sum(r["blocks"] for r in closed)
if blocks != c["range_closed_blocks"]:
    errs.append(f"range closed blocks {blocks} != claims {c['range_closed_blocks']}")
if st["range_closed"] != c["range_closed"] or st["range_closed_blocks"] != c["range_closed_blocks"]:
    errs.append("status.json range counts do not match claims")
if "512,594" not in cov and "512594" not in cov:
    errs.append("range-coverage.txt missing 512,594")
if "TRUST-ANCHOR" not in cov:
    errs.append("range-coverage.txt missing TRUST-ANCHOR")
if c["genesis_ibd_reached_c958794"] is not False or st.get("genesis_ibd_reached_c958794") is not False:
    errs.append("must not claim C(958794) was reached")
if "no ouroboros C(958794)" not in none and "no ouroboros C(958794)" not in none.lower():
    if "There is no ouroboros C(958794)" not in none:
        errs.append("no-c958794.txt does not admit the missing capture")
if "--noassumevalid" not in unit:
    errs.append("genesis-unit.service missing --noassumevalid")
if "loadtxoutset" in unit or "assumeutxo" in unit.lower():
    errs.append("genesis-unit.service looks like a snapshot boot")
if "Genesis block stored" not in excerpt:
    errs.append("lineage excerpt missing Genesis block stored")
if "current height: 0" not in excerpt:
    errs.append("lineage excerpt missing current height: 0")
if "assumevalid=0" not in excerpt:
    errs.append("lineage excerpt missing assumevalid=0")
if "loadtxoutset matches=0" not in excerpt:
    errs.append("lineage excerpt missing snapshot-boot negative control")
if c["genesis_block_hash"] not in excerpt:
    errs.append("lineage excerpt missing Bitcoin genesis hash")
if str(c["genesis_ibd_last_height"]) not in excerpt:
    errs.append("lineage excerpt missing last height 580755")
if "loading snapshot" in excerpt.lower() and "loading snapshot matches=0" not in excerpt:
    errs.append("lineage excerpt contains loading snapshot without the negative control")
if errs:
    print("FAIL: R4:", "; ".join(errs))
    sys.exit(1)
print(f"R4: UNPROVEN (no C(H)); genesis-IBD exists, stopped at {c['genesis_ibd_last_height']}; ranges {c['range_closed']} CLOSED / {c['range_closed_blocks']} blocks count_as_r4=false")
PY

# 3. assumevalid=0 must stay wired into the validator (submitblock path)
if ! grep -q 'self.validator.force_full_scripts = force_full_scripts' "$ROOT/src/ouroboros/node.py"; then
  die "node.py no longer sets validator.force_full_scripts (submitblock assumevalid=0 wiring is gone)"
else
  say "R4: node.py sets validator.force_full_scripts from assumevalid"
fi
if ! grep -q 'force_check_scripts or getattr(self, "force_full_scripts"' "$ROOT/src/ouroboros/validation.py"; then
  die "validation.py no longer consults force_full_scripts"
else
  say "R4: validation.py consults force_full_scripts"
fi
if ! grep -q '850000' "$ROOT/tests/test_assumevalid_submitblock_path.py"; then
  die "test_assumevalid_submitblock_path.py no longer names the 850000 checkpoint"
else
  say "R4: in-repo assumevalid submitblock test still names 850000"
fi

# 4. R1 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r1"]
r = json.loads((proof / "r1/results.json").read_text())
errs = []
if r["script_tests"]["pass"] != c["script_pass"] or r["script_tests"]["fail"] != c["script_fail"]:
    errs.append("script")
if r["tx_valid"]["pass"] != c["tx_valid_pass"]:
    errs.append("tx_valid")
if r["tx_invalid"]["pass"] != c["tx_invalid_pass"]:
    errs.append("tx_invalid")
if r["sighash"]["exact_match"] != c["sighash_pass"]:
    errs.append("sighash")
if r["divergences"] != c["divergences"]:
    errs.append("divergences")
if r["decided"] != c["decided"] or r["charter_r1_total_vectors"] != c["charter_vector_count"]:
    errs.append("charter totals")
script_txt = (proof / "r1/script.txt").read_text()
if "1222 passed, 0 failed" not in script_txt:
    errs.append("script.txt missing 1222 passed, 0 failed")
if "PASSED : 500" not in (proof / "r1/sighash.txt").read_text():
    errs.append("sighash.txt missing PASSED : 500")
tx = (proof / "r1/tx.txt").read_text()
if "121/121" not in tx:
    errs.append("tx.txt missing 121/121")
if "93/93" not in tx:
    errs.append("tx.txt missing 93/93")
if errs:
    print("FAIL: R1:", ", ".join(errs))
    sys.exit(1)
print(f"R1: script {c['script_pass']}/1222 tx {c['tx_valid_pass']}+{c['tx_invalid_pass']} sighash {c['sighash_pass']}/500 divergences={c['divergences']}")
PY

# 5. R2 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r2"]
r = json.loads((proof / "r2/results.json").read_text())
errs = []
if r["pass"] != c["pass"] or r["fail"] != c["fail"]:
    errs.append("pass/fail")
if r["err"] != c["err"]:
    errs.append("err")
if r["consensus_splits_accept_vs_reject"] != c["consensus_splits_accept_vs_reject"]:
    errs.append("splits")
if any(not f["same_accept_reject"] for f in r["fails"]):
    errs.append("a listed FAIL is accept-vs-reject — that would be a consensus split")
if len(r["fails"]) != c["fail"]:
    errs.append("fails list length")
excerpt = (proof / "r2/nightly-report-excerpt.txt").read_text()
if "ouroboros       347     23" not in excerpt:
    errs.append("excerpt missing ouroboros 347/23")
failx = (proof / "r2/fail-excerpt.txt").read_text()
if "CONSENSUS SPLITS (accept vs reject): 0" not in failx:
    errs.append("fail excerpt missing splits=0")
if "same_accept_reject: true" not in failx:
    errs.append("fail excerpt missing same_accept_reject")
if errs:
    print("FAIL: R2:", ", ".join(errs))
    sys.exit(1)
print(f"R2: {c['pass']} PASS / {c['fail']} FAIL, consensus splits={c['consensus_splits_accept_vs_reject']}")
PY

# 6. R5 scorecards
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r5"]
live = json.loads((proof / "r5/live-20260901T182642Z.json").read_text())["impls"]["ouroboros"]
sc = json.loads((proof / "r5/scorecard.json").read_text())
errs = []
if live["tiers"]["T1"]["pass"] != c["live_t1_pass"] or live["tiers"]["T1"]["total"] != c["live_t1_total"]:
    errs.append("live T1")
if live["tiers"]["T2"]["pass"] != c["live_t2_pass"] or live["tiers"]["T2"]["total"] != c["live_t2_total"]:
    errs.append("live T2")
t1_fails = sorted(r["method"] for r in live["rows"] if r["tier"] == "T1" and r["status"] == "FAIL")
if t1_fails != sorted(c["live_t1_fail_methods"]):
    errs.append(f"live T1 FAIL set {t1_fails!r}")
if sc["live"]["T1"]["pass"] != c["live_t1_pass"] or sc["live"]["T2"]["pass"] != c["live_t2_pass"]:
    errs.append("scorecard live T1/T2")
if sc["live"]["fails_t1"] != c["live_t1_fail_methods"]:
    errs.append("scorecard T1 fail methods")
if c["regtest_t3_status"] != "UNPROVEN":
    errs.append("T3 must be UNPROVEN in this bundle")
if sc["regtest"]["T3"].get("status") != "UNPROVEN":
    errs.append("scorecard T3 is not UNPROVEN")
if sc["regtest"].get("artifact") not in (None, ""):
    errs.append("scorecard claims a regtest artifact this bundle does not have")
after = (proof / "r5/t2-after.txt").read_text()
if "41 passed" not in after:
    errs.append("t2-after.txt is not a 41-passed run")
if "14 passed" not in after:
    errs.append("t2-after.txt missing the assumevalid 14-passed run")
if errs:
    print("FAIL: R5:", "; ".join(errs))
    sys.exit(1)
print(f"R5 live T1 {c['live_t1_pass']}/{c['live_t1_total']} T2 {c['live_t2_pass']}/{c['live_t2_total']} T3 {c['regtest_t3_status']}")
PY

# 7. README cites every claims.json file
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
readme = (proof / "README.md").read_text()
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if f not in readme:
            missing.append(f)
if missing:
    print("FAIL: README.md does not cite:", ", ".join(missing))
    sys.exit(1)
print("README: every claims.json file is cited")
PY

# 8. provenance: interpreted, pin is stale, so recorded
want_so="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("proof/claims.json").read_text())["provenance"]["installed_sync_so_sha256"])')"
if python3 -c 'import sync' >/dev/null 2>&1; then
  got_so="$(python3 -c 'import pathlib, sync; print(__import__("hashlib").sha256(next(pathlib.Path(sync.__file__).parent.glob("*.so")).read_bytes()).hexdigest())')"
  if [ "$got_so" != "$want_so" ]; then
    say "NOTE: installed sync.so sha256=$got_so (bundle records $want_so). maturin rebuilds are not bit-stable; the attested artifact is runnable-tree.sha256."
  else
    say "provenance: installed sync.so sha256=$want_so"
  fi
else
  say "NOTE: sync extension not importable; skipped .so sha256 check. Bundle records $want_so."
fi
if ! grep -q "$want_so" "$PROOF/provenance.txt"; then
  die "provenance.txt does not contain the claimed installed sync.so sha256"
else
  say "provenance.txt records claimed sync.so sha256"
fi
if grep -qiE 'promote_does_not_apply: yes' "$PROOF/provenance.txt"; then
  say "provenance: interpreted (promote does not apply)"
else
  die "provenance.txt must say promote_does_not_apply: yes"
fi
if ! grep -qiE 'deploy_pin_stale: yes' "$PROOF/provenance.txt"; then
  die "provenance.txt must say deploy_pin_stale: yes"
else
  say "provenance: deploy pin recorded as STALE (not pin-closure)"
fi

# 9. runnable-tree: the attested source (interpreted "binary")
need "runnable-tree.sha256"
if (cd "$ROOT" && sha256sum -c "$PROOF/runnable-tree.sha256" --quiet); then
  say "runnable-tree.sha256: OK ($(wc -l < "$PROOF/runnable-tree.sha256") files)"
else
  die "runnable-tree.sha256 mismatch — production source is not the attested tree"
fi

# 10. in-repo T2 parity + assumevalid submitblock control
if command -v python3 >/dev/null 2>&1; then
  say "== re-run: pytest test_t2_r5_parity + test_assumevalid_submitblock_path =="
  if python3 -m pytest -q tests/test_t2_r5_parity.py tests/test_assumevalid_submitblock_path.py --tb=line; then
    say "R5/R4 in-repo: test_t2_r5_parity + test_assumevalid_submitblock_path PASS"
  else
    die "in-repo pytest (t2_r5_parity + assumevalid_submitblock_path) failed"
  fi
else
  say "NOTE: python3 not on PATH; skipped in-repo re-run."
  say "      The recorded after-control is r5/t2-after.txt (41 + 14 passed)."
fi

# 11. MANIFEST (all files except MANIFEST itself)
if [ -f "$PROOF/MANIFEST.sha256" ]; then
  if (cd "$PROOF" && sha256sum -c MANIFEST.sha256 --quiet); then
    say "MANIFEST.sha256: OK"
  else
    die "MANIFEST.sha256 mismatch"
  fi
else
  die "MANIFEST.sha256 missing — run bash proof/assemble.sh"
fi

if [ "$fail" -ne 0 ]; then
  say "== FAIL =="
  exit 1
fi
say "== PASS: every claim cites a file in this bundle and the numbers match =="
exit 0
