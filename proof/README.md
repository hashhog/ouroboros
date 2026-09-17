# ouroboros proof bundle

A skeptical Bitcoin engineer should be able to check this node without
trusting a narrative. This directory is that check: every claim below
names a file in this directory, and `bash proof/verify.sh` re-checks
those files (and re-runs the in-repo controls).

It claims **only what the included files show.**

## How to check

From the ouroboros repository root:

```
bash proof/verify.sh
```

That is the control. It exits 0 only if every claim in `claims.json`
matches a file here, R4 stays UNPROVEN (no C(H) capture, snapshot-booted
ranges refused, genesis-IBD did not reach 958794), the production source
tree matches `runnable-tree.sha256`, and the in-repo T2 + assumevalid
submitblock tests are green.

Re-running the heavy instruments (from-genesis IBD, full R2 corpus, live
R5 probe) needs the commands in `r4/command.txt`, `r1/command.txt`,
`r2/command.txt`, `r5/command.txt`. Those take days / hours / a running
node. The files here are the captured results of those commands.

## What each file proves

### Provenance — `provenance.txt` and `runnable-tree.sha256`

ouroboros is interpreted Python plus a native Rust extension.
`promote_mainnet.sh` refuses this node. `start_mainnet.sh` runs
`python3 -m ouroboros.cli` from this working directory after
`tools/reinstall_ouroboros.sh` rebuilds the `sync` wheel from source.
The attested artifact is therefore:

- the production source tree hashed in `runnable-tree.sha256` (every
  `src/ouroboros/**/*.py` except tests, `src/ouroboros/data/*`, the
  ferrous-utils Rust sources, `pyproject.toml`, `setup.sh`, `Cargo.toml`,
  `Cargo.lock`)
- the currently installed `sync` `.so` recorded in `provenance.txt`

`verify.sh` re-hashes the source tree. A one-byte edit of a production
file fails the bundle.

A `deploy/ouroboros/MANIFEST` wheel exists
(`52039f392abc8a1555d52c94041aef71c9233e276d47152e56980df2b73c302c`) and
is **not** what would run: `reinstall_ouroboros.sh` rebuilds from this
tree on every start. `provenance.txt` records `deploy_pin_stale: yes`.
That is the opposite of nimrod's pin-closure, stated so it cannot be
skimmed as the same thing.

**Does not prove** a live PID matches these bytes today: the mainnet unit
has been maintenance-paused since 2026-09-10.

### R4 from-genesis lineage — `r4/` — UNPROVEN

TRUST-ANCHOR rule, applied without weakening: a reproduction of C(H)
counts only if the chainstate at H descends from a genesis→H validation
with scripts on (`assumevalid=0`) executed by this node's own validation
code. **Snapshot-booted lineages do not count.**

This node has no such capture. `r4/status.json` says `UNPROVEN`.
`r4/no-c958794.txt` says there is no `r4/C958794.json`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r4/status.json` | The claim: R4 is UNPROVEN. `snapshot_booted_does_not_count=true`, `range_counts_as_r4=false`, genesis-IBD stopped at 580755, no C(H). | A C(H) hash. There isn't one. |
| `r4/no-c958794.txt` | There is no ouroboros row in the C(958794) table and no av0-danger-ledger. `verify.sh` fails if `r4/C958794.json` appears. | That a from-genesis run is impossible. A unit exists; it did not finish. |
| `r4/command.txt` | What a real R4 receipt would take. | That anyone has a C(H) on this tree. |
| `r4/genesis-unit.service` | The launch command: `--noassumevalid`, `--connect=127.0.0.1:28620` (capped blk-replay), datadir `/home/work/genesis-ibd/ouroboros`, no loadtxoutset. | That a stranger can re-run it without that datadir and the capped feeder. |
| `r4/lineage-excerpt.txt` | The load-bearing lines: `Genesis block stored`, `current height: 0`, `-assumevalid=0`, `loadtxoutset matches=0`, last height 580755, Bitcoin genesis hash `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`. The `[snapshot] Seeded presync prev_bits` line is an nBits seed at height 0, not a UTXO snapshot boot. | Completeness — the 284 MiB gzip is not in this bundle. Blocks after 580755. A `hash_serialized_3`. |
| `r4/range-coverage.txt` and `r4/range-rows.json` | Snapshot-booted ladder coverage: 25 CLOSED / 512,594 blocks (53.04%), plus STALLED 481807→515000, STALLED 515000→550000, NO-ORACLE-SURFACE 852000→875000, NO-ORACLE-SURFACE 875000→900000. Both files say `counts_as_r4=false`. Every row is `scripts_ack=p2p-only`. | From-genesis UTXO-hash identity with Core. These boots start from a Core-format snapshot. |

### R1 interpreter — `r1/`

Core's script/tx/sighash vectors through ouroboros' own
`ScriptInterpreter.verify` / CheckTransaction / legacy SignatureHash
(Python; the phaseb shim drives the same interpreter).

| file | what it proves | what it does not prove |
|---|---|---|
| `r1/results.json` | script 1222/1222, tx_valid 121/121, tx_invalid 93/93, sighash 500/500, 0 divergences. CHARTER 1,936 vectors, 1,936 decided. | Reason-string parity with Core. The native Rust interpreter (`ferrous-utils/sync`) is a separate path; these numbers are the Python interpreter. |
| `r1/script.txt`, `r1/tx.txt`, `r1/sighash.txt` | The raw harness summaries that `r1/results.json` was taken from. script: in-repo `python3 tests/test_script_vectors.py`. tx: phaseb shim `--txvectors`. sighash: Core `sighash.json` via `_calculate_signature_hash`. | A stranger's re-run of the phaseb tx arm — that needs the meta-repo shim; see `r1/command.txt`. |

### R2 validator — `r2/`

Adversarial corpus, accept/reject vs live `bitcoind`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r2/results.json` | 347 PASS / 23 FAIL / 0 ERR of the nightly 370-entry sweep (93.8%). All 23 FAILs are same-decision (`consensus_splits_accept_vs_reject: 0`). | Error-code / reject-token identity with Core. Eleven of the FAILs are mempool/txindex shape on an accepted block, not a block-decision split. |
| `r2/nightly-report-excerpt.txt` | The nightly table those numbers were copied from (`ouroboros       347     23`). | A clean classifier: the 10-impl report has an accounting gap on split counts; the 23 ouroboros FAIL logs were read directly. |
| `r2/fail-excerpt.txt` | The 23 FAIL entries, each `same_accept_reject: true`. | A live re-sweep. That is `r2/command.txt`. |

### R5 operator RPC — `r5/`

| file | what it proves | what it does not prove |
|---|---|---|
| `r5/live-20260901T182642Z.json` | Live lane 2026-09-01T18:26Z: T1 38/46, T2 14/41. Seven T1 FAILs (`addnode`, `disconnectnode`, `getblocktemplate`, `getnettotals`, `getrpcinfo`, `sendrawtransaction`, `testmempoolaccept`). T3 is SKIP-REGTEST on this lane. | The pin running that probe is this commit. It is not. The mainnet unit has been paused since 2026-09-10; later probes are connection-refused. |
| `r5/t2-after.txt` | In-repo T2 parity `tests/test_t2_r5_parity.py`: 41 passed / 0 failed, plus `tests/test_assumevalid_submitblock_path.py`: 14 passed. Re-run live by `verify.sh`. | A live `r5_probe.py` going green. That needs the unit started, which this run does not do. |
| `r5/scorecard.json` | The numbers above in one place, each pointing at the artifact. T3 marked UNPROVEN (no regtest-lane artifact in this bundle). | Anything not in those artifacts. |
| `r5/command.txt` | How to re-run the live and regtest lanes. | That those lanes were re-run for this commit. |

## What is NOT proven here

- **R4 from-genesis C(H).** UNPROVEN. Named blocker: no genesis→H
  `hash_serialized_3` capture; the genesis-IBD log stops at ~580755;
  snapshot-booted range-runner CLOSED rows are not a substitute.
- **Tip parity is not consensus evidence.** Even when the live node
  matches Core's tip it proves serialization, PoW, headers-first sync
  and UTXO bookkeeping on the assumevalid-skipped prefix. R1/R2/R4
  are the consensus proof, and R4 is missing.
- **Blocks after 580,755** have no from-genesis UTXO-hash capture.
- **T3 wallet.** UNPROVEN. Live lane SKIP-REGTEST; no regtest artifact
  in this bundle.
- **That a live PID is running these bytes.** The unit is paused.
- **That the deploy/ouroboros wheel is the running binary.** It is not;
  the pin is stale.
- **Fund custody.** Do not send money to this node. See `SECURITY.md`.

## TRUST-ANCHOR, applied

A snapshot-booted range (`range-runner.sh` CLOSED rows in
`r4/range-rows.json`) is **not** R4 evidence. Those boots start from a
Core-format UTXO snapshot; counting them as from-genesis would be
circular. This bundle includes them so the coverage holes are visible
and so `verify.sh` can fail if anyone later flips `range_counts_as_r4`
to true without a lineage log.
