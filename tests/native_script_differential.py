#!/usr/bin/env python3
"""Python-vs-native script interpreter differential.

Runs ouroboros's pure-Python ``ScriptInterpreter`` and the Rust port
(``sync.ScriptTx`` / ``script_verify`` / ``script_eval`` /
``script_sighash_legacy``, see ferrous-utils/sync/src/validate/interpreter.rs)
side by side and reports every disagreement:

  * Core script_tests.json — VerifyScript decision, AND the resulting stack
    after evaluating scriptSig and then scriptPubKey (EvalScript-level);
  * Core tx_valid.json / tx_invalid.json — per-input VerifyScript decision;
  * Core sighash.json — legacy SignatureHash bytes;
  * tools/phaseb-vectors/connecttx-vectors.json and checkblock-vectors.json
    — real mainnet transactions with real prevouts at block-connect flags;
  * any --corpus file in phaseb_vectors.py --dump-corpus format.

A disagreement is a FINDING. This harness does not decide which side is
right (Core is the oracle; the R1 reject-bar and the R2 corpus decide that);
it only proves the two interpreters make the same decision on the same
input, which is what lets the native path replace the Python one.

It also times the real-transaction sources on both sides (--bench-repeat)
so the speedup is measured on real inputs, not synthetic ones.

Run from the ouroboros repo root with OUROBOROS_NATIVE_SCRIPT unset (the
harness refuses otherwise — the Python side must be the pure oracle):

    .venv/bin/python3 tests/native_script_differential.py
    .venv/bin/python3 tests/native_script_differential.py --negative-control

The negative control inverts every native decision and asserts the harness
notices; run it whenever you change the harness.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ROOT = Path(os.environ.get("HASHHOG_ROOT", REPO.parent))
PHASEB = Path(os.environ.get("HASHHOG_PHASEB", ROOT / "tools" / "phaseb-vectors"))
CORE_DATA = Path(os.environ.get("HASHHOG_CORE_TESTDATA", ROOT / "bitcoin-core" / "src" / "test" / "data"))

for p in (str(REPO / "src"), str(PHASEB)):
    if p not in sys.path:
        sys.path.insert(0, p)

if os.environ.get("OUROBOROS_NATIVE_SCRIPT", "").strip():
    sys.exit("refusing to run with OUROBOROS_NATIVE_SCRIPT set: the Python side "
             "must be the pure oracle (its sighash would route to native)")

import ouroboros.script as oscript  # noqa: E402
from ouroboros.script import ScriptInterpreter  # noqa: E402
from ouroboros.database import Block  # noqa: E402
from ouroboros.p2p_messages import TxMessage  # noqa: E402

assert not oscript.NATIVE_SCRIPT_ENABLED
SYNC = oscript._native_sync_module()

import phaseb_vectors  # noqa: E402  (loaders: script_tests / tx_* / sighash)


def _load_shim():
    """The R1 arm's shim: reuse its credit/spend construction + flag map."""
    path = PHASEB / "ouroboros-shim" / "verifyscript_shim.py"
    spec = importlib.util.spec_from_file_location("ouroboros_verifyscript_shim", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SHIM = _load_shim()


class Findings:
    def __init__(self, show: int):
        self.rows: list[dict] = []
        self.show = show
        self.per_source: dict[str, dict] = {}

    def bump(self, source: str, key: str, n: int = 1):
        d = self.per_source.setdefault(source, {"cases": 0, "inputs": 0, "mismatch": 0,
                                                "py_accept": 0, "nat_accept": 0, "skipped": 0})
        d[key] += n

    def mismatch(self, source: str, **info):
        self.bump(source, "mismatch")
        self.rows.append({"source": source, **info})

    def report(self) -> int:
        print("\n=== Python-vs-native script differential ===")
        print(f"{'source':<26}{'cases':>8}{'inputs':>9}{'py_acc':>8}{'nat_acc':>8}{'skip':>6}{'MISMATCH':>10}")
        tot = 0
        for src, d in self.per_source.items():
            print(f"{src:<26}{d['cases']:>8}{d['inputs']:>9}{d['py_accept']:>8}{d['nat_accept']:>8}"
                  f"{d['skipped']:>6}{d['mismatch']:>10}")
            tot += d["mismatch"]
        print(f"TOTAL mismatches: {tot}")
        if self.rows:
            print(f"\n--- FINDINGS (showing up to {self.show}) ---")
            for r in self.rows[: self.show]:
                print("  " + json.dumps(r, default=str)[:400])
        return 1 if tot else 0


def _decisions(interp: ScriptInterpreter, script_sig, spk, tx, i, flags, amount, amts, spks):
    py = interp.verify_python(script_sig, spk, tx, i, flags=flags, amount=amount,
                              input_amounts=amts, input_script_pubkeys=spks)
    nat = interp.verify_native(script_sig, spk, tx, i, flags=flags, amount=amount,
                               input_amounts=amts, input_script_pubkeys=spks)
    return py, nat, interp.last_error


def _py_eval(interp, script, tx, script_code, flags, initial):
    try:
        return True, list(interp._execute_script(script, tx, 0, script_code, flags,
                                                 initial_stack=list(initial)))
    except Exception as e:  # noqa: BLE001 - Python side signals failure by raising
        return False, type(e).__name__


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def run_script_tests(f: Findings, limit, timing):
    src = "script_tests"
    cases = phaseb_vectors.load_script_tests(CORE_DATA / "script_tests.json")
    interp = ScriptInterpreter()
    n = 0
    for case in cases:
        if "assemble_error" in case:
            f.bump(src, "skipped")
            continue
        if not phaseb_vectors.flagfill_valid(set(case["flags"])):
            f.bump(src, "skipped")
            continue
        if limit and n >= limit:
            break
        n += 1
        f.bump(src, "cases")
        f.bump(src, "inputs")
        ssig = bytes.fromhex(case["scriptSig_hex"])
        spk = bytes.fromhex(case["scriptPubKey_hex"])
        amount = int(case["amount_sats"])
        witness = [bytes.fromhex(w) for w in case["witness"]]
        flags = SHIM.build_flags(case["flags"])
        credit = SHIM.build_crediting_tx(spk, amount)
        spend = SHIM.build_spending_tx(ssig, witness, credit)

        t0 = time.perf_counter()
        py = interp.verify_python(ssig, spk, spend, 0, flags=flags, amount=amount,
                                  input_amounts=[amount], input_script_pubkeys=[spk])
        t1 = time.perf_counter()
        nat = interp.verify_native(ssig, spk, spend, 0, flags=flags, amount=amount,
                                   input_amounts=[amount], input_script_pubkeys=[spk])
        t2 = time.perf_counter()
        timing["py"] += t1 - t0
        timing["nat"] += t2 - t1
        f.bump(src, "py_accept", int(py))
        f.bump(src, "nat_accept", int(nat))
        if py != nat:
            f.mismatch(src, idx=case["idx"], comment=case["comment"][:80], flags=case["flags"],
                       expected=case["expected_reason"], py=py, native=nat,
                       native_err=interp.last_error)

        # EvalScript-level stack differential (BASE): scriptSig, then
        # scriptPubKey on the resulting stack. The Python side hands
        # scriptPubKey as the scriptCode for the scriptSig run exactly the way
        # verify_python does, so this compares what the node actually runs.
        ctx = oscript.native_script_context(spend, [amount], [spk])
        py_ok, py_stack = _py_eval(interp, ssig, spend, spk, flags, [])
        nat_ok, _c, nat_err, nat_stack = SYNC.script_eval(ctx, 0, ssig, flags, 0, [], amount)
        if py_ok != nat_ok or (py_ok and py_stack != nat_stack):
            f.mismatch("script_tests:eval-ssig", idx=case["idx"], comment=case["comment"][:80],
                       flags=case["flags"], py_ok=py_ok, nat_ok=nat_ok, nat_err=nat_err,
                       py_stack=None if not py_ok else [s.hex() for s in py_stack],
                       nat_stack=[s.hex() for s in nat_stack])
            continue
        if py_ok:
            py_ok2, py_stack2 = _py_eval(interp, spk, spend, spk, flags, py_stack)
            nat_ok2, _c, nat_err2, nat_stack2 = SYNC.script_eval(ctx, 0, spk, flags, 0, nat_stack, amount)
            if py_ok2 != nat_ok2 or (py_ok2 and py_stack2 != nat_stack2):
                f.mismatch("script_tests:eval-spk", idx=case["idx"], comment=case["comment"][:80],
                           flags=case["flags"], py_ok=py_ok2, nat_ok=nat_ok2, nat_err=nat_err2,
                           py_stack=None if not py_ok2 else [s.hex() for s in py_stack2],
                           nat_stack=[s.hex() for s in nat_stack2])
    f.per_source.setdefault("script_tests:eval-ssig", {"cases": n, "inputs": n, "mismatch": 0,
                                                      "py_accept": 0, "nat_accept": 0, "skipped": 0})
    f.per_source.setdefault("script_tests:eval-spk", {"cases": n, "inputs": n, "mismatch": 0,
                                                     "py_accept": 0, "nat_accept": 0, "skipped": 0})
    f.per_source["script_tests:eval-ssig"]["cases"] = n
    f.per_source["script_tests:eval-spk"]["cases"] = n


def _run_tx_cases(f: Findings, src: str, cases: list[dict], limit, timing, flags_of):
    """Per-input differential over verifytx-shaped cases (tx_hex + prevouts)."""
    interp = ScriptInterpreter()
    n = 0
    for case in cases:
        if "assemble_error" in case or case.get("structural"):
            f.bump(src, "skipped")
            continue
        if limit and n >= limit:
            break
        try:
            tx = TxMessage.from_payload(bytes.fromhex(case["tx_hex"])).transaction
        except Exception:  # noqa: BLE001
            f.bump(src, "skipped")
            continue
        n += 1
        f.bump(src, "cases")
        flags = flags_of(case)
        spk_map, amt_map = {}, {}
        for p in case.get("prevouts") or []:
            key = (bytes.fromhex(p["txid"])[::-1], int(p["vout"]))
            spk_map[key] = bytes.fromhex(p["scriptPubKey_hex"])
            amt_map[key] = int(p.get("amount_sats", p.get("value_sats", 0)))
        spks, amts, ok = [], [], True
        for tx_in in tx.inputs:
            key = (bytes(tx_in.prev_txid), tx_in.prev_vout)
            if key not in spk_map:
                ok = False
                break
            spks.append(spk_map[key])
            amts.append(amt_map[key])
        if not ok:
            f.bump(src, "skipped")
            continue
        for i, tx_in in enumerate(tx.inputs):
            f.bump(src, "inputs")
            t0 = time.perf_counter()
            py = interp.verify_python(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                      input_amounts=amts, input_script_pubkeys=spks)
            t1 = time.perf_counter()
            nat = interp.verify_native(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                       input_amounts=amts, input_script_pubkeys=spks)
            t2 = time.perf_counter()
            timing["py"] += t1 - t0
            timing["nat"] += t2 - t1
            f.bump(src, "py_accept", int(py))
            f.bump(src, "nat_accept", int(nat))
            if py != nat:
                f.mismatch(src, idx=case.get("idx", case.get("txid")), input=i,
                           flags=case.get("flags"), py=py, native=nat, native_err=interp.last_error,
                           txid=tx.txid[::-1].hex())


def run_tx_vectors(f: Findings, limit, timing):
    for name, valid in (("tx_valid", True), ("tx_invalid", False)):
        cases = phaseb_vectors.load_tx_tests(CORE_DATA / f"{name}.json", valid)
        _run_tx_cases(f, name, cases, limit, timing, lambda c: SHIM.build_flags(c["flags"]))


def run_sighash(f: Findings, limit):
    src = "sighash"
    cases = phaseb_vectors.load_sighash_tests(CORE_DATA / "sighash.json")
    interp = ScriptInterpreter()
    n = 0
    for c in cases:
        if limit and n >= limit:
            break
        n += 1
        f.bump(src, "cases")
        f.bump(src, "inputs")
        tx = TxMessage.from_payload(bytes.fromhex(c["tx_hex"])).transaction
        script = bytes.fromhex(c["script_hex"])
        py = interp._calculate_signature_hash_python(tx, c["input_index"], script, c["hashtype"])
        nat = interp._calculate_signature_hash_native(tx, c["input_index"], script, c["hashtype"])
        f.bump(src, "py_accept", int(py[::-1].hex() == c["expected"]))
        f.bump(src, "nat_accept", int(nat[::-1].hex() == c["expected"]))
        if py != nat:
            f.mismatch(src, idx=c["idx"], nin=c["input_index"], hashtype=c["hashtype"],
                       py=py[::-1].hex(), native=nat[::-1].hex(), core=c["expected"])


def _block_flags(height: int, block_hash_display: str | None) -> int:
    h = bytes.fromhex(block_hash_display)[::-1] if block_hash_display else None
    return int(SYNC.get_block_script_flags(int(height), "mainnet", h))


def run_connecttx(f: Findings, limit, timing):
    path = PHASEB / "connecttx-vectors.json"
    if not path.exists():
        return
    cases = json.load(open(path))["cases"]
    for c in cases:
        c.setdefault("idx", c.get("txid"))
    _run_tx_cases(f, "connecttx-vectors", cases, limit, timing,
                  lambda c: _block_flags(int(c["spend_height"]), None))


def run_checkblock(f: Findings, limit, timing):
    """Real mainnet blocks from checkblock-vectors.json (accept-real cases)."""
    path = PHASEB / "checkblock-vectors.json"
    if not path.exists():
        return
    d = json.load(open(path))
    interp = ScriptInterpreter()
    seen = set()
    for case in d["cases"]:
        if not case.get("kind", "").startswith("accept-real"):
            continue
        if case["hash"] in seen:
            continue
        seen.add(case["hash"])
        src = f"block-{case['height']}"
        block = Block.deserialize(bytes.fromhex(case["block_hex"]))
        flags = _block_flags(int(case["height"]), case["hash"])
        spk_map, amt_map = {}, {}
        for p in d["prevout_sets"][case["prevout_set"]]:
            key = (bytes.fromhex(p["txid"])[::-1], int(p["vout"]))
            spk_map[key] = bytes.fromhex(p["scriptPubKey_hex"])
            amt_map[key] = int(p.get("value_sats", p.get("amount_sats", 0)))
        n = 0
        for tx in block.transactions:
            if tx.is_coinbase:
                continue
            if limit and n >= limit:
                break
            spks, amts, ok = [], [], True
            for tx_in in tx.inputs:
                key = (bytes(tx_in.prev_txid), tx_in.prev_vout)
                if key not in spk_map:
                    ok = False
                    break
                spks.append(spk_map[key])
                amts.append(amt_map[key])
            # this tx's outputs may be spent later in the same block
            for vout, out in enumerate(tx.outputs):
                spk_map[(bytes(tx.txid), vout)] = bytes(out.script_pubkey)
                amt_map[(bytes(tx.txid), vout)] = int(out.value)
            if not ok:
                f.bump(src, "skipped")
                continue
            n += 1
            f.bump(src, "cases")
            for i, tx_in in enumerate(tx.inputs):
                f.bump(src, "inputs")
                t0 = time.perf_counter()
                py = interp.verify_python(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                          input_amounts=amts, input_script_pubkeys=spks)
                t1 = time.perf_counter()
                nat = interp.verify_native(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                           input_amounts=amts, input_script_pubkeys=spks)
                t2 = time.perf_counter()
                timing["py"] += t1 - t0
                timing["nat"] += t2 - t1
                f.bump(src, "py_accept", int(py))
                f.bump(src, "nat_accept", int(nat))
                if py != nat:
                    f.mismatch(src, txid=tx.txid[::-1].hex(), input=i, flags=flags, py=py, native=nat,
                               native_err=interp.last_error)


PACK_CACHE = Path(os.environ.get("HASHHOG_PACK_CACHE",
                                 ROOT / "tools" / "diff-test-artifacts" / "stateless-replay-cache"))


def run_packs(f: Findings, heights: list[int], timing, tx_limit: int = 0):
    """Real mainnet blocks from the stateless-replay pack cache (raw block +
    every spent prevout), verified input by input on both interpreters at
    that height's block-connect flags."""
    interp = ScriptInterpreter()
    for h in heights:
        path = PACK_CACHE / f"{h:07d}.json"
        if not path.exists():
            f.bump(f"pack-{h}", "skipped")
            continue
        pack = json.load(open(path))
        src = f"pack-{h}"
        block = Block.deserialize(bytes.fromhex(pack["raw_hex"]))
        flags = _block_flags(int(pack["height"]), pack["hash"])
        spk_map, amt_map = {}, {}
        for key, v in pack["prevouts"].items():
            txid_disp, vout = key.split(":")
            k = (bytes.fromhex(txid_disp)[::-1], int(vout))
            spk_map[k] = bytes.fromhex(v["script_hex"])
            amt_map[k] = int(v["value_sats"])
        n = 0
        for tx in block.transactions:
            if tx.is_coinbase:
                continue
            if tx_limit and n >= tx_limit:
                break
            spks, amts, ok = [], [], True
            for tx_in in tx.inputs:
                k = (bytes(tx_in.prev_txid), tx_in.prev_vout)
                if k not in spk_map:
                    ok = False
                    break
                spks.append(spk_map[k])
                amts.append(amt_map[k])
            for vout, out in enumerate(tx.outputs):
                spk_map[(bytes(tx.txid), vout)] = bytes(out.script_pubkey)
                amt_map[(bytes(tx.txid), vout)] = int(out.value)
            if not ok:
                f.bump(src, "skipped")
                continue
            n += 1
            f.bump(src, "cases")
            for i, tx_in in enumerate(tx.inputs):
                f.bump(src, "inputs")
                t0 = time.perf_counter()
                py = interp.verify_python(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                          input_amounts=amts, input_script_pubkeys=spks)
                t1 = time.perf_counter()
                nat = interp.verify_native(tx_in.script_sig, spks[i], tx, i, flags=flags, amount=amts[i],
                                           input_amounts=amts, input_script_pubkeys=spks)
                t2 = time.perf_counter()
                timing["py"] += t1 - t0
                timing["nat"] += t2 - t1
                f.bump(src, "py_accept", int(py))
                f.bump(src, "nat_accept", int(nat))
                if py != nat:
                    f.mismatch(src, txid=tx.txid[::-1].hex(), input=i, flags=flags, py=py, native=nat,
                               native_err=interp.last_error)


def run_corpus(f: Findings, path: Path, limit, timing):
    d = json.load(open(path))
    cases = d["cases"] if isinstance(d, dict) else d
    for i, c in enumerate(cases):
        c.setdefault("idx", c.get("txid", i))
    _run_tx_cases(f, f"corpus:{path.name}"[:26], cases, limit, timing,
                  lambda c: SHIM.build_flags(c["flags"]) if isinstance(c.get("flags"), list)
                  else int(c["flags"]))


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=0, help="max cases per source (0 = all)")
    ap.add_argument("--corpus", action="append", default=[],
                    help="extra verifytx corpus JSON (phaseb --dump-corpus format); repeatable")
    ap.add_argument("--only", default=None,
                    help="comma list of sources: script_tests,tx,sighash,connecttx,checkblock,corpus")
    ap.add_argument("--bench-repeat", type=int, default=1,
                    help="repeat the real-transaction sources N times for timing")
    ap.add_argument("--show", type=int, default=50, help="findings to print")
    ap.add_argument("--packs", default="",
                    help="comma list of mainnet heights from the stateless-replay pack cache "
                         "(real blocks + prevouts); verified input by input on both sides")
    ap.add_argument("--pack-tx-limit", type=int, default=0, help="max txs per pack (0 = all)")
    ap.add_argument("--negative-control", action="store_true",
                    help="invert every native decision and require the harness to notice")
    args = ap.parse_args()
    only = set(args.only.split(",")) if args.only else None

    def want(name):
        return only is None or name in only

    if args.negative_control:
        orig = ScriptInterpreter.verify_native

        def inverted(self, *a, **k):
            return not orig(self, *a, **k)

        ScriptInterpreter.verify_native = inverted
        print("NEGATIVE CONTROL: every native decision inverted")

    f = Findings(args.show)
    timing_vec = {"py": 0.0, "nat": 0.0}
    timing_real = {"py": 0.0, "nat": 0.0}

    t_start = time.time()
    if want("script_tests"):
        run_script_tests(f, args.limit, timing_vec)
    if want("tx"):
        run_tx_vectors(f, args.limit, timing_vec)
    if want("sighash"):
        run_sighash(f, args.limit)
    for rep in range(max(1, args.bench_repeat)):
        if want("connecttx"):
            run_connecttx(f, args.limit, timing_real)
        if want("checkblock"):
            run_checkblock(f, args.limit, timing_real)
        if want("corpus"):
            for c in args.corpus:
                run_corpus(f, Path(c), args.limit, timing_real)
        if args.packs and want("packs"):
            run_packs(f, [int(h) for h in args.packs.split(",") if h], timing_real, args.pack_tx_limit)
        if rep == 0 and args.bench_repeat > 1:
            # keep the per-source counts honest: they count one pass only
            snapshot = {k: dict(v) for k, v in f.per_source.items()}
    if args.bench_repeat > 1:
        for k, v in snapshot.items():
            m = f.per_source[k]["mismatch"]
            f.per_source[k] = v
            f.per_source[k]["mismatch"] = m

    rc = f.report()
    real_inputs = sum(v["inputs"] for k, v in f.per_source.items()
                      if k.startswith(("block-", "connecttx", "corpus:", "pack-")))
    print(f"\nwall: {time.time() - t_start:.1f}s")
    if timing_vec["py"]:
        print(f"vectors  : python {timing_vec['py']:.2f}s  native {timing_vec['nat']:.2f}s  "
              f"speedup x{timing_vec['py'] / max(timing_vec['nat'], 1e-9):.1f}")
    if timing_real["py"] and real_inputs:
        reps = max(1, args.bench_repeat)
        py_rate = real_inputs * reps / timing_real["py"]
        nat_rate = real_inputs * reps / timing_real["nat"]
        print(f"real txs : {real_inputs} inputs x{reps}  python {timing_real['py']:.2f}s "
              f"({py_rate:,.0f} inputs/s)  native {timing_real['nat']:.2f}s ({nat_rate:,.0f} inputs/s)  "
              f"speedup x{timing_real['py'] / max(timing_real['nat'], 1e-9):.1f}")

    if args.negative_control:
        total = sum(v["mismatch"] for v in f.per_source.values())
        if total:
            print(f"NEGATIVE CONTROL OK: instrument saw {total} injected mismatches")
            return 0
        print("NEGATIVE CONTROL FAILED: instrument is blind")
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
