"""1-vs-N script-pool identity over the diff-test corpus (QUEUES.md 2026-09-19).

Gap 1: decision identity was tested on OP_TRUE/OP_FALSE only. This control
extracts ConnectBlock-shaped VerifyScript jobs from every
``tools/diff-test-corpus/**/block.hex`` that has spendable prevouts in its
chain-context, drains them through ``sync.script_verify_parallel`` at 1, 2,
4 and 8 workers, and asserts the exact ``(ok, fail-index, reason)`` triple
is identical. A control that collects nothing fails: floors are asserted,
not hoped for.

Gap 2: ``--par`` is a no-op on the Python path. Native is still opt-in;
``docs/NATIVE-SCRIPT-DEFAULT.md`` names what it would take to flip the
default and what still blocks it (genesis-IBD provenance, operator-gated
restart, fail-closed wheel). This file locks those claims so they cannot
rot into a silent default-on.

Command:
  python3 -m pytest tests/test_parallel_corpus_identity.py -q --tb=short -s
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

from ouroboros.database import Block
from ouroboros.script import _native_tx_bytes
from tests._real_sync import real_sync_or_skip

_sync = real_sync_or_skip()

for _name in ("ScriptTx", "script_verify_parallel", "get_block_script_flags"):
    if not hasattr(_sync, _name):
        import pytest

        pytest.skip(
            f"sync extension missing {_name}; rebuild ferrous-utils/sync",
            allow_module_level=True,
        )


REPO = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("HASHHOG_ROOT", REPO.parent))
CORPUS = ROOT / "tools" / "diff-test-corpus"
NATIVE_DEFAULT_DOC = REPO / "docs" / "NATIVE-SCRIPT-DEFAULT.md"

# A control that collects nothing is not a control. These floors are the
# 2026-09-19 walk of the in-tree corpus (374 entries, 302 with jobs).
MIN_ENTRIES_WITH_JOBS = 200
MIN_JOBS = 400
MIN_REJECT_BATCHES = 50
MIN_DISTINCT_REASONS = 10


def _hex_bytes(text: str) -> bytes:
    return bytes.fromhex(text.strip().split()[0])


def _read_block_hex(path: Path) -> bytes:
    return _hex_bytes(path.read_text())


def _find_base_dir(entry: Path) -> Path | None:
    for parent in entry.parents:
        cand = parent / "_base"
        if cand.is_dir() and (cand / "blocks").is_dir():
            return cand
        if parent == CORPUS or parent == ROOT:
            break
    return None


def _load_base_raw(base_dir: Path, n: int) -> list[bytes]:
    out = []
    for i in range(1, n + 1):
        p = base_dir / "blocks" / f"{i}.hex"
        if not p.exists():
            raise FileNotFoundError(p)
        out.append(_read_block_hex(p))
    return out


def _apply_block(utxos: dict, raw: bytes) -> None:
    block = Block.deserialize(raw)
    for tx in block.transactions:
        if not tx.is_coinbase:
            for inp in tx.inputs:
                utxos.pop((bytes(inp.prev_txid), int(inp.prev_vout)), None)
        txid = bytes(tx.txid)
        for i, out in enumerate(tx.outputs):
            utxos[(txid, i)] = (int(out.value), bytes(out.script_pubkey))


_BASE_UTXO_CACHE: dict[tuple[str, int], dict] = {}


def _context_utxos(entry: Path) -> tuple[dict, int]:
    """UTXO set after applying chain-context, plus context block count."""
    ctx = entry / "chain-context.txt"
    utxos: dict = {}
    n_blocks = 0
    if not ctx.exists():
        return utxos, 0
    for raw_line in ctx.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("BASE_CHAIN_BLOCKS="):
            n = int(line.split("=", 1)[1])
            base = _find_base_dir(entry)
            if base is None:
                raise FileNotFoundError(f"BASE_CHAIN_BLOCKS={n} but no _base for {entry}")
            key = (str(base), n)
            cached = _BASE_UTXO_CACHE.get(key)
            if cached is None:
                cached = {}
                for raw in _load_base_raw(base, n):
                    _apply_block(cached, raw)
                _BASE_UTXO_CACHE[key] = cached
            utxos = dict(cached)
            n_blocks += n
            continue
        _apply_block(utxos, _hex_bytes(line))
        n_blocks += 1
    return utxos, n_blocks


def _jobs_from_candidate(utxos: dict, raw: bytes, flags: int) -> list:
    block = Block.deserialize(raw)
    jobs = []
    intra: dict = {}
    for tx in block.transactions:
        if tx.is_coinbase:
            txid = bytes(tx.txid)
            for i, out in enumerate(tx.outputs):
                intra[(txid, i)] = (int(out.value), bytes(out.script_pubkey))
            continue
        amts, spks = [], []
        complete = True
        for inp in tx.inputs:
            key = (bytes(inp.prev_txid), int(inp.prev_vout))
            coin = intra.get(key) or utxos.get(key)
            if coin is None:
                complete = False
                break
            amts.append(coin[0])
            spks.append(coin[1])
        if complete and amts:
            ctx = _sync.ScriptTx(_native_tx_bytes(tx), amts, spks)
            for i, inp in enumerate(tx.inputs):
                jobs.append(
                    (
                        ctx,
                        int(i),
                        bytes(inp.script_sig),
                        spks[i],
                        int(flags),
                        int(amts[i]),
                    )
                )
        for inp in tx.inputs:
            intra.pop((bytes(inp.prev_txid), int(inp.prev_vout)), None)
        txid = bytes(tx.txid)
        for i, out in enumerate(tx.outputs):
            intra[(txid, i)] = (int(out.value), bytes(out.script_pubkey))
    return jobs


def _iter_entries():
    if not CORPUS.is_dir():
        return
    for expected in CORPUS.rglob("expected.json"):
        entry = expected.parent
        if (entry / "block.hex").exists():
            yield entry


def _run(n: int, jobs):
    return _sync.script_verify_parallel(jobs, n)


class TestCorpusDecisionIdentity:
    def test_diff_test_corpus_1_vs_n_reasons_included(self):
        if not CORPUS.is_dir():
            import pytest

            pytest.skip(f"diff-test-corpus not present at {CORPUS}; set HASHHOG_ROOT")

        entries = list(_iter_entries())
        assert entries, f"corpus at {CORPUS} has no expected.json+block.hex entries"

        n_with_jobs = 0
        n_jobs = 0
        n_parse_fail = 0
        n_no_jobs = 0
        accept_batches = 0
        reject_batches = 0
        reasons: dict[str, int] = {}
        mismatches: list[str] = []
        all_jobs = []
        workers = (1, 2, 4, 8)

        for entry in entries:
            rel = str(entry.relative_to(CORPUS))
            try:
                utxos, n_ctx = _context_utxos(entry)
                cand = _read_block_hex(entry / "block.hex")
                flags = int(_sync.get_block_script_flags(max(n_ctx, 1), "regtest"))
                jobs = _jobs_from_candidate(utxos, cand, flags)
            except (ValueError, FileNotFoundError, OSError):
                n_parse_fail += 1
                continue
            if not jobs:
                n_no_jobs += 1
                continue
            n_with_jobs += 1
            n_jobs += len(jobs)
            all_jobs.extend(jobs)
            results = {n: _run(n, jobs) for n in workers}
            serial = results[1]
            for n in workers[1:]:
                if results[n] != serial:
                    mismatches.append(
                        f"{rel}: 1 worker {serial} vs {n} workers {results[n]} "
                        f"({len(jobs)} jobs)"
                    )
            if serial[0]:
                accept_batches += 1
            else:
                reject_batches += 1
                reasons[serial[2]] = reasons.get(serial[2], 0) + 1

        print(
            f"corpus 1-vs-N: {len(entries)} entries, {n_with_jobs} with script "
            f"jobs ({n_jobs} jobs), {accept_batches} accept, {reject_batches} "
            f"reject, {n_no_jobs} no-script, {n_parse_fail} unparseable"
        )
        print(f"reject reasons ({len(reasons)}): " + ", ".join(
            f"{k}={v}" for k, v in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        ))

        assert n_with_jobs >= MIN_ENTRIES_WITH_JOBS, (
            f"only {n_with_jobs} entries produced script jobs "
            f"(floor {MIN_ENTRIES_WITH_JOBS}); a control that collects "
            f"nothing is not a control"
        )
        assert n_jobs >= MIN_JOBS, f"only {n_jobs} jobs (floor {MIN_JOBS})"
        assert reject_batches >= MIN_REJECT_BATCHES, (
            f"only {reject_batches} rejecting batches "
            f"(floor {MIN_REJECT_BATCHES}); identity on accepts alone is weak"
        )
        assert len(reasons) >= MIN_DISTINCT_REASONS, (
            f"only {len(reasons)} distinct reject reasons {sorted(reasons)}; "
            f"floor {MIN_DISTINCT_REASONS}"
        )
        assert mismatches == [], "1-vs-N identity failed:\n  " + "\n  ".join(mismatches[:20])

        # One mixed drain over every extracted job: lowest-index fail must
        # still be independent of worker count (the chain-split surface).
        mega = {n: _run(n, all_jobs) for n in workers}
        print(f"mega-batch {len(all_jobs)} jobs: {mega}")
        assert mega[1] == mega[2] == mega[4] == mega[8], mega
        print("1 vs 2/4/8: 0 mismatches")


class TestNativeDefaultBlockers:
    def test_native_is_still_opt_in(self):
        src = (REPO / "src" / "ouroboros" / "script.py").read_text()
        assert '_env_truthy(os.environ.get(_NATIVE_SCRIPT_ENV, ""))' in src, (
            "native default flipped without updating docs/NATIVE-SCRIPT-DEFAULT.md "
            "and this control"
        )
        from ouroboros.script import NATIVE_SCRIPT_ENABLED

        # Pytest installs the stub before import; auto-enable must not have
        # silently turned native on against the stub.
        assert NATIVE_SCRIPT_ENABLED is False

    def test_par_help_names_native_requirement(self):
        import ouroboros.cli as cli_mod
        from ouroboros.cli import rewrite_core_par_flags

        src = inspect.getsource(cli_mod)
        assert "OUROBOROS_NATIVE_SCRIPT=1" in src
        assert "GIL" in src
        assert rewrite_core_par_flags(["start", "-par=4"]) == ["start", "--par", "4"]

    def test_doc_states_what_it_takes_and_what_blocks(self):
        assert NATIVE_DEFAULT_DOC.is_file(), NATIVE_DEFAULT_DOC
        text = NATIVE_DEFAULT_DOC.read_text()
        required = (
            "OUROBOROS_NATIVE_SCRIPT=0",
            "Genesis IBD",
            "GIL",
            "fail-closed",
            "Do not restart",
            "operator-gated",
            "test_parallel_corpus_identity.py",
            "_NATIVE_SCRIPT_REQUESTED",
        )
        missing = [s for s in required if s not in text]
        assert missing == [], f"NATIVE-SCRIPT-DEFAULT.md missing {missing}"
