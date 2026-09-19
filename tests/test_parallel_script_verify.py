"""Parallel script verification controls (QUEUES.md ouroboros item 0, 2026-09-19).

REQUIRED:
1. Decision identity — accept/reject AND reject reason identical at 1 worker
   and at N.
2. Failure propagation — one failing check in one worker rejects the whole
   batch with the same reason as the serial path.
3. Measured scaling — blk/h at 1, 2, 4, 8 workers on a post-segwit-shaped
   batch with thousands of inputs, reported as numbers.
4. Bounded RSS — more workers must not mean unbounded buffers (batch=128,
   work vector is borrowed, extra RSS is O(threads) not O(threads × inputs)).

Worker count must not change validity. `--par=1` is serial.

The Python interpreter holds the GIL and cannot parallelise; this control
exercises the native Rust interpreter (`sync.script_verify_parallel`).
``tests/conftest.py`` stubs ``sync``, so we load the real extension via
``tests/_real_sync.py``.

Command:
  python3 -m pytest tests/test_parallel_script_verify.py -q --tb=short
"""

from __future__ import annotations

import inspect
import time
from pathlib import Path

from ouroboros.cli import rewrite_core_par_flags
from ouroboros.validation import (
    init_script_check_threads,
    resolve_script_check_threads,
    script_check_threads,
)
from tests._real_sync import real_sync_installed, real_sync_or_skip

_sync = real_sync_or_skip()

for _name in (
    "ScriptTx",
    "script_verify_parallel",
    "resolve_script_check_threads",
    "script_check_batch_size",
    "max_scriptcheck_threads",
    "default_scriptcheck_threads",
):
    if not hasattr(_sync, _name):
        import pytest
        pytest.skip(
            f"sync extension missing {_name}; rebuild ferrous-utils/sync",
            allow_module_level=True,
        )


REPO = Path(__file__).resolve().parents[1]
CHECKQUEUE_RS = REPO / "ferrous-utils" / "sync" / "src" / "validate" / "checkqueue.rs"


def _dummy_tx_bytes() -> bytes:
    """One-input extended-transport tx for ScriptTx."""
    out = bytearray()
    out += (2).to_bytes(4, "little")
    out += b"\x00\x01"
    out += b"\x01"  # 1 input
    out += b"\x00" * 32
    out += (0xFFFFFFFF).to_bytes(4, "little")
    out += b"\x00"  # empty scriptSig
    out += (0xFFFFFFFF).to_bytes(4, "little")
    out += b"\x01"  # 1 output
    out += (900).to_bytes(8, "little")
    out += b"\x01\x51"  # OP_TRUE
    out += b"\x00"  # empty witness
    out += (0).to_bytes(4, "little")
    return bytes(out)


def _ctx():
    return _sync.ScriptTx(_dummy_tx_bytes(), None, None)


def op_true() -> bytes:
    return b"\x51"


def op_false() -> bytes:
    return b"\x00"


def hash_heavy_script(rounds: int) -> bytes:
    """scriptPubKey valid with empty scriptSig: N × PUSH32/SHA256/DROP + OP_TRUE.

    PUSH does not count toward MAX_OPS_PER_SCRIPT (201); SHA256+DROP do, so
    cap rounds at 96.
    """
    s = bytearray()
    for _ in range(rounds):
        s.append(0x20)
        s.extend(b"\xAB" * 32)
        s.append(0xA8)  # OP_SHA256
        s.append(0x75)  # OP_DROP
    s.append(0x51)
    return bytes(s)


def mk_jobs(spks: list[bytes]):
    ctx = _ctx()
    return [(ctx, 0, b"", spk, 0, 1000) for spk in spks]


def run_n(n: int, jobs):
    with real_sync_installed(_sync):
        return _sync.script_verify_parallel(jobs, n)


def rss_kb() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return 0
    return 0


class TestParResolveMatchesCore:
    def test_constants_and_mapping(self):
        assert _sync.default_scriptcheck_threads() == 0
        assert _sync.max_scriptcheck_threads() == 15
        assert _sync.script_check_batch_size() == 128

        with real_sync_installed(_sync):
            assert resolve_script_check_threads(1) == 1
            assert resolve_script_check_threads(4) == 4
            assert resolve_script_check_threads(16) == 16
            assert resolve_script_check_threads(100) == _sync.max_scriptcheck_threads() + 1

            auto = resolve_script_check_threads(0)
            assert 1 <= auto <= _sync.max_scriptcheck_threads() + 1
            leave_one = resolve_script_check_threads(-1)
            assert 1 <= leave_one <= _sync.max_scriptcheck_threads() + 1
            assert leave_one <= auto

            n = init_script_check_threads(1)
            assert n == 1
            assert script_check_threads() == 1
            init_script_check_threads(0)

    def test_cli_exposes_par_and_rewrites_core_single_dash(self):
        import ouroboros.cli as cli_mod

        src = inspect.getsource(cli_mod)
        assert "--par" in src
        assert "rewrite_core_par_flags" in src
        assert rewrite_core_par_flags(["start", "-par=4"]) == ["start", "--par", "4"]
        assert rewrite_core_par_flags(["start", "-par", "1"]) == ["start", "--par", "1"]
        assert rewrite_core_par_flags(["start", "--par=8"]) == ["start", "--par", "8"]


class TestDecisionIdentity:
    def test_decision_identity_1_vs_n_accept(self):
        jobs = mk_jobs([op_true()] * 64)
        one = run_n(1, jobs)
        eight = run_n(8, jobs)
        assert one[0] is True, f"serial must accept OP_TRUE: {one}"
        assert one == eight, f"1 vs 8 workers: {one} vs {eight}"

    def test_decision_identity_and_failure_propagation_1_vs_n(self):
        spks = [op_true()] * 64
        spks[37] = op_false()
        jobs = mk_jobs(spks)
        serial = run_n(1, jobs)
        assert serial[0] is False, f"serial must reject injected OP_FALSE, got {serial}"
        assert serial[1] == 37, f"fail index must be 37, got {serial}"
        assert serial[2] == "SCRIPT_ERR_EVAL_FALSE", serial
        for n in (2, 4, 8):
            parallel = run_n(n, jobs)
            assert serial == parallel, (
                f"failure at 1 worker must equal {n} workers; "
                f"serial={serial} n={n} got={parallel}"
            )


class TestMeasuredScaling:
    def test_measured_scaling_1_2_4_8(self):
        inputs = 2048
        rounds = 16
        jobs = mk_jobs([hash_heavy_script(rounds)] * inputs)

        while True:
            t0 = time.perf_counter()
            ok, idx, name = run_n(1, jobs)
            ms = (time.perf_counter() - t0) * 1000.0
            assert ok, f"hash-heavy OP_TRUE must verify: {idx} {name}"
            if ms >= 150.0 or rounds >= 96:
                print(
                    f"scaling warmup: 1 worker {ms:.1f} ms at {rounds} "
                    f"SHA256 rounds, {inputs} inputs"
                )
                break
            rounds *= 2
            if rounds > 96:
                rounds = 96
            jobs = mk_jobs([hash_heavy_script(rounds)] * inputs)

        print(f"measured scaling ({inputs} inputs, {rounds} SHA256 rounds/input):")
        times_ms: list[float] = []
        for n in (1, 2, 4, 8):
            best = 60.0
            for _ in range(2):
                t0 = time.perf_counter()
                ok, idx, name = run_n(n, jobs)
                assert ok, f"n={n}: {idx} {name}"
                best = min(best, time.perf_counter() - t0)
            secs = max(best, 1e-9)
            blk_h = 3600.0 / secs
            times_ms.append(best * 1000.0)
            print(f"  {n:2d} workers: {blk_h:8.1f} blk/h  ({best * 1000.0:.1f} ms/block)")

        # Weak liveness bound, not a claimed speedup: 8 workers must not be a
        # serial-plus-disaster (more than 3× slower than 1).
        assert times_ms[3] < times_ms[0] * 3.0 + 50.0, (
            f"8-worker time {times_ms[3]:.1f} ms must not be 3× worse than "
            f"1-worker {times_ms[0]:.1f} ms"
        )


class TestBoundedRss:
    def test_bounded_rss_more_workers_not_unbounded_buffers(self):
        assert _sync.script_check_batch_size() == 128
        src = CHECKQUEUE_RS.read_text()
        assert "SCRIPT_CHECK_BATCH_SIZE" in src
        assert "claim_batch" in src
        # Work is claimed by index into the caller's slice — no per-worker
        # clone of the whole vector (the O(threads × inputs) failure mode).
        assert "checks[range]" in src

        jobs = mk_jobs([op_true()] * 4096)
        run_n(1, jobs)
        rss_after_1 = rss_kb()
        run_n(8, jobs)
        rss_after_8 = rss_kb()
        extra = max(rss_after_8 - rss_after_1, 0)
        print(
            f"bounded RSS: after 1 worker {rss_after_1} kB, after 8 workers "
            f"{rss_after_8} kB, extra {extra} kB"
        )
        # 64 MiB slack covers thread stacks + allocator jitter.
        assert extra < 64 * 1024, (
            f"8 workers added {extra} kB RSS over 1 worker "
            f"({rss_after_1} → {rss_after_8}); per-worker buffers must stay bounded"
        )


class TestGilHonesty:
    def test_python_interpreter_path_does_not_fake_a_pool(self):
        import ouroboros.validation as val_mod

        src = inspect.getsource(val_mod.TransactionValidator.run_script_check_queue)
        assert "GIL" in src
        assert "ThreadPoolExecutor" not in inspect.getsource(val_mod)
        # Native-only drain; Python stays serial.
        assert "script_verify_parallel" in src
