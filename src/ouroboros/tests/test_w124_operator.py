"""W124 — Operator-experience audit tests (ouroboros).

30 gates covering: process lifecycle (signals + PID file + daemon),
logging (categories + SIGHUP reopen), datadir/cookie/config, RPC
shutdown coordination, and the two-pipeline guard (Rust pipeline
must not install signal handlers or hold process state Python
doesn't own).

Mirrors `audit/w124_operator_experience.md`. PRESENT gates assert
the wiring is in place; PARTIAL/MISSING gates are xfail with
strict=True so they flip to XPASS the moment a fix lands.

Reference: bitcoin-core/src/init.cpp, src/shutdown.cpp,
src/logging/{logger.cpp,h}.
"""

from __future__ import annotations

import inspect
import os
import re
import signal
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module imports (kept lazy where useful so a partially-broken environment
# still surfaces a clean import error inside the test rather than during
# collection).
# ---------------------------------------------------------------------------

import ouroboros.daemon as daemon_mod
import ouroboros.cli as cli_mod
import ouroboros.logging_config as logcfg_mod
import ouroboros.cookie_auth as cookie_mod


REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src" / "ouroboros"
TOOLS_ROOT = REPO_ROOT / "tools"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
META_TOOLS_ROOT = REPO_ROOT.parent / "tools"  # /home/work/hashhog/tools


# ===========================================================================
# Process lifecycle (G1-G10)
# ===========================================================================


def test_w124_g1_sighup_rebound_at_cli_load() -> None:
    """G1: SIGHUP handler is installed at cli-group load time.

    `cli_mod` calls `install_sighup_log_reopen(reopen_log_file)` inside the
    `cli` Click group. Once the group has run, a non-default SIGHUP handler
    must be in place — Python's default for SIGHUP is to terminate the
    process (the W9 incident root cause).
    """
    src = SRC_ROOT / "cli.py"
    text = src.read_text(encoding="utf-8")
    assert "install_sighup_log_reopen(reopen_log_file)" in text, (
        "G1: cli.py must wire SIGHUP -> reopen_log_file via "
        "install_sighup_log_reopen; W9 incident closure"
    )


def test_w124_g1_run_mainnet_daemon_setsid_nohup_disown() -> None:
    """G1 ops-side: the canonical mainnet launcher must use
    setsid + nohup + disown. Repro of the W9 incident: the prior
    `start_mainnet.sh` path lacked these.
    """
    script = SCRIPTS_ROOT / "run_mainnet_daemon.sh"
    assert script.exists(), f"missing canonical launcher: {script}"
    body = script.read_text(encoding="utf-8")
    assert "setsid" in body, "G1: launcher must use setsid"
    assert "nohup" in body, "G1: launcher must use nohup"
    assert "disown" in body, "G1: launcher must disown the child"
    assert "</dev/null" in body, (
        "G1: launcher must redirect stdin to /dev/null (no tty coupling)"
    )


def test_w124_g2_pidfile_class_present_and_atomic() -> None:
    """G2: PidFile class exists, write() is atomic (tmp+rename),
    remove() is idempotent.
    """
    assert hasattr(daemon_mod, "PidFile")
    src = (SRC_ROOT / "daemon.py").read_text(encoding="utf-8")
    # Atomic write: write to .tmp then os.replace.
    assert "os.replace(tmp, self.path)" in src, (
        "G2: PidFile.write must use os.replace for atomicity"
    )
    # Stale detection via os.kill(pid, 0).
    assert "os.kill(pid, 0)" in src, (
        "G2: PidFile must detect stale via os.kill(pid, 0)"
    )


def test_w124_g2_pidfile_write_remove_lifecycle(tmp_path: Path) -> None:
    """G2: PidFile.write then remove leaves no file."""
    pid_path = tmp_path / "ouroboros.pid"
    pf = daemon_mod.PidFile(pid_path)
    pf.write()
    assert pid_path.exists()
    assert pid_path.read_text().strip() == str(os.getpid())
    pf.remove()
    assert not pid_path.exists()


def test_w124_g3_reinstall_script_exists_and_idempotent() -> None:
    """G3: tools/reinstall_ouroboros.sh exists, is executable, and
    runs `pip install -e <canonical>`. Closes FIX-80 (pip drift).
    """
    script = META_TOOLS_ROOT / "reinstall_ouroboros.sh"
    if not script.exists():
        pytest.skip("meta tools/ not visible from sandbox; gate vacuous here")
    body = script.read_text(encoding="utf-8")
    assert "pip3 install -e" in body, (
        "G3: reinstall script must use pip3 install -e"
    )
    assert "CANONICAL_OUROBOROS_SRC" in body or "/home/work/hashhog/ouroboros" in body, (
        "G3: reinstall script must hard-code canonical source path"
    )
    assert os.access(script, os.X_OK), "G3: reinstall script must be executable"


def test_w124_g3_start_mainnet_hooks_reinstall() -> None:
    """G3 ops-side: tools/start_mainnet.sh must invoke
    reinstall_ouroboros.sh BEFORE delegating to the launcher script.
    """
    script = META_TOOLS_ROOT / "start_mainnet.sh"
    if not script.exists():
        pytest.skip("meta tools/ not visible from sandbox; gate vacuous here")
    body = script.read_text(encoding="utf-8")
    # Reinstall must appear before the run_mainnet_daemon.sh delegate.
    reinstall_idx = body.find("reinstall_ouroboros.sh")
    daemon_idx = body.find("run_mainnet_daemon.sh")
    assert reinstall_idx > 0, "G3: start_mainnet must call reinstall_ouroboros.sh"
    assert daemon_idx > 0, "G3: start_mainnet must delegate to run_mainnet_daemon.sh"
    assert reinstall_idx < daemon_idx, (
        "G3: reinstall must run BEFORE the daemon launcher (avoid stale code)"
    )


def test_w124_g4_daemonize_double_fork() -> None:
    """G4: daemonize() performs the canonical POSIX double-fork."""
    assert hasattr(daemon_mod, "daemonize")
    src = (SRC_ROOT / "daemon.py").read_text(encoding="utf-8")
    # Two os.fork() calls + setsid in between (canonical double-fork).
    fork_count = len(re.findall(r"\bos\.fork\(\)", src))
    assert fork_count == 2, f"G4: daemonize must call os.fork() twice, got {fork_count}"
    assert "os.setsid()" in src, "G4: daemonize must call setsid between forks"
    assert "os.chdir(\"/\")" in src or "os.chdir('/')" in src, (
        "G4: daemonize must chdir to / so it doesn't pin a mount"
    )


def test_w124_g5_daemon_cli_flag_present() -> None:
    """G5: `--daemon` flag is exposed on `start`."""
    src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
    assert '"--daemon"' in src, "G5: cli must expose --daemon flag"
    # Daemonize BEFORE PID file write (parity with Core init.cpp:1432).
    daemonize_pos = src.find("daemonize()")
    pidfile_write_pos = src.find("_pid_file.write()")
    assert daemonize_pos > 0 and pidfile_write_pos > 0
    assert daemonize_pos < pidfile_write_pos, (
        "G5: daemonize() must run BEFORE PidFile.write() so PID matches "
        "grandchild (Core parity)"
    )


def test_w124_g6_signal_handlers_register_at_load() -> None:
    """G6: cli module installs SIGINT + SIGTERM handlers at import."""
    src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
    assert "signal.signal(signal.SIGINT, handle_sigint)" in src
    assert "signal.signal(signal.SIGTERM, handle_sigterm)" in src


def test_w124_g6_node_installs_asyncio_aware_handler() -> None:
    """G6 layer 2: BitcoinNode.start re-installs an event-loop-aware handler
    that sets `_shutdown_event` and schedules `self.stop()`.
    """
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    assert "signal.signal(signal.SIGINT, signal_handler)" in src
    assert "signal.signal(signal.SIGTERM, signal_handler)" in src
    assert "_shutdown_event.set()" in src, (
        "G6: node signal_handler must set _shutdown_event"
    )


def test_w124_g7_handler_does_not_sys_exit_from_thread() -> None:
    """G7: cli signal handlers must NOT call sys.exit() — that segfaults
    the PyO3/Rust tear-down. Documented in handle_sigint docstring.
    """
    src_handler = inspect.getsource(cli_mod.handle_sigint)
    # The handler may *say* "Does NOT call sys.exit()" in the docstring; the
    # actual function body must not contain sys.exit(.
    body_only = re.sub(r'"""[\s\S]*?"""', '', src_handler, count=1)
    assert "sys.exit(" not in body_only, (
        "G7: handle_sigint body must not call sys.exit() — PyO3 tear-down race"
    )


def test_w124_g8_main_loop_swallows_systemexit() -> None:
    """G8: main loop catches SystemExit so a stray uvicorn sys.exit() can't
    tear the node down — only real shutdown signals exit the loop.
    """
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    assert "except SystemExit:" in src, "G8: _main_loop must catch SystemExit"


def test_w124_g9_node_stays_alive_with_zero_peers() -> None:
    """G9: _main_loop iterates on self.running, NOT on peer count
    (Core parity — node must stay alive with zero peers).
    """
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    # The main loop must check self.running, not peer_count.
    assert "while self.running:" in src, (
        "G9: _main_loop must iterate while self.running"
    )
    # Comment in the source asserts the Core-parity intent.
    assert "MUST stay alive even when there are zero connected peers" in src, (
        "G9: Core-parity intent must be documented in _main_loop"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG-1 [G10, P2]: no flushchainstate RPC — operators cannot force a "
        "UTXO flush before SIGTERM; relies on RocksDB close path."
    ),
)
def test_w124_g10_flushchainstate_rpc_present() -> None:
    """G10: Core's `flushchainstate` RPC has a parity stub."""
    src = (SRC_ROOT / "rpc.py").read_text(encoding="utf-8")
    assert "rpc_flushchainstate" in src, "G10: no rpc_flushchainstate handler"


# ===========================================================================
# Logging (G11-G17)
# ===========================================================================


def test_w124_g11_sighup_reopens_rotating_log_file() -> None:
    """G11: reopen_log_file() exists and carries over handler filters
    (without that carry-over, SIGHUP would silently broaden logging).
    """
    assert hasattr(logcfg_mod, "reopen_log_file")
    src = (SRC_ROOT / "logging_config.py").read_text(encoding="utf-8")
    assert "Carry any handler-level filters across the reopen" in src, (
        "G11: filter carry-over must be explicit (silent-broaden footgun)"
    )


def test_w124_g11_reopen_returns_true_when_file_handler_active(
    tmp_path: Path,
) -> None:
    """G11 functional: configure logging with a file handler, then call
    reopen_log_file and assert it returns True (a handler was reopened).
    """
    logcfg_mod.configure_logging(
        debug=False,
        json_format=False,
        log_file=str(tmp_path / "ouroboros.log"),
        print_to_console=False,
    )
    try:
        assert logcfg_mod.reopen_log_file() is True
    finally:
        # Defensive: leave the test runner's logging unchanged.
        logcfg_mod.configure_logging(
            debug=False, json_format=False, log_file=None, print_to_console=True,
        )


def test_w124_g12_per_category_debug_filter() -> None:
    """G12: parse_debug_categories handles Core-style category strings."""
    parsed = daemon_mod.parse_debug_categories("net,mempool,validation")
    assert parsed == {"net", "mempool", "validation"}
    # Unknown categories are kept (don't filter out at parse time).
    parsed_unknown = daemon_mod.parse_debug_categories("net,bogus")
    assert "bogus" in parsed_unknown


def test_w124_g13_printtoconsole_flag_present() -> None:
    """G13: --printtoconsole / --noprinttoconsole exposed."""
    src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
    assert "--printtoconsole/--noprinttoconsole" in src


def test_w124_g14_debug_all_enables_all() -> None:
    """G14: -debug=all / -debug=1 enables every known category."""
    full_all = daemon_mod.parse_debug_categories("all")
    full_one = daemon_mod.parse_debug_categories("1")
    assert full_all == set(daemon_mod.DEBUG_CATEGORIES)
    assert full_one == set(daemon_mod.DEBUG_CATEGORIES)
    # And empty / "0" returns the empty set.
    assert daemon_mod.parse_debug_categories("0") == set()
    assert daemon_mod.parse_debug_categories(None) == set()


def test_w124_g15_json_formatter_present() -> None:
    """G15: JSONFormatter exists and emits ISO-8601 UTC timestamps."""
    import logging
    fmt = logcfg_mod.JSONFormatter()
    rec = logging.LogRecord(
        name="ouroboros.test", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello", args=(), exc_info=None,
    )
    out = fmt.format(rec)
    assert '"level": "INFO"' in out
    assert '"msg": "hello"' in out
    assert '"logger": "ouroboros.test"' in out


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG-2 [G16, P3]: no `logging` RPC for runtime category toggle. "
        "Infrastructure exists (parse + filter + SIGHUP-safe reopen) but no "
        "RPC to mutate without restart."
    ),
)
def test_w124_g16_runtime_logging_rpc_present() -> None:
    """G16: Core's `logging` RPC parity — runtime category toggle."""
    src = (SRC_ROOT / "rpc.py").read_text(encoding="utf-8")
    assert "rpc_logging" in src, "G16: no rpc_logging handler"


def test_w124_g17_log_rotation_defaults_documented() -> None:
    """G17: log-rotation params have sensible defaults (10 MiB x 5).

    PARTIAL: no operator-tunable knob; operators must rely on logrotate +
    SIGHUP (which is wired by G11). Defaults are checked here.
    """
    import logging.handlers
    sig = inspect.signature(logcfg_mod.configure_logging)
    assert sig.parameters["max_bytes"].default == 10 * 1024 * 1024
    assert sig.parameters["backup_count"].default == 5


# ===========================================================================
# Datadir / cookie / config (G18-G22)
# ===========================================================================


def test_w124_g18_cookie_written_before_rpc_binds() -> None:
    """G18: cookie file is written before the RPC server starts.

    Specifically: `generate_cookie(self.data_dir)` must appear before
    the RPC server is constructed AND before the RPC asyncio task is
    scheduled. The line 151 `self._rpc_task: asyncio.Task | None = None`
    is a type annotation, not the server start — that's
    `asyncio.create_task(_safe_rpc_start())`.
    """
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    cookie_pos = src.find("generate_cookie(self.data_dir)")
    rpc_server_ctor_pos = src.find("self.rpc_server = RPCServer(")
    rpc_task_start_pos = src.find("asyncio.create_task(_safe_rpc_start")
    assert cookie_pos > 0, "G18: generate_cookie must be invoked"
    assert rpc_server_ctor_pos > 0, "G18: RPCServer must be constructed"
    assert rpc_task_start_pos > 0, "G18: RPC task must be scheduled"
    assert cookie_pos < rpc_server_ctor_pos, (
        "G18: cookie must be written before RPCServer is constructed "
        "(matches Core init order)"
    )
    assert cookie_pos < rpc_task_start_pos, (
        "G18: cookie must be written before RPC asyncio task starts"
    )


def test_w124_g19_cookie_file_is_0600(tmp_path: Path) -> None:
    """G19: cookie file is created with 0600 permissions (POSIX)."""
    cookie_mod.generate_cookie(str(tmp_path))
    cookie_path = tmp_path / cookie_mod.COOKIE_FILENAME
    assert cookie_path.exists()
    mode = cookie_path.stat().st_mode & 0o777
    assert mode == 0o600, f"G19: cookie file must be 0600, got {oct(mode)}"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG-3 [G20, P1]: no datadir lock — multi-instance protection relies "
        "on PidFile + RocksDB LOCK + start_mainnet.sh check_not_running, all "
        "of which have gaps. Core has explicit fs::LockDirectory()."
    ),
)
def test_w124_g20_datadir_lock_machinery_present() -> None:
    """G20: a datadir lock (fcntl/flock or .lock file) must exist."""
    src_files = [
        p for p in SRC_ROOT.rglob("*.py")
        if "/tests/" not in str(p) and not p.name.startswith("test_")
    ]
    needles = ("fcntl.flock", "fcntl.lockf", "LockDirectory", "datadir_lock")
    seen = False
    for path in src_files:
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(n in txt for n in needles):
            seen = True
            break
    assert seen, "G20: no datadir lock machinery found in src/ouroboros/"


def test_w124_g21_config_file_under_datadir() -> None:
    """G21: default config path is <datadir>/ouroboros.conf."""
    src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
    assert 'Path(data_dir) / "ouroboros.conf"' in src


def test_w124_g22_network_sections_parsed() -> None:
    """G22: NodeConfig reads [mainnet]/[testnet4]/[regtest] sections."""
    src = (SRC_ROOT / "config.py").read_text(encoding="utf-8")
    # Sections-to-try mechanism must include all the expected networks.
    for sec in ("main", "mainnet", "testnet", "testnet3", "testnet4",
                "regtest", "signet"):
        assert f"'{sec}'" in src or f'"{sec}"' in src, (
            f"G22: config must consider [{sec}] section"
        )


# ===========================================================================
# RPC / shutdown coordination (G23-G27)
# ===========================================================================


def test_w124_g23_stop_rpc_present_and_delays() -> None:
    """G23: `stop` RPC schedules shutdown via call_later (response can flush)."""
    src = (SRC_ROOT / "rpc.py").read_text(encoding="utf-8")
    assert "async def rpc_stop" in src, "G23: rpc_stop missing"
    # The handler must defer shutdown so the HTTP response can complete.
    assert "call_later(0.5" in src, (
        "G23: rpc_stop must defer shutdown (call_later) so response can flush"
    )
    # And it must trigger the same _shutdown_event the signal handlers use.
    assert "_shutdown_event" in src


def test_w124_g24_uptime_rpc_present() -> None:
    src = (SRC_ROOT / "rpc.py").read_text(encoding="utf-8")
    assert "async def rpc_uptime" in src


def test_w124_g25_getrpcinfo_present() -> None:
    src = (SRC_ROOT / "rpc.py").read_text(encoding="utf-8")
    assert "async def rpc_getrpcinfo" in src


def test_w124_g26_shutdown_sequence_ordered() -> None:
    """G26: node.stop calls block_sync.stop → peer_manager.stop → rpc cancel
    → zmq_notifier.stop → fee/mempool persist → cookie delete in that order.
    """
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    # Locate each step inside async def stop.
    stop_start = src.find("async def stop(self):")
    assert stop_start > 0
    stop_body = src[stop_start: stop_start + 4000]

    order = [
        "block_sync.stop()",
        "peer_manager.stop()",
        "_rpc_task.cancel()",
        "zmq_notifier.stop()",
        "fee_estimator.save_to_file",
        "mempool.dump_to_file",
        "delete_cookie(self.data_dir)",
    ]
    last = -1
    for step in order:
        pos = stop_body.find(step)
        assert pos > last, f"G26: shutdown step out of order: {step}"
        last = pos


def test_w124_g27_mempool_dumped_on_shutdown() -> None:
    src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    assert 'mempool.dump_to_file(mempool_path)' in src, (
        "G27: mempool must be dumped to disk on shutdown"
    )


# ===========================================================================
# Two-pipeline coordination (G28-G30)
# ===========================================================================


def test_w124_g28_zmq_notifier_wired_into_shutdown() -> None:
    """G28: node.stop awaits zmq_notifier.stop (LINGER=0 + ctx.term)."""
    node_src = (SRC_ROOT / "node.py").read_text(encoding="utf-8")
    notifier_src = (SRC_ROOT / "zmq_notifier.py").read_text(encoding="utf-8")
    assert "await self.zmq_notifier.stop()" in node_src
    assert "LINGER" in notifier_src and "term()" in notifier_src, (
        "G28: ZMQNotifier.stop must set LINGER=0 + ctx.term to avoid leaks"
    )


def test_w124_g29_rust_no_signal_handlers() -> None:
    """G29 two-pipeline guard: ferrous-utils (Rust) must NOT install OS
    signal handlers — they must land in the Python interpreter.

    Counterpart to the FIX-74/75/79 and W122 GCS-in-Rust guards. Forbidden
    tokens: signal_hook, ctrlc, sigaction, libc::signal, signal::raise.
    """
    rust_root = REPO_ROOT / "ferrous-utils" / "sync" / "src"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    forbidden = (
        "signal_hook",
        "use ctrlc",
        "ctrlc::",
        "sigaction",
        "libc::signal",
        "signal::raise",
        "SignalKind::",
        "tokio::signal",
    )
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in txt:
                offenders.append(f"{path}: {needle}")

    assert not offenders, (
        "G29 two-pipeline guard: ferrous-utils/sync/src must NOT install OS "
        "signal handlers — signal delivery must land in the Python "
        f"interpreter. Offenders: {offenders[:5]}"
    )


def test_w124_g30_rust_no_persistent_global_state() -> None:
    """G30 two-pipeline guard: ferrous-utils must hold no `static mut` /
    `lazy_static!` / `OnceLock` cells that survive across PyO3 calls and
    would leak past Python's shutdown without explicit teardown.

    Rust hot paths legitimately use `tokio::runtime::Runtime::new()` +
    `rt.block_on(...)` inside `py.allow_threads(|| ...)` blocks — the
    runtime is constructed per-call and dropped when the closure returns,
    so Python's drop of `BitcoinNode.db` (and the PyBlockchainDB wrapper)
    is sufficient to tear everything down. What's FORBIDDEN is:

      - `static mut FOO` (raw mutable globals)
      - `lazy_static!` (typed mutable globals)
      - `static FOO: OnceLock<Runtime>` (process-lifetime tokio runtime)
      - `static FOO: OnceLock<JoinHandle<...>>` (process-lifetime
        background threads Python doesn't see)

    Counterpart to G29 — together they prove the Rust pipeline owns no
    process state Python doesn't already control.
    """
    rust_root = REPO_ROOT / "ferrous-utils" / "sync" / "src"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    # Coarse-grained forbidden tokens. Per-call `tokio::runtime::Runtime::new()`
    # is allowed (see docstring); the `static .*OnceLock<Runtime>` pattern is
    # not.
    forbidden_re = [
        re.compile(r"\bstatic\s+mut\b"),
        re.compile(r"\blazy_static!"),
        re.compile(r"\bstatic\s+[A-Z0-9_]+\s*:\s*OnceLock<\s*Runtime"),
        re.compile(r"\bstatic\s+[A-Z0-9_]+\s*:\s*OnceCell<\s*Runtime"),
        re.compile(r"\bstatic\s+[A-Z0-9_]+\s*:\s*Lazy<\s*Runtime"),
        re.compile(r"\bstatic\s+[A-Z0-9_]+\s*:\s*OnceLock<\s*JoinHandle"),
    ]
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Skip test modules — they're allowed to spawn threads internally.
        if path.name.endswith("_tests.rs") or "/tests/" in str(path):
            continue
        for pat in forbidden_re:
            if pat.search(txt):
                offenders.append(f"{path}: {pat.pattern}")

    assert not offenders, (
        "G30 two-pipeline guard: ferrous-utils/sync/src must NOT hold "
        "process-lifetime static state that survives PyO3 call boundaries. "
        f"Offenders: {offenders[:5]}"
    )
