W124 — Operator-experience audit (ouroboros)
=============================================

Date: 2026-05-17
Impl: ouroboros (Python pipeline + Rust hot paths in ferrous-utils)
Target: operational surfaces — process lifecycle, signals, PID file,
        logging, datadir/cookie/config, RPC shutdown, two-pipeline
        coordination, ops scripts (`run_mainnet_daemon.sh`,
        `reinstall_ouroboros.sh`).

Reference: `bitcoin-core/src/init.cpp`, `src/shutdown.cpp`,
`src/logging/{logger.cpp,h}`, `src/util/syserror.{cpp,h}`,
`src/common/args.cpp` (config-file machinery).

Status: **3 BUGS / 30 gates.**  PRESENT 23 / PARTIAL 4 / MISSING 3.
Two-pipeline guard: PRESERVED (audit + xfail tests, zero production code
change).

Context
-------

Wave 8/9 incident (`wave9-2026-04-14/OUROBOROS-EXIT-REGRESSION.md`)
showed ouroboros silently died at T+9 min after restart because
`tools/start_mainnet.sh` invoked `python3 -m ouroboros.cli` *without*
`nohup`/`setsid`/`disown`; when the launching shell exited, SIGHUP
killed the daemon (the BitcoinNode handlers only covered SIGTERM /
SIGINT). The fix was the in-repo launcher `scripts/run_mainnet_daemon.sh`
(setsid + nohup + disown + `</dev/null` redirect), which `start_mainnet.sh`
now delegates to for ouroboros only. The W9 launcher remains the source
of truth for "how to start ouroboros on mainnet from a non-persistent
shell."

A separate operational footgun was fixed by FIX-80
(`tools/reinstall_ouroboros.sh`): when sub-agents work in
`.claude/worktrees/agent-*`, `pip install -e <worktree>` silently
re-points the editable install at the worktree. After the worktree is
deleted the import resolves to the wrong source. The reinstall helper
runs **before every mainnet ouroboros start** via the hook in
`tools/start_mainnet.sh:155-176`.

Both closures are verified by audit gates G1, G2, G3 below.

Gates (30)
----------

### Process lifecycle (1–10)

**G1: SIGHUP doesn't kill the daemon when launched via the canonical
launcher.** PRESENT.
`scripts/run_mainnet_daemon.sh` uses `setsid nohup … </dev/null & disown`
on lines 67–79, putting the process in a new session immune to parent
SIGHUP. Inside the process, `install_sighup_log_reopen()` in
`src/ouroboros/cli.py:172-175` replaces the default-action SIGHUP handler
with a log-reopen hook so SIGHUP is also harmless even if delivered.
Refs `bitcoin-core/src/init.cpp` SIGHUP wiring (`HandleSIGHUP →
LogInstance().StartLogging` re-call); Core only ever rotates the log.

**G2: PID file written at startup, removed on graceful shutdown.**
PRESENT.
`src/ouroboros/daemon.py` defines `PidFile` (lines 75-133): atomic
tmp+rename write, stale-detection via `os.kill(pid, 0)`, idempotent
remove. Wired in `cli.py:597-608` after `daemonize()` so the recorded
PID matches the surviving grandchild (parity with Core's
`CreatePidFile()` in `init.cpp:183-199` called after the fork). On
shutdown, both `handle_sigint`/`handle_sigterm` (`cli.py:73-76`) and the
`finally:` block at `cli.py:625-630` call `_pid_file.remove()`.

**G3: Editable pip install drift is prevented before every restart.**
PRESENT.
`tools/reinstall_ouroboros.sh` runs `pip3 install -e
/home/work/hashhog/ouroboros --break-system-packages --quiet` then
verifies `ouroboros.__file__` is under the canonical source root.
Invoked unconditionally by `tools/start_mainnet.sh:162-165` before
delegating to the launcher script. Single-impl in the fleet — closes
FIX-80.

**G4: Daemonize via POSIX double-fork.** PRESENT.
`daemon.daemonize()` (`daemon.py:140-191`) implements the canonical
double-fork: first `fork()` decouples from the shell, `setsid()`,
second `fork()` so the daemon can never re-acquire a TTY, then
`chdir("/")`, `umask(0o022)`, stdio redirected to `/dev/null`. Mirrors
Core's `daemon()` libc call.

**G5: Bitcoin Core `-daemon` CLI flag.** PRESENT.
`cli.py:410-418` exposes `--daemon` on `start`; behaviour: daemonize
**before** writing the PID file (matches Core, `cli.py:572-594`), and
flips console logging off unless `--printtoconsole` is explicit
(`cli.py:579-588`). Core parity.

**G6: SIGTERM / SIGINT handlers exist and trigger graceful shutdown.**
PRESENT.
Two layers: process-level handlers at `cli.py:90-91` register
`handle_sigint`/`handle_sigterm` (set `_cancelled`, request
`_sync_manager.cancel_sync()`, run `asyncio.run(_node.stop())`); inside
the running event loop, `BitcoinNode.start()` re-installs an asyncio-
aware handler at `node.py:174-175` that sets `_shutdown_event` and
schedules `self.stop()` via `loop.call_soon_threadsafe`. The two layers
are deliberate: the cli.py handler covers `ouroboros sync` (pre-event-
loop) and shutdown-during-startup; the node.py handler covers the
post-event-loop main-loop case (`Received signal N, shutting down…`,
the line that was conspicuously *absent* in the W9 incident log).

**G7: Signal handler does not call sys.exit() from a thread.** PRESENT.
`cli.py:47-52` explicit warning + implementation comment ("Calling
`sys.exit()` from a signal handler while threads are running causes
segfaults (Rust/PyO3 tear-down)"). The handler sets `_cancelled` and
defers exit to the main loop. Required for ouroboros specifically
because of the Python + Rust two-pipeline architecture (PyO3 holds
threads that would dangle if the interpreter tore down mid-call).

**G8: Main loop does not exit on stray SystemExit.** PRESENT.
`node.py:631-635` catches `SystemExit` in the main loop and logs+
ignores it. Comment: "Never let a stray sys.exit() (e.g. from uvicorn)
tear down the node — only explicit shutdown signals should stop us."

**G9: Stays alive with zero peers.** PRESENT (Core parity).
`node.py:603-609` main-loop comment and behaviour: "The node MUST stay
alive even when there are zero connected peers (matching Bitcoin Core
behaviour). Only SIGINT, SIGTERM, or an RPC stop command should cause
the loop to exit." Loop iterates on `self.running`, not on peer count.

**G10: `flushchainstate` RPC exists.** **MISSING — BUG-1 (P2 ops gap).**
Core ships `flushchainstate` to let operators force a UTXO flush before
SIGTERM (used by `tools/stop_mainnet.sh:flushchainstate` per repo
CLAUDE.md). ouroboros has no `rpc_flushchainstate` (grep across
`src/ouroboros/rpc.py` is empty). `tools/stop_mainnet.sh` falls back to
plain SIGTERM for ouroboros; the in-process stop sequence
(`node.stop()` at `node.py:548-601`) does persist mempool + fee
estimator but never *explicitly* triggers a chainstate flush — it
relies on RocksDB's normal close path inside `BlockchainDatabase`
(Rust drop on Python GC). Acceptable today but operator-surface gap.

### Logging (11–17)

**G11: SIGHUP reopens the rotating log file (logrotate compat).**
PRESENT.
`logging_config.reopen_log_file()` (`logging_config.py:192-227`)
preserves rotating-file handler max_bytes + backup_count + level +
formatter + **filters** (the explicit comment "Carry any handler-level
filters across the reopen (notably the category filter; without this
SIGHUP would silently broaden logging)" addresses a subtle Core-parity
bug). Wired via `install_sighup_log_reopen(reopen_log_file)` in
`cli.py:174-175`. Core parity (`HandleSIGHUP →
LogInstance().StartLogging`).

**G12: Per-category debug filter (Core-style `-debug=net,mempool,…`).**
PRESENT.
`daemon.parse_debug_categories()` + `_CategoryFilter` in
`logging_config.py:78-110`. Categories map to logger-name prefixes via
`_CATEGORY_TO_LOGGERS` (`logging_config.py:43-75`) covering net,
mempool, rpc, http, addrman, tor, zmq, validation, etc. Unknown
categories logged-and-tolerated (matches Core's permissive behaviour).
DEBUG-level records are gated; INFO+ always pass (Core
`LogPrintLevel` semantics).

**G13: `-printtoconsole` toggle.** PRESENT.
`cli.py:131-139` `--printtoconsole/--noprinttoconsole`. Default: on
in foreground, off under `--daemon` (`cli.py:579-588`). When off and a
log file is configured, output is file-only — matches Core's
`-printtoconsole` semantics.

**G14: `-debug=all` and `-debug=1` enable every category.** PRESENT.
`daemon.parse_debug_categories()` (`daemon.py:47-68`) — "any token in
{1, all, true, yes}" returns the full `DEBUG_CATEGORIES` frozenset.
Core parity.

**G15: Structured log support (`--log-json`).** PRESENT.
`logging_config.JSONFormatter` (`logging_config.py:20-34`); selectable
via `--log-json` (`cli.py:130`). Emits ISO-8601 UTC timestamps, level,
logger, msg, optional exception. Ahead of Core (Core has no JSON
logging upstream).

**G16: `logging` RPC (Core's runtime category toggle).** **PARTIAL —
BUG-2 (P3 operator-experience gap).** Core's `logging` RPC lets ops
enable/disable categories without restart. ouroboros has the
*infrastructure* (categories, filter, reopen-on-SIGHUP) but no
`rpc_logging` to mutate at runtime. Operators can change categories
only by editing config + SIGHUP → restart. Acceptable; flagged for
visibility.

**G17: Log rotation parameters operator-tunable.** PARTIAL.
`configure_logging(max_bytes=10MB, backup_count=5)` —
`logging_config.py:122-123`. Defaults match Core's debug.log sizing
(10 MiB) but there is no CLI/config knob to override at runtime.
Operators must rely on logrotate via SIGHUP (which **does** work — see
G11). Acceptable; flagged as PARTIAL.

### Datadir / cookie / config (18–22)

**G18: Cookie file written before RPC binds.** PRESENT.
`node.py:183-192` — `generate_cookie()` runs *before* the RPC server is
started. Comment: "Write the cookie file early (before the RPC server
binds) so that external tools polling with curl can read it as soon
as the port opens — matching Bitcoin Core's init order." Cookie is
deleted on clean shutdown via `delete_cookie(self.data_dir)` at
`node.py:596`.

**G19: Cookie file 0600.** PRESENT.
`cookie_auth.generate_cookie()` (`cookie_auth.py:22-27`) calls
`cookie_path.chmod(0o600)` on POSIX. Core parity.

**G20: Datadir lock (single-instance enforcement).** **MISSING —
BUG-3 (P1 multi-instance safety).** Core writes a `.lock` file in the
datadir (`util/fs.cpp` `LockDirectory()`) and holds an exclusive
`flock`/Win32 mutex; a second `bitcoind` against the same datadir
exits with "Cannot obtain a lock on data directory". ouroboros has
**no flock/fcntl/lock-file machinery** (verified: `grep -rn
'fcntl\|flock' src/ouroboros/` returns zero hits). Multi-instance
protection relies entirely on:
  (a) the PID file (G2) — but PidFile only refuses if it sees a
      live PID in the file, and PidFile only opens *after*
      `BitcoinNode.start()` has already opened the RocksDB;
  (b) RocksDB's own LOCK file in the chainstate directory — which
      catches the truly-concurrent case but produces a noisy
      "RocksDB error: lock hold by current process …" message, not
      Core's clean "data directory locked" diagnostic;
  (c) `start_mainnet.sh:check_not_running ouroboros 8359` —
      operator-side, not enforced in-process.
A racing operator who shells the CLI directly bypasses (c) and gets
(b)'s less-clear error. Worth a dedicated datadir lock parity pass
in a future fix wave.

**G21: Config file location follows datadir.** PRESENT.
`cli.py:178` — `config_file or str(Path(data_dir) / "ouroboros.conf")`.
Override via `--config` flag (`cli.py:107-111`) or env
`OUROBOROS_DATADIR` (`cli.py:146-147`). Core parity (`-datadir`,
`-conf`).

**G22: Network section parsing (`[mainnet]` / `[testnet4]` / …).**
PRESENT.
`config.NodeConfig` (`config.py:128-228`) reads `[main]`, `[mainnet]`,
`[testnet]`, `[testnet3]`, `[testnet4]`, `[regtest]`, `[signet]`
sections (`config.py:226-227`). Env vars (`OUROBOROS_<KEY>`)
override config. Core parity with `configparser` semantics.

### RPC / shutdown coordination (23–27)

**G23: `stop` RPC triggers graceful shutdown.** PRESENT.
`rpc.py:6402-6414` `rpc_stop`: schedules `_trigger_shutdown()` via
`call_later(0.5, ...)` so the HTTP response can flush before the event
loop exits. Sets `_shutdown_event` (preferred — interleaves cleanly
with the main loop) or falls back to `self.node.stop()`. Returns
"Ouroboros server stopping" (matches Core's "Bitcoin Core stopping").

**G24: `uptime` RPC.** PRESENT.
`rpc.py:6416-6421` — `return int(time.time() - start)` where
`start = self.node.start_time`. Core parity.

**G25: `getrpcinfo` RPC.** PRESENT.
`rpc.py:8962` `rpc_getrpcinfo`. Returns active commands + log path.
Core parity.

**G26: Shutdown order: P2P stop → RPC stop → mempool persist → DB
flush.** PRESENT (with caveat).
`node.stop()` (`node.py:548-601`):
  1. `block_sync.stop()`           — drain in-flight block downloads
  2. `peer_manager.stop()`         — closes peers + saves addrman
  3. `_rpc_task.cancel()`          — RPC server shutdown
  4. `zmq_notifier.stop()`         — close ZMQ sockets + term ctx
  5. `fee_estimator.save_to_file()`
  6. `mempool.dump_to_file()`
  7. `delete_cookie(self.data_dir)`

Caveat: order matches Core *intent* but RPC is stopped *after* the
peer manager (Core stops HTTPRPC first via `Interrupt()` then peers
via `Shutdown()`). For ouroboros this is structurally fine because
the RPC server is a uvicorn task with no peer-touching callbacks
once peer_manager has stopped — gate considered PRESENT.

**G27: Mempool persisted on graceful shutdown.** PRESENT.
`mempool.dump_to_file(os.path.join(self.data_dir, "mempool.dat"))` at
`node.py:591-593`. Matches Core's `DumpMempool()` call in
`Shutdown()`.

### Two-pipeline coordination (28–30)

**G28: ZMQ notifier wires into shutdown.** PRESENT.
`node.stop()` (`node.py:577-579`) awaits `self.zmq_notifier.stop()`.
`ZMQNotifier.stop()` (`zmq_notifier.py:161-180`) sets `LINGER=0` on
every socket, closes them, and calls `_context.term()`. No leaked
sockets across restarts.

**G29: Rust pipeline does not install its own signal handlers.**
PRESENT (two-pipeline coordination invariant).
The Rust crate `ferrous-utils/sync` is invoked synchronously from
Python via PyO3. It runs no async runtime of its own that would
register OS signals. Signal delivery lands in the Python interpreter,
which forwards via the asyncio-aware handler at `node.py:168-175` →
`_shutdown_event.set()` → main-loop checks and `node.stop()`.
A new test in `test_w124_operator.py::test_w124_g29_rust_no_signal_handlers`
greps `ferrous-utils/sync/src/` for `signal_hook`, `ctrlc`, etc., and
fails if a future change introduces a Rust signal handler.

**G30: Rust pipeline holds no process-lifetime state Python can't tear
down.** PRESENT (two-pipeline coordination invariant).
Rust hot paths use `tokio::runtime::Runtime::new()` + `rt.block_on(...)`
inside `py.allow_threads(|| ...)` blocks — runtime is per-call and
dropped when the closure returns. `BlockchainDatabase` is the only
persistent Rust-side resource and it is dropped when the Python
`BitcoinNode.db` reference goes out of scope at `node.stop()` exit. No
`static mut`, `lazy_static!`, or `static FOO: OnceLock<Runtime>` cells
in `ferrous-utils/sync/src/` (verified by
`test_w124_g30_rust_no_persistent_global_state`). Forbidden patterns
checked: `static mut`, `lazy_static!`, `OnceLock<Runtime>`,
`OnceCell<Runtime>`, `Lazy<Runtime>`, `OnceLock<JoinHandle<...>>` — a
process-lifetime tokio runtime or join-handle would leak past Python's
drop of `BitcoinNode.db`. Per-call `Runtime::new()` is allowed and
expected.

Bugs
----

**BUG-1 [G10, P2 operator-experience]: no `flushchainstate` RPC.**
Operators using `tools/stop_mainnet.sh` cannot proactively flush
chainstate before SIGTERM; ouroboros relies on RocksDB's close-path
flush instead of an explicit RPC trigger. Acceptable for correctness
but a parity gap. Fix sketch: add `rpc_flushchainstate` that calls
`self.node.db.flush_chainstate()` (already exists Rust-side).

**BUG-2 [G16, P3 ops gap]: no `logging` RPC for runtime category
toggle.** The infrastructure exists (`parse_debug_categories`,
`_CategoryFilter`, SIGHUP-safe filter carry-over) but there is no RPC
to mutate the active set without restart. Fix sketch: `rpc_logging`
takes `include` and `exclude` lists of categories, rebuilds
`_CategoryFilter`, reattaches to existing handlers.

**BUG-3 [G20, P1 multi-instance safety]: no datadir lock.** ouroboros
does not write a `.lock` file or hold an exclusive `flock`/`fcntl`
lock on the datadir. Multi-instance protection relies on the PID
file (which only opens *after* RocksDB), RocksDB's own LOCK
(produces a noisy error), and `start_mainnet.sh:check_not_running`
(operator-side, bypassable when shelling the CLI directly). A racing
operator can sometimes get further into the startup sequence than
they should. Fix sketch: add `datadir.lock` write+`fcntl.flock`
on Linux/macOS, refuse to start if held; remove on graceful
shutdown.

Summary
-------

PRESENT: G1, G2, G3, G4, G5, G6, G7, G8, G9, G11, G12, G13, G14,
G15, G18, G19, G21, G22, G23, G24, G25, G26, G27, G28, G29, G30
**(26 / 30)**

PARTIAL: G16 (no runtime `logging` RPC), G17 (no operator-tunable
log-rotation knob; SIGHUP still works for logrotate)
**(2 / 30)**

MISSING: G10 (`flushchainstate` RPC), G20 (datadir lock)
**(2 / 30)**

Total bugs: **3** (BUG-1 P2, BUG-2 P3, BUG-3 P1).

Two-pipeline guard
------------------

PRESERVED. No production code changes in W124. The new
`test_w124_g29_rust_no_signal_handlers` xfail test extends the
FIX-74/75/79/W122 guard chain — it greps `ferrous-utils/sync/src/`
for forbidden tokens (`signal_hook`, `ctrlc`, `sigaction`, `kill`)
and asserts none appear. Same shape as W122's GCS guard.

W9 SIGHUP incident closure
--------------------------

The W9 incident (`wave9-2026-04-14/OUROBOROS-EXIT-REGRESSION.md`)
is fully closed by the combination of:
  - launcher `scripts/run_mainnet_daemon.sh` (setsid + nohup + disown)
  - in-process `install_sighup_log_reopen()` handler (so SIGHUP is
    harmless even if a future operator launches without setsid)
  - `tools/start_mainnet.sh:155-176` delegating to the launcher for
    ouroboros
  - test `test_w124_g1_sighup_rebound` asserts a SIGHUP handler is
    installed at module-load time.

FIX-80 pip-install drift closure
--------------------------------

`tools/reinstall_ouroboros.sh` + `tools/start_mainnet.sh:155-176` hook
remove the worktree-drift footgun. Gate G3 documents the closure.
Test `test_w124_g3_reinstall_script_exists_and_idempotent` asserts the
script is present, executable, and runs `pip install -e` with the
canonical source path.
