"""Operational utilities: daemonize, PID file, sd_notify, debug categories.

Closes the operational-parity gaps documented in the W26 audit. Mirrors
Bitcoin Core's ``init.cpp`` / ``util/system.cpp``:

    * ``-daemon``        — fork into the background.
    * ``-pid=<path>``    — write own PID to a file at startup, remove on
                            graceful shutdown.
    * ``-debug=<cat>``   — Core-style per-category debug filtering.
    * ``-printtoconsole``— explicit flag to keep logs on stderr/stdout.
    * SIGHUP             — reopen the log file (so logrotate can rotate
                            without restarting the node).
    * sd_notify          — best-effort systemd readiness/watchdog notify.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import sys
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Debug categories (Bitcoin Core parity, src/logging/categories.h)
# ---------------------------------------------------------------------------
#
# Core uses a bitfield; we use a set of lowercase strings.  ``"all"`` /
# ``"1"`` enable everything.  Unknown categories are tolerated with a
# warning so configs aren't fragile across versions.

DEBUG_CATEGORIES: frozenset[str] = frozenset({
    "net", "tor", "mempool", "http", "bench", "zmq", "walletdb",
    "rpc", "estimatefee", "addrman", "selectcoins", "reindex",
    "cmpctblock", "rand", "prune", "proxy", "mempoolrej", "libevent",
    "coindb", "qt", "leveldb", "validation", "i2p", "ipc", "lock",
    "blockstorage", "txreconciliation", "scan", "txpackages", "kernel",
    "privbroadcast",
})


def parse_debug_categories(value: str | None) -> set[str]:
    """Parse a Core-style ``-debug`` value into a set of categories.

    ``None``, empty string or ``"0"`` disables category filtering and
    returns an empty set.  ``"1"`` / ``"all"`` enables every known
    category.  Anything else is split on commas, trimmed, lower-cased.
    Unknown categories are kept in the returned set (they simply won't
    match anything in code) but a warning is logged.
    """
    if not value or value.strip() in {"0", "false", "no"}:
        return set()
    raw = [c.strip().lower() for c in value.split(",") if c.strip()]
    if not raw:
        return set()
    if any(c in {"1", "all", "true", "yes"} for c in raw):
        return set(DEBUG_CATEGORIES)
    out: set[str] = set()
    for cat in raw:
        if cat not in DEBUG_CATEGORIES:
            logger.warning("Unknown debug category %r — ignoring at filter time", cat)
        out.add(cat)
    return out


# ---------------------------------------------------------------------------
# PID file
# ---------------------------------------------------------------------------

class PidFile:
    """Best-effort PID file writer/cleaner.

    Mirrors Bitcoin Core's behaviour around ``g_pidfile_path``:
    write at startup, unlink on graceful shutdown.  Stale PID files
    (process no longer running) are silently overwritten.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path).expanduser()
        self._owned = False

    def _stale(self) -> bool:
        """Return True if the file exists but the recorded PID is gone."""
        try:
            txt = self.path.read_text().strip()
            if not txt:
                return True
            pid = int(txt)
        except (OSError, ValueError):
            return True
        if pid == os.getpid():
            return True
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        return False

    def write(self) -> None:
        """Write the current PID into the file.

        Raises ``RuntimeError`` if a live PID is already recorded
        (someone else owns the datadir).
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and not self._stale():
            existing = self.path.read_text().strip()
            raise RuntimeError(
                f"PID file {self.path} already owned by pid {existing}"
            )
        # Atomic-ish write so a torn write never confuses operators.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(f"{os.getpid()}\n")
        os.replace(tmp, self.path)
        self._owned = True

    def remove(self) -> None:
        """Remove the PID file if we wrote it."""
        if not self._owned:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("Failed to remove pid file %s: %s", self.path, exc)
        finally:
            self._owned = False


# ---------------------------------------------------------------------------
# Daemonize (POSIX double-fork, like Bitcoin Core's ``daemon()`` call)
# ---------------------------------------------------------------------------

def daemonize(*, redirect_stdio: bool = True) -> None:
    """Detach from the controlling terminal.

    Performs the canonical double-fork dance:

      * ``fork()`` — first child decouples from the shell.
      * ``setsid()`` — become session leader.
      * ``fork()`` again — guarantee we can never re-acquire a TTY.
      * Redirect stdin/stdout/stderr to ``/dev/null`` (best effort).

    The parent processes ``_exit(0)`` so the shell sees the launcher
    return immediately.  The grandchild returns to the caller and
    continues node startup.
    """
    if os.name != "posix":  # pragma: no cover - Windows not supported
        raise RuntimeError("--daemon requires a POSIX OS")

    # First fork: parent exits, child continues.
    try:
        pid = os.fork()
    except OSError as exc:
        raise RuntimeError(f"first fork failed: {exc}") from exc
    if pid > 0:
        os._exit(0)

    # Decouple from controlling TTY.
    os.setsid()

    # Second fork: prevent re-acquiring a controlling terminal.
    try:
        pid = os.fork()
    except OSError as exc:
        raise RuntimeError(f"second fork failed: {exc}") from exc
    if pid > 0:
        os._exit(0)

    # Reset working dir + umask (avoid keeping a mount busy / inheriting
    # a restrictive umask from the launcher).
    os.chdir("/")
    os.umask(0o022)

    if redirect_stdio:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        with open(os.devnull, "rb", 0) as devnull_r:
            os.dup2(devnull_r.fileno(), 0)
        with open(os.devnull, "ab", 0) as devnull_w:
            os.dup2(devnull_w.fileno(), 1)
            os.dup2(devnull_w.fileno(), 2)


# ---------------------------------------------------------------------------
# sd_notify — best-effort systemd integration
# ---------------------------------------------------------------------------
#
# We deliberately do NOT take a hard dependency on python-systemd;
# Core's parity here is "READY=1 / STOPPING=1 / STATUS=…" datagram
# strings sent to ``$NOTIFY_SOCKET``.  When the env var is absent
# (i.e. not running under systemd), the calls are no-ops.

def sd_notify(state: str) -> bool:
    """Send a notification to systemd. Returns True on success.

    Silently no-ops when ``NOTIFY_SOCKET`` is not set, so callers can
    invoke unconditionally.
    """
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    # Abstract socket: leading '@' becomes a NUL byte for AF_UNIX.
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(state.encode("utf-8"), addr)
        return True
    except OSError as exc:
        logger.debug("sd_notify(%r) failed: %s", state, exc)
        return False


def sd_notify_ready(status: str | None = None) -> bool:
    payload = "READY=1"
    if status:
        payload += "\nSTATUS=" + status
    return sd_notify(payload)


def sd_notify_stopping(status: str | None = None) -> bool:
    payload = "STOPPING=1"
    if status:
        payload += "\nSTATUS=" + status
    return sd_notify(payload)


def sd_notify_status(status: str) -> bool:
    return sd_notify("STATUS=" + status)


# ---------------------------------------------------------------------------
# Convenience: install SIGHUP handler that reopens the rotating log file.
# ---------------------------------------------------------------------------

def install_sighup_log_reopen(reopen_callable) -> None:
    """Wire SIGHUP to ``reopen_callable``.

    On non-POSIX platforms (Windows) SIGHUP doesn't exist, so we
    silently skip — matching Bitcoin Core's behaviour.
    """
    if not hasattr(signal, "SIGHUP"):  # pragma: no cover
        return

    def _handler(signum, frame):  # pragma: no cover - signal entry point
        try:
            reopen_callable()
        except Exception as exc:
            logger.error("SIGHUP log reopen failed: %s", exc)

    signal.signal(signal.SIGHUP, _handler)


__all__ = [
    "DEBUG_CATEGORIES",
    "parse_debug_categories",
    "PidFile",
    "daemonize",
    "sd_notify",
    "sd_notify_ready",
    "sd_notify_stopping",
    "sd_notify_status",
    "install_sighup_log_reopen",
]
