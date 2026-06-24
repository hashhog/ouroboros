"""
Structured logging configuration for Ouroboros.

Supports plain text (default) and JSON output formats, with optional
log rotation via RotatingFileHandler.  Adds Bitcoin Core parity:

  * Per-category debug filtering (``-debug=net,mempool,…``).
  * SIGHUP log-file reopen so logrotate can rotate without restarting.
  * Explicit ``-printtoconsole`` toggle (vs file-only logging).
"""

import json
import logging
import logging.handlers
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


_PLAIN_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


# Map of Core debug-category names to the (logger-name) prefixes we use
# inside ouroboros.  Anything not in this map is treated as a free-form
# logger-name suffix (matches against ``record.name``).
_CATEGORY_TO_LOGGERS: dict[str, tuple[str, ...]] = {
    "net":            ("ouroboros.p2p", "ouroboros.peer", "ouroboros.transport_v2"),
    "mempool":        ("ouroboros.mempool",),
    "mempoolrej":     ("ouroboros.mempool",),
    "validation":     ("ouroboros.validation", "ouroboros.consensus"),
    "rpc":            ("ouroboros.rpc",),
    "http":           ("ouroboros.rpc", "ouroboros.rest"),
    "addrman":        ("ouroboros.addrman",),
    "tor":            ("ouroboros.tor",),
    "i2p":            ("ouroboros.tor",),
    "proxy":          ("ouroboros.tor",),
    "zmq":            ("ouroboros.zmq_notifier", "ouroboros.zmq_publisher"),
    "prune":          ("ouroboros.pruning",),
    "blockstorage":   ("ouroboros.database", "ouroboros.block_sync"),
    "coindb":         ("ouroboros.database",),
    "leveldb":        ("ouroboros.database",),
    "cmpctblock":     ("ouroboros.compact_blocks",),
    "txpackages":     ("ouroboros.mempool",),
    "estimatefee":    ("ouroboros.fee_estimator",),
    "walletdb":       ("ouroboros.wallet",),
    "reindex":        ("ouroboros.sync_manager", "ouroboros.block_sync"),
    "bench":          ("ouroboros.metrics",),
    "selectcoins":    ("ouroboros.wallet",),
    "rand":           ("ouroboros",),
    "lock":           ("ouroboros",),
    "scan":           ("ouroboros",),
    "ipc":            ("ouroboros",),
    "kernel":         ("ouroboros",),
    "qt":             ("ouroboros",),
    "libevent":       ("ouroboros",),
    "txreconciliation": ("ouroboros.p2p",),
    "privbroadcast":  ("ouroboros.p2p",),
}


# ---------------------------------------------------------------------------
# Live (runtime-mutable) active-category state
# ---------------------------------------------------------------------------
#
# The set of currently-enabled debug categories is held here as process-global
# state so it can be toggled at runtime (Core parity: the ``logging`` RPC
# mutates ``BCLog::Logger::m_categories`` in-memory, taking effect immediately
# without restart).  ``_CategoryFilter`` consults this set on EVERY record
# rather than snapshotting it at construction, so a filter instance already
# attached to a handler honours a category flip the instant the set changes.
#
# Empty set  -> no DEBUG records pass (just INFO+ everywhere).
# Full set   -> every DEBUG record passes ("all").
_ACTIVE_CATEGORIES: set[str] = set()


def _resolve_allowed_loggers(cats: set[str]) -> set[str]:
    """Expand a set of category names to the logger-name prefixes they gate."""
    allowed: set[str] = set()
    for cat in cats:
        for prefix in _CATEGORY_TO_LOGGERS.get(cat, ()):
            allowed.add(prefix)
        # Also allow a free-form match on logger-name suffix.
        allowed.add(f"ouroboros.{cat}")
    return allowed


def get_active_categories() -> set[str]:
    """Return a copy of the currently-enabled debug categories."""
    return set(_ACTIVE_CATEGORIES)


def set_active_categories(categories: Iterable[str]) -> None:
    """Replace the active debug-category set (takes effect immediately).

    Also brings the root logger level up to DEBUG when any category is
    active (otherwise no DEBUG records are produced for the filter to pass),
    and back down to INFO when the set is emptied — mirroring how
    ``configure_logging`` derives the level from the category set.
    """
    global _ACTIVE_CATEGORIES
    _ACTIVE_CATEGORIES = set(categories)
    root = logging.getLogger()
    if _ACTIVE_CATEGORIES:
        if root.level > logging.DEBUG:
            root.setLevel(logging.DEBUG)
    # NB: we never lower an explicitly-requested DEBUG level here; configure_
    # logging owns the baseline.  When the set empties, the filter simply
    # stops passing DEBUG records, which is the same observable result.


def enable_category(name: str) -> None:
    """Enable a single category (or all of them for the ALL token)."""
    from ouroboros.daemon import DEBUG_CATEGORIES  # local import: avoid cycle
    if name in _ALL_TOKENS:
        set_active_categories(DEBUG_CATEGORIES)
    else:
        set_active_categories(_ACTIVE_CATEGORIES | {name})


def disable_category(name: str) -> None:
    """Disable a single category (or all of them for the ALL token)."""
    if name in _ALL_TOKENS:
        set_active_categories(set())
    else:
        set_active_categories(_ACTIVE_CATEGORIES - {name})


# Core's special input-only tokens that expand to the full category mask
# (logging.cpp: "all", "1", and the empty string "").  These are accepted as
# inputs but are NEVER emitted as output keys.
_ALL_TOKENS: frozenset[str] = frozenset({"all", "1", ""})


class _CategoryFilter(logging.Filter):
    """Filter records so only logs from selected categories are emitted at DEBUG.

    INFO and above are always allowed through (parity with Core's
    ``LogPrintLevel`` semantics — DEBUG is the gated level).  The active
    category set is read live from ``_ACTIVE_CATEGORIES`` on every record so
    runtime toggles (the ``logging`` RPC) take effect with no restart.
    Empty set means no DEBUG records pass — i.e. just INFO+ everywhere.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.INFO:
            return True
        cats = _ACTIVE_CATEGORIES
        if not cats:
            return False
        from ouroboros.daemon import DEBUG_CATEGORIES  # local import: avoid cycle
        if cats >= set(DEBUG_CATEGORIES):
            return True
        # DEBUG-level: only let through if the logger name matches an
        # enabled category's logger prefix.
        for prefix in _resolve_allowed_loggers(cats):
            if record.name == prefix or record.name.startswith(prefix + "."):
                return True
        return False


# Globals so SIGHUP can reopen the file handler without rebuilding everything.
_FILE_HANDLER: logging.handlers.RotatingFileHandler | None = None
_LOG_FILE_PATH: str | None = None


def configure_logging(
    *,
    debug: bool = False,
    json_format: bool = False,
    log_file: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    debug_categories: Iterable[str] | None = None,
    print_to_console: bool = True,
) -> None:
    """
    Configure root logger for the process.

    Args:
        debug: Use DEBUG level (default INFO).
        json_format: Emit JSON lines instead of plain text.
        log_file: Optional path for a rotating log file.
        max_bytes: Max size per log file before rotation.
        backup_count: Number of rotated files to keep.
        debug_categories: When non-empty, DEBUG logs are filtered to
            this set of Core-style categories.  Implies ``debug=True``
            (otherwise no DEBUG records are produced to be filtered).
        print_to_console: Attach a stderr StreamHandler.  When False
            and ``log_file`` is set, logs only go to the file.
    """
    global _FILE_HANDLER, _LOG_FILE_PATH

    cats = set(debug_categories or ())
    effective_debug = debug or bool(cats)
    level = logging.DEBUG if effective_debug else logging.INFO
    formatter: logging.Formatter = (
        JSONFormatter() if json_format else logging.Formatter(_PLAIN_FMT)
    )

    # Seed the process-global active-category state from startup config so the
    # ``logging`` RPC reports & toggles relative to the -debug startup flags.
    set_active_categories(cats)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    # Drop any prior category filters at the logger level (legacy).
    for f in list(root.filters):
        if isinstance(f, _CategoryFilter):
            root.removeFilter(f)

    # Filters on a Logger only fire for direct logger.handle() calls — they
    # do NOT apply to records propagating up from child loggers.  Handler-
    # level filters DO apply to every record reaching the handler, so we
    # attach the category filter there instead.  The filter is ALWAYS attached
    # (even when no categories are enabled at startup) so the ``logging`` RPC
    # can enable a category at runtime and have it take effect immediately —
    # the filter reads the live _ACTIVE_CATEGORIES set on each record.
    cat_filter = _CategoryFilter()

    if print_to_console:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        console.addFilter(cat_filter)
        root.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(path),
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(cat_filter)
        root.addHandler(file_handler)
        _FILE_HANDLER = file_handler
        _LOG_FILE_PATH = str(path)
    else:
        _FILE_HANDLER = None
        _LOG_FILE_PATH = None


def reopen_log_file() -> bool:
    """Close + reopen the active rotating file handler.

    Used by the SIGHUP handler so logrotate can rename + signal
    without restarting the node (parity with Bitcoin Core, which
    re-opens its debug.log on SIGHUP).  Returns True if a handler
    was actually reopened.
    """
    global _FILE_HANDLER
    if _FILE_HANDLER is None or _LOG_FILE_PATH is None:
        return False
    try:
        _FILE_HANDLER.close()
    except Exception:
        pass
    new_handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE_PATH,
        maxBytes=_FILE_HANDLER.maxBytes,
        backupCount=_FILE_HANDLER.backupCount,
    )
    new_handler.setFormatter(_FILE_HANDLER.formatter)
    new_handler.setLevel(_FILE_HANDLER.level)
    # Carry any handler-level filters across the reopen (notably the
    # category filter; without this SIGHUP would silently broaden logging).
    for f in list(_FILE_HANDLER.filters):
        new_handler.addFilter(f)
    root = logging.getLogger()
    # Replace the old handler in place to keep ordering stable.
    for i, h in enumerate(list(root.handlers)):
        if h is _FILE_HANDLER:
            root.handlers[i] = new_handler
            break
    else:
        root.addHandler(new_handler)
    _FILE_HANDLER = new_handler
    return True
