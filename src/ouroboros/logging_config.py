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


class _CategoryFilter(logging.Filter):
    """Filter records so only logs from selected categories are emitted at DEBUG.

    INFO and above are always allowed through (parity with Core's
    ``LogPrintLevel`` semantics — DEBUG is the gated level).  Empty
    set means no DEBUG records pass — i.e. just INFO+ everywhere.
    """

    def __init__(self, categories: Iterable[str]):
        super().__init__()
        self.allowed_loggers: set[str] = set()
        self.all = False
        cats = set(categories)
        from ouroboros.daemon import DEBUG_CATEGORIES  # local import: avoid cycle at module load
        if cats >= set(DEBUG_CATEGORIES):
            self.all = True
            return
        for cat in cats:
            for prefix in _CATEGORY_TO_LOGGERS.get(cat, ()):
                self.allowed_loggers.add(prefix)
            # Also allow free-form match on logger name suffix.
            self.allowed_loggers.add(f"ouroboros.{cat}")

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.INFO:
            return True
        if self.all:
            return True
        # DEBUG-level: only let through if the logger name matches.
        for prefix in self.allowed_loggers:
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
    # attach the category filter there instead.
    cat_filter = _CategoryFilter(cats) if cats else None

    if print_to_console:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        if cat_filter is not None:
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
        if cat_filter is not None:
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
