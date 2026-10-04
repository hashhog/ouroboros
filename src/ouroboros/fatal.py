"""System errors during validation: never a verdict, retry once, then halt.

Gate 6 (docs/RELEASE-CHECKLIST.md): OOM, heap caps, timeouts and I/O failures
lead to retry or halt, never to a reject or an accept.

Bitcoin Core's model (bitcoin-core/src):

* A script check reports only ``ScriptError`` values (``CScriptCheck``,
  ``CCheckQueue``); ``bad_alloc`` terminates the process.
* A coins-DB read error goes through ``CCoinsViewErrorCatcher``
  (coins.cpp:415-427), whose callback aborts the node.
* A failed block read / flush / write is ``FatalError`` -> ``AbortNode``
  (validation.cpp:2136, :3021, :2779-2836): the block is never marked invalid
  and the delivering peer is never punished (``MaybePunishNodeForBlock`` acts
  only on a ``BlockValidationResult``).

ouroboros signals consensus failures with ``ValueError`` (script interpreter,
Rust ``PyValueError``) or a ``(False, reason)`` tuple, and system failures with
the exception classes in :data:`SYSTEM_ERROR_TYPES` — the Rust storage layer
raises ``PyRuntimeError("Database error: ...")``, an allocation failure is
``MemoryError``, ``asyncio.to_thread`` / ``threading`` raise ``RuntimeError``
("can't start new thread"), the OS raises ``OSError`` (ENOSPC, EIO, EMFILE).

Three outcomes, never two: OK / consensus failure / INTERNAL.  INTERNAL is
retried once by the caller (:func:`retry_once`); if it recurs the caller calls
:func:`abort_node`, which latches a process-wide fatal flag that block connect,
submitblock and the mempool check (:func:`raise_if_fatal`) and asks the node to
exit non-zero (systemd restarts it).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

#: Marker carried by every string form of an internal error.  The block-reject
#: classifier treats it as a non-verdict BEFORE any keyword mapping, so a system
#: error whose text happens to contain "script" / "input" / "transaction
#: validation" can never be relabelled as a consensus reason.
INTERNAL_ERROR_MARKER = "internal-validation-error"

#: Process exit status after :func:`abort_node` (Core: EXIT_FAILURE).
EXIT_CODE_FATAL = 1


class InternalValidationError(Exception):
    """A system fault while validating (DB read, OOM, thread, FFI, I/O).

    Never a verdict on the block or transaction: do not mark it failed, do not
    punish the peer, do not insert it into recent-rejects, never skip checks.
    """

    def __init__(self, message: str):
        if INTERNAL_ERROR_MARKER not in message:
            message = f"{INTERNAL_ERROR_MARKER}: {message}"
        super().__init__(message)


#: Exception classes that mean "the node could not decide", not "invalid".
#: RuntimeError covers the Rust storage layer (PyRuntimeError "Database
#: error: ..."), thread-start failure and RecursionError.  Holds that subclass
#: RuntimeError (MissingAncestorHeaderError) opt out via ``_ouroboros_hold``.
SYSTEM_ERROR_TYPES: tuple[type[BaseException], ...] = (
    InternalValidationError,
    MemoryError,
    OSError,
    SystemError,
    RuntimeError,
)


def is_system_error(exc: BaseException) -> bool:
    """True when *exc* is a system fault rather than a consensus failure."""
    if getattr(type(exc), "_ouroboros_hold", False):
        return False
    if isinstance(exc, NotImplementedError):
        # A RuntimeError subclass, but a code path that does not exist — not a
        # resource failure.  Callers treat it like any other unexpected bug.
        return False
    return isinstance(exc, SYSTEM_ERROR_TYPES)


def is_internal_error_text(text: str | None) -> bool:
    """True when a stringified failure carries the internal-error marker."""
    return bool(text) and INTERNAL_ERROR_MARKER in str(text).lower()


def as_internal(exc: BaseException, where: str) -> InternalValidationError:
    """Wrap *exc* as an :class:`InternalValidationError` naming *where*."""
    if isinstance(exc, InternalValidationError):
        return exc
    err = InternalValidationError(f"{where}: {type(exc).__name__}: {exc}")
    err.__cause__ = exc
    return err


def retry_once(fn: Callable[..., Any], *args: Any, where: str, **kwargs: Any) -> Any:
    """Call ``fn(*args, **kwargs)``; on a system error retry ONCE.

    A second system error raises :class:`InternalValidationError` (the caller
    then halts with :func:`abort_node`).  Any other exception — a consensus
    ``ValueError`` included — propagates unchanged on the first attempt.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as first:  # noqa: BLE001 - classified below
        if not is_system_error(first):
            raise
        logger.warning("%s: system error, retrying once: %r", where, first)
    try:
        return fn(*args, **kwargs)
    except Exception as second:  # noqa: BLE001 - classified below
        if not is_system_error(second):
            raise
        raise as_internal(second, where) from second


async def retry_once_async(make_coro: Callable[[], Any], *, where: str) -> Any:
    """Async form of :func:`retry_once`: ``make_coro()`` builds a fresh awaitable."""
    try:
        return await make_coro()
    except Exception as first:  # noqa: BLE001 - classified below
        if not is_system_error(first):
            raise
        logger.warning("%s: system error, retrying once: %r", where, first)
    try:
        return await make_coro()
    except Exception as second:  # noqa: BLE001 - classified below
        if not is_system_error(second):
            raise
        raise as_internal(second, where) from second


# ---------------------------------------------------------------------------
# AbortNode equivalent
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_fatal_reason: str | None = None
_abort_hook: Callable[[str], None] | None = None


def set_abort_hook(hook: Callable[[str], None] | None) -> None:
    """Register the node's shutdown request (called once, from ``Node.start``)."""
    global _abort_hook
    with _lock:
        _abort_hook = hook


def abort_node(reason: str, exc: BaseException | None = None) -> InternalValidationError:
    """Core ``AbortNode``: latch the fatal flag, log, request a non-zero exit.

    Idempotent: only the first reason is kept and the hook fires once.
    Returns an :class:`InternalValidationError` the caller may raise.
    """
    global _fatal_reason
    with _lock:
        first = _fatal_reason is None
        if first:
            _fatal_reason = reason
        hook = _abort_hook
    if first:
        logger.critical(
            "FATAL (AbortNode): %s%s — no further blocks or transactions are "
            "accepted; the node is shutting down with exit status %d",
            reason, f" ({type(exc).__name__}: {exc})" if exc is not None else "",
            EXIT_CODE_FATAL,
        )
        if hook is not None:
            try:
                hook(reason)
            except Exception:  # noqa: BLE001 - the latch is already set
                logger.exception("abort hook failed")
    return InternalValidationError(f"node halted: {reason}")


def is_fatal() -> bool:
    return _fatal_reason is not None


def fatal_reason() -> str | None:
    return _fatal_reason


def raise_if_fatal(where: str) -> None:
    """Refuse work after :func:`abort_node` (connect, submitblock, mempool)."""
    reason = _fatal_reason
    if reason is not None:
        raise InternalValidationError(f"{where} refused: node halted ({reason})")


def _reset_for_tests() -> None:
    global _fatal_reason, _abort_hook
    with _lock:
        _fatal_reason = None
        _abort_hook = None
