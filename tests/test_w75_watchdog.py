"""Unit tests for the W75-WATCHDOG block-accept wedge diagnostic.

Background: the 2026-04-14..19 incident had this process accept headers
and request blocks for 5 days without the in-memory tip ever advancing
past 801188 (see wave47-2026-04-16/W75-OUROBOROS-STALL.md).  The
watchdog added in a580144 surfaces the class of failure in-process so a
recurrence lands one WARN line in the log instead of going silent for
days.

These tests exercise the rate-limited `_check_wedge_watchdog` helper in
isolation — driving `_last_tip_advance` backwards with a wall-clock
offset and asserting the preconditions / rate-limiter behave.
"""

from __future__ import annotations

import logging
import time
from unittest.mock import MagicMock

from ouroboros.block_sync import BlockSync


def _make_block_sync() -> BlockSync:
    """Construct a bare BlockSync with the minimum mocks the watchdog touches."""
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 801188)
    return BlockSync(db=db, validator=MagicMock(), peer_manager=MagicMock())


def test_watchdog_fires_when_all_preconditions_hold(caplog):
    """Stale tip + non-empty headers + non-empty buffer → one WARN."""
    bs = _make_block_sync()
    # Drive the last-advance stamp back past the 300s threshold.
    bs._last_tip_advance = time.time() - 400.0
    # Wedge preconditions: headers queued and blocks buffered.
    bs._validated_headers = [(b"\x00" * 32, MagicMock())]
    bs._ibd_block_buffer = {b"\x11" * 32: (None, b"payload")}
    # Make the buffer-fill counter non-trivial so the log line is
    # representative of the wedge signature.
    bs._blk_received = 22_000_000
    bs._blk_duplicate = 21_999_000
    bs._blk_buffered = 1_000
    bs._blk_connected = 0

    with caplog.at_level(logging.WARNING):
        bs._check_wedge_watchdog()

    w75_lines = [r for r in caplog.records if "[W75-WATCHDOG]" in r.getMessage()]
    assert len(w75_lines) == 1, (
        f"expected exactly one WARN, got {len(w75_lines)}: "
        f"{[r.getMessage() for r in w75_lines]}"
    )
    msg = w75_lines[0].getMessage()
    assert "tip-stall suspected" in msg
    assert "no_advance_for=400s" in msg or "no_advance_for=401s" in msg
    assert "tip=801188" in msg
    assert "conn=0" in msg


def test_watchdog_silent_when_tip_recent():
    """Fresh tip advance → no WARN even if buffer + headers are populated."""
    bs = _make_block_sync()
    bs._last_tip_advance = time.time() - 10.0  # well under 300s
    bs._validated_headers = [(b"\x00" * 32, MagicMock())]
    bs._ibd_block_buffer = {b"\x11" * 32: (None, b"payload")}

    logger = logging.getLogger("ouroboros.block_sync")
    with _capture(logger) as records:
        bs._check_wedge_watchdog()

    assert not any("[W75-WATCHDOG]" in r.getMessage() for r in records)


def test_watchdog_silent_when_no_headers_pending():
    """No validated headers → caught up, stalling is legitimate, no WARN."""
    bs = _make_block_sync()
    bs._last_tip_advance = time.time() - 400.0
    bs._validated_headers = []  # caught up
    bs._ibd_block_buffer = {b"\x11" * 32: (None, b"payload")}

    logger = logging.getLogger("ouroboros.block_sync")
    with _capture(logger) as records:
        bs._check_wedge_watchdog()

    assert not any("[W75-WATCHDOG]" in r.getMessage() for r in records)


def test_watchdog_silent_when_buffer_empty():
    """Empty buffer → downloader-bound, not an accept-path wedge, no WARN."""
    bs = _make_block_sync()
    bs._last_tip_advance = time.time() - 400.0
    bs._validated_headers = [(b"\x00" * 32, MagicMock())]
    bs._ibd_block_buffer = {}  # nothing waiting to connect

    logger = logging.getLogger("ouroboros.block_sync")
    with _capture(logger) as records:
        bs._check_wedge_watchdog()

    assert not any("[W75-WATCHDOG]" in r.getMessage() for r in records)


def test_watchdog_rate_limits_to_once_per_window():
    """Back-to-back calls while still wedged emit only one WARN per window."""
    bs = _make_block_sync()
    bs._last_tip_advance = time.time() - 400.0
    bs._validated_headers = [(b"\x00" * 32, MagicMock())]
    bs._ibd_block_buffer = {b"\x11" * 32: (None, b"payload")}

    logger = logging.getLogger("ouroboros.block_sync")
    with _capture(logger) as records:
        # 50 successive calls, as if sync_loop ran 50 times in the
        # space of a few seconds (possible during IBD's 1s cadence).
        for _ in range(50):
            bs._check_wedge_watchdog()

    w75 = [r for r in records if "[W75-WATCHDOG]" in r.getMessage()]
    assert len(w75) == 1, f"rate limiter failed: got {len(w75)} WARN lines"


def test_watchdog_refires_after_window_elapses():
    """After _wedge_warn_every seconds have passed, a second WARN is allowed."""
    bs = _make_block_sync()
    bs._last_tip_advance = time.time() - 400.0
    bs._validated_headers = [(b"\x00" * 32, MagicMock())]
    bs._ibd_block_buffer = {b"\x11" * 32: (None, b"payload")}

    logger = logging.getLogger("ouroboros.block_sync")
    with _capture(logger) as records:
        bs._check_wedge_watchdog()
        # Back-date the last-warn stamp past the every-window to simulate
        # time passing without restarting the process.
        bs._last_wedge_warn = time.time() - (bs._wedge_warn_every + 1.0)
        bs._check_wedge_watchdog()

    w75 = [r for r in records if "[W75-WATCHDOG]" in r.getMessage()]
    assert len(w75) == 2, f"expected two WARN lines after window, got {len(w75)}"


# ---------------------------------------------------------------------------
# Helper: logging capture that works regardless of pytest's caplog propagation
# ---------------------------------------------------------------------------
class _capture:
    """Attach a temporary handler to a logger and collect LogRecords."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.records: list[logging.LogRecord] = []
        self._prev_level = logger.level
        self._handler: logging.Handler | None = None

    def __enter__(self) -> list[logging.LogRecord]:
        self.logger.setLevel(logging.DEBUG)

        class _H(logging.Handler):
            def __init__(self, sink: list[logging.LogRecord]):
                super().__init__(level=logging.DEBUG)
                self._sink = sink

            def emit(self, record: logging.LogRecord) -> None:
                self._sink.append(record)

        self._handler = _H(self.records)
        self.logger.addHandler(self._handler)
        return self.records

    def __exit__(self, *_exc: object) -> None:
        if self._handler is not None:
            self.logger.removeHandler(self._handler)
        self.logger.setLevel(self._prev_level)
