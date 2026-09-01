"""Tests for the ouroboros operational-parity CLI surface.

Covers W26 ops-parity gaps: --daemon (just the helper, not actual fork),
PID file, SIGHUP log reopen, --debug=<categories>, --printtoconsole,
sd_notify, and the --reindex acknowledged-but-deferred flag.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from ouroboros.cli import cli
from ouroboros.daemon import (
    DEBUG_CATEGORIES,
    PidFile,
    parse_debug_categories,
    sd_notify,
    sd_notify_ready,
    sd_notify_status,
    sd_notify_stopping,
)
from ouroboros.logging_config import (
    _CategoryFilter,
    configure_logging,
    get_active_categories,
    reopen_log_file,
    set_active_categories,
)


# ---------------------------------------------------------------------------
# parse_debug_categories
# ---------------------------------------------------------------------------

def test_parse_debug_none_disables():
    assert parse_debug_categories(None) == set()
    assert parse_debug_categories("") == set()
    assert parse_debug_categories("0") == set()


def test_parse_debug_all_or_one_means_every_category():
    assert parse_debug_categories("1") == set(DEBUG_CATEGORIES)
    assert parse_debug_categories("all") == set(DEBUG_CATEGORIES)
    assert parse_debug_categories("ALL") == set(DEBUG_CATEGORIES)


def test_parse_debug_categories_csv():
    parsed = parse_debug_categories("net, mempool ,validation")
    assert parsed == {"net", "mempool", "validation"}


def test_parse_debug_unknown_kept_but_warns(caplog):
    with caplog.at_level(logging.WARNING):
        parsed = parse_debug_categories("net,florp")
    assert parsed == {"net", "florp"}
    assert any("Unknown debug category" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# PidFile
# ---------------------------------------------------------------------------

def test_pidfile_write_and_remove(tmp_path):
    pidpath = tmp_path / "node.pid"
    pf = PidFile(pidpath)
    pf.write()
    assert pidpath.exists()
    assert pidpath.read_text().strip() == str(os.getpid())
    pf.remove()
    assert not pidpath.exists()


def test_pidfile_remove_only_when_owned(tmp_path):
    pidpath = tmp_path / "node.pid"
    pidpath.write_text("99999\n")
    # We didn't write it, so remove() must not unlink it.
    pf = PidFile(pidpath)
    pf.remove()
    assert pidpath.exists()


def test_pidfile_stale_overwrite(tmp_path):
    pidpath = tmp_path / "node.pid"
    # PID 1 always exists; using a clearly-dead PID instead.
    pidpath.write_text("999999\n")
    pf = PidFile(pidpath)
    pf.write()  # should NOT raise — stale entry
    assert pidpath.read_text().strip() == str(os.getpid())
    pf.remove()


def test_pidfile_owned_by_live_process_raises(tmp_path):
    pidpath = tmp_path / "node.pid"
    # Our own PID is alive but isn't us-as-PidFile-owner.  Use the
    # parent PID so _stale() reports "live but not us".
    pidpath.write_text(f"{os.getppid()}\n")
    pf = PidFile(pidpath)
    with pytest.raises(RuntimeError, match="already owned"):
        pf.write()


# ---------------------------------------------------------------------------
# sd_notify
# ---------------------------------------------------------------------------

def test_sd_notify_noop_without_env(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert sd_notify("READY=1") is False
    assert sd_notify_ready() is False
    assert sd_notify_stopping() is False
    assert sd_notify_status("foo") is False


def test_sd_notify_sends_datagram(tmp_path, monkeypatch):
    sockpath = tmp_path / "notify.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(str(sockpath))
    srv.settimeout(1.0)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", str(sockpath))
        assert sd_notify_ready("ouroboros up") is True
        data, _ = srv.recvfrom(4096)
        text = data.decode("utf-8")
        assert "READY=1" in text
        assert "STATUS=ouroboros up" in text
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# Logging — categories + reopen
# ---------------------------------------------------------------------------

@pytest.fixture
def _restore_categories():
    # _CategoryFilter reads the live module-global category set (so the
    # ``logging`` RPC can toggle at runtime); restore it after each test.
    saved = get_active_categories()
    yield
    set_active_categories(saved)


def test_category_filter_blocks_debug_outside_category(_restore_categories):
    set_active_categories({"net"})
    flt = _CategoryFilter()

    def make(name, level=logging.DEBUG):
        return logging.LogRecord(name, level, __file__, 0, "x", None, None)

    assert flt.filter(make("ouroboros.p2p")) is True   # net category
    assert flt.filter(make("ouroboros.peer")) is True  # net category
    assert flt.filter(make("ouroboros.mempool")) is False
    # INFO+ is always allowed regardless of category
    assert flt.filter(make("ouroboros.mempool", logging.INFO)) is True


def test_category_filter_all_passes_through(_restore_categories):
    set_active_categories(set(DEBUG_CATEGORIES))
    flt = _CategoryFilter()
    rec = logging.LogRecord("ouroboros.anything", logging.DEBUG,
                            __file__, 0, "x", None, None)
    assert flt.filter(rec) is True


def test_log_file_reopen_creates_new_handle(tmp_path):
    log_path = tmp_path / "ouroboros.log"
    configure_logging(log_file=str(log_path), print_to_console=False)
    logging.getLogger("ouroboros.test").info("first")
    assert log_path.exists()

    # Simulate logrotate: rename the active file out of the way.
    rotated = tmp_path / "ouroboros.log.1"
    log_path.rename(rotated)
    assert reopen_log_file() is True

    logging.getLogger("ouroboros.test").info("after-rotate")
    # New file at the original path; rotated file untouched.
    assert log_path.exists()
    assert "after-rotate" in log_path.read_text()
    assert "first" in rotated.read_text()


def test_print_to_console_false_only_writes_file(tmp_path):
    log_path = tmp_path / "ouroboros.log"
    configure_logging(log_file=str(log_path), print_to_console=False)
    root = logging.getLogger()
    # Only a RotatingFileHandler should be attached.
    handler_types = [type(h).__name__ for h in root.handlers]
    assert "StreamHandler" not in handler_types
    assert "RotatingFileHandler" in handler_types


# ---------------------------------------------------------------------------
# CLI surface — group flags accept new options without errors
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def _restore_event_loop():
    """Click + asyncio.run() in our test scaffolding closes the event loop;
    later tests that use asyncio.get_event_loop() will explode otherwise.
    Re-install a fresh loop after each test in this file.
    """
    import asyncio
    yield
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
    except Exception:
        pass


def test_cli_group_help_lists_new_flags(runner):
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0, res.output
    assert "--debug" in res.output
    assert "--printtoconsole" in res.output


def test_start_help_lists_new_flags(runner):
    res = runner.invoke(cli, ["start", "--help"])
    assert res.exit_code == 0, res.output
    assert "--daemon" in res.output
    assert "--pid" in res.output
    assert "--reindex" in res.output


def test_debug_csv_parsed_in_ctx(runner, tmp_path):
    # `status` is a cheap sub-command that exits without forking the node.
    # We just want to verify --debug=net,mempool doesn't crash arg parsing.
    res = runner.invoke(
        cli,
        [
            "--data-dir", str(tmp_path),
            "--debug=net,mempool",
            "status",
        ],
    )
    # ``status`` opens the DB / mempool; that may print errors, but the
    # CLI itself must not crash on arg parsing.
    # We accept exit_code == 0 OR a DB-init error — both prove parsing.
    assert "--debug" not in res.output  # not a help dump
    # The category filter installs (on at least one handler) without exception.
    handler_filters: list[_CategoryFilter] = []
    for h in logging.getLogger().handlers:
        for f in h.filters:
            if isinstance(f, _CategoryFilter):
                handler_filters.append(f)
    assert handler_filters, (
        "Expected a _CategoryFilter to be installed on a handler "
        "by --debug=net,mempool"
    )
    # The filter has no per-instance state any more; the parsed CSV lands
    # in the live category set it reads from.
    assert {"net", "mempool"} <= get_active_categories()


def test_reindex_flag_warns_but_doesnt_crash(runner, tmp_path, monkeypatch):
    """--reindex runs the warning branch and exits without crashing."""
    import ouroboros.cli as cli_mod

    class _StubNode:
        def __init__(self, *a, **kw): pass
        async def run(self): return
        async def stop(self): return

    monkeypatch.setattr(cli_mod, "BitcoinNode", _StubNode)
    monkeypatch.setattr(cli_mod, "SyncManager", lambda *a, **kw: type(
        "S", (), {"is_synced": lambda self: True}
    )())

    # Stub asyncio.run so we don't actually drive an event loop —
    # that closes the running loop and breaks unrelated test modules.
    monkeypatch.setattr(cli_mod.asyncio, "run", lambda coro: None)

    res = runner.invoke(
        cli,
        [
            "--data-dir", str(tmp_path),
            "start",
            "--force",
            "--reindex",
            "--rpc-port", "0",
            "--p2p-port", "0",
        ],
        catch_exceptions=False,
    )
    # The warning text should be emitted regardless of the rest.
    assert "reindex" in res.output.lower()


def test_pidfile_written_via_start(runner, tmp_path, monkeypatch):
    """`start` writes the pid file and removes it on graceful exit."""
    import ouroboros.cli as cli_mod

    class _StubNode:
        def __init__(self, *a, **kw): pass
        async def run(self): return
        async def stop(self): return

    monkeypatch.setattr(cli_mod, "BitcoinNode", _StubNode)
    monkeypatch.setattr(cli_mod, "SyncManager", lambda *a, **kw: type(
        "S", (), {"is_synced": lambda self: True}
    )())

    # Spy on PidFile to confirm write/remove ordering without depending
    # on filesystem race.  Also avoids us needing to stand up a real
    # event loop here (see test_reindex_flag_… for rationale).
    monkeypatch.setattr(cli_mod.asyncio, "run", lambda coro: None)

    writes: list[str] = []
    removes: list[str] = []

    real_pidfile = cli_mod.PidFile

    class _SpyPidFile(real_pidfile):
        def write(self):
            writes.append(str(self.path))
            super().write()

        def remove(self):
            removes.append(str(self.path))
            super().remove()

    monkeypatch.setattr(cli_mod, "PidFile", _SpyPidFile)

    pid_path = tmp_path / "custom.pid"
    res = runner.invoke(
        cli,
        [
            "--data-dir", str(tmp_path),
            "start",
            "--force",
            "--pid", str(pid_path),
            "--rpc-port", "0",
            "--p2p-port", "0",
        ],
        catch_exceptions=False,
    )
    assert writes == [str(pid_path)], f"PidFile.write() not called; output={res.output}"
    assert removes == [str(pid_path)], f"PidFile.remove() not called; output={res.output}"
    # Removed cleanly: file should not exist now.
    assert not pid_path.exists()
