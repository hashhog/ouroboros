"""Wallet files are owner-only (0600) and wallet dirs owner-only (0700).

Security audit 2026-10-30, H6: an unencrypted ``wallet.dat`` holds the HD
seed and mnemonic in plain JSON, and ``Wallet._save`` created it with the
process umask (0o022 under the daemon), so the live file was 0664 and any
local account could read every key.  ``backupwallet`` kept that mode on the
copy.  Core sets umask 0077 at startup (common/system.cpp:92-93), so its
wallet files and directories are created owner-only.

Every test runs under umask 0o022 (the daemon's) so it fails on the pre-fix
code, which inherited the umask.
"""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from ouroboros.wallet import Wallet, WalletManager


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def loose_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture
def datadir(tmp_path, loose_umask):
    d = tmp_path / "datadir"
    d.mkdir()
    return d


def test_createwallet_file_0600_dir_0700(datadir):
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    assert wallet is not None
    assert _mode(wallet.wallet_path) == 0o600
    assert _mode(wallet.wallet_path.parent) == 0o700
    assert _mode(datadir / "wallets") == 0o700


def test_save_after_mutation_keeps_0600(datadir):
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    os.chmod(wallet.wallet_path, 0o644)
    asyncio.run(wallet.generate_new_address())
    assert _mode(wallet.wallet_path) == 0o600
    assert not wallet.wallet_path.with_name("wallet.dat.tmp").exists()


def test_save_over_world_readable_tmp_is_0600(datadir):
    """A stale, wider ``wallet.dat.tmp`` must not lend its mode to the save."""
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    tmp = wallet.wallet_path.with_name("wallet.dat.tmp")
    tmp.write_text("{}")
    os.chmod(tmp, 0o666)
    wallet._save()
    assert _mode(wallet.wallet_path) == 0o600


def test_backupwallet_copy_is_0600(datadir, tmp_path):
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    dest = tmp_path / "backup.dat"
    wallet.backup(str(dest))
    assert _mode(dest) == 0o600
    assert dest.read_bytes() == wallet.wallet_path.read_bytes()


def test_backupwallet_over_existing_world_readable_file_is_0600(datadir, tmp_path):
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    dest = tmp_path / "backup.dat"
    dest.write_text("old")
    os.chmod(dest, 0o644)
    wallet.backup(str(dest))
    assert _mode(dest) == 0o600
    assert dest.read_bytes() == wallet.wallet_path.read_bytes()


def test_load_tightens_existing_loose_wallet(datadir):
    """A wallet written by the old code (0664 file, 0775 dir) is fixed on load."""
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    mgr.unload_wallet("w1")
    os.chmod(wallet.wallet_path, 0o664)
    os.chmod(wallet.wallet_path.parent, 0o775)

    mgr2 = WalletManager(str(datadir), "regtest")
    loaded, _ = mgr2.load_wallet("w1")
    assert _mode(loaded.wallet_path) == 0o600
    assert _mode(loaded.wallet_path.parent) == 0o700


def test_restorewallet_file_0600_dir_0700(datadir, tmp_path):
    mgr = WalletManager(str(datadir), "regtest")
    wallet, _ = mgr.create_wallet("w1")
    backup = tmp_path / "backup.dat"
    wallet.backup(str(backup))
    os.chmod(backup, 0o644)

    restored, _ = mgr.restore_wallet("w2", str(backup))
    assert _mode(restored.wallet_path) == 0o600
    assert _mode(restored.wallet_path.parent) == 0o700


def test_legacy_single_file_wallet_0600(datadir):
    w = Wallet(data_dir=str(datadir), network="regtest", name="legacy")
    assert w.wallet_path == datadir / "wallets" / "legacy.json"
    assert _mode(w.wallet_path) == 0o600
    assert _mode(w.wallet_path.parent) == 0o700


def test_existing_datadir_mode_untouched(datadir):
    """Only wallet paths are tightened; the datadir itself is left alone."""
    os.chmod(datadir, 0o755)
    WalletManager(str(datadir), "regtest").create_wallet("w1")
    assert _mode(datadir) == 0o755
