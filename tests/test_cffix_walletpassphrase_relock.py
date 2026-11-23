"""An unlocked encrypted wallet must relock, and re-keying needs the old passphrase.

Three holes left an encrypted wallet open to any later RPC caller:

* ``encryptwallet`` left the wallet unlocked.  Core's ``CWallet::EncryptWallet``
  ends with ``Lock()`` (wallet/wallet.cpp), so a freshly encrypted wallet is
  locked until ``walletpassphrase``.
* ``walletpassphrase`` ignored its ``timeout``.  Core (wallet/rpc/encrypt.cpp)
  sets ``nRelockTime`` and schedules a callback ``timeout`` seconds out that
  locks the wallet again, unless a newer ``walletpassphrase`` or a
  ``walletlock`` replaced that relock time.
* ``walletpassphrasechange`` checked the old passphrase only while the wallet
  was locked.  Core's ``CWallet::ChangeWalletPassphrase`` locks first and then
  decrypts the master key with the old passphrase, so a wrong old passphrase
  fails (RPC_WALLET_PASSPHRASE_INCORRECT, -14) even on an unlocked wallet.

The relock is driven through an event loop whose clock the test moves by
hand, so no test waits in real time.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from ouroboros.rpc import RPCServer
from ouroboros.wallet import WalletManager

PASS = "pw"
SEED = bytes(range(32))


class _ManualClockLoop(asyncio.SelectorEventLoop):
    """Event loop whose ``time()`` only moves when the test advances it."""

    def __init__(self) -> None:
        super().__init__()
        self._now = 1000.0

    def time(self) -> float:  # noqa: D401 - asyncio API
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds
        # Let the loop run every callback whose time has come.
        self.run_until_complete(asyncio.sleep(0))
        self.run_until_complete(asyncio.sleep(0))


def _rpc(wallet):
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(wallet=wallet, network="regtest")
    server._current_wallet_name = None
    return server


def _error(result):
    """The JSON-RPC error dict of an RPC handler's return value, or None."""
    return getattr(result, "error", None)


def _hd_wallet(tmp_path):
    mgr = WalletManager(str(tmp_path), network="regtest")
    wallet, _ = mgr.create_wallet("w", blank=True)
    wallet.init_hd(SEED)
    return wallet


def _encrypted(tmp_path, loop):
    wallet = _hd_wallet(tmp_path)
    res = loop.run_until_complete(_rpc(wallet).rpc_encryptwallet(PASS))
    assert _error(res) is None, res
    return wallet


def _locked(tmp_path, loop):
    """An encrypted wallet in the locked state, whatever encryptwallet left.

    The timeout and passphrase-change tests start from a locked wallet so each
    of them fails on its own bug, not on encryptwallet's.
    """
    wallet = _encrypted(tmp_path, loop)
    if not wallet.is_locked:
        wallet.lock()
    return wallet


def test_encryptwallet_leaves_wallet_locked(tmp_path):
    loop = _ManualClockLoop()
    try:
        wallet = _encrypted(tmp_path, loop)
        assert wallet.is_encrypted
        assert wallet.is_locked, "encryptwallet left the wallet unlocked"
        assert wallet.keys == [] and wallet._hd_seed is None
        assert json.loads(wallet.wallet_path.read_text())["encrypted"] is True
    finally:
        loop.close()


def test_walletpassphrase_relocks_after_timeout(tmp_path):
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)
        res = loop.run_until_complete(server.rpc_walletpassphrase(PASS, 1))
        assert _error(res) is None, res
        assert not wallet.is_locked
        assert wallet._hd_seed == SEED

        loop.advance(0.5)
        assert not wallet.is_locked, "relocked before the timeout"

        loop.advance(1.0)
        assert wallet.is_locked, "walletpassphrase timeout never relocked the wallet"
        assert wallet._hd_seed is None and wallet.keys == []
    finally:
        loop.close()


def test_walletlock_cancels_pending_relock(tmp_path):
    """Core: walletlock sets nRelockTime = 0, so the old callback is a no-op
    and cannot lock a wallet that was unlocked again after it."""
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)
        assert _error(loop.run_until_complete(server.rpc_walletpassphrase(PASS, 1))) is None
        assert _error(loop.run_until_complete(server.rpc_walletlock())) is None
        assert wallet.is_locked
        assert _error(loop.run_until_complete(server.rpc_walletpassphrase(PASS, 100))) is None

        loop.advance(2.0)
        assert not wallet.is_locked, "a stale relock locked the newer unlock early"
        loop.advance(100.0)
        assert wallet.is_locked
    finally:
        loop.close()


def test_walletpassphrase_again_renews_timeout(tmp_path):
    """Core: walletpassphrase on an unlocked wallet with the right passphrase
    succeeds and its relock time replaces the earlier one."""
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)
        assert _error(loop.run_until_complete(server.rpc_walletpassphrase(PASS, 1))) is None
        res = loop.run_until_complete(server.rpc_walletpassphrase(PASS, 100))
        assert _error(res) is None, res
        bad = loop.run_until_complete(server.rpc_walletpassphrase("wrong", 100))
        assert _error(bad) is not None and _error(bad)["code"] == -14, bad

        loop.advance(2.0)
        assert not wallet.is_locked, "the earlier 1 s relock still fired"
        loop.advance(100.0)
        assert wallet.is_locked
    finally:
        loop.close()


def test_passphrasechange_empty_passphrase_is_invalid_parameter(tmp_path):
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)
        for old, new in (("", "x"), (PASS, "")):
            err = _error(loop.run_until_complete(server.rpc_walletpassphrasechange(old, new)))
            assert err == {"code": -8, "message": "passphrase cannot be empty"}, err
    finally:
        loop.close()


def test_walletpassphrase_rejects_negative_timeout(tmp_path):
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        res = loop.run_until_complete(_rpc(wallet).rpc_walletpassphrase(PASS, -1))
        err = _error(res)
        assert err is not None and err["code"] == -8, res
        assert err["message"] == "Timeout cannot be negative."
        assert wallet.is_locked
    finally:
        loop.close()


def test_passphrasechange_on_unlocked_wallet_checks_old_passphrase(tmp_path):
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)
        loop.run_until_complete(server.rpc_walletpassphrase(PASS, 600))

        res = loop.run_until_complete(server.rpc_walletpassphrasechange("wrong", "evil"))
        err = _error(res)
        assert err is not None, "re-keyed an unlocked wallet without the old passphrase"
        assert err["code"] == -14
        assert err["message"] == "Error: The wallet passphrase entered was incorrect."

        # 'pw' still opens the wallet on disk; 'evil' does not.
        mgr = WalletManager(str(tmp_path), network="regtest")
        reloaded, _ = mgr.load_wallet("w")
        assert reloaded.is_locked
        reloaded.unlock(PASS)
        assert reloaded._hd_seed == SEED
    finally:
        loop.close()


def test_passphrasechange_with_right_old_passphrase_keeps_unlock_state(tmp_path):
    """Core: ChangeWalletPassphrase restores the lock state it found
    (fWasLocked) -- an unlocked wallet stays unlocked, a locked one locked."""
    loop = _ManualClockLoop()
    try:
        wallet = _locked(tmp_path, loop)
        server = _rpc(wallet)

        assert _error(loop.run_until_complete(server.rpc_walletpassphrasechange(PASS, "p2"))) is None
        assert wallet.is_locked

        assert _error(loop.run_until_complete(server.rpc_walletpassphrase("p2", 600))) is None
        assert _error(loop.run_until_complete(server.rpc_walletpassphrasechange("p2", "p3"))) is None
        assert not wallet.is_locked
        assert wallet._hd_seed == SEED

        mgr = WalletManager(str(tmp_path), network="regtest")
        reloaded, _ = mgr.load_wallet("w")
        reloaded.unlock("p3")
        assert reloaded._hd_seed == SEED
    finally:
        loop.close()
