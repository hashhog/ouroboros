"""A locked encrypted wallet must never be saved as plaintext.

``Wallet._save`` picked the on-disk format from ``self._passphrase`` alone.
A wallet that is encrypted but locked (loaded from disk without
``walletpassphrase``, or unlocked and then locked again) has no passphrase in
memory and no keys either, so every save reached from a locked wallet
replaced the ciphertext with a plaintext file holding no keys: the HD seed was
gone for good.  ``lockunspent`` (persistent), ``unloadwallet``,
``importprivkey`` and ``sethdseed`` all reached that save on a locked wallet.

Core keeps crypted keys as separate database records that are never rewritten
in plaintext (wallet/wallet.cpp, wallet/walletdb.cpp), and the key-writing
RPCs call ``EnsureWalletIsUnlocked`` (wallet/rpc/util.cpp), which answers
RPC_WALLET_UNLOCK_NEEDED (-13).
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from ouroboros.rpc import RPCServer, RpcError
from ouroboros.wallet import WalletKey, WalletManager

PASS = "pw"
SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
TXID = "ab" * 32


def _make_encrypted(tmp_path):
    """Create an HD wallet, encrypt it, return (manager, ciphertext_hex)."""
    mgr = WalletManager(str(tmp_path), network="regtest")
    wallet, _ = mgr.create_wallet("w", blank=True)
    wallet.init_hd(SEED)
    wallet.encrypt(PASS)
    data = json.loads(wallet.wallet_path.read_text())
    assert data["encrypted"] is True
    return mgr, data["ciphertext"]


def _locked_wallet(tmp_path, mode):
    """Return (manager, wallet, original_ciphertext) with *wallet* locked.

    ``reopen``: unload and load again from disk (locked at load).
    ``relock``: unlock and lock again in the same session.
    """
    mgr, ct = _make_encrypted(tmp_path)
    if mode == "reopen":
        mgr = WalletManager(str(tmp_path), network="regtest")
        wallet, _ = mgr.load_wallet("w")
    else:
        wallet = mgr.get_wallet("w")
        wallet.lock()
        wallet.unlock(PASS)
        wallet.lock()
        # lock() re-encrypts with a fresh salt and nonce; that file is the
        # ciphertext every later save of the locked wallet must keep.
        ct = json.loads(wallet.wallet_path.read_text())["ciphertext"]
    assert wallet.is_locked
    return mgr, wallet, ct


def _assert_ciphertext_intact(wallet_path, original_ct):
    data = json.loads(wallet_path.read_text())
    assert data.get("encrypted") is True, "locked wallet was rewritten as plaintext"
    assert data.get("ciphertext") == original_ct
    assert "keys" not in data and "hd" not in data


def _assert_seed_recoverable(tmp_path):
    mgr = WalletManager(str(tmp_path), network="regtest")
    wallet, _ = mgr.load_wallet("w")
    assert wallet.is_locked
    wallet.unlock(PASS)
    assert wallet._hd_seed == SEED


def _rpc(wallet):
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(wallet=wallet, network="regtest")
    server._current_wallet_name = None
    return server


MODES = ["reopen", "relock"]


@pytest.mark.parametrize("mode", MODES)
def test_lock_coin_persistent_keeps_ciphertext(tmp_path, mode):
    _, wallet, ct = _locked_wallet(tmp_path, mode)
    wallet.lock_coin(TXID, 0, persistent=True)
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    _assert_seed_recoverable(tmp_path)


@pytest.mark.parametrize("mode", MODES)
def test_unload_wallet_keeps_ciphertext(tmp_path, mode):
    mgr, wallet, ct = _locked_wallet(tmp_path, mode)
    path = wallet.wallet_path
    mgr.unload_wallet("w")
    _assert_ciphertext_intact(path, ct)
    _assert_seed_recoverable(tmp_path)


@pytest.mark.parametrize("mode", MODES)
def test_importprivkey_on_locked_wallet_needs_unlock(tmp_path, mode):
    _, wallet, ct = _locked_wallet(tmp_path, mode)
    wif = WalletKey(bytes([7]) * 32, "regtest").to_wif()
    with pytest.raises(RpcError) as exc:
        asyncio.run(_rpc(wallet).rpc_importprivkey(wif, "", False))
    assert exc.value.code == -13
    assert wallet.keys == []
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    _assert_seed_recoverable(tmp_path)


@pytest.mark.parametrize("mode", MODES)
def test_sethdseed_on_locked_wallet_needs_unlock(tmp_path, mode):
    _, wallet, ct = _locked_wallet(tmp_path, mode)
    with pytest.raises(RpcError) as exc:
        asyncio.run(_rpc(wallet).rpc_sethdseed(OTHER_SEED.hex()))
    assert exc.value.code == -13
    assert wallet._hd_seed is None
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    _assert_seed_recoverable(tmp_path)


@pytest.mark.parametrize("mode", MODES)
def test_init_hd_on_locked_wallet_refuses(tmp_path, mode):
    """The wallet-level guard, for callers that skip the RPC layer."""
    _, wallet, ct = _locked_wallet(tmp_path, mode)
    with pytest.raises(ValueError):
        wallet.init_hd(OTHER_SEED)
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    _assert_seed_recoverable(tmp_path)


def test_persistent_lock_on_locked_wallet_survives_reload(tmp_path):
    """Core lets lockunspent run on a locked wallet and persists the lock
    (lockunspent has no EnsureWalletIsUnlocked); the lock must not be lost
    and must not cost the ciphertext."""
    _, wallet, ct = _locked_wallet(tmp_path, "reopen")
    wallet.lock_coin(TXID, 1, persistent=True)
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    mgr = WalletManager(str(tmp_path), network="regtest")
    again, _ = mgr.load_wallet("w")
    assert again.is_locked_coin(TXID, 1)
    again.unlock(PASS)
    assert again.is_locked_coin(TXID, 1)
    assert again._hd_seed == SEED


def test_unlocked_save_still_encrypts_and_relocks(tmp_path):
    """Control: an unlocked encrypted wallet still saves fresh ciphertext
    that holds its current state."""
    mgr, ct = _make_encrypted(tmp_path)
    wallet = mgr.get_wallet("w")
    wallet.lock_coin(TXID, 2, persistent=True)
    data = json.loads(wallet.wallet_path.read_text())
    assert data["encrypted"] is True and "hd" not in data
    mgr.unload_wallet("w")
    mgr = WalletManager(str(tmp_path), network="regtest")
    again, _ = mgr.load_wallet("w")
    again.unlock(PASS)
    assert again._hd_seed == SEED
    assert again.is_locked_coin(TXID, 2)


def test_lock_released_while_locked_stays_released(tmp_path):
    """A persistent lock taken while unlocked and released while locked must
    not come back from the ciphertext on unlock or on reload."""
    mgr, _ = _make_encrypted(tmp_path)
    wallet = mgr.get_wallet("w")
    wallet.lock_coin(TXID, 3, persistent=True)
    wallet.lock()
    ct = json.loads(wallet.wallet_path.read_text())["ciphertext"]
    assert wallet.unlock_coin(TXID, 3)
    _assert_ciphertext_intact(wallet.wallet_path, ct)
    wallet.unlock(PASS)
    assert not wallet.is_locked_coin(TXID, 3)
    mgr = WalletManager(str(tmp_path), network="regtest")
    again, _ = mgr.load_wallet("w")
    assert not again.is_locked_coin(TXID, 3)
    again.unlock(PASS)
    assert not again.is_locked_coin(TXID, 3)


def test_older_file_locks_inside_ciphertext_still_load(tmp_path):
    """Files written before locks moved out of the ciphertext keep them only
    inside it; unlock() must still restore them, also after a save taken
    while locked."""
    from ouroboros.wallet import encrypt_wallet_data

    mgr, _ = _make_encrypted(tmp_path)
    wallet = mgr.get_wallet("w")
    inner = {
        "keys": [],
        "hd": {"seed_hex": SEED.hex(), "next_index": 0,
               "base_path": wallet._hd_base_path},
        "locked_coins": [{"txid": TXID, "vout": 4}],
    }
    old = {
        "version": 1, "network": "regtest", "encrypted": True,
        "ciphertext": encrypt_wallet_data(
            json.dumps(inner).encode(), PASS).hex(),
    }
    mgr.unload_wallet("w")
    wallet.wallet_path.write_text(json.dumps(old))
    mgr = WalletManager(str(tmp_path), network="regtest")
    again, _ = mgr.load_wallet("w")
    again.lock_coin(TXID, 5, persistent=True)
    _assert_ciphertext_intact(again.wallet_path, old["ciphertext"])
    mgr = WalletManager(str(tmp_path), network="regtest")
    third, _ = mgr.load_wallet("w")
    third.unlock(PASS)
    assert third._hd_seed == SEED
    assert third.is_locked_coin(TXID, 4)
    assert third.is_locked_coin(TXID, 5)
