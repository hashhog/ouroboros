"""
Integration tests for BIP-39 mnemonic wiring in :mod:`ouroboros.wallet`.

The pure-BIP-39 algorithmic tests live in :mod:`tests.test_bip39`. This
file covers the wallet glue:
  * ``Wallet.init_hd(mnemonic=...)`` derives the same seed as
    ``bip39.mnemonic_to_seed`` would.
  * ``Wallet.restore_from_mnemonic`` produces deterministic addresses
    across two independent wallet instances given the same mnemonic +
    BIP-39 passphrase.
  * ``Wallet.get_mnemonic`` round-trips through wallet save/load.
  * ``WalletManager.create_wallet`` defaults to a fresh BIP-39 mnemonic.
  * The legacy raw-seed path still works and reports no mnemonic.
"""

from __future__ import annotations

import tempfile

import pytest

from ouroboros.bip39 import mnemonic_to_seed
from ouroboros.wallet import HDKey, Wallet, WalletManager


V1_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)
V1_SEED_HEX = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)


def _new_wallet(name: str = "w1") -> tuple[Wallet, str]:
    """Create an empty Wallet in a fresh tempdir; return (wallet, datadir)."""
    tmp = tempfile.mkdtemp()
    w = Wallet(data_dir=tmp, network="mainnet", name=name)
    return w, tmp


def test_init_hd_with_mnemonic_uses_bip39_seed():
    """init_hd(mnemonic=...) must derive its seed via PBKDF2, not random."""
    w, _ = _new_wallet()
    w.init_hd(mnemonic=V1_MNEMONIC, bip39_passphrase="TREZOR", pool_size=10)

    expected_seed = bytes.fromhex(V1_SEED_HEX)
    assert w._hd_seed == expected_seed
    assert w._hd_seed == mnemonic_to_seed(V1_MNEMONIC, "TREZOR")

    words, pw = w.get_mnemonic()
    assert words == V1_MNEMONIC.split()
    assert pw == "TREZOR"


def test_init_hd_rejects_both_seed_and_mnemonic():
    w, _ = _new_wallet()
    with pytest.raises(ValueError):
        w.init_hd(seed=bytes(32), mnemonic=V1_MNEMONIC)
    with pytest.raises(ValueError):
        w.init_hd()  # neither


def test_init_hd_with_raw_seed_has_no_mnemonic():
    """The legacy raw-seed path must report (None, None) for get_mnemonic."""
    w, _ = _new_wallet()
    w.init_hd(seed=bytes(32), pool_size=10)
    assert w.get_mnemonic() == (None, None)


def test_restore_from_mnemonic_matches_init_hd():
    """Two wallets restored from the same mnemonic + passphrase must
    produce identical xprv + identical first BIP-84 address."""
    w1, _ = _new_wallet("w1")
    w2, _ = _new_wallet("w2")
    xprv1 = w1.init_hd(mnemonic=V1_MNEMONIC, bip39_passphrase="TREZOR", pool_size=10)
    xprv2 = w2.restore_from_mnemonic(V1_MNEMONIC, "TREZOR", pool_size=10)
    assert xprv1 == xprv2

    # Also derive an address through the BIP-84 path and compare.
    master1 = HDKey.from_seed(w1._hd_seed, "mainnet")
    master2 = HDKey.from_seed(w2._hd_seed, "mainnet")
    addr1 = master1.derive_path("m/84'/0'/0'/0/0").to_wallet_key().get_p2wpkh_address()
    addr2 = master2.derive_path("m/84'/0'/0'/0/0").to_wallet_key().get_p2wpkh_address()
    assert addr1 == addr2


def test_mnemonic_persists_across_save_load():
    """Mnemonic survives a round-trip through the wallet JSON file."""
    tmp = tempfile.mkdtemp()
    w = Wallet(data_dir=tmp, network="mainnet", name="w1")
    w.init_hd(mnemonic=V1_MNEMONIC, bip39_passphrase="TREZOR", pool_size=10)
    # Reload from disk
    w2 = Wallet(data_dir=tmp, network="mainnet", name="w1")
    words, pw = w2.get_mnemonic()
    assert words == V1_MNEMONIC.split()
    assert pw == "TREZOR"
    assert w2._hd_seed == bytes.fromhex(V1_SEED_HEX)


def test_wallet_manager_create_wallet_generates_mnemonic_by_default():
    """Fresh wallets created via WalletManager must have a recoverable mnemonic."""
    tmp = tempfile.mkdtemp()
    mgr = WalletManager(data_dir=tmp, network="mainnet")
    wallet, warnings = mgr.create_wallet(name="fresh")
    assert wallet is not None
    words, pw = wallet.get_mnemonic()
    assert words is not None
    assert len(words) == 12
    assert pw == ""
    # Reload and check persistence
    mgr2 = WalletManager(data_dir=tmp, network="mainnet")
    wallet_loaded, _ = mgr2.load_wallet(name="fresh")
    assert wallet_loaded.get_mnemonic()[0] == words


def test_wallet_manager_restore_from_mnemonic_via_create_wallet():
    """Passing mnemonic= to create_wallet must restore from that exact phrase."""
    tmp = tempfile.mkdtemp()
    mgr = WalletManager(data_dir=tmp, network="mainnet")
    wallet, _ = mgr.create_wallet(
        name="restored",
        mnemonic=V1_MNEMONIC,
        bip39_passphrase="TREZOR",
    )
    assert wallet is not None
    assert wallet._hd_seed == bytes.fromhex(V1_SEED_HEX)
    words, pw = wallet.get_mnemonic()
    assert words == V1_MNEMONIC.split()
    assert pw == "TREZOR"


def test_wallet_manager_rejects_invalid_mnemonic():
    """Garbage mnemonic must surface as a ValueError, not corrupt a wallet dir."""
    tmp = tempfile.mkdtemp()
    mgr = WalletManager(data_dir=tmp, network="mainnet")
    with pytest.raises(Exception):
        mgr.create_wallet(name="bad", mnemonic="this is not a real mnemonic phrase")
