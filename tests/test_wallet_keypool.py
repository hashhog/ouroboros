"""
Unit tests for wallet HD key derivation and key pool management.

Tests BIP32/BIP84 key derivation, key pool pre-generation, and address types.
"""

import os
import tempfile

from ouroboros.wallet import (
    HDKey,
    KeyPool,
    Wallet,
    WalletKey,
)


class TestHDKey:
    """Test BIP32 HD key derivation."""

    def test_master_from_seed(self):
        """Test master key derivation from seed."""
        # Test vector from BIP32
        seed = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
        )
        master = HDKey.from_seed(seed, "mainnet")

        assert master.depth == 0
        assert master.parent_fingerprint == b"\x00\x00\x00\x00"
        assert master.child_index == 0
        assert len(master.private_key) == 32
        assert len(master.chain_code) == 32
        assert len(master.public_key) == 33  # compressed

    def test_child_derivation_normal(self):
        """Test normal (non-hardened) child derivation."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "mainnet")
        child = master.derive_child(0, hardened=False)

        assert child.depth == 1
        assert child.parent_fingerprint == master.fingerprint
        assert child.child_index == 0

    def test_child_derivation_hardened(self):
        """Test hardened child derivation."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "mainnet")
        child = master.derive_child(0, hardened=True)

        assert child.depth == 1
        assert child.child_index == 0x80000000  # hardened flag set

    def test_derive_path_bip84(self):
        """Test BIP84 path derivation: m/84'/0'/0'/0/0."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "mainnet")

        # BIP84 native segwit path
        key = master.derive_path("m/84'/0'/0'/0/0")
        assert key.depth == 5

    def test_xprv_serialization(self):
        """Test xprv base58 serialization."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "mainnet")
        xprv = master.serialize_xprv()

        assert xprv.startswith("xprv")  # mainnet

        # Roundtrip
        restored = HDKey.from_xprv(xprv, "mainnet")
        assert restored.private_key == master.private_key
        assert restored.chain_code == master.chain_code

    def test_xpub_serialization(self):
        """Test xpub base58 serialization."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "mainnet")
        xpub = master.serialize_xpub()

        assert xpub.startswith("xpub")  # mainnet

    def test_testnet_serialization(self):
        """Test testnet key serialization."""
        seed = os.urandom(32)
        master = HDKey.from_seed(seed, "testnet")

        xprv = master.serialize_xprv()
        xpub = master.serialize_xpub()

        assert xprv.startswith("tprv")
        assert xpub.startswith("tpub")


class TestKeyPool:
    """Test BIP84 key pool management."""

    def test_init_key_pool(self):
        """Test key pool initialization."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=100)

        assert pool.seed == seed
        assert pool.network == "mainnet"
        assert pool.pool_size == 100
        assert pool.coin_type == 0  # mainnet

    def test_testnet_coin_type(self):
        """Test testnet uses coin type 1."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "testnet")

        assert pool.coin_type == 1

    def test_top_up_generates_keys(self):
        """Test top_up pre-generates keys."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)

        generated = pool.top_up()

        assert generated == 20  # 10 receive + 10 change
        assert len(pool._receive_pool) == 10
        assert len(pool._change_pool) == 10

    def test_get_new_address_receive(self):
        """Test getting a new receive address."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)
        pool.top_up()

        addr, index = pool.get_new_address(is_change=False)

        assert addr.startswith("bc1q")  # P2WPKH bech32
        assert index == 0
        assert 0 in pool._used_receive_indices

    def test_get_new_address_change(self):
        """Test getting a new change address."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)
        pool.top_up()

        addr, index = pool.get_new_address(is_change=True)

        assert addr.startswith("bc1q")
        assert index == 0
        assert 0 in pool._used_change_indices

    def test_address_types(self):
        """Test different address type generation."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)
        pool.top_up()

        # P2WPKH (bech32)
        addr_wpkh, _ = pool.get_new_address(address_type="bech32")
        assert addr_wpkh.startswith("bc1q")

        # P2SH-P2WPKH
        addr_sh, _ = pool.get_new_address(address_type="p2sh-segwit")
        assert addr_sh.startswith("3")

        # P2TR (bech32m)
        addr_tr, _ = pool.get_new_address(address_type="bech32m")
        assert addr_tr.startswith("bc1p")

        # P2PKH (legacy)
        addr_pkh, _ = pool.get_new_address(address_type="legacy")
        assert addr_pkh.startswith("1")

    def test_auto_refill(self):
        """Test key pool auto-refills when below threshold."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)
        pool.top_up()

        # Use most of the keys
        for _ in range(9):
            pool.get_new_address(is_change=False)

        # Pool should have refilled since we're below threshold
        initial_size = len(pool._receive_pool)
        pool.get_new_address(is_change=False)

        # Should have more keys now
        assert len(pool._receive_pool) >= initial_size

    def test_serialization_roundtrip(self):
        """Test key pool serialize/deserialize."""
        seed = os.urandom(32)
        pool = KeyPool(seed, "mainnet", pool_size=10)
        pool.top_up()

        # Use some addresses
        pool.get_new_address(is_change=False)
        pool.get_new_address(is_change=True)

        # Serialize
        data = pool.to_dict()

        # Deserialize
        restored = KeyPool.from_dict(data)

        assert restored.seed == pool.seed
        assert restored.network == pool.network
        assert restored._used_receive_indices == pool._used_receive_indices
        assert restored._used_change_indices == pool._used_change_indices

    def test_deterministic_addresses(self):
        """Test same seed produces same addresses."""
        seed = os.urandom(32)

        pool1 = KeyPool(seed, "mainnet", pool_size=5)
        pool1.top_up()

        pool2 = KeyPool(seed, "mainnet", pool_size=5)
        pool2.top_up()

        # Get addresses from both
        addr1, _ = pool1.get_new_address()
        addr2, _ = pool2.get_new_address()

        assert addr1 == addr2


class TestWalletKey:
    """Test WalletKey address generation."""

    def test_p2wpkh_address_mainnet(self):
        """Test P2WPKH address generation for mainnet."""
        key = WalletKey.generate("mainnet")
        addr = key.get_p2wpkh_address()

        assert addr.startswith("bc1q")
        assert len(addr) == 42  # bech32 P2WPKH

    def test_p2wpkh_address_testnet(self):
        """Test P2WPKH address generation for testnet."""
        key = WalletKey.generate("testnet")
        addr = key.get_p2wpkh_address()

        assert addr.startswith("tb1q")

    def test_p2pkh_address(self):
        """Test P2PKH legacy address."""
        key = WalletKey.generate("mainnet")
        addr = key.get_p2pkh_address()

        assert addr.startswith("1")

    def test_p2sh_p2wpkh_address(self):
        """Test P2SH-P2WPKH address."""
        key = WalletKey.generate("mainnet")
        addr = key.get_p2sh_p2wpkh_address()

        assert addr.startswith("3")

    def test_p2tr_address(self):
        """Test P2TR Taproot address."""
        key = WalletKey.generate("mainnet")
        addr = key.get_p2tr_address()

        assert addr.startswith("bc1p")

    def test_wif_roundtrip(self):
        """Test WIF serialization roundtrip."""
        key = WalletKey.generate("mainnet")
        wif = key.to_wif()

        restored = WalletKey.from_wif(wif, "mainnet")

        assert restored.secret == key.secret
        assert restored.pubkey == key.pubkey


class TestWalletHD:
    """Test Wallet HD functionality."""

    def test_init_hd_wallet(self):
        """Test initializing HD wallet."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)

            xprv = wallet.init_hd(seed)

            assert wallet.is_hd
            assert xprv.startswith("xprv")
            assert wallet._key_pool is not None

    def test_generate_address_from_pool(self):
        """Test generating addresses from key pool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)
            wallet.init_hd(seed, pool_size=10)

            import asyncio
            addr = asyncio.get_event_loop().run_until_complete(
                wallet.generate_new_address(address_type="bech32")
            )

            assert addr.startswith("bc1q")

    def test_generate_change_address(self):
        """Test generating change addresses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)
            wallet.init_hd(seed, pool_size=10)

            import asyncio
            addr = asyncio.get_event_loop().run_until_complete(
                wallet.get_change_address(address_type="bech32")
            )

            assert addr.startswith("bc1q")

    def test_keypool_size(self):
        """Test keypool size reporting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)
            wallet.init_hd(seed, pool_size=10)

            # Should have 20 keys (10 receive + 10 change)
            size = wallet.get_keypool_size()
            assert size == 20

    def test_keypoolrefill(self):
        """Test refilling the key pool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)
            wallet.init_hd(seed, pool_size=5)

            # Refill to larger size
            generated = wallet.keypoolrefill(10)

            assert generated > 0
            assert wallet.get_keypool_size() == 20  # 10 receive + 10 change

    def test_wallet_persistence(self):
        """Test wallet saves and loads key pool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seed = os.urandom(32)

            # Create wallet and generate addresses
            wallet1 = Wallet(tmpdir, "mainnet", "test")
            wallet1.init_hd(seed, pool_size=5)

            import asyncio
            asyncio.get_event_loop().run_until_complete(
                wallet1.generate_new_address()
            )

            # Reload wallet
            wallet2 = Wallet(tmpdir, "mainnet", "test")

            assert wallet2.is_hd
            assert wallet2._key_pool is not None

            # Used indices should be preserved
            assert 0 in wallet2._key_pool._used_receive_indices

    def test_address_type_variants(self):
        """Test generating different address types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wallet = Wallet(tmpdir, "mainnet", "test")
            seed = os.urandom(32)
            wallet.init_hd(seed, pool_size=10)

            import asyncio
            loop = asyncio.get_event_loop()

            # bech32 (P2WPKH)
            addr1 = loop.run_until_complete(
                wallet.generate_new_address(address_type="bech32")
            )
            assert addr1.startswith("bc1q")

            # p2sh-segwit
            addr2 = loop.run_until_complete(
                wallet.generate_new_address(address_type="p2sh-segwit")
            )
            assert addr2.startswith("3")

            # bech32m (P2TR)
            addr3 = loop.run_until_complete(
                wallet.generate_new_address(address_type="bech32m")
            )
            assert addr3.startswith("bc1p")

            # legacy (P2PKH)
            addr4 = loop.run_until_complete(
                wallet.generate_new_address(address_type="legacy")
            )
            assert addr4.startswith("1")
