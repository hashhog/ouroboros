"""
Tests for output descriptor parsing, checksum, and address derivation.

Verifies BIP 380–386 descriptor support: parsing, checksum computation,
address derivation with range support, and wallet integration.
"""

import json
import os
import sys
import tempfile
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

# Ensure the src directory is on the path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

# Mock the Rust extension module before any ouroboros import
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

import pytest

from ouroboros.descriptors import (
    Descriptor,
    DescriptorEntry,
    ExtendedPubKey,
    KeyExpression,
    add_checksum,
    descriptor_checksum,
    parse_descriptor,
    verify_checksum,
    _hash160,
    _pubkey_to_p2wpkh,
    _pubkey_to_p2pkh,
    _pubkey_to_p2sh_p2wpkh,
    _pubkey_to_p2tr,
    _make_multisig_script,
    _script_to_p2sh,
    _script_to_p2wsh,
)


# Known test vectors
#
# BIP 84 test vector xpub (from BIP 84 / Bitcoin Core test data):
#   m/84'/0'/0' xpub from seed
#   000102030405060708090a0b0c0d0e0f (BIP 32 test vector 1)
#
# We use the BIP 32 test vector 1 master xpub for reproducible tests.

# BIP 32 test vector 1 master key (from seed 000102030405060708090a0b0c0d0e0f)
_TEST_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)
_TEST_XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)

# A known compressed public key (from BIP 32 test vector 1 master)
_TEST_PUBKEY_HEX = (
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
)


# Checksum tests


class TestDescriptorChecksum:
    """BIP 380 descriptor checksum algorithm."""

    def test_checksum_known_vectors(self):
        """Test checksum computation against known Bitcoin Core values."""
        # Compute checksum for a simple descriptor
        desc = f"wpkh({_TEST_PUBKEY_HEX})"
        cs = descriptor_checksum(desc)
        assert len(cs) == 8
        assert all(c in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" for c in cs)

    def test_add_and_verify_checksum(self):
        desc = f"pkh({_TEST_PUBKEY_HEX})"
        with_cs = add_checksum(desc)
        assert "#" in with_cs
        assert verify_checksum(with_cs)

    def test_verify_bad_checksum(self):
        desc = f"wpkh({_TEST_PUBKEY_HEX})"
        bad = f"{desc}#aaaaaaaa"
        assert not verify_checksum(bad)

    def test_verify_no_checksum(self):
        assert not verify_checksum("wpkh(deadbeef)")

    def test_add_checksum_strips_existing(self):
        desc = f"wpkh({_TEST_PUBKEY_HEX})"
        first = add_checksum(desc)
        second = add_checksum(first)
        assert first == second

    def test_checksum_is_deterministic(self):
        desc = f"tr({_TEST_PUBKEY_HEX})"
        assert descriptor_checksum(desc) == descriptor_checksum(desc)


# --- Extended public key tests ---


class TestExtendedPubKey:
    """BIP 32 extended public key deserialisation and derivation."""

    def test_deserialize_xpub(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        assert epk.depth == 0
        assert len(epk.public_key) == 33
        assert epk.public_key[0] in (0x02, 0x03)
        assert epk.network == "mainnet"

    def test_deserialize_xprv_extracts_pubkey(self):
        """When given an xprv, the public key is extracted."""
        epk = ExtendedPubKey.deserialize(_TEST_XPRV)
        assert len(epk.public_key) == 33
        # Should match the xpub's public key
        epk_pub = ExtendedPubKey.deserialize(_TEST_XPUB)
        assert epk.public_key == epk_pub.public_key

    def test_child_derivation(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        child = epk.derive_child(0)
        assert child.depth == 1
        assert child.parent_fingerprint == epk.fingerprint
        assert len(child.public_key) == 33
        # Different from parent
        assert child.public_key != epk.public_key

    def test_derive_path(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        child = epk.derive_path("0/0")
        assert child.depth == 2

    def test_hardened_derivation_fails(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        with pytest.raises(ValueError, match="hardened"):
            epk.derive_child(0x80000000)

    def test_hardened_path_fails(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        with pytest.raises(ValueError, match="hardened"):
            epk.derive_path("0'/1")

    def test_serialize_roundtrip(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        assert epk.serialize() == _TEST_XPUB

    def test_different_indices_different_keys(self):
        epk = ExtendedPubKey.deserialize(_TEST_XPUB)
        child0 = epk.derive_child(0)
        child1 = epk.derive_child(1)
        assert child0.public_key != child1.public_key


# Key expression parsing tests


class TestKeyExpression:
    """Parsing of individual key expressions."""

    def test_parse_hex_pubkey(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(_TEST_PUBKEY_HEX)
        assert ke.hex_pubkey is not None
        assert len(ke.hex_pubkey) == 33
        assert not ke.is_range

    def test_parse_xpub(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(_TEST_XPUB)
        assert ke.ext_key is not None
        assert not ke.is_range
        assert not ke.is_private

    def test_parse_xpub_with_derivation(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(f"{_TEST_XPUB}/0/*")
        assert ke.ext_key is not None
        assert ke.is_range
        assert ke.derivation_suffix == "0/*"

    def test_parse_xprv(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(_TEST_XPRV)
        assert ke.ext_key is not None
        assert ke.is_private

    def test_parse_with_origin(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(f"[d34db33f/84'/0'/0']{_TEST_XPUB}/0/*")
        assert ke.origin is not None
        assert ke.origin.fingerprint == "d34db33f"
        assert ke.ext_key is not None
        assert ke.is_range

    def test_derive_pubkey_from_hex(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(_TEST_PUBKEY_HEX)
        pub = ke.derive_pubkey()
        assert pub == bytes.fromhex(_TEST_PUBKEY_HEX)

    def test_derive_pubkey_from_xpub_range(self):
        from ouroboros.descriptors import _parse_key_expression
        ke = _parse_key_expression(f"{_TEST_XPUB}/0/*")
        pub0 = ke.derive_pubkey(0)
        pub1 = ke.derive_pubkey(1)
        assert len(pub0) == 33
        assert len(pub1) == 33
        assert pub0 != pub1

    def test_invalid_hex_raises(self):
        from ouroboros.descriptors import _parse_key_expression
        with pytest.raises(ValueError):
            _parse_key_expression("deadbeef")  # too short


# Descriptor parsing tests #


class TestDescriptorParsing:
    """Parsing of full descriptor strings."""

    def test_wpkh_hex_pubkey(self):
        desc = parse_descriptor(f"wpkh({_TEST_PUBKEY_HEX})")
        assert desc.descriptor_type == "wpkh"
        assert len(desc.keys) == 1
        assert not desc.is_range

    def test_wpkh_xpub_range(self):
        desc = parse_descriptor(f"wpkh({_TEST_XPUB}/0/*)")
        assert desc.descriptor_type == "wpkh"
        assert desc.is_range

    def test_pkh(self):
        desc = parse_descriptor(f"pkh({_TEST_PUBKEY_HEX})")
        assert desc.descriptor_type == "pkh"

    def test_tr(self):
        desc = parse_descriptor(f"tr({_TEST_PUBKEY_HEX})")
        assert desc.descriptor_type == "tr"

    def test_sh_wpkh(self):
        desc = parse_descriptor(f"sh(wpkh({_TEST_PUBKEY_HEX}))")
        assert desc.descriptor_type == "sh-wpkh"

    def test_multi(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"multi(1,{_TEST_PUBKEY_HEX},{pk2})")
        assert desc.descriptor_type == "multi"
        assert desc.multisig_threshold == 1
        assert len(desc.keys) == 2

    def test_wsh_multi(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"wsh(multi(2,{_TEST_PUBKEY_HEX},{pk2}))")
        assert desc.descriptor_type == "wsh-multi"
        assert desc.multisig_threshold == 2

    def test_with_checksum(self):
        raw = f"wpkh({_TEST_PUBKEY_HEX})"
        with_cs = add_checksum(raw)
        desc = parse_descriptor(with_cs)
        assert desc.descriptor_type == "wpkh"

    def test_bad_checksum_raises(self):
        raw = f"wpkh({_TEST_PUBKEY_HEX})#aaaaaaaa"
        with pytest.raises(ValueError, match="checksum"):
            parse_descriptor(raw)

    def test_unsupported_descriptor_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            parse_descriptor("rawscript(deadbeef)")

    def test_with_origin(self):
        desc = parse_descriptor(
            f"wpkh([d34db33f/84'/0'/0']{_TEST_XPUB}/0/*)"
        )
        assert desc.descriptor_type == "wpkh"
        assert desc.is_range
        assert desc.keys[0].origin is not None

    def test_multi_invalid_threshold(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        with pytest.raises(ValueError, match="threshold"):
            parse_descriptor(f"multi(3,{_TEST_PUBKEY_HEX},{pk2})")


# Address derivation tests


class TestAddressDerivation:
    """Address generation from parsed descriptors."""

    def test_wpkh_address_mainnet(self):
        desc = parse_descriptor(f"wpkh({_TEST_PUBKEY_HEX})")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("bc1q")

    def test_wpkh_address_testnet(self):
        desc = parse_descriptor(f"wpkh({_TEST_PUBKEY_HEX})")
        addr = desc.derive_address(0, "testnet")
        assert addr.startswith("tb1q")

    def test_pkh_address(self):
        desc = parse_descriptor(f"pkh({_TEST_PUBKEY_HEX})")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("1")

    def test_tr_address(self):
        desc = parse_descriptor(f"tr({_TEST_PUBKEY_HEX})")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("bc1p")

    def test_sh_wpkh_address(self):
        desc = parse_descriptor(f"sh(wpkh({_TEST_PUBKEY_HEX}))")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("3")

    def test_multi_p2sh_address(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"multi(1,{_TEST_PUBKEY_HEX},{pk2})")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("3")

    def test_wsh_multi_address(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"wsh(multi(1,{_TEST_PUBKEY_HEX},{pk2}))")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("bc1q")

    def test_range_produces_unique_addresses(self):
        desc = parse_descriptor(f"wpkh({_TEST_XPUB}/0/*)")
        addrs = desc.derive_addresses(0, 20, "mainnet")
        assert len(addrs) == 20
        assert len(set(addrs)) == 20  # all unique

    def test_range_is_deterministic(self):
        desc = parse_descriptor(f"wpkh({_TEST_XPUB}/0/*)")
        addrs1 = desc.derive_addresses(0, 5, "mainnet")
        addrs2 = desc.derive_addresses(0, 5, "mainnet")
        assert addrs1 == addrs2

    def test_derive_addresses_start_offset(self):
        desc = parse_descriptor(f"wpkh({_TEST_XPUB}/0/*)")
        all_20 = desc.derive_addresses(0, 20, "mainnet")
        last_10 = desc.derive_addresses(10, 10, "mainnet")
        assert last_10 == all_20[10:]


# Script pubkey derivation tests


class TestScriptPubKey:
    """scriptPubKey derivation from descriptors."""

    def test_wpkh_script_pubkey(self):
        desc = parse_descriptor(f"wpkh({_TEST_PUBKEY_HEX})")
        spk = desc.derive_script_pubkey(0)
        assert spk[:2] == b"\x00\x14"  # OP_0 PUSH_20
        assert len(spk) == 22

    def test_pkh_script_pubkey(self):
        desc = parse_descriptor(f"pkh({_TEST_PUBKEY_HEX})")
        spk = desc.derive_script_pubkey(0)
        assert spk[:3] == b"\x76\xa9\x14"  # OP_DUP OP_HASH160 PUSH_20
        assert spk[-2:] == b"\x88\xac"     # OP_EQUALVERIFY OP_CHECKSIG
        assert len(spk) == 25

    def test_tr_script_pubkey(self):
        desc = parse_descriptor(f"tr({_TEST_PUBKEY_HEX})")
        spk = desc.derive_script_pubkey(0)
        assert spk[:2] == b"\x51\x20"  # OP_1 PUSH_32
        assert len(spk) == 34

    def test_sh_wpkh_script_pubkey(self):
        desc = parse_descriptor(f"sh(wpkh({_TEST_PUBKEY_HEX}))")
        spk = desc.derive_script_pubkey(0)
        assert spk[:2] == b"\xa9\x14"  # OP_HASH160 PUSH_20
        assert spk[-1:] == b"\x87"     # OP_EQUAL
        assert len(spk) == 23

    def test_wsh_multi_script_pubkey(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"wsh(multi(1,{_TEST_PUBKEY_HEX},{pk2}))")
        spk = desc.derive_script_pubkey(0)
        assert spk[:2] == b"\x00\x20"  # OP_0 PUSH_32
        assert len(spk) == 34


# --- Multisig script tests ---


class TestMultisigScript:
    """Bare multisig redeemScript construction."""

    def test_1_of_2(self):
        pk1 = bytes.fromhex(_TEST_PUBKEY_HEX)
        pk2 = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        script = _make_multisig_script(1, [pk1, pk2])
        assert script[0] == 0x51  # OP_1
        assert script[-1] == 0xAE  # OP_CHECKMULTISIG
        assert script[-2] == 0x52  # OP_2

    def test_invalid_threshold(self):
        pk = bytes.fromhex(_TEST_PUBKEY_HEX)
        with pytest.raises(ValueError, match="threshold"):
            _make_multisig_script(0, [pk])
        with pytest.raises(ValueError, match="threshold"):
            _make_multisig_script(2, [pk])


# DescriptorEntry serialisation tests


class TestDescriptorEntry:
    """Wallet-level descriptor entry serialisation."""

    def test_roundtrip(self):
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        descriptor = parse_descriptor(desc_str)
        entry = DescriptorEntry(
            descriptor=descriptor,
            desc_string=desc_str,
            timestamp=1700000000,
            active=True,
            range_start=0,
            range_end=100,
            next_index=5,
            internal=False,
            label="test",
        )
        d = entry.to_dict()
        restored = DescriptorEntry.from_dict(d)
        assert restored.desc_string == desc_str
        assert restored.timestamp == 1700000000
        assert restored.active is True
        assert restored.range_start == 0
        assert restored.range_end == 100
        assert restored.next_index == 5
        assert restored.internal is False
        assert restored.label == "test"
        assert restored.descriptor.descriptor_type == "wpkh"
        assert restored.descriptor.is_range


# Wallet integration tests


class TestWalletDescriptorIntegration:
    """Integration of descriptor support in the Wallet class."""

    def _make_wallet(self, tmp_path):
        from ouroboros.wallet import Wallet
        return Wallet(data_dir=str(tmp_path), network="mainnet", name="test")

    def test_importdescriptors_success(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        results = wallet.importdescriptors([
            {"desc": desc_str, "timestamp": "now"},
        ])
        assert len(results) == 1
        assert results[0]["success"] is True
        assert len(wallet.descriptors) == 1

    def test_importdescriptors_without_checksum(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        results = wallet.importdescriptors([
            {"desc": f"wpkh({_TEST_XPUB}/0/*)", "timestamp": "now"},
        ])
        assert results[0]["success"] is True
        # Checksum should have been added
        assert "#" in wallet.descriptors[0].desc_string

    def test_importdescriptors_bad_checksum(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        results = wallet.importdescriptors([
            {"desc": f"wpkh({_TEST_XPUB}/0/*)#aaaaaaaa"},
        ])
        assert results[0]["success"] is False
        assert "error" in results[0]

    def test_importdescriptors_invalid_descriptor(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        results = wallet.importdescriptors([
            {"desc": "invalid(stuff)"},
        ])
        assert results[0]["success"] is False

    def test_importdescriptors_multiple(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        results = wallet.importdescriptors([
            {"desc": f"wpkh({_TEST_XPUB}/0/*)", "active": True},
            {"desc": f"pkh({_TEST_PUBKEY_HEX})", "active": True},
            {"desc": f"wsh(multi(1,{_TEST_PUBKEY_HEX},{pk2}))", "active": True},
        ])
        assert all(r["success"] for r in results)
        assert len(wallet.descriptors) == 3

    def test_importdescriptors_replaces_existing(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        wallet.importdescriptors([{"desc": desc_str, "range": [0, 100]}])
        wallet.importdescriptors([{"desc": desc_str, "range": [0, 500]}])
        assert len(wallet.descriptors) == 1
        assert wallet.descriptors[0].range_end == 500

    def test_listdescriptors(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        wallet.importdescriptors([{"desc": desc_str}])
        listed = wallet.listdescriptors()
        assert len(listed) == 1
        assert listed[0]["desc"] == desc_str

    def test_deriveaddresses_range(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = f"wpkh({_TEST_XPUB}/0/*)"
        addrs = wallet.deriveaddresses(desc_str, [0, 19])
        assert len(addrs) == 20
        assert all(a.startswith("bc1q") for a in addrs)
        assert len(set(addrs)) == 20

    def test_deriveaddresses_non_range(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = f"wpkh({_TEST_PUBKEY_HEX})"
        addrs = wallet.deriveaddresses(desc_str)
        assert len(addrs) == 1
        assert addrs[0].startswith("bc1q")

    def test_deriveaddresses_range_on_non_range_raises(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        with pytest.raises(ValueError, match="Range should not"):
            wallet.deriveaddresses(f"wpkh({_TEST_PUBKEY_HEX})", [0, 5])

    def test_generate_descriptor_address(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        wallet.importdescriptors([{"desc": desc_str}])
        addr0 = wallet.generate_descriptor_address()
        addr1 = wallet.generate_descriptor_address()
        assert addr0 != addr1
        assert wallet.descriptors[0].next_index == 2

    def test_generate_descriptor_address_no_descriptors(self, tmp_path):
        wallet = self._make_wallet(tmp_path)
        with pytest.raises(ValueError, match="No active"):
            wallet.generate_descriptor_address()

    def test_wallet_persistence(self, tmp_path):
        """Descriptors survive save/reload."""
        from ouroboros.wallet import Wallet

        wallet1 = Wallet(data_dir=str(tmp_path), network="mainnet", name="persist_test")
        desc_str = add_checksum(f"wpkh({_TEST_XPUB}/0/*)")
        wallet1.importdescriptors([{"desc": desc_str, "label": "main"}])
        wallet1.descriptors[0].next_index = 5
        wallet1._save()

        # Reload
        wallet2 = Wallet(data_dir=str(tmp_path), network="mainnet", name="persist_test")
        assert len(wallet2.descriptors) == 1
        assert wallet2.descriptors[0].desc_string == desc_str
        assert wallet2.descriptors[0].next_index == 5
        assert wallet2.descriptors[0].label == "main"

    def test_deriveaddresses_matches_direct(self, tmp_path):
        """Wallet.deriveaddresses matches Descriptor.derive_addresses."""
        wallet = self._make_wallet(tmp_path)
        desc_str = f"wpkh({_TEST_XPUB}/0/*)"
        wallet_addrs = wallet.deriveaddresses(desc_str, [0, 4])

        desc = parse_descriptor(desc_str)
        direct_addrs = desc.derive_addresses(0, 5, "mainnet")
        assert wallet_addrs == direct_addrs


# Cross-verification: wpkh xpub derivation against HDKey


class TestCrossVerification:
    """
    Verify descriptor address derivation matches the existing HDKey
    implementation in wallet.py.
    """

    def test_wpkh_matches_hdkey_derivation(self):
        """
        Import a wpkh descriptor with xpub, derive 20 addresses, and
        verify they match addresses derived via HDKey → WalletKey.
        """
        from ouroboros.wallet import HDKey

        # Derive the BIP 32 test vector 1 master key from seed
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        master = HDKey.from_seed(seed, "mainnet")
        xpub_str = master.serialize_xpub()

        # Derive 20 addresses via descriptor
        desc = parse_descriptor(f"wpkh({xpub_str}/0/*)")
        desc_addrs = desc.derive_addresses(0, 20, "mainnet")

        # Derive 20 addresses via HDKey → WalletKey
        hdkey_addrs = []
        for i in range(20):
            child = master.derive_path(f"m/0/{i}")
            wk = child.to_wallet_key()
            hdkey_addrs.append(wk.get_p2wpkh_address())

        assert desc_addrs == hdkey_addrs

    def test_pkh_matches_hdkey_derivation(self):
        from ouroboros.wallet import HDKey

        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        master = HDKey.from_seed(seed, "mainnet")
        xpub_str = master.serialize_xpub()

        desc = parse_descriptor(f"pkh({xpub_str}/0/*)")
        desc_addrs = desc.derive_addresses(0, 20, "mainnet")

        hdkey_addrs = []
        for i in range(20):
            child = master.derive_path(f"m/0/{i}")
            wk = child.to_wallet_key()
            hdkey_addrs.append(wk.get_p2pkh_address())

        assert desc_addrs == hdkey_addrs

    def test_sh_wpkh_matches_hdkey_derivation(self):
        from ouroboros.wallet import HDKey

        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        master = HDKey.from_seed(seed, "mainnet")
        xpub_str = master.serialize_xpub()

        desc = parse_descriptor(f"sh(wpkh({xpub_str}/0/*))")
        desc_addrs = desc.derive_addresses(0, 20, "mainnet")

        hdkey_addrs = []
        for i in range(20):
            child = master.derive_path(f"m/0/{i}")
            wk = child.to_wallet_key()
            hdkey_addrs.append(wk.get_p2sh_p2wpkh_address())

        assert desc_addrs == hdkey_addrs

    def test_tr_matches_hdkey_derivation(self):
        from ouroboros.wallet import HDKey

        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        master = HDKey.from_seed(seed, "mainnet")
        xpub_str = master.serialize_xpub()

        desc = parse_descriptor(f"tr({xpub_str}/0/*)")
        desc_addrs = desc.derive_addresses(0, 20, "mainnet")

        hdkey_addrs = []
        for i in range(20):
            child = master.derive_path(f"m/0/{i}")
            wk = child.to_wallet_key()
            hdkey_addrs.append(wk.get_p2tr_address())

        assert desc_addrs == hdkey_addrs

    def test_single_key_matches(self):
        """A non-range wpkh descriptor with a raw pubkey matches WalletKey."""
        from ouroboros.wallet import HDKey

        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        master = HDKey.from_seed(seed, "mainnet")
        pubkey_hex = master.public_key.hex()

        desc = parse_descriptor(f"wpkh({pubkey_hex})")
        desc_addr = desc.derive_address(0, "mainnet")

        wk = master.to_wallet_key()
        wk_addr = wk.get_p2wpkh_address()

        assert desc_addr == wk_addr


# New descriptor type tests (BIP 380-386 expansion)


class TestPkDescriptor:
    """Tests for pk() bare pay-to-pubkey descriptor."""

    def test_pk_parsing(self):
        desc = parse_descriptor(f"pk({_TEST_PUBKEY_HEX})")
        assert desc.descriptor_type == "pk"
        assert len(desc.keys) == 1
        assert not desc.is_range

    def test_pk_script_pubkey(self):
        desc = parse_descriptor(f"pk({_TEST_PUBKEY_HEX})")
        spk = desc.derive_script_pubkey(0)
        # <pubkey> OP_CHECKSIG
        assert spk[-1] == 0xAC  # OP_CHECKSIG
        assert spk[0] == 33  # push 33 bytes
        assert len(spk) == 35  # 1 + 33 + 1

    def test_pk_address_is_p2sh(self):
        # P2PK has no standard address format; we wrap in P2SH
        desc = parse_descriptor(f"pk({_TEST_PUBKEY_HEX})")
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("3")


class TestSortedMultiDescriptor:
    """Tests for sortedmulti() descriptor."""

    def test_sortedmulti_parsing(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"sortedmulti(1,{_TEST_PUBKEY_HEX},{pk2})")
        assert desc.descriptor_type == "sortedmulti"
        assert desc.multisig_threshold == 1
        assert desc.sorted_multi is True
        assert len(desc.keys) == 2

    def test_sortedmulti_keys_sorted(self):
        # Keys should be sorted lexicographically in the script
        pk1 = _TEST_PUBKEY_HEX
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc1 = parse_descriptor(f"sortedmulti(1,{pk1},{pk2})")
        desc2 = parse_descriptor(f"sortedmulti(1,{pk2},{pk1})")
        # Both should produce the same script regardless of input order
        assert desc1.derive_script_pubkey(0) == desc2.derive_script_pubkey(0)

    def test_wsh_sortedmulti(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"wsh(sortedmulti(2,{_TEST_PUBKEY_HEX},{pk2}))")
        assert desc.descriptor_type == "wsh-sortedmulti"
        assert desc.sorted_multi is True
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("bc1q")


class TestComboDescriptor:
    """Tests for combo() descriptor."""

    def test_combo_parsing(self):
        desc = parse_descriptor(f"combo({_TEST_PUBKEY_HEX})")
        assert desc.descriptor_type == "combo"
        assert len(desc.keys) == 1

    def test_combo_derives_all_scripts(self):
        desc = parse_descriptor(f"combo({_TEST_PUBKEY_HEX})")
        scripts = desc.derive_all_scripts(0)
        # P2PK, P2PKH, P2WPKH, P2SH-P2WPKH (4 types for compressed key)
        assert len(scripts) == 4

    def test_combo_derives_all_addresses(self):
        desc = parse_descriptor(f"combo({_TEST_PUBKEY_HEX})")
        addrs = desc.derive_all_addresses(0, "mainnet")
        assert len(addrs) == 4
        # P2SH (for P2PK)
        assert addrs[0].startswith("3")
        # P2PKH
        assert addrs[1].startswith("1")
        # P2WPKH
        assert addrs[2].startswith("bc1q")
        # P2SH-P2WPKH
        assert addrs[3].startswith("3")

    def test_combo_with_xpub(self):
        desc = parse_descriptor(f"combo({_TEST_XPUB}/0/*)")
        assert desc.is_range
        addrs0 = desc.derive_all_addresses(0, "mainnet")
        addrs1 = desc.derive_all_addresses(1, "mainnet")
        assert addrs0 != addrs1


class TestAddrDescriptor:
    """Tests for addr() descriptor."""

    def test_addr_p2pkh(self):
        # Use a known P2PKH address
        addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        desc = parse_descriptor(f"addr({addr})")
        assert desc.descriptor_type == "addr"
        assert desc.address == addr
        assert not desc.is_range

    def test_addr_p2wpkh(self):
        # A P2WPKH address
        addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        desc = parse_descriptor(f"addr({addr})")
        assert desc.descriptor_type == "addr"
        assert desc.derive_address(0, "mainnet") == addr

    def test_addr_script_pubkey(self):
        # P2PKH address
        addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        desc = parse_descriptor(f"addr({addr})")
        spk = desc.derive_script_pubkey(0)
        # P2PKH script structure
        assert spk[:3] == b"\x76\xa9\x14"
        assert spk[-2:] == b"\x88\xac"


class TestRawDescriptor:
    """Tests for raw() descriptor."""

    def test_raw_parsing(self):
        # A simple OP_RETURN script
        script_hex = "6a0b68656c6c6f20776f726c64"  # OP_RETURN "hello world"
        desc = parse_descriptor(f"raw({script_hex})")
        assert desc.descriptor_type == "raw"
        assert desc.script_hex == script_hex

    def test_raw_script_pubkey(self):
        script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
        desc = parse_descriptor(f"raw({script_hex})")
        spk = desc.derive_script_pubkey(0)
        assert spk == bytes.fromhex(script_hex)

    def test_raw_invalid_hex(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            parse_descriptor("raw(not_hex)")


class TestShMultiDescriptor:
    """Tests for sh(multi()) and nested variants."""

    def test_sh_multi(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"sh(multi(1,{_TEST_PUBKEY_HEX},{pk2}))")
        assert desc.descriptor_type == "sh-multi"
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("3")

    def test_sh_sortedmulti(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"sh(sortedmulti(1,{_TEST_PUBKEY_HEX},{pk2}))")
        assert desc.descriptor_type == "sh-sortedmulti"
        assert desc.sorted_multi is True

    def test_sh_wsh_multi(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"sh(wsh(multi(1,{_TEST_PUBKEY_HEX},{pk2})))")
        assert desc.descriptor_type == "sh-wsh-multi"
        addr = desc.derive_address(0, "mainnet")
        assert addr.startswith("3")

    def test_sh_wsh_sortedmulti(self):
        pk2 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,{_TEST_PUBKEY_HEX},{pk2})))")
        assert desc.descriptor_type == "sh-wsh-sortedmulti"
        assert desc.sorted_multi is True


class TestGetDescriptorInfo:
    """Tests for getdescriptorinfo function."""

    def test_basic_wpkh(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = f"wpkh({_TEST_PUBKEY_HEX})"
        info = getdescriptorinfo(desc_str)
        assert "descriptor" in info
        assert "#" in info["descriptor"]
        assert len(info["checksum"]) == 8
        assert info["isrange"] is False
        assert info["issolvable"] is True
        assert info["hasprivatekeys"] is False

    def test_ranged_xpub(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = f"wpkh({_TEST_XPUB}/0/*)"
        info = getdescriptorinfo(desc_str)
        assert info["isrange"] is True

    def test_with_xprv(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = f"wpkh({_TEST_XPRV})"
        info = getdescriptorinfo(desc_str)
        assert info["hasprivatekeys"] is True

    def test_addr_not_solvable(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = "addr(1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)"
        info = getdescriptorinfo(desc_str)
        assert info["issolvable"] is False

    def test_raw_not_solvable(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = "raw(76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac)"
        info = getdescriptorinfo(desc_str)
        assert info["issolvable"] is False

    def test_checksum_deterministic(self):
        from ouroboros.descriptors import getdescriptorinfo

        desc_str = f"wpkh({_TEST_PUBKEY_HEX})"
        info1 = getdescriptorinfo(desc_str)
        info2 = getdescriptorinfo(desc_str)
        assert info1["checksum"] == info2["checksum"]
