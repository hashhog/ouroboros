"""
Tests for BIP-86 / BIP-341 Taproot key tweak (W20 fix).

Covers:
  * BIP-86 vector 1 (canonical ``abandon...about`` test vector)
  * Even-Y and odd-Y internal-pubkey parity
  * Round-trip sign-then-verify against the on-chain output key
  * Silent-fallback removal in ``WalletKey.get_p2tr_address``
  * P2TR scriptPubKey contains the *tweaked* output key
"""

from __future__ import annotations

import hashlib
import os

import pytest
from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

from ouroboros.taproot import (
    SECP256K1_ORDER,
    _tagged_hash,
    derive_taproot_output_xonly,
    derive_taproot_sign_secret,
)
from ouroboros.wallet import WalletKey


# ---------------------------------------------------------------------------
# BIP-86 canonical test vector
# ---------------------------------------------------------------------------
#
# Source: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
# Mnemonic:  abandon abandon ... about
# Path:      m/86'/0'/0'/0/0
# Internal:  cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
# Output:    a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
# Address:   bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
#
# The corresponding child *private* key (computed offline from the
# mnemonic + path) is:
BIP86_CHILD_PRIV = bytes.fromhex(
    "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"
)
BIP86_INTERNAL_X = bytes.fromhex(
    "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
)
BIP86_OUTPUT_X = bytes.fromhex(
    "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
)
BIP86_ADDRESS = (
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
)


class TestBip86Vector:
    def test_internal_pubkey_matches(self):
        pub = PrivateKey(BIP86_CHILD_PRIV).public_key.format(compressed=True)
        assert pub[1:] == BIP86_INTERNAL_X

    def test_derive_taproot_output_xonly_from_compressed(self):
        pub = PrivateKey(BIP86_CHILD_PRIV).public_key.format(compressed=True)
        out = derive_taproot_output_xonly(pub, None)
        assert out == BIP86_OUTPUT_X

    def test_derive_taproot_output_xonly_from_xonly(self):
        out = derive_taproot_output_xonly(BIP86_INTERNAL_X, None)
        assert out == BIP86_OUTPUT_X

    def test_tweaked_secret_produces_output_key(self):
        d_prime = derive_taproot_sign_secret(BIP86_CHILD_PRIV, None)
        Q = PrivateKey(d_prime).public_key.format(compressed=True)
        assert Q[1:] == BIP86_OUTPUT_X

    def test_wallet_address_matches_bip86(self):
        # WalletKey takes a 32-byte secret; the public address is derived
        # internally and must hit the canonical BIP-86 string.
        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        assert key.get_p2tr_address() == BIP86_ADDRESS


# ---------------------------------------------------------------------------
# Sign / verify round-trip across all parity combinations
# ---------------------------------------------------------------------------

class TestSignVerifyRoundTrip:
    @staticmethod
    def _sign_verify(d: bytes, msg: bytes) -> bool:
        d_prime = derive_taproot_sign_secret(d, None)
        sig = PrivateKey(d_prime).sign_schnorr(msg)
        out_x = derive_taproot_output_xonly(
            PrivateKey(d).public_key.format(compressed=True), None
        )
        return PublicKeyXOnly(out_x).verify(sig, msg)

    def test_known_vector_roundtrip(self):
        msg = hashlib.sha256(b"hashhog-w20-bip86").digest()
        assert self._sign_verify(BIP86_CHILD_PRIV, msg)

    def test_even_y_internal_roundtrip(self):
        # Search for an internal key whose pubkey has even Y (prefix 0x02).
        # Statistically half of all keys hit this on the first try.
        msg = hashlib.sha256(b"even-y-test").digest()
        for _ in range(64):
            d = os.urandom(32)
            if int.from_bytes(d, "big") == 0:
                continue
            pub = PrivateKey(d).public_key.format(compressed=True)
            if pub[0] == 0x02:
                assert self._sign_verify(d, msg)
                return
        pytest.skip("Could not find even-Y key in 64 tries")

    def test_odd_y_internal_roundtrip(self):
        # Same, but force odd Y. Critical: the BIP-341 even-Y negation
        # must be applied — without it, the signature does NOT verify.
        msg = hashlib.sha256(b"odd-y-test").digest()
        for _ in range(64):
            d = os.urandom(32)
            if int.from_bytes(d, "big") == 0:
                continue
            pub = PrivateKey(d).public_key.format(compressed=True)
            if pub[0] == 0x03:
                assert self._sign_verify(d, msg)
                return
        pytest.skip("Could not find odd-Y key in 64 tries")

    def test_naive_untweaked_sign_does_not_verify(self):
        # Sanity check: signing with the *raw* internal key (the W20 bug)
        # produces a Schnorr signature that does NOT verify against the
        # on-chain Taproot output key.
        msg = hashlib.sha256(b"untweaked-sign").digest()
        sig = PrivateKey(BIP86_CHILD_PRIV).sign_schnorr(msg)
        ok = PublicKeyXOnly(BIP86_OUTPUT_X).verify(sig, msg)
        assert ok is False, (
            "raw-key sig accidentally verified against tweaked output key — "
            "BIP-86 may have been silently bypassed"
        )


# ---------------------------------------------------------------------------
# Edge-case input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_short_secret_raises(self):
        with pytest.raises(ValueError):
            derive_taproot_sign_secret(b"\x01" * 31, None)

    def test_zero_secret_raises(self):
        with pytest.raises(ValueError):
            derive_taproot_sign_secret(b"\x00" * 32, None)

    def test_secret_at_curve_order_raises(self):
        n_bytes = SECP256K1_ORDER.to_bytes(32, "big")
        with pytest.raises(ValueError):
            derive_taproot_sign_secret(n_bytes, None)

    def test_non_bytes_secret_raises(self):
        with pytest.raises(ValueError):
            derive_taproot_sign_secret("not bytes", None)  # type: ignore[arg-type]

    def test_wrong_length_merkle_root_raises(self):
        with pytest.raises(ValueError):
            derive_taproot_sign_secret(BIP86_CHILD_PRIV, b"\x00" * 16)

    def test_empty_merkle_root_equivalent_to_none(self):
        # BIP-86 says "no merkle root"; either b"" or None must yield
        # the same tweaked secret.
        a = derive_taproot_sign_secret(BIP86_CHILD_PRIV, None)
        b = derive_taproot_sign_secret(BIP86_CHILD_PRIV, b"")
        assert a == b


# ---------------------------------------------------------------------------
# Silent-fallback removal in WalletKey.get_p2tr_address
# ---------------------------------------------------------------------------

class TestNoSilentFallback:
    def test_corrupted_pubkey_length_raises(self):
        # Manually construct a WalletKey with a corrupted pubkey
        # (skip the constructor's regular pubkey derivation).
        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        key.pubkey = b"\x02" + b"\x00" * 31  # wrong length (32, not 33)
        with pytest.raises(ValueError) as exc_info:
            key.get_p2tr_address()
        assert "BIP-86" in str(exc_info.value) or "compressed" in str(
            exc_info.value
        )

    def test_invalid_pubkey_prefix_raises(self):
        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        key.pubkey = b"\x05" + b"\x11" * 32  # bogus prefix
        with pytest.raises(ValueError):
            key.get_p2tr_address()

    def test_all_zero_pubkey_raises(self):
        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        # Even-Y prefix but x = 0 isn't on the curve; coincurve raises,
        # the new code must surface it (not silently return untweaked).
        key.pubkey = b"\x02" + b"\x00" * 32
        with pytest.raises(ValueError):
            key.get_p2tr_address()


# ---------------------------------------------------------------------------
# scriptPubKey integrity: P2TR spk must contain tweaked output key
# ---------------------------------------------------------------------------

class TestScriptPubKey:
    def test_p2tr_spk_uses_tweaked_output(self):
        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        spk = key.get_p2tr_script_pubkey()
        assert spk == b"\x51\x20" + BIP86_OUTPUT_X
        # And it must NOT be the internal x-only key (the pre-W20 bug).
        assert spk != b"\x51\x20" + BIP86_INTERNAL_X

    def test_p2tr_spk_matches_address(self):
        # The 32-byte program in the spk should be the same bytes that
        # the bech32m address decodes to.
        from ouroboros.address import _bech32m_decode

        key = WalletKey(BIP86_CHILD_PRIV, "mainnet")
        addr = key.get_p2tr_address()
        spk = key.get_p2tr_script_pubkey()

        hrp, wit_ver, data = _bech32m_decode(addr)
        assert hrp == "bc"
        assert wit_ver == 1
        assert data is not None
        # _bech32m_decode returns 5-bit data; repack to 8-bit.
        import bech32
        prog = bytes(bech32.convertbits(data, 5, 8, False))
        assert prog == spk[2:]
