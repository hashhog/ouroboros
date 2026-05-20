"""
Unit tests for BIP-32 spec-compliance fixes from W161 audit.

Covers three bugs fixed in the same PR:

* **BUG-1** — :meth:`HDKey.derive_child` MUST silently retry at
  ``index + 1`` when ``parse256(IL) >= n`` or ``k_i == 0``, per the
  BIP-32 spec §"Private parent key → private child key". Pre-fix it
  raised ``ValueError`` and the (rare but spec-mandated) skip semantics
  diverged from Bitcoin Core / hardware wallets.

* **BUG-3** — :meth:`ExtendedPubKey.derive_child` MUST silently retry
  at ``index + 1`` on the same conditions, per the spec §"Public parent
  key → public child key". Pre-fix it raised ``ValueError`` and any
  watch-only restore from a Core-derived xpub that ever hit an invalid
  index would diverge silently.

* **BUG-5** — derive_child MUST refuse to derive when the resulting
  depth byte would overflow (``self.depth == 0xFF``), eagerly raising
  :class:`BIP32MaxDepthError` rather than constructing a 256-deep
  HDKey object whose serialise step crashes much later. Defence-in-depth
  check in :meth:`_serialize_extended` /
  :meth:`ExtendedPubKey.serialize` rejects directly-constructed
  out-of-range depths too.

Bitcoin Core references:
  * ``src/key.cpp::CExtKey::Derive`` (lines 482-489) — depth guard
  * ``src/key.cpp::CKey::Derive`` (lines 293-310) — retry semantics
    via ``secp256k1_ec_seckey_tweak_add`` returning false
  * ``src/pubkey.cpp::CExtPubKey::Derive`` (lines 415-421) — public-side
    same shape.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from ouroboros.descriptors import ExtendedPubKey
from ouroboros.wallet import (
    BIP32IndexExhaustedError,
    BIP32MaxDepthError,
    SECP256K1_ORDER,
    HDKey,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_BIP32_TV1_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def _master() -> HDKey:
    """Return BIP-32 test-vector-1 master key (mainnet)."""
    return HDKey.from_seed(_BIP32_TV1_SEED, "mainnet")


def _xpub_from(hd: HDKey) -> ExtendedPubKey:
    """Construct the watch-only twin of an HDKey."""
    return ExtendedPubKey(
        public_key=hd.public_key,
        chain_code=hd.chain_code,
        depth=hd.depth,
        parent_fingerprint=hd.parent_fingerprint,
        child_index=hd.child_index,
        network=hd.network,
    )


# ---------------------------------------------------------------------------
# BUG-5 — depth-byte overflow
# ---------------------------------------------------------------------------


class TestDepthOverflow:
    """W161 BUG-5: derive_child must refuse depth > 0xFF up front."""

    def test_derive_at_depth_254_allowed(self):
        """A node at depth 254 must still derive (the child sits at 255)."""
        m = _master()
        # Construct a synthetic depth-254 HDKey directly (avoiding 254
        # actual derivations would be needed to reach this naturally).
        spoof = HDKey(
            private_key=m.private_key,
            chain_code=m.chain_code,
            depth=254,
            parent_fingerprint=m.parent_fingerprint,
            child_index=0,
            network=m.network,
        )
        child = spoof.derive_child(0, hardened=False)
        assert child.depth == 255

    def test_derive_at_depth_255_rejected_private(self):
        """At depth 255 the next child would overflow → must raise."""
        m = _master()
        spoof = HDKey(
            private_key=m.private_key,
            chain_code=m.chain_code,
            depth=255,
            parent_fingerprint=m.parent_fingerprint,
            child_index=0,
            network=m.network,
        )
        with pytest.raises(BIP32MaxDepthError):
            spoof.derive_child(0, hardened=False)
        with pytest.raises(BIP32MaxDepthError):
            spoof.derive_child(0, hardened=True)

    def test_derive_at_depth_255_rejected_public(self):
        """Public-side mirror of the private-side check."""
        m = _master()
        spoof = ExtendedPubKey(
            public_key=m.public_key,
            chain_code=m.chain_code,
            depth=255,
            parent_fingerprint=m.parent_fingerprint,
            child_index=0,
            network=m.network,
        )
        with pytest.raises(BIP32MaxDepthError):
            spoof.derive_child(0)

    def test_serialise_rejects_directly_constructed_overdepth(self):
        """Defence-in-depth: a depth > 255 HDKey must fail at serialise.

        (Direct construction via the dataclass / ``__init__`` could in
        principle install a Python int > 255, e.g. from a malformed
        ``from_xprv`` future refactor or a test fixture. The serialise
        path must surface :class:`BIP32MaxDepthError` rather than the
        historical ``ValueError: bytes must be in range(0, 256)``.)
        """
        m = _master()
        spoof = HDKey(
            private_key=m.private_key,
            chain_code=m.chain_code,
            depth=256,  # past the byte field
            parent_fingerprint=m.parent_fingerprint,
            child_index=0,
            network=m.network,
        )
        with pytest.raises(BIP32MaxDepthError):
            spoof.serialize_xprv()
        with pytest.raises(BIP32MaxDepthError):
            spoof.serialize_xpub()

    def test_xpub_serialise_rejects_directly_constructed_overdepth(self):
        m = _master()
        spoof = ExtendedPubKey(
            public_key=m.public_key,
            chain_code=m.chain_code,
            depth=256,
            parent_fingerprint=m.parent_fingerprint,
            child_index=0,
            network=m.network,
        )
        with pytest.raises(BIP32MaxDepthError):
            spoof.serialize()


# ---------------------------------------------------------------------------
# BUG-1 — private CKD MUST retry on IL>=n / k_i==0
# ---------------------------------------------------------------------------


class _HmacShim:
    """Fake hmac context that yields a controlled SHA-512 digest.

    Used to inject a synthetic IL value (first 32 bytes of the HMAC
    output) without having to brute-force a real BIP-32 seed that
    naturally produces ``IL >= n``. The chain-code half is set to a
    plausible 32 random bytes so the resulting child key is structurally
    valid for the retry-success case.
    """

    def __init__(self, il: bytes, ir: bytes):
        assert len(il) == 32 and len(ir) == 32
        self._digest = il + ir

    def digest(self):
        return self._digest


def _patch_hmac_sequence(monkeypatch, target_module, digests: list[bytes]):
    """Replace ``hmac.new(...).digest()`` with a sequenced shim.

    Each successive call to ``hmac.new(...).digest()`` returns the next
    entry in *digests*. Once exhausted, falls through to the real
    implementation so unrelated HMAC users (e.g. PBKDF2 in the seed
    path) are not affected.
    """
    real_new = hmac.new
    calls = {"i": 0}

    def fake_new(key, msg, digestmod):  # noqa: ANN001 — match hmac.new
        if calls["i"] < len(digests):
            d = digests[calls["i"]]
            calls["i"] += 1
            return _HmacShim(d[:32], d[32:])
        return real_new(key, msg, digestmod)

    monkeypatch.setattr(target_module, "hmac",
                        type("M", (), {"new": staticmethod(fake_new)}))


class TestPrivateCKDRetry:
    """W161 BUG-1: private derive_child must retry on IL>=n / k_i==0."""

    def test_retry_on_il_ge_n_returns_valid_child(self, monkeypatch):
        """First attempt (IL >= n) is rejected → retry at index+1 succeeds."""
        m = _master()
        # First HMAC: synthesise IL >= n. Use n itself (smallest invalid).
        bad_il = SECP256K1_ORDER.to_bytes(32, "big")
        # Second HMAC: pass through to real HMAC for index+1.
        # We arrange this by patching with a list of length 1 so the
        # second call falls through.
        from ouroboros import wallet as wallet_mod

        bad_digest = bad_il + b"\x55" * 32  # IL + arbitrary IR
        _patch_hmac_sequence(monkeypatch, wallet_mod, [bad_digest])

        child = m.derive_child(0, hardened=False)
        # The retry skipped index 0 and produced a valid child at 1.
        assert child.child_index == 1
        assert len(child.private_key) == 32
        assert child.depth == 1

    def test_retry_on_il_eq_n_returns_valid_child(self, monkeypatch):
        """Boundary: IL == n is invalid (must be < n) → retry."""
        m = _master()
        from ouroboros import wallet as wallet_mod

        boundary_il = SECP256K1_ORDER.to_bytes(32, "big")
        _patch_hmac_sequence(
            monkeypatch, wallet_mod, [boundary_il + b"\xaa" * 32]
        )
        child = m.derive_child(0, hardened=False)
        assert child.child_index == 1

    def test_retry_on_child_zero_returns_valid_child(self, monkeypatch):
        """Synthetic IL chosen so (IL + parent) mod n == 0 triggers retry."""
        m = _master()
        from ouroboros import wallet as wallet_mod

        parent_int = int.from_bytes(m.private_key, "big")
        # IL == n - parent_int  →  (IL + parent_int) % n == 0
        bad_il_int = (SECP256K1_ORDER - parent_int) % SECP256K1_ORDER
        assert 0 < bad_il_int < SECP256K1_ORDER
        bad_il = bad_il_int.to_bytes(32, "big")
        _patch_hmac_sequence(
            monkeypatch, wallet_mod, [bad_il + b"\x33" * 32]
        )
        child = m.derive_child(0, hardened=False)
        assert child.child_index == 1
        assert int.from_bytes(child.private_key, "big") != 0

    def test_retry_hardened_does_not_cross_boundary(self, monkeypatch):
        """Hardened retry must stay >= 0x80000000."""
        m = _master()
        from ouroboros import wallet as wallet_mod

        bad_il = SECP256K1_ORDER.to_bytes(32, "big")
        _patch_hmac_sequence(monkeypatch, wallet_mod, [bad_il + b"\x77" * 32])
        child = m.derive_child(0, hardened=True)
        # 0 hardened == 0x80000000; retry lands at 0x80000001.
        assert child.child_index == 0x80000001
        assert child.child_index & 0x80000000

    def test_retry_normal_index_at_boundary_raises(self, monkeypatch):
        """A non-hardened retry cannot enter the hardened half (>= 2**31)."""
        m = _master()
        from ouroboros import wallet as wallet_mod

        # Fake every HMAC call to return IL == n → force exhaustion.
        # We're asking derive_child(2**31 - 1) — there is exactly one
        # slot available and it is rejected.
        bad_il = SECP256K1_ORDER.to_bytes(32, "big")
        many_bads = [bad_il + b"\x00" * 32] * 4
        _patch_hmac_sequence(monkeypatch, wallet_mod, many_bads)
        with pytest.raises(BIP32IndexExhaustedError):
            m.derive_child(0x7FFFFFFF, hardened=False)


# ---------------------------------------------------------------------------
# BUG-3 — public CKD MUST retry on IL>=n / point-at-infinity
# ---------------------------------------------------------------------------


class TestPublicCKDRetry:
    """W161 BUG-3: public derive_child must retry on IL>=n / k_i==0."""

    def test_retry_on_il_ge_n_returns_valid_child(self, monkeypatch):
        """First attempt (IL >= n) rejected → retry at index+1 succeeds."""
        m = _master()
        xpub = _xpub_from(m)
        from ouroboros import descriptors as desc_mod

        bad_il = SECP256K1_ORDER.to_bytes(32, "big")
        _patch_hmac_sequence(monkeypatch, desc_mod, [bad_il + b"\x55" * 32])

        child = xpub.derive_child(0)
        assert child.child_index == 1
        assert len(child.public_key) == 33
        assert child.depth == 1

    def test_retry_hardened_index_rejected(self):
        """Public CKD must refuse a hardened index (mathematically impossible)."""
        m = _master()
        xpub = _xpub_from(m)
        with pytest.raises(ValueError, match="hardened"):
            xpub.derive_child(0x80000000)

    def test_retry_at_boundary_exhausts(self, monkeypatch):
        """When the last non-hardened slot is rejected → exhausted error."""
        m = _master()
        xpub = _xpub_from(m)
        from ouroboros import descriptors as desc_mod

        bad_il = SECP256K1_ORDER.to_bytes(32, "big")
        _patch_hmac_sequence(
            monkeypatch, desc_mod, [bad_il + b"\x00" * 32] * 4
        )
        # Requesting the very last non-hardened index — the retry has
        # nowhere to advance to.
        with pytest.raises(BIP32IndexExhaustedError):
            xpub.derive_child(0x7FFFFFFF)


# ---------------------------------------------------------------------------
# Sanity: existing BIP-32 test vector 1 still derives correctly
# ---------------------------------------------------------------------------


def test_bip32_tv1_master_m_zero_hardened_unchanged():
    """The retry refactor must not perturb BIP-32 test-vector-1 derivation."""
    m = _master()
    # BIP-32 TV1 m/0H expected xprv:
    expected_xprv = (
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL"
        "5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    )
    child = m.derive_child(0, hardened=True)
    assert child.serialize_xprv() == expected_xprv
