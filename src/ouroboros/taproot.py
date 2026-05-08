"""
BIP-341 / BIP-86 Taproot key tweak helpers.

Reference:
  - BIP-340: Schnorr signatures
    https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
  - BIP-341: Taproot
    https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
  - BIP-86: Taproot single-key (key-path-only) descriptors
    https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

The tweaked spending key for a Taproot key-path output is::

    d'  =  (d_even  +  t)  mod  n

where:
  * ``d``        is the wallet's internal private key,
  * ``d_even``   = ``d`` if the internal pubkey ``P = d * G`` has even Y,
                  else ``n - d`` (BIP-341's even-Y normalization),
  * ``t``        = ``tagged_hash("TapTweak", x_only(P) || merkle_root)``,
                  with ``merkle_root`` the empty byte string for BIP-86
                  (key-path only, no script tree),
  * ``n``        is the secp256k1 group order.

Signing the tweaked output key with the **untweaked** private key produces
a signature that does NOT verify against the on-chain output key, so any
funds received at a BIP-86 address would be unspendable. This module is
the single source of truth for the tweak in the wallet signing path; it
is wired into ``rpc.py`` ``signrawtransactionwithwallet`` and
``walletprocesspsbt`` (the only two places ouroboros currently signs
P2TR key-path inputs).
"""

from __future__ import annotations

import hashlib

from coincurve import PrivateKey

# secp256k1 group order
SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def derive_taproot_sign_secret(
    secret_d_bytes: bytes,
    merkle_root: bytes | None = None,
) -> bytes:
    """Return the BIP-341 tweaked spending secret for a Taproot key-path output.

    Args:
        secret_d_bytes: 32-byte big-endian internal private key.
        merkle_root: 32-byte merkle root of the script tree, or ``None`` /
            ``b""`` for a BIP-86 key-path-only output.

    Returns:
        The 32-byte big-endian tweaked private key ``d'`` such that
        ``d' * G`` equals the on-chain Taproot output key (modulo BIP-340
        even-Y normalization performed inside ``sign_schnorr``).

    Raises:
        ValueError: if ``secret_d_bytes`` is malformed, ``d`` is out of
            range, the tweak is out of range, or the result is zero.
    """
    if not isinstance(secret_d_bytes, (bytes, bytearray)):
        raise ValueError("secret_d_bytes must be bytes")
    if len(secret_d_bytes) != 32:
        raise ValueError(
            f"secret_d_bytes must be 32 bytes, got {len(secret_d_bytes)}"
        )

    d = int.from_bytes(secret_d_bytes, "big")
    if not (1 <= d < SECP256K1_ORDER):
        raise ValueError("Internal private key out of range [1, n)")

    # P = d * G; recover compressed-form to inspect Y parity.
    pub_compressed = PrivateKey(bytes(secret_d_bytes)).public_key.format(
        compressed=True
    )
    if len(pub_compressed) != 33 or pub_compressed[0] not in (0x02, 0x03):
        raise ValueError("Failed to derive internal pubkey")

    # BIP-341 even-Y normalization on the internal key.
    if pub_compressed[0] == 0x03:
        d = (SECP256K1_ORDER - d) % SECP256K1_ORDER

    x_only = pub_compressed[1:]

    if merkle_root is None:
        merkle_bytes = b""
    else:
        if not isinstance(merkle_root, (bytes, bytearray)):
            raise ValueError("merkle_root must be bytes or None")
        merkle_bytes = bytes(merkle_root)
        if merkle_bytes and len(merkle_bytes) != 32:
            raise ValueError(
                f"merkle_root must be 32 bytes (or empty), "
                f"got {len(merkle_bytes)}"
            )

    t_bytes = _tagged_hash("TapTweak", x_only + merkle_bytes)
    t = int.from_bytes(t_bytes, "big")
    if t >= SECP256K1_ORDER:
        # Astronomically rare but BIP-341 mandates rejection.
        raise ValueError("TapTweak scalar out of range")

    d_prime = (d + t) % SECP256K1_ORDER
    if d_prime == 0:
        raise ValueError("Tweaked private key is zero")

    return d_prime.to_bytes(32, "big")


def derive_taproot_output_xonly(
    pubkey_compressed: bytes,
    merkle_root: bytes | None = None,
) -> bytes:
    """Compute the 32-byte x-only Taproot output key from a compressed pubkey.

    This is the verifier-side counterpart to ``derive_taproot_sign_secret``
    and exists primarily for testing. The result is the value placed in a
    P2TR ``OP_1 <32>`` scriptPubKey.

    Note: callers that already have the *internal* pubkey but want the
    address must lift it to even-Y first (BIP-341). This helper does that
    internally by lifting the input pubkey into the curve and adding
    ``t * G``; for BIP-86 wallets this matches the address that
    ``derive_taproot_sign_secret(d).pubkey`` produces.
    """
    from coincurve import PublicKey

    if len(pubkey_compressed) == 32:
        # already x-only — lift to even-Y by prefixing 0x02
        pub_compressed = b"\x02" + bytes(pubkey_compressed)
    elif len(pubkey_compressed) == 33 and pubkey_compressed[0] in (0x02, 0x03):
        # Force even-Y for the tweak input per BIP-341.
        pub_compressed = b"\x02" + pubkey_compressed[1:]
    else:
        raise ValueError("pubkey must be 32-byte x-only or 33-byte compressed")

    x_only = pub_compressed[1:]
    merkle_bytes = b"" if merkle_root is None else bytes(merkle_root)
    t = _tagged_hash("TapTweak", x_only + merkle_bytes)

    P = PublicKey(pub_compressed)
    Q = P.add(t)
    return Q.format(compressed=True)[1:]
