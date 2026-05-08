"""
BIP-39: Mnemonic code for generating deterministic keys.

Implements the canonical mnemonic phrase encoding and the
``mnemonic + passphrase -> 64-byte seed`` PBKDF2-HMAC-SHA512 derivation used
by Bitcoin Core, hardware wallets, and every other BIP-39 implementation.

Reference:
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Test vectors:
    https://github.com/trezor/python-mnemonic/blob/master/vectors.json

Notes
-----
* Wordlist is vendored at ``src/ouroboros/data/bip39_english.txt`` (2048
  words). Loaded once at module import.
* ``mnemonic_to_seed`` uses ``hashlib.pbkdf2_hmac`` (OpenSSL-backed). See
  haskoin's W21 PBKDF2 iteration-collapse trap — we explicitly verify a
  byte-identical TREZOR vector in tests.
* Both the mnemonic and the passphrase are NFKD-normalised before being
  fed to PBKDF2, per the BIP-39 spec.

This module is consensus-irrelevant but wallet-critical: a silent bug here
makes cross-impl restore impossible.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from importlib import resources

__all__ = [
    "Bip39Error",
    "WORDLIST",
    "WORDLIST_INDEX",
    "entropy_to_mnemonic",
    "mnemonic_to_entropy",
    "mnemonic_to_seed",
    "validate_mnemonic",
    "generate_mnemonic",
]


class Bip39Error(ValueError):
    """Raised on any BIP-39 validation or encoding failure."""


# --- wordlist ---


def _load_wordlist() -> list[str]:
    """Load the 2048-word English wordlist from the vendored data file.

    We use ``importlib.resources`` so the package keeps working when
    installed as a wheel / zipped egg.
    """
    raw = resources.files("ouroboros.data").joinpath("bip39_english.txt").read_text(
        encoding="utf-8"
    )
    words = [w.strip() for w in raw.splitlines() if w.strip()]
    if len(words) != 2048:
        raise Bip39Error(
            f"BIP-39 wordlist must contain exactly 2048 words; got {len(words)}"
        )
    return words


WORDLIST: list[str] = _load_wordlist()
WORDLIST_INDEX: dict[str, int] = {w: i for i, w in enumerate(WORDLIST)}


# --- valid entropy / word-count tables (BIP-39 §3) ---

# Entropy length (bits) -> number of mnemonic words.
# 128/160/192/224/256 bits -> 12/15/18/21/24 words.
_VALID_ENT_BYTES = {16, 20, 24, 28, 32}
_VALID_WORD_COUNTS = {12, 15, 18, 21, 24}


# --- helpers ---


def _nfkd(s: str) -> str:
    """Apply Unicode NFKD normalisation. Required by BIP-39 for both the
    mnemonic and the passphrase prior to PBKDF2."""
    return unicodedata.normalize("NFKD", s)


def _bytes_to_bits(data: bytes) -> str:
    """Return *data* as a big-endian binary string. Used for the
    entropy + checksum -> 11-bit-per-word packing step."""
    return "".join(f"{b:08b}" for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    """Inverse of :func:`_bytes_to_bits`. ``len(bits)`` must be a multiple of 8."""
    if len(bits) % 8 != 0:
        raise Bip39Error(f"bit-string length {len(bits)} not divisible by 8")
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _checksum_bits(entropy: bytes) -> str:
    """Return the BIP-39 checksum bit-string for *entropy*.

    The checksum is the first ``len(entropy_bits) / 32`` bits of
    ``sha256(entropy)``.
    """
    cs_len = (len(entropy) * 8) // 32
    digest = hashlib.sha256(entropy).digest()
    return _bytes_to_bits(digest)[:cs_len]


# --- public API ---


def entropy_to_mnemonic(entropy: bytes) -> list[str]:
    """Encode *entropy* (16, 20, 24, 28 or 32 bytes) as a BIP-39 mnemonic.

    Returns a list of words (12, 15, 18, 21 or 24 entries).
    """
    if not isinstance(entropy, (bytes, bytearray)):
        raise Bip39Error("entropy must be bytes-like")
    if len(entropy) not in _VALID_ENT_BYTES:
        raise Bip39Error(
            f"entropy length must be one of {_VALID_ENT_BYTES} bytes; "
            f"got {len(entropy)}"
        )

    bits = _bytes_to_bits(bytes(entropy)) + _checksum_bits(bytes(entropy))
    # Total bits is always a multiple of 11 by construction:
    #   ENT (multiple of 32) + ENT/32  ==  33*ENT/32  ==  multiple of 11 only
    # when ENT is a multiple of 32 (it is — 128/160/192/224/256).
    assert len(bits) % 11 == 0, "bit length not 11-aligned (should be unreachable)"
    return [
        WORDLIST[int(bits[i : i + 11], 2)]
        for i in range(0, len(bits), 11)
    ]


def mnemonic_to_entropy(mnemonic: list[str] | str) -> bytes:
    """Decode a mnemonic back to its entropy. Raises :class:`Bip39Error`
    on any structural / checksum / wordlist failure.
    """
    words = _coerce_words(mnemonic)
    if len(words) not in _VALID_WORD_COUNTS:
        raise Bip39Error(
            f"mnemonic word-count must be one of {_VALID_WORD_COUNTS}; "
            f"got {len(words)}"
        )

    bits_parts: list[str] = []
    for w in words:
        idx = WORDLIST_INDEX.get(w)
        if idx is None:
            raise Bip39Error(f"word not in BIP-39 English wordlist: {w!r}")
        bits_parts.append(f"{idx:011b}")
    bits = "".join(bits_parts)

    # Split off entropy and checksum.
    cs_len = len(bits) // 33
    ent_len = len(bits) - cs_len
    ent_bits = bits[:ent_len]
    cs_bits = bits[ent_len:]

    entropy = _bits_to_bytes(ent_bits)
    expected_cs = _checksum_bits(entropy)
    if cs_bits != expected_cs:
        raise Bip39Error("invalid mnemonic checksum")
    return entropy


def mnemonic_to_seed(mnemonic: list[str] | str, passphrase: str = "") -> bytes:
    """Derive the 64-byte BIP-39 seed from *mnemonic* and *passphrase*.

    Spec::

        seed = PBKDF2(
            password = NFKD(mnemonic),
            salt     = "mnemonic" + NFKD(passphrase),
            hash     = HMAC-SHA512,
            iterations = 2048,
            dklen    = 64,
        )

    Note: this function does **not** validate the mnemonic checksum. That
    matches the BIP-39 spec ("the produced binary seed is not used to
    represent the original mnemonic — it is used to derive deterministic
    wallets") but callers wanting strict validation should call
    :func:`validate_mnemonic` first.
    """
    if isinstance(mnemonic, list):
        mnemonic_str = " ".join(mnemonic)
    else:
        mnemonic_str = mnemonic

    password = _nfkd(mnemonic_str).encode("utf-8")
    salt = ("mnemonic" + _nfkd(passphrase)).encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha512",
        password,
        salt,
        iterations=2048,
        dklen=64,
    )


def validate_mnemonic(mnemonic: list[str] | str) -> None:
    """Raise :class:`Bip39Error` if *mnemonic* is structurally or
    checksum-invalid. Returns ``None`` on success."""
    mnemonic_to_entropy(mnemonic)


def generate_mnemonic(entropy_bits: int = 128) -> list[str]:
    """Return a freshly-generated mnemonic of *entropy_bits* bits.

    *entropy_bits* must be one of 128, 160, 192, 224, 256 (matching the
    five valid mnemonic lengths). Entropy is sourced from
    :func:`os.urandom`.
    """
    if entropy_bits not in (128, 160, 192, 224, 256):
        raise Bip39Error(
            "entropy_bits must be one of 128, 160, 192, 224, 256; "
            f"got {entropy_bits}"
        )
    entropy = os.urandom(entropy_bits // 8)
    return entropy_to_mnemonic(entropy)


# --- internal helpers ---


def _coerce_words(mnemonic: list[str] | str) -> list[str]:
    """Accept either a list of words or a whitespace-separated string."""
    if isinstance(mnemonic, str):
        # Per BIP-39, words are separated by a single ASCII space, but in
        # practice users paste with arbitrary whitespace. We split on any
        # whitespace and reject empties.
        words = mnemonic.split()
    else:
        words = list(mnemonic)
    if not words:
        raise Bip39Error("empty mnemonic")
    return words
